<script lang="ts">
  // REQ: AGT-012 (T8.6) — vqlog in the UI: one line answers counts, top lists, percentiles, and
  // time series over the query log, with what it cost. The same tool agents use.
  import { api, type S } from '../lib/api';
  import { route, navigate, href } from '../lib/router.svelte';
  import { num, ms } from '../lib/format';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import Tabs, { activeTab, type TabItem } from '../lib/components/Tabs.svelte';
  import TabPanel from '../lib/components/TabPanel.svelte';
  import BudgetAttribution from '../lib/components/BudgetAttribution.svelte';
  import { t, tn, type MessageKey } from '../lib/i18n';

  // REQ: OBS-027 — the Analyze page answers "why": the query language, and who spent the
  // error budget.
  const tabs: TabItem[] = $derived([
    { id: 'query', label: t('qw.explain.query') },
    { id: 'budget', label: t('analyze.tab.budget') },
  ]);
  const tab = $derived(activeTab(tabs));

  const examples: { label: MessageKey; q: string }[] = [
    { label: 'analyze.example.topBlocked', q: 'from -24h | where status = blocked | top 10 name' },
    { label: 'analyze.example.busiest', q: 'from -24h | by client | stats count, distinct(domain) | limit 20' },
    { label: 'analyze.example.perHour', q: 'from -24h | bucket 1h | stats count, p50(latency), p95(latency)' },
    { label: 'analyze.example.slow', q: 'from -24h | where latency > 100 | by upstream | stats count, p95(latency)' },
    { label: 'analyze.example.failed', q: 'from -24h | where rcode in (NXDOMAIN, SERVFAIL) | top 20 domain' },
  ];

  let text = $state(route.params.get('q') ?? examples[0].q);
  let result = $state<S['VqlogResult'] | null>(null);
  let error = $state<unknown>(null);
  let busy = $state(false);

  // Runs whatever is in the URL, so results can be shared and survive a reload.
  $effect(() => {
    const q = route.params.get('q');
    if (!q || tab !== 'query') return;
    text = q;
    void run(q, route.params.get('estimate') === '1');
  });

  async function run(q: string, dryRun: boolean) {
    busy = true;
    try {
      result = await api.vqlog(q, dryRun);
      error = null;
    } catch (e) {
      result = null;
      error = e;
    } finally {
      busy = false;
    }
  }

  function go(dryRun = false) {
    const q = text.trim();
    if (!q) return;
    // A new URL reruns through the effect; the same URL wouldn't, so run directly then.
    if (route.params.get('q') === q && (route.params.get('estimate') === '1') === dryRun) void run(q, dryRun);
    else navigate('/analyze', { q, estimate: dryRun ? '1' : undefined });
  }

  function keydown(e: KeyboardEvent) {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      go();
    }
  }

  const statCols = $derived(new Set((result?.columns ?? []).filter((c) => c === 'count' || c.includes('('))));
  const isLatency = (c: string) => /\((upstream_)?latency\)$/.test(c);
  function cell(c: string, v: unknown): string {
    if (v === null || v === undefined) return '–';
    if (typeof v === 'number') return isLatency(c) ? ms(v) : num(v);
    return String(v);
  }
  // Key cells link to the query log for that value.
  function link(c: string, v: unknown): string | undefined {
    if (typeof v !== 'string') return undefined;
    if (c === 'name') return href('/queries', { name: v, match: 'exact' });
    if (c === 'domain') return href('/queries', { name: v, match: 'suffix' });
    if (c === 'client') return href('/queries', { client: v });
    return undefined;
  }
</script>

<div class="page">
  <h1>{t('nav.analyze')}<HelpButton id="vqlog" /></h1>
  <Tabs {tabs} active={tab} label={t('nav.analyze')} />
  <TabPanel active={tab}>
  {#if tab === 'budget'}
    <BudgetAttribution />
  {:else}
  <form
    class="card"
    onsubmit={(e) => {
      e.preventDefault();
      go();
    }}
  >
    <label class="field">
      <span class="small muted">{t('analyze.queryLabel')}</span>
      <textarea name="q" rows="2" spellcheck="false" bind:value={text} onkeydown={keydown} aria-label={t('analyze.queryAria')}></textarea>
    </label>
    <div class="row actions">
      <button class="primary" type="submit" disabled={busy}>{t('analyze.run')}</button>
      <button type="button" disabled={busy} onclick={() => go(true)} title={t('analyze.estimateTitle')}>{t('analyze.estimate')}</button>
      <span class="spacer"></span>
      <span class="small muted">{t('analyze.stages')}</span>
    </div>
    <div class="examples small">
      {#each examples as ex (ex.q)}
        <button type="button" class="chip" onclick={() => { text = ex.q; go(); }}>{t(ex.label)}</button>
      {/each}
    </div>
  </form>

  <ErrorNote {error} />

  {#if result}
    <section class="card" data-testid="vqlog-result">
      <p class="small muted understood">{t('analyze.asUnderstood')}<code>{result.query}</code></p>
      <p class="small muted" data-testid="vqlog-cost">
        {#if result.cost.rowsScanned === 0 && result.rows.length === 0}
          {tn('analyze.estimate', result.cost.estimatedRows, { n: num(result.cost.estimatedRows), blocks: num(result.cost.blocks) })}
        {:else}
          {tn('analyze.matched', result.groups, { n: num(result.groups), matched: num(result.cost.rowsMatched), scanned: num(result.cost.rowsScanned), estimated: num(result.cost.estimatedRows), elapsed: num(result.cost.elapsedMs) })}
        {/if}
      </p>
      {#if result.truncated}
        <div class="notice warn" role="status">{t('analyze.partial', { reason: result.truncatedReason ?? '' })}</div>
      {/if}
      {#if result.missingNodes.length}
        <div class="notice warn" role="status">{t('analyze.notIncluded', { nodes: result.missingNodes.join(', ') })}</div>
      {/if}
      <!-- REQ: AGT-012 (T9.12) — answered from the rollups, or past what the log keeps. -->
      {#if result.source === 'rollups'}
        <p class="small muted" data-testid="vqlog-source">{t('analyze.rollups')}</p>
      {/if}
      {#if result.note}
        <div class="notice" role="status" data-testid="vqlog-note">{result.note}</div>
      {/if}
      {#if result.rows.length}
        <div class="table-wrap">
          <table>
            <thead>
              <tr>{#each result.columns as c (c)}<th class:num={statCols.has(c)}>{c}</th>{/each}</tr>
            </thead>
            <tbody>
              {#each result.rows as row, i (i)}
                <tr>
                  {#each row as v, j (j)}
                    {@const c = result.columns[j]}
                    {@const to = link(c, v)}
                    <td class:num={statCols.has(c)} class:mono={c === 'name' || c === 'domain' || c === 'client'}>
                      {#if to}<a href={to}>{cell(c, v)}</a>{:else}{cell(c, v)}{/if}
                    </td>
                  {/each}
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {:else if result.cost.rowsScanned > 0}
        <p class="empty">{t('analyze.nothing')}</p>
      {/if}
    </section>
  {/if}
  {/if}
  </TabPanel>
</div>

<style>
  .field {
    display: grid;
    gap: 4px;
  }
  textarea {
    width: 100%;
    font: 14px/1.5 var(--mono, monospace);
    resize: vertical;
    box-sizing: border-box;
  }
  .actions {
    gap: 8px;
    margin-top: 8px;
    flex-wrap: wrap;
    align-items: center;
  }
  .examples {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
    margin-top: 10px;
  }
  .chip {
    border-radius: 999px;
    padding: 3px 10px;
    font-size: 12.5px;
  }
  .understood code {
    overflow-wrap: anywhere;
  }
</style>
