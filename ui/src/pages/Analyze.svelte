<script lang="ts">
  // REQ: AGT-012 (T8.6) — vqlog in the UI: one line answers counts, top lists, percentiles, and
  // time series over the query log, with what it cost. The same tool agents use.
  import { api, type S } from '../lib/api';
  import { route, navigate, href } from '../lib/router.svelte';
  import { num, ms } from '../lib/format';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';

  const examples: { label: string; q: string }[] = [
    { label: 'Top blocked names today', q: 'from -24h | where status = blocked | top 10 name' },
    { label: 'Busiest devices', q: 'from -24h | by client | stats count, distinct(domain) | limit 20' },
    { label: 'Queries per hour, with latency', q: 'from -24h | bucket 1h | stats count, p50(latency), p95(latency)' },
    { label: 'Slow answers by upstream', q: 'from -24h | where latency > 100 | by upstream | stats count, p95(latency)' },
    { label: 'Failed lookups', q: 'from -24h | where rcode in (NXDOMAIN, SERVFAIL) | top 20 domain' },
  ];

  let text = $state(route.params.get('q') ?? examples[0].q);
  let result = $state<S['VqlogResult'] | null>(null);
  let error = $state<unknown>(null);
  let busy = $state(false);

  // Runs whatever is in the URL, so results can be shared and survive a reload.
  $effect(() => {
    const q = route.params.get('q');
    if (!q) return;
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
  <h1>Analyze<HelpButton id="vqlog" /></h1>
  <form
    class="card"
    onsubmit={(e) => {
      e.preventDefault();
      go();
    }}
  >
    <label class="field">
      <span class="small muted">Query (vqlog) · Ctrl+Enter runs it</span>
      <textarea name="q" rows="2" spellcheck="false" bind:value={text} onkeydown={keydown} aria-label="vqlog query"></textarea>
    </label>
    <div class="row actions">
      <button class="primary" type="submit" disabled={busy}>Run</button>
      <button type="button" disabled={busy} onclick={() => go(true)} title="Only estimate how much it would read">Estimate cost</button>
      <span class="spacer"></span>
      <span class="small muted">Stages: from · where · bucket · by · stats · top · sort · limit</span>
    </div>
    <div class="examples small">
      {#each examples as ex (ex.q)}
        <button type="button" class="chip" onclick={() => { text = ex.q; go(); }}>{ex.label}</button>
      {/each}
    </div>
  </form>

  <ErrorNote {error} />

  {#if result}
    <section class="card" data-testid="vqlog-result">
      <p class="small muted understood">As understood: <code>{result.query}</code></p>
      <p class="small muted" data-testid="vqlog-cost">
        {#if result.cost.rowsScanned === 0 && result.rows.length === 0}
          Estimate: up to {num(result.cost.estimatedRows)} logged queries in {num(result.cost.blocks)} blocks would be read.
        {:else}
          Matched {num(result.cost.rowsMatched)} of {num(result.cost.rowsScanned)} queries read (estimated at most
          {num(result.cost.estimatedRows)}) in {num(result.cost.elapsedMs)} ms · {num(result.groups)} groups
        {/if}
      </p>
      {#if result.truncated}
        <div class="notice warn" role="status">Partial: {result.truncatedReason}</div>
      {/if}
      {#if result.missingNodes.length}
        <div class="notice warn" role="status">Not included: {result.missingNodes.join(', ')}</div>
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
        <p class="empty">Nothing matched.</p>
      {/if}
    </section>
  {/if}
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
