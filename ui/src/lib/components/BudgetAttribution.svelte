<script lang="ts">
  // REQ: OBS-027 (ADR-127) — "Who spent it?": an objective's error budget over its window,
  // as a burn-down per node (with the change markers, OBS-033), the bad answers by client, name,
  // upstream, status, and response code, and each node's own burn-down.
  import { api, type S } from '../api';
  import { href, navigate, route } from '../router.svelte';
  import { logDate, num } from '../format';
  import { changes } from '../annotations.svelte';
  import Chart, { type Series } from './Chart.svelte';
  import BarList from './BarList.svelte';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';
  import { tr } from '../i18n';
  import { objectiveTitle } from '../objectives';
  import T from '../i18n/T.svelte';
  const { t } = tr('budgetAttribution');

  const objective = $derived(route.params.get('objective') === 'latency' ? 'latency' : 'availability');
  let data = $state<S['SloAttribution'] | null>(null);
  let slo = $state<S['SloStatus'] | null>(null);
  let error = $state<unknown>(null);

  async function load(o: string) {
    try {
      const [a, s] = await Promise.all([api.sloAttribution({ objective: o, limit: 10 }), api.slo().catch(() => null)]);
      data = a;
      slo = s;
      error = null;
    } catch (e) {
      error = e;
    }
  }
  $effect(() => {
    void load(objective);
  });
  // REQ: OBS-033 — the window's change markers on the burn-down.
  $effect(() => {
    if (data) void changes.load(data.from);
  });

  const colors = ['--s-blocked', '--s-forwarded', '--s-local', '--s-cached', '--s-other'];
  /** Budget left (percent) after each period, per node and for every node together. */
  function burndown(points: S['AttributionPoint'][], allowed: number, nodes: (string | undefined)[]) {
    const times = [...new Set(points.map((p) => p.startUnixSeconds))].sort((a, b) => a - b);
    const series: Series[] = nodes.map((n, i) => {
      let spent = 0;
      const values = times.map((t) => {
        for (const p of points) if (p.startUnixSeconds === t && (n === undefined || p.node === n)) spent += p.bad;
        return Math.round((100 - (spent * 100) / Math.max(1, allowed)) * 10) / 10;
      });
      return { label: n ?? t('every node'), color: colors[i % colors.length], values };
    });
    return { times, series };
  }
  const nodeNames = $derived([...new Set((data?.timeline ?? []).map((p) => p.node ?? ''))].filter(Boolean));
  const all = $derived(data ? burndown(data.timeline, data.budget.allowedBad, [undefined]) : null);
  const perNode = $derived(
    data && nodeNames.length > 1
      ? nodeNames.map((n) => ({ node: n, ...burndown(data!.timeline, data!.budget.allowedBad, [n]) }))
      : [],
  );

  // A row's queries in the log, where it still has them: the bad answers of that client or name.
  const latencyMs = $derived(slo?.objectives.find((o) => o.name === 'latency')?.latencyMs);
  function logLink(kind: 'client' | 'name', key: string): string {
    const bad = objective === 'availability' ? { rcode: 'SERVFAIL' } : { minLatencyMs: String(latencyMs ?? 250) };
    const what = kind === 'client' ? { client: key } : { name: key, match: 'exact' };
    return href('/queries', { ...what, ...bad, from: data?.from ?? '-30d' });
  }
  const hidden = (w: string) => data?.coverage.hidden?.includes(w) ?? false;
  const nothing = $derived(data != null && data.budget.bad === 0);
  // REQ: API-012 — the summary is one sentence per variant (overspent, or the share left); the date
  // through lib/format.ts (the browser's default locale, as before).
  const sum = $derived(
    data
      ? { bad: num(data.budget.bad), answered: num(data.budget.answered), since: logDate(data.from), target: data.budget.targetPct, allowed: num(data.budget.allowedBad), left: data.budget.remainingPct }
      : {},
  );
</script>

{#snippet strong(x: string)}<strong>{x}</strong>{/snippet}

<div class="budget-tab" data-testid="budget-attribution">
  <div class="row head">
    <h2>{t('Who spent the error budget?')}<HelpButton id="slo-attribution" /></h2>
    <span class="spacer"></span>
    <div class="seg" role="group" aria-label={t('Objective')}>
      {#each ['availability', 'latency'] as o (o)}
        <button aria-pressed={objective === o} onclick={() => navigate('/analyze', { tab: 'budget', objective: o })}>{objectiveTitle(o)}</button>
      {/each}
    </div>
  </div>
  <ErrorNote {error} />
  {#if !data}
    <p class="empty">{t('Loading…')}</p>
  {:else}
    <p class="small" data-testid="budget-summary">
      {#if data.budget.remainingPct < 0}
        <T ctx="budgetAttribution" msg={'<strong>{bad}</strong> bad of {answered} answers since {since}; the target ({target}%) allows {allowed}: <span>overspent</span>.'} params={sum} {strong}
          >{#snippet span(x: string)}<span class="bad-text">{x}</span>{/snippet}</T
        >
      {:else}
        <T ctx="budgetAttribution" msg={'<strong>{bad}</strong> bad of {answered} answers since {since}; the target ({target}%) allows {allowed}: {left}% of the budget left.'} params={sum} {strong} />
      {/if}
    </p>
    {#if data.note}<div class="notice small">{data.note}</div>{/if}
    {#if data.missingNodes?.length}<div class="notice warn small">{t("Without {nodes}: they didn't answer.", { nodes: data.missingNodes.join(', ') })}</div>{/if}
    {#if data.coverage.partialNodes?.length}
      <p class="muted small" data-testid="partial-nodes">
        {t('No client and name lists for part of the window from {nodes} (an older build, or a pod counted from the minutes it shipped); their bad answers count everywhere else.', { nodes: data.coverage.partialNodes.join(', ') })}
      </p>
    {/if}
    {#if nothing}
      <p class="empty" data-testid="budget-empty">{t('Nothing spent this window.')}</p>
    {:else}
      {#if all}
        <Chart title={t('Budget left (%)')} times={all.times} series={all.series} height={200} markers={changes.markers} format={(n) => `${n}%`} />
      {/if}
      {#if hidden('timeline_only')}
        <p class="muted small">{t('The privacy level keeps only the timeline: no breakdown by client, name, or anything else.')}</p>
      {:else}
        <div class="lists">
          {#if hidden('clients_hidden')}
            <section class="card"><h3>{t('Clients')}</h3><p class="muted small">{t('Hidden by the privacy level.')}</p></section>
          {:else}
            <BarList title={t('Clients')} testid="by-client" rows={data.byClient} link={(r) => logLink('client', r.key)} empty={t('No clients recorded.')} />
          {/if}
          <BarList
            title={hidden('names_hidden') ? t('Names ({n}, hidden by the privacy level)', { n: data.byName.length }) : t('Names')}
            testid="by-name"
            rows={data.byName}
            link={hidden('names_hidden') ? undefined : (r) => logLink('name', r.key)}
            empty={t('No names recorded.')}
          />
          <BarList title={t('Upstreams')} testid="by-upstream" rows={data.byUpstream} link={(r) => (r.key === 'none' ? undefined : href('/upstreams'))} />
          <BarList title={t('Status')} testid="by-status" rows={data.byStatus} />
          <BarList title={t('Response code')} testid="by-rcode" rows={data.byRcode} />
        </div>
        <p class="muted small">
          {t('Clients and names are approximate top lists (each count may be up to its ± over); the other lists are exact. Links open the query log, which keeps fewer days than the budget\'s window.')}
        </p>
      {/if}
      {#if perNode.length}
        <h3>{t('By node')}</h3>
        <div class="nodes">
          {#each perNode as n (n.node)}
            <Chart title={n.node} times={n.times} series={n.series} height={120} format={(v) => `${v}%`} />
          {/each}
        </div>
      {/if}
    {/if}
  {/if}
</div>

<style>
  .head {
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
  }
  .head h2 {
    margin: 0;
  }
  .lists {
    display: grid;
    gap: var(--gap);
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    margin-top: var(--gap);
  }
  .nodes {
    display: grid;
    gap: var(--gap);
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  }
  .bad-text {
    color: var(--bad);
    font-weight: 600;
  }
</style>
