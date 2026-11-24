<script lang="ts">
  // REQ: OBS-027 (ADR-127) — "Who spent it?": an objective's error budget over its window,
  // as a burn-down per node (with the change markers, OBS-033), the bad answers by client, name,
  // upstream, status, and response code, and each node's own burn-down.
  import { api, type S } from '../api';
  import { href, navigate, route } from '../router.svelte';
  import { num } from '../format';
  import { changes } from '../annotations.svelte';
  import { t, type MessageKey } from '../i18n';
  import Chart, { type Series } from './Chart.svelte';
  import BarList from './BarList.svelte';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';

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
      return { label: n ?? t('qw.cache.everyNode'), color: colors[i % colors.length], values };
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
  // The two objectives' words are keys: what they say follows the language on screen.
  const titles: Record<string, MessageKey> = {
    availability: 'dashboard.slo.availability',
    latency: 'dashboard.slo.latency',
  };
</script>

<div class="budget-tab" data-testid="budget-attribution">
  <div class="row head">
    <h2>{t('simulation.budget.title')}<HelpButton id="slo-attribution" /></h2>
    <span class="spacer"></span>
    <div class="seg" role="group" aria-label={t('simulation.budget.objectiveAria')}>
      {#each ['availability', 'latency'] as o (o)}
        <button aria-pressed={objective === o} onclick={() => navigate('/analyze', { tab: 'budget', objective: o })}>{t(titles[o])}</button>
      {/each}
    </div>
  </div>
  <ErrorNote {error} />
  {#if !data}
    <p class="empty">{t('slo.loading')}</p>
  {:else}
    <p class="small" data-testid="budget-summary">
      <strong>{num(data.budget.bad)}</strong>{t('simulation.budget.summary', {
        answers: num(data.budget.answered),
        date: new Date(data.from).toLocaleDateString(),
        target: data.budget.targetPct,
        allowed: num(data.budget.allowedBad),
      })}
      {#if data.budget.remainingPct < 0}<span class="bad-text">{t('simulation.budget.summary.overspent')}</span>{:else}{t('simulation.budget.summary.left', { pct: data.budget.remainingPct })}{/if}
    </p>
    {#if data.note}<div class="notice small">{data.note}</div>{/if}
    {#if data.missingNodes?.length}<div class="notice warn small">{t('heatmap.missing', { nodes: data.missingNodes.join(', ') })}</div>{/if}
    {#if data.coverage.partialNodes?.length}
      <p class="muted small" data-testid="partial-nodes">
        {t('simulation.budget.partialNodes', { nodes: data.coverage.partialNodes.join(', ') })}
      </p>
    {/if}
    {#if nothing}
      <p class="empty" data-testid="budget-empty">{t('simulation.budget.empty')}</p>
    {:else}
      {#if all}
        <Chart title={t('simulation.budget.chartLeft')} times={all.times} series={all.series} height={200} markers={changes.markers} format={(n) => `${n}%`} />
      {/if}
      {#if hidden('timeline_only')}
        <p class="muted small">{t('simulation.budget.timelineOnly')}</p>
      {:else}
        <div class="lists">
          {#if hidden('clients_hidden')}
            <section class="card"><h3>{t('nav.clients')}</h3><p class="muted small">{t('simulation.budget.hiddenByPrivacy')}</p></section>
          {:else}
            <BarList
              title={t('nav.clients')}
              testid="by-client"
              rows={data.byClient}
              link={(r) => logLink('client', r.key)}
              empty={t('simulation.budget.noClients')}
            />
          {/if}
          <BarList
            title={hidden('names_hidden')
              ? t('simulation.budget.namesHidden', { n: data.byName.length })
              : t('traffic.mode.name')}
            testid="by-name"
            rows={data.byName}
            link={hidden('names_hidden') ? undefined : (r) => logLink('name', r.key)}
            empty={t('simulation.budget.noNames')}
          />
          <BarList title={t('upstreams.field.members')} testid="by-upstream" rows={data.byUpstream} link={(r) => (r.key === 'none' ? undefined : href('/upstreams'))} />
          <BarList title={t('cluster.col.status')} testid="by-status" rows={data.byStatus} />
          <BarList title={t('simulation.budget.rcode')} testid="by-rcode" rows={data.byRcode} />
        </div>
        <p class="muted small">
          {t('simulation.budget.approximate')}
        </p>
      {/if}
      {#if perNode.length}
        <h3>{t('simulation.budget.byNode')}</h3>
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
