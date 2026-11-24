<script lang="ts">
  // REQ: API-005 — the previous dashboard (ADR-157): KPI tiles, queries over time by status, where
  // time goes, top lists, upstream share and health (`spec/07` §3). It is kept, unchanged, behind
  // `#/?view=legacy` (see Dashboard.svelte) for anyone who prefers it, and is meant to be removed.
  import { api, type S } from '../lib/api';
  import { href } from '../lib/router.svelte';
  import { poll } from '../lib/poll';
  import { clock, ms, num, pct, short } from '../lib/format';
  import Kpi from '../lib/components/Kpi.svelte';
  import Chart from '../lib/components/Chart.svelte';
  import Tip from '../lib/components/Tip.svelte';
  import Donut from '../lib/components/Donut.svelte';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import BreakerBadge from '../lib/components/BreakerBadge.svelte';
  import ClientChip from '../lib/components/ClientChip.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import SloCard from '../lib/components/SloCard.svelte';
  import DevicesByType from '../lib/components/DevicesByType.svelte';
  import ChangesControls from '../lib/components/ChangesControls.svelte';
  import LatencyHeatmap from '../lib/components/LatencyHeatmap.svelte';
  import { changes } from '../lib/annotations.svelte';
  import { currentMode } from '../lib/mode.svelte';
  import { t, type MessageKey } from '../lib/i18n';

  // `label` is a catalog key: it is read in the template, so it follows the language.
  const ranges = [
    { id: '15m', label: 'flow.window.15m' as MessageKey, from: '-15m', step: 'second' as const, summary: '-15m', secs: 900 },
    { id: '1h', label: 'flow.window.1h' as MessageKey, from: '-1h', step: 'minute' as const, summary: '-1h', secs: 3600 },
    { id: '24h', label: 'flow.window.24h' as MessageKey, from: '-24h', step: 'minute' as const, summary: '-24h', secs: 86400 },
    { id: '48h', label: 'legacy.range.48h' as MessageKey, from: '-48h', step: 'minute' as const, summary: '-48h', secs: 172800 },
    { id: '7d', label: 'flow.window.7d' as MessageKey, from: '-7d', step: 'hour' as const, summary: '-7d', secs: 604800 },
    { id: '30d', label: 'legacy.range.30d' as MessageKey, from: '-30d', step: 'hour' as const, summary: '-30d', secs: 2592000 },
  ];
  let range = $state(ranges[2]);

  let summary = $state<S['Summary'] | null>(null);
  // T6.8 — the previous period of the same length, for the tiles' change.
  let previous = $state<S['Summary'] | null>(null);
  let buckets = $state<S['TimeBucket'][]>([]);
  let topDomains = $state<S['TopItem'][]>([]);
  let topBlocked = $state<S['TopItem'][]>([]);
  let topClients = $state<S['TopItem'][]>([]);
  let upstreams = $state<S['UpstreamInfo'][]>([]);
  let stages = $state<S['LatencyRow'][]>([]);
  let byPath = $state<S['LatencyRow'][]>([]);
  // REQ: OBS-016 — the objectives (their own window, not the dashboard's range). The card,
  // like traffic by group, where time goes, upstreams, and upstream exchanges, is technical
  // detail: Advanced view only (owner, 2026-10-09). Burning budgets still reach everyone through the health icon
  // and alerts.
  let slo = $state<S['SloStatus'] | null>(null);
  const advanced = $derived(currentMode() === 'advanced');
  // What each "Where time goes" row means (path/transport, or a wait stage).
  const paths: Record<string, MessageKey> = {
    cache: 'legacy.path.cache',
    upstream: 'legacy.path.upstream',
    local: 'legacy.path.local',
    synthesized: 'legacy.path.synthesized',
  };
  const protos: Record<string, MessageKey> = {
    udp: 'legacy.proto.udp',
    tcp: 'legacy.proto.tcp',
    dot: 'legacy.proto.dot',
    doh: 'legacy.proto.doh',
  };
  const pathTip = (key: string) => {
    if (key.startsWith('wait: ')) {
      const what = key.slice(6);
      return what === 'upstream'
        ? t('legacy.path.waitUpstream')
        : t('legacy.path.wait', { what });
    }
    const [path, proto] = key.split('/');
    const p = paths[path] ? t(paths[path]) : t('legacy.path.fallback');
    return proto && protos[proto] ? t('legacy.path.over', { path: p, proto: t(protos[proto]) }) : p;
  };
  let groups = $state<S['GroupInfo'][]>([]);
  // ADR-050 — the top lists for one kind of device ('' = everyone).
  let group = $state('');
  const groupColor = (n: string) => groups.find((g) => g.name === n)?.color ?? 'var(--muted)';
  // REQ: CLU-002 — the whole cluster ('' ), one node (`node:<id>`), or one site's nodes
  // (`site:<name>`). Remembered in this browser only.
  let nodes = $state<S['ClusterView']['nodes']>([]);
  let scope = $state(remembered());
  function remembered(): string {
    try {
      return localStorage.getItem('dashboard.scope') ?? '';
    } catch {
      return '';
    }
  }
  $effect(() => {
    try {
      localStorage.setItem('dashboard.scope', scope);
    } catch {
      // Private windows and blocked storage: the choice just isn't remembered.
    }
  });
  const nodeLabel = (n: S['ClusterView']['nodes'][number]) =>
    (n.ephemeral ? t('legacy.nodePod', { site: n.site, pod: n.pod ?? n.nodeId.slice(0, 8) }) : n.site) +
    (n.role.includes('primary') ? t('legacy.nodePrimary') : '') +
    (n.thisNode ? ` · ${t('legacy.thisNode')}` : '');
  // Sites with resolver pods get a choice of their own: the pods come and go.
  const podSites = $derived([...new Set(nodes.filter((n) => n.ephemeral).map((n) => n.site))]);
  const scopeLabel = $derived(
    scope.startsWith('node:')
      ? (nodes.find((n) => `node:${n.nodeId}` === scope)?.site ?? t('legacy.oneNode'))
      : scope.startsWith('site:')
        ? t('legacy.siteLabel', { site: scope.slice(5) })
        : t('legacy.everyNode'),
  );
  // Upstream health is each node's own: say whose when another node is shown.
  const otherNode = $derived(
    scope !== '' && !(scope.startsWith('node:') && nodes.find((n) => `node:${n.nodeId}` === scope)?.thisNode),
  );
  let error = $state<unknown>(null);
  // REQ: OBS-030 — "Where time goes" as percentiles or as a heatmap over time.
  let timeView = $state<'table' | 'heatmap'>('table');
  // REQ: OBS-037 — Top domains as names on the internet or internal names (cluster, private
  // reverse lookups), which have their own list.
  let domainsView = $state<'internet' | 'internal'>('internet');
  // REQ: OBS-004 (ADR-160) — the top lists and active clients follow the time range, by whole
  // hours: a range under a day says from which hour; a group's lists cover this hour only.
  let nowS = $state(Math.floor(Date.now() / 1000));
  // The chosen range's own word ("24 h"), read here so every sentence that carries it follows the language.
  const rangeName = $derived(t(range.label));
  const rangeLabel = $derived(
    range.secs < 86400
      ? t('legacy.sinceTime', { time: clock(Math.floor((nowS - range.secs) / 3600) * 3600) })
      : t('legacy.lastRange', { range: rangeName }),
  );
  const topLabel = $derived(group ? t('legacy.thisHour') : rangeLabel);

  async function load() {
    const r = range;
    try {
      const g = group || undefined;
      const sc = scope || undefined;
      const tf = g ? undefined : r.from;
      nowS = Math.floor(Date.now() / 1000);
      // REQ: OBS-033 — the window's change markers, once for every chart (refetched each minute).
      void changes.load(r.from, sc);
      const [s, ts, d, b, c, u, st, lp, gs, cl, sl] = await Promise.all([
        api.summary(r.summary, undefined, sc),
        api.timeseries({ from: r.from, step: r.step, scope: sc }),
        api.top(domainsView === 'internal' ? 'internal' : 'domains', 10, undefined, g, sc, undefined, tf),
        api.top('blocked', 10, undefined, g, sc, undefined, tf),
        api.top('clients', 10, undefined, g, sc, undefined, tf),
        api.upstreams(),
        api.latency('stage', sc),
        api.latency('path', sc),
        api.groups(),
        api.cluster().catch(() => null),
        api.slo(sc).catch(() => null),
      ]);
      slo = sl;
      groups = gs.items;
      nodes = cl?.enabled ? cl.nodes : [];
      summary = s;
      const mins = Math.round(r.secs / 60);
      previous = await api.summary(`-${2 * mins}m`, `-${mins}m`, sc).catch(() => null);
      buckets = dense(ts.items, { second: 1, minute: 60, hour: 3600, day: 86400 }[r.step], r.secs);
      topDomains = d.items;
      topBlocked = b.items;
      topClients = c.items;
      upstreams = u.items;
      stages = st.items;
      byPath = lp.items;
      error = null;
    } catch (e) {
      error = e;
    }
  }

  /** Every bucket in the window, zeros where nothing happened (the API skips empty ones). */
  function dense(items: S['TimeBucket'][], step: number, secs: number): S['TimeBucket'][] {
    const now = Math.floor(Date.now() / 1000);
    const last = Math.floor(now / step) * step;
    const first = Math.floor((now - secs) / step) * step + step;
    const byStart = new Map(items.map((b) => [b.startUnixSeconds, b]));
    const out: S['TimeBucket'][] = [];
    for (let t = first; t <= last; t += step) {
      out.push(
        byStart.get(t) ?? {
          startUnixSeconds: t,
          total: 0,
          byStatus: {},
          byQtype: {},
          byRcode: {},
          upstreamQueries: 0,
          upstreamFailures: 0,
          byGroup: {},
          blockedByGroup: {},
          slow: 0,
        },
      );
    }
    return out;
  }

  $effect(() => {
    void range;
    void group;
    void scope;
    return poll(load, range.step === 'second' ? 5000 : 15000);
  });

  // Queries over time, stacked by status (minor statuses folded into "other"). DNS-007: answers
  // refreshed in the background count as cached; the Advanced view shows them on their own.
  const main = $derived(
    advanced ? (['blocked', 'cached', 'refreshed', 'forwarded', 'local'] as const) : (['blocked', 'cached', 'forwarded', 'local'] as const),
  );
  const colors: Record<string, string> = {
    blocked: '--s-blocked',
    cached: '--s-cached',
    refreshed: '--s-refreshed',
    forwarded: '--s-forwarded',
    local: '--s-local',
    other: '--s-other',
  };
  // The words beside those colours, from the catalog: a status shows as its identifier in English.
  const STATUS_KEY: Record<string, MessageKey> = {
    blocked: 'wall.kpi.blocked',
    cached: 'legacy.status.cached',
    refreshed: 'legacy.status.refreshed',
    forwarded: 'legacy.status.forwarded',
    local: 'legacy.status.local',
    other: 'legacy.status.other',
  };
  const statusWord = (k: string) => (STATUS_KEY[k] ? t(STATUS_KEY[k]) : k);
  const times = $derived(buckets.map((b) => b.startUnixSeconds));
  const statusSeries = $derived.by(() => {
    const series = [...main, 'other'].map((k) => ({ label: statusWord(k), color: colors[k], values: [] as number[] }));
    for (const b of buckets) {
      let rest = b.total;
      main.forEach((k, i) => {
        const extra = k === 'cached' ? (b.byStatus['stale'] ?? 0) + (advanced ? 0 : (b.byStatus['refreshed'] ?? 0)) : 0;
        const v = (b.byStatus[k] ?? 0) + extra;
        series[i].values.push(v);
        rest -= v;
      });
      series[main.length].values.push(Math.max(0, rest));
    }
    return series.filter((s) => s.values.some((v) => v > 0));
  });
  // ADR-050 — which kinds of devices make the traffic, in each group's color.
  const groupSeries = $derived.by(() => {
    const names = new Set<string>();
    for (const b of buckets) for (const k of Object.keys(b.byGroup ?? {})) names.add(k);
    const color = (n: string) => groups.find((g) => g.name === n)?.color ?? '--s-other';
    return [...names]
      .sort()
      .map((n) => ({ label: n, color: color(n), values: buckets.map((b) => b.byGroup?.[n] ?? 0) }))
      .filter((s) => s.values.some((v) => v > 0));
  });
  const upstreamSeries = $derived([
    { label: t('legacy.upstreamQueries'), color: '--s-forwarded', values: buckets.map((b) => b.upstreamQueries) },
    { label: t('legacy.failures'), color: '--s-blocked', values: buckets.map((b) => b.upstreamFailures) },
  ]);

  // The busiest upstream path stands in for "typical answer time" until per-node p95 lands.
  const upstreamP90 = $derived.by(() => {
    const rows = (summary?.latency ?? []).filter((r) => r.key.startsWith('upstream'));
    rows.sort((a, b) => b.count - a.count);
    return rows[0];
  });
  const cacheP50 = $derived(
    (summary?.latency ?? []).filter((r) => r.key.startsWith('cache')).sort((a, b) => b.count - a.count)[0] as S['LatencyRow'] | undefined,
  );

  /** Change as a fraction; null when there's nothing to compare with. */
  function change(now: number | null | undefined, before: number | null | undefined): number | null {
    if (now == null || before == null || !Number.isFinite(now) || !Number.isFinite(before) || before === 0) return null;
    return (now - before) / before;
  }
  const prevP90 = $derived(
    (previous?.latency ?? []).filter((r) => r.key.startsWith('upstream')).sort((a, b) => b.count - a.count)[0] as S['LatencyRow'] | undefined,
  );
  const share = (b: S['TimeBucket'], k: string) => (b.total ? ((b.byStatus[k] ?? 0) / b.total) * 100 : 0);
  const sparkTotal = $derived(buckets.map((b) => b.total));
  const sparkBlocked = $derived(buckets.map((b) => share(b, 'blocked')));
  const sparkCached = $derived(buckets.map((b) => share(b, 'cached') + share(b, 'stale') + share(b, 'refreshed')));
  // DNS-007 — of the answers that weren't blocked or local, the share given from an expired
  // cached copy while it was refreshed (the Advanced view's split of the cache tile).
  const refreshedPercent = $derived(
    summary && summary.cached + summary.forwarded > 0 ? ((summary.refreshed ?? 0) * 100) / (summary.cached + summary.forwarded) : null,
  );
  const cacheSub = $derived(
    advanced && refreshedPercent != null && (summary?.refreshed ?? 0) > 0
      ? t('legacy.cacheFreshRefreshed', {
          fresh: pct((summary?.cacheHitPercent ?? 0) - refreshedPercent),
          refreshed: pct(refreshedPercent),
        })
      : t('legacy.cacheAnswers', { answers: short(summary?.cached) }),
  );
  const sparkFailures = $derived(buckets.map((b) => b.upstreamFailures));

  // T6.8 — the same statuses as the chart, as totals over the range.
  const statusParts = $derived(
    statusSeries.map((s) => ({ label: s.label, color: s.color, value: s.values.reduce((a, v) => a + v, 0) })),
  );

  const totalUpstream = $derived(upstreams.reduce((a, u) => a + u.requests, 0));
  const maxTop = (items: S['TopItem'][]) => Math.max(1, ...items.map((i) => i.count));
  // REQ: OBS-004 — a top client's bar split by how its queries were answered, in the status
  // chart's colours; "other" is the rest of its count (local, special, refused, …, and the
  // sketch's error bound).
  const clientSplit = (i: S['TopItem']) => {
    const s = i.byStatus;
    if (!s) return [];
    const other = Math.max(0, i.count - s.blocked - s.cached - s.forwarded);
    return [
      { label: 'blocked', n: s.blocked },
      { label: 'cached', n: s.cached },
      { label: 'forwarded', n: s.forwarded },
      { label: 'other', n: other },
    ];
  };
  const splitText = (i: S['TopItem']) =>
    clientSplit(i)
      .filter((p) => p.n > 0)
      .map((p) => `${num(p.n)} ${statusWord(p.label)}`)
      .join(' · ');
</script>

<div class="page">
  <div class="page-head">
    <h1>{t('legacy.title')}<HelpButton id="how-it-works" /></h1>
    <!-- The view controls, one group: on a narrow screen they wrap together below the heading. -->
    <div class="head-controls">
      {#if nodes.length > 1}
        <!-- REQ: CLU-002 — every node together, or one node (or site) at a time. -->
        <label class="pill-field">
          {t('legacy.showing')}
          <select bind:value={scope} aria-label={t('legacy.nodes')}>
            <option value="">{t('legacy.everyNode')}</option>
            {#each nodes as n (n.nodeId)}<option value={`node:${n.nodeId}`}>{nodeLabel(n)}</option>{/each}
            {#each podSites as s (s)}<option value={`site:${s}`}>{t('legacy.siteAllNodes', { site: s })}</option>{/each}
          </select>
        </label>
      {/if}
      {#if groups.length > 1}
        <label class="pill-field">
          {t('legacy.topListsFor')}
          <select bind:value={group} aria-label={t('legacy.group')}>
            <option value="">{t('legacy.everyDevice')}</option>
            {#each groups as g (g.name)}<option value={g.name}>{g.name}</option>{/each}
          </select>
        </label>
      {/if}
      <div class="seg" role="group" aria-label={t('legacy.timeRange')}>
        {#each ranges as r (r.id)}
          <button aria-pressed={range.id === r.id} onclick={() => (range = r)}>{t(r.label)}</button>
        {/each}
      </div>
      <ChangesControls />
    </div>
  </div>
  <ChangesControls part="body" {advanced} />

  <ErrorNote {error} />
  {#if summary?.missingNodes?.length}
    <!-- REQ: CLU-002 — a node that doesn't answer leaves partial totals, said plainly. -->
    <div class="notice warn small">
      {t('legacy.partialResults', { nodes: summary.missingNodes.join(', ') })}
    </div>
  {/if}

  <div class="kpis">
    <!-- More blocking or more queries isn't good or bad, so those changes stay neutral. -->
    <Kpi label={t('legacy.queries')} value={short(summary?.queries)} sub={`${t('legacy.lastRange', { range: rangeName })}${scope ? ` · ${scopeLabel}` : ''}`} delta={change(summary?.queries, previous?.queries)} spark={sparkTotal} sparkColor="--s-forwarded" />
    <Kpi label={t('legacy.blocked')} value={pct(summary?.blockedPercent)} sub={t('legacy.blockedQueries', { queries: short(summary?.blocked) })} tone="bad" delta={change(summary?.blockedPercent, previous?.blockedPercent)} spark={sparkBlocked} sparkColor="--s-blocked" ring={summary?.blockedPercent} />
    <Kpi label={t('legacy.cacheHits')} value={pct(summary?.cacheHitPercent)} sub={cacheSub} tone="ok" delta={change(summary?.cacheHitPercent, previous?.cacheHitPercent)} good="up" spark={sparkCached} sparkColor="--s-cached" ring={summary?.cacheHitPercent} />
    <Kpi label={t('legacy.upstreamP90')} value={ms(upstreamP90?.p90Ms)} sub={cacheP50 ? t('legacy.cacheP50', { value: ms(cacheP50.p50Ms) }) : t('legacy.thisHour')} delta={change(upstreamP90?.p90Ms, prevP90?.p90Ms)} good="down" />
    <Kpi label={t('legacy.activeClients')} value={num(summary?.activeClients)} sub={rangeLabel} delta={change(summary?.activeClients, previous?.activeClients)} />
    <Kpi label={t('legacy.nxdomainServfail')} value={`${short(summary?.nxdomain)} / ${short(summary?.servfail)}`} sub={t('legacy.lastRange', { range: rangeName })} delta={change(summary?.servfail, previous?.servfail)} good="down" spark={sparkFailures} sparkColor="--s-blocked" />
  </div>

  {#if advanced}<SloCard {slo} />{/if}

  <div class="status-row">
    <Chart title={t('legacy.chartQueriesByStatus')} {times} series={statusSeries} stacked seconds={range.step === 'second'} markers={changes.markers} />
    <section class="card">
      <h2>{t('legacy.answersByStatus')}</h2>
      {#if statusParts.length === 0}
        <p class="empty">{t('legacy.noAnswersRange')}</p>
      {:else}
        <Donut parts={statusParts} center={t('legacy.donutCenter', { range: rangeName })} format={short} />
      {/if}
    </section>
  </div>

  <!-- Advanced view only (owner, 2026-10-09), like the Service level card above. -->
  {#if advanced && (groupSeries.length > 1 || (groupSeries.length === 1 && groupSeries[0].label !== 'default'))}
    <Chart title={t('legacy.chartTrafficByGroup')} {times} series={groupSeries} stacked seconds={range.step === 'second'} markers={changes.markers} />
  {/if}
  <!-- REQ: OBS-025 — devices by what they look like (Advanced view). -->
  {#if advanced}<DevicesByType />{/if}

  {#if advanced}
  <div class="grid-2">
    <section class="card" class:wide={timeView === 'heatmap'}>
      <div class="card-head">
        <h2>{t('legacy.whereTimeGoes')} {#if timeView === 'table'}<span class="muted small">{t('legacy.parenThisHour')}</span>{/if}{#if timeView === 'heatmap'}<HelpButton id="latency-heatmap" />{:else}<HelpButton id="cache" />{/if}</h2>
        <div class="seg" role="group" aria-label={t('legacy.whereTimeGoesAs')}>
          <button type="button" aria-pressed={timeView === 'table'} onclick={() => (timeView = 'table')}>{t('legacy.percentiles')}</button>
          <button type="button" aria-pressed={timeView === 'heatmap'} onclick={() => (timeView = 'heatmap')} data-testid="time-heatmap-tab">{t('nav.heatmap')}</button>
        </div>
      </div>
      {#if timeView === 'heatmap'}
        <LatencyHeatmap />
      {:else if byPath.length + stages.length === 0}
        <p class="empty">{t('legacy.noAnswersHour')}</p>
      {:else}
        <div class="table-wrap">
          <table class="compact">
            <thead><tr><th>{t('legacy.col.path')}</th><th class="num">{t('flow.col.answers')}</th><th class="num">p50</th><th class="num">p90</th><th class="num">p99</th><th class="num">{t('legacy.col.max')}</th></tr></thead>
            <tbody>
              {#each [...byPath, ...stages.map((s) => ({ ...s, key: `wait: ${s.key}` }))] as r (r.key)}
                <tr>
                  <td><Tip text={pathTip(r.key)}>{r.key}</Tip></td>
                  <td class="num">{num(r.count)}</td>
                  <td class="num">{ms(r.p50Ms)}</td>
                  <td class="num">{ms(r.p90Ms)}</td>
                  <td class="num">{ms(r.p99Ms)}</td>
                  <td class="num">{ms(r.maxMs)}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </section>

    <section class="card">
      <div class="card-head"><h2>{t('nav.upstreams')}{#if otherNode} <span class="muted small">{t('legacy.asThisNode')}</span>{/if}</h2><a href={href('/upstreams')} class="small">{t('legacy.details')}</a></div>
      {#if upstreams.length === 0}
        <p class="empty">{t('legacy.noUpstreams')}</p>
      {:else}
        <ul class="bars">
          {#each upstreams as u (u.id)}
            <li>
              <div class="row">
                <strong>{u.name}</strong>
                <BreakerBadge value={u.breaker} />
                <span class="spacer"></span>
                <span class="muted small">{pct(totalUpstream ? (u.requests / totalUpstream) * 100 : 0, 0)} · {ms(u.latencyEwmaMs)}</span>
              </div>
              <div class="bar"><span style:width={`${totalUpstream ? (u.requests / totalUpstream) * 100 : 0}%`}></span></div>
            </li>
          {/each}
        </ul>
      {/if}
    </section>
  </div>

    <Chart title={t('legacy.chartUpstreamExchanges')} {times} series={upstreamSeries} height={160} bars seconds={range.step === 'second'} markers={changes.markers} />
  {/if}

  <div class="grid-3">
    {#each [
      { kind: 'domains', title: t('legacy.topDomains'), items: topDomains, link: (k: string) => href('/queries', { name: k, match: 'exact' }) },
      { kind: 'blocked', title: t('legacy.topBlocked'), items: topBlocked, link: (k: string) => href('/queries', { name: k, match: 'exact', status: 'blocked' }) },
      { kind: 'clients', title: t('legacy.topClients'), items: topClients, link: (k: string) => href('/queries', { client: k }) },
    ] as card (card.kind)}
      <section class="card">
        {#if card.kind === 'domains'}
          <div class="card-head">
            <h2>{card.title} <span class="muted small">({topLabel})</span><HelpButton id="internal-names" /></h2>
            <div class="seg" role="group" aria-label={t('legacy.domainsScope')}>
              <button type="button" aria-pressed={domainsView === 'internet'} onclick={() => { domainsView = 'internet'; void load(); }}>{t('legacy.internet')}</button>
              <button type="button" aria-pressed={domainsView === 'internal'} onclick={() => { domainsView = 'internal'; void load(); }} data-testid="domains-internal-tab">{t('legacy.internal')}</button>
            </div>
          </div>
        {:else}
          <h2>{card.title} <span class="muted small">({topLabel})</span></h2>
        {/if}
        {#if card.kind === 'clients' && card.items.some((i) => i.byStatus)}
          <p class="legend small muted" data-testid="clients-legend">
            {#each ['blocked', 'cached', 'forwarded', 'other'] as k (k)}<span><i style:background={`var(${colors[k]})`}></i>{statusWord(k)}</span>{/each}
          </p>
        {/if}
        {#if card.items.length === 0}
          <p class="empty">{t('legacy.empty')}</p>
        {:else}
          <ol class="bars">
            {#each card.items as i (i.key)}
              <li>
                <div class="row">
                  {#if card.kind === 'clients'}
                    <span class="name"><ClientChip ip={i.key} name={i.name} onchanged={() => void load()} /></span>
                    <!-- ADR-050 — the groups whose settings apply to the device. -->
                    {#each i.groups ?? [] as g (g)}<span class="group-chip small" style:--gc={groupColor(g)}>{g}</span>{/each}
                  {:else}
                    <a class="name" href={card.link(i.key)}>{i.key}</a>
                  {/if}
                  <span class="spacer"></span>
                  <span class="num small">{num(i.count)}</span>
                </div>
                {#if card.kind === 'clients' && i.byStatus}
                  <div class="bar" title={splitText(i)} role="img" aria-label={splitText(i)} data-testid="client-split">
                    <span class="stack" style:width={`${(i.count / maxTop(card.items)) * 100}%`}>
                      {#each clientSplit(i) as p (p.label)}
                        {#if p.n > 0}<span style:flex-grow={p.n} style:background={`var(${colors[p.label]})`}></span>{/if}
                      {/each}
                    </span>
                  </div>
                {:else}
                  <div class="bar"><span style:width={`${(i.count / maxTop(card.items)) * 100}%`}></span></div>
                {/if}
              </li>
            {/each}
          </ol>
        {/if}
      </section>
    {/each}
  </div>
</div>

<style>
  /* The header's view controls stay together, right of the heading; they wrap as one group. */
  .head-controls {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
  }
  /* REQ: OBS-030 — the heatmap takes the row's width. */
  .card.wide {
    grid-column: 1 / -1;
  }
  .status-row {
    display: grid;
    gap: var(--gap);
    grid-template-columns: minmax(0, 2.2fr) minmax(240px, 1fr);
  }
  @media (max-width: 1000px) {
    .status-row {
      grid-template-columns: minmax(0, 1fr);
    }
  }
  .kpis {
    display: grid;
    gap: 12px;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  }
  .bars {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: 8px;
  }
  .name {
    word-break: break-all;
    min-width: 0;
  }
  .bar {
    height: 5px;
    background: var(--surface-2);
    border-radius: 999px;
    margin-top: 3px;
    overflow: hidden;
  }
  .bar span {
    display: block;
    height: 100%;
    border-radius: 999px;
    background: var(--accent);
  }
  /* REQ: OBS-004 — a top client's bar, split by status. */
  .bar .stack {
    display: flex;
    background: none;
    overflow: hidden;
  }
  .bar .stack > span {
    flex: 0 1 0;
    min-width: 0;
    border-radius: 0;
  }
  .legend {
    display: flex;
    flex-wrap: wrap;
    gap: 4px 12px;
    margin: -4px 0 8px;
  }
  .legend span {
    display: inline-flex;
    align-items: center;
    gap: 5px;
  }
  .legend i {
    width: 8px;
    height: 8px;
    border-radius: 2px;
  }
  .num {
    font-variant-numeric: tabular-nums;
  }
</style>
