<script lang="ts">
  // REQ: API-005 — dashboard: KPI tiles, queries over time by status, where time goes, top
  // lists, upstream share and health (`spec/07` §3).
  import { api, type S } from '../lib/api';
  import { href } from '../lib/router.svelte';
  import { poll } from '../lib/poll';
  import { ms, num, pct, short } from '../lib/format';
  import Kpi from '../lib/components/Kpi.svelte';
  import Chart from '../lib/components/Chart.svelte';
  import Tip from '../lib/components/Tip.svelte';
  import Donut from '../lib/components/Donut.svelte';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import StatusBadge from '../lib/components/StatusBadge.svelte';
  import ClientChip from '../lib/components/ClientChip.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import SloCard from '../lib/components/SloCard.svelte';
  import { currentMode } from '../lib/mode.svelte';

  const ranges = [
    { id: '15m', label: '15 min', from: '-15m', step: 'second' as const, summary: '-15m', secs: 900 },
    { id: '1h', label: '1 h', from: '-1h', step: 'minute' as const, summary: '-1h', secs: 3600 },
    { id: '24h', label: '24 h', from: '-24h', step: 'minute' as const, summary: '-24h', secs: 86400 },
    { id: '48h', label: '48 h', from: '-48h', step: 'minute' as const, summary: '-48h', secs: 172800 },
    { id: '7d', label: '7 d', from: '-7d', step: 'hour' as const, summary: '-7d', secs: 604800 },
    { id: '30d', label: '30 d', from: '-30d', step: 'hour' as const, summary: '-30d', secs: 2592000 },
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
  const paths: Record<string, string> = {
    cache: 'Answered from the cache: a repeat question, no upstream asked. Usually well under a millisecond.',
    upstream:
      'Not in the cache: asked an upstream resolver and waited for it. Also counts stale answers served because the upstream was slow, and SERVFAIL. Usually the slowest path.',
    local: 'Answered from names on your network (local records), without asking anyone.',
    synthesized:
      "Answered without looking anything up: blocked names, refused or rate-limited queries, malformed ones, and special names (like Firefox's DNS-over-HTTPS canary).",
  };
  const protos: Record<string, string> = {
    udp: 'plain DNS over UDP, what most devices use',
    tcp: 'plain DNS over TCP, for large answers and some tools',
    dot: 'DNS over TLS (port 853), e.g. Android Private DNS',
    doh: 'DNS over HTTPS, e.g. browsers or Apple devices with a profile',
  };
  const pathTip = (key: string) => {
    if (key.startsWith('wait: ')) {
      const what = key.slice(6);
      return what === 'upstream'
        ? "Of the upstream path above: the time spent waiting for upstream resolvers (the rest is this node's own work)."
        : `Time spent waiting for ${what} when it answered.`;
    }
    const [path, proto] = key.split('/');
    const p = paths[path] ?? 'Answers that took this path.';
    return proto && protos[proto] ? `${p} Over ${protos[proto]}.` : p;
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
    (n.ephemeral ? `${n.site} pod ${n.pod ?? n.nodeId.slice(0, 8)}` : n.site) +
    (n.role.includes('primary') ? ' (primary)' : '') +
    (n.thisNode ? ' · this node' : '');
  // Sites with resolver pods get a choice of their own: the pods come and go.
  const podSites = $derived([...new Set(nodes.filter((n) => n.ephemeral).map((n) => n.site))]);
  const scopeLabel = $derived(
    scope.startsWith('node:')
      ? (nodes.find((n) => `node:${n.nodeId}` === scope)?.site ?? 'one node')
      : scope.startsWith('site:')
        ? `site ${scope.slice(5)}`
        : 'every node',
  );
  // Upstream health is each node's own: say whose when another node is shown.
  const otherNode = $derived(
    scope !== '' && !(scope.startsWith('node:') && nodes.find((n) => `node:${n.nodeId}` === scope)?.thisNode),
  );
  let error = $state<unknown>(null);

  async function load() {
    const r = range;
    try {
      const g = group || undefined;
      const sc = scope || undefined;
      const [s, ts, d, b, c, u, st, lp, gs, cl, sl] = await Promise.all([
        api.summary(r.summary, undefined, sc),
        api.timeseries({ from: r.from, step: r.step, scope: sc }),
        api.top('domains', 10, undefined, g, sc),
        api.top('blocked', 10, undefined, g, sc),
        api.top('clients', 10, undefined, g, sc),
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

  // Queries over time, stacked by status (minor statuses folded into "other").
  const main = ['blocked', 'cached', 'forwarded', 'local'] as const;
  const colors: Record<string, string> = {
    blocked: '--s-blocked',
    cached: '--s-cached',
    forwarded: '--s-forwarded',
    local: '--s-local',
    other: '--s-other',
  };
  const times = $derived(buckets.map((b) => b.startUnixSeconds));
  const statusSeries = $derived.by(() => {
    const series = [...main, 'other'].map((k) => ({ label: k, color: colors[k], values: [] as number[] }));
    for (const b of buckets) {
      let rest = b.total;
      main.forEach((k, i) => {
        const v = (b.byStatus[k] ?? 0) + (k === 'cached' ? (b.byStatus['stale'] ?? 0) : 0);
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
    { label: 'upstream queries', color: '--s-forwarded', values: buckets.map((b) => b.upstreamQueries) },
    { label: 'failures', color: '--s-blocked', values: buckets.map((b) => b.upstreamFailures) },
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
  const sparkCached = $derived(buckets.map((b) => share(b, 'cached') + share(b, 'stale')));
  const sparkFailures = $derived(buckets.map((b) => b.upstreamFailures));

  // T6.8 — the same statuses as the chart, as totals over the range.
  const statusParts = $derived(
    statusSeries.map((s) => ({ label: s.label, color: s.color, value: s.values.reduce((a, v) => a + v, 0) })),
  );

  const totalUpstream = $derived(upstreams.reduce((a, u) => a + u.requests, 0));
  const maxTop = (items: S['TopItem'][]) => Math.max(1, ...items.map((i) => i.count));
</script>

<div class="page">
  <div class="page-head">
    <h1>Dashboard<HelpButton id="how-it-works" /></h1>
    {#if nodes.length > 1}
      <!-- REQ: CLU-002 — every node together, or one node (or site) at a time. -->
      <label class="small">
        Showing
        <select bind:value={scope} aria-label="Nodes">
          <option value="">every node</option>
          {#each nodes as n (n.nodeId)}<option value={`node:${n.nodeId}`}>{nodeLabel(n)}</option>{/each}
          {#each podSites as s (s)}<option value={`site:${s}`}>site {s} (all its nodes)</option>{/each}
        </select>
      </label>
    {/if}
    {#if groups.length > 1}
      <label class="small">
        Top lists for
        <select bind:value={group} aria-label="Group">
          <option value="">every device</option>
          {#each groups as g (g.name)}<option value={g.name}>{g.name}</option>{/each}
        </select>
      </label>
    {/if}
    <div class="seg" role="group" aria-label="Time range">
      {#each ranges as r (r.id)}
        <button aria-pressed={range.id === r.id} onclick={() => (range = r)}>{r.label}</button>
      {/each}
    </div>
  </div>

  <ErrorNote {error} />
  {#if summary?.missingNodes?.length}
    <!-- REQ: CLU-002 — a node that doesn't answer leaves partial totals, said plainly. -->
    <div class="notice warn small">
      Partial results: {summary.missingNodes.join(', ')} didn't answer, so these numbers cover the other cluster nodes.
    </div>
  {/if}

  <div class="kpis">
    <!-- More blocking or more queries isn't good or bad, so those changes stay neutral. -->
    <Kpi label="Queries" value={short(summary?.queries)} sub={`last ${range.label}${scope ? ` · ${scopeLabel}` : ''}`} delta={change(summary?.queries, previous?.queries)} spark={sparkTotal} sparkColor="--s-forwarded" />
    <Kpi label="Blocked" value={pct(summary?.blockedPercent)} sub={`${short(summary?.blocked)} queries`} tone="bad" delta={change(summary?.blockedPercent, previous?.blockedPercent)} spark={sparkBlocked} sparkColor="--s-blocked" ring={summary?.blockedPercent} />
    <Kpi label="Cache hits" value={pct(summary?.cacheHitPercent)} sub={`${short(summary?.cached)} answers`} tone="ok" delta={change(summary?.cacheHitPercent, previous?.cacheHitPercent)} good="up" spark={sparkCached} sparkColor="--s-cached" ring={summary?.cacheHitPercent} />
    <Kpi label="Upstream p90" value={ms(upstreamP90?.p90Ms)} sub={cacheP50 ? `cache p50 ${ms(cacheP50.p50Ms)}` : 'this hour'} delta={change(upstreamP90?.p90Ms, prevP90?.p90Ms)} good="down" />
    <Kpi label="Active clients" value={num(summary?.activeClients)} sub="this hour" delta={change(summary?.activeClients, previous?.activeClients)} />
    <Kpi label="NXDOMAIN / SERVFAIL" value={`${short(summary?.nxdomain)} / ${short(summary?.servfail)}`} sub={`last ${range.label}`} delta={change(summary?.servfail, previous?.servfail)} good="down" spark={sparkFailures} sparkColor="--s-blocked" />
  </div>

  {#if advanced}<SloCard {slo} />{/if}

  <div class="status-row">
    <Chart title="Queries by status" {times} series={statusSeries} stacked seconds={range.step === 'second'} />
    <section class="card">
      <h2>Answers by status</h2>
      {#if statusParts.length === 0}
        <p class="empty">No answers in this range.</p>
      {:else}
        <Donut parts={statusParts} center={`answers · ${range.label}`} format={short} />
      {/if}
    </section>
  </div>

  <!-- Advanced view only (owner, 2026-10-09), like the Service level card above. -->
  {#if advanced && (groupSeries.length > 1 || (groupSeries.length === 1 && groupSeries[0].label !== 'default'))}
    <Chart title="Traffic by group" {times} series={groupSeries} stacked seconds={range.step === 'second'} />
  {/if}

  {#if advanced}
  <div class="grid-2">
    <section class="card">
      <h2>Where time goes <span class="muted small">(this hour)</span><HelpButton id="cache" /></h2>
      {#if byPath.length + stages.length === 0}
        <p class="empty">No answers yet this hour.</p>
      {:else}
        <div class="table-wrap">
          <table class="compact">
            <thead><tr><th>Path</th><th class="num">Answers</th><th class="num">p50</th><th class="num">p90</th><th class="num">p99</th><th class="num">max</th></tr></thead>
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
      <div class="card-head"><h2>Upstreams{#if otherNode} <span class="muted small">(as this node sees them)</span>{/if}</h2><a href={href('/upstreams')} class="small">Details</a></div>
      {#if upstreams.length === 0}
        <p class="empty">No upstreams configured.</p>
      {:else}
        <ul class="bars">
          {#each upstreams as u (u.id)}
            <li>
              <div class="row">
                <strong>{u.name}</strong>
                <StatusBadge value={u.breaker} />
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

    <Chart title="Upstream exchanges" {times} series={upstreamSeries} height={160} bars seconds={range.step === 'second'} />
  {/if}

  <div class="grid-3">
    {#each [
      { title: 'Top domains', items: topDomains, link: (k: string) => href('/queries', { name: k, match: 'exact' }) },
      { title: 'Top blocked', items: topBlocked, link: (k: string) => href('/queries', { name: k, match: 'exact', status: 'blocked' }) },
      { title: 'Top clients', items: topClients, link: (k: string) => href('/queries', { client: k }) },
    ] as t (t.title)}
      <section class="card">
        <h2>{t.title} <span class="muted small">(this hour)</span></h2>
        {#if t.items.length === 0}
          <p class="empty">Nothing yet.</p>
        {:else}
          <ol class="bars">
            {#each t.items as i (i.key)}
              <li>
                <div class="row">
                  {#if t.title === 'Top clients'}
                    <span class="name"><ClientChip ip={i.key} name={i.name} onchanged={() => void load()} /></span>
                    <!-- ADR-050 — the groups whose settings apply to the device. -->
                    {#each i.groups ?? [] as g (g)}<span class="group-chip small" style:--gc={groupColor(g)}>{g}</span>{/each}
                  {:else}
                    <a class="name" href={t.link(i.key)}>{i.key}</a>
                  {/if}
                  <span class="spacer"></span>
                  <span class="num small">{num(i.count)}</span>
                </div>
                <div class="bar"><span style:width={`${(i.count / maxTop(t.items)) * 100}%`}></span></div>
              </li>
            {/each}
          </ol>
        {/if}
      </section>
    {/each}
  </div>
</div>

<style>
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
  .num {
    font-variant-numeric: tabular-nums;
  }
</style>
