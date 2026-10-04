<script lang="ts">
  // REQ: API-005 — dashboard: KPI tiles, queries over time by status, where time goes, top
  // lists, upstream share and health (`spec/07` §3).
  import { api, type S } from '../lib/api';
  import { href } from '../lib/router.svelte';
  import { poll } from '../lib/poll';
  import { ms, num, pct, short } from '../lib/format';
  import Kpi from '../lib/components/Kpi.svelte';
  import Chart from '../lib/components/Chart.svelte';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import StatusBadge from '../lib/components/StatusBadge.svelte';

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
  let buckets = $state<S['TimeBucket'][]>([]);
  let topDomains = $state<S['TopItem'][]>([]);
  let topBlocked = $state<S['TopItem'][]>([]);
  let topClients = $state<S['TopItem'][]>([]);
  let upstreams = $state<S['UpstreamInfo'][]>([]);
  let stages = $state<S['LatencyRow'][]>([]);
  let byPath = $state<S['LatencyRow'][]>([]);
  let error = $state<unknown>(null);

  async function load() {
    const r = range;
    try {
      const [s, ts, d, b, c, u, st, lp] = await Promise.all([
        api.summary(r.summary),
        api.timeseries({ from: r.from, step: r.step }),
        api.top('domains', 10),
        api.top('blocked', 10),
        api.top('clients', 10),
        api.upstreams(),
        api.latency('stage'),
        api.latency('path'),
      ]);
      summary = s;
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
        },
      );
    }
    return out;
  }

  $effect(() => {
    void range;
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

  const totalUpstream = $derived(upstreams.reduce((a, u) => a + u.requests, 0));
  const maxTop = (items: S['TopItem'][]) => Math.max(1, ...items.map((i) => i.count));
</script>

<div class="page">
  <div class="page-head">
    <h1>Dashboard</h1>
    <div class="seg" role="group" aria-label="Time range">
      {#each ranges as r (r.id)}
        <button aria-pressed={range.id === r.id} onclick={() => (range = r)}>{r.label}</button>
      {/each}
    </div>
  </div>

  <ErrorNote {error} />

  <div class="kpis">
    <Kpi label="Queries" value={short(summary?.queries)} sub={`last ${range.label}`} />
    <Kpi label="Blocked" value={pct(summary?.blockedPercent)} sub={`${short(summary?.blocked)} queries`} tone="bad" />
    <Kpi label="Cache hits" value={pct(summary?.cacheHitPercent)} sub={`${short(summary?.cached)} answers`} tone="ok" />
    <Kpi label="Upstream p90" value={ms(upstreamP90?.p90Ms)} sub={cacheP50 ? `cache p50 ${ms(cacheP50.p50Ms)}` : 'this hour'} />
    <Kpi label="Active clients" value={num(summary?.activeClients)} sub="this hour" />
    <Kpi label="NXDOMAIN / SERVFAIL" value={`${short(summary?.nxdomain)} / ${short(summary?.servfail)}`} sub={`last ${range.label}`} />
  </div>

  <Chart title="Queries by status" {times} series={statusSeries} stacked seconds={range.step === 'second'} />

  <div class="grid-2">
    <section class="card">
      <h2>Where time goes <span class="muted small">(this hour)</span></h2>
      {#if byPath.length + stages.length === 0}
        <p class="empty">No answers yet this hour.</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead><tr><th>Path</th><th class="num">Answers</th><th class="num">p50</th><th class="num">p90</th><th class="num">p99</th><th class="num">max</th></tr></thead>
            <tbody>
              {#each [...byPath, ...stages.map((s) => ({ ...s, key: `wait: ${s.key}` }))] as r (r.key)}
                <tr>
                  <td>{r.key}</td>
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
      <div class="card-head"><h2>Upstreams</h2><a href={href('/upstreams')} class="small">Details</a></div>
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

  <Chart title="Upstream exchanges" {times} series={upstreamSeries} height={160} seconds={range.step === 'second'} />

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
                  <a class="name" href={t.link(i.key)}>{i.name ? `${i.name} (${i.key})` : i.key}</a>
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
  .kpis {
    display: grid;
    gap: 12px;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
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
    height: 4px;
    background: var(--surface-2);
    border-radius: 2px;
    margin-top: 3px;
    overflow: hidden;
  }
  .bar span {
    display: block;
    height: 100%;
    background: var(--accent);
  }
  .num {
    font-variant-numeric: tabular-nums;
  }
</style>
