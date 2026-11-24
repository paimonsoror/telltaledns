<script lang="ts" module>
  // REQ: API-011 — the window labels are keys: the window itself is an ID the API takes.
  import type { MessageKey } from '../i18n';

  export const COMPARE_WINDOWS: { id: string; label: MessageKey; from: string }[] = [
    { id: '1h', label: 'flow.window.1h', from: '-1h' },
    { id: '6h', label: 'flow.window.6h', from: '-6h' },
    { id: '24h', label: 'flow.window.24h', from: '-24h' },
    { id: '7d', label: 'flow.window.7d', from: '-7d' },
    { id: '30d', label: 'legacy.range.30d', from: '-30d' },
  ];
</script>

<script lang="ts">
  // REQ: OBS-028 (ADR-128) — every node side by side over one window: a small multiple per
  // metric and node (the window's value and a sparkline on one scale per metric), the odd cell
  // outlined with its finding, a grey note where a node only looks worse on a smaller base, and
  // the same numbers as a table with their intervals. Phones show one metric at a time.
  import type { S } from '../api';
  import { ms, num } from '../format';
  import { navigate } from '../router.svelte';
  // REQ: API-011 — the words the comparison says itself; a metric is a column of numbers.
  import { t, localeTag } from '../i18n';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';

  let {
    data,
    error,
    win,
    onwindow,
  }: { data: S['NodeCompare'] | null; error: unknown; win: string; onwindow: (id: string) => void } = $props();

  type Key = 'qps' | 'servfailPct' | 'slowPct' | 'fromCachePct' | 'upstreamFailPct' | 'p50Us' | 'p99Us';
  type Node = S['NodeNumbers'];
  // A metric's label is a key; `token` is a name nobody translates (SERVFAIL, p50, p99).
  const METRICS: { key: Key; label?: MessageKey; token?: string; series?: keyof S['NodeSeries'] }[] = [
    { key: 'qps', label: 'clusterWidgets.compare.metric.qps', series: 'qps' },
    { key: 'servfailPct', token: 'SERVFAIL', series: 'servfailPct' },
    { key: 'slowPct', label: 'clusterWidgets.compare.metric.slow', series: 'slowPct' },
    { key: 'fromCachePct', label: 'qw.cache.fromCache', series: 'fromCachePct' },
    { key: 'upstreamFailPct', label: 'clusterWidgets.compare.metric.upstreamFailures', series: 'upstreamFailPct' },
    { key: 'p50Us', token: 'p50' },
    { key: 'p99Us', token: 'p99', series: 'p99Us' },
  ];
  const metricLabel = (m: (typeof METRICS)[number]) => (m.label ? t(m.label) : (m.token ?? ''));

  let table = $state(false);
  let width = $state(0);
  const narrow = $derived(width > 0 && width < 560);
  let phoneMetric = $state<Key>('servfailPct');

  const percent = (v: number | null | undefined) =>
    v == null ? '–' : v >= 10 ? `${v.toFixed(1)} %` : v >= 0.1 ? `${v.toFixed(2)} %` : `${v.toFixed(3)} %`;
  function value(n: Node, k: Key): string {
    if (k === 'qps') return n.qps < 10 ? n.qps.toFixed(2) : num(Math.round(n.qps));
    if (k === 'p50Us' || k === 'p99Us') return ms(n[k] == null ? null : (n[k] as number) / 1000);
    return n[k === 'upstreamFailPct' ? 'upstreamQueries' : 'answered'] === 0 ? '–' : percent(n[k]);
  }
  function interval(n: Node, k: Key): string {
    const i = n.intervals[k];
    return i ? `${percent(n[k] as number)} (${percent(i[0]).replace(' %', '')}–${percent(i[1])})` : value(n, k);
  }
  const finding = (n: Node, k: Key) => data?.findings.find((f) => f.nodeId === n.nodeId && f.metric === k);

  // A sparkline on one scale for every node, so the cells compare honestly.
  const W = 120;
  const H = 28;
  function points(n: Node, k: Key): (number | null)[] {
    const m = METRICS.find((x) => x.key === k);
    return m?.series ? ((n.series[m.series] as (number | null)[]) ?? []) : [];
  }
  const scales = $derived.by(() => {
    const out: Record<string, number> = {};
    for (const m of METRICS) {
      let max = 0;
      for (const n of data?.nodes ?? []) for (const v of points(n, m.key)) if (v != null && v > max) max = v;
      out[m.key] = max;
    }
    return out;
  });
  function path(n: Node, k: Key): string {
    const vs = points(n, k);
    const max = scales[k] || 1;
    if (vs.length < 2) return '';
    let d = '';
    let pen = false;
    vs.forEach((v, i) => {
      if (v == null) {
        pen = false;
        return;
      }
      const x = (i / (vs.length - 1)) * W;
      const y = H - 1 - (v / max) * (H - 2);
      d += `${pen ? 'L' : 'M'}${x.toFixed(1)},${y.toFixed(1)}`;
      pen = true;
    });
    return d;
  }
  const since = (iso: string) => new Date(iso).toLocaleString(localeTag(), { weekday: 'short', hour: '2-digit', minute: '2-digit' });

  // "Open in dashboard": the dashboard reads its scope from this key when it opens.
  function openDashboard(n: Node) {
    try {
      localStorage.setItem('dashboard.scope', n.thisNode ? '' : `node:${n.nodeId}`);
    } catch {
      // Private windows and blocked storage: the dashboard opens on the whole cluster.
    }
    navigate('/');
  }
  const shown = $derived(narrow ? METRICS.filter((m) => m.key === phoneMetric) : METRICS);
</script>

<section class="card" data-testid="compare" bind:clientWidth={width}>
  <div class="head">
    <h2>{t('clusterWidgets.compare.title')}<HelpButton id="cluster-compare" /></h2>
    <div class="controls">
      <div class="seg" role="group" aria-label={t('dashw.window')}>
        {#each COMPARE_WINDOWS as w (w.id)}
          <button type="button" aria-pressed={win === w.id} onclick={() => onwindow(w.id)}>{t(w.label)}</button>
        {/each}
      </div>
      <span class="switch-track"><label class="switch"><input type="checkbox" role="switch" bind:checked={table} data-testid="compare-table-toggle" />{t('flow.table')}</label></span>
    </div>
  </div>
  <ErrorNote {error} />
  {#if data}
    {#if data.missingNodes?.length}
      <p class="muted small" data-testid="compare-missing">{t('clusterWidgets.compare.missing', { nodes: data.missingNodes.join(', ') })}</p>
    {/if}
    {#if data.nodes.length < 2}
      <p class="muted" data-testid="compare-single">{t('clusterWidgets.compare.single')}</p>
    {:else if table}
      <div class="scroll">
        <table data-testid="compare-table">
          <thead>
            <tr>
              <th>{t('qw.cache.node')}</th>
              <th class="num">{t('clusterWidgets.compare.col.answered')}</th>
              {#each METRICS as m (m.key)}<th class="num">{metricLabel(m)}</th>{/each}
            </tr>
          </thead>
          <tbody>
            {#each data.nodes as n (n.nodeId)}
              <tr>
                <td>{n.label}{#if n.thisNode} <span class="muted small">{t('clusterWidgets.compare.thisNode')}</span>{/if}</td>
                <td class="num">{num(n.answered)}</td>
                {#each METRICS as m (m.key)}
                  <td class="num" class:odd={finding(n, m.key)?.level === 'odd'}>{interval(n, m.key)}</td>
                {/each}
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      <p class="muted small">{t('clusterWidgets.compare.intervals')}</p>
    {:else}
      {#if narrow}
        <label class="pill-field">{t('clusterWidgets.compare.metric')}
          <select bind:value={phoneMetric} data-testid="compare-metric">
            {#each METRICS as m (m.key)}<option value={m.key}>{metricLabel(m)}</option>{/each}
          </select>
        </label>
      {/if}
      <div class="grid" class:cards={narrow} style:--cols={data.nodes.length} data-testid="compare-grid">
        {#if !narrow}
          <div></div>
          {#each data.nodes as n (n.nodeId)}
            <div class="node">
              <strong>{n.label}</strong>{#if n.thisNode} <span class="muted small">{t('legacy.thisNode')}</span>{/if}
              <button type="button" class="link small" onclick={() => openDashboard(n)}>{t('clusterWidgets.compare.openDashboard')}</button>
            </div>
          {/each}
        {/if}
        {#each shown as m (m.key)}
          {#if !narrow}<div class="metric">{metricLabel(m)}</div>{/if}
          {#each data.nodes as n (n.nodeId)}
            {@const f = finding(n, m.key)}
            <div
              class="cell"
              class:odd={f?.level === 'odd'}
              data-testid="compare-cell"
              data-node={n.label}
              data-metric={m.key}
              data-level={f?.level ?? ''}
            >
              {#if narrow}
                <div class="node">
                  <strong>{n.label}</strong>
                  <button type="button" class="link small" onclick={() => openDashboard(n)}>{t('clusterWidgets.compare.openDashboard')}</button>
                </div>
              {/if}
              <div class="big">{value(n, m.key)}</div>
              {#if m.series}
                <svg viewBox="0 0 {W} {H}" width={W} height={H} aria-hidden="true" preserveAspectRatio="none">
                  <path d={path(n, m.key)} />
                </svg>
              {/if}
              {#if f}
                <div class="finding small" class:note={f.level === 'note'} data-testid="compare-finding">
                  {f.detail.replace(/, since .*$/, '')}{#if f.oddSince}{t('clusterWidgets.compare.since', { when: since(f.oddSince) })}{/if}
                </div>
              {/if}
            </div>
          {/each}
        {/each}
      </div>
    {/if}
    {#if data.partial}
      <p class="muted small">{t('clusterWidgets.compare.partial')}</p>
    {/if}
  {/if}
</section>

<style>
  .head {
    display: flex;
    flex-wrap: wrap;
    gap: 8px 16px;
    align-items: center;
    justify-content: space-between;
  }
  .controls {
    display: flex;
    flex-wrap: wrap;
    gap: 8px 12px;
    align-items: center;
  }
  .grid {
    display: grid;
    grid-template-columns: max-content repeat(var(--cols), minmax(140px, 1fr));
    gap: 8px;
    margin-top: 12px;
    overflow-x: auto;
  }
  .grid.cards {
    grid-template-columns: 1fr;
  }
  .metric {
    color: var(--muted);
    align-self: center;
  }
  .node {
    display: flex;
    flex-wrap: wrap;
    gap: 4px 8px;
    align-items: baseline;
  }
  .cell {
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 6px 8px;
    min-width: 0;
  }
  .cell.odd {
    border: 2px solid var(--warn);
  }
  .big {
    font-size: 1.15rem;
    font-variant-numeric: tabular-nums;
  }
  svg {
    display: block;
    width: 100%;
    max-width: 240px;
  }
  svg path {
    fill: none;
    stroke: var(--accent);
    stroke-width: 1.5;
    vector-effect: non-scaling-stroke;
  }
  .cell.odd svg path {
    stroke: var(--warn);
  }
  .finding {
    margin-top: 4px;
  }
  .finding.note {
    color: var(--muted);
  }
  .scroll {
    overflow-x: auto;
  }
  td.odd {
    outline: 2px solid var(--warn);
    outline-offset: -2px;
  }
  .num {
    text-align: right;
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
  }
</style>
