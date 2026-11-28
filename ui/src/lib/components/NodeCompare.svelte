<script lang="ts" module>
  // The windows' ids and what each asks the API for; the words shown for them are in the component.
  export const COMPARE_WINDOWS = [
    { id: '1h', from: '-1h' },
    { id: '6h', from: '-6h' },
    { id: '24h', from: '-24h' },
    { id: '7d', from: '-7d' },
    { id: '30d', from: '-30d' },
  ];
</script>

<script lang="ts">
  // REQ: OBS-028 (ADR-128) — every node side by side over one window: a small multiple per
  // metric and node (the window's value and a sparkline on one scale per metric), the odd cell
  // outlined with its finding, a grey note where a node only looks worse on a smaller base, and
  // the same numbers as a table with their intervals. Phones show one metric at a time.
  import type { S } from '../api';
  import { ms, num, weekdayTime } from '../format';
  import { navigate } from '../router.svelte';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';
  import { tr } from '../i18n';
  const { t } = tr('nodeCompare');

  let {
    data,
    error,
    win,
    onwindow,
  }: { data: S['NodeCompare'] | null; error: unknown; win: string; onwindow: (id: string) => void } = $props();

  type Key = 'qps' | 'servfailPct' | 'slowPct' | 'fromCachePct' | 'upstreamFailPct' | 'p50Us' | 'p99Us';
  type Node = S['NodeNumbers'];
  const METRICS: { key: Key; label: string; series?: keyof S['NodeSeries'] }[] = [
    { key: 'qps', label: t('Queries/s'), series: 'qps' },
    { key: 'servfailPct', label: t('SERVFAIL'), series: 'servfailPct' },
    { key: 'slowPct', label: t('Slow'), series: 'slowPct' },
    { key: 'fromCachePct', label: t('From cache'), series: 'fromCachePct' },
    { key: 'upstreamFailPct', label: t('Upstream failures'), series: 'upstreamFailPct' },
    { key: 'p50Us', label: t('p50') },
    { key: 'p99Us', label: t('p99'), series: 'p99Us' },
  ];
  // The window buttons' words, by id.
  const WINDOW_LABEL: Record<string, string> = { '1h': t('1 h'), '6h': t('6 h'), '24h': t('24 h'), '7d': t('7 d'), '30d': t('30 d') };

  let table = $state(false);
  let width = $state(0);
  const narrow = $derived(width > 0 && width < 560);
  let phoneMetric = $state<Key>('servfailPct');

  // A percentage: two decimals under 10, one from 10, three under 0.1; the unit is part of the message.
  const digits = (v: number) => (v >= 10 ? v.toFixed(1) : v >= 0.1 ? v.toFixed(2) : v.toFixed(3));
  const percent = (v: number | null | undefined) => (v == null ? '–' : t('{n} %', { n: digits(v) }));
  function value(n: Node, k: Key): string {
    if (k === 'qps') return n.qps < 10 ? n.qps.toFixed(2) : num(Math.round(n.qps));
    if (k === 'p50Us' || k === 'p99Us') return ms(n[k] == null ? null : (n[k] as number) / 1000);
    return n[k === 'upstreamFailPct' ? 'upstreamQueries' : 'answered'] === 0 ? '–' : percent(n[k]);
  }
  function interval(n: Node, k: Key): string {
    const i = n.intervals[k];
    return i ? t('{value} ({low}–{high})', { value: percent(n[k] as number), low: i[0] == null ? '–' : digits(i[0]), high: percent(i[1]) }) : value(n, k);
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
    <h2>{t('Compare nodes')}<HelpButton id="cluster-compare" /></h2>
    <div class="controls">
      <div class="seg" role="group" aria-label={t('Window')}>
        {#each COMPARE_WINDOWS as w (w.id)}
          <button type="button" aria-pressed={win === w.id} onclick={() => onwindow(w.id)}>{WINDOW_LABEL[w.id]}</button>
        {/each}
      </div>
      <span class="switch-track"><label class="switch"><input type="checkbox" role="switch" bind:checked={table} data-testid="compare-table-toggle" />{t('Table')}</label></span>
    </div>
  </div>
  <ErrorNote {error} />
  {#if data}
    {#if data.missingNodes?.length}
      <p class="muted small" data-testid="compare-missing">{t('Not answering: {nodes}; the comparison covers the rest.', { nodes: data.missingNodes.join(', ') })}</p>
    {/if}
    {#if data.nodes.length < 2}
      <p class="muted" data-testid="compare-single">{t('One node; nothing to compare.')}</p>
    {:else if table}
      <div class="scroll">
        <table data-testid="compare-table">
          <thead>
            <tr>
              <th>{t('Node')}</th>
              <th class="num">{t('Answered')}</th>
              {#each METRICS as m (m.key)}<th class="num">{m.label}</th>{/each}
            </tr>
          </thead>
          <tbody>
            {#each data.nodes as n (n.nodeId)}
              <tr>
                <td>{n.label}{#if n.thisNode} <span class="muted small">{t('(this node)')}</span>{/if}</td>
                <td class="num">{num(n.answered)}</td>
                {#each METRICS as m (m.key)}
                  <td class="num" class:odd={finding(n, m.key)?.level === 'odd'}>{interval(n, m.key)}</td>
                {/each}
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      <p class="muted small">{t('Percentages with their 95 % intervals: with few answers the interval is wide, and a high share means little.')}</p>
    {:else}
      {#if narrow}
        <label class="pill-field">{t('Metric')}
          <select bind:value={phoneMetric} data-testid="compare-metric">
            {#each METRICS as m (m.key)}<option value={m.key}>{m.label}</option>{/each}
          </select>
        </label>
      {/if}
      <div class="grid" class:cards={narrow} style:--cols={data.nodes.length} data-testid="compare-grid">
        {#if !narrow}
          <div></div>
          {#each data.nodes as n (n.nodeId)}
            <div class="node">
              <strong>{n.label}</strong>{#if n.thisNode} <span class="muted small">{t('this node')}</span>{/if}
              <button type="button" class="link small" onclick={() => openDashboard(n)}>{t('Open in dashboard')}</button>
            </div>
          {/each}
        {/if}
        {#each shown as m (m.key)}
          {#if !narrow}<div class="metric">{m.label}</div>{/if}
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
                  <button type="button" class="link small" onclick={() => openDashboard(n)}>{t('Open in dashboard')}</button>
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
                  {f.detail.replace(/, since .*$/, '')}{#if f.oddSince}{t(', since {when}', { when: weekdayTime(f.oddSince) })}{/if}
                </div>
              {/if}
            </div>
          {/each}
        {/each}
      </div>
    {/if}
    {#if data.partial}
      <p class="muted small">{t("Some answers have no latency counts (an older build's), so their p50 and p99 are missing.")}</p>
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
