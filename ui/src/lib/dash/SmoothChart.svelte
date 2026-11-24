<script lang="ts">
  // REQ: API-005 (ADR-157) — the dashboard's time chart. The line is smoothed (fewer, wider
  // buckets drawn as a monotone curve, so it never overshoots), the legend is a row of totals
  // instead of a wrapping table, and hovering shows a tooltip with the exact numbers for that
  // interval. Every chart keeps its table view (`spec/07` §3), and the change markers of OBS-033.
  import uPlot from 'uplot';
  import 'uplot/dist/uPlot.min.css';
  import { onDestroy, untrack } from 'svelte';
  import { clock, num, short } from '../format';
  import type { Marker } from '../annotations.svelte';
  import { visibleMarkers } from '../markers';
  import { bucketLabel, bucketStart, rebucket, type RawSeries, type Shown } from './smooth';
  // `tr` rather than `t`: the table below walks its times as `t`.
  import { t as tr, localeTag } from '../i18n';

  let {
    title,
    times,
    series,
    mode = 'area',
    height = 220,
    format = num,
    maxPoints = 0,
    legend = true,
    tableToggle = true,
    sync = '',
    yMax = 0,
    axes = 'full',
    markers = [],
  }: {
    title: string;
    /** Unix seconds, one per source bucket. */
    times: number[];
    series: RawSeries[];
    /** `area`: each series over the others, softly filled; `stack`: bands that add up; `line`: lines only. */
    mode?: 'area' | 'stack' | 'line';
    height?: number;
    format?: (n: number) => string;
    /** Most points to draw (0 = by width, about one per 6 px). */
    maxPoints?: number;
    legend?: boolean;
    tableToggle?: boolean;
    /** Charts that share a key share their cursor. */
    sync?: string;
    yMax?: number;
    /** `minimal`: no vertical gridlines, a lighter value axis. */
    axes?: 'full' | 'minimal';
    /** REQ: OBS-033 — change markers: a thin line each, hover for what and who. */
    markers?: Marker[];
  } = $props();

  // REQ: OBS-033 — markers sit over the plot as small buttons (keyboard and screen readers reach
  // them; the canvas stays untouched). Past 40 in view, those within 8 px share one, with a count.
  const MAX_SINGLE = 40;
  let wrap = $state<HTMLDivElement | undefined>();
  let placed = $state<{ x: number; marks: Marker[] }[]>([]);
  let box = $state({ left: 0, top: 0, width: 0, height: 0 });
  let mtip = $state<{ x: number; marks: Marker[] } | null>(null);

  function place(u: uPlot) {
    const min = u.scales.x.min;
    const max = u.scales.x.max;
    if (!wrap || min == null || max == null || markers.length === 0) {
      placed = [];
      return;
    }
    const o = u.over.getBoundingClientRect();
    const w = wrap.getBoundingClientRect();
    box = { left: o.left - w.left, top: o.top - w.top, width: o.width, height: o.height };
    // The chart leaves the newest, still-filling bucket off, but a change made this minute is
    // shown, at the right edge: markers run to the end of the raw data, or to now when that is
    // later (a note saved just after the minute turned has no bucket yet; GitHub issue #39).
    const rawStep = times.length > 1 ? times[1] - times[0] : 60;
    const rawEnd = (times[times.length - 1] ?? max) + rawStep;
    const shownMarks = visibleMarkers(markers, min, rawEnd, Date.now() / 1000);
    const col = shownMarks.length > MAX_SINGLE ? 8 : 1;
    const cols = new Map<number, { x: number; marks: Marker[] }>();
    for (const m of shownMarks) {
      const x = Math.min(u.valToPos(Math.min(m.time, max), 'x'), o.width - 1);
      const k = Math.round(x / col);
      const c = cols.get(k);
      if (c) c.marks.push(m);
      else cols.set(k, { x: Math.round(x), marks: [m] });
    }
    placed = [...cols.values()].sort((a, b) => a.x - b.x);
  }
  const markLabel = (marks: Marker[]) => marks.map((m) => `${clock(m.time)}: ${m.summary}${m.actor ? ` (${m.actor})` : ''}`).join('; ');
  function openMark(marks: Marker[]) {
    const h = marks.find((m) => m.href)?.href;
    if (h) location.hash = h;
  }
  const inRange = $derived(times.length ? markers.filter((m) => m.time >= times[0] && m.time <= times[times.length - 1] + 3600) : []);

  let el = $state<HTMLDivElement | undefined>();
  let width = $state(0);
  let tipW = $state(150);
  let showTable = $state(false);
  let themeTick = $state(0);
  let hover = $state<{ i: number; x: number; y: number } | null>(null);
  let plot: uPlot | undefined;
  let lastSig = '';

  const mq = window.matchMedia('(prefers-color-scheme: dark)');
  const onTheme = () => themeTick++;
  mq.addEventListener('change', onTheme);
  const themeObserver = new MutationObserver(onTheme);
  themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

  const css = (c: string) => (c.startsWith('--') ? `var(${c})` : c);
  function color(c: string): string {
    if (!c.startsWith('--')) return c;
    return getComputedStyle(document.documentElement).getPropertyValue(c).trim() || '#888';
  }

  const pts = $derived(maxPoints || Math.max(24, Math.min(120, Math.round(width / 6))));
  const view = $derived(rebucket(times, series, pts));
  const multiDay = $derived(times.length > 1 && times[times.length - 1] - times[0] > 172_800);
  const h = $derived(width && width < 480 ? Math.min(height, 190) : height);
  // A short chart has no room for a tall tooltip: say less, in less width.
  const compact = $derived(h <= 170);

  const pctText = (v: number) => `${v.toFixed(v < 10 ? 1 : 0)}%`;
  const fmt = (s: Shown, v: number) => (s.den ? pctText(v) : format(v));
  const allRatio = $derived(view.series.length > 0 && view.series.every((s) => s.den));
  // The value axis is narrow: compact numbers there (10K), exact ones in the tooltip and the table.
  const axisFmt = (v: number) => (allRatio ? `${v}%` : format === num ? short(v) : format(v));

  function layout() {
    let ys = view.series.map((s) => s.shown);
    let order = view.series.map((_, i) => i);
    if (mode === 'stack') {
      const acc = new Array(view.times.length).fill(0);
      ys = view.series.map((s) => s.shown.map((v, i) => (acc[i] += v)));
      // Draw the top band first, so lower bands paint over it.
      order = order.reverse();
    }
    return { ys, order };
  }

  function build() {
    plot?.destroy();
    plot = undefined;
    hover = null;
    if (!el || width < 50 || showTable || view.times.length === 0) return;
    const muted = color('--muted');
    const grid = color('--surface-2');
    const surface = color('--surface');
    const { ys, order } = layout();
    const fade = (c: string) => (u: uPlot) => {
      if (!Number.isFinite(u.bbox?.top) || !Number.isFinite(u.bbox?.height)) return c + '55';
      const g = u.ctx.createLinearGradient(0, u.bbox.top, 0, u.bbox.top + u.bbox.height);
      g.addColorStop(0, c + (mode === 'stack' ? 'cc' : '66'));
      g.addColorStop(1, c + (mode === 'stack' ? '44' : '08'));
      return g;
    };
    const sparse = view.times.length < 3;
    const opts: uPlot.Options = {
      width,
      height: h,
      padding: [10, 8, 0, 0],
      legend: { show: false },
      cursor: {
        x: true,
        y: false,
        drag: { x: false, y: false, setScale: false },
        points: {
          size: 8,
          width: 2,
          stroke: (_u: uPlot, si: number) => color(view.series[order[si - 1]]?.color ?? '--muted'),
          fill: () => surface,
        },
        ...(sync ? { sync: { key: sync } } : {}),
      },
      hooks: {
        // Placing the markers reads them: untracked, so new markers don't rebuild the plot.
        draw: [(u: uPlot) => untrack(() => place(u))],
        setCursor: [
          (u: uPlot) =>
            untrack(() => {
              const i = u.cursor.idx;
              const left = u.cursor.left;
              if (i == null || left == null || left < 0) {
                if (hover) hover = null;
                return;
              }
              hover = { i, x: u.over.offsetLeft + left, y: u.over.offsetTop + 6 };
            }),
        ],
      },
      scales: {
        x: { time: true },
        y: { range: (_u, _min, max) => [0, yMax || Math.max(1, max * 1.12)] },
      },
      axes: [
        {
          stroke: muted,
          grid: axes === 'minimal' ? { show: false } : { stroke: grid, width: 1 },
          ticks: { show: false },
          space: width < 500 ? 70 : 96,
          values: (_u, vals) =>
            vals.map((v) =>
              multiDay
                ? new Date(v * 1000).toLocaleDateString(localeTag(), { month: 'short', day: 'numeric' })
                : clock(v, view.span < 60 && view.times[view.times.length - 1] - view.times[0] < 180),
            ),
        },
        {
          stroke: muted,
          grid: { stroke: grid, width: 1, dash: axes === 'minimal' ? [3, 4] : [] },
          ticks: { show: false },
          size: axes === 'minimal' ? 40 : 50,
          space: 44,
          values: (_u, vals) => vals.map((v) => axisFmt(v)),
        },
      ],
      series: [
        {},
        ...order.map((i) => {
          const c = color(view.series[i].color);
          return {
            label: view.series[i].label,
            stroke: c,
            width: 2,
            fill: mode === 'line' ? undefined : fade(c),
            paths: uPlot.paths.spline?.(),
            points: { show: sparse },
          } satisfies uPlot.Series;
        }),
      ],
    };
    plot = new uPlot(opts, [view.times, ...order.map((i) => ys[i])], el);
  }

  $effect(() => {
    // Rebuild when the shape changes; when only the numbers moved (a poll), just swap the data,
    // so a tooltip being read isn't wiped.
    void [view, width, h, themeTick, showTable, mode, axes, yMax];
    untrack(() => {
      const sig = [width, h, themeTick, showTable, mode, axes, yMax, view.span, view.times.length, view.series.map((s) => s.label + s.color).join(',')].join('|');
      if (plot && sig === lastSig) {
        const { ys, order } = layout();
        plot.setData([view.times, ...order.map((i) => ys[i])]);
      } else {
        lastSig = sig;
        build();
      }
    });
  });

  // New markers move only the overlay, not the plot.
  $effect(() => {
    void markers;
    if (plot) place(plot);
    else placed = [];
  });

  onDestroy(() => {
    plot?.destroy();
    mq.removeEventListener('change', onTheme);
    themeObserver.disconnect();
  });

  const tipLeft = $derived(
    hover ? Math.max(0, hover.x + 14 + tipW > width ? hover.x - tipW - 14 : hover.x + 14) : 0,
  );
  const hoverTotal = $derived(
    hover && mode === 'stack' && view.series.length > 1 && !allRatio ? view.series.reduce((a, s) => a + (s.shown[hover!.i] ?? 0), 0) : null,
  );
</script>

<figure class="sc" aria-label={title}>
  {#if legend || tableToggle}
    <div class="bar" class:solo={!legend}>
      {#if legend && view.series.length}
        <ul class="legend">
          {#each view.series as s (s.label)}
            <li><i style:background={css(s.color)}></i><span>{s.label}</span><b>{fmt(s, s.total)}</b></li>
          {/each}
        </ul>
      {/if}
      <span class="spacer"></span>
      {#if tableToggle}
        <button class="link small" onclick={() => (showTable = !showTable)} aria-pressed={showTable}>{showTable ? tr('dashboard.chart') : tr('flow.table')}</button>
      {/if}
    </div>
  {/if}
  {#if times.length === 0}
    <p class="empty">{tr('dashboard.noData')}</p>
  {/if}
  {#if showTable}
    <div class="table-wrap table-view" class:below={!legend}>
      <table class="compact">
        <thead>
          <tr>
            <th>{tr('dashw.time')}</th>
            {#each view.series as s (s.label)}<th class="num">{s.label}</th>{/each}
          </tr>
        </thead>
        <tbody>
          {#each view.times as t, i (t)}
            <tr>
              <td>{bucketLabel(t, view.span, multiDay)}</td>
              {#each view.series as s (s.label)}<td class="num">{fmt(s, s.shown[i] ?? 0)}</td>{/each}
            </tr>
          {/each}
        </tbody>
      </table>
      {#if inRange.length}
        <!-- REQ: OBS-033 — the markers in this range, as rows. -->
        <table class="compact changes-table">
          <thead><tr><th>{tr('dashboard.changed')}</th><th>{tr('dashboard.what')}</th></tr></thead>
          <tbody>
            {#each inRange as m, i (i)}
              <tr><td>{clock(m.time)}</td><td>{m.summary}{#if m.actor} · {m.actor}{/if}{#if m.nodes.length} · {m.nodes.join(', ')}{/if}</td></tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </div>
  {/if}
  <div class="plot" bind:this={wrap} bind:clientWidth={width} hidden={showTable || times.length === 0}>
    <div bind:this={el}></div>
    {#if placed.length}
      <div
        class="mk-layer"
        data-testid="chart-markers"
        style:left={`${box.left}px`}
        style:top={`${box.top}px`}
        style:width={`${box.width}px`}
        style:height={`${box.height}px`}
      >
        {#each placed as p (p.x)}
          <button
            type="button"
            class="mk"
            class:note={p.marks.every((m) => m.kind === 'note')}
            data-kind={p.marks[0].kind}
            style:left={`${p.x}px`}
            aria-label={markLabel(p.marks)}
            onmouseenter={() => (mtip = p)}
            onmouseleave={() => (mtip = null)}
            onfocus={() => (mtip = p)}
            onblur={() => (mtip = null)}
            onclick={() => openMark(p.marks)}
          >
            {#if p.marks.length > 1}<span class="mk-count">×{p.marks.length}</span>{/if}
          </button>
        {/each}
        {#if mtip}
          <div class="mk-tip" role="tooltip" data-testid="marker-tip" style:left={`${Math.max(0, Math.min(mtip.x + 8, box.width - 240))}px`}>
            {#each mtip.marks.slice(0, 5) as m, i (i)}
              <div>
                <span class="muted">{clock(m.time)}</span>
                {m.summary}
                {#if m.actor}<span class="muted"> · {m.actor}</span>{/if}
                {#if m.nodes.length}<span class="muted"> · {m.nodes.join(', ')}</span>{/if}
              </div>
            {/each}
            {#if mtip.marks.length > 5}<div class="muted">{tr('dashboard.andMore', { n: mtip.marks.length - 5 })}</div>{/if}
          </div>
        {/if}
      </div>
    {/if}
    {#if hover && view.times[hover.i] != null}
      <div class="tip" class:compact role="tooltip" bind:clientWidth={tipW} style:left={`${tipLeft}px`} style:top={`${hover.y}px`}>
        <div class="when">{compact ? bucketStart(view.times[hover.i], view.span, multiDay) : bucketLabel(view.times[hover.i], view.span, multiDay)}</div>
        {#each view.series as s (s.label)}
          <div class="line"><i style:background={css(s.color)}></i><span>{s.label}</span><b>{fmt(s, s.shown[hover.i] ?? 0)}</b></div>
        {/each}
        {#if hoverTotal != null}
          <div class="line sum"><span>{tr('dashboard.total')}</span><b>{format(hoverTotal)}</b></div>
        {/if}
      </div>
    {/if}
  </div>
</figure>

<style>
  .sc {
    position: relative;
    margin: 0;
    min-width: 0;
  }
  /* Without a legend the Table link sits in the chart's corner instead of taking a row. */
  .bar.solo {
    position: absolute;
    top: 0;
    right: 0;
    z-index: 2;
    margin: 0;
    min-height: 0;
  }
  .table-view.below {
    margin-top: 24px;
  }
  .bar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 4px 12px;
    margin-bottom: 6px;
    min-height: 24px;
  }
  .legend {
    display: flex;
    flex-wrap: wrap;
    gap: 2px 16px;
    list-style: none;
    margin: 0;
    padding: 0;
    font-size: 12.5px;
    color: var(--muted);
  }
  .legend li,
  .line {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .legend i,
  .line i {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    flex: none;
  }
  .legend b {
    color: var(--text);
    font-weight: 600;
    font-variant-numeric: tabular-nums;
  }
  .plot {
    position: relative;
    width: 100%;
    min-height: 40px;
  }
  .tip {
    position: absolute;
    z-index: 3;
    min-width: 150px;
    max-width: 260px;
    padding: 8px 10px;
    border-radius: 10px;
    background: var(--surface);
    border: 1px solid var(--border);
    box-shadow: 0 8px 24px rgb(0 0 0 / 18%);
    font-size: 12.5px;
    pointer-events: none;
  }
  .when {
    color: var(--muted);
    margin-bottom: 4px;
    white-space: nowrap;
  }
  .tip.compact {
    min-width: 0;
    padding: 5px 8px;
    font-size: 12px;
  }
  .tip.compact .when {
    margin-bottom: 1px;
  }
  .line {
    padding: 1px 0;
  }
  .line b {
    margin-left: auto;
    padding-left: 14px;
    font-variant-numeric: tabular-nums;
  }
  .line.sum {
    margin-top: 3px;
    padding-top: 4px;
    border-top: 1px solid var(--surface-2);
    color: var(--muted);
  }
  .line.sum b {
    color: var(--text);
  }
  .table-view {
    max-height: 300px;
    overflow-y: auto;
  }
  .changes-table {
    margin-top: 12px;
  }
  /* REQ: OBS-033 — change markers. The layer lets the plot's own hover through. */
  .mk-layer {
    position: absolute;
    pointer-events: none;
  }
  .mk {
    position: absolute;
    top: 0;
    bottom: 0;
    width: 9px;
    min-height: 0;
    margin-left: -4px;
    padding: 0;
    border: 0;
    border-radius: 0;
    background: none;
    cursor: pointer;
    pointer-events: auto;
  }
  .mk:hover {
    background: none;
  }
  .mk::before {
    content: '';
    position: absolute;
    left: 4px;
    top: 0;
    bottom: 0;
    width: 1px;
    background: var(--mk-ink);
    opacity: 0.7;
  }
  /* The kind's glyph, just above the x axis: a diamond; a note is a dot in its own colour. */
  .mk::after {
    content: '';
    position: absolute;
    left: 1px;
    bottom: 1px;
    width: 7px;
    height: 7px;
    background: var(--mk-ink);
    transform: rotate(45deg);
  }
  .mk.note::before {
    background: var(--mk-note);
  }
  .mk.note::after {
    background: var(--mk-note);
    border-radius: 50%;
    transform: none;
  }
  .mk:hover::before,
  .mk:focus-visible::before {
    opacity: 1;
    width: 2px;
  }
  .mk:focus-visible {
    outline: 2px solid var(--focus);
    outline-offset: 0;
  }
  .mk-count {
    position: absolute;
    top: 0;
    left: 6px;
    font-size: 10px;
    line-height: 1;
    padding: 1px 3px;
    border-radius: 6px;
    background: var(--surface-2);
    color: var(--text);
    white-space: nowrap;
  }
  .mk-tip {
    position: absolute;
    top: 4px;
    z-index: 4;
    max-width: 240px;
    padding: 6px 8px;
    border-radius: 8px;
    background: var(--surface);
    border: 1px solid var(--border);
    box-shadow: var(--shadow);
    font-size: 12px;
    pointer-events: none;
  }
  .sc :global(.u-cursor-x) {
    border-right: 1px dashed var(--muted) !important;
    opacity: 0.7;
  }
  .sc :global(.u-over) {
    touch-action: pan-y;
  }
</style>
