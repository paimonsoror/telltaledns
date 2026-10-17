<script lang="ts">
  // Time-series chart (uPlot) with a table view: every chart has one (`spec/07` §3).
  import uPlot from 'uplot';
  import 'uplot/dist/uPlot.min.css';
  import { onDestroy, untrack } from 'svelte';
  import { clock, num } from '../format';
  import type { Marker } from '../annotations.svelte';

  export interface Series {
    label: string;
    /** A CSS variable name (`--s-blocked`) or a color. */
    color: string;
    values: number[];
  }

  let {
    title,
    times,
    series,
    stacked = false,
    bars = false,
    height = 220,
    seconds = false,
    format = num,
    markers = [],
  }: {
    title: string;
    /** Unix seconds. */
    times: number[];
    series: Series[];
    stacked?: boolean;
    /** T6.8 — rounded bars instead of lines (counts per bucket). */
    bars?: boolean;
    height?: number;
    seconds?: boolean;
    format?: (n: number) => string;
    /** REQ: OBS-033 — change markers: a thin line each, hover for what and who. */
    markers?: Marker[];
  } = $props();

  // REQ: OBS-033 — markers sit over the plot as small buttons (keyboard and screen readers
  // reach them; the canvas stays untouched). Past 40 in view, those within 8 px share one, with
  // a count.
  const MAX_SINGLE = 40;
  let wrap = $state<HTMLDivElement | undefined>();
  let placed = $state<{ x: number; marks: Marker[] }[]>([]);
  let box = $state({ left: 0, top: 0, width: 0, height: 0 });
  let tip = $state<{ x: number; marks: Marker[] } | null>(null);

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
    // The last bucket covers a step past its start: a change made this minute is shown at the
    // right edge.
    const step = times.length > 1 ? times[times.length - 1] - times[times.length - 2] : 60;
    const shown = markers.filter((m) => m.time >= min && m.time < max + step);
    const col = shown.length > MAX_SINGLE ? 8 : 1;
    const cols = new Map<number, { x: number; marks: Marker[] }>();
    for (const m of shown) {
      const x = Math.min(u.valToPos(Math.min(m.time, max), 'x'), o.width - 1);
      const k = Math.round(x / col);
      const c = cols.get(k);
      if (c) c.marks.push(m);
      else cols.set(k, { x: Math.round(x), marks: [m] });
    }
    placed = [...cols.values()].sort((a, b) => a.x - b.x);
  }

  const markLabel = (marks: Marker[]) =>
    marks.map((m) => `${clock(m.time)}: ${m.summary}${m.actor ? ` (${m.actor})` : ''}`).join('; ');
  function openMark(marks: Marker[]) {
    const h = marks.find((m) => m.href)?.href;
    if (h) location.hash = h;
  }
  const inRange = $derived(
    times.length ? markers.filter((m) => m.time >= times[0] && m.time <= times[times.length - 1] + 3600) : [],
  );

  // T6.8 — smooth lines, and rounded bars drawn over each other at the same time (later series
  // on top: use it where each series is a part of the one before, like failures of queries).
  const spline = uPlot.paths.spline?.();
  const roundBars = uPlot.paths.bars?.({ size: [0.65, 18], radius: 0.3 });

  let el = $state<HTMLDivElement | undefined>();
  let width = $state(0);
  let showTable = $state(false);
  let plot: uPlot | undefined;
  let themeTick = $state(0);

  function color(c: string): string {
    if (!c.startsWith('--')) return c;
    return getComputedStyle(document.documentElement).getPropertyValue(c).trim() || '#888';
  }

  const mq = window.matchMedia('(prefers-color-scheme: dark)');
  const onTheme = () => themeTick++;
  mq.addEventListener('change', onTheme);
  const themeObserver = new MutationObserver(onTheme);
  themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

  function build() {
    plot?.destroy();
    plot = undefined;
    if (!el || width < 50 || showTable) return;
    const muted = color('--muted');
    const grid = color('--surface-2');
    // Stacked: plot running sums, drawn top band first so lower bands paint over it.
    let ys = series.map((s) => s.values);
    let order = series.map((_, i) => i);
    // A fill that fades towards the baseline.
    const fade = (c: string) => (u: uPlot) => {
      // uPlot asks for the fill before the plot box is measured on its first draw.
      if (!Number.isFinite(u.bbox?.top) || !Number.isFinite(u.bbox?.height)) return c + '80';
      const g = u.ctx.createLinearGradient(0, u.bbox.top, 0, u.bbox.top + u.bbox.height);
      g.addColorStop(0, c + 'b3');
      g.addColorStop(1, c + '33');
      return g;
    };
    if (stacked) {
      const acc = new Array(times.length).fill(0);
      ys = series.map((s) => s.values.map((v, i) => (acc[i] += v ?? 0)));
      order = order.reverse();
    }
    const opts: uPlot.Options = {
      width,
      height,
      padding: [8, 8, 0, 0],
      cursor: { points: { show: false } },
      // Placing the markers reads them: untracked, so new markers don't rebuild the plot.
      hooks: { draw: [(u: uPlot) => untrack(() => place(u))] },
      legend: {
        show: true,
        live: true,
        // Solid dots in the series color (fills can be gradients, which a marker can't show).
        markers: { width: 0, fill: (_u: uPlot, si: number) => (si > 0 ? color(series[order[si - 1]]?.color ?? '--muted') : 'transparent') },
      },
      scales: { x: { time: true } },
      axes: [
        {
          stroke: muted,
          grid: { stroke: grid, width: 1 },
          ticks: { show: false },
          // Room for "12:34 PM" so labels never run together.
          space: 80,
          // Over two days: label with the date.
          values: (_u, vals) =>
            vals.map((v) =>
              times.length > 1 && times[times.length - 1] - times[0] > 172_800
                ? new Date(v * 1000).toLocaleDateString([], { month: 'short', day: 'numeric' })
                : clock(v, seconds && times[times.length - 1] - times[0] < 180),
            ),
        },
        {
          stroke: muted,
          grid: { stroke: grid, width: 1 },
          ticks: { show: false },
          size: 52,
          values: (_u, vals) => vals.map((v) => format(v)),
        },
      ],
      series: [
        { value: (_u, v) => (v == null ? 'total' : clock(v, true)) },
        ...order.map((i) => {
          const c = color(series[i].color);
          return {
            label: series[i].label,
            stroke: c,
            width: bars ? 0 : 2,
            fill: bars ? c : stacked ? fade(c) : undefined,
            // Stacked bands keep straight edges so they meet exactly.
            paths: bars ? roundBars : stacked ? undefined : spline,
            points: { show: !bars && times.length < 3 },
            value: (_u: uPlot, _v: number | null, _si: number, idx: number | null) =>
              // Not hovering: the total over the shown range.
              format(idx == null ? series[i].values.reduce((a, v) => a + (v ?? 0), 0) : (series[i].values[idx] ?? 0)),
          } satisfies uPlot.Series;
        }),
      ],
    };
    plot = new uPlot(opts, [times, ...order.map((i) => ys[i])], el);
  }

  $effect(() => {
    // Rebuild on data, size, theme, or view changes.
    void [times, series, width, themeTick, showTable, stacked];
    build();
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
</script>

<section class="card chart">
  <div class="card-head">
    <h2>{title}</h2>
    <button class="link small" onclick={() => (showTable = !showTable)} aria-pressed={showTable}>
      {showTable ? 'Chart' : 'Table'}
    </button>
  </div>
  {#if times.length === 0}
    <p class="empty">No data yet.</p>
  {:else if showTable}
    <div class="table-wrap table-view">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            {#each series as s (s.label)}<th class="num">{s.label}</th>{/each}
          </tr>
        </thead>
        <tbody>
          {#each times as t, i (t)}
            <tr>
              <td>{clock(t, seconds)}</td>
              {#each series as s (s.label)}<td class="num">{format(s.values[i] ?? 0)}</td>{/each}
            </tr>
          {/each}
        </tbody>
      </table>
      {#if inRange.length}
        <!-- REQ: OBS-033 — the markers in this range, as rows. -->
        <table class="compact changes-table">
          <thead><tr><th>Changed</th><th>What</th></tr></thead>
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
            onmouseenter={() => (tip = p)}
            onmouseleave={() => (tip = null)}
            onfocus={() => (tip = p)}
            onblur={() => (tip = null)}
            onclick={() => openMark(p.marks)}
          >
            {#if p.marks.length > 1}<span class="mk-count">×{p.marks.length}</span>{/if}
          </button>
        {/each}
        {#if tip}
          <div class="mk-tip" role="tooltip" data-testid="marker-tip" style:left={`${Math.max(0, Math.min(tip.x + 8, box.width - 240))}px`}>
            {#each tip.marks.slice(0, 5) as m, i (i)}
              <div>
                <span class="muted">{clock(m.time)}</span>
                {m.summary}
                {#if m.actor}<span class="muted"> · {m.actor}</span>{/if}
                {#if m.nodes.length}<span class="muted"> · {m.nodes.join(', ')}</span>{/if}
              </div>
            {/each}
            {#if tip.marks.length > 5}<div class="muted">and {tip.marks.length - 5} more</div>{/if}
          </div>
        {/if}
      </div>
    {/if}
  </div>
</section>

<style>
  .plot {
    width: 100%;
    min-height: 40px;
    position: relative;
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
    margin-left: -4px;
    padding: 0;
    border: 0;
    background: none;
    cursor: pointer;
    pointer-events: auto;
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
    z-index: 2;
    max-width: 240px;
    padding: 6px 8px;
    border-radius: 8px;
    background: var(--surface);
    border: 1px solid var(--border);
    box-shadow: var(--shadow);
    font-size: 12px;
    pointer-events: none;
  }
  .changes-table {
    margin-top: 12px;
  }
  .table-view {
    max-height: 320px;
    overflow-y: auto;
  }
  .chart :global(.u-legend) {
    font-size: 12px;
    color: var(--muted);
  }
  /* The legend is a table; keep it out of the data-table header style. */
  .chart :global(.u-legend th),
  .chart :global(.u-legend td) {
    padding: 2px 6px;
    border: 0;
    text-transform: none;
    letter-spacing: normal;
    font-size: 12px;
    background: none;
  }
  /* T6.8 — a dot legend above the plot. */
  .chart :global(.uplot) {
    display: flex;
    flex-direction: column;
  }
  .chart :global(.u-legend) {
    order: -1;
    margin: 0 0 6px;
    text-align: left;
  }
  .chart :global(.u-legend .u-marker) {
    width: 9px;
    height: 9px;
    border-radius: 50%;
    border: 0 !important;
    margin-right: 6px;
  }
</style>
