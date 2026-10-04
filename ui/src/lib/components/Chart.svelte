<script lang="ts">
  // Time-series chart (uPlot) with a table view: every chart has one (`spec/07` §3).
  import uPlot from 'uplot';
  import 'uplot/dist/uPlot.min.css';
  import { onDestroy } from 'svelte';
  import { clock, num } from '../format';

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
    height = 220,
    seconds = false,
    format = num,
  }: {
    title: string;
    /** Unix seconds. */
    times: number[];
    series: Series[];
    stacked?: boolean;
    height?: number;
    seconds?: boolean;
    format?: (n: number) => string;
  } = $props();

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
    const grid = color('--border');
    // Stacked: plot running sums, drawn top band first so lower bands paint over it.
    let ys = series.map((s) => s.values);
    let order = series.map((_, i) => i);
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
      legend: { show: true, live: true },
      scales: { x: { time: true } },
      axes: [
        {
          stroke: muted,
          grid: { stroke: grid, width: 1 },
          ticks: { stroke: grid },
          values: (_u, vals) => vals.map((v) => clock(v, seconds)),
        },
        {
          stroke: muted,
          grid: { stroke: grid, width: 1 },
          ticks: { stroke: grid },
          size: 52,
          values: (_u, vals) => vals.map((v) => format(v)),
        },
      ],
      series: [
        { value: (_u, v) => (v == null ? '' : clock(v, true)) },
        ...order.map((i) => {
          const c = color(series[i].color);
          return {
            label: series[i].label,
            stroke: c,
            width: 1.5,
            fill: stacked ? c + '99' : undefined,
            points: { show: times.length < 3 },
            value: (_u: uPlot, _v: number | null, _si: number, idx: number | null) =>
              idx == null ? '' : format(series[i].values[idx] ?? 0),
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
    </div>
  {/if}
  <div class="plot" bind:clientWidth={width} hidden={showTable || times.length === 0}>
    <div bind:this={el}></div>
  </div>
</section>

<style>
  .plot {
    width: 100%;
    min-height: 40px;
  }
  .table-view {
    max-height: 320px;
    overflow-y: auto;
  }
  .chart :global(.u-legend) {
    font-size: 12px;
    color: var(--muted);
  }
  .chart :global(.u-legend .u-marker) {
    border-radius: 3px;
  }
</style>
