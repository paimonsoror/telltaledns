<script lang="ts">
  // REQ: OBS-030 (ADR-130) — answer time as a shape over time: columns are minutes (or hours),
  // rows the `telltale_query_duration_seconds` buckets (fast at the bottom), colour how many
  // answers landed there; the latency objective's threshold dashed; exemplars as dots that open
  // their query (a trace ID the query log finds); the change markers as ticks.
  import { onDestroy } from 'svelte';
  import { api, type S } from '../api';
  import { href } from '../router.svelte';
  import { clock, ms, num } from '../format';
  import { changes } from '../annotations.svelte';
  import { strength } from '../heatmap';
  import ErrorNote from './ErrorNote.svelte';

  let {
    by = 'path',
    upstream,
    testid = 'latency-heatmap',
  }: { by?: 'path' | 'upstream'; upstream?: string; testid?: string } = $props();

  const windows = [
    { id: '1h', label: '1 h', from: '-1h', step: 'minute' },
    { id: '6h', label: '6 h', from: '-6h', step: 'minute' },
    { id: '24h', label: '24 h', from: '-24h', step: 'minute' },
    { id: '7d', label: '7 d', from: '-7d', step: 'hour' },
  ];
  const PATHS = ['cache', 'upstream', 'local', 'synthesized'];
  const PATH_LABEL: Record<string, string> = { cache: 'cache', upstream: 'upstream', local: 'local names', synthesized: 'blocked & special' };
  const PATH_COLOR: Record<string, string> = { cache: '--s-cached', upstream: '--s-forwarded', local: '--s-local', synthesized: '--s-blocked' };

  let win = $state(windows[1]);
  let paths = $state<string[]>([...PATHS]);
  let data = $state<S['LatencyHeatmap'] | null>(null);
  let exemplars = $state<S['LatencyExemplar'][]>([]);
  let thresholdMs = $state<number | null>(null);
  let error = $state<unknown>(null);
  let showTable = $state(false);
  let width = $state(0);
  let canvas = $state<HTMLCanvasElement | undefined>();
  let tip = $state<{ x: number; y: number; text: string } | null>(null);

  async function load() {
    try {
      const [h, x, slo] = await Promise.all([
        api.latencyHeatmap({ from: win.from, step: win.step, by }),
        api.latencyExemplars({ from: win.from }).catch(() => ({ items: [] as S['LatencyExemplar'][] })),
        api.slo().catch(() => null),
      ]);
      data = h;
      exemplars = x.items;
      thresholdMs = slo?.objectives.find((o) => o.name === 'latency')?.latencyMs ?? null;
      error = null;
    } catch (e) {
      error = e;
    }
  }
  $effect(() => {
    void [win, by];
    void load();
  });
  $effect(() => {
    if (data) void changes.load(data.from);
  });

  // The series drawn: the chosen paths summed, or the one upstream.
  const keys = $derived(by === 'upstream' ? (upstream ? [upstream] : Object.keys(data?.series ?? {})) : paths);
  const rows = $derived((data?.boundsUs.length ?? 16) + 1);
  const grid = $derived.by(() => {
    if (!data) return [] as number[][];
    return data.starts.map((_, c) =>
      Array.from({ length: rows }, (_, r) => keys.reduce((a, k) => a + (data!.series[k]?.[c]?.[r] ?? 0), 0)),
    );
  });
  const max = $derived(Math.max(0, ...grid.flat()));
  const shown = $derived(
    exemplars.filter((x) => (by === 'upstream' ? !upstream || x.upstream === upstream : paths.includes(x.path))),
  );

  const LABEL_W = 64;
  const ROW_H = 11;
  const top = 6;
  const geo = $derived({
    cw: data && data.starts.length ? Math.max(1, (width - LABEL_W - 4) / data.starts.length) : 1,
    h: top + rows * ROW_H + 18,
  });
  const boundLabel = (us: number) => (us >= 1_000_000 ? `${us / 1_000_000} s` : us >= 1000 ? `${us / 1000} ms` : `${us} µs`);
  const rowLabel = (r: number) => (data && r < data.boundsUs.length ? `≤ ${boundLabel(data.boundsUs[r])}` : '> 5 s');
  /** The row of a latency (the first bound at or above it). */
  const rowOf = (us: number) => {
    const i = data?.boundsUs.findIndex((b) => us <= b) ?? -1;
    return i < 0 ? rows - 1 : i;
  };
  const yOf = (r: number) => top + (rows - 1 - r) * ROW_H;
  const step = $derived(data?.step === 'hour' ? 3600 : 60);
  const xOf = (t: number) => (data ? LABEL_W + ((t - data.starts[0]) / step) * geo.cw : 0);

  const mq = window.matchMedia('(prefers-color-scheme: dark)');
  let themeTick = $state(0);
  const onTheme = () => themeTick++;
  mq.addEventListener('change', onTheme);
  const obs = new MutationObserver(onTheme);
  obs.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
  onDestroy(() => {
    mq.removeEventListener('change', onTheme);
    obs.disconnect();
  });
  const css = (v: string) => getComputedStyle(document.documentElement).getPropertyValue(v).trim() || '#888';

  $effect(() => {
    void themeTick;
    if (!canvas || !data || showTable || width <= 0) return;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = Math.round(width * dpr);
    canvas.height = Math.round(geo.h * dpr);
    canvas.style.height = `${geo.h}px`;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, width, geo.h);
    ctx.font = '10px system-ui, sans-serif';
    ctx.textBaseline = 'middle';
    const ink = css('--hm-ink');
    const bg = css('--hm-bg');
    const muted = css('--muted');
    for (let r = 0; r < rows; r++) {
      if (r % 2 === 0 || rows < 10) {
        ctx.fillStyle = muted;
        ctx.fillText(rowLabel(r), 0, yOf(r) + ROW_H / 2);
      }
    }
    grid.forEach((col, c) => {
      const x = LABEL_W + c * geo.cw;
      col.forEach((v, r) => {
        ctx.fillStyle = bg;
        ctx.fillRect(x, yOf(r), Math.max(1, geo.cw - (geo.cw > 3 ? 1 : 0)), ROW_H - 1);
        const s = strength(v, max);
        if (s > 0) {
          ctx.globalAlpha = s;
          ctx.fillStyle = ink;
          ctx.fillRect(x, yOf(r), Math.max(1, geo.cw - (geo.cw > 3 ? 1 : 0)), ROW_H - 1);
          ctx.globalAlpha = 1;
        }
      });
    });
    // The latency objective's threshold: above the row whose bound it is.
    if (thresholdMs != null) {
      const r = rowOf(thresholdMs * 1000);
      const y = yOf(r);
      ctx.strokeStyle = css('--bad');
      ctx.setLineDash([4, 3]);
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(LABEL_W, y - 0.5);
      ctx.lineTo(width, y - 0.5);
      ctx.stroke();
      ctx.setLineDash([]);
    }
    // REQ: OBS-033 — change markers as ticks along the top.
    ctx.fillStyle = muted;
    for (const m of changes.markers) {
      if (!data.starts.length || m.time < data.starts[0]) continue;
      const x = xOf(m.time);
      if (x > width) continue;
      ctx.fillRect(x, 0, 1, top + rows * ROW_H);
    }
    // Time labels.
    ctx.fillStyle = muted;
    const every = Math.max(1, Math.ceil(70 / geo.cw));
    data.starts.forEach((t, c) => {
      if (c % every === 0) ctx.fillText(win.step === 'hour' ? new Date(t * 1000).toLocaleDateString([], { month: 'short', day: 'numeric' }) : clock(t), LABEL_W + c * geo.cw, top + rows * ROW_H + 9);
    });
  });

  function move(e: MouseEvent) {
    if (!data) return;
    const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
    const x = e.clientX - r.left;
    const y = e.clientY - r.top;
    const c = Math.floor((x - LABEL_W) / geo.cw);
    const row = rows - 1 - Math.floor((y - top) / ROW_H);
    if (c < 0 || c >= data.starts.length || row < 0 || row >= rows) {
      tip = null;
      return;
    }
    const lo = row === 0 ? '0' : boundLabel(data.boundsUs[row - 1]);
    const hi = row < data.boundsUs.length ? boundLabel(data.boundsUs[row]) : 'more';
    tip = { x, y, text: `${clock(data.starts[c])} · ${lo}–${hi} · ${num(grid[c][row])} answers` };
  }
  const dotLabel = (x: S['LatencyExemplar']) =>
    `${ms(x.latencyUs / 1000)} ${PATH_LABEL[x.path] ?? x.path}${x.upstream ? ` via ${x.upstream}` : ''} at ${clock(x.tsUnixMicros / 1_000_000, true)}: open this query`;
  function togglePath(p: string) {
    paths = paths.includes(p) ? paths.filter((x) => x !== p) : [...paths, p];
  }
</script>

<div class="lh" data-testid={testid}>
  <div class="row controls">
    <div class="seg" role="group" aria-label="Window">
      {#each windows as w (w.id)}
        <button type="button" aria-pressed={win.id === w.id} onclick={() => (win = w)}>{w.label}</button>
      {/each}
    </div>
    {#if by === 'path'}
      <div class="chips" role="group" aria-label="Paths">
        {#each PATHS as p (p)}
          <button type="button" class="chip" aria-pressed={paths.includes(p)} onclick={() => togglePath(p)}>
            <i style:background={`var(${PATH_COLOR[p]})`}></i>{PATH_LABEL[p]}
          </button>
        {/each}
      </div>
    {/if}
    <span class="spacer"></span>
    <button class="link small" onclick={() => (showTable = !showTable)} aria-pressed={showTable}>{showTable ? 'Grid' : 'Table'}</button>
  </div>
  <ErrorNote {error} />
  {#if !data}
    <p class="empty">Loading…</p>
  {:else if data.starts.length === 0}
    <p class="empty">No answers in this window yet.</p>
  {:else if showTable}
    <div class="table-wrap table-view">
      <table class="compact" data-testid="{testid}-table">
        <thead><tr><th>Time</th>{#each Array.from({ length: rows }, (_, r) => r) as r (r)}<th class="num">{rowLabel(r)}</th>{/each}</tr></thead>
        <tbody>
          {#each data.starts as t, c (t)}
            <tr><td>{clock(t)}</td>{#each grid[c] as v, r (r)}<td class="num">{v ? num(v) : ''}</td>{/each}</tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
  {#if data && data.starts.length}
    <div class="plot" bind:clientWidth={width} hidden={showTable}>
      <!-- svelte-ignore a11y_no_static_element_interactions -->
      <div class="surface" onmousemove={move} onmouseleave={() => (tip = null)}>
        <canvas bind:this={canvas} data-testid="{testid}-canvas"></canvas>
        {#each shown as x, i (i)}
          {@const px = xOf(Math.floor(x.tsUnixMicros / 1_000_000 / step) * step) + geo.cw / 2}
          {#if px >= LABEL_W && px <= width}
            <a
              class="dot"
              href={href('/queries', { trace: x.traceId })}
              style:left={`${px}px`}
              style:top={`${yOf(rowOf(x.latencyUs)) + ROW_H / 2}px`}
              style:--dot={`var(${PATH_COLOR[x.path] ?? '--muted'})`}
              aria-label={dotLabel(x)}
              title={dotLabel(x)}
              data-testid="exemplar"
            ></a>
          {/if}
        {/each}
        {#if tip}<div class="tip" role="tooltip" style:left={`${Math.min(tip.x + 12, width - 240)}px`} style:top={`${tip.y + 12}px`}>{tip.text}</div>{/if}
      </div>
    </div>
    <p class="muted small">
      Darker = more answers in that time and latency band.
      {#if thresholdMs != null}<span class="thr"></span> the latency objective ({thresholdMs} ms).{/if}
      Dots are real queries: select one to open it.
      {#if data.partial}Some {data.step}s are from an older build and have no bands.{/if}
      {#if data.missingNodes?.length}Without {data.missingNodes.join(', ')}.{/if}
    </p>
  {/if}
</div>

<style>
  .controls {
    gap: 8px;
    flex-wrap: wrap;
    align-items: center;
    margin-bottom: 8px;
  }
  .chips {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
  }
  .chip {
    min-height: 26px;
    padding: 2px 10px;
    border-radius: 999px;
    font-size: 12px;
    display: inline-flex;
    gap: 6px;
    align-items: center;
  }
  .chip i {
    width: 8px;
    height: 8px;
    border-radius: 50%;
  }
  .chip[aria-pressed='false'] {
    opacity: 0.55;
  }
  .plot {
    width: 100%;
  }
  .surface {
    position: relative;
  }
  canvas {
    display: block;
    width: 100%;
  }
  .dot {
    position: absolute;
    width: 9px;
    height: 9px;
    margin: -4.5px 0 0 -4.5px;
    border-radius: 50%;
    background: var(--dot);
    border: 1.5px solid var(--surface);
  }
  .dot:hover,
  .dot:focus-visible {
    outline: 2px solid var(--focus);
    transform: scale(1.4);
  }
  @media (prefers-reduced-motion: reduce) {
    .dot:hover {
      transform: none;
    }
  }
  .tip {
    position: absolute;
    z-index: 2;
    padding: 6px 8px;
    border-radius: 8px;
    background: var(--surface);
    border: 1px solid var(--border);
    box-shadow: var(--shadow);
    font-size: 12px;
    pointer-events: none;
    white-space: nowrap;
  }
  .table-view {
    max-height: 360px;
    overflow: auto;
  }
  .thr {
    display: inline-block;
    width: 18px;
    border-top: 1px dashed var(--bad);
    vertical-align: middle;
  }
</style>
