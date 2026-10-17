<script lang="ts">
  // REQ: OBS-034 (ADR-134) — one device's day as swimlanes: a lane per domain (queries per bin,
  // blocked underlined, slow ticked), the latency lane (p99), and above them the events (first
  // contacts, anomalies, blocked bursts) and the change markers. Lane labels open the query log.
  import { api, type S } from '../api';
  import { href } from '../router.svelte';
  import { num } from '../format';
  import ErrorNote from './ErrorNote.svelte';
  import { LABEL_W, LANE_H, LAT_H, draw, geometry, hit, spans, xOf, type Timeline } from '../timeline';

  let { client }: { client: string } = $props();

  const windows = [
    { id: '1h', label: '1 h', from: '-1h' },
    { id: '6h', label: '6 h', from: '-6h' },
    { id: '24h', label: '24 h', from: '-24h' },
    { id: '3d', label: '3 d', from: '-3d' },
    { id: '7d', label: '7 d', from: '-7d' },
  ];
  let win = $state('24h');
  let data = $state<Timeline | null>(null);
  let error = $state<unknown>(null);
  let loading = $state(false);
  let table = $state(false);
  let width = $state(0);
  let canvas = $state<HTMLCanvasElement>();
  let scroller = $state<HTMLDivElement>();
  // A window wider than the screen opens on its newest end: "now" is what you came for.
  $effect(() => {
    void data;
    void table;
    if (scroller) scroller.scrollLeft = scroller.scrollWidth;
  });
  let tip = $state<{ x: number; y: number; text: string } | null>(null);
  let theme = $state(0);

  async function load() {
    loading = true;
    try {
      data = await api.timeline(client, { from: windows.find((w) => w.id === win)?.from });
      error = null;
    } catch (e) {
      data = null;
      error = e;
    } finally {
      loading = false;
    }
  }
  $effect(() => {
    void [client, win];
    void load();
  });
  // Redraw when the theme changes.
  $effect(() => {
    const o = new MutationObserver(() => theme++);
    o.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
    const m = window.matchMedia('(prefers-color-scheme: dark)');
    const bump = () => theme++;
    m.addEventListener('change', bump);
    return () => {
      o.disconnect();
      m.removeEventListener('change', bump);
    };
  });

  const g = $derived(data ? geometry(data, width) : null);
  const coverage = $derived(data?.coverageFrom ? Date.parse(data.coverageFrom) / 1000 : null);
  $effect(() => {
    void theme;
    if (!canvas || !data || !g) return;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = Math.round(g.width * dpr);
    canvas.height = Math.round(g.height * dpr);
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const css = getComputedStyle(canvas);
    const v = (n: string, f: string) => css.getPropertyValue(n).trim() || f;
    draw(ctx, data, g, { ink: v('--hm-ink', '#3b6fb6'), bad: v('--bad', '#c2413a'), warn: v('--warn', '#c98a00'), muted: v('--muted', '#888'), grid: v('--border', '#ddd') }, coverage);
  });

  const hm = (unix: number) => new Date(unix * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const day = (unix: number) => new Date(unix * 1000).toLocaleDateString([], { weekday: 'short', day: 'numeric', month: 'short' });
  const span = (bin: number) => (data ? `${hm(data.bins[bin])}–${hm(data.bins[bin] + data.binSeconds)}` : '');
  function move(e: MouseEvent) {
    if (!data || !g) return;
    const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
    const h = hit(data, g, e.clientX - r.left, e.clientY - r.top);
    if (!h) {
      tip = null;
      return;
    }
    const l = data.lanes[h.lane];
    const text = l
      ? `${span(h.bin)} · ${l.domain ?? 'a domain'} · ${num(l.counts[h.bin])} queries, ${num(l.blocked[h.bin])} blocked${l.slow[h.bin] ? `, ${num(l.slow[h.bin])} slow` : ''}`
      : `${span(h.bin)} · ${num(data.queries[h.bin])} queries · p99 ${data.p99Ms[h.bin] == null ? '–' : `${data.p99Ms[h.bin]} ms`}`;
    tip = { x: e.clientX - r.left, y: e.clientY - r.top, text };
  }
  const window_ = $derived(data ? { from: data.from, to: data.to } : {});
  const laneHref = (l: S['TimelineLane']) =>
    href('/queries', l.other || !l.domain ? { client, ...window_ } : { client, name: l.domain, match: 'suffix', ...window_ });
  const newAt = (l: S['TimelineLane']) => (l.firstSeenTime ? Date.parse(l.firstSeenTime) / 1000 : null);
  const evShape: Record<string, string> = { firstSeen: 'hollow', anomaly: 'warn', blockedBurst: 'bad', identity: 'diamond' };
  const cols = $derived(data ? spans(data) : []);
  const sum = (a: number[], f: number, t: number) => a.slice(f, t).reduce((x, y) => x + y, 0);
</script>

<div class="tl" data-testid="timeline" bind:clientWidth={width}>
  <div class="controls">
    <div class="seg" role="group" aria-label="Window">
      {#each windows as w (w.id)}
        <button type="button" aria-pressed={win === w.id} onclick={() => (win = w.id)}>{w.label}</button>
      {/each}
    </div>
    <label class="small"><input type="checkbox" bind:checked={table} data-testid="timeline-table-toggle" /> Table</label>
    {#if loading}<span class="muted small">Reading the query log…</span>{/if}
  </div>
  <ErrorNote {error} />
  {#if data}
    {#if data.truncated}
      <p class="notice warn small" data-testid="timeline-truncated">The query log read stopped early ({data.truncatedReason}): the lanes cover what it read.</p>
    {/if}
    {#if data.coverageFrom}
      <p class="muted small" data-testid="timeline-coverage">The query log starts {day(Date.parse(data.coverageFrom) / 1000)} {hm(Date.parse(data.coverageFrom) / 1000)}: the grey part has no rows.</p>
    {/if}
    {#if data.lanes.length === 0}
      <p class="empty">No queries from this device in this window.</p>
    {:else if table}
      <div class="scroll">
        <table data-testid="timeline-table">
          <thead>
            <tr><th>Domain</th><th class="num">Total</th><th class="num">Blocked</th>{#each cols as c (c.from)}<th class="num">{hm(c.start)}</th>{/each}</tr>
          </thead>
          <tbody>
            {#each data.lanes as l, i (i)}
              <tr>
                <td class="mono">{l.domain ?? '(hidden)'}</td>
                <td class="num">{num(l.total)}</td>
                <td class="num">{num(l.blockedTotal)}</td>
                {#each cols as c (c.from)}<td class="num">{sum(l.counts, c.from, c.to) || ''}</td>{/each}
              </tr>
            {/each}
            <tr class="muted">
              <td>p99 (ms)</td><td></td><td></td>
              {#each cols as c (c.from)}
                {@const v = data.p99Ms.slice(c.from, c.to).filter((x) => x != null) as number[]}
                <td class="num">{v.length ? Math.max(...v) : ''}</td>
              {/each}
            </tr>
          </tbody>
        </table>
      </div>
    {:else if g}
      <div class="scroll" bind:this={scroller} data-testid="timeline-scroll">
        <div class="inner" style:grid-template-columns="{LABEL_W}px {g.width}px">
          <div class="label sticky small muted">{day(data.bins[0])}</div>
          <div class="rail" data-testid="timeline-rail">
            {#each data.markers as m (m.tUnixMs + m.kind + (m.node ?? ''))}
              <span class="marker" style:left="{xOf(data, g, m.tUnixMs / 1000)}px" title="{hm(m.tUnixMs / 1000)} · {m.summary}" data-testid="timeline-marker"></span>
            {/each}
            {#each data.events as e, i (i)}
              <a
                class="event {evShape[e.kind] ?? ''}"
                style:left="{xOf(data, g, e.timeUnixSeconds)}px"
                href={e.href}
                title="{hm(e.timeUnixSeconds)} · {e.summary}"
                data-testid="timeline-event"
                data-kind={e.kind}
                aria-label="{hm(e.timeUnixSeconds)}: {e.summary}"
              ></a>
            {/each}
          </div>
          <div class="labels sticky">
            {#each data.lanes as l, i (i)}
              <a class="lane-label mono small" class:other={l.other} style:height="{LANE_H}px" href={laneHref(l)} data-testid="timeline-lane" title={l.domain ?? ''}
                >{l.domain ?? `domain ${i + 1}`}</a
              >
            {/each}
            <span class="lane-label small muted" style:height="{LAT_H}px">p99</span>
          </div>
          <div class="canvas-wrap" style:height="{g.height}px">
            <canvas
              bind:this={canvas}
              style:width="{g.width}px"
              style:height="{g.height}px"
              data-testid="timeline-canvas"
              data-lanes={data.lanes.length}
              data-bins={data.bins.length}
              onmousemove={move}
              onmouseleave={() => (tip = null)}
            ></canvas>
            {#each data.lanes as l, i (i)}
              {@const at = newAt(l)}
              {#if at != null && at >= data.bins[0]}
                <span class="new" style:left="{xOf(data, g, at)}px" style:top="{i * LANE_H}px" data-testid="timeline-new">new</span>
              {/if}
            {/each}
            {#if tip}
              <div class="tip small" style:left="{Math.min(tip.x + 12, g.width - 220)}px" style:top="{tip.y + 12}px" data-testid="timeline-tip">{tip.text}</div>
            {/if}
          </div>
        </div>
      </div>
      <p class="muted small">Darker is more queries; red underline: blocked; amber tick: slower than the latency objective. Dots above: <span class="key hollow"></span> first contact, <span class="key warn"></span> anomaly, <span class="key bad"></span> blocked burst, <span class="key diamond"></span> the device's identity changed; grey ticks are changes.</p>
    {/if}
  {/if}
</div>

<style>
  .controls {
    display: flex;
    flex-wrap: wrap;
    gap: 8px 12px;
    align-items: center;
    margin-bottom: 8px;
  }
  .scroll {
    overflow-x: auto;
    -webkit-overflow-scrolling: touch;
  }
  .inner {
    display: grid;
    align-items: start;
  }
  .sticky {
    position: sticky;
    left: 0;
    z-index: 2;
    background: var(--surface);
  }
  .rail {
    position: relative;
    height: 22px;
    border-bottom: 1px solid var(--border);
  }
  .labels {
    display: flex;
    flex-direction: column;
  }
  .lane-label {
    display: flex;
    align-items: center;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    padding-right: 6px;
  }
  .lane-label.other {
    font-style: italic;
  }
  .canvas-wrap {
    position: relative;
  }
  canvas {
    display: block;
  }
  .event,
  .key {
    position: absolute;
    top: 6px;
    width: 10px;
    height: 10px;
    margin-left: -5px;
    border-radius: 50%;
    background: var(--hm-ink);
  }
  .key {
    position: static;
    display: inline-block;
    margin: 0 2px;
    vertical-align: middle;
  }
  .event.hollow,
  .key.hollow {
    background: var(--surface);
    border: 2px solid var(--hm-ink);
    box-sizing: border-box;
  }
  .event.warn,
  .key.warn {
    background: var(--warn);
  }
  .event.bad,
  .key.bad {
    background: var(--bad);
  }
  /* REQ: OBS-034 (T14.12) — an identity change. */
  .event.diamond,
  .key.diamond {
    border-radius: 1px;
    transform: rotate(45deg);
    background: var(--text);
  }
  .marker {
    position: absolute;
    top: 2px;
    bottom: 2px;
    width: 1px;
    background: var(--muted);
    opacity: 0.6;
  }
  .new {
    position: absolute;
    font-size: 9px;
    line-height: 10px;
    padding: 0 2px;
    border-radius: 3px;
    background: var(--hm-ink);
    color: var(--surface);
    pointer-events: none;
  }
  .tip {
    position: absolute;
    pointer-events: none;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 4px 6px;
    white-space: nowrap;
    z-index: 3;
  }
  .num {
    text-align: right;
    font-variant-numeric: tabular-nums;
  }
</style>
