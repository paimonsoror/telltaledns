<script lang="ts">
  // REQ: OBS-029 (ADR-129) — the rhythm heatmap: when the network (or one device, or one name)
  // asks, as days × time of day. The Traffic map says what; this says when. Built on the time
  // buckets and the hourly top lists: nothing new is counted.
  import { onDestroy } from 'svelte';
  import { api, type S } from '../lib/api';
  import { href, navigate, route } from '../lib/router.svelte';
  import { num } from '../lib/format';
  import { changes } from '../lib/annotations.svelte';
  import { draw, geometry, height, hit, layout, locate, type Grid } from '../lib/heatmap';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';

  type Kind = 'network' | 'client' | 'name';
  const windows = [
    { id: '24h', label: '24 h', from: '-24h', days: 1 },
    { id: '7d', label: '7 d', from: '-7d', days: 7 },
    { id: '30d', label: '30 d', from: '-30d', days: 30 },
    { id: '90d', label: '90 d', from: '-90d', days: 90 },
  ];
  const p = route.params;
  let kind = $state<Kind>((['network', 'client', 'name'].includes(p.get('kind') ?? '') ? p.get('kind') : 'network') as Kind);
  let key = $state(p.get('key') ?? '');
  let keyInput = $state(p.get('key') ?? '');
  let win = $state(windows.find((w) => w.id === p.get('window')) ?? windows[1]);
  let grain = $state(p.get('grain') ?? '15m');
  let measure = $state<'queries' | 'blocked'>(p.get('measure') === 'blocked' ? 'blocked' : 'queries');
  let fold = $state(p.get('fold') === '1');
  let data = $state<S['Heatmap'] | null>(null);
  let error = $state<unknown>(null);
  let showTable = $state(false);
  let width = $state(0);
  let canvas = $state<HTMLCanvasElement | undefined>();
  let focus = $state<[number, number] | null>(null);
  let tip = $state<{ x: number; y: number; text: string } | null>(null);

  // Finer grains only where the data has them: the network, within 7 days; phones get hours.
  const effectiveGrain = $derived(kind !== 'network' || win.days > 7 || width < 480 ? 'hour' : grain);

  async function load() {
    if (kind !== 'network' && !key) {
      data = null;
      return;
    }
    try {
      data = await api.heatmap({
        from: win.from,
        grain: effectiveGrain,
        kind,
        key: kind === 'network' ? undefined : key,
        measure: kind === 'client' ? 'queries' : measure,
      });
      error = null;
    } catch (e) {
      data = null;
      error = e;
    }
  }
  $effect(() => {
    void [kind, key, win, effectiveGrain, measure];
    void load();
  });
  $effect(() => {
    if (data) void changes.load(data.from);
  });

  const grid = $derived<Grid | null>(
    data ? layout(data.starts, data.values, data.covered ?? null, data.slotSeconds, fold) : null,
  );
  const geo = $derived(grid && width > 0 ? geometry(grid, width, 96, 52) : null);

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
    if (!canvas || !grid || !geo || showTable) return;
    const dpr = window.devicePixelRatio || 1;
    const h = height(grid, geo);
    canvas.width = Math.round(width * dpr);
    canvas.height = Math.round(h * dpr);
    canvas.style.height = `${h}px`;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, width, h);
    const ticks = fold
      ? []
      : changes.markers.map((m) => locate(grid, m.time)).filter((x): x is { row: number; col: number } => x != null);
    draw(
      ctx,
      grid,
      geo,
      {
        ink: css(measure === 'blocked' ? '--hm-ink-blocked' : '--hm-ink'),
        bg: css('--hm-bg'),
        muted: css('--muted'),
        hatch: css('--hm-hatch'),
      },
      focus,
      ticks,
    );
  });

  function slotText(ri: number, ci: number): string {
    if (!grid) return '';
    const c = grid.cells[ri][ci];
    const mins = (ci * grid.slot) / 60;
    const end = mins + grid.slot / 60;
    const hm = (m: number) => `${String(Math.floor(m / 60) % 24).padStart(2, '0')}:${String(m % 60).padStart(2, '0')}`;
    const when = `${grid.rows[ri].label} ${hm(mins)}–${hm(end)}`;
    if (!c.covered) return `${when} · below this hour's top list`;
    if (c.value == null) return `${when} · no data`;
    const what = measure === 'blocked' ? 'blocked queries' : 'queries';
    return fold
      ? `${when} · ${num(Math.round(c.value))} ${what} on average over ${c.days} day${c.days === 1 ? '' : 's'}`
      : `${when} · ${num(c.value)} ${what}`;
  }
  function show(ri: number, ci: number, x: number, y: number) {
    tip = { x, y, text: slotText(ri, ci) };
  }
  function move(e: MouseEvent) {
    if (!grid || !geo) return;
    const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
    const at = hit(grid, geo, e.clientX - r.left, e.clientY - r.top);
    if (!at) {
      tip = null;
      return;
    }
    show(at[0], at[1], e.clientX - r.left, e.clientY - r.top);
  }
  /** The query log for one cell (from its start; folded cells, the latest day). */
  function cellLink(ri: number, ci: number): string | undefined {
    if (!grid) return undefined;
    const c = grid.cells[ri][ci];
    if (!c.start) return undefined;
    const from = new Date(c.start * 1000).toISOString();
    const status = measure === 'blocked' ? 'blocked' : undefined;
    if (kind === 'client') return href('/queries', { client: key, from });
    if (kind === 'name') return href('/queries', { name: key, match: 'exact', from, status });
    return href('/queries', { from, status });
  }
  function open(ri: number, ci: number) {
    const to = cellLink(ri, ci);
    if (to) location.hash = to;
  }
  function click(e: MouseEvent) {
    if (!grid || !geo) return;
    const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
    const at = hit(grid, geo, e.clientX - r.left, e.clientY - r.top);
    if (at) open(at[0], at[1]);
  }
  function keydown(e: KeyboardEvent) {
    if (!grid || !geo) return;
    const [ri, ci] = focus ?? [0, 0];
    const moves: Record<string, [number, number]> = {
      ArrowRight: [ri, Math.min(grid.cols - 1, ci + 1)],
      ArrowLeft: [ri, Math.max(0, ci - 1)],
      ArrowDown: [Math.min(grid.rows.length - 1, ri + 1), ci],
      ArrowUp: [Math.max(0, ri - 1), ci],
      Home: [ri, 0],
      End: [ri, grid.cols - 1],
    };
    if (e.key === 'Enter') {
      e.preventDefault();
      open(ri, ci);
      return;
    }
    const to = moves[e.key];
    if (!to) return;
    e.preventDefault();
    focus = to;
    show(to[0], to[1], geo.x0 + to[1] * geo.cw, geo.y0 + to[0] * geo.ch);
  }
  function setKey(e: SubmitEvent) {
    e.preventDefault();
    key = keyInput.trim();
    navigate('/heatmap', { kind, key, window: win.id }, true);
  }
  const kinds: { id: Kind; label: string }[] = [
    { id: 'network', label: 'Network' },
    { id: 'client', label: 'Device' },
    { id: 'name', label: 'Name' },
  ];
  // The table view: one row per day (or weekday), hours as columns (finer slots summed).
  const table = $derived.by(() => {
    if (!grid) return [];
    const per = Math.max(1, Math.round(3600 / grid.slot));
    return grid.rows.map((r, ri) => ({
      label: r.label,
      hours: Array.from({ length: 24 }, (_, h) => {
        const cs = grid.cells[ri].slice(h * per, (h + 1) * per);
        if (cs.some((c) => !c.covered)) return '–';
        const v = cs.reduce((a, c) => a + (c.value ?? 0), 0);
        return fold ? num(Math.round(v)) : num(v);
      }),
    }));
  });
</script>

<div class="page">
  <div class="page-head">
    <h1>Heatmap<HelpButton id="heatmap" /></h1>
    <div class="row controls">
      <div class="seg" role="group" aria-label="What">
        {#each kinds as k (k.id)}
          <button type="button" aria-pressed={kind === k.id} onclick={() => (kind = k.id)}>{k.label}</button>
        {/each}
      </div>
      <div class="seg" role="group" aria-label="Window">
        {#each windows as w (w.id)}
          <button type="button" aria-pressed={win.id === w.id} onclick={() => (win = w)}>{w.label}</button>
        {/each}
      </div>
      {#if kind === 'network' && win.days <= 7}
        <span class="pill-field bare">
          <select bind:value={grain} aria-label="Slot">
            <option value="hour">hours</option>
            <option value="15m">15 minutes</option>
            <option value="minute">minutes</option>
          </select>
        </span>
      {/if}
      {#if kind !== 'client'}
        <span class="pill-field bare">
          <select bind:value={measure} aria-label="Count">
            <option value="queries">queries</option>
            <option value="blocked">blocked</option>
          </select>
        </span>
      {/if}
      <span class="switch-track"><label class="switch"><input type="checkbox" role="switch" bind:checked={fold} data-testid="heatmap-fold" />Typical week</label></span>
    </div>
  </div>
  {#if kind !== 'network'}
    <form class="row keyform" onsubmit={setKey}>
      <input
        bind:value={keyInput}
        placeholder={kind === 'client' ? 'a device address, e.g. 192.168.2.14' : 'a name, e.g. pool.ntp.org'}
        aria-label={kind === 'client' ? 'Device address' : 'Name'}
        data-testid="heatmap-key"
      />
      <button type="submit">Show</button>
    </form>
  {/if}

  <ErrorNote {error} />

  <section class="card" data-testid="heatmap">
    <div class="card-head">
      <h2>
        {#if kind === 'network'}The whole network{:else if key}{key}{:else}Pick a {kind === 'client' ? 'device' : 'name'}{/if}
        {#if data}<span class="muted small">· {data.grain === '15m' ? '15-minute' : data.grain} slots, your local time</span>{/if}
      </h2>
      {#if kind === 'client' && key}
        <!-- REQ: OBS-034 — the device's day, lane by lane. -->
        <a class="small" href={href('/clients', { device: key, view: 'timeline' })} data-testid="heatmap-day">Day timeline</a>
      {/if}
      <button class="link small" onclick={() => (showTable = !showTable)} aria-pressed={showTable}>{showTable ? 'Grid' : 'Table'}</button>
    </div>
    {#if data?.missingNodes?.length}<p class="small muted">Without {data.missingNodes.join(', ')}: they didn't answer.</p>{/if}
    {#if !data}
      <p class="empty">{kind === 'network' || key ? 'Loading…' : 'Enter one above.'}</p>
    {:else if showTable}
      <div class="table-wrap table-view">
        <table class="compact" data-testid="heatmap-table">
          <thead><tr><th>Day</th>{#each Array.from({ length: 24 }, (_, h) => h) as h (h)}<th class="num">{String(h).padStart(2, '0')}</th>{/each}</tr></thead>
          <tbody>
            {#each table as r, i (i)}
              <tr><td>{r.label}</td>{#each r.hours as v, j (j)}<td class="num">{v}</td>{/each}</tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
    <div class="grid-wrap" bind:clientWidth={width} hidden={!data || showTable}>
      <div
        class="grid-focus"
        tabindex="0"
        role="grid"
        aria-roledescription="heatmap"
        aria-label="Heatmap: rows are days, columns times of day. Arrow keys move between cells, Enter opens the query log."
        data-testid="heatmap-canvas"
        onmousemove={move}
        onmouseleave={() => (tip = null)}
        onclick={click}
        onkeydown={keydown}
        onblur={() => (tip = null)}
      >
        <canvas bind:this={canvas}></canvas>
      </div>
      {#if tip}<div class="tip" role="tooltip" data-testid="heatmap-tip" style:left={`${Math.min(tip.x + 12, width - 260)}px`} style:top={`${tip.y + 12}px`}>{tip.text}</div>{/if}
    </div>
    {#if data}
      <p class="muted small legend">
        Stronger colour = more {measure === 'blocked' ? 'blocked queries' : 'queries'}; bars at the right and bottom sum each row and column.
        {#if data.precision === 'topList'}Counts come from each hour's top 100: <span class="hatch-sw"></span> hatched hours had this one below the list.{/if}
        Select a cell for its queries (the query log keeps fewer days than the heatmap).
      </p>
    {/if}
  </section>
</div>

<style>
  .controls {
    gap: 8px;
    flex-wrap: wrap;
    align-items: center;
  }
  .keyform {
    gap: 8px;
    margin-bottom: 12px;
  }
  .keyform input {
    flex: 1 1 240px;
  }
  .grid-wrap {
    position: relative;
    width: 100%;
  }
  canvas {
    display: block;
    width: 100%;
  }
  .grid-focus {
    cursor: pointer;
  }
  .grid-focus:focus-visible {
    outline: 2px solid var(--focus);
  }
  .tip {
    position: absolute;
    z-index: 2;
    max-width: 260px;
    padding: 6px 8px;
    border-radius: 8px;
    background: var(--surface);
    border: 1px solid var(--border);
    box-shadow: var(--shadow);
    font-size: 12px;
    pointer-events: none;
  }
  .table-view {
    max-height: 420px;
    overflow: auto;
  }
  .hatch-sw {
    display: inline-block;
    width: 12px;
    height: 10px;
    background: repeating-linear-gradient(135deg, var(--hm-hatch) 0 1px, transparent 1px 4px);
    vertical-align: middle;
  }
</style>
