<script lang="ts">
  // REQ: OBS-029 (ADR-129) — the rhythm heatmap: when the network (or one device, or one name)
  // asks, as days × time of day. The Traffic map says what; this says when. Built on the time
  // buckets and the hourly top lists: nothing new is counted.
  import { onDestroy, untrack } from 'svelte';
  import { api, type S } from '../lib/api';
  import { href, navigate, route } from '../lib/router.svelte';
  import { num } from '../lib/format';
  import { changes } from '../lib/annotations.svelte';
  import { draw, geometry, height, hit, layout, locate, type Grid } from '../lib/heatmap';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import { t, tn, type MessageKey } from '../lib/i18n';

  type Kind = 'network' | 'client' | 'name';
  const windows = [
    { id: '24h', label: 'flow.window.24h' as MessageKey, from: '-24h', days: 1 },
    { id: '7d', label: 'flow.window.7d' as MessageKey, from: '-7d', days: 7 },
    { id: '30d', label: 'legacy.range.30d' as MessageKey, from: '-30d', days: 30 },
    { id: '90d', label: 'heatmap.window.90d' as MessageKey, from: '-90d', days: 90 },
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
  // The grid's width, for the grain, read from the card's head: the grid's own width drops to 0
  // while it's hidden (no data, e.g. after an error), which would flip the grain to hours,
  // reload, show the grid, flip it back and loop. The head is always shown, as wide as the grid.
  let headWidth = $state(0);
  let canvas = $state<HTMLCanvasElement | undefined>();
  let focus = $state<[number, number] | null>(null);
  let tip = $state<{ x: number; y: number; text: string } | null>(null);

  // Finer grains only where the data has them: the network, within 7 days; phones get hours.
  const effectiveGrain = $derived(kind !== 'network' || win.days > 7 || headWidth < 480 ? 'hour' : grain);
  const measured = $derived(headWidth > 0);

  // Only the latest request's answer is shown: a slower, older one mustn't land on top.
  let seq = 0;
  async function load() {
    const mine = ++seq;
    error = null;
    if (kind !== 'network' && !key) {
      data = null;
      return;
    }
    try {
      const got = await api.heatmap({
        from: win.from,
        grain: effectiveGrain,
        kind,
        key: kind === 'network' ? undefined : key,
        measure: kind === 'client' ? 'queries' : measure,
      });
      if (mine === seq) data = got;
    } catch (e) {
      if (mine !== seq) return;
      data = null;
      error = e;
    }
  }
  $effect(() => {
    void [kind, key, win, effectiveGrain, measure];
    // Wait for the first measurement, so a phone doesn't ask for finer slots and then hours.
    if (measured) void load();
  });
  $effect(() => {
    if (data) void changes.load(data.from);
  });

  const grid = $derived<Grid | null>(
    data ? layout(data.starts, data.values, data.covered ?? null, data.slotSeconds, fold) : null,
  );
  let wrap = $state<HTMLDivElement | undefined>();
  let innerHeight = $state(0);
  // How far down the page the grid starts (the notes above it move it).
  let top = $state(0);
  $effect(() => {
    void [innerHeight, width, data, showTable];
    if (wrap) top = wrap.getBoundingClientRect().top + window.scrollY;
  });
  // Rows fill the window's height below the grid's top, less the legend and margins below.
  const geo = $derived(grid && width > 0 ? geometry(grid, width, 96, 52, innerHeight - top - 120) : null);

  // Links and Back change the URL without remounting the page.
  $effect(() => {
    const q = route.params;
    // Only the URL is a dependency: the controls' own changes don't snap back.
    untrack(() => {
      const k = q.get('kind') ?? '';
      kind = (['network', 'client', 'name'].includes(k) ? k : 'network') as Kind;
      key = q.get('key') ?? '';
      keyInput = key;
      const w = windows.find((x) => x.id === q.get('window')) ?? windows[1];
      if (w.id !== win.id) win = w;
      grain = q.get('grain') ?? '15m';
      measure = q.get('measure') === 'blocked' ? 'blocked' : 'queries';
      fold = q.get('fold') === '1';
    });
  });

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
    if (!c.covered) return t('heatmap.tip.below', { when });
    if (c.value == null) return t('heatmap.tip.none', { when });
    const what = t(measure === 'blocked' ? 'heatmap.measure.blocked' : 'heatmap.count.queries');
    return fold
      ? tn('heatmap.tip.average', c.days, { when, count: num(Math.round(c.value)), what })
      : t('heatmap.tip.value', { when, count: num(c.value), what });
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
    // Everything shown goes in the URL: the URL is read back on every change.
    navigate('/heatmap', { kind, key, window: win.id, grain: grain === '15m' ? undefined : grain, measure: measure === 'blocked' ? measure : undefined, fold: fold ? '1' : undefined }, true);
  }
  const kinds: { id: Kind; label: MessageKey }[] = [
    { id: 'network', label: 'heatmap.scope.network' },
    { id: 'client', label: 'flow.device' },
    { id: 'name', label: 'clients.col.name' },
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

<svelte:window bind:innerHeight />

<div class="page">
  <div class="page-head">
    <h1>{t('nav.heatmap')}<HelpButton id="heatmap" /></h1>
    <div class="row controls">
      <div class="seg" role="group" aria-label={t('heatmap.what')}>
        {#each kinds as k (k.id)}
          <button type="button" aria-pressed={kind === k.id} onclick={() => (kind = k.id)}>{t(k.label)}</button>
        {/each}
      </div>
      <div class="seg" role="group" aria-label={t('flow.window')}>
        {#each windows as w (w.id)}
          <button type="button" aria-pressed={win.id === w.id} onclick={() => (win = w)}>{t(w.label)}</button>
        {/each}
      </div>
      {#if kind === 'network' && win.days <= 7}
        <span class="pill-field bare">
          <select bind:value={grain} aria-label={t('heatmap.slot')}>
            <option value="hour">{t('heatmap.slot.hour')}</option>
            <option value="15m">{t('heatmap.slot.15m')}</option>
            <option value="minute">{t('heatmap.slot.minute')}</option>
          </select>
        </span>
      {/if}
      {#if kind !== 'client'}
        <span class="pill-field bare">
          <select bind:value={measure} aria-label={t('heatmap.count')}>
            <option value="queries">{t('heatmap.count.queries')}</option>
            <option value="blocked">{t('wall.kpi.blocked')}</option>
          </select>
        </span>
      {/if}
      <span class="switch-track"><label class="switch"><input type="checkbox" role="switch" bind:checked={fold} data-testid="heatmap-fold" />{t('heatmap.typicalWeek')}</label></span>
    </div>
  </div>
  {#if kind !== 'network'}
    <form class="row keyform" onsubmit={setKey}>
      <input
        bind:value={keyInput}
        placeholder={kind === 'client' ? t('flow.devicePlaceholder') : t('heatmap.keyPlaceholder.name')}
        aria-label={kind === 'client' ? t('flow.deviceAddress') : t('clients.col.name')}
        data-testid="heatmap-key"
      />
      <button type="submit">{t('heatmap.show')}</button>
    </form>
  {/if}

  <ErrorNote {error} />

  <section class="card" data-testid="heatmap">
    <div class="card-head" bind:clientWidth={headWidth}>
      <h2>
        {#if kind === 'network'}{t('heatmap.head.all')}{:else if key}{key}{:else}{kind === 'client' ? t('heatmap.head.pickDevice') : t('heatmap.head.pickName')}{/if}
        {#if data}<span class="muted small">· {t('heatmap.slots', { grain: data.grain === '15m' ? t('heatmap.grain.15m') : data.grain })}</span>{/if}
      </h2>
      {#if kind === 'client' && key}
        <!-- REQ: OBS-034 — the device's day, lane by lane. -->
        <a class="small" href={href('/clients', { device: key, view: 'timeline' })} data-testid="heatmap-day">{t('heatmap.dayTimeline')}</a>
      {/if}
      <button class="link small" onclick={() => (showTable = !showTable)} aria-pressed={showTable}>{showTable ? t('dashw.showGrid') : t('flow.table')}</button>
    </div>
    {#if data?.missingNodes?.length}<p class="small muted">{t('heatmap.missing', { nodes: data.missingNodes.join(', ') })}</p>{/if}
    {#if !data && !error}
      <p class="empty">{kind === 'network' || key ? t('common.loading') : t('heatmap.empty')}</p>
    {:else if data && showTable}
      <div class="table-wrap table-view">
        <table class="compact" data-testid="heatmap-table">
          <thead><tr><th>{t('heatmap.col.day')}</th>{#each Array.from({ length: 24 }, (_, h) => h) as h (h)}<th class="num">{String(h).padStart(2, '0')}</th>{/each}</tr></thead>
          <tbody>
            {#each table as r, i (i)}
              <tr><td>{r.label}</td>{#each r.hours as v, j (j)}<td class="num">{v}</td>{/each}</tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
    <div class="grid-wrap" bind:this={wrap} bind:clientWidth={width} hidden={!data || showTable}>
      <div
        class="grid-focus"
        tabindex="0"
        role="grid"
        aria-roledescription={t('heatmap.grid.role')}
        aria-label={t('heatmap.grid.aria')}
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
        {t('heatmap.legend.stronger', { what: t(measure === 'blocked' ? 'heatmap.measure.blocked' : 'heatmap.count.queries') })}
        {#if data.precision === 'topList'}{t('heatmap.legend.topListBefore')}<span class="hatch-sw"></span>{t('heatmap.legend.topListAfter')}{/if}
        {t('heatmap.legend.cell')}
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
