<script lang="ts">
  // REQ: OBS-032 (ADR-132) — the query flow: groups → decision → upstream → response code, for
  // the network (the time buckets' joint counts) or one device (its query log). Each band is
  // an exact counter for its pair; nothing is split proportionally.
  import { onDestroy, untrack } from 'svelte';
  import { api, type S } from '../lib/api';
  import { href, navigate, route } from '../lib/router.svelte';
  import { clock, num } from '../lib/format';
  import { poll } from '../lib/poll';
  import { STAGES, STAGE_LABEL, fold, layout, share, type FlowLink, type FlowNode, type PlacedLink, type PlacedNode } from '../lib/sankey';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';

  const windows = [
    { id: '15m', label: '15 min', from: '-15m', device: true },
    { id: '1h', label: '1 h', from: '-1h', device: true },
    { id: '6h', label: '6 h', from: '-6h', device: true },
    { id: '24h', label: '24 h', from: '-24h', device: true },
    { id: '7d', label: '7 d', from: '-7d', device: false },
  ];
  // Nodes under this share of every answer fold into "other" unless "Show small" is on.
  const SMALL = 0.005;
  const p = route.params;
  let client = $state(p.get('client') ?? '');
  let clientInput = $state(p.get('client') ?? '');
  let device = $state(!!p.get('client'));
  let win = $state(windows.find((w) => w.id === p.get('window')) ?? windows[1]);
  let live = $state(false);
  let showSmall = $state(false);
  let showTable = $state(false);
  let data = $state<S['QueryFlow'] | null>(null);
  let error = $state<unknown>(null);
  // When the shown numbers were read (Live says so, so a quiet refresh is still visible).
  let updated = $state(0);
  let width = $state(0);
  let tip = $state<{ x: number; y: number; text: string } | null>(null);
  let wrap = $state<HTMLDivElement | undefined>();
  let innerHeight = $state(0);
  // How far down the page the diagram starts (the notes above it move it).
  let top = $state(0);

  // Links and Back change the URL without remounting the page.
  $effect(() => {
    const q = route.params;
    // Only the URL is a dependency: the controls' own changes don't snap back.
    untrack(() => {
      client = q.get('client') ?? '';
      clientInput = client;
      device = !!client;
      const w = windows.find((x) => x.id === q.get('window')) ?? windows[1];
      if (w.id !== win.id) win = w;
    });
  });

  async function load() {
    if (device && !client) {
      data = null;
      return;
    }
    try {
      data = await api.flow({ from: win.from, client: device ? client : undefined });
      updated = Date.now() / 1000;
      error = null;
    } catch (e) {
      data = null;
      error = e;
    }
  }
  let stop: (() => void) | undefined;
  $effect(() => {
    void [device, client, win];
    stop?.();
    stop = undefined;
    if (live) stop = poll(load, 15_000);
    else void load();
  });
  onDestroy(() => stop?.());

  const folded = $derived(data ? fold(data.nodes as FlowNode[], data.links as FlowLink[], data.total, showSmall ? 0 : SMALL) : null);
  const vertical = $derived(width > 0 && width < 560);
  const crowd = $derived(folded ? Math.max(...STAGES.map((s) => folded.nodes.filter((n) => n.stage === s).length)) : 0);
  $effect(() => {
    void [innerHeight, width, data, showTable];
    if (wrap) top = wrap.getBoundingClientRect().top + window.scrollY;
  });
  // The window's height below the diagram's top, less the stage names above it and the legend
  // and margins below: thicker bands and more labels on a big screen, never under 320 px.
  const fit = $derived(Math.min(1000, innerHeight - top - 120));
  const height = $derived(vertical ? 560 : Math.max(320, crowd * 30, fit));
  // Room for the labels: the first three columns label to their right, the last to its left.
  const pad = $derived(vertical ? 0 : 4);
  const lay = $derived(folded && width > 0 ? layout(folded.nodes, folded.links, width - 2 * pad, height - (vertical ? 24 : 0), vertical) : null);
  const byId = $derived(new Map((lay?.nodes ?? []).map((n) => [n.id, n])));

  const STATUS_COLOR: Record<string, string> = {
    cached: '--s-cached',
    refreshed: '--s-refreshed',
    forwarded: '--s-forwarded',
    stale: '--warn',
    blocked: '--s-blocked',
    local: '--s-local',
    servfail: '--bad',
  };
  function color(n: PlacedNode | undefined): string {
    if (!n) return 'var(--s-other)';
    if (n.stage === 'status') return `var(${STATUS_COLOR[n.name] ?? '--s-other'})`;
    if (n.stage === 'rcode') return n.name === 'SERVFAIL' ? 'var(--bad)' : n.name === 'NOERROR' ? 'var(--s-cached)' : 'var(--s-other)';
    return n.stage === 'upstream' ? 'var(--s-forwarded)' : 'var(--info)';
  }
  /** The page behind a node: its group, the lists for blocked, the query log for a status or
   * a response code, the upstreams. */
  function nodeLink(n: PlacedNode | FlowNode): string | undefined {
    if (n.name === 'other') return undefined;
    const c = device ? client : undefined;
    switch (n.stage) {
      case 'group':
        return c ? href('/queries', { client: c, group: n.name, from: win.from }) : href('/groups');
      case 'status':
        return n.name === 'blocked' && !c ? href('/lists') : href('/queries', { status: n.name, client: c, from: win.from });
      case 'upstream':
        return href('/upstreams');
      case 'rcode':
        return href('/queries', { rcode: n.name, client: c, from: win.from });
    }
    return undefined;
  }
  function linkText(l: FlowLink): string {
    const s = byId.get(l.source);
    const t = byId.get(l.target);
    return `${s?.name ?? l.source} → ${t?.name ?? l.target}: ${num(l.count)} (${share(l, data?.total ?? 0, s)})`;
  }
  function nodeText(n: PlacedNode): string {
    const pct = data?.total ? ` (${((100 * n.count) / data.total).toFixed(1)} %)` : '';
    const dead = n.deadEnd ? ` · ${num(n.deadEnd)} end here` : '';
    return `${STAGE_LABEL[n.stage]} ${n.name}: ${num(n.count)}${pct}${dead}`;
  }
  function at(e: MouseEvent): { x: number; y: number } {
    const r = (e.currentTarget as Element).closest('.flow-wrap')?.getBoundingClientRect();
    return { x: e.clientX - (r?.left ?? 0), y: e.clientY - (r?.top ?? 0) };
  }
  function hoverLink(e: MouseEvent, l: PlacedLink) {
    tip = { ...at(e), text: linkText(l) };
  }
  function hoverNode(e: MouseEvent, n: PlacedNode) {
    tip = { ...at(e), text: nodeText(n) };
  }
  function focusLink(l: PlacedLink) {
    tip = { x: l.x1, y: l.y1, text: linkText(l) };
  }
  function setClient(e: SubmitEvent) {
    e.preventDefault();
    client = clientInput.trim();
    navigate('/flow', { client, window: win.id }, true);
  }
  function setDevice(on: boolean) {
    device = on;
    if (!on) navigate('/flow', { window: win.id }, true);
    if (on && !win.device) win = windows[3];
  }
  function label(n: PlacedNode): { x: number; y: number; anchor: string } | null {
    if (vertical) return n.w >= 44 ? { x: n.x + 2, y: n.y + n.h + 12, anchor: 'start' } : null;
    if (n.h < 11) return null;
    const last = n.col === STAGES.length - 1;
    return { x: last ? n.x - 6 : n.x + n.w + 6, y: n.y + n.h / 2 + 4, anchor: last ? 'end' : 'start' };
  }
  const rows = $derived(
    (folded?.links ?? []).map((l) => ({
      ...l,
      from: folded?.nodes.find((n) => n.id === l.source),
      to: folded?.nodes.find((n) => n.id === l.target),
    })),
  );
</script>

<svelte:window bind:innerHeight />

<div class="page">
  <div class="page-head">
    <h1>Flow<HelpButton id="flow" /></h1>
    <div class="row controls">
      <div class="seg" role="group" aria-label="What">
        <button type="button" aria-pressed={!device} onclick={() => setDevice(false)}>Network</button>
        <button type="button" aria-pressed={device} onclick={() => setDevice(true)}>Device</button>
      </div>
      <div class="seg" role="group" aria-label="Window">
        {#each windows.filter((w) => !device || w.device) as w (w.id)}
          <button type="button" aria-pressed={win.id === w.id} onclick={() => (win = w)}>{w.label}</button>
        {/each}
      </div>
      <div class="switch-track">
        <label class="switch"><input type="checkbox" role="switch" bind:checked={showSmall} data-testid="flow-small" />Show small</label>
        <label class="switch"><input type="checkbox" role="switch" bind:checked={live} data-testid="flow-live" />Live</label>
      </div>
    </div>
  </div>
  {#if device}
    <form class="row keyform" onsubmit={setClient}>
      <input bind:value={clientInput} placeholder="a device address, e.g. 192.168.2.14" aria-label="Device address" data-testid="flow-client" />
      <button type="submit">Show</button>
    </form>
  {/if}

  <ErrorNote {error} />

  <section class="card" data-testid="flow">
    <div class="card-head">
      <h2>
        {#if !device}The whole network{:else if client}{client}{:else}Pick a device{/if}
        {#if data}<span class="muted small">· {num(data.total)} answers{data.source === 'querylog' ? ', from the query log' : ''}</span>{/if}
        {#if live && data}<span class="muted small" data-testid="flow-updated">· updated {clock(updated, true)}, every 15 s</span>{/if}
      </h2>
      <button class="link small" onclick={() => (showTable = !showTable)} aria-pressed={showTable} data-testid="flow-table-toggle">{showTable ? 'Diagram' : 'Table'}</button>
    </div>
    {#if data?.missingNodes?.length}<p class="small muted">Without {data.missingNodes.join(', ')}: they didn't answer.</p>{/if}
    {#if data?.partial}<p class="small muted" data-testid="flow-partial">Some of this window was counted by a build without flow counts: those answers are missing.</p>{/if}
    {#if data?.truncated}<p class="small warn-text" data-testid="flow-truncated">The query log read stopped early: the numbers cover what it read.</p>{/if}
    {#if !data}
      <p class="empty">{!device || client ? 'Loading…' : 'Enter one above.'}</p>
    {:else if !data.total}
      <p class="empty">No answers in this window.</p>
    {:else if showTable}
      <div class="table-wrap">
        <table class="compact" data-testid="flow-table">
          <thead><tr><th>From</th><th>To</th><th class="num">Answers</th><th class="num">Share</th></tr></thead>
          <tbody>
            {#each rows as r, i (i)}
              <tr class:fail={r.failure}>
                <td>{STAGE_LABEL[r.from?.stage ?? '']} {r.from?.name}</td>
                <td>{STAGE_LABEL[r.to?.stage ?? '']} {r.to?.name}</td>
                <td class="num">{num(r.count)}</td>
                <td class="num">{share(r, data.total, r.from)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
    <div class="flow-wrap" bind:this={wrap} bind:clientWidth={width} hidden={!data || !data.total || showTable}>
      {#if lay}
        {#if !vertical}
          <div class="stages" aria-hidden="true">{#each STAGES as s (s)}<span>{STAGE_LABEL[s]}</span>{/each}</div>
        {/if}
        <svg
          width={width}
          {height}
          viewBox={`${-pad} 0 ${width} ${height}`}
          role="img"
          aria-label="Query flow: groups, then decisions, upstreams and response codes; band widths are answer counts. The table view lists every link."
          data-testid="flow-svg"
          data-vertical={vertical ? '1' : '0'}
          data-scale={lay.scale}
          data-total={data?.total}
        >
          <g class="links">
            {#each lay.links as l (l.source + '>' + l.target)}
              <path
                d={l.d}
                class:failure={l.failure}
                style:stroke={l.failure ? 'var(--bad)' : color(byId.get(l.source))}
                stroke-width={Math.max(1, l.width)}
                tabindex="0"
                role="button"
                aria-label={linkText(l)}
                data-testid="flow-link"
                data-source={l.source}
                data-target={l.target}
                data-count={l.count}
                data-width={l.width}
                data-y0={l.y0}
                data-y1={l.y1}
                data-x0={l.x0}
                data-x1={l.x1}
                onmousedown={(e) => e.preventDefault()}
                onmousemove={(e) => hoverLink(e, l)}
                onmouseleave={() => (tip = null)}
                onfocus={() => focusLink(l)}
                onblur={() => (tip = null)}
              ></path>
            {/each}
          </g>
          <g class="nodes">
            {#each lay.nodes as n (n.id)}
              {@const to = nodeLink(n)}
              {@const lb = label(n)}
              <a href={to} data-testid="flow-node" data-id={n.id} data-x={n.x} data-y={n.y} data-w={n.w} data-h={n.h} data-col={n.col} aria-label={nodeText(n)} onmousemove={(e) => hoverNode(e, n)} onmouseleave={() => (tip = null)}>
                <rect x={n.x} y={n.y} width={Math.max(1, n.w)} height={Math.max(1, n.h)} rx="2" style:fill={color(n)}></rect>
                {#if lb}<text x={lb.x} y={lb.y} text-anchor={lb.anchor}>{n.name} <tspan class="count">{num(n.count)}</tspan></text>{/if}
              </a>
            {/each}
          </g>
          {#if vertical}
            {#each STAGES as s, i (s)}
              <text class="stage" x={width - 4} y={i * ((height - 24 - 14) / 3) + 11} text-anchor="end">{STAGE_LABEL[s]}</text>
            {/each}
          {/if}
        </svg>
      {/if}
      {#if tip}<div class="tip" role="tooltip" data-testid="flow-tip" style:left={`${Math.max(0, Math.min(tip.x + 12, width - 260))}px`} style:top={`${tip.y + 12}px`}>{tip.text}</div>{/if}
    </div>
    {#if data?.total}
      <p class="muted small legend">
        Band width = answers, each counted for exactly that pair; <span class="sw fail-sw"></span> red bands end in a SERVFAIL.
        {#if (folded?.folded ?? 0) > 0}{folded?.folded} nodes under 0.5 % are folded into “other” (Show small lists them).{/if}
        Select a node for the page behind it.
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
  .flow-wrap {
    position: relative;
    width: 100%;
  }
  .stages {
    display: flex;
    justify-content: space-between;
    font-size: 12px;
    color: var(--muted);
    margin-bottom: 4px;
  }
  svg {
    display: block;
    overflow: visible;
  }
  /* A click doesn't focus a band (mousedown above): its tip stays at the pointer, and no browser
     draws a focus box around the band's whole bounding rectangle. Tab still reaches each band. */
  path {
    fill: none;
    stroke-opacity: 0.35;
    cursor: pointer;
    -webkit-tap-highlight-color: transparent;
  }
  path.failure {
    stroke-opacity: 0.6;
  }
  path:hover,
  path:focus-visible {
    stroke-opacity: 0.7;
    outline: none;
  }
  text {
    font-size: 12px;
    fill: var(--text);
    paint-order: stroke;
    stroke: var(--surface);
    stroke-width: 3px;
  }
  text .count,
  text.stage {
    fill: var(--muted);
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
  tr.fail td {
    color: var(--bad);
  }
  .warn-text {
    color: var(--warn);
  }
  .sw {
    display: inline-block;
    width: 12px;
    height: 8px;
    border-radius: 2px;
    vertical-align: middle;
  }
  .fail-sw {
    background: var(--bad);
    opacity: 0.6;
  }
</style>
