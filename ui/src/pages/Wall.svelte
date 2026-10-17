<script lang="ts">
  // REQ: OBS-035 (ADR-135, ADR-141) — the wall display: a full-screen page for a wall monitor or a
  // tablet, no navigation, the live query stream as a ticker. The panels
  // (`?panels=map,flow,slo,latency,heat,kpi`) are laid out for the screen (`?layout=auto`): one at
  // a time on a phone, a hero and side panels on a TV, three columns on an ultrawide, everything
  // at once on a large screen; panels that don't fit rotate in a slot every `?every=` seconds.
  // Nothing new is read. Esc or a click goes back to the dashboard; Space pauses; the arrow keys
  // move the hero. `prefers-reduced-motion` or `?motion=off`: nothing moves.
  import { onDestroy, untrack } from 'svelte';
  import type { S } from '../lib/api';
  import { navigate, route } from '../lib/router.svelte';
  import { clock } from '../lib/format';
  import { session } from '../lib/session.svelte';
  import Logo from '../lib/components/Logo.svelte';
  import LatencyHeatmap from '../lib/components/LatencyHeatmap.svelte';
  import WallMap from '../lib/components/wall/WallMap.svelte';
  import WallFlow from '../lib/components/wall/WallFlow.svelte';
  import WallSlo from '../lib/components/wall/WallSlo.svelte';
  import WallHeat from '../lib/components/wall/WallHeat.svelte';
  import WallKpi from '../lib/components/wall/WallKpi.svelte';
  import {
    PANEL_TITLE,
    Ticker,
    chooseLayout,
    frameHub,
    motionAllowed,
    parseEvery,
    parseLayout,
    parsePanels,
    screenClassStable,
    type ScreenClass,
  } from '../lib/wall';

  const panels = $derived(parsePanels(route.params.get('panels')));
  const every = $derived(parseEvery(route.params.get('every')));
  const mode = $derived(parseLayout(route.params.get('layout')));
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const motion = $derived(motionAllowed(route.params.get('motion'), reduced));

  // The screen's class comes from the whole wall (the last one kept near a boundary); the slots
  // from the panel area, which a large screen's tail column narrows.
  let ww = $state(0);
  let wh = $state(0);
  let aw = $state(0);
  let ah = $state(0);
  let prevCls: ScreenClass | null = null;
  const cls = $derived<ScreenClass>(
    mode === 'grid'
      ? 'large'
      : mode === 'auto' || mode === 'single'
        ? screenClassStable(ww || window.innerWidth, wh || window.innerHeight, prevCls)
        : mode,
  );
  const layout = $derived(chooseLayout(aw || window.innerWidth, ah || window.innerHeight, panels, mode === 'single' ? 'single' : cls));
  $effect(() => {
    prevCls = cls;
  });

  // Each slot's place in its rotation.
  let idx = $state<number[]>([]);
  let paused = $state(false);
  let now = $state(Date.now() / 1000);
  let titleShown = $state(true);
  const at = (i: number) => {
    const s = layout.slots[i];
    return s ? s.panels[(idx[i] ?? 0) % s.panels.length] : undefined;
  };
  const rotating = $derived(layout.slots.some((s) => s.panels.length > 1));
  const hero = $derived(at(0));
  const single = $derived(layout.slots.length === 1);

  // Rotation, restarted by every move so a panel always gets its full time.
  let turn = $state(0);
  $effect(() => {
    void turn;
    if (paused || !rotating) return;
    const t = setTimeout(() => step(1, null), every * 1000);
    return () => clearTimeout(t);
  });
  $effect(() => {
    void hero;
    titleShown = true;
    const t = setTimeout(() => (titleShown = false), 3000);
    return () => clearTimeout(t);
  });
  // A new address or a new layout starts each slot from its first panel.
  $effect(() => {
    void route.params.toString();
    void layout.slots.map((s) => s.panels.join()).join('|');
    untrack(() => {
      idx = layout.slots.map(() => 0);
      turn++;
    });
  });
  /** Moves every rotating slot (`only`: just that one) by `d`. */
  function step(d: number, only: number | null) {
    idx = layout.slots.map((s, i) => {
      const cur = idx[i] ?? 0;
      return (only === null || only === i) && s.panels.length > 1 ? (cur + d + s.panels.length) % s.panels.length : cur;
    });
    turn++;
  }
  const tick = setInterval(() => (now = Date.now() / 1000), 1000);
  // REQ: OBS-035 (T14.15) — one animation loop for every panel; a hidden tab stops it.
  const vis = () => frameHub().visibility();
  document.addEventListener('visibilitychange', vis);
  onDestroy(() => {
    clearInterval(tick);
    document.removeEventListener('visibilitychange', vis);
  });

  // REQ: OBS-035 (T14.13) — a wall display's session can only show the wall: nowhere to exit to.
  const display = $derived(!!session.user?.display);
  function exit() {
    if (!display) navigate('/');
  }
  function key(e: KeyboardEvent) {
    if (e.key === 'Escape') exit();
    else if (e.key === ' ') {
      e.preventDefault();
      paused = !paused;
      turn++;
    } else if (e.key === 'ArrowRight') step(1, 0);
    else if (e.key === 'ArrowLeft') step(-1, 0);
  }

  // The live tail: the newest 50, flushed four times a second; frames are dropped, never queued.
  const ticker = new Ticker<S['QueryRow']>(50);
  let rows = $state<S['QueryRow'][]>([]);
  $effect(() => {
    const es = new EventSource('/api/v1/queries/stream');
    let pending: S['QueryRow'][] = [];
    es.addEventListener('query', (m) => {
      pending.push(JSON.parse((m as MessageEvent).data) as S['QueryRow']);
      if (pending.length > 50) pending = pending.slice(-50);
    });
    const flush = setInterval(() => {
      if (pending.length === 0 || document.visibilityState !== 'visible') return;
      ticker.push(pending);
      pending = [];
      rows = ticker.items.slice(0, 24);
    }, 250);
    return () => {
      es.close();
      clearInterval(flush);
    };
  });
  const heroList = $derived(layout.slots[0]?.panels ?? []);
</script>

<svelte:window onkeydown={key} />

<!-- svelte-ignore a11y_click_events_have_key_events -->
<!-- svelte-ignore a11y_no_static_element_interactions -->
<div
  class="wall"
  class:motion
  class:side={layout.tailSide}
  data-testid="wall"
  data-panel={hero}
  data-class={layout.cls}
  data-slots={layout.slots.length}
  data-motion={motion ? 'on' : 'off'}
  bind:clientWidth={ww}
  bind:clientHeight={wh}
  onclick={exit}
>
  <div class="corner">
    <Logo />
    <span class="clock" data-testid="wall-clock">{clock(now)}</span>
    {#if paused}<span class="paused" data-testid="wall-paused">paused</span>{/if}
  </div>
  {#if single && hero}
    <h1 class="title" class:fade={motion && !titleShown} class:gone={!motion && !titleShown}>{PANEL_TITLE[hero]}</h1>
  {/if}
  <div class="area" bind:clientWidth={aw} bind:clientHeight={ah} data-testid="wall-area">
    {#each layout.slots as s, i (i)}
      {@const p = at(i)}
      <section
        class="slot"
        class:hero={i === 0}
        style:left="{s.x}px"
        style:top="{s.y}px"
        style:width="{s.w}px"
        style:height="{s.h}px"
        data-testid="wall-slot"
        data-panel={p}
        data-rotates={s.panels.length > 1 ? 'yes' : 'no'}
      >
        {#if !single && p}<h2 class="caption">{PANEL_TITLE[p]}</h2>{/if}
        <div class="panel" data-testid="wall-panel-{p}">
          {#key p}
            {#if p === 'map'}<WallMap {motion} />
            {:else if p === 'flow'}<WallFlow {motion} />
            {:else if p === 'slo'}<WallSlo />
            {:else if p === 'latency'}<div class="lat"><LatencyHeatmap wall testid="wall-latency" /></div>
            {:else if p === 'kpi'}<WallKpi />
            {:else if p === 'heat'}<WallHeat />{/if}
          {/key}
        </div>
      </section>
    {/each}
  </div>
  <ol class="dots" aria-label="Panels" data-testid="wall-order">
    {#each panels as p (p)}<li class:on={p === hero} data-panel={p}></li>{/each}
  </ol>
  {#if !paused && rotating}
    {#key turn}
      <div class="progress" class:run={motion} style:--every="{every}s" data-testid="wall-progress"></div>
    {/key}
  {/if}
  <div class="tail" data-testid="wall-tail" data-side={layout.tailSide ? 'yes' : 'no'}>
    {#each rows as r, i (i)}
      <span class="item s-{r.status}">{r.clientName ?? r.client} → {r.name} · {r.status}</span>
    {:else}
      <span class="muted">Waiting for queries…</span>
    {/each}
  </div>
  <span hidden data-testid="wall-hero-list">{heroList.join(',')}</span>
</div>

<style>
  .wall {
    position: fixed;
    inset: 0;
    background: var(--bg);
    color: var(--text);
    display: grid;
    grid-template-columns: minmax(0, 1fr);
    grid-template-rows: auto minmax(0, 1fr) auto auto;
    grid-template-areas: 'title' 'area' 'dots' 'tail';
    padding: 2vmin 3vmin 0;
    gap: 1.5vmin;
    cursor: default;
    overflow: hidden;
  }
  /* A large screen: the tail is a column beside the panels. */
  .wall.side {
    grid-template-columns: minmax(0, 1fr) 22vw;
    grid-template-rows: auto minmax(0, 1fr) auto;
    grid-template-areas: 'title title' 'area tail' 'dots dots';
  }
  .title {
    grid-area: title;
    margin: 0;
    font-size: 3.6vmin;
    font-weight: 600;
    min-height: 1px;
  }
  .area {
    grid-area: area;
    position: relative;
    min-height: 0;
    min-width: 0;
  }
  .slot {
    position: absolute;
    box-sizing: border-box;
    padding: 0.8vmin;
    display: flex;
    flex-direction: column;
    min-width: 0;
    min-height: 0;
    overflow: hidden;
  }
  .caption {
    margin: 0 0 0.6vmin;
    font-size: 1.8vmin;
    font-weight: 600;
    color: var(--muted);
  }
  .panel {
    flex: 1;
    min-height: 0;
    position: relative;
    overflow: hidden;
  }
  .panel > :global(*) {
    height: 100%;
  }
  .corner {
    position: absolute;
    top: 1.5vmin;
    right: 2vmin;
    display: flex;
    gap: 1.5vmin;
    align-items: center;
    font-size: 2.2vmin;
    opacity: 0.75;
    z-index: 2;
  }
  .clock {
    font-variant-numeric: tabular-nums;
  }
  .paused {
    font-size: 1.6vmin;
    text-transform: uppercase;
    letter-spacing: 0.1em;
  }
  .motion .title {
    transition: opacity 0.8s ease;
  }
  .title.fade,
  .title.gone {
    opacity: 0;
  }
  .lat :global(.lh) {
    font-size: 1.6vmin;
  }
  .dots {
    grid-area: dots;
    display: flex;
    gap: 1vmin;
    list-style: none;
    margin: 0;
    padding: 0;
    justify-content: center;
  }
  .dots li {
    width: 1vmin;
    height: 1vmin;
    border-radius: 50%;
    background: var(--border);
  }
  .dots li.on {
    background: var(--accent);
  }
  .progress {
    position: absolute;
    left: 0;
    bottom: 0;
    height: 2px;
    background: var(--accent);
    width: 0;
  }
  .progress.run {
    animation: grow var(--every) linear forwards;
  }
  @keyframes grow {
    to {
      width: 100%;
    }
  }
  .tail {
    grid-area: tail;
    display: flex;
    gap: 3vmin;
    white-space: nowrap;
    overflow: hidden;
    font-size: 1.9vmin;
    padding: 1vmin 0 1.5vmin;
    border-top: 1px solid var(--border);
    font-family: ui-monospace, monospace;
  }
  .wall.side .tail {
    flex-direction: column;
    gap: 0.8vmin;
    border-top: 0;
    border-left: 1px solid var(--border);
    padding: 0 0 0 1.5vmin;
    font-size: 1.5vmin;
  }
  .item {
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .item.s-blocked {
    color: var(--bad);
  }
  .item.s-cached,
  .item.s-refreshed,
  .item.s-stale {
    color: var(--s-cached);
  }
  .item.s-forwarded {
    color: var(--s-forwarded);
  }
</style>
