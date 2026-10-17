<script lang="ts">
  // REQ: OBS-035 (ADR-135) — the wall display: a full-screen page for a wall monitor or a tablet,
  // no navigation, one panel at a time on a timer (`?panels=map,flow,slo,latency,heat&every=20`),
  // and the live query stream as a ticker along the bottom. Nothing new is read: the same APIs
  // and stream as the other pages. Esc or a click goes back to the dashboard; Space pauses; the
  // arrow keys move between panels. `prefers-reduced-motion` or `?motion=off`: nothing moves.
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
  import { PANEL_TITLE, Ticker, motionAllowed, parseEvery, parsePanels } from '../lib/wall';

  const panels = $derived(parsePanels(route.params.get('panels')));
  const every = $derived(parseEvery(route.params.get('every')));
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const motion = $derived(motionAllowed(route.params.get('motion'), reduced));

  let idx = $state(0);
  let paused = $state(false);
  let now = $state(Date.now() / 1000);
  let titleShown = $state(true);
  const current = $derived(panels[idx % panels.length]);

  // Rotation, restarted by every move so a panel always gets its full time.
  let turn = $state(0);
  $effect(() => {
    void turn;
    if (paused || panels.length < 2) return;
    const t = setTimeout(() => go(1), every * 1000);
    return () => clearTimeout(t);
  });
  $effect(() => {
    void current;
    titleShown = true;
    const t = setTimeout(() => (titleShown = false), 3000);
    return () => clearTimeout(t);
  });
  // A new address (other panels, another order) starts from its first panel.
  $effect(() => {
    void route.params.toString();
    untrack(() => {
      idx = 0;
      turn++;
    });
  });
  function go(d: number) {
    idx = (idx + d + panels.length) % panels.length;
    turn++;
  }
  const tick = setInterval(() => (now = Date.now() / 1000), 1000);
  onDestroy(() => clearInterval(tick));

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
    } else if (e.key === 'ArrowRight') go(1);
    else if (e.key === 'ArrowLeft') go(-1);
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
      rows = ticker.items.slice(0, 12);
    }, 250);
    return () => {
      es.close();
      clearInterval(flush);
    };
  });
</script>

<svelte:window onkeydown={key} />

<!-- svelte-ignore a11y_click_events_have_key_events -->
<!-- svelte-ignore a11y_no_static_element_interactions -->
<div class="wall" class:motion data-testid="wall" data-panel={current} data-motion={motion ? 'on' : 'off'} onclick={exit}>
  <div class="corner">
    <Logo />
    <span class="clock" data-testid="wall-clock">{clock(now)}</span>
    {#if paused}<span class="paused" data-testid="wall-paused">paused</span>{/if}
  </div>
  <h1 class="title" class:fade={motion && !titleShown} class:gone={!motion && !titleShown}>{PANEL_TITLE[current]}</h1>
  <div class="panel" data-testid="wall-panel-{current}">
    {#key current}
      {#if current === 'map'}<WallMap {motion} />
      {:else if current === 'flow'}<WallFlow {motion} />
      {:else if current === 'slo'}<WallSlo />
      {:else if current === 'latency'}<div class="lat"><LatencyHeatmap wall testid="wall-latency" /></div>
      {:else}<WallHeat />{/if}
    {/key}
  </div>
  <ol class="dots" aria-label="Panels" data-testid="wall-order">
    {#each panels as p, i (p)}<li class:on={i === idx % panels.length} data-panel={p}></li>{/each}
  </ol>
  {#if !paused && panels.length > 1}
    {#key turn}
      <div class="progress" class:run={motion} style:--every="{every}s" data-testid="wall-progress"></div>
    {/key}
  {/if}
  <div class="tail" data-testid="wall-tail">
    {#each rows as r, i (i)}
      <span class="item s-{r.status}">{r.clientName ?? r.client} → {r.name} · {r.status}</span>
    {:else}
      <span class="muted">Waiting for queries…</span>
    {/each}
  </div>
</div>

<style>
  .wall {
    position: fixed;
    inset: 0;
    background: var(--bg);
    color: var(--text);
    display: grid;
    grid-template-rows: auto 1fr auto auto;
    padding: 2vmin 3vmin 0;
    gap: 1.5vmin;
    cursor: default;
    overflow: hidden;
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
  }
  .clock {
    font-variant-numeric: tabular-nums;
  }
  .paused {
    font-size: 1.6vmin;
    text-transform: uppercase;
    letter-spacing: 0.1em;
  }
  .title {
    margin: 0;
    font-size: 3.6vmin;
    font-weight: 600;
  }
  .motion .title {
    transition: opacity 0.8s ease;
  }
  .title.fade,
  .title.gone {
    opacity: 0;
  }
  .panel {
    min-height: 0;
    position: relative;
  }
  .panel > :global(*) {
    height: 100%;
  }
  .lat :global(.lh) {
    font-size: 1.6vmin;
  }
  .dots {
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
    display: flex;
    gap: 3vmin;
    white-space: nowrap;
    overflow: hidden;
    font-size: 1.9vmin;
    padding: 1vmin 0 1.5vmin;
    border-top: 1px solid var(--border);
    font-family: ui-monospace, monospace;
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
