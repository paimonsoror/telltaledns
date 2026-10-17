<script lang="ts">
  // REQ: OBS-035 — the traffic map on the wall: this hour's busiest names as tiles sized by
  // queries, refreshed every 5 s; tiles tween to their new place over 600 ms, and one that grew a
  // lot pulses once.
  import { onDestroy, untrack } from 'svelte';
  import { api, type S } from '../../api';
  import { poll } from '../../poll';
  import { short } from '../../format';
  import { squarify } from '../../treemap';
  import { ease, frameHub, lerpBoxes, type Box } from '../../wall';

  let { motion }: { motion: boolean } = $props();
  let items = $state<S['TopItem'][]>([]);
  let w = $state(0);
  let h = $state(0);
  let shown = $state(new Map<string, Box>());
  let grew = $state(new Set<string>());
  let prev = new Map<string, number>();
  let from = new Map<string, Box>();
  let to = new Map<string, Box>();
  let started = 0;
  const TWEEN_MS = 600;

  $effect(() =>
    poll(async () => {
      try {
        items = (await api.top('domains', 30)).items;
      } catch {
        // The wall keeps the last picture.
      }
    }, 5000),
  );

  // REQ: OBS-035 (T14.15) — on the wall's one animation loop while a tween runs.
  let off: (() => void) | null = null;
  const loop = {
    start: () => {
      off ??= frameHub().add(() => {
        const t = ease((performance.now() - started) / TWEEN_MS);
        shown = lerpBoxes(from, to, t);
        if (t >= 1) loop.stop();
      });
    },
    stop: () => {
      off?.();
      off = null;
    },
  };
  onDestroy(() => loop.stop());

  $effect(() => {
    if (w <= 0 || h <= 0) return;
    const rects = squarify(
      items.map((i) => i.count),
      w,
      h,
    );
    const next = new Map<string, Box>(items.map((it, i) => [it.key, rects[i]]));
    const g = new Set<string>();
    for (const it of items) {
      const p = prev.get(it.key);
      if (p != null && it.count > p * 1.2 && it.count - p >= 10) g.add(it.key);
    }
    prev = new Map(items.map((it) => [it.key, it.count]));
    grew = motion ? g : new Set();
    // Untracked: this effect writes `shown`, so reading it here would rerun it forever.
    from = untrack(() => shown);
    to = next;
    if (motion && from.size > 0) {
      started = performance.now();
      loop.start();
    } else {
      shown = lerpBoxes(from, to, 1);
    }
  });
</script>

<div class="map" bind:clientWidth={w} bind:clientHeight={h} data-testid="wall-map">
  {#each items as it (it.key)}
    {@const b = shown.get(it.key)}
    {#if b && b.w > 1 && b.h > 1}
      <div
        class="tile"
        class:pulse={grew.has(it.key)}
        style:left="{b.x}px"
        style:top="{b.y}px"
        style:width="{b.w}px"
        style:height="{b.h}px"
      >
        {#if b.w > 70 && b.h > 34}<span class="name">{it.name ?? it.key}</span><span class="n">{short(it.count)}</span>{/if}
      </div>
    {/if}
  {/each}
</div>

<style>
  .map {
    position: relative;
    width: 100%;
    height: 100%;
  }
  .tile {
    position: absolute;
    box-sizing: border-box;
    border: 2px solid var(--bg);
    background: color-mix(in srgb, var(--s-cached) 70%, var(--bg));
    color: var(--text);
    padding: 0.6vmin;
    overflow: hidden;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
  }
  .name {
    font-size: 1.8vmin;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .n {
    font-size: 2.6vmin;
    font-variant-numeric: tabular-nums;
  }
  .pulse {
    animation: pulse 1.2s ease-out 1;
  }
  @keyframes pulse {
    0% {
      box-shadow: inset 0 0 0 0.6vmin var(--accent);
    }
    100% {
      box-shadow: inset 0 0 0 0 var(--accent);
    }
  }
</style>
