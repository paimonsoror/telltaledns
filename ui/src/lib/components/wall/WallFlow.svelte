<script lang="ts">
  // REQ: OBS-035 — the query flow on the wall: the last hour's Sankey, refreshed every 10 s, with
  // particles travelling along each band at a rate proportional to its count (60 at most).
  import { onDestroy } from 'svelte';
  import { api, type S } from '../../api';
  import { poll } from '../../poll';
  import { fold, layout, type FlowLink, type FlowNode } from '../../sankey';
  import { Particles, frameHub } from '../../wall';

  let { motion }: { motion: boolean } = $props();
  let data = $state<S['QueryFlow'] | null>(null);
  let w = $state(0);
  let h = $state(0);
  let svg = $state<SVGSVGElement>();
  let dots = $state<{ x: number; y: number; bad: boolean }[]>([]);
  const particles = new Particles();

  $effect(() =>
    poll(async () => {
      try {
        data = await api.flow({ from: '-1h' });
      } catch {
        // The wall keeps the last picture.
      }
    }, 10_000),
  );

  const placed = $derived.by(() => {
    if (!data || w <= 0 || h <= 0) return null;
    const f = fold(data.nodes as FlowNode[], data.links as FlowLink[], data.total, 0.01);
    return layout(f.nodes, f.links, w, h);
  });
  $effect(() => {
    if (placed) particles.plan(placed.links.map((l) => l.count));
  });

  // REQ: OBS-035 (T14.15) — on the wall's one animation loop.
  const frame = (dt: number) => {
    particles.step(dt);
    const paths = svg?.querySelectorAll<SVGPathElement>('path.band');
    if (!paths || !placed) return;
    const lens = Array.from(paths, (p) => p.getTotalLength());
    dots = particles.dots.flatMap((d) => {
      const p = paths[d.link];
      if (!p) return [];
      const pt = p.getPointAtLength(lens[d.link] * d.t);
      return [{ x: pt.x, y: pt.y, bad: placed.links[d.link]?.failure ?? false }];
    });
  };
  let off: (() => void) | null = null;
  const loop = {
    start: () => {
      off ??= frameHub().add(frame);
    },
    stop: () => {
      off?.();
      off = null;
    },
  };
  $effect(() => {
    if (motion && placed) loop.start();
    else {
      loop.stop();
      dots = [];
    }
  });
  onDestroy(() => loop.stop());
</script>

<div class="flow" bind:clientWidth={w} bind:clientHeight={h} data-testid="wall-flow">
  {#if placed}
    <svg bind:this={svg} width={w} height={h} viewBox="0 0 {w} {h}" aria-label="Where queries went in the last hour">
      {#each placed.links as l (l.source + l.target)}
        <path class="band" class:bad={l.failure} d={l.d} stroke-width={Math.max(1, l.width)} />
      {/each}
      {#each placed.nodes as n (n.id)}
        <rect x={n.x} y={n.y} width={n.w} height={Math.max(1, n.h)} class="node" />
        {#if n.h > 14 && w >= 600}
          <text x={n.col < 2 ? n.x + n.w + 6 : n.x - 6} y={n.y + n.h / 2} text-anchor={n.col < 2 ? 'start' : 'end'}>{n.name}</text>
        {/if}
      {/each}
      {#each dots as d, i (i)}
        <circle cx={d.x} cy={d.y} r="3" class="dot" class:bad={d.bad} />
      {/each}
    </svg>
  {/if}
</div>

<style>
  .flow {
    width: 100%;
    height: 100%;
  }
  .band {
    fill: none;
    stroke: var(--s-forwarded);
    stroke-opacity: 0.35;
  }
  .band.bad {
    stroke: var(--bad);
    stroke-opacity: 0.6;
  }
  .node {
    fill: var(--text);
    opacity: 0.8;
  }
  text {
    font-size: 1.8vmin;
    fill: var(--text);
    dominant-baseline: middle;
  }
  .dot {
    fill: var(--text);
  }
  .dot.bad {
    fill: var(--bad);
  }
</style>
