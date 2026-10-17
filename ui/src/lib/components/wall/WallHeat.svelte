<script lang="ts">
  // REQ: OBS-035 — the network's week on the wall: the rhythm heatmap, 7 days × 15 minutes,
  // refreshed every 5 minutes.
  import { api, type S } from '../../api';
  import { poll } from '../../poll';
  import { draw, geometry, height, layout } from '../../heatmap';

  let data = $state<S['Heatmap'] | null>(null);
  let w = $state(0);
  let canvas = $state<HTMLCanvasElement>();
  $effect(() =>
    poll(async () => {
      try {
        data = await api.heatmap({ kind: 'network', from: '-7d', grain: '15m' });
      } catch {
        // The wall keeps the last picture.
      }
    }, 300_000),
  );
  const grid = $derived(data ? layout(data.starts, data.values, data.covered ?? null, data.slotSeconds, false) : null);
  const geo = $derived(grid && w > 0 ? geometry(grid, w, 96, 0) : null);
  $effect(() => {
    if (!canvas || !grid || !geo) return;
    const hgt = height(grid, geo);
    const dpr = window.devicePixelRatio || 1;
    canvas.width = Math.round(w * dpr);
    canvas.height = Math.round(hgt * dpr);
    canvas.style.height = `${hgt}px`;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, hgt);
    const css = (v: string) => getComputedStyle(document.documentElement).getPropertyValue(v).trim() || '#888';
    draw(ctx, grid, geo, { ink: css('--hm-ink'), bg: css('--hm-bg'), muted: css('--muted'), hatch: css('--hm-hatch') }, null);
  });
</script>

<div class="heat" bind:clientWidth={w} data-testid="wall-heat">
  <canvas bind:this={canvas} style:width="{w}px"></canvas>
</div>

<style>
  .heat {
    width: 100%;
  }
  canvas {
    display: block;
  }
</style>
