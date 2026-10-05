<script lang="ts">
  // T6.8 — a donut: the total in the middle, one rounded segment per part, and a breakdown
  // grid below (the grid is the accessible view: every number is there as text).
  import { num } from '../format';

  export interface Part {
    label: string;
    value: number;
    /** A CSS variable name (`--s-blocked`). */
    color: string;
  }

  let { parts, center = 'total', format = num }: { parts: Part[]; center?: string; format?: (n: number) => string } = $props();

  const R = 42;
  /** Stroke width (matches the CSS). */
  const W = 11;
  const C = 2 * Math.PI * R;
  const total = $derived(parts.reduce((a, p) => a + Math.max(0, p.value), 0));
  // Each segment as a dash on the circle, starting at 12 o'clock, with a small gap between.
  const arcs = $derived.by(() => {
    const shown = parts.filter((p) => p.value > 0);
    // Round caps stick out half the stroke width at each end: shorten each dash by the stroke
    // width plus a 2-unit gap, and start it half that later, so neighbours never touch.
    const cut = shown.length > 1 ? W + 2 : 0;
    let at = 0;
    return shown.map((p) => {
      const len = (p.value / total) * C;
      const arc = { ...p, dash: Math.max(0.01, len - cut), offset: -(at + Math.min(cut, len) / 2) };
      at += len;
      return arc;
    });
  });
  const share = (v: number) => (total ? `${((v / total) * 100).toFixed(v / total < 0.1 ? 1 : 0)}%` : '–');
</script>

<div class="donut">
  <svg viewBox="0 0 100 100" aria-hidden="true">
    <circle cx="50" cy="50" r={R} class="track" />
    {#each arcs as a (a.label)}
      <circle
        cx="50"
        cy="50"
        r={R}
        class="seg"
        stroke={`var(${a.color})`}
        stroke-dasharray={`${a.dash} ${C}`}
        stroke-dashoffset={a.offset}
        transform="rotate(-90 50 50)"
      />
    {/each}
    <text x="50" y="49" class="total">{format(total)}</text>
    <text x="50" y="62" class="label">{center}</text>
  </svg>
  <ul class="breakdown">
    {#each parts as p (p.label)}
      <li>
        <span class="dot" style:background={`var(${p.color})`}></span>
        <span class="name">{p.label}</span>
        <span class="v">{format(p.value)}</span>
        <span class="muted small">{share(p.value)}</span>
      </li>
    {/each}
  </ul>
</div>

<style>
  .donut {
    display: grid;
    gap: 14px;
    justify-items: center;
  }
  svg {
    width: min(190px, 100%);
    height: auto;
  }
  circle {
    fill: none;
    stroke-width: 11;
  }
  .track {
    stroke: var(--surface-2);
  }
  .seg {
    stroke-linecap: round;
  }
  .total {
    text-anchor: middle;
    font-size: 15px;
    font-weight: 700;
    fill: var(--text);
    font-variant-numeric: tabular-nums;
  }
  .label {
    text-anchor: middle;
    font-size: 7.5px;
    fill: var(--muted);
  }
  .breakdown {
    list-style: none;
    margin: 0;
    padding: 0;
    width: 100%;
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(130px, 1fr));
    gap: 8px 16px;
  }
  .breakdown li {
    display: grid;
    grid-template-columns: auto 1fr auto auto;
    align-items: center;
    gap: 6px;
    font-size: 13px;
  }
  .dot {
    width: 9px;
    height: 9px;
    border-radius: 50%;
  }
  .name {
    text-transform: capitalize;
  }
  .v {
    font-weight: 600;
    font-variant-numeric: tabular-nums;
  }
</style>
