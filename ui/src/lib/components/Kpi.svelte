<script lang="ts">
  // T6.8 — a KPI tile: the number, its change against the previous period (colored by what's
  // good for this metric, not by direction), and an optional sparkline.
  let {
    label,
    value,
    sub = '',
    tone = '',
    delta = null,
    good = 'neutral',
    spark = [],
    sparkColor = '--accent',
    ring = null,
  }: {
    /** T6.8 — a small progress ring for a ratio, 0–100 (drawn in the spark color). */
    ring?: number | null;
    label: string;
    value: string;
    sub?: string;
    tone?: string;
    /** Change against the previous period, as a fraction (0.12 = +12%). */
    delta?: number | null;
    /** Which way is good: `up`, `down`, or `neutral` (no color). */
    good?: 'up' | 'down' | 'neutral';
    spark?: number[];
    sparkColor?: string;
  } = $props();

  const deltaClass = $derived(
    delta == null || Math.abs(delta) < 0.005 || good === 'neutral'
      ? 'flat'
      : (delta > 0) === (good === 'up')
        ? 'up-good'
        : 'up-bad',
  );
  const deltaText = $derived.by(() => {
    if (delta == null || !Number.isFinite(delta)) return '';
    const p = Math.abs(delta) * 100;
    const shown = p >= 100 ? Math.round(p).toLocaleString() : p.toFixed(p < 10 ? 1 : 0);
    return `${delta > 0 ? '▲' : delta < 0 ? '▼' : '•'} ${shown}%`;
  });
  // The sparkline as a 100×28 path.
  const sparkPath = $derived.by(() => {
    const v = spark.filter((x) => Number.isFinite(x));
    if (v.length < 2) return '';
    const max = Math.max(...v);
    const min = Math.min(...v);
    const span = max - min || 1;
    return v
      .map((y, i) => `${i ? 'L' : 'M'}${((i / (v.length - 1)) * 100).toFixed(1)},${(26 - ((y - min) / span) * 24).toFixed(1)}`)
      .join(' ');
  });
</script>

<div class="card kpi">
  {#if ring != null && Number.isFinite(ring)}
    {@const r = 15}
    {@const c = 2 * Math.PI * r}
    <svg class="ring" viewBox="0 0 40 40" aria-hidden="true">
      <circle cx="20" cy="20" {r} class="track" />
      <circle cx="20" cy="20" {r} class="fill" stroke={`var(${sparkColor})`} stroke-dasharray={`${(Math.min(100, Math.max(0, ring)) / 100) * c} ${c}`} transform="rotate(-90 20 20)" />
    </svg>
  {/if}
  <div class="label">{label}</div>
  <div class="value {tone}">{value}</div>
  <div class="foot">
    {#if deltaText}<span class="delta {deltaClass}" title="Against the previous period of the same length">{deltaText}</span>{/if}
    {#if sub}<span class="sub muted small">{sub}</span>{/if}
  </div>
  {#if sparkPath}
    <svg class="spark" viewBox="0 0 100 28" preserveAspectRatio="none" aria-hidden="true">
      <path d={sparkPath} fill="none" stroke={`var(${sparkColor})`} stroke-width="2" vector-effect="non-scaling-stroke" stroke-linecap="round" stroke-linejoin="round" />
    </svg>
  {/if}
</div>

<style>
  .kpi {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 16px 18px 14px;
    position: relative;
    overflow: hidden;
  }
  .label {
    font-size: 12.5px;
    font-weight: 500;
    color: var(--muted);
  }
  .value {
    font-size: 28px;
    font-weight: 700;
    letter-spacing: -0.02em;
    font-variant-numeric: tabular-nums;
    line-height: 1.25;
  }
  .value.bad {
    color: var(--bad);
  }
  .value.ok {
    color: var(--ok);
  }
  .foot {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
    min-height: 20px;
  }
  .delta {
    padding: 0 7px;
    border-radius: 999px;
    font-size: 11.5px;
    font-weight: 600;
    font-variant-numeric: tabular-nums;
    background: var(--surface-2);
    color: var(--muted);
  }
  .delta.up-good {
    color: var(--ok-strong);
    background: color-mix(in srgb, var(--ok) 13%, transparent);
  }
  .delta.up-bad {
    color: var(--bad-strong);
    background: color-mix(in srgb, var(--bad) 13%, transparent);
  }
  .ring {
    position: absolute;
    top: 14px;
    right: 14px;
    width: 34px;
    height: 34px;
  }
  .ring circle {
    fill: none;
    stroke-width: 5;
  }
  .ring .track {
    stroke: var(--surface-2);
  }
  .ring .fill {
    stroke-linecap: round;
  }
  .spark {
    width: 100%;
    height: 28px;
    margin-top: auto;
    padding-top: 6px;
    opacity: 0.85;
  }
</style>
