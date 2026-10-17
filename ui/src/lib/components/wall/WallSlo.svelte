<script lang="ts">
  // REQ: OBS-035 — the service level on the wall: each objective's error budget left as a large
  // ring, the last hour's burn rate in words (amber from 1×, red from 6×), and the top three
  // devices that spent the availability budget (OBS-027). Every 30 s.
  import { api, type S } from '../../api';
  import { poll } from '../../poll';
  import { num } from '../../format';

  let slo = $state<S['SloStatus'] | null>(null);
  let spent = $state<S['AttributionRow'][]>([]);
  // REQ: OBS-035 (T14.15) — the rings fit their slot, from a phone to a corner of a 4K screen.
  let w = $state(0);
  let h = $state(0);
  const ring = $derived(Math.max(70, Math.min(h * 0.58, (w - 40) / 2.3, 420)));
  $effect(() =>
    poll(async () => {
      try {
        slo = await api.slo();
        const a = await api.sloAttribution({ objective: 'availability', limit: 3 }).catch(() => null);
        spent = a?.byClient.slice(0, 3) ?? [];
      } catch {
        // The wall keeps the last picture.
      }
    }, 30_000),
  );
  const R = 42;
  const C = 2 * Math.PI * R;
  const burn = (o: S['SloObjective']) => o.burnRates.find((b) => b.window === '1h')?.rate ?? o.burnRates[0]?.rate ?? null;
  // The hour's burn rate: 1 spends exactly the budget; 6 and up is a slow-burn alert's pace.
  const burnTone = (r: number | null) => (r == null || r < 1 ? '' : r < 6 ? 'warn' : 'bad');
  const tone = (left: number | null | undefined) => (left == null ? 'muted' : left < 25 ? 'bad' : left < 50 ? 'warn' : 'ok');
</script>

<div class="slo" data-testid="wall-slo" bind:clientWidth={w} bind:clientHeight={h}>
  {#if slo && slo.enabled}
    <div class="rings">
      {#each slo.objectives as o (o.name)}
        {@const left = o.budgetRemainingPercent}
        {@const r = burn(o)}
        <figure class="ring {tone(left)}" data-testid="wall-ring">
          <svg viewBox="0 0 100 100" style:width="{ring}px" style:height="{ring}px" aria-label="{o.name}: {left == null ? 'no data' : `${Math.round(left)} % of the budget left`}">
            <circle cx="50" cy="50" r={R} class="track" />
            <circle cx="50" cy="50" r={R} class="left" stroke-dasharray="{(Math.max(0, Math.min(100, left ?? 0)) / 100) * C} {C}" transform="rotate(-90 50 50)" />
            <text x="50" y="62" text-anchor="middle" class="big">{left == null ? '–' : `${Math.round(left)}%`}</text>
          </svg>
          <figcaption>{o.name === 'availability' ? 'Answers that work' : o.name === 'latency' ? 'Answers that are quick' : o.name}<br /><span class="muted"><span class="burn {burnTone(r)}" data-testid="wall-burn">burn {r == null ? '–' : r.toFixed(1)}×</span> · {o.sliPercent == null ? '–' : `${o.sliPercent.toFixed(2)} %`}</span></figcaption>
        </figure>
      {/each}
    </div>
    {#if spent.length}
      <div class="spent">
        <span class="muted">Who spent it</span>
        {#each spent as s (s.key)}<span class="who">{s.name ?? s.key} <b>{num(s.bad)}</b></span>{/each}
      </div>
    {/if}
  {:else if slo}
    <p class="muted big-text">Service-level objectives are off.</p>
  {/if}
</div>

<style>
  .slo {
    width: 100%;
    height: 100%;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 3vmin;
  }
  .rings {
    display: flex;
    gap: 8vmin;
    justify-content: center;
    flex-wrap: wrap;
  }
  figure {
    margin: 0;
    text-align: center;
    font-size: 2.4vmin;
  }
  svg {
    display: block;
    margin: 0 auto;
  }
  circle {
    fill: none;
    stroke-width: 8;
  }
  .track {
    stroke: var(--border);
  }
  .ok .left {
    stroke: var(--ok, var(--s-cached));
  }
  .warn .left {
    stroke: var(--warn);
  }
  .bad .left {
    stroke: var(--bad);
  }
  .muted .left {
    stroke: var(--muted);
  }
  .burn.warn {
    color: var(--warn);
  }
  .burn.bad {
    color: var(--bad);
  }
  .big {
    font-size: 16px;
    fill: var(--text);
    font-variant-numeric: tabular-nums;
  }
  .spent {
    display: flex;
    gap: 3vmin;
    font-size: 2.4vmin;
    flex-wrap: wrap;
    justify-content: center;
  }
  .big-text {
    font-size: 3vmin;
  }
</style>
