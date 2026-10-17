<script lang="ts">
  // REQ: OBS-035 — the service level on the wall: each objective's error budget left as a large
  // ring, the last hour's burn rate as a needle (1 spends exactly the budget), and the top three
  // devices that spent the availability budget (OBS-027). Every 30 s.
  import { api, type S } from '../../api';
  import { poll } from '../../poll';
  import { num } from '../../format';

  let slo = $state<S['SloStatus'] | null>(null);
  let spent = $state<S['AttributionRow'][]>([]);
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
  // The needle: 0 at the left, 1 straight up, 14.4 (a fast burn) at the right, capped.
  const angle = (r: number | null) => (r == null ? -90 : -90 + Math.min(180, (Math.log1p(r) / Math.log1p(14.4)) * 180));
  const tone = (left: number | null | undefined) => (left == null ? 'muted' : left < 25 ? 'bad' : left < 50 ? 'warn' : 'ok');
</script>

<div class="slo" data-testid="wall-slo">
  {#if slo && slo.enabled}
    <div class="rings">
      {#each slo.objectives as o (o.name)}
        {@const left = o.budgetRemainingPercent}
        {@const r = burn(o)}
        <figure class="ring {tone(left)}" data-testid="wall-ring">
          <svg viewBox="0 0 100 100" aria-label="{o.name}: {left == null ? 'no data' : `${Math.round(left)} % of the budget left`}">
            <circle cx="50" cy="50" r={R} class="track" />
            <circle cx="50" cy="50" r={R} class="left" stroke-dasharray="{(Math.max(0, Math.min(100, left ?? 0)) / 100) * C} {C}" transform="rotate(-90 50 50)" />
            <line x1="50" y1="50" x2="50" y2="22" class="needle" transform="rotate({angle(r)} 50 50)" />
            <text x="50" y="62" text-anchor="middle" class="big">{left == null ? '–' : `${Math.round(left)}%`}</text>
          </svg>
          <figcaption>{o.name === 'availability' ? 'Answers that work' : o.name === 'latency' ? 'Answers that are quick' : o.name}<br /><span class="muted">burn {r == null ? '–' : r.toFixed(1)}× · {o.sliPercent == null ? '–' : `${o.sliPercent.toFixed(2)} %`}</span></figcaption>
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
    width: 38vmin;
    height: 38vmin;
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
  .needle {
    stroke: var(--text);
    stroke-width: 2;
    stroke-linecap: round;
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
