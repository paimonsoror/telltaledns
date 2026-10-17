<script lang="ts">
  // REQ: OBS-035 (T14.15, ADR-141) — the wall's "right now" tile: the last hour's queries per
  // second, blocked share, and answers from the cache, and the health word; every 15 s. It fills
  // the gaps on wide and large screens, and reads only what the dashboard reads.
  import { api, type S } from '../../api';
  import { poll } from '../../poll';
  import { num } from '../../format';

  let summary = $state<S['Summary'] | null>(null);
  let health = $state<S['Health'] | null>(null);
  let w = $state(0);
  $effect(() =>
    poll(async () => {
      try {
        summary = await api.summary('-1h');
      } catch {
        // The wall keeps the last picture.
      }
      health = await api.health().catch(() => health);
    }, 15_000),
  );
  const span = $derived(summary ? Math.max(1, summary.toUnixSeconds - summary.fromUnixSeconds) : 3600);
  const qps = $derived(summary ? summary.queries / span : null);
  const tiles = $derived([
    { label: 'queries / s', value: qps == null ? '–' : qps < 10 ? qps.toFixed(1) : num(Math.round(qps)) },
    { label: 'blocked', value: summary ? `${summary.blockedPercent.toFixed(1)}%` : '–' },
    { label: 'from the cache', value: summary ? `${summary.cacheHitPercent.toFixed(0)}%` : '–' },
    { label: 'health', value: health?.level ?? '–', tone: health?.level },
  ]);
</script>

<div class="kpi" class:narrow={w > 0 && w < 420} bind:clientWidth={w} data-testid="wall-kpi">
  {#each tiles as t (t.label)}
    <div class="tile">
      <span class="value {t.tone ?? ''}">{t.value}</span>
      <span class="label">{t.label}</span>
    </div>
  {/each}
</div>

<style>
  .kpi {
    width: 100%;
    height: 100%;
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1.5vmin;
    align-content: center;
  }
  .kpi.narrow {
    grid-template-columns: 1fr;
  }
  .tile {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    min-width: 0;
  }
  .value {
    font-size: 4.5vmin;
    font-variant-numeric: tabular-nums;
    line-height: 1.1;
  }
  .narrow .value {
    font-size: 3.2vmin;
  }
  .value.healthy {
    color: var(--ok, var(--s-cached));
  }
  .value.degraded {
    color: var(--warn);
  }
  .value.severe {
    color: var(--bad);
  }
  .label {
    font-size: 1.6vmin;
    color: var(--muted);
  }
</style>
