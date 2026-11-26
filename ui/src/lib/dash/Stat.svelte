<script lang="ts">
  import { num } from '../format';
  import { tr } from '../i18n';
  const { t } = tr('stat');

  // Dashboard lab — one number with its label and its change against the previous period. No
  // card, ring or sparkline: the change is plain colored text, colored by what is good for the
  // metric, not by direction.
  let {
    label,
    value,
    sub = '',
    delta = null,
    good = 'neutral',
    tone = '',
    size = 'md',
  }: {
    label: string;
    value: string;
    sub?: string;
    delta?: number | null;
    good?: 'up' | 'down' | 'neutral';
    tone?: 'bad' | 'ok' | '';
    size?: 'sm' | 'md' | 'lg';
  } = $props();

  const kind = $derived(
    delta == null || Math.abs(delta) < 0.005 || good === 'neutral' ? 'flat' : (delta > 0) === (good === 'up') ? 'good' : 'bad',
  );
  const text = $derived.by(() => {
    if (delta == null || !Number.isFinite(delta) || Math.abs(delta) < 0.005) return '';
    const p = Math.abs(delta) * 100;
    return `${delta > 0 ? '▲' : '▼'} ${p >= 100 ? num(Math.round(p)) : p.toFixed(p < 10 ? 1 : 0)}%`;
  });
</script>

<div class="stat {size}">
  <div class="label">{label}</div>
  <div class="value {tone}">{value}</div>
  {#if text || sub}
    <div class="foot">
      {#if text}<span class="delta {kind}" title={t('Against the previous period of the same length')}>{text}</span>{/if}
      {#if sub}<span class="sub">{sub}</span>{/if}
    </div>
  {/if}
</div>

<style>
  .stat {
    min-width: 0;
  }
  .label {
    font-size: 12.5px;
    color: var(--muted);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .value {
    font-weight: 650;
    letter-spacing: -0.02em;
    font-variant-numeric: tabular-nums;
    line-height: 1.2;
    white-space: nowrap;
  }
  .sm .value {
    font-size: 18px;
  }
  .md .value {
    font-size: 26px;
  }
  .lg .value {
    font-size: 38px;
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
    gap: 0 8px;
    font-size: 12px;
    color: var(--muted);
    font-variant-numeric: tabular-nums;
  }
  .delta.good {
    color: var(--ok-strong);
  }
  .delta.bad {
    color: var(--bad-strong);
  }
</style>
