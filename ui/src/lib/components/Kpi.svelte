<script lang="ts">
  let { label, value, sub = '', tone = '' }: { label: string; value: string; sub?: string; tone?: string } = $props();
</script>

<div class="card kpi">
  <div class="label">{label}</div>
  <div class="value {tone}">{value}</div>
  {#if sub}<div class="sub muted small">{sub}</div>{/if}
</div>

<style>
  .kpi {
    padding: 12px 14px;
  }
  .label {
    font-size: 12px;
    color: var(--muted);
  }
  .value {
    font-size: 24px;
    font-weight: 700;
    font-variant-numeric: tabular-nums;
    line-height: 1.3;
  }
  .value.bad {
    color: var(--bad);
  }
  .value.ok {
    color: var(--ok);
  }
</style>
