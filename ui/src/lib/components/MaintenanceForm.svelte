<script lang="ts">
  // REQ: OPS-010 (ADR-118) — start maintenance on a node: how long (presets or minutes), why,
  // and, for the primary under automatic failover with another eligible node online, whether to
  // hand the primary role over first (checked by default). Otherwise a primary keeps the role,
  // and the form says to promote another node first.
  import { api, type S } from '../api';
  // REQ: API-011 — the form's own words; the label it is given is already the page's.
  import { t, type MessageKey } from '../i18n';
  import ErrorNote from './ErrorNote.svelte';

  let {
    node,
    label,
    primary = false,
    canHandover = false,
    onclose,
    ondone,
  }: {
    /** `local` or a node ID (what the API takes). */
    node: string;
    /** How the node is shown. */
    label: string;
    primary?: boolean;
    canHandover?: boolean;
    onclose: () => void;
    ondone: (r: S['MaintenanceResult']) => void;
  } = $props();

  const presets: [MessageKey, number][] = [
    ['clusterWidgets.maintenance.preset.30m', 1800],
    ['flow.window.1h', 3600],
    ['clusterWidgets.maintenance.preset.2h', 7200],
    ['clusterWidgets.maintenance.preset.4h', 14_400],
  ];
  let secs = $state<number | 'custom'>(3600);
  let customMinutes = $state(90);
  let reason = $state('');
  let handover = $state(true);
  let busy = $state(false);
  let error = $state<unknown>(null);
  const forSecs = $derived(secs === 'custom' ? Math.round(customMinutes * 60) : secs);
  const valid = $derived(reason.trim().length > 0 && forSecs >= 60 && forSecs <= 86_400);

  async function start() {
    busy = true;
    error = null;
    try {
      const r = await api.startMaintenance(node, { forSecs, reason: reason.trim(), handover: primary && canHandover ? handover : undefined });
      ondone(r);
    } catch (e) {
      error = e;
    } finally {
      busy = false;
    }
  }
</script>

<div class="notice maint-form" role="dialog" aria-label={t('clusterWidgets.maintenance.aria', { label })} data-testid="maintenance-form">
  <p>
    <strong>{t('clusterWidgets.maintenance.title', { label })}</strong> {t('clusterWidgets.maintenance.body')}
  </p>
  <div class="row presets" role="radiogroup" aria-label={t('clusterWidgets.maintenance.howLong')}>
    {#each presets as [text, s] (s)}
      <label class="seg-item"><input type="radio" name="maint-for" value={s} bind:group={secs} /> {t(text)}</label>
    {/each}
    <label class="seg-item"><input type="radio" name="maint-for" value="custom" bind:group={secs} /> {t('clusterWidgets.maintenance.other')}</label>
    {#if secs === 'custom'}
      <label class="minutes"
        ><input type="number" min="1" max="1440" step="1" bind:value={customMinutes} aria-label={t('clusterWidgets.maintenance.minutesAria')} /> {t(
          'heatmap.slot.minute',
        )}</label
      >
    {/if}
  </div>
  <label class="field"
    >{t('changes.plan.why')} <input
      bind:value={reason}
      maxlength="200"
      placeholder={t('clusterWidgets.maintenance.reasonPlaceholder')}
      data-testid="maintenance-reason"
    /></label
  >
  {#if primary && canHandover}
    <label class="check"
      ><input type="checkbox" bind:checked={handover} data-testid="maintenance-handover" /> {t('clusterWidgets.maintenance.handover')}</label
    >
  {:else if primary}
    <p class="small muted" data-testid="maintenance-primary-note">
      {t('clusterWidgets.maintenance.primaryNote')}
    </p>
  {/if}
  <ErrorNote {error} />
  <div class="row">
    <button class="primary" onclick={start} disabled={busy || !valid} data-testid="maintenance-start"
      >{busy ? t('clusterWidgets.drill.starting') : t('clusterWidgets.maintenance.start')}</button
    >
    <button onclick={onclose}>{t('common.cancel')}</button>
  </div>
</div>

<style>
  .maint-form {
    margin: 8px 0;
    max-width: 640px;
  }
  .presets {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    align-items: center;
    margin: 8px 0;
  }
  .seg-item,
  .minutes {
    display: inline-flex;
    gap: 4px;
    align-items: center;
  }
  .minutes input {
    width: 80px;
  }
  .field {
    display: flex;
    flex-direction: column;
    gap: 4px;
    margin: 8px 0;
    max-width: 360px;
  }
  .check {
    display: flex;
    gap: 6px;
    align-items: baseline;
    margin: 8px 0;
  }
  .row {
    display: flex;
    gap: 8px;
  }
</style>
