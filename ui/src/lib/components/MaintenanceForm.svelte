<script lang="ts">
  // REQ: OPS-010 (ADR-118) — start maintenance on a node: how long (presets or minutes), why,
  // and, for the primary under automatic failover with another eligible node online, whether to
  // hand the primary role over first (checked by default). Otherwise a primary keeps the role,
  // and the form says to promote another node first.
  import { api, type S } from '../api';
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

  const presets: [string, number][] = [
    ['30 min', 1800],
    ['1 h', 3600],
    ['2 h', 7200],
    ['4 h', 14_400],
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

<div class="notice maint-form" role="dialog" aria-label={`Maintenance for ${label}`} data-testid="maintenance-form">
  <p>
    <strong>Put {label} in maintenance?</strong> It reports not ready, so load balancers and Kubernetes stop sending it new
    queries, but it keeps answering every query that still arrives. Its alerts and health conditions are left out until the
    window ends.
  </p>
  <div class="row presets" role="radiogroup" aria-label="How long">
    {#each presets as [text, s] (s)}
      <label class="seg-item"><input type="radio" name="maint-for" value={s} bind:group={secs} /> {text}</label>
    {/each}
    <label class="seg-item"><input type="radio" name="maint-for" value="custom" bind:group={secs} /> other</label>
    {#if secs === 'custom'}
      <label class="minutes"
        ><input type="number" min="1" max="1440" step="1" bind:value={customMinutes} aria-label="Minutes" /> minutes</label
      >
    {/if}
  </div>
  <label class="field">Why <input bind:value={reason} maxlength="200" placeholder="SD card swap" data-testid="maintenance-reason" /></label>
  {#if primary && canHandover}
    <label class="check"
      ><input type="checkbox" bind:checked={handover} data-testid="maintenance-handover" /> Hand the primary role to another node first
      (about 30 s without configuration changes)</label
    >
  {:else if primary}
    <p class="small muted" data-testid="maintenance-primary-note">
      This node is the primary; it keeps publishing. Promote another node first if you're taking it offline (see Promote on that
      node's Cluster page).
    </p>
  {/if}
  <ErrorNote {error} />
  <div class="row">
    <button class="primary" onclick={start} disabled={busy || !valid} data-testid="maintenance-start">{busy ? 'Starting…' : 'Start maintenance'}</button>
    <button onclick={onclose}>Cancel</button>
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
