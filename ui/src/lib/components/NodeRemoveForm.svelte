<script lang="ts">
  // REQ: CLU-001 (ADR-155) — remove a node from the cluster (an admin): the confirmation first
  // shows what the primary says would happen (a dry run), and a node that is up is cut off only
  // when the box is ticked (force).
  import { onMount } from 'svelte';
  import { api, ApiError, type S } from '../api';
  // REQ: API-011 — the confirmation's own words; the site and the notes are the page's.
  import { t, tn } from '../i18n';
  import ErrorNote from './ErrorNote.svelte';

  let {
    nodeId,
    site,
    up,
    failoverActive,
    onclose,
    ondone,
  }: {
    nodeId: string;
    site: string;
    /** Up in the cluster view the page shows. */
    up: boolean;
    /** Automatic failover runs now. */
    failoverActive: boolean;
    onclose: () => void;
    ondone: (r: S['NodeRemoval']) => void;
  } = $props();

  let preview = $state<S['NodeRemoval'] | null>(null);
  let error = $state<unknown>(null);
  let busy = $state(false);
  let sure = $state(false);
  // The primary said the node is up although the page had it down: it needs the box too.
  let sawUp = $state(false);
  const isUp = $derived(up || sawUp || (preview?.up ?? false));

  // A 409 `node_is_up` (it came up since the page loaded) turns the box on and checks again.
  async function failed(e: unknown) {
    if (e instanceof ApiError && e.code === 'node_is_up' && !isUp) {
      sawUp = true;
      await check();
    } else {
      error = e;
    }
  }

  async function check() {
    try {
      preview = await api.removeNode(nodeId, { dryRun: true, force: isUp });
      error = null;
    } catch (e) {
      await failed(e);
    }
  }
  onMount(check);

  async function remove() {
    busy = true;
    error = null;
    try {
      ondone(await api.removeNode(nodeId, { force: isUp }));
    } catch (e) {
      await failed(e);
    } finally {
      busy = false;
    }
  }

  const voters = $derived.by(() => {
    if (!preview) return '';
    const left = tn('clusterWidgets.remove.voters', preview.votersAfter);
    if (preview.automaticFailoverAfter) return t('clusterWidgets.remove.staysOn', { left });
    return failoverActive
      ? t('clusterWidgets.remove.turnsManual', { left })
      : t('clusterWidgets.remove.staysOff', { left });
  });
</script>

<div class="notice node-remove" role="dialog" aria-label={t('clusterWidgets.remove.aria', { site })} data-testid="node-remove-form">
  <p>
    <strong>{t('clusterWidgets.remove.title', { site })}</strong> {t('clusterWidgets.remove.body')}
  </p>
  <p class="small">{t('clusterWidgets.remove.nodeId')} <span class="mono id" data-testid="node-remove-id">{nodeId}</span></p>
  {#if preview}
    <div data-testid="node-remove-preview">
      <p class="small">{voters}</p>
      {#if preview.notes.length}
        <ul class="small notes">
          {#each preview.notes as n, i (i)}<li>{n}</li>{/each}
        </ul>
      {/if}
    </div>
  {/if}
  {#if isUp}
    <label class="check"
      ><input type="checkbox" bind:checked={sure} data-testid="node-remove-force" /> {t('clusterWidgets.remove.force')}</label
    >
  {/if}
  <ErrorNote {error} />
  <div class="row">
    <button class="danger" onclick={remove} disabled={busy || !preview || (isUp && !sure)} data-testid="node-remove-confirm"
      >{busy ? t('clusterWidgets.remove.removing') : t('clusterWidgets.remove.confirm')}</button
    >
    <button onclick={onclose}>{t('common.cancel')}</button>
  </div>
</div>

<style>
  .node-remove {
    margin: 8px 0;
    max-width: 640px;
  }
  .id {
    user-select: all;
    word-break: break-all;
  }
  .notes {
    margin: 4px 0;
    padding-left: 18px;
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
