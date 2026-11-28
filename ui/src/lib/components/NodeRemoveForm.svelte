<script lang="ts">
  // REQ: CLU-001 (ADR-155) — remove a node from the cluster (an admin): the confirmation first
  // shows what the primary says would happen (a dry run), and a node that is up is cut off only
  // when the box is ticked (force).
  import { onMount } from 'svelte';
  import { api, ApiError, type S } from '../api';
  import ErrorNote from './ErrorNote.svelte';
  import { tr } from '../i18n';
  import T from '../i18n/T.svelte';
  const { t, tn } = tr('nodeRemoveForm');

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

  // REQ: API-012 — `votersAfter` is a count (u32 on the server): tn() gives the ternary's English.
  const voters = $derived.by(() => {
    if (!preview) return '';
    const n = preview.votersAfter;
    if (preview.automaticFailoverAfter) return tn('{n} voter left; automatic failover stays on.', '{n} voters left; automatic failover stays on.', n, { n });
    return failoverActive
      ? tn('{n} voter left; automatic failover turns into manual.', '{n} voters left; automatic failover turns into manual.', n, { n })
      : tn('{n} voter left; automatic failover stays off (it needs 3).', '{n} voters left; automatic failover stays off (it needs 3).', n, { n });
  });
</script>

<div class="notice node-remove" role="dialog" aria-label={t('Remove {site} from the cluster', { site })} data-testid="node-remove-form">
  <p>
    <T
      ctx="nodeRemoveForm"
      msg={"<strong>Remove {site} from the cluster?</strong> It stops counting as a voter, disappears from this page, and the cluster refuses it afterwards, even while its certificate is valid. Its own data isn't touched."}
      params={{ site }}>{#snippet strong(text: string)}<strong>{text}</strong>{/snippet}</T
    >
  </p>
  <p class="small">{t('Node ID')} <span class="mono id" data-testid="node-remove-id" translate="no">{nodeId}</span></p>
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
      ><input type="checkbox" bind:checked={sure} data-testid="node-remove-force" /> {t('It is up. Remove it anyway: its connection is closed and the cluster refuses it afterwards.')}</label
    >
  {/if}
  <ErrorNote {error} />
  <div class="row">
    <button class="danger" onclick={remove} disabled={busy || !preview || (isUp && !sure)} data-testid="node-remove-confirm"
      >{busy ? t('Removing…') : t('Remove')}</button
    >
    <button onclick={onclose}>{t('Cancel')}</button>
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
