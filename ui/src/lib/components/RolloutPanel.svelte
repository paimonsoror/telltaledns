<script lang="ts">
  // REQ: CLU-013 (T13.2, ADR-116) — staged rollouts and pins on the Cluster page: a banner while
  // the cluster is pinned (to what, since when, by whom, why, what it holds back; Unpin), the
  // version baking (canaries and what each runs, time left, the guard's readings; Promote,
  // Abort), and the kept versions (Pin to any). Changes need an admin.
  import { api, type S } from '../api';
  import { can } from '../session.svelte';
  import { poll } from '../poll';
  import { duration, logDate, logTime, pct } from '../format';
  // REQ: API-011 — the words the panel says itself; a version, a commit, and a reason are data.
  import { t, type MessageKey } from '../i18n';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';

  let { nodes, onchanged }: { nodes: S['ClusterNode'][]; onchanged?: () => void } = $props();

  let status = $state<S['RolloutStatus'] | null>(null);
  let versions = $state<S['ClusterVersions'] | null>(null);
  let error = $state<unknown>(null);
  let actionError = $state<unknown>(null);
  let done = $state<string | null>(null);
  let busy = $state(false);

  async function load() {
    try {
      status = await api.rolloutStatus();
      error = null;
    } catch (e) {
      error = e;
    }
    try {
      versions = await api.clusterVersions();
    } catch {
      versions = null; // the primary keeps them; unreachable from here now
    }
  }
  $effect(() => poll(load, 5000));

  const label = (id: string) => {
    const n = nodes.find((x) => x.nodeId === id);
    return n ? (n.pod ?? n.site) : id.slice(0, 8);
  };
  const when = (iso: string) => `${logDate(iso)} ${logTime(iso)}`;
  const outcome: Record<string, [MessageKey, string]> = {
    stable: ['clusterWidgets.rollout.outcome.stable', 'ok'],
    canary: ['cluster.stage.baking', 'warn'],
    canary_promoted: ['clusterWidgets.rollout.outcome.promoted', 'ok'],
    canary_failed: ['changes.state.failed', 'bad'],
    superseded: ['clusterWidgets.rollout.outcome.superseded', ''],
    aborted: ['clusterWidgets.rollout.outcome.aborted', 'warn'],
    pinned_to: ['clusterWidgets.rollout.outcome.pin', 'warn'],
  };
  const readings = (r: S['GuardReadings']) =>
    t('clusterWidgets.rollout.readings', {
      before: r.beforePercent != null ? pct(r.beforePercent) : '–',
      after: r.afterPercent != null ? pct(r.afterPercent) : '–',
      answers: r.answers.toLocaleString(),
    });

  async function run(f: () => Promise<S['RolloutAction']>) {
    busy = true;
    actionError = null;
    done = null;
    try {
      done = (await f()).done;
      await load();
      onchanged?.();
    } catch (e) {
      actionError = e;
    } finally {
      busy = false;
    }
  }

  // Pinning: a reason, a dry run that lists what changes, then the pin.
  let pinning = $state<string | null>(null);
  let reason = $state('');
  let pinPreview = $state<S['RolloutAction'] | null>(null);
  function openPin(v: string) {
    pinning = v;
    reason = '';
    pinPreview = null;
    actionError = null;
  }
  async function checkPin() {
    if (!pinning) return;
    busy = true;
    actionError = null;
    try {
      pinPreview = await api.pinVersion(pinning, reason.trim(), true);
    } catch (e) {
      actionError = e;
    } finally {
      busy = false;
    }
  }
  async function pin() {
    const v = pinning;
    if (!v) return;
    await run(() => api.pinVersion(v, reason.trim(), false));
    if (!actionError) pinning = null;
  }
  let unpinPreview = $state<S['RolloutAction'] | null>(null);
  async function checkUnpin() {
    busy = true;
    actionError = null;
    try {
      unpinPreview = await api.unpin(true);
    } catch (e) {
      actionError = e;
    } finally {
      busy = false;
    }
  }
  async function unpin() {
    await run(() => api.unpin(false));
    unpinPreview = null;
  }
  const admin = $derived(can('admin'));
</script>

{#if status?.pinned}
  {@const p = status.pinned}
  <div class="notice warn pin-banner" role="status" data-testid="pin-banner">
    <div>
      <strong>{t('cluster.pin.title', { version: p.to })}</strong>{t('clusterWidgets.rollout.pin.body', {
        when: when(p.since),
        by: p.by,
        reason: p.reason,
      })}<HelpButton id="pins" />
    </div>
    {#if p.changes?.length}
      <div class="small" data-testid="pin-changes">{t('clusterWidgets.rollout.pin.held', { changes: p.changes.join('; ') })}</div>
    {/if}
    {#if admin}
      <div class="row">
        {#if unpinPreview}
          <span class="small"
            >{t('clusterWidgets.rollout.unpin.preview', {
              canaries: status.canaries.length ? t('clusterWidgets.rollout.unpin.canaries') : '',
            })}</span
          >
          <button class="primary" disabled={busy} onclick={unpin} data-testid="unpin-confirm">{t('clusterWidgets.rollout.unpin.confirm')}</button>
          <button disabled={busy} onclick={() => (unpinPreview = null)}>{t('common.cancel')}</button>
        {:else}
          <button disabled={busy} onclick={checkUnpin} data-testid="unpin">{t('clusterWidgets.rollout.unpin.open')}</button>
        {/if}
      </div>
    {/if}
  </div>
{/if}

<section class="card" data-testid="rollout-card">
  <h2>{t('clusterWidgets.rollout.title')}<HelpButton id="rollouts" /></h2>
  <ErrorNote {error} />
  {#if status}
    {#if status.canaries.length === 0}
      <p class="small muted" data-testid="rollout-off">
        {t('clusterWidgets.rollout.off')}
      </p>
    {:else}
      <p class="small">
        {t('clusterWidgets.rollout.canaries')}: <strong>{status.canaries.join(', ')}</strong>{t('clusterWidgets.rollout.canariesBody', {
          bake: duration(status.bakeSecs),
        })}
      </p>
    {/if}
    {#if status.stage === 'canary' && status.version}
      <div class="baking" data-testid="rollout-baking">
        <p>
          <span class="badge warn">{t('cluster.stage.baking')}</span> {t('cluster.col.version')} <strong>{status.version}</strong>{t(
            'clusterWidgets.rollout.baking.runs',
            { nodes: (status.rolloutCanaries ?? []).map(label).join(', '), stable: status.stable },
          )}
          {#if status.secondsLeft != null}<strong>{duration(status.secondsLeft)}</strong>{t('clusterWidgets.rollout.baking.left')}{/if}
        </p>
        {#if status.readings}<p class="small muted" data-testid="rollout-readings">{t('clusterWidgets.rollout.guard', { readings: readings(status.readings) })}</p>{/if}
        {#if admin}
          <div class="row">
            <button disabled={busy} onclick={() => run(api.promoteRollout)} data-testid="rollout-promote">{t('clusterWidgets.rollout.promote')}</button>
            <button disabled={busy} onclick={() => run(api.abortRollout)} data-testid="rollout-abort">{t('clusterWidgets.rollout.abort', { version: status.stable })}</button>
          </div>
        {/if}
      </div>
    {:else if status.stage === 'waiting'}
      <p class="notice warn small" data-testid="rollout-waiting">
        {t('clusterWidgets.rollout.waiting', {
          since: status.waitingSince ? t('clusterWidgets.rollout.waitingSince', { when: when(status.waitingSince) }) : '',
        })}
      </p>
    {:else if status.stage !== 'pinned'}
      <p class="small">{t('clusterWidgets.rollout.everyNode', { version: status.stable })}</p>
    {/if}
    {#if status.skipped}<p class="small muted">{t('clusterWidgets.rollout.skipped', { reason: status.skipped })}</p>{/if}
    {#if status.stage !== 'canary' && status.readings?.reason}
      <p class="small bad-text" data-testid="rollout-last-failure">{t('clusterWidgets.rollout.lastFailure', { reason: status.readings.reason })}</p>
    {/if}
    {#if status.nodes.length && status.canaries.length}
      <table class="compact" data-testid="rollout-nodes">
        <thead><tr><th>{t('qw.cache.node')}</th><th></th><th>{t('clusterWidgets.rollout.col.runs')}</th><th>{t('clusterWidgets.rollout.col.ready')}</th><th class="num">SERVFAIL</th></tr></thead>
        <tbody>
          {#each status.nodes as n (n.node)}
            <tr>
              <td>{label(n.node)}</td>
              <td>{#if n.canary}<span class="badge">{t('cluster.node.canary')}</span>{/if}</td>
              <td>
                {n.appliedSeq}
                {#if status.version && status.stage === 'canary'}
                  {#if String(n.appliedSeq) === status.version.split('.')[1]}<span class="ok-text" title={t('clusterWidgets.rollout.runsBaking')}>✓</span>
                  {:else if n.canary}<span class="muted" title={t('clusterWidgets.rollout.gettingIt')}>…</span>{/if}
                {/if}
              </td>
              <td>{n.connected ? (n.ready ? t('cluster.node.ready') : t('cluster.node.notReady')) : t('clusterWidgets.rollout.gone')}</td>
              <td class="num">{pct(n.servfailPercent)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  {/if}
  <ErrorNote error={actionError} />
  {#if done}<p class="notice ok small" role="status" data-testid="rollout-done">{done}</p>{/if}
</section>

{#if versions && versions.items.length}
  <section class="card" data-testid="versions-card">
    <h2>{t('clusterWidgets.rollout.versions.title')}<HelpButton id="pins" /></h2>
    <p class="muted small">{t('clusterWidgets.rollout.versions.about', { n: versions.history })}</p>
    <div class="table-wrap">
      <table class="compact">
        <thead><tr><th>{t('cluster.col.version')}</th><th>{t('clusterWidgets.rollout.versions.col.published')}</th><th>{t('clusterWidgets.rollout.versions.col.outcome')}</th><th>{t('clusterWidgets.rollout.versions.col.by')}</th><th></th></tr></thead>
        <tbody>
          {#each versions.items as v (v.version)}
            {@const [text, cls] = outcome[v.outcome] ?? ([null, ''] as [MessageKey | null, string])}
            <tr data-testid="version-row">
              <td class="mono">{v.version}{#if v.current} <span class="badge ok">{t('clusterWidgets.rollout.versions.current')}</span>{/if}</td>
              <td class="small">{when(v.created)}</td>
              <td>
                <span class="badge {cls}">{text ? t(text) : v.outcome}{v.pinnedTo ? ` ${v.pinnedTo}` : ''}</span>
                {#if v.readings?.reason}<div class="small muted">{v.readings.reason}</div>{/if}
                {#if v.reason && v.outcome === 'pinned_to'}<div class="small muted">{v.reason}</div>{/if}
              </td>
              <td class="small">{v.by}</td>
              <td class="actions">
                {#if admin && !v.current && v.pinnable && v.outcome !== 'pinned_to'}
                  <button class="link small" onclick={() => openPin(v.version)} data-testid="pin-open">{t('clusterWidgets.rollout.pin.open')}</button>
                {/if}
              </td>
            </tr>
            {#if pinning === v.version}
              <tr>
                <td colspan="5">
                  <div class="pin-form" data-testid="pin-form">
                    <label>
                      {t('clusterWidgets.rollout.pin.why', { version: v.version })}
                      <input
                        bind:value={reason}
                        maxlength="200"
                        placeholder={t('clusterWidgets.rollout.pin.reasonPlaceholder')}
                        aria-label={t('clusterWidgets.rollout.pin.reasonAria')}
                      />
                    </label>
                    {#if pinPreview}
                      <p class="small" data-testid="pin-preview">
                        {pinPreview.changes?.length
                          ? t('clusterWidgets.rollout.pin.changes', { changes: pinPreview.changes.join('; ') })
                          : t('clusterWidgets.rollout.pin.same')}
                        {t('clusterWidgets.rollout.pin.waits')}
                      </p>
                      <div class="row">
                        <button class="primary" disabled={busy} onclick={pin} data-testid="pin-confirm">{t('clusterWidgets.rollout.pin.confirm')}</button>
                        <button disabled={busy} onclick={() => (pinPreview = null)}>{t('settings.editor.changeIt')}</button>
                      </div>
                    {:else}
                      <div class="row">
                        <button disabled={busy || !reason.trim()} onclick={checkPin} data-testid="pin-check">{t('settings.editor.check')}</button>
                        <button onclick={() => (pinning = null)}>{t('common.cancel')}</button>
                      </div>
                    {/if}
                  </div>
                </td>
              </tr>
            {/if}
          {/each}
        </tbody>
      </table>
    </div>
  </section>
{/if}

<style>
  .pin-banner {
    display: grid;
    gap: 6px;
    margin-bottom: var(--gap);
  }
  .row {
    display: flex;
    gap: 8px;
    align-items: center;
    flex-wrap: wrap;
  }
  .baking {
    border: 1px dashed var(--warn);
    border-radius: 8px;
    padding: 8px 12px;
    margin: 8px 0;
  }
  .baking p {
    margin: 0 0 6px;
  }
  .pin-form {
    display: grid;
    gap: 8px;
    max-width: 520px;
  }
  .pin-form label {
    display: grid;
    gap: 4px;
  }
  .actions {
    text-align: right;
  }
  .ok-text {
    color: var(--ok);
  }
  .bad-text {
    color: var(--bad);
  }
  .table-wrap {
    overflow-x: auto;
  }
</style>
