<script lang="ts">
  // REQ: CLU-013 (T13.2, ADR-116) — staged rollouts and pins on the Cluster page: a banner while
  // the cluster is pinned (to what, since when, by whom, why, what it holds back; Unpin), the
  // version baking (canaries and what each runs, time left, the guard's readings; Promote,
  // Abort), and the kept versions (Pin to any). Changes need an admin.
  import { api, type S } from '../api';
  import { can } from '../session.svelte';
  import { poll } from '../poll';
  import { duration, logDate, logTime, num, pct } from '../format';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';
  import { own, tr } from '../i18n';
  import T from '../i18n/T.svelte';
  const { t } = tr('rolloutPanel');

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
  // REQ: API-012 — the waiting sentence with a start time reads "come online(since …)", with no space
  // before the parenthesis: the page always showed it so (Svelte trims the space at the start of an
  // {#if} block), and the English stays as it was.
  const when = (iso: string) => `${logDate(iso)} ${logTime(iso)}`;
  const outcome: Record<string, [string, string]> = {
    stable: [t('stable'), 'ok'],
    canary: [t('baking'), 'warn'],
    canary_promoted: [t('promoted'), 'ok'],
    canary_failed: [t('failed'), 'bad'],
    superseded: [t('superseded'), ''],
    aborted: [t('aborted'), 'warn'],
    pinned_to: [t('pin'), 'warn'],
  };
  /** A version's outcome as the server sends it: one the UI doesn't know shows as it is. */
  const outcomeOf = (o: string): [string, string] => (own(outcome, o) ?? [o, '']);
  const readings = (r: S['GuardReadings']) =>
    t('SERVFAIL {before} before, {after} during ({n} answers)', { before: r.beforePercent != null ? pct(r.beforePercent) : '–', after: r.afterPercent != null ? pct(r.afterPercent) : '–', n: num(r.answers) });

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

{#snippet strong(x: string)}<strong>{x}</strong>{/snippet}

{#if status?.pinned}
  {@const p = status.pinned}
  <div class="notice warn pin-banner" role="status" data-testid="pin-banner">
    <div>
      <T ctx="rolloutPanel" msg={"<strong>The cluster is pinned to version {to}</strong> since {since} by {by}: {reason}. Every node serves that version, and configuration changes wait until it's unpinned."} params={{ to: p.to, since: when(p.since), by: p.by, reason: p.reason }} {strong} /><HelpButton id="pins" />
    </div>
    {#if p.changes?.length}
      <div class="small" data-testid="pin-changes">{t('Held back since then: {changes}.', { changes: p.changes.join('; ') })}</div>
    {/if}
    {#if admin}
      <div class="row">
        {#if unpinPreview}
          <span class="small">{status.canaries.length ? t('Unpinning publishes the current configuration, to the canary nodes first.') : t('Unpinning publishes the current configuration.')}</span>
          <button class="primary" disabled={busy} onclick={unpin} data-testid="unpin-confirm">{t('Unpin')}</button>
          <button disabled={busy} onclick={() => (unpinPreview = null)}>{t('Cancel')}</button>
        {:else}
          <button disabled={busy} onclick={checkUnpin} data-testid="unpin">{t('Unpin…')}</button>
        {/if}
      </div>
    {/if}
  </div>
{/if}

<section class="card" data-testid="rollout-card">
  <h2>{t('Staged rollouts')}<HelpButton id="rollouts" /></h2>
  <ErrorNote {error} />
  {#if status}
    {#if status.canaries.length === 0}
      <p class="small muted" data-testid="rollout-off">
        {t('Off: a change reaches every node at once. Name canary nodes in Settings → Cluster to give new versions to them first.')}
      </p>
    {:else}
      <p class="small">
        <T ctx="rolloutPanel" msg={'Canaries: <strong>{canaries}</strong>. A change reaches them and the primary first, and every other node after {bake} if nothing fails.'} params={{ canaries: status.canaries.join(', '), bake: duration(status.bakeSecs) }} {strong} />
      </p>
    {/if}
    {#if status.stage === 'canary' && status.version}
      <div class="baking" data-testid="rollout-baking">
        <p>
          <span class="badge warn">{t('baking')}</span>
          <T ctx="rolloutPanel" msg={'Version <strong>{version}</strong> runs on {nodes} and the primary; the others stay on {stable}.'} params={{ version: status.version, nodes: (status.rolloutCanaries ?? []).map(label).join(', '), stable: status.stable }} {strong} />
          {#if status.secondsLeft != null}<T ctx="rolloutPanel" msg={'<strong>{time}</strong> left.'} params={{ time: duration(status.secondsLeft) }} {strong} />{/if}
        </p>
        {#if status.readings}<p class="small muted" data-testid="rollout-readings">{t('Guard: {readings}', { readings: readings(status.readings) })}</p>{/if}
        {#if admin}
          <div class="row">
            <button disabled={busy} onclick={() => run(api.promoteRollout)} data-testid="rollout-promote">{t('Promote now')}</button>
            <button disabled={busy} onclick={() => run(api.abortRollout)} data-testid="rollout-abort">{t('Abort (pin to {stable})', { stable: status.stable })}</button>
          </div>
        {/if}
      </div>
    {:else if status.stage === 'waiting'}
      <p class="notice warn small" data-testid="rollout-waiting">
        {#if status.waitingSince}{t('A change waits for a canary node to come online(since {when}); after a minute it goes to every node at once.', { when: when(status.waitingSince) })}{:else}{t('A change waits for a canary node to come online; after a minute it goes to every node at once.')}{/if}
      </p>
    {:else if status.stage !== 'pinned'}
      <p class="small">{t('Every node runs version {stable}.', { stable: status.stable })}</p>
    {/if}
    {#if status.skipped}<p class="small muted">{t('The last change went to every node at once: {skipped}.', { skipped: status.skipped })}</p>{/if}
    {#if status.stage !== 'canary' && status.readings?.reason}
      <p class="small bad-text" data-testid="rollout-last-failure">{t('Last failure: {reason}', { reason: status.readings.reason })}</p>
    {/if}
    {#if status.nodes.length && status.canaries.length}
      <table class="compact" data-testid="rollout-nodes">
        <thead><tr><th>{t('Node')}</th><th></th><th>{t('Runs')}</th><th>{t('Ready')}</th><th class="num">{t('SERVFAIL')}</th></tr></thead>
        <tbody>
          {#each status.nodes as n (n.node)}
            <tr>
              <td>{label(n.node)}</td>
              <td>{#if n.canary}<span class="badge">{t('canary')}</span>{/if}</td>
              <td>
                {n.appliedSeq}
                {#if status.version && status.stage === 'canary'}
                  {#if String(n.appliedSeq) === status.version.split('.')[1]}<span class="ok-text" title={t('runs the version baking')}>✓</span>
                  {:else if n.canary}<span class="muted" title={t('getting it')}>…</span>{/if}
                {/if}
              </td>
              <td>{n.connected ? (n.ready ? t('ready') : t('not ready')) : t('gone')}</td>
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
    <h2>{t('Versions')}<HelpButton id="pins" /></h2>
    <p class="muted small">{t('The last {n} versions the primary published, newest first. Pinning one serves it on every node again, as a new version.', { n: versions.history })}</p>
    <div class="table-wrap">
      <table class="compact">
        <thead><tr><th>{t('Version')}</th><th>{t('Published')}</th><th>{t('Outcome')}</th><th>{t('By')}</th><th></th></tr></thead>
        <tbody>
          {#each versions.items as v (v.version)}
            {@const [text, cls] = outcomeOf(v.outcome)}
            <tr data-testid="version-row">
              <td class="mono">{v.version}{#if v.current} <span class="badge ok">{t('current')}</span>{/if}</td>
              <td class="small">{when(v.created)}</td>
              <td>
                <span class="badge {cls}">{text}{v.pinnedTo ? ` ${v.pinnedTo}` : ''}</span>
                {#if v.readings?.reason}<div class="small muted">{v.readings.reason}</div>{/if}
                {#if v.reason && v.outcome === 'pinned_to'}<div class="small muted">{v.reason}</div>{/if}
              </td>
              <td class="small">{v.by}</td>
              <td class="actions">
                {#if admin && !v.current && v.pinnable && v.outcome !== 'pinned_to'}
                  <button class="link small" onclick={() => openPin(v.version)} data-testid="pin-open">{t('Pin…')}</button>
                {/if}
              </td>
            </tr>
            {#if pinning === v.version}
              <tr>
                <td colspan="5">
                  <div class="pin-form" data-testid="pin-form">
                    <label>
                      {t('Why pin to version {version}?', { version: v.version })}
                      <input bind:value={reason} maxlength="200" placeholder={t('the new upstream breaks banking sites')} aria-label={t('Reason')} />
                    </label>
                    {#if pinPreview}
                      <p class="small" data-testid="pin-preview">
                        {pinPreview.changes?.length
                          ? t('Every node changes: {changes}. Configuration changes wait until you unpin.', { changes: pinPreview.changes.join('; ') })
                          : t('The configuration is the same; the filter snapshot may differ. Configuration changes wait until you unpin.')}
                      </p>
                      <div class="row">
                        <button class="primary" disabled={busy} onclick={pin} data-testid="pin-confirm">{t('Pin')}</button>
                        <button disabled={busy} onclick={() => (pinPreview = null)}>{t('Change it')}</button>
                      </div>
                    {:else}
                      <div class="row">
                        <button disabled={busy || !reason.trim()} onclick={checkPin} data-testid="pin-check">{t('Check')}</button>
                        <button onclick={() => (pinning = null)}>{t('Cancel')}</button>
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
