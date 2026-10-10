<script lang="ts">
  // REQ: CLU-013 (T13.2, ADR-116) — staged rollouts and pins on the Cluster page: a banner while
  // the cluster is pinned (to what, since when, by whom, why, what it holds back; Unpin), the
  // version baking (canaries and what each runs, time left, the guard's readings; Promote,
  // Abort), and the kept versions (Pin to any). Changes need an admin.
  import { api, type S } from '../api';
  import { can } from '../session.svelte';
  import { poll } from '../poll';
  import { duration, logDate, logTime, pct } from '../format';
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
  const when = (t: string) => `${logDate(t)} ${logTime(t)}`;
  const outcome: Record<string, [string, string]> = {
    stable: ['stable', 'ok'],
    canary: ['baking', 'warn'],
    canary_promoted: ['promoted', 'ok'],
    canary_failed: ['failed', 'bad'],
    superseded: ['superseded', ''],
    aborted: ['aborted', 'warn'],
    pinned_to: ['pin', 'warn'],
  };
  const readings = (r: S['GuardReadings']) =>
    `SERVFAIL ${r.beforePercent != null ? pct(r.beforePercent) : '–'} before, ${r.afterPercent != null ? pct(r.afterPercent) : '–'} during (${r.answers.toLocaleString()} answers)`;

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
      <strong>The cluster is pinned to version {p.to}</strong> since {when(p.since)} by {p.by}: {p.reason}. Every node serves
      that version, and configuration changes wait until it's unpinned.<HelpButton id="pins" />
    </div>
    {#if p.changes?.length}
      <div class="small" data-testid="pin-changes">Held back since then: {p.changes.join('; ')}.</div>
    {/if}
    {#if admin}
      <div class="row">
        {#if unpinPreview}
          <span class="small">Unpinning publishes the current configuration{status.canaries.length ? ', to the canary nodes first' : ''}.</span>
          <button class="primary" disabled={busy} onclick={unpin} data-testid="unpin-confirm">Unpin</button>
          <button disabled={busy} onclick={() => (unpinPreview = null)}>Cancel</button>
        {:else}
          <button disabled={busy} onclick={checkUnpin} data-testid="unpin">Unpin…</button>
        {/if}
      </div>
    {/if}
  </div>
{/if}

<section class="card" data-testid="rollout-card">
  <h2>Staged rollouts<HelpButton id="rollouts" /></h2>
  <ErrorNote {error} />
  {#if status}
    {#if status.canaries.length === 0}
      <p class="small muted" data-testid="rollout-off">
        Off: a change reaches every node at once. Name canary nodes in Settings → Cluster to give new versions to them
        first.
      </p>
    {:else}
      <p class="small">
        Canaries: <strong>{status.canaries.join(', ')}</strong>. A change reaches them and the primary first, and every other
        node after {duration(status.bakeSecs)} if nothing fails.
      </p>
    {/if}
    {#if status.stage === 'canary' && status.version}
      <div class="baking" data-testid="rollout-baking">
        <p>
          <span class="badge warn">baking</span> Version <strong>{status.version}</strong> runs on {(status.rolloutCanaries ?? []).map(label).join(', ')}
          and the primary; the others stay on {status.stable}.
          {#if status.secondsLeft != null}<strong>{duration(status.secondsLeft)}</strong> left.{/if}
        </p>
        {#if status.readings}<p class="small muted" data-testid="rollout-readings">Guard: {readings(status.readings)}</p>{/if}
        {#if admin}
          <div class="row">
            <button disabled={busy} onclick={() => run(api.promoteRollout)} data-testid="rollout-promote">Promote now</button>
            <button disabled={busy} onclick={() => run(api.abortRollout)} data-testid="rollout-abort">Abort (pin to {status.stable})</button>
          </div>
        {/if}
      </div>
    {:else if status.stage === 'waiting'}
      <p class="notice warn small" data-testid="rollout-waiting">
        A change waits for a canary node to come online{#if status.waitingSince} (since {when(status.waitingSince)}){/if}; after a
        minute it goes to every node at once.
      </p>
    {:else if status.stage !== 'pinned'}
      <p class="small">Every node runs version {status.stable}.</p>
    {/if}
    {#if status.skipped}<p class="small muted">The last change went to every node at once: {status.skipped}.</p>{/if}
    {#if status.stage !== 'canary' && status.readings?.reason}
      <p class="small bad-text" data-testid="rollout-last-failure">Last failure: {status.readings.reason}</p>
    {/if}
    {#if status.nodes.length && status.canaries.length}
      <table class="compact" data-testid="rollout-nodes">
        <thead><tr><th>Node</th><th></th><th>Runs</th><th>Ready</th><th class="num">SERVFAIL</th></tr></thead>
        <tbody>
          {#each status.nodes as n (n.node)}
            <tr>
              <td>{label(n.node)}</td>
              <td>{#if n.canary}<span class="badge">canary</span>{/if}</td>
              <td>
                {n.appliedSeq}
                {#if status.version && status.stage === 'canary'}
                  {#if String(n.appliedSeq) === status.version.split('.')[1]}<span class="ok-text" title="runs the version baking">✓</span>
                  {:else if n.canary}<span class="muted" title="getting it">…</span>{/if}
                {/if}
              </td>
              <td>{n.connected ? (n.ready ? 'ready' : 'not ready') : 'gone'}</td>
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
    <h2>Versions<HelpButton id="pins" /></h2>
    <p class="muted small">The last {versions.history} versions the primary published, newest first. Pinning one serves it on every node again, as a new version.</p>
    <div class="table-wrap">
      <table class="compact">
        <thead><tr><th>Version</th><th>Published</th><th>Outcome</th><th>By</th><th></th></tr></thead>
        <tbody>
          {#each versions.items as v (v.version)}
            {@const [text, cls] = outcome[v.outcome] ?? [v.outcome, '']}
            <tr data-testid="version-row">
              <td class="mono">{v.version}{#if v.current} <span class="badge ok">current</span>{/if}</td>
              <td class="small">{when(v.created)}</td>
              <td>
                <span class="badge {cls}">{text}{v.pinnedTo ? ` ${v.pinnedTo}` : ''}</span>
                {#if v.readings?.reason}<div class="small muted">{v.readings.reason}</div>{/if}
                {#if v.reason && v.outcome === 'pinned_to'}<div class="small muted">{v.reason}</div>{/if}
              </td>
              <td class="small">{v.by}</td>
              <td class="actions">
                {#if admin && !v.current && v.pinnable && v.outcome !== 'pinned_to'}
                  <button class="link small" onclick={() => openPin(v.version)} data-testid="pin-open">Pin…</button>
                {/if}
              </td>
            </tr>
            {#if pinning === v.version}
              <tr>
                <td colspan="5">
                  <div class="pin-form" data-testid="pin-form">
                    <label>
                      Why pin to version {v.version}?
                      <input bind:value={reason} maxlength="200" placeholder="the new upstream breaks banking sites" aria-label="Reason" />
                    </label>
                    {#if pinPreview}
                      <p class="small" data-testid="pin-preview">
                        {pinPreview.changes?.length ? `Every node changes: ${pinPreview.changes.join('; ')}.` : 'The configuration is the same; the filter snapshot may differ.'}
                        Configuration changes wait until you unpin.
                      </p>
                      <div class="row">
                        <button class="primary" disabled={busy} onclick={pin} data-testid="pin-confirm">Pin</button>
                        <button disabled={busy} onclick={() => (pinPreview = null)}>Change it</button>
                      </div>
                    {:else}
                      <div class="row">
                        <button disabled={busy || !reason.trim()} onclick={checkPin} data-testid="pin-check">Check</button>
                        <button onclick={() => (pinning = null)}>Cancel</button>
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
