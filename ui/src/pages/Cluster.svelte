<script lang="ts">
  // REQ: CLU-008 — is the cluster active, healthy, and serving? Every node with its link,
  // configuration version and lag, and DNS serving numbers; pass/fail checks with fixes; and a
  // timeline of joins, disconnects, published and applied versions. Refreshes every 5 s.
  import { api, type S } from '../lib/api';
  import { can } from '../lib/session.svelte';
  import { poll } from '../lib/poll';
  import { duration, ms, num, pct, logTime, logDate } from '../lib/format';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';

  let view = $state<S['ClusterView'] | null>(null);
  let error = $state<unknown>(null);

  $effect(() =>
    poll(async () => {
      try {
        view = await api.cluster();
        error = null;
      } catch (e) {
        error = e;
      }
    }, 5000),
  );

  const kinds: Record<string, string> = {
    joined: 'Joined',
    connected: 'Connected',
    disconnected: 'Disconnected',
    published: 'Published',
    applied: 'Applied',
    sync_failed: 'Sync failed',
    rejected: 'Rejected',
  };
  const kindClass = (k: string) =>
    k === 'disconnected' || k === 'sync_failed' || k === 'rejected' ? 'bad' : k === 'published' || k === 'applied' ? 'ok' : '';
  const shortId = (id: string) => id.slice(0, 8);
  const failing = $derived(view?.checks.filter((c) => !c.ok) ?? []);
  const me = $derived(view?.nodes.find((n) => n.thisNode));
  const siteOf = (id: string) => view?.nodes.find((n) => n.nodeId === id)?.site ?? id;
  const primaryUp = $derived(view?.nodes.some((n) => n.role.includes('primary') && n.up && !n.thisNode) ?? false);

  // REQ: CLU-005 — manual failover (ADR-051): only when the primary is gone.
  let confirming = $state(false);
  let emergency = $state(false);
  let promoting = $state(false);
  let promoteError = $state<unknown>(null);
  async function promote() {
    promoting = true;
    promoteError = null;
    try {
      view = await api.promoteCluster(emergency);
      confirming = false;
    } catch (e) {
      promoteError = e;
    } finally {
      promoting = false;
    }
  }
</script>

<div class="page">
  <div class="page-head">
    <h1>Cluster<HelpButton id="cluster" /></h1>
    {#if view?.enabled}
      <span class="badge {view.healthy ? 'ok' : 'bad'}" data-testid="cluster-health">
        {view.healthy ? 'Healthy' : `Needs attention (${failing.length})`}
      </span>
    {/if}
  </div>
  <ErrorNote {error} />

  {#if view && !view.enabled}
    <section class="card" data-testid="cluster-standalone">
      <h2>This node runs on its own</h2>
      <p>
        A cluster keeps several TelltaleDNS nodes on one configuration: change it in one place, and every node (a Pi, a
        Kubernetes pod, another machine) follows within seconds, keeps answering if the others are down, and shows up here
        with its health.
      </p>
      <pre class="mono small">telltale cluster init --name home --advertise https://this-node:8443
telltale cluster token create        # then, on the other node:
telltale cluster join tt_join_…</pre>
      <p class="muted small">Run these as the user TelltaleDNS runs as, then restart it. See the help for what's shared and what stays per node.</p>
    </section>
  {:else if view}
    <section class="card summary">
      <dl class="facts">
        <dt>Cluster</dt><dd>{view.name} <span class="muted mono small">{view.clusterId}</span></dd>
        <dt>Nodes</dt><dd>{view.nodes.length} ({view.nodes.filter((n) => n.up).length} up)</dd>
        <dt>Configuration</dt><dd>version {num(view.newestConfigSeq)}</dd>
        <dt>Primary</dt><dd>{view.nodes.find((n) => n.role.includes('primary'))?.site ?? 'none'}</dd>
        <dt>Configuration from</dt><dd>{view.authority === 'gitops' ? 'Git (only Git-managed nodes may publish it)' : 'the primary (its file and UI)'}</dd>
        <!-- REQ: CLU-005 — how the cluster fails over (ADR-056). -->
        {#if view.failover}
          <dt>Failover</dt>
          <dd data-testid="cluster-failover">
            {#if view.failover.active}
              automatic: {view.failover.reachableVoters} of {view.failover.voters} voters reachable
              {#if view.failover.leaseHeld}<span class="muted small">· this primary's lease: {Math.round(view.failover.leaseSecondsLeft ?? 0)} s left</span>{/if}
              {#if view.failover.votedFor}<div class="muted small">voted for {siteOf(view.failover.votedFor)} in epoch {view.failover.votedEpoch}</div>{/if}
            {:else if view.failover.mode === 'auto'}
              automatic, but waiting for 3 or more voters ({view.failover.voters} now)
            {:else}
              manual (promote a node when the primary is gone)
            {/if}
          </dd>
        {/if}
      </dl>
      {#if me && me.role === 'replica' && can('admin') && !view.failover?.active}
        <div class="promote">
          {#if !confirming}
            <button onclick={() => (confirming = true)} disabled={primaryUp} title={primaryUp ? 'The primary is up' : ''}>Promote this node…</button>
            {#if primaryUp}<span class="muted small">Available when the primary is gone.</span>{/if}
          {:else}
            <div class="notice" role="alertdialog" aria-label="Promote this node">
              <p>
                <strong>Make {me.site} the primary?</strong> Use this only when the primary is gone. This node continues from
                version {num(me.configSeq)}; if the old primary comes back, it steps down, and anything it changed in the
                meantime is listed under Conflicts.
              </p>
              {#if view.authority === 'gitops' && me.configSource !== 'gitops'}
                <label class="check"
                  ><input type="checkbox" bind:checked={emergency} /> Emergency: keep the configuration at version {num(me.configSeq)} (this
                  node isn't managed from Git, so it can't publish changes)</label
                >
              {/if}
              <ErrorNote error={promoteError} />
              <div class="row">
                <button class="primary" onclick={promote} disabled={promoting}>{promoting ? 'Promoting…' : 'Promote'}</button>
                <button onclick={() => (confirming = false)}>Cancel</button>
              </div>
            </div>
          {/if}
        </div>
      {/if}
    </section>

    {#if view.conflicts.length}
      <section class="card" data-testid="cluster-conflicts">
        <h2>Conflicts</h2>
        <p class="muted small">
          Versions this node published after another node took over as primary. They were never applied anywhere; to keep a
          change, make it again where the configuration comes from now.
        </p>
        <ul class="conflicts">
          {#each view.conflicts as k (k.epoch * 1e9 + k.seq)}
            <li>
              <strong>Version {num(k.seq)}</strong> <span class="muted small">(epoch {k.epoch}, published {logDate(k.publishedAt)} {logTime(k.publishedAt)})</span>
              <div class="small">Changed: <span class="mono">{k.changed.join(', ') || '—'}</span></div>
            </li>
          {/each}
        </ul>
      </section>
    {/if}

    <section class="card">
      <h2>Checks</h2>
      <ul class="checks">
        {#each view.checks as c (c.id)}
          <li class:fail={!c.ok} data-testid="cluster-check">
            <span class="mark" aria-hidden="true">{c.ok ? '✓' : '✗'}</span>
            <div>
              <div>{c.summary}</div>
              {#if c.fix}<div class="muted small">{c.fix}</div>{/if}
            </div>
          </li>
        {/each}
      </ul>
    </section>

    <section class="card">
      <h2>Nodes</h2>
      <div class="table-wrap">
        <table class="nodes">
          <thead>
            <tr>
              <th>Node</th>
              <th>Status</th>
              <th>Configuration</th>
              <th>Serving DNS</th>
              <th>Version</th>
              <th>Uptime</th>
            </tr>
          </thead>
          <tbody>
            {#each view.nodes as n (n.nodeId)}
              <tr data-testid="cluster-node">
                <td>
                  <strong>{n.site}</strong>
                  <span class="badge {n.role === 'primary' ? 'ok' : n.role.includes('emergency') ? 'warn' : ''}">{n.role}</span>
                  {#if n.thisNode}<span class="muted small">this node</span>{/if}
                  <div class="mono muted small" title={n.nodeId}>
                    {shortId(n.nodeId)}{#if n.configSource}{' · '}{n.configSource === 'gitops' ? 'Git-managed' : 'local file'}{/if}
                  </div>
                </td>
                <td>
                  <span class="badge {n.up ? 'ok' : 'bad'}">{n.up ? 'up' : 'down'}</span>
                  <div class="muted small">
                    {#if n.thisNode}—{:else}{n.link}{#if n.rttMs != null}{' · '}{ms(n.rttMs)} RTT{/if}{#if !n.up}{' · '}seen {duration(n.lastSeenSecondsAgo)} ago{/if}{/if}
                  </div>
                </td>
                <td>
                  version {num(n.configSeq)}
                  <div class="small {n.configLag ? 'warn-text' : 'muted'}">
                    {#if n.configLag}{n.configLag} behind{#if n.behindSeconds != null} for {duration(n.behindSeconds)}{/if}{:else}in sync{/if}
                  </div>
                </td>
                <td>
                  <span class="badge {n.ready ? 'ok' : 'bad'}">{n.ready ? 'ready' : 'not ready'}</span>
                  <div class="muted small">
                    {num(n.qps)} q/s · {pct(n.servfailPercent)} SERVFAIL · upstream p90 {n.upstreamP90Ms > 0 ? ms(n.upstreamP90Ms) : '–'}
                  </div>
                </td>
                <td class="small">{n.version}</td>
                <td class="small">
                  {duration(n.uptimeSeconds)}
                  {#if n.certExpiresAt}<div class="muted">cert until {logDate(n.certExpiresAt)}</div>{/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      {#if view.nodes.length === 1}
        <p class="muted small">No other node has connected yet. On another node: <span class="mono">telltale cluster join</span> with a token from <span class="mono">telltale cluster token create</span>.</p>
      {/if}
    </section>

    <section class="card">
      <h2>Events</h2>
      {#if view.events.length === 0}
        <p class="empty">Nothing yet.</p>
      {:else}
        <ol class="events">
          {#each view.events as e, i (i)}
            <li>
              <span class="mono small muted">{logDate(e.at)} {logTime(e.at)}</span>
              <span class="badge {kindClass(e.kind)}">{kinds[e.kind] ?? e.kind}</span>
              <span class="mono small">{view.nodes.find((n) => n.nodeId === e.nodeId)?.site ?? shortId(e.nodeId)}</span>
              <span class="small">{e.detail}</span>
            </li>
          {/each}
        </ol>
      {/if}
    </section>
  {/if}
</div>

<style>
  .facts {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 4px 16px;
    margin: 0;
  }
  .facts dt {
    color: var(--muted);
  }
  .facts dd {
    margin: 0;
  }
  .checks {
    list-style: none;
    padding: 0;
    margin: 0;
    display: grid;
    gap: 8px;
  }
  .checks li {
    display: flex;
    gap: 10px;
    align-items: flex-start;
  }
  .checks .mark {
    color: var(--ok, green);
    font-weight: 700;
    width: 1em;
  }
  .checks li.fail .mark {
    color: var(--bad, crimson);
  }
  .table-wrap {
    overflow-x: auto;
  }
  .nodes td {
    vertical-align: top;
  }
  .warn-text {
    color: var(--warn, darkorange);
  }
  .events {
    list-style: none;
    padding: 0;
    margin: 0;
    display: grid;
    gap: 6px;
  }
  .events li {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    align-items: baseline;
  }
  .promote {
    margin-top: 12px;
    display: flex;
    gap: 10px;
    align-items: center;
    flex-wrap: wrap;
  }
  .conflicts {
    margin: 0;
    padding-left: 18px;
    display: grid;
    gap: 6px;
  }
  pre {
    overflow-x: auto;
    padding: 8px;
    background: var(--surface-2, rgb(127 127 127 / 8%));
    border-radius: 6px;
  }
</style>
