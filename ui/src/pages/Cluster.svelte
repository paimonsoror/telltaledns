<script lang="ts">
  // REQ: CLU-008 — is the cluster active, healthy, and serving? Every node with its link,
  // configuration version and lag, and DNS serving numbers; pass/fail checks with fixes; and a
  // timeline of joins, disconnects, published and applied versions. Refreshes every 5 s.
  import { api, type S } from '../lib/api';
  import { can, session } from '../lib/session.svelte';
  import { poll } from '../lib/poll';
  import { duration, ms, num, pct, rate, logTime, logDate } from '../lib/format';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import HostCard from '../lib/components/HostCard.svelte';
  import Icon from '../lib/components/Icon.svelte';
  import Topology, { type Node } from '../lib/components/Topology.svelte';
  import MaintenanceForm from '../lib/components/MaintenanceForm.svelte';
  import DrillForm from '../lib/components/DrillForm.svelte';
  import NodeRemoveForm from '../lib/components/NodeRemoveForm.svelte';
  import DrillPanel from '../lib/components/DrillPanel.svelte';
  import RolloutPanel from '../lib/components/RolloutPanel.svelte';
  import Tabs, { activeTab, type TabItem } from '../lib/components/Tabs.svelte';
  import TabPanel from '../lib/components/TabPanel.svelte';
  import NodeCompare, { COMPARE_WINDOWS } from '../lib/components/NodeCompare.svelte';
  import { refreshHealth } from '../lib/health.svelte';
  import { tick } from 'svelte';
  import { tr, own } from '../lib/i18n';
  import T from '../lib/i18n/T.svelte';
  const { t, tn } = tr('cluster');

  // The words of the node rows are read once, here: the language is fixed for the life of the page.
  const words = {
    witness: t('witness'), pod: t('pod'), thisNode: t('this node'), gitManaged: t('Git-managed'), localFile: t('local file'),
    maintenance: t('maintenance'), endMaintenance: t('End maintenance'), maintenanceOpen: t('Maintenance…'), drill: t('Drill…'),
    remove: t('Remove…'), up: t('up'), down: t('down'), votesOnly: t('votes only'), canary: t('canary'), inSync: t('in sync'),
    ready: t('ready'), notReady: t('not ready'),
  };

  let view = $state<S['ClusterView'] | null>(null);
  let info = $state<S['SystemInfo'] | null>(null);
  let error = $state<unknown>(null);

  async function load() {
    try {
      view = await api.cluster();
      // A standalone node's own maintenance window comes from its system information.
      if (!view.enabled) info = await api.info();
      error = null;
    } catch (e) {
      error = e;
    }
  }
  $effect(() => poll(load, 5000));

  // REQ: OBS-028 (ADR-128) — the node comparison, read on every tab so its tab can say when a
  // node is odd (ADR-121); the window is remembered in this browser.
  let compareWin = $state(rememberedWindow());
  let compare = $state<S['NodeCompare'] | null>(null);
  let compareError = $state<unknown>(null);
  function rememberedWindow(): string {
    try {
      const w = localStorage.getItem('cluster.compare') ?? '';
      return COMPARE_WINDOWS.some((x) => x.id === w) ? w : '24h';
    } catch {
      return '24h';
    }
  }
  function setCompareWin(id: string) {
    compareWin = id;
    try {
      localStorage.setItem('cluster.compare', id);
    } catch {
      // Private windows and blocked storage: the choice just isn't remembered.
    }
  }
  async function loadCompare() {
    const from = COMPARE_WINDOWS.find((w) => w.id === compareWin)?.from ?? '-24h';
    try {
      compare = await api.compare({ from });
      compareError = null;
    } catch (e) {
      compareError = e;
    }
  }
  $effect(() => {
    void compareWin;
    return poll(loadCompare, 60_000);
  });
  const oddNodes = $derived(new Set((compare?.findings ?? []).filter((f) => f.level === 'odd').map((f) => f.nodeId)).size);

  // REQ: OPS-010 (ADR-118) — maintenance per node: a form, an end button, the result's note.
  let maintFor = $state<string | null>(null);
  let maintBusy = $state(false);
  let maintError = $state<unknown>(null);
  let maintNote = $state<string | null>(null);
  const apiNode = (n: Node) => (n.thisNode ? 'local' : n.nodeId);
  // The primary hands over only under automatic failover with another eligible node online.
  const canHandover = (n: Node) =>
    !!view?.failover?.active &&
    (view?.nodes.some((o) => o.nodeId !== n.nodeId && o.eligible && !o.witness && o.up && !o.maintenance) ?? false);
  async function changed(note?: string | null) {
    maintFor = null;
    maintNote = note ?? null;
    await load();
    void refreshHealth();
    window.dispatchEvent(new Event('telltale:maintenance-changed'));
  }
  async function endMaintenance(node: string) {
    maintBusy = true;
    maintError = null;
    try {
      const r = await api.endMaintenance(node);
      await changed(r.note);
    } catch (e) {
      maintError = e;
    } finally {
      maintBusy = false;
    }
  }
  // REQ: CLU-001 (ADR-155) — an admin removes a node from the cluster (never this node or the
  // primary): the confirmation form in its row, then the result's notes above the page.
  let removeFor = $state<string | null>(null);
  let removeNote = $state<S['NodeRemoval'] | null>(null);
  const canRemove = (n: Node) => can('admin') && !n.thisNode && !n.role.includes('primary');
  async function removed(r: S['NodeRemoval']) {
    removeFor = null;
    removeNote = r;
    await load();
  }
  // REQ: CLU-014 (ADR-151) — a failover drill per node: the form, and the tab with reports. A
  // drilled node is in maintenance with the drill's reason.
  let drillFor = $state<string | null>(null);
  let drillNote = $state<string | null>(null);
  const isDrill = (m: S['NodeMaintenance'] | null | undefined) => !!m && m.reason.startsWith('failover drill');
  const drilling = $derived(view?.nodes.some((n) => isDrill(n.maintenance)) ?? false);
  const drillParam = $derived(new URLSearchParams(location.hash.split('?')[1] ?? '').get('drill'));
  async function drillStarted(r: S['DrillStart']) {
    drillFor = null;
    drillNote = t('{preview} The report follows about a minute after it ends, under Drills.', { preview: r.preview });
    await load();
    void refreshHealth();
  }
  // This node's own window (standalone too).
  const mine = $derived(view?.enabled ? view.nodes.find((n) => n.thisNode)?.maintenance : info?.maintenance);
  const until = (m: S['NodeMaintenance']) => `${logDate(m.until)} ${logTime(m.until)}`;

  const kinds: Record<string, string> = {
    joined: t('Joined'),
    connected: t('Connected'),
    disconnected: t('Disconnected'),
    published: t('Published'),
    applied: t('Applied'),
    sync_failed: t('Sync failed'),
    rejected: t('Rejected'),
    restarted: t('Restarted'),
    expired: t('Pod gone'),
    left: t('Left'),
    voted: t('Voted'),
    cert_issued: t('Certificate'),
    ca_rotation: t('CA rotation'),
    maintenance: t('Maintenance'),
    maintenance_ended: t('Back in service'),
    handover: t('Maintenance handover'),
    handover_failed: t('Handover failed'),
    lease_released: t('Lease released'),
    stepped_down: t('Stepped down'),
    rollout_started: t('Rollout'),
    rollout_promoted: t('Promoted'),
    rollout_failed: t('Rollout failed'),
    pinned: t('Pinned'),
    unpinned: t('Unpinned'),
  };
  const kindClass = (k: string) =>
    k === 'disconnected' || k === 'sync_failed' || k === 'rejected' || k === 'handover_failed' || k === 'rollout_failed'
      ? 'bad'
      : k === 'restarted' || k === 'maintenance' || k === 'handover' || k === 'rollout_started' || k === 'pinned'
        ? 'warn'
        : k === 'published' || k === 'applied' || k === 'rollout_promoted'
          ? 'ok'
          : '';
  // REQ: CLU-013 — the nodes running the version baking.
  const canaries = $derived(view?.rollout?.stage === 'canary' ? (view.rollout.canaries ?? []) : []);
  // REQ: CLU-009 (T6.14) — pod churn: joins, pods gone, and restarts in the last hour.
  const churn = $derived.by(() => {
    const since = Date.now() - 3600_000;
    const recent = (view?.events ?? []).filter((e) => Date.parse(e.at) >= since);
    const count = (k: string) => recent.filter((e) => e.kind === k).length;
    // Pods gone: left on shutdown (T6.14), or expired after dying without a word.
    return { joined: count('joined'), expired: count('expired') + count('left'), restarted: count('restarted') };
  });
  // The last hour's churn: one whole message for each plural form (pods gone, restarts).
  const churnText = $derived.by(() => {
    const c = churn;
    return c.expired === 1
      ? c.restarted === 1
        ? t('Last hour: {joined} joined · {expired} pod gone · {restarted} restart', c)
        : t('Last hour: {joined} joined · {expired} pod gone · {restarted} restarts', c)
      : c.restarted === 1
        ? t('Last hour: {joined} joined · {expired} pods gone · {restarted} restart', c)
        : t('Last hour: {joined} joined · {expired} pods gone · {restarted} restarts', c);
  });
  // Who made the commit in use: one whole message for each of its optional parts (the date, the signer).
  const byLine = (s: NonNullable<S['ClusterView']['source']>) => {
    const p = { author: s.author, date: s.committedAt ? logDate(s.committedAt) : null, signer: s.signedBy };
    return s.committedAt
      ? s.signedBy
        ? t('by {author}, {date}, signed by {signer}', p)
        : t('by {author}, {date}', p)
      : s.signedBy
        ? t('by {author}, signed by {signer}', p)
        : t('by {author}', p);
  };
  // T6.14 — selecting a node in the topology jumps to its row (opening its pod site).
  let selected = $state<string | null>(null);
  async function select(n: Node) {
    if (n.ephemeral && !openSites.includes(n.site)) openSites = [...openSites, n.site];
    selected = n.nodeId;
    await tick();
    document.getElementById(`node-${n.nodeId}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }
  const avg = (xs: (number | null | undefined)[]) => {
    const v = xs.filter((x): x is number => x != null);
    return v.length ? v.reduce((a, b) => a + b, 0) / v.length : null;
  };
  const shortId = (id: string) => id.slice(0, 8);
  const failing = $derived(view?.checks.filter((c) => !c.ok) ?? []);
  const me = $derived(view?.nodes.find((n) => n.thisNode));
  const siteOf = (id: string) => view?.nodes.find((n) => n.nodeId === id)?.site ?? id;
  // REQ: CLU-009 — Kubernetes resolver pods come and go: shown per site, collapsed.
  const fixed = $derived(view?.nodes.filter((n) => !n.ephemeral) ?? []);
  const podSites = $derived.by(() => {
    const by = new Map<string, NonNullable<typeof view>['nodes']>();
    for (const n of view?.nodes ?? []) if (n.ephemeral) by.set(n.site, [...(by.get(n.site) ?? []), n]);
    return [...by.entries()];
  });
  let openSites = $state<string[]>([]);
  const toggleSite = (s: string) =>
    (openSites = openSites.includes(s) ? openSites.filter((x) => x !== s) : [...openSites, s]);
  const upPrimaries = $derived(view?.nodes.filter((n) => n.role.includes('primary') && n.up && !n.thisNode) ?? []);
  // REQ: CLU-005 (ADR-048) — a Git-managed node may take over from an emergency primary while it runs.
  const takeover = $derived(
    upPrimaries.length > 0 &&
      upPrimaries.every((n) => n.role === 'emergency primary') &&
      view?.authority === 'gitops' &&
      me?.configSource === 'gitops'
  );
  const primaryUp = $derived(upPrimaries.length > 0 && !takeover);

  // REQ: API-005 (ADR-121) — the page in tabs, the summary above them. A tab with something
  // wrong says so: failing checks and conflicts, a pin or a version baking, problem events in
  // the last hour.
  const problemKinds = new Set(['disconnected', 'sync_failed', 'rejected', 'handover_failed', 'rollout_failed']);
  const recentProblems = $derived.by(() => {
    const since = Date.now() - 3600_000;
    return (view?.events ?? []).filter((e) => problemKinds.has(e.kind) && Date.parse(e.at) >= since).length;
  });
  const problems = $derived(failing.length + (view?.conflicts.length ?? 0));
  const stage = $derived(view?.rollout?.stage ?? 'none');
  const stageWord: Record<string, string> = { canary: t('baking'), waiting: t('waiting'), pinned: t('pinned') };
  const tabWords = { nodes: t('Nodes'), health: t('Health'), rollouts: t('Rollouts'), events: t('Events'), compare: t('Compare'), drills: t('Drills'), running: t('running') };
  const tabs = $derived<TabItem[]>([
    { id: 'nodes', label: tabWords.nodes, count: view?.nodes.length ?? null },
    { id: 'health', label: tabWords.health, count: problems || null, alert: problems > 0 },
    { id: 'rollouts', label: tabWords.rollouts, count: own(stageWord, stage) ?? null, alert: stage === 'pinned' },
    { id: 'events', label: tabWords.events, count: recentProblems || null, alert: recentProblems > 0 },
    { id: 'compare', label: tabWords.compare, count: oddNodes ? t('{n} odd', { n: oddNodes }) : null, alert: oddNodes > 0 },
    // REQ: CLU-014 — failover drills.
    { id: 'drills', label: tabWords.drills, count: drilling ? tabWords.running : null },
  ]);
  const tab = $derived(activeTab(tabs));

  // REQ: CLU-005 — manual failover (ADR-051): only when the primary is gone.
  let confirming = $state(false);
  let emergency = $state(false);
  let promoting = $state(false);
  let promoteError = $state<unknown>(null);
  // REQ: CLU-005 (`spec/12` §5) — promotion is confirmed with the password (and the code).
  let password = $state('');
  let totp = $state('');
  async function promote() {
    promoting = true;
    promoteError = null;
    try {
      view = await api.promoteCluster(emergency, password, totp);
      confirming = false;
      password = '';
      totp = '';
    } catch (e) {
      promoteError = e;
    } finally {
      promoting = false;
    }
  }
</script>

{#snippet strong(x: string)}<strong>{x}</strong>{/snippet}
{#snippet mono(x: string)}<span class="mono" translate="no">{x}</span>{/snippet}
{#snippet monosmall(x: string)}<span class="mono small" translate="no">{x}</span>{/snippet}
{#snippet strongname(x: string)}<strong translate="no">{x}</strong>{/snippet}
{#snippet rollouts(x: string)}<a href="#/cluster?tab=rollouts">{x}</a>{/snippet}
{#snippet joincmd()}<span class="mono" translate="no">telltale cluster join</span>{/snippet}
{#snippet tokencmd()}<span class="mono" translate="no">telltale cluster token create</span>{/snippet}

<div class="page">
  <div class="page-head">
    <h1>{t('Cluster')}<HelpButton id="cluster" /></h1>
    {#if view?.enabled}
      <span class="badge {view.healthy ? 'ok' : 'bad'}" data-testid="cluster-health">
        {view.healthy ? t('Healthy') : t('Needs attention ({n})', { n: failing.length })}
      </span>
    {/if}
  </div>
  <ErrorNote {error} />
  {#if mine}
    <!-- REQ: OPS-010 — the node serving this page is in maintenance. -->
    <div class="notice warn maint-banner" role="status" data-testid="maintenance-banner">
      <T ctx="cluster" msg={'<strong>This node is in maintenance</strong> until {until} ({reason}, by {by}): it reports not ready, so load balancers send it no new queries, and it keeps answering what still arrives. Its alerts and health conditions are paused.'} params={{ until: until(mine), reason: mine.reason, by: mine.by }} {strong} /><HelpButton id="maintenance" />
      {#if can('operator')}
        <button onclick={() => endMaintenance('local')} disabled={maintBusy} data-testid="maintenance-end-banner">{t('End maintenance')}</button>
      {/if}
    </div>
  {/if}
  {#if maintNote}<p class="notice small" data-testid="maintenance-note" translate="no">{maintNote}</p>{/if}
  {#if removeNote}
    <div class="notice small" role="status" data-testid="node-remove-note">
      <strong>{t('{site} ({id}) was removed from the cluster.', { site: removeNote.site, id: shortId(removeNote.nodeId) })}</strong>
      {#each removeNote.notes as note, i (i)}<div translate="no">{note}</div>{/each}
    </div>
  {/if}
  {#if drillNote}<p class="notice small" data-testid="drill-note">{drillNote} <a href="#/cluster?tab=drills">{t('Drills')}</a></p>{/if}
  <ErrorNote error={maintError} />

  {#if view && !view.enabled}
    <section class="card" data-testid="cluster-standalone">
      <h2>{t('This node runs on its own')}</h2>
      <p>
        {t('A cluster keeps several TelltaleDNS nodes on one configuration: change it in one place, and every node (a Pi, a Kubernetes pod, another machine) follows within seconds, keeps answering if the others are down, and shows up here with its health.')}
      </p>
      <pre class="mono small" translate="no">telltale cluster init --name home --advertise https://this-node:8443
telltale cluster token create        # then, on the other node:
telltale cluster join tt_join_…</pre>
      <p class="muted small">{t('Run these as the user TelltaleDNS runs as, then restart it. See the help for what\'s shared and what stays per node.')}</p>
    </section>
    {#if can('operator') && !mine}
      <!-- REQ: OPS-010 — a standalone node can be put in maintenance too (readiness, banner, alerts). -->
      <section class="card">
        <h2>{t('Maintenance')}<HelpButton id="maintenance" /></h2>
        {#if maintFor === 'local'}
          <MaintenanceForm node="local" label={t('this node')} onclose={() => (maintFor = null)} ondone={(r) => changed(r.note)} />
        {:else}
          <p class="small muted">{t('Taking this machine down for a while? Maintenance makes it report not ready (so a load balancer moves away) and pauses its alerts, while it keeps answering DNS.')}</p>
          <button onclick={() => (maintFor = 'local')} data-testid="maintenance-open">{t('Maintenance…')}</button>
        {/if}
      </section>
    {/if}
    {#if view.host}
      <!-- REQ: CLU-008 (T6.11) — a standalone node still shows its machine. -->
      <section class="machines">
        <h2>{t('This machine')}<HelpButton id="host-resources" /></h2>
        <div class="host-grid"><HostCard title={t('This node')} host={view.host} /></div>
      </section>
    {/if}
  {:else if view}
    <section class="card summary">
      <dl class="facts">
        <dt>{t('Cluster')}</dt><dd translate="no">{view.name} <span class="muted mono small">{view.clusterId}</span></dd>
        <dt>{t('Nodes')}</dt><dd>{t('{n} ({up} up)', { n: view.nodes.length, up: view.nodes.filter((n) => n.up).length })}</dd>
        <dt>{t('Configuration')}</dt><dd>{t('version {n}', { n: num(view.newestConfigSeq) })}</dd>
        <dt>{t('Primary')}</dt><dd>{view.nodes.find((n) => n.role.includes('primary'))?.site ?? t('none')}</dd>
        <dt>{t('Configuration from')}</dt>
        <dd>
          {#if view.source}
            <!-- REQ: CLU-003 — the Git repository, the commit in use, and the last check (ADR-049). -->
            <span data-testid="cluster-source">
              <T ctx="cluster" msg={'Git: <mono>{repo}</mono> @ {ref}, <mono>{path}</mono>'} params={{ repo: view.source.repo, ref: view.source.gitRef, path: view.source.path }} mono={monosmall} />
            </span>
            {#if view.source.commit}
              <div class="small">
                {t('commit')} <span class="mono" title={view.source.commit} translate="no">{view.source.commit.slice(0, 12)}</span>
                {#if view.source.subject}“{view.source.subject}”{/if}
                <span class="muted">{byLine(view.source)}</span>
              </div>
            {:else}
              <div class="small muted">{t('no commit accepted yet: nothing is published until one is')}</div>
            {/if}
            {#if view.source.error}
              <div class="notice {view.source.refused ? 'bad' : 'warn'} small" role="alert">
                {view.source.refused ? t('Newest commit refused') : t('Repository check failed')}: {view.source.error}
                <div class="muted">{t('Every node keeps serving the commit above.')}</div>
              </div>
            {/if}
          {:else}
            {view.authority === 'gitops' ? t('Git (only Git-managed nodes may publish it)') : t('the primary (its file and UI)')}
          {/if}
        </dd>
        <!-- REQ: CLU-005 — how the cluster fails over (ADR-056). -->
        {#if view.failover}
          <dt>{t('Failover')}</dt>
          <dd data-testid="cluster-failover">
            {#if view.failover.active}
              {t('automatic: {reachable} of {voters} voters reachable', { reachable: view.failover.reachableVoters, voters: view.failover.voters })}
              {#if view.failover.leaseHeld}<span class="muted small">{t("· this primary's lease: {n} s left", { n: Math.round(view.failover.leaseSecondsLeft ?? 0) })}</span>{/if}
              {#if view.failover.votedFor}<div class="muted small">{t('voted for {site} in epoch {epoch}', { site: siteOf(view.failover.votedFor), epoch: view.failover.votedEpoch })}</div>{/if}
            {:else if view.failover.mode === 'auto'}
              {t('automatic, but waiting for 3 or more voters ({voters} now)', { voters: view.failover.voters })}
            {:else}
              {t('manual (promote a node when the primary is gone)')}
            {/if}
          </dd>
        {/if}
      </dl>
      {#if me && me.role === 'replica' && can('admin') && !view.failover?.active}
        <div class="promote">
          {#if !confirming}
            <button onclick={() => (confirming = true)} disabled={primaryUp} title={primaryUp ? t('The primary is up') : ''}
              >{takeover ? t('Take over from the emergency primary…') : t('Promote this node…')}</button
            >
            {#if primaryUp}<span class="muted small">{t('Available when the primary is gone.')}</span>{/if}
          {:else}
            <div class="notice" role="alertdialog" aria-label={t('Promote this node')}>
              {#if takeover}
                <p>
                  <T ctx="cluster" msg={'<strong>Make {site} the primary again?</strong> The emergency primary ({sites}) steps down by itself, and this node publishes from Git again, continuing from version {n}.'} params={{ site: me.site, sites: upPrimaries.map((n) => n.site).join(', '), n: num(me.configSeq) }} {strong} />
                </p>
              {:else}
                <p>
                  <T ctx="cluster" msg={'<strong>Make {site} the primary?</strong> Use this only when the primary is gone. This node continues from version {n}; if the old primary comes back, it steps down, and anything it changed in the meantime is listed under Conflicts.'} params={{ site: me.site, n: num(me.configSeq) }} {strong} />
                </p>
              {/if}
              {#if view.authority === 'gitops' && me.configSource !== 'gitops'}
                <label class="check"
                  ><input type="checkbox" bind:checked={emergency} /> {t("Emergency: keep the configuration at version {n} (this node isn't managed from Git, so it can't publish changes)", { n: num(me.configSeq) })}</label
                >
              {/if}
              <label class="field"
                >{t('Your password')} <input type="password" autocomplete="current-password" bind:value={password} /></label
              >
              {#if session.user?.totpEnabled}
                <label class="field"
                  >{t('Code from your authenticator app')} <input inputmode="numeric" autocomplete="one-time-code" bind:value={totp} /></label
                >
              {/if}
              <ErrorNote error={promoteError} />
              <div class="row">
                <button class="primary" onclick={promote} disabled={promoting || !password}>{promoting ? t('Promoting…') : t('Promote')}</button>
                <button onclick={() => (confirming = false)}>{t('Cancel')}</button>
              </div>
            </div>
          {/if}
        </div>
      {/if}
    </section>

    <!-- REQ: CLU-013 (ADR-116) — a pin stays loud on every tab; the full banner (what it holds
         back, Unpin) is on Rollouts. -->
    {#if view.rollout?.pinned && tab !== 'rollouts'}
      {@const p = view.rollout.pinned}
      <div class="notice warn" role="status" data-testid="pin-note">
        <T ctx="cluster" msg={"<strong>The cluster is pinned to version {to}</strong> by {by}: {reason}. Configuration changes wait until it's unpinned. <rollouts>Rollouts</rollouts>"} params={{ to: p.to, by: p.by, reason: p.reason }} {strong} {rollouts} />
      </div>
    {/if}
    <Tabs {tabs} active={tab} label={t('Cluster')} />
    <TabPanel active={tab}>
    {#if tab === 'nodes'}
      <!-- REQ: CLU-008 (T6.14) — the cluster at a glance. -->
      <section class="card">
        <h2>{t('Topology')}<HelpButton id="cluster-topology" /></h2>
        <Topology nodes={view.nodes} onselect={select} {canaries} />
      </section>

      <section class="card">
        <h2>{t('Nodes')}</h2>
        <div class="table-wrap">
          <table class="nodes">
            <thead>
              <tr>
                <th>{t('Node')}</th>
                <th>{t('Status')}</th>
                <th>{t('Configuration')}</th>
                <th>{t('Serving DNS')}</th>
                <th>{t('Version')}</th>
                <th>{t('Uptime')}</th>
              </tr>
            </thead>
            <tbody>
              {#snippet row(n: NonNullable<typeof view>['nodes'][number])}
                <tr data-testid="cluster-node" id={`node-${n.nodeId}`} class:selected={selected === n.nodeId}>
                  <td>
                    <strong translate="no">{n.site}</strong>
                    <span class="badge {n.role === 'primary' ? 'ok' : n.role.includes('emergency') ? 'warn' : ''}" translate={n.witness ? undefined : 'no'}>{n.witness ? words.witness : n.role}</span>
                    {#if n.ephemeral}<span class="muted small">{words.pod}</span>{/if}
                    {#if n.thisNode}<span class="muted small">{words.thisNode}</span>{/if}
                    <div class="mono muted small" title={n.nodeId}>
                      {shortId(n.nodeId)}{#if n.configSource}{' · '}{n.configSource === 'gitops' ? words.gitManaged : words.localFile}{/if}
                    </div>
                    {#if n.pod}<div class="muted small" data-testid="cluster-node-pod">{#if n.kubeNode}<T ctx="cluster" msg={'pod <mono>{pod}</mono> on <mono>{node}</mono>'} params={{ pod: n.pod, node: n.kubeNode }} {mono} />{:else}{words.pod} <span class="mono" translate="no">{n.pod}</span>{/if}</div>{/if}
                    <!-- REQ: OPS-010 — the window, and the actions for operators. -->
                    {#if n.maintenance}
                      <div class="small" data-testid="cluster-node-maintenance">
                        <span class="badge warn" title={t('by {by}', { by: n.maintenance.by })}><Icon name="wrench" size={12} /> {words.maintenance}</span>
                        {t('{time} left · {reason}', { time: duration(n.maintenance.secondsLeft), reason: n.maintenance.reason })}
                      </div>
                    {/if}
                    {#if (can('operator') && !n.witness) || canRemove(n)}
                      <div class="small">
                        {#if can('operator') && !n.witness}
                          {#if n.maintenance}
                            <button class="link small" onclick={() => endMaintenance(apiNode(n))} disabled={maintBusy} data-testid="maintenance-end">{words.endMaintenance}</button>
                          {:else if maintFor !== n.nodeId}
                            <button class="link small" onclick={() => (maintFor = n.nodeId)} data-testid="maintenance-open">{words.maintenanceOpen}</button>
                          {/if}
                          {#if !n.maintenance && drillFor !== n.nodeId && (view?.nodes.length ?? 0) > 1}
                            · <button class="link small" onclick={() => (drillFor = n.nodeId)} data-testid="drill-open-form">{words.drill}</button>
                          {/if}
                        {/if}
                        <!-- REQ: CLU-001 (ADR-155) — an admin removes a stale or retired node. -->
                        {#if canRemove(n) && removeFor !== n.nodeId}
                          {#if can('operator') && !n.witness}·{/if}
                          <button class="link small" onclick={() => (removeFor = n.nodeId)} data-testid="node-remove-open">{words.remove}</button>
                        {/if}
                      </div>
                    {/if}
                  </td>
                  <td>
                    <span class="badge {n.up ? 'ok' : 'bad'}">{n.up ? words.up : words.down}</span>
                    <div class="muted small">
                      {#if n.thisNode}—{:else}<span translate="no">{n.link}</span>{#if n.rttMs != null}{' · '}{t('{rtt} RTT', { rtt: ms(n.rttMs) })}{/if}{#if !n.up}{' · '}{t('seen {time} ago', { time: duration(n.lastSeenSecondsAgo) })}{/if}{/if}
                    </div>
                  </td>
                  <!-- REQ: CLU-008 (ADR-056) — a witness only votes: no configuration, no DNS. -->
                  {#if n.witness}
                    <td class="muted">–</td>
                    <td class="muted">{words.votesOnly}</td>
                  {:else}
                    <td>
                      {t('version {n}', { n: num(n.configSeq) })}
                      {#if canaries.includes(n.nodeId) || (n.thisNode && n.role === 'primary' && canaries.length)}<span class="badge warn" data-testid="cluster-node-canary">{words.canary}</span>{/if}
                      {#if n.sourceCommit}<span class="mono muted small" title={n.sourceCommit}> · {n.sourceCommit.slice(0, 7)}</span>{/if}
                      <div class="small {n.configLag ? 'warn-text' : 'muted'}">
                        {#if n.configLag}{t('{n} behind', { n: n.configLag })}{#if n.behindSeconds != null}{t('for {time}', { time: duration(n.behindSeconds) })}{/if}{:else}{words.inSync}{/if}
                      </div>
                    </td>
                    <td>
                      <span class="badge {n.ready ? 'ok' : 'bad'}">{n.ready ? words.ready : words.notReady}</span>
                      <div class="muted small">
                        {n.querySharePercent != null
                          ? t('{rate} q/s ({share} of queries) · {servfail} SERVFAIL · upstream p90 {p90}', { rate: rate(n.qps), share: pct(n.querySharePercent), servfail: pct(n.servfailPercent), p90: n.upstreamP90Ms > 0 ? ms(n.upstreamP90Ms) : '–' })
                          : t('{rate} q/s · {servfail} SERVFAIL · upstream p90 {p90}', { rate: rate(n.qps), servfail: pct(n.servfailPercent), p90: n.upstreamP90Ms > 0 ? ms(n.upstreamP90Ms) : '–' })}
                      </div>
                      {#if n.cacheEntries != null}
                        <div class="muted small">{n.cacheHitPercent != null ? t('cache: {hits} hits · {n} entries', { hits: pct(n.cacheHitPercent), n: num(n.cacheEntries) }) : t('cache: no lookups · {n} entries', { n: num(n.cacheEntries) })}</div>
                      {/if}
                    </td>
                  {/if}
                  <td class="small" translate="no">{n.version}</td>
                  <td class="small">
                    {#if n.witness}<span class="muted">–</span>{:else}{duration(n.uptimeSeconds)}{/if}
                    {#if n.restarts}<div class="warn-text">{tn('{n} restart', '{n} restarts', n.restarts, { n: n.restarts })}</div>{/if}
                    {#if n.certExpiresAt}<div class="muted">{t('cert until {date}', { date: logDate(n.certExpiresAt) })}</div>{/if}
                  </td>
                </tr>
                {#if maintFor === n.nodeId}
                  <tr class="maint-row">
                    <td colspan="6">
                      <MaintenanceForm
                        node={apiNode(n)}
                        label={n.thisNode ? words.thisNode : (n.pod ?? n.site)}
                        primary={n.role === 'primary'}
                        canHandover={canHandover(n)}
                        onclose={() => (maintFor = null)}
                        ondone={(r) => changed(r.note)}
                      />
                    </td>
                  </tr>
                {/if}
                {#if removeFor === n.nodeId}
                  <tr class="maint-row">
                    <td colspan="6">
                      <NodeRemoveForm
                        nodeId={n.nodeId}
                        site={n.site}
                        up={n.up}
                        failoverActive={!!view?.failover?.active}
                        onclose={() => (removeFor = null)}
                        ondone={removed}
                      />
                    </td>
                  </tr>
                {/if}
                {#if drillFor === n.nodeId}
                  <tr class="maint-row">
                    <td colspan="6">
                      <DrillForm
                        node={apiNode(n)}
                        label={n.thisNode ? words.thisNode : (n.pod ?? n.site)}
                        onclose={() => (drillFor = null)}
                        ondone={drillStarted}
                      />
                    </td>
                  </tr>
                {/if}
              {/snippet}
              {#each fixed as n (n.nodeId)}{@render row(n)}{/each}
              {#each podSites as [site, pods] (site)}
                <tr class="pods" data-testid="cluster-pods">
                  <td colspan="6">
                    <button class="link" onclick={() => toggleSite(site)} aria-expanded={openSites.includes(site)}>
                      {openSites.includes(site) ? '▾' : '▸'} {#if pods.length === 1}<T ctx="cluster" msg={'<strong>{site}</strong>: {n} resolver pod'} params={{ site, n: pods.length }} strong={strongname} />{:else}<T ctx="cluster" msg={'<strong>{site}</strong>: {n} resolver pods'} params={{ site, n: pods.length }} strong={strongname} />{/if}
                    </button>
                    <span class="muted small">
                      {t('{up} up · {ready} ready · {rate} q/s · {behind} behind', { up: pods.filter((p) => p.up).length, ready: pods.filter((p) => p.ready).length, rate: rate(pods.reduce((total, p) => total + p.qps, 0)), behind: pods.filter((p) => p.configLag > 0).length })}
                      {#if avg(pods.map((p) => p.cacheHitPercent)) != null}{t('· cache {pct} hits on average (each pod has its own)', { pct: pct(avg(pods.map((p) => p.cacheHitPercent)) ?? 0) })}{/if}
                    </span>
                  </td>
                </tr>
                {#if openSites.includes(site)}{#each pods as n (n.nodeId)}{@render row(n)}{/each}{/if}
              {/each}
            </tbody>
          </table>
        </div>
        {#if view.nodes.length === 1}
          <p class="muted small"><T ctx="cluster" msg={'No other node has connected yet. On another node: <joincmd/> with a token from <tokencmd/>.'} {joincmd} {tokencmd} /></p>
        {/if}
      </section>
    {:else if tab === 'health'}
      <section class="card">
        <h2>{t('Checks')}</h2>
        <ul class="checks">
          {#each view.checks as c (c.id)}
            <li class:fail={!c.ok} data-testid="cluster-check">
              <span class="mark" aria-hidden="true">{c.ok ? '✓' : '✗'}</span>
              <div>
                <div translate="no">{c.summary}</div>
                {#if c.fix}<div class="muted small" translate="no">{c.fix}</div>{/if}
              </div>
            </li>
          {/each}
        </ul>
      </section>

      {#if view.conflicts.length}
        <section class="card" data-testid="cluster-conflicts">
          <h2>{t('Conflicts')}</h2>
          <p class="muted small">
            {t('Versions this node published after another node took over as primary. They were never applied anywhere; to keep a change, make it again where the configuration comes from now.')}
          </p>
          <ul class="conflicts">
            {#each view.conflicts as k (k.epoch * 1e9 + k.seq)}
              <li>
                <strong>{t('Version {n}', { n: num(k.seq) })}</strong> <span class="muted small">{t('(epoch {epoch}, published {date} {time})', { epoch: k.epoch, date: logDate(k.publishedAt), time: logTime(k.publishedAt) })}</span>
                <div class="small">{t('Changed:')} <span class="mono" translate="no">{k.changed.join(', ') || '—'}</span></div>
              </li>
            {/each}
          </ul>
        </section>
      {/if}

      <!-- REQ: CLU-008 (T6.11) — the machines nodes run on (pods only when their site is open). -->
      {@const machines = view.nodes.filter((n) => n.host && (!n.ephemeral || openSites.includes(n.site)))}
      {#if machines.length}
        <section class="machines" data-testid="cluster-machines">
          <h2>{t('Machines')}<HelpButton id="host-resources" /></h2>
          <div class="host-grid">
            {#each machines as n (n.nodeId)}
              {#if n.host}<div class="host-slot" class:selected={selected === n.nodeId}><HostCard title={n.site} sub={`${n.thisNode ? words.thisNode : n.role} · ${n.pod ?? shortId(n.nodeId)}`} host={n.host} /></div>{/if}
            {/each}
          </div>
        </section>
      {/if}
    {:else if tab === 'rollouts'}
      <!-- REQ: CLU-013 — the pin, the version baking, and the kept versions. -->
      <RolloutPanel nodes={view.nodes} onchanged={load} />
    {:else if tab === 'compare'}
      <NodeCompare data={compare} error={compareError} win={compareWin} onwindow={setCompareWin} />
    {:else if tab === 'drills'}
      <DrillPanel open={drillParam} />
    {:else}
      <section class="card">
        <h2>{t('Events')}</h2>
        {#if podSites.length || churn.restarted}
          <p class="muted small" data-testid="cluster-churn">
            {churnText}
          </p>
        {/if}
        {#if view.events.length === 0}
          <p class="empty">{t('Nothing yet.')}</p>
        {:else}
          <ol class="events">
            {#each view.events as e, i (i)}
              {@const kindWord = own(kinds, e.kind)}
              <li>
                <span class="mono small muted">{logDate(e.at)} {logTime(e.at)}</span>
                <span class="badge {kindClass(e.kind)}" translate={kindWord ? undefined : 'no'}>{kindWord ?? e.kind}</span>
                <span class="mono small" translate="no">{view.nodes.find((n) => n.nodeId === e.nodeId)?.site ?? shortId(e.nodeId)}</span>
                <span class="small" translate="no">{e.detail}</span>
              </li>
            {/each}
          </ol>
        {/if}
      </section>
    {/if}
    </TabPanel>
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
  .nodes tr.selected td,
  .host-slot.selected :global(.card) {
    box-shadow: inset 3px 0 0 var(--accent);
    background: color-mix(in srgb, var(--accent) 8%, transparent);
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
  .field {
    display: flex;
    flex-direction: column;
    gap: 4px;
    margin: 8px 0;
    max-width: 320px;
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
  .machines h2 {
    margin: 4px 0 12px;
  }
  .host-grid {
    display: grid;
    gap: var(--gap);
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  }
  .maint-banner {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    align-items: center;
    margin-bottom: var(--gap);
  }
  .maint-row td {
    background: color-mix(in srgb, var(--warn) 6%, transparent);
  }
  pre {
    overflow-x: auto;
    padding: 8px;
    background: var(--surface-2, rgb(127 127 127 / 8%));
    border-radius: 6px;
  }
</style>
