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
  import { t, tn, type MessageKey } from '../lib/i18n';
  import { tick } from 'svelte';

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
    drillNote = t('cluster.drill.started', { preview: r.preview });
    await load();
    void refreshHealth();
  }
  // This node's own window (standalone too).
  const mine = $derived(view?.enabled ? view.nodes.find((n) => n.thisNode)?.maintenance : info?.maintenance);
  const until = (m: S['NodeMaintenance']) => `${logDate(m.until)} ${logTime(m.until)}`;

  // An event's kind reads in the language on screen; a kind the UI has no words for stays as it is.
  const kinds: Record<string, MessageKey> = {
    joined: 'cluster.kind.joined',
    connected: 'cluster.kind.connected',
    disconnected: 'cluster.kind.disconnected',
    published: 'cluster.kind.published',
    applied: 'cluster.kind.applied',
    sync_failed: 'cluster.kind.syncFailed',
    rejected: 'cluster.kind.rejected',
    restarted: 'cluster.kind.restarted',
    expired: 'cluster.kind.expired',
    left: 'cluster.kind.left',
    voted: 'cluster.kind.voted',
    cert_issued: 'cluster.kind.certIssued',
    ca_rotation: 'cluster.kind.caRotation',
    maintenance: 'cluster.maint.title',
    maintenance_ended: 'cluster.kind.maintenanceEnded',
    handover: 'cluster.kind.handover',
    handover_failed: 'cluster.kind.handoverFailed',
    lease_released: 'cluster.kind.leaseReleased',
    stepped_down: 'cluster.kind.steppedDown',
    rollout_started: 'cluster.kind.rolloutStarted',
    rollout_promoted: 'cluster.kind.rolloutPromoted',
    rollout_failed: 'cluster.kind.rolloutFailed',
    pinned: 'cluster.kind.pinned',
    unpinned: 'cluster.kind.unpinned',
  };
  const kindLabel = (k: string) => (kinds[k] ? t(kinds[k]) : k);
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
  const stageWord: Record<string, MessageKey> = { canary: 'cluster.stage.baking', waiting: 'cluster.stage.waiting', pinned: 'cluster.stage.pinned' };
  const tabs = $derived<TabItem[]>([
    { id: 'nodes', label: t('legacy.nodes'), count: view?.nodes.length ?? null },
    { id: 'health', label: t('cluster.health.title'), count: problems || null, alert: problems > 0 },
    { id: 'rollouts', label: t('cluster.rollouts.title'), count: stageWord[stage] ? t(stageWord[stage]) : null, alert: stage === 'pinned' },
    { id: 'events', label: t('cluster.events.title'), count: recentProblems || null, alert: recentProblems > 0 },
    { id: 'compare', label: t('cluster.compare.title'), count: oddNodes ? t('cluster.tab.compareOdd', { n: oddNodes }) : null, alert: oddNodes > 0 },
    // REQ: CLU-014 — failover drills.
    { id: 'drills', label: t('cluster.drills.title'), count: drilling ? t('cluster.tab.drillsRunning') : null },
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

<div class="page">
  <div class="page-head">
    <h1>{t('nav.cluster')}<HelpButton id="cluster" /></h1>
    {#if view?.enabled}
      <span class="badge {view.healthy ? 'ok' : 'bad'}" data-testid="cluster-health">
        {view.healthy ? t('cluster.healthy') : t('cluster.needsAttention', { n: failing.length })}
      </span>
    {/if}
  </div>
  <ErrorNote {error} />
  {#if mine}
    <!-- REQ: OPS-010 — the node serving this page is in maintenance. -->
    <div class="notice warn maint-banner" role="status" data-testid="maintenance-banner">
      <strong>{t('cluster.maint.bannerTitle')}</strong>{t('cluster.maint.bannerBody', { until: until(mine), reason: mine.reason, by: mine.by })}<HelpButton id="maintenance" />
      {#if can('operator')}
        <button onclick={() => endMaintenance('local')} disabled={maintBusy} data-testid="maintenance-end-banner">{t('cluster.maint.end')}</button>
      {/if}
    </div>
  {/if}
  {#if maintNote}<p class="notice small" data-testid="maintenance-note">{maintNote}</p>{/if}
  {#if removeNote}
    <div class="notice small" role="status" data-testid="node-remove-note">
      <strong>{t('cluster.remove.done', { site: removeNote.site, id: shortId(removeNote.nodeId) })}</strong>
      {#each removeNote.notes as note, i (i)}<div>{note}</div>{/each}
    </div>
  {/if}
  {#if drillNote}<p class="notice small" data-testid="drill-note">{drillNote} <a href="#/cluster?tab=drills">{t('cluster.drills.title')}</a></p>{/if}
  <ErrorNote error={maintError} />

  {#if view && !view.enabled}
    <section class="card" data-testid="cluster-standalone">
      <h2>{t('cluster.standalone.title')}</h2>
      <p>
        {t('cluster.standalone.about')}
      </p>
      <pre class="mono small">telltale cluster init --name home --advertise https://this-node:8443
telltale cluster token create        # {t('cluster.standalone.comment')}
telltale cluster join tt_join_…</pre>
      <p class="muted small">{t('cluster.standalone.hint')}</p>
    </section>
    {#if can('operator') && !mine}
      <!-- REQ: OPS-010 — a standalone node can be put in maintenance too (readiness, banner, alerts). -->
      <section class="card">
        <h2>{t('cluster.maint.title')}<HelpButton id="maintenance" /></h2>
        {#if maintFor === 'local'}
          <MaintenanceForm node="local" label={t('legacy.thisNode')} onclose={() => (maintFor = null)} ondone={(r) => changed(r.note)} />
        {:else}
          <p class="small muted">{t('cluster.maint.hint')}</p>
          <button onclick={() => (maintFor = 'local')} data-testid="maintenance-open">{t('cluster.maint.open')}</button>
        {/if}
      </section>
    {/if}
    {#if view.host}
      <!-- REQ: CLU-008 (T6.11) — a standalone node still shows its machine. -->
      <section class="machines">
        <h2>{t('cluster.machine.title')}<HelpButton id="host-resources" /></h2>
        <div class="host-grid"><HostCard title={t('cluster.machine.cardTitle')} host={view.host} /></div>
      </section>
    {/if}
  {:else if view}
    <section class="card summary">
      <dl class="facts">
        <dt>{t('nav.cluster')}</dt><dd>{view.name} <span class="muted mono small">{view.clusterId}</span></dd>
        <dt>{t('legacy.nodes')}</dt><dd>{view.nodes.length} ({view.nodes.filter((n) => n.up).length} {t('cluster.node.up')})</dd>
        <dt>{t('cluster.configuration')}</dt><dd>{t('cluster.config.version', { version: num(view.newestConfigSeq) })}</dd>
        <dt>{t('cluster.primary')}</dt><dd>{view.nodes.find((n) => n.role.includes('primary'))?.site ?? t('groups.lists.none')}</dd>
        <dt>{t('cluster.config.from')}</dt>
        <dd>
          {#if view.source}
            <!-- REQ: CLU-003 — the Git repository, the commit in use, and the last check (ADR-049). -->
            <span data-testid="cluster-source">
              {t('cluster.config.git')} <span class="mono small">{view.source.repo}</span> @ {view.source.gitRef}, <span class="mono small">{view.source.path}</span>
            </span>
            {#if view.source.commit}
              <div class="small">
                {t('cluster.config.commit')} <span class="mono" title={view.source.commit}>{view.source.commit.slice(0, 12)}</span>
                {#if view.source.subject}“{view.source.subject}”{/if}
                <span class="muted">{t('cluster.config.by', { author: view.source.author ?? '' })}{#if view.source.committedAt}, {logDate(view.source.committedAt)}{/if}{#if view.source.signedBy}{t('cluster.config.signedBy', { signer: view.source.signedBy })}{/if}</span>
              </div>
            {:else}
              <div class="small muted">{t('cluster.config.noCommit')}</div>
            {/if}
            {#if view.source.error}
              <div class="notice {view.source.refused ? 'bad' : 'warn'} small" role="alert">
                {view.source.refused ? t('cluster.config.refused') : t('cluster.config.checkFailed')}: {view.source.error}
                <div class="muted">{t('cluster.config.keepsServing')}</div>
              </div>
            {/if}
          {:else}
            {view.authority === 'gitops' ? t('cluster.config.fromGit') : t('cluster.config.fromPrimary')}
          {/if}
        </dd>
        <!-- REQ: CLU-005 — how the cluster fails over (ADR-056). -->
        {#if view.failover}
          <dt>{t('cluster.failover')}</dt>
          <dd data-testid="cluster-failover">
            {#if view.failover.active}
              {t('cluster.failover.automatic', { reachable: view.failover.reachableVoters, voters: view.failover.voters })}
              {#if view.failover.leaseHeld}<span class="muted small">{t('cluster.failover.lease', { seconds: Math.round(view.failover.leaseSecondsLeft ?? 0) })}</span>{/if}
              {#if view.failover.votedFor}<div class="muted small">{t('cluster.failover.votedFor', { site: siteOf(view.failover.votedFor), epoch: view.failover.votedEpoch })}</div>{/if}
            {:else if view.failover.mode === 'auto'}
              {t('cluster.failover.waiting', { voters: view.failover.voters })}
            {:else}
              {t('cluster.failover.manual')}
            {/if}
          </dd>
        {/if}
      </dl>
      {#if me && me.role === 'replica' && can('admin') && !view.failover?.active}
        <div class="promote">
          {#if !confirming}
            <button onclick={() => (confirming = true)} disabled={primaryUp} title={primaryUp ? t('cluster.promote.primaryUp') : ''}
              >{takeover ? t('cluster.promote.takeoverOpen') : t('cluster.promote.open')}</button
            >
            {#if primaryUp}<span class="muted small">{t('cluster.promote.available')}</span>{/if}
          {:else}
            <div class="notice" role="alertdialog" aria-label={t('cluster.promote.aria')}>
              {#if takeover}
                <p>
                  <strong>{t('cluster.promote.takeoverTitle', { site: me.site })}</strong> {t('cluster.promote.takeoverBody', { primaries: upPrimaries.map((n) => n.site).join(', '), version: num(me.configSeq) })}
                </p>
              {:else}
                <p>
                  <strong>{t('cluster.promote.title', { site: me.site })}</strong> {t('cluster.promote.body', { version: num(me.configSeq) })}
                </p>
              {/if}
              {#if view.authority === 'gitops' && me.configSource !== 'gitops'}
                <label class="check"
                  ><input type="checkbox" bind:checked={emergency} /> {t('cluster.promote.emergency', { version: num(me.configSeq) })}</label
                >
              {/if}
              <label class="field"
                >{t('cluster.promote.password')} <input type="password" autocomplete="current-password" bind:value={password} /></label
              >
              {#if session.user?.totpEnabled}
                <label class="field"
                  >{t('cluster.promote.code')} <input inputmode="numeric" autocomplete="one-time-code" bind:value={totp} /></label
                >
              {/if}
              <ErrorNote error={promoteError} />
              <div class="row">
                <button class="primary" onclick={promote} disabled={promoting || !password}>{promoting ? t('cluster.promote.promoting') : t('cluster.promote.promote')}</button>
                <button onclick={() => (confirming = false)}>{t('common.cancel')}</button>
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
        <strong>{t('cluster.pin.title', { version: p.to })}</strong> {t('cluster.pin.body', { by: p.by, reason: p.reason })}
        <a href="#/cluster?tab=rollouts">{t('cluster.rollouts.title')}</a>
      </div>
    {/if}
    <Tabs {tabs} active={tab} label={t('nav.cluster')} />
    <TabPanel active={tab}>
    {#if tab === 'nodes'}
      <!-- REQ: CLU-008 (T6.14) — the cluster at a glance. -->
      <section class="card">
        <h2>{t('cluster.topology.title')}<HelpButton id="cluster-topology" /></h2>
        <Topology nodes={view.nodes} onselect={select} {canaries} />
      </section>

      <section class="card">
        <h2>{t('legacy.nodes')}</h2>
        <div class="table-wrap">
          <table class="nodes">
            <thead>
              <tr>
                <th>{t('qw.cache.node')}</th>
                <th>{t('cluster.col.status')}</th>
                <th>{t('cluster.configuration')}</th>
                <th>{t('cluster.col.servingDns')}</th>
                <th>{t('cluster.col.version')}</th>
                <th>{t('cluster.col.uptime')}</th>
              </tr>
            </thead>
            <tbody>
              {#snippet row(n: NonNullable<typeof view>['nodes'][number])}
                <tr data-testid="cluster-node" id={`node-${n.nodeId}`} class:selected={selected === n.nodeId}>
                  <td>
                    <strong>{n.site}</strong>
                    <span class="badge {n.role === 'primary' ? 'ok' : n.role.includes('emergency') ? 'warn' : ''}">{n.witness ? t('cluster.node.witness') : n.role}</span>
                    {#if n.ephemeral}<span class="muted small">{t('cluster.node.pod')}</span>{/if}
                    {#if n.thisNode}<span class="muted small">{t('legacy.thisNode')}</span>{/if}
                    <div class="mono muted small" title={n.nodeId}>
                      {shortId(n.nodeId)}{#if n.configSource}{' · '}{n.configSource === 'gitops' ? t('cluster.node.gitManaged') : t('cluster.node.localFile')}{/if}
                    </div>
                    {#if n.pod}<div class="muted small" data-testid="cluster-node-pod">{t('cluster.node.pod')} <span class="mono">{n.pod}</span>{#if n.kubeNode}{t('cluster.node.on')}<span class="mono">{n.kubeNode}</span>{/if}</div>{/if}
                    <!-- REQ: OPS-010 — the window, and the actions for operators. -->
                    {#if n.maintenance}
                      <div class="small" data-testid="cluster-node-maintenance">
                        <span class="badge warn" title={t('cluster.maint.by', { by: n.maintenance.by })}><Icon name="wrench" size={12} /> {t('cluster.maint.badge')}</span>
                        {t('cluster.maint.left', { time: duration(n.maintenance.secondsLeft) })} · {n.maintenance.reason}
                      </div>
                    {/if}
                    {#if (can('operator') && !n.witness) || canRemove(n)}
                      <div class="small">
                        {#if can('operator') && !n.witness}
                          {#if n.maintenance}
                            <button class="link small" onclick={() => endMaintenance(apiNode(n))} disabled={maintBusy} data-testid="maintenance-end">{t('cluster.maint.end')}</button>
                          {:else if maintFor !== n.nodeId}
                            <button class="link small" onclick={() => (maintFor = n.nodeId)} data-testid="maintenance-open">{t('cluster.maint.open')}</button>
                          {/if}
                          {#if !n.maintenance && drillFor !== n.nodeId && (view?.nodes.length ?? 0) > 1}
                            · <button class="link small" onclick={() => (drillFor = n.nodeId)} data-testid="drill-open-form">{t('cluster.drill.open')}</button>
                          {/if}
                        {/if}
                        <!-- REQ: CLU-001 (ADR-155) — an admin removes a stale or retired node. -->
                        {#if canRemove(n) && removeFor !== n.nodeId}
                          {#if can('operator') && !n.witness}·{/if}
                          <button class="link small" onclick={() => (removeFor = n.nodeId)} data-testid="node-remove-open">{t('cluster.remove.open')}</button>
                        {/if}
                      </div>
                    {/if}
                  </td>
                  <td>
                    <span class="badge {n.up ? 'ok' : 'bad'}">{n.up ? t('cluster.node.up') : t('cluster.node.down')}</span>
                    <div class="muted small">
                      {#if n.thisNode}—{:else}{n.link}{#if n.rttMs != null}{' · '}{ms(n.rttMs)} RTT{/if}{#if !n.up}{' · '}{t('cluster.node.seen', { time: duration(n.lastSeenSecondsAgo) })}{/if}{/if}
                    </div>
                  </td>
                  <td>
                    {t('cluster.config.version', { version: num(n.configSeq) })}
                    {#if canaries.includes(n.nodeId) || (n.thisNode && n.role === 'primary' && canaries.length)}<span class="badge warn" data-testid="cluster-node-canary">{t('cluster.node.canary')}</span>{/if}
                    {#if n.sourceCommit}<span class="mono muted small" title={n.sourceCommit}> · {n.sourceCommit.slice(0, 7)}</span>{/if}
                    <div class="small {n.configLag ? 'warn-text' : 'muted'}">
                      {#if n.configLag}{n.behindSeconds != null ? t('cluster.node.behindFor', { n: n.configLag, time: duration(n.behindSeconds) }) : t('cluster.node.behind', { n: n.configLag })}{:else}{t('cluster.node.inSync')}{/if}
                    </div>
                  </td>
                  <td>
                    <span class="badge {n.ready ? 'ok' : 'bad'}">{n.ready ? t('cluster.node.ready') : t('cluster.node.notReady')}</span>
                    <div class="muted small">
                      {rate(n.qps)} q/s{#if n.querySharePercent != null}{t('cluster.node.shareOfQueries', { pct: pct(n.querySharePercent) })}{/if} · {pct(n.servfailPercent)} SERVFAIL · {t('cluster.node.upstreamP90')} {n.upstreamP90Ms > 0 ? ms(n.upstreamP90Ms) : '–'}
                    </div>
                    {#if n.cacheEntries != null}
                      <div class="muted small">{t('cluster.node.cache')} {n.cacheHitPercent != null ? t('cluster.node.cacheHits', { pct: pct(n.cacheHitPercent) }) : t('cluster.node.noLookups')} · {t('cluster.node.entries', { n: num(n.cacheEntries) })}</div>
                    {/if}
                  </td>
                  <td class="small">{n.version}</td>
                  <td class="small">
                    {duration(n.uptimeSeconds)}
                    {#if n.restarts}<div class="warn-text">{tn('cluster.node.restarts', n.restarts, { n: n.restarts })}</div>{/if}
                    {#if n.certExpiresAt}<div class="muted">{t('cluster.node.certUntil', { date: logDate(n.certExpiresAt) })}</div>{/if}
                  </td>
                </tr>
                {#if maintFor === n.nodeId}
                  <tr class="maint-row">
                    <td colspan="6">
                      <MaintenanceForm
                        node={apiNode(n)}
                        label={n.thisNode ? t('legacy.thisNode') : (n.pod ?? n.site)}
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
                        label={n.thisNode ? t('legacy.thisNode') : (n.pod ?? n.site)}
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
                      {openSites.includes(site) ? '▾' : '▸'} <strong>{site}</strong>: {tn('cluster.pods.count', pods.length, { n: pods.length })}
                    </button>
                    <span class="muted small">
                      {t('cluster.pods.up', { n: pods.filter((p) => p.up).length })} · {t('cluster.pods.ready', { n: pods.filter((p) => p.ready).length })} ·
                      {rate(pods.reduce((t, p) => t + p.qps, 0))} q/s · {t('cluster.pods.behind', { n: pods.filter((p) => p.configLag > 0).length })}
                      {#if avg(pods.map((p) => p.cacheHitPercent)) != null}{t('cluster.pods.cacheAvg', { pct: pct(avg(pods.map((p) => p.cacheHitPercent)) ?? 0) })}{/if}
                    </span>
                  </td>
                </tr>
                {#if openSites.includes(site)}{#each pods as n (n.nodeId)}{@render row(n)}{/each}{/if}
              {/each}
            </tbody>
          </table>
        </div>
        {#if view.nodes.length === 1}
          <p class="muted small">{t('cluster.nodes.empty')} <span class="mono">telltale cluster join</span> {t('cluster.nodes.emptyMid')} <span class="mono">telltale cluster token create</span>{t('queries.whyEnd')}</p>
        {/if}
      </section>
    {:else if tab === 'health'}
      <section class="card">
        <h2>{t('cluster.checks.title')}</h2>
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

      {#if view.conflicts.length}
        <section class="card" data-testid="cluster-conflicts">
          <h2>{t('cluster.conflicts.title')}</h2>
          <p class="muted small">
            {t('cluster.conflicts.about')}
          </p>
          <ul class="conflicts">
            {#each view.conflicts as k (k.epoch * 1e9 + k.seq)}
              <li>
                <strong>{t('cluster.conflicts.version', { n: num(k.seq) })}</strong> <span class="muted small">{t('cluster.conflicts.when', { epoch: k.epoch, date: logDate(k.publishedAt), time: logTime(k.publishedAt) })}</span>
                <div class="small">{t('cluster.conflicts.changed')} <span class="mono">{k.changed.join(', ') || '—'}</span></div>
              </li>
            {/each}
          </ul>
        </section>
      {/if}

      <!-- REQ: CLU-008 (T6.11) — the machines nodes run on (pods only when their site is open). -->
      {@const machines = view.nodes.filter((n) => n.host && (!n.ephemeral || openSites.includes(n.site)))}
      {#if machines.length}
        <section class="machines" data-testid="cluster-machines">
          <h2>{t('cluster.machines.title')}<HelpButton id="host-resources" /></h2>
          <div class="host-grid">
            {#each machines as n (n.nodeId)}
              {#if n.host}<div class="host-slot" class:selected={selected === n.nodeId}><HostCard title={n.site} sub={`${n.thisNode ? t('legacy.thisNode') : n.role} · ${n.pod ?? shortId(n.nodeId)}`} host={n.host} /></div>{/if}
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
        <h2>{t('cluster.events.title')}</h2>
        {#if podSites.length || churn.restarted}
          <p class="muted small" data-testid="cluster-churn">
            {t('cluster.events.lastHour')} {t('cluster.events.joined', { n: churn.joined })} · {tn('cluster.events.gone', churn.expired, { n: churn.expired })} · {tn('cluster.events.restarted', churn.restarted, { n: churn.restarted })}
          </p>
        {/if}
        {#if view.events.length === 0}
          <p class="empty">{t('cluster.events.empty')}</p>
        {:else}
          <ol class="events">
            {#each view.events as e, i (i)}
              <li>
                <span class="mono small muted">{logDate(e.at)} {logTime(e.at)}</span>
                <span class="badge {kindClass(e.kind)}">{kindLabel(e.kind)}</span>
                <span class="mono small">{view.nodes.find((n) => n.nodeId === e.nodeId)?.site ?? shortId(e.nodeId)}</span>
                <span class="small">{e.detail}</span>
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
