<script lang="ts">
  // REQ: API-005, API-010 — configured devices and the clients seen in the last hour (60–65
  // minutes up to now, not the clock hour: ADR-158); name a device from either list.
  import { api, type S } from '../lib/api';
  import { href, navigate, route } from '../lib/router.svelte';
  import { ago, num } from '../lib/format';
  import { session } from '../lib/session.svelte';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import ClientChip from '../lib/components/ClientChip.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import IdentityLine from '../lib/components/IdentityLine.svelte';
  import Tabs, { activeTab, type TabItem } from '../lib/components/Tabs.svelte';
  import TabPanel from '../lib/components/TabPanel.svelte';
  import Drawer from '../lib/components/Drawer.svelte';
  import RhythmStrip from '../lib/components/RhythmStrip.svelte';
  import DeviceTimeline from '../lib/components/DeviceTimeline.svelte';
  import { groupFromText, loadWorkloads, workloadOf, workloads } from '../lib/workloads.svelte';
  import { mode } from '../lib/mode.svelte';
  import ConfigEditor, { type Field } from '../lib/components/ConfigEditor.svelte';
  import { plainHttpPage } from '../lib/plainHttp';
  import { listsMac } from '../lib/macKeys';

  let configured = $state<S['ClientInfo'][]>([]);
  let groups = $state<S['GroupInfo'][]>([]);
  const groupColor = (n: string) => groups.find((g) => g.name === n)?.color ?? 'var(--muted)';
  const fromText: Record<string, string> = {
    network: 'from its network',
    default: 'default: no network group matches',
  };
  let seen = $state<S['TopItem'][]>([]);
  // REQ: CLU-002 (ADR-158) — nodes that didn't answer (an older node doesn't know the
  // last-hour read): their clients aren't in the list, so say so.
  let seenMissing = $state<string[]>([]);
  // REQ: T8.2, T8.3 (T8.6) — devices found by the routers' DHCP or mDNS.
  let found = $state<S['DhcpLease'][]>([]);
  const sourceText: Record<string, string> = { router: 'router', mdns: 'mDNS' };
  // REQ: T8.2, API-002 (ADR-181) — the routers, added and changed here (admins). A key or
  // password is pasted, never a file named: the server saves it to a new file under secrets/
  // in the data folder of the node that took the change, and never shows it again. Changing the
  // address, type, site or TLS settings needs it pasted again. Each row says whether the node
  // that answered (on a replica, the primary) has its keys and uses them, or not (after a
  // restore or a failover; a key in /run/secrets/ or /etc/telltale-secrets/ is used on any
  // node). A key file a platform mounts, or a config file names, that isn't there is put back
  // as a file, not pasted (review round 2, R7: `file_missing`).
  type KeyStatus = { credentials?: Record<string, string> | null };
  const kept = (field: string, what: string) => (_: Record<string, unknown>, __: string, e?: KeyStatus) => {
    const s = e?.credentials?.[field];
    if (s === 'saved') return `Saved. Type a new ${what} to replace it.`;
    if (s === 'missing') return `Key missing: enter the ${what} again`;
    if (s === 'file_missing') return `Key file missing: put the file there (or paste the ${what})`;
    if (s === 'not_used') return `Not used: enter the ${what} again`;
    return `Paste the ${what}`;
  };
  const routerStatus = (e: KeyStatus) => {
    const s = Object.values(e.credentials ?? {});
    if (s.length === 0) return null;
    if (s.includes('missing')) return { text: 'key missing: enter it again', cls: 'bad' };
    if (s.includes('file_missing')) return { text: 'key file missing: put the file there, or paste the key', cls: 'bad' };
    if (s.includes('not_used')) return { text: 'key not used: enter it again', cls: 'bad' };
    return { text: 'key saved', cls: 'ok' };
  };
  const routerFields: Field[] = [
    { key: 'type', label: 'Type', type: 'select', options: ['unifi', 'opnsense', 'fritzbox'], optionLabels: { unifi: 'UniFi', opnsense: 'OPNsense', fritzbox: 'FRITZ!Box' }, initial: 'unifi' },
    { key: 'url', label: 'Address', type: 'text', placeholder: 'https://192.168.1.1',
      help: 'UniFi OS consoles: https://192.168.1.1. The classic Network application: https://controller:8443. OPNsense: https://opnsense.lan. FRITZ!Box: https://192.168.178.1:49443, with a username and password under Advanced. A pasted key is sent only over https://. Changing the address (or the type, site or TLS settings) needs the key pasted again.' },
    { key: 'api_key', label: 'API key', type: 'secret', placeholderFor: kept('api_key', 'API key'),
      help: 'UniFi Network 9+: Settings → Control Plane → Integrations. OPNsense: System → Access → Users → API keys. It is saved on the node that takes configuration changes, and not in backups.' },
    { key: 'api_secret', label: 'API secret (OPNsense)', type: 'secret', placeholderFor: kept('api_secret', 'API secret') },
    { key: 'username', label: 'Username (FRITZ!Box; UniFi instead of an API key)', type: 'text', placeholder: 'telltale', advanced: true,
      help: 'A local UniFi user; read-only is enough. FRITZ!Box: a user of the box (System → FRITZ!Box Users), with access to its settings.' },
    { key: 'password', label: 'Password (UniFi, FRITZ!Box)', type: 'secret', placeholderFor: kept('password', 'password'), advanced: true },
    { key: 'client_subnets', label: 'Client networks (FRITZ!Box, one per line)', type: 'lines', placeholder: '192.168.178.0/24',
      help: "The box's IPv4 networks whose hosts it may name: required for a FRITZ!Box, and not overlapping another box's." },
    { key: 'site', label: 'Site (UniFi)', type: 'text', placeholder: 'default', advanced: true },
    { key: 'tls_ca', label: 'Console certificate', type: 'text', placeholder: '/etc/telltale/udm.pem',
      help: 'A self-signed console: a file with its certificate, so it is verified.' },
    { key: 'tls_server_name', label: 'Name in the certificate', type: 'text', placeholder: 'unifi.local',
      help: 'UniFi consoles name themselves unifi.local; a FRITZ!Box, fritz.box.' },
    { key: 'tls_insecure_skip_verify', label: "Don't check the certificate", type: 'bool',
      help: 'Works with any console, but anything on your network could pose as it and receive the key. With a pasted key, give the address as a number (https://192.168.1.1).' },
    { key: 'interval_secs', label: 'Read every (seconds)', type: 'number', placeholder: '300', advanced: true },
    { key: 'offline_days', label: 'Offline devices seen within (days, UniFi)', type: 'number', placeholder: '30', advanced: true,
      help: '0: only the connected clients.' },
  ];
  // REQ: API-002, T8.2 (ADR-181) — the key files stay the server's: never sent back.
  const routerFiles = ['api_key_file', 'api_secret_file', 'password_file'];
  // REQ: API-002, T8.2 (ADR-181) — security F2: a page opened over plain HTTP from another
  // machine sends what is pasted into it unencrypted; say so (the server can't tell).
  const plainHttpNotice = plainHttpPage(location)
    ? 'You are on a plain-HTTP page: a key you paste crosses the network unencrypted. Open this page over https first.'
    : null;
  // REQ: API-010, FLT-006 (ADR-183) — a discovered device is named when a configured device lists its
  // address or its MAC address (a device named by its MAC follows it to whatever address it gets).
  const named = (l: S['DhcpLease']) => configured.some((c) => c.match.includes(l.ip) || (!!l.mac && listsMac(c.match, l.mac)));
  // REQ: OBS-025 — what each device looks like, by address.
  let identities = $state<Record<string, S['DeviceIdentity']>>({});
  let error = $state<unknown>(null);
  const canEdit = $derived(session.user?.role === 'admin' || session.user?.role === 'operator');

  function load() {
    Promise.all([api.clients(), api.top('clients', 100, undefined, undefined, undefined, 'rolling'), api.groups()])
      .then(([c, t, g]) => {
        configured = c.items;
        seen = t.items;
        seenMissing = t.missingNodes ?? [];
        groups = g.items;
      })
      .catch((e) => (error = e));
    api
      .dhcpLeases()
      .then((l) => (found = l.items))
      .catch(() => (found = []));
    api
      .identities()
      .then((r) => (identities = Object.fromEntries(r.items.map((i) => [i.client, i]))))
      .catch(() => (identities = {}));
    void loadWorkloads(true);
  }

  $effect(load);

  // REQ: CLU-014 — which servers each device used this week (Advanced view, a cluster): a lens,
  // never a finding; the help says what it can't tell.
  let affinity = $state<Record<string, S['AffinityRow']>>({});
  $effect(() => {
    if (mode.value !== 'advanced') return;
    api
      .affinity('7d')
      .then((p) => (affinity = Object.fromEntries(p.items.map((r) => [r.client, r]))))
      .catch(() => (affinity = {}));
  });
  // Only meaningful with more than one node answering.
  const showAffinity = $derived(
    mode.value === 'advanced' && new Set(Object.values(affinity).flatMap((r) => r.nodes.map((n) => n.node))).size > 1,
  );

  // REQ: FLT-017 — Kubernetes workloads (a tab only when there are any), by namespace.
  let namespace = $state('');
  const namespaces = $derived([...new Set(workloads.items.map((w) => w.namespace))].sort());
  const shownWorkloads = $derived(workloads.items.filter((w) => !namespace || w.namespace === namespace));
  const kindText: Record<string, string> = {
    deploy: 'Deployment',
    sts: 'StatefulSet',
    ds: 'DaemonSet',
    job: 'Job',
    cronjob: 'CronJob',
    rs: 'ReplicaSet',
    pod: 'Pod',
  };

  // REQ: API-005 (ADR-121) — one table per tab, each with its size.
  const tabs = $derived<TabItem[]>([
    { id: 'seen', label: 'Last hour', count: seen.length },
    { id: 'devices', label: 'Devices', count: configured.length },
    ...(workloads.items.length ? [{ id: 'workloads', label: 'Workloads', count: workloads.items.length }] : []),
    { id: 'discovered', label: 'Discovered', count: found.length },
  ]);
  const tab = $derived(activeTab(tabs));

  // REQ: OBS-031, OBS-034 — a device's drawer: its rhythm and its day. The address says which
  // (`#/clients?device=…&view=timeline`), so findings and the heatmap can link to it.
  const rhythmFor = $derived(route.params.get('device'));
  const view = $derived(route.params.get('view') === 'timeline' ? 'timeline' : 'rhythm');
  let rhythm = $state<S['ClientRhythm'] | null>(null);
  let rhythmError = $state<unknown>(null);
  function openDevice(ip: string, v: 'rhythm' | 'timeline') {
    const params: Record<string, string> = { device: ip, view: v };
    const t = route.params.get('tab');
    if (t) params.tab = t;
    navigate('/clients', params);
  }
  function closeDevice() {
    const t = route.params.get('tab');
    navigate('/clients', t ? { tab: t } : {});
  }
  $effect(() => {
    const ip = rhythmFor;
    if (!ip || view !== 'rhythm') return;
    rhythm = null;
    rhythmError = null;
    api
      .rhythm(ip)
      .then((r) => (rhythm = r))
      .catch((e) => (rhythmError = e));
  });

  async function remove(name: string) {
    try {
      await api.deleteClient(name);
      load();
    } catch (e) {
      error = e;
    }
  }
</script>

<div class="page">
  <h1>Clients<HelpButton id="devices" /></h1>
  <ErrorNote {error} />
  <Tabs {tabs} active={tab} label="Clients" />
  <TabPanel active={tab}>
  {#if tab === 'seen'}
    <section class="card">
      <h2>Seen in the last hour</h2>
      {#if seenMissing.length}
        <p class="small muted" data-testid="seen-missing">Without {seenMissing.join(', ')}: they didn’t answer, so their clients aren’t listed.</p>
      {/if}
      {#if seen.length === 0}
        <p class="empty">No queries in the last hour.</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead><tr><th>Client</th><th>Device</th><th>Groups</th>{#if showAffinity}<th data-testid="affinity-head">Servers<HelpButton id="affinity" /></th>{/if}<th class="num">Queries</th><th></th></tr></thead>
            <tbody>
              {#each seen as c (c.key)}
                <tr>
                  <td class="mono"><ClientChip ip={c.key} onchanged={load} /></td>
                  <td>{c.name ?? ''}<IdentityLine identity={identities[c.key]} /></td>
                  <td class="small">
                    {#each c.groups ?? [] as g (g)}<span class="group-chip" style:--gc={groupColor(g)}>{g}</span>{/each}
                  </td>
                  {#if showAffinity}
                    {@const a = affinity[c.key]}
                    <td class="small" data-testid="affinity" title={a ? a.nodes.map((n) => `${n.node}: ${num(n.queries)}`).join('\n') : ''}>{a?.label ?? ''}</td>
                  {/if}
                  <td class="num">{num(c.count)}</td>
                  <td class="num"><a href={href('/queries', { client: c.key })}>Queries</a> · <a href={href('/heatmap', { kind: 'client', key: c.key })}>When</a> · <button type="button" class="link small" onclick={() => openDevice(c.key, 'rhythm')} data-testid="open-rhythm">Rhythm</button> · <button type="button" class="link small" onclick={() => openDevice(c.key, 'timeline')} data-testid="open-timeline">Day</button></td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </section>
  {:else if tab === 'devices'}
    <section class="card">
      <h2>Devices</h2>
      {#if configured.length === 0}
        <p class="empty">No devices yet. Click an address anywhere (here, the dashboard, or the query log) and choose “Name this device…”, or add <code>[[client]]</code> entries to the config file.</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead><tr><th>Name</th><th>Recognized by</th><th>Groups</th><th>Defined in</th><th></th></tr></thead>
            <tbody>
              {#each configured as c (c.name)}
                <tr>
                  <td><strong>{c.name}</strong><IdentityLine identity={c.identity} /></td>
                  <td class="mono small">{c.match.join(', ')}</td>
                  <td class="small">
                    <!-- REQ: FLT-005 — the groups that apply, and where they come from (ADR-050). -->
                    {#each c.effectiveGroups ?? [] as g (g)}<span class="group-chip" style:--gc={groupColor(g)}>{g}</span>{/each}
                    {#if (c.effectiveGroups ?? []).length === 0}
                      <span class="muted">its network's group, wherever it's seen</span>
                    {:else if fromText[c.groupsFrom ?? '']}
                      <div class="muted">{fromText[c.groupsFrom ?? '']}</div>
                    {/if}
                  </td>
                  <td class="small">{c.source === 'api' ? 'the UI / API' : 'config file'}</td>
                  <td class="num">
                    {#if c.source === 'api' && canEdit}
                      <button class="link small" onclick={() => remove(c.name)} aria-label={`Forget ${c.name}`}>Forget</button>
                    {/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </section>
  {:else if tab === 'workloads'}
    <section class="card" data-testid="workloads">
      <div class="card-head">
        <h2>Kubernetes workloads<HelpButton id="kubernetes-workloads" /></h2>
        <label class="small">
          Namespace
          <select bind:value={namespace} aria-label="Namespace" data-testid="workload-namespace">
            <option value="">All</option>
            {#each namespaces as n (n)}<option value={n}>{n}</option>{/each}
          </select>
        </label>
      </div>
      <p class="muted small">
        Each workload is one device, whichever pods it runs: its queries, anomalies, and timeline survive rollouts. Its
        group comes from a <code>telltaledns.io/group</code> label on its pods or namespace, a rule, or the default group.
        Counts cover the last 24 hours.
      </p>
      <div class="table-wrap">
        <table>
          <thead
            ><tr
              ><th>Workload</th><th>Group</th><th class="num">Pods</th><th class="num" title="In the last 24 hours">Queries</th><th class="num" title="In the last 24 hours">Blocked</th><th>Last seen</th><th></th></tr
            ></thead
          >
          <tbody>
            {#each shownWorkloads as w (w.name)}
              <tr data-testid="workload-row">
                <td class="mono nowrap" title={kindText[w.kind] ?? w.kind}><ClientChip ip={w.key} name={w.name} onchanged={load} /></td>
                <td class="small nowrap">
                  {#if w.group}<span class="group-chip" style:--gc={groupColor(w.group)}>{w.group}</span>{/if}
                  <div class="muted" data-testid="group-from">{groupFromText[w.groupFrom] ?? w.groupFrom}</div>
                </td>
                <td class="num" title={w.pods.map((p) => `${p.name} ${p.addresses.join(' ')}${p.terminating ? ' (terminating)' : ''}`).join('\n')}>{w.pods.filter((p) => !p.terminating).length}</td>
                <td class="num">{num(w.queries24h)}</td>
                <td class="num">{num(w.blocked24h)}</td>
                <td class="small">{w.lastSeen ? ago(Date.parse(w.lastSeen) / 1000) : 'not in the last day'}</td>
                <td class="num nowrap"><a href={href('/queries', { client: w.name })}>Queries</a> · <button type="button" class="link" onclick={() => openDevice(w.key, 'timeline')}>Day</button></td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </section>
  {:else}
    <section class="card" data-testid="discovered">
      <h2>Discovered on your network</h2>
      <p class="muted small">
        Names your router's DHCP knows (<code>[[router]]</code>: UniFi, OPNsense, FRITZ!Box), or that devices announced
        themselves over mDNS (<code>[clients] mdns</code>). Unnamed devices already show these names; click an address to keep
        one, change it, or put the device in a group.
      </p>
      {#if found.length === 0}
        <p class="empty">Nothing discovered yet. Connect your router under <strong>Routers</strong>, below, or set <code>[clients] mdns = true</code>.</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead><tr><th>Address</th><th>Name it gave</th><th>From</th><th>MAC</th><th>In TelltaleDNS</th></tr></thead>
            <tbody>
              {#each found as l (l.ip)}
                <tr>
                  <td class="mono"><ClientChip ip={l.ip} onchanged={load} /></td>
                  <td>{l.hostname ?? ''}</td>
                  <td><span class="badge info">{sourceText[l.source] ?? l.source}</span></td>
                  <td class="mono small">{l.mac}</td>
                  <td class="small">{#if named(l)}<strong>{l.clientName}</strong>{:else}<span class="muted">not named yet</span>{/if}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </section>
    <ConfigEditor kind="router" path="routers" title="Routers" noun="router" fields={routerFields} role="admin"
      summary={(d) => `${String(d.type ?? '')} · ${String(d.url ?? '')}`}
      status={routerStatus} omit={routerFiles} notice={plainHttpNotice}
      onchanged={load} />
  {/if}
  </TabPanel>
  {#if rhythmFor}
    <Drawer title={workloadOf(rhythmFor)?.name ?? rhythmFor} onclose={closeDevice}>
      <div class="seg" role="group" aria-label="Device view">
        <button type="button" aria-pressed={view === 'rhythm'} onclick={() => openDevice(rhythmFor, 'rhythm')} data-testid="device-rhythm">Rhythm</button>
        <button type="button" aria-pressed={view === 'timeline'} onclick={() => openDevice(rhythmFor, 'timeline')} data-testid="device-timeline">Timeline</button>
      </div>
      {#if view === 'timeline'}
        <p class="muted small">This device's day from the query log: a lane per domain it talks to, the answer time below, and what happened above.<HelpButton id="device-timeline" /></p>
        <DeviceTimeline client={rhythmFor} />
      {:else}
      <p class="muted small">How regularly this device asks for each domain it talks to most: each column is a gap between two queries (log scale), darker where more of them fall. One dark cell is a timer; a smear is a person.<HelpButton id="rhythm" /></p>
      <ErrorNote error={rhythmError} />
      {#if rhythm}
        {#if !rhythm.available}
          <p class="empty">The anomaly engine is off (<code>[telemetry.anomaly] enabled</code>), so nothing measures the rhythm.</p>
        {:else}
          <RhythmStrip rows={rhythm.domains} client={rhythm.client} binsS={rhythm.binsS} />
          {#if rhythm.missingNodes?.length}<p class="muted small">Not answering: {rhythm.missingNodes.join(', ')}.</p>{/if}
        {/if}
      {/if}
      {/if}
    </Drawer>
  {/if}
</div>

<style>
  /* REQ: FLT-017 — a workload's name on one line (the table scrolls instead). */
  .nowrap {
    white-space: nowrap;
  }
</style>
