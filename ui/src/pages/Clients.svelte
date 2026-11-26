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
  import { own, tr } from '../lib/i18n';
  import T from '../lib/i18n/T.svelte';
  const { t } = tr('clients');

  let configured = $state<S['ClientInfo'][]>([]);
  let groups = $state<S['GroupInfo'][]>([]);
  const groupColor = (n: string) => groups.find((g) => g.name === n)?.color ?? 'var(--muted)';
  // The constants of the rows are read once, here: language is fixed for the life of the page.
  const fromText: Record<string, string> = {
    network: t('from its network'),
    default: t('default: no network group matches'),
  };
  const byUi = t('the UI / API');
  const byFile = t('config file');
  let seen = $state<S['TopItem'][]>([]);
  // REQ: CLU-002 (ADR-158) — nodes that didn't answer (an older node doesn't know the
  // last-hour read): their clients aren't in the list, so say so.
  let seenMissing = $state<string[]>([]);
  // REQ: T8.2, T8.3 (T8.6) — devices found by the routers' DHCP or mDNS.
  let found = $state<S['DhcpLease'][]>([]);
  const sourceText: Record<string, string> = { router: t('router'), mdns: t('mDNS') };
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
    if (s === 'saved') return t('Saved. Type a new {what} to replace it.', { what });
    if (s === 'missing') return t('Key missing: enter the {what} again', { what });
    if (s === 'file_missing') return t('Key file missing: put the file there (or paste the {what})', { what });
    if (s === 'not_used') return t('Not used: enter the {what} again', { what });
    return t('Paste the {what}', { what });
  };
  const keyText = {
    missing: t('key missing: enter it again'),
    file_missing: t('key file missing: put the file there, or paste the key'),
    not_used: t('key not used: enter it again'),
    saved: t('key saved'),
  };
  const routerStatus = (e: KeyStatus) => {
    const s = Object.values(e.credentials ?? {});
    if (s.length === 0) return null;
    if (s.includes('missing')) return { text: keyText.missing, cls: 'bad' };
    if (s.includes('file_missing')) return { text: keyText.file_missing, cls: 'bad' };
    if (s.includes('not_used')) return { text: keyText.not_used, cls: 'bad' };
    return { text: keyText.saved, cls: 'ok' };
  };
  const routerFields: Field[] = [
    { key: 'type', label: t('Type'), type: 'select', options: ['unifi', 'opnsense'], initial: 'unifi' },
    { key: 'url', label: t('Address'), type: 'text', placeholder: 'https://192.168.1.1',
      help: t('UniFi OS consoles: https://192.168.1.1. The classic Network application: https://controller:8443. OPNsense: https://opnsense.lan. A pasted key is sent only over https://. Changing the address (or the type, site or TLS settings) needs the key pasted again.') },
    { key: 'api_key', label: t('API key'), type: 'secret', placeholderFor: kept('api_key', t('API key')),
      help: t('UniFi Network 9+: Settings → Control Plane → Integrations. OPNsense: System → Access → Users → API keys. It is saved on the node that takes configuration changes, and not in backups.') },
    { key: 'api_secret', label: t('API secret (OPNsense)'), type: 'secret', placeholderFor: kept('api_secret', t('API secret')) },
    { key: 'username', label: t('Username (UniFi, instead of an API key)'), type: 'text', placeholder: t('telltale'), advanced: true,
      help: t('A local UniFi user; read-only is enough.') },
    { key: 'password', label: t('Password (UniFi)'), type: 'secret', placeholderFor: kept('password', t('password')), advanced: true },
    { key: 'site', label: t('Site (UniFi)'), type: 'text', placeholder: t('default'), advanced: true },
    { key: 'tls_ca', label: t('Console certificate'), type: 'text', placeholder: '/etc/telltale/udm.pem',
      help: t('A self-signed console: a file with its certificate, so it is verified.') },
    { key: 'tls_server_name', label: t('Name in the certificate'), type: 'text', placeholder: 'unifi.local',
      help: t('UniFi consoles name themselves unifi.local.') },
    { key: 'tls_insecure_skip_verify', label: t("Don't check the certificate"), type: 'bool',
      help: t('Works with any console, but anything on your network could pose as it and receive the key. With a pasted key, give the address as a number (https://192.168.1.1).') },
    { key: 'interval_secs', label: t('Read every (seconds)'), type: 'number', placeholder: '300', advanced: true },
    { key: 'offline_days', label: t('Offline devices seen within (days, UniFi)'), type: 'number', placeholder: '30', advanced: true,
      help: t('0: only the connected clients.') },
  ];
  // REQ: API-002, T8.2 (ADR-181) — the key files stay the server's: never sent back.
  const routerFiles = ['api_key_file', 'api_secret_file', 'password_file'];
  // REQ: API-002, T8.2 (ADR-181) — security F2: a page opened over plain HTTP from another
  // machine sends what is pasted into it unencrypted; say so (the server can't tell).
  const plainHttpNotice = plainHttpPage(location)
    ? t('You are on a plain-HTTP page: a key you paste crosses the network unencrypted. Open this page over https first.')
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
  // A kind comes from the server: read with `Object.hasOwn`, and one the UI doesn't know shows as it is.
  const kindText: Record<string, string> = {
    deploy: t('Deployment'),
    sts: t('StatefulSet'),
    ds: t('DaemonSet'),
    job: t('Job'),
    cronjob: t('CronJob'),
    rs: t('ReplicaSet'),
    pod: t('Pod'),
  };
  const notLately = t('not in the last day');
  // The words of the rows: one call for each place the English stood.
  const seenLinks = { queries: t('Queries'), when: t('When'), rhythm: t('Rhythm'), day: t('Day') };
  const workloadLinks = { queries: t('Queries'), day: t('Day') };
  const rowWords = { ownGroup: t("its network's group, wherever it's seen"), forget: t('Forget'), notNamed: t('not named yet') };

  // REQ: API-005 (ADR-121) — one table per tab, each with its size.
  const tabLabels = { seen: t('Last hour'), devices: t('Devices'), workloads: t('Workloads'), discovered: t('Discovered') };
  const tabs = $derived<TabItem[]>([
    { id: 'seen', label: tabLabels.seen, count: seen.length },
    { id: 'devices', label: tabLabels.devices, count: configured.length },
    ...(workloads.items.length ? [{ id: 'workloads', label: tabLabels.workloads, count: workloads.items.length }] : []),
    { id: 'discovered', label: tabLabels.discovered, count: found.length },
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

{#snippet strong(x: string)}<strong>{x}</strong>{/snippet}
{#snippet cliententry()}<code translate="no">[[client]]</code>{/snippet}
{#snippet routerentry()}<code translate="no">[[router]]</code>{/snippet}
{#snippet mdnskey()}<code translate="no">[clients] mdns</code>{/snippet}
{#snippet mdnson()}<code translate="no">[clients] mdns = true</code>{/snippet}
{#snippet anomalykey()}<code translate="no">[telemetry.anomaly] enabled</code>{/snippet}
{#snippet groupkey()}<code translate="no">telltaledns.io/group</code>{/snippet}

<div class="page">
  <h1>{t('Clients')}<HelpButton id="devices" /></h1>
  <ErrorNote {error} />
  <Tabs {tabs} active={tab} label={t('Clients')} />
  <TabPanel active={tab}>
  {#if tab === 'seen'}
    <section class="card">
      <h2>{t('Seen in the last hour')}</h2>
      {#if seenMissing.length}
        <p class="small muted" data-testid="seen-missing">{t('Without {nodes}: they didn’t answer, so their clients aren’t listed.', { nodes: seenMissing.join(', ') })}</p>
      {/if}
      {#if seen.length === 0}
        <p class="empty">{t('No queries in the last hour.')}</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead><tr><th>{t('Client')}</th><th>{t('Device')}</th><th>{t('Groups')}</th>{#if showAffinity}<th data-testid="affinity-head">{t('Servers')}<HelpButton id="affinity" /></th>{/if}<th class="num">{t('Queries')}</th><th></th></tr></thead>
            <tbody>
              {#each seen as c (c.key)}
                <tr>
                  <td class="mono"><ClientChip ip={c.key} onchanged={load} /></td>
                  <td><span translate="no">{c.name ?? ''}</span><IdentityLine identity={identities[c.key]} /></td>
                  <td class="small">
                    {#each c.groups ?? [] as g (g)}<span class="group-chip" translate="no" style:--gc={groupColor(g)}>{g}</span>{/each}
                  </td>
                  {#if showAffinity}
                    {@const a = affinity[c.key]}
                    <td class="small" data-testid="affinity" title={a ? a.nodes.map((n) => `${n.node}: ${num(n.queries)}`).join('\n') : ''}><span translate="no">{a?.label ?? ''}</span></td>
                  {/if}
                  <td class="num">{num(c.count)}</td>
                  <td class="num"><a href={href('/queries', { client: c.key })}>{seenLinks.queries}</a> · <a href={href('/heatmap', { kind: 'client', key: c.key })}>{seenLinks.when}</a> · <button type="button" class="link small" onclick={() => openDevice(c.key, 'rhythm')} data-testid="open-rhythm">{seenLinks.rhythm}</button> · <button type="button" class="link small" onclick={() => openDevice(c.key, 'timeline')} data-testid="open-timeline">{seenLinks.day}</button></td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </section>
  {:else if tab === 'devices'}
    <section class="card">
      <h2>{t('Devices')}</h2>
      {#if configured.length === 0}
        <p class="empty"><T ctx="clients" msg={'No devices yet. Click an address anywhere (here, the dashboard, or the query log) and choose “Name this device…”, or add <cliententry/> entries to the config file.'} {cliententry} /></p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead><tr><th>{t('Name')}</th><th>{t('Recognized by')}</th><th>{t('Groups')}</th><th>{t('Defined in')}</th><th></th></tr></thead>
            <tbody>
              {#each configured as c (c.name)}
                <tr>
                  <td><strong translate="no">{c.name}</strong><IdentityLine identity={c.identity} /></td>
                  <td class="mono small" translate="no">{c.match.join(', ')}</td>
                  <td class="small">
                    <!-- REQ: FLT-005 — the groups that apply, and where they come from (ADR-050). -->
                    {#each c.effectiveGroups ?? [] as g (g)}<span class="group-chip" translate="no" style:--gc={groupColor(g)}>{g}</span>{/each}
                    {#if (c.effectiveGroups ?? []).length === 0}
                      <span class="muted">{rowWords.ownGroup}</span>
                    {:else if own(fromText, c.groupsFrom)}
                      <div class="muted">{own(fromText, c.groupsFrom)}</div>
                    {/if}
                  </td>
                  <td class="small">{c.source === 'api' ? byUi : byFile}</td>
                  <td class="num">
                    {#if c.source === 'api' && canEdit}
                      <button class="link small" onclick={() => remove(c.name)} aria-label={t('Forget {name}', { name: c.name })}>{rowWords.forget}</button>
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
        <h2>{t('Kubernetes workloads')}<HelpButton id="kubernetes-workloads" /></h2>
        <label class="small">
          {t('Namespace')}
          <select bind:value={namespace} aria-label={t('Namespace')} data-testid="workload-namespace">
            <option value="">{t('All')}</option>
            {#each namespaces as n (n)}<option value={n} translate="no">{n}</option>{/each}
          </select>
        </label>
      </div>
      <p class="muted small">
        <T ctx="clients" msg={'Each workload is one device, whichever pods it runs: its queries, anomalies, and timeline survive rollouts. Its group comes from a <groupkey/> label on its pods or namespace, a rule, or the default group. Counts cover the last 24 hours.'} {groupkey} />
      </p>
      <div class="table-wrap">
        <table>
          <thead
            ><tr
              ><th>{t('Workload')}</th><th>{t('Group')}</th><th class="num">{t('Pods')}</th><th class="num" title={t('In the last 24 hours')}>{t('Queries')}</th><th class="num" title={t('In the last 24 hours')}>{t('Blocked')}</th><th>{t('Last seen')}</th><th></th></tr
            ></thead
          >
          <tbody>
            {#each shownWorkloads as w (w.name)}
              <tr data-testid="workload-row">
                <td class="mono nowrap" title={own(kindText, w.kind) ?? w.kind}><ClientChip ip={w.key} name={w.name} onchanged={load} /></td>
                <td class="small nowrap">
                  {#if w.group}<span class="group-chip" translate="no" style:--gc={groupColor(w.group)}>{w.group}</span>{/if}
                  <div class="muted" data-testid="group-from">{groupFromText(w.groupFrom)}</div>
                </td>
                <td class="num" title={w.pods.map((p) => (p.terminating ? t('{name} {addresses} (terminating)', { name: p.name, addresses: p.addresses.join(' ') }) : `${p.name} ${p.addresses.join(' ')}`)).join('\n')}>{w.pods.filter((p) => !p.terminating).length}</td>
                <td class="num">{num(w.queries24h)}</td>
                <td class="num">{num(w.blocked24h)}</td>
                <td class="small">{w.lastSeen ? ago(Date.parse(w.lastSeen) / 1000) : notLately}</td>
                <td class="num nowrap"><a href={href('/queries', { client: w.name })}>{workloadLinks.queries}</a> · <button type="button" class="link" onclick={() => openDevice(w.key, 'timeline')}>{workloadLinks.day}</button></td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </section>
  {:else}
    <section class="card" data-testid="discovered">
      <h2>{t('Discovered on your network')}</h2>
      <p class="muted small">
        <T ctx="clients" msg={"Names your router's DHCP knows (<routerentry/>: UniFi, OPNsense), or that devices announced themselves over mDNS (<mdnskey/>). Unnamed devices already show these names; click an address to keep one, change it, or put the device in a group."} {routerentry} {mdnskey} />
      </p>
      {#if found.length === 0}
        <p class="empty"><T ctx="clients" msg={'Nothing discovered yet. Connect your router under <strong>Routers</strong>, below, or set <mdnson/>.'} {strong} {mdnson} /></p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead><tr><th>{t('Address')}</th><th>{t('Name it gave')}</th><th>{t('From')}</th><th>{t('MAC')}</th><th>{t('In TelltaleDNS')}</th></tr></thead>
            <tbody>
              {#each found as l (l.ip)}
                <tr>
                  <td class="mono"><ClientChip ip={l.ip} onchanged={load} /></td>
                  <td translate="no">{l.hostname ?? ''}</td>
                  <td><span class="badge info">{own(sourceText, l.source) ?? l.source}</span></td>
                  <td class="mono small" translate="no">{l.mac}</td>
                  <td class="small">{#if named(l)}<strong translate="no">{l.clientName}</strong>{:else}<span class="muted">{rowWords.notNamed}</span>{/if}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </section>
    <ConfigEditor kind="router" path="routers" title={t('Routers')} noun={t('router')} fields={routerFields} role="admin"
      summary={(d) => `${String(d.type ?? '')} · ${String(d.url ?? '')}`}
      status={routerStatus} omit={routerFiles} notice={plainHttpNotice}
      onchanged={load} />
  {/if}
  </TabPanel>
  {#if rhythmFor}
    <Drawer title={workloadOf(rhythmFor)?.name ?? rhythmFor} onclose={closeDevice}>
      <div class="seg" role="group" aria-label={t('Device view')}>
        <button type="button" aria-pressed={view === 'rhythm'} onclick={() => openDevice(rhythmFor, 'rhythm')} data-testid="device-rhythm">{t('Rhythm')}</button>
        <button type="button" aria-pressed={view === 'timeline'} onclick={() => openDevice(rhythmFor, 'timeline')} data-testid="device-timeline">{t('Timeline')}</button>
      </div>
      {#if view === 'timeline'}
        <p class="muted small">{t('This device\'s day from the query log: a lane per domain it talks to, the answer time below, and what happened above.')}<HelpButton id="device-timeline" /></p>
        <DeviceTimeline client={rhythmFor} />
      {:else}
      <p class="muted small">{t('How regularly this device asks for each domain it talks to most: each column is a gap between two queries (log scale), darker where more of them fall. One dark cell is a timer; a smear is a person.')}<HelpButton id="rhythm" /></p>
      <ErrorNote error={rhythmError} />
      {#if rhythm}
        {#if !rhythm.available}
          <p class="empty"><T ctx="clients" msg={'The anomaly engine is off (<anomalykey/>), so nothing measures the rhythm.'} {anomalykey} /></p>
        {:else}
          <RhythmStrip rows={rhythm.domains} client={rhythm.client} binsS={rhythm.binsS} />
          {#if rhythm.missingNodes?.length}<p class="muted small">{t('Not answering: {nodes}.', { nodes: rhythm.missingNodes.join(', ') })}</p>{/if}
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
