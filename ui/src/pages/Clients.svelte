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
  import { groupFromLabel, loadWorkloads, workloadOf, workloads } from '../lib/workloads.svelte';
  import { mode } from '../lib/mode.svelte';
  import ConfigEditor, { type Field } from '../lib/components/ConfigEditor.svelte';
  import { plainHttpPage } from '../lib/plainHttp';
  import { listsMac } from '../lib/macKeys';
  import { t } from '../lib/i18n';

  let configured = $state<S['ClientInfo'][]>([]);
  let groups = $state<S['GroupInfo'][]>([]);
  const groupColor = (n: string) => groups.find((g) => g.name === n)?.color ?? 'var(--muted)';
  const fromText = $derived<Record<string, string>>({
    network: t('clients.from.network'),
    default: t('clients.from.default'),
  });
  let seen = $state<S['TopItem'][]>([]);
  // REQ: CLU-002 (ADR-158) — nodes that didn't answer (an older node doesn't know the
  // last-hour read): their clients aren't in the list, so say so.
  let seenMissing = $state<string[]>([]);
  // REQ: T8.2, T8.3 (T8.6) — devices found by the routers' DHCP or mDNS.
  let found = $state<S['DhcpLease'][]>([]);
  const sourceText = $derived<Record<string, string>>({
    router: t('clients.router.noun'),
    mdns: t('clients.source.mdns'),
  });
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
    if (s === 'saved') return t('clients.keep.saved', { what });
    if (s === 'missing') return t('clients.keep.missing', { what });
    if (s === 'file_missing') return t('clients.keep.fileMissing', { what });
    if (s === 'not_used') return t('clients.keep.notUsed', { what });
    return t('clients.keep.paste', { what });
  };
  const routerStatus = (e: KeyStatus) => {
    const s = Object.values(e.credentials ?? {});
    if (s.length === 0) return null;
    if (s.includes('missing')) return { text: t('clients.routerStatus.missing'), cls: 'bad' };
    if (s.includes('file_missing')) return { text: t('clients.routerStatus.fileMissing'), cls: 'bad' };
    if (s.includes('not_used')) return { text: t('clients.routerStatus.notUsed'), cls: 'bad' };
    return { text: t('clients.routerStatus.saved'), cls: 'ok' };
  };
  const routerFields = $derived<Field[]>([
    { key: 'type', label: t('qw.cache.type'), type: 'select', options: ['unifi', 'opnsense'], initial: 'unifi' },
    { key: 'url', label: t('qw.explain.address'), type: 'text', placeholder: 'https://192.168.1.1',
      help: t('clients.router.urlHelp') },
    { key: 'api_key', label: t('clients.keep.apiKey'), type: 'secret', placeholderFor: kept('api_key', t('clients.keep.apiKey')),
      help: t('clients.router.apiKeyHelp') },
    { key: 'api_secret', label: t('clients.router.apiSecret'), type: 'secret', placeholderFor: kept('api_secret', t('clients.keep.apiSecret')) },
    { key: 'username', label: t('clients.router.username'), type: 'text', placeholder: 'telltale', advanced: true,
      help: t('clients.router.usernameHelp') },
    { key: 'password', label: t('clients.router.password'), type: 'secret', placeholderFor: kept('password', t('clients.keep.password')), advanced: true },
    { key: 'site', label: t('clients.router.site'), type: 'text', placeholder: 'default', advanced: true },
    { key: 'tls_ca', label: t('clients.router.tlsCa'), type: 'text', placeholder: '/etc/telltale/udm.pem',
      help: t('clients.router.tlsCaHelp') },
    { key: 'tls_server_name', label: t('clients.router.tlsName'), type: 'text', placeholder: 'unifi.local',
      help: t('clients.router.tlsNameHelp') },
    { key: 'tls_insecure_skip_verify', label: t('clients.router.tlsInsecure'), type: 'bool',
      help: t('clients.router.tlsInsecureHelp') },
    { key: 'interval_secs', label: t('clients.router.interval'), type: 'number', placeholder: '300', advanced: true },
    { key: 'offline_days', label: t('clients.router.offlineDays'), type: 'number', placeholder: '30', advanced: true,
      help: t('clients.router.offlineDaysHelp') },
  ]);
  // REQ: API-002, T8.2 (ADR-181) — the key files stay the server's: never sent back.
  const routerFiles = ['api_key_file', 'api_secret_file', 'password_file'];
  // REQ: API-002, T8.2 (ADR-181) — security F2: a page opened over plain HTTP from another
  // machine sends what is pasted into it unencrypted; say so (the server can't tell).
  const plainHttpNotice = $derived(
    plainHttpPage(location) ? t('clients.plainHttp') : null,
  );
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
  const kindText = $derived<Record<string, string>>({
    deploy: t('clients.kind.deploy'),
    sts: t('clients.kind.sts'),
    ds: t('clients.kind.ds'),
    job: t('clients.kind.job'),
    cronjob: t('clients.kind.cronjob'),
    rs: t('clients.kind.rs'),
    pod: t('clients.kind.pod'),
  });

  // REQ: API-005 (ADR-121) — one table per tab, each with its size.
  const tabs = $derived<TabItem[]>([
    { id: 'seen', label: t('clients.tab.seen'), count: seen.length },
    { id: 'devices', label: t('clients.tab.devices'), count: configured.length },
    ...(workloads.items.length ? [{ id: 'workloads', label: t('clients.tab.workloads'), count: workloads.items.length }] : []),
    { id: 'discovered', label: t('clients.tab.discovered'), count: found.length },
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
  <h1>{t('nav.clients')}<HelpButton id="devices" /></h1>
  <ErrorNote {error} />
  <Tabs {tabs} active={tab} label={t('nav.clients')} />
  <TabPanel active={tab}>
  {#if tab === 'seen'}
    <section class="card">
      <h2>{t('clients.seen.title')}</h2>
      {#if seenMissing.length}
        <p class="small muted" data-testid="seen-missing">{t('clients.seen.missing', { names: seenMissing.join(', ') })}</p>
      {/if}
      {#if seen.length === 0}
        <p class="empty">{t('clients.seen.empty')}</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead><tr><th>{t('qw.explain.client')}</th><th>{t('flow.device')}</th><th>{t('nav.groups')}</th>{#if showAffinity}<th data-testid="affinity-head">{t('clients.col.servers')}<HelpButton id="affinity" /></th>{/if}<th class="num">{t('clients.col.queries')}</th><th></th></tr></thead>
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
                  <td class="num"><a href={href('/queries', { client: c.key })}>{t('legacy.queries')}</a> · <a href={href('/heatmap', { kind: 'client', key: c.key })}>{t('clients.link.when')}</a> · <button type="button" class="link small" onclick={() => openDevice(c.key, 'rhythm')} data-testid="open-rhythm">{t('clients.link.rhythm')}</button> · <button type="button" class="link small" onclick={() => openDevice(c.key, 'timeline')} data-testid="open-timeline">{t('clients.link.day')}</button></td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </section>
  {:else if tab === 'devices'}
    <section class="card">
      <h2>{t('clients.tab.devices')}</h2>
      {#if configured.length === 0}
        <p class="empty">{t('clients.devices.emptyLead')}<code>[[client]]</code>{t('clients.devices.emptyTail')}</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead><tr><th>{t('clients.col.name')}</th><th>{t('clients.col.recognizedBy')}</th><th>{t('nav.groups')}</th><th>{t('clients.col.definedIn')}</th><th></th></tr></thead>
            <tbody>
              {#each configured as c (c.name)}
                <tr>
                  <td><strong>{c.name}</strong><IdentityLine identity={c.identity} /></td>
                  <td class="mono small">{c.match.join(', ')}</td>
                  <td class="small">
                    <!-- REQ: FLT-005 — the groups that apply, and where they come from (ADR-050). -->
                    {#each c.effectiveGroups ?? [] as g (g)}<span class="group-chip" style:--gc={groupColor(g)}>{g}</span>{/each}
                    {#if (c.effectiveGroups ?? []).length === 0}
                      <span class="muted">{t('clients.devices.noGroup')}</span>
                    {:else if fromText[c.groupsFrom ?? '']}
                      <div class="muted">{fromText[c.groupsFrom ?? '']}</div>
                    {/if}
                  </td>
                  <td class="small">{c.source === 'api' ? t('localdns.source.ui') : t('rules.source.file')}</td>
                  <td class="num">
                    {#if c.source === 'api' && canEdit}
                      <button class="link small" onclick={() => remove(c.name)} aria-label={t('clients.forgetAria', { name: c.name })}>{t('clients.forget')}</button>
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
        <h2>{t('clients.workloads.title')}<HelpButton id="kubernetes-workloads" /></h2>
        <label class="small">
          {t('clients.workloads.namespace')}
          <select bind:value={namespace} aria-label={t('clients.workloads.namespace')} data-testid="workload-namespace">
            <option value="">{t('common.all')}</option>
            {#each namespaces as n (n)}<option value={n}>{n}</option>{/each}
          </select>
        </label>
      </div>
      <p class="muted small">
        {t('clients.workloads.introLead')}<code>telltaledns.io/group</code>{t('clients.workloads.introTail')}
      </p>
      <div class="table-wrap">
        <table>
          <thead
            ><tr
              ><th>{t('clients.col.workload')}</th><th>{t('legacy.group')}</th><th class="num">{t('clients.col.pods')}</th><th class="num" title={t('clients.col.last24h')}>{t('clients.col.queries')}</th><th class="num" title={t('clients.col.last24h')}>{t('clients.col.blocked')}</th><th>{t('clients.col.lastSeen')}</th><th></th></tr
            ></thead
          >
          <tbody>
            {#each shownWorkloads as w (w.name)}
              <tr data-testid="workload-row">
                <td class="mono nowrap" title={kindText[w.kind] ?? w.kind}><ClientChip ip={w.key} name={w.name} onchanged={load} /></td>
                <td class="small nowrap">
                  {#if w.group}<span class="group-chip" style:--gc={groupColor(w.group)}>{w.group}</span>{/if}
                  <div class="muted" data-testid="group-from">{groupFromLabel(w.groupFrom)}</div>
                </td>
                <td class="num" title={w.pods.map((p) => `${p.name} ${p.addresses.join(' ')}${p.terminating ? t('clients.workloads.terminating') : ''}`).join('\n')}>{w.pods.filter((p) => !p.terminating).length}</td>
                <td class="num">{num(w.queries24h)}</td>
                <td class="num">{num(w.blocked24h)}</td>
                <td class="small">{w.lastSeen ? ago(Date.parse(w.lastSeen) / 1000) : t('clients.workloads.notInLastDay')}</td>
                <td class="num nowrap"><a href={href('/queries', { client: w.name })}>{t('legacy.queries')}</a> · <button type="button" class="link" onclick={() => openDevice(w.key, 'timeline')}>{t('clients.link.day')}</button></td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </section>
  {:else}
    <section class="card" data-testid="discovered">
      <h2>{t('clients.discovered.title')}</h2>
      <p class="muted small">
        {t('clients.discovered.introLead')}<code>[[router]]</code>{t('clients.discovered.introMid')}<code>[clients] mdns</code>{t('clients.discovered.introTail')}
      </p>
      {#if found.length === 0}
        <p class="empty">{t('clients.discovered.emptyLead')}<strong>{t('clients.router.title')}</strong>{t('clients.discovered.emptyMid')}<code>[clients] mdns = true</code>{t('queries.whyEnd')}</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead><tr><th>{t('qw.explain.address')}</th><th>{t('clients.col.nameItGave')}</th><th>{t('clients.col.from')}</th><th>{t('qw.explain.mac')}</th><th>{t('clients.col.inTelltale')}</th></tr></thead>
            <tbody>
              {#each found as l (l.ip)}
                <tr>
                  <td class="mono"><ClientChip ip={l.ip} onchanged={load} /></td>
                  <td>{l.hostname ?? ''}</td>
                  <td><span class="badge info">{sourceText[l.source] ?? l.source}</span></td>
                  <td class="mono small">{l.mac}</td>
                  <td class="small">{#if named(l)}<strong>{l.clientName}</strong>{:else}<span class="muted">{t('clients.discovered.notNamed')}</span>{/if}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </section>
    <ConfigEditor kind="router" path="routers" title={t('clients.router.title')} noun={t('clients.router.noun')} fields={routerFields} role="admin"
      summary={(d) => `${String(d.type ?? '')} · ${String(d.url ?? '')}`}
      status={routerStatus} omit={routerFiles} notice={plainHttpNotice}
      onchanged={load} />
  {/if}
  </TabPanel>
  {#if rhythmFor}
    <Drawer title={workloadOf(rhythmFor)?.name ?? rhythmFor} onclose={closeDevice}>
      <div class="seg" role="group" aria-label={t('clients.device.view')}>
        <button type="button" aria-pressed={view === 'rhythm'} onclick={() => openDevice(rhythmFor, 'rhythm')} data-testid="device-rhythm">{t('clients.link.rhythm')}</button>
        <button type="button" aria-pressed={view === 'timeline'} onclick={() => openDevice(rhythmFor, 'timeline')} data-testid="device-timeline">{t('clients.device.timeline')}</button>
      </div>
      {#if view === 'timeline'}
        <p class="muted small">{t('clients.device.timelineIntro')}<HelpButton id="device-timeline" /></p>
        <DeviceTimeline client={rhythmFor} />
      {:else}
      <p class="muted small">{t('clients.device.rhythmIntro')}<HelpButton id="rhythm" /></p>
      <ErrorNote error={rhythmError} />
      {#if rhythm}
        {#if !rhythm.available}
          <p class="empty">{t('clients.device.anomalyOffLead')}<code>[telemetry.anomaly] enabled</code>{t('clients.device.anomalyOffTail')}</p>
        {:else}
          <RhythmStrip rows={rhythm.domains} client={rhythm.client} binsS={rhythm.binsS} />
          {#if rhythm.missingNodes?.length}<p class="muted small">{t('clients.device.notAnswering', { names: rhythm.missingNodes.join(', ') })}</p>{/if}
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
