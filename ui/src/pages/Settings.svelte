<script lang="ts">
  // REQ: API-003, API-005 — my account (password, two-factor), API tokens, users (admin),
  // and system information.
  import { api, type S } from '../lib/api';
  import { can, session, refreshSession } from '../lib/session.svelte';
  import { ago, dateTime, duration, num } from '../lib/format';
  import { poll } from '../lib/poll';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import ConfigEditor, { type Field } from '../lib/components/ConfigEditor.svelte';
  import Tabs, { activeTab, type TabItem } from '../lib/components/Tabs.svelte';
  import TabPanel from '../lib/components/TabPanel.svelte';
  import WallDisplays from '../lib/components/WallDisplays.svelte';
  import SupportPackage from '../lib/components/SupportPackage.svelte';
  import DomainIcon from '../lib/icons/DomainIcon.svelte';
  import { iconPrefs, setIconPrefs } from '../lib/icons/prefs.svelte';
  import DevPackStub from '../lib/devpack/DevPackStub.svelte';
  import { tr } from '../lib/i18n';
  import T from '../lib/i18n/T.svelte';
  const { t, tn } = tr('settings');

  // The words of the table rows below, read once here (never at module level, never per row).
  const words = {
    agent: t('agent'), never: t('never'), revoke: t('Revoke'),
    userAgent: t('agent'), userNever: t('never'), userRevoke: t('Revoke'),
    viewer: t('viewer'), operator: t('operator'), admin: t('admin'),
    on: t('on'), off: t('off'), reset: t('Reset'), you: t('(you)'),
    disabled: t('Disabled · enable'), active: t('Active · disable'), tokens: t('Tokens'), delete: t('Delete'), reallyDelete: t('Really delete?'),
    webUi: t('Web UI and API'), extraTarget: t('(extra target)'), skipped: t('skipped'), answers: t('answers'), notAnswering: t('not answering'), missedOnce: t('missed once'),
  };
  const selfSigned = t('self-signed certificate (doesn\'t expire)');

  // OBS-039 — what the Domain icons card previews: a brand, an ordinary name, a name of the network.
  const ICON_PREVIEW = ['www.netflix.com', 'cdn.example.org', 'nas.home.arpa'];

  const tabs = $derived<TabItem[]>(
    [
      { id: 'account', label: t('Account') },
      { id: 'tokens', label: t('API tokens') },
      ...(can('admin') ? [{ id: 'users', label: t('Users') }, { id: 'audit', label: t('Audit log') }] : []),
      { id: 'system', label: t('System') },
      // REQ: API-005 (ADR-121) — how queries are handled (cache, rate limit, what's kept out of
      // the log, simulation), apart from the node's own housekeeping.
      { id: 'queries', label: t('Query handling') },
      // REQ: CLU-013 — staged rollouts are an admin's.
      ...(can('admin') ? [{ id: 'cluster', label: t('Cluster') }] : []),
    ],
  );
  // REQ: DNS-014 (review 01 q1) — the fields of `[ratelimit]`.
  const rateLimitFields: Field[] = [
    { key: 'enabled', label: t('Limit queries per client'), type: 'bool', initial: true },
    { key: 'queries', label: t('Queries allowed per window'), type: 'number', placeholder: '1000',
      help: t('Per client; short bursts up to this are fine. A client over it gets the action below until its allowance refills.') },
    { key: 'window_secs', label: t('Window (seconds)'), type: 'number', placeholder: '60' },
    { key: 'action', label: t('When over the limit'), type: 'select', options: ['refused', 'drop'],
      help: t('refused answers REFUSED; drop answers nothing.') },
    { key: 'exempt', label: t('Never limited'), type: 'lines', placeholder: '127.0.0.0/8\n192.168.1.1/32',
      help: t('Addresses or networks, one per line (a router that forwards for the whole network, say). Replaces the list from the config file, so keep 127.0.0.0/8 and ::1/128.') },
    { key: 'ipv4_prefix', label: t('IPv4: count clients per /N'), type: 'number', advanced: true, placeholder: '32',
      help: t('32 counts each address on its own.') },
    { key: 'ipv6_prefix', label: t('IPv6: count clients per /N'), type: 'number', advanced: true, placeholder: '64',
      help: t('64 groups a device\'s rotating privacy addresses.') },
  ];
  // REQ: OBS-022 (T12.1) — the fields of `[exclusions]`.
  const exclusionFields: Field[] = [
    { key: 'enabled', label: t('Leave these out of the log and stats'), type: 'bool', initial: true,
      help: t('Off keeps the lists below but logs everything again.') },
    { key: 'names', label: t('Names'), type: 'lines', placeholder: t('connectivitycheck.gstatic.com\nntp.org', null, 'an example of two names, one per line'),
      help: t('One per line; each covers its subdomains too. Noise like connectivity checks, time servers, or a monitoring probe.') },
    { key: 'clients', label: t('Devices'), type: 'lines', placeholder: '192.168.1.10\n10.20.0.0/24',
      help: t('Addresses or networks, one per line (a monitoring host, say).') },
  ];
  // REQ: OBS-024 (T13.1) — the fields of `[simulate]`.
  const simulateFields: Field[] = [
    { key: 'enabled', label: t('Allow change simulations'), type: 'bool', initial: true,
      help: t('The "What would this have done?" button, the simulate parameter of dry runs, and simulate_change for agents.') },
    { key: 'plans_by_default', label: t("Agents' plans simulate by default"), type: 'bool', initial: false,
      help: t('Off: a plan simulates only when the agent asks (simulate: "24h"). On: every plan replays the query log, which costs CPU on each node.') },
    { key: 'default_window', label: t('Default window'), type: 'text', placeholder: '24h',
      help: t('How far back a simulation replays when no window is given: 30m, 24h, up to 7d.') },
    { key: 'max_secs', label: t('Time limit per node (seconds)'), type: 'number', placeholder: '20', advanced: true,
      help: t('1 to 300. A node that runs out of time answers with what it read so far (partial).') },
    { key: 'max_rows', label: t('Most logged queries read per node'), type: 'number', placeholder: '2000000', advanced: true,
      help: t('At least 1,000. Newest first.') },
  ];
  // REQ: CLU-013 (T13.2) — `[cluster.rollout]`: a canary picker over the cluster's nodes, sites,
  // and its resolver pods, the bake, and the guard.
  let clusterView = $state<S['ClusterView'] | null>(null);
  const rolloutFields = $derived.by((): Field[] => {
    const nodes = clusterView?.nodes ?? [];
    const fixed = nodes.filter((n) => !n.ephemeral && !n.witness && !n.role.includes('primary'));
    const sites = [...new Set(nodes.filter((n) => !n.witness).map((n) => n.site))].sort();
    const options = [...fixed.map((n) => n.nodeId), ...sites.map((s) => `site:${s}`), 'ephemeral'];
    const optionLabels: Record<string, string> = {
      ephemeral: t('resolver pods (Kubernetes)'),
      ...Object.fromEntries(fixed.map((n) => [n.nodeId, `${n.site} (${n.nodeId.slice(0, 8)})`])),
      ...Object.fromEntries(sites.map((s) => [`site:${s}`, t('every node at site {site}', { site: s })])),
    };
    return [
      { key: 'canaries', label: t('Canary nodes'), type: 'multi', options, optionLabels,
        help: t('They (and the primary) get each change first. None: changes reach every node at once.') },
      { key: 'bake_secs', label: t('Bake time (seconds)'), type: 'number', placeholder: '300',
        help: t('How long a change runs on the canaries before everyone gets it. At least 5.') },
      { key: 'servfail_pct', label: t('Fail above this SERVFAIL share (%)'), type: 'number', placeholder: '5',
        help: t("Or 2 points over the canaries' share before the change, whichever is higher; judged from 50 answers.") },
      { key: 'require_traffic', label: t('Wait for 50 answers before judging'), type: 'bool', advanced: true,
        help: t('Off: a quiet bake passes. On: keep baking until the canaries answered 50 queries (or the longest bake), then judge.') },
      { key: 'max_bake_secs', label: t('Longest bake (seconds)'), type: 'number', placeholder: '3600', advanced: true },
      { key: 'fail_on_disconnect', label: t('Fail when a canary disconnects for a minute'), type: 'bool', advanced: true, initial: true,
        help: t('It might have crashed on the change. A pod rescheduled mid-bake fails the rollout too; unpin to try again.') },
      { key: 'history', label: t('Versions kept for pinning'), type: 'number', placeholder: '20', advanced: true },
    ];
  });
  const rolloutNote = (v: Record<string, unknown>) => {
    const c = (v.canaries as string[] | undefined) ?? [];
    if (!c.length) return t('No canaries: a change reaches every node at once.');
    const named = c.map((x) => rolloutFields[0].optionLabels?.[x] ?? x).join(', ');
    const secs = Number(v.bake_secs ?? 300);
    return secs >= 120
      ? t('Changes reach {named} (and the primary) first, and the rest after {n} minutes if nothing fails.', { named, n: Math.round(secs / 60) })
      : t('Changes reach {named} (and the primary) first, and the rest after {n} s if nothing fails.', { named, n: secs });
  };
  const tab = $derived(activeTab(tabs));

  // ---- account
  let current = $state('');
  let next = $state('');
  let pwMsg = $state('');
  let pwError = $state<unknown>(null);
  async function changePassword(e: SubmitEvent) {
    e.preventDefault();
    pwError = null;
    pwMsg = '';
    try {
      await api.changePassword({ currentPassword: current, newPassword: next });
      current = next = '';
      pwMsg = t('Password changed. Your other sessions were signed out.');
    } catch (err) {
      pwError = err;
    }
  }

  let totp = $state<S['TotpSetup'] | null>(null);
  let totpCode = $state('');
  let recovery = $state<string[]>([]);
  let totpPassword = $state('');
  let totpError = $state<unknown>(null);
  async function startTotp() {
    totpError = null;
    try {
      totp = await api.totpSetup();
    } catch (err) {
      totpError = err;
    }
  }
  async function enableTotp(e: SubmitEvent) {
    e.preventDefault();
    totpError = null;
    try {
      recovery = (await api.totpEnable(totpCode)).codes;
      totp = null;
      totpCode = '';
      await refreshSession();
    } catch (err) {
      totpError = err;
    }
  }
  async function disableTotp(e: SubmitEvent) {
    e.preventDefault();
    totpError = null;
    try {
      await api.totpDisable(totpPassword);
      totpPassword = '';
      recovery = [];
      await refreshSession();
    } catch (err) {
      totpError = err;
    }
  }

  // ---- tokens
  let tokens = $state<S['TokenInfo'][]>([]);
  let tokenName = $state('');
  let tokenScope = $state<S['Scope']>('read');
  let tokenDays = $state('');
  // REQ: AGT-004 — agent tokens: scopes instead of a role, optional group, rate limit.
  let tokenKind = $state<'user' | 'agent'>('user');
  const agentScopes: [string, string][] = [
    ['analytics:read', t('Statistics, top lists, anomalies, explain')],
    ['querylog:read', t('The query log (who asked for what)')],
    ['config:read', t('Lists, groups, devices, names, upstreams')],
    ['config:write:clients', t('Name and regroup devices')],
    ['config:write:records', t('Change names on my network')],
    ['config:write:forwards', t('Send domains to other servers')],
    ['cluster:admin', t('Promote a node; staged rollouts and pins')],
    ['cluster:upgrade', t('Install newer TelltaleDNS versions on nodes')],
  ];
  let tokenScopes = $state<string[]>(['analytics:read', 'config:read']);
  let tokenGroup = $state('');
  let newToken = $state('');
  let tokenError = $state<unknown>(null);
  async function loadTokens() {
    try {
      tokens = (await api.tokens()).items;
    } catch (err) {
      tokenError = err;
    }
  }
  async function createToken(e: SubmitEvent) {
    e.preventDefault();
    tokenError = null;
    try {
      const made = await api.createToken(
        tokenKind === 'agent'
          ? {
              name: tokenName.trim(),
              kind: 'agent',
              scopes: tokenScopes,
              group: tokenGroup.trim() || undefined,
              expiresInDays: tokenDays ? Number(tokenDays) : undefined,
            }
          : {
              name: tokenName.trim(),
              scope: tokenScope,
              expiresInDays: tokenDays ? Number(tokenDays) : undefined,
            },
      );
      newToken = made.token;
      tokenName = '';
      await loadTokens();
    } catch (err) {
      tokenError = err;
    }
  }
  async function revoke(id: string) {
    tokenError = null;
    try {
      await api.deleteToken(id);
      await loadTokens();
    } catch (err) {
      tokenError = err;
    }
  }
  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // Clipboard needs HTTPS or localhost; the token stays visible to copy by hand.
    }
  }

  // ---- users (admin)
  let users = $state<S['UserInfo'][]>([]);
  let nu = $state({ username: '', password: '', role: 'viewer' as S['Role'], allowBasicApi: false });
  let userError = $state<unknown>(null);
  // REQ: API-004 (ADR-175) — where password sign-in is allowed, for an admin. An older server
  // doesn't send it: then there is nothing to show.
  let passwordLogin = $state<S['PasswordLogin'] | null>(null);
  async function loadUsers() {
    try {
      const list = await api.users();
      users = list.items;
      passwordLogin = list.passwordLogin ?? null;
    } catch (err) {
      userError = err;
    }
  }
  async function addUser(e: SubmitEvent) {
    e.preventDefault();
    userError = null;
    try {
      await api.createUser({ ...nu });
      nu = { username: '', password: '', role: 'viewer', allowBasicApi: false };
      await loadUsers();
    } catch (err) {
      userError = err;
    }
  }
  async function patchUser(u: S['UserInfo'], b: S['UpdateUser']) {
    userError = null;
    try {
      await api.updateUser(u.id, b);
      await loadUsers();
    } catch (err) {
      userError = err;
      await loadUsers();
    }
  }
  async function removeUser(u: S['UserInfo']) {
    if (!confirmDelete(u)) return;
    userError = null;
    try {
      await api.deleteUser(u.id);
      await loadUsers();
    } catch (err) {
      userError = err;
    }
  }
  // REQ: API-003 (review 06-06) — an admin sees and revokes another user's API tokens.
  let tokensOf = $state<number | null>(null);
  let userTokens = $state<S['TokenInfo'][]>([]);
  async function showTokens(u: S['UserInfo']) {
    userError = null;
    if (tokensOf === u.id) {
      tokensOf = null;
      return;
    }
    try {
      userTokens = (await api.userTokens(u.id)).items;
      tokensOf = u.id;
    } catch (err) {
      userError = err;
    }
  }
  async function revokeUserToken(u: S['UserInfo'], token: string) {
    userError = null;
    try {
      await api.revokeUserToken(u.id, token);
      userTokens = (await api.userTokens(u.id)).items;
    } catch (err) {
      userError = err;
    }
  }
  // Two-step delete without a modal dialog: the first click arms the button.
  let armed = $state<number | null>(null);
  function confirmDelete(u: S['UserInfo']): boolean {
    if (armed === u.id) {
      armed = null;
      return true;
    }
    armed = u.id;
    return false;
  }

  // ---- audit log (REQ: API-006)
  let audit = $state<S['AuditInfo'][]>([]);
  let auditCursor = $state<string | undefined>();
  let auditAction = $state('');
  let auditError = $state<unknown>(null);
  let verified = $state<S['AuditVerify'] | null>(null);
  async function loadAudit(more = false) {
    auditError = null;
    try {
      const page = await api.audit({ action: auditAction || undefined, cursor: more ? auditCursor : undefined, limit: 100 });
      audit = more ? [...audit, ...page.items] : page.items;
      auditCursor = page.nextCursor ?? undefined;
    } catch (err) {
      auditError = err;
    }
  }
  async function verifyAudit() {
    auditError = null;
    try {
      verified = await api.auditVerify();
    } catch (err) {
      auditError = err;
    }
  }
  function summary(e: S['AuditInfo']): string {
    const d = (e.detail ?? {}) as Record<string, unknown>;
    return Object.entries(d)
      .filter(([, v]) => v !== null && v !== undefined)
      .map(([k, v]) => {
        if (v && typeof v === 'object' && 'from' in v && 'to' in v) {
          const c = v as { from: unknown; to: unknown };
          return `${k}: ${String(c.from)} → ${String(c.to)}`;
        }
        return `${k}: ${Array.isArray(v) ? v.join(', ') : typeof v === 'object' ? JSON.stringify(v) : String(v)}`;
      })
      .join(' · ');
  }

  // ---- system
  let info = $state<S['SystemInfo'] | null>(null);
  // REQ: OBS-033 — the last 200 change markers (every node's), filterable: the table view of
  // every chart's markers.
  let changeList = $state<S['AnnotationPage'] | null>(null);
  let changeKind = $state('');
  let changeText = $state('');
  let changeError = $state<unknown>(null);
  async function loadChanges() {
    try {
      changeList = await api.annotations({ from: '-90d', limit: 200, kinds: changeKind || undefined });
      changeError = null;
    } catch (e) {
      changeError = e;
    }
  }
  $effect(() => {
    void changeKind;
    if (tab === 'system') return poll(loadChanges, 30_000);
  });
  const shownChanges = $derived(
    (changeList?.items ?? []).filter((a) => {
      const q = changeText.trim().toLowerCase();
      return !q || `${a.summary} ${a.actor ?? ''} ${a.node ?? ''}`.toLowerCase().includes(q);
    }),
  );
  // REQ: OBS-020 — every node's listener probes, refreshed while the tab is open.
  let probes = $state<S['ProbeResult'][] | null>(null);
  async function loadProbes() {
    try {
      probes = (await api.probes()).items;
    } catch {
      probes = [];
    }
  }

  $effect(() => {
    if (tab === 'tokens') void loadTokens();
    if (tab === 'users' && can('admin')) void loadUsers();
    if (tab === 'audit' && can('admin')) void loadAudit();
    if (tab === 'system') api.info().then((i) => (info = i)).catch(() => {});
    if (tab === 'cluster') api.cluster().then((v) => (clusterView = v)).catch(() => {});
  });
  $effect(() => {
    if (tab === 'system') return poll(loadProbes, 10_000);
  });
  const certText = (p: S['ProbeResult']) =>
    p.certDaysLeft == null
      ? (p.certError ?? '')
      : p.certSelfSigned && p.certDaysLeft > 36_500
        ? selfSigned
        : p.certDaysLeft < 0
          ? t('certificate expired {n} day(s) ago', { n: -p.certDaysLeft })
          : t('certificate expires in {n} day(s)', { n: p.certDaysLeft });

  // REQ: OPS-004 — check the release index now instead of at the daily check.
  let checking = $state(false);
  let checkError = $state<unknown>(null);
  async function checkNow() {
    if (!info) return;
    checking = true;
    checkError = null;
    try {
      info.update = await api.checkUpdates();
    } catch (e) {
      checkError = e;
    } finally {
      checking = false;
    }
  }
</script>

{#snippet strong(x: string)}<strong>{x}</strong>{/snippet}
{#snippet strongdata(x: string)}<strong translate="no">{x}</strong>{/snippet}
{#snippet mono(x: string)}<code class="mono" translate="no">{x}</code>{/snippet}
{#snippet monospan(x: string)}<span class="mono" translate="no">{x}</span>{/snippet}
{#snippet code(x: string)}<code translate="no">{x}</code>{/snippet}
{#snippet app(x: string)}<a href={totp?.otpauthUrl}>{x}</a>{/snippet}
{#snippet guide(x: string)}<a href="https://github.com/paimonsoror/telltaledns/blob/main/docs/running.md#users-and-sign-in" target="_blank" rel="noreferrer">{x}</a>{/snippet}
{#snippet cachepage(x: string)}<a href="#/cache">{x}</a>{/snippet}
{#snippet authheader()}<code translate="no">Authorization: Bearer &lt;token&gt;</code>{/snippet}
{#snippet agentname()}<code translate="no">agent:&lt;name&gt;</code>{/snippet}
{#snippet agentsoff()}<code translate="no">[agents] enabled = false</code>{/snippet}
{#snippet singleaddr()}<code translate="no">192.168.1.10/32</code>{/snippet}
{#snippet loopbackaddr()}<code translate="no">127.0.0.1/32</code>{/snippet}
{#snippet trustedproxies()}<code translate="no">trusted_proxies</code>{/snippet}
{#snippet apisection()}<code translate="no">[api]</code>{/snippet}
{#snippet adminnets()}<code translate="no">allowed_admin_networks</code>{/snippet}
{#snippet authoidc()}<code translate="no">[auth.oidc]</code>{/snippet}
{#snippet openapi()}<a href="/api/v1/openapi.json" target="_blank" rel="noreferrer" translate="no">/api/v1/openapi.json</a>{/snippet}
{#snippet probesoff()}<code translate="no">[probe] enabled = false</code>{/snippet}
{#snippet apitls()}<code translate="no">[api] tls</code>{/snippet}
{#snippet updatescheck()}<code translate="no">[updates] check = false</code>{/snippet}
{#snippet restorecmd()}<code translate="no">telltale backup restore FILE</code>{/snippet}
{#snippet createcmd()}<code translate="no">telltale backup create --include-qlog</code>{/snippet}
{#snippet metrics()}<code translate="no">/metrics</code>{/snippet}

<div class="page">
  <h1>{t('Settings')}</h1>
  <Tabs {tabs} active={tab} label={t('Settings')} />

  <TabPanel active={tab}>
  {#if tab === 'account' && session.user}
    <div class="grid-2">
      <section class="card">
        <h2>{t('Account')}<HelpButton id="account" /></h2>
        <p><strong translate="no">{session.user.username}</strong> · <span class="badge" translate="no">{session.user.role}</span></p>
        <form class="stack" onsubmit={changePassword}>
          <h3>{t('Change password')}</h3>
          <label class="field">{t('Current password')}
            <input type="password" autocomplete="current-password" required bind:value={current} />
          </label>
          <label class="field">{t('New password (at least 10 characters)')}
            <input type="password" autocomplete="new-password" minlength="10" required bind:value={next} />
          </label>
          <ErrorNote error={pwError} />
          {#if pwMsg}<div class="notice ok">{pwMsg}</div>{/if}
          <div><button class="primary" type="submit">{t('Change password')}</button></div>
        </form>
      </section>

      <section class="card stack-card">
        <h2>{t('Two-factor sign-in')}<HelpButton id="two-factor" /></h2>
        <ErrorNote error={totpError} />
        {#if recovery.length}
          <div class="notice warn">
            <T ctx="settings" msg={"<strong>Save these recovery codes now.</strong> Each works once if you lose your phone; they won't be shown again."} {strong} />
            <ul class="codes mono" translate="no">{#each recovery as c (c)}<li>{c}</li>{/each}</ul>
          </div>
        {/if}
        {#if session.user.totpEnabled}
          <p><span class="badge ok">{t('on')}</span> {t('{n} recovery codes left.', { n: session.user.recoveryCodesLeft })}</p>
          <form class="stack" onsubmit={disableTotp}>
            <label class="field">{t('Password, to turn it off')}
              <input type="password" autocomplete="current-password" required bind:value={totpPassword} />
            </label>
            <div><button class="danger" type="submit">{t('Turn off two-factor')}</button></div>
          </form>
        {:else if totp}
          <ol class="steps">
            <li><T ctx="settings" msg={'Add this account to an authenticator app: on a phone, <app>open it in the app</app>, or enter the key by hand:'} {app} />
              <div class="mono key" translate="no">{totp.secretBase32.replace(/(.{4})/g, '$1 ').trim()}</div>
            </li>
            <li>{t('Enter the 6-digit code it shows.')}</li>
          </ol>
          <!-- REQ: API-003 (issue #64) — in a quoted attribute Svelte reads `{6}` as an expression, so the pattern is one. -->
          <form class="row" onsubmit={enableTotp}>
            <input aria-label={t('6-digit code')} title={t('6 digits')} inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern={'[0-9]{6}'} required placeholder="123456" bind:value={totpCode} />
            <button class="primary" type="submit">{t('Turn on')}</button>
            <button type="button" onclick={() => (totp = null)}>{t('Cancel')}</button>
          </form>
        {:else}
          <p class="muted">{t('Ask for a code from an authenticator app when signing in, on top of the password.')}</p>
          <div><button onclick={startTotp}>{t('Set up two-factor sign-in')}</button></div>
        {/if}
      </section>

      <!-- REQ: OBS-039 (ADR-167) — how this browser draws the mark left of a domain name. -->
      <section class="card stack-card" data-testid="icons-card">
        <h2>{t('Domain icons')}<HelpButton id="domain-icons" /></h2>
        <p class="muted">
          {t('The small mark left of a domain name in the dashboard\'s lists and the query log. It\'s drawn from what TelltaleDNS already knows, so nothing about your queries is sent to anyone. Remembered for you in this browser.')}
        </p>
        <div class="icon-row">
          <span class="icon-lbl" id="icons-style-lbl">{t('Style')}</span>
          <span class="seg small" role="group" aria-labelledby="icons-style-lbl">
            <button aria-pressed={iconPrefs.style === 'brand'} onclick={() => setIconPrefs({ style: 'brand' })}>{t('Brand and monogram')}</button>
            <button aria-pressed={iconPrefs.style === 'mono'} onclick={() => setIconPrefs({ style: 'mono' })}>{t('Monogram only')}</button>
            <button aria-pressed={iconPrefs.style === 'off'} onclick={() => setIconPrefs({ style: 'off' })}>{t('Off')}</button>
          </span>
        </div>
        <div class="icon-row">
          <span class="icon-lbl" id="icons-size-lbl">{t('Size')}</span>
          <span class="seg small" role="group" aria-labelledby="icons-size-lbl">
            <button aria-pressed={iconPrefs.size === 'default'} disabled={iconPrefs.style === 'off'} onclick={() => setIconPrefs({ size: 'default' })}>{t('Default')}</button>
            <button aria-pressed={iconPrefs.size === 'small'} disabled={iconPrefs.style === 'off'} onclick={() => setIconPrefs({ size: 'small' })}>{t('Small')}</button>
          </span>
        </div>
        <ul class="icon-preview" aria-label={t('Preview')}>
          {#each ICON_PREVIEW as n (n)}
            <li><DomainIcon name={n} /><span class="mono small" translate="no">{n}</span></li>
          {/each}
        </ul>
      </section>
      <!-- REQ: API-013 (ADR-190) — test a language pack (Advanced view, or while one is in this browser). -->
      <DevPackStub />
    </div>
  {:else if tab === 'tokens'}
    <section class="card">
      <h2>{t('API tokens')}<HelpButton id="api-tokens" /></h2>
      <p class="muted">
        <T ctx="settings" msg={'For scripts, dashboards, and AI agents: send <authheader/>. A token never has more rights than you.'} {authheader} />
      </p>
      <form class="row" onsubmit={createToken}>
        <input aria-label={t('Token name')} required placeholder={t('name, e.g. grafana')} bind:value={tokenName} />
        <select aria-label={t('Kind')} bind:value={tokenKind}>
          <option value="user">{t('for my scripts')}</option>
          <option value="agent">{t('for an AI agent')}</option>
        </select>
        {#if tokenKind === 'user'}
          <select aria-label={t('Scope')} bind:value={tokenScope}>
            <option value="read">{t('read (viewer)')}</option>
            <option value="write">{t('write (operator)')}</option>
            <option value="admin">{t('admin')}</option>
          </select>
        {/if}
        <select aria-label={t('Expires')} bind:value={tokenDays}>
          <option value="">{t('never expires')}</option>
          <option value="7">{t('7 days')}</option>
          <option value="30">{t('30 days')}</option>
          <option value="90">{t('90 days')}</option>
          <option value="365">{t('1 year')}</option>
        </select>
        <HelpButton id="token-scope" />
        <button class="primary" type="submit">{t('Create token')}</button>
      </form>
      {#if tokenKind === 'agent'}
        <fieldset class="agent-scopes">
          <legend>{t('What the agent may do')}<HelpButton id="agent-tokens" /></legend>
          {#each agentScopes as [id, label] (id)}
            <label><input type="checkbox" value={id} bind:group={tokenScopes} /> {label} <code class="small" translate="no">{id}</code></label>
          {/each}
          <label>{t('Only this group\'s devices and queries (optional):')}
            <input aria-label={t('Group')} placeholder={t('e.g. kids')} bind:value={tokenGroup} /></label>
          <p class="muted small">
            <T ctx="settings" msg={'Agents must give a reason for every change, are limited to 120 requests a minute, show as <agentname/> in the audit log, and stop at once with <agentsoff/>.'} {agentname} {agentsoff} />
          </p>
        </fieldset>
      {/if}
      <ErrorNote error={tokenError} />
      {#if newToken}
        <div class="notice ok new-token">
          <strong>{t('Copy the token now; it won\'t be shown again.')}</strong>
          <div class="row"><code class="token" translate="no">{newToken}</code><button onclick={() => copy(newToken)}>{t('Copy')}</button><button class="link" onclick={() => (newToken = '')}>{t('Done')}</button></div>
        </div>
      {/if}
      {#if tokens.length === 0}
        <p class="empty">{t('No tokens yet.')}</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead><tr><th>{t('Name')}</th><th>{t('Scope')}</th><th>{t('Created')}</th><th>{t('Last used')}</th><th>{t('Expires')}</th><th></th></tr></thead>
            <tbody>
              {#each tokens as tok (tok.id)}
                <tr>
                  <td><strong translate="no">{tok.name}</strong><div class="muted small mono" translate="no">tt_{tok.id}_…</div></td>
                  <td>
                    {#if tok.kind === 'agent'}
                      <span class="badge">{words.agent}</span>
                      <div class="muted small"><span translate="no">{(tok.scopes ?? []).join(', ')}</span>{tok.group ? ` ${t('· group {group}', { group: tok.group })}` : ''}</div>
                    {:else}
                      <span class="badge" translate="no">{tok.scope}</span>
                    {/if}
                  </td>
                  <td class="small">{ago(tok.createdUnixSeconds)}</td>
                  <td class="small">{ago(tok.lastUsedUnixSeconds)}</td>
                  <td class="small">{tok.expiresUnixSeconds ? dateTime(tok.expiresUnixSeconds) : words.never}</td>
                  <td class="num"><button class="danger" onclick={() => revoke(tok.id)}>{words.revoke}</button></td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </section>
  {:else if tab === 'users' && can('admin')}
    <!-- REQ: API-004 (ADR-175) — where password sign-in is allowed, when `disable_local_login` limits it. -->
    {#if passwordLogin?.restricted}
      <section class="card" data-testid="password-sign-in">
        <h2>{t('Password sign-in')}</h2>
        {#if passwordLogin.networks.length}
          <p>{t('Password sign-in is limited to admins on these networks:')}</p>
          <ul class="nets mono" translate="no">
            <!-- Not keyed on `n`: allowed_admin_networks may repeat an entry, and Svelte throws on a duplicate key. -->
            {#each passwordLogin.networks as n}<li>{n}</li>{/each}
          </ul>
          {#if passwordLogin.coversWholeNetworks}
            <p class="small"><span class="badge warn">{t('Includes whole networks')}</span> <T ctx="settings" msg={'Anyone on these networks is still shown the sign-in form, not just the machines you name. To limit it to the machines you manage from, list each as a single address, such as <singleaddr/>.'} {singleaddr} /></p>
          {:else}
            <p class="muted small">{t('Only the machines listed are shown the sign-in form.')}</p>
            {#if passwordLogin.includesLoopback && !passwordLogin.loopbackIsTrustedProxy}
              <p class="muted small"><T ctx="settings" msg={'If a reverse proxy on this machine serves this page, add <loopbackaddr/> to <trustedproxies/> under <apisection/>. Until then everyone it serves looks like this machine and can use a password.'} {loopbackaddr} {trustedproxies} {apisection} /></p>
            {/if}
          {/if}
        {:else}
          <p>{t('Password sign-in is limited to admins on no network, so if your sign-in provider is down, nobody can sign in with a password.')}</p>
        {/if}
        <p class="muted small"><T ctx="settings" msg={'Change it with <adminnets/> under <authoidc/> in the configuration file, then restart. See <guide>Users and sign-in</guide> in the guide.'} {adminnets} {authoidc} {guide} /></p>
      </section>
    {/if}
    <section class="card">
      <h2>{t('Users')}<HelpButton id="users" /></h2>
      <ErrorNote error={userError} />
      <div class="table-wrap">
        <table>
          <thead><tr><th>{t('User')}</th><th>{t('Role')}</th><th>{t('Two-factor')}</th><th>{t('HTTP Basic')}</th><th>{t('Status')}</th><th></th></tr></thead>
          <tbody>
            {#each users as u (u.id)}
              <tr>
                <td>
                  <strong translate="no">{u.username}</strong>{#if u.id === session.user?.id} <span class="muted small">{words.you}</span>{/if}
                  {#if u.oidcProvider}<div class="muted small">{t('signs in with {provider}', { provider: u.oidcProvider })}</div>{/if}
                </td>
                <td>
                  <select aria-label={t('Role of {name}', { name: u.username })} value={u.role} onchange={(e) => patchUser(u, { role: e.currentTarget.value as S['Role'] })}>
                    <option value="viewer">{words.viewer}</option>
                    <option value="operator">{words.operator}</option>
                    <option value="admin">{words.admin}</option>
                  </select>
                </td>
                <td>
                  {#if u.totpEnabled}<span class="badge ok">{words.on}</span> <button class="link small" onclick={() => patchUser(u, { resetTotp: true })}>{words.reset}</button>{:else}<span class="muted">{words.off}</span>{/if}
                </td>
                <td><input type="checkbox" role="switch" aria-label={t('HTTP Basic for {name}', { name: u.username })} checked={u.allowBasicApi} onchange={(e) => patchUser(u, { allowBasicApi: e.currentTarget.checked })} /></td>
                <td>
                  <button class="link" onclick={() => patchUser(u, { disabled: !u.disabled })}>{u.disabled ? words.disabled : words.active}</button>
                </td>
                <td class="num">
                  <button class="link" aria-expanded={tokensOf === u.id} onclick={() => showTokens(u)}>{words.tokens}</button>
                  {#if u.id !== session.user?.id}
                    <button class="danger" onclick={() => removeUser(u)}>{armed === u.id ? words.reallyDelete : words.delete}</button>
                  {/if}
                </td>
              </tr>
              {#if tokensOf === u.id}
                <tr class="user-tokens">
                  <td colspan="6">
                    {#if userTokens.length === 0}
                      <span class="muted small">{t('{name} has no API tokens.', { name: u.username })}</span>
                    {:else}
                      <table>
                        <thead><tr><th>{t('{name}\'s token', { name: u.username })}</th><th>{t('Scope')}</th><th>{t('Last used')}</th><th>{t('Expires')}</th><th></th></tr></thead>
                        <tbody>
                          {#each userTokens as tok (tok.id)}
                            <tr>
                              <td><strong translate="no">{tok.name}</strong><div class="muted small mono" translate="no">tt_{tok.id}_…</div></td>
                              <td>{#if tok.kind === 'agent'}<span class="badge">{words.userAgent}</span>{:else}<span class="badge" translate="no">{tok.scope}</span>{/if}</td>
                              <td class="small">{ago(tok.lastUsedUnixSeconds)}</td>
                              <td class="small">{tok.expiresUnixSeconds ? dateTime(tok.expiresUnixSeconds) : words.userNever}</td>
                              <td class="num"><button class="danger" onclick={() => revokeUserToken(u, tok.id)}>{words.userRevoke}</button></td>
                            </tr>
                          {/each}
                        </tbody>
                      </table>
                    {/if}
                  </td>
                </tr>
              {/if}
            {/each}
          </tbody>
        </table>
      </div>
      <form class="stack add-user" onsubmit={addUser}>
        <h3>{t('Add a user')}</h3>
        <div class="row">
          <input aria-label={t('Username')} required placeholder={t('username')} autocomplete="off" bind:value={nu.username} />
          <input aria-label={t('Password')} required type="password" minlength="10" placeholder={t('password (10+ characters)')} autocomplete="new-password" bind:value={nu.password} />
          <select aria-label={t('Role')} bind:value={nu.role}>
            <option value="viewer">{t('viewer')}</option>
            <option value="operator">{t('operator')}</option>
            <option value="admin">{t('admin')}</option>
          </select>
          <label class="switch small"><input type="checkbox" role="switch" bind:checked={nu.allowBasicApi} />{t('HTTP Basic')}</label><HelpButton id="http-basic" />
          <button class="primary" type="submit">{t('Add')}</button>
        </div>
        <p class="muted small">{t('Viewers see dashboards and the query log; operators can also pause blocking and manage lists, clients, and groups; admins can do everything.')}</p>
      </form>
    </section>
    <!-- REQ: OBS-035 (T14.13) — wall displays. -->
    <WallDisplays />
  {:else if tab === 'audit' && can('admin')}
    <section class="card">
      <div class="card-head">
        <h2>{t('Audit log')}<HelpButton id="audit-log" /></h2>
        <div class="row">
          <span class="pill-field bare">
            <select aria-label={t('Action')} bind:value={auditAction} onchange={() => loadAudit()}>
              <option value="">{t('All changes')}</option>
              <option value="user.">{t('Users')}</option>
              <option value="token.">{t('API tokens')}</option>
              <option value="auth.">{t('Sign-ins and lockouts')}</option>
              <option value="config.">{t('Configuration')}</option>
            </select>
          </span>
          <button onclick={verifyAudit}>{t('Verify chain')}</button>
        </div>
      </div>
      <p class="muted small">
        {t('Every change to users, passwords, two-factor sign-in, and API tokens, plus sign-ins, lockouts, and configuration reloads. Entries can\'t be edited, and each one is chained to the one before it, so tampering is detectable.')}
      </p>
      {#if verified}
        <div class="notice {verified.ok ? 'ok' : 'bad'} verify-result" role="status">
          {#if verified.ok}
            <T ctx="settings" msg={'Chain intact: {entries} entries. Head <mono>{hash}…</mono>'} params={{ entries: verified.entries, hash: verified.headHash.slice(0, 16) }} {mono} />
          {:else}
            <T ctx="settings" msg={'<strong>Chain broken at entry {seq}</strong>: the log was changed outside TelltaleDNS.'} params={{ seq: verified.firstBadSeq }} {strong} />
          {/if}
        </div>
      {/if}
      <ErrorNote error={auditError} />
      {#if audit.length === 0}
        <p class="empty">{t('No entries.')}</p>
      {:else}
        <div class="table-wrap">
          <table class="audit">
            <thead><tr><th class="num">#</th><th>{t('When')}</th><th>{t('Who')}</th><th>{t('What')}</th><th>{t('Details')}</th></tr></thead>
            <tbody>
              {#each audit as e (e.seq)}
                <tr>
                  <td class="num muted">{e.seq}</td>
                  <td class="small nowrap" title={e.time}>{dateTime(e.tsUnixSeconds)}</td>
                  <td translate="no">
                    {e.actor} <span class="badge">{e.actorKind}</span>
                    {#if e.remote}<div class="muted small mono">{e.remote}</div>{/if}
                  </td>
                  <td translate="no"><code>{e.action}</code><div class="small">{e.target}</div></td>
                  <td class="small">
                    <span translate="no">{summary(e)}</span>
                    {#if e.reason}<div class="muted">{t('Reason: {reason}', { reason: e.reason })}</div>{/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
        {#if auditCursor}
          <div class="row foot"><span class="spacer"></span><button onclick={() => loadAudit(true)}>{t('Older')}</button></div>
        {/if}
      {/if}
    </section>
  {:else if tab === 'cluster' && can('admin')}
    {#if clusterView && !clusterView.enabled}
      <section class="card"><p class="empty">{t('This node runs on its own: staged rollouts need a cluster (see the Cluster page).')}</p></section>
    {:else}
      <!-- REQ: CLU-013 (T13.2) — staged rollouts: who gets a change first, and the guard. -->
      <ConfigEditor kind="rollout" path="cluster/rollout-settings" singleton role="admin" title={t('Staged rollouts')} noun={t('rollout settings')}
        fields={rolloutFields} help="rollouts" note={rolloutNote}
        summary={(d) => {
          const c = Array.isArray(d.canaries) ? (d.canaries as string[]) : [];
          return c.length
            ? tn('{n} canary entry; bake {secs} s', '{n} canary entries; bake {secs} s', c.length, { n: c.length, secs: String(d.bake_secs ?? 300) })
            : t('off: changes reach every node at once');
        }} />
      <p class="muted small">
        {t('A change to these settings reaches every node at once (it\'s never staged itself). The Cluster page shows the version baking, the guard\'s readings, and the versions you can pin back to.')}
      </p>
    {/if}
  {:else if tab === 'system'}
    <section class="card">
      <h2>{t('System')}<HelpButton id="system" /></h2>
      {#if info}
        <dl class="sys">
          <dt>{t('Version')}</dt><dd translate="no">{info.version}</dd>
          <dt>{t('Node')}</dt><dd translate="no">{info.node} ({info.role})</dd>
          <dt>{t('Started')}</dt><dd>{t('{since} · up {uptime}', { since: dateTime(Date.parse(info.startedAt) / 1000), uptime: duration(info.uptimeSeconds) })}</dd>
          <!-- REQ: OBS-002 (T9.13) -->
          {#if info.starts > 1}
            <dt>{t('Restarts')}</dt><dd data-testid="restarts">{info.starts - 1}{#if info.uncleanStarts}{t('({n} after a crash or a kill)', { n: info.uncleanStarts })}{/if}</dd>
          {/if}
          <dt>{t('DNS listeners')}</dt><dd class="mono" translate="no">{info.listeners.join(', ')}</dd>
          <dt>{t('Query log')}</dt><dd>{info.queryLog ? t('on') : t('off')}</dd>
          <dt>{t('Filter snapshot')}</dt><dd>{info.filterSnapshot != null ? t('{snapshot} · {n} names', { snapshot: info.filterSnapshot, n: num(info.filterNames) }) : t('none yet · {n} names', { n: num(info.filterNames) })}</dd>
        </dl>
      {/if}
      <p class="muted small"><T ctx="settings" msg={'API reference: <openapi/> (OpenAPI 3.1).'} {openapi} /></p>
    </section>
    <!-- REQ: OBS-020 (ADR-107) — can clients reach each listener? -->
    <section class="card" data-testid="probes">
      <h2>{t('Listener checks')}<HelpButton id="probes" /></h2>
      {#if probes == null}
        <p class="empty">{t('Loading…')}</p>
      {:else if probes.length === 0}
        <p class="empty"><T ctx="settings" msg={'No results yet (the first round runs a few seconds after start), or probes are off (<probesoff/>).'} {probesoff} /></p>
      {:else}
        <div class="table-wrap">
          <table class="compact">
            <thead><tr>{#if probes.some((p) => p.node)}<th>{t('Node')}</th>{/if}<th>{t('Asked')}</th><th>{t('Result')}</th><th class="num">{t('Time')}</th><th>{t('Notes')}</th></tr></thead>
            <tbody>
              {#each probes as p, i (i)}
                <tr>
                  {#if probes.some((x) => x.node)}<td translate="no">{p.node ?? ''}</td>{/if}
                  <td>{#if p.proto === 'api'}<div class="web-ui">{words.webUi}</div>{/if}<span class="mono" translate="no">{p.target}</span>{#if !p.listener}<span class="muted small"> {words.extraTarget}</span>{/if}</td>
                  <td>
                    {#if p.skipped}<span class="badge">{words.skipped}</span>
                    {:else if p.ok}<span class="badge ok">{words.answers}</span>
                    {:else if p.consecutiveFailures >= 2}<span class="badge bad">{words.notAnswering}</span>
                    {:else}<span class="badge warn">{words.missedOnce}</span>{/if}
                  </td>
                  <td class="num">{p.latencyMs != null ? t('{ms} ms', { ms: p.latencyMs.toFixed(1) }) : '–'}</td>
                  <td class="small">
                    <span translate="no">{p.skipped ?? p.error ?? ''}</span>
                    {#if certText(p)}<span class:cert-soon={(p.certDaysLeft ?? 99) < 14}>{certText(p)}</span>{/if}
                    <!-- REQ: API-003 (ADR-149) — what the certificate covers, and its fingerprint to compare with the browser's. -->
                    {#if p.certNames?.length}<div class="muted" data-testid="cert-names">{t('for {names}', { names: p.certNames.join(', ') })}</div>{/if}
                    {#if p.certSha256}<div class="muted fingerprint" data-testid="cert-sha256"><T ctx="settings" msg={'SHA-256 <mono>{sha}</mono>'} params={{ sha: p.certSha256 }} mono={monospan} /></div>{/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
      <p class="muted small"><T ctx="settings" msg={"Every 30 s each node asks each of its listeners a question through the listener's own protocol, the way a device would. With HTTPS on the web UI (<apitls/>), it's checked too: compare its SHA-256 fingerprint with the one your browser shows before trusting a self-signed certificate."} {apitls} /></p>
    </section>
    <section class="card" data-testid="changes-list">
      <h2>{t('Changes')}<HelpButton id="change-markers" /></h2>
      <div class="change-filters">
        <label class="pill-field">
          {t('Kind')}
          <select bind:value={changeKind} aria-label={t('Kind of change')}>
            <option value="">{t('every kind')}</option>
            <option value="config.applied">{t('configuration applied')}</option>
            <option value="note">{t('notes')}</option>
            <option value="lists.refreshed">{t('list refreshes')}</option>
            <option value="rollout.stage">{t('rollouts')}</option>
            <option value="build.started,node.restarted">{t('builds and restarts')}</option>
            <option value="maintenance.entered,maintenance.left">{t('maintenance')}</option>
            <option value="blocking.paused,blocking.resumed">{t('pauses')}</option>
            <option value="cache.flushed">{t('cache flushes')}</option>
            <option value="upstream.breaker">{t('upstreams benched or recovered')}</option>
          </select>
        </label>
        <input class="small" type="search" placeholder={t('Filter')} bind:value={changeText} aria-label={t('Filter changes')} />
      </div>
      <ErrorNote error={changeError} />
      {#if changeList == null}
        <p class="empty">{t('Loading…')}</p>
      {:else if shownChanges.length === 0}
        <p class="empty">{changeKind || changeText ? t('No changes recorded that match in the last 90 days.') : t('No changes recorded in the last 90 days.')}</p>
      {:else}
        <div class="table-wrap">
          <table class="compact">
            <thead><tr><th>{t('When')}</th>{#if shownChanges.some((a) => a.node)}<th>{t('Node')}</th>{/if}<th>{t('What')}</th><th>{t('Who')}</th></tr></thead>
            <tbody>
              {#each shownChanges as a, i (i)}
                <tr>
                  <td class="nowrap">{dateTime(a.tUnixMs / 1000)}</td>
                  {#if shownChanges.some((x) => x.node)}<td translate="no">{a.node ?? ''}</td>{/if}
                  <td translate="no">{#if a.href}<a href={a.href}>{a.summary}</a>{:else}{a.summary}{/if}</td>
                  <td class="small" translate="no">{a.actor ?? a.source ?? ''}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
      {#if changeList?.missingNodes?.length}<p class="muted small">{t('Not answering: {nodes}.', { nodes: changeList.missingNodes.join(', ') })}</p>{/if}
      <p class="muted small">{t('The last 200 configuration versions, builds, restarts, list refreshes, rollouts, maintenance, pauses, cache flushes, upstreams benched or recovered, and notes, from every node. Each node keeps 90 days.')}</p>
    </section>
    {#if info}
      <!-- REQ: OPS-004 (ADR-046) -->
      <section class="card" data-testid="updates">
        <h2>{t('Version and updates')}<HelpButton id="updates" /></h2>
        <dl class="sys">
          <dt>{t('This build')}</dt><dd><T ctx="settings" msg={'<strong>{version}</strong> · commit <code>{commit}</code> · {channel} channel'} params={{ version: info.build.version, commit: info.build.commit, channel: info.build.channel }} strong={strongdata} {code} /></dd>
          <dt>{t('Built')}</dt><dd>{t('{date} · {target} · {install} install', { date: info.build.date, target: info.build.target, install: info.build.install })}</dd>
          <dt>{t('Status')}</dt>
          <dd>
            {#if info.update.state === 'available'}
              <span class="badge warn">{t('Update available')}</span> <span translate="no">{info.update.latest}{info.update.latestDate ? ` (${info.update.latestDate})` : ''}</span>
              {#if info.update.notesUrl}<a href={info.update.notesUrl} target="_blank" rel="noreferrer">{t("What's new")}</a>{/if}
            {:else if info.update.state === 'up_to_date'}
              {t('Up to date')}
            {:else if info.update.state === 'newer'}
              {info.update.latest ? t('Newer than the published {channel} build ({version})', { channel: info.build.channel, version: info.update.latest }) : t('Newer than the published {channel} build', { channel: info.build.channel })}
            {:else if info.update.state === 'off'}
              <T ctx="settings" msg={'Not checked (<updatescheck/>)'} {updatescheck} />
            {:else}
              {info.update.error ? t('Not known yet: {error}', { error: info.update.error }) : t('Not known yet')}
            {/if}
            <div class="muted small">
              {#if info.update.checkedUnixSeconds}{t('Checked {when}', { when: ago(info.update.checkedUnixSeconds) })}{/if}
              {#if can('admin') && info.update.state !== 'off'}
                <button class="link small" disabled={checking} onclick={checkNow} data-testid="check-updates"
                  >{checking ? t('Checking…') : t('Check now')}</button
                >
              {/if}
            </div>
            <ErrorNote error={checkError} />
          </dd>
        </dl>
        <p class="small" translate="no">{info.update.how}</p>
      </section>
    {/if}
    {#if can('admin')}
      <!-- REQ: API-007 (T6.7) -->
      <section class="card">
        <h2>{t('Backup')}<HelpButton id="backup" /></h2>
        <p>
          <T ctx="settings" msg={'One file with your settings, users and API tokens, the devices and names you added here, the audit log, and statistics history. Restore it on a new machine with <restorecmd/>.'} {restorecmd} />
        </p>
        <p><a class="button" href="/api/v1/backup" download>{t('Download a backup')}</a></p>
        <p class="muted small">
          <T ctx="settings" msg={"It holds password hashes, so keep it private. The query log isn't included; for that, run <createcmd/> on the server."} {createcmd} />
        </p>
      </section>
      <!-- REQ: OPS-011 (ADR-156) — one redacted file for a bug report. -->
      <SupportPackage />
    {/if}
  {:else if tab === 'queries'}
    <!-- REQ: DNS-006 (T6.15) — the cache has its own page now. -->
    <section class="card">
      <h2>{t('Cache')}</h2>
      <p class="small"><T ctx="settings" msg={"Hit rates, what's cached, settings, lookups, and flushing are on the <cachepage>Cache page</cachepage>."} {cachepage} /></p>
    </section>
    <!-- REQ: DNS-014 (review 01 q1) — the per-client rate limit, adjustable here and in the config file. -->
    <ConfigEditor kind="ratelimit" path="ratelimit" singleton title={t('Rate limit')} noun={t('rate limit')} fields={rateLimitFields}
      summary={(d) => (d.enabled === false ? t('off') : t('{queries} queries per {secs} s per client, then {action}', { queries: String(d.queries), secs: String(d.window_secs), action: String(d.action) }))} />
    <p class="muted small">
      {t('One client is one address (IPv6: one /64). A router or proxy that forwards for a whole network looks like one client: add it to "Never limited", or raise the number. A change applies at once and every client\'s count starts over.')}
    </p>
    <!-- REQ: OBS-022 (T12.1) — names and devices kept out of the query log and analytics. -->
    <ConfigEditor kind="exclusions" path="exclusions" singleton title={t('Kept out of the log')} noun={t('exclusions')} fields={exclusionFields}
      summary={(d) => {
        const n = (k: string) => (Array.isArray(d[k]) ? (d[k] as unknown[]).length : 0);
        if (n('names') + n('clients') === 0) return t('nothing excluded');
        return d.enabled === false
          ? t('off: {names} names, {devices} devices', { names: n('names'), devices: n('clients') })
          : t('{names} names, {devices} devices', { names: n('names'), devices: n('clients') });
      }} />
    <p class="muted small">
      <T ctx="settings" msg={'Their queries are still answered and still counted in <metrics/>, but left out of the query log, the live view, the dashboard and top lists, anomalies, and exports, on every node. Queries logged before stay.'} {metrics} /><HelpButton id="exclusions" />
    </p>
    <!-- REQ: OBS-024 (T13.1) — change simulation's switches and bounds. -->
    <ConfigEditor kind="simulate" path="simulate-settings" singleton title={t('Change simulation')} noun={t('simulation settings')} fields={simulateFields}
      help="simulate"
      summary={(d) =>
        d.enabled === false
          ? t('off')
          : d.plans_by_default
            ? t("on, {window} by default; agents' plans always simulate", { window: String(d.default_window ?? '24h') })
            : t("on, {window} by default; agents' plans simulate when asked", { window: String(d.default_window ?? '24h') })} />
    <p class="muted small">
      {t('A simulation replays the query log with and without a change and shows what would have been answered differently. It never touches DNS answers and runs at background priority; at query-log privacy level 1 or above names can\'t be replayed.')}
    </p>
  {/if}
  </TabPanel>
</div>

<style>
  .nets {
    margin: 6px 0 10px;
    padding-left: 22px;
  }
  .icon-row {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px 14px;
    margin: 10px 0;
  }
  .icon-lbl {
    width: 3.2em;
    color: var(--muted);
  }
  .icon-preview {
    list-style: none;
    margin: 14px 0 0;
    padding: 0;
    display: grid;
    gap: 8px;
  }
  .icon-preview li {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .change-filters {
    display: flex;
    flex-wrap: wrap;
    gap: 8px 12px;
    align-items: center;
    margin-bottom: 8px;
  }
  .cert-soon {
    color: var(--warn);
    font-weight: 600;
  }
  .web-ui {
    font-weight: 600;
  }
  .fingerprint .mono {
    font-size: 11px;
    overflow-wrap: anywhere;
  }
  .agent-scopes {
    display: grid;
    gap: 0.35rem;
    margin: 0.75rem 0;
    border: 1px solid var(--border, #ddd);
    border-radius: 8px;
    padding: 0.75rem 1rem;
  }
  .stack-card {
    display: grid;
    gap: 10px;
    align-content: start;
  }
  .codes {
    columns: 2;
    margin: 8px 0 0;
    padding-left: 18px;
  }
  .steps {
    margin: 0;
    padding-left: 18px;
    display: grid;
    gap: 6px;
  }
  .key {
    margin-top: 4px;
    font-size: 15px;
    letter-spacing: 0.04em;
    word-break: break-all;
  }
  .token {
    word-break: break-all;
    flex: 1 1 260px;
    background: var(--surface-2);
    padding: 6px 8px;
    border-radius: 6px;
  }
  .new-token {
    margin: 10px 0;
    display: grid;
    gap: 6px;
  }
  form.row {
    margin: 10px 0;
  }
  .add-user {
    margin-top: 16px;
  }
  .verify-result {
    margin: 8px 0;
  }
  .nowrap {
    white-space: nowrap;
  }
  .foot {
    margin-top: 10px;
  }
  .sys {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 6px 16px;
    margin: 0 0 10px;
  }
  .sys dt {
    color: var(--muted);
  }
  .sys dd {
    margin: 0;
    word-break: break-all;
  }
</style>
