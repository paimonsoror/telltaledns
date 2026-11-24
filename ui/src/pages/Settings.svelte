<script lang="ts">
  // REQ: API-003, API-005 — my account (password, two-factor), API tokens, users (admin),
  // and system information.
  import { api, type S } from '../lib/api';
  import { can, session, refreshSession } from '../lib/session.svelte';
  import { ago, dateTime, duration } from '../lib/format';
  import { poll } from '../lib/poll';
  // REQ: API-011 — `t` is already taken here (a token, and the rows of both token tables), so the
  // catalog comes in as `tr`.
  import { t as tr, tn, type MessageKey } from '../lib/i18n';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import ConfigEditor, { type Field } from '../lib/components/ConfigEditor.svelte';
  import Tabs, { activeTab, type TabItem } from '../lib/components/Tabs.svelte';
  import TabPanel from '../lib/components/TabPanel.svelte';
  import WallDisplays from '../lib/components/WallDisplays.svelte';
  import SupportPackage from '../lib/components/SupportPackage.svelte';
  import DomainIcon from '../lib/icons/DomainIcon.svelte';
  import { iconPrefs, setIconPrefs } from '../lib/icons/prefs.svelte';

  // OBS-039 — what the Domain icons card previews: a brand, an ordinary name, a name of the network.
  const ICON_PREVIEW = ['www.netflix.com', 'cdn.example.org', 'nas.home.arpa'];

  const tabs = $derived<TabItem[]>(
    [
      { id: 'account', label: tr('settings.tab.account') },
      { id: 'tokens', label: tr('settings.tab.tokens') },
      ...(can('admin')
        ? [{ id: 'users', label: tr('settings.tab.users') }, { id: 'audit', label: tr('settings.tab.audit') }]
        : []),
      { id: 'system', label: tr('settings.tab.system') },
      // REQ: API-005 (ADR-121) — how queries are handled (cache, rate limit, what's kept out of
      // the log, simulation), apart from the node's own housekeeping.
      { id: 'queries', label: tr('settings.tab.queries') },
      // REQ: CLU-013 — staged rollouts are an admin's.
      ...(can('admin') ? [{ id: 'cluster', label: tr('settings.tab.cluster') }] : []),
    ],
  );
  // REQ: DNS-014 (review 01 q1) — the fields of `[ratelimit]`. A getter: the labels follow the
  // language on screen.
  const rateLimitFields = $derived.by((): Field[] => [
    { key: 'enabled', label: tr('settings.queries.ratelimit.enabled'), type: 'bool', initial: true },
    { key: 'queries', label: tr('settings.queries.ratelimit.queries'), type: 'number', placeholder: '1000',
      help: tr('settings.queries.ratelimit.queriesHelp') },
    { key: 'window_secs', label: tr('settings.queries.ratelimit.window'), type: 'number', placeholder: '60' },
    { key: 'action', label: tr('settings.queries.ratelimit.action'), type: 'select', options: ['refused', 'drop'],
      help: tr('settings.queries.ratelimit.actionHelp') },
    { key: 'exempt', label: tr('settings.queries.ratelimit.exempt'), type: 'lines', placeholder: '127.0.0.0/8\n192.168.1.1/32',
      help: tr('settings.queries.ratelimit.exemptHelp') },
    { key: 'ipv4_prefix', label: tr('settings.queries.ratelimit.ipv4'), type: 'number', advanced: true, placeholder: '32',
      help: tr('settings.queries.ratelimit.ipv4Help') },
    { key: 'ipv6_prefix', label: tr('settings.queries.ratelimit.ipv6'), type: 'number', advanced: true, placeholder: '64',
      help: tr('settings.queries.ratelimit.ipv6Help') },
  ]);
  // REQ: OBS-022 (T12.1) — the fields of `[exclusions]`.
  const exclusionFields = $derived.by((): Field[] => [
    { key: 'enabled', label: tr('settings.queries.exclusions.enabled'), type: 'bool', initial: true,
      help: tr('settings.queries.exclusions.enabledHelp') },
    { key: 'names', label: tr('settings.queries.exclusions.names'), type: 'lines', placeholder: 'connectivitycheck.gstatic.com\nntp.org',
      help: tr('settings.queries.exclusions.namesHelp') },
    { key: 'clients', label: tr('settings.queries.exclusions.clients'), type: 'lines', placeholder: '192.168.1.10\n10.20.0.0/24',
      help: tr('settings.queries.exclusions.clientsHelp') },
  ]);
  // REQ: OBS-024 (T13.1) — the fields of `[simulate]`.
  const simulateFields = $derived.by((): Field[] => [
    { key: 'enabled', label: tr('settings.queries.simulate.enabled'), type: 'bool', initial: true,
      help: tr('settings.queries.simulate.enabledHelp') },
    { key: 'plans_by_default', label: tr('settings.queries.simulate.plans'), type: 'bool', initial: false,
      help: tr('settings.queries.simulate.plansHelp') },
    { key: 'default_window', label: tr('settings.queries.simulate.window'), type: 'text', placeholder: '24h',
      help: tr('settings.queries.simulate.windowHelp') },
    { key: 'max_secs', label: tr('settings.queries.simulate.maxSecs'), type: 'number', placeholder: '20', advanced: true,
      help: tr('settings.queries.simulate.maxSecsHelp') },
    { key: 'max_rows', label: tr('settings.queries.simulate.maxRows'), type: 'number', placeholder: '2000000', advanced: true,
      help: tr('settings.queries.simulate.maxRowsHelp') },
  ]);
  // REQ: CLU-013 (T13.2) — `[cluster.rollout]`: a canary picker over the cluster's nodes, sites,
  // and its resolver pods, the bake, and the guard.
  let clusterView = $state<S['ClusterView'] | null>(null);
  const rolloutFields = $derived.by((): Field[] => {
    const nodes = clusterView?.nodes ?? [];
    const fixed = nodes.filter((n) => !n.ephemeral && !n.witness && !n.role.includes('primary'));
    const sites = [...new Set(nodes.filter((n) => !n.witness).map((n) => n.site))].sort();
    const options = [...fixed.map((n) => n.nodeId), ...sites.map((s) => `site:${s}`), 'ephemeral'];
    const optionLabels: Record<string, string> = {
      ephemeral: tr('settings.cluster.rollout.ephemeral'),
      ...Object.fromEntries(fixed.map((n) => [n.nodeId, `${n.site} (${n.nodeId.slice(0, 8)})`])),
      ...Object.fromEntries(sites.map((s) => [`site:${s}`, tr('settings.cluster.rollout.site', { site: s })])),
    };
    return [
      { key: 'canaries', label: tr('settings.cluster.rollout.canaries'), type: 'multi', options, optionLabels,
        help: tr('settings.cluster.rollout.canariesHelp') },
      { key: 'bake_secs', label: tr('settings.cluster.rollout.bakeTime'), type: 'number', placeholder: '300',
        help: tr('settings.cluster.rollout.bakeTimeHelp') },
      { key: 'servfail_pct', label: tr('settings.cluster.rollout.servfail'), type: 'number', placeholder: '5',
        help: tr('settings.cluster.rollout.servfailHelp') },
      { key: 'require_traffic', label: tr('settings.cluster.rollout.requireTraffic'), type: 'bool', advanced: true,
        help: tr('settings.cluster.rollout.requireTrafficHelp') },
      { key: 'max_bake_secs', label: tr('settings.cluster.rollout.maxBake'), type: 'number', placeholder: '3600', advanced: true },
      { key: 'fail_on_disconnect', label: tr('settings.cluster.rollout.failOnDisconnect'), type: 'bool', advanced: true, initial: true,
        help: tr('settings.cluster.rollout.failOnDisconnectHelp') },
      { key: 'history', label: tr('settings.cluster.rollout.history'), type: 'number', placeholder: '20', advanced: true },
    ];
  });
  const rolloutNote = (v: Record<string, unknown>) => {
    const c = (v.canaries as string[] | undefined) ?? [];
    if (!c.length) return tr('settings.cluster.rollout.noteNone');
    const named = c.map((x) => rolloutFields[0].optionLabels?.[x] ?? x).join(', ');
    const secs = Number(v.bake_secs ?? 300);
    const time = secs >= 120 ? tn('settings.cluster.rollout.minutes', Math.round(secs / 60)) : tr('settings.cluster.rollout.seconds', { n: secs });
    return tr('settings.cluster.rollout.noteBody', { names: named, time });
  };
  const tab = $derived(activeTab(tabs));
  // A role in the reader's language; a value this build doesn't know stays as the server sent it.
  const roleName = (role: string) =>
    role === 'admin' || role === 'operator' || role === 'viewer' ? tr(`common.role.${role}` as MessageKey) : role;
  // A node's part in a cluster: the same words the sidebar uses.
  const nodeRole = (role: string) => (role === 'primary' ? tr('nav.primary') : role === 'replica' ? tr('nav.replica') : role);

  // ---- account
  let current = $state('');
  let next = $state('');
  // A flag, not a sentence: the notice is translated when it is drawn, so it follows the language.
  let pwChanged = $state(false);
  let pwError = $state<unknown>(null);
  async function changePassword(e: SubmitEvent) {
    e.preventDefault();
    pwError = null;
    pwChanged = false;
    try {
      await api.changePassword({ currentPassword: current, newPassword: next });
      current = next = '';
      pwChanged = true;
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
  let tokenKind = $state<'user' | 'agent'>('user');
  // REQ: AGT-004 — agent tokens: scopes instead of a role, optional group, rate limit. The
  // identifier in each pair is what the API is sent; only the sentence beside it is translated.
  const agentScopes = $derived.by((): [string, string][] => [
    ['analytics:read', tr('settings.tokens.scope.analytics')],
    ['querylog:read', tr('settings.tokens.scope.querylog')],
    ['config:read', tr('settings.tokens.scope.configRead')],
    ['config:write:clients', tr('settings.tokens.scope.clients')],
    ['config:write:records', tr('settings.tokens.scope.records')],
    ['config:write:forwards', tr('settings.tokens.scope.forwards')],
    ['cluster:admin', tr('settings.tokens.scope.clusterAdmin')],
    ['cluster:upgrade', tr('settings.tokens.scope.upgrade')],
  ]);
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
      const t = await api.createToken(
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
      newToken = t.token;
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
        ? tr('settings.probes.certSelfSigned')
        : p.certDaysLeft < 0
          ? tr('settings.probes.certExpired', { n: -p.certDaysLeft })
          : tr('settings.probes.certExpires', { n: p.certDaysLeft });

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

<div class="page">
  <h1>{tr('settings.title')}</h1>
  <Tabs {tabs} active={tab} label={tr('settings.title')} />

  <TabPanel active={tab}>
  {#if tab === 'account' && session.user}
    <div class="grid-2">
      <section class="card">
        <h2>{tr('settings.account.title')}<HelpButton id="account" /></h2>
        <p><strong>{session.user.username}</strong> · <span class="badge">{roleName(session.user.role)}</span></p>
        <form class="stack" onsubmit={changePassword}>
          <h3>{tr('settings.account.changePassword')}</h3>
          <label class="field">{tr('settings.account.currentPassword')}
            <input type="password" autocomplete="current-password" required bind:value={current} />
          </label>
          <label class="field">{tr('settings.account.newPassword')}
            <input type="password" autocomplete="new-password" minlength="10" required bind:value={next} />
          </label>
          <ErrorNote error={pwError} />
          {#if pwChanged}<div class="notice ok">{tr('settings.account.passwordChanged')}</div>{/if}
          <div><button class="primary" type="submit">{tr('settings.account.changePassword')}</button></div>
        </form>
      </section>

      <section class="card stack-card">
        <h2>{tr('settings.twoFactor.title')}<HelpButton id="two-factor" /></h2>
        <ErrorNote error={totpError} />
        {#if recovery.length}
          <div class="notice warn">
            <strong>{tr('settings.twoFactor.saveCodes')}</strong> {tr('settings.twoFactor.saveCodesNote')}
            <ul class="codes mono">{#each recovery as c (c)}<li>{c}</li>{/each}</ul>
          </div>
        {/if}
        {#if session.user.totpEnabled}
          <p><span class="badge ok">{tr('settings.value.on')}</span> {tr('settings.twoFactor.codesLeft', { n: session.user.recoveryCodesLeft })}</p>
          <form class="stack" onsubmit={disableTotp}>
            <label class="field">{tr('settings.twoFactor.offPassword')}
              <input type="password" autocomplete="current-password" required bind:value={totpPassword} />
            </label>
            <div><button class="danger" type="submit">{tr('settings.twoFactor.turnOff')}</button></div>
          </form>
        {:else if totp}
          <ol class="steps">
            <li>{tr('settings.twoFactor.stepOneLead')} <a href={totp.otpauthUrl}>{tr('settings.twoFactor.stepOneLink')}</a>{tr('settings.twoFactor.stepOneTail')}
              <div class="mono key">{totp.secretBase32.replace(/(.{4})/g, '$1 ').trim()}</div>
            </li>
            <li>{tr('settings.twoFactor.stepTwo')}</li>
          </ol>
          <!-- REQ: API-003 (issue #64) — in a quoted attribute Svelte reads `{6}` as an expression, so the pattern is one. -->
          <form class="row" onsubmit={enableTotp}>
            <input aria-label={tr('settings.twoFactor.codeLabel')} title={tr('settings.twoFactor.codeTitle')} inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern={'[0-9]{6}'} required placeholder="123456" bind:value={totpCode} />
            <button class="primary" type="submit">{tr('settings.twoFactor.turnOn')}</button>
            <button type="button" onclick={() => (totp = null)}>{tr('common.cancel')}</button>
          </form>
        {:else}
          <p class="muted">{tr('settings.twoFactor.about')}</p>
          <div><button onclick={startTotp}>{tr('settings.twoFactor.setup')}</button></div>
        {/if}
      </section>

      <!-- REQ: OBS-039 (ADR-167) — how this browser draws the mark left of a domain name. -->
      <section class="card stack-card" data-testid="icons-card">
        <h2>{tr('settings.icons.title')}<HelpButton id="domain-icons" /></h2>
        <p class="muted">
          {tr('settings.icons.about')}
        </p>
        <div class="icon-row">
          <span class="icon-lbl" id="icons-style-lbl">{tr('settings.icons.style')}</span>
          <span class="seg small" role="group" aria-labelledby="icons-style-lbl">
            <button aria-pressed={iconPrefs.style === 'brand'} onclick={() => setIconPrefs({ style: 'brand' })}>{tr('settings.icons.brand')}</button>
            <button aria-pressed={iconPrefs.style === 'mono'} onclick={() => setIconPrefs({ style: 'mono' })}>{tr('settings.icons.mono')}</button>
            <button aria-pressed={iconPrefs.style === 'off'} onclick={() => setIconPrefs({ style: 'off' })}>{tr('settings.icons.off')}</button>
          </span>
        </div>
        <div class="icon-row">
          <span class="icon-lbl" id="icons-size-lbl">{tr('settings.icons.size')}</span>
          <span class="seg small" role="group" aria-labelledby="icons-size-lbl">
            <button aria-pressed={iconPrefs.size === 'default'} disabled={iconPrefs.style === 'off'} onclick={() => setIconPrefs({ size: 'default' })}>{tr('settings.icons.default')}</button>
            <button aria-pressed={iconPrefs.size === 'small'} disabled={iconPrefs.style === 'off'} onclick={() => setIconPrefs({ size: 'small' })}>{tr('settings.icons.small')}</button>
          </span>
        </div>
        <ul class="icon-preview" aria-label={tr('settings.icons.preview')}>
          {#each ICON_PREVIEW as n (n)}
            <li><DomainIcon name={n} /><span class="mono small">{n}</span></li>
          {/each}
        </ul>
      </section>
    </div>
  {:else if tab === 'tokens'}
    <section class="card">
      <h2>{tr('settings.tokens.title')}<HelpButton id="api-tokens" /></h2>
      <p class="muted">
        {tr('settings.tokens.aboutLead')} <code>Authorization: Bearer &lt;token&gt;</code>{tr('settings.tokens.aboutTail')}
      </p>
      <form class="row" onsubmit={createToken}>
        <input aria-label={tr('settings.tokens.nameLabel')} required placeholder={tr('settings.tokens.namePlaceholder')} bind:value={tokenName} />
        <select aria-label={tr('settings.tokens.kindLabel')} bind:value={tokenKind}>
          <option value="user">{tr('settings.tokens.kindUser')}</option>
          <option value="agent">{tr('settings.tokens.kindAgent')}</option>
        </select>
        {#if tokenKind === 'user'}
          <select aria-label={tr('settings.tokens.scopeLabel')} bind:value={tokenScope}>
            <option value="read">{tr('settings.tokens.scopeRead')}</option>
            <option value="write">{tr('settings.tokens.scopeWrite')}</option>
            <option value="admin">{tr('settings.tokens.scopeAdmin')}</option>
          </select>
        {/if}
        <select aria-label={tr('settings.tokens.expiresLabel')} bind:value={tokenDays}>
          <option value="">{tr('settings.tokens.expiresNever')}</option>
          <option value="7">{tr('settings.tokens.expires7')}</option>
          <option value="30">{tr('settings.tokens.expires30')}</option>
          <option value="90">{tr('settings.tokens.expires90')}</option>
          <option value="365">{tr('settings.tokens.expiresYear')}</option>
        </select>
        <HelpButton id="token-scope" />
        <button class="primary" type="submit">{tr('settings.tokens.create')}</button>
      </form>
      {#if tokenKind === 'agent'}
        <fieldset class="agent-scopes">
          <legend>{tr('settings.tokens.agentLegend')}<HelpButton id="agent-tokens" /></legend>
          {#each agentScopes as [id, label] (id)}
            <label><input type="checkbox" value={id} bind:group={tokenScopes} /> {label} <code class="small">{id}</code></label>
          {/each}
          <label>{tr('settings.tokens.groupOnly')}
            <input aria-label={tr('settings.tokens.groupLabel')} placeholder={tr('settings.tokens.groupPlaceholder')} bind:value={tokenGroup} /></label>
          <p class="muted small">
            {tr('settings.tokens.agentNoteLead')}
            <code>agent:&lt;name&gt;</code> {tr('settings.tokens.agentNoteMid')} <code>[agents] enabled = false</code>{tr('settings.tokens.agentNoteTail')}
          </p>
        </fieldset>
      {/if}
      <ErrorNote error={tokenError} />
      {#if newToken}
        <div class="notice ok new-token">
          <strong>{tr('settings.tokens.copyNow')}</strong>
          <div class="row"><code class="token">{newToken}</code><button onclick={() => copy(newToken)}>{tr('common.copy')}</button><button class="link" onclick={() => (newToken = '')}>{tr('settings.tokens.done')}</button></div>
        </div>
      {/if}
      {#if tokens.length === 0}
        <p class="empty">{tr('settings.tokens.empty')}</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead><tr><th>{tr('settings.tokens.colName')}</th><th>{tr('settings.tokens.colScope')}</th><th>{tr('settings.tokens.colCreated')}</th><th>{tr('settings.tokens.colLastUsed')}</th><th>{tr('settings.tokens.colExpires')}</th><th></th></tr></thead>
            <tbody>
              {#each tokens as t (t.id)}
                <tr>
                  <td><strong>{t.name}</strong><div class="muted small mono">tt_{t.id}_…</div></td>
                  <td>
                    {#if t.kind === 'agent'}
                      <span class="badge">agent</span>
                      <div class="muted small">{(t.scopes ?? []).join(', ')}{t.group ? tr('settings.tokens.groupSuffix', { group: t.group }) : ''}</div>
                    {:else}
                      <span class="badge">{t.scope}</span>
                    {/if}
                  </td>
                  <td class="small">{ago(t.createdUnixSeconds)}</td>
                  <td class="small">{ago(t.lastUsedUnixSeconds)}</td>
                  <td class="small">{t.expiresUnixSeconds ? dateTime(t.expiresUnixSeconds) : tr('common.never')}</td>
                  <td class="num"><button class="danger" onclick={() => revoke(t.id)}>{tr('settings.tokens.revoke')}</button></td>
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
        <h2>{tr('settings.users.passwordSignIn')}</h2>
        {#if passwordLogin.networks.length}
          <p>{tr('settings.users.limitedTo')}</p>
          <ul class="nets mono">
            <!-- Not keyed on `n`: allowed_admin_networks may repeat an entry, and Svelte throws on a duplicate key. -->
            {#each passwordLogin.networks as n}<li>{n}</li>{/each}
          </ul>
          {#if passwordLogin.coversWholeNetworks}
            <p class="small"><span class="badge warn">{tr('settings.users.wholeNetworks')}</span> {tr('settings.users.wholeNetworksLead')} <code>192.168.1.10/32</code>{tr('settings.users.wholeNetworksTail')}</p>
          {:else}
            <p class="muted small">{tr('settings.users.onlyListed')}</p>
            {#if passwordLogin.includesLoopback && !passwordLogin.loopbackIsTrustedProxy}
              <p class="muted small">{tr('settings.users.loopbackLead')} <code>127.0.0.1/32</code> {tr('settings.users.loopbackMid')} <code>trusted_proxies</code> {tr('settings.users.loopbackMid2')} <code>[api]</code>{tr('settings.users.loopbackTail')}</p>
            {/if}
          {/if}
        {:else}
          <p>{tr('settings.users.noNetworks')}</p>
        {/if}
        <p class="muted small">{tr('settings.users.changeLead')} <code>allowed_admin_networks</code> {tr('settings.users.changeMid')} <code>[auth.oidc]</code>{tr('settings.users.changeMid2')} <a href="https://github.com/paimonsoror/telltaledns/blob/main/docs/running.md#users-and-sign-in" target="_blank" rel="noreferrer">{tr('settings.users.changeLink')}</a> {tr('settings.users.changeTail')}</p>
      </section>
    {/if}
    <section class="card">
      <h2>{tr('settings.users.title')}<HelpButton id="users" /></h2>
      <ErrorNote error={userError} />
      <div class="table-wrap">
        <table>
          <thead><tr><th>{tr('settings.users.colUser')}</th><th>{tr('settings.users.colRole')}</th><th>{tr('settings.users.colTwoFactor')}</th><th>{tr('settings.users.colBasic')}</th><th>{tr('settings.users.colStatus')}</th><th></th></tr></thead>
          <tbody>
            {#each users as u (u.id)}
              <tr>
                <td>
                  <strong>{u.username}</strong>{#if u.id === session.user?.id} <span class="muted small">{tr('settings.users.you')}</span>{/if}
                  {#if u.oidcProvider}<div class="muted small">{tr('settings.users.signsInWith', { provider: u.oidcProvider })}</div>{/if}
                </td>
                <td>
                  <select aria-label={tr('settings.users.roleOf', { name: u.username })} value={u.role} onchange={(e) => patchUser(u, { role: e.currentTarget.value as S['Role'] })}>
                    <option value="viewer">{tr('common.role.viewer')}</option>
                    <option value="operator">{tr('common.role.operator')}</option>
                    <option value="admin">{tr('common.role.admin')}</option>
                  </select>
                </td>
                <td>
                  {#if u.totpEnabled}<span class="badge ok">{tr('settings.value.on')}</span> <button class="link small" onclick={() => patchUser(u, { resetTotp: true })}>{tr('settings.users.reset')}</button>{:else}<span class="muted">{tr('settings.value.off')}</span>{/if}
                </td>
                <td><input type="checkbox" role="switch" aria-label={tr('settings.users.basicFor', { name: u.username })} checked={u.allowBasicApi} onchange={(e) => patchUser(u, { allowBasicApi: e.currentTarget.checked })} /></td>
                <td>
                  <button class="link" onclick={() => patchUser(u, { disabled: !u.disabled })}>{u.disabled ? tr('settings.users.disabledEnable') : tr('settings.users.activeDisable')}</button>
                </td>
                <td class="num">
                  <button class="link" aria-expanded={tokensOf === u.id} onclick={() => showTokens(u)}>{tr('settings.users.tokens')}</button>
                  {#if u.id !== session.user?.id}
                    <button class="danger" onclick={() => removeUser(u)}>{armed === u.id ? tr('settings.users.reallyDelete') : tr('settings.users.delete')}</button>
                  {/if}
                </td>
              </tr>
              {#if tokensOf === u.id}
                <tr class="user-tokens">
                  <td colspan="6">
                    {#if userTokens.length === 0}
                      <span class="muted small">{tr('settings.users.noTokens', { name: u.username })}</span>
                    {:else}
                      <table>
                        <thead><tr><th>{tr('settings.users.tokenOf', { name: u.username })}</th><th>{tr('settings.tokens.colScope')}</th><th>{tr('settings.tokens.colLastUsed')}</th><th>{tr('settings.tokens.colExpires')}</th><th></th></tr></thead>
                        <tbody>
                          {#each userTokens as t (t.id)}
                            <tr>
                              <td><strong>{t.name}</strong><div class="muted small mono">tt_{t.id}_…</div></td>
                              <td>{#if t.kind === 'agent'}<span class="badge">agent</span>{:else}<span class="badge">{t.scope}</span>{/if}</td>
                              <td class="small">{ago(t.lastUsedUnixSeconds)}</td>
                              <td class="small">{t.expiresUnixSeconds ? dateTime(t.expiresUnixSeconds) : tr('common.never')}</td>
                              <td class="num"><button class="danger" onclick={() => revokeUserToken(u, t.id)}>{tr('settings.tokens.revoke')}</button></td>
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
        <h3>{tr('settings.users.addTitle')}</h3>
        <div class="row">
          <input aria-label={tr('settings.users.usernameLabel')} required placeholder={tr('settings.users.usernamePlaceholder')} autocomplete="off" bind:value={nu.username} />
          <input aria-label={tr('settings.users.passwordLabel')} required type="password" minlength="10" placeholder={tr('settings.users.passwordPlaceholder')} autocomplete="new-password" bind:value={nu.password} />
          <select aria-label={tr('settings.users.roleLabel')} bind:value={nu.role}>
            <option value="viewer">{tr('common.role.viewer')}</option>
            <option value="operator">{tr('common.role.operator')}</option>
            <option value="admin">{tr('common.role.admin')}</option>
          </select>
          <label class="switch small"><input type="checkbox" role="switch" bind:checked={nu.allowBasicApi} />{tr('settings.users.colBasic')}</label><HelpButton id="http-basic" />
          <button class="primary" type="submit">{tr('settings.users.add')}</button>
        </div>
        <p class="muted small">{tr('settings.users.rolesNote')}</p>
      </form>
    </section>
    <!-- REQ: OBS-035 (T14.13) — wall displays. -->
    <WallDisplays />
  {:else if tab === 'audit' && can('admin')}
    <section class="card">
      <div class="card-head">
        <h2>{tr('settings.audit.title')}<HelpButton id="audit-log" /></h2>
        <div class="row">
          <span class="pill-field bare">
            <select aria-label={tr('settings.audit.actionLabel')} bind:value={auditAction} onchange={() => loadAudit()}>
              <option value="">{tr('settings.audit.allChanges')}</option>
              <option value="user.">{tr('settings.audit.users')}</option>
              <option value="token.">{tr('settings.audit.tokens')}</option>
              <option value="auth.">{tr('settings.audit.signIns')}</option>
              <option value="config.">{tr('settings.audit.config')}</option>
            </select>
          </span>
          <button onclick={verifyAudit}>{tr('settings.audit.verify')}</button>
        </div>
      </div>
      <p class="muted small">
        {tr('settings.audit.about')}
      </p>
      {#if verified}
        <div class="notice {verified.ok ? 'ok' : 'bad'} verify-result" role="status">
          {#if verified.ok}
            {tr('settings.audit.intact', { n: verified.entries })} <code class="mono">{verified.headHash.slice(0, 16)}…</code>
          {:else}
            <strong>{tr('settings.audit.broken', { n: String(verified.firstBadSeq ?? '–') })}</strong>{tr('settings.audit.brokenTail')}
          {/if}
        </div>
      {/if}
      <ErrorNote error={auditError} />
      {#if audit.length === 0}
        <p class="empty">{tr('settings.audit.empty')}</p>
      {:else}
        <div class="table-wrap">
          <table class="audit">
            <thead><tr><th class="num">#</th><th>{tr('settings.audit.colWhen')}</th><th>{tr('settings.audit.colWho')}</th><th>{tr('settings.audit.colWhat')}</th><th>{tr('settings.audit.colDetails')}</th></tr></thead>
            <tbody>
              {#each audit as e (e.seq)}
                <tr>
                  <td class="num muted">{e.seq}</td>
                  <td class="small nowrap" title={e.time}>{dateTime(e.tsUnixSeconds)}</td>
                  <td>
                    {e.actor} <span class="badge">{e.actorKind}</span>
                    {#if e.remote}<div class="muted small mono">{e.remote}</div>{/if}
                  </td>
                  <td><code>{e.action}</code><div class="small">{e.target}</div></td>
                  <td class="small">
                    {summary(e)}
                    {#if e.reason}<div class="muted">{tr('settings.audit.reason', { reason: e.reason })}</div>{/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
        {#if auditCursor}
          <div class="row foot"><span class="spacer"></span><button onclick={() => loadAudit(true)}>{tr('settings.audit.older')}</button></div>
        {/if}
      {/if}
    </section>
  {:else if tab === 'cluster' && can('admin')}
    {#if clusterView && !clusterView.enabled}
      <section class="card"><p class="empty">{tr('settings.cluster.standalone')}</p></section>
    {:else}
      <!-- REQ: CLU-013 (T13.2) — staged rollouts: who gets a change first, and the guard. -->
      <ConfigEditor kind="rollout" path="cluster/rollout-settings" singleton role="admin" title={tr('settings.cluster.rollout.title')} noun={tr('settings.cluster.rollout.noun')}
        fields={rolloutFields} help="rollouts" note={rolloutNote}
        summary={(d) => {
          const c = Array.isArray(d.canaries) ? (d.canaries as string[]) : [];
          return c.length
            ? tn('settings.cluster.rollout.summary', c.length, { bake: String(d.bake_secs ?? 300) })
            : tr('settings.cluster.rollout.summaryOff');
        }} />
      <p class="muted small">
        {tr('settings.cluster.rollout.footnote')}
      </p>
    {/if}
  {:else if tab === 'system'}
    <section class="card">
      <h2>{tr('settings.system.title')}<HelpButton id="system" /></h2>
      {#if info}
        <dl class="sys">
          <dt>{tr('settings.system.version')}</dt><dd>{info.version}</dd>
          <dt>{tr('settings.system.node')}</dt><dd>{info.node} ({nodeRole(info.role)})</dd>
          <dt>{tr('settings.system.started')}</dt><dd>{tr('settings.system.startedValue', { time: dateTime(Date.parse(info.startedAt) / 1000), uptime: duration(info.uptimeSeconds) })}</dd>
          <!-- REQ: OBS-002 (T9.13) -->
          {#if info.starts > 1}
            <dt>{tr('settings.system.restarts')}</dt><dd data-testid="restarts">{info.starts - 1}{#if info.uncleanStarts} {tr('settings.system.unclean', { n: info.uncleanStarts })}{/if}</dd>
          {/if}
          <dt>{tr('settings.system.listeners')}</dt><dd class="mono">{info.listeners.join(', ')}</dd>
          <dt>{tr('settings.system.queryLog')}</dt><dd>{info.queryLog ? tr('settings.value.on') : tr('settings.value.off')}</dd>
          <dt>{tr('settings.system.snapshot')}</dt><dd>{info.filterSnapshot ?? tr('settings.system.noSnapshot')}{tr('settings.system.names', { names: info.filterNames.toLocaleString() })}</dd>
        </dl>
      {/if}
      <p class="muted small">{tr('settings.system.apiRef')} <a href="/api/v1/openapi.json" target="_blank" rel="noreferrer">/api/v1/openapi.json</a> {tr('settings.system.apiRefNote')}</p>
    </section>
    <!-- REQ: OBS-020 (ADR-107) — can clients reach each listener? -->
    <section class="card" data-testid="probes">
      <h2>{tr('settings.probes.title')}<HelpButton id="probes" /></h2>
      {#if probes == null}
        <p class="empty">{tr('common.loading')}</p>
      {:else if probes.length === 0}
        <p class="empty">{tr('settings.probes.emptyLead')}<code>[probe] enabled = false</code>{tr('settings.probes.emptyTail')}</p>
      {:else}
        <div class="table-wrap">
          <table class="compact">
            <thead><tr>{#if probes.some((p) => p.node)}<th>{tr('settings.probes.colNode')}</th>{/if}<th>{tr('settings.probes.colAsked')}</th><th>{tr('settings.probes.colResult')}</th><th class="num">{tr('settings.probes.colTime')}</th><th>{tr('settings.probes.colNotes')}</th></tr></thead>
            <tbody>
              {#each probes as p (`${p.node ?? ''}|${p.target}`)}
                <tr>
                  {#if probes.some((x) => x.node)}<td>{p.node ?? ''}</td>{/if}
                  <td>{#if p.proto === 'api'}<div class="web-ui">{tr('settings.probes.webUi')}</div>{/if}<span class="mono">{p.target}</span>{#if !p.listener}<span class="muted small">{tr('settings.probes.extraTarget')}</span>{/if}</td>
                  <td>
                    {#if p.skipped}<span class="badge">{tr('settings.probes.skipped')}</span>
                    {:else if p.ok}<span class="badge ok">{tr('settings.probes.answers')}</span>
                    {:else if p.consecutiveFailures >= 2}<span class="badge bad">{tr('settings.probes.notAnswering')}</span>
                    {:else}<span class="badge warn">{tr('settings.probes.missedOnce')}</span>{/if}
                  </td>
                  <td class="num">{p.latencyMs != null ? `${p.latencyMs.toFixed(1)} ms` : '–'}</td>
                  <td class="small">
                    {p.skipped ?? p.error ?? ''}
                    {#if certText(p)}<span class:cert-soon={(p.certDaysLeft ?? 99) < 14}>{certText(p)}</span>{/if}
                    <!-- REQ: API-003 (ADR-149) — what the certificate covers, and its fingerprint to compare with the browser's. -->
                    {#if p.certNames?.length}<div class="muted" data-testid="cert-names">{tr('settings.probes.forNames', { names: p.certNames.join(', ') })}</div>{/if}
                    {#if p.certSha256}<div class="muted fingerprint" data-testid="cert-sha256">SHA-256 <span class="mono">{p.certSha256}</span></div>{/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
      <p class="muted small">{tr('settings.probes.footnoteLead')}<code>[api] tls</code>{tr('settings.probes.footnoteTail')}</p>
    </section>
    <section class="card" data-testid="changes-list">
      <h2>{tr('settings.changes.title')}<HelpButton id="change-markers" /></h2>
      <div class="change-filters">
        <label class="pill-field">
          {tr('settings.changes.kind')}
          <select bind:value={changeKind} aria-label={tr('settings.changes.kindLabel')}>
            <option value="">{tr('settings.changes.kindAll')}</option>
            <option value="config.applied">{tr('settings.changes.kindConfig')}</option>
            <option value="note">{tr('settings.changes.kindNotes')}</option>
            <option value="lists.refreshed">{tr('settings.changes.kindLists')}</option>
            <option value="rollout.stage">{tr('settings.changes.kindRollouts')}</option>
            <option value="build.started,node.restarted">{tr('settings.changes.kindBuilds')}</option>
            <option value="maintenance.entered,maintenance.left">{tr('settings.changes.kindMaintenance')}</option>
            <option value="blocking.paused,blocking.resumed">{tr('settings.changes.kindPauses')}</option>
            <option value="cache.flushed">{tr('settings.changes.kindCache')}</option>
            <option value="upstream.breaker">{tr('settings.changes.kindUpstreams')}</option>
          </select>
        </label>
        <input class="small" type="search" placeholder={tr('settings.changes.filterPlaceholder')} bind:value={changeText} aria-label={tr('settings.changes.filterLabel')} />
      </div>
      <ErrorNote error={changeError} />
      {#if changeList == null}
        <p class="empty">{tr('common.loading')}</p>
      {:else if shownChanges.length === 0}
        <p class="empty">{tr('settings.changes.empty')}{changeKind || changeText ? tr('settings.changes.emptyMatch') : ''}{tr('settings.changes.emptyTail')}</p>
      {:else}
        <div class="table-wrap">
          <table class="compact">
            <thead><tr><th>{tr('settings.changes.colWhen')}</th>{#if shownChanges.some((a) => a.node)}<th>{tr('settings.changes.colNode')}</th>{/if}<th>{tr('settings.changes.colWhat')}</th><th>{tr('settings.changes.colWho')}</th></tr></thead>
            <tbody>
              {#each shownChanges as a, i (i)}
                <tr>
                  <td class="nowrap">{dateTime(a.tUnixMs / 1000)}</td>
                  {#if shownChanges.some((x) => x.node)}<td>{a.node ?? ''}</td>{/if}
                  <td>{#if a.href}<a href={a.href}>{a.summary}</a>{:else}{a.summary}{/if}</td>
                  <td class="small">{a.actor ?? a.source ?? ''}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
      {#if changeList?.missingNodes?.length}<p class="muted small">{tr('settings.changes.missing', { nodes: changeList.missingNodes.join(', ') })}</p>{/if}
      <p class="muted small">{tr('settings.changes.footnote')}</p>
    </section>
    {#if info}
      <!-- REQ: OPS-004 (ADR-046) -->
      <section class="card" data-testid="updates">
        <h2>{tr('settings.updates.title')}<HelpButton id="updates" /></h2>
        <dl class="sys">
          <dt>{tr('settings.updates.thisBuild')}</dt><dd><strong>{info.build.version}</strong>{tr('settings.updates.commit')} <code>{info.build.commit}</code>{tr('settings.updates.channel', { channel: info.build.channel })}</dd>
          <dt>{tr('settings.updates.built')}</dt><dd>{tr('settings.updates.builtValue', { date: info.build.date, target: info.build.target, install: info.build.install })}</dd>
          <dt>{tr('settings.updates.status')}</dt>
          <dd>
            {#if info.update.state === 'available'}
              <span class="badge warn">{tr('settings.updates.available')}</span> {info.update.latest}{#if info.update.latestDate} {tr('settings.updates.date', { date: info.update.latestDate })}{/if}
              {#if info.update.notesUrl}<a href={info.update.notesUrl} target="_blank" rel="noreferrer">{tr('settings.updates.whatsNew')}</a>{/if}
            {:else if info.update.state === 'up_to_date'}
              {tr('settings.updates.upToDate')}
            {:else if info.update.state === 'newer'}
              {tr('settings.updates.newer', { channel: info.build.channel })}{#if info.update.latest} {tr('settings.updates.newerVersion', { version: info.update.latest })}{/if}
            {:else if info.update.state === 'off'}
              {tr('settings.updates.notCheckedLead')}<code>[updates] check = false</code>{tr('settings.updates.notCheckedTail')}
            {:else}
              {tr('settings.updates.unknown')}{#if info.update.error}{tr('settings.updates.unknownError', { error: info.update.error })}{/if}
            {/if}
            <div class="muted small">
              {#if info.update.checkedUnixSeconds}{tr('settings.updates.checked', { time: ago(info.update.checkedUnixSeconds) })}{/if}
              {#if can('admin') && info.update.state !== 'off'}
                <button class="link small" disabled={checking} onclick={checkNow} data-testid="check-updates"
                  >{checking ? tr('settings.updates.checking') : tr('settings.updates.checkNow')}</button
                >
              {/if}
            </div>
            <ErrorNote error={checkError} />
          </dd>
        </dl>
        <p class="small">{info.update.how}</p>
      </section>
    {/if}
    {#if can('admin')}
      <!-- REQ: API-007 (T6.7) -->
      <section class="card">
        <h2>{tr('settings.backup.title')}<HelpButton id="backup" /></h2>
        <p>
          {tr('settings.backup.aboutLead')} <code>telltale backup restore FILE</code>{tr('settings.backup.aboutTail')}
        </p>
        <p><a class="button" href="/api/v1/backup" download>{tr('settings.backup.download')}</a></p>
        <p class="muted small">
          {tr('settings.backup.privateLead')}
          <code>telltale backup create --include-qlog</code> {tr('settings.backup.privateTail')}
        </p>
      </section>
      <!-- REQ: OPS-011 (ADR-156) — one redacted file for a bug report. -->
      <SupportPackage />
    {/if}
  {:else if tab === 'queries'}
    <!-- REQ: DNS-006 (T6.15) — the cache has its own page now. -->
    <section class="card">
      <h2>{tr('settings.queries.cacheTitle')}</h2>
      <p class="small">{tr('settings.queries.cacheAboutLead')} <a href="#/cache">{tr('settings.queries.cacheAboutLink')}</a>{tr('settings.queries.cacheAboutTail')}</p>
    </section>
    <!-- REQ: DNS-014 (review 01 q1) — the per-client rate limit, adjustable here and in the config file. -->
    <ConfigEditor kind="ratelimit" path="ratelimit" singleton title={tr('settings.queries.ratelimit.title')} noun={tr('settings.queries.ratelimit.noun')} fields={rateLimitFields}
      summary={(d) => (d.enabled === false
        ? tr('settings.queries.ratelimit.summaryOff')
        : tr('settings.queries.ratelimit.summary', { queries: String(d.queries), window: String(d.window_secs), action: String(d.action) }))} />
    <p class="muted small">
      {tr('settings.queries.ratelimit.footnote')}
    </p>
    <!-- REQ: OBS-022 (T12.1) — names and devices kept out of the query log and analytics. -->
    <ConfigEditor kind="exclusions" path="exclusions" singleton title={tr('settings.queries.exclusions.title')} noun={tr('settings.queries.exclusions.noun')} fields={exclusionFields}
      summary={(d) => {
        const n = (k: string) => (Array.isArray(d[k]) ? (d[k] as unknown[]).length : 0);
        if (n('names') + n('clients') === 0) return tr('settings.queries.exclusions.summaryNone');
        return `${d.enabled === false ? tr('settings.queries.exclusions.summaryOff') : ''}${tr('settings.queries.exclusions.summary', { names: n('names'), clients: n('clients') })}`;
      }} />
    <p class="muted small">
      {tr('settings.queries.exclusions.footnoteLead')} <code>/metrics</code>{tr('settings.queries.exclusions.footnoteTail')}<HelpButton id="exclusions" />
    </p>
    <!-- REQ: OBS-024 (T13.1) — change simulation's switches and bounds. -->
    <ConfigEditor kind="simulate" path="simulate-settings" singleton title={tr('settings.queries.simulate.title')} noun={tr('settings.queries.simulate.noun')} fields={simulateFields}
      help="simulate"
      summary={(d) =>
        d.enabled === false
          ? tr('settings.queries.simulate.summaryOff')
          : tr('settings.queries.simulate.summary', {
              window: String(d.default_window ?? '24h'),
              plans: d.plans_by_default ? tr('settings.queries.simulate.always') : tr('settings.queries.simulate.whenAsked'),
            })} />
    <p class="muted small">
      {tr('settings.queries.simulate.footnote')}
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
