<script lang="ts">
  // REQ: API-003, API-005 — my account (password, two-factor), API tokens, users (admin),
  // and system information.
  import { api, type S } from '../lib/api';
  import { can, session, refreshSession } from '../lib/session.svelte';
  import { route, navigate } from '../lib/router.svelte';
  import { ago, dateTime, duration } from '../lib/format';
  import { poll } from '../lib/poll';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import ConfigEditor, { type Field } from '../lib/components/ConfigEditor.svelte';

  const tabs = $derived(
    [
      { id: 'account', label: 'Account' },
      { id: 'tokens', label: 'API tokens' },
      ...(can('admin') ? [{ id: 'users', label: 'Users' }, { id: 'audit', label: 'Audit log' }] : []),
      { id: 'system', label: 'System' },
    ],
  );
  // REQ: DNS-014 (review 01 q1) — the fields of `[ratelimit]`.
  const rateLimitFields: Field[] = [
    { key: 'enabled', label: 'Limit queries per client', type: 'bool', initial: true },
    { key: 'queries', label: 'Queries allowed per window', type: 'number', placeholder: '1000',
      help: 'Per client; short bursts up to this are fine. A client over it gets the action below until its allowance refills.' },
    { key: 'window_secs', label: 'Window (seconds)', type: 'number', placeholder: '60' },
    { key: 'action', label: 'When over the limit', type: 'select', options: ['refused', 'drop'],
      help: 'refused answers REFUSED; drop answers nothing.' },
    { key: 'exempt', label: 'Never limited', type: 'lines', placeholder: '127.0.0.0/8\n192.168.1.1/32',
      help: 'Addresses or networks, one per line (a router that forwards for the whole network, say). Replaces the list from the config file, so keep 127.0.0.0/8 and ::1/128.' },
    { key: 'ipv4_prefix', label: 'IPv4: count clients per /N', type: 'number', advanced: true, placeholder: '32',
      help: '32 counts each address on its own.' },
    { key: 'ipv6_prefix', label: 'IPv6: count clients per /N', type: 'number', advanced: true, placeholder: '64',
      help: '64 groups a device\'s rotating privacy addresses.' },
  ];
  // REQ: OBS-022 (T12.1) — the fields of `[exclusions]`.
  const exclusionFields: Field[] = [
    { key: 'enabled', label: 'Leave these out of the log and stats', type: 'bool', initial: true,
      help: 'Off keeps the lists below but logs everything again.' },
    { key: 'names', label: 'Names', type: 'lines', placeholder: 'connectivitycheck.gstatic.com\nntp.org',
      help: 'One per line; each covers its subdomains too. Noise like connectivity checks, time servers, or a monitoring probe.' },
    { key: 'clients', label: 'Devices', type: 'lines', placeholder: '192.168.1.10\n10.20.0.0/24',
      help: 'Addresses or networks, one per line (a monitoring host, say).' },
  ];
  // REQ: OBS-024 (T13.1) — the fields of `[simulate]`.
  const simulateFields: Field[] = [
    { key: 'enabled', label: 'Allow change simulations', type: 'bool', initial: true,
      help: 'The "What would this have done?" button, the simulate parameter of dry runs, and simulate_change for agents.' },
    { key: 'plans_by_default', label: "Agents' plans simulate by default", type: 'bool', initial: false,
      help: 'Off: a plan simulates only when the agent asks (simulate: "24h"). On: every plan replays the query log, which costs CPU on each node.' },
    { key: 'default_window', label: 'Default window', type: 'text', placeholder: '24h',
      help: 'How far back a simulation replays when no window is given: 30m, 24h, up to 7d.' },
    { key: 'max_secs', label: 'Time limit per node (seconds)', type: 'number', placeholder: '20', advanced: true,
      help: '1 to 300. A node that runs out of time answers with what it read so far (partial).' },
    { key: 'max_rows', label: 'Most logged queries read per node', type: 'number', placeholder: '2000000', advanced: true,
      help: 'At least 1,000. Newest first.' },
  ];
  const tab = $derived.by(() => {
    const t = route.params.get('tab');
    return tabs.some((x) => x.id === t) ? (t as string) : 'account';
  });

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
      pwMsg = 'Password changed. Your other sessions were signed out.';
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
    ['analytics:read', 'Statistics, top lists, anomalies, explain'],
    ['querylog:read', 'The query log (who asked for what)'],
    ['config:read', 'Lists, groups, devices, names, upstreams'],
    ['config:write:clients', 'Name and regroup devices'],
    ['config:write:records', 'Change names on my network'],
    ['config:write:forwards', 'Send domains to other servers'],
    ['cluster:admin', 'Promote a node to primary'],
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
  async function loadUsers() {
    try {
      users = (await api.users()).items;
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
  });
  $effect(() => {
    if (tab === 'system') return poll(loadProbes, 10_000);
  });
  const certText = (p: S['ProbeResult']) =>
    p.certDaysLeft == null
      ? (p.certError ?? '')
      : p.certDaysLeft < 0
        ? `certificate expired ${-p.certDaysLeft} day(s) ago`
        : `certificate expires in ${p.certDaysLeft} day(s)`;

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
  <h1>Settings</h1>
  <div class="seg tabs" role="tablist">
    {#each tabs as t (t.id)}
      <button role="tab" aria-selected={tab === t.id} onclick={() => navigate('/settings', { tab: t.id })}>{t.label}</button>
    {/each}
  </div>

  {#if tab === 'account' && session.user}
    <div class="grid-2">
      <section class="card">
        <h2>Account<HelpButton id="account" /></h2>
        <p><strong>{session.user.username}</strong> · <span class="badge">{session.user.role}</span></p>
        <form class="stack" onsubmit={changePassword}>
          <h3>Change password</h3>
          <label class="field">Current password
            <input type="password" autocomplete="current-password" required bind:value={current} />
          </label>
          <label class="field">New password (at least 10 characters)
            <input type="password" autocomplete="new-password" minlength="10" required bind:value={next} />
          </label>
          <ErrorNote error={pwError} />
          {#if pwMsg}<div class="notice ok">{pwMsg}</div>{/if}
          <div><button class="primary" type="submit">Change password</button></div>
        </form>
      </section>

      <section class="card stack-card">
        <h2>Two-factor sign-in<HelpButton id="two-factor" /></h2>
        <ErrorNote error={totpError} />
        {#if recovery.length}
          <div class="notice warn">
            <strong>Save these recovery codes now.</strong> Each works once if you lose your phone; they won't be shown again.
            <ul class="codes mono">{#each recovery as c (c)}<li>{c}</li>{/each}</ul>
          </div>
        {/if}
        {#if session.user.totpEnabled}
          <p><span class="badge ok">on</span> {session.user.recoveryCodesLeft} recovery codes left.</p>
          <form class="stack" onsubmit={disableTotp}>
            <label class="field">Password, to turn it off
              <input type="password" autocomplete="current-password" required bind:value={totpPassword} />
            </label>
            <div><button class="danger" type="submit">Turn off two-factor</button></div>
          </form>
        {:else if totp}
          <ol class="steps">
            <li>Add this account to an authenticator app: on a phone, <a href={totp.otpauthUrl}>open it in the app</a>, or enter the key by hand:
              <div class="mono key">{totp.secretBase32.replace(/(.{4})/g, '$1 ').trim()}</div>
            </li>
            <li>Enter the 6-digit code it shows.</li>
          </ol>
          <form class="row" onsubmit={enableTotp}>
            <input inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}" required placeholder="123456" bind:value={totpCode} />
            <button class="primary" type="submit">Turn on</button>
            <button type="button" onclick={() => (totp = null)}>Cancel</button>
          </form>
        {:else}
          <p class="muted">Ask for a code from an authenticator app when signing in, on top of the password.</p>
          <div><button onclick={startTotp}>Set up two-factor sign-in</button></div>
        {/if}
      </section>
    </div>
  {:else if tab === 'tokens'}
    <section class="card">
      <h2>API tokens<HelpButton id="api-tokens" /></h2>
      <p class="muted">
        For scripts, dashboards, and AI agents: send <code>Authorization: Bearer &lt;token&gt;</code>.
        A token never has more rights than you.
      </p>
      <form class="row" onsubmit={createToken}>
        <input aria-label="Token name" required placeholder="name, e.g. grafana" bind:value={tokenName} />
        <select aria-label="Kind" bind:value={tokenKind}>
          <option value="user">for my scripts</option>
          <option value="agent">for an AI agent</option>
        </select>
        {#if tokenKind === 'user'}
          <select aria-label="Scope" bind:value={tokenScope}>
            <option value="read">read (viewer)</option>
            <option value="write">write (operator)</option>
            <option value="admin">admin</option>
          </select>
        {/if}
        <select aria-label="Expires" bind:value={tokenDays}>
          <option value="">never expires</option>
          <option value="7">7 days</option>
          <option value="30">30 days</option>
          <option value="90">90 days</option>
          <option value="365">1 year</option>
        </select>
        <HelpButton id="token-scope" />
        <button class="primary" type="submit">Create token</button>
      </form>
      {#if tokenKind === 'agent'}
        <fieldset class="agent-scopes">
          <legend>What the agent may do<HelpButton id="agent-tokens" /></legend>
          {#each agentScopes as [id, label] (id)}
            <label><input type="checkbox" value={id} bind:group={tokenScopes} /> {label} <code class="small">{id}</code></label>
          {/each}
          <label>Only this group's devices and queries (optional):
            <input aria-label="Group" placeholder="e.g. kids" bind:value={tokenGroup} /></label>
          <p class="muted small">
            Agents must give a reason for every change, are limited to 120 requests a minute, show as
            <code>agent:&lt;name&gt;</code> in the audit log, and stop at once with <code>[agents] enabled = false</code>.
          </p>
        </fieldset>
      {/if}
      <ErrorNote error={tokenError} />
      {#if newToken}
        <div class="notice ok new-token">
          <strong>Copy the token now; it won't be shown again.</strong>
          <div class="row"><code class="token">{newToken}</code><button onclick={() => copy(newToken)}>Copy</button><button class="link" onclick={() => (newToken = '')}>Done</button></div>
        </div>
      {/if}
      {#if tokens.length === 0}
        <p class="empty">No tokens yet.</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead><tr><th>Name</th><th>Scope</th><th>Created</th><th>Last used</th><th>Expires</th><th></th></tr></thead>
            <tbody>
              {#each tokens as t (t.id)}
                <tr>
                  <td><strong>{t.name}</strong><div class="muted small mono">tt_{t.id}_…</div></td>
                  <td>
                    {#if t.kind === 'agent'}
                      <span class="badge">agent</span>
                      <div class="muted small">{(t.scopes ?? []).join(', ')}{t.group ? ` · group ${t.group}` : ''}</div>
                    {:else}
                      <span class="badge">{t.scope}</span>
                    {/if}
                  </td>
                  <td class="small">{ago(t.createdUnixSeconds)}</td>
                  <td class="small">{ago(t.lastUsedUnixSeconds)}</td>
                  <td class="small">{t.expiresUnixSeconds ? dateTime(t.expiresUnixSeconds) : 'never'}</td>
                  <td class="num"><button class="danger" onclick={() => revoke(t.id)}>Revoke</button></td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </section>
  {:else if tab === 'users' && can('admin')}
    <section class="card">
      <h2>Users<HelpButton id="users" /></h2>
      <ErrorNote error={userError} />
      <div class="table-wrap">
        <table>
          <thead><tr><th>User</th><th>Role</th><th>Two-factor</th><th>HTTP Basic</th><th>Status</th><th></th></tr></thead>
          <tbody>
            {#each users as u (u.id)}
              <tr>
                <td>
                  <strong>{u.username}</strong>{#if u.id === session.user?.id} <span class="muted small">(you)</span>{/if}
                  {#if u.oidcProvider}<div class="muted small">signs in with {u.oidcProvider}</div>{/if}
                </td>
                <td>
                  <select aria-label={`Role of ${u.username}`} value={u.role} onchange={(e) => patchUser(u, { role: e.currentTarget.value as S['Role'] })}>
                    <option value="viewer">viewer</option>
                    <option value="operator">operator</option>
                    <option value="admin">admin</option>
                  </select>
                </td>
                <td>
                  {#if u.totpEnabled}<span class="badge ok">on</span> <button class="link small" onclick={() => patchUser(u, { resetTotp: true })}>Reset</button>{:else}<span class="muted">off</span>{/if}
                </td>
                <td><input type="checkbox" aria-label={`HTTP Basic for ${u.username}`} checked={u.allowBasicApi} onchange={(e) => patchUser(u, { allowBasicApi: e.currentTarget.checked })} /></td>
                <td>
                  <button class="link" onclick={() => patchUser(u, { disabled: !u.disabled })}>{u.disabled ? 'Disabled · enable' : 'Active · disable'}</button>
                </td>
                <td class="num">
                  <button class="link" aria-expanded={tokensOf === u.id} onclick={() => showTokens(u)}>Tokens</button>
                  {#if u.id !== session.user?.id}
                    <button class="danger" onclick={() => removeUser(u)}>{armed === u.id ? 'Really delete?' : 'Delete'}</button>
                  {/if}
                </td>
              </tr>
              {#if tokensOf === u.id}
                <tr class="user-tokens">
                  <td colspan="6">
                    {#if userTokens.length === 0}
                      <span class="muted small">{u.username} has no API tokens.</span>
                    {:else}
                      <table>
                        <thead><tr><th>{u.username}'s token</th><th>Scope</th><th>Last used</th><th>Expires</th><th></th></tr></thead>
                        <tbody>
                          {#each userTokens as t (t.id)}
                            <tr>
                              <td><strong>{t.name}</strong><div class="muted small mono">tt_{t.id}_…</div></td>
                              <td>{#if t.kind === 'agent'}<span class="badge">agent</span>{:else}<span class="badge">{t.scope}</span>{/if}</td>
                              <td class="small">{ago(t.lastUsedUnixSeconds)}</td>
                              <td class="small">{t.expiresUnixSeconds ? dateTime(t.expiresUnixSeconds) : 'never'}</td>
                              <td class="num"><button class="danger" onclick={() => revokeUserToken(u, t.id)}>Revoke</button></td>
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
        <h3>Add a user</h3>
        <div class="row">
          <input aria-label="Username" required placeholder="username" autocomplete="off" bind:value={nu.username} />
          <input aria-label="Password" required type="password" minlength="10" placeholder="password (10+ characters)" autocomplete="new-password" bind:value={nu.password} />
          <select aria-label="Role" bind:value={nu.role}>
            <option value="viewer">viewer</option>
            <option value="operator">operator</option>
            <option value="admin">admin</option>
          </select>
          <label class="row small"><input type="checkbox" bind:checked={nu.allowBasicApi} /> HTTP Basic</label><HelpButton id="http-basic" />
          <button class="primary" type="submit">Add</button>
        </div>
        <p class="muted small">Viewers see dashboards and the query log; operators can also pause blocking and manage lists, clients, and groups; admins can do everything.</p>
      </form>
    </section>
  {:else if tab === 'audit' && can('admin')}
    <section class="card">
      <div class="card-head">
        <h2>Audit log<HelpButton id="audit-log" /></h2>
        <div class="row">
          <select aria-label="Action" bind:value={auditAction} onchange={() => loadAudit()}>
            <option value="">All changes</option>
            <option value="user.">Users</option>
            <option value="token.">API tokens</option>
            <option value="auth.">Sign-ins and lockouts</option>
            <option value="config.">Configuration</option>
          </select>
          <button onclick={verifyAudit}>Verify chain</button>
        </div>
      </div>
      <p class="muted small">
        Every change to users, passwords, two-factor sign-in, and API tokens, plus sign-ins, lockouts, and configuration
        reloads. Entries can't be edited, and each one is chained to the one before it, so tampering is detectable.
      </p>
      {#if verified}
        <div class="notice {verified.ok ? 'ok' : 'bad'} verify-result" role="status">
          {#if verified.ok}
            Chain intact: {verified.entries} entries. Head <code class="mono">{verified.headHash.slice(0, 16)}…</code>
          {:else}
            <strong>Chain broken at entry {verified.firstBadSeq}</strong>: the log was changed outside TelltaleDNS.
          {/if}
        </div>
      {/if}
      <ErrorNote error={auditError} />
      {#if audit.length === 0}
        <p class="empty">No entries.</p>
      {:else}
        <div class="table-wrap">
          <table class="audit">
            <thead><tr><th class="num">#</th><th>When</th><th>Who</th><th>What</th><th>Details</th></tr></thead>
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
                    {#if e.reason}<div class="muted">Reason: {e.reason}</div>{/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
        {#if auditCursor}
          <div class="row foot"><span class="spacer"></span><button onclick={() => loadAudit(true)}>Older</button></div>
        {/if}
      {/if}
    </section>
  {:else if tab === 'system'}
    <section class="card">
      <h2>System<HelpButton id="system" /></h2>
      {#if info}
        <dl class="sys">
          <dt>Version</dt><dd>{info.version}</dd>
          <dt>Node</dt><dd>{info.node} ({info.role})</dd>
          <dt>Started</dt><dd>{dateTime(Date.parse(info.startedAt) / 1000)} · up {duration(info.uptimeSeconds)}</dd>
          <!-- REQ: OBS-002 (T9.13) -->
          {#if info.starts > 1}
            <dt>Restarts</dt><dd data-testid="restarts">{info.starts - 1}{#if info.uncleanStarts} ({info.uncleanStarts} after a crash or a kill){/if}</dd>
          {/if}
          <dt>DNS listeners</dt><dd class="mono">{info.listeners.join(', ')}</dd>
          <dt>Query log</dt><dd>{info.queryLog ? 'on' : 'off'}</dd>
          <dt>Filter snapshot</dt><dd>{info.filterSnapshot ?? 'none yet'} · {info.filterNames.toLocaleString()} names</dd>
        </dl>
      {/if}
      <p class="muted small">API reference: <a href="/api/v1/openapi.json" target="_blank" rel="noreferrer">/api/v1/openapi.json</a> (OpenAPI 3.1).</p>
    </section>
    <!-- REQ: OBS-020 (ADR-107) — can clients reach each listener? -->
    <section class="card" data-testid="probes">
      <h2>Listener checks<HelpButton id="probes" /></h2>
      {#if probes == null}
        <p class="empty">Loading…</p>
      {:else if probes.length === 0}
        <p class="empty">No results yet (the first round runs a few seconds after start), or probes are off (<code>[probe] enabled = false</code>).</p>
      {:else}
        <div class="table-wrap">
          <table class="compact">
            <thead><tr>{#if probes.some((p) => p.node)}<th>Node</th>{/if}<th>Asked</th><th>Result</th><th class="num">Time</th><th>Notes</th></tr></thead>
            <tbody>
              {#each probes as p (`${p.node ?? ''}|${p.target}`)}
                <tr>
                  {#if probes.some((x) => x.node)}<td>{p.node ?? ''}</td>{/if}
                  <td class="mono">{p.target}{#if !p.listener}<span class="muted small"> (extra target)</span>{/if}</td>
                  <td>
                    {#if p.skipped}<span class="badge">skipped</span>
                    {:else if p.ok}<span class="badge ok">answers</span>
                    {:else if p.consecutiveFailures >= 2}<span class="badge bad">not answering</span>
                    {:else}<span class="badge warn">missed once</span>{/if}
                  </td>
                  <td class="num">{p.latencyMs != null ? `${p.latencyMs.toFixed(1)} ms` : '–'}</td>
                  <td class="small">
                    {p.skipped ?? p.error ?? ''}
                    {#if certText(p)}<span class:cert-soon={(p.certDaysLeft ?? 99) < 14}>{certText(p)}</span>{/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
      <p class="muted small">Every 30 s each node asks each of its listeners a question through the listener's own protocol, the way a device would.</p>
    </section>
    {#if info}
      <!-- REQ: OPS-004 (ADR-046) -->
      <section class="card" data-testid="updates">
        <h2>Version and updates<HelpButton id="updates" /></h2>
        <dl class="sys">
          <dt>This build</dt><dd><strong>{info.build.version}</strong> · commit <code>{info.build.commit}</code> · {info.build.channel} channel</dd>
          <dt>Built</dt><dd>{info.build.date} · {info.build.target} · {info.build.install} install</dd>
          <dt>Status</dt>
          <dd>
            {#if info.update.state === 'available'}
              <span class="badge warn">Update available</span> {info.update.latest}{info.update.latestDate ? ` (${info.update.latestDate})` : ''}
              {#if info.update.notesUrl}<a href={info.update.notesUrl} target="_blank" rel="noreferrer">What's new</a>{/if}
            {:else if info.update.state === 'up_to_date'}
              Up to date
            {:else if info.update.state === 'newer'}
              Newer than the published {info.build.channel} build{info.update.latest ? ` (${info.update.latest})` : ''}
            {:else if info.update.state === 'off'}
              Not checked (<code>[updates] check = false</code>)
            {:else}
              Not known yet{info.update.error ? `: ${info.update.error}` : ''}
            {/if}
            <div class="muted small">
              {#if info.update.checkedUnixSeconds}Checked {ago(info.update.checkedUnixSeconds)}{/if}
              {#if can('admin') && info.update.state !== 'off'}
                <button class="link small" disabled={checking} onclick={checkNow} data-testid="check-updates"
                  >{checking ? 'Checking…' : 'Check now'}</button
                >
              {/if}
            </div>
            <ErrorNote error={checkError} />
          </dd>
        </dl>
        <p class="small">{info.update.how}</p>
      </section>
    {/if}
    <!-- REQ: DNS-006 (T6.15) — the cache has its own page now. -->
    <section class="card">
      <h2>Cache</h2>
      <p class="small">Hit rates, what's cached, settings, lookups, and flushing are on the <a href="#/cache">Cache page</a>.</p>
    </section>
    <!-- REQ: DNS-014 (review 01 q1) — the per-client rate limit, adjustable here and in the config file. -->
    <ConfigEditor kind="ratelimit" path="ratelimit" singleton title="Rate limit" noun="rate limit" fields={rateLimitFields}
      summary={(d) => (d.enabled === false ? 'off' : `${String(d.queries)} queries per ${String(d.window_secs)} s per client, then ${String(d.action)}`)} />
    <p class="muted small">
      One client is one address (IPv6: one /64). A router or proxy that forwards for a whole network looks like one client:
      add it to "Never limited", or raise the number. A change applies at once and every client's count starts over.
    </p>
    <!-- REQ: OBS-022 (T12.1) — names and devices kept out of the query log and analytics. -->
    <ConfigEditor kind="exclusions" path="exclusions" singleton title="Kept out of the log" noun="exclusions" fields={exclusionFields}
      summary={(d) => {
        const n = (k: string) => (Array.isArray(d[k]) ? (d[k] as unknown[]).length : 0);
        if (n('names') + n('clients') === 0) return 'nothing excluded';
        return `${d.enabled === false ? 'off: ' : ''}${n('names')} names, ${n('clients')} devices`;
      }} />
    <p class="muted small">
      Their queries are still answered and still counted in <code>/metrics</code>, but left out of the query log, the live view,
      the dashboard and top lists, anomalies, and exports, on every node. Queries logged before stay.<HelpButton id="exclusions" />
    </p>
    <!-- REQ: OBS-024 (T13.1) — change simulation's switches and bounds. -->
    <ConfigEditor kind="simulate" path="simulate-settings" singleton title="Change simulation" noun="simulation settings" fields={simulateFields}
      help="simulate"
      summary={(d) =>
        d.enabled === false
          ? 'off'
          : `on, ${String(d.default_window ?? '24h')} by default; agents' plans ${d.plans_by_default ? 'always simulate' : 'simulate when asked'}`} />
    <p class="muted small">
      A simulation replays the query log with and without a change and shows what would have been answered differently. It never
      touches DNS answers and runs at background priority; at query-log privacy level 1 or above names can't be replayed.
    </p>
    {#if can('admin')}
      <!-- REQ: API-007 (T6.7) -->
      <section class="card">
        <h2>Backup<HelpButton id="backup" /></h2>
        <p>
          One file with your settings, users and API tokens, the devices and names you added here, the audit log, and
          statistics history. Restore it on a new machine with <code>telltale backup restore FILE</code>.
        </p>
        <p><a class="button" href="/api/v1/backup" download>Download a backup</a></p>
        <p class="muted small">
          It holds password hashes, so keep it private. The query log isn't included; for that, run
          <code>telltale backup create --include-qlog</code> on the server.
        </p>
      </section>
    {/if}
  {/if}
</div>

<style>
  .cert-soon {
    color: var(--warn);
    font-weight: 600;
  }
  .agent-scopes {
    display: grid;
    gap: 0.35rem;
    margin: 0.75rem 0;
    border: 1px solid var(--border, #ddd);
    border-radius: 8px;
    padding: 0.75rem 1rem;
  }
  .tabs button[aria-selected='true'] {
    background: var(--accent);
    color: var(--accent-text);
  }
  .tabs {
    justify-self: start;
    flex-wrap: wrap;
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
