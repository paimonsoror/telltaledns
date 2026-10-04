<script lang="ts">
  // REQ: API-003, API-005 — my account (password, two-factor), API tokens, users (admin),
  // and system information.
  import { api, type S } from '../lib/api';
  import { can, session, refreshSession } from '../lib/session.svelte';
  import { route, navigate } from '../lib/router.svelte';
  import { ago, dateTime, duration } from '../lib/format';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';

  const tabs = $derived(
    [
      { id: 'account', label: 'Account' },
      { id: 'tokens', label: 'API tokens' },
      ...(can('admin') ? [{ id: 'users', label: 'Users' }, { id: 'audit', label: 'Audit log' }] : []),
      { id: 'system', label: 'System' },
    ],
  );
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
      const t = await api.createToken({
        name: tokenName.trim(),
        scope: tokenScope,
        expiresInDays: tokenDays ? Number(tokenDays) : undefined,
      });
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

  $effect(() => {
    if (tab === 'tokens') void loadTokens();
    if (tab === 'users' && can('admin')) void loadUsers();
    if (tab === 'audit' && can('admin')) void loadAudit();
    if (tab === 'system') api.info().then((i) => (info = i)).catch(() => {});
  });
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
        <select aria-label="Scope" bind:value={tokenScope}>
          <option value="read">read (viewer)</option>
          <option value="write">write (operator)</option>
          <option value="admin">admin</option>
        </select>
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
                  <td><span class="badge">{t.scope}</span></td>
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
                  {#if u.id !== session.user?.id}
                    <button class="danger" onclick={() => removeUser(u)}>{armed === u.id ? 'Really delete?' : 'Delete'}</button>
                  {/if}
                </td>
              </tr>
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
          <dt>DNS listeners</dt><dd class="mono">{info.listeners.join(', ')}</dd>
          <dt>Query log</dt><dd>{info.queryLog ? 'on' : 'off'}</dd>
          <dt>Filter snapshot</dt><dd>{info.filterSnapshot ?? 'none yet'} · {info.filterNames.toLocaleString()} names</dd>
        </dl>
      {/if}
      <p class="muted small">API reference: <a href="/api/v1/openapi.json" target="_blank" rel="noreferrer">/api/v1/openapi.json</a> (OpenAPI 3.1).</p>
    </section>
  {/if}
</div>

<style>
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
