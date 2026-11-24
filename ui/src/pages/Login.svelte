<script lang="ts">
  // REQ: API-003 — password sign-in, then a TOTP or recovery code when the account needs one.
  import { api, ApiError } from '../lib/api';
  import { session, signedIn } from '../lib/session.svelte';
  import { route } from '../lib/router.svelte';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import AuthShell from './AuthShell.svelte';
  import { t } from '../lib/i18n';

  let username = $state('');
  let password = $state('');
  let totp = $state('');
  let recovery = $state('');
  let needCode = $state(false);
  let useRecovery = $state(false);
  let busy = $state(false);
  let error = $state<unknown>(null);

  // REQ: API-004 — "Sign in with ..." returns here; failures come back as ?loginError=.
  const loginError = $derived(route.params.get('loginError'));
  const back = $derived(
    location.hash && !location.hash.includes('loginError') ? `/${location.hash}` : '/#/',
  );
  const startUrl = (id: string) =>
    `/api/v1/auth/oidc/${encodeURIComponent(id)}/start?returnTo=${encodeURIComponent(back)}`;

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    error = null;
    try {
      const r = await api.login({
        username,
        password,
        totp: needCode && !useRecovery ? totp : undefined,
        recoveryCode: needCode && useRecovery ? recovery : undefined,
      });
      signedIn(r);
    } catch (err) {
      if (err instanceof ApiError && err.code === 'totp_required') {
        needCode = true;
      } else {
        error = err;
      }
    } finally {
      busy = false;
    }
  }
</script>

<AuthShell title={t('auth.signIn')}>
  {#if loginError}
    <div class="notice bad provider-error" role="alert">{loginError}</div>
  {/if}
  {#if session.oidc.length}
    <div class="providers">
      {#each session.oidc as p (p.id)}
        <a class="btn provider" href={startUrl(p.id)}>{t('auth.signInWith', { provider: p.name })}</a>
      {/each}
    </div>
    <!-- REQ: API-004 (ADR-175) — with password sign-in limited to admins on trusted networks, say what the form is. -->
    {#if session.localLogin}<div class="or muted small">{t(session.passwordLoginRestricted ? 'auth.passwordOrAdmin' : 'auth.passwordOr')}</div>{/if}
  {/if}
  {#if !session.localLogin}
    <p class="muted small">{t('auth.passwordOff')}</p>
  {:else}
  <form class="stack" onsubmit={submit}>
    {#if !needCode}
      <label class="field">{t('auth.username')}
        <input name="username" autocomplete="username" required bind:value={username} />
      </label>
      <label class="field">{t('auth.password')}
        <input name="password" type="password" autocomplete="current-password" required bind:value={password} />
      </label>
    {:else if !useRecovery}
      <p class="muted">{t('auth.codeHint')}</p>
      <!-- REQ: API-003 (issue #64) — in a quoted attribute Svelte reads `{6}` as an expression, so the pattern is one. -->
      <label class="field">{t('auth.code')}
        <input name="totp" title={t('auth.codeTitle')} inputmode="numeric" autocomplete="one-time-code" pattern={'[0-9]{6}'} maxlength="6" required bind:value={totp} />
      </label>
      <button type="button" class="link" onclick={() => (useRecovery = true)}>{t('auth.useRecovery')}</button>
    {:else}
      <label class="field">{t('auth.recoveryCode')}
        <input name="recovery" autocomplete="off" required bind:value={recovery} placeholder="xxxxx-xxxxx" />
      </label>
      <button type="button" class="link" onclick={() => (useRecovery = false)}>{t('auth.useAppCode')}</button>
    {/if}
    <ErrorNote {error} />
    <button class="primary" type="submit" disabled={busy}>{busy ? t('auth.signingIn') : t('auth.signIn')}</button>
  </form>
  {#if session.passwordLoginRestricted}
    <p class="muted small" data-testid="password-restricted">{t('auth.passwordRestricted')}</p>
  {/if}
  {/if}
</AuthShell>

<style>
  .providers {
    display: grid;
    gap: 8px;
  }
  .provider {
    display: block;
    text-align: center;
    font-weight: 600;
    padding: 9px 12px;
  }
  .or {
    text-align: center;
  }
</style>
