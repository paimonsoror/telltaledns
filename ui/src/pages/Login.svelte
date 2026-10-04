<script lang="ts">
  // REQ: API-003 — password sign-in, then a TOTP or recovery code when the account needs one.
  import { api, ApiError } from '../lib/api';
  import { signedIn } from '../lib/session.svelte';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import AuthShell from './AuthShell.svelte';

  let username = $state('');
  let password = $state('');
  let totp = $state('');
  let recovery = $state('');
  let needCode = $state(false);
  let useRecovery = $state(false);
  let busy = $state(false);
  let error = $state<unknown>(null);

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

<AuthShell title="Sign in">
  <form class="stack" onsubmit={submit}>
    {#if !needCode}
      <label class="field">Username
        <input name="username" autocomplete="username" required bind:value={username} />
      </label>
      <label class="field">Password
        <input name="password" type="password" autocomplete="current-password" required bind:value={password} />
      </label>
    {:else if !useRecovery}
      <p class="muted">Enter the 6-digit code from your authenticator app.</p>
      <label class="field">Code
        <input name="totp" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required bind:value={totp} />
      </label>
      <button type="button" class="link" onclick={() => (useRecovery = true)}>Use a recovery code instead</button>
    {:else}
      <label class="field">Recovery code
        <input name="recovery" autocomplete="off" required bind:value={recovery} placeholder="xxxxx-xxxxx" />
      </label>
      <button type="button" class="link" onclick={() => (useRecovery = false)}>Use the app code instead</button>
    {/if}
    <ErrorNote {error} />
    <button class="primary" type="submit" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
  </form>
</AuthShell>
