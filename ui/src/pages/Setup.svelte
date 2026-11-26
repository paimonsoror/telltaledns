<script lang="ts">
  // REQ: API-003 — first run: the one-time setup token creates the first admin.
  import { api } from '../lib/api';
  import { signedIn } from '../lib/session.svelte';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import AuthShell from './AuthShell.svelte';
  import { tr } from '../lib/i18n';
  import T from '../lib/i18n/T.svelte';
  const { t } = tr('setup');

  let setupToken = $state('');
  let username = $state('admin');
  let password = $state('');
  let confirm = $state('');
  let busy = $state(false);
  let error = $state<unknown>(null);

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (password !== confirm) {
      error = new Error(t('The passwords don’t match.'));
      return;
    }
    busy = true;
    error = null;
    try {
      signedIn(await api.setup({ setupToken: setupToken.trim(), username, password }));
    } catch (err) {
      error = err;
    } finally {
      busy = false;
    }
  }
</script>

{#snippet setuptokencmd()}<code translate="no">telltale auth setup-token</code>{/snippet}

<AuthShell title={t('Welcome to TelltaleDNS')}>
  <p class="muted">
    <T ctx="setup" msg={'Create the first admin. <setuptokencmd/> prints the setup token (the server log says which file holds it).'} {setuptokencmd} />
  </p>
  <form class="stack" onsubmit={submit}>
    <label class="field">{t('Setup token')}
      <input name="setupToken" autocomplete="off" required bind:value={setupToken} />
    </label>
    <label class="field">{t('Admin username')}
      <input name="username" autocomplete="username" required bind:value={username} />
    </label>
    <label class="field">{t('Password (at least 10 characters)')}
      <input name="password" type="password" autocomplete="new-password" minlength="10" required bind:value={password} />
    </label>
    <label class="field">{t('Repeat password')}
      <input name="confirm" type="password" autocomplete="new-password" minlength="10" required bind:value={confirm} />
    </label>
    <ErrorNote {error} />
    <button class="primary" type="submit" disabled={busy}>{busy ? t('Creating…') : t('Create admin and sign in')}</button>
  </form>
</AuthShell>
