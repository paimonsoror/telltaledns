<script lang="ts">
  // REQ: API-003 — first run: the one-time setup token creates the first admin.
  import { api } from '../lib/api';
  import { signedIn } from '../lib/session.svelte';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import AuthShell from './AuthShell.svelte';
  import { t } from '../lib/i18n';

  let setupToken = $state('');
  let username = $state('admin');
  let password = $state('');
  let confirm = $state('');
  let busy = $state(false);
  let error = $state<unknown>(null);

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    if (password !== confirm) {
      error = new Error(t('auth.setup.mismatch'));
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

<AuthShell title={t('auth.setup.title')}>
  <p class="muted">
    {t('auth.setup.introBefore')} <code>telltale auth setup-token</code> {t('auth.setup.introAfter')}
  </p>
  <form class="stack" onsubmit={submit}>
    <label class="field">{t('auth.setup.token')}
      <input name="setupToken" autocomplete="off" required bind:value={setupToken} />
    </label>
    <label class="field">{t('auth.setup.username')}
      <input name="username" autocomplete="username" required bind:value={username} />
    </label>
    <label class="field">{t('auth.setup.password')}
      <input name="password" type="password" autocomplete="new-password" minlength="10" required bind:value={password} />
    </label>
    <label class="field">{t('auth.setup.repeat')}
      <input name="confirm" type="password" autocomplete="new-password" minlength="10" required bind:value={confirm} />
    </label>
    <ErrorNote {error} />
    <button class="primary" type="submit" disabled={busy}>{busy ? t('auth.setup.creating') : t('auth.setup.create')}</button>
  </form>
</AuthShell>
