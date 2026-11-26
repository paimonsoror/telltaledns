<script lang="ts">
  // REQ: OBS-035 (T14.13, ADR-140) — wall displays (admin): a revocable link for an unattended
  // screen that shows only the wall, optionally limited to some addresses. The link is shown
  // once, when it's made.
  import { api, type S } from '../api';
  import { ago, dateTime } from '../format';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';
  import { tr } from '../i18n';
  import T from '../i18n/T.svelte';
  const { t } = tr('wallDisplays');

  let items = $state<S['DisplayInfo'][]>([]);
  let error = $state<unknown>(null);
  let name = $state('');
  let networks = $state('');
  let days = $state('');
  let busy = $state(false);
  let made = $state<S['NewDisplay'] | null>(null);
  let copied = $state(false);

  async function load() {
    try {
      items = (await api.displays()).items;
      error = null;
    } catch (e) {
      error = e;
    }
  }
  $effect(() => void load());

  const link = (n: S['NewDisplay']) => `${location.origin}${location.pathname}${n.link}`;
  async function create(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    try {
      made = await api.createDisplay({
        name: name.trim(),
        networks: networks.split(/[\s,]+/).filter(Boolean),
        expiresInDays: days.trim() ? Number(days) : null,
      });
      name = networks = days = '';
      copied = false;
      await load();
    } catch (err) {
      error = err;
    } finally {
      busy = false;
    }
  }
  async function revoke(d: S['DisplayInfo']) {
    busy = true;
    try {
      await api.revokeDisplay(d.id);
      if (made?.info.id === d.id) made = null;
      await load();
    } catch (err) {
      error = err;
    } finally {
      busy = false;
    }
  }
  async function copy(n: S['NewDisplay']) {
    try {
      await navigator.clipboard.writeText(link(n));
      copied = true;
    } catch {
      copied = false;
    }
  }
</script>

<section class="card" data-testid="wall-displays">
  <h2>{t('Wall displays')}<HelpButton id="wall-display" /></h2>
  <p class="muted small">
    {t('A link for a screen on the wall: open it once on that screen\'s browser and it stays signed in, showing only the wall (the traffic map, the flow, the service level, the heatmaps, and the live queries). It can\'t open any other page or change anything. Limit it to the screen\'s address if you can; revoke it here to sign the screen out.')}
  </p>
  <ErrorNote {error} />
  <form class="row" onsubmit={create}>
    <label class="small">{t('Name')} <input bind:value={name} placeholder={t('hallway')} maxlength="64" required data-testid="display-name" /></label>
    <label class="small">{t('Only from')} <input bind:value={networks} placeholder={t('192.168.2.40, 10.0.0.0/24 (optional)')} data-testid="display-networks" /></label>
    <label class="small">{t('Ends after')} <input bind:value={days} inputmode="numeric" placeholder={t('days (optional)')} size="10" /></label>
    <button class="primary" disabled={busy || !name.trim()} data-testid="display-create">{t('Make a link')}</button>
  </form>
  {#if made}
    <div class="notice ok" data-testid="display-link">
      <p>
        <T ctx="wallDisplays" msg={"<strong>{name}</strong>: open this on the wall's browser. It's shown only now."} params={{ name: made.info.name }}
          >{#snippet strong(text: string)}<strong translate="no">{text}</strong>{/snippet}</T
        >
      </p>
      <p class="mono small link" translate="no">{link(made)}</p>
      <button type="button" class="small" onclick={() => made && copy(made)}>{copied ? t('Copied') : t('Copy the link')}</button>
    </div>
  {/if}
  {#if items.length === 0}
    <p class="empty">{t('No wall displays.')}</p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead><tr><th>{t('Name')}</th><th>{t('Only from')}</th><th>{t('Made by')}</th><th>{t('Last used')}</th><th>{t('Ends')}</th><th></th></tr></thead>
        <tbody>
          {#each items as d (d.id)}
            <tr data-testid="display-row">
              <td><strong translate="no">{d.name}</strong></td>
              <td class="mono small">{d.networks.length ? d.networks.join(', ') : t('anywhere')}</td>
              <td class="small" translate="no">{d.owner}</td>
              <td class="small">{d.lastUsedUnixSeconds ? ago(d.lastUsedUnixSeconds) : t('never')}</td>
              <td class="small">{d.expiresUnixSeconds ? dateTime(d.expiresUnixSeconds) : t('when revoked')}</td>
              <td class="num"><button class="link small danger" disabled={busy} onclick={() => revoke(d)} data-testid="display-revoke">{t('Revoke')}</button></td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</section>

<style>
  .row {
    display: flex;
    flex-wrap: wrap;
    gap: 8px 12px;
    align-items: end;
  }
  .link {
    word-break: break-all;
  }
</style>
