<script lang="ts">
  // REQ: OBS-035 (T14.13, ADR-140) — wall displays (admin): a revocable link for an unattended
  // screen that shows only the wall, optionally limited to some addresses. The link is shown
  // once, when it's made.
  import { api, type S } from '../api';
  import { ago, dateTime } from '../format';
  // REQ: API-011 — the card's own words; what the server sends stays as it is.
  import { t } from '../i18n';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';

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
  <h2>{t('settings.wall.title')}<HelpButton id="wall-display" /></h2>
  <p class="muted small">
    {t('settings.wall.about')}
  </p>
  <ErrorNote {error} />
  <form class="row" onsubmit={create}>
    <label class="small">{t('settings.wall.name')} <input bind:value={name} placeholder={t('settings.wall.namePlaceholder')} maxlength="64" required data-testid="display-name" /></label>
    <label class="small">{t('settings.wall.onlyFrom')} <input bind:value={networks} placeholder={t('settings.wall.networksPlaceholder')} data-testid="display-networks" /></label>
    <label class="small">{t('settings.wall.endsAfter')} <input bind:value={days} inputmode="numeric" placeholder={t('settings.wall.daysPlaceholder')} size="10" /></label>
    <button class="primary" disabled={busy || !name.trim()} data-testid="display-create">{t('settings.wall.make')}</button>
  </form>
  {#if made}
    <div class="notice ok" data-testid="display-link">
      <p><strong>{made.info.name}</strong>{t('settings.wall.linkNote')}</p>
      <p class="mono small link">{link(made)}</p>
      <button type="button" class="small" onclick={() => made && copy(made)}>{copied ? t('common.copied') : t('settings.wall.copyLink')}</button>
    </div>
  {/if}
  {#if items.length === 0}
    <p class="empty">{t('settings.wall.empty')}</p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead><tr><th>{t('settings.wall.colName')}</th><th>{t('settings.wall.colOnlyFrom')}</th><th>{t('settings.wall.colMadeBy')}</th><th>{t('settings.wall.colLastUsed')}</th><th>{t('settings.wall.colEnds')}</th><th></th></tr></thead>
        <tbody>
          {#each items as d (d.id)}
            <tr data-testid="display-row">
              <td><strong>{d.name}</strong></td>
              <td class="mono small">{d.networks.length ? d.networks.join(', ') : t('settings.wall.anywhere')}</td>
              <td class="small">{d.owner}</td>
              <td class="small">{d.lastUsedUnixSeconds ? ago(d.lastUsedUnixSeconds) : t('common.never')}</td>
              <td class="small">{d.expiresUnixSeconds ? dateTime(d.expiresUnixSeconds) : t('settings.wall.whenRevoked')}</td>
              <td class="num"><button class="link small danger" disabled={busy} onclick={() => revoke(d)} data-testid="display-revoke">{t('settings.wall.revoke')}</button></td>
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
