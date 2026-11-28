<script lang="ts">
  // REQ: OBS-025 (T13.3) — devices by what they look like (Advanced dashboard).
  import { api, type S } from '../api';
  import { href } from '../router.svelte';
  import HelpButton from './HelpButton.svelte';
  import { tr } from '../i18n';
  const { t } = tr('devicesByType');

  let items = $state<S['DeviceIdentity'][]>([]);
  $effect(() => {
    api
      .identities()
      .then((r) => (items = r.items))
      .catch(() => (items = []));
  });
  const counts = $derived.by(() => {
    const m = new Map<string, number>();
    for (const i of items) m.set(i.class, (m.get(i.class) ?? 0) + 1);
    return [...m.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  });
</script>

<section class="card" data-testid="devices-by-type">
  <div class="card-head">
    <h2>{t('Devices by type')}<HelpButton id="identify" /></h2>
    <a href={href('/clients')} class="small">{t('Clients')}</a>
  </div>
  {#if counts.length === 0}
    <p class="empty">{t('No devices identified yet.')}</p>
  {:else}
    <table class="compact">
      <thead><tr><th>{t('Type')}</th><th class="num">{t('Devices')}</th></tr></thead>
      <tbody>
        {#each counts as [cls, n] (cls)}<tr><td translate="no">{cls}</td><td class="num">{n}</td></tr>{/each}
      </tbody>
    </table>
  {/if}
</section>
