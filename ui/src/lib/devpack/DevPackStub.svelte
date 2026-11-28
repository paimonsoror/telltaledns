<!-- REQ: API-013 (ADR-190) — Settings, Account: "Test a language pack". The first load holds only this: a
  heading and Open; the card (with its sentence) is a chunk of its own, loaded on Open, or at once while
  this browser keeps a pack or a notice about one. In the Advanced view, and in the Simple view too while
  a pack or a notice is there (ADR-036: the Advanced view never hides what changes behavior). A tab opened
  before an upgrade asks for the chunk the new server no longer has: it says to reload. -->
<script lang="ts">
  import type { Component } from 'svelte';
  import { tr } from '../i18n';
  import { devpack } from '../i18n/devpack';
  import { currentMode } from '../mode.svelte';
  const { t } = tr('devPackStub');

  let Card = $state<Component | null>(null);
  let stale = $state(false);
  const open = () =>
    import('./DevPackCard.svelte').then(
      (m) => (Card = m.default),
      () => (stale = true),
    );
  if (devpack.active) void open();
</script>

{#if currentMode() === 'advanced' || devpack.active}
  <section class="card" data-testid="devpack-card" aria-labelledby="devpack-heading">
    <h2 id="devpack-heading">{t('Test a language pack')}</h2>
    {#if Card}
      <Card />
    {:else if stale}
      <p role="status" data-testid="devpack-stale">{t('TelltaleDNS was updated: reload this page.')}</p>
      <button onclick={() => location.reload()}>{t('Reload')}</button>
    {:else}
      <button onclick={open} data-testid="devpack-open">{t('Open')}</button>
    {/if}
  </section>
{/if}
