<script lang="ts">
  // REQ: OBS-025 (T13.3, ADR-117) — what a device looks like, in one line: "Looks like a Roku
  // player (likely) · Roku · talks to roku.com", the group suggested for its kind, and the
  // evidence on request. A guess never names or moves a device on its own.
  import { api, type S } from '../api';
  import { t, type MessageKey } from '../i18n';
  import HelpButton from './HelpButton.svelte';

  let { identity }: { identity: S['DeviceIdentity'] | null | undefined } = $props();
  let evidence = $state<S['DeviceIdentity'] | null>(null);
  let open = $state(false);

  // Which English article a product or kind takes ('an' before a vowel); Chinese has neither.
  const articleKey = (family: 'setAs' | 'looks' | 'couldBe', p: string): MessageKey =>
    /^[aeiou]/i.test(p)
      ? (`deviceWidgets.identity.${family}.an` as MessageKey)
      : (`deviceWidgets.identity.${family}.a` as MessageKey);
  const line = $derived.by(() => {
    const i = identity;
    if (!i || !i.available) return '';
    if (i.source === 'override') return t(articleKey('setAs', i.class), { what: i.class });
    if (i.level === 'unknown' || !i.product) return i.vendor ? t('deviceWidgets.identity.madeBy', { vendor: i.vendor }) : '';
    return t(articleKey('looks', i.product), { product: i.product, level: i.level });
  });

  async function toggle() {
    open = !open;
    if (open && identity && !evidence) {
      evidence = await api.identity(identity.client).catch(() => null);
    }
  }
</script>

{#if line && identity}
  <div class="identity small" data-testid="identity-line">
    <span>{line}</span>
    {#if identity.source !== 'override' && identity.level !== 'unknown' && identity.vendor}<span class="muted">· {identity.vendor}</span>{/if}
    {#if identity.suggestedGroup}
      <span class="badge info" title={t('deviceWidgets.identity.suggestedTitle')}
        >{t('deviceWidgets.identity.suggested', { group: identity.suggestedGroup })}</span
      >
    {/if}
    {#if identity.source !== 'override'}
      <button class="link small" onclick={toggle} aria-expanded={open}>{open ? t('deviceWidgets.identity.hideWhy') : t('queries.why')}</button><HelpButton id="identify" />
    {/if}
    {#if open && evidence?.evidence}
      {@const e = evidence.evidence}
      <ul class="why">
        {#if e.domains.length}<li>{t('deviceWidgets.identity.talksTo', { domains: e.domains.map((d) => d.name).join(', ') })}</li>{/if}
        {#if evidence.vendor}<li>{t('deviceWidgets.identity.macVendor', { vendor: evidence.vendor, prefix: e.macPrefix ? ` (${e.macPrefix})` : '' })}</li>{/if}
        {#if e.matchedName}<li>{t('deviceWidgets.identity.callsItself', { name: e.matchedName })}</li>{/if}
        {#if e.runnerUp}<li class="muted">{t(articleKey('couldBe', e.runnerUp.product), { product: e.runnerUp.product })}</li>{/if}
        <li class="muted">{t('deviceWidgets.identity.notRight')}</li>
      </ul>
    {/if}
  </div>
{/if}

<style>
  .identity {
    display: flex;
    flex-wrap: wrap;
    gap: 4px 8px;
    align-items: baseline;
  }
  .why {
    flex-basis: 100%;
    margin: 2px 0 0;
    padding-left: 18px;
  }
</style>
