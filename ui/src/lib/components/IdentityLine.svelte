<script lang="ts">
  // REQ: OBS-025 (T13.3, ADR-117) — what a device looks like, in one line: "Looks like a Roku
  // player (likely) · Roku · talks to roku.com", the group suggested for its kind, and the
  // evidence on request. A guess never names or moves a device on its own.
  import { api, type S } from '../api';
  import HelpButton from './HelpButton.svelte';
  import { tr } from '../i18n';
  const { t } = tr('identityLine');

  let { identity }: { identity: S['DeviceIdentity'] | null | undefined } = $props();
  let evidence = $state<S['DeviceIdentity'] | null>(null);
  let open = $state(false);

  // REQ: API-012 — English's article (an or a, from the name) chooses between two whole messages.
  const an = (p: string) => /^[aeiou]/i.test(p);
  const line = $derived.by(() => {
    const i = identity;
    if (!i || !i.available) return '';
    if (i.source === 'override') return an(i.class) ? t('Set as an {kind}', { kind: i.class }) : t('Set as a {kind}', { kind: i.class });
    if (i.level === 'unknown' || !i.product) return i.vendor ? t('Made by {vendor}', { vendor: i.vendor }) : '';
    const p = { product: i.product, level: i.level };
    return an(i.product) ? t('Looks like an {product} ({level})', p) : t('Looks like a {product} ({level})', p);
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
    {#if identity.source !== 'override' && identity.level !== 'unknown' && identity.vendor}<span class="muted" translate="no">· {identity.vendor}</span>{/if}
    {#if identity.suggestedGroup}
      <span class="badge info" title={t('This group\'s settings ask for this kind of device. Add it from the address\'s menu: Add to group…')}
        >{t('{group} suggested', { group: identity.suggestedGroup })}</span
      >
    {/if}
    {#if identity.source !== 'override'}
      <button class="link small" onclick={toggle} aria-expanded={open}>{open ? t('Hide why') : t('Why?')}</button><HelpButton id="identify" />
    {/if}
    {#if open && evidence?.evidence}
      {@const e = evidence.evidence}
      <ul class="why">
        {#if e.domains.length}<li>{t('Talks to {domains}', { domains: e.domains.map((d) => d.name).join(', ') })}</li>{/if}
        {#if evidence.vendor}<li>{e.macPrefix ? t('MAC vendor {vendor} ({prefix})', { vendor: evidence.vendor, prefix: e.macPrefix }) : t('MAC vendor {vendor}', { vendor: evidence.vendor })}</li>{/if}
        {#if e.matchedName}<li>{t('Calls itself “{name}”', { name: e.matchedName })}</li>{/if}
        {#if e.runnerUp}<li class="muted">{an(e.runnerUp.product) ? t('Could also be an {product}', { product: e.runnerUp.product }) : t('Could also be a {product}', { product: e.runnerUp.product })}</li>{/if}
        <li class="muted">{t('Not right? Name the device and set what it is (“What it is”).')}</li>
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
