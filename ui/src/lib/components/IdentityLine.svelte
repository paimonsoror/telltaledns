<script lang="ts">
  // REQ: OBS-025 (T13.3, ADR-117) — what a device looks like, in one line: "Looks like a Roku
  // player (likely) · Roku · talks to roku.com", the group suggested for its kind, and the
  // evidence on request. A guess never names or moves a device on its own.
  import { api, type S } from '../api';
  import HelpButton from './HelpButton.svelte';

  let { identity }: { identity: S['DeviceIdentity'] | null | undefined } = $props();
  let evidence = $state<S['DeviceIdentity'] | null>(null);
  let open = $state(false);

  const article = (p: string) => (/^[aeiou]/i.test(p) ? 'an' : 'a');
  const line = $derived.by(() => {
    const i = identity;
    if (!i || !i.available) return '';
    if (i.source === 'override') return `Set as ${article(i.class)} ${i.class}`;
    if (i.level === 'unknown' || !i.product) return i.vendor ? `Made by ${i.vendor}` : '';
    return `Looks like ${article(i.product)} ${i.product} (${i.level})`;
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
      <span class="badge info" title="This group's settings ask for this kind of device. Add it from the address's menu: Add to group…"
        >{identity.suggestedGroup} suggested</span
      >
    {/if}
    {#if identity.source !== 'override'}
      <button class="link small" onclick={toggle} aria-expanded={open}>{open ? 'Hide why' : 'Why?'}</button><HelpButton id="identify" />
    {/if}
    {#if open && evidence?.evidence}
      {@const e = evidence.evidence}
      <ul class="why">
        {#if e.domains.length}<li>Talks to {e.domains.map((d) => d.name).join(', ')}</li>{/if}
        {#if evidence.vendor}<li>MAC vendor {evidence.vendor}{e.macPrefix ? ` (${e.macPrefix})` : ''}</li>{/if}
        {#if e.matchedName}<li>Calls itself “{e.matchedName}”</li>{/if}
        {#if e.runnerUp}<li class="muted">Could also be {article(e.runnerUp.product)} {e.runnerUp.product}</li>{/if}
        <li class="muted">Not right? Name the device and set what it is (“What it is”).</li>
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
