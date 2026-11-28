<!-- REQ: API-013 (ADR-190) — the banner of a test language pack, on every page, in a node of its own
  before the app: sticky, above every overlay of the UI (a stylesheet z-index of 100; the app's fixed and
  sticky layers move down by its height, `--devpack-h`, set through the CSSOM). English on purpose: a pack
  must not change what it says, so it holds no message of the layer; all its text is under translate="no"
  and lang="en", which the text lint and the pseudo-locale tests hold as kept as written. Left to right
  whatever the pack's direction. The file's name is shown without forbidden code points, at most 48
  characters, isolated for direction; the fingerprint (12 hex digits of its SHA-256) is its identity. -->
<script lang="ts">
  import { languageName, shownName } from '../i18n/names';
  import type { View } from './lifecycle';

  type Actions = { remove(): void; dismiss(): void; once(): void; reload(): void };
  let { view: first, actions }: { view: View; actions: Actions } = $props();
  // svelte-ignore state_referenced_locally
  let view = $state<View>(first);

  /** Called by the pack's code when what the banner says changes. */
  export function set(next: View) {
    view = next;
  }

  let el = $state<HTMLElement | null>(null);
  $effect(() => {
    const node = el;
    if (!node) return;
    const root = document.documentElement;
    const height = () => root.style.setProperty('--devpack-h', `${node.offsetHeight}px`);
    const ro = new ResizeObserver(height);
    ro.observe(node);
    height();
    return () => {
      ro.disconnect();
      root.style.removeProperty('--devpack-h');
    };
  });
  const name = $derived('name' in view ? shownName(view.name) : '');
  const finger = $derived('sha' in view ? view.sha.slice(0, 12) : '');
  const language = $derived('tag' in view ? (languageName(view.tag, view.tag) ?? view.tag) : '');
</script>

{#if view.kind !== 'none'}
  <div class="devpack" class:notice={view.kind === 'notice'} translate="no" lang="en" dir="ltr" bind:this={el} data-testid="devpack-banner">
    <aside aria-label="Test language pack">
      <p data-testid="devpack-says">
        {#if view.kind === 'notice'}
          The test language pack {#if name}<bdi>{name}</bdi>{/if} was removed:
          {#if view.gone === 'upgrade'}TelltaleDNS was updated. Download the template again and check your file: translations whose English didn't change still apply.
          {:else if view.gone === 'expired'}it was loaded 7 days ago.
          {:else if view.gone === 'damaged'}the copy kept in this browser couldn't be read.
          {:else if view.gone === 'failed'}it could not be checked twice in a row. Check the file again under Settings.
          {:else}a page could not be drawn with it.{/if}
        {:else if view.kind === 'active'}
          Test language pack: <bdi>{name}</bdi> ({language}, fingerprint <span class="mono">{finger}</span>). Labels come from that file, not from TelltaleDNS.
        {:else if view.kind === 'paused' && view.why === 'param'}
          The test language pack <bdi>{name}</bdi> is paused for this page load: the address asks for a language.
        {:else if view.kind === 'paused' && view.why === 'user'}
          The test language pack <bdi>{name}</bdi> is paused: another user of this browser loaded it.
        {:else if view.kind === 'paused'}
          The test language pack <bdi>{name}</bdi> is paused on this page.
        {:else if view.kind === 'unchecked'}
          The test language pack <bdi>{name}</bdi> could not be checked, so this page is in your usual language. Reload to try again.
        {:else if view.kind === 'updated'}
          TelltaleDNS was updated: the test pack goes away when you reload.
        {:else}
          Signed in: loading the test pack.
        {/if}
      </p>
      <span class="actions">
        {#if view.kind === 'notice'}
          <button onclick={actions.dismiss} aria-label="Dismiss this notice">Dismiss</button>
        {/if}
        {#if view.kind === 'updated' || view.kind === 'unchecked'}
          <button onclick={actions.reload} aria-label="Reload this page">Reload</button>
        {/if}
        {#if view.kind === 'paused' && view.why !== 'param'}
          <button onclick={actions.once} aria-label="Show the test language pack on this page, for one page load" data-testid="devpack-once">Show the test pack on this page</button>
        {/if}
        {#if view.kind === 'active'}
          <a href="#/settings?tab=account" aria-label="Details: Settings, Account">Details</a>
        {/if}
        {#if view.kind === 'active' || view.kind === 'paused' || view.kind === 'unchecked'}
          <button class="danger" onclick={actions.remove} aria-label="Remove the test language pack and reload" data-testid="devpack-remove">Remove</button>
        {/if}
      </span>
    </aside>
  </div>
{/if}

<style>
  :global(.devpack-host) {
    position: sticky;
    top: 0;
    z-index: 100;
  }
  .devpack {
    background: var(--warn);
    color: #1b1300;
    border-bottom: 1px solid rgb(0 0 0 / 25%);
    font: 14px/1.4 system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
  }
  .devpack.notice {
    background: var(--surface);
    color: var(--text);
    border-bottom-color: var(--border);
  }
  aside {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px 12px;
    padding: 6px 16px;
  }
  p {
    margin: 0;
    flex: 1 1 16rem;
    min-width: 0;
    overflow-wrap: anywhere;
  }
  .actions {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
  }
  .mono {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  }
  a {
    color: inherit;
    text-decoration: underline;
  }
</style>
