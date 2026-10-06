<script lang="ts">
  import type { Snippet } from 'svelte';

  let { title, onclose, children }: { title: string; onclose: () => void; children: Snippet } = $props();
  let panel = $state<HTMLElement | undefined>();

  $effect(() => {
    panel?.focus();
  });

  function key(e: KeyboardEvent) {
    if (e.key === 'Escape') onclose();
  }
</script>

<svelte:window onkeydown={key} />

<div class="backdrop" role="presentation" onclick={onclose}></div>
<div class="drawer" role="dialog" aria-modal="true" aria-label={title} tabindex="-1" bind:this={panel}>
  <header>
    <h2>{title}</h2>
    <button class="link" onclick={onclose} aria-label="Close">✕</button>
  </header>
  <div class="body">{@render children()}</div>
</div>

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    background: rgb(0 0 0 / 35%);
    z-index: 20;
  }
  .drawer {
    position: fixed;
    top: 0;
    right: 0;
    bottom: 0;
    width: min(640px, 100vw);
    background: var(--bg);
    border-left: 1px solid var(--border);
    z-index: 21;
    display: flex;
    flex-direction: column;
    outline: none;
    /* Opened from a "?" inside a page heading, it would otherwise take the heading's size and
       weight: the body text's own type, whatever it sits in. */
    font: 14px/1.45 system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
    font-weight: 400;
    letter-spacing: normal;
    text-transform: none;
    text-align: left;
    white-space: normal;
  }
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 16px;
    border-bottom: 1px solid var(--border);
    background: var(--surface);
  }
  header h2 {
    margin: 0;
    word-break: break-all;
  }
  .body {
    overflow-y: auto;
    padding: 16px;
    display: grid;
    gap: 14px;
    align-content: start;
  }
</style>
