<script lang="ts">
  // A label with a short explanation on hover or keyboard focus (a tooltip that also works
  // without a mouse; the text is the label's accessible description). The bubble is placed in
  // the viewport (position: fixed), so a scrolling table around the label can't clip it.
  import type { Snippet } from 'svelte';

  let { text, children }: { text: string; children: Snippet } = $props();
  const id = `tip-${Math.random().toString(36).slice(2, 9)}`;
  let el = $state<HTMLButtonElement | null>(null);
  let pos = $state<{ top: number; left: number } | null>(null);

  const WIDTH = 320;
  function show() {
    if (!el) return;
    const r = el.getBoundingClientRect();
    const left = Math.max(8, Math.min(r.left, window.innerWidth - Math.min(WIDTH, window.innerWidth * 0.8) - 8));
    // Below the label, or above it when there's no room below.
    const below = r.bottom + 6;
    pos = { top: below + 90 > window.innerHeight ? Math.max(8, r.top - 96) : below, left };
  }
  const hide = () => (pos = null);
</script>

<button
  type="button"
  class="tip"
  aria-describedby={id}
  bind:this={el}
  onpointerenter={show}
  onpointerleave={hide}
  onfocus={show}
  onblur={hide}
  onkeydown={(e) => e.key === 'Escape' && hide()}
>
  {@render children()}
  <span
    class="bubble"
    class:open={pos != null}
    role="tooltip"
    {id}
    style={pos ? `top:${pos.top}px;left:${pos.left}px` : ''}>{text}</span
  >
</button>

<style>
  .tip {
    display: inline;
    padding: 0;
    border: 0;
    background: none;
    color: inherit;
    font: inherit;
    text-align: inherit;
    text-decoration: underline dotted var(--muted);
    text-underline-offset: 3px;
    cursor: help;
    outline: none;
  }
  .tip:focus-visible {
    outline: 2px solid var(--focus, var(--accent));
    outline-offset: 2px;
    border-radius: 3px;
  }
  .bubble {
    position: fixed;
    z-index: 50;
    width: max-content;
    max-width: min(320px, 80vw);
    padding: 8px 10px;
    border-radius: 8px;
    background: var(--surface);
    color: var(--text);
    border: 1px solid var(--border);
    box-shadow: var(--shadow, 0 4px 16px rgb(0 0 0 / 15%));
    font-size: 0.8125rem;
    font-weight: 400;
    line-height: 1.4;
    white-space: normal;
    text-align: left;
    text-decoration: none;
    pointer-events: none;
    opacity: 0;
    visibility: hidden;
    transition: opacity 0.12s;
  }
  .bubble.open {
    opacity: 1;
    visibility: visible;
  }
</style>
