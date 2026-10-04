<script lang="ts">
  // REQ: API-011, ADR-036 — the "?" beside a setting: opens a side panel with the topic in a
  // fixed order (summary, diagram, when, example, caution, term, docs). It never blocks the
  // form underneath (Escape or ✕ closes it).
  import { docsUrl, topic } from '../help';
  import Drawer from './Drawer.svelte';
  import FlowDiagram from './FlowDiagram.svelte';

  let { id }: { id: string } = $props();
  const t = $derived(topic(id));
  let open = $state(false);
</script>

<button
  type="button"
  class="help-btn"
  aria-label={`Help: ${t.title}`}
  title={t.title}
  data-help={id}
  onclick={(e) => {
    e.preventDefault();
    e.stopPropagation();
    open = true;
  }}>?</button
>

{#if open}
  <Drawer title={t.title} onclose={() => (open = false)}>
    <div class="help" data-testid="help-panel">
      <p class="lead">{t.summary}</p>
      {#if t.diagram}<FlowDiagram highlight={t.diagram} />{/if}
      {#if t.when}<h3>When you'd use it</h3><p>{t.when}</p>{/if}
      {#if t.example}<h3>Example</h3><p>{t.example}</p>{/if}
      {#if t.caution}<h3>Careful</h3><p class="notice warn">{t.caution}</p>{/if}
      {#if t.term}<p class="muted small">The DNS term for this is <b>{t.term}</b>.</p>{/if}
      {#if docsUrl(t)}<p><a href={docsUrl(t)} target="_blank" rel="noreferrer">Full documentation</a></p>{/if}
    </div>
  </Drawer>
{/if}

<style>
  .help-btn {
    display: inline-grid;
    place-items: center;
    width: 20px;
    height: 20px;
    margin-left: 6px;
    padding: 0;
    border-radius: 50%;
    border: 1px solid var(--border);
    background: var(--surface);
    color: var(--muted);
    font-size: 12px;
    font-weight: 700;
    line-height: 1;
    cursor: pointer;
    vertical-align: middle;
  }
  .help-btn:hover,
  .help-btn:focus-visible {
    color: var(--accent);
    border-color: var(--accent);
  }
  .help .lead {
    font-size: 1.05em;
  }
  .help h3 {
    margin: 16px 0 4px;
    font-size: 14px;
  }
</style>
