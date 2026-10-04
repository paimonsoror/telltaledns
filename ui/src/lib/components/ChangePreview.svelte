<script lang="ts">
  // REQ: API-011, ADR-036 — before a change is saved: what it will do, in a sentence and a
  // diagram.
  import type { FlowPath } from '../help';
  import FlowDiagram from './FlowDiagram.svelte';

  let {
    sentence,
    highlight,
    device,
    name,
  }: { sentence: string; highlight: FlowPath; device?: string; name?: string } = $props();
</script>

<div class="preview" data-testid="change-preview">
  <p><b>What this will do:</b> {sentence}</p>
  <FlowDiagram {highlight} {device} {name} />
</div>

<style>
  .preview {
    border: 1px dashed var(--border);
    border-radius: 8px;
    padding: 10px 12px;
  }
  .preview p {
    margin: 0 0 6px;
  }
</style>
