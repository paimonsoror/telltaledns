<script lang="ts">
  // REQ: API-011, ADR-036 — before a change is saved: what it will do, in a sentence and a
  // diagram.
  import type { FlowPath } from '../help';
  import type { S } from '../api';
  import FlowDiagram from './FlowDiagram.svelte';
  import SimulationCard from './SimulationCard.svelte';

  let {
    sentence,
    highlight,
    device,
    name,
    simulate,
  }: {
    sentence: string;
    highlight: FlowPath;
    device?: string;
    name?: string;
    /** REQ: OBS-024 — the change's dry run with `simulate`: offers "What would this have done?". */
    simulate?: () => Promise<S['Simulation'] | null | undefined>;
  } = $props();
</script>

<div class="preview" data-testid="change-preview">
  <p><b>What this will do:</b> {sentence}</p>
  <FlowDiagram {highlight} {device} {name} />
  {#if simulate}<SimulationCard run={simulate} />{/if}
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
