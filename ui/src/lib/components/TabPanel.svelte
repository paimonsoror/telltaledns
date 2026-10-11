<script lang="ts">
  // REQ: API-005 (ADR-121) — the open tab's content, labelled by its tab. Pages render only the
  // open tab inside, so a closed tab loads and polls nothing.
  import type { Snippet } from 'svelte';

  let { active, children }: { active: string; children: Snippet } = $props();
</script>

<div class="tabpanel" role="tabpanel" id="tabpanel" aria-labelledby="tab-{active}">
  {@render children()}
</div>

<style>
  .tabpanel {
    display: grid;
    gap: var(--gap);
    min-width: 0;
  }
</style>
