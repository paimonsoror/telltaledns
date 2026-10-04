<script lang="ts">
  import { ApiError } from '../api';

  let { error }: { error: unknown } = $props();
  const message = $derived(error instanceof Error ? error.message : String(error));
  const hint = $derived(error instanceof ApiError ? error.hint : undefined);
</script>

{#if error}
  <div class="notice bad" role="alert">
    <strong>{message}</strong>
    {#if hint}<div class="muted small">{hint}</div>{/if}
  </div>
{/if}
