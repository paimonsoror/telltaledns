<script lang="ts">
  import { ApiError } from '../api';

  // `quiet`: no `role="alert"` of its own, for a note that sits in a live region of its page (the
  // quick rule form's check as you type), which announces it politely.
  let { error, quiet = false }: { error: unknown; quiet?: boolean } = $props();
  const message = $derived(error instanceof Error ? error.message : String(error));
  const hint = $derived(error instanceof ApiError ? error.hint : undefined);
</script>

{#if error}
  <div class="notice bad" role={quiet ? undefined : 'alert'}>
    <strong>{message}</strong>
    {#if hint}<div class="muted small">{hint}</div>{/if}
  </div>
{/if}
