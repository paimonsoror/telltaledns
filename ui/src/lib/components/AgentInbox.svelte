<script lang="ts">
  // REQ: AGT-007 (T7.1) — a header pill while agents' plans wait for an operator.
  import { api } from '../api';
  import { can } from '../session.svelte';
  import { poll } from '../poll';
  import { href } from '../router.svelte';

  let waiting = $state(0);
  $effect(() => {
    if (!can('operator')) return;
    return poll(async () => {
      try {
        waiting = (await api.plans()).items.filter((p) => p.state === 'pending').length;
      } catch {
        // The header stays quiet if plans can't be read.
      }
    }, 15000);
  });
</script>

{#if waiting > 0}
  <a class="pill" href={href('/agent-changes')} data-testid="agent-inbox">
    {waiting} agent change{waiting === 1 ? '' : 's'} to review
  </a>
{/if}

<style>
  .pill {
    display: inline-flex;
    align-items: center;
    padding: 4px 10px;
    border-radius: 999px;
    background: color-mix(in srgb, var(--warn) 18%, transparent);
    color: var(--warn-strong, var(--text));
    font-size: 0.85rem;
    font-weight: 600;
    white-space: nowrap;
  }
</style>
