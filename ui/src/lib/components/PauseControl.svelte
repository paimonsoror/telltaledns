<script lang="ts">
  // REQ: FLT-009 (T7.1) — pause blocking for everyone for a while (the "let me in" button,
  // often on a phone), see when it turns back on, and resume early. Group pauses show as a
  // count that links to Groups.
  import { api, type S } from '../api';
  import { can } from '../session.svelte';
  import { poll } from '../poll';
  import { href } from '../router.svelte';
  import Icon from './Icon.svelte';

  let nodes = $state<S['BlockingNode'][]>([]);
  let open = $state(false);
  let busy = $state(false);
  let error = $state<string | null>(null);
  const writable = $derived(can('operator'));
  let wrap = $state<HTMLElement | undefined>();
  // The menu closes on Escape or a click anywhere else.
  function outside(e: MouseEvent) {
    if (open && wrap && !wrap.contains(e.target as Node)) open = false;
  }
  function key(e: KeyboardEvent) {
    if (open && e.key === 'Escape') open = false;
  }

  async function load() {
    try {
      nodes = (await api.blocking()).items;
    } catch {
      // Not fatal: the control just shows nothing until the next poll.
    }
  }
  $effect(() => poll(load, 15_000));

  // Everyone's pause, as the longest time left on any node (they're paused together).
  const everyone = $derived(
    Math.max(0, ...nodes.flatMap((n) => n.pauses.filter((p) => !p.group).map((p) => p.secondsLeft))),
  );
  const groups = $derived(new Set(nodes.flatMap((n) => n.pauses.filter((p) => p.group).map((p) => p.group))).size);
  const left = (s: number) => (s >= 3600 ? `${Math.round(s / 360) / 10} h` : `${Math.max(1, Math.round(s / 60))} min`);

  async function act(fn: () => Promise<unknown>) {
    busy = true;
    error = null;
    try {
      await fn();
      open = false;
      await load();
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }
</script>

{#if everyone > 0}
  <span class="paused" data-testid="blocking-paused" role="status">
    <Icon name="pause" size={14} />
    <span>Blocking paused · {left(everyone)} left</span>
    {#if writable}
      <button class="link small" disabled={busy} onclick={() => act(() => api.blockingResume({}))}>Resume</button>
    {/if}
  </span>
{:else}
  {#if groups > 0}
    <a class="group-paused small" href={href('/groups')} data-testid="groups-paused"
      >{groups} group{groups === 1 ? '' : 's'} paused</a
    >
  {/if}
  {#if writable}
    <span class="pause-menu" bind:this={wrap}>
      <button class="icon-btn" title="Pause blocking" aria-label="Pause blocking" aria-expanded={open} aria-haspopup="menu" onclick={() => (open = !open)}
        ><Icon name="pause" /></button
      >
      {#if open}
      <div class="menu" role="menu">
        <p class="small muted">Turn blocking off for everyone for:</p>
        {#each [5, 15, 60] as m (m)}
          <button role="menuitem" disabled={busy} onclick={() => act(() => api.blockingPause({ minutes: m }))}
            >{m < 60 ? `${m} minutes` : '1 hour'}</button
          >
        {/each}
        {#if error}<p class="small bad-text">{error}</p>{/if}
      </div>
      {/if}
    </span>
  {/if}
{/if}

<svelte:window onclick={outside} onkeydown={key} />

<style>
  .paused {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 10px;
    border-radius: 999px;
    background: color-mix(in srgb, var(--warn) 18%, transparent);
    color: var(--warn-strong, var(--text));
    font-size: 0.85rem;
    font-weight: 600;
    white-space: nowrap;
  }
  .group-paused {
    white-space: nowrap;
    color: var(--warn-strong, var(--warn));
  }
  .pause-menu {
    position: relative;
  }
  .menu {
    position: absolute;
    right: 0;
    top: calc(100% + 6px);
    z-index: 30;
    display: grid;
    gap: 6px;
    min-width: 200px;
    padding: 10px;
    border-radius: 10px;
    background: var(--surface);
    border: 1px solid var(--border);
    box-shadow: var(--shadow, 0 4px 16px rgb(0 0 0 / 15%));
  }
  .menu p {
    margin: 0 0 2px;
  }
  .bad-text {
    color: var(--bad);
    margin: 0;
  }
</style>
