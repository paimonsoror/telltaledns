<script lang="ts">
  // REQ: OBS-033 — the Changes toggle and "Note…" (`part="head"`, in the page header), and the
  // note form and, in the Advanced view, the kind filter (`part="body"`, below it): one set for
  // every time chart on the page.
  import { api } from '../api';
  import { can } from '../session.svelte';
  import { changes, KINDS } from '../annotations.svelte';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';

  let { part = 'head', advanced = false }: { part?: 'head' | 'body'; advanced?: boolean } = $props();

  let text = $state('');
  let when = $state('');
  let saving = $state(false);
  let error = $state<unknown>(null);

  async function add(e: SubmitEvent) {
    e.preventDefault();
    saving = true;
    error = null;
    try {
      await api.annotate({ text: text.trim(), time: when ? new Date(when).toISOString() : undefined });
      text = '';
      when = '';
      changes.noting = false;
      if (!changes.show) changes.toggle(true);
      await changes.refresh();
    } catch (err) {
      error = err;
    } finally {
      saving = false;
    }
  }
</script>

{#if part === 'head'}
<div class="changes-controls">
  <label class="small toggle">
    <input
      type="checkbox"
      checked={changes.show}
      onchange={(e) => changes.toggle(e.currentTarget.checked)}
      data-testid="changes-toggle"
    />
    Changes
  </label>
  <HelpButton id="change-markers" />
  {#if can('operator')}
    <button type="button" class="small" aria-expanded={changes.noting} onclick={() => (changes.noting = !changes.noting)} data-testid="note-open">Note…</button>
  {/if}
</div>
{:else}
{#if changes.noting}
  <form class="card note-form" onsubmit={add} data-testid="note-form">
    <label class="field grow">
      What happened
      <input
        maxlength="200"
        required
        bind:value={text}
        placeholder="moved the access point to the hallway"
        data-testid="note-text"
      />
    </label>
    <label class="field">
      When <span class="muted small">(optional, up to 7 days back)</span>
      <input type="datetime-local" bind:value={when} data-testid="note-time" />
    </label>
    <div class="actions">
      <button class="primary" type="submit" disabled={saving || !text.trim()}>Add note</button>
      <button type="button" onclick={() => (changes.noting = false)}>Cancel</button>
    </div>
    <ErrorNote {error} />
    <p class="muted small">Shows on every time chart of every node. Notes can't be edited or deleted; add a correcting one.</p>
  </form>
{/if}

{#if advanced && changes.show}
  <div class="kinds" role="group" aria-label="Kinds of changes shown">
    {#each KINDS as k (k.id)}
      <button
        type="button"
        class="chip"
        aria-pressed={!changes.hidden.includes(k.id)}
        onclick={() => changes.setKind(k.id, changes.hidden.includes(k.id))}>{k.label}</button
      >
    {/each}
  </div>
{/if}
{/if}

<style>
  .changes-controls {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }
  .toggle {
    display: inline-flex;
    align-items: center;
    gap: 4px;
  }
  .note-form {
    display: flex;
    flex-wrap: wrap;
    gap: 10px 14px;
    align-items: flex-end;
  }
  .note-form .grow {
    flex: 2 1 260px;
  }
  .note-form .field {
    flex: 1 1 180px;
  }
  .note-form .actions {
    display: flex;
    gap: 8px;
  }
  .note-form p {
    flex-basis: 100%;
    margin: 0;
  }
  .kinds {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }
  .chip {
    min-height: 28px;
    padding: 2px 10px;
    border-radius: 999px;
    font-size: 12.5px;
  }
  .chip[aria-pressed='true'] {
    background: var(--accent);
    color: var(--accent-text);
    border-color: var(--accent);
  }
</style>
