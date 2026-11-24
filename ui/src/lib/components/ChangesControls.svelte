<script lang="ts">
  // REQ: OBS-033 — the Changes toggle and "Note…" (`part="head"`, in the page header), and the
  // note form and, in the Advanced view, the kind filter (`part="body"`, below it): one set for
  // every time chart on the page.
  import { api } from '../api';
  import { can } from '../session.svelte';
  import { changes, KINDS } from '../annotations.svelte';
  import { t } from '../i18n';
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
<!-- Shaped like the time-range control next to it: a track, a switch, and Note… as a segment. -->
<div class="changes-controls">
  <label class="switch">
    <input
      type="checkbox"
      role="switch"
      checked={changes.show}
      onchange={(e) => changes.toggle(e.currentTarget.checked)}
      data-testid="changes-toggle"
    />
    {t('settings.changes.title')}
  </label>
  <HelpButton id="change-markers" />
  {#if can('operator')}
    <button type="button" class="note-btn" aria-expanded={changes.noting} onclick={() => (changes.noting = !changes.noting)} data-testid="note-open">{t('widgets.changes.noteOpen')}</button>
  {/if}
</div>
{:else}
{#if changes.noting}
  <form class="card note-form" onsubmit={add} data-testid="note-form">
    <label class="field grow">
      {t('widgets.changes.what')}
      <input
        maxlength="200"
        required
        bind:value={text}
        placeholder={t('widgets.changes.whatHint')}
        data-testid="note-text"
      />
    </label>
    <label class="field">
      {t('changes.plan.when')} <span class="muted small">{t('widgets.changes.whenHint')}</span>
      <input type="datetime-local" bind:value={when} data-testid="note-time" />
    </label>
    <div class="actions">
      <button class="primary" type="submit" disabled={saving || !text.trim()}>{t('widgets.changes.add')}</button>
      <button type="button" onclick={() => (changes.noting = false)}>{t('common.cancel')}</button>
    </div>
    <ErrorNote {error} />
    <p class="muted small">{t('widgets.changes.noteHelp')}</p>
  </form>
{/if}

{#if advanced && changes.show}
  <div class="kinds" role="group" aria-label={t('widgets.changes.kinds')}>
    {#each KINDS as k (k.id)}
      <button
        type="button"
        class="chip"
        aria-pressed={!changes.hidden.includes(k.id)}
        onclick={() => changes.setKind(k.id, changes.hidden.includes(k.id))}>{t(k.label)}</button
      >
    {/each}
  </div>
{/if}
{/if}

<style>
  .changes-controls {
    display: inline-flex;
    align-items: center;
    gap: 2px;
    padding: 3px 3px 3px 12px;
    border-radius: 999px;
    background: var(--surface-2);
    white-space: nowrap;
  }
  .note-btn {
    border: 0;
    border-radius: 999px;
    min-height: 28px;
    padding: 3px 12px;
    background: transparent;
    color: var(--muted);
  }
  .note-btn:hover,
  .note-btn[aria-expanded='true'] {
    background: var(--surface);
    color: var(--text);
    box-shadow: 0 1px 3px rgb(16 24 40 / 12%);
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
