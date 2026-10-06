<script lang="ts" module>
  // REQ: API-002 (T7.5, ADR-069) — add, change, remove, or revert upstreams, upstream groups,
  // lists, and groups from the UI. Each change is previewed (dry run: what it does, warnings)
  // before it's applied; on a Git-managed node the result says what to add to Git.
  export type Field = {
    key: string;
    label: string;
    type: 'text' | 'number' | 'select' | 'multi' | 'lines' | 'bool';
    options?: string[];
    placeholder?: string;
    help?: string;
    /** Only in the Advanced view. */
    advanced?: boolean;
    /** The value a new entry starts with. */
    initial?: unknown;
  };
</script>

<script lang="ts">
  import { api, type S } from '../api';
  import { can } from '../session.svelte';
  import { currentMode } from '../mode.svelte';
  import Drawer from './Drawer.svelte';
  import ErrorNote from './ErrorNote.svelte';
  import KeepInGit from './KeepInGit.svelte';
  import HelpButton from './HelpButton.svelte';

  let {
    kind,
    path,
    title,
    noun,
    fields,
    summary,
    onchanged,
  }: {
    kind: 'upstream' | 'upstream_group' | 'list' | 'group';
    path: 'upstreams' | 'upstream-groups' | 'lists' | 'groups';
    title: string;
    noun: string;
    fields: Field[];
    summary: (def: Record<string, unknown>) => string;
    onchanged?: () => void;
  } = $props();

  let entries = $state<S['ConfigEntry'][]>([]);
  let error = $state<unknown>(null);
  let editing = $state<{ name: string; isNew: boolean; values: Record<string, unknown> } | null>(null);
  let preview = $state<S['ConfigChange'] | null>(null);
  let result = $state<S['ConfigChange'] | null>(null);
  let busy = $state(false);
  let formError = $state<unknown>(null);
  const writable = $derived(can('operator'));
  const advanced = $derived(currentMode() === 'advanced');
  const shown = $derived(fields.filter((f) => advanced || !f.advanced));

  async function load() {
    try {
      entries = (await api.configEntries(kind)).items;
      error = null;
    } catch (e) {
      error = e;
    }
  }
  $effect(() => {
    void kind;
    void load();
  });

  const badge: Record<string, [string, string]> = {
    file: ['config file', ''],
    added: ['added here', 'ok'],
    override: ['overrides the file', 'warn'],
    hidden: ['hidden', 'bad'],
  };

  function open(e?: S['ConfigEntry']) {
    preview = null;
    result = null;
    formError = null;
    const def = (e?.definition ?? {}) as Record<string, unknown>;
    const initial = e ? {} : Object.fromEntries(fields.filter((f) => f.initial !== undefined).map((f) => [f.key, f.initial]));
    editing = { name: e?.name ?? '', isNew: !e, values: { ...initial, ...def } };
  }

  // The body: the fields shown, with empty ones left out (the defaults apply); other fields of
  // an existing entry are kept as they were.
  function body(): Record<string, unknown> {
    const v = { ...editing!.values };
    delete v.name;
    for (const f of fields) {
      const x = v[f.key];
      if (x === '' || x === null || x === undefined || (Array.isArray(x) && x.length === 0 && f.type !== 'multi')) delete v[f.key];
    }
    return v;
  }

  async function check(e: SubmitEvent) {
    e.preventDefault();
    if (!editing) return;
    busy = true;
    formError = null;
    try {
      preview = await api.putEntry(path, editing.name.trim(), body(), true);
    } catch (err) {
      formError = err;
      preview = null;
    } finally {
      busy = false;
    }
  }
  async function apply() {
    if (!editing) return;
    busy = true;
    try {
      result = await api.putEntry(path, editing.name.trim(), body(), false);
      preview = null;
      await load();
      onchanged?.();
      if (!result.keepInGit) editing = null;
    } catch (err) {
      formError = err;
    } finally {
      busy = false;
    }
  }
  async function remove(e: S['ConfigEntry']) {
    busy = true;
    error = null;
    try {
      result = await api.deleteEntry(path, e.name);
      await load();
      onchanged?.();
      if (result.keepInGit) editing = { name: e.name, isNew: false, values: {} };
    } catch (err) {
      error = err;
    } finally {
      busy = false;
    }
  }
  const lines = (v: unknown) => (Array.isArray(v) ? v.join('\n') : '');
  const toLines = (s: string) => s.split('\n').map((x) => x.trim()).filter(Boolean);
</script>

<section class="card" data-testid={`editor-${kind}`}>
  <div class="head">
    <h2>{title}<HelpButton id="config-sources" /></h2>
    {#if writable}<button onclick={() => open()}>Add {noun}</button>{/if}
  </div>
  <ErrorNote {error} />
  {#if entries.length === 0}
    <p class="empty">None yet.</p>
  {:else}
    <div class="table-wrap">
      <table class="compact">
        <tbody>
          {#each entries as e (e.name)}
            {@const [label, cls] = badge[e.source] ?? [e.source, '']}
            <tr data-testid="entry-row">
              <td><strong>{e.name}</strong><span class="badge {cls}">{label}</span></td>
              <td class="small muted">{e.definition ? summary(e.definition as Record<string, unknown>) : 'left out of the configuration'}</td>
              {#if writable}
                <td class="actions">
                  {#if e.source !== 'hidden'}<button class="link small" onclick={() => open(e)}>Edit</button>{/if}
                  {#if e.source === 'override' || e.source === 'hidden'}
                    <button class="link small" disabled={busy} onclick={() => remove(e)}>Revert to the file</button>
                  {:else}
                    <button class="link small danger" disabled={busy} onclick={() => remove(e)}>Remove</button>
                  {/if}
                </td>
              {/if}
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</section>

{#if editing}
  <Drawer title={editing.isNew ? `Add ${noun}` : `${noun}: ${editing.name}`} onclose={() => (editing = null)}>
    {#if result?.keepInGit}
      <p class="notice ok small">{result.applied ? 'Saved.' : ''}</p>
      <KeepInGit toml={result.keepInGit} />
      <button onclick={() => (editing = null)}>Done</button>
    {:else}
      <form class="form" onsubmit={check}>
        <label>
          Name
          <input class="mono" bind:value={editing.name} required readonly={!editing.isNew} aria-label="Name" />
        </label>
        {#each shown as f (f.key)}
          <label>
            {f.label}
            {#if f.type === 'select'}
              <select bind:value={editing.values[f.key]} aria-label={f.label}>
                <option value={undefined}>(default)</option>
                {#each f.options ?? [] as o (o)}<option value={o}>{o}</option>{/each}
              </select>
            {:else if f.type === 'multi'}
              <span class="multi" role="group" aria-label={f.label}>
                {#each f.options ?? [] as o (o)}
                  {@const arr = (editing.values[f.key] as string[] | undefined) ?? []}
                  <label class="check"
                    ><input
                      type="checkbox"
                      checked={arr.includes(o)}
                      onchange={(ev) =>
                        (editing!.values[f.key] = (ev.currentTarget as HTMLInputElement).checked
                          ? [...arr, o]
                          : arr.filter((x) => x !== o))}
                    />{o}</label
                  >
                {/each}
              </span>
            {:else if f.type === 'lines'}
              <textarea
                rows="4"
                class="mono"
                placeholder={f.placeholder}
                aria-label={f.label}
                value={lines(editing.values[f.key])}
                oninput={(ev) => (editing!.values[f.key] = toLines((ev.currentTarget as HTMLTextAreaElement).value))}
              ></textarea>
            {:else if f.type === 'bool'}
              <input type="checkbox" bind:checked={editing.values[f.key] as boolean} aria-label={f.label} />
            {:else if f.type === 'number'}
              <input type="number" bind:value={editing.values[f.key]} placeholder={f.placeholder} aria-label={f.label} />
            {:else}
              <input class="mono" bind:value={editing.values[f.key]} placeholder={f.placeholder} aria-label={f.label} />
            {/if}
            {#if f.help}<span class="muted small">{f.help}</span>{/if}
          </label>
        {/each}
        <ErrorNote error={formError} />
        {#if preview}
          <div class="preview" data-testid="entry-preview">
            <p><b>What this will do:</b> {preview.impact || 'Changes the configuration as shown.'}</p>
            {#each preview.warnings as w (w)}<p class="small warn-text">{w}</p>{/each}
          </div>
          <div class="row">
            <button type="button" class="primary" disabled={busy} onclick={apply}>Apply</button>
            <button type="button" onclick={() => (preview = null)}>Change it</button>
          </div>
        {:else}
          <div class="row"><button class="primary" disabled={busy || !editing.name.trim()}>Check</button></div>
        {/if}
      </form>
    {/if}
  </Drawer>
{/if}

<style>
  .head {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 8px;
  }
  .head h2 {
    margin: 0;
  }
  .badge {
    margin-left: 8px;
  }
  .actions {
    text-align: right;
    white-space: nowrap;
  }
  .actions button + button {
    margin-left: 10px;
  }
  .form {
    display: grid;
    gap: 12px;
  }
  .form label {
    display: grid;
    gap: 4px;
  }
  .multi {
    display: flex;
    flex-wrap: wrap;
    gap: 6px 14px;
  }
  .check {
    display: inline-flex !important;
    align-items: center;
    gap: 6px;
  }
  .preview {
    border: 1px dashed var(--border);
    border-radius: 8px;
    padding: 10px 12px;
  }
  .preview p {
    margin: 0 0 4px;
  }
  .warn-text {
    color: var(--warn-strong, var(--warn));
  }
  .row {
    display: flex;
    gap: 8px;
  }
  .danger {
    color: var(--bad);
  }
</style>
