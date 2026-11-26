<script lang="ts" module>
  // REQ: API-002 (T7.5, ADR-069) — add, change, remove, or revert upstreams, upstream groups,
  // lists, and groups from the UI. Each change is previewed (dry run: what it does, warnings)
  // before it's applied; on a Git-managed node the result says what to add to Git.
  export type Field = {
    key: string;
    label: string;
    /** `secret`: typed, never shown back (T8.2, ADR-181: a router's key or password). */
    type: 'text' | 'number' | 'select' | 'multi' | 'lines' | 'bool' | 'secret';
    options?: string[];
    /** How `select`/`multi` options read (CLU-013: node IDs by their site or pod). */
    optionLabels?: Record<string, string>;
    placeholder?: string;
    /** A placeholder from the draft, its name, and the entry being edited (T8.2, ADR-181: whether
     *  a router's key is saved). */
    placeholderFor?: (
      values: Record<string, unknown>,
      name: string,
      entry?: { credentials?: Record<string, string> | null },
    ) => string;
    help?: string;
    /** Only in the Advanced view. */
    advanced?: boolean;
    /** The value a new entry starts with. */
    initial?: unknown;
    /** `lines` fields kept as text while editing and converted on Check (T9.7: schedule
     *  windows as `weekdays 21:00-07:00`). `fromText` throws to report a bad line. */
    toText?: (v: unknown) => string;
    fromText?: (s: string) => unknown;
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
  import SimulationCard from './SimulationCard.svelte';
  import { tk, tr, type Msg } from '../i18n';
  import T from '../i18n/T.svelte';
  const { t, m } = tr('configEditor');

  let {
    kind,
    path,
    title,
    noun,
    fields,
    summary,
    onchanged,
    help,
    rowAction,
    formAction,
    singleton = false,
    role,
    note,
    status,
    omit = [],
    notice = null,
  }: {
    kind: 'upstream' | 'upstream_group' | 'list' | 'group' | 'alert_destination' | 'alert_rule' | 'schedule' | 'ratelimit' | 'exclusions' | 'simulate' | 'rollout' | 'router';
    path: 'upstreams' | 'upstream-groups' | 'lists' | 'groups' | 'alerts/destinations' | 'alerts/rules' | 'schedules' | 'ratelimit' | 'exclusions' | 'simulate-settings' | 'cluster/rollout-settings' | 'routers';
    title: string;
    noun: string;
    fields: Field[];
    summary: (def: Record<string, unknown>) => string;
    onchanged?: () => void;
    help?: string;
    /** A button on each row (T9.6: "Send test"); `run` returns what to show. */
    rowAction?: { label: string; run: (name: string) => Promise<{ ok: boolean; text: string }> };
    /** A button in the form that tries the draft before saving (T9.12: "Test it"). */
    formAction?: { label: string; run: (body: Record<string, unknown>) => Promise<{ ok: boolean; text: string }> };
    /** One entry that always exists (the rate limit): no Add, and no Remove, only Revert to the file. */
    singleton?: boolean;
    /** Who may change it (CLU-013: the rollout settings are an admin's). */
    role?: 'operator' | 'admin';
    /** A sentence about the draft, under the fields (CLU-013: who gets a change first). */
    note?: (values: Record<string, unknown>) => string;
    /** A badge on a row from what the server says of the entry (T8.2, ADR-181: "key saved"). */
    status?: (e: S['ConfigEntry']) => { text: string; cls: string } | null;
    /** Keys of an entry the body never sends back (T8.2, ADR-181: a router's key files; the
     *  server keeps them, or replaces them with a pasted value's new file). */
    omit?: string[];
    /** A warning at the top of the form (T8.2, ADR-181: a page opened over plain HTTP). */
    notice?: string | null;
  } = $props();
  let formOut = $state<{ ok: boolean; text: string } | null>(null);
  async function runFormAction() {
    if (!formAction || !editing) return;
    formOut = { ok: true, text: t('Testing…') };
    try {
      formOut = await formAction.run(body());
    } catch (err) {
      formOut = { ok: false, text: err instanceof Error ? err.message : String(err) };
    }
  }
  let actionOut = $state<{ name: string; ok: boolean; text: string } | null>(null);
  async function runAction(name: string) {
    if (!rowAction) return;
    actionOut = { name, ok: true, text: t('Sending…') };
    try {
      actionOut = { name, ...(await rowAction.run(name)) };
    } catch (err) {
      actionOut = { name, ok: false, text: err instanceof Error ? err.message : String(err) };
    }
  }

  let entries = $state<S['ConfigEntry'][]>([]);
  let error = $state<unknown>(null);
  let editing = $state<{ name: string; isNew: boolean; values: Record<string, unknown>; entry?: S['ConfigEntry'] } | null>(null);
  // Text of fields with `toText`/`fromText`, while editing.
  let texts = $state<Record<string, string>>({});
  let preview = $state<S['ConfigChange'] | null>(null);
  let result = $state<S['ConfigChange'] | null>(null);
  let busy = $state(false);
  let formError = $state<unknown>(null);
  const writable = $derived(can(role ?? 'operator'));
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

  const badge: Record<string, [Msg, string]> = {
    file: [m('config file'), ''],
    added: [m('added here'), 'ok'],
    override: [m('overrides the file'), 'warn'],
    hidden: [m('hidden'), 'bad'],
  };
  /** REQ: API-012 — an entry's source badge: the words and the class; a source the UI doesn't know
   * as it is (the source comes from the server: read with `Object.hasOwn`). */
  const badgeOf = (source: string): [string, string] => (Object.hasOwn(badge, source) ? [tk(badge[source][0]), badge[source][1]] : [source, '']);

  function open(e?: S['ConfigEntry']) {
    preview = null;
    result = null;
    formError = null;
    formOut = null;
    const def = (e?.definition ?? {}) as Record<string, unknown>;
    const initial = e ? {} : Object.fromEntries(fields.filter((f) => f.initial !== undefined).map((f) => [f.key, f.initial]));
    editing = { name: e?.name ?? '', isNew: !e, values: { ...initial, ...def }, entry: e };
    texts = Object.fromEntries(fields.filter((f) => f.toText).map((f) => [f.key, f.toText!(editing!.values[f.key])]));
  }

  // The body: the fields shown, with empty ones left out (the defaults apply); other fields of
  // an existing entry are kept as they were.
  function body(): Record<string, unknown> {
    const v = { ...editing!.values };
    delete v.name;
    for (const k of omit) delete v[k];
    for (const f of fields) if (f.fromText) v[f.key] = f.fromText(texts[f.key] ?? '');
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
      // T8.2 (ADR-181) — a pasted value is sent once: not kept in the page once it's saved
      // (the form can stay open to show what to keep in Git).
      for (const f of fields) if (f.type === 'secret') delete editing.values[f.key];
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
  // REQ: OBS-024 — kinds whose changes move decisions can be replayed over the query log.
  const replayable = $derived(['upstream', 'upstream_group', 'list', 'group', 'schedule'].includes(kind));
  async function simulateDraft(): Promise<S['Simulation'] | null | undefined> {
    if (!editing) return null;
    return (await api.putEntry(path, editing.name.trim(), body(), true, 'true')).simulation;
  }
  const lines = (v: unknown) => (Array.isArray(v) ? v.join('\n') : '');
  const toLines = (s: string) => s.split('\n').map((x) => x.trim()).filter(Boolean);
</script>

<section class="card" data-testid={`editor-${kind}`}>
  <div class="head">
    <h2>{title}{#if help}<HelpButton id={help} />{:else}<HelpButton id="config-sources" />{/if}</h2>
    {#if writable && !singleton}<button onclick={() => open()}>{t('Add {noun}', { noun })}</button>{/if}
  </div>
  <ErrorNote {error} />
  {#if entries.length === 0}
    <p class="empty">{t('None yet.')}</p>
  {:else}
    <div class="table-wrap">
      <table class="compact">
        <tbody>
          {#each entries as e (e.name)}
            {@const [label, cls] = badgeOf(e.source)}
            {@const st = status?.(e)}
            <tr data-testid="entry-row">
              <td><strong translate="no">{e.name}</strong><span class="badge {cls}">{label}</span>{#if st}<span class="badge {st.cls}" data-testid="entry-status">{st.text}</span>{/if}</td>
              <td class="small muted">{e.definition ? summary(e.definition as Record<string, unknown>) : t('left out of the configuration')}</td>
              {#if writable}
                <td class="actions">
                  {#if rowAction && e.source !== 'hidden'}
                    <button class="link small" onclick={() => runAction(e.name)}>{rowAction.label}</button>
                  {/if}
                  {#if e.source !== 'hidden'}<button class="link small" onclick={() => open(e)}>{t('Edit')}</button>{/if}
                  {#if e.source === 'override' || e.source === 'hidden'}
                    <button class="link small" disabled={busy} onclick={() => remove(e)}>{t('Revert to the file')}</button>
                  {:else if !singleton}
                    <button class="link small danger" disabled={busy} onclick={() => remove(e)}>{t('Remove')}</button>
                  {/if}
                </td>
              {/if}
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
  {#if actionOut}
    <p class="notice small {actionOut.ok ? 'ok' : 'bad'}" role="status" data-testid="row-action-result">
      <strong translate="no">{actionOut.name}</strong>: {actionOut.text}
    </p>
  {/if}
</section>

{#if editing}
  <Drawer title={editing.isNew ? t('Add {noun}', { noun }) : `${noun}: ${editing.name}`} onclose={() => (editing = null)}>
    {#if result?.keepInGit}
      <p class="notice ok small">{result.applied ? t('Saved.') : ''}</p>
      <KeepInGit toml={result.keepInGit} />
      <button onclick={() => (editing = null)}>{t('Done')}</button>
    {:else}
      <form class="form" onsubmit={check}>
        {#if notice}<p class="notice warn small" role="note" data-testid="editor-notice">{notice}</p>{/if}
        <label>
          {t('Name')}
          <input class="mono" bind:value={editing.name} required readonly={!editing.isNew} aria-label={t('Name')} />
        </label>
        {#each shown as f (f.key)}
          <label>
            {f.label}
            {#if f.type === 'select'}
              <select bind:value={editing.values[f.key]} aria-label={f.label}>
                <option value={undefined}>{t('(default)')}</option>
                {#each f.options ?? [] as o (o)}<option value={o} translate="no">{o}</option>{/each}
              </select>
            {:else if f.type === 'multi'}
              <!-- Values chosen earlier that aren't offered now (a node gone) stay visible. -->
              {@const chosen = (editing.values[f.key] as string[] | undefined) ?? []}
              <span class="multi" role="group" aria-label={f.label}>
                {#each [...new Set([...(f.options ?? []), ...chosen])] as o (o)}
                  {@const arr = (editing.values[f.key] as string[] | undefined) ?? []}
                  <label class="check"
                    ><input
                      type="checkbox"
                      checked={arr.includes(o)}
                      onchange={(ev) =>
                        (editing!.values[f.key] = (ev.currentTarget as HTMLInputElement).checked
                          ? [...arr, o]
                          : arr.filter((x) => x !== o))}
                    />{f.optionLabels?.[o] ?? o}</label
                  >
                {/each}
              </span>
            {:else if f.type === 'lines' && f.fromText}
              <textarea
                rows="4"
                class="mono"
                placeholder={f.placeholder}
                aria-label={f.label}
                bind:value={texts[f.key]}
              ></textarea>
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
              <input type="checkbox" role="switch" bind:checked={editing.values[f.key] as boolean} aria-label={f.label} />
            {:else if f.type === 'number'}
              <!-- step="any": thresholds such as 0.5 % are allowed. -->
              <input type="number" step="any" bind:value={editing.values[f.key]} placeholder={f.placeholder} aria-label={f.label} />
            {:else if f.type === 'secret'}
              <!-- T8.2 (ADR-181): sent once, saved to a file by the server, never read back. -->
              <input
                type="password"
                autocomplete="new-password"
                class="mono"
                bind:value={editing.values[f.key]}
                placeholder={f.placeholderFor?.(editing.values, editing.name, editing.entry) ?? f.placeholder}
                aria-label={f.label}
              />
            {:else}
              <input
                class="mono"
                bind:value={editing.values[f.key]}
                placeholder={f.placeholderFor?.(editing.values, editing.name, editing.entry) ?? f.placeholder}
                aria-label={f.label}
              />
            {/if}
            {#if f.help}<span class="muted small">{f.help}</span>{/if}
          </label>
        {/each}
        {#if note}<p class="small" data-testid="editor-note">{note(editing.values)}</p>{/if}
        <ErrorNote error={formError} />
        {#if preview}
          <div class="preview" data-testid="entry-preview">
            <p>
              <T ctx="configEditor" msg={'<b>What this will do:</b> {impact}'} params={{ impact: preview.impact || t('Changes the configuration as shown.') }}
                >{#snippet b(text: string)}<b>{text}</b>{/snippet}</T
              >
            </p>
            {#each preview.warnings as w (w)}<p class="small warn-text">{w}</p>{/each}
            {#if replayable}<SimulationCard run={simulateDraft} />{/if}
          </div>
          <div class="row">
            <button type="button" class="primary" disabled={busy} onclick={apply}>{t('Apply')}</button>
            <button type="button" onclick={() => (preview = null)}>{t('Change it')}</button>
          </div>
        {:else}
          <div class="row">
            <button class="primary" disabled={busy || !editing.name.trim()}>{t('Check')}</button>
            {#if formAction}<button type="button" onclick={runFormAction}>{formAction.label}</button>{/if}
          </div>
        {/if}
        {#if formOut}
          <p class="notice small {formOut.ok ? 'ok' : 'bad'}" data-testid="form-action-result" role="status">
            {formOut.text}
          </p>
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
