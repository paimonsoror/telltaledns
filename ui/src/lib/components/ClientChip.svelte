<script lang="ts">
  // REQ: API-010 — a device anywhere in the UI (top clients, query log, live tail): a menu with
  // "Name this device…", "Add to group…", and "Show queries". Naming stores a device through
  // the API; names are resolved when read, so the new name shows on past queries too.
  import { api, ApiError, type S } from '../api';
  import { href } from '../router.svelte';
  import { session } from '../session.svelte';
  import Drawer from './Drawer.svelte';
  import HelpButton from './HelpButton.svelte';
  import ChangePreview from './ChangePreview.svelte';

  let {
    ip,
    name = null,
    onchanged,
  }: { ip: string; name?: string | null; onchanged?: (name: string) => void } = $props();

  let open = $state(false);
  let editing = $state<'name' | 'groups' | null>(null);
  let root = $state<HTMLElement | undefined>();

  // Form state, loaded when the drawer opens.
  let existing = $state<S['ClientInfo'] | null>(null);
  let groups = $state<S['GroupInfo'][]>([]);
  let newName = $state('');
  let chosen = $state<string[]>([]);
  let busy = $state(false);
  // The form appears only once its data is in, so a slow load can't wipe what was typed.
  let loading = $state(false);
  let error = $state('');
  let done = $state('');

  const canEdit = $derived(session.user?.role === 'admin' || session.user?.role === 'operator');

  function close() {
    open = false;
  }

  function outside(e: MouseEvent) {
    if (open && root && !root.contains(e.target as Node)) open = false;
  }

  function key(e: KeyboardEvent) {
    if (e.key === 'Escape') open = false;
  }

  async function edit(mode: 'name' | 'groups') {
    open = false;
    editing = mode;
    error = '';
    done = '';
    loading = true;
    try {
      // REQ: API-010 (T8.6) — suggest the name the device gave DHCP, the router, or mDNS.
      const [c, g, leases] = await Promise.all([api.clients(), api.groups(), api.dhcpLeases().catch(() => null)]);
      groups = g.items;
      existing = c.items.find((x) => x.match.includes(ip)) ?? null;
      const suggested = leases?.items.find((l) => l.ip === ip)?.hostname;
      newName = existing?.name ?? name ?? suggested ?? '';
      chosen = existing ? [...existing.groups] : ['default'];
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  }

  function toggle(g: string) {
    chosen = chosen.includes(g) ? chosen.filter((x) => x !== g) : [...chosen, g];
  }

  /** REQ: OBS-024 — the device change as a dry run, replayed over the query log. */
  async function simulateChange(): Promise<S['Simulation'] | null | undefined> {
    const n = newName.trim();
    const r = await api.putClient(
      existing?.name ?? n,
      { name: n, match: existing ? existing.match : [ip], groups: chosen.length ? chosen : ['default'] },
      true,
      'true',
    );
    return r.simulation;
  }

  async function save(ev: SubmitEvent) {
    ev.preventDefault();
    const n = newName.trim();
    if (!n) {
      error = 'Give the device a name.';
      return;
    }
    busy = true;
    error = '';
    try {
      const target = existing?.name ?? n;
      const r = await api.putClient(target, {
        name: n,
        match: existing ? existing.match : [ip],
        groups: chosen.length ? chosen : ['default'],
      });
      done =
        r.recentQueries > 0
          ? `Saved. ${r.recentQueries} recent queries now show “${n}”.`
          : `Saved. Queries from ${ip} now show “${n}”.`;
      onchanged?.(n);
    } catch (e) {
      error = e instanceof ApiError && e.hint ? `${e.message} ${e.hint}` : e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }
</script>

<svelte:window onclick={outside} onkeydown={key} />

<span class="chip" bind:this={root}>
  <button
    class="link chip-button"
    title={name ? `${name} (${ip})` : ip}
    aria-haspopup="menu"
    aria-expanded={open}
    onclick={(e) => {
      e.stopPropagation();
      open = !open;
    }}>{name ?? ip}</button
  >
  {#if open}
    <span class="menu" role="menu" aria-label={`Device ${ip}`}>
      {#if canEdit}
        <button role="menuitem" onclick={() => edit('name')}>Name this device…</button>
        <button role="menuitem" onclick={() => edit('groups')}>Add to group…</button>
      {/if}
      <a role="menuitem" href={href('/queries', { client: ip })} onclick={close}>Show queries</a>
    </span>
  {/if}
</span>

{#if editing}
  <Drawer title={editing === 'name' ? 'Name this device' : 'Add to a group'} onclose={() => (editing = null)}>
    {#if loading}
      <p class="muted" role="status" aria-live="polite">Loading…</p>
    {:else if existing && existing.source === 'file'}
      <p class="notice">
        <b>{existing.name}</b> is defined in the configuration file, so it's changed there, not here.
      </p>
    {:else}
      <form class="stack" onsubmit={save}>
        <p class="muted small">
          Queries from <code>{ip}</code> will show this name everywhere, including past ones. The device is
          recognized by {existing ? existing.match.join(', ') : ip}.
        </p>
        <label>
          Name
          <input name="device-name" bind:value={newName} placeholder="Living room TV" maxlength="64" required />
        </label>
        <HelpButton id="device-name" />
        <fieldset>
          <legend>Groups <span class="muted small">(first one's settings apply)</span><HelpButton id="device-groups" /></legend>
          {#each groups as g (g.name)}
            <label class="check"><input type="checkbox" checked={chosen.includes(g.name)} onchange={() => toggle(g.name)} /> {g.name}</label>
          {/each}
        </fieldset>
        {#if newName.trim()}
          <ChangePreview
            highlight="blocked"
            device={newName.trim()}
            name="any site"
            sentence={`Queries from ${ip} will show “${newName.trim()}”, past ones included, and get the lists of ${chosen.length ? chosen.join(', ') : 'default'}.`}
            simulate={simulateChange}
          />
        {/if}
        {#if error}<p class="notice bad" role="alert">{error}</p>{/if}
        {#if done}<p class="notice ok" role="status">{done}</p>{/if}
        <div class="row">
          <button type="submit" class="primary" disabled={busy}>{busy ? 'Saving…' : 'Save'}</button>
          <button type="button" onclick={() => (editing = null)}>Close</button>
        </div>
      </form>
    {/if}
  </Drawer>
{/if}

<style>
  .chip {
    position: relative;
    display: inline-block;
  }
  .chip-button {
    font: inherit;
    padding: 0;
  }
  .menu {
    position: absolute;
    z-index: 15;
    top: 100%;
    left: 0;
    margin-top: 4px;
    display: flex;
    flex-direction: column;
    min-width: 180px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    box-shadow: 0 6px 18px rgb(0 0 0 / 18%);
    padding: 4px;
  }
  .menu button,
  .menu a {
    text-align: left;
    padding: 6px 10px;
    border: 0;
    background: none;
    color: var(--text);
    font: inherit;
    border-radius: 6px;
    cursor: pointer;
    white-space: nowrap;
  }
  .menu button:hover,
  .menu a:hover,
  .menu button:focus-visible,
  .menu a:focus-visible {
    background: var(--hover, rgb(127 127 127 / 12%));
  }
  .stack {
    display: grid;
    gap: 12px;
  }
  fieldset {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 8px 12px;
  }
  .check {
    display: flex;
    gap: 8px;
    align-items: center;
    font-weight: normal;
  }
</style>
