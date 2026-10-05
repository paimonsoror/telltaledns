<script lang="ts">
  // REQ: FLT-005 (T6.12, ADR-067) — make a quick rule: allow or block a domain for a device,
  // a group, or everyone, for a while or for good. Used in the query log's "Why?" drawer
  // (prefilled from the query) and on the Quick rules page.
  import { api, type S } from '../api';
  import ErrorNote from './ErrorNote.svelte';

  let {
    domain = '',
    device = '',
    group = '',
    onsaved,
  }: { domain?: string; device?: string; group?: string; onsaved?: () => void } = $props();

  let action = $state<'allow' | 'block'>('allow');
  let name = $state('');
  let scope = $state<'device' | 'group' | 'everyone'>('device');
  let who = $state('');
  let whichGroup = $state('');
  let duration = $state('60');
  let note = $state('');
  let saving = $state(false);
  let error = $state<unknown>(null);
  let saved = $state('');
  let groups = $state<S['GroupInfo'][]>([]);
  let devices = $state<S['ClientInfo'][]>([]);

  $effect(() => {
    name = domain;
    who = device;
    whichGroup = group;
    scope = device ? 'device' : group ? 'group' : 'everyone';
  });
  $effect(() => {
    api.groups().then((g) => (groups = g.items)).catch(() => {});
    api.clients().then((c) => (devices = c.items)).catch(() => {});
  });

  const durations = [
    { v: '30', l: '30 minutes' },
    { v: '60', l: '1 hour' },
    { v: '120', l: '2 hours' },
    { v: 'today', l: 'Until midnight' },
    { v: '1440', l: '1 day' },
    { v: 'always', l: 'Until I remove it' },
  ];

  /** Minutes until local midnight (at least 1). */
  function untilMidnight(): number {
    const now = new Date();
    const end = new Date(now);
    end.setHours(24, 0, 0, 0);
    return Math.max(1, Math.round((end.getTime() - now.getTime()) / 60000));
  }

  async function save(e: SubmitEvent) {
    e.preventDefault();
    saving = true;
    error = null;
    saved = '';
    const forMinutes = duration === 'always' ? undefined : duration === 'today' ? untilMidnight() : Number(duration);
    const body: S['RuleInput'] = {
      action,
      domain: name.trim(),
      devices: scope === 'device' ? [who.trim()] : [],
      groups: scope === 'group' ? [whichGroup] : [],
      forMinutes,
      note: note.trim() || undefined,
    };
    const id = `r-${Date.now().toString(36)}`;
    try {
      const c = await api.putRule(id, body);
      saved = c.impact ?? 'Saved.';
      onsaved?.();
    } catch (err) {
      error = err;
    } finally {
      saving = false;
    }
  }
</script>

<form class="quick" onsubmit={save} data-testid="quick-rule-form">
  <div class="row">
    <span class="seg" role="group" aria-label="Action">
      <button type="button" aria-pressed={action === 'allow'} onclick={() => (action = 'allow')}>Allow</button>
      <button type="button" aria-pressed={action === 'block'} onclick={() => (action = 'block')}>Block</button>
    </span>
    <input class="grow mono" aria-label="Domain" placeholder="game.example.com" bind:value={name} required />
  </div>
  <div class="row">
    <label class="small">For
      <select bind:value={scope} aria-label="Applies to">
        <option value="device">a device</option>
        <option value="group">a group</option>
        <option value="everyone">everyone</option>
      </select>
    </label>
    {#if scope === 'device'}
      <input aria-label="Device" list="quick-devices" placeholder="device name or IP" bind:value={who} required />
      <datalist id="quick-devices">{#each devices as d (d.name)}<option value={d.name}></option>{/each}</datalist>
    {:else if scope === 'group'}
      <select aria-label="Group" bind:value={whichGroup} required>
        {#each groups as g (g.name)}<option value={g.name}>{g.name}</option>{/each}
      </select>
    {/if}
    <label class="small">for
      <select aria-label="Duration" bind:value={duration}>
        {#each durations as d (d.v)}<option value={d.v}>{d.l}</option>{/each}
      </select>
    </label>
  </div>
  <div class="row">
    <input class="grow" aria-label="Note" placeholder="Note (optional), e.g. Mom's game" bind:value={note} />
    <button class="primary" disabled={saving || !name.trim()}>{saving ? 'Saving…' : 'Save rule'}</button>
  </div>
  <p class="muted small">
    Includes subdomains. Decides before any list. Devices may keep an old answer for a few minutes.
  </p>
  <ErrorNote {error} />
  {#if saved}<div class="notice ok small" data-testid="quick-rule-saved">{saved}</div>{/if}
</form>

<style>
  .quick {
    display: grid;
    gap: 10px;
  }
  .row {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    align-items: center;
  }
  .grow {
    flex: 1 1 200px;
  }
  label {
    display: inline-flex;
    gap: 6px;
    align-items: center;
  }
</style>
