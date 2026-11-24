<script lang="ts">
  // REQ: FLT-005 (T6.12, ADR-067) — make a quick rule: allow or block a domain for a device,
  // a group, or everyone, for a while or for good. Used in the query log's "Why?" drawer
  // (prefilled from the query) and on the Quick rules page.
  // REQ: FLT-005 (T20.1, ADR-162) — with `rule`, it edits that rule in place: the form starts
  // from the rule, saves under its ID (the rule keeps who made it and when), and the end time
  // stays as it was unless a new duration is picked. Pass a snapshot, not the live row: a list
  // that reloads must not reset what the person is typing.
  // REQ: FLT-005, FLT-017 (GitHub issue #73) — a rule can name a configured device, an IP, or a
  // CIDR, and nothing else: the names a router or a device gives an address (what the query log
  // shows for a device nobody named) are refused. So the "Why?" drawer fills in the configured
  // device the row is, else the address, and says what the log shows for it (never as the value). A
  // pod's address changes whenever it restarts: a Kubernetes workload an operator placed in a group
  // (a pod or namespace label, or a rule) starts as a rule for that group; any other starts from the
  // pod's address and points at "Add to group…", because the group it falls to is its network's (or
  // `default`) and a rule for that is a rule for every device there. A dry run as you change a
  // field shows a refusal before Save.
  import { untrack } from 'svelte';
  import { api, ApiError, type S } from '../api';
  import { endsAt } from '../format';
  // `t` is this file's own timer (the check as you type); the catalog's is `tr`.
  import { t as tr, type MessageKey } from '../i18n';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';
  import SimulationCard from './SimulationCard.svelte';

  let {
    domain = '',
    device = '',
    group = '',
    address = '',
    seenAs = '',
    workload = '',
    workloadFrom = '',
    known,
    rule,
    onsaved,
    oncancel,
  }: {
    domain?: string;
    /** What the Device field starts with: the configured device the row is, else the address. */
    device?: string;
    group?: string;
    /** The address the query came from (the Why? drawer): the form says what it filled in. */
    address?: string;
    /** What the query log shows for the address when it is no configured device's name (a router's, mDNS, a peer's). */
    seenAs?: string;
    /** The Kubernetes workload the address is a pod of. */
    workload?: string;
    /** Where the workload's group came from (`pod_label`, `namespace_label`, `map`, `default_group`, `none`). */
    workloadFrom?: string;
    /** The configured devices, when the page has them already (the Why? drawer): the form doesn't ask again. */
    known?: S['ClientInfo'][];
    rule?: S['RuleInfo'];
    onsaved?: (message: string) => void;
    oncancel?: () => void;
  } = $props();

  // One datalist per form: the page can hold the new-rule form and an edit form together.
  const listId = `quick-devices-${Math.random().toString(36).slice(2, 8)}`;
  // The check's note, which the Device field points at.
  const checkDomId = `${listId}-check`;

  /** A group an operator put the workload in. */
  const placedBy: Record<string, MessageKey> = {
    pod_label: 'queries.origin.podLabel',
    namespace_label: 'queries.origin.namespaceLabel',
    map: 'queries.origin.map',
  };
  /** Where any other group of a workload comes from. */
  const otherGroup: Record<string, MessageKey> = {
    default_group: 'queries.origin.defaultGroup',
    none: 'queries.origin.network',
  };
  /** The words for a workload's group, whichever it is. */
  const origin = (from: string) =>
    Object.hasOwn(placedBy, from) ? tr(placedBy[from]) : Object.hasOwn(otherGroup, from) ? tr(otherGroup[from]) : tr('queries.origin.group');
  // What the log calls a pod is `namespace/kind/name`. When this node's explanation has no workload for
  // the row, that shape decides nothing about the rule (the field and the scope stay as they were);
  // it only changes the advice in the label, which is wrong for a pod: its address changes.
  const podLike = $derived(/^[^/\s]+\/[^/\s]+\/[^/\s]+$/.test(seenAs));
  // Only a group an operator placed the workload in starts a pod's rule, and never `default`: that is
  // every device nothing else claims. (`group` is today's group of the workload, not the row's.)
  const placed = $derived(!!workload && !!group && group !== 'default' && Object.hasOwn(placedBy, workloadFrom));

  let action = $state<'allow' | 'block'>('allow');
  let name = $state('');
  let scope = $state<'device' | 'group' | 'everyone'>('device');
  let who = $state('');
  let whichGroup = $state('');
  let duration = $state('60');
  let note = $state('');
  let saving = $state(false);
  let error = $state<unknown>(null);
  // What the server said the save did (`''` when it said nothing); `null` until something is saved.
  let saved = $state<string | null>(null);
  let groups = $state<S['GroupInfo'][]>([]);
  let devices = $state<S['ClientInfo'][]>([]);

  $effect(() => {
    if (rule) {
      action = rule.action === 'block' ? 'block' : 'allow';
      name = rule.domain;
      who = rule.devices[0] ?? '';
      whichGroup = rule.groups[0] ?? '';
      scope = rule.devices.length ? 'device' : rule.groups.length ? 'group' : 'everyone';
      note = rule.note ?? '';
      duration = rule.expires && (rule.expiresInSeconds ?? 0) > 0 ? 'keep' : 'always';
      return;
    }
    name = domain;
    who = device;
    whichGroup = group;
    // A pod starts as a rule for its group only where an operator placed the workload in one.
    scope = placed ? 'group' : device ? 'device' : group ? 'group' : 'everyone';
  });
  $effect(() => {
    api.groups().then((g) => (groups = g.items)).catch(() => {});
    if (!known) api.clients().then((c) => (devices = c.items)).catch(() => {});
  });

  const durations = $derived([
    { v: '30', l: tr('queries.duration.30m') },
    { v: '60', l: tr('queries.duration.1h') },
    { v: '120', l: tr('queries.duration.2h') },
    { v: 'today', l: tr('queries.duration.today') },
    { v: '1440', l: tr('queries.duration.1d') },
    { v: 'always', l: tr('queries.duration.always') },
  ]);
  /** An edit can keep the end time the rule has (a new duration counts from now). */
  const options = $derived(
    rule?.expires && (rule.expiresInSeconds ?? 0) > 0
      ? [{ v: 'keep', l: tr('queries.duration.keep', { end: endsAt(rule.expires) }) }, ...durations]
      : durations,
  );

  /** Minutes until local midnight (at least 1). */
  function untilMidnight(): number {
    const now = new Date();
    const end = new Date(now);
    end.setHours(24, 0, 0, 0);
    return Math.max(1, Math.round((end.getTime() - now.getTime()) / 60000));
  }

  function ruleBody(): S['RuleInput'] {
    const open = duration === 'always' || duration === 'keep';
    const forMinutes = open ? undefined : duration === 'today' ? untilMidnight() : Number(duration);
    return {
      action,
      domain: name.trim(),
      devices: scope === 'device' ? [who.trim()] : [],
      groups: scope === 'group' ? [whichGroup] : [],
      expires: duration === 'keep' ? rule?.expires : undefined,
      forMinutes,
      note: note.trim() || undefined,
    };
  }

  /** REQ: OBS-024 — the rule as a dry run, replayed over the query log (nothing is saved). */
  async function simulateRule(): Promise<S['Simulation'] | null | undefined> {
    // An edit is simulated under its own ID, so it replaces the rule instead of joining it.
    const c = await api.putRule(rule?.id ?? `r-sim-${Date.now().toString(36)}`, ruleBody(), true, 'true');
    return c.simulation;
  }

  // The check as you type: the rule as a dry run, once what it names has settled, so a refusal (a
  // device a rule can't name) shows before Save, with what to do. Only a refusal of the rule
  // itself shows (422, 400); anything else waits for Save, which shows it too. Nothing is saved:
  // a new rule is checked under an ID of its own that is never stored. No check runs until the
  // person changes a field: what the form was filled in with is valid by construction, and a check
  // takes a place among the configuration changes and a full validation on the node.
  const checkId = `r-check-${Math.random().toString(36).slice(2, 8)}`;
  let checkError = $state<unknown>(null);
  let checkSeq = 0;
  let touched = $state(false);
  const touch = () => (touched = true);
  $effect(() => {
    const ready = touched && name.trim() !== '' && (scope === 'device' ? who.trim() !== '' : scope === 'group' ? whichGroup !== '' : true);
    const mine = ++checkSeq;
    checkError = null;
    // A refusal at Save is about the values it was made with: a changed value clears it.
    if (touched) error = null;
    if (!ready) return;
    const body = untrack(ruleBody);
    const t = setTimeout(() => {
      api
        .putRule(rule?.id ?? checkId, body, true)
        .then(() => {
          if (mine === checkSeq) checkError = null;
        })
        .catch((err) => {
          if (mine === checkSeq && err instanceof ApiError && (err.status === 422 || err.status === 400)) checkError = err;
        });
    }, 400);
    return () => clearTimeout(t);
  });

  async function save(e: SubmitEvent) {
    e.preventDefault();
    saving = true;
    error = null;
    saved = null;
    const body = ruleBody();
    const id = rule?.id ?? `r-${Date.now().toString(36)}`;
    try {
      const c = await api.putRule(id, body);
      saved = c.impact ?? '';
      onsaved?.(saved || tr('queries.quickRule.saved'));
    } catch (err) {
      error = err;
    } finally {
      saving = false;
    }
  }
</script>

<form class="quick" onsubmit={save} data-testid={rule ? 'quick-rule-edit-form' : 'quick-rule-form'}>
  <div class="row">
    <span class="seg" role="group" aria-label={tr('queries.quickRule.action')}>
      <button type="button" aria-pressed={action === 'allow'} onclick={() => (action = 'allow')}>{tr('queries.quickRule.allow')}</button>
      <button type="button" aria-pressed={action === 'block'} onclick={() => (action = 'block')}>{tr('queries.quickRule.block')}</button>
    </span>
    <input class="grow mono" aria-label={tr('queries.quickRule.domain')} placeholder="game.example.com" bind:value={name} oninput={touch} required />
  </div>
  <div class="row">
    <label class="small">{tr('queries.quickRule.for')}
      <select bind:value={scope} onchange={touch} aria-label={tr('queries.quickRule.appliesTo')}>
        <option value="device">{tr('queries.quickRule.scopeDevice')}</option>
        <option value="group">{tr('queries.quickRule.scopeGroup')}</option>
        <option value="everyone">{tr('queries.quickRule.scopeEveryone')}</option>
      </select>
    </label>
    {#if scope === 'device'}
      <input
        aria-label={tr('queries.quickRule.device')}
        list={listId}
        placeholder={tr('queries.quickRule.devicePlaceholder')}
        bind:value={who}
        oninput={touch}
        aria-invalid={checkError ? 'true' : undefined}
        aria-describedby={checkError ? checkDomId : undefined}
        required
      />
      <datalist id={listId}>{#each known ?? devices as d (d.name)}<option value={d.name}></option>{/each}</datalist>
    {:else if scope === 'group'}
      <select aria-label={tr('queries.quickRule.group')} bind:value={whichGroup} onchange={touch} required>
        {#each groups as g (g.name)}<option value={g.name}>{g.name}</option>{/each}
      </select>
    {/if}
    <label class="small">{tr('queries.quickRule.forLower')}
      <select aria-label={tr('queries.quickRule.duration')} bind:value={duration}>
        {#each options as d (d.v)}<option value={d.v}>{d.l}</option>{/each}
      </select>
    </label>
  </div>
  <div class="row">
    <input class="grow" aria-label={tr('queries.quickRule.note')} placeholder={tr('queries.quickRule.notePlaceholder')} bind:value={note} />
    <button class="primary" disabled={saving || !name.trim()}>{saving ? tr('queries.quickRule.saving') : rule ? tr('queries.quickRule.saveChanges') : tr('queries.quickRule.save')}</button>
    {#if rule}<button type="button" class="link" onclick={oncancel}>{tr('common.cancel')}</button>{/if}
  </div>
  {#if !rule && address}
    <!-- REQ: FLT-005, FLT-017 (issue #73) — what the form filled in, and what the log shows for it. The
         log's name is a label, said only as what the log shows (its source isn't known here). -->
    {#if scope === 'group' && workload}
      <p class="muted small seen" data-testid="quick-rule-seen-as">
        {#if whichGroup === group}
          {tr('queries.seen.groupPlaced', { workload })}<bdi>{whichGroup}</bdi>{tr('queries.seen.groupPlacedAfter', { origin: origin(workloadFrom) })}
        {:else if group}
          <bdi>{workload}</bdi>{tr('queries.seen.groupOtherMid')}<bdi>{group}</bdi>{tr('queries.seen.groupOtherAfter')}<bdi>{whichGroup}</bdi>{tr('queries.seen.everyDevice')}
        {:else}
          {tr('queries.seen.forPrefix')}<bdi>{whichGroup}</bdi>{tr('queries.seen.everyDevice')}
        {/if}
      </p>
    {:else if scope === 'device' && workload && who.trim() === address}
      <p class="muted small seen" data-testid="quick-rule-seen-as">
        {tr('queries.seen.podIs', { address })}<bdi>{workload}</bdi>{tr('queries.seen.podChanges')}
        {#if placed}{tr('queries.seen.podUseGroup')}{:else}{tr('queries.seen.podAddGroup')}{/if}
      </p>
    {:else if scope === 'device' && device !== address && who.trim() === device}
      <p class="muted small seen" data-testid="quick-rule-seen-as">{tr('queries.seen.namedDevice', { address })}<bdi>{device}</bdi>{tr('queries.seen.namedDeviceEnd')}</p>
    {:else if scope === 'device' && who.trim() === address}
      <p class="muted small seen" data-testid="quick-rule-seen-as">
        {#if seenAs && seenAs !== address}{tr('queries.seen.seenAsStart', { address })}<bdi>{seenAs}</bdi>{tr('queries.seen.seenAsEnd')}{/if}
        {#if podLike}
          {tr('queries.seen.podUnknown')}
        {:else}
          {tr('queries.seen.address')}<HelpButton id="device-name" />
        {/if}
      </p>
    {/if}
  {/if}
  <p class="muted small">
    {tr('queries.quickRule.foot')}{#if rule}{' '}{tr('queries.quickRule.footEdit')}{/if}
  </p>
  <!-- A polite live region that stays in the page, so a refusal that comes and goes while someone types
       is announced once, and the Device field points at it while it is there. -->
  <div id={checkDomId} role="status" data-testid="quick-rule-check">{#if !error}<ErrorNote error={checkError} quiet />{/if}</div>
  <ErrorNote {error} />
  {#if saved !== null && !rule}<div class="notice ok small" data-testid="quick-rule-saved">{saved || tr('queries.quickRule.saved')}</div>{/if}
  {#if name.trim() && (scope !== 'device' || who.trim())}<SimulationCard run={simulateRule} />{/if}
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
  /* A long name from a router or a device wraps instead of widening the drawer. */
  .seen {
    overflow-wrap: anywhere;
  }
</style>
