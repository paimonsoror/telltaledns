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
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';
  import SimulationCard from './SimulationCard.svelte';
  import { tk, tr, type Msg } from '../i18n';
  import T from '../i18n/T.svelte';
  const { t, m } = tr('quickRuleForm');

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
  const placedBy: Record<string, Msg> = {
    pod_label: m('set by a label on its pods'),
    namespace_label: m('set by a label on its namespace'),
    map: m('set by a rule'),
  };
  /** Where any other group of a workload comes from. */
  const otherGroup: Record<string, Msg> = {
    default_group: m('the default group for workloads'),
    none: m("its network's group"),
  };
  /** The words for a workload's group, whichever it is. */
  const origin = (from: string) =>
    Object.hasOwn(placedBy, from) ? tk(placedBy[from]) : Object.hasOwn(otherGroup, from) ? tk(otherGroup[from]) : t('its group');
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
  let saved = $state('');
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

  const durations = [
    { v: '30', l: t('30 minutes') },
    { v: '60', l: t('1 hour') },
    { v: '120', l: t('2 hours') },
    { v: 'today', l: t('Until midnight') },
    { v: '1440', l: t('1 day') },
    { v: 'always', l: t('Until I remove it') },
  ];
  /** An edit can keep the end time the rule has (a new duration counts from now). */
  const options = $derived(
    rule?.expires && (rule.expiresInSeconds ?? 0) > 0
      ? [{ v: 'keep', l: t('Keep the current end ({end})', { end: endsAt(rule.expires) }) }, ...durations]
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
    saved = '';
    const body = ruleBody();
    const id = rule?.id ?? `r-${Date.now().toString(36)}`;
    try {
      const c = await api.putRule(id, body);
      saved = c.impact ?? t('Saved.');
      onsaved?.(saved);
    } catch (err) {
      error = err;
    } finally {
      saving = false;
    }
  }
</script>

<form class="quick" onsubmit={save} data-testid={rule ? 'quick-rule-edit-form' : 'quick-rule-form'}>
  <div class="row">
    <span class="seg" role="group" aria-label={t('Action')}>
      <button type="button" aria-pressed={action === 'allow'} onclick={() => (action = 'allow')}>{t('Allow')}</button>
      <button type="button" aria-pressed={action === 'block'} onclick={() => (action = 'block')}>{t('Block')}</button>
    </span>
    <input class="grow mono" aria-label={t('Domain')} placeholder={t('game.example.com')} bind:value={name} oninput={touch} required />
  </div>
  <div class="row">
    <label class="small">{t('For')}
      <select bind:value={scope} onchange={touch} aria-label={t('Applies to')}>
        <option value="device">{t('a device')}</option>
        <option value="group">{t('a group')}</option>
        <option value="everyone">{t('everyone')}</option>
      </select>
    </label>
    {#if scope === 'device'}
      <input
        aria-label={t('Device')}
        list={listId}
        placeholder={t('named device, IP, or network')}
        bind:value={who}
        oninput={touch}
        aria-invalid={checkError ? 'true' : undefined}
        aria-describedby={checkError ? checkDomId : undefined}
        required
      />
      <datalist id={listId}>{#each known ?? devices as d (d.name)}<option value={d.name}></option>{/each}</datalist>
    {:else if scope === 'group'}
      <select aria-label={t('Group')} bind:value={whichGroup} onchange={touch} required>
        {#each groups as g (g.name)}<option value={g.name} translate="no">{g.name}</option>{/each}
      </select>
    {/if}
    <label class="small">{t('for')}
      <select aria-label={t('Duration')} bind:value={duration}>
        {#each options as d (d.v)}<option value={d.v}>{d.l}</option>{/each}
      </select>
    </label>
  </div>
  <div class="row">
    <input class="grow" aria-label={t('Note')} placeholder={t('Note (optional), e.g. Mom\'s game')} bind:value={note} />
    <button class="primary" disabled={saving || !name.trim()}>{saving ? t('Saving…') : rule ? t('Save changes') : t('Save rule')}</button>
    {#if rule}<button type="button" class="link" onclick={oncancel}>{t('Cancel')}</button>{/if}
  </div>
  {#if !rule && address}
    <!-- REQ: FLT-005, FLT-017 (issue #73) — what the form filled in, and what the log shows for it. The
         log's name is a label, said only as what the log shows (its source isn't known here). -->
    {#if scope === 'group' && workload}
      <p class="muted small seen" data-testid="quick-rule-seen-as">
        {#if whichGroup === group}
          <T
            ctx="quickRuleForm"
            msg={'<bdi>{workload}</bdi> is a Kubernetes workload and its pods come and go, so this rule is for its group, <bdi>{group}</bdi> ({origin}): every device in it. For one address instead, choose “a device”.'}
            params={{ workload, group: whichGroup, origin: origin(workloadFrom) }}>{#snippet bdi(text: string)}<bdi translate="no">{text}</bdi>{/snippet}</T
          >
        {:else if group}
          <T
            ctx="quickRuleForm"
            msg={'<bdi>{workload}</bdi> is a Kubernetes workload whose group is <bdi>{group}</bdi>. This rule is for <bdi>{which}</bdi>: every device in it.'}
            params={{ workload, group, which: whichGroup }}>{#snippet bdi(text: string)}<bdi translate="no">{text}</bdi>{/snippet}</T
          >
        {:else}
          <T ctx="quickRuleForm" msg={'This rule is for <bdi>{which}</bdi>: every device in it.'} params={{ which: whichGroup }}
            >{#snippet bdi(text: string)}<bdi translate="no">{text}</bdi>{/snippet}</T
          >
        {/if}
      </p>
    {:else if scope === 'device' && workload && who.trim() === address}
      <p class="muted small seen" data-testid="quick-rule-seen-as">
        <T ctx="quickRuleForm" msg={"{address} is one pod of <bdi>{workload}</bdi>, and a pod's address changes whenever it restarts."} params={{ address, workload }}
          >{#snippet bdi(text: string)}<bdi translate="no">{text}</bdi>{/snippet}</T
        >
        {#if placed}{t('For every pod, choose “a group”.')}{:else}{t('To cover all its pods, put the workload in a group first: click its name in the log, then Add to group…')}{/if}
      </p>
    {:else if scope === 'device' && device !== address && who.trim() === device}
      <p class="muted small seen" data-testid="quick-rule-seen-as">
        <T ctx="quickRuleForm" msg={'{address} is your device “<bdi>{device}</bdi>”.'} params={{ address, device }}>{#snippet bdi(text: string)}<bdi translate="no">{text}</bdi>{/snippet}</T>
      </p>
    {:else if scope === 'device' && who.trim() === address}
      <p class="muted small seen" data-testid="quick-rule-seen-as">
        {#if seenAs && seenAs !== address}<T ctx="quickRuleForm" msg={'{address} (shown in the log as <bdi>{seen}</bdi>).'} params={{ address, seen: seenAs }}
            >{#snippet bdi(text: string)}<bdi translate="no">{text}</bdi>{/snippet}</T
          >{/if}
        {#if podLike}
          {t('This looks like a Kubernetes pod this node doesn\'t know about: a pod\'s address changes whenever it restarts, so use the group an operator placed it in, not the address.')}
        {:else}
          {t('A rule for an address stops matching when the address changes: reserve the address in your router, or name the device so you change one place, not every rule.')}<HelpButton id="device-name" />
        {/if}
      </p>
    {/if}
  {/if}
  <p class="muted small">
    {t('Includes subdomains. Decides before any list. Devices may keep an old answer for a few minutes.')}{#if rule} {t('Saving keeps who made the rule and when.')}{/if}
  </p>
  <!-- A polite live region that stays in the page, so a refusal that comes and goes while someone types
       is announced once, and the Device field points at it while it is there. -->
  <div id={checkDomId} role="status" data-testid="quick-rule-check">{#if !error}<ErrorNote error={checkError} quiet />{/if}</div>
  <ErrorNote {error} />
  {#if saved && !rule}<div class="notice ok small" data-testid="quick-rule-saved">{saved}</div>{/if}
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
