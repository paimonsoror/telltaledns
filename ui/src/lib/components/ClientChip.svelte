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
  import Icon from './Icon.svelte';
  import { groupFromText, loadWorkloads, podAt, workloadOf } from '../workloads.svelte';
  import { t as tr, type MessageKey } from '../i18n';
  import { isMac, listsMac, normMac, sameIp } from '../macKeys';

  let {
    ip,
    name = null,
    onchanged,
    display,
  }: {
    ip: string;
    name?: string | null;
    onchanged?: (name: string) => void;
    /** What to show in place of the name (a pod's workload for its full pod name); the name is still the device's. */
    display?: string;
  } = $props();

  let open = $state(false);
  let editing = $state<'name' | 'groups' | 'workload' | null>(null);
  let root = $state<HTMLElement | undefined>();

  // REQ: FLT-017 — a Kubernetes workload (by its key, a pod address, or its name): its glyph,
  // its name, and the pod on hover; Kubernetes names it, and "Add to group…" writes a rule.
  $effect(() => {
    void loadWorkloads();
  });
  const workload = $derived(workloadOf(ip) ?? workloadOf(name));
  const pod = $derived(podAt(ip));
  const label = $derived(workload ? (name ?? workload.name) : (name ?? ip));
  const tip = $derived(
    workload
      ? pod
        ? tr('qw.chip.tip.pod', { workload: workload.name, pod, ip })
        : workload.pods.length
          ? tr('qw.chip.tip.pods', { workload: workload.name, pods: workload.pods.map((p) => p.name).join(', ') })
          : tr('qw.chip.tip.workload', { workload: workload.name })
      : name
        ? tr('qw.chip.tip.named', { name, ip })
        : ip,
  );
  let wGroup = $state('');
  let preview = $state<S['ConfigChange'] | null>(null);

  // Form state, loaded when the drawer opens.
  let existing = $state<S['ClientInfo'] | null>(null);
  let groups = $state<S['GroupInfo'][]>([]);
  let newName = $state('');
  let chosen = $state<string[]>([]);
  // REQ: OBS-025 — what it looks like (pre-fills the name, pre-selects a suggested group) and
  // what it was set to be ('' = let TelltaleDNS guess).
  let identity = $state<S['DeviceIdentity'] | null>(null);
  let kind = $state('');
  // REQ: FLT-006, API-010 (ADR-183) — how this address is recognized now (`identity.recognition`), and
  // so the MAC address a device here could be named by: a MAC follows the device when its address
  // changes, an address doesn't. `devices` are the configured devices; `first` is what the form
  // started with, for when the MAC is chosen and then not.
  let recognition = $state<S['DeviceRecognition'] | null>(null);
  let devices = $state<S['ClientInfo'][]>([]);
  let useMac = $state(false);
  let first = $state<{ name: string; groups: string[]; kind: string } | null>(null);
  const mac = $derived(recognition?.mac ? normMac(recognition.mac) : '');
  /** A configured device that already lists the MAC. */
  const macHolder = $derived(mac ? (devices.find((d) => listsMac(d.match, mac)) ?? null) : null);
  /** The device edited doesn't list the MAC, and the one that does is not a configuration file's. */
  const offerMac = $derived(!!mac && !(existing && listsMac(existing.match, mac)) && macHolder?.source !== 'file');
  const heldElsewhere = $derived(offerMac && !!macHolder && macHolder.name !== existing?.name);
  const macChosen = $derived(offerMac && useMac);
  /** The device the form edits: the one that has the MAC when the MAC is chosen, else the one at this address. */
  const target = $derived(macChosen && heldElsewhere ? macHolder : existing);
  const macSource = $derived(
    recognition?.macFrom === 'neighbor' ? tr('qw.chip.mac.source.neighbor') : tr('qw.chip.mac.source.router'),
  );
  /** What keeps vouching for the MAC, and what it can't follow: the sentence says so, not just that the MAC "follows". */
  const macVouch = $derived(
    recognition?.macFrom === 'neighbor' ? tr('qw.chip.mac.vouch.neighbor') : tr('qw.chip.mac.vouch.router'),
  );
  /** Why the address, not the MAC, is what the form starts with. */
  const macReason = $derived(
    recognition?.macShared
      ? recognition.macFrom === 'neighbor'
        ? tr('qw.chip.mac.reason.shared.neighbor')
        : tr('qw.chip.mac.reason.shared.router')
      : recognition?.macFrom === 'neighbor'
        ? tr('qw.chip.mac.reason.local')
        : '',
  );
  /** Who the sentences below talk about. */
  const who = $derived(macChosen ? tr('qw.chip.who', { mac, ip }) : ip);
  /** Which English article a product name takes ('an' before a vowel); Chinese has neither. */
  const articleKey = (p: string): MessageKey =>
    /^[aeiou]/i.test(p) ? 'qw.chip.identity.looks.an' : 'qw.chip.identity.looks.a';
  const kinds = ['phone', 'tablet', 'laptop', 'desktop', 'tv', 'streaming', 'speaker', 'console', 'camera', 'doorbell', 'plug', 'bulb', 'thermostat', 'hub', 'vacuum', 'printer', 'nas', 'network', 'appliance', 'wearable', 'car', 'other', 'unknown'];
  // The kinds above are what the API is sent; these are what a person reads.
  const KIND_LABEL: Record<string, MessageKey> = {
    phone: 'qw.kind.phone',
    tablet: 'qw.kind.tablet',
    laptop: 'qw.kind.laptop',
    desktop: 'qw.kind.desktop',
    tv: 'qw.kind.tv',
    streaming: 'qw.kind.streaming',
    speaker: 'qw.kind.speaker',
    console: 'qw.kind.console',
    camera: 'qw.kind.camera',
    doorbell: 'qw.kind.doorbell',
    plug: 'qw.kind.plug',
    bulb: 'qw.kind.bulb',
    thermostat: 'qw.kind.thermostat',
    hub: 'qw.kind.hub',
    vacuum: 'qw.kind.vacuum',
    printer: 'qw.kind.printer',
    nas: 'qw.kind.nas',
    network: 'qw.kind.network',
    appliance: 'qw.kind.appliance',
    wearable: 'qw.kind.wearable',
    car: 'qw.kind.car',
    other: 'qw.kind.misc',
    unknown: 'qw.kind.unknown',
  };
  /** The words for a kind; a kind this build doesn't know yet is shown as it is. */
  const kindLabel = (k: string) => (KIND_LABEL[k] ? tr(KIND_LABEL[k]) : k);
  let busy = $state(false);
  // The form appears only once its data is in, so a slow load can't wipe what was typed.
  let loading = $state(false);
  // A message is kept as its parts, not as a finished sentence, so it follows the language on
  // screen: `error` is the server's own words (or the one thing this form checks itself), and
  // `done` says what was saved.
  type Saved =
    | { kind: 'workload'; workload: string; group: string }
    | { kind: 'recent'; n: number; name: string }
    | { kind: 'queries'; who: string; name: string };
  let serverError = $state('');
  let nameError = $state(false);
  const error = $derived(nameError ? tr('qw.chip.error.name') : serverError);
  let saved = $state<Saved | null>(null);
  const done = $derived(
    !saved
      ? ''
      : saved.kind === 'workload'
        ? tr('qw.chip.saved.workload', { workload: saved.workload, group: saved.group })
        : saved.kind === 'recent'
          ? tr('qw.chip.saved.recent', { n: saved.n, name: saved.name })
          : tr('qw.chip.saved.queries', { who: saved.who, name: saved.name }),
  );

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

  /** REQ: FLT-017 — "Add to group…" for a workload: its groups, then a dry run, then a rule. */
  async function editWorkload() {
    open = false;
    editing = 'workload';
    serverError = '';
    nameError = false;
    saved = null;
    preview = null;
    loading = true;
    try {
      groups = (await api.groups()).items;
      wGroup = workload?.group ?? '';
    } catch (e) {
      serverError = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  }

  async function previewWorkload() {
    if (!workload || !wGroup) return;
    busy = true;
    serverError = '';
    nameError = false;
    try {
      preview = await api.putWorkloadGroup(workload.name, wGroup, true);
    } catch (e) {
      serverError = e instanceof ApiError && e.hint ? `${e.message} ${e.hint}` : e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  async function saveWorkload(ev: SubmitEvent) {
    ev.preventDefault();
    if (!workload || !wGroup) return;
    busy = true;
    serverError = '';
    nameError = false;
    try {
      await api.putWorkloadGroup(workload.name, wGroup);
      saved = { kind: 'workload', workload: workload.name, group: wGroup };
      void loadWorkloads(true);
      onchanged?.(workload.name);
    } catch (e) {
      serverError = e instanceof ApiError && e.hint ? `${e.message} ${e.hint}` : e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  async function edit(mode: 'name' | 'groups') {
    open = false;
    editing = mode;
    serverError = '';
    nameError = false;
    saved = null;
    loading = true;
    try {
      // REQ: API-010 (T8.6) — suggest the name the device gave DHCP, the router, or mDNS.
      const [c, g, leases, id] = await Promise.all([
        api.clients(),
        api.groups(),
        api.dhcpLeases().catch(() => null),
        api.identity(ip).catch(() => null),
      ]);
      groups = g.items;
      devices = c.items;
      identity = id;
      recognition = id?.recognition ?? null;
      // The device this address is recognized as (by its address or by a MAC), else the one that lists the address.
      const named = recognition?.device?.toLowerCase();
      const byRecognition =
        named && ['ip', 'neighbor_mac', 'router_mac', 'edns_mac'].includes(recognition?.identifiedBy ?? '')
          ? c.items.find((x) => x.name.toLowerCase() === named)
          : undefined;
      existing = byRecognition ?? c.items.find((x) => x.match.includes(ip)) ?? null;
      const suggested = leases?.items.find((l) => l.ip === ip)?.hostname;
      // A guess only pre-fills the form (owner, 2026-10-09): it never becomes a name by itself.
      const guess = id?.available && id.level !== 'unknown' ? (id.product ?? undefined) : undefined;
      newName = existing?.name ?? name ?? suggested ?? guess ?? '';
      chosen = existing ? [...existing.groups] : ['default'];
      if (mode === 'groups' && id?.suggestedGroup && !chosen.includes(id.suggestedGroup)) {
        chosen = [id.suggestedGroup, ...chosen.filter((x) => x !== 'default')];
      }
      kind = existing?.kind ?? '';
      first = { name: newName, groups: [...chosen], kind };
      // For a new device the MAC is what the form starts with only when a router reports it, for
      // this address alone: the kernel's table is this server's (not a cluster's, a pod's or
      // Docker's), and a shared MAC can't tell devices apart. A device that already exists keeps its
      // keys unless the MAC is chosen: re-saving it to change a group must not strip its address.
      useMac = !existing && (recognition?.macFrom === 'router' || recognition?.macFrom === 'peer') && !recognition.macShared;
      if (target?.name !== existing?.name) fill();
    } catch (e) {
      serverError = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  }

  /** The form's fields from the device edited (the one that has the MAC, when the MAC is chosen), or what it started with. */
  function fill() {
    const t = target;
    if (t) {
      newName = t.name;
      chosen = [...t.groups];
      kind = t.kind ?? '';
    } else if (first) {
      newName = first.name;
      chosen = [...first.groups];
      kind = first.kind;
    }
  }

  /** The "Recognize it by" choice: the MAC address, or this address. */
  function recognizeBy(mac: boolean) {
    const before = target?.name;
    useMac = mac;
    if (target?.name !== before) fill();
  }

  /**
   * The keys the device is recognized by: what it has now (or this address, for a new device); with
   * the MAC chosen, the MAC first and no key for this address, the other keys kept.
   */
  function matchFor(): string[] {
    const base = target ? target.match : [ip];
    if (!macChosen) return base;
    return [mac, ...base.filter((k) => !sameIp(k, ip) && !(isMac(k) && normMac(k) === mac))];
  }

  function toggle(g: string) {
    chosen = chosen.includes(g) ? chosen.filter((x) => x !== g) : [...chosen, g];
  }

  /** REQ: OBS-024 — the device change as a dry run, replayed over the query log. */
  async function simulateChange(): Promise<S['Simulation'] | null | undefined> {
    const n = newName.trim();
    const r = await api.putClient(
      target?.name ?? n,
      { name: n, match: matchFor(), groups: chosen.length ? chosen : ['default'] },
      true,
      'true',
    );
    return r.simulation;
  }

  async function save(ev: SubmitEvent) {
    ev.preventDefault();
    const n = newName.trim();
    if (!n) {
      nameError = true;
      return;
    }
    busy = true;
    serverError = '';
    nameError = false;
    try {
      const r = await api.putClient(target?.name ?? n, {
        name: n,
        match: matchFor(),
        groups: chosen.length ? chosen : ['default'],
        kind: kind || undefined,
      });
      saved =
        r.recentQueries > 0 ? { kind: 'recent', n: r.recentQueries, name: n } : { kind: 'queries', who, name: n };
      onchanged?.(n);
    } catch (e) {
      serverError = e instanceof ApiError && e.hint ? `${e.message} ${e.hint}` : e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }
</script>

<svelte:window onclick={outside} onkeydown={key} />

<span class="chip" bind:this={root}>
  <button
    class="link chip-button"
    title={tip}
    aria-haspopup="menu"
    aria-expanded={open}
    data-testid={workload ? 'workload-chip' : undefined}
    onclick={(e) => {
      e.stopPropagation();
      open = !open;
    }}
    >{#if workload}<span class="glyph" aria-label={tr('qw.chip.glyph')}><Icon name="workload" size={14} /></span>{/if}{display ?? label}</button
  >
  {#if open}
    <span class="menu" role="menu" aria-label={tr('qw.chip.menu', { ip })}>
      {#if canEdit && workload}
        <button role="menuitem" disabled title={tr('qw.chip.kubernetesNames')}>{tr('qw.chip.name')} <span class="muted small">{tr('qw.chip.namedByKubernetes')}</span></button>
        <button role="menuitem" onclick={editWorkload}>{tr('qw.chip.addToGroup')}</button>
      {:else if canEdit}
        <button role="menuitem" onclick={() => edit('name')}>{tr('qw.chip.name')}</button>
        <button role="menuitem" onclick={() => edit('groups')}>{tr('qw.chip.addToGroup')}</button>
      {/if}
      <a role="menuitem" href={href('/queries', { client: workload ? workload.name : ip })} onclick={close}>{tr('qw.chip.showQueries')}</a>
    </span>
  {/if}
</span>

{#if editing === 'workload' && workload}
  <Drawer title={tr('qw.chip.workload.title')} onclose={() => (editing = null)}>
    {#if loading}
      <p class="muted" role="status" aria-live="polite">{tr('common.loading')}</p>
    {:else}
      <form class="stack" onsubmit={saveWorkload} data-testid="workload-group-form">
        <p class="muted small">
          <b>{workload.name}</b> {tr('qw.chip.workload.isK8s')}
          {#if workload.group}{tr('qw.chip.workload.groupNow', { group: workload.group, from: groupFromText[workload.groupFrom] ?? workload.groupFrom })}{:else}{tr('qw.chip.workload.noGroup')}{/if} {tr('qw.chip.workload.ruleLead')} <code>telltaledns.io/group</code> {tr('qw.chip.workload.ruleTail')}<HelpButton id="kubernetes-workloads" />
        </p>
        <label>
          {tr('qw.chip.group')}
          <select bind:value={wGroup} onchange={() => (preview = null)} aria-label={tr('qw.chip.group')}>
            <option value="" disabled>{tr('qw.chip.group.choose')}</option>
            {#each groups as g (g.name)}<option value={g.name}>{g.name}</option>{/each}
          </select>
        </label>
        {#if preview}
          <div class="notice" data-testid="workload-dry-run">
            <p class="impact">{preview.impact}</p>
            {#if preview.keepInGit}<pre class="small">{preview.keepInGit}</pre>{/if}
          </div>
        {/if}
        {#if error}<p class="notice bad" role="alert">{error}</p>{/if}
        {#if done}<p class="notice ok" role="status">{done}</p>{/if}
        <div class="row">
          {#if !preview}
            <button type="button" class="primary" disabled={busy || !wGroup} onclick={previewWorkload}>{busy ? tr('qw.chip.checking') : tr('qw.chip.preview')}</button>
          {:else}
            <button type="submit" class="primary" disabled={busy || !!done}>{busy ? tr('qw.chip.saving') : tr('common.save')}</button>
          {/if}
          <button type="button" onclick={() => (editing = null)}>{tr('common.close')}</button>
        </div>
      </form>
    {/if}
  </Drawer>
{:else if editing === 'name' || editing === 'groups'}
  <Drawer title={editing === 'name' ? tr('qw.chip.name.title') : tr('qw.chip.groups.title')} onclose={() => (editing = null)}>
    {#if loading}
      <p class="muted" role="status" aria-live="polite">{tr('common.loading')}</p>
    {:else if existing && existing.source === 'file'}
      <p class="notice">
        <b>{existing.name}</b> {tr('qw.chip.fromFile')}
      </p>
    {:else}
      <form class="stack" onsubmit={save}>
        <p class="muted small">
          {#if macChosen}{tr('qw.chip.form.intro.macLead')}<code>{mac}</code>{tr('qw.chip.form.intro.macMid')} <code>{ip}</code>{tr('qw.chip.form.intro.macTail', { match: matchFor().join(', ') })}{:else}{tr('qw.chip.form.intro.ipLead')} <code>{ip}</code> {tr('qw.chip.form.intro.ipTail', { match: matchFor().join(', ') })}{/if}
        </p>
        <label>
          {tr('qw.chip.form.name')}
          <input name="device-name" bind:value={newName} placeholder={tr('qw.chip.form.namePlaceholder')} maxlength="64" required />
        </label>
        <HelpButton id="device-name" />
        {#if identity?.available && identity.level !== 'unknown' && identity.product && identity.source !== 'override'}
          <p class="muted small" data-testid="identity-suggestion">
            {tr(articleKey(identity.product), { product: identity.product, level: identity.level })}
            {#if identity.suggestedGroup}{tr('qw.chip.identity.suggestedGroup', { group: identity.suggestedGroup })}{/if}
          </p>
        {/if}
        <label>
          {tr('qw.chip.form.kind')}
          <select bind:value={kind} aria-label={tr('qw.chip.form.kind')}>
            <option value="">{tr('qw.chip.form.kind.guess')}</option>
            {#each kinds as k (k)}<option value={k}>{k === 'unknown' ? tr('qw.chip.kind.unknownStop') : kindLabel(k)}</option>{/each}
          </select>
        </label>
        <fieldset>
          <legend>{tr('qw.chip.form.groups')} <span class="muted small">{tr('qw.chip.form.groupsFirst')}</span><HelpButton id="device-groups" /></legend>
          {#each groups as g (g.name)}
            <label class="check"><input type="checkbox" checked={chosen.includes(g.name)} onchange={() => toggle(g.name)} /> {g.name}</label>
          {/each}
        </fieldset>
        {#if offerMac}
          <!-- REQ: FLT-006, API-010 (ADR-183) — a MAC address follows the device when its address changes. -->
          <fieldset data-testid="recognize-by">
            <legend>{tr('qw.chip.form.mac')}<HelpButton id="device-mac" /></legend>
            <label class="check">
              <input type="radio" name="recognize-by" value="mac" checked={useMac} onchange={() => recognizeBy(true)} />
              <span>{tr('qw.chip.mac.itsMac')} <code>{mac}</code> <span class="muted small">{tr('qw.chip.mac.follows', { source: macSource, vouch: macVouch })}</span></span>
            </label>
            <label class="check">
              <input type="radio" name="recognize-by" value="ip" checked={!useMac} onchange={() => recognizeBy(false)} />
              <span>{tr('qw.chip.mac.thisAddress')} <code>{ip}</code><span class="muted small">{tr('qw.chip.mac.thisAddressTail')}</span></span>
            </label>
            {#if macReason}<p class="muted small" data-testid="mac-reason">{macReason}</p>{/if}
            {#if macChosen && heldElsewhere && macHolder}
              <p class="notice" data-testid="mac-holder">{tr('qw.chip.mac.holder', { name: macHolder.name })}</p>
            {/if}
            {#if macChosen && recognition?.macRandomized}
              <p class="notice" data-testid="mac-randomized">
                {tr('qw.chip.mac.randomized')}
              </p>
            {/if}
            {#if macChosen && !matchFor().some((k) => !isMac(k) && !k.startsWith('id:'))}
              <p class="muted small" data-testid="mac-only-limits">
                {tr('qw.chip.mac.onlyLimits')}
              </p>
            {/if}
          </fieldset>
        {/if}
        {#if newName.trim()}
          <ChangePreview
            highlight="blocked"
            device={newName.trim()}
            name={tr('qw.chip.preview.anySite')}
            sentence={tr('qw.chip.preview.sentence', {
              who,
              name: newName.trim(),
              lists: chosen.length ? chosen.join(', ') : 'default',
            })}
            simulate={simulateChange}
          />
        {/if}
        {#if error}<p class="notice bad" role="alert">{error}</p>{/if}
        {#if done}<p class="notice ok" role="status">{done}</p>{/if}
        <div class="row">
          <button type="submit" class="primary" disabled={busy}>{busy ? tr('qw.chip.saving') : tr('common.save')}</button>
          <button type="button" onclick={() => (editing = null)}>{tr('common.close')}</button>
        </div>
      </form>
    {/if}
  </Drawer>
{/if}

<style>
  .impact {
    margin: 0;
  }
  .chip {
    position: relative;
    display: inline-block;
  }
  .chip-button {
    font: inherit;
    padding: 0;
  }
  .glyph {
    display: inline-flex;
    vertical-align: -2px;
    margin-right: 3px;
    color: var(--accent, currentColor);
  }
  .menu button:disabled {
    opacity: 0.6;
    cursor: default;
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
