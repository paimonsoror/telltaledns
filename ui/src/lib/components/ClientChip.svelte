<script module lang="ts">
  // REQ: API-012 — the binder and the device kinds' names are made once for the file, not once per
  // chip: the chip is a row of the query log, and the kinds are read only in the name drawer's list.
  import { tk, tr, type Msg } from '../i18n';
  import T from '../i18n/T.svelte';
  const { t, m } = tr('clientChip');

  const kinds = ['phone', 'tablet', 'laptop', 'desktop', 'tv', 'streaming', 'speaker', 'console', 'camera', 'doorbell', 'plug', 'bulb', 'thermostat', 'hub', 'vacuum', 'printer', 'nas', 'network', 'appliance', 'wearable', 'car', 'other', 'unknown'];
  /** How each kind is named in the list (the value sent stays the kind). */
  const KIND_TEXT: Record<string, Msg> = {
    phone: m('phone'),
    tablet: m('tablet'),
    laptop: m('laptop'),
    desktop: m('desktop'),
    tv: m('tv'),
    streaming: m('streaming'),
    speaker: m('speaker'),
    console: m('console'),
    camera: m('camera'),
    doorbell: m('doorbell'),
    plug: m('plug'),
    bulb: m('bulb'),
    thermostat: m('thermostat'),
    hub: m('hub'),
    vacuum: m('vacuum'),
    printer: m('printer'),
    nas: m('nas'),
    network: m('network'),
    appliance: m('appliance'),
    wearable: m('wearable'),
    car: m('car'),
    other: m('other'),
  };
</script>

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
  import { isMac, listsMac, normMac, sameIp } from '../macKeys';

  let {
    ip,
    name = null,
    onchanged,
    display,
    chip = true,
  }: {
    ip: string;
    name?: string | null;
    onchanged?: (name: string) => void;
    /** What to show in place of the name (a pod's workload for its full pod name); the name is still the device's. */
    display?: string;
    /** False: no chip and no menu, only the dialogs, opened with `nameDevice()` (the quick rule form's MAC hint). */
    chip?: boolean;
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
        ? t('Kubernetes workload {name} (pod {pod}, {ip})', { name: workload.name, pod, ip })
        : workload.pods.length
          ? t('Kubernetes workload {name} (pods: {pods})', { name: workload.name, pods: workload.pods.map((p) => p.name).join(', ') })
          : t('Kubernetes workload {name}', { name: workload.name })
      : name
        ? `${name} (${ip})`
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
  const macSource = $derived(recognition?.macFrom === 'neighbor' ? t('seen on this network') : t('from your router'));
  /** What keeps vouching for the MAC, and what it can't follow: the sentence says so, not just that the MAC "follows". */
  const macVouch = $derived(
    recognition?.macFrom === 'neighbor'
      ? t("this server's neighbor table still holds this MAC at one address")
      : t('your router still reports this MAC at one address (IPv4 only)'),
  );
  /** Why the address, not the MAC, is what the form starts with. */
  const macReason = $derived(
    recognition?.macShared
      ? recognition.macFrom === 'neighbor'
        ? t("This server's neighbor table holds this MAC address at more than one address (a range extender or bridge may share it), so it can't tell these devices apart.")
        : t("Your router reports this MAC address at more than one address (a range extender or bridge may share it), so it can't tell these devices apart.")
      : recognition?.macFrom === 'neighbor'
        ? t("Only this server sees this MAC address directly: other servers in your cluster, or one in Docker or Kubernetes, won't recognize the device by it.")
        : '',
  );
  /** Who the sentences below talk about. */
  const who = $derived(macChosen ? t('this device ({mac}, now at {ip})', { mac, ip }) : ip);
  /** An English article goes with the product's name: one message for each (REQ: API-012). */
  const an = (p: string) => /^[aeiou]/i.test(p);
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

  /** REQ: FLT-017 — "Add to group…" for a workload: its groups, then a dry run, then a rule. */
  async function editWorkload() {
    open = false;
    editing = 'workload';
    error = '';
    done = '';
    preview = null;
    loading = true;
    try {
      groups = (await api.groups()).items;
      wGroup = workload?.group ?? '';
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  }

  async function previewWorkload() {
    if (!workload || !wGroup) return;
    busy = true;
    error = '';
    try {
      preview = await api.putWorkloadGroup(workload.name, wGroup, true);
    } catch (e) {
      error = e instanceof ApiError && e.hint ? `${e.message} ${e.hint}` : e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  async function saveWorkload(ev: SubmitEvent) {
    ev.preventDefault();
    if (!workload || !wGroup) return;
    busy = true;
    error = '';
    try {
      await api.putWorkloadGroup(workload.name, wGroup);
      done = t("Saved. {name}'s next query uses {group}.", { name: workload.name, group: wGroup });
      void loadWorkloads(true);
      onchanged?.(workload.name);
    } catch (e) {
      error = e instanceof ApiError && e.hint ? `${e.message} ${e.hint}` : e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  async function edit(mode: 'name' | 'groups') {
    open = false;
    editing = mode;
    error = '';
    done = '';
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
      error = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  }

  /**
   * REQ: FLT-005, FLT-006 (ADR-183, GitHub issue #95) — "Name this device…" for this address, as the menu opens it: for a
   * place that links to the dialog without showing a chip (the quick rule form, whose own form must not hold this one's).
   */
  export function nameDevice() {
    void edit('name');
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
      error = t('Give the device a name.');
      return;
    }
    busy = true;
    error = '';
    try {
      const r = await api.putClient(target?.name ?? n, {
        name: n,
        match: matchFor(),
        groups: chosen.length ? chosen : ['default'],
        kind: kind || undefined,
      });
      done =
        r.recentQueries > 0
          ? t('Saved. {n} recent queries now show “{name}”.', { n: r.recentQueries, name: n })
          : t('Saved. Queries from {who} now show “{name}”.', { who, name: n });
      onchanged?.(n);
    } catch (e) {
      error = e instanceof ApiError && e.hint ? `${e.message} ${e.hint}` : e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }
</script>

<svelte:window onclick={outside} onkeydown={key} />

{#if chip}
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
    >{#if workload}<span class="glyph" aria-label={t('Kubernetes workload')}><Icon name="workload" size={14} /></span>{/if}{display ?? label}</button
  >
  {#if open}
    <span class="menu" role="menu" aria-label={t('Device {ip}', { ip })}>
      {#if canEdit && workload}
        <button role="menuitem" disabled title={t('Kubernetes names workloads')}>{t('Name this device…')} <span class="muted small">{t('(named by Kubernetes)')}</span></button>
        <button role="menuitem" onclick={editWorkload}>{t('Add to group…')}</button>
      {:else if canEdit}
        <button role="menuitem" onclick={() => edit('name')}>{t('Name this device…')}</button>
        <button role="menuitem" onclick={() => edit('groups')}>{t('Add to group…')}</button>
      {/if}
      <a role="menuitem" href={href('/queries', { client: workload ? workload.name : ip })} onclick={close}>{t('Show queries')}</a>
    </span>
  {/if}
</span>
{/if}

{#if editing === 'workload' && workload}
  <Drawer title={t('Put the workload in a group')} onclose={() => (editing = null)}>
    {#if loading}
      <p class="muted" role="status" aria-live="polite">{t('Loading…')}</p>
    {:else}
      <form class="stack" onsubmit={saveWorkload} data-testid="workload-group-form">
        <p class="muted small">
          <T ctx="clientChip" msg={'<b>{name}</b> is a Kubernetes workload: its name comes from Kubernetes.'} params={{ name: workload.name }}
            >{#snippet b(text: string)}<b translate="no">{text}</b>{/snippet}</T
          >
          {#if workload.group}{t('Its group is {group} now (set by its {from}).', { group: workload.group, from: groupFromText(workload.groupFrom) })}{:else}{t(
              "It has no group of its own now: its network's group applies.",
            )}{/if}
          <T
            ctx="clientChip"
            msg={'This adds a rule for exactly this workload; a <groupkey/> label on its pods or namespace still wins, and is the way to do it from Git.'}
            >{#snippet groupkey()}<code translate="no">telltaledns.io/group</code>{/snippet}</T
          ><HelpButton id="kubernetes-workloads" />
        </p>
        <label>
          {t('Group')}
          <select bind:value={wGroup} onchange={() => (preview = null)} aria-label={t('Group')}>
            <option value="" disabled>{t('Choose a group')}</option>
            {#each groups as g (g.name)}<option value={g.name} translate="no">{g.name}</option>{/each}
          </select>
        </label>
        {#if preview}
          <div class="notice" data-testid="workload-dry-run">
            <p class="impact">{preview.impact}</p>
            {#if preview.keepInGit}<pre class="small" translate="no">{preview.keepInGit}</pre>{/if}
          </div>
        {/if}
        {#if error}<p class="notice bad" role="alert">{error}</p>{/if}
        {#if done}<p class="notice ok" role="status">{done}</p>{/if}
        <div class="row">
          {#if !preview}
            <button type="button" class="primary" disabled={busy || !wGroup} onclick={previewWorkload}>{busy ? t('Checking…') : t('Preview')}</button>
          {:else}
            <button type="submit" class="primary" disabled={busy || !!done}>{busy ? t('Saving…') : t('Save')}</button>
          {/if}
          <button type="button" onclick={() => (editing = null)}>{t('Close')}</button>
        </div>
      </form>
    {/if}
  </Drawer>
{:else if editing === 'name' || editing === 'groups'}
  <Drawer title={editing === 'name' ? t('Name this device') : t('Add to a group')} onclose={() => (editing = null)}>
    {#if loading}
      <p class="muted" role="status" aria-live="polite">{t('Loading…')}</p>
    {:else if existing && existing.source === 'file'}
      <p class="notice">
        <T ctx="clientChip" msg={"<b>{name}</b> is defined in the configuration file, so it's changed there, not here."} params={{ name: existing.name }}
          >{#snippet b(text: string)}<b translate="no">{text}</b>{/snippet}</T
        >
      </p>
    {:else}
      <form class="stack" onsubmit={save}>
        <p class="muted small">
          {#if macChosen}
            <T
              ctx="clientChip"
              msg={'Queries from this device (<code>{mac}</code>, now at <code>{ip}</code>) will show this name everywhere, including past ones. The device is recognized by {keys}.'}
              params={{ mac, ip, keys: matchFor().join(', ') }}>{#snippet code(text: string)}<code translate="no">{text}</code>{/snippet}</T
            >
          {:else}
            <T
              ctx="clientChip"
              msg={'Queries from <code>{ip}</code> will show this name everywhere, including past ones. The device is recognized by {keys}.'}
              params={{ ip, keys: matchFor().join(', ') }}>{#snippet code(text: string)}<code translate="no">{text}</code>{/snippet}</T
            >
          {/if}
        </p>
        <label>
          {t('Name')}
          <input name="device-name" bind:value={newName} placeholder={t('Living room TV')} maxlength="64" required />
        </label>
        <HelpButton id="device-name" />
        {#if identity?.available && identity.level !== 'unknown' && identity.product && identity.source !== 'override'}
          <p class="muted small" data-testid="identity-suggestion">
            {an(identity.product)
              ? t('Looks like an {product} ({level}).', { product: identity.product, level: identity.level })
              : t('Looks like a {product} ({level}).', { product: identity.product, level: identity.level })}
            {#if identity.suggestedGroup}{t('The {group} group asks for this kind of device.', { group: identity.suggestedGroup })}{/if}
          </p>
        {/if}
        <label>
          {t('What it is')}
          <select bind:value={kind} aria-label={t('What it is')}>
            <option value="">{t('Let TelltaleDNS guess')}</option>
            {#each kinds as k (k)}<option value={k}>{k === 'unknown' ? t('unknown (stop guessing)') : tk(KIND_TEXT[k])}</option>{/each}
          </select>
        </label>
        <fieldset>
          <legend>{t('Groups')} <span class="muted small">{t("(first one's settings apply)")}</span><HelpButton id="device-groups" /></legend>
          {#each groups as g (g.name)}
            <label class="check" translate="no"><input type="checkbox" checked={chosen.includes(g.name)} onchange={() => toggle(g.name)} /> {g.name}</label>
          {/each}
        </fieldset>
        {#if offerMac}
          <!-- REQ: FLT-006, API-010 (ADR-183) — a MAC address follows the device when its address changes. -->
          <fieldset data-testid="recognize-by">
            <legend>{t('Recognize it by')}<HelpButton id="device-mac" /></legend>
            <label class="check">
              <input type="radio" name="recognize-by" value="mac" checked={useMac} onchange={() => recognizeBy(true)} />
              <span
                ><T
                  ctx="clientChip"
                  msg={'Its MAC address, <code>{mac}</code> <muted>({source}): follows the device when its address changes, while {vouch}</muted>'}
                  params={{ mac, source: macSource, vouch: macVouch }}
                  >{#snippet code(text: string)}<code translate="no">{text}</code>{/snippet}{#snippet muted(text: string)}<span class="muted small">{text}</span>{/snippet}</T
                ></span
              >
            </label>
            <label class="check">
              <input type="radio" name="recognize-by" value="ip" checked={!useMac} onchange={() => recognizeBy(false)} />
              <span
                ><T
                  ctx="clientChip"
                  msg={'This address, <code>{ip}</code><muted>: stops matching if the device gets another address (a DHCP reservation in your router keeps it)</muted>'}
                  params={{ ip }}
                  >{#snippet code(text: string)}<code translate="no">{text}</code>{/snippet}{#snippet muted(text: string)}<span class="muted small">{text}</span>{/snippet}</T
                ></span
              >
            </label>
            {#if macReason}<p class="muted small" data-testid="mac-reason">{macReason}</p>{/if}
            {#if macChosen && heldElsewhere && macHolder}
              <p class="notice" data-testid="mac-holder">{t('{name} already has this MAC address: this changes {name}.', { name: macHolder.name })}</p>
            {/if}
            {#if macChosen && recognition?.macRandomized}
              <p class="notice" data-testid="mac-randomized">
                {t('This is a private Wi-Fi address the device made up. It stays the same on your network unless the device is set to change it or forgets the network; if it changes, name the device again, or turn its private address off for this network.')}
              </p>
            {/if}
            {#if macChosen && !matchFor().some((k) => !isMac(k) && !k.startsWith('id:'))}
              <p class="muted small" data-testid="mac-only-limits">
                {t('With only a MAC address, this device isn\'t covered by its group\'s anomaly mutes, change previews and simulations, the Clients page\'s guess of what it is, or look-ups of its identity and rhythm by name.')}
              </p>
            {/if}
          </fieldset>
        {/if}
        {#if newName.trim()}
          <ChangePreview
            highlight="blocked"
            device={newName.trim()}
            name={t('any site')}
            sentence={t('Queries from {who} will show “{name}”, past ones included, and get the lists of {groups}.', {
              who,
              name: newName.trim(),
              groups: chosen.length ? chosen.join(', ') : 'default',
            })}
            simulate={simulateChange}
          />
        {/if}
        {#if error}<p class="notice bad" role="alert">{error}</p>{/if}
        {#if done}<p class="notice ok" role="status">{done}</p>{/if}
        <div class="row">
          <button type="submit" class="primary" disabled={busy}>{busy ? t('Saving…') : t('Save')}</button>
          <button type="button" onclick={() => (editing = null)}>{t('Close')}</button>
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
