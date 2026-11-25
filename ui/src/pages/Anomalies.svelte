<script lang="ts">
  // REQ: OBS-013 — device anomalies with their evidence: what was seen, the device's usual value
  // (± spread), and the bar it crossed. Alert-only: nothing here blocks anything.
  // REQ: OBS-014 — acknowledging: mark findings as seen, on every node; they stop counting in
  // the badge and hide here unless "Show acknowledged" is on.
  // REQ: OBS-038 — muting: a kind of finding for a device stops counting (it is still recorded);
  // muted findings hide here unless "Show muted" is on, and the mutes are listed below.
  // REQ: OBS-038 (ADR-186) — a sweep of local addresses is its own kind: a mute made for one when
  // it still counted as a burst of failed lookups is pointed out on the sweep.
  import { api, type S } from '../lib/api';
  import { href } from '../lib/router.svelte';
  import { can } from '../lib/session.svelte';
  import { dateTime, num } from '../lib/format';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import RhythmStrip from '../lib/components/RhythmStrip.svelte';
  import MuteForm from '../lib/components/MuteForm.svelte';
  import KeepInGit from '../lib/components/KeepInGit.svelte';

  let all = $state<S['AnomalyFinding'][]>([]);
  let showAcked = $state(false);
  let showMuted = $state(false);
  // The ones that count; muted findings are listed only on request.
  const counted = $derived(all.filter((f) => !f.mutedBy));
  const visible = $derived(showMuted ? all : counted);
  const items = $derived(showAcked ? visible : visible.filter((f) => !f.acknowledged));
  const ackedCount = $derived(visible.filter((f) => f.acknowledged).length);
  const mutedCount = $derived(all.length - counted.length);
  const open = $derived(counted.filter((f) => !f.acknowledged));
  // REQ: OBS-038 — the mutes (from the files or the API), and the finding whose form is open.
  type MuteDef = { devices?: string[]; groups?: string[]; kinds?: string[]; expires?: string; note?: string };
  let mutes = $state<S['ConfigEntry'][]>([]);
  let muteFor = $state<string | null>(null);
  // What the last mute did: kept on the page, because the finding it muted leaves the list.
  let muted = $state<S['ConfigChange'] | null>(null);
  const muteDef = (e: S['ConfigEntry']) => (e.definition ?? {}) as unknown as MuteDef;
  const noteOf = (name: string) => {
    const e = mutes.find((m) => m.name === name);
    return e ? muteDef(e).note : undefined;
  };
  const ended = (e: S['ConfigEntry']) => {
    const x = muteDef(e).expires;
    return !!x && Date.parse(x) <= Date.now();
  };
  const writable = $derived(can('operator'));
  let busy = $state(false);
  let actionError = $state<unknown>(null);
  let reloadTick = $state(0);
  // REQ: OBS-009 (T7.14) — first-seen domains, with how machine-generated each name looks.
  let fresh = $state<S['NewDomain'][]>([]);
  let suspiciousOnly = $state(false);
  const shown = $derived(suspiciousOnly ? fresh.filter((d) => d.dgaScore >= 0.6) : fresh);
  let error = $state<unknown>(null);
  let loaded = $state(false);
  let range = $state('-7d');

  const titles: Record<string, string> = {
    rate_spike: 'Many more queries than usual',
    domain_volume: 'Unusual traffic to one domain',
    drift: 'Many new domains',
    beacon: 'Regular phone-home',
    chatty_loop: 'Chatty loop',
    nxdomain_storm: 'Burst of failed lookups',
    reverse_sweep: 'Sweep of local addresses',
    dga: 'Machine-generated-looking domains',
  };
  // Findings measured against an absolute bar, not the device's usual value.
  const absolute = new Set(['nxdomain_storm', 'reverse_sweep', 'dga']);
  // The mute of bursts that a counted sweep names (`stormMute`), while it still lists
  // nxdomain_storm and not reverse_sweep: before 0.9 a sweep counted as a burst, so the mute was
  // probably made for it, and it no longer covers the sweep.
  const stormMuteOf = (f: S['AnomalyFinding']) => {
    if (f.kind !== 'reverse_sweep' || f.mutedBy || !f.stormMute) return undefined;
    const e = mutes.find((m) => m.name === f.stormMute);
    const kinds = e ? (muteDef(e).kinds ?? []) : [];
    return e && kinds.includes('nxdomain_storm') && !kinds.includes('reverse_sweep') ? e : undefined;
  };
  const windowText = (s: number) => (s >= 86400 ? `${s / 86400} day` : s >= 3600 ? `${s / 3600} h` : `${s / 60} min`);

  async function removeMute(name: string) {
    busy = true;
    actionError = null;
    try {
      await api.deleteEntry('anomaly-mutes', name);
      reloadTick++;
      window.dispatchEvent(new Event('telltale:anomalies-changed'));
    } catch (e) {
      actionError = e;
    } finally {
      busy = false;
    }
  }

  async function change(ids: string[], ack: boolean) {
    if (ids.length === 0) return;
    busy = true;
    actionError = null;
    try {
      await (ack ? api.acknowledgeAnomalies(ids) : api.unacknowledgeAnomalies(ids));
      reloadTick++;
      // The sidebar badge counts unacknowledged findings: let it refresh now.
      window.dispatchEvent(new Event('telltale:anomalies-changed'));
    } catch (e) {
      actionError = e;
    } finally {
      busy = false;
    }
  }

  $effect(() => {
    void range;
    void reloadTick;
    api
      .anomalies(range, undefined, true)
      .then((r) => {
        all = r.items;
        loaded = true;
      })
      .catch((e) => (error = e));
    api
      .configEntries('anomaly_mute')
      .then((r) => (mutes = r.items))
      .catch(() => (mutes = []));
    api
      .newDomains(range === '-24h' ? '-24h' : range, 500)
      .then((r) => (fresh = r.items))
      .catch(() => (fresh = []));
  });
</script>

<div class="page">
  <div class="page-head">
    <h1>Anomalies<HelpButton id="anomalies" /></h1>
    <label class="pill-field">
      Show
      <select bind:value={range} aria-label="Time range">
        <option value="-24h">last 24 hours</option>
        <option value="-7d">last 7 days</option>
        <option value="-30d">last 30 days</option>
      </select>
    </label>
  </div>
  <ErrorNote {error} />
  <ErrorNote error={actionError} />
  {#if muted}
    <div class="notice ok small" data-testid="mute-saved">
      Muted. {muted.impact ?? ''}
      <button class="link small" onclick={() => (muted = null)}>Dismiss</button>
    </div>
    {#if muted.keepInGit}<KeepInGit toml={muted.keepInGit} />{/if}
  {/if}
  <p class="muted small">
    Each device is compared with its own usual behavior, learned over its first week. Findings only inform you; to act,
    open the device's queries or move it to a stricter group. Acknowledge a finding once you've looked at it: it stops
    counting as new, on every node. Mute a kind of finding for a device that does it harmlessly, over and over.
  </p>
  <div class="row toolbar">
    <span class="switch-track"><label class="switch"><input type="checkbox" role="switch" bind:checked={showAcked} data-testid="show-acknowledged" />Show acknowledged ({ackedCount})</label></span>
    <span class="switch-track"><label class="switch"><input type="checkbox" role="switch" bind:checked={showMuted} data-testid="show-muted" />Show muted ({mutedCount})</label></span>
    <span class="spacer"></span>
    {#if writable && open.length > 1}
      <button class="small" disabled={busy} onclick={() => change(open.map((f) => f.id), true)} data-testid="ack-all"
        >Acknowledge all {open.length}</button
      >
    {/if}
  </div>
  {#if loaded && items.length === 0}
    <section class="card">
      <p class="empty">
        {#if ackedCount > 0}Nothing new: every finding in this period is acknowledged.{:else if mutedCount > 0}Nothing unusual: {mutedCount} muted {mutedCount === 1 ? 'finding is' : 'findings are'} hidden.{:else}Nothing unusual. New devices are quiet here for their first 7 days while TelltaleDNS learns them.{/if}
      </p>
    </section>
  {/if}
  {#each items as f (f.id)}
    <section class="card finding" class:acked={!!f.acknowledged} class:muted-finding={!!f.mutedBy} data-testid="anomaly">
      <div class="row">
        <span class="badge {f.informational ? '' : f.kind === 'beacon' || f.kind === 'drift' ? 'warn' : 'bad'}">{titles[f.kind] ?? f.kind}</span>
        {#if f.informational}<span class="muted small" data-testid="informational">for your information: not counted as an anomaly</span>{/if}
        <strong>{f.clientName ?? f.client}</strong>
        {#if f.domain}<span class="mono">→ {f.domain}</span>{/if}
        <span class="spacer"></span>
        <span class="muted small">{dateTime(Date.parse(f.windowStart) / 1000)}</span>
      </div>
      {#if f.kind === 'reverse_sweep'}
        <p class="muted small" data-testid="sweep-explained">
          This device looked up the names of many addresses on your network. Network scanners do this, and so do some TVs and NAS boxes, on their own, often once an hour.
        </p>
      {/if}
      <p>{f.detail}</p>
      {#if writable}
        {@const old = stormMuteOf(f)}
        {#if old}
          <p class="notice small" data-testid="storm-mute-hint">
            <b>{old.name}</b> mutes <i>Burst of failed lookups</i> for this device. Before 0.9 a sweep counted as one, so that mute was probably made for it: it now hides only this device's real bursts. Mute the sweep, then remove <b>{old.name}</b> if the sweep was its only reason.
            {#if old.source === 'file'}
              <span class="muted">It's in the config file: change its kinds there.</span>
            {:else}
              <button class="link small" disabled={busy} onclick={() => removeMute(old.name)} data-testid="remove-storm-mute">Remove {old.name}</button>
            {/if}
          </p>
        {/if}
      {/if}
      {#if (f.kind === 'beacon' || f.kind === 'chatty_loop') && f.rhythm && f.domain}
        <!-- REQ: OBS-031 — the beacon's rhythm when it was reported. -->
        <RhythmStrip rows={[{ domain: f.domain, recent: f.rhythm }]} client={f.client} toggle={false} />
      {/if}
      {#if f.mutedBy}
        <p class="small ack-line" data-testid="muted">
          <span class="badge">Muted</span>
          by <b>{f.mutedBy}</b>: not counted in the badge, the alerts or the metrics{#if noteOf(f.mutedBy)}: “{noteOf(f.mutedBy)}”{/if}
        </p>
      {/if}
      {#if f.acknowledged}
        <p class="small ack-line" data-testid="acknowledged">
          <span class="badge ok">Acknowledged</span>
          by {f.acknowledged.by}, {dateTime(Date.parse(f.acknowledged.at) / 1000)}{#if f.acknowledged.note}: “{f.acknowledged.note}”{/if}
        </p>
      {/if}
      <dl class="evidence small">
        <dt>Observed</dt><dd>{num(Math.round(f.observed * 10) / 10)}</dd>
        {#if f.kind === 'nxdomain_storm'}
          <dt>Queries</dt><dd>{num(f.baseline)}</dd>
        {:else if f.kind === 'reverse_sweep'}
          <dt>Reverse lookups</dt><dd>{num(f.baseline)}</dd>
        {:else if !absolute.has(f.kind)}
          <dt>Usual</dt><dd>{num(Math.round(f.baseline * 10) / 10)} ± {num(Math.round(f.spread * 10) / 10)}</dd>
        {/if}
        <dt>Threshold</dt><dd>{num(Math.round(f.threshold * 10) / 10)}</dd>
        <dt>Window</dt><dd>{windowText(f.windowSeconds)}</dd>
      </dl>
      <div class="row actions">
        <a class="small" href={href('/queries', { client: f.client, name: f.domain ?? undefined, match: f.domain ? 'suffix' : undefined })}>Show these queries</a>
        <!-- REQ: OBS-034 — the device's day around it. -->
        <a class="small" href={href('/clients', { device: f.client, view: 'timeline' })} data-testid="see-the-day">See the day</a>
        {#if f.nodes && f.nodes.length > 0}<span class="muted small">Found by {f.nodes.join(', ')}</span>{/if}
        <span class="spacer"></span>
        {#if writable}
          {#if f.mutedBy}
            <button class="link small" disabled={busy} onclick={() => removeMute(f.mutedBy ?? '')} data-testid="remove-mute-here">Remove mute</button>
          {:else}
            <button class="link small" disabled={busy} onclick={() => (muteFor = muteFor === f.id ? null : f.id)} aria-expanded={muteFor === f.id} data-testid="mute">Mute for this device…</button>
          {/if}
          {#if f.acknowledged}
            <button class="link small" disabled={busy} onclick={() => change([f.id], false)}>Undo acknowledge</button>
          {:else}
            <button class="small" disabled={busy} onclick={() => change([f.id], true)} data-testid="ack">Acknowledge</button>
          {/if}
        {/if}
      </div>
      {#if muteFor === f.id}
        <MuteForm
          finding={f}
          similar={all.filter((x) => x.client === f.client && x.kind === f.kind && !x.mutedBy).length}
          oncancel={() => (muteFor = null)}
          onsaved={(change) => {
            muted = change;
            muteFor = null;
            reloadTick++;
            window.dispatchEvent(new Event('telltale:anomalies-changed'));
          }}
        />
      {/if}
    </section>
  {/each}

  {#if mutes.length > 0}
    <section class="card" data-testid="mutes">
      <div class="row head">
        <h2>Mutes<HelpButton id="anomaly-mutes" /></h2>
      </div>
      <p class="muted small">Kinds of finding that stop counting for these devices. They are still recorded: turn on Show muted to see them.</p>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Name</th><th>For</th><th>Kinds</th><th>Until</th><th>Why</th><th></th></tr></thead>
          <tbody>
            {#each mutes as m (m.name)}
              {@const d = muteDef(m)}
              <tr data-testid="mute-row" class:ended={ended(m)}>
                <td class="mono">{m.name}</td>
                <td class="small">{[...(d.devices ?? []), ...(d.groups ?? []).map((g) => `group ${g}`)].join(', ')}</td>
                <td class="small">{(d.kinds ?? []).map((k) => titles[k] ?? k).join(', ')}</td>
                <td class="small">{#if d.expires}{ended(m) ? 'ended ' : ''}{dateTime(Date.parse(d.expires) / 1000)}{:else}until removed{/if}</td>
                <td class="small">{d.note ?? ''}</td>
                <td class="num">
                  {#if writable}
                    {#if m.source === 'file'}<span class="muted small">in the config file</span>{:else}<button class="link small" disabled={busy} onclick={() => removeMute(m.name)} data-testid="remove-mute">Remove</button>{/if}
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </section>
  {/if}

  <section class="card" data-testid="new-domains">
    <div class="row head">
      <h2>New domains<HelpButton id="new-domains" /></h2>
      <span class="spacer"></span>
      <span class="switch-track"><label class="switch"><input type="checkbox" role="switch" bind:checked={suspiciousOnly} />Only machine-generated-looking</label></span>
    </div>
    <p class="muted small">Domains each device contacted for the first time (after its first day), newest first. The score says how generated the name looks (0.6 and up is suspicious).</p>
    {#if shown.length === 0}
      <p class="empty">No new domains in this period.</p>
    {:else}
      <div class="table-wrap">
        <table>
          <thead><tr><th>First seen</th><th>Device</th><th>Domain</th><th class="num">Score</th></tr></thead>
          <tbody>
            {#each shown.slice(0, 200) as d, i (i)}
              <tr>
                <td class="small">{dateTime(Date.parse(d.time) / 1000)}</td>
                <td>{d.clientName ?? d.client}</td>
                <td class="mono"><a href={href('/queries', { client: d.client, name: d.domain, match: 'suffix' })}>{d.domain}</a></td>
                <td class="num">{#if d.dgaScore >= 0.6}<span class="badge bad">{d.dgaScore.toFixed(2)}</span>{:else}<span class="muted">{d.dgaScore.toFixed(2)}</span>{/if}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>
</div>

<style>
  .finding .row {
    gap: 10px;
    flex-wrap: wrap;
  }
  .finding.acked,
  .finding.muted-finding {
    opacity: 0.75;
  }
  .ended {
    opacity: 0.6;
  }
  .ack-line {
    margin: 4px 0;
  }
  .actions {
    align-items: center;
  }
  .toolbar {
    gap: 10px;
    align-items: center;
    margin-bottom: 8px;
  }
  .evidence {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 2px 12px;
    margin: 6px 0;
  }
  .evidence dt {
    color: var(--muted);
  }
  .evidence dd {
    margin: 0;
  }
  .head {
    gap: 10px;
    align-items: center;
  }
  .head h2 {
    margin: 0;
  }
</style>
