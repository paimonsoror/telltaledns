<script lang="ts">
  // REQ: OBS-013 — device anomalies with their evidence: what was seen, the device's usual value
  // (± spread), and the bar it crossed. Alert-only: nothing here blocks anything.
  // REQ: OBS-014 — acknowledging: mark findings as seen, on every node; they stop counting in
  // the badge and hide here unless "Show acknowledged" is on.
  // REQ: OBS-038 — muting: a kind of finding for a device stops counting (it is still recorded);
  // muted findings hide here unless "Show muted" is on, and the mutes are listed below.
  import { api, type S } from '../lib/api';
  import { href } from '../lib/router.svelte';
  import { can } from '../lib/session.svelte';
  import { dateTime, num } from '../lib/format';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import RhythmStrip from '../lib/components/RhythmStrip.svelte';
  import MuteForm from '../lib/components/MuteForm.svelte';
  import KeepInGit from '../lib/components/KeepInGit.svelte';
  import { t, tn, type MessageKey } from '../lib/i18n';

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

  // A kind the UI has words for reads in the language on screen; the value stays the identifier.
  const KIND_KEY: Record<string, MessageKey> = {
    rate_spike: 'anomalies.kind.rateSpike',
    domain_volume: 'anomalies.kind.domainVolume',
    drift: 'anomalies.kind.drift',
    beacon: 'anomalies.kind.beacon',
    chatty_loop: 'anomalies.kind.chattyLoop',
    nxdomain_storm: 'anomalies.kind.nxdomainStorm',
    dga: 'anomalies.kind.dga',
  };
  const kindLabel = (kind: string) => (KIND_KEY[kind] ? t(KIND_KEY[kind]) : kind);
  // Findings measured against an absolute bar, not the device's usual value.
  const absolute = new Set(['nxdomain_storm', 'dga']);
  const windowText = (s: number) =>
    s >= 86400
      ? tn('anomalies.window.days', s / 86400)
      : s >= 3600
        ? tn('anomalies.window.hours', s / 3600)
        : tn('anomalies.window.minutes', s / 60);

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
    <h1>{t('nav.anomalies')}<HelpButton id="anomalies" /></h1>
    <label class="pill-field">
      {t('heatmap.show')}
      <select bind:value={range} aria-label={t('legacy.timeRange')}>
        <option value="-24h">{t('anomalies.range.24h')}</option>
        <option value="-7d">{t('anomalies.range.7d')}</option>
        <option value="-30d">{t('anomalies.range.30d')}</option>
      </select>
    </label>
  </div>
  <ErrorNote {error} />
  <ErrorNote error={actionError} />
  {#if muted}
    <div class="notice ok small" data-testid="mute-saved">
      {t('anomalies.muted.saved')} {muted.impact ?? ''}
      <button class="link small" onclick={() => (muted = null)}>{t('anomalies.dismiss')}</button>
    </div>
    {#if muted.keepInGit}<KeepInGit toml={muted.keepInGit} />{/if}
  {/if}
  <p class="muted small">
    {t('anomalies.intro')}
  </p>
  <div class="row toolbar">
    <span class="switch-track"><label class="switch"><input type="checkbox" role="switch" bind:checked={showAcked} data-testid="show-acknowledged" />{t('anomalies.showAcknowledged', { n: ackedCount })}</label></span>
    <span class="switch-track"><label class="switch"><input type="checkbox" role="switch" bind:checked={showMuted} data-testid="show-muted" />{t('anomalies.showMuted', { n: mutedCount })}</label></span>
    <span class="spacer"></span>
    {#if writable && open.length > 1}
      <button class="small" disabled={busy} onclick={() => change(open.map((f) => f.id), true)} data-testid="ack-all"
        >{t('anomalies.acknowledgeAll', { n: open.length })}</button
      >
    {/if}
  </div>
  {#if loaded && items.length === 0}
    <section class="card">
      <p class="empty">
        {#if ackedCount > 0}{t('anomalies.empty.acknowledged')}{:else if mutedCount > 0}{tn('anomalies.empty.muted', mutedCount)}{:else}{t('anomalies.empty.none')}{/if}
      </p>
    </section>
  {/if}
  {#each items as f (f.id)}
    <section class="card finding" class:acked={!!f.acknowledged} class:muted-finding={!!f.mutedBy} data-testid="anomaly">
      <div class="row">
        <span class="badge {f.informational ? '' : f.kind === 'beacon' || f.kind === 'drift' ? 'warn' : 'bad'}">{kindLabel(f.kind)}</span>
        {#if f.informational}<span class="muted small" data-testid="informational">{t('anomalies.informational')}</span>{/if}
        <strong>{f.clientName ?? f.client}</strong>
        {#if f.domain}<span class="mono">→ {f.domain}</span>{/if}
        <span class="spacer"></span>
        <span class="muted small">{dateTime(Date.parse(f.windowStart) / 1000)}</span>
      </div>
      <p>{f.detail}</p>
      {#if (f.kind === 'beacon' || f.kind === 'chatty_loop') && f.rhythm && f.domain}
        <!-- REQ: OBS-031 — the beacon's rhythm when it was reported. -->
        <RhythmStrip rows={[{ domain: f.domain, recent: f.rhythm }]} client={f.client} toggle={false} />
      {/if}
      {#if f.mutedBy}
        <p class="small ack-line" data-testid="muted">
          <span class="badge">{t('anomalies.muted.badge')}</span>
          {t('anomalies.ack.by')} <b>{f.mutedBy}</b>{t('anomalies.muted.rest')}{#if noteOf(f.mutedBy)}{t('anomalies.note', { note: noteOf(f.mutedBy) ?? '' })}{/if}
        </p>
      {/if}
      {#if f.acknowledged}
        <p class="small ack-line" data-testid="acknowledged">
          <span class="badge ok">{t('anomalies.ack.badge')}</span>
          {t('anomalies.ack.by')} {f.acknowledged.by}{t('anomalies.ack.sep')}{dateTime(Date.parse(f.acknowledged.at) / 1000)}{#if f.acknowledged.note}{t('anomalies.note', { note: f.acknowledged.note })}{/if}
        </p>
      {/if}
      <dl class="evidence small">
        <dt>{t('anomalies.evidence.observed')}</dt><dd>{num(Math.round(f.observed * 10) / 10)}</dd>
        {#if f.kind === 'nxdomain_storm'}
          <dt>{t('clients.col.queries')}</dt><dd>{num(f.baseline)}</dd>
        {:else if !absolute.has(f.kind)}
          <dt>{t('anomalies.evidence.usual')}</dt><dd>{num(Math.round(f.baseline * 10) / 10)} ± {num(Math.round(f.spread * 10) / 10)}</dd>
        {/if}
        <dt>{t('anomalies.evidence.threshold')}</dt><dd>{num(Math.round(f.threshold * 10) / 10)}</dd>
        <dt>{t('anomalies.evidence.window')}</dt><dd>{windowText(f.windowSeconds)}</dd>
      </dl>
      <div class="row actions">
        <a class="small" href={href('/queries', { client: f.client, name: f.domain ?? undefined, match: f.domain ? 'suffix' : undefined })}>{t('anomalies.showQueries')}</a>
        <!-- REQ: OBS-034 — the device's day around it. -->
        <a class="small" href={href('/clients', { device: f.client, view: 'timeline' })} data-testid="see-the-day">{t('anomalies.seeTheDay')}</a>
        {#if f.nodes && f.nodes.length > 0}<span class="muted small">{t('anomalies.foundBy', { nodes: f.nodes.join(', ') })}</span>{/if}
        <span class="spacer"></span>
        {#if writable}
          {#if f.mutedBy}
            <button class="link small" disabled={busy} onclick={() => removeMute(f.mutedBy ?? '')} data-testid="remove-mute-here">{t('anomalies.removeMute')}</button>
          {:else}
            <button class="link small" disabled={busy} onclick={() => (muteFor = muteFor === f.id ? null : f.id)} aria-expanded={muteFor === f.id} data-testid="mute">{t('anomalies.muteForDevice')}</button>
          {/if}
          {#if f.acknowledged}
            <button class="link small" disabled={busy} onclick={() => change([f.id], false)}>{t('anomalies.undoAcknowledge')}</button>
          {:else}
            <button class="small" disabled={busy} onclick={() => change([f.id], true)} data-testid="ack">{t('anomalies.acknowledge')}</button>
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
        <h2>{t('anomalies.mutes.title')}<HelpButton id="anomaly-mutes" /></h2>
      </div>
      <p class="muted small">{t('anomalies.mutes.intro')}</p>
      <div class="table-wrap">
        <table>
          <thead><tr><th>{t('clients.col.name')}</th><th>{t('rules.col.for')}</th><th>{t('anomalies.mutes.col.kinds')}</th><th>{t('anomalies.mutes.col.until')}</th><th>{t('changes.plan.why')}</th><th></th></tr></thead>
          <tbody>
            {#each mutes as m (m.name)}
              {@const d = muteDef(m)}
              <tr data-testid="mute-row" class:ended={ended(m)}>
                <td class="mono">{m.name}</td>
                <td class="small">{[...(d.devices ?? []), ...(d.groups ?? []).map((g) => t('anomalies.mutes.group', { name: g }))].join(', ')}</td>
                <td class="small">{(d.kinds ?? []).map((k) => kindLabel(k)).join(', ')}</td>
                <td class="small">{#if d.expires}{ended(m) ? `${t('anomalies.mutes.ended')} ` : ''}{dateTime(Date.parse(d.expires) / 1000)}{:else}{t('anomalies.mutes.untilRemoved')}{/if}</td>
                <td class="small">{d.note ?? ''}</td>
                <td class="num">
                  {#if writable}
                    {#if m.source === 'file'}<span class="muted small">{t('rules.inConfigFile')}</span>{:else}<button class="link small" disabled={busy} onclick={() => removeMute(m.name)} data-testid="remove-mute">{t('rules.remove')}</button>{/if}
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
      <h2>{t('anomalies.newDomains.title')}<HelpButton id="new-domains" /></h2>
      <span class="spacer"></span>
      <span class="switch-track"><label class="switch"><input type="checkbox" role="switch" bind:checked={suspiciousOnly} />{t('anomalies.newDomains.onlySuspicious')}</label></span>
    </div>
    <p class="muted small">{t('anomalies.newDomains.intro')}</p>
    {#if shown.length === 0}
      <p class="empty">{t('anomalies.newDomains.empty')}</p>
    {:else}
      <div class="table-wrap">
        <table>
          <thead><tr><th>{t('anomalies.newDomains.col.firstSeen')}</th><th>{t('flow.device')}</th><th>{t('localdns.forward.domain')}</th><th class="num">{t('anomalies.newDomains.col.score')}</th></tr></thead>
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
