<script lang="ts">
  // REQ: OBS-013 — device anomalies with their evidence: what was seen, the device's usual value
  // (± spread), and the bar it crossed. Alert-only: nothing here blocks anything.
  // REQ: OBS-014 — acknowledging: mark findings as seen, on every node; they stop counting in
  // the badge and hide here unless "Show acknowledged" is on.
  import { api, type S } from '../lib/api';
  import { href } from '../lib/router.svelte';
  import { can } from '../lib/session.svelte';
  import { dateTime, num } from '../lib/format';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';

  let all = $state<S['AnomalyFinding'][]>([]);
  let showAcked = $state(false);
  const items = $derived(showAcked ? all : all.filter((f) => !f.acknowledged));
  const ackedCount = $derived(all.filter((f) => f.acknowledged).length);
  const open = $derived(all.filter((f) => !f.acknowledged));
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
    nxdomain_storm: 'Burst of failed lookups',
    dga: 'Machine-generated-looking domains',
  };
  // Findings measured against an absolute bar, not the device's usual value.
  const absolute = new Set(['nxdomain_storm', 'dga']);
  const windowText = (s: number) => (s >= 86400 ? `${s / 86400} day` : s >= 3600 ? `${s / 3600} h` : `${s / 60} min`);

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
      .anomalies(range)
      .then((r) => {
        all = r.items;
        loaded = true;
      })
      .catch((e) => (error = e));
    api
      .newDomains(range === '-24h' ? '-24h' : range, 500)
      .then((r) => (fresh = r.items))
      .catch(() => (fresh = []));
  });
</script>

<div class="page">
  <div class="page-head">
    <h1>Anomalies<HelpButton id="anomalies" /></h1>
    <label class="small">
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
  <p class="muted small">
    Each device is compared with its own usual behavior, learned over its first week. Findings only inform you; to act,
    open the device's queries or move it to a stricter group. Acknowledge a finding once you've looked at it: it stops
    counting as new, on every node.
  </p>
  <div class="row toolbar">
    <label class="small"><input type="checkbox" bind:checked={showAcked} data-testid="show-acknowledged" /> Show acknowledged ({ackedCount})</label>
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
        {#if ackedCount > 0}Nothing new: every finding in this period is acknowledged.{:else}Nothing unusual. New devices are quiet here for their first 7 days while TelltaleDNS learns them.{/if}
      </p>
    </section>
  {/if}
  {#each items as f (f.id)}
    <section class="card finding" class:acked={!!f.acknowledged} data-testid="anomaly">
      <div class="row">
        <span class="badge {f.kind === 'beacon' || f.kind === 'drift' ? 'warn' : 'bad'}">{titles[f.kind] ?? f.kind}</span>
        <strong>{f.clientName ?? f.client}</strong>
        {#if f.domain}<span class="mono">→ {f.domain}</span>{/if}
        <span class="spacer"></span>
        <span class="muted small">{dateTime(Date.parse(f.windowStart) / 1000)}</span>
      </div>
      <p>{f.detail}</p>
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
        {:else if !absolute.has(f.kind)}
          <dt>Usual</dt><dd>{num(Math.round(f.baseline * 10) / 10)} ± {num(Math.round(f.spread * 10) / 10)}</dd>
        {/if}
        <dt>Threshold</dt><dd>{num(Math.round(f.threshold * 10) / 10)}</dd>
        <dt>Window</dt><dd>{windowText(f.windowSeconds)}</dd>
      </dl>
      <div class="row actions">
        <a class="small" href={href('/queries', { client: f.client, name: f.domain ?? undefined, match: f.domain ? 'suffix' : undefined })}>Show these queries</a>
        {#if f.nodes && f.nodes.length > 0}<span class="muted small">Found by {f.nodes.join(', ')}</span>{/if}
        <span class="spacer"></span>
        {#if writable}
          {#if f.acknowledged}
            <button class="link small" disabled={busy} onclick={() => change([f.id], false)}>Undo acknowledge</button>
          {:else}
            <button class="small" disabled={busy} onclick={() => change([f.id], true)} data-testid="ack">Acknowledge</button>
          {/if}
        {/if}
      </div>
    </section>
  {/each}

  <section class="card" data-testid="new-domains">
    <div class="row head">
      <h2>New domains<HelpButton id="new-domains" /></h2>
      <span class="spacer"></span>
      <label class="small"><input type="checkbox" bind:checked={suspiciousOnly} /> Only machine-generated-looking</label>
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
  .finding.acked {
    opacity: 0.75;
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
