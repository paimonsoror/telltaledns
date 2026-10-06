<script lang="ts">
  // REQ: OBS-013 — device anomalies with their evidence: what was seen, the device's usual value
  // (± spread), and the bar it crossed. Alert-only: nothing here blocks anything.
  import { api, type S } from '../lib/api';
  import { href } from '../lib/router.svelte';
  import { dateTime, num } from '../lib/format';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';

  let items = $state<S['AnomalyFinding'][]>([]);
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

  $effect(() => {
    void range;
    api
      .anomalies(range)
      .then((r) => {
        items = r.items;
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
  <p class="muted small">
    Each device is compared with its own usual behavior, learned over its first week. Findings only inform you; to act,
    open the device's queries or move it to a stricter group.
  </p>
  {#if loaded && items.length === 0}
    <section class="card"><p class="empty">Nothing unusual. New devices are quiet here for their first 7 days while TelltaleDNS learns them.</p></section>
  {/if}
  {#each items as f, i (i)}
    <section class="card finding" data-testid="anomaly">
      <div class="row">
        <span class="badge {f.kind === 'beacon' || f.kind === 'drift' ? 'warn' : 'bad'}">{titles[f.kind] ?? f.kind}</span>
        <strong>{f.clientName ?? f.client}</strong>
        {#if f.domain}<span class="mono">→ {f.domain}</span>{/if}
        <span class="spacer"></span>
        <span class="muted small">{dateTime(Date.parse(f.windowStart) / 1000)}</span>
      </div>
      <p>{f.detail}</p>
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
      <a class="small" href={href('/queries', { client: f.client, name: f.domain ?? undefined, match: f.domain ? 'suffix' : undefined })}>Show these queries</a>
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
