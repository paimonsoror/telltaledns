<script lang="ts">
  // REQ: OBS-013 — device anomalies with their evidence: what was seen, the device's usual value
  // (± spread), and the bar it crossed. Alert-only: nothing here blocks anything.
  import { api, type S } from '../lib/api';
  import { href } from '../lib/router.svelte';
  import { dateTime, num } from '../lib/format';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';

  let items = $state<S['AnomalyFinding'][]>([]);
  let error = $state<unknown>(null);
  let loaded = $state(false);
  let range = $state('-7d');

  const titles: Record<string, string> = {
    rate_spike: 'Many more queries than usual',
    domain_volume: 'Unusual traffic to one domain',
    drift: 'Many new domains',
    beacon: 'Regular phone-home',
  };

  $effect(() => {
    void range;
    api
      .anomalies(range)
      .then((r) => {
        items = r.items;
        loaded = true;
      })
      .catch((e) => (error = e));
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
        <dt>Usual</dt><dd>{num(Math.round(f.baseline * 10) / 10)} ± {num(Math.round(f.spread * 10) / 10)}</dd>
        <dt>Threshold</dt><dd>{num(Math.round(f.threshold * 10) / 10)}</dd>
        <dt>Window</dt><dd>{f.windowSeconds >= 86400 ? `${f.windowSeconds / 86400} day` : `${f.windowSeconds / 3600} h`}</dd>
      </dl>
      <a class="small" href={href('/queries', { client: f.client, name: f.domain ?? undefined, match: f.domain ? 'suffix' : undefined })}>Show these queries</a>
    </section>
  {/each}
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
</style>
