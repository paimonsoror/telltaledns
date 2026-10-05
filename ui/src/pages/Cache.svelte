<script lang="ts">
  // REQ: DNS-006, OBS-003, CLU-008 (T6.15) — the cache, per node: how well it's working over the
  // last hour, what it holds (by kind, and the top entries), the settings in effect, whether it
  // started warm, and lookups and flushing. Each node (each Kubernetes pod) has its own cache.
  import { api, type S } from '../lib/api';
  import { poll } from '../lib/poll';
  import { bytes, duration, logDate, logTime, num, pct } from '../lib/format';
  import Chart from '../lib/components/Chart.svelte';

  type Series = { label: string; color: string; values: number[] };
  import CacheCard from '../lib/components/CacheCard.svelte';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import ShareBar from '../lib/components/ShareBar.svelte';

  type Stats = S['CacheNodeStats'];
  type NodeEntries = S['CacheNodeEntries'];

  let stats = $state<Stats[]>([]);
  let error = $state<unknown>(null);
  let sort = $state<'hits' | 'bytes' | 'expiring'>('hits');
  let node = $state('');
  let entries = $state<NodeEntries[]>([]);
  let loading = $state(false);
  let entriesError = $state<unknown>(null);

  $effect(() =>
    poll(async () => {
      try {
        stats = (await api.cacheStats()).items;
        error = null;
      } catch (e) {
        error = e;
      }
    }, 15_000),
  );

  // The top entries walk each node's cache: loaded on demand, not polled.
  async function loadEntries() {
    loading = true;
    entriesError = null;
    try {
      entries = (await api.cacheEntries({ sort, limit: 25, node: node || undefined })).items;
    } catch (e) {
      entriesError = e;
    } finally {
      loading = false;
    }
  }
  $effect(() => {
    void sort;
    void node;
    void loadEntries();
  });

  const label = (s: { node?: string | null }) => s.node ?? 'this node';
  const colors = ['--s-cached', '--s-forwarded', '--s-local', '--s-blocked', '--s-other'];

  // History points are per node, every 15 s: aligned on 15 s steps, gaps where a node has none.
  const charts = $derived.by(() => {
    const step = 15;
    const at = (iso: string) => Math.round(Date.parse(iso) / 1000 / step) * step;
    const times = [...new Set(stats.flatMap((s) => (s.history ?? []).map((p) => at(p.at))))].sort((a, b) => a - b);
    const index = new Map(times.map((t, i) => [t, i]));
    const series = (pick: (p: S['CachePoint']) => number | null | undefined): Series[] =>
      stats.map((s, i) => {
        const values: (number | null)[] = times.map(() => null);
        for (const p of s.history ?? []) {
          const j = index.get(at(p.at));
          if (j != null) values[j] = pick(p) ?? null;
        }
        return { label: label(s), color: colors[i % colors.length], values: values as number[] };
      });
    return { times, hit: series((p) => p.hitPercent), lookups: series((p) => p.lookups) };
  });

  const lastHour = (s: Stats, k: 'staleServed' | 'prefetches' | 'evictions' | 'lookups') =>
    (s.history ?? []).reduce((t, p) => t + p[k], 0);
  const hitLastHour = (s: Stats) => {
    const looked = lastHour(s, 'lookups');
    const hits = (s.history ?? []).reduce((t, p) => t + ((p.hitPercent ?? 0) / 100) * p.lookups, 0);
    return looked > 0 ? (hits * 100) / looked : null;
  };
  const plural = (n: number, one: string, many: string) => `${num(n)} ${n === 1 ? one : many}`;
  const kinds: [keyof S['CacheMakeup'], string, string][] = [
    ['positive', 'answer', 'answers'],
    ['nxdomain', 'no such name', 'no such name'],
    ['nodata', 'no data', 'no data'],
    ['servfail', 'SERVFAIL', 'SERVFAIL'],
  ];
  const total = (m: S['CacheMakeup']) => m.positive + m.nxdomain + m.nodata + m.servfail;
  const ttl = (s: number) => (s >= 0 ? `${duration(s)} left` : `stale ${duration(-s)}`);
  let lookupName = $state('');
</script>

<div class="page">
  <div class="page-head">
    <h1>Cache<HelpButton id="cache-page" /></h1>
  </div>
  <ErrorNote {error} />

  <section class="nodes">
    {#each stats as s, i (s.node ?? i)}
      {@const used = s.settings ? (s.bytes * 100) / s.settings.maxBytes : null}
      <section class="card node" data-testid="cache-node">
        <h2>{label(s)}</h2>
        <dl class="facts">
          <dt>Hit rate</dt>
          <dd>
            <strong>{pct(hitLastHour(s))}</strong> <span class="muted small">last hour</span>
            <span class="muted small">· {pct(s.hitPercent)} since start</span>
          </dd>
          <dt>Holds</dt>
          <dd>{plural(s.entries, 'answer', 'answers')} · {bytes(s.bytes)}{#if s.settings}{` of ${bytes(s.settings.maxBytes)}`}{/if}</dd>
          {#if used != null}<dd class="bar"><ShareBar value={used} label={`${pct(used)} of the memory budget`} /></dd>{/if}
          <dt>Last hour</dt>
          <dd class="small">
            {plural(lastHour(s, 'lookups'), 'lookup', 'lookups')} · {num(lastHour(s, 'prefetches'))} prefetched · {num(lastHour(s, 'staleServed'))} stale served · {num(lastHour(s, 'evictions'))} evicted
          </dd>
          <dt>Started</dt>
          <dd class="small" data-testid="cache-warm">
            {#if !s.settings?.persist}
              cold (keeping the cache across restarts is off)
            {:else if s.warmStart?.loaded != null}
              warm: {plural(s.warmStart.loaded, 'answer', 'answers')} reloaded, {logDate(s.warmStart.at)} {logTime(s.warmStart.at)}
            {:else if s.warmStart}
              cold: {s.warmStart.note}
            {:else}
              –
            {/if}
          </dd>
        </dl>
        {#if s.settings}
          {@const c = s.settings}
          <details class="settings">
            <summary class="small">Settings</summary>
            <dl class="facts small" data-testid="cache-settings">
              <dt>Memory</dt><dd>{bytes(c.maxBytes)}{#if c.maxEntries}{`, at most ${num(c.maxEntries)} answers`}{/if}</dd>
              <dt>TTL</dt><dd>{duration(c.minTtlSeconds)} to {duration(c.maxTtlSeconds)}; negative answers up to {duration(c.negativeTtlMaxSeconds)}; SERVFAIL {duration(c.servfailTtlSeconds)}</dd>
              <dt>Serve stale</dt><dd>{c.serveStale ? `on, for up to ${duration(c.staleMaxAgeSeconds)} after expiry` : 'off'}</dd>
              <dt>Prefetch</dt><dd>{c.prefetch ? `on, with under ${c.prefetchThresholdPercent}% of the TTL left, after ${c.prefetchMinHits} hits` : 'off'}</dd>
              <dt>Across restarts</dt><dd>{c.persist ? 'kept' : 'not kept'}</dd>
            </dl>
            <p class="muted small">Change these under <span class="mono">[cache]</span> in the configuration.</p>
          </details>
        {/if}
      </section>
    {/each}
  </section>

  {#if charts.times.length > 1}
    <Chart title="Hit rate, last hour (%)" times={charts.times} series={charts.hit} height={180} format={(n) => pct(n)} />
    <Chart title="Lookups per 15 s" times={charts.times} series={charts.lookups} height={160} />
  {:else if stats.length}
    <p class="muted small">The charts fill in over the first minutes (a sample every 15 s).</p>
  {/if}

  <section class="card">
    <div class="head-row">
      <h2>What's cached<HelpButton id="cache-page" /></h2>
      <span class="spacer"></span>
      <label class="small">Sort
        <select bind:value={sort} aria-label="Sort by">
          <option value="hits">most hits</option>
          <option value="bytes">largest</option>
          <option value="expiring">expiring soonest</option>
        </select>
      </label>
      {#if stats.length > 1}
        <select bind:value={node} aria-label="Node">
          <option value="">every node</option>
          {#each stats as s, i (s.node ?? i)}<option value={s.node ?? ''}>{label(s)}</option>{/each}
        </select>
      {/if}
      <button onclick={loadEntries} disabled={loading}>{loading ? 'Loading…' : 'Refresh'}</button>
    </div>
    <ErrorNote error={entriesError} />
    {#each entries as n, i (n.node ?? i)}
      <div class="entries" data-testid="cache-top">
        {#if entries.length > 1}<h3>{label(n)}</h3>{/if}
        {#if n.error}
          <p class="notice warn small">{n.error}</p>
        {:else}
          {@const t = total(n.makeup)}
          <p class="small makeup" data-testid="cache-makeup">
            {#each kinds as [k, one, many] (k)}
              <span><strong>{num(n.makeup[k])}</strong> {n.makeup[k] === 1 ? one : many}{#if t}{` (${pct((n.makeup[k] * 100) / t, 0)})`}{/if}</span>
            {/each}
            <span class="muted">· {num(n.makeup.stale)} stale (kept for serving stale) · {num(n.makeup.validated)} DNSSEC-validated</span>
          </p>
          {#if n.entries.length === 0}
            <p class="empty">Nothing cached{sort === 'expiring' ? ' that is still fresh' : ''}.</p>
          {:else}
            <div class="table-wrap">
              <table class="compact">
                <thead>
                  <tr><th>Name</th><th>Type</th><th>Answer</th><th>Fresh</th><th class="num">Hits</th><th class="num">Size</th></tr>
                </thead>
                <tbody>
                  {#each n.entries as e, j (j)}
                    <tr>
                      <td class="mono"><button class="link" onclick={() => (lookupName = e.name)} title="Look it up below">{e.name}</button></td>
                      <td>{e.qtype}{#if e.dnssecOk}<span class="muted small"> (DO)</span>{/if}</td>
                      <td class="small">{e.rcode} · {e.answers}{#if e.authentic}<span class="badge ok">validated</span>{/if}</td>
                      <td class="small {e.ttlLeftSeconds < 0 ? 'muted' : ''}">{ttl(e.ttlLeftSeconds)}</td>
                      <td class="num">{num(e.hits)}</td>
                      <td class="num small">{bytes(e.bytes)}</td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          {/if}
        {/if}
      </div>
    {/each}
  </section>

  {#key lookupName}
    <CacheCard name={lookupName} compact title="Look up and flush" />
  {/key}
</div>

<style>
  .nodes {
    display: grid;
    gap: var(--gap);
    grid-template-columns: repeat(auto-fill, minmax(min(100%, 380px), 1fr));
    margin-bottom: var(--gap);
  }
  .facts {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 4px 12px;
    margin: 0;
  }
  .facts dt {
    color: var(--muted);
  }
  .facts dd {
    margin: 0;
  }
  .facts dd.bar {
    grid-column: 2;
  }
  .settings {
    margin-top: 10px;
  }
  .head-row {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    align-items: center;
    margin-bottom: 8px;
  }
  .head-row h2 {
    margin: 0;
  }
  .spacer {
    flex: 1;
  }
  .makeup {
    display: flex;
    flex-wrap: wrap;
    gap: 4px 14px;
  }
  .entries + .entries {
    margin-top: 16px;
  }
  h3 {
    margin: 8px 0 4px;
    font-size: 1rem;
  }
  .badge {
    margin-left: 6px;
  }
</style>
