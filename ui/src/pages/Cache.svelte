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
      entries = (await api.cacheEntries({ sort, limit: LIMIT, node: node || undefined })).items;
      expanded = null;
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
  const LIMIT = 25;
  const NODES_SHOWN = 6;
  const barColors = ['--ok', '--warn', '--info', '--bad'];
  let showAllNodes = $state(false);
  let expanded = $state<string | null>(null);
  const ttlShort = (s: number) => (s >= 0 ? duration(s) : `-${duration(-s)}`);
  type Merged = {
    key: string;
    name: string;
    qtype: string;
    dnssecOk: boolean;
    rcode: string;
    answers: number;
    authentic: boolean;
    hits: number;
    bytes: number;
    ttlMin: number;
    ttlMax: number;
    nodes: { node: string; entry: S['CacheTopEntry'] }[];
  };
  // Answers with an error (a node that couldn't be asked) don't count as nodes holding names.
  const answered = $derived(entries.filter((n) => !n.error));
  const multi = $derived(answered.length > 1);
  const nodeCount = $derived(answered.length);
  // One row per name and type across the nodes (the list doesn't grow with the cluster).
  const merged = $derived.by((): Merged[] => {
    const by = new Map<string, Merged>();
    for (const n of answered) {
      for (const e of n.entries) {
        const key = `${e.name}|${e.qtype}|${e.dnssecOk}`;
        const m = by.get(key);
        const node = label(n);
        if (m) {
          m.hits += e.hits;
          m.bytes = Math.max(m.bytes, e.bytes);
          m.ttlMin = Math.min(m.ttlMin, e.ttlLeftSeconds);
          m.ttlMax = Math.max(m.ttlMax, e.ttlLeftSeconds);
          m.authentic ||= e.authentic;
          m.nodes.push({ node, entry: e });
        } else {
          by.set(key, {
            key,
            name: e.name,
            qtype: e.qtype,
            dnssecOk: e.dnssecOk,
            rcode: e.rcode,
            answers: e.answers,
            authentic: e.authentic,
            hits: e.hits,
            bytes: e.bytes,
            ttlMin: e.ttlLeftSeconds,
            ttlMax: e.ttlLeftSeconds,
            nodes: [{ node, entry: e }],
          });
        }
      }
    }
    const rows = [...by.values()];
    if (sort === 'bytes') rows.sort((a, b) => b.bytes - a.bytes);
    else if (sort === 'expiring') rows.sort((a, b) => a.ttlMin - b.ttlMin);
    else rows.sort((a, b) => b.hits - a.hits || b.nodes.length - a.nodes.length);
    return rows.slice(0, LIMIT);
  });
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
    <!-- T6.15 — scales with the cluster: one row per node for the makeup, and one merged
         list of names (not one list per node) unless a node is picked. -->
    {#if entries.length}
      {@const shownNodes = showAllNodes ? entries : entries.slice(0, NODES_SHOWN)}
      <div class="table-wrap">
        <table class="compact makeup-table" data-testid="cache-makeup">
          <thead>
            <tr>
              {#if entries.length > 1}<th>Node</th>{/if}
              <th>Holds</th>
              <th class="bar-col">
                <span class="key k-ok"></span>answers
                <span class="key k-warn"></span>no such name
                <span class="key k-info"></span>no data
                <span class="key k-bad"></span>SERVFAIL
              </th>
              <th class="num">Stale</th>
              <th class="num">Validated</th>
            </tr>
          </thead>
          <tbody>
            {#each shownNodes as n, i (n.node ?? i)}
              {@const t = total(n.makeup)}
              <tr>
                {#if entries.length > 1}<td>{label(n)}</td>{/if}
                {#if n.error}
                  <td colspan="4" class="small warn-text">{n.error}</td>
                {:else}
                  <td class="small">{plural(t, 'answer', 'answers')}</td>
                  <td class="bar-col">
                    {#if t}
                      <span class="stack" title={kinds.map(([k, one, many]) => `${num(n.makeup[k])} ${n.makeup[k] === 1 ? one : many}`).join(' · ')}>
                        {#each kinds as [k], j (k)}
                          {#if n.makeup[k]}<span style:width={`${(n.makeup[k] * 100) / t}%`} style:--c={`var(${barColors[j]})`}></span>{/if}
                        {/each}
                      </span>
                    {/if}
                  </td>
                  <td class="num small">{num(n.makeup.stale)}</td>
                  <td class="num small">{num(n.makeup.validated)}</td>
                {/if}
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      {#if entries.length > NODES_SHOWN}
        <button class="link small" onclick={() => (showAllNodes = !showAllNodes)}>
          {showAllNodes ? 'Show fewer nodes' : `Show all ${entries.length} nodes`}
        </button>
      {/if}

      {#if merged.length === 0}
        <p class="empty">Nothing cached{sort === 'expiring' ? ' that is still fresh' : ''}.</p>
      {:else}
        <div class="table-wrap" data-testid="cache-top">
          <table class="compact">
            <thead>
              <tr>
                <th>Name</th><th>Type</th><th>Answer</th><th>Fresh</th>
                {#if multi}<th>Nodes</th>{/if}
                <th class="num">Hits</th><th class="num">Size</th>
              </tr>
            </thead>
            <tbody>
              {#each merged as m (m.key)}
                <tr class:open={expanded === m.key}>
                  <td class="mono"><button class="link" onclick={() => (lookupName = m.name)} title="Look it up below">{m.name}</button></td>
                  <td>{m.qtype}{#if m.dnssecOk}<span class="muted small"> (DO)</span>{/if}</td>
                  <td class="small">{m.rcode} · {m.answers}{#if m.authentic}<span class="badge ok">validated</span>{/if}</td>
                  <td class="small {m.ttlMax < 0 ? 'muted' : ''}">{ttlShort(m.ttlMin) === ttlShort(m.ttlMax) ? ttl(m.ttlMin) : `${ttlShort(m.ttlMin)} to ${ttlShort(m.ttlMax)}`}</td>
                  {#if multi}
                    <td class="small">
                      <button class="link" aria-expanded={expanded === m.key} onclick={() => (expanded = expanded === m.key ? null : m.key)}
                        >{m.nodes.length} of {nodeCount}</button
                      >
                    </td>
                  {/if}
                  <td class="num">{num(m.hits)}</td>
                  <td class="num small">{bytes(m.bytes)}</td>
                </tr>
                {#if expanded === m.key}
                  <tr class="detail">
                    <td colspan="7">
                      <ul class="per-node">
                        {#each m.nodes as d (d.node)}
                          <li><strong>{d.node}</strong> · {ttl(d.entry.ttlLeftSeconds)} · {plural(d.entry.hits, 'hit', 'hits')}</li>
                        {/each}
                      </ul>
                    </td>
                  </tr>
                {/if}
              {/each}
            </tbody>
          </table>
        </div>
        {#if multi}
          <p class="muted small">
            Merged across nodes: each name once, with the hits of the nodes where it's among their top {LIMIT}. Pick a node
            above for its own list.
          </p>
        {/if}
      {/if}
    {/if}
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
  .bar-col {
    width: 45%;
    min-width: 160px;
  }
  th.bar-col {
    font-weight: 400;
    text-transform: none;
    letter-spacing: 0;
  }
  .key {
    display: inline-block;
    width: 9px;
    height: 9px;
    border-radius: 2px;
    margin: 0 4px 0 10px;
  }
  .k-ok {
    background: var(--ok);
  }
  .k-warn {
    background: var(--warn);
  }
  .k-info {
    background: var(--info);
  }
  .k-bad {
    background: var(--bad);
  }
  .key:first-child {
    margin-left: 0;
  }
  .stack {
    display: flex;
    height: 10px;
    border-radius: 5px;
    overflow: hidden;
    background: var(--surface-2);
  }
  .stack span {
    background: var(--c);
  }
  .warn-text {
    color: var(--warn-strong, var(--warn));
  }
  tr.detail td {
    background: var(--surface-2);
  }
  .per-node {
    list-style: none;
    margin: 0;
    padding: 4px 0;
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
    gap: 2px 16px;
    font-size: 0.85rem;
  }
  .makeup-table {
    margin-bottom: 6px;
  }
  .badge {
    margin-left: 6px;
  }
</style>
