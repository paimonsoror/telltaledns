<script lang="ts">
  // REQ: DNS-006, OBS-003, CLU-008 (T6.15) — the cache, per node: how well it's working over the
  // last hour, what it holds (by kind, and the top entries), the settings in effect, whether it
  // started warm, and lookups and flushing. Each node (each Kubernetes pod) has its own cache.
  import { api, type S } from '../lib/api';
  import { poll } from '../lib/poll';
  import { bytes, duration, logDate, logTime, num, pct } from '../lib/format';
  import Chart from '../lib/components/Chart.svelte';
  import { changes } from '../lib/annotations.svelte';

  type Series = { label: string; color: string; values: number[] };
  import CacheCard from '../lib/components/CacheCard.svelte';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import ShareBar from '../lib/components/ShareBar.svelte';
  import { tr, own } from '../lib/i18n';
  import T from '../lib/i18n/T.svelte';
  const { t, tn } = tr('cache');

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
      // REQ: OBS-033 — the last hour's change markers (a flush, a restart) on both charts.
      void changes.load('-1h');
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

  // The words read in the rows are read once, here: the language is fixed for the life of the page.
  const thisNode = t('this node');
  const rowWords = { lookItUp: t('Look it up below'), dnssecOk: t('(DO)'), validated: t('validated') };
  const label = (s: { node?: string | null }) => s.node ?? thisNode;
  const colors = ['--s-cached', '--s-forwarded', '--s-local', '--s-blocked', '--s-other'];

  // History points are per node, every 15 s: aligned on 15 s steps, gaps where a node has none.
  const charts = $derived.by(() => {
    const step = 15;
    const at = (iso: string) => Math.round(Date.parse(iso) / 1000 / step) * step;
    const times = [...new Set(stats.flatMap((s) => (s.history ?? []).map((p) => at(p.at))))].sort((a, b) => a - b);
    const index = new Map(times.map((time, i) => [time, i]));
    const series = (pick: (p: S['CachePoint']) => number | null | undefined): Series[] =>
      stats.map((s, i) => {
        const values: (number | null)[] = times.map(() => null);
        for (const p of s.history ?? []) {
          const j = index.get(at(p.at));
          if (j != null) values[j] = pick(p) ?? null;
        }
        return { label: label(s), color: colors[i % colors.length], values: values as number[] };
      });
    // DNS-007: answered from the cache (fresh or refreshed); fresh hits alone from older nodes.
    return { times, hit: series((p) => p.answeredPercent ?? p.hitPercent), lookups: series((p) => p.lookups) };
  });

  const lastHour = (s: Stats, k: 'staleServed' | 'prefetches' | 'evictions' | 'lookups') =>
    (s.history ?? []).reduce((sum, p) => sum + p[k], 0);
  const hitLastHour = (s: Stats, fresh = false) => {
    const looked = lastHour(s, 'lookups');
    const hits = (s.history ?? []).reduce((sum, p) => sum + (((fresh ? p.hitPercent : (p.answeredPercent ?? p.hitPercent)) ?? 0) / 100) * p.lookups, 0);
    return looked > 0 ? (hits * 100) / looked : null;
  };
  const answersOf = (n: number) => tn('{n} answer', '{n} answers', n, { n: num(n) });
  const hitsOf = (n: number) => tn('{n} hit', '{n} hits', n, { n: num(n) });
  // One whole message for each plural form of the last hour's line (lookups: 1 or more).
  const lastHourText = (s: Stats) => {
    const lookups = lastHour(s, 'lookups');
    const p = { n: num(lookups), prefetched: num(lastHour(s, 'prefetches')), stale: num(lastHour(s, 'staleServed')), evicted: num(lastHour(s, 'evictions')) };
    return lookups === 1
      ? t('{n} lookup · {prefetched} prefetched · {stale} stale served · {evicted} evicted', p)
      : t('{n} lookups · {prefetched} prefetched · {stale} stale served · {evicted} evicted', p);
  };
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
  const kinds: (keyof S['CacheMakeup'])[] = ['positive', 'nxdomain', 'nodata', 'servfail'];
  // A kind's count with its name, for the bar's tooltip: one message for each kind.
  const kindCount = (k: keyof S['CacheMakeup'], c: number) =>
    k === 'positive'
      ? answersOf(c)
      : k === 'nxdomain'
        ? t('{n} no such name', { n: num(c) })
        : k === 'nodata'
          ? t('{n} no data', { n: num(c) })
          : t('{n} SERVFAIL', { n: num(c) });
  const total = (m: S['CacheMakeup']) => m.positive + m.nxdomain + m.nodata + m.servfail;
  const ttl = (s: number) => (s >= 0 ? t('{time} left', { time: duration(s) }) : t('stale {time}', { time: duration(-s) }));
  let lookupName = $state('');
  // REQ: OBS-021 — the size advice's verdicts.
  const sizingLabel: Record<string, string> = { grow: t('could grow'), shrink: t('could shrink'), ok: t('right size'), learning: t('learning') };
  const sizingTone: Record<string, string> = { grow: 'warn', shrink: 'info', ok: 'ok', learning: '' };
</script>

{#snippet cachekey()}<span class="mono" translate="no">[cache]</span>{/snippet}

<div class="page">
  <div class="page-head">
    <h1>{t('Cache')}<HelpButton id="cache-page" /></h1>
  </div>
  <ErrorNote {error} />

  <section class="nodes">
    {#each stats as s, i (s.node ?? i)}
      {@const used = s.settings ? (s.bytes * 100) / s.settings.maxBytes : null}
      <section class="card node" data-testid="cache-node">
        <h2>{label(s)}</h2>
        <dl class="facts">
          <dt>{t('Answered from the cache')}</dt>
          <dd data-testid="cache-answered">
            <strong>{pct(hitLastHour(s))}</strong> <span class="muted small">{t('last hour')}</span>
            <span class="muted small">{t('· {pct} since start', { pct: pct(s.answeredPercent ?? s.hitPercent) })}</span>
            {#if s.answeredPercent != null && s.hitPercent != null && s.answeredPercent - s.hitPercent >= 0.1}
              <div class="muted small">{t('{pct} fresh last hour; the rest had just expired and was answered at once while it was refreshed (or kept answering while upstreams failed).', { pct: pct(hitLastHour(s, true)) })}</div>
            {/if}
          </dd>
          <dt>{t('Holds')}</dt>
          <dd>{answersOf(s.entries)} · {bytes(s.bytes)}{#if s.settings}{` ${t('of {max}', { max: bytes(s.settings.maxBytes) })}`}{/if}</dd>
          {#if used != null}<dd class="bar"><ShareBar value={used} label={t('{pct} of the memory budget', { pct: pct(used) })} /></dd>{/if}
          <dt>{t('Last hour')}</dt>
          <dd class="small">
            {lastHourText(s)}
          </dd>
          <dt>{t('Started')}</dt>
          <dd class="small" data-testid="cache-warm">
            {#if !s.settings?.persist}
              {t('cold (keeping the cache across restarts is off)')}
            {:else if s.warmStart?.loaded != null}
              {s.warmStart.loaded === 1
                ? t('warm: {n} answer reloaded, {date} {time}', { n: num(s.warmStart.loaded), date: logDate(s.warmStart.at), time: logTime(s.warmStart.at) })
                : t('warm: {n} answers reloaded, {date} {time}', { n: num(s.warmStart.loaded), date: logDate(s.warmStart.at), time: logTime(s.warmStart.at) })}
            {:else if s.warmStart}
              {t('cold: {note}', { note: s.warmStart.note })}
            {:else}
              –
            {/if}
          </dd>
          {#if s.sizing}
            <!-- REQ: OBS-021 — whether the cache is the right size. -->
            {@const z = s.sizing}
            <dt>{t('Size')}</dt>
            <dd class="small" data-testid="cache-sizing">
              <span class="badge {sizingTone[z.verdict] ?? ''}">{own(sizingLabel, z.verdict) ?? z.verdict}</span>
              <span translate="no">{z.advice}</span>
              {#if z.verdict !== 'learning'}
                <span class="muted">
                  {t('Bigger:')}
                  {#each z.steps as st, j (st.sizePercent)}{j ? ' · ' : ''}{t('{size}% → +{extra}% hits', { size: st.sizePercent, extra: st.extraHitPercent })}{/each}{t('. Peak {size}.', { size: bytes(z.peakBytes) })}
                </span>
              {/if}
            </dd>
          {/if}
        </dl>
        {#if s.settings}
          {@const c = s.settings}
          <details class="settings">
            <summary class="small">{t('Settings')}</summary>
            <dl class="facts small" data-testid="cache-settings">
              <dt>{t('Memory')}</dt><dd>{bytes(c.maxBytes)}{#if c.maxEntries}{t(', at most {n} answers', { n: num(c.maxEntries) })}{/if}</dd>
              <dt>{t('TTL')}</dt><dd>{t('{min} to {max}; negative answers up to {negative}; SERVFAIL {servfail}', { min: duration(c.minTtlSeconds), max: duration(c.maxTtlSeconds), negative: duration(c.negativeTtlMaxSeconds), servfail: duration(c.servfailTtlSeconds) })}</dd>
              <dt>{t('Serve stale')}</dt>
              <dd>
                {#if !c.serveStale}{t('off')}
                {:else if c.staleAnswerWaitMs === 0}{t('answered at once and refreshed in the background, for up to {age} after expiry', { age: duration(c.staleMaxAgeSeconds) })}
                {:else if c.staleAnswerWaitMs != null}{t("when upstreams don't answer within {wait} s, for up to {age} after expiry", { wait: (c.staleAnswerWaitMs / 1000).toFixed(1), age: duration(c.staleMaxAgeSeconds) })}
                {:else}{t("when upstreams don't answer, for up to {age} after expiry", { age: duration(c.staleMaxAgeSeconds) })}{/if}
              </dd>
              <dt>{t('Prefetch')}</dt><dd>{c.prefetch ? t('on, with under {pct}% of the TTL left, after {hits} hits', { pct: c.prefetchThresholdPercent, hits: c.prefetchMinHits }) : t('off')}</dd>
              <dt>{t('Across restarts')}</dt><dd>{c.persist ? t('kept') : t('not kept')}</dd>
            </dl>
            <p class="muted small"><T ctx="cache" msg={'Change these under <cachekey/> in the configuration.'} {cachekey} /></p>
          </details>
        {/if}
      </section>
    {/each}
  </section>

  {#if charts.times.length > 1}
    <Chart title={t('Answered from the cache, last hour (%)')} times={charts.times} series={charts.hit} height={180} format={(n) => pct(n)} markers={changes.markers} />
    <Chart title={t('Lookups per 15 s')} times={charts.times} series={charts.lookups} height={160} markers={changes.markers} />
  {:else if stats.length}
    <p class="muted small">{t('The charts fill in over the first minutes (a sample every 15 s).')}</p>
  {/if}

  <section class="card">
    <div class="head-row">
      <h2>{t('What\'s cached')}<HelpButton id="cache-page" /></h2>
      <span class="spacer"></span>
      <label class="pill-field">{t('Sort')}
        <select bind:value={sort} aria-label={t('Sort by')}>
          <option value="hits">{t('most hits')}</option>
          <option value="bytes">{t('largest')}</option>
          <option value="expiring">{t('expiring soonest')}</option>
        </select>
      </label>
      {#if stats.length > 1}
        <label class="pill-field">{t('Showing')}
          <select bind:value={node} aria-label={t('Node')}>
            <option value="">{t('every node')}</option>
            {#each stats as s, i (s.node ?? i)}<option value={s.node ?? ''}>{label(s)}</option>{/each}
          </select>
        </label>
      {/if}
      <button onclick={loadEntries} disabled={loading}>{loading ? t('Loading…') : t('Refresh')}</button>
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
              {#if entries.length > 1}<th>{t('Node')}</th>{/if}
              <th>{t('Holds')}</th>
              <th class="bar-col">
                <span class="key k-ok"></span>{t('answers')}
                <span class="key k-warn"></span>{t('no such name')}
                <span class="key k-info"></span>{t('no data')}
                <span class="key k-bad"></span>{t('SERVFAIL')}
              </th>
              <th class="num">{t('Stale')}</th>
              <th class="num">{t('Validated')}</th>
            </tr>
          </thead>
          <tbody>
            {#each shownNodes as n, i (n.node ?? i)}
              {@const all = total(n.makeup)}
              <tr>
                {#if entries.length > 1}<td>{label(n)}</td>{/if}
                {#if n.error}
                  <td colspan="4" class="small warn-text" translate="no">{n.error}</td>
                {:else}
                  <td class="small">{answersOf(all)}</td>
                  <td class="bar-col">
                    {#if all}
                      <span class="stack" title={kinds.map((k) => kindCount(k, n.makeup[k])).join(' · ')}>
                        {#each kinds as k, j (k)}
                          {#if n.makeup[k]}<span style:width={`${(n.makeup[k] * 100) / all}%`} style:--c={`var(${barColors[j]})`}></span>{/if}
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
          {showAllNodes ? t('Show fewer nodes') : t('Show all {n} nodes', { n: entries.length })}
        </button>
      {/if}

      {#if merged.length === 0}
        <p class="empty">{sort === 'expiring' ? t('Nothing cached that is still fresh.') : t('Nothing cached.')}</p>
      {:else}
        <div class="table-wrap" data-testid="cache-top">
          <table class="compact">
            <thead>
              <tr>
                <th>{t('Name')}</th><th>{t('Type')}</th><th>{t('Answer')}</th><th>{t('Fresh')}</th>
                {#if multi}<th>{t('Nodes')}</th>{/if}
                <th class="num">{t('Hits')}</th><th class="num">{t('Size')}</th>
              </tr>
            </thead>
            <tbody>
              {#each merged as m (m.key)}
                <tr class:open={expanded === m.key}>
                  <td class="mono"><button class="link" onclick={() => (lookupName = m.name)} title={rowWords.lookItUp}><span translate="no">{m.name}</span></button></td>
                  <td><span translate="no">{m.qtype}</span>{#if m.dnssecOk}<span class="muted small">{rowWords.dnssecOk}</span>{/if}</td>
                  <td class="small"><span translate="no">{m.rcode} · {m.answers}</span>{#if m.authentic}<span class="badge ok">{rowWords.validated}</span>{/if}</td>
                  <td class="small {m.ttlMax < 0 ? 'muted' : ''}">{ttlShort(m.ttlMin) === ttlShort(m.ttlMax) ? ttl(m.ttlMin) : t('{from} to {to}', { from: ttlShort(m.ttlMin), to: ttlShort(m.ttlMax) })}</td>
                  {#if multi}
                    <td class="small">
                      <button class="link" aria-expanded={expanded === m.key} onclick={() => (expanded = expanded === m.key ? null : m.key)}
                        >{t('{n} of {total}', { n: m.nodes.length, total: nodeCount })}</button
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
                          <li><strong translate="no">{d.node}</strong> · {ttl(d.entry.ttlLeftSeconds)} · {hitsOf(d.entry.hits)}</li>
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
            {t("Merged across nodes: each name once, with the hits of the nodes where it's among their top {n}. Pick a node above for its own list.", { n: LIMIT })}
          </p>
        {/if}
      {/if}
    {/if}
  </section>

  {#key lookupName}
    <CacheCard name={lookupName} compact title={t('Look up and flush')} />
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
