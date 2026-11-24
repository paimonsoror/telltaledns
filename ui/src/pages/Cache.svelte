<script lang="ts">
  // REQ: DNS-006, OBS-003, CLU-008 (T6.15) — the cache, per node: how well it's working over the
  // last hour, what it holds (by kind, and the top entries), the settings in effect, whether it
  // started warm, and lookups and flushing. Each node (each Kubernetes pod) has its own cache.
  import { api, type S } from '../lib/api';
  import { poll } from '../lib/poll';
  import { bytes, duration, logDate, logTime, num, pct } from '../lib/format';
  import { t, tn } from '../lib/i18n';
  import Chart from '../lib/components/Chart.svelte';
  import { changes } from '../lib/annotations.svelte';

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

  const label = (s: { node?: string | null }) => s.node ?? t('legacy.thisNode');
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
    // DNS-007: answered from the cache (fresh or refreshed); fresh hits alone from older nodes.
    return { times, hit: series((p) => p.answeredPercent ?? p.hitPercent), lookups: series((p) => p.lookups) };
  });

  const lastHour = (s: Stats, k: 'staleServed' | 'prefetches' | 'evictions' | 'lookups') =>
    (s.history ?? []).reduce((t, p) => t + p[k], 0);
  const hitLastHour = (s: Stats, fresh = false) => {
    const looked = lastHour(s, 'lookups');
    const hits = (s.history ?? []).reduce((t, p) => t + (((fresh ? p.hitPercent : (p.answeredPercent ?? p.hitPercent)) ?? 0) / 100) * p.lookups, 0);
    return looked > 0 ? (hits * 100) / looked : null;
  };
  // A count reads as words in either language; the number keeps the language's formatting.
  const count = (n: number, key: string) => tn(key, n, { n: num(n) });
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
  const kinds: [keyof S['CacheMakeup'], string][] = [
    ['positive', 'cache.makeup.kind.answer'],
    ['nxdomain', 'cache.makeup.kind.noSuchName'],
    ['nodata', 'cache.makeup.kind.noData'],
    ['servfail', 'cache.makeup.kind.servfail'],
  ];
  const total = (m: S['CacheMakeup']) => m.positive + m.nxdomain + m.nodata + m.servfail;
  const ttl = (s: number) => (s >= 0 ? t('cache.top.ttlLeft', { ttl: duration(s) }) : t('cache.top.ttlStale', { ttl: duration(-s) }));
  let lookupName = $state('');
  // REQ: OBS-021 — the size advice's verdicts.
  const sizingLabel = $derived<Record<string, string>>({
    grow: t('cache.sizing.grow'),
    shrink: t('cache.sizing.shrink'),
    ok: t('cache.sizing.ok'),
    learning: t('cache.sizing.learning'),
  });
  const sizingTone: Record<string, string> = { grow: 'warn', shrink: 'info', ok: 'ok', learning: '' };
</script>

<div class="page">
  <div class="page-head">
    <h1>{t('nav.cache')}<HelpButton id="cache-page" /></h1>
  </div>
  <ErrorNote {error} />

  <section class="nodes">
    {#each stats as s, i (s.node ?? i)}
      {@const used = s.settings ? (s.bytes * 100) / s.settings.maxBytes : null}
      <section class="card node" data-testid="cache-node">
        <h2>{label(s)}</h2>
        <dl class="facts">
          <dt>{t('cache.node.answeredHeading')}</dt>
          <dd data-testid="cache-answered">
            <strong>{pct(hitLastHour(s))}</strong> <span class="muted small">{t('cache.node.lastHour')}</span>
            <span class="muted small">{t('cache.node.sinceStart', { pct: pct(s.answeredPercent ?? s.hitPercent) })}</span>
            {#if s.answeredPercent != null && s.hitPercent != null && s.answeredPercent - s.hitPercent >= 0.1}
              <div class="muted small">{t('cache.node.fresh', { pct: pct(hitLastHour(s, true)) })}</div>
            {/if}
          </dd>
          <dt>{t('cache.node.holdsHeading')}</dt>
          <dd>{count(s.entries, 'cache.node.answers')} · {bytes(s.bytes)}{#if s.settings}{t('cache.node.ofBudget', { bytes: bytes(s.settings.maxBytes) })}{/if}</dd>
          {#if used != null}<dd class="bar"><ShareBar value={used} label={t('cache.node.shareLabel', { pct: pct(used) })} /></dd>{/if}
          <dt>{t('clients.tab.seen')}</dt>
          <dd class="small">
            {t('cache.node.lastHourLine', {
              lookups: count(lastHour(s, 'lookups'), 'cache.node.lookups'),
              prefetched: num(lastHour(s, 'prefetches')),
              stale: num(lastHour(s, 'staleServed')),
              evicted: num(lastHour(s, 'evictions')),
            })}
          </dd>
          <dt>{t('cache.node.started')}</dt>
          <dd class="small" data-testid="cache-warm">
            {#if !s.settings?.persist}
              {t('cache.node.coldOff')}
            {:else if s.warmStart?.loaded != null}
              {t('cache.node.warm', {
                answers: count(s.warmStart.loaded, 'cache.node.answers'),
                date: logDate(s.warmStart.at),
                time: logTime(s.warmStart.at),
              })}
            {:else if s.warmStart}
              {t('cache.node.cold', { note: s.warmStart.note ?? '' })}
            {:else}
              –
            {/if}
          </dd>
          {#if s.sizing}
            <!-- REQ: OBS-021 — whether the cache is the right size. -->
            {@const z = s.sizing}
            <dt>{t('cache.sizing.heading')}</dt>
            <dd class="small" data-testid="cache-sizing">
              <span class="badge {sizingTone[z.verdict] ?? ''}">{sizingLabel[z.verdict] ?? z.verdict}</span>
              {z.advice}
              {#if z.verdict !== 'learning'}
                <span class="muted">
                  {t('cache.sizing.bigger')}
                  {#each z.steps as st, j (st.sizePercent)}{j ? ' · ' : ''}{t('cache.sizing.step', { size: st.sizePercent, hits: st.extraHitPercent })}{/each}.
                  {t('cache.sizing.peak', { bytes: bytes(z.peakBytes) })}
                </span>
              {/if}
            </dd>
          {/if}
        </dl>
        {#if s.settings}
          {@const c = s.settings}
          <details class="settings">
            <summary class="small">{t('nav.settings')}</summary>
            <dl class="facts small" data-testid="cache-settings">
              <dt>{t('qw.cache.memory')}</dt><dd>{bytes(c.maxBytes)}{#if c.maxEntries}{count(c.maxEntries, 'cache.settings.maxEntries')}{/if}</dd>
              <dt>{t('localdns.col.ttl')}</dt><dd>{t('cache.settings.ttlLine', {
                min: duration(c.minTtlSeconds),
                max: duration(c.maxTtlSeconds),
                negative: duration(c.negativeTtlMaxSeconds),
                servfail: duration(c.servfailTtlSeconds),
              })}</dd>
              <dt>{t('cache.settings.serveStale')}</dt>
              <dd>
                {#if !c.serveStale}{t('lists.badge.off')}
                {:else if c.staleAnswerWaitMs === 0}{t('cache.settings.serveStaleAtOnce', { duration: duration(c.staleMaxAgeSeconds) })}
                {:else}{t('cache.settings.serveStaleWhen')}{c.staleAnswerWaitMs != null ? t('cache.settings.serveStaleWithin', { seconds: (c.staleAnswerWaitMs / 1000).toFixed(1) }) : ''}{t('cache.settings.serveStaleFor', { duration: duration(c.staleMaxAgeSeconds) })}{/if}
              </dd>
              <dt>{t('cache.settings.prefetch')}</dt><dd>{c.prefetch ? t('cache.settings.prefetchOn', { percent: c.prefetchThresholdPercent, hits: count(c.prefetchMinHits, 'cache.settings.prefetchHits') }) : t('lists.badge.off')}</dd>
              <dt>{t('cache.settings.acrossRestarts')}</dt><dd>{c.persist ? t('cache.settings.kept') : t('cache.settings.notKept')}</dd>
            </dl>
            <p class="muted small">{t('cache.settings.changeUnder')}<span class="mono">[cache]</span>{t('cache.settings.inConfig')}</p>
          </details>
        {/if}
      </section>
    {/each}
  </section>

  {#if charts.times.length > 1}
    <Chart title={t('cache.node.chartAnswered')} times={charts.times} series={charts.hit} height={180} format={(n) => pct(n)} markers={changes.markers} />
    <Chart title={t('cache.node.chartLookups')} times={charts.times} series={charts.lookups} height={160} markers={changes.markers} />
  {:else if stats.length}
    <p class="muted small">{t('cache.node.chartsFilling')}</p>
  {/if}

  <section class="card">
    <div class="head-row">
      <h2>{t('cache.makeup.title')}<HelpButton id="cache-page" /></h2>
      <span class="spacer"></span>
      <label class="pill-field">{t('cache.makeup.sort')}
        <select bind:value={sort} aria-label={t('cache.makeup.sortAria')}>
          <option value="hits">{t('cache.makeup.sortHits')}</option>
          <option value="bytes">{t('cache.makeup.sortBytes')}</option>
          <option value="expiring">{t('cache.makeup.sortExpiring')}</option>
        </select>
      </label>
      {#if stats.length > 1}
        <label class="pill-field">{t('legacy.showing')}
          <select bind:value={node} aria-label={t('qw.cache.node')}>
            <option value="">{t('qw.cache.everyNode')}</option>
            {#each stats as s, i (s.node ?? i)}<option value={s.node ?? ''}>{label(s)}</option>{/each}
          </select>
        </label>
      {/if}
      <button onclick={loadEntries} disabled={loading}>{loading ? t('slo.loading') : t('cache.makeup.refresh')}</button>
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
              {#if entries.length > 1}<th>{t('qw.cache.node')}</th>{/if}
              <th>{t('cache.makeup.colHolds')}</th>
              <th class="bar-col">
                <span class="key k-ok"></span>{t('cache.makeup.kind.answer.other')}
                <span class="key k-warn"></span>{t('cache.makeup.kind.noSuchName.other')}
                <span class="key k-info"></span>{t('cache.makeup.kind.noData.other')}
                <span class="key k-bad"></span>{t('cache.makeup.kind.servfail.other')}
              </th>
              <th class="num">{t('cache.makeup.colStale')}</th>
              <th class="num">{t('cache.makeup.colValidated')}</th>
            </tr>
          </thead>
          <tbody>
            {#each shownNodes as n, i (n.node ?? i)}
              {@const held = total(n.makeup)}
              <tr>
                {#if entries.length > 1}<td>{label(n)}</td>{/if}
                {#if n.error}
                  <td colspan="4" class="small warn-text">{n.error}</td>
                {:else}
                  <td class="small">{count(held, 'cache.makeup.kind.answer')}</td>
                  <td class="bar-col">
                    {#if held}
                      <span class="stack" title={kinds.map(([k, kind]) => count(n.makeup[k], kind)).join(' · ')}>
                        {#each kinds as [k], j (k)}
                          {#if n.makeup[k]}<span style:width={`${(n.makeup[k] * 100) / held}%`} style:--c={`var(${barColors[j]})`}></span>{/if}
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
          {showAllNodes ? t('cache.makeup.showFewer') : tn('cache.makeup.showAll', entries.length, { n: num(entries.length) })}
        </button>
      {/if}

      {#if merged.length === 0}
        <p class="empty">{sort === 'expiring' ? t('cache.top.emptyFresh') : t('cache.top.empty')}</p>
      {:else}
        <div class="table-wrap" data-testid="cache-top">
          <table class="compact">
            <thead>
              <tr>
                <th>{t('clients.col.name')}</th><th>{t('qw.cache.type')}</th><th>{t('qw.cache.answer')}</th><th>{t('qw.cache.fresh')}</th>
                {#if multi}<th>{t('legacy.nodes')}</th>{/if}
                <th class="num">{t('qw.cache.hits')}</th><th class="num">{t('lists.col.size')}</th>
              </tr>
            </thead>
            <tbody>
              {#each merged as m (m.key)}
                <tr class:open={expanded === m.key}>
                  <td class="mono"><button class="link" onclick={() => (lookupName = m.name)} title={t('cache.top.lookupTitle')}>{m.name}</button></td>
                  <td>{m.qtype}{#if m.dnssecOk}<span class="muted small"> (DO)</span>{/if}</td>
                  <td class="small">{m.rcode} · {m.answers}{#if m.authentic}<span class="badge ok">{t('qw.cache.validated')}</span>{/if}</td>
                  <td class="small {m.ttlMax < 0 ? 'muted' : ''}">{ttlShort(m.ttlMin) === ttlShort(m.ttlMax) ? ttl(m.ttlMin) : t('cache.top.ttlRange', { from: ttlShort(m.ttlMin), to: ttlShort(m.ttlMax) })}</td>
                  {#if multi}
                    <td class="small">
                      <button class="link" aria-expanded={expanded === m.key} onclick={() => (expanded = expanded === m.key ? null : m.key)}
                        >{t('cache.top.nodesOf', { shown: m.nodes.length, total: nodeCount })}</button
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
                          <li><strong>{d.node}</strong> · {ttl(d.entry.ttlLeftSeconds)} · {count(d.entry.hits, 'cache.top.hits')}</li>
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
            {t('cache.top.merged', { limit: LIMIT })}
          </p>
        {/if}
      {/if}
    {/if}
  </section>

  {#key lookupName}
    <CacheCard name={lookupName} compact title={t('cache.top.cardTitle')} />
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
