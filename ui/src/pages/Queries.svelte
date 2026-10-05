<script lang="ts">
  // REQ: API-005, OBS-007 — the query log: filters (kept in the URL), newest first, paging by
  // cursor, a stage-timing bar per row, and "Why?" (explain, FLT-013) in a drawer.
  import { api, type S } from '../lib/api';
  import { route, navigate } from '../lib/router.svelte';
  import { logDate, logTime, ms, num } from '../lib/format';
  import Drawer from '../lib/components/Drawer.svelte';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import ExplainView from '../lib/components/ExplainView.svelte';
  import StatusBadge from '../lib/components/StatusBadge.svelte';
  import ClientChip from '../lib/components/ClientChip.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import QuickRuleForm from '../lib/components/QuickRuleForm.svelte';
  import CacheCard from '../lib/components/CacheCard.svelte';
  import { can } from '../lib/session.svelte';

  const STATUSES = ['blocked', 'cached', 'forwarded', 'local', 'stale', 'special', 'refused', 'servfail', 'rate_limited'];
  const RANGES = [
    { v: '-15m', l: '15 min' },
    { v: '-1h', l: '1 h' },
    { v: '-24h', l: '24 h' },
    { v: '-168h', l: '7 days' },
    { v: '', l: 'All' },
  ];
  const PAGE = 100;

  // The form mirrors the URL; "Search" writes it, and the URL drives loading.
  let name = $state('');
  let match = $state('substring');
  let client = $state('');
  let statuses = $state(new Set<string>());
  let qtype = $state('');
  let rcode = $state('');
  let from = $state('-24h');
  let minLatency = $state('');
  let group = $state('');
  let groups = $state<S['GroupInfo'][]>([]);
  $effect(() => {
    api
      .groups()
      .then((g) => (groups = g.items))
      .catch(() => {});
  });
  const groupColor = (n: string | null | undefined) => groups.find((g) => g.name === n)?.color ?? 'var(--muted)';

  // Links into the log (dashboard, clients, the nav) change the URL without remounting.
  $effect(() => {
    const p = route.params;
    name = p.get('name') ?? '';
    match = p.get('match') ?? 'substring';
    client = p.get('client') ?? '';
    statuses = new Set((p.get('status') ?? '').split(',').filter(Boolean));
    qtype = p.get('qtype') ?? '';
    rcode = p.get('rcode') ?? '';
    from = p.get('from') === 'all' ? '' : (p.get('from') ?? '-24h');
    minLatency = p.get('minLatencyMs') ?? '';
    group = p.get('group') ?? '';
  });

  let rows = $state<S['QueryRow'][]>([]);
  let cursor = $state<string | undefined>();
  let scanned = $state<S['ScanStats'] | null>(null);
  let missing = $state<string[]>([]);
  let loading = $state(false);
  let error = $state<unknown>(null);
  let live = $state(false);
  let why = $state<S['QueryRow'] | null>(null);
  let explained = $state<S['Explanation'] | null>(null);
  let whyError = $state<unknown>(null);

  function query(): Record<string, string> {
    const q = route.params;
    const o: Record<string, string> = {};
    for (const k of ['name', 'match', 'client', 'status', 'qtype', 'rcode', 'from', 'minLatencyMs', 'group']) {
      const v = q.get(k);
      if (v) o[k] = v;
    }
    if (!q.has('from')) o.from = '-24h';
    if (o.from === 'all') delete o.from;
    if (o.name === undefined) delete o.match;
    return o;
  }

  async function load(more = false) {
    loading = true;
    try {
      const page = await api.queries({ ...query(), limit: PAGE, cursor: more ? cursor : undefined });
      rows = more ? [...rows, ...page.items] : page.items;
      cursor = page.nextCursor ?? undefined;
      scanned = page.scanned;
      missing = page.missingNodes ?? [];
      error = null;
    } catch (e) {
      error = e;
    } finally {
      loading = false;
    }
  }

  // REQ: OBS-008 — Live: the server streams matching queries (SSE); rows are added in
  // batches every 250 ms and the newest MAX_LIVE are kept.
  const MAX_LIVE = 500;
  let skipped = $state(0);
  let liveState = $state<'connecting' | 'open' | 'retrying'>('connecting');

  function streamParams(): string {
    const q = query();
    const p = new URLSearchParams();
    for (const k of ['name', 'match', 'client', 'status', 'qtype', 'minLatencyMs']) if (q[k]) p.set(k, q[k]);
    return p.toString();
  }

  $effect(() => {
    void route.params.toString();
    if (!live) {
      void load(false);
      return;
    }
    rows = [];
    cursor = undefined;
    scanned = null;
    skipped = 0;
    error = null;
    liveState = 'connecting';
    const qs = streamParams();
    const es = new EventSource(`/api/v1/queries/stream${qs ? `?${qs}` : ''}`);
    let pending: S['QueryRow'][] = [];
    es.addEventListener('query', (m) => {
      pending.push(JSON.parse((m as MessageEvent).data) as S['QueryRow']);
    });
    es.addEventListener('dropped', (m) => {
      skipped += (JSON.parse((m as MessageEvent).data) as S['TailDropped']).dropped;
    });
    es.onopen = () => (liveState = 'open');
    es.onerror = () => (liveState = 'retrying');
    const flush = setInterval(() => {
      if (pending.length === 0) return;
      rows = [...pending.reverse(), ...rows].slice(0, MAX_LIVE);
      pending = [];
    }, 250);
    return () => {
      es.close();
      clearInterval(flush);
    };
  });

  const liveIgnores = $derived(live && (route.params.has('rcode') || route.params.has('from') || route.params.has('group')));

  function search(e?: SubmitEvent) {
    e?.preventDefault();
    navigate('/queries', {
      name: name.trim() || undefined,
      match: name.trim() && match !== 'substring' ? match : undefined,
      client: client.trim() || undefined,
      status: [...statuses].join(',') || undefined,
      qtype: qtype.trim().toUpperCase() || undefined,
      rcode: rcode.trim().toUpperCase() || undefined,
      from: from === '-24h' ? undefined : from || 'all',
      minLatencyMs: minLatency || undefined,
      group: group || undefined,
    });
  }

  function toggleStatus(s: string) {
    const next = new Set(statuses);
    if (next.has(s)) next.delete(s);
    else next.add(s);
    statuses = next;
    search();
  }

  function clear() {
    name = '';
    match = 'substring';
    client = '';
    statuses = new Set();
    qtype = '';
    rcode = '';
    from = '-24h';
    minLatency = '';
    group = '';
    search();
  }

  // API-010 — a rename shows at once: live rows are relabelled in place, a search re-runs.
  function renamed(ip: string, name: string) {
    if (live) rows = rows.map((x) => (x.client === ip ? { ...x, clientName: name } : x));
    else void load();
  }

  async function explain(r: S['QueryRow']) {
    why = r;
    explained = null;
    whyError = null;
    try {
      explained = await api.explain({ name: r.name, client: r.client, qtype: r.qtype });
    } catch (e) {
      whyError = e;
    }
  }

  const maxMs = $derived(Math.max(1, ...rows.map((r) => r.totalMs)));
</script>

<div class="page">
  <div class="page-head">
    <h1>Query log<HelpButton id="query-log" /></h1>
    <label class="row small live-toggle">
      <input type="checkbox" bind:checked={live} /> Live<HelpButton id="live-view" />
      {#if live}<span class="badge {liveState === 'open' ? 'ok' : 'warn'}">{liveState === 'open' ? 'streaming' : liveState}</span>{/if}
    </label>
  </div>
  {#if liveIgnores}
    <div class="notice warn small">The live view ignores the Rcode, Since, and Group filters; it shows new queries as they happen.</div>
  {/if}

  <form class="card filters" onsubmit={search}>
    <div class="fields">
      <label class="field grow">Name
        <input name="name" placeholder="ads.example.com" bind:value={name} />
      </label>
      <label class="field">Match
        <select name="match" bind:value={match}>
          <option value="substring">contains</option>
          <option value="exact">exactly</option>
          <option value="suffix">and subdomains</option>
          <option value="glob">wildcard (*)</option>
          <option value="regex">regex</option>
        </select>
      </label>
      <label class="field">Client
        <input name="client" placeholder="192.168.1.20" bind:value={client} />
      </label>
      <label class="field narrow">Type
        <input name="qtype" placeholder="A,AAAA" bind:value={qtype} />
      </label>
      <label class="field narrow">Rcode
        <input name="rcode" placeholder="NXDOMAIN" bind:value={rcode} />
      </label>
      <label class="field narrow">Slower than (ms)
        <input name="minLatency" type="number" min="0" bind:value={minLatency} />
      </label>
      {#if groups.length > 1}
        <label class="field">Group
          <select name="group" bind:value={group} onchange={() => search()}>
            <option value="">any</option>
            {#each groups as g (g.name)}<option value={g.name}>{g.name}</option>{/each}
          </select>
        </label>
      {/if}
      <label class="field">Since
        <select name="from" bind:value={from} onchange={() => search()}>
          {#each RANGES as r (r.v)}<option value={r.v}>{r.l}</option>{/each}
        </select>
      </label>
    </div>
    <div class="row">
      {#each STATUSES as s (s)}
        <button type="button" class="chip" aria-pressed={statuses.has(s)} onclick={() => toggleStatus(s)}>{s}</button>
      {/each}
      <span class="spacer"></span>
      <button type="button" onclick={clear}>Clear</button>
      <button type="submit" class="primary">Search</button>
    </div>
  </form>

  <ErrorNote {error} />

  <section class="card">
    {#if rows.length === 0 && !loading}
      <p class="empty">No queries match.</p>
    {:else}
      <div class="table-wrap">
        <table class="log">
          <thead>
            <tr>
              <th>Time</th><th>Client</th><th>Name</th><th>Type</th><th>Status</th><th>Rule</th>
              <th class="num">Time taken</th><th></th>
            </tr>
          </thead>
          <tbody>
            {#each rows as r, i (r.tsUnixMicros + ':' + i)}
              <tr>
                <td class="nowrap" title={logDate(r.time)}>
                  {logTime(r.time)}
                  {#if r.node}<div class="muted small" title="The cluster node that answered">{r.node}</div>{/if}
                </td>
                <td class="nowrap">
                  <ClientChip ip={r.client} name={r.clientName} onchanged={(n) => renamed(r.client, n)} />
                  {#if r.group}<div class="group-chip small" style:--gc={groupColor(r.group)}>{r.group}</div>{/if}
                </td>
                <td class="name mono">{r.name}</td>
                <td>{r.qtype}</td>
                <td>
                  <StatusBadge value={r.status} />
                  {#if r.rcode && r.rcode !== 'NOERROR'}<div><StatusBadge value={r.rcode} /></div>{/if}
                </td>
                <td class="small">{#if r.list}{r.list}<div class="muted">{r.rule}</div>{:else}<span class="muted">–</span>{/if}</td>
                <td class="num">
                  {ms(r.totalMs)}
                  <div class="timing" title={`upstream ${ms(r.upstreamMs)} of ${ms(r.totalMs)}`}>
                    <span class="own" style:width={`${((r.totalMs - r.upstreamMs) / maxMs) * 100}%`}></span>
                    <span class="up" style:width={`${(r.upstreamMs / maxMs) * 100}%`}></span>
                  </div>
                </td>
                <td><button class="link" onclick={() => explain(r)}>Why?</button></td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
    <div class="row foot">
      <span class="muted small">
        {#if live}
          {`${num(rows.length)} live rows (newest ${MAX_LIVE} kept)`}{#if skipped}{` · ${num(skipped)} matching queries skipped to keep up`}{/if}
        {:else}
          {num(rows.length)} rows{#if missing.length}{` · not reached: ${missing.join(', ')}`}{/if}{#if scanned}{` · searched ${num(scanned.blocksRead)} of ${num(scanned.blocksTotal)} blocks in ${num(scanned.segments)} hourly files`}{/if}
        {/if}
      </span>
      <span class="spacer"></span>
      {#if cursor && !live}
        <button onclick={() => load(true)} disabled={loading}>{loading ? 'Loading…' : 'Older'}</button>
      {/if}
    </div>
  </section>
</div>

{#if why}
  <Drawer title={`Why: ${why.name}`} onclose={() => (why = null)}>
    <ErrorNote error={whyError} />
    {#if explained}
      <p class="muted small">
        Explains how this query would be handled now; lists or settings may have changed since {logTime(why.time)}.
        Logged as <strong>{why.status}</strong>{why.list ? ` by ${why.list}` : ''}.
      </p>
      <ExplainView x={explained} />
      {#if can('operator')}
        <!-- REQ: FLT-005 (T6.12) — act on it: a quick rule for this device or its group. -->
        <section class="card quick-card">
          <h2>Make a quick rule<HelpButton id="quick-rules" /></h2>
          <QuickRuleForm domain={why.name} device={why.clientName ?? why.client} group={why.group ?? ''} />
        </section>
      {/if}
      <!-- REQ: DNS-006 (T6.13) — what the cache holds for this name, and flushing it. -->
      <div class="quick-card"><CacheCard name={why.name} compact /></div>
    {:else if !whyError}
      <p class="muted">Loading…</p>
    {/if}
  </Drawer>
{/if}

<style>
  .filters {
    display: grid;
    gap: 10px;
  }
  .fields {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
  }
  .fields .grow {
    flex: 2 1 220px;
  }
  .fields .field {
    flex: 1 1 130px;
  }
  .fields .narrow {
    flex: 1 1 90px;
  }
  .chip {
    min-height: 28px;
    padding: 2px 10px;
    border-radius: 999px;
    font-size: 12.5px;
  }
  .chip[aria-pressed='true'] {
    background: var(--accent);
    color: var(--accent-text);
    border-color: var(--accent);
  }
  .log td {
    font-size: 13px;
  }
  .nowrap {
    white-space: nowrap;
  }
  .name {
    word-break: break-all;
    min-width: 160px;
  }
  .timing {
    display: flex;
    justify-content: flex-end;
    height: 4px;
    margin-top: 3px;
    min-width: 60px;
  }
  .timing .own {
    background: var(--s-cached);
  }
  .timing .up {
    background: var(--s-forwarded);
  }
  .foot {
    margin-top: 10px;
  }
  .quick-card {
    margin-top: 16px;
  }
</style>
