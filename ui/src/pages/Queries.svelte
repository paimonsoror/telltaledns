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
  import { mayBeAt } from '../lib/deviceKeys';
  import DomainIcon from '../lib/icons/DomainIcon.svelte';
  import { t, type MessageKey } from '../lib/i18n';

  const STATUSES = ['blocked', 'cached', 'refreshed', 'forwarded', 'local', 'stale', 'special', 'refused', 'servfail', 'rate_limited'];
  // A status the UI has words for reads in the language on screen; the value sent stays the
  // identifier (in the URL and in the request).
  const STATUS_KEY: Record<string, MessageKey> = {
    blocked: 'wall.kpi.blocked',
    cached: 'legacy.status.cached',
    forwarded: 'legacy.status.forwarded',
    local: 'legacy.status.local',
    stale: 'queries.status.stale',
    refreshing: 'queries.status.refreshing',
    refreshed: 'legacy.status.refreshed',
    special: 'queries.status.special',
    refused: 'help.flow.refused',
    servfail: 'queries.status.servfail',
    rate_limited: 'queries.status.rate_limited',
    paused: 'wall.paused',
    allowed: 'queries.status.allowed',
    malformed: 'queries.status.malformed',
  };
  const statusLabel = (s: string) => (STATUS_KEY[s] ? t(STATUS_KEY[s]) : s);
  const RANGES = $derived([
    { v: '-15m', l: t('flow.window.15m') },
    { v: '-1h', l: t('flow.window.1h') },
    { v: '-24h', l: t('flow.window.24h') },
    { v: '-168h', l: t('queries.range.7d') },
    { v: '', l: t('common.all') },
  ]);
  const PAGE = 100;

  // The form mirrors the URL; "Search" writes it, and the URL drives loading.
  let name = $state('');
  // REQ: OBS-003 (ADR-171) — `match` holds the Match select's value: a match, or `!` and a match
  // for "does not ..." (the URL keeps them apart: `match=substring&nameNot=true`).
  let match = $state('substring');
  let client = $state('');
  let statuses = $state(new Set<string>());
  let qtype = $state('');
  let rcode = $state('');
  let clientNot = $state(false);
  let statusNot = $state(false);
  let qtypeNot = $state(false);
  let rcodeNot = $state(false);
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
    match = `${p.get('nameNot') === 'true' ? '!' : ''}${p.get('match') ?? 'substring'}`;
    client = p.get('client') ?? '';
    statuses = new Set((p.get('status') ?? '').split(',').filter(Boolean));
    qtype = p.get('qtype') ?? '';
    rcode = p.get('rcode') ?? '';
    clientNot = p.get('clientNot') === 'true';
    statusNot = p.get('statusNot') === 'true';
    qtypeNot = p.get('qtypeNot') === 'true';
    rcodeNot = p.get('rcodeNot') === 'true';
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
  // The configured devices, for the quick rule form's pre-fill: null until they have arrived.
  let configured = $state<S['ClientInfo'][] | null>(null);
  let whySeq = 0;
  let whyError = $state<unknown>(null);

  function query(): Record<string, string> {
    const q = route.params;
    const o: Record<string, string> = {};
    for (const k of ['name', 'match', 'nameNot', 'client', 'clientNot', 'status', 'statusNot', 'qtype', 'qtypeNot', 'rcode', 'rcodeNot', 'from', 'minLatencyMs', 'group', 'trace']) {
      const v = q.get(k);
      if (v) o[k] = v;
    }
    if (!q.has('from')) o.from = '-24h';
    // REQ: OBS-017 — a trace ID names its own time.
    if (o.from === 'all' || o.trace) delete o.from;
    if (o.name === undefined) delete o.match;
    // REQ: OBS-003 — a negation without its filter (an old link) is dropped, not sent: the API refuses it.
    for (const [flag, field] of [['nameNot', 'name'], ['clientNot', 'client'], ['statusNot', 'status'], ['qtypeNot', 'qtype'], ['rcodeNot', 'rcode']]) {
      if (!o[field]) delete o[flag];
    }
    return o;
  }

  // REQ: OBS-008 — only the newest load lands: a page still loading when the search changes, or
  // when Live is switched on, must not put its (older) rows into what's showing now.
  let loadSeq = 0;
  async function load(more = false) {
    const seq = ++loadSeq;
    loading = true;
    try {
      const page = await api.queries({ ...query(), limit: PAGE, cursor: more ? cursor : undefined });
      if (seq !== loadSeq) return;
      rows = more ? [...rows, ...page.items] : page.items;
      cursor = page.nextCursor ?? undefined;
      scanned = page.scanned;
      missing = page.missingNodes ?? [];
      error = null;
    } catch (e) {
      if (seq === loadSeq) error = e;
    } finally {
      if (seq === loadSeq) loading = false;
    }
  }

  // REQ: OBS-008 — Live: the server streams matching queries (SSE); rows are added in
  // batches every 250 ms and the newest MAX_LIVE are kept.
  const MAX_LIVE = 500;
  let skipped = $state(0);
  let liveState = $state<'connecting' | 'open' | 'retrying'>('connecting');
  // The words under the Live switch: what the stream is doing, in the language on screen.
  const liveLabel = $derived(
    liveState === 'open' ? t('queries.live.streaming') : liveState === 'connecting' ? t('queries.live.connecting') : t('queries.live.retrying'),
  );

  function streamParams(): string {
    const q = query();
    const p = new URLSearchParams();
    for (const k of ['name', 'match', 'nameNot', 'client', 'clientNot', 'status', 'statusNot', 'qtype', 'qtypeNot', 'minLatencyMs']) if (q[k]) p.set(k, q[k]);
    return p.toString();
  }

  $effect(() => {
    void route.params.toString();
    if (!live) {
      void load(false);
      return;
    }
    loadSeq++; // a load still in flight is stale now
    loading = false;
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
      match: name.trim() && match.replace(/^!/, '') !== 'substring' ? match.replace(/^!/, '') : undefined,
      nameNot: name.trim() && match.startsWith('!') ? 'true' : undefined,
      client: client.trim() || undefined,
      clientNot: client.trim() && clientNot ? 'true' : undefined,
      status: [...statuses].join(',') || undefined,
      statusNot: statuses.size && statusNot ? 'true' : undefined,
      qtype: qtype.trim().toUpperCase() || undefined,
      qtypeNot: qtype.trim() && qtypeNot ? 'true' : undefined,
      rcode: rcode.trim().toUpperCase() || undefined,
      rcodeNot: rcode.trim() && rcodeNot ? 'true' : undefined,
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
    clientNot = statusNot = qtypeNot = rcodeNot = false;
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
    const mine = ++whySeq;
    why = r;
    explained = null;
    configured = null;
    whyError = null;
    // The configured devices are for the quick rule form, which only someone who makes rules sees:
    // asked beside the explanation (a read from every node that must not hold it up), and not at all
    // for anyone else.
    const devices = can('operator')
      ? api
          .clients()
          .then((c) => c.items)
          .catch(() => [] as S['ClientInfo'][])
      : null;
    try {
      const x = await api.explain({ name: r.name, client: r.client, qtype: r.qtype });
      if (mine === whySeq) explained = x;
    } catch (e) {
      if (mine === whySeq) whyError = e;
      return;
    }
    if (devices) void devices.then((items) => mine === whySeq && (configured = items));
  }

  /**
   * REQ: FLT-005, FLT-017 (issue #73) — what the quick rule form starts with. A rule can name a
   * configured device, an IP, or a CIDR; never a name a router or mDNS gives an address, nor a pod's
   * `namespace/kind/name`. So, in order:
   * - a pod (this node's explanation has the workload; the shape of a name decides nothing, as a
   *   device or a router may call itself anything): its address, and today's group of the workload
   *   from the same explanation (the row's own group is the one it was logged with, which may be
   *   from before the workload was placed);
   * - the device this node's explanation recognized;
   * - a configured device the log names, when the explanation has none (the row may come from a node
   *   that recognized it by a MAC address this node can't see) and the device's own keys could be
   *   this address (`mayBeAt`: its IP holds it, or its MAC is not ruled out by the MAC the
   *   explanation knows): a name that merely equals what a router or mDNS calls another device is
   *   not that device;
   * - the address, with what the log shows for it as a label, not as the value.
   */
  function prefillOf(row: S['QueryRow'], x: S['Explanation'], devices: S['ClientInfo'][]) {
    const pod = x.client.workload ?? undefined;
    const logged = row.clientName ?? '';
    if (pod) {
      return { device: row.client, seenAs: '', workload: pod.name, workloadFrom: pod.groupFrom, group: x.client.groups[0] ?? '' };
    }
    const own = x.client.device ?? undefined;
    const named = own
      ? undefined
      : devices.find((d) => d.name.toLowerCase() === logged.toLowerCase() && mayBeAt(d, row.client, x.client.mac))?.name;
    const device = own ?? named ?? row.client;
    return {
      device,
      seenAs: device === row.client && logged ? logged : '',
      workload: '',
      workloadFrom: '',
      group: row.group ?? '',
    };
  }

  const maxMs = $derived(Math.max(1, ...rows.map((r) => r.totalMs)));
</script>

<div class="page">
  <div class="page-head">
    <h1>{t('nav.queries')}<HelpButton id="query-log" /></h1>
    <span class="switch-track live-toggle">
      <label class="switch"><input type="checkbox" role="switch" bind:checked={live} />{t('flow.live')}</label>
      <HelpButton id="live-view" />
      {#if live}<span class="badge {liveState === 'open' ? 'ok' : 'warn'}">{liveLabel}</span>{/if}
    </span>
  </div>
  {#if liveIgnores}
    <div class="notice warn small">{t('queries.liveIgnores')}</div>
  {/if}
  {#if route.params.get('trace') && !live}
    <!-- REQ: OBS-017 — from a latency exemplar (Grafana) or an exported trace. -->
    <div class="notice small" data-testid="trace-filter">
      {t('queries.traceNotice')} <code>{route.params.get('trace')}</code><HelpButton id="exemplars" />
      <button type="button" class="link" onclick={clear}>{t('queries.showAllQueries')}</button>
    </div>
  {/if}

  <form class="card filters" onsubmit={search}>
    <div class="fields">
      <label class="field grow">{t('clients.col.name')}
        <input name="name" placeholder="ads.example.com" bind:value={name} />
      </label>
      <label class="field">{t('queries.filter.match')}
        <select name="match" bind:value={match}>
          <option value="substring">{t('queries.match.substring')}</option>
          <option value="exact">{t('queries.match.exact')}</option>
          <option value="suffix">{t('queries.match.suffix')}</option>
          <option value="glob">{t('queries.match.glob')}</option>
          <option value="regex">{t('queries.match.regex')}</option>
          <!-- REQ: OBS-003 (ADR-171) — the same five, negated: every query whose name does not match. -->
          <option value="!substring">{t('queries.match.notSubstring')}</option>
          <option value="!exact">{t('queries.match.notExact')}</option>
          <option value="!suffix">{t('queries.match.notSuffix')}</option>
          <option value="!glob">{t('queries.match.notGlob')}</option>
          <option value="!regex">{t('queries.match.notRegex')}</option>
        </select>
      </label>
      <div class="pair">
        <label class="field">{t('qw.explain.client')}
          <input name="client" placeholder="192.168.1.20" bind:value={client} />
        </label>
        <label class="not" title={t('queries.filter.clientNot')}><input type="checkbox" name="clientNot" bind:checked={clientNot} />{t('queries.not')}</label>
      </div>
      <div class="pair narrow">
        <label class="field">{t('qw.cache.type')}
          <input name="qtype" placeholder="A,AAAA" bind:value={qtype} />
        </label>
        <label class="not" title={t('queries.filter.qtypeNot')}><input type="checkbox" name="qtypeNot" bind:checked={qtypeNot} />{t('queries.not')}</label>
      </div>
      <div class="pair narrow">
        <label class="field">{t('queries.filter.rcode')}
          <input name="rcode" placeholder="NXDOMAIN" bind:value={rcode} />
        </label>
        <label class="not" title={t('queries.filter.rcodeNot')}><input type="checkbox" name="rcodeNot" bind:checked={rcodeNot} />{t('queries.not')}</label>
      </div>
      <label class="field narrow">{t('queries.filter.minLatency')}
        <input name="minLatency" type="number" min="0" bind:value={minLatency} />
      </label>
      {#if groups.length > 1}
        <label class="field">{t('legacy.group')}
          <select name="group" bind:value={group} onchange={() => search()}>
            <option value="">{t('queries.filter.any')}</option>
            {#each groups as g (g.name)}<option value={g.name}>{g.name}</option>{/each}
          </select>
        </label>
      {/if}
      <label class="field">{t('queries.filter.since')}
        <select name="from" bind:value={from} onchange={() => search()}>
          {#each RANGES as r (r.v)}<option value={r.v}>{r.l}</option>{/each}
        </select>
      </label>
    </div>
    <div class="row">
      <button type="button" class="chip" data-testid="status-not" aria-pressed={statusNot} title={t('queries.statusNot')} onclick={() => { statusNot = !statusNot; if (statuses.size) search(); }}>{t('queries.not')}</button>
      {#each STATUSES as s (s)}
        <button type="button" class="chip" aria-pressed={statuses.has(s)} onclick={() => toggleStatus(s)}>{statusLabel(s)}</button>
      {/each}
      <span class="spacer"></span>
      <button type="button" onclick={clear}>{t('queries.clear')}</button>
      <button type="submit" class="primary">{t('common.search')}</button>
    </div>
  </form>

  <ErrorNote {error} />

  <section class="card">
    {#if rows.length === 0 && !loading}
      <p class="empty">{t('queries.empty')}</p>
    {:else}
      <div class="table-wrap">
        <table class="log">
          <thead>
            <tr>
              <th>{t('dashw.time')}</th><th>{t('qw.explain.client')}</th><th>{t('clients.col.name')}</th><th>{t('qw.cache.type')}</th><th>{t('cluster.col.status')}</th><th>{t('rules.col.rule')}</th>
              <th class="num">{t('queries.col.took')}</th><th></th>
            </tr>
          </thead>
          <tbody>
            {#each rows as r, i (r.tsUnixMicros + ':' + i)}
              <tr>
                <td class="nowrap" title={logDate(r.time)}>
                  {logTime(r.time)}
                  {#if r.node}<div class="muted small" title={t('queries.nodeTitle')}>{r.node}</div>{/if}
                </td>
                <td class="nowrap">
                  <ClientChip ip={r.client} name={r.clientName} onchanged={(n) => renamed(r.client, n)} />
                  {#if r.group}<div class="group-chip small" style:--gc={groupColor(r.group)}>{r.group}</div>{/if}
                </td>
                <td class="name mono"><span class="nmi"><DomainIcon name={r.name} quiet={r.status === 'blocked'} /><span>{r.name}</span></span></td>
                <td>{r.qtype}</td>
                <td>
                  <StatusBadge value={r.status} />
                  {#if r.rcode && r.rcode !== 'NOERROR'}<div><StatusBadge value={r.rcode} /></div>{/if}
                </td>
                <td class="small">{#if r.list}{r.list}<div class="muted">{r.rule}</div>{:else}<span class="muted">–</span>{/if}</td>
                <td class="num">
                  {ms(r.totalMs)}
                  <div class="timing" title={t('queries.timing', { upstream: ms(r.upstreamMs), total: ms(r.totalMs) })}>
                    <span class="own" style:width={`${((r.totalMs - r.upstreamMs) / maxMs) * 100}%`}></span>
                    <span class="up" style:width={`${(r.upstreamMs / maxMs) * 100}%`}></span>
                  </div>
                </td>
                <td><button class="link" onclick={() => explain(r)}>{t('queries.why')}</button></td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
    <div class="row foot">
      <span class="muted small">
        {#if live}
          {t('queries.foot.liveRows', { n: num(rows.length), max: MAX_LIVE })}{#if skipped}{t('queries.foot.skipped', { n: num(skipped) })}{/if}
        {:else}
          {t('queries.foot.rows', { n: num(rows.length) })}{#if missing.length}{t('queries.foot.notReached', { names: missing.join(', ') })}{/if}{#if scanned}{t('queries.foot.searched', { read: num(scanned.blocksRead), total: num(scanned.blocksTotal), files: num(scanned.segments) })}{/if}
        {/if}
      </span>
      <span class="spacer"></span>
      {#if cursor && !live}
        <button onclick={() => load(true)} disabled={loading}>{loading ? t('common.loading') : t('queries.older')}</button>
      {/if}
    </div>
  </section>
</div>

{#if why}
  <Drawer title={t('queries.whyTitle', { name: why.name })} onclose={() => (why = null)}>
    <ErrorNote error={whyError} />
    {#if explained}
      <p class="muted small">
        {t('queries.whyExplains', { time: logTime(why.time) })}
        {t('queries.whyLoggedAs')} <strong>{statusLabel(why.status)}</strong>{why.list ? t('queries.whyLoggedBy', { list: why.list }) : ''}{t('queries.whyEnd')}
      </p>
      <ExplainView x={explained} />
      {#if can('operator')}
        <!-- REQ: FLT-005 (T6.12) — act on it: a quick rule for this device or its group. -->
        <section class="card quick-card">
          <h2>{t('queries.makeQuickRule')}<HelpButton id="quick-rules" /></h2>
          {#if configured}
            {@const pre = prefillOf(why, explained, configured)}
            <!-- REQ: FLT-005, FLT-017 (issue #73) — what a rule can name; see prefillOf. -->
            <QuickRuleForm
              domain={why.name}
              device={pre.device}
              address={why.client}
              seenAs={pre.seenAs}
              workload={pre.workload}
              workloadFrom={pre.workloadFrom}
              group={pre.group}
              known={configured}
            />
          {:else}
            <p class="muted small" role="status">{t('queries.loadingDevices')}</p>
          {/if}
        </section>
      {/if}
      <!-- REQ: DNS-006 (T6.13) — what the cache holds for this name, and flushing it. -->
      <div class="quick-card"><CacheCard name={why.name} compact /></div>
    {:else if !whyError}
      <p class="muted">{t('common.loading')}</p>
    {/if}
  </Drawer>
{/if}

<style>
  /* REQ: OBS-039 — the mark and the name on one line; a long name wraps beside the mark. */
  .nmi {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    max-width: 100%;
  }
  .nmi > span:last-child {
    min-width: 0;
    overflow-wrap: anywhere;
  }
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
  /* A filter and its "not" box stay together when the row wraps. */
  .pair {
    display: flex;
    align-items: flex-end;
    gap: 6px;
    flex: 1 1 150px;
  }
  .pair.narrow {
    flex-basis: 110px;
  }
  .pair .field {
    flex: 1 1 auto;
    min-width: 0;
  }
  .not {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding-bottom: 8px;
    font-size: 12.5px;
    color: var(--muted);
    white-space: nowrap;
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
