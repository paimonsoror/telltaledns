<script lang="ts">
  // REQ: API-005 (ADR-157) — the dashboard: the numbers that matter as plain text, one chart whose
  // hover gives the exact figures, and the top lists. One card (the chart) on an otherwise open page.
  //
  // Advanced adds, without adding cards: the service level (OBS-016) as a strip under the numbers;
  // the chart's other views (groups, upstream exchanges) beside Status; where time goes (OBS-030)
  // and the upstreams as plain sections; devices by type (OBS-025) as a line under the clients.
  import { api, type S } from '../lib/api';
  import { changes } from '../lib/annotations.svelte';
  import { change, DashData, remember } from '../lib/dash/data.svelte';
  import DashHead from '../lib/dash/DashHead.svelte';
  import SmoothChart from '../lib/dash/SmoothChart.svelte';
  import Stat from '../lib/dash/Stat.svelte';
  import TopList from '../lib/dash/TopList.svelte';
  import BreakerBadge from '../lib/components/BreakerBadge.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import LatencyHeatmap from '../lib/components/LatencyHeatmap.svelte';
  import Tip from '../lib/components/Tip.svelte';
  import { href } from '../lib/router.svelte';
  import { ms, num, pct, short } from '../lib/format';
  import { t } from '../lib/i18n';

  const d = new DashData();
  $effect(() => d.attach());
  $effect(() => remember(d.scope));
  const s = $derived(d.summary);
  const scopeLabel = $derived(
    d.scope.startsWith('node:')
      ? (d.nodes.find((n) => `node:${n.nodeId}` === d.scope)?.site ?? t('dashboard.oneNode'))
      : d.scope.startsWith('site:')
        ? t('dashboard.siteLabel', { site: d.scope.slice(5) })
        : t('dashboard.everyNode'),
  );

  const lists = $derived([
    {
      title: t('dashboard.topDomains'),
      items: d.topDomains,
      kind: 'domains' as const,
      link: (k: string, merged: boolean) => href('/queries', { name: k, match: merged ? 'substring' : 'exact' }),
    },
    {
      title: t('dashboard.topBlocked'),
      items: d.topBlocked,
      kind: 'blocked' as const,
      link: (k: string, merged: boolean) => href('/queries', { name: k, match: merged ? 'substring' : 'exact', status: 'blocked' }),
    },
    { title: t('dashboard.topClients'), items: d.topClients, kind: 'clients' as const, link: (k: string) => href('/queries', { client: k }) },
  ]);

  // The chart's view: Totals (queries and the blocked part) and Status (stacked) for everyone;
  // Groups and Upstream in the Advanced view.
  type View = 'totals' | 'status' | 'group' | 'upstream';
  let view = $state<View>('totals');
  const hasGroups = $derived(d.groupSeries.length > 1 || (d.groupSeries.length === 1 && d.groupSeries[0].label !== 'default'));
  const views = $derived([
    { id: 'totals' as View, name: t('dashboard.view.totals') },
    { id: 'status' as View, name: t('dashboard.view.status') },
    ...(d.advanced ? [...(hasGroups ? [{ id: 'group' as View, name: t('dashboard.view.groups') }] : []), { id: 'upstream' as View, name: t('dashboard.view.upstream') }] : []),
  ]);
  const shown = $derived(views.some((v) => v.id === view) ? view : 'totals');
  const chart = $derived(
    shown === 'status'
      ? { title: t('dashboard.chart.queriesByStatus'), series: d.statusSeries, mode: 'stack' as const }
      : shown === 'group'
        ? { title: t('dashboard.chart.trafficByGroup'), series: d.groupSeries, mode: 'stack' as const }
        : shown === 'upstream'
          ? { title: t('dashboard.chart.upstreamExchanges'), series: d.upstreamSeries, mode: 'area' as const }
          : { title: t('dashboard.queries'), series: [d.totalSeries, d.blockedSeries], mode: 'area' as const },
  );

  // The cache number, split the way the Advanced view splits it (DNS-007).
  const cacheSub = $derived(
    d.advanced && d.refreshedPercent != null && (s?.refreshed ?? 0) > 0
      ? t('dashboard.cacheFreshRefreshed', {
          fresh: pct((s?.cacheHitPercent ?? 0) - d.refreshedPercent),
          refreshed: pct(d.refreshedPercent),
        })
      : t('dashboard.cacheAnswers', { answers: short(s?.cached) }),
  );

  // Service level (OBS-016). Read through functions, not module-level tables: the words follow the
  // language on screen. `last 30 days`: the count picks its own English plural.
  const sloWindow = (days: number) =>
    days === 1 ? t('dashboard.slo.window.one', { n: 1 }) : t('dashboard.slo.window.other', { n: days });
  const sloTitle = (name: string) =>
    name === 'availability' ? t('dashboard.slo.availability') : name === 'latency' ? t('dashboard.slo.latency') : name;
  const sloAlert = (name: string | null | undefined): { text: string; tone: string; tip: string } | null =>
    name === 'fast'
      ? { text: t('dashboard.slo.alert.fast'), tone: 'bad', tip: t('dashboard.slo.alert.fastTip') }
      : name === 'slow'
        ? { text: t('dashboard.slo.alert.slow'), tone: 'bad', tip: t('dashboard.slo.alert.slowTip') }
        : name === 'ticket'
          ? { text: t('dashboard.slo.alert.ticket'), tone: 'warn', tip: t('dashboard.slo.alert.ticketTip') }
          : null;
  const sloPct = (v: number | null | undefined, digits = 2) => (v == null ? '–' : `${v.toFixed(v >= 99.995 || v === 0 ? 0 : digits)}%`);
  const budgetTone = (v: number | null | undefined) => (v == null ? '' : v >= 50 ? 'ok' : v >= 25 ? 'warn' : 'bad');
  const burnText = (b: S['SloBurn']) => (b.rate == null ? '–' : `${b.rate >= 10 ? b.rate.toFixed(0) : b.rate.toFixed(1)}×`);
  const burnTip = (b: S['SloBurn']) =>
    b.rate == null
      ? t('dashboard.slo.burn.none', { window: b.window })
      : t('dashboard.slo.burn.some', { window: b.window, bad: short(b.bad), total: short(b.total) });

  // Where time goes (OBS-030): what each row means (path/transport, or a wait stage).
  let timeView = $state<'table' | 'heatmap'>('table');
  const pathOf = (path: string) =>
    path === 'cache'
      ? t('dashboard.path.cache')
      : path === 'upstream'
        ? t('dashboard.path.upstream')
        : path === 'local'
          ? t('dashboard.path.local')
          : path === 'synthesized'
            ? t('dashboard.path.synthesized')
            : t('dashboard.path.fallback');
  const protoOf = (proto: string) =>
    proto === 'udp'
      ? t('dashboard.proto.udp')
      : proto === 'tcp'
        ? t('dashboard.proto.tcp')
        : proto === 'dot'
          ? t('dashboard.proto.dot')
          : proto === 'doh'
            ? t('dashboard.proto.doh')
            : '';
  const pathTip = (key: string) => {
    if (key.startsWith('wait: ')) {
      const what = key.slice(6);
      return what === 'upstream' ? t('dashboard.path.waitUpstream') : t('dashboard.path.wait', { what });
    }
    const [path, proto] = key.split('/');
    const p = pathOf(path);
    const pr = proto ? protoOf(proto) : '';
    return pr ? t('dashboard.path.over', { path: p, proto: pr }) : p;
  };
  const timeRows = $derived([...d.byPath, ...d.stages.map((x) => ({ ...x, key: `wait: ${x.key}` }))]);

  // Upstreams: health is each node's own, so say whose when another node is shown.
  const totalUp = $derived(d.upstreams.reduce((a, u) => a + u.requests, 0));
  const otherNode = $derived(d.scope !== '' && !(d.scope.startsWith('node:') && d.nodes.find((n) => `node:${n.nodeId}` === d.scope)?.thisNode));

  // Devices by type (OBS-025).
  let identities = $state<S['DeviceIdentity'][]>([]);
  $effect(() => {
    if (!d.advanced) return;
    api
      .identities()
      .then((r) => (identities = r.items))
      .catch(() => (identities = []));
  });
  const types = $derived.by(() => {
    const m = new Map<string, number>();
    for (const i of identities) m.set(i.class, (m.get(i.class) ?? 0) + 1);
    return [...m.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  });
</script>

<div class="page calm">
  <DashHead {d} />

  <div class="stats">
    <div class="cell" data-testid="stat-queries"><Stat label={t('dashboard.queries')} value={short(s?.queries)} delta={change(s?.queries, d.previous?.queries)} sub={`${t('dashboard.lastRange', { range: d.range.label })}${d.scope ? ` · ${scopeLabel}` : ''}`} /></div>
    <div class="cell" data-testid="stat-blocked"><Stat label={t('dashboard.blocked')} value={pct(s?.blockedPercent)} delta={change(s?.blockedPercent, d.previous?.blockedPercent)} sub={t('dashboard.blockedQueries', { queries: short(s?.blocked) })} /></div>
    <div class="cell" data-testid="stat-cache"><Stat label={t('dashboard.cacheHits')} value={pct(s?.cacheHitPercent)} delta={change(s?.cacheHitPercent, d.previous?.cacheHitPercent)} good="up" sub={cacheSub} /></div>
    <div class="cell" data-testid="stat-upstream"><Stat label={t('dashboard.upstreamP90')} value={ms(d.upstreamP90?.p90Ms)} sub={d.cacheP50 ? t('dashboard.cacheP50', { value: ms(d.cacheP50.p50Ms) }) : t('dashboard.thisHour')} delta={change(d.upstreamP90?.p90Ms, d.prevP90?.p90Ms)} good="down" /></div>
    <div class="cell" data-testid="stat-clients"><Stat label={t('dashboard.activeClients')} value={num(s?.activeClients)} sub={d.rangeLabel} /></div>
  </div>
  <p class="fine muted small">{t('dashboard.nxdomainLine', { nxdomain: short(s?.nxdomain), servfail: short(s?.servfail), range: d.range.label })}</p>

  {#if d.advanced}
    <section class="slo sec" data-testid="slo-card" aria-label={t('dashboard.slo.heading')}>
      <div class="sh">
        <h2>{t('dashboard.slo.heading')} {#if d.slo?.enabled}<span class="muted small">{sloWindow(d.slo.windowDays)}</span>{/if}<HelpButton id="slo" /></h2>
      </div>
      {#if !d.slo}
        <p class="muted small">{t('common.loading')}</p>
      {:else if !d.slo.enabled}
        <p class="muted small">{t('dashboard.slo.off')}<code>[slo] enabled = false</code>{t('dashboard.slo.offEnd')}</p>
      {:else}
        {#if d.slo.missingNodes?.length}
          <p class="small muted">{t('dashboard.slo.missing', { nodes: d.slo.missingNodes.join(', ') })}</p>
        {/if}
        <div class="objs">
          {#each d.slo.objectives as o (o.name)}
            {@const left = o.budgetRemainingPercent}
            {@const alert = sloAlert(o.alert)}
            <div class="obj" data-testid={`slo-${o.name}`}>
              <div class="oh">
                <strong>{sloTitle(o.name)}</strong>
                {#if alert}
                  <Tip text={alert.tip}><span class="badge {alert.tone}">{alert.text}</span></Tip>
                {:else if o.total > 0}
                  <span class="badge ok">{t('dashboard.slo.onTrack')}</span>
                {/if}
              </div>
              <div class="muted small">{t('dashboard.slo.target', { means: o.goodMeans, target: o.targetPercent })}</div>
              <div class="fig"><b>{sloPct(o.sliPercent, 3)}</b> <span class="muted small">{t('dashboard.slo.ofAnswers', { answers: short(o.total) })}</span></div>
              <div class="track {budgetTone(left)}" title={t('dashboard.slo.budgetTitle')}><span style:width={`${Math.max(0, Math.min(100, left ?? 0))}%`}></span></div>
              <div class="small">
                {#if left == null}{t('dashboard.slo.noAnswers')}{:else if left < 0}{t('dashboard.slo.overspent')}{:else}{t('dashboard.slo.budgetLeft', { pct: left.toFixed(0) })}{/if}
                · <a href={href('/analyze', { tab: 'budget', objective: o.name })} data-testid={`slo-who-${o.name}`}>{t('dashboard.slo.who')}</a>
              </div>
              <div class="small muted">
                {t('dashboard.slo.burnRate')}
                {#each o.burnRates as b, i (b.window)}{i ? ' · ' : ' '}<Tip text={burnTip(b)}><span class="burn" class:hot={(b.rate ?? 0) >= 6}>{b.window} {burnText(b)}</span></Tip>{/each}
              </div>
            </div>
          {/each}
        </div>
      {/if}
    </section>
  {/if}

  <section class="card plot" data-testid="dashboard-chart">
    <div class="views seg" role="group" aria-label={t('dashboard.chartView')}>
      {#each views as v (v.id)}
        <button aria-pressed={shown === v.id} onclick={() => (view = v.id)}>{v.name}</button>
      {/each}
    </div>
    <SmoothChart title={chart.title} times={d.times} series={chart.series} mode={chart.mode} height={260} axes="minimal" markers={changes.markers} />
  </section>

  {#if d.advanced}
    <div class="pair">
      <section class="sec" class:wide={timeView === 'heatmap'}>
        <div class="sh">
          <h2>{t('dashboard.whereTimeGoes')} {#if timeView === 'table'}<span class="muted small">{t('dashboard.thisHour')}</span>{/if}{#if timeView === 'heatmap'}<HelpButton id="latency-heatmap" />{:else}<HelpButton id="cache" />{/if}</h2>
          <div class="seg" role="group" aria-label={t('dashboard.whereTimeGoesAs')}>
            <button type="button" aria-pressed={timeView === 'table'} onclick={() => (timeView = 'table')}>{t('dashboard.percentiles')}</button>
            <button type="button" aria-pressed={timeView === 'heatmap'} onclick={() => (timeView = 'heatmap')} data-testid="time-heatmap-tab">{t('dashboard.heatmap')}</button>
          </div>
        </div>
        {#if timeView === 'heatmap'}
          <LatencyHeatmap />
        {:else if timeRows.length === 0}
          <p class="empty">{t('dashboard.noAnswersHour')}</p>
        {:else}
          <div class="table-wrap">
            <table class="compact times">
              <thead><tr><th>{t('dashboard.table.path')}</th><th class="num hide-sm">{t('dashboard.table.answers')}</th><th class="num">p50</th><th class="num">p90</th><th class="num">p99</th><th class="num hide-sm">{t('dashboard.table.max')}</th></tr></thead>
              <tbody>
                {#each timeRows as r (r.key)}
                  <tr>
                    <td><Tip text={pathTip(r.key)}>{r.key}</Tip></td>
                    <td class="num hide-sm">{num(r.count)}</td>
                    <td class="num">{ms(r.p50Ms)}</td>
                    <td class="num">{ms(r.p90Ms)}</td>
                    <td class="num">{ms(r.p99Ms)}</td>
                    <td class="num hide-sm">{ms(r.maxMs)}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        {/if}
      </section>

      <section class="sec">
        <div class="sh">
          <h2>{t('dashboard.upstreams')}{#if otherNode} <span class="muted small">{t('dashboard.asThisNode')}</span>{/if}</h2>
          <a href={href('/upstreams')} class="small">{t('dashboard.details')}</a>
        </div>
        {#if d.upstreams.length === 0}
          <p class="empty">{t('dashboard.noUpstreams')}</p>
        {:else}
          <ul class="ups">
            {#each d.upstreams as u (u.id)}
              {@const share = totalUp ? (u.requests / totalUp) * 100 : 0}
              <li style:--w={`${share}%`}>
                <div class="uh">
                  <strong>{u.name}</strong>
                  <BreakerBadge value={u.breaker} />
                  <span class="spacer"></span>
                  <span class="muted small">{pct(share, 0)} · {ms(u.latencyEwmaMs)}</span>
                </div>
              </li>
            {/each}
          </ul>
        {/if}
      </section>
    </div>
  {/if}

  <div class="lists">
    {#each lists as l (l.kind)}
      <section>
        {#if l.kind === 'domains'}
          <div class="sh">
            <h2>{l.title} <span class="muted small">{d.topLabel}</span><HelpButton id="internal-names" /></h2>
            <div class="seg" role="group" aria-label={t('dashboard.domainsScope')}>
              <button type="button" aria-pressed={d.domainsView === 'internet'} onclick={() => (d.domainsView = 'internet')}>{t('dashboard.internet')}</button>
              <button type="button" aria-pressed={d.domainsView === 'internal'} onclick={() => (d.domainsView = 'internal')} data-testid="domains-internal-tab">{t('dashboard.internal')}</button>
            </div>
          </div>
        {:else}
          <div class="sh"><h2>{l.title} <span class="muted small">{d.topLabel}</span></h2></div>
        {/if}
        {#if l.kind === 'clients' && l.items.some((i) => i.byStatus)}
          <p class="legend small muted" data-testid="clients-legend">
            {#each [['blocked', '--s-blocked'], ['cached', '--s-cached'], ['forwarded', '--s-forwarded'], ['other', '--s-other']] as [k, c] (k)}<span><i style:background={`var(${c})`}></i>{k}</span>{/each}
          </p>
        {/if}
        <TopList items={l.items} kind={l.kind} link={l.link} groupColor={d.groupColor} onchanged={() => void d.load()} />
        {#if d.advanced && l.kind === 'clients' && types.length}
          <p class="types small muted" data-testid="devices-by-type">
            {t('dashboard.byType')}
            {#each types as [cls, n] (cls)}<span class="ty">{cls} <b>{n}</b></span>{/each}
            <a href={href('/clients')}>{t('dashboard.clients')}</a>
          </p>
        {/if}
      </section>
    {/each}
  </div>
</div>

<style>
  .calm {
    gap: 22px;
  }
  .stats {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 16px 12px;
  }
  .cell {
    min-width: 0;
  }
  .fine {
    margin: -8px 0 0;
  }
  .plot {
    padding: 14px 18px 8px;
  }
  /* The chart's views: one switch above the chart, left-aligned, so the Table link keeps the corner. */
  .views {
    margin-bottom: 8px;
    max-width: 100%;
    overflow-x: auto;
    scrollbar-width: none;
  }
  .views button {
    flex: none;
  }

  /* Plain sections: a heading over a hairline, no card. */
  .sec {
    min-width: 0;
  }
  .sh {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 6px 10px;
    margin: 0 0 4px;
    padding: 0 0 8px;
    border-bottom: 1px solid var(--border);
  }
  .sec .sh {
    margin-bottom: 8px;
  }
  .sh h2 {
    margin: 0;
    padding: 0;
    font-size: 14px;
  }
  .sh h2::before {
    display: none;
  }

  /* Service level: two objectives side by side, a thin budget track under each figure. */
  .objs {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(min(100%, 300px), 1fr));
    gap: 16px 36px;
  }
  .obj {
    display: grid;
    gap: 5px;
    min-width: 0;
  }
  .oh {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }
  .fig b {
    font-size: 22px;
    font-weight: 650;
    letter-spacing: -0.02em;
    font-variant-numeric: tabular-nums;
    margin-right: 6px;
  }
  .track {
    height: 4px;
    border-radius: 999px;
    background: var(--surface-2);
    overflow: hidden;
  }
  .track span {
    display: block;
    height: 100%;
    border-radius: 999px;
    background: var(--ok);
  }
  .track.warn span {
    background: var(--warn);
  }
  .track.bad span {
    background: var(--bad);
  }
  .burn.hot {
    color: var(--bad-strong);
    font-weight: 600;
  }

  .pair {
    display: grid;
    grid-template-columns: minmax(0, 1fr);
    gap: 22px 36px;
  }
  .wide {
    grid-column: 1 / -1;
  }
  .times th,
  .times td {
    padding: 6px 8px 6px 0;
    vertical-align: middle;
  }
  .times td {
    line-height: 1.3;
  }
  .times th.num,
  .times td.num {
    padding-right: 0;
    padding-left: 12px;
  }
  @media (max-width: 640px) {
    .hide-sm {
      display: none;
    }
  }
  .ups {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
  }
  .ups li {
    position: relative;
    padding: 9px 0 11px;
    border-bottom: 1px solid var(--surface-2);
  }
  .ups li:last-child {
    border-bottom: 0;
  }
  /* The share of requests as a thin line under the name. */
  .ups li::after {
    content: '';
    position: absolute;
    left: 0;
    bottom: 4px;
    height: 2px;
    width: var(--w);
    min-width: 2px;
    border-radius: 2px;
    background: var(--s-forwarded);
    opacity: 0.55;
  }
  .uh {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
  }

  /* REQ: OBS-004 (ADR-159) — the key to a device's split bar. */
  .legend {
    display: flex;
    flex-wrap: wrap;
    gap: 2px 12px;
    margin: 4px 0 0;
  }
  .legend span {
    display: inline-flex;
    align-items: center;
    gap: 5px;
  }
  .legend i {
    width: 8px;
    height: 8px;
    border-radius: 2px;
  }
  .types {
    display: flex;
    flex-wrap: wrap;
    gap: 2px 12px;
    margin: 10px 0 0;
  }
  .ty b {
    color: var(--text);
    font-variant-numeric: tabular-nums;
  }
  .lists {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(min(100%, 270px), 1fr));
    gap: 8px 36px;
    margin-top: 6px;
  }
  @media (min-width: 560px) {
    .stats {
      grid-template-columns: repeat(3, minmax(0, 1fr));
    }
  }
  @media (min-width: 980px) {
    .stats {
      grid-template-columns: repeat(5, minmax(0, 1fr));
      gap: 0;
    }
    .cell {
      padding: 2px 22px;
      border-left: 1px solid var(--border);
    }
    .cell:first-child {
      padding-left: 0;
      border-left: 0;
    }
    .pair {
      grid-template-columns: minmax(0, 1.6fr) minmax(0, 1fr);
    }
  }
</style>
