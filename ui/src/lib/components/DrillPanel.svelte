<script lang="ts">
  // REQ: CLU-014 (ADR-151) — failover drills: the running ones with live counters and End now,
  // every node's reports newest first, and a report: coverage, the verdict per device (stuck
  // first), the time to failover, and whether each device came back afterwards.
  import { api, type S } from '../api';
  import { can } from '../session.svelte';
  import { poll } from '../poll';
  import { duration, logDate, logTime, num, pct } from '../format';
  // REQ: API-011 — the drills tab's own words; a node, a target, and a reason are data.
  import { t, tn, type MessageKey } from '../i18n';
  import ClientChip from './ClientChip.svelte';
  import Drawer from './Drawer.svelte';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';

  let { open = null }: { /** A report to open (`#/cluster?tab=drills&drill=<id>`). */ open?: string | null } = $props();

  let page = $state<S['DrillPage'] | null>(null);
  let live = $state<Record<string, S['ActiveDrill'] | null>>({});
  let error = $state<unknown>(null);
  let report = $state<S['DrillReport'] | null>(null);
  let reportError = $state<unknown>(null);
  let ending = $state(false);

  const running = $derived(page?.items.filter((d) => d.status === 'running') ?? []);
  const busy = $derived((page?.items ?? []).some((d) => d.status === 'running' || d.status === 'collecting'));

  async function load() {
    try {
      page = await api.drills(20);
      error = null;
      const next: Record<string, S['ActiveDrill'] | null> = {};
      for (const d of page.items.filter((x) => x.status === 'running')) {
        next[d.id] = await api.activeDrill(d.node).catch(() => null);
      }
      live = next;
    } catch (e) {
      error = e;
    }
  }
  // Every 2 s while a drill runs or its report is being put together, else every 15 s.
  $effect(() => poll(load, busy ? 2000 : 15_000));

  async function show(id: string) {
    reportError = null;
    try {
      report = await api.drillReport(id);
    } catch (e) {
      reportError = e;
    }
  }
  $effect(() => {
    if (open) void show(open);
  });

  async function end(d: S['DrillSummary']) {
    ending = true;
    try {
      await api.endDrill(d.node);
      await load();
    } catch (e) {
      error = e;
    } finally {
      ending = false;
    }
  }

  const statusText: Record<string, MessageKey> = {
    running: 'cluster.tab.drillsRunning',
    collecting: 'clusterWidgets.drillPanel.status.collecting',
    complete: 'clusterWidgets.drillPanel.status.complete',
    cancelled: 'clusterWidgets.drillPanel.status.cancelled',
  };
  const verdictText: Record<string, MessageKey> = {
    followed: 'clusterWidgets.drillPanel.tile.followed',
    stuck: 'clusterWidgets.drillPanel.tile.stuck',
    quiet: 'clusterWidgets.drillPanel.tile.quiet',
    elsewhere: 'clusterWidgets.drillPanel.verdict.elsewhere',
  };
  const verdictClass: Record<string, string> = { followed: 'ok', stuck: 'bad', quiet: '', elsewhere: '' };
  const when = (iso: string) => `${logDate(iso)} ${logTime(iso)}`;
  const maxTtf = $derived(Math.max(1, ...(report?.devices.map((d) => d.timeToFailoverMs ?? 0) ?? [1])));
</script>

{#each running as d (d.id)}
  {@const a = live[d.id]}
  <section class="card drill-live" data-testid="drill-live">
    <h2>{t('clusterWidgets.drillPanel.live.title', { node: d.node })}<HelpButton id="failover-drill" /></h2>
    <p>
      {t('clusterWidgets.drillPanel.live.notAnswering')} <strong>{d.targets}</strong>{t('clusterWidgets.drillPanel.live.reason', { reason: d.reason })}
      {#if a}
        <span data-testid="drill-counters"
          >{tn('clusterWidgets.drillPanel.live.devices', a.devicesDropped, { dropped: num(a.dropped) })}{t('clusterWidgets.drillPanel.live.left', {
            time: duration(a.secondsLeft),
          })}</span
        >
      {/if}
    </p>
    {#if can('operator')}
      <button onclick={() => end(d)} disabled={ending} data-testid="drill-end">{t('clusterWidgets.drillPanel.live.end')}</button>
    {/if}
  </section>
{/each}

<section class="card">
  <h2>{t('clusterWidgets.drillPanel.title')}<HelpButton id="failover-drill" /></h2>
  <p class="muted small">
    {t('clusterWidgets.drillPanel.about')} <em>{t('cluster.drill.open')}</em>{t('clusterWidgets.drillPanel.aboutEnd')}
  </p>
  <ErrorNote {error} />
  {#if page && page.items.length === 0}
    <p class="empty">{t('clusterWidgets.drillPanel.empty')}</p>
  {:else if page}
    <div class="table-wrap">
      <table>
        <thead>
          <tr><th>{t('changes.plan.when')}</th><th>{t('qw.cache.node')}</th><th>{t('clusterWidgets.drillPanel.col.targets')}</th><th>{t('cluster.col.status')}</th><th class="num">{t('clusterWidgets.drillPanel.col.coverage')}</th><th class="num">{t('clusterWidgets.drillPanel.col.followed')}</th><th class="num">{t('clusterWidgets.drillPanel.col.stuck')}</th><th class="num">{t('clusterWidgets.drillPanel.col.quiet')}</th><th></th></tr>
        </thead>
        <tbody>
          {#each page.items as d (d.id)}
            <tr data-testid="drill-row">
              <td class="small">{when(d.since)}</td>
              <td>{d.node}{#if d.viaBalancer}<span class="muted small">{t('clusterWidgets.drillPanel.viaBalancer')}</span>{/if}</td>
              <td class="small">{d.targets}</td>
              <td class="small">{statusText[d.status] ? t(statusText[d.status]) : d.status}</td>
              <td class="num">{d.coveragePercent != null ? pct(d.coveragePercent) : '–'}</td>
              <td class="num">{d.followed}</td>
              <td class="num" class:bad-text={d.stuck > 0}>{d.stuck}</td>
              <td class="num">{d.quiet}</td>
              <td>{#if d.status === 'complete'}<button class="link small" onclick={() => show(d.id)} data-testid="drill-open">{t('clusterWidgets.drillPanel.report')}</button>{/if}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    {#if page.missingNodes.length}<p class="muted small">{t('clusterWidgets.drillPanel.missing', { nodes: page.missingNodes.join(', ') })}</p>{/if}
  {/if}
</section>
<ErrorNote error={reportError} />

{#if report}
  <Drawer title={t('clusterWidgets.drillPanel.drawer.title', { node: report.node, when: when(report.since) })} onclose={() => (report = null)}>
    <div class="report" data-testid="drill-report">
      <p class="small muted">
        {t('clusterWidgets.drillPanel.report.for', {
          targets: report.targets,
          duration: duration(Math.round((Date.parse(report.ended ?? report.until) - Date.parse(report.since)) / 1000)),
          reason: report.reason,
          by: report.by,
        })}
      </p>
      <div class="tiles">
        <div class="tile"><span class="big">{report.coveragePercent != null ? pct(report.coveragePercent) : '–'}</span><span class="small muted">{t('clusterWidgets.drillPanel.tile.coverage')}</span></div>
        <div class="tile"><span class="big ok-text">{report.followed}</span><span class="small muted">{t('clusterWidgets.drillPanel.tile.followed')}</span></div>
        <div class="tile"><span class="big" class:bad-text={report.stuck > 0}>{report.stuck}</span><span class="small muted">{t('clusterWidgets.drillPanel.tile.stuck')}</span></div>
        <div class="tile"><span class="big">{report.quiet}</span><span class="small muted">{t('clusterWidgets.drillPanel.tile.quiet')}</span></div>
        <div class="tile">
          <span class="big">{report.medianFailoverMs != null ? `${(report.medianFailoverMs / 1000).toFixed(1)} s` : '–'}</span>
          <span class="small muted"
            >{t('clusterWidgets.drillPanel.tile.median')}{#if report.p90FailoverMs != null}{t('clusterWidgets.drillPanel.tile.p90', {
                seconds: (report.p90FailoverMs / 1000).toFixed(1),
              })}{/if}</span
          >
        </div>
      </div>
      {#if report.viaBalancer}
        <p class="notice small">
          {t('clusterWidgets.drillPanel.balancer')}{#if report.balancerSwitchMs != null}{t('clusterWidgets.drillPanel.balancerFor', {
              seconds: (report.balancerSwitchMs / 1000).toFixed(1),
            })}{/if}
        </p>
      {/if}
      {#if report.missingNodes.length}<p class="notice warn small">{t('clusterWidgets.drillPanel.missingParts', { nodes: report.missingNodes.join(', ') })}</p>{/if}
      {#if report.devices.length === 0}
        <p class="muted small">{t('clusterWidgets.drillPanel.privacy')}</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>{t('flow.device')}</th><th>{t('clusterWidgets.drillPanel.col.verdict')}</th><th class="num">{t('clusterWidgets.drillPanel.col.unanswered')}</th><th>{t('clusterWidgets.drillPanel.col.ttf')}</th><th>{t('clusterWidgets.drillPanel.col.afterwards')}</th><th>{t('legacy.group')}</th></tr>
            </thead>
            <tbody>
              {#each report.devices as d (d.client)}
                <tr data-testid="drill-device">
                  <td class="mono"><ClientChip ip={d.client} name={d.name ?? undefined} /></td>
                  <td><span class="badge {verdictClass[d.verdict] ?? ''}">{verdictText[d.verdict] ? t(verdictText[d.verdict]) : d.verdict}</span></td>
                  <td class="num">{num(d.dropped)}</td>
                  <td>
                    {#if d.timeToFailoverMs != null}
                      <span class="ttf"><span class="bar" style:width={`${Math.max(4, (d.timeToFailoverMs / maxTtf) * 100)}%`}></span></span>
                      <span class="small">{(d.timeToFailoverMs / 1000).toFixed(1)} s</span>
                    {:else}<span class="muted">–</span>{/if}
                  </td>
                  <td class="small">
                    {#if d.returned === true}{t('clusterWidgets.drillPanel.cameBack')}{:else if d.returned === false}{t('clusterWidgets.drillPanel.stayedOn', {
                        list: (d.nodes ?? []).join(', ') || t('clusterWidgets.drillPanel.theOtherNode'),
                      })}{:else if d.verdict === 'followed'}<span class="muted">{t('clusterWidgets.drillPanel.checkedAfter')}</span>{/if}
                  </td>
                  <td class="small">{d.group ?? ''}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
      <p class="small muted">
        {#each report.nodes as n, i (n.node)}{i ? ' · ' : ''}{tn('clusterWidgets.drillPanel.nodeLine', n.devices, {
            node: n.node,
            queries: num(n.queries),
          })}{/each}
      </p>
    </div>
  </Drawer>
{/if}

<style>
  .tiles {
    display: flex;
    flex-wrap: wrap;
    gap: 16px;
    margin: 8px 0 12px;
  }
  .tile {
    display: flex;
    flex-direction: column;
    min-width: 90px;
  }
  .big {
    font-size: 1.5rem;
    font-weight: 600;
  }
  .ttf {
    display: inline-block;
    width: 80px;
    height: 8px;
    background: var(--surface-2, rgba(127, 127, 127, 0.15));
    border-radius: 4px;
    vertical-align: middle;
    margin-right: 6px;
  }
  .bar {
    display: block;
    height: 100%;
    border-radius: 4px;
    background: var(--brand);
  }
</style>
