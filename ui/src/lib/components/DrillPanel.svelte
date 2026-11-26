<script lang="ts">
  // REQ: CLU-014 (ADR-151) — failover drills: the running ones with live counters and End now,
  // every node's reports newest first, and a report: coverage, the verdict per device (stuck
  // first), the time to failover, and whether each device came back afterwards.
  import { api, type S } from '../api';
  import { can } from '../session.svelte';
  import { poll } from '../poll';
  import { duration, logDate, logTime, num, pct } from '../format';
  import ClientChip from './ClientChip.svelte';
  import Drawer from './Drawer.svelte';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';
  import { own, tr } from '../i18n';
  import T from '../i18n/T.svelte';
  // REQ: API-012 — `devicesDropped` is a count (u32 on the server): tn() gives the ternary's English.
  const { t, tn } = tr('drillPanel');

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

  const statusText: Record<string, string> = {
    running: t('running'),
    collecting: t('collecting the report'),
    complete: t('complete'),
    cancelled: t('cancelled (restart)'),
  };
  const verdictText: Record<string, string> = {
    followed: t('followed'),
    stuck: t('stuck'),
    quiet: t('quiet'),
    elsewhere: t('elsewhere'),
  };
  const verdictClass: Record<string, string> = { followed: 'ok', stuck: 'bad', quiet: '', elsewhere: '' };
  /** A status or a verdict comes from the server: read with `Object.hasOwn` (one the UI doesn't know
   * shows as it is). */
  const when = (t: string) => `${logDate(t)} ${logTime(t)}`;
  const maxTtf = $derived(Math.max(1, ...(report?.devices.map((d) => d.timeToFailoverMs ?? 0) ?? [1])));
</script>

{#each running as d (d.id)}
  {@const a = live[d.id]}
  <section class="card drill-live" data-testid="drill-live">
    <h2>{t('Drill running on {node}', { node: d.node })}<HelpButton id="failover-drill" /></h2>
    <p>
      <T ctx="drillPanel" msg={'Not answering <strong>{targets}</strong> ({reason}).'} params={{ targets: d.targets, reason: d.reason }}
        >{#snippet strong(x: string)}<strong translate="no">{x}</strong>{/snippet}</T
      >
      {#if a}
        <span data-testid="drill-counters"
          >{tn('{n} queries unanswered from {devices} device · {left} left', '{n} queries unanswered from {devices} devices · {left} left', a.devicesDropped, { n: num(a.dropped), devices: num(a.devicesDropped), left: duration(a.secondsLeft) })}</span
        >
      {/if}
    </p>
    {#if can('operator')}
      <button onclick={() => end(d)} disabled={ending} data-testid="drill-end">{t('End now')}</button>
    {/if}
  </section>
{/each}

<section class="card">
  <h2>{t('Failover drills')}<HelpButton id="failover-drill" /></h2>
  <p class="muted small">
    <T
      ctx="drillPanel"
      msg={"A drill makes one node stop answering chosen devices for up to five minutes, then shows which devices switched to another node (they have a working second DNS server) and which were stuck. Start one with <em>Drill…</em> on a node's row."}
      >{#snippet em(x: string)}<em>{x}</em>{/snippet}</T
    >
  </p>
  <ErrorNote {error} />
  {#if page && page.items.length === 0}
    <p class="empty">{t('No drills yet.')}</p>
  {:else if page}
    <div class="table-wrap">
      <table>
        <thead>
          <tr><th>{t('When')}</th><th>{t('Node')}</th><th>{t('Targets')}</th><th>{t('Status')}</th><th class="num">{t('Coverage')}</th><th class="num">{t('Followed')}</th><th class="num">{t('Stuck')}</th><th class="num">{t('Quiet')}</th><th></th></tr>
        </thead>
        <tbody>
          {#each page.items as d (d.id)}
            <tr data-testid="drill-row">
              <td class="small">{when(d.since)}</td>
              <td>{d.node}{#if d.viaBalancer}<span class="muted small"> {t('· via balancer')}</span>{/if}</td>
              <td class="small" translate="no">{d.targets}</td>
              <td class="small">{own(statusText, d.status) ?? d.status}</td>
              <td class="num">{d.coveragePercent != null ? pct(d.coveragePercent) : '–'}</td>
              <td class="num">{d.followed}</td>
              <td class="num" class:bad-text={d.stuck > 0}>{d.stuck}</td>
              <td class="num">{d.quiet}</td>
              <td>{#if d.status === 'complete'}<button class="link small" onclick={() => show(d.id)} data-testid="drill-open">{t('Report')}</button>{/if}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    {#if page.missingNodes.length}<p class="muted small">{t('Not answering: {nodes}.', { nodes: page.missingNodes.join(', ') })}</p>{/if}
  {/if}
</section>
<ErrorNote error={reportError} />

{#if report}
  <Drawer title={t('Drill on {node}, {when}', { node: report.node, when: when(report.since) })} onclose={() => (report = null)}>
    <div class="report" data-testid="drill-report">
      <p class="small muted">
        {t('{targets} for {duration} · {reason} · by {by}', {
          targets: report.targets,
          duration: duration(Math.round((Date.parse(report.ended ?? report.until) - Date.parse(report.since)) / 1000)),
          reason: report.reason,
          by: report.by,
        })}
      </p>
      <div class="tiles">
        <div class="tile"><span class="big">{report.coveragePercent != null ? pct(report.coveragePercent) : '–'}</span><span class="small muted">{t('coverage')}</span></div>
        <div class="tile"><span class="big ok-text">{report.followed}</span><span class="small muted">{t('followed')}</span></div>
        <div class="tile"><span class="big" class:bad-text={report.stuck > 0}>{report.stuck}</span><span class="small muted">{t('stuck')}</span></div>
        <div class="tile"><span class="big">{report.quiet}</span><span class="small muted">{t('quiet')}</span></div>
        <div class="tile">
          <span class="big">{report.medianFailoverMs != null ? t('{n} s', { n: (report.medianFailoverMs / 1000).toFixed(1) }) : '–'}</span>
          <span class="small muted"
            >{#if report.p90FailoverMs != null}{t('median failover, p90 {n} s', { n: (report.p90FailoverMs / 1000).toFixed(1) })}{:else}{t('median failover')}{/if}</span
          >
        </div>
      </div>
      {#if report.viaBalancer}
        <p class="notice small">
          {t('This node is a resolver pod behind one balancer address: devices never see a server change, so the verdicts measure the balancer.')}{#if report.balancerSwitchMs != null} {t('It kept sending queries to the silent pod for {n} s.', { n: (report.balancerSwitchMs / 1000).toFixed(1) })}{/if}
        </p>
      {/if}
      {#if report.missingNodes.length}<p class="notice warn small">{t('Missing parts from {nodes}: devices that went there count as stuck or quiet.', { nodes: report.missingNodes.join(', ') })}</p>{/if}
      {#if report.devices.length === 0}
        <p class="muted small">{t('The query log\'s privacy level hides the devices; the counts above still hold.')}</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>{t('Device')}</th><th>{t('Verdict')}</th><th class="num">{t('Unanswered')}</th><th>{t('Time to failover')}</th><th>{t('Afterwards')}</th><th>{t('Group')}</th></tr>
            </thead>
            <tbody>
              {#each report.devices as d (d.client)}
                {@const on = (d.nodes ?? []).join(', ')}
                <tr data-testid="drill-device">
                  <td class="mono"><ClientChip ip={d.client} name={d.name ?? undefined} /></td>
                  <td><span class="badge {own(verdictClass, d.verdict) ?? ''}">{own(verdictText, d.verdict) ?? d.verdict}</span></td>
                  <td class="num">{num(d.dropped)}</td>
                  <td>
                    {#if d.timeToFailoverMs != null}
                      <span class="ttf"><span class="bar" style:width={`${Math.max(4, (d.timeToFailoverMs / maxTtf) * 100)}%`}></span></span>
                      <span class="small">{t('{n} s', { n: (d.timeToFailoverMs / 1000).toFixed(1) })}</span>
                    {:else}<span class="muted">–</span>{/if}
                  </td>
                  <td class="small">
                    {#if d.returned === true}{t('came back')}{:else if d.returned === false}{on ? t('stayed on {nodes}', { nodes: on }) : t('stayed on the other node')}{:else if d.verdict === 'followed'}<span class="muted">{t('checked 15 min after')}</span>{/if}
                  </td>
                  <td class="small" translate="no">{d.group ?? ''}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
      <p class="small muted">
        {#each report.nodes as n, i (n.node)}{i ? ' · ' : ''}{t('{node}: {queries} queries from {devices} devices', { node: n.node, queries: num(n.queries), devices: num(n.devices) })}{/each}
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
