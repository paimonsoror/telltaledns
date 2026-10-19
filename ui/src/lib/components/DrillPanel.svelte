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
    running: 'running',
    collecting: 'collecting the report',
    complete: 'complete',
    cancelled: 'cancelled (restart)',
  };
  const verdictText: Record<string, string> = {
    followed: 'followed',
    stuck: 'stuck',
    quiet: 'quiet',
    elsewhere: 'elsewhere',
  };
  const verdictClass: Record<string, string> = { followed: 'ok', stuck: 'bad', quiet: '', elsewhere: '' };
  const when = (t: string) => `${logDate(t)} ${logTime(t)}`;
  const maxTtf = $derived(Math.max(1, ...(report?.devices.map((d) => d.timeToFailoverMs ?? 0) ?? [1])));
</script>

{#each running as d (d.id)}
  {@const a = live[d.id]}
  <section class="card drill-live" data-testid="drill-live">
    <h2>Drill running on {d.node}<HelpButton id="failover-drill" /></h2>
    <p>
      Not answering <strong>{d.targets}</strong> ({d.reason}).
      {#if a}
        <span data-testid="drill-counters"
          >{num(a.dropped)} queries unanswered from {num(a.devicesDropped)} device{a.devicesDropped === 1 ? '' : 's'} · {duration(a.secondsLeft)} left</span
        >
      {/if}
    </p>
    {#if can('operator')}
      <button onclick={() => end(d)} disabled={ending} data-testid="drill-end">End now</button>
    {/if}
  </section>
{/each}

<section class="card">
  <h2>Failover drills<HelpButton id="failover-drill" /></h2>
  <p class="muted small">
    A drill makes one node stop answering chosen devices for up to five minutes, then shows which devices switched to another
    node (they have a working second DNS server) and which were stuck. Start one with <em>Drill…</em> on a node's row.
  </p>
  <ErrorNote {error} />
  {#if page && page.items.length === 0}
    <p class="empty">No drills yet.</p>
  {:else if page}
    <div class="table-wrap">
      <table>
        <thead>
          <tr><th>When</th><th>Node</th><th>Targets</th><th>Status</th><th class="num">Coverage</th><th class="num">Followed</th><th class="num">Stuck</th><th class="num">Quiet</th><th></th></tr>
        </thead>
        <tbody>
          {#each page.items as d (d.id)}
            <tr data-testid="drill-row">
              <td class="small">{when(d.since)}</td>
              <td>{d.node}{#if d.viaBalancer}<span class="muted small"> · via balancer</span>{/if}</td>
              <td class="small">{d.targets}</td>
              <td class="small">{statusText[d.status] ?? d.status}</td>
              <td class="num">{d.coveragePercent != null ? pct(d.coveragePercent) : '–'}</td>
              <td class="num">{d.followed}</td>
              <td class="num" class:bad-text={d.stuck > 0}>{d.stuck}</td>
              <td class="num">{d.quiet}</td>
              <td>{#if d.status === 'complete'}<button class="link small" onclick={() => show(d.id)} data-testid="drill-open">Report</button>{/if}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    {#if page.missingNodes.length}<p class="muted small">Not answering: {page.missingNodes.join(', ')}.</p>{/if}
  {/if}
</section>
<ErrorNote error={reportError} />

{#if report}
  <Drawer title={`Drill on ${report.node}, ${when(report.since)}`} onclose={() => (report = null)}>
    <div class="report" data-testid="drill-report">
      <p class="small muted">
        {report.targets} for {duration(Math.round((Date.parse(report.ended ?? report.until) - Date.parse(report.since)) / 1000))} · {report.reason} · by {report.by}
      </p>
      <div class="tiles">
        <div class="tile"><span class="big">{report.coveragePercent != null ? pct(report.coveragePercent) : '–'}</span><span class="small muted">coverage</span></div>
        <div class="tile"><span class="big ok-text">{report.followed}</span><span class="small muted">followed</span></div>
        <div class="tile"><span class="big" class:bad-text={report.stuck > 0}>{report.stuck}</span><span class="small muted">stuck</span></div>
        <div class="tile"><span class="big">{report.quiet}</span><span class="small muted">quiet</span></div>
        <div class="tile">
          <span class="big">{report.medianFailoverMs != null ? `${(report.medianFailoverMs / 1000).toFixed(1)} s` : '–'}</span>
          <span class="small muted">median failover{#if report.p90FailoverMs != null}, p90 {(report.p90FailoverMs / 1000).toFixed(1)} s{/if}</span>
        </div>
      </div>
      {#if report.viaBalancer}
        <p class="notice small">
          This node is a resolver pod behind one balancer address: devices never see a server change, so the verdicts measure the
          balancer.{#if report.balancerSwitchMs != null} It kept sending queries to the silent pod for {(report.balancerSwitchMs / 1000).toFixed(1)} s.{/if}
        </p>
      {/if}
      {#if report.missingNodes.length}<p class="notice warn small">Missing parts from {report.missingNodes.join(', ')}: devices that went there count as stuck or quiet.</p>{/if}
      {#if report.devices.length === 0}
        <p class="muted small">The query log's privacy level hides the devices; the counts above still hold.</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>Device</th><th>Verdict</th><th class="num">Unanswered</th><th>Time to failover</th><th>Afterwards</th><th>Group</th></tr>
            </thead>
            <tbody>
              {#each report.devices as d (d.client)}
                <tr data-testid="drill-device">
                  <td class="mono"><ClientChip ip={d.client} name={d.name ?? undefined} /></td>
                  <td><span class="badge {verdictClass[d.verdict] ?? ''}">{verdictText[d.verdict] ?? d.verdict}</span></td>
                  <td class="num">{num(d.dropped)}</td>
                  <td>
                    {#if d.timeToFailoverMs != null}
                      <span class="ttf"><span class="bar" style:width={`${Math.max(4, (d.timeToFailoverMs / maxTtf) * 100)}%`}></span></span>
                      <span class="small">{(d.timeToFailoverMs / 1000).toFixed(1)} s</span>
                    {:else}<span class="muted">–</span>{/if}
                  </td>
                  <td class="small">
                    {#if d.returned === true}came back{:else if d.returned === false}stayed on {(d.nodes ?? []).join(', ') || 'the other node'}{:else if d.verdict === 'followed'}<span class="muted">checked 15 min after</span>{/if}
                  </td>
                  <td class="small">{d.group ?? ''}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
      <p class="small muted">
        {#each report.nodes as n, i (n.node)}{i ? ' · ' : ''}{n.node}: {num(n.queries)} queries from {num(n.devices)} devices{/each}
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
