<script lang="ts">
  // REQ: CLU-008 (T6.11) — the machine a node runs on, for monitoring and triage: what looks
  // wrong first, then memory, CPU, and disk with their last hour, then the details.
  import type { S } from '../api';
  import { bytes, duration, num, pct } from '../format';
  // REQ: API-011 — the card's own words; the numbers and the OS's names are not ours to translate.
  import { t, type MessageKey } from '../i18n';
  import HelpButton from './HelpButton.svelte';

  let { title, sub = '', host }: { title: string; sub?: string; host: S['HostReport'] } = $props();
  const h = $derived(host.latest);

  /** The level a share of a resource is at, for the bar's colour. */
  const level = (p: number | null | undefined, warn = 75, bad = 90) =>
    p == null ? '' : p >= bad ? 'bad' : p >= warn ? 'warn' : 'ok';
  const width = (p: number | null | undefined) => `${Math.min(100, Math.max(0, p ?? 0))}%`;

  // A 100×24 sparkline of one series of the last hour.
  function line(key: 'cpuPercent' | 'memUsedPercent' | 'diskUsedPercent' | 'temperatureC', max = 100): string {
    const pts = host.history.map((p) => p[key]).filter((v): v is number => v != null && Number.isFinite(v));
    if (pts.length < 2) return '';
    const top = Math.max(max, ...pts);
    return pts.map((v, i) => `${i ? 'L' : 'M'}${((i / (pts.length - 1)) * 100).toFixed(1)},${(23 - (v / top) * 22).toFixed(1)}`).join(' ');
  }
  const memPct = $derived(h.cgroupMemUsedPercent ?? h.memUsedPercent);
  const unavailable: Record<string, MessageKey> = {
    memory: 'clusterWidgets.host.na.memory',
    load: 'clusterWidgets.host.na.load',
    cpu: 'clusterWidgets.host.cpu',
    process: 'clusterWidgets.host.na.process',
    cgroup: 'clusterWidgets.host.na.cgroup',
    thermal: 'clusterWidgets.host.na.thermal',
    disk: 'clusterWidgets.host.na.disk',
    os: 'clusterWidgets.host.na.os',
  };
</script>

<article class="card host" data-testid="host-card">
  <header>
    <h3>{title}</h3>
    {#if sub}<span class="muted small">{sub}</span>{/if}
    <span class="muted small sys">{[h.os, h.arch, h.kernel && `Linux ${h.kernel}`].filter(Boolean).join(' · ')}</span>
  </header>

  {#if h.warnings.length}
    <ul class="warnings" data-testid="host-warnings">
      {#each h.warnings as w (w)}<li>{w}</li>{/each}
    </ul>
  {/if}

  <div class="meters">
    <div class="meter">
      <div class="row"><span class="label">{t('qw.cache.memory')}</span><b>{pct(memPct, 0)}</b></div>
      <div class="bar"><span class={level(memPct)} style:width={width(memPct)}></span></div>
      <div class="muted small">
        {#if h.cgroupMemLimitBytes != null}
          {t('clusterWidgets.host.mem.cgroup', {
            used: bytes(h.cgroupMemUsedBytes),
            limit: bytes(h.cgroupMemLimitBytes),
            hostPct: pct(h.memUsedPercent, 0),
            hostTotal: bytes(h.memTotalBytes),
          })}
        {:else if h.memTotalBytes != null}
          {t('clusterWidgets.host.mem.of', {
            used: bytes((h.memTotalBytes ?? 0) - (h.memAvailableBytes ?? 0)),
            total: bytes(h.memTotalBytes),
          })}
        {:else}{t('clusterWidgets.host.unavailable')}{/if}
        {#if h.swapTotalBytes}{' · '}{t('clusterWidgets.host.mem.swap', { used: bytes(h.swapUsedBytes), total: bytes(h.swapTotalBytes) })}{/if}
        {#if h.oomKills}{' · '}<span class="bad-text">{t('clusterWidgets.host.mem.oom', { n: num(h.oomKills) })}</span>{/if}
      </div>
      {#if line('memUsedPercent')}<svg class="spark" viewBox="0 0 100 24" preserveAspectRatio="none" aria-hidden="true"><path d={line('memUsedPercent')} /></svg>{/if}
    </div>

    <div class="meter">
      <div class="row"><span class="label">{t('clusterWidgets.host.cpu')}</span><b>{pct(h.cpuPercent, 0)}</b></div>
      <div class="bar"><span class={level(h.cpuPercent, 70, 90)} style:width={width(h.cpuPercent)}></span></div>
      <div class="muted small">
        {#if h.load1 != null}{t('clusterWidgets.host.cpu.load', { l1: h.load1.toFixed(2), l5: h.load5?.toFixed(2) ?? '', l15: h.load15?.toFixed(2) ?? '' })}{/if}
        {#if h.cpus != null}{' · '}{t('clusterWidgets.host.cpu.cores', { n: h.cpus })}{/if}
        {#if h.cgroupCpuQuotaCores != null}{' · '}{t('clusterWidgets.host.cpu.limit', { n: h.cgroupCpuQuotaCores })}{/if}
        {#if h.throttledPercent}{' · '}<span class={h.throttledPercent >= 10 ? 'bad-text' : ''}>{t('clusterWidgets.host.cpu.throttled', { pct: pct(h.throttledPercent, 0) })}</span>{/if}
        {#if h.cpuPercent == null && h.load1 == null}{t('clusterWidgets.host.unavailable')}{/if}
      </div>
      {#if line('cpuPercent')}<svg class="spark" viewBox="0 0 100 24" preserveAspectRatio="none" aria-hidden="true"><path d={line('cpuPercent')} /></svg>{/if}
    </div>

    <div class="meter">
      <div class="row"><span class="label">{t('clusterWidgets.host.dataDisk')}</span><b>{pct(h.diskUsedPercent, 0)}</b></div>
      <div class="bar"><span class={level(h.diskUsedPercent, 80, 90)} style:width={width(h.diskUsedPercent)}></span></div>
      <div class="muted small">
        {#if h.diskTotalBytes != null}{t('clusterWidgets.host.disk.free', { free: bytes(h.diskFreeBytes), total: bytes(h.diskTotalBytes) })}{:else}{t('clusterWidgets.host.unavailable')}{/if}
        {#if h.qlogBytes != null}{' · '}{t('clusterWidgets.host.disk.qlog', { bytes: bytes(h.qlogBytes) })}{/if}
        {#if h.snapshotBytes != null}{' · '}{t('clusterWidgets.host.disk.lists', { bytes: bytes(h.snapshotBytes) })}{/if}
        {#if h.writeBytesPerSecond != null}{' · '}{t('clusterWidgets.host.disk.writes', { bytes: bytes(h.writeBytesPerSecond) })}{/if}
      </div>
      {#if line('diskUsedPercent')}<svg class="spark" viewBox="0 0 100 24" preserveAspectRatio="none" aria-hidden="true"><path d={line('diskUsedPercent')} /></svg>{/if}
    </div>
  </div>

  <dl class="facts small">
    {#if h.temperatureC != null}<dt>{t('clusterWidgets.host.fact.temperature')}</dt><dd class={h.temperatureC >= 80 ? 'bad-text' : h.temperatureC >= 70 ? 'warn-text' : ''}>{h.temperatureC.toFixed(1)} °C</dd>{/if}
    {#if h.processRssBytes != null}<dt>{t('clusterWidgets.host.fact.memory')}</dt><dd>{bytes(h.processRssBytes)}{#if h.threads != null}{' · '}{t('clusterWidgets.host.fact.threads', { n: h.threads })}{/if}</dd>{/if}
    {#if h.openFds != null}<dt>{t('clusterWidgets.host.fact.openFiles')}</dt><dd>{num(h.openFds)}{#if h.maxFds != null}{t('clusterWidgets.host.fact.of')}{num(h.maxFds)}{/if}</dd>{/if}
    {#if h.hostUptimeSeconds != null}<dt>{t('clusterWidgets.host.fact.machineUp')}</dt><dd>{duration(h.hostUptimeSeconds)}</dd>{/if}
    {#if h.clockOffsetMs != null}<dt>{t('clusterWidgets.host.fact.clock')}</dt><dd class={Math.abs(h.clockOffsetMs) >= 2000 ? 'bad-text' : ''}>{Math.abs(h.clockOffsetMs) < 50 ? t('clusterWidgets.host.fact.inStep') : t(h.clockOffsetMs > 0 ? 'clusterWidgets.host.fact.ahead' : 'clusterWidgets.host.fact.behind', { seconds: (h.clockOffsetMs / 1000).toFixed(1) })}</dd>{/if}
  </dl>
  {#if h.unavailable.length}
    <p class="muted small">{t('clusterWidgets.host.notAvailable', { list: h.unavailable.map((u) => (unavailable[u] ? t(unavailable[u]) : u)).join(', ') })}<HelpButton id="host-resources" /></p>
  {/if}
</article>

<style>
  .host {
    display: grid;
    gap: 12px;
    align-content: start;
  }
  header {
    display: flex;
    flex-wrap: wrap;
    align-items: baseline;
    gap: 4px 10px;
  }
  h3 {
    margin: 0;
    font-size: 15px;
  }
  .sys {
    flex-basis: 100%;
  }
  .warnings {
    margin: 0;
    padding: 8px 12px 8px 28px;
    border-radius: 10px;
    background: color-mix(in srgb, var(--bad) 10%, transparent);
    color: var(--bad-strong);
    font-size: 13px;
    font-weight: 600;
  }
  .meters {
    display: grid;
    gap: 14px;
  }
  .row {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
  }
  .label {
    font-size: 13px;
    color: var(--muted);
    font-weight: 600;
  }
  .row b {
    font-variant-numeric: tabular-nums;
  }
  .bar {
    height: 8px;
    margin: 4px 0;
    border-radius: 999px;
    background: var(--surface-2);
    overflow: hidden;
  }
  .bar span {
    display: block;
    height: 100%;
    border-radius: 999px;
    background: var(--accent);
  }
  .bar span.warn {
    background: var(--warn);
  }
  .bar span.bad {
    background: var(--bad);
  }
  .spark {
    width: 100%;
    height: 24px;
    margin-top: 4px;
  }
  .spark path {
    fill: none;
    stroke: var(--accent);
    stroke-width: 1.5;
    vector-effect: non-scaling-stroke;
    opacity: 0.8;
  }
  .facts {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 4px 14px;
    margin: 0;
  }
  .facts dt {
    color: var(--muted);
  }
  .facts dd {
    margin: 0;
  }
  .bad-text {
    color: var(--bad-strong);
    font-weight: 600;
  }
  .warn-text {
    color: var(--warn-strong);
  }
</style>
