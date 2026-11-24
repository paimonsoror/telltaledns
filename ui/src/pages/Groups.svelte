<script lang="ts">
  // REQ: API-005, FLT-005 (ADR-050) — groups as categories of devices: each group's networks,
  // what its devices did in the last 24 hours, its heaviest names this hour, and its settings.
  import { api, type S } from '../lib/api';
  import { href } from '../lib/router.svelte';
  import { dateTime, num, pct } from '../lib/format';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import { currentMode } from '../lib/mode.svelte';
  import ConfigEditor, { type Field } from '../lib/components/ConfigEditor.svelte';
  import ClientChip from '../lib/components/ClientChip.svelte';
  import { loadWorkloads, workloads } from '../lib/workloads.svelte';
  import { t, tn } from '../lib/i18n';

  // REQ: FLT-017 — the workloads a group holds (the default group: those without one).
  const workloadsIn = (group: string) =>
    workloads.items.filter((w) => (w.group ?? 'default') === group);
  $effect(() => {
    void loadWorkloads();
  });

  let groups = $state<S['GroupInfo'][]>([]);
  let tops = $state<Record<string, { domains: S['TopItem'][]; blocked: S['TopItem'][] }>>({});
  let error = $state<unknown>(null);
  let listNames = $state<string[]>([]);
  let services = $state<S['ServiceInfo'][]>([]);
  // REQ: FLT-010 (T9.7) — schedules, edited below the groups.
  let scheduleNames = $state<string[]>([]);
  let upstreamGroupNames = $state<string[]>([]);
  type Window = { days: string[]; start: string; end: string };
  const windowText = (v: unknown) =>
    ((v as Window[] | undefined) ?? []).map((w) => `${w.days.join(',')} ${w.start}-${w.end}`).join('\n');
  function windowsFrom(s: string): Window[] {
    const out: Window[] = [];
    for (const line of s.split('\n').map((x) => x.trim()).filter(Boolean)) {
      const m = /^([a-z,]+)\s+(\d{1,2}:\d{2})\s*-\s*(\d{1,2}:\d{2})$/i.exec(line);
      if (!m) throw new Error(t('groups.schedule.errLine', { line }));
      out.push({ days: m[1].toLowerCase().split(',').filter(Boolean), start: m[2], end: m[3] });
    }
    if (!out.length) throw new Error(t('groups.schedule.errEmpty'));
    return out;
  }
  const scheduleFields = $derived<Field[]>([
    { key: 'action', label: t('groups.schedule.action'), type: 'select', options: ['block_all', 'enable_lists', 'block_services'], initial: 'block_all',
      help: t('groups.schedule.actionHelp') },
    { key: 'window', label: t('groups.schedule.window'), type: 'lines', placeholder: 'weekdays 21:00-07:00\nsat,sun 23:00-08:00',
      help: t('groups.schedule.windowHelp'),
      toText: windowText, fromText: windowsFrom },
    { key: 'lists', label: t('groups.schedule.lists'), type: 'multi', options: listNames },
    { key: 'services', label: t('groups.schedule.services'), type: 'multi', options: services.map((s) => s.id) },
    { key: 'tz', label: t('groups.schedule.tz'), type: 'text', placeholder: 'America/New_York', advanced: true,
      help: t('groups.schedule.tzHelp') },
  ]);
  const serviceName = (id: string) => services.find((s) => s.id === id)?.name ?? id;

  // REQ: API-002 (T7.5) — add and change groups here.
  const groupFields = $derived<Field[]>([
    { key: 'networks', label: t('groups.field.networks'), type: 'lines', placeholder: '192.168.2.0/24',
      help: t('groups.field.networksHelp') },
    { key: 'lists', label: t('nav.lists'), type: 'multi', options: listNames,
      help: t('groups.field.listsHelp') },
    // REQ: UPS-007 (T9.25)
    { key: 'upstreams', label: t('groups.field.upstreams'), type: 'select', options: upstreamGroupNames,
      help: t('groups.field.upstreamsHelp') },
    // REQ: FLT-011 (T7.11)
    { key: 'safe_search', label: t('groups.field.safeSearch'), type: 'bool',
      help: t('groups.field.safeSearchHelp') },
    { key: 'youtube_restrict', label: t('groups.field.youtube'), type: 'select', options: ['strict', 'moderate', 'off'], advanced: true },
    // REQ: FLT-012 (T7.9)
    { key: 'blocked_services', label: t('groups.field.blockedServices'), type: 'multi', options: services.map((s) => s.id),
      help: t('groups.field.blockedServicesHelp') },
    // REQ: FLT-014 (T7.20), DNS-016 (T7.21) — answer filtering and DNS64 (T8.6).
    { key: 'rebinding_protection', label: t('groups.field.rebinding'), type: 'bool', advanced: true,
      help: t('groups.field.rebindingHelp') },
    { key: 'block_answer_ips', label: t('groups.field.blockAnswerIps'), type: 'lines', placeholder: '203.0.113.0/24', advanced: true,
      help: t('groups.field.blockAnswerIpsHelp') },
    { key: 'dns64', label: t('groups.field.dns64'), type: 'bool', advanced: true,
      help: t('groups.field.dns64Help') },
    { key: 'dns64_prefix', label: t('groups.field.dns64Prefix'), type: 'text', placeholder: '64:ff9b::/96', advanced: true },
    // REQ: DNS-016 (T9.10)
    { key: 'dns64_exclude', label: t('groups.field.dns64Exclude'), type: 'lines', placeholder: '2001:db8:bad::/48', advanced: true,
      help: t('groups.field.dns64ExcludeHelp') },
    // REQ: FLT-016 (T12.5)
    { key: 'filter_aaaa', label: t('groups.field.filterAaaa'), type: 'bool', advanced: true,
      help: t('groups.field.filterAaaaHelp') },
    // REQ: FLT-010 (T9.7)
    { key: 'schedules', label: t('groups.schedule.title'), type: 'multi', options: scheduleNames,
      help: t('groups.field.schedulesHelp') },
    { key: 'block_mode', label: t('groups.field.blockMode'), type: 'select', options: ['null_ip', 'nxdomain', 'nodata', 'refused', 'custom_ip'], advanced: true },
    { key: 'priority', label: t('groups.col.priority'), type: 'number', placeholder: '0', advanced: true,
      help: t('groups.field.priorityHelp') },
    { key: 'color', label: t('groups.field.color'), type: 'text', placeholder: '#4f8cff', advanced: true },
  ]);

  function load() {
    api.lists().then((l) => (listNames = l.items.map((x) => x.name))).catch(() => {});
    api.services().then((s) => (services = s.items)).catch(() => {});
    api
      .configEntries('upstream_group')
      .then((e) => (upstreamGroupNames = e.items.filter((x) => x.source !== 'hidden').map((x) => x.name)))
      .catch(() => {});
    api
      .configEntries('schedule')
      .then((e) => (scheduleNames = e.items.filter((x) => x.source !== 'hidden').map((x) => x.name)))
      .catch(() => {});
    api
      .groups()
      .then(async (g) => {
        groups = g.items;
        const entries = await Promise.all(
          g.items
            .filter((x) => x.queries24h > 0)
            .map(async (x) => {
              const [d, b] = await Promise.all([api.top('domains', 5, undefined, x.name), api.top('blocked', 5, undefined, x.name)]);
              return [x.name, { domains: d.items, blocked: b.items }] as const;
            }),
        );
        tops = Object.fromEntries(entries);
      })
      .catch((e) => (error = e));
  }
  $effect(load);
  const advanced = $derived(currentMode() === 'advanced');
  const total = $derived(groups.reduce((a, g) => a + g.queries24h, 0));
</script>

<div class="page">
  <h1>{t('nav.groups')}<HelpButton id="groups" /></h1>
  <ErrorNote {error} />
  <p class="muted small">
    {t('groups.intro')}
  </p>

  <div class="group-grid">
    {#each groups as g (g.name)}
      <section class="card group" data-testid="group-card" style:--gc={g.color}>
        <div class="card-head">
          <h2>{g.name}</h2>
          {#if g.pausedUntilUnixSeconds}
            <span class="badge warn">{t('groups.pausedUntil', { time: dateTime(g.pausedUntilUnixSeconds) })}</span>
          {/if}
        </div>
        <div class="muted small mono">
          {g.networks.length
            ? g.networks.join(', ')
            : g.name === 'default'
              ? t('groups.devices.default')
              : workloadsIn(g.name).length
                ? t('groups.devices.namedAndWorkloads')
                : t('groups.devices.namedOnly')}
        </div>
        {#if g.safeSearch}
          <div class="small" data-testid="group-safe-search">
            {t('groups.safeSearch')}{g.youtubeRestrict === 'off' ? t('groups.safeSearch.notYouTube') : g.youtubeRestrict === 'moderate' ? t('groups.safeSearch.youtubeModerate') : ''}<HelpButton id="safe-search" />
          </div>
        {/if}
        {#if g.schedules.length}
          <div class="small" data-testid="group-schedules">
            {t('groups.schedulesLabel')} {#each g.schedules as s, i (s)}{i ? ', ' : ''}{s}{#if g.schedulesOn.includes(s)}
                <span class="badge warn">{t('groups.schedules.onNow')}</span>{/if}{/each}<HelpButton id="schedules" />
          </div>
        {/if}
        {#if g.blockedServices.length}
          <div class="small" data-testid="group-services">
            {t('groups.blocks', { services: g.blockedServices.map(serviceName).join(', ') })}<HelpButton id="blocked-services" />
          </div>
        {/if}
        <!-- REQ: FLT-014, FLT-015 (T7.20), DNS-016 (T7.21) — shown since T8.6. -->
        {#if g.rebindingProtection || g.blockAnswerIps.length}
          <div class="small" data-testid="group-answers">
            {[
              g.rebindingProtection ? t('groups.answers.rebinding') : '',
              g.blockAnswerIps.length ? t('groups.answers.blockIps', { networks: g.blockAnswerIps.join(', ') }) : '',
            ]
              .filter(Boolean)
              .join('; ')}<HelpButton id="rebinding" />
          </div>
        {/if}
        {#if g.rewrites.length}
          <div class="small" data-testid="group-rewrites">
            {t('groups.rewritesLabel')} {#each g.rewrites as r, i (r.domain)}{i ? ', ' : ''}<span class="mono">{r.domain} → {r.answer}</span>{/each}<HelpButton id="rewrites" />
          </div>
        {/if}
        {#if g.upstreams}
          <div class="small" data-testid="group-upstreams">
            {t('groups.upstreamsLabel')} <span class="mono">{g.upstreams}</span>
          </div>
        {/if}
        {#if g.dns64}
          <div class="small" data-testid="group-dns64">
            {t('groups.dns64OnStart')}<span class="mono">{g.dns64Prefix ?? '64:ff9b::/96'}</span>{t('groups.dns64OnEnd')}<HelpButton id="dns64" />
          </div>
        {/if}
        {#if g.filterAaaa}
          <div class="small" data-testid="group-filter-aaaa">{t('groups.filterAaaa')}<HelpButton id="filter-aaaa" /></div>
        {/if}
        <dl class="stats">
          <div><dt>{t('groups.stat.queries')}</dt><dd>{num(g.queries24h)}{#if total}<span class="muted small"> · {pct((g.queries24h / total) * 100, 0)}</span>{/if}</dd></div>
          <div><dt>{t('legacy.blocked')}</dt><dd>{g.queries24h ? pct((g.blocked24h / g.queries24h) * 100) : '–'}</dd></div>
          <div><dt>{t('groups.stat.devices')}</dt><dd>{num(g.devicesThisHour)}</dd></div>
        </dl>
        {#if tops[g.name]}
          <div class="tops small">
            <div>
              <div class="muted">{t('groups.top.names')}</div>
              <ol>{#each tops[g.name].domains as t (t.key)}<li class="mono">{t.key} <span class="muted">{num(t.count)}</span></li>{/each}</ol>
            </div>
            <div>
              <div class="muted">{t('legacy.topBlocked')}</div>
              {#if tops[g.name].blocked.length}
                <ol>{#each tops[g.name].blocked as t (t.key)}<li class="mono">{t.key} <span class="muted">{num(t.count)}</span></li>{/each}</ol>
              {:else}<span class="muted">{t('groups.top.nothingBlocked')}</span>{/if}
            </div>
          </div>
        {/if}
        <!-- REQ: FLT-017 — the Kubernetes workloads in the group, with their glyph. -->
        {#if workloadsIn(g.name).length}
          <div class="small workloads" data-testid="group-workloads">
            <span class="muted">{t('groups.workloadsLabel')}</span>
            {#each workloadsIn(g.name).slice(0, 8) as w (w.name)}<span class="wl"><ClientChip ip={w.key} name={w.name} /></span>{/each}
            {#if workloadsIn(g.name).length > 8}<a href={href('/clients', { tab: 'workloads' })}>{tn('groups.workloads.more', workloadsIn(g.name).length - 8)}</a>{/if}
          </div>
        {/if}
        <a class="small" href={href('/queries', { group: g.name })}>{t('groups.showQueries')}</a>
      </section>
    {/each}
  </div>

  <section class="card">
    <h2>{t('nav.settings')}</h2>
    <div class="table-wrap">
      <table>
        <thead><tr><th>{t('legacy.group')}</th><th class="num">{t('groups.col.priority')}</th><th>{t('nav.lists')}<HelpButton id="lists" /></th>{#if advanced}<th>{t('groups.field.blockMode')}</th>{/if}<th>{t('groups.col.blocking')}</th></tr></thead>
        <tbody>
          {#each groups as g (g.name)}
            <tr>
              <td><strong>{g.name}</strong></td>
              <td class="num">{g.priority}</td>
              <td>{g.lists ? g.lists.join(', ') || t('groups.lists.none') : t('groups.lists.everyEnabled')}</td>
              {#if advanced}<td>{g.blockMode} · {t('groups.blockTtl', { seconds: g.blockTtlSeconds })}</td>{/if}
              <td>
                {#if g.pausedUntilUnixSeconds}
                  <span class="badge warn">{t('groups.pausedUntil', { time: dateTime(g.pausedUntilUnixSeconds) })}</span>
                {:else}
                  <span class="badge ok">{t('settings.value.on')}</span>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  </section>
  <ConfigEditor kind="group" path="groups" title={t('groups.manage.title')} noun={t('groups.manage.noun')} fields={groupFields}
    summary={(d) => `${((d.networks as string[]) ?? []).join(', ') || t('groups.devices.namedOnly')} · ${d.lists ? tn('groups.manage.lists', (d.lists as string[]).length) : t('groups.lists.everyEnabled')}`}
    onchanged={load} />
  <!-- REQ: FLT-010 (T9.7) — schedules made here; groups follow them through `schedules`. -->
  <ConfigEditor kind="schedule" path="schedules" title={t('groups.schedule.title')} noun={t('groups.schedule.noun')} help="schedules" fields={scheduleFields}
    summary={(d) => `${String(d.action ?? '')}: ${((d.window as { days: string[]; start: string; end: string }[]) ?? []).map((w) => `${w.days.join(',')} ${w.start}-${w.end}`).join('; ')}`}
    onchanged={load} />
</div>

<style>
  .workloads {
    display: flex;
    flex-wrap: wrap;
    gap: 4px 10px;
    align-items: baseline;
  }
  .group-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 16px;
    margin-bottom: 16px;
  }
  .group {
    margin: 0;
  }
  /* T6.8 — the title's accent bar carries the group's color. */
  .group h2::before {
    background: var(--gc);
    width: 4px;
  }
  .stats {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 8px;
    margin: 12px 0;
  }
  .stats dt {
    color: var(--muted);
    font-size: 0.8em;
  }
  .stats dd {
    margin: 0;
    font-size: 1.35em;
    font-weight: 650;
    font-variant-numeric: tabular-nums;
  }
  .tops {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
    margin-bottom: 8px;
  }
  .tops > div {
    min-width: 0;
  }
  .tops ol {
    margin: 4px 0 0;
    padding-left: 18px;
  }
  .tops li {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
</style>
