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
  import { tr } from '../lib/i18n';
  import T from '../lib/i18n/T.svelte';
  const { t } = tr('groups');

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
      if (!m) throw new Error(t('"{line}": write the days and times like "weekdays 21:00-07:00"', { line }));
      out.push({ days: m[1].toLowerCase().split(',').filter(Boolean), start: m[2], end: m[3] });
    }
    if (!out.length) throw new Error(t('Add at least one window, like "weekdays 21:00-07:00".'));
    return out;
  }
  const scheduleFields = $derived<Field[]>([
    { key: 'action', label: t('During the windows'), type: 'select', options: ['block_all', 'enable_lists', 'block_services'], initial: 'block_all',
      help: t('block_all: a bedtime (everything blocked except quick allow rules and local names). enable_lists: extra lists apply. block_services: extra services are blocked.') },
    { key: 'window', label: t('Windows (one per line)'), type: 'lines', placeholder: t('weekdays 21:00-07:00\nsat,sun 23:00-08:00', undefined, 'an example of what the server reads: keep the English day names'),
      help: t('Days: mon … sun, weekdays, weekends, daily. An end before the start runs past midnight.'),
      toText: windowText, fromText: windowsFrom },
    { key: 'lists', label: t('Lists (enable_lists)'), type: 'multi', options: listNames },
    { key: 'services', label: t('Services (block_services)'), type: 'multi', options: services.map((s) => s.id) },
    { key: 'tz', label: t('Time zone'), type: 'text', placeholder: 'America/New_York', advanced: true,
      help: t('IANA time zone. Default: the node\u2019s.') },
  ]);
  const serviceName = (id: string) => services.find((s) => s.id === id)?.name ?? id;
  // The words of the cards and the settings rows are read once, here: language is fixed for the page.
  const words = { none: t('none'), every: t('every enabled list'), only: t('named devices only'), mixed: t('named devices and Kubernetes workloads'), rest: t('devices that match nothing else') };
  const rebinding = t('Rebinding protection on');
  const onNow = t('on now');
  const card = {
    safeOn: t('Safe search on'),
    safeNotYt: t('Safe search on (not YouTube)'),
    safeModerate: t('Safe search on (YouTube moderate)'),
    schedules: t('Schedules:'),
    rewrites: t('Rewrites:'),
    upstreams: t('Upstream servers:'),
    noV6: t('No IPv6 addresses (AAAA answered with nothing)'),
    queries: t('Queries (24 h)'),
    blocked: t('Blocked'),
    devices: t('Devices (this hour)'),
    topNames: t('Top names'),
    topBlocked: t('Top blocked'),
    nothingBlocked: t('nothing blocked'),
    workloads: t('Workloads:'),
    show: t("Show this group's queries"),
    on: t('on'),
  };

  // REQ: API-002 (T7.5) — add and change groups here.
  const groupFields = $derived<Field[]>([
    { key: 'networks', label: t('Networks'), type: 'lines', placeholder: '192.168.2.0/24',
      help: t('One per line. Every device on these networks belongs to the group.') },
    { key: 'lists', label: t('Lists'), type: 'multi', options: listNames,
      help: t('Leave all unticked on a new group to use every enabled list.') },
    // REQ: UPS-007 (T9.25)
    { key: 'upstreams', label: t('Upstream servers'), type: 'select', options: upstreamGroupNames,
      help: t('The upstream group this group’s questions go to. (default) uses the default group; routes for a domain still win.') },
    // REQ: FLT-011 (T7.11)
    { key: 'safe_search', label: t('Safe search'), type: 'bool',
      help: t('Google, Bing, DuckDuckGo, Yandex, and Pixabay show only safe results; YouTube uses Restricted Mode.') },
    { key: 'youtube_restrict', label: t('YouTube restriction'), type: 'select', options: ['strict', 'moderate', 'off'], advanced: true },
    // REQ: FLT-012 (T7.9)
    { key: 'blocked_services', label: t('Blocked services'), type: 'multi', options: services.map((s) => s.id),
      help: t('Block a whole service (all its domains) for this group, on top of its lists.') },
    // REQ: FLT-014 (T7.20), DNS-016 (T7.21) — answer filtering and DNS64 (T8.6).
    { key: 'rebinding_protection', label: t('Rebinding protection'), type: 'bool', advanced: true,
      help: t('Block answers from the internet that point at private addresses (DNS rebinding).') },
    { key: 'block_answer_ips', label: t('Block answers in'), type: 'lines', placeholder: '203.0.113.0/24', advanced: true,
      help: t('Answers with an address in these networks are blocked, whatever the name.') },
    { key: 'dns64', label: t('DNS64'), type: 'bool', advanced: true,
      help: t('Make IPv6 addresses for IPv4-only names, for IPv6-only networks with NAT64.') },
    { key: 'dns64_prefix', label: t('DNS64 prefix'), type: 'text', placeholder: '64:ff9b::/96', advanced: true },
    // REQ: DNS-016 (T9.10)
    { key: 'dns64_exclude', label: t('DNS64 exclusions'), type: 'lines', placeholder: '2001:db8:bad::/48', advanced: true,
      help: t('IPv6 addresses here count as missing (the name gets made-up ones); IPv4 addresses here are never made into IPv6.') },
    // REQ: FLT-016 (T12.5)
    { key: 'filter_aaaa', label: t('No IPv6 addresses'), type: 'bool', advanced: true,
      help: t('Answer IPv6 (AAAA) questions with nothing, so these devices use IPv4: for a network whose IPv6 is broken. Your own names still answer. Not with DNS64.') },
    // REQ: FLT-010 (T9.7)
    { key: 'schedules', label: t('Schedules'), type: 'multi', options: scheduleNames,
      help: t('Schedules this group follows (make them under Schedules, below).') },
    { key: 'block_mode', label: t('Blocked answer'), type: 'select', options: ['null_ip', 'nxdomain', 'nodata', 'refused', 'custom_ip'], advanced: true },
    { key: 'priority', label: t('Priority'), type: 'number', placeholder: '0', advanced: true,
      help: t('When a device matches several groups, the highest priority wins.') },
    { key: 'color', label: t('Color'), type: 'text', placeholder: t('#4f8cff'), advanced: true },
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

{#snippet mono(x: string)}<span class="mono" translate="no">{x}</span>{/snippet}

<div class="page">
  <h1>{t('Groups')}<HelpButton id="groups" /></h1>
  <ErrorNote {error} />
  <p class="muted small">
    {t('A group is a kind of device: every device on a group\'s networks belongs to it (a named device can also be put in a group of its own). Groups decide which lists apply and show what each kind of device does.')}
  </p>

  <div class="group-grid">
    {#each groups as g (g.name)}
      <section class="card group" data-testid="group-card" style:--gc={g.color}>
        <div class="card-head">
          <h2 translate="no">{g.name}</h2>
          {#if g.pausedUntilUnixSeconds}
            <span class="badge warn">{t('paused until {when}', { when: dateTime(g.pausedUntilUnixSeconds) })}</span>
          {/if}
        </div>
        <div class="muted small mono">
          {g.networks.length
            ? g.networks.join(', ')
            : g.name === 'default'
              ? words.rest
              : workloadsIn(g.name).length
                ? words.mixed
                : words.only}
        </div>
        {#if g.safeSearch}
          <div class="small" data-testid="group-safe-search">
            {g.youtubeRestrict === 'off' ? card.safeNotYt : g.youtubeRestrict === 'moderate' ? card.safeModerate : card.safeOn}<HelpButton id="safe-search" />
          </div>
        {/if}
        {#if g.schedules.length}
          <div class="small" data-testid="group-schedules">
            {card.schedules} {#each g.schedules as s, i (s)}{i ? ', ' : ''}<span translate="no">{s}</span>{#if g.schedulesOn.includes(s)}
                <span class="badge warn">{onNow}</span>{/if}{/each}<HelpButton id="schedules" />
          </div>
        {/if}
        {#if g.blockedServices.length}
          <div class="small" data-testid="group-services">
            {t('Blocks {services}', { services: g.blockedServices.map(serviceName).join(', ') })}<HelpButton id="blocked-services" />
          </div>
        {/if}
        <!-- REQ: FLT-014, FLT-015 (T7.20), DNS-016 (T7.21) — shown since T8.6. -->
        {#if g.rebindingProtection || g.blockAnswerIps.length}
          <div class="small" data-testid="group-answers">
            {[
              g.rebindingProtection ? rebinding : '',
              g.blockAnswerIps.length ? t('blocks answers in {networks}', { networks: g.blockAnswerIps.join(', ') }) : '',
            ]
              .filter(Boolean)
              .join('; ')}<HelpButton id="rebinding" />
          </div>
        {/if}
        {#if g.rewrites.length}
          <div class="small" data-testid="group-rewrites">
            {card.rewrites} {#each g.rewrites as r, i (r.domain)}{i ? ', ' : ''}<span class="mono" translate="no">{r.domain} → {r.answer}</span>{/each}<HelpButton id="rewrites" />
          </div>
        {/if}
        {#if g.upstreams}
          <div class="small" data-testid="group-upstreams">
            {card.upstreams} <span class="mono" translate="no">{g.upstreams}</span>
          </div>
        {/if}
        {#if g.dns64}
          <div class="small" data-testid="group-dns64">
            <T ctx="groups" msg={'DNS64 on (<mono>{prefix}</mono>)'} params={{ prefix: g.dns64Prefix ?? '64:ff9b::/96' }} {mono} /><HelpButton id="dns64" />
          </div>
        {/if}
        {#if g.filterAaaa}
          <div class="small" data-testid="group-filter-aaaa">{card.noV6}<HelpButton id="filter-aaaa" /></div>
        {/if}
        <dl class="stats">
          <div><dt>{card.queries}</dt><dd>{num(g.queries24h)}{#if total}<span class="muted small"> · {pct((g.queries24h / total) * 100, 0)}</span>{/if}</dd></div>
          <div><dt>{card.blocked}</dt><dd>{g.queries24h ? pct((g.blocked24h / g.queries24h) * 100) : '–'}</dd></div>
          <div><dt>{card.devices}</dt><dd>{num(g.devicesThisHour)}</dd></div>
        </dl>
        {#if tops[g.name]}
          <div class="tops small">
            <div>
              <div class="muted">{card.topNames}</div>
              <ol>{#each tops[g.name].domains as top (top.key)}<li class="mono" translate="no">{top.key} <span class="muted">{num(top.count)}</span></li>{/each}</ol>
            </div>
            <div>
              <div class="muted">{card.topBlocked}</div>
              {#if tops[g.name].blocked.length}
                <ol>{#each tops[g.name].blocked as top (top.key)}<li class="mono" translate="no">{top.key} <span class="muted">{num(top.count)}</span></li>{/each}</ol>
              {:else}<span class="muted">{card.nothingBlocked}</span>{/if}
            </div>
          </div>
        {/if}
        <!-- REQ: FLT-017 — the Kubernetes workloads in the group, with their glyph. -->
        {#if workloadsIn(g.name).length}
          <div class="small workloads" data-testid="group-workloads">
            <span class="muted">{card.workloads}</span>
            {#each workloadsIn(g.name).slice(0, 8) as w (w.name)}<span class="wl"><ClientChip ip={w.key} name={w.name} /></span>{/each}
            {#if workloadsIn(g.name).length > 8}<a href={href('/clients', { tab: 'workloads' })}>{t('and {n} more', { n: workloadsIn(g.name).length - 8 })}</a>{/if}
          </div>
        {/if}
        <a class="small" href={href('/queries', { group: g.name })}>{card.show}</a>
      </section>
    {/each}
  </div>

  <section class="card">
    <h2>{t('Settings')}</h2>
    <div class="table-wrap">
      <table>
        <thead><tr><th>{t('Group')}</th><th class="num">{t('Priority')}</th><th>{t('Lists')}<HelpButton id="lists" /></th>{#if advanced}<th>{t('Blocked answer')}</th>{/if}<th>{t('Blocking')}</th></tr></thead>
        <tbody>
          {#each groups as g (g.name)}
            <tr>
              <td><strong translate="no">{g.name}</strong></td>
              <td class="num">{g.priority}</td>
              <td>{g.lists ? g.lists.join(', ') || words.none : words.every}</td>
              {#if advanced}<td>{t('{mode} · TTL {ttl} s', { mode: g.blockMode, ttl: g.blockTtlSeconds })}</td>{/if}
              <td>
                {#if g.pausedUntilUnixSeconds}
                  <span class="badge warn">{t('paused until {when}', { when: dateTime(g.pausedUntilUnixSeconds) })}</span>
                {:else}
                  <span class="badge ok">{card.on}</span>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  </section>
  <ConfigEditor kind="group" path="groups" title={t('Manage groups')} noun={t('group')} fields={groupFields}
    summary={(d) => `${((d.networks as string[]) ?? []).join(', ') || words.only} · ${d.lists ? t('{n} lists', { n: (d.lists as string[]).length }) : words.every}`}
    onchanged={load} />
  <!-- REQ: FLT-010 (T9.7) — schedules made here; groups follow them through `schedules`. -->
  <ConfigEditor kind="schedule" path="schedules" title={t('Schedules')} noun={t('schedule')} help="schedules" fields={scheduleFields}
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
