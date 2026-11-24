<script lang="ts">
  // REQ: API-005, FLT-004 — filter lists with their download state.
  import { api, type S } from '../lib/api';
  import { ago, bytes, num } from '../lib/format';
  import { poll } from '../lib/poll';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import StatusBadge from '../lib/components/StatusBadge.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import ShareBar from '../lib/components/ShareBar.svelte';
  import { currentMode } from '../lib/mode.svelte';
  import ConfigEditor, { type Field } from '../lib/components/ConfigEditor.svelte';
  import { t, tn } from '../lib/i18n';

  // REQ: API-002 (T7.5) — add and change lists here.
  const listFields = $derived<Field[]>([
    { key: 'url', label: t('lists.field.download'), type: 'text', placeholder: t('lists.field.downloadPlaceholder'),
      help: t('lists.field.downloadHelp') },
    { key: 'rules', label: t('alerts.rule.title'), type: 'lines', placeholder: t('lists.field.rulesPlaceholder') },
    { key: 'kind', label: t('lists.col.kind'), type: 'select', options: ['block', 'allow'], initial: 'block' },
    { key: 'match', label: t('lists.field.match'), type: 'select', options: ['subtree', 'exact'], advanced: true,
      help: t('lists.field.matchHelp') },
    { key: 'enabled', label: t('lists.field.enabled'), type: 'bool', initial: true },
    // REQ: OBS-018 — try a list before it blocks anything.
    { key: 'mode', label: t('lists.field.mode'), type: 'select', options: ['enforce', 'shadow'], initial: 'enforce',
      help: t('lists.field.modeHelp') },
    { key: 'refresh_secs', label: t('lists.field.refresh'), type: 'number', placeholder: t('lists.field.refreshPlaceholder'), advanced: true },
  ]);

  let lists = $state<S['ListInfo'][]>([]);
  let info = $state<S['SystemInfo'] | null>(null);
  // REQ: OBS-018 — what shadow lists would have blocked, and likely over-blocking.
  let shadow = $state<S['ShadowListStats'][]>([]);
  let suspects = $state<S['OverblockSuspect'][]>([]);
  let error = $state<unknown>(null);
  // Until the first answer, the table isn't "empty": it's loading.
  let loaded = $state(false);

  $effect(() =>
    poll(async () => {
      try {
        const [l, i, sh, ob] = await Promise.all([
          api.lists(),
          api.info(),
          api.shadowLists().catch(() => ({ items: [] as S['ShadowListStats'][] })),
          api.overblocking(20).catch(() => ({ items: [] as S['OverblockSuspect'][] })),
        ]);
        lists = l.items;
        info = i;
        shadow = sh.items;
        suspects = ob.items;
        loaded = true;
        error = null;
      } catch (e) {
        error = e;
      }
    }, 15000),
  );
  const advanced = $derived(currentMode() === 'advanced');
  // REQ: API-002 (T9.12) — download and parse the draft list before saving it.
  const tryList = $derived({
    label: t('lists.test.label'),
    run: async (b: Record<string, unknown>) => {
      const r = await api.checkList(b);
      const notes = r.warnings.length ? t('lists.test.badLines', { lines: r.warnings.slice(0, 3).join('; ') }) : '';
      return r.ok
        ? { ok: true, text: t('lists.test.works', { detail: r.detail, ms: r.elapsedMs, notes }) }
        : { ok: false, text: t('lists.test.fails', { detail: r.error ?? r.detail, notes }) };
    },
  });
</script>

<div class="page">
  <div class="page-head">
    <h1>{t('nav.lists')}<HelpButton id="lists" /></h1>
    {#if info}
      <span class="muted">
        {tn('lists.snapshotBlocked', info.filterNames, { n: num(info.filterNames), snapshot: info.filterSnapshot ?? '–' })}
      </span>
    {/if}
  </div>
  <ErrorNote {error} />
  <section class="card">
    {#if !loaded}
      <p class="empty muted">{t('common.loading')}</p>
    {:else if lists.length === 0}
      <p class="empty">{t('lists.emptyStart')}<code>[[list]]</code>{t('lists.emptyEnd')}</p>
    {:else}
      <div class="table-wrap">
        <table>
          <thead>
            <tr><th>{t('lists.col.list')}</th><th>{t('lists.col.kind')}<HelpButton id="list-kind" /></th><th>{t('lists.col.state')}<HelpButton id="list-refresh" /></th><th class="num">{t('lists.col.namesUsed')}</th><th class="num">{t('lists.col.unique')}<HelpButton id="list-overlap" /></th><th class="num">{t('qw.cache.hits')}</th>{#if advanced}<th class="num">{t('lists.col.lines')}</th><th class="num">{t('lists.col.size')}</th>{/if}<th>{t('lists.col.checked')}</th><th>{t('lists.col.changed')}</th></tr>
          </thead>
          <tbody>
            {#each lists as l (l.name)}
              <tr class:off={!l.enabled}>
                <td>
                  <strong>{l.name}</strong>{#if !l.enabled} <span class="badge">{t('lists.badge.off')}</span>{/if}{#if l.mode === 'shadow'} <span class="badge info" title={t('lists.badge.shadowTitle')}>{t('qw.explain.shadow')}</span>{/if}
                  {#if advanced}<div class="muted small src">{l.source}</div>{/if}
                  {#if l.error}<div class="small err">{l.error}</div>{/if}
                  <!-- REQ: FLT-003 (review 02-08) — regex rules the snapshot leaves out. -->
                  {#if l.regexSkipped > 0}<div class="small warn-text" data-testid="list-regex-skipped">{tn('lists.regexSkippedStart', l.regexSkipped, { n: num(l.regexSkipped) })}<code>max_regexes</code>{t('lists.regexSkippedEnd')}</div>{/if}
                </td>
                <td><span class="badge {l.kind === 'allow' ? 'ok' : 'bad'}">{l.kind}</span></td>
                <td>
                  <StatusBadge value={l.state} />
                  <!-- REQ: OBS-023 — downloads fine, but its content stopped changing. -->
                  {#if l.staleDays}<div class="small warn-text" data-testid="list-stale" title={t('lists.staleTitle')}>{tn('lists.stale', l.staleDays)}</div>{/if}
                </td>
                <td class="num">{num(l.entries)}{#if info?.filterNames && l.kind !== 'allow'}<ShareBar value={(l.entries / info.filterNames) * 100} color="--s-blocked" label={t('lists.shareLabel')} />{/if}</td>
                <!-- REQ: OBS-009 (T7.14) — unique contribution, overlap, hits. -->
                <td class="num" data-testid="list-unique">
                  {num(l.unique)}
                  {#if l.entries > 0 && l.overlap.length && l.overlap[0].names / l.entries >= 0.95}
                    <div class="small warn-text">{t('lists.overlapShare', { pct: Math.round((l.overlap[0].names / l.entries) * 100), list: l.overlap[0].list })}</div>
                  {/if}
                </td>
                <td class="num">{num(l.hits)}{#if l.state === 'ok' && l.entries > 0 && l.hits === 0}<div class="small muted">{t('lists.noneYet')}</div>{/if}</td>
                {#if advanced}
                  <td class="num">{num(l.lines)}</td>
                  <td class="num">{bytes(l.bytes)}</td>
                {/if}
                <td class="small">{ago(l.lastCheckedUnixSeconds)}</td>
                <td class="small">{ago(l.lastChangedUnixSeconds)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>
  {#if shadow.length}
    <!-- REQ: OBS-018 (ADR-109) — what a list would do before it does it. -->
    <section class="card" data-testid="shadow-lists">
      <h2>{t('lists.shadow.title')}<HelpButton id="shadow-lists" /></h2>
      {#each shadow as s (s.list)}
        <div class="shadow-list">
          <div class="row">
            <strong>{s.list}</strong>
            <span class="muted small">
              {t('lists.shadow.counts', { queries: tn('lists.shadow.queries', s.hits, { n: num(s.hits) }), devices: tn('lists.shadow.devices', s.devices, { n: num(s.devices) }) })}{#if s.since}{t('lists.shadow.since', { when: ago(Date.parse(s.since) / 1000) })}{/if}{#if s.lastHitAt}{t('lists.shadow.last', { when: ago(Date.parse(s.lastHitAt) / 1000) })}{/if}
            </span>
          </div>
          {#if s.topNames.length}
            <div class="small names">{#each s.topNames.slice(0, 10) as n (n.name)}<span class="name mono">{n.name} <span class="muted">{num(n.count)}</span></span>{/each}</div>
          {:else}
            <p class="muted small">{t('lists.shadow.empty')}</p>
          {/if}
        </div>
      {/each}
      <p class="muted small">{t('lists.shadow.noteStart')}<strong>enforce</strong>{t('queries.whyEnd')}</p>
    </section>
  {/if}
  {#if suspects.length}
    <!-- REQ: OBS-018 — blocked names someone seems to want. -->
    <section class="card" data-testid="overblocking">
      <h2>{t('lists.overblocking.title')}<HelpButton id="overblocking" /></h2>
      <div class="table-wrap">
        <table class="compact">
          <thead><tr><th>{t('clients.col.name')}</th><th>{t('lists.overblocking.col.blockedBy')}</th><th class="num">{t('lists.overblocking.col.allowedAfter')}</th><th class="num">{t('lists.overblocking.col.retries')}</th><th class="num">{t('lists.overblocking.col.devices')}</th><th>{t('lists.overblocking.col.last')}</th></tr></thead>
          <tbody>
            {#each suspects as s (s.name)}
              <tr>
                <td class="mono">{s.name}</td>
                <td class="small">{s.lists.join(', ')}</td>
                <td class="num">{num(s.allowedAfterBlock)}</td>
                <td class="num">{num(s.retryBursts)}</td>
                <td class="num">{num(s.devices)}</td>
                <td class="small">{ago(Date.parse(s.lastSeen) / 1000)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      <p class="muted small">{t('lists.overblocking.note')}</p>
    </section>
  {/if}
  <ConfigEditor kind="list" path="lists" title={t('lists.manage.title')} noun={t('lists.manage.noun')} fields={listFields}
    summary={(d) => `${String(d.kind ?? 'block')} · ${d.url ? String(d.url) : tn('lists.manage.rules', ((d.rules as string[]) ?? []).length)}${d.enabled === false ? t('lists.manage.summaryOff') : ''}`}
    onchanged={async () => (lists = (await api.lists()).items)} formAction={tryList} />
  <p class="muted small">{t('lists.footNote')}</p>
</div>

<style>
  .src {
    word-break: break-all;
    max-width: 420px;
  }
  .err {
    color: var(--bad);
  }
  .warn-text {
    color: var(--warn);
  }
  tr.off {
    opacity: 0.6;
  }
  .shadow-list {
    display: grid;
    gap: 4px;
    margin-bottom: 12px;
  }
  .names {
    display: flex;
    flex-wrap: wrap;
    gap: 4px 12px;
  }
  .name {
    word-break: break-all;
  }
</style>
