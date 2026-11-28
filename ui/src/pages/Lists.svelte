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
  import { tr } from '../lib/i18n';
  import T from '../lib/i18n/T.svelte';
  const { t } = tr('lists');

  // REQ: API-002 (T7.5) — add and change lists here.
  const listFields: Field[] = [
    { key: 'url', label: t('Download from'), type: 'text', placeholder: 'https://example.org/hosts.txt',
      help: t('Hosts files, plain domain lists, and Adblock-style lists all work. Or leave this empty and write the rules below.') },
    { key: 'rules', label: t('Rules'), type: 'lines', placeholder: t('ads.example.com, ||tracker.example^ (one per line)') },
    { key: 'kind', label: t('Kind'), type: 'select', options: ['block', 'allow'], initial: 'block' },
    { key: 'match', label: t('Plain names match'), type: 'select', options: ['subtree', 'exact'], advanced: true,
      help: t('subtree: the name and everything below it. exact: only the name itself.') },
    { key: 'enabled', label: t('On'), type: 'bool', initial: true },
    // REQ: OBS-018 — try a list before it blocks anything.
    { key: 'mode', label: t('Mode'), type: 'select', options: ['enforce', 'shadow'], initial: 'enforce',
      help: t('enforce: it blocks. shadow: it never blocks; the page shows what it would have blocked, so you can judge it first.') },
    { key: 'refresh_secs', label: t('Check for updates every (seconds)'), type: 'number', placeholder: '86400', advanced: true },
  ];

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
  // The words of the rows are read once, here: language is fixed for the life of the page.
  const words = {
    off: t('off'),
    shadow: t('shadow'),
    shadowTip: t('Never blocks: what it would have blocked is counted below'),
    staleTip: t('Its source may be abandoned while still answering'),
    noneYet: t('none yet'),
    shareLabel: t('share of the blocked names in the snapshot'),
    nothingYet: t("Nothing yet: it hasn't matched anything your devices asked for."),
  };
  // REQ: API-002 (T9.12) — download and parse the draft list before saving it.
  const tryList = {
    label: t('Test it'),
    run: async (b: Record<string, unknown>) => {
      const r = await api.checkList(b);
      const notes = r.warnings.length ? ` ${t("Lines it can't use: {lines}", { lines: r.warnings.slice(0, 3).join('; ') })}` : '';
      return r.ok
        ? { ok: true, text: t('Works: {detail}, in {ms} ms.{notes}', { detail: r.detail, ms: r.elapsedMs, notes }) }
        : { ok: false, text: t("Doesn't work: {error}.{notes}", { error: r.error ?? r.detail, notes }) };
    },
  };
</script>

{#snippet listentry()}<code translate="no">[[list]]</code>{/snippet}
{#snippet maxregexes()}<code translate="no">max_regexes</code>{/snippet}
{#snippet enforce()}<strong translate="no">enforce</strong>{/snippet}

<div class="page">
  <div class="page-head">
    <h1>{t('Lists')}<HelpButton id="lists" /></h1>
    {#if info}
      <span class="muted">
        {t('{n} blocked names in snapshot {snapshot}', { n: num(info.filterNames), snapshot: info.filterSnapshot ?? '–' })}
      </span>
    {/if}
  </div>
  <ErrorNote {error} />
  <section class="card">
    {#if !loaded}
      <p class="empty muted">{t('Loading…')}</p>
    {:else if lists.length === 0}
      <p class="empty"><T ctx="lists" msg={'No lists are configured. Add <listentry/> entries (URLs, files, or inline rules).'} {listentry} /></p>
    {:else}
      <div class="table-wrap">
        <table>
          <thead>
            <tr><th>{t('List')}</th><th>{t('Kind')}<HelpButton id="list-kind" /></th><th>{t('State')}<HelpButton id="list-refresh" /></th><th class="num">{t('Names used')}</th><th class="num">{t('Unique')}<HelpButton id="list-overlap" /></th><th class="num">{t('Hits')}</th>{#if advanced}<th class="num">{t('Lines')}</th><th class="num">{t('Size')}</th>{/if}<th>{t('Checked')}</th><th>{t('Changed')}</th></tr>
          </thead>
          <tbody>
            {#each lists as l (l.name)}
              <tr class:off={!l.enabled}>
                <td>
                  <strong translate="no">{l.name}</strong>{#if !l.enabled} <span class="badge">{words.off}</span>{/if}{#if l.mode === 'shadow'} <span class="badge info" title={words.shadowTip}>{words.shadow}</span>{/if}
                  {#if advanced}<div class="muted small src" translate="no">{l.source}</div>{/if}
                  {#if l.error}<div class="small err" translate="no">{l.error}</div>{/if}
                  <!-- REQ: FLT-003 (review 02-08) — regex rules the snapshot leaves out. -->
                  {#if l.regexSkipped > 0}<div class="small warn-text" data-testid="list-regex-skipped">{#if l.regexSkipped === 1}<T ctx="lists" msg={'{n} regex rule left out (over the limit of <maxregexes/>, or too large to compile)'} params={{ n: num(l.regexSkipped) }} {maxregexes} />{:else}<T ctx="lists" msg={'{n} regex rules left out (over the limit of <maxregexes/>, or too large to compile)'} params={{ n: num(l.regexSkipped) }} {maxregexes} />{/if}</div>{/if}
                </td>
                <td><span class="badge {l.kind === 'allow' ? 'ok' : 'bad'}" translate="no">{l.kind}</span></td>
                <td>
                  <span translate="no"><StatusBadge value={l.state} /></span>
                  <!-- REQ: OBS-023 — downloads fine, but its content stopped changing. -->
                  {#if l.staleDays}<div class="small warn-text" data-testid="list-stale" title={words.staleTip}>{t('unchanged for {n} days', { n: l.staleDays })}</div>{/if}
                </td>
                <td class="num">{num(l.entries)}{#if info?.filterNames && l.kind !== 'allow'}<ShareBar value={(l.entries / info.filterNames) * 100} color="--s-blocked" label={words.shareLabel} />{/if}</td>
                <!-- REQ: OBS-009 (T7.14) — unique contribution, overlap, hits. -->
                <td class="num" data-testid="list-unique">
                  {num(l.unique)}
                  {#if l.entries > 0 && l.overlap.length && l.overlap[0].names / l.entries >= 0.95}
                    <div class="small warn-text">{t('{pct}% also in {list}', { pct: Math.round((l.overlap[0].names / l.entries) * 100), list: l.overlap[0].list })}</div>
                  {/if}
                </td>
                <td class="num">{num(l.hits)}{#if l.state === 'ok' && l.entries > 0 && l.hits === 0}<div class="small muted">{words.noneYet}</div>{/if}</td>
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
      <h2>{t('Would have blocked')}<HelpButton id="shadow-lists" /></h2>
      {#each shadow as s (s.list)}
        <div class="shadow-list">
          <div class="row">
            <strong translate="no">{s.list}</strong>
            <span class="muted small">
              {#if s.hits === 1}{#if s.devices === 1}{t('{n} query from {m} device', { n: num(s.hits), m: num(s.devices) })}{:else}{t('{n} query from {m} devices', { n: num(s.hits), m: num(s.devices) })}{/if}{:else if s.devices === 1}{t('{n} queries from {m} device', { n: num(s.hits), m: num(s.devices) })}{:else}{t('{n} queries from {m} devices', { n: num(s.hits), m: num(s.devices) })}{/if}{#if s.since}{t('since {when}', { when: ago(Date.parse(s.since) / 1000) })}{/if}{#if s.lastHitAt}{t('· last {when}', { when: ago(Date.parse(s.lastHitAt) / 1000) })}{/if}
            </span>
          </div>
          {#if s.topNames.length}
            <div class="small names">{#each s.topNames.slice(0, 10) as n, i (i)}<span class="name mono" translate="no">{n.name} <span class="muted">{num(n.count)}</span></span>{/each}</div>
          {:else}
            <p class="muted small">{words.nothingYet}</p>
          {/if}
        </div>
      {/each}
      <p class="muted small"><T ctx="lists" msg={"Shadow lists never block. When the names above are ones you'd want blocked, switch the list to <enforce/>."} {enforce} /></p>
    </section>
  {/if}
  {#if suspects.length}
    <!-- REQ: OBS-018 — blocked names someone seems to want. -->
    <section class="card" data-testid="overblocking">
      <h2>{t('Likely over-blocking')}<HelpButton id="overblocking" /></h2>
      <div class="table-wrap">
        <table class="compact">
          <thead><tr><th>{t('Name')}</th><th>{t('Blocked by')}</th><th class="num">{t('Allowed soon after')}</th><th class="num">{t('Retry bursts')}</th><th class="num">{t('Devices')}</th><th>{t('Last')}</th></tr></thead>
          <tbody>
            {#each suspects as s (s.name)}
              <tr>
                <td class="mono" translate="no">{s.name}</td>
                <td class="small" translate="no">{s.lists.join(', ')}</td>
                <td class="num">{num(s.allowedAfterBlock)}</td>
                <td class="num">{num(s.retryBursts)}</td>
                <td class="num">{num(s.devices)}</td>
                <td class="small">{ago(Date.parse(s.lastSeen) / 1000)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      <p class="muted small">{t('"Allowed soon after" counts devices that got the name within 10 minutes of a block (a pause or an allow): someone wanted it. Retry bursts are apps asking 10+ times a minute; ad libraries do that too.')}</p>
    </section>
  {/if}
  <ConfigEditor kind="list" path="lists" title={t('Manage lists')} noun={t('list')} fields={listFields}
    summary={(d) => `${String(d.kind ?? 'block')} · ${d.url ? String(d.url) : t('{n} rules', { n: ((d.rules as string[]) ?? []).length })}${d.enabled === false ? ` · ${words.off}` : ''}`}
    onchanged={async () => (lists = (await api.lists()).items)} formAction={tryList} />
  <p class="muted small">{t('"Names used" counts the names this list puts in the active snapshot; "Unique" the ones no other list has (what removing it would lose). "Hits" counts the queries it decided since each node started, across the cluster.')}</p>
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
