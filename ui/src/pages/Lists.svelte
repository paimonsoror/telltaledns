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

  // REQ: API-002 (T7.5) — add and change lists here.
  const listFields: Field[] = [
    { key: 'url', label: 'Download from', type: 'text', placeholder: 'https://example.org/hosts.txt',
      help: 'Hosts files, plain domain lists, and Adblock-style lists all work. Or leave this empty and write the rules below.' },
    { key: 'rules', label: 'Rules', type: 'lines', placeholder: 'ads.example.com, ||tracker.example^ (one per line)' },
    { key: 'kind', label: 'Kind', type: 'select', options: ['block', 'allow'], initial: 'block' },
    { key: 'match', label: 'Plain names match', type: 'select', options: ['subtree', 'exact'], advanced: true,
      help: 'subtree: the name and everything below it. exact: only the name itself.' },
    { key: 'enabled', label: 'On', type: 'bool', initial: true },
    // REQ: OBS-018 — try a list before it blocks anything.
    { key: 'mode', label: 'Mode', type: 'select', options: ['enforce', 'shadow'], initial: 'enforce',
      help: 'enforce: it blocks. shadow: it never blocks; the page shows what it would have blocked, so you can judge it first.' },
    { key: 'refresh_secs', label: 'Check for updates every (seconds)', type: 'number', placeholder: '86400', advanced: true },
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
  // REQ: API-002 (T9.12) — download and parse the draft list before saving it.
  const tryList = {
    label: 'Test it',
    run: async (b: Record<string, unknown>) => {
      const r = await api.checkList(b);
      const notes = r.warnings.length ? ` Lines it can't use: ${r.warnings.slice(0, 3).join('; ')}` : '';
      return r.ok
        ? { ok: true, text: `Works: ${r.detail}, in ${r.elapsedMs} ms.${notes}` }
        : { ok: false, text: `Doesn't work: ${r.error ?? r.detail}.${notes}` };
    },
  };
</script>

<div class="page">
  <div class="page-head">
    <h1>Lists<HelpButton id="lists" /></h1>
    {#if info}
      <span class="muted">
        {num(info.filterNames)} blocked names in snapshot {info.filterSnapshot ?? '–'}
      </span>
    {/if}
  </div>
  <ErrorNote {error} />
  <section class="card">
    {#if !loaded}
      <p class="empty muted">Loading…</p>
    {:else if lists.length === 0}
      <p class="empty">No lists are configured. Add <code>[[list]]</code> entries (URLs, files, or inline rules).</p>
    {:else}
      <div class="table-wrap">
        <table>
          <thead>
            <tr><th>List</th><th>Kind<HelpButton id="list-kind" /></th><th>State<HelpButton id="list-refresh" /></th><th class="num">Names used</th><th class="num">Unique<HelpButton id="list-overlap" /></th><th class="num">Hits</th>{#if advanced}<th class="num">Lines</th><th class="num">Size</th>{/if}<th>Checked</th><th>Changed</th></tr>
          </thead>
          <tbody>
            {#each lists as l (l.name)}
              <tr class:off={!l.enabled}>
                <td>
                  <strong>{l.name}</strong>{#if !l.enabled} <span class="badge">off</span>{/if}{#if l.mode === 'shadow'} <span class="badge info" title="Never blocks: what it would have blocked is counted below">shadow</span>{/if}
                  {#if advanced}<div class="muted small src">{l.source}</div>{/if}
                  {#if l.error}<div class="small err">{l.error}</div>{/if}
                  <!-- REQ: FLT-003 (review 02-08) — regex rules the snapshot leaves out. -->
                  {#if l.regexSkipped > 0}<div class="small warn-text" data-testid="list-regex-skipped">{num(l.regexSkipped)} regex {l.regexSkipped === 1 ? 'rule' : 'rules'} left out (over the limit of <code>max_regexes</code>, or too large to compile)</div>{/if}
                </td>
                <td><span class="badge {l.kind === 'allow' ? 'ok' : 'bad'}">{l.kind}</span></td>
                <td><StatusBadge value={l.state} /></td>
                <td class="num">{num(l.entries)}{#if info?.filterNames && l.kind !== 'allow'}<ShareBar value={(l.entries / info.filterNames) * 100} color="--s-blocked" label="share of the blocked names in the snapshot" />{/if}</td>
                <!-- REQ: OBS-009 (T7.14) — unique contribution, overlap, hits. -->
                <td class="num" data-testid="list-unique">
                  {num(l.unique)}
                  {#if l.entries > 0 && l.overlap.length && l.overlap[0].names / l.entries >= 0.95}
                    <div class="small warn-text">{Math.round((l.overlap[0].names / l.entries) * 100)}% also in {l.overlap[0].list}</div>
                  {/if}
                </td>
                <td class="num">{num(l.hits)}{#if l.state === 'ok' && l.entries > 0 && l.hits === 0}<div class="small muted">none yet</div>{/if}</td>
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
      <h2>Would have blocked<HelpButton id="shadow-lists" /></h2>
      {#each shadow as s (s.list)}
        <div class="shadow-list">
          <div class="row">
            <strong>{s.list}</strong>
            <span class="muted small">
              {num(s.hits)} {s.hits === 1 ? 'query' : 'queries'} from {num(s.devices)} {s.devices === 1 ? 'device' : 'devices'}{#if s.since} since {ago(Date.parse(s.since) / 1000)}{/if}{#if s.lastHitAt} · last {ago(Date.parse(s.lastHitAt) / 1000)}{/if}
            </span>
          </div>
          {#if s.topNames.length}
            <div class="small names">{#each s.topNames.slice(0, 10) as n (n.name)}<span class="name mono">{n.name} <span class="muted">{num(n.count)}</span></span>{/each}</div>
          {:else}
            <p class="muted small">Nothing yet: it hasn't matched anything your devices asked for.</p>
          {/if}
        </div>
      {/each}
      <p class="muted small">Shadow lists never block. When the names above are ones you'd want blocked, switch the list to <strong>enforce</strong>.</p>
    </section>
  {/if}
  {#if suspects.length}
    <!-- REQ: OBS-018 — blocked names someone seems to want. -->
    <section class="card" data-testid="overblocking">
      <h2>Likely over-blocking<HelpButton id="overblocking" /></h2>
      <div class="table-wrap">
        <table class="compact">
          <thead><tr><th>Name</th><th>Blocked by</th><th class="num">Allowed soon after</th><th class="num">Retry bursts</th><th class="num">Devices</th><th>Last</th></tr></thead>
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
      <p class="muted small">"Allowed soon after" counts devices that got the name within 10 minutes of a block (a pause or an allow): someone wanted it. Retry bursts are apps asking 10+ times a minute; ad libraries do that too.</p>
    </section>
  {/if}
  <ConfigEditor kind="list" path="lists" title="Manage lists" noun="list" fields={listFields}
    summary={(d) => `${String(d.kind ?? 'block')} · ${d.url ? String(d.url) : `${((d.rules as string[]) ?? []).length} rules`}${d.enabled === false ? ' · off' : ''}`}
    onchanged={async () => (lists = (await api.lists()).items)} formAction={tryList} />
  <p class="muted small">"Names used" counts the names this list puts in the active snapshot; "Unique" the ones no other list has (what removing it would lose). "Hits" counts the queries it decided on this node since it started.</p>
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
