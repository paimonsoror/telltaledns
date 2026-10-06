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
    { key: 'refresh_secs', label: 'Check for updates every (seconds)', type: 'number', placeholder: '86400', advanced: true },
  ];

  let lists = $state<S['ListInfo'][]>([]);
  let info = $state<S['SystemInfo'] | null>(null);
  let error = $state<unknown>(null);

  $effect(() =>
    poll(async () => {
      try {
        const [l, i] = await Promise.all([api.lists(), api.info()]);
        lists = l.items;
        info = i;
        error = null;
      } catch (e) {
        error = e;
      }
    }, 15000),
  );
  const advanced = $derived(currentMode() === 'advanced');
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
    {#if lists.length === 0}
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
                  <strong>{l.name}</strong>{#if !l.enabled} <span class="badge">off</span>{/if}
                  {#if advanced}<div class="muted small src">{l.source}</div>{/if}
                  {#if l.error}<div class="small err">{l.error}</div>{/if}
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
  <ConfigEditor kind="list" path="lists" title="Manage lists" noun="list" fields={listFields}
    summary={(d) => `${String(d.kind ?? 'block')} · ${d.url ? String(d.url) : `${((d.rules as string[]) ?? []).length} rules`}${d.enabled === false ? ' · off' : ''}`}
    onchanged={async () => (lists = (await api.lists()).items)} />
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
</style>
