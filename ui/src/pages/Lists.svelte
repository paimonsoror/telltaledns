<script lang="ts">
  // REQ: API-005, FLT-004 — filter lists with their download state.
  import { api, type S } from '../lib/api';
  import { ago, bytes, num } from '../lib/format';
  import { poll } from '../lib/poll';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import StatusBadge from '../lib/components/StatusBadge.svelte';

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
</script>

<div class="page">
  <div class="page-head">
    <h1>Lists</h1>
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
            <tr><th>List</th><th>Kind</th><th>State</th><th class="num">Names used</th><th class="num">Lines</th><th class="num">Size</th><th>Checked</th><th>Changed</th></tr>
          </thead>
          <tbody>
            {#each lists as l (l.name)}
              <tr class:off={!l.enabled}>
                <td>
                  <strong>{l.name}</strong>{#if !l.enabled} <span class="badge">off</span>{/if}
                  <div class="muted small src">{l.source}</div>
                  {#if l.error}<div class="small err">{l.error}</div>{/if}
                </td>
                <td><span class="badge {l.kind === 'allow' ? 'ok' : 'bad'}">{l.kind}</span></td>
                <td><StatusBadge value={l.state} /></td>
                <td class="num">{num(l.entries)}</td>
                <td class="num">{num(l.lines)}</td>
                <td class="num">{bytes(l.bytes)}</td>
                <td class="small">{ago(l.lastCheckedUnixSeconds)}</td>
                <td class="small">{ago(l.lastChangedUnixSeconds)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>
  <p class="muted small">"Names used" counts what this list adds to the active snapshot after removing names other lists already cover.</p>
</div>

<style>
  .src {
    word-break: break-all;
    max-width: 420px;
  }
  .err {
    color: var(--bad);
  }
  tr.off {
    opacity: 0.6;
  }
</style>
