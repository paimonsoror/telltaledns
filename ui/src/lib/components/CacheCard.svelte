<script lang="ts">
  // REQ: DNS-006, API-005 (T6.13) — the cache: counters per node, what it holds for a name,
  // and flushing a name, a subtree, or everything, on every node (or one).
  import { api, type S } from '../api';
  import { can } from '../session.svelte';
  import { bytes, num, pct } from '../format';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';

  let {
    name: initial = '',
    compact = false,
    title = 'Cache',
  }: { name?: string; compact?: boolean; title?: string } = $props();

  let stats = $state<S['CacheNodeStats'][]>([]);
  let name = $state('');
  let found = $state<S['CacheLookup'] | null>(null);
  let subtree = $state(false);
  let node = $state('');
  let flushed = $state<S['CacheFlushResult'] | null>(null);
  let busy = $state(false);
  let error = $state<unknown>(null);
  let confirmAll = $state(false);
  const writable = $derived(can('operator'));

  async function loadStats() {
    try {
      stats = (await api.cacheStats()).items;
    } catch (e) {
      error = e;
    }
  }
  async function lookup(e?: SubmitEvent) {
    e?.preventDefault();
    if (!name.trim()) return;
    error = null;
    try {
      found = await api.cacheLookup(name.trim());
    } catch (err) {
      error = err;
    }
  }
  async function flush(all: boolean) {
    busy = true;
    error = null;
    try {
      flushed = await api.cacheFlush({
        name: all ? undefined : name.trim(),
        subtree: all ? undefined : subtree,
        node: node || undefined,
      });
      confirmAll = false;
      await loadStats();
      if (!all) await lookup();
    } catch (err) {
      error = err;
    } finally {
      busy = false;
    }
  }
  $effect(() => {
    name = initial;
    void loadStats();
    if (initial) void lookup();
  });
  const ttl = (s: number) => (s >= 0 ? `${num(s)} s left` : `stale for ${num(-s)} s`);
</script>

<section class="card" data-testid="cache-card">
  <h2>{title}<HelpButton id="cache-tools" /></h2>
  {#if stats.length && !compact}
    <div class="table-wrap">
      <table class="compact">
        <thead>
          <tr><th>Node</th><th class="num">Entries</th><th class="num">Memory</th><th class="num" title="Answered from the cache: fresh, or refreshed in the background">From cache</th><th class="num">Stale served</th><th class="num">Prefetches</th><th class="num">Evictions</th></tr>
        </thead>
        <tbody>
          {#each stats as s, i (s.node ?? i)}
            <tr>
              <td>{s.node ?? 'this node'}</td>
              <td class="num">{num(s.entries)}</td>
              <td class="num">{bytes(s.bytes)}</td>
              <td class="num">{pct(s.answeredPercent ?? s.hitPercent)}</td>
              <td class="num">{num(s.staleServed)}</td>
              <td class="num">{num(s.prefetches)}</td>
              <td class="num">{num(s.evictions)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}

  <form class="row" onsubmit={lookup}>
    <input class="grow mono" aria-label="Name to look up" placeholder="www.example.com" bind:value={name} />
    <button>Look up</button>
  </form>
  {#if found}
    {#if found.entries.length === 0}
      <p class="muted small">Nothing cached for <span class="mono">{found.name}</span>.</p>
    {:else}
      <div class="table-wrap">
        <table class="compact" data-testid="cache-entries">
          <thead><tr><th>Node</th><th>Type</th><th>Answer</th><th>Fresh</th><th class="num">Hits</th></tr></thead>
          <tbody>
            {#each found.entries as e, i (i)}
              <tr>
                <td>{e.node ?? 'this node'}</td>
                <td>{e.qtype}{#if e.dnssecOk}<span class="muted small"> (DO)</span>{/if}</td>
                <td>{e.rcode} · {e.answers} answer{e.answers === 1 ? '' : 's'}{#if e.authentic}<span class="badge ok">validated</span>{/if}</td>
                <td class="small">{ttl(e.ttlLeftSeconds)}</td>
                <td class="num">{num(e.hits)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  {/if}

  {#if writable}
    <div class="row">
      <label class="small"><input type="checkbox" bind:checked={subtree} /> and everything under it</label>
      {#if stats.length > 1}
        <select aria-label="Node" bind:value={node}>
          <option value="">every node</option>
          {#each stats as s, i (s.node ?? i)}<option value={s.node ?? ''}>{s.node}</option>{/each}
        </select>
      {/if}
      <button disabled={busy || !name.trim()} onclick={() => flush(false)}>Flush this name</button>
      {#if confirmAll}
        <button class="danger" disabled={busy} onclick={() => flush(true)}>Yes, empty the cache</button>
        <button class="link" onclick={() => (confirmAll = false)}>Cancel</button>
      {:else}
        <button class="link" onclick={() => (confirmAll = true)}>Flush everything…</button>
      {/if}
    </div>
  {/if}
  {#if flushed}
    <p class="notice ok small" data-testid="cache-flushed">
      Removed {num(flushed.totalRemoved)} {flushed.totalRemoved === 1 ? 'entry' : 'entries'}{#each flushed.nodes.filter((n) => n.error) as n (n.node)}{` · ${n.node}: ${n.error}`}{/each}.
    </p>
  {/if}
  <ErrorNote {error} />
  <p class="muted small">
    Flushing doesn't clear devices' own caches. Blocked answers are never cached, so unblocking needs no flush. To change
    what a name resolves to, use Names on my network.
  </p>
</section>

<style>
  .row {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    align-items: center;
    margin: 12px 0;
  }
  .grow {
    flex: 1 1 220px;
  }
  .badge {
    margin-left: 6px;
  }
</style>
