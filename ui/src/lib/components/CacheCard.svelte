<script lang="ts">
  // REQ: DNS-006, API-005 (T6.13) — the cache: counters per node, what it holds for a name,
  // and flushing a name, a subtree, or everything, on every node (or one).
  import { api, type S } from '../api';
  import { can } from '../session.svelte';
  import { bytes, num, pct } from '../format';
  import { t, tn } from '../i18n';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';

  let {
    name: initial = '',
    compact = false,
    title: titleProp,
  }: { name?: string; compact?: boolean; title?: string } = $props();

  // A caller that names the card ("Look up and flush") says it; otherwise the catalog does.
  const title = $derived(titleProp ?? t('nav.cache'));

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
  const ttl = (s: number) => (s >= 0 ? t('qw.cache.ttl.left', { n: num(s) }) : t('qw.cache.ttl.stale', { n: num(-s) }));
</script>

<section class="card" data-testid="cache-card">
  <h2>{title}<HelpButton id="cache-tools" /></h2>
  {#if stats.length && !compact}
    <div class="table-wrap">
      <table class="compact">
        <thead>
          <tr><th>{t('qw.cache.node')}</th><th class="num">{t('qw.cache.entries')}</th><th class="num">{t('qw.cache.memory')}</th><th class="num" title={t('qw.cache.fromCache.title')}>{t('qw.cache.fromCache')}</th><th class="num">{t('qw.cache.staleServed')}</th><th class="num">{t('qw.cache.prefetches')}</th><th class="num">{t('qw.cache.evictions')}</th></tr>
        </thead>
        <tbody>
          {#each stats as s, i (s.node ?? i)}
            <tr>
              <td>{s.node ?? t('legacy.thisNode')}</td>
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
    <input class="grow mono" aria-label={t('qw.cache.lookupLabel')} placeholder={t('qw.cache.lookupPlaceholder')} bind:value={name} />
    <button>{t('qw.cache.lookup')}</button>
  </form>
  {#if found}
    {#if found.entries.length === 0}
      <p class="muted small">{t('qw.cache.nothingCachedLead')} <span class="mono">{found.name}</span>{t('qw.cache.nothingCachedTail')}</p>
    {:else}
      <div class="table-wrap">
        <table class="compact" data-testid="cache-entries">
          <thead><tr><th>{t('qw.cache.node')}</th><th>{t('qw.cache.type')}</th><th>{t('qw.cache.answer')}</th><th>{t('qw.cache.fresh')}</th><th class="num">{t('qw.cache.hits')}</th></tr></thead>
          <tbody>
            {#each found.entries as e, i (i)}
              <tr>
                <td>{e.node ?? t('legacy.thisNode')}</td>
                <td>{e.qtype}{#if e.dnssecOk}<span class="muted small"> (DO)</span>{/if}</td>
                <td>{e.rcode} · {tn('qw.cache.answers', e.answers)}{#if e.authentic}<span class="badge ok">{t('qw.cache.validated')}</span>{/if}</td>
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
      <label class="small"><input type="checkbox" bind:checked={subtree} /> {t('qw.cache.subtree')}</label>
      {#if stats.length > 1}
        <select aria-label={t('qw.cache.node')} bind:value={node}>
          <option value="">{t('qw.cache.everyNode')}</option>
          {#each stats as s, i (s.node ?? i)}<option value={s.node ?? ''}>{s.node}</option>{/each}
        </select>
      {/if}
      <button disabled={busy || !name.trim()} onclick={() => flush(false)}>{t('qw.cache.flushName')}</button>
      {#if confirmAll}
        <button class="danger" disabled={busy} onclick={() => flush(true)}>{t('qw.cache.confirmAll')}</button>
        <button class="link" onclick={() => (confirmAll = false)}>{t('common.cancel')}</button>
      {:else}
        <button class="link" onclick={() => (confirmAll = true)}>{t('qw.cache.flushAll')}</button>
      {/if}
    </div>
  {/if}
  {#if flushed}
    <p class="notice ok small" data-testid="cache-flushed">
      {tn('qw.cache.flushed', flushed.totalRemoved, { n: num(flushed.totalRemoved) })}{#each flushed.nodes.filter((n) => n.error) as n (n.node)}{` · ${n.node}: ${n.error}`}{/each}.
    </p>
  {/if}
  <ErrorNote {error} />
  <p class="muted small">
    {t('qw.cache.footnote')}
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
