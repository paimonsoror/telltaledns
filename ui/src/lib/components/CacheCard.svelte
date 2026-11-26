<script lang="ts">
  // REQ: DNS-006, API-005 (T6.13) — the cache: counters per node, what it holds for a name,
  // and flushing a name, a subtree, or everything, on every node (or one).
  import { api, type S } from '../api';
  import { can } from '../session.svelte';
  import { bytes, num, pct } from '../format';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';
  import { tr } from '../i18n';
  import T from '../i18n/T.svelte';
  // REQ: API-012 — `answers` (u16) and `totalRemoved` (u64) are counts: tn() gives the ternaries'
  // English.
  const { t, tn } = tr('cacheCard');

  let {
    name: initial = '',
    compact = false,
    title = t('Cache'),
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
  const ttl = (s: number) => (s >= 0 ? t('{n} s left', { n: num(s) }) : t('stale for {n} s', { n: num(-s) }));
  const errors = (f: S['CacheFlushResult']) =>
    f.nodes
      .filter((n) => n.error)
      .map((n) => ` · ${n.node}: ${n.error}`)
      .join('');
</script>

<section class="card" data-testid="cache-card">
  <h2>{title}<HelpButton id="cache-tools" /></h2>
  {#if stats.length && !compact}
    <div class="table-wrap">
      <table class="compact">
        <thead>
          <tr><th>{t('Node')}</th><th class="num">{t('Entries')}</th><th class="num">{t('Memory')}</th><th class="num" title={t('Answered from the cache: fresh, or refreshed in the background')}>{t('From cache')}</th><th class="num">{t('Stale served')}</th><th class="num">{t('Prefetches')}</th><th class="num">{t('Evictions')}</th></tr>
        </thead>
        <tbody>
          {#each stats as s, i (s.node ?? i)}
            <tr>
              <td>{s.node ?? t('this node')}</td>
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
    <input class="grow mono" aria-label={t('Name to look up')} placeholder={t('www.example.com')} bind:value={name} />
    <button>{t('Look up')}</button>
  </form>
  {#if found}
    {#if found.entries.length === 0}
      <p class="muted small">
        <T ctx="cacheCard" msg={'Nothing cached for <span>{name}</span>.'} params={{ name: found.name }}
          >{#snippet span(x: string)}<span class="mono" translate="no">{x}</span>{/snippet}</T
        >
      </p>
    {:else}
      <div class="table-wrap">
        <table class="compact" data-testid="cache-entries">
          <thead><tr><th>{t('Node')}</th><th>{t('Type')}</th><th>{t('Answer')}</th><th>{t('Fresh')}</th><th class="num">{t('Hits')}</th></tr></thead>
          <tbody>
            {#each found.entries as e, i (i)}
              <tr>
                <td>{e.node ?? t('this node')}</td>
                <td translate="no">{e.qtype}{#if e.dnssecOk}<span class="muted small" translate="no"> (DO)</span>{/if}</td>
                <td>{tn('{rcode} · {n} answer', '{rcode} · {n} answers', e.answers, { rcode: e.rcode, n: e.answers })}{#if e.authentic}<span class="badge ok">{t('validated')}</span>{/if}</td>
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
      <label class="small"><input type="checkbox" bind:checked={subtree} /> {t('and everything under it')}</label>
      {#if stats.length > 1}
        <select aria-label={t('Node')} bind:value={node}>
          <option value="">{t('every node')}</option>
          {#each stats as s, i (s.node ?? i)}<option value={s.node ?? ''}>{s.node}</option>{/each}
        </select>
      {/if}
      <button disabled={busy || !name.trim()} onclick={() => flush(false)}>{t('Flush this name')}</button>
      {#if confirmAll}
        <button class="danger" disabled={busy} onclick={() => flush(true)}>{t('Yes, empty the cache')}</button>
        <button class="link" onclick={() => (confirmAll = false)}>{t('Cancel')}</button>
      {:else}
        <button class="link" onclick={() => (confirmAll = true)}>{t('Flush everything…')}</button>
      {/if}
    </div>
  {/if}
  {#if flushed}
    <p class="notice ok small" data-testid="cache-flushed">
      {tn('Removed {n} entry{errors}.', 'Removed {n} entries{errors}.', flushed.totalRemoved, { n: num(flushed.totalRemoved), errors: errors(flushed) })}
    </p>
  {/if}
  <ErrorNote {error} />
  <p class="muted small">
    {t('Flushing doesn\'t clear devices\' own caches. Blocked answers are never cached, so unblocking needs no flush. To change what a name resolves to, use Names on my network.')}
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
