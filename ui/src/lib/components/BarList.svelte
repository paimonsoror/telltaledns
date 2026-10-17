<script lang="ts">
  // REQ: OBS-027 — one breakdown as bars sized by share, with a table view (spec/07 §3). An
  // approximate row shows its error bound as a faint extension.
  import type { S } from '../api';
  import { num } from '../format';

  let {
    title,
    rows,
    link,
    testid,
    empty = 'Nothing here.',
  }: {
    title: string;
    rows: S['AttributionRow'][];
    /** Where a row leads (undefined: no link). */
    link?: (r: S['AttributionRow']) => string | undefined;
    testid?: string;
    empty?: string;
  } = $props();
  let table = $state(false);
  const max = $derived(Math.max(1, ...rows.map((r) => r.bad)));
  const label = (r: S['AttributionRow']) => (r.name ? `${r.name} (${r.key})` : r.key);
</script>

<section class="card bars-card" data-testid={testid}>
  <div class="card-head">
    <h3>{title}</h3>
    <button class="link small" onclick={() => (table = !table)} aria-pressed={table}>{table ? 'Bars' : 'Table'}</button>
  </div>
  {#if rows.length === 0}
    <p class="empty small">{empty}</p>
  {:else if table}
    <div class="table-wrap">
      <table class="compact">
        <thead><tr><th>{title}</th><th class="num">Bad</th><th class="num">Share</th>{#if rows.some((r) => !r.exact)}<th class="num">± up to</th>{/if}</tr></thead>
        <tbody>
          {#each rows as r (r.key)}
            {@const to = link?.(r)}
            <tr>
              <td class="key">{#if to}<a href={to}>{label(r)}</a>{:else}{label(r)}{/if}</td>
              <td class="num">{num(r.bad)}</td>
              <td class="num">{r.sharePct}%</td>
              {#if rows.some((x) => !x.exact)}<td class="num">{r.exact ? '' : num(r.errorMax ?? 0)}</td>{/if}
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {:else}
    <ul class="bars">
      {#each rows as r (r.key)}
        {@const to = link?.(r)}
        <li>
          <div class="row">
            <span class="key">{#if to}<a href={to}>{label(r)}</a>{:else}{label(r)}{/if}</span>
            <span class="spacer"></span>
            <span class="muted small">{num(r.bad)} · {r.sharePct}%{#if !r.exact && r.errorMax} (± up to {num(r.errorMax)}){/if}</span>
          </div>
          <div class="bar">
            <span style:width={`${(r.bad / max) * 100}%`}></span>
            {#if !r.exact && r.errorMax}<i style:width={`${(Math.min(r.errorMax, r.bad) / max) * 100}%`}></i>{/if}
          </div>
        </li>
      {/each}
    </ul>
  {/if}
</section>

<style>
  .bars {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: 8px;
  }
  .key {
    overflow-wrap: anywhere;
    font-size: 13px;
  }
  .bar {
    display: flex;
    height: 7px;
    border-radius: 999px;
    background: var(--surface-2);
    overflow: hidden;
  }
  .bar span {
    background: var(--s-blocked);
    border-radius: 999px;
  }
  /* The error bound: the true count may be this much lower. */
  .bar i {
    background: var(--s-blocked);
    opacity: 0.3;
    margin-left: -1px;
  }
  h3 {
    margin: 0;
    font-size: 14px;
  }
</style>
