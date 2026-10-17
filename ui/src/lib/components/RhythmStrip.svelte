<script lang="ts" module>
  /** The bins' upper bounds in seconds, as the API sends them (`binsS`). */
  export const BINS_S = [1, 1.5, 2.2, 3.3, 5, 7.5, 11, 17, 25, 38, 56, 84, 126, 190, 285, 427, 640, 960, 1440, 2160, 3240, 4860, 7290];

  export type RhythmRow = {
    domain: string;
    hour?: number[];
    recent?: number[];
    period?: string | null;
    knownPeriodic?: boolean;
    regularHours?: number;
  };
</script>

<script lang="ts">
  // REQ: OBS-031 (ADR-131) — how a device's queries are spaced, per domain: columns are the gap
  // between queries (log scale, under 1 s to 2 h and longer), each cell as dark as its share of
  // the row's busiest bin, so a chatty and a quiet domain both show their shape. A time-sync loop
  // is one dark cell; a browser is a smear.
  import { href } from '../router.svelte';
  import { num } from '../format';

  let {
    rows,
    client,
    binsS = BINS_S,
    toggle = true,
  }: { rows: RhythmRow[]; client?: string; binsS?: number[]; toggle?: boolean } = $props();

  // A beacon finding carries one strip: its recent view.
  let view = $state<'hour' | 'recent'>('recent');
  let table = $state(false);
  const CELL = 14;
  const N = 24;
  const W = CELL * N;
  const bins = (r: RhythmRow) => (view === 'hour' ? r.hour : r.recent) ?? r.recent ?? r.hour ?? [];

  const label = (i: number) => {
    const s = (x: number) => (x < 60 ? `${x} s` : x < 3600 ? `${Math.round(x / 60)} min` : `${(x / 3600).toFixed(1)} h`);
    if (i === 0) return `under ${s(binsS[0])}`;
    return i >= binsS.length ? `${s(binsS[binsS.length - 1])} and longer` : `${s(binsS[i - 1])}–${s(binsS[i])}`;
  };
  // Where a period sits on the axis (log within its bin).
  function x(t: number): number {
    const i = binsS.findIndex((e) => t < e);
    const bin = i === -1 ? N - 1 : i;
    const lo = bin === 0 ? 0.5 : binsS[bin - 1];
    const hi = bin < binsS.length ? binsS[bin] : lo * 1.5;
    return (bin + Math.log(t / lo) / Math.log(hi / lo)) * CELL;
  }
  const ticks = [
    { t: 1, text: '1 s' },
    { t: 10, text: '10 s' },
    { t: 60, text: '1 min' },
    { t: 600, text: '10 min' },
    { t: 3600, text: '1 h' },
  ];
  function cells(r: RhythmRow) {
    const b = bins(r);
    const total = b.reduce((a, n) => a + n, 0);
    const max = Math.max(0, ...b);
    return b.map((n, i) => ({ i, n, share: total ? n / total : 0, shade: max ? n / max : 0 }));
  }
  const hasRecent = $derived(rows.some((r) => r.hour && r.recent));
</script>

<div class="rhythm" data-testid="rhythm">
  {#if toggle}
    <div class="controls">
      {#if hasRecent}
        <div class="seg" role="group" aria-label="Which hours">
          <button type="button" aria-pressed={view === 'recent'} onclick={() => (view = 'recent')}>Recent</button>
          <button type="button" aria-pressed={view === 'hour'} onclick={() => (view = 'hour')}>This hour</button>
        </div>
      {/if}
      <label class="small"><input type="checkbox" bind:checked={table} data-testid="rhythm-table-toggle" /> Table</label>
    </div>
  {/if}
  {#if rows.length === 0}
    <p class="empty">No tracked domains for this device yet.</p>
  {:else if table}
    <div class="scroll">
      <table data-testid="rhythm-table">
        <thead>
          <tr><th>Domain</th>{#each Array(N) as _, i (i)}<th class="num" title={label(i)}>{i}</th>{/each}</tr>
        </thead>
        <tbody>
          {#each rows as r (r.domain)}
            <tr><td class="mono">{r.domain}</td>{#each bins(r) as n, i (i)}<td class="num">{n ? num(n) : ''}</td>{/each}</tr>
          {/each}
        </tbody>
      </table>
    </div>
    <p class="muted small">Columns are the gap between two queries: 0 is under 1 s, then 1–1.5 s, 1.5–2.2 s, … up to 2 hours and longer.</p>
  {:else}
    <div class="scroll">
      <div class="grid">
        {#each rows as r (r.domain)}
          {@const cs = cells(r)}
          {@const top = cs.reduce((a, c) => (c.n > a.n ? c : a), cs[0] ?? { i: 0, n: 0, share: 0, shade: 0 })}
          <a
            class="name mono small"
            href={href('/queries', { client, name: r.domain, match: 'suffix' })}
            data-testid="rhythm-row"
            data-domain={r.domain}
            title="Open these queries">{r.domain}</a
          >
          <svg width={W} height={CELL} viewBox="0 0 {W} {CELL}" role="img" aria-label="{r.domain}: {r.period ?? 'no single rhythm'}">
            {#each cs as c (c.i)}
              <rect
                x={c.i * CELL + 1}
                y="1"
                width={CELL - 2}
                height={CELL - 2}
                rx="2"
                fill="var(--hm-ink)"
                fill-opacity={c.n ? Math.max(0.06, c.shade) : 0.03}
                class:dominant={c.i === top.i && top.share >= 0.5}
                data-bin={c.i}
                data-n={c.n}
              ><title>{label(c.i)}: {num(c.n)} ({Math.round(c.share * 100)} %)</title></rect>
            {/each}
          </svg>
          <span class="small period">
            {#if r.period}<span data-testid="rhythm-period">{r.period}</span>{/if}
            {#if r.knownPeriodic}<span class="badge">usual</span>
            {:else if (r.regularHours ?? 0) >= 4}<span class="badge warn">new rhythm</span>{/if}
          </span>
        {/each}
        <span></span>
        <svg width={W} height="14" viewBox="0 0 {W} 14" aria-hidden="true" class="axis">
          {#each ticks as t (t.t)}
            <text x={x(t.t)} y="11" text-anchor="middle">{t.text}</text>
          {/each}
        </svg>
        <span></span>
      </div>
    </div>
  {/if}
</div>

<style>
  .controls {
    display: flex;
    flex-wrap: wrap;
    gap: 8px 12px;
    align-items: center;
    margin-bottom: 8px;
  }
  .scroll {
    overflow-x: auto;
    -webkit-overflow-scrolling: touch;
  }
  .grid {
    display: grid;
    grid-template-columns: minmax(90px, max-content) max-content minmax(90px, 1fr);
    gap: 3px 10px;
    align-items: center;
  }
  .name {
    position: sticky;
    left: 0;
    background: var(--surface);
    z-index: 1;
    padding-right: 4px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 180px;
  }
  rect.dominant {
    stroke: var(--text);
    stroke-width: 1.5;
  }
  .axis text {
    font-size: 10px;
    fill: var(--muted);
  }
  .period {
    white-space: nowrap;
    display: flex;
    gap: 6px;
    align-items: center;
  }
  .num {
    text-align: right;
    font-variant-numeric: tabular-nums;
  }
</style>
