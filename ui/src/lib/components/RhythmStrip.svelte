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
  import { t, type MessageKey } from '../i18n';

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
    const s = (x: number) =>
      x < 60
        ? t('deviceWidgets.rhythm.unit.s', { n: x })
        : x < 3600
          ? t('nav.pause.minutesLeft', { n: Math.round(x / 60) })
          : t('deviceWidgets.rhythm.unit.h', { n: (x / 3600).toFixed(1) });
    if (i === 0) return t('deviceWidgets.rhythm.under', { span: s(binsS[0]) });
    return i >= binsS.length
      ? t('deviceWidgets.rhythm.andLonger', { span: s(binsS[binsS.length - 1]) })
      : t('deviceWidgets.rhythm.range', { from: s(binsS[i - 1]), to: s(binsS[i]) });
  };
  // Where a period sits on the axis (log within its bin).
  function x(t: number): number {
    const i = binsS.findIndex((e) => t < e);
    const bin = i === -1 ? N - 1 : i;
    const lo = bin === 0 ? 0.5 : binsS[bin - 1];
    const hi = bin < binsS.length ? binsS[bin] : lo * 1.5;
    return (bin + Math.log(t / lo) / Math.log(hi / lo)) * CELL;
  }
  const ticks: { t: number; unit: MessageKey; n: number }[] = [
    { t: 1, unit: 'deviceWidgets.rhythm.unit.s', n: 1 },
    { t: 10, unit: 'deviceWidgets.rhythm.unit.s', n: 10 },
    { t: 60, unit: 'nav.pause.minutesLeft', n: 1 },
    { t: 600, unit: 'nav.pause.minutesLeft', n: 10 },
    { t: 3600, unit: 'deviceWidgets.rhythm.unit.h', n: 1 },
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
        <div class="seg" role="group" aria-label={t('deviceWidgets.rhythm.hours')}>
          <button type="button" aria-pressed={view === 'recent'} onclick={() => (view = 'recent')}>{t('deviceWidgets.rhythm.recent')}</button>
          <button type="button" aria-pressed={view === 'hour'} onclick={() => (view = 'hour')}>{t('deviceWidgets.rhythm.thisHour')}</button>
        </div>
      {/if}
      <span class="switch-track"><label class="switch"><input type="checkbox" role="switch" bind:checked={table} data-testid="rhythm-table-toggle" />{t('flow.table')}</label></span>
    </div>
  {/if}
  {#if rows.length === 0}
    <p class="empty">{t('deviceWidgets.rhythm.empty')}</p>
  {:else if table}
    <div class="scroll">
      <table data-testid="rhythm-table">
        <thead>
          <tr><th>{t('localdns.forward.domain')}</th>{#each Array(N) as _, i (i)}<th class="num" title={label(i)}>{i}</th>{/each}</tr>
        </thead>
        <tbody>
          {#each rows as r (r.domain)}
            <tr><td class="mono">{r.domain}</td>{#each bins(r) as n, i (i)}<td class="num">{n ? num(n) : ''}</td>{/each}</tr>
          {/each}
        </tbody>
      </table>
    </div>
    <p class="muted small">{t('deviceWidgets.rhythm.legend')}</p>
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
            title={t('deviceWidgets.rhythm.openQueries')}>{r.domain}</a
          >
          <svg width={W} height={CELL} viewBox="0 0 {W} {CELL}" role="img" aria-label={t('deviceWidgets.rhythm.aria', { domain: r.domain, period: r.period ?? t('deviceWidgets.rhythm.noRhythm') })}>
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
              ><title>{t('deviceWidgets.rhythm.cell', { gap: label(c.i), count: num(c.n), pct: Math.round(c.share * 100) })}</title></rect>
            {/each}
          </svg>
          <span class="small period">
            {#if r.period}<span data-testid="rhythm-period">{r.period}</span>{/if}
            {#if r.knownPeriodic}<span class="badge">{t('deviceWidgets.rhythm.usual')}</span>
            {:else if (r.regularHours ?? 0) >= 4}<span class="badge warn">{t('deviceWidgets.rhythm.newRhythm')}</span>{/if}
          </span>
        {/each}
        <span></span>
        <svg width={W} height="14" viewBox="0 0 {W} 14" aria-hidden="true" class="axis">
          {#each ticks as tick (tick.t)}
            <text x={x(tick.t)} y="11" text-anchor="middle">{t(tick.unit, { n: tick.n })}</text>
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
