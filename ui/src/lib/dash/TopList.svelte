<script lang="ts">
  // REQ: API-005, OBS-037 (ADR-157) — a top list that never widens its card, however long the
  // names are. Every row is one line; what doesn't fit is one tap away.
  //  - A name is shown by what it is (`names.ts`): a Kubernetes service by its own name with the
  //    namespace as a tag, a pod's search-list expansions as the one real name they started from
  //    (merged into one row), hash labels shortened, reverse zones as the address.
  //  - Whatever is still too long gives up its subdomain first (`…metrics.` shrinks, the part that
  //    says who owns it stays); a single long label keeps its end; a tag gives way before the name.
  //  - A device's groups are dots with the name on hover, and a pod's own name is its workload's.
  //  - Tap the count for the full name with a Copy button and, where the display differs from the
  //    name, one sentence saying how.
  //  - REQ: OBS-004 (ADR-159) — a device's queries split by how they were answered: a thin bar under
  //    its name (as long as its share of the busiest, in the status colours), and the numbers in the
  //    tap panel.
  import type { S } from '../api';
  import ClientChip from '../components/ClientChip.svelte';
  import DomainIcon from '../icons/DomainIcon.svelte';
  import { num } from '../format';
  import { parseName, workloadName, type Parsed } from './names';
  import { tk, tr } from '../i18n';
  import T from '../i18n/T.svelte';
  const { t, m } = tr('topList');

  let {
    items,
    kind,
    link,
    groupColor = () => 'var(--muted)',
    limit = 10,
    onchanged,
    smart = true,
    merge = true,
  }: {
    items: S['TopItem'][];
    kind: 'domains' | 'blocked' | 'clients';
    /** Where a row goes; `merged` is true for a row that stands for several names. */
    link: (key: string, merged: boolean) => string;
    groupColor?: (name: string) => string;
    limit?: number;
    onchanged?: () => void;
    /** Read names by what they are (Kubernetes, hashes, reverse zones). */
    smart?: boolean;
    /** One row for a real name that pods asked with several search suffixes added. */
    merge?: boolean;
  } = $props();

  interface Row {
    it: S['TopItem'];
    p: Parsed | null;
    count: number;
    /** The names merged into this row (more than one only for search-suffix expansions). */
    variants: { key: string; count: number }[];
  }
  // A pod's search list turns one lookup into several (`api.example.com.<ns>.svc.cluster.local`,
  // `….svc.cluster.local`, `….cluster.local`): they are one question, so they get one row.
  const rows = $derived.by((): Row[] => {
    const out: Row[] = [];
    const byMain = new Map<string, Row>();
    for (const it of items) {
      const p = kind !== 'clients' && smart ? parseName(it.key) : null;
      if (p && merge && p.kind === 'expansion') {
        const g = byMain.get(p.main);
        if (g) {
          g.count += it.count;
          g.variants.push({ key: it.key, count: it.count });
          continue;
        }
        const r: Row = { it, p, count: it.count, variants: [{ key: it.key, count: it.count }] };
        byMain.set(p.main, r);
        out.push(r);
        continue;
      }
      out.push({ it, p, count: it.count, variants: [] });
    }
    return out.sort((a, b) => b.count - a.count);
  });
  const shown = $derived(rows.slice(0, limit));
  const max = $derived(Math.max(1, ...rows.map((r) => r.count)));
  const total = $derived(Math.max(1, rows.reduce((a, r) => a + r.count, 0)));
  let open = $state<Record<string, boolean>>({});
  let copied = $state('');

  /** The part of a name that identifies who it belongs to, and the labels before it. */
  function cut(name: string): [string, string] {
    const p = name.replace(/\.$/, '').split('.');
    if (p.length <= 2) return ['', name];
    const k = p[p.length - 1].length === 2 && p[p.length - 2].length <= 3 && p.length > 3 ? 3 : 2;
    return [p.slice(0, -k).join('.') + '.', p.slice(-k).join('.')];
  }
  /** A single long label keeps its end (`…-headless`), where the cut-off lands in the middle. */
  function ends(label: string): [string, string] {
    return !label.includes('.') && label.length > 22 ? [label.slice(0, -7), label.slice(-7)] : [label, ''];
  }
  const pctOf = (v: number, t: number) => (t ? `${((v / t) * 100).toFixed(v / t < 0.1 ? 1 : 0)}%` : '–');

  // A device's split: blocked, cached (stale and refreshed included) and forwarded come from the API;
  // "other" is the rest of its count (local, special, refused, …, and the sketch's error bound).
  const COLORS = { blocked: '--s-blocked', cached: '--s-cached', forwarded: '--s-forwarded', other: '--s-other' } as const;
  /** REQ: API-012 — how each part is named (`k` stays the status). */
  const PART_TEXT = { blocked: m('blocked'), cached: m('cached'), forwarded: m('forwarded'), other: m('other') } as const;
  function splitOf(it: S['TopItem'], count: number) {
    const s = it.byStatus;
    if (!s) return null;
    const other = Math.max(0, count - s.blocked - s.cached - s.forwarded);
    return (['blocked', 'cached', 'forwarded', 'other'] as const)
      .map((k) => ({ k, n: k === 'other' ? other : s[k], color: COLORS[k] }))
      .filter((p) => p.n > 0);
  }
  const splitText = (parts: { k: keyof typeof PART_TEXT; n: number }[]) => parts.map((p) => `${num(p.n)} ${tk(PART_TEXT[p.k])}`).join(' · ');

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      copied = text;
      setTimeout(() => (copied = ''), 1500);
    } catch {
      // No clipboard (an insecure page): the name is selectable in the panel.
    }
  }
</script>

{#if shown.length === 0}
  <p class="empty">{t('Nothing yet.')}</p>
{:else}
  <ol class="tl">
    {#each shown as r (r.it.key)}
      {@const it = r.it}
      {@const p = r.p}
      {@const merged = r.variants.length > 1}
      {@const target = merged ? (p?.main ?? it.key) : it.key}
      {@const [sub, base] = p ? cut(p.main) : kind === 'clients' ? ['', ''] : cut(it.key)}
      {@const [head, tail] = ends(base)}
      {@const tag = merged ? t('search suffix ×{n}', { n: r.variants.length }) : (p?.tag ?? '')}
      {@const sp = kind === 'clients' ? splitOf(it, r.count) : null}
      <li class:open={open[it.key]} style:--w={`${(r.count / max) * 100}%`}>
        <div class="line">
          <span class="who">
            {#if kind === 'clients'}
              <span class="dev"><ClientChip ip={it.key} name={it.name} display={it.name ? workloadName(it.name) : undefined} {onchanged} /></span>
              {#each it.groups ?? [] as g (g)}<i class="gdot" style:--gc={groupColor(g)} title={g} translate="no"></i>{/each}
            {:else}
              <!-- REQ: OBS-039 (ADR-167) — the name's mark; nothing when icons are off. -->
              <DomainIcon name={target} quiet={kind === 'blocked'} />
              <a class="dom" href={link(target, merged)} title={p?.note || it.key} aria-label={target}>{#if sub}<span class="sub" translate="no">{sub}</span>{/if}{#if tail}<span class="head" translate="no">{head}</span><span class="tail" translate="no">{tail}</span>{:else}<span class="base" translate="no">{base}</span>{/if}</a>
              {#if tag}<span class="tag">{tag}</span>{/if}
            {/if}
          </span>
          <button class="n" aria-expanded={!!open[it.key]} aria-label={t('Details for {name}', { name: it.name ?? p?.main ?? it.key })} onclick={() => (open[it.key] = !open[it.key])}>
            <span class="num">{num(r.count)}</span><span class="chev" aria-hidden="true"></span>
          </button>
        </div>
        {#if sp}
          <div class="sp" role="img" aria-label={splitText(sp)} title={splitText(sp)} data-testid="client-split">
            {#each sp as q (q.k)}<span style:flex-grow={q.n} style:background={`var(${q.color})`}></span>{/each}
          </div>
        {/if}
        {#if open[it.key]}
          <div class="more">
            {#if merged}
              <p class="small muted">
                <T ctx="topList" msg={"Pods asked for <b>{name}</b> with each of their DNS search suffixes added, so it's one question that looks like {n}:"} params={{ name: p?.main, n: r.variants.length }}
                  >{#snippet b(text: string)}<b class="real" translate="no">{text}</b>{/snippet}</T
                >
              </p>
              <ul class="vars">
                {#each r.variants as v (v.key)}
                  <li><code translate="no">{v.key}</code><b>{num(v.count)}</b></li>
                {/each}
              </ul>
            {:else}
              <div class="full">
                <code translate="no">{it.key}</code>
                <button class="link small" onclick={() => copy(it.key)}>{copied === it.key ? t('Copied') : t('Copy')}</button>
              </div>
              {#if it.name && kind === 'clients'}<div class="small muted" translate="no">{it.name}</div>{/if}
              {#if p?.note}<p class="small muted">{p.note}</p>{/if}
            {/if}
            {#if sp}
              <ul class="how">
                {#each sp as q (q.k)}
                  <li><i style:background={`var(${q.color})`}></i><span>{tk(PART_TEXT[q.k])}</span><b>{num(q.n)}</b><span class="muted">{pctOf(q.n, r.count)}</span></li>
                {/each}
              </ul>
            {/if}
            <p class="small muted">
              {#if kind === 'clients'}
                <T ctx="topList" msg={'{n} queries · {share} of this list · <a>Show its queries</a>'} params={{ n: num(r.count), share: pctOf(r.count, total) }}
                  >{#snippet a(text: string)}<a href={link(target, merged)}>{text}</a>{/snippet}</T
                >
              {:else}
                <T ctx="topList" msg={'{n} queries · {share} of this list · <a>Show in the query log</a>'} params={{ n: num(r.count), share: pctOf(r.count, total) }}
                  >{#snippet a(text: string)}<a href={link(target, merged)}>{text}</a>{/snippet}</T
                >
              {/if}
            </p>
          </div>
        {/if}
      </li>
    {/each}
  </ol>
{/if}

<style>
  .tl {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
  }
  li {
    border-bottom: 1px solid var(--surface-2);
  }
  li:last-child {
    border-bottom: 0;
  }
  .line {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    align-items: center;
    gap: 10px;
    padding: 7px 4px;
    min-height: 34px;
  }
  .who {
    display: flex;
    align-items: center;
    gap: 6px;
    min-width: 0;
  }
  .dom {
    display: flex;
    min-width: 0;
    max-width: 100%;
    white-space: nowrap;
  }
  .sub {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    color: var(--muted);
  }
  .base {
    flex: none;
    max-width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  /* One long label: the front gives way, the last few characters stay. */
  .head {
    flex: 0 1 auto;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .tail {
    flex: none;
  }
  /* A word after the name (a namespace, "search suffix"): it gives way before the name does. */
  .tag {
    flex: 0 4 auto;
    min-width: 3.6em;
    max-width: 45%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    padding: 0 6px;
    border-radius: 999px;
    background: var(--surface-2);
    color: var(--muted);
    font-size: 11.5px;
    line-height: 18px;
  }
  /* A device's name stays on one line, however long the workload's. The menu the chip opens is not
     inside the clipped button, so it isn't cut off. */
  .dev {
    display: block;
    flex: 0 1 auto;
    min-width: 0;
  }
  .dev :global(.chip) {
    display: block;
    max-width: 100%;
  }
  .dev :global(.chip-button) {
    display: block;
    max-width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    text-align: left;
  }
  .gdot {
    flex: none;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--gc);
  }
  /* The count is the row's toggle: a quiet chevron says so. */
  .n {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    min-height: 0;
    padding: 2px 2px 2px 6px;
    border: 0;
    border-radius: 6px;
    background: transparent;
    color: inherit;
    font: inherit;
  }
  .n:hover {
    background: color-mix(in srgb, var(--surface-2) 70%, transparent);
  }
  .num {
    font-variant-numeric: tabular-nums;
    text-align: right;
  }
  .chev {
    width: 6px;
    height: 6px;
    border-right: 1.5px solid var(--muted);
    border-bottom: 1.5px solid var(--muted);
    transform: translateY(-1px) rotate(45deg);
    opacity: 0.55;
    transition: transform 0.15s;
  }
  .open > .line .chev {
    transform: translateY(1px) rotate(-135deg);
  }
  @media (prefers-reduced-motion: reduce) {
    .chev {
      transition: none;
    }
  }

  /* How a device's queries were answered: as long as its share of the busiest, in the status colours. */
  .sp {
    display: flex;
    gap: 1px;
    width: max(var(--w), 8px);
    height: 3px;
    margin: -5px 4px 8px;
    border-radius: 3px;
    overflow: hidden;
  }
  .sp span {
    min-width: 1px;
  }
  .how {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: 3px;
    max-width: 320px;
  }
  .how li {
    display: flex;
    align-items: baseline;
    gap: 7px;
    border: 0;
  }
  .how i {
    flex: none;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    align-self: center;
  }
  .how b {
    margin-left: auto;
    font-variant-numeric: tabular-nums;
  }
  .how .muted {
    min-width: 3.4em;
    text-align: right;
    font-variant-numeric: tabular-nums;
  }

  .more {
    display: grid;
    gap: 6px;
    padding: 2px 6px 12px 4px;
    font-size: 12.5px;
  }
  .more p {
    margin: 0;
  }
  .full {
    display: flex;
    align-items: baseline;
    gap: 10px;
  }
  .full code {
    min-width: 0;
    overflow-wrap: anywhere;
    word-break: break-all;
    font-size: 12px;
    user-select: all;
  }
  .real {
    color: var(--text);
    font-weight: 600;
  }
  /* The merged names, one per line with its count. */
  .vars {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: 3px;
  }
  .vars li {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 12px;
    border: 0;
  }
  .vars code {
    min-width: 0;
    overflow-wrap: anywhere;
    font-size: 12px;
  }
  .vars b {
    font-variant-numeric: tabular-nums;
  }
</style>
