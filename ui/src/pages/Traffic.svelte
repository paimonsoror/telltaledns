<script lang="ts">
  // REQ: OBS-026 (ADR-123) — traffic map: what the network is reaching, one tile per service,
  // site, or name, sized by queries this hour; allowed in blue, blocked in red. Built only on
  // the existing top lists (`/stats/top`), so it adds nothing to the query path.
  import { api, type S } from '../lib/api';
  import { href } from '../lib/router.svelte';
  import { poll } from '../lib/poll';
  import { num, pct, short, timeOfDay } from '../lib/format';
  import { squarify } from '../lib/treemap';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import { tr } from '../lib/i18n';
  const { t } = tr('traffic');

  type Mode = 'service' | 'site' | 'name';
  type Show = 'all' | 'allowed' | 'blocked';
  type Status = 'allowed' | 'blocked';
  interface Tile {
    id: string;
    status: Status;
    label: string;
    /** A service from the catalog (not a domain). */
    service: boolean;
    count: number;
    /** Queries since the previous refresh. */
    delta: number;
    members: { name: string; count: number }[];
  }

  const REFRESH_MS = 5000;
  // The most each list reports (`TOP_REPORTED`).
  const LIMIT = 100;
  // Tiles drawn with a "growing now" ring.
  const HOT = 5;

  let mode = $state<Mode>(remembered('traffic.mode', 'service') as Mode);
  let show = $state<Show>('all');
  let hour = $state<S['Hour']>('current');
  let allowed = $state<S['TopItem'][]>([]);
  let blocked = $state<S['TopItem'][]>([]);
  let deltas = $state(new Map<string, number>());
  let services = new Map<string, string>();
  let refreshed = $state<Date | null>(null);
  let error = $state<unknown>(null);
  let hover = $state<Tile | null>(null);
  let w = $state(0);
  let h = $state(0);

  function remembered(key: string, fallback: string): string {
    try {
      return localStorage.getItem(key) ?? fallback;
    } catch {
      return fallback;
    }
  }
  $effect(() => {
    try {
      localStorage.setItem('traffic.mode', mode);
    } catch {
      // Private windows and blocked storage: the choice just isn't remembered.
    }
  });

  // The previous refresh's counts, per `status:name`, for "growing now".
  let last = new Map<string, number>();
  let lastHour: S['Hour'] | null = null;

  async function load() {
    const hr = hour;
    try {
      if (services.size === 0) {
        const s = await api.services().catch(() => null);
        const m = new Map<string, string>();
        for (const svc of s?.items ?? []) for (const d of svc.domains) m.set(d.toLowerCase(), svc.name);
        services = m;
      }
      const [a, b] = await Promise.all([
        api.top('domains', LIMIT, undefined, undefined, undefined, hr),
        api.top('blocked', LIMIT, undefined, undefined, undefined, hr),
      ]);
      if (hr !== hour) return;
      // The domains list counts every query, blocked ones too: what was answered is the
      // difference, and a remainder within the sketch's error is a name that was only blocked.
      const blockedBy = new Map(b.items.map((i) => [i.key, i.count]));
      const answered = a.items
        .map((i) => ({ ...i, count: i.count - (blockedBy.get(i.key) ?? 0) }))
        .filter((i) => i.count > i.errorBound);
      const now = new Map<string, number>();
      for (const i of answered) now.set(`allowed:${i.key}`, i.count);
      for (const i of b.items) now.set(`blocked:${i.key}`, i.count);
      const d = new Map<string, number>();
      // Only within the same hour list: a new hour starts every count again.
      if (hr === 'current' && lastHour === 'current') {
        for (const [k, c] of now) {
          const p = last.get(k);
          if (p !== undefined && c > p) d.set(k, c - p);
        }
      }
      last = now;
      lastHour = hr;
      allowed = answered;
      blocked = b.items;
      deltas = d;
      refreshed = new Date();
      error = null;
    } catch (e) {
      error = e;
    }
  }

  $effect(() => {
    void hour;
    return poll(load, REFRESH_MS);
  });

  // Country codes that sell names one level down (example.co.uk); a rough stand-in for the
  // public suffix list, which the UI doesn't ship.
  const SECOND_LEVEL = new Set(['co', 'com', 'net', 'org', 'gov', 'edu', 'ac', 'ne', 'or', 'go', 'gob', 'mil']);
  function site(name: string): string {
    const l = name.toLowerCase().replace(/\.$/, '').split('.');
    if (l.length <= 2) return l.join('.');
    const n = l[l.length - 1].length === 2 && SECOND_LEVEL.has(l[l.length - 2]) ? 3 : 2;
    return l.slice(-n).join('.');
  }
  function service(name: string): string | undefined {
    const l = name.toLowerCase().replace(/\.$/, '').split('.');
    for (let i = 0; i < l.length - 1; i++) {
      const s = services.get(l.slice(i).join('.'));
      if (s) return s;
    }
    return undefined;
  }

  const tiles = $derived.by(() => {
    const out = new Map<string, Tile>();
    const add = (status: Status, items: S['TopItem'][]) => {
      for (const i of items) {
        let label = i.key;
        let svc = false;
        if (mode === 'service') {
          const s = service(i.key);
          label = s ?? site(i.key);
          svc = s !== undefined;
        } else if (mode === 'site') {
          label = site(i.key);
        }
        const id = `${status}:${label}`;
        const tile = out.get(id) ?? { id, status, label, service: svc, count: 0, delta: 0, members: [] };
        tile.count += i.count;
        tile.delta += deltas.get(`${status}:${i.key}`) ?? 0;
        tile.members.push({ name: i.key, count: i.count });
        out.set(id, tile);
      }
    };
    if (show !== 'blocked') add('allowed', allowed);
    if (show !== 'allowed') add('blocked', blocked);
    return [...out.values()].sort((a, b) => b.count - a.count);
  });

  const total = $derived(tiles.reduce((a, tile) => a + tile.count, 0));
  const rects = $derived(squarify(tiles.map((tile) => tile.count), w, h));
  // The tiles growing fastest since the last refresh.
  const hot = $derived(
    new Set(
      tiles
        .filter((tile) => tile.delta > 0)
        .sort((a, b) => b.delta - a.delta)
        .slice(0, HOT)
        .map((tile) => tile.id),
    ),
  );
  // Each colour's shade is the tile's size against the biggest of that colour.
  const maxBy = $derived({
    allowed: Math.max(1, ...tiles.filter((tile) => tile.status === 'allowed').map((tile) => tile.count)),
    blocked: Math.max(1, ...tiles.filter((tile) => tile.status === 'blocked').map((tile) => tile.count)),
  });
  const strength = (tile: Tile) => 30 + 70 * Math.sqrt(tile.count / maxBy[tile.status]);

  function link(tile: Tile): string {
    const status = tile.status === 'blocked' ? 'blocked' : undefined;
    if (mode === 'name') return href('/queries', { name: tile.label, match: 'exact', status });
    // A service spans several sites: show the biggest.
    const top = mode === 'service' && tile.service ? site(tile.members[0]?.name ?? tile.label) : tile.label;
    return href('/queries', { name: top, match: 'suffix', status });
  }
  const modes: { id: Mode; label: string }[] = [
    { id: 'service', label: t('Services') },
    { id: 'site', label: t('Sites') },
    { id: 'name', label: t('Names') },
  ];
  const shows: { id: Show; label: string }[] = [
    { id: 'all', label: t('All') },
    { id: 'allowed', label: t('Allowed') },
    { id: 'blocked', label: t('Blocked') },
  ];
  // A tile's status word, as the details and the tile's description say it (language is fixed for
  // the page's life, so these are read once).
  const statusText: Record<Status, string> = { allowed: t('allowed'), blocked: t('blocked') };
  // What the lists cover, and when they were read: one whole sentence for each of the four cases.
  const busiest = $derived(
    hour === 'current'
      ? refreshed
        ? t('The busiest {limit} names and {limit} blocked names this hour, every node; counts are approximate. Updated {time}.', { limit: LIMIT, time: timeOfDay(refreshed) })
        : t('The busiest {limit} names and {limit} blocked names this hour, every node; counts are approximate.', { limit: LIMIT })
      : refreshed
        ? t('The busiest {limit} names and {limit} blocked names in the previous clock hour, every node; counts are approximate. Updated {time}.', { limit: LIMIT, time: timeOfDay(refreshed) })
        : t('The busiest {limit} names and {limit} blocked names in the previous clock hour, every node; counts are approximate.', { limit: LIMIT }),
  );
</script>

<div class="page">
  <div class="page-head">
    <h1>{t('Traffic map')}<HelpButton id="traffic-map" /></h1>
    <div class="row">
      <div class="seg" role="group" aria-label={t('Group by')}>
        {#each modes as m (m.id)}
          <button type="button" aria-pressed={mode === m.id} onclick={() => (mode = m.id)}>{m.label}</button>
        {/each}
      </div>
      <div class="seg" role="group" aria-label={t('Show')}>
        {#each shows as s (s.id)}
          <button type="button" aria-pressed={show === s.id} onclick={() => (show = s.id)}>{s.label}</button>
        {/each}
      </div>
      <span class="pill-field bare">
        <select bind:value={hour} aria-label={t('Hour')}>
          <option value="current">{t('this hour')}</option>
          <option value="previous">{t('previous hour')}</option>
        </select>
      </span>
    </div>
  </div>

  <ErrorNote {error} />

  <section class="card map-card">
    <div class="map" bind:clientWidth={w} bind:clientHeight={h}>
      {#each tiles as tile, i (tile.id)}
        {@const r = rects[i]}
        {#if r && r.w > 0}
          {@const s = strength(tile)}
          <a
            class="tile {tile.status}"
            class:hot={hot.has(tile.id)}
            class:strong={s >= 62}
            href={link(tile)}
            style:left={`${r.x}px`}
            style:top={`${r.y}px`}
            style:width={`${r.w}px`}
            style:height={`${r.h}px`}
            style:--mix={`${s}%`}
            aria-label={t('{label}, {status}, {n} queries', { label: tile.label, status: statusText[tile.status], n: num(tile.count) })}
            onmouseenter={() => (hover = tile)}
            onfocus={() => (hover = tile)}
          >
            {#if r.w > 64 && r.h > 30}
              <span class="name" translate="no">{tile.label}</span>
              {#if r.h > 50}
                <span class="count">{short(tile.count)}{#if tile.delta > 0}<span class="delta"> +{short(tile.delta)}</span>{/if}</span>
              {/if}
            {/if}
          </a>
        {/if}
      {/each}
      {#if tiles.length === 0 && refreshed}
        <p class="empty">{t('No queries yet this hour.')}</p>
      {/if}
    </div>
  </section>

  <section class="card details" aria-live="polite">
    {#if hover}
      {@const tile = tiles.find((x) => x.id === hover?.id) ?? hover}
      <div class="row between">
        <strong translate="no">{tile.label}</strong>
        <span class="badge {tile.status}">{statusText[tile.status]}</span>
      </div>
      <p class="small muted">
        {#if tile.delta > 0}
          {t("{n} queries · {share} of what's shown· +{delta} in the last {secs} s", { n: num(tile.count), share: pct((100 * tile.count) / Math.max(1, total)), delta: num(tile.delta), secs: REFRESH_MS / 1000 })}
        {:else}
          {t("{n} queries · {share} of what's shown", { n: num(tile.count), share: pct((100 * tile.count) / Math.max(1, total)) })}
        {/if}
      </p>
      {#if mode !== 'name'}
        <ul class="members">
          {#each tile.members.slice(0, 8) as m (m.name)}
            <li><a href={href('/queries', { name: m.name, match: 'exact' })}>{m.name}</a><span><a class="when" href={href('/heatmap', { kind: 'name', key: m.name })} aria-label={t('When {name} is asked for', { name: m.name })}>{t('when')}</a> {num(m.count)}</span></li>
          {/each}
          {#if tile.members.length > 8}<li class="muted">{t('and {n} more', { n: tile.members.length - 8 })}</li>{/if}
        </ul>
      {/if}
    {:else}
      <p class="small muted">{t('Point at a tile to see the names behind it. Select one to open them in the query log.')}</p>
    {/if}
    <div class="legend small muted">
      <span><i class="sw allowed"></i>{t('Allowed')}</span>
      <span><i class="sw blocked"></i>{t('Blocked')}</span>
      <span>{t('Bigger and stronger colour = more queries')}</span>
      <span><i class="sw ring"></i>{t('Growing fastest right now')}</span>
      <span>{busiest}</span>
    </div>
  </section>
</div>

<style>
  .map-card {
    padding: 10px;
  }
  .map {
    position: relative;
    height: max(360px, calc(100vh - 330px));
    overflow: hidden;
  }
  .tile {
    position: absolute;
    box-sizing: border-box;
    border: 1px solid var(--surface);
    border-radius: 4px;
    padding: 4px 6px;
    overflow: hidden;
    display: flex;
    flex-direction: column;
    gap: 1px;
    color: var(--text);
    text-decoration: none;
    transition:
      left 0.6s ease,
      top 0.6s ease,
      width 0.6s ease,
      height 0.6s ease,
      background-color 0.6s ease;
  }
  .tile.allowed {
    background: color-mix(in srgb, var(--info) var(--mix), var(--surface));
  }
  .tile.blocked {
    background: color-mix(in srgb, var(--s-blocked) var(--mix), var(--surface));
  }
  .tile.strong {
    color: var(--tm-ink);
  }
  .tile:hover,
  .tile:focus-visible {
    outline: 2px solid var(--focus);
    outline-offset: -2px;
    z-index: 2;
  }
  .tile.hot {
    box-shadow: inset 0 0 0 3px var(--warn);
    animation: pulse 1.6s ease-in-out infinite;
  }
  @keyframes pulse {
    50% {
      box-shadow: inset 0 0 0 1px var(--warn);
    }
  }
  @media (prefers-reduced-motion: reduce) {
    .tile {
      transition: none;
    }
    .tile.hot {
      animation: none;
    }
  }
  .name {
    font-weight: 600;
    font-size: 13px;
    line-height: 1.2;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .count {
    font-size: 12px;
    font-variant-numeric: tabular-nums;
    opacity: 0.85;
  }
  .empty {
    position: absolute;
    inset: 0;
    display: grid;
    place-items: center;
    margin: 0;
    color: var(--muted);
  }
  .details {
    display: grid;
    gap: 8px;
  }
  .between {
    justify-content: space-between;
  }
  .badge {
    font-size: 12px;
    padding: 2px 8px;
    border-radius: 999px;
    color: var(--tm-ink);
  }
  .badge.allowed {
    background: var(--info);
  }
  .badge.blocked {
    background: var(--s-blocked);
  }
  .members {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(min(100%, 280px), 1fr));
    gap: 2px 20px;
    font-size: 13px;
  }
  .members li {
    display: flex;
    justify-content: space-between;
    gap: 8px;
    min-width: 0;
  }
  .members a {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .members span {
    font-variant-numeric: tabular-nums;
    color: var(--muted);
  }
  .legend {
    display: flex;
    flex-wrap: wrap;
    gap: 6px 16px;
    align-items: center;
  }
  .legend span {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }
  .sw {
    display: inline-block;
    width: 12px;
    height: 12px;
    border-radius: 3px;
  }
  .sw.allowed {
    background: var(--info);
  }
  .sw.blocked {
    background: var(--s-blocked);
  }
  .sw.ring {
    box-shadow: inset 0 0 0 2px var(--warn);
  }
</style>
