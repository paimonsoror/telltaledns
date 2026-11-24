// REQ: API-005, CLU-002, OBS-033 (ADR-157) — the dashboard's data: what it loads, how often, and
// the series derived from it. The same loading as the legacy page (`pages/DashboardLegacy.svelte`),
// except that the Advanced-only measures are fetched only in the Advanced view.
import { api, type S } from '../api';
import { poll } from '../poll';
import { currentMode } from '../mode.svelte';
import { clock } from '../format';
import { changes } from '../annotations.svelte';
import { t, type MessageKey } from '../i18n';
import type { RawSeries } from './smooth';

/** The ranges the switch offers. `label` is a getter: it reads the language when it is shown, not
 *  when this module loads. */
export const RANGES = [
  { id: '15m', get label() { return t('flow.window.15m'); }, from: '-15m', step: 'second' as const, secs: 900 },
  { id: '1h', get label() { return t('flow.window.1h'); }, from: '-1h', step: 'minute' as const, secs: 3600 },
  { id: '24h', get label() { return t('flow.window.24h'); }, from: '-24h', step: 'minute' as const, secs: 86400 },
  { id: '48h', get label() { return t('legacy.range.48h'); }, from: '-48h', step: 'minute' as const, secs: 172800 },
  { id: '7d', get label() { return t('flow.window.7d'); }, from: '-7d', step: 'hour' as const, secs: 604800 },
  { id: '30d', get label() { return t('legacy.range.30d'); }, from: '-30d', step: 'hour' as const, secs: 2592000 },
];
export type Range = (typeof RANGES)[number];

const STEP_SECS = { second: 1, minute: 60, hour: 3600, day: 86400 } as const;

export function remembered(): string {
  try {
    return localStorage.getItem('dashboard.scope') ?? '';
  } catch {
    return '';
  }
}
export function remember(scope: string) {
  try {
    localStorage.setItem('dashboard.scope', scope);
  } catch {
    // Private windows and blocked storage: the choice just isn't remembered.
  }
}

/** Every bucket in the window, zeros where nothing happened (the API skips empty ones). */
function dense(items: S['TimeBucket'][], step: number, secs: number): S['TimeBucket'][] {
  const now = Math.floor(Date.now() / 1000);
  const last = Math.floor(now / step) * step;
  const first = Math.floor((now - secs) / step) * step + step;
  const byStart = new Map(items.map((b) => [b.startUnixSeconds, b]));
  const out: S['TimeBucket'][] = [];
  // `sec` rather than `t`: `t` is the translator here.
  for (let sec = first; sec <= last; sec += step) {
    out.push(
      byStart.get(sec) ?? {
        startUnixSeconds: sec,
        total: 0,
        byStatus: {},
        byQtype: {},
        byRcode: {},
        upstreamQueries: 0,
        upstreamFailures: 0,
        byGroup: {},
        blockedByGroup: {},
        slow: 0,
      },
    );
  }
  return out;
}

/** Change as a fraction; null when there's nothing to compare with. */
export function change(now: number | null | undefined, before: number | null | undefined): number | null {
  if (now == null || before == null || !Number.isFinite(now) || !Number.isFinite(before) || before === 0) return null;
  return (now - before) / before;
}

export const STATUS_COLORS: Record<string, string> = {
  blocked: '--s-blocked',
  cached: '--s-cached',
  refreshed: '--s-refreshed',
  forwarded: '--s-forwarded',
  local: '--s-local',
  other: '--s-other',
};

export class DashData {
  range = $state<Range>(RANGES[2]);
  /** REQ: CLU-002 — '' = every node, `node:<id>`, or `site:<name>`. Remembered in this browser only. */
  scope = $state(remembered());
  /** The top lists for one kind of device ('' = everyone). */
  group = $state('');
  domainsView = $state<'internet' | 'internal'>('internet');

  summary = $state<S['Summary'] | null>(null);
  previous = $state<S['Summary'] | null>(null);
  buckets = $state<S['TimeBucket'][]>([]);
  topDomains = $state<S['TopItem'][]>([]);
  topBlocked = $state<S['TopItem'][]>([]);
  topClients = $state<S['TopItem'][]>([]);
  upstreams = $state<S['UpstreamInfo'][]>([]);
  groups = $state<S['GroupInfo'][]>([]);
  nodes = $state<S['ClusterView']['nodes']>([]);
  error = $state<unknown>(null);
  loaded = $state(false);
  #seq = 0;
  #xbusy = false;
  #xscope: string | undefined;

  /** The Advanced view (the header's Simple/Advanced switch): more measures, never different behavior. */
  advanced = $derived(currentMode() === 'advanced');
  /** Advanced only: where time goes (by path, and by wait stage), and the service-level objectives. */
  byPath = $state<S['LatencyRow'][]>([]);
  stages = $state<S['LatencyRow'][]>([]);
  slo = $state<S['SloStatus'] | null>(null);

  groupColor = (n: string) => this.groups.find((g) => g.name === n)?.color ?? 'var(--muted)';

  /** REQ: OBS-004 (ADR-160) — the top lists and active clients follow the range, by whole hours: a
   *  range under a day says from which hour; a group's lists cover this hour only. */
  nowS = $state(Math.floor(Date.now() / 1000));
  rangeLabel = $derived(
    this.range.secs < 86400
      ? t('legacy.sinceTime', { time: clock(Math.floor((this.nowS - this.range.secs) / 3600) * 3600) })
      : t('legacy.lastRange', { range: this.range.label }),
  );
  topLabel = $derived(this.group ? t('legacy.thisHour') : this.rangeLabel);

  times = $derived(this.buckets.map((b) => b.startUnixSeconds));
  stepSecs = $derived(STEP_SECS[this.range.step]);

  /** The words of the status chart's legend, from the catalog so they follow the language; the
   *  English values are the status identifiers themselves. */
  private statusWord(key: string): string {
    const labels: Record<string, MessageKey> = {
      blocked: 'wall.kpi.blocked',
      cached: 'legacy.status.cached',
      refreshed: 'legacy.status.refreshed',
      forwarded: 'legacy.status.forwarded',
      local: 'legacy.status.local',
      other: 'queries.status.other',
    };
    return labels[key] ? t(labels[key]) : key;
  }

  /** The queries by status as the production chart folds them (cached takes stale and refreshed). */
  statusSeries = $derived.by((): RawSeries[] => {
    // DNS-007: answers refreshed in the background count as cached; Advanced shows them apart.
    const adv = this.advanced;
    const keys = adv ? (['blocked', 'cached', 'refreshed', 'forwarded', 'local'] as const) : (['blocked', 'cached', 'forwarded', 'local'] as const);
    const series = [...keys, 'other'].map((k) => ({ label: this.statusWord(k), color: STATUS_COLORS[k], values: [] as number[] }));
    for (const b of this.buckets) {
      let rest = b.total;
      keys.forEach((k, i) => {
        const extra = k === 'cached' ? (b.byStatus['stale'] ?? 0) + (adv ? 0 : (b.byStatus['refreshed'] ?? 0)) : 0;
        const v = (b.byStatus[k] ?? 0) + extra;
        series[i].values.push(v);
        rest -= v;
      });
      series[keys.length].values.push(Math.max(0, rest));
    }
    return series.filter((s) => s.values.some((v) => v > 0));
  });

  /** Queries and their blocked part, for the two-line view. */
  totalSeries = $derived<RawSeries>({ label: t('legacy.queries'), color: '--s-forwarded', values: this.buckets.map((b) => b.total) });
  blockedSeries = $derived<RawSeries>({ label: t('legacy.blocked'), color: '--s-blocked', values: this.buckets.map((b) => b.byStatus['blocked'] ?? 0) });
  /** Ratios: the numerators with their per-bucket totals as the denominators. */
  blockedPctSeries = $derived<RawSeries>({
    label: t('legacy.blocked'),
    color: '--s-blocked',
    values: this.buckets.map((b) => b.byStatus['blocked'] ?? 0),
    den: this.buckets.map((b) => b.total),
  });
  cachedPctSeries = $derived<RawSeries>({
    label: t('legacy.cacheHits'),
    color: '--s-cached',
    values: this.buckets.map((b) => (b.byStatus['cached'] ?? 0) + (b.byStatus['stale'] ?? 0) + (b.byStatus['refreshed'] ?? 0)),
    den: this.buckets.map((b) => b.total),
  });
  failuresSeries = $derived<RawSeries>({ label: t('dashboard.upstreamFailures'), color: '--s-blocked', values: this.buckets.map((b) => b.upstreamFailures) });

  /** Which kinds of devices make the traffic, in each group's color. */
  groupSeries = $derived.by((): RawSeries[] => {
    const names = new Set<string>();
    for (const b of this.buckets) for (const k of Object.keys(b.byGroup ?? {})) names.add(k);
    const color = (n: string) => this.groups.find((g) => g.name === n)?.color ?? '--s-other';
    return [...names]
      .sort()
      .map((n) => ({ label: n, color: color(n), values: this.buckets.map((b) => b.byGroup?.[n] ?? 0) }))
      .filter((s) => s.values.some((v) => v > 0));
  });
  /** Exchanges with upstream resolvers, and the failed ones. */
  upstreamSeries = $derived<RawSeries[]>([
    { label: t('dashboard.upstreamQueries'), color: '--s-forwarded', values: this.buckets.map((b) => b.upstreamQueries) },
    { label: t('dashboard.failures'), color: '--s-blocked', values: this.buckets.map((b) => b.upstreamFailures) },
  ]);
  /** DNS-007: of the answers that weren't blocked or local, the share given from an expired cached copy. */
  refreshedPercent = $derived(
    this.summary && this.summary.cached + this.summary.forwarded > 0 ? ((this.summary.refreshed ?? 0) * 100) / (this.summary.cached + this.summary.forwarded) : null,
  );

  /** The share of answers by status over the range, for the proportion bar. */
  parts = $derived(this.statusSeries.map((s) => ({ label: s.label, color: s.color, value: s.values.reduce((a, v) => a + v, 0) })));

  upstreamP90 = $derived.by(() => {
    const rows = (this.summary?.latency ?? []).filter((r) => r.key.startsWith('upstream'));
    rows.sort((a, b) => b.count - a.count);
    return rows[0] as S['LatencyRow'] | undefined;
  });
  cacheP50 = $derived(
    (this.summary?.latency ?? []).filter((r) => r.key.startsWith('cache')).sort((a, b) => b.count - a.count)[0] as S['LatencyRow'] | undefined,
  );
  prevP90 = $derived(
    (this.previous?.latency ?? []).filter((r) => r.key.startsWith('upstream')).sort((a, b) => b.count - a.count)[0] as S['LatencyRow'] | undefined,
  );

  async load() {
    const seq = ++this.#seq;
    const r = this.range;
    const g = this.group || undefined;
    const sc = this.scope || undefined;
    const tf = g ? undefined : r.from;
    this.nowS = Math.floor(Date.now() / 1000);
    const adv = this.advanced;
    // REQ: OBS-033 — the window's change markers, once for every chart (refetched each minute).
    void changes.load(r.from, sc);
    try {
      // The Advanced extras load on their own, one fetch at a time: the service level can take
      // seconds on a busy or slow node, and neither the rest of the page nor the next poll waits
      // for it (a slow one would otherwise be superseded by every tick and never land).
      if (adv && !(this.#xbusy && this.#xscope === sc)) {
        this.#xbusy = true;
        this.#xscope = sc;
        void Promise.all([api.latency('path', sc), api.latency('stage', sc), api.slo(sc).catch(() => null)])
          .catch(() => null)
          .then((more) => {
            this.#xbusy = false;
            if (!more || sc !== (this.scope || undefined)) return;
            this.byPath = more[0].items;
            this.stages = more[1].items;
            this.slo = more[2];
          });
      }
      const [s, ts, d, b, c, u, gs, cl] = await Promise.all([
        api.summary(r.from, undefined, sc),
        api.timeseries({ from: r.from, step: r.step, scope: sc }),
        // Deeper than the ten shown: pods' search-suffix variants of one name merge into one row.
        api.top(this.domainsView === 'internal' ? 'internal' : 'domains', 25, undefined, g, sc, undefined, tf),
        api.top('blocked', 25, undefined, g, sc, undefined, tf),
        api.top('clients', 10, undefined, g, sc, undefined, tf),
        api.upstreams(),
        api.groups(),
        api.cluster().catch(() => null),
      ]);
      const mins = Math.round(r.secs / 60);
      const prev = await api.summary(`-${2 * mins}m`, `-${mins}m`, sc).catch(() => null);
      // A slower answer for a range or filter the viewer has since left must not replace the newer one.
      if (seq !== this.#seq) return;
      this.summary = s;
      this.previous = prev;
      this.buckets = dense(ts.items, STEP_SECS[r.step], r.secs);
      this.topDomains = d.items;
      this.topBlocked = b.items;
      this.topClients = c.items;
      this.upstreams = u.items;
      this.groups = gs.items;
      this.nodes = cl?.enabled ? cl.nodes : [];
      this.error = null;
      this.loaded = true;
    } catch (e) {
      if (seq === this.#seq) this.error = e;
    }
  }

  /** Call inside an `$effect`: loads now and polls while the page is visible. */
  attach(): () => void {
    void this.range;
    void this.group;
    void this.scope;
    void this.domainsView;
    void this.advanced;
    return poll(() => this.load(), this.range.step === 'second' ? 5000 : 15000);
  }
}
