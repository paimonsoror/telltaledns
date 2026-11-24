// REQ: OBS-033 (ADR-133) — change markers: one fetch per page window, shared by every chart on
// the page (one request per window change, not one per chart), the Changes toggle (remembered
// in this browser), and the kind filter.
import { api, type S } from './api';
import type { MessageKey } from './i18n';

export interface Marker {
  /** Unix seconds. */
  time: number;
  kind: string;
  summary: string;
  href?: string;
  actor?: string;
  /** The nodes it happened on (one marker for the same change on several nodes). */
  nodes: string[];
}

/** Every kind, in the order the filter chips show them. */
export const KINDS: { id: string; label: MessageKey }[] = [
  { id: 'config.applied', label: 'cluster.configuration' },
  { id: 'note', label: 'annotations.kind.note' },
  { id: 'lists.refreshed', label: 'nav.lists' },
  { id: 'rollout.stage', label: 'cluster.rollouts.title' },
  { id: 'build.started', label: 'annotations.kind.buildStarted' },
  { id: 'node.restarted', label: 'annotations.kind.nodeRestarted' },
  { id: 'maintenance.entered', label: 'cluster.maint.title' },
  { id: 'drill.started', label: 'cluster.drills.title' },
  { id: 'blocking.paused', label: 'annotations.kind.blockingPaused' },
  { id: 'cache.flushed', label: 'nav.cache' },
  { id: 'upstream.breaker', label: 'annotations.kind.upstreamBreaker' },
];
/** Kinds a chip stands for besides its own. */
const ALSO: Record<string, string[]> = {
  'maintenance.entered': ['maintenance.left'],
  'drill.started': ['drill.ended'],
  'blocking.paused': ['blocking.resumed'],
};

/** Lines of one change from several nodes: the same kind and sequence (or summary) within a minute. */
export function merge(items: S['Annotation'][]): Marker[] {
  const out: (Marker & { key: string })[] = [];
  // Oldest first, so each group is anchored at its first node's time.
  for (const a of [...items].sort((x, y) => x.tUnixMs - y.tUnixMs)) {
    const key = `${a.kind}|${a.seq ?? a.summary}`;
    const time = a.tUnixMs / 1000;
    const same = out.find((m) => m.key === key && time - m.time <= 60);
    if (same) {
      if (a.node && !same.nodes.includes(a.node)) same.nodes.push(a.node);
      same.actor ??= a.actor ?? undefined;
      continue;
    }
    out.push({
      key,
      time,
      kind: a.kind,
      summary: a.summary,
      href: a.href ?? undefined,
      actor: a.actor ?? undefined,
      nodes: [...(a.nodes ?? []), ...(a.node ? [a.node] : [])],
    });
  }
  return out.map(({ key: _key, ...m }) => m).sort((x, y) => y.time - x.time);
}

const SHOW = 'dashboard.changes';
const KINDS_KEY = 'dashboard.changeKinds';
/** The same window is fetched again at most this often (a page polling every 5 s doesn't). */
const REFRESH_MS = 60_000;

function stored(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}
function store(key: string, v: string) {
  try {
    localStorage.setItem(key, v);
  } catch {
    // Private windows and blocked storage: the choice just isn't remembered.
  }
}

class Changes {
  /** The Changes toggle (default on). */
  show = $state(stored(SHOW) !== 'off');
  /** Chip ids switched off. */
  hidden = $state<string[]>((stored(KINDS_KEY) ?? '').split(',').filter(Boolean));
  all = $state<Marker[]>([]);
  missingNodes = $state<string[]>([]);
  truncated = $state(false);
  error = $state<unknown>(null);
  /** The "Note…" form is open. */
  noting = $state(false);
  private key = '';
  private at = 0;

  /** The markers the charts draw: none when the toggle is off. */
  get markers(): Marker[] {
    if (!this.show) return [];
    const off = new Set(this.hidden.flatMap((h) => [h, ...(ALSO[h] ?? [])]));
    return this.all.filter((m) => !off.has(m.kind));
  }

  toggle(on: boolean) {
    this.show = on;
    store(SHOW, on ? 'on' : 'off');
  }

  setKind(id: string, on: boolean) {
    this.hidden = on ? this.hidden.filter((h) => h !== id) : [...new Set([...this.hidden, id])];
    store(KINDS_KEY, this.hidden.join(','));
  }

  /** Fetches the window's markers when the window or scope changed, or a minute went by. */
  async load(from: string, scope?: string, force = false) {
    const key = `${from}|${scope ?? ''}`;
    if (!force && key === this.key && Date.now() - this.at < REFRESH_MS) return;
    this.key = key;
    this.at = Date.now();
    try {
      const p = await api.annotations({ from, scope, limit: 2000 });
      if (key !== this.key) return; // a newer window was asked for meanwhile
      this.all = merge(p.items);
      this.missingNodes = p.missingNodes ?? [];
      this.truncated = p.truncated;
      this.error = null;
    } catch (e) {
      this.error = e;
    }
  }

  /** Fetches the current window again now (after adding a note). */
  refresh() {
    const [from, scope] = this.key.split('|');
    return this.load(from || '-24h', scope || undefined, true);
  }
}

export const changes = new Changes();
