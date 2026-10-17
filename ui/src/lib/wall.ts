// REQ: OBS-035 (ADR-135) — the wall display's moving parts, kept free of Svelte and the DOM so
// the tests can check them directly: the panel list from the URL, tile tweens, the particle
// budget, the live ticker's buffer, and an animation loop that stops when the tab is hidden.

export const PANELS = ['map', 'flow', 'slo', 'latency', 'heat'] as const;
export type Panel = (typeof PANELS)[number];
export const PANEL_TITLE: Record<Panel, string> = {
  map: 'What the network is reaching',
  flow: 'Where queries go',
  slo: 'Service level',
  latency: 'Answer time',
  heat: 'The week',
};

/** `?panels=slo,flow` in that order; unknown names dropped; none (or nothing valid): all. */
export function parsePanels(text: string | null | undefined): Panel[] {
  const out: Panel[] = [];
  for (const p of (text ?? '').split(',').map((s) => s.trim())) {
    if ((PANELS as readonly string[]).includes(p) && !out.includes(p as Panel)) out.push(p as Panel);
  }
  return out.length ? out : [...PANELS];
}

/** `?every=` seconds per panel: 20 by default, 5 to 600. */
export function parseEvery(text: string | null | undefined): number {
  const n = Number(text);
  return Number.isFinite(n) && n > 0 ? Math.min(600, Math.max(5, Math.round(n))) : 20;
}

/** Animation unless the viewer asked for less (`prefers-reduced-motion`) or `?motion=off`. */
export function motionAllowed(param: string | null | undefined, reducedMotion: boolean): boolean {
  return !reducedMotion && param !== 'off';
}

export interface Box {
  x: number;
  y: number;
  w: number;
  h: number;
}

/** Eases a tween's progress (smoothstep). */
export const ease = (t: number) => {
  const c = Math.min(1, Math.max(0, t));
  return c * c * (3 - 2 * c);
};

/** The rects between two layouts at `t` (0 to 1), by key: a new key grows from its own centre.
 * At 0 the shared keys are exactly where they were; at 1 every key is exactly at `to`. */
export function lerpBoxes(from: Map<string, Box>, to: Map<string, Box>, t: number): Map<string, Box> {
  const out = new Map<string, Box>();
  if (t >= 1) {
    for (const [k, b] of to) out.set(k, { ...b });
    return out;
  }
  const u = Math.max(0, t);
  for (const [k, b] of to) {
    const a = from.get(k) ?? { x: b.x + b.w / 2, y: b.y + b.h / 2, w: 0, h: 0 };
    out.set(k, {
      x: a.x + (b.x - a.x) * u,
      y: a.y + (b.y - a.y) * u,
      w: a.w + (b.w - a.w) * u,
      h: a.h + (b.h - a.h) * u,
    });
  }
  return out;
}

/** At most this many particles on the flow at once. */
export const MAX_DOTS = 60;

/** Particles per link, proportional to its count (floored), never more than `cap` in all. */
export function dotBudget(counts: number[], cap = MAX_DOTS): number[] {
  const total = counts.reduce((a, n) => a + Math.max(0, n), 0);
  if (total <= 0) return counts.map(() => 0);
  return counts.map((n) => Math.floor((cap * Math.max(0, n)) / total));
}

export interface Dot {
  link: number;
  /** Where along the link, 0 to 1. */
  t: number;
}

/** The flow's particles: each link's budget of dots, evenly spaced, moving along it. */
export class Particles {
  dots: Dot[] = [];
  constructor(readonly cap = MAX_DOTS) {}

  /** New links (or counts): dots re-planned within the cap. */
  plan(counts: number[]) {
    const budget = dotBudget(counts, this.cap);
    this.dots = [];
    budget.forEach((n, link) => {
      for (let i = 0; i < n; i++) this.dots.push({ link, t: i / n });
    });
  }

  /** Moves every dot on by `dt` seconds (a link takes `secondsPerLink`). */
  step(dt: number, secondsPerLink = 4) {
    const d = dt / secondsPerLink;
    for (const p of this.dots) p.t = (p.t + d) % 1;
  }
}

/** The newest `cap` items, newest first; never grows past `cap`. */
export class Ticker<T> {
  items: T[] = [];
  constructor(readonly cap = 50) {}

  /** Adds a batch in arrival order (oldest first). */
  push(batch: T[]) {
    if (batch.length === 0) return;
    const newest = batch.slice(-this.cap).reverse();
    this.items = [...newest, ...this.items].slice(0, this.cap);
  }
}

/** The pieces of the page an animation loop needs (the real ones in the browser). */
export interface LoopHost {
  request: (cb: (t: number) => void) => number;
  cancel: (id: number) => void;
  hidden: () => boolean;
}

/** A requestAnimationFrame loop that runs only while started and the tab is visible. */
export class Loop {
  private id: number | null = null;
  private last: number | null = null;
  private on = false;
  constructor(
    private readonly frame: (dt: number) => void,
    private readonly host: LoopHost,
  ) {}

  get running(): boolean {
    return this.id !== null;
  }

  start() {
    this.on = true;
    this.schedule();
  }

  stop() {
    this.on = false;
    this.unschedule();
  }

  /** Call on `visibilitychange`: a hidden tab draws nothing. */
  visibility() {
    if (this.host.hidden()) this.unschedule();
    else this.schedule();
  }

  private schedule() {
    if (!this.on || this.id !== null || this.host.hidden()) return;
    this.id = this.host.request((t) => {
      this.id = null;
      const dt = this.last == null ? 0 : Math.min(0.25, (t - this.last) / 1000);
      this.last = t;
      this.frame(dt);
      this.schedule();
    });
  }

  private unschedule() {
    if (this.id !== null) this.host.cancel(this.id);
    this.id = null;
    this.last = null;
  }
}

/** The browser's loop host. */
export const browserHost = (): LoopHost => ({
  request: (cb) => requestAnimationFrame(cb),
  cancel: (id) => cancelAnimationFrame(id),
  hidden: () => document.visibilityState !== 'visible',
});
