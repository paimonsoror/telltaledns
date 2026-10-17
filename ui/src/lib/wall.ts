// REQ: OBS-035 (ADR-135) — the wall display's moving parts, kept free of Svelte and the DOM so
// the tests can check them directly: the panel list from the URL, tile tweens, the particle
// budget, the live ticker's buffer, and an animation loop that stops when the tab is hidden.

export const PANELS = ['map', 'flow', 'slo', 'latency', 'heat', 'kpi'] as const;
export type Panel = (typeof PANELS)[number];
export const PANEL_TITLE: Record<Panel, string> = {
  map: 'What the network is reaching',
  flow: 'Where queries go',
  slo: 'Service level',
  latency: 'Answer time',
  heat: 'The week',
  kpi: 'Right now',
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

// ---- REQ: OBS-035 (T14.15, ADR-141) — layouts for the screen's size and shape.

/** The kinds of screen a wall meets, from its size in CSS pixels. */
export const SCREEN_CLASSES = ['compact', 'portrait', 'standard', 'ultrawide', 'large'] as const;
export type ScreenClass = (typeof SCREEN_CLASSES)[number];

/** `compact` (shorter side under 600), `portrait` (taller than 1.2 × wide), `large` (2560 × 1300
 * and up), `ultrawide` (2.1 × as wide as tall), else `standard`. */
export function screenClass(w: number, h: number): ScreenClass {
  if (Math.min(w, h) < 600) return 'compact';
  if (h > 1.2 * w) return 'portrait';
  if (w >= 2560 && h >= 1300) return 'large';
  if (w >= 2.1 * h) return 'ultrawide';
  return 'standard';
}

/** [`screenClass`] that keeps `prev` while a 4 % change would still give it, so a window
 * resized across a boundary doesn't flip back and forth. */
export function screenClassStable(w: number, h: number, prev: ScreenClass | null): ScreenClass {
  const now = screenClass(w, h);
  if (!prev || now === prev) return now;
  for (const f of [0.96, 1.04]) {
    if (screenClass(w * f, h) === prev || screenClass(w, h * f) === prev) return prev;
  }
  return now;
}

/** Each panel's smallest useful size (CSS px). */
export const PANEL_MIN: Record<Panel, { w: number; h: number }> = {
  map: { w: 420, h: 280 },
  flow: { w: 520, h: 300 },
  slo: { w: 300, h: 240 },
  latency: { w: 420, h: 200 },
  heat: { w: 480, h: 200 },
  kpi: { w: 240, h: 150 },
};

/** Panels that read well small: the side slots take them first. */
const SMALL_FIRST: Panel[] = ['kpi', 'slo'];

/** A slot as fractions of the panel area. */
export interface SlotFrac {
  x: number;
  y: number;
  w: number;
  h: number;
}

const F = (x: number, y: number, w: number, h: number): SlotFrac => ({ x, y, w, h });
const T3 = 1 / 3;

/** Candidate layouts per screen class, most slots first; the first slot is the hero. */
export const TEMPLATES: Record<ScreenClass, SlotFrac[][]> = {
  compact: [[F(0, 0, 1, 1)]],
  portrait: [[F(0, 0, 1, 0.6), F(0, 0.6, 1, 0.4)], [F(0, 0, 1, 1)]],
  standard: [
    [F(0, 0, 0.66, 1), F(0.66, 0, 0.34, 0.5), F(0.66, 0.5, 0.34, 0.5)],
    [F(0, 0, 0.64, 1), F(0.64, 0, 0.36, 1)],
    [F(0, 0, 1, 1)],
  ],
  ultrawide: [
    [F(0.25, 0, 0.5, 1), F(0, 0, 0.25, 0.5), F(0, 0.5, 0.25, 0.5), F(0.75, 0, 0.25, 0.5), F(0.75, 0.5, 0.25, 0.5)],
    [F(0.25, 0, 0.5, 1), F(0, 0, 0.25, 1), F(0.75, 0, 0.25, 1)],
    [F(0, 0, 0.66, 1), F(0.66, 0, 0.34, 1)],
    [F(0, 0, 1, 1)],
  ],
  large: [
    [F(0, 0, T3, 0.5), F(T3, 0, T3, 0.5), F(2 * T3, 0, T3, 0.5), F(0, 0.5, T3, 0.5), F(T3, 0.5, T3, 0.5), F(2 * T3, 0.5, T3, 0.5)],
    [F(0, 0, 0.5, 0.5), F(0.5, 0, 0.5, 0.5), F(0, 0.5, 0.5, 0.5), F(0.5, 0.5, 0.5, 0.5)],
    [F(0, 0, 1, 1)],
  ],
};

/** `?layout=`: `auto` (the default), `single` (one panel at a time, full screen), `grid` (the
 * large screen's grid whatever the size), or a screen class to force. */
export type LayoutMode = 'auto' | 'single' | 'grid' | ScreenClass;
export function parseLayout(text: string | null | undefined): LayoutMode {
  const t = (text ?? '').trim();
  return t === 'single' || t === 'grid' || (SCREEN_CLASSES as readonly string[]).includes(t) ? (t as LayoutMode) : 'auto';
}

/** A placed slot: its rectangle (CSS px) and the panels it shows, rotating when more than one. */
export interface Slot extends Box {
  panels: Panel[];
}

export interface Layout {
  cls: ScreenClass;
  slots: Slot[];
  /** The live tail as a column beside the panels (large screens) instead of a strip. */
  tailSide: boolean;
}

/** Fits `panels` (in their order) into the first template of the class (most slots first) that
 * gives every slot a panel at least its minimum size: the hero takes the first panel that fits
 * it, small side slots prefer the panels that read well small; leftovers rotate in a slot they
 * fit (the hero first). Deterministic. */
export function chooseLayout(
  w: number,
  h: number,
  panels: Panel[],
  mode: LayoutMode = 'auto',
  prev: ScreenClass | null = null,
): Layout {
  const cls: ScreenClass = mode === 'grid' ? 'large' : mode === 'auto' || mode === 'single' ? screenClassStable(w, h, prev) : mode;
  const templates = mode === 'single' ? [[F(0, 0, 1, 1)]] : TEMPLATES[cls];
  const fits = (p: Panel, b: Box) => b.w >= PANEL_MIN[p].w && b.h >= PANEL_MIN[p].h;
  for (const t of templates) {
    if (t.length > panels.length) continue;
    const boxes: Box[] = t.map((f) => ({ x: f.x * w, y: f.y * h, w: f.w * w, h: f.h * h }));
    const left = [...panels];
    const take = (b: Box, order: Panel[]) => {
      const p = order.find((x) => left.includes(x) && fits(x, b));
      if (p) left.splice(left.indexOf(p), 1);
      return p;
    };
    const chosen: (Panel | undefined)[] = [];
    // The hero: the first panel that fits, saving the small-first ones for the side slots.
    const big = left.filter((p) => !SMALL_FIRST.includes(p));
    chosen.push(take(boxes[0], big.length ? big : left));
    for (let i = 1; i < boxes.length; i++) {
      // A small slot (under 30 % of the screen) prefers the panels that read well small.
      const smallSlot = boxes[i].w * boxes[i].h < 0.3 * w * h;
      const small = smallSlot ? SMALL_FIRST.filter((p) => left.includes(p)) : [];
      chosen.push(take(boxes[i], [...small, ...left.filter((p) => !small.includes(p))]));
    }
    if (chosen.some((c) => c === undefined)) continue;
    const slots: Slot[] = boxes.map((b, i) => ({ ...b, panels: [chosen[i] as Panel] }));
    for (const p of left) (slots.find((x) => fits(p, x)) ?? slots[0]).panels.push(p);
    return { cls, slots, tailSide: cls === 'large' && mode !== 'single' };
  }
  return { cls, slots: [{ x: 0, y: 0, w, h, panels: [...panels] }], tailSide: false };
}

/** REQ: OBS-035 (T14.15) — one animation loop for every panel on the wall: frame callbacks
 * register and unregister, and the loop runs while any is registered and the tab is visible. */
export class FrameHub {
  private cbs = new Set<(dt: number) => void>();
  private loop: Loop;
  constructor(host: LoopHost) {
    this.loop = new Loop((dt) => {
      for (const cb of this.cbs) cb(dt);
    }, host);
  }
  get size(): number {
    return this.cbs.size;
  }
  get running(): boolean {
    return this.loop.running;
  }
  add(cb: (dt: number) => void): () => void {
    this.cbs.add(cb);
    this.loop.start();
    return () => {
      this.cbs.delete(cb);
      if (this.cbs.size === 0) this.loop.stop();
    };
  }
  visibility() {
    this.loop.visibility();
  }
}

let hub: FrameHub | null = null;
/** The page's one hub (made on first use). */
export function frameHub(): FrameHub {
  hub ??= new FrameHub(browserHost());
  return hub;
}
