// REQ: OBS-029 (ADR-129) — the rhythm heatmap's layout: slots (UTC starts from the API) laid
// out by local time, one row per day (or per weekday, folded to the mean), one column per slot of
// the day; and drawing the grid on a canvas. Pure functions, like `treemap.ts`.

export interface Cell {
  /** Queries (folded: the mean over the days it covers); `null` where nothing is known. */
  value: number | null;
  /** The key was in the hour's top list (always true for the network). */
  covered: boolean;
  /** Unix seconds of the slot's start (folded: the latest day's). */
  start: number;
  /** Folded: how many days the mean is over. */
  days: number;
}

export interface Grid {
  rows: { label: string; start: number }[];
  cols: number;
  /** Seconds per column. */
  slot: number;
  cells: Cell[][];
  max: number;
  rowSums: number[];
  colSums: number[];
}

const WEEKDAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];

/** Local midnight (Unix seconds) of the day `t` (Unix seconds) falls in. */
function dayStart(t: number): number {
  const d = new Date(t * 1000);
  d.setHours(0, 0, 0, 0);
  return Math.floor(d.getTime() / 1000);
}

/** The column of `t` within its local day. */
function column(t: number, slot: number, cols: number): number {
  const d = new Date(t * 1000);
  const secs = d.getHours() * 3600 + d.getMinutes() * 60 + d.getSeconds();
  return Math.min(cols - 1, Math.floor(secs / slot));
}

/** Lays slots out by local day (or folded onto Mon..Sun as means). */
export function layout(
  starts: number[],
  values: number[],
  covered: boolean[] | null | undefined,
  slot: number,
  fold: boolean,
): Grid {
  const cols = Math.max(1, Math.round(86_400 / slot));
  const empty = (start: number): Cell => ({ value: null, covered: true, start, days: 0 });
  const rows: { label: string; start: number }[] = [];
  const cells: Cell[][] = [];
  if (fold) {
    const sums = Array.from({ length: 7 }, () => Array.from({ length: cols }, () => ({ sum: 0, n: 0, start: 0, covered: true })));
    starts.forEach((t, i) => {
      const wd = (new Date(t * 1000).getDay() + 6) % 7;
      const c = sums[wd][column(t, slot, cols)];
      if (covered && !covered[i]) {
        c.covered = c.n > 0 ? c.covered : false;
        return;
      }
      c.sum += values[i] ?? 0;
      c.n += 1;
      c.covered = true;
      c.start = Math.max(c.start, t);
    });
    for (let wd = 0; wd < 7; wd++) {
      rows.push({ label: WEEKDAYS[wd], start: 0 });
      cells.push(
        sums[wd].map((c) => ({
          value: c.n ? c.sum / c.n : null,
          covered: c.n > 0 || c.covered,
          start: c.start,
          days: c.n,
        })),
      );
    }
  } else {
    const index = new Map<number, number>();
    starts.forEach((t, i) => {
      const day = dayStart(t);
      let r = index.get(day);
      if (r === undefined) {
        r = rows.length;
        index.set(day, r);
        rows.push({
          label: new Date(day * 1000).toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric' }),
          start: day,
        });
        cells.push(Array.from({ length: cols }, (_, c) => empty(day + c * slot)));
      }
      const cell = cells[r][column(t, slot, cols)];
      cell.start = t;
      cell.days = 1;
      if (covered && !covered[i]) {
        cell.covered = false;
        return;
      }
      cell.value = (cell.value ?? 0) + (values[i] ?? 0);
    });
  }
  let max = 0;
  const rowSums = cells.map((row) => row.reduce((a, c) => a + (c.value ?? 0), 0));
  const colSums = Array.from({ length: cols }, (_, c) => cells.reduce((a, row) => a + (row[c].value ?? 0), 0));
  for (const row of cells) for (const c of row) if (c.value != null) max = Math.max(max, c.value);
  return { rows, cols, slot, cells, max, rowSums, colSums };
}

/** A cell's colour strength, 0..1: a square-root ramp so quiet cells stay visible. */
export function strength(value: number | null, max: number): number {
  if (value == null || value <= 0 || max <= 0) return 0;
  return 0.12 + 0.88 * Math.sqrt(value / max);
}

export interface Geometry {
  /** Where the cells start (after the row labels) and each cell's size. */
  x0: number;
  y0: number;
  cw: number;
  ch: number;
}

/** Cell size for a grid drawn `width` wide (labels and marginals included). */
export function geometry(grid: Grid, width: number, labelWidth: number, marginal: number): Geometry {
  const cw = Math.max(1, (width - labelWidth - marginal - 8) / grid.cols);
  const ch = grid.cols > 100 ? 14 : Math.max(14, Math.min(26, cw));
  return { x0: labelWidth, y0: 18, cw, ch };
}

/** Draws the grid; `ink` is the hue for full strength, `bg` the empty cell, `muted` the text. */
export function draw(
  ctx: CanvasRenderingContext2D,
  grid: Grid,
  g: Geometry,
  colors: { ink: string; bg: string; muted: string; hatch: string },
  focus: [number, number] | null,
  ticks: { row: number; col: number }[] = [],
) {
  const { x0, y0, cw, ch } = g;
  ctx.font = '11px system-ui, sans-serif';
  ctx.textBaseline = 'middle';
  ctx.fillStyle = colors.muted;
  // Hour labels above every few columns.
  const perHour = Math.round(3600 / grid.slot);
  const every = cw * perHour < 22 ? 6 : cw * perHour < 40 ? 3 : 1;
  for (let h = 0; h < 24; h += every) {
    ctx.fillText(String(h).padStart(2, '0'), x0 + h * perHour * cw, 8);
  }
  const maxRow = Math.max(1, ...grid.rowSums);
  grid.rows.forEach((r, ri) => {
    const y = y0 + ri * ch;
    ctx.fillStyle = colors.muted;
    ctx.fillText(r.label, 0, y + ch / 2);
    grid.cells[ri].forEach((c, ci) => {
      const x = x0 + ci * cw;
      if (!c.covered) {
        ctx.fillStyle = colors.bg;
        ctx.fillRect(x, y, Math.max(1, cw - 1), ch - 1);
        ctx.strokeStyle = colors.hatch;
        ctx.lineWidth = 1;
        ctx.beginPath();
        for (let k = -ch; k < cw; k += 4) {
          ctx.moveTo(x + k, y + ch - 1);
          ctx.lineTo(x + k + ch, y);
        }
        ctx.save();
        ctx.rect(x, y, Math.max(1, cw - 1), ch - 1);
        ctx.clip();
        ctx.stroke();
        ctx.restore();
        return;
      }
      const s = strength(c.value, grid.max);
      ctx.fillStyle = colors.bg;
      ctx.fillRect(x, y, Math.max(1, cw - 1), ch - 1);
      if (s > 0) {
        ctx.globalAlpha = s;
        ctx.fillStyle = colors.ink;
        ctx.fillRect(x, y, Math.max(1, cw - 1), ch - 1);
        ctx.globalAlpha = 1;
      }
    });
    // The row's marginal on the right.
    const mx = x0 + grid.cols * cw + 6;
    ctx.globalAlpha = 0.5;
    ctx.fillStyle = colors.ink;
    ctx.fillRect(mx, y + 2, Math.max(1, (40 * grid.rowSums[ri]) / maxRow), ch - 5);
    ctx.globalAlpha = 1;
  });
  // The columns' marginal below.
  const maxCol = Math.max(1, ...grid.colSums);
  const by = y0 + grid.rows.length * ch + 4;
  ctx.globalAlpha = 0.5;
  ctx.fillStyle = colors.ink;
  grid.colSums.forEach((v, ci) => {
    const h = (24 * v) / maxCol;
    ctx.fillRect(x0 + ci * cw, by + 24 - h, Math.max(1, cw - 1), h);
  });
  ctx.globalAlpha = 1;
  // REQ: OBS-033 — change markers: a small tick on the cell's top edge.
  ctx.fillStyle = colors.muted;
  for (const t of ticks) {
    const x = x0 + t.col * cw;
    const y = y0 + t.row * ch;
    ctx.beginPath();
    ctx.moveTo(x, y);
    ctx.lineTo(x + Math.min(6, cw), y);
    ctx.lineTo(x, y + Math.min(6, ch));
    ctx.fill();
  }
  if (focus) {
    const [ri, ci] = focus;
    ctx.strokeStyle = colors.muted;
    ctx.lineWidth = 2;
    ctx.strokeRect(x0 + ci * cw - 1, y0 + ri * ch - 1, cw + 1, ch + 1);
  }
}

/** The height the canvas needs. */
export function height(grid: Grid, g: Geometry): number {
  return g.y0 + grid.rows.length * g.ch + 34;
}

/** The cell under `(x, y)` (canvas CSS pixels), if any. */
export function hit(grid: Grid, g: Geometry, x: number, y: number): [number, number] | null {
  const ci = Math.floor((x - g.x0) / g.cw);
  const ri = Math.floor((y - g.y0) / g.ch);
  if (ri < 0 || ci < 0 || ri >= grid.rows.length || ci >= grid.cols) return null;
  return [ri, ci];
}

/** Where a marker at `t` (Unix seconds) falls in an unfolded grid. */
export function locate(grid: Grid, t: number): { row: number; col: number } | null {
  const day = dayStart(t);
  const row = grid.rows.findIndex((r) => r.start === day);
  if (row < 0) return null;
  return { row, col: column(t, grid.slot, grid.cols) };
}
