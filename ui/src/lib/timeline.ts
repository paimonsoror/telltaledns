// REQ: OBS-034 (ADR-134) — the device timeline's geometry and drawing: one 18 px lane per domain,
// a cell per bin shaded with the heatmap's square-root ramp, blocked bins underlined, slow bins
// ticked, and a latency lane (p99 per bin) under them.
import type { S } from './api';

export type Timeline = S['DeviceTimeline'];

export const LANE_H = 18;
export const LAT_H = 30;
export const LABEL_W = 150;

export interface Geometry {
  /** The canvas width and height (CSS pixels), and one bin's width. */
  width: number;
  height: number;
  col: number;
  lanes: number;
}

/** At least 2 px a bin: narrower screens scroll. */
export function geometry(t: Timeline, available: number): Geometry {
  const n = Math.max(1, t.bins.length);
  const width = Math.max(available - LABEL_W, n * 2);
  return { width, height: t.lanes.length * LANE_H + LAT_H, col: width / n, lanes: t.lanes.length };
}

/** The x of a time (Unix seconds) on the canvas. */
export function xOf(t: Timeline, g: Geometry, unix: number): number {
  const first = t.bins[0] ?? 0;
  return ((unix - first) / t.binSeconds) * g.col;
}

/** The lane (or `lanes` for the latency lane) and bin under a point, if any. */
export function hit(t: Timeline, g: Geometry, x: number, y: number): { lane: number; bin: number } | null {
  if (x < 0 || y < 0 || x >= g.width || y >= g.height) return null;
  const bin = Math.min(t.bins.length - 1, Math.floor(x / g.col));
  const lane = Math.min(g.lanes, Math.floor(y / LANE_H));
  return { lane, bin };
}

export interface Colors {
  ink: string;
  bad: string;
  warn: string;
  muted: string;
  grid: string;
}

/** Shade strength: square root, so a few queries still show next to thousands. */
export const strength = (n: number, max: number) => (n > 0 && max > 0 ? 0.12 + 0.88 * Math.sqrt(n / max) : 0);

export function draw(ctx: CanvasRenderingContext2D, t: Timeline, g: Geometry, c: Colors, coverageFrom: number | null) {
  ctx.clearRect(0, 0, g.width, g.height);
  let max = 0;
  for (const l of t.lanes) for (const n of l.counts) if (n > max) max = n;
  const w = Math.max(1, g.col - (g.col > 3 ? 1 : 0));
  t.lanes.forEach((l, i) => {
    const y = i * LANE_H;
    ctx.fillStyle = c.grid;
    ctx.fillRect(0, y + LANE_H - 1, g.width, 1);
    l.counts.forEach((n, j) => {
      if (!n) return;
      const x = j * g.col;
      ctx.globalAlpha = strength(n, max);
      ctx.fillStyle = c.ink;
      ctx.fillRect(x, y + 3, w, LANE_H - 7);
      ctx.globalAlpha = 1;
      if (l.blocked[j]) {
        ctx.fillStyle = c.bad;
        ctx.fillRect(x, y + LANE_H - 4, w, 2);
      }
      if (l.slow[j]) {
        ctx.fillStyle = c.warn;
        ctx.fillRect(x, y + 1, w, 2);
      }
    });
  });
  // The latency lane: p99 per bin as a line with dots, on its own scale.
  const top = t.lanes.length * LANE_H;
  const vals = t.p99Ms;
  const vmax = Math.max(1, ...vals.map((v) => v ?? 0));
  ctx.strokeStyle = c.warn;
  ctx.fillStyle = c.warn;
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  let pen = false;
  vals.forEach((v, j) => {
    if (v == null) {
      pen = false;
      return;
    }
    const x = (j + 0.5) * g.col;
    const y = top + LAT_H - 3 - (v / vmax) * (LAT_H - 8);
    if (pen) ctx.lineTo(x, y);
    else ctx.moveTo(x, y);
    pen = true;
  });
  ctx.stroke();
  // Before the query log's oldest row: greyed.
  if (coverageFrom != null) {
    const x = Math.max(0, Math.min(g.width, xOf(t, g, coverageFrom)));
    if (x > 0) {
      ctx.globalAlpha = 0.18;
      ctx.fillStyle = c.muted;
      ctx.fillRect(0, 0, x, g.height);
      ctx.globalAlpha = 1;
    }
  }
}

/** Columns for the table: bins summed into at most `cols` spans. */
export function spans(t: Timeline, cols = 24): { start: number; from: number; to: number }[] {
  const n = t.bins.length;
  const per = Math.max(1, Math.ceil(n / cols));
  const out = [];
  for (let i = 0; i < n; i += per) out.push({ start: t.bins[i], from: i, to: Math.min(n, i + per) });
  return out;
}
