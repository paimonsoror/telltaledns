// Squarified treemap (Bruls, Huizing & van Wijk, 2000): lays out weighted items as rectangles
// whose areas are proportional to their weights, keeping each as close to square as it can.

export interface Rect {
  x: number;
  y: number;
  w: number;
  h: number;
}

/** Rectangles for `weights` (any order) inside a `width` × `height` box, in the same order. */
export function squarify(weights: number[], width: number, height: number): Rect[] {
  const out: Rect[] = weights.map(() => ({ x: 0, y: 0, w: 0, h: 0 }));
  const total = weights.reduce((a, b) => a + Math.max(0, b), 0);
  if (total <= 0 || width <= 0 || height <= 0) return out;
  // Heaviest first, scaled so the weights are areas.
  const scale = (width * height) / total;
  const order = weights
    .map((w, i) => ({ i, a: Math.max(0, w) * scale }))
    .filter((e) => e.a > 0)
    .sort((p, q) => q.a - p.a);

  let box: Rect = { x: 0, y: 0, w: width, h: height };
  let row: { i: number; a: number }[] = [];
  for (const e of order) {
    const side = Math.min(box.w, box.h);
    if (row.length === 0 || worst([...row, e], side) <= worst(row, side)) {
      row.push(e);
    } else {
      box = place(row, box, out);
      row = [e];
    }
  }
  if (row.length) place(row, box, out);
  return out;
}

/** The worst aspect ratio in `row` laid along a side of length `side`. */
function worst(row: { a: number }[], side: number): number {
  let sum = 0;
  let min = Infinity;
  let max = 0;
  for (const r of row) {
    sum += r.a;
    min = Math.min(min, r.a);
    max = Math.max(max, r.a);
  }
  const s2 = side * side;
  const sum2 = sum * sum;
  return Math.max((s2 * max) / sum2, sum2 / (s2 * min));
}

/** Lays `row` along the shorter side of `box`; returns what's left of the box. */
function place(row: { i: number; a: number }[], box: Rect, out: Rect[]): Rect {
  const sum = row.reduce((a, r) => a + r.a, 0);
  if (box.w >= box.h) {
    // A column on the left.
    const w = sum / box.h;
    let y = box.y;
    for (const r of row) {
      const h = r.a / w;
      out[r.i] = { x: box.x, y, w, h };
      y += h;
    }
    return { x: box.x + w, y: box.y, w: box.w - w, h: box.h };
  }
  // A row along the top.
  const h = sum / box.w;
  let x = box.x;
  for (const r of row) {
    const w = r.a / h;
    out[r.i] = { x, y: box.y, w, h };
    x += w;
  }
  return { x: box.x, y: box.y + h, w: box.w, h: box.h - h };
}
