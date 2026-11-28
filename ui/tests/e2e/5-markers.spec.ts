// REQ: OBS-033 (GitHub issue #39) — which change markers a live chart draws, without a browser:
// a marker newer than the chart's last bucket (a note saved just after the minute turned) is
// drawn at once, not after the next poll. (The page behaviour is `obs_033 change markers` in
// `1-ui.spec.ts`, which used to fail whenever it saved its note in a minute's first moments.)
import { expect, test } from '@playwright/test';
import { CLOCK_SKEW_S, MAX_SINGLE, markerColumns, visibleMarkers } from '../../src/lib/markers';

const mark = (time: number) => ({ time });
// A chart whose last bucket starts at T and ends at T + 60 (a minute step), loaded just before the
// minute turned: Greg's trace in issue #39 (bucket 07:04:00, note saved at 07:05:00.020).
const T = 1_790_000_040;
const FROM = T - 86_400;
const END = T + 60;

test('obs_033 a marker saved after the chart loaded is drawn at once', () => {
  const note = T + 60.02; // 07:05:00.020, past the data's end by 20 ms
  expect(note).toBeGreaterThanOrEqual(END);
  // The old rule (up to the data's end) dropped it.
  expect([mark(note)].filter((m) => m.time >= FROM && m.time < END)).toHaveLength(0);
  // Now it is drawn, as the minute has turned.
  expect(visibleMarkers([mark(note)], FROM, END, T + 60.055)).toHaveLength(1);
  // And a few seconds later still, before the next poll.
  expect(visibleMarkers([mark(note)], FROM, END, T + 74.9)).toHaveLength(1);
});

test('obs_033 the window still ends where it should', () => {
  const now = T + 30; // inside the last bucket
  const all = [mark(FROM - 1), mark(FROM), mark(T), mark(END - 1), mark(now + CLOCK_SKEW_S - 1), mark(now + CLOCK_SKEW_S), mark(now + 3600)];
  const drawn = visibleMarkers(all, FROM, END, now).map((m) => m.time);
  // Before the start: no. The start is inside. The data's own range is inside.
  expect(drawn).not.toContain(FROM - 1);
  expect(drawn).toContain(FROM);
  expect(drawn).toContain(T);
  expect(drawn).toContain(END - 1);
  // A marker the server stamped a little ahead of this browser's clock is drawn; one an hour ahead is not.
  expect(drawn).toContain(now + CLOCK_SKEW_S - 1);
  expect(drawn).not.toContain(now + CLOCK_SKEW_S);
  expect(drawn).not.toContain(now + 3600);
});

test('obs_033 the data may end later than now, and a chart that ended in the past keeps its own end', () => {
  // Data ahead of the clock (the last bucket is the current one): its end wins.
  expect(visibleMarkers([mark(END - 1)], FROM, END, T - 3600)).toHaveLength(1);
  // A chart whose window ended an hour ago passes that end, and a later change is not on it.
  const past = T - 3600;
  expect(visibleMarkers([mark(past - 10), mark(past + 600)], FROM, past, past)).toHaveLength(1);
});

test('obs_033 it keeps the order and the objects it was given', () => {
  const a = { time: T, summary: 'a' };
  const b = { time: T + 10, summary: 'b' };
  const out = visibleMarkers([b, a], FROM, END, T + 20);
  expect(out).toEqual([b, a]);
  expect(out[0]).toBe(b);
});

// REQ: OBS-033, API-005 — the buttons a chart draws for its markers (`markerColumns`): past 40 in view, one per 8-px column,
// drawn at the pixel of the column's first marker; two neighbouring columns that would be drawn at one pixel are one button,
// with both columns' markers. A chart keys its buttons by `k`, which is unique, and which a pixel (up to 40) and an 8-px
// column (past 40) never share.
const id = (x: number) => x;
/** Markers far apart, one column each, to pass `MAX_SINGLE`. */
const apart = (n: number) => Array.from({ length: n }, (_, i) => 100 + 8 * i);

test('api_005 obs_033 two neighbouring columns drawn at one pixel are one button', () => {
  const cols = markerColumns([11.6, 12.1, ...apart(MAX_SINGLE - 1)], id);
  // 11.6 is column 1 and 12.1 column 2, both drawn at 12: one button, the left column's, with both markers.
  expect(cols[0]).toEqual({ k: -2, x: 12, marks: [11.6, 12.1] });
  expect(cols).toHaveLength(MAX_SINGLE);
  expect(new Set(cols.map((c) => c.x)).size).toBe(cols.length);
  expect(new Set(cols.map((c) => c.k)).size).toBe(cols.length);
  // Up to 40, a column is one pixel: 11.6 and 12.1 are drawn as one button.
  expect(markerColumns([11.6, 12.1], id)).toEqual([{ k: 12, x: 12, marks: [11.6, 12.1] }]);
});

test('api_005 obs_033 a redraw across 40 markers gives no key a different place', () => {
  // Pixels 0, 8, 16, … up to 40 markers; one more and they are 8-px columns 0, 1, 2, … : the numbers meet, the places don't.
  const forty = Array.from({ length: MAX_SINGLE }, (_, i) => 8 * i);
  const keys = (xs: number[]) => new Map(markerColumns(xs, id).map((c) => [c.k, c.x]));
  const before = keys(forty);
  const after = keys([...forty, 8 * MAX_SINGLE]);
  expect([...before.keys()].filter((k) => after.has(k))).toEqual([]);
  // The same over random redraws from 40 to 41 markers and back.
  const rnd = random(0x4041);
  for (let run = 0; run < 500; run++) {
    const xs = Array.from({ length: MAX_SINGLE + 1 }, () => rnd() * 1200);
    const a = keys(xs.slice(0, MAX_SINGLE));
    const b = keys(xs);
    const reused = [...a].filter(([k, x]) => b.has(k) && b.get(k) !== x);
    expect(reused, `redraw ${run}: a key drawn at another place`).toEqual([]);
  }
});

/** Each column its own button: the placement the merge of `drawn` starts from (markers by their index). */
function base(xs: number[]): { x: number; marks: number[] }[] {
  const col = xs.length > 40 ? 8 : 1;
  const cols = new Map<number, { x: number; marks: number[] }>();
  xs.forEach((x, i) => {
    const c = cols.get(Math.round(x / col));
    if (c) c.marks.push(i);
    else cols.set(Math.round(x / col), { x: Math.round(x), marks: [i] });
  });
  return [...cols.values()].sort((a, b) => a.x - b.x);
}
/** The buttons the charts draw, written out on its own: `base`, with buttons drawn at one pixel made one, markers in order. */
function drawn(xs: number[]): { x: number; marks: number[] }[] {
  const out: { x: number; marks: number[] }[] = [];
  for (const b of base(xs)) {
    const last = out[out.length - 1];
    if (last && last.x === b.x) last.marks = [...last.marks, ...b.marks].sort((p, q) => p - q);
    else out.push({ x: b.x, marks: [...b.marks] });
  }
  return out;
}
/** A small seeded generator (mulberry32): the same sets on every run. */
function random(seed: number) {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4_294_967_296;
  };
}

test('api_005 obs_033 marker columns over three thousand random sets: unique keys, one button a pixel, the same buttons where none met', () => {
  const rnd = random(0x0e4c);
  let met = 0;
  for (let run = 0; run < 3000; run++) {
    const n = 1 + Math.floor(rnd() * 160);
    // Three kinds of set: spread over the plot; crowded round the 8-px edges (8j + 3.5 to 8j + 4.5), where two columns
    // meet; and partly past the plot's end, held at its last pixel as the charts hold them (Chart, SmoothChart).
    const width = 300 + Math.floor(rnd() * 1300);
    const kind = run % 3;
    const raw = Array.from({ length: n }, () => (kind === 0 ? rnd() * width : kind === 1 ? 8 * Math.floor(rnd() * (width / 8)) + 3.5 + rnd() : rnd() * width * 1.3));
    // Newest first, as the charts pass them: the right-most first.
    raw.sort((a, b) => b - a);
    const xs = raw.map((x) => Math.min(x, width - 1));
    const cols = markerColumns(
      xs.map((_, i) => i),
      (i) => xs[i],
    );
    expect(new Set(cols.map((c) => c.k)).size, `set ${run}: one key per button`).toBe(cols.length);
    expect(new Set(cols.map((c) => c.x)).size, `set ${run}: one button per pixel`).toBe(cols.length);
    expect(cols.flatMap((c) => c.marks).sort((a, b) => a - b), `set ${run}: every marker once`).toEqual(xs.map((_, i) => i));
    expect(cols.map(({ x, marks }) => ({ x, marks })), `set ${run}: the buttons`).toEqual(drawn(xs));
    // Where no two columns met at one pixel, the buttons are the columns, one each, exactly.
    const columns = base(xs);
    if (new Set(columns.map((c) => c.x)).size === columns.length) expect(cols.map(({ x, marks }) => ({ x, marks })), `set ${run}: the columns`).toEqual(columns);
    else met++;
  }
  // Both cases came up, often.
  expect(met, 'sets where two columns met').toBeGreaterThan(300);
  expect(3000 - met, 'sets where none met').toBeGreaterThan(300);
});
