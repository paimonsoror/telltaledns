// REQ: OBS-033 (GitHub issue #39) — which change markers a live chart draws, without a browser:
// a marker newer than the chart's last bucket (a note saved just after the minute turned) is
// drawn at once, not after the next poll. (The page behaviour is `obs_033 change markers` in
// `1-ui.spec.ts`, which used to fail whenever it saved its note in a minute's first moments.)
import { expect, test } from '@playwright/test';
import { CLOCK_SKEW_S, markerColumns, visibleMarkers } from '../../src/lib/markers';

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

test('obs_033 marker columns keep distinct keys when two round to one pixel', () => {
  // With many markers, columns are 8 px wide. 3.6 and 4.4 fall in adjacent columns but both
  // round to x = 4; keying the buttons by x made Svelte reject the duplicate key.
  const groups = markerColumns(
    [
      { x: 3.6, mark: 'a' },
      { x: 4.4, mark: 'b' },
    ],
    8,
  );
  expect(groups.map((g) => g.x)).toEqual([4, 4]);
  expect(new Set(groups.map((g) => g.k)).size).toBe(2);
});

test('obs_033 it keeps the order and the objects it was given', () => {
  const a = { time: T, summary: 'a' };
  const b = { time: T + 10, summary: 'b' };
  const out = visibleMarkers([b, a], FROM, END, T + 20);
  expect(out).toEqual([b, a]);
  expect(out[0]).toBe(b);
});
