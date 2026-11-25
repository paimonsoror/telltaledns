// REQ: OBS-033 (GitHub issue #39) — which change markers a time chart draws.

/**
 * How far ahead of this browser's clock a marker may be and still be drawn: the server stamps a
 * change or a note with its own clock, and the two can differ by a little.
 */
export const CLOCK_SKEW_S = 60;

/**
 * The markers a chart draws: those from the chart's start to the end of its data, or to now when
 * that is later.
 *
 * A chart's data ends at its last bucket, which is only as new as the last load. A change made
 * since (a note saved just after the minute turned) has no bucket yet, and used to be left off until
 * the next poll, up to 15 seconds later, so a saved note looked unsaved. The chart's window runs to
 * now, so such a marker belongs on it at once: the caller draws it at the right edge.
 *
 * `nowS` is the end of the chart's window in Unix seconds. Every chart that takes markers ends
 * now (the dashboard's ranges, the Cache page's last hour, the budget burn-down), so that is
 * `Date.now() / 1000`; a chart that ended in the past would pass its own end.
 */
export function visibleMarkers<T extends { time: number }>(markers: T[], from: number, dataEnd: number, nowS: number): T[] {
  const to = Math.max(dataEnd, nowS + CLOCK_SKEW_S);
  return markers.filter((m) => m.time >= from && m.time < to);
}

/** One drawn marker group: `k` identifies the column it occupies, `x` where it is drawn. */
export interface MarkerColumn<T> {
  k: number;
  x: number;
  marks: T[];
}

/**
 * Group markers by the column they occupy. `col` is the column width in pixels (8 when many
 * markers are in view). Adjacent columns can round to the same pixel, so `k`, the unrounded
 * column, is what identifies a group; the chart keys its marker buttons by it.
 */
export function markerColumns<T>(points: { x: number; mark: T }[], col: number): MarkerColumn<T>[] {
  const cols = new Map<number, MarkerColumn<T>>();
  for (const { x, mark } of points) {
    const k = Math.round(x / col);
    const c = cols.get(k);
    if (c) c.marks.push(mark);
    else cols.set(k, { k, x: Math.round(x), marks: [mark] });
  }
  return [...cols.values()].sort((a, b) => a.x - b.x);
}
