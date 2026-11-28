// REQ: OBS-033 (GitHub issue #39) — which change markers a time chart draws, and where.

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

/** Past this many markers in view, those within 8 px of each other share one button, with a count. */
export const MAX_SINGLE = 40;

/** One marker button: the markers it stands for, the whole pixel it is drawn at, and its key. */
export interface MarkerColumn<T> {
  /**
   * Its column, unique, so the chart keys its buttons by it (REQ: API-005): the pixel (0 or more) up to `MAX_SINGLE` markers,
   * `-1 - column` (-1 or less) for an 8-px column past it, so a redraw across the threshold reuses no key for another place.
   */
  k: number;
  /** Where the button is drawn: the rounded position of its first marker. */
  x: number;
  marks: T[];
}

/**
 * REQ: OBS-033 — a chart's markers as buttons: one per pixel column, or past `MAX_SINGLE` one per 8 px; `xOf` is a marker's
 * position across the plot in CSS pixels, 0 or more (a chart draws markers from its start). Sorted by position. A button is
 * drawn at its first marker (the caller passes them newest first), so two neighbouring 8-px columns can come to the same pixel
 * (11.6 and 12.1 are columns 1 and 2, both at 12): they are one button, the left column's, with the markers of both in the
 * order given, and its count says how many.
 */
export function markerColumns<T>(marks: T[], xOf: (m: T) => number): MarkerColumn<T>[] {
  const col = marks.length > MAX_SINGLE ? 8 : 1;
  // Each column with the places of its markers in `marks`.
  const cols = new Map<number, { c: number; x: number; at: number[] }>();
  marks.forEach((m, i) => {
    const x = xOf(m);
    const c = Math.round(x / col);
    const e = cols.get(c);
    if (e) e.at.push(i);
    else cols.set(c, { c, x: Math.round(x), at: [i] });
  });
  const out: { c: number; x: number; at: number[] }[] = [];
  for (const b of [...cols.values()].sort((p, q) => p.x - q.x)) {
    const last = out[out.length - 1];
    if (last?.x === b.x) {
      last.c = Math.min(last.c, b.c);
      last.at = [...last.at, ...b.at].sort((p, q) => p - q);
    } else out.push(b);
  }
  return out.map((b) => ({ k: col === 1 ? b.c : -1 - b.c, x: b.x, marks: b.at.map((i) => marks[i]) }));
}
