// REQ: API-005 — the parts of a donut (the old dashboard's "Answers by status"): one per status, with the status id, the words
// shown for it, its colour and its total. The donut keys its segments and its breakdown by the id, never by the words: a label
// is text to show, and two can read alike in a language (API-012).

export interface Part {
  /** What the part is (a status): unique among the parts. */
  id: string;
  label: string;
  value: number;
  /** A CSS variable name (`--s-blocked`). */
  color: string;
}

/** The key of a part in the donut's each-blocks. */
export const partKey = (p: Part): string => p.id;

/** One part per series, with the series' total over the range. */
export function partsOf(series: { id: string; label: string; color: string; values: number[] }[]): Part[] {
  return series.map((s) => ({ id: s.id, label: s.label, color: s.color, value: s.values.reduce((a, v) => a + v, 0) }));
}
