// REQ: API-005 — keys for a list whose values can repeat, when a row must stay with its item (a button that acts at once):
// each value with how many times it came before it, after a NUL (`a`, `b`, `a` → `a\u00000`, `b\u00000`, `a\u00001`). A value
// listed once keeps its key wherever it moves, and a repeat stays unique: the count, after the last NUL, has no NUL in it.
// One pass and one small map: these lists are drawn again on every poll.

export function occurrenceKeys(values: readonly string[]): string[] {
  const seen = new Map<string, number>();
  return values.map((v) => {
    const n = seen.get(v) ?? 0;
    seen.set(v, n + 1);
    return `${v}\u0000${n}`;
  });
}

/** `items`, each with its occurrence key by `text`: `{#each keyed(items, text) as { item, key } (key)}`. */
export function keyed<T>(items: readonly T[], text: (item: T) => string): { item: T; key: string }[] {
  const seen = new Map<string, number>();
  return items.map((item) => {
    const v = text(item);
    const n = seen.get(v) ?? 0;
    seen.set(v, n + 1);
    return { item, key: `${v}\u0000${n}` };
  });
}
