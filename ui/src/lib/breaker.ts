// REQ: API-005, OBS-011 (GitHub issue #9) — how the UI says an upstream's circuit-breaker state.
// The API, the metrics, and the alert rules keep the pattern's own words (`closed`, `open`,
// `half_open`: closed lets requests through); people read Healthy, Benched, and Probing.

const LABELS: Record<string, string> = {
  closed: 'Healthy',
  open: 'Benched',
  half_open: 'Probing',
};

/** The words for a breaker state: unknown values are shown as they are, nothing as a dash. */
export function breakerLabel(state: string | null | undefined): string {
  if (!state) return '–';
  return LABELS[state] ?? state;
}
