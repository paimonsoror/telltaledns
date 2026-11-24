// REQ: API-005, OBS-011 (GitHub issue #9) — how the UI says an upstream's circuit-breaker state.
// The API, the metrics, and the alert rules keep the pattern's own words (`closed`, `open`,
// `half_open`: closed lets requests through); people read Healthy, Benched, and Probing.

import { t, type MessageKey } from './i18n';

const LABELS: Record<string, MessageKey> = {
  closed: 'cluster.healthy',
  open: 'dashw.breaker.open',
  half_open: 'dashw.breaker.halfOpen',
};

/** The words for a breaker state: unknown values are shown as they are, nothing as a dash. */
export function breakerLabel(state: string | null | undefined): string {
  if (!state) return '–';
  const key = LABELS[state];
  return key ? t(key) : state;
}
