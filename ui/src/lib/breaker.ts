// REQ: API-005, OBS-011 (GitHub issue #9) — how the UI says an upstream's circuit-breaker state.
// The API, the metrics, and the alert rules keep the pattern's own words (`closed`, `open`,
// `half_open`: closed lets requests through); people read Healthy, Benched, and Probing.
import { tk, tr, type Msg } from './i18n';

const { t, m } = tr('breaker');

const LABELS: Record<string, Msg> = {
  closed: m('Healthy'),
  open: m('Benched'),
  half_open: m('Probing'),
};

/** The words for a breaker state: unknown values are shown as they are, nothing as a dash. REQ:
 * API-012 — the state comes from the server: read with `Object.hasOwn`. */
export function breakerLabel(state: string | null | undefined): string {
  if (!state) return '–';
  return Object.hasOwn(LABELS, state) ? tk(LABELS[state]) : state;
}

/** The tooltip: the raw state, for anyone who knows the circuit-breaker pattern. */
export function breakerTitle(state: string | null | undefined): string | undefined {
  return state ? t('circuit breaker: {state}', { state }) : undefined;
}
