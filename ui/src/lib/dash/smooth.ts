// Dashboard lab — calming a time series for display: fewer, wider buckets (sums stay exact for
// the interval they cover), no half-filled bucket at the newest edge.
import { clock, monthDay } from '../format';
import { tr } from '../i18n';

const { t } = tr('smooth');

export interface RawSeries {
  /** What the series is (a status, a group's name): what the chart keys it by. REQ: API-012 — the
   * `label` is display text only. */
  key: string;
  label: string;
  /** A CSS variable name (`--s-blocked`) or a color. */
  color: string;
  values: number[];
  /** A ratio series: `values` are numerators and `den` the denominators; shown as a percentage. */
  den?: number[];
}

export interface Shown extends RawSeries {
  /** What the chart draws and the tooltip says, per bucket. */
  shown: number[];
  /** The whole range: a sum, or a percentage for a ratio. */
  total: number;
}

export interface Binned {
  times: number[];
  /** Seconds each bucket covers. */
  span: number;
  series: Shown[];
}

export function rebucket(times: number[], series: RawSeries[], maxPts: number): Binned {
  const step = times.length > 1 ? times[1] - times[0] : 60;
  // The newest source bucket is still filling: leave it out so the line doesn't dip at the edge.
  const end = times.length > 3 ? times.length - 1 : times.length;
  const f = Math.max(1, Math.ceil(end / Math.max(8, maxPts)));
  // Group from the newest end, so every shown bucket is full; the oldest leftovers are dropped.
  const first = end % f;
  const out: Binned = { times: [], span: f * step, series: [] };
  for (let i = first; i < end; i += f) out.times.push(times[i]);
  for (const s of series) {
    const values: number[] = [];
    const den: number[] | undefined = s.den ? [] : undefined;
    for (let i = first; i < end; i += f) {
      let v = 0;
      let d = 0;
      for (let j = i; j < i + f; j++) {
        v += s.values[j] ?? 0;
        d += s.den?.[j] ?? 0;
      }
      values.push(v);
      den?.push(d);
    }
    const shown = den ? values.map((v, k) => (den[k] > 0 ? (v / den[k]) * 100 : 0)) : values;
    const sum = values.reduce((a, v) => a + v, 0);
    const dsum = den ? den.reduce((a, v) => a + v, 0) : 0;
    out.series.push({ ...s, values, den, shown, total: den ? (dsum > 0 ? (sum / dsum) * 100 : 0) : sum });
  }
  return out;
}

/** "05:47:00 PM · 17 s": the start and how long the bucket is, for a tooltip with little room. */
export function bucketStart(start: number, span: number, multiDay: boolean): string {
  const time = clock(start, span < 60);
  const day = multiDay ? `${monthDay(start)}, ` : '';
  const len = span < 60 ? t('{n} s', { n: span }) : span < 3600 ? t('{n} min', { n: Math.round(span / 60) }) : t('{n} h', { n: Math.round(span / 3600) });
  return `${day}${time} · ${len}`;
}

/** "05:47 PM – 05:48 PM", with the date when the range spans days. */
export function bucketLabel(start: number, span: number, multiDay: boolean): string {
  const withSec = span < 60;
  const day = multiDay ? `${monthDay(start)}, ` : '';
  if (span >= 3600) return `${day}${clock(start, withSec)}`;
  return `${day}${clock(start, withSec)} – ${clock(start + span, withSec)}`;
}
