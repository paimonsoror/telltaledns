// REQ: API-011 — numbers follow the language on screen, and re-build when it changes.
import { i18n, t } from './i18n';

let cached: { tag: string; nf: Intl.NumberFormat; compact: Intl.NumberFormat; rate2: Intl.NumberFormat; rate1: Intl.NumberFormat; rate0: Intl.NumberFormat } | null = null;

function formats() {
  const tag = i18n.locale;
  if (cached?.tag !== tag) {
    cached = {
      tag,
      nf: new Intl.NumberFormat(tag),
      compact: new Intl.NumberFormat(tag, { notation: 'compact', maximumFractionDigits: 1 }),
      rate2: new Intl.NumberFormat(tag, { maximumFractionDigits: 2 }),
      rate1: new Intl.NumberFormat(tag, { maximumFractionDigits: 1 }),
      rate0: new Intl.NumberFormat(tag, { maximumFractionDigits: 0 }),
    };
  }
  return cached;
}

export const num = (n: number | undefined | null) => (n == null ? '–' : formats().nf.format(n));
/** A rate such as queries per second: two decimals under 10, one under 100, then whole. */
export const rate = (n: number | undefined | null) => {
  if (n == null) return '–';
  const f = formats();
  return (n < 10 ? f.rate2 : n < 100 ? f.rate1 : f.rate0).format(n);
};
export const short = (n: number | undefined | null) =>
  n == null ? '–' : n < 10_000 ? formats().nf.format(n) : formats().compact.format(n);
export const pct = (n: number | undefined | null, digits = 1) => (n == null || Number.isNaN(n) ? '–' : `${n.toFixed(digits)}%`);

export function ms(n: number | undefined | null): string {
  if (n == null) return '–';
  if (n === 0) return '0 ms';
  if (n < 1) return `${(n * 1000).toFixed(0)} µs`;
  if (n < 10) return `${n.toFixed(2)} ms`;
  if (n < 1000) return `${n.toFixed(0)} ms`;
  return `${(n / 1000).toFixed(2)} s`;
}

export function bytes(n: number | undefined | null): string {
  if (n == null) return '–';
  const u = ['B', 'KiB', 'MiB', 'GiB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) {
    n /= 1024;
    i++;
  }
  return `${i ? n.toFixed(1) : n} ${u[i]}`;
}

export function duration(secs: number): string {
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const ds = t('common.dayShort');
  const hs = t('common.hourShort');
  const ms = t('common.minuteShort');
  if (d) return `${d}${ds} ${h}${hs}`;
  if (h) return `${h}${hs} ${m}${ms}`;
  if (m) return `${m}${ms}`;
  return `${Math.floor(secs)}${t('common.secondShort')}`;
}

/** "5 min ago" / "in 2 h" from Unix seconds. */
export function ago(unix: number | undefined | null): string {
  if (!unix) return t('common.never');
  const diff = Date.now() / 1000 - unix;
  const s = duration(Math.abs(diff));
  return t(diff >= 0 ? 'common.ago' : 'common.inFuture', { time: s });
}

export function clock(unixSeconds: number, withSeconds = false): string {
  return new Date(unixSeconds * 1000).toLocaleTimeString(i18n.locale, {
    hour: '2-digit',
    minute: '2-digit',
    second: withSeconds ? '2-digit' : undefined,
  });
}

export function dateTime(unixSeconds: number): string {
  return new Date(unixSeconds * 1000).toLocaleString(i18n.locale);
}

/** Query-log time (RFC 3339 with ms) → local "HH:MM:SS.mmm". */
export function logTime(rfc3339: string): string {
  const d = new Date(rfc3339);
  const clock = d.toLocaleTimeString(i18n.locale, { hour12: false });
  return `${clock}.${String(d.getMilliseconds()).padStart(3, '0')}`;
}

export function logDate(rfc3339: string): string {
  return new Date(rfc3339).toLocaleDateString(i18n.locale);
}

/** A rule's end time: "21:30", or "Tue 21:30" when it isn't today; empty without one. */
export function endsAt(rfc3339: string | null | undefined): string {
  if (!rfc3339) return '';
  const d = new Date(rfc3339);
  const time = d.toLocaleTimeString(i18n.locale, { hour: '2-digit', minute: '2-digit' });
  return d.toDateString() === new Date().toDateString()
    ? time
    : `${d.toLocaleDateString(i18n.locale, { weekday: 'short' })} ${time}`;
}
