// REQ: API-012 (ADR-189) — every formatter is built for one locale by `makeFormat`, and the
// functions below delegate to the instance the runtime installs before the app mounts. With
// English (the default, and the only language today) the locale is `undefined`, the browser's
// own format as before, and the compact forms the UI writes itself ("5m ago", "1.50 ms",
// "1.5 KiB") are messages of the `format` context whose English is exactly today's output.
// This module imports nothing from the runtime, so the tests load it as it is.
import { interpolate, plural, type Binder, type Msg } from './i18n/message';

/** What the runtime passes in: the messages of the `format` context. */
export type Bind = (context: 'format') => Binder;

const english: Bind = () => ({
  english: true,
  t: (text: string, params?: Readonly<Record<string, string | number | null | undefined>> | null) => interpolate(text, params),
  tn: (one: string, other: string, count: number, params?: Readonly<Record<string, string | number | null | undefined>> | null) =>
    interpolate(plural('en', { one, other }, count) ?? other, params),
  m: (e: string): Msg => Object.freeze({ c: 'format', e }),
}) as Binder;

export function makeFormat(locale: string | undefined, bind: Bind) {
  const { t, english: en } = bind('format');
  // `[]` and `undefined` both mean the browser default, as they did before.
  const at = locale ?? [];
  const nf = new Intl.NumberFormat(locale);
  const compact = new Intl.NumberFormat(locale, { notation: 'compact', maximumFractionDigits: 1 });
  const rate2 = new Intl.NumberFormat(locale, { maximumFractionDigits: 2 });
  const rate1 = new Intl.NumberFormat(locale, { maximumFractionDigits: 1 });
  const rate0 = new Intl.NumberFormat(locale, { maximumFractionDigits: 0 });
  // English keeps `toFixed`; another language writes the same digits with `Intl`.
  const fixed = (n: number, digits: number) =>
    en ? n.toFixed(digits) : new Intl.NumberFormat(locale, { minimumFractionDigits: digits, maximumFractionDigits: digits }).format(n);
  const units = [t('B'), t('KiB'), t('MiB'), t('GiB')];

  const num = (n: number | undefined | null) => (n == null ? '–' : nf.format(n));
  const rate = (n: number | undefined | null) => (n == null ? '–' : (n < 10 ? rate2 : n < 100 ? rate1 : rate0).format(n));
  const short = (n: number | undefined | null) => (n == null ? '–' : n < 10_000 ? nf.format(n) : compact.format(n));
  const pct = (n: number | undefined | null, digits = 1) => (n == null || Number.isNaN(n) ? '–' : t('{n}%', { n: fixed(n, digits) }));

  function ms(n: number | undefined | null): string {
    if (n == null) return '–';
    if (n === 0) return t('0 ms');
    if (n < 1) return t('{n} µs', { n: fixed(n * 1000, 0) });
    if (n < 10) return t('{n} ms', { n: fixed(n, 2) });
    if (n < 1000) return t('{n} ms', { n: fixed(n, 0) });
    return t('{n} s', { n: fixed(n / 1000, 2) });
  }

  function bytes(n: number | undefined | null): string {
    if (n == null) return '–';
    let i = 0;
    while (n >= 1024 && i < units.length - 1) {
      n /= 1024;
      i++;
    }
    return t('{n} {unit}', { n: i ? fixed(n, 1) : en ? String(n) : nf.format(n), unit: units[i] });
  }

  function duration(secs: number): string {
    const d = Math.floor(secs / 86400);
    const h = Math.floor((secs % 86400) / 3600);
    const m = Math.floor((secs % 3600) / 60);
    if (d) return t('{d}d {h}h', { d, h });
    if (h) return t('{h}h {m}m', { h, m });
    if (m) return t('{m}m', { m });
    return t('{s}s', { s: Math.floor(secs) });
  }

  function ago(unix: number | undefined | null): string {
    if (!unix) return t('never');
    const diff = Date.now() / 1000 - unix;
    const s = duration(Math.abs(diff));
    return diff >= 0 ? t('{s} ago', { s }) : t('in {s}', { s });
  }

  function clock(unixSeconds: number, withSeconds = false): string {
    return new Date(unixSeconds * 1000).toLocaleTimeString(at, {
      hour: '2-digit',
      minute: '2-digit',
      second: withSeconds ? '2-digit' : undefined,
    });
  }

  function dateTime(unixSeconds: number): string {
    return new Date(unixSeconds * 1000).toLocaleString(locale);
  }

  function monthDay(unixSeconds: number): string {
    return new Date(unixSeconds * 1000).toLocaleDateString(at, { month: 'short', day: 'numeric' });
  }

  function weekdayDate(unixSeconds: number): string {
    return new Date(unixSeconds * 1000).toLocaleDateString(at, { weekday: 'short', month: 'short', day: 'numeric' });
  }

  function weekdayTime(rfc3339: string): string {
    return new Date(rfc3339).toLocaleString(at, { weekday: 'short', hour: '2-digit', minute: '2-digit' });
  }

  function timeOfDay(d: Date): string {
    return d.toLocaleTimeString(locale);
  }

  function logTime(rfc3339: string): string {
    const d = new Date(rfc3339);
    const time = d.toLocaleTimeString(at, { hour12: false });
    return `${time}.${String(d.getMilliseconds()).padStart(3, '0')}`;
  }

  function logDate(rfc3339: string): string {
    return new Date(rfc3339).toLocaleDateString(locale);
  }

  function endsAt(rfc3339: string | null | undefined): string {
    if (!rfc3339) return '';
    const d = new Date(rfc3339);
    const time = d.toLocaleTimeString(at, { hour: '2-digit', minute: '2-digit' });
    return d.toDateString() === new Date().toDateString() ? time : t('{day} {time}', { day: d.toLocaleDateString(at, { weekday: 'short' }), time });
  }

  return { num, rate, short, pct, ms, bytes, duration, ago, clock, dateTime, monthDay, weekdayDate, weekdayTime, timeOfDay, logTime, logDate, endsAt };
}

export type Format = ReturnType<typeof makeFormat>;

let f: Format = makeFormat(undefined, english);

/** Called by the runtime once, before the app mounts. */
export function installFormat(next: Format): void {
  f = next;
}

export const num = (n: number | undefined | null) => f.num(n);
/** A rate such as queries per second: two decimals under 10, one under 100, then whole. */
export const rate = (n: number | undefined | null) => f.rate(n);
export const short = (n: number | undefined | null) => f.short(n);
export const pct = (n: number | undefined | null, digits = 1) => f.pct(n, digits);

export function ms(n: number | undefined | null): string {
  return f.ms(n);
}

export function bytes(n: number | undefined | null): string {
  return f.bytes(n);
}

export function duration(secs: number): string {
  return f.duration(secs);
}

/** "5m ago" / "in 2h" from Unix seconds. */
export function ago(unix: number | undefined | null): string {
  return f.ago(unix);
}

export function clock(unixSeconds: number, withSeconds = false): string {
  return f.clock(unixSeconds, withSeconds);
}

export function dateTime(unixSeconds: number): string {
  return f.dateTime(unixSeconds);
}

/** REQ: API-012 — "Nov 24" from Unix seconds (a chart's axis and tooltip). */
export function monthDay(unixSeconds: number): string {
  return f.monthDay(unixSeconds);
}

/** REQ: API-012 — "Mon, Nov 24" from Unix seconds (a heatmap's row). */
export function weekdayDate(unixSeconds: number): string {
  return f.weekdayDate(unixSeconds);
}

/** REQ: API-012 — "Mon 21:05" from an RFC 3339 time (when a node began to stand out). */
export function weekdayTime(rfc3339: string): string {
  return f.weekdayTime(rfc3339);
}

/** REQ: API-012 — "9:05:07 PM" from a Date (when a list was last refreshed). */
export function timeOfDay(d: Date): string {
  return f.timeOfDay(d);
}

/** Query-log time (RFC 3339 with ms) → local "HH:MM:SS.mmm". */
export function logTime(rfc3339: string): string {
  return f.logTime(rfc3339);
}

export function logDate(rfc3339: string): string {
  return f.logDate(rfc3339);
}

/** A rule's end time: "21:30", or "Tue 21:30" when it isn't today; empty without one. */
export function endsAt(rfc3339: string | null | undefined): string {
  return f.endsAt(rfc3339);
}
