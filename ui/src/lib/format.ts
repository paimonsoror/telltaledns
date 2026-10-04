const nf = new Intl.NumberFormat();
const compact = new Intl.NumberFormat(undefined, { notation: 'compact', maximumFractionDigits: 1 });

export const num = (n: number | undefined | null) => (n == null ? '–' : nf.format(n));
export const short = (n: number | undefined | null) => (n == null ? '–' : n < 10_000 ? nf.format(n) : compact.format(n));
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
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m`;
  return `${Math.floor(secs)}s`;
}

/** "5 min ago" / "in 2 h" from Unix seconds. */
export function ago(unix: number | undefined | null): string {
  if (!unix) return 'never';
  const diff = Date.now() / 1000 - unix;
  const s = duration(Math.abs(diff));
  return diff >= 0 ? `${s} ago` : `in ${s}`;
}

export function clock(unixSeconds: number, withSeconds = false): string {
  return new Date(unixSeconds * 1000).toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: withSeconds ? '2-digit' : undefined,
  });
}

export function dateTime(unixSeconds: number): string {
  return new Date(unixSeconds * 1000).toLocaleString();
}

/** Query-log time (RFC 3339 with ms) → local "HH:MM:SS.mmm". */
export function logTime(rfc3339: string): string {
  const d = new Date(rfc3339);
  const t = d.toLocaleTimeString([], { hour12: false });
  return `${t}.${String(d.getMilliseconds()).padStart(3, '0')}`;
}

export function logDate(rfc3339: string): string {
  return new Date(rfc3339).toLocaleDateString();
}
