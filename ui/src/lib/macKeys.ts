// REQ: API-010, FLT-006 (ADR-183) — a device's `match` keys: MAC addresses and addresses, compared
// the way the server compares them (a MAC as bytes, whatever its spelling; an address with its
// /32 or /128 and its IPv4-mapped form).

/** One part of a MAC key as the server's `MatchKey::parse` reads it: two hex digits (its radix parser also lets a `+` and one digit by). */
const PART = /^(?:[0-9a-f]{2}|\+[0-9a-f])$/i;

/**
 * The six bytes of a MAC key, as the server reads it: six parts split on `:` or `-` (the two may be
 * mixed), each of two hex digits, in any case, with spaces around trimmed. Null when it isn't one.
 */
export function macBytes(s: string): number[] | null {
  const parts = s.trim().split(/[:-]/);
  if (parts.length !== 6 || !parts.every((p) => PART.test(p))) return null;
  return parts.map((p) => parseInt(p.replace('+', ''), 16));
}

/** Whether `s` is a MAC address in any spelling the server reads. */
export const isMac = (s: string) => macBytes(s) !== null;

/** A MAC address in one form (lowercase, colons, two digits a part), so two spellings of one compare equal. */
export function normMac(m: string): string {
  const b = macBytes(m);
  return b ? b.map((x) => x.toString(16).padStart(2, '0')).join(':') : m.trim().toLowerCase().replace(/-/g, ':');
}

/** The address a host key stands for: `a.b.c.d/32` and `x::y/128` are hosts, `::ffff:a.b.c.d` is `a.b.c.d`. */
function host(s: string): string {
  let h = s.trim().toLowerCase();
  if (h.includes(':') && h.endsWith('/128')) h = h.slice(0, -4);
  else if (!h.includes(':') && h.endsWith('/32')) h = h.slice(0, -3);
  return h.startsWith('::ffff:') && h.includes('.') ? h.slice(7) : h;
}

/** Whether the key names exactly the address `ip` (and no network, no MAC, no client ID). */
export function sameIp(key: string, ip: string): boolean {
  return host(key) === host(ip);
}

/** Whether a device's keys already list the MAC address `mac`. */
export const listsMac = (match: string[], mac: string) => match.some((k) => isMac(k) && normMac(k) === normMac(mac));
