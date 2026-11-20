// REQ: API-002, T8.2 (ADR-181) — whether this page was opened over plain HTTP from another
// machine: what is typed into it then crosses the network unencrypted. A page on this machine
// (localhost, 127.0.0.0/8, ::1) doesn't leave it.
export function plainHttpPage(where: { protocol: string; hostname: string }): boolean {
  if (where.protocol !== 'http:') return false;
  const h = where.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  const loopback = h === 'localhost' || h.endsWith('.localhost') || h === '::1' || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h);
  return !loopback;
}
