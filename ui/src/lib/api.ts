// Typed client for /api/v1 (types generated from docs/api/openapi.json: `npm run types`).
// REQ: API-005 — the UI uses only the public API, the same one scripts and agents use.

import type { components } from './api-types';

export type S = components['schemas'];
export type Problem = S['Problem'];

/** An API error (RFC 9457 problem+json). */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly hint?: string;
  constructor(p: Partial<Problem> & { status: number }) {
    super(p.detail ?? p.title ?? `HTTP ${p.status}`);
    this.status = p.status;
    this.code = p.code ?? 'internal';
    this.hint = p.hint ?? undefined;
  }
}

let csrf: string | undefined;
let onSignedOut: (() => void) | undefined;

/** The session's CSRF token, sent as `X-CSRF-Token` on every change. */
export function setCsrf(token: string | undefined) {
  csrf = token;
}

/** Called when a request finds the session gone (expired, signed out elsewhere). */
export function whenSignedOut(f: () => void) {
  onSignedOut = f;
}

type Query = Record<string, string | number | boolean | undefined | null>;

function qs(q?: Query): string {
  if (!q) return '';
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(q)) {
    if (v !== undefined && v !== null && v !== '') p.set(k, String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : '';
}

async function call<T>(
  method: string,
  path: string,
  opts: { query?: Query; body?: unknown; headers?: Record<string, string> } = {},
): Promise<T> {
  const headers: Record<string, string> = { accept: 'application/json', ...opts.headers };
  if (opts.body !== undefined) headers['content-type'] = 'application/json';
  if (method !== 'GET' && csrf) headers['x-csrf-token'] = csrf;
  let res: Response;
  try {
    res = await fetch(`/api/v1${path}${qs(opts.query)}`, {
      method,
      headers,
      credentials: 'same-origin',
      body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
    });
  } catch {
    throw new ApiError({ status: 0, code: 'unavailable', detail: 'cannot reach the server' });
  }
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  let json: unknown;
  try {
    json = text ? JSON.parse(text) : undefined;
  } catch {
    json = undefined;
  }
  if (!res.ok) {
    const p = (json ?? {}) as Partial<Problem>;
    const err = new ApiError({ ...p, status: res.status, detail: p.detail ?? (text || res.statusText) });
    if (res.status === 401 && err.code === 'unauthorized' && !path.startsWith('/auth/')) onSignedOut?.();
    throw err;
  }
  return json as T;
}

/** A random Idempotency-Key (getRandomValues also works on plain-HTTP LAN addresses). */
function newKey(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, '0')).join('');
}

const get = <T>(path: string, query?: Query) => call<T>('GET', path, { query });
const post = <T>(path: string, body?: unknown) => call<T>('POST', path, { body: body ?? {} });

export const api = {
  // Sign-in (API-003)
  status: () => get<S['AuthStatus']>('/auth/status'),
  setup: (b: S['SetupRequest']) => post<S['LoginResponse']>('/auth/setup', b),
  login: (b: S['LoginRequest']) => post<S['LoginResponse']>('/auth/login', b),
  logout: () => post<S['LogoutResult'] | undefined>('/auth/logout'),
  me: () => get<S['Me']>('/auth/me'),
  changePassword: (b: S['PasswordChange']) => post<void>('/auth/password', b),
  totpSetup: () => post<S['TotpSetup']>('/auth/totp/setup'),
  totpEnable: (code: string) => post<S['RecoveryCodes']>('/auth/totp/enable', { code }),
  totpDisable: (password: string) => post<void>('/auth/totp/disable', { password }),
  tokens: () => get<S['Listed_TokenInfo']>('/tokens'),
  createToken: (b: S['CreateToken']) => post<S['NewToken']>('/tokens', b),
  deleteToken: (id: string) => call<void>('DELETE', `/tokens/${encodeURIComponent(id)}`),
  users: () => get<S['Listed_UserInfo']>('/users'),
  createUser: (b: S['CreateUser']) => post<S['UserInfo']>('/users', b),
  updateUser: (id: number, b: S['UpdateUser']) => call<S['UserInfo']>('PATCH', `/users/${id}`, { body: b }),
  deleteUser: (id: number) => call<void>('DELETE', `/users/${id}`),
  audit: (q: { action?: string; cursor?: string; limit?: number }) => get<S['AuditPage']>('/audit', q),
  auditVerify: () => get<S['AuditVerify']>('/audit/verify'),

  // Data (API-001)
  info: () => get<S['SystemInfo']>('/system/info'),
  summary: (from = '-24h') => get<S['Summary']>('/stats/summary', { from }),
  timeseries: (q: { from?: string; step?: S['Step'] }) => get<S['Items_TimeBucket']>('/stats/timeseries', q),
  top: (kind: S['TopKind'], limit = 10, client?: string) => get<S['Items_TopItem']>('/stats/top', { kind, limit, client }),
  latency: (by: S['LatencyBy']) => get<S['Items_LatencyRow']>('/stats/latency', { by }),
  queries: (q: Query) => get<S['QueryPage']>('/queries', q),
  explain: (q: { name: string; client?: string; qtype?: string }) => get<S['Explanation']>('/explain', q),
  lists: () => get<S['Items_ListInfo']>('/lists'),
  groups: () => get<S['Items_GroupInfo']>('/groups'),
  clients: () => get<S['Items_ClientInfo']>('/clients'),
  localNames: () => get<S['Items_LocalName']>('/records'),
  forwards: () => get<S['Items_ForwardInfo']>('/forwards'),
  upstreams: () => get<S['Items_UpstreamInfo']>('/upstreams'),

  // Configuration changes (API-002, API-010). Each change carries a fresh Idempotency-Key, so a
  // retried request (flaky Wi-Fi) is applied once.
  putClient: (name: string, body: S['ClientInput'], dryRun = false) =>
    call<S['ClientChange']>('PUT', `/clients/${encodeURIComponent(name)}`, {
      body,
      query: { dryRun: dryRun || undefined },
      headers: dryRun ? {} : { 'idempotency-key': newKey() },
    }),
  putRecords: (name: string, body: S['RecordsInput'], dryRun = false) =>
    call<S['ConfigChange']>('PUT', `/records/${encodeURIComponent(name)}`, {
      body,
      query: { dryRun: dryRun || undefined },
      headers: dryRun ? {} : { 'idempotency-key': newKey() },
    }),
  deleteRecords: (name: string) =>
    call<S['ConfigChange']>('DELETE', `/records/${encodeURIComponent(name)}`, { headers: { 'idempotency-key': newKey() } }),
  putForward: (domain: string, body: S['ForwardInput'], dryRun = false) =>
    call<S['ConfigChange']>('PUT', `/forwards/${encodeURIComponent(domain)}`, {
      body,
      query: { dryRun: dryRun || undefined },
      headers: dryRun ? {} : { 'idempotency-key': newKey() },
    }),
  deleteForward: (domain: string) =>
    call<S['ConfigChange']>('DELETE', `/forwards/${encodeURIComponent(domain)}`, { headers: { 'idempotency-key': newKey() } }),
  deleteClient: (name: string) =>
    call<S['ClientChange']>('DELETE', `/clients/${encodeURIComponent(name)}`, {
      headers: { 'idempotency-key': newKey() },
    }),
};
