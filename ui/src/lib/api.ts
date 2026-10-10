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

export type EntryPath = 'upstreams' | 'upstream-groups' | 'lists' | 'groups' | 'alerts/destinations' | 'alerts/rules' | 'schedules' | 'ratelimit' | 'exclusions';

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
  userTokens: (id: number) => get<S['Listed_TokenInfo']>(`/users/${id}/tokens`),
  revokeUserToken: (id: number, token: string) =>
    call<void>('DELETE', `/users/${id}/tokens/${encodeURIComponent(token)}`),
  audit: (q: { action?: string; cursor?: string; limit?: number }) => get<S['AuditPage']>('/audit', q),
  auditVerify: () => get<S['AuditVerify']>('/audit/verify'),

  // Data (API-001)
  info: () => get<S['SystemInfo']>('/system/info'),
  // REQ: AGT-007 (T7.1) — agents' plans; operators approve or reject them.
  plans: () => get<S['Items_Plan']>('/plans'),
  approvePlan: (id: string) => post<S['Plan']>(`/plans/${encodeURIComponent(id)}/approve`),
  rejectPlan: (id: string) => post<S['Plan']>(`/plans/${encodeURIComponent(id)}/reject`),
  // REQ: OPS-004 — "Check now" (admin).
  checkUpdates: () => post<S['UpdateStatus']>('/system/update-check'),
  // `scope`: `cluster` (default, every node), `node:<id>`, or `site:<name>` (CLU-002).
  summary: (from = '-24h', to?: string, scope?: string) =>
    get<S['Summary']>('/stats/summary', { from, to, scope }),
  timeseries: (q: { from?: string; step?: S['Step']; scope?: string }) =>
    get<S['Items_TimeBucket']>('/stats/timeseries', q),
  top: (kind: S['TopKind'], limit = 10, client?: string, group?: string, scope?: string) =>
    get<S['Items_TopItem']>('/stats/top', { kind, limit, client, group, scope }),
  latency: (by: S['LatencyBy'], scope?: string) => get<S['Items_LatencyRow']>('/stats/latency', { by, scope }),
  // REQ: OBS-016 — the service-level objectives and their error budgets.
  slo: (scope?: string) => get<S['SloStatus']>('/stats/slo', { scope }),
  queries: (q: Query) => get<S['QueryPage']>('/queries', q),
  explain: (q: { name: string; client?: string; qtype?: string }) => get<S['Explanation']>('/explain', q),
  lists: () => get<S['Items_ListInfo']>('/lists'),
  groups: () => get<S['Items_GroupInfo']>('/groups'),
  // REQ: FLT-012 (T7.9) — the blockable services.
  services: () => get<S['Items_ServiceInfo']>('/services'),
  clients: () => get<S['Items_ClientInfo']>('/clients'),
  anomalies: (since = '-7d', acknowledged?: boolean) =>
    get<S['Items_AnomalyFinding']>('/analytics/anomalies', { since, acknowledged: acknowledged === undefined ? undefined : String(acknowledged) }),
  // REQ: OBS-014 — acknowledge findings (or take it back), on every node.
  acknowledgeAnomalies: (ids: string[], note?: string) =>
    post<S['AnomalyAckResult']>('/analytics/anomalies/acknowledge', { ids, ...(note ? { note } : {}) }),
  unacknowledgeAnomalies: (ids: string[]) => post<S['AnomalyAckResult']>('/analytics/anomalies/unacknowledge', { ids }),
  // REQ: OBS-015 — healthy, degraded, or severe, and why.
  health: () => get<S['Health']>('/system/health'),
  // REQ: OBS-020 — the synthetic probes of every node's listeners.
  probes: () => get<S['Items_ProbeResult']>('/system/probes'),
  // REQ: OBS-009 (T7.14)
  newDomains: (since = '-24h', limit = 200) =>
    get<S['Items_NewDomain']>('/analytics/new-domains', { since, limit: String(limit) }),
  // REQ: AGT-012 (T8.6) — vqlog, from the Analyze page.
  vqlog: (q: string, dryRun = false) => get<S['VqlogResult']>('/analytics/vqlog', { q, dryRun: dryRun ? 'true' : undefined }),
  // REQ: T8.2, T8.3 — device names from the routers' DHCP and mDNS.
  dhcpLeases: () => get<S['Items_DhcpLease']>('/dhcp/leases'),
  // REQ: DNS-018 (T8.6)
  zones: () => get<S['Items_ZoneInfo']>('/zones'),
  // REQ: OBS-010 (T9.6)
  alertsStatus: () => get<S['AlertsStatus']>('/alerts'),
  alertTest: (name: string) => post<S['AlertTest']>(`/alerts/destinations/${encodeURIComponent(name)}/test`),
  // REQ: API-002 (T9.12) — pre-save checks of a draft.
  checkUpstream: (body: Record<string, unknown>) => post<S['CheckResult']>('/checks/upstream', body),
  checkList: (body: Record<string, unknown>) => post<S['CheckResult']>('/checks/list', body),
  cluster: () => get<S['ClusterView']>('/cluster'),
  promoteCluster: (emergency = false, password = '', totp = '') =>
    post<S['ClusterView']>('/cluster/promote', { emergency, password, ...(totp ? { totp } : {}) }),
  // REQ: OPS-010 — maintenance on a node (`local` or a node ID): not ready, still answering.
  startMaintenance: (node: string, body: S['MaintenanceRequest']) =>
    post<S['MaintenanceResult']>(`/nodes/${encodeURIComponent(node)}/maintenance`, body),
  endMaintenance: (node: string) => call<S['MaintenanceResult']>('DELETE', `/nodes/${encodeURIComponent(node)}/maintenance`),
  localNames: () => get<S['Items_LocalName']>('/records'),
  forwards: () => get<S['Items_ForwardInfo']>('/forwards'),
  rules: () => get<S['Items_RuleInfo']>('/rules'),
  cacheStats: () => get<S['Items_CacheNodeStats']>('/cache/stats'),
  cacheLookup: (name: string) => get<S['CacheLookup']>('/cache/lookup', { name }),
  cacheEntries: (q: { sort?: string; limit?: number; node?: string }) =>
    get<S['Items_CacheNodeEntries']>('/cache/entries', q),
  cacheFlush: (body: S['CacheFlushRequest']) => post<S['CacheFlushResult']>('/cache/flush', body),
  blocking: () => get<S['Items_BlockingNode']>('/blocking'),
  blockingPause: (body: S['BlockingRequest']) => post<S['Items_BlockingNode']>('/blocking/pause', body),
  blockingResume: (body: S['BlockingRequest']) => post<S['Items_BlockingNode']>('/blocking/resume', body),
  upstreams: () => get<S['Items_UpstreamInfo']>('/upstreams'),
  // REQ: OBS-018 — what shadow lists would have blocked, and likely over-blocking.
  shadowLists: () => get<S['Items_ShadowListStats']>('/analytics/shadow-lists'),
  overblocking: (limit = 50) => get<S['Items_OverblockSuspect']>('/analytics/overblocking', { limit }),
  // REQ: OBS-019 — upstream answer quality and second opinions, per node.
  upstreamChecks: () => get<S['Items_UpstreamChecks']>('/analytics/upstream-checks'),

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
  // REQ: FLT-005 (T6.12) — quick rules.
  putRule: (id: string, body: S['RuleInput'], dryRun = false) =>
    call<S['ConfigChange']>('PUT', `/rules/${encodeURIComponent(id)}`, {
      body,
      query: { dryRun: dryRun || undefined },
      headers: dryRun ? {} : { 'idempotency-key': newKey() },
    }),
  // REQ: API-002 (T7.5, ADR-069) — upstreams, upstream groups, lists, and groups.
  configEntries: (kind?: string) => get<S['Items_ConfigEntry']>('/config/entries', { kind }),
  putEntry: (path: EntryPath, name: string, body: Record<string, unknown>, dryRun = false) =>
    call<S['ConfigChange']>('PUT', `/${path}/${encodeURIComponent(name)}`, {
      body,
      query: { dryRun: dryRun || undefined },
      headers: dryRun ? {} : { 'idempotency-key': newKey() },
    }),
  deleteEntry: (path: EntryPath, name: string) =>
    call<S['ConfigChange']>('DELETE', `/${path}/${encodeURIComponent(name)}`, { headers: { 'idempotency-key': newKey() } }),
  deleteRule: (id: string) =>
    call<S['ConfigChange']>('DELETE', `/rules/${encodeURIComponent(id)}`, { headers: { 'idempotency-key': newKey() } }),
  deleteClient: (name: string) =>
    call<S['ClientChange']>('DELETE', `/clients/${encodeURIComponent(name)}`, {
      headers: { 'idempotency-key': newKey() },
    }),
};
