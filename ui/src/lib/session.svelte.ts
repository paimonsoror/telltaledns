// Who is signed in. Loaded from GET /auth/status on start and after sign-in/out.

import { api, setCsrf, whenSignedOut, type S } from './api';
import { devpack } from './i18n/devpack';

export const session = $state({
  loaded: false,
  /** The server can't be reached or answered with an error. */
  error: '',
  setupRequired: false,
  user: null as S['Me'] | null,
  /** Sign-in providers (OIDC) and whether the password form is offered here. */
  oidc: [] as S['OidcButton'][],
  localLogin: true,
  /** REQ: API-004 (ADR-175) — password sign-in is limited to admins on trusted networks. */
  passwordLoginRestricted: false,
});

export async function refreshSession() {
  try {
    const s = await api.status();
    session.setupRequired = s.setupRequired;
    session.user = s.user ?? null;
    session.oidc = s.oidc;
    session.localLogin = s.localLogin;
    // An older server doesn't send it: it reads as "not restricted", as before.
    session.passwordLoginRestricted = s.passwordLoginRestricted ?? false;
    setCsrf(s.csrfToken ?? undefined);
    session.error = '';
  } catch (e) {
    session.error = e instanceof Error ? e.message : String(e);
  } finally {
    session.loaded = true;
  }
}

/** After sign-in or setup. */
export function signedIn(r: S['LoginResponse']) {
  setCsrf(r.csrfToken);
  session.user = r.user;
  session.setupRequired = false;
}

let out: Promise<void> | undefined;

/** REQ: API-013 (ADR-190) — one sign-out at a time: a call while one is under way (a second click before the answer)
 * gets that one's promise and does nothing else, so it never undoes where the first one sends the page. */
export function signOut() {
  return (out ??= leave().finally(() => (out = undefined)));
}

async function leave() {
  let next: string | undefined;
  // REQ: API-013 (ADR-190) — a sign-out under way: a test pack's code reloads no page until the answer says whether
  // the page leaves for the provider.
  devpack.leaving = true;
  try {
    // REQ: API-004 — OIDC sessions also sign out at the provider.
    next = (await api.logout())?.logoutUrl ?? undefined;
  } finally {
    setCsrf(undefined);
    // Set before the user is cleared: a test pack's code never reloads a page that leaves for the provider, and
    // reloads one now that it held back meanwhile.
    devpack.leaving = !!next;
    session.user = null;
    if (!next) devpack.settled?.();
  }
  if (next) location.href = next;
}

whenSignedOut(() => {
  setCsrf(undefined);
  session.user = null;
});

const rank = { viewer: 0, operator: 1, admin: 2 } as const;

export function can(role: S['Role']): boolean {
  return session.user !== null && rank[session.user.role] >= rank[role];
}
