// Who is signed in. Loaded from GET /auth/status on start and after sign-in/out.

import { api, setCsrf, whenSignedOut, type S } from './api';

export const session = $state({
  loaded: false,
  /** The server can't be reached or answered with an error. */
  error: '',
  setupRequired: false,
  user: null as S['Me'] | null,
});

export async function refreshSession() {
  try {
    const s = await api.status();
    session.setupRequired = s.setupRequired;
    session.user = s.user ?? null;
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

export async function signOut() {
  try {
    await api.logout();
  } finally {
    setCsrf(undefined);
    session.user = null;
  }
}

whenSignedOut(() => {
  setCsrf(undefined);
  session.user = null;
});

const rank = { viewer: 0, operator: 1, admin: 2 } as const;

export function can(role: S['Role']): boolean {
  return session.user !== null && rank[session.user.role] >= rank[role];
}
