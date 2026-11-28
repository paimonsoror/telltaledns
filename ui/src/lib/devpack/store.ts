// REQ: API-013 (ADR-190) — a test language pack in this browser: one storage key for this address
// holds either the record and the file's text together (one write, so two tabs can never pair one
// file's record with another's text), or the notice that the pack was removed and why. The record
// carries two stamps, the web UI build and the server's build commit, and lasts 7 days. With them it
// keeps what the check of the text gave (the table a page installs), stamped with the build and the
// fingerprint it was made for: a page load uses it only while both are unchanged, and checks the text
// again otherwise (or when the kept table is not well formed). Same record, same write. It also names
// the user who loaded it: the pack is that user's, paused for anyone else. A tab writes over or removes
// only what it read, while the key still holds it, so a tab left open never replaces or deletes a pack
// another tab loaded since.
import { DEVPACK_KEY } from '../i18n/devpack';
import { canonical } from '../i18n/match';

/** The one-load flag (session storage, removed when read): `1` after "Show the test pack on this page",
 * `away` after the pack left a page because someone went away, `in` after a page reloaded for a sign-in. */
export const ONCE_KEY = 'telltale.devpack.once';
/** This web UI's build: the path of the page's entry module (`/assets/index-<hash>.js`, whose content-hashed
 * name changes with the English by construction; under the development server, `/src/main.ts`), from this
 * address, whatever other module scripts the page holds (a browser extension's, from this address or another, the
 * development server's client). */
export function entryPath(): string {
  const own = (sel: string) => [...document.querySelectorAll<HTMLScriptElement>(sel)].map((s) => new URL(s.src, location.href)).find((u) => u.origin === location.origin);
  return (own('script[type="module"][src*="/assets/index-"]') ?? own('script[type="module"][src*="/src/main."]'))?.pathname ?? '';
}

/** How long a pack (and the notice after one) lasts. */
export const LIFETIME_MS = 7 * 24 * 3600 * 1000;

/** Why a pack was removed: another build, 7 days, an unreadable copy, a check that threw twice in a row, or a page
 * that failed to draw with it. */
export type Gone = 'upgrade' | 'expired' | 'damaged' | 'failed' | 'draw';
export type PackRecord = {
  readonly v: 1;
  /** The web UI build it was loaded on (the entry module's path). */
  readonly ui: string;
  /** The server build it was loaded on. */
  readonly server: { readonly commit: string };
  /** Who was signed in when it was loaded: the pack applies to that user only (ADR-190). */
  readonly user: string;
  readonly loadedAt: number;
  readonly expires: number;
  /** The file's name as chosen (shown sanitized), its SHA-256 (64 hex), the language tag and direction. */
  readonly name: string;
  readonly sha: string;
  readonly tag: string;
  readonly dir: 'ltr' | 'rtl';
  /** Checks in a row that threw on this file and build. */
  readonly fails: number;
  readonly text: string;
  /** What the check of `text` gave on the web UI build `ui`, for the fingerprint `sha`: hash ->
   * translation (or plural forms). Absent: each load checks the text. */
  readonly checked?: { readonly ui: string; readonly sha: string; readonly table: Readonly<Record<string, unknown>> };
};
export type Notice = { readonly v: 1; readonly gone: Gone; readonly name: string; readonly at: number };
export type Store = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;

/** A tag as the card stores it: a language tag in its canonical form, not for private use (the card's check of the
 * tag says the same before Use; the rest of it needs the plural table, which a page load does not fetch). */
const isTag = (t: string) => canonical(t) === t && !/(^|-)x-/i.test(t);

const isRecord = (x: Record<string, unknown>): boolean =>
  typeof x.ui === 'string' &&
  !!x.server &&
  typeof (x.server as { commit?: unknown }).commit === 'string' &&
  typeof x.user === 'string' &&
  Number.isFinite(x.loadedAt) &&
  Number.isFinite(x.expires) &&
  typeof x.name === 'string' &&
  typeof x.sha === 'string' &&
  /^[0-9a-f]{64}$/.test(x.sha) &&
  typeof x.tag === 'string' &&
  isTag(x.tag) &&
  (x.dir === 'ltr' || x.dir === 'rtl') &&
  Number.isInteger(x.fails) &&
  (x.fails as number) >= 0 &&
  typeof x.text === 'string';
const GONE = ['upgrade', 'expired', 'damaged', 'failed', 'draw'];
const isNotice = (x: Record<string, unknown>): boolean => typeof x.gone === 'string' && GONE.includes(x.gone) && typeof x.name === 'string' && Number.isFinite(x.at);

/** What a stored value is: a record, a notice, or damaged (anything else). */
export function readValue(value: string): { record: PackRecord } | { notice: Notice } | { damaged: true } {
  let x: unknown;
  try {
    x = JSON.parse(value);
  } catch {
    return { damaged: true };
  }
  if (!x || typeof x !== 'object' || Array.isArray(x) || (x as { v?: unknown }).v !== 1) return { damaged: true };
  const o = x as Record<string, unknown>;
  if (isRecord(o)) return { record: o as PackRecord };
  if (isNotice(o)) return { notice: o as Notice };
  return { damaged: true };
}

/** Why a record no longer applies on this web UI build at `now`, or null: another build of the web UI,
 * or 7 days gone, by a clock that runs either way (loaded after now, or meant to last longer than 7 days:
 * expired too). (The server's build is compared after sign-in, with the app's build poll.) */
export function lifetime(r: PackRecord, ui: string, now: number): Gone | null {
  if (r.ui !== ui) return 'upgrade';
  if (now >= r.expires || now < r.loadedAt || r.expires - r.loadedAt > LIFETIME_MS) return 'expired';
  return null;
}

/** Whether a notice dated `at` no longer applies at `now`: 7 days gone, or dated after now. */
export const stale = (at: number, now: number) => now - at > LIFETIME_MS || at > now;

/** One write of the key; false when the browser cannot keep it (storage blocked or full): then
 * nothing was written. */
export function write(store: Store | null, v: PackRecord | Notice): boolean {
  if (!store) return false;
  try {
    store.setItem(DEVPACK_KEY, JSON.stringify(v));
    return true;
  } catch {
    return false;
  }
}

/** The notice that replaces a pack. */
export const notice = (gone: Gone, name: string, at: number): Notice => ({ v: 1, gone, name, at });

/** Removes the key (the pack or its notice). */
export function forget(store: Store | null): void {
  try {
    store?.removeItem(DEVPACK_KEY);
  } catch {
    // Storage blocked: there is nothing to remove.
  }
}

/** What a tab read from the key: a record (known by its fingerprint and load time), a notice, or the value as
 * read (one that was damaged). */
export type Held = PackRecord | Notice | string;

/** Whether the key still holds what this tab read: another tab may have put a newer pack there meanwhile. */
export function holds(store: Store | null, ref: Held): boolean {
  let v: string | null = null;
  try {
    v = store?.getItem(DEVPACK_KEY) ?? null;
  } catch {
    return false;
  }
  if (v === null) return false;
  if (typeof ref === 'string') return v === ref;
  const got = readValue(v);
  if ('record' in got) return 'sha' in ref && got.record.sha === ref.sha && got.record.loadedAt === ref.loadedAt;
  if ('notice' in got) return 'gone' in ref && got.notice.gone === ref.gone && got.notice.at === ref.at && got.notice.name === ref.name;
  return false;
}

/** Writes `next` over what this tab read, only while the key still holds it. */
export const rewrite = (store: Store | null, ref: Held, next: PackRecord | Notice) => holds(store, ref) && write(store, next);

/** Removes what this tab read, only while the key still holds it, and leaves `next` (a notice) instead. The key
 * is emptied first, so a write that fails never leaves the old value behind. True when the key no longer holds
 * `ref` (removed now, or replaced by another tab before). */
export function retire(store: Store | null, ref: Held, next?: Notice): boolean {
  if (holds(store, ref)) {
    forget(store);
    if (next) write(store, next);
  }
  return !holds(store, ref);
}

/** The record of a pack loaded now from a checked file (with the check's table, when given). */
export function newRecord(
  p: { ui: string; commit: string; user: string; name: string; sha: string; tag: string; dir: 'ltr' | 'rtl'; text: string; table?: Readonly<Record<string, unknown>> },
  now: number,
): PackRecord {
  const rec: PackRecord = { v: 1, ui: p.ui, server: { commit: p.commit }, user: p.user, loadedAt: now, expires: now + LIFETIME_MS, name: p.name, sha: p.sha, tag: p.tag, dir: p.dir, fails: 0, text: p.text };
  return p.table ? { ...rec, checked: { ui: p.ui, sha: p.sha, table: p.table } } : rec;
}

/** A kept table that is well formed: 8-hex keys; a string, or an object of plural forms (strings, `other`
 * among them), as values. Anything else: null (the page checks the text again). */
export function keptTable(t: unknown): Record<string, string | Record<string, string>> | null {
  if (!t || typeof t !== 'object' || Array.isArray(t)) return null;
  const out: Record<string, string | Record<string, string>> = Object.create(null);
  for (const [k, v] of Object.entries(t)) {
    if (!/^[0-9a-f]{8}$/.test(k)) return null;
    if (typeof v === 'string') out[k] = v;
    else if (v && typeof v === 'object' && !Array.isArray(v) && Object.hasOwn(v, 'other') && Object.values(v).every((s) => typeof s === 'string')) out[k] = v as Record<string, string>;
    else return null;
  }
  return out;
}
