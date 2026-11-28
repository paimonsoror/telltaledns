// REQ: API-013 (ADR-190) — the code a page load runs when this browser keeps a test language pack (or
// the notice after one); an English reader never loads it. It decides (`lifecycle.ts`), shows the
// English banner in its own node before the app, above every overlay, and returns the pack's language
// for this load. The checking code (`recheck.ts`) loads only when the file is checked again: a load
// with the table kept for this build and file needs neither it nor the template. After sign-in it
// compares the server's build commit, from the app's own build poll, with the one the pack was loaded
// on: the first answer of a load that differs removes the pack and reloads; a later one removes it and
// says so, without a reload, so nothing typed is lost. It follows who is signed in, as the app tells it:
// someone going away (a sign-out, a session that ends, the display page) takes a pack this load shows
// away (a sign-out that goes on to the provider's lets the page leave, and the page it comes back to is
// paused; Back to the page that left, shown again from the browser's cache, reloads it), and a sign-in on a
// page paused for nobody or for another user reloads (`whenSeen`, `lifecycle.ts`). Each of these reloads leaves a
// flag for the load it lands on: after someone went away that load is paused, whoever the status says is
// signed in; and after either reload it does not reload for the first user the app reports. So reads of who is
// signed in that disagree (nodes that don't share sessions), in either direction or in turn, reload a page
// twice at most in a row. "Show the test pack on this page" keeps its one load as it is. A tab removes or
// writes over only what it read, and reloads only once the key no longer holds the pack, so a value it cannot
// change never makes it reload again.
import { mount } from 'svelte';
import type { Choice } from '../i18n';
import { devpack } from '../i18n/devpack';
import DevPackBanner from './DevPackBanner.svelte';
import { decide, whenSeen, type Decision, type View } from './lifecycle';
import { ONCE_KEY, entryPath, notice, retire, type Held, type PackRecord, type Store } from './store';

performance.mark('telltale.devpack.start');

let store: Store | null = null;
let session: Store | null = null;
let record: PackRecord | null = null;
/** What this load read and the banner's Remove or Dismiss takes away: the record, or the notice. */
let held: Held | null = null;
let installed = false;
let banner: { set(v: View): void } | undefined;

const reload = () => location.reload();
const actions = {
  remove() {
    if (held) retire(store, held);
    reload();
  },
  dismiss() {
    if (held) retire(store, held);
    devpack.active = false;
    banner?.set({ kind: 'none' });
  },
  once() {
    try {
      session?.setItem(ONCE_KEY, '1');
    } catch {
      // Session storage blocked: the page reloads paused.
    }
    reload();
  },
  reload,
};

/** The pack's language for this page load (null: the usual language), with the banner shown. `signal` ends
 * when the page load stops waiting: then nothing is shown, and the page is in the usual language. */
export async function boot(value: string, signal: AbortSignal): Promise<Choice | null> {
  try {
    store = localStorage;
    session = sessionStorage;
  } catch {
    // Storage blocked: there is no pack to read.
  }
  const out = await decide(value, {
    store,
    takeOnce: () => {
      try {
        const v = session?.getItem(ONCE_KEY) ?? null;
        session?.removeItem(ONCE_KEY);
        return v;
      } catch {
        return null;
      }
    },
    fetch: (input, init) => fetch(input, init),
    now: () => Date.now(),
    ui: entryPath(),
    template: devpack.template,
    search: location.search,
    hash: location.hash,
    languages: navigator.languages ?? [],
    checker: () => import('./recheck'),
    signal,
  });
  // The page load stopped waiting (a request or a chunk that stalled): the page is drawn in the usual language,
  // and a pack that arrives late says it could not be checked, never that it is in use.
  const r = out.record;
  const late = signal.aborted && out.choice !== null;
  const view: View = late && r ? { kind: 'unchecked', name: r.name, sha: r.sha, tag: r.tag } : out.view;
  record = r;
  held = r ?? out.notice ?? null;
  installed = !late && out.choice !== null;
  devpack.failed = failed;
  if (view.kind !== 'none') {
    devpack.active = true;
    const host = document.createElement('div');
    host.className = 'devpack-host';
    document.body.insertBefore(host, document.getElementById('app'));
    banner = mount(DevPackBanner, { target: host, props: { view, actions } });
  }
  if (r) {
    watchServer(r);
    watchUser(r, out);
  }
  performance.mark('telltale.devpack.ready');
  return installed ? out.choice : null;
}

function watchServer(r: PackRecord) {
  let first = true;
  devpack.onBuild = (commit) => {
    if (!commit) return;
    const wasFirst = first;
    first = false;
    if (!record || commit === r.server.commit) return;
    // Another server build (an upgrade, a rollback or a downgrade): the pack goes, with a notice. The first
    // answer of a load reloads, once the key no longer holds the pack (a reload never finds it again).
    record = null;
    const gone = retire(store, r, notice('upgrade', r.name, Date.now()));
    if (wasFirst && gone) reload();
    else banner?.set({ kind: 'updated', name: r.name, sha: r.sha, tag: r.tag });
  };
}

/** A page that left for the provider's sign-out, shown again from the browser's back-forward cache: it reloads. */
const shownAgain = (e: PageTransitionEvent) => e.persisted && reload();

/** Who is signed in, as the app says on every change of page (null: nobody, or the display page), against who was
 * when this load decided, by the rules of `whenSeen`: the flag for the next load, then the reload (none while the
 * page leaves for the provider's sign-out, which a reload would cancel). */
function watchUser(r: PackRecord, out: Decision) {
  let last: string | null | undefined;
  // A reload held back while a sign-out waited for the server's answer (a request found the session gone meanwhile).
  let held = false;
  devpack.settled = () => {
    if (!held) return;
    held = false;
    removeEventListener('pageshow', shownAgain);
    reload();
  };
  devpack.seen = (who) => {
    // Someone is signed in again: a page that was to leave for the provider's sign-out did not (its address never
    // replaced the page), and the next sign-out or session end takes the pack away as any does.
    if (who !== null && who !== last && devpack.leaving) {
      devpack.leaving = false;
      held = false;
      removeEventListener('pageshow', shownAgain);
    }
    const act = whenSeen(out, who, { installed, last, leaving: !!devpack.leaving });
    last = who;
    if (act === 'none') return;
    try {
      session?.setItem(ONCE_KEY, act === 'in' ? 'in' : 'away');
    } catch {
      // Session storage blocked: the next load decides from the status alone.
    }
    // The provider's session would stay if this page reloaded now; the page the provider sends back to is paused.
    // Back to this page may show it again as it is, from the browser's back-forward cache, with the pack and nobody
    // signed in: it reloads then, into a paused load.
    if (act === 'leave') {
      held = true;
      addEventListener('pageshow', shownAgain, { once: true });
      return;
    }
    if (act === 'in' && who === r.user) banner?.set({ kind: 'signed-in', name: r.name, sha: r.sha, tag: r.tag });
    reload();
  };
}

/** The page failed to draw with the pack: it is removed, with a notice that says so, and the page reloads once
 * without it (when the key still held it and no longer does; otherwise the page is drawn in English as it is). */
function failed(): boolean {
  if (!installed || !record) return false;
  if (!retire(store, record, notice('draw', record.name, Date.now()))) return false;
  record = null;
  reload();
  return true;
}
