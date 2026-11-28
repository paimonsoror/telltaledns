import { mount } from 'svelte';
import './app.css';
import App from './App.svelte';
import { installFormat, makeFormat } from './lib/format';
import { earlyCalls, install, load, tr, type Choice } from './lib/i18n';
import { DEVPACK_KEY, devpack } from './lib/i18n/devpack';
import { LOCALES, TEMPLATE } from './lib/i18n/locales.gen';

// REQ: API-013 (ADR-190) — this web UI's template, for a test language pack.
devpack.template = TEMPLATE;

// REQ: API-012 (ADR-189) — the language is settled before the page is drawn: `?lang=` (this page
// load only, never stored), the stored choice, then the browser's languages. A catalog has 4 s to
// arrive, then the page is English. The formats and `<html lang>`/`dir` follow before the mount.
function use(choice: Choice) {
  const rt = install(choice);
  installFormat(makeFormat(rt.formatLocale, tr));
  document.documentElement.lang = rt.lang;
  document.documentElement.dir = rt.dir;
  return rt;
}

async function start() {
  let stored: string | null = null;
  let pack: string | null = null;
  try {
    stored = localStorage.getItem('telltale.locale');
    pack = localStorage.getItem(DEVPACK_KEY);
  } catch {
    // Storage blocked: the browser's languages decide.
  }
  // REQ: API-013 (ADR-190) — a test pack's code loads only when this browser keeps one (or the
  // notice after one); it comes before the stored choice, and pauses itself under `?lang=`.
  const value = pack;
  const provider = value === null ? undefined : (signal: AbortSignal) => import('./lib/devpack/devpack-boot').then((m) => m.boot(value, signal));
  let choice: Choice = { tag: 'en' };
  try {
    choice = await load(LOCALES, { search: location.search, stored, languages: navigator.languages ?? [] }, fetch, 4000, provider);
  } catch {
    // Whatever went wrong in choosing the language, the page is English.
  }
  const before = earlyCalls();
  const rt = use(choice);
  // For the page tests: messages read before the language was installed (expected: none).
  if (rt.lang === 'en-XA') document.documentElement.dataset.i18nEarly = String(before);
  const target = document.getElementById('app');
  if (!target) return;
  try {
    mount(App, { target });
  } catch (e) {
    // English is drawn as before; a page in another language that fails to draw is drawn in English
    // (a test pack is removed instead, and the page loads once more without it).
    if (rt.lang === 'en') throw e;
    console.error(e);
    if (devpack.failed?.()) return;
    target.replaceChildren();
    use({ tag: 'en' });
    mount(App, { target });
  }
}

void start();
