import { mount } from 'svelte';
import './app.css';
import App from './App.svelte';
import { installFormat, makeFormat } from './lib/format';
import { earlyCalls, install, load, tr, type Choice } from './lib/i18n';
import { LOCALES } from './lib/i18n/locales.gen';

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
  try {
    stored = localStorage.getItem('telltale.locale');
  } catch {
    // Storage blocked: the browser's languages decide.
  }
  let choice: Choice = { tag: 'en' };
  try {
    choice = await load(LOCALES, { search: location.search, stored, languages: navigator.languages ?? [] }, fetch);
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
    // English is drawn as before; a page in another language that fails to draw is drawn in English.
    if (rt.lang === 'en') throw e;
    console.error(e);
    target.replaceChildren();
    use({ tag: 'en' });
    mount(App, { target });
  }
}

void start();
