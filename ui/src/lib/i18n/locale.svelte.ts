// REQ: API-005, API-011 — the UI speaks English and Simplified Chinese. The choice is kept in
// this browser (like the theme and the detail level); until someone chooses, the browser's own
// languages decide, so a Chinese browser opens in Chinese and every other one in English.
export const LOCALES = ['en', 'zh-CN'] as const;
export type Locale = (typeof LOCALES)[number];

const STORAGE = 'telltale.locale';

export function isLocale(v: unknown): v is Locale {
  return v === 'en' || v === 'zh-CN';
}

/** `?lang=zh-CN` on any URL: the way a shared link or a browser bookmark sets the language. */
function fromQuery(): Locale | null {
  try {
    const v = new URLSearchParams(location.search).get('lang');
    return isLocale(v) ? v : null;
  } catch {
    return null;
  }
}

function fromStorage(): Locale | null {
  try {
    const v = localStorage.getItem(STORAGE);
    return isLocale(v) ? v : null;
  } catch {
    return null;
  }
}

/** The first of the browser's languages that we speak; anything Chinese is `zh-CN`. */
function fromBrowser(): Locale {
  let langs: readonly string[] = [];
  try {
    langs = navigator.languages?.length ? navigator.languages : [navigator.language];
  } catch {
    // No navigator (a test runner importing this module): English.
  }
  for (const l of langs) if (l && l.toLowerCase().startsWith('zh')) return 'zh-CN';
  return 'en';
}

export function detectLocale(): Locale {
  return fromQuery() ?? fromStorage() ?? fromBrowser();
}

/** The language on screen. `t()` reads `i18n.locale`, so changing it re-renders every string. */
export const i18n = $state<{ locale: Locale }>({ locale: detectLocale() });

/** The tag to hand to `Intl` and to `<html lang>`. */
export function localeTag(): string {
  return i18n.locale;
}

function applyDocumentLang() {
  try {
    document.documentElement.lang = i18n.locale;
  } catch {
    // No document (a script importing this module): nothing to mark up.
  }
}

export function setLocale(l: Locale) {
  i18n.locale = l;
  try {
    localStorage.setItem(STORAGE, l);
  } catch {
    // Private mode: the choice lasts for this page.
  }
  applyDocumentLang();
}

/** `English` / `中文`: the name of a language in that language, for the switcher. */
export function localeName(l: Locale): string {
  return l === 'zh-CN' ? '中文' : 'English';
}

// A `?lang=` link is a choice too: remember it, then drop it from the address bar so the next
// page keeps it (the router never sees it).
(() => {
  const q = fromQuery();
  if (q) {
    try {
      localStorage.setItem(STORAGE, q);
    } catch {
      // Private mode: the query parameter still applies for this page.
    }
    try {
      const url = new URL(location.href);
      url.searchParams.delete('lang');
      history.replaceState(history.state, '', url.toString());
    } catch {
      // No history (a test runner): the parameter did its job already.
    }
  }
  applyDocumentLang();
})();