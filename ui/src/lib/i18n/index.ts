// REQ: API-011, ADR-036 — `t()`: the one way the UI says anything to a person. It reads the
// locale state, so a template that calls it re-renders when the language changes. A missing
// Chinese string falls back to English rather than showing a key.
import { en, type MessageKey } from './messages/en';
import { zh } from './messages/zh-CN';
import { i18n } from './locale.svelte';

export { i18n, setLocale, localeTag, localeName, detectLocale, LOCALES, isLocale } from './locale.svelte';
export type { Locale } from './locale.svelte';
export type { MessageKey };

export type Params = Record<string, string | number>;

const INTERPOLATE = /\{(\w+)\}/g;

function interpolate(text: string, params?: Params): string {
  if (!params) return text;
  return text.replace(INTERPOLATE, (whole, name: string) =>
    name in params ? String(params[name]) : whole,
  );
}

function table(): Partial<Record<MessageKey, string>> & Record<string, string> {
  return i18n.locale === 'zh-CN' ? zh : (en as unknown as Record<string, string>);
}

/**
 * The text for `key` in the language on screen. Placeholders look like `{name}` and are filled
 * from `params`; an unknown placeholder is left as it is (a typo shows up instead of vanishing).
 */
export function t(key: MessageKey, params?: Params): string {
  // `table()` reads `i18n.locale`, which is what makes every translated string reactive.
  const chosen = table()[key];
  const text = chosen ?? (en as Record<string, string>)[key] ?? key;
  return interpolate(text, params);
}

/**
 * A count with the right plural form: `tn('queries.rows', n)` looks up `queries.rows.one` or
 * `queries.rows.other` for the locale's plural rules and passes `n` as `{n}`. The base key is a
 * prefix, not a string of its own; `check:i18n` proves every `.one` has its `.other`.
 */
export function tn(key: string, n: number, params?: Params): string {
  const category = new Intl.PluralRules(i18n.locale).select(n);
  const one = `${key}.${category}`;
  const other = `${key}.other`;
  const exists = (k: string) =>
    table()[k as MessageKey] !== undefined || (en as Record<string, string>)[k] !== undefined;
  return t((exists(one) ? one : other) as MessageKey, { n, ...params });
}
