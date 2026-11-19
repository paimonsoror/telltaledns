// REQ: API-005 (issue #64) — a markup rule that is not about one page. In a quoted attribute Svelte
// reads `{...}` as an expression: `pattern="[0-9]{6}"` became `pattern="[0-9]6"`, so no 6-digit
// code could be entered in two places (turning two-factor on, and signing in with it). Write such
// a value as an expression: `pattern={'[0-9]{6}'}`.
import { expect, test } from '@playwright/test';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

const SRC = resolve(import.meta.dirname, '../../src');

function svelteFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    return statSync(p).isDirectory() ? svelteFiles(p) : p.endsWith('.svelte') ? [p] : [];
  });
}

// A quoted attribute, in either kind of quote: `name="value"` or `name='value'`. The value may run
// over several lines and may hold `{...}` expressions of its own.
const QUOTED_ATTRIBUTE = /\s([\w:-]+)=(?:"([^"]*)"|'([^']*)')/g;
// `{digits}` or `{digits,digits}`: a regex quantifier to the reader, an expression to Svelte.
const QUANTIFIER = /\{\d+(?:,\d*)?\}/;

/** Every quoted attribute in `text` whose value holds something like a regex quantifier: `[offset, text]`. */
function quantifierAttributes(text: string): [number, string][] {
  return [...text.matchAll(QUOTED_ATTRIBUTE)]
    .filter((m) => QUANTIFIER.test(m[2] ?? m[3] ?? ''))
    .map((m): [number, string] => [m.index ?? 0, m[0].trim()]);
}

test('api_005 no quoted attribute holds a {n} that Svelte would read as an expression', () => {
  const found: string[] = [];
  for (const file of svelteFiles(SRC)) {
    const text = readFileSync(file, 'utf8');
    for (const [at, attribute] of quantifierAttributes(text)) {
      const line = text.slice(0, at + 1).split('\n').length;
      found.push(`${relative(SRC, file)}:${line}:${attribute}`);
    }
  }
  expect(found, "write the value as an expression, e.g. pattern={'[0-9]{6}'}").toEqual([]);
});

// The check has to be able to fail: each of these is the mistake in another shape, or not a mistake.
test('api_005 the check sees the mistake it is for, and not the fix', () => {
  expect(quantifierAttributes('<input pattern="[0-9]{6}" maxlength="6" />').length).toBe(1);
  expect(quantifierAttributes('<input class="a" pattern="[a-z]{2,}">').length).toBe(1);
  expect(quantifierAttributes("<input pattern={'[0-9]{6}'} maxlength=\"6\" />")).toEqual([]);
  expect(quantifierAttributes('<a href="/x/{id}" class="a b">')).toEqual([]);
  expect(quantifierAttributes(`<div class="a {open ? 'b' : 'c'}" title='x {y}'>`)).toEqual([]);
});

test('api_005 the check sees single-quoted values too', () => {
  expect(quantifierAttributes("<input pattern='[0-9]{6}' />").length).toBe(1);
  expect(quantifierAttributes(`<a title='say "hi" {2}'>`).length).toBe(1);
});

test('api_005 the check sees a quantifier after another expression in the value', () => {
  expect(quantifierAttributes('<input pattern="{prefix}[0-9]{6}" />').length).toBe(1);
});

test('api_005 the check sees values that run over several lines, and reports the right line', () => {
  const text = '<input\n  class="a"\n  pattern="[0-9]\n  {6}"\n/>';
  const found = quantifierAttributes(text);
  expect(found.length).toBe(1);
  expect(text.slice(0, found[0][0] + 1).split('\n').length).toBe(3);
  expect(quantifierAttributes('<p title="first\nsecond {2,3}">').length).toBe(1);
});
