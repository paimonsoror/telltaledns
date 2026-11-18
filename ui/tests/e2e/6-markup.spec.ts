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

// A quoted attribute value holding `{digits}` or `{digits,digits}`: a regex quantifier to the
// reader, an expression to Svelte.
const QUANTIFIER_IN_ATTRIBUTE = /\s([\w:-]+)="[^"{}]*\{\d+(?:,\d*)?\}[^"]*"/g;

test('api_005 no quoted attribute holds a {n} that Svelte would read as an expression', () => {
  const found: string[] = [];
  for (const file of svelteFiles(SRC)) {
    const text = readFileSync(file, 'utf8');
    for (const m of text.matchAll(QUANTIFIER_IN_ATTRIBUTE)) {
      const line = text.slice(0, m.index ?? 0).split('\n').length;
      found.push(`${relative(SRC, file)}:${line}:${m[0]}`);
    }
  }
  expect(found, "write the value as an expression, e.g. pattern={'[0-9]{6}'}").toEqual([]);
});

test('api_005 the check sees the mistake it is for, and not the fix', () => {
  expect('<input pattern="[0-9]{6}" maxlength="6" />'.match(QUANTIFIER_IN_ATTRIBUTE)?.length).toBe(1);
  expect("<input pattern={'[0-9]{6}'} maxlength=\"6\" />".match(QUANTIFIER_IN_ATTRIBUTE)).toBeNull();
  expect('<a href="/x/{id}" class="a b">'.match(QUANTIFIER_IN_ATTRIBUTE)).toBeNull();
});
