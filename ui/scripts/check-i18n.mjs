// REQ: API-011 — every string the UI can say exists in each language, with the same placeholders.
// Run by `npm run check:i18n` in CI, next to check:help.
//
// The catalogs are flat `'key': 'value'` literals, so this reads them without a TypeScript build:
// one regex per quoted pair, a second pass for `{placeholders}`. A key defined twice is an error
// (the later one would silently win), as is a language that adds a key English doesn't have.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const here = import.meta.dirname;
const root = resolve(here, '../src/lib/i18n/messages');
const LANGS = ['en', 'zh-CN'];
const PAIR =
  /'((?:[^'\\]|\\.)+)'\s*:\s*(?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)"|`((?:[^`\\$]|\\.)*)`)/g;

const unescape = (s) => s.replace(/\\(['"`\\])/g, '$1');
const placeholders = (s) => [...unescape(s).matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();

function catalog(lang) {
  // Every fragment the language index composes (index.ts itself lists them).
  const index = readFileSync(resolve(root, lang, 'index.ts'), 'utf8');
  const files = [...index.matchAll(/from '\.\/([\w-]+)'/g)].map((m) => m[1]);
  files.push('index');
  const keys = new Map();
  for (const file of [...new Set(files)]) {
    const text = readFileSync(resolve(root, lang, `${file}.ts`), 'utf8');
    for (const m of text.matchAll(PAIR)) {
      const key = m[1];
      const value = m[2] ?? m[3] ?? m[4] ?? '';
      if (keys.has(key)) keys.set(key, { ...keys.get(key), duplicate: true, file });
      else keys.set(key, { value, file });
    }
  }
  return keys;
}

const errors = [];
const en = catalog('en');
const zh = catalog('zh-CN');

for (const [key, v] of en) {
  if (v.duplicate) errors.push(`en: "${key}" is defined twice (${v.file})`);
  if (!zh.has(key)) errors.push(`zh-CN: missing "${key}" (${v.file})`);
  // A plural group is one that has `.one`: it must have `.other` too. A plain key that happens
  // to end in `.other` (a status word, say) is not a plural.
  if (/\.one$/.test(key)) {
    const base = key.slice(0, -'.one'.length);
    if (!en.has(`${base}.other`)) errors.push(`en: "${key}" has no "${base}.other"`);
  }
}
for (const [key, v] of zh) {
  if (!en.has(key)) errors.push(`zh-CN: "${key}" is not an English key (${v.file})`);
  if (v.duplicate) errors.push(`zh-CN: "${key}" is defined twice (${v.file})`);
  if (!unescape(v.value).trim()) errors.push(`zh-CN: "${key}" is empty`);
}
for (const [key, v] of en) {
  if (!unescape(v.value).trim()) errors.push(`en: "${key}" is empty`);
}
for (const [key, v] of zh) {
  const e = en.get(key);
  if (!e) continue;
  const a = placeholders(e.value).join(',');
  const b = placeholders(v.value).join(',');
  if (a !== b) errors.push(`zh-CN: "${key}" placeholders {${a}} differ from English {${b}}`);
}

if (errors.length) {
  for (const e of errors) console.error(`i18n: ${e}`);
  process.exit(1);
}
console.log(`i18n: ${en.size} strings × ${LANGS.length} languages, all present and consistent`);