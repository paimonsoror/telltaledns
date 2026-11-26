// Precompresses dist/ for the embedded server and enforces the bundle budgets (`spec/07` §3, API-005,
// API-012): the UI with English (everything outside `assets/locales/`) ≤ 400 KiB gzipped, each
// language file there ≤ 80 KiB and all of them together ≤ 400 KiB. A text file is replaced by its
// `x.gz` (when that is smaller): the binary embeds what dist/ holds, so a raw copy beside its `.gz`
// cost about the file's gzip size again in the image (NFR-001, ADR-168). The server sends the `.gz`
// to a browser that accepts gzip, and inflates it for any other client.
// REQ: API-012 (ADR-189) — it also fails if `assets/locales/` holds anything but the files the
// i18n prebuild step emitted (its list, one per manifest locale), if a `.json` sits elsewhere under
// `assets/`, or if text of another language (one of the three longest translated values of each
// catalog) is found in a core file.
// Usage: node scripts/postbuild.mjs [dist-dir] [locales-dir] [emitted-list]
//   (defaults: dist/, src/locales/ and src/lib/i18n/emitted.gen.json)
import { existsSync, readdirSync, readFileSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { gzipSync, constants } from 'node:zlib';

const DIST = process.argv[2] ?? new URL('../dist/', import.meta.url).pathname;
const LOCALES = process.argv[3] ?? new URL('../src/locales/', import.meta.url).pathname;
const EMITTED = process.argv[4] ?? new URL('../src/lib/i18n/emitted.gen.json', import.meta.url).pathname;
const CORE = 400 * 1024;
const LOCALE = 80 * 1024;
const LOCALES_TOTAL = 400 * 1024;
const TEXT = /\.(html|js|css|svg|json|txt|map)$/;
const LOCALE_DIR = `assets${sep}locales${sep}`;

function* walk(dir) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) yield* walk(p);
    else yield p;
  }
}

const errors = [];
const manifest = existsSync(join(LOCALES, 'manifest.json')) ? JSON.parse(readFileSync(join(LOCALES, 'manifest.json'), 'utf8')) : {};
const tags = Object.keys(manifest);
// What prebuild wrote: [{ file, tag }]. No list: nothing may be in assets/locales/.
const emitted = existsSync(EMITTED) ? JSON.parse(readFileSync(EMITTED, 'utf8')) : [];

// The three longest translated values of each catalog, skipping values equal to their English.
const probes = [];
for (const tag of tags) {
  const p = join(LOCALES, `${tag}.json`);
  if (!existsSync(p)) continue;
  const values = [];
  for (const [ctx, pairs] of Object.entries(JSON.parse(readFileSync(p, 'utf8')))) {
    if (ctx === '~leftover') continue;
    for (const [english, tx] of pairs) {
      const en = Array.isArray(english) ? english : [english];
      for (const v of typeof tx === 'string' ? [tx] : Object.values(tx)) if (v && !en.includes(v)) values.push(v);
    }
  }
  values.sort((a, b) => b.length - a.length);
  for (const v of values.slice(0, 3)) probes.push({ tag, v });
}
const escaped = (v) => [...v].map((c) => (c.charCodeAt(0) > 126 ? `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}` : c)).join('');

let core = 0;
let localesTotal = 0;
const rows = [];
const seen = new Set();
for (const file of [...walk(DIST)]) {
  if (file.endsWith('.gz')) continue;
  const rel = relative(DIST, file);
  const raw = readFileSync(file);
  let size = raw.length;
  const inLocales = rel.startsWith(LOCALE_DIR);
  if (inLocales) {
    const name = rel.slice(LOCALE_DIR.length);
    const e = emitted.find((x) => x.file === name);
    if (!e || !tags.includes(e.tag) || seen.has(e.tag)) errors.push(`${rel}: assets/locales/ holds the files the i18n prebuild step emitted, one per manifest locale, only`);
    else seen.add(e.tag);
  } else {
    if (rel.startsWith(`assets${sep}`) && rel.endsWith('.json')) errors.push(`${rel}: a .json under assets/ outside assets/locales/`);
    if (TEXT.test(file) && probes.length) {
      const text = raw.toString('utf8');
      for (const { tag, v } of probes) {
        const esc = escaped(v);
        if (text.includes(v) || text.includes(esc) || text.includes(esc.replace(/\\u([0-9a-f]{4})/g, (_, h) => `\\u${h.toUpperCase()}`)))
          errors.push(`${rel}: holds text of ${tag} ("${v.slice(0, 40)}"): another language belongs in assets/locales/`);
      }
    }
  }
  if (TEXT.test(file)) {
    const gz = gzipSync(raw, { level: constants.Z_BEST_COMPRESSION });
    size = gz.length;
    if (gz.length < raw.length) {
      writeFileSync(`${file}.gz`, gz);
      unlinkSync(file);
    }
  }
  if (inLocales) {
    localesTotal += size;
    if (size > LOCALE) errors.push(`${rel}: ${(size / 1024).toFixed(1)} KiB gzipped, over the ${LOCALE / 1024} KiB a language may take`);
  } else core += size;
  rows.push([rel, raw.length, size]);
}
for (const tag of tags) if (!seen.has(tag)) errors.push(`assets/locales/: no file for the manifest locale ${tag}`);
rows.sort((a, b) => b[2] - a[2]);
for (const [f, raw, gz] of rows) {
  console.log(`${f.padEnd(40)} ${String(raw).padStart(9)} B  ${String(gz).padStart(8)} B gz`);
}
const kib = (n) => (n / 1024).toFixed(1);
console.log(`core ${kib(core)} KiB gzipped (budget ${kib(CORE)} KiB): everything outside assets/locales/`);
console.log(`each language at most ${kib(LOCALE)} KiB gzipped: ${seen.size} file(s) in assets/locales/`);
console.log(`all languages ${kib(localesTotal)} KiB gzipped (budget ${kib(LOCALES_TOTAL)} KiB)`);
if (core > CORE) errors.push('the UI with English is over its size budget');
if (localesTotal > LOCALES_TOTAL) errors.push('the languages together are over their size budget');
if (errors.length) {
  for (const e of errors) console.error(`error: ${e}`);
  process.exit(1);
}
