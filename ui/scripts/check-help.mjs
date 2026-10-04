// REQ: API-011 (T3.11 AC) — every help id used in the UI exists in docs/help/topics.json, and
// every topic not marked `general` is used somewhere. Run by `npm run check:help` in CI.
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';

const here = import.meta.dirname;
const topics = JSON.parse(readFileSync(resolve(here, '../../docs/help/topics.json'), 'utf8')).topics;
const ids = new Map(topics.map((t) => [t.id, t]));

const used = new Map();
function walk(dir) {
  for (const f of readdirSync(dir)) {
    const p = join(dir, f);
    if (statSync(p).isDirectory()) walk(p);
    else if (/\.(svelte|ts)$/.test(f)) {
      for (const m of readFileSync(p, 'utf8').matchAll(/<HelpButton id="([^"]+)"/g)) {
        used.set(m[1], [...(used.get(m[1]) ?? []), p.slice(resolve(here, '..').length + 1)]);
      }
    }
  }
}
walk(resolve(here, '../src'));

const errors = [];
for (const [id, where] of used) if (!ids.has(id)) errors.push(`unknown help id "${id}" in ${where.join(', ')}`);
for (const t of topics) {
  if (!t.general && !used.has(t.id)) errors.push(`topic "${t.id}" isn't used in the UI (use it, or mark it general)`);
  for (const k of ['id', 'title', 'term', 'summary']) if (!t[k]) errors.push(`topic "${t.id}" has no ${k}`);
}
const dupes = topics.map((t) => t.id).filter((id, i, a) => a.indexOf(id) !== i);
for (const d of dupes) errors.push(`topic "${d}" is defined twice`);
if (errors.length) {
  for (const e of errors) console.error(`help: ${e}`);
  process.exit(1);
}
console.log(`help: ${used.size} topics used, ${topics.length} defined, all consistent`);
