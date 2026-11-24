// REQ: API-011 (T3.11 AC) — every help id used in the UI exists in docs/help/topics.json, every
// topic not marked `general` is used somewhere, and the Chinese translation
// (docs/help/topics.zh-CN.json) says the same topics with the same structural fields.
// Run by `npm run check:help` in CI.
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';

const here = import.meta.dirname;
const read = (name) => JSON.parse(readFileSync(resolve(here, '../../docs/help', name), 'utf8')).topics;
const topics = read('topics.json');
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

// The Chinese file: the same topics in the same order of ids, the same structural fields
// (`id`, `diagram`, `docs`, `general` — a wrong one would change what the UI does, not just what
// it says), translated text where the English has some, and nothing of its own.
const zhTopics = read('topics.zh-CN.json');
const zh = new Map(zhTopics.map((t) => [t.id, t]));
for (const d of zhTopics.map((t) => t.id).filter((id, i, a) => a.indexOf(id) !== i)) {
  errors.push(`zh-CN: topic "${d}" is defined twice`);
}
for (const t of zhTopics) if (!ids.has(t.id)) errors.push(`zh-CN: topic "${t.id}" isn't an English topic`);
for (const t of topics) {
  const z = zh.get(t.id);
  if (!z) {
    errors.push(`zh-CN: topic "${t.id}" is missing`);
    continue;
  }
  if (z.general !== t.general) errors.push(`zh-CN: topic "${t.id}" has general ${z.general}, English has ${t.general}`);
  for (const k of ['diagram', 'docs']) {
    if (z[k] !== t[k]) errors.push(`zh-CN: topic "${t.id}" has ${k} "${z[k]}", English has "${t[k]}"`);
  }
  for (const k of ['id', 'title', 'term', 'summary']) {
    if (typeof z[k] !== 'string' || !z[k].trim()) errors.push(`zh-CN: topic "${t.id}" has no ${k}`);
  }
  for (const k of ['when', 'example', 'caution']) {
    if (t[k] && (typeof z[k] !== 'string' || !z[k].trim())) {
      errors.push(`zh-CN: topic "${t.id}" has no ${k} (English has one)`);
    }
  }
}

if (errors.length) {
  for (const e of errors) console.error(`help: ${e}`);
  process.exit(1);
}
console.log(
  `help: ${used.size} topics used, ${topics.length} defined, ${zhTopics.length} translated, all consistent`,
);
