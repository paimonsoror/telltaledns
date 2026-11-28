// REQ: API-012 (ADR-189) — helpers for the specs of the languages tool: a copy of the fixture
// project (tests/i18n-fixtures/project, with the made-up locale `qaa`) in a temporary folder, small
// edits to it, and the check run on it or on the UI itself.
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import * as lib from '../../scripts/i18n-lib.mjs';
import { install, parseCatalog, type Choice } from '../../src/lib/i18n';
import { extraAgrees } from '../../src/lib/i18n/added';

export const UI = resolve(import.meta.dirname, '../..');
export const FIXTURE = resolve(UI, 'tests/i18n-fixtures/project');

export type Finding = { level: 'fail' | 'report'; rule: string; check?: string; file: string; msg: string; values?: string[] };
export type Result = {
  findings: Finding[];
  shipped: Record<string, { json: string }>;
  files: { rel: string; usesLayer: boolean; literal: number[]; intl: number; physical: number }[];
  entries: Map<string, unknown>;
};

const temps: string[] = [];
/** Removes the temporary copies (call from `test.afterAll`). */
export function cleanup() {
  for (const d of temps.splice(0)) rmSync(d, { recursive: true, force: true });
}

/** A copy of the fixture project in a temporary folder, after `edit`. */
export function project(edit?: (dir: string) => void): string {
  const dir = mkdtempSync(join(tmpdir(), 'tt-i18n-'));
  temps.push(dir);
  cpSync(FIXTURE, dir, { recursive: true });
  edit?.(dir);
  return dir;
}
/** A copy of the UI's sources and ratchet baseline (all the check reads) in a temporary folder,
 * after `edit`. */
export function uiCopy(edit?: (dir: string) => void): string {
  const dir = mkdtempSync(join(tmpdir(), 'tt-i18n-ui-'));
  temps.push(dir);
  cpSync(join(UI, 'src'), join(dir, 'src'), { recursive: true });
  cpSync(join(UI, 'i18n-baseline.json'), join(dir, 'i18n-baseline.json'));
  edit?.(dir);
  return dir;
}
export const file = (dir: string, rel: string) => join(dir, rel);
export const edit = (dir: string, rel: string, f: (s: string) => string) => {
  const before = readFileSync(file(dir, rel), 'utf8');
  const after = f(before);
  if (after === before) throw new Error(`fixture edit changed nothing in ${rel}`);
  writeFileSync(file(dir, rel), after);
};
export const put = (dir: string, rel: string, text: string) => writeFileSync(file(dir, rel), text);
/** Edits the fixture's locale file and writes it back in canonical form. */
export const qaa = (dir: string, f: (cat: Record<string, unknown[]>) => void) => {
  const cat = JSON.parse(readFileSync(file(dir, 'src/locales/qaa.json'), 'utf8'));
  f(cat);
  put(dir, 'src/locales/qaa.json', lib.serializeCatalog(cat));
};
export const manifest = (dir: string, f: (m: Record<string, Record<string, unknown>>) => void) => {
  const m = JSON.parse(readFileSync(file(dir, 'src/locales/manifest.json'), 'utf8'));
  f(m);
  put(dir, 'src/locales/manifest.json', lib.serializeJson(m));
};
export const run = (dir: string, opts?: object): Result => lib.check(dir, opts);
export const fails = (r: Result) => r.findings.filter((f) => f.level === 'fail');
export const failRules = (r: Result) => [...new Set(fails(r).map((f) => f.rule))].sort();
let ui: Result | null = null;
/** The check on the UI itself (once per worker). */
export const checkUi = (): Result => (ui ??= lib.check(UI));

/** Runs `body` with `c` installed, then English again. A catalog the build did not ship gets the digit and
 * added-token rules, as the code that brings one gives them (ADR-190), unless `c` names its own `extra`. */
export function under(c: Choice, body: () => void) {
  install(c.built || 'extra' in c ? c : { ...c, extra: extraAgrees });
  try {
    body();
  } finally {
    install({ tag: 'en' });
  }
}
export const table = (o: object) => parseCatalog(JSON.stringify(o));
