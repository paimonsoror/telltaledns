// REQ: DOC-006 — the project site's decisions explorer (site/assets/decisions.js) counts, filters and orders the decision
// records and nothing else. A part page (decisions-N.html, ADR-136) also holds each record's "Builds on" and "Referenced by"
// link chips, written with the same `adr` class: they were counted as records with no status (a page of 39 read "All 183"
// and "Null 144"), every status filter hid them, and the sort moved them out of their records to the end of the list. The
// site is plain files: it is built here as `python3 site/build.py` builds it (into site/_site, which git ignores) and
// opened from disk, with no server.
import { expect, test, type Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { failOnPageErrors } from './page-errors';

failOnPageErrors(test);

const REPO = resolve(import.meta.dirname, '../../..');
const OUT = join(REPO, 'site', '_site');

/** A decision record as the built file holds it. */
type Rec = { id: string; num: number; status: string };
/** A built decisions page: its records and how many link chips it holds. */
type Built = { name: string; records: Rec[]; chips: number };

const RECORD = /<(?:article|details) class="adr[^"]*" id="(adr-\d{3})" data-num="(\d+)" data-status="([^"]*)"/g;
const CHIP = /<a class="chip adr" /g;

let index: Built;
let parts: Built[] = [];

function built(name: string): Built {
  const html = readFileSync(join(OUT, name), 'utf8');
  return {
    name,
    records: [...html.matchAll(RECORD)].map((m) => ({ id: m[1], num: Number(m[2]), status: m[3] })),
    chips: html.match(CHIP)?.length ?? 0,
  };
}

const partNumber = (name: string) => Number(/(\d+)\.html$/.exec(name)?.[1]);

test.beforeAll(() => {
  execFileSync('python3', [join(REPO, 'site', 'build.py')], { cwd: REPO, stdio: 'pipe', timeout: 120_000 });
  index = built('decisions.html');
  parts = readdirSync(OUT)
    .filter((n) => /^decisions-\d+\.html$/.test(n))
    .sort((a, b) => partNumber(a) - partNumber(b))
    .map(built);
});

// A page from disk logs nothing: no missing file, no refused script.
const consoleErrors: string[] = [];
test.beforeEach(({ page }) => {
  consoleErrors.length = 0;
  page.on('console', (m) => {
    if (m.type() === 'error') consoleErrors.push(`${page.url()}: ${m.text()}`);
  });
});
test.afterEach(() => {
  expect(consoleErrors, 'no console errors').toEqual([]);
});

const open = (page: Page, name: string, hash = '') => page.goto(pathToFileURL(join(OUT, name)).href + hash);

function byStatus(records: Rec[]): Record<string, number> {
  const n: Record<string, number> = {};
  for (const r of records) n[r.status] = (n[r.status] ?? 0) + 1;
  return n;
}

/** The count line for `shown` of `n` records. */
const countLine = (shown: number, n: number) => (shown === n ? `${n} decisions` : `Showing ${shown} of ${n}`);

// REQ: DOC-006
test('doc_006 every decisions page counts its own records, and its status buttons add up to them', async ({ page }) => {
  // The pages hold every ADR of the specification once: the index a row each, the part pages a record each.
  const spec = readFileSync(join(REPO, 'spec', '11-decisions.md'), 'utf8');
  const ids = [...spec.matchAll(/^## (ADR-\d{3}) — /gm)].map((m) => m[1].toLowerCase()).sort();
  expect(ids.length).toBeGreaterThan(0);
  expect(index.records.map((r) => r.id).sort()).toEqual(ids);
  expect(parts.flatMap((p) => p.records.map((r) => r.id)).sort()).toEqual(ids);
  expect(parts.some((p) => p.chips > 0), 'the part pages hold link chips').toBe(true);
  for (const b of [index, ...parts]) {
    const n = b.records.length;
    await open(page, b.name);
    await expect(page.locator('.adr-tools'), `${b.name}: the explorer runs`).toBeVisible();
    const labels = await page.locator('#adr-status button').allTextContents();
    expect(labels[0], b.name).toBe(`All ${n}`);
    expect(labels.filter((l) => /^null\b/i.test(l)), `${b.name}: a button for no status`).toEqual([]);
    const buttons: Record<string, number> = {};
    for (const l of labels.slice(1)) {
      const m = /^(\S+) (\d+)$/.exec(l);
      expect(m, `${b.name}: "${l}"`).not.toBeNull();
      if (m) buttons[m[1].toLowerCase()] = Number(m[2]);
    }
    expect(buttons, b.name).toEqual(byStatus(b.records));
    expect(Object.values(buttons).reduce((s, x) => s + x, 0), `${b.name}: the status buttons add up`).toBe(n);
    await expect(page.locator('#adr-count'), b.name).toHaveText(`${n} decisions`);
  }
});

// REQ: DOC-006
test('doc_006 a status filter on a part page hides records only, and every link chip stays in its record', async ({ page }) => {
  for (const b of parts) {
    const n = b.records.length;
    await open(page, b.name);
    const chips = page.locator('#adr-list a.chip.adr');
    await expect(chips, b.name).toHaveCount(b.chips);
    const astray = await chips.evaluateAll((cs) => cs.filter((c) => !c.parentElement?.closest('details.adr')).length);
    expect(astray, `${b.name}: link chips moved out of their records`).toBe(0);
    for (const [status, k] of Object.entries(byStatus(b.records))) {
      await page.locator('#adr-status button').filter({ hasText: new RegExp(`^${status} \\d+$`, 'i') }).click();
      const what = `${b.name}, ${status}`;
      await expect(page.locator('#adr-count'), what).toHaveText(countLine(k, n));
      const shown = page.locator('#adr-list details.adr:not([hidden])');
      await expect(shown, what).toHaveCount(k);
      expect(await shown.evaluateAll((ds, s) => ds.every((d) => d.getAttribute('data-status') === s), status), what).toBe(true);
      await expect(page.locator('#adr-list a.chip.adr[hidden]'), `${what}: hidden link chips`).toHaveCount(0);
    }
    await page.locator('#adr-status button').first().click();
    await expect(page.locator('#adr-list details.adr[hidden]'), b.name).toHaveCount(0);
    await expect(page.locator('#adr-count'), b.name).toHaveText(`${n} decisions`);
  }
});

// REQ: DOC-006
test('doc_006 search, area, order, expand all and a link to a record still work on a part page', async ({ page }) => {
  const b = parts[parts.length - 1];
  const n = b.records.length;
  await open(page, b.name);
  const records = page.locator('#adr-list details.adr');
  const shown = page.locator('#adr-list details.adr:not([hidden])');
  // Search: the records whose own text holds the words (the record named, and the ones that mention it).
  const word = b.records[0].id;
  const found = await records.evaluateAll((ds, w) => ds.filter((d) => (d.textContent ?? '').toLowerCase().includes(w)).length, word);
  expect(found).toBeGreaterThan(0);
  await page.locator('#adr-q').fill(word);
  await expect(page.locator('#adr-count')).toHaveText(countLine(found, n));
  await expect(shown).toHaveCount(found);
  await page.locator('#adr-q').fill('');
  await expect(page.locator('#adr-count')).toHaveText(`${n} decisions`);
  // Area: the first one offered, which some record on the page names.
  const area = await page.locator('#adr-area option').nth(1).getAttribute('value');
  if (area) {
    const inArea = await records.evaluateAll((ds, a) => ds.filter((d) => ` ${d.getAttribute('data-areas')} `.includes(` ${a} `)).length, area);
    await page.locator('#adr-area').selectOption(area);
    await expect(page.locator('#adr-count')).toHaveText(countLine(inArea, n));
    await expect(shown).toHaveCount(inArea);
    await page.locator('#adr-area').selectOption('');
    await expect(shown).toHaveCount(n);
  }
  // Order: newest first, and oldest first on request.
  const nums = () => records.evaluateAll((ds) => ds.map((d) => Number(d.getAttribute('data-num'))));
  const oldest = b.records.map((r) => r.num).sort((x, y) => x - y);
  expect(await nums()).toEqual([...oldest].reverse());
  await page.locator('#adr-sort').selectOption('asc');
  expect(await nums()).toEqual(oldest);
  // Expand all opens every record.
  await page.locator('#adr-expand').click();
  await expect(page.locator('#adr-expand')).toHaveText('Collapse all');
  expect(await records.evaluateAll((ds) => ds.every((d) => (d as HTMLDetailsElement).open))).toBe(true);
  // A link to a record opens it.
  const target = b.records[Math.floor(n / 2)].id;
  await page.goto('about:blank');
  await open(page, b.name, `#${target}`);
  await expect(page.locator(`#${target}`)).toHaveJSProperty('open', true);
});

// REQ: DOC-005 (ADR-136) — every link to a record names the part page that holds it, and a link to a page that no longer
// holds the record (the pages were split again) goes on to the one that does.
test('doc_005 every index row links to the part page that holds its record', () => {
  const html = readFileSync(join(OUT, 'decisions.html'), 'utf8');
  const rows = [...html.matchAll(/<article class="adr[^"]*" id="(adr-\d{3})"[^>]*><a class="adr-head" href="([^"#]+)#([^"]+)"/g)];
  expect(rows.length).toBe(index.records.length);
  const holder = new Map(parts.flatMap((p) => p.records.map((r): [string, string] => [r.id, p.name])));
  for (const [, id, href, anchor] of rows) expect([href, anchor], id).toEqual([holder.get(id), id]);
});

// REQ: DOC-005
test('doc_005 a link to a record on another part page goes on to the page that holds it', async ({ page }) => {
  const last = parts[parts.length - 1];
  const target = last.records[last.records.length - 1].id;
  expect(parts[0].records.map((r) => r.id)).not.toContain(target);
  await open(page, parts[0].name, `#${target}`);
  await expect(page).toHaveURL(new RegExp(`/${last.name.replace('.', '\\.')}#${target}$`));
  await expect(page.locator(`#${target}`)).toHaveJSProperty('open', true);
});

// REQ: DOC-005 (ADR-136) — a decision named in a record's text links to the part page that holds it (an anchor when it is
// on the same page), so the link works without JavaScript; only an old link from outside needs the forward above.
test('doc_005 a decision named in a record links to the page that holds it, without JavaScript', async ({ browser }) => {
  const holder = new Map(parts.flatMap((p) => p.records.map((r): [string, string] => [r.id, p.name])));
  const wrong: string[] = [];
  let across: { from: string; href: string } | undefined;
  for (const p of parts) {
    const html = readFileSync(join(OUT, p.name), 'utf8');
    for (const [, page, id] of html.matchAll(/<a href="((?:decisions-\d+\.html)?)#(adr-\d{3})">ADR-\d{3}<\/a>/g)) {
      if ((page || p.name) !== holder.get(id)) wrong.push(`${p.name}: ${page}#${id} (${holder.get(id)} holds it)`);
      else if (page && !across) across = { from: p.name, href: `${page}#${id}` };
    }
  }
  expect(wrong.length, `mentions that name the wrong page, for instance:\n${wrong.slice(0, 5).join('\n')}`).toBe(0);
  expect(across, 'a record names a decision on another part page').toBeDefined();
  if (!across) return;
  // Without JavaScript: open the record that names it, and follow the link.
  const context = await browser.newContext({ javaScriptEnabled: false });
  const nojs = await context.newPage();
  nojs.on('console', (m) => {
    if (m.type() === 'error') consoleErrors.push(`${nojs.url()}: ${m.text()}`);
  });
  await nojs.goto(pathToFileURL(join(OUT, across.from)).href);
  const link = `a[href="${across.href}"]`;
  const record = nojs.locator('#adr-list details.adr', { has: nojs.locator(link) }).first();
  await record.locator('summary').click();
  await record.locator(link).first().click();
  const [file, id] = across.href.split('#');
  await expect(nojs).toHaveURL(new RegExp(`/${file.replace('.', '\\.')}#${id}$`));
  await expect(nojs.locator(`details#${id}`)).toHaveCount(1);
  await context.close();
});
