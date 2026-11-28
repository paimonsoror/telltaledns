// REQ: API-013 (ADR-190) — testing a language pack, in the browser against the real server: the card under
// Settings → Account (Advanced view), the template and the check, Use and the reload, the English banner above
// every overlay, the pause on the sign-in, setup and two-factor screens, the removal on another build of the web UI
// or the server, after 7 days and when damaged, and what a pack never reaches. The tests sign in once for real as
// the suite's admin (as 2-shots.spec.ts does; the admin is created from the setup token when this file runs
// alone, as 1-ui.spec.ts does), keep the cookies only, and give each test a fresh context: no pack reaches another
// test. On the server they create one viewer of their own and sign in and out; nothing about a pack reaches it.
// (The parts that need no browser are 7-devpack.spec.ts.)
import { expect, test, type Browser, type BrowserContext, type Page, type Route } from '@playwright/test';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { gunzipSync } from 'node:zlib';
import * as lib from '../../scripts/i18n-lib.mjs';
import { agree } from '../../src/lib/i18n/agree';
import { identity } from '../../src/lib/i18n/shipping';
import { materialize, readTemplate } from '../../src/lib/i18n/template';
import { DATA, jsonStrings, makeCollides, makeRule, readPage } from './i18n-pseudo-rule';
import { NOTE_RESTORED, cachingBrowser, howShown, noCache, restoresPages } from './bfcache';
import { failOnPageErrors, listen } from './page-errors';

// A page error on any page a test opens (`fresh` listens to each) fails the test.
failOnPageErrors(test);

const UI = resolve(import.meta.dirname, '../..');
const ADMIN = { user: 'admin', pass: 'correct horse battery' };
const KEY = 'telltale.devpack';
const DAY = 86_400_000;

type Entry = { ctx: string; english: string | [string, string]; note?: string };
const ENTRIES = [...(lib.check(UI, { ratchets: false }).entries as Map<string, Entry>).values()];
/** A message of the UI, which must exist (a fixture never names English the UI does not have). */
function message(ctx: string, english: Entry['english']): Entry {
  const e = ENTRIES.find((x) => x.ctx === ctx && JSON.stringify(x.english) === JSON.stringify(english) && !x.note);
  if (!e) throw new Error(`no message ${ctx}: ${JSON.stringify(english)}`);
  return e;
}
const SETTINGS = message('settings', 'Settings');
const SIGN_IN = message('login', 'Sign in');
const FLUSHED = message('cacheCard', ['Removed {n} entry{errors}.', 'Removed {n} entries{errors}.']);
/** A small French pack: the Settings heading, the sign-in heading and a plural of French's three categories. */
const FR: Record<string, unknown[]> = {
  [SETTINGS.ctx]: [[SETTINGS.english, 'Réglages']],
  [SIGN_IN.ctx]: [[SIGN_IN.english, 'Se connecter']],
  [FLUSHED.ctx]: [[FLUSHED.english, { one: '{n} entrée supprimée{errors}.', many: '{n} d’entrées supprimées{errors}.', other: '{n} entrées supprimées{errors}.' }]],
};
const FR_TEXT = JSON.stringify(FR, null, 2);
const valueOf = (ctx: string) => (FR[ctx][0] as [unknown, string])[1];
/** Every message of the UI, translated as its English with a marker after it (a pack that changes every label). */
const MARK = 'ZQXJ';
const ALL_TEXT = JSON.stringify(
  Object.fromEntries(
    [...new Set(ENTRIES.map((e) => e.ctx))].map((ctx) => [
      ctx,
      ENTRIES.filter((e) => e.ctx === ctx).map((e) => {
        const tx = typeof e.english === 'string' ? `${e.english} ${MARK}` : { one: `${e.english[0]} ${MARK}`, many: `${e.english[1]} ${MARK}`, other: `${e.english[1]} ${MARK}` };
        return e.note ? [e.english, tx, e.note] : [e.english, tx];
      }),
    ]),
  ),
);

/** This web UI's build as the build wrote it: the src of the built page's one module script, its entry (read from
 * `dist`, which keeps the page gzipped; the pack's code reads it in the browser, its own way). */
function builtEntry(): string {
  const dist = join(UI, 'dist');
  const html = existsSync(join(dist, 'index.html')) ? readFileSync(join(dist, 'index.html'), 'utf8') : gunzipSync(readFileSync(join(dist, 'index.html.gz'))).toString('utf8');
  const modules = [...html.matchAll(/<script\b[^>]*>/g)].map((m) => m[0]).filter((s) => /\btype="module"/.test(s));
  const src = modules.length === 1 ? /\bsrc="([^"]+)"/.exec(modules[0])?.[1] : undefined;
  if (!src?.startsWith('/assets/')) throw new Error(`the built page's module scripts: ${JSON.stringify(modules)}`);
  return src;
}

let signedIn: { cookies: Awaited<ReturnType<BrowserContext['storageState']>>['cookies']; origins: [] };
let COMMIT = '';
let ENTRY = '';
test.beforeAll(async ({ browser }) => {
  const context = await browser.newContext({ baseURL: test.info().project.use.baseURL });
  const page = await context.newPage();
  await page.goto('/');
  const welcome = page.getByRole('heading', { name: 'Welcome to TelltaleDNS' });
  await expect(welcome.or(page.getByRole('heading', { name: 'Sign in' }))).toBeVisible();
  if (await welcome.isVisible()) {
    // This file alone: the first run's admin, as 1-ui.spec.ts creates it.
    const token = readFileSync(join(UI, '.e2e/data/setup-token'), 'utf8').trim();
    await page.getByLabel('Setup token').fill(token);
    await page.getByLabel('Admin username').fill(ADMIN.user);
    await page.getByLabel('Password (at least 10 characters)').fill(ADMIN.pass);
    await page.getByLabel('Repeat password').fill(ADMIN.pass);
    await page.getByRole('button', { name: 'Create admin and sign in' }).click();
  } else {
    await page.getByLabel('Username', { exact: true }).fill(ADMIN.user);
    await page.getByLabel('Password', { exact: true }).fill(ADMIN.pass);
    await page.getByRole('button', { name: 'Sign in' }).click();
  }
  await expect(page.getByRole('heading', { name: 'Dashboard' }).first()).toBeVisible({ timeout: 30_000 });
  COMMIT = (await (await page.request.get('/api/v1/system/info')).json()).build.commit;
  ENTRY = builtEntry();
  signedIn = { cookies: (await context.storageState()).cookies, origins: [] };
  await context.close();
});

/** Two change markers, one and two minutes ago: within the last hour, and within a chart's data (review part B of
 * T29.3, nit 8). */
const MARKERS = () => {
  const now = Date.now();
  return [
    { kind: 'note', summary: 'A note of the language pack tests', tUnixMs: now - 60_000, actor: 'admin' },
    { kind: 'config.applied', summary: 'configuration 1 applied (ui, 1 section changed)', tUnixMs: now - 120_000, seq: 1, source: 'ui', actor: 'admin' },
  ];
};

/** A fresh context (signed in unless `signedOut`), its page, and the problems the page reports: console errors but a
 * 401 or 403, as 1-ui.spec.ts (`allow` names others the test expects). Its page errors fail the test (page-errors.ts). */
async function fresh(browser: Browser, o: { signedOut?: boolean; width?: number; allow?: RegExp; init?: () => void } = {}) {
  const context = await browser.newContext({
    baseURL: test.info().project.use.baseURL,
    storageState: o.signedOut ? undefined : signedIn,
    viewport: o.width ? { width: o.width, height: 700 } : undefined,
  });
  if (o.init) await context.addInitScript(o.init);
  // The same two change markers in the last hour on every chart, whatever earlier spec files changed: a server that has
  // run only this file has none in a chart's data, and a test that looks at a chart under a pack needs a marker button
  // there. (The test of a pack that reads one word gives its own, many more.) Requests are still seen: the request event
  // fires for a routed request.
  await context.route(
    (u) => u.pathname === '/api/v1/annotations',
    (q) => (q.request().method() === 'GET' ? q.fulfill({ json: { items: MARKERS(), truncated: false } }) : q.fallback()),
  );
  const page = await context.newPage();
  listen(page);
  const problems: string[] = [];
  page.on('console', (m) => {
    if (m.type() !== 'error' || /status of 40[13]/.test(m.text()) || o.allow?.test(m.text())) return;
    problems.push(`console: ${m.text()}`);
  });
  return { context, page, problems };
}
const done = async (s: { context: BrowserContext; problems: string[] }) => {
  expect(s.problems, 'no console errors (CSP violations among them)').toEqual([]);
  await s.context.close();
};

/** Keeps a pack in this browser as the card's Use does (the record and the text in one key). From an address
 * of its own, so the page the test opens next is a new page load (a change of the hash alone is not). */
async function storePack(page: Page, text: string, o: { tag?: string; name?: string; ui?: string; commit?: string; user?: string; loadedAt?: number; fails?: number } = {}) {
  await page.goto('/?devpack-test=store');
  const loadedAt = o.loadedAt ?? Date.now();
  const rec = {
    v: 1, ui: o.ui ?? ENTRY, server: { commit: o.commit ?? COMMIT }, user: o.user ?? ADMIN.user, loadedAt, expires: loadedAt + 7 * DAY, name: o.name ?? 'fr.json',
    sha: createHash('sha256').update(text).digest('hex'), tag: o.tag ?? 'fr', dir: 'ltr', fails: o.fails ?? 0, text,
  };
  await page.evaluate(([k, v]) => localStorage.setItem(k, v), [KEY, JSON.stringify(rec)]);
  return rec;
}
const kept = (page: Page) => page.evaluate((k) => localStorage.getItem(k), KEY);
/** Signs in on the sign-in page shown (a session of this context's own, so signing it out leaves the file's). */
async function signInHere(page: Page, who = ADMIN) {
  await page.getByLabel('Username', { exact: true }).fill(who.user);
  await page.getByLabel('Password', { exact: true }).fill(who.pass);
  await page.getByRole('button', { name: 'Sign in' }).click();
}
const banner = (page: Page) => page.getByTestId('devpack-banner');
/** Settings → Account in the Advanced view, with the card open. */
async function openCard(page: Page) {
  await page.goto('/#/settings?tab=account');
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  const card = page.getByTestId('devpack-card');
  if (!(await card.isVisible())) {
    const advanced = page.getByRole('button', { name: 'Advanced', exact: true });
    if (await advanced.isVisible()) await advanced.click();
    else {
      await page.getByRole('button', { name: /^Menu/ }).click();
      await page.getByRole('button', { name: 'Advanced view' }).click();
    }
  }
  await expect(card).toBeVisible();
  if (await page.getByTestId('devpack-open').isVisible()) await page.getByTestId('devpack-open').click();
  await expect(page.getByTestId('devpack-body')).toBeVisible();
  await expect(page.getByTestId('devpack-tag-line')).not.toContainText('Loading');
  return card;
}
/** Chooses a file in the card (the tag as typed, or from the file's name). */
async function chooseFile(page: Page, text: string | Buffer, name = 'fr.json', tag?: string) {
  if (tag !== undefined) await page.getByTestId('devpack-tag').fill(tag);
  await page.getByTestId('devpack-file').setInputFiles({ name, mimeType: 'application/json', buffer: Buffer.isBuffer(text) ? text : Buffer.from(text) });
}
/** Where the banner's Remove button is, the element on top there is the button. */
const removeOnTop = (page: Page) =>
  page.evaluate(() => {
    const b = document.querySelector('[data-testid="devpack-remove"]');
    if (!b) return 'no Remove button';
    const r = b.getBoundingClientRect();
    const top = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
    return top === b || b.contains(top) ? 'on top' : `covered by ${top?.outerHTML.slice(0, 80)}`;
  });
const templateUrl = () => /TEMPLATE: string \| null = "([^"]+)"/.exec(readFileSync(join(UI, 'src/lib/i18n/locales.gen.ts'), 'utf8'))?.[1] ?? '';
/** The banner host's stacking order, and the highest of every other element's on the page (with which one). */
const stacking = (page: Page) =>
  page.evaluate(() => {
    const host = document.querySelector('.devpack-host');
    let most = -Infinity;
    let who = '';
    for (const e of document.querySelectorAll('*')) {
      if (!host || host.contains(e)) continue;
      const z = Number(getComputedStyle(e).zIndex);
      if (Number.isFinite(z) && z > most) [most, who] = [z, `${e.tagName.toLowerCase()}.${String(e.className).trim().split(/\s+/)[0]}`];
    }
    return { own: host ? Number(getComputedStyle(host).zIndex) : NaN, most, who };
  });

test('api_013 an english session loads no pack code and makes no pack request', async ({ browser }) => {
  const s = await fresh(browser);
  const assets: string[] = [];
  s.page.on('request', (r) => {
    const path = new URL(r.url()).pathname;
    if (path.startsWith('/assets/')) assets.push(path);
  });
  await s.page.goto('/');
  for (const [path, heading] of [['/#/', 'Dashboard'], ['/#/queries', 'Query log'], ['/#/settings?tab=account', 'Settings']]) {
    await s.page.goto(path);
    await expect(s.page.getByRole('heading', { name: heading }).first()).toBeVisible();
  }
  // In the Advanced view the card is there, as a heading, a sentence and Open: its code is not loaded.
  await s.page.getByRole('button', { name: 'Advanced', exact: true }).click();
  await expect(s.page.getByTestId('devpack-open')).toBeVisible();
  await expect(banner(s.page)).toHaveCount(0);
  // For the size measurement: what an English reader downloads.
  console.log(`DVP_EAGER ${JSON.stringify([...new Set(assets)].sort())}`);
  // Exactly the entry chunk, its stylesheet and the brand icons: no lazy script or stylesheet, no template.
  expect([...new Set(assets)].map((p) => p.replace(/-[\w-]+\.(js|css)$/, '-*.$1')).sort()).toEqual(['/assets/brands-*.js', '/assets/index-*.css', '/assets/index-*.js']);
  expect(await kept(s.page)).toBeNull();
  await done(s);
});

test('api_013 the template downloads for a chosen tag', async ({ browser }) => {
  const s = await fresh(browser);
  // The template, as the built binary serves it.
  const res = await s.page.request.get(templateUrl(), { headers: { 'accept-encoding': 'gzip' } });
  expect(res.status()).toBe(200);
  expect(res.headers()['content-type']).toBe('application/json');
  expect(res.headers()['cache-control']).toContain('immutable');
  expect(res.headers()['content-encoding']).toBe('gzip');
  // Imported here, so the file loads (and each test fails on its own) on a tree without the module.
  const { readTemplate, materialize } = await import('../../src/lib/i18n/template');
  const tpl = readTemplate(await res.text());
  await openCard(s.page);
  await s.page.getByTestId('devpack-tag').fill('de');
  await expect(s.page.getByTestId('devpack-tag-line')).toContainText('saved as de');
  const [download] = await Promise.all([s.page.waitForEvent('download'), s.page.getByTestId('devpack-template').click()]);
  expect(download.suggestedFilename()).toBe('de.json');
  // Chromium's bytes are Node's for this build (both read the committed plural table the template carries).
  const bytes = readFileSync(await download.path());
  expect(bytes.toString('utf8')).toBe(materialize(tpl, tpl.plurals.get('de') ?? []));
  expect(bytes.subarray(0, 3).equals(Buffer.from([0xef, 0xbb, 0xbf]))).toBe(false);
  const [notes] = await Promise.all([s.page.waitForEvent('download'), s.page.getByTestId('devpack-notes').click()]);
  expect(notes.suggestedFilename()).toBe('de-notes.txt');
  const text = readFileSync(await notes.path(), 'utf8');
  expect(text).toContain('TelltaleDNS: notes for translators of de.json');
  expect(text).toContain('Plural forms of this language: one, other.');
  expect(text).toContain(`Made from web UI build ${ENTRY.replace(/^\/assets\//, '').replace(/\.js$/, '')}`);
  // A tag the committed table does not know is refused, with no download.
  await s.page.getByTestId('devpack-tag').fill('tok');
  await expect(s.page.getByTestId('devpack-tag-line')).toContainText("doesn't know the plural forms of this language");
  await expect(s.page.getByTestId('devpack-template')).toHaveCount(0);
  await done(s);
});

test('api_013 a loaded pack shows after apply and reload', async ({ browser }) => {
  const s = await fresh(browser);
  let removed = [0, 1, 2];
  await s.page.route('**/api/v1/cache/flush', (r) => r.fulfill({ json: { totalRemoved: removed.shift() ?? 2, nodes: [] } }));
  await openCard(s.page);
  await chooseFile(s.page, FR_TEXT);
  // The tag comes from the file's name.
  await expect(s.page.getByTestId('devpack-tag')).toHaveValue('fr');
  await expect(s.page.getByTestId('devpack-summary')).toContainText(`fr.json: 3 of ${ENTRIES.length.toLocaleString('en-US')} texts translated`);
  await s.page.getByTestId('devpack-use').click();
  await expect(s.page.getByTestId('devpack-confirm')).toContainText('Use this language pack in this browser?');
  // Use reloads into Settings, where the card opens with the pack in use and fetches the template itself (after
  // the load event, at times): wait for that, so the count below covers the next page load alone.
  const cardTemplate = s.page.waitForResponse((r) => new URL(r.url()).pathname.startsWith('/assets/locales/template-'));
  await Promise.all([s.page.waitForEvent('load'), s.page.getByTestId('devpack-confirm-use').click()]);
  await cardTemplate;
  // The record keeps the check's table for this build and this file: a load after Use fetches neither the
  // template nor the checking code.
  expect(JSON.parse((await kept(s.page)) ?? '{}').checked).toMatchObject({ ui: ENTRY, sha: createHash('sha256').update(FR_TEXT).digest('hex') });
  const after: string[] = [];
  s.page.on('request', (r) => after.push(new URL(r.url()).pathname));
  await s.page.goto('/?devpack-test=again#/');
  await expect(s.page.locator('html')).toHaveAttribute('lang', 'fr');
  await expect(banner(s.page)).toBeVisible();
  expect(after.filter((p) => p.startsWith('/assets/locales/') || /\/recheck-[\w-]+\.js$/.test(p))).toEqual([]);
  // After the reload: the pack's text, its lang and dir, and its plural rules.
  await s.page.goto('/#/settings?tab=account');
  await expect(s.page.getByRole('heading', { level: 1 })).toHaveText(valueOf(SETTINGS.ctx));
  await expect(s.page.locator('html')).toHaveAttribute('lang', 'fr');
  await expect(s.page.locator('html')).toHaveAttribute('dir', 'ltr');
  await expect(banner(s.page)).toContainText('Test language pack: fr.json (français, fingerprint ');
  await expect(banner(s.page)).toContainText(createHash('sha256').update(FR_TEXT).digest('hex').slice(0, 12));
  await s.page.goto('/#/cache');
  const card = s.page.getByTestId('cache-card');
  await card.locator('form input').fill('i18n.example');
  const said: string[] = [];
  for (let i = 0; i < 3; i++) {
    await card.locator('div.row button').first().click();
    await expect(s.page.getByTestId('cache-flushed')).toContainText(`${i} `);
    said.push((await s.page.getByTestId('cache-flushed').innerText()).trim());
  }
  // French counts 0 as one; English would say "0 entries".
  expect(said).toEqual(['0 entrée supprimée.', '1 entrée supprimée.', '2 entrées supprimées.']);
  await done(s);
});

test('api_013 the banner stays on top of every overlay', async ({ browser }) => {
  const s = await fresh(browser, { width: 360 });
  await storePack(s.page, FR_TEXT, { name: `${'x'.repeat(200)}.json` });
  // A drawer (a help panel).
  await s.page.goto('/#/settings?tab=account');
  await expect(banner(s.page)).toBeVisible();
  await s.page.locator('button[data-help="account"]').click();
  await expect(s.page.locator('.drawer')).toBeVisible();
  expect(await removeOnTop(s.page)).toBe('on top');
  // Above every layer of the UI, wherever one opens (the tips, the health panel, the pause control): the banner's
  // stacking order is higher than any other element's on each page here (review part B of T29.3, finding 5).
  const z1 = await stacking(s.page);
  expect(z1.own, `above ${z1.who} (${z1.most})`).toBeGreaterThan(z1.most);
  const below = await s.page.evaluate(() => [document.querySelector('[data-testid="devpack-banner"]')?.getBoundingClientRect().bottom ?? 0, document.querySelector('.drawer')?.getBoundingClientRect().top ?? 0]);
  expect(below[1]).toBeGreaterThanOrEqual(below[0] - 1);
  await s.page.keyboard.press('Escape');
  // The phone menu: the banner on top, and the menu's last item (the build) reachable below it.
  await s.page.goto('/#/');
  await s.page.getByRole('button', { name: /^Menu/ }).click();
  await expect(s.page.locator('nav.side')).toBeVisible();
  expect(await removeOnTop(s.page)).toBe('on top');
  // The health panel, open from the menu (stacking order 40), and the dashboard's own layers.
  await s.page.getByTestId('health-icon').click();
  await expect(s.page.getByTestId('health-panel')).toBeVisible();
  const z2 = await stacking(s.page);
  expect(z2.most).toBeGreaterThanOrEqual(40);
  expect(z2.own, `above ${z2.who} (${z2.most})`).toBeGreaterThan(z2.most);
  await s.page.getByTestId('health-icon').click();
  const footer = s.page.getByTestId('build-footer');
  await footer.scrollIntoViewIfNeeded();
  await expect(footer).toBeInViewport();
  expect(await s.page.evaluate(() => {
    const f = document.querySelector('[data-testid="build-footer"]');
    const r = f?.getBoundingClientRect();
    const top = r && document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
    return !!f && !!top && f.contains(top);
  })).toBe(true);
  // The wall.
  await s.page.goto('/#/wall');
  await expect(s.page.getByTestId('wall-area')).toBeVisible();
  expect(await removeOnTop(s.page)).toBe('on top');
  const z3 = await stacking(s.page);
  expect(z3.own, `above ${z3.who} (${z3.most})`).toBeGreaterThan(z3.most);
  // A long file name does not push Remove off a phone screen.
  expect(await s.page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await expect(banner(s.page)).toContainText(`${'x'.repeat(23)}…`);
  await done(s);
});

test('api_013 the pack is paused on the sign-in setup and two-factor screens', async ({ browser }) => {
  const s = await fresh(browser, { signedOut: true });
  await storePack(s.page, FR_TEXT, { commit: 'unknown-when-signed-out' });
  // Sign-in: English, and the banner says it is paused.
  await s.page.goto('/');
  await expect(s.page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  await expect(s.page.locator('html')).toHaveAttribute('lang', 'en');
  await expect(banner(s.page)).toContainText('The test language pack fr.json is paused on this page.');
  await expect(s.page.getByTestId('devpack-once')).toBeVisible();
  // Two-factor: the code step of the same page.
  await s.page.route('**/api/v1/auth/login', (r) => r.fulfill({ status: 401, json: { type: 'about:blank', title: 'Unauthorized', status: 401, code: 'totp_required', detail: 'a code is needed' } }));
  await s.page.getByLabel('Username', { exact: true }).fill('someone');
  await s.page.getByLabel('Password', { exact: true }).fill('a long password');
  await s.page.getByRole('button', { name: 'Sign in' }).click();
  await expect(s.page.getByText('Enter the 6-digit code from your authenticator app.')).toBeVisible();
  await expect(banner(s.page)).toContainText('is paused on this page');
  // Setup.
  await s.page.route('**/api/v1/auth/status', (r) => r.fulfill({ json: { setupRequired: true, user: null, oidc: [], localLogin: true, csrfToken: null } }));
  await s.page.reload();
  await expect(s.page.getByRole('heading', { name: 'Welcome to TelltaleDNS' })).toBeVisible();
  await expect(s.page.locator('html')).toHaveAttribute('lang', 'en');
  await expect(banner(s.page)).toContainText('is paused on this page');
  expect(JSON.parse((await kept(s.page)) ?? '{}').name).toBe('fr.json');
  await done(s);
});

test('api_013 show the test pack on this page lasts one load', async ({ browser }) => {
  const s = await fresh(browser, { signedOut: true });
  await storePack(s.page, FR_TEXT);
  await s.page.goto('/');
  await expect(s.page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  await Promise.all([s.page.waitForEvent('load'), s.page.getByTestId('devpack-once').click()]);
  await expect(s.page.getByRole('heading', { name: valueOf(SIGN_IN.ctx) })).toBeVisible();
  await expect(s.page.locator('html')).toHaveAttribute('lang', 'fr');
  await expect(banner(s.page)).toContainText('Test language pack: fr.json');
  expect(await s.page.evaluate(() => sessionStorage.getItem('telltale.devpack.once'))).toBeNull();
  // The next load is paused again.
  await s.page.reload();
  await expect(s.page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  await expect(banner(s.page)).toContainText('is paused on this page');
  await done(s);
});

test('api_013 signing in with a paused pack reloads into the pack', async ({ browser }) => {
  const s = await fresh(browser, { signedOut: true });
  await storePack(s.page, FR_TEXT);
  await s.page.goto('/');
  await expect(banner(s.page)).toContainText('is paused on this page');
  await s.page.getByLabel('Username', { exact: true }).fill(ADMIN.user);
  await s.page.getByLabel('Password', { exact: true }).fill(ADMIN.pass);
  await s.page.getByRole('button', { name: 'Sign in' }).click();
  // Signing in reloads the page into the pack.
  await expect(s.page.locator('html')).toHaveAttribute('lang', 'fr', { timeout: 30_000 });
  await expect(banner(s.page)).toContainText('Test language pack: fr.json');
  await s.page.goto('/#/settings?tab=account');
  await expect(s.page.getByRole('heading', { level: 1 })).toHaveText(valueOf(SETTINGS.ctx));
  await done(s);
});

test('api_013 signing out takes the pack off the page', async ({ browser }) => {
  // Signed in with a pack, then Sign out: the sign-in page is drawn after one reload, in the usual language, and
  // the pack is paused (review part A of T29.3, finding 1).
  const s = await fresh(browser, { signedOut: true });
  await storePack(s.page, FR_TEXT);
  await s.page.goto('/');
  await signInHere(s.page);
  await expect(s.page.locator('html')).toHaveAttribute('lang', 'fr', { timeout: 30_000 });
  await expect(banner(s.page)).toContainText('Test language pack: fr.json');
  await Promise.all([s.page.waitForEvent('load'), s.page.getByRole('button', { name: 'Sign out' }).click()]);
  await expect(s.page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  await expect(s.page.locator('html')).toHaveAttribute('lang', 'en');
  await expect(banner(s.page)).toContainText('The test language pack fr.json is paused on this page.');
  await done(s);
});

test('api_013 signing out at the provider leaves for it with a pack in use', async ({ browser }) => {
  // REQ: API-004 — an OIDC session signs out at the provider too: the page goes to the logout address the server
  // gives, with a pack in use as without one (the page that leaves for it is never also reloaded). The provider is a
  // marker on this address, put in the server's real answer; the first round, without a pack, is the control. The
  // page the provider sends back to is paused, as after any sign-out. (3-oidc.spec.ts does it with a real provider.)
  for (const pack of [false, true]) {
    const s = await fresh(browser, { signedOut: true });
    if (pack) await storePack(s.page, FR_TEXT);
    await s.page.goto('/');
    await signInHere(s.page);
    await expect(s.page.locator('html')).toHaveAttribute('lang', pack ? 'fr' : 'en', { timeout: 30_000 });
    await expect(s.page.getByRole('button', { name: 'Sign out' })).toBeVisible();
    await s.page.route('**/api/v1/auth/logout', async (r) => {
      const res = await r.fetch();
      await r.fulfill({ response: res, status: 200, json: { logoutUrl: '/?devpack-test=provider-logout' } });
    });
    await s.page.getByRole('button', { name: 'Sign out' }).click();
    await expect(s.page, pack ? 'with a pack in use' : 'without a pack').toHaveURL(/\?devpack-test=provider-logout(#|$)/, { timeout: 15_000 });
    await expect(s.page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
    await expect(s.page.locator('html')).toHaveAttribute('lang', 'en');
    if (pack) await expect(banner(s.page)).toContainText('The test language pack fr.json is paused on this page.');
    await done(s);
  }
});

test('api_013 back after signing out at the provider never shows the pack', async () => {
  // REQ: API-004 — the page that leaves for the provider's sign-out is not reloaded on its way out. Back from the
  // provider's page returns to it, and the browser may show it again as it was, from its back-forward cache: it must
  // show the usual language with the pack paused. This test's browser keeps that cache, which the suite's browser
  // turns off; a browser that never shows a page again from it cannot exercise the fix, and the test says so by
  // skipping. (3-oidc.spec.ts does it with a real provider.)
  const { browser: own, note } = await cachingBrowser(test.info().project.use.launchOptions ?? {}, process.env.DVP_FULL_CHROME);
  try {
    const s = await fresh(own, { signedOut: true, init: NOTE_RESTORED });
    const probe = await restoresPages(s.page);
    console.log(`DVP_BFCACHE marker probe ${own.version()} ${note}${JSON.stringify(probe)}`);
    test.skip(!probe.restored, noCache(own, note, probe.why));
    await storePack(s.page, FR_TEXT);
    await s.page.goto('/');
    await signInHere(s.page);
    await expect(s.page.locator('html')).toHaveAttribute('lang', 'fr', { timeout: 30_000 });
    await s.page.route('**/api/v1/auth/logout', async (r) => {
      const res = await r.fetch();
      await r.fulfill({ response: res, status: 200, json: { logoutUrl: '/?devpack-test=provider-logout' } });
    });
    await s.page.getByRole('button', { name: 'Sign out' }).click();
    await expect(s.page).toHaveURL(/\?devpack-test=provider-logout(#|$)/, { timeout: 15_000 });
    await expect(banner(s.page)).toContainText('is paused on this page');
    await s.page.goBack({ waitUntil: 'commit' });
    await expect(s.page).not.toHaveURL(/devpack-test=provider-logout/);
    await expect(s.page.locator('html')).toHaveAttribute('lang', 'en', { timeout: 15_000 });
    await expect(s.page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
    await expect(banner(s.page)).toContainText('The test language pack fr.json is paused on this page.');
    // The page that left was shown again from the cache (then reloaded): the fix was exercised.
    const shown = await howShown(s.page);
    console.log(`DVP_BFCACHE marker back ${own.version()} ${JSON.stringify(shown)}`);
    expect(shown.restored, 'Back showed the page that left again from the back-forward cache').toBeGreaterThanOrEqual(1);
    await done(s);
  } finally {
    await own.close();
  }
});

test('api_013 a provider sign-out that never leaves the page lets a later session end take the pack away', async ({ browser }) => {
  // The provider's address never replaces the page (here it answers 204, so the browser stays): the sign-in page stays
  // drawn with the pack. Signing in again there, then a session that ends, takes the pack off the page as any session
  // end does: the page reloads once, in the usual language, with the pack paused.
  const s = await fresh(browser, { signedOut: true });
  await storePack(s.page, FR_TEXT);
  await s.page.goto('/');
  await signInHere(s.page);
  await expect(s.page.locator('html')).toHaveAttribute('lang', 'fr', { timeout: 30_000 });
  const logout = async (r: Route) => {
    const res = await r.fetch();
    await r.fulfill({ response: res, status: 200, json: { logoutUrl: '/?devpack-test=nowhere' } });
  };
  await s.page.route('**/api/v1/auth/logout', logout);
  await s.page.route((u) => u.searchParams.get('devpack-test') === 'nowhere', (r) => r.fulfill({ status: 204, body: '' }));
  let loads = 0;
  s.page.on('load', () => loads++);
  await s.page.getByRole('button', { name: 'Sign out' }).click();
  await expect(s.page.getByRole('heading', { name: valueOf(SIGN_IN.ctx) })).toBeVisible();
  await s.page.waitForTimeout(1500);
  expect(s.page.url()).not.toContain('devpack-test=nowhere');
  // Signed in again on that page: the pack's language, and no reload (the user who loaded it).
  await s.page.unroute('**/api/v1/auth/logout', logout);
  await s.page.getByLabel('Username', { exact: true }).fill(ADMIN.user);
  await s.page.getByLabel('Password', { exact: true }).fill(ADMIN.pass);
  await s.page.getByRole('button', { name: valueOf(SIGN_IN.ctx), exact: true }).click();
  await expect(s.page.getByRole('button', { name: 'Sign out' })).toBeVisible({ timeout: 30_000 });
  await expect(s.page.locator('html')).toHaveAttribute('lang', 'fr');
  expect(loads).toBe(0);
  // Then the session ends: the next request finds it gone.
  await s.page.route(
    (u) => u.pathname.startsWith('/api/v1/') && !u.pathname.startsWith('/api/v1/auth/'),
    (r) => r.fulfill({ status: 401, json: { type: 'about:blank', title: 'Unauthorized', status: 401, code: 'unauthorized', detail: 'the session is gone' } }),
  );
  await Promise.all([s.page.waitForEvent('load'), s.page.evaluate(() => (location.hash = '#/queries')).catch(() => undefined)]);
  await expect(s.page.getByRole('heading', { name: 'Sign in' })).toBeVisible({ timeout: 30_000 });
  await expect(s.page.locator('html')).toHaveAttribute('lang', 'en');
  await expect(banner(s.page)).toContainText('is paused on this page');
  await done(s);
});

test('api_013 a session that ends while the sign-out waits for its answer reloads nothing before it', async ({ browser }) => {
  // The server's answer to Sign out is held back for a second, and meanwhile a request finds the session gone (the
  // server ended it first). Nothing reloads while the answer waits. With a provider's address in it, the page then
  // leaves for the provider; without one (a local sign-out), it reloads once into the usual language, the pack paused.
  for (const provider of [true, false]) {
    const s = await fresh(browser, { signedOut: true });
    await storePack(s.page, FR_TEXT);
    await s.page.goto('/');
    await signInHere(s.page);
    await expect(s.page.locator('html')).toHaveAttribute('lang', 'fr', { timeout: 30_000 });
    let answer: () => void = () => undefined;
    const answered = new Promise<void>((go) => (answer = go));
    await s.page.route('**/api/v1/auth/logout', async (r) => {
      const res = await r.fetch();
      await answered;
      await r.fulfill(provider ? { response: res, status: 200, json: { logoutUrl: '/?devpack-test=provider-logout' } } : { response: res });
    });
    let loads = 0;
    s.page.on('load', () => loads++);
    await s.page.getByRole('button', { name: 'Sign out' }).click();
    await s.page.route(
      (u) => u.pathname.startsWith('/api/v1/') && !u.pathname.startsWith('/api/v1/auth/'),
      (r) => r.fulfill({ status: 401, json: { type: 'about:blank', title: 'Unauthorized', status: 401, code: 'unauthorized', detail: 'the session is gone' } }),
    );
    await s.page.evaluate(() => (location.hash = '#/queries'));
    await expect(s.page.getByRole('heading', { name: valueOf(SIGN_IN.ctx) })).toBeVisible();
    await s.page.waitForTimeout(1000);
    expect(loads, provider ? 'nothing reloads while the answer waits (provider)' : 'nothing reloads while the answer waits (local)').toBe(0);
    answer();
    if (provider) await expect(s.page).toHaveURL(/\?devpack-test=provider-logout(#|$)/, { timeout: 15_000 });
    else await expect.poll(() => loads, { timeout: 15_000 }).toBe(1);
    await expect(s.page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
    await expect(s.page.locator('html')).toHaveAttribute('lang', 'en');
    await expect(banner(s.page)).toContainText('The test language pack fr.json is paused on this page.');
    await done(s);
  }
});

test('api_013 a second sign-out while the first waits for its answer leaves the page on its way to the provider', async ({ browser }) => {
  // REQ: API-004 — Sign out is clicked twice while the server's answer to the first waits (a double click, a slow
  // server). The first answer gives a provider's address, and the provider's page is slow to come; an answer to a
  // second request would come after it, with no address. The second click asks nothing and changes nothing: the page
  // reaches the provider's address, loads once (there), and that page is paused.
  const s = await fresh(browser, { signedOut: true });
  await storePack(s.page, FR_TEXT);
  await s.page.goto('/');
  await signInHere(s.page);
  await expect(s.page.locator('html')).toHaveAttribute('lang', 'fr', { timeout: 30_000 });
  let asked = 0;
  await s.page.route('**/api/v1/auth/logout', async (r) => {
    const first = ++asked === 1;
    const res = await r.fetch();
    await new Promise((go) => setTimeout(go, first ? 1000 : 1500));
    await r.fulfill(first ? { response: res, status: 200, json: { logoutUrl: '/?devpack-test=provider-logout' } } : { response: res });
  });
  await s.page.route(
    (u) => u.searchParams.get('devpack-test') === 'provider-logout',
    async (r) => {
      await new Promise((go) => setTimeout(go, 2000));
      await r.continue().catch(() => undefined);
    },
  );
  let loads = 0;
  s.page.on('load', () => loads++);
  const out = s.page.getByRole('button', { name: 'Sign out' });
  await out.click();
  await out.click();
  await expect(s.page).toHaveURL(/\?devpack-test=provider-logout(#|$)/, { timeout: 15_000 });
  await expect(s.page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  await expect(s.page.locator('html')).toHaveAttribute('lang', 'en');
  await expect(banner(s.page)).toContainText('The test language pack fr.json is paused on this page.');
  await s.page.waitForTimeout(1000);
  expect(loads, 'the page loads once, at the provider').toBe(1);
  expect(asked, 'one sign-out request').toBe(1);
  await done(s);
});

test('api_013 a session that ends takes the pack off the page', async ({ browser }) => {
  // A request that finds the session gone draws the sign-in page: after one reload, in the usual language, and
  // the pack paused. Here the status still says signed in (as two nodes that disagree could): that load stays
  // paused, and no reload follows (finding 1).
  const s = await fresh(browser);
  await storePack(s.page, FR_TEXT);
  await s.page.goto('/#/settings?tab=account');
  await expect(s.page.locator('html')).toHaveAttribute('lang', 'fr');
  let loads = 0;
  s.page.on('load', () => loads++);
  await s.page.route(
    (u) => u.pathname.startsWith('/api/v1/') && !u.pathname.startsWith('/api/v1/auth/'),
    (r) => r.fulfill({ status: 401, json: { type: 'about:blank', title: 'Unauthorized', status: 401, code: 'unauthorized', detail: 'the session is gone' } }),
  );
  // The next request the page makes finds the session gone (one already running may: then the page reloads
  // before this navigation is done).
  await Promise.all([s.page.waitForEvent('load'), s.page.evaluate(() => (location.hash = '#/queries')).catch(() => undefined)]);
  await expect(s.page.getByRole('heading', { name: 'Sign in' })).toBeVisible({ timeout: 30_000 });
  await expect(s.page.locator('html')).toHaveAttribute('lang', 'en');
  await expect(banner(s.page)).toContainText('is paused on this page');
  await s.page.waitForTimeout(3000);
  expect(loads).toBe(1);
  await done(s);
});

test('api_013 reads of who is signed in that disagree reload a page once for a sign-in', async ({ browser }) => {
  // The pack's code reads who is signed in before the page is drawn, and the app reads it again: nodes behind one
  // address that don't share sessions can disagree. Here, on every load, the pack's read says nobody and the app's
  // says the user: the page reloads once for that sign-in, and the load it lands on does not again. A sign-in on
  // that load, after a sign-out, still reloads into the pack.
  const s = await fresh(browser, { signedOut: true });
  await storePack(s.page, FR_TEXT);
  await s.page.goto('/');
  await signInHere(s.page);
  await expect(s.page.locator('html')).toHaveAttribute('lang', 'fr', { timeout: 30_000 });
  // From here, the first status request of each page load (the pack's own) says nobody is signed in.
  let first = true;
  s.page.on('request', (q) => {
    if (q.isNavigationRequest() && q.frame() === s.page.mainFrame()) first = true;
  });
  const nobody = async (r: Route) => {
    if (!first) return r.fallback();
    first = false;
    const res = await r.fetch();
    await r.fulfill({ response: res, json: { ...(await res.json()), user: null } });
  };
  await s.page.route('**/api/v1/auth/status', nobody);
  let loads = 0;
  s.page.on('load', () => loads++);
  await s.page.reload();
  await expect(banner(s.page)).toContainText('The test language pack fr.json is paused on this page.', { timeout: 30_000 });
  await s.page.waitForTimeout(4000);
  expect(loads, 'the reload asked for, and one for the sign-in the app reports').toBe(2);
  await expect(s.page.locator('html')).toHaveAttribute('lang', 'en');
  await expect(s.page.getByRole('button', { name: 'Sign out' })).toBeVisible();
  await s.page.unroute('**/api/v1/auth/status', nobody);
  await s.page.getByRole('button', { name: 'Sign out' }).click();
  await expect(s.page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  await Promise.all([s.page.waitForEvent('load'), signInHere(s.page)]);
  await expect(s.page.locator('html')).toHaveAttribute('lang', 'fr', { timeout: 30_000 });
  await expect(banner(s.page)).toContainText('Test language pack: fr.json');
  await done(s);
});

test('api_013 the display page from a signed-in page is drawn without the pack', async ({ browser }) => {
  // A change of the hash alone (typed in the address bar) is not a page load: the display page reloads, paused.
  const s = await fresh(browser);
  await storePack(s.page, FR_TEXT);
  await s.page.goto('/#/');
  await expect(s.page.locator('html')).toHaveAttribute('lang', 'fr');
  await Promise.all([s.page.waitForEvent('load'), s.page.evaluate(() => (location.hash = '#/display?token=not-a-token'))]);
  await expect(s.page.locator('html')).toHaveAttribute('lang', 'en');
  await expect(banner(s.page)).toContainText('is paused on this page');
  await done(s);
});

test('api_013 show the test pack on this page keeps its load on the sign-in page', async ({ browser }) => {
  // Nobody is signed in on the page "Show the test pack on this page" asked for: that is not someone going away.
  const s = await fresh(browser, { signedOut: true });
  await storePack(s.page, FR_TEXT);
  await s.page.goto('/');
  await Promise.all([s.page.waitForEvent('load'), s.page.getByTestId('devpack-once').click()]);
  await expect(s.page.locator('html')).toHaveAttribute('lang', 'fr');
  await s.page.evaluate(() => ((window as unknown as { __dvpNoReload: boolean }).__dvpNoReload = true));
  await s.page.waitForTimeout(2000);
  expect(await s.page.evaluate(() => (window as unknown as { __dvpNoReload?: boolean }).__dvpNoReload)).toBe(true);
  await expect(s.page.getByRole('heading', { name: valueOf(SIGN_IN.ctx) })).toBeVisible();
  await done(s);
});

test('api_013 a pack is paused for anyone but the user who loaded it', async ({ browser }) => {
  // A pack belongs to the user who loaded it: another user who signs in at that browser gets the usual language,
  // a banner that says so, and "Show the test pack on this page" for one load (review part A of T29.3, finding 3).
  const s = await fresh(browser);
  await storePack(s.page, FR_TEXT, { user: 'someone-else' });
  await s.page.goto('/#/settings?tab=account');
  await expect(s.page.getByRole('heading', { level: 1 })).toHaveText('Settings');
  await expect(s.page.locator('html')).toHaveAttribute('lang', 'en');
  await expect(banner(s.page)).toContainText('The test language pack fr.json is paused: another user of this browser loaded it.');
  await expect(banner(s.page)).not.toContainText('someone-else');
  await Promise.all([s.page.waitForEvent('load'), s.page.getByTestId('devpack-once').click()]);
  await expect(s.page.getByRole('heading', { level: 1 })).toHaveText(valueOf(SETTINGS.ctx));
  await s.page.reload();
  await expect(banner(s.page)).toContainText('another user of this browser loaded it');
  await expect(s.page.locator('html')).toHaveAttribute('lang', 'en');
  await done(s);
});

const VIEWER = { user: 'dvp-viewer', pass: 'a viewer password for packs' };
test('api_013 the user who loaded a pack gets it back after signing in again and another user does not', async ({ browser }) => {
  // A viewer of this file's own (created once; this file may run alone).
  const a = await fresh(browser);
  const csrf = (await (await a.page.request.get('/api/v1/auth/status')).json()).csrfToken as string;
  const made = await a.page.request.post('/api/v1/users', { headers: { 'x-csrf-token': csrf }, data: { username: VIEWER.user, password: VIEWER.pass, role: 'viewer' } });
  expect([200, 201, 409], await made.text()).toContain(made.status());
  await a.context.close();
  const s = await fresh(browser, { signedOut: true });
  await storePack(s.page, FR_TEXT);
  await s.page.goto('/');
  // The user who loaded it: the pack; out, and back in: the pack again.
  await signInHere(s.page);
  await expect(s.page.locator('html')).toHaveAttribute('lang', 'fr', { timeout: 30_000 });
  await Promise.all([s.page.waitForEvent('load'), s.page.getByRole('button', { name: 'Sign out' }).click()]);
  await expect(s.page.locator('html')).toHaveAttribute('lang', 'en');
  await signInHere(s.page);
  await expect(s.page.locator('html')).toHaveAttribute('lang', 'fr', { timeout: 30_000 });
  await Promise.all([s.page.waitForEvent('load'), s.page.getByRole('button', { name: 'Sign out' }).click()]);
  // Another user, on the same page: paused for them; signed out and the first user in again: the pack.
  await signInHere(s.page, VIEWER);
  await expect(banner(s.page)).toContainText('another user of this browser loaded it', { timeout: 30_000 });
  await expect(s.page.locator('html')).toHaveAttribute('lang', 'en');
  await s.page.getByRole('button', { name: 'Sign out' }).click();
  await expect(s.page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  await signInHere(s.page);
  await expect(s.page.locator('html')).toHaveAttribute('lang', 'fr', { timeout: 30_000 });
  await expect(banner(s.page)).toContainText('Test language pack: fr.json');
  await done(s);
});

test('api_013 the banner removes the pack from any page', async ({ browser }) => {
  for (const path of ['/#/', '/#/queries', '/#/settings?tab=account', '/#/wall', '/#/display?token=not-a-token']) {
    const s = await fresh(browser);
    await storePack(s.page, FR_TEXT);
    await s.page.goto(path);
    await expect(banner(s.page), path).toBeVisible();
    await Promise.all([s.page.waitForEvent('load'), s.page.getByTestId('devpack-remove').click()]);
    await expect(s.page.locator('html'), path).toHaveAttribute('lang', 'en');
    await expect(banner(s.page), path).toHaveCount(0);
    expect(await kept(s.page), path).toBeNull();
    await done(s);
  }
});

test('api_013 a pack is cleared when the web ui build changes', async ({ browser }) => {
  const s = await fresh(browser);
  await storePack(s.page, FR_TEXT, { ui: '/assets/index-OLDBUILD.js' });
  await s.page.goto('/#/settings?tab=account');
  await expect(banner(s.page)).toContainText('The test language pack fr.json was removed: TelltaleDNS was updated.');
  await expect(s.page.getByRole('heading', { level: 1 })).toHaveText('Settings');
  expect(JSON.parse((await kept(s.page)) ?? '{}')).toMatchObject({ v: 1, gone: 'upgrade', name: 'fr.json' });
  // The card shows it too, in the Simple view; Dismiss removes the notice.
  await expect(s.page.getByTestId('devpack-card-notice')).toBeVisible();
  await s.page.getByRole('button', { name: 'Dismiss this notice' }).first().click();
  await expect(banner(s.page)).toHaveCount(0);
  expect(await kept(s.page)).toBeNull();
  await done(s);
});

test('api_013 the web ui build is the entry module whatever module script comes first', async ({ browser }) => {
  // Other module scripts before the entry (a browser extension's; here an inline one and one from another address
  // whose path looks like an entry's, which the page's policy keeps from running) leave this web UI's build as the
  // pack's code reads it: a kept pack stays in use, and Use stamps the entry, as the build wrote it.
  const OTHER = 'https://extension.invalid/assets/index-NOTOURS.js';
  const s = await fresh(browser, { allow: /Content Security Policy|inline script|extension\.invalid|ERR_NAME_NOT_RESOLVED/ });
  await s.context.route(
    (u) => u.pathname === '/',
    async (r) => {
      if (r.request().resourceType() !== 'document') return r.fallback();
      const res = await r.fetch();
      const headers = { ...res.headers() };
      delete headers['content-encoding'];
      delete headers['content-length'];
      const body = (await res.text()).replace('<script type="module"', `<script type="module">window.dvpInline = 1;</script><script type="module" src="${OTHER}"></script><script type="module"`);
      await r.fulfill({ status: res.status(), headers, body });
    },
  );
  await storePack(s.page, FR_TEXT);
  await s.page.goto('/#/settings?tab=account');
  expect(await s.page.evaluate(() => [...document.querySelectorAll('script[type="module"]')].map((x) => x.getAttribute('src')))).toEqual([null, OTHER, ENTRY]);
  await expect(s.page.locator('html')).toHaveAttribute('lang', 'fr');
  await expect(banner(s.page)).toContainText('Test language pack: fr.json');
  await openCard(s.page);
  await chooseFile(s.page, FR_TEXT, 'again.json', 'fr');
  await s.page.getByTestId('devpack-use').click();
  await Promise.all([s.page.waitForEvent('load'), s.page.getByTestId('devpack-confirm-use').click()]);
  await expect(banner(s.page)).toContainText('Test language pack: again.json');
  expect(JSON.parse((await kept(s.page)) ?? '{}')).toMatchObject({ name: 'again.json', ui: ENTRY, checked: { ui: ENTRY } });
  await done(s);
});

test('api_013 a pack is cleared when the server build changes', async ({ browser }) => {
  // The first answer of a load: removed, a reload, the notice.
  const a = await fresh(browser);
  await storePack(a.page, FR_TEXT, { commit: 'an-older-build' });
  await a.page.goto('/#/settings?tab=account');
  await expect(banner(a.page)).toContainText('was removed: TelltaleDNS was updated.');
  await expect(a.page.locator('html')).toHaveAttribute('lang', 'en');
  expect(JSON.parse((await kept(a.page)) ?? '{}').gone).toBe('upgrade');
  await done(a);
  // A later answer (the server upgraded while the tab is open): removed, said, and no reload.
  const b = await fresh(browser);
  await b.page.clock.install();
  await storePack(b.page, FR_TEXT);
  await b.page.goto('/#/settings?tab=account');
  await expect(b.page.locator('html')).toHaveAttribute('lang', 'fr');
  await expect(banner(b.page)).toContainText('Test language pack: fr.json');
  await b.page.route('**/api/v1/system/info', async (r) => {
    const res = await r.fetch();
    const info = await res.json();
    info.build.commit = 'a-newer-build';
    await r.fulfill({ response: res, json: info });
  });
  await b.page.evaluate(() => ((window as unknown as { __dvpNoReload: boolean }).__dvpNoReload = true));
  await b.page.clock.runFor(61_000);
  await expect(banner(b.page)).toContainText('TelltaleDNS was updated: the test pack goes away when you reload.');
  expect(await b.page.evaluate(() => (window as unknown as { __dvpNoReload?: boolean }).__dvpNoReload)).toBe(true);
  expect(JSON.parse((await kept(b.page)) ?? '{}').gone).toBe('upgrade');
  await done(b);
});

test('api_013 a page that fails to draw with the pack loads once more without it', async ({ browser }) => {
  // A fault while the app is drawn with the pack: the pack is removed with its notice, and the page loads once
  // more, in the usual language (review part B of T29.3, finding 6). The fault: anything put into the app's node
  // throws while the page is French, as a component that throws would.
  const s = await fresh(browser, { allow: /dvp-test/ });
  await storePack(s.page, FR_TEXT);
  await s.context.addInitScript(() => {
    const guard = (proto: object, name: string) => {
      const p = proto as Record<string, (...a: unknown[]) => unknown>;
      const f = p[name];
      p[name] = function (this: Node, ...a: unknown[]) {
        if (document.documentElement.lang === 'fr' && document.getElementById('app')?.contains(this)) throw new Error('dvp-test: a fault while drawing');
        return f.apply(this, a);
      };
    };
    for (const n of ['appendChild', 'insertBefore', 'replaceChild']) guard(Node.prototype, n);
    for (const n of ['append', 'prepend', 'before', 'after', 'replaceChildren']) guard(Element.prototype, n);
    for (const n of ['before', 'after']) guard(CharacterData.prototype, n);
  });
  let loads = 0;
  s.page.on('load', () => loads++);
  await s.page.goto('/#/');
  await expect.poll(() => loads, { timeout: 30_000 }).toBe(2);
  await expect(s.page.locator('html')).toHaveAttribute('lang', 'en');
  await expect(s.page.getByRole('heading', { name: 'Dashboard' }).first()).toBeVisible();
  // The notice says what happened, in the banner and in the card (not that the file could not be checked).
  await expect(banner(s.page)).toContainText('The test language pack fr.json was removed: a page could not be drawn with it.');
  expect(JSON.parse((await kept(s.page)) ?? '{}')).toMatchObject({ v: 1, gone: 'draw', name: 'fr.json' });
  // Once: the next load draws in English, and nothing reloads it again.
  await s.page.waitForTimeout(2000);
  expect(loads).toBe(2);
  await s.page.goto('/#/settings?tab=account');
  await expect(s.page.getByTestId('devpack-card-notice')).toContainText('The test language pack fr.json was removed: a page could not be drawn with it.');
  await expect(s.page.getByTestId('devpack-card-notice')).not.toContainText('checked');
  await done(s);
});

test('api_013 the card says when a language is written right to left', async ({ browser }) => {
  // The tag line names the direction the file will be shown in (review part B of T29.3, finding 6).
  const s = await fresh(browser);
  await openCard(s.page);
  for (const [tag, name] of [['ar', 'Arabic'], ['he', 'Hebrew']]) {
    await s.page.getByTestId('devpack-tag').fill(tag);
    await expect(s.page.getByTestId('devpack-tag-line'), tag).toContainText(name);
    await expect(s.page.getByTestId('devpack-tag-line'), tag).toContainText(`written right to left; saved as ${tag}.`);
  }
  await s.page.getByTestId('devpack-tag').fill('fr');
  await expect(s.page.getByTestId('devpack-tag-line')).toContainText('written left to right; saved as fr.');
  await done(s);
});

test('api_013 a tab left open neither removes nor replaces a newer pack', async ({ browser }) => {
  // Tab B shows a pack, and tab A loads another one since: B's Remove and Dismiss leave A's pack (review part A of
  // T29.3, finding 4).
  const s = await fresh(browser);
  await storePack(s.page, FR_TEXT, { name: 'older.json' });
  const b = await s.context.newPage();
  listen(b);
  await b.goto('/#/');
  await expect(banner(b)).toContainText('Test language pack: older.json');
  const newer = await storePack(s.page, ALL_TEXT, { name: 'newer.json' });
  await Promise.all([b.waitForEvent('load'), b.getByTestId('devpack-remove').click()]);
  await expect(banner(b)).toContainText('Test language pack: newer.json');
  expect(JSON.parse((await kept(b)) ?? '{}')).toMatchObject({ name: 'newer.json', sha: newer.sha });
  // A notice in B, and a pack loaded in A since: B's Dismiss leaves the pack.
  await s.page.evaluate(([k, v]) => localStorage.setItem(k, v), [KEY, JSON.stringify({ v: 1, gone: 'expired', name: 'gone.json', at: Date.now() })]);
  await b.reload();
  await expect(banner(b)).toContainText('The test language pack gone.json was removed');
  const third = await storePack(s.page, FR_TEXT, { name: 'third.json' });
  await b.getByRole('button', { name: 'Dismiss this notice' }).first().click();
  await expect(banner(b)).toHaveCount(0);
  expect(JSON.parse((await kept(b)) ?? '{}')).toMatchObject({ name: 'third.json', sha: third.sha });
  await b.close();
  await done(s);
});

test('api_013 a notice that cannot be kept never makes a page reload again', async ({ browser }) => {
  // Another server build takes the pack away with a notice. With storage that takes no write, the pack is still
  // removed first, so the one reload finds nothing; with storage that takes neither a write nor a removal, the page
  // does not reload at all, and says what happened (review part A of T29.3, finding 5).
  for (const removable of [true, false]) {
    const s = await fresh(browser);
    await storePack(s.page, FR_TEXT, { commit: 'an-older-build' });
    await s.context.addInitScript((canRemove: boolean) => {
      const set = Storage.prototype.setItem;
      const del = Storage.prototype.removeItem;
      Storage.prototype.setItem = function (this: Storage, k: string, v: string) {
        if (k === 'telltale.devpack') throw new DOMException('read-only', 'QuotaExceededError');
        return set.call(this, k, v);
      };
      if (!canRemove)
        Storage.prototype.removeItem = function (this: Storage, k: string) {
          if (k === 'telltale.devpack') throw new DOMException('read-only', 'SecurityError');
          return del.call(this, k);
        };
    }, removable);
    let loads = 0;
    s.page.on('load', () => loads++);
    await s.page.goto('/#/settings?tab=account');
    if (removable) {
      await expect.poll(() => loads, { timeout: 30_000 }).toBe(2);
      await expect(s.page.locator('html')).toHaveAttribute('lang', 'en');
      await expect(banner(s.page)).toHaveCount(0);
      expect(await kept(s.page)).toBeNull();
    } else {
      await expect(banner(s.page)).toContainText('TelltaleDNS was updated: the test pack goes away when you reload.', { timeout: 30_000 });
      expect(JSON.parse((await kept(s.page)) ?? '{}').server?.commit).toBe('an-older-build');
    }
    // No further load: the next one finds nothing to remove, or this one does not reload.
    await s.page.waitForTimeout(3000);
    expect(loads, removable ? 'takes a removal' : 'takes nothing').toBe(removable ? 2 : 1);
    await done(s);
  }
});

test('api_013 a pack expires after seven days', async ({ browser }) => {
  const s = await fresh(browser);
  await storePack(s.page, FR_TEXT);
  await s.page.clock.install({ time: new Date(Date.now() + 7 * DAY + 60_000) });
  await s.page.goto('/#/settings?tab=account');
  await expect(banner(s.page)).toContainText('The test language pack fr.json was removed: it was loaded 7 days ago.');
  await expect(s.page.locator('html')).toHaveAttribute('lang', 'en');
  expect(JSON.parse((await kept(s.page)) ?? '{}').gone).toBe('expired');
  await done(s);
});

test('api_013 a damaged stored pack falls back without a blank page', async ({ browser }) => {
  // A value that is not a record.
  const a = await fresh(browser);
  await a.page.goto('/?devpack-test=store');
  await a.page.evaluate((k) => localStorage.setItem(k, '{"v":1,"ui":'), KEY);
  await a.page.goto('/#/');
  await expect(a.page.getByRole('heading', { name: 'Dashboard' }).first()).toBeVisible();
  await expect(banner(a.page)).toContainText("was removed: the copy kept in this browser couldn't be read.");
  await done(a);
  // The template answered 500, damaged, or not at all: the usual language, and the pack stays.
  for (const [what, handle] of [
    ['500', (r: import('@playwright/test').Route) => r.fulfill({ status: 500, body: '' })],
    ['damaged', (r: import('@playwright/test').Route) => r.fulfill({ status: 200, contentType: 'application/json', body: '{"v": 1, "contexts"' })],
    ['hung', () => undefined],
  ] as const) {
    const s = await fresh(browser, { allow: /status of 500|ERR_|Failed to load/ });
    await storePack(s.page, FR_TEXT);
    await s.page.route('**/assets/locales/template-*.json', handle);
    await s.page.goto('/#/');
    await expect(s.page.getByRole('heading', { name: 'Dashboard' }).first(), what).toBeVisible({ timeout: 20_000 });
    await expect(banner(s.page), what).toContainText('could not be checked, so this page is in your usual language');
    await expect(s.page.locator('html'), what).toHaveAttribute('lang', 'en');
    expect(JSON.parse((await kept(s.page)) ?? '{}').fails, what).toBe(0);
    await done(s);
  }
});

test('api_013 pack code that never arrives still gives a drawn page', async ({ browser }) => {
  // A chunk request that stalls: the pack's own code, or the checking code. An import cannot be aborted; the page
  // load gives it up with the time a catalog has, and the page is drawn in the usual language (review part A of
  // T29.3, finding 6).
  for (const [what, chunk, says] of [
    ["the pack's code", /\/assets\/devpack-boot-[\w-]+\.js$/, ''],
    ['the checking code', /\/assets\/recheck-[\w-]+\.js$/, 'could not be checked, so this page is in your usual language'],
  ] as const) {
    const s = await fresh(browser, { allow: /ERR_|Failed to load/ });
    await storePack(s.page, FR_TEXT);
    await s.page.route(chunk, () => undefined);
    await s.page.goto('/#/');
    await expect(s.page.getByRole('heading', { name: 'Dashboard' }).first(), what).toBeVisible({ timeout: 20_000 });
    await expect(s.page.locator('html'), what).toHaveAttribute('lang', 'en');
    if (says) await expect(banner(s.page), what).toContainText(says);
    else await expect(banner(s.page), what).toHaveCount(0);
    expect(JSON.parse((await kept(s.page)) ?? '{}').fails, what).toBe(0);
    await done(s);
  }
});

test("api_013 a card opened in a tab from before an upgrade says reload", async ({ browser }) => {
  const s = await fresh(browser, { allow: /status of 404/ });
  await s.page.route('**/assets/DevPackCard-*.js', (r) => r.fulfill({ status: 404, body: '' }));
  await s.page.goto('/#/settings?tab=account');
  await s.page.getByRole('button', { name: 'Advanced', exact: true }).click();
  await s.page.getByTestId('devpack-open').click();
  await expect(s.page.getByTestId('devpack-stale')).toHaveText('TelltaleDNS was updated: reload this page.');
  await expect(s.page.getByTestId('devpack-card').getByRole('button', { name: 'Reload' })).toBeVisible();
  await done(s);
});

test('api_013 blocked storage still checks and downloads but refuses use', async ({ browser }) => {
  const s = await fresh(browser, {
    init: () => {
      Object.defineProperty(window, 'localStorage', {
        get() {
          throw new DOMException('blocked', 'SecurityError');
        },
      });
    },
  });
  await openCard(s.page);
  await s.page.getByTestId('devpack-tag').fill('fr');
  const [download] = await Promise.all([s.page.waitForEvent('download'), s.page.getByTestId('devpack-template').click()]);
  expect(download.suggestedFilename()).toBe('fr.json');
  await chooseFile(s.page, FR_TEXT);
  await expect(s.page.getByTestId('devpack-summary')).toContainText('fr.json: 3 of');
  await s.page.getByTestId('devpack-use').click();
  await s.page.getByTestId('devpack-confirm-use').click();
  await expect(s.page.getByTestId('devpack-use-error')).toHaveText("This browser can't keep the pack: its storage is full or blocked.");
  await done(s);
});

test('api_013 a quota error on use writes nothing', async ({ browser }) => {
  const s = await fresh(browser, {
    init: () => {
      const set = Storage.prototype.setItem;
      Storage.prototype.setItem = function (this: Storage, k: string, v: string) {
        if (k === 'telltale.devpack' && (window as unknown as { __dvpFull?: boolean }).__dvpFull) throw new DOMException('full', 'QuotaExceededError');
        return set.call(this, k, v);
      };
    },
  });
  await storePack(s.page, FR_TEXT, { name: 'earlier.json' });
  await openCard(s.page);
  // The page load checked the kept file and kept its table with it.
  const before = await kept(s.page);
  expect(JSON.parse(before ?? '{}')).toMatchObject({ name: 'earlier.json', checked: { ui: ENTRY } });
  await s.page.evaluate(() => ((window as unknown as { __dvpFull: boolean }).__dvpFull = true));
  await chooseFile(s.page, JSON.stringify({ [SETTINGS.ctx]: [[SETTINGS.english, 'Paramètres']] }), 'fr.json');
  await s.page.getByTestId('devpack-use').click();
  await s.page.getByTestId('devpack-confirm-use').click();
  await expect(s.page.getByTestId('devpack-use-error')).toHaveText("This browser can't keep the pack: its storage is full or blocked.");
  // The pack kept before is the one still kept, as it was.
  expect(await kept(s.page)).toBe(before);
  // How much this browser keeps for one address (for the report: a record holds the file's text and its table).
  const fits = await s.page.evaluate(() => {
    let most = 0;
    for (const n of [1_000_000, 2_000_000, 2_500_000, 3_000_000, 4_000_000, 5_000_000]) {
      try {
        localStorage.setItem('telltale.devpack.probe', 'x'.repeat(n));
        most = n;
      } catch {
        break;
      }
    }
    localStorage.removeItem('telltale.devpack.probe');
    return most;
  });
  console.log(`DVP_QUOTA this Chromium keeps a value of ${fits} characters (and not the next size tried)`);
  await done(s);
});

test('api_013 use stores the file that was confirmed', async ({ browser }) => {
  // A file chosen while Use waits for the server is not stored in place of the one confirmed (review part A of
  // T29.3, finding 7).
  const s = await fresh(browser);
  await openCard(s.page);
  await chooseFile(s.page, FR_TEXT);
  await expect(s.page.getByTestId('devpack-summary').last()).toContainText('fr.json');
  let release = () => {};
  const held = new Promise<void>((r) => (release = r));
  await s.page.route('**/api/v1/system/info', async (r) => {
    await held;
    await r.continue();
  });
  await s.page.getByTestId('devpack-use').click();
  await s.page.getByTestId('devpack-confirm-use').click();
  await chooseFile(s.page, ALL_TEXT, 'other.json');
  await expect(s.page.getByTestId('devpack-summary').last()).toContainText('other.json');
  await Promise.all([s.page.waitForEvent('load'), Promise.resolve().then(release)]);
  const rec = JSON.parse((await kept(s.page)) ?? '{}');
  expect([rec.name, rec.sha]).toEqual(['fr.json', createHash('sha256').update(FR_TEXT).digest('hex')]);
  await done(s);
});

test('api_013 a pack whose table does not fit is kept without it', async ({ browser }) => {
  // A store that refuses the record with its table, and takes it without.
  const s = await fresh(browser, {
    init: () => {
      const set = Storage.prototype.setItem;
      Storage.prototype.setItem = function (this: Storage, k: string, v: string) {
        if (k === 'telltale.devpack' && v.includes('"checked"')) throw new DOMException('full', 'QuotaExceededError');
        return set.call(this, k, v);
      };
    },
  });
  await openCard(s.page);
  await chooseFile(s.page, FR_TEXT);
  await s.page.getByTestId('devpack-use').click();
  await Promise.all([s.page.waitForEvent('load'), s.page.getByTestId('devpack-confirm-use').click()]);
  // Kept without the table; each load checks the file again, and the page is in the pack's language.
  const rec = JSON.parse((await kept(s.page)) ?? '{}');
  expect([rec.name, rec.checked]).toEqual(['fr.json', undefined]);
  await s.page.goto('/?devpack-test=again#/settings?tab=account');
  await expect(s.page.getByRole('heading', { level: 1 })).toHaveText(valueOf(SETTINGS.ctx));
  await expect(banner(s.page)).toContainText('Test language pack: fr.json');
  await done(s);
});

test('api_013 lang parameter pauses the pack for one page load', async ({ browser }) => {
  const s = await fresh(browser);
  await storePack(s.page, FR_TEXT);
  await s.page.goto('/?lang=en#/settings?tab=account');
  await expect(s.page.getByRole('heading', { level: 1 })).toHaveText('Settings');
  await expect(s.page.locator('html')).toHaveAttribute('lang', 'en');
  await expect(banner(s.page)).toContainText('is paused for this page load: the address asks for a language.');
  await s.page.goto('/?lang=en-XA#/settings?tab=account');
  await expect(s.page.locator('html')).toHaveAttribute('lang', 'en-XA');
  await s.page.goto('/#/settings?tab=account');
  await expect(s.page.getByRole('heading', { level: 1 })).toHaveText(valueOf(SETTINGS.ctx));
  await expect(s.page.locator('html')).toHaveAttribute('lang', 'fr');
  await done(s);
});

/** What a page sends and keeps: every request (method, address, body), and every value written to storage. */
async function record(s: { context: BrowserContext; page: Page }) {
  const sent: string[] = [];
  s.page.on('request', (r) => sent.push(`${r.method()} ${r.url()} ${r.postData() ?? ''}`));
  await s.context.addInitScript(() => {
    const w = window as unknown as { __dvpStored: string[] };
    w.__dvpStored = [];
    const set = Storage.prototype.setItem;
    Storage.prototype.setItem = function (this: Storage, k: string, v: string) {
      w.__dvpStored.push(`${k}=${v}`);
      return set.call(this, k, v);
    };
  });
  return { sent, stored: () => s.page.evaluate(() => (window as unknown as { __dvpStored?: string[] }).__dvpStored ?? []) };
}

test('api_013 pack text never reaches a request or storage', async ({ browser }) => {
  const s = await fresh(browser);
  const r = await record(s);
  await storePack(s.page, ALL_TEXT);
  for (const [path, testid] of [['/#/', 'dashboard-chart'], ['/#/queries', ''], ['/#/clients', ''], ['/#/settings?tab=account', 'devpack-card'], ['/#/settings?tab=tokens', ''], ['/#/cache', 'cache-card']]) {
    await s.page.goto(path);
    await expect(s.page.locator('html')).toHaveAttribute('lang', 'fr');
    if (testid) await expect(s.page.getByTestId(testid).first()).toBeVisible();
    await expect(s.page.locator('main').first()).toContainText(MARK);
  }
  // The Cache page's charts draw their change markers under the pack (those within the chart's own data).
  const mk = s.page.getByTestId('chart-markers').first().locator('button.mk');
  await expect(mk.first()).toBeAttached();
  expect(await mk.first().getAttribute('aria-label')).toMatch(/A note of the language pack tests|configuration 1 applied/);
  // A search and a filter, typed and chosen through the translated page.
  await s.page.locator('form[role="search"] input').fill('nas.e2e.test');
  await s.page.locator('form[role="search"] input').press('Enter');
  await expect(s.page).toHaveURL(/name=nas\.e2e\.test/);
  await expect(s.page.locator('html')).toHaveAttribute('lang', 'fr');
  const decoded = (x: string) => {
    try {
      return decodeURIComponent(x);
    } catch {
      return x;
    }
  };
  expect(r.sent.filter((x) => x.includes(MARK) || decoded(x).includes(MARK))).toEqual([]);
  expect((await r.stored()).filter((x) => !x.startsWith(`${KEY}=`) && x.includes(MARK))).toEqual([]);
  expect(await s.page.evaluate((m) => Object.keys(localStorage).filter((k) => k !== 'telltale.devpack' && (localStorage.getItem(k) ?? '').includes(m)), MARK)).toEqual([]);
  await done(s);
});

test('api_013 api_005 a pack that reads one word draws every page with live data and no page error', async ({ browser }) => {
  // The template a translator downloads, every message translated as the same word with the tokens the check keeps
  // (its placeholders, tags, addresses, numbers, words kept as written): a key built from a translated text repeats on
  // every page that draws one. Every route of the app is visited once; the pages that draw lists from data that can
  // repeat a value get such data: markers over 40 in a chart's window, names that read alike in the top lists, two
  // cache nodes that show one name. Every list is drawn, the pack's banner stays, and no page error occurs.
  test.setTimeout(150_000);
  const FR_TAG = ['one', 'many', 'other'];
  const tpl = readTemplate(lib.templateJson(lib.check(UI, { ratchets: false })));
  const skeleton = JSON.parse(materialize(tpl, FR_TAG)) as Record<string, unknown[][]>;
  const WORD = 'Mot';
  /** The word, with what the check finds missing from it for `english`; empty when that does not agree. */
  const word = (english: string, o: { verbatim: readonly string[]; glossary: readonly string[] }) => {
    const missing = agree(english, WORD, { ...o, dir: 'ltr' }).fails.filter((f) => f.token && !f.detail.startsWith('added')).map((f) => f.token);
    const text = [WORD, ...new Set(missing)].join(' ');
    return agree(english, text, { ...o, dir: 'ltr' }).fails.length ? '' : text;
  };
  let same = 0;
  let all = 0;
  for (const [ctx, pairs] of Object.entries(skeleton)) {
    if (ctx === '~leftover') continue;
    for (const pair of pairs) {
      const english = pair[0] as string | [string, string];
      const o = { verbatim: tpl.entries.get(identity(ctx, english, pair[2] as string | undefined))?.verbatim ?? [], glossary: tpl.glossary };
      all++;
      if (typeof english === 'string') pair[1] = word(english, o);
      else {
        const forms = { one: word(english[0], o), many: word(english[1], o), other: word(english[1], o) };
        pair[1] = Object.values(forms).every(Boolean) ? forms : { one: '', many: '', other: '' };
      }
      if (pair[1] === WORD) same++;
    }
  }
  console.log(`DVP_SKELETON ${same} of ${all} messages read "${WORD}" alone`);
  expect(same, 'most messages read the one word alone').toBeGreaterThan(all / 2);
  const s = await fresh(browser);
  const now = Math.floor(Date.now() / 1000);
  const marks = Array.from({ length: 60 }, (_, i) => ({ tUnixMs: (now - 22 * 3600 + i * 1260) * 1000, kind: 'config.applied', summary: `change ${i + 1}`, seq: i + 1, node: null, nodes: [], actor: null, href: null }));
  await s.page.route('**/api/v1/annotations?**', (r) => r.fulfill({ json: { items: marks, truncated: false, missingNodes: [] } }));
  const top = (key: string, count: number) => ({ key, count, errorBound: 0 });
  await s.page.route('**/api/v1/stats/top?**', (r) => {
    const kind = new URL(r.request().url()).searchParams.get('kind');
    const items = kind === 'domains' ? [top('a.b.example', 9), top('a.b.example', 8)] : kind === 'blocked' ? [top('ads.b.example', 3), top('ads.b.example', 2)] : [];
    return r.fulfill({ json: { items, missingNodes: [] } });
  });
  const stat = (entries: number) => ({ answeredPercent: 80, bytes: 1e6, entries, evictions: 0, hitPercent: 70, hits: 900, inserts: 500, misses: 100, node: 'home', prefetches: 0, staleServed: 0, uncacheable: 0, settings: null, sizing: null, warmStart: null, history: [] });
  const makeup = { nodata: 0, nxdomain: 0, positive: 3, servfail: 0, stale: 0, validated: 0 };
  await s.page.route('**/api/v1/cache/stats', (r) => r.fulfill({ json: { items: [stat(100), stat(200)] } }));
  await s.page.route('**/api/v1/cache/entries?**', (r) => r.fulfill({ json: { items: [{ node: 'home', makeup, entries: [] }, { node: 'home', makeup, entries: [] }], missingNodes: [] } }));
  await storePack(s.page, JSON.stringify(skeleton, null, 2), { name: 'skeleton.json' });
  const shows = async () => {
    await expect(s.page.locator('html')).toHaveAttribute('lang', 'fr');
    await expect(banner(s.page)).toContainText('Test language pack: skeleton.json');
  };
  await s.page.goto('/#/');
  await shows();
  await expect(s.page.locator('ol.tl a.dom', { hasText: /^a\.b\.example$/ })).toHaveCount(2);
  await expect(s.page.getByTestId('chart-markers').first().locator('button.mk').first()).toBeAttached();
  await s.page.goto('/#/?view=legacy');
  await s.page.reload();
  await shows();
  await expect(s.page.locator('ol.bars').first().locator('a.name')).toHaveText(['a.b.example', 'a.b.example']);
  await expect(s.page.locator('ol.bars').nth(1).locator('a.name')).toHaveText(['ads.b.example', 'ads.b.example']);
  await expect(s.page.getByTestId('chart-markers').first().locator('button.mk').first()).toBeAttached();
  await s.page.goto('/#/cache');
  await shows();
  await expect(s.page.getByTestId('cache-node').locator('h2')).toHaveText(['home', 'home']);
  await s.page.goto('/#/settings?tab=account');
  await expect(s.page.getByRole('heading', { level: 1 })).toHaveText(WORD);
  // Every route of the app (its list of pages), the previous dashboard and the wall, once each.
  const routes = [...readFileSync(join(UI, 'src/App.svelte'), 'utf8').matchAll(/\{ path: '(\/[^']*)'/g)].map((m) => m[1]);
  expect(routes.length, 'the app lists its pages').toBeGreaterThan(15);
  for (const path of [...routes, '/?view=legacy', '/wall']) {
    await s.page.goto(`/#${path}`);
    await shows();
    await s.page.waitForTimeout(600);
  }
  await done(s);
});

test('api_013 a pack never translates its own warning banner and buttons', async ({ browser }) => {
  const s = await fresh(browser);
  await storePack(s.page, ALL_TEXT, { name: 'all.json' });
  await s.page.goto('/#/settings?tab=account');
  await expect(s.page.locator('html')).toHaveAttribute('lang', 'fr');
  // Every message of the page is the pack's; the banner and the card's own buttons are not.
  await expect(s.page.getByRole('heading', { level: 1 })).toHaveText(`Settings ${MARK}`);
  await expect(banner(s.page)).toContainText('Test language pack: all.json');
  expect(await banner(s.page).innerText()).not.toContain(MARK);
  await expect(s.page.getByTestId('devpack-in-use')).toBeVisible();
  for (const name of ['Remove and reload', 'Download for a pull request (fr.json)']) await expect(s.page.getByTestId('devpack-in-use').getByRole('button', { name, exact: true })).toBeVisible();
  expect(await s.page.getByTestId('devpack-in-use').locator('p').first().innerText()).toMatch(/^In use: all\.json, French \(français\) \(fr\), fingerprint [0-9a-f]{12}\./);
  await chooseFile(s.page, ALL_TEXT, 'all.json', 'fr');
  await expect(s.page.getByTestId('devpack-use')).toHaveText('Use this pack…');
  await expect(s.page.getByTestId('devpack-pr')).toHaveText('Download for a pull request (fr.json)');
  await s.page.getByTestId('devpack-use').click();
  expect(await s.page.getByTestId('devpack-confirm').innerText()).not.toContain(MARK);
  await expect(s.page.getByTestId('devpack-confirm-use')).toHaveText('Use it and reload');
  await done(s);
});

test("api_013 the card's actions send nothing about the pack", async ({ browser }) => {
  const s = await fresh(browser);
  const r = await record(s);
  await s.page.goto('/#/settings?tab=account');
  await expect(s.page.getByRole('heading', { level: 1 })).toBeVisible();
  const from = r.sent.length;
  await openCard(s.page);
  await s.page.getByTestId('devpack-tag').fill('fr');
  await Promise.all([s.page.waitForEvent('download'), s.page.getByTestId('devpack-template').click()]);
  await Promise.all([s.page.waitForEvent('download'), s.page.getByTestId('devpack-notes').click()]);
  await chooseFile(s.page, FR_TEXT);
  await Promise.all([s.page.waitForEvent('download'), s.page.getByTestId('devpack-pr').click()]);
  const beforeUse = r.sent.length;
  await s.page.getByTestId('devpack-use').click();
  await Promise.all([s.page.waitForEvent('load'), s.page.getByTestId('devpack-confirm-use').click()]);
  const card = r.sent.slice(from, beforeUse);
  // Only reads: the card's chunk and its stylesheet, the template, and the app's own polls.
  expect(card.filter((x) => !x.startsWith('GET '))).toEqual([]);
  expect(card.filter((x) => x.includes('/assets/locales/')).map((x) => new URL(x.split(' ')[1]).pathname)).toEqual([templateUrl()]);
  // Use: /system/info for the server's build and /auth/status for who is signed in, up to the reload's own page
  // request (the reloaded page asks for both too).
  const reloadAt = r.sent.findIndex((x, i) => i >= beforeUse && x.startsWith('GET ') && new URL(x.split(' ')[1]).pathname === '/');
  expect(reloadAt).toBeGreaterThan(beforeUse);
  const use = r.sent.slice(beforeUse, reloadAt);
  expect(use.filter((x) => !x.startsWith('GET '))).toEqual([]);
  expect(use.filter((x) => x.includes('/api/v1/system/info')).length).toBeGreaterThanOrEqual(1);
  expect(use.filter((x) => x.includes('/api/v1/auth/status')).length).toBeGreaterThanOrEqual(1);
  // Nothing about the file in any request: its name, fingerprint or text.
  const sha = createHash('sha256').update(FR_TEXT).digest('hex');
  for (const needle of ['fr.json', sha, sha.slice(0, 12), 'Réglages', 'R%C3%A9glages', 'Se connecter', 'supprim']) expect(r.sent.filter((x) => x.includes(needle)), needle).toEqual([]);
  await done(s);
});

test('api_013 the check screen shows pack text inert', async ({ browser }) => {
  const s = await fresh(browser);
  await openCard(s.page);
  const pack = { [SETTINGS.ctx]: [[SETTINGS.english, 'Régla\u202Eges abc']], [SIGN_IN.ctx]: [[SIGN_IN.english, '<b>Se</b> connecter']] };
  await chooseFile(s.page, JSON.stringify(pack), 'fr.json');
  await s.page.getByTestId('devpack-broken').locator('summary').click();
  const list = s.page.getByTestId('devpack-broken').locator('li');
  await expect(list.first()).toBeVisible();
  // The direction override is a visible marker, and the rest of the line keeps its order.
  await expect(list.filter({ hasText: 'U+202E' }).first()).toContainText('Régla⟨U+202E⟩ges abc');
  // A tag is shown as typed, never as markup.
  await expect(list.filter({ hasText: 'connecter' }).first()).toContainText('<b>Se</b> connecter');
  expect(await s.page.getByTestId('devpack-broken').locator('li b').count()).toBe(0);
  await done(s);
});

test('api_013 a refused file says why and stores nothing', async ({ browser }) => {
  const s = await fresh(browser);
  await openCard(s.page);
  const cases: [string | Buffer, string][] = [
    [`{"${SETTINGS.ctx}": [], "${SETTINGS.ctx}": []}`, `This file can't be used: the key "${SETTINGS.ctx}" appears twice (line 1, column`],
    [Buffer.from([0x7b, 0xff, 0x7d]), "This file can't be used: it isn't UTF-8 text."],
    [Buffer.alloc(1024 * 1024 + 1, 0x20), "This file can't be used: it is larger than 1 MiB."],
    ['{"settings": [["Settings"]]}', `This file can't be used: pair 1 of "settings" is not in the form of the template.`],
  ];
  for (const [text, says] of cases) {
    await chooseFile(s.page, text, 'fr.json', 'fr');
    await expect(s.page.getByTestId('devpack-refused')).toContainText(says);
    await expect(s.page.getByTestId('devpack-use')).toHaveCount(0);
  }
  expect(await kept(s.page)).toBeNull();
  await done(s);
});

test('api_013 the pack card works with the keyboard and at 360 px', async ({ browser }) => {
  const s = await fresh(browser, { width: 360 });
  await s.page.goto('/#/settings?tab=account');
  await s.page.getByRole('button', { name: /^Menu/ }).click();
  await s.page.getByRole('button', { name: 'Advanced view' }).click();
  await s.page.keyboard.press('Escape');
  await s.page.getByTestId('devpack-open').focus();
  await s.page.keyboard.press('Enter');
  await expect(s.page.getByTestId('devpack-tag')).toBeVisible();
  // A real label names each field.
  await expect(s.page.getByLabel('Language tag (such as de, fr, pt-BR or zh-Hant)')).toBeVisible();
  await s.page.getByTestId('devpack-tag').focus();
  await s.page.keyboard.type('fr');
  await s.page.keyboard.press('Tab');
  await expect(s.page.getByTestId('devpack-template')).toBeFocused();
  await chooseFile(s.page, FR_TEXT);
  await expect(s.page.getByTestId('devpack-summary')).toHaveAttribute('role', 'status');
  await s.page.getByTestId('devpack-use').focus();
  await s.page.keyboard.press('Enter');
  // The confirmation's heading takes the focus; Escape gives it back.
  await expect(s.page.locator('#devpack-confirm')).toBeFocused();
  await s.page.keyboard.press('Escape');
  await expect(s.page.getByTestId('devpack-use')).toBeFocused();
  for (const d of ['devpack-broken', 'devpack-missing', 'devpack-left', 'devpack-worth', 'devpack-coverage']) await s.page.getByTestId(d).locator('summary').click();
  expect(await s.page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await done(s);
});

// The whole-page rule of the pseudo-locale (8-i18n-pseudo.spec.ts), on the card, its states and the banner.
const MESSAGES = ENTRIES.flatMap((e) => (Array.isArray(e.english) ? e.english : [e.english]));
// The help glossary is English outside the layer (ADR-189: help stays English in part A), as 8-i18n-pseudo.spec.ts has it.
const HELP: string[] = JSON.parse(readFileSync(join(UI, '../docs/help/topics.json'), 'utf8')).topics.flatMap((t: Record<string, unknown>) =>
  Object.values(t).filter((v): v is string => typeof v === 'string'),
);
const RULE = makeRule({ data: DATA, help: HELP, messages: MESSAGES });
const collides = makeCollides(MESSAGES);
async function leftovers(page: Page, received: Set<string>) {
  const { text, other, help, at } = await page.evaluate(readPage);
  const places = new Map<string, string[]>();
  for (const [x, place] of at) places.set(x, [...(places.get(x) ?? []), place]);
  return RULE.found(text, other, [...received].filter((v) => !collides(v)), help, places).map((x) => `${x} (${places.get(JSON.parse(x))?.slice(0, 2).join('; ')})`);
}

test('api_012 pseudo locale leaves no literal text: the language pack card and banner', async ({ browser }) => {
  const s = await fresh(browser);
  const received = new Set<string>();
  s.page.on('response', (r) => {
    if (/json/.test(r.headers()['content-type'] ?? '') && !r.url().includes('/assets/locales/')) void r.text().then((t) => jsonStrings(JSON.parse(t), received), () => undefined);
  });
  await storePack(s.page, FR_TEXT);
  await s.page.goto('/?lang=en-XA#/settings?tab=account');
  await expect(s.page.locator('html')).toHaveAttribute('lang', 'en-XA');
  // A pack is kept here: the card shows in the Simple view, open.
  await expect(s.page.getByTestId('devpack-in-use')).toBeVisible();
  expect(await leftovers(s.page, received), 'the banner (paused) and the card with a pack in use').toEqual([]);
  // A file checked, every list open; then the confirmation.
  const pack = { ...FR, [SETTINGS.ctx]: [[SETTINGS.english, 'Régla\u202Eges'], ['Gone', 'Parti']], '~leftover': [['Older', 'Ancien']] };
  await chooseFile(s.page, JSON.stringify(pack), 'fr.json', 'fr');
  await expect(s.page.getByTestId('devpack-summary').last()).toContainText('fr.json');
  for (const d of ['devpack-broken', 'devpack-missing', 'devpack-left', 'devpack-worth', 'devpack-coverage']) await s.page.getByTestId(d).locator('summary').click();
  expect(await leftovers(s.page, received), 'a checked file, its lists open').toEqual([]);
  await s.page.getByTestId('devpack-use').click();
  expect(await leftovers(s.page, received), 'the confirmation').toEqual([]);
  // A refused file, a refused tag, and the notice after a removal.
  await chooseFile(s.page, '{"a": 1, "a": 2}', 'fr.json', 'fr');
  expect(await leftovers(s.page, received), 'a refused file').toEqual([]);
  await s.page.getByTestId('devpack-tag').fill('zh');
  expect(await leftovers(s.page, received), 'a refused tag').toEqual([]);
  await s.page.evaluate((k) => localStorage.setItem(k, JSON.stringify({ v: 1, gone: 'failed', name: 'fr.json', at: Date.now() })), KEY);
  await s.page.reload();
  await expect(s.page.getByTestId('devpack-card-notice')).toBeVisible();
  expect(await leftovers(s.page, received), 'the notice in the banner and the card').toEqual([]);
  await done(s);
});
