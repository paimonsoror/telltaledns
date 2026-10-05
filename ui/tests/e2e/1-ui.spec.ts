// REQ: API-003, API-005 — the UI end to end against a real server: first-run setup, the
// dashboard, the query log and "Why?", explain, tokens, users and roles, sign-out/in, and a
// phone-width layout, and the masked-client-IP banner. Any CSP violation or page error fails the suite.
import { expect, test, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { query } from './dns';

test.describe.configure({ mode: 'serial' });

const ADMIN = { user: 'admin', pass: 'correct horse battery' };
const VIEWER = { user: 'viewer1', pass: 'another long password' };

let page: Page;
const problems: string[] = [];

test.beforeAll(async ({ browser }) => {
  page = await browser.newPage();
  page.on('pageerror', (e) => problems.push(`page error: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error' && !/status of 40[13]/.test(m.text())) problems.push(`console: ${m.text()}`);
  });
});

test.afterEach(() => {
  expect(problems, 'no page errors or CSP violations').toEqual([]);
});

test.afterAll(async () => {
  await page.close();
});

async function signIn(user: string, pass: string) {
  await page.getByLabel('Username', { exact: true }).fill(user);
  await page.getByLabel('Password', { exact: true }).fill(pass);
  await page.getByRole('button', { name: 'Sign in' }).click();
}

test('first run: the setup token creates the admin', async () => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Welcome to TelltaleDNS' })).toBeVisible();
  const token = readFileSync(resolve(import.meta.dirname, '../../.e2e/data/setup-token'), 'utf8').trim();
  await page.getByLabel('Setup token').fill(token);
  await page.getByLabel('Admin username').fill(ADMIN.user);
  await page.getByLabel('Password (at least 10 characters)').fill(ADMIN.pass);
  await page.getByLabel('Repeat password').fill(ADMIN.pass);
  await page.getByRole('button', { name: 'Create admin and sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
});

test('dashboard shows traffic and top blocked names', async () => {
  // The blocklist compiles in the background after start (DNS never waits for it).
  await expect
    .poll(async () => (await (await page.request.get('/api/v1/system/info')).json()).filterSnapshot ?? null, {
      timeout: 30_000,
    })
    .not.toBeNull();
  for (let i = 0; i < 5; i++) expect(await query('ads.e2e.test')).toBe(0);
  for (let i = 0; i < 3; i++) expect(await query('nas.e2e.test')).toBe(0);
  await expect(async () => {
    await page.reload();
    await expect(page.getByRole('link', { name: 'ads.e2e.test' }).first()).toBeVisible({ timeout: 2000 });
  }).toPass({ timeout: 20_000 });
  await expect(page.getByText('Queries by status')).toBeVisible();
  // Every chart has a table view.
  await page.getByRole('button', { name: 'Table' }).first().click();
  await expect(page.locator('.table-view table').first()).toBeVisible();
});

test('query log finds the blocked query and explains it', async () => {
  await page.goto('/#/queries?name=ads.e2e.test');
  await expect(async () => {
    await page.reload();
    await expect(page.locator('table.log tbody tr').first()).toContainText('blocked', { timeout: 2000 });
  }).toPass({ timeout: 20_000 });
  await expect(page.locator('table.log tbody tr').first()).toContainText('e2e-block');
  await page.getByRole('button', { name: 'Why?' }).first().click();
  const drawer = page.getByRole('dialog');
  await expect(drawer).toContainText('e2e-block');
  await expect(drawer).toContainText('★');
  await page.keyboard.press('Escape');
  await expect(drawer).toBeHidden();
  // Status chips filter, and the filter lands in the URL.
  await page.goto('/#/queries');
  await page.getByRole('button', { name: 'local', exact: true }).click();
  await expect(page).toHaveURL(/status=local/);
  await expect(async () => {
    await page.reload();
    await expect(page.locator('table.log tbody tr').first()).toContainText('nas.e2e.test', { timeout: 2000 });
  }).toPass({ timeout: 20_000 });
});

test('live view streams new queries', async () => {
  await page.goto('/#/queries?status=blocked');
  await page.getByLabel('Live').check();
  await expect(page.locator('.live-toggle .badge')).toHaveText('streaming');
  await expect(page.locator('table.log tbody tr')).toHaveCount(0);
  await expect(async () => {
    expect(await query('live.ads.e2e.test')).toBe(0);
    await expect(page.locator('table.log tbody tr').first()).toContainText('live.ads.e2e.test', { timeout: 1500 });
  }).toPass({ timeout: 15_000 });
  // Server-side filter: a local answer doesn't match status=blocked.
  expect(await query('nas.e2e.test')).toBe(0);
  await page.waitForTimeout(800);
  await expect(page.locator('table.log tbody tr', { hasText: 'nas.e2e.test' })).toHaveCount(0);
  await page.getByLabel('Live').uncheck();
});

test('explain page', async () => {
  await page.goto('/#/explain?name=nas.e2e.test&client=127.0.0.1');
  await expect(page.locator('.explain')).toContainText('local');
  await page.getByRole('textbox', { name: 'Name', exact: true }).fill('ads.e2e.test');
  await page.getByRole('button', { name: 'Explain' }).click();
  await expect(page.locator('.explain')).toContainText('blocked');
});

test('the menu links to the project on GitHub and its site', async () => {
  await page.goto('/#/');
  const gh = page.getByRole('link', { name: 'TelltaleDNS on GitHub' });
  await expect(gh).toHaveAttribute('href', 'https://github.com/paimonsoror/telltaledns');
  await expect(gh).toHaveAttribute('target', '_blank');
  await expect(page.getByRole('link', { name: 'Project site and guides' })).toHaveAttribute(
    'href',
    'https://paimonsoror.github.io/telltaledns/',
  );
});

test('lists, groups, clients, upstreams, local DNS render', async () => {
  for (const [path, text] of [
    ['/#/lists', 'e2e-block'],
    ['/#/groups', 'default'],
    ['/#/clients', '127.0.0.1'],
    ['/#/upstreams', 'nowhere'],
    ['/#/local-dns', 'nas.e2e.test'],
    ['/#/anomalies', 'Nothing unusual'],
  ]) {
    await page.goto(path);
    await expect(page.locator('main')).toContainText(text);
  }
});

test('API tokens: created once, usable, revocable', async ({ request }) => {
  await page.goto('/#/settings?tab=tokens');
  await page.getByLabel('Token name').fill('e2e');
  await page.getByRole('button', { name: 'Create token' }).click();
  const token = (await page.locator('code.token').textContent())?.trim() ?? '';
  expect(token).toMatch(/^tt_/);
  const auth = { authorization: `Bearer ${token}` };
  expect((await request.get('/api/v1/system/info', { headers: auth })).status()).toBe(200);
  expect((await request.get('/api/v1/system/info')).status()).toBe(401);
  await page.getByRole('button', { name: 'Revoke' }).click();
  await expect(page.getByText('No tokens yet.')).toBeVisible();
  expect((await request.get('/api/v1/system/info', { headers: auth })).status()).toBe(401);
});

test('admins add users; viewers see less', async () => {
  await page.goto('/#/settings?tab=users');
  await page.getByLabel('Username', { exact: true }).fill(VIEWER.user);
  await page.getByLabel('Password', { exact: true }).fill(VIEWER.pass);
  await page.getByRole('button', { name: 'Add', exact: true }).click();
  await expect(page.locator('main table')).toContainText(VIEWER.user);
  // REQ: API-006 — the change is in the audit log, and the chain verifies.
  await page.getByRole('tab', { name: 'Audit log' }).click();
  await expect(page.locator('table.audit tbody tr').first()).toContainText('user.create');
  await expect(page.locator('table.audit tbody tr').first()).toContainText(VIEWER.user);
  await page.getByRole('button', { name: 'Verify chain' }).click();
  await expect(page.locator('.verify-result')).toContainText('Chain intact');
  await page.getByRole('tab', { name: 'Users' }).click();
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  await signIn(VIEWER.user, 'wrong password!!');
  await expect(page.getByRole('alert')).toContainText('wrong username or password');
  await signIn(VIEWER.user, VIEWER.pass);
  // Signing in keeps the page; a viewer asking for the users tab gets their account instead.
  await expect(page.getByRole('heading', { name: 'Settings' })).toBeVisible();
  await expect(page.getByRole('tab', { name: 'Account' })).toHaveAttribute('aria-selected', 'true');
  await expect(page.getByRole('tab', { name: 'API tokens' })).toBeVisible();
  await expect(page.getByRole('tab', { name: 'Users' })).toHaveCount(0);
  await expect(page.getByRole('tab', { name: 'Audit log' })).toHaveCount(0);
  expect((await page.request.get('/api/v1/users')).status()).toBe(403);
  await page.getByRole('button', { name: 'Sign out' }).click();
  await page.goto('/');
  await signIn(ADMIN.user, ADMIN.pass);
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
});

test('works at phone width (360 px)', async () => {
  await page.setViewportSize({ width: 360, height: 740 });
  await page.goto('/#/queries');
  await expect(page.getByRole('heading', { name: 'Query log' })).toBeVisible();
  await page.getByRole('button', { name: 'Menu' }).click();
  await page.getByRole('link', { name: 'Dashboard' }).click();
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow).toBeLessThanOrEqual(0);
});

// REQ: OPS-003 — every e2e query comes from 127.0.0.1 (infrastructure), so 100+ of them
// make client IPs look masked: the banner says so and links to the fix.
test('ops_003 masked client IPs raise a banner', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await Promise.all(Array.from({ length: 120 }, (_, i) => query(`m${i}.nas.e2e.test`).catch(() => -1)));
  // A slow runner can drop some of those UDP queries (CI flake 2026-10-04): keep sending small
  // batches until the detector has seen its 100.
  let batch = 0;
  await expect
    .poll(
      async () => {
        const masked = (await (await page.request.get('/api/v1/system/info')).json()).clientIpsMasked;
        if (!masked) {
          batch += 1;
          await Promise.all(
            Array.from({ length: 20 }, (_, i) => query(`m${batch}-${i}.nas.e2e.test`).catch(() => -1)),
          );
        }
        return masked?.sources ?? [];
      },
      { timeout: 30_000 },
    )
    .toContain('127.0.0.1');
  await expect(async () => {
    await page.reload();
    await expect(page.getByTestId('masked-banner')).toBeVisible({ timeout: 2000 });
  }).toPass({ timeout: 20_000 });
  await expect(page.getByTestId('masked-banner')).toContainText('127.0.0.1');
  await expect(page.getByRole('link', { name: 'How to fix it' })).toHaveAttribute('href', /seeing-real-client-ips/);
});

// REQ: FLT-005 (ADR-050, T3.14 AC) — devices on a group's network are in that group: the
// Groups card shows the network and traffic, the dashboard charts traffic by group, and the
// query log filters by group.
test('flt_005 network groups: cards, chart, and query-log filter', async () => {
  for (let i = 0; i < 5; i++) await query(`g${i}.nas.e2e.test`).catch(() => -1);
  await page.goto('/#/groups');
  const card = page.getByTestId('group-card').filter({ hasText: 'lab' });
  await expect(card).toContainText('127.0.0.0/8');
  await expect(async () => {
    await page.reload();
    await expect(card.locator('dd').first()).not.toHaveText('0', { timeout: 2000 });
  }).toPass({ timeout: 20_000 });
  await page.goto('/#/');
  await expect(page.getByRole('heading', { name: 'Traffic by group' })).toBeVisible();
  await page.getByLabel('Group').selectOption('lab');
  await expect(page.locator('section.card', { hasText: 'Top domains' })).toContainText('nas.e2e.test');
  await page.goto('/#/queries?group=lab');
  await expect(page.locator('table.log tbody tr').first().locator('.group-chip')).toHaveText('lab');
  const r = await page.request.get('/api/v1/queries?group=lab&limit=5');
  expect(r.status()).toBe(200);
  expect((await r.json()).items.every((x: { group: string }) => x.group === 'lab')).toBe(true);
  expect((await page.request.get('/api/v1/queries?group=nope')).status()).toBe(400);
  // The clients list shows the group each client gets from its network.
  await page.goto('/#/clients');
  const seen = page.locator('section.card', { hasText: 'Seen this hour' });
  await expect(seen.locator('tbody tr', { hasText: '127.0.0.1' }).locator('.group-chip')).toHaveText('lab');
});

// REQ: CLU-008 — the Cluster page on a standalone node says so and how to start a cluster.
test('clu_008 cluster page on a standalone node', async () => {
  await page.goto('/#/cluster');
  await expect(page.getByRole('heading', { name: 'Cluster' })).toBeVisible();
  await expect(page.getByTestId('cluster-standalone')).toContainText('telltale cluster init');
  expect((await (await page.request.get('/api/v1/cluster')).json()).enabled).toBe(false);
});

// REQ: API-010 (T3.10 AC) — name a device from the top-clients widget; the name shows at once in
// the widget, the query log (past rows included), and the live tail.
test('api_010 name a device from the dashboard', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/');
  const widget = page.locator('section.card', { hasText: 'Top clients' });
  // A slow form load must not wipe what was typed (CI flake on 2026-10-04): delay it.
  const slow = '**/api/v1/clients';
  await page.route(slow, async (r) => {
    await new Promise((done) => setTimeout(done, 800));
    await r.continue();
  });
  await widget.getByRole('button', { name: '127.0.0.1' }).click();
  await page.getByRole('menuitem', { name: 'Name this device…' }).click();
  await page.getByLabel('Name', { exact: true }).fill('Test laptop');
  await page.unroute(slow);
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('status')).toContainText('Saved');
  await page.keyboard.press('Escape');
  await expect(widget).toContainText('Test laptop');
  // History is relabelled (names are resolved when read).
  await page.goto('/#/queries');
  await expect(page.locator('table.log tbody tr').first()).toContainText('Test laptop');
  // New queries in the live tail carry the name too.
  await page.getByLabel('Live').check();
  await expect(page.locator('.live-toggle .badge')).toContainText('streaming');
  await query('api010.nas.e2e.test').catch(() => -1); // no upstream: logged as servfail
  const liveRow = page.locator('table.log tbody tr', { hasText: 'api010.nas.e2e.test' });
  await expect(liveRow).toContainText('Test laptop');
  await page.getByLabel('Live').uncheck();
});

// REQ: API-002, AGT-002, AGT-003 — the same change through the API: dry run, If-Match,
// Idempotency-Key, validation, delete, audit.
test('api_010 device API: dry run, versions, idempotency', async () => {
  const r = page.request;
  const csrf = (await (await r.get('/api/v1/auth/status')).json()).csrfToken as string;
  const h = (extra: Record<string, string> = {}) => ({ 'x-csrf-token': csrf, ...extra });
  const list = await r.get('/api/v1/clients');
  const version = Number((list.headers()['etag'] ?? '"0"').replaceAll('"', ''));
  const laptop = (await list.json()).items.find((c: { name: string }) => c.name === 'Test laptop');
  expect(laptop).toMatchObject({ source: 'api', match: ['127.0.0.1'] });

  const rename = { name: 'Renamed laptop', match: ['127.0.0.1'], groups: ['default'] };
  const url = '/api/v1/clients/Test%20laptop';
  // Dry run: reported, not applied.
  const dry = await r.put(`${url}?dryRun=true`, { headers: h(), data: rename });
  expect(dry.status()).toBe(200);
  expect(await dry.json()).toMatchObject({ applied: false, configVersion: version, after: { name: 'Renamed laptop' } });
  // A stale version is refused.
  const stale = await r.put(url, { headers: h({ 'if-match': `"${version + 99}"` }), data: rename });
  expect(stale.status()).toBe(412);
  expect((await stale.json()).code).toBe('version_conflict');
  // An unknown group is refused with the reason.
  const bad = await r.put(url, { headers: h(), data: { ...rename, groups: ['nope'] } });
  expect(bad.status()).toBe(422);
  expect((await bad.json()).detail).toContain('nope');
  // Applied once; the retry replays the first answer; the key can't be reused for another change.
  const key = `e2e-${Date.now()}`;
  const first = await r.put(url, { headers: h({ 'if-match': `"${version}"`, 'idempotency-key': key }), data: rename });
  expect(first.status()).toBe(200);
  const applied = await first.json();
  expect(applied).toMatchObject({ applied: true, configVersion: version + 1 });
  const again = await r.put(url, { headers: h({ 'if-match': `"${version}"`, 'idempotency-key': key }), data: rename });
  expect(again.headers()['idempotency-replayed']).toBe('true');
  expect(await again.json()).toEqual(applied);
  const reused = await r.put(url, { headers: h({ 'idempotency-key': key }), data: { ...rename, name: 'Other' } });
  expect(reused.status()).toBe(409);
  // Past query-log rows now show the new name.
  const rows = (await (await r.get('/api/v1/queries?client=127.0.0.1&limit=5')).json()).items;
  expect(rows.length).toBeGreaterThan(0);
  for (const row of rows) expect(row.clientName).toBe('Renamed laptop');
  // Audited with the author.
  const audit = (await (await r.get('/api/v1/audit?action=client.put')).json()).items;
  expect(audit[0]).toMatchObject({ action: 'client.put', target: 'Test laptop', actor: 'admin' });
  // Forget it: the address comes back.
  expect((await r.delete('/api/v1/clients/Renamed%20laptop', { headers: h() })).status()).toBe(200);
  const after = (await (await r.get('/api/v1/queries?client=127.0.0.1&limit=1')).json()).items[0];
  expect(after.clientName).toBeUndefined();
});

// REQ: API-011 (T3.11 AC) — a novice opens a "?" panel and sees its diagram; Explain draws the
// decision; Simple hides detail that Advanced shows.
test('api_011 help panels, diagrams, and simple/advanced', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/lists');
  await page.getByRole('button', { name: 'Help: Block or allow whole categories of sites' }).click();
  const panel = page.getByTestId('help-panel');
  await expect(panel).toBeVisible();
  await expect(panel).toContainText('When you');
  await expect(panel.getByRole('img')).toHaveAttribute('aria-label', /blocks it/);
  await page.keyboard.press('Escape');
  await expect(panel).toHaveCount(0);

  await page.goto('/#/explain?name=ads.e2e.test&client=127.0.0.1');
  await expect(page.getByTestId('explain-flow').getByRole('img')).toHaveAttribute('aria-label', /blocks it.*\(list e2e-block\)/);

  // Simple (the default) hides each list's source; Advanced shows it, and is remembered.
  await page.goto('/#/lists');
  await page.getByRole('button', { name: 'Simple', exact: true }).click();
  await expect(page.locator('main')).not.toContainText('Lines');
  await page.getByRole('button', { name: 'Advanced', exact: true }).click();
  await expect(page.locator('main')).toContainText('Lines');
  await page.reload();
  await expect(page.getByRole('button', { name: 'Advanced', exact: true })).toHaveAttribute('aria-pressed', 'true');
  await page.getByRole('button', { name: 'Simple', exact: true }).click();
});

// REQ: API-011 (T3.12 AC) — a novice creates nas.home.arpa and sends corp.example elsewhere through
// the wizards, without docs; DNS answers at once; the API does the same with dry-run.
test('api_011 names on my network: wizards, DNS, and the API', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/local-dns');
  await expect(page.getByRole('heading', { name: 'Names on my network' })).toBeVisible();

  await page.getByRole('button', { name: 'Set up my home domain', exact: true }).click();
  await expect(page.getByRole('textbox', { name: 'Home domain', exact: true })).toHaveValue('home.arpa');
  await page.getByRole('button', { name: 'Next' }).click();
  await page.getByRole('textbox', { name: 'Device name', exact: true }).fill('nas');
  await page.getByRole('textbox', { name: 'Address', exact: true }).fill('192.168.1.10');
  await expect(page.getByTestId('change-preview')).toContainText('nas.home.arpa gets the address 192.168.1.10');
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('status')).toContainText('nas.home.arpa now answers');
  await page.keyboard.press('Escape');
  await expect(page.locator('main')).toContainText('nas.home.arpa');
  expect(await query('nas.home.arpa')).toBe(0); // NOERROR, answered locally

  await page.getByRole('button', { name: 'Send a domain to another server', exact: true }).click();
  await page.getByRole('textbox', { name: 'Domain', exact: true }).fill('corp.example');
  await page.getByRole('textbox', { name: 'Server address', exact: true }).fill('10.0.0.53');
  await expect(page.getByTestId('change-preview')).toContainText('asked of 10.0.0.53');
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('status')).toContainText('corp.example');
  await page.keyboard.press('Escape');
  await expect(page.locator('main')).toContainText('udp://10.0.0.53');

  // Explain confirms both paths.
  await page.goto('/#/explain?name=nas.home.arpa&client=127.0.0.1');
  await expect(page.getByTestId('explain-flow').getByRole('img')).toHaveAttribute('aria-label', /your own names/);
  await page.goto('/#/explain?name=intranet.corp.example&client=127.0.0.1');
  await expect(page.getByTestId('explain-flow').getByRole('img')).toHaveAttribute('aria-label', /server you chose/);

  // The API: dry run, validation, and the same change.
  const r = page.request;
  const csrf = (await (await r.get('/api/v1/auth/status')).json()).csrfToken as string;
  const h = { 'x-csrf-token': csrf };
  const dry = await r.put('/api/v1/records/printer.home.arpa?dryRun=true', { headers: h, data: { records: [{ type: 'A', value: '192.168.1.20' }] } });
  expect(await dry.json()).toMatchObject({ applied: false, after: { name: 'printer.home.arpa' } });
  expect((await (await r.get('/api/v1/records')).json()).items.map((n: { name: string }) => n.name)).not.toContain('printer.home.arpa');
  const bad = await r.put('/api/v1/records/printer.home.arpa', { headers: h, data: { records: [{ type: 'A', value: 'printer' }] } });
  expect(bad.status()).toBe(422);
  const file = await r.put('/api/v1/records/nas.e2e.test', { headers: h, data: { records: [{ type: 'A', value: '10.1.1.1' }] } });
  expect(file.status()).toBe(409);
  const fwDry = await r.put('/api/v1/forwards/lab.example?dryRun=true', { headers: h, data: { servers: ['tls://10.0.0.9'] } });
  expect(await fwDry.json()).toMatchObject({ applied: false, after: { domain: 'lab.example', servers: ['tls://10.0.0.9'] } });
  expect((await r.delete('/api/v1/forwards/corp.example', { headers: h })).status()).toBe(200);
  expect((await r.delete('/api/v1/records/nas.home.arpa', { headers: h })).status()).toBe(200);
  expect(await query('nas.home.arpa').catch(() => -1)).not.toBe(0);
});

// REQ: FLT-005 (T6.12, ADR-067) — a quick rule from "Why?": allow a blocked name for this
// device for an hour; DNS stops blocking it at once, the Rules page shows it with its
// countdown, and removing it blocks the name again. No list is recompiled.
test('flt_005 quick rule: allow for 1 hour from the query log', async () => {
  expect(await query('ads.e2e.test')).toBe(0); // blocked: 0.0.0.0
  await page.goto('/#/queries?status=blocked&name=ads.e2e.test&match=exact');
  await page.getByRole('button', { name: 'Why?' }).first().click();
  const form = page.getByTestId('quick-rule-form');
  await expect(form.getByRole('textbox', { name: 'Domain' })).toHaveValue('ads.e2e.test');
  await expect(form.getByRole('combobox', { name: 'Duration' })).toHaveValue('60');
  await form.getByRole('textbox', { name: 'Note' }).fill('e2e game');
  await form.getByRole('button', { name: 'Save rule' }).click();
  await expect(page.getByTestId('quick-rule-saved')).toContainText('allowed for');
  await page.keyboard.press('Escape');

  // Not blocked any more: it goes upstream (unreachable in this test, so not a 0.0.0.0 answer).
  expect(await query('ads.e2e.test').catch(() => -1)).not.toBe(0);

  await page.goto('/#/rules');
  const table = page.getByTestId('rules-table');
  await expect(table).toContainText('ads.e2e.test');
  await expect(table).toContainText('e2e game');
  await expect(table).toContainText(/in (59m|1h)/);

  // The query log attributes the decision to the rule.
  // (The allowed query is logged once its upstream attempt ends, a few seconds later here.)
  await page.goto('/#/queries?name=ads.e2e.test&match=exact');
  await expect
    .poll(
      async () => {
        await page.reload();
        return page.locator('table.log tbody').innerText();
      },
      { timeout: 20_000, intervals: [1000] },
    )
    .toContain('quick allow');

  // Removing it: the lists decide again.
  await page.goto('/#/rules');
  await page.getByTestId('rules-table').getByRole('button', { name: 'Remove' }).click();
  await expect(page.locator('main')).toContainText('No quick rules');
  expect(await query('ads.e2e.test')).toBe(0);
});

// REQ: FLT-005 (ADR-067) — an expiring rule stops applying at its expiry without a restart,
// the sweep removes it within seconds, and the audit log records `rule.expire`.
test('flt_005 quick rules expire on their own and are audited', async () => {
  const r = page.request;
  const csrf = (await (await r.get('/api/v1/auth/status')).json()).csrfToken as string;
  const h = { 'x-csrf-token': csrf };
  const expires = new Date(Date.now() + 4000).toISOString().replace(/\.\d+Z$/, 'Z');
  const put = await r.put('/api/v1/rules/e2e-expiring', {
    headers: h,
    data: { action: 'allow', domain: 'ads.e2e.test', devices: ['127.0.0.1'], expires },
  });
  expect(put.status()).toBe(200);
  expect(await query('ads.e2e.test').catch(() => -1)).not.toBe(0); // allowed while it lasts
  await expect
    .poll(async () => (await (await r.get('/api/v1/rules')).json()).items.length, { timeout: 20_000, intervals: [1000] })
    .toBe(0);
  expect(await query('ads.e2e.test')).toBe(0); // the list blocks it again
  const audit = await (await r.get('/api/v1/audit?limit=20')).json();
  expect(JSON.stringify(audit)).toContain('rule.expire');
  // Mistakes are refused with a reason.
  const past = await r.put('/api/v1/rules/e2e-past', {
    headers: h,
    data: { action: 'block', domain: 'x.e2e.test', expires: '2020-01-01T00:00:00Z' },
  });
  expect(past.status()).toBe(422);
  const unknownGroup = await r.put('/api/v1/rules/e2e-bad', {
    headers: h,
    data: { action: 'block', domain: 'x.e2e.test', groups: ['nope'] },
  });
  expect(unknownGroup.status()).toBe(422);
});

// REQ: CLU-008, CLU-009 (T6.14) — the topology matches GET /cluster: a controller with 3 pods on
// two Kubernetes nodes and a Pi; 8 pods on one node fold into "+3"; a pod down is red; selecting
// a pod opens its site and highlights its row (pod name, Kubernetes node, share, cache).
test('clu_008 cluster topology', async () => {
  const node = (o: Record<string, unknown>) => ({
    ephemeral: false, witness: false, protocol: 4, role: 'replica', thisNode: false, eligible: true, version: '0.1.0',
    up: true, connected: true, link: 'inbound', lastSeenSecondsAgo: 1, rttMs: 3, configSeq: 9, configLag: 0, ready: true,
    qps: 10, servfailPercent: 0, upstreamP90Ms: 12, uptimeSeconds: 3600, restarts: 0, cacheEntries: 500,
    cacheHitPercent: 80, querySharePercent: 10, ...o,
  });
  const pod = (name: string, kube: string, o: Record<string, unknown> = {}) =>
    node({ nodeId: `id-${name}`, site: 'k8s', ephemeral: true, pod: `telltale-resolver-${name}`, kubeNode: kube, ...o });
  const view = (pods: ReturnType<typeof node>[]) => ({
    enabled: true, clusterId: 'c1', name: 'home', thisNode: 'id-ctl', newestConfigSeq: 9, healthy: true, checks: [],
    events: [], conflicts: [], authority: 'primary',
    nodes: [
      node({ nodeId: 'id-ctl', site: 'k8s', role: 'primary', thisNode: true, link: 'self', rttMs: null, pod: 'telltaledns-756965cdc7-8j9h9', kubeNode: 'k3s-node-with-a-long-name-1', qps: 40, querySharePercent: 40 }),
      node({ nodeId: 'id-pi', site: 'home-raspberry-pi-in-the-hall-closet', rttMs: 4, qps: 30, querySharePercent: 30, restarts: 2 }),
      ...pods,
    ],
  });
  let current = view([
    pod('aaaaa', 'k3s-1', { qps: 20, querySharePercent: 20 }),
    pod('bbbbb', 'k3s-2', { qps: 10, querySharePercent: 10, cacheHitPercent: 55 }),
    pod('ccccc', 'k3s-2', { up: false, qps: 0, querySharePercent: null }),
  ]);
  await page.route('**/api/v1/cluster', (route) => route.fulfill({ json: current }));
  await page.goto('/#/cluster');
  const topo = page.getByTestId('cluster-topology');
  await expect(topo.getByTestId('topology-site')).toHaveCount(2);
  await expect(topo.getByTestId('topology-node')).toHaveCount(2); // controller and Pi
  await expect(topo.getByTestId('topology-pod')).toHaveCount(3);
  await expect(topo).toContainText('node k3s-1 · 1 pod');
  await expect(topo).toContainText('node k3s-2 · 2 pods');
  await expect(topo).toContainText('4 ms'); // the Pi's round trip, measured by this node
  // Long pod and site names are shortened in the middle to fit (the full name is in the tooltip).
  await expect(topo.getByTestId('topology-node').first()).toContainText(/telltale.*….*-8j9h9/);
  await expect(topo.getByTestId('topology-site').nth(1).locator('text').first()).toHaveText(/^home-.*….*closet$/);
  await expect(topo.locator('.pod.bad')).toHaveCount(1);
  await expect(topo.locator('path.link.bad')).toHaveCount(1); // the k3s-2 group has a pod down

  // Selecting a pod opens its site in the table and highlights its row.
  await topo.getByRole('button', { name: /telltale-resolver-bbbbb/ }).click();
  const row = page.locator('#node-id-bbbbb');
  await expect(row).toHaveClass(/selected/);
  await expect(row).toContainText('telltale-resolver-bbbbb on k3s-2');
  await expect(row).toContainText('10.0% of queries');
  await expect(row).toContainText('cache: 55.0% hits');
  await expect(page.locator('#node-id-pi')).toContainText('2 restarts');

  // Updates with the page (every 5 s): 8 pods on one node fold into 5 + "+3".
  current = view(Array.from({ length: 8 }, (_, i) => pod(`p${i}xxx`, 'k3s-1')));
  await expect(topo.getByTestId('topology-pod')).toHaveCount(6, { timeout: 10_000 });
  await expect(topo).toContainText('+3');
  await expect(topo).toContainText('node k3s-1 · 8 pods');
  await page.unroute('**/api/v1/cluster');
});

// REQ: DNS-006, API-005 (T6.13) — the cache: a cached answer shows up in a lookup (the UI
// card and the API), a flush removes it and says how many, and viewers can look but not flush.
test('dns_006 cache lookup and flush', async () => {
  await query('www.cache.e2e.test'); // routed to the stub upstream (server.mjs)
  const r = page.request;
  await expect
    .poll(async () => (await (await r.get('/api/v1/cache/lookup?name=www.cache.e2e.test')).json()).entries.length, {
      timeout: 10_000,
    })
    .toBeGreaterThan(0);
  await page.goto('/#/settings?tab=system');
  const card = page.getByTestId('cache-card');
  await card.getByRole('textbox', { name: 'Name to look up' }).fill('www.cache.e2e.test');
  await card.getByRole('button', { name: 'Look up' }).click();
  await expect(card.getByTestId('cache-entries')).toContainText('NOERROR');
  await card.getByRole('button', { name: 'Flush this name' }).click();
  await expect(card.getByTestId('cache-flushed')).toContainText(/Removed [1-9]/);
  await expect(card).toContainText('Nothing cached for');
  const stats = await (await r.get('/api/v1/cache/stats')).json();
  expect(stats.items.length).toBe(1);
  // A viewer may look but not flush.
  const viewer = await page.context().browser()!.newContext({ baseURL: page.url().split('/#')[0] });
  const vr = viewer.request;
  const st = await (await vr.get('/api/v1/auth/status')).json();
  const login = await vr.post('/api/v1/auth/login', {
    headers: { 'x-csrf-token': st.csrfToken ?? '' },
    data: { username: VIEWER.user, password: VIEWER.pass },
  });
  expect(login.ok()).toBeTruthy();
  const csrf = (await (await vr.get('/api/v1/auth/status')).json()).csrfToken as string;
  expect((await vr.get('/api/v1/cache/stats')).status()).toBe(200);
  expect((await vr.post('/api/v1/cache/flush', { headers: { 'x-csrf-token': csrf }, data: {} })).status()).toBe(403);
  await viewer.close();
});
