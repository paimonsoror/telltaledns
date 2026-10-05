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
  await page.getByRole('textbox', { name: 'Name' }).fill('ads.e2e.test');
  await page.getByRole('button', { name: 'Explain' }).click();
  await expect(page.locator('.explain')).toContainText('blocked');
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
