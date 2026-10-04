// REQ: API-003, API-005 — the UI end to end against a real server: first-run setup, the
// dashboard, the query log and "Why?", explain, tokens, users and roles, sign-out/in, and a
// phone-width layout. Any CSP violation or page error fails the suite.
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
  await page.getByLabel('Username').fill(user);
  await page.getByLabel('Password').fill(pass);
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

test('explain page', async () => {
  await page.goto('/#/explain?name=nas.e2e.test&client=127.0.0.1');
  await expect(page.locator('.explain')).toContainText('local');
  await page.getByLabel('Name').fill('ads.e2e.test');
  await page.getByRole('button', { name: 'Explain' }).click();
  await expect(page.locator('.explain')).toContainText('blocked');
});

test('lists, groups, clients, upstreams, local DNS render', async () => {
  for (const [path, text] of [
    ['/#/lists', 'e2e-block'],
    ['/#/groups', 'default'],
    ['/#/clients', '127.0.0.1'],
    ['/#/upstreams', 'nowhere'],
    ['/#/local-dns', '[[record]]'],
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
  await page.getByLabel('Username').fill(VIEWER.user);
  await page.getByLabel('Password').fill(VIEWER.pass);
  await page.getByRole('button', { name: 'Add', exact: true }).click();
  await expect(page.locator('main table')).toContainText(VIEWER.user);

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
