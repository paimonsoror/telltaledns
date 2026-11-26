// REQ: API-012 (ADR-189) — languages in the web UI, in the browser against the real server: an
// English reader downloads nothing but the core, and `?lang=` applies to one page load and stores
// nothing. Expects the state 1-ui.spec.ts leaves (the admin `admin`, some queries in the log), as
// 2-shots.spec.ts does. (The parts that need no browser are 7-i18n.spec.ts.)
import { expect, test, type Page } from '@playwright/test';

const ADMIN = { user: 'admin', pass: 'correct horse battery' };
// The core: files directly under /assets/, of these kinds. No subfolder (assets/locales/), no JSON.
const CORE = /^\/assets\/[^/]+\.(js|css|svg|png|woff2)$/;

async function signIn(page: Page) {
  await page.goto('/');
  await page.getByLabel('Username', { exact: true }).fill(ADMIN.user);
  await page.getByLabel('Password', { exact: true }).fill(ADMIN.pass);
  await page.getByRole('button', { name: 'Sign in' }).click();
  // As 1-ui.spec.ts finds it: the heading's accessible name holds more than the word (and Argon2 is slow).
  await expect(page.getByRole('heading', { name: 'Dashboard' }).first()).toBeVisible({ timeout: 30_000 });
}

test('api_012 an english session requests only core assets', async ({ page }) => {
  const assets: string[] = [];
  page.on('request', (r) => {
    const path = new URL(r.url()).pathname;
    if (path.startsWith('/assets/')) assets.push(path);
  });
  await signIn(page);
  for (const [path, heading] of [
    ['/#/', 'Dashboard'],
    ['/#/queries', 'Query log'],
    ['/#/settings', 'Settings'],
  ]) {
    await page.goto(path);
    await expect(page.getByRole('heading', { name: heading }).first()).toBeVisible();
  }
  await expect(page.locator('html')).toHaveAttribute('lang', 'en');
  expect(assets.length, 'the page loaded its assets').toBeGreaterThan(0);
  expect(assets.filter((p) => !CORE.test(p))).toEqual([]);
});

test('api_012 lang parameter applies to one page load and stores nothing', async ({ page }) => {
  await signIn(page);
  const rows = page.locator('table.log tbody tr');
  const storage = () => page.evaluate(() => ({ local: { ...localStorage }, session: { ...sessionStorage } }));
  await page.goto('/#/queries');
  await expect(rows.first()).toBeVisible();
  await expect(page.locator('html')).toHaveAttribute('lang', 'en');
  const before = await storage();
  // This page load is the pseudo-locale: the formats' messages are accented ("ms" -> "ɱš").
  await page.goto('/?lang=en-XA#/queries');
  await expect(page.locator('html')).toHaveAttribute('lang', 'en-XA');
  await expect(page.locator('html')).toHaveAttribute('data-i18n-early', '0');
  await expect(rows.first()).toContainText('š');
  expect(await storage()).toEqual(before);
  // The next load without it is English again, and nothing was kept.
  await page.goto('/#/queries');
  await expect(page.locator('html')).toHaveAttribute('lang', 'en');
  await expect(rows.first()).toBeVisible();
  expect(await page.locator('table.log').innerText()).not.toContain('š');
  expect(await storage()).toEqual(before);
  // A language that has no catalog: English, and nothing stored either.
  await page.goto('/?lang=zh-Hans#/queries');
  await expect(page.locator('html')).toHaveAttribute('lang', 'en');
  await expect(rows.first()).toBeVisible();
  expect(await storage()).toEqual(before);
});

// A count of 0, 1 and 2 on pages whose text comes from tn(): the English plural rule gives `0 answers`,
// `1 answer`, `2 answers` whatever language the browser asks for (French counts 0 as one; Japanese has one
// form; Russian has few and many).
test('api_012 english plurals ignore the browser language', async ({ browser }) => {
  const baseURL = test.info().project.use.baseURL;
  const lookup = { name: 'i18n.example', entries: [0, 1, 2].map((answers) => ({ ageSeconds: 1, answers, authentic: false, bytes: 90, checkingDisabled: false, dnssecOk: false, hits: 2, node: null, qtype: 'A', rcode: 'NOERROR', ttlLeftSeconds: 30 })) };
  const plan = (i: number) => ({ id: `p-${i}`, state: 'pending', summary: 's', tool: 't', method: 'POST', path: '/api/v1/rules', reason: 'r', requestedBy: 'agent', needsApproval: true, preview: {}, configVersion: 1, createdUnixSeconds: 0, expiresUnixSeconds: 0 });
  const read: Record<string, string[]> = {};
  for (const locale of ['en-US', 'fr-FR', 'ja-JP', 'ru-RU']) {
    const context = await browser.newContext({ baseURL, locale });
    const page = await context.newPage();
    let removed = [0, 1, 2];
    let waiting = 1;
    await page.route('**/api/v1/cache/lookup?**', (r) => r.fulfill({ json: lookup }));
    await page.route('**/api/v1/cache/flush', (r) => r.fulfill({ json: { totalRemoved: removed.shift() ?? 2, nodes: [] } }));
    await page.route('**/api/v1/plans', (r) => r.fulfill({ json: { items: Array.from({ length: waiting }, (_, i) => plan(i)) } }));
    await signIn(page);
    // The agent inbox of the header: one and two changes.
    const inbox = page.getByTestId('agent-inbox');
    const pill: string[] = [];
    for (const n of [1, 2]) {
      waiting = n;
      await page.reload();
      await expect(inbox).toBeVisible();
      await expect(inbox).toContainText(`${n} agent change`);
      pill.push((await inbox.innerText()).trim());
    }
    // The cache card: three answers counts in one lookup, then three flushes that removed 0, 1 and 2 entries.
    await page.goto('/#/cache');
    const card = page.getByTestId('cache-card');
    await card.locator('form input').fill('i18n.example');
    await card.locator('form button').click();
    await expect(page.getByTestId('cache-entries')).toBeVisible();
    const answers = (await page.locator('[data-testid="cache-entries"] tbody tr td:nth-child(3)').allInnerTexts()).map((s) => s.trim());
    const flushed: string[] = [];
    for (let i = 0; i < 3; i++) {
      await card.locator('div.row button').first().click();
      await expect(page.getByTestId('cache-flushed')).toContainText(`Removed ${i} `);
      flushed.push((await page.getByTestId('cache-flushed').innerText()).trim());
    }
    await expect(page.locator('html')).toHaveAttribute('lang', 'en');
    read[locale] = [...pill, ...answers, ...flushed];
    await context.close();
  }
  const english = ['1 agent change to review', '2 agent changes to review', 'NOERROR · 0 answers', 'NOERROR · 1 answer', 'NOERROR · 2 answers', 'Removed 0 entries.', 'Removed 1 entry.', 'Removed 2 entries.'];
  for (const [locale, texts] of Object.entries(read)) expect(texts, locale).toEqual(english);
});
