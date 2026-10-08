// REQ: DOC-002 — dashboard screenshots for the README and the site, taken on the made-up network
// of demo.toml after run.sh has sent it synthetic traffic. Not part of the e2e suite.
import { test, type Browser } from '@playwright/test';
import { resolve } from 'node:path';

const repo = resolve(import.meta.dirname, '../../..');

async function capture(browser: Browser, theme: 'light' | 'dark', width: number, height: number, scale: number) {
  const context = await browser.newContext({
    baseURL: 'http://127.0.0.1:28053',
    colorScheme: theme,
    viewport: { width, height },
    deviceScaleFactor: scale,
  });
  const page = await context.newPage();
  // The demo's devices are on loopback, which reads as masked client IPs (OPS-003): keep that
  // banner out of the pictures.
  await page.route('**/api/v1/system/info', async (route) => {
    const res = await route.fetch();
    const info = await res.json();
    delete info.clientIpsMasked;
    await route.fulfill({ response: res, json: info });
  });
  await page.goto('/');
  await page.getByLabel('Username', { exact: true }).fill('admin');
  await page.getByLabel('Password', { exact: true }).fill('correct horse battery');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.getByRole('heading', { name: 'Dashboard' }).waitFor();
  await page.getByRole('button', { name: '15 min' }).click();
  await page.waitForTimeout(3000);
  return { page, context };
}

for (const theme of ['light', 'dark'] as const) {
  test(`dashboard ${theme}`, async ({ browser }) => {
    // The README: sharp on high-density screens.
    const readme = await capture(browser, theme, 1280, 900, 1.5);
    await readme.page.screenshot({ path: `${repo}/docs/images/dashboard-${theme}.jpg`, type: 'jpeg', quality: 82 });
    await readme.context.close();
    // The site: the same size as its other screenshots (2-shots.spec.ts).
    const site = await capture(browser, theme, 1280, 860, 1);
    await site.page.screenshot({ path: `${repo}/site/assets/shots/dashboard-${theme}.jpg`, type: 'jpeg', quality: 80 });
    await site.context.close();
  });
}
