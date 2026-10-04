// Screenshots of the main pages for the site (T4.7, DOC-002), written to site/assets/shots/ as
// JPEG. Regenerate with `SHOTS=1 npx playwright test` (after 1-ui.spec.ts); skipped
// otherwise. Expects the state left by ui.spec.ts (admin `admin`, some traffic).
import { test } from '@playwright/test';
import { resolve } from 'node:path';

const shot = (name: string) => resolve(import.meta.dirname, '../../../site/assets/shots', `${name}.jpg`);

test.skip(!process.env.SHOTS, 'set SHOTS=1 to capture screenshots');

for (const theme of ['light', 'dark'] as const) {
  test(`screenshots (${theme})`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: theme });
    await page.setViewportSize({ width: 1280, height: 860 });
    // Every e2e query comes from 127.0.0.1, which reads as masked client IPs (OPS-003); keep
    // that banner out of the pictures.
    await page.route('**/api/v1/system/info', async (route) => {
      const res = await route.fetch();
      const info = await res.json();
      delete info.clientIpsMasked;
      await route.fulfill({ response: res, json: info });
    });
    await page.goto('/');
    await page.getByLabel('Username').fill('admin');
    await page.getByLabel('Password').fill('correct horse battery');
    await page.getByRole('button', { name: 'Sign in' }).click();
    for (const [name, path] of [
      ['dashboard', '/#/'],
      ['queries', '/#/queries'],
      ['lists', '/#/lists'],
      ['settings', '/#/settings?tab=tokens'],
    ]) {
      await page.goto(path);
      // The test server is minutes old: the 15-minute range shows its traffic.
      if (name === 'dashboard') await page.getByRole('button', { name: '15 min' }).click();
      await page.waitForTimeout(600);
      await page.screenshot({ path: shot(`${name}-${theme}`), type: 'jpeg', quality: 80 });
    }
    // "Why?" on a blocked query: it names the list and the rule.
    await page.goto('/#/queries?status=blocked');
    await page.getByRole('button', { name: 'Why?' }).first().click();
    await page.waitForTimeout(400);
    await page.screenshot({ path: shot(`why-${theme}`), type: 'jpeg', quality: 80 });
  });
}
