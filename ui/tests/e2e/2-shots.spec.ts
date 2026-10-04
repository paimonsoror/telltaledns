// Screenshots of the main pages, for docs and the site (T4.7). Run with SHOTS=1; skipped
// otherwise. Expects the state left by ui.spec.ts (admin `admin`, some traffic).
import { test } from '@playwright/test';

test.skip(!process.env.SHOTS, 'set SHOTS=1 to capture screenshots');

for (const theme of ['light', 'dark'] as const) {
  test(`screenshots (${theme})`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: theme });
    await page.setViewportSize({ width: 1280, height: 860 });
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
      await page.waitForTimeout(600);
      await page.screenshot({ path: `test-results/shots/${name}-${theme}.png`, fullPage: true });
    }
    await page.goto('/#/queries');
    await page.getByRole('button', { name: 'Why?' }).first().click();
    await page.waitForTimeout(400);
    await page.screenshot({ path: `test-results/shots/why-${theme}.png` });
  });
}
