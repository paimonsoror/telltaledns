// REQ: API-005 — an exception a page does not catch (a page error) fails the test that met it, as in 1-ui.spec.ts: a spec file
// calls `failOnPageErrors(test)` once, and every test's own page is listened to; a page a test opens itself (in a browser
// context of its own) is listened to with `listen(page)`. Each error is kept with the page's address and its stack.
import { expect, type Page, type test as playwrightTest } from '@playwright/test';

const errors: string[] = [];

/** Keeps the page errors of `page` until the end of the running test. */
export function listen(page: Page) {
  page.on('pageerror', (e) => errors.push(`page error at ${page.url()}: ${e.stack || e.message}`));
}

export function failOnPageErrors(test: typeof playwrightTest) {
  test.beforeEach(({ page }) => {
    errors.length = 0;
    listen(page);
  });
  test.afterEach(() => {
    expect(errors, 'no page errors').toEqual([]);
  });
}
