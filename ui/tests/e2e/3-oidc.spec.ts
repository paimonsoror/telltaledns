// REQ: API-004 — T3.6 acceptance: sign in through real Keycloak and Authentik (see
// ../oidc/compose.yml). Runs when OIDC_E2E lists the providers, after 1-ui.spec.ts (which
// creates the local admin). Each test uses a fresh browser context.
import { expect, test, type Page } from '@playwright/test';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { NOTE_RESTORED, cachingBrowser, howShown, noCache, restoresPages } from './bfcache';
import { failOnPageErrors, listen } from './page-errors';

const providers = (process.env.OIDC_E2E ?? '').split(',').filter(Boolean);
test.skip(providers.length === 0, 'set OIDC_E2E=keycloak,authentik with the providers running');
test.describe.configure({ mode: 'serial' });
// A page error on a page a test listens to (the pages of the tests with a test language pack) fails the test.
failOnPageErrors(test);

const USERS = {
  alice: { pass: 'alice-password', role: 'admin' },
  bob: { pass: 'bob-password', role: 'viewer' },
  carol: { pass: 'carol-password', role: '' },
} as const;

async function providerLogin(page: Page, id: string, user: keyof typeof USERS) {
  const pass = USERS[user].pass;
  if (id === 'keycloak') {
    await page.locator('#username').fill(user);
    await page.locator('#password').fill(pass);
    await page.locator('#kc-login').click();
  } else {
    // Authentik: identification, then password (web components; Playwright pierces shadow DOM).
    await page.locator('input[name="uidField"]').fill(user);
    await page.getByRole('button', { name: /^(Continue|Log in)$/ }).click();
    const password = page.getByRole('textbox', { name: 'Password' });
    await password.waitFor({ state: 'visible' });
    await password.fill(pass);
    await page.getByRole('button', { name: 'Continue' }).click();
  }
}

async function signIn(page: Page, id: string, name: string, user: keyof typeof USERS) {
  await page.goto('/#/queries');
  await page.getByRole('link', { name: `Sign in with ${name}` }).click();
  await providerLogin(page, id, user);
}

/** REQ: API-013 (ADR-190) — a test language pack kept in this browser as the card's Use keeps it, for `user` on the
 * server build `commit`: French, the web UI build read from the built page (its one module script, the entry; the
 * build keeps the page gzipped). */
function devpack(user: string, commit: string) {
  const dist = resolve(import.meta.dirname, '../../dist');
  const html = existsSync(join(dist, 'index.html')) ? readFileSync(join(dist, 'index.html'), 'utf8') : gunzipSync(readFileSync(join(dist, 'index.html.gz'))).toString('utf8');
  const modules = [...html.matchAll(/<script\b[^>]*>/g)].map((m) => m[0]).filter((s) => /\btype="module"/.test(s));
  const ui = modules.length === 1 ? (/\bsrc="([^"]+)"/.exec(modules[0])?.[1] ?? '') : '';
  const text = JSON.stringify({ settings: [['Settings', 'Réglages']] });
  const loadedAt = Date.now();
  const sha = createHash('sha256').update(text).digest('hex');
  return { v: 1, ui, server: { commit }, user, loadedAt, expires: loadedAt + 7 * 86_400_000, name: 'fr.json', sha, tag: 'fr', dir: 'ltr', fails: 0, text };
}

/** REQ: API-013 (ADR-190) — the tests with a test language pack run with Keycloak only. What they test of the pack
 * (the page that leaves for the provider is never also reloaded, the page after it is paused, Back) does not depend
 * on the provider: the Keycloak run covers it end to end, and the versions of 9-devpack.spec.ts, whose provider is an
 * address on this server, run everywhere. Two of them also check that the provider's own session is over after its
 * sign-out: Keycloak's sign-out ends it here, and the sign-out of this setup's Authentik provider
 * (`default-provider-invalidation-flow`, ../oidc/authentik-blueprint.yaml) does not. */
const PACK_TESTS =
  'the language pack tests run with Keycloak: the pack does not depend on the provider, the Keycloak run covers it end to end and 9-devpack.spec.ts runs everywhere; the sign-out of this Authentik setup does not end its own session';

for (const id of providers) {
  const name = id === 'keycloak' ? 'Keycloak' : 'Authentik';

  test(`${id}: a mapped admin signs in and lands where they started`, async ({ browser }) => {
    const page = await browser.newPage();
    await signIn(page, id, name, 'alice');
    await expect(page.getByRole('heading', { name: 'Query log' })).toBeVisible({ timeout: 20_000 });
    await expect(page.locator('header .who')).toContainText(/alice/);
    await expect(page.locator('header .who .role')).toHaveText('admin');
    // The account was created on first sign-in and is marked as provider-managed.
    await page.goto('/#/settings?tab=users');
    await expect(page.locator('main table')).toContainText(`signs in with ${id}`);
    // Signing out also signs out at the provider, which returns to TelltaleDNS.
    await page.getByRole('button', { name: 'Sign out' }).click();
    // Keycloak asks "Do you want to log out?" (no id_token_hint is sent; ADR-034).
    const confirm = page.getByRole('button', { name: /^(Logout|Log out)$/i });
    const asked = await confirm
      .waitFor({ state: 'visible', timeout: 8000 })
      .then(() => true)
      .catch(() => false);
    if (asked) await confirm.click();
    // Keycloak returns to TelltaleDNS; Authentik's default flow shows its own "logged out of
    // TelltaleDNS" page instead. Either way the TelltaleDNS session is over.
    await expect(
      page.getByRole('heading', { name: 'Sign in' }).or(page.getByRole('heading', { name: /logged out of TelltaleDNS/ })),
    ).toBeVisible({ timeout: 20_000 });
    await page.goto('/#/');
    await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
    await page.close();
  });

  test(`${id}: groups decide the role`, async ({ browser }) => {
    const page = await browser.newPage();
    await signIn(page, id, name, 'bob');
    await expect(page.locator('header .who .role')).toHaveText('viewer', { timeout: 20_000 });
    await page.close();
  });

  test(`${id}: a user in no mapped group is refused with a reason`, async ({ browser }) => {
    const page = await browser.newPage();
    await signIn(page, id, name, 'carol');
    await expect(page.locator('.provider-error')).toContainText('group', { timeout: 20_000 });
    await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
    await page.close();
  });

  test(`${id}: with a test language pack in use, signing out also signs out at the provider`, async ({ browser }) => {
    // REQ: API-004, API-013 (ADR-190) — the page that leaves for the provider's sign-out is never also reloaded by
    // the pack's code: the provider's page is reached, and signing in again asks for the password.
    test.skip(id !== 'keycloak', PACK_TESTS);
    const page = await browser.newPage();
    listen(page);
    await signIn(page, id, name, 'alice');
    await expect(page.getByRole('heading', { name: 'Query log' })).toBeVisible({ timeout: 20_000 });
    const who = (await (await page.request.get('/api/v1/auth/status')).json()).user.username as string;
    const commit = (await (await page.request.get('/api/v1/system/info')).json()).build.commit as string;
    await page.evaluate(([k, v]) => localStorage.setItem(k, v), ['telltale.devpack', JSON.stringify(devpack(who, commit))]);
    await page.reload();
    await expect(page.locator('html')).toHaveAttribute('lang', 'fr', { timeout: 20_000 });
    await expect(page.getByTestId('devpack-banner')).toContainText('Test language pack: fr.json');
    const here = new URL(page.url()).origin;
    await page.getByRole('button', { name: 'Sign out' }).click();
    await page.waitForURL((u) => u.origin !== here, { timeout: 20_000 });
    const confirm = page.getByRole('button', { name: /^(Logout|Log out)$/i });
    const asked = await confirm
      .waitFor({ state: 'visible', timeout: 8000 })
      .then(() => true)
      .catch(() => false);
    if (asked) await confirm.click();
    await expect(
      page.getByRole('heading', { name: 'Sign in' }).or(page.getByRole('heading', { name: /logged out of TelltaleDNS/ })),
    ).toBeVisible({ timeout: 20_000 });
    // Back on TelltaleDNS: the sign-in page, in English, with the pack paused.
    await page.goto('/#/');
    await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
    await expect(page.locator('html')).toHaveAttribute('lang', 'en');
    await expect(page.getByTestId('devpack-banner')).toContainText('is paused on this page');
    // The provider's session is over: signing in again asks for the password.
    await page.getByRole('link', { name: `Sign in with ${name}` }).click();
    await expect(id === 'keycloak' ? page.locator('#username') : page.locator('input[name="uidField"]')).toBeVisible({ timeout: 20_000 });
    await page.close();
  });

  test(`${id}: with a test language pack in use, a session that ends while signing out still signs out at the provider`, async ({ browser }) => {
    // REQ: API-004, API-013 (ADR-190) — TelltaleDNS's answer to Sign out is held back for a second while a request
    // finds the session gone: nothing reloads meanwhile, and the page then leaves for the provider's sign-out.
    test.skip(id !== 'keycloak', PACK_TESTS);
    const page = await browser.newPage();
    listen(page);
    await signIn(page, id, name, 'alice');
    await expect(page.getByRole('heading', { name: 'Query log' })).toBeVisible({ timeout: 20_000 });
    const who = (await (await page.request.get('/api/v1/auth/status')).json()).user.username as string;
    const commit = (await (await page.request.get('/api/v1/system/info')).json()).build.commit as string;
    await page.evaluate(([k, v]) => localStorage.setItem(k, v), ['telltale.devpack', JSON.stringify(devpack(who, commit))]);
    await page.reload();
    await expect(page.locator('html')).toHaveAttribute('lang', 'fr', { timeout: 20_000 });
    let answer: () => void = () => undefined;
    const answered = new Promise<void>((go) => (answer = go));
    await page.route('**/api/v1/auth/logout', async (r) => {
      const res = await r.fetch();
      await answered;
      await r.fulfill({ response: res });
    });
    let loads = 0;
    page.on('load', () => loads++);
    const here = new URL(page.url()).origin;
    await page.getByRole('button', { name: 'Sign out' }).click();
    await page.route(
      (u) => u.origin === here && u.pathname.startsWith('/api/v1/') && !u.pathname.startsWith('/api/v1/auth/'),
      (r) => r.fulfill({ status: 401, json: { type: 'about:blank', title: 'Unauthorized', status: 401, code: 'unauthorized', detail: 'the session is gone' } }),
    );
    await page.evaluate(() => (location.hash = '#/settings'));
    await page.waitForTimeout(1000);
    expect(loads, 'nothing reloads while the answer waits').toBe(0);
    answer();
    await page.waitForURL((u) => u.origin !== here, { timeout: 20_000 });
    const confirm = page.getByRole('button', { name: /^(Logout|Log out)$/i });
    if (await confirm.waitFor({ state: 'visible', timeout: 8000 }).then(() => true, () => false)) await confirm.click();
    await expect(
      page.getByRole('heading', { name: 'Sign in' }).or(page.getByRole('heading', { name: /logged out of TelltaleDNS/ })),
    ).toBeVisible({ timeout: 20_000 });
    await page.goto('/#/');
    await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
    await expect(page.locator('html')).toHaveAttribute('lang', 'en');
    await page.close();
  });

  test(`${id}: with a test language pack in use, a second sign-out while the first waits still signs out at the provider`, async ({ browser }) => {
    // REQ: API-004, API-013 (ADR-190) — Sign out is clicked twice while TelltaleDNS's answer to the first waits a
    // second, and the provider's page is slow to come: the second click changes nothing, the page reaches the
    // provider's sign-out, and signing in again asks for the password.
    test.skip(id !== 'keycloak', PACK_TESTS);
    const page = await browser.newPage();
    listen(page);
    await signIn(page, id, name, 'alice');
    await expect(page.getByRole('heading', { name: 'Query log' })).toBeVisible({ timeout: 20_000 });
    const who = (await (await page.request.get('/api/v1/auth/status')).json()).user.username as string;
    const commit = (await (await page.request.get('/api/v1/system/info')).json()).build.commit as string;
    await page.evaluate(([k, v]) => localStorage.setItem(k, v), ['telltale.devpack', JSON.stringify(devpack(who, commit))]);
    await page.reload();
    await expect(page.locator('html')).toHaveAttribute('lang', 'fr', { timeout: 20_000 });
    const here = new URL(page.url()).origin;
    let asked = 0;
    await page.route('**/api/v1/auth/logout', async (r) => {
      const first = ++asked === 1;
      const res = await r.fetch();
      await new Promise((go) => setTimeout(go, first ? 1000 : 1500));
      await r.fulfill({ response: res });
    });
    let slowed = false;
    await page.route(
      (u) => u.origin !== here,
      async (r) => {
        if (!slowed && r.request().isNavigationRequest()) {
          slowed = true;
          await new Promise((go) => setTimeout(go, 2000));
        }
        await r.continue().catch(() => undefined);
      },
    );
    const out = page.getByRole('button', { name: 'Sign out' });
    await out.click();
    await out.click();
    await page.waitForURL((u) => u.origin !== here, { timeout: 20_000 });
    const confirm = page.getByRole('button', { name: /^(Logout|Log out)$/i });
    if (await confirm.waitFor({ state: 'visible', timeout: 8000 }).then(() => true, () => false)) await confirm.click();
    await expect(
      page.getByRole('heading', { name: 'Sign in' }).or(page.getByRole('heading', { name: /logged out of TelltaleDNS/ })),
    ).toBeVisible({ timeout: 20_000 });
    expect(asked, 'one sign-out request').toBe(1);
    await page.unrouteAll({ behavior: 'ignoreErrors' });
    await page.goto('/#/');
    await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
    await expect(page.locator('html')).toHaveAttribute('lang', 'en');
    await page.getByRole('link', { name: `Sign in with ${name}` }).click();
    await expect(id === 'keycloak' ? page.locator('#username') : page.locator('input[name="uidField"]')).toBeVisible({ timeout: 20_000 });
    await page.close();
  });

  test(`${id}: with a test language pack in use, back from the provider's sign-out shows no pack`, async () => {
    // REQ: API-004, API-013 (ADR-190) — the page that left for the provider's sign-out was not reloaded. Back from the
    // provider returns to it, and the browser may show it again as it was, from its back-forward cache: it shows the
    // usual language with the pack paused. This test's browser keeps that cache, which the suite's browser turns off:
    // a full Chromium (DVP_FULL_CHROME, or the installed `chromium` channel), else the suite's own browser. A browser
    // that never shows a page again from that cache cannot exercise the fix, and the test says so by skipping.
    test.skip(id !== 'keycloak', PACK_TESTS);
    const { browser: own, note } = await cachingBrowser(test.info().project.use.launchOptions ?? {}, process.env.DVP_FULL_CHROME);
    try {
      const context = await own.newContext({ baseURL: test.info().project.use.baseURL });
      await context.addInitScript(NOTE_RESTORED);
      const page = await context.newPage();
      listen(page);
      // Does this browser show a page of TelltaleDNS again from that cache?
      const probe = await restoresPages(page);
      console.log(`DVP_BFCACHE ${id} probe ${own.version()} ${note}${JSON.stringify(probe)}`);
      test.skip(!probe.restored, noCache(own, note, probe.why));
      await signIn(page, id, name, 'alice');
      await expect(page.getByRole('heading', { name: 'Query log' })).toBeVisible({ timeout: 20_000 });
      const who = (await (await page.request.get('/api/v1/auth/status')).json()).user.username as string;
      const commit = (await (await page.request.get('/api/v1/system/info')).json()).build.commit as string;
      await page.evaluate(([k, v]) => localStorage.setItem(k, v), ['telltale.devpack', JSON.stringify(devpack(who, commit))]);
      await page.reload();
      await expect(page.locator('html')).toHaveAttribute('lang', 'fr', { timeout: 20_000 });
      // The page that will leave: its history entry is marked, so Back is known to have reached it.
      await page.evaluate(() => history.replaceState({ ...history.state, dvpLeft: true }, ''));
      const here = new URL(page.url()).origin;
      await page.getByRole('button', { name: 'Sign out' }).click();
      await page.waitForURL((u) => u.origin !== here, { timeout: 20_000 });
      const confirm = page.getByRole('button', { name: /^(Logout|Log out)$/i });
      if (await confirm.waitFor({ state: 'visible', timeout: 8000 }).then(() => true, () => false)) await confirm.click();
      await expect(
        page.getByRole('heading', { name: 'Sign in' }).or(page.getByRole('heading', { name: /logged out of TelltaleDNS/ })),
      ).toBeVisible({ timeout: 20_000 });
      // Back, through the provider's pages, to the page that left.
      const atLeft = () => page.evaluate(() => !!(history.state as { dvpLeft?: boolean } | null)?.dvpLeft).catch(() => false);
      for (let i = 0; i < 4 && !(await atLeft()); i++) {
        await page.goBack({ waitUntil: 'commit' });
        await page.waitForTimeout(500);
      }
      expect(await atLeft(), 'Back reached the page that left for the provider').toBe(true);
      await expect(page.locator('html')).toHaveAttribute('lang', 'en', { timeout: 15_000 });
      await expect(page.getByTestId('devpack-banner')).toContainText('is paused on this page');
      // The page that left was shown again from the cache (then reloaded): the fix was exercised.
      const back = await howShown(page);
      console.log(`DVP_BFCACHE ${id} back ${own.version()} ${JSON.stringify(back)}`);
      expect(back.restored, 'Back showed the page that left again from the back-forward cache').toBeGreaterThanOrEqual(1);
      await context.close();
    } finally {
      await own.close();
    }
  });
}