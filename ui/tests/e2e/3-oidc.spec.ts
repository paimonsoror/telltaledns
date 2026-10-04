// REQ: API-004 — T3.6 acceptance: sign in through real Keycloak and Authentik (see
// ../oidc/compose.yml). Runs when OIDC_E2E lists the providers, after 1-ui.spec.ts (which
// creates the local admin). Each test uses a fresh browser context.
import { expect, test, type Page } from '@playwright/test';

const providers = (process.env.OIDC_E2E ?? '').split(',').filter(Boolean);
test.skip(providers.length === 0, 'set OIDC_E2E=keycloak,authentik with the providers running');
test.describe.configure({ mode: 'serial' });

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

for (const id of providers) {
  const name = id === 'keycloak' ? 'Keycloak' : 'Authentik';

  test(`${id}: a mapped admin signs in and lands where they started`, async ({ browser }) => {
    const page = await browser.newPage();
    await signIn(page, id, name, 'alice');
    await expect(page.getByRole('heading', { name: 'Query log' })).toBeVisible({ timeout: 20_000 });
    await expect(page.locator('header .who')).toContainText(/alice/);
    await expect(page.locator('header .who .badge')).toHaveText('admin');
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
    await expect(page.locator('header .who .badge')).toHaveText('viewer', { timeout: 20_000 });
    await page.close();
  });

  test(`${id}: a user in no mapped group is refused with a reason`, async ({ browser }) => {
    const page = await browser.newPage();
    await signIn(page, id, name, 'carol');
    await expect(page.locator('.provider-error')).toContainText('group', { timeout: 20_000 });
    await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
    await page.close();
  });
}