// REQ: FLT-005, FLT-006 (ADR-183, GitHub issue #95) — the quick rule form in the query log's Why? drawer. When its Device field
// holds a bare address and a router (this node's, or another full cluster member's) reports one MAC address for it, the form
// suggests naming the device by that MAC, so rules follow it, and opens the naming dialog with the MAC chosen; once the device is
// named, the field holds its name. A MAC only this server's neighbor table holds, one several addresses share, and a recognition
// the server leaves out (query-log privacy level 2 and above) or a MAC it withholds (a caller who may not read the devices) give no
// hint, as the naming dialog itself doesn't start from such a MAC. A one-node test server has no router, so the explanation and the
// identity read are the real answers with their MAC fields stubbed; the row in the log is a real query. Each test that checks for
// no hint first shows the hint for the same address, or checks that the identity read was answered (the form renders only after
// it), so the absence is a decision and not data that never arrived. Some guards pin behaviour another branch of the form already
// decides (a pod's row). Expects the state 1-ui.spec.ts leaves (the admin), as 5-each-keys.spec.ts does.
import { expect, test, type Page } from '@playwright/test';
import { query } from './dns';
import { failOnPageErrors } from './page-errors';

failOnPageErrors(test);
test.use({ viewport: { width: 1280, height: 900 } });

const ADMIN = { user: 'admin', pass: 'correct horse battery' };
/** A loopback address no other test uses, and a name answered locally (no upstream, no list needed). */
const ADDR = '127.0.0.71';
const NAME = 'nas.e2e.test';
const MAC = '02:00:00:00:00:71';
const HINT = 'name the device by its MAC address to make rules follow it';

type Recognition = { identifiedBy: string; mac?: string; macFrom?: string; macShared?: boolean } | null;
/** What the node says about the address: its recognition (null: left out), or a failed read. */
type Stub = Recognition | 'error';

async function signIn(page: Page) {
  await page.goto('/');
  await page.getByLabel('Username', { exact: true }).fill(ADMIN.user);
  await page.getByLabel('Password', { exact: true }).fill(ADMIN.pass);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Dashboard' }).first()).toBeVisible({ timeout: 30_000 });
}

/** A row for `addr` in the log: asked once, then read back (the log is read from flushed files, a second behind). */
async function ensureRow(page: Page, addr = ADDR) {
  const has = async () => ((await (await page.request.get(`/api/v1/queries?client=${addr}&name=${NAME}&match=exact&from=-1h&limit=1`)).json()).items ?? []).length > 0;
  if (await has()) return;
  await query(NAME, 1, 15354, addr);
  await expect.poll(has, { timeout: 20_000 }).toBe(true);
}

/**
 * The explanation and the identity read of `addr`, as a node whose router reports `stub()` would answer them: the real answers with
 * the MAC fields replaced. Returns how many identity reads were answered.
 */
async function stubRecognition(page: Page, stub: () => Stub, addr = ADDR) {
  let identities = 0;
  await page.route(`**/api/v1/clients/${addr}/identity`, async (route) => {
    identities++;
    const s = stub();
    if (s === 'error') {
      await route.fulfill({ status: 500, contentType: 'application/problem+json', json: { title: 'stubbed failure', status: 500 } });
      return;
    }
    const body = await (await route.fetch()).json();
    if (s) body.recognition = s;
    else delete body.recognition;
    await route.fulfill({ status: 200, contentType: 'application/json', json: body });
  });
  await page.route('**/api/v1/explain**', async (route) => {
    const body = await (await route.fetch()).json();
    const s = stub();
    delete body.client.device;
    if (s && s !== 'error' && s.mac) {
      body.client.mac = s.mac;
      body.client.macFrom = s.macFrom;
    } else {
      delete body.client.mac;
      delete body.client.macFrom;
    }
    await route.fulfill({ status: 200, contentType: 'application/json', json: body });
  });
  return () => identities;
}

/** The Why? drawer of `addr`'s row, open, with its quick rule form shown (with `bare`: checked to be the form for a bare address). */
async function whyDrawer(page: Page, addr = ADDR, bare = addr === ADDR) {
  await page.goto(`/#/queries?client=${addr}&name=${NAME}&match=exact`);
  const why = page.getByRole('button', { name: 'Why?' }).first();
  await expect(async () => {
    await page.reload();
    await expect(why).toBeVisible({ timeout: 2000 });
  }).toPass({ timeout: 20_000 });
  await why.click();
  const form = page.getByTestId('quick-rule-form');
  await expect(form).toBeVisible();
  if (bare) {
    await expect(deviceField(form)).toHaveValue(addr);
    // The pre-fill's own sentence is there: the form is the one for a bare address.
    await expect(form.getByTestId('quick-rule-seen-as')).toContainText('A rule for an address stops matching when the address changes');
  }
  return form;
}
const deviceField = (form: ReturnType<Page['getByTestId']>) => form.getByRole('combobox', { name: 'Device', exact: true });

const router = (from: 'router' | 'peer'): Recognition => ({ identifiedBy: 'cidr', mac: MAC, macFrom: from, macShared: false });

/** The drawer of the same row opened again (with what the stub says now), once the identity read for it was answered. */
async function reopen(page: Page, identities: () => number) {
  await page.keyboard.press('Escape');
  await expect(page.getByTestId('quick-rule-form')).toHaveCount(0);
  const before = identities();
  const form = await whyDrawer(page);
  expect(identities(), 'the drawer read the identity of the address').toBeGreaterThan(before);
  return form;
}

test('flt_005 the quick rule form suggests naming the device by its MAC when a router knows it', async ({ page }) => {
  await signIn(page);
  await ensureRow(page);
  const identities = await stubRecognition(page, () => router('router'));
  const csrf = (await (await page.request.get('/api/v1/auth/status')).json()).csrfToken as string;
  const rules = async () => (await (await page.request.get('/api/v1/rules')).json()).items as unknown[];
  const rulesBefore = await rules();
  try {
    const form = await whyDrawer(page);
    const hint = form.getByTestId('quick-rule-mac-hint');
    await expect(hint).toContainText(HINT);
    await expect(hint).toContainText(MAC);
    expect(identities(), 'the drawer read the identity of the address').toBeGreaterThan(0);
    // The hint opens the naming dialog, which starts from the router's MAC (a new device, a MAC at this address alone).
    await hint.getByRole('button', { name: 'Name this device…', exact: true }).click();
    const dialog = page.getByRole('dialog', { name: 'Name this device', exact: true });
    await expect(dialog).toBeVisible();
    await expect(dialog.getByTestId('recognize-by')).toBeVisible();
    await expect(dialog.getByRole('radio', { name: /^Its MAC address/ })).toBeChecked();
    await expect(dialog).toContainText(MAC);
    await dialog.getByLabel('Name', { exact: true }).fill('e2e-mac-hint');
    await dialog.getByRole('button', { name: 'Save', exact: true }).click();
    await expect(dialog.getByRole('status').filter({ hasText: 'Saved.' })).toBeVisible();
    const saved = (await (await page.request.get('/api/v1/clients')).json()).items.find((c: { name: string }) => c.name === 'e2e-mac-hint');
    expect(saved?.match, 'named by the MAC alone').toEqual([MAC]);
    // The dialog's own Close button (its header's ✕ is labelled Close too).
    await dialog.getByRole('button', { name: 'Close', exact: true }).filter({ hasText: 'Close' }).click();
    await expect(dialog).toHaveCount(0);
    // Back in the form: the rule is for the device's name now, and the address's advice is gone.
    await expect(form.getByRole('combobox', { name: 'Device', exact: true })).toHaveValue('e2e-mac-hint');
    await expect(form.getByTestId('quick-rule-mac-hint')).toHaveCount(0);
    // The form still says which device the address is: the one just named.
    await expect(form.getByTestId('quick-rule-seen-as')).toContainText(`${ADDR} is your device “e2e-mac-hint”.`);
    // Nothing in the dialog submitted the rule form: no rule was made.
    expect(await rules()).toEqual(rulesBefore);
  } finally {
    await page.unroute(`**/api/v1/clients/${ADDR}/identity`);
    await page.unroute('**/api/v1/explain**');
    await page.request.delete('/api/v1/clients/e2e-mac-hint', { headers: { 'x-csrf-token': csrf } });
  }
});

test('flt_005 no MAC hint without a router MAC or with a shared MAC', async ({ page }) => {
  await signIn(page);
  await ensureRow(page);
  let next: Stub = router('peer');
  const identities = await stubRecognition(page, () => next);
  try {
    // Another cluster member's router counts like this node's: the hint is there.
    const form = await whyDrawer(page);
    await expect(form.getByTestId('quick-rule-mac-hint')).toContainText(HINT);
    // A MAC only this server's neighbor table holds: other servers, Docker or Kubernetes wouldn't recognize the device by it.
    next = { identifiedBy: 'cidr', mac: MAC, macFrom: 'neighbor', macShared: false };
    let again = await reopen(page, identities);
    await expect(again.getByTestId('quick-rule-mac-hint')).toHaveCount(0);
    // A router's MAC at more than one address (a range extender or bridge): it tells no device apart.
    next = { identifiedBy: 'cidr', mac: MAC, macFrom: 'router', macShared: true };
    again = await reopen(page, identities);
    await expect(again.getByTestId('quick-rule-mac-hint')).toHaveCount(0);
    // No MAC known for the address at all.
    next = { identifiedBy: 'cidr' };
    again = await reopen(page, identities);
    await expect(again.getByTestId('quick-rule-mac-hint')).toHaveCount(0);
  } finally {
    await page.unroute(`**/api/v1/clients/${ADDR}/identity`);
    await page.unroute('**/api/v1/explain**');
  }
});

test('flt_005 no MAC hint when recognition is withheld', async ({ page }) => {
  await signIn(page);
  await ensureRow(page);
  let next: Stub = router('router');
  const identities = await stubRecognition(page, () => next);
  try {
    const form = await whyDrawer(page);
    await expect(form.getByTestId('quick-rule-mac-hint')).toContainText(HINT);
    // Query-log privacy level 2 and above: the identity has no recognition at all.
    next = null;
    let again = await reopen(page, identities);
    await expect(again.getByTestId('quick-rule-mac-hint')).toHaveCount(0);
    // A caller who may not read the devices: the recognition without its MAC fields.
    next = { identifiedBy: 'cidr' };
    again = await reopen(page, identities);
    await expect(again.getByTestId('quick-rule-mac-hint')).toHaveCount(0);
    // The read fails: no hint, and the form is still there.
    next = 'error';
    again = await reopen(page, identities);
    await expect(again.getByTestId('quick-rule-mac-hint')).toHaveCount(0);
  } finally {
    await page.unroute(`**/api/v1/clients/${ADDR}/identity`);
    await page.unroute('**/api/v1/explain**');
  }
});

// The MAC belongs to this address: another address or a name typed into Device has no hint, and the address typed back has it again.
test('flt_005 the MAC hint goes when the Device field holds another address or a name', async ({ page }) => {
  await signIn(page);
  await ensureRow(page);
  await stubRecognition(page, () => router('router'));
  try {
    const form = await whyDrawer(page);
    const hint = form.getByTestId('quick-rule-mac-hint');
    await expect(hint).toContainText(HINT);
    await deviceField(form).fill('127.0.0.72');
    await expect(hint).toHaveCount(0);
    await deviceField(form).fill('some-device');
    await expect(hint).toHaveCount(0);
    await deviceField(form).fill(ADDR);
    await expect(hint).toContainText(HINT);
  } finally {
    await page.unroute(`**/api/v1/clients/${ADDR}/identity`);
    await page.unroute('**/api/v1/explain**');
  }
});

// The MAC is shown as the naming dialog shows it (lower case, colons), whatever spelling the router gave.
test('flt_005 the MAC hint shows the MAC normalized', async ({ page }) => {
  await signIn(page);
  await ensureRow(page);
  await stubRecognition(page, () => ({ identifiedBy: 'cidr', mac: '02-00-00-00-00-7A', macFrom: 'router', macShared: false }));
  try {
    const hint = (await whyDrawer(page)).getByTestId('quick-rule-mac-hint');
    await expect(hint).toContainText(HINT);
    await expect(hint).toContainText('02:00:00:00:00:7a');
    await expect(hint).not.toContainText('02-00-00-00-00-7A');
  } finally {
    await page.unroute(`**/api/v1/clients/${ADDR}/identity`);
    await page.unroute('**/api/v1/explain**');
  }
});

// A pod's address changes whenever it restarts, so a router's MAC for it is no advice: the fixture's jellyfin pod (127.0.0.81).
test('flt_005 no MAC hint for a Kubernetes pod address', async ({ page }) => {
  const POD = '127.0.0.81';
  await signIn(page);
  await ensureRow(page, POD);
  await expect
    .poll(async () => (await (await page.request.get(`/api/v1/explain?name=${NAME}&client=${POD}`)).json()).client.workload?.name ?? null, { timeout: 20_000 })
    .toBe('media/deploy/jellyfin');
  const identities = await stubRecognition(page, () => router('router'), POD);
  try {
    const form = await whyDrawer(page, POD);
    await expect(form.getByTestId('quick-rule-seen-as')).toContainText('media/deploy/jellyfin');
    expect(identities(), 'the drawer read the identity of the address').toBeGreaterThan(0);
    await expect(form.getByTestId('quick-rule-mac-hint')).toHaveCount(0);
  } finally {
    await page.unroute(`**/api/v1/clients/${POD}/identity`);
    await page.unroute('**/api/v1/explain**');
  }
});

// A name in the log shaped like a pod's (namespace/kind/name) that this node doesn't know as one: the form advises the group, not a MAC.
test('flt_005 no MAC hint for a name shaped like a pod', async ({ page }) => {
  await signIn(page);
  await ensureRow(page);
  const identities = await stubRecognition(page, () => router('router'));
  await page.route('**/api/v1/queries?**', async (route) => {
    const body = await (await route.fetch()).json();
    for (const row of body.items ?? []) if (row.client === ADDR) row.clientName = 'media/deploy/ghost';
    await route.fulfill({ status: 200, contentType: 'application/json', json: body });
  });
  try {
    const form = await whyDrawer(page, ADDR, false);
    await expect(deviceField(form)).toHaveValue(ADDR);
    await expect(form.getByTestId('quick-rule-seen-as')).toContainText('This looks like a Kubernetes pod');
    expect(identities(), 'the drawer read the identity of the address').toBeGreaterThan(0);
    await expect(form.getByTestId('quick-rule-mac-hint')).toHaveCount(0);
  } finally {
    await page.unroute(`**/api/v1/clients/${ADDR}/identity`);
    await page.unroute('**/api/v1/explain**');
    await page.unroute('**/api/v1/queries?**');
  }
});

// Editing a rule (the Quick rules page) gives no hint: the form there edits the rule as it is, and is given the rule alone (no
// address, no MAC). The control comes first, in the same test: with the same stubs, the Why? drawer of the rule's address has the
// hint. So an edit form that showed the hint for that address (given the address and the MAC, without the form's own "not when
// editing" check) fails here.
test('flt_005 no MAC hint when editing a rule', async ({ page }) => {
  await signIn(page);
  await ensureRow(page);
  await stubRecognition(page, () => router('router'));
  const csrf = (await (await page.request.get('/api/v1/auth/status')).json()).csrfToken as string;
  const put = await page.request.put('/api/v1/rules/e2e-mac-edit', {
    headers: { 'x-csrf-token': csrf },
    data: { action: 'allow', domain: 'mac-edit.e2e.test', devices: [ADDR], forMinutes: 60 },
  });
  expect(put.status()).toBe(200);
  try {
    const drawer = await whyDrawer(page);
    await expect(drawer.getByTestId('quick-rule-mac-hint')).toContainText(HINT);
    await page.keyboard.press('Escape');
    await expect(page.getByTestId('quick-rule-form')).toHaveCount(0);
    await page.goto('/#/rules');
    await page.getByTestId('rules-table').getByRole('row').filter({ hasText: 'mac-edit.e2e.test' }).getByRole('button', { name: 'Edit' }).click();
    const form = page.getByTestId('quick-rule-edit-form');
    await expect(deviceField(form)).toHaveValue(ADDR);
    await expect(page.getByTestId('quick-rule-mac-hint')).toHaveCount(0);
  } finally {
    await page.unroute(`**/api/v1/clients/${ADDR}/identity`);
    await page.unroute('**/api/v1/explain**');
    await page.request.delete('/api/v1/rules/e2e-mac-edit', { headers: { 'x-csrf-token': csrf } });
  }
});
