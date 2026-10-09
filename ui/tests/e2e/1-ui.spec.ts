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
  const welcome = page.getByRole('heading', { name: 'Welcome to TelltaleDNS' });
  const signInHeading = page.getByRole('heading', { name: 'Sign in' });
  await expect(welcome.or(signInHeading)).toBeVisible();
  if (await signInHeading.isVisible()) {
    // A CI retry: the first attempt created the admin and then timed out (a stalled runner).
    // Sign in as that admin so the serial suite doesn't fail in a cascade.
    await signIn(ADMIN.user, ADMIN.pass);
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible({ timeout: 30_000 });
    return;
  }
  const token = readFileSync(resolve(import.meta.dirname, '../../.e2e/data/setup-token'), 'utf8').trim();
  await page.getByLabel('Setup token').fill(token);
  await page.getByLabel('Admin username').fill(ADMIN.user);
  await page.getByLabel('Password (at least 10 characters)').fill(ADMIN.pass);
  await page.getByLabel('Repeat password').fill(ADMIN.pass);
  await page.getByRole('button', { name: 'Create admin and sign in' }).click();
  // Creating the admin hashes its password (Argon2) and loads the dashboard for the first time.
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible({ timeout: 30_000 });
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
    await expect(page.getByRole('link', { name: 'ads.e2e.test', exact: true }).first()).toBeVisible({ timeout: 2000 });
  }).toPass({ timeout: 20_000 });
  await expect(page.getByText('Queries by status')).toBeVisible();
  // Every chart has a table view.
  await page.getByRole('button', { name: 'Table' }).first().click();
  await expect(page.locator('.table-view table').first()).toBeVisible();
  // "Where time goes": each path explains itself on hover (and keyboard focus).
  const local = page.getByRole('button', { name: 'local/udp' });
  await local.hover();
  await expect(page.getByRole('tooltip').filter({ hasText: 'names on your network' })).toBeVisible();
  await expect(local).toHaveAccessibleDescription(/names on your network.*UDP/);
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
  await page.getByRole('textbox', { name: 'Name', exact: true }).fill('ads.e2e.test');
  await page.getByRole('button', { name: 'Explain' }).click();
  await expect(page.locator('.explain')).toContainText('blocked');
});

test('the menu links to the project on GitHub and its site', async () => {
  await page.goto('/#/');
  const gh = page.getByRole('link', { name: 'TelltaleDNS on GitHub' });
  await expect(gh).toHaveAttribute('href', 'https://github.com/paimonsoror/telltaledns');
  await expect(gh).toHaveAttribute('target', '_blank');
  await expect(page.getByRole('link', { name: 'Project site and guides' })).toHaveAttribute(
    'href',
    'https://paimonsoror.github.io/telltaledns/',
  );
});

// REQ: OBS-015 — the health icon sits left of the project links; its shape and the panel follow
// the level; on phones a dot on the menu button says something's wrong.
test('obs_015 health icon, its reasons, and the phone dot', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/');
  const icon = page.getByTestId('health-icon');
  await expect(icon).toBeVisible();
  await expect(icon).toHaveAttribute('data-level', /^(healthy|degraded|severe)$/);
  const [h, gh] = [await icon.boundingBox(), await page.getByRole('link', { name: 'TelltaleDNS on GitHub' }).boundingBox()];
  expect(h!.x).toBeLessThan(gh!.x);
  await page.route('**/api/v1/system/health', (route) =>
    route.fulfill({
      json: {
        level: 'severe',
        checkedAt: '2026-10-08T12:00:00.000Z',
        reasons: [
          { level: 'severe', code: 'upstream_group_down', summary: 'no upstream in group default is answering (quad9, cloudflare)', node: 'home-pi', link: '#/upstreams' },
          { level: 'degraded', code: 'rate_limited', summary: '12 queries were rate-limited in the last 5 minutes', link: '#/queries?status=rate_limited' },
        ],
      },
    }),
  );
  await page.reload();
  await expect(icon).toHaveAttribute('data-level', 'severe');
  await icon.click();
  const panel = page.getByTestId('health-panel');
  await expect(panel).toContainText('Severe');
  await expect(panel).toContainText('home-pi');
  await expect(panel).toContainText('rate-limited');
  await panel.getByRole('link', { name: 'Look' }).first().click();
  await expect(page).toHaveURL(/#\/upstreams/);
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.getByTestId('menu-health-dot')).toBeVisible();
  await page.unroute('**/api/v1/system/health');
  await page.setViewportSize({ width: 1280, height: 800 });
});

// REQ: OBS-016 — the dashboard's Service level card: the server's objectives (a few local
// answers make them "on track"), then a stubbed outage that burns the availability budget fast.
test('obs_016 service level card', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  for (let i = 0; i < 5; i++) await query(`slo${i}.localhost`).catch(() => 0);
  await page.goto('/#/');
  const card = page.getByTestId('slo-card');
  await expect(card).toContainText('Service level');
  await expect(card).toContainText('(last 30 days)');
  await expect(card.getByTestId('slo-availability')).toContainText('Answers that work');
  await expect(card.getByTestId('slo-latency')).toContainText('answers sent within 250 ms');
  const burns = (rates: number[]) =>
    ['5m', '30m', '1h', '6h', '3d'].map((window, i) => ({ window, rate: rates[i], total: 10000, bad: Math.round(rates[i] * 10) }));
  await page.route('**/api/v1/stats/slo*', (route) =>
    route.fulfill({
      json: {
        enabled: true,
        windowDays: 30,
        objectives: [
          {
            name: 'availability', goodMeans: "answers that aren't SERVFAIL", targetPercent: 99.9, sliPercent: 99.912,
            good: 999120, total: 1000000, budgetRemainingPercent: 12, burnRates: burns([20.1, 17.5, 16.2, 3.1, 1.2]),
            alert: 'fast', summary: 'availability: …',
          },
          {
            name: 'latency', goodMeans: 'answers sent within 250 ms', targetPercent: 99, latencyMs: 250, sliPercent: 99.7,
            good: 997000, total: 1000000, budgetRemainingPercent: 70, burnRates: burns([0.2, 0.3, 0.3, 0.3, 0.3]), summary: 'latency: …',
          },
        ],
      },
    }),
  );
  await page.reload();
  const a = card.getByTestId('slo-availability');
  await expect(a).toContainText('burning fast');
  await expect(a).toContainText('99.912%');
  await expect(a).toContainText('12% of the error budget left');
  await expect(a).toContainText('1h 16×');
  await expect(card.getByTestId('slo-latency')).toContainText('on track');
  await page.unroute('**/api/v1/stats/slo*');
});

// REQ: OBS-020 — Settings → System lists the listener probes: the e2e server's UDP listener
// answers its own probe (every 5 s there), and probe queries stay out of the query log.
test('obs_020 listener checks', async () => {
  await page.goto('/#/settings?tab=system');
  const card = page.getByTestId('probes');
  await expect(card).toContainText('Listener checks');
  await expect(card).toContainText('udp://127.0.0.1:15354', { timeout: 15_000 });
  await expect(card).toContainText('answers');
  const log = await page.evaluate(async () =>
    (await fetch('/api/v1/queries?name=probe.telltale.invalid&limit=5')).json(),
  );
  expect(log.items).toEqual([]);
});

// REQ: OBS-019 — the Upstreams page's Answer quality: second opinions off on the e2e server
// (it says how to turn them on), then a stubbed filtering upstream with its EDE and a
// disagreement.
test('obs_019 upstream answer quality', async () => {
  await page.goto('/#/upstreams');
  const card = page.getByTestId('upstream-quality');
  await expect(card).toContainText('Answer quality');
  await expect(card).toContainText('Second opinions are off');
  await page.route('**/api/v1/analytics/upstream-checks', (route) =>
    route.fulfill({
      json: {
        items: [
          {
            enabled: true, sampleEvery: 1000,
            upstreams: [{
              upstream: 'family-dns', same: 40, differentAddresses: 3, differentRcode: 0, filtered: 2, unanswered: 0,
              dnssecSecure: 10, dnssecInsecure: 30, dnssecBogus: 1, dnssecIndeterminate: 0,
              ede: [{ code: 17, name: 'Filtered', count: 12 }],
            }],
            recent: [{
              at: '2026-10-09T12:00:00.000Z', name: 'casino.example.org', qtype: 'A', result: 'filtered',
              upstream: 'family-dns', answer: 'NXDOMAIN', reference: 'quad9', referenceAnswer: 'NOERROR 192.0.2.7',
            }],
          },
        ],
      },
    }),
  );
  await page.reload();
  await expect(card).toContainText('2 filtered');
  await expect(card).toContainText('1 bogus');
  await expect(card).toContainText('17 Filtered: 12');
  await expect(card).toContainText('casino.example.org');
  await expect(card).toContainText('quad9: NOERROR 192.0.2.7');
  await expect(card).not.toContainText('Second opinions are off');
  await page.unroute('**/api/v1/analytics/upstream-checks');
});

// REQ: OBS-014 — acknowledging a finding hides it (and drops it from the badge) until "Show
// acknowledged"; the acknowledge itself goes to the real server. A fresh server has no
// findings yet (devices learn for a week), so the list is stubbed.
test('obs_014 acknowledge an anomaly', async () => {
  const id = '6a2c0e00a1b2c3d4';
  const acked = new Set<string>();
  const finding = {
    id,
    kind: 'rate_spike',
    client: '192.168.1.20',
    clientName: 'tablet',
    windowStart: '2026-10-08T10:00:00.000Z',
    windowSeconds: 3600,
    observed: 4100,
    baseline: 119,
    spread: 30,
    threshold: 400,
    detail: '4100 queries in an hour; usually 119 ± 30',
    nodes: ['home-pi', 'k8s'],
  };
  await page.route('**/api/v1/analytics/anomalies?*', (route) => {
    const unackedOnly = new URL(route.request().url()).searchParams.get('acknowledged') === 'false';
    const f = acked.has(id) ? { ...finding, acknowledged: { by: 'admin', at: '2026-10-08T12:00:00.000Z' } } : finding;
    return route.fulfill({ json: { items: unackedOnly && acked.has(id) ? [] : [f] } });
  });
  await page.route('**/api/v1/analytics/anomalies/*acknowledge', async (route) => {
    const res = await route.fetch();
    const body = route.request().postDataJSON() as { ids: string[] };
    if (res.ok()) {
      for (const i of body.ids) {
        if (route.request().url().endsWith('/unacknowledge')) acked.delete(i);
        else acked.add(i);
      }
    }
    await route.fulfill({ response: res });
  });
  await page.goto('/#/anomalies');
  await page.reload(); // the sidebar badge loads at start
  const badge = page.locator('a.nav[href="#/anomalies"] .count');
  await expect(badge).toHaveText('1');
  await expect(page.getByTestId('anomaly')).toContainText('Found by home-pi, k8s');
  await page.getByTestId('ack').click();
  await expect(page.getByTestId('anomaly')).toHaveCount(0);
  await expect(page.getByText('every finding in this period is acknowledged')).toBeVisible();
  await expect(badge).toHaveCount(0);
  await page.getByTestId('show-acknowledged').check();
  await expect(page.getByTestId('acknowledged')).toContainText('by admin');
  await page.getByRole('button', { name: 'Undo acknowledge' }).click();
  await expect(page.getByTestId('ack')).toBeVisible();
  await page.unroute('**/api/v1/analytics/anomalies?*');
  await page.unroute('**/api/v1/analytics/anomalies/*acknowledge');
});

// The header's icon buttons match: the pause button (its own component) is the same round,
// borderless button as the theme toggle, on the same line (owner report 2026-10-06).
test('header icon buttons are the same size and aligned', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/');
  const pause = page.getByRole('button', { name: 'Pause blocking' });
  const theme = page.getByRole('button', { name: /^Theme:/ });
  await page.getByRole('heading', { level: 1 }).first().waitFor();
  const [p, t] = [await pause.boundingBox(), await theme.boundingBox()];
  expect(p && t).toBeTruthy();
  expect(Math.round(p!.width)).toBe(Math.round(t!.width));
  expect(Math.round(p!.height)).toBe(Math.round(t!.height));
  expect(Math.abs(p!.y + p!.height / 2 - (t!.y + t!.height / 2))).toBeLessThanOrEqual(1);
  expect(await pause.evaluate((b) => getComputedStyle(b).borderTopWidth)).toBe('0px');
  await page.locator('header').first().screenshot({ path: '.shots/header-buttons.png' });
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

// REQ: FLT-005 (ADR-050, T3.14 AC) — devices on a group's network are in that group: the
// Groups card shows the network and traffic, the dashboard charts traffic by group, and the
// query log filters by group.
test('flt_005 network groups: cards, chart, and query-log filter', async () => {
  for (let i = 0; i < 5; i++) await query(`g${i}.nas.e2e.test`).catch(() => -1);
  await page.goto('/#/groups');
  const card = page.getByTestId('group-card').filter({ hasText: 'lab' });
  await expect(card).toContainText('127.0.0.0/8');
  await expect(async () => {
    await page.reload();
    await expect(card.locator('dd').first()).not.toHaveText('0', { timeout: 2000 });
  }).toPass({ timeout: 20_000 });
  await page.goto('/#/');
  await expect(page.getByRole('heading', { name: 'Traffic by group' })).toBeVisible();
  await page.getByLabel('Group').selectOption('lab');
  await expect(page.locator('section.card', { hasText: 'Top domains' })).toContainText('nas.e2e.test');
  await page.goto('/#/queries?group=lab');
  await expect(page.locator('table.log tbody tr').first().locator('.group-chip')).toHaveText('lab');
  const r = await page.request.get('/api/v1/queries?group=lab&limit=5');
  expect(r.status()).toBe(200);
  expect((await r.json()).items.every((x: { group: string }) => x.group === 'lab')).toBe(true);
  expect((await page.request.get('/api/v1/queries?group=nope')).status()).toBe(400);
  // The clients list shows the group each client gets from its network.
  await page.goto('/#/clients');
  const seen = page.locator('section.card', { hasText: 'Seen this hour' });
  await expect(seen.locator('tbody tr', { hasText: '127.0.0.1' }).locator('.group-chip')).toHaveText('lab');
});

// REQ: CLU-008 — the Cluster page on a standalone node says so and how to start a cluster.
test('clu_008 cluster page on a standalone node', async () => {
  await page.goto('/#/cluster');
  await expect(page.getByRole('heading', { name: 'Cluster' })).toBeVisible();
  await expect(page.getByTestId('cluster-standalone')).toContainText('telltale cluster init');
  expect((await (await page.request.get('/api/v1/cluster')).json()).enabled).toBe(false);
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

// REQ: FLT-005 (T6.12, ADR-067) — a quick rule from "Why?": allow a blocked name for this
// device for an hour; DNS stops blocking it at once, the Rules page shows it with its
// countdown, and removing it blocks the name again. No list is recompiled.
test('flt_005 quick rule: allow for 1 hour from the query log', async () => {
  expect(await query('ads.e2e.test')).toBe(0); // blocked: 0.0.0.0
  await page.goto('/#/queries?status=blocked&name=ads.e2e.test&match=exact');
  await page.getByRole('button', { name: 'Why?' }).first().click();
  const form = page.getByTestId('quick-rule-form');
  await expect(form.getByRole('textbox', { name: 'Domain' })).toHaveValue('ads.e2e.test');
  await expect(form.getByRole('combobox', { name: 'Duration' })).toHaveValue('60');
  await form.getByRole('textbox', { name: 'Note' }).fill('e2e game');
  await form.getByRole('button', { name: 'Save rule' }).click();
  await expect(page.getByTestId('quick-rule-saved')).toContainText('allowed for');
  await page.keyboard.press('Escape');

  // Not blocked any more: it goes upstream (unreachable in this test, so not a 0.0.0.0 answer).
  expect(await query('ads.e2e.test').catch(() => -1)).not.toBe(0);

  await page.goto('/#/rules');
  const table = page.getByTestId('rules-table');
  await expect(table).toContainText('ads.e2e.test');
  await expect(table).toContainText('e2e game');
  await expect(table).toContainText(/in (59m|1h)/);

  // The query log attributes the decision to the rule.
  // (The allowed query is logged once its upstream attempt ends, a few seconds later here.)
  await page.goto('/#/queries?name=ads.e2e.test&match=exact');
  await expect
    .poll(
      async () => {
        await page.reload();
        return page.locator('table.log tbody').innerText();
      },
      { timeout: 20_000, intervals: [1000] },
    )
    .toContain('quick allow');

  // Removing it: the lists decide again.
  await page.goto('/#/rules');
  await page.getByTestId('rules-table').getByRole('button', { name: 'Remove' }).click();
  await expect(page.locator('main')).toContainText('No quick rules');
  expect(await query('ads.e2e.test')).toBe(0);
});

// REQ: FLT-005 (ADR-067) — an expiring rule stops applying at its expiry without a restart,
// the sweep removes it within seconds, and the audit log records `rule.expire`.
test('flt_005 quick rules expire on their own and are audited', async () => {
  const r = page.request;
  const csrf = (await (await r.get('/api/v1/auth/status')).json()).csrfToken as string;
  const h = { 'x-csrf-token': csrf };
  const expires = new Date(Date.now() + 4000).toISOString().replace(/\.\d+Z$/, 'Z');
  const put = await r.put('/api/v1/rules/e2e-expiring', {
    headers: h,
    data: { action: 'allow', domain: 'ads.e2e.test', devices: ['127.0.0.1'], expires },
  });
  expect(put.status()).toBe(200);
  expect(await query('ads.e2e.test').catch(() => -1)).not.toBe(0); // allowed while it lasts
  await expect
    .poll(async () => (await (await r.get('/api/v1/rules')).json()).items.length, { timeout: 20_000, intervals: [1000] })
    .toBe(0);
  expect(await query('ads.e2e.test')).toBe(0); // the list blocks it again
  const audit = await (await r.get('/api/v1/audit?limit=20')).json();
  expect(JSON.stringify(audit)).toContain('rule.expire');
  // Mistakes are refused with a reason.
  const past = await r.put('/api/v1/rules/e2e-past', {
    headers: h,
    data: { action: 'block', domain: 'x.e2e.test', expires: '2020-01-01T00:00:00Z' },
  });
  expect(past.status()).toBe(422);
  const unknownGroup = await r.put('/api/v1/rules/e2e-bad', {
    headers: h,
    data: { action: 'block', domain: 'x.e2e.test', groups: ['nope'] },
  });
  expect(unknownGroup.status()).toBe(422);
});

// REQ: CLU-008, CLU-009 (T6.14) — the topology matches GET /cluster: a controller with 3 pods on
// two Kubernetes nodes and a Pi; 8 pods on one node fold into "+3"; a pod down is red; selecting
// a pod opens its site and highlights its row (pod name, Kubernetes node, share, cache).
test('clu_008 cluster topology', async () => {
  const node = (o: Record<string, unknown>) => ({
    ephemeral: false, witness: false, protocol: 4, role: 'replica', thisNode: false, eligible: true, version: '0.1.0',
    up: true, connected: true, link: 'inbound', lastSeenSecondsAgo: 1, rttMs: 3, configSeq: 9, configLag: 0, ready: true,
    qps: 10, servfailPercent: 0, upstreamP90Ms: 12, uptimeSeconds: 3600, restarts: 0, cacheEntries: 500,
    cacheHitPercent: 80, querySharePercent: 10, ...o,
  });
  const pod = (name: string, kube: string, o: Record<string, unknown> = {}) =>
    node({ nodeId: `id-${name}`, site: 'k8s', ephemeral: true, pod: `telltale-resolver-${name}`, kubeNode: kube, ...o });
  const view = (pods: ReturnType<typeof node>[]) => ({
    enabled: true, clusterId: 'c1', name: 'home', thisNode: 'id-ctl', newestConfigSeq: 9, healthy: true, checks: [],
    events: [], conflicts: [], authority: 'primary',
    nodes: [
      node({ nodeId: 'id-ctl', site: 'k8s', role: 'primary', thisNode: true, link: 'self', rttMs: null, pod: 'telltaledns-756965cdc7-8j9h9', kubeNode: 'k3s-node-with-a-long-name-1', qps: 40, querySharePercent: 40 }),
      node({ nodeId: 'id-pi', site: 'home-raspberry-pi-in-the-hall-closet', rttMs: 4, qps: 30, querySharePercent: 30, restarts: 2 }),
      ...pods,
    ],
  });
  let current = view([
    pod('aaaaa', 'k3s-1', { qps: 20, querySharePercent: 20 }),
    pod('bbbbb', 'k3s-2', { qps: 10, querySharePercent: 10, cacheHitPercent: 55 }),
    pod('ccccc', 'k3s-2', { up: false, qps: 0, querySharePercent: null }),
  ]);
  await page.route('**/api/v1/cluster', (route) => route.fulfill({ json: current }));
  await page.goto('/#/cluster');
  const topo = page.getByTestId('cluster-topology');
  await expect(topo.getByTestId('topology-site')).toHaveCount(2);
  await expect(topo.getByTestId('topology-node')).toHaveCount(2); // controller and Pi
  await expect(topo.getByTestId('topology-pod')).toHaveCount(3);
  await expect(topo).toContainText('node k3s-1 · 1 replica pod');
  await expect(topo).toContainText('node k3s-2 · 2 replica pods');
  await expect(topo).toContainText('4 ms'); // the Pi's round trip, measured by this node
  // Long pod and site names are shortened in the middle to fit (the full name is in the tooltip).
  await expect(topo.getByTestId('topology-node').first()).toContainText(/tellta.*….*-8j9h9/);
  // The primary is marked as such; the Pi is a replica.
  await expect(topo.getByTestId('topology-node').first().getByTestId('topology-role')).toHaveText('PRIMARY');
  await expect(topo.getByTestId('topology-node').nth(1).getByTestId('topology-role')).toHaveText('replica');
  await expect(topo.getByTestId('topology-site').nth(1).locator('text').first()).toHaveText(/^home-.*….*closet$/);
  await expect(topo.locator('.pod.bad')).toHaveCount(1);
  await expect(topo.locator('path.link.bad')).toHaveCount(1); // the k3s-2 group has a pod down

  // Selecting a pod opens its site in the table and highlights its row.
  await topo.getByRole('button', { name: /telltale-resolver-bbbbb/ }).click();
  const row = page.locator('#node-id-bbbbb');
  await expect(row).toHaveClass(/selected/);
  await expect(row).toContainText('telltale-resolver-bbbbb on k3s-2');
  await expect(row).toContainText('10.0% of queries');
  await expect(row).toContainText('cache: 55.0% hits');
  await expect(page.locator('#node-id-pi')).toContainText('2 restarts');

  // Updates with the page (every 5 s): 8 pods on one node fold into 5 + "+3".
  current = view(Array.from({ length: 8 }, (_, i) => pod(`p${i}xxx`, 'k3s-1')));
  await expect(topo.getByTestId('topology-pod')).toHaveCount(6, { timeout: 10_000 });
  await expect(topo).toContainText('+3');
  await expect(topo).toContainText('node k3s-1 · 8 replica pods');
  await page.unroute('**/api/v1/cluster');
});

// REQ: DNS-006, API-005 (T6.13) — the cache: a cached answer shows up in a lookup (the UI
// card and the API), a flush removes it and says how many, and viewers can look but not flush.
test('dns_006 cache lookup and flush', async () => {
  await query('www.cache.e2e.test'); // routed to the stub upstream (server.mjs)
  const r = page.request;
  await expect
    .poll(async () => (await (await r.get('/api/v1/cache/lookup?name=www.cache.e2e.test')).json()).entries.length, {
      timeout: 10_000,
    })
    .toBeGreaterThan(0);
  await page.goto('/#/cache'); // T6.15: its own page (Settings links to it)
  const card = page.getByTestId('cache-card');
  await card.getByRole('textbox', { name: 'Name to look up' }).fill('www.cache.e2e.test');
  await card.getByRole('button', { name: 'Look up' }).click();
  await expect(card.getByTestId('cache-entries')).toContainText('NOERROR');
  await card.getByRole('button', { name: 'Flush this name' }).click();
  await expect(card.getByTestId('cache-flushed')).toContainText(/Removed [1-9]/);
  await expect(card).toContainText('Nothing cached for');
  const stats = await (await r.get('/api/v1/cache/stats')).json();
  expect(stats.items.length).toBe(1);
  // A viewer may look but not flush.
  const viewer = await page.context().browser()!.newContext({ baseURL: page.url().split('/#')[0] });
  const vr = viewer.request;
  const st = await (await vr.get('/api/v1/auth/status')).json();
  const login = await vr.post('/api/v1/auth/login', {
    headers: { 'x-csrf-token': st.csrfToken ?? '' },
    data: { username: VIEWER.user, password: VIEWER.pass },
  });
  expect(login.ok()).toBeTruthy();
  const csrf = (await (await vr.get('/api/v1/auth/status')).json()).csrfToken as string;
  expect((await vr.get('/api/v1/cache/stats')).status()).toBe(200);
  expect((await vr.post('/api/v1/cache/flush', { headers: { 'x-csrf-token': csrf }, data: {} })).status()).toBe(403);
  await viewer.close();
});

// REQ: DNS-006, OBS-003 (T6.15) — the Cache page: this node's hit rate, how full it is, its
// settings and start; what it holds by kind and its top entries (sortable); Settings links here.
test('dns_006 cache page', async () => {
  await query('top.cache.e2e.test'); // the stub upstream: one cacheable answer
  await query('top.cache.e2e.test'); // and a hit
  await page.goto('/#/cache');
  const node = page.getByTestId('cache-node');
  await expect(node).toHaveCount(1);
  await expect(node).toContainText('Hit rate');
  await expect(node.getByTestId('cache-warm')).toContainText('cold (keeping the cache across restarts is off)');
  // REQ: OBS-021 — a fresh server has too few lookups to judge the size.
  await expect(node.getByTestId('cache-sizing')).toContainText('learning');
  await expect(node.getByTestId('cache-sizing')).toContainText('Not enough lookups yet');
  await node.getByText('Settings', { exact: true }).click();
  await expect(node.getByTestId('cache-settings')).toContainText('Serve stale');
  const top = page.getByTestId('cache-top');
  await page.getByRole('button', { name: 'Refresh' }).click();
  await expect(top).toContainText('top.cache.e2e.test');
  await expect(page.getByTestId('cache-makeup')).toContainText(/[1-9]\d* answers?/);
  // The most-hit entry first; sorting by size and expiry also lists it.
  const firstName = top.locator('tbody tr').first().locator('td').first();
  await expect(firstName).toHaveText('top.cache.e2e.test');
  await page.getByLabel('Sort by').selectOption('expiring');
  await expect(top).toContainText('top.cache.e2e.test');
  // Clicking a name fills in the lookup below.
  await top.getByRole('button', { name: 'top.cache.e2e.test' }).first().click();
  const card = page.getByTestId('cache-card');
  await expect(card.getByRole('textbox', { name: 'Name to look up' })).toHaveValue('top.cache.e2e.test');
  await expect(card.getByTestId('cache-entries')).toContainText('NOERROR');
  // The API: top entries need a known sort.
  expect((await page.request.get('/api/v1/cache/entries?sort=nope')).status()).toBe(400);
  await page.goto('/#/settings?tab=system');
  await expect(page.getByRole('link', { name: 'Cache page' })).toHaveAttribute('href', '#/cache');
  // REQ: OPS-004 — "Check now" (admins): a local build isn't compared with releases, so the
  // status stays "newer" and nothing is fetched.
  const check = page.waitForResponse('**/api/v1/system/update-check');
  await page.getByTestId('check-updates').click();
  expect((await check).status()).toBe(200);
  await expect(page.getByTestId('updates')).toContainText('Newer than the published');
});

// REQ: DNS-006, CLU-008 (T6.15) — the Cache page scales with the cluster: with 8 nodes, each
// name is listed once (hits summed, "N of 8" nodes, per-node detail on demand), and the makeup
// is one row per node, the first 6 shown.
test('dns_006 cache page with many nodes', async () => {
  const pods = Array.from({ length: 8 }, (_, i) => `telltale-resolver-${i}`);
  const entry = (name: string, hits: number, ttl: number) => ({
    name, qtype: 'A', rcode: 'NOERROR', answers: 1, authentic: false, dnssecOk: false,
    ttlLeftSeconds: ttl, ageSeconds: 10, bytes: 180, hits,
  });
  const makeup = { positive: 90, nxdomain: 6, nodata: 3, servfail: 1, stale: 2, validated: 40 };
  await page.route('**/api/v1/cache/entries**', (route) =>
    route.fulfill({
      json: {
        missingNodes: [],
        items: pods.map((node, i) => ({
          node,
          makeup,
          // Every node holds popular.example; the first three also hold three.example.
          entries: [entry('popular.example', 10, 100 + i), ...(i < 3 ? [entry('three.example', 5, 50)] : [])],
        })),
      },
    }),
  );
  await page.goto('/#/cache');
  const top = page.getByTestId('cache-top');
  await expect(top.locator('tbody tr')).toHaveCount(2); // two names, not 11 rows
  const first = top.locator('tbody tr').first();
  await expect(first).toContainText('popular.example');
  await expect(first).toContainText('8 of 8');
  await expect(first).toContainText('80'); // 8 × 10 hits
  await expect(top.locator('tbody tr').nth(1)).toContainText('3 of 8');
  await first.getByRole('button', { name: '8 of 8' }).click();
  await expect(top.locator('tr.detail')).toContainText('telltale-resolver-7');
  const makeupRows = page.getByTestId('cache-makeup').locator('tbody tr');
  await expect(makeupRows).toHaveCount(6);
  await page.getByRole('button', { name: 'Show all 8 nodes' }).click();
  await expect(makeupRows).toHaveCount(8);
  await page.unroute('**/api/v1/cache/entries**');
});

// REQ: FLT-009 (T7.1) — pause blocking from the header and resume it; the API refuses bad
// input (no minutes, too many, an unknown group).
test('flt_009 pause and resume blocking', async () => {
  await page.goto('/#/');
  await page.getByRole('button', { name: 'Pause blocking' }).click();
  await page.getByRole('menuitem', { name: '5 minutes', exact: true }).click();
  const pill = page.getByTestId('blocking-paused');
  await expect(pill).toContainText(/Blocking paused · [45] min left/);
  const st = await (await page.request.get('/api/v1/blocking')).json();
  expect(st.items[0].pauses[0].group ?? null).toBeNull();
  await pill.getByRole('button', { name: 'Resume' }).click();
  await expect(pill).toHaveCount(0);
  const csrf = (await (await page.request.get('/api/v1/auth/status')).json()).csrfToken as string;
  const post = (data: object) =>
    page.request.post('/api/v1/blocking/pause', { headers: { 'x-csrf-token': csrf }, data });
  expect((await post({})).status()).toBe(400);
  expect((await post({ minutes: 5000 })).status()).toBe(400);
  expect((await post({ minutes: 5, group: 'nope' })).status()).toBe(400);
  // A group pause shows as a count, not as everyone paused.
  expect((await post({ minutes: 5, group: 'lab' })).status()).toBe(200);
  await page.reload();
  await expect(page.getByTestId('groups-paused')).toContainText('1 group paused');
  await page.request.post('/api/v1/blocking/resume', { headers: { 'x-csrf-token': csrf }, data: {} });
});

// The help drawer reads the same wherever its "?" sits (owner report: from the Quick rules
// page title it took the heading's size).
test('api_011 help drawer text is body-sized everywhere', async () => {
  const size = async () => {
    const p = page.getByRole('dialog').locator('p').first();
    await expect(p).toBeVisible();
    const px = await p.evaluate((el) => getComputedStyle(el).fontSize);
    await page.keyboard.press('Escape');
    return px;
  };
  // The header's "?" (the reference), then the one in the Quick rules title.
  await page.goto('/#/rules');
  await page.locator('header.top').getByRole('button', { name: /help/i }).first().click();
  const reference = await size();
  await page.getByRole('heading', { name: 'Quick rules' }).getByRole('button').click();
  expect(await size()).toBe(reference);
});

// REQ: API-002 (T7.5, ADR-069) — upstreams and lists through the API: add, override the
// files' entry, refuse a change that breaks the configuration, and revert.
// REQ: AGT-007 (T7.1) — an agent's plan waits for an operator: the header says so, the
// Agent changes page shows what it does and why, and approving it lets the agent apply it.
test('agt_007 approve an agent plan in the UI', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  const r = page.request;
  const csrf = (await (await r.get('/api/v1/auth/status')).json()).csrfToken as string;
  const token = (
    await (
      await r.post('/api/v1/tokens', {
        headers: { 'x-csrf-token': csrf },
        data: { name: 'ui-agent', kind: 'agent', scopes: ['analytics:read', 'config:write:rules'] },
      })
    ).json()
  ).token as string;
  const mcp = async (name: string, args: Record<string, unknown>) => {
    const res = await r.post('/mcp', {
      headers: { authorization: `Bearer ${token}`, accept: 'application/json, text/event-stream' },
      data: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } },
    });
    return (await res.json()).result as { isError: boolean; structuredContent?: Record<string, unknown> };
  };
  const planned = await mcp('plan_block_domain', { domain: 'plan.e2e.test', groups: ['default'], reason: 'the e2e asked' });
  expect(planned.isError).toBe(false);
  const id = planned.structuredContent!.planId as string;
  expect((await mcp('apply_plan', { planId: id })).isError).toBe(true);

  await page.goto('/#/');
  await expect(page.getByTestId('agent-inbox')).toHaveText('1 agent change to review', { timeout: 20000 });
  await page.getByTestId('agent-inbox').click();
  await expect(page.getByRole('heading', { name: 'Agent changes' })).toBeVisible();
  const card = page.getByTestId('plan').filter({ hasText: 'Block plan.e2e.test' });
  await expect(card).toContainText('waiting for approval');
  await expect(card).toContainText('the e2e asked');
  await expect(card).toContainText('agent:ui-agent (owner: admin)');
  await card.getByRole('button', { name: 'Approve' }).click();
  await expect(card).toContainText('approved');
  await expect(card).toContainText('Decided by');

  const applied = await mcp('apply_plan', { planId: id });
  expect(applied.isError).toBe(false);
  await expect(card).toContainText('applied', { timeout: 10000 });
  expect((await (await r.get('/api/v1/rules')).json()).items.map((x: { id: string }) => x.id)).toContain('agent-block-plan-e2e-test');
  expect((await r.delete('/api/v1/rules/agent-block-plan-e2e-test', { headers: { 'x-csrf-token': csrf } })).status()).toBe(200);
});

// REQ: API-002 (T7.5, ADR-069) — the Lists and Upstreams pages add, change, and revert entries
// with a preview first; the config files are never rewritten.
test('api_002 lists and upstreams are edited from the UI', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/lists');
  const lists = page.getByTestId('editor-list');
  await lists.getByRole('button', { name: 'Add list' }).click();
  await page.getByRole('textbox', { name: 'Name', exact: true }).fill('ui-extra');
  await page.getByRole('textbox', { name: 'Rules', exact: true }).fill('||ui-extra.e2e.test^');
  // REQ: API-002 (T9.12) — try the draft before saving it.
  await page.getByRole('button', { name: 'Test it' }).click();
  await expect(page.getByTestId('form-action-result')).toContainText('Works: 1 rules from 1 lines');
  await page.getByRole('button', { name: 'Check' }).click();
  await expect(page.getByTestId('entry-preview')).toBeVisible();
  await page.getByRole('button', { name: 'Apply' }).click();
  const row = lists.getByTestId('entry-row').filter({ hasText: 'ui-extra' });
  await expect(row).toContainText('added here');
  await expect(row).toContainText('1 rules');
  await row.getByRole('button', { name: 'Remove' }).click();
  await expect(row).toHaveCount(0);

  // An upstream from the files: overridden, then back to the files' version.
  await page.goto('/#/upstreams');
  const ups = page.getByTestId('editor-upstream');
  const router = ups.getByTestId('entry-row').filter({ hasText: 'router' });
  await expect(router).toContainText('config file');
  await router.getByRole('button', { name: 'Edit' }).click();
  await expect(page.getByRole('textbox', { name: 'Name', exact: true })).toHaveValue('router');
  await page.getByRole('textbox', { name: 'Address', exact: true }).fill('udp://127.0.0.1:15399');
  // The e2e fake upstream answers there (T9.12).
  await page.getByRole('button', { name: 'Test it' }).click();
  await expect(page.getByTestId('form-action-result')).toContainText('Works: answered NOERROR');
  await page.getByRole('button', { name: 'Check' }).click();
  await page.getByRole('button', { name: 'Apply' }).click();
  await expect(router).toContainText('overrides the file');
  await router.getByRole('button', { name: 'Revert to the file' }).click();
  await expect(router).toContainText('config file');
});

test('api_002 upstreams and lists can be added, overridden, and reverted', async () => {
  const r = page.request;
  const csrf = (await (await r.get('/api/v1/auth/status')).json()).csrfToken as string;
  const h = { 'x-csrf-token': csrf };
  const overrides = async () =>
    ((await (await r.get('/api/v1/config/entries')).json()).items as { kind: string; name: string; source: string }[])
      .filter((o) => o.source !== 'file')
      .map((o) => `${o.kind}:${o.name}:${o.source}`)
      .sort();
  // A dry run changes nothing.
  let res = await r.put('/api/v1/upstreams/extra?dryRun=true', { headers: h, data: { url: 'udp://127.0.0.1:9' } });
  expect(res.status()).toBe(200);
  expect((await res.json()).applied).toBe(false);
  expect(await overrides()).toEqual([]);
  // Added, and an override of the files' "router".
  expect((await r.put('/api/v1/upstreams/extra', { headers: h, data: { url: 'udp://127.0.0.1:9' } })).status()).toBe(200);
  res = await r.put('/api/v1/upstreams/router', { headers: h, data: { url: 'udp://127.0.0.1:15399', timeout_ms: 900 } });
  expect(res.status()).toBe(200);
  expect(await overrides()).toEqual(['upstream:extra:added', 'upstream:router:override']);
  // Hiding the only upstream of the default group is refused, and says what to do.
  res = await r.delete('/api/v1/upstreams/nowhere', { headers: h });
  expect(res.status()).toBe(422);
  expect(JSON.stringify(await res.json())).toContain('only upstream in upstream group');
  // REQ: API-002 (T9.22) — removing an upstream a group shares takes it out of the group too.
  expect((await r.put('/api/v1/upstream-groups/router', { headers: h, data: { members: ['router', 'extra'] } })).status()).toBe(200);
  res = await r.delete('/api/v1/upstreams/extra?dryRun=true', { headers: h });
  expect(res.status()).toBe(200);
  expect((await res.json()).impact).toContain('upstream group `router`');
  expect((await r.delete('/api/v1/upstreams/extra', { headers: h })).status()).toBe(200);
  const groups = (await (await r.get('/api/v1/config/entries')).json()).items as { kind: string; name: string; definition: { members?: string[] } }[];
  expect(groups.find((g) => g.kind === 'upstream_group' && g.name === 'router')?.definition.members).toEqual(['router']);
  // Revert the overrides.
  expect((await r.delete('/api/v1/upstream-groups/router', { headers: h })).status()).toBe(200);
  expect((await r.delete('/api/v1/upstreams/router', { headers: h })).status()).toBe(200);
  expect(await overrides()).toEqual([]);
  // A list: added, then removed.
  res = await r.put('/api/v1/lists/e2e-extra', { headers: h, data: { rules: ['||extra.e2e.test^'] } });
  expect(res.status()).toBe(200);
  expect(await overrides()).toEqual(['list:e2e-extra:added']);
  expect((await r.delete('/api/v1/lists/e2e-extra', { headers: h })).status()).toBe(200);
  expect(await overrides()).toEqual([]);
});

// REQ: AGT-012 (T8.6) — the Analyze page runs vqlog: a top list linked to the query log, a cost
// estimate without scanning, and a mistake shown with its hint.
test('agt_012 analyze page', async () => {
  for (let i = 0; i < 3; i++) await query('ads.e2e.test').catch(() => -1);
  await page.goto('/#/analyze?q=' + encodeURIComponent('from -1h | where status = blocked | top 5 name'));
  const result = page.getByTestId('vqlog-result');
  await expect(async () => {
    await page.getByRole('button', { name: 'Run' }).click();
    await expect(result.getByRole('link', { name: 'ads.e2e.test', exact: true })).toBeVisible({ timeout: 2000 });
  }).toPass({ timeout: 20_000 });
  await expect(result).toContainText('As understood: from -1h | where status = blocked | by name | stats count');
  await expect(page.getByTestId('vqlog-cost')).toContainText('Matched');
  await page.getByRole('button', { name: 'Estimate cost' }).click();
  await expect(page.getByTestId('vqlog-cost')).toContainText('Estimate: up to');
  await page.getByLabel('vqlog query').fill('top 5 colour');
  await page.getByLabel('vqlog query').press('Control+Enter');
  await expect(page.getByRole('alert')).toContainText('unknown key');
  await expect(page.getByRole('alert')).toContainText('Keys: name, domain');
  // The browser logs that 400; it's the expected answer to the typo, not a page problem.
  for (let i = problems.length - 1; i >= 0; i--) if (problems[i].includes('status of 400')) problems.splice(i, 1);
  // An example chip fills the box and runs it.
  await page.getByRole('button', { name: 'Queries per hour, with latency' }).click();
  await expect(result.locator('thead')).toContainText('p95(latency)');
});

// REQ: T8.3, API-010 (T8.6) — a device found over mDNS shows under Discovered and its name is
// suggested when naming it; groups show answer settings; zones are listed.
test('t8_6 discovered devices, group settings, and zones', async () => {
  const { createSocket } = await import('node:dgram');
  const label = (s: string) => [Buffer.from([s.length]), Buffer.from(s)];
  const msg = Buffer.concat([
    Buffer.from([0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0]),
    ...label('printer-e2e'),
    ...label('local'),
    Buffer.from([0, 0, 1, 0x80, 1, 0, 0, 0, 120, 0, 4, 127, 0, 0, 9]),
  ]);
  const sock = createSocket('udp4');
  await new Promise<void>((done) => sock.send(msg, 15353, '127.0.0.1', () => done()));
  sock.close();
  await page.goto('/#/clients');
  const found = page.getByTestId('discovered');
  await expect(async () => {
    await page.reload();
    await expect(found.locator('tbody tr', { hasText: 'printer-e2e' })).toBeVisible({ timeout: 2000 });
  }).toPass({ timeout: 20_000 });
  const row = found.locator('tbody tr', { hasText: 'printer-e2e' });
  await expect(row).toContainText('mDNS');
  await expect(row).toContainText('not named yet');
  await row.getByRole('button', { name: '127.0.0.9' }).click();
  await row.getByRole('menuitem', { name: 'Name this device…' }).click();
  await expect(page.getByLabel('Name', { exact: true })).toHaveValue('printer-e2e');
  await page.keyboard.press('Escape');

  await page.goto('/#/groups');
  const card = page.getByTestId('group-card').filter({ hasText: 'ipv6only' });
  await expect(card.getByTestId('group-dns64')).toContainText('DNS64 on (64:ff9b::/96)');
  await expect(card.getByTestId('group-rewrites')).toContainText('tv.e2e.test → 192.168.1.30');
  await expect(card.getByTestId('group-answers')).toContainText('Rebinding protection on; blocks answers in 203.0.113.0/24');

  await page.goto('/#/local-dns');
  const zones = page.getByTestId('zones');
  await expect(zones.locator('tbody tr', { hasText: 'zone.e2e.test' })).toContainText('ipv6only');
});

// REQ: OBS-010 (T9.6) — the Alerts page: add a destination, send it a test, add a rule that
// fires, see it under "Now" with the delivery, then remove both.
test('obs_010 alerts page: destinations, test, rules', async () => {
  test.setTimeout(120_000); // the rule fires on the next 5 s check
  const { createServer } = await import('node:http');
  const got: string[] = [];
  const hook = createServer((req, res) => {
    let b = '';
    req.on('data', (c) => (b += c));
    req.on('end', () => {
      got.push(b);
      res.end('ok');
    });
  });
  await new Promise<void>((r) => hook.listen(18998, '127.0.0.1', () => r()));
  try {
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.goto('/#/alerts');
    await expect(page.locator('h1', { hasText: 'Alerts' })).toBeVisible();
    // Advanced: the rule's threshold.
    await page.getByRole('button', { name: 'Advanced', exact: true }).click();
    const dests = page.getByTestId('editor-alert_destination');
    await dests.getByRole('button', { name: 'Add destination' }).click();
    await page.getByRole('textbox', { name: 'Name', exact: true }).fill('ui-hook');
    await page.getByLabel('Type', { exact: true }).selectOption('webhook');
    await page.getByRole('textbox', { name: 'Address', exact: true }).fill('http://127.0.0.1:18998/alert');
    await page.getByRole('button', { name: 'Check' }).click();
    await expect(page.getByTestId('entry-preview')).toBeVisible();
    await page.getByRole('button', { name: 'Apply' }).click();
    const row = dests.getByTestId('entry-row').filter({ hasText: 'ui-hook' });
    await expect(row).toContainText('webhook: http://127.0.0.1:18998/alert');
    await row.getByRole('button', { name: 'Send test' }).click();
    await expect(dests.getByTestId('row-action-result')).toContainText('sent');
    expect(got.some((b) => b.includes('This is a test alert'))).toBe(true);

    const rules = page.getByTestId('editor-alert_rule');
    await rules.getByRole('button', { name: 'Add rule' }).click();
    await page.getByRole('textbox', { name: 'Name', exact: true }).fill('ui-disk');
    await page.getByLabel('When', { exact: true }).selectOption('disk_full');
    await page.getByRole('group', { name: 'Send to' }).getByLabel('ui-hook').check();
    await page.getByRole('spinbutton', { name: 'For at least (seconds)' }).fill('0');
    await page.getByRole('spinbutton', { name: 'Threshold (%)' }).fill('0.1');
    await page.getByRole('button', { name: 'Check' }).click();
    await page.getByRole('button', { name: 'Apply' }).click();
    await expect(rules.getByTestId('entry-row').filter({ hasText: 'ui-disk' })).toContainText('disk_full → ui-hook');
    const now = page.getByTestId('alerts-now');
    await expect(async () => {
      await page.reload();
      await expect(now).toContainText('ui-disk', { timeout: 2000 });
      await expect(now).toContainText('delivered', { timeout: 2000 });
    }).toPass({ timeout: 45_000 });
    expect(got.some((b) => b.includes('"rule":"ui-disk"'))).toBe(true);

    await rules.getByTestId('entry-row').filter({ hasText: 'ui-disk' }).getByRole('button', { name: 'Remove' }).click();
    await expect(rules.getByTestId('entry-row').filter({ hasText: 'ui-disk' })).toHaveCount(0);
    await row.getByRole('button', { name: 'Remove' }).click();
    await expect(row).toHaveCount(0);
  } finally {
    await page.getByRole('button', { name: 'Simple', exact: true }).click().catch(() => {});
    hook.close();
  }
});

// REQ: FLT-010 (T9.7) — schedules from the UI: a bad window is explained, a good one saved;
// a group follows it (on now), then both are undone.
test('flt_010 schedules are edited from the UI', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/groups');
  const sched = page.getByTestId('editor-schedule');
  await sched.getByRole('button', { name: 'Add schedule' }).click();
  await page.getByRole('textbox', { name: 'Name', exact: true }).fill('ui-bedtime');
  const windows = page.getByRole('textbox', { name: 'Windows (one per line)' });
  await windows.fill('sometimes');
  await page.getByRole('button', { name: 'Check' }).click();
  await expect(page.getByRole('alert')).toContainText('weekdays 21:00-07:00');
  await windows.fill('daily 00:00-24:00');
  await page.getByRole('button', { name: 'Check' }).click();
  await expect(page.getByTestId('entry-preview')).toBeVisible();
  await page.getByRole('button', { name: 'Apply' }).click();
  const row = sched.getByTestId('entry-row').filter({ hasText: 'ui-bedtime' });
  await expect(row).toContainText('block_all: daily 00:00-24:00');

  // The test-only group follows it (an override of the files' group).
  await page.reload();
  const groups = page.getByTestId('editor-group');
  const g = groups.getByTestId('entry-row').filter({ hasText: 'ipv6only' });
  await g.getByRole('button', { name: 'Edit' }).click();
  await page.getByRole('group', { name: 'Schedules' }).getByLabel('ui-bedtime').check();
  await page.getByRole('button', { name: 'Check' }).click();
  await page.getByRole('button', { name: 'Apply' }).click();
  const card = page.getByTestId('group-card').filter({ hasText: 'ipv6only' });
  await expect(async () => {
    await page.reload();
    await expect(card.getByTestId('group-schedules')).toContainText('on now', { timeout: 2000 });
  }).toPass({ timeout: 30_000 });

  await g.getByRole('button', { name: 'Revert to the file' }).click();
  await expect(g).toContainText('config file');
  await row.getByRole('button', { name: 'Remove' }).click();
  await expect(row).toHaveCount(0);
});

// REQ: DNS-014 (review 01 q1) — the per-client rate limit is adjusted from Settings → System
// (checked first, then applied) and reverted to the config file's.
test('dns_014 the rate limit is adjusted from the UI and reverted', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/settings?tab=system');
  const editor = page.getByTestId('editor-ratelimit');
  const row = editor.getByTestId('entry-row');
  await expect(row).toContainText('config file');
  await expect(row).toContainText('1000 queries per 60 s');
  await expect(editor.getByRole('button', { name: 'Add rate limit' })).toHaveCount(0);
  await expect(row.getByRole('button', { name: 'Remove' })).toHaveCount(0);

  await row.getByRole('button', { name: 'Edit' }).click();
  const queries = page.getByRole('spinbutton', { name: 'Queries allowed per window' });
  await queries.fill('0');
  await page.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('queries');
  // The refusal above is expected: not a page problem.
  for (let i = problems.length - 1; i >= 0; i--) if (problems[i].includes('status of 422')) problems.splice(i, 1);
  await queries.fill('5000');
  await page.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(page.getByTestId('entry-preview')).toContainText('count starts over');
  await page.getByRole('button', { name: 'Apply' }).click();
  await expect(row).toContainText('5000 queries per 60 s');
  await expect(row).toContainText('overrides the file');

  await row.getByRole('button', { name: 'Revert to the file' }).click();
  await expect(row).toContainText('config file');
  await expect(row).toContainText('1000 queries per 60 s');
});

// REQ: UPS-007 (T9.25) — a group's upstream servers are chosen in the Groups editor.
test('ups_007 a group picks its upstream group from the UI', async () => {
  await page.goto('/#/groups');
  const g = page.getByTestId('editor-group').getByTestId('entry-row').filter({ hasText: 'ipv6only' });
  await g.getByRole('button', { name: 'Edit' }).click();
  await page.getByLabel('Upstream servers').selectOption('router');
  await page.getByRole('button', { name: 'Check' }).click();
  await page.getByRole('button', { name: 'Apply' }).click();
  const card = page.getByTestId('group-card').filter({ hasText: 'ipv6only' });
  await expect(async () => {
    await page.reload();
    await expect(card.getByTestId('group-upstreams')).toContainText('router', { timeout: 2000 });
  }).toPass({ timeout: 30_000 });
  await g.getByRole('button', { name: 'Revert to the file' }).click();
  await expect(g).toContainText('config file');
});

// REQ: OBS-018 — a list in shadow mode never blocks: its name is answered (by the stub
// upstream) and counted under "Would have blocked"; the list carries a shadow badge.
// Last, because it caches a name (the cache test counts what's cached).
test('obs_018 shadow list and over-blocking', async () => {
  for (let i = 0; i < 2; i++) expect(await query('shadow.cache.e2e.test')).toBe(0);
  await page.goto('/#/lists');
  // The lists table comes first; the "Would have blocked" card also names the list.
  const row = page.locator('tr', { hasText: 'e2e-shadow' }).first();
  // Last in the suite: the earlier config changes can keep the first load busy for a while.
  await expect(row.locator('.badge', { hasText: 'shadow' })).toBeVisible({ timeout: 15_000 });
  // The page reads the counts once; the telemetry thread counts the queries moments later.
  const card = page.getByTestId('shadow-lists');
  await expect(async () => {
    await page.reload();
    await expect(card).toContainText('shadow.cache.e2e.test', { timeout: 2000 });
  }).toPass({ timeout: 20_000 });
  await expect(card).toContainText('2 queries from 1 device');
  await page.route('**/api/v1/analytics/overblocking*', (route) =>
    route.fulfill({
      json: {
        items: [{ name: 'login.bank.example', lists: ['e2e-block'], devices: 1, retryBursts: 0, allowedAfterBlock: 2, lastSeen: new Date().toISOString() }],
      },
    }),
  );
  await page.reload();
  const ob = page.getByTestId('overblocking');
  await expect(ob).toContainText('login.bank.example');
  await expect(ob).toContainText('e2e-block');
  await page.unroute('**/api/v1/analytics/overblocking*');
});
