// REQ: API-012 (ADR-189) — the pseudo-locale on every page, in the browser against the real server:
// the whole-page rule. Every piece of text a page shows (the text nodes outside translate="no", the
// attributes a reader sees or hears, and canvas text, fillText/strokeText hooked) carries a pseudo
// character, has no letters, is code, is a formatted date or time, or is data of the test: the names
// and values its mocks and the demo server sent (every string of every JSON answer the page received
// and of every body it sent, and of its address), and the ones the test declares with `declare`. No
// data string is ever the English of a message: such a value is left out (the page must mark it
// translate="no"), and a declaration of one fails the test. And no pseudo text reaches a request or
// the browser's storage. Expects the state 1-ui.spec.ts leaves (the admin, some queries), as
// 8-i18n-pages.spec.ts does. The rule is i18n-pseudo-rule.ts (held to fixtures, with no browser, by
// 7-i18n-pseudo-rule.spec.ts).
import { expect, test, type Page, type Route } from '@playwright/test';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import * as lib from '../../scripts/i18n-lib.mjs';
import { DATA, PSEUDO, jsonStrings, makeCollides, makeRule, readPage } from './i18n-pseudo-rule';
import { UI } from './i18n-fixture';
import { failOnPageErrors } from './page-errors';

// REQ: API-005 — a page error fails the test, as in 1-ui.spec.ts.
failOnPageErrors(test);

const ADMIN = { user: 'admin', pass: 'correct horse battery' };
// The help glossary is English data outside the layer (ADR-189: help stays English in part A).
const HELP: string[] = JSON.parse(readFileSync(join(UI, '../docs/help/topics.json'), 'utf8')).topics.flatMap((t: Record<string, unknown>) =>
  Object.values(t).filter((v): v is string => typeof v === 'string'),
);
// The English of every message of the UI, for the check that data is not one of them, and for the rule: a piece that is
// a message's English is that message gone back to English, whatever data the piece also shows.
// (A plural message has its forms as a list.)
const MESSAGES: string[] = [...(lib.check(UI, { ratchets: false }).entries as Map<string, { english: string | string[] }>).values()].flatMap((e) => (Array.isArray(e.english) ? e.english : [e.english]));
const collides = makeCollides(MESSAGES);
const RULE = makeRule({ data: DATA, help: HELP, messages: MESSAGES });

/** The data of this test: what its mocks and the server sent and what it typed (`received`), and what it declares. */
const received = new Set<string>();
const declared = new Set<string>();
const pending: Promise<void>[] = [];
test.beforeEach(() => {
  received.clear();
  declared.clear();
  pending.length = 0;
});
/** Declares data the page shows as it was given and that no JSON answer holds (a value the test typed into a
 * field, say). A text the UI says itself cannot be declared: it would hide a site gone back to its English. */
function declare(...names: string[]) {
  for (const n of names) {
    expect(collides(n), `"${n}" is the English of a message`).toBeUndefined();
    declared.add(n);
  }
}
const takeJson = (body: string | null | undefined) => {
  if (!body) return;
  try {
    jsonStrings(JSON.parse(body), received);
  } catch {
    // not JSON: nothing to take
  }
};

async function signIn(page: Page) {
  await page.goto('/');
  await page.getByLabel('Username', { exact: true }).fill(ADMIN.user);
  await page.getByLabel('Password', { exact: true }).fill(ADMIN.pass);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Dashboard' }).first()).toBeVisible({ timeout: 30_000 });
}

/** Records what the page sends and stores, and the canvas text it draws (before any page script). */
async function watch(page: Page) {
  const sent: string[] = [];
  page.on('request', (r) => {
    sent.push(`${r.method()} ${r.url()} ${r.postData() ?? ''}`);
    takeJson(r.postData());
  });
  page.on('response', (r) => {
    if (/json/.test(r.headers()['content-type'] ?? '')) pending.push(r.text().then(takeJson, () => undefined));
  });
  await page.addInitScript(() => {
    const w = window as unknown as { __i18aCanvas: string[]; __i18aStored: string[] };
    w.__i18aCanvas = [];
    w.__i18aStored = [];
    for (const f of ['fillText', 'strokeText'] as const) {
      const orig = CanvasRenderingContext2D.prototype[f];
      CanvasRenderingContext2D.prototype[f] = function (this: CanvasRenderingContext2D, text: string, ...rest: [number, number, number?]) {
        w.__i18aCanvas.push(String(text));
        return orig.call(this, text, ...rest);
      };
    }
    const set = Storage.prototype.setItem;
    Storage.prototype.setItem = function (this: Storage, k: string, v: string) {
      w.__i18aStored.push(`${k}=${v}`);
      return set.call(this, k, v);
    };
  });
  return sent;
}

// With I18A_PIECES set, every piece of text the tests read is written to test-results/i18a-pieces.json at the
// end of the file: what the states reach, for the report of which messages some tested state shows.
const PIECES = new Set<string>();
test.afterAll(() => {
  if (!process.env.I18A_PIECES) return;
  mkdirSync(join(UI, 'test-results'), { recursive: true });
  writeFileSync(join(UI, 'test-results', 'i18a-pieces.json'), JSON.stringify([...PIECES]));
});

/** Every text the page shows that is English (empty: the rule holds), each with where it is. */
async function leftovers(page: Page): Promise<string[]> {
  await Promise.all(pending);
  const { text, other, help, at } = await page.evaluate(readPage);
  if (process.env.I18A_PIECES) for (const s of [...text, ...other, ...help]) PIECES.add(s);
  // The address of the page is data too (a refusal a provider sent back in it).
  const url = new URL(page.url());
  const fromUrl = [...url.searchParams.values(), ...new URLSearchParams(url.hash.split('?')[1] ?? '').values()];
  const own = [...declared, ...[...received, ...fromUrl].filter((v) => !collides(v))];
  const places = new Map<string, string[]>();
  for (const [s, place] of at) places.set(s, [...(places.get(s) ?? []), place]);
  return RULE.found(text, other, own, help, places).map((s) => `${s} (${places.get(JSON.parse(s))?.slice(0, 3).join('; ') ?? '?'})`);
}

/** Nothing the page sent or stored holds pseudo text. */
async function clean(page: Page, sent: string[]) {
  const stored: string[] = await page.evaluate(() => (window as unknown as { __i18aStored: string[] }).__i18aStored);
  const decoded = (s: string) => {
    try {
      return decodeURIComponent(s);
    } catch {
      return s;
    }
  };
  expect(sent.filter((s) => PSEUDO.test(s) || PSEUDO.test(decoded(s))), 'requests').toEqual([]);
  expect(stored.filter((s) => PSEUDO.test(s)), 'storage').toEqual([]);
}

async function open(page: Page, hash: string, ready: string) {
  await page.goto(`/?lang=en-XA#${hash}`);
  await expect(page.locator('html')).toHaveAttribute('lang', 'en-XA');
  await expect(page.locator(ready).first()).toBeVisible();
}

// A cluster of three, and anomaly findings: what a one-node test server cannot show.
const T0 = '2026-11-24T22:00:00Z';
const node = (o: Record<string, unknown>) => ({
  behindSeconds: null, cacheEntries: 1200, cacheHitPercent: 61.5, certExpiresAt: null, configLag: 0, configSeq: 42, configSource: 'file', connected: true,
  eligible: true, ephemeral: false, host: null, kubeNode: null, lastSeenSecondsAgo: 1, link: 'direct', maintenance: null, pod: null, protocol: 3, qps: 4.2,
  querySharePercent: 33, ready: true, restarts: 0, rttMs: 1.4, servfailPercent: 0.2, sourceCommit: null, startedAt: T0, thisNode: false, up: true,
  upstreamP90Ms: 21, uptimeSeconds: 86_400, version: '0.9.0', witness: false, ...o,
});
const CLUSTER = {
  authority: null, checks: [], clusterId: 'c-home', conflicts: [], enabled: true, events: [], healthy: true, host: null, name: 'home', newestConfigSeq: 42,
  rollout: null, source: null, thisNode: 'n-aaaa1111',
  failover: { active: true, leaseHeld: true, leaseSecondsLeft: 8, mode: 'automatic', reachableVoters: 3, votedEpoch: 4, votedFor: 'n-aaaa1111', voters: 3 },
  nodes: [node({ nodeId: 'n-aaaa1111', site: 'homelab', role: 'primary', thisNode: true, rttMs: null }), node({ nodeId: 'n-bbbb2222', site: 'pi', role: 'secondary' })],
};
const FINDINGS = {
  items: ['f-1', 'f-2'].map((id) => ({
    acknowledged: null, baseline: 40, client: '127.0.1.11', clientName: null, detail: 'Many more queries than usual in this hour.', domain: null, id,
    informational: false, kind: 'rate_spike', mutedBy: null, nodes: [], observed: 900, rhythm: null, spread: 12, stormMute: null, threshold: 200,
    windowSeconds: 3600, windowStart: T0,
  })),
};

test('api_012 pseudo locale leaves no literal text: dashboard', async ({ page }) => {
  const sent = await watch(page);
  await signIn(page);
  await open(page, '/', '[data-testid="stat-queries"]');
  expect(await leftovers(page), 'dashboard').toEqual([]);
  await page.locator('ol.tl button.n').first().click();
  await expect(page.locator('ol.tl .more').first()).toBeVisible();
  await page.locator('figure.sc .bar button.link').first().click();
  await expect(page.locator('figure.sc .table-view').first()).toBeVisible();
  expect(await leftovers(page), 'a top list opened, a chart as a table').toEqual([]);
  await clean(page, sent);
});

test('api_012 pseudo locale leaves no literal text: query log', async ({ page }) => {
  const sent = await watch(page);
  await signIn(page);
  await open(page, '/queries', 'table.log tbody tr');
  await page.locator('table.log button.chip-button').first().click();
  await expect(page.locator('.chip .menu').first()).toBeVisible();
  expect(await leftovers(page), 'a device menu').toEqual([]);
  await page.locator('.chip .menu [role="menuitem"]').nth(1).click();
  await expect(page.locator('.drawer').first()).toBeVisible();
  expect(await leftovers(page), 'a device drawer').toEqual([]);
  await page.keyboard.press('Escape');
  await page.locator('table.log tbody tr td:last-child button').first().click();
  await expect(page.getByTestId('quick-rule-form')).toBeVisible();
  expect(await leftovers(page), 'the why drawer and its quick rule').toEqual([]);
  await clean(page, sent);
});

test('api_012 pseudo locale leaves no literal text: quick rules', async ({ page }) => {
  const sent = await watch(page);
  await signIn(page);
  await open(page, '/rules', '[data-testid="quick-rule-form"]');
  await page.locator('[data-testid="quick-rule-form"] input.mono').fill('i18n-pseudo.example.com');
  await page.locator('[data-testid="quick-rule-form"] select').first().selectOption('everyone');
  await page.locator('[data-testid="quick-rule-form"] button.primary').click();
  await expect(page.getByTestId('quick-rule-saved')).toBeVisible();
  expect(await leftovers(page), 'the quick rule form, saved').toEqual([]);
  await clean(page, sent);
});

test('api_012 pseudo locale leaves no literal text: groups and upstreams', async ({ page }) => {
  const sent = await watch(page);
  declare('failover: router');
  await signIn(page);
  await open(page, '/upstreams', '[data-testid="entry-row"]');
  expect(await leftovers(page), 'upstreams').toEqual([]);
  await open(page, '/groups', '[data-testid="editor-group"]');
  await page.locator('[data-testid="editor-group"] .head > button').click();
  await page.locator('form.form input.mono').first().fill('i18n-pseudo');
  await page.locator('form.form button.primary').click();
  await expect(page.getByTestId('entry-preview')).toBeVisible();
  expect(await leftovers(page), 'a group checked').toEqual([]);
  await clean(page, sent);
});

test('api_012 pseudo locale leaves no literal text: cluster', async ({ page }) => {
  const sent = await watch(page);
  await page.route('**/api/v1/cluster', (r) => r.fulfill({ json: CLUSTER }));
  await page.route('**/api/v1/cluster/nodes/**', (r) =>
    r.fulfill({ json: { automaticFailoverAfter: false, eligible: true, ephemeral: false, heldClusterKey: false, nodeId: 'n-bbbb2222', notes: [], removed: false, site: 'pi', up: true, votersAfter: 1, witness: false } }),
  );
  await page.route('**/api/v1/nodes/*/drill**', (r) =>
    r.fulfill({
      json: { baseline: 6, dryRun: true, handover: 'none', id: 'd-1', node: 'n-bbbb2222', note: null, since: T0, until: T0, targets: 'clients', targetsResolved: 1, preview: 'Would stop answering 1 device.', checks: [{ name: 'others', ok: true, detail: 'One other node serves.' }], devices: [{ client: '192.168.1.20', name: 'laptop' }] },
    }),
  );
  await signIn(page);
  await open(page, '/cluster', '[data-testid="cluster-node"]');
  await page.getByTestId('drill-open-form').first().click();
  await page.getByTestId('drill-clients').fill('192.168.1.20');
  await page.getByTestId('drill-reason').fill('i18n');
  await page.getByTestId('drill-preview-button').click();
  await expect(page.getByTestId('drill-preview')).toBeVisible();
  await page.getByTestId('node-remove-open').first().click();
  await expect(page.getByTestId('node-remove-preview')).toBeVisible();
  await page.getByTestId('maintenance-open').first().click();
  await expect(page.getByTestId('maintenance-form')).toBeVisible();
  expect(await leftovers(page), 'drill, removal and maintenance forms').toEqual([]);
  await clean(page, sent);
});

test('api_012 pseudo locale leaves no literal text: anomalies', async ({ page }) => {
  const sent = await watch(page);
  await page.route('**/api/v1/analytics/anomalies?**', (r) => r.fulfill({ json: FINDINGS }));
  await signIn(page);
  await open(page, '/anomalies', '[data-testid="mute"]');
  await page.getByTestId('mute').first().click();
  await expect(page.getByTestId('mute-similar')).toBeVisible();
  expect(await leftovers(page), 'the mute form').toEqual([]);
  await clean(page, sent);
});

test('api_012 pseudo locale leaves no literal text: settings', async ({ page }) => {
  const sent = await watch(page);
  await signIn(page);
  await open(page, '/settings?tab=system', '[data-testid="support-package"]');
  await page.getByTestId('support-preview').click();
  await expect(page.getByTestId('support-manifest')).toBeVisible();
  expect(await leftovers(page), 'the support package preview').toEqual([]);
  await open(page, '/settings?tab=users', '[data-testid="wall-displays"]');
  await page.getByTestId('display-name').fill('i18n pseudo');
  await page.getByTestId('display-create').click();
  await expect(page.getByTestId('display-link')).toBeVisible();
  expect(await leftovers(page), 'a wall display link').toEqual([]);
  await clean(page, sent);
});

test('api_012 pseudo locale leaves no literal text: heatmap flow and wall', async ({ page }) => {
  const sent = await watch(page);
  await signIn(page);
  await open(page, '/heatmap', 'canvas');
  expect(await leftovers(page), 'heatmap (canvas text included)').toEqual([]);
  await open(page, '/flow', 'h1');
  expect(await leftovers(page), 'flow').toEqual([]);
  await open(page, '/wall', '[data-testid="wall-area"]');
  expect(await leftovers(page), 'wall').toEqual([]);
  await clean(page, sent);
});

// A1c: what the header, the cluster, the cache, the error budget and a device's views show only with
// data a test server does not have (health reasons, plans waiting, drills, a machine, an identity, a
// day, a configuration kept in Git).
const HEALTH = {
  checkedAt: T0, level: 'degraded', missingNodes: ['attic'],
  maintenance: [{ by: 'admin', node: 'pi', reason: 'SD card swap', secondsLeft: 1800, since: T0, until: T0 }],
  reasons: [{ code: 'upstream_down', level: 'degraded', link: '#/upstreams', node: 'pi', summary: 'Upstream quad9 does not answer.' }],
};
const PLANS = { items: [1, 2].map((i) => ({ id: `p-${i}`, state: 'pending', summary: 's', tool: 't', method: 'POST', path: '/api/v1/rules', reason: 'r', requestedBy: 'agent', needsApproval: true, preview: {}, configVersion: 1, createdUnixSeconds: 0, expiresUnixSeconds: 0 })) };
const row = (key: string, bad: number, exact = true) => ({ key, bad, sharePct: 50, exact, errorMax: exact ? null : 5, name: null });
const BUDGET = {
  objective: 'availability', step: '1h', from: '2026-11-24T10:00:00Z', to: T0, note: null, missingNodes: ['attic'],
  budget: { allowedBad: 500, answered: 100_000, bad: 560, remainingPct: -12, targetPct: 99.5 },
  byClient: [row('192.168.1.20', 300, false)], byName: [row('ads.example.com', 200, false)], byNode: [], byRcode: [row('SERVFAIL', 560)], byStatus: [row('servfail', 560)], byUpstream: [row('quad9', 400), row('none', 160)],
  coverage: { approximate: true, hidden: ['names_hidden'], partialNodes: ['pi'], topListsFromHours: 24 },
  timeline: ['homelab', 'pi'].flatMap((node) => [0, 1, 2].map((i) => ({ answered: 1000, bad: 10, budgetSpentPct: 2, node, start: T0, startUnixSeconds: 1_764_021_600 + i * 3600 }))),
};
const DRILL = { by: 'admin', coveragePercent: 80, elsewhere: 0, ended: T0, followed: 1, id: 'd-1', medianFailoverMs: 2300, missingNodes: [], node: 'pi', p90FailoverMs: 4100, quiet: 1, reason: 'monthly', since: T0, status: 'complete', stuck: 1, targets: 'everyone', until: T0, viaBalancer: true };
const DRILLS = { items: [{ ...DRILL, id: 'd-r', status: 'running' }, DRILL, { ...DRILL, id: 'd-c', status: 'cancelled' }], missingNodes: ['attic'] };
const REPORT = {
  ...DRILL, balancerSwitchMs: 3400, baseline: 6, overflow: 0, missingNodes: ['attic'], nodes: [{ node: 'pi', queries: 3, devices: 1 }],
  devices: [
    { client: '192.168.1.20', dropped: 4, group: 'default', name: null, nodes: [], queriesElsewhere: 1, returned: false, timeToFailoverMs: 2100, verdict: 'followed' },
    { client: '192.168.1.21', dropped: 9, group: null, name: null, nodes: [], queriesElsewhere: 0, returned: null, timeToFailoverMs: null, verdict: 'stuck' },
  ],
};
const HOST = {
  history: [],
  latest: {
    arch: 'aarch64', cgroupCpuQuotaCores: 2, cgroupMemLimitBytes: 536_870_912, cgroupMemUsedBytes: 314_572_800, cgroupMemUsedPercent: 58.6, clockOffsetMs: 3200, cpuPercent: 93, cpus: 4,
    diskFreeBytes: 2e9, diskTotalBytes: 3e10, diskUsedPercent: 93, hostUptimeSeconds: 864_000, kernel: '6.6.31', load1: 3.2, load5: 2.1, load15: 1.4, maxFds: 1024, memAvailableBytes: 1e9,
    memTotalBytes: 4e9, memUsedPercent: 75, oomKills: 2, openFds: 96, os: 'Debian GNU/Linux 12', processRssBytes: 8e7, qlogBytes: 9e8, sampledAt: T0, snapshotBytes: 1.2e7, swapTotalBytes: 1e9,
    swapUsedBytes: 1e8, temperatureC: 81.5, threads: 12, throttledPercent: 12.5, unavailable: ['process', 'thermal'], warnings: ['The data disk is nearly full.'], writeBytesPerSecond: 20_480,
  },
};
// How the machine card writes the host's operating system, architecture and kernel: the mock's values and the word Linux.
const HOST_LINE = `${HOST.latest.os} · ${HOST.latest.arch} · Linux ${HOST.latest.kernel}`;
const IDENTITY = { available: true, class: 'speaker', client: '127.0.0.1', level: 'likely', product: 'Echo Dot', score: 0.8, source: 'fingerprint', suggestedGroup: 'IoT', vendor: 'Amazon' };
const EVIDENCE = { domains: [{ name: 'amazon.com', weight: 1 }], macPrefix: 'a4:5e:60', matchedName: 'Echo-Kitchen', names: [], runnerUp: { product: 'Echo Show', productId: 'x', score: 0.4 }, seenDomains: [] };
const DAY = (() => {
  const t0 = Math.floor(Date.now() / 1000 / 3600) * 3600 - 23 * 3600;
  const bins = Array.from({ length: 24 }, (_, i) => t0 + i * 3600);
  const iso = (u: number) => new Date(u * 1000).toISOString();
  const lane = (domain: string | null, other = false) => ({ domain, other, counts: bins.map((_, i) => i % 3), blocked: bins.map((_, i) => (i % 5 ? 0 : 1)), slow: bins.map((_, i) => (i % 2 ? 1 : 0)), total: 24, blockedTotal: 5, firstSeenTime: domain ? iso(t0 + 3600) : null });
  return {
    client: '127.0.0.1', from: iso(t0), to: iso(t0 + 24 * 3600), binSeconds: 3600, bins, source: 'querylog', truncated: true, truncatedReason: 'row limit', coverageFrom: iso(t0 + 7200),
    lanes: [lane('example.com'), lane(null), lane(null, true)], queries: bins.map(() => 5), p99Ms: bins.map((_, i) => (i % 4 ? 12 : null)),
    events: [{ time: iso(t0 + 3600), timeUnixSeconds: t0 + 3600, kind: 'firstSeen', summary: 'first query to example.com', href: '#/queries', domain: 'example.com' }],
    markers: [],
  };
})();

test('api_012 pseudo locale leaves no literal text: health, agent inbox, help and notes', async ({ page }) => {
  const sent = await watch(page);
  await page.route('**/api/v1/system/health', (r) => r.fulfill({ json: HEALTH }));
  await page.route('**/api/v1/plans', (r) => r.fulfill({ json: PLANS }));
  await signIn(page);
  await open(page, '/', '[data-testid="agent-inbox"]');
  await page.getByTestId('health-icon').click();
  await expect(page.getByTestId('health-maintenance')).toBeVisible();
  expect(await leftovers(page), 'the header pill and the health panel').toEqual([]);
  await page.keyboard.press('Escape');
  await page.locator('button[data-help="how-it-works"]').first().click();
  await expect(page.getByTestId('help-panel')).toBeVisible();
  expect(await leftovers(page), 'a help panel').toEqual([]);
  await page.keyboard.press('Escape');
  await page.getByTestId('note-open').click();
  await expect(page.getByTestId('note-form')).toBeVisible();
  expect(await leftovers(page), 'the note form').toEqual([]);
  await clean(page, sent);
});

test('api_012 pseudo locale leaves no literal text: cache explain and the error budget', async ({ page }) => {
  const sent = await watch(page);
  const entry = (answers: number, ttl: number) => ({ ageSeconds: 1, answers, authentic: answers === 1, bytes: 90, checkingDisabled: false, dnssecOk: true, hits: 2, node: null, qtype: 'A', rcode: 'NOERROR', ttlLeftSeconds: ttl });
  await page.route('**/api/v1/cache/lookup?**', (r) => r.fulfill({ json: { name: 'i18n.example', entries: [entry(1, 30), entry(2, -5)] } }));
  await page.route('**/api/v1/cache/flush', (r) => r.fulfill({ json: { totalRemoved: 2, nodes: [{ node: 'pi', removed: null, error: 'not reachable' }] } }));
  await page.route('**/api/v1/stats/slo/attribution?**', (r) => r.fulfill({ json: BUDGET }));
  await signIn(page);
  await open(page, '/cache', '[data-testid="cache-card"]');
  await page.locator('[data-testid="cache-card"] form input').fill('i18n.example');
  await page.locator('[data-testid="cache-card"] form button').click();
  await expect(page.getByTestId('cache-entries')).toBeVisible();
  await page.locator('[data-testid="cache-card"] div.row button').first().click();
  await expect(page.getByTestId('cache-flushed')).toBeVisible();
  expect(await leftovers(page), 'a cache lookup and flush').toEqual([]);
  await open(page, '/explain?name=ads.e2e.test&client=127.0.0.1', '[data-testid="explain-flow"]');
  expect(await leftovers(page), 'an explanation and its diagram').toEqual([]);
  await open(page, '/analyze?tab=budget', '[data-testid="budget-summary"]');
  // The lists show the server's words (a status, an answer code, the upstream a query had none of) as they are.
  expect(await leftovers(page), 'the error budget with its lists as bars').toEqual([]);
  await page.locator('[data-testid="by-client"] button.link').click();
  await page.locator('[data-testid="by-upstream"] button.link').click();
  await page.locator('[data-testid="budget-attribution"] section.chart .card-head button.link').first().click();
  expect(await leftovers(page), 'the error budget, two lists and a chart as tables').toEqual([]);
  await clean(page, sent);
});

test('api_012 pseudo locale leaves no literal text: drills and a machine', async ({ page }) => {
  const sent = await watch(page);
  declare(HOST_LINE);
  await page.route('**/api/v1/cluster', (r) => r.fulfill({ json: CLUSTER }));
  await page.route('**/api/v1/drills?**', (r) => r.fulfill({ json: DRILLS }));
  await page.route('**/api/v1/drills/d-1', (r) => r.fulfill({ json: REPORT }));
  await page.route('**/api/v1/nodes/pi/drill', (r) => r.fulfill({ json: { by: 'admin', devicesDropped: 2, dropped: 40, id: 'd-r', node: 'pi', reason: 'monthly', secondsLeft: 90, since: T0, targets: 'everyone', until: T0 } }));
  await signIn(page);
  await open(page, '/cluster?tab=drills', '[data-testid="drill-counters"]');
  await page.getByTestId('drill-open').first().click();
  await expect(page.getByTestId('drill-report')).toBeVisible();
  expect(await leftovers(page), 'running drills, the list and a report').toEqual([]);
  await page.unroute('**/api/v1/cluster');
  await page.route('**/api/v1/cluster', (r) => r.fulfill({ json: { ...CLUSTER, enabled: false, host: HOST } }));
  await open(page, '/cluster', '[data-testid="host-card"]');
  expect(await leftovers(page), "a node's machine").toEqual([]);
  await clean(page, sent);
});

test('api_012 pseudo locale leaves no literal text: a device and a change kept in git', async ({ page }) => {
  const sent = await watch(page);
  await page.route('**/api/v1/clients/identities', (r) => r.fulfill({ json: { items: [IDENTITY] } }));
  await page.route('**/api/v1/clients/127.0.0.1/identity', (r) => r.fulfill({ json: { ...IDENTITY, evidence: EVIDENCE } }));
  await page.route('**/api/v1/clients/*/timeline*', (r) => r.fulfill({ json: DAY }));
  await page.route('**/api/v1/groups/i18n-git*', (r) =>
    r.request().method() === 'PUT' && !new URL(r.request().url()).searchParams.has('dryRun')
      ? r.fulfill({ json: { applied: true, keepInGit: '[[groups]]\nname = "i18n-git"\n', warnings: [] } })
      : r.fallback(),
  );
  await signIn(page);
  await open(page, '/clients', '[data-testid="identity-line"]');
  await page.locator('[data-testid="identity-line"] button.link').first().click();
  await expect(page.locator('[data-testid="identity-line"] ul.why')).toBeVisible();
  expect(await leftovers(page), "a device's identity and why").toEqual([]);
  await open(page, '/clients?device=127.0.0.1&view=timeline', '[data-testid="timeline-canvas"]');
  const box = (await page.getByTestId('timeline-canvas').boundingBox())!;
  await page.mouse.move(box.x + box.width / 2, box.y + 9);
  await expect(page.getByTestId('timeline-tip')).toBeVisible();
  expect(await leftovers(page), "a device's day and a lane's tip").toEqual([]);
  await page.mouse.move(box.x + box.width / 2, box.y + 3 * 18 + 15);
  await expect(page.getByTestId('timeline-tip')).toBeVisible();
  expect(await leftovers(page), 'the latency lane tip').toEqual([]);
  await page.getByTestId('timeline-table-toggle').click();
  await expect(page.getByTestId('timeline-table')).toBeVisible();
  expect(await leftovers(page), "a device's day as a table").toEqual([]);
  await open(page, '/groups', '[data-testid="editor-group"]');
  await page.locator('[data-testid="editor-group"] .head > button').click();
  await page.locator('form.form input.mono').first().fill('i18n-git');
  await page.locator('form.form button.primary').click();
  await expect(page.getByTestId('entry-preview')).toBeVisible();
  await page.locator('form.form button.primary').click();
  await expect(page.getByTestId('keep-in-git')).toBeVisible();
  expect(await leftovers(page), 'a change to keep in Git').toEqual([]);
  await clean(page, sent);
});

// A1d: what the service level, the latency heatmap, the wall's panels, the cluster's topology,
// comparison and rollouts, the pause control, the simulation card and the rhythm strip show only with
// data a test server does not have.
const NOW = Math.floor(Date.now() / 1000);
const BOUNDS = [250, 500, 1000, 2000, 4000, 8000, 16_000, 32_000, 64_000, 125_000, 250_000, 500_000, 1_000_000, 2_000_000, 3_000_000, 5_000_000];
const HEAT_STARTS = Array.from({ length: 30 }, (_, i) => NOW - (30 - i) * 60);
const HEAT = (by: string, names: string[]) => ({
  boundsUs: BOUNDS, by, from: T0, missingNodes: ['attic'], partial: true, step: 'minute', to: T0, starts: HEAT_STARTS,
  series: Object.fromEntries(names.map((n, k) => [n, HEAT_STARTS.map((_, c) => Array.from({ length: 17 }, (__, r) => Math.max(0, Math.round(40 * Math.exp(-((r - 3 - 2 * k) ** 2) / 5) * (1.2 + Math.sin(c / 4)))))) ])),
});
const EXEMPLARS = { missingNodes: [], items: [{ latencyUs: 120_000, node: null, path: 'upstream', time: T0, traceId: 'a'.repeat(32), tsUnixMicros: (NOW - 600) * 1e6, upstream: 'quad9' }, { latencyUs: 900, node: null, path: 'cache', time: T0, traceId: 'b'.repeat(32), tsUnixMicros: (NOW - 300) * 1e6, upstream: null }] };
const burn = (window: string, rate: number | null) => ({ window, rate, bad: 12, total: rate == null ? 0 : 1000 });
const objective = (o: Record<string, unknown>) => ({ alert: null, budgetRemainingPercent: 62.4, name: 'availability', good: 99_900, goodMeans: "answers that aren't SERVFAIL", latencyMs: null, sliPercent: 99.912, summary: 'x', targetPercent: 99.9, total: 100_000, burnRates: [burn('5m', 0.4), burn('1h', 1.2), burn('3d', null)], ...o });
const SLO = {
  enabled: true, windowDays: 30, missingNodes: ['attic'],
  objectives: [objective({ alert: 'fast', budgetRemainingPercent: 12.5 }), objective({ name: 'latency', alert: 'ticket', budgetRemainingPercent: -3, latencyMs: 50 }), objective({ name: 'custom-slo', alert: 'slow', budgetRemainingPercent: null, sliPercent: null, total: 0 })],
};
const SUMMARY = (to: boolean) => ({ activeClients: 12, blocked: 5000, blockedPercent: 20, cacheHitPercent: 62, cached: 12_000, forwarded: 8000, fromUnixSeconds: NOW - 3600, latency: [], missingNodes: [], nxdomain: 300, queries: to ? 10 : 25_000, refreshed: 100, servfail: 40, toUnixSeconds: NOW });
const ATTRIBUTION = {
  objective: 'availability', step: '1h', from: T0, to: T0, note: null, missingNodes: [], budget: { allowedBad: 500, answered: 100_000, bad: 300, remainingPct: 40, targetPct: 99.5 },
  byClient: [{ key: '192.168.1.20', bad: 3000, sharePct: 53.6, exact: true, errorMax: null, name: 'laptop' }], byName: [], byNode: [], byRcode: [], byStatus: [], byUpstream: [],
  coverage: { approximate: false, hidden: [], partialNodes: [], topListsFromHours: 24 }, timeline: [],
};
const fnode = (stage: string, name: string, count: number) => ({ count, deadEnd: 0, id: `${stage}:${name}`, name, stage });
const flink = (a: string, b: string, count: number, failure = false) => ({ count, failure, source: a, target: b });
const FLOW = {
  from: T0, to: T0, total: 1200, missingNodes: [],
  nodes: [fnode('group', 'default', 1000), fnode('group', 'tv', 2), fnode('status', 'cached', 500), fnode('status', 'forwarded', 600), fnode('upstream', 'quad9', 400), fnode('rcode', 'NOERROR', 1100), fnode('rcode', 'SERVFAIL', 20)],
  links: [flink('group:default', 'status:cached', 400), flink('group:default', 'status:forwarded', 600), flink('group:tv', 'status:cached', 2), flink('status:forwarded', 'upstream:quad9', 400), flink('upstream:quad9', 'rcode:NOERROR', 380), flink('upstream:quad9', 'rcode:SERVFAIL', 20, true), flink('status:cached', 'rcode:NOERROR', 500)],
};

test('api_012 pseudo locale leaves no literal text: service level, latency heatmap and the wall', async ({ page }) => {
  const sent = await watch(page);
  await page.addInitScript(() => localStorage.setItem('telltale.mode.admin', 'advanced'));
  await page.route(/\/api\/v1\/stats\/slo(\?.*)?$/, (r) => r.fulfill({ json: SLO }));
  await page.route('**/api/v1/stats/slo/attribution?**', (r) => r.fulfill({ json: ATTRIBUTION }));
  await page.route('**/api/v1/stats/summary?**', (r) => r.fulfill({ json: SUMMARY(new URL(r.request().url()).searchParams.has('to')) }));
  await page.route('**/api/v1/stats/latency/heatmap?**', (r) => r.fulfill({ json: HEAT('path', ['cache', 'upstream', 'local', 'synthesized']) }));
  await page.route('**/api/v1/stats/latency/exemplars?**', (r) => r.fulfill({ json: EXEMPLARS }));
  await page.route('**/api/v1/stats/flow?**', (r) => r.fulfill({ json: FLOW }));
  await signIn(page);
  const drawn = () => page.evaluate(() => (window as unknown as { __i18aCanvas: string[] }).__i18aCanvas.length);
  await open(page, '/?view=legacy', '[data-testid="slo-card"]');
  await expect(page.getByTestId('slo-availability')).toBeVisible();
  expect(await leftovers(page), 'the tiles with a change, and the service level card').toEqual([]);
  const before = await drawn();
  await page.getByTestId('time-heatmap-tab').click();
  await expect(page.getByTestId('exemplar').first()).toBeVisible();
  await expect.poll(drawn).toBeGreaterThan(before);
  await page.getByTestId('latency-heatmap-canvas').hover({ position: { x: 300, y: 40 } });
  await expect(page.locator('[data-testid="latency-heatmap"] .tip')).toBeVisible();
  expect(await leftovers(page), 'the latency heatmap, its canvas text, a tip and the dots').toEqual([]);
  await page.locator('[data-testid="latency-heatmap"] button.link').click();
  await expect(page.getByTestId('latency-heatmap-table')).toBeVisible();
  expect(await leftovers(page), 'the latency heatmap as a table').toEqual([]);
  const ready: Record<string, string> = {
    flow: '[data-testid="wall-flow"] svg text',
    slo: '[data-testid="wall-slo"] .who',
    kpi: '[data-testid="wall-kpi"] .tile',
    latency: '[data-testid="wall-latency-canvas"]',
  };
  for (const p of ['flow', 'slo', 'kpi', 'latency']) {
    const had = await drawn();
    await open(page, `/wall?layout=single&panels=${p}`, `[data-testid="wall-panel-${p}"]`);
    await expect(page.locator(ready[p]).first()).toBeVisible();
    if (p === 'latency') await expect.poll(drawn).toBeGreaterThan(had);
    if (p === 'kpi') await expect(page.locator('[data-testid="wall-kpi"] .value').first()).not.toHaveText('–');
    expect(await leftovers(page), `the wall's ${p} panel`).toEqual([]);
  }
  await clean(page, sent);
});

const pnode = (o: Record<string, unknown>) => ({ ...node({}), ...o });
const CLUSTER3 = {
  ...CLUSTER,
  rollout: { canaries: ['n-bbbb2222'], stage: 'canary', version: '3.131', pinned: null },
  nodes: [
    pnode({ nodeId: 'n-aaaa1111', site: 'homelab', role: 'primary', thisNode: true, rttMs: null }),
    pnode({ nodeId: 'n-bbbb2222', site: 'homelab', role: 'secondary', ready: false, maintenance: { by: 'admin', node: 'pi', reason: 'SD card swap', secondsLeft: 1800, since: T0, until: T0 } }),
    pnode({ nodeId: 'n-cccc3333', site: 'attic', role: 'secondary', up: false, connected: false, restarts: 3, configLag: 2 }),
    pnode({ nodeId: 'n-dddd4444', site: 'cloud', role: 'secondary', witness: true }),
    pnode({ nodeId: 'n-ffff6666', site: 'cloud', role: 'emergency primary' }),
    ...Array.from({ length: 8 }, (_, i) => pnode({ nodeId: `n-pod${i}`, site: 'k8s', role: 'secondary', ephemeral: true, pod: `telltaledns-756965cdc7-p${i}`, kubeNode: i < 7 ? 'kube-1' : null })),
  ],
};
const series = (f: (i: number) => number | null) => Array.from({ length: 6 }, (_, i) => f(i));
const compareNode = (o: Record<string, unknown>) => ({
  answered: 120_000, fromCache: 70_000, fromCachePct: 58.3, intervals: { servfailPct: [0.1, 0.4], slowPct: [0.02, 0.2], fromCachePct: [58, 58.6], upstreamFailPct: [0.5, 2.1] },
  label: 'homelab', nodeId: 'n-aaaa1111', p50Us: 800, p99Us: 45_000, qps: 33.4, servfail: 240, servfailPct: 0.2, slow: 120, slowPct: 0.1, thisNode: true, upstreamFailPct: 1.2, upstreamFailures: 12, upstreamQueries: 1000,
  series: { fromCachePct: series((i) => 55 + i), p99Us: series((i) => (i === 2 ? null : 40_000 + i)), qps: series((i) => 30 + i), servfailPct: series(() => 0.2), slowPct: series(() => 0.1), start: series((i) => NOW - i * 300), upstreamFailPct: series((i) => i) },
  ...o,
});
const COMPARE = {
  findings: [
    { detail: 'SERVFAIL 4.2 % against 0.2 % on the other nodes, since 21:05', label: 'pi', level: 'odd', metric: 'servfailPct', nodeId: 'n-bbbb2222', observed: 4.2, others: 0.2, spread: 0.5, oddSince: T0 },
    { detail: 'Upstream failures 12 % looks worse only because it asked upstream 25 times', label: 'attic', level: 'note', metric: 'upstreamFailPct', nodeId: 'n-cccc3333', observed: 12, others: 1.2, spread: 1, oddSince: null },
  ],
  from: T0, to: T0, missingNodes: ['cloud'], partial: true, step: 'hour',
  nodes: [compareNode({}), compareNode({ label: 'pi', nodeId: 'n-bbbb2222', thisNode: false, servfailPct: 4.2, p50Us: null, p99Us: null }), compareNode({ label: 'attic', nodeId: 'n-cccc3333', thisNode: false, answered: 0, intervals: {}, upstreamFailPct: 12 })],
};
const rnode = (n: string, o: Record<string, unknown>) => ({ appliedSeq: 131, canary: false, connected: true, node: n, ready: true, servfailPercent: 0.3, site: 'x', ...o });
const ROLLOUT = {
  bakeEnds: null, bakeSecs: 600, canaries: ['site:pi'], fromPrimary: true, pinned: null, readings: { afterPercent: 0.6, answers: 1200, beforePercent: null, reason: null }, rolloutCanaries: ['n-bbbb2222'],
  secondsLeft: 420, skipped: 'no canary node was online', stable: '3.130', stage: 'canary', started: T0, version: '3.131', waitingSince: null,
  nodes: [rnode('n-aaaa1111', {}), rnode('n-bbbb2222', { canary: true }), rnode('n-cccc3333', { canary: true, ready: false, appliedSeq: 130 }), rnode('n-dddd4444', { connected: false, ready: false })],
};
const version = (v: string, outcome: string, o: Record<string, unknown>) => ({ by: 'homelab', created: T0, current: false, filterVersion: 4, outcome, pinnable: true, pinnedTo: null, readings: null, reason: null, version: v, ...o });
const VERSIONS = { history: 8, items: [version('3.131', 'canary', { current: true, pinnable: false }), version('3.130', 'stable'), version('3.129', 'canary_failed', { readings: { afterPercent: 6, answers: 90, beforePercent: 0.4, reason: 'SERVFAIL rose on the canaries' } }), version('3.128', 'pinned_to', { pinnedTo: '3.124', reason: 'by hand', pinnable: false }), version('3.127', 'new-outcome', {})] };

test('api_012 pseudo locale leaves no literal text: topology, comparison and rollouts', async ({ page }) => {
  const sent = await watch(page);
  declare('SERVFAIL 4.2 % against 0.2 % on the other nodes');
  let pinned = false;
  await page.route('**/api/v1/cluster', (r) => r.fulfill({ json: CLUSTER3 }));
  await page.route('**/api/v1/cluster/compare?**', (r) => r.fulfill({ json: COMPARE }));
  await page.route('**/api/v1/cluster/rollout', (r) =>
    r.fulfill({
      json: pinned
        ? { ...ROLLOUT, stage: 'pinned', version: null, pinned: { by: 'admin', changes: ['lists: changed'], diff: [], reason: 'broke banking', since: T0, to: '3.124' }, readings: { afterPercent: null, answers: 0, beforePercent: null, reason: 'SERVFAIL rose' } }
        : ROLLOUT,
    }),
  );
  await page.route('**/api/v1/cluster/versions', (r) => r.fulfill({ json: VERSIONS }));
  await page.route('**/api/v1/cluster/versions/*/pin?**', (r) => r.fulfill({ json: { changes: ['lists: changed'], configVersion: 1, done: 'would pin', dryRun: true } }));
  await page.route('**/api/v1/cluster/pin?**', (r) => r.fulfill({ json: { changes: [], configVersion: 1, done: 'would unpin', dryRun: true } }));
  await signIn(page);
  await open(page, '/cluster', '[data-testid="cluster-topology"]');
  expect(await leftovers(page), 'the topology, with pods, a witness, a node in maintenance and a node that is down').toEqual([]);
  await open(page, '/cluster?tab=compare', '[data-testid="compare-grid"]');
  expect(await leftovers(page), 'the comparison').toEqual([]);
  await page.getByTestId('compare-table-toggle').click();
  await expect(page.getByTestId('compare-table')).toBeVisible();
  expect(await leftovers(page), 'the comparison as a table').toEqual([]);
  await open(page, '/cluster?tab=rollouts', '[data-testid="rollout-baking"]');
  expect(await leftovers(page), 'a version baking').toEqual([]);
  await page.getByTestId('pin-open').first().click();
  await page.getByTestId('pin-form').locator('input').fill('i18n pseudo');
  await page.getByTestId('pin-check').click();
  await expect(page.getByTestId('pin-preview')).toBeVisible();
  expect(await leftovers(page), 'a pin checked').toEqual([]);
  pinned = true;
  await open(page, '/cluster', '[data-testid="cluster-topology"]');
  await open(page, '/cluster?tab=rollouts', '[data-testid="pin-banner"]');
  await page.getByTestId('unpin').click();
  await expect(page.getByTestId('unpin-confirm')).toBeVisible();
  expect(await leftovers(page), 'the pin banner and an unpin checked').toEqual([]);
  await clean(page, sent);
});

const SIMULATION = (reason: string | null, available = true) => ({
  applicable: true, available, from: T0, to: T0, rows: 12_345, partial: true, unchanged: 12_000, undetermined: 1, missingNodes: ['attic'], reason, notes: ['identity_from_event', 'something_new'],
  newlyBlocked: { devices: 1, queries: 300, topNames: [{ devices: 1, list: 'ads', name: 'ads.example.com', queries: 200 }, { devices: 1, list: null, name: 'one.example.net', queries: 1 }] },
  newlyAllowed: { devices: 3, queries: 40, topNames: [] }, changedRoute: { devices: 2, queries: 2, topNames: [] }, changedAnswer: { devices: 0, queries: 0, topNames: [] },
  byDevice: [{ changedAnswer: 0, changedRoute: 1, client: '192.168.1.20', name: 'laptop', newlyAllowed: 20, newlyBlocked: 100 }, { changedAnswer: 3, changedRoute: 0, client: '192.168.1.21', name: null, newlyAllowed: 0, newlyBlocked: 0 }], byGroup: [],
});
const BEACON = (id: string, kind: string) => ({
  acknowledged: null, baseline: 40, client: '127.0.1.11', clientName: null, detail: 'Asks for beacon.example.net every 38 seconds.', domain: 'beacon.example.net', id, informational: false, kind,
  mutedBy: null, nodes: [], observed: 900, rhythm: Array.from({ length: 24 }, (_, i) => Math.round(200 * Math.exp(-((i - 9) ** 2)))), spread: 12, stormMute: null, threshold: 200, windowSeconds: 3600, windowStart: T0,
});
const rdom = (domain: string, o: Record<string, unknown>) => ({
  domain, dominantBin: 9, dominantSharePct: 62, hour: Array.from({ length: 24 }, (_, i) => Math.round(30 * Math.exp(-((i - 9) ** 2)))), knownPeriodic: false, meanPerHour: 60, nodes: [], period: 'every 38 s',
  recent: Array.from({ length: 24 }, (_, i) => Math.round(300 * Math.exp(-((i - 9) ** 2)))), regularHours: 0, since: T0, ...o,
});
const RHYTHM = {
  available: true, client: '127.0.1.11', missingNodes: [], reason: null,
  binsS: [1, 1.5, 2.2, 3.3, 5, 7.5, 11, 17, 25, 38, 56, 84, 126, 190, 285, 427, 640, 960, 1440, 2160, 3240, 4860, 7290],
  domains: [rdom('time.example.com', { knownPeriodic: true }), rdom('beacon.example.net', { regularHours: 5 }), rdom('www.example.org', { period: null })],
};

test('api_012 pseudo locale leaves no literal text: pause, simulation and rhythm', async ({ page }) => {
  const sent = await watch(page);
  await page.route('**/api/v1/analytics/anomalies?**', (r) => r.fulfill({ json: { items: [BEACON('f-b', 'beacon'), BEACON('f-c', 'chatty_loop')] } }));
  await page.route('**/api/v1/clients/*/rhythm', (r) => r.fulfill({ json: RHYTHM }));
  const reasons = ['disabled', 'privacy_level', 'no_query_log', 'busy', 'local_file', 'download_limit', 'unheard_of', null];
  let call = 0;
  await page.route('**/api/v1/rules/*?**', (r) => {
    const url = new URL(r.request().url());
    if (r.request().method() !== 'PUT' || !url.searchParams.has('simulate')) return r.fallback();
    const n = call++;
    return r.fulfill({ json: { applied: false, preview: null, simulation: n === 0 ? SIMULATION(null) : SIMULATION(reasons[(n - 1) % reasons.length], false), warnings: [] } });
  });
  await signIn(page);
  await open(page, '/', '[data-testid="stat-queries"]');
  await page.locator('.pause-menu button.icon-btn').click();
  await expect(page.locator('.pause-menu [role="menu"]')).toBeVisible();
  expect(await leftovers(page), 'the pause menu').toEqual([]);
  // The control reads the pauses when it starts (and every 15 s): each state is a new page load.
  const paused = async (pauses: { group: string | null; secondsLeft: number }[], ready: string, what: string) => {
    await page.unroute('**/api/v1/blocking');
    await page.route('**/api/v1/blocking', (r) => r.fulfill({ json: { items: [{ node: 'pi', pauses: pauses.map((p) => ({ ...p, until: T0 })) }] } }));
    await page.reload();
    await expect(page.locator(ready)).toBeVisible();
    expect(await leftovers(page), what).toEqual([]);
  };
  await paused([{ group: 'kids', secondsLeft: 900 }, { group: 'guests', secondsLeft: 900 }], '[data-testid="groups-paused"]', 'two groups paused');
  await paused([{ group: 'kids', secondsLeft: 900 }], '[data-testid="groups-paused"]', 'one group paused');
  for (const secs of [30, 1500, 5400]) await paused([{ group: null, secondsLeft: secs }], '[data-testid="blocking-paused"]', `everyone paused for ${secs} s`);
  await page.unroute('**/api/v1/blocking');
  await page.reload();
  await expect(page.locator('.pause-menu button.icon-btn')).toBeVisible();
  await open(page, '/rules', '[data-testid="quick-rule-form"]');
  await page.locator('[data-testid="quick-rule-form"] input.mono').fill('i18n-sim.example.com');
  await page.getByTestId('simulate-button').click();
  await expect(page.getByTestId('simulation-card')).toBeVisible();
  expect(await leftovers(page), 'a simulation').toEqual([]);
  for (let i = 0; i < reasons.length; i++) {
    await page.getByTestId('simulate-button').click();
    await expect(page.getByTestId('simulation-unavailable')).toBeVisible();
    expect(await leftovers(page), `a simulation that could not run (${reasons[i]})`).toEqual([]);
  }
  await open(page, '/anomalies', '[data-testid="rhythm"]');
  expect(await leftovers(page), "a beacon's rhythm").toEqual([]);
  await open(page, '/clients?device=127.0.1.11', '[data-testid="rhythm-row"]');
  expect(await leftovers(page), "a device's rhythm").toEqual([]);
  await page.locator('[data-testid="rhythm"] .seg button').last().click();
  await page.getByTestId('rhythm-table-toggle').click();
  await expect(page.getByTestId('rhythm-table')).toBeVisible();
  expect(await leftovers(page), "a device's rhythm as a table").toEqual([]);
  await clean(page, sent);
});

test('api_012 pseudo text never reaches a request or storage: the shared forms', async ({ page }) => {
  // The forms above that write (a quick rule, a group checked, a wall display, a drill preview, a
  // mute preview) each ran under the pseudo-locale with their requests and storage watched; this one
  // names a device, whose body carries the name and kind typed in, never their labels.
  const sent = await watch(page);
  await signIn(page);
  await open(page, '/queries', 'table.log tbody tr');
  await page.locator('table.log button.chip-button').first().click();
  await page.locator('.chip .menu [role="menuitem"]').first().click();
  await expect(page.locator('.drawer').first()).toBeVisible();
  const form = page.locator('.drawer form.stack');
  if (await form.count()) {
    await form.locator('select').first().selectOption('phone');
    await form.locator('input[name="device-name"]').fill('i18n pseudo device');
    await form.locator('button.primary[type="submit"]').click();
    await expect(page.locator('.drawer .notice.ok')).toBeVisible();
  }
  expect(await leftovers(page), 'the device drawer').toEqual([]);
  await clean(page, sent);
  expect(sent.some((s) => s.startsWith('PUT ') && s.includes('/api/v1/clients/')) || !(await form.count()), 'a device was saved').toBe(true);
});

// A1e: what the dashboards, the query log, the traffic map, the rhythm heatmap, the flow, Analyze,
// Explain and the anomalies show only with data a one-node test server does not have (a cluster,
// groups, partial answers, a query log of every status, a heatmap of days, a flow that folds, a long
// query's answers, a finding of every kind).
const problem = (status: number, detail: string) => ({ status, json: { type: 'about:blank', title: detail, status, code: 'internal', detail } });
const lrow = (key: string, count: number, p50: number, p90: number, p99: number, max: number) => ({ key, count, p50Ms: p50, p90Ms: p90, p99Ms: p99, p999Ms: max, maxMs: max });
const LATENCY = {
  path: [lrow('cache/udp', 8000, 0.2, 0.4, 0.9, 3), lrow('upstream/udp', 2500, 14, 41, 90, 210), lrow('upstream/doh', 120, 30, 80, 150, 300), lrow('synthesized/tcp', 300, 0.1, 0.2, 0.4, 2), lrow('mystery', 4, 1, 2, 3, 4)],
  stage: [lrow('upstream', 2500, 12, 38, 80, 200), lrow('filter', 9000, 0.05, 0.1, 0.2, 0.5)],
};
const DASH_BUCKETS = (step: number) => {
  const last = Math.floor(Date.now() / 1000 / step) * step;
  return Array.from({ length: 40 }, (_, i) => {
    const total = 200 + ((i * 37) % 90);
    return {
      startUnixSeconds: last - (39 - i) * step, total, byStatus: { blocked: Math.round(total * 0.2), cached: Math.round(total * 0.5), forwarded: Math.round(total * 0.25), stale: 3, local: 2 },
      byQtype: { A: total }, byRcode: { NOERROR: total }, upstreamQueries: Math.round(total * 0.25), upstreamFailures: i % 7 === 0 ? 2 : 0,
      byGroup: { default: Math.round(total * 0.6), kids: Math.round(total * 0.4) }, blockedByGroup: { kids: 10 }, slow: 1,
    };
  });
};
const topItem = (key: string, count: number, o: Record<string, unknown> = {}) => ({ key, count, errorBound: 0, ...o });
const DASH_TOP: Record<string, unknown[]> = {
  domains: [topItem('ads.example.com', 900), topItem('cdn.example.net', 700)],
  internal: [topItem('nas.lan', 300)],
  blocked: [topItem('track.example.net', 330)],
  clients: [topItem('192.168.1.20', 1500, { name: 'work-pc', groups: ['default', 'kids'], byStatus: { blocked: 500, cached: 600, forwarded: 300 } })],
};
const UPSTREAMS = { items: [{ id: 1, name: 'quad9', breaker: 'closed', requests: 600, latencyEwmaMs: 21, failures: 0 }, { id: 2, name: 'cloudflare', breaker: 'open', requests: 200, latencyEwmaMs: 48, failures: 12 }] };

test('api_012 pseudo locale leaves no literal text: both dashboards, with a cluster, groups, partial answers and no data', async ({ page }) => {
  const sent = await watch(page);
  await page.addInitScript(() => localStorage.setItem('telltale.mode.admin', 'advanced'));
  type Phase = 'full' | 'partial' | 'empty' | 'error';
  let phase = 'full' as Phase;
  const answer = (r: Route, full: unknown, empty: unknown = { items: [] }) => r.fulfill({ json: phase === 'empty' ? empty : full });
  await page.route('**/api/v1/cluster', (r) => r.fulfill({ json: CLUSTER3 }));
  await page.route('**/api/v1/groups', (r) => r.fulfill({ json: { items: [{ name: 'default', color: '#4c9ffe' }, { name: 'kids', color: '#e8590c' }] } }));
  await page.route('**/api/v1/clients/identities', (r) => answer(r, { items: [{ client: '192.168.1.20', class: 'phone' }, { client: '192.168.1.22', class: 'tv' }] }));
  await page.route(/\/api\/v1\/stats\/slo(\?.*)?$/, (r) => r.fulfill({ json: SLO }));
  await page.route('**/api/v1/stats/summary?**', (r) => {
    const to = new URL(r.request().url()).searchParams.has('to');
    if (phase === 'error') return r.fulfill(problem(500, 'the statistics store is busy'));
    if (phase === 'empty') return r.fulfill({ json: { ...SUMMARY(to), queries: 0, blocked: 0, blockedPercent: 0, cacheHitPercent: 0, cached: 0, forwarded: 0, activeClients: 0, nxdomain: 0, servfail: 0 } });
    return r.fulfill({ json: { ...SUMMARY(to), latency: LATENCY.path, missingNodes: phase === 'partial' ? ['attic', 'pi'] : [] } });
  });
  await page.route('**/api/v1/stats/timeseries?**', (r) => {
    const step = { second: 1, minute: 60, hour: 3600 }[new URL(r.request().url()).searchParams.get('step') ?? 'minute'] ?? 60;
    return answer(r, { items: DASH_BUCKETS(step) });
  });
  await page.route('**/api/v1/stats/top?**', (r) => answer(r, { items: DASH_TOP[new URL(r.request().url()).searchParams.get('kind') ?? 'domains'] ?? [] }));
  await page.route('**/api/v1/upstreams', (r) => answer(r, UPSTREAMS));
  await page.route('**/api/v1/stats/latency?**', (r) => answer(r, { items: LATENCY[new URL(r.request().url()).searchParams.get('by') === 'stage' ? 'stage' : 'path'] }));
  await page.route('**/api/v1/stats/latency/heatmap?**', (r) => r.fulfill({ json: HEAT('path', ['cache', 'upstream', 'local', 'synthesized']) }));
  await page.route('**/api/v1/stats/latency/exemplars?**', (r) => r.fulfill({ json: EXEMPLARS }));
  await signIn(page);
  const nodes = page.locator('.page .pill-field select').first();
  await open(page, '/', '[data-testid="stat-queries"]');
  await expect(page.getByTestId('slo-availability')).toBeVisible();
  await expect(page.locator('table.times tbody tr').first()).toBeVisible();
  await expect(page.getByTestId('devices-by-type')).toBeVisible();
  await expect(nodes).toBeVisible();
  expect(await leftovers(page), 'the dashboard, advanced: service level, where time goes, upstreams, lists, clients by type').toEqual([]);
  await nodes.selectOption('site:k8s');
  await page.locator('.views button').last().click();
  expect(await leftovers(page), 'a site chosen, the upstream exchanges chart').toEqual([]);
  await nodes.selectOption('node:n-bbbb2222');
  await page.getByTestId('domains-internal-tab').click();
  await page.getByTestId('time-heatmap-tab').click();
  await expect(page.getByTestId('latency-heatmap')).toBeVisible();
  expect(await leftovers(page), 'another node chosen, internal names, the latency heatmap').toEqual([]);
  await open(page, '/?view=legacy', '[data-testid="slo-card"]');
  await expect(page.getByTestId('client-split').first()).toBeVisible();
  expect(await leftovers(page), 'the previous dashboard, advanced').toEqual([]);
  const states: [Phase, string, string][] = [
    ['partial', '.notice.warn', 'partial answers'],
    ['empty', '.empty', 'no data'],
    ['error', '[role="alert"]', 'an error'],
  ];
  for (const [p, ready, what] of states) {
    phase = p;
    for (const hash of ['/?view=legacy', '/?view=new']) {
      await open(page, hash, '[data-testid="stat-queries"], .kpis');
      await page.reload();
      await expect(page.locator(ready).first()).toBeVisible();
      expect(await leftovers(page), `${hash}: ${what}`).toEqual([]);
    }
  }
  await clean(page, sent);
});

const QROW = (i: number, o: Record<string, unknown>) => ({
  answers: 1, client: '192.168.1.20', clientName: 'work-pc', group: 'kids', list: 'ads', name: 'blocked.example', node: 'pi', proto: 'udp', qtype: 'A', rcode: null, responseBytes: 64, rule: '||blocked.example^',
  status: 'blocked', time: T0, totalMs: 0.4, tsUnixMicros: Date.parse(T0) * 1000 - i, upstreamMs: 0, ...o,
});
const QROWS = [
  QROW(0, {}),
  QROW(1, { name: 'plain.example', status: 'forwarded', list: null, rule: null, group: null, node: null, totalMs: 38.5, upstreamMs: 35, clientName: null, client: '192.168.1.33' }),
  QROW(2, { name: 'refused.example', status: 'refused', rcode: 'REFUSED', list: null, rule: null, qtype: 'AAAA', totalMs: 0.1 }),
  QROW(3, { name: 'servfail.example', status: 'servfail', rcode: 'SERVFAIL', list: 'shadow', rule: 'rule-9', qtype: 'MX', totalMs: 1200, upstreamMs: 1190 }),
];

test('api_012 pseudo locale leaves no literal text: the query log, filtered, live, empty and failing', async ({ page }) => {
  const sent = await watch(page);
  let mode: 'rows' | 'none' | 'error' = 'rows';
  await page.route('**/api/v1/groups', (r) => r.fulfill({ json: { items: [{ name: 'default', color: '#4c9ffe' }, { name: 'kids', color: '#e8590c' }] } }));
  await page.route('**/api/v1/queries?**', (r) => {
    if (mode === 'error') return r.fulfill(problem(500, 'the log store is being rebuilt'));
    return r.fulfill({
      json: { items: mode === 'none' ? [] : QROWS, nextCursor: mode === 'none' ? null : 'c-2', scanned: { blocksRead: 12, blocksTotal: 340, rowsScanned: 12_000, segments: 5 }, missingNodes: mode === 'none' ? [] : ['attic'] },
    });
  });
  await signIn(page);
  const filters =
    'name=blocked&match=!suffix&client=192.168.1.20&clientNot=true&status=blocked,cached&statusNot=true&qtype=A&qtypeNot=true&rcode=NXDOMAIN&rcodeNot=true&minLatencyMs=5&from=-1h&group=kids';
  await open(page, `/queries?${filters}&trace=0af7651916cd43dd8448eb211c80319c`, '[data-testid="trace-filter"]');
  await expect(page.locator('table.log tbody tr').first()).toBeVisible();
  await expect(page.locator('.row.foot button')).toBeVisible();
  expect(await leftovers(page), 'the filters, a trace, rows of every status, the footer with a node not reached').toEqual([]);
  await page.locator('table.log tbody tr td:last-child button').first().click();
  await expect(page.locator('.drawer').first()).toBeVisible();
  await expect(page.getByTestId('explain-flow')).toBeVisible();
  expect(await leftovers(page), 'the why drawer of a logged query').toEqual([]);
  await page.keyboard.press('Escape');
  await open(page, `/queries?${filters}`, 'table.log tbody tr');
  await page.locator('.live-toggle input').check();
  await expect(page.locator('.live-toggle .badge')).toBeVisible();
  await expect(page.locator('.notice.warn').first()).toBeVisible();
  expect(await leftovers(page), 'live, with filters it ignores').toEqual([]);
  await page.locator('.live-toggle input').uncheck();
  mode = 'none';
  await open(page, '/queries?name=nothing-matches', '.empty');
  expect(await leftovers(page), 'no query matches').toEqual([]);
  mode = 'error';
  await open(page, '/queries', '[role="alert"]');
  expect(await leftovers(page), 'an error').toEqual([]);
  await clean(page, sent);
});

const TRAFFIC_TOP = (kind: string) =>
  kind === 'blocked'
    ? [topItem('track.example.net', 330), topItem('ads.example.com', 120), topItem('x.ads.example.co.uk', 60)]
    : [
        ...Array.from({ length: 12 }, (_, i) => topItem(`n${i}.streamco.example`, 500 - i * 20)),
        topItem('track.example.net', 430), topItem('ads.example.com', 220), topItem('x.ads.example.co.uk', 90), topItem('www.example.org', 150),
      ];
const HEATMAP = (url: URL) => {
  const grain = url.searchParams.get('grain') ?? '15m';
  const slot = ({ hour: 3600, '15m': 900, minute: 60 } as Record<string, number>)[grain] ?? 900;
  const days = ({ '-24h': 1, '-7d': 7, '-30d': 30, '-90d': 90 } as Record<string, number>)[url.searchParams.get('from') ?? '-7d'] ?? 7;
  const kind = url.searchParams.get('kind') ?? 'network';
  const dayEnd = Math.floor(Date.now() / 1000 / 86400) * 86400 + 86400;
  const n = (days * 86400) / slot;
  const starts = Array.from({ length: n }, (_, i) => dayEnd - (n - i) * slot);
  return {
    covered: kind === 'network' ? null : starts.map((_, i) => i % 9 !== 4), from: T0, grain, key: url.searchParams.get('key'), kind, measure: url.searchParams.get('measure') ?? 'queries',
    missingNodes: ['attic'], precision: kind === 'network' ? 'exact' : 'topList', slotSeconds: slot, starts, to: T0,
    values: starts.map((t, i) => Math.round(40 * (1 + Math.sin(((((t % 86400) / 3600) - 6) / 24) * 2 * Math.PI)) * (1 + (i % 5) / 10))),
  };
};
const FLOW_FOLD = {
  ...FLOW, client: null, partial: false, source: 'buckets', truncated: false,
  nodes: [fnode('group', 'default', 995), fnode('group', 'kids', 198), fnode('group', 'iot', 4), fnode('group', 'tv', 3), fnode('status', 'cached', 500), fnode('status', 'forwarded', 600), fnode('status', 'blocked', 100), fnode('upstream', 'quad9', 400), fnode('rcode', 'NOERROR', 1100), fnode('rcode', 'SERVFAIL', 20)],
  links: [
    flink('group:default', 'status:cached', 400), flink('group:default', 'status:forwarded', 500), flink('group:default', 'status:blocked', 95), flink('group:kids', 'status:cached', 98), flink('group:kids', 'status:forwarded', 100),
    flink('group:iot', 'status:cached', 2), flink('group:iot', 'status:blocked', 2), flink('group:tv', 'status:blocked', 3), flink('status:forwarded', 'upstream:quad9', 400),
    flink('upstream:quad9', 'rcode:NOERROR', 380), flink('upstream:quad9', 'rcode:SERVFAIL', 20, true), flink('status:cached', 'rcode:NOERROR', 500),
  ],
};

test('api_012 pseudo locale leaves no literal text: the traffic map, the rhythm heatmap and the flow, with data', async ({ page }) => {
  const sent = await watch(page);
  await page.route('**/api/v1/services', (r) => r.fulfill({ json: { items: [{ id: 'streamco', name: 'StreamCo', category: 'streaming', domains: [...Array.from({ length: 12 }, (_, i) => `n${i}.streamco.example`)] }] } }));
  await page.route('**/api/v1/stats/top?**', (r) => r.fulfill({ json: { items: TRAFFIC_TOP(new URL(r.request().url()).searchParams.get('kind') ?? 'domains') } }));
  await page.route('**/api/v1/stats/heatmap?**', (r) => r.fulfill({ json: HEATMAP(new URL(r.request().url())) }));
  await page.route('**/api/v1/stats/flow?**', (r) => {
    const client = new URL(r.request().url()).searchParams.get('client');
    return r.fulfill({ json: client ? { ...FLOW_FOLD, client, source: 'querylog', partial: true, truncated: true, missingNodes: ['attic'] } : FLOW_FOLD });
  });
  await signIn(page);
  await open(page, '/traffic', 'a.tile');
  await page.locator('a.tile').first().hover({ position: { x: 5, y: 5 } });
  await expect(page.locator('.details .members')).toBeVisible();
  expect(await leftovers(page), 'the traffic map and a tile with its names').toEqual([]);
  await page.locator('.page-head .seg').first().locator('button').nth(2).click();
  await page.locator('.page-head .pill-field select').selectOption('previous');
  await expect(page.locator('a.tile').first()).toBeVisible();
  expect(await leftovers(page), 'names, the previous hour').toEqual([]);
  const drawn = () => page.evaluate(() => (window as unknown as { __i18aCanvas: string[] }).__i18aCanvas.length);
  const before = await drawn();
  await open(page, '/heatmap', '[data-testid="heatmap-canvas"]');
  await expect.poll(drawn).toBeGreaterThan(before);
  await page.getByTestId('heatmap-canvas').hover({ position: { x: 200, y: 60 } });
  await expect(page.getByTestId('heatmap-tip')).toBeVisible();
  expect(await leftovers(page), 'the heatmap, its canvas text, a cell and the legend').toEqual([]);
  await page.getByTestId('heatmap-fold').check();
  await page.getByTestId('heatmap-canvas').hover({ position: { x: 120, y: 40 } });
  await page.locator('[data-testid="heatmap"] button.link').click();
  await expect(page.getByTestId('heatmap-table')).toBeVisible();
  expect(await leftovers(page), 'a typical week, as a table').toEqual([]);
  await page.locator('[data-testid="heatmap"] button.link').click();
  await open(page, '/heatmap?kind=client&key=192.168.1.20&measure=blocked', '[data-testid="heatmap-canvas"]');
  await expect(page.getByTestId('heatmap-day')).toBeVisible();
  expect(await leftovers(page), "a device's heatmap with its coverage").toEqual([]);
  await open(page, '/heatmap?kind=name', '[data-testid="heatmap-key"]');
  expect(await leftovers(page), 'a name to pick').toEqual([]);
  await open(page, '/flow', '[data-testid="flow-svg"]');
  await expect(page.getByTestId('flow-node').first()).toBeVisible();
  await page.getByTestId('flow-node').first().hover({ position: { x: 3, y: 3 } });
  await expect(page.getByTestId('flow-tip')).toBeVisible();
  expect(await leftovers(page), 'the flow with its small groups folded and a node tip').toEqual([]);
  await page.getByTestId('flow-link').first().focus();
  await page.getByTestId('flow-live').check();
  await expect(page.getByTestId('flow-updated')).toBeVisible();
  await page.getByTestId('flow-table-toggle').click();
  await expect(page.getByTestId('flow-table')).toBeVisible();
  expect(await leftovers(page), 'live, and the flow as a table').toEqual([]);
  await open(page, '/flow?client=192.168.1.20', '[data-testid="flow-partial"]');
  await expect(page.getByTestId('flow-truncated')).toBeVisible();
  expect(await leftovers(page), "a device's flow from the query log, partial and cut short").toEqual([]);
  await clean(page, sent);
});

const VQ = (o: Record<string, unknown>) => ({
  columns: ['name', 'count', 'p95(latency)'], cost: { blocks: 40, elapsedMs: 12, estimatedRows: 20_000, rowsMatched: 3, rowsScanned: 12_000, segments: 5 }, groups: 3, missingNodes: [], note: null,
  query: 'from -24h | top 3 name', rows: [['ads.example.com', 900, 41.5], ['cdn.example.net', 700, null]], source: 'querylog', truncated: false, truncatedReason: null, ...o,
});

test('api_012 pseudo locale leaves no literal text: Analyze and Explain, with answers, estimates and errors', async ({ page }) => {
  const sent = await watch(page);
  await page.route('**/api/v1/analytics/vqlog?**', (r) => {
    const url = new URL(r.request().url());
    const q = url.searchParams.get('q') ?? '';
    if (url.searchParams.get('dryRun') === 'true') return r.fulfill({ json: VQ({ query: q, rows: [], groups: 0, cost: { blocks: 40, elapsedMs: 1, estimatedRows: 20_000, rowsMatched: 0, rowsScanned: 0, segments: 5 } }) });
    if (q.includes('#bad')) return r.fulfill(problem(400, 'unknown stage "frm" at 1'));
    if (q.includes('#none')) return r.fulfill({ json: VQ({ query: q, rows: [], groups: 0 }) });
    if (q.includes('#odd')) return r.fulfill({ json: VQ({ query: q, truncated: true, truncatedReason: 'the scan limit was reached', missingNodes: ['attic'], source: 'rollups', note: 'The window is longer than the log keeps.' }) });
    return r.fulfill({ json: VQ({ query: q }) });
  });
  await signIn(page);
  await open(page, '/analyze?q=from -24h | top 3 name', '[data-testid="vqlog-result"]');
  expect(await leftovers(page), 'a result with its cost').toEqual([]);
  await open(page, '/analyze?q=from -24h | top 3 name&estimate=1', '[data-testid="vqlog-result"]');
  expect(await leftovers(page), 'an estimate').toEqual([]);
  await open(page, '/analyze?q=from -30d | top 1 name %23odd', '[data-testid="vqlog-source"]');
  await expect(page.getByTestId('vqlog-note')).toBeVisible();
  expect(await leftovers(page), 'partial, from the rollups, with a note').toEqual([]);
  await open(page, '/analyze?q=from -24h | where x = y %23none', '.empty');
  expect(await leftovers(page), 'nothing matched').toEqual([]);
  await open(page, '/analyze?q=frm -24h %23bad', '[role="alert"]');
  expect(await leftovers(page), 'an error').toEqual([]);
  await open(page, '/analyze?tab=budget', 'h1');
  expect(await leftovers(page), 'the error budget tab').toEqual([]);
  await page.route('**/api/v1/explain?**', (r) => r.fulfill(problem(400, 'name is not a valid DNS name')));
  await open(page, '/explain?name=bad..name', '[role="alert"]');
  expect(await leftovers(page), 'an explanation that failed').toEqual([]);
  await page.unroute('**/api/v1/explain?**');
  await open(page, '/explain?name=ads.example.com&client=127.0.1.11', '[data-testid="explain-flow"]');
  expect(await leftovers(page), 'an explanation').toEqual([]);
  await clean(page, sent);
});

const FINDING = (id: string, kind: string, o: Record<string, unknown> = {}) => ({ ...BEACON(id, kind), ...o });
const FINDINGS_ALL = {
  items: [
    FINDING('f-1', 'beacon', { clientName: 'work-pc', nodes: ['pi', 'attic'] }),
    FINDING('f-2', 'rate_spike', { domain: null, rhythm: null }),
    FINDING('f-3', 'domain_volume', { informational: true, rhythm: null }),
    FINDING('f-4', 'drift', { domain: null, rhythm: null }),
    FINDING('f-5', 'chatty_loop'),
    FINDING('f-6', 'nxdomain_storm', { domain: null, rhythm: null, windowSeconds: 300 }),
    FINDING('f-7', 'reverse_sweep', { domain: null, rhythm: null, stormMute: 'old-storm-mute', windowSeconds: 86_400 }),
    FINDING('f-8', 'reverse_sweep', { domain: null, rhythm: null, stormMute: 'file-storm-mute', client: '192.168.1.43' }),
    FINDING('f-9', 'dga', { rhythm: null }),
    FINDING('f-10', 'brand_new', { domain: null, rhythm: null }),
    FINDING('f-11', 'beacon', { mutedBy: 'noisy-tv', client: '192.168.1.30', clientName: 'den-tv' }),
    FINDING('f-12', 'drift', { acknowledged: { at: T0, by: 'admin', note: 'looked fine' }, domain: null, rhythm: null }),
    FINDING('f-13', 'drift', { acknowledged: { at: T0, by: 'pi', note: null }, domain: null, rhythm: null }),
  ],
};
const mute = (name: string, source: string, definition: Record<string, unknown>) => ({ kind: 'anomaly_mute', name, source, definition });
const MUTES = {
  items: [
    mute('noisy-tv', 'api', { devices: ['192.168.1.30'], groups: ['kids'], kinds: ['beacon', 'drift'], expires: '2099-01-01T00:00:00Z', note: 'it phones home on purpose' }),
    mute('old-storm-mute', 'api', { groups: ['default'], kinds: ['nxdomain_storm'], expires: '2020-01-01T00:00:00Z' }),
    mute('file-storm-mute', 'file', { devices: ['192.168.1.43'], kinds: ['nxdomain_storm', 'something_else'] }),
  ],
};

test('api_012 pseudo locale leaves no literal text: the anomalies of every kind, their mutes and actions', async ({ page }) => {
  const sent = await watch(page);
  let items: unknown[] = FINDINGS_ALL.items;
  let failing = false;
  await page.route('**/api/v1/analytics/anomalies?**', (r) => r.fulfill({ json: { items } }));
  await page.route('**/api/v1/config/entries?**', (r) => r.fulfill({ json: items.length ? MUTES : { items: [] } }));
  await page.route('**/api/v1/analytics/new-domains?**', (r) =>
    r.fulfill({ json: { items: items.length ? [{ client: '192.168.1.20', clientName: 'work-pc', dgaScore: 0.85, domain: 'xkqjzv.example', time: T0 }, { client: '192.168.1.21', clientName: null, dgaScore: 0.2, domain: 'docs.example.org', time: T0 }] : [] } }),
  );
  await page.route('**/api/v1/analytics/anomalies/acknowledge', (r) => (failing ? r.fulfill(problem(500, 'the acknowledgement could not be stored')) : r.fallback()));
  await page.route('**/api/v1/anomaly-mutes/**', (r) => {
    if (r.request().method() === 'DELETE') return r.fulfill(problem(409, 'the mute is held by the config file'));
    const dry = new URL(r.request().url()).searchParams.get('dryRun') === 'true';
    return r.fulfill({ json: { applied: !dry, configVersion: 5, impact: 'Hides 3 findings from the badge, the alerts and the metrics.', keepInGit: dry ? null : '[[anomaly_mutes]]\nname = "x"\n', warnings: [], recentQueries: 0 } });
  });
  await signIn(page);
  await open(page, '/anomalies', '[data-testid="anomaly"]');
  await expect(page.getByTestId('storm-mute-hint').first()).toBeVisible();
  await expect(page.getByTestId('mutes')).toBeVisible();
  expect(await leftovers(page), 'findings of every kind, a sweep with a mute that no longer covers it, the mutes, new domains').toEqual([]);
  await page.getByTestId('show-acknowledged').check();
  await page.getByTestId('show-muted').check();
  await expect(page.getByTestId('muted').first()).toBeVisible();
  await expect(page.getByTestId('acknowledged').first()).toBeVisible();
  expect(await leftovers(page), 'acknowledged and muted findings shown').toEqual([]);
  await page.getByTestId('show-acknowledged').uncheck();
  await page.getByTestId('show-muted').uncheck();
  failing = true;
  await page.getByTestId('ack-all').click();
  await expect(page.locator('[role="alert"]').first()).toBeVisible();
  await page.getByTestId('remove-storm-mute').click();
  expect(await leftovers(page), 'actions that fail').toEqual([]);
  await page.getByTestId('mute').first().click();
  await expect(page.getByTestId('mute-preview')).toBeVisible();
  await page.getByTestId('mute-save').click();
  await expect(page.getByTestId('mute-saved')).toBeVisible();
  expect(await leftovers(page), 'a mute saved').toEqual([]);
  items = FINDINGS_ALL.items.filter((f) => (f as { id: string }).id === 'f-12' || (f as { id: string }).id === 'f-13');
  await page.reload();
  await expect(page.locator('.empty').first()).toBeVisible();
  expect(await leftovers(page), 'every finding acknowledged').toEqual([]);
  items = FINDINGS_ALL.items.filter((f) => (f as { id: string }).id === 'f-11');
  await page.reload();
  await expect(page.locator('.empty').first()).toBeVisible();
  expect(await leftovers(page), 'one muted finding hidden').toEqual([]);
  items = [];
  await page.reload();
  await expect(page.locator('.empty').first()).toBeVisible();
  expect(await leftovers(page), 'nothing unusual').toEqual([]);
  await clean(page, sent);
});

// A1f: what the Devices and the Filtering & DNS pages show only with data a one-node test server does not
// have (workloads, routers with keys in every state, groups with every line, lists of every state, rules
// of every kind, a quality table, local names and zones) and in the forms that write.
const ITEMS = (items: unknown[], o: Record<string, unknown> = {}) => ({ items, ...o });
const wload = (o: Record<string, unknown>) => ({
  blocked24h: 12, group: 'kids', groupFrom: 'pod_label', key: 'media/deploy/plex', kind: 'deploy', labels: {}, lastSeen: T0, name: 'media/deploy/plex', namespace: 'media',
  pods: [{ name: 'plex-1', addresses: ['10.42.0.5'] }, { name: 'plex-2', addresses: ['10.42.0.6'], terminating: true }], queries24h: 4000, workloadName: 'plex', ...o,
});
const WLOADS = [
  wload({}),
  wload({ key: 'shop/sts/db', name: 'shop/sts/db', namespace: 'shop', kind: 'sts', groupFrom: 'namespace_label', lastSeen: null, pods: [] }),
  wload({ key: 'shop/job/seed', name: 'shop/job/seed', namespace: 'shop', kind: 'job', group: null, groupFrom: 'none' }),
  wload({ key: 'shop/weird/y', name: 'shop/weird/y', namespace: 'shop', kind: 'weird', groupFrom: 'brand_new' }),
];
const ENTRY = (kind: string, name: string, source: string, definition: unknown, credentials: unknown = null) => ({ kind, name, source, definition, credentials });
const ROUTERS = [
  ENTRY('router', 'edge-one', 'added', { type: 'unifi', url: 'https://192.168.1.1' }, { api_key: 'saved' }),
  ENTRY('router', 'edge-two', 'added', { type: 'opnsense', url: 'https://opnsense.lan' }, { api_key: 'missing', api_secret: 'missing' }),
  ENTRY('router', 'edge-three', 'override', { type: 'unifi', url: 'https://10.0.0.1' }, { api_key: 'file_missing' }),
  ENTRY('router', 'edge-four', 'added', { type: 'unifi', url: 'https://10.0.0.2' }, { password: 'not_used' }),
  ENTRY('router', 'edge-five', 'file', { type: 'unifi', url: 'https://10.0.0.3' }, {}),
  ENTRY('router', 'edge-six', 'hidden', null),
];
const GROUP_ENTRIES = [ENTRY('group', 'kids', 'added', { networks: ['192.168.2.0/24'], lists: ['ads', 'porn'] }), ENTRY('group', 'guests', 'override', { lists: ['ads'] }), ENTRY('group', 'plain', 'file', {}), ENTRY('group', 'old', 'hidden', null)];
const SCHEDULE_ENTRIES = [ENTRY('schedule', 'bedtime', 'added', { action: 'block_all', window: [{ days: ['weekdays'], start: '21:00', end: '07:00' }] }), ENTRY('schedule', 'empty', 'file', {})];
const LIST_ENTRIES = [ENTRY('list', 'ads-list', 'added', { url: 'https://example.org/hosts.txt', enabled: false }), ENTRY('list', 'own-list', 'file', { rules: ['ads.example.com'], kind: 'allow' })];
const UPSTREAM_ENTRIES = [ENTRY('upstream', 'quad-nine', 'added', { url: 'tls://9.9.9.9' }), ENTRY('upstream', 'router-up', 'file', {})];
const UPGROUP_ENTRIES = [ENTRY('upstream_group', 'fast-group', 'added', { members: ['quad-nine'], strategy: 'fastest' })];
const entriesOf: Record<string, unknown[]> = { router: ROUTERS, group: GROUP_ENTRIES, schedule: SCHEDULE_ENTRIES, list: LIST_ENTRIES, upstream: UPSTREAM_ENTRIES, upstream_group: UPGROUP_ENTRIES };
const change = (o: Record<string, unknown> = {}) => ({ applied: true, configVersion: 7, impact: 'Changes the configuration as shown.', keepInGit: null, warnings: [], recentQueries: 0, ...o });
const problemH = (status: number, detail: string, hint: string) => ({ status, json: { type: 'about:blank', title: detail, status, code: 'invalid_request', detail, hint } });

/** The editors' answers: the entries by kind, a dry run (the name `warn-…` has warnings, `bad-…` is refused), an apply. */
async function editors(page: Page, failing: { value: boolean } = { value: false }) {
  await page.route('**/api/v1/config/entries?**', (r) => r.fulfill({ json: ITEMS(entriesOf[new URL(r.request().url()).searchParams.get('kind') ?? ''] ?? []) }));
  await page.route(/\/api\/v1\/(routers|groups|schedules|lists|upstreams|upstream-groups)\/[^/]+(\?.*)?$/, (r) => {
    const req = r.request();
    const u = new URL(req.url());
    const name = decodeURIComponent(u.pathname.split('/').pop() ?? '');
    if (req.method() === 'DELETE') return r.fulfill({ json: change({ keepInGit: '[[x]]\nname = "x"\n' }) });
    if (name.startsWith('bad-')) return r.fulfill(problemH(422, `${name}: the address must start with tls:// or https://`, 'Check the address and try again.'));
    const dry = u.searchParams.get('dryRun') === 'true';
    if (!dry && failing.value) return r.fulfill(problem(500, 'the change could not be saved'));
    if (dry) return r.fulfill({ json: change({ applied: false, impact: name.startsWith('warn-') ? 'Adds one entry; nothing else changes.' : '', warnings: name.startsWith('warn-') ? ['A self-signed certificate is not checked.'] : [] }) });
    return r.fulfill({ json: change({ keepInGit: name.startsWith('git-') ? '[[x]]\nname = "x"\n' : null }) });
  });
}
const GROUP_CARDS = {
  items: [
    { blockAnswerIps: [], blockMode: 'null_ip', blockTtlSeconds: 60, blocked24h: 2400, blockedServices: [], color: '#4c9ffe', devicesThisHour: 8, dns64: false, dns64Prefix: null, filterAaaa: false, lists: null, name: 'default', networks: [], pausedUntilUnixSeconds: null, priority: 0, queries24h: 12000, rebindingProtection: false, rewrites: [], safeSearch: false, schedules: [], schedulesOn: [], upstreams: null, youtubeRestrict: null },
    {
      blockAnswerIps: ['203.0.113.0/24'], blockMode: 'nxdomain', blockTtlSeconds: 30, blocked24h: 1500, blockedServices: ['streamco', 'chatapp'], color: '#e8590c', devicesThisHour: 3, dns64: true, dns64Prefix: null, filterAaaa: true, lists: ['ads', 'porn'], name: 'kids',
      networks: ['192.168.2.0/24'], pausedUntilUnixSeconds: Date.parse(T0) / 1000 + 1800, priority: 10, queries24h: 6000, rebindingProtection: true, rewrites: [{ domain: 'nas.lan', answer: '192.168.1.5' }], safeSearch: true, schedules: ['bedtime', 'homework'], schedulesOn: ['bedtime'], upstreams: 'quad9-only', youtubeRestrict: 'moderate',
    },
    { blockAnswerIps: ['10.0.0.0/8'], blockMode: 'null_ip', blockTtlSeconds: 60, blocked24h: 0, blockedServices: [], color: '#2f9e44', devicesThisHour: 0, dns64: true, dns64Prefix: '64:ff9b:1::/96', filterAaaa: false, lists: [], name: 'guests', networks: [], pausedUntilUnixSeconds: null, priority: 5, queries24h: 0, rebindingProtection: false, rewrites: [], safeSearch: true, schedules: [], schedulesOn: [], upstreams: null, youtubeRestrict: 'off' },
  ],
};
const WL_MANY = Array.from({ length: 10 }, (_, i) => wload({ key: `work/deploy/app${i}`, name: `work/deploy/app${i}`, namespace: 'work', group: 'kids', pods: [{ name: `app${i}-0`, addresses: [`10.43.0.${i + 1}`] }] }));

test('api_012 pseudo locale leaves no literal text: clients, with workloads, routers and a device drawer', async ({ page }) => {
  const sent = await watch(page);
  await page.addInitScript(() => localStorage.setItem('telltale.mode.admin', 'advanced'));
  await editors(page);
  await page.route('**/api/v1/clients', (r) =>
    r.fulfill({
      json: ITEMS([
        { name: 'work-pc', match: ['192.168.1.20', 'a4:5e:60:12:34:56'], groups: ['kids'], effectiveGroups: ['kids'], groupsFrom: 'client', source: 'api', identity: null, kind: null },
        { name: 'den-tv', match: ['192.168.1.30'], groups: [], effectiveGroups: [], groupsFrom: 'network', source: 'file', identity: null, kind: null },
        { name: 'hall-cam', match: ['192.168.1.31'], groups: [], effectiveGroups: ['guests'], groupsFrom: 'default', source: 'api', identity: null, kind: null },
      ]),
    }),
  );
  await page.route('**/api/v1/stats/top?**', (r) =>
    r.fulfill({ json: ITEMS([topItem('192.168.1.20', 1500, { name: 'work-pc', groups: ['kids'] }), topItem('192.168.1.21', 400, { name: null, groups: [] })], { missingNodes: ['attic'] }) }),
  );
  await page.route('**/api/v1/dhcp/leases', (r) =>
    r.fulfill({ json: ITEMS([{ ip: '192.168.1.40', mac: 'a4:5e:60:12:34:60', hostname: 'ring-bell', source: 'router', clientName: null, expiresUnixSeconds: 0 }, { ip: '192.168.1.20', mac: 'a4:5e:60:12:34:56', hostname: 'work-pc', source: 'mdns', clientName: 'work-pc', expiresUnixSeconds: 0 }]) }),
  );
  await page.route('**/api/v1/kubernetes/status', (r) => r.fulfill({ json: { addressesDropped: 0, enabled: true, lastError: null, lastSyncSecondsAgo: 3, namespacesWatched: [], pods: 4, role: 'primary', source: 'in-cluster', watching: true, workloads: WLOADS.length } }));
  await page.route('**/api/v1/kubernetes/workloads**', (r) => r.fulfill({ json: { items: WLOADS, nextCursor: null, total: WLOADS.length } }));
  await page.route('**/api/v1/clients/affinity?**', (r) =>
    r.fulfill({
      json: {
        caveat: 'x', missingNodes: [], windowDays: 7,
        items: [{ client: '192.168.1.20', label: 'mostly pi', name: 'work-pc', nodes: [{ node: 'pi', queries: 90 }, { node: 'homelab', queries: 10 }], queries: 100, topNode: 'pi', topSharePercent: 90 }],
      },
    }),
  );
  await page.route('**/api/v1/clients/*/rhythm', (r) => r.fulfill({ json: { available: false, binsS: [], client: '192.168.1.20', domains: [], missingNodes: [], reason: null } }));
  await signIn(page);
  await open(page, '/clients', '[data-testid="seen-missing"]');
  await expect(page.getByTestId('affinity-head')).toBeVisible();
  expect(await leftovers(page), 'the last hour, a node not answering, the servers column').toEqual([]);
  await open(page, '/clients?tab=devices', 'table tbody tr');
  expect(await leftovers(page), 'the devices').toEqual([]);
  await open(page, '/clients?tab=workloads', '[data-testid="workload-row"]');
  await page.getByTestId('workload-namespace').selectOption('shop');
  expect(await leftovers(page), 'the workloads of one namespace').toEqual([]);
  await open(page, '/clients?tab=discovered', '[data-testid="editor-router"]');
  await expect(page.getByTestId('entry-status').first()).toBeVisible();
  expect(await leftovers(page), 'the discovered devices and routers with every state of a key').toEqual([]);
  for (const [i, what] of ['key saved', 'key missing', 'key file missing', 'key not used'].entries()) {
    await page.locator('[data-testid="editor-router"] [data-testid="entry-row"]').nth(i).locator('button.link').first().click();
    await expect(page.locator('.drawer form.form').first()).toBeVisible();
    expect(await leftovers(page), `a router with a ${what}`).toEqual([]);
    await page.keyboard.press('Escape');
  }
  await page.locator('[data-testid="editor-router"] .head > button').click();
  await page.locator('form.form input.mono').first().fill('warn-router');
  await page.locator('form.form button.primary').click();
  await expect(page.getByTestId('entry-preview')).toBeVisible();
  expect(await leftovers(page), 'a router checked, with a warning').toEqual([]);
  await page.keyboard.press('Escape');
  await open(page, '/clients?device=192.168.1.20', '.drawer .empty');
  expect(await leftovers(page), 'a device whose rhythm is not measured').toEqual([]);
  await clean(page, sent);
});

test('api_012 pseudo locale leaves no literal text: groups, every line of a card, the group and schedule forms', async ({ page }) => {
  const sent = await watch(page);
  await page.addInitScript(() => localStorage.setItem('telltale.mode.admin', 'advanced'));
  const failing = { value: false };
  await editors(page, failing);
  await page.route('**/api/v1/groups', (r) => r.fulfill({ json: GROUP_CARDS }));
  await page.route('**/api/v1/stats/top?**', (r) => {
    const u = new URL(r.request().url());
    const blocked = u.searchParams.get('kind') === 'blocked';
    return r.fulfill({ json: ITEMS(blocked ? (u.searchParams.get('group') === 'kids' ? [topItem('track.example.net', 330)] : []) : [topItem('cdn.example.net', 700), topItem('www.example.org', 120)]) });
  });
  await page.route('**/api/v1/services', (r) => r.fulfill({ json: ITEMS([{ id: 'streamco', name: 'StreamCo', category: 'streaming', domains: ['streamco.example'] }]) }));
  await page.route('**/api/v1/kubernetes/status', (r) => r.fulfill({ json: { addressesDropped: 0, enabled: true, lastError: null, lastSyncSecondsAgo: 3, namespacesWatched: [], pods: 10, role: 'primary', source: 'in-cluster', watching: true, workloads: WL_MANY.length } }));
  await page.route('**/api/v1/kubernetes/workloads**', (r) => r.fulfill({ json: { items: WL_MANY, nextCursor: null, total: WL_MANY.length } }));
  await signIn(page);
  await open(page, '/groups', '[data-testid="group-workloads"]');
  for (const id of ['group-safe-search', 'group-schedules', 'group-services', 'group-answers', 'group-rewrites', 'group-upstreams', 'group-dns64', 'group-filter-aaaa']) await expect(page.getByTestId(id).first()).toBeVisible();
  expect(await leftovers(page), 'the cards of three groups, the settings table').toEqual([]);
  await page.locator('[data-testid="editor-group"] .head > button').click();
  await expect(page.locator('.drawer form.form').first()).toBeVisible();
  expect(await leftovers(page), 'the group form, advanced').toEqual([]);
  await page.locator('form.form input.mono').first().fill('bad-group');
  await page.locator('form.form button.primary').click();
  await expect(page.locator('.drawer [role="alert"]').first()).toBeVisible();
  expect(await leftovers(page), 'a group refused, with a hint').toEqual([]);
  await page.locator('form.form input.mono').first().fill('git-group');
  await page.locator('form.form button.primary').click();
  await page.locator('form.form button.primary').click();
  await expect(page.getByTestId('keep-in-git')).toBeVisible();
  expect(await leftovers(page), 'a group saved, to keep in git').toEqual([]);
  await page.keyboard.press('Escape');
  await page.locator('[data-testid="editor-schedule"] .head > button').click();
  await page.locator('form.form input.mono').first().fill('night');
  await page.locator('form.form button.primary').click();
  await expect(page.locator('.drawer [role="alert"]').first()).toBeVisible();
  expect(await leftovers(page), 'a schedule with no window').toEqual([]);
  await page.locator('form.form textarea').first().fill('tomorrow evening');
  await page.locator('form.form button.primary').click();
  expect(await leftovers(page), 'a schedule with a window that makes no sense').toEqual([]);
  await page.locator('form.form textarea').first().fill('weekdays 21:00-07:00');
  await page.locator('form.form button.primary').click();
  await expect(page.getByTestId('entry-preview')).toBeVisible();
  expect(await leftovers(page), 'a schedule checked').toEqual([]);
  failing.value = true;
  await page.locator('form.form button.primary').click();
  await expect(page.locator('.drawer [role="alert"]').first()).toBeVisible();
  expect(await leftovers(page), 'a schedule that could not be saved').toEqual([]);
  await clean(page, sent);
});

const LIST_ROWS = {
  items: [
    { bytes: 2_400_000, enabled: true, entries: 120_000, error: null, hits: 5000, kind: 'block', lastChangedUnixSeconds: 1_700_000_000, lastCheckedUnixSeconds: 1_700_000_500, lines: 125_000, mode: 'enforce', name: 'ads-main', overlap: [{ list: 'tracking-main', names: 118_000 }], regexSkipped: 3, source: 'https://example.org/hosts.txt', staleDays: 45, state: 'ok', unique: 90_000 },
    { bytes: 100, enabled: false, entries: 12, error: null, hits: 0, kind: 'allow', lastChangedUnixSeconds: null, lastCheckedUnixSeconds: null, lines: 12, mode: 'enforce', name: 'allow-mine', overlap: [], regexSkipped: 1, source: 'inline', staleDays: null, state: 'ok', unique: 12 },
    { bytes: 100, enabled: true, entries: 40_000, error: 'download failed: 503', hits: 0, kind: 'block', lastChangedUnixSeconds: null, lastCheckedUnixSeconds: null, lines: 0, mode: 'shadow', name: 'shadow-trackers', overlap: [], regexSkipped: 0, source: 'https://broken.example/list.txt', staleDays: null, state: 'error', unique: 100 },
  ],
};

test('api_012 pseudo locale leaves no literal text: lists of every state, shadow lists, over-blocking and the list test', async ({ page }) => {
  const sent = await watch(page);
  await page.addInitScript(() => localStorage.setItem('telltale.mode.admin', 'advanced'));
  await editors(page);
  await page.route('**/api/v1/lists', (r) => r.fulfill({ json: LIST_ROWS }));
  await page.route('**/api/v1/analytics/shadow-lists', (r) =>
    r.fulfill({
      json: ITEMS([
        { list: 'shadow-trackers', hits: 1, devices: 1, since: '2026-11-22T22:00:00Z', lastHitAt: '2026-11-24T21:00:00Z', topNames: [{ name: 't.example.com', count: 5 }], nodes: [] },
        { list: 'shadow-two', hits: 12, devices: 3, since: null, lastHitAt: null, topNames: [], nodes: [] },
        { list: 'shadow-three', hits: 7, devices: 1, since: null, lastHitAt: '2026-11-24T21:00:00Z', topNames: [], nodes: [] },
        { list: 'shadow-four', hits: 1, devices: 2, since: '2026-11-22T22:00:00Z', lastHitAt: null, topNames: [], nodes: [] },
      ]),
    }),
  );
  await page.route('**/api/v1/analytics/overblocking?**', (r) => r.fulfill({ json: ITEMS([{ allowedAfterBlock: 14, devices: 3, lastSeen: '2026-11-24T21:30:00Z', lists: ['ads-main', 'tracking-main'], name: 'cdn.example.net', retryBursts: 6 }]) }));
  let n = 0;
  await page.route('**/api/v1/checks/list', (r) => {
    n++;
    if (n === 1) return r.fulfill({ json: { ok: true, detail: '1,200 names', elapsedMs: 340, warnings: ['line 4: not a domain'], rules: 1200 } });
    if (n === 2) return r.fulfill({ json: { ok: false, detail: 'HTTP 404', elapsedMs: 120, error: 'the server answered 404', warnings: [], rules: null } });
    return r.fulfill({ json: { ok: true, detail: '1,198 names', elapsedMs: 410, warnings: [], rules: 1198 } });
  });
  await signIn(page);
  await open(page, '/lists', '[data-testid="shadow-lists"]');
  await expect(page.getByTestId('overblocking')).toBeVisible();
  await expect(page.getByTestId('list-stale')).toBeVisible();
  expect(await leftovers(page), 'lists of every state, shadow lists, over-blocking').toEqual([]);
  await page.locator('[data-testid="editor-list"] .head > button').click();
  await page.locator('form.form input.mono').first().fill('try-list');
  await page.locator('form.form input[aria-label]').nth(1).fill('https://example.org/x.txt');
  for (const what of ['works, with a line it cannot use', 'does not work', 'works']) {
    await page.locator('form.form button:not(.primary)').last().click();
    await expect(page.getByTestId('form-action-result')).toBeVisible();
    expect(await leftovers(page), `the list test: ${what}`).toEqual([]);
  }
  await page.keyboard.press('Escape');
  await page.locator('[data-testid="editor-list"] button.link:not(.danger)').first().click();
  await expect(page.locator('.drawer form.form').first()).toBeVisible();
  expect(await leftovers(page), 'a list edited').toEqual([]);
  await clean(page, sent);
});

const RULE_ROWS = {
  items: [
    { action: 'block', created: '2026-11-24T20:00:00Z', createdBy: 'admin', devices: [], domain: 'ads.example.com', expires: null, expiresInSeconds: null, groups: [], id: 'r-1', note: null, source: 'api' },
    { action: 'allow', created: '2026-11-24T20:00:00Z', createdBy: 'admin', devices: ['work-pc'], domain: 'game.example.com', expires: '2026-11-24T23:00:00Z', expiresInSeconds: 3600, groups: [], id: 'r-2', note: 'a game', source: 'api' },
    { action: 'block', created: null, createdBy: null, devices: [], domain: 'social.example', expires: '2026-11-24T21:59:00Z', expiresInSeconds: 0, groups: ['kids'], id: 'r-3', note: null, source: 'api' },
    { action: 'allow', created: '2026-11-24T20:00:00Z', createdBy: 'admin', devices: ['work-pc', 'den-tv'], domain: 'school.example', expires: null, expiresInSeconds: null, groups: [], id: 'r-4', note: null, source: 'api' },
    { action: 'block', created: null, createdBy: null, devices: [], domain: 'file.example', expires: null, expiresInSeconds: null, groups: [], id: 'r-5', note: null, source: 'file' },
  ],
};

test('api_012 pseudo locale leaves no literal text: quick rules of every kind, their edit form and a failed removal', async ({ page }) => {
  const sent = await watch(page);
  let removeFails = false;
  await page.route('**/api/v1/rules', (r) => r.fulfill({ json: RULE_ROWS }));
  await page.route('**/api/v1/rules/*', (r) => {
    if (r.request().method() === 'DELETE') return r.fulfill(removeFails ? problem(409, 'the rule is held by the config file') : { json: change({}) });
    return r.fulfill({ json: change({ impact: 'Allows game.example.com for work-pc.' }) });
  });
  await signIn(page);
  await open(page, '/rules', '[data-testid="rules-table"]');
  expect(await leftovers(page), 'rules of every kind: forever, in an hour, expired, several devices, from the file').toEqual([]);
  await page.locator('[data-testid="rules-table"] button.link:not([disabled])').nth(2).click();
  await expect(page.getByTestId('rule-edit-row')).toBeVisible();
  expect(await leftovers(page), 'a rule edited').toEqual([]);
  await page.locator('[data-testid="rule-edit-row"] button.primary').click();
  await expect(page.getByTestId('rule-edited')).toBeVisible();
  expect(await leftovers(page), 'a rule saved').toEqual([]);
  removeFails = true;
  await page.locator('[data-testid="rules-table"] button.link:not([disabled])').nth(1).click();
  await expect(page.locator('[role="alert"]').first()).toBeVisible();
  expect(await leftovers(page), 'a rule that could not be removed').toEqual([]);
  await open(page, '/rules', '[data-testid="rules-table"]');
  await page.route('**/api/v1/rules', (r) => r.fulfill({ json: ITEMS([]) }));
  await page.reload();
  await expect(page.locator('.empty').first()).toBeVisible();
  expect(await leftovers(page), 'no rules').toEqual([]);
  await clean(page, sent);
});

const FK = (o: Record<string, number>) => ({ badResponse: 0, network: 0, otherRcode: 0, refused: 0, servfail: 0, timeout: 0, unresolved: 0, ...o });
const UP_ROWS = {
  items: [
    { id: 1, name: 'quad-nine', breaker: 'closed', endpoint: 'tls://9.9.9.9', failures: 0, failuresByKind: FK({}), groups: ['default'], latencyEwmaMs: 21, requests: 600 },
    { id: 2, name: 'cloud-two', breaker: 'open', endpoint: 'https://1.1.1.1/dns-query', failures: 12, failuresByKind: FK({ timeout: 5, network: 3, badResponse: 1, unresolved: 1, servfail: 1, refused: 1 }), groups: ['default'], latencyEwmaMs: 48, requests: 200 },
  ],
};
const QUALITY_ROW = (node: string | null) => ({
  node, enabled: true, sampleEvery: 1000, reference: 'cloud-two',
  upstreams: [
    { upstream: 'quad-nine', same: 10, differentAddresses: 3, differentRcode: 1, filtered: 2, unanswered: 1, dnssecSecure: 5, dnssecInsecure: 2, dnssecBogus: 1, dnssecIndeterminate: 1, ede: [{ code: 15, name: 'Blocked', count: 4 }] },
    { upstream: 'cloud-two', same: 0, differentAddresses: 0, differentRcode: 0, filtered: 0, unanswered: 0, dnssecSecure: 0, dnssecInsecure: 0, dnssecBogus: 0, dnssecIndeterminate: 0, ede: [] },
  ],
  recent: [
    { answer: '192.0.2.1', at: T0, name: 'cdn.example.net', qtype: 'A', reference: 'cloud-two', referenceAnswer: '192.0.2.9', result: 'different_addresses', upstream: 'quad-nine' },
    { answer: '0.0.0.0', at: T0, name: 'bad.example', qtype: 'A', reference: 'cloud-two', referenceAnswer: '192.0.2.9', result: 'filtered', upstream: 'quad-nine' },
  ],
});

test('api_012 pseudo locale leaves no literal text: upstreams, the quality table of a cluster and the forms', async ({ page }) => {
  const sent = await watch(page);
  await page.addInitScript(() => localStorage.setItem('telltale.mode.admin', 'advanced'));
  await editors(page);
  let phase: 'cluster' | 'off' | 'none' = 'cluster';
  await page.route('**/api/v1/upstreams', (r) => r.fulfill({ json: UP_ROWS }));
  await page.route('**/api/v1/stats/latency?**', (r) => r.fulfill({ json: ITEMS([lrow('quad-nine', 600, 14, 41, 90, 210), lrow('cloud-two', 200, 30, 80, 150, 300)]) }));
  await page.route('**/api/v1/stats/latency/heatmap?**', (r) => r.fulfill({ json: HEAT('upstream', ['quad-nine', 'cloud-two']) }));
  await page.route('**/api/v1/stats/latency/exemplars?**', (r) => r.fulfill({ json: EXEMPLARS }));
  await page.route('**/api/v1/analytics/upstream-checks', (r) =>
    r.fulfill({
      json: ITEMS(
        phase === 'cluster'
          ? [QUALITY_ROW('pi'), QUALITY_ROW('attic')]
          : [{ ...QUALITY_ROW(null), enabled: phase !== 'off', upstreams: phase === 'none' ? [] : QUALITY_ROW(null).upstreams, recent: [] }],
      ),
    }),
  );
  let tests = 0;
  await page.route('**/api/v1/checks/upstream', (r) => (++tests === 1 ? r.fulfill({ json: { ok: true, detail: 'tls://9.9.9.9 answered NOERROR', elapsedMs: 31, warnings: [] } }) : r.fulfill({ json: { ok: false, detail: 'timed out', elapsedMs: 2000, error: 'no answer within 2 seconds', warnings: [] } })));
  await signIn(page);
  await open(page, '/upstreams', '[data-testid="upstream-quality"] table');
  await expect(page.locator('ul.disagreements').first()).toBeVisible();
  expect(await leftovers(page), 'the table with its failures, the quality of two nodes, the latest disagreements').toEqual([]);
  phase = 'off';
  await page.reload();
  await expect(page.locator('[data-testid="upstream-quality"] p.muted').first()).toBeVisible();
  expect(await leftovers(page), 'second opinions off').toEqual([]);
  phase = 'none';
  await page.reload();
  await expect(page.locator('[data-testid="upstream-quality"] .empty')).toBeVisible();
  expect(await leftovers(page), 'nothing to show in the quality table').toEqual([]);
  await page.locator('[data-testid="editor-upstream"] .head > button').click();
  await page.locator('form.form input.mono').first().fill('try-upstream');
  await page.locator('form.form input.mono').nth(1).fill('tls://9.9.9.9');
  for (const what of ['works', 'does not work']) {
    await page.locator('form.form button:not(.primary)').last().click();
    await expect(page.getByTestId('form-action-result')).toBeVisible();
    expect(await leftovers(page), `the upstream test: ${what}`).toEqual([]);
  }
  await page.keyboard.press('Escape');
  await page.locator('[data-testid="editor-upstream_group"] .head > button').click();
  await page.locator('form.form input.mono').first().fill('bad-group');
  await page.locator('form.form button.primary').click();
  await expect(page.locator('.drawer [role="alert"]').first()).toBeVisible();
  expect(await leftovers(page), 'an upstream group refused').toEqual([]);
  await clean(page, sent);
});

test('api_012 pseudo locale leaves no literal text: names on my network, its zones, forwards and forms', async ({ page }) => {
  const sent = await watch(page);
  await page.addInitScript(() => localStorage.setItem('telltale.mode.admin', 'advanced'));
  let saveFails: 'no' | 'hint' | 'plain' = 'no';
  await page.route('**/api/v1/records', (r) =>
    r.fulfill({ json: ITEMS([{ name: 'nas.home.arpa', source: 'api', records: [{ type: 'A', value: '192.168.1.10', ttl: null }, { type: 'AAAA', value: 'fd00::10', ttl: 300 }] }, { name: 'printer.home.arpa', source: 'file', records: [{ type: 'TXT', value: 'hello', ttl: null }] }]) }),
  );
  await page.route('**/api/v1/forwards', (r) => r.fulfill({ json: ITEMS([{ domain: 'corp.example', servers: ['10.0.0.53'], source: 'api', stub: false }, { domain: 'lab.example', servers: ['10.1.0.1'], source: 'file', stub: true }]) }));
  await page.route('**/api/v1/zones', (r) => r.fulfill({ json: ITEMS([{ name: 'corp.example', records: 12, groups: [], file: 'zones/corp.zone', negativeTtlSeconds: 60 }, { name: 'kids.example', records: 3, groups: ['kids'], file: null, negativeTtlSeconds: 60 }]) }));
  await page.route(/\/api\/v1\/(records|forwards)\/[^/]+$/, (r) => {
    if (r.request().method() === 'DELETE') return r.fulfill(problem(409, 'the record is held by the config file'));
    if (saveFails === 'hint') return r.fulfill(problemH(422, 'nas.home.arpa already has a CNAME', 'A name with a CNAME has no other records.'));
    if (saveFails === 'plain') return r.fulfill(problem(500, 'the change could not be saved'));
    return r.fulfill({ json: change({}) });
  });
  await signIn(page);
  await open(page, '/local-dns', 'table tbody tr');
  await expect(page.getByTestId('zones')).toBeVisible();
  expect(await leftovers(page), 'names, zones and forwards, advanced').toEqual([]);
  await page.locator('td.nowrap button.link').nth(1).click();
  await expect(page.locator('[role="alert"]').first()).toBeVisible();
  expect(await leftovers(page), 'a name that could not be removed').toEqual([]);
  await page.locator('.actions button.primary').click();
  expect(await leftovers(page), 'the wizard, step one').toEqual([]);
  await page.locator('.drawer button.primary').click();
  await page.locator('input[name="label"]').fill('den-nas');
  await page.locator('input[name="value"]').fill('192.168.1.10');
  await expect(page.getByTestId('change-preview')).toBeVisible();
  expect(await leftovers(page), 'the wizard, step two, with the preview').toEqual([]);
  for (const type of ['AAAA', 'CNAME', 'PTR', 'TXT', 'MX', 'SRV']) {
    await page.locator('select[name="type"]').selectOption(type);
    expect(await leftovers(page), `a ${type} record`).toEqual([]);
  }
  saveFails = 'hint';
  await page.locator('form.stack button.primary[type="submit"]').click();
  await expect(page.locator('.drawer .notice.bad')).toBeVisible();
  expect(await leftovers(page), 'a record refused, with a hint').toEqual([]);
  saveFails = 'no';
  await page.locator('form.stack button.primary[type="submit"]').click();
  await expect(page.locator('.drawer .notice.ok')).toBeVisible();
  expect(await leftovers(page), 'a record saved').toEqual([]);
  await page.keyboard.press('Escape');
  await page.locator('td.nowrap button.link').first().click();
  await expect(page.locator('.drawer input[name="name"]')).toHaveAttribute('readonly', '');
  expect(await leftovers(page), 'a name edited (the name is read only)').toEqual([]);
  await page.keyboard.press('Escape');
  await page.locator('.actions button').last().click();
  await page.locator('input[name="domain"]').fill('corp.example');
  await page.locator('input[name="servers"]').fill('10.0.0.53');
  await page.locator('input[name="stub"]').check();
  expect(await leftovers(page), 'the forward form, a stub zone').toEqual([]);
  saveFails = 'plain';
  await page.locator('form.stack button.primary[type="submit"]').click();
  await expect(page.locator('.drawer .notice.bad')).toBeVisible();
  expect(await leftovers(page), 'a forward that could not be saved').toEqual([]);
  await page.keyboard.press('Escape');
  await page.route('**/api/v1/records', (r) => r.fulfill({ json: ITEMS([]) }));
  await page.route('**/api/v1/forwards', (r) => r.fulfill({ json: ITEMS([]) }));
  await page.reload();
  await expect(page.locator('.empty').first()).toBeVisible();
  expect(await leftovers(page), 'nothing yet').toEqual([]);
  await clean(page, sent);
});

// A1g: the screens before sign-in (the status answer is made up), the shell with its banners and badges,
// the wall display with a live tail, and the pages of the System group in the states a one-node test
// server cannot show (a cluster with a witness, pods, a gone node and a pin; a standalone node in
// maintenance; destinations and rules of alerts; plans in every state; the cache of seven nodes).
type Answer = NonNullable<Parameters<Route['fulfill']>[0]>;
const STATUS = (o: Record<string, unknown> = {}) => ({ csrfToken: null, localLogin: true, oidc: [], passwordLoginRestricted: false, setupRequired: false, user: null, ...o });
const PROVIDERS = [{ id: 'kc', name: 'Keycloak' }, { id: 'ak', name: 'Authentik' }];
const coded = (status: number, code: string, detail: string): Answer => ({ status, json: { type: 'about:blank', title: detail, status, code, detail } });

test('api_012 pseudo locale leaves no literal text: the sign-in screens, first-run setup and the display link', async ({ page }) => {
  const sent = await watch(page);
  let status: Answer = { json: STATUS({ oidc: PROVIDERS }) };
  let login: Answer = coded(401, 'invalid_credentials', 'the user name or the password is not right');
  let gate: Promise<void> = Promise.resolve();
  let displayGate: Promise<void> = Promise.resolve();
  await page.route('**/api/v1/auth/status', async (r) => {
    await gate;
    await r.fulfill(status);
  });
  await page.route('**/api/v1/auth/login', (r) => r.fulfill(login));
  await page.route('**/api/v1/auth/setup', (r) => r.fulfill(coded(400, 'invalid_request', 'the setup token is not right')));
  await page.route('**/api/v1/auth/display', async (r) => {
    await displayGate;
    await r.fulfill(coded(401, 'unauthorized', 'this display code is used or has expired'));
  });
  // The provider buttons, and a provider's refusal in the address.
  await page.goto('/?lang=en-XA#/?loginError=Your%20account%20is%20in%20no%20group%20the%20server%20maps%20to%20a%20role.');
  await expect(page.locator('html')).toHaveAttribute('lang', 'en-XA');
  await expect(page.locator('.provider-error')).toBeVisible();
  expect(await leftovers(page), 'sign in: the providers, a refusal and the password form').toEqual([]);
  status = { json: STATUS({ oidc: PROVIDERS, passwordLoginRestricted: true }) };
  await page.reload();
  await expect(page.getByTestId('password-restricted')).toBeVisible();
  expect(await leftovers(page), 'password sign-in limited to admins on trusted networks').toEqual([]);
  status = { json: STATUS({ oidc: PROVIDERS, localLogin: false }) };
  await page.reload();
  await expect(page.locator('.providers')).toBeVisible();
  await expect(page.locator('form')).toHaveCount(0);
  expect(await leftovers(page), 'password sign-in turned off').toEqual([]);
  // The password form: a wrong password, then the two code steps.
  status = { json: STATUS() };
  await page.reload();
  await page.locator('input[name="username"]').fill('ada');
  await page.locator('input[name="password"]').fill('not the password');
  await page.locator('button[type="submit"]').click();
  await expect(page.locator('[role="alert"]:not(.provider-error)')).toBeVisible();
  expect(await leftovers(page), 'a wrong password').toEqual([]);
  login = coded(401, 'totp_required', 'a code is needed');
  await page.locator('button[type="submit"]').click();
  await expect(page.locator('input[name="totp"]')).toBeVisible();
  expect(await leftovers(page), 'the code step').toEqual([]);
  await page.locator('button.link').click();
  await expect(page.locator('input[name="recovery"]')).toBeVisible();
  expect(await leftovers(page), 'the recovery code step').toEqual([]);
  // First run: the passwords differ, then the server refuses the token.
  status = { json: STATUS({ setupRequired: true }) };
  await page.reload();
  await expect(page.locator('input[name="setupToken"]')).toBeVisible();
  expect(await leftovers(page), 'first-run setup').toEqual([]);
  await page.locator('input[name="setupToken"]').fill('tok');
  await page.locator('input[name="password"]').fill('long enough password');
  await page.locator('input[name="confirm"]').fill('another long password');
  await page.locator('button[type="submit"]').click();
  await expect(page.locator('[role="alert"]:not(.provider-error)')).toBeVisible();
  expect(await leftovers(page), 'the passwords differ').toEqual([]);
  await page.locator('input[name="confirm"]').fill('long enough password');
  await page.locator('button[type="submit"]').click();
  await expect(page.getByText('the setup token is not right')).toBeVisible();
  expect(await leftovers(page), 'a refused setup token').toEqual([]);
  // The server cannot be reached; the first answer still to come.
  status = coded(502, 'bad_gateway', 'the server did not answer');
  await page.reload();
  await expect(page.locator('main.center .notice')).toBeVisible();
  expect(await leftovers(page), 'the server cannot be reached').toEqual([]);
  status = { json: STATUS() };
  let release!: () => void;
  gate = new Promise<void>((resolve) => (release = resolve));
  await page.reload();
  await expect(page.locator('p.empty')).toBeVisible();
  expect(await leftovers(page), 'the page is loading').toEqual([]);
  release();
  await expect(page.locator('input[name="username"]')).toBeVisible();
  // A display link with no code, with a code that is still being exchanged, and one that is refused.
  await page.goto('/?lang=en-XA#/display');
  await expect(page.getByTestId('display-error')).toBeVisible();
  expect(await leftovers(page), 'a display link without its code').toEqual([]);
  let opened!: () => void;
  displayGate = new Promise<void>((resolve) => (opened = resolve));
  await page.goto('/?lang=en-XA#/display?code=abcd');
  await page.reload();
  await expect(page.locator('[data-testid="display-open"] p.muted')).toBeVisible();
  expect(await leftovers(page), 'the wall is opening').toEqual([]);
  opened();
  await expect(page.getByTestId('display-error')).toBeVisible();
  expect(await leftovers(page), 'a display code that is refused').toEqual([]);
  await clean(page, sent);
});

const SHELL_INFO = (o: Record<string, unknown> = {}) => ({
  build: { commit: 'abc1234', date: '2026-11-24', profile: 'release', target: 'x86_64-unknown-linux-gnu', version: '0.9.0' },
  clientIpsMasked: { queries: 5000, sharePercent: 92, sources: ['10.42.0.1', '172.17.0.1'] }, cluster: { name: 'home', primary: true, site: 'homelab' }, filterNames: 1, filterSnapshot: 1, listeners: [],
  maintenance: { by: 'admin', node: 'homelab', reason: 'SD card swap', secondsLeft: 1800, since: T0, until: T0 }, node: 'homelab', queryLog: false, role: 'primary', startedAt: T0, starts: 1,
  uncleanStarts: 0, update: { state: 'available' }, uptimeSeconds: 100, version: '0.9.0', ...o,
});

test('api_012 pseudo locale leaves no literal text: the shell, its banners, its phone menu and its badges', async ({ page }) => {
  const sent = await watch(page);
  let info: Record<string, unknown> = SHELL_INFO();
  await page.addInitScript(() => {
    localStorage.setItem('telltale.mode.admin', 'advanced');
    localStorage.setItem('theme', 'dark');
  });
  await page.route('**/api/v1/system/info', (r) => r.fulfill({ json: info }));
  await page.route('**/api/v1/system/health', (r) => r.fulfill({ json: HEALTH }));
  await page.route('**/api/v1/analytics/anomalies?**', (r) => r.fulfill({ json: FINDINGS }));
  await page.route('**/api/v1/lists', (r) => r.fulfill({ json: { items: [{ name: 'ads', state: 'failed' }] } }));
  await signIn(page);
  await open(page, '/rules', '[data-testid="build-footer"]');
  await expect(page.getByTestId('masked-banner')).toBeVisible();
  await expect(page.getByTestId('maintenance-app-banner')).toBeVisible();
  await expect(page.locator('nav.side b.count').first()).toBeVisible();
  expect(await leftovers(page), 'the build footer of a primary with an update, the banners, the badges and the wall button').toEqual([]);
  info = SHELL_INFO({ cluster: { name: 'home', primary: false, site: 'pi' }, maintenance: null, clientIpsMasked: null, queryLog: true, update: { state: 'none' } });
  await page.evaluate(() => window.dispatchEvent(new Event('telltale:maintenance-changed')));
  await expect(page.getByTestId('maintenance-app-banner')).toHaveCount(0);
  await expect(page.locator('[data-testid="node-role"]:not(.primary)')).toBeVisible();
  expect(await leftovers(page), 'a replica').toEqual([]);
  await page.setViewportSize({ width: 390, height: 800 });
  await page.locator('button.icon-btn.menu').click();
  await expect(page.getByTestId('menu-scrim')).toBeVisible();
  await expect(page.getByTestId('menu-health-dot')).toBeVisible();
  expect(await leftovers(page), 'the phone menu: its scrim, detail level and health dot').toEqual([]);
  await clean(page, sent);
});

test('api_012 pseudo locale leaves no literal text: the wall display, paused, with a live tail and every panel', async ({ page }) => {
  const sent = await watch(page);
  const tail = `retry: 86400000\n\nevent: query\ndata: ${JSON.stringify(QROW(1, {}))}\n\n`;
  await page.route('**/api/v1/queries/stream', (r) => r.fulfill({ status: 200, headers: { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' }, body: tail }));
  await signIn(page);
  await open(page, '/wall?panels=map,flow,slo,latency,heat,kpi&layout=grid', '[data-testid="wall-area"]');
  await expect(page.locator('.tail .item').first()).toBeVisible();
  expect(await leftovers(page), 'the wall with every panel and a live tail').toEqual([]);
  await page.keyboard.press('Space');
  await expect(page.getByTestId('wall-paused')).toBeVisible();
  expect(await leftovers(page), 'the wall paused').toEqual([]);
  await page.setViewportSize({ width: 390, height: 800 });
  await open(page, '/wall?panels=slo,kpi', '[data-testid="wall-area"]');
  await expect(page.locator('h1.title')).toBeVisible();
  expect(await leftovers(page), 'a phone: one panel and its title').toEqual([]);
  await clean(page, sent);
});

const EVENT_KINDS = [
  'joined', 'connected', 'disconnected', 'published', 'applied', 'sync_failed', 'rejected', 'restarted', 'expired', 'left', 'voted', 'cert_issued', 'ca_rotation', 'maintenance', 'maintenance_ended',
  'handover', 'handover_failed', 'lease_released', 'stepped_down', 'rollout_started', 'rollout_promoted', 'rollout_failed', 'pinned', 'unpinned', 'brand_new',
];
const MAINT = (node: string) => ({ by: 'admin', node, reason: 'SD card swap', secondsLeft: 600, since: T0, until: T0 });
const BIG = {
  ...CLUSTER, healthy: false, authority: 'gitops', host: null,
  events: EVENT_KINDS.map((kind, i) => ({ at: new Date(Date.now() - i * 60_000).toISOString(), detail: `${kind} happened`, kind, nodeId: i % 3 === 0 ? 'n-zzzz9999' : 'n-bbbb2222' })),
  checks: [{ id: 'sync', ok: true, summary: 'Every node is on the newest version.' }, { id: 'link', ok: false, summary: 'The link to pi is down.', fix: 'Check the cable of pi.' }, { id: 'bare', ok: false, summary: 'One more check failed.' }],
  conflicts: [{ changed: ['group.kids', 'list.ads'], detectedAt: T0, epoch: 3, newPrimary: 'n-bbbb2222', publishedAt: T0, seq: 41 }, { changed: [], detectedAt: T0, epoch: 3, newPrimary: 'n-bbbb2222', publishedAt: T0, seq: 40 }],
  source: { author: 'Ada', checkedAt: T0, commit: 'abcdef1234567890', committedAt: T0, error: 'could not fetch the repository', gitRef: 'main', path: 'telltale.toml', refused: false, repo: 'git@example.com:me/dns.git', signedBy: 'Ada', subject: 'Block more ads' },
  rollout: { stage: 'canary', canaries: ['n-bbbb2222'], version: '3.131', pinned: { by: 'admin', reason: 'hold for the weekend', since: T0, to: '3.130' } },
  nodes: [
    node({ nodeId: 'n-aaaa1111', site: 'homelab', role: 'primary', thisNode: true, rttMs: null, configSource: 'gitops', sourceCommit: 'abcdef1234', restarts: 1, certExpiresAt: T0, host: HOST }),
    node({ nodeId: 'n-bbbb2222', site: 'pi', role: 'secondary', up: false, ready: false, configLag: 3, behindSeconds: 90, lastSeenSecondsAgo: 125, maintenance: MAINT('n-bbbb2222'), cacheEntries: null, cacheHitPercent: null, querySharePercent: null, upstreamP90Ms: 0, restarts: 2 }),
    node({ nodeId: 'n-cccc3333', site: 'attic', role: 'witness', witness: true }),
    node({ nodeId: 'n-dddd4444', site: 'k8s', role: 'secondary', ephemeral: true, pod: 'resolver-0', kubeNode: 'worker-1', cacheHitPercent: 60 }),
    node({ nodeId: 'n-eeee5555', site: 'k8s', role: 'secondary', ephemeral: true, pod: 'resolver-1', kubeNode: null, cacheHitPercent: null, configLag: 1 }),
  ],
};
const REPLICA = (o: Record<string, unknown>) => ({
  ...CLUSTER, failover: { active: false, leaseHeld: false, leaseSecondsLeft: null, mode: 'auto', reachableVoters: 2, votedEpoch: 0, votedFor: null, voters: 2 },
  nodes: [node({ nodeId: 'n-aaaa1111', site: 'homelab', role: 'primary', up: false, configSource: 'gitops' }), node({ nodeId: 'n-bbbb2222', site: 'pi', role: 'replica', thisNode: true, rttMs: null, configSource: 'file' })],
  ...o,
});

test('api_012 pseudo locale leaves no literal text: the cluster of a witness, pods, a gone node and a pin, a promotion and a standalone node', async ({ page }) => {
  const sent = await watch(page);
  declare(HOST_LINE, '· abcdef1');
  let view: Record<string, unknown> = BIG;
  let info: Record<string, unknown> = SHELL_INFO({ clientIpsMasked: null, queryLog: true, maintenance: null, update: { state: 'none' } });
  await page.route('**/api/v1/cluster', (r) => r.fulfill({ json: view }));
  await page.route('**/api/v1/system/info', (r) => r.fulfill({ json: info }));
  await page.route('**/api/v1/nodes/*/maintenance', (r) => r.fulfill({ json: { note: 'This node is in service again.' } }));
  await signIn(page);
  await open(page, '/cluster', '[data-testid="cluster-node"]');
  await expect(page.getByTestId('pin-note')).toBeVisible();
  await expect(page.getByTestId('cluster-pods')).toBeVisible();
  await page.locator('[data-testid="cluster-pods"] button.link').click();
  await expect(page.getByTestId('cluster-node-pod').first()).toBeVisible();
  expect(await leftovers(page), 'nodes: a primary with its commit, a gone node in maintenance, a witness, pods, a pin and a source that failed').toEqual([]);
  await open(page, '/cluster?tab=health', '[data-testid="cluster-check"]');
  await expect(page.getByTestId('cluster-conflicts')).toBeVisible();
  expect(await leftovers(page), 'health: checks that fail with a fix, conflicts, machines').toEqual([]);
  await open(page, '/cluster?tab=events', '[data-testid="cluster-churn"]');
  expect(await leftovers(page), 'events of every kind and one this page does not know').toEqual([]);
  view = REPLICA({ authority: 'gitops' });
  await page.reload();
  await open(page, '/cluster', '[data-testid="cluster-node"]');
  await page.locator('.promote button').first().click();
  await expect(page.locator('[role="alertdialog"]')).toBeVisible();
  expect(await leftovers(page), 'promote this node, with the emergency choice').toEqual([]);
  view = REPLICA({ authority: 'gitops', nodes: [node({ nodeId: 'n-aaaa1111', site: 'homelab', role: 'emergency primary', configSource: 'file' }), node({ nodeId: 'n-bbbb2222', site: 'pi', role: 'replica', thisNode: true, rttMs: null, configSource: 'gitops' })] });
  await page.reload();
  await open(page, '/cluster', '[data-testid="cluster-node"]');
  await page.locator('.promote button').first().click();
  await expect(page.locator('[role="alertdialog"]')).toBeVisible();
  expect(await leftovers(page), 'take over from the emergency primary').toEqual([]);
  // A cluster where no node is a primary any more: the summary names none (the pseudo text of `none`).
  view = REPLICA({ nodes: [node({ nodeId: 'n-bbbb2222', site: 'pi', role: 'replica', thisNode: true, rttMs: null, configSource: 'file' })] });
  await page.reload();
  await open(page, '/cluster', '[data-testid="cluster-node"]');
  expect(await leftovers(page), 'a cluster with no primary').toEqual([]);
  await expect(page.locator('dl.facts')).toContainText('ñóñé');
  view = { ...CLUSTER, enabled: false, host: HOST, nodes: [] };
  info = SHELL_INFO({ clientIpsMasked: null, queryLog: true });
  await page.reload();
  await open(page, '/cluster', '[data-testid="cluster-standalone"]');
  await expect(page.getByTestId('maintenance-banner')).toBeVisible();
  await page.getByTestId('maintenance-end-banner').click();
  await expect(page.getByTestId('maintenance-note')).toBeVisible();
  expect(await leftovers(page), 'a standalone node in maintenance, then back in service').toEqual([]);
  await clean(page, sent);
});

test('api_012 pseudo locale leaves no literal text: alerts, with destinations and rules, and the plans of agents in every state', async ({ page }) => {
  const sent = await watch(page);
  entriesOf.alert_destination = [ENTRY('alert_destination', 'mail', 'added', { type: 'email', to: ['you@gmail.com'], url: 'smtp://smtp.gmail.com:587' }), ENTRY('alert_destination', 'push', 'file', { type: 'ntfy', url: 'https://ntfy.sh/x' })];
  entriesOf.alert_rule = [ENTRY('alert_rule', 'down', 'added', { when: 'upstream_down', to: ['mail'], enabled: false }), ENTRY('alert_rule', 'lag', 'file', { when: 'sync_lag', to: ['mail', 'push'] })];
  await editors(page);
  await page.route(/\/api\/v1\/alerts$/, (r) =>
    r.fulfill({
      json: {
        evaluating: true,
        firing: [{ rule: 'upstream_down', subject: 'quad9', summary: 'Upstream quad9 does not answer.' }],
        maintenance: [MAINT('pi')],
        deliveries: [{ destination: 'mail', ok: true, unixSeconds: 1_764_021_600, error: null }, { destination: 'push', ok: false, unixSeconds: 1_764_021_000, error: 'the server answered 503' }],
      },
    }),
  );
  await page.route('**/api/v1/alerts/destinations/*/test', (r) => r.fulfill({ json: { ok: true, error: null } }));
  await signIn(page);
  await open(page, '/alerts', '[data-testid="alerts-now"]');
  await expect(page.getByTestId('alerts-maintenance')).toBeVisible();
  await page.locator('[data-testid="editor-alert_destination"] [data-testid="entry-row"] button.link').first().click();
  await expect(page.getByTestId('row-action-result')).toBeVisible();
  await page.locator('[data-testid="editor-alert_destination"] button:not(.link):not([data-help])').first().click();
  await expect(page.locator('form.form').first()).toBeVisible();
  expect(await leftovers(page), 'alerts that fire, a node in maintenance, deliveries, the destinations and rules, the add form and a test').toEqual([]);
  await page.route(/\/api\/v1\/alerts$/, (r) => r.fulfill({ json: { evaluating: false, firing: [], maintenance: [], deliveries: [] } }));
  await page.reload();
  await open(page, '/alerts', '[data-testid="alerts-now"]');
  await expect(page.locator('[data-testid="alerts-now"] p.muted')).toBeVisible();
  expect(await leftovers(page), 'alerts checked on the primary').toEqual([]);
  // The plans of agents: every state, a preview with a simulation, the buttons of one that waits.
  const plan = (id: string, state: string, o: Record<string, unknown> = {}) => ({
    id, state, summary: `Change ${id}`, tool: 'rules', method: 'PUT', path: `/api/v1/rules/${id}`, reason: 'a test', requestedBy: 'agent', needsApproval: true, configVersion: 3, createdUnixSeconds: Date.parse(T0) / 1000 - 90,
    expiresUnixSeconds: Date.parse(T0) / 1000 + 400, preview: {}, ...o,
  });
  const plans = [
    plan('p-1', 'pending', { preview: { impact: 'Blocks game.example.com for everyone.', warnings: ['It also blocks a name a device asked for an hour ago.'], before: null, after: { domain: 'game.example.com' }, simulation: SIMULATION(null) } }),
    plan('p-2', 'ready'), plan('p-3', 'approved', { decidedBy: 'admin' }), plan('p-4', 'rejected', { decidedBy: 'admin' }), plan('p-5', 'applying'), plan('p-6', 'applied'),
    plan('p-7', 'stale'), plan('p-8', 'failed'), plan('p-9', 'discarded'), plan('p-10', 'expired'), plan('p-11', 'brand_new'),
  ];
  let decided = '';
  await page.route('**/api/v1/plans', (r) => r.fulfill({ json: { items: plans } }));
  await page.route('**/api/v1/plans/*/approve', (r) => {
    decided = 'approved';
    return r.fulfill({ json: plan('p-1', 'approved') });
  });
  await open(page, '/agent-changes', '[data-testid="plan"]');
  await expect(page.getByTestId('plan')).toHaveCount(11);
  expect(await leftovers(page), 'plans in every state, with a preview, warnings and a simulation').toEqual([]);
  await page.locator('[data-testid="plan"] button.primary').first().click();
  await expect.poll(() => decided).toBe('approved');
  await clean(page, sent);
});

const CSET = {
  maxBytes: 64e6, maxEntries: 50_000, maxTtlSeconds: 86_400, minTtlSeconds: 30, negativeTtlMaxSeconds: 3600, persist: true, prefetch: true, prefetchMinHits: 3, prefetchThresholdPercent: 10, serveStale: true,
  servfailTtlSeconds: 60, staleAnswerWaitMs: 1800, staleMaxAgeSeconds: 86_400,
};
const CPOINT = (i: number) => ({ answeredPercent: 80, at: new Date(Date.parse(T0) - (6 - i) * 15_000).toISOString(), bytes: 1e6, entries: 100, evictions: 1, hitPercent: 70, lookups: 50, prefetches: 2, staleServed: 3 });
const CSTAT = (node: string | null, o: Record<string, unknown> = {}) => ({
  answeredPercent: 82, bytes: 2e7, entries: 1200, evictions: 3, hitPercent: 80, hits: 900, inserts: 500, misses: 100, node, prefetches: 9, staleServed: 4, uncacheable: 0, settings: CSET,
  sizing: { advice: 'The cache is a little small.', lookups: 1000, peakBytes: 3e7, steps: [{ extraBytes: 1e7, extraHitPercent: 1.5, extraHits: 15, sizePercent: 150 }, { extraBytes: 2e7, extraHitPercent: 2.5, extraHits: 25, sizePercent: 200 }], verdict: 'grow' },
  warmStart: { at: T0, loaded: 1, note: null }, history: [0, 1, 2, 3, 4, 5].map(CPOINT), ...o,
});
const CMAKE = (o: Record<string, unknown> = {}) => ({ nodata: 3, nxdomain: 20, positive: 100, servfail: 1, stale: 4, validated: 50, ...o });
const CENTRY = (name: string, o: Record<string, unknown> = {}) => ({ ageSeconds: 5, answers: 2, authentic: true, bytes: 120, dnssecOk: false, hits: 9, name, qtype: 'A', rcode: 'NOERROR', ttlLeftSeconds: 120, ...o });

test('api_012 pseudo locale leaves no literal text: the cache of seven nodes, their settings and what they hold', async ({ page }) => {
  const sent = await watch(page);
  const names = ['homelab', 'pi', 'attic', 'cellar', 'den', 'loft', 'shed'];
  const stats = [
    CSTAT('homelab'),
    CSTAT('pi', { settings: { ...CSET, persist: false, serveStale: false, prefetch: false, maxEntries: null }, sizing: { ...CSTAT(null).sizing, verdict: 'learning', steps: [] }, warmStart: null, answeredPercent: 80, hitPercent: 80 }),
    CSTAT('attic', { settings: { ...CSET, staleAnswerWaitMs: 0 }, sizing: { ...CSTAT(null).sizing, verdict: 'ok' }, warmStart: { at: T0, loaded: null, note: 'no saved cache was found' } }),
    CSTAT('cellar', { settings: { ...CSET, staleAnswerWaitMs: null }, sizing: { ...CSTAT(null).sizing, verdict: 'shrink' }, warmStart: { at: T0, loaded: 3, note: null }, answeredPercent: null, hitPercent: null }),
    CSTAT('den', { sizing: null, settings: null, history: [] }),
    CSTAT('loft', { sizing: { ...CSTAT(null).sizing, verdict: 'brand_new' } }),
    CSTAT('shed'),
  ];
  const held = (node: string, o: Record<string, unknown> = {}) => ({ node, makeup: CMAKE(), entries: [CENTRY('a.example'), CENTRY('b.example', { qtype: 'AAAA', dnssecOk: true, rcode: 'NXDOMAIN', answers: 0, ttlLeftSeconds: -30, authentic: false }), CENTRY(`${node}.example`, { hits: 1 })], ...o });
  let entries: Record<string, unknown>[] = names.map((n) => held(n));
  entries[1] = { node: 'pi', error: 'the node did not answer', makeup: CMAKE({ positive: 0, nxdomain: 0, nodata: 0, servfail: 0 }), entries: [] };
  entries[2] = held('attic', { makeup: CMAKE({ positive: 1, nxdomain: 1, nodata: 1, servfail: 1 }) });
  await page.route('**/api/v1/cache/stats', (r) => r.fulfill({ json: { items: stats } }));
  await page.route('**/api/v1/cache/entries?**', (r) => r.fulfill({ json: { items: entries } }));
  await signIn(page);
  await open(page, '/cache', '[data-testid="cache-top"]');
  await expect(page.getByTestId('cache-node')).toHaveCount(7);
  await page.locator('div.table-wrap + button.link.small').click();
  await page.locator('[data-testid="cache-top"] td button[aria-expanded]').first().click();
  await expect(page.locator('ul.per-node')).toBeVisible();
  await page.locator('[data-testid="cache-node"] details summary').first().click();
  expect(await leftovers(page), 'seven nodes: every warm start, size verdict and serve-stale line, their settings, the makeup and the merged names').toEqual([]);
  await page.locator('.head-row select').first().selectOption('expiring');
  entries = [held('homelab', { entries: [] })];
  await page.route('**/api/v1/cache/entries?**', (r) => r.fulfill({ json: { items: entries } }));
  await page.locator('.head-row select').first().selectOption('bytes');
  await expect(page.locator('.empty').first()).toBeVisible();
  expect(await leftovers(page), 'nothing cached').toEqual([]);
  await page.locator('.head-row select').first().selectOption('expiring');
  await expect(page.locator('.empty').first()).toBeVisible();
  expect(await leftovers(page), 'nothing cached that is still fresh').toEqual([]);
  await clean(page, sent);
});

// ---- the Settings page: every tab, with what a one-node test server cannot show
/** The same page again, as the mocks answer now (`open` to the address the page is on is no new load). */
async function reopen(page: Page, ready: string) {
  await page.reload();
  await expect(page.locator('html')).toHaveAttribute('lang', 'en-XA');
  await expect(page.locator(ready).first()).toBeVisible();
}
const ST_ADMIN = (o: Record<string, unknown> = {}) =>
  STATUS({ csrfToken: 'x', user: { allowBasicApi: false, display: null, id: 1, recoveryCodesLeft: 0, role: 'admin', totpEnabled: false, username: 'admin', via: 'password', ...o } });
const ST_TOKEN = (o: Record<string, unknown> = {}) => ({ createdUnixSeconds: NOW - 86_400, expiresUnixSeconds: null, group: null, id: 'a1b2c3', kind: 'user', lastUsedUnixSeconds: NOW - 60, name: 'grafana', ratePerMinute: null, scope: 'read', ...o });

test('api_012 pseudo locale leaves no literal text: settings, the account, the two-factor flow and the icon preferences', async ({ page }) => {
  const sent = await watch(page);
  let on = false;
  let wrongCode = false;
  let passwordFails = false;
  await signIn(page);
  await page.route('**/api/v1/auth/status', (r) => r.fulfill({ json: ST_ADMIN({ totpEnabled: on, recoveryCodesLeft: on ? 4 : 0 }) }));
  await page.route('**/api/v1/auth/password', (r) => r.fulfill(passwordFails ? coded(403, 'forbidden', 'the current password is wrong') : { json: {} }));
  await page.route('**/api/v1/auth/totp/setup', (r) =>
    r.fulfill({ json: { otpauthUrl: 'otpauth://totp/TelltaleDNS:admin?secret=JBSWY3DPEHPK3PXP&issuer=TelltaleDNS', secretBase32: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP' } }),
  );
  await page.route('**/api/v1/auth/totp/enable', (r) => {
    if (wrongCode) return r.fulfill(coded(422, 'invalid_request', 'that code is not right'));
    on = true;
    return r.fulfill({ json: { codes: ['k3f9a-2xq7m', 'p8d1z-77ncw', 'vb40e-hh2yu', 'c6rr5-m1t3j'] } });
  });
  await page.route('**/api/v1/auth/totp/disable', (r) => r.fulfill(coded(403, 'forbidden', 'the password is wrong')));
  await open(page, '/settings', '[data-testid="icons-card"]');
  expect(await leftovers(page), 'the account, two-factor off, the icon preferences').toEqual([]);
  const form = 'form.stack:has(h3)';
  await page.locator(`${form} input[autocomplete="current-password"]`).fill('the old password');
  await page.locator(`${form} input[autocomplete="new-password"]`).fill('a brand new password');
  await page.locator(`${form} button.primary`).click();
  await expect(page.locator(`${form} .notice.ok`)).toBeVisible();
  expect(await leftovers(page), 'a password changed').toEqual([]);
  passwordFails = true;
  await page.locator(`${form} input[autocomplete="current-password"]`).fill('the old password');
  await page.locator(`${form} input[autocomplete="new-password"]`).fill('a brand new password');
  await page.locator(`${form} button.primary`).click();
  await expect(page.locator(`${form} [role="alert"]`)).toBeVisible();
  expect(await leftovers(page), 'a password refused').toEqual([]);
  // The two-factor card: the key, a wrong code, the recovery codes, then on.
  const card = page.locator('section.stack-card').first();
  await card.locator('button:not(.help-btn)').first().click();
  await expect(card.locator('ol.steps')).toBeVisible();
  expect(await leftovers(page), 'the key to enter in an authenticator app').toEqual([]);
  wrongCode = true;
  await card.locator('input[inputmode="numeric"]').fill('000000');
  await card.locator('form.row button.primary').click();
  await expect(card.locator('[role="alert"]')).toBeVisible();
  expect(await leftovers(page), 'a code that is not right').toEqual([]);
  wrongCode = false;
  await card.locator('input[inputmode="numeric"]').fill('123456');
  await card.locator('form.row button.primary').click();
  await expect(card.locator('.notice.warn ul.codes')).toBeVisible();
  expect(await leftovers(page), 'the recovery codes, and two-factor on').toEqual([]);
  await card.locator('input[type="password"]').fill('the password');
  await card.locator('button.danger').click();
  await expect(card.locator('[role="alert"]')).toBeVisible();
  expect(await leftovers(page), 'turning two-factor off with a wrong password').toEqual([]);
  // The icon preferences: the brand and monogram style by default, then the other two and the sizes.
  const icons = page.getByTestId('icons-card');
  await icons.locator('.seg').first().locator('button').nth(1).click();
  await icons.locator('.seg').nth(1).locator('button').nth(1).click();
  expect(await leftovers(page), 'monograms, small').toEqual([]);
  await icons.locator('.seg').first().locator('button').nth(2).click();
  await expect(icons.locator('.seg').nth(1).locator('button').first()).toBeDisabled();
  expect(await leftovers(page), 'icons off').toEqual([]);
  await clean(page, sent);
});

test('api_012 pseudo locale leaves no literal text: settings, API tokens of both kinds, a new token and a refusal', async ({ page }) => {
  const sent = await watch(page);
  let items: Record<string, unknown>[] = [
    ST_TOKEN({}),
    ST_TOKEN({ id: 'd4e5f6', name: 'ops-bot', kind: 'agent', scopes: ['analytics:read', 'config:read'], group: 'kids', lastUsedUnixSeconds: null, expiresUnixSeconds: NOW + 86_400 * 30 }),
    ST_TOKEN({ id: 'j0k1l2', name: 'deploy', scope: 'admin', expiresUnixSeconds: NOW - 3600 }),
  ];
  let refuse = false;
  await page.route('**/api/v1/tokens', (r) => {
    if (r.request().method() === 'POST') {
      if (refuse) return r.fulfill(coded(422, 'invalid_request', 'a token with this name exists'));
      return r.fulfill({ json: { info: ST_TOKEN({ id: 'q6r7s8', name: 'dashboards' }), token: 'tt_q6r7s8_V3ryS3cretT0kenValueNobodyKnows01' } });
    }
    return r.fulfill({ json: { items } });
  });
  await page.route('**/api/v1/tokens/*', (r) => r.fulfill({ status: 204 }));
  await signIn(page);
  await open(page, '/settings?tab=tokens', 'table');
  expect(await leftovers(page), 'tokens of every kind, the form for my scripts').toEqual([]);
  const form = page.locator('form.row').first();
  await form.locator('select').first().selectOption('agent');
  await expect(page.locator('fieldset.agent-scopes')).toBeVisible();
  expect(await leftovers(page), 'the form for an AI agent and its scopes').toEqual([]);
  await form.locator('input').first().fill('dashboards');
  await form.locator('button.primary').click();
  await expect(page.locator('.new-token')).toBeVisible();
  expect(await leftovers(page), 'the new token').toEqual([]);
  await page.locator('.new-token button').first().click();
  await page.locator('.new-token button.link').click();
  refuse = true;
  await form.locator('input').first().fill('grafana');
  await form.locator('button.primary').click();
  await expect(page.locator('[role="alert"]').first()).toBeVisible();
  expect(await leftovers(page), 'a token refused').toEqual([]);
  items = [];
  await page.locator('table button.danger').first().click();
  await expect(page.locator('p.empty')).toBeVisible();
  expect(await leftovers(page), 'no tokens yet').toEqual([]);
  await clean(page, sent);
});

test('api_012 pseudo locale leaves no literal text: settings, users, where passwords are allowed, their tokens and a refusal', async ({ page }) => {
  const sent = await watch(page);
  const user = (o: Record<string, unknown>) => ({ allowBasicApi: false, createdUnixSeconds: NOW - 86_400 * 30, disabled: false, id: 1, oidcProvider: null, role: 'viewer', totpEnabled: false, username: 'admin', ...o });
  const users = [
    user({ id: 1, username: 'admin', role: 'admin', totpEnabled: true }),
    user({ id: 2, username: 'ada', role: 'operator', allowBasicApi: true, oidcProvider: 'Keycloak' }),
    user({ id: 3, username: 'bob', disabled: true }),
  ];
  const pl = (o: Record<string, unknown>) => ({ coversWholeNetworks: false, includesLoopback: false, loopbackIsTrustedProxy: false, networks: ['192.168.1.10/32'], restricted: true, ...o });
  let passwordLogin: Record<string, unknown> | undefined = pl({ coversWholeNetworks: true, networks: ['192.168.1.0/24', '10.0.0.0/8'] });
  let refuse = false;
  await page.route('**/api/v1/users**', (r) => {
    const req = r.request();
    const path = new URL(req.url()).pathname;
    if (req.method() === 'GET' && path.endsWith('/tokens')) return r.fulfill({ json: { items: path.includes('/users/2/') ? [ST_TOKEN({}), ST_TOKEN({ id: 'd4e5f6', name: 'ops-bot', kind: 'agent', scopes: ['analytics:read'] })] : [] } });
    if (req.method() === 'GET') return r.fulfill({ json: { items: users, ...(passwordLogin ? { passwordLogin } : {}) } });
    if (refuse) return r.fulfill(coded(409, 'conflict', 'the last admin cannot be changed this way'));
    return r.fulfill(req.method() === 'POST' ? { json: user({ id: 9, username: 'dee' }) } : req.method() === 'DELETE' ? { status: 204 } : { json: users[1] });
  });
  await signIn(page);
  await page.route('**/api/v1/auth/status', (r) => r.fulfill({ json: ST_ADMIN({ totpEnabled: true }) }));
  await open(page, '/settings?tab=users', '[data-testid="password-sign-in"]');
  expect(await leftovers(page), 'users, password sign-in limited to whole networks').toEqual([]);
  const toggle = page.locator('td.num button[aria-expanded]');
  await toggle.nth(1).click();
  await expect(page.locator('tr.user-tokens table')).toBeVisible();
  expect(await leftovers(page), 'the tokens of a user').toEqual([]);
  await toggle.nth(2).click();
  await expect(page.locator('tr.user-tokens table')).toHaveCount(0);
  await expect(page.locator('tr.user-tokens span.muted')).toBeVisible();
  expect(await leftovers(page), 'a user without tokens').toEqual([]);
  await page.locator('td.num button.danger').first().click();
  expect(await leftovers(page), 'a delete that waits for a second click').toEqual([]);
  await page.locator('td.num button.danger').first().click();
  await page.locator('tbody td button.link.small').first().click();
  await page.locator('tbody tr:not(.user-tokens) td:nth-child(5) button.link').first().click();
  for (const [name, change] of [
    ['single machines', {}],
    ['a reverse proxy on this machine', { includesLoopback: true, networks: ['127.0.0.1/32', '192.168.1.10/32'] }],
    ['a trusted reverse proxy', { includesLoopback: true, loopbackIsTrustedProxy: true, networks: ['127.0.0.1/32'] }],
    ['no network', { networks: [] }],
  ] as [string, Record<string, unknown>][]) {
    passwordLogin = pl(change);
    await reopen(page, '[data-testid="password-sign-in"]');
    expect(await leftovers(page), name).toEqual([]);
  }
  passwordLogin = undefined;
  await reopen(page, 'form.add-user');
  await expect(page.getByTestId('password-sign-in')).toHaveCount(0);
  await page.locator('form.add-user input[autocomplete="off"]').fill('dee');
  await page.locator('form.add-user input[type="password"]').fill('a long enough password');
  await page.locator('form.add-user select').selectOption('operator');
  // The first add is over once its answer has come and the page has emptied the form for the next user: only then
  // is the next add refused and the form filled again.
  const added = page.waitForResponse((r) => r.request().method() === 'POST' && new URL(r.url()).pathname === '/api/v1/users');
  await page.locator('form.add-user button.primary').click();
  await added;
  await expect(page.locator('form.add-user input[autocomplete="off"]')).toHaveValue('');
  await expect(page.locator('form.add-user input[type="password"]')).toHaveValue('');
  refuse = true;
  await page.locator('form.add-user input[autocomplete="off"]').fill('eve');
  await page.locator('form.add-user input[type="password"]').fill('another long password');
  await page.locator('form.add-user button.primary').click();
  await expect(page.locator('[role="alert"]').first()).toBeVisible();
  expect(await leftovers(page), 'a user refused').toEqual([]);
  await clean(page, sent);
});

test('api_012 pseudo locale leaves no literal text: settings, the audit log and the staged rollouts of a cluster', async ({ page }) => {
  const sent = await watch(page);
  await page.addInitScript(() => localStorage.setItem('telltale.mode.admin', 'advanced'));
  const aud = (seq: number, o: Record<string, unknown>) => ({
    action: 'user.create', actor: 'admin', actorKind: 'user', detail: { username: 'ada', role: 'viewer' }, hash: 'f'.repeat(64), reason: null, remote: '192.168.1.20', seq, target: 'ada', time: T0, tsUnixSeconds: NOW - 600 * seq, ...o,
  });
  let items = [
    aud(9, { action: 'config.apply', actor: 'agent:ops-bot', actorKind: 'agent', detail: { section: { from: 'a', to: 'b' }, lists: ['ads', 'trackers'], flag: true, empty: null }, reason: 'block a noisy tracker', remote: null }),
    aud(8, { action: 'auth.login', actor: 'ada', actorKind: 'oidc', detail: {} }),
  ];
  let verify: Record<string, unknown> = { entries: 128, headHash: 'abcdef0123456789abcdef0123456789', ok: true };
  await page.route('**/api/v1/audit**', (r) => r.fulfill({ json: { items, nextCursor: items.length ? 'c-6' : null } }));
  await page.route('**/api/v1/audit/verify', (r) => r.fulfill({ json: verify }));
  await signIn(page);
  await open(page, '/settings?tab=audit', 'table.audit');
  expect(await leftovers(page), 'the audit log, with an older page').toEqual([]);
  await page.locator('.card-head .row button').click();
  await expect(page.locator('.verify-result')).toBeVisible();
  expect(await leftovers(page), 'a chain that is intact').toEqual([]);
  verify = { entries: 128, firstBadSeq: 77, headHash: 'abcdef0123456789abcdef0123456789', ok: false };
  await page.locator('.card-head .row button').click();
  await expect(page.locator('.verify-result.bad')).toBeVisible();
  expect(await leftovers(page), 'a chain that is broken').toEqual([]);
  await page.locator('.card-head select').selectOption('auth.');
  items = [];
  await page.locator('.card-head select').selectOption('user.');
  await expect(page.locator('p.empty')).toBeVisible();
  expect(await leftovers(page), 'no entries').toEqual([]);
  // Staged rollouts: a cluster that is off, then a cluster of nodes, sites and pods, with the editor.
  const nd = (o: Record<string, unknown>) => ({ ...node({}), ...o });
  let cluster: Record<string, unknown> = { ...CLUSTER, enabled: false, nodes: [] };
  const entry = (definition: Record<string, unknown> | null, source = 'added', name = 'rollout-settings') => ({ kind: 'rollout', name, source, definition, credentials: null });
  let rollout = [entry({ canaries: ['n-bbbb2222'], bake_secs: 300 })];
  await page.route('**/api/v1/cluster', (r) => r.fulfill({ json: cluster }));
  await page.route('**/api/v1/config/entries?kind=rollout', (r) => r.fulfill({ json: { items: rollout } }));
  await page.route('**/api/v1/cluster/rollout-settings/**', (r) => r.fulfill({ json: { applied: !r.request().url().includes('dryRun=true'), configVersion: 7, impact: 'Changes these settings.', keepInGit: null, warnings: ['a canary that is gone is ignored'], recentQueries: 0 } }));
  await open(page, '/settings?tab=cluster', 'h1');
  await expect(page.locator('p.empty').first()).toBeVisible();
  await expect(page.getByTestId('editor-rollout')).toHaveCount(0);
  expect(await leftovers(page), 'a node on its own').toEqual([]);
  cluster = {
    ...CLUSTER,
    nodes: [
      nd({ nodeId: 'n-aaaa1111', site: 'homelab', role: 'primary', thisNode: true }),
      nd({ nodeId: 'n-bbbb2222', site: 'pi', role: 'secondary' }),
      nd({ nodeId: 'n-cccc3333', site: 'attic', role: 'witness', witness: true }),
      nd({ nodeId: 'n-dddd4444', site: 'k8s', role: 'secondary', ephemeral: true, pod: 'resolver-0' }),
    ],
  };
  await reopen(page, '[data-testid="editor-rollout"] [data-testid="entry-row"]');
  expect(await leftovers(page), 'staged rollouts with one canary').toEqual([]);
  await page.locator('[data-testid="editor-rollout"] [data-testid="entry-row"] button.link').first().click();
  await expect(page.locator('form.form')).toBeVisible();
  await page.locator('form.form .multi label.check input').nth(2).check();
  await page.locator('form.form input[type="number"]').first().fill('90');
  await expect(page.getByTestId('editor-note')).toBeVisible();
  expect(await leftovers(page), 'the rollout editor, with its note in seconds').toEqual([]);
  await page.locator('form.form input[type="number"]').first().fill('240');
  await page.locator('form.form button.primary').click();
  await expect(page.getByTestId('entry-preview')).toBeVisible();
  expect(await leftovers(page), 'the rollout editor, with its note in minutes and a check').toEqual([]);
  rollout = [entry({ canaries: [] }), entry({ canaries: ['n-bbbb2222', 'ephemeral'], bake_secs: 120 }, 'override', 'rollout-two')];
  await reopen(page, '[data-testid="editor-rollout"] [data-testid="entry-row"]');
  expect(await leftovers(page), 'no canaries, and two with a bake of two minutes').toEqual([]);
  await clean(page, sent);
});

test('api_012 pseudo locale leaves no literal text: settings, the system tab with its probes, changes and updates', async ({ page }) => {
  const sent = await watch(page);
  const upd = (o: Record<string, unknown>) => ({ checkedUnixSeconds: NOW - 7200, error: null, how: 'Pull the new image and restart the container.', latest: '0.9.1', latestCommit: 'def5678', latestDate: '2026-11-25', notesUrl: 'https://example.com/releases/0.9.1', state: 'available', ...o });
  const info = (o: Record<string, unknown>) => ({
    build: { channel: 'edge', commit: 'abc1234', date: '2026-11-24', install: 'container', target: 'x86_64-unknown-linux-gnu', version: '0.9.0' }, clientIpsMasked: null, cluster: null, filterNames: 1_250_000,
    filterSnapshot: 42, listeners: ['0.0.0.0:53', '[::]:53'], maintenance: null, node: 'lab', queryLog: true, role: 'primary', startedAt: T0, starts: 3, uncleanStarts: 1, update: upd({}), uptimeSeconds: 90_061, version: '0.9.0', ...o,
  });
  const probe = (target: string, o: Record<string, unknown>) => ({ certNames: [], checkedUnixSeconds: NOW - 5, consecutiveFailures: 0, error: null, latencyMs: 1.24, listener: true, node: null, ok: true, proto: 'udp', skipped: null, target, ...o });
  let probes: Record<string, unknown>[] | null = [
    probe('192.168.1.2:53', { node: 'lab' }),
    probe('192.168.1.2:853', { node: 'pi', proto: 'dot', certDaysLeft: 40, certNames: ['dns.home.arpa'], certSha256: 'ab:cd:ef:01:23:45:67:89', certSelfSigned: false }),
    probe('192.168.1.2:8053', { proto: 'api', certDaysLeft: 5, certSelfSigned: false }),
    probe('192.168.1.2:9953', { proto: 'doh', certDaysLeft: -3, certSelfSigned: false }),
    probe('192.168.1.2:8443', { proto: 'doh', certDaysLeft: 90_000, certSelfSigned: true }),
    probe('192.168.1.2:4443', { proto: 'dot', certDaysLeft: null, certError: 'the certificate could not be read' }),
    probe('1.1.1.1:53', { listener: false, ok: false, consecutiveFailures: 1, latencyMs: null, error: 'timed out' }),
    probe('[::1]:53', { ok: false, consecutiveFailures: 3, latencyMs: null, error: 'connection refused' }),
    probe('192.168.1.2:5353', { skipped: 'the listener is off', ok: false, latencyMs: null }),
  ];
  let state: Record<string, unknown> = info({});
  let changes: Record<string, unknown> = {
    items: [
      { actor: 'admin', kind: 'config.applied', node: 'lab', summary: 'Configuration version 40 applied', t: T0, tUnixMs: NOW * 1000 },
      { actor: null, kind: 'note', node: 'pi', source: 'api', summary: 'moved the access point', t: T0, tUnixMs: (NOW - 900) * 1000, href: '#/queries' },
    ],
    missingNodes: ['attic'],
    truncated: false,
  };
  let check: Answer = { json: upd({ state: 'up_to_date', latest: '0.9.0' }) };
  await page.route('**/api/v1/system/info', (r) => r.fulfill({ json: state }));
  await page.route('**/api/v1/system/probes', (r) => r.fulfill({ json: { items: probes ?? [] } }));
  await page.route('**/api/v1/annotations?**', (r) => r.fulfill({ json: changes }));
  await page.route('**/api/v1/system/update-check', (r) => r.fulfill(check));
  await signIn(page);
  await open(page, '/settings?tab=system', '[data-testid="updates"]');
  await expect(page.locator('[data-testid="probes"] table')).toBeVisible();
  await expect(page.locator('[data-testid="changes-list"] table')).toBeVisible();
  expect(await leftovers(page), 'system: restarts after a crash, every probe result and certificate, the changes, an update available').toEqual([]);
  await page.getByTestId('check-updates').click();
  await expect(page.getByTestId('updates').locator('.badge.warn')).toHaveCount(0);
  expect(await leftovers(page), 'up to date, checked now').toEqual([]);
  check = coded(502, 'unavailable', 'the release index did not answer');
  state = info({ update: upd({ state: 'unknown', error: 'the release index could not be reached', latest: null }) });
  await reopen(page, '[data-testid="updates"]');
  await page.getByTestId('check-updates').click();
  await expect(page.getByTestId('updates').locator('[role="alert"]')).toBeVisible();
  expect(await leftovers(page), 'not known yet, a check that fails').toEqual([]);
  for (const [name, update, rest] of [
    ['newer than the published build', upd({ state: 'newer', latest: '0.8.9' }), {}],
    ['newer, no version', upd({ state: 'newer', latest: null }), {}],
    ['updates off', upd({ state: 'off', checkedUnixSeconds: null }), {}],
    ['not known yet', upd({ state: 'unknown', error: null, latest: null, checkedUnixSeconds: null }), {}],
    ['available, without a date or notes', upd({ latestDate: null, notesUrl: null }), { starts: 1, uncleanStarts: 0, filterSnapshot: null, queryLog: false }],
    ['a restart that was not a crash', upd({ state: 'up_to_date' }), { starts: 2, uncleanStarts: 0 }],
  ] as [string, Record<string, unknown>, Record<string, unknown>][]) {
    state = info({ update, ...rest });
    await reopen(page, '[data-testid="updates"]');
    expect(await leftovers(page), name).toEqual([]);
  }
  // The changes: filtered by kind and by text, with nothing that matches, and none at all.
  await page.getByTestId('changes-list').locator('select').selectOption('note');
  await page.getByTestId('changes-list').locator('input[type="search"]').fill('zzzz');
  await expect(page.getByTestId('changes-list').locator('p.empty')).toBeVisible();
  expect(await leftovers(page), 'no change that matches').toEqual([]);
  changes = { items: [], truncated: false };
  probes = [];
  await reopen(page, '[data-testid="changes-list"] p.empty');
  expect(await leftovers(page), 'no changes and no probe results').toEqual([]);
  await clean(page, sent);
});

test('api_012 pseudo locale leaves no literal text: settings, query handling with its three editors', async ({ page }) => {
  const sent = await watch(page);
  declare('24h');
  await page.addInitScript(() => localStorage.setItem('telltale.mode.admin', 'advanced'));
  const entry = (kind: string, name: string, source: string, definition: Record<string, unknown> | null) => ({ kind, name, source, definition, credentials: null });
  let sets: Record<string, unknown[]> = {
    ratelimit: [entry('ratelimit', 'ratelimit', 'added', { enabled: true, queries: 1000, window_secs: 60, action: 'refused', exempt: ['127.0.0.0/8'] })],
    exclusions: [entry('exclusions', 'exclusions', 'added', { enabled: true, names: ['ntp.org'], clients: ['192.168.1.10'] })],
    simulate: [entry('simulate', 'simulate-settings', 'added', { enabled: true, plans_by_default: true, default_window: '12h' })],
  };
  let refuse = false;
  await page.route('**/api/v1/config/entries?kind=*', (r) => {
    const kind = new URL(r.request().url()).searchParams.get('kind') ?? '';
    return r.fulfill({ json: { items: sets[kind] ?? [] } });
  });
  await page.route(/\/api\/v1\/(ratelimit|exclusions|simulate-settings)\/[^/]+(\?.*)?$/, (r) => {
    if (refuse) return r.fulfill(coded(422, 'invalid_request', 'the value is out of range'));
    return r.fulfill({ json: { applied: !r.request().url().includes('dryRun=true'), configVersion: 7, impact: 'Changes this setting.', keepInGit: null, warnings: ['a dropped query is never answered'], recentQueries: 0 } });
  });
  await signIn(page);
  await open(page, '/settings?tab=queries', '[data-testid="editor-ratelimit"] [data-testid="entry-row"]');
  expect(await leftovers(page), 'query handling: everything on').toEqual([]);
  for (const kind of ['ratelimit', 'exclusions', 'simulate']) {
    await page.locator(`[data-testid="editor-${kind}"] [data-testid="entry-row"] button.link`).first().click();
    await expect(page.locator('form.form')).toBeVisible();
    await page.locator('form.form button.primary').click();
    await expect(page.getByTestId('entry-preview')).toBeVisible();
    expect(await leftovers(page), `the ${kind} editor, checked`).toEqual([]);
    refuse = kind === 'simulate';
    if (refuse) {
      await page.locator('form.form button:not(.primary)').first().click();
      await page.locator('form.form button.primary').click();
      await expect(page.locator('form.form [role="alert"]')).toBeVisible();
      expect(await leftovers(page), 'a setting refused').toEqual([]);
      refuse = false;
    }
    await page.locator('.drawer button[aria-label]').first().click();
  }
  sets = {
    ratelimit: [entry('ratelimit', 'ratelimit', 'override', { enabled: false })],
    exclusions: [entry('exclusions', 'exclusions', 'file', { enabled: false, names: ['ntp.org'], clients: ['192.168.1.10', '10.20.0.0/24'] })],
    simulate: [entry('simulate', 'simulate-settings', 'file', { enabled: false })],
  };
  await reopen(page, '[data-testid="editor-ratelimit"] [data-testid="entry-row"]');
  expect(await leftovers(page), 'query handling: everything off').toEqual([]);
  sets = {
    ratelimit: [entry('ratelimit', 'ratelimit', 'hidden', null)],
    exclusions: [entry('exclusions', 'exclusions', 'file', {})],
    simulate: [entry('simulate', 'simulate-settings', 'added', { enabled: true, plans_by_default: false })],
  };
  await reopen(page, '[data-testid="editor-ratelimit"] [data-testid="entry-row"]');
  expect(await leftovers(page), 'query handling: one left out, one with nothing, plans that wait to be asked').toEqual([]);
  sets = { ratelimit: [], exclusions: [], simulate: [] };
  await reopen(page, '[data-testid="editor-ratelimit"] p.empty');
  expect(await leftovers(page), 'query handling: none yet').toEqual([]);
  await clean(page, sent);
});

test('api_012 pseudo locale reads the help panel and the drawer it stands in as help, not a drawer that holds another drawer', async ({ page }) => {
  // A "?" button renders its drawer inline, so the drawer of a device holds the drawer of a help panel.
  await page.setContent(`
    <div class="drawer">
      <h2 title="Device title">Device</h2>
      <p>Groups</p>
      <button data-help title="Help">?</button>
      <div class="drawer">
        <h2 title="Topic title">How it works</h2>
        <div data-testid="help-panel"><p>Glossary words</p><button aria-label="Close help"></button></div>
        <span title="Drawer button">Own drawer</span>
      </div>
    </div>
    <div class="drawer"><p>A drawer with no help</p></div>
    <div data-testid="help-panel"><p>A panel in no drawer</p></div>`);
  const read = await page.evaluate(readPage);
  expect(read.text.sort()).toEqual(['?', 'A drawer with no help', 'Device', 'Groups']);
  expect(read.other.sort()).toEqual(['Device title']);
  expect(read.help.sort()).toEqual(['A panel in no drawer', 'Close help', 'Drawer button', 'Glossary words', 'Help', 'How it works', 'Own drawer', 'Topic title']);
});
