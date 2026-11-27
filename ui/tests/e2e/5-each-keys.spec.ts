// REQ: API-005 — a list the UI draws from data that can repeat a value is keyed by something unique (Svelte refuses a keyed
// list with two equal keys: the page's update stops with `each_key_duplicate`), and an identity is an id, never the text shown
// for it. Each browser test gives a page a state the server can send (mocked where a one-node test server cannot), checks what
// the page draws, and fails on a page error; a pure function is tested without a page. Expects the state 1-ui.spec.ts leaves
// (the admin, some queries), as 8-i18n-pages.spec.ts does.
import { expect, test, type Page } from '@playwright/test';
import { partKey, partsOf } from '../../src/lib/donut';
import { keyed, occurrenceKeys } from '../../src/lib/keys';
import { fold } from '../../src/lib/sankey';
import { failOnPageErrors } from './page-errors';

failOnPageErrors(test);
test.use({ viewport: { width: 1280, height: 900 } });

const ADMIN = { user: 'admin', pass: 'correct horse battery' };

async function signIn(page: Page) {
  await page.goto('/');
  await page.getByLabel('Username', { exact: true }).fill(ADMIN.user);
  await page.getByLabel('Password', { exact: true }).fill(ADMIN.pass);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Dashboard' }).first()).toBeVisible({ timeout: 30_000 });
}

const NOW = Math.floor(Date.now() / 1000);

// ---- Change markers (REQ: OBS-033). Past 40 in a chart's window they share a button per 8-px column, drawn at the pixel of
// its first marker; two neighbouring columns drawn at one pixel are one button. The charts key their buttons by the column.

const change = (t: number, seq: number) => ({ tUnixMs: Math.round(t * 1000), kind: 'config.applied', summary: `change ${seq}`, seq, node: null, nodes: [], actor: null, href: null });
/** The left edge (px) of every marker button, chart by chart. */
const lefts = (page: Page) =>
  page.getByTestId('chart-markers').evaluateAll((layers) => layers.map((l) => [...l.querySelectorAll<HTMLElement>('button.mk')].map((b) => parseFloat(b.style.left))));
/** How many markers every chart's buttons stand for (a button's count badge, or one). */
const held = (page: Page) =>
  page.getByTestId('chart-markers').evaluateAll((layers) =>
    layers.map((l) => [...l.querySelectorAll<HTMLElement>('button.mk')].reduce((n, b) => n + Number(b.querySelector('.mk-count')?.textContent?.replace('×', '') || 1), 0)),
  );

/**
 * Two markers at `a` and `b` (Unix seconds) show where the page's charts draw a time. The page is then loaded with markers in
 * pairs half a pixel apart, every 16.3 px across: the pairs' place against the 8-px columns moves by 0.3 px from one pair to
 * the next, so some pair has one marker in [8k + 3.5, 8k + 4) and the other in [8k + 4, 8k + 4.5), two columns drawn at one
 * pixel. Every chart (`charts` of them) must draw its buttons at different pixels, standing for every marker, with no page
 * error.
 */
async function straddle(page: Page, path: string, charts: number, a: number, b: number) {
  // Two loads of a page with charts after the sign-in, each waited for.
  test.setTimeout(60_000);
  const marks = { times: [a, b] };
  await page.route('**/api/v1/annotations?**', (r) => r.fulfill({ json: { items: marks.times.map((t, i) => change(t, i + 1)), truncated: false, missingNodes: [] } }));
  await page.goto(`/#${path}`);
  // A new load: the page may be at that address already, with the server's own markers.
  await page.reload();
  await expect.poll(async () => (await lefts(page)).map((l) => l.length), { timeout: 20_000 }).toEqual(Array(charts).fill(2));
  const [[xa, xb]] = await lefts(page);
  const at = (x: number) => a + ((x - xa) * (b - a)) / (xb - xa);
  const times: number[] = [];
  for (let x = xa + 2; x + 0.5 <= xb - 2; x += 16.3) times.push(at(x), at(x + 0.5));
  expect(times.length, 'more than 40 markers: 8-px columns').toBeGreaterThan(40);
  marks.times = times;
  await page.reload();
  const shared = (l: number[]) => l.length - new Set(l).size;
  await expect
    .poll(async () => (await lefts(page)).map((l) => (l.length > 2 && shared(l) === 0 ? 'drawn, one button a pixel' : `${l.length} buttons, ${shared(l)} at a shared pixel`)), { timeout: 20_000 })
    .toEqual(Array(charts).fill('drawn, one button a pixel'));
  expect(await held(page), 'every marker on a button').toEqual(Array(charts).fill(times.length));
}

test('api_005 obs_033 markers that share a pixel in two columns: the cache page and its two charts', async ({ page }) => {
  // The last hour of one node, a sample every 15 s: the charts' window is fixed.
  const end = Math.floor(NOW / 15) * 15;
  const point = (i: number) => ({ answeredPercent: 80, at: new Date((end - (240 - i) * 15) * 1000).toISOString(), bytes: 1e6, entries: 100, evictions: 0, hitPercent: 70, lookups: 50, prefetches: 0, staleServed: 0 });
  const stats = { answeredPercent: 80, bytes: 1e6, entries: 100, evictions: 0, hitPercent: 70, hits: 900, inserts: 500, misses: 100, node: null, prefetches: 0, staleServed: 0, uncacheable: 0, settings: null, sizing: null, warmStart: null, history: Array.from({ length: 241 }, (_, i) => point(i)) };
  await page.route('**/api/v1/cache/stats', (r) => r.fulfill({ json: { items: [stats] } }));
  await signIn(page);
  await straddle(page, '/cache', 2, end - 3300, end - 300);
});

test('api_005 obs_033 markers that share a pixel in two columns: the dashboard', async ({ page }) => {
  await signIn(page);
  await straddle(page, '/', 1, NOW - 22 * 3600, NOW - 2 * 3600);
});

test('api_005 obs_033 markers that share a pixel in two columns: the previous dashboard', async ({ page }) => {
  await signIn(page);
  await straddle(page, '/?view=legacy', 1, NOW - 22.8 * 3600, NOW - 1.2 * 3600);
});

// ---- The previous dashboard's donut ("Answers by status"): a part is a status, keyed by its id; its words are shown only.

test('api_005 api_012 the donut keys its parts by status: two statuses whose words read alike keep two parts', () => {
  // In a language, "cached" and "refreshed" may be one word.
  const parts = partsOf([
    { id: 'cached', label: 'W', color: '--s-cached', values: [1, 2] },
    { id: 'refreshed', label: 'W', color: '--s-refreshed', values: [4] },
  ]);
  expect(parts).toEqual([
    { id: 'cached', label: 'W', color: '--s-cached', value: 3 },
    { id: 'refreshed', label: 'W', color: '--s-refreshed', value: 4 },
  ]);
  expect(parts.map(partKey)).toEqual(['cached', 'refreshed']);
});

const bucket = (t: number, byStatus: Record<string, number>) => {
  const total = Object.values(byStatus).reduce((a, n) => a + n, 0);
  return { startUnixSeconds: t, total, byStatus, byQtype: { A: total }, byRcode: { NOERROR: total }, upstreamQueries: 0, upstreamFailures: 0, byGroup: {}, blockedByGroup: {}, slow: 0 };
};

test('api_005 the previous dashboard draws a donut of two statuses', async ({ page }) => {
  const last = Math.floor(NOW / 60) * 60;
  await page.route('**/api/v1/stats/timeseries?**', (r) => r.fulfill({ json: { items: Array.from({ length: 30 }, (_, i) => bucket(last - i * 60, { blocked: 3, forwarded: 7 })) } }));
  await signIn(page);
  await page.goto('/#/?view=legacy');
  const donut = page.locator('.donut');
  await expect(donut.locator('.breakdown li .name')).toHaveText(['blocked', 'forwarded']);
  await expect(donut.locator('circle.seg')).toHaveCount(2);
});

// ---- Lists keyed by place: the data can repeat a value (the server allows it, or passes it through).

const ITEMS = (items: unknown[]) => ({ items, missingNodes: [] });
const topItem = (key: string, count: number, o: Record<string, unknown> = {}) => ({ key, count, errorBound: 0, ...o });

test('api_005 names on my network: one zone for two sets of groups', async ({ page }) => {
  // The configuration check refuses the same zone twice for the same groups only.
  const zone = (groups: string[]) => ({ name: 'home.arpa', records: 2, groups, file: null, negativeTtlSeconds: 60 });
  await page.route('**/api/v1/zones', (r) => r.fulfill({ json: ITEMS([zone(['kids']), zone(['adults'])]) }));
  await signIn(page);
  await page.goto('/#/local-dns');
  const zones = page.getByTestId('zones').locator('tbody tr');
  await expect(zones.locator('td:nth-child(1)')).toHaveText(['home.arpa', 'home.arpa']);
  await expect(zones.locator('td:nth-child(3)')).toHaveText(['kids', 'adults']);
});

test('api_005 names on my network: a domain routed twice', async ({ page }) => {
  // The configuration check reads only a suffix's form: two routes (or one, twice) may send it.
  const forward = (servers: string[]) => ({ domain: 'corp.example', servers, source: 'file', stub: false });
  await page.route('**/api/v1/forwards', (r) => r.fulfill({ json: ITEMS([forward(['10.0.0.53']), forward(['10.0.0.54'])]) }));
  await signIn(page);
  await page.goto('/#/local-dns');
  const forwards = page.locator('section.card').filter({ has: page.getByRole('heading', { name: 'Domains sent to other servers' }) }).locator('tbody tr');
  await expect(forwards.locator('td:nth-child(1)')).toHaveText(['corp.example', 'corp.example']);
  await expect(forwards.locator('td:nth-child(2)')).toHaveText(['10.0.0.53', '10.0.0.54']);
});

test('api_005 groups: a schedule listed twice', async ({ page }) => {
  const group = {
    blockAnswerIps: [], blockMode: 'null_ip', blockTtlSeconds: 60, blocked24h: 0, blockedServices: [], color: '#4c9ffe', devicesThisHour: 0, dns64: false, dns64Prefix: null, filterAaaa: false, lists: null, name: 'kids', networks: ['10.9.0.0/16'],
    pausedUntilUnixSeconds: null, priority: 0, queries24h: 0, rebindingProtection: false, rewrites: [], safeSearch: false, schedules: ['night', 'night'], schedulesOn: [], upstreams: null, youtubeRestrict: null,
  };
  await page.route('**/api/v1/groups', (r) => r.fulfill({ json: ITEMS([group]) }));
  await signIn(page);
  await page.goto('/#/groups');
  await expect(page.getByTestId('group-schedules').locator('span[translate="no"]')).toHaveText(['night', 'night']);
});

// The groups of a device: a configured device's list is passed through as written (`groups = ["lab", "lab"]` is valid), and a
// top client's groups are sorted by priority with only neighbours made one, so two groups of one priority can leave a repeat.
const twiceLab = (page: Page) =>
  page.route('**/api/v1/stats/top?**', (r) => {
    const kind = new URL(r.request().url()).searchParams.get('kind');
    return r.fulfill({ json: ITEMS(kind === 'clients' ? [topItem('192.168.1.20', 12, { name: 'lab-pc', groups: ['lab', 'lab'] })] : []) });
  });

test('api_005 clients: the last hour, a client whose groups list one group twice', async ({ page }) => {
  await twiceLab(page);
  await signIn(page);
  await page.goto('/#/clients');
  await expect(page.locator('main table tbody tr').first().locator('.group-chip')).toHaveText(['lab', 'lab']);
});

test('api_005 clients: the devices, a device whose groups list one group twice', async ({ page }) => {
  await page.route('**/api/v1/clients', (r) =>
    r.fulfill({ json: ITEMS([{ name: 'lab-pc', match: ['192.168.1.20'], groups: ['lab', 'lab'], effectiveGroups: ['lab', 'lab'], groupsFrom: 'client', source: 'file', identity: null, kind: null }]) }),
  );
  await signIn(page);
  await page.goto('/#/clients?tab=devices');
  await expect(page.locator('main table tbody tr').first().locator('.group-chip')).toHaveText(['lab', 'lab']);
});

test('api_005 the dashboard: a top client whose groups list one group twice', async ({ page }) => {
  await twiceLab(page);
  await signIn(page);
  await page.goto('/#/');
  await page.reload();
  await expect(page.locator('ol.tl .gdot')).toHaveCount(2);
});

test('api_005 the previous dashboard: a top client whose groups list one group twice', async ({ page }) => {
  await twiceLab(page);
  await signIn(page);
  await page.goto('/#/?view=legacy');
  await expect(page.locator('ol.bars .group-chip')).toHaveText(['lab', 'lab']);
});

test('api_005 cache: one node lists a name and type twice', async ({ page }) => {
  // The cache keeps an answer per routing view and per CD bit (and per client subnet), and its top list does not say which:
  // one node can list a name and type twice. Two nodes answer, so the names are merged and a row opens per node.
  const makeup = { nodata: 0, nxdomain: 0, positive: 3, servfail: 0, stale: 0, validated: 0 };
  const entry = (hits: number) => ({ ageSeconds: 5, answers: 1, authentic: false, bytes: 90, dnssecOk: false, hits, name: 'twice.example', qtype: 'A', rcode: 'NOERROR', ttlLeftSeconds: 120 });
  await page.route('**/api/v1/cache/entries?**', (r) => r.fulfill({ json: ITEMS([{ node: 'pi', makeup, entries: [entry(4), entry(2)] }, { node: 'homelab', makeup, entries: [entry(1)] }]) }));
  await signIn(page);
  await page.goto('/#/cache');
  const row = page.getByTestId('cache-top').locator('tbody tr').filter({ hasText: 'twice.example' });
  await row.locator('button[aria-expanded]').click();
  await expect(page.locator('ul.per-node li strong')).toHaveText(['pi', 'pi', 'homelab']);
});

test("api_005 a device's day: two markers of one kind in the same millisecond", async ({ page }) => {
  // Two notes saved with the same time (the note form sends whole minutes).
  const t0 = Math.floor(NOW / 3600) * 3600 - 23 * 3600;
  const bins = Array.from({ length: 24 }, (_, i) => t0 + i * 3600);
  const iso = (u: number) => new Date(u * 1000).toISOString();
  const lane = { domain: 'example.com', other: false, counts: bins.map(() => 2), blocked: bins.map(() => 0), slow: bins.map(() => 0), total: 48, blockedTotal: 0, firstSeenTime: null };
  const marker = (summary: string) => ({ tUnixMs: (t0 + 5 * 3600) * 1000, kind: 'note', summary, node: null, nodes: [], actor: 'admin', href: null, seq: null });
  const day = {
    client: '127.0.0.1', from: iso(t0), to: iso(t0 + 24 * 3600), binSeconds: 3600, bins, source: 'querylog', truncated: false, truncatedReason: null, coverageFrom: null,
    lanes: [lane], queries: bins.map(() => 2), p99Ms: bins.map(() => 3), events: [], markers: [marker('first note'), marker('second note')],
  };
  await page.route('**/api/v1/clients/*/timeline*', (r) => r.fulfill({ json: day }));
  await signIn(page);
  await page.goto('/#/clients?device=127.0.0.1&view=timeline');
  await expect(page.getByTestId('timeline-marker')).toHaveCount(2);
  await expect(page.getByTestId('timeline-marker').last()).toHaveAttribute('title', /second note$/);
});

test('api_005 analyze: a statistic asked twice', async ({ page }) => {
  // The server's answer for the query: it repeats the column (one per statistic asked).
  const q = 'from -1h | stats count, count';
  await signIn(page);
  const res = await page.request.get(`/api/v1/analytics/vqlog?q=${encodeURIComponent(q)}`);
  expect(res.status()).toBe(200);
  const body = await res.json();
  expect(body.columns).toEqual(['count', 'count']);
  await page.goto(`/#/analyze?q=${encodeURIComponent(q)}`);
  await expect(page.getByTestId('vqlog-result').locator('thead th')).toHaveText(['count', 'count']);
});

// Server text: the page shows the warnings and notes as the server sends them, and nothing promises that they differ.
const twice = (s: string) => [s, s];
const dry = (warnings: string[]) => ({ applied: false, configVersion: 7, impact: 'Adds one entry.', keepInGit: null, warnings, recentQueries: 0 });

test("api_005 an editor's dry run: a warning the server repeats", async ({ page }) => {
  await page.route('**/api/v1/groups/eachkeys-group*', (r) => r.fulfill({ json: dry(twice('A warning the server gave twice.')) }));
  await signIn(page);
  await page.goto('/#/groups');
  await page.locator('[data-testid="editor-group"] .head > button').click();
  await page.locator('form.form input.mono').first().fill('eachkeys-group');
  await page.locator('form.form button.primary').click();
  await expect(page.getByTestId('entry-preview').locator('.warn-text')).toHaveText(twice('A warning the server gave twice.'));
});

test("api_005 a mute's dry run: a warning the server repeats", async ({ page }) => {
  await page.route('**/api/v1/anomaly-mutes/*', (r) => r.fulfill({ json: dry(twice('A mute warning the server gave twice.')) }));
  const finding = { acknowledged: null, baseline: 40, client: '127.0.1.11', clientName: null, detail: 'Many more queries than usual in this hour.', domain: null, id: 'f-1', informational: false, kind: 'rate_spike', mutedBy: null, nodes: [], observed: 900, rhythm: null, spread: 12, stormMute: null, threshold: 200, windowSeconds: 3600, windowStart: new Date(NOW * 1000).toISOString() };
  await page.route('**/api/v1/analytics/anomalies?**', (r) => r.fulfill({ json: { items: [finding] } }));
  await signIn(page);
  await page.goto('/#/anomalies');
  await page.getByTestId('mute').first().click();
  await expect(page.getByTestId('mute-form').locator('.notice.warn')).toHaveText(twice('A mute warning the server gave twice.'));
});

test("api_005 an agent's plan: a warning the server repeats", async ({ page }) => {
  const plan = { id: 'p-1', state: 'pending', summary: 'Block game.example.com', tool: 'rules', method: 'PUT', path: '/api/v1/rules/p-1', reason: 'a test', requestedBy: 'agent', needsApproval: true, configVersion: 3, createdUnixSeconds: NOW - 60, expiresUnixSeconds: NOW + 400, preview: { impact: 'Blocks game.example.com.', warnings: twice('A plan warning the server gave twice.') } };
  await page.route('**/api/v1/plans', (r) => r.fulfill({ json: { items: [plan] } }));
  await signIn(page);
  await page.goto('/#/agent-changes');
  await expect(page.getByTestId('plan').locator('.warn-text')).toHaveText(twice('A plan warning the server gave twice.'));
});

test('api_005 a support package: a note the server repeats', async ({ page }) => {
  await page.route('**/api/v1/system/support-package?**', (r) => r.fulfill({ json: { created: new Date(NOW * 1000).toISOString(), level: 'strict', files: [], redactions: {}, notes: twice('A note the server gave twice.') } }));
  await signIn(page);
  await page.goto('/#/settings?tab=system');
  await page.getByTestId('support-preview').click();
  await expect(page.getByTestId('support-manifest').getByText('A note the server gave twice.', { exact: true })).toHaveCount(2);
});

// ---- Identities by id, not by the text shown.

test('api_005 obs_026 the traffic map: two services with one name are two tiles', async ({ page }) => {
  const service = (id: string) => ({ id, name: 'StreamCo', category: 'video', domains: [`${id}.example`] });
  await page.route('**/api/v1/services', (r) => r.fulfill({ json: ITEMS([service('stream-a'), service('stream-b')]) }));
  await page.route('**/api/v1/stats/top?**', (r) => {
    const kind = new URL(r.request().url()).searchParams.get('kind');
    return r.fulfill({ json: ITEMS(kind === 'blocked' ? [] : [topItem('www.stream-a.example', 600), topItem('www.stream-b.example', 400)]) });
  });
  await page.addInitScript(() => localStorage.setItem('traffic.mode', 'service'));
  await signIn(page);
  await page.goto('/#/traffic');
  const tiles = page.locator('a.tile');
  await expect(tiles.locator('.name')).toHaveText(['StreamCo', 'StreamCo']);
  await expect(tiles.first()).toHaveAttribute('href', /name=stream-a\.example/);
  await expect(tiles.last()).toHaveAttribute('href', /name=stream-b\.example/);
  await tiles.last().hover({ position: { x: 5, y: 5 } });
  await expect(page.locator('.details .members li a:not(.when)')).toHaveText(['www.stream-b.example']);
});

test('api_005 obs_032 the flow folds small groups into one marked node, and a group called other stays itself', () => {
  const n = (stage: string, name: string, count: number) => ({ id: `${stage}:${name}`, stage, name, count, deadEnd: 0 });
  const l = (source: string, target: string, count: number) => ({ source, target, count, failure: false });
  const nodes = [n('group', 'default', 595), n('group', 'other', 393), n('group', 'guests', 5), n('group', 'iot', 4), n('group', 'tv', 3), n('status', 'forwarded', 1000)];
  const links = nodes.filter((x) => x.stage === 'group').map((x) => l(x.id, 'status:forwarded', x.count));
  const f = fold(nodes, links, 1000, 0.005);
  expect(f.folded).toBe(2);
  // The group called other keeps its count and its place; the folded node is last, after a smaller one.
  expect(f.nodes.filter((x) => x.stage === 'group').map((x) => [x.id, x.name, x.count, x.folded === true])).toEqual([
    ['group:default', 'default', 595, false],
    ['group:other', 'other', 393, false],
    ['group:guests', 'guests', 5, false],
    ['group/other', 'other', 7, true],
  ]);
  expect(f.links.map((x) => [x.source, x.count])).toEqual([['group:default', 595], ['group:other', 393], ['group/other', 7], ['group:guests', 5]]);
  expect(new Set(f.nodes.map((x) => x.id)).size).toBe(f.nodes.length);
});

test('api_005 obs_032 the flow page: a group called other keeps its link, the folded node has none', async ({ page }) => {
  const n = (stage: string, name: string, count: number) => ({ id: `${stage}:${name}`, stage, name, count, deadEnd: 0 });
  const l = (source: string, target: string, count: number) => ({ source, target, count, failure: false });
  const groups = [n('group', 'default', 600), n('group', 'other', 393), n('group', 'iot', 4), n('group', 'tv', 3)];
  const flow = {
    from: new Date((NOW - 3600) * 1000).toISOString(), to: new Date(NOW * 1000).toISOString(), client: null, source: 'buckets', total: 1000, partial: false, truncated: false, missingNodes: [],
    nodes: [...groups, n('status', 'forwarded', 1000), n('rcode', 'NOERROR', 1000)],
    links: [...groups.map((g) => l(g.id, 'status:forwarded', g.count)), l('status:forwarded', 'rcode:NOERROR', 1000)],
  };
  await page.route('**/api/v1/stats/flow?**', (r) => r.fulfill({ json: flow }));
  await signIn(page);
  await page.goto('/#/flow');
  const svg = page.getByTestId('flow-svg');
  const other = svg.locator('[data-id="group:other"]');
  await expect(other).toHaveAttribute('href', '#/groups');
  await expect(other).toHaveAttribute('aria-label', 'Groups other: 393 (39.3 %)');
  const folded = svg.locator('[data-id="group/other"]');
  await expect(folded).toHaveAttribute('aria-label', 'Groups other: 7 (0.7 %)');
  await expect(folded).not.toHaveAttribute('href', /./);
});

// ---- The listener checks (REQ: OBS-020): the extra targets are taken as listed, unchecked against the listeners and each
// other, so a target can be probed twice on one node.

test('api_005 obs_020 the listener checks: one target checked twice', async ({ page }) => {
  const probe = (latencyMs: number) => ({ node: null, target: 'udp://127.0.0.1:53', proto: 'udp', listener: false, ok: true, checkedUnixSeconds: NOW, consecutiveFailures: 0, latencyMs, lastOkUnixSeconds: NOW, error: null, skipped: null });
  await page.route('**/api/v1/system/probes', (r) => r.fulfill({ json: ITEMS([probe(0.4), probe(0.6)]) }));
  await signIn(page);
  await page.goto('/#/settings?tab=system');
  await expect(page.getByTestId('probes').locator('tbody tr td:nth-child(3)')).toHaveText(['0.4 ms', '0.6 ms']);
});

// ---- Names shown as the server keeps them: unescaped (a label that holds a dot, bytes that are not UTF-8) and, for a
// device's rhythm, cut at 64 characters, so two names can read alike.

test('api_005 obs_018 a shadow list: two of its names read alike', async ({ page }) => {
  const at = new Date(NOW * 1000).toISOString();
  const list = { list: 'trackers', hits: 9, devices: 1, since: at, lastHitAt: at, topNames: [{ name: 'a.b.example', count: 5 }, { name: 'a.b.example', count: 4 }], nodes: [] };
  await page.route('**/api/v1/analytics/shadow-lists', (r) => r.fulfill({ json: ITEMS([list]) }));
  await signIn(page);
  await page.goto('/#/lists');
  await expect(page.getByTestId('shadow-lists').locator('.names .name')).toHaveText(['a.b.example 5', 'a.b.example 4']);
});

test("api_005 obs_031 a device's rhythm: two domains that read alike", async ({ page }) => {
  // Two registrable domains of 67 characters (a 63-character label, then .com or .net), each cut to its first 64.
  const cut = `${'x'.repeat(63)}.`;
  const bins = Array.from({ length: 24 }, (_, i) => (i === 9 ? 30 : 0));
  const domain = (meanPerHour: number) => ({ domain: cut, dominantBin: 9, dominantSharePct: 100, hour: bins, recent: bins, knownPeriodic: false, meanPerHour, nodes: [], period: 'every 38 s', regularHours: 0, since: new Date(NOW * 1000).toISOString() });
  const rhythm = { available: true, client: '127.0.1.11', missingNodes: [], reason: null, binsS: [1, 1.5, 2.2, 3.3, 5, 7.5, 11, 17, 25, 38, 56, 84, 126, 190, 285, 427, 640, 960, 1440, 2160, 3240, 4860, 7290], domains: [domain(60), domain(30)] };
  await page.route('**/api/v1/clients/*/rhythm', (r) => r.fulfill({ json: rhythm }));
  await signIn(page);
  await page.goto('/#/clients?device=127.0.1.11');
  await expect(page.getByTestId('rhythm-row')).toHaveCount(2);
  await page.getByTestId('rhythm-table-toggle').click();
  await expect(page.getByTestId('rhythm-table').locator('tbody tr')).toHaveCount(2);
});

// ---- A forwarded domain's row stays with its domain: its Remove acts at once.

test('api_005 the keys of a list whose values can repeat: each value with how many times it came before', () => {
  expect(occurrenceKeys(['corp.example', 'lab.example', 'corp.example'])).toEqual(['corp.example\u00000', 'lab.example\u00000', 'corp.example\u00001']);
  // A value listed once has one key wherever it is.
  expect(occurrenceKeys(['lab.example'])).toEqual(occurrenceKeys(['corp.example', 'lab.example']).slice(1));
});

test('api_005 names on my network: after a forwarded domain is removed, the focus is not on the next one', async ({ page }) => {
  let domains = ['corp.example', 'lab.example'];
  await page.route('**/api/v1/forwards', (r) => r.fulfill({ json: ITEMS(domains.map((domain) => ({ domain, servers: ['10.0.0.53'], source: 'api', stub: false }))) }));
  await page.route('**/api/v1/forwards/*', (r) => {
    if (r.request().method() !== 'DELETE') return r.fallback();
    const gone = decodeURIComponent(new URL(r.request().url()).pathname.split('/').pop() ?? '');
    domains = domains.filter((d) => d !== gone);
    return r.fulfill({ json: { applied: true, configVersion: 8, impact: '', keepInGit: null, warnings: [], recentQueries: 0 } });
  });
  await signIn(page);
  await page.goto('/#/local-dns');
  await page.getByRole('button', { name: 'Stop sending corp.example' }).focus();
  await page.keyboard.press('Enter');
  const forwards = page.locator('section.card').filter({ has: page.getByRole('heading', { name: 'Domains sent to other servers' }) }).locator('tbody tr');
  await expect(forwards.locator('td:nth-child(1)')).toHaveText(['lab.example']);
  // The removed domain's row went with its button: a second Enter would not remove the next domain.
  expect(await page.evaluate(() => document.activeElement?.getAttribute('aria-label') ?? '')).not.toBe('Stop sending lab.example');
});

// ---- Firing alerts: one per rule and subject, both free text.

test('api_005 alerts: two firing alerts whose rule and subject join to the same text', async ({ page }) => {
  const firing = [{ rule: 'down', subject: 'quad9', summary: 'One.' }, { rule: 'downq', subject: 'uad9', summary: 'Two.' }];
  await page.route(/\/api\/v1\/alerts$/, (r) => r.fulfill({ json: { evaluating: true, firing, maintenance: [], deliveries: [] } }));
  await signIn(page);
  await page.goto('/#/alerts');
  await expect(page.getByTestId('alerts-now').locator('tbody tr td:nth-child(3)')).toHaveText(['One.', 'Two.']);
});

// ---- Top lists whose names read alike: two different names the server sends as the same text (a dot inside a label,
// bytes that are not UTF-8). Each list keys its rows by the name with its occurrence.

test('api_005 a list keyed by text and occurrence keeps its items and their order', () => {
  const items = [{ key: 'a.b.example' }, { key: 'c.example' }, { key: 'a.b.example' }];
  const rows = keyed(items, (x) => x.key);
  expect(rows.map((r) => r.item)).toEqual(items);
  expect(rows[0].item).toBe(items[0]);
  expect(rows.map((r) => r.key)).toEqual(occurrenceKeys(items.map((x) => x.key)));
  expect(new Set(rows.map((r) => r.key)).size).toBe(3);
});

/** The hour's top lists: two names that read alike, for domains and for blocked names. */
const alike = (page: Page) =>
  page.route('**/api/v1/stats/top?**', (r) => {
    const kind = new URL(r.request().url()).searchParams.get('kind');
    const items = kind === 'domains' ? [topItem('a.b.example', 9), topItem('a.b.example', 8)] : kind === 'blocked' ? [topItem('ads.b.example', 3), topItem('ads.b.example', 2)] : [];
    return r.fulfill({ json: ITEMS(items) });
  });

test('api_005 obs_026 the traffic map: a tile of two names that read alike', async ({ page }) => {
  await page.route('**/api/v1/services', (r) => r.fulfill({ json: ITEMS([]) }));
  await alike(page);
  await page.addInitScript(() => localStorage.setItem('traffic.mode', 'site'));
  await signIn(page);
  await page.goto('/#/traffic');
  await page.locator('a.tile').first().hover({ position: { x: 5, y: 5 } });
  await expect(page.locator('.details .members li a:not(.when)')).toHaveText(['a.b.example', 'a.b.example']);
});

test('api_005 the dashboard: top names that read alike, each row with its own details', async ({ page }) => {
  // And a pod's search-suffix expansions of one name, merged into one row: its variants read alike too.
  const asked = 'api.example.com.default.svc.cluster.local';
  await page.route('**/api/v1/stats/top?**', (r) => {
    const kind = new URL(r.request().url()).searchParams.get('kind');
    return r.fulfill({ json: ITEMS(kind === 'domains' ? [topItem('a.b.example', 9), topItem('a.b.example', 8), topItem(asked, 4), topItem(asked, 3)] : []) });
  });
  await signIn(page);
  await page.goto('/#/');
  await page.reload();
  const rows = page.locator('ol.tl > li');
  await expect(rows).toHaveCount(3);
  await expect(rows.locator('a.dom').first()).toHaveText('a.b.example');
  await expect(rows.nth(1).locator('a.dom')).toHaveText('a.b.example');
  // One row opened: its own details only.
  await rows.nth(1).locator('button.n').click();
  await expect(rows.nth(1)).toHaveClass(/open/);
  await expect(rows.nth(0)).not.toHaveClass(/open/);
  await rows.nth(2).locator('button.n').click();
  await expect(rows.nth(2).locator('ul.vars code')).toHaveText([asked, asked]);
});

test('api_005 the previous dashboard: top names that read alike', async ({ page }) => {
  await alike(page);
  await signIn(page);
  await page.goto('/#/?view=legacy');
  await expect(page.locator('ol.bars').first().locator('a.name')).toHaveText(['a.b.example', 'a.b.example']);
  await expect(page.locator('ol.bars').nth(1).locator('a.name')).toHaveText(['ads.b.example', 'ads.b.example']);
});

test("api_005 groups: a group's top names that read alike", async ({ page }) => {
  const group = {
    blockAnswerIps: [], blockMode: 'null_ip', blockTtlSeconds: 60, blocked24h: 5, blockedServices: [], color: '#4c9ffe', devicesThisHour: 1, dns64: false, dns64Prefix: null, filterAaaa: false, lists: null, name: 'kids', networks: ['10.9.0.0/16'],
    pausedUntilUnixSeconds: null, priority: 0, queries24h: 20, rebindingProtection: false, rewrites: [], safeSearch: false, schedules: [], schedulesOn: [], upstreams: null, youtubeRestrict: null,
  };
  await page.route('**/api/v1/groups', (r) => r.fulfill({ json: ITEMS([group]) }));
  await alike(page);
  await signIn(page);
  await page.goto('/#/groups');
  const lists = page.locator('.tops ol');
  await expect(lists.nth(0).locator('li')).toHaveText(['a.b.example 9', 'a.b.example 8']);
  await expect(lists.nth(1).locator('li')).toHaveText(['ads.b.example 3', 'ads.b.example 2']);
});

test('api_005 obs_035 the wall map: two tiles whose names read alike, each in its own place', async ({ page }) => {
  await page.route('**/api/v1/stats/top?**', (r) => r.fulfill({ json: ITEMS([topItem('a.b.example', 900), topItem('a.b.example', 800), topItem('c.example', 700)]) }));
  await signIn(page);
  await page.goto('/#/wall?layout=single&panels=map&motion=off');
  const tiles = page.getByTestId('wall-map').locator('.tile');
  await expect(tiles.locator('.name')).toHaveText(['a.b.example', 'a.b.example', 'c.example']);
  const places = await tiles.evaluateAll((els) => els.map((e) => `${(e as HTMLElement).style.left},${(e as HTMLElement).style.top}`));
  expect(new Set(places).size).toBe(3);
});

// ---- The upstreams' second opinions (REQ: OBS-019): with every answer checked, a dual-stack device's A and AAAA questions for
// one name can disagree in the same millisecond, and one question asked twice can disagree twice.

const disagreement = (name: string, qtype: string, o: Record<string, unknown> = {}) => ({
  at: '2026-11-24T12:00:00.123Z', name, qtype, result: 'filtered', upstream: 'family-dns', answer: 'NXDOMAIN', reference: 'quad9', referenceAnswer: 'NOERROR 192.0.2.7', ...o,
});
const quality = (upstream: string) => ({
  upstream, same: 40, differentAddresses: 0, differentRcode: 0, filtered: 2, unanswered: 0, dnssecSecure: 0, dnssecInsecure: 0, dnssecBogus: 0, dnssecIndeterminate: 0, ede: [],
});
const checksOf = (node: string | null, recent: unknown[]) => ({ node, enabled: true, sampleEvery: 1, reference: 'quad9', upstreams: [quality('family-dns')], recent });

test('api_005 obs_019 the upstreams: disagreements at the same time about one name', async ({ page }) => {
  const recent = [disagreement('dual.example', 'A'), disagreement('dual.example', 'AAAA'), disagreement('twice.example', 'A'), disagreement('twice.example', 'A')];
  await page.route('**/api/v1/analytics/upstream-checks', (r) => r.fulfill({ json: { items: [checksOf(null, recent)] } }));
  await signIn(page);
  await page.goto('/#/upstreams');
  await expect(page.locator('ul.disagreements li span.mono')).toHaveText(['dual.example', 'dual.example', 'twice.example', 'twice.example']);
  await expect(page.locator('ul.disagreements li')).toHaveText([/dual\.example A ·/, /dual\.example AAAA ·/, /twice\.example A ·/, /twice\.example A ·/]);
});

// ---- Nodes by the name the server shows for them: a pod's name, else its site, else its ID. Two machines of one site (no pods)
// show the same name.

test('api_005 obs_019 the upstreams: two nodes that show one name', async ({ page }) => {
  await page.route('**/api/v1/analytics/upstream-checks', (r) =>
    r.fulfill({ json: { items: [checksOf('home', [disagreement('one.example', 'A')]), checksOf('home', [disagreement('two.example', 'A')])] } }),
  );
  await signIn(page);
  await page.goto('/#/upstreams');
  await expect(page.getByTestId('upstream-quality').locator('tbody tr td:first-child')).toHaveText(['home', 'home']);
  await expect(page.locator('ul.disagreements li span.mono')).toHaveText(['one.example', 'two.example']);
});

test('api_005 dns_006 the cache: two nodes that show one name, each card with its own settings', async ({ page }) => {
  const settings = {
    maxBytes: 64e6, maxEntries: null, maxTtlSeconds: 86_400, minTtlSeconds: 30, negativeTtlMaxSeconds: 3600, persist: false, prefetch: false, prefetchMinHits: 3, prefetchThresholdPercent: 10, serveStale: false,
    servfailTtlSeconds: 60, staleAnswerWaitMs: null, staleMaxAgeSeconds: 86_400,
  };
  const stat = (entries: number) => ({ answeredPercent: 80, bytes: 1e6, entries, evictions: 0, hitPercent: 70, hits: 900, inserts: 500, misses: 100, node: 'home', prefetches: 0, staleServed: 0, uncacheable: 0, settings, sizing: null, warmStart: null, history: [] });
  const makeup = (positive: number) => ({ nodata: 0, nxdomain: 0, positive, servfail: 0, stale: 0, validated: 0 });
  await page.route('**/api/v1/cache/stats', (r) => r.fulfill({ json: { items: [stat(100), stat(200)] } }));
  await page.route('**/api/v1/cache/entries?**', (r) => r.fulfill({ json: ITEMS([{ node: 'home', makeup: makeup(3), entries: [] }, { node: 'home', makeup: makeup(5), entries: [] }]) }));
  await signIn(page);
  await page.goto('/#/cache');
  const cards = page.getByTestId('cache-node');
  await expect(cards.locator('h2')).toHaveText(['home', 'home']);
  await expect(cards.nth(1)).toContainText('200 answers');
  await expect(page.getByTestId('cache-makeup').locator('tbody tr td:nth-child(2)')).toHaveText(['3 answers', '5 answers']);
  await expect(page.locator('.head-row select[aria-label="Node"] option')).toHaveText(['every node', 'home', 'home']);
  await expect(page.getByTestId('cache-card').locator('select[aria-label="Node"] option')).toHaveText(['every node', 'home', 'home']);
  // The second card's settings opened: that card's only.
  await cards.nth(1).locator('details summary').click();
  await expect(cards.nth(1).locator('details')).toHaveAttribute('open', '');
  await expect(cards.nth(0).locator('details')).not.toHaveAttribute('open', '');
});

test('api_005 ops_010 alerts: two nodes in maintenance that show one name', async ({ page }) => {
  const maintenance = (reason: string) => ({ by: 'admin', node: 'home', reason, secondsLeft: 600, since: new Date(NOW * 1000).toISOString(), until: new Date((NOW + 600) * 1000).toISOString() });
  await page.route(/\/api\/v1\/alerts$/, (r) => r.fulfill({ json: { evaluating: true, firing: [], maintenance: [maintenance('SD card swap'), maintenance('new power supply')], deliveries: [] } }));
  await signIn(page);
  await page.goto('/#/alerts');
  await expect(page.getByTestId('alerts-maintenance')).toHaveCount(2);
  await expect(page.getByTestId('alerts-maintenance').first()).toContainText('SD card swap');
  await expect(page.getByTestId('alerts-maintenance').last()).toContainText('new power supply');
});

test("api_005 clu_014 a drill's report: two nodes that show one name", async ({ page }) => {
  const at = new Date(NOW * 1000).toISOString();
  const member = (nodeId: string, o: Record<string, unknown>) => ({
    behindSeconds: null, cacheEntries: 1200, cacheHitPercent: 61.5, certExpiresAt: null, configLag: 0, configSeq: 42, configSource: 'file', connected: true, eligible: true, ephemeral: false, host: null,
    kubeNode: null, lastSeenSecondsAgo: 1, link: 'direct', maintenance: null, nodeId, pod: null, protocol: 3, qps: 4.2, querySharePercent: 50, ready: true, restarts: 0, rttMs: 1.4, servfailPercent: 0.2,
    site: 'home', sourceCommit: null, startedAt: at, thisNode: false, up: true, upstreamP90Ms: 21, uptimeSeconds: 86_400, version: '0.9.0', witness: false, ...o,
  });
  const cluster = {
    authority: null, checks: [], clusterId: 'c-home', conflicts: [], enabled: true, events: [], healthy: true, host: null, name: 'home', newestConfigSeq: 42, rollout: null, source: null, thisNode: 'n-aaaa1111',
    failover: { active: true, leaseHeld: true, leaseSecondsLeft: 8, mode: 'automatic', reachableVoters: 2, votedEpoch: 4, votedFor: 'n-aaaa1111', voters: 2 },
    nodes: [member('n-aaaa1111', { role: 'primary', thisNode: true, rttMs: null }), member('n-bbbb2222', { role: 'secondary' })],
  };
  const drill = { by: 'admin', coveragePercent: 80, elsewhere: 0, ended: at, followed: 1, id: 'd-1', medianFailoverMs: 2300, missingNodes: [], node: 'home', p90FailoverMs: 4100, quiet: 0, reason: 'monthly', since: at, status: 'complete', stuck: 0, targets: 'everyone', until: at, viaBalancer: false };
  const report = { ...drill, baseline: 6, overflow: 0, nodes: [{ node: 'home', queries: 3, devices: 1 }, { node: 'home', queries: 5, devices: 2 }], devices: [] };
  await page.route('**/api/v1/cluster', (r) => r.fulfill({ json: cluster }));
  await page.route('**/api/v1/drills?**', (r) => r.fulfill({ json: { items: [drill], missingNodes: [] } }));
  await page.route('**/api/v1/drills/d-1', (r) => r.fulfill({ json: report }));
  await signIn(page);
  await page.goto('/#/cluster?tab=drills');
  await page.getByTestId('drill-open').click();
  const counts = page.getByTestId('drill-report').locator('p.small.muted').last();
  await expect(counts).toContainText('home: 3 queries from 1 devices');
  await expect(counts).toContainText('home: 5 queries from 2 devices');
});

test('api_005 ops_011 a cluster support package: two nodes that show one name', async ({ page }) => {
  const nodes = [
    { node: 'home', status: 'ok', files: 12, bytes: 4096, note: null },
    { node: 'home', status: 'missing', files: 0, bytes: 0, note: 'not connected' },
  ];
  await page.route('**/api/v1/system/support-package?**', (r) => r.fulfill({ json: { created: new Date(NOW * 1000).toISOString(), level: 'strict', redactions: {}, notes: [], nodes } }));
  await signIn(page);
  await page.goto('/#/settings?tab=system');
  await page.getByTestId('support-preview').click();
  const rows = page.getByTestId('support-node');
  await expect(rows.locator('td:first-child')).toHaveText(['home', 'home']);
  await expect(rows.last()).toContainText('not connected');
});
