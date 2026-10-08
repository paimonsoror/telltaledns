// Screenshots of the main pages for the site (T4.7, DOC-002), written to site/assets/shots/ as
// JPEG. Regenerate with `SHOTS=1 npx playwright test` (after 1-ui.spec.ts); skipped
// otherwise. Expects the state left by ui.spec.ts (admin `admin`, some traffic).
import { test } from '@playwright/test';
import { resolve } from 'node:path';

const shot = (name: string) => resolve(import.meta.dirname, '../../../site/assets/shots', `${name}.jpg`);
const review = (name: string) => resolve(import.meta.dirname, '../../.shots', `${name}.jpg`);

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
    await page.getByLabel('Username', { exact: true }).fill('admin');
    await page.getByLabel('Password', { exact: true }).fill('correct horse battery');
    await page.getByRole('button', { name: 'Sign in' }).click();
    // The dashboard's site shots come from the demo network instead (tests/demo/run.sh): this
    // server is minutes old and has one client, which makes for an empty-looking dashboard.
    for (const [name, path] of [
      ['queries', '/#/queries'],
      ['lists', '/#/lists'],
      ['settings', '/#/settings?tab=tokens'],
      ['cache', '/#/cache'],
    ]) {
      await page.goto(path);
      await page.waitForTimeout(600);
      await page.screenshot({ path: shot(`${name}-${theme}`), type: 'jpeg', quality: 80 });
    }
    // The Cluster page with example data (the test server runs alone): a controller and three
    // resolver pods on two Kubernetes nodes, and a Pi. The site's caption says it's an example.
    await page.route('**/api/v1/cluster', (route) => route.fulfill({ json: exampleCluster() }));
    await page.goto('/#/cluster');
    await page.waitForTimeout(600);
    await page.screenshot({ path: shot(`cluster-${theme}`), type: 'jpeg', quality: 80 });
    await page.unroute('**/api/v1/cluster');
    // "Why?" on a blocked query: it names the list and the rule.
    await page.goto('/#/queries?status=blocked');
    await page.getByRole('button', { name: 'Why?' }).first().click();
    await page.waitForTimeout(400);
    await page.screenshot({ path: shot(`why-${theme}`), type: 'jpeg', quality: 80 });
    // T6.8 — every other page too, for design review: written to ui/.shots/ (git-ignored),
    // not to the site.
    for (const [name, path] of [
      ['dashboard-full', '/#/'],
      ['explain', '/#/explain?name=ads.e2e.test&client=127.0.0.1'],
      ['analyze', '/#/analyze?q=' + encodeURIComponent('from -1h | by name, status | stats count, p95(latency)')],
      ['anomalies', '/#/anomalies'],
      ['clients', '/#/clients'],
      ['groups', '/#/groups'],
      ['upstreams', '/#/upstreams'],
      ['local-dns', '/#/local-dns'],
      ['alerts', '/#/alerts'],
      ['cluster', '/#/cluster'],
      ['settings-system', '/#/settings?tab=system'],
    ]) {
      await page.goto(path);
      await page.waitForTimeout(600);
      await page.screenshot({ path: review(`${name}-${theme}`), type: 'jpeg', quality: 80, fullPage: true });
    }
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto('/#/');
    await page.waitForTimeout(600);
    await page.screenshot({ path: review(`phone-dashboard-${theme}`), type: 'jpeg', quality: 80 });
  });
}

/** An example cluster for the site's screenshot (T6.14): not a real deployment. */
function exampleCluster() {
  const node = (o: Record<string, unknown>) => ({
    ephemeral: false, witness: false, protocol: 4, role: 'replica', thisNode: false, eligible: true,
    version: '0.1.0-edge', up: true, connected: true, link: 'inbound', lastSeenSecondsAgo: 2, rttMs: 1,
    configSeq: 41, configLag: 0, ready: true, qps: 12, servfailPercent: 0.1, upstreamP90Ms: 18,
    uptimeSeconds: 86_400, restarts: 0, cacheEntries: 3_200, cacheHitPercent: 71, querySharePercent: 20,
    configSource: 'gitops', ...o,
  });
  const pod = (name: string, kube: string, o: Record<string, unknown> = {}) =>
    node({ nodeId: `id-${name}`, site: 'k8s', ephemeral: true, pod: `telltale-resolver-${name}`, kubeNode: kube,
      eligible: false, configSource: undefined, uptimeSeconds: 7_200, ...o });
  const at = (minAgo: number) => new Date(Date.now() - minAgo * 60_000).toISOString();
  return {
    enabled: true, clusterId: 'example', name: 'home', thisNode: '3f9a1c07d2e84b16', newestConfigSeq: 41, healthy: true,
    authority: 'gitops', conflicts: [],
    checks: [
      { id: 'peers_up', ok: true, summary: 'All 4 peers are up' },
      { id: 'in_sync', ok: true, summary: 'Every node serves configuration version 41' },
      { id: 'serving', ok: true, summary: 'Every node is serving DNS' },
      { id: 'load_balance', ok: true, summary: "Queries are spread evenly over each site's pods" },
    ],
    nodes: [
      node({ nodeId: '3f9a1c07d2e84b16', site: 'k8s', role: 'primary', thisNode: true, link: 'self', rttMs: null,
        pod: 'telltale-0', kubeNode: 'node-a', qps: 14, querySharePercent: 22 }),
      pod('6c9f-2xk4p', 'node-a', { qps: 13, querySharePercent: 21 }),
      pod('6c9f-8hq7d', 'node-b', { qps: 12, querySharePercent: 19 }),
      pod('6c9f-k2m9w', 'node-b', { qps: 12, querySharePercent: 19, ready: false, configLag: 1 }),
      node({ nodeId: 'b81e5d2a90c4f377', site: 'home-pi', rttMs: 4, qps: 12, querySharePercent: 19, configSource: 'file',
        cacheHitPercent: 76 }),
    ],
    events: [
      { at: at(2), kind: 'joined', nodeId: 'id-6c9f-k2m9w', detail: 'a new resolver pod' },
      { at: at(3), kind: 'left', nodeId: 'id-6c9f-r5t1z', detail: 'shut down (scaled in, replaced, or deleted)' },
      { at: at(9), kind: 'published', nodeId: '3f9a1c07d2e84b16', detail: 'version 41' },
      { at: at(9), kind: 'applied', nodeId: 'b81e5d2a90c4f377', detail: 'version 41: 1 blob(s) fetched, 38 ms' },
    ],
  };
}
