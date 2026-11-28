// REQ: API-012 (ADR-189) — report only: which pages overflow sideways at 360 px under the pseudo-locale
// (every text about 35% longer), and which already do in English. A page that overflows is printed
// (`FIT360` lines in the log, and an annotation of the test) and never fails the test: pages that overflow
// today would pull layout work into part A. Expects the state 1-ui.spec.ts leaves, as 8-i18n-pages.spec.ts does.
import { expect, test, type Page } from '@playwright/test';
import { failOnPageErrors } from './page-errors';

// REQ: API-005 — a page error fails the test, as in 1-ui.spec.ts (the overflow itself is only reported).
failOnPageErrors(test);

const ADMIN = { user: 'admin', pass: 'correct horse battery' };
const WIDTH = 360;

/** [name, route, an element that shows the page is ready]. */
const PAGES: [string, string, string][] = [
  ['Dashboard', '/', '[data-testid="stat-queries"]'],
  ['Traffic map', '/traffic', 'h1'],
  ['Heatmap', '/heatmap', 'canvas'],
  ['Flow', '/flow', 'h1'],
  ['Query log', '/queries', 'table.log tbody tr'],
  ['Analyze', '/analyze', 'h1'],
  ['Explain', '/explain', 'h1'],
  ['Anomalies', '/anomalies', 'h1'],
  ['Clients', '/clients', 'h1'],
  ['Groups', '/groups', '[data-testid="editor-group"]'],
  ['Lists', '/lists', 'h1'],
  ['Quick rules', '/rules', '[data-testid="quick-rule-form"]'],
  ['Upstreams', '/upstreams', '[data-testid="entry-row"]'],
  ['Names on my network', '/local-dns', 'h1'],
  ['Cluster', '/cluster', 'h1'],
  ['Alerts', '/alerts', 'h1'],
  ['Agent changes', '/agent-changes', 'h1'],
  ['Cache', '/cache', '[data-testid="cache-card"]'],
  ['Settings: account', '/settings?tab=account', 'h1'],
  ['Settings: API tokens', '/settings?tab=tokens', 'h1'],
  ['Settings: users', '/settings?tab=users', '[data-testid="wall-displays"]'],
  ['Settings: audit log', '/settings?tab=audit', 'h1'],
  ['Settings: system', '/settings?tab=system', '[data-testid="support-package"]'],
  ['Settings: query handling', '/settings?tab=queries', 'h1'],
  ['Settings: cluster', '/settings?tab=cluster', 'h1'],
  ['Wall display', '/wall', '[data-testid="wall-area"]'],
];

async function signIn(page: Page) {
  await page.goto('/');
  await page.getByLabel('Username', { exact: true }).fill(ADMIN.user);
  await page.getByLabel('Password', { exact: true }).fill(ADMIN.pass);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Dashboard' }).first()).toBeVisible({ timeout: 30_000 });
}

type Fit = { over: number; wide: string[] };

/** How far the page reaches past the window, and the first elements that stick out and are not inside a box
 * that scrolls or clips (a table in its own scroll area is not the page overflowing). */
async function fit(page: Page, url: string, ready: string): Promise<Fit> {
  await page.goto(url);
  await expect(page.locator(ready).first()).toBeVisible();
  return page.evaluate(async () => {
    // Fonts, and frames until the width has held for six of them, so the layout the page settles into is
    // what is measured (the page's data arrives after its first paint).
    await document.fonts.ready;
    let last = -1;
    let held = 0;
    for (let frame = 0; frame < 120 && held < 6; frame++) {
      await new Promise<void>((done) => requestAnimationFrame(() => done()));
      const now = document.documentElement.scrollWidth;
      held = now === last ? held + 1 : 0;
      last = now;
    }
    const w = document.documentElement.clientWidth;
    const clipped = (e: Element) => {
      for (let p = e.parentElement; p && p !== document.body && p !== document.documentElement; p = p.parentElement) {
        const o = getComputedStyle(p).overflowX;
        if (o === 'auto' || o === 'scroll' || o === 'hidden' || o === 'clip') return true;
      }
      return false;
    };
    const wide: string[] = [];
    const hidden: string[] = [];
    for (const e of document.body.querySelectorAll('*')) {
      const r = e.getBoundingClientRect();
      if (r.width === 0 || r.right <= w + 1) continue;
      const cls = typeof e.className === 'string' && e.className.trim() ? `.${e.className.trim().split(/\s+/).join('.')}` : '';
      const fixed = getComputedStyle(e).position === 'fixed';
      const what = `${e.localName}${cls.replace(/\.svelte-[a-z0-9]+/g, '')} ${Math.round(r.width)}px`;
      if (!fixed && !clipped(e)) {
        if (wide.length < 3) wide.push(what);
      } else if (hidden.length < 3) hidden.push(`${what} (${fixed ? 'fixed' : 'in a box that scrolls or clips'})`);
    }
    return { over: document.documentElement.scrollWidth - w, wide: wide.length ? wide : hidden };
  });
}

for (const [name, route, ready] of PAGES) {
  test(`api_012 pseudo locale fits 360 px: ${name}`, async ({ page }) => {
    await page.setViewportSize({ width: WIDTH, height: 740 });
    await signIn(page);
    const english = await fit(page, `/#${route}`, ready);
    const pseudo = await fit(page, `/?lang=en-XA#${route}`, ready);
    const word = (f: Fit) => (f.over > 0 ? `overflows by ${f.over} px (${f.wide.join(', ') || 'no single element found'})` : 'fits');
    const line = `FIT360 ${name}: english ${word(english)}; pseudo ${word(pseudo)}`;
    console.log(line);
    test.info().annotations.push({ type: 'fits-360', description: line });
  });
}
