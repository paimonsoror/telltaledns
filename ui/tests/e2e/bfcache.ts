// REQ: API-004, API-013 (ADR-190) — what the two Back tests (9-devpack.spec.ts, 3-oidc.spec.ts) share: a browser that
// keeps the back-forward cache, which Playwright turns off, and a probe of whether it shows a page of TelltaleDNS
// again from that cache. A test whose browser never does skips, saying why, since it cannot exercise the Back fix.
import { chromium, expect, type Browser, type LaunchOptions, type Page } from '@playwright/test';

type Launch = (o: LaunchOptions) => Promise<Browser>;

/** A browser for a Back test: a full Chromium (`full`, the DVP_FULL_CHROME path, or the installed `chromium` channel),
 * else the suite's own (`o`, the project's launch options). `note` says why the full Chromium was not used: the first
 * line of the error its start gave, for the skip's reason. */
export async function cachingBrowser(o: LaunchOptions, full: string | undefined, launch: Launch = (x) => chromium.launch(x)): Promise<{ browser: Browser; note: string }> {
  const keep = { ...o, ignoreDefaultArgs: ['--disable-back-forward-cache'] };
  if (full) return { browser: await launch({ ...keep, executablePath: full }), note: '' };
  try {
    return { browser: await launch({ ...keep, executablePath: undefined, channel: 'chromium' }), note: '' };
  } catch (e) {
    const first = String(e instanceof Error ? e.message : e).split('\n').map((s) => s.trim()).find(Boolean) ?? 'no message';
    return { browser: await launch(keep), note: `the full Chromium did not start: ${first.slice(0, 240)}; ` };
  }
}

/** Notes in session storage when the browser shows a page again from its back-forward cache (an init script). */
export const NOTE_RESTORED = () =>
  addEventListener('pageshow', (e) => {
    if (e.persisted) sessionStorage.setItem('dvp-restored', String((Number(sessionStorage.getItem('dvp-restored')) || 0) + 1));
  });

/** What the page says about how it was shown: restored from the back-forward cache (how often), and why not. A read
 * that a navigation interrupts (the page reloading) says nothing. */
export const howShown = (page: Page) =>
  page
    .evaluate(() => {
      const nav = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming & { notRestoredReasons?: unknown };
      return { restored: Number(sessionStorage.getItem('dvp-restored')) || 0, type: nav?.type ?? '', notRestored: JSON.stringify(nav?.notRestoredReasons ?? null).slice(0, 400) };
    })
    .catch((e: Error) => ({ restored: 0, type: '', notRestored: `not read: ${e.message.slice(0, 80)}` }));

/** Forgets the probe's own restores. A failure fails the test: a count left behind could pass for the Back test's. */
export const resetRestored = (page: Pick<Page, 'evaluate'>) => page.evaluate(() => sessionStorage.removeItem('dvp-restored'));

/** Whether the browser of `page` (with NOTE_RESTORED) shows a page of this app again from its back-forward cache: the
 * sign-in page, another document of this address, then Back. The count is reset afterwards. */
export async function restoresPages(page: Page): Promise<{ restored: boolean; why: string }> {
  await page.goto('/?devpack-probe=1');
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  await page.goto('/livez');
  await page.goBack({ waitUntil: 'commit' });
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  const r = await howShown(page);
  await resetRestored(page);
  return { restored: r.restored > 0, why: r.notRestored };
}

/** The reason a Back test gives when its browser never shows a page again from the back-forward cache. */
export const noCache = (b: Browser, note: string, why: string) =>
  `${note}this browser (${b.version()}) never shows a page again from its back-forward cache (${why}): the Back fix is not exercised here`;
