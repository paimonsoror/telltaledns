import { defineConfig, devices } from '@playwright/test';

// REQ: API-005 — T3.9 acceptance: the Playwright suite runs the real binary (`server.mjs`).
// Build first: `cargo build -p telltale` and `npm run build` (or set TELLTALE_BIN).
export default defineConfig({
  testDir: 'tests/e2e',
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL: 'http://127.0.0.1:18054',
    trace: 'retain-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'node tests/e2e/server.mjs',
    url: 'http://127.0.0.1:18054/livez',
    reuseExistingServer: false,
    timeout: 60_000,
    stdout: 'pipe',
    stderr: 'pipe',
  },
});
