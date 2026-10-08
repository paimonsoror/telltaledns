import { defineConfig } from '@playwright/test';

// The screenshot demo (run.sh) only: run.sh starts the server, so there is no webServer here.
export default defineConfig({
  testDir: '.',
  workers: 1,
  reporter: 'line',
  use: { baseURL: 'http://127.0.0.1:28053' },
});
