import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

// REQ: API-005 — built to ui/dist and embedded in the binary (ADR-009, ADR-030).
// `npm run dev` proxies the API to a local server (`telltale run`, API on :8053).
const api = process.env.TELLTALE_API ?? 'http://127.0.0.1:8053';

export default defineConfig({
  plugins: [svelte()],
  base: '/',
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    target: 'es2022',
    sourcemap: false,
    modulePreload: { polyfill: false },
    // The binary serves these files under a strict CSP: never inline anything.
    assetsInlineLimit: 0,
  },
  server: {
    proxy: { '/api': api, '/metrics': api },
  },
});
