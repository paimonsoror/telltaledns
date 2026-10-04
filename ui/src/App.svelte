<script lang="ts">
  // REQ: API-005 — the embedded web UI: sign-in/setup gate, navigation, pages.
  import type { Component } from 'svelte';
  import { api, type S } from './lib/api';
  import { session, refreshSession, signOut } from './lib/session.svelte';
  import { route, href } from './lib/router.svelte';
  import { poll } from './lib/poll';
  import Logo from './lib/components/Logo.svelte';
  import HelpButton from './lib/components/HelpButton.svelte';
  import { currentMode, loadMode, setMode } from './lib/mode.svelte';
  import Login from './pages/Login.svelte';
  import Setup from './pages/Setup.svelte';
  import Dashboard from './pages/Dashboard.svelte';
  import Queries from './pages/Queries.svelte';
  import Explain from './pages/Explain.svelte';
  import Clients from './pages/Clients.svelte';
  import Groups from './pages/Groups.svelte';
  import Lists from './pages/Lists.svelte';
  import Upstreams from './pages/Upstreams.svelte';
  import LocalDns from './pages/LocalDns.svelte';
  import Settings from './pages/Settings.svelte';

  const pages: { path: string; label: string; page: Component }[] = [
    { path: '/', label: 'Dashboard', page: Dashboard },
    { path: '/queries', label: 'Query log', page: Queries },
    { path: '/explain', label: 'Explain', page: Explain },
    { path: '/clients', label: 'Clients', page: Clients },
    { path: '/groups', label: 'Groups', page: Groups },
    { path: '/lists', label: 'Lists', page: Lists },
    { path: '/upstreams', label: 'Upstreams', page: Upstreams },
    { path: '/local-dns', label: 'Names on my network', page: LocalDns },
    { path: '/settings', label: 'Settings', page: Settings },
  ];
  const current = $derived(pages.find((p) => p.path === route.path) ?? pages[0]);

  let menuOpen = $state(false);
  let info = $state<S['SystemInfo'] | null>(null);

  // Theme: follows the system unless chosen; the choice is kept in this browser.
  function stored(): string | null {
    try {
      return localStorage.getItem('theme');
    } catch {
      return null;
    }
  }
  let theme = $state(stored() ?? 'auto');
  $effect(() => {
    if (theme === 'auto') delete document.documentElement.dataset.theme;
    else document.documentElement.dataset.theme = theme;
    try {
      if (theme === 'auto') localStorage.removeItem('theme');
      else localStorage.setItem('theme', theme);
    } catch {
      // Private mode: the choice lasts for this page only.
    }
  });
  const nextTheme = $derived(theme === 'auto' ? 'dark' : theme === 'dark' ? 'light' : 'auto');

  void refreshSession();

  // Each user has their own Simple/Advanced choice.
  $effect(() => {
    void session.user?.username;
    loadMode();
  });

  $effect(() => {
    if (session.user) {
      // Refreshed every minute: the masked-client-IP banner (OPS-003) can come and go.
      return poll(() => api.info().then((i) => (info = i)), 60_000);
    }
  });

  $effect(() => {
    void route.path;
    menuOpen = false;
  });
</script>

{#if !session.loaded}
  <p class="empty">Loading…</p>
{:else if session.error && !session.user}
  <main class="center">
    <div class="notice bad">Can't reach TelltaleDNS: {session.error}</div>
    <button onclick={refreshSession}>Retry</button>
  </main>
{:else if session.setupRequired}
  <Setup />
{:else if !session.user}
  <Login />
{:else}
  <div class="layout" class:open={menuOpen}>
    <header class="top">
      <button class="menu" aria-label="Menu" aria-expanded={menuOpen} onclick={() => (menuOpen = !menuOpen)}>☰</button>
      <a class="brand" href="#/"><Logo /> <span>TelltaleDNS</span></a>
      {#if info}<span class="node muted small">{info.node}</span>{/if}
      <span class="spacer"></span>
      <span class="mode small" role="group" aria-label="Detail level">
        <button class="link small" aria-pressed={currentMode() === 'simple'} onclick={() => setMode('simple')}>Simple</button>
        <button class="link small" aria-pressed={currentMode() === 'advanced'} onclick={() => setMode('advanced')}>Advanced</button>
        <HelpButton id="simple-advanced" />
      </span>
      <button class="link small" onclick={() => (theme = nextTheme)} title="Theme">Theme: {theme}</button>
      <span class="who small">{session.user.username} <span class="badge">{session.user.role}</span></span>
      <button class="small" onclick={signOut}>Sign out</button>
    </header>
    <nav class="side" aria-label="Main">
      {#each pages as p (p.path)}
        <a href={href(p.path)} aria-current={current.path === p.path ? 'page' : undefined}>{p.label}</a>
      {/each}
      <!-- On phones the header has no room: the detail level lives in the menu. -->
      <span class="mode mode-nav small" role="group" aria-label="Detail level (menu)">
        <button class="link small" aria-pressed={currentMode() === 'simple'} onclick={() => setMode('simple')}>Simple view</button>
        <button class="link small" aria-pressed={currentMode() === 'advanced'} onclick={() => setMode('advanced')}>Advanced view</button>
      </span>
    </nav>
    <main class="content">
      {#if info && !info.queryLog}
        <div class="notice warn banner">The query log is off on this node: the query log and "Why?" from history are unavailable.</div>
      {/if}
      {#if info?.clientIpsMasked}
        {@const m = info.clientIpsMasked}
        <div class="notice warn banner" data-testid="masked-banner">
          <strong>Client IPs appear masked.</strong>
          {m.sharePercent}% of the last {m.queries} queries came from {m.sources.join(', ')}, which look like
          infrastructure (a Kubernetes node, a Docker bridge, or a router forwarding DNS) rather than devices.
          Per-device statistics and rules see those addresses instead of your devices.
          <a href="https://github.com/paimonsoror/telltaledns/blob/main/docs/running.md#seeing-real-client-ips" target="_blank" rel="noreferrer">How to fix it</a><HelpButton id="masked-clients" />
        </div>
      {/if}
      {#key current.path}
        <current.page />
      {/key}
    </main>
  </div>
{/if}

<style>
  .layout {
    display: grid;
    grid-template-columns: 200px minmax(0, 1fr);
    grid-template-rows: auto 1fr;
    grid-template-areas: 'top top' 'side content';
    min-height: 100vh;
  }
  .top {
    grid-area: top;
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 8px 16px;
    background: var(--brand);
    color: #e8eef6;
    position: sticky;
    top: 0;
    z-index: 10;
  }
  .top .link,
  .top .muted {
    color: #b9c7d4;
  }
  .top button.small {
    min-height: 30px;
    background: transparent;
    color: #e8eef6;
    border-color: #3a5263;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 8px;
    color: #e8eef6;
    font-weight: 700;
  }
  .brand:hover {
    text-decoration: none;
  }
  .who .badge {
    background: #22394a;
    color: #b9c7d4;
  }
  .menu {
    display: none;
    background: transparent;
    color: #e8eef6;
    border-color: #3a5263;
  }
  .side {
    grid-area: side;
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 12px 8px;
    border-right: 1px solid var(--border);
    background: var(--surface);
  }
  .side a {
    padding: 8px 12px;
    border-radius: 8px;
    color: var(--text);
  }
  .side a:hover {
    background: var(--surface-2);
    text-decoration: none;
  }
  .side a[aria-current='page'] {
    background: var(--surface-2);
    font-weight: 600;
    box-shadow: inset 3px 0 0 var(--accent);
  }
  .content {
    grid-area: content;
    padding: 20px;
    min-width: 0;
  }
  .mode {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }
  .mode-nav {
    display: none;
  }
  .mode button[aria-pressed="true"] {
    font-weight: 700;
    text-decoration: underline;
  }
  .banner {
    margin-bottom: 16px;
  }
  .center {
    min-height: 100vh;
    display: grid;
    place-content: center;
    gap: 12px;
    padding: 16px;
  }

  @media (max-width: 760px) {
    .layout {
      grid-template-columns: minmax(0, 1fr);
      grid-template-areas: 'top' 'content';
    }
    .menu {
      display: inline-block;
    }
    .node,
    .top .mode,
    .who {
      display: none;
    }
    .side {
      display: none;
      position: fixed;
      top: 50px;
      left: 0;
      bottom: 0;
      width: min(260px, 80vw);
      z-index: 15;
      box-shadow: var(--shadow);
    }
    .mode-nav {
      display: flex;
      margin-top: 12px;
      padding: 0 12px;
    }
    .layout.open .side {
      display: flex;
    }
    .content {
      padding: 12px;
    }
  }
</style>
