<script lang="ts">
  // REQ: API-005 — the embedded web UI: sign-in/setup gate, navigation, pages.
  import type { Component } from 'svelte';
  import { api, type S } from './lib/api';
  import { session, refreshSession, signOut } from './lib/session.svelte';
  import { route, href } from './lib/router.svelte';
  import { poll } from './lib/poll';
  import Logo from './lib/components/Logo.svelte';
  import HelpButton from './lib/components/HelpButton.svelte';
  import Icon from './lib/components/Icon.svelte';
  import PauseControl from './lib/components/PauseControl.svelte';
  import { navigate } from './lib/router.svelte';
  import { currentMode, loadMode, setMode } from './lib/mode.svelte';
  import Login from './pages/Login.svelte';
  import Setup from './pages/Setup.svelte';
  import Dashboard from './pages/Dashboard.svelte';
  import Queries from './pages/Queries.svelte';
  import Explain from './pages/Explain.svelte';
  import Clients from './pages/Clients.svelte';
  import Anomalies from './pages/Anomalies.svelte';
  import Cluster from './pages/Cluster.svelte';
  import Cache from './pages/Cache.svelte';
  import Groups from './pages/Groups.svelte';
  import Lists from './pages/Lists.svelte';
  import Rules from './pages/Rules.svelte';
  import Upstreams from './pages/Upstreams.svelte';
  import LocalDns from './pages/LocalDns.svelte';
  import Settings from './pages/Settings.svelte';

  // T6.8 — the sidebar in sections, each page with an icon.
  const pages: { path: string; label: string; page: Component; icon: string; section: string }[] = [
    { path: '/', label: 'Dashboard', page: Dashboard, icon: 'dashboard', section: 'Monitor' },
    { path: '/queries', label: 'Query log', page: Queries, icon: 'queries', section: 'Monitor' },
    { path: '/explain', label: 'Explain', page: Explain, icon: 'explain', section: 'Monitor' },
    { path: '/anomalies', label: 'Anomalies', page: Anomalies, icon: 'anomalies', section: 'Monitor' },
    { path: '/clients', label: 'Clients', page: Clients, icon: 'clients', section: 'Devices' },
    { path: '/groups', label: 'Groups', page: Groups, icon: 'groups', section: 'Devices' },
    { path: '/lists', label: 'Lists', page: Lists, icon: 'lists', section: 'Filtering & DNS' },
    { path: '/rules', label: 'Quick rules', page: Rules, icon: 'rules', section: 'Filtering & DNS' },
    { path: '/upstreams', label: 'Upstreams', page: Upstreams, icon: 'upstreams', section: 'Filtering & DNS' },
    { path: '/local-dns', label: 'Names on my network', page: LocalDns, icon: 'names', section: 'Filtering & DNS' },
    { path: '/cluster', label: 'Cluster', page: Cluster, icon: 'cluster', section: 'System' },
    { path: '/cache', label: 'Cache', page: Cache, icon: 'cache', section: 'System' },
    { path: '/settings', label: 'Settings', page: Settings, icon: 'settings', section: 'System' },
  ];
  const sections = [...new Set(pages.map((p) => p.section))];

  // Top bar search: a name or a client, shown in the query log.
  let search = $state('');
  function doSearch(e: SubmitEvent) {
    e.preventDefault();
    const q = search.trim();
    if (!q) return;
    const key = /^[0-9a-f:.]+$/i.test(q) && /[.:]/.test(q) && !/[g-z]/i.test(q) ? 'client' : 'name';
    navigate('/queries', { [key]: q });
    search = '';
  }
  const initials = $derived(
    (session.user?.username ?? '?')
      .split(/[\s._-]+/)
      .filter(Boolean)
      .slice(0, 2)
      .map((w) => w[0]?.toUpperCase())
      .join(''),
  );
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

  // T6.8 — count badges in the sidebar: anomalies found in the last day, lists that fail to
  // download. Best effort: a failed call just hides the badge.
  let badges = $state<Record<string, number>>({});
  $effect(() => {
    if (session.user) {
      return poll(async () => {
        const [a, l] = await Promise.all([api.anomalies('-24h').catch(() => null), api.lists().catch(() => null)]);
        badges = {
          '/anomalies': a?.items.length ?? 0,
          '/lists': l?.items.filter((x) => x.state === 'failed').length ?? 0,
        };
      }, 60_000);
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
    <nav class="side" aria-label="Main">
      <a class="brand" href="#/"><Logo /> <span>TelltaleDNS</span></a>
      {#each sections as sec (sec)}
        <div class="section">{sec}</div>
        {#each pages.filter((p) => p.section === sec) as p (p.path)}
          <a class="nav" href={href(p.path)} aria-current={current.path === p.path ? 'page' : undefined}>
            <Icon name={p.icon} /> <span>{p.label}</span>
            {#if badges[p.path]}
              <b class="count" class:alert={p.path === '/lists'} title={p.path === '/lists' ? 'lists failing to download' : 'anomalies in the last 24 hours'}>{badges[p.path]}</b>
            {/if}
          </a>
        {/each}
      {/each}
      <!-- On phones the header has no room: the detail level lives in the menu. -->
      <span class="mode mode-nav small" role="group" aria-label="Detail level (menu)">
        <button class="link small" aria-pressed={currentMode() === 'simple'} onclick={() => setMode('simple')}>Simple view</button>
        <button class="link small" aria-pressed={currentMode() === 'advanced'} onclick={() => setMode('advanced')}>Advanced view</button>
      </span>
      <span class="spacer"></span>
      <!-- The project: plain links, nothing is fetched (works on an offline network). -->
      <div class="project-links">
        <a href="https://github.com/paimonsoror/telltaledns" target="_blank" rel="noreferrer" aria-label="TelltaleDNS on GitHub" title="TelltaleDNS on GitHub">
          <svg viewBox="0 0 16 16" width="18" height="18" aria-hidden="true"><path fill="currentColor" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" /></svg>
        </a>
        <a href="https://paimonsoror.github.io/telltaledns/" target="_blank" rel="noreferrer" aria-label="Project site and guides" title="Project site and guides">
          <Icon name="book" size={18} />
        </a>
      </div>
      <!-- REQ: OPS-004 (ADR-046) — which build this is, and whether a newer one exists. -->
      {#if info?.build}
        <a class="build small" href="#/settings?tab=system" data-testid="build-footer" title={`commit ${info.build.commit}, ${info.build.target}`}>
          {#if info.node}<span class="node">{info.node}</span>{/if}
          <span>{info.build.version} · {info.build.commit}</span>
          {#if info.update?.state === 'available'}<span class="pill">update</span>{/if}
        </a>
      {/if}
    </nav>
    <header class="top">
      <button class="icon-btn menu" aria-label="Menu" aria-expanded={menuOpen} onclick={() => (menuOpen = !menuOpen)}><Icon name="menu" /></button>
      <form class="search" role="search" onsubmit={doSearch}>
        <Icon name="search" size={16} />
        <input aria-label="Search names or clients" placeholder="Search a name or client…" bind:value={search} />
      </form>
      <span class="spacer"></span>
      <span class="mode seg small" role="group" aria-label="Detail level">
        <button aria-pressed={currentMode() === 'simple'} onclick={() => setMode('simple')}>Simple</button>
        <button aria-pressed={currentMode() === 'advanced'} onclick={() => setMode('advanced')}>Advanced</button>
      </span>
      <HelpButton id="simple-advanced" />
      <PauseControl />
      <button class="icon-btn" onclick={() => (theme = nextTheme)} title={`Theme: ${theme} (click for ${nextTheme})`} aria-label={`Theme: ${theme}`}>
        <Icon name={theme === 'dark' ? 'moon' : theme === 'light' ? 'sun' : 'auto'} />
      </button>
      <span class="who">
        <span class="avatar" aria-hidden="true">{initials}</span>
        <span class="who-text"><strong>{session.user.username}</strong><span class="role muted small">{session.user.role}</span></span>
      </span>
      <button class="icon-btn" onclick={signOut} title="Sign out" aria-label="Sign out"><Icon name="logout" /></button>
    </header>
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
    grid-template-columns: 232px minmax(0, 1fr);
    grid-template-rows: auto 1fr;
    grid-template-areas: 'side top' 'side content';
    min-height: 100vh;
  }
  /* Sidebar: dark, sectioned, filled pill for the current page. */
  .side {
    grid-area: side;
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 16px 12px;
    background: var(--side-bg);
    color: var(--side-text);
    position: sticky;
    top: 0;
    height: 100vh;
    overflow-y: auto;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 4px 10px 14px;
    color: #f2f6fa;
    font-weight: 700;
    font-size: 15px;
  }
  .brand:hover {
    text-decoration: none;
  }
  .section {
    margin: 14px 12px 6px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--side-muted);
  }
  .nav {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 12px;
    border-radius: 10px;
    color: var(--side-text);
  }
  .nav:hover {
    background: var(--side-hover);
    text-decoration: none;
  }
  .nav[aria-current='page'] {
    background: var(--accent-strong);
    color: var(--accent-text);
    font-weight: 600;
  }
  .nav {
    position: relative;
  }
  .count {
    margin-left: auto;
    min-width: 20px;
    padding: 0 6px;
    border-radius: 999px;
    background: var(--warn);
    color: #1b1300;
    font-size: 11px;
    line-height: 18px;
    text-align: center;
  }
  .count.alert {
    background: var(--bad);
    color: var(--on-bad);
  }
  .project-links {
    display: flex;
    gap: 4px;
    margin-top: 16px;
  }
  .project-links a {
    display: grid;
    place-items: center;
    width: 34px;
    height: 34px;
    border-radius: 8px;
    color: var(--side-muted);
  }
  .project-links a:hover,
  .project-links a:focus-visible {
    background: var(--side-hover);
    color: var(--side-text);
  }
  .project-links + .build {
    margin-top: 6px;
  }
  .build {
    display: grid;
    gap: 2px;
    margin-top: 16px;
    padding: 10px 12px;
    border-radius: 10px;
    background: var(--side-hover);
    color: var(--side-muted);
  }
  .build:hover {
    text-decoration: none;
    color: var(--side-text);
  }
  .build .node {
    color: var(--side-text);
    font-weight: 600;
  }
  .pill {
    justify-self: start;
    padding: 0 8px;
    border-radius: 999px;
    background: var(--warn);
    color: #1b1300;
    font-weight: 600;
  }
  /* Top bar: light, borderless. */
  .top {
    grid-area: top;
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 24px;
    background: var(--bg);
    position: sticky;
    top: 0;
    z-index: 10;
  }
  .search {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 0 12px;
    width: min(360px, 40vw);
    border-radius: 999px;
    background: var(--surface);
    box-shadow: var(--shadow);
    color: var(--muted);
  }
  .search input {
    border: 0;
    background: transparent;
    padding: 6px 0;
    flex: 1;
    min-height: 36px;
  }
  .search input:focus-visible {
    outline: none;
  }
  .search:focus-within {
    outline: 2px solid var(--focus);
    outline-offset: 1px;
  }
  .icon-btn {
    display: inline-grid;
    place-items: center;
    width: 36px;
    height: 36px;
    min-height: 36px;
    padding: 0;
    border: 0;
    border-radius: 999px;
    background: transparent;
    color: var(--muted);
  }
  .icon-btn:hover {
    background: var(--surface-2);
    color: var(--text);
  }
  .who {
    display: flex;
    align-items: center;
    gap: 8px;
    padding-left: 6px;
  }
  .avatar {
    display: inline-grid;
    place-items: center;
    width: 34px;
    height: 34px;
    border-radius: 999px;
    background: color-mix(in srgb, var(--accent) 18%, var(--surface));
    color: var(--accent);
    font-weight: 700;
    font-size: 13px;
  }
  .who-text {
    display: grid;
    line-height: 1.2;
  }
  .who-text .small {
    text-transform: capitalize;
  }
  .menu {
    display: none;
  }
  .content {
    grid-area: content;
    padding: 8px 24px 32px;
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
  .mode-nav button[aria-pressed='true'] {
    font-weight: 700;
    text-decoration: underline;
  }
  .side .mode-nav button {
    color: var(--side-text);
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

  /* Medium widths: the sidebar shrinks to icons. */
  @media (max-width: 1100px) and (min-width: 761px) {
    .layout {
      grid-template-columns: 72px minmax(0, 1fr);
    }
    .brand span,
    .nav span,
    .count,
    .section,
    .build {
      display: none;
    }
    .nav {
      justify-content: center;
      padding: 10px;
    }
    .brand {
      justify-content: center;
      padding: 4px 0 14px;
    }
  }
  @media (max-width: 760px) {
    .layout {
      grid-template-columns: minmax(0, 1fr);
      grid-template-areas: 'top' 'content';
    }
    .menu {
      display: inline-grid;
    }
    .top .mode,
    .who-text,
    .top :global(.help-btn) {
      display: none;
    }
    .top {
      gap: 6px;
      padding: 10px 12px;
    }
    .search {
      width: auto;
      flex: 1;
      min-width: 0;
    }
    .search input {
      width: 100%;
      min-width: 0;
    }
    .spacer {
      display: none;
    }
    .side {
      display: none;
      position: fixed;
      top: 0;
      left: 0;
      bottom: 0;
      height: auto;
      width: min(270px, 82vw);
      z-index: 15;
      box-shadow: 0 8px 30px rgb(0 0 0 / 35%);
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
      padding: 8px 12px 24px;
    }
  }
</style>
