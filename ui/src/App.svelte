<script lang="ts">
  // REQ: API-005 — the embedded web UI: sign-in/setup gate, navigation, pages.
  import type { Component } from 'svelte';
  import { api, type S } from './lib/api';
  import { session, refreshSession, signOut } from './lib/session.svelte';
  import { route, href } from './lib/router.svelte';
  import { poll } from './lib/poll';
  import Logo from './lib/components/Logo.svelte';
  import Wall from './pages/Wall.svelte';
  import Display from './pages/Display.svelte';
  import HelpButton from './lib/components/HelpButton.svelte';
  import Icon from './lib/components/Icon.svelte';
  import PauseControl from './lib/components/PauseControl.svelte';
  import AgentInbox from './lib/components/AgentInbox.svelte';
  import HealthIcon from './lib/components/HealthIcon.svelte';
  import { health, watchHealth } from './lib/health.svelte';
  import AgentChanges from './pages/AgentChanges.svelte';
  import { navigate } from './lib/router.svelte';
  import { currentMode, loadMode, setMode } from './lib/mode.svelte';
  import { t, type MessageKey } from './lib/i18n';
  import LanguageToggle from './lib/components/LanguageToggle.svelte';
  import { loadIconPrefs } from './lib/icons/prefs.svelte';
  import Login from './pages/Login.svelte';
  import Setup from './pages/Setup.svelte';
  import Dashboard from './pages/Dashboard.svelte';
  import Traffic from './pages/Traffic.svelte';
  import Heatmap from './pages/Heatmap.svelte';
  import Flow from './pages/Flow.svelte';
  import Queries from './pages/Queries.svelte';
  import Explain from './pages/Explain.svelte';
  import Analyze from './pages/Analyze.svelte';
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
  import Alerts from './pages/Alerts.svelte';

  // T6.8 — the sidebar in sections, each page with an icon.
  const pages: { path: string; label: MessageKey; page: Component; icon: string; section: MessageKey }[] = [
    { path: '/', label: 'nav.dashboard', page: Dashboard, icon: 'dashboard', section: 'nav.section.monitor' },
    { path: '/traffic', label: 'nav.traffic', page: Traffic, icon: 'traffic', section: 'nav.section.monitor' },
    { path: '/heatmap', label: 'nav.heatmap', page: Heatmap, icon: 'heatmap', section: 'nav.section.monitor' },
    { path: '/flow', label: 'nav.flow', page: Flow, icon: 'flow', section: 'nav.section.monitor' },
    { path: '/queries', label: 'nav.queries', page: Queries, icon: 'queries', section: 'nav.section.monitor' },
    { path: '/analyze', label: 'nav.analyze', page: Analyze, icon: 'analyze', section: 'nav.section.monitor' },
    { path: '/explain', label: 'nav.explain', page: Explain, icon: 'explain', section: 'nav.section.monitor' },
    { path: '/anomalies', label: 'nav.anomalies', page: Anomalies, icon: 'anomalies', section: 'nav.section.monitor' },
    { path: '/clients', label: 'nav.clients', page: Clients, icon: 'clients', section: 'nav.section.devices' },
    { path: '/groups', label: 'nav.groups', page: Groups, icon: 'groups', section: 'nav.section.devices' },
    { path: '/lists', label: 'nav.lists', page: Lists, icon: 'lists', section: 'nav.section.filtering' },
    { path: '/rules', label: 'nav.rules', page: Rules, icon: 'rules', section: 'nav.section.filtering' },
    { path: '/upstreams', label: 'nav.upstreams', page: Upstreams, icon: 'upstreams', section: 'nav.section.filtering' },
    { path: '/local-dns', label: 'nav.localDns', page: LocalDns, icon: 'names', section: 'nav.section.filtering' },
    { path: '/cluster', label: 'nav.cluster', page: Cluster, icon: 'cluster', section: 'nav.section.system' },
    { path: '/alerts', label: 'nav.alerts', page: Alerts, icon: 'bell', section: 'nav.section.system' },
    { path: '/agent-changes', label: 'nav.agentChanges', page: AgentChanges, icon: 'inbox', section: 'nav.section.system' },
    { path: '/cache', label: 'nav.cache', page: Cache, icon: 'cache', section: 'nav.section.system' },
    { path: '/settings', label: 'nav.settings', page: Settings, icon: 'settings', section: 'nav.section.system' },
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
  // A role in the reader's language; a value this build doesn't know stays as the server sent it.
  const roleName = (role: string) =>
    role === 'admin' || role === 'operator' || role === 'viewer' ? t(`common.role.${role}` as MessageKey) : role;
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

  // Each user has their own Simple/Advanced choice, and their own domain icon choice (OBS-039).
  $effect(() => {
    void session.user?.username;
    loadMode();
    loadIconPrefs();
  });

  $effect(() => {
    if (session.user) {
      // Refreshed every minute: the masked-client-IP banner (OPS-003) can come and go, and at
      // once when maintenance starts or ends (OPS-010).
      const stop = poll(() => api.info().then((i) => (info = i)), 60_000);
      const changed = () => void api.info().then((i) => (info = i)).catch(() => {});
      window.addEventListener('telltale:maintenance-changed', changed);
      return () => {
        stop();
        window.removeEventListener('telltale:maintenance-changed', changed);
      };
    }
  });

  // T6.8 — count badges in the sidebar: anomalies found in the last day that nobody has
  // acknowledged yet (OBS-014), lists that fail to download. Best effort: a failed call just
  // hides the badge.
  let badges = $state<Record<string, number>>({});
  async function loadBadges() {
    const [a, l] = await Promise.all([api.anomalies('-24h', false).catch(() => null), api.lists().catch(() => null)]);
    badges = {
      // REQ: OBS-036 — informational findings (a chatty loop) aren't counted.
      '/anomalies': a?.items.filter((x) => !x.informational).length ?? 0,
      '/lists': l?.items.filter((x) => x.state === 'failed').length ?? 0,
    };
  }
  $effect(() => {
    if (session.user) {
      const stop = poll(loadBadges, 60_000);
      // The Anomalies page says when someone acknowledged a finding.
      const changed = () => void loadBadges();
      window.addEventListener('telltale:anomalies-changed', changed);
      return () => {
        stop();
        window.removeEventListener('telltale:anomalies-changed', changed);
      };
    }
  });

  // REQ: OBS-015 — health for the sidebar icon and the phone menu's dot.
  $effect(() => {
    if (session.user) return watchHealth();
  });
  const unwell = $derived(health.value && health.value.level !== 'healthy' ? health.value.level : null);

  $effect(() => {
    void route.path;
    menuOpen = false;
  });
  // On phones the menu covers the page and its own button: any link in it closes it (also the
  // page you're already on, which changes no route), as do the dimmed page beside it and Esc.
  const closeMenu = () => (menuOpen = false);
</script>

<svelte:window
  onkeydown={(e) => {
    if (e.key === 'Escape' && menuOpen) closeMenu();
  }}
/>

{#if !session.loaded}
  <p class="empty">{t('common.loading')}</p>
{:else if session.error && !session.user}
  <main class="center">
    <div class="notice bad">{t('common.unreachable', { error: session.error })}</div>
    <button onclick={refreshSession}>{t('common.retry')}</button>
  </main>
{:else if route.path === '/display'}
  <!-- REQ: OBS-035 (T14.13) — a wall display's link, signed in or not. -->
  <Display />
{:else if session.setupRequired}
  <Setup />
{:else if !session.user}
  <Login />
{:else if route.path === '/wall' || session.user.display}
  <!-- REQ: OBS-035 — the wall display: signed in like any page, without the navigation. -->
  <Wall />
{:else}
  <div class="layout" class:open={menuOpen}>
    {#if menuOpen}
      <button type="button" class="scrim" aria-label={t('nav.closeMenu')} data-testid="menu-scrim" onclick={closeMenu}></button>
    {/if}
    <nav class="side" aria-label={t('nav.main')}>
      <a class="brand" href="#/" onclick={closeMenu}><Logo /> <span>TelltaleDNS</span></a>
      {#each sections as sec (sec)}
        <div class="section">{t(sec)}</div>
        {#each pages.filter((p) => p.section === sec) as p (p.path)}
          <a class="nav" href={href(p.path)} aria-current={current.path === p.path ? 'page' : undefined} onclick={closeMenu}>
            <Icon name={p.icon} /> <span>{t(p.label)}</span>
            {#if badges[p.path]}
              <b class="count" class:alert={p.path === '/lists'} title={p.path === '/lists' ? t('nav.badge.lists') : t('nav.badge.anomalies')}>{badges[p.path]}</b>
            {/if}
          </a>
        {/each}
      {/each}
      <!-- On phones the header has no room: the detail level lives in the menu. -->
      <span class="mode mode-nav small" role="group" aria-label={t('nav.detailLevelMenu')}>
        <button class="link small" aria-pressed={currentMode() === 'simple'} onclick={() => setMode('simple')}>{t('nav.simpleView')}</button>
        <button class="link small" aria-pressed={currentMode() === 'advanced'} onclick={() => setMode('advanced')}>{t('nav.advancedView')}</button>
      </span>
      <span class="spacer"></span>
      <!-- The project: plain links, nothing is fetched (works on an offline network). -->
      <div class="project-links">
        <!-- REQ: OBS-015 — health first: status, set apart from the links out. -->
        <HealthIcon />
        <span class="links-gap" aria-hidden="true"></span>
        <a href="https://github.com/paimonsoror/telltaledns" target="_blank" rel="noreferrer" aria-label={t('nav.github')} title={t('nav.github')}>
          <svg viewBox="0 0 16 16" width="18" height="18" aria-hidden="true"><path fill="currentColor" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" /></svg>
        </a>
        <a href="https://paimonsoror.github.io/telltaledns/" target="_blank" rel="noreferrer" aria-label={t('nav.site')} title={t('nav.site')}>
          <Icon name="book" size={18} />
        </a>
      </div>
      <!-- REQ: OPS-004 (ADR-046) — which build this is, and whether a newer one exists. -->
      {#if info?.build}
        <a class="build small" href="#/settings?tab=system" data-testid="build-footer" onclick={closeMenu} title={t('nav.build', { commit: info.build.commit, target: info.build.target })}>
          {#if info.node}<span class="node"
              >{info.node}<!-- REQ: CLU-002 — in a cluster, which kind of node this UI belongs to. -->{#if info.cluster}<span
                  class="role"
                  class:primary={info.cluster.primary}
                  data-testid="node-role"
                  title={info.cluster.primary
                    ? t('nav.primaryTitle', { name: info.cluster.name, site: info.cluster.site })
                    : t('nav.replicaTitle', { site: info.cluster.site })}
                  >{info.cluster.primary ? t('nav.primary') : t('nav.replica')}</span
                >{/if}</span
            >{/if}
          <span>{info.build.version} · {info.build.commit}</span>
          {#if info.update?.state === 'available'}<span class="pill">{t('nav.update')}</span>{/if}
        </a>
      {/if}
    </nav>
    <header class="top">
      <button class="icon-btn menu" aria-label={unwell ? t('nav.menuHealth', { level: unwell }) : t('nav.menu')} aria-expanded={menuOpen} onclick={() => (menuOpen = !menuOpen)}
        ><Icon name="menu" />{#if unwell}<span class="menu-dot {unwell}" data-testid="menu-health-dot"></span>{/if}</button
      >
      <form class="search" role="search" onsubmit={doSearch}>
        <Icon name="search" size={16} />
        <input aria-label={t('nav.searchAria')} placeholder={t('nav.searchPlaceholder')} bind:value={search} />
      </form>
      <span class="spacer"></span>
      <span class="mode seg small" role="group" aria-label={t('nav.detailLevel')}>
        <button aria-pressed={currentMode() === 'simple'} onclick={() => setMode('simple')}>{t('nav.simple')}</button>
        <button aria-pressed={currentMode() === 'advanced'} onclick={() => setMode('advanced')}>{t('nav.advanced')}</button>
      </span>
      <HelpButton id="simple-advanced" />
      <AgentInbox />
      <PauseControl />
      {#if currentMode() === 'advanced'}
        <!-- REQ: OBS-035 — the wall display (full screen, for a monitor). -->
        <button class="icon-btn" onclick={() => navigate('/wall')} title={t('nav.wallTitle')} aria-label={t('nav.wall')} data-testid="open-wall"
          ><Icon name="wall" /></button
        >
      {/if}
      <button
        class="icon-btn"
        onclick={() => (theme = nextTheme)}
        title={t('nav.themeNext', { theme: t(`nav.theme.${theme}` as MessageKey), next: t(`nav.theme.${nextTheme}` as MessageKey) })}
        aria-label={t('nav.theme', { theme: t(`nav.theme.${theme}` as MessageKey) })}
      >
        <Icon name={theme === 'dark' ? 'moon' : theme === 'light' ? 'sun' : 'auto'} />
      </button>
      <LanguageToggle />
      <span class="who">
        <span class="avatar" aria-hidden="true">{initials}</span>
        <span class="who-text"><strong>{session.user.username}</strong><span class="role muted small">{roleName(session.user.role)}</span></span>
      </span>
      <button class="icon-btn" onclick={signOut} title={t('nav.signOut')} aria-label={t('nav.signOut')}><Icon name="logout" /></button>
    </header>
    <main class="content">
      {#if info && !info.queryLog}
        <div class="notice warn banner">{t('nav.banner.queryLogOff')}</div>
      {/if}
      {#if info?.clientIpsMasked}
        {@const m = info.clientIpsMasked}
        <div class="notice warn banner" data-testid="masked-banner">
          <strong>{t('nav.banner.masked.title')}</strong>
          {t('nav.banner.masked.body', { share: m.sharePercent, queries: m.queries, sources: m.sources.join(', ') })}
          <a href="https://github.com/paimonsoror/telltaledns/blob/main/docs/running.md#seeing-real-client-ips" target="_blank" rel="noreferrer">{t('nav.banner.masked.fix')}</a><HelpButton id="masked-clients" />
        </div>
      {/if}
      {#if info?.maintenance && current.path !== '/cluster'}
        <!-- REQ: OPS-010 — the node serving this UI is in maintenance (the Cluster page has its own, with actions). -->
        <div class="notice warn banner" data-testid="maintenance-app-banner">
          <strong>{t('nav.banner.maintenance.title')}</strong>
          {t('nav.banner.maintenance.body', { reason: info.maintenance.reason })}
          <a href="#/cluster">{t('nav.banner.maintenance.link')}</a><HelpButton id="maintenance" />
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
  .links-gap {
    width: 1px;
    margin: 7px 4px;
    background: var(--side-hover);
  }
  .menu {
    position: relative;
  }
  /* REQ: OBS-015 — on phones the sidebar is hidden: a dot on the menu button when not healthy. */
  .menu-dot {
    position: absolute;
    top: 4px;
    right: 4px;
    width: 9px;
    height: 9px;
    border-radius: 50%;
    background: var(--warn);
    border: 2px solid var(--surface);
  }
  .menu-dot.severe {
    background: var(--bad);
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
  .role {
    margin-left: 6px;
    padding: 0 6px;
    border: 1px solid var(--side-muted);
    border-radius: 999px;
    color: var(--side-muted);
    font-size: 11px;
    font-weight: 600;
  }
  .role.primary {
    border-color: var(--side-text);
    color: var(--side-text);
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
  /* The page beside the open phone menu: dimmed, and a tap closes the menu. */
  .scrim {
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
    /* Health and the project links stack in the narrow sidebar. */
    .project-links {
      flex-direction: column;
      align-items: center;
    }
    .links-gap {
      width: 20px;
      height: 1px;
      margin: 4px 0;
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
    .scrim {
      display: block;
      position: fixed;
      inset: 0;
      z-index: 14;
      min-height: 0;
      padding: 0;
      border: 0;
      border-radius: 0;
      background: rgb(0 0 0 / 45%);
      cursor: default;
    }
    .content {
      padding: 8px 12px 24px;
    }
  }
</style>
