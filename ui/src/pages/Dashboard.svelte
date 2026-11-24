<script lang="ts">
  // REQ: API-005 (ADR-157) — the dashboard is the new one unless this browser asked for the old
  // one. `#/?view=legacy` shows the previous dashboard and remembers the choice (in this browser
  // only); `#/?view=new` goes back. Nothing in the UI points at it: it is the way out for someone
  // who really prefers the old page, and it is meant to go away once nobody uses it.
  import { href, route } from '../lib/router.svelte';
  import { t } from '../lib/i18n';
  import DashboardCalm from './DashboardCalm.svelte';
  import DashboardLegacy from './DashboardLegacy.svelte';

  const KEY = 'dashboard.view';
  function stored(): boolean {
    try {
      return localStorage.getItem(KEY) === 'legacy';
    } catch {
      return false;
    }
  }
  let legacy = $state(stored());
  $effect(() => {
    const v = route.params.get('view');
    if (v !== 'legacy' && v !== 'new') return;
    legacy = v === 'legacy';
    try {
      if (legacy) localStorage.setItem(KEY, 'legacy');
      else localStorage.removeItem(KEY);
    } catch {
      // Private windows and blocked storage: the choice lasts until the page is reloaded.
    }
  });
</script>

{#if legacy}
  <DashboardLegacy />
  <p class="muted small switch-back"><a href={href('/', { view: 'new' })} data-testid="dashboard-new-link">{t('dashboard.switchBack')}</a></p>
{:else}
  <DashboardCalm />
{/if}

<style>
  .switch-back {
    margin: 18px 0 0;
  }
</style>
