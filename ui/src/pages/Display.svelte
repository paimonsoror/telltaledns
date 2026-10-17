<script lang="ts">
  // REQ: OBS-035 (T14.13, ADR-140) — opens a wall display's link: the code in the address's
  // fragment (never sent with page loads) is exchanged once for a display session, then the
  // wall shows. The code is taken out of the address at once.
  import { onMount } from 'svelte';
  import { api, setCsrf } from '../lib/api';
  import { navigate, route } from '../lib/router.svelte';
  import { refreshSession } from '../lib/session.svelte';

  let error = $state<string | null>(null);
  onMount(() => {
    const code = route.params.get('code') ?? '';
    // The rest of the address (panels, timing) goes to the wall.
    const rest: Record<string, string> = {};
    for (const [k, v] of route.params) if (k !== 'code') rest[k] = v;
    navigate('/display', {}, true);
    if (!code) {
      error = "This address has no display code. Ask an admin for the wall display's link.";
      return;
    }
    api
      .openDisplay({ code })
      .then(async (r) => {
        setCsrf(r.csrfToken);
        await refreshSession();
        navigate('/wall', rest, true);
      })
      .catch((e) => (error = e instanceof Error ? e.message : String(e)));
  });
</script>

<main class="center" data-testid="display-open">
  {#if error}
    <div class="notice bad" data-testid="display-error">{error}</div>
  {:else}
    <p class="muted">Opening the wall…</p>
  {/if}
</main>
