<script lang="ts">
  // Query status / list state / breaker state → a colored badge.
  let { value }: { value: string | null | undefined } = $props();

  const tones: Record<string, string> = {
    blocked: 'bad',
    failed: 'bad',
    open: 'bad',
    refused: 'bad',
    servfail: 'bad',
    SERVFAIL: 'bad',
    cached: 'ok',
    // DNS-007: answered from the cache at once while refreshed in the background.
    refreshed: 'ok',
    stale: 'warn',
    ok: 'ok',
    closed: 'ok',
    allowed: 'ok',
    forwarded: 'info',
    resolved: 'info',
    local: 'info',
    half_open: 'warn',
    pending: 'warn',
    NXDOMAIN: 'warn',
  };
  const tone = $derived(value ? (tones[value] ?? '') : '');
</script>

<span class="badge {tone}">{value ?? '–'}</span>
