<script lang="ts">
  // Query status / list state / breaker state → a colored badge. `label` is the text shown when it
  // should read differently from the value (BreakerBadge); `title` is the tooltip.
  let {
    value,
    label,
    title,
  }: { value: string | null | undefined; label?: string; title?: string } = $props();

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

<span class="badge {tone}" {title}>{#if label !== undefined}{label}{:else}<span translate="no">{value ?? '–'}</span>{/if}</span>
