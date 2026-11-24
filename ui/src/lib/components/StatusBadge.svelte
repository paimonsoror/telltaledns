<script lang="ts">
  // Query status / list state / breaker state → a colored badge. `label` is the text shown when it
  // should read differently from the value (BreakerBadge); `title` is the tooltip.
  import { t, type MessageKey } from '../i18n';

  let {
    value,
    label,
    title,
  }: { value: string | null | undefined; label?: string; title?: string } = $props();

  // The words a status reads as, from the catalog so they follow the language; an rcode, a breaker
  // state, or a state this build doesn't know yet is shown exactly as it comes.
  const STATUS_KEY: Record<string, MessageKey> = {
    blocked: 'queries.status.blocked',
    cached: 'queries.status.cached',
    forwarded: 'queries.status.forwarded',
    local: 'queries.status.local',
    stale: 'queries.status.stale',
    refreshing: 'queries.status.refreshing',
    refreshed: 'queries.status.refreshed',
    special: 'queries.status.special',
    refused: 'queries.status.refused',
    servfail: 'queries.status.servfail',
    rate_limited: 'queries.status.rate_limited',
    paused: 'queries.status.paused',
    allowed: 'queries.status.allowed',
    malformed: 'queries.status.malformed',
  };

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
  // A status the catalog names reads in the language on screen; everything else as it comes.
  const shown = $derived(label ?? (value ? (STATUS_KEY[value] ? t(STATUS_KEY[value]) : value) : '–'));
</script>

<span class="badge {tone}" {title}>{shown}</span>
