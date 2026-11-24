<script lang="ts">
  // REQ: API-005, OBS-011 (GitHub issue #9) — an upstream's health in plain words (Healthy,
  // Benched, Probing); the circuit breaker's own state is the tooltip.
  import StatusBadge from './StatusBadge.svelte';
  import { breakerLabel } from '../breaker';
  import { t, type MessageKey } from '../i18n';

  let { value }: { value: string | null | undefined } = $props();

  // The states people read, from the catalog so they follow the language; a state this build
  // doesn't know yet, and "nothing at all", stay exactly as `breakerLabel` says them.
  const LABEL_KEY: Record<string, MessageKey> = {
    closed: 'dashw.breaker.closed',
    open: 'dashw.breaker.open',
    half_open: 'dashw.breaker.halfOpen',
  };
  const label = $derived(value && LABEL_KEY[value] ? t(LABEL_KEY[value]) : breakerLabel(value));
  const title = $derived(value ? t('dashw.breaker.title', { state: value }) : undefined);
</script>

<StatusBadge {value} {label} {title} />
