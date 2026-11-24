<script lang="ts">
  // REQ: API-005, CLU-002, OBS-033 (ADR-157) — the heading with the view controls, the note form,
  // and the partial-results notice.
  import type { DashData } from './data.svelte';
  import DashControls from './DashControls.svelte';
  import ChangesControls from '../components/ChangesControls.svelte';
  import ErrorNote from '../components/ErrorNote.svelte';
  import HelpButton from '../components/HelpButton.svelte';
  import { t } from '../i18n';

  let { d, title }: { d: DashData; title?: string } = $props();
  // The page's own name when the caller gives none.
  const heading = $derived(title ?? t('dashboard.title'));
</script>

<div class="page-head">
  <h1>{heading}<HelpButton id="how-it-works" /></h1>
  <DashControls {d} />
</div>
<ChangesControls part="body" advanced={d.advanced} />
<ErrorNote error={d.error} />
{#if d.summary?.missingNodes?.length}
  <div class="notice warn small">{t('dashboard.partialResults', { nodes: d.summary.missingNodes.join(', ') })}</div>
{/if}
