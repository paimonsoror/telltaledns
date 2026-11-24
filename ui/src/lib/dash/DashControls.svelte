<script lang="ts">
  // REQ: API-005, CLU-002, OBS-033 (ADR-157) — the dashboard's view controls: node (or site), device
  // group, time range, and the Changes switch with Note….
  import { RANGES, type DashData } from './data.svelte';
  import type { S } from '../api';
  import ChangesControls from '../components/ChangesControls.svelte';
  import { t } from '../i18n';

  let { d, part = 'all' }: { d: DashData; part?: 'all' | 'range' | 'filters' } = $props();

  const nodeLabel = (n: S['ClusterView']['nodes'][number]) =>
    (n.ephemeral ? t('dashboard.nodePod', { site: n.site, pod: n.pod ?? n.nodeId.slice(0, 8) }) : n.site) +
    (n.role.includes('primary') ? t('dashboard.nodePrimary') : '') +
    (n.thisNode ? ` · ${t('dashboard.thisNode')}` : '');
  const podSites = $derived([...new Set(d.nodes.filter((n) => n.ephemeral).map((n) => n.site))]);
</script>

<div class="ctl">
  {#if part !== 'range'}
    {#if d.nodes.length > 1}
      <label class="pill-field">
        {t('dashboard.showing')}
        <select bind:value={d.scope} aria-label={t('dashboard.nodes')}>
          <option value="">{t('dashboard.everyNode')}</option>
          {#each d.nodes as n (n.nodeId)}<option value={`node:${n.nodeId}`}>{nodeLabel(n)}</option>{/each}
          {#each podSites as s (s)}<option value={`site:${s}`}>{t('dashboard.siteAllNodes', { site: s })}</option>{/each}
        </select>
      </label>
    {/if}
    {#if d.groups.length > 1}
      <label class="pill-field">
        {t('dashboard.topListsFor')}
        <select bind:value={d.group} aria-label={t('dashboard.group')}>
          <option value="">{t('dashboard.everyDevice')}</option>
          {#each d.groups as g (g.name)}<option value={g.name}>{g.name}</option>{/each}
        </select>
      </label>
    {/if}
  {/if}
  {#if part !== 'filters'}
    <div class="seg" role="group" aria-label={t('dashboard.timeRange')}>
      {#each RANGES as r (r.id)}
        <button aria-pressed={d.range.id === r.id} onclick={() => (d.range = r)}>{r.label}</button>
      {/each}
    </div>
    <ChangesControls />
  {/if}
</div>

<style>
  .ctl {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
  }
  /* On a phone the range scrolls inside its own track instead of wrapping into two rows. */
  .seg {
    max-width: 100%;
    overflow-x: auto;
    scrollbar-width: none;
  }
  .seg button {
    flex: none;
  }
</style>
