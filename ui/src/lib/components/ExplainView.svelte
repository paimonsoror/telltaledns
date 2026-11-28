<script lang="ts">
  // FLT-013: why a name is or isn't blocked for a client, every matching rule, and the route.
  import type { S } from '../api';
  import { dateTime } from '../format';
  import StatusBadge from './StatusBadge.svelte';
  import FlowDiagram from './FlowDiagram.svelte';
  import type { FlowPath } from '../help';
  import { own, tr } from '../i18n';
  import T from '../i18n/T.svelte';
  const { t } = tr('explainView');

  let { x }: { x: S['Explanation'] } = $props();

  const tierLabel: Record<string, string> = {
    important_allow: t('allow (important)'),
    important_block: t('block (important)'),
    allow: t('allow'),
    block: t('block'),
  };
  /** REQ: API-012 — a tier and a MAC's source come from the server: read with `Object.hasOwn` (one
   * the UI doesn't know shows as it is). */

  // REQ: FLT-013, FLT-006 (ADR-183) — how the device was recognized, when it was by its MAC address,
  // and where the MAC comes from: said as the server says it (`macFrom`), no more: "from your router"
  // only for this node's own router, "seen on this network" only for the neighbor table. Any other
  // `identifiedBy` is shown as the server says it. Without `macFrom` (a caller who may not read
  // MACs) a router's MAC is "from a router".
  const macFromLabel: Record<string, string> = {
    given: t('given with the question'),
    neighbor: t('seen on this network'),
    router: t('from your router'),
    peer: t('from another server in your cluster'),
  };
  const by = $derived.by(() => {
    const b = x.client.identifiedBy;
    if (b !== 'router_mac' && b !== 'neighbor_mac') return b;
    const from = x.client.macFrom ? (own(macFromLabel, x.client.macFrom) ?? x.client.macFrom) : b === 'router_mac' ? t('from a router') : '';
    return from ? t('its MAC address, {from}', { from }) : t('its MAC address');
  });

  // REQ: API-011 — the decision as a diagram: which way this query goes.
  const path = $derived<FlowPath>(
    x.outcome === 'refused'
      ? 'refused'
      : x.outcome === 'blocked'
        ? 'blocked'
        : x.outcome === 'local' || x.outcome === 'special'
          ? 'local'
          : x.route?.routed
            ? 'route'
            : 'upstream',
  );
  const detail = $derived(
    x.outcome === 'blocked' && x.block
      ? t('list {list}', { list: x.block.list })
      : x.outcome === 'special'
        ? t('a special-use name TelltaleDNS answers itself')
        : x.route
          ? t('upstream group {group}', { group: x.route.group })
          : '',
  );
</script>

{#snippet strong(s: string)}<strong translate="no">{s}</strong>{/snippet}

<div class="explain">
  <div class="notice {x.outcome === 'blocked' || x.outcome === 'refused' ? 'bad' : 'ok'}">
    <div class="row">
      <StatusBadge value={x.outcome} />
      <strong>{x.summary}</strong>
    </div>
    {#if x.pausedUntilUnixSeconds}
      <div class="muted small">{t('Blocking is paused for this client until {until}.', { until: dateTime(x.pausedUntilUnixSeconds) })}</div>
    {/if}
  </div>

  <section class="card" data-testid="explain-flow">
    <FlowDiagram highlight={path} device={x.client.device ?? x.client.ip} name={x.name} {detail} />
  </section>

  <section class="card">
    <h3>{t('Client')}</h3>
    <dl>
      <dt>{t('Address')}</dt>
      <dd class="mono" translate="no">{x.client.ip}</dd>
      {#if x.client.mac}<dt>{t('MAC')}</dt><dd><span class="mono" translate="no">{x.client.mac}</span>{#if x.client.macFrom} <span class="muted small" data-testid="explain-mac-from">({(own(macFromLabel, x.client.macFrom) ?? x.client.macFrom)})</span>{/if}</dd>{/if}
      <dt>{t('Device')}</dt>
      <dd>{x.client.device ?? t('not a configured device')} <span class="muted small" data-testid="explain-identified-by">{t('(by {by})', { by })}</span></dd>
      <dt>{t('Groups')}</dt>
      <dd translate="no">{x.client.groups.join(', ') || '–'}</dd>
      <dt>{t('Query')}</dt>
      <dd translate="no"><span class="mono" translate="no">{x.name}</span> {x.qtype}</dd>
    </dl>
  </section>

  {#if x.block}
    <section class="card">
      <h3>{t('Block response')}</h3>
      <dl>
        <dt>{t('List')}</dt>
        <dd>{x.block.list}</dd>
        <dt>{t('Answer')}</dt>
        <dd>{t('{mode} · TTL {ttl} s · EDE {ede}', { mode: x.block.mode, ttl: x.block.ttlSeconds, ede: x.block.edeCode })}</dd>
      </dl>
    </section>
  {/if}

  <section class="card">
    <h3>{t('Matching rules')}</h3>
    {#if !x.filter && ['local', 'special', 'refused'].includes(x.outcome)}
      <p class="muted">{t('Not checked: this query is answered before filtering.')}</p>
    {:else if !x.filter}
      <p class="muted">{t('No filter snapshot is loaded yet.')}</p>
    {:else if x.filter.rules.length === 0}
      <p class="muted">{t('No list has a rule for this name (snapshot {snapshot}).', { snapshot: x.filter.snapshot ?? '–' })}</p>
    {:else}
      <p class="muted small">{t("Snapshot {snapshot}, in precedence order. ★ decides; dimmed lists aren't used by this client.", { snapshot: x.filter.snapshot ?? '–' })}</p>
      <ul class="rules">
        {#each x.filter.rules as r, i (i)}
          <li class:winner={r.winner} class:off={!r.enabled}>
            <div class="row">
              <span class="mark">{r.winner ? '★' : ''}</span>
              <span class="badge {r.tier.includes('allow') ? 'ok' : 'bad'}">{own(tierLabel, r.tier) ?? r.tier}</span>
              <strong>{r.list}</strong>
              <!-- REQ: OBS-018 — a shadow list's rule is counted, never enforced. -->
              {#if r.shadow}<span class="badge info" title={t('This list is in shadow mode: it never blocks')}>{t('shadow')}</span>{/if}
              {#if r.name}<span class="mono">{r.name}</span>{/if}
              <span class="muted small">{r.kind}{r.scope ? ` · ${r.scope}` : ''}</span>
            </div>
            {#each r.lines as l (l.line)}
              <div class="line mono" translate="no"><span class="muted">{r.list}:{l.line}</span> {l.text}</div>
            {/each}
          </li>
        {/each}
      </ul>
    {/if}
    {#each x.filter?.notes ?? [] as n, i (i)}<p class="muted small">{n}</p>{/each}
  </section>

  {#if x.route}
    <section class="card">
      <h3>{t('Route')}</h3>
      <p>
        {#if x.route.routed}
          <T ctx="explainView" msg={'Upstream group <strong>{group}</strong> (matched a route)'} params={{ group: x.route.group }} {strong} />
        {:else}
          <T ctx="explainView" msg={'Upstream group <strong>{group}</strong> (default)'} params={{ group: x.route.group }} {strong} />
        {/if}
      </p>
    </section>
  {/if}

  {#each x.notes as n, i (i)}<p class="muted small">{n}</p>{/each}
</div>

<style>
  .explain {
    display: grid;
    gap: 12px;
  }
  dl {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 4px 14px;
    margin: 0;
  }
  dt {
    color: var(--muted);
    font-size: 12.5px;
  }
  dd {
    margin: 0;
    word-break: break-all;
  }
  .rules {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: 8px;
  }
  .rules li {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 8px 10px;
  }
  .rules li.winner {
    border-color: var(--accent);
  }
  .rules li.off {
    opacity: 0.55;
  }
  .mark {
    width: 1em;
    color: var(--accent);
  }
  .line {
    margin-top: 4px;
    word-break: break-all;
  }
</style>
