<script lang="ts">
  // FLT-013: why a name is or isn't blocked for a client, every matching rule, and the route.
  import type { S } from '../api';
  import { dateTime } from '../format';
  import { t, type MessageKey } from '../i18n';
  import StatusBadge from './StatusBadge.svelte';
  import FlowDiagram from './FlowDiagram.svelte';
  import type { FlowPath } from '../help';

  let { x }: { x: S['Explanation'] } = $props();

  const TIER_LABEL: Record<string, MessageKey> = {
    important_allow: 'qw.explain.tier.importantAllow',
    important_block: 'qw.explain.tier.importantBlock',
    allow: 'qw.explain.tier.allow',
    block: 'qw.explain.tier.block',
  };
  /** The words for a tier; a tier this build doesn't know yet is shown as the server said it. */
  const tierLabel = (tier: string) => (TIER_LABEL[tier] ? t(TIER_LABEL[tier]) : tier);

  // REQ: FLT-013, FLT-006 (ADR-183) — how the device was recognized, when it was by its MAC address,
  // and where the MAC comes from: said as the server says it (`macFrom`), no more: "from your router"
  // only for this node's own router, "seen on this network" only for the neighbor table. Any other
  // `identifiedBy` is shown as the server says it. Without `macFrom` (a caller who may not read
  // MACs) a router's MAC is "from a router".
  const MAC_FROM: Record<string, MessageKey> = {
    given: 'qw.explain.macFrom.given',
    neighbor: 'qw.explain.macFrom.neighbor',
    router: 'qw.explain.macFrom.router',
    peer: 'qw.explain.macFrom.peer',
  };
  /** Where a MAC came from, in the words the server's `macFrom` means (a value we don't know stays as it is). */
  const macFromLabel = (from: string) => (MAC_FROM[from] ? t(MAC_FROM[from]) : from);
  const by = $derived.by(() => {
    const b = x.client.identifiedBy;
    if (b !== 'router_mac' && b !== 'neighbor_mac') return b;
    const from = x.client.macFrom ? macFromLabel(x.client.macFrom) : b === 'router_mac' ? t('qw.explain.macFrom.aRouter') : '';
    return from ? t('qw.explain.by.mac', { from }) : t('qw.explain.by.macOnly');
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
      ? t('qw.explain.detail.list', { list: x.block.list })
      : x.outcome === 'special'
        ? t('qw.explain.detail.special')
        : x.route
          ? t('qw.explain.detail.upstream', { group: x.route.group })
          : '',
  );
</script>

<div class="explain">
  <div class="notice {x.outcome === 'blocked' || x.outcome === 'refused' ? 'bad' : 'ok'}">
    <div class="row">
      <StatusBadge value={x.outcome} />
      <strong>{x.summary}</strong>
    </div>
    {#if x.pausedUntilUnixSeconds}
      <div class="muted small">{t('qw.explain.paused', { time: dateTime(x.pausedUntilUnixSeconds) })}</div>
    {/if}
  </div>

  <section class="card" data-testid="explain-flow">
    <FlowDiagram highlight={path} device={x.client.device ?? x.client.ip} name={x.name} {detail} />
  </section>

  <section class="card">
    <h3>{t('qw.explain.client')}</h3>
    <dl>
      <dt>{t('qw.explain.address')}</dt>
      <dd class="mono">{x.client.ip}</dd>
      {#if x.client.mac}<dt>MAC</dt><dd><span class="mono">{x.client.mac}</span>{#if x.client.macFrom} <span class="muted small" data-testid="explain-mac-from">{t('qw.explain.macFromSpan', { from: macFromLabel(x.client.macFrom) })}</span>{/if}</dd>{/if}
      <dt>{t('qw.explain.device')}</dt>
      <dd>{x.client.device ?? t('qw.explain.notConfigured')} <span class="muted small" data-testid="explain-identified-by">{t('qw.explain.identifiedBy', { by })}</span></dd>
      <dt>{t('qw.explain.groups')}</dt>
      <dd>{x.client.groups.join(', ') || '–'}</dd>
      <dt>{t('qw.explain.query')}</dt>
      <dd><span class="mono">{x.name}</span> {x.qtype}</dd>
    </dl>
  </section>

  {#if x.block}
    <section class="card">
      <h3>{t('qw.explain.blockResponse')}</h3>
      <dl>
        <dt>{t('qw.explain.list')}</dt>
        <dd>{x.block.list}</dd>
        <dt>{t('qw.explain.answer')}</dt>
        <dd>{x.block.mode} · TTL {x.block.ttlSeconds} s · EDE {x.block.edeCode}</dd>
      </dl>
    </section>
  {/if}

  <section class="card">
    <h3>{t('qw.explain.matchingRules')}</h3>
    {#if !x.filter && ['local', 'special', 'refused'].includes(x.outcome)}
      <p class="muted">{t('qw.explain.notChecked')}</p>
    {:else if !x.filter}
      <p class="muted">{t('qw.explain.noSnapshot')}</p>
    {:else if x.filter.rules.length === 0}
      <p class="muted">{t('qw.explain.noRule', { snapshot: x.filter.snapshot ?? '–' })}</p>
    {:else}
      <p class="muted small">{t('qw.explain.snapshot', { snapshot: x.filter.snapshot ?? '–' })}</p>
      <ul class="rules">
        {#each x.filter.rules as r, i (i)}
          <li class:winner={r.winner} class:off={!r.enabled}>
            <div class="row">
              <span class="mark">{r.winner ? '★' : ''}</span>
              <span class="badge {r.tier.includes('allow') ? 'ok' : 'bad'}">{tierLabel(r.tier)}</span>
              <strong>{r.list}</strong>
              <!-- REQ: OBS-018 — a shadow list's rule is counted, never enforced. -->
              {#if r.shadow}<span class="badge info" title={t('qw.explain.shadowTitle')}>{t('qw.explain.shadow')}</span>{/if}
              {#if r.name}<span class="mono">{r.name}</span>{/if}
              <span class="muted small">{r.kind}{r.scope ? ` · ${r.scope}` : ''}</span>
            </div>
            {#each r.lines as l (l.line)}
              <div class="line mono"><span class="muted">{r.list}:{l.line}</span> {l.text}</div>
            {/each}
          </li>
        {/each}
      </ul>
    {/if}
    {#each x.filter?.notes ?? [] as n, i (i)}<p class="muted small">{n}</p>{/each}
  </section>

  {#if x.route}
    <section class="card">
      <h3>{t('qw.explain.route')}</h3>
      <p>{t('qw.explain.upstreamGroup')} <strong>{x.route.group}</strong> {x.route.routed ? t('qw.explain.matchedRoute') : t('qw.explain.defaultRoute')}</p>
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
