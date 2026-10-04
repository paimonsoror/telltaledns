<script lang="ts">
  // FLT-013: why a name is or isn't blocked for a client, every matching rule, and the route.
  import type { S } from '../api';
  import { dateTime } from '../format';
  import StatusBadge from './StatusBadge.svelte';

  let { x }: { x: S['Explanation'] } = $props();

  const tierLabel: Record<string, string> = {
    important_allow: 'allow (important)',
    important_block: 'block (important)',
    allow: 'allow',
    block: 'block',
  };
</script>

<div class="explain">
  <div class="notice {x.outcome === 'blocked' || x.outcome === 'refused' ? 'bad' : 'ok'}">
    <div class="row">
      <StatusBadge value={x.outcome} />
      <strong>{x.summary}</strong>
    </div>
    {#if x.pausedUntilUnixSeconds}
      <div class="muted small">Blocking is paused for this client until {dateTime(x.pausedUntilUnixSeconds)}.</div>
    {/if}
  </div>

  <section class="card">
    <h3>Client</h3>
    <dl>
      <dt>Address</dt>
      <dd class="mono">{x.client.ip}</dd>
      {#if x.client.mac}<dt>MAC</dt><dd class="mono">{x.client.mac}</dd>{/if}
      <dt>Device</dt>
      <dd>{x.client.device ?? 'not a configured device'} <span class="muted small">(by {x.client.identifiedBy})</span></dd>
      <dt>Groups</dt>
      <dd>{x.client.groups.join(', ') || '–'}</dd>
      <dt>Query</dt>
      <dd><span class="mono">{x.name}</span> {x.qtype}</dd>
    </dl>
  </section>

  {#if x.block}
    <section class="card">
      <h3>Block response</h3>
      <dl>
        <dt>List</dt>
        <dd>{x.block.list}</dd>
        <dt>Answer</dt>
        <dd>{x.block.mode} · TTL {x.block.ttlSeconds} s · EDE {x.block.edeCode}</dd>
      </dl>
    </section>
  {/if}

  <section class="card">
    <h3>Matching rules</h3>
    {#if !x.filter && ['local', 'special', 'refused'].includes(x.outcome)}
      <p class="muted">Not checked: this query is answered before filtering.</p>
    {:else if !x.filter}
      <p class="muted">No filter snapshot is loaded yet.</p>
    {:else if x.filter.rules.length === 0}
      <p class="muted">No list has a rule for this name (snapshot {x.filter.snapshot ?? '–'}).</p>
    {:else}
      <p class="muted small">Snapshot {x.filter.snapshot ?? '–'}, in precedence order. ★ decides; dimmed lists aren't used by this client.</p>
      <ul class="rules">
        {#each x.filter.rules as r, i (i)}
          <li class:winner={r.winner} class:off={!r.enabled}>
            <div class="row">
              <span class="mark">{r.winner ? '★' : ''}</span>
              <span class="badge {r.tier.includes('allow') ? 'ok' : 'bad'}">{tierLabel[r.tier] ?? r.tier}</span>
              <strong>{r.list}</strong>
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
      <h3>Route</h3>
      <p>Upstream group <strong>{x.route.group}</strong> {x.route.routed ? '(matched a route)' : '(default)'}</p>
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
