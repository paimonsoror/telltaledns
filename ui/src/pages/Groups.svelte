<script lang="ts">
  // REQ: API-005, FLT-005 (ADR-050) — groups as categories of devices: each group's networks,
  // what its devices did in the last 24 hours, its heaviest names this hour, and its settings.
  import { api, type S } from '../lib/api';
  import { href } from '../lib/router.svelte';
  import { dateTime, num, pct } from '../lib/format';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import { currentMode } from '../lib/mode.svelte';
  import ConfigEditor, { type Field } from '../lib/components/ConfigEditor.svelte';

  let groups = $state<S['GroupInfo'][]>([]);
  let tops = $state<Record<string, { domains: S['TopItem'][]; blocked: S['TopItem'][] }>>({});
  let error = $state<unknown>(null);
  let listNames = $state<string[]>([]);

  // REQ: API-002 (T7.5) — add and change groups here.
  const groupFields = $derived<Field[]>([
    { key: 'networks', label: 'Networks', type: 'lines', placeholder: '192.168.2.0/24',
      help: 'One per line. Every device on these networks belongs to the group.' },
    { key: 'lists', label: 'Lists', type: 'multi', options: listNames,
      help: 'Leave all unticked on a new group to use every enabled list.' },
    { key: 'block_mode', label: 'Blocked answer', type: 'select', options: ['null_ip', 'nxdomain', 'nodata', 'refused', 'custom_ip'], advanced: true },
    { key: 'priority', label: 'Priority', type: 'number', placeholder: '0', advanced: true,
      help: 'When a device matches several groups, the highest priority wins.' },
    { key: 'color', label: 'Color', type: 'text', placeholder: '#4f8cff', advanced: true },
  ]);

  function load() {
    api.lists().then((l) => (listNames = l.items.map((x) => x.name))).catch(() => {});
    api
      .groups()
      .then(async (g) => {
        groups = g.items;
        const entries = await Promise.all(
          g.items
            .filter((x) => x.queries24h > 0)
            .map(async (x) => {
              const [d, b] = await Promise.all([api.top('domains', 5, undefined, x.name), api.top('blocked', 5, undefined, x.name)]);
              return [x.name, { domains: d.items, blocked: b.items }] as const;
            }),
        );
        tops = Object.fromEntries(entries);
      })
      .catch((e) => (error = e));
  }
  $effect(load);
  const advanced = $derived(currentMode() === 'advanced');
  const total = $derived(groups.reduce((a, g) => a + g.queries24h, 0));
</script>

<div class="page">
  <h1>Groups<HelpButton id="groups" /></h1>
  <ErrorNote {error} />
  <p class="muted small">
    A group is a kind of device: every device on a group's networks belongs to it (a named device can also be put in a
    group of its own). Groups decide which lists apply and show what each kind of device does.
  </p>

  <div class="group-grid">
    {#each groups as g (g.name)}
      <section class="card group" data-testid="group-card" style:--gc={g.color}>
        <div class="card-head">
          <h2>{g.name}</h2>
          {#if g.pausedUntilUnixSeconds}
            <span class="badge warn">paused until {dateTime(g.pausedUntilUnixSeconds)}</span>
          {/if}
        </div>
        <div class="muted small mono">
          {g.networks.length ? g.networks.join(', ') : g.name === 'default' ? 'devices that match nothing else' : 'named devices only'}
        </div>
        <dl class="stats">
          <div><dt>Queries (24 h)</dt><dd>{num(g.queries24h)}{#if total}<span class="muted small"> · {pct((g.queries24h / total) * 100, 0)}</span>{/if}</dd></div>
          <div><dt>Blocked</dt><dd>{g.queries24h ? pct((g.blocked24h / g.queries24h) * 100) : '–'}</dd></div>
          <div><dt>Devices (this hour)</dt><dd>{num(g.devicesThisHour)}</dd></div>
        </dl>
        {#if tops[g.name]}
          <div class="tops small">
            <div>
              <div class="muted">Top names</div>
              <ol>{#each tops[g.name].domains as t (t.key)}<li class="mono">{t.key} <span class="muted">{num(t.count)}</span></li>{/each}</ol>
            </div>
            <div>
              <div class="muted">Top blocked</div>
              {#if tops[g.name].blocked.length}
                <ol>{#each tops[g.name].blocked as t (t.key)}<li class="mono">{t.key} <span class="muted">{num(t.count)}</span></li>{/each}</ol>
              {:else}<span class="muted">nothing blocked</span>{/if}
            </div>
          </div>
        {/if}
        <a class="small" href={href('/queries', { group: g.name })}>Show this group's queries</a>
      </section>
    {/each}
  </div>

  <section class="card">
    <h2>Settings</h2>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Group</th><th class="num">Priority</th><th>Lists<HelpButton id="lists" /></th>{#if advanced}<th>Blocked answer</th>{/if}<th>Blocking</th></tr></thead>
        <tbody>
          {#each groups as g (g.name)}
            <tr>
              <td><strong>{g.name}</strong></td>
              <td class="num">{g.priority}</td>
              <td>{g.lists ? g.lists.join(', ') || 'none' : 'every enabled list'}</td>
              {#if advanced}<td>{g.blockMode} · TTL {g.blockTtlSeconds} s</td>{/if}
              <td>
                {#if g.pausedUntilUnixSeconds}
                  <span class="badge warn">paused until {dateTime(g.pausedUntilUnixSeconds)}</span>
                {:else}
                  <span class="badge ok">on</span>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  </section>
  <ConfigEditor kind="group" path="groups" title="Manage groups" noun="group" fields={groupFields}
    summary={(d) => `${((d.networks as string[]) ?? []).join(', ') || 'named devices only'} · ${d.lists ? `${(d.lists as string[]).length} lists` : 'every enabled list'}`}
    onchanged={load} />
</div>

<style>
  .group-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 16px;
    margin-bottom: 16px;
  }
  .group {
    margin: 0;
  }
  /* T6.8 — the title's accent bar carries the group's color. */
  .group h2::before {
    background: var(--gc);
    width: 4px;
  }
  .stats {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 8px;
    margin: 12px 0;
  }
  .stats dt {
    color: var(--muted);
    font-size: 0.8em;
  }
  .stats dd {
    margin: 0;
    font-size: 1.35em;
    font-weight: 650;
    font-variant-numeric: tabular-nums;
  }
  .tops {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
    margin-bottom: 8px;
  }
  .tops > div {
    min-width: 0;
  }
  .tops ol {
    margin: 4px 0 0;
    padding-left: 18px;
  }
  .tops li {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
</style>
