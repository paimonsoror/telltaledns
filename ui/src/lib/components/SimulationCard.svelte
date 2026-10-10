<script lang="ts">
  // REQ: OBS-024 (T13.1, ADR-115) — "What would this have done?": the change replayed over
  // the query log, on request only (it can take seconds on a Pi). Every logged query in the
  // window is decided again with and without the change; only the differences are shown.
  import type { S } from '../api';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';

  let {
    run,
    result = null,
  }: {
    /** Runs the simulation (a dry run with `simulate`); shows the button. */
    run?: () => Promise<S['Simulation'] | null | undefined>;
    /** A simulation already made (an agent's plan): shown without a button. */
    result?: S['Simulation'] | null;
  } = $props();

  let busy = $state(false);
  let ran = $state<S['Simulation'] | null>(null);
  const sim = $derived(ran ?? result);
  let error = $state<unknown>(null);

  async function go() {
    if (!run) return;
    busy = true;
    error = null;
    ran = null;
    try {
      ran = (await run()) ?? null;
    } catch (e) {
      error = e;
    } finally {
      busy = false;
    }
  }

  const classes = [
    ['newlyBlocked', 'Newly blocked', 'bad'],
    ['newlyAllowed', 'Newly allowed', 'ok'],
    ['changedRoute', 'Changed route', ''],
    ['changedAnswer', 'Changed answer', ''],
  ] as const;

  const reasons: Record<string, string> = {
    disabled: 'Simulation is off on this cluster (Settings → System → Change simulation).',
    privacy_level:
      "The query log keeps names hashed or hidden at this node's privacy level, so this change can't be replayed. Moving a device between groups with the same lists still can be.",
    no_query_log: 'The query log is off on this node, so there is nothing to replay.',
    busy: 'Another simulation is running on this node. Try again in a few seconds.',
  };
  const notes: Record<string, string> = {
    identity_from_event:
      'Some devices were recognized by MAC address or client ID when they asked; they keep the group their queries were logged with.',
    badfilter_cross_snapshot: "A changed list has $badfilter rules; they don't cancel rules of the other lists in a preview.",
    names_capped: 'Very many names changed: counts are complete, but not every name is listed.',
    privacy_level_1_devices_only:
      'At privacy level 1 only devices moving between groups can be checked: queries of a device whose new groups decide differently are counted as undetermined.',
  };

  const total = (s: S['Simulation']) =>
    s.newlyBlocked.queries + s.newlyAllowed.queries + s.changedRoute.queries + s.changedAnswer.queries;
  const logLink = (name: string, s: S['Simulation']) =>
    `#/queries?name=${encodeURIComponent(name)}&match=exact&from=${encodeURIComponent(s.from ?? '-24h')}`;
  const n = (v: number) => v.toLocaleString();
</script>

<div class="sim" data-testid="simulation">
  {#if run}
    <div class="row">
      <button type="button" onclick={go} disabled={busy} data-testid="simulate-button"
        >{busy ? 'Replaying the logged queries…' : 'What would this have done?'}</button
      ><HelpButton id="simulate" />
    </div>
  {/if}
  <ErrorNote {error} />
  {#if sim}
    {#if !sim.available}
      <p class="notice small" data-testid="simulation-unavailable">{reasons[sim.reason ?? ''] ?? `Not simulated: ${sim.reason}`}</p>
    {:else if !sim.applicable}
      <p class="muted small" data-testid="simulation-not-applicable">
        This change can't affect how queries are answered, so there is nothing to replay.
      </p>
    {:else}
      <div class="card-in" data-testid="simulation-card">
        <p class="small">
          Over {n(sim.rows)} logged queries{sim.from ? ` since ${new Date(sim.from).toLocaleString()}` : ''}:
          {total(sim) === 0 ? 'none would have been answered differently.' : `${n(total(sim))} would have been answered differently.`}
          {#if sim.partial}<b>Partial:</b> the time or row limit was reached, so older queries weren't replayed.{/if}
        </p>
        <div class="tiles">
          {#each classes as [k, label, cls] (k)}
            <div class="tile {sim[k].queries > 0 ? cls : ''}" data-testid={`sim-${k}`}>
              <b class="num">{n(sim[k].queries)}</b>
              <span>{label}</span>
              <span class="muted small">{n(sim[k].devices)} device{sim[k].devices === 1 ? '' : 's'}</span>
            </div>
          {/each}
        </div>
        {#each classes as [k, label] (k)}
          {#if sim[k].topNames.length}
            <h4>{label}</h4>
            <ul class="names">
              {#each sim[k].topNames as t (t.name)}
                <li>
                  <a class="mono" href={logLink(t.name, sim)}>{t.name}</a>
                  <span class="muted small"
                    >{n(t.queries)} quer{t.queries === 1 ? 'y' : 'ies'}, {n(t.devices)} device{t.devices === 1 ? '' : 's'}{t.list
                      ? ` · ${t.list}`
                      : ''}</span
                  >
                </li>
              {/each}
            </ul>
          {/if}
        {/each}
        {#if sim.byDevice.length}
          <h4>By device</h4>
          <div class="chips">
            {#each sim.byDevice.slice(0, 12) as d (d.client)}
              <span class="chip small" title={d.client}
                >{d.name ?? d.client}: {[
                  d.newlyBlocked ? `${n(d.newlyBlocked)} blocked` : '',
                  d.newlyAllowed ? `${n(d.newlyAllowed)} allowed` : '',
                  d.changedRoute ? `${n(d.changedRoute)} rerouted` : '',
                  d.changedAnswer ? `${n(d.changedAnswer)} answered differently` : '',
                ]
                  .filter(Boolean)
                  .join(', ')}</span
              >
            {/each}
          </div>
        {/if}
        {#if sim.undetermined > 0}
          <p class="small">{n(sim.undetermined)} queries couldn't be decided again (names hashed in the log).</p>
        {/if}
        {#each sim.notes as note (note)}<p class="muted small">{notes[note] ?? note}</p>{/each}
        {#if sim.missingNodes?.length}
          <p class="small warn-text">Not included (didn't answer): {sim.missingNodes.join(', ')}.</p>
        {/if}
      </div>
    {/if}
  {/if}
</div>

<style>
  .sim {
    display: grid;
    gap: 8px;
    margin-top: 8px;
  }
  .row {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .card-in {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 10px 12px;
  }
  .card-in p {
    margin: 0 0 8px;
  }
  .tiles {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
    gap: 8px;
    margin-bottom: 8px;
  }
  .tile {
    display: grid;
    gap: 2px;
    padding: 8px;
    border-radius: 6px;
    background: var(--surface-2, var(--bg));
  }
  .tile.bad .num {
    color: var(--bad);
  }
  .tile.ok .num {
    color: var(--ok);
  }
  .num {
    font-size: 1.3em;
  }
  h4 {
    margin: 8px 0 4px;
  }
  .names {
    margin: 0;
    padding-left: 18px;
  }
  .names li {
    overflow-wrap: anywhere;
  }
  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }
</style>
