<script lang="ts">
  // REQ: OBS-024 (T13.1, ADR-115) — "What would this have done?": the change replayed over
  // the query log, on request only (it can take seconds on a Pi). Every logged query in the
  // window is decided again with and without the change; only the differences are shown.
  import type { S } from '../api';
  import { t as tr, tn, type MessageKey } from '../i18n';
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

  // Each class's words are a key (what it says follows the language on screen); the class and its
  // tone stay as they are.
  const classes = [
    ['newlyBlocked', 'simulation.preview.newlyBlocked', 'bad'],
    ['newlyAllowed', 'simulation.preview.newlyAllowed', 'ok'],
    ['changedRoute', 'simulation.preview.changedRoute', ''],
    ['changedAnswer', 'simulation.preview.changedAnswer', ''],
  ] as const;

  // The identifiers the server sends, as keys: `reason` says why it couldn't run, `note` what an
  // approximation was. One this file doesn't know is shown as the server sent it.
  const reasons: Record<string, MessageKey> = {
    disabled: 'simulation.preview.reason.disabled',
    privacy_level: 'simulation.preview.reason.privacyLevel',
    no_query_log: 'simulation.preview.reason.noQueryLog',
    busy: 'simulation.preview.reason.busy',
    // REQ: OBS-024 (ADR-180)
    local_file: 'simulation.preview.reason.localFile',
    download_limit: 'simulation.preview.reason.downloadLimit',
  };
  const notes: Record<string, MessageKey> = {
    identity_from_event: 'simulation.preview.note.identityFromEvent',
    badfilter_cross_snapshot: 'simulation.preview.note.badfilterCrossSnapshot',
    names_capped: 'simulation.preview.note.namesCapped',
    privacy_level_1_devices_only: 'simulation.preview.note.privacyLevel1DevicesOnly',
  };

  const total = (s: S['Simulation']) =>
    s.newlyBlocked.queries + s.newlyAllowed.queries + s.changedRoute.queries + s.changedAnswer.queries;
  const logLink = (name: string, s: S['Simulation']) =>
    `#/queries?name=${encodeURIComponent(name)}&match=exact&from=${encodeURIComponent(s.from ?? '-24h')}`;
  const n = (v: number) => v.toLocaleString();
  /** Why a simulation didn't run, in words; an unknown reason is the server's own. */
  const reasonText = (id: string | null | undefined) =>
    id && reasons[id] ? tr(reasons[id]) : tr('simulation.preview.notSimulated', { reason: String(id) });
  /** What a note about the numbers says; an unknown one is the server's own. */
  const noteText = (id: string) => (notes[id] ? tr(notes[id]) : id);
  /** "Over n logged queries since …:" — the count's own words, then when the window started. */
  const overText = (s: S['Simulation']) =>
    tn('simulation.preview.over', s.rows, {
      n: n(s.rows),
      when: s.from ? tr('simulation.preview.since', { time: new Date(s.from).toLocaleString() }) : '',
    });
</script>

<div class="sim" data-testid="simulation">
  {#if run}
    <div class="row">
      <button type="button" onclick={go} disabled={busy} data-testid="simulate-button"
        >{busy ? tr('simulation.preview.replaying') : tr('simulation.preview.button')}</button
      ><HelpButton id="simulate" />
    </div>
  {/if}
  <ErrorNote {error} />
  {#if sim}
    {#if !sim.available}
      <p class="notice small" data-testid="simulation-unavailable">{reasonText(sim.reason)}</p>
    {:else if !sim.applicable}
      <p class="muted small" data-testid="simulation-not-applicable">
        {tr('simulation.preview.notApplicable')}
      </p>
    {:else}
      <div class="card-in" data-testid="simulation-card">
        <p class="small">
          {overText(sim)}
          {total(sim) === 0
            ? tr('simulation.preview.noneDifferent')
            : tr('simulation.preview.different', { n: n(total(sim)) })}
          {#if sim.partial}<b>{tr('simulation.preview.partialLabel')}</b> {tr('simulation.preview.partialNote')}{/if}
        </p>
        <div class="tiles">
          {#each classes as [k, label, cls] (k)}
            <div class="tile {sim[k].queries > 0 ? cls : ''}" data-testid={`sim-${k}`}>
              <b class="num">{n(sim[k].queries)}</b>
              <span>{tr(label)}</span>
              <span class="muted small">{tn('simulation.preview.devices', sim[k].devices, { n: n(sim[k].devices) })}</span>
            </div>
          {/each}
        </div>
        {#each classes as [k, label] (k)}
          {#if sim[k].topNames.length}
            <h4>{tr(label)}</h4>
            <ul class="names">
              {#each sim[k].topNames as t (t.name)}
                <li>
                  <a class="mono" href={logLink(t.name, sim)}>{t.name}</a>
                  <span class="muted small"
                    >{tr('simulation.preview.counts', {
                      queries: tn('simulation.preview.queries', t.queries, { n: n(t.queries) }),
                      devices: tn('simulation.preview.devices', t.devices, { n: n(t.devices) }),
                    })}{t.list ? ` · ${t.list}` : ''}</span
                  >
                </li>
              {/each}
            </ul>
          {/if}
        {/each}
        {#if sim.byDevice.length}
          <h4>{tr('simulation.preview.byDevice')}</h4>
          <div class="chips">
            {#each sim.byDevice.slice(0, 12) as d (d.client)}
              <span class="chip small" title={d.client}
                >{d.name ?? d.client}: {[
                  d.newlyBlocked ? tr('simulation.preview.chip.blocked', { n: n(d.newlyBlocked) }) : '',
                  d.newlyAllowed ? tr('simulation.preview.chip.allowed', { n: n(d.newlyAllowed) }) : '',
                  d.changedRoute ? tr('simulation.preview.chip.rerouted', { n: n(d.changedRoute) }) : '',
                  d.changedAnswer ? tr('simulation.preview.chip.answeredDifferently', { n: n(d.changedAnswer) }) : '',
                ]
                  .filter(Boolean)
                  .join(', ')}</span
              >
            {/each}
          </div>
        {/if}
        {#if sim.undetermined > 0}
          <p class="small">{tn('simulation.preview.undetermined', sim.undetermined, { n: n(sim.undetermined) })}</p>
        {/if}
        {#each sim.notes as note (note)}<p class="muted small">{noteText(note)}</p>{/each}
        {#if sim.missingNodes?.length}
          <p class="small warn-text">{tr('simulation.preview.missingNodes', { nodes: sim.missingNodes.join(', ') })}</p>
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
