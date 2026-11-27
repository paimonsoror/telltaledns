<script lang="ts">
  // REQ: OBS-024 (T13.1, ADR-115) — "What would this have done?": the change replayed over
  // the query log, on request only (it can take seconds on a Pi). Every logged query in the
  // window is decided again with and without the change; only the differences are shown.
  import type { S } from '../api';
  import { dateTime, num } from '../format';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';
  import { own, tr } from '../i18n';
  import T from '../i18n/T.svelte';
  // REQ: API-012 — the counts are u64 on the server (never negative): tn() gives the ternaries' English.
  const { t, tn } = tr('simulationCard');

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
    ['newlyBlocked', t('Newly blocked'), 'bad'],
    ['newlyAllowed', t('Newly allowed'), 'ok'],
    ['changedRoute', t('Changed route'), ''],
    ['changedAnswer', t('Changed answer'), ''],
  ] as const;

  const reasons: Record<string, string> = {
    disabled: t('Simulation is off on this cluster (Settings → Query handling → Change simulation).'),
    privacy_level: t(
      "The query log keeps names hashed or hidden at this node's privacy level, so this change can't be replayed. Moving a device between groups with the same lists still can be.",
    ),
    no_query_log: t('The query log is off on this node, so there is nothing to replay.'),
    busy: t('Another simulation is running on this node. Try again in a few seconds.'),
    // REQ: OBS-024 (ADR-180)
    local_file: t("This change names a local file the configuration doesn't read yet, so only an administrator can replay it."),
    download_limit: t(
      'This change adds or changes more lists than one simulation reads on this node (at most 4 by URL or from a file, within 4 times its list size limit). Simulate fewer list changes at a time.',
    ),
  };
  const notes: Record<string, string> = {
    identity_from_event: t(
      'Some devices were recognized by MAC address or client ID when they asked; they keep the group their queries were logged with.',
    ),
    badfilter_cross_snapshot: t("A changed list has $badfilter rules; they don't cancel rules of the other lists in a preview."),
    names_capped: t('Very many names changed: counts are complete, but not every name is listed.'),
    privacy_level_1_devices_only: t(
      'At privacy level 1 only devices moving between groups can be checked: queries of a device whose new groups decide differently are counted as undetermined.',
    ),
  };
  // The reason and the notes come from the server: read with `Object.hasOwn`; one the UI doesn't know shows as it is.
  const why = (reason: string | null | undefined) => {
    const k = reason ?? '';
    return own(reasons, k) ?? t('Not simulated: {reason}', { reason: String(reason) });
  };
  const noteText = (note: string) => (own(notes, note) ?? note);

  const total = (s: S['Simulation']) =>
    s.newlyBlocked.queries + s.newlyAllowed.queries + s.changedRoute.queries + s.changedAnswer.queries;
  const logLink = (name: string, s: S['Simulation']) =>
    `#/queries?name=${encodeURIComponent(name)}&match=exact&from=${encodeURIComponent(s.from ?? '-24h')}`;
  const n = (v: number) => num(v);
</script>

{#snippet b(x: string)}<b>{x}</b>{/snippet}

<div class="sim" data-testid="simulation">
  {#if run}
    <div class="row">
      <button type="button" onclick={go} disabled={busy} data-testid="simulate-button"
        >{busy ? t('Replaying the logged queries…') : t('What would this have done?')}</button
      ><HelpButton id="simulate" />
    </div>
  {/if}
  <ErrorNote {error} />
  {#if sim}
    {#if !sim.available}
      <p class="notice small" data-testid="simulation-unavailable">{why(sim.reason)}</p>
    {:else if !sim.applicable}
      <p class="muted small" data-testid="simulation-not-applicable">
        {t("This change can't affect how queries are answered, so there is nothing to replay.")}
      </p>
    {:else}
      {@const none = total(sim) === 0}
      {@const sum = { rows: n(sim.rows), since: sim.from ? dateTime(Date.parse(sim.from) / 1000) : '', n: n(total(sim)) }}
      <div class="card-in" data-testid="simulation-card">
        <p class="small">
          {#if sim.from}
            {none ? t('Over {rows} logged queries since {since}: none would have been answered differently.', sum) : t('Over {rows} logged queries since {since}: {n} would have been answered differently.', sum)}
          {:else}
            {none ? t('Over {rows} logged queries: none would have been answered differently.', sum) : t('Over {rows} logged queries: {n} would have been answered differently.', sum)}
          {/if}
          {#if sim.partial}<T ctx="simulationCard" msg={"<b>Partial:</b> the time or row limit was reached, so older queries weren't replayed."} {b} />{/if}
        </p>
        <div class="tiles">
          {#each classes as [k, label, cls] (k)}
            <div class="tile {sim[k].queries > 0 ? cls : ''}" data-testid={`sim-${k}`}>
              <b class="num">{n(sim[k].queries)}</b>
              <span>{label}</span>
              <span class="muted small">{tn('{n} device', '{n} devices', sim[k].devices, { n: n(sim[k].devices) })}</span>
            </div>
          {/each}
        </div>
        {#each classes as [k, label] (k)}
          {#if sim[k].topNames.length}
            <h4>{label}</h4>
            <ul class="names">
              {#each sim[k].topNames as nm (nm.name)}
                <li>
                  <a class="mono" href={logLink(nm.name, sim)} translate="no">{nm.name}</a>
                  <span class="muted small"
                    >{t('{queries}, {devices}', {
                      queries: tn('{n} query', '{n} queries', nm.queries, { n: n(nm.queries) }),
                      devices: tn('{n} device', '{n} devices', nm.devices, { n: n(nm.devices) }),
                    })}{nm.list ? ` · ${nm.list}` : ''}</span
                  >
                </li>
              {/each}
            </ul>
          {/if}
        {/each}
        {#if sim.byDevice.length}
          <h4>{t('By device')}</h4>
          <div class="chips">
            {#each sim.byDevice.slice(0, 12) as d (d.client)}
              <span class="chip small" title={d.client}
                >{t('{who}: {what}', {
                  who: d.name ?? d.client,
                  what: [
                    d.newlyBlocked ? t('{n} blocked', { n: n(d.newlyBlocked) }) : '',
                    d.newlyAllowed ? t('{n} allowed', { n: n(d.newlyAllowed) }) : '',
                    d.changedRoute ? t('{n} rerouted', { n: n(d.changedRoute) }) : '',
                    d.changedAnswer ? t('{n} answered differently', { n: n(d.changedAnswer) }) : '',
                  ]
                    .filter(Boolean)
                    .join(', '),
                })}</span
              >
            {/each}
          </div>
        {/if}
        {#if sim.undetermined > 0}
          <p class="small">{t("{n} queries couldn't be decided again (names hashed in the log).", { n: n(sim.undetermined) })}</p>
        {/if}
        {#each sim.notes as note (note)}<p class="muted small">{noteText(note)}</p>{/each}
        {#if sim.missingNodes?.length}
          <p class="small warn-text">{t("Not included (didn't answer): {nodes}.", { nodes: sim.missingNodes.join(', ') })}</p>
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
