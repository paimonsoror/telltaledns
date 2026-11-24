<script lang="ts">
  // REQ: OBS-038 (ADR-161) — mute a kind of finding for a device: the device and kind come from the
  // finding; you pick how long and why. The preview is a dry run, so a mistake (a name that
  // matches nothing, a MAC address) shows here before anything is saved.
  import { api, type S } from '../api';
  import { t as tr, tn, type MessageKey } from '../i18n';
  import ErrorNote from './ErrorNote.svelte';

  let {
    finding,
    similar = 1,
    onsaved,
    oncancel,
  }: {
    finding: S['AnomalyFinding'];
    /** Findings of this kind for this device in the period shown, this one included. */
    similar?: number;
    /** Called with the change once it is saved; the page shows the confirmation (this form closes). */
    onsaved?: (change: S['ConfigChange']) => void;
    oncancel?: () => void;
  } = $props();

  // The kinds are what the API is sent; these are what a person reads.
  const kindTitles: Record<string, MessageKey> = {
    rate_spike: 'anomalies.kind.rateSpike',
    domain_volume: 'anomalies.kind.domainVolume',
    drift: 'anomalies.kind.drift',
    beacon: 'anomalies.kind.beacon',
    nxdomain_storm: 'anomalies.kind.nxdomainStorm',
    dga: 'anomalies.kind.dga',
    chatty_loop: 'anomalies.kind.chattyLoop',
  };
  const durations: { v: string; l: MessageKey; ms: number | null }[] = [
    { v: '1d', l: 'queries.duration.1d', ms: 86_400_000 },
    { v: '1w', l: 'deviceWidgets.mute.duration.1w', ms: 7 * 86_400_000 },
    { v: '30d', l: 'settings.tokens.expires30', ms: 30 * 86_400_000 },
    { v: 'never', l: 'queries.duration.always', ms: null },
  ];

  // The address is what findings are made from, so it is the default; a device name works too when
  // it is a configured device with an IP or network.
  let device = $state('');
  let kinds = $state<string[]>([]);
  let duration = $state('1w');
  let note = $state('');
  $effect(() => {
    device = finding.client;
    kinds = [finding.kind];
  });

  let saving = $state(false);
  let error = $state<unknown>(null);
  let preview = $state<S['ConfigChange'] | null>(null);
  let previewError = $state<unknown>(null);

  const slug = (s: string) =>
    s
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '');
  // The same device and kind give the same name, so muting again changes the mute (its end time)
  // instead of adding another.
  const name = $derived(`${slug(device).slice(0, 40) || 'device'}-${kinds.length === 1 ? slug(kinds[0]).replace(/_/g, '-') : 'several'}`);

  function body(): Record<string, unknown> {
    const ms = durations.find((d) => d.v === duration)?.ms ?? null;
    return {
      devices: [device.trim()],
      kinds: [...kinds].sort(),
      ...(ms ? { expires: new Date(Date.now() + ms).toISOString() } : {}),
      ...(note.trim() ? { note: note.trim() } : {}),
    };
  }

  let seq = 0;
  $effect(() => {
    const n = name;
    const ready = device.trim() !== '' && kinds.length > 0;
    void duration;
    void note;
    const mine = ++seq;
    preview = null;
    previewError = null;
    if (!ready) return;
    const t = setTimeout(() => {
      api
        .putEntry('anomaly-mutes', n, body(), true)
        .then((c) => {
          if (mine === seq) preview = c;
        })
        .catch((e) => {
          if (mine === seq) previewError = e;
        });
    }, 250);
    return () => clearTimeout(t);
  });

  async function save(e: SubmitEvent) {
    e.preventDefault();
    saving = true;
    error = null;
    try {
      onsaved?.(await api.putEntry('anomaly-mutes', name, body()));
    } catch (err) {
      error = err;
    } finally {
      saving = false;
    }
  }

  function toggle(k: string, on: boolean) {
    kinds = on ? [...kinds, k] : kinds.filter((x) => x !== k);
  }
</script>

<form class="mute" onsubmit={save} data-testid="mute-form">
  <p class="small">
    {tr('deviceWidgets.mute.introLead')}<b>{tr('deviceWidgets.mute.showMuted')}</b>{tr('deviceWidgets.mute.introTail')}
  </p>
  <label class="small field">{tr('deviceWidgets.mute.device')}
    <input class="mono" bind:value={device} required aria-label={tr('flow.device')} />
  </label>
  <fieldset class="kinds">
    <legend class="small">{tr('deviceWidgets.mute.kinds')}</legend>
    {#each Object.keys(kindTitles) as k (k)}
      <label class="small">
        <input type="checkbox" checked={kinds.includes(k)} onchange={(e) => toggle(k, e.currentTarget.checked)} />
        {tr(kindTitles[k])}
      </label>
    {/each}
  </fieldset>
  <div class="row">
    <label class="small">{tr('deviceWidgets.mute.for')}
      <select bind:value={duration} aria-label={tr('deviceWidgets.mute.howLong')}>
        {#each durations as d (d.v)}<option value={d.v}>{tr(d.l)}</option>{/each}
      </select>
    </label>
    <input class="grow" aria-label={tr('rules.col.note')} placeholder={tr('deviceWidgets.mute.notePlaceholder')} maxlength="200" bind:value={note} />
  </div>
  {#if similar > 0}
    <p class="muted small" data-testid="mute-similar">
      {tn('deviceWidgets.mute.similar', similar)}
    </p>
  {/if}
  {#if preview}
    <div class="notice small" data-testid="mute-preview"><b>{tr('deviceWidgets.mute.previewLead')}</b> {preview.impact || tr('deviceWidgets.mute.previewFallback')}</div>
    {#each preview.warnings as w (w)}<div class="notice warn small">{w}</div>{/each}
  {/if}
  <ErrorNote error={previewError} />
  <ErrorNote {error} />
  <div class="row">
    <button class="primary" disabled={saving || !!previewError || !preview} data-testid="mute-save">{saving ? tr('qw.chip.saving') : tr('deviceWidgets.mute.mute')}</button>
    <button type="button" class="link" onclick={() => oncancel?.()}>{tr('common.cancel')}</button>
  </div>
</form>

<style>
  .mute {
    display: grid;
    gap: 10px;
    border-top: 1px dashed var(--border);
    padding-top: 10px;
    margin-top: 8px;
  }
  .row {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    align-items: center;
  }
  .field {
    display: grid;
    gap: 4px;
  }
  .grow {
    flex: 1 1 220px;
  }
  .kinds {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 6px 10px 8px;
    display: flex;
    flex-wrap: wrap;
    gap: 4px 16px;
  }
  .kinds label {
    display: inline-flex;
    gap: 6px;
    align-items: center;
  }
</style>
