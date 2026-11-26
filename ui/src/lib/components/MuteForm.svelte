<script lang="ts">
  // REQ: OBS-038 (ADR-161) — mute a kind of finding for a device: the device and kind come from the
  // finding; you pick how long and why. The preview is a dry run, so a mistake (a name that
  // matches nothing, a MAC address) shows here before anything is saved.
  import { api, type S } from '../api';
  import ErrorNote from './ErrorNote.svelte';
  import { tk, tr, type Msg } from '../i18n';
  import T from '../i18n/T.svelte';
  const { t, tn, m } = tr('muteForm');

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

  const kindTitles: Record<string, Msg> = {
    rate_spike: m('Many more queries than usual'),
    domain_volume: m('Unusual traffic to one domain'),
    drift: m('Many new domains'),
    beacon: m('Regular phone-home'),
    nxdomain_storm: m('Burst of failed lookups'),
    reverse_sweep: m('Sweep of local addresses'),
    dga: m('Machine-generated-looking domains'),
    chatty_loop: m('Chatty loop'),
  };
  const durations: { v: string; l: string; ms: number | null }[] = [
    { v: '1d', l: t('1 day'), ms: 86_400_000 },
    { v: '1w', l: t('1 week'), ms: 7 * 86_400_000 },
    { v: '30d', l: t('30 days'), ms: 30 * 86_400_000 },
    { v: 'never', l: t('Until I remove it'), ms: null },
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

  // REQ: API-012 — `similar` is a count (a length, never negative). English keeps its "This
  // finding" for one; the other branch is a plural whose two English forms are the same sentence,
  // so a translation has its language's forms there.

  function toggle(k: string, on: boolean) {
    kinds = on ? [...kinds, k] : kinds.filter((x) => x !== k);
  }
</script>

<form class="mute" onsubmit={save} data-testid="mute-form">
  <p class="small">
    <T
      ctx="muteForm"
      msg={'Stop counting the kinds below for this device. The findings are still recorded and listed (turn on <b>Show muted</b>), and every other device is still checked.'}
      >{#snippet b(text: string)}<b>{text}</b>{/snippet}</T
    >
  </p>
  <label class="small field">{t('Device (name, IP or network)')}
    <input class="mono" bind:value={device} required aria-label={t('Device')} />
  </label>
  <fieldset class="kinds">
    <legend class="small">{t('Kinds of finding')}</legend>
    {#each Object.keys(kindTitles) as k (k)}
      <label class="small">
        <input type="checkbox" checked={kinds.includes(k)} onchange={(e) => toggle(k, e.currentTarget.checked)} />
        {tk(kindTitles[k])}
      </label>
    {/each}
  </fieldset>
  <div class="row">
    <label class="small">{t('For')}
      <select bind:value={duration} aria-label={t('How long')}>
        {#each durations as d (d.v)}<option value={d.v}>{d.l}</option>{/each}
      </select>
    </label>
    <input class="grow" aria-label={t('Note')} placeholder={t('Why (optional), e.g. hourly reverse-DNS sweep')} maxlength="200" bind:value={note} />
  </div>
  {#if similar > 0}
    <p class="muted small" data-testid="mute-similar">
      {similar === 1
        ? t('This finding in the period shown would have been muted.')
        : tn('These {n} findings in the period shown would have been muted.', 'These {n} findings in the period shown would have been muted.', similar, { n: similar })}
    </p>
  {/if}
  {#if preview}
    <div class="notice small" data-testid="mute-preview">
      <T ctx="muteForm" msg={'<b>What this will do:</b> {impact}'} params={{ impact: preview.impact || t('Mutes these findings for this device.') }}
        >{#snippet b(text: string)}<b>{text}</b>{/snippet}</T
      >
    </div>
    {#each preview.warnings as w (w)}<div class="notice warn small">{w}</div>{/each}
  {/if}
  <ErrorNote error={previewError} />
  <ErrorNote {error} />
  <div class="row">
    <button class="primary" disabled={saving || !!previewError || !preview} data-testid="mute-save">{saving ? t('Saving…') : t('Mute')}</button>
    <button type="button" class="link" onclick={() => oncancel?.()}>{t('Cancel')}</button>
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
