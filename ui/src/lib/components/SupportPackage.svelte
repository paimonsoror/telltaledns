<script lang="ts">
  // REQ: OPS-011 (ADR-156) — make a support package: one file for an issue report, with what triage
  // needs and nothing that identifies you. A preview says what it would hold; the download is the
  // archive; the pseudonym map, if asked for, is a second, short-lived download.
  import { api, type S, type SupportManifest } from '../api';
  // REQ: API-011 — the card's own words; what the server sends (a file's path, a note) stays as it is.
  import { t } from '../i18n';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';

  type Level = 'strict' | 'standard' | 'none';
  let level = $state<Level>('strict');
  let reveal = $state('');
  let sample = $state(0);
  let keepMap = $state(false);
  // REQ: OPS-011 (ADR-172) — every node makes and hides its own part; there is no map to keep.
  let cluster = $state(false);
  $effect(() => {
    if (cluster) keepMap = false;
  });
  let busy = $state(false);
  let error = $state<unknown>(null);
  let preview = $state<SupportManifest | null>(null);
  let made = $state<{ name: string; id?: string; manifest: SupportManifest } | null>(null);
  let mapGone = $state(false);

  // A getter: the three choices follow the language on screen.
  const levels = $derived.by((): { id: Level; title: string; text: string }[] => [
    {
      id: 'strict',
      title: t('settings.support.strict'),
      text: t('settings.support.strictText'),
    },
    {
      id: 'standard',
      title: t('settings.support.standard'),
      text: t('settings.support.standardText'),
    },
    {
      id: 'none',
      title: t('settings.support.none'),
      text: t('settings.support.noneText'),
    },
  ]);

  const request = $derived<S['SupportPackageRequest']>({
    level,
    reveal: reveal
      .split(/[,\n]/)
      .map((s) => s.trim())
      .filter(Boolean),
    querySample: level === 'strict' ? 0 : Math.max(0, Math.min(1000, Math.floor(Number(sample) || 0))),
    keepMap: keepMap && !cluster,
    cluster,
  });

  const total = (m: SupportManifest) =>
    (m.files ?? []).reduce((n, f) => n + f.bytes, 0) + (m.nodes ?? []).reduce((n, x) => n + x.bytes, 0);
  const counts = (r?: Record<string, number>) =>
    r
      ? Object.entries(r)
          .map(([k, v]) => `${v} ${k}`)
          .join(', ')
      : '';
  const kib = (n: number) => (n < 1024 ? `${n} B` : `${(n / 1024).toFixed(n < 10240 ? 1 : 0)} KiB`);

  async function run(kind: 'preview' | 'make') {
    busy = true;
    error = null;
    mapGone = false;
    try {
      if (kind === 'preview') {
        preview = await api.supportPreview(request);
      } else {
        const r = await api.supportPackage(request);
        save(r.blob, r.name);
        made = { name: r.name, id: r.id, manifest: r.manifest };
        preview = null;
      }
    } catch (e) {
      error = e;
    } finally {
      busy = false;
    }
  }

  /** Hands a blob to the browser as a download. */
  function save(blob: Blob, name: string) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 10_000);
  }

  async function downloadMap() {
    if (!made?.id) return;
    busy = true;
    error = null;
    try {
      save(await api.supportMap(made.id), 'telltale-support-map.txt');
      mapGone = true;
    } catch (e) {
      error = e;
      mapGone = true;
    } finally {
      busy = false;
    }
  }
</script>

<section class="card" data-testid="support-package">
  <h2>{t('settings.support.title')}<HelpButton id="support-package" /></h2>
  <p>
    {t('settings.support.about')}
  </p>
  <fieldset class="levels">
    <legend class="small">{t('settings.support.howMuch')}</legend>
    {#each levels as l (l.id)}
      <label class="level">
        <input type="radio" name="support-level" value={l.id} bind:group={level} data-testid={`level-${l.id}`} />
        <span><b>{l.title}</b><br /><span class="muted small">{l.text}</span></span>
      </label>
    {/each}
  </fieldset>
  <div class="opts">
    <label class="small">{t('settings.support.reveal')}
      <input bind:value={reveal} placeholder={t('settings.support.revealPlaceholder')} aria-label={t('settings.support.revealLabel')} />
    </label>
    {#if level !== 'strict'}
      <label class="small">{t('settings.support.sample')}
        <input type="number" min="0" max="1000" bind:value={sample} aria-label={t('settings.support.sampleLabel')} />
      </label>
    {/if}
    <label class="small check">
      <input type="checkbox" bind:checked={cluster} data-testid="cluster" />
      {t('settings.support.cluster')}
    </label>
    <label class="small check">
      <input type="checkbox" bind:checked={keepMap} disabled={cluster} data-testid="keep-map" />
      {t('settings.support.keepMap')}
    </label>
  </div>
  <div class="row">
    <button disabled={busy} onclick={() => run('preview')} data-testid="support-preview">{t('settings.support.preview')}</button>
    <button class="primary" disabled={busy} onclick={() => run('make')} data-testid="support-make">
      {busy ? t('settings.support.working') : t('settings.support.make')}
    </button>
  </div>
  <ErrorNote {error} />

  {#if preview || made}
    {@const m = preview ?? made?.manifest}
    {#if m}
      <div class="manifest" data-testid="support-manifest">
        {#if made}
          <div class="notice ok small" data-testid="support-made">
            {t('settings.support.saved')} <span class="mono">{made.name}</span> {t('settings.support.savedSize', { size: kib(total(m)) })}
            {t('settings.support.savedNote')}
          </div>
          {#if made.id}
            <p class="small">
              <button class="link" disabled={busy || mapGone} onclick={downloadMap} data-testid="support-map">{t('settings.support.downloadMap')}</button>
              {#if mapGone}<span class="muted">{t('settings.support.mapGone')}</span>{/if}
              {t('settings.support.mapLead')} <span class="mono">device-3</span> {t('settings.support.mapTail')}
            </p>
          {/if}
        {:else}
          <p class="small muted">{t('settings.support.previewNote')}</p>
        {/if}
        {#if m.nodes}
          <!-- REQ: OPS-011 (ADR-172) — a cluster package: each node's part, and whether it answered. -->
          <div class="table-wrap">
            <table>
              <thead><tr><th>{t('qw.cache.node')}</th><th>{t('settings.support.colAnswered')}</th><th class="num">{t('settings.support.colFiles')}</th><th class="num">{t('lists.col.size')}</th><th>{t('rules.col.note')}</th></tr></thead>
              <tbody>
                {#each m.nodes as n (n.node)}
                  <tr data-testid="support-node">
                    <td class="mono">{n.node}</td>
                    <td class="small">{#if n.status === 'ok'}<span class="badge ok">{t('settings.support.yes')}</span>{:else}<span class="badge warn">{t('settings.support.missing')}</span>{/if}</td>
                    <td class="num small">{n.status === 'ok' ? n.files : '—'}</td>
                    <td class="num small">{n.status === 'ok' ? kib(n.bytes) : '—'}</td>
                    <td class="small">{n.note ?? ''}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        {:else}
        <div class="table-wrap">
          <table>
            <thead><tr><th>{t('settings.support.colFile')}</th><th>{t('settings.support.colPart')}</th><th class="num">{t('lists.col.size')}</th><th>{t('settings.support.colReplaced')}</th></tr></thead>
            <tbody>
              {#each m.files ?? [] as f (f.path)}
                <tr data-testid="support-file">
                  <td class="mono">{f.path}</td>
                  <td class="small">{f.collector}</td>
                  <td class="num small">{f.status === 'missing' ? '—' : kib(f.bytes)}</td>
                  <td class="small">
                    {#if f.status === 'missing'}<span class="badge warn">{t('settings.support.missing')}</span> {f.note}
                    {:else if f.status === 'truncated'}<span class="badge warn">{t('settings.support.cut')}</span> {f.note}
                    {:else}{counts(f.redactions)}{/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
        {/if}
        {#if (m.config_fields_removed ?? []).length > 0}
          <p class="small muted">{t('settings.support.removedSecrets', { fields: (m.config_fields_removed ?? []).join(', ') })}</p>
        {/if}
        {#if (m.config_fields_unclassified ?? []).length > 0}
          <p class="small"><span class="badge warn">{t('settings.support.report')}</span> {t('settings.support.unclassified', { fields: (m.config_fields_unclassified ?? []).join(', ') })}</p>
        {/if}
        {#each m.notes as n (n)}<p class="small muted">{n}</p>{/each}
      </div>
    {/if}
  {/if}
</section>

<style>
  .levels {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 6px 12px 10px;
    display: grid;
    gap: 8px;
    margin: 8px 0;
  }
  .level {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 8px;
    align-items: start;
  }
  .opts {
    display: grid;
    gap: 8px;
    margin: 8px 0;
  }
  .opts label {
    display: grid;
    gap: 4px;
  }
  .opts .check {
    display: flex;
    gap: 8px;
    align-items: center;
  }
  .row {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin: 8px 0;
  }
  .manifest {
    margin-top: 10px;
    display: grid;
    gap: 8px;
  }
</style>
