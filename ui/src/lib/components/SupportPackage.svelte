<script lang="ts">
  // REQ: OPS-011 (ADR-156) — make a support package: one file for an issue report, with what triage
  // needs and nothing that identifies you. A preview says what it would hold; the download is the
  // archive; the pseudonym map, if asked for, is a second, short-lived download.
  import { api, type S, type SupportManifest } from '../api';
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

  const levels: { id: Level; title: string; text: string }[] = [
    {
      id: 'strict',
      title: 'Strict (recommended)',
      text: 'Addresses, device, group, node and pod names, e-mail addresses and home paths become pseudonyms (device-1, 10.4.7.9). No query names, no free text, and only warnings and errors from the log.',
    },
    {
      id: 'standard',
      title: 'Standard',
      text: 'As strict, plus the log\'s INFO lines, top lists with pseudonymized names, and, if you choose, a sample of recent queries.',
    },
    {
      id: 'none',
      title: 'None',
      text: 'Real addresses, names and domains. Passwords, tokens and keys are still removed. Read it yourself before you share it.',
    },
  ];

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
  <h2>Support package<HelpButton id="support-package" /></h2>
  <p>
    One file to attach to a bug report: build and platform facts, your settings (without secrets), cluster and health,
    upstreams, list names and counts, a metrics snapshot, and this node's recent log. Nothing is uploaded.
  </p>
  <fieldset class="levels">
    <legend class="small">How much to hide</legend>
    {#each levels as l (l.id)}
      <label class="level">
        <input type="radio" name="support-level" value={l.id} bind:group={level} data-testid={`level-${l.id}`} />
        <span><b>{l.title}</b><br /><span class="muted small">{l.text}</span></span>
      </label>
    {/each}
  </fieldset>
  <div class="opts">
    <label class="small">Keep these readable (names, separated by commas)
      <input bind:value={reveal} placeholder="e.g. pi" aria-label="Names to keep readable" />
    </label>
    {#if level !== 'strict'}
      <label class="small">Recent queries to include (0 for none)
        <input type="number" min="0" max="1000" bind:value={sample} aria-label="Query sample" />
      </label>
    {/if}
    <label class="small check">
      <input type="checkbox" bind:checked={cluster} data-testid="cluster" />
      Every node in the cluster (each node hides its own names and addresses first, so nothing real crosses the network)
    </label>
    <label class="small check">
      <input type="checkbox" bind:checked={keepMap} disabled={cluster} data-testid="keep-map" />
      Let me download the key to the pseudonyms (for 10 minutes, once)
    </label>
  </div>
  <div class="row">
    <button disabled={busy} onclick={() => run('preview')} data-testid="support-preview">Preview what it holds</button>
    <button class="primary" disabled={busy} onclick={() => run('make')} data-testid="support-make">
      {busy ? 'Working…' : 'Make the package'}
    </button>
  </div>
  <ErrorNote {error} />

  {#if preview || made}
    {@const m = preview ?? made?.manifest}
    {#if m}
      <div class="manifest" data-testid="support-manifest">
        {#if made}
          <div class="notice ok small" data-testid="support-made">
            Saved <span class="mono">{made.name}</span> ({kib(total(m))} before compression). Look it over before you
            attach it: log lines are redacted by pattern, which is best effort.
          </div>
          {#if made.id}
            <p class="small">
              <button class="link" disabled={busy || mapGone} onclick={downloadMap} data-testid="support-map">Download the pseudonym map</button>
              {#if mapGone}<span class="muted">(given out; make another package to get a new one)</span>{/if}
              It lists what each pseudonym stands for, so it has your real names and addresses: keep it to yourself, and
              tell a maintainer what <span class="mono">device-3</span> was only if you want to.
            </p>
          {/if}
        {:else}
          <p class="small muted">This is what a package would hold right now; nothing was saved.</p>
        {/if}
        {#if m.nodes}
          <!-- REQ: OPS-011 (ADR-172) — a cluster package: each node's part, and whether it answered. -->
          <div class="table-wrap">
            <table>
              <thead><tr><th>Node</th><th>Answered</th><th class="num">Files</th><th class="num">Size</th><th>Note</th></tr></thead>
              <tbody>
                {#each m.nodes as n (n.node)}
                  <tr data-testid="support-node">
                    <td class="mono">{n.node}</td>
                    <td class="small">{#if n.status === 'ok'}<span class="badge ok">yes</span>{:else}<span class="badge warn">missing</span>{/if}</td>
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
            <thead><tr><th>File</th><th>Part</th><th class="num">Size</th><th>Replaced or removed</th></tr></thead>
            <tbody>
              {#each m.files ?? [] as f (f.path)}
                <tr data-testid="support-file">
                  <td class="mono">{f.path}</td>
                  <td class="small">{f.collector}</td>
                  <td class="num small">{f.status === 'missing' ? '—' : kib(f.bytes)}</td>
                  <td class="small">
                    {#if f.status === 'missing'}<span class="badge warn">missing</span> {f.note}
                    {:else if f.status === 'truncated'}<span class="badge warn">cut</span> {f.note}
                    {:else}{counts(f.redactions)}{/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
        {/if}
        {#if (m.config_fields_removed ?? []).length > 0}
          <p class="small muted">Settings removed as secrets: {(m.config_fields_removed ?? []).join(', ')}.</p>
        {/if}
        {#if (m.config_fields_unclassified ?? []).length > 0}
          <p class="small"><span class="badge warn">Please report</span> These settings had no rule and were removed: {(m.config_fields_unclassified ?? []).join(', ')}.</p>
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
