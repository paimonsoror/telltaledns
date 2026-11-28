<!-- REQ: API-013 (ADR-190) — the card "Test a language pack" (a chunk of its own, loaded on Open): download
  the template for a language tag (what `sync` writes for a new language) and the notes for translators;
  check a translated file with the build's own rules; use it in this browser after a confirmation; download
  it in the repository's exact form for a pull request; see and remove the pack in use. Only the template
  is fetched, and `/system/info` and `/auth/status` once on Use (the server's build, and who is signed in:
  the pack is that user's); nothing about a file leaves the browser. Text from a file is
  shown as plain text, isolated for direction (`<bdi>`), with forbidden code points as visible markers and
  never as message markup. The confirmation, the line naming the pack in use, the notices, and the buttons
  Use, Download for a pull request and Remove are English on purpose (a pack must not change them): they
  hold no message of the layer and sit under translate="no" and lang="en". -->
<script lang="ts">
  import { tick, untrack } from 'svelte';
  import { api } from '../api';
  import { dateTime, num, pct } from '../format';
  import { tr } from '../i18n';
  import T from '../i18n/T.svelte';
  import { DEVPACK_KEY, devpack } from '../i18n/devpack';
  import { MAX_BYTES, checkPack, decodeFile, languageName, markers, shownName, tagInfo, type Checked, type Refusal, type Tag } from '../i18n/pack';
  import type { Pair } from '../i18n/pairs';
  import { materialize, readTemplate, type Template } from '../i18n/template';
  import { notesText } from './notes';
  import { brokenWords, leftoverWords, refusalWords, tagWords, worthWords } from './packWords';
  import { sha256 } from './sha256';
  import { entryPath, newRecord, readValue, retire, write, type Notice, type PackRecord, type Store } from './store';
  const { t, tn } = tr('devPackCard');
  // This web UI's build (the entry module's path).
  const ui = entryPath();

  // The developer page for translators (the project site, as the menu's link to the site).
  const GUIDE = 'https://paimonsoror.github.io/telltaledns/dev-languages.html';
  /** At most this many entries of one list are drawn. */
  const LIST_MAX = 200;

  let store: Store | null = null;
  try {
    store = localStorage;
  } catch {
    // Storage blocked: a file can still be checked and downloaded, not used.
  }
  function readKept(): { record?: PackRecord; notice?: Notice } {
    try {
      const v = store?.getItem(DEVPACK_KEY);
      if (!v) return {};
      const r = readValue(v);
      return 'record' in r ? { record: r.record } : 'notice' in r ? { notice: r.notice } : {};
    } catch {
      return {};
    }
  }
  let kept = $state(readKept());

  // The template: fetched once, when the card opens (same origin, normally from the browser's cache).
  let tpl = $state<Template | null>(null);
  let tplFailed = $state(false);
  async function loadTemplate() {
    try {
      if (!devpack.template) throw new Error('no template');
      const res = await fetch(devpack.template, { credentials: 'same-origin' });
      if (!res.ok) throw new Error(String(res.status));
      tpl = readTemplate(await res.text());
    } catch {
      tplFailed = true;
    }
  }
  void loadTemplate();

  let tagInput = $state('');
  const info = $derived(tpl && tagInput.trim() ? tagInfo(tagInput, tpl.plurals) : null);
  const tag = $derived(info?.ok ? info.value : null);
  const names = $derived(tag ? { english: languageName(tag.tag, 'en'), own: languageName(tag.tag, tag.tag) } : null);
  const nameOf = (n: typeof names, code: string) => (n?.english ? (n.own && n.own !== n.english ? `${n.english} (${n.own})` : n.english) : code);

  type Chosen = { name: string; bytes: Uint8Array; sha: string; text?: string; bom: boolean };
  let chosen = $state.raw<Chosen | null>(null);
  let outcome = $state.raw<{ refused: Refusal } | { checked: Checked; tag: Tag } | null>(null);
  let fileInput = $state<HTMLInputElement | null>(null);

  async function choose(f: File | undefined) {
    if (!f) return;
    confirming = false;
    useError = '';
    if (!tagInput.trim()) {
      const m = /^([A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*)(?: ?\(\d+\))?\.json$/.exec(f.name);
      if (m) tagInput = m[1];
    }
    if (f.size > MAX_BYTES) {
      chosen = { name: f.name, bytes: new Uint8Array(), sha: '', bom: false };
      outcome = { refused: { code: 'size' } };
      return;
    }
    const bytes = new Uint8Array(await f.arrayBuffer());
    const d = decodeFile(bytes);
    chosen = { name: f.name, bytes, sha: sha256(bytes), text: d?.text, bom: d?.bom ?? false };
    runCheck();
  }
  function runCheck() {
    if (!chosen || chosen.sha === '') return;
    if (chosen.text === undefined) outcome = { refused: { code: 'utf8' } };
    else if (!tpl || !tag) outcome = null;
    else {
      const r = checkPack(chosen.text, chosen.bom, tpl, tag);
      outcome = r.refused ? { refused: r.refused } : { checked: r.checked, tag };
    }
  }
  // A file chosen before the template arrived is checked when it does.
  $effect(() => {
    if (tpl) untrack(runCheck);
  });

  // The pack in use: checked again here, as each page load does.
  const keptCheck = $derived.by(() => {
    const r = kept.record;
    if (!r || !tpl) return null;
    const ti = tagInfo(r.tag, tpl.plurals);
    if (!ti.ok) return null;
    const c = checkPack(r.text, false, tpl, ti.value);
    return c.refused ? null : { checked: c.checked, tag: ti.value };
  });

  /** Hands text to the browser as a download (UTF-8). */
  function save(text: string, name: string, type: string) {
    const url = URL.createObjectURL(new Blob([text], { type }));
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 10_000);
  }
  const build = () => ui.replace(/^\/assets\//, '').replace(/\.js$/, '');
  function downloadTemplate() {
    if (tpl && tag) save(materialize(tpl, tag.categories), `${tag.tag}.json`, 'application/json');
  }
  function downloadNotes() {
    if (tpl && tag) save(notesText(tpl, tag, names ?? {}, build(), new Date().toISOString().slice(0, 10)), `${tag.tag}-notes.txt`, 'text/plain');
  }

  let confirming = $state(false);
  let useError = $state<'' | 'storage' | 'server'>('');
  let busy = $state(false);
  let confirmHeading = $state<HTMLElement | null>(null);
  let useButton = $state<HTMLButtonElement | null>(null);
  async function startUse() {
    confirming = true;
    useError = '';
    await tick();
    confirmHeading?.focus();
  }
  async function cancel() {
    confirming = false;
    await tick();
    useButton?.focus();
  }
  async function use() {
    // The file and the check confirmed, as they are now: a file chosen while the requests run is not stored.
    const file = chosen;
    const got = outcome;
    if (!file || !got || !('checked' in got)) return;
    busy = true;
    useError = '';
    let commit: string;
    let user: string;
    try {
      // The server's build, and who is signed in: the pack is that user's (another is paused).
      const [info, status] = await Promise.all([api.info(), api.status()]);
      commit = info.build?.commit ?? '';
      user = status.user?.username ?? '';
    } catch {
      useError = 'server';
      busy = false;
      return;
    }
    // The record keeps the check's table for this build and fingerprint, so a page load need not check
    // the file again; when that does not fit, the record alone (each load then checks the file).
    const rec = newRecord({ ui, commit, user, name: file.name, sha: file.sha, tag: got.tag.tag, dir: got.tag.dir, text: file.text ?? '', table: got.checked.table }, Date.now());
    if (!write(store, rec) && !write(store, { ...rec, checked: undefined })) {
      useError = 'storage';
      busy = false;
      return;
    }
    location.reload();
  }
  // What this card read is removed only while the key still holds it (another tab may have loaded a newer pack).
  function removePack() {
    if (kept.record) retire(store, kept.record);
    location.reload();
  }
  function dismiss() {
    if (kept.notice) retire(store, kept.notice);
    kept = {};
    devpack.active = false;
  }

  const englishOf = (e: Pair[0]) => (typeof e === 'string' ? e : `${e[0]} / ${e[1]}`);
  const share = (done: number, total: number) => pct(total ? (done * 100) / total : 100, 0);
  let openBroken = $state(false);
  let openMissing = $state(false);
  let openLeft = $state(false);
  let openWorth = $state(false);
</script>

<svelte:window
  onkeydown={(e) => {
    if (confirming && e.key === 'Escape') void cancel();
  }}
/>

{#snippet file(x: string)}<bdi translate="no">{x}</bdi>{/snippet}

{#snippet summary(c: Checked, name: string)}
  <p role="status" data-testid="devpack-summary">
    <T ctx="devPackCard" msg={'<file>{name}</file>: {done} of {total} texts translated ({share}).'} params={{ name: shownName(name), done: num(c.translated), total: num(c.total), share: share(c.translated, c.total) }} {file} />
    {#if c.brokenTexts}{tn('{n} text breaks a rule and shows in English.', '{n} texts break a rule and show in English.', c.brokenTexts, { n: num(c.brokenTexts) })}{/if}
    {#if c.leftovers.length}{tn('{n} pair is left over.', '{n} pairs are left over.', c.leftovers.length, { n: num(c.leftovers.length) })}{/if}
  </p>
{/snippet}

{#snippet entry(ctx: string, english: Pair[0], translation: string | undefined, lang: string, why: string)}
  <li>
    <span class="ctx mono small" translate="no">{ctx}</span>
    <bdi dir="auto" class="en" lang="en" translate="no">{markers(englishOf(english))}</bdi>
    {#if translation !== undefined}<bdi dir="auto" class="tx" {lang} translate="no">{markers(translation)}</bdi>{/if}
    {#if why}<span class="why">{why}</span>{/if}
  </li>
{/snippet}

{#snippet more(n: number)}
  {#if n > LIST_MAX}<p class="muted small">{t('And {n} more.', { n: num(n - LIST_MAX) })}</p>{/if}
{/snippet}

<div class="devpack" data-testid="devpack-body">
  <p class="muted">{t('For translators: see your translation of this web UI before you send it to the project. The file stays in this browser; nothing about it is sent to TelltaleDNS or anyone else.')}</p>
  <p><a href={GUIDE} target="_blank" rel="noreferrer">{t('How to translate TelltaleDNS')}</a></p>

  {#if kept.record}
    {@const r = kept.record}
    <div class="in-use" data-testid="devpack-in-use">
      <p translate="no" lang="en">
        In use: <bdi>{shownName(r.name)}</bdi>, {nameOf({ english: languageName(r.tag, 'en'), own: languageName(r.tag, r.tag) }, r.tag)} ({r.tag}), fingerprint <span class="mono">{r.sha.slice(0, 12)}</span>.
        Loaded {dateTime(r.loadedAt / 1000)}; removed on {dateTime(r.expires / 1000)} or when TelltaleDNS is updated.
      </p>
      {#if keptCheck}{@render summary(keptCheck.checked, r.name)}{/if}
      {#if keptCheck?.checked.broken.length}
        <ul class="entries">
          {#each keptCheck.checked.broken.slice(0, LIST_MAX) as b, i (i)}{@render entry(b.ctx, b.english, b.translation, r.tag, brokenWords(b))}{/each}
        </ul>
      {/if}
      <div class="row">
        <button onclick={() => fileInput?.click()}>{t('Check a new version of the file')}</button>
        <span class="row" translate="no" lang="en">
          {#if keptCheck}
            {@const k = keptCheck}
            <button onclick={() => save(k.checked.pr, `${k.tag.tag}.json`, 'application/json')}>Download for a pull request ({r.tag}.json)</button>
          {/if}
          <button class="danger" onclick={removePack} data-testid="devpack-card-remove">Remove and reload</button>
        </span>
      </div>
    </div>
  {:else if kept.notice}
    {@const n = kept.notice}
    <div class="notice" translate="no" lang="en" data-testid="devpack-card-notice">
      <p>
        The test language pack {#if n.name}<bdi>{shownName(n.name)}</bdi>{/if} was removed:
        {#if n.gone === 'upgrade'}TelltaleDNS was updated. Download the template again and check your file: translations whose English didn't change still apply.
        {:else if n.gone === 'expired'}it was loaded 7 days ago.
        {:else if n.gone === 'damaged'}the copy kept in this browser couldn't be read.
        {:else if n.gone === 'failed'}it could not be checked twice in a row. Check the file again under Settings.
        {:else}a page could not be drawn with it.{/if}
      </p>
      <button onclick={dismiss} aria-label="Dismiss this notice">Dismiss</button>
    </div>
  {/if}

  <section aria-labelledby="devpack-step1">
    <h3 id="devpack-step1">{t('1. Get the template')}</h3>
    <label class="field">{t('Language tag (such as de, fr, pt-BR or zh-Hant)')}
      <input bind:value={tagInput} onchange={runCheck} autocomplete="off" spellcheck="false" data-testid="devpack-tag" />
    </label>
    <p class="small" aria-live="polite" data-testid="devpack-tag-line">
      {#if !tpl}{tplFailed ? t('The template could not be loaded: reload this page.') : t('Loading the template…')}
      {:else if !info}{tagWords({ code: 'empty' })}
      {:else if !info.ok}{tagWords(info.why)}
      {:else if info.value.dir === 'rtl'}{t('{name}: written right to left; saved as {tag}.', { name: nameOf(names, info.value.tag), tag: info.value.tag })}
      {:else}{t('{name}: written left to right; saved as {tag}.', { name: nameOf(names, info.value.tag), tag: info.value.tag })}{/if}
    </p>
    {#if tag?.dir === 'rtl'}<p class="notice warn">{t("The layout isn't ready for right-to-left languages yet.")}</p>{/if}
    <div class="row">
      {#if tag}
        <button onclick={downloadTemplate} data-testid="devpack-template">{t('Download the template ({file})', { file: `${tag.tag}.json` })}</button>
        <button onclick={downloadNotes} data-testid="devpack-notes">{t('Notes for translators ({file})', { file: `${tag.tag}-notes.txt` })}</button>
      {:else}
        <button disabled>{t('Download the template')}</button>
        <button disabled>{t('Notes for translators')}</button>
      {/if}
    </div>
  </section>

  <section aria-labelledby="devpack-step2">
    <h3 id="devpack-step2">{t('2. Check your file')}</h3>
    <label class="field">{t('Choose your file (or drop it on the button)')}
      <input type="file" accept=".json,application/json" bind:this={fileInput} onchange={(e) => void choose(e.currentTarget.files?.[0])} data-testid="devpack-file" />
    </label>

    {#if outcome && 'refused' in outcome}
      <p class="notice bad" role="alert" data-testid="devpack-refused">{refusalWords(outcome.refused)}</p>
    {:else if outcome && 'checked' in outcome && chosen}
      {@const c = outcome.checked}
      {@const lang = outcome.tag.tag}
      {@render summary(c, chosen.name)}
      {#if !c.canonical}<p class="notice warn" data-testid="devpack-not-canonical">{t('Not in the repository\'s exact form: "Download for a pull request" fixes that.')}</p>{/if}
      <details bind:open={openBroken} data-testid="devpack-broken">
        <summary>{t('Breaks a rule, shown in English ({n})', { n: num(c.brokenTexts) })}</summary>
        {#if openBroken}
          <ul class="entries">
            {#each c.broken.slice(0, LIST_MAX) as b, i (i)}{@render entry(b.ctx, b.english, b.translation, lang, brokenWords(b))}{/each}
          </ul>
          {@render more(c.broken.length)}
        {/if}
      </details>
      <details bind:open={openMissing} data-testid="devpack-missing">
        <summary>{t('Not translated ({n})', { n: num(c.missing.length) })}</summary>
        {#if openMissing}
          <ul class="entries">
            {#each c.missing.slice(0, LIST_MAX) as m, i (i)}{@render entry(m.ctx, m.english, undefined, lang, '')}{/each}
          </ul>
          {@render more(c.missing.length)}
        {/if}
      </details>
      <details bind:open={openLeft} data-testid="devpack-left">
        <summary>{t('Left over ({n})', { n: num(c.leftovers.length) })}</summary>
        {#if openLeft}
          <ul class="entries">
            {#each c.leftovers.slice(0, LIST_MAX) as l, i (i)}{@render entry(l.ctx, l.english, undefined, lang, leftoverWords(l))}{/each}
          </ul>
          {@render more(c.leftovers.length)}
        {/if}
      </details>
      <details bind:open={openWorth} data-testid="devpack-worth">
        <summary>{t('Worth a look ({n})', { n: num(c.worth.length) })}</summary>
        {#if openWorth}
          <ul class="entries">
            {#each c.worth.slice(0, LIST_MAX) as w, i (i)}{@render entry(w.ctx, w.english, undefined, lang, worthWords(w))}{/each}
          </ul>
          {@render more(c.worth.length)}
        {/if}
      </details>
      <details data-testid="devpack-coverage">
        <summary>{t('Coverage per context, lowest first')}</summary>
        <ul class="coverage">
          {#each c.coverage as row (row.ctx)}
            <li><span class="mono small" translate="no">{row.ctx}</span> {t('{done} of {total} ({share})', { done: num(row.translated), total: num(row.total), share: share(row.translated, row.total) })}</li>
          {/each}
        </ul>
      </details>
      <details>
        <summary>{t('Before you send it: what only the check of the pull request can judge')}</summary>
        <ul>
          <li>{t("The language's entry in the manifest, with its owner: add it in the pull request, or ask a maintainer.")}</li>
          <li>{t('A back-translation of each sensitive message you changed (the notes for translators list them).')}</li>
          <li>{t('English that changed after this build, and a newer version of the rules.')}</li>
          <li>{t('The file as committed: an editor or a Git setting can add CRLF line ends or a byte-order mark after the download.')}</li>
          <li>{t('The size of the language as shipped, and the review itself.')}</li>
        </ul>
      </details>

      {#if confirming}
        <div class="confirm" translate="no" lang="en" dir="ltr" role="group" aria-labelledby="devpack-confirm" data-testid="devpack-confirm">
          <h3 id="devpack-confirm" tabindex="-1" bind:this={confirmHeading}>Use this language pack in this browser?</h3>
          <p>
            Every label you see will come from <bdi>{shownName(chosen.name)}</bdi>. A pack can make a button say something different from what it does: use only a file you made or one from someone you
            trust, ideally on a test install.
          </p>
          <p>It stays until you remove it, for 7 days, or until TelltaleDNS is updated. The sign-in page stays in your usual language unless you ask. The page reloads: unsaved changes on it are lost.</p>
          {#if useError === 'storage'}<p class="notice bad" role="alert" data-testid="devpack-use-error">This browser can't keep the pack: its storage is full or blocked.</p>{/if}
          {#if useError === 'server'}<p class="notice bad" role="alert" data-testid="devpack-use-error">TelltaleDNS could not be reached: try again.</p>{/if}
          <div class="row">
            <button class="primary" onclick={use} disabled={busy} data-testid="devpack-confirm-use">Use it and reload</button>
            <button onclick={cancel}>Cancel</button>
          </div>
        </div>
      {:else}
        <div class="row" translate="no" lang="en">
          <button class="primary" onclick={startUse} bind:this={useButton} data-testid="devpack-use">Use this pack…</button>
          <button onclick={() => save(c.pr, `${lang}.json`, 'application/json')} data-testid="devpack-pr">Download for a pull request ({lang}.json)</button>
        </div>
      {/if}
    {/if}
  </section>
</div>

<style>
  .devpack {
    display: grid;
    gap: 14px;
    min-width: 0;
  }
  section {
    display: grid;
    gap: 8px;
    min-width: 0;
  }
  h3 {
    margin: 0;
    font-size: 15px;
  }
  p {
    margin: 0;
  }
  .in-use,
  .confirm {
    display: grid;
    gap: 8px;
    padding: 10px 12px;
    border: 1px solid var(--border);
    border-radius: 8px;
  }
  .confirm {
    border-color: var(--warn);
  }
  .confirm h3:focus-visible {
    outline: 2px solid var(--focus);
  }
  .entries,
  .coverage,
  details ul {
    display: grid;
    gap: 6px;
    margin: 6px 0 0;
    padding: 0;
    list-style: none;
  }
  .entries li {
    display: grid;
    gap: 2px;
    padding: 6px 8px;
    border-radius: 6px;
    background: var(--bg);
    overflow-wrap: anywhere;
    min-width: 0;
  }
  .en {
    color: var(--muted);
  }
  .why {
    font-size: 13px;
  }
  summary {
    cursor: pointer;
  }
  input[type='file'] {
    max-width: 100%;
  }
</style>
