<script lang="ts">
  // REQ: API-011, DNS-010, UPS-007 (T3.12) — "Names on my network": the names TelltaleDNS answers
  // itself, grouped by domain (a zone-lite view: SOA/NS are generated, never asked for), plus the
  // domains sent to other servers. A wizard sets up a home domain; another sends a domain
  // elsewhere. Every change is previewed (sentence + diagram) and can be tested with Explain.
  import { api, ApiError, type S } from '../lib/api';
  import { href } from '../lib/router.svelte';
  import { session } from '../lib/session.svelte';
  import { currentMode } from '../lib/mode.svelte';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import ChangePreview from '../lib/components/ChangePreview.svelte';
  import Drawer from '../lib/components/Drawer.svelte';
  import { t } from '../lib/i18n';

  let names = $state<S['LocalName'][]>([]);
  let forwards = $state<S['ForwardInfo'][]>([]);
  // REQ: DNS-018 (T7.22) — zones from the config files (shown since T8.6).
  let zones = $state<S['ZoneInfo'][]>([]);
  let error = $state<unknown>(null);
  const canEdit = $derived(session.user?.role === 'admin' || session.user?.role === 'operator');
  const advanced = $derived(currentMode() === 'advanced');
  const types = $derived(advanced ? ['A', 'AAAA', 'CNAME', 'PTR', 'TXT', 'MX', 'SRV'] : ['A', 'AAAA', 'CNAME']);

  function load() {
    Promise.all([api.localNames(), api.forwards()])
      .then(([n, f]) => {
        names = n.items;
        forwards = f.items;
        error = null;
      })
      .catch((e) => (error = e));
    api
      .zones()
      .then((z) => (zones = z.items))
      .catch(() => (zones = []));
  }
  $effect(load);

  /** Names grouped by their domain (everything after the first label). */
  const groups = $derived.by(() => {
    const m = new Map<string, S['LocalName'][]>();
    for (const n of names) {
      const i = n.name.indexOf('.');
      const d = i < 0 ? n.name : n.name.slice(i + 1);
      m.set(d, [...(m.get(d) ?? []), n]);
    }
    return [...m.entries()].sort(([a], [b]) => a.localeCompare(b));
  });

  // ---- one form for "add a name", "edit", and the home-domain wizard
  // `edit` and `wizard` are what the drawer's title (and a read-only name) are read from, so the
  // title is in the language on screen when the language changes.
  type Editor = { edit: boolean; name: string; rtype: string; value: string; existing: S['RecordInput'][]; wizard: boolean; step: number; domain: string; label: string };
  let ed = $state<Editor | null>(null);
  let busy = $state(false);
  let formError = $state('');
  let done = $state('');

  function openAdd() {
    ed = { edit: false, name: '', rtype: 'A', value: '', existing: [], wizard: false, step: 1, domain: '', label: '' };
    formError = done = '';
  }
  function openEdit(n: S['LocalName']) {
    const r = n.records[0];
    ed = { edit: true, name: n.name, rtype: r?.type ?? 'A', value: r?.value ?? '', existing: n.records.slice(1), wizard: false, step: 1, domain: '', label: '' };
    formError = done = '';
  }
  function openWizard() {
    ed = { edit: false, name: '', rtype: 'A', value: '', existing: [], wizard: true, step: 1, domain: 'home.arpa', label: '' };
    formError = done = '';
  }

  const fullName = $derived(ed ? (ed.wizard ? `${ed.label.trim().toLowerCase()}.${ed.domain.trim().toLowerCase()}` : ed.name.trim().toLowerCase()) : '');
  const sentence = $derived.by(() => {
    if (!ed) return '';
    const v = ed.value.trim() || '…';
    const what: Record<string, string> = {
      A: t('localdns.preview.a', { value: v }),
      AAAA: t('localdns.preview.aaaa', { value: v }),
      CNAME: t('localdns.preview.cname', { value: v }),
      PTR: t('localdns.preview.ptr', { value: v }),
      TXT: t('localdns.preview.txt', { value: v }),
      MX: t('localdns.preview.mx', { value: v }),
      SRV: t('localdns.preview.srv', { value: v }),
    };
    return t(
      ed.rtype === 'A' || ed.rtype === 'AAAA' ? 'localdns.preview.sentenceReverse' : 'localdns.preview.sentence',
      { name: fullName || '…', what: what[ed.rtype] ?? v },
    );
  });

  async function saveName(ev: SubmitEvent) {
    ev.preventDefault();
    if (!ed) return;
    if (!fullName || fullName.startsWith('.') || fullName.endsWith('.')) {
      formError = t('localdns.form.needName');
      return;
    }
    busy = true;
    formError = '';
    try {
      const records = [{ type: ed.rtype, value: ed.value.trim() }, ...ed.existing];
      await api.putRecords(fullName, { records });
      done = t('localdns.form.saved', { name: fullName });
      load();
    } catch (e) {
      formError = e instanceof ApiError && e.hint ? `${e.message} ${e.hint}` : e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  async function removeName(n: string) {
    try {
      await api.deleteRecords(n);
      load();
    } catch (e) {
      error = e;
    }
  }

  // ---- "Send a domain to another server"
  // REQ: DNS-022 — `stub`: the servers are the domain's own (authoritative only); their
  // hand-offs to other servers for sub-domains are followed.
  let fw = $state<{ domain: string; servers: string; stub: boolean } | null>(null);
  const fwSentence = $derived(
    fw
      ? t(fw.stub ? 'localdns.forward.sentenceStub' : 'localdns.forward.sentence', {
          domain: fw.domain.trim() || '…',
          servers: fw.servers.trim() || '…',
        })
      : '',
  );
  async function saveForward(ev: SubmitEvent) {
    ev.preventDefault();
    if (!fw) return;
    busy = true;
    formError = '';
    try {
      const servers = fw.servers.split(/[\s,]+/).filter(Boolean);
      await api.putForward(fw.domain.trim().toLowerCase(), { servers, stub: fw.stub });
      done = t('localdns.forward.saved', { domain: fw.domain.trim(), servers: servers.join(', ') });
      load();
    } catch (e) {
      formError = e instanceof ApiError && e.hint ? `${e.message} ${e.hint}` : e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }
  async function removeForward(d: string) {
    try {
      await api.deleteForward(d);
      load();
    } catch (e) {
      error = e;
    }
  }
</script>

<div class="page">
  <div class="page-head">
    <h1>{t('nav.localDns')}<HelpButton id="local-dns" /></h1>
    <span class="muted small">{t('localdns.subtitle')}</span>
  </div>
  <ErrorNote {error} />

  {#if canEdit}
    <div class="row actions">
      <button class="primary" onclick={openWizard}>{t('localdns.setUpHomeDomain')}</button>
      <button onclick={openAdd}>{t('localdns.addName')}</button>
      <button onclick={() => ((fw = { domain: '', servers: '', stub: false }), (formError = done = ''))}>{t('localdns.sendDomain')}</button>
    </div>
  {/if}

  {#if groups.length === 0}
    <section class="card">
      <p class="empty">
        {t('localdns.emptyStart')}<code>nas.home.arpa</code>{t('localdns.emptyEnd')}
      </p>
    </section>
  {/if}
  {#each groups as [domain, list] (domain)}
    <section class="card">
      <h2>{domain}</h2>
      <div class="table-wrap">
        <table>
          <thead><tr><th>{t('clients.col.name')}</th><th>{t('localdns.col.answers')}</th>{#if advanced}<th>{t('localdns.col.ttl')}</th>{/if}<th>{t('clients.col.definedIn')}</th><th></th></tr></thead>
          <tbody>
            {#each list as n (n.name)}
              <tr>
                <td class="mono">{n.name}</td>
                <td>
                  {#each n.records as r, i (i)}
                    <div><span class="badge">{r.type}</span> <span class="mono">{r.value}</span></div>
                  {/each}
                </td>
                {#if advanced}<td class="small">{n.records.map((r) => r.ttl ?? t('localdns.ttlDefault')).join(', ')}</td>{/if}
                <td class="small">{n.source === 'api' ? t('localdns.source.ui') : t('rules.source.file')}</td>
                <td class="num nowrap">
                  <a class="small" href={href('/explain', { name: n.name, client: '127.0.0.1' })}>{t('localdns.test')}</a>
                  {#if n.source === 'api' && canEdit}
                    <button class="link small" onclick={() => openEdit(n)}>{t('rules.edit')}</button>
                    <button class="link small" onclick={() => removeName(n.name)} aria-label={t('localdns.removeName', { name: n.name })}>{t('rules.remove')}</button>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </section>
  {/each}

  {#if zones.length}
    <section class="card" data-testid="zones">
      <h2>{t('localdns.zones.title')}</h2>
      <p class="muted small">
        {t('localdns.zones.introStart')}<code>[[zone]]</code>{t('localdns.zones.introEnd')}
      </p>
      <div class="table-wrap">
        <table>
          <thead><tr><th>{t('localdns.zones.col.zone')}</th><th class="num">{t('localdns.zones.col.records')}</th><th>{t('localdns.zones.col.seenBy')}</th><th>{t('clients.col.from')}</th><th></th></tr></thead>
          <tbody>
            {#each zones as z (z.name)}
              <tr>
                <td class="mono">{z.name}</td>
                <td class="num">{z.records}</td>
                <td class="small">{z.groups.length ? z.groups.join(', ') : t('rules.everyone')}</td>
                <td class="small mono">{z.file ?? t('rules.source.file')}</td>
                <td class="num"><a class="small" href={href('/explain', { name: z.name, client: '127.0.0.1' })}>{t('localdns.test')}</a></td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </section>
  {/if}

  <section class="card">
    <h2>{t('localdns.forwards.title')}<HelpButton id="routes" /></h2>
    {#if forwards.length === 0}
      <p class="empty">{t('localdns.forwards.empty')}</p>
    {:else}
      <div class="table-wrap">
        <table>
          <thead><tr><th>{t('localdns.forward.domain')}</th><th>{t('clients.col.servers')}</th><th>{t('clients.col.definedIn')}</th><th></th></tr></thead>
          <tbody>
            {#each forwards as f (f.domain)}
              <tr>
                <td class="mono">{f.domain}</td>
                <td class="mono small">{f.servers.join(', ')}{#if f.stub}<span class="muted"> {t('localdns.forwards.stub')}</span>{/if}</td>
                <td class="small">{f.source === 'api' ? t('localdns.source.ui') : t('rules.source.file')}</td>
                <td class="num">
                  {#if f.source === 'api' && canEdit}
                    <button class="link small" onclick={() => removeForward(f.domain)} aria-label={t('localdns.forwards.remove', { domain: f.domain })}>{t('rules.remove')}</button>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>
</div>

{#if ed}
  <Drawer title={ed.wizard ? t('localdns.setUpHomeDomain') : ed.edit ? t('localdns.editName', { name: ed.name }) : t('localdns.addName')} onclose={() => (ed = null)}>
    <form class="stack" onsubmit={saveName}>
      {#if ed.wizard && ed.step === 1}
        <p>
          {t('localdns.wizard.introStart')}<b>home.arpa</b>{t('localdns.wizard.introEnd')}
        </p>
        <label>{t('localdns.wizard.homeDomain')} <input name="home-domain" bind:value={ed.domain} required /></label>
        <div class="row">
          <button type="button" class="primary" onclick={() => ed && (ed.step = 2)} disabled={!ed.domain.trim()}>{t('localdns.wizard.next')}</button>
        </div>
      {:else}
        {#if ed.wizard}
          <p>{t('localdns.wizard.firstDevice')}</p>
          <label>{t('localdns.wizard.deviceName')} <input name="label" bind:value={ed.label} placeholder="nas" required /></label>
          <p class="muted small">{t('localdns.wizard.fullNameStart')}<code>{fullName}</code>{t('queries.whyEnd')}</p>
        {:else}
          <label>{t('clients.col.name')} <input name="name" bind:value={ed.name} placeholder="nas.home.arpa" required readonly={ed.edit} /></label>
        {/if}
        <label>
          {t('qw.cache.type')}
          <select name="type" bind:value={ed.rtype}>
            {#each types as rt (rt)}<option value={rt}>{rt === 'A' ? t('localdns.form.typeA') : rt === 'AAAA' ? t('localdns.form.typeAAAA') : rt === 'CNAME' ? t('localdns.form.typeCNAME') : rt}</option>{/each}
          </select>
        </label>
        <label>
          {ed.rtype === 'A' || ed.rtype === 'AAAA' ? t('qw.explain.address') : t('localdns.form.value')}
          <input name="value" bind:value={ed.value} placeholder={ed.rtype === 'A' ? '192.168.1.10' : ed.rtype === 'CNAME' ? 'nas.home.arpa' : ''} required />
        </label>
        {#if ed.existing.length}<p class="muted small">{t('localdns.form.alsoKeeps', { records: ed.existing.map((r) => `${r.type} ${r.value}`).join(', ') })}</p>{/if}
        {#if fullName && ed.value.trim()}
          <ChangePreview highlight="local" device={t('localdns.preview.anyDevice')} name={fullName} {sentence} />
        {/if}
        {#if formError}<p class="notice bad" role="alert">{formError}</p>{/if}
        {#if done}<p class="notice ok" role="status">{done} <a href={href('/explain', { name: fullName, client: '127.0.0.1' })}>{t('lists.test.label')}</a></p>{/if}
        <div class="row">
          {#if ed.wizard}<button type="button" onclick={() => ed && (ed.step = 1)}>{t('localdns.form.back')}</button>{/if}
          <button type="submit" class="primary" disabled={busy}>{busy ? t('localdns.form.saving') : t('common.save')}</button>
        </div>
      {/if}
    </form>
  </Drawer>
{/if}

{#if fw}
  <Drawer title={t('localdns.sendDomain')} onclose={() => (fw = null)}>
    <form class="stack" onsubmit={saveForward}>
      <p>{t('localdns.forward.intro')}</p>
      <label>{t('localdns.forward.domain')} <input name="domain" bind:value={fw.domain} placeholder="corp.example" required /></label>
      <label>{t('localdns.forward.servers')} <input name="servers" bind:value={fw.servers} placeholder="10.0.0.53" required /></label>
      <p class="muted small">{t('localdns.forward.serversHintStart')}<code>tls://10.0.0.53</code>{t('queries.whyEnd')}</p>
      <label
        ><input type="checkbox" name="stub" bind:checked={fw.stub} /> {t('localdns.forward.stubLabel')}</label
      >
      <p class="muted small">
        {t('localdns.forward.stubBefore')}<em>{t('localdns.forward.stubTerm')}</em>{t('localdns.forward.stubAfter')}
      </p>
      {#if fw.domain.trim() && fw.servers.trim()}
        <ChangePreview highlight="route" device={t('localdns.preview.anyDevice')} name={`anything.${fw.domain.trim()}`} sentence={fwSentence} />
      {/if}
      {#if formError}<p class="notice bad" role="alert">{formError}</p>{/if}
      {#if done}<p class="notice ok" role="status">{done}</p>{/if}
      <div class="row"><button type="submit" class="primary" disabled={busy}>{busy ? t('localdns.form.saving') : t('common.save')}</button></div>
    </form>
  </Drawer>
{/if}

<style>
  .actions {
    margin-bottom: 12px;
    flex-wrap: wrap;
    gap: 8px;
  }
  .stack {
    display: grid;
    gap: 12px;
  }
</style>
