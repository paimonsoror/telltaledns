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
  import { own, tr } from '../lib/i18n';
  import { occurrenceKeys } from '../lib/keys';
  import T from '../lib/i18n/T.svelte';
  const { t } = tr('localDns');

  let names = $state<S['LocalName'][]>([]);
  let forwards = $state<S['ForwardInfo'][]>([]);
  // REQ: DNS-018 (T7.22) — zones from the config files (shown since T8.6).
  let zones = $state<S['ZoneInfo'][]>([]);
  let error = $state<unknown>(null);
  const canEdit = $derived(session.user?.role === 'admin' || session.user?.role === 'operator');
  const advanced = $derived(currentMode() === 'advanced');
  const types = $derived(advanced ? ['A', 'AAAA', 'CNAME', 'PTR', 'TXT', 'MX', 'SRV'] : ['A', 'AAAA', 'CNAME']);
  // The words of the rows and the forms are read once, here: language is fixed for the life of the page.
  // A record type comes from the form's own list: read with `Object.hasOwn`, and one without a note shows as it is.
  const typeText: Record<string, string> = { A: t('A (IPv4 address)'), AAAA: t('AAAA (IPv6 address)'), CNAME: t('CNAME (alias of another name)') };
  const words = {
    byUi: t('the UI / API'),
    byFile: t('config file'),
    everyone: t('everyone'),
    ttl: t('default'),
    save: t('Save'),
    saving: t('Saving…'),
    testIt: t('Test it'),
    address: t('Address'),
    value: t('Value'),
    example: t('nas.home.arpa'),
    testName: t('Test'),
    testZone: t('Test'),
    edit: t('Edit'),
    removeName: t('Remove'),
    removeForward: t('Remove'),
  };

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
  type Editor = { title: string; edit: boolean; name: string; rtype: string; value: string; existing: S['RecordInput'][]; wizard: boolean; step: number; domain: string; label: string };
  let ed = $state<Editor | null>(null);
  let busy = $state(false);
  let formError = $state('');
  let done = $state('');

  function openAdd() {
    ed = { title: t('Add a name'), edit: false, name: '', rtype: 'A', value: '', existing: [], wizard: false, step: 1, domain: '', label: '' };
    formError = done = '';
  }
  function openEdit(n: S['LocalName']) {
    const r = n.records[0];
    ed = { title: t('Edit {name}', { name: n.name }), edit: true, name: n.name, rtype: r?.type ?? 'A', value: r?.value ?? '', existing: n.records.slice(1), wizard: false, step: 1, domain: '', label: '' };
    formError = done = '';
  }
  function openWizard() {
    ed = { title: t('Set up my home domain'), edit: false, name: '', rtype: 'A', value: '', existing: [], wizard: true, step: 1, domain: 'home.arpa', label: '' };
    formError = done = '';
  }

  const fullName = $derived(ed ? (ed.wizard ? `${ed.label.trim().toLowerCase()}.${ed.domain.trim().toLowerCase()}` : ed.name.trim().toLowerCase()) : '');
  const sentence = $derived.by(() => {
    if (!ed) return '';
    const v = ed.value.trim() || '…';
    // What the answer is, by the record's type (a type is read with `Object.hasOwn`; one without a phrase shows the value).
    const what: Record<string, () => string> = {
      A: () => t('the address {value}', { value: v }),
      AAAA: () => t('the IPv6 address {value}', { value: v }),
      CNAME: () => t('the same answer as {value}', { value: v }),
      PTR: () => t('the name {value} (a reverse lookup)', { value: v }),
      TXT: () => t('the text “{value}”', { value: v }),
      MX: () => t('mail server {value}', { value: v }),
      SRV: () => t('service {value}', { value: v }),
    };
    const params = { name: fullName || '…', what: own(what, ed.rtype)?.() ?? v };
    return ed.rtype === 'A' || ed.rtype === 'AAAA'
      ? t('Every device that asks for {name} gets {what}, answered by TelltaleDNS itself, and a reverse lookup of the address finds the name.', params)
      : t('Every device that asks for {name} gets {what}, answered by TelltaleDNS itself.', params);
  });

  async function saveName(ev: SubmitEvent) {
    ev.preventDefault();
    if (!ed) return;
    if (!fullName || fullName.startsWith('.') || fullName.endsWith('.')) {
      formError = t('Give the name, like nas.home.arpa.');
      return;
    }
    busy = true;
    formError = '';
    try {
      const records = [{ type: ed.rtype, value: ed.value.trim() }, ...ed.existing];
      await api.putRecords(fullName, { records });
      done = t('Saved. {name} now answers on every device.', { name: fullName });
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
      ? fw.stub
        ? t('Every name under {domain} is looked up starting at {servers}, following any sub-domains they hand to other servers, instead of the public DNS servers; your local names still answer first.', { domain: fw.domain.trim() || '…', servers: fw.servers.trim() || '…' })
        : t('Every name under {domain} is asked of {servers} instead of the public DNS servers; your local names still answer first.', { domain: fw.domain.trim() || '…', servers: fw.servers.trim() || '…' })
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
      done = t('Saved. Names under {domain} now go to {servers}.', { domain: fw.domain.trim(), servers: servers.join(', ') });
      load();
    } catch (e) {
      formError = e instanceof ApiError && e.hint ? `${e.message} ${e.hint}` : e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }
  // REQ: API-005 — a forwarded domain's row stays with its domain (its Remove acts at once), and one routed twice stays two rows.
  const forwardKeys = $derived(occurrenceKeys(forwards.map((f) => f.domain)));
  async function removeForward(d: string) {
    try {
      await api.deleteForward(d);
      load();
    } catch (e) {
      error = e;
    }
  }
</script>

{#snippet code(x: string)}<code translate="no">{x}</code>{/snippet}
{#snippet em(x: string)}<em>{x}</em>{/snippet}
{#snippet nasexample()}<code translate="no">nas.home.arpa</code>{/snippet}
{#snippet zoneentry()}<code translate="no">[[zone]]</code>{/snippet}
{#snippet homearpa()}<b translate="no">home.arpa</b>{/snippet}
{#snippet tlsexample()}<code translate="no">tls://10.0.0.53</code>{/snippet}

<div class="page">
  <div class="page-head">
    <h1>{t('Names on my network')}<HelpButton id="local-dns" /></h1>
    <span class="muted small">{t('Local DNS')}</span>
  </div>
  <ErrorNote {error} />

  {#if canEdit}
    <div class="row actions">
      <button class="primary" onclick={openWizard}>{t('Set up my home domain')}</button>
      <button onclick={openAdd}>{t('Add a name')}</button>
      <button onclick={() => ((fw = { domain: '', servers: '', stub: false }), (formError = done = ''))}>{t('Send a domain to another server')}</button>
    </div>
  {/if}

  {#if groups.length === 0}
    <section class="card">
      <p class="empty">
        <T ctx="localDns" msg={'No local names yet. “Set up my home domain” gives your NAS, printer, or server a name like <nasexample/> that every device can use.'} {nasexample} />
      </p>
    </section>
  {/if}
  {#each groups as [domain, list] (domain)}
    <section class="card">
      <h2 translate="no">{domain}</h2>
      <div class="table-wrap">
        <table>
          <thead><tr><th>{t('Name')}</th><th>{t('Answers with')}</th>{#if advanced}<th>{t('TTL')}</th>{/if}<th>{t('Defined in')}</th><th></th></tr></thead>
          <tbody>
            {#each list as n (n.name)}
              <tr>
                <td class="mono" translate="no">{n.name}</td>
                <td>
                  {#each n.records as r, i (i)}
                    <div><span class="badge" translate="no">{r.type}</span> <span class="mono" translate="no">{r.value}</span></div>
                  {/each}
                </td>
                {#if advanced}<td class="small">{n.records.map((r) => r.ttl ?? words.ttl).join(', ')}</td>{/if}
                <td class="small">{n.source === 'api' ? words.byUi : words.byFile}</td>
                <td class="num nowrap">
                  <a class="small" href={href('/explain', { name: n.name, client: '127.0.0.1' })}>{words.testName}</a>
                  {#if n.source === 'api' && canEdit}
                    <button class="link small" onclick={() => openEdit(n)}>{words.edit}</button>
                    <button class="link small" onclick={() => removeName(n.name)} aria-label={t('Remove {name}', { name: n.name })}>{words.removeName}</button>
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
      <h2>{t('Zones')}</h2>
      <p class="muted small">
        <T ctx="localDns" msg={"TelltaleDNS answers everything under these domains itself, from the configuration files (<zoneentry/>): names it doesn't have get “no such name”. A zone limited to groups is seen only by their devices."} {zoneentry} />
      </p>
      <div class="table-wrap">
        <table>
          <thead><tr><th>{t('Zone')}</th><th class="num">{t('Records')}</th><th>{t('Seen by')}</th><th>{t('From')}</th><th></th></tr></thead>
          <tbody>
            {#each zones as z, i (i)}
              <tr>
                <td class="mono" translate="no">{z.name}</td>
                <td class="num">{z.records}</td>
                <td class="small">{z.groups.length ? z.groups.join(', ') : words.everyone}</td>
                <td class="small mono">{z.file ?? words.byFile}</td>
                <td class="num"><a class="small" href={href('/explain', { name: z.name, client: '127.0.0.1' })}>{words.testZone}</a></td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </section>
  {/if}

  <section class="card">
    <h2>{t('Domains sent to other servers')}<HelpButton id="routes" /></h2>
    {#if forwards.length === 0}
      <p class="empty">{t('None: every name not on this page is asked of the public DNS servers.')}</p>
    {:else}
      <div class="table-wrap">
        <table>
          <thead><tr><th>{t('Domain')}</th><th>{t('Servers')}</th><th>{t('Defined in')}</th><th></th></tr></thead>
          <tbody>
            {#each forwards as f, i (forwardKeys[i])}
              <tr>
                <td class="mono" translate="no">{f.domain}</td>
                <td class="mono small"><span translate="no">{f.servers.join(', ')}</span>{#if f.stub}<span class="muted">{t('(stub zone)')}</span>{/if}</td>
                <td class="small">{f.source === 'api' ? words.byUi : words.byFile}</td>
                <td class="num">
                  {#if f.source === 'api' && canEdit}
                    <button class="link small" onclick={() => removeForward(f.domain)} aria-label={t('Stop sending {domain}', { domain: f.domain })}>{words.removeForward}</button>
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
  <Drawer title={ed.title} onclose={() => (ed = null)}>
    <form class="stack" onsubmit={saveName}>
      {#if ed.wizard && ed.step === 1}
        <p>
          <T ctx="localDns" msg={"Pick the domain your devices' names end with. <homearpa/> is reserved for exactly this (RFC 8375), so it never clashes with the internet; use a domain you own if you have one."} {homearpa} />
        </p>
        <label>{t('Home domain')} <input name="home-domain" bind:value={ed.domain} required /></label>
        <div class="row">
          <button type="button" class="primary" onclick={() => ed && (ed.step = 2)} disabled={!ed.domain.trim()}>{t('Next')}</button>
        </div>
      {:else}
        {#if ed.wizard}
          <p>{t('Now your first device. You can add more with “Add a name”.')}</p>
          <label>{t('Device name')} <input name="label" bind:value={ed.label} placeholder={t('nas')} required /></label>
          <p class="muted small"><T ctx="localDns" msg={'Its full name will be <code>{name}</code>.'} params={{ name: fullName }} {code} /></p>
        {:else}
          <label>{t('Name')} <input name="name" bind:value={ed.name} placeholder={words.example} required readonly={ed.edit} /></label>
        {/if}
        <label>
          {t('Type')}
          <select name="type" bind:value={ed.rtype}>
            {#each types as rt (rt)}<option value={rt} translate={own(typeText, rt) ? undefined : 'no'}>{own(typeText, rt) ?? rt}</option>{/each}
          </select>
        </label>
        <label>
          {ed.rtype === 'A' || ed.rtype === 'AAAA' ? words.address : words.value}
          <input name="value" bind:value={ed.value} placeholder={ed.rtype === 'A' ? '192.168.1.10' : ed.rtype === 'CNAME' ? words.example : ''} required />
        </label>
        {#if ed.existing.length}<p class="muted small">{t('Also keeps: {records}.', { records: ed.existing.map((r) => `${r.type} ${r.value}`).join(', ') })}</p>{/if}
        {#if fullName && ed.value.trim()}
          <ChangePreview highlight="local" device={t('Any device')} name={fullName} {sentence} />
        {/if}
        {#if formError}<p class="notice bad" role="alert">{formError}</p>{/if}
        {#if done}<p class="notice ok" role="status">{done} <a href={href('/explain', { name: fullName, client: '127.0.0.1' })}>{words.testIt}</a></p>{/if}
        <div class="row">
          {#if ed.wizard}<button type="button" onclick={() => ed && (ed.step = 1)}>{t('Back')}</button>{/if}
          <button type="submit" class="primary" disabled={busy}>{busy ? words.saving : words.save}</button>
        </div>
      {/if}
    </form>
  </Drawer>
{/if}

{#if fw}
  <Drawer title={t('Send a domain to another server')} onclose={() => (fw = null)}>
    <form class="stack" onsubmit={saveForward}>
      <p>{t('For names that only another DNS server knows: a work network over VPN, your router\'s own names, another lab.')}</p>
      <label>{t('Domain')} <input name="domain" bind:value={fw.domain} placeholder={t('corp.example')} required /></label>
      <label>{t('Server address')} <input name="servers" bind:value={fw.servers} placeholder="10.0.0.53" required /></label>
      <p class="muted small"><T ctx="localDns" msg={'Several servers: separate them with spaces (tried in order). Encrypted: <tlsexample/>.'} {tlsexample} /></p>
      <label
        ><input type="checkbox" name="stub" bind:checked={fw.stub} /> {t('These servers only know this domain, and hand some sub-domains to other servers')}</label
      >
      <p class="muted small">
        <T ctx="localDns" msg={"A <em>stub zone</em>: the servers are asked directly (by IP address) and their hand-offs are followed, as BIND's stub zones do. Use it when the servers refuse other questions."} {em} />
      </p>
      {#if fw.domain.trim() && fw.servers.trim()}
        <ChangePreview highlight="route" device={t('Any device')} name={`anything.${fw.domain.trim()}`} sentence={fwSentence} />
      {/if}
      {#if formError}<p class="notice bad" role="alert">{formError}</p>{/if}
      {#if done}<p class="notice ok" role="status">{done}</p>{/if}
      <div class="row"><button type="submit" class="primary" disabled={busy}>{busy ? words.saving : words.save}</button></div>
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
