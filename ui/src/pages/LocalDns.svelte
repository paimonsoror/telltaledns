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
  type Editor = { title: string; name: string; rtype: string; value: string; existing: S['RecordInput'][]; wizard: boolean; step: number; domain: string; label: string };
  let ed = $state<Editor | null>(null);
  let busy = $state(false);
  let formError = $state('');
  let done = $state('');

  function openAdd() {
    ed = { title: 'Add a name', name: '', rtype: 'A', value: '', existing: [], wizard: false, step: 1, domain: '', label: '' };
    formError = done = '';
  }
  function openEdit(n: S['LocalName']) {
    const r = n.records[0];
    ed = { title: `Edit ${n.name}`, name: n.name, rtype: r?.type ?? 'A', value: r?.value ?? '', existing: n.records.slice(1), wizard: false, step: 1, domain: '', label: '' };
    formError = done = '';
  }
  function openWizard() {
    ed = { title: 'Set up my home domain', name: '', rtype: 'A', value: '', existing: [], wizard: true, step: 1, domain: 'home.arpa', label: '' };
    formError = done = '';
  }

  const fullName = $derived(ed ? (ed.wizard ? `${ed.label.trim().toLowerCase()}.${ed.domain.trim().toLowerCase()}` : ed.name.trim().toLowerCase()) : '');
  const sentence = $derived.by(() => {
    if (!ed) return '';
    const v = ed.value.trim() || '…';
    const what: Record<string, string> = {
      A: `the address ${v}`,
      AAAA: `the IPv6 address ${v}`,
      CNAME: `the same answer as ${v}`,
      PTR: `the name ${v} (a reverse lookup)`,
      TXT: `the text “${v}”`,
      MX: `mail server ${v}`,
      SRV: `service ${v}`,
    };
    return `Every device that asks for ${fullName || '…'} gets ${what[ed.rtype] ?? v}, answered by TelltaleDNS itself${ed.rtype === 'A' || ed.rtype === 'AAAA' ? ', and a reverse lookup of the address finds the name' : ''}.`;
  });

  async function saveName(ev: SubmitEvent) {
    ev.preventDefault();
    if (!ed) return;
    if (!fullName || fullName.startsWith('.') || fullName.endsWith('.')) {
      formError = 'Give the name, like nas.home.arpa.';
      return;
    }
    busy = true;
    formError = '';
    try {
      const records = [{ type: ed.rtype, value: ed.value.trim() }, ...ed.existing];
      await api.putRecords(fullName, { records });
      done = `Saved. ${fullName} now answers on every device.`;
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
  let fw = $state<{ domain: string; servers: string } | null>(null);
  const fwSentence = $derived(
    fw ? `Every name under ${fw.domain.trim() || '…'} is asked of ${fw.servers.trim() || '…'} instead of the public DNS servers; your local names still answer first.` : '',
  );
  async function saveForward(ev: SubmitEvent) {
    ev.preventDefault();
    if (!fw) return;
    busy = true;
    formError = '';
    try {
      const servers = fw.servers.split(/[\s,]+/).filter(Boolean);
      await api.putForward(fw.domain.trim().toLowerCase(), { servers });
      done = `Saved. Names under ${fw.domain.trim()} now go to ${servers.join(', ')}.`;
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
    <h1>Names on my network<HelpButton id="local-dns" /></h1>
    <span class="muted small">Local DNS</span>
  </div>
  <ErrorNote {error} />

  {#if canEdit}
    <div class="row actions">
      <button class="primary" onclick={openWizard}>Set up my home domain</button>
      <button onclick={openAdd}>Add a name</button>
      <button onclick={() => ((fw = { domain: '', servers: '' }), (formError = done = ''))}>Send a domain to another server</button>
    </div>
  {/if}

  {#if groups.length === 0}
    <section class="card">
      <p class="empty">
        No local names yet. “Set up my home domain” gives your NAS, printer, or server a name like
        <code>nas.home.arpa</code> that every device can use.
      </p>
    </section>
  {/if}
  {#each groups as [domain, list] (domain)}
    <section class="card">
      <h2>{domain}</h2>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Name</th><th>Answers with</th>{#if advanced}<th>TTL</th>{/if}<th>Defined in</th><th></th></tr></thead>
          <tbody>
            {#each list as n (n.name)}
              <tr>
                <td class="mono">{n.name}</td>
                <td>
                  {#each n.records as r, i (i)}
                    <div><span class="badge">{r.type}</span> <span class="mono">{r.value}</span></div>
                  {/each}
                </td>
                {#if advanced}<td class="small">{n.records.map((r) => r.ttl ?? 'default').join(', ')}</td>{/if}
                <td class="small">{n.source === 'api' ? 'the UI / API' : 'config file'}</td>
                <td class="num nowrap">
                  <a class="small" href={href('/explain', { name: n.name, client: '127.0.0.1' })}>Test</a>
                  {#if n.source === 'api' && canEdit}
                    <button class="link small" onclick={() => openEdit(n)}>Edit</button>
                    <button class="link small" onclick={() => removeName(n.name)} aria-label={`Remove ${n.name}`}>Remove</button>
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
      <h2>Zones</h2>
      <p class="muted small">
        TelltaleDNS answers everything under these domains itself, from the configuration files (<code>[[zone]]</code>):
        names it doesn't have get “no such name”. A zone limited to groups is seen only by their devices.
      </p>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Zone</th><th class="num">Records</th><th>Seen by</th><th>From</th><th></th></tr></thead>
          <tbody>
            {#each zones as z (z.name)}
              <tr>
                <td class="mono">{z.name}</td>
                <td class="num">{z.records}</td>
                <td class="small">{z.groups.length ? z.groups.join(', ') : 'everyone'}</td>
                <td class="small mono">{z.file ?? 'config file'}</td>
                <td class="num"><a class="small" href={href('/explain', { name: z.name, client: '127.0.0.1' })}>Test</a></td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </section>
  {/if}

  <section class="card">
    <h2>Domains sent to other servers<HelpButton id="routes" /></h2>
    {#if forwards.length === 0}
      <p class="empty">None: every name not on this page is asked of the public DNS servers.</p>
    {:else}
      <div class="table-wrap">
        <table>
          <thead><tr><th>Domain</th><th>Servers</th><th>Defined in</th><th></th></tr></thead>
          <tbody>
            {#each forwards as f (f.domain)}
              <tr>
                <td class="mono">{f.domain}</td>
                <td class="mono small">{f.servers.join(', ')}</td>
                <td class="small">{f.source === 'api' ? 'the UI / API' : 'config file'}</td>
                <td class="num">
                  {#if f.source === 'api' && canEdit}
                    <button class="link small" onclick={() => removeForward(f.domain)} aria-label={`Stop sending ${f.domain}`}>Remove</button>
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
          Pick the domain your devices' names end with. <b>home.arpa</b> is reserved for exactly this
          (RFC 8375), so it never clashes with the internet; use a domain you own if you have one.
        </p>
        <label>Home domain <input name="home-domain" bind:value={ed.domain} required /></label>
        <div class="row">
          <button type="button" class="primary" onclick={() => ed && (ed.step = 2)} disabled={!ed.domain.trim()}>Next</button>
        </div>
      {:else}
        {#if ed.wizard}
          <p>Now your first device. You can add more with “Add a name”.</p>
          <label>Device name <input name="label" bind:value={ed.label} placeholder="nas" required /></label>
          <p class="muted small">Its full name will be <code>{fullName}</code>.</p>
        {:else}
          <label>Name <input name="name" bind:value={ed.name} placeholder="nas.home.arpa" required readonly={ed.title.startsWith('Edit')} /></label>
        {/if}
        <label>
          Type
          <select name="type" bind:value={ed.rtype}>
            {#each types as t (t)}<option value={t}>{t === 'A' ? 'A (IPv4 address)' : t === 'AAAA' ? 'AAAA (IPv6 address)' : t === 'CNAME' ? 'CNAME (alias of another name)' : t}</option>{/each}
          </select>
        </label>
        <label>
          {ed.rtype === 'A' || ed.rtype === 'AAAA' ? 'Address' : 'Value'}
          <input name="value" bind:value={ed.value} placeholder={ed.rtype === 'A' ? '192.168.1.10' : ed.rtype === 'CNAME' ? 'nas.home.arpa' : ''} required />
        </label>
        {#if ed.existing.length}<p class="muted small">Also keeps: {ed.existing.map((r) => `${r.type} ${r.value}`).join(', ')}.</p>{/if}
        {#if fullName && ed.value.trim()}
          <ChangePreview highlight="local" device="Any device" name={fullName} {sentence} />
        {/if}
        {#if formError}<p class="notice bad" role="alert">{formError}</p>{/if}
        {#if done}<p class="notice ok" role="status">{done} <a href={href('/explain', { name: fullName, client: '127.0.0.1' })}>Test it</a></p>{/if}
        <div class="row">
          {#if ed.wizard}<button type="button" onclick={() => ed && (ed.step = 1)}>Back</button>{/if}
          <button type="submit" class="primary" disabled={busy}>{busy ? 'Saving…' : 'Save'}</button>
        </div>
      {/if}
    </form>
  </Drawer>
{/if}

{#if fw}
  <Drawer title="Send a domain to another server" onclose={() => (fw = null)}>
    <form class="stack" onsubmit={saveForward}>
      <p>For names that only another DNS server knows: a work network over VPN, your router's own names, another lab.</p>
      <label>Domain <input name="domain" bind:value={fw.domain} placeholder="corp.example" required /></label>
      <label>Server address <input name="servers" bind:value={fw.servers} placeholder="10.0.0.53" required /></label>
      <p class="muted small">Several servers: separate them with spaces (tried in order). Encrypted: <code>tls://10.0.0.53</code>.</p>
      {#if fw.domain.trim() && fw.servers.trim()}
        <ChangePreview highlight="route" device="Any device" name={`anything.${fw.domain.trim()}`} sentence={fwSentence} />
      {/if}
      {#if formError}<p class="notice bad" role="alert">{formError}</p>{/if}
      {#if done}<p class="notice ok" role="status">{done}</p>{/if}
      <div class="row"><button type="submit" class="primary" disabled={busy}>{busy ? 'Saving…' : 'Save'}</button></div>
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
