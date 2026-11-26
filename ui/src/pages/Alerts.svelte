<script lang="ts">
  // REQ: OBS-010 (T9.6) — alerts in the UI: what fires now, how the last deliveries went, and
  // the destinations (with "Send test") and rules, edited like any other configuration.
  import { api, type S } from '../lib/api';
  import { dateTime } from '../lib/format';
  import { poll } from '../lib/poll';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import ConfigEditor, { type Field } from '../lib/components/ConfigEditor.svelte';
  import { tr } from '../lib/i18n';
  import T from '../lib/i18n/T.svelte';
  const { t } = tr('alerts');

  let status = $state<S['AlertsStatus'] | null>(null);
  let destinations = $state<string[]>([]);
  let error = $state<unknown>(null);

  async function load() {
    try {
      const [s, d] = await Promise.all([api.alertsStatus(), api.configEntries('alert_destination')]);
      status = s;
      destinations = d.items.filter((e) => e.source !== 'hidden').map((e) => e.name);
      error = null;
    } catch (e) {
      error = e;
    }
  }
  $effect(() => poll(load, 15_000));

  // The words of the delivery rows are read once, here: the language is fixed for the life of the page.
  const words = { delivered: t('delivered'), failed: t('failed') };
  const kinds = ['email', 'ntfy', 'gotify', 'slack', 'webhook'];
  const destinationFields: Field[] = [
    { key: 'type', label: t('Type'), type: 'select', options: kinds, initial: 'email',
      help: t('email (any provider’s SMTP), ntfy or Gotify (phone push), slack (Slack, Mattermost, Discord), or a JSON webhook.') },
    { key: 'url', label: t('Address'), type: 'text', placeholder: t('smtp://smtp.gmail.com:587 or https://ntfy.sh/my-topic'),
      help: t('Email: smtp://host:587 (STARTTLS) or smtps://host:465. Others: the https:// URL.') },
    { key: 'from', label: t('From (email)'), type: 'text', placeholder: 'you@gmail.com' },
    { key: 'to', label: t('To (email, one per line)'), type: 'lines', placeholder: 'you@gmail.com' },
    { key: 'username', label: t('Account (email)'), type: 'text', placeholder: 'you@gmail.com' },
    // REQ: OBS-010 (ADR-179) — a destination with a credential file is an administrator's, and
    // the file is in a folder meant for secrets.
    { key: 'password_file', label: t('Password file (email)'), type: 'text', placeholder: '/run/secrets/smtp-password',
      help: t('A file on the node holding the password (a Gmail app password, for example). The password itself never goes through the UI. An administrator sets this. Use a file under /run/secrets, /etc/telltale-secrets or the data directory\'s secrets folder.') },
    { key: 'token_file', label: t('Token file (ntfy, Gotify)'), type: 'text', placeholder: '/run/secrets/ntfy-token', advanced: true,
      help: t('A file on the node holding the access token. An administrator sets this. Use a file under /run/secrets, /etc/telltale-secrets or the data directory\'s secrets folder.') },
    { key: 'tls_ca', label: t('Private CA (email)'), type: 'text', placeholder: '/etc/telltale/mail-ca.pem', advanced: true },
  ];
  const conditions = [
    'upstream_down', 'node_down', 'sync_lag', 'list_failing', 'list_stale', 'servfail_rate', 'anomaly', 'new_device',
    'disk_full', 'plan_pending', 'update_available', 'maintenance',
  ];
  const ruleFields = $derived<Field[]>([
    { key: 'when', label: t('When'), type: 'select', options: conditions, initial: 'upstream_down' },
    { key: 'to', label: t('Send to'), type: 'multi', options: destinations },
    { key: 'for_secs', label: t('For at least (seconds)'), type: 'number', placeholder: '60',
      help: t('How long the condition must hold before the alert goes out, so short blips stay quiet.') },
    { key: 'threshold', label: t('Threshold (%)'), type: 'number', placeholder: t('5 (servfail_rate) or 90 (disk_full)'), advanced: true },
    { key: 'enabled', label: t('On'), type: 'bool', initial: true },
  ]);
  const test = {
    label: t('Send test'),
    run: async (name: string) => {
      const r = await api.alertTest(name);
      return r.ok ? { ok: true, text: t('sent. Check that it arrived.') } : { ok: false, text: r.error ?? t('not delivered') };
    },
  };
</script>

{#snippet strong(x: string)}<strong translate="no">{x}</strong>{/snippet}

<div class="page">
  <h1>{t('Alerts')}<HelpButton id="alerts" /></h1>
  <ErrorNote {error} />

  <section class="card" data-testid="alerts-now">
    <h2>{t('Now')}</h2>
    {#if status && !status.evaluating}
      <p class="muted small">{t('Rules are checked on the cluster\'s primary (or a node on its own); there\'s nothing to check here.')}</p>
    {:else if status && status.firing.length === 0}
      <p class="empty">{t('Nothing is firing.')}</p>
    {:else if status}
      <div class="table-wrap">
        <table>
          <thead><tr><th>{t('Rule')}</th><th>{t('About')}</th><th>{t('What')}</th></tr></thead>
          <tbody>
            {#each status.firing as f (f.rule + f.subject)}
              <tr><td><span class="badge bad" translate="no">{f.rule}</span></td><td class="mono small" translate="no">{f.subject}</td><td>{f.summary}</td></tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
    {#each status?.maintenance ?? [] as m (m.node)}
      <!-- REQ: OPS-010 — alerts about a node in maintenance are paused. -->
      <p class="small muted" data-testid="alerts-maintenance">
        <T ctx="alerts" msg={'Alerts for <strong>{node}</strong> are paused during maintenance until {until} ({reason}).'} params={{ node: m.node, until: dateTime(Date.parse(m.until) / 1000), reason: m.reason }} {strong} />
      </p>
    {/each}
    {#if status?.deliveries.length}
      <h3 class="small muted">{t('Last delivery per destination')}</h3>
      <div class="table-wrap">
        <table class="compact">
          <tbody>
            {#each status.deliveries as d (d.destination)}
              <tr>
                <td><strong translate="no">{d.destination}</strong></td>
                <td>{#if d.ok}<span class="badge ok">{words.delivered}</span>{:else}<span class="badge bad">{words.failed}</span>{/if}</td>
                <td class="small muted">{dateTime(d.unixSeconds)}</td>
                <td class="small">{d.error ?? ''}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>

  <ConfigEditor kind="alert_destination" path="alerts/destinations" title={t('Destinations')} noun={t('destination')}
    help="alerts" fields={destinationFields} rowAction={test} onchanged={load}
    summary={(d) => `${String(d.type ?? '')}: ${d.type === 'email' ? ((d.to as string[]) ?? []).join(', ') : String(d.url ?? '')}`} />
  <ConfigEditor kind="alert_rule" path="alerts/rules" title={t('Rules')} noun={t('rule')} help="alerts" fields={ruleFields}
    summary={(d) => `${String(d.when ?? '')} → ${((d.to as string[]) ?? []).join(', ')}${d.enabled === false ? ` ${t('(off)')}` : ''}`} />
</div>
