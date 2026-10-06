<script lang="ts">
  // REQ: OBS-010 (T9.6) — alerts in the UI: what fires now, how the last deliveries went, and
  // the destinations (with "Send test") and rules, edited like any other configuration.
  import { api, type S } from '../lib/api';
  import { dateTime } from '../lib/format';
  import { poll } from '../lib/poll';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import ConfigEditor, { type Field } from '../lib/components/ConfigEditor.svelte';

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

  const kinds = ['email', 'ntfy', 'gotify', 'slack', 'webhook'];
  const destinationFields: Field[] = [
    { key: 'type', label: 'Type', type: 'select', options: kinds, initial: 'email',
      help: 'email (any provider’s SMTP), ntfy or Gotify (phone push), slack (Slack, Mattermost, Discord), or a JSON webhook.' },
    { key: 'url', label: 'Address', type: 'text', placeholder: 'smtp://smtp.gmail.com:587 or https://ntfy.sh/my-topic',
      help: 'Email: smtp://host:587 (STARTTLS) or smtps://host:465. Others: the https:// URL.' },
    { key: 'from', label: 'From (email)', type: 'text', placeholder: 'you@gmail.com' },
    { key: 'to', label: 'To (email, one per line)', type: 'lines', placeholder: 'you@gmail.com' },
    { key: 'username', label: 'Account (email)', type: 'text', placeholder: 'you@gmail.com' },
    { key: 'password_file', label: 'Password file (email)', type: 'text', placeholder: '/run/secrets/smtp-password',
      help: 'A file on the node holding the password (a Gmail app password, for example). The password itself never goes through the UI.' },
    { key: 'token_file', label: 'Token file (ntfy, Gotify)', type: 'text', placeholder: '/run/secrets/ntfy-token', advanced: true },
    { key: 'tls_ca', label: 'Private CA (email)', type: 'text', placeholder: '/etc/telltale/mail-ca.pem', advanced: true },
  ];
  const conditions = [
    'upstream_down', 'node_down', 'sync_lag', 'list_failing', 'servfail_rate', 'anomaly', 'new_device',
    'disk_full', 'plan_pending', 'update_available',
  ];
  const ruleFields = $derived<Field[]>([
    { key: 'when', label: 'When', type: 'select', options: conditions, initial: 'upstream_down' },
    { key: 'to', label: 'Send to', type: 'multi', options: destinations },
    { key: 'for_secs', label: 'For at least (seconds)', type: 'number', placeholder: '60',
      help: 'How long the condition must hold before the alert goes out, so short blips stay quiet.' },
    { key: 'threshold', label: 'Threshold (%)', type: 'number', placeholder: '5 (servfail_rate) or 90 (disk_full)', advanced: true },
    { key: 'enabled', label: 'On', type: 'bool', initial: true },
  ]);
  const test = {
    label: 'Send test',
    run: async (name: string) => {
      const r = await api.alertTest(name);
      return r.ok ? { ok: true, text: 'sent. Check that it arrived.' } : { ok: false, text: r.error ?? 'not delivered' };
    },
  };
</script>

<div class="page">
  <h1>Alerts<HelpButton id="alerts" /></h1>
  <ErrorNote {error} />

  <section class="card" data-testid="alerts-now">
    <h2>Now</h2>
    {#if status && !status.evaluating}
      <p class="muted small">Rules are checked on the cluster's primary (or a node on its own); there's nothing to check here.</p>
    {:else if status && status.firing.length === 0}
      <p class="empty">Nothing is firing.</p>
    {:else if status}
      <div class="table-wrap">
        <table>
          <thead><tr><th>Rule</th><th>About</th><th>What</th></tr></thead>
          <tbody>
            {#each status.firing as f (f.rule + f.subject)}
              <tr><td><span class="badge bad">{f.rule}</span></td><td class="mono small">{f.subject}</td><td>{f.summary}</td></tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
    {#if status?.deliveries.length}
      <h3 class="small muted">Last delivery per destination</h3>
      <div class="table-wrap">
        <table class="compact">
          <tbody>
            {#each status.deliveries as d (d.destination)}
              <tr>
                <td><strong>{d.destination}</strong></td>
                <td>{#if d.ok}<span class="badge ok">delivered</span>{:else}<span class="badge bad">failed</span>{/if}</td>
                <td class="small muted">{dateTime(d.unixSeconds)}</td>
                <td class="small">{d.error ?? ''}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>

  <ConfigEditor kind="alert_destination" path="alerts/destinations" title="Destinations" noun="destination"
    help="alerts" fields={destinationFields} rowAction={test} onchanged={load}
    summary={(d) => `${String(d.type ?? '')}: ${d.type === 'email' ? ((d.to as string[]) ?? []).join(', ') : String(d.url ?? '')}`} />
  <ConfigEditor kind="alert_rule" path="alerts/rules" title="Rules" noun="rule" help="alerts" fields={ruleFields}
    summary={(d) => `${String(d.when ?? '')} → ${((d.to as string[]) ?? []).join(', ')}${d.enabled === false ? ' (off)' : ''}`} />
</div>
