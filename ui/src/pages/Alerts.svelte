<script lang="ts">
  // REQ: OBS-010 (T9.6) — alerts in the UI: what fires now, how the last deliveries went, and
  // the destinations (with "Send test") and rules, edited like any other configuration.
  import { api, type S } from '../lib/api';
  import { dateTime } from '../lib/format';
  import { poll } from '../lib/poll';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import ConfigEditor, { type Field } from '../lib/components/ConfigEditor.svelte';
  import { t } from '../lib/i18n';

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
  const destinationFields = $derived<Field[]>([
    { key: 'type', label: t('qw.cache.type'), type: 'select', options: kinds, initial: 'email',
      help: t('alerts.dest.typeHelp') },
    { key: 'url', label: t('qw.explain.address'), type: 'text', placeholder: t('alerts.dest.addressPlaceholder'),
      help: t('alerts.dest.addressHelp') },
    { key: 'from', label: t('alerts.dest.from'), type: 'text', placeholder: 'you@gmail.com' },
    { key: 'to', label: t('alerts.dest.to'), type: 'lines', placeholder: 'you@gmail.com' },
    { key: 'username', label: t('alerts.dest.account'), type: 'text', placeholder: 'you@gmail.com' },
    // REQ: OBS-010 (ADR-179) — a destination with a credential file is an administrator's, and
    // the file is in a folder meant for secrets.
    { key: 'password_file', label: t('alerts.dest.passwordFile'), type: 'text', placeholder: '/run/secrets/smtp-password',
      help: t('alerts.dest.passwordFileHelp') },
    { key: 'token_file', label: t('alerts.dest.tokenFile'), type: 'text', placeholder: '/run/secrets/ntfy-token', advanced: true,
      help: t('alerts.dest.tokenFileHelp') },
    { key: 'tls_ca', label: t('alerts.dest.tlsCa'), type: 'text', placeholder: '/etc/telltale/mail-ca.pem', advanced: true },
  ]);
  const conditions = [
    'upstream_down', 'node_down', 'sync_lag', 'list_failing', 'list_stale', 'servfail_rate', 'anomaly', 'new_device',
    'disk_full', 'plan_pending', 'update_available', 'maintenance',
  ];
  const ruleFields = $derived<Field[]>([
    { key: 'when', label: t('alerts.rule.when'), type: 'select', options: conditions, initial: 'upstream_down' },
    { key: 'to', label: t('alerts.rule.sendTo'), type: 'multi', options: destinations },
    { key: 'for_secs', label: t('alerts.rule.forSecs'), type: 'number', placeholder: '60',
      help: t('alerts.rule.forSecsHelp') },
    { key: 'threshold', label: t('alerts.rule.threshold'), type: 'number', placeholder: t('alerts.rule.thresholdPlaceholder'), advanced: true },
    { key: 'enabled', label: t('alerts.rule.on'), type: 'bool', initial: true },
  ]);
  const test = $derived({
    label: t('alerts.dest.sendTest'),
    run: async (name: string) => {
      const r = await api.alertTest(name);
      return r.ok ? { ok: true, text: t('alerts.dest.sent') } : { ok: false, text: r.error ?? t('alerts.dest.notDelivered') };
    },
  });
</script>

<div class="page">
  <h1>{t('nav.alerts')}<HelpButton id="alerts" /></h1>
  <ErrorNote {error} />

  <section class="card" data-testid="alerts-now">
    <h2>{t('alerts.now.title')}</h2>
    {#if status && !status.evaluating}
      <p class="muted small">{t('alerts.now.elsewhere')}</p>
    {:else if status && status.firing.length === 0}
      <p class="empty">{t('alerts.now.empty')}</p>
    {:else if status}
      <div class="table-wrap">
        <table>
          <thead><tr><th>{t('rules.col.rule')}</th><th>{t('alerts.now.about')}</th><th>{t('dashboard.what')}</th></tr></thead>
          <tbody>
            {#each status.firing as f (f.rule + f.subject)}
              <tr><td><span class="badge bad">{f.rule}</span></td><td class="mono small">{f.subject}</td><td>{f.summary}</td></tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
    {#each status?.maintenance ?? [] as m (m.node)}
      <!-- REQ: OPS-010 — alerts about a node in maintenance are paused. -->
      <p class="small muted" data-testid="alerts-maintenance">
        {t('alerts.maintenance.lead')} <strong>{m.node}</strong> {t('alerts.maintenance.rest', { when: dateTime(Date.parse(m.until) / 1000), reason: m.reason })}
      </p>
    {/each}
    {#if status?.deliveries.length}
      <h3 class="small muted">{t('alerts.deliveries.title')}</h3>
      <div class="table-wrap">
        <table class="compact">
          <tbody>
            {#each status.deliveries as d (d.destination)}
              <tr>
                <td><strong>{d.destination}</strong></td>
                <td>{#if d.ok}<span class="badge ok">{t('alerts.deliveries.delivered')}</span>{:else}<span class="badge bad">{t('changes.state.failed')}</span>{/if}</td>
                <td class="small muted">{dateTime(d.unixSeconds)}</td>
                <td class="small">{d.error ?? ''}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>

  <ConfigEditor kind="alert_destination" path="alerts/destinations" title={t('alerts.dest.title')} noun={t('alerts.dest.noun')}
    help="alerts" fields={destinationFields} rowAction={test} onchanged={load}
    summary={(d) => `${String(d.type ?? '')}: ${d.type === 'email' ? ((d.to as string[]) ?? []).join(', ') : String(d.url ?? '')}`} />
  <ConfigEditor kind="alert_rule" path="alerts/rules" title={t('alerts.rule.title')} noun={t('alerts.rule.noun')} help="alerts" fields={ruleFields}
    summary={(d) => `${String(d.when ?? '')} → ${((d.to as string[]) ?? []).join(', ')}${d.enabled === false ? t('alerts.rule.summaryOff') : ''}`} />
</div>
