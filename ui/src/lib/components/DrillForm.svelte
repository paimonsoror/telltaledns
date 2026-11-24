<script lang="ts">
  // REQ: CLU-014 (ADR-151) — start a failover drill on a node: how long, whom (everyone, a
  // group, or some devices), why; a preview first (the dry run: every precondition, the devices
  // it would stop answering, what that does to them), then Start when every check passes.
  import { api, type S } from '../api';
  // REQ: API-011 — the form's own words; the preview's sentences come from the API.
  import { t, type MessageKey } from '../i18n';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';

  let {
    node,
    label,
    onclose,
    ondone,
  }: {
    /** `local` or a node ID (what the API takes). */
    node: string;
    label: string;
    onclose: () => void;
    ondone: (r: S['DrillStart']) => void;
  } = $props();

  const presets: [MessageKey, number][] = [
    ['clusterWidgets.drill.preset.15s', 15],
    ['clusterWidgets.drill.preset.30s', 30],
    ['clusterWidgets.drill.preset.1m', 60],
    ['clusterWidgets.drill.preset.2m', 120],
    ['clusterWidgets.drill.preset.5m', 300],
  ];
  let secs = $state(30);
  let who = $state<'all' | 'group' | 'clients'>('clients');
  let group = $state('');
  let clients = $state('');
  let reason = $state('');
  let refused = $state(false);
  let groups = $state<string[]>([]);
  let preview = $state<S['DrillStart'] | null>(null);
  let busy = $state(false);
  let error = $state<unknown>(null);

  $effect(() => {
    api
      .groups()
      .then((g) => (groups = g.items.map((x) => x.name)))
      .catch(() => (groups = []));
  });

  const list = $derived(
    clients
      .split(/[\s,]+/)
      .map((c) => c.trim())
      .filter(Boolean),
  );
  const targets = $derived<S['DrillTargets']>(who === 'all' ? 'all' : who === 'group' ? { group } : { clients: list });
  const valid = $derived(reason.trim().length > 0 && (who === 'all' || (who === 'group' ? !!group : list.length > 0)));
  const ready = $derived(!!preview && preview.checks.every((c) => c.ok));

  // Any change makes the preview stale.
  $effect(() => {
    void [secs, who, group, clients, reason, refused];
    preview = null;
  });

  async function send(dryRun: boolean) {
    busy = true;
    error = null;
    try {
      const r = await api.startDrill(node, { forSecs: secs, targets, reason: reason.trim(), mode: refused ? 'refused' : 'drop' }, dryRun);
      if (dryRun) preview = r;
      else ondone(r);
    } catch (e) {
      error = e;
    } finally {
      busy = false;
    }
  }
</script>

<div class="notice drill-form" role="dialog" aria-label={t('clusterWidgets.drill.aria', { label })} data-testid="drill-form">
  <p>
    <strong>{t('clusterWidgets.drill.title', { label })}</strong> {t('clusterWidgets.drill.body')}<HelpButton id="failover-drill" />
  </p>
  <div class="row presets" role="radiogroup" aria-label={t('clusterWidgets.drill.howLong')}>
    {#each presets as [text, s] (s)}
      <label class="seg-item"><input type="radio" name="drill-for" value={s} bind:group={secs} /> {t(text)}</label>
    {/each}
  </div>
  <div class="row presets" role="radiogroup" aria-label={t('clusterWidgets.drill.whom')}>
    <label class="seg-item"><input type="radio" name="drill-who" value="clients" bind:group={who} /> {t('clusterWidgets.drill.who.clients')}</label>
    <label class="seg-item"><input type="radio" name="drill-who" value="group" bind:group={who} /> {t('queries.quickRule.scopeGroup')}</label>
    <label class="seg-item"><input type="radio" name="drill-who" value="all" bind:group={who} /> {t('clusterWidgets.drill.who.all')}</label>
  </div>
  {#if who === 'clients'}
    <label class="field"
      >{t('clients.tab.devices')} <input bind:value={clients} placeholder="192.168.1.20, laptop" data-testid="drill-clients" />
      <span class="muted small">{t('clusterWidgets.drill.devicesHelp')}</span></label
    >
  {:else if who === 'group'}
    <label class="field"
      >{t('legacy.group')}
      <select bind:value={group} data-testid="drill-group">
        <option value="">{t('clusterWidgets.drill.choose')}</option>
        {#each groups as g (g)}<option value={g}>{g}</option>{/each}
      </select></label
    >
  {/if}
  <label class="field"
    >{t('changes.plan.why')} <input
      bind:value={reason}
      maxlength="200"
      placeholder={t('clusterWidgets.drill.reasonPlaceholder')}
      data-testid="drill-reason"
    /></label
  >
  <label class="check"
    ><input type="checkbox" bind:checked={refused} data-testid="drill-refused" /> {t('clusterWidgets.drill.refused')}</label
  >
  {#if preview}
    <div class="preview" data-testid="drill-preview">
      <p>{preview.preview}</p>
      <ul class="checks">
        {#each preview.checks as c (c.name)}
          <li class:fail={!c.ok}><span aria-hidden="true">{c.ok ? '✓' : '✗'}</span> {c.detail}</li>
        {/each}
      </ul>
      {#if (preview.devices ?? []).length}
        <p class="small muted">
          {t('clusterWidgets.drill.resolved', { resolved: preview.targetsResolved, baseline: preview.baseline })}
          {(preview.devices ?? [])
            .slice(0, 8)
            .map((d) => d.name ?? d.client)
            .join(', ')}{(preview.devices ?? []).length > 8 ? ', …' : ''}
        </p>
      {/if}
    </div>
  {/if}
  <ErrorNote {error} />
  <div class="row">
    {#if !preview}
      <button class="primary" onclick={() => send(true)} disabled={busy || !valid} data-testid="drill-preview-button"
        >{busy ? t('clusterWidgets.drill.checking') : t('qw.chip.preview')}</button
      >
    {:else}
      <button class="primary" onclick={() => send(false)} disabled={busy || !ready} data-testid="drill-start"
        >{busy ? t('clusterWidgets.drill.starting') : t('clusterWidgets.drill.start')}</button
      >
    {/if}
    <button onclick={onclose}>{t('common.cancel')}</button>
  </div>
</div>

<style>
  .drill-form {
    margin: 8px 0;
    max-width: 680px;
  }
  .presets {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    align-items: center;
    margin: 8px 0;
  }
  .seg-item {
    display: inline-flex;
    gap: 4px;
    align-items: center;
  }
  .field {
    display: flex;
    flex-direction: column;
    gap: 4px;
    margin: 8px 0;
    max-width: 420px;
  }
  .check {
    display: flex;
    gap: 6px;
    align-items: baseline;
    margin: 8px 0;
  }
  .preview p {
    margin: 6px 0;
  }
  .checks {
    list-style: none;
    padding: 0;
    margin: 6px 0;
  }
  .checks li.fail {
    color: var(--bad);
  }
  .row {
    display: flex;
    gap: 8px;
  }
</style>
