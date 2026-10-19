<script lang="ts">
  // REQ: CLU-014 (ADR-151) — start a failover drill on a node: how long, whom (everyone, a
  // group, or some devices), why; a preview first (the dry run: every precondition, the devices
  // it would stop answering, what that does to them), then Start when every check passes.
  import { api, type S } from '../api';
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

  const presets: [string, number][] = [
    ['15 s', 15],
    ['30 s', 30],
    ['1 min', 60],
    ['2 min', 120],
    ['5 min', 300],
  ];
  let secs = $state(30);
  let who = $state<'all' | 'group' | 'clients'>('clients');
  let group = $state('');
  let clients = $state('');
  let reason = $state('');
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
    void [secs, who, group, clients, reason];
    preview = null;
  });

  async function send(dryRun: boolean) {
    busy = true;
    error = null;
    try {
      const r = await api.startDrill(node, { forSecs: secs, targets, reason: reason.trim() }, dryRun);
      if (dryRun) preview = r;
      else ondone(r);
    } catch (e) {
      error = e;
    } finally {
      busy = false;
    }
  }
</script>

<div class="notice drill-form" role="dialog" aria-label={`Failover drill on ${label}`} data-testid="drill-form">
  <p>
    <strong>Run a failover drill on {label}?</strong> For a short time it stops answering the devices you choose, while the
    other nodes keep serving. Devices with a working second DNS server switch to it; a report then shows who followed and who
    was stuck.<HelpButton id="failover-drill" />
  </p>
  <div class="row presets" role="radiogroup" aria-label="How long">
    {#each presets as [text, s] (s)}
      <label class="seg-item"><input type="radio" name="drill-for" value={s} bind:group={secs} /> {text}</label>
    {/each}
  </div>
  <div class="row presets" role="radiogroup" aria-label="Whom">
    <label class="seg-item"><input type="radio" name="drill-who" value="clients" bind:group={who} /> some devices</label>
    <label class="seg-item"><input type="radio" name="drill-who" value="group" bind:group={who} /> a group</label>
    <label class="seg-item"><input type="radio" name="drill-who" value="all" bind:group={who} /> everyone</label>
  </div>
  {#if who === 'clients'}
    <label class="field"
      >Devices <input bind:value={clients} placeholder="192.168.1.20, laptop" data-testid="drill-clients" />
      <span class="muted small">Addresses, device names, or Kubernetes workloads. Start with your own device.</span></label
    >
  {:else if who === 'group'}
    <label class="field"
      >Group
      <select bind:value={group} data-testid="drill-group">
        <option value="">Choose…</option>
        {#each groups as g (g)}<option value={g}>{g}</option>{/each}
      </select></label
    >
  {/if}
  <label class="field">Why <input bind:value={reason} maxlength="200" placeholder="does the second server work?" data-testid="drill-reason" /></label>
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
          {preview.targetsResolved} of the {preview.baseline} devices that used this node in the last hour:
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
      <button class="primary" onclick={() => send(true)} disabled={busy || !valid} data-testid="drill-preview-button">{busy ? 'Checking…' : 'Preview'}</button>
    {:else}
      <button class="primary" onclick={() => send(false)} disabled={busy || !ready} data-testid="drill-start">{busy ? 'Starting…' : 'Start drill'}</button>
    {/if}
    <button onclick={onclose}>Cancel</button>
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
