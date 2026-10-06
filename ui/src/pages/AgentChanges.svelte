<script lang="ts">
  // REQ: AGT-007 (T7.1) — "Pending agent changes": what AI agents planned through MCP, what
  // each would do (the dry run), why, and who asked. Operators approve or reject plans that
  // wait for them ([agents] require_approval); the agent then applies an approved plan.
  import { api, type S } from '../lib/api';
  import { can } from '../lib/session.svelte';
  import { poll } from '../lib/poll';
  import { ago, duration } from '../lib/format';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';

  let plans = $state<S['Plan'][]>([]);
  let error = $state<unknown>(null);
  let busy = $state('');
  let now = $state(Date.now() / 1000);
  const writable = $derived(can('operator'));

  async function load() {
    try {
      plans = (await api.plans()).items;
      now = Date.now() / 1000;
      error = null;
    } catch (e) {
      error = e;
    }
  }
  $effect(() => poll(load, 5000));

  async function decide(id: string, approve: boolean) {
    busy = id;
    try {
      await (approve ? api.approvePlan(id) : api.rejectPlan(id));
      await load();
    } catch (e) {
      error = e;
    } finally {
      busy = '';
    }
  }

  const pending = $derived(plans.filter((p) => p.state === 'pending'));
  const others = $derived(plans.filter((p) => p.state !== 'pending'));
  const label: Record<string, [string, string]> = {
    pending: ['waiting for approval', 'warn'],
    ready: ['ready to apply', ''],
    approved: ['approved', 'ok'],
    rejected: ['rejected', 'bad'],
    applying: ['applying', ''],
    applied: ['applied', 'ok'],
    stale: ['stale: the config changed', 'bad'],
    failed: ['failed', 'bad'],
    discarded: ['discarded', ''],
    expired: ['expired', ''],
  };
  type Preview = { impact?: string; warnings?: string[]; before?: unknown; after?: unknown };
  const preview = (p: S['Plan']) => (p.preview ?? {}) as Preview;
</script>

<div class="page">
  <div class="page-head">
    <h1>Agent changes<HelpButton id="agent-changes" /></h1>
  </div>
  <p class="muted small">
    AI agents connected over MCP don't change anything directly: they make a plan, shown here with what it would do.
    With <code>[agents] require_approval = true</code>, a plan waits for an operator before the agent can apply it.
    Plans expire after 10 minutes.
  </p>
  <ErrorNote {error} />

  {#snippet card(p: S['Plan'])}
    {@const [text, cls] = label[p.state] ?? [p.state, '']}
    {@const pv = preview(p)}
    <section class="card plan" data-testid="plan" class:waiting={p.state === 'pending'}>
      <div class="head">
        <strong>{p.summary}</strong>
        <span class="badge {cls}">{text}</span>
      </div>
      <dl class="small">
        <dt>Why</dt><dd>{p.reason}</dd>
        <dt>Asked by</dt><dd class="mono">{p.requestedBy}</dd>
        <dt>When</dt>
        <dd>
          {ago(p.createdUnixSeconds)}
          {#if p.state === 'pending' || p.state === 'ready' || p.state === 'approved'}
            · expires in {duration(Math.max(0, p.expiresUnixSeconds - now))}
          {/if}
        </dd>
        {#if p.decidedBy}<dt>Decided by</dt><dd>{p.decidedBy}</dd>{/if}
        <dt>Change</dt><dd class="mono">{p.method} {p.path}</dd>
      </dl>
      {#if pv.impact}<p class="small"><b>What it does:</b> {pv.impact}</p>{/if}
      {#each pv.warnings ?? [] as w (w)}<p class="small warn-text">{w}</p>{/each}
      <details class="small">
        <summary>Before and after</summary>
        <div class="diff">
          <div><div class="muted">Before</div><pre class="mono">{JSON.stringify(pv.before ?? null, null, 2)}</pre></div>
          <div><div class="muted">After</div><pre class="mono">{JSON.stringify(pv.after ?? null, null, 2)}</pre></div>
        </div>
      </details>
      {#if p.state === 'pending' && writable}
        <div class="row">
          <button class="primary" disabled={busy === p.id} onclick={() => decide(p.id, true)}>Approve</button>
          <button disabled={busy === p.id} onclick={() => decide(p.id, false)}>Reject</button>
        </div>
      {/if}
    </section>
  {/snippet}

  <h2>Waiting for approval</h2>
  {#if pending.length === 0}
    <p class="empty">Nothing is waiting.</p>
  {:else}
    {#each pending as p (p.id)}{@render card(p)}{/each}
  {/if}

  {#if others.length}
    <h2>Recent plans</h2>
    {#each others as p (p.id)}{@render card(p)}{/each}
  {/if}
</div>

<style>
  .plan.waiting {
    border-color: var(--warn);
  }
  .head {
    display: flex;
    justify-content: space-between;
    gap: 12px;
    align-items: baseline;
  }
  dl {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 2px 12px;
    margin: 8px 0;
  }
  dt {
    color: var(--muted);
  }
  dd {
    margin: 0;
    overflow-wrap: anywhere;
  }
  .diff {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
    margin-top: 6px;
  }
  .diff pre {
    margin: 4px 0 0;
    padding: 8px;
    background: var(--surface-2);
    border-radius: 6px;
    overflow-x: auto;
    max-height: 260px;
  }
  @media (max-width: 700px) {
    .diff {
      grid-template-columns: 1fr;
    }
  }
  .warn-text {
    color: var(--warn-strong, var(--warn));
  }
  .row {
    display: flex;
    gap: 8px;
    margin-top: 8px;
  }
</style>
