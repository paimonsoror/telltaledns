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
  import SimulationCard from '../lib/components/SimulationCard.svelte';
  import { tr, own } from '../lib/i18n';
  import T from '../lib/i18n/T.svelte';
  const { t } = tr('agentChanges');

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

  // The words of a plan's card are read once, here (a card is drawn for every plan, every 5 s).
  const words = {
    why: t('Why'), askedBy: t('Asked by'), when: t('When'), decidedBy: t('Decided by'), change: t('Change'), whatItDoes: t('What it does:'), beforeAfter: t('Before and after'),
    before: t('Before'), after: t('After'), approve: t('Approve'), reject: t('Reject'),
  };
  const pending = $derived(plans.filter((p) => p.state === 'pending'));
  const others = $derived(plans.filter((p) => p.state !== 'pending'));
  const label: Record<string, [string, string]> = {
    pending: [t('waiting for approval'), 'warn'],
    ready: [t('ready to apply'), ''],
    approved: [t('approved'), 'ok'],
    rejected: [t('rejected'), 'bad'],
    applying: [t('applying'), ''],
    applied: [t('applied'), 'ok'],
    stale: [t('stale: the config changed'), 'bad'],
    failed: [t('failed'), 'bad'],
    discarded: [t('discarded'), ''],
    expired: [t('expired'), ''],
  };
  type Preview = { impact?: string; warnings?: string[]; before?: unknown; after?: unknown; simulation?: S['Simulation'] | null };
  const preview = (p: S['Plan']) => (p.preview ?? {}) as Preview;
</script>

<div class="page">
  <div class="page-head">
    <h1>{t('Agent changes')}<HelpButton id="agent-changes" /></h1>
  </div>
  <p class="muted small">
    <T ctx="agentChanges" msg={"AI agents connected over MCP don't change anything directly: they make a plan, shown here with what it would do. With <requireapproval/>, a plan waits for an operator before the agent can apply it. Plans expire after 10 minutes."} {requireapproval} />
  </p>
  <ErrorNote {error} />

  {#snippet requireapproval()}<code translate="no">[agents] require_approval = true</code>{/snippet}
  {#snippet card(p: S['Plan'])}
    {@const [text, cls] = own(label, p.state) ?? [p.state, '']}
    {@const pv = preview(p)}
    <section class="card plan" data-testid="plan" class:waiting={p.state === 'pending'}>
      <div class="head">
        <strong translate="no">{p.summary}</strong>
        <span class="badge {cls}">{text}</span>
      </div>
      <dl class="small">
        <dt>{words.why}</dt><dd translate="no">{p.reason}</dd>
        <dt>{words.askedBy}</dt><dd class="mono" translate="no">{p.requestedBy}</dd>
        <dt>{words.when}</dt>
        <dd>
          {ago(p.createdUnixSeconds)}
          {#if p.state === 'pending' || p.state === 'ready' || p.state === 'approved'}
            {t('· expires in {time}', { time: duration(Math.max(0, p.expiresUnixSeconds - now)) })}
          {/if}
        </dd>
        {#if p.decidedBy}<dt>{words.decidedBy}</dt><dd translate="no">{p.decidedBy}</dd>{/if}
        <dt>{words.change}</dt><dd class="mono" translate="no">{p.method} {p.path}</dd>
      </dl>
      {#if pv.impact}<p class="small"><b>{words.whatItDoes}</b> <span translate="no">{pv.impact}</span></p>{/if}
      {#each pv.warnings ?? [] as w, i (i)}<p class="small warn-text" translate="no">{w}</p>{/each}
      <!-- REQ: OBS-024 — what the plan would have done to the logged queries, when the agent asked. -->
      {#if pv.simulation}<SimulationCard result={pv.simulation} />{/if}
      <details class="small">
        <summary>{words.beforeAfter}</summary>
        <div class="diff">
          <div><div class="muted">{words.before}</div><pre class="mono" translate="no">{JSON.stringify(pv.before ?? null, null, 2)}</pre></div>
          <div><div class="muted">{words.after}</div><pre class="mono" translate="no">{JSON.stringify(pv.after ?? null, null, 2)}</pre></div>
        </div>
      </details>
      {#if p.state === 'pending' && writable}
        <div class="row">
          <button class="primary" disabled={busy === p.id} onclick={() => decide(p.id, true)}>{words.approve}</button>
          <button disabled={busy === p.id} onclick={() => decide(p.id, false)}>{words.reject}</button>
        </div>
      {/if}
    </section>
  {/snippet}

  <h2>{t('Waiting for approval')}</h2>
  {#if pending.length === 0}
    <p class="empty">{t('Nothing is waiting.')}</p>
  {:else}
    {#each pending as p (p.id)}{@render card(p)}{/each}
  {/if}

  {#if others.length}
    <h2>{t('Recent plans')}</h2>
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
