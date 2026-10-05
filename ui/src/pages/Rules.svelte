<script lang="ts">
  // REQ: FLT-005 (T6.12, ADR-067) — quick rules: what's in effect (with a countdown), who made
  // it and why, removing one, and making a new one.
  import { api, type S } from '../lib/api';
  import { can } from '../lib/session.svelte';
  import { poll } from '../lib/poll';
  import { duration, logDate } from '../lib/format';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import QuickRuleForm from '../lib/components/QuickRuleForm.svelte';

  let rules = $state<S['RuleInfo'][]>([]);
  let error = $state<unknown>(null);
  let removing = $state('');
  const writable = $derived(can('operator'));

  async function load() {
    try {
      rules = (await api.rules()).items;
      error = null;
    } catch (e) {
      error = e;
    }
  }
  $effect(() => poll(load, 10000));

  async function remove(id: string) {
    removing = id;
    try {
      await api.deleteRule(id);
      await load();
    } catch (e) {
      error = e;
    } finally {
      removing = '';
    }
  }
  /** "21:30", or "Tue 21:30" when it isn't today. */
  function ends(rfc3339: string | null | undefined): string {
    if (!rfc3339) return '';
    const d = new Date(rfc3339);
    const time = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    return d.toDateString() === new Date().toDateString() ? time : `${d.toLocaleDateString([], { weekday: 'short' })} ${time}`;
  }
  const whom = (r: S['RuleInfo']) =>
    r.devices.length ? r.devices.join(', ') : r.groups.length ? `group ${r.groups.join(', ')}` : 'everyone';
</script>

<div class="page">
  <div class="page-head">
    <h1>Quick rules<HelpButton id="quick-rules" /></h1>
  </div>
  <p class="muted small">
    Allow or block a site for one device, a group, or everyone, for a while or for good. Quick rules decide before any
    list: a device's rule beats its group's, which beats everyone's.
  </p>
  <ErrorNote {error} />

  {#if writable}
    <section class="card">
      <h2>New rule</h2>
      <QuickRuleForm onsaved={load} />
    </section>
  {/if}

  <section class="card">
    <h2>In effect</h2>
    {#if rules.length === 0}
      <p class="empty">No quick rules. Make one here, or from "Why?" in the query log.</p>
    {:else}
      <div class="table-wrap">
        <table data-testid="rules-table">
          <thead>
            <tr><th>Rule</th><th>For</th><th>Ends</th><th>Note</th><th>Made</th><th></th></tr>
          </thead>
          <tbody>
            {#each rules as r (r.id)}
              <tr>
                <td>
                  <span class="badge {r.action === 'allow' ? 'ok' : 'bad'}">{r.action}</span>
                  <span class="mono">{r.domain}</span>
                </td>
                <td>{whom(r)}</td>
                <td class="small">
                  {#if r.expiresInSeconds == null}never{:else if r.expiresInSeconds === 0}expired{:else}in {duration(r.expiresInSeconds)}<div class="muted">at {ends(r.expires)}</div>{/if}
                </td>
                <td class="small">{r.note ?? ''}</td>
                <td class="small muted">{r.createdBy ?? (r.source === 'file' ? 'config file' : '')}{#if r.created}<div>{logDate(r.created)}</div>{/if}</td>
                <td>
                  {#if r.source === 'api' && writable}
                    <button class="link" disabled={removing === r.id} onclick={() => remove(r.id)}>Remove</button>
                  {:else if r.source === 'file'}
                    <span class="muted small">in the config file</span>
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
