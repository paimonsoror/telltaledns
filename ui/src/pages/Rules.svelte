<script lang="ts">
  // REQ: FLT-005 (T6.12, ADR-067) — quick rules: what's in effect (with a countdown), who made
  // it and why, removing one, and making a new one.
  // REQ: FLT-005 (T20.1, ADR-162) — editing one in place, under its ID.
  import { api, type S } from '../lib/api';
  import { can } from '../lib/session.svelte';
  import { poll } from '../lib/poll';
  import { duration, endsAt, logDate } from '../lib/format';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import QuickRuleForm from '../lib/components/QuickRuleForm.svelte';
  import { tr } from '../lib/i18n';
  const { t } = tr('rules');

  let rules = $state<S['RuleInfo'][]>([]);
  let error = $state<unknown>(null);
  let removing = $state('');
  /** The rule being edited: a copy taken when Edit was pressed, so the list's reloads don't reset the form. */
  let editing = $state<S['RuleInfo'] | null>(null);
  /** What the last edit did. It sits on the page, not in the row: the row is redrawn when the list reloads. */
  let edited = $state('');
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
    edited = '';
    try {
      await api.deleteRule(id);
      await load();
    } catch (e) {
      error = e;
    } finally {
      removing = '';
    }
  }
  /** The form holds one device or one group (or everyone), so a rule with more is changed through the API. */
  const fitsForm = (r: S['RuleInfo']) => r.devices.length + r.groups.length <= 1;
  function edit(r: S['RuleInfo']) {
    edited = '';
    editing = $state.snapshot(r);
  }
  async function afterEdit(message: string) {
    editing = null;
    // The message names the saved rule (its domain may have changed), so it isn't named again here.
    edited = t('Rule updated. {message}', { message });
    await load();
  }
  // The words of the rows are read once, here: language is fixed for the life of the page.
  const words = { everyone: t('everyone'), never: t('never'), expired: t('expired'), edit: t('Edit'), remove: t('Remove'), api: t('Several devices or groups: change it through the API.'), file: t('in the config file'), byFile: t('config file') };
  const whom = (r: S['RuleInfo']) =>
    r.devices.length ? r.devices.join(', ') : r.groups.length ? t('group {names}', { names: r.groups.join(', ') }) : words.everyone;
</script>

<div class="page">
  <div class="page-head">
    <h1>{t('Quick rules')}<HelpButton id="quick-rules" /></h1>
  </div>
  <p class="muted small">
    {t('Allow or block a site for one device, a group, or everyone, for a while or for good. Quick rules decide before any list: a device\'s rule beats its group\'s, which beats everyone\'s.')}
  </p>
  <ErrorNote {error} />
  {#if edited}<div class="notice ok small" role="status" data-testid="rule-edited">{edited}</div>{/if}

  {#if writable}
    <section class="card">
      <h2>{t('New rule')}</h2>
      <QuickRuleForm onsaved={() => load()} />
    </section>
  {/if}

  <section class="card">
    <h2>{t('In effect')}</h2>
    {#if rules.length === 0}
      <p class="empty">{t('No quick rules. Make one here, or from "Why?" in the query log.')}</p>
    {:else}
      <div class="table-wrap">
        <table data-testid="rules-table">
          <thead>
            <tr><th>{t('Rule')}</th><th>{t('For')}</th><th>{t('Ends')}</th><th>{t('Note')}</th><th>{t('Made')}</th><th></th></tr>
          </thead>
          <tbody>
            {#each rules as r (r.id)}
              <tr>
                <td>
                  <span class="badge {r.action === 'allow' ? 'ok' : 'bad'}" translate="no">{r.action}</span>
                  <span class="mono" translate="no">{r.domain}</span>
                </td>
                <td>{whom(r)}</td>
                <td class="small">
                  {#if r.expiresInSeconds == null}{words.never}{:else if r.expiresInSeconds === 0}{words.expired}{:else}{t('in {time}', { time: duration(r.expiresInSeconds) })}<div class="muted">{t('at {time}', { time: endsAt(r.expires) })}</div>{/if}
                </td>
                <td class="small" translate="no">{r.note ?? ''}</td>
                <td class="small muted">{#if r.createdBy != null}<span translate="no">{r.createdBy}</span>{:else if r.source === 'file'}{words.byFile}{/if}{#if r.created}<div>{logDate(r.created)}</div>{/if}</td>
                <td>
                  {#if r.source === 'api' && writable}
                    {#if fitsForm(r) && r.expiresInSeconds !== 0}
                      <button class="link" disabled={editing?.id === r.id} onclick={() => edit(r)}>{words.edit}</button>
                    {/if}
                    <button class="link" disabled={removing === r.id} onclick={() => remove(r.id)}>{words.remove}</button>
                    {#if !fitsForm(r)}<div class="muted small">{words.api}</div>{/if}
                  {:else if r.source === 'file'}
                    <span class="muted small">{words.file}</span>
                  {/if}
                </td>
              </tr>
              {#if editing?.id === r.id}
                <tr data-testid="rule-edit-row">
                  <td colspan="6">
                    <h3>{t('Edit rule')}</h3>
                    <QuickRuleForm rule={editing} onsaved={afterEdit} oncancel={() => (editing = null)} />
                  </td>
                </tr>
              {/if}
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>
</div>
