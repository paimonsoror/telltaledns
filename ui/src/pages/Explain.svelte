<script lang="ts">
  // REQ: FLT-013 — "why is this blocked?" for any name and device.
  import { api, type S } from '../lib/api';
  import { route, navigate } from '../lib/router.svelte';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import ExplainView from '../lib/components/ExplainView.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import { t } from '../lib/i18n';

  let name = $state(route.params.get('name') ?? '');
  let client = $state(route.params.get('client') ?? '');
  let qtype = $state(route.params.get('qtype') ?? 'A');
  let result = $state<S['Explanation'] | null>(null);
  let error = $state<unknown>(null);
  let busy = $state(false);

  $effect(() => {
    const n = route.params.get('name');
    if (!n) return;
    busy = true;
    api
      .explain({ name: n, client: route.params.get('client') || undefined, qtype: route.params.get('qtype') || undefined })
      .then((r) => {
        result = r;
        error = null;
      })
      .catch((e) => {
        result = null;
        error = e;
      })
      .finally(() => (busy = false));
  });

  function submit(e: SubmitEvent) {
    e.preventDefault();
    navigate('/explain', { name: name.trim(), client: client.trim() || undefined, qtype: qtype.trim() || undefined });
  }
</script>

<div class="page">
  <h1>{t('nav.explain')}<HelpButton id="explain" /></h1>
  <form class="card row" onsubmit={submit}>
    <label class="field grow">{t('clients.col.name')}
      <input name="name" required placeholder={t('explain.form.namePlaceholder')} bind:value={name} />
    </label>
    <label class="field">{t('explain.form.client')}
      <input name="client" placeholder={t('explain.form.clientPlaceholder')} bind:value={client} />
    </label>
    <label class="field narrow">{t('qw.cache.type')}
      <input name="qtype" bind:value={qtype} />
    </label>
    <button class="primary" type="submit" disabled={busy}>{t('explain.form.submit')}</button>
  </form>
  <ErrorNote {error} />
  {#if result}<ExplainView x={result} />{/if}
</div>

<style>
  form {
    align-items: end;
  }
  .grow {
    flex: 2 1 220px;
  }
  .field {
    flex: 1 1 140px;
  }
  .narrow {
    flex: 0 1 80px;
  }
</style>
