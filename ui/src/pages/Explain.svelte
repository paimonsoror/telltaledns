<script lang="ts">
  // REQ: FLT-013 — "why is this blocked?" for any name and device.
  import { api, type S } from '../lib/api';
  import { route, navigate } from '../lib/router.svelte';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import ExplainView from '../lib/components/ExplainView.svelte';

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
  <h1>Explain</h1>
  <form class="card row" onsubmit={submit}>
    <label class="field grow">Name
      <input name="name" required placeholder="ads.example.com" bind:value={name} />
    </label>
    <label class="field">Client IP
      <input name="client" placeholder="192.168.1.20" bind:value={client} />
    </label>
    <label class="field narrow">Type
      <input name="qtype" bind:value={qtype} />
    </label>
    <button class="primary" type="submit" disabled={busy}>Explain</button>
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
