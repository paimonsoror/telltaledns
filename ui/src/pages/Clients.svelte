<script lang="ts">
  // REQ: API-005, API-010 — configured devices and the clients seen this hour; name a device
  // from either list.
  import { api, type S } from '../lib/api';
  import { href } from '../lib/router.svelte';
  import { num } from '../lib/format';
  import { session } from '../lib/session.svelte';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import ClientChip from '../lib/components/ClientChip.svelte';

  let configured = $state<S['ClientInfo'][]>([]);
  let seen = $state<S['TopItem'][]>([]);
  let error = $state<unknown>(null);
  const canEdit = $derived(session.user?.role === 'admin' || session.user?.role === 'operator');

  function load() {
    Promise.all([api.clients(), api.top('clients', 100)])
      .then(([c, t]) => {
        configured = c.items;
        seen = t.items;
      })
      .catch((e) => (error = e));
  }

  $effect(load);

  async function remove(name: string) {
    try {
      await api.deleteClient(name);
      load();
    } catch (e) {
      error = e;
    }
  }
</script>

<div class="page">
  <h1>Clients</h1>
  <ErrorNote {error} />
  <div class="grid-2">
    <section class="card">
      <h2>Seen this hour</h2>
      {#if seen.length === 0}
        <p class="empty">No queries this hour.</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead><tr><th>Client</th><th>Device</th><th class="num">Queries</th><th></th></tr></thead>
            <tbody>
              {#each seen as c (c.key)}
                <tr>
                  <td class="mono"><ClientChip ip={c.key} onchanged={load} /></td>
                  <td>{c.name ?? ''}</td>
                  <td class="num">{num(c.count)}</td>
                  <td class="num"><a href={href('/queries', { client: c.key })}>Queries</a></td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </section>
    <section class="card">
      <h2>Devices</h2>
      {#if configured.length === 0}
        <p class="empty">No devices yet. Click an address anywhere (here, the dashboard, or the query log) and choose “Name this device…”, or add <code>[[client]]</code> entries to the config file.</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead><tr><th>Name</th><th>Recognized by</th><th>Groups</th><th>Defined in</th><th></th></tr></thead>
            <tbody>
              {#each configured as c (c.name)}
                <tr>
                  <td><strong>{c.name}</strong></td>
                  <td class="mono small">{c.match.join(', ')}</td>
                  <td>{c.groups.join(', ')}</td>
                  <td class="small">{c.source === 'api' ? 'the UI / API' : 'config file'}</td>
                  <td class="num">
                    {#if c.source === 'api' && canEdit}
                      <button class="link small" onclick={() => remove(c.name)} aria-label={`Forget ${c.name}`}>Forget</button>
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
</div>
