<script lang="ts">
  // REQ: API-005 — client groups: lists, block mode, pause state.
  import { api, type S } from '../lib/api';
  import { dateTime } from '../lib/format';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import { currentMode } from '../lib/mode.svelte';

  let groups = $state<S['GroupInfo'][]>([]);
  let error = $state<unknown>(null);

  $effect(() => {
    api
      .groups()
      .then((g) => (groups = g.items))
      .catch((e) => (error = e));
  });
  const advanced = $derived(currentMode() === 'advanced');
</script>

<div class="page">
  <h1>Groups<HelpButton id="groups" /></h1>
  <ErrorNote {error} />
  <section class="card">
    <div class="table-wrap">
      <table>
        <thead><tr><th>Group</th><th class="num">Priority</th><th>Lists<HelpButton id="lists" /></th>{#if advanced}<th>Blocked answer</th>{/if}<th>Blocking</th></tr></thead>
        <tbody>
          {#each groups as g (g.name)}
            <tr>
              <td><strong>{g.name}</strong></td>
              <td class="num">{g.priority}</td>
              <td>{g.lists ? g.lists.join(', ') || 'none' : 'every enabled list'}</td>
              {#if advanced}<td>{g.blockMode} · TTL {g.blockTtlSeconds} s</td>{/if}
              <td>
                {#if g.pausedUntilUnixSeconds}
                  <span class="badge warn">paused until {dateTime(g.pausedUntilUnixSeconds)}</span>
                {:else}
                  <span class="badge ok">on</span>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  </section>
  <p class="muted small">Groups are defined with <code>[[group]]</code> in the configuration. Editing here comes with the configuration API.</p>
</div>
