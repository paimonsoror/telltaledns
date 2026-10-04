<script lang="ts">
  // REQ: API-005 — upstream servers: live health (circuit breaker), traffic, latency.
  import { api, type S } from '../lib/api';
  import { ms, num, pct } from '../lib/format';
  import { poll } from '../lib/poll';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import StatusBadge from '../lib/components/StatusBadge.svelte';

  let upstreams = $state<S['UpstreamInfo'][]>([]);
  let latency = $state<S['LatencyRow'][]>([]);
  let error = $state<unknown>(null);

  $effect(() =>
    poll(async () => {
      try {
        const [u, l] = await Promise.all([api.upstreams(), api.latency('upstream')]);
        upstreams = u.items;
        latency = l.items;
        error = null;
      } catch (e) {
        error = e;
      }
    }, 10000),
  );

  const byKey = $derived(new Map(latency.map((r) => [r.key, r])));
</script>

<div class="page">
  <h1>Upstreams</h1>
  <ErrorNote {error} />
  <section class="card">
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Upstream</th><th>Groups</th><th>Health</th><th class="num">Requests</th><th class="num">Failures</th>
            <th class="num">Smoothed</th><th class="num">p50</th><th class="num">p99</th>
          </tr>
        </thead>
        <tbody>
          {#each upstreams as u (u.id)}
            {@const l = byKey.get(u.name)}
            <tr>
              <td><strong>{u.name}</strong><div class="muted small mono">{u.endpoint}</div></td>
              <td>{u.groups.join(', ')}</td>
              <td><StatusBadge value={u.breaker} /></td>
              <td class="num">{num(u.requests)}</td>
              <td class="num">{num(u.failures)} <span class="muted small">({pct(u.requests ? (u.failures / u.requests) * 100 : 0)})</span></td>
              <td class="num">{ms(u.latencyEwmaMs)}</td>
              <td class="num">{ms(l?.p50Ms)}</td>
              <td class="num">{ms(l?.p99Ms)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  </section>
  <p class="muted small">
    Health: <strong>closed</strong> = healthy, <strong>open</strong> = benched after failures,
    <strong>half_open</strong> = being probed. Percentiles cover this hour.
  </p>
</div>
