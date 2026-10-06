<script lang="ts">
  // REQ: API-005 — upstream servers: live health (circuit breaker), traffic, latency.
  import { api, type S } from '../lib/api';
  import { ms, num, pct } from '../lib/format';
  import { poll } from '../lib/poll';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import StatusBadge from '../lib/components/StatusBadge.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import ShareBar from '../lib/components/ShareBar.svelte';
  import { currentMode } from '../lib/mode.svelte';
  import { href } from '../lib/router.svelte';
  import ConfigEditor, { type Field } from '../lib/components/ConfigEditor.svelte';

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
  const advanced = $derived(currentMode() === 'advanced');
  const totalRequests = $derived(upstreams.reduce((a, u) => a + u.requests, 0));

  // REQ: API-002 (T7.5) — add and change upstreams and upstream groups here.
  const upstreamFields: Field[] = [
    { key: 'url', label: 'Address', type: 'text', placeholder: 'tls://9.9.9.9 or https://dns.quad9.net/dns-query',
      help: 'udp://, tcp://, tls:// (DNS over TLS), https:// (DNS over HTTPS), or quic://.' },
    { key: 'tls_server_name', label: 'TLS server name', type: 'text', placeholder: 'dns.quad9.net', advanced: true,
      help: 'The name on the server certificate, for tls:// and quic:// addresses given by IP.' },
    { key: 'timeout_ms', label: 'Timeout (ms)', type: 'number', placeholder: '2000', advanced: true },
  ];
  const names = $derived(upstreams.map((u) => u.name).filter((n) => !n.startsWith('forward:')));
  const groupFields = $derived<Field[]>([
    { key: 'members', label: 'Upstreams', type: 'multi', options: names },
    { key: 'strategy', label: 'Strategy', type: 'select', options: ['failover', 'round_robin', 'weighted', 'fastest', 'parallel'],
      help: 'failover: in order, the next on failure. fastest: the quickest lately. parallel: ask several, take the first answer.' },
  ]);
  const reload = async () => {
    upstreams = (await api.upstreams()).items;
  };
</script>

<div class="page">
  <h1>Upstreams<HelpButton id="upstreams" /></h1>
  <ErrorNote {error} />
  <section class="card">
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Upstream</th><th>Groups</th><th>Health<HelpButton id="upstream-health" /></th><th class="num">Requests</th><th class="num">Failures</th>
            {#if advanced}<th class="num">Smoothed</th>{/if}<th class="num">p50</th>{#if advanced}<th class="num">p99</th>{/if}
          </tr>
        </thead>
        <tbody>
          {#each upstreams as u (u.id)}
            {@const l = byKey.get(u.name)}
            <tr>
              <td><strong>{u.name}</strong>{#if advanced}<div class="muted small mono">{u.endpoint}</div>{/if}</td>
              <td>{u.groups.join(', ')}</td>
              <td><StatusBadge value={u.breaker} /></td>
              <td class="num">{num(u.requests)}<ShareBar value={totalRequests ? (u.requests / totalRequests) * 100 : 0} color="--s-forwarded" label="share of all upstream requests" /></td>
              <td class="num">{num(u.failures)} <span class="muted small">({pct(u.requests ? (u.failures / u.requests) * 100 : 0)})</span><ShareBar value={u.requests ? (u.failures / u.requests) * 100 : 0} color="--s-blocked" label="failure rate" /></td>
              {#if advanced}<td class="num">{ms(u.latencyEwmaMs)}</td>{/if}
              <td class="num">{ms(l?.p50Ms)}</td>
              {#if advanced}<td class="num">{ms(l?.p99Ms)}</td>{/if}
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
  <ConfigEditor kind="upstream" path="upstreams" title="Upstream servers" noun="upstream" fields={upstreamFields}
    summary={(d) => String(d.url ?? '')} onchanged={reload} />
  <ConfigEditor kind="upstream_group" path="upstream-groups" title="Upstream groups" noun="upstream group" fields={groupFields}
    summary={(d) => `${String(d.strategy ?? 'failover')}: ${((d.members as string[]) ?? []).join(', ')}`} onchanged={reload} />
  <p class="muted small">
    To send one domain to a different server (a work network, your router), add a forwarded domain on the
    <a href={href('/local-dns')}>Names on my network</a> page.<HelpButton id="routes" />
  </p>
</div>
