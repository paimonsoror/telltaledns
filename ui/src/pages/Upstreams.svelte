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
  // REQ: OBS-019 — what the upstreams' answers said, per node.
  let checks = $state<S['UpstreamChecks'][]>([]);
  let error = $state<unknown>(null);

  $effect(() =>
    poll(async () => {
      try {
        const [u, l, c] = await Promise.all([
          api.upstreams(),
          api.latency('upstream'),
          api.upstreamChecks().catch(() => ({ items: [] as S['UpstreamChecks'][] })),
        ]);
        upstreams = u.items;
        latency = l.items;
        checks = c.items;
        error = null;
      } catch (e) {
        error = e;
      }
    }, 10000),
  );

  const byKey = $derived(new Map(latency.map((r) => [r.key, r])));
  const advanced = $derived(currentMode() === 'advanced');
  const totalRequests = $derived(upstreams.reduce((a, u) => a + u.requests, 0));

  // REQ: UPS-006, OBS-011 — what the failures were, which says what to fix: timeouts point at
  // the path, network errors at the connection, SERVFAIL at the domain asked about.
  const failureKinds: [keyof S['FailureKinds'], string][] = [
    ['timeout', 'timeouts'],
    ['network', 'connection errors'],
    ['badResponse', 'bad replies'],
    ['unresolved', 'name not resolved'],
    ['servfail', 'SERVFAIL'],
    ['refused', 'REFUSED'],
    ['otherRcode', 'other errors'],
  ];
  const breakdown = (u: S['UpstreamInfo']) =>
    failureKinds
      .filter(([k]) => u.failuresByKind[k] > 0)
      .map(([k, label]) => `${num(u.failuresByKind[k])} ${label}`)
      .join(' · ');

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
  const results: [keyof S['UpstreamQuality'], string, string][] = [
    ['same', 'same', ''],
    ['differentAddresses', 'other addresses', 'Both had addresses, none in common: CDNs and geo-DNS answer per resolver, usually harmless.'],
    ['differentRcode', 'other response', 'A different response code (SERVFAIL, REFUSED, ...).'],
    ['filtered', 'filtered', 'One had addresses, the other none or only 0.0.0.0/loopback: one of them filters this name.'],
    ['unanswered', 'no second answer', 'The second upstream didn’t answer.'],
  ];
  const resultLabel: Record<string, string> = {
    different_addresses: 'other addresses',
    different_rcode: 'other response',
    filtered: 'filtered',
  };
  const opinions = (q: S['UpstreamQuality']) => results.reduce((n, [k]) => n + (q[k] as number), 0);
  const multiNode = $derived(checks.length > 1);
  const anyQuality = $derived(checks.some((c) => c.upstreams.length > 0));
  const reload = async () => {
    upstreams = (await api.upstreams()).items;
  };
  // REQ: API-002 (T9.12) — ask the draft upstream before saving it.
  const tryUpstream = {
    label: 'Test it',
    run: async (b: Record<string, unknown>) => {
      const r = await api.checkUpstream(b);
      return r.ok
        ? { ok: true, text: `Works: ${r.detail} in ${r.elapsedMs} ms.` }
        : { ok: false, text: `Doesn't work: ${r.error ?? r.detail}` };
    },
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
              <td class="num">{num(u.failures)} <span class="muted small">({pct(u.requests ? (u.failures / u.requests) * 100 : 0)})</span><ShareBar value={u.requests ? (u.failures / u.requests) * 100 : 0} color="--s-blocked" label="failure rate" />
                {#if u.failures > 0}<div class="muted small">{breakdown(u)}</div>{/if}</td>
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
  <!-- REQ: OBS-019 (ADR-108) — are the upstreams telling the truth? -->
  <section class="card" data-testid="upstream-quality">
    <h2>Answer quality<HelpButton id="upstream-checks" /></h2>
    {#if !anyQuality}
      <p class="empty">Nothing to show yet: DNSSEC verdicts and error codes appear as upstreams answer.</p>
    {:else}
      <div class="table-wrap">
        <table class="compact">
          <thead>
            <tr>
              {#if multiNode}<th>Node</th>{/if}<th>Upstream</th><th>Second opinions</th><th>DNSSEC</th><th>Error codes (EDE)</th>
            </tr>
          </thead>
          <tbody>
            {#each checks as c (c.node ?? '')}
              {#each c.upstreams as q (q.upstream)}
                <tr>
                  {#if multiNode}<td>{c.node ?? ''}</td>{/if}
                  <td><strong>{q.upstream}</strong></td>
                  <td class="small">
                    {#if opinions(q) === 0}<span class="muted">–</span>{/if}
                    {#each results as [k, label, tip] (k)}
                      {#if (q[k] as number) > 0}<span class="chip" class:bad={k === 'filtered'} title={tip}>{num(q[k] as number)} {label}</span>{/if}
                    {/each}
                  </td>
                  <td class="small">
                    {#if q.dnssecSecure + q.dnssecInsecure + q.dnssecBogus + q.dnssecIndeterminate === 0}<span class="muted">–</span>
                    {:else}{num(q.dnssecSecure)} secure · {num(q.dnssecInsecure)} unsigned{#if q.dnssecBogus} · <span class="bad-text">{num(q.dnssecBogus)} bogus</span>{/if}{#if q.dnssecIndeterminate} · {num(q.dnssecIndeterminate)} undecided{/if}{/if}
                  </td>
                  <td class="small">
                    {#if q.ede.length === 0}<span class="muted">none</span>{/if}
                    {#each q.ede as e (e.code)}<span class="chip" class:bad={e.code >= 15 && e.code <= 17}>{e.code} {e.name}: {num(e.count)}</span>{/each}
                  </td>
                </tr>
              {/each}
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
    {#if checks.length && !checks.some((c) => c.enabled)}
      <p class="muted small">
        Second opinions are off. With <code>[upstream_check] sample_every = 1000</code>, one forwarded question in 1,000 is
        asked again of another upstream and the answers compared (that upstream sees those names).
      </p>
    {/if}
    {#each checks.filter((c) => c.recent.length) as c (c.node ?? '')}
      <h3 class="small">Latest disagreements{#if multiNode} on {c.node}{/if}</h3>
      <ul class="disagreements small">
        {#each c.recent.slice(0, 10) as d (`${d.at}|${d.name}`)}
          <li>
            <span class="mono">{d.name}</span> {d.qtype} · <strong>{d.upstream}</strong>: {d.answer} · <strong>{d.reference}</strong>: {d.referenceAnswer}
            <span class="chip" class:bad={d.result === 'filtered'}>{resultLabel[d.result] ?? d.result}</span>
          </li>
        {/each}
      </ul>
    {/each}
  </section>
  <ConfigEditor kind="upstream" path="upstreams" title="Upstream servers" noun="upstream" fields={upstreamFields}
    summary={(d) => String(d.url ?? '')} onchanged={reload} formAction={tryUpstream} />
  <ConfigEditor kind="upstream_group" path="upstream-groups" title="Upstream groups" noun="upstream group" fields={groupFields}
    summary={(d) => `${String(d.strategy ?? 'failover')}: ${((d.members as string[]) ?? []).join(', ')}`} onchanged={reload} />
  <p class="muted small">
    To send one domain to a different server (a work network, your router), add a forwarded domain on the
    <a href={href('/local-dns')}>Names on my network</a> page.<HelpButton id="routes" />
  </p>
</div>

<style>
  .chip {
    display: inline-block;
    padding: 0 6px;
    margin: 1px 4px 1px 0;
    border-radius: 999px;
    background: var(--surface-2);
    white-space: nowrap;
  }
  .chip.bad,
  .bad-text {
    color: var(--bad);
    font-weight: 600;
  }
  .disagreements {
    margin: 4px 0 0;
    padding-left: 18px;
  }
</style>
