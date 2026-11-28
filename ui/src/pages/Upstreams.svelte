<script lang="ts">
  // REQ: API-005 — upstream servers: live health (circuit breaker), traffic, latency.
  import { api, type S } from '../lib/api';
  import { ms, num, pct } from '../lib/format';
  import { poll } from '../lib/poll';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import BreakerBadge from '../lib/components/BreakerBadge.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import ShareBar from '../lib/components/ShareBar.svelte';
  import { currentMode } from '../lib/mode.svelte';
  import { href } from '../lib/router.svelte';
  import ConfigEditor, { type Field } from '../lib/components/ConfigEditor.svelte';
  import LatencyHeatmap from '../lib/components/LatencyHeatmap.svelte';
  import { own, tr } from '../lib/i18n';
  import T from '../lib/i18n/T.svelte';
  const { t } = tr('upstreams');

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
    ['timeout', t('timeouts')],
    ['network', t('connection errors')],
    ['badResponse', t('bad replies')],
    ['unresolved', t('name not resolved')],
    ['servfail', t('SERVFAIL')],
    ['refused', t('REFUSED')],
    ['otherRcode', t('other errors')],
  ];
  const breakdown = (u: S['UpstreamInfo']) =>
    failureKinds
      .filter(([k]) => u.failuresByKind[k] > 0)
      .map(([k, label]) => `${num(u.failuresByKind[k])} ${label}`)
      .join(' · ');

  // REQ: API-002 (T7.5) — add and change upstreams and upstream groups here.
  const upstreamFields: Field[] = [
    { key: 'url', label: t('Address'), type: 'text', placeholder: t('tls://9.9.9.9 or https://dns.quad9.net/dns-query'),
      // REQ: UPS-011 (ADR-180) — plugin upstreams are the config file's.
      help: t('udp://, tcp://, tls:// (DNS over TLS), https:// (DNS over HTTPS), or quic://. Plugin upstreams (exec://, unix://) are defined in the config file.') },
    { key: 'tls_server_name', label: t('TLS server name'), type: 'text', placeholder: 'dns.quad9.net', advanced: true,
      help: t('The name on the server certificate, for tls:// and quic:// addresses given by IP.') },
    { key: 'timeout_ms', label: t('Timeout (ms)'), type: 'number', placeholder: '2000', advanced: true },
  ];
  const names = $derived(upstreams.map((u) => u.name).filter((n) => !n.startsWith('forward:')));
  const groupFields = $derived<Field[]>([
    { key: 'members', label: t('Upstreams'), type: 'multi', options: names },
    { key: 'strategy', label: t('Strategy'), type: 'select', options: ['failover', 'round_robin', 'weighted', 'fastest', 'parallel'],
      help: t('failover: in order, the next on failure. fastest: the quickest lately. parallel: ask several, take the first answer.') },
  ]);
  // The words of the rows are read once, here: language is fixed for the life of the page.
  const otherAddresses = t('other addresses');
  const otherResponse = t('other response');
  const filtered = t('filtered');
  const results: [keyof S['UpstreamQuality'], string, string][] = [
    ['same', t('same'), ''],
    ['differentAddresses', otherAddresses, t('Both had addresses, none in common: CDNs and geo-DNS answer per resolver, usually harmless.')],
    ['differentRcode', otherResponse, t('A different response code (SERVFAIL, REFUSED, ...).')],
    ['filtered', filtered, t('One had addresses, the other none or only 0.0.0.0/loopback: one of them filters this name.')],
    ['unanswered', t('no second answer'), t('The second upstream didn’t answer.')],
  ];
  // A result comes from the server: read with `Object.hasOwn`, and one the UI doesn't know shows as it is.
  const resultLabel: Record<string, string> = {
    different_addresses: otherAddresses,
    different_rcode: otherResponse,
    filtered,
  };
  const words = { shareRequests: t('share of all upstream requests'), shareFailures: t('failure rate'), none: t('none') };
  const opinions = (q: S['UpstreamQuality']) => results.reduce((n, [k]) => n + (q[k] as number), 0);
  const multiNode = $derived(checks.length > 1);
  const anyQuality = $derived(checks.some((c) => c.upstreams.length > 0));
  const reload = async () => {
    upstreams = (await api.upstreams()).items;
  };
  // REQ: API-002 (T9.12) — ask the draft upstream before saving it.
  const tryUpstream = {
    label: t('Test it'),
    run: async (b: Record<string, unknown>) => {
      const r = await api.checkUpstream(b);
      return r.ok
        ? { ok: true, text: t('Works: {detail} in {ms} ms.', { detail: r.detail, ms: r.elapsedMs }) }
        : { ok: false, text: t("Doesn't work: {error}", { error: r.error ?? r.detail }) };
    },
  };
  // REQ: OBS-030 — the upstream whose answer times the heatmap shows.
  let latencyOf = $state('');
</script>

{#snippet strong(x: string)}<strong>{x}</strong>{/snippet}
{#snippet link(x: string)}<a href={href('/local-dns')}>{x}</a>{/snippet}
{#snippet samplekey()}<code translate="no">[upstream_check] sample_every = 1000</code>{/snippet}

<div class="page">
  <h1>{t('Upstreams')}<HelpButton id="upstreams" /></h1>
  <ErrorNote {error} />
  <section class="card">
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>{t('Upstream')}</th><th>{t('Groups')}</th><th>{t('Health')}<HelpButton id="upstream-health" /></th><th class="num">{t('Requests')}</th><th class="num">{t('Failures')}</th>
            {#if advanced}<th class="num">{t('Smoothed')}</th>{/if}<th class="num">{t('p50')}</th>{#if advanced}<th class="num">{t('p99')}</th>{/if}
          </tr>
        </thead>
        <tbody>
          {#each upstreams as u (u.id)}
            {@const l = byKey.get(u.name)}
            <tr>
              <td><strong translate="no">{u.name}</strong>{#if advanced}<div class="muted small mono" translate="no">{u.endpoint}</div>{/if}</td>
              <td translate="no">{u.groups.join(', ')}</td>
              <td><BreakerBadge value={u.breaker} /></td>
              <td class="num">{num(u.requests)}<ShareBar value={totalRequests ? (u.requests / totalRequests) * 100 : 0} color="--s-forwarded" label={words.shareRequests} /></td>
              <td class="num">{num(u.failures)} <span class="muted small">({pct(u.requests ? (u.failures / u.requests) * 100 : 0)})</span><ShareBar value={u.requests ? (u.failures / u.requests) * 100 : 0} color="--s-blocked" label={words.shareFailures} />
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
    <T ctx="upstreams" msg={"Health: <strong>Healthy</strong> = answering, <strong>Benched</strong> = stopped asking it after failures, <strong>Probing</strong> = a trial query is checking whether it has recovered. Percentiles cover this hour. Hover a badge for the circuit breaker's own word."} {strong} />
  </p>
  <!-- REQ: OBS-030 (ADR-130) — one upstream's answer times as a shape over time. -->
  {#if upstreams.length}
    <section class="card" data-testid="upstream-latency">
      <div class="card-head">
        <h2>{t('Answer time over time')}<HelpButton id="latency-heatmap" /></h2>
        <span class="pill-field bare">
          <select bind:value={latencyOf} aria-label={t('Upstream')}>
            {#each upstreams as u (u.id)}<option value={u.name} translate="no">{u.name}</option>{/each}
          </select>
        </span>
      </div>
      {#key latencyOf}<LatencyHeatmap by="upstream" upstream={latencyOf || upstreams[0].name} testid="upstream-latency-heatmap" />{/key}
    </section>
  {/if}
  <!-- REQ: OBS-019 (ADR-108) — are the upstreams telling the truth? -->
  <section class="card" data-testid="upstream-quality">
    <h2>{t('Answer quality')}<HelpButton id="upstream-checks" /></h2>
    {#if !anyQuality}
      <p class="empty">{t('Nothing to show yet: DNSSEC verdicts and error codes appear as upstreams answer.')}</p>
    {:else}
      <div class="table-wrap">
        <table class="compact">
          <thead>
            <tr>
              {#if multiNode}<th>{t('Node')}</th>{/if}<th>{t('Upstream')}</th><th>{t('Second opinions')}</th><th>{t('DNSSEC')}</th><th>{t('Error codes (EDE)')}</th>
            </tr>
          </thead>
          <tbody>
            {#each checks as c, i (i)}
              {#each c.upstreams as q (q.upstream)}
                <tr>
                  {#if multiNode}<td translate="no">{c.node ?? ''}</td>{/if}
                  <td><strong translate="no">{q.upstream}</strong></td>
                  <td class="small">
                    {#if opinions(q) === 0}<span class="muted">–</span>{/if}
                    {#each results as [k, label, tip] (k)}
                      {#if (q[k] as number) > 0}<span class="chip" class:bad={k === 'filtered'} title={tip}>{num(q[k] as number)} {label}</span>{/if}
                    {/each}
                  </td>
                  <td class="small">
                    {#if q.dnssecSecure + q.dnssecInsecure + q.dnssecBogus + q.dnssecIndeterminate === 0}<span class="muted">–</span>
                    {:else}{t('{n} secure · {m} unsigned', { n: num(q.dnssecSecure), m: num(q.dnssecInsecure) })}{#if q.dnssecBogus} · <span class="bad-text">{t('{n} bogus', { n: num(q.dnssecBogus) })}</span>{/if}{#if q.dnssecIndeterminate}{t('· {n} undecided', { n: num(q.dnssecIndeterminate) })}{/if}{/if}
                  </td>
                  <td class="small">
                    {#if q.ede.length === 0}<span class="muted">{words.none}</span>{/if}
                    {#each q.ede as e (e.code)}<span class="chip" class:bad={e.code >= 15 && e.code <= 17} translate="no">{e.code} {e.name}: {num(e.count)}</span>{/each}
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
        <T ctx="upstreams" msg={'Second opinions are off. With <samplekey/>, one forwarded question in 1,000 is asked again of another upstream and the answers compared (that upstream sees those names).'} {samplekey} />
      </p>
    {/if}
    {#each checks.filter((c) => c.recent.length) as c, i (i)}
      <h3 class="small">{t('Latest disagreements')}{#if multiNode}{t('on {node}', { node: c.node })}{/if}</h3>
      <ul class="disagreements small">
        {#each c.recent.slice(0, 10) as d, j (j)}
          <li>
            <span translate="no"><span class="mono">{d.name}</span> {d.qtype} · <strong>{d.upstream}</strong>: {d.answer} · <strong>{d.reference}</strong>: {d.referenceAnswer}</span>
            <span class="chip" class:bad={d.result === 'filtered'}>{own(resultLabel, d.result) ?? d.result}</span>
          </li>
        {/each}
      </ul>
    {/each}
  </section>
  <ConfigEditor kind="upstream" path="upstreams" title={t('Upstream servers')} noun={t('upstream')} fields={upstreamFields}
    summary={(d) => String(d.url ?? '')} onchanged={reload} formAction={tryUpstream} />
  <ConfigEditor kind="upstream_group" path="upstream-groups" title={t('Upstream groups')} noun={t('upstream group')} fields={groupFields}
    summary={(d) => `${String(d.strategy ?? 'failover')}: ${((d.members as string[]) ?? []).join(', ')}`} onchanged={reload} />
  <p class="muted small">
    <T ctx="upstreams" msg={'To send one domain to a different server (a work network, your router), add a forwarded domain on the <link>Names on my network</link> page.'} {link} /><HelpButton id="routes" />
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
