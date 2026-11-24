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
  import { t, tn, type MessageKey } from '../lib/i18n';

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

  // A plural group's base key: `tn()` adds `.one` or `.other`, so `t()` has no string for it.
  type CountKey<T = MessageKey> = T extends `${infer Base}.one` ? Base : never;

  // REQ: UPS-006, OBS-011 — what the failures were, which says what to fix: timeouts point at
  // the path, network errors at the connection, SERVFAIL at the domain asked about.
  const failureKinds: [keyof S['FailureKinds'], CountKey][] = [
    ['timeout', 'upstreams.failure.timeout'],
    ['network', 'upstreams.failure.network'],
    ['badResponse', 'upstreams.failure.badResponse'],
    ['unresolved', 'upstreams.failure.unresolved'],
    ['servfail', 'upstreams.failure.servfail'],
    ['refused', 'upstreams.failure.refused'],
    ['otherRcode', 'upstreams.failure.otherRcode'],
  ];
  const breakdown = (u: S['UpstreamInfo']) =>
    failureKinds
      .filter(([k]) => u.failuresByKind[k] > 0)
      .map(([k, key]) => tn(key, u.failuresByKind[k], { n: num(u.failuresByKind[k]) }))
      .join(' · ');

  // REQ: API-002 (T7.5) — add and change upstreams and upstream groups here.
  const upstreamFields = $derived<Field[]>([
    { key: 'url', label: t('qw.explain.address'), type: 'text', placeholder: t('upstreams.field.addressPlaceholder'),
      // REQ: UPS-011 (ADR-180) — plugin upstreams are the config file's.
      help: t('upstreams.field.addressHelp') },
    { key: 'tls_server_name', label: t('upstreams.field.tlsName'), type: 'text', placeholder: t('upstreams.field.tlsNamePlaceholder'), advanced: true,
      help: t('upstreams.field.tlsNameHelp') },
    { key: 'timeout_ms', label: t('upstreams.field.timeout'), type: 'number', placeholder: '2000', advanced: true },
  ]);
  const names = $derived(upstreams.map((u) => u.name).filter((n) => !n.startsWith('forward:')));
  const groupFields = $derived<Field[]>([
    { key: 'members', label: t('upstreams.field.members'), type: 'multi', options: names },
    { key: 'strategy', label: t('upstreams.field.strategy'), type: 'select', options: ['failover', 'round_robin', 'weighted', 'fastest', 'parallel'],
      help: t('upstreams.field.strategyHelp') },
  ]);
  const results: [keyof S['UpstreamQuality'], CountKey, MessageKey | ''][] = [
    ['same', 'upstreams.opinion.same', ''],
    ['differentAddresses', 'upstreams.opinion.otherAddresses', 'upstreams.opinion.otherAddressesTip'],
    ['differentRcode', 'upstreams.opinion.otherResponse', 'upstreams.opinion.otherResponseTip'],
    ['filtered', 'upstreams.opinion.filtered', 'upstreams.opinion.filteredTip'],
    ['unanswered', 'upstreams.opinion.unanswered', 'upstreams.opinion.unansweredTip'],
  ];
  const resultLabel: Record<string, MessageKey> = {
    different_addresses: 'upstreams.disagreement.otherAddresses',
    different_rcode: 'upstreams.disagreement.otherResponse',
    filtered: 'upstreams.disagreement.filtered',
  };
  const opinions = (q: S['UpstreamQuality']) => results.reduce((n, [k]) => n + (q[k] as number), 0);
  const multiNode = $derived(checks.length > 1);
  const anyQuality = $derived(checks.some((c) => c.upstreams.length > 0));
  const reload = async () => {
    upstreams = (await api.upstreams()).items;
  };
  // REQ: API-002 (T9.12) — ask the draft upstream before saving it.
  const tryUpstream = $derived({
    label: t('lists.test.label'),
    run: async (b: Record<string, unknown>) => {
      const r = await api.checkUpstream(b);
      return r.ok
        ? { ok: true, text: t('upstreams.test.works', { detail: r.detail, ms: r.elapsedMs }) }
        : { ok: false, text: t('upstreams.test.fails', { error: r.error ?? r.detail }) };
    },
  });
  // REQ: OBS-030 — the upstream whose answer times the heatmap shows.
  let latencyOf = $state('');
</script>

<div class="page">
  <h1>{t('nav.upstreams')}<HelpButton id="upstreams" /></h1>
  <ErrorNote {error} />
  <section class="card">
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>{t('flow.stage.upstream')}</th><th>{t('nav.groups')}</th><th>{t('cluster.health.title')}<HelpButton id="upstream-health" /></th><th class="num">{t('upstreams.col.requests')}</th><th class="num">{t('upstreams.col.failures')}</th>
            {#if advanced}<th class="num">{t('upstreams.col.smoothed')}</th>{/if}<th class="num">p50</th>{#if advanced}<th class="num">p99</th>{/if}
          </tr>
        </thead>
        <tbody>
          {#each upstreams as u (u.id)}
            {@const l = byKey.get(u.name)}
            <tr>
              <td><strong>{u.name}</strong>{#if advanced}<div class="muted small mono">{u.endpoint}</div>{/if}</td>
              <td>{u.groups.join(', ')}</td>
              <td><BreakerBadge value={u.breaker} /></td>
              <td class="num">{num(u.requests)}<ShareBar value={totalRequests ? (u.requests / totalRequests) * 100 : 0} color="--s-forwarded" label={t('upstreams.share.requests')} /></td>
              <td class="num">{num(u.failures)} <span class="muted small">({pct(u.requests ? (u.failures / u.requests) * 100 : 0)})</span><ShareBar value={u.requests ? (u.failures / u.requests) * 100 : 0} color="--s-blocked" label={t('upstreams.share.failures')} />
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
    {t('upstreams.health.intro')}<strong>{t('cluster.healthy')}</strong>{t('upstreams.health.answering')}<strong>{t('dashw.breaker.open')}</strong>{t('upstreams.health.stopped')}<strong>{t('dashw.breaker.halfOpen')}</strong>{t('upstreams.health.trial')}
  </p>
  <!-- REQ: OBS-030 (ADR-130) — one upstream's answer times as a shape over time. -->
  {#if upstreams.length}
    <section class="card" data-testid="upstream-latency">
      <div class="card-head">
        <h2>{t('upstreams.latency.title')}<HelpButton id="latency-heatmap" /></h2>
        <span class="pill-field bare">
          <select bind:value={latencyOf} aria-label={t('flow.stage.upstream')}>
            {#each upstreams as u (u.id)}<option value={u.name}>{u.name}</option>{/each}
          </select>
        </span>
      </div>
      {#key latencyOf}<LatencyHeatmap by="upstream" upstream={latencyOf || upstreams[0].name} testid="upstream-latency-heatmap" />{/key}
    </section>
  {/if}
  <!-- REQ: OBS-019 (ADR-108) — are the upstreams telling the truth? -->
  <section class="card" data-testid="upstream-quality">
    <h2>{t('upstreams.quality.title')}<HelpButton id="upstream-checks" /></h2>
    {#if !anyQuality}
      <p class="empty">{t('upstreams.quality.empty')}</p>
    {:else}
      <div class="table-wrap">
        <table class="compact">
          <thead>
            <tr>
              {#if multiNode}<th>{t('qw.cache.node')}</th>{/if}<th>{t('flow.stage.upstream')}</th><th>{t('upstreams.col.secondOpinions')}</th><th>{t('upstreams.col.dnssec')}</th><th>{t('upstreams.col.ede')}</th>
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
                      {#if (q[k] as number) > 0}<span class="chip" class:bad={k === 'filtered'} title={tip ? t(tip) : ''}>{tn(label, q[k] as number, { n: num(q[k] as number) })}</span>{/if}
                    {/each}
                  </td>
                  <td class="small">
                    {#if q.dnssecSecure + q.dnssecInsecure + q.dnssecBogus + q.dnssecIndeterminate === 0}<span class="muted">–</span>
                    {:else}{tn('upstreams.dnssec.secure', q.dnssecSecure, { n: num(q.dnssecSecure) })} · {tn('upstreams.dnssec.unsigned', q.dnssecInsecure, { n: num(q.dnssecInsecure) })}{#if q.dnssecBogus} · <span class="bad-text">{tn('upstreams.dnssec.bogus', q.dnssecBogus, { n: num(q.dnssecBogus) })}</span>{/if}{#if q.dnssecIndeterminate} · {tn('upstreams.dnssec.undecided', q.dnssecIndeterminate, { n: num(q.dnssecIndeterminate) })}{/if}{/if}
                  </td>
                  <td class="small">
                    {#if q.ede.length === 0}<span class="muted">{t('groups.lists.none')}</span>{/if}
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
        {t('upstreams.secondOpinionsOff.before')}<code>[upstream_check] sample_every = 1000</code>{t('upstreams.secondOpinionsOff.after')}
      </p>
    {/if}
    {#each checks.filter((c) => c.recent.length) as c (c.node ?? '')}
      <h3 class="small">{t('upstreams.disagreements')}{#if multiNode}{t('upstreams.disagreements.on', { node: c.node ?? '' })}{/if}</h3>
      <ul class="disagreements small">
        {#each c.recent.slice(0, 10) as d (`${d.at}|${d.name}`)}
          <li>
            <span class="mono">{d.name}</span> {d.qtype} · <strong>{d.upstream}</strong>: {d.answer} · <strong>{d.reference}</strong>: {d.referenceAnswer}
            <span class="chip" class:bad={d.result === 'filtered'}>{resultLabel[d.result] ? t(resultLabel[d.result]) : d.result}</span>
          </li>
        {/each}
      </ul>
    {/each}
  </section>
  <ConfigEditor kind="upstream" path="upstreams" title={t('groups.field.upstreams')} noun={t('upstreams.manage.noun')} fields={upstreamFields}
    summary={(d) => String(d.url ?? '')} onchanged={reload} formAction={tryUpstream} />
  <ConfigEditor kind="upstream_group" path="upstream-groups" title={t('upstreams.manage.groupTitle')} noun={t('upstreams.manage.groupNoun')} fields={groupFields}
    summary={(d) => `${String(d.strategy ?? 'failover')}: ${((d.members as string[]) ?? []).join(', ')}`} onchanged={reload} />
  <p class="muted small">
    {t('upstreams.forwarded.before')}<a href={href('/local-dns')}>{t('nav.localDns')}</a>{t('upstreams.forwarded.after')}<HelpButton id="routes" />
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
