<script lang="ts">
  // REQ: OBS-016 (ADR-105) — the service-level objectives: how often DNS answers well, the
  // error budget left over the window, and how fast it's being spent right now.
  import type { S } from '../api';
  import { short } from '../format';
  import { href } from '../router.svelte';
  import { t, tn, type MessageKey } from '../i18n';
  import HelpButton from './HelpButton.svelte';
  import Tip from './Tip.svelte';

  let { slo }: { slo: S['SloStatus'] | null } = $props();

  // The words are keys: what they say follows the language on screen, the tone doesn't.
  const titles: Record<string, MessageKey> = {
    availability: 'dashboard.slo.availability',
    latency: 'dashboard.slo.latency',
  };
  const alerts: Record<string, { text: MessageKey; tone: string; tip: MessageKey }> = {
    fast: { text: 'slo.alert.fast', tone: 'bad', tip: 'slo.alert.fastTip' },
    slow: { text: 'slo.alert.slow', tone: 'bad', tip: 'slo.alert.slowTip' },
    ticket: { text: 'slo.alert.ticket', tone: 'warn', tip: 'slo.alert.ticketTip' },
  };
  const percent = (v: number | null | undefined, digits = 2) =>
    v == null ? '–' : `${v.toFixed(v >= 99.995 || v === 0 ? 0 : digits)}%`;
  const budgetTone = (v: number | null | undefined) => (v == null ? '' : v >= 50 ? 'ok' : v >= 25 ? 'warn' : 'bad');
  const burnText = (b: S['SloBurn']) => (b.rate == null ? '–' : `${b.rate >= 10 ? b.rate.toFixed(0) : b.rate.toFixed(1)}×`);
  const burnTip = (b: S['SloBurn']) =>
    b.rate == null
      ? t('slo.burn.none', { window: b.window })
      : t('slo.burn.some', { window: b.window, bad: short(b.bad), total: short(b.total) });
</script>

<section class="card slo" data-testid="slo-card">
  <div class="card-head">
    <h2>
      {t('slo.title')}
      {#if slo?.enabled}<span class="muted small">{tn('slo.window', slo.windowDays)}</span>{/if}
      <HelpButton id="slo" />
    </h2>
  </div>
  {#if !slo}
    <p class="empty">{t('slo.loading')}</p>
  {:else if !slo.enabled}
    <p class="empty">{t('slo.off')}<code>[slo] enabled = false</code>{t('slo.offEnd')}</p>
  {:else}
    {#if slo.missingNodes?.length}
      <p class="small muted">{t('slo.missing', { nodes: slo.missingNodes.join(', ') })}</p>
    {/if}
    <div class="objectives">
      {#each slo.objectives as o (o.name)}
        {@const left = o.budgetRemainingPercent}
        <div class="objective" data-testid={`slo-${o.name}`}>
          <div class="row">
            <strong>{titles[o.name] ? t(titles[o.name]) : o.name}</strong>
            <span class="spacer"></span>
            {#if o.alert && alerts[o.alert]}
              <Tip text={t(alerts[o.alert].tip)}><span class="badge {alerts[o.alert].tone}">{t(alerts[o.alert].text)}</span></Tip>
            {:else if o.total > 0}
              <span class="badge ok">{t('slo.onTrack')}</span>
            {/if}
          </div>
          <div class="muted small">{t('slo.target', { means: o.goodMeans, target: o.targetPercent })}</div>
          <div class="figure">
            <span class="big">{percent(o.sliPercent, 3)}</span>
            <span class="muted small">{t('slo.ofAnswers', { answers: short(o.total) })}</span>
          </div>
          <div class="budget" title={t('slo.budgetTitle')}>
            <div class="bar {budgetTone(left)}"><span style:width={`${Math.max(0, Math.min(100, left ?? 0))}%`}></span></div>
            <span class="small">
              {#if left == null}{t('slo.budget.none')}{:else if left < 0}{t('slo.budget.overspent')}{:else}{t('slo.budget.left', { pct: left.toFixed(0) })}{/if}
            </span>
          </div>
          <div class="burns small">
            <span class="muted">{t('slo.burnRate')}</span>
            {#each o.burnRates as b (b.window)}
              <Tip text={burnTip(b)}><span class="burn" class:hot={(b.rate ?? 0) >= 6}>{b.window} {burnText(b)}</span></Tip>
            {/each}
          </div>
          <!-- REQ: OBS-027 — who and what spent it. -->
          <a class="small" href={href('/analyze', { tab: 'budget', objective: o.name })} data-testid={`slo-who-${o.name}`}>{t('slo.who')}</a>
        </div>
      {/each}
    </div>
  {/if}
</section>

<style>
  .objectives {
    display: grid;
    gap: var(--gap);
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  }
  .objective {
    display: grid;
    gap: 6px;
  }
  .figure .big {
    font-size: 1.6rem;
    font-weight: 650;
    font-variant-numeric: tabular-nums;
    margin-right: 6px;
  }
  .budget {
    display: grid;
    gap: 4px;
  }
  .bar {
    height: 8px;
    background: var(--surface-2);
    border-radius: 999px;
    overflow: hidden;
  }
  .bar span {
    display: block;
    height: 100%;
    border-radius: 999px;
    background: var(--muted);
  }
  .bar.ok span {
    background: var(--ok);
  }
  .bar.warn span {
    background: var(--warn);
  }
  .bar.bad span {
    background: var(--bad);
  }
  .burns {
    display: flex;
    flex-wrap: wrap;
    gap: 4px 10px;
    align-items: baseline;
  }
  .burn {
    font-variant-numeric: tabular-nums;
  }
  .burn.hot {
    color: var(--bad);
    font-weight: 600;
  }
</style>
