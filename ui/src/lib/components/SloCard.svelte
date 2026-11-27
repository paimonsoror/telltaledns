<script lang="ts">
  // REQ: OBS-016 (ADR-105) — the service-level objectives: how often DNS answers well, the
  // error budget left over the window, and how fast it's being spent right now.
  import type { S } from '../api';
  import { short } from '../format';
  import { href } from '../router.svelte';
  import HelpButton from './HelpButton.svelte';
  import Tip from './Tip.svelte';
  import { own, tr } from '../i18n';
  import { objectiveTitle } from '../objectives';
  import T from '../i18n/T.svelte';
  const { t } = tr('sloCard');

  let { slo }: { slo: S['SloStatus'] | null } = $props();

  // The objectives' names and alert levels come from the server: read with `Object.hasOwn`; one the
  // UI doesn't know shows as it is.
  const alerts: Record<string, { text: string; tone: string; tip: string }> = {
    fast: {
      text: t('burning fast'),
      tone: 'bad',
      tip: t('Over the last hour (and the last 5 minutes) the budget is going more than 14 times faster than it can last: at this rate a month’s budget is gone in about two days.'),
    },
    slow: {
      text: t('burning'),
      tone: 'bad',
      tip: t('Over the last 6 hours (and the last 30 minutes) the budget is going more than 6 times faster than it can last.'),
    },
    ticket: {
      text: t('on course to run out'),
      tone: 'warn',
      tip: t('Over the last 3 days the budget has been going faster than it can last: worth a look this week.'),
    },
  };
  const percent = (v: number | null | undefined, digits = 2) =>
    v == null ? '–' : `${v.toFixed(v >= 99.995 || v === 0 ? 0 : digits)}%`;
  const budgetTone = (v: number | null | undefined) => (v == null ? '' : v >= 50 ? 'ok' : v >= 25 ? 'warn' : 'bad');
  const burnText = (b: S['SloBurn']) => (b.rate == null ? '–' : `${b.rate >= 10 ? b.rate.toFixed(0) : b.rate.toFixed(1)}×`);
  const burnTip = (b: S['SloBurn']) =>
    b.rate == null
      ? t('No answers to judge in the last {window}.', { window: b.window })
      : t('Last {window}: {bad} bad of {total} answers. 1× spends exactly the budget over the window.', { window: b.window, bad: short(b.bad), total: short(b.total) });
</script>

{#snippet code(x: string)}<code translate="no">{x}</code>{/snippet}

<section class="card slo" data-testid="slo-card">
  <div class="card-head">
    <h2>
      {t('Service level')}
      {#if slo?.enabled}<span class="muted small">{t('(last {n} days)', { n: slo.windowDays })}</span>{/if}
      <HelpButton id="slo" />
    </h2>
  </div>
  {#if !slo}
    <p class="empty">{t('Loading…')}</p>
  {:else if !slo.enabled}
    <p class="empty"><T ctx="sloCard" msg={'Objectives are off (<code>[slo] enabled = false</code>).'} {code} /></p>
  {:else}
    {#if slo.missingNodes?.length}
      <p class="small muted">{t('Without {nodes}: they didn’t answer.', { nodes: slo.missingNodes.join(', ') })}</p>
    {/if}
    <div class="objectives">
      {#each slo.objectives as o (o.name)}
        {@const left = o.budgetRemainingPercent}
        {@const level = own(alerts, o.alert) ?? null}
        <div class="objective" data-testid={`slo-${o.name}`}>
          <div class="row">
            <strong>{objectiveTitle(o.name)}</strong>
            <span class="spacer"></span>
            {#if level}
              <Tip text={level.tip}><span class="badge {level.tone}">{level.text}</span></Tip>
            {:else if o.total > 0}
              <span class="badge ok">{t('on track')}</span>
            {/if}
          </div>
          <div class="muted small">{t('{means} · target {target}%', { means: o.goodMeans, target: o.targetPercent })}</div>
          <div class="figure">
            <span class="big">{percent(o.sliPercent, 3)}</span>
            <span class="muted small">{t('of {n} answers', { n: short(o.total) })}</span>
          </div>
          <div class="budget" title={t('Error budget left: the bad answers the target still allows over the window')}>
            <div class="bar {budgetTone(left)}"><span style:width={`${Math.max(0, Math.min(100, left ?? 0))}%`}></span></div>
            <span class="small">
              {#if left == null}{t('no answers yet')}{:else if left < 0}{t('budget overspent')}{:else}{t('{n}% of the error budget left', { n: left.toFixed(0) })}{/if}
            </span>
          </div>
          <div class="burns small">
            <span class="muted">{t('Burn rate')}</span>
            {#each o.burnRates as b (b.window)}
              <Tip text={burnTip(b)}><span class="burn" class:hot={(b.rate ?? 0) >= 6}>{b.window} {burnText(b)}</span></Tip>
            {/each}
          </div>
          <!-- REQ: OBS-027 — who and what spent it. -->
          <a class="small" href={href('/analyze', { tab: 'budget', objective: o.name })} data-testid={`slo-who-${o.name}`}>{t('Who spent it?')}</a>
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
