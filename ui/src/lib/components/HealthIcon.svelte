<script lang="ts">
  // REQ: OBS-015 (ADR-104) — one icon for how TelltaleDNS is doing, next to the project links:
  // a circle with a check (healthy, quiet), a triangle with "!" (degraded), an octagon with "×"
  // (severe). The shape changes with the color, so it reads without color too. Clicking lists
  // the reasons, each with its node and where to look.
  import { health } from '../health.svelte';
  import { dateTime } from '../format';
  import Icon from './Icon.svelte';
  import { t, tn, type MessageKey } from '../i18n';

  let open = $state(false);
  let wrap = $state<HTMLElement | undefined>();
  let panel = $state<HTMLElement | undefined>();
  // The sidebar scrolls, is 72 px wide at medium widths, and is its own stacking context
  // (sticky), so the panel lives in <body>, fixed to the viewport just above the button.
  function portal(node: HTMLElement) {
    document.body.appendChild(node);
    return {
      destroy() {
        node.remove();
      },
    };
  }
  let pos = $state({ left: 0, bottom: 0 });
  function toggle() {
    open = !open;
    const r = wrap?.getBoundingClientRect();
    if (open && r) {
      pos = {
        left: Math.max(8, Math.min(r.left, window.innerWidth - 336)),
        bottom: window.innerHeight - r.top + 6,
      };
    }
  }
  const h = $derived(health.value);
  const level = $derived(h?.level ?? 'healthy');
  // The words for a level; a level this build doesn't know yet stays as the server said it.
  const LEVEL: Record<string, MessageKey> = {
    healthy: 'nav.health.level.healthy',
    degraded: 'nav.health.level.degraded',
    severe: 'nav.health.level.severe',
  };
  const levelWord = (l: string) => (LEVEL[l] ? t(LEVEL[l]) : l);
  const label = $derived(
    h === null
      ? t('nav.health.aria.checking')
      : level === 'healthy'
        ? t('nav.health.aria.ok')
        : tn('nav.health.aria.reasons', h.reasons.length, { level: levelWord(level).toLowerCase() }),
  );

  function outside(e: MouseEvent) {
    const t = e.target as Node;
    if (open && wrap && !wrap.contains(t) && !panel?.contains(t)) open = false;
  }
  function key(e: KeyboardEvent) {
    if (open && e.key === 'Escape') open = false;
  }
</script>

<span class="health" bind:this={wrap}>
  <button
    class="health-btn {level}"
    aria-label={label}
    title={label}
    aria-expanded={open}
    aria-haspopup="dialog"
    data-testid="health-icon"
    data-level={level}
    onclick={toggle}><Icon name={`health-${level}`} size={18} /></button
  >
  {#if open}
    <div class="panel" role="dialog" aria-label={t('nav.health.title')} data-testid="health-panel" bind:this={panel} use:portal style:left={`${pos.left}px`} style:bottom={`${pos.bottom}px`}>
      <p class="head"><span class="badge {level === 'healthy' ? 'ok' : level === 'severe' ? 'bad' : 'warn'}">{levelWord(level)}</span></p>
      {#if h === null}
        <p class="small muted">{t('nav.health.checking')}</p>
      {:else if h.reasons.length === 0}
        <p class="small">{t('nav.health.allGood')}</p>
      {:else}
        <ul>
          {#each h.reasons as r, i (i)}
            <li class={r.level}>
              <span class="small">{#if r.node}<strong>{r.node}</strong>: {/if}{r.summary}</span>
              {#if r.link}<a class="small" href={r.link} onclick={() => (open = false)}>{t('nav.health.look')}</a>{/if}
            </li>
          {/each}
        </ul>
      {/if}
      {#if h?.maintenance?.length}
        <!-- REQ: OPS-010 — nodes in maintenance are left out of the level; say so. -->
        <p class="small" data-testid="health-maintenance">
          {tn('nav.health.maintenance', h.maintenance.length)}
          {#each h.maintenance as m, i (i)}{i ? t('nav.health.separator') : ''}<strong>{m.node}</strong>
            {t('nav.health.until', { time: dateTime(Date.parse(m.until) / 1000), reason: m.reason })}{/each}
        </p>
      {/if}
      {#if h && h.missingNodes && h.missingNodes.length > 0}
        <p class="small muted">{t('nav.health.missing', { nodes: h.missingNodes.join(', ') })}</p>
      {/if}
      {#if h?.checkedAt}<p class="small muted">{t('nav.health.checked', { time: dateTime(Date.parse(h.checkedAt) / 1000) })}</p>{/if}
    </div>
  {/if}
</span>

<svelte:window onclick={outside} onkeydown={key} />

<style>
  .health {
    position: relative;
    display: inline-flex;
  }
  .health-btn {
    display: grid;
    place-items: center;
    width: 34px;
    height: 34px;
    padding: 0;
    border: 0;
    border-radius: 8px;
    background: none;
    color: var(--side-muted);
    cursor: pointer;
  }
  .health-btn:hover,
  .health-btn:focus-visible {
    background: var(--side-hover);
    color: var(--side-text);
  }
  .health-btn.degraded {
    color: var(--warn);
  }
  .health-btn.severe {
    color: var(--bad);
  }
  .panel {
    position: fixed;
    z-index: 40;
    width: min(320px, calc(100vw - 16px));
    padding: 10px 12px;
    border-radius: 10px;
    background: var(--surface);
    color: var(--text);
    border: 1px solid var(--border);
    box-shadow: var(--shadow, 0 4px 16px rgb(0 0 0 / 15%));
  }
  .panel p {
    margin: 0 0 6px;
  }
  .panel ul {
    margin: 0 0 6px;
    padding: 0;
    list-style: none;
    display: grid;
    gap: 6px;
  }
  .panel li {
    display: flex;
    gap: 8px;
    align-items: baseline;
    justify-content: space-between;
    padding-left: 8px;
    border-left: 3px solid var(--warn);
  }
  .panel li.severe {
    border-left-color: var(--bad);
  }
</style>
