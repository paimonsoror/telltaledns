<script lang="ts">
  // REQ: API-011, ADR-036 — how one question travels: a device asks TelltaleDNS, which answers
  // from memory, from your own names, with a block, from another server, or from the public
  // DNS servers. The path in `highlight` is drawn bold; the rest stays faint. Inline SVG (no
  // library, CSP-safe), with a text equivalent for screen readers and small screens.
  import type { FlowPath } from '../help';
  import { t, type MessageKey } from '../i18n';

  let {
    highlight,
    device,
    name,
    detail = '',
  }: { highlight: FlowPath; device?: string; name?: string; detail?: string } = $props();

  // The words are looked up in the language on screen: `t()` reads the locale, so a diagram
  // that is on screen when the language changes is redrawn in the other one. A caller that
  // passes its own device or name (the explain view, a change preview) keeps them as they are.
  const deviceWord = $derived(device ?? t('help.flow.aDevice'));
  const nameWord = $derived(name ?? t('help.flow.aName'));
  const shown = $derived(deviceWord.length > 18 ? deviceWord.slice(0, 17) + '…' : deviceWord);

  const outs: { id: FlowPath; label: string; sub: string }[] = $derived([
    { id: 'cache', label: t('help.flow.fromMemory'), sub: t('help.flow.cacheSub') },
    { id: 'local', label: t('help.flow.local'), sub: t('help.flow.localSub') },
    { id: 'blocked', label: t('help.flow.blocked'), sub: t('help.flow.blockedSub') },
    { id: 'route', label: t('help.flow.route'), sub: t('help.flow.routeSub') },
    { id: 'upstream', label: t('help.flow.upstream'), sub: t('help.flow.upstreamSub') },
  ]);

  const answers: Record<FlowPath, MessageKey> = {
    cache: 'help.flow.answer.cache',
    local: 'help.flow.answer.local',
    blocked: 'help.flow.answer.blocked',
    route: 'help.flow.answer.route',
    upstream: 'help.flow.answer.upstream',
    refused: 'help.flow.answer.refused',
  };
  const text = $derived(
    t('help.flow.sentence', {
      device: deviceWord,
      name: nameWord,
      outcome: t(answers[highlight]),
      detail: detail ? ` (${detail})` : '',
    }),
  );
  const y = (i: number) => 20 + i * 40;
</script>

<figure class="flow">
  <svg viewBox="0 0 640 220" role="img" aria-label={text}>
    <defs>
      <marker id="flow-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto">
        <path d="M0 0 L10 5 L0 10 z" class="flow-head" />
      </marker>
    </defs>
    <rect x="8" y="84" width="130" height="52" rx="10" class="flow-box" class:flow-refused={highlight === 'refused'} />
    <text x="73" y="106" text-anchor="middle" class="flow-text">{shown}</text>
    <text x="73" y="124" text-anchor="middle" class="flow-sub">{t('help.flow.asks')}</text>
    <path d="M138 110 H226" class="flow-line" class:flow-on={highlight !== 'refused'} marker-end="url(#flow-arrow)" />
    <rect x="228" y="80" width="150" height="60" rx="12" class="flow-core" />
    <text x="303" y="107" text-anchor="middle" class="flow-core-text">TelltaleDNS</text>
    <text x="303" y="125" text-anchor="middle" class="flow-core-sub">{highlight === 'refused' ? t('help.flow.refused') : t('help.flow.decides')}</text>
    {#each outs as o, i (o.id)}
      <path
        d={`M378 110 C420 110 420 ${y(i) + 18} 462 ${y(i) + 18}`}
        class="flow-line"
        class:flow-on={o.id === highlight}
        marker-end="url(#flow-arrow)"
      />
      <rect x="464" y={y(i)} width="168" height="36" rx="8" class="flow-box" class:flow-pick={o.id === highlight} class:flow-blocked={o.id === 'blocked' && highlight === 'blocked'} />
      <text x="476" y={y(i) + 16} class="flow-text">{o.label}</text>
      <text x="476" y={y(i) + 30} class="flow-sub">{o.sub}</text>
    {/each}
  </svg>
  <figcaption>{text}</figcaption>
</figure>

<style>
  .flow {
    margin: 0;
  }
  .flow svg {
    display: block;
    width: 100%;
    height: auto;
    max-width: 640px;
  }
  .flow figcaption {
    font-size: 13px;
    color: var(--muted);
    margin-top: 6px;
  }
  :global(.flow-box) {
    fill: var(--surface);
    stroke: var(--border);
    stroke-width: 1.5;
  }
  :global(.flow-pick) {
    stroke: var(--accent);
    stroke-width: 2.5;
  }
  :global(.flow-blocked) {
    stroke: var(--bad);
  }
  :global(.flow-refused) {
    stroke: var(--bad);
    stroke-width: 2.5;
  }
  :global(.flow-core) {
    fill: var(--brand);
  }
  :global(.flow-core-text) {
    fill: #fff;
    font-weight: 700;
    font-size: 14px;
  }
  :global(.flow-core-sub) {
    fill: #fff;
    opacity: 0.8;
    font-size: 11px;
  }
  :global(.flow-text) {
    fill: var(--text);
    font-size: 13px;
    font-weight: 600;
  }
  :global(.flow-sub) {
    fill: var(--muted);
    font-size: 11px;
  }
  :global(.flow-line) {
    fill: none;
    stroke: var(--border);
    stroke-width: 1.5;
    opacity: 0.6;
  }
  :global(.flow-line.flow-on) {
    stroke: var(--accent);
    stroke-width: 3;
    opacity: 1;
  }
  :global(.flow-head) {
    fill: var(--accent);
  }
</style>
