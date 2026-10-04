<script lang="ts">
  // REQ: API-011, ADR-036 — how one question travels: a device asks TelltaleDNS, which answers
  // from memory, from your own names, with a block, from another server, or from the public
  // DNS servers. The path in `highlight` is drawn bold; the rest stays faint. Inline SVG (no
  // library, CSP-safe), with a text equivalent for screen readers and small screens.
  import type { FlowPath } from '../help';

  let {
    highlight,
    device = 'A device',
    name = 'a name',
    detail = '',
  }: { highlight: FlowPath; device?: string; name?: string; detail?: string } = $props();

  const outs: { id: FlowPath; label: string; sub: string }[] = [
    { id: 'cache', label: 'From memory', sub: 'cache' },
    { id: 'local', label: 'Your names', sub: 'local records' },
    { id: 'blocked', label: 'Blocked', sub: 'filter lists' },
    { id: 'route', label: 'Another server', sub: 'routes' },
    { id: 'upstream', label: 'Public DNS', sub: 'upstreams' },
  ];

  const sentence: Record<FlowPath, string> = {
    cache: 'answers from memory, because it was asked recently',
    local: 'answers with one of your own names',
    blocked: 'blocks it, so it never loads',
    route: 'asks the server you chose for that domain',
    upstream: 'asks a public DNS server and remembers the answer',
    refused: 'refuses, because the device may not use this server',
  };
  const text = $derived(`${device} asks for ${name}; TelltaleDNS ${sentence[highlight]}${detail ? ` (${detail})` : ''}.`);
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
    <text x="73" y="106" text-anchor="middle" class="flow-text">{device.length > 18 ? device.slice(0, 17) + '…' : device}</text>
    <text x="73" y="124" text-anchor="middle" class="flow-sub">asks for a name</text>
    <path d="M138 110 H226" class="flow-line" class:flow-on={highlight !== 'refused'} marker-end="url(#flow-arrow)" />
    <rect x="228" y="80" width="150" height="60" rx="12" class="flow-core" />
    <text x="303" y="107" text-anchor="middle" class="flow-core-text">TelltaleDNS</text>
    <text x="303" y="125" text-anchor="middle" class="flow-core-sub">{highlight === 'refused' ? 'refused' : 'decides'}</text>
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
