<script lang="ts" module>
  // REQ: CLU-008, CLU-009 (T6.14) — the cluster at a glance, drawn from GET /cluster (no
  // dependencies): sites as boxes; nodes as chips; Kubernetes resolver pods grouped by the
  // Kubernetes node they run on (more than six fold into "+N"); a link from the primary to every
  // other node or pod group, labelled with its round-trip time when this node measured it,
  // dashed red when down, amber when its configuration is behind, and as thick as its share of
  // the queries.
  import type { S } from '../api';

  export type Node = S['ClusterNode'];
  export type Health = 'ok' | 'warn' | 'bad';

  export const health = (n: Node): Health => (!n.up ? 'bad' : !n.ready || n.configLag > 0 ? 'warn' : 'ok');
  const worst = (hs: Health[]): Health => (hs.includes('bad') ? 'bad' : hs.includes('warn') ? 'warn' : 'ok');
  export const worstOf = (ns: Node[]): Health => worst(ns.map(health));

  export const MAX_PODS = 6;
  const SITE_W = 232;
  const PAD = 12;
  const CHIP_W = SITE_W - 2 * PAD;
  const CHIP_H = 40;
  const POD_W = 44;
  /** Room on the left of the primary's site for the links to its other nodes and pods. */
  const INDENT = 16;
  const POD_H = 22;
  const POD_GAP = 6;
  const HEAD = 26;
  const GAP_X = 28;
  const GAP_Y = 64;
  const PER_ROW = 4;

  export type Box = { x: number; y: number; w: number; h: number };
  export type Chip = Box & { node: Node };
  export type PodChip = Box & { node?: Node; more?: Node[] };
  export type Group = Box & { label: string; pods: PodChip[]; nodes: Node[] };
  export type Site = Box & { name: string; chips: Chip[]; groups: Group[] };
  export type Link = { d: string; mx: number; my: number; health: Health; width: number; label?: string; key: string };
  export type Layout = { w: number; h: number; sites: Site[]; links: Link[] };

  function siteBox(name: string, nodes: Node[], hubId?: string): Site {
    const chips: Chip[] = [];
    const groups: Group[] = [];
    let y = HEAD;
    // The primary first, full width; the site's other nodes indented below it.
    const fixed = nodes.filter((n) => !n.ephemeral).sort((a, b) => Number(b.nodeId === hubId) - Number(a.nodeId === hubId));
    for (const n of fixed) {
      const indent = hubId && n.nodeId !== hubId && nodes.some((m) => m.nodeId === hubId) ? INDENT : 0;
      chips.push({ x: PAD + indent, y, w: CHIP_W - indent, h: CHIP_H, node: n });
      y += CHIP_H + 8;
    }
    const byKube = new Map<string, Node[]>();
    for (const n of nodes.filter((n) => n.ephemeral)) {
      const k = n.kubeNode ?? '';
      byKube.set(k, [...(byKube.get(k) ?? []), n]);
    }
    for (const [kube, pods] of [...byKube.entries()].sort(([a], [b]) => a.localeCompare(b))) {
      const shown = pods.length > MAX_PODS ? pods.slice(0, MAX_PODS - 1) : pods;
      const rest = pods.length > MAX_PODS ? pods.slice(MAX_PODS - 1) : [];
      const gx = PAD + INDENT;
      const chipsIn: PodChip[] = shown.map((node, i) => ({
        x: gx + 8 + (i % 3) * (POD_W + POD_GAP),
        y: y + 20 + Math.floor(i / 3) * (POD_H + POD_GAP),
        w: POD_W,
        h: POD_H,
        node,
      }));
      if (rest.length) {
        const i = shown.length;
        chipsIn.push({ x: gx + 8 + (i % 3) * (POD_W + POD_GAP), y: y + 20 + Math.floor(i / 3) * (POD_H + POD_GAP), w: POD_W, h: POD_H, more: rest });
      }
      const rows = Math.ceil(chipsIn.length / 3);
      const h = 20 + rows * (POD_H + POD_GAP) + 4;
      groups.push({ x: gx, y, w: CHIP_W - INDENT, h, label: kube ? `node ${kube}` : 'pods', pods: chipsIn, nodes: pods });
      y += h + 8;
    }
    return { x: 0, y: 0, w: SITE_W, h: y + PAD - 8, name, chips, groups };
  }

  function move(s: Site, dx: number, dy: number) {
    s.x += dx;
    s.y += dy;
    for (const c of s.chips) (c.x += dx), (c.y += dy);
    for (const g of s.groups) {
      g.x += dx;
      g.y += dy;
      for (const p of g.pods) (p.x += dx), (p.y += dy);
    }
  }

  const share = (ns: Node[]) => ns.reduce((t, n) => t + (n.querySharePercent ?? 0), 0);
  const width = (pct: number) => 1.5 + Math.min(100, pct) * 0.1;

  /** Places sites (the primary's on top, the others in rows of four below) and links. */
  export function layout(nodes: Node[]): Layout {
    const hub = nodes.find((n) => n.role.includes('primary') && n.up) ?? nodes.find((n) => n.thisNode) ?? nodes[0];
    const names = [...new Set(nodes.map((n) => n.site))];
    const top = hub?.site ?? names[0];
    const others = names.filter((s) => s !== top).sort();
    const sites = [top, ...others].filter((s) => s != null).map((s) => siteBox(s, nodes.filter((n) => n.site === s), hub?.nodeId));
    const [first, ...rest] = sites;
    if (!first) return { w: 0, h: 0, sites: [], links: [] };
    const rows: Site[][] = [];
    for (let i = 0; i < rest.length; i += PER_ROW) rows.push(rest.slice(i, i + PER_ROW));
    const rowW = (r: Site[]) => r.length * SITE_W + (r.length - 1) * GAP_X;
    const w = Math.max(SITE_W, ...rows.map(rowW)) + 2;
    move(first, (w - SITE_W) / 2, 1);
    let y = first.y + first.h + GAP_Y;
    for (const r of rows) {
      let x = (w - rowW(r)) / 2;
      for (const s of r) {
        move(s, x, y);
        x += SITE_W + GAP_X;
      }
      y += Math.max(...r.map((s) => s.h)) + GAP_Y;
    }
    const h = rows.length ? y - GAP_Y + 1 : first.y + first.h + 1;

    const links: Link[] = [];
    const hubChip = first.chips.find((c) => c.node.nodeId === hub?.nodeId);
    // Round-trip times are measured by this node, to each peer.
    const rtt = (target: Node[]): string | undefined => {
      if (hub?.thisNode) {
        const r = target.map((n) => n.rttMs).filter((v): v is number => v != null);
        return r.length ? `${Math.round(r.reduce((a, b) => a + b, 0) / r.length)} ms` : undefined;
      }
      const me = target.find((n) => n.thisNode);
      return me && hub?.rttMs != null ? `${Math.round(hub.rttMs)} ms` : undefined;
    };
    for (const s of sites) {
      const targets: { box: Box; nodes: Node[]; key: string }[] = [
        ...s.chips.filter((c) => c.node.nodeId !== hub?.nodeId).map((c) => ({ box: c as Box, nodes: [c.node], key: c.node.nodeId })),
        ...s.groups.map((g) => ({ box: g as Box, nodes: g.nodes, key: `${s.name}/${g.label}` })),
      ];
      for (const [i, t] of targets.entries()) {
        const hs = worst(t.nodes.map(health));
        let d: string, mx: number, my: number;
        if (s === first && hubChip) {
          // Inside the primary's site: down the indent, one lane per target, then in.
          // No time label here: the table has each pod's round trip.
          const x0 = hubChip.x + 5 + Math.min(i, 3) * 3;
          const y1 = t.box.y + Math.min(t.box.h / 2, 12);
          d = `M${x0} ${hubChip.y + hubChip.h} V${y1} H${t.box.x}`;
          links.push({ d, mx: x0, my: y1, health: hs, width: 1 + Math.min(100, share(t.nodes)) * 0.03, key: t.key });
          continue;
        } else {
          const x0 = first.x + first.w / 2;
          const y0 = first.y + first.h;
          const x1 = t.box.x + t.box.w / 2;
          const y1 = t.box.y;
          d = `M${x0} ${y0} C${x0} ${y0 + GAP_Y / 2} ${x1} ${y1 - GAP_Y / 2} ${x1} ${y1}`;
          mx = (x0 + x1) / 2;
          my = (y0 + y1) / 2;
        }
        links.push({ d, mx, my, health: hs, width: width(share(t.nodes)), label: rtt(t.nodes), key: t.key });
      }
    }
    return { w, h, sites, links };
  }
</script>

<script lang="ts">
  let { nodes, onselect }: { nodes: Node[]; onselect?: (n: Node) => void } = $props();

  const L = $derived(layout(nodes));
  const label = (n: Node) => n.pod ?? n.nodeId.slice(0, 8);
  // Long names (Kubernetes pods: telltaledns-756965cdc7-8j9h9) are shortened in the middle to
  // fit: the end tells pods apart. The full name is in the tooltip. Widths are estimates per
  // character for the UI font at that size.
  const fit = (text: string, px: number, perChar: number) => {
    const max = Math.max(4, Math.floor(px / perChar));
    if (text.length <= max) return text;
    const head = Math.ceil((max - 1) * 0.45);
    return `${text.slice(0, head)}…${text.slice(text.length - (max - 1 - head))}`;
  };
  // The second line: load; whole items are left out (round trip first, then share) when they
  // don't fit, rather than cutting words. The role is the badge.
  const sub = (n: Node, px: number) => {
    const parts = [
      n.thisNode ? 'you' : '',
      `${n.qps} q/s`,
      n.querySharePercent != null ? `${Math.round(n.querySharePercent)}%` : '',
      n.rttMs != null && !n.thisNode ? `${Math.round(n.rttMs)} ms` : '',
    ].filter(Boolean);
    while (parts.length > 1 && parts.join(' · ').length * 5.6 > px) parts.pop();
    return parts.join(' · ');
  };
  const podLabel = (n: Node) => (n.pod ? n.pod.slice(-5) : n.nodeId.slice(0, 5));
  const role = (n: Node) => (n.witness ? 'witness' : n.role);
  // T6.14 — the primary stands out: a filled badge and an accent stripe; replicas and
  // witnesses get a quiet outlined badge, an emergency primary an amber one.
  const badge = (n: Node) =>
    n.role.includes('emergency')
      ? { kind: 'emergency', text: 'EMERGENCY' }
      : n.role === 'primary'
        ? { kind: 'primary', text: 'PRIMARY' }
        : { kind: 'replica', text: n.witness ? 'witness' : 'replica' };
  const badgeW = (n: Node) => badge(n).text.length * 6.2 + 12;
  const describe = (n: Node) =>
    [
      `${n.pod ?? n.nodeId} (${n.site}, ${role(n)})`,
      n.kubeNode ? `on Kubernetes node ${n.kubeNode}` : '',
      n.up ? (n.ready ? 'up, serving' : 'up, not ready') : 'down',
      n.configLag ? `configuration ${n.configLag} behind` : 'in sync',
      `${n.qps} q/s${n.querySharePercent != null ? `, ${n.querySharePercent}% of queries` : ''}`,
      n.cacheHitPercent != null ? `cache ${n.cacheHitPercent}% hits` : '',
      n.restarts ? `${n.restarts} restart${n.restarts === 1 ? '' : 's'}` : '',
    ]
      .filter(Boolean)
      .join(' · ');
  const key = (e: KeyboardEvent, n: Node) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      onselect?.(n);
    }
  };
</script>

<div class="topo" data-testid="cluster-topology">
  <svg width={L.w} height={L.h} viewBox={`0 0 ${L.w} ${L.h}`} role="group" aria-label="Cluster topology">
    <!-- Site boxes, then the links over them, then the nodes and pods on top. -->
    {#each L.sites as s (s.name)}
      <g data-testid="topology-site">
        <rect class="site" x={s.x} y={s.y} width={s.w} height={s.h} rx="10" />
        <text class="site-name" x={s.x + PAD} y={s.y + 18}>{fit(s.name, s.w - 2 * PAD, 7.5)}<title>{s.name}</title></text>
      </g>
    {/each}
    {#each L.links as l (l.key)}
      <path class="link {l.health}" d={l.d} stroke-width={l.width} />
      {#if l.label}<text class="rtt" x={l.mx + 6} y={l.my}>{l.label}</text>{/if}
    {/each}
    {#each L.sites as s (s.name)}
      <g>
        {#each s.chips as c (c.node.nodeId)}
          {@const b = badge(c.node)}
          {@const bw = badgeW(c.node)}
          <g
            class="chip {health(c.node)}"
            class:me={c.node.thisNode}
            role="button"
            tabindex="0"
            aria-label={describe(c.node)}
            data-testid="topology-node"
            onclick={() => onselect?.(c.node)}
            onkeydown={(e) => key(e, c.node)}
          >
            <title>{describe(c.node)}</title>
            <rect x={c.x} y={c.y} width={c.w} height={c.h} rx="8" />
            {#if b.kind === 'primary'}<rect class="stripe" x={c.x + 3} y={c.y + 6} width="3" height={c.h - 12} rx="1.5" />{/if}
            <circle class="dot" cx={c.x + 14} cy={c.y + 14} r="4" />
            <text class="name" x={c.x + 24} y={c.y + 17}>{fit(label(c.node), c.w - 32 - bw - 6, 7.2)}</text>
            <g class="role-badge {b.kind}" data-testid="topology-role">
              <rect x={c.x + c.w - bw - 6} y={c.y + 6} width={bw} height="15" rx="7.5" />
              <text x={c.x + c.w - 6 - bw / 2} y={c.y + 17} text-anchor="middle">{b.text}</text>
            </g>
            <text class="sub" x={c.x + 24} y={c.y + 32}>{sub(c.node, c.w - 32)}</text>
          </g>
        {/each}
        {#each s.groups as g (g.label)}
          <rect class="group" x={g.x} y={g.y} width={g.w} height={g.h} rx="6" />
          {@const count = ` · ${g.nodes.length} replica pod${g.nodes.length === 1 ? '' : 's'}`}
          <text class="group-name" x={g.x + 8} y={g.y + 14}>{fit(g.label, g.w - 16 - count.length * 6, 6)}{count}<title>{g.label}</title></text>
          {#each g.pods as p, i (p.node?.nodeId ?? `more-${i}`)}
            {@const n = p.node ?? p.more?.[0]}
            {#if n}
              <g
                class="pod {p.more ? worstOf(p.more) : health(n)}"
                role="button"
                tabindex="0"
                aria-label={p.more ? `${p.more.length} more pods on ${g.label}` : describe(n)}
                data-testid="topology-pod"
                onclick={() => onselect?.(n)}
                onkeydown={(e) => key(e, n)}
              >
                <title>{p.more ? `${p.more.length} more pods` : describe(n)}</title>
                <rect x={p.x} y={p.y} width={p.w} height={p.h} rx="5" />
                <text x={p.x + p.w / 2} y={p.y + 15} text-anchor="middle">{p.more ? `+${p.more.length}` : podLabel(n)}</text>
              </g>
            {/if}
          {/each}
        {/each}
      </g>
    {/each}
  </svg>
  <p class="legend muted small">
    <span class="legend-badge">PRIMARY</span> publishes the configuration; replicas follow it ·
    <span class="key ok"></span> serving, in sync <span class="key warn"></span> not ready or behind <span class="key bad"></span> down ·
    line thickness = share of queries{#if L.links.some((l) => l.label)}{' · times are round trips from this node'}{/if}
  </p>
</div>

<style>
  .topo {
    overflow-x: auto;
  }
  svg {
    display: block;
    margin: 0 auto;
    font-size: 12px;
  }
  .site {
    fill: var(--surface-2);
    stroke: var(--border);
  }
  .site-name {
    font-weight: 700;
    fill: var(--text);
  }
  .group {
    fill: none;
    stroke: var(--border);
    stroke-dasharray: 3 3;
  }
  .group-name {
    font-size: 11px;
    fill: var(--muted);
  }
  .link {
    fill: none;
    stroke: var(--muted);
    opacity: 0.7;
  }
  .link.warn {
    stroke: var(--warn);
    opacity: 1;
  }
  .link.bad {
    stroke: var(--bad);
    stroke-dasharray: 6 4;
    opacity: 1;
  }
  .rtt {
    font-size: 11px;
    fill: var(--muted);
  }
  .chip,
  .pod {
    cursor: pointer;
    outline: none;
  }
  .chip rect,
  .pod rect {
    fill: var(--surface);
    stroke: var(--ok);
    stroke-width: 1.5;
  }
  .chip.warn rect,
  .pod.warn rect {
    stroke: var(--warn);
  }
  .chip.bad rect,
  .pod.bad rect {
    stroke: var(--bad);
    stroke-dasharray: 4 3;
  }
  .chip.me rect {
    stroke-width: 2.5;
  }
  .chip:focus-visible rect,
  .pod:focus-visible rect,
  .chip:hover rect,
  .pod:hover rect {
    stroke: var(--focus, var(--accent));
    stroke-width: 2.5;
  }
  .dot {
    fill: var(--ok);
  }
  .chip.warn .dot {
    fill: var(--warn);
  }
  .chip.bad .dot {
    fill: var(--bad);
  }
  .name {
    font-weight: 600;
    fill: var(--text);
  }
  .sub {
    font-size: 11px;
    fill: var(--muted);
  }
  .pod text {
    font-size: 11px;
    fill: var(--text);
    font-family: var(--mono);
  }
  .stripe {
    fill: var(--accent-strong);
  }
  .chip .role-badge rect {
    fill: none;
    stroke: var(--border);
    stroke-width: 1;
    stroke-dasharray: none;
  }
  .role-badge text {
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.02em;
    fill: var(--muted);
  }
  .chip .role-badge.primary rect {
    fill: var(--accent-strong);
    stroke: var(--accent-strong);
  }
  .role-badge.primary text {
    fill: var(--accent-text);
  }
  .chip .role-badge.emergency rect {
    stroke: var(--warn);
  }
  .role-badge.emergency text {
    fill: var(--warn-strong, var(--warn));
  }
  .legend-badge {
    display: inline-block;
    padding: 0 6px;
    border-radius: 999px;
    font-size: 10px;
    font-weight: 600;
    background: var(--accent-strong);
    color: var(--accent-text);
    vertical-align: 1px;
  }
  .legend {
    text-align: center;
    margin: 6px 0 0;
  }
  .key {
    display: inline-block;
    width: 10px;
    height: 10px;
    border-radius: 3px;
    border: 2px solid var(--ok);
    margin: 0 2px 0 8px;
    vertical-align: -1px;
  }
  .key.warn {
    border-color: var(--warn);
  }
  .key.bad {
    border-color: var(--bad);
    border-style: dashed;
  }
</style>
