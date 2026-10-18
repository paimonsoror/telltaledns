// REQ: OBS-032 (ADR-132) — the query flow's layout: four columns (groups, decisions, upstreams,
// response codes), node heights on one scale (a column's nodes add up to what flows through
// it), links stacked within their nodes so each band's width is its exact count. Pure: the
// page draws it as SVG.

export type FlowNode = { id: string; stage: string; name: string; count: number; deadEnd: number };
export type FlowLink = { source: string; target: string; count: number; failure: boolean };

export const STAGES = ['group', 'status', 'upstream', 'rcode'] as const;
export const STAGE_LABEL: Record<string, string> = {
  group: 'Groups',
  status: 'Decision',
  upstream: 'Upstream',
  rcode: 'Response',
};

export type PlacedNode = FlowNode & { col: number; x: number; y: number; w: number; h: number };
export type PlacedLink = FlowLink & {
  /** The band's thickness. */
  width: number;
  /** Centre line: from the source's edge to the target's. */
  x0: number;
  y0: number;
  x1: number;
  y1: number;
  d: string;
};
export type Layout = { nodes: PlacedNode[]; links: PlacedLink[]; scale: number; vertical: boolean; width: number; height: number };

/**
 * Folds nodes carrying less than `share` of `total` into one `<stage>:other` node per stage
 * (their links merged), so the diagram stays readable; `share` 0 keeps everything.
 */
export function fold(nodes: FlowNode[], links: FlowLink[], total: number, share: number): { nodes: FlowNode[]; links: FlowLink[]; folded: number } {
  if (share <= 0 || total <= 0) return { nodes, links, folded: 0 };
  const min = total * share;
  const to = new Map<string, string>();
  for (const n of nodes) if (n.count < min) to.set(n.id, `${n.stage}:other`);
  // A stage with one small node keeps it: folding it would only rename it.
  for (const s of STAGES) {
    const small = nodes.filter((n) => n.stage === s && to.has(n.id));
    if (small.length === 1) to.delete(small[0].id);
  }
  if (!to.size) return { nodes, links, folded: 0 };
  const map = (id: string) => to.get(id) ?? id;
  const byId = new Map<string, FlowNode>();
  for (const n of nodes) {
    const id = map(n.id);
    const into = byId.get(id);
    if (into) {
      into.count += n.count;
      into.deadEnd += n.deadEnd;
    } else byId.set(id, { ...n, id, name: id === n.id ? n.name : 'other' });
  }
  const byPair = new Map<string, FlowLink>();
  for (const l of links) {
    const k = `${map(l.source)}\u0000${map(l.target)}`;
    const into = byPair.get(k);
    if (into) {
      into.count += l.count;
      into.failure ||= l.failure;
    } else byPair.set(k, { ...l, source: map(l.source), target: map(l.target) });
  }
  const order = (a: FlowNode, b: FlowNode) =>
    STAGES.indexOf(a.stage as never) - STAGES.indexOf(b.stage as never) || Number(a.name === 'other') - Number(b.name === 'other') || b.count - a.count;
  return { nodes: [...byId.values()].sort(order), links: [...byPair.values()].sort((a, b) => b.count - a.count), folded: to.size };
}

/**
 * Places `nodes` (in the API's order: by stage, largest first) in `width` × `height`; with
 * `vertical` the stages run top to bottom (phones). Gaps of `gap` px between nodes; node
 * thickness `nodeW`.
 */
export function layout(nodes: FlowNode[], links: FlowLink[], width: number, height: number, vertical = false, gap = 10, nodeW = 14): Layout {
  const along = vertical ? height : width;
  const across = vertical ? width : height;
  const cols = STAGES.map((s) => nodes.filter((n) => n.stage === s));
  const sum = (ns: FlowNode[]) => ns.reduce((a, n) => a + n.count, 0);
  const biggest = Math.max(1, ...cols.map(sum));
  const crowd = Math.max(1, ...cols.map((c) => c.length));
  const scale = Math.max(0, across - gap * (crowd - 1)) / biggest;
  const step = (along - nodeW) / (STAGES.length - 1);
  const placed: PlacedNode[] = [];
  const centre = new Map<string, number>();
  cols.forEach((c, ci) => {
    // A column with room to spare (upstreams carry only forwarded answers) puts each node level
    // with what flows into it, keeping the column's order: a band then runs across instead of
    // climbing over the others. The first column, and a full one, simply stack.
    const want = c.map((n) => {
      let w = 0;
      let at = 0;
      for (const l of links) {
        const from = l.target === n.id ? centre.get(l.source) : undefined;
        if (from !== undefined && l.count > 0) {
          w += l.count;
          at += l.count * from;
        }
      }
      return w > 0 ? at / w - (n.count * scale) / 2 : 0;
    });
    const tops = settle(c.map((n) => n.count * scale), ci === 0 ? c.map(() => 0) : want, gap, across);
    c.forEach((n, i) => {
      const h = n.count * scale;
      // Stored in screen terms: x and w across the page, y and h down it.
      const a = ci * step;
      placed.push(vertical ? { ...n, col: ci, x: tops[i], y: a, w: h, h: nodeW } : { ...n, col: ci, x: a, y: tops[i], w: nodeW, h });
      centre.set(n.id, tops[i] + h / 2);
    });
  });
  const byId = new Map(placed.map((n) => [n.id, n]));
  const offset = (n: PlacedNode) => (vertical ? n.x : n.y);
  const outAt = new Map<string, number>();
  const inAt = new Map<string, number>();
  // Bands leave a node in the order of their targets (column, then position) and enter in
  // the order of their sources, so they don't cross inside a node.
  const sorted = links
    .filter((l) => byId.has(l.source) && byId.has(l.target) && l.count > 0)
    .map((l) => ({ l, s: byId.get(l.source) as PlacedNode, t: byId.get(l.target) as PlacedNode }));
  const out = [...sorted].sort((a, b) => a.t.col - b.t.col || offset(a.t) - offset(b.t));
  const placedLinks = new Map<FlowLink, PlacedLink>();
  for (const { l, s } of out) {
    const w = l.count * scale;
    const o = outAt.get(s.id) ?? 0;
    outAt.set(s.id, o + w);
    placedLinks.set(l, { ...l, width: w, x0: 0, y0: offset(s) + o + w / 2, x1: 0, y1: 0, d: '' });
  }
  const inn = [...sorted].sort((a, b) => a.s.col - b.s.col || offset(a.s) - offset(b.s));
  for (const { l, s, t } of inn) {
    const p = placedLinks.get(l) as PlacedLink;
    const o = inAt.get(t.id) ?? 0;
    inAt.set(t.id, o + p.width);
    const c1 = offset(t) + o + p.width / 2;
    const a0 = (vertical ? s.y : s.x) + nodeW;
    const a1 = vertical ? t.y : t.x;
    const mid = (a0 + a1) / 2;
    const c0 = p.y0;
    if (vertical) {
      Object.assign(p, { x0: c0, y0: a0, x1: c1, y1: a1, d: `M${c0},${a0}C${c0},${mid} ${c1},${mid} ${c1},${a1}` });
    } else {
      Object.assign(p, { x0: a0, y0: c0, x1: a1, y1: c1, d: `M${a0},${c0}C${mid},${c0} ${mid},${c1} ${a1},${c1}` });
    }
  }
  return {
    nodes: placed,
    links: [...placedLinks.values()].sort((a, b) => b.width - a.width),
    scale,
    vertical,
    width,
    height,
  };
}

/**
 * Tops for nodes of `sizes` (in order) as close to `want` as they fit in `0..room`, `gap` apart,
 * order kept: pushed down past the one before, then up from the end.
 */
export function settle(sizes: number[], want: number[], gap: number, room: number): number[] {
  const tops: number[] = [];
  for (let i = 0; i < sizes.length; i++) {
    const after = i ? tops[i - 1] + sizes[i - 1] + gap : 0;
    tops.push(Math.max(after, want[i]));
  }
  for (let i = sizes.length - 1; i >= 0; i--) {
    const below = i === sizes.length - 1 ? room : tops[i + 1] - gap;
    tops[i] = Math.max(0, Math.min(tops[i], below - sizes[i]));
  }
  return tops;
}

/** A link's share of every answer and of its source's, as text. */
export function share(l: FlowLink, total: number, from: FlowNode | undefined): string {
  const pct = (n: number, of: number) => (of > 0 ? `${((100 * n) / of).toFixed(n * 1000 < of ? 2 : 1)} %` : '–');
  const of = from ? ` · ${pct(l.count, from.count)} of ${from.name}` : '';
  return `${pct(l.count, total)} of all${of}`;
}
