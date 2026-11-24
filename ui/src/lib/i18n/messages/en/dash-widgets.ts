// REQ: API-011 — dash-widgets strings (English): the latency heatmap (window, paths, tooltip,
// canvas labels, legend) and the circuit-breaker badge.
export const dashWidgets = {
  // The heatmap's own controls.
  'dashw.window': 'Window',
  'dashw.paths': 'Paths',
  'dashw.window.1h': '1 h',
  'dashw.window.6h': '6 h',
  'dashw.window.24h': '24 h',
  'dashw.window.7d': '7 d',
  'dashw.path.cache': 'cache',
  'dashw.path.upstream': 'upstream',
  'dashw.path.local': 'local names',
  'dashw.path.synthesized': 'blocked & special',
  'dashw.showGrid': 'Grid',
  'dashw.showTable': 'Table',
  'dashw.loading': 'Loading…',
  'dashw.empty': 'No answers in this window yet.',
  'dashw.time': 'Time',
  // The tooltip over a cell, and the exemplar dots.
  'dashw.tipMore': 'more',
  'dashw.tipAnswers.one': '{time} · {range} · {answers} answer',
  'dashw.tipAnswers.other': '{time} · {range} · {answers} answers',
  'dashw.dot.via': ' via {upstream}',
  'dashw.dot.label': '{latency} {path}{via} at {time}: open this query',
  // What the colours, the line, and the dots mean.
  'dashw.legend.darker': 'Darker = more answers in that time and latency band.',
  'dashw.legend.threshold': 'the latency objective ({ms} ms).',
  'dashw.legend.dots': 'Dots are real queries: select one to open it.',
  'dashw.legend.partial': 'Some {step}s are from an older build and have no bands.',
  'dashw.legend.missing': 'Without {nodes}.',
  // The circuit-breaker badge: plain words for a state, the pattern's word in the tooltip.
  'dashw.breaker.closed': 'Healthy',
  'dashw.breaker.open': 'Benched',
  'dashw.breaker.halfOpen': 'Probing',
  'dashw.breaker.title': 'circuit breaker: {state}',
} as const;
