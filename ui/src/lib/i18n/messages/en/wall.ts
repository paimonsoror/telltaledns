// REQ: API-011 — strings for the wall page, English source of truth.
export const wall = {
  // The corner: the notice that the rotation is paused (the clock stays as it is).
  'wall.paused': 'paused',

  // The dots under the panels; a screen reader's only word for them.
  'wall.panels': 'Panels',

  // The tail: what it says before the first query of the stream arrives.
  'wall.waiting': 'Waiting for queries…',
  'wall.panel.map': 'What the network is reaching',
  'wall.panel.flow': 'Where queries go',
  'wall.panel.latency': 'Answer time',
  'wall.panel.heat': 'The week',
  'wall.panel.kpi': 'Right now',
  'wall.flow.aria': 'Where queries went in the last hour',
  'wall.slo.whoSpent': 'Who spent it',
  'wall.slo.off': 'Service-level objectives are off.',
  'wall.slo.noData': 'no data',
  'wall.slo.budgetLeft': '{pct} % of the budget left',
  'wall.kpi.qps': 'queries / s',
  'wall.kpi.blocked': 'blocked',
  'wall.kpi.fromCache': 'from the cache',
  'wall.kpi.health': 'health',
  'wall.slo.answersWork': 'Answers that work',
} as const;
