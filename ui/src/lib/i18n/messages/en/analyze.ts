// REQ: API-011 — analyze strings (English): the page's heading and its two tabs, the query box in
// the middle (its label, its example chips, its buttons), and what the answer says about what it
// cost. The query language's own words (from, where, bucket, …) stay as they are.
export const analyze = {
  // The heading and the tabs.
  'analyze.tab.budget': 'Error budget',

  // The query box: its label, what runs it, and the stage list beside the buttons.
  'analyze.queryLabel': 'Query (vqlog) · Ctrl+Enter runs it',
  'analyze.queryAria': 'vqlog query',
  'analyze.run': 'Run',
  'analyze.estimate': 'Estimate cost',
  'analyze.estimateTitle': 'Only estimate how much it would read',
  'analyze.stages': 'Stages: from · where · bucket · by · stats · top · sort · limit',

  // The example chips: the words a chip shows (the query it runs stays as it is).
  'analyze.example.topBlocked': 'Top blocked names today',
  'analyze.example.busiest': 'Busiest devices',
  'analyze.example.perHour': 'Queries per hour, with latency',
  'analyze.example.slow': 'Slow answers by upstream',
  'analyze.example.failed': 'Failed lookups',

  // What the answer says: the query as it was understood, what it cost, and what it left out.
  'analyze.asUnderstood': 'As understood: ',
  // A plural group: `.one` when `{n}` is 1, `.other` otherwise.
  'analyze.estimate.one': 'Estimate: up to {n} logged query in {blocks} blocks would be read.',
  'analyze.estimate.other': 'Estimate: up to {n} logged queries in {blocks} blocks would be read.',
  'analyze.matched.one':
    'Matched {matched} of {scanned} queries read (estimated at most {estimated}) in {elapsed} ms · {n} group',
  'analyze.matched.other':
    'Matched {matched} of {scanned} queries read (estimated at most {estimated}) in {elapsed} ms · {n} groups',
  'analyze.partial': 'Partial: {reason}',
  'analyze.notIncluded': 'Not included: {nodes}',
  'analyze.rollups': 'From the rollups (counts kept for long windows), not the query log.',
  'analyze.nothing': 'Nothing matched.',
} as const;
