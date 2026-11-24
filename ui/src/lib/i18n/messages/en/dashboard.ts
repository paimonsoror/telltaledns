// REQ: API-011 — dashboard strings (English): the calm dashboard page, its heading and controls,
// the figures, the service level, where time goes, the upstreams, the top lists, and the chart.
export const dashboard = {
  // The heading, the controls, and the partial-results notice.
  'dashboard.switchBack': 'Switch to the new dashboard',

  // The time ranges (the switch under the heading).

  // The figures.
  'dashboard.nxdomainLine': '{nxdomain} NXDOMAIN · {servfail} SERVFAIL in the last {range}',

  // The change against the previous period (the small figure under a number).
  'dashboard.previousPeriodTitle': 'Against the previous period of the same length',

  // The chart: its views and its titles.
  'dashboard.chartView': 'Chart view',
  'dashboard.view.totals': 'Totals',
  'dashboard.upstreamFailures': 'Upstream failures',
  'dashboard.upstreamQueries': 'Upstream queries',
  'dashboard.failures': 'Failures',

  // The service level (the Advanced view): what the objectives and their alerts say.
  'dashboard.slo.window.one': 'last {n} day',
  'dashboard.slo.window.other': 'last {n} days',
  'dashboard.slo.availability': 'Answers that work',
  'dashboard.slo.latency': 'Answers that are quick',

  // Where time goes (the Advanced view): the views, the table, and what each path means.
  'dashboard.path.cache':
    'Answered from the cache: a repeat question, no upstream asked. Includes answers whose cached copy had just expired and was given at once while it was refreshed in the background. Usually well under a millisecond.',

  // The upstreams (the Advanced view).
  'dashboard.asThisNode': 'as this node sees them',

  // The top lists.
  'dashboard.topClients': 'Top clients',
  'dashboard.byType': 'By type',
  'dashboard.clients': 'Clients',
  'dashboard.searchSuffix': 'search suffix ×{n}',
  'dashboard.detailsFor': 'Details for {name}',
  'dashboard.podsAskedPre': 'Pods asked for ',
  'dashboard.podsAskedPost': "with each of their DNS search suffixes added, so it's one question that looks like {n}:",
  'dashboard.queriesCount': '{count} queries',
  'dashboard.ofThisList': '{pct} of this list',
  'dashboard.showItsQueries': 'Show its queries',
  'dashboard.showInLog': 'Show in the query log',

  // The chart's own chrome.
  'dashboard.chart': 'Chart',
  'dashboard.noData': 'No data yet.',
  'dashboard.changed': 'Changed',
  'dashboard.what': 'What',
  'dashboard.total': 'Total',
  'dashboard.andMore': 'and {n} more',
} as const;
