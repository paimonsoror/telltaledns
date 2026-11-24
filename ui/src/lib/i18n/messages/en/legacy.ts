// REQ: API-011 — strings for the legacy page, English source of truth.
//
// The page shows a name inside a sentence in a few places (a node's site, a scope, a range), so
// the sentence carries a `{name}` placeholder and the page passes the name in.
export const legacy = {
  // The heading and the controls above the figures.
  'legacy.title': 'Dashboard',
  'legacy.showing': 'Showing',
  'legacy.nodes': 'Nodes',
  'legacy.everyNode': 'every node',
  'legacy.nodePod': '{site} pod {pod}',
  'legacy.nodePrimary': ' (primary)',
  'legacy.thisNode': 'this node',
  'legacy.siteAllNodes': 'site {site} (all its nodes)',
  'legacy.siteLabel': 'site {site}',
  'legacy.oneNode': 'one node',
  'legacy.topListsFor': 'Top lists for',
  'legacy.group': 'Group',
  'legacy.everyDevice': 'every device',
  'legacy.timeRange': 'Time range',
  'legacy.partialResults':
    "Partial results: {nodes} didn't answer, so these numbers cover the other cluster nodes.",

  // The time ranges (the switch under the heading) and the words that say which hours a card covers.
  'legacy.range.48h': '48 h',
  'legacy.range.30d': '30 d',
  'legacy.lastRange': 'last {range}',
  'legacy.sinceTime': 'since {time}',
  'legacy.thisHour': 'this hour',

  // The figures.
  'legacy.queries': 'Queries',
  'legacy.blocked': 'Blocked',
  'legacy.cacheHits': 'Cache hits',
  'legacy.upstreamP90': 'Upstream p90',
  'legacy.activeClients': 'Active clients',
  'legacy.nxdomainServfail': 'NXDOMAIN / SERVFAIL',
  'legacy.blockedQueries': '{queries} queries',
  'legacy.cacheAnswers': '{answers} answers',
  'legacy.cacheFreshRefreshed': '{fresh} fresh · {refreshed} refreshed',
  'legacy.cacheP50': 'cache p50 {value}',

  // The status words the charts and the top clients' legend show (the value stays the identifier).
  'legacy.status.cached': 'cached',
  'legacy.status.refreshed': 'refreshed',
  'legacy.status.forwarded': 'forwarded',
  'legacy.status.local': 'local',
  'legacy.status.other': 'other',

  // The charts: their titles, what an empty one says, and the donut's middle.
  'legacy.chartQueriesByStatus': 'Queries by status',
  'legacy.answersByStatus': 'Answers by status',
  'legacy.noAnswersRange': 'No answers in this range.',
  'legacy.donutCenter': 'answers · {range}',
  'legacy.chartTrafficByGroup': 'Traffic by group',
  'legacy.chartUpstreamExchanges': 'Upstream exchanges',
  'legacy.upstreamQueries': 'upstream queries',
  'legacy.failures': 'failures',

  // Where time goes (the Advanced view): the views, the table, and what each path means.
  'legacy.whereTimeGoes': 'Where time goes',
  'legacy.parenThisHour': '(this hour)',
  'legacy.whereTimeGoesAs': 'Where time goes as',
  'legacy.percentiles': 'Percentiles',
  'legacy.noAnswersHour': 'No answers yet this hour.',
  'legacy.col.path': 'Path',
  // `max` stays as it is, beside p50/p90/p99.
  'legacy.col.max': 'max',
  'legacy.path.cache':
    'Answered from the cache: a repeat question, no upstream asked. Includes answers whose cached copy had just expired and was given at once while it was refreshed in the background. Usually well under a millisecond.',
  'legacy.path.upstream':
    'Not in the cache: asked an upstream resolver and waited for it. Also counts stale answers served because the upstream was slow or failing, and SERVFAIL. Usually the slowest path.',
  'legacy.path.local': 'Answered from names on your network (local records), without asking anyone.',
  'legacy.path.synthesized':
    "Answered without looking anything up: blocked names, refused or rate-limited queries, malformed ones, and special names (like Firefox's DNS-over-HTTPS canary).",
  'legacy.path.fallback': 'Answers that took this path.',
  'legacy.path.waitUpstream':
    "Of the upstream path above: the time spent waiting for upstream resolvers (the rest is this node's own work).",
  'legacy.path.wait': 'Time spent waiting for {what} when it answered.',
  'legacy.path.over': '{path} Over {proto}.',
  'legacy.proto.udp': 'plain DNS over UDP, what most devices use',
  'legacy.proto.tcp': 'plain DNS over TCP, for large answers and some tools',
  'legacy.proto.dot': 'DNS over TLS (port 853), e.g. Android Private DNS',
  'legacy.proto.doh': 'DNS over HTTPS, e.g. browsers or Apple devices with a profile',

  // The upstreams (the Advanced view).
  'legacy.asThisNode': '(as this node sees them)',
  'legacy.details': 'Details',
  'legacy.noUpstreams': 'No upstreams configured.',

  // The top lists.
  'legacy.topDomains': 'Top domains',
  'legacy.topBlocked': 'Top blocked',
  'legacy.topClients': 'Top clients',
  'legacy.domainsScope': 'Top domains on the internet or internal',
  'legacy.internet': 'Internet',
  'legacy.internal': 'Internal',
  'legacy.empty': 'Nothing yet.',
} as const;
