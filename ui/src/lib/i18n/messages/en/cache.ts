// REQ: API-011 — strings for the cache page, English source of truth.
// A count's noun is its own key (`.one`/`.other`) and the surrounding sentence carries it as a
// placeholder, so a sentence can put the number where its own language wants it.
export const cache = {
  // The heading.

  // A node's card: how well its cache worked, how much it holds, and how it started.
  'cache.node.answeredHeading': 'Answered from the cache',
  'cache.node.lastHour': 'last hour',
  'cache.node.sinceStart': '· {pct} since start',
  'cache.node.fresh':
    '{pct} fresh last hour; the rest had just expired and was answered at once while it was refreshed (or kept answering while upstreams failed).',
  'cache.node.answers.one': '{n} answer',
  'cache.node.answers.other': '{n} answers',
  'cache.node.holdsHeading': 'Holds',
  'cache.node.ofBudget': ' of {bytes}',
  'cache.node.shareLabel': '{pct} of the memory budget',
  'cache.node.lookups.one': '{n} lookup',
  'cache.node.lookups.other': '{n} lookups',
  'cache.node.lastHourLine':
    '{lookups} · {prefetched} prefetched · {stale} stale served · {evicted} evicted',
  'cache.node.started': 'Started',
  'cache.node.coldOff': 'cold (keeping the cache across restarts is off)',
  'cache.node.warm': 'warm: {answers} reloaded, {date} {time}',
  'cache.node.cold': 'cold: {note}',
  'cache.node.chartAnswered': 'Answered from the cache, last hour (%)',
  'cache.node.chartLookups': 'Lookups per 15 s',
  'cache.node.chartsFilling': 'The charts fill in over the first minutes (a sample every 15 s).',

  // The size advice: its verdict, and what a bigger cache would buy.
  'cache.sizing.heading': 'Size',
  'cache.sizing.grow': 'could grow',
  'cache.sizing.shrink': 'could shrink',
  'cache.sizing.ok': 'right size',
  'cache.sizing.learning': 'learning',
  'cache.sizing.bigger': 'Bigger:',
  'cache.sizing.step': '{size}% → +{hits}% hits',
  'cache.sizing.peak': 'Peak {bytes}.',

  // The two tables under "What's cached": their controls, and the makeup table per node.
  'cache.makeup.title': "What's cached",
  'cache.makeup.sort': 'Sort',
  'cache.makeup.sortAria': 'Sort by',
  'cache.makeup.sortHits': 'most hits',
  'cache.makeup.sortBytes': 'largest',
  'cache.makeup.sortExpiring': 'expiring soonest',
  'cache.makeup.refresh': 'Refresh',
  'cache.makeup.colHolds': 'Holds',
  'cache.makeup.colStale': 'Stale',
  'cache.makeup.colValidated': 'Validated',
  'cache.makeup.kind.answer.one': '{n} answer',
  'cache.makeup.kind.answer.other': '{n} answers',
  'cache.makeup.kind.noSuchName.one': '{n} no such name',
  'cache.makeup.kind.noSuchName.other': '{n} no such name',
  'cache.makeup.kind.noData.one': '{n} no data',
  'cache.makeup.kind.noData.other': '{n} no data',
  'cache.makeup.kind.servfail.one': '{n} SERVFAIL',
  'cache.makeup.kind.servfail.other': '{n} SERVFAIL',
  'cache.makeup.showFewer': 'Show fewer nodes',
  'cache.makeup.showAll.one': 'Show all {n} node',
  'cache.makeup.showAll.other': 'Show all {n} nodes',

  // The top entries: the merged list of names, and one name across the nodes.
  'cache.top.empty': 'Nothing cached.',
  'cache.top.emptyFresh': 'Nothing cached that is still fresh.',
  'cache.top.lookupTitle': 'Look it up below',
  'cache.top.ttlLeft': '{ttl} left',
  'cache.top.ttlStale': 'stale {ttl}',
  'cache.top.ttlRange': '{from} to {to}',
  'cache.top.nodesOf': '{shown} of {total}',
  'cache.top.hits.one': '{n} hit',
  'cache.top.hits.other': '{n} hits',
  'cache.top.merged':
    "Merged across nodes: each name once, with the hits of the nodes where it's among their top {limit}. Pick a node above for its own list.",
  'cache.top.cardTitle': 'Look up and flush',

  // The settings in effect on a node.
  'cache.settings.maxEntries.one': ', at most {n} answer',
  'cache.settings.maxEntries.other': ', at most {n} answers',
  'cache.settings.ttlLine':
    '{min} to {max}; negative answers up to {negative}; SERVFAIL {servfail}',
  'cache.settings.serveStale': 'Serve stale',
  'cache.settings.serveStaleAtOnce':
    'answered at once and refreshed in the background, for up to {duration} after expiry',
  'cache.settings.serveStaleWhen': "when upstreams don't answer",
  'cache.settings.serveStaleWithin': ' within {seconds} s',
  'cache.settings.serveStaleFor': ', for up to {duration} after expiry',
  'cache.settings.prefetch': 'Prefetch',
  'cache.settings.prefetchOn': 'on, with under {percent}% of the TTL left, after {hits}',
  'cache.settings.prefetchHits.one': '{n} hit',
  'cache.settings.prefetchHits.other': '{n} hits',
  'cache.settings.acrossRestarts': 'Across restarts',
  'cache.settings.kept': 'kept',
  'cache.settings.notKept': 'not kept',
  'cache.settings.changeUnder': 'Change these under ',
  'cache.settings.inConfig': ' in the configuration.',
} as const;
