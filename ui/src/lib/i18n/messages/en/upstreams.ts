// REQ: API-011 — strings for the upstreams page, English source of truth: the heading, the table
// of upstream servers (its columns, the share bars' tooltips, and what the failures were), what the
// health badges mean, the answer-time heatmap, the answer-quality checks (second opinions, DNSSEC,
// error codes), the two editors (upstreams and upstream groups), and the last note.
//
// A sentence a value sits inside is split at the value, so the markup keeps its own elements:
// `upstreams.health.intro` ends just before the first badge word, `upstreams.secondOpinionsOff.before`
// just before the `<code>`, and `upstreams.forwarded.before`/`.after` around the link.
export const upstreams = {
  // The heading, and the table's columns.
  'upstreams.col.requests': 'Requests',
  'upstreams.col.failures': 'Failures',
  'upstreams.col.smoothed': 'Smoothed',
  'upstreams.col.secondOpinions': 'Second opinions',
  'upstreams.col.dnssec': 'DNSSEC',
  'upstreams.col.ede': 'Error codes (EDE)',

  // What the two share bars under a row's numbers are.
  'upstreams.share.requests': 'share of all upstream requests',
  'upstreams.share.failures': 'failure rate',

  // What the failures were, under a row's failure rate: a count and its kind.
  'upstreams.failure.timeout.one': '{n} timeout',
  'upstreams.failure.timeout.other': '{n} timeouts',
  'upstreams.failure.network.one': '{n} connection error',
  'upstreams.failure.network.other': '{n} connection errors',
  'upstreams.failure.badResponse.one': '{n} bad reply',
  'upstreams.failure.badResponse.other': '{n} bad replies',
  'upstreams.failure.unresolved.one': '{n} name not resolved',
  'upstreams.failure.unresolved.other': '{n} name not resolved',
  'upstreams.failure.servfail.one': '{n} SERVFAIL',
  'upstreams.failure.servfail.other': '{n} SERVFAIL',
  'upstreams.failure.refused.one': '{n} REFUSED',
  'upstreams.failure.refused.other': '{n} REFUSED',
  'upstreams.failure.otherRcode.one': '{n} other error',
  'upstreams.failure.otherRcode.other': '{n} other errors',

  // What the health badges mean; each word is the one its badge shows (BreakerBadge's words).
  'upstreams.health.intro': 'Health: ',
  'upstreams.health.answering': ' = answering, ',
  'upstreams.health.stopped': ' = stopped asking it after failures, ',
  'upstreams.health.trial':
    " = a trial query is checking whether it has recovered. Percentiles cover this hour. Hover a badge for the circuit breaker's own word.",

  // The answer-time heatmap and the menu that picks its upstream.
  'upstreams.latency.title': 'Answer time over time',

  // The answer-quality checks: the heading, and what they say before upstreams have answered.
  'upstreams.quality.title': 'Answer quality',
  'upstreams.quality.empty':
    'Nothing to show yet: DNSSEC verdicts and error codes appear as upstreams answer.',

  // What the second upstream said, per row: a chip with its count and a tooltip saying why.
  'upstreams.opinion.same.one': '{n} same',
  'upstreams.opinion.same.other': '{n} same',
  'upstreams.opinion.otherAddresses.one': '{n} other addresses',
  'upstreams.opinion.otherAddresses.other': '{n} other addresses',
  'upstreams.opinion.otherAddressesTip':
    'Both had addresses, none in common: CDNs and geo-DNS answer per resolver, usually harmless.',
  'upstreams.opinion.otherResponse.one': '{n} other response',
  'upstreams.opinion.otherResponse.other': '{n} other response',
  'upstreams.opinion.otherResponseTip': 'A different response code (SERVFAIL, REFUSED, ...).',
  'upstreams.opinion.filtered.one': '{n} filtered',
  'upstreams.opinion.filtered.other': '{n} filtered',
  'upstreams.opinion.filteredTip':
    'One had addresses, the other none or only 0.0.0.0/loopback: one of them filters this name.',
  'upstreams.opinion.unanswered.one': '{n} no second answer',
  'upstreams.opinion.unanswered.other': '{n} no second answer',
  'upstreams.opinion.unansweredTip': 'The second upstream didn’t answer.',

  // The verdict on one disagreement (the chip in the list under the table).
  'upstreams.disagreement.otherAddresses': 'other addresses',
  'upstreams.disagreement.otherResponse': 'other response',
  'upstreams.disagreement.filtered': 'filtered',

  // The DNSSEC verdicts a row counts, and what an empty error-code cell says.
  'upstreams.dnssec.secure.one': '{n} secure',
  'upstreams.dnssec.secure.other': '{n} secure',
  'upstreams.dnssec.unsigned.one': '{n} unsigned',
  'upstreams.dnssec.unsigned.other': '{n} unsigned',
  'upstreams.dnssec.bogus.one': '{n} bogus',
  'upstreams.dnssec.bogus.other': '{n} bogus',
  'upstreams.dnssec.undecided.one': '{n} undecided',
  'upstreams.dnssec.undecided.other': '{n} undecided',

  // The note when second opinions are off.
  'upstreams.secondOpinionsOff.before': 'Second opinions are off. With ',
  'upstreams.secondOpinionsOff.after':
    ', one forwarded question in 1,000 is asked again of another upstream and the answers compared (that upstream sees those names).',

  // The latest disagreements, per node.
  'upstreams.disagreements': 'Latest disagreements',
  'upstreams.disagreements.on': ' on {node}',

  // The two editors: their titles and the nouns their sentences put in.
  'upstreams.manage.noun': 'upstream',
  'upstreams.manage.groupTitle': 'Upstream groups',
  'upstreams.manage.groupNoun': 'upstream group',

  // The upstream editor's fields: what they are called, their hints, what they help with.
  'upstreams.field.addressPlaceholder': 'tls://9.9.9.9 or https://dns.quad9.net/dns-query',
  'upstreams.field.addressHelp':
    'udp://, tcp://, tls:// (DNS over TLS), https:// (DNS over HTTPS), or quic://. Plugin upstreams (exec://, unix://) are defined in the config file.',
  'upstreams.field.tlsName': 'TLS server name',
  'upstreams.field.tlsNamePlaceholder': 'dns.quad9.net',
  'upstreams.field.tlsNameHelp':
    'The name on the server certificate, for tls:// and quic:// addresses given by IP.',
  'upstreams.field.timeout': 'Timeout (ms)',

  // The upstream group editor's fields.
  'upstreams.field.members': 'Upstreams',
  'upstreams.field.strategy': 'Strategy',
  'upstreams.field.strategyHelp':
    'failover: in order, the next on failure. fastest: the quickest lately. parallel: ask several, take the first answer.',

  // Asking the draft upstream whether it works, before saving it.
  'upstreams.test.works': 'Works: {detail} in {ms} ms.',
  'upstreams.test.fails': "Doesn't work: {error}",

  // Where a domain goes elsewhere.
  'upstreams.forwarded.before':
    'To send one domain to a different server (a work network, your router), add a forwarded domain on the ',
  'upstreams.forwarded.after': ' page.',
} as const;
