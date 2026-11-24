// REQ: API-011 — queries strings (English): the query log (its heading, the live view, the
// filters, the table, the foot, and the "Why?" drawer), the status words a badge shows, and the
// quick rule form the drawer opens.
//
// A sentence a name sits inside (a `<bdi>` around it) is split at the name: `…Start`/`…Mid`
// end just before it, `…End`/`…After` carry on just after it, so the markup keeps the element.
export const queries = {
  // The heading, the live view, and the notices above the filters.
  'queries.title': 'Query log',
  'queries.live': 'Live',
  'queries.live.streaming': 'streaming',
  'queries.live.connecting': 'connecting',
  'queries.live.retrying': 'retrying',
  'queries.liveIgnores':
    'The live view ignores the Rcode, Since, and Group filters; it shows new queries as they happen.',
  'queries.traceNotice': 'The query with trace ID',
  'queries.showAllQueries': 'Show all queries',

  // The filters: their labels, the Match menu, and the "not" boxes.
  'queries.filter.name': 'Name',
  'queries.filter.match': 'Match',
  'queries.match.substring': 'contains',
  'queries.match.exact': 'exactly',
  'queries.match.suffix': 'and subdomains',
  'queries.match.glob': 'wildcard (*)',
  'queries.match.regex': 'regex',
  'queries.match.notSubstring': 'does not contain',
  'queries.match.notExact': 'is not',
  'queries.match.notSuffix': 'is not, or under',
  'queries.match.notGlob': 'does not match wildcard',
  'queries.match.notRegex': 'does not match regex',
  'queries.filter.client': 'Client',
  'queries.filter.clientNot': 'Every client except this one',
  'queries.filter.type': 'Type',
  'queries.filter.qtypeNot': 'Every type except these',
  'queries.filter.rcode': 'Rcode',
  'queries.filter.rcodeNot': 'Every response code except these',
  'queries.filter.minLatency': 'Slower than (ms)',
  'queries.filter.group': 'Group',
  'queries.filter.any': 'any',
  'queries.filter.since': 'Since',
  'queries.not': 'not',
  'queries.statusNot': 'Every status except the ones chosen',
  'queries.clear': 'Clear',

  // The status of a query, as a badge and as a filter chip (the value sent stays the identifier).
  'queries.status.blocked': 'blocked',
  'queries.status.other': 'other',
  'queries.status.cached': 'cached',
  'queries.status.forwarded': 'forwarded',
  'queries.status.local': 'local',
  'queries.status.stale': 'stale',
  'queries.status.refreshing': 'refreshing',
  'queries.status.refreshed': 'refreshed',
  'queries.status.special': 'special',
  'queries.status.refused': 'refused',
  'queries.status.servfail': 'servfail',
  'queries.status.rate_limited': 'rate_limited',
  'queries.status.paused': 'paused',
  'queries.status.allowed': 'allowed',
  'queries.status.malformed': 'malformed',

  // The time ranges of the Since menu (the values are the API's; only the words are here).
  'queries.range.15m': '15 min',
  'queries.range.1h': '1 h',
  'queries.range.24h': '24 h',
  'queries.range.7d': '7 days',

  // The table: its columns, a row's tooltips, and what an empty answer says.
  'queries.col.time': 'Time',
  'queries.col.client': 'Client',
  'queries.col.name': 'Name',
  'queries.col.type': 'Type',
  'queries.col.status': 'Status',
  'queries.col.rule': 'Rule',
  'queries.col.took': 'Time taken',
  'queries.nodeTitle': 'The cluster node that answered',
  'queries.timing': 'upstream {upstream} of {total}',
  'queries.why': 'Why?',
  'queries.empty': 'No queries match.',

  // The foot: how many rows are shown, what the search looked at, and the next page.
  'queries.foot.rows': '{n} rows',
  'queries.foot.notReached': ' · not reached: {names}',
  'queries.foot.searched': ' · searched {read} of {total} blocks in {files} hourly files',
  'queries.foot.liveRows': '{n} live rows (newest {max} kept)',
  'queries.foot.skipped': ' · {n} matching queries skipped to keep up',
  'queries.older': 'Older',

  // The "Why?" drawer: its title and what it says about the row before the explanation.
  'queries.whyTitle': 'Why: {name}',
  'queries.whyExplains':
    'Explains how this query would be handled now; lists or settings may have changed since {time}.',
  'queries.whyLoggedAs': 'Logged as',
  'queries.whyLoggedBy': ' by {list}',
  'queries.whyEnd': '.',
  'queries.makeQuickRule': 'Make a quick rule',
  'queries.loadingDevices': 'Loading devices…',

  // The quick rule form: its words, and what it applies to.
  'queries.quickRule.action': 'Action',
  'queries.quickRule.allow': 'Allow',
  'queries.quickRule.block': 'Block',
  'queries.quickRule.domain': 'Domain',
  'queries.quickRule.for': 'For',
  'queries.quickRule.appliesTo': 'Applies to',
  'queries.quickRule.scopeDevice': 'a device',
  'queries.quickRule.scopeGroup': 'a group',
  'queries.quickRule.scopeEveryone': 'everyone',
  'queries.quickRule.device': 'Device',
  'queries.quickRule.devicePlaceholder': 'named device, IP, or network',
  'queries.quickRule.group': 'Group',
  'queries.quickRule.forLower': 'for',
  'queries.quickRule.duration': 'Duration',
  'queries.quickRule.note': 'Note',
  'queries.quickRule.notePlaceholder': "Note (optional), e.g. Mom's game",
  'queries.quickRule.saving': 'Saving…',
  'queries.quickRule.saveChanges': 'Save changes',
  'queries.quickRule.save': 'Save rule',
  'queries.quickRule.saved': 'Saved.',

  // How long a rule lasts.
  'queries.duration.30m': '30 minutes',
  'queries.duration.1h': '1 hour',
  'queries.duration.2h': '2 hours',
  'queries.duration.today': 'Until midnight',
  'queries.duration.1d': '1 day',
  'queries.duration.always': 'Until I remove it',
  'queries.duration.keep': 'Keep the current end ({end})',

  // Where a workload's group comes from (the words beside a group in the form's note).
  'queries.origin.podLabel': 'set by a label on its pods',
  'queries.origin.namespaceLabel': 'set by a label on its namespace',
  'queries.origin.map': 'set by a rule',
  'queries.origin.defaultGroup': 'the default group for workloads',
  'queries.origin.network': "its network's group",
  'queries.origin.group': 'its group',

  // What the form filled in, and what the log shows for it.
  'queries.seen.groupPlaced':
    '{workload} is a Kubernetes workload and its pods come and go, so this rule is for its group, ',
  'queries.seen.groupPlacedAfter':
    ' ({origin}): every device in it. For one address instead, choose “a device”.',
  'queries.seen.groupOtherMid': ' is a Kubernetes workload whose group is ',
  'queries.seen.groupOtherAfter': '. This rule is for ',
  'queries.seen.everyDevice': ': every device in it.',
  'queries.seen.forPrefix': 'This rule is for ',
  'queries.seen.podIs': '{address} is one pod of ',
  'queries.seen.podChanges': ", and a pod's address changes whenever it restarts.",
  'queries.seen.podUseGroup': 'For every pod, choose “a group”.',
  'queries.seen.podAddGroup':
    'To cover all its pods, put the workload in a group first: click its name in the log, then Add to group…',
  'queries.seen.namedDevice': '{address} is your device “',
  'queries.seen.namedDeviceEnd': '”.',
  'queries.seen.seenAsStart': '{address} (shown in the log as ',
  'queries.seen.seenAsEnd': ').',
  'queries.seen.podUnknown':
    "This looks like a Kubernetes pod this node doesn't know about: a pod's address changes whenever it restarts, so use the group an operator placed it in, not the address.",
  'queries.seen.address':
    'A rule for an address stops matching when the address changes: reserve the address in your router, or name the device so you change one place, not every rule.',

  // What every quick rule does, under the form.
  'queries.quickRule.foot':
    'Includes subdomains. Decides before any list. Devices may keep an old answer for a few minutes.',
  'queries.quickRule.footEdit': 'Saving keeps who made the rule and when.',
} as const;
