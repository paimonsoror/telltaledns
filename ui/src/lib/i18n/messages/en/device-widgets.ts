// REQ: API-011 — device-widgets strings (English): the mute form on the Anomalies page, a device's
// rhythm strip, its day as a timeline, its identity line, and the "Devices by type" card. English
// is the source of truth: these are the characters the tests read.
//
// A sentence a piece of markup sits inside (a `<b>` around "Show muted", a key dot in the timeline's
// legend) is split at it: `…lead`/`…firstContact` end just before it, `…tail`/`…anomaly` carry on
// just after it, so the markup keeps the element.
export const deviceWidgets = {
  // Muting a kind of finding for one device: what the form says, its fields, and its buttons.
  'deviceWidgets.mute.introLead':
    'Stop counting the kinds below for this device. The findings are still recorded and listed (turn on ',
  'deviceWidgets.mute.introTail': '), and every other device is still checked.',
  'deviceWidgets.mute.showMuted': 'Show muted',
  'deviceWidgets.mute.device': 'Device (name, IP or network)',
  'deviceWidgets.mute.kinds': 'Kinds of finding',
  'deviceWidgets.mute.for': 'For',
  'deviceWidgets.mute.howLong': 'How long',
  'deviceWidgets.mute.duration.1w': '1 week',
  'deviceWidgets.mute.notePlaceholder': 'Why (optional), e.g. hourly reverse-DNS sweep',
  // Never said "finding" for a count of two, so both plural categories keep today's word.
  'deviceWidgets.mute.similar.one': 'This finding in the period shown would have been muted.',
  'deviceWidgets.mute.similar.other': 'These {n} findings in the period shown would have been muted.',
  'deviceWidgets.mute.previewLead': 'What this will do:',
  'deviceWidgets.mute.previewFallback': 'Mutes these findings for this device.',
  'deviceWidgets.mute.mute': 'Mute',

  // A device's rhythm: which hours are shown, the table view, the axis, and the two badges.
  'deviceWidgets.rhythm.hours': 'Which hours',
  'deviceWidgets.rhythm.recent': 'Recent',
  'deviceWidgets.rhythm.thisHour': 'This hour',
  'deviceWidgets.rhythm.empty': 'No tracked domains for this device yet.',
  'deviceWidgets.rhythm.legend':
    'Columns are the gap between two queries: 0 is under 1 s, then 1–1.5 s, 1.5–2.2 s, … up to 2 hours and longer.',
  'deviceWidgets.rhythm.openQueries': 'Open these queries',
  'deviceWidgets.rhythm.aria': '{domain}: {period}',
  'deviceWidgets.rhythm.noRhythm': 'no single rhythm',
  'deviceWidgets.rhythm.under': 'under {span}',
  'deviceWidgets.rhythm.andLonger': '{span} and longer',
  'deviceWidgets.rhythm.range': '{from}–{to}',
  'deviceWidgets.rhythm.unit.s': '{n} s',
  'deviceWidgets.rhythm.unit.h': '{n} h',
  'deviceWidgets.rhythm.cell': '{gap}: {count} ({pct} %)',
  'deviceWidgets.rhythm.usual': 'usual',
  'deviceWidgets.rhythm.newRhythm': 'new rhythm',

  // A device's day as swimlanes: the window, the table, the notices, and what the canvas shows.
  'deviceWidgets.timeline.window.3d': '3 d',
  'deviceWidgets.timeline.loading': 'Reading the query log…',
  'deviceWidgets.timeline.truncated':
    'The query log read stopped early ({reason}): the lanes cover what it read.',
  'deviceWidgets.timeline.coverage': 'The query log starts {day} {time}: the grey part has no rows.',
  'deviceWidgets.timeline.empty': 'No queries from this device in this window.',
  'deviceWidgets.timeline.hidden': '(hidden)',
  'deviceWidgets.timeline.p99Row': 'p99 (ms)',
  'deviceWidgets.timeline.laneFallback': 'domain {n}',
  'deviceWidgets.timeline.new': 'new',
  'deviceWidgets.timeline.unit.ms': '{n} ms',
  // What hovers over a cell: the gap, the domain, and what happened in it. The count never said
  // "query" for one, so both plural categories keep today's word: `tn()` is used for the count,
  // not to change the sentence.
  'deviceWidgets.timeline.tip.anyDomain': 'a domain',
  'deviceWidgets.timeline.tip.lane': '{span} · {domain} · {queries}, {blocked}{slow}',
  'deviceWidgets.timeline.tip.queries.one': '{q} queries',
  'deviceWidgets.timeline.tip.queries.other': '{q} queries',
  'deviceWidgets.timeline.tip.blocked.one': '{q} blocked',
  'deviceWidgets.timeline.tip.blocked.other': '{q} blocked',
  'deviceWidgets.timeline.tip.slow.one': '{q} slow',
  'deviceWidgets.timeline.tip.slow.other': '{q} slow',
  'deviceWidgets.timeline.tip.latency': '{span} · {queries} · p99 {p99}',
  // The key under the lanes, split at each key dot.
  'deviceWidgets.timeline.legendLead':
    'Darker is more queries; red underline: blocked; amber tick: slower than the latency objective. Dots above: ',
  'deviceWidgets.timeline.legend.firstContact': ' first contact, ',
  'deviceWidgets.timeline.legend.anomaly': ' anomaly, ',
  'deviceWidgets.timeline.legend.blockedBurst': ' blocked burst, ',
  'deviceWidgets.timeline.legend.identity':
    " the device's identity changed; grey ticks are changes.",

  // What a device looks like: the one line, the suggested group, and the evidence on request.
  'deviceWidgets.identity.setAs.a': 'Set as a {what}',
  'deviceWidgets.identity.setAs.an': 'Set as an {what}',
  'deviceWidgets.identity.madeBy': 'Made by {vendor}',
  'deviceWidgets.identity.looks.a': 'Looks like a {product} ({level})',
  'deviceWidgets.identity.looks.an': 'Looks like an {product} ({level})',
  'deviceWidgets.identity.suggested': '{group} suggested',
  'deviceWidgets.identity.suggestedTitle':
    "This group's settings ask for this kind of device. Add it from the address's menu: Add to group…",
  'deviceWidgets.identity.hideWhy': 'Hide why',
  'deviceWidgets.identity.talksTo': 'Talks to {domains}',
  'deviceWidgets.identity.macVendor': 'MAC vendor {vendor}{prefix}',
  'deviceWidgets.identity.callsItself': 'Calls itself “{name}”',
  'deviceWidgets.identity.couldBe.a': 'Could also be a {product}',
  'deviceWidgets.identity.couldBe.an': 'Could also be an {product}',
  'deviceWidgets.identity.notRight': 'Not right? Name the device and set what it is (“What it is”).',

  // Devices by what they look like (Advanced dashboard).
  'deviceWidgets.byType.title': 'Devices by type',
  'deviceWidgets.byType.empty': 'No devices identified yet.',
} as const;
