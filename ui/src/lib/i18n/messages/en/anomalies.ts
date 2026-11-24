// REQ: API-011 — strings for the anomalies page, English source of truth: the heading and the
// time-range picker, what the page is for, the toolbar switches, the finding kinds, a finding's
// evidence and actions, the mutes table, and the new-domains table.
//
// A sentence a name sits inside (a `<b>` or a `<span>` around it) is split at the name:
// `…by` ends just before it, `…rest` carries on just after it, so the markup keeps the element.
//
// The window of a finding never said "days" for a count of two, so both plural categories keep
// today's word: `tn()` is used for the count, not to change the sentence.
export const anomalies = {
  // The heading, and the range the page looks at.
  'anomalies.range.24h': 'last 24 hours',
  'anomalies.range.7d': 'last 7 days',
  'anomalies.range.30d': 'last 30 days',

  // The notice after a mute is saved (the finding it muted has left the list).
  'anomalies.muted.saved': 'Muted.',
  'anomalies.dismiss': 'Dismiss',

  // What the page is for.
  'anomalies.intro':
    "Each device is compared with its own usual behavior, learned over its first week. Findings only inform you; to act, open the device's queries or move it to a stricter group. Acknowledge a finding once you've looked at it: it stops counting as new, on every node. Mute a kind of finding for a device that does it harmlessly, over and over.",

  // The toolbar: what is hidden, and acknowledging everything at once.
  'anomalies.showAcknowledged': 'Show acknowledged ({n})',
  'anomalies.showMuted': 'Show muted ({n})',
  'anomalies.acknowledgeAll': 'Acknowledge all {n}',

  // What the list says when it is empty.
  'anomalies.empty.acknowledged': 'Nothing new: every finding in this period is acknowledged.',
  'anomalies.empty.muted.one': 'Nothing unusual: {n} muted finding is hidden.',
  'anomalies.empty.muted.other': 'Nothing unusual: {n} muted findings are hidden.',
  'anomalies.empty.none':
    'Nothing unusual. New devices are quiet here for their first 7 days while TelltaleDNS learns them.',

  // The kinds of finding, as a badge and in the mutes table (the value stays the identifier).
  'anomalies.kind.rateSpike': 'Many more queries than usual',
  'anomalies.kind.domainVolume': 'Unusual traffic to one domain',
  'anomalies.kind.drift': 'Many new domains',
  'anomalies.kind.beacon': 'Regular phone-home',
  'anomalies.kind.chattyLoop': 'Chatty loop',
  'anomalies.kind.nxdomainStorm': 'Burst of failed lookups',
  'anomalies.kind.dga': 'Machine-generated-looking domains',
  'anomalies.informational': 'for your information: not counted as an anomaly',

  // A finding that is muted: who, and what that means.
  'anomalies.muted.badge': 'Muted',
  'anomalies.muted.rest': ': not counted in the badge, the alerts or the metrics',

  // A finding that is acknowledged: who, and when.
  'anomalies.ack.badge': 'Acknowledged',
  'anomalies.ack.by': 'by',
  'anomalies.ack.sep': ', ',

  // A note someone left, quoted.
  'anomalies.note': ': “{note}”',

  // The evidence: what was seen, the device's usual value, and the bar it crossed.
  'anomalies.evidence.observed': 'Observed',
  'anomalies.evidence.usual': 'Usual',
  'anomalies.evidence.threshold': 'Threshold',
  'anomalies.evidence.window': 'Window',

  // How long the window of a finding was.
  'anomalies.window.days.one': '{n} day',
  'anomalies.window.days.other': '{n} day',
  'anomalies.window.hours.one': '{n} h',
  'anomalies.window.hours.other': '{n} h',
  'anomalies.window.minutes.one': '{n} min',
  'anomalies.window.minutes.other': '{n} min',

  // What a finding's actions do.
  'anomalies.showQueries': 'Show these queries',
  'anomalies.seeTheDay': 'See the day',
  'anomalies.foundBy': 'Found by {nodes}',
  'anomalies.removeMute': 'Remove mute',
  'anomalies.muteForDevice': 'Mute for this device…',
  'anomalies.undoAcknowledge': 'Undo acknowledge',
  'anomalies.acknowledge': 'Acknowledge',

  // The mutes table: its heading, what it is, its columns, and its rows.
  'anomalies.mutes.title': 'Mutes',
  'anomalies.mutes.intro':
    'Kinds of finding that stop counting for these devices. They are still recorded: turn on Show muted to see them.',
  'anomalies.mutes.col.kinds': 'Kinds',
  'anomalies.mutes.col.until': 'Until',
  'anomalies.mutes.group': 'group {name}',
  'anomalies.mutes.ended': 'ended',
  'anomalies.mutes.untilRemoved': 'until removed',

  // First-seen domains: its heading, its switch, and its table.
  'anomalies.newDomains.title': 'New domains',
  'anomalies.newDomains.onlySuspicious': 'Only machine-generated-looking',
  'anomalies.newDomains.intro':
    'Domains each device contacted for the first time (after its first day), newest first. The score says how generated the name looks (0.6 and up is suspicious).',
  'anomalies.newDomains.empty': 'No new domains in this period.',
  'anomalies.newDomains.col.firstSeen': 'First seen',
  'anomalies.newDomains.col.score': 'Score',
} as const;
