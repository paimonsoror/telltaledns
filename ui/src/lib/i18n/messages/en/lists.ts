// REQ: API-011 — strings for the lists page, English source of truth: the heading and the
// snapshot count, the table (its columns, the badges on a row, and the notes under a number), the
// shadow section, the over-blocking section, the editor below them, and the page's own foot note.
//
// A sentence a value sits inside is split at the value, so the markup keeps its own elements:
// `lists.emptyStart` ends just before the `<code>` and `lists.emptyEnd` carries on just after it.
export const lists = {
  // The heading, the snapshot count, and what an empty table says.
  'lists.snapshotBlocked.one': '{n} blocked names in snapshot {snapshot}',
  'lists.snapshotBlocked.other': '{n} blocked names in snapshot {snapshot}',
  'lists.emptyStart': 'No lists are configured. Add ',
  'lists.emptyEnd': ' entries (URLs, files, or inline rules).',

  // The table's columns.
  'lists.col.list': 'List',
  'lists.col.kind': 'Kind',
  'lists.col.state': 'State',
  'lists.col.namesUsed': 'Names used',
  'lists.col.unique': 'Unique',
  'lists.col.lines': 'Lines',
  'lists.col.size': 'Size',
  'lists.col.checked': 'Checked',
  'lists.col.changed': 'Changed',

  // A row: the badges beside its name, the notes under a number, and the share bar.
  'lists.badge.off': 'off',
  'lists.badge.shadowTitle': 'Never blocks: what it would have blocked is counted below',
  'lists.regexSkippedStart.one': '{n} regex rule left out (over the limit of ',
  'lists.regexSkippedStart.other': '{n} regex rules left out (over the limit of ',
  'lists.regexSkippedEnd': ', or too large to compile)',
  'lists.stale.one': 'unchanged for {n} days',
  'lists.stale.other': 'unchanged for {n} days',
  'lists.staleTitle': 'Its source may be abandoned while still answering',
  'lists.shareLabel': 'share of the blocked names in the snapshot',
  'lists.overlapShare': '{pct}% also in {list}',
  'lists.noneYet': 'none yet',

  // What a shadow list would have blocked (OBS-018).
  'lists.shadow.title': 'Would have blocked',
  'lists.shadow.counts': '{queries} from {devices}',
  'lists.shadow.queries.one': '{n} query',
  'lists.shadow.queries.other': '{n} queries',
  'lists.shadow.devices.one': '{n} device',
  'lists.shadow.devices.other': '{n} devices',
  'lists.shadow.since': ' since {when}',
  'lists.shadow.last': ' · last {when}',
  'lists.shadow.empty': "Nothing yet: it hasn't matched anything your devices asked for.",
  'lists.shadow.noteStart':
    "Shadow lists never block. When the names above are ones you'd want blocked, switch the list to ",

  // Blocked names someone seems to want (OBS-018).
  'lists.overblocking.title': 'Likely over-blocking',
  'lists.overblocking.col.blockedBy': 'Blocked by',
  'lists.overblocking.col.allowedAfter': 'Allowed soon after',
  'lists.overblocking.col.retries': 'Retry bursts',
  'lists.overblocking.col.devices': 'Devices',
  'lists.overblocking.col.last': 'Last',
  'lists.overblocking.note':
    '"Allowed soon after" counts devices that got the name within 10 minutes of a block (a pause or an allow): someone wanted it. Retry bursts are apps asking 10+ times a minute; ad libraries do that too.',

  // The lists editor: its title and noun, what a row says, and its own foot note.
  'lists.manage.title': 'Manage lists',
  'lists.manage.noun': 'list',
  'lists.manage.rules.one': '{n} rules',
  'lists.manage.rules.other': '{n} rules',
  'lists.manage.summaryOff': ' · off',
  'lists.footNote':
    '"Names used" counts the names this list puts in the active snapshot; "Unique" the ones no other list has (what removing it would lose). "Hits" counts the queries it decided since each node started, across the cluster.',

  // The editor's fields (API-002, OBS-018).
  'lists.field.download': 'Download from',
  'lists.field.downloadPlaceholder': 'https://example.org/hosts.txt',
  'lists.field.downloadHelp':
    'Hosts files, plain domain lists, and Adblock-style lists all work. Or leave this empty and write the rules below.',
  'lists.field.rulesPlaceholder': 'ads.example.com, ||tracker.example^ (one per line)',
  'lists.field.match': 'Plain names match',
  'lists.field.matchHelp': 'subtree: the name and everything below it. exact: only the name itself.',
  'lists.field.enabled': 'On',
  'lists.field.mode': 'Mode',
  'lists.field.modeHelp':
    'enforce: it blocks. shadow: it never blocks; the page shows what it would have blocked, so you can judge it first.',
  'lists.field.refresh': 'Check for updates every (seconds)',
  'lists.field.refreshPlaceholder': '86400',

  // Trying the draft list before saving it (T9.12).
  'lists.test.label': 'Test it',
  'lists.test.badLines': " Lines it can't use: {lines}",
  'lists.test.works': 'Works: {detail}, in {ms} ms.{notes}',
  'lists.test.fails': "Doesn't work: {detail}.{notes}",
} as const;
