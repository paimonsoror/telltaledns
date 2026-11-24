// REQ: API-011 — strings for the groups page, English source of truth: the heading and what a
// group is, each group's card (what it holds, its heaviest names this hour, its workloads), the
// settings table under the cards, and the two editors (groups, and the schedules they follow).
//
// A sentence a value sits inside is split at the value, so the markup keeps its own elements:
// `groups.dns64OnStart` ends just before the prefix and `groups.dns64OnEnd` closes after it.
export const groups = {
  // The heading, and what a group is.
  'groups.intro':
    "A group is a kind of device: every device on a group's networks belongs to it (a named device can also be put in a group of its own). Groups decide which lists apply and show what each kind of device does.",

  // A card: a pause, what the group holds, and what it does.
  'groups.pausedUntil': 'paused until {time}',
  'groups.devices.default': 'devices that match nothing else',
  'groups.devices.namedAndWorkloads': 'named devices and Kubernetes workloads',
  'groups.devices.namedOnly': 'named devices only',
  'groups.safeSearch': 'Safe search on',
  'groups.safeSearch.notYouTube': ' (not YouTube)',
  'groups.safeSearch.youtubeModerate': ' (YouTube moderate)',
  'groups.schedulesLabel': 'Schedules:',
  'groups.schedules.onNow': 'on now',
  'groups.blocks': 'Blocks {services}',
  'groups.answers.rebinding': 'Rebinding protection on',
  'groups.answers.blockIps': 'blocks answers in {networks}',
  'groups.rewritesLabel': 'Rewrites:',
  'groups.upstreamsLabel': 'Upstream servers:',
  'groups.dns64OnStart': 'DNS64 on (',
  'groups.dns64OnEnd': ')',
  'groups.filterAaaa': 'No IPv6 addresses (AAAA answered with nothing)',

  // The numbers on a card, and the names it was asked for.
  'groups.stat.queries': 'Queries (24 h)',
  'groups.stat.devices': 'Devices (this hour)',
  'groups.top.names': 'Top names',
  'groups.top.nothingBlocked': 'nothing blocked',

  // The Kubernetes workloads a group holds, and the link to its queries.
  'groups.workloadsLabel': 'Workloads:',
  'groups.workloads.more.one': 'and {n} more',
  'groups.workloads.more.other': 'and {n} more',
  'groups.showQueries': "Show this group's queries",

  // The settings table under the cards.
  'groups.col.priority': 'Priority',
  'groups.col.blocking': 'Blocking',
  'groups.lists.none': 'none',
  'groups.lists.everyEnabled': 'every enabled list',
  'groups.blockTtl': 'TTL {seconds} s',

  // The groups editor: its title and noun, and what a row says about an entry.
  'groups.manage.title': 'Manage groups',
  'groups.manage.noun': 'group',
  'groups.manage.lists.one': '{n} lists',
  'groups.manage.lists.other': '{n} lists',

  // The groups editor's fields.
  'groups.field.networks': 'Networks',
  'groups.field.networksHelp': 'One per line. Every device on these networks belongs to the group.',
  'groups.field.listsHelp': 'Leave all unticked on a new group to use every enabled list.',
  'groups.field.upstreams': 'Upstream servers',
  'groups.field.upstreamsHelp':
    'The upstream group this group’s questions go to. (default) uses the default group; routes for a domain still win.',
  'groups.field.safeSearch': 'Safe search',
  'groups.field.safeSearchHelp':
    'Google, Bing, DuckDuckGo, Yandex, and Pixabay show only safe results; YouTube uses Restricted Mode.',
  'groups.field.youtube': 'YouTube restriction',
  'groups.field.blockedServices': 'Blocked services',
  'groups.field.blockedServicesHelp':
    'Block a whole service (all its domains) for this group, on top of its lists.',
  'groups.field.rebinding': 'Rebinding protection',
  'groups.field.rebindingHelp':
    'Block answers from the internet that point at private addresses (DNS rebinding).',
  'groups.field.blockAnswerIps': 'Block answers in',
  'groups.field.blockAnswerIpsHelp':
    'Answers with an address in these networks are blocked, whatever the name.',
  'groups.field.dns64': 'DNS64',
  'groups.field.dns64Help':
    'Make IPv6 addresses for IPv4-only names, for IPv6-only networks with NAT64.',
  'groups.field.dns64Prefix': 'DNS64 prefix',
  'groups.field.dns64Exclude': 'DNS64 exclusions',
  'groups.field.dns64ExcludeHelp':
    'IPv6 addresses here count as missing (the name gets made-up ones); IPv4 addresses here are never made into IPv6.',
  'groups.field.filterAaaa': 'No IPv6 addresses',
  'groups.field.filterAaaaHelp':
    'Answer IPv6 (AAAA) questions with nothing, so these devices use IPv4: for a network whose IPv6 is broken. Your own names still answer. Not with DNS64.',
  'groups.field.schedulesHelp': 'Schedules this group follows (make them under Schedules, below).',
  'groups.field.blockMode': 'Blocked answer',
  'groups.field.priorityHelp': 'When a device matches several groups, the highest priority wins.',
  'groups.field.color': 'Color',

  // The schedules editor under the groups: its title and noun, its fields, and what it says about
  // a window that doesn't read.
  'groups.schedule.title': 'Schedules',
  'groups.schedule.noun': 'schedule',
  'groups.schedule.action': 'During the windows',
  'groups.schedule.actionHelp':
    'block_all: a bedtime (everything blocked except quick allow rules and local names). enable_lists: extra lists apply. block_services: extra services are blocked.',
  'groups.schedule.window': 'Windows (one per line)',
  'groups.schedule.windowHelp':
    'Days: mon … sun, weekdays, weekends, daily. An end before the start runs past midnight.',
  'groups.schedule.lists': 'Lists (enable_lists)',
  'groups.schedule.services': 'Services (block_services)',
  'groups.schedule.tz': 'Time zone',
  'groups.schedule.tzHelp': 'IANA time zone. Default: the node’s.',
  'groups.schedule.errLine': '"{line}": write the days and times like "weekdays 21:00-07:00"',
  'groups.schedule.errEmpty': 'Add at least one window, like "weekdays 21:00-07:00".',
} as const;
