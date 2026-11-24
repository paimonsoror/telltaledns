// REQ: API-011 — clients strings (English): the page and its four tabs (the last hour,
// configured devices, Kubernetes workloads, discovered devices), the tables in them, the routers
// edited below the discovered ones, and the per-device drawer (rhythm and timeline).
//
// A sentence with something in the middle of it (a `<code>` or a `<strong>`) is split at that
// element: `…Lead`/`…Mid` end just before it, `…Tail`/`…After` carry on just after it, so the
// markup keeps the element and the English reads as one sentence.
export const clients = {
  // The page, its heading, and the tabs (a tab's count is a number, shown by the tabs).
  'clients.tab.seen': 'Last hour',
  'clients.tab.devices': 'Devices',
  'clients.tab.workloads': 'Workloads',
  'clients.tab.discovered': 'Discovered',

  // Clients seen in the last hour: the heading, a node that didn't answer, and an empty table.
  'clients.seen.title': 'Seen in the last hour',
  'clients.seen.missing': 'Without {names}: they didn’t answer, so their clients aren’t listed.',
  'clients.seen.empty': 'No queries in the last hour.',
  'clients.col.servers': 'Servers',
  'clients.col.queries': 'Queries',
  'clients.link.when': 'When',
  'clients.link.rhythm': 'Rhythm',
  'clients.link.day': 'Day',

  // Configured devices: the heading, what an empty table says, and its columns.
  'clients.devices.emptyLead':
    'No devices yet. Click an address anywhere (here, the dashboard, or the query log) and choose “Name this device…”, or add ',
  'clients.devices.emptyTail': ' entries to the config file.',
  'clients.col.name': 'Name',
  'clients.col.recognizedBy': 'Recognized by',
  'clients.col.definedIn': 'Defined in',
  'clients.devices.noGroup': "its network's group, wherever it's seen",
  'clients.from.network': 'from its network',
  'clients.from.default': 'default: no network group matches',
  'clients.forget': 'Forget',
  'clients.forgetAria': 'Forget {name}',

  // Kubernetes workloads: the heading, the namespace filter, what a workload is, and the columns.
  'clients.workloads.title': 'Kubernetes workloads',
  'clients.workloads.namespace': 'Namespace',
  'clients.workloads.introLead':
    'Each workload is one device, whichever pods it runs: its queries, anomalies, and timeline survive rollouts. Its group comes from a ',
  'clients.workloads.introTail':
    ' label on its pods or namespace, a rule, or the default group. Counts cover the last 24 hours.',
  'clients.col.workload': 'Workload',
  'clients.col.pods': 'Pods',
  'clients.col.blocked': 'Blocked',
  'clients.col.lastSeen': 'Last seen',
  'clients.col.last24h': 'In the last 24 hours',
  'clients.workloads.notInLastDay': 'not in the last day',
  'clients.workloads.terminating': ' (terminating)',
  'clients.kind.deploy': 'Deployment',
  'clients.kind.sts': 'StatefulSet',
  'clients.kind.ds': 'DaemonSet',
  'clients.kind.job': 'Job',
  'clients.kind.cronjob': 'CronJob',
  'clients.kind.rs': 'ReplicaSet',
  'clients.kind.pod': 'Pod',

  // Devices found by the routers' DHCP or mDNS: the heading, what it lists, and its columns.
  'clients.discovered.title': 'Discovered on your network',
  'clients.discovered.introLead': "Names your router's DHCP knows (",
  'clients.discovered.introMid': ': UniFi, OPNsense), or that devices announced themselves over mDNS (',
  'clients.discovered.introTail':
    '). Unnamed devices already show these names; click an address to keep one, change it, or put the device in a group.',
  'clients.discovered.emptyLead': 'Nothing discovered yet. Connect your router under ',
  'clients.discovered.emptyMid': ', below, or set ',
  'clients.col.nameItGave': 'Name it gave',
  'clients.col.from': 'From',
  'clients.col.inTelltale': 'In TelltaleDNS',
  'clients.discovered.notNamed': 'not named yet',
  // What a lease came from (the value stays the API's `router` or `mdns`).
  'clients.source.mdns': 'mDNS',

  // The routers, added and changed here (the config editor below the discovered devices).
  'clients.router.title': 'Routers',
  'clients.router.noun': 'router',
  'clients.router.urlHelp':
    'UniFi OS consoles: https://192.168.1.1. The classic Network application: https://controller:8443. OPNsense: https://opnsense.lan. A pasted key is sent only over https://. Changing the address (or the type, site or TLS settings) needs the key pasted again.',
  'clients.router.apiKeyHelp':
    'UniFi Network 9+: Settings → Control Plane → Integrations. OPNsense: System → Access → Users → API keys. It is saved on the node that takes configuration changes, and not in backups.',
  'clients.router.apiSecret': 'API secret (OPNsense)',
  'clients.router.username': 'Username (UniFi, instead of an API key)',
  'clients.router.usernameHelp': 'A local UniFi user; read-only is enough.',
  'clients.router.password': 'Password (UniFi)',
  'clients.router.site': 'Site (UniFi)',
  'clients.router.tlsCa': 'Console certificate',
  'clients.router.tlsCaHelp': 'A self-signed console: a file with its certificate, so it is verified.',
  'clients.router.tlsName': 'Name in the certificate',
  'clients.router.tlsNameHelp': 'UniFi consoles name themselves unifi.local.',
  'clients.router.tlsInsecure': "Don't check the certificate",
  'clients.router.tlsInsecureHelp':
    'Works with any console, but anything on your network could pose as it and receive the key. With a pasted key, give the address as a number (https://192.168.1.1).',
  'clients.router.interval': 'Read every (seconds)',
  'clients.router.offlineDays': 'Offline devices seen within (days, UniFi)',
  'clients.router.offlineDaysHelp': '0: only the connected clients.',

  // A key that is already saved: what the field says, and what goes in it.
  'clients.keep.apiKey': 'API key',
  'clients.keep.apiSecret': 'API secret',
  'clients.keep.password': 'password',
  'clients.keep.saved': 'Saved. Type a new {what} to replace it.',
  'clients.keep.missing': 'Key missing: enter the {what} again',
  'clients.keep.fileMissing': 'Key file missing: put the file there (or paste the {what})',
  'clients.keep.notUsed': 'Not used: enter the {what} again',
  'clients.keep.paste': 'Paste the {what}',

  // What a router's row says about its keys.
  'clients.routerStatus.missing': 'key missing: enter it again',
  'clients.routerStatus.fileMissing': 'key file missing: put the file there, or paste the key',
  'clients.routerStatus.notUsed': 'key not used: enter it again',
  'clients.routerStatus.saved': 'key saved',
  // A page opened over plain HTTP from another machine sends what is pasted into it unencrypted.
  'clients.plainHttp':
    'You are on a plain-HTTP page: a key you paste crosses the network unencrypted. Open this page over https first.',

  // A device's drawer: its view, its rhythm, and its day.
  'clients.device.view': 'Device view',
  'clients.device.timeline': 'Timeline',
  'clients.device.timelineIntro':
    "This device's day from the query log: a lane per domain it talks to, the answer time below, and what happened above.",
  'clients.device.rhythmIntro':
    'How regularly this device asks for each domain it talks to most: each column is a gap between two queries (log scale), darker where more of them fall. One dark cell is a timer; a smear is a person.',
  'clients.device.anomalyOffLead': 'The anomaly engine is off (',
  'clients.device.anomalyOffTail': '), so nothing measures the rhythm.',
  'clients.device.notAnswering': 'Not answering: {names}.',
} as const;
