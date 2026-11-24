// REQ: API-011 — settings strings (English): the page's tabs and its cards (account, two-factor,
// domain icons, API tokens, users, audit log), the node's system information (listener checks,
// changes, updates, backup), query handling (cache link, rate limit, exclusions, simulation), and
// the cluster's staged rollouts — plus the config editor, the wall displays, and the support
// package it hosts.
//
// A sentence with something in the middle of it (a `<code>` or a link) is split at that element:
// `…Lead`/`…Mid` end just before it, `…Tail`/`…After` carry on just after it, so the markup keeps
// the element and the English reads as one sentence.
export const settings = {
  'settings.tab.account': 'Account',
  'settings.tab.tokens': 'API tokens',
  'settings.tab.users': 'Users',
  'settings.tab.audit': 'Audit log',
  'settings.tab.queries': 'Query handling',

  // A switch's two states, wherever a table shows one.
  'settings.value.on': 'on',

  // My account: the password, and two-factor sign-in.
  'settings.account.changePassword': 'Change password',
  'settings.account.currentPassword': 'Current password',
  'settings.account.newPassword': 'New password (at least 10 characters)',
  'settings.account.passwordChanged': 'Password changed. Your other sessions were signed out.',
  'settings.twoFactor.title': 'Two-factor sign-in',
  'settings.twoFactor.saveCodes': 'Save these recovery codes now.',
  'settings.twoFactor.saveCodesNote':
    "Each works once if you lose your phone; they won't be shown again.",
  'settings.twoFactor.codesLeft': '{n} recovery codes left.',
  'settings.twoFactor.offPassword': 'Password, to turn it off',
  'settings.twoFactor.turnOff': 'Turn off two-factor',
  'settings.twoFactor.stepOneLead': 'Add this account to an authenticator app: on a phone,',
  'settings.twoFactor.stepOneLink': 'open it in the app',
  'settings.twoFactor.stepOneTail': ', or enter the key by hand:',
  'settings.twoFactor.stepTwo': 'Enter the 6-digit code it shows.',
  'settings.twoFactor.codeLabel': '6-digit code',
  'settings.twoFactor.turnOn': 'Turn on',
  'settings.twoFactor.about':
    'Ask for a code from an authenticator app when signing in, on top of the password.',
  'settings.twoFactor.setup': 'Set up two-factor sign-in',

  // Domain icons: how this browser draws the mark left of a name.
  'settings.icons.title': 'Domain icons',
  'settings.icons.about':
    "The small mark left of a domain name in the dashboard's lists and the query log. It's drawn from what TelltaleDNS already knows, so nothing about your queries is sent to anyone. Remembered for you in this browser.",
  'settings.icons.style': 'Style',
  'settings.icons.brand': 'Brand and monogram',
  'settings.icons.mono': 'Monogram only',
  'settings.icons.off': 'Off',
  'settings.icons.size': 'Size',
  'settings.icons.default': 'Default',
  'settings.icons.small': 'Small',

  // API tokens: the form, the agent scopes, the new token, and the table.
  'settings.tokens.aboutLead': 'For scripts, dashboards, and AI agents: send',
  'settings.tokens.aboutTail': '. A token never has more rights than you.',
  'settings.tokens.nameLabel': 'Token name',
  'settings.tokens.namePlaceholder': 'name, e.g. grafana',
  'settings.tokens.kindUser': 'for my scripts',
  'settings.tokens.kindAgent': 'for an AI agent',
  'settings.tokens.scopeRead': 'read (viewer)',
  'settings.tokens.scopeWrite': 'write (operator)',
  'settings.tokens.expiresLabel': 'Expires',
  'settings.tokens.expiresNever': 'never expires',
  'settings.tokens.expires30': '30 days',
  'settings.tokens.expires90': '90 days',
  'settings.tokens.expiresYear': '1 year',
  'settings.tokens.create': 'Create token',
  'settings.tokens.agentLegend': 'What the agent may do',
  'settings.tokens.groupOnly': "Only this group's devices and queries (optional):",
  'settings.tokens.groupPlaceholder': 'e.g. kids',
  'settings.tokens.agentNoteLead':
    'Agents must give a reason for every change, are limited to 120 requests a minute, show as',
  'settings.tokens.agentNoteMid': 'in the audit log, and stop at once with',
  'settings.tokens.agentNoteTail': '.',
  'settings.tokens.copyNow': "Copy the token now; it won't be shown again.",
  'settings.tokens.empty': 'No tokens yet.',
  'settings.tokens.colScope': 'Scope',
  'settings.tokens.colCreated': 'Created',
  'settings.tokens.colExpires': 'Expires',
  'settings.tokens.groupSuffix': ' · group {group}',
  // REQ: AGT-004 — what an agent token may do (the identifier it sends stays as it is).
  'settings.tokens.scope.analytics': 'Statistics, top lists, anomalies, explain',
  'settings.tokens.scope.querylog': 'The query log (who asked for what)',
  'settings.tokens.scope.configRead': 'Lists, groups, devices, names, upstreams',
  'settings.tokens.scope.clients': 'Name and regroup devices',
  'settings.tokens.scope.records': 'Change names on my network',
  'settings.tokens.scope.forwards': 'Send domains to other servers',
  'settings.tokens.scope.clusterAdmin': 'Promote a node; staged rollouts and pins',
  'settings.tokens.scope.upgrade': 'Install newer TelltaleDNS versions on nodes',

  // Users (an admin's): where a password may be used, the table, and the form.
  'settings.users.passwordSignIn': 'Password sign-in',
  'settings.users.limitedTo': 'Password sign-in is limited to admins on these networks:',
  'settings.users.wholeNetworks': 'Includes whole networks',
  'settings.users.wholeNetworksLead':
    'Anyone on these networks is still shown the sign-in form, not just the machines you name. To limit it to the machines you manage from, list each as a single address, such as',
  'settings.users.onlyListed': 'Only the machines listed are shown the sign-in form.',
  'settings.users.loopbackLead':
    'If a reverse proxy on this machine serves this page, add',
  'settings.users.loopbackMid': 'to',
  'settings.users.loopbackTail':
    '. Until then everyone it serves looks like this machine and can use a password.',
  'settings.users.noNetworks':
    'Password sign-in is limited to admins on no network, so if your sign-in provider is down, nobody can sign in with a password.',
  'settings.users.changeLead': 'Change it with',
  'settings.users.changeMid': 'under',
  'settings.users.changeMid2': 'in the configuration file, then restart. See',
  'settings.users.changeLink': 'Users and sign-in',
  'settings.users.changeTail': 'in the guide.',
  'settings.users.colUser': 'User',
  'settings.users.colRole': 'Role',
  'settings.users.colTwoFactor': 'Two-factor',
  'settings.users.colBasic': 'HTTP Basic',
  'settings.users.you': '(you)',
  'settings.users.signsInWith': 'signs in with {provider}',
  'settings.users.roleOf': 'Role of {name}',
  'settings.users.reset': 'Reset',
  'settings.users.basicFor': 'HTTP Basic for {name}',
  'settings.users.disabledEnable': 'Disabled · enable',
  'settings.users.activeDisable': 'Active · disable',
  'settings.users.tokens': 'Tokens',
  'settings.users.reallyDelete': 'Really delete?',
  'settings.users.delete': 'Delete',
  'settings.users.noTokens': '{name} has no API tokens.',
  'settings.users.tokenOf': "{name}'s token",
  'settings.users.addTitle': 'Add a user',
  'settings.users.usernamePlaceholder': 'username',
  'settings.users.passwordPlaceholder': 'password (10+ characters)',
  'settings.users.add': 'Add',
  'settings.users.rolesNote':
    'Viewers see dashboards and the query log; operators can also pause blocking and manage lists, clients, and groups; admins can do everything.',

  // The audit log (REQ: API-006): the filter, the chain check, and the table.
  'settings.audit.allChanges': 'All changes',
  'settings.audit.signIns': 'Sign-ins and lockouts',
  'settings.audit.verify': 'Verify chain',
  'settings.audit.about':
    "Every change to users, passwords, two-factor sign-in, and API tokens, plus sign-ins, lockouts, and configuration reloads. Entries can't be edited, and each one is chained to the one before it, so tampering is detectable.",
  'settings.audit.intact': 'Chain intact: {n} entries. Head',
  'settings.audit.broken': 'Chain broken at entry {n}',
  'settings.audit.brokenTail': ': the log was changed outside TelltaleDNS.',
  'settings.audit.empty': 'No entries.',
  'settings.audit.colWho': 'Who',
  'settings.audit.colWhat': 'What',
  'settings.audit.reason': 'Reason: {reason}',

  // REQ: CLU-013 — staged rollouts (an admin's): the picker over the nodes, the bake, the guard.
  'settings.cluster.standalone':
    'This node runs on its own: staged rollouts need a cluster (see the Cluster page).',
  'settings.cluster.rollout.noun': 'rollout settings',
  'settings.cluster.rollout.summaryOff': 'off: changes reach every node at once',
  'settings.cluster.rollout.summary.one': '{n} canary entry; bake {bake} s',
  'settings.cluster.rollout.summary.other': '{n} canary entries; bake {bake} s',
  'settings.cluster.rollout.footnote':
    "A change to these settings reaches every node at once (it's never staged itself). The Cluster page shows the version baking, the guard's readings, and the versions you can pin back to.",
  'settings.cluster.rollout.canaries': 'Canary nodes',
  'settings.cluster.rollout.canariesHelp':
    'They (and the primary) get each change first. None: changes reach every node at once.',
  'settings.cluster.rollout.ephemeral': 'resolver pods (Kubernetes)',
  'settings.cluster.rollout.site': 'every node at site {site}',
  'settings.cluster.rollout.bakeTime': 'Bake time (seconds)',
  'settings.cluster.rollout.bakeTimeHelp':
    'How long a change runs on the canaries before everyone gets it. At least 5.',
  'settings.cluster.rollout.servfail': 'Fail above this SERVFAIL share (%)',
  'settings.cluster.rollout.servfailHelp':
    "Or 2 points over the canaries' share before the change, whichever is higher; judged from 50 answers.",
  'settings.cluster.rollout.requireTraffic': 'Wait for 50 answers before judging',
  'settings.cluster.rollout.requireTrafficHelp':
    'Off: a quiet bake passes. On: keep baking until the canaries answered 50 queries (or the longest bake), then judge.',
  'settings.cluster.rollout.maxBake': 'Longest bake (seconds)',
  'settings.cluster.rollout.failOnDisconnect': 'Fail when a canary disconnects for a minute',
  'settings.cluster.rollout.failOnDisconnectHelp':
    'It might have crashed on the change. A pod rescheduled mid-bake fails the rollout too; unpin to try again.',
  'settings.cluster.rollout.history': 'Versions kept for pinning',
  'settings.cluster.rollout.noteNone': 'No canaries: a change reaches every node at once.',
  'settings.cluster.rollout.noteBody':
    'Changes reach {names} (and the primary) first, and the rest after {time} if nothing fails.',
  'settings.cluster.rollout.minutes.one': '{n} minute',
  'settings.cluster.rollout.minutes.other': '{n} minutes',

  // The node's system information (REQ: OBS-002).
  'settings.system.started': 'Started',
  'settings.system.startedValue': '{time} · up {uptime}',
  'settings.system.restarts': 'Restarts',
  'settings.system.unclean': '({n} after a crash or a kill)',
  'settings.system.listeners': 'DNS listeners',
  'settings.system.snapshot': 'Filter snapshot',
  'settings.system.names': ' · {names} names',
  'settings.system.apiRef': 'API reference:',
  'settings.system.apiRefNote': '(OpenAPI 3.1).',

  // REQ: OBS-020 — the listener checks, and what a certificate says (REQ: API-003, ADR-149).
  'settings.probes.title': 'Listener checks',
  'settings.probes.emptyLead':
    'No results yet (the first round runs a few seconds after start), or probes are off (',
  'settings.probes.colAsked': 'Asked',
  'settings.probes.colResult': 'Result',
  'settings.probes.colTime': 'Time',
  'settings.probes.webUi': 'Web UI and API',
  'settings.probes.extraTarget': ' (extra target)',
  'settings.probes.skipped': 'skipped',
  'settings.probes.answers': 'answers',
  'settings.probes.notAnswering': 'not answering',
  'settings.probes.missedOnce': 'missed once',
  'settings.probes.forNames': 'for {names}',
  'settings.probes.certSelfSigned': "self-signed certificate (doesn't expire)",
  'settings.probes.certExpired': 'certificate expired {n} day(s) ago',
  'settings.probes.certExpires': 'certificate expires in {n} day(s)',
  'settings.probes.footnoteLead':
    "Every 30 s each node asks each of its listeners a question through the listener's own protocol, the way a device would. With HTTPS on the web UI (",
  'settings.probes.footnoteTail':
    "), it's checked too: compare its SHA-256 fingerprint with the one your browser shows before trusting a self-signed certificate.",

  // REQ: OBS-033 — the change markers of the last 90 days (every node's).
  'settings.changes.title': 'Changes',
  'settings.changes.kindLabel': 'Kind of change',
  'settings.changes.kindAll': 'every kind',
  'settings.changes.kindConfig': 'configuration applied',
  'settings.changes.kindNotes': 'notes',
  'settings.changes.kindLists': 'list refreshes',
  'settings.changes.kindRollouts': 'rollouts',
  'settings.changes.kindBuilds': 'builds and restarts',
  'settings.changes.kindMaintenance': 'maintenance',
  'settings.changes.kindPauses': 'pauses',
  'settings.changes.kindCache': 'cache flushes',
  'settings.changes.kindUpstreams': 'upstreams benched or recovered',
  'settings.changes.filterPlaceholder': 'Filter',
  'settings.changes.filterLabel': 'Filter changes',
  'settings.changes.empty': 'No changes recorded',
  'settings.changes.emptyMatch': ' that match',
  'settings.changes.emptyTail': ' in the last 90 days.',
  'settings.changes.missing': 'Not answering: {nodes}.',
  'settings.changes.footnote':
    'The last 200 configuration versions, builds, restarts, list refreshes, rollouts, maintenance, pauses, cache flushes, upstreams benched or recovered, and notes, from every node. Each node keeps 90 days.',

  // REQ: OPS-004 — this build, and the published one it is compared with.
  'settings.updates.title': 'Version and updates',
  'settings.updates.thisBuild': 'This build',
  'settings.updates.built': 'Built',
  'settings.updates.commit': ' · commit',
  'settings.updates.channel': ' · {channel} channel',
  'settings.updates.builtValue': '{date} · {target} · {install} install',
  'settings.updates.available': 'Update available',
  'settings.updates.date': '({date})',
  'settings.updates.whatsNew': "What's new",
  'settings.updates.upToDate': 'Up to date',
  'settings.updates.newer': 'Newer than the published {channel} build',
  'settings.updates.newerVersion': ' ({version})',
  'settings.updates.notCheckedLead': 'Not checked (',
  'settings.updates.unknown': 'Not known yet',
  'settings.updates.unknownError': ': {error}',
  'settings.updates.checkNow': 'Check now',

  // REQ: API-007 — one file with everything, and what it holds.
  'settings.backup.title': 'Backup',
  'settings.backup.aboutLead':
    'One file with your settings, users and API tokens, the devices and names you added here, the audit log, and statistics history. Restore it on a new machine with',
  'settings.backup.aboutTail': '.',
  'settings.backup.download': 'Download a backup',
  'settings.backup.privateLead':
    "It holds password hashes, so keep it private. The query log isn't included; for that, run",
  'settings.backup.privateTail': 'on the server.',

  // REQ: DNS-006 — the cache has its own page.
  'settings.queries.cacheAboutLead':
    "Hit rates, what's cached, settings, lookups, and flushing are on the",
  'settings.queries.cacheAboutLink': 'Cache page',
  'settings.queries.cacheAboutTail': '.',

  // REQ: DNS-014 — the per-client rate limit.
  'settings.queries.ratelimit.title': 'Rate limit',
  'settings.queries.ratelimit.noun': 'rate limit',
  'settings.queries.ratelimit.summary':
    '{queries} queries per {window} s per client, then {action}',
  'settings.queries.ratelimit.footnote':
    'One client is one address (IPv6: one /64). A router or proxy that forwards for a whole network looks like one client: add it to "Never limited", or raise the number. A change applies at once and every client\'s count starts over.',
  'settings.queries.ratelimit.enabled': 'Limit queries per client',
  'settings.queries.ratelimit.queries': 'Queries allowed per window',
  'settings.queries.ratelimit.queriesHelp':
    'Per client; short bursts up to this are fine. A client over it gets the action below until its allowance refills.',
  'settings.queries.ratelimit.window': 'Window (seconds)',
  'settings.queries.ratelimit.action': 'When over the limit',
  'settings.queries.ratelimit.actionHelp': 'refused answers REFUSED; drop answers nothing.',
  'settings.queries.ratelimit.exempt': 'Never limited',
  'settings.queries.ratelimit.exemptHelp':
    'Addresses or networks, one per line (a router that forwards for the whole network, say). Replaces the list from the config file, so keep 127.0.0.0/8 and ::1/128.',
  'settings.queries.ratelimit.ipv4': 'IPv4: count clients per /N',
  'settings.queries.ratelimit.ipv4Help': '32 counts each address on its own.',
  'settings.queries.ratelimit.ipv6': 'IPv6: count clients per /N',
  'settings.queries.ratelimit.ipv6Help': "64 groups a device's rotating privacy addresses.",

  // REQ: OBS-022 — names and devices kept out of the query log and analytics.
  'settings.queries.exclusions.title': 'Kept out of the log',
  'settings.queries.exclusions.noun': 'exclusions',
  'settings.queries.exclusions.summaryOff': 'off: ',
  'settings.queries.exclusions.summaryNone': 'nothing excluded',
  'settings.queries.exclusions.summary': '{names} names, {clients} devices',
  'settings.queries.exclusions.footnoteLead':
    'Their queries are still answered and still counted in',
  'settings.queries.exclusions.footnoteTail':
    ', but left out of the query log, the live view, the dashboard and top lists, anomalies, and exports, on every node. Queries logged before stay.',
  'settings.queries.exclusions.enabled': 'Leave these out of the log and stats',
  'settings.queries.exclusions.enabledHelp':
    'Off keeps the lists below but logs everything again.',
  'settings.queries.exclusions.namesHelp':
    'One per line; each covers its subdomains too. Noise like connectivity checks, time servers, or a monitoring probe.',
  'settings.queries.exclusions.clientsHelp':
    'Addresses or networks, one per line (a monitoring host, say).',

  // REQ: OBS-024 — change simulation's switches and bounds.
  'settings.queries.simulate.title': 'Change simulation',
  'settings.queries.simulate.noun': 'simulation settings',
  'settings.queries.simulate.summary': "on, {window} by default; agents' plans {plans}",
  'settings.queries.simulate.always': 'always simulate',
  'settings.queries.simulate.whenAsked': 'simulate when asked',
  'settings.queries.simulate.footnote':
    "A simulation replays the query log with and without a change and shows what would have been answered differently. It never touches DNS answers and runs at background priority; at query-log privacy level 1 or above names can't be replayed.",
  'settings.queries.simulate.enabled': 'Allow change simulations',
  'settings.queries.simulate.enabledHelp':
    'The "What would this have done?" button, the simulate parameter of dry runs, and simulate_change for agents.',
  'settings.queries.simulate.plans': "Agents' plans simulate by default",
  'settings.queries.simulate.plansHelp':
    'Off: a plan simulates only when the agent asks (simulate: "24h"). On: every plan replays the query log, which costs CPU on each node.',
  'settings.queries.simulate.window': 'Default window',
  'settings.queries.simulate.windowHelp':
    'How far back a simulation replays when no window is given: 30m, 24h, up to 7d.',
  'settings.queries.simulate.maxSecs': 'Time limit per node (seconds)',
  'settings.queries.simulate.maxSecsHelp':
    '1 to 300. A node that runs out of time answers with what it read so far (partial).',
  'settings.queries.simulate.maxRows': 'Most logged queries read per node',
  'settings.queries.simulate.maxRowsHelp': 'At least 1,000. Newest first.',

  // REQ: API-002 (T7.5, ADR-069) — the editor that adds, changes, previews, and reverts an entry.
  'settings.editor.add': 'Add {noun}',
  'settings.editor.editTitle': '{noun}: {name}',
  'settings.editor.none': 'None yet.',
  'settings.editor.hiddenNote': 'left out of the configuration',
  'settings.editor.revert': 'Revert to the file',
  'settings.editor.done': 'Done',
  'settings.editor.testing': 'Testing…',
  'settings.editor.sending': 'Sending…',
  'settings.editor.what': 'What this will do:',
  'settings.editor.whatFallback': 'Changes the configuration as shown.',
  'settings.editor.changeIt': 'Change it',
  'settings.editor.check': 'Check',
  'settings.editor.badgeAdded': 'added here',
  'settings.editor.badgeOverride': 'overrides the file',
  'settings.editor.badgeHidden': 'hidden',

  // REQ: OBS-035 (T14.13, ADR-140) — wall displays (an admin's).
  'settings.wall.title': 'Wall displays',
  'settings.wall.about':
    "A link for a screen on the wall: open it once on that screen's browser and it stays signed in, showing only the wall (the traffic map, the flow, the service level, the heatmaps, and the live queries). It can't open any other page or change anything. Limit it to the screen's address if you can; revoke it here to sign the screen out.",
  'settings.wall.namePlaceholder': 'hallway',
  'settings.wall.onlyFrom': 'Only from',
  'settings.wall.networksPlaceholder': '192.168.2.40, 10.0.0.0/24 (optional)',
  'settings.wall.endsAfter': 'Ends after',
  'settings.wall.daysPlaceholder': 'days (optional)',
  'settings.wall.make': 'Make a link',
  'settings.wall.linkNote': ": open this on the wall's browser. It's shown only now.",
  'settings.wall.copyLink': 'Copy the link',
  'settings.wall.empty': 'No wall displays.',
  'settings.wall.colMadeBy': 'Made by',
  'settings.wall.colLastUsed': 'Last used',
  'settings.wall.colEnds': 'Ends',
  'settings.wall.anywhere': 'anywhere',
  'settings.wall.whenRevoked': 'when revoked',
  'settings.wall.revoke': 'Revoke',

  // REQ: OPS-011 (ADR-156) — one redacted file for a bug report.
  'settings.support.title': 'Support package',
  'settings.support.about':
    "One file to attach to a bug report: build and platform facts, your settings (without secrets), cluster and health, upstreams, list names and counts, a metrics snapshot, and this node's recent log. Nothing is uploaded.",
  'settings.support.howMuch': 'How much to hide',
  'settings.support.strict': 'Strict (recommended)',
  'settings.support.strictText':
    'Addresses, device, group, node and pod names, e-mail addresses and home paths become pseudonyms (device-1, 10.4.7.9). No query names, no free text, and only warnings and errors from the log.',
  'settings.support.standard': 'Standard',
  'settings.support.standardText':
    "As strict, plus the log's INFO lines, top lists with pseudonymized names, and, if you choose, a sample of recent queries.",
  'settings.support.none': 'None',
  'settings.support.noneText':
    'Real addresses, names and domains. Passwords, tokens and keys are still removed. Read it yourself before you share it.',
  'settings.support.reveal': 'Keep these readable (names, separated by commas)',
  'settings.support.revealPlaceholder': 'e.g. pi',
  'settings.support.revealLabel': 'Names to keep readable',
  'settings.support.sample': 'Recent queries to include (0 for none)',
  'settings.support.sampleLabel': 'Query sample',
  'settings.support.cluster':
    'Every node in the cluster (each node hides its own names and addresses first, so nothing real crosses the network)',
  'settings.support.keepMap': 'Let me download the key to the pseudonyms (for 10 minutes, once)',
  'settings.support.preview': 'Preview what it holds',
  'settings.support.working': 'Working…',
  'settings.support.make': 'Make the package',
  'settings.support.saved': 'Saved',
  'settings.support.savedSize': '({size} before compression).',
  'settings.support.savedNote':
    'Look it over before you attach it: log lines are redacted by pattern, which is best effort.',
  'settings.support.downloadMap': 'Download the pseudonym map',
  'settings.support.mapGone': '(given out; make another package to get a new one)',
  'settings.support.mapLead':
    'It lists what each pseudonym stands for, so it has your real names and addresses: keep it to yourself, and tell a maintainer what',
  'settings.support.mapTail': 'was only if you want to.',
  'settings.support.previewNote':
    'This is what a package would hold right now; nothing was saved.',
  'settings.support.colAnswered': 'Answered',
  'settings.support.colFiles': 'Files',
  'settings.support.yes': 'yes',
  'settings.support.missing': 'missing',
  'settings.support.colFile': 'File',
  'settings.support.colPart': 'Part',
  'settings.support.colReplaced': 'Replaced or removed',
  'settings.support.cut': 'cut',
  'settings.support.removedSecrets': 'Settings removed as secrets: {fields}.',
  'settings.support.report': 'Please report',
  'settings.support.unclassified':
    'These settings had no rule and were removed: {fields}.',
} as const;
