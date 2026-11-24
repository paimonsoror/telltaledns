// REQ: API-011 — strings for the cluster page, English source of truth.
//
// A sentence the page splits around markup keeps its punctuation on the side it was on: the
// value after a name or a `<span>` carries the space and the comma, so the rendered text does
// not change. The tab labels double as the heading or the link that names the same place.
export const cluster = {
  // The heading, the health badge, and the maintenance banner above everything.
  'cluster.healthy': 'Healthy',
  'cluster.needsAttention': 'Needs attention ({n})',
  'cluster.maint.bannerTitle': 'This node is in maintenance',
  'cluster.maint.bannerBody':
    ' until {until} ({reason}, by {by}): it reports not ready, so load balancers send it no new queries, and it keeps answering what still arrives. Its alerts and health conditions are paused.',
  'cluster.maint.end': 'End maintenance',
  'cluster.maint.open': 'Maintenance…',
  'cluster.maint.title': 'Maintenance',
  'cluster.maint.by': 'by {by}',
  'cluster.maint.badge': 'maintenance',
  'cluster.maint.left': '{time} left',
  'cluster.maint.hint':
    'Taking this machine down for a while? Maintenance makes it report not ready (so a load balancer moves away) and pauses its alerts, while it keeps answering DNS.',

  // The notes a removal and a failover drill leave above the page.
  'cluster.remove.open': 'Remove…',
  'cluster.remove.done': '{site} ({id}) was removed from the cluster.',
  'cluster.drill.open': 'Drill…',
  'cluster.drill.started':
    '{preview} The report follows about a minute after it ends, under Drills.',

  // A node that runs on its own: what a cluster is, the commands, and its machine.
  'cluster.standalone.title': 'This node runs on its own',
  'cluster.standalone.about':
    'A cluster keeps several TelltaleDNS nodes on one configuration: change it in one place, and every node (a Pi, a Kubernetes pod, another machine) follows within seconds, keeps answering if the others are down, and shows up here with its health.',
  'cluster.standalone.comment': 'then, on the other node:',
  'cluster.standalone.hint':
    "Run these as the user TelltaleDNS runs as, then restart it. See the help for what's shared and what stays per node.",
  'cluster.machine.title': 'This machine',
  'cluster.machine.cardTitle': 'This node',

  // The summary: the cluster, its nodes, where the configuration comes from, the failover.
  'cluster.configuration': 'Configuration',
  'cluster.config.version': 'version {version}',
  'cluster.config.from': 'Configuration from',
  'cluster.config.git': 'Git:',
  'cluster.config.commit': 'commit',
  'cluster.config.by': 'by {author}',
  'cluster.config.signedBy': ', signed by {signer}',
  'cluster.config.noCommit': 'no commit accepted yet: nothing is published until one is',
  'cluster.config.refused': 'Newest commit refused',
  'cluster.config.checkFailed': 'Repository check failed',
  'cluster.config.keepsServing': 'Every node keeps serving the commit above.',
  'cluster.config.fromGit': 'Git (only Git-managed nodes may publish it)',
  'cluster.config.fromPrimary': 'the primary (its file and UI)',
  'cluster.primary': 'Primary',
  'cluster.failover': 'Failover',
  'cluster.failover.automatic': 'automatic: {reachable} of {voters} voters reachable',
  'cluster.failover.lease': "· this primary's lease: {seconds} s left",
  'cluster.failover.votedFor': 'voted for {site} in epoch {epoch}',
  'cluster.failover.waiting': 'automatic, but waiting for 3 or more voters ({voters} now)',
  'cluster.failover.manual': 'manual (promote a node when the primary is gone)',

  // Promotion (ADR-051): the button, its confirmation, and the password it asks for.
  'cluster.promote.primaryUp': 'The primary is up',
  'cluster.promote.takeoverOpen': 'Take over from the emergency primary…',
  'cluster.promote.open': 'Promote this node…',
  'cluster.promote.available': 'Available when the primary is gone.',
  'cluster.promote.aria': 'Promote this node',
  'cluster.promote.takeoverTitle': 'Make {site} the primary again?',
  'cluster.promote.takeoverBody':
    'The emergency primary ({primaries}) steps down by itself, and this node publishes from Git again, continuing from version {version}.',
  'cluster.promote.title': 'Make {site} the primary?',
  'cluster.promote.body':
    'Use this only when the primary is gone. This node continues from version {version}; if the old primary comes back, it steps down, and anything it changed in the meantime is listed under Conflicts.',
  'cluster.promote.emergency':
    "Emergency: keep the configuration at version {version} (this node isn't managed from Git, so it can't publish changes)",
  'cluster.promote.password': 'Your password',
  'cluster.promote.code': 'Code from your authenticator app',
  'cluster.promote.promoting': 'Promoting…',
  'cluster.promote.promote': 'Promote',

  // A pinned cluster says so on every tab but Rollouts.
  'cluster.pin.title': 'The cluster is pinned to version {version}',
  'cluster.pin.body':
    "by {by}: {reason}. Configuration changes wait until it's unpinned.",

  // The tabs, and what a tab's count says.
  'cluster.health.title': 'Health',
  'cluster.rollouts.title': 'Rollouts',
  'cluster.events.title': 'Events',
  'cluster.compare.title': 'Compare',
  'cluster.drills.title': 'Drills',
  'cluster.tab.compareOdd': '{n} odd',
  'cluster.tab.drillsRunning': 'running',
  'cluster.stage.baking': 'baking',
  'cluster.stage.waiting': 'waiting',
  'cluster.stage.pinned': 'pinned',

  // The topology, the nodes table, and the pods of a site.
  'cluster.topology.title': 'Topology',
  'cluster.col.status': 'Status',
  'cluster.col.servingDns': 'Serving DNS',
  'cluster.col.version': 'Version',
  'cluster.col.uptime': 'Uptime',
  'cluster.node.witness': 'witness',
  'cluster.node.pod': 'pod',
  'cluster.node.on': ' on ',
  'cluster.node.gitManaged': 'Git-managed',
  'cluster.node.localFile': 'local file',
  'cluster.node.up': 'up',
  'cluster.node.down': 'down',
  'cluster.node.seen': 'seen {time} ago',
  'cluster.node.canary': 'canary',
  'cluster.node.behind': '{n} behind',
  'cluster.node.behindFor': '{n} behind for {time}',
  'cluster.node.inSync': 'in sync',
  'cluster.node.ready': 'ready',
  'cluster.node.notReady': 'not ready',
  'cluster.node.shareOfQueries': ' ({pct} of queries)',
  'cluster.node.upstreamP90': 'upstream p90',
  'cluster.node.cache': 'cache:',
  'cluster.node.cacheHits': '{pct} hits',
  'cluster.node.noLookups': 'no lookups',
  'cluster.node.entries': '{n} entries',
  'cluster.node.restarts.one': '{n} restart',
  'cluster.node.restarts.other': '{n} restarts',
  'cluster.node.certUntil': 'cert until {date}',
  'cluster.pods.count.one': '{n} resolver pod',
  'cluster.pods.count.other': '{n} resolver pods',
  'cluster.pods.up': '{n} up',
  'cluster.pods.ready': '{n} ready',
  'cluster.pods.behind': '{n} behind',
  'cluster.pods.cacheAvg': '· cache {pct} hits on average (each pod has its own)',
  'cluster.nodes.empty': 'No other node has connected yet. On another node:',
  'cluster.nodes.emptyMid': 'with a token from',

  // The health tab: the checks (their words come from the API) and the conflicts.
  'cluster.checks.title': 'Checks',
  'cluster.conflicts.title': 'Conflicts',
  'cluster.conflicts.about':
    'Versions this node published after another node took over as primary. They were never applied anywhere; to keep a change, make it again where the configuration comes from now.',
  'cluster.conflicts.version': 'Version {n}',
  'cluster.conflicts.when': '(epoch {epoch}, published {date} {time})',
  'cluster.conflicts.changed': 'Changed:',
  'cluster.machines.title': 'Machines',

  // The events tab: the last hour's churn, the timeline, and what each event was.
  'cluster.events.lastHour': 'Last hour:',
  'cluster.events.joined': '{n} joined',
  'cluster.events.gone.one': '{n} pod gone',
  'cluster.events.gone.other': '{n} pods gone',
  'cluster.events.restarted.one': '{n} restart',
  'cluster.events.restarted.other': '{n} restarts',
  'cluster.events.empty': 'Nothing yet.',
  'cluster.kind.joined': 'Joined',
  'cluster.kind.connected': 'Connected',
  'cluster.kind.disconnected': 'Disconnected',
  'cluster.kind.published': 'Published',
  'cluster.kind.applied': 'Applied',
  'cluster.kind.syncFailed': 'Sync failed',
  'cluster.kind.rejected': 'Rejected',
  'cluster.kind.restarted': 'Restarted',
  'cluster.kind.expired': 'Pod gone',
  'cluster.kind.left': 'Left',
  'cluster.kind.voted': 'Voted',
  'cluster.kind.certIssued': 'Certificate',
  'cluster.kind.caRotation': 'CA rotation',
  'cluster.kind.maintenanceEnded': 'Back in service',
  'cluster.kind.handover': 'Maintenance handover',
  'cluster.kind.handoverFailed': 'Handover failed',
  'cluster.kind.leaseReleased': 'Lease released',
  'cluster.kind.steppedDown': 'Stepped down',
  'cluster.kind.rolloutStarted': 'Rollout',
  'cluster.kind.rolloutPromoted': 'Promoted',
  'cluster.kind.rolloutFailed': 'Rollout failed',
  'cluster.kind.pinned': 'Pinned',
  'cluster.kind.unpinned': 'Unpinned',
} as const;
