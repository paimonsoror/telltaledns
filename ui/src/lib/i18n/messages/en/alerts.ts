// REQ: API-011 — strings for the alerts page, English source of truth: the page and the card of
// what fires now, a node's maintenance notice, the last delivery per destination, and the two
// editors (destinations, with "Send test", and the rules).
//
// A sentence a name sits inside (a `<strong>` around it) is split at the name: `…lead` ends just
// before it, `…rest` carries on just after it, so the markup keeps the element.
export const alerts = {
  // The page, and the card of what fires now.
  'alerts.now.title': 'Now',
  'alerts.now.elsewhere':
    "Rules are checked on the cluster's primary (or a node on its own); there's nothing to check here.",
  'alerts.now.empty': 'Nothing is firing.',
  'alerts.now.about': 'About',

  // A node in maintenance has its alerts paused.
  'alerts.maintenance.lead': 'Alerts for',
  'alerts.maintenance.rest': 'are paused during maintenance until {when} ({reason}).',

  // How the last delivery to each destination went.
  'alerts.deliveries.title': 'Last delivery per destination',
  'alerts.deliveries.delivered': 'delivered',

  // Destinations: the editor's title and noun, its fields, and "Send test".
  'alerts.dest.title': 'Destinations',
  'alerts.dest.noun': 'destination',
  'alerts.dest.typeHelp':
    'email (any provider’s SMTP), ntfy or Gotify (phone push), slack (Slack, Mattermost, Discord), or a JSON webhook.',
  'alerts.dest.addressPlaceholder': 'smtp://smtp.gmail.com:587 or https://ntfy.sh/my-topic',
  'alerts.dest.addressHelp':
    'Email: smtp://host:587 (STARTTLS) or smtps://host:465. Others: the https:// URL.',
  'alerts.dest.from': 'From (email)',
  'alerts.dest.to': 'To (email, one per line)',
  'alerts.dest.account': 'Account (email)',
  'alerts.dest.passwordFile': 'Password file (email)',
  'alerts.dest.passwordFileHelp':
    "A file on the node holding the password (a Gmail app password, for example). The password itself never goes through the UI. An administrator sets this. Use a file under /run/secrets, /etc/telltale-secrets or the data directory's secrets folder.",
  'alerts.dest.tokenFile': 'Token file (ntfy, Gotify)',
  'alerts.dest.tokenFileHelp':
    "A file on the node holding the access token. An administrator sets this. Use a file under /run/secrets, /etc/telltale-secrets or the data directory's secrets folder.",
  'alerts.dest.tlsCa': 'Private CA (email)',
  'alerts.dest.sendTest': 'Send test',
  'alerts.dest.sent': 'sent. Check that it arrived.',
  'alerts.dest.notDelivered': 'not delivered',

  // Rules: the editor's title and noun, and its fields.
  'alerts.rule.title': 'Rules',
  'alerts.rule.noun': 'rule',
  'alerts.rule.when': 'When',
  'alerts.rule.sendTo': 'Send to',
  'alerts.rule.forSecs': 'For at least (seconds)',
  'alerts.rule.forSecsHelp':
    'How long the condition must hold before the alert goes out, so short blips stay quiet.',
  'alerts.rule.threshold': 'Threshold (%)',
  'alerts.rule.thresholdPlaceholder': '5 (servfail_rate) or 90 (disk_full)',
  'alerts.rule.on': 'On',
  'alerts.rule.summaryOff': ' (off)',
} as const;
