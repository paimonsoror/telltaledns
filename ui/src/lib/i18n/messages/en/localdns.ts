// REQ: API-011 — strings for the localdns page ("Names on my network"), English source of truth:
// the names TelltaleDNS answers itself, the zones the config files declare, the domains sent to
// other servers, and the two drawers that add or change them.
//
// A sentence with an element inside it is split at that element (`…Start` ends just before it,
// `…End` carries on just after it), so the `<code>`, `<b>`, and `<em>` stay where they are.
export const localdns = {
  // The heading and its subtitle (the DNS word), and the buttons that open a form: a button's
  // words are also its drawer's title.
  'localdns.subtitle': 'Local DNS',
  'localdns.setUpHomeDomain': 'Set up my home domain',
  'localdns.addName': 'Add a name',
  'localdns.editName': 'Edit {name}',
  'localdns.sendDomain': 'Send a domain to another server',

  // Nothing defined yet, with an example name in the middle.
  'localdns.emptyStart':
    'No local names yet. “Set up my home domain” gives your NAS, printer, or server a name like ',
  'localdns.emptyEnd': ' that every device can use.',

  // A name's table: its columns, where the name is defined, and what a row offers.
  'localdns.col.answers': 'Answers with',
  'localdns.col.ttl': 'TTL',
  'localdns.ttlDefault': 'default',
  'localdns.source.ui': 'the UI / API',
  'localdns.test': 'Test',
  'localdns.removeName': 'Remove {name}',

  // The zones from the config files: what they are, and who sees one.
  'localdns.zones.title': 'Zones',
  'localdns.zones.introStart':
    'TelltaleDNS answers everything under these domains itself, from the configuration files (',
  'localdns.zones.introEnd':
    "): names it doesn't have get “no such name”. A zone limited to groups is seen only by their devices.",
  'localdns.zones.col.zone': 'Zone',
  'localdns.zones.col.records': 'Records',
  'localdns.zones.col.seenBy': 'Seen by',

  // The domains sent elsewhere: the table, its empty state, and the stub-zone mark.
  'localdns.forwards.title': 'Domains sent to other servers',
  'localdns.forwards.empty': 'None: every name not on this page is asked of the public DNS servers.',
  'localdns.forwards.stub': '(stub zone)',
  'localdns.forwards.remove': 'Stop sending {domain}',

  // What a change will do, in one sentence (the preview shows the page's own words).
  'localdns.preview.a': 'the address {value}',
  'localdns.preview.aaaa': 'the IPv6 address {value}',
  'localdns.preview.cname': 'the same answer as {value}',
  'localdns.preview.ptr': 'the name {value} (a reverse lookup)',
  'localdns.preview.txt': 'the text “{value}”',
  'localdns.preview.mx': 'mail server {value}',
  'localdns.preview.srv': 'service {value}',
  'localdns.preview.sentence':
    'Every device that asks for {name} gets {what}, answered by TelltaleDNS itself.',
  'localdns.preview.sentenceReverse':
    'Every device that asks for {name} gets {what}, answered by TelltaleDNS itself, and a reverse lookup of the address finds the name.',
  'localdns.preview.anyDevice': 'Any device',

  // The "add a name" form (and the wizard's second step).
  'localdns.form.value': 'Value',
  'localdns.form.typeA': 'A (IPv4 address)',
  'localdns.form.typeAAAA': 'AAAA (IPv6 address)',
  'localdns.form.typeCNAME': 'CNAME (alias of another name)',
  'localdns.form.alsoKeeps': 'Also keeps: {records}.',
  'localdns.form.back': 'Back',
  'localdns.form.saving': 'Saving…',
  'localdns.form.needName': 'Give the name, like nas.home.arpa.',
  'localdns.form.saved': 'Saved. {name} now answers on every device.',

  // The home-domain wizard's first step: why home.arpa.
  'localdns.wizard.introStart': "Pick the domain your devices' names end with. ",
  'localdns.wizard.introEnd':
    ' is reserved for exactly this (RFC 8375), so it never clashes with the internet; use a domain you own if you have one.',
  'localdns.wizard.homeDomain': 'Home domain',
  'localdns.wizard.next': 'Next',
  'localdns.wizard.firstDevice': 'Now your first device. You can add more with “Add a name”.',
  'localdns.wizard.deviceName': 'Device name',
  'localdns.wizard.fullNameStart': 'Its full name will be ',

  // The "send a domain" drawer: where it goes, and the stub-zone choice.
  'localdns.forward.intro':
    "For names that only another DNS server knows: a work network over VPN, your router's own names, another lab.",
  'localdns.forward.domain': 'Domain',
  'localdns.forward.servers': 'Server address',
  'localdns.forward.serversHintStart':
    'Several servers: separate them with spaces (tried in order). Encrypted: ',
  'localdns.forward.stubLabel':
    'These servers only know this domain, and hand some sub-domains to other servers',
  'localdns.forward.stubBefore': 'A ',
  'localdns.forward.stubTerm': 'stub zone',
  'localdns.forward.stubAfter':
    ": the servers are asked directly (by IP address) and their hand-offs are followed, as BIND's stub zones do. Use it when the servers refuse other questions.",
  'localdns.forward.sentence':
    'Every name under {domain} is asked of {servers} instead of the public DNS servers; your local names still answer first.',
  'localdns.forward.sentenceStub':
    'Every name under {domain} is looked up starting at {servers}, following any sub-domains they hand to other servers, instead of the public DNS servers; your local names still answer first.',
  'localdns.forward.saved': 'Saved. Names under {domain} now go to {servers}.',
} as const;
