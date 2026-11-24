// REQ: API-011 — help strings (English): the "?" panel's own labels and the words its flow
// diagram is drawn with. The topics themselves are translated in docs/help/topics.zh-CN.json.
export const help = {
  // The button and the panel's headings, in the order the panel shows them.
  'help.button.aria': 'Help: {title}',
  'help.panel.when': "When you'd use it",
  'help.panel.example': 'Example',
  'help.panel.caution': 'Careful',
  'help.panel.termBefore': 'The DNS term for this is ',
  'help.panel.docs': 'Full documentation',

  // The flow diagram: the boxes, then the sentence under it.
  'help.flow.aDevice': 'A device',
  'help.flow.aName': 'a name',
  'help.flow.asks': 'asks for a name',
  'help.flow.decides': 'decides',
  'help.flow.refused': 'refused',
  'help.flow.fromMemory': 'From memory',
  'help.flow.local': 'Your names',
  'help.flow.localSub': 'local records',
  'help.flow.blockedSub': 'filter lists',
  'help.flow.route': 'Another server',
  'help.flow.routeSub': 'routes',
  'help.flow.upstream': 'Public DNS',
  'help.flow.upstreamSub': 'upstreams',
  'help.flow.sentence': '{device} asks for {name}; TelltaleDNS {outcome}{detail}.',
  'help.flow.answer.cache': 'answers from memory, because it was asked recently',
  'help.flow.answer.local': 'answers with one of your own names',
  'help.flow.answer.blocked': 'blocks it, so it never loads',
  'help.flow.answer.route': 'asks the server you chose for that domain',
  'help.flow.answer.upstream': 'asks a public DNS server and remembers the answer',
  'help.flow.answer.refused': 'refuses, because the device may not use this server',
} as const;
