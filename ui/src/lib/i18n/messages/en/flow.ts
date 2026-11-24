// REQ: API-011 — strings for the flow page, English source of truth: the heading and the
// controls above the diagram, the device form, the card head (what it shows and how much), the
// notices, the table view, and the diagram's own labels (its screen-reader text, a node's
// tooltip, the legend under it). The stage names come from `lib/sankey.ts`, not from here.
//
// Where a swatch (`<span class="sw">`) sits in the middle of a sentence, the sentence is split:
// `…bands` ends just before it and `…fail` carries on just after it.
export const flow = {
  // The heading and the controls above the diagram.
  'flow.what': 'What',
  'flow.network': 'Network',
  'flow.device': 'Device',
  'flow.window': 'Window',
  'flow.window.15m': '15 min',
  'flow.window.1h': '1 h',
  'flow.window.6h': '6 h',
  'flow.window.24h': '24 h',
  'flow.window.7d': '7 d',
  'flow.showSmall': 'Show small',
  'flow.live': 'Live',

  // The device address form, which a device opens with.
  'flow.devicePlaceholder': 'a device address, e.g. 192.168.2.14',
  'flow.deviceAddress': 'Device address',
  'flow.show': 'Show',

  // The card head: what it shows, how many answers, and the table toggle.
  'flow.pickDevice': 'Pick a device',
  'flow.answers.one': '· {n} answer',
  'flow.answers.other': '· {n} answers',
  'flow.fromQueryLog': ', from the query log',
  'flow.updated': '· updated {time}, every 15 s',
  'flow.diagram': 'Diagram',
  'flow.table': 'Table',

  // What the card says about the numbers it could not use.
  'flow.missingNodes': "Without {nodes}: they didn't answer.",
  'flow.partial':
    'Some of this window was counted by a build without flow counts: those answers are missing.',
  'flow.truncated': 'The query log read stopped early: the numbers cover what it read.',

  // What an empty card says.
  'flow.enterDevice': 'Enter one above.',
  'flow.empty': 'No answers in this window.',

  // The table view: its columns (the cells are data).
  'flow.col.from': 'From',
  'flow.col.to': 'To',
  'flow.col.answers': 'Answers',
  'flow.col.share': 'Share',

  // The diagram: its screen-reader text, a node's tooltip, and the legend under it.
  'flow.diagramAria':
    'Query flow: groups, then decisions, upstreams and response codes; band widths are answer counts. The table view lists every link.',
  'flow.nodeEndHere.one': ' · {n} ends here',
  'flow.nodeEndHere.other': ' · {n} end here',
  'flow.legend.bands': 'Band width = answers, each counted for exactly that pair; ',
  'flow.legend.fail': ' red bands end in a SERVFAIL.',
  'flow.legend.folded.one': '{n} node under 0.5 % is folded into “other” (Show small lists it).',
  'flow.legend.folded.other': '{n} nodes under 0.5 % are folded into “other” (Show small lists them).',
  'flow.legend.select': 'Select a node for the page behind it.',
  'flow.stage.status': 'Decision',
  'flow.stage.upstream': 'Upstream',
  'flow.stage.rcode': 'Response',
} as const;
