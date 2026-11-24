// REQ: API-011 — strings for the heatmap page, English source of truth: the heading, the
// controls beside it (what is counted, over which window, in what slots), the card's head, the
// tooltip over a cell, the table view, and the legend under the grid.
//
// A slot's grain can be any value the API reports (`heatmap.grain.15m` is the one the UI names
// itself); the day labels along the rows come from the grid, not from here.
export const heatmap = {
  // The heading and the segmented controls: what is counted, and over which window.
  'heatmap.what': 'What',
  'heatmap.scope.network': 'Network',
  'heatmap.window.90d': '90 d',
  'heatmap.slot': 'Slot',
  'heatmap.slot.hour': 'hours',
  'heatmap.slot.15m': '15 minutes',
  'heatmap.slot.minute': 'minutes',
  'heatmap.count': 'Count',
  'heatmap.count.queries': 'queries',
  'heatmap.typicalWeek': 'Typical week',

  // The form for a device or a name: its hint and the words a screen reader hears.
  'heatmap.keyPlaceholder.name': 'a name, e.g. pool.ntp.org',
  'heatmap.show': 'Show',

  // The card's head: what the grid covers, how its slots are cut, and the two views.
  'heatmap.head.all': 'The whole network',
  'heatmap.head.pickDevice': 'Pick a device',
  'heatmap.head.pickName': 'Pick a name',
  'heatmap.grain.15m': '15-minute',
  'heatmap.slots': '{grain} slots, your local time',
  'heatmap.dayTimeline': 'Day timeline',
  'heatmap.missing': "Without {nodes}: they didn't answer.",
  'heatmap.empty': 'Enter one above.',

  // The table view, and what the grid is when it is read out.
  'heatmap.col.day': 'Day',
  'heatmap.grid.aria':
    'Heatmap: rows are days, columns times of day. Arrow keys move between cells, Enter opens the query log.',
  'heatmap.grid.role': 'heatmap',

  // The tooltip over a cell: when it is, and what it counted.
  'heatmap.tip.below': "{when} · below this hour's top list",
  'heatmap.tip.none': '{when} · no data',
  'heatmap.measure.blocked': 'blocked queries',
  'heatmap.tip.value': '{when} · {count} {what}',
  'heatmap.tip.average.one': '{when} · {count} {what} on average over {n} day',
  'heatmap.tip.average.other': '{when} · {count} {what} on average over {n} days',

  // What the colours, the bars, and the hatch mean.
  'heatmap.legend.stronger':
    'Stronger colour = more {what}; bars at the right and bottom sum each row and column.',
  'heatmap.legend.topListBefore': "Counts come from each hour's top 100: ",
  'heatmap.legend.topListAfter': ' hatched hours had this one below the list.',
  'heatmap.legend.cell':
    'Select a cell for its queries (the query log keeps fewer days than the heatmap).',
} as const;
