// REQ: API-011 — strings for the shared widgets, English source of truth: the time-series chart
// (its view toggle, the table view, the legend's word for "the whole range", and the change-marker
// overlay), the KPI tile, the donut, and the Changes controls with their note form.
//
// A row that puts a marker's parts together keeps its separators here too: the dot between them,
// the comma between node names, and the `; ` between markers. The English values are exactly what
// the UI said before, so the language on screen did not move by a character.
export const widgets = {
  // The chart's view toggle, and the table it shows instead.
  'widgets.chart.empty': 'No data yet.',
  'widgets.chart.changed': 'Changed',
  // The legend's value for no bucket under the cursor: the total over the range shown.
  'widgets.chart.total': 'total',
  // One change marker's label (its tooltip and what a screen reader says), and how several read
  // one after another.
  'widgets.chart.mark': '{time}: {summary}',
  'widgets.chart.mark.actor': '{time}: {summary} ({actor})',
  // The marker tooltip stops at five: this is the rest of them.
  'widgets.chart.more.one': 'and {n} more',
  'widgets.chart.more.other': 'and {n} more',
  // What a marker's parts are separated by (and what goes between node names). The separator
  // carries a trailing space only: the space before it was, and stays, trimmed by the markup.
  'widgets.chart.sep': '· ',
  'widgets.chart.list': ', ',

  // The KPI tile: what its change against the previous period measures.
  'widgets.kpi.deltaTitle': 'Against the previous period of the same length',

  // The donut's centre when the caller names nothing.

  // The Changes toggle, the note form, and the kind filter.
  'widgets.changes.noteOpen': 'Note…',
  'widgets.changes.what': 'What happened',
  'widgets.changes.whatHint': 'moved the access point to the hallway',
  'widgets.changes.whenHint': '(optional, up to 7 days back)',
  'widgets.changes.add': 'Add note',
  'widgets.changes.noteHelp':
    "Shows on every time chart of every node. Notes can't be edited or deleted; add a correcting one.",
  'widgets.changes.kinds': 'Kinds of changes shown',
  'widgets.barList.bad': 'Bad',
  'widgets.barList.uncertain': '± up to',
  'widgets.changePreview.lead': 'What this will do:',
  'widgets.barList.empty': 'Nothing here.',
  'widgets.barList.bars': 'Bars',
} as const;
