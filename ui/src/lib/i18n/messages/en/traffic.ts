// REQ: API-011 — strings for the traffic page, English source of truth: the heading and the
// controls beside it, what one tile says when it is read out, the card under the map (a tile in
// words, the names behind it, the hint when nothing is chosen), and the legend.
//
// A tile's label and status are its own (the status is the API's identifier, spoken as it is).
export const traffic = {
  // The heading, the two segmented controls, and the hour menu.
  'traffic.groupBy': 'Group by',
  'traffic.mode.service': 'Services',
  'traffic.mode.site': 'Sites',
  'traffic.mode.name': 'Names',
  'traffic.show.allowed': 'Allowed',
  'traffic.hour': 'Hour',
  'traffic.hour.previous': 'previous hour',

  // One tile, read out: where its label and status go, and how many queries it holds.
  'traffic.tile.aria.one': '{label}, {status}, {n} query',
  'traffic.tile.aria.other': '{label}, {status}, {n} queries',
  'traffic.empty': 'No queries yet this hour.',

  // The card under the map: the tile in words, the names behind it, and the hint when nothing
  // is selected.
  'traffic.details.queries.one': '{n} query',
  'traffic.details.queries.other': '{n} queries',
  'traffic.details.share': " · {pct} of what's shown",
  'traffic.details.growth': ' · +{n} in the last {seconds} s',
  'traffic.details.when': 'when',
  'traffic.details.whenTitle': 'When {name} is asked for',
  'traffic.details.andMore.one': 'and {n} more',
  'traffic.details.andMore.other': 'and {n} more',
  'traffic.details.hint':
    'Point at a tile to see the names behind it. Select one to open them in the query log.',

  // The legend: what the two colours and the ring mean, and what the busiest lists cover.
  'traffic.legend.size': 'Bigger and stronger colour = more queries',
  'traffic.legend.ring': 'Growing fastest right now',
  'traffic.legend.foot':
    'The busiest {names} names and {blocked} blocked names {when}, every node; counts are approximate',
  'traffic.legend.updated': '. Updated {time}',
  'traffic.legend.previousHour': 'in the previous clock hour',
} as const;
