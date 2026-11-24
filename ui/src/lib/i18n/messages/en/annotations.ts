// REQ: OBS-033, API-011 — strings for annotations, English source of truth: the words the kind
// filter and the marker tooltips use for each kind of change (the kind itself stays an identifier).
export const annotations = {
  'annotations.kind.note': 'Notes',
  'annotations.kind.buildStarted': 'Builds',
  'annotations.kind.nodeRestarted': 'Restarts',
  'annotations.kind.blockingPaused': 'Pauses',
  'annotations.kind.upstreamBreaker': 'Breakers',
} as const;
