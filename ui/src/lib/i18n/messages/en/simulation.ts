// REQ: API-011 — strings for simulation, English source of truth: "What would this have done?"
// (`SimulationCard`), the note that says what to add to the repository (`KeepInGit`), and "Who
// spent the error budget?" (`BudgetAttribution`).
//
// A count's noun is its own key (`.one`/`.other`) and the surrounding sentence carries it as a
// placeholder. Where today's English never inflects (a sentence that says "queries" for one too),
// both categories keep that same word: `tn()` is there for the count, not to reword the sentence.
// An identifier the server sends (a reason, a note) is a key here; one this file doesn't know is
// shown as it came.
export const simulation = {
  // "What would this have done?": the button, and why there is no answer at all.
  'simulation.preview.button': 'What would this have done?',
  'simulation.preview.replaying': 'Replaying the logged queries…',
  'simulation.preview.reason.disabled':
    'Simulation is off on this cluster (Settings → Query handling → Change simulation).',
  'simulation.preview.reason.privacyLevel':
    "The query log keeps names hashed or hidden at this node's privacy level, so this change can't be replayed. Moving a device between groups with the same lists still can be.",
  'simulation.preview.reason.noQueryLog': 'The query log is off on this node, so there is nothing to replay.',
  'simulation.preview.reason.busy': 'Another simulation is running on this node. Try again in a few seconds.',
  'simulation.preview.reason.localFile':
    "This change names a local file the configuration doesn't read yet, so only an administrator can replay it.",
  'simulation.preview.reason.downloadLimit':
    'This change adds or changes more lists than one simulation reads on this node (at most 4 by URL or from a file, within 4 times its list size limit). Simulate fewer list changes at a time.',
  'simulation.preview.notSimulated': 'Not simulated: {reason}',
  'simulation.preview.notApplicable':
    "This change can't affect how queries are answered, so there is nothing to replay.",

  // What was replayed: how much of the log, and what it would answer differently.
  'simulation.preview.over.one': 'Over {n} logged queries{when}:',
  'simulation.preview.over.other': 'Over {n} logged queries{when}:',
  'simulation.preview.since': ' since {time}',
  'simulation.preview.noneDifferent': 'none would have been answered differently.',
  'simulation.preview.different': '{n} would have been answered differently.',
  'simulation.preview.partialLabel': 'Partial:',
  'simulation.preview.partialNote': "the time or row limit was reached, so older queries weren't replayed.",

  // The four classes of difference: a tile each, and the heading of its names.
  'simulation.preview.newlyBlocked': 'Newly blocked',
  'simulation.preview.newlyAllowed': 'Newly allowed',
  'simulation.preview.changedRoute': 'Changed route',
  'simulation.preview.changedAnswer': 'Changed answer',
  'simulation.preview.devices.one': '{n} device',
  'simulation.preview.devices.other': '{n} devices',

  // A name's own counts (the name itself is the log's), and the per-device chips under them.
  'simulation.preview.queries.one': '{n} query',
  'simulation.preview.queries.other': '{n} queries',
  'simulation.preview.counts': '{queries}, {devices}',
  'simulation.preview.byDevice': 'By device',
  'simulation.preview.chip.blocked': '{n} blocked',
  'simulation.preview.chip.allowed': '{n} allowed',
  'simulation.preview.chip.rerouted': '{n} rerouted',
  'simulation.preview.chip.answeredDifferently': '{n} answered differently',

  // What couldn't be replayed, what the approximations were, and who didn't answer.
  'simulation.preview.undetermined.one':
    "{n} queries couldn't be decided again (names hashed in the log).",
  'simulation.preview.undetermined.other':
    "{n} queries couldn't be decided again (names hashed in the log).",
  'simulation.preview.note.identityFromEvent':
    'Some devices were recognized by MAC address or client ID when they asked; they keep the group their queries were logged with.',
  'simulation.preview.note.badfilterCrossSnapshot':
    "A changed list has $badfilter rules; they don't cancel rules of the other lists in a preview.",
  'simulation.preview.note.namesCapped':
    'Very many names changed: counts are complete, but not every name is listed.',
  'simulation.preview.note.privacyLevel1DevicesOnly':
    'At privacy level 1 only devices moving between groups can be checked: queries of a device whose new groups decide differently are counted as undetermined.',
  'simulation.preview.missingNodes': "Not included (didn't answer): {nodes}.",

  // Keep it in Git: the heading, copying the snippet, and what the node's Git build needs.
  'simulation.keepInGit.title': 'Keep it in Git',
  'simulation.keepInGit.note':
    "This node's configuration comes from Git. The change is saved on this node and shared with the cluster, but a rebuild from Git won't have it until you add this:",

  // Who spent the error budget: its heading, the two objectives, and the summary line.
  'simulation.budget.title': 'Who spent the error budget?',
  'simulation.budget.objectiveAria': 'Objective',
  'simulation.budget.summary':
    ' bad of {answers} answers since {date}; the target ({target}%) allows {allowed}:',
  'simulation.budget.summary.overspent': 'overspent.',
  'simulation.budget.summary.left': '{pct}% of the budget left.',
  'simulation.budget.partialNodes':
    'No client and name lists for part of the window from {nodes} (an older build, or a pod counted from the minutes it shipped); their bad answers count everywhere else.',

  // The burn-down and its empty states.
  'simulation.budget.empty': 'Nothing spent this window.',
  'simulation.budget.chartLeft': 'Budget left (%)',

  // The breakdowns: their headings, what a hidden list says, and what an empty one says.
  'simulation.budget.timelineOnly':
    'The privacy level keeps only the timeline: no breakdown by client, name, or anything else.',
  'simulation.budget.hiddenByPrivacy': 'Hidden by the privacy level.',
  'simulation.budget.noClients': 'No clients recorded.',
  'simulation.budget.namesHidden': 'Names ({n}, hidden by the privacy level)',
  'simulation.budget.noNames': 'No names recorded.',
  'simulation.budget.rcode': 'Response code',
  'simulation.budget.approximate':
    "Clients and names are approximate top lists (each count may be up to its ± over); the other lists are exact. Links open the query log, which keeps fewer days than the budget's window.",
  'simulation.budget.byNode': 'By node',
} as const;
