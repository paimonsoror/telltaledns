// REQ: API-011 — strings for slo, English source of truth: the service-level card (`SloCard`),
// its objectives, the words a burning budget shows as, and what each one means on hover.
// Where today's English never inflects (the window says "days" for one too), both plural
// categories keep that same word: `tn()` is there for the count, not to reword the sentence.
export const slo = {
  // The card: its heading, how long the window is, and what it says before there is data.
  'slo.title': 'Service level',
  'slo.window.one': '(last {n} days)',
  'slo.window.other': '(last {n} days)',
  'slo.loading': 'Loading…',
  'slo.off': 'Objectives are off (',
  'slo.offEnd': ').',
  'slo.missing': 'Without {nodes}: they didn’t answer.',

  // The objectives, the badge of one that is fine, and where its numbers come from.
  'slo.onTrack': 'on track',
  'slo.target': '{means} · target {target}%',
  'slo.ofAnswers': 'of {answers} answers',

  // How a burning budget reads, and what each word means on hover.
  'slo.alert.fast': 'burning fast',
  'slo.alert.fastTip':
    'Over the last hour (and the last 5 minutes) the budget is going more than 14 times faster than it can last: at this rate a month’s budget is gone in about two days.',
  'slo.alert.slow': 'burning',
  'slo.alert.slowTip':
    'Over the last 6 hours (and the last 30 minutes) the budget is going more than 6 times faster than it can last.',
  'slo.alert.ticket': 'on course to run out',
  'slo.alert.ticketTip':
    'Over the last 3 days the budget has been going faster than it can last: worth a look this week.',

  // The error budget left, and the burn rate beside it.
  'slo.budgetTitle': 'Error budget left: the bad answers the target still allows over the window',
  'slo.budget.none': 'no answers yet',
  'slo.budget.overspent': 'budget overspent',
  'slo.budget.left': '{pct}% of the error budget left',
  'slo.burnRate': 'Burn rate',
  'slo.burn.none': 'No answers to judge in the last {window}.',
  'slo.burn.some': 'Last {window}: {bad} bad of {total} answers. 1× spends exactly the budget over the window.',

  // Who spent it.
  'slo.who': 'Who spent it?',
} as const;
