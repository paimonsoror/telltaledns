// REQ: API-011 — strings for the changes page, English source of truth: the heading and what the
// page is for, the badge a plan's state shows, one plan (its fields, the dry run, and
// before/after), and the two lists (what waits, and what is recent).
//
// A sentence a code sample sits inside (a `<code>` around it) is split at it: `…intro` ends just
// before it, `…introMid` carries on just after it, so the markup keeps the element. The last
// piece of that sentence ends in a space because a count follows it.
export const changes = {
  // The heading, and what the page is for.
  'changes.title': 'Agent changes',
  'changes.intro':
    "AI agents connected over MCP don't change anything directly: they make a plan, shown here with what it would do. With",
  'changes.introMid': ', a plan waits for an operator before the agent can apply it. ',
  'changes.expires.one': 'Plans expire after {n} minute.',
  'changes.expires.other': 'Plans expire after {n} minutes.',

  // The state of a plan, as the badge beside its summary shows it (the value sent stays the identifier).
  'changes.state.pending': 'waiting for approval',
  'changes.state.ready': 'ready to apply',
  'changes.state.approved': 'approved',
  'changes.state.rejected': 'rejected',
  'changes.state.applying': 'applying',
  'changes.state.applied': 'applied',
  'changes.state.stale': 'stale: the config changed',
  'changes.state.failed': 'failed',
  'changes.state.discarded': 'discarded',

  // One plan: what it says, what it would do, the dry run, and before/after.
  'changes.plan.why': 'Why',
  'changes.plan.askedBy': 'Asked by',
  'changes.plan.when': 'When',
  'changes.plan.expires': '· expires in {time}',
  'changes.plan.decidedBy': 'Decided by',
  'changes.plan.change': 'Change',
  'changes.plan.impact': 'What it does:',
  'changes.plan.beforeAfter': 'Before and after',
  'changes.plan.before': 'Before',
  'changes.plan.after': 'After',
  'changes.plan.approve': 'Approve',
  'changes.plan.reject': 'Reject',

  // The two lists: what waits for an operator, and what is done.
  'changes.waiting.title': 'Waiting for approval',
  'changes.waiting.empty': 'Nothing is waiting.',
  'changes.recent': 'Recent plans',
} as const;
