// REQ: API-011 — strings for the rules page, English source of truth.
export const rules = {
  // The heading and what quick rules do, above the cards.
  'rules.intro':
    "Allow or block a site for one device, a group, or everyone, for a while or for good. Quick rules decide before any list: a device's rule beats its group's, which beats everyone's.",

  // The two cards: making one, and the ones in effect.
  'rules.new': 'New rule',
  'rules.inEffect': 'In effect',
  'rules.empty': 'No quick rules. Make one here, or from "Why?" in the query log.',

  // The table's columns.
  'rules.col.rule': 'Rule',
  'rules.col.for': 'For',
  'rules.col.ends': 'Ends',
  'rules.col.note': 'Note',
  'rules.col.made': 'Made',

  // Who a rule is for (a device's name is the rule's own data).
  'rules.group': 'group {groups}',
  'rules.everyone': 'everyone',

  // When a rule ends.
  'rules.ends.never': 'never',
  'rules.ends.expired': 'expired',
  'rules.ends.in': 'in {when}',
  'rules.ends.at': 'at {time}',

  // Where a rule was made, and what saving an edit said.
  'rules.source.file': 'config file',
  'rules.inConfigFile': 'in the config file',
  'rules.updated': 'Rule updated. {message}',

  // The row's buttons, the edit heading, and why one rule is changed elsewhere.
  'rules.edit': 'Edit',
  'rules.remove': 'Remove',
  'rules.editRule': 'Edit rule',
  'rules.manyScopes': 'Several devices or groups: change it through the API.',
} as const;
