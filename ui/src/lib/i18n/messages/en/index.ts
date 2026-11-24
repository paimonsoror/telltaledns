// REQ: API-011 — the English catalog is the source of truth for keys: `MessageKey` is derived
// from it, and `npm run check:i18n` proves every other language says the same things.
import { common } from './common';
import { nav } from './nav';
import { auth } from './auth';
import { dashboard } from './dashboard';
import { dashWidgets } from './dash-widgets';
import { queries } from './queries';
import { queryWidgets } from './query-widgets';
import { settings } from './settings';
import { help } from './help';

export const en = {
  ...common,
  ...nav,
  ...auth,
  ...dashboard,
  ...dashWidgets,
  ...queries,
  ...queryWidgets,
  ...settings,
  ...help,
} as const;

export type MessageKey = keyof typeof en;