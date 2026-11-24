// REQ: API-011 — 中文文案的组合。缺键由 `npm run check:i18n` 找出，运行时会回退到英文原文。
import type { MessageKey } from '../en';
import { common } from './common';
import { nav } from './nav';
import { auth } from './auth';
import { dashboard } from './dashboard';
import { dashWidgets } from './dash-widgets';
import { queries } from './queries';
import { queryWidgets } from './query-widgets';
import { settings } from './settings';
import { help } from './help';

export const zh: Partial<Record<MessageKey, string>> = {
  ...common,
  ...nav,
  ...auth,
  ...dashboard,
  ...dashWidgets,
  ...queries,
  ...queryWidgets,
  ...settings,
  ...help,
};