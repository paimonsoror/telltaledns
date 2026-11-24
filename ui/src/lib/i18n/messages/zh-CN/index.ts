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
import { widgets } from './widgets';
import { clusterWidgets } from './cluster-widgets';
import { deviceWidgets } from './device-widgets';
import { simulation } from './simulation';
import { slo } from './slo';
import { annotations } from './annotations';
import { traffic } from './traffic';
import { heatmap } from './heatmap';
import { flow } from './flow';
import { analyze } from './analyze';
import { explain } from './explain';
import { anomalies } from './anomalies';
import { clients } from './clients';
import { groups } from './groups';
import { lists } from './lists';
import { rules } from './rules';
import { upstreams } from './upstreams';
import { localdns } from './localdns';
import { cluster } from './cluster';
import { alerts } from './alerts';
import { changes } from './changes';
import { cache } from './cache';
import { legacy } from './legacy';
import { display } from './display';
import { wall } from './wall';

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
  ...traffic,
  ...heatmap,
  ...flow,
  ...analyze,
  ...explain,
  ...anomalies,
  ...clients,
  ...groups,
  ...lists,
  ...rules,
  ...upstreams,
  ...localdns,
  ...cluster,
  ...alerts,
  ...changes,
  ...cache,
  ...legacy,
  ...display,
  ...wall,
  ...widgets,
  ...clusterWidgets,
  ...deviceWidgets,
  ...simulation,
  ...slo,
  ...annotations,
};