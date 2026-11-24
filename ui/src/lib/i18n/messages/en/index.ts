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
import { widgets } from './widgets';
import { clusterWidgets } from './cluster-widgets';
import { deviceWidgets } from './device-widgets';
import { simulation } from './simulation';
import { slo } from './slo';
import { annotations } from './annotations';
import { wall } from './wall';
import { display } from './display';
import { legacy } from './legacy';
import { cache } from './cache';
import { changes } from './changes';
import { alerts } from './alerts';
import { cluster } from './cluster';
import { localdns } from './localdns';
import { upstreams } from './upstreams';
import { rules } from './rules';
import { lists } from './lists';
import { groups } from './groups';
import { clients } from './clients';
import { anomalies } from './anomalies';
import { explain } from './explain';
import { analyze } from './analyze';
import { flow } from './flow';
import { heatmap } from './heatmap';
import { traffic } from './traffic';

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

} as const;

export type MessageKey = keyof typeof en;