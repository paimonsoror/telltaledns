// REQ: API-012 — the service-level objectives' names, as one table (the dashboards, the wall, the
// budget view and the service-level card show them). An objective comes from the server: one the UI
// does not know shows as it is.
import { own, tk, tr } from './i18n';

const { m } = tr('objectives');
const TITLE = { availability: m('Answers that work'), latency: m('Answers that are quick') };

export const objectiveTitle = (name: string): string => {
  const known = own(TITLE, name);
  return known ? tk(known) : name;
};
