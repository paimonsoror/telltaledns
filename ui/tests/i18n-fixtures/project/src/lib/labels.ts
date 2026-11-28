// A fixture for tests/e2e/7-i18n.spec.ts (API-012): a label marked in a module and shown elsewhere.
import { tk, tr } from './i18n';

const { m } = tr('labels');

export const LISTS = m('Lists');

export function listsLabel(): string {
  return tk(LISTS);
}
