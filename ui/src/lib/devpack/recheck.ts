// REQ: API-013 (ADR-190) — the checking code a page load needs only when it checks a test pack's file
// again (no kept table for this build and file): the template's reader, the tag's rules and the check,
// with the whole agreement rule. A chunk of its own, which the card shares; a load with a kept table
// never fetches it.
export { readTemplate } from '../i18n/template';
export { checkPack, tagInfo } from '../i18n/pack';
