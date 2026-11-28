// REQ: API-013 (ADR-190) — `<tag>-notes.txt`, the notes a translator downloads with the template: the
// language, the web UI build it was made from, how to translate and send the file, the glossary, and
// per context the English's own notes, the translator notes, the sensitive messages and the words to
// keep as written. In English on purpose: it is the instructions for writing the pack, read beside
// the English it translates. The only place these notes reach a translator without a checkout.
import type { Tag } from '../i18n/pack';
import type { Template } from '../i18n/template';

const show = (e: string | readonly [string, string]) => (typeof e === 'string' ? JSON.stringify(e) : `${JSON.stringify(e[0])} / ${JSON.stringify(e[1])}`);

/** The notes file's text. `names`: the language in English and in itself (display only); `build`:
 * the web UI build; `date`: the day it was made (YYYY-MM-DD). */
export function notesText(tpl: Template, tag: Tag, names: { english?: string; own?: string }, build: string, date: string): string {
  const out: string[] = [];
  const name = [names.english, names.own && names.own !== names.english ? `(${names.own})` : ''].filter(Boolean).join(' ');
  out.push(`TelltaleDNS: notes for translators of ${tag.tag}.json`, '');
  out.push(`Language: ${name || tag.tag}, tag ${tag.tag}, written ${tag.dir === 'rtl' ? 'right to left (the layout is not ready for right-to-left languages yet)' : 'left to right'}.`);
  out.push(`Plural forms of this language: ${tag.categories.join(', ')}.`);
  out.push(`Made from web UI build ${build} on ${date}.`, '');
  out.push(
    'How to translate',
    `- ${tag.tag}.json holds, per context, pairs of English and translation: ["English", "translation"]. Write the translation in the second place. An empty "" means "not translated yet": the English shows.`,
    '- A third item, ["English", "", "note"], is the English\'s own note, which tells two uses of the same English apart: keep it exactly as it is.',
    '- Keep each {name} exactly as written: it is replaced by a value. Keep tags such as <b>...</b> around the same words, and translate the words inside.',
    '- Keep web addresses, numbers, commands and setting names as they are written, and the words listed below for an entry.',
    `- A plural is [["one form", "other form"], { ${tag.categories.map((c) => `"${c}": ""`).join(', ')} }]: write a form for each category of the language. A form other than "other" may leave out a {name} (as in "one file"), but where the number never changes, as in the limits of a file ({max}), keep it in every form. Keep {n} in a form unless you know that it covers exactly one number in your language. Many forms cover more: French and Brazilian Portuguese "one" is 0 and 1, Russian "one" is 1, 21, 31, 101 and so on, Latvian "zero" is 0, 10 to 20, 30 and so on. The CLDR plural rules for your language list what each form covers (https://www.unicode.org/cldr/charts/latest/supplemental/language_plural_rules.html).`,
    '- Check the file in TelltaleDNS (Settings, Account, Advanced view: "Test a language pack"). Its check is the one the project runs.',
    '',
    'Sending it',
    `1. On GitHub, add ui/src/locales/${tag.tag}.json: the file from "Download for a pull request", unchanged.`,
    `2. Add the language to ui/src/locales/manifest.json, or ask a maintainer: your GitHub name as its owner, "dir": "${tag.dir}", "offered": false, and "since" (a release version such as "0.9.0", which a maintainer settles). All four are required and the check reads the layout exactly, so copy the block from the page behind "How to translate TelltaleDNS" on the card.`,
    '3. In the description: the language; that you read every text (a machine translation is a draft only); a back-translation of each sensitive message you changed (listed below).',
    '4. Wait for the check and for the review of the language\'s owner.',
    '',
  );
  if (tpl.glossary.length) out.push('Terms kept as written everywhere', tpl.glossary.join(', '), '');
  const byContext = new Map<string, string[]>();
  for (const e of tpl.entries.values()) {
    const lines: string[] = [];
    if (e.note) lines.push(`the English's own note: ${e.note}`);
    if (e.info?.text) lines.push(`note: ${e.info.text}`);
    if (e.info?.sensitive) lines.push('sensitive: give a back-translation in the pull request');
    if (e.verbatim?.length) lines.push(`keep as written: ${e.verbatim.join(', ')}`);
    if (!lines.length) continue;
    byContext.set(e.ctx, [...(byContext.get(e.ctx) ?? []), `  ${show(e.english)}`, ...lines.map((l) => `    ${l}`)]);
  }
  if (byContext.size) {
    out.push('Notes per context');
    for (const ctx of tpl.contexts) if (byContext.has(ctx)) out.push(`[${ctx}]`, ...(byContext.get(ctx) ?? []));
    out.push('');
  }
  return `${out.join('\n')}\n`;
}
