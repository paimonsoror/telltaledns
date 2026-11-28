// REQ: API-013 (ADR-190) — what the check of a language pack found, in plain words, for the card
// "Test a language pack": why a file is refused, why an entry is dropped, what is worth a look, why a
// pair is left over, and why a language tag is refused. Messages of the layer (a translator sees them
// in the template); a token or a key from the file is a parameter, shown as text.
import { tr } from '../i18n';
import { num } from '../format';
import { MAX_CHARS, MAX_CONTEXTS, MAX_PAIRS, markers, type Broken, type Leftover, type Refusal, type TagRefusal, type Worth } from '../i18n/pack';

/** Why a whole file is refused. */
export function refusalWords(r: Refusal): string {
  const { t, tn } = tr('packWords');
  switch (r.code) {
    case 'size':
      return t("This file can't be used: it is larger than 1 MiB.");
    case 'utf8':
      return t("This file can't be used: it isn't UTF-8 text.");
    case 'json':
      return t("This file can't be used: it isn't valid JSON (line {line}, column {column}).", { line: num(r.line), column: num(r.column) });
    case 'duplicate':
      return t('This file can\'t be used: the key "{key}" appears twice (line {line}, column {column}); the second would hide the first.', { key: markers(r.key), line: num(r.line), column: num(r.column) });
    case 'depth':
      return t("This file can't be used: it is nested deeper than a language file.");
    case 'shape':
      return t("This file can't be used: it isn't a language file (each context holds a list of pairs).");
    case 'contexts':
      // A limit of the check is its message's count, so a translator writes the noun in the form its number takes,
      // and {max}, the number as the language writes it.
      return tn("This file can't be used: it has more than {max} context.", "This file can't be used: it has more than {max} contexts.", MAX_CONTEXTS, { max: num(MAX_CONTEXTS) });
    case 'pairs':
      return tn("This file can't be used: it has more than {max} pair.", "This file can't be used: it has more than {max} pairs.", MAX_PAIRS, { max: num(MAX_PAIRS) });
    case 'context':
      return t('This file can\'t be used: "{ctx}" is not a context name.', { ctx: markers(r.ctx) });
    case 'long':
      return tn(
        'This file can\'t be used: pair {n} of "{ctx}" has a text longer than {max} character.',
        'This file can\'t be used: pair {n} of "{ctx}" has a text longer than {max} characters.',
        MAX_CHARS,
        { n: num(r.n), ctx: markers(r.ctx), max: num(MAX_CHARS) },
      );
    case 'pair':
      return t('This file can\'t be used: pair {n} of "{ctx}" is not in the form of the template.', { n: num(r.n), ctx: markers(r.ctx) });
  }
}

/** Why an entry is dropped (English is shown in its place). */
export function brokenWords(b: Broken): string {
  const { t } = tr('packWords');
  const token = markers(b.token ?? '');
  const added = b.detail?.startsWith('added') ?? false;
  switch (b.rule) {
    case 'placeholders':
      return added ? t("{token} isn't in the English: a translation keeps the placeholders the English has, and no others.", { token }) : t('Keep {token} exactly as it is: it is replaced by a value.', { token });
    case 'tags':
      return added ? t("The tag {token} isn't in the English.", { token }) : t('Keep the tag {token} exactly as in the English.', { token });
    case 'urls':
      if (!added) return t('Keep the web address exactly as in the English: {token}', { token });
      return b.token?.includes('://') ? t("This web address isn't in the English: {token}", { token }) : t('The translation has more web addresses than the English.');
    case 'structural':
      return added ? t('Remove {token}: a translation adds no address, port, path or setting.', { token }) : t('Keep {token} as written.', { token });
    case 'digits':
      return t('Keep the number {token}.', { token });
    case 'verbatim':
      return t('Keep {token} untranslated: it is a value people type.', { token });
    case 'mixed-script':
      return t('A word mixes Latin letters with Cyrillic or Greek ones that look alike: {token}', { token });
    case 'code':
      return added ? t("{token} isn't in the English: a translation adds no code.", { token }) : t('Keep {token} as written: it is code.', { token });
    case 'code-point':
      return t("Remove the character {token}: it is invisible, changes the direction, or can't be shown.", { token });
    case 'twice':
      return t('The same English and note are in this context twice: only the first is used.');
    case 'categories':
      // The file's own keys, with their forbidden code points shown as markers (as every token of the file).
      return t('This language uses {want}; this entry has {got}.', { want: (b.want ?? []).join(', '), got: markers((b.got ?? []).join(', ')) });
    default:
      return t('It breaks the rule "{rule}" of the check.', { rule: b.rule });
  }
}

/** A finding that drops nothing, for a person to read. */
export function worthWords(w: Worth): string {
  const { t } = tr('packWords');
  const token = markers(w.token);
  if (w.rule === 'hyphenated') return t('Worth a look: {token} is not in the translation. Fine if it is an ordinary word.', { token });
  if (w.rule === 'capitals') return t('Worth a look: {token} is not in the translation. Keep it if it is a name or an abbreviation.', { token });
  return t('Worth a look: the translation adds {token}.', { token });
}

/** Why a pair of the file is not used. */
export function leftoverWords(l: Leftover): string {
  const { t } = tr('packWords');
  if (l.reason === 'note') return t('Same English, different note: keep the third item as in the template.');
  if (l.reason === 'aside') return t('Set aside under "~leftover": it is kept there and not used.');
  return t("This English isn't in this build: it changed, or it was edited in the file.");
}

/** Why a language tag is refused. */
export function tagWords(why: TagRefusal): string {
  const { t } = tr('packWords');
  switch (why.code) {
    case 'empty':
      return t('Type a language tag, such as de, fr, pt-BR or zh-Hant.');
    case 'syntax':
      return t("This isn't a language tag.");
    case 'english':
      return t('English is the source of every text: there is no English language pack.');
    case 'pseudo':
      return t('This is a pseudo-locale: it is made from the English.');
    case 'reserved':
      return t('This tag is for private or special use, not a language.');
    case 'shape':
      return t('Write the tag as a language with its script or region only, such as pt-BR or zh-Hant.');
    case 'alias':
      return t('Write this language as {hint}.', { hint: why.hint ?? '' });
    case 'plurals':
      return t("TelltaleDNS doesn't know the plural forms of this language yet: ask for it to be added.");
    case 'script':
      return t('This language is written in more than one script: add the script, such as {hint}.', { hint: why.hint ?? '' });
  }
}
