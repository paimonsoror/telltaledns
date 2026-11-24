// REQ: API-011, ADR-036 — the help glossary (docs/help/topics.json and its Chinese twin
// docs/help/topics.zh-CN.json), shared with the site. Every "?" in the UI names a topic id;
// `npm run check:help` (CI) proves each id exists, in every language, and that every topic not
// marked `general` is used somewhere.
import enData from '../../../docs/help/topics.json';
import zhData from '../../../docs/help/topics.zh-CN.json';
import { i18n, type Locale } from './i18n';

/** Paths through the query flow a diagram can highlight. */
export type FlowPath = 'cache' | 'local' | 'blocked' | 'route' | 'upstream' | 'refused';

export interface Topic {
  id: string;
  title: string;
  term: string;
  summary: string;
  when: string;
  example: string;
  caution: string;
  diagram?: FlowPath;
  docs?: string;
  general?: boolean;
}

/** One table per language; `id`, `diagram`, `docs` and `general` are the same in all of them. */
const tables: Record<Locale, Map<string, Topic>> = {
  en: new Map((enData.topics as Topic[]).map((t) => [t.id, t])),
  'zh-CN': new Map((zhData.topics as Topic[]).map((t) => [t.id, t])),
};

/** The stand-in's one sentence, so a missing topic reads oddly in both languages. */
const missingSummary: Record<Locale, string> = {
  en: 'No help text for this yet.',
  'zh-CN': '这个还没有帮助文本。',
};

/**
 * The topics in the language on screen. Reading `i18n.locale` here is what makes `topic()` —
 * and so every `$derived(topic(id))` — re-read when someone switches the language.
 */
function table(): Map<string, Topic> {
  return tables[i18n.locale] ?? tables.en;
}

/** The topic, or a stand-in that says it's missing (the CI check keeps this from shipping). */
export function topic(id: string): Topic {
  const found = table().get(id);
  if (found) return found;
  return {
    id,
    title: id,
    term: '',
    summary: missingSummary[i18n.locale] ?? missingSummary.en,
    when: '',
    example: '',
    caution: '',
  };
}

/** Where a topic's full documentation lives. */
export function docsUrl(t: Topic): string | undefined {
  return t.docs ? `https://github.com/paimonsoror/telltaledns/blob/main/docs/running.md#${t.docs}` : undefined;
}
