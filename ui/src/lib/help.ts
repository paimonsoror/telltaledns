// REQ: API-011, ADR-036 — the help glossary (docs/help/topics.json), shared with the site.
// Every "?" in the UI names a topic id; `npm run check:help` (CI) proves each id exists and
// every topic not marked `general` is used somewhere.
import data from '../../../docs/help/topics.json';

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

const topics = new Map<string, Topic>((data.topics as Topic[]).map((t) => [t.id, t]));

/** The topic, or a stand-in that says it's missing (the CI check keeps this from shipping). */
export function topic(id: string): Topic {
  return (
    topics.get(id) ?? {
      id,
      title: id,
      term: '',
      summary: 'No help text for this yet.',
      when: '',
      example: '',
      caution: '',
    }
  );
}

/** Where a topic's full documentation lives. */
export function docsUrl(t: Topic): string | undefined {
  return t.docs ? `https://github.com/paimonsoror/telltaledns/blob/main/docs/running.md#${t.docs}` : undefined;
}
