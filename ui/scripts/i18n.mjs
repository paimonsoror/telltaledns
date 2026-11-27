// REQ: API-012 (ADR-189) — the languages tool. Run from `ui/`:
//   node scripts/i18n.mjs check              the CI check (`npm run check:i18n`): fails only on what
//                                            the author of a file controls; prints the report and,
//                                            in GitHub Actions, the job summary
//   node scripts/i18n.mjs report [--summary] the report only (Markdown with --summary); never fails
//   node scripts/i18n.mjs prebuild           writes the shipped catalogs and the URL table (run by
//                                            npm before dev, check, build and test:e2e; git-ignored)
//   node scripts/i18n.mjs sync <tag> [--prune]   for translators: adds the missing messages, moves
//                                            left-over pairs to "~leftover" (or deletes them)
//   node scripts/i18n.mjs carry <context> --from "<old>" --to "<new>"   for maintainers: an English
//                                            edit that keeps the meaning keeps its translations
//   node scripts/i18n.mjs baseline           lowers i18n-baseline.json's counts to the tree's (and
//                                            lists new files at zero); never raises one
//   node scripts/i18n.mjs plurals            for maintainers, once and reviewed: rewrites
//                                            src/locales/plurals.json from this Node's CLDR data
// Needs a Node that strips TypeScript types (24, as CI and the Dockerfile use; or 22.18+): the
// library imports the runtime's own modules in src/lib/i18n/*.ts.
import { appendFileSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';

if (!process.features.typescript) {
  console.error(`scripts/i18n.mjs needs Node 24 (or 22.18 and later), which strips TypeScript types; this is Node ${process.version}`);
  process.exit(2);
}
const { baselineOf, carry, check, formatReport, pluralTable, prebuild, serializeJson, summaryMarkdown, sync } = await import('./i18n-lib.mjs');

const ROOT = join(import.meta.dirname, '..');
const [cmd, ...args] = process.argv.slice(2);

/** Each locale file one commit back (HEAD^1: a pull request's base in CI's merge commit), or null. */
function previousLocales() {
  const manifest = JSON.parse(readFileSync(join(ROOT, 'src', 'locales', 'manifest.json'), 'utf8'));
  const git = (...a) => execFileSync('git', ['-C', ROOT, ...a], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
  try {
    git('rev-parse', '--verify', '-q', 'HEAD^1');
  } catch {
    return null;
  }
  const out = {};
  for (const tag of Object.keys(manifest)) {
    try {
      out[tag] = git('show', `HEAD^1:./src/locales/${tag}.json`);
    } catch {
      out[tag] = '{\n}\n';
    }
  }
  return out;
}

switch (cmd) {
  case 'check':
  case 'report': {
    const result = check(ROOT, { previous: previousLocales() });
    if (args.includes('--summary')) process.stdout.write(summaryMarkdown(result));
    else console.log(formatReport(result));
    if (cmd === 'check' && process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, summaryMarkdown(result));
    if (cmd === 'check' && result.findings.some((f) => f.level === 'fail')) process.exit(1);
    break;
  }
  case 'prebuild': {
    const n = prebuild(ROOT);
    console.log(`i18n prebuild: ${n} locale file(s) and src/lib/i18n/locales.gen.ts`);
    break;
  }
  case 'sync': {
    const [tag] = args;
    if (!tag) throw new Error('usage: sync <tag> [--prune]');
    sync(ROOT, tag, { prune: args.includes('--prune') });
    console.log(`i18n sync: src/locales/${tag}.json`);
    break;
  }
  case 'carry': {
    const [ctx] = args;
    const from = args[args.indexOf('--from') + 1];
    const to = args[args.indexOf('--to') + 1];
    if (!ctx || !args.includes('--from') || !args.includes('--to') || from === undefined || to === undefined) throw new Error('usage: carry <context> --from "<old>" --to "<new>"');
    console.log(`i18n carry: ${carry(ROOT, ctx, from, to)} pair(s) rewritten`);
    break;
  }
  case 'plurals': {
    const table = pluralTable();
    writeFileSync(join(ROOT, 'src', 'locales', 'plurals.json'), serializeJson(table));
    console.log(`i18n plurals: ${Object.keys(table).length} languages from node ${process.version} (ICU ${process.versions.icu}, CLDR ${process.versions.cldr}); review the diff`);
    break;
  }
  case 'baseline': {
    // Lowers counts and lists new files at zero; never raises a count or lists a file above zero.
    const result = check(ROOT, { ratchets: false });
    const path = join(ROOT, 'i18n-baseline.json');
    const previous = existsSync(path) ? JSON.parse(readFileSync(path, 'utf8')) : null;
    writeFileSync(path, serializeJson(baselineOf(ROOT, result.files, previous)));
    console.log('i18n baseline: i18n-baseline.json written');
    break;
  }
  default:
    console.error('usage: node scripts/i18n.mjs check | report [--summary] | prebuild | sync <tag> [--prune] | carry <context> --from <old> --to <new> | baseline | plurals');
    process.exit(2);
}
