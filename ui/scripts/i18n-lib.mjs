// REQ: API-012 (ADR-189) — the library behind `scripts/i18n.mjs` and the tests in
// `tests/e2e/7-i18n.spec.ts`. It reads the source from the Svelte and TypeScript syntax trees
// (never a regex over source), extracts every message with its file's context, checks the locale
// files against the English that is in the source now, and builds what ships. FAIL is kept for
// what the author of a file controls; missing, outdated and left-over translations are REPORT.
// `root` is the UI folder (`ui/`, or a fixture project with the same layout).
import { readFileSync, readdirSync, statSync, existsSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join, relative, basename } from 'node:path';
import { createHash } from 'node:crypto';
import { gzipSync, constants } from 'node:zlib';
import ts from 'typescript';
import { parse as parseSvelte } from 'svelte/compiler';
import { englishKey, hash, normalize } from '../src/lib/i18n/ident.ts';
import { agree } from '../src/lib/i18n/safe.ts';
import { CATEGORIES, LEFTOVER, LIMITS, merge, parse, serialize, shapeError, skeleton } from '../src/lib/i18n/pairs.ts';

/** The hash and normalization the runtime uses (one module, `src/lib/i18n/ident.ts`), and the pair
 * files' parser and canonical form (`src/lib/i18n/pairs.ts`). */
export { hash, normalize, parse, CATEGORIES, LEFTOVER };

export const DATA_FILES = ['contexts.json', 'glossary.json', 'manifest.json', 'notes.json', 'plurals.json', 'verbatim.json'];
const OPTIONAL_FILES = ['baseline.json'];
export const COMMON = 'common';
export const COMMON_MAX = 40;
export const LOCALE_BUDGET = 80 * 1024;
export const LOCALES_BUDGET = 400 * 1024;
/** The attributes whose text a reader sees or hears, on any element (and `label` on `<optgroup>`):
 * read by the literal-text lint and the codemod's inputs. */
export const TEXT_ATTRS = ['aria-label', 'title', 'placeholder', 'alt', 'aria-roledescription', 'aria-description', 'aria-valuetext', 'aria-placeholder'];
const isTextAttr = (element, attr) => TEXT_ATTRS.includes(attr) || (element === 'optgroup' && attr === 'label');
const NOT_TEXT_ATTRS = ['translate', 'lang', 'dir'];
/** The props of the app's components that hold text a reader sees (`<Kpi label="Queries" />`, `empty="Nothing yet"`):
 * a literal one with letters is literal text, as a literal title or placeholder on an element is. */
export const TEXT_PROPS = ['label', 'title', 'empty', 'noun', 'summary', 'hint', 'placeholder'];
const isComponentNode = (n) => n.type === 'Component' || n.type === 'SvelteComponent' || n.type === 'SvelteSelf';
// Languages written in more than one script: a catalog names the script (`zh-Hans`, `sr-Latn`). The
// matcher also takes a catalog only for a request of the same likely script, list or not.
const MULTI_SCRIPT = ['az', 'bs', 'ha', 'kk', 'ks', 'ku', 'mn', 'pa', 'sd', 'sr', 'uz', 'zh'];
const MANIFEST_FIELDS = ['belowSince', 'dir', 'offered', 'owners', 'since'];
const RESERVED_MANIFEST_FIELDS = ['parent', 'regions'];
const LOGIN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const VERSION = /^\d+\.\d+\.\d+$/;
const CONTEXT = /^[a-z][A-Za-z0-9]*$/;

// ---------------------------------------------------------------------------------------------
// Canonical forms

const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const sortKeys = (v) =>
  Array.isArray(v) ? v.map(sortKeys) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort(cmp).map((k) => [k, sortKeys(v[k])])) : v;

/** A data file (manifest, contexts, glossary): keys sorted at every level, two-space indent. */
export function serializeJson(v) {
  return `${JSON.stringify(sortKeys(v), null, 2)}\n`;
}

const pairNote = (p) => (typeof p[2] === 'string' ? p[2] : '');
const canonValue = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? Object.fromEntries(CATEGORIES.filter((c) => Object.hasOwn(v, c)).map((c) => [c, v[c]])) : v);

/** A catalog-shaped file (a locale, notes, verbatim, baseline), byte for byte as ADR-189 writes it
 * (`src/lib/i18n/pairs.ts`). */
export const serializeCatalog = serialize;

// ---------------------------------------------------------------------------------------------
// Files and contexts

/** The lower-camel name of a source file: `pages/Anomalies.svelte` -> `anomalies`. */
export function contextName(rel) {
  const b = basename(rel)
    .replace(/\.svelte\.ts$|\.svelte$|\.ts$/, '')
    .replace(/[-_.]+([A-Za-z0-9])/g, (_, c) => c.toUpperCase());
  return b.charAt(0).toLowerCase() + b.slice(1);
}

function* walk(dir) {
  for (const name of readdirSync(dir).sort(cmp)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) yield* walk(p);
    else yield p;
  }
}

const slash = (p) => p.split('\\').join('/');
const GENERATED = /^\s*(?:\/\/|\/\*)[^\n]*(?:GENERATED|auto-generated)/;

/** The source files the layer applies to: `.svelte` and `.ts` under `src/`, without the layer's own
 * modules (the `.ts` files of `lib/i18n/`: they hold the machinery, not text a reader sees; a component
 * placed there is held like any other) and without generated files. Paths are relative to `src/`. */
export function sourceFiles(root) {
  const src = join(root, 'src');
  const out = [];
  for (const p of walk(src)) {
    const rel = slash(relative(src, p));
    if (!/\.(svelte|ts)$/.test(rel) || (rel.startsWith('lib/i18n/') && rel.endsWith('.ts')) || rel.startsWith('locales/')) continue;
    const text = readFileSync(p, 'utf8');
    if (GENERATED.test(text.slice(0, 400))) continue;
    out.push({ rel, text });
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// Extraction from one file

const lineAt = (text) => {
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) starts.push(i + 1);
  return (off) => {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= off) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };
};

const SPACE = /[ \t\n\r\f]+/g;
const PLACEHOLDER = /\{[A-Za-z_][A-Za-z0-9_]*\}/g;
/** A string as the lint reads it: placeholders masked as `{}`, whitespace runs collapsed (as the
 * browser shows text), trimmed. Empty, or nothing but placeholders: null. */
export function masked(s) {
  const m = s.replace(PLACEHOLDER, '{}').replace(SPACE, ' ').trim();
  return m.replace(/\{\}/g, '').trim() === '' ? null : m;
}
/** The value the variable an identifier names is declared with: its nearest declaration in the
 * scopes around it (the block, the function and its parameters, a loop, a catch clause, the file).
 * A parameter, an import, a function or a destructured name declares no value here. */
function declaredWith(id) {
  const name = id.text;
  const binds = (b) =>
    ts.isIdentifier(b) ? b.text === name : (ts.isObjectBindingPattern(b) || ts.isArrayBindingPattern(b)) && b.elements.some((el) => !ts.isOmittedExpression(el) && binds(el.name));
  const inList = (list) => {
    for (const d of list.declarations) if (binds(d.name)) return ts.isIdentifier(d.name) && d.initializer ? [d.initializer] : [];
    return null;
  };
  const imports = (s) => {
    const cl = s.importClause;
    if (!cl) return false;
    if (cl.name?.text === name) return true;
    const nb = cl.namedBindings;
    return !!nb && (ts.isNamespaceImport(nb) ? nb.name.text === name : nb.elements.some((el) => el.name.text === name));
  };
  const inStatements = (statements) => {
    for (const s of statements) {
      if (ts.isVariableStatement(s)) {
        const r = inList(s.declarationList);
        if (r) return r;
      } else if ((ts.isFunctionDeclaration(s) || ts.isClassDeclaration(s) || ts.isEnumDeclaration(s)) && s.name?.text === name) return [];
      else if (ts.isImportDeclaration(s) && imports(s)) return [];
    }
    return null;
  };
  for (let p = id.parent; p; p = p.parent) {
    let r = null;
    if (ts.isBlock(p) || ts.isSourceFile(p) || ts.isModuleBlock(p) || ts.isCaseClause(p) || ts.isDefaultClause(p)) r = inStatements(p.statements);
    else if (ts.isFunctionLike(p) && (p.parameters.some((x) => binds(x.name)) || (!ts.isFunctionDeclaration(p) && p.name && ts.isIdentifier(p.name) && p.name.text === name))) r = [];
    else if ((ts.isForStatement(p) || ts.isForOfStatement(p) || ts.isForInStatement(p)) && p.initializer && ts.isVariableDeclarationList(p.initializer)) r = inList(p.initializer);
    else if (ts.isCatchClause(p) && p.variableDeclaration && binds(p.variableDeclaration.name)) r = [];
    if (r) return r;
  }
  return [];
}
const LETTER = /\p{L}/u;
const TWO_WORDS = /\p{L}+\s+\p{L}+/u;
const I18N_MODULE = /(^|\/)i18n(\/index(\.ts)?)?$/;
const T_MODULE = /(^|\/)i18n\/T\.svelte$/;
const PHYSICAL_PROP =
  /^(?:(?:margin|padding|scroll-margin|scroll-padding)-(?:left|right)|border-(?:left|right)(?:-(?:width|style|color))?|border-(?:top|bottom)-(?:left|right)-radius|left|right)$/;
const PHYSICAL_VALUE_PROP = /^(?:text-align|float|clear)$/;
const PHYSICAL_VALUE = /\b(?:left|right)\b/;

/** Whether a CSS declaration names a physical side (`margin-left`, `text-align: right`). */
export function physical(property, value) {
  const p = property.toLowerCase();
  return PHYSICAL_PROP.test(p) || (PHYSICAL_VALUE_PROP.test(p) && PHYSICAL_VALUE.test(String(value)));
}

function cssPhysical(stylesheet) {
  let n = 0;
  const visit = (node) => {
    if (!node || typeof node !== 'object') return;
    if (Array.isArray(node)) return node.forEach(visit);
    if (node.type === 'Declaration' && physical(node.property, node.value)) n++;
    for (const [k, v] of Object.entries(node)) if (k !== 'parent' && k !== 'metadata' && v && typeof v === 'object') visit(v);
  };
  visit(stylesheet);
  return n;
}

/** Physical CSS properties in a plain stylesheet (`src/app.css`). */
export function cssFilePhysical(css) {
  return cssPhysical(parseSvelte(`<style>${css}</style>`, { modern: true }).css);
}

const isLit = (n) => n && (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n));
const unwrap = (n) => {
  while (n.parent && (ts.isParenthesizedExpression(n.parent) || ts.isAsExpression(n.parent) || ts.isNonNullExpression(n.parent) || ts.isSatisfiesExpression?.(n.parent))) n = n.parent;
  return n;
};

/** Everything the check and the lints need from one source file. */
export function analyzeFile(rel, text, context) {
  const line = lineAt(text);
  const out = {
    rel,
    context,
    usesLayer: false,
    messages: [], // { kind, english, note, line }
    fails: [], // { rule, line, msg }
    literal: [], // lines of literal template text (the lint)
    scriptText: [], // lines of script strings of two or more words (warn level)
    intl: 0,
    physical: 0,
  };
  const fail = (rule, at, msg) => out.fails.push({ rule, line: line(at), msg });
  const isFormat = rel === 'lib/format.ts';
  const imports = { tr: new Set(), tk: new Set(), T: new Set() };
  const fns = new Map(); // local name -> { fn: 't'|'tn'|'m', ctx }
  const objs = new Map(); // local name -> ctx (a binder held whole: `const b = tr('x'); b.t(...)`)
  const units = []; // { sf, offset, module }

  const parseUnit = (code, offset, module, statement = false) => {
    const src = statement ? code : `(${code})`;
    const sf = ts.createSourceFile(`${rel}.unit.ts`, src, ts.ScriptTarget.ES2022, true, ts.ScriptKind.TS);
    units.push({ sf, offset: statement ? offset : offset - 1, module });
    return units[units.length - 1];
  };

  // Pass 1: imports and binders, from the scripts.
  const collect = (unit) => {
    const visit = (n) => {
      if (ts.isImportDeclaration(n) && ts.isStringLiteral(n.moduleSpecifier)) {
        const from = n.moduleSpecifier.text;
        const cl = n.importClause;
        if (cl && T_MODULE.test(from) && cl.name) imports.T.add(cl.name.text);
        if (cl && I18N_MODULE.test(from) && cl.namedBindings && ts.isNamedImports(cl.namedBindings)) {
          for (const el of cl.namedBindings.elements) {
            const imported = (el.propertyName ?? el.name).text;
            if (imported === 'tr' || imported === 'tk') imports[imported].add(el.name.text);
          }
        }
      }
      if (ts.isVariableDeclaration(n) && n.initializer) {
        const init = n.initializer;
        if (ts.isCallExpression(init) && isBinderCall(init)) {
          const ctx = isLit(init.arguments[0]) ? init.arguments[0].text : null;
          if (ts.isObjectBindingPattern(n.name)) {
            for (const el of n.name.elements) {
              const prop = el.propertyName && ts.isIdentifier(el.propertyName) ? el.propertyName.text : ts.isIdentifier(el.name) ? el.name.text : null;
              if (['t', 'tn', 'm'].includes(prop) && ts.isIdentifier(el.name)) fns.set(el.name.text, { fn: prop, ctx });
            }
          } else if (ts.isIdentifier(n.name)) objs.set(n.name.text, ctx);
        }
      }
      ts.forEachChild(n, visit);
    };
    visit(unit.sf);
  };
  const isBinderCall = (call) => ts.isIdentifier(call.expression) && (imports.tr.has(call.expression.text) || (isFormat && call.expression.text === 'bind'));

  const inFunction = (n) => {
    for (let p = n.parent; p; p = p.parent) {
      if (ts.isClassStaticBlockDeclaration(p)) return false;
      if (ts.isFunctionLike(p)) return true;
      if (ts.isPropertyDeclaration(p) && !p.modifiers?.some((m) => m.kind === ts.SyntaxKind.StaticKeyword)) return true;
    }
    return false;
  };
  const inType = (n) => {
    for (let p = n.parent; p; p = p.parent) if (ts.isTypeNode(p) && !ts.isExpressionWithTypeArguments(p)) return true;
    return false;
  };
  const propertyName = (n) => {
    const p = n.parent;
    return (
      p &&
      (ts.isPropertyAssignment(p) || ts.isPropertySignature(p) || ts.isPropertyDeclaration(p) || ts.isMethodDeclaration(p) || ts.isEnumMember(p) || ts.isGetAccessor(p) || ts.isSetAccessor(p)) &&
      p.name === n
    );
  };

  /** The message function a call invokes, if any: { fn, ctx } or { fn: 'tk' }. */
  const messageCall = (call) => {
    const e = call.expression;
    if (ts.isIdentifier(e)) {
      if (fns.has(e.text)) return fns.get(e.text);
      if (imports.tk.has(e.text)) return { fn: 'tk', ctx: null };
      return null;
    }
    if (ts.isPropertyAccessExpression(e) && ['t', 'tn', 'm'].includes(e.name.text)) {
      if (ts.isIdentifier(e.expression) && objs.has(e.expression.text)) return { fn: e.name.text, ctx: objs.get(e.expression.text) };
      if (ts.isCallExpression(e.expression) && isBinderCall(e.expression)) {
        const a = e.expression.arguments[0];
        return { fn: e.name.text, ctx: isLit(a) ? a.text : null };
      }
    }
    return null;
  };
  const translates = (n) => {
    let found = false;
    const visit = (x) => {
      if (found) return;
      if (ts.isCallExpression(x)) {
        const mc = messageCall(x);
        if (mc && mc.fn !== 'm') found = true;
      }
      ts.forEachChild(x, visit);
    };
    visit(n);
    return found;
  };
  const allowed = (ctx) => ctx === context || ctx === COMMON;

  // Pass 2: messages, rules, strings, Intl.
  const analyze = (unit) => {
    const at = (n) => unit.offset + n.getStart(unit.sf);
    const visit = (n) => {
      if (ts.isCallExpression(n)) {
        if (isBinderCall(n)) {
          out.usesLayer = true;
          const a = n.arguments[0];
          if (!isLit(a)) fail('non-literal', at(n), 'the context of tr() must be a string literal');
          else if (isFormat ? a.text !== 'format' : !allowed(a.text)) fail('context', at(n), `context ${JSON.stringify(a.text)}: a file uses its own context (${JSON.stringify(context)}) or "common"`);
        }
        const mc = messageCall(n);
        if (mc) {
          const args = n.arguments;
          if (mc.fn !== 'tk') {
            const nEnglish = mc.fn === 'tn' ? 2 : 1;
            const noteAt = mc.fn === 't' ? 2 : mc.fn === 'tn' ? 4 : 1;
            const lits = args.slice(0, nEnglish);
            const note = args[noteAt];
            if (lits.length < nEnglish || !lits.every(isLit)) fail('non-literal', at(n), `${mc.fn}() takes English as string literals`);
            else if (note && !isLit(note) && note.kind !== ts.SyntaxKind.UndefinedKeyword && !(ts.isIdentifier(note) && note.text === 'undefined'))
              fail('non-literal', at(n), `the note of ${mc.fn}() must be a string literal`);
            else if (mc.ctx !== null) {
              const english = nEnglish === 2 ? [lits[0].text, lits[1].text] : lits[0].text;
              out.messages.push({ kind: mc.fn, ctx: mc.ctx, english, note: note && isLit(note) ? note.text : undefined, line: line(at(n)) });
            }
            // A plural's two English forms name the same placeholders: a translation's forms are
            // checked against them, and a form other than `other` may leave some out.
            const ph = (s) => [...new Set(s.match(PLACEHOLDER) ?? [])].sort().join(' ');
            if (mc.fn === 'tn' && lits.length === 2 && lits.every(isLit) && ph(lits[0].text) !== ph(lits[1].text))
              fail('plural-forms', at(n), `tn()'s two English forms name different placeholders (${JSON.stringify(ph(lits[0].text))} and ${JSON.stringify(ph(lits[1].text))})`);
          } else {
            // tk() shows a message m() marked; an object made in place would escape extraction: in
            // the call, in either branch of a condition, or as the value the variable it names is
            // declared with (in the scope it is read from).
            const objectLike = (e, depth = 0) => {
              while (e && (ts.isParenthesizedExpression(e) || ts.isAsExpression(e) || ts.isSatisfiesExpression?.(e) || ts.isTypeAssertionExpression?.(e) || ts.isNonNullExpression(e))) e = e.expression;
              if (!e || depth > 3) return false;
              if (ts.isObjectLiteralExpression(e)) return true;
              if (ts.isConditionalExpression(e)) return objectLike(e.whenTrue, depth + 1) || objectLike(e.whenFalse, depth + 1);
              if (ts.isBinaryExpression(e) && [ts.SyntaxKind.BarBarToken, ts.SyntaxKind.QuestionQuestionToken, ts.SyntaxKind.AmpersandAmpersandToken].includes(e.operatorToken.kind)) return objectLike(e.left, depth + 1) || objectLike(e.right, depth + 1);
              if (ts.isIdentifier(e)) return declaredWith(e).some((v) => objectLike(v, depth + 1));
              return false;
            };
            if (objectLike(args[0])) fail('non-literal', at(n), 'tk() shows a message marked with m(), never an object literal');
          }
          if (mc.fn !== 'm') {
            if (unit.module && !inFunction(n)) fail('top-level', at(n), `${mc.fn}() at the top level of a module runs before the language is loaded: call it where the text is shown, or mark it with m()`);
            const u = unwrap(n);
            const p = u.parent;
            if (p && ts.isBinaryExpression(p) && [ts.SyntaxKind.EqualsEqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsEqualsToken, ts.SyntaxKind.EqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsToken].includes(p.operatorToken.kind))
              fail('misuse', at(n), 'a translated text is display text only: never a comparison operand');
            if (p && ts.isCallExpression(p) && p.arguments[0] === u && ts.isPropertyAccessExpression(p.expression) && ['set', 'get', 'has', 'add', 'delete'].includes(p.expression.name.text))
              fail('misuse', at(n), 'a translated text is display text only: never a Map or Set key');
          }
        }
        // Stored values: a translation never reaches storage.
        if (ts.isPropertyAccessExpression(n.expression) && n.expression.name.text === 'setItem' && n.arguments.some(translates))
          fail('misuse', at(n), 'a translated text is display text only: never a stored value');
      }
      if (ts.isPropertyAccessExpression(n)) {
        if (ts.isIdentifier(n.expression) && n.expression.text === 'Intl') out.intl++;
        else if (/^toLocale/.test(n.name.text)) out.intl++;
      }
      if (isLit(n) || ts.isTemplateExpression(n)) stringLiteral(n, unit, at);
      ts.forEachChild(n, visit);
    };
    visit(unit.sf);
  };

  const stringLiteral = (n, unit, at) => {
    const p = n.parent;
    if (!p || inType(n) || propertyName(n)) return;
    if (ts.isImportDeclaration(p) || ts.isExportDeclaration(p) || ts.isExternalModuleReference(p)) return;
    if (ts.isCallExpression(p) && p.expression.kind === ts.SyntaxKind.ImportKeyword) return;
    if (ts.isCallExpression(p)) {
      if (isBinderCall(p)) return;
      const mc = messageCall(p);
      const i = p.arguments.indexOf(n);
      if (mc && ((mc.fn === 't' && i === 2) || (mc.fn === 'tn' && i === 4) || (mc.fn === 'm' && i === 1))) return;
    }
    const raw = ts.isTemplateExpression(n) ? n.head.text + n.templateSpans.map((s) => `{}${s.literal.text}`).join('') : n.text;
    const m = masked(raw);
    if (m === null) return;
    const isMessage = ts.isCallExpression(p) && messageCall(p);
    if (!isMessage && TWO_WORDS.test(raw)) out.scriptText.push(line(at(n)));
  };

  if (rel.endsWith('.svelte')) {
    let ast;
    try {
      ast = parseSvelte(text, { modern: true, filename: rel });
    } catch (e) {
      fail('malformed', 0, `cannot parse: ${e.message}`);
      return out;
    }
    const scripts = [ast.module, ast.instance].filter(Boolean);
    for (const s of scripts) collect(parseUnit(text.slice(s.content.start, s.content.end), s.content.start, s.context === 'module', true));
    const exprs = [];
    const expr = (node) => node && typeof node.start === 'number' && exprs.push(node);
    const attrText = (value) => (Array.isArray(value) ? value.map((v) => (v.type === 'Text' ? v.data : '{}')).join('') : null);
    // A literal attribute value: plain text without `{…}` (Svelte would substitute those itself), or
    // a string literal as the expression (`msg={'Muted by <b>{who}</b>'}`).
    const staticText = (value) => {
      const parts = Array.isArray(value) ? value : [value];
      if (parts.length !== 1) return null;
      const p = parts[0];
      if (p.type === 'Text') return p.data;
      const e = p.type === 'ExpressionTag' ? p.expression : null;
      if (e?.type === 'Literal' && typeof e.value === 'string') return e.value;
      if (e?.type === 'TemplateLiteral' && e.expressions.length === 0) return e.quasis[0].value.cooked;
      return null;
    };
    const handleRun = (nodes, st) => {
      const raw = nodes.map((n) => (n.type === 'Text' ? n.data : '{}')).join('');
      const m = masked(raw);
      if (m === null) return;
      if (!st.translateNo && LETTER.test(m.replace(/\{\}/g, ''))) out.literal.push(line(nodes[0].start));
    };
    const element = (n, st) => {
      let translateNo = st.translateNo;
      const isT = n.type === 'Component' && imports.T.has(n.name);
      const tAttrs = {};
      for (const a of n.attributes ?? []) {
        if (a.type === 'Attribute') {
          if (a.value === true) continue;
          const parts = Array.isArray(a.value) ? a.value : [a.value];
          if (isT && ['ctx', 'msg', 'note'].includes(a.name)) {
            tAttrs[a.name] = staticText(a.value);
            if (tAttrs[a.name] === null) for (const part of parts) if (part.type === 'ExpressionTag') expr(part.expression);
            continue;
          }
          for (const part of parts) if (part.type === 'ExpressionTag') expr(part.expression);
          if (a.name === 'href' && parts.some((part) => part.type === 'ExpressionTag')) hrefs.push(parts.filter((x) => x.type === 'ExpressionTag').map((x) => x.expression));
          const s = attrText(a.value);
          if (a.name === 'translate' && s === 'no') translateNo = true;
          if (s === null || NOT_TEXT_ATTRS.includes(a.name)) continue;
          const m = masked(s);
          if (m === null) continue;
          if ((isTextAttr(n.name, a.name) || (isComponentNode(n) && TEXT_PROPS.includes(a.name))) && !st.translateNo && LETTER.test(m.replace(/\{\}/g, ''))) out.literal.push(line(a.start));
        } else if (a.type === 'StyleDirective') {
          if (physical(a.name, '')) out.physical++;
          const parts = a.value === true ? [] : Array.isArray(a.value) ? a.value : [a.value];
          for (const part of parts) if (part.type === 'ExpressionTag') expr(part.expression);
        } else if (a.type !== 'LetDirective' && a.expression) expr(a.expression);
      }
      if (n.type === 'SvelteElement' && n.tag && typeof n.tag === 'object') expr(n.tag);
      if (n.type === 'SvelteComponent' && n.expression) expr(n.expression);
      if (isT) {
        out.usesLayer = true;
        if (tAttrs.ctx == null || tAttrs.msg == null || ('note' in tAttrs && tAttrs.note == null))
          fail('non-literal', n.start, "<T> takes ctx, msg and note as literals: ctx=\"name\", msg={'English with {placeholders}'}");
        else if (tAttrs.ctx !== context) fail('context', n.start, `<T ctx=${JSON.stringify(tAttrs.ctx)}>: a file uses its own context (${JSON.stringify(context)})`);
        else out.messages.push({ kind: 'T', ctx: tAttrs.ctx, english: tAttrs.msg, note: tAttrs.note ?? undefined, line: line(n.start) });
      }
      if (n.fragment) fragment(n.fragment, { translateNo });
    };
    const hrefs = [];
    const eachKeys = [];
    const fragment = (frag, st) => {
      let run = [];
      const flush = () => {
        if (run.length) handleRun(run, st);
        run = [];
      };
      for (const n of frag?.nodes ?? []) {
        if (n.type === 'Text' || n.type === 'ExpressionTag') {
          run.push(n);
          if (n.type === 'ExpressionTag') expr(n.expression);
          continue;
        }
        flush();
        switch (n.type) {
          case 'Comment':
          case 'DebugTag':
            break;
          case 'IfBlock':
            expr(n.test);
            fragment(n.consequent, st);
            if (n.alternate) fragment(n.alternate, st);
            break;
          case 'EachBlock':
            expr(n.expression);
            if (n.key) {
              expr(n.key);
              eachKeys.push(n.key);
            }
            fragment(n.body, st);
            if (n.fallback) fragment(n.fallback, st);
            break;
          case 'AwaitBlock':
            expr(n.expression);
            for (const f of [n.pending, n.then, n.catch]) if (f) fragment(f, st);
            break;
          case 'KeyBlock':
            expr(n.expression);
            fragment(n.fragment, st);
            break;
          case 'SnippetBlock':
            fragment(n.body, st);
            break;
          case 'ConstTag':
            exprs.push({ declaration: n.declaration });
            break;
          case 'RenderTag':
          case 'HtmlTag':
          case 'AttachTag':
            expr(n.expression);
            break;
          default:
            if (n.attributes) element(n, st);
            else if (n.fragment) fragment(n.fragment, st);
        }
      }
      flush();
    };
    fragment(ast.fragment, { translateNo: false });
    out.physical += ast.css ? cssPhysical(ast.css) : 0;
    const unitOf = new Map();
    for (const e of exprs) {
      if (e.declaration) {
        const d = e.declaration;
        const code = text.slice(d.start, d.end);
        const stmt = /^\s*(const|let|var)\b/.test(code);
        parseUnit(stmt ? code : `const ${code}`, stmt ? d.start : d.start - 6, false, true);
      } else unitOf.set(e, parseUnit(text.slice(e.start, e.end), e.start, false));
    }
    for (const u of units) analyze(u);
    const holdsTranslation = (node) => {
      const u = unitOf.get(node);
      return !!u && translates(u.sf);
    };
    for (const k of eachKeys) if (holdsTranslation(k)) fail('misuse', k.start, 'a translated text is display text only: never an {#each} key');
    for (const list of hrefs) if (list.some(holdsTranslation)) fail('misuse', list[0].start, 'a translated text is display text only: never part of a URL (href)');
  } else {
    const u = parseUnit(text, 0, true, true);
    collect(u);
    analyze(u);
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// The project: data files, locales, the whole check

const readJson = (p) => parse(readFileSync(p, 'utf8'));
// A note holds one more level than a locale file: the list of tokens of `exemptAdded`.
const NOTES_LIMITS = { ...LIMITS, depth: LIMITS.depth + 1 };
const identity = (ctx, english, note) => `${ctx}\u0004${englishKey(english)}\u0004${note ?? ''}`;
const show = (english) => (Array.isArray(english) ? `${english[0]} | ${english[1]}` : english);

/** A language's plural categories, from the committed table (`src/locales/plurals.json`), never
 * from the JavaScript engine (whose CLDR data moves with Node and differs between browsers). */
function pluralCategories(tag, plurals) {
  const lang = new Intl.Locale(tag).language;
  return Object.hasOwn(plurals ?? {}, lang) ? plurals[lang] : null;
}

/** The maintainer's step that writes `src/locales/plurals.json` once, from this Node's CLDR data
 * (ICU), for review: every language subtag the engine has plural rules for, categories in the
 * order zero, one, two, few, many, other. The check and `sync` read the file, never the engine. */
export function pluralTable() {
  const a = 'abcdefghijklmnopqrstuvwxyz';
  const codes = [];
  for (const x of a) for (const y of a) {
    codes.push(x + y);
    for (const z of a) codes.push(x + y + z);
  }
  const out = {};
  for (const code of Intl.PluralRules.supportedLocalesOf(codes)) {
    const r = new Intl.PluralRules(code).resolvedOptions();
    const lang = new Intl.Locale(r.locale).language;
    if (lang !== new Intl.Locale(code).language) continue;
    out[lang] = CATEGORIES.filter((c) => r.pluralCategories.includes(c));
  }
  return out;
}

const pairShape = shapeError;

function canonicalTagError(tag) {
  let c;
  try {
    [c] = Intl.getCanonicalLocales(tag);
  } catch {
    return 'not a BCP 47 tag';
  }
  if (c !== tag) return `not canonical (write "${c}")`;
  const loc = new Intl.Locale(tag);
  if (!/^[a-z]{2,3}(-[A-Z][a-z]{3})?(-(?:[A-Z]{2}|\d{3}))?$/.test(tag)) return 'a catalog tag is language[-Script][-REGION]';
  // Every English request is answered in English (and en-XA is computed from it): an English
  // catalog would never be chosen.
  if (loc.language === 'en') return 'English is built in: no catalog of English';
  if (MULTI_SCRIPT.includes(loc.language) && !loc.script) return `"${loc.language}" is written in more than one script: name it (for example "${loc.language}-${new Intl.Locale(loc.language).maximize().script}")`;
  return null;
}

/** Loads the data files of `src/locales/`, reporting their own problems. */
function loadData(root, findings) {
  const dir = join(root, 'src', 'locales');
  const rel = (f) => `src/locales/${f}`;
  const failAt = (file, rule, msg) => findings.push({ level: 'fail', rule, file, msg });
  const data = { manifest: {}, contexts: {}, glossary: [], notes: {}, plurals: {}, verbatim: {}, baseline: null, locales: {} };
  if (!existsSync(dir)) {
    failAt('src/locales', 'manifest', 'src/locales/ is missing');
    return data;
  }
  for (const f of readdirSync(dir).sort(cmp)) {
    const p = join(dir, f);
    const text = readFileSync(p, 'utf8');
    if (DATA_FILES.includes(f) || OPTIONAL_FILES.includes(f)) {
      let v;
      try {
        v = parse(text, f === 'notes.json' ? NOTES_LIMITS : LIMITS);
      } catch (e) {
        failAt(rel(f), 'malformed', `not acceptable JSON: ${e.message}`);
        continue;
      }
      const catalogShaped = ['notes.json', 'verbatim.json', 'baseline.json'].includes(f);
      const isPluralTable = (x) =>
        !!x && typeof x === 'object' && !Array.isArray(x) && Object.entries(x).every(([k, cs]) => /^[a-z]{2,3}$/.test(k) && Array.isArray(cs) && cs.includes('other') && cs.join() === CATEGORIES.filter((c) => cs.includes(c)).join());
      const ok = catalogShaped
        ? isCatalogShape(v)
        : f === 'glossary.json'
          ? Array.isArray(v) && v.every((s) => typeof s === 'string' && s)
          : f === 'plurals.json'
            ? isPluralTable(v)
            : v && typeof v === 'object' && !Array.isArray(v);
      if (!ok) {
        failAt(rel(f), 'malformed', 'unexpected shape');
        continue;
      }
      const canon = catalogShaped ? serializeCatalog(v, 'data') : f === 'glossary.json' ? serializeJson([...new Set(v)].sort(cmp)) : serializeJson(v);
      if (canon !== text) failAt(rel(f), 'canonical', 'not in canonical form (run `node scripts/i18n.mjs sync` or re-serialize)');
      data[f.replace('.json', '')] = v;
      continue;
    }
    data.locales[f] = text;
  }
  for (const f of DATA_FILES) if (!existsSync(join(dir, f))) failAt(rel(f), 'manifest', `${f} is missing`);
  // The manifest.
  for (const [tag, e] of Object.entries(data.manifest)) {
    const where = rel('manifest.json');
    const err = canonicalTagError(tag);
    if (err) failAt(where, 'manifest', `${JSON.stringify(tag)}: ${err}`);
    if (!e || typeof e !== 'object' || Array.isArray(e)) {
      failAt(where, 'manifest', `${JSON.stringify(tag)}: an entry is an object`);
      continue;
    }
    for (const k of Object.keys(e)) {
      if (RESERVED_MANIFEST_FIELDS.includes(k)) failAt(where, 'manifest', `${JSON.stringify(tag)}: ${JSON.stringify(k)} is reserved: regional overlays are not built yet, so a regional language is a full catalog`);
      else if (!MANIFEST_FIELDS.includes(k)) failAt(where, 'manifest', `${JSON.stringify(tag)}: unknown field ${JSON.stringify(k)}`);
    }
    if (!Array.isArray(e.owners) || !e.owners.length || !e.owners.every((o) => typeof o === 'string' && LOGIN.test(o))) failAt(where, 'manifest', `${JSON.stringify(tag)}: "owners" lists the GitHub logins (plain, without an at-sign) of the people who answer for it`);
    if (e.dir !== 'ltr' && e.dir !== 'rtl') failAt(where, 'manifest', `${JSON.stringify(tag)}: "dir" is "ltr" or "rtl"`);
    if (typeof e.offered !== 'boolean') failAt(where, 'manifest', `${JSON.stringify(tag)}: "offered" is true or false`);
    if (e.dir === 'rtl' && e.offered === true) failAt(where, 'manifest', `${JSON.stringify(tag)}: a right-to-left language is not offered before the right-to-left layout exists`);
    if (typeof e.since !== 'string' || !VERSION.test(e.since)) failAt(where, 'manifest', `${JSON.stringify(tag)}: "since" is a release version (x.y.z)`);
    if (e.belowSince !== undefined && (typeof e.belowSince !== 'string' || !VERSION.test(e.belowSince))) failAt(where, 'manifest', `${JSON.stringify(tag)}: "belowSince" is a release version`);
    if (!Object.hasOwn(data.locales, `${tag}.json`)) failAt(where, 'manifest', `${JSON.stringify(tag)}: src/locales/${tag}.json is missing`);
    if (!err && pluralCategories(tag, data.plurals) === null)
      failAt(where, 'manifest', `${JSON.stringify(tag)}: src/locales/plurals.json has no plural rules for "${new Intl.Locale(tag).language}": ask a maintainer to add the language`);
  }
  for (const f of Object.keys(data.locales)) {
    const tag = f.replace(/\.json$/, '');
    if (!f.endsWith('.json') || !Object.hasOwn(data.manifest, tag)) {
      failAt(rel(f), 'stray', 'src/locales/ holds the data files and one catalog per manifest entry only');
      delete data.locales[f];
    }
  }
  for (const [path, ctx] of Object.entries(data.contexts)) {
    if (typeof ctx !== 'string' || !CONTEXT.test(ctx) || ctx === COMMON) failAt(rel('contexts.json'), 'context', `${JSON.stringify(path)}: ${JSON.stringify(ctx)} is not a context name`);
  }
  return data;
}

function isCatalogShape(v) {
  return !!v && typeof v === 'object' && !Array.isArray(v) && Object.values(v).every((a) => Array.isArray(a));
}

/** Reads a catalog-shaped data file (notes, verbatim) into identity -> value. */
function byIdentity(cat) {
  const m = new Map();
  for (const [ctx, pairs] of Object.entries(cat ?? {})) for (const p of pairs) if (Array.isArray(p) && p.length >= 1) m.set(identity(ctx, p[0], pairNote(p) || undefined), p[1]);
  return m;
}

/**
 * The whole check. Returns `{ findings, entries, shipped, files }`:
 * - findings: `{ level: 'fail'|'report', rule, file, line?, msg, values? }` (catalog text only in `values`);
 * - entries: identity -> { ctx, english, note, files } for every message in the source now;
 * - shipped: tag -> { hash: translation } of the current pairs that agree with their English.
 * `previous`: tag -> the text of that locale file one commit back, or null when it cannot be read.
 */
export function check(root, { previous = null, ratchets = true } = {}) {
  const findings = [];
  const add = (f) => findings.push(f);
  const data = loadData(root, findings);
  const files = sourceFiles(root).map((f) => analyzeFile(f.rel, f.text, Object.hasOwn(data.contexts, f.rel) ? data.contexts[f.rel] : contextName(f.rel)));
  const src = (rel) => `src/${rel}`;

  // Source rules.
  const byContext = new Map();
  for (const f of files) {
    for (const x of f.fails) add({ level: 'fail', rule: x.rule, file: src(f.rel), line: x.line, msg: x.msg });
    if (!f.usesLayer) continue;
    if (!CONTEXT.test(f.context) || f.context === COMMON) add({ level: 'fail', rule: 'context', file: src(f.rel), msg: `${JSON.stringify(f.context)} cannot be a file's context: add the file to src/locales/contexts.json` });
    byContext.set(f.context, [...(byContext.get(f.context) ?? []), f.rel]);
  }
  for (const [ctx, rels] of byContext)
    if (rels.length > 1) add({ level: 'fail', rule: 'context-collision', file: src(rels[1]), msg: `context ${JSON.stringify(ctx)} belongs to ${rels.map(src).join(' and ')}: give the library file its own name in src/locales/contexts.json` });
  for (const path of Object.keys(data.contexts)) if (!files.some((f) => f.rel === path)) add({ level: 'report', rule: 'stale', file: 'src/locales/contexts.json', msg: `${JSON.stringify(path)} is not a source file` });

  const entries = new Map();
  for (const f of files)
    for (const m of f.messages) {
      const id = identity(m.ctx, m.english, m.note);
      const e = entries.get(id) ?? { ctx: m.ctx, english: m.english, note: m.note, files: [] };
      e.files.push(`${src(f.rel)}:${m.line}`);
      entries.set(id, e);
    }
  const common = [...entries.values()].filter((e) => e.ctx === COMMON);
  if (common.length > COMMON_MAX) add({ level: 'fail', rule: 'common-size', file: common[0].files[0], msg: `"common" holds ${common.length} messages; at most ${COMMON_MAX} (bare actions): move the rest to their files' contexts` });
  const hashes = new Map();
  for (const [id, e] of entries) {
    const h = hash(e.ctx, e.english, e.note);
    const other = hashes.get(h);
    if (other && other !== id) {
      const o = entries.get(other);
      add({ level: 'fail', rule: 'hash-collision', file: e.files[0], msg: `two messages share the hash ${h}: add a note to one of them (${o.files[0]})`, values: [show(o.english), show(e.english)] });
    } else hashes.set(h, id);
  }

  const notes = byIdentity(data.notes);
  const verbatim = byIdentity(data.verbatim);
  for (const [name, m] of [['notes.json', notes], ['verbatim.json', verbatim]])
    for (const id of m.keys()) if (!entries.has(id)) add({ level: 'report', rule: 'stale', file: `src/locales/${name}`, msg: `an entry of context ${JSON.stringify(id.split('\u0004')[0])} is no longer in the source`, values: [id.split('\u0004')[1]] });
  for (const [id, v] of verbatim) if (!Array.isArray(v) || !v.every((w) => typeof w === 'string' && w)) add({ level: 'fail', rule: 'malformed', file: 'src/locales/verbatim.json', msg: 'a verbatim value is a list of words', values: [id.split('\u0004')[1]] });
  // `exemptAdded` lists the tokens a translation of the message may add (`["24:00"]`), never "all".
  const tokenList = (x) => Array.isArray(x) && x.length > 0 && x.every((w) => typeof w === 'string' && w);
  for (const [id, v] of notes)
    if (!v || typeof v !== 'object' || Array.isArray(v) || Object.keys(v).some((k) => !['text', 'sensitive', 'exemptDigits', 'exemptAdded'].includes(k)) || (Object.hasOwn(v, 'exemptAdded') && !tokenList(v.exemptAdded)))
      add({ level: 'fail', rule: 'malformed', file: 'src/locales/notes.json', msg: 'a note is { text?, sensitive?, exemptDigits?, exemptAdded? } (exemptAdded: the tokens it allows, ["24:00"])', values: [id.split('\u0004')[1]] });

  // Locales.
  const shipped = {};
  let total = 0;
  for (const [tag, meta] of Object.entries(data.manifest).sort(([a], [b]) => cmp(a, b))) {
    const file = `src/locales/${tag}.json`;
    const text = data.locales[`${tag}.json`];
    const cats = text === undefined || canonicalTagError(tag) ? null : pluralCategories(tag, data.plurals);
    if (cats === null) continue;
    const dir = meta?.dir === 'rtl' ? 'rtl' : 'ltr';
    let cat;
    try {
      cat = parse(text);
    } catch (e) {
      add({ level: 'fail', rule: 'malformed', file, msg: `not acceptable JSON: ${e.message}` });
      continue;
    }
    if (!isCatalogShape(cat)) {
      add({ level: 'fail', rule: 'malformed', file, msg: 'a locale file maps each context to a list of pairs' });
      continue;
    }
    // A context is a source file's name (or the left-over section): anything else is refused, so no
    // locale file can carry text that is not data into the report.
    const badContexts = Object.keys(cat).filter((ctx) => ctx !== LEFTOVER && !CONTEXT.test(ctx));
    for (const ctx of badContexts) add({ level: 'fail', rule: 'context', file, msg: `context ${JSON.stringify(ctx)} is not a context name (lower camel case, or "~leftover")` });
    const shapeErrors = [];
    for (const [ctx, pairs] of Object.entries(cat)) for (const p of pairs) {
      const err = pairShape(p, cats, ctx);
      if (err) shapeErrors.push({ ctx, err, p });
    }
    for (const s of shapeErrors) add({ level: 'fail', rule: s.err.startsWith('plural categories') ? 'plural-categories' : 'malformed', file, msg: `context ${JSON.stringify(s.ctx)}: ${s.err}`, values: [JSON.stringify(s.p)] });
    if (shapeErrors.length || badContexts.length) continue;
    if (serializeCatalog(cat) !== text) add({ level: 'fail', rule: 'canonical', file, msg: 'not in canonical form (run `node scripts/i18n.mjs sync ' + tag + '`)' });
    const s = ship(cat, entries, { verbatim, notes, glossary: data.glossary, dir });
    for (const x of s.findings) {
      const where = `context ${JSON.stringify(x.ctx)}`;
      if (x.check) add({ level: x.level, rule: x.rule, check: x.check, file, msg: `${where}: ${x.check}: ${x.detail}${x.at >= 0 ? ` at ${x.at}` : ''}`, values: [x.english, ...(x.translation === undefined ? [] : [x.translation]), x.token] });
      else add({ level: x.level, rule: x.rule, file, msg: `${where}: ${x.detail}`, values: [show(x.english)] });
    }
    const { table, translated, leftovers } = s;
    // Reports: missing, left over, coverage.
    const current = [...entries.entries()];
    const missing = current.filter(([id]) => !translated.has(id));
    if (missing.length) add({ level: 'report', rule: 'missing', file, msg: `${missing.length} of ${current.length} messages have no translation`, values: missing.map(([, e]) => `${e.ctx}: ${show(e.english)}`) });
    for (const l of leftovers) {
      const near = nearest(l.english, current.filter(([, e]) => e.ctx === l.ctx).map(([, e]) => e.english));
      add({ level: 'report', rule: 'left-over', file, msg: `context ${JSON.stringify(l.ctx)}: this English is no longer in the source; it is not shipped`, values: near === null ? [show(l.english)] : [show(l.english), `nearest now: ${show(near)}`] });
    }
    const pct = current.length ? Math.floor((translated.size * 1000) / current.length) / 10 : 100;
    add({ level: 'report', rule: 'coverage', file, msg: `${JSON.stringify(tag)}: ${translated.size} of ${current.length} messages (${pct}%)${data.baseline ? baselineCoverage(data.baseline, translated) : ''}; owners: ${(meta?.owners ?? []).join(', ')}` });
    // Sensitive changes and swaps, against the file one commit back.
    const prev = previous ? previous[tag] : null;
    if (prev === null || prev === undefined) add({ level: 'report', rule: 'not-checked', file, msg: 'sensitive and swap lines: not checked (no previous version of this file)' });
    else sensitiveAndSwaps(prev, cat, notes, file, add);
    const json = serializeShipped(table);
    const gz = gzipSync(json, { level: constants.Z_BEST_COMPRESSION }).length;
    total += gz;
    if (gz > LOCALE_BUDGET) add({ level: 'fail', rule: 'size', file, msg: `${(gz / 1024).toFixed(1)} KiB gzipped; a language may take ${LOCALE_BUDGET / 1024} KiB` });
    shipped[tag] = { json, dir, offered: meta?.offered === true };
  }
  if (total > LOCALES_BUDGET) add({ level: 'fail', rule: 'size', file: 'src/locales', msg: `all languages: ${(total / 1024).toFixed(1)} KiB gzipped; together they may take ${LOCALES_BUDGET / 1024} KiB` });

  if (ratchets) ratchetFindings(root, files, add);
  return { findings, entries, shipped, files, data };
}

/** The ratchets: literal text, Intl outside format.ts, physical CSS. A count above zero in a file that
 * `i18n-baseline.json` does not list (a file new, or moved, since the baseline was written) fails, as it does
 * in a file the baseline lists at zero. */
function ratchetFindings(root, files, add) {
  const src = (rel) => `src/${rel}`;
  let base = {};
  if (existsSync(join(root, 'i18n-baseline.json'))) {
    try {
      base = readJson(join(root, 'i18n-baseline.json'));
    } catch (e) {
      add({ level: 'fail', rule: 'malformed', file: 'i18n-baseline.json', msg: `not acceptable JSON: ${e.message}` });
      return;
    }
  }
  const counts = ratchetCounts(root, files);
  for (const [kind, now] of Object.entries(counts)) {
    const was = base[kind] ?? {};
    for (const [rel, n] of Object.entries(now)) {
      const listed = Object.hasOwn(was, rel);
      const b = listed ? was[rel] : 0;
      const f = files.find((x) => x.rel === rel);
      if (kind === 'literal') {
        const lines = `lines ${f?.literal.join(', ')}`;
        if (n > 0 && listed && b === 0) add({ level: 'fail', rule: 'literal-text', file: src(rel), line: f?.literal[0], msg: `${n} literal text${n === 1 ? '' : 's'} in a file the baseline holds at zero: use t() (${lines})` });
        else if (n > 0 && !listed)
          add({ level: 'fail', rule: 'literal-text', file: src(rel), line: f?.literal[0], msg: `${n} literal text${n === 1 ? '' : 's'} in a file i18n-baseline.json does not list: use t() (${lines})` });
      } else if (n > b) {
        const what = kind === 'intl' ? `${n} Intl/toLocale call sites, ${b} allowed: format in lib/format.ts` : `${n} physical CSS properties, ${b} allowed: use logical ones (margin-inline-start, text-align: start)`;
        add({ level: 'fail', rule: kind === 'intl' ? 'intl' : 'physical-css', file: kind === 'physical' && rel === 'app.css' ? 'src/app.css' : src(rel), msg: listed ? what : `${what} (a file i18n-baseline.json does not list)` });
      }
      if (kind === 'intl' && n > 0 && f?.usesLayer && rel !== 'lib/format.ts') add({ level: 'fail', rule: 'intl', file: src(rel), msg: 'a file on the translation layer formats through lib/format.ts only' });
      if (n < b) add({ level: 'report', rule: 'baseline', file: 'i18n-baseline.json', msg: `${kind} ${JSON.stringify(rel)}: ${n}, baseline ${b} (lower it: node scripts/i18n.mjs baseline)` });
    }
  }
  const above = Object.values(counts.literal).filter((n) => n > 0).length;
  add({ level: 'report', rule: 'literal-text', file: 'i18n-baseline.json', msg: `${above} files hold literal text` });
  for (const f of files) {
    if (f.usesLayer && f.scriptText.length) add({ level: 'report', rule: 'script-text', file: src(f.rel), msg: `script strings of two or more words on lines ${f.scriptText.join(', ')}: text the reader sees goes through t()` });
  }
}

/**
 * What one locale file ships. Every pair is checked against its own English half (so a change to
 * the English in the source alone can never make a locale fail); a pair that agrees and whose
 * identity (context, normalized English, note) is in the source now, compared as text, ships under
 * the hash of that source entry. Findings are structured: `{ level, rule, ctx, english,
 * translation?, check?, token?, at?, detail }` (`check`: the agreement rule that failed).
 */
export function ship(cat, entries, { verbatim = new Map(), notes = new Map(), glossary = [], dir = 'ltr' } = {}) {
  const findings = [];
  const table = {};
  const translated = new Set();
  const leftovers = [];
  const seen = new Set();
  for (const [ctx, pairs] of Object.entries(cat)) {
    if (ctx === LEFTOVER) continue;
    for (const p of pairs) {
      const note = pairNote(p) || undefined;
      const id = identity(ctx, p[0], note);
      if (seen.has(id)) {
        findings.push({ level: 'fail', rule: 'malformed', ctx, english: p[0], detail: 'the same English twice' });
        continue;
      }
      seen.add(id);
      const empty = typeof p[1] === 'string' ? p[1] === '' : Object.values(p[1]).every((x) => x === '');
      if (empty) continue;
      // A maintainer's exemptions (notes.json, reviewed): the digit rule, and the tokens the
      // added-token rule allows (then reported instead).
      const ea = notes.get(id)?.exemptAdded;
      const opts = { verbatim: verbatim.get(id) ?? [], glossary, dir, exemptDigits: !!notes.get(id)?.exemptDigits, exemptAdded: Array.isArray(ea) ? ea : undefined };
      // A plural form against the English form of its category (`one`), else English `other`; a
      // form other than `other` may leave out placeholders (a dual, or a "one" that names no number).
      const forms = typeof p[1] === 'string' ? [[p[0], p[1], false]] : Object.entries(p[1]).map(([c, x]) => [c === 'one' ? p[0][0] : p[0][1], x, c !== 'other']);
      let ok = true;
      for (const [en, tx, subset] of forms) {
        if (tx === '') {
          ok = false;
          continue;
        }
        const v = agree(en, tx, { ...opts, placeholderSubset: subset });
        for (const x of v.fails) findings.push({ level: 'fail', rule: 'agreement', ctx, english: en, translation: tx, check: x.rule, token: x.token, at: x.at, detail: x.detail });
        for (const x of v.reports) findings.push({ level: 'report', rule: `agreement-${x.rule}`, ctx, english: en, check: x.rule, token: x.token, at: x.at, detail: x.detail });
        if (v.fails.length) ok = false;
      }
      const e = entries.get(id);
      if (!e) {
        leftovers.push({ ctx, english: p[0] });
        continue;
      }
      if (ok) {
        table[hash(e.ctx, e.english, e.note)] = typeof p[1] === 'string' ? p[1] : canonValue(p[1]);
        translated.add(id);
      }
    }
  }
  return { table, translated, leftovers, findings };
}

function baselineCoverage(baseline, translated) {
  const ids = [...byIdentity(baseline).keys()];
  const done = ids.filter((id) => translated.has(id)).length;
  return `; ${done} of the ${ids.length} at the previous release (${ids.length ? Math.floor((done * 1000) / ids.length) / 10 : 100}%)`;
}

function sensitiveAndSwaps(prevText, cat, notes, file, add) {
  let prev;
  try {
    prev = parse(prevText);
  } catch {
    prev = {};
  }
  const old = new Map();
  for (const [ctx, pairs] of Object.entries(isCatalogShape(prev) ? prev : {})) for (const p of pairs) if (Array.isArray(p) && ctx !== LEFTOVER) old.set(identity(ctx, p[0], pairNote(p) || undefined), JSON.stringify(p[1]));
  const oldValues = new Map([...old].map(([id, v]) => [v, id]));
  for (const [ctx, pairs] of Object.entries(cat)) {
    if (ctx === LEFTOVER) continue;
    for (const p of pairs) {
      const id = identity(ctx, p[0], pairNote(p) || undefined);
      const now = JSON.stringify(p[1]);
      if (old.get(id) === now) continue;
      if (notes.get(id)?.sensitive) add({ level: 'report', rule: 'sensitive', file, msg: `context ${JSON.stringify(ctx)}: a sensitive message changed: its pull request carries a back-translation`, values: [show(p[0])] });
      const was = oldValues.get(now);
      if (was && was !== id && now !== '""') add({ level: 'report', rule: 'swap', file, msg: `context ${JSON.stringify(ctx)}: the new translation is the old translation of another message`, values: [show(p[0]), was.split('\u0004')[1]] });
    }
  }
}

/** The nearest current English (by edit distance), as a hint for a left-over pair. */
function nearest(english, candidates) {
  const a = englishKey(english);
  let best = null;
  let bestD = Infinity;
  for (const c of candidates) {
    const b = englishKey(c);
    const d = distance(a, b);
    if (d < bestD) {
      bestD = d;
      best = c;
    }
  }
  return best !== null && bestD < Math.max(a.length, englishKey(best).length) ? best : null;
}

function distance(a, b) {
  if (a.length > 300 || b.length > 300) return Math.abs(a.length - b.length) + (a === b ? 0 : 1);
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    prev = cur;
  }
  return prev[b.length];
}

/** The shipped form: hash -> translation, keys sorted, no English. */
export function serializeShipped(table) {
  return JSON.stringify(Object.fromEntries(Object.keys(table).sort(cmp).map((k) => [k, table[k]])));
}

/** Per-file counts of the three ratchets. */
export function ratchetCounts(root, files) {
  const counts = { literal: {}, intl: {}, physical: {} };
  for (const f of files) {
    counts.literal[f.rel] = f.literal.length;
    if (f.rel !== 'lib/format.ts') counts.intl[f.rel] = f.intl;
    counts.physical[f.rel] = f.physical;
  }
  const css = join(root, 'src', 'app.css');
  if (existsSync(css)) counts.physical['app.css'] = cssFilePhysical(readFileSync(css, 'utf8'));
  return counts;
}

/**
 * The baseline file from the current tree and the baseline before it (`node scripts/i18n.mjs
 * baseline`). Each ratchet lists every file, zeros too, so a file the baseline does not list is new
 * (or moved) since it was written. A listed file keeps the lower of its two counts: a count is
 * lowered, never raised. A file not listed is added only at zero (one that holds text, an Intl call
 * or a physical property stays unlisted, and the check fails it). A file that is gone is dropped.
 * Without a baseline before it, every count is written as it is.
 */
export function baselineOf(root, files, previous = null) {
  const counts = ratchetCounts(root, files);
  const out = {};
  for (const [k, v] of Object.entries(counts)) {
    const was = previous?.[k];
    out[k] = {};
    for (const [rel, n] of Object.entries(v)) {
      if (!was) out[k][rel] = n;
      else if (Object.hasOwn(was, rel)) out[k][rel] = Math.min(was[rel], n);
      else if (n === 0) out[k][rel] = 0;
    }
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// Output

const LEVELS = { fail: 'FAIL', report: 'REPORT' };

/** The console report (values included: the log is not rendered). */
export function formatReport(result) {
  const lines = [];
  const fails = result.findings.filter((f) => f.level === 'fail');
  const used = result.files.filter((f) => f.usesLayer);
  lines.push(`i18n: ${result.files.length} source files, ${used.length} on the translation layer, ${result.entries.size} messages; ${Object.keys(result.shipped).length} locale(s) in the manifest`);
  // No line of the log may start with what a file put in a message (a CI runner reads `::…` lines
  // as commands): line breaks and other controls in a message or a path are printed escaped.
  const one = (s) => String(s).replace(/[\u0000-\u001f\u007f-\u009f\u{2028}\u{2029}]/gu, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
  for (const f of result.findings) {
    lines.push(`${LEVELS[f.level]} ${one(f.rule)} ${one(f.file)}${f.line ? `:${f.line}` : ''}: ${one(f.msg)}`);
    for (const v of f.values ?? []) lines.push(`    ${JSON.stringify(v)}`);
  }
  lines.push(fails.length ? `i18n: ${fails.length} failure(s)` : 'i18n: no failures');
  return lines.join('\n');
}

function fence(lines) {
  const body = lines.join('\n');
  let longest = 0;
  for (const m of body.matchAll(/`+/g)) longest = Math.max(longest, m[0].length);
  const f = '`'.repeat(Math.max(3, longest + 1));
  return `${f}text\n${body}\n${f}`;
}

/** The GitHub job summary (Markdown): rules, files, contexts and counts in the text; any catalog
 * or English value only inside a fenced block, so none of it is rendered as Markdown. */
export function summaryMarkdown(result) {
  const out = ['## Languages (i18n check)', ''];
  const fails = result.findings.filter((f) => f.level === 'fail');
  out.push(`${result.files.filter((f) => f.usesLayer).length} files on the translation layer, ${result.entries.size} messages, ${fails.length} failure(s).`, '');
  for (const level of ['fail', 'report']) {
    const list = result.findings.filter((f) => f.level === level);
    if (!list.length) continue;
    out.push(`### ${LEVELS[level]}`, '');
    for (const f of list) {
      const safeName = (s) => String(s).replace(/[^A-Za-z0-9 ._:/~()%,-]/g, '?');
      out.push(`- ${safeName(f.rule)} in ${safeName(f.file)}${f.line ? `:${f.line}` : ''} (${(f.values ?? []).length} value(s))`);
      const body = [f.msg, ...(f.values ?? []).map((v) => JSON.stringify(v))];
      out.push('', fence(body), '');
    }
  }
  return `${out.join('\n')}\n`;
}

// ---------------------------------------------------------------------------------------------
// Commands that write

/** Writes the shipped catalogs, the URL table and the list of the files it wrote (all git-ignored;
 * postbuild allows exactly the listed files in `assets/locales/`). With no locale: an empty table. */
export function prebuild(root, result = check(root, { ratchets: false })) {
  const outDir = join(root, 'public', 'assets', 'locales');
  rmSync(outDir, { recursive: true, force: true });
  const rows = [];
  const emitted = [];
  for (const [tag, s] of Object.entries(result.shipped)) {
    const sha = createHash('sha256').update(s.json).digest('hex').slice(0, 8);
    const name = `${tag}-${sha}.json`;
    mkdirSync(outDir, { recursive: true });
    writeFileSync(join(outDir, name), s.json);
    emitted.push({ file: name, tag });
    rows.push(`  ${JSON.stringify(tag)}: { url: ${JSON.stringify(`/assets/locales/${name}`)}, dir: ${JSON.stringify(s.dir)}, offered: ${s.offered} },`);
  }
  mkdirSync(join(root, 'src', 'lib', 'i18n'), { recursive: true });
  writeFileSync(join(root, 'src', 'lib', 'i18n', 'emitted.gen.json'), serializeJson(emitted));
  const gen = [
    '// GENERATED by scripts/i18n.mjs prebuild from src/locales/ (ADR-189); git-ignored, never committed.',
    "import type { LocaleTable } from './index';",
    '',
    `export const LOCALES: LocaleTable = Object.freeze(Object.assign(Object.create(null), {${rows.length ? `\n${rows.join('\n')}\n` : ''}}));`,
    '',
  ].join('\n');
  const genPath = join(root, 'src', 'lib', 'i18n', 'locales.gen.ts');
  mkdirSync(join(root, 'src', 'lib', 'i18n'), { recursive: true });
  if (!existsSync(genPath) || readFileSync(genPath, 'utf8') !== gen) writeFileSync(genPath, gen);
  return rows.length;
}

/** `sync <tag>`: extract -> skeleton -> merge. Every message of the source is in the file (`[english,
 * ""]` where it has no translation yet); pairs whose English is gone move to `~leftover` (or go,
 * with `prune`). Plural categories come from `src/locales/plurals.json`. */
export function sync(root, tag, { prune = false } = {}) {
  const result = check(root, { ratchets: false });
  const cats = pluralCategories(tag, result.data.plurals);
  if (cats === null) throw new Error(`src/locales/plurals.json has no plural rules for "${tag}": ask a maintainer to add the language`);
  const p = join(root, 'src', 'locales', `${tag}.json`);
  const cat = existsSync(p) ? parse(readFileSync(p, 'utf8')) : {};
  const skel = skeleton(result.entries.values(), cats);
  writeFileSync(p, serializeCatalog(merge(cat, skel, identity, { prune })));
}

/** `carry <context> --from <old> --to <new>`: an English edit that keeps the meaning; rewrites the
 * English half in every locale file, and in the notes and verbatim lists. */
export function carry(root, ctx, from, to) {
  const dir = join(root, 'src', 'locales');
  const manifest = readJson(join(dir, 'manifest.json'));
  const files = [...Object.keys(manifest).map((t) => `${t}.json`), 'notes.json', 'verbatim.json'];
  let n = 0;
  for (const f of files) {
    const p = join(dir, f);
    if (!existsSync(p)) continue;
    const cat = parse(readFileSync(p, 'utf8'), f === 'notes.json' ? NOTES_LIMITS : LIMITS);
    for (const pr of cat[ctx] ?? []) {
      if (typeof pr[0] === 'string' && normalize(pr[0]) === normalize(from)) {
        pr[0] = to;
        n++;
      }
    }
    writeFileSync(p, serializeCatalog(cat, f === 'notes.json' || f === 'verbatim.json' ? 'data' : 'locale'));
  }
  return n;
}
