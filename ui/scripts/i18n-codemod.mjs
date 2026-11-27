// REQ: API-012 (ADR-189) — a development tool for part A's migration: it moves the literal text of
// a Svelte file behind the file's `t()`, and lists every site it cannot move safely, for the hand.
//
//   node scripts/i18n-codemod.mjs [--write] [--json <file>] (--all | <file under src/>...)
//
// It reads the Svelte syntax tree (and the TypeScript one for scripts and expressions) and edits by
// source offsets, last offset first:
// - a template text node becomes `{t('…')}`, its leading and trailing whitespace left outside the
//   call; the literal is the text as the browser shows it (whitespace runs collapsed to one space,
//   character entities decoded). Svelte keeps the whitespace inside a text node as written (it trims
//   and collapses only at the edges), and the browser collapses it when it draws the text
//   (`white-space: normal`): the page reads the same, and the DOM's text node holds one space where
//   the source had a line break and an indent. `<pre>` keeps whitespace, and is listed;
// - the attributes a reader sees or hears (`aria-label`, `title`, `placeholder`, `alt`,
//   `aria-roledescription`, `aria-description`, `aria-valuetext`, `aria-placeholder`, `label` on
//   `<optgroup>`) become `name={t('…')}` with their value as it is;
// - the file gets `import { tr } from '…/lib/i18n'` and `const { t } = tr('<context>')` once.
// It lists, per file and never edits: text in one sentence with an expression (`{n} rows`), with an
// inline element or a block that carries text (`Read the <a>docs</a>`), words cut by an element with
// no text (`Dots: <span class="key"></span> first, <span class="key"></span> next`: the `split`
// class; moved one by one they would become several messages), attributes and component
// properties with text, `<pre>` and `<textarea>` content, text with braces, plural ternaries
// (`n === 1 ? 'row' : 'rows'`: `tn()` takes the English `one` form for -1 too, so each comes with
// the count's range), script strings that read as text, strings used as identifiers or keys,
// canvas `fillText`, and `Intl`/`toLocale*` sites (they move into `lib/format.ts`).
// Without `--write` nothing is written; the report is the same.
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import ts from 'typescript';
import { parse as parseSvelte } from 'svelte/compiler';
import { TEXT_ATTRS, contextName, sourceFiles } from './i18n-lib.mjs';

const WS = /[ \t\n\r\f]+/g;
const LETTER = /\p{L}/u;
const TWO_WORDS = /\p{L}+\s+\p{L}+/u;
const CAPITALIZED = /^[A-Z][a-z]+(?:[\s'’-][A-Za-z]+)*[.:!?…]?$/;

// Elements that never continue a sentence around them (blocks, table parts, form controls, media).
const SEPARATORS = new Set(
  'address article aside audio blockquote br button canvas caption col colgroup datalist dd details dialog div dl dt fieldset figcaption figure footer form h1 h2 h3 h4 h5 h6 header hgroup hr iframe img input legend li main menu meter nav ol optgroup option output p picture pre progress section select summary svg table tbody td template textarea tfoot th thead title tr ul video'.split(' '),
);
// Components that show no text of their own beside a sentence (icons, help and badges).
const QUIET_COMPONENTS = new Set(['Icon', 'HelpButton', 'Tip', 'DomainIcon', 'HealthIcon', 'Logo', 'StatusBadge', 'BreakerBadge']);
const NO_TEXT_ELEMENTS = new Set(['pre', 'textarea']);

const collapse = (s) => s.replace(WS, ' ');
const excerpt = (s, n = 100) => {
  const c = collapse(s).trim();
  return c.length > n ? `${c.slice(0, n - 1)}…` : c;
};
/** A JavaScript string literal in single quotes; invisible characters escaped. */
export function quote(s) {
  let out = "'";
  for (const ch of s) {
    const c = ch.codePointAt(0);
    if (ch === "'" || ch === '\\') out += `\\${ch}`;
    else if (ch === '\n') out += '\\n';
    else if (ch === '\r') out += '\\r';
    else if (ch === '\t') out += '\\t';
    else if (c < 0x20 || c === 0x7f || c === 0xa0 || (c >= 0x2000 && c <= 0x200f) || (c >= 0x2028 && c <= 0x202f) || c === 0xfeff) out += `\\u${c.toString(16).padStart(4, '0')}`;
    else out += ch;
  }
  return `${out}'`;
}

/** Whether a script string reads as text a person sees (two words, or a capitalized word). */
export function readsAsText(s) {
  if (!LETTER.test(s)) return false;
  // Addresses, paths and CSS (a canvas font) are not text.
  if (/^(?:https?:|mailto:|\/|#\/|\.\.?\/)/.test(s) || /\d(?:px|rem|em)\b|var\(--|sans-serif|monospace/.test(s)) return false;
  return TWO_WORDS.test(s) || CAPITALIZED.test(s);
}

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

/** The relative import of `lib/i18n` from a file under `src/`. */
function i18nImport(rel) {
  let p = relative(dirname(join('/src', rel)), '/src/lib/i18n').split('\\').join('/');
  if (!p.startsWith('.')) p = `./${p}`;
  return p;
}

// ---------------------------------------------------------------------------------------------
// Scripts and expressions (TypeScript syntax tree)

const COMPARE = new Set([ts.SyntaxKind.EqualsEqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsEqualsToken, ts.SyntaxKind.EqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsToken]);
const PLURAL_TEST = (b) => {
  if (!ts.isBinaryExpression(b)) return null;
  const k = b.operatorToken.kind;
  const lit = (n) => ts.isNumericLiteral(n) && n.text;
  if (COMPARE.has(k)) {
    if (lit(b.right) === '1') return b.left;
    if (lit(b.left) === '1') return b.right;
  }
  if ((k === ts.SyntaxKind.GreaterThanToken && lit(b.right) === '1') || (k === ts.SyntaxKind.LessThanToken && lit(b.right) === '2')) return b.left;
  if ((k === ts.SyntaxKind.LessThanEqualsToken && lit(b.right) === '1') || (k === ts.SyntaxKind.GreaterThanEqualsToken && lit(b.right) === '2')) return b.left;
  return null;
};
const strings = (n) => {
  const out = [];
  const visit = (x) => {
    if (ts.isStringLiteral(x) || ts.isNoSubstitutionTemplateLiteral(x)) out.push(x.text);
    else if (ts.isTemplateExpression(x)) out.push(x.head.text + x.templateSpans.map((s) => `{}${s.literal.text}`).join(''));
    ts.forEachChild(x, visit);
  };
  visit(n);
  return out;
};
const inType = (n) => {
  for (let p = n.parent; p; p = p.parent) if (ts.isTypeNode(p) && !ts.isExpressionWithTypeArguments(p)) return true;
  return false;
};
const MESSAGE_FNS = new Set(['t', 'tn', 'm', 'tk', 'tc', 'tr', 'bind']);

/** Property names whose values the file uses as identifiers: `{#each … (x.p)}` keys, `x.p ===`,
 * `new Set(xs.map((x) => x.p))`. Labels stored under them are keys, not just text. */
function keyProps(units, eachKeys) {
  const out = new Set(eachKeys);
  for (const { sf } of units) {
    const visit = (n) => {
      if (ts.isBinaryExpression(n) && COMPARE.has(n.operatorToken.kind)) for (const side of [n.left, n.right]) if (ts.isPropertyAccessExpression(side)) out.add(side.name.text);
      if (ts.isNewExpression(n) && ts.isIdentifier(n.expression) && ['Set', 'Map'].includes(n.expression.text))
        for (const a of n.arguments ?? []) {
          const v = (x) => {
            if (ts.isArrowFunction(x) && ts.isPropertyAccessExpression(x.body)) out.add(x.body.name.text);
            ts.forEachChild(x, v);
          };
          v(a);
        }
      ts.forEachChild(n, visit);
    };
    visit(sf);
  }
  return out;
}

/** Lists what a script or an expression holds for the hand. `unit`: { sf, offset }. */
function scanUnit(unit, keys, list, line) {
  const at = (n) => line(unit.offset + n.getStart(unit.sf));
  const inPlural = new Set();
  const visit = (n) => {
    if (ts.isConditionalExpression(n)) {
      const count = PLURAL_TEST(n.condition);
      const words = [...strings(n.whenTrue), ...strings(n.whenFalse)].filter((s) => LETTER.test(s));
      if (count && words.length) {
        const c = count.getText(unit.sf);
        const never = /\.(length|size)$/.test(c) || /^Object\.(keys|values|entries)\(/.test(c);
        list('plural', at(n), `${excerpt(n.getText(unit.sf), 120)}`, { count: c, range: never ? 'never negative (a length or size): tn() keeps the English' : 'check by hand: tn() picks "one" for -1, the ternary the plural' });
        for (const s of [n.whenTrue, n.whenFalse]) {
          const mark = (x) => {
            inPlural.add(x);
            ts.forEachChild(x, mark);
          };
          mark(s);
        }
      }
    }
    if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && ['fillText', 'strokeText'].includes(n.expression.name.text)) list('canvas', at(n), excerpt(n.getText(unit.sf)));
    if (ts.isPropertyAccessExpression(n) && ((ts.isIdentifier(n.expression) && n.expression.text === 'Intl') || /^toLocale/.test(n.name.text))) list('intl', at(n), excerpt(n.parent ? n.parent.getText(unit.sf) : n.getText(unit.sf)));
    if ((ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n) || ts.isTemplateExpression(n)) && !inPlural.has(n)) {
      const raw = ts.isTemplateExpression(n) ? n.head.text + n.templateSpans.map((s) => `{}${s.literal.text}`).join('') : n.text;
      const p = n.parent;
      const skip =
        !p ||
        inType(n) ||
        ts.isImportDeclaration(p) ||
        ts.isExportDeclaration(p) ||
        ts.isExternalModuleReference(p) ||
        (ts.isCallExpression(p) && p.expression.kind === ts.SyntaxKind.ImportKeyword) ||
        (ts.isCallExpression(p) && ts.isIdentifier(p.expression) && MESSAGE_FNS.has(p.expression.text)) ||
        (ts.isCallExpression(p) && ts.isPropertyAccessExpression(p.expression) && ['t', 'tn', 'm'].includes(p.expression.name.text)) ||
        (ts.isCallExpression(p) && ts.isPropertyAccessExpression(p.expression) && ts.isIdentifier(p.expression.expression) && p.expression.expression.text === 'console') ||
        // (counted with its canvas site)
        (ts.isCallExpression(p) && ts.isPropertyAccessExpression(p.expression) && ['fillText', 'strokeText'].includes(p.expression.name.text));
      if (!skip && readsAsText(raw)) {
        const name = (ts.isPropertyAssignment(p) || ts.isPropertySignature(p)) && p.name === n;
        if (name) list('key', at(n), excerpt(raw), { why: 'an object key' });
        else if (ts.isBinaryExpression(p) && COMPARE.has(p.operatorToken.kind)) list('identifier', at(n), excerpt(raw), { why: 'compared' });
        else if (ts.isCaseClause(p)) list('identifier', at(n), excerpt(raw), { why: 'a case label' });
        else if (ts.isElementAccessExpression(p) && p.argumentExpression === n) list('key', at(n), excerpt(raw), { why: 'an index' });
        else if (ts.isCallExpression(p) && p.arguments[0] === n && ts.isPropertyAccessExpression(p.expression) && ['get', 'set', 'has', 'delete', 'add'].includes(p.expression.name.text)) list('key', at(n), excerpt(raw), { why: `a ${p.expression.name.text}() key` });
        else if (ts.isPropertyAssignment(p) && p.initializer === n && ts.isIdentifier(p.name) && keys.has(p.name.text)) list('identifier', at(n), excerpt(raw), { why: `the value of "${p.name.text}", which the file uses as a key` });
        else list('script', at(n), excerpt(raw));
      }
    }
    ts.forEachChild(n, visit);
  };
  visit(unit.sf);
}

const unitOf = (code, offset, statement) => ({
  sf: ts.createSourceFile('unit.ts', statement ? code : `(${code})`, ts.ScriptTarget.ES2022, true, ts.ScriptKind.TS),
  offset: statement ? offset : offset - 1,
});

// ---------------------------------------------------------------------------------------------
// One file

/**
 * The codemod on one file. Returns `{ code, handled, listed, binder }`: the new source (equal to
 * `text` when nothing is handled), the sites it moved (`{ kind: 'text'|'attribute', line, english }`)
 * and the sites it lists (`{ class, line, text, ...detail }`).
 */
export function transform(rel, text, { context = contextName(rel) } = {}) {
  const line = lineAt(text);
  const handled = [];
  const listed = [];
  const list = (cls, ln, t, extra = {}) => listed.push({ class: cls, line: ln, text: t, ...extra });
  if (!rel.endsWith('.svelte')) {
    const u = unitOf(text, 0, true);
    scanUnit(u, keyProps([u], []), list, line);
    return { code: text, handled, listed, binder: null };
  }
  const ast = parseSvelte(text, { modern: true, filename: rel });
  const units = [];
  const eachKeys = [];
  // Every identifier anywhere (scripts and template), and the names bound where the binder would
  // clash: at the top of a script, or in a template scope (each, snippet, await, const, let).
  const identifiers = new Set();
  const bound = new Set();
  const patternNames = (p) => {
    if (!p || typeof p !== 'object') return;
    if (Array.isArray(p)) return p.forEach(patternNames);
    if (p.type === 'Identifier') bound.add(p.name);
    else for (const k of ['properties', 'elements', 'value', 'left', 'argument', 'id', 'declarations']) if (p[k]) patternNames(p[k]);
  };
  const ids = (node) => {
    if (!node || typeof node !== 'object') return;
    if (Array.isArray(node)) return node.forEach(ids);
    if (node.type === 'Identifier' && typeof node.name === 'string') identifiers.add(node.name);
    if (node.type === 'EachBlock') {
      patternNames(node.context);
      if (typeof node.index === 'string') bound.add(node.index);
    }
    if (node.type === 'SnippetBlock') patternNames(node.parameters);
    if (node.type === 'AwaitBlock') patternNames([node.value, node.error]);
    if (node.type === 'ConstTag') patternNames(node.declaration);
    if (node.type === 'LetDirective') bound.add(node.name);
    for (const [k, v] of Object.entries(node)) if (k !== 'parent' && k !== 'metadata' && v && typeof v === 'object') ids(v);
  };
  ids(ast.fragment);
  for (const s of [ast.module, ast.instance].filter(Boolean)) {
    const u = unitOf(text.slice(s.content.start, s.content.end), s.content.start, true);
    units.push(u);
    const visit = (n) => {
      if (ts.isIdentifier(n)) identifiers.add(n.text);
      ts.forEachChild(n, visit);
    };
    visit(u.sf);
    const names = (b) => (ts.isIdentifier(b) ? bound.add(b.text) : (ts.isObjectBindingPattern(b) || ts.isArrayBindingPattern(b)) && b.elements.forEach((el) => !ts.isOmittedExpression(el) && names(el.name)));
    for (const st of u.sf.statements) {
      if (ts.isVariableStatement(st)) st.declarationList.declarations.forEach((d) => names(d.name));
      else if ((ts.isFunctionDeclaration(st) || ts.isClassDeclaration(st) || ts.isEnumDeclaration(st)) && st.name) bound.add(st.name.text);
      else if (ts.isImportDeclaration(st) && st.importClause) {
        const cl = st.importClause;
        if (cl.name) bound.add(cl.name.text);
        const nb = cl.namedBindings;
        if (nb && ts.isNamespaceImport(nb)) bound.add(nb.name.text);
        else if (nb) nb.elements.forEach((el) => bound.add(el.name.text));
      }
    }
  }
  const expr = (e) => {
    if (e && typeof e.start === 'number' && typeof e.end === 'number') units.push(unitOf(text.slice(e.start, e.end), e.start, false));
  };

  const edits = [];
  const isComponent = (n) => n.type === 'Component' || n.type === 'SvelteComponent' || n.type === 'SvelteSelf';
  const isText = (n) => n.type === 'Text' && LETTER.test(n.data);
  /** Text with letters, an expression or a render tag anywhere inside (attributes aside). */
  const carriesText = (n) => {
    if (n.type === 'Text') return LETTER.test(n.data);
    if (n.type === 'ExpressionTag' || n.type === 'RenderTag' || n.type === 'HtmlTag') return true;
    return fragmentsOf(n).some((f) => f.nodes.some(carriesText));
  };
  const fragmentsOf = (n) => [n.fragment, n.consequent, n.alternate, n.body, n.fallback, n.pending, n.then, n.catch].filter((f) => f && Array.isArray(f.nodes));
  /** A node that joins the text beside it into one sentence. */
  const joins = (n) => {
    switch (n.type) {
      case 'RenderTag':
      case 'HtmlTag':
        return true;
      case 'IfBlock':
      case 'EachBlock':
      case 'AwaitBlock':
      case 'KeyBlock':
        return fragmentsOf(n).some((f) => f.nodes.some((x) => isText(x) || x.type === 'ExpressionTag' || joins(x)));
      case 'RegularElement':
        return !SEPARATORS.has(n.name) && carriesText(n);
      case 'SvelteElement':
        return carriesText(n);
      default:
        return isComponent(n) ? !QUIET_COMPONENTS.has(n.name) : false;
    }
  };
  /** An element that sits inside a sentence and shows no text of its own: a swatch (`<span
   * class="key"></span>`), an inline image or `<svg>`, an icon or another quiet component. It does
   * not join the words around it (no text to list), yet it splits them. */
  const splitter = (n) => (n.type === 'RegularElement' && (!SEPARATORS.has(n.name) || n.name === 'svg' || n.name === 'img') && !carriesText(n)) || (isComponent(n) && QUIET_COMPONENTS.has(n.name));
  /** The runs of text, expressions and splitters in a fragment that read as one sentence cut in
   * pieces: two parts with a word or an expression in them, one or more splitters between them, and
   * a word somewhere. Moved one text at a time they would become several messages with no trace. */
  const splitRuns = (nodes) => {
    const runs = [];
    let cur = [];
    const end = () => {
      if (cur.length) runs.push(cur);
      cur = [];
    };
    for (const x of nodes) {
      if (x.type === 'Text' || x.type === 'ExpressionTag' || splitter(x)) cur.push(x);
      else end();
    }
    end();
    return runs.filter((r) => {
      let content = false;
      let cut = false;
      let joined = false;
      for (const x of r) {
        if (isText(x) || x.type === 'ExpressionTag') {
          if (content && cut) joined = true;
          content = true;
        } else if (splitter(x) && content) cut = true;
      }
      return joined && r.some(isText);
    });
  };
  const attributes = (n, st) => {
    for (const a of n.attributes ?? []) {
      if (a.type !== 'Attribute') {
        if (a.expression) expr(a.expression);
        if (a.type === 'StyleDirective' && Array.isArray(a.value)) for (const p of a.value) if (p.type === 'ExpressionTag') expr(p.expression);
        continue;
      }
      if (a.value === true) continue;
      const parts = Array.isArray(a.value) ? a.value : [a.value];
      for (const p of parts) if (p.type === 'ExpressionTag') expr(p.expression);
      const textual = TEXT_ATTRS.includes(a.name) || (n.name === 'optgroup' && a.name === 'label');
      const lettered = parts.some((p) => p.type === 'Text' && LETTER.test(p.data));
      // (As the literal-text lint reads it: a `translate="no"` around the element, not on it.)
      if (!lettered || st.translateNo) continue;
      const one = parts.length === 1 && parts[0].type === 'Text';
      if (textual && one) {
        if (/[{}]/.test(parts[0].data)) list('braces', line(a.start), excerpt(parts[0].data));
        else {
          edits.push({ start: a.start, end: a.end, text: `${a.name}={${T}(${quote(parts[0].data)})}` });
          handled.push({ kind: 'attribute', line: line(a.start), english: parts[0].data });
        }
      } else if (textual) list('attribute', line(a.start), excerpt(text.slice(a.start, a.end)));
      else if (isComponent(n) && one && readsAsText(parts[0].data)) list('prop', line(a.start), excerpt(text.slice(a.start, a.end)), { component: n.name });
    }
  };
  let T = 't';
  const handleText = (n, st) => {
    if (st.translateNo || st.inSentence || !isText(n)) return;
    const lead = /^[ \t\n\r\f]*/.exec(n.raw)[0];
    const trail = /[ \t\n\r\f]*$/.exec(n.raw.slice(lead.length))[0];
    const inner = n.data.slice(lead.length, n.data.length - trail.length);
    if (/[{}]/.test(inner)) return list('braces', line(n.start), excerpt(inner));
    if (inner !== inner.trim()) return list('other', line(n.start), excerpt(inner), { why: 'an encoded space at the edge of the text' });
    edits.push({ start: n.start + lead.length, end: n.end - trail.length, text: `{${T}(${quote(collapse(inner))})}` });
    handled.push({ kind: 'text', line: line(n.start), english: collapse(inner) });
  };
  const visitNode = (n, st) => {
    switch (n.type) {
      case 'Text':
        return handleText(n, st);
      case 'ExpressionTag':
      case 'RenderTag':
      case 'HtmlTag':
        return expr(n.expression);
      case 'Comment':
      case 'DebugTag':
        return;
      case 'ConstTag': {
        const d = n.declaration;
        const code = text.slice(d.start, d.end);
        const stmt = /^\s*(const|let|var)\b/.test(code);
        return units.push(unitOf(stmt ? code : `const ${code}`, stmt ? d.start : d.start - 6, true));
      }
      case 'IfBlock':
        expr(n.test);
        break;
      case 'EachBlock':
        expr(n.expression);
        if (n.key) {
          expr(n.key);
          if (n.key.type === 'MemberExpression' && n.key.property?.type === 'Identifier') eachKeys.push(n.key.property.name);
        }
        break;
      case 'AwaitBlock':
      case 'KeyBlock':
        expr(n.expression);
        break;
      case 'SnippetBlock':
        break;
      default:
        if (n.attributes) attributes(n, st);
        if (n.type === 'SvelteElement' && n.tag && typeof n.tag === 'object') expr(n.tag);
        if (n.type === 'SvelteComponent' && n.expression) expr(n.expression);
    }
    let next = st;
    if (n.attributes?.some((a) => a.type === 'Attribute' && a.name === 'translate' && Array.isArray(a.value) && a.value.length === 1 && a.value[0].type === 'Text' && a.value[0].data === 'no')) next = { ...st, translateNo: true };
    if (n.type === 'RegularElement' && NO_TEXT_ELEMENTS.has(n.name)) {
      if (!st.translateNo && !st.inSentence && carriesText(n)) list('pre', line(n.start), excerpt(text.slice(n.start, n.end)), { element: n.name });
      return;
    }
    for (const f of fragmentsOf(n)) fragment(f, next);
  };
  /** A fragment: a sentence with an inline element or a text-carrying block is listed whole (with
   * the text inside those); a run of text and expressions is listed; other text is moved. */
  const fragment = (frag, st) => {
    const nodes = frag.nodes.filter((x) => x.type !== 'Comment');
    const direct = nodes.some(isText);
    const hasExpr = nodes.some((x) => x.type === 'ExpressionTag');
    const joiners = nodes.filter(joins);
    const quiet = st.translateNo || st.inSentence;
    if (joiners.length && (direct || (hasExpr && joiners.some(carriesText)))) {
      if (!quiet) {
        const shown = (x) => x.type !== 'Text' || x.data.trim() !== '';
        const first = nodes.find(shown);
        const last = [...nodes].reverse().find(shown);
        list('inline', line(first.start), excerpt(text.slice(first.start, last.end), 120));
      }
      // The text inside the joining nodes belongs to that sentence: listed with it, never moved
      // (their attributes are still moved).
      for (const x of nodes) {
        if (x.type === 'ExpressionTag') expr(x.expression);
        else if (joins(x)) visitNode(x, { ...st, inSentence: true });
        else if (x.type !== 'Text') visitNode(x, st);
      }
      return;
    }
    // A sentence cut by elements with no text: listed whole, its words left for the hand (their
    // expressions and the elements' attributes are still read).
    const split = new Set();
    for (const r of splitRuns(nodes)) {
      const shown = r.filter((x) => x.type !== 'Text' || x.data.trim() !== '');
      if (!quiet) list('split', line(shown[0].start), excerpt(text.slice(shown[0].start, shown[shown.length - 1].end), 120));
      for (const x of r) split.add(x);
    }
    let run = [];
    const flush = () => {
      if (run.some((x) => x.type === 'ExpressionTag') && run.some(isText)) {
        if (!quiet) list('expression', line(run[0].start), excerpt(text.slice(run[0].start, run[run.length - 1].end)));
        for (const x of run) if (x.type === 'ExpressionTag') expr(x.expression);
      } else for (const x of run) visitNode(x, st);
      run = [];
    };
    for (const x of nodes) {
      if (split.has(x)) {
        flush();
        if (x.type === 'ExpressionTag') expr(x.expression);
        else if (x.type !== 'Text') visitNode(x, st);
        continue;
      }
      if (x.type === 'Text' || x.type === 'ExpressionTag') {
        run.push(x);
        continue;
      }
      flush();
      visitNode(x, st);
    }
    flush();
  };

  // The binder: the file's own if it has one, else `t` (or a name the file does not use).
  const existing = (() => {
    if (!ast.instance) return null;
    const u = unitOf(text.slice(ast.instance.content.start, ast.instance.content.end), ast.instance.content.start, true);
    let found = null;
    const visit = (n) => {
      if (ts.isVariableDeclaration(n) && n.initializer && ts.isCallExpression(n.initializer) && ts.isIdentifier(n.initializer.expression) && n.initializer.expression.text === 'tr') {
        const a = n.initializer.arguments[0];
        if (a && ts.isStringLiteral(a) && a.text === context && ts.isObjectBindingPattern(n.name))
          for (const el of n.name.elements) if ((el.propertyName ?? el.name).getText(u.sf) === 't' && ts.isIdentifier(el.name)) found = el.name.text;
      }
      ts.forEachChild(n, visit);
    };
    visit(u.sf);
    return found;
  })();
  // A name the file binds where the template would see it (or, for another name, uses at all) is
  // never taken: `t`, else `tx`, `tt`, `tl`.
  const free = (name, strict) => !bound.has(name) && !(strict && identifiers.has(name));
  if (existing) T = existing;
  else T = ['t', 'tx', 'tt', 'tl'].find((name, i) => free(name, i > 0)) ?? null;
  if (T) fragment(ast.fragment, { translateNo: false });
  else list('other', 1, 'the file binds t, tx, tt and tl', { why: 'no free name for the binder: bind it by hand' });
  const keys = keyProps(units, eachKeys);
  for (const u of units) scanUnit(u, keys, list, line);

  let binder = null;
  if (handled.length && !existing) {
    const imp = i18nImport(rel);
    const trName = free('tr', false) ? 'tr' : ['i18nTr', 'trI18n'].find((n) => free(n, true));
    const spec = trName === 'tr' ? '{ tr }' : `{ tr as ${trName} }`;
    const decl = `const { ${T === 't' ? 't' : `t: ${T}`} } = ${trName}(${quote(context)});`;
    if (ast.instance) {
      const body = ast.instance.content.body ?? [];
      const imports = body.filter((s) => s.type === 'ImportDeclaration');
      const content = text.slice(ast.instance.content.start, ast.instance.content.end);
      const indent = /\n([ \t]+)\S/.exec(content)?.[1] ?? '  ';
      // After the last import (or at the top of the script).
      const at = imports.length ? imports[imports.length - 1].end : ast.instance.content.start;
      edits.push({ start: at, end: at, text: `\n${indent}import ${spec} from ${quote(imp)};\n${indent}${decl}${imports.length ? '' : '\n'}` });
    } else {
      const at = ast.module ? ast.module.end : 0;
      const block = `<script lang="ts">\n  import ${spec} from ${quote(imp)};\n  ${decl}\n</script>`;
      edits.push({ start: at, end: at, text: ast.module ? `\n\n${block}` : `${block}\n\n` });
    }
    binder = { name: T, context, import: imp };
  }
  edits.sort((a, b) => b.start - a.start || b.end - a.end);
  let code = text;
  let floor = Infinity;
  for (const e of edits) {
    if (e.end > floor) throw new Error(`${rel}: overlapping edits at ${e.start}`);
    code = code.slice(0, e.start) + e.text + code.slice(e.end);
    floor = e.start;
  }
  listed.sort((a, b) => a.line - b.line || a.class.localeCompare(b.class));
  handled.sort((a, b) => a.line - b.line);
  return { code, handled, listed, binder };
}

// ---------------------------------------------------------------------------------------------
// The command

const CLASSES = ['expression', 'inline', 'split', 'attribute', 'prop', 'pre', 'braces', 'plural', 'script', 'identifier', 'key', 'canvas', 'intl', 'other'];
/** Files the codemod reads: every source file but the layer, the generated ones and `lib/format.ts`. */
export function codemodFiles(root) {
  return sourceFiles(root).filter((f) => f.rel !== 'lib/format.ts');
}

export function run(root, rels, { write = false } = {}) {
  const contexts = existsSync(join(root, 'src/locales/contexts.json')) ? JSON.parse(readFileSync(join(root, 'src/locales/contexts.json'), 'utf8')) : {};
  const files = codemodFiles(root).filter((f) => !rels || rels.includes(f.rel));
  const out = [];
  for (const f of files) {
    const context = Object.hasOwn(contexts, f.rel) ? contexts[f.rel] : contextName(f.rel);
    const r = transform(f.rel, f.text, { context });
    if (write && r.code !== f.text) writeFileSync(join(root, 'src', f.rel), r.code);
    out.push({ file: f.rel, context, ...r, code: undefined });
  }
  return out;
}

function main(argv) {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const write = argv.includes('--write');
  const ji = argv.indexOf('--json');
  const json = ji >= 0 ? argv[ji + 1] : null;
  const rels = argv.includes('--all') ? null : argv.filter((a, i) => !a.startsWith('--') && i !== ji + 1).map((a) => a.replace(/^src\//, ''));
  if (rels && !rels.length) {
    console.error('usage: node scripts/i18n-codemod.mjs [--write] [--json <file>] (--all | <file under src/>...)');
    process.exit(2);
  }
  const res = run(root, rels, { write });
  const tot = { handled: 0, text: 0, attribute: 0, listed: 0, byClass: Object.fromEntries(CLASSES.map((c) => [c, 0])) };
  for (const r of res) {
    if (!r.handled.length && !r.listed.length) continue;
    const by = {};
    for (const l of r.listed) by[l.class] = (by[l.class] ?? 0) + 1;
    tot.handled += r.handled.length;
    tot.text += r.handled.filter((h) => h.kind === 'text').length;
    tot.attribute += r.handled.filter((h) => h.kind === 'attribute').length;
    tot.listed += r.listed.length;
    for (const [c, n] of Object.entries(by)) tot.byClass[c] += n;
    console.log(`${r.file}: handled ${r.handled.length}, listed ${r.listed.length}${r.listed.length ? ` (${Object.entries(by).map(([c, n]) => `${c} ${n}`).join(', ')})` : ''}`);
  }
  console.log(`total: handled ${tot.handled} (text ${tot.text}, attributes ${tot.attribute}), listed ${tot.listed}: ${CLASSES.filter((c) => tot.byClass[c]).map((c) => `${c} ${tot.byClass[c]}`).join(', ')}${write ? '; files written' : ''}`);
  if (json) writeFileSync(json, `${JSON.stringify(res, null, 1)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) main(process.argv.slice(2));
