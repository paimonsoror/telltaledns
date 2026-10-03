//! List parsers for every syntax in `spec/05` §2.
//!
//! REQ: FLT-001 — hosts files, plain domains, `*.` wildcards, AdBlock/AdGuard DNS syntax
//! (`||domain^`, `|domain^`, `@@`, `/regex/`, `$important`, `$badfilter`, `$client`,
//! `$dnstype`, `$denyallow`, `$dnsrewrite`), and Pi-hole regex (`;querytype=`, `;invert`).
//! Formats are detected per line, so mixed lists work. Cosmetic and URL rules are counted as
//! unsupported, not errors (`spec/05` §2).
//!
//! Classification order for a trimmed line (ADR-017):
//! 1. blank; comment (`#`, `!`, `[Adblock Plus 2.0]`); inline ` # comment` stripped
//! 2. cosmetic/HTML rules (`##`, `#@#`, `#?#`, `#$#`, `#%#`, `$$`) → unsupported
//! 3. hosts (`<IP> name...`)
//! 4. AdBlock: starts with `@@`, `||`, `|`, or `/`, or is `name^[$modifiers]`
//! 5. Pi-hole regex: contains a regex metacharacter, or `;querytype=` / `;invert`
//! 6. `*.name` or `.name` (subdomains only), else a plain name

mod modifiers;
mod name;

use std::borrow::Cow;
use std::fmt;
use std::net::IpAddr;

use telltale_config::{ListKind, ListMatch};

pub use self::modifiers::{Modifiers, Negatable};
pub use self::name::{NameError, normalize};

/// Block or allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Action {
    Block,
    Allow,
}

/// Which names a domain rule covers (FLT-002).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// The name and every name below it.
    Subtree,
    /// Only the name.
    Exact,
    /// Names below it, not the name itself (`*.example.com`).
    Subdomains,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Pattern {
    /// Normalized name (lowercase ASCII, no trailing dot).
    Domain { name: String, scope: Scope },
    /// A regex over the lowercase query name, validated to compile with `regex-automata`'s
    /// syntax (no backreferences or lookaround). `invert` = Pi-hole `;invert`.
    Regex { pattern: String, invert: bool },
}

/// One rule, as the compiler (T2.3) consumes it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Rule {
    pub action: Action,
    pub pattern: Pattern,
    pub modifiers: Modifiers,
}

/// How to read a list's plain entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ListOptions {
    pub kind: ListKind,
    pub match_mode: ListMatch,
}

impl ListOptions {
    fn action(self) -> Action {
        match self.kind {
            ListKind::Block => Action::Block,
            ListKind::Allow => Action::Allow,
        }
    }
    fn plain_scope(self) -> Scope {
        match self.match_mode {
            ListMatch::Subtree => Scope::Subtree,
            ListMatch::Exact => Scope::Exact,
        }
    }
}

/// What one line turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineKind {
    Blank,
    Comment,
    /// Hosts-file boilerplate (`127.0.0.1 localhost`), not a list entry.
    Ignored,
    /// This many rules were produced (hosts lines can carry several names).
    Rules(usize),
    /// Valid syntax we don't apply (cosmetic rules, URL paths, unknown modifiers).
    Unsupported(String),
    /// Malformed.
    Invalid(String),
}

/// Per-list parse statistics (`spec/05` §6: invalid and unsupported lines).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParseStats {
    pub lines: u64,
    pub blank: u64,
    pub comments: u64,
    pub ignored: u64,
    pub rules: u64,
    pub invalid: u64,
    pub unsupported: u64,
    /// The first problem lines of each kind, for the UI and `telltale lists check`.
    pub samples: Vec<Sample>,
}

/// A problem line: 1-based line number, the line, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sample {
    pub line: u32,
    pub text: String,
    pub reason: String,
    pub unsupported: bool,
}

/// Problem lines kept per kind (invalid, unsupported), so a list full of unsupported
/// cosmetic rules still shows its invalid ones.
const MAX_SAMPLES: usize = 10;

/// Parses a whole list, calling `sink(line_number, rule)` for every rule.
pub fn parse_list(data: &[u8], opts: ListOptions, mut sink: impl FnMut(u32, Rule)) -> ParseStats {
    let data = data.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(data);
    // The final newline terminates the last line; it doesn't start another.
    let data = data.strip_suffix(b"\n").unwrap_or(data);
    let mut stats = ParseStats::default();
    if data.is_empty() {
        return stats;
    }
    let mut rules = Vec::new();
    for (i, raw) in data.split(|&b| b == b'\n').enumerate() {
        let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
        let line_no = u32::try_from(i + 1).unwrap_or(u32::MAX);
        let text: Cow<'_, str> = String::from_utf8_lossy(raw);
        stats.lines += 1;
        rules.clear();
        match parse_line(&text, opts, &mut rules) {
            LineKind::Blank => stats.blank += 1,
            LineKind::Comment => stats.comments += 1,
            LineKind::Ignored => stats.ignored += 1,
            LineKind::Rules(n) => {
                stats.rules += n as u64;
                for r in rules.drain(..) {
                    sink(line_no, r);
                }
            }
            LineKind::Unsupported(reason) => {
                stats.unsupported += 1;
                sample(&mut stats, line_no, &text, reason, true);
            }
            LineKind::Invalid(reason) => {
                stats.invalid += 1;
                sample(&mut stats, line_no, &text, reason, false);
            }
        }
    }
    stats
}

fn sample(stats: &mut ParseStats, line: u32, text: &str, reason: String, unsupported: bool) {
    if stats
        .samples
        .iter()
        .filter(|s| s.unsupported == unsupported)
        .count()
        < MAX_SAMPLES
    {
        stats.samples.push(Sample {
            line,
            text: text.chars().take(200).collect(),
            reason,
            unsupported,
        });
    }
}

/// Parses one line, appending its rules to `out`.
pub fn parse_line(line: &str, opts: ListOptions, out: &mut Vec<Rule>) -> LineKind {
    let mut l = line.trim();
    if l.is_empty() {
        return LineKind::Blank;
    }
    if l.starts_with('#') || l.starts_with('!') || (l.starts_with('[') && l.ends_with(']')) {
        return LineKind::Comment;
    }
    let adblock_shaped = l.starts_with("@@") || l.starts_with('|') || l.starts_with('/');
    // Inline comments (`0.0.0.0 ads.example.com # tracker`); AdBlock lines have none, and a
    // quoted `$client` value may contain ` #`.
    if !adblock_shaped
        && let Some(i) = l
            .find([' ', '\t'])
            .and_then(|ws| l[ws..].find('#').map(|h| ws + h))
        && l[..i].ends_with([' ', '\t'])
    {
        l = l[..i].trim_end();
    }
    if ["##", "#@#", "#?#", "#$#", "#%#", "$$"]
        .iter()
        .any(|m| l.contains(m))
    {
        return LineKind::Unsupported("cosmetic or HTML filtering rule".into());
    }

    let mut tokens = l.split_whitespace();
    let first = tokens.next().unwrap_or_default();
    // Hosts files carry link-local entries with a zone (`fe80::1%lo0 localhost`).
    let addr = first.split_once('%').map_or(first, |(a, _)| a);
    if addr.parse::<IpAddr>().is_ok() {
        return hosts_line(tokens, opts, out);
    }
    if adblock_shaped || is_caret_rule(l) {
        return adblock(l, opts, out);
    }
    if l.contains(char::is_whitespace) {
        return LineKind::Invalid("unexpected whitespace".into());
    }
    if l.contains(['^', '$', '(', ')', '[', ']', '{', '}', '\\', '|', '+', '?'])
        || l.contains(";querytype=")
        || l.ends_with(";invert")
    {
        return pihole_regex(l, opts, out);
    }
    match domain_pattern(l, opts.plain_scope()) {
        Ok(pattern) => push(out, opts.action(), pattern, Modifiers::default()),
        Err(kind) => kind,
    }
}

/// `name^` or `name^$modifiers` without a leading `||` (AdGuard DNS syntax, ADR-017:
/// treated like `||name^`).
fn is_caret_rule(l: &str) -> bool {
    let Some(caret) = l.find('^') else {
        return false;
    };
    let rest = &l[caret + 1..];
    caret > 0
        && (rest.is_empty() || rest.starts_with('$') || rest == "|")
        && l[..caret].bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'*') || b >= 0x80
        })
}

fn push(out: &mut Vec<Rule>, action: Action, pattern: Pattern, modifiers: Modifiers) -> LineKind {
    out.push(Rule {
        action,
        pattern,
        modifiers,
    });
    LineKind::Rules(1)
}

fn hosts_line<'a>(
    names: impl Iterator<Item = &'a str>,
    opts: ListOptions,
    out: &mut Vec<Rule>,
) -> LineKind {
    let mut produced = 0;
    let mut seen = 0;
    let mut first_error = None;
    for raw in names {
        seen += 1;
        if name::is_hosts_boilerplate(&raw.to_ascii_lowercase()) {
            continue;
        }
        match normalize(raw) {
            Ok(n) if name::is_hosts_boilerplate(&n) => {}
            Ok(n) => {
                out.push(Rule {
                    action: opts.action(),
                    pattern: Pattern::Domain {
                        name: n,
                        scope: opts.plain_scope(),
                    },
                    modifiers: Modifiers::default(),
                });
                produced += 1;
            }
            Err(e) => {
                first_error.get_or_insert_with(|| format!("`{raw}`: {e}"));
            }
        }
    }
    match (produced, seen, first_error) {
        (0, 0, _) => LineKind::Unsupported("IP address without a name".into()),
        (0, _, Some(e)) => LineKind::Invalid(e),
        (0, _, None) => LineKind::Ignored,
        (n, _, _) => LineKind::Rules(n),
    }
}

/// `@@`, `||name^`, `|name^`, `/regex/`, `name^`, each with optional `$modifiers`.
fn adblock(l: &str, opts: ListOptions, out: &mut Vec<Rule>) -> LineKind {
    let (action, body) = match l.strip_prefix("@@") {
        Some(rest) => (Action::Allow, rest),
        None => (opts.action(), l),
    };
    // /regex/ or /regex/$modifiers
    if let Some(rest) = body.strip_prefix('/') {
        let (pattern, mods) = match rest.rfind("/$") {
            Some(i) => (&rest[..i], Some(&rest[i + 2..])),
            None => match rest.strip_suffix('/') {
                Some(p) => (p, None),
                None => return LineKind::Unsupported("URL path rule".into()),
            },
        };
        let modifiers = match mods.map(modifiers::parse).transpose() {
            Ok(m) => m.unwrap_or_default(),
            Err(e) => return modifier_error(e),
        };
        // Query names never contain `/`; such a "regex" is a URL rule (`/banner/ads/`).
        if pattern.contains('/') {
            return LineKind::Unsupported("URL path rule".into());
        }
        return regex_rule(pattern, false, action, modifiers, out);
    }
    let (pat, mods) = match body.split_once('$') {
        Some((p, m)) => (p, Some(m)),
        None => (body, None),
    };
    let modifiers = match mods.map(modifiers::parse).transpose() {
        Ok(m) => m.unwrap_or_default(),
        Err(e) => return modifier_error(e),
    };
    // Strip the separator / anchors: `||x^`, `||x^|`, `|x^`, `|x|`, `x^`.
    let (exact, name) = if let Some(n) = pat.strip_prefix("||") {
        (false, n)
    } else if let Some(n) = pat.strip_prefix('|') {
        (true, n)
    } else {
        (false, pat)
    };
    let name = name.strip_suffix('|').unwrap_or(name);
    let name = name.strip_suffix('^').unwrap_or(name);
    if name.is_empty() {
        return LineKind::Invalid("rule without a name".into());
    }
    let default = if exact { Scope::Exact } else { Scope::Subtree };
    match domain_pattern(name, default) {
        Ok(pattern) => {
            if !modifiers.denyallow.is_empty() && action == Action::Allow {
                return LineKind::Invalid("$denyallow only applies to blocking rules".into());
            }
            push(out, action, pattern, modifiers)
        }
        Err(kind) => kind,
    }
}

fn modifier_error((unsupported, reason): (bool, String)) -> LineKind {
    if unsupported {
        LineKind::Unsupported(reason)
    } else {
        LineKind::Invalid(reason)
    }
}

/// A name, `*.name`, or something URL- or wildcard-shaped we don't support.
fn domain_pattern(s: &str, default: Scope) -> Result<Pattern, LineKind> {
    // `*.name` and AdBlock's `.name` (any name ending in `.name`) both mean "below name".
    let (scope, name) = match s.strip_prefix("*.").or_else(|| s.strip_prefix('.')) {
        Some(rest) => (Scope::Subdomains, rest),
        None => (default, s),
    };
    if name.contains(['/', ':', '?', '=']) {
        return Err(LineKind::Unsupported(
            "URL rule (DNS filtering sees names only)".into(),
        ));
    }
    if name.contains('*') {
        return Err(LineKind::Unsupported("wildcard inside a name".into()));
    }
    // `||192.0.2.1^` filters answers containing that address (AdGuard semantics), which is
    // the response IP filter's job (FLT-015), not a name rule.
    if name
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .is_ok()
    {
        return Err(LineKind::Unsupported(
            "IP address rule (response IP filtering)".into(),
        ));
    }
    normalize(name)
        .map(|name| Pattern::Domain { name, scope })
        .map_err(|e| LineKind::Invalid(e.into()))
}

/// Pi-hole regex with `;querytype=A,AAAA` / `;querytype=!A` and `;invert` options.
fn pihole_regex(l: &str, opts: ListOptions, out: &mut Vec<Rule>) -> LineKind {
    let mut pattern = l;
    let mut invert = false;
    let mut modifiers = Modifiers::default();
    // Options are trailing `;key[=value]` segments; a `;` inside the regex stays.
    while let Some(i) = pattern.rfind(';') {
        let opt = &pattern[i + 1..];
        let (key, value) = opt.split_once('=').unwrap_or((opt, ""));
        if key.is_empty() || !key.bytes().all(|b| b.is_ascii_lowercase()) {
            break;
        }
        match key {
            "invert" if value.is_empty() => invert = true,
            "querytype" if !value.is_empty() => {
                let (negated, list) = value
                    .strip_prefix('!')
                    .map_or((false, value), |v| (true, v));
                for t in list.split(',') {
                    let Some(q) = telltale_proto::rtype::from_name(t) else {
                        return LineKind::Invalid(format!("unknown query type `{t}`"));
                    };
                    modifiers.dnstype.push(Negatable { value: q, negated });
                }
            }
            _ => {
                return LineKind::Unsupported(format!(
                    "Pi-hole regex option `;{key}` is not supported"
                ));
            }
        }
        pattern = &pattern[..i];
    }
    regex_rule(pattern, invert, opts.action(), modifiers, out)
}

fn regex_rule(
    pattern: &str,
    invert: bool,
    action: Action,
    modifiers: Modifiers,
    out: &mut Vec<Rule>,
) -> LineKind {
    if pattern.is_empty() {
        return LineKind::Invalid("empty regex".into());
    }
    if pattern.len() > 1024 {
        return LineKind::Invalid("regex longer than 1024 characters".into());
    }
    // REQ: FLT-003 / `05` §3.2 — reject what the linear-time engine can't compile
    // (backreferences, lookaround) here, so a bad pattern is reported against its line.
    if let Err(e) = regex_syntax::ParserBuilder::new()
        .case_insensitive(true)
        .build()
        .parse(pattern)
    {
        let msg = e.to_string();
        let last = msg.lines().last().unwrap_or("invalid regex").trim();
        let first = last.strip_prefix("error: ").unwrap_or(last);
        return LineKind::Invalid(format!("regex: {first}"));
    }
    push(
        out,
        action,
        Pattern::Regex {
            pattern: pattern.to_owned(),
            invert,
        },
        modifiers,
    )
}

impl fmt::Display for Rule {
    /// Canonical one-line form used by golden tests and `telltale lists check`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let action = match self.action {
            Action::Block => "block",
            Action::Allow => "allow",
        };
        match &self.pattern {
            Pattern::Domain { name, scope } => {
                let scope = match scope {
                    Scope::Subtree => "subtree",
                    Scope::Exact => "exact",
                    Scope::Subdomains => "subdomains",
                };
                write!(f, "{action} {scope} {name}")?;
            }
            Pattern::Regex { pattern, invert } => {
                let kind = if *invert { "regex-invert" } else { "regex" };
                write!(f, "{action} {kind} /{pattern}/")?;
            }
        }
        if !self.modifiers.is_empty() {
            write!(f, " ${}", self.modifiers)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
