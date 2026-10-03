//! Explain (FLT-013): every rule that matches a name, traced back to its list and line.
//!
//! Domain rules live in the snapshot only as names, so their lines are found by re-parsing
//! the stored source of each list that matched (`spec/05` §1 keeps sources for this).
//! Modifier and regex rules carry their line numbers. Allocates and reads files: never on
//! the query path.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::compile::is_plain;
use crate::fetch::content_hash;
use crate::matcher::{Match, Matcher, RuleRef, Tier};
use crate::parse::{Action, ListOptions, Pattern, Scope, parse_list};
use crate::snapshot::{ScopeTag, Snapshot};

/// One line of a list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleLine {
    /// 1-based, as an editor shows it.
    pub line: u32,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    /// A plain domain rule (`||ads.example.com^`, a hosts entry, a plain name).
    Domain,
    /// A domain rule with modifiers (`$client`, `$dnstype`, `$denyallow`).
    Modifier,
    Regex,
}

/// One matching rule, explained.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExplainedRule {
    pub list: String,
    pub list_id: u16,
    pub tier: Tier,
    pub kind: RuleKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,
    /// The listed name that matched (`example.com` for a query of `ads.example.com`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The client's groups use this list.
    pub enabled: bool,
    /// This rule decides the query (the first enabled rule in precedence order).
    pub winner: bool,
    /// A manual rule (overlay), not from a compiled list.
    pub manual: bool,
    /// Where the rule is (several if the list repeats it). Empty if the source isn't stored.
    pub lines: Vec<RuleLine>,
}

/// Every rule matching a query, in precedence order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Explained {
    /// The snapshot version the rules came from (`None` without a snapshot).
    pub snapshot: Option<u64>,
    pub rules: Vec<ExplainedRule>,
    /// Caveats, such as a list whose source changed after the snapshot was compiled.
    pub notes: Vec<String>,
}

/// Longest line text returned (a pathological list shouldn't bloat an explain response).
const MAX_LINE_TEXT: usize = 500;

/// Explains `matches` (from [`Matcher::matches`] for `qname`, wire format), reading list
/// sources through `source(list name)`.
pub fn explain(
    m: &Matcher,
    qname: &[u8],
    matches: &[Match],
    source: impl Fn(&str) -> Option<Vec<u8>>,
) -> Explained {
    let snap = m.snapshot();
    let labels = wire_labels(qname);
    let winner = matches.iter().position(|x| x.enabled);
    let mut out = Explained {
        snapshot: snap.map(|s| s.manifest.version),
        ..Explained::default()
    };
    let mut wanted = Wanted::default();
    for (i, x) in matches.iter().enumerate() {
        let a = x.attribution;
        let list = if a.overlay {
            "manual".to_owned()
        } else {
            snap.and_then(|s| s.list_name(a.list))
                .map_or_else(|| format!("#{}", a.list), str::to_owned)
        };
        let mut rule = ExplainedRule {
            list,
            list_id: a.list,
            tier: a.tier,
            kind: RuleKind::Domain,
            scope: None,
            name: None,
            enabled: x.enabled,
            winner: winner == Some(i),
            manual: a.overlay,
            lines: Vec::new(),
        };
        match a.rule {
            RuleRef::Domain { scope, labels: n } => {
                let name = suffix(&labels, usize::from(n));
                rule.scope = Some(scope);
                if !a.overlay {
                    wanted.domains.entry(a.list).or_default().push((
                        i,
                        name.clone(),
                        scope,
                        a.tier,
                    ));
                }
                rule.name = Some(name);
            }
            RuleRef::ModRule { index } => {
                rule.kind = RuleKind::Modifier;
                if !a.overlay
                    && let Some(r) = snap.and_then(|s| s.modrules.get(index as usize))
                {
                    rule.scope = Some(match r.scope {
                        ScopeTag::Subtree => Scope::Subtree,
                        ScopeTag::Exact => Scope::Exact,
                        ScopeTag::Subdomains => Scope::Subdomains,
                    });
                    wanted.known.entry(a.list).or_default().push((i, r.line));
                }
            }
            RuleRef::Regex { index } => {
                rule.kind = RuleKind::Regex;
                if !a.overlay
                    && let Some(r) = snap.and_then(|s| s.regexes.get(index as usize))
                {
                    wanted.known.entry(a.list).or_default().push((i, r.line));
                }
            }
        }
        out.rules.push(rule);
    }
    if let Some(snap) = snap {
        attach_lines(snap, wanted, &source, &mut out);
    }
    out
}

/// Rules to find in each list's source, by index into the explained rules.
#[derive(Default)]
struct Wanted {
    /// Plain domain rules: found by parsing the list.
    domains: BTreeMap<u16, Vec<(usize, String, Scope, Tier)>>,
    /// Modifier and regex rules: their line numbers are in the snapshot.
    known: BTreeMap<u16, Vec<(usize, u32)>>,
}

/// Fills in each rule's lines from the stored list sources.
fn attach_lines(
    snap: &Snapshot,
    mut wanted: Wanted,
    source: &impl Fn(&str) -> Option<Vec<u8>>,
    out: &mut Explained,
) {
    let lists: BTreeSet<u16> = wanted
        .domains
        .keys()
        .chain(wanted.known.keys())
        .copied()
        .collect();
    for id in lists {
        let Some(meta) = snap.manifest.lists.get(usize::from(id)) else {
            continue;
        };
        let Some(src) = source(&meta.name) else {
            out.notes.push(format!(
                "the source of list {} isn't stored, so its line numbers are unavailable",
                meta.name
            ));
            continue;
        };
        if content_hash(&src) != meta.source_hash {
            out.notes.push(format!(
                "list {} changed after snapshot {} was compiled; its line numbers refer to the newer copy",
                meta.name, snap.manifest.version
            ));
        }
        // Rule index → line numbers in this list.
        let mut found: Vec<(usize, u32)> = wanted.known.remove(&id).unwrap_or_default();
        if let Some(domains) = wanted.domains.get(&id) {
            let options = ListOptions {
                kind: meta.kind,
                match_mode: meta.match_mode,
            };
            parse_list(&src, options, |line, rule| {
                let Pattern::Domain { name, scope } = &rule.pattern else {
                    return;
                };
                if rule.modifiers.badfilter || !is_plain(&rule.modifiers) {
                    return;
                }
                let tier = Tier::of(rule.action == Action::Allow, rule.modifiers.important);
                for (i, n, s, t) in domains {
                    if n == name && s == scope && *t == tier {
                        found.push((*i, line));
                    }
                }
            });
        }
        let texts = line_texts(&src, &found.iter().map(|(_, l)| *l).collect());
        for (i, line) in found {
            if let Some(r) = out.rules.get_mut(i) {
                r.lines.push(RuleLine {
                    line,
                    text: texts.get(&line).cloned().unwrap_or_default(),
                });
            }
        }
    }
    for r in &mut out.rules {
        r.lines.sort_by_key(|l| l.line);
        r.lines.dedup_by_key(|l| l.line);
    }
}

/// Lowercase labels of a wire-format name.
fn wire_labels(wire: &[u8]) -> Vec<String> {
    let mut labels = Vec::new();
    let mut pos = 0;
    while let Some(&len) = wire.get(pos) {
        let len = usize::from(len);
        if len == 0 {
            break;
        }
        let Some(label) = wire.get(pos + 1..pos + 1 + len) else {
            break;
        };
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        pos += 1 + len;
    }
    labels
}

/// The last `n` labels, dotted.
fn suffix(labels: &[String], n: usize) -> String {
    labels[labels.len().saturating_sub(n)..].join(".")
}

/// The text of the given 1-based lines, numbered the way [`parse_list`] numbers them.
fn line_texts(src: &[u8], wanted: &BTreeSet<u32>) -> BTreeMap<u32, String> {
    let data = src.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(src);
    let mut out = BTreeMap::new();
    let Some(&last) = wanted.last() else {
        return out;
    };
    for (i, raw) in data.split(|&b| b == b'\n').enumerate() {
        let no = u32::try_from(i + 1).unwrap_or(u32::MAX);
        if no > last {
            break;
        }
        if wanted.contains(&no) {
            let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
            let text: String = String::from_utf8_lossy(raw)
                .chars()
                .take(MAX_LINE_TEXT)
                .collect();
            out.insert(no, text);
        }
    }
    out
}

#[cfg(test)]
mod tests;
