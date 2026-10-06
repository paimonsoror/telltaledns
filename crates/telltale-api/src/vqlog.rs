//! REQ: AGT-012 (T8.4, ADR-082) — `vqlog`, a small analytics language over the query log:
//! filter, group by, top-K, percentiles, and time buckets, with a cost estimate, so an agent
//! (or a person) asks one tool instead of many narrow ones. It is parsed into a fixed plan;
//! there's no SQL, no expressions, nothing that runs code. The binary executes plans.
//!
//! ```text
//! from -24h | where status = blocked and group = kids | top 10 name
//! from -7d | where client = 192.168.1.20 | bucket 1h | stats count, p95(latency)
//! where name under roku.com | by client | stats count, distinct(name) | sort count desc | limit 20
//! from -1d | where status = blocked and (client = 192.168.1.20 or name under roku.com) | top 10 name
//! ```
//!
//! Stages, separated by `|`, each at most once except `where` (they combine with `and`):
//! - `from TIME [to TIME]` — `-24h`, `-7d`, `-30m`, or RFC 3339. Default: the last 24 hours.
//! - `where COND [and COND]...` — `FIELD OP VALUE`, and (T9.12) `or`: `and` binds tighter,
//!   and a parenthesized group (`(A or B and C)`, one level) is one term of the `and` list.
//!   A bare `or` makes the whole stage one group. Fields: `name`, `client`, `group`,
//!   `status`, `qtype`, `rcode`, `upstream`, `proto`, `latency`, `upstream_latency` (ms).
//!   Ops: `=`, `!=`, `in (a, b)`, `not in (a, b)`; for `name` also `~` (glob, `*` and `?`),
//!   `has` (substring), and `under` (the name or below it); for `client` a value can be a
//!   CIDR; for latencies `>`, `>=`, `<`, `<=`.
//! - `bucket DURATION` — time buckets (`5m`, `1h`, `1d`) as the first column.
//! - `by KEY[, KEY]...` (or `group by`) — keys: `name`, `domain` (registrable), `client`,
//!   `group`, `status`, `qtype`, `rcode`, `upstream`, `proto`.
//! - `stats AGG[, AGG]...` — `count`, `distinct(KEY)`, `avg(M)`, `min(M)`, `max(M)`,
//!   `p50(M)`, `p90(M)`, `p95(M)`, `p99(M)`; `M` is `latency`, `upstream_latency`, `answers`,
//!   or `bytes`. Default: `count`.
//! - `top N KEY` — shorthand for `by KEY | stats count | sort count desc | limit N`.
//! - `sort COLUMN [asc|desc]` — by an aggregate or a key. Default: time for buckets, else the
//!   first aggregate, descending.
//! - `limit N` — rows returned (default 50, at most 200).

use std::fmt;

/// Rows returned at most (AGT-009).
pub const MAX_LIMIT: usize = 200;
const DEFAULT_LIMIT: usize = 50;
/// The longest query accepted.
pub const MAX_QUERY_LEN: usize = 2000;

/// A grouping key (and a `distinct` target).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Key {
    Name,
    Domain,
    Client,
    Group,
    Status,
    Qtype,
    Rcode,
    Upstream,
    Proto,
}

impl Key {
    pub const ALL: [Self; 9] = [
        Self::Name,
        Self::Domain,
        Self::Client,
        Self::Group,
        Self::Status,
        Self::Qtype,
        Self::Rcode,
        Self::Upstream,
        Self::Proto,
    ];
    pub const fn label(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Domain => "domain",
            Self::Client => "client",
            Self::Group => "group",
            Self::Status => "status",
            Self::Qtype => "qtype",
            Self::Rcode => "rcode",
            Self::Upstream => "upstream",
            Self::Proto => "proto",
        }
    }
    fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.label() == s)
    }
}

/// A per-query number to aggregate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Metric {
    /// Total time, ms.
    Latency,
    /// Time waiting for the upstream, ms.
    UpstreamLatency,
    Answers,
    /// Response size.
    Bytes,
}

impl Metric {
    const ALL: [Self; 4] = [
        Self::Latency,
        Self::UpstreamLatency,
        Self::Answers,
        Self::Bytes,
    ];
    pub const fn label(self) -> &'static str {
        match self {
            Self::Latency => "latency",
            Self::UpstreamLatency => "upstream_latency",
            Self::Answers => "answers",
            Self::Bytes => "bytes",
        }
    }
    fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|m| m.label() == s)
    }
}

/// An aggregate column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Agg {
    Count,
    Distinct(Key),
    Avg(Metric),
    Min(Metric),
    Max(Metric),
    /// Percentile (50, 90, 95, 99).
    Pct(u8, Metric),
}

impl fmt::Display for Agg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Count => f.write_str("count"),
            Self::Distinct(k) => write!(f, "distinct({})", k.label()),
            Self::Avg(m) => write!(f, "avg({})", m.label()),
            Self::Min(m) => write!(f, "min({})", m.label()),
            Self::Max(m) => write!(f, "max({})", m.label()),
            Self::Pct(p, m) => write!(f, "p{p}({})", m.label()),
        }
    }
}

/// A `where` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Name,
    Client,
    Group,
    Status,
    Qtype,
    Rcode,
    Upstream,
    Proto,
    Latency,
    UpstreamLatency,
}

impl Field {
    const ALL: [Self; 10] = [
        Self::Name,
        Self::Client,
        Self::Group,
        Self::Status,
        Self::Qtype,
        Self::Rcode,
        Self::Upstream,
        Self::Proto,
        Self::Latency,
        Self::UpstreamLatency,
    ];
    pub const fn label(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Client => "client",
            Self::Group => "group",
            Self::Status => "status",
            Self::Qtype => "qtype",
            Self::Rcode => "rcode",
            Self::Upstream => "upstream",
            Self::Proto => "proto",
            Self::Latency => "latency",
            Self::UpstreamLatency => "upstream_latency",
        }
    }
    fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|f| f.label() == s)
    }
    const fn numeric(self) -> bool {
        matches!(self, Self::Latency | Self::UpstreamLatency)
    }
}

/// A comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
    In,
    NotIn,
    /// Glob (`*`, `?`), names only.
    Glob,
    /// Substring, names only.
    Has,
    /// The name or a name below it.
    Under,
    Gt,
    Ge,
    Lt,
    Le,
}

impl Op {
    const fn text(self) -> &'static str {
        match self {
            Self::Eq => "=",
            Self::Ne => "!=",
            Self::In => "in",
            Self::NotIn => "not in",
            Self::Glob => "~",
            Self::Has => "has",
            Self::Under => "under",
            Self::Gt => ">",
            Self::Ge => ">=",
            Self::Lt => "<",
            Self::Le => "<=",
        }
    }
    /// Whether a row matching the condition must equal (one of) the values.
    pub const fn positive(self) -> bool {
        !matches!(self, Self::Ne | Self::NotIn)
    }
}

/// One `where` condition.
#[derive(Debug, Clone, PartialEq)]
pub struct Cond {
    pub field: Field,
    pub op: Op,
    pub values: Vec<String>,
}

/// A parsed query.
#[derive(Debug, Clone, PartialEq)]
pub struct Query {
    pub from: Option<String>,
    pub to: Option<String>,
    /// Conditions every row meets.
    pub conds: Vec<Cond>,
    /// REQ: AGT-012 (T9.12) — `or` groups every row also meets: each a list of alternatives,
    /// an alternative a list of conditions that all hold.
    pub any_of: Vec<Vec<Vec<Cond>>>,
    pub bucket_secs: Option<u64>,
    pub keys: Vec<Key>,
    pub aggs: Vec<Agg>,
    /// A column name and whether descending.
    pub sort: Option<(String, bool)>,
    pub limit: usize,
}

impl Query {
    /// The output columns before labels: `time` (with a bucket), the keys, the aggregates.
    pub fn columns(&self) -> Vec<String> {
        let mut c = Vec::new();
        if self.bucket_secs.is_some() {
            c.push("time".to_owned());
        }
        c.extend(self.keys.iter().map(|k| k.label().to_owned()));
        c.extend(self.aggs.iter().map(ToString::to_string));
        c
    }

    /// The sort column and direction, with the defaults applied.
    pub fn sort_by(&self) -> (String, bool) {
        if let Some(s) = &self.sort {
            return s.clone();
        }
        if self.bucket_secs.is_some() {
            return ("time".to_owned(), false);
        }
        (
            self.aggs
                .first()
                .map_or_else(|| "count".to_owned(), ToString::to_string),
            true,
        )
    }
}

fn dur_text(s: u64) -> String {
    if s.is_multiple_of(86_400) {
        format!("{}d", s / 86_400)
    } else if s.is_multiple_of(3600) {
        format!("{}h", s / 3600)
    } else if s.is_multiple_of(60) {
        format!("{}m", s / 60)
    } else {
        format!("{s}s")
    }
}

fn quote(v: &str) -> String {
    if !v.is_empty() && v.chars().all(word_char) {
        v.to_owned()
    } else {
        format!("\"{}\"", v.replace('"', ""))
    }
}

/// The normalized form (defaults filled in), so a caller sees how it was understood.
impl fmt::Display for Query {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "from {}", self.from.as_deref().unwrap_or("-24h"))?;
        if let Some(t) = &self.to {
            write!(f, " to {t}")?;
        }
        let mut terms: Vec<String> = self.conds.iter().map(cond_text).collect();
        for g in &self.any_of {
            let alts: Vec<String> = g
                .iter()
                .map(|a| a.iter().map(cond_text).collect::<Vec<_>>().join(" and "))
                .collect();
            terms.push(format!("({})", alts.join(" or ")));
        }
        if !terms.is_empty() {
            write!(f, " | where {}", terms.join(" and "))?;
        }
        if let Some(b) = self.bucket_secs {
            write!(f, " | bucket {}", dur_text(b))?;
        }
        if !self.keys.is_empty() {
            let k: Vec<&str> = self.keys.iter().map(|k| k.label()).collect();
            write!(f, " | by {}", k.join(", "))?;
        }
        let a: Vec<String> = self.aggs.iter().map(ToString::to_string).collect();
        write!(f, " | stats {}", a.join(", "))?;
        let (col, desc) = self.sort_by();
        write!(f, " | sort {col} {}", if desc { "desc" } else { "asc" })?;
        write!(f, " | limit {}", self.limit)
    }
}

fn cond_text(c: &Cond) -> String {
    let v = if matches!(c.op, Op::In | Op::NotIn) {
        let vs: Vec<String> = c.values.iter().map(|v| quote(v)).collect();
        format!("({})", vs.join(", "))
    } else {
        c.values.first().map(|v| quote(v)).unwrap_or_default()
    };
    format!("{} {} {v}", c.field.label(), c.op.text())
}

/// A parse error, with what to do about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub message: String,
    pub hint: String,
}

fn err<T>(message: impl Into<String>, hint: impl Into<String>) -> Result<T, Error> {
    Err(Error {
        message: message.into(),
        hint: hint.into(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Word(String),
    Str(String),
    Sym(&'static str),
}

fn word_char(c: char) -> bool {
    !c.is_whitespace() && !"|(),=!~<>\"".contains(c)
}

fn lex(s: &str) -> Result<Vec<Tok>, Error> {
    let mut out = Vec::new();
    let mut it = s.char_indices().peekable();
    while let Some(&(i, c)) = it.peek() {
        if c.is_whitespace() {
            it.next();
            continue;
        }
        if c == '"' {
            it.next();
            let mut v = String::new();
            loop {
                match it.next() {
                    Some((_, '"')) => break,
                    Some((_, ch)) => v.push(ch),
                    None => return err(format!("unclosed quote at {i}"), "Close the \"…\"."),
                }
            }
            out.push(Tok::Str(v));
            continue;
        }
        let two = s.get(i..i + 2);
        let sym = match two {
            Some("!=") => Some("!="),
            Some(">=") => Some(">="),
            Some("<=") => Some("<="),
            _ => None,
        };
        if let Some(sym) = sym {
            it.next();
            it.next();
            out.push(Tok::Sym(sym));
            continue;
        }
        let one = match c {
            '|' => Some("|"),
            '(' => Some("("),
            ')' => Some(")"),
            ',' => Some(","),
            '=' => Some("="),
            '~' => Some("~"),
            '<' => Some("<"),
            '>' => Some(">"),
            _ => None,
        };
        if let Some(sym) = one {
            it.next();
            out.push(Tok::Sym(sym));
            continue;
        }
        if !word_char(c) {
            return err(
                format!("unexpected `{c}` at {i}"),
                "Quote values with \"…\".",
            );
        }
        let mut w = String::new();
        while let Some(&(_, ch)) = it.peek() {
            if !word_char(ch) {
                break;
            }
            w.push(ch);
            it.next();
        }
        out.push(Tok::Word(w));
    }
    Ok(out)
}

/// `5m`, `1h`, `2d`, `30s` → seconds.
pub fn parse_duration(s: &str) -> Option<u64> {
    let (n, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit())?);
    let n: u64 = n.parse().ok()?;
    let mul = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => return None,
    };
    n.checked_mul(mul).filter(|&v| v > 0)
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }
    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        self.pos += 1;
        t
    }
    fn sym(&mut self, s: &str) -> bool {
        if self.peek()
            == Some(&Tok::Sym(match s {
                "(" => "(",
                ")" => ")",
                "," => ",",
                "|" => "|",
                _ => return false,
            }))
        {
            self.pos += 1;
            return true;
        }
        false
    }
    /// A keyword (case-insensitive bare word).
    fn kw(&mut self, k: &str) -> bool {
        if let Some(Tok::Word(w)) = self.peek()
            && w.eq_ignore_ascii_case(k)
        {
            self.pos += 1;
            return true;
        }
        false
    }
    fn word(&mut self, what: &str) -> Result<String, Error> {
        match self.next() {
            Some(Tok::Word(w)) => Ok(w.to_ascii_lowercase()),
            other => err(
                format!("expected {what}, found {}", show(other.as_ref())),
                "",
            ),
        }
    }
    fn value(&mut self) -> Result<String, Error> {
        match self.next() {
            Some(Tok::Word(w) | Tok::Str(w)) => Ok(w),
            other => err(
                format!("expected a value, found {}", show(other.as_ref())),
                "Quote values with \"…\".",
            ),
        }
    }
    fn number(&mut self, what: &str) -> Result<usize, Error> {
        let w = self.word(what)?;
        w.parse()
            .or_else(|_| err(format!("{what}: `{w}` is not a number"), ""))
    }
    fn at_stage_end(&self) -> bool {
        matches!(self.peek(), None | Some(Tok::Sym("|")))
    }
}

fn show(t: Option<&Tok>) -> String {
    match t {
        None => "the end".to_owned(),
        Some(Tok::Word(w)) => format!("`{w}`"),
        Some(Tok::Str(s)) => format!("\"{s}\""),
        Some(Tok::Sym(s)) => format!("`{s}`"),
    }
}

const STAGES: &str = "Stages: from, where, bucket, by, stats, top, sort, limit (separated by |).";

/// Parses a query.
#[allow(clippy::too_many_lines)] // one arm per stage
pub fn parse(text: &str) -> Result<Query, Error> {
    if text.len() > MAX_QUERY_LEN {
        return err(
            "the query is too long",
            format!("At most {MAX_QUERY_LEN} characters."),
        );
    }
    let mut p = Parser {
        toks: lex(text)?,
        pos: 0,
    };
    let mut q = Query {
        from: None,
        to: None,
        conds: Vec::new(),
        any_of: Vec::new(),
        bucket_secs: None,
        keys: Vec::new(),
        aggs: Vec::new(),
        sort: None,
        limit: DEFAULT_LIMIT,
    };
    let mut seen: Vec<String> = Vec::new();
    let mut top = false;
    while p.peek().is_some() {
        let stage = p.word("a stage")?;
        if stage != "where" && seen.contains(&stage) {
            return err(format!("`{stage}` appears twice"), STAGES);
        }
        seen.push(stage.clone());
        match stage.as_str() {
            "from" => {
                q.from = Some(p.value()?);
                if p.kw("to") {
                    q.to = Some(p.value()?);
                }
            }
            "where" => where_stage(&mut p, &mut q)?,
            "bucket" => {
                let w = p.word("a duration")?;
                q.bucket_secs = Some(parse_duration(&w).ok_or_else(|| Error {
                    message: format!("bucket: `{w}` is not a duration"),
                    hint: "Use 5m, 1h, 1d.".to_owned(),
                })?);
            }
            "group" | "by" => {
                if stage == "group" && !p.kw("by") {
                    return err("expected `by` after `group`", "group by client, status");
                }
                if seen.iter().filter(|s| *s == "group" || *s == "by").count() > 1 || top {
                    return err("grouping appears twice", STAGES);
                }
                q.keys = keys(&mut p)?;
            }
            "stats" => {
                if top {
                    return err(
                        "`top` already sets the statistics",
                        "Use `by KEY | stats …` instead of top.",
                    );
                }
                loop {
                    q.aggs.push(agg(&mut p)?);
                    if !p.sym(",") {
                        break;
                    }
                }
            }
            "top" => {
                if !q.keys.is_empty() || !q.aggs.is_empty() {
                    return err(
                        "`top` sets the grouping and statistics itself",
                        "Use top alone, or `by` and `stats`.",
                    );
                }
                top = true;
                q.limit = p.number("top")?;
                q.keys = keys(&mut p)?;
                q.aggs = vec![Agg::Count];
                q.sort = Some(("count".to_owned(), true));
            }
            "sort" => {
                let mut col = p.word("a column")?;
                // An aggregate column: `p95(latency)`.
                if p.sym("(") {
                    let arg = p.word("an argument")?;
                    if !p.sym(")") {
                        return err(format!("expected `)` after {col}({arg}"), "");
                    }
                    col = format!("{col}({arg})");
                }
                let desc = if p.kw("asc") {
                    false
                } else {
                    p.kw("desc");
                    true
                };
                q.sort = Some((col, desc));
            }
            "limit" => q.limit = p.number("limit")?,
            other => return err(format!("unknown stage `{other}`"), STAGES),
        }
        if !p.at_stage_end() {
            return err(
                format!("unexpected {} in `{stage}`", show(p.peek())),
                STAGES,
            );
        }
        p.sym("|");
    }
    if q.aggs.is_empty() {
        q.aggs.push(Agg::Count);
    }
    if q.limit == 0 || q.limit > MAX_LIMIT {
        return err(
            format!("limit {} is out of range", q.limit),
            format!("1 to {MAX_LIMIT}."),
        );
    }
    let cols = q.columns();
    if let Some((c, _)) = &q.sort
        && !cols.contains(c)
    {
        return err(
            format!("sort: no column `{c}`"),
            format!("Columns: {}.", cols.join(", ")),
        );
    }
    Ok(q)
}

fn keys(p: &mut Parser) -> Result<Vec<Key>, Error> {
    let mut v = Vec::new();
    loop {
        let w = p.word("a key")?;
        let k = Key::parse(&w).ok_or_else(|| Error {
            message: format!("unknown key `{w}`"),
            hint: format!("Keys: {}.", Key::ALL.map(Key::label).join(", ")),
        })?;
        if !v.contains(&k) {
            v.push(k);
        }
        if !p.sym(",") {
            break;
        }
    }
    if v.len() > 3 {
        return err("at most three keys", "Group by fewer keys.");
    }
    Ok(v)
}

fn agg(p: &mut Parser) -> Result<Agg, Error> {
    let f = p.word("a statistic")?;
    if f == "count" {
        if p.sym("(") && !p.sym(")") {
            return err("count takes nothing", "count");
        }
        return Ok(Agg::Count);
    }
    if !p.sym("(") {
        return err(
            format!("`{f}` needs an argument"),
            "For example p95(latency) or distinct(client).",
        );
    }
    let arg = p.word("an argument")?;
    if !p.sym(")") {
        return err(format!("expected `)` after {f}({arg}"), "");
    }
    let metric = || {
        Metric::parse(&arg).ok_or_else(|| Error {
            message: format!("{f}: unknown measure `{arg}`"),
            hint: format!("Measures: {}.", Metric::ALL.map(Metric::label).join(", ")),
        })
    };
    Ok(match f.as_str() {
        "distinct" => Agg::Distinct(Key::parse(&arg).ok_or_else(|| Error {
            message: format!("distinct: unknown key `{arg}`"),
            hint: format!("Keys: {}.", Key::ALL.map(Key::label).join(", ")),
        })?),
        "avg" => Agg::Avg(metric()?),
        "min" => Agg::Min(metric()?),
        "max" => Agg::Max(metric()?),
        "p50" => Agg::Pct(50, metric()?),
        "p90" => Agg::Pct(90, metric()?),
        "p95" => Agg::Pct(95, metric()?),
        "p99" => Agg::Pct(99, metric()?),
        _ => {
            return err(
                format!("unknown statistic `{f}`"),
                "Statistics: count, distinct(KEY), avg, min, max, p50, p90, p95, p99 (of a measure).",
            );
        }
    })
}

/// One term of a `where` list: a condition, or a parenthesized `or` group.
enum Term {
    Cond(Cond),
    Group(Vec<Vec<Cond>>),
}

/// The most alternatives in all `or` groups of a query.
const MAX_ALTERNATIVES: usize = 32;

/// REQ: AGT-012 (T9.12) — `COND (and|or) …`, `and` binding tighter, with `( … )` groups one
/// level deep.
fn where_stage(p: &mut Parser, q: &mut Query) -> Result<(), Error> {
    let mut terms = Vec::new();
    // Before each term after the first: whether `or` joined it.
    let mut ors = Vec::new();
    loop {
        if p.sym("(") {
            terms.push(Term::Group(or_group(p)?));
            if !p.sym(")") {
                return err(
                    "expected `)` to close the group",
                    "(client = 10.0.0.5 or name under roku.com)",
                );
            }
        } else {
            terms.push(Term::Cond(cond(p)?));
        }
        if p.kw("or") {
            ors.push(true);
        } else if p.kw("and") {
            ors.push(false);
        } else {
            break;
        }
    }
    if ors.contains(&true) {
        // A bare `or`: the whole stage is one group, of plain conditions only.
        let mut alts = vec![Vec::new()];
        for (i, t) in terms.into_iter().enumerate() {
            let Term::Cond(c) = t else {
                return err(
                    "`or` next to a parenthesized group is ambiguous",
                    "Put the `or` inside the parentheses: status = blocked and (client = a or name under b)",
                );
            };
            if i > 0 && ors.get(i - 1) == Some(&true) {
                alts.push(Vec::new());
            }
            if let Some(last) = alts.last_mut() {
                last.push(c);
            }
        }
        terms = vec![Term::Group(alts)];
    }
    for t in terms {
        match t {
            Term::Cond(c) => q.conds.push(c),
            Term::Group(mut g) if g.len() == 1 => q.conds.append(&mut g[0]),
            Term::Group(g) => q.any_of.push(g),
        }
    }
    if q.any_of.iter().map(Vec::len).sum::<usize>() > MAX_ALTERNATIVES {
        return err(
            format!("at most {MAX_ALTERNATIVES} alternatives in `or` groups"),
            "Use `in (a, b, …)` for many values of one field.",
        );
    }
    Ok(())
}

/// The inside of `( … )`: conditions joined by `and` and `or`.
fn or_group(p: &mut Parser) -> Result<Vec<Vec<Cond>>, Error> {
    let mut alts = vec![Vec::new()];
    loop {
        if matches!(p.peek(), Some(Tok::Sym("("))) {
            return err(
                "only one level of parentheses",
                "status = blocked and (client = a or name under b)",
            );
        }
        if let Some(last) = alts.last_mut() {
            last.push(cond(p)?);
        }
        if p.kw("or") {
            alts.push(Vec::new());
        } else if !p.kw("and") {
            return Ok(alts);
        }
    }
}

fn cond(p: &mut Parser) -> Result<Cond, Error> {
    let w = p.word("a field")?;
    let field = Field::parse(&w).ok_or_else(|| Error {
        message: format!("unknown field `{w}`"),
        hint: format!("Fields: {}.", Field::ALL.map(Field::label).join(", ")),
    })?;
    let op = match p.next() {
        Some(Tok::Sym("=")) => Op::Eq,
        Some(Tok::Sym("!=")) => Op::Ne,
        Some(Tok::Sym("~")) => Op::Glob,
        Some(Tok::Sym(">")) => Op::Gt,
        Some(Tok::Sym(">=")) => Op::Ge,
        Some(Tok::Sym("<")) => Op::Lt,
        Some(Tok::Sym("<=")) => Op::Le,
        Some(Tok::Word(o)) if o.eq_ignore_ascii_case("in") => Op::In,
        Some(Tok::Word(o)) if o.eq_ignore_ascii_case("has") => Op::Has,
        Some(Tok::Word(o)) if o.eq_ignore_ascii_case("under") => Op::Under,
        Some(Tok::Word(o)) if o.eq_ignore_ascii_case("not") => {
            if !p.kw("in") {
                return err("expected `in` after `not`", "status not in (cached, local)");
            }
            Op::NotIn
        }
        other => {
            return err(
                format!(
                    "expected an operator after `{w}`, found {}",
                    show(other.as_ref())
                ),
                "Operators: =, !=, in (…), not in (…), ~, has, under, >, >=, <, <=.",
            );
        }
    };
    let name_only = matches!(op, Op::Glob | Op::Has | Op::Under);
    let numeric_only = matches!(op, Op::Gt | Op::Ge | Op::Lt | Op::Le);
    if name_only && field != Field::Name {
        return err(
            format!("`{}` only applies to name", op.text()),
            "name ~ \"*.example.com\"",
        );
    }
    if numeric_only != field.numeric() {
        return err(
            format!("`{} {}` isn't supported", field.label(), op.text()),
            "Latencies compare with >, >=, <, <= (ms); other fields with =, !=, in, not in.",
        );
    }
    let values = if matches!(op, Op::In | Op::NotIn) {
        if !p.sym("(") {
            return err("expected `(` after in", "status in (blocked, refused)");
        }
        let mut v = Vec::new();
        loop {
            v.push(p.value()?);
            if !p.sym(",") {
                break;
            }
        }
        if !p.sym(")") {
            return err("expected `)` to close the list", "");
        }
        v
    } else {
        vec![p.value()?]
    };
    if field.numeric() && values[0].parse::<f64>().is_err() {
        return err(
            format!("{}: `{}` is not a number of ms", field.label(), values[0]),
            "latency > 100",
        );
    }
    if values.len() > 64 {
        return err("at most 64 values in a list", "");
    }
    Ok(Cond { field, op, values })
}

/// Does `name` match glob `pat` (`*` any run, `?` one character)? Both lowercase.
pub fn glob_match(pat: &str, name: &str) -> bool {
    let (p, n): (Vec<char>, Vec<char>) = (pat.chars().collect(), name.chars().collect());
    let (mut pi, mut ni) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ni;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ni = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: AGT-012 — the documented forms parse, and the normalized text shows the defaults.
    #[test]
    fn agt_012_parse() {
        let q = parse("from -24h | where status = blocked and group = kids | top 10 name").unwrap();
        assert_eq!(q.keys, vec![Key::Name]);
        assert_eq!(q.aggs, vec![Agg::Count]);
        assert_eq!(q.limit, 10);
        assert_eq!(
            q.to_string(),
            "from -24h | where status = blocked and group = kids | by name | stats count | sort count desc | limit 10"
        );
        let q =
            parse("where client = 192.168.1.20 | bucket 1h | stats count, p95(latency)").unwrap();
        assert_eq!(q.bucket_secs, Some(3600));
        assert_eq!(q.aggs, vec![Agg::Count, Agg::Pct(95, Metric::Latency)]);
        assert_eq!(q.sort_by(), ("time".to_owned(), false));
        assert_eq!(q.columns(), vec!["time", "count", "p95(latency)"]);
        let q = parse(
            r#"WHERE name ~ "*.roku.com" and status not in (cached, local) and latency >= 100 | group by client, status | stats distinct(name) | sort distinct(name) asc | limit 5"#,
        )
        .unwrap();
        assert_eq!(q.conds.len(), 3);
        assert_eq!(q.conds[1].op, Op::NotIn);
        assert_eq!(q.conds[1].values, vec!["cached", "local"]);
        assert_eq!(q.sort, Some(("distinct(name)".to_owned(), false)));
        assert_eq!(
            parse("").unwrap().to_string(),
            "from -24h | stats count | sort count desc | limit 50"
        );
    }

    /// REQ: AGT-012 (T9.12) — `or`: `and` binds tighter; a group is one term; a group of
    /// one alternative is plain conditions; the normalized text parses back the same.
    #[test]
    fn agt_012_parse_or() {
        let q = parse(
            "where status = blocked and (client = 10.0.0.5 or name under roku.com and qtype = A)",
        )
        .unwrap();
        assert_eq!(q.conds.len(), 1);
        assert_eq!(q.any_of.len(), 1);
        assert_eq!(q.any_of[0].len(), 2);
        assert_eq!(q.any_of[0][1].len(), 2);
        let text = q.to_string();
        assert!(
            text.starts_with("from -24h | where status = blocked and (client = 10.0.0.5 or name under roku.com and qtype = A) |"),
            "{text}"
        );
        assert_eq!(parse(&text).unwrap().to_string(), text);
        let q = parse("where client = 10.0.0.5 or status = blocked and group = kids").unwrap();
        assert_eq!(q.conds.len(), 0);
        assert_eq!(q.any_of[0].len(), 2);
        assert_eq!(q.any_of[0][1].len(), 2);
        assert_eq!(parse(&q.to_string()).unwrap().any_of, q.any_of);
        let q = parse("where (status = blocked and group = kids)").unwrap();
        assert_eq!((q.conds.len(), q.any_of.len()), (2, 0));
        for bad in [
            "where (status = blocked or (client = a))",
            "where (status = blocked or group = kids) or client = a",
            "where (status = blocked or group = kids",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
        let many: Vec<String> = (0..40).map(|i| format!("client = 10.0.0.{i}")).collect();
        assert!(parse(&format!("where {}", many.join(" or "))).is_err());
    }

    /// REQ: AGT-012 — mistakes come back with a hint, never a partial plan.
    #[test]
    fn agt_012_parse_errors() {
        for (q, want) in [
            ("drop table", "unknown stage"),
            ("where name like x", "expected an operator"),
            ("where status ~ blocked", "only applies to name"),
            ("where latency = 5", "isn't supported"),
            ("where latency > fast", "not a number"),
            ("by color", "unknown key"),
            ("stats p95(color)", "unknown measure"),
            ("stats median(latency)", "unknown statistic"),
            ("limit 500", "out of range"),
            ("by name | sort latency", "no column"),
            ("top 5 name | stats count", "already sets"),
            ("from -1h | from -2h", "appears twice"),
            ("where name = \"x", "unclosed quote"),
            ("bucket 7x", "not a duration"),
        ] {
            let e = parse(q).unwrap_err();
            assert!(e.message.contains(want), "{q}: {e:?}");
        }
    }

    #[test]
    fn agt_012_glob() {
        assert!(glob_match("*.roku.com", "api.roku.com"));
        assert!(!glob_match("*.roku.com", "roku.com"));
        assert!(glob_match("ad?.example.*", "ads.example.net"));
        assert!(glob_match("*", ""));
        assert!(!glob_match("a*b", "acd"));
    }
}
