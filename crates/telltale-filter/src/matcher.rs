//! The filter decision (`spec/03` §3 step 6, `spec/05` §1).
//!
//! REQ: FLT-003, FLT-013, ADR-003, ADR-020. Domain rules are looked up in a query-time hash
//! index built from the snapshot's FSTs when the matcher is created: one probe per (scope,
//! reversed suffix) of the query name, which are independent memory reads, instead of a
//! byte-by-byte FST walk (~30 ns per byte of dependent node decoding). Modifier rules (an FST
//! walk, only when the snapshot has any) and the overlay of manual rules are checked in the
//! same pass, collecting every matching rule. Regexes run only if an enabled list has any. The winner
//! follows the four tiers (important allow > important block > allow > block); within a tier,
//! attribution prefers an exact rule, then the most specific suffix, then a regex, then the
//! lowest list ID. Steady-state lookups allocate nothing (scratch buffers live in [`Scratch`]).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fst::raw::{Fst, Output};
use regex_automata::meta::{Cache, Regex};
use regex_automata::{Input, PatternID, PatternSet};
use telltale_config::Cidr;

use crate::compile::{regex_builder, reversed_key};
use crate::parse::{ListOptions, ParseStats, Pattern, Scope, parse_list};
use crate::snapshot::{Class, ModRule, NegValue, RegexRule, ScopeTag, Snapshot, shard_of};

/// Most labels a name can have (255-byte wire limit).
const MAX_LABELS: usize = 128;

/// Which lists apply to a client (bit `i` = list ID `i`): the union of its groups' lists.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ListMask {
    words: Vec<u64>,
}

impl ListMask {
    /// Every list ID below `lists`.
    pub fn all(lists: usize) -> Self {
        let mut m = Self::default();
        for i in 0..lists {
            m.set(u16::try_from(i).unwrap_or(u16::MAX));
        }
        m
    }

    pub fn set(&mut self, list: u16) {
        let i = usize::from(list);
        if self.words.len() <= i / 64 {
            self.words.resize(i / 64 + 1, 0);
        }
        self.words[i / 64] |= 1 << (i % 64);
    }

    pub fn contains(&self, list: u16) -> bool {
        let i = usize::from(list);
        self.words
            .get(i / 64)
            .is_some_and(|w| w & (1 << (i % 64)) != 0)
    }

    /// The lowest list ID in both `self` and `bits`.
    fn first_common(&self, bits: &[u64]) -> Option<u16> {
        for (i, (a, b)) in self.words.iter().zip(bits).enumerate() {
            let both = a & b;
            if both != 0 {
                return u16::try_from(i * 64 + both.trailing_zeros() as usize).ok();
            }
        }
        None
    }

    fn intersects(&self, other: &Self) -> bool {
        self.words.iter().zip(&other.words).any(|(a, b)| a & b != 0)
    }

    fn union_with(&mut self, other: &Self) {
        if self.words.len() < other.words.len() {
            self.words.resize(other.words.len(), 0);
        }
        for (a, b) in self.words.iter_mut().zip(&other.words) {
            *a |= b;
        }
    }
}

/// Who is asking, for `$client` rules (which name an IP, a CIDR, a device, or a client ID).
#[derive(Debug, Clone, Copy)]
pub struct ClientCtx<'a> {
    pub ip: IpAddr,
    /// The identified device's name (FLT-006), if it's a configured client.
    pub name: Option<&'a str>,
    /// The DoH/DoT client ID, if the query carried one.
    pub client_id: Option<&'a str>,
}

/// Precedence tier (`spec/05` §1), best first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    ImportantAllow,
    ImportantBlock,
    Allow,
    Block,
}

impl Tier {
    fn from_class(c: Class) -> Self {
        match c {
            Class::ImportantAllow => Self::ImportantAllow,
            Class::ImportantBlock => Self::ImportantBlock,
            Class::Allow => Self::Allow,
            Class::Block => Self::Block,
        }
    }
    pub(crate) fn of(allow: bool, important: bool) -> Self {
        Self::from_class(Class::new(allow, important))
    }
    fn is_allow(self) -> bool {
        matches!(self, Self::ImportantAllow | Self::Allow)
    }
}

/// What matched, for FLT-013 attribution and explain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleRef {
    /// A plain domain rule; `labels` = labels of the matching name (`example.com` = 2).
    Domain { scope: Scope, labels: u8 },
    /// Index into the snapshot's modifier rules (or the overlay's, if `overlay`).
    ModRule { index: u32 },
    /// Index into the snapshot's regex rules (or the overlay's).
    Regex { index: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attribution {
    pub list: u16,
    pub tier: Tier,
    pub rule: RuleRef,
    /// The rule came from the manual-rules overlay, not the snapshot.
    pub overlay: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// No rule matched: resolve normally.
    None,
    Allow(Attribution),
    Block(Attribution),
}

/// Ordering key for attribution within a tier: exact < deeper suffix < regex < list ID.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Rank(u8, u8, u16);

#[derive(Default, Clone, Copy)]
struct Best([Option<(Rank, Attribution)>; 4]);

impl Best {
    fn offer(&mut self, tier: Tier, rank: Rank, a: Attribution) {
        let slot = &mut self.0[tier as usize];
        if slot.is_none_or(|(r, _)| rank < r) {
            *slot = Some((rank, a));
        }
    }
    fn decision(&self) -> Decision {
        self.0
            .iter()
            .flatten()
            .next()
            .map_or(Decision::None, |(_, a)| {
                if a.tier.is_allow() {
                    Decision::Allow(*a)
                } else {
                    Decision::Block(*a)
                }
            })
    }
}

/// Where the lookup passes report matches: [`Best`] keeps each tier's winner (the query
/// path), [`Collect`] keeps every match (explain, FLT-013).
trait Sink {
    /// A domain entry matched at `labels`: `bits` are the lists with a rule of `tier` there.
    fn domain(&mut self, tier: Tier, scope: Scope, labels: u8, bits: &[u64], mask: &ListMask);
    /// One rule from one list matched.
    fn rule(&mut self, rank: Rank, a: Attribution);
}

impl Sink for Best {
    #[inline]
    fn domain(&mut self, tier: Tier, scope: Scope, labels: u8, bits: &[u64], mask: &ListMask) {
        if let Some(list) = mask.first_common(bits) {
            self.offer(
                tier,
                domain_rank(scope, labels, list),
                Attribution {
                    list,
                    tier,
                    rule: RuleRef::Domain { scope, labels },
                    overlay: false,
                },
            );
        }
    }

    #[inline]
    fn rule(&mut self, rank: Rank, a: Attribution) {
        self.offer(a.tier, rank, a);
    }
}

/// One rule that matches a name, from any list (FLT-013 explain).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Match {
    pub attribution: Attribution,
    /// The client's groups use this list, so the rule takes part in its decision.
    pub enabled: bool,
}

/// Every match, each marked enabled or not for the client's mask.
struct Collect<'a> {
    mask: &'a ListMask,
    out: Vec<(Tier, Rank, Match)>,
}

impl Sink for Collect<'_> {
    fn domain(&mut self, tier: Tier, scope: Scope, labels: u8, bits: &[u64], _: &ListMask) {
        for (w, &word) in bits.iter().enumerate() {
            let mut rest = word;
            while rest != 0 {
                let bit = rest.trailing_zeros() as usize;
                rest &= rest - 1;
                let Ok(list) = u16::try_from(w * 64 + bit) else {
                    continue;
                };
                let a = Attribution {
                    list,
                    tier,
                    rule: RuleRef::Domain { scope, labels },
                    overlay: false,
                };
                self.rule(domain_rank(scope, labels, list), a);
            }
        }
    }

    fn rule(&mut self, rank: Rank, a: Attribution) {
        let enabled = self.mask.contains(a.list);
        self.out.push((
            a.tier,
            rank,
            Match {
                attribution: a,
                enabled,
            },
        ));
    }
}

fn domain_rank(scope: Scope, labels: u8, list: u16) -> Rank {
    match scope {
        Scope::Exact => Rank(0, 0, list),
        _ => Rank(1, u8::MAX - labels, list),
    }
}

/// `$client` value, compiled once.
#[derive(Debug, Clone)]
enum ClientPred {
    Ip(IpAddr),
    Net(Cidr),
    Name(String),
}

impl ClientPred {
    fn new(v: &str) -> Self {
        if let Ok(ip) = v.parse::<IpAddr>() {
            Self::Ip(ip)
        } else if let Ok(c) = Cidr::parse(v) {
            Self::Net(c)
        } else {
            Self::Name(v.to_ascii_lowercase())
        }
    }
    fn matches(&self, c: &ClientCtx<'_>) -> bool {
        match self {
            Self::Ip(ip) => *ip == c.ip,
            Self::Net(n) => n.contains(c.ip),
            Self::Name(n) => [c.name, c.client_id]
                .into_iter()
                .flatten()
                .any(|x| x.eq_ignore_ascii_case(n)),
        }
    }
}

/// A modifier rule with its predicates compiled.
#[derive(Debug, Clone)]
struct CompiledMod {
    list: u16,
    scope: Scope,
    tier: Tier,
    clients: Vec<(ClientPred, bool)>,
    dnstype: Vec<NegValue<u16>>,
    /// Reversed keys of `$denyallow` names.
    deny: Vec<Vec<u8>>,
    /// `$dnsrewrite` rules don't block or allow: they rewrite (FLT-014, T9.20).
    rewrite: bool,
    /// What a rewrite does (none for an exception's `$dnsrewrite`).
    action: Option<crate::rewrite::RewriteAction>,
    allow: bool,
}

fn scope_of(t: ScopeTag) -> Scope {
    match t {
        ScopeTag::Subtree => Scope::Subtree,
        ScopeTag::Exact => Scope::Exact,
        ScopeTag::Subdomains => Scope::Subdomains,
    }
}

impl CompiledMod {
    fn new(m: &ModRule) -> Self {
        Self {
            list: m.list,
            scope: scope_of(m.scope),
            tier: Tier::of(m.allow, m.important),
            clients: m
                .client
                .iter()
                .map(|c| (ClientPred::new(&c.value), c.negated))
                .collect(),
            dnstype: m.dnstype.clone(),
            deny: m.denyallow.iter().map(|d| reversed_key(d)).collect(),
            rewrite: m.dnsrewrite.is_some(),
            action: m.dnsrewrite.as_deref().and_then(crate::rewrite::parse),
            allow: m.allow,
        }
    }

    /// Does this rule apply to `qkey` (full reversed qname) for this client and qtype?
    fn applies(&self, qkey: &[u8], qtype: u16, client: &ClientCtx<'_>) -> bool {
        !self.rewrite && self.applies_to(qkey, qtype, client)
    }

    /// The rule's predicates (`$dnstype`, `$denyallow`, `$client`), whatever it does.
    fn applies_to(&self, qkey: &[u8], qtype: u16, client: &ClientCtx<'_>) -> bool {
        if !dnstype_ok(&self.dnstype, qtype) {
            return false;
        }
        if self.deny.iter().any(|d| qkey.starts_with(d)) {
            return false;
        }
        if self.clients.is_empty() {
            return true;
        }
        // AdGuard semantics: matches if any positive value matches (or there are none), and
        // no negated value matches.
        let mut any_positive = false;
        let mut positive_hit = false;
        for (p, negated) in &self.clients {
            let hit = p.matches(client);
            if *negated {
                if hit {
                    return false;
                }
            } else {
                any_positive = true;
                positive_hit |= hit;
            }
        }
        !any_positive || positive_hit
    }
}

fn dnstype_ok(types: &[NegValue<u16>], qtype: u16) -> bool {
    let mut any_positive = false;
    let mut positive_hit = false;
    for t in types {
        if t.negated {
            if t.value == qtype {
                return false;
            }
        } else {
            any_positive = true;
            positive_hit |= t.value == qtype;
        }
    }
    !any_positive || positive_hit
}

fn scope_applies(scope: Scope, labels: usize, total: usize) -> bool {
    match scope {
        Scope::Subtree => true,
        Scope::Exact => labels == total,
        Scope::Subdomains => labels < total,
    }
}

/// Regex rules compiled into two multi-pattern sets (matching and `;invert`).
#[derive(Debug)]
struct RegexSets {
    rules: Vec<RegexRule>,
    /// Pattern ID → index into `rules`.
    normal_ids: Vec<u32>,
    invert_ids: Vec<u32>,
    normal: Option<Regex>,
    invert: Option<Regex>,
    /// Lists that have regex rules (prefilter: skip regexes when a client has none enabled).
    lists: ListMask,
}

impl RegexSets {
    fn new(rules: Vec<RegexRule>) -> Result<Self, String> {
        let mut normal_ids = Vec::new();
        let mut invert_ids = Vec::new();
        let mut lists = ListMask::default();
        for (i, r) in rules.iter().enumerate() {
            let id = u32::try_from(i).map_err(|e| e.to_string())?;
            if r.invert {
                invert_ids.push(id);
            } else {
                normal_ids.push(id);
            }
            lists.set(r.list);
        }
        let build = |ids: &[u32]| -> Result<Option<Regex>, String> {
            if ids.is_empty() {
                return Ok(None);
            }
            let pats: Vec<&str> = ids
                .iter()
                .map(|&i| rules[i as usize].pattern.as_str())
                .collect();
            regex_builder()
                .build_many(&pats)
                .map(Some)
                .map_err(|e| format!("regex set: {e}"))
        };
        Ok(Self {
            normal: build(&normal_ids)?,
            invert: build(&invert_ids)?,
            normal_ids,
            invert_ids,
            rules,
            lists,
        })
    }

    fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// Manual rules applied without recompiling (ADR-003): consulted together with the snapshot,
/// at the same precedence, and folded into the next compile by the caller.
#[derive(Debug, Default)]
pub struct Overlay {
    domains: HashMap<Vec<u8>, Vec<(Scope, Class, u16)>>,
    mods: HashMap<Vec<u8>, Vec<CompiledMod>>,
    regexes: Option<RegexSets>,
    lists: ListMask,
}

impl Overlay {
    /// Parses each `(list ID, options, rules text)` into an overlay.
    pub fn build(lists: &[(u16, ListOptions, &str)]) -> Result<(Self, Vec<ParseStats>), String> {
        let mut o = Self::default();
        let mut regexes = Vec::new();
        let mut stats = Vec::new();
        for &(list, options, text) in lists {
            o.lists.set(list);
            stats.push(parse_list(text.as_bytes(), options, |line, rule| {
                if rule.modifiers.badfilter {
                    return; // `$badfilter` needs the compiler's view of every list.
                }
                let m = &rule.modifiers;
                let plain = m.client.is_empty()
                    && m.dnstype.is_empty()
                    && m.denyallow.is_empty()
                    && m.dnsrewrite.is_none();
                let allow = rule.action == crate::parse::Action::Allow;
                match &rule.pattern {
                    Pattern::Domain { name, scope } if plain => {
                        o.domains.entry(reversed_key(name)).or_default().push((
                            *scope,
                            Class::new(allow, m.important),
                            list,
                        ));
                    }
                    Pattern::Domain { name, scope } => {
                        let mr = ModRule {
                            list,
                            line,
                            scope: (*scope).into(),
                            allow,
                            important: m.important,
                            client: m
                                .client
                                .iter()
                                .map(|c| NegValue {
                                    value: c.value.clone(),
                                    negated: c.negated,
                                })
                                .collect(),
                            dnstype: m
                                .dnstype
                                .iter()
                                .map(|t| NegValue {
                                    value: t.value,
                                    negated: t.negated,
                                })
                                .collect(),
                            denyallow: m.denyallow.clone(),
                            dnsrewrite: m.dnsrewrite.clone(),
                        };
                        o.mods
                            .entry(reversed_key(name))
                            .or_default()
                            .push(CompiledMod::new(&mr));
                    }
                    Pattern::Regex { pattern, invert } => regexes.push(RegexRule {
                        pattern: pattern.clone(),
                        list,
                        line,
                        allow,
                        important: m.important,
                        invert: *invert,
                        dnstype: m
                            .dnstype
                            .iter()
                            .map(|t| NegValue {
                                value: t.value,
                                negated: t.negated,
                            })
                            .collect(),
                    }),
                }
            }));
        }
        if !regexes.is_empty() {
            o.regexes = Some(RegexSets::new(regexes)?);
        }
        Ok((o, stats))
    }

    pub fn is_empty(&self) -> bool {
        self.domains.is_empty() && self.mods.is_empty() && self.regexes.is_none()
    }
}

/// Query-time index of one scope's domain FSTs (ADR-020): a bucketed hash table where each
/// 64-byte bucket holds 8 entries of `fingerprint (48 bits) | list-set ID (16 bits)`, so a
/// probe, hit or miss, almost always touches one cache line. The fingerprint comes from a
/// seeded 64-bit hash (random seed per index, so collisions can't be precomputed). A false
/// match needs a 47-bit fingerprint collision among a bucket's entries: ~6e-14 per probe, or
/// about one per few thousand years of a busy resolver.
#[derive(Debug, Default)]
struct ScopeIndex {
    seed: u64,
    buckets: Vec<Bucket>,
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(align(64))]
struct Bucket([u64; 8]);

/// Most list-set IDs the 16-bit entry field can hold; larger snapshots use the FST walk.
const MAX_INDEXED_LISTSETS: u64 = 1 << 16;

impl ScopeIndex {
    fn build(maps: &[fst::Map<Vec<u8>>], seed: u64) -> Result<Self, String> {
        use fst::Streamer;
        let n: usize = maps.iter().map(fst::Map::len).sum();
        if n == 0 {
            return Ok(Self::default());
        }
        // 75% load: ~11 bytes per name, and few buckets overflow into the next one.
        let nb = (n * 4 / 3).div_ceil(8).max(1);
        let mut idx = Self {
            seed,
            buckets: vec![Bucket::default(); nb],
        };
        for map in maps {
            let mut stream = map.stream();
            while let Some((key, value)) = stream.next() {
                if value >= MAX_INDEXED_LISTSETS {
                    return Err("too many list sets for the index".into());
                }
                let (mut b, fp) = idx.locate(key);
                let entry = (fp << 16) | value;
                'insert: loop {
                    for slot in &mut idx.buckets[b].0 {
                        if *slot == 0 {
                            *slot = entry;
                            break 'insert;
                        }
                    }
                    b = if b + 1 == nb { 0 } else { b + 1 };
                }
            }
        }
        Ok(idx)
    }

    /// Bucket from the low 32 hash bits, fingerprint from the high 48 (forced non-zero, so an
    /// entry is never 0 = empty).
    #[allow(clippy::cast_possible_truncation)] // fastrange of a u32: the result is < len
    fn locate(&self, key: &[u8]) -> (usize, u64) {
        let h = xxhash_rust::xxh3::xxh3_64_with_seed(key, self.seed);
        let b = ((u64::from(h as u32) * self.buckets.len() as u64) >> 32) as usize;
        (b, (h >> 16) | 1)
    }

    fn get(&self, key: &[u8]) -> Option<u32> {
        if self.buckets.is_empty() {
            return None;
        }
        let (mut b, fp) = self.locate(key);
        loop {
            for &e in &self.buckets[b].0 {
                if e == 0 {
                    return None;
                }
                if e >> 16 == fp {
                    return u32::try_from(e & 0xffff).ok();
                }
            }
            b = if b + 1 == self.buckets.len() {
                0
            } else {
                b + 1
            };
        }
    }

    fn bytes(&self) -> usize {
        self.buckets.len() * std::mem::size_of::<Bucket>()
    }
}

/// Per-scope indexes (subtree, exact, subdomains).
#[derive(Debug, Default)]
struct DomainIndex([ScopeIndex; 3]);

impl DomainIndex {
    fn build(s: &Snapshot) -> Result<Self, String> {
        let seed: u64 = rand::random();
        Ok(Self([
            ScopeIndex::build(&s.domains[0], seed ^ 0x9e37_79b9_7f4a_7c15)?,
            ScopeIndex::build(&s.domains[1], seed ^ 0xc2b2_ae3d_27d4_eb4f)?,
            ScopeIndex::build(&s.domains[2], seed ^ 0x1656_67b1_9e37_79f9)?,
        ]))
    }

    fn bytes(&self) -> usize {
        self.0.iter().map(ScopeIndex::bytes).sum()
    }
}

/// How domain rules are looked up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lookup {
    /// Walk the FSTs (no extra memory; available as soon as the snapshot is loaded).
    Walk,
    /// Build the hash index first (≈ 14 bytes per name, ~2× faster lookups).
    Indexed,
}

const SCOPES: [Scope; 3] = [Scope::Subtree, Scope::Exact, Scope::Subdomains];

/// Distinguishes matchers so a [`Scratch`] rebuilds its regex caches after a swap.
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// An immutable snapshot + overlay, ready for lookups. Share it behind an `Arc` and swap the
/// `Arc` (`ArcSwap`) to publish a new one.
#[derive(Debug)]
pub struct Matcher {
    id: u64,
    snapshot: Option<Arc<Snapshot>>,
    index: Option<DomainIndex>,
    mods: Vec<CompiledMod>,
    regexes: RegexSets,
    overlay: Overlay,
    /// REQ: FLT-014 (T9.20) — any `$dnsrewrite` rule at all (else [`Matcher::rewrites`] is
    /// one bool check).
    has_rewrites: bool,
}

/// Per-worker scratch (regex caches and match sets). Create one per thread with
/// [`Scratch::default`]; it adapts to whichever matcher it's used with.
#[derive(Debug, Default)]
pub struct Scratch {
    matcher: u64,
    caches: Vec<Option<(Cache, PatternSet)>>,
    /// Lowercase dotted name for regexes.
    name: Vec<u8>,
}

/// Wire-format qname split into labels and the reversed key, on the stack.
struct Name {
    key: [u8; 256],
    key_len: usize,
    /// `ends[d]` = key length after `d + 1` labels.
    ends: [u8; MAX_LABELS],
    labels: usize,
}

impl Name {
    /// `None` for the root, malformed input, or labels containing `.` (which can't be in a
    /// list and would make the reversed key ambiguous).
    fn from_wire(wire: &[u8]) -> Option<Self> {
        let mut starts = [0u8; MAX_LABELS];
        let mut n = 0;
        let mut pos = 0;
        loop {
            let len = usize::from(*wire.get(pos)?);
            if len == 0 {
                break;
            }
            if n == MAX_LABELS || len > 63 || pos + 1 + len > wire.len() {
                return None;
            }
            starts[n] = u8::try_from(pos).ok()?;
            n += 1;
            pos += 1 + len;
        }
        if n == 0 {
            return None;
        }
        let mut name = Self {
            key: [0; 256],
            key_len: 0,
            ends: [0; MAX_LABELS],
            labels: n,
        };
        for d in 0..n {
            let s = usize::from(starts[n - 1 - d]);
            let len = usize::from(wire[s]);
            let label = &wire[s + 1..s + 1 + len];
            if label.contains(&b'.') || name.key_len + len + 1 > name.key.len() {
                return None;
            }
            name.key[name.key_len..name.key_len + len].copy_from_slice(label);
            name.key_len += len;
            name.key[name.key_len] = b'.';
            name.key_len += 1;
            name.ends[d] = u8::try_from(name.key_len).ok()?;
        }
        Some(name)
    }

    fn key(&self) -> &[u8] {
        &self.key[..self.key_len]
    }

    /// Key prefix for the last `labels` labels.
    fn prefix(&self, labels: usize) -> &[u8] {
        &self.key[..usize::from(self.ends[labels - 1])]
    }
}

/// Walks `fst` along `key`, calling `f(labels, value)` at every label boundary in
/// `from..=to` (label counts) where the FST has a final state.
fn walk(fst: &Fst<Vec<u8>>, name: &Name, from: usize, to: usize, mut f: impl FnMut(usize, u64)) {
    if fst.is_empty() {
        return;
    }
    let mut node = fst.root();
    let mut out = Output::zero();
    let mut depth = 0;
    let end = usize::from(name.ends[to - 1]);
    for (i, &b) in name.key[..end].iter().enumerate() {
        let Some(t) = node.find_input(b) else {
            return;
        };
        let tr = node.transition(t);
        out = out.cat(tr.out);
        node = fst.node(tr.addr);
        if i + 1 == usize::from(name.ends[depth]) {
            depth += 1;
            if depth >= from && node.is_final() {
                f(depth, out.cat(node.final_output()).value());
            }
        }
    }
}

impl Matcher {
    /// A matcher over `snapshot` (or no snapshot) plus `overlay`, using the FST walk. Builds
    /// the regex sets.
    pub fn new(snapshot: Option<Arc<Snapshot>>, overlay: Overlay) -> Result<Self, String> {
        Self::with_lookup(snapshot, overlay, Lookup::Walk)
    }

    /// Like [`Matcher::new`], choosing the domain lookup. `Indexed` takes ~0.4 s per million
    /// names to build: publish a `Walk` matcher first and swap in the indexed one when ready.
    pub fn with_lookup(
        snapshot: Option<Arc<Snapshot>>,
        overlay: Overlay,
        lookup: Lookup,
    ) -> Result<Self, String> {
        let (mods, regexes, index) = match &snapshot {
            Some(s) => (
                s.modrules.iter().map(CompiledMod::new).collect(),
                RegexSets::new(s.regexes.clone())?,
                match lookup {
                    // A snapshot beyond the index's limits still works, just via the walk.
                    Lookup::Indexed => DomainIndex::build(s).ok(),
                    Lookup::Walk => None,
                },
            ),
            None => (Vec::new(), RegexSets::new(Vec::new())?, None),
        };
        let has_rewrites = mods.iter().any(|m: &CompiledMod| m.rewrite)
            || overlay.mods.values().flatten().any(|m| m.rewrite);
        Ok(Self {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            snapshot,
            index,
            mods,
            regexes,
            overlay,
            has_rewrites,
        })
    }

    /// REQ: FLT-014 (T9.20) — whether any list has `$dnsrewrite` rules.
    pub fn has_rewrites(&self) -> bool {
        self.has_rewrites
    }

    pub fn snapshot(&self) -> Option<&Arc<Snapshot>> {
        self.snapshot.as_ref()
    }

    pub fn overlay(&self) -> &Overlay {
        &self.overlay
    }

    /// Heap bytes of the query-time domain index (0 in `Walk` mode).
    pub fn index_bytes(&self) -> usize {
        self.index.as_ref().map_or(0, DomainIndex::bytes)
    }

    pub fn lookup(&self) -> Lookup {
        if self.index.is_some() {
            Lookup::Indexed
        } else {
            Lookup::Walk
        }
    }

    /// The filter decision for `qname` (wire format, lowercase) and `qtype`, for a client
    /// whose groups enable `mask`.
    pub fn decide(
        &self,
        qname: &[u8],
        qtype: u16,
        client: &ClientCtx<'_>,
        mask: &ListMask,
        scratch: &mut Scratch,
    ) -> Decision {
        let Some(name) = Name::from_wire(qname) else {
            return Decision::None;
        };
        let mut best = Best::default();
        self.run(&name, qname, qtype, client, mask, scratch, &mut best);
        best.decision()
    }

    /// REQ: FLT-014 (T9.20) — the `$dnsrewrite` answer for `qname`/`qtype`, if a rewrite rule in
    /// a list this client uses applies (and no exception turns it off), with the first rule's
    /// list. A rewrite wins over blocking (AdGuard's semantics). One bool check when no list
    /// has rewrites.
    pub fn rewrites(
        &self,
        qname: &[u8],
        qtype: u16,
        client: &ClientCtx<'_>,
        mask: &ListMask,
    ) -> Option<(crate::rewrite::ListRewrite, u16)> {
        if !self.has_rewrites {
            return None;
        }
        let name = Name::from_wire(qname)?;
        let mut hits: Vec<&CompiledMod> = Vec::new();
        let take = |m: &'_ CompiledMod, labels: usize| {
            m.rewrite
                && mask.contains(m.list)
                && scope_applies(m.scope, labels, name.labels)
                && m.applies_to(name.key(), qtype, client)
        };
        if let Some(s) = &self.snapshot {
            let mods = &self.mods;
            let mut found: Vec<usize> = Vec::new();
            walk(
                s.modrules_index.as_fst(),
                &name,
                1,
                name.labels,
                |labels, v| {
                    if let (Ok(start), Ok(count)) =
                        (usize::try_from(v >> 32), usize::try_from(v & 0xffff_ffff))
                    {
                        for (i, m) in mods.iter().enumerate().skip(start).take(count) {
                            if take(m, labels) {
                                found.push(i);
                            }
                        }
                    }
                },
            );
            hits.extend(found.into_iter().filter_map(|i| mods.get(i)));
        }
        for labels in 1..=name.labels {
            if let Some(mods) = self.overlay.mods.get(name.prefix(labels)) {
                hits.extend(mods.iter().filter(|m| take(m, labels)));
            }
        }
        // An exception (`@@…$dnsrewrite`) turns rewrites off.
        if hits.is_empty() || hits.iter().any(|m| m.allow) {
            return None;
        }
        // Important rules first, then the most specific (exact, deeper) as listed.
        hits.sort_by_key(|m| std::cmp::Reverse(matches!(m.tier, Tier::ImportantBlock)));
        let actions: Vec<&crate::rewrite::RewriteAction> =
            hits.iter().filter_map(|m| m.action.as_ref()).collect();
        if actions.is_empty() {
            return None;
        }
        Some((crate::rewrite::combine(&actions, qtype), hits[0].list))
    }

    /// Every rule in every list (and the overlay) that matches `qname` for this client and
    /// qtype, in precedence order (tier, then exact > deeper suffix > regex > list ID), each
    /// marked `enabled` if `mask` uses its list. The first enabled match is what [`decide`]
    /// returns. Allocates: for explain (FLT-013), never the query path.
    ///
    /// [`decide`]: Matcher::decide
    pub fn matches(
        &self,
        qname: &[u8],
        qtype: u16,
        client: &ClientCtx<'_>,
        mask: &ListMask,
    ) -> Vec<Match> {
        let Some(name) = Name::from_wire(qname) else {
            return Vec::new();
        };
        // Look through every list; `Collect` marks which ones the client uses.
        let mut every = ListMask::all(self.snapshot.as_ref().map_or(0, |s| s.manifest.lists.len()));
        every.union_with(&self.overlay.lists);
        let mut sink = Collect {
            mask,
            out: Vec::new(),
        };
        let mut scratch = Scratch::default();
        self.run(&name, qname, qtype, client, &every, &mut scratch, &mut sink);
        sink.out.sort_by_key(|(tier, rank, _)| (*tier, *rank));
        sink.out.into_iter().map(|(_, _, m)| m).collect()
    }

    /// The lookup passes, reporting to `sink`: snapshot domains, modifier rules, overlay,
    /// regexes.
    #[allow(clippy::too_many_arguments)]
    #[inline]
    fn run(
        &self,
        name: &Name,
        qname: &[u8],
        qtype: u16,
        client: &ClientCtx<'_>,
        mask: &ListMask,
        scratch: &mut Scratch,
        sink: &mut impl Sink,
    ) {
        if let Some(s) = &self.snapshot {
            self.snapshot_domains(s, name, mask, sink);
            if !self.mods.is_empty() {
                walk(
                    s.modrules_index.as_fst(),
                    name,
                    1,
                    name.labels,
                    |labels, v| {
                        self.offer_mods(name, labels, v, qtype, client, mask, sink);
                    },
                );
            }
        }
        if !self.overlay.is_empty() && self.overlay.lists.intersects(mask) {
            self.overlay_domains(name, qtype, client, mask, sink);
        }
        let need_regex = (!self.regexes.is_empty() && self.regexes.lists.intersects(mask))
            || self
                .overlay
                .regexes
                .as_ref()
                .is_some_and(|r| r.lists.intersects(mask));
        if need_regex {
            self.regex_pass(qname, qtype, mask, scratch, sink);
        }
    }

    fn snapshot_domains(&self, s: &Snapshot, name: &Name, mask: &ListMask, sink: &mut impl Sink) {
        let total = name.labels;
        let mut offer = |scope: Scope, labels: usize, id: u32| {
            if !scope_applies(scope, labels, total) {
                return;
            }
            let labels = u8::try_from(labels).unwrap_or(u8::MAX);
            for class in Class::ALL {
                if let Some(bits) = s.listsets.get(id, class) {
                    sink.domain(Tier::from_class(class), scope, labels, bits, mask);
                }
            }
        };
        if let Some(index) = &self.index {
            for labels in 1..=total {
                let prefix = name.prefix(labels);
                for (i, scope) in SCOPES.into_iter().enumerate() {
                    if scope_applies(scope, labels, total)
                        && let Some(id) = index.0[i].get(prefix)
                    {
                        offer(scope, labels, id);
                    }
                }
            }
            return;
        }
        // FST walk: depth 1 lives in the TLD's shard, depth ≥ 2 in the first-two-labels shard.
        let shards = s.domains[0].len();
        let deep = shard_of(name.prefix(total.min(2)), shards);
        let top = shard_of(name.prefix(1), shards);
        for (i, scope) in SCOPES.into_iter().enumerate() {
            let maps = &s.domains[i];
            let mut f = |labels: usize, v: u64| {
                if let Ok(id) = u32::try_from(v) {
                    offer(scope, labels, id);
                }
            };
            if top == deep {
                walk(maps[deep].as_fst(), name, 1, total, &mut f);
            } else {
                walk(maps[top].as_fst(), name, 1, 1, &mut f);
                if total >= 2 {
                    walk(maps[deep].as_fst(), name, 2, total, &mut f);
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn offer_mods(
        &self,
        name: &Name,
        labels: usize,
        v: u64,
        qtype: u16,
        client: &ClientCtx<'_>,
        mask: &ListMask,
        sink: &mut impl Sink,
    ) {
        let (Ok(start), Ok(count)) = (usize::try_from(v >> 32), usize::try_from(v & 0xffff_ffff))
        else {
            return;
        };
        for (i, m) in self.mods.iter().enumerate().skip(start).take(count) {
            if mask.contains(m.list)
                && scope_applies(m.scope, labels, name.labels)
                && m.applies(name.key(), qtype, client)
            {
                let labels = u8::try_from(labels).unwrap_or(u8::MAX);
                sink.rule(
                    domain_rank(m.scope, labels, m.list),
                    Attribution {
                        list: m.list,
                        tier: m.tier,
                        rule: RuleRef::ModRule {
                            index: u32::try_from(i).unwrap_or(u32::MAX),
                        },
                        overlay: false,
                    },
                );
            }
        }
    }

    fn overlay_domains(
        &self,
        name: &Name,
        qtype: u16,
        client: &ClientCtx<'_>,
        mask: &ListMask,
        sink: &mut impl Sink,
    ) {
        let o = &self.overlay;
        for labels in 1..=name.labels {
            let prefix = name.prefix(labels);
            let l8 = u8::try_from(labels).unwrap_or(u8::MAX);
            if let Some(entries) = o.domains.get(prefix) {
                for &(scope, class, list) in entries {
                    if mask.contains(list) && scope_applies(scope, labels, name.labels) {
                        let tier = Tier::from_class(class);
                        sink.rule(
                            domain_rank(scope, l8, list),
                            Attribution {
                                list,
                                tier,
                                rule: RuleRef::Domain { scope, labels: l8 },
                                overlay: true,
                            },
                        );
                    }
                }
            }
            if let Some(mods) = o.mods.get(prefix) {
                for (i, m) in mods.iter().enumerate() {
                    if mask.contains(m.list)
                        && scope_applies(m.scope, labels, name.labels)
                        && m.applies(name.key(), qtype, client)
                    {
                        sink.rule(
                            domain_rank(m.scope, l8, m.list),
                            Attribution {
                                list: m.list,
                                tier: m.tier,
                                rule: RuleRef::ModRule {
                                    index: u32::try_from(i).unwrap_or(u32::MAX),
                                },
                                overlay: true,
                            },
                        );
                    }
                }
            }
        }
    }

    fn regex_pass(
        &self,
        qname: &[u8],
        qtype: u16,
        mask: &ListMask,
        scratch: &mut Scratch,
        sink: &mut impl Sink,
    ) {
        // Slots: snapshot normal, snapshot invert, overlay normal, overlay invert.
        let sets: [(Option<&RegexSets>, bool); 2] = [
            (Some(&self.regexes), false),
            (self.overlay.regexes.as_ref(), true),
        ];
        if scratch.matcher != self.id {
            scratch.matcher = self.id;
            scratch.caches = sets
                .iter()
                .flat_map(|(set, _)| {
                    let set = *set;
                    [
                        set.and_then(|s| s.normal.as_ref()),
                        set.and_then(|s| s.invert.as_ref()),
                    ]
                })
                .map(|re| re.map(|r| (r.create_cache(), PatternSet::new(r.pattern_len()))))
                .collect();
        }
        // Lowercase dotted name, as patterns expect (`ads.example.com`).
        scratch.name.clear();
        let mut pos = 0;
        while let Some(&len) = qname.get(pos) {
            if len == 0 {
                break;
            }
            let len = usize::from(len);
            if !scratch.name.is_empty() {
                scratch.name.push(b'.');
            }
            scratch
                .name
                .extend_from_slice(qname.get(pos + 1..pos + 1 + len).unwrap_or_default());
            pos += 1 + len;
        }
        let input = Input::new(&scratch.name);
        for (set_idx, (set, overlay)) in sets.iter().enumerate() {
            let Some(set) = set else { continue };
            if set.is_empty() || !set.lists.intersects(mask) {
                continue;
            }
            for (kind, (re, ids)) in [
                (&set.normal, &set.normal_ids),
                (&set.invert, &set.invert_ids),
            ]
            .into_iter()
            .enumerate()
            {
                let (Some(re), Some(Some((cache, pats)))) =
                    (re, scratch.caches.get_mut(set_idx * 2 + kind))
                else {
                    continue;
                };
                pats.clear();
                re.which_overlapping_matches_with(cache, &input, pats);
                let invert = kind == 1;
                for (pid, &rule_idx) in ids.iter().enumerate() {
                    let matched = PatternID::new(pid).is_ok_and(|id| pats.contains(id));
                    // A normal rule applies when it matches; an `;invert` rule when it doesn't.
                    if matched == invert {
                        continue;
                    }
                    let r = &set.rules[rule_idx as usize];
                    if !mask.contains(r.list) || !dnstype_ok(&r.dnstype, qtype) {
                        continue;
                    }
                    let tier = Tier::of(r.allow, r.important);
                    sink.rule(
                        Rank(2, 0, r.list),
                        Attribution {
                            list: r.list,
                            tier,
                            rule: RuleRef::Regex { index: rule_idx },
                            overlay: *overlay,
                        },
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
