//! List compiler (`spec/05` §3.4 steps 2–6).
//!
//! REQ: FLT-002, FLT-003 — parse lists in parallel → external sort → k-way merge → one FST
//! per scope (subtree / exact / subdomains) whose values index an interned list-set table;
//! regex rules and modifier rules go to their own tables; `$badfilter` removes its target
//! rule from every list. The output directory appears atomically (written as `<out>.partial`,
//! then renamed). Compilation runs on its own threads and shares nothing with the query path.

pub(crate) mod listset;
mod sort;

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fst::MapBuilder;

use self::listset::{Class, ListSetBuilder};
use self::sort::{Record, Sorter, merge};
use crate::parse::{Action, ListOptions, Modifiers, ParseStats, Pattern, Rule, Scope, parse_list};
use crate::snapshot::{
    self, Blob, CompileStats, ListCompileStats, Manifest, ManifestList, ModRule, ModRules,
    NegValue, RegexRule, Regexes,
};

/// One list to compile. Its ID is its position in the input.
#[derive(Debug, Clone)]
pub struct ListInput {
    pub name: String,
    pub options: ListOptions,
    pub data: ListData,
    /// BLAKE3 of the source (recorded in the manifest).
    pub source_hash: String,
    /// Source size in bytes, for spreading lists over parser threads.
    pub size: u64,
}

/// Where a list's text comes from. `Stored` sources are read (and decompressed) only when
/// their parser thread gets to them, and dropped right after, so peak memory holds one
/// list's text per thread rather than all of them.
#[derive(Debug, Clone)]
pub enum ListData {
    Bytes(Vec<u8>),
    Stored(crate::fetch::Store),
}

impl ListInput {
    fn load(self) -> io::Result<(Vec<u8>, ListOptions)> {
        let data = match self.data {
            ListData::Bytes(b) => b,
            ListData::Stored(store) => store.read_source(&self.name)?,
        };
        Ok((data, self.options))
    }
}

#[derive(Debug, Clone)]
pub struct CompileOptions {
    /// Parser threads (lists are spread across them by size).
    pub threads: usize,
    /// In-memory budget for sort records before spilling to disk (`05` §3.4: 128 MiB).
    pub memory_budget: usize,
    /// Snapshot version recorded in the manifest.
    pub version: u64,
}

impl Default for CompileOptions {
    fn default() -> Self {
        Self {
            threads: 1,
            memory_budget: 128 << 20,
            version: 1,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("building an FST: {0}")]
    Fst(#[from] fst::Error),
    #[error("{0} lists given; at most {max} fit in one snapshot", max = telltale_config::MAX_LISTS)]
    TooManyLists(usize),
    #[error("{0} already exists")]
    Exists(PathBuf),
}

/// Wall time per phase.
#[derive(Debug, Clone, Default)]
pub struct Timings {
    pub parse: Duration,
    pub merge: Duration,
    pub tables: Duration,
    pub total: Duration,
}

#[derive(Debug, Clone)]
pub struct CompileReport {
    pub manifest: Manifest,
    /// Parse statistics per list (same order as the input).
    pub parse: Vec<ParseStats>,
    /// Regexes the engine refused: (list, line, reason).
    pub regex_errors: Vec<(String, u32, String)>,
    /// Sort runs spilled to disk (0 when everything fit in the memory budget).
    pub spilled_runs: usize,
    pub timings: Timings,
}

/// Domain FST key: labels reversed, each followed by `.` (`ads.example.com` →
/// `com.example.ads.`), so a byte walk sees label boundaries (`05` §3.1).
pub fn reversed_key(name: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(name.len() + 1);
    push_reversed(name, &mut key);
    key
}

fn push_reversed(name: &str, key: &mut Vec<u8>) {
    for label in name.rsplit('.') {
        key.extend_from_slice(label.as_bytes());
        key.push(b'.');
    }
}

const SCOPES: [(Scope, &str); 3] = [
    (Scope::Subtree, snapshot::SUBTREE_FST),
    (Scope::Exact, snapshot::EXACT_FST),
    (Scope::Subdomains, snapshot::SUBDOMAINS_FST),
];

fn scope_byte(s: Scope) -> u8 {
    match s {
        Scope::Subtree => 0,
        Scope::Exact => 1,
        Scope::Subdomains => 2,
    }
}

fn class_of(rule: &Rule) -> Class {
    Class::new(rule.action == Action::Allow, rule.modifiers.important)
}

/// Rules whose only modifier is `$important` go to the domain FSTs; anything with a predicate
/// or rewrite becomes a [`ModRule`].
fn is_plain(m: &Modifiers) -> bool {
    m.client.is_empty() && m.dnstype.is_empty() && m.denyallow.is_empty() && m.dnsrewrite.is_none()
}

/// What one parser thread produced.
struct Parsed {
    sorter_sources: Vec<sort::Source>,
    runs: usize,
    mods: Vec<(Vec<u8>, ModRule, Rule)>,
    regexes: Vec<(RegexRule, Rule)>,
    /// `$badfilter` targets among plain domain rules: key → bitmask of classes.
    bad_domains: HashMap<Vec<u8>, u8>,
    bad_rules: HashSet<Rule>,
    stats: Vec<(usize, ParseStats)>,
}

fn parse_bucket(
    bucket: Vec<(usize, ListInput)>,
    budget: usize,
    tmp: &Path,
    tag: &str,
) -> io::Result<Parsed> {
    let mut sorter = Sorter::new(budget, tmp, tag);
    let mut out = Parsed {
        sorter_sources: Vec::new(),
        runs: 0,
        mods: Vec::new(),
        regexes: Vec::new(),
        bad_domains: HashMap::new(),
        bad_rules: HashSet::new(),
        stats: Vec::new(),
    };
    let mut key = Vec::with_capacity(256);
    let mut err: Option<io::Error> = None;
    for (id, input) in bucket {
        let list = u16::try_from(id).map_err(io::Error::other)?;
        let (data, options) = input.load()?;
        let stats = parse_list(&data, options, |line, mut rule| {
            if err.is_some() {
                return;
            }
            let badfilter = std::mem::take(&mut rule.modifiers.badfilter);
            match &rule.pattern {
                Pattern::Domain { name, scope } if is_plain(&rule.modifiers) => {
                    key.clear();
                    key.push(scope_byte(*scope));
                    push_reversed(name, &mut key);
                    let class = class_of(&rule) as u8;
                    if badfilter {
                        *out.bad_domains.entry(key.clone()).or_default() |= 1 << class;
                    } else if let Err(e) = sorter.push(&key, list, class) {
                        err = Some(e);
                    }
                }
                _ if badfilter => {
                    out.bad_rules.insert(rule);
                }
                Pattern::Domain { name, scope } => {
                    let m = &rule.modifiers;
                    let neg = |v: &[crate::parse::Negatable<String>]| {
                        v.iter()
                            .map(|n| NegValue {
                                value: n.value.clone(),
                                negated: n.negated,
                            })
                            .collect()
                    };
                    let modrule = ModRule {
                        list,
                        line,
                        scope: (*scope).into(),
                        allow: rule.action == Action::Allow,
                        important: m.important,
                        client: neg(&m.client),
                        dnstype: m
                            .dnstype
                            .iter()
                            .map(|n| NegValue {
                                value: n.value,
                                negated: n.negated,
                            })
                            .collect(),
                        denyallow: m.denyallow.clone(),
                        dnsrewrite: m.dnsrewrite.clone(),
                    };
                    out.mods.push((reversed_key(name), modrule, rule));
                }
                Pattern::Regex { pattern, invert } => {
                    let r = RegexRule {
                        pattern: pattern.clone(),
                        list,
                        line,
                        allow: rule.action == Action::Allow,
                        important: rule.modifiers.important,
                        invert: *invert,
                        dnstype: rule
                            .modifiers
                            .dnstype
                            .iter()
                            .map(|n| NegValue {
                                value: n.value,
                                negated: n.negated,
                            })
                            .collect(),
                    };
                    out.regexes.push((r, rule));
                }
            }
        });
        drop(data);
        if let Some(e) = err.take() {
            return Err(e);
        }
        out.stats.push((id, stats));
    }
    out.runs = sorter.runs();
    out.sorter_sources = sorter.finish()?;
    Ok(out)
}

/// Spreads lists over `threads` buckets, largest first onto the least-loaded bucket.
fn buckets(inputs: Vec<ListInput>, threads: usize) -> Vec<Vec<(usize, ListInput)>> {
    let n = threads.clamp(1, inputs.len().max(1));
    let mut order: Vec<(usize, ListInput)> = inputs.into_iter().enumerate().collect();
    order.sort_by_key(|(_, l)| std::cmp::Reverse(l.size));
    let mut buckets: Vec<(u64, Vec<(usize, ListInput)>)> =
        (0..n).map(|_| (0, Vec::new())).collect();
    for item in order {
        if let Some(b) = buckets.iter_mut().min_by_key(|b| b.0) {
            b.0 += item.1.size;
            b.1.push(item);
        }
    }
    buckets.into_iter().map(|b| b.1).collect()
}

/// What the manifest and reports need after the inputs are consumed.
struct ListMeta {
    name: String,
    source_hash: String,
    options: ListOptions,
}

/// Hard rule (`spec/05` §3.4): compiling never competes with queries for CPU.
fn lower_priority() {
    // Best effort; failing to renice (e.g. a restricted container) isn't an error.
    let _ = telltale_net::lower_thread_priority(10);
}

/// Compiles `inputs` into a new snapshot directory `out` (which must not exist).
/// The calling thread does the merge; run it on a background thread.
pub fn compile(
    inputs: Vec<ListInput>,
    out: &Path,
    opts: &CompileOptions,
) -> Result<CompileReport, CompileError> {
    let started = Instant::now();
    lower_priority();
    if inputs.len() > telltale_config::MAX_LISTS {
        return Err(CompileError::TooManyLists(inputs.len()));
    }
    if out.exists() {
        return Err(CompileError::Exists(out.to_owned()));
    }
    let mut partial = out.as_os_str().to_owned();
    partial.push(".partial");
    let tmp = PathBuf::from(partial);
    if tmp.exists() {
        fs::remove_dir_all(&tmp)?;
    }
    fs::create_dir_all(&tmp)?;
    let result = build(inputs, &tmp, opts, started);
    match result {
        Ok(report) => {
            fs::rename(&tmp, out)?;
            Ok(report)
        }
        Err(e) => {
            let _ = fs::remove_dir_all(&tmp);
            Err(e)
        }
    }
}

fn build(
    inputs: Vec<ListInput>,
    dir: &Path,
    opts: &CompileOptions,
    started: Instant,
) -> Result<CompileReport, CompileError> {
    let mut timings = Timings::default();
    let meta: Vec<ListMeta> = inputs
        .iter()
        .map(|l| ListMeta {
            name: l.name.clone(),
            source_hash: l.source_hash.clone(),
            options: l.options,
        })
        .collect();
    let count = meta.len();

    // Steps 1–2: parse lists in parallel into sort runs.
    let parsed = parse_all(buckets(inputs, opts.threads), count, dir, opts)?;
    timings.parse = started.elapsed();

    // Steps 3–4: merge into the scope FSTs and the list-set table.
    let t = Instant::now();
    let mut stats = CompileStats::default();
    let mut per_list: Vec<ListCompileStats> = (0..count)
        .map(|i| ListCompileStats {
            id: u16::try_from(i).unwrap_or(u16::MAX),
            invalid: parsed.parse_stats[i].invalid,
            unsupported: parsed.parse_stats[i].unsupported,
            ..ListCompileStats::default()
        })
        .collect();
    let names = merge_domains(
        parsed.sources,
        &parsed.bad_domains,
        dir,
        count,
        &mut per_list,
        &mut stats,
    )?;
    timings.merge = t.elapsed();

    // Steps 5–6: modifier rules and regexes.
    let t = Instant::now();
    let regex_errors = write_tables(
        parsed.mods,
        parsed.regexes,
        &parsed.bad_rules,
        dir,
        &meta,
        &mut per_list,
        &mut stats,
    )?;
    timings.tables = t.elapsed();

    stats.per_list = per_list;
    let manifest = write_manifest(dir, &meta, opts.version, names, stats)?;
    timings.total = started.elapsed();
    Ok(CompileReport {
        manifest,
        parse: parsed.parse_stats,
        regex_errors,
        spilled_runs: parsed.spilled_runs,
        timings,
    })
}

/// Everything the parser threads produced, combined.
struct Combined {
    sources: Vec<sort::Source>,
    mods: Vec<(Vec<u8>, ModRule, Rule)>,
    regexes: Vec<(RegexRule, Rule)>,
    bad_domains: HashMap<Vec<u8>, u8>,
    bad_rules: HashSet<Rule>,
    parse_stats: Vec<ParseStats>,
    spilled_runs: usize,
}

fn parse_all(
    groups: Vec<Vec<(usize, ListInput)>>,
    count: usize,
    dir: &Path,
    opts: &CompileOptions,
) -> io::Result<Combined> {
    let budget = opts.memory_budget / groups.len().max(1);
    let parsed: Vec<io::Result<Parsed>> = std::thread::scope(|s| {
        let handles: Vec<_> = groups
            .into_iter()
            .enumerate()
            .map(|(i, bucket)| {
                let tag = format!("t{i}");
                std::thread::Builder::new()
                    .name(format!("telltale-compile-{i}"))
                    .spawn_scoped(s, move || {
                        lower_priority();
                        parse_bucket(bucket, budget, dir, &tag)
                    })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| match h {
                Ok(h) => h
                    .join()
                    .unwrap_or_else(|_| Err(io::Error::other("compile thread panicked"))),
                Err(e) => Err(e),
            })
            .collect()
    });
    let mut c = Combined {
        sources: Vec::new(),
        mods: Vec::new(),
        regexes: Vec::new(),
        bad_domains: HashMap::new(),
        bad_rules: HashSet::new(),
        parse_stats: vec![ParseStats::default(); count],
        spilled_runs: 0,
    };
    for p in parsed {
        let p = p?;
        c.sources.extend(p.sorter_sources);
        c.spilled_runs += p.runs;
        c.mods.extend(p.mods);
        c.regexes.extend(p.regexes);
        for (k, mask) in p.bad_domains {
            *c.bad_domains.entry(k).or_default() |= mask;
        }
        c.bad_rules.extend(p.bad_rules);
        for (id, st) in p.stats {
            c.parse_stats[id] = st;
        }
    }
    Ok(c)
}

type FstWriter = MapBuilder<BufWriter<File>>;

/// Merges sorted records into the three scope FSTs and `listsets.bin`, applying
/// `$badfilter`. Returns the distinct names per scope.
fn merge_domains(
    sources: Vec<sort::Source>,
    bad_domains: &HashMap<Vec<u8>, u8>,
    dir: &Path,
    lists: usize,
    per_list: &mut [ListCompileStats],
    stats: &mut CompileStats,
) -> Result<[u64; 3], CompileError> {
    let mut sets = ListSetBuilder::new(lists);
    let mut names = [0u64; 3];
    let mut builders: Vec<FstWriter> = SCOPES
        .iter()
        .map(|(_, file)| -> Result<_, CompileError> {
            Ok(MapBuilder::new(BufWriter::new(File::create(
                dir.join(file),
            )?))?)
        })
        .collect::<Result<_, CompileError>>()?;
    let mut flush = |key: &[u8],
                     sets: &mut ListSetBuilder,
                     builders: &mut [FstWriter]|
     -> Result<(), CompileError> {
        let (count, first) = sets.union_count();
        if count == 0 {
            return Ok(()); // every rule on this name was badfiltered
        }
        let id = sets.intern();
        sets.for_each_list(|l| per_list[usize::from(l)].entries += 1);
        if count == 1
            && let Some(l) = first
        {
            per_list[usize::from(l)].unique += 1;
        }
        let scope = usize::from(key[0]);
        names[scope] += 1;
        builders[scope].insert(&key[1..], u64::from(id))?;
        Ok(())
    };
    let mut current: Vec<u8> = Vec::with_capacity(256);
    let mut badfiltered = 0u64;
    let mut merge_err: Option<CompileError> = None;
    let merged = merge(sources, |rec: &Record| {
        if current != rec.key {
            if !current.is_empty()
                && let Err(e) = flush(&current, &mut sets, &mut builders)
            {
                merge_err = Some(e);
                return Err(io::Error::other("merge aborted"));
            }
            sets.clear();
            current.clear();
            current.extend_from_slice(&rec.key);
        }
        if bad_domains
            .get(rec.key.as_slice())
            .is_some_and(|mask| mask & (1 << rec.class) != 0)
        {
            badfiltered += 1;
        } else if let Some(class) = Class::from_u8(rec.class) {
            sets.set(class, rec.list);
        }
        Ok(())
    });
    if let Err(e) = merged {
        return Err(merge_err.take().unwrap_or(CompileError::Io(e)));
    }
    if !current.is_empty() {
        flush(&current, &mut sets, &mut builders)?;
    }
    for b in builders {
        b.into_inner()?.flush()?;
    }
    stats.badfiltered = badfiltered;
    [
        stats.subtree_names,
        stats.exact_names,
        stats.subdomains_names,
    ] = names;
    stats.listsets = sets.len() as u64;
    let mut w = BufWriter::new(File::create(dir.join(snapshot::LISTSETS))?);
    sets.finish().write(&mut w)?;
    w.flush()?;
    Ok(names)
}

/// Writes `modrules.fst` + `modrules.json` and `regex.json`. Returns rejected regexes.
fn write_tables(
    mut mods: Vec<(Vec<u8>, ModRule, Rule)>,
    mut regexes: Vec<(RegexRule, Rule)>,
    bad_rules: &HashSet<Rule>,
    dir: &Path,
    inputs: &[ListMeta],
    per_list: &mut [ListCompileStats],
    stats: &mut CompileStats,
) -> Result<Vec<(String, u32, String)>, CompileError> {
    let before = mods.len() + regexes.len();
    mods.retain(|(_, _, rule)| !bad_rules.contains(rule));
    regexes.retain(|(_, rule)| !bad_rules.contains(rule));
    stats.badfiltered += (before - mods.len() - regexes.len()) as u64;

    mods.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then(a.1.list.cmp(&b.1.list))
            .then(a.1.line.cmp(&b.1.line))
    });
    let mut idx = MapBuilder::new(BufWriter::new(File::create(
        dir.join(snapshot::MODRULES_FST),
    )?))?;
    let mut i = 0;
    while i < mods.len() {
        let mut j = i;
        while j < mods.len() && mods[j].0 == mods[i].0 {
            j += 1;
        }
        idx.insert(&mods[i].0, ((i as u64) << 32) | (j - i) as u64)?;
        i = j;
    }
    idx.into_inner()?.flush()?;
    for (_, m, _) in &mods {
        per_list[usize::from(m.list)].entries += 1;
    }
    let modrules = ModRules {
        rules: mods.into_iter().map(|(_, m, _)| m).collect(),
    };
    stats.modrules = modrules.rules.len() as u64;
    write_json(&dir.join(snapshot::MODRULES), &modrules)?;

    let (kept, regex_errors) = check_regexes(regexes.into_iter().map(|(r, _)| r).collect(), inputs);
    for r in &kept {
        per_list[usize::from(r.list)].entries += 1;
    }
    stats.regexes = kept.len() as u64;
    stats.regex_rejected = regex_errors.len() as u64;
    write_json(&dir.join(snapshot::REGEX), &Regexes { rules: kept })?;
    Ok(regex_errors)
}

/// Hashes every blob and writes `manifest.json`.
fn write_manifest(
    dir: &Path,
    inputs: &[ListMeta],
    version: u64,
    names: [u64; 3],
    mut stats: CompileStats,
) -> Result<Manifest, CompileError> {
    let mut blobs = Vec::new();
    for name in snapshot::BLOBS {
        let data = fs::read(dir.join(name))?;
        blobs.push(Blob {
            name: name.to_owned(),
            blake3: blake3::hash(&data).to_hex().to_string(),
            bytes: data.len() as u64,
        });
    }
    let filter_blobs = [
        snapshot::SUBTREE_FST,
        snapshot::EXACT_FST,
        snapshot::SUBDOMAINS_FST,
        snapshot::LISTSETS,
    ];
    let filter_bytes: u64 = blobs
        .iter()
        .filter(|b| filter_blobs.contains(&b.name.as_str()))
        .map(|b| b.bytes)
        .sum();
    let total_names = names.iter().sum::<u64>();
    #[allow(clippy::cast_precision_loss)] // sizes and counts far below 2^52
    {
        stats.bytes_per_name = if total_names == 0 {
            0.0
        } else {
            (filter_bytes as f64 / total_names as f64 * 100.0).round() / 100.0
        };
    }
    let manifest = Manifest {
        format: snapshot::FORMAT,
        version,
        created: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
        lists: inputs
            .iter()
            .enumerate()
            .map(|(i, l)| ManifestList {
                id: u16::try_from(i).unwrap_or(u16::MAX),
                name: l.name.clone(),
                source_hash: l.source_hash.clone(),
                kind: l.options.kind,
                match_mode: l.options.match_mode,
            })
            .collect(),
        blobs,
        stats,
    };
    write_json(&dir.join(snapshot::MANIFEST), &manifest)?;
    Ok(manifest)
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> io::Result<()> {
    let mut w = BufWriter::new(File::create(path)?);
    serde_json::to_writer(&mut w, value).map_err(io::Error::other)?;
    w.flush()?;
    w.into_inner()
        .map_err(io::IntoInnerError::into_error)?
        .sync_all()
}

/// The regex engine settings shared with the matcher: case-insensitive, linear time.
pub fn regex_builder() -> regex_automata::meta::Builder {
    let mut b = regex_automata::meta::Regex::builder();
    b.syntax(regex_automata::util::syntax::Config::new().case_insensitive(true))
        .configure(
            regex_automata::meta::Config::new()
                .nfa_size_limit(Some(64 << 20))
                .hybrid_cache_capacity(2 << 20),
        );
    b
}

/// Drops regexes the engine won't build (e.g. size limits), reporting each one.
fn check_regexes(
    rules: Vec<RegexRule>,
    inputs: &[ListMeta],
) -> (Vec<RegexRule>, Vec<(String, u32, String)>) {
    let patterns: Vec<&str> = rules.iter().map(|r| r.pattern.as_str()).collect();
    if patterns.is_empty() || regex_builder().build_many(&patterns).is_ok() {
        return (rules, Vec::new());
    }
    let mut kept = Vec::new();
    let mut errors = Vec::new();
    for r in rules {
        match regex_builder().build(&r.pattern) {
            Ok(_) => kept.push(r),
            Err(e) => errors.push((
                inputs[usize::from(r.list)].name.clone(),
                r.line,
                e.to_string(),
            )),
        }
    }
    (kept, errors)
}

#[cfg(test)]
mod tests;
