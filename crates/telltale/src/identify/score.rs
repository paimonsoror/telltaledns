//! Scoring a device against the signatures (REQ: OBS-025, ADR-117): pure, deterministic
//! (f32 arithmetic in a fixed order over sorted inputs), so every node and architecture gives
//! the same answer for the same inputs.

use serde::Serialize;
use telltale_config::DeviceClass;

use super::catalog::Signature;

/// Weights of the three kinds of evidence.
const W_DOMAINS: f32 = 0.60;
const W_VENDOR: f32 = 0.25;
const W_NAME: f32 = 0.15;
/// Levels.
pub(crate) const LIKELY: f32 = 0.60;
pub(crate) const POSSIBLY: f32 = 0.35;
/// A runner-up this close is reported ("could also be …").
const RUNNER_UP_WITHIN: f32 = 0.10;

/// What is known about one device.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, serde::Deserialize)]
pub(crate) struct Inputs {
    /// The MAC's registered vendor (none for an unknown or private address).
    pub(crate) vendor: Option<String>,
    /// The MAC's registry prefix (`D0:4D:2C`), shown with the vendor.
    pub(crate) mac_prefix: Option<String>,
    /// Names it announces (DHCP, mDNS), as given.
    pub(crate) names: Vec<String>,
    /// Registrable domains it talks to, lowercase.
    pub(crate) domains: Vec<String>,
}

impl Inputs {
    /// Sorted and deduplicated, so the result doesn't depend on the order they were found.
    pub(crate) fn normalized(mut self) -> Self {
        self.names.sort();
        self.names.dedup();
        for d in &mut self.domains {
            *d = d.trim_end_matches('.').to_ascii_lowercase();
        }
        self.domains.sort();
        self.domains.dedup();
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Level {
    Likely,
    Possibly,
    Unknown,
}

impl Level {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Likely => "likely",
            Self::Possibly => "possibly",
            Self::Unknown => "unknown",
        }
    }
}

/// The best guess, with its evidence.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct Guess {
    /// `None` when unknown.
    pub(crate) product_id: Option<String>,
    pub(crate) product: Option<String>,
    pub(crate) class: DeviceClass,
    pub(crate) level: Level,
    pub(crate) score: f32,
    pub(crate) vendor: Option<String>,
    pub(crate) mac_prefix: Option<String>,
    /// Matched domains and their weights, by name.
    pub(crate) domains: Vec<(String, f32)>,
    /// The announced name that matched.
    pub(crate) matched_name: Option<String>,
    /// The next best, when it's close: (id, product, score).
    pub(crate) runner_up: Option<(String, String, f32)>,
}

/// Case-insensitive glob with `*` and `?` (`pattern` lowercase).
#[cfg(test)]
pub(crate) fn glob(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.to_lowercase().chars().collect();
    glob_chars(&p, &t)
}

/// [`glob`] over characters already lowercased: no allocation.
fn glob_chars(p: &[char], t: &[char]) -> bool {
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Whether `word` (lowercase) appears in `vendor` as whole words ("ring" in "Ring LLC", not
/// in "Engineering").
#[cfg(test)]
pub(crate) fn vendor_matches(word: &str, vendor: &str) -> bool {
    word_in(word, &vendor.to_lowercase())
}

/// [`vendor_matches`] with the vendor already lowercased.
fn word_in(word: &str, v: &str) -> bool {
    let mut from = 0;
    while let Some(i) = v[from..].find(word) {
        let start = from + i;
        let end = start + word.len();
        let before = v[..start].chars().next_back();
        let after = v[end..].chars().next();
        if !before.is_some_and(char::is_alphanumeric) && !after.is_some_and(char::is_alphanumeric) {
            return true;
        }
        from = start + word.len().max(1);
        if from >= v.len() {
            break;
        }
    }
    false
}

/// One device's inputs, prepared once for every signature.
struct Prepared<'a> {
    inp: &'a Inputs,
    names: Vec<Vec<char>>,
    vendor: Option<String>,
}

impl Prepared<'_> {
    /// The first announced name (they're sorted) a signature's globs match.
    fn name_match(&self, sig: &Signature) -> Option<usize> {
        self.names
            .iter()
            .position(|n| sig.hostname_globs.iter().any(|p| glob_chars(p, n)))
    }
}

/// A signature's score for the device. The arithmetic and its order are fixed: the golden
/// file depends on them.
fn score_value(sig: &Signature, d: &Prepared<'_>) -> f32 {
    let matched: f32 = sig
        .domains
        .iter()
        .filter(|(dom, _)| d.inp.domains.binary_search(dom).is_ok())
        .map(|x| x.1)
        .sum();
    let domain_score = if sig.total_weight > 0.0 {
        matched / sig.total_weight
    } else {
        0.0
    };
    let vendor_match = d
        .vendor
        .as_deref()
        .map(|v| sig.vendors.iter().any(|w| word_in(w, v)));
    let vendor_score = if vendor_match == Some(true) { 1.0 } else { 0.0 };
    let name_score = if d.name_match(sig).is_some() {
        1.0
    } else {
        0.0
    };
    let mut score = W_DOMAINS * domain_score + W_VENDOR * vendor_score + W_NAME * name_score;
    // A known vendor that isn't this product's maker: a Samsung TV running the Roku app is
    // still a Samsung TV.
    if !sig.vendors.is_empty() && vendor_match == Some(false) {
        score *= 0.5;
    }
    if sig.vendor_required && vendor_match != Some(true) {
        score = 0.0;
    }
    score
}

/// The best signature for `inp` (signatures sorted by `id`; ties go to the first).
pub(crate) fn score(sigs: &[Signature], inp: &Inputs) -> Guess {
    let d = Prepared {
        inp,
        names: inp
            .names
            .iter()
            .map(|n| n.to_lowercase().chars().collect())
            .collect(),
        vendor: inp.vendor.as_deref().map(str::to_lowercase),
    };
    // Best and runner-up in one pass; strictly greater keeps the earlier `id` on a tie.
    let mut best: Option<(usize, f32)> = None;
    let mut second: Option<(usize, f32)> = None;
    for (i, sig) in sigs.iter().enumerate() {
        let s = score_value(sig, &d);
        match best {
            Some((_, b)) if s <= b => {
                if second.is_none_or(|(_, x)| s > x) {
                    second = Some((i, s));
                }
            }
            _ => {
                second = best;
                best = Some((i, s));
            }
        }
    }
    let unknown = |score: f32| Guess {
        product_id: None,
        product: None,
        class: DeviceClass::Unknown,
        level: Level::Unknown,
        score,
        vendor: inp.vendor.clone(),
        mac_prefix: inp.mac_prefix.clone(),
        domains: Vec::new(),
        matched_name: None,
        runner_up: None,
    };
    let Some((bi, bs)) = best else {
        return unknown(0.0);
    };
    if bs < POSSIBLY {
        return unknown(bs);
    }
    let sig = &sigs[bi];
    let second = second.filter(|(_, s)| *s > 0.0).map(|(i, s)| (&sigs[i], s));
    let mut level = if bs >= LIKELY {
        Level::Likely
    } else {
        Level::Possibly
    };
    // A tie with another kind of device isn't "likely" (ADR-117, amended).
    if level == Level::Likely && second.is_some_and(|(o, s)| s >= bs && o.class != sig.class) {
        level = Level::Possibly;
    }
    Guess {
        product_id: Some(sig.id.clone()),
        product: Some(sig.name.clone()),
        class: sig.class,
        level,
        score: bs,
        vendor: inp.vendor.clone(),
        mac_prefix: inp.mac_prefix.clone(),
        domains: sig
            .domains
            .iter()
            .filter(|(dom, _)| inp.domains.binary_search(dom).is_ok())
            .cloned()
            .collect(),
        matched_name: d.name_match(sig).map(|i| inp.names[i].clone()),
        runner_up: second
            .filter(|(_, s)| bs - s <= RUNNER_UP_WITHIN)
            .map(|(o, s)| (o.id.clone(), o.name.clone(), s)),
    }
}
