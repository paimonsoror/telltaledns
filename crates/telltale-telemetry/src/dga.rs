//! How random a domain label looks (REQ: OBS-009; `spec/06` §7 "DGA likelihood"; T7.14).
//!
//! Malware that generates its rendezvous domains (a DGA) produces labels like `xjwqkzpvb` or
//! `a8f3k2j9x1`. The score (0 to 1) combines three signals on the registrable domain's own
//! label (`xjwqkzpvb` in `xjwqkzpvb.com`):
//! - **Letter pairs:** the mean surprise, in bits, of each letter following the previous one,
//!   against English word spelling (`presets/bigrams.bin`, built from the public-domain
//!   dwyl/english-words list). Brand names and abbreviations stay under 6.1 bits; random
//!   letters are 7.5 and up.
//! - **Letter/digit switches** (`a8f3k2`): IDs, not words with a number (`office365`).
//! - **Consonant runs** and **character entropy**, as smaller terms.
//!
//! Labels under 8 characters and IDNs (`xn--`) score 0. Words strung together
//! (`redcarpetmountain`) look like English and score low: dictionary DGAs aren't caught.
//!
//! Deterministic: table lookups and basic arithmetic only (no `ln`), so the same name scores
//! the same on every architecture. Off the query path: scored on the aggregator thread, for a
//! device's first-seen domains only.

/// 27 × 27 signed bytes: row = previous letter (`a`..`z`, 26 = start), column = next letter
/// (26 = end); each is `round(4 × log2 P(next | previous))`.
static BIGRAMS: &[u8; 729] = include_bytes!("../../../presets/bigrams.bin");

/// log2(n) for n = 0..=64 (0 for 0).
#[allow(clippy::unreadable_literal, clippy::approx_constant)] // generated
const LOG2: [f64; 65] = [
    0.0,
    0.0,
    1.0,
    1.584962500721156,
    2.0,
    2.321928094887362,
    2.584962500721156,
    2.807354922057604,
    3.0,
    3.169925001442312,
    3.321928094887362,
    3.4594316186372973,
    3.584962500721156,
    3.700439718141092,
    3.807354922057604,
    3.9068905956085187,
    4.0,
    4.087462841250339,
    4.169925001442312,
    4.247927513443585,
    4.321928094887363,
    4.392317422778761,
    4.459431618637297,
    4.523561956057013,
    4.584962500721156,
    4.643856189774724,
    4.700439718141092,
    4.754887502163468,
    4.807354922057604,
    4.857980995127572,
    4.906890595608519,
    4.954196310386875,
    5.0,
    5.044394119358453,
    5.087462841250339,
    5.129283016944966,
    5.169925001442312,
    5.20945336562895,
    5.247927513443585,
    5.285402218862249,
    5.321928094887363,
    5.357552004618084,
    5.392317422778761,
    5.426264754702098,
    5.459431618637297,
    5.491853096329675,
    5.523561956057013,
    5.554588851677638,
    5.584962500721156,
    5.614709844115208,
    5.643856189774724,
    5.672425341971495,
    5.700439718141092,
    5.727920454563199,
    5.754887502163468,
    5.78135971352466,
    5.807354922057604,
    5.832890014164741,
    5.857980995127572,
    5.882643049361842,
    5.906890595608519,
    5.930737337562887,
    5.954196310386875,
    5.977279923499917,
    6.0,
];

/// c × log2(c) for c = 0..=64.
#[allow(clippy::unreadable_literal, clippy::approx_constant)] // generated
const C_LOG2_C: [f64; 65] = [
    0.0,
    0.0,
    2.0,
    4.754887502163468,
    8.0,
    11.60964047443681,
    15.509775004326936,
    19.651484454403228,
    24.0,
    28.52932501298081,
    33.219280948873624,
    38.05374780501027,
    43.01955000865387,
    48.105716335834195,
    53.302968908806456,
    58.60335893412778,
    64.0,
    69.48686830125577,
    75.05865002596161,
    80.71062275542812,
    86.43856189774725,
    92.23866587835397,
    98.10749561002054,
    104.0419249893113,
    110.03910001730775,
    116.09640474436812,
    122.21143267166839,
    128.38196255841365,
    134.6059378176129,
    140.88144885869957,
    147.20671786825557,
    153.58008562199313,
    160.0,
    166.46500593882897,
    172.97373660251154,
    179.5249055930738,
    186.11730005192322,
    192.74977452827116,
    199.42124551085624,
    206.1306865356277,
    212.8771237954945,
    219.65963218934144,
    226.47733175670794,
    233.3293844521902,
    240.21499122004107,
    247.13338933483536,
    254.0838499786226,
    261.06567602884894,
    268.0782000346155,
    275.1207823616452,
    282.1928094887362,
    289.29369244054624,
    296.42286534333675,
    303.57978409184955,
    310.7639251168273,
    317.9747842438563,
    325.2118756352258,
    332.47473080739024,
    339.76289771739914,
    347.07593991234864,
    354.41343573651113,
    361.7749775913361,
    369.16017124398627,
    376.56863518049477,
    384.0,
];

fn clamp01(x: f64) -> f64 {
    x.clamp(0.0, 1.0)
}

fn bigram(prev: usize, next: usize) -> f64 {
    f64::from(i8::from_ne_bytes([BIGRAMS[prev * 27 + next]]))
}

/// The score of one label (ASCII; case is ignored): 0 = looks like a word or a brand, 1 =
/// looks generated.
pub fn score(label: &[u8]) -> f32 {
    let n = label.len();
    if !(8..=63).contains(&n) || label[..4].eq_ignore_ascii_case(b"xn--") {
        return 0.0;
    }
    let lower = |b: u8| b.to_ascii_lowercase();
    // Letter pairs, start and end included; a digit or hyphen restarts the word.
    let (mut total, mut pairs, mut prev) = (0.0f64, 0u32, 26usize);
    for &b in label {
        let b = lower(b);
        if b.is_ascii_lowercase() {
            let c = usize::from(b - b'a');
            total += bigram(prev, c);
            pairs += 1;
            prev = c;
        } else {
            prev = 26;
        }
    }
    total += bigram(prev, 26);
    pairs += 1;
    let bits = -total / f64::from(pairs) / 4.0;
    let s_bigram = clamp01((bits - 6.0) / 2.0);
    // Longest consonant run.
    let (mut run, mut best) = (0u32, 0u32);
    for &b in label {
        let b = lower(b);
        if b.is_ascii_lowercase() && !b"aeiouy".contains(&b) {
            run += 1;
            best = best.max(run);
        } else {
            run = 0;
        }
    }
    let s_cons = clamp01((f64::from(best) - 5.0) / 3.0);
    // Letter/digit switches.
    let switches = label
        .windows(2)
        .filter(|w| w[0].is_ascii_digit() != w[1].is_ascii_digit())
        .count();
    let s_mix = clamp01((f64::from(u8::try_from(switches).unwrap_or(u8::MAX)) - 2.0) / 4.0);
    // Character entropy against the most a label of this length can have.
    let mut freq = [0u8; 256];
    for &b in label {
        freq[usize::from(lower(b))] += 1;
    }
    let sum: f64 = freq.iter().map(|&c| C_LOG2_C[usize::from(c)]).sum();
    let h = LOG2[n] - sum / f64::from(u8::try_from(n).unwrap_or(u8::MAX));
    let s_ent = clamp01((h / LOG2[n.min(36)] - 0.85) / 0.15);
    let s = 0.7 * s_bigram.max(s_mix) + 0.2 * s_cons + 0.1 * s_ent;
    #[allow(clippy::cast_possible_truncation)] // 0..=1
    let s = s as f32;
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: OBS-009 — DGA scores match the reference implementation that calibrated them
    /// (generated labels high; brands, abbreviations, words, short labels, and IDNs low).
    #[test]
    fn obs_009_dga_scores() {
        for (label, want) in [
            ("xjwqkzpvb", 1.0),
            ("qwhdkzlmpx", 1.0),
            ("a8f3k2j9x1", 0.8),
            ("f3a9c2e8b1d7", 0.8),
            ("kjhgfdsaqw", 0.933),
            ("nqmpsfhkxt", 0.873),
            ("google", 0.0),
            ("msftconnecttest", 0.0),
            ("googlesyndication", 0.0),
            ("nflxvideo", 0.1),
            ("office365", 0.078),
            ("jsdelivr", 0.1),
            ("tiktokcdn", 0.033),
            ("redcarpetmountain", 0.004),
            ("xn--bcher-kva", 0.0),
            ("short", 0.0),
            ("myq-cloud", 0.1),
            ("akamaitechnologies", 0.004),
        ] {
            let got = score(label.as_bytes());
            assert!(
                (f64::from(got) - want).abs() < 0.001,
                "{label}: {got} vs {want}"
            );
        }
        assert!((score(b"XJWQKZPVB") - 1.0).abs() < 1e-6, "case-insensitive");
    }
}
