//! Prometheus text exposition format (version 0.0.4) writer. REQ: OBS-005.

// Microsecond sums only lose f64 precision past 2^52 us (~142 years of latency).
#![allow(clippy::cast_precision_loss)]

use std::fmt::Write as _;

use crate::{BUCKETS_US, Path, Proto, QTYPES, Snapshot, Status};

/// RCODE names (RFC 6895 registry, 0-15).
const RCODES: [&str; 16] = [
    "NOERROR",
    "FORMERR",
    "SERVFAIL",
    "NXDOMAIN",
    "NOTIMP",
    "REFUSED",
    "YXDOMAIN",
    "YXRRSET",
    "NXRRSET",
    "NOTAUTH",
    "NOTZONE",
    "DSOTYPENI",
    "RCODE12",
    "RCODE13",
    "RCODE14",
    "RCODE15",
];

/// Content type for `/metrics`.
pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Builds a scrape body. Each metric family is declared once with `HELP`/`TYPE`.
#[derive(Debug, Default)]
pub struct PromWriter {
    out: String,
}

/// Escapes a label value (backslash, quote, newline).
fn escape(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn labels(pairs: &[(&str, &str)]) -> String {
    if pairs.is_empty() {
        return String::new();
    }
    let inner: Vec<String> = pairs
        .iter()
        .map(|(k, v)| format!("{k}=\"{}\"", escape(v)))
        .collect();
    format!("{{{}}}", inner.join(","))
}

impl PromWriter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Declares a metric family.
    pub fn family(&mut self, name: &str, kind: &str, help: &str) -> &mut Self {
        let _ = writeln!(self.out, "# HELP {name} {help}");
        let _ = writeln!(self.out, "# TYPE {name} {kind}");
        self
    }

    /// One sample.
    pub fn sample(
        &mut self,
        name: &str,
        pairs: &[(&str, &str)],
        value: impl std::fmt::Display,
    ) -> &mut Self {
        let _ = writeln!(self.out, "{name}{} {value}", labels(pairs));
        self
    }

    pub fn finish(self) -> String {
        self.out
    }

    /// Query counters and latency histograms from a [`Snapshot`].
    pub fn queries(&mut self, s: &Snapshot) -> &mut Self {
        self.family(
            "telltale_queries_total",
            "counter",
            "DNS queries by transport and outcome.",
        );
        for proto in Proto::ALL {
            for status in Status::ALL {
                let v = s.queries[proto as usize][status as usize];
                self.sample(
                    "telltale_queries_total",
                    &[("proto", proto.label()), ("status", status.label())],
                    v,
                );
            }
        }
        self.family(
            "telltale_queries_by_qtype_total",
            "counter",
            "DNS queries by query type (top 12 + other).",
        );
        for (i, (_, name)) in QTYPES.iter().enumerate() {
            self.sample(
                "telltale_queries_by_qtype_total",
                &[("qtype", name)],
                s.qtypes[i],
            );
        }
        self.sample(
            "telltale_queries_by_qtype_total",
            &[("qtype", "other")],
            s.qtypes[QTYPES.len()],
        );

        self.family("telltale_responses_total", "counter", "Responses by RCODE.");
        for (i, name) in RCODES.iter().enumerate() {
            if s.rcodes[i] > 0 || i <= 5 {
                self.sample("telltale_responses_total", &[("rcode", name)], s.rcodes[i]);
            }
        }
        self.sample(
            "telltale_responses_total",
            &[("rcode", "EXTENDED")],
            s.rcodes[16],
        );

        self.family(
            "telltale_query_duration_seconds",
            "histogram",
            "Time from receiving a query to having its answer, by path.",
        );
        for path in Path::ALL {
            let p = path as usize;
            let mut cumulative = 0u64;
            for (b, ub) in BUCKETS_US.iter().enumerate() {
                cumulative += s.buckets[p][b];
                let le = format!("{}", *ub as f64 / 1e6);
                self.sample(
                    "telltale_query_duration_seconds_bucket",
                    &[("path", path.label()), ("le", &le)],
                    cumulative,
                );
            }
            cumulative += s.buckets[p][BUCKETS_US.len()];
            self.sample(
                "telltale_query_duration_seconds_bucket",
                &[("path", path.label()), ("le", "+Inf")],
                cumulative,
            );
            self.sample(
                "telltale_query_duration_seconds_sum",
                &[("path", path.label())],
                s.sum_us[p] as f64 / 1e6,
            );
            self.sample(
                "telltale_query_duration_seconds_count",
                &[("path", path.label())],
                cumulative,
            );
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::Metrics;

    #[test]
    fn obs_005_text_format() {
        let m = Metrics::new(1);
        m.record(
            Proto::Udp,
            Status::Cached,
            Some(0),
            1,
            Duration::from_micros(40),
        );
        m.record(
            Proto::Udp,
            Status::Forwarded,
            Some(0),
            28,
            Duration::from_millis(30),
        );
        let mut w = PromWriter::new();
        w.queries(&m.snapshot());
        w.family("telltale_build_info", "gauge", "Build information.")
            .sample(
                "telltale_build_info",
                &[("version", "0.1.0"), ("odd", "a\"b\\c")],
                1,
            );
        let text = w.finish();
        assert!(text.contains("# TYPE telltale_queries_total counter"));
        assert!(text.contains("telltale_queries_total{proto=\"udp\",status=\"cached\"} 1"));
        assert!(
            text.contains(
                "telltale_query_duration_seconds_bucket{path=\"cache\",le=\"0.00005\"} 1"
            )
        );
        assert!(
            text.contains(
                "telltale_query_duration_seconds_bucket{path=\"upstream\",le=\"0.025\"} 0"
            )
        );
        assert!(
            text.contains(
                "telltale_query_duration_seconds_bucket{path=\"upstream\",le=\"0.05\"} 1"
            )
        );
        assert!(text.contains("telltale_query_duration_seconds_count{path=\"upstream\"} 1"));
        assert!(text.contains("telltale_queries_by_qtype_total{qtype=\"AAAA\"} 1"));
        assert!(text.contains("odd=\"a\\\"b\\\\c\""), "label values escaped");
        // Every family is declared exactly once.
        assert_eq!(text.matches("# TYPE telltale_queries_total").count(), 1);
    }
}
