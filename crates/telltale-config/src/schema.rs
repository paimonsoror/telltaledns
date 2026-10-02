//! The TelltaleDNS configuration schema (`telltale.toml`).
//!
//! REQ: OPS-005 — every struct uses `deny_unknown_fields`; defaults live here so the
//! file only needs to say what differs. Sections mirror `spec/03`, `04`, `06`, `08`, `12`.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::types::{ByteSize, SafeString};

/// Current config schema version. Bump with a migration when the schema changes incompatibly.
pub const CONFIG_VERSION: u32 = 1;

/// Root of `telltale.toml`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Schema version of this file (currently 1).
    pub config_version: u32,
    /// This node's role and local settings.
    pub node: NodeConfig,
    /// Cluster identity (full cluster settings arrive with M5).
    pub cluster: ClusterConfig,
    /// DNS listeners. Setting `[[listen]]` replaces the defaults entirely.
    pub listen: Vec<Listener>,
    /// Upstream resolvers.
    pub upstream: Vec<Upstream>,
    /// Named groups of upstreams with a selection strategy.
    pub upstream_group: Vec<UpstreamGroup>,
    /// Per-domain / per-group / per-qtype routing to upstream groups.
    pub route: Vec<Route>,
    /// Response cache.
    pub cache: CacheConfig,
    /// Telemetry, query log, and metrics.
    pub telemetry: TelemetryConfig,
}

impl Default for Config {
    fn default() -> Self {
        let any4 = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let any6 = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
        Self {
            config_version: CONFIG_VERSION,
            node: NodeConfig::default(),
            cluster: ClusterConfig::default(),
            // REQ: DNS-001 — UDP and TCP on IPv4 and IPv6 by default.
            listen: vec![
                Listener::plain(ListenProto::Udp, SocketAddr::new(any4, 53)),
                Listener::plain(ListenProto::Tcp, SocketAddr::new(any4, 53)),
                Listener::plain(ListenProto::Udp, SocketAddr::new(any6, 53)),
                Listener::plain(ListenProto::Tcp, SocketAddr::new(any6, 53)),
            ],
            upstream: Vec::new(),
            upstream_group: Vec::new(),
            route: Vec::new(),
            cache: CacheConfig::default(),
            telemetry: TelemetryConfig::default(),
        }
    }
}

/// Process role (`spec/02` §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Resolver + controller in one process (Pi / single node).
    #[default]
    All,
    /// Data plane only.
    Resolver,
    /// Control plane only.
    Controller,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct NodeConfig {
    /// Process role.
    pub role: Role,
    /// Node name; empty means the hostname.
    pub name: SafeString,
    /// UDP worker threads; 0 means `min(cgroup CPU limit, cores)`.
    pub workers: u16,
    /// The only writable directory (snapshots, state.db, query log).
    pub data_dir: SafeString,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            role: Role::All,
            name: SafeString::default(),
            workers: 0,
            data_dir: SafeString::from("/var/lib/telltale"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct ClusterConfig {
    /// Cluster name.
    pub name: SafeString,
    /// Site label used to group nodes in the UI (e.g. `home-pi`, `k8s`).
    pub site: SafeString,
    /// Whether this node may become the cluster primary.
    pub eligible: bool,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            name: SafeString::from("telltale"),
            site: SafeString::from("default"),
            eligible: true,
        }
    }
}

/// Listener protocol (DNS-001..004).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ListenProto {
    Udp,
    Tcp,
    Dot,
    Doh,
    Doh3,
    Doq,
}

impl ListenProto {
    /// Protocols that require a TLS certificate.
    pub const fn needs_tls(self) -> bool {
        matches!(self, Self::Dot | Self::Doh | Self::Doh3 | Self::Doq)
    }
    /// HTTP-based protocols (have a URL path).
    pub const fn is_http(self) -> bool {
        matches!(self, Self::Doh | Self::Doh3)
    }
    /// Stream protocols over TCP (where PROXY protocol v2 applies).
    pub const fn is_tcp_based(self) -> bool {
        matches!(self, Self::Tcp | Self::Dot | Self::Doh)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Listener {
    /// `udp`, `tcp`, `dot`, `doh`, `doh3`, or `doq`.
    pub proto: ListenProto,
    /// Address and port to bind.
    pub addr: SocketAddr,
    /// URL path for DoH (default `/dns-query`; `/dns-query/{client-id}` also matches).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<SafeString>,
    /// Certificate and key (required for dot/doh/doh3/doq; reloaded on change).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsFiles>,
    /// Accept PROXY protocol v2 (TCP-based listeners only).
    #[serde(default)]
    pub proxy_protocol: bool,
}

impl Listener {
    fn plain(proto: ListenProto, addr: SocketAddr) -> Self {
        Self {
            proto,
            addr,
            path: None,
            tls: None,
            proxy_protocol: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TlsFiles {
    pub cert: SafeString,
    pub key: SafeString,
}

/// DoH HTTP version preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub enum HttpVersion {
    /// Try HTTP/3 via Alt-Svc and fall back to HTTP/2.
    #[default]
    #[serde(rename = "auto")]
    Auto,
    #[serde(rename = "2")]
    H2,
    #[serde(rename = "3")]
    H3,
}

/// One upstream resolver (`spec/04` §1–2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    /// Unique name referenced by upstream groups.
    pub name: SafeString,
    /// Scheme selects the protocol: `udp://`, `tcp://`, `tls://`, `https://`, `h3://`,
    /// `quic://`, `sdns://`, `recursive://`, `unix://`, `exec://`.
    pub url: SafeString,
    /// TLS SNI / certificate name override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_server_name: Option<SafeString>,
    /// Pinned IPs used to resolve a hostname URL (UPS-009).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bootstrap: Vec<IpAddr>,
    /// Weight for the `weighted` strategy.
    #[serde(default = "default_weight")]
    pub weight: u32,
    /// Per-attempt timeout in milliseconds.
    #[serde(default = "default_upstream_timeout_ms")]
    pub timeout_ms: u32,
    /// DoH HTTP version: `"auto"`, `"2"`, or `"3"`.
    #[serde(default)]
    pub http_version: HttpVersion,
    /// Extra HTTP headers for DoH (e.g. an auth token).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<SafeString, SafeString>,
    /// Max pooled connections for TCP/DoT/DoH.
    #[serde(default = "default_pool_size")]
    pub pool_size: u16,
    /// Idle connection timeout in milliseconds.
    #[serde(default = "default_idle_timeout_ms")]
    pub idle_timeout_ms: u32,
    /// Base64 SHA-256 SPKI pins.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub spki_pins: Vec<SafeString>,
    /// Disable certificate verification (dangerous; logs a warning).
    #[serde(default)]
    pub tls_insecure_skip_verify: bool,
    /// `socks5://host:port` or `http://host:port` proxy (P1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<SafeString>,
    /// ECS handling: `strip` (default), `pass`, or a CIDR to substitute (P1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecs: Option<SafeString>,
    /// Free-form labels.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<SafeString>,
}

const fn default_weight() -> u32 {
    1
}
// 02 §8: 400 ms per attempt by default.
const fn default_upstream_timeout_ms() -> u32 {
    400
}
const fn default_pool_size() -> u16 {
    4
}
const fn default_idle_timeout_ms() -> u32 {
    30_000
}
const fn default_parallel_fanout() -> u8 {
    2
}

/// Upstream selection strategy (UPS-005).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Strategy {
    #[default]
    Failover,
    RoundRobin,
    Weighted,
    Fastest,
    Parallel,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpstreamGroup {
    /// Unique group name. Queries that match no route use the group named `default`.
    pub name: SafeString,
    /// Upstream names, in priority order for `failover`.
    pub members: Vec<SafeString>,
    #[serde(default)]
    pub strategy: Strategy,
    /// How many members to race (strategy `parallel` only).
    #[serde(default = "default_parallel_fanout")]
    pub parallel_fanout: u8,
}

/// Conditional forwarding / routing rule (UPS-007, DNS-017).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Route {
    /// Domain suffixes (subtree match), e.g. `corp.example.com`, `168.192.in-addr.arpa`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub match_suffix: Vec<SafeString>,
    /// Client group names this route applies to (empty = all).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub match_group: Vec<SafeString>,
    /// Query types this route applies to, e.g. `["PTR"]` (empty = all).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub match_qtype: Vec<SafeString>,
    /// Target upstream group.
    pub upstream_group: SafeString,
    /// Add a DNSSEC negative trust anchor for the suffixes (local zones are usually unsigned).
    #[serde(default)]
    pub dnssec_nta: bool,
}

/// Cache settings (`spec/03` §4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct CacheConfig {
    /// Memory budget for cached responses.
    pub max_bytes: ByteSize,
    /// Optional cap on entry count (0 = limited by bytes only).
    pub max_entries: u32,
    /// Minimum TTL served, seconds.
    pub min_ttl: u32,
    /// Maximum TTL served, seconds.
    pub max_ttl: u32,
    /// Cap for negative-answer TTLs, seconds (RFC 2308).
    pub negative_ttl_max: u32,
    /// How long SERVFAIL is cached, seconds (RFC 9520).
    pub servfail_ttl: u32,
    /// Serve expired answers when upstreams fail (RFC 8767, DNS-007).
    pub serve_stale: bool,
    /// How long expired entries are kept for serve-stale, seconds.
    pub stale_max_age: u32,
    /// Answer from stale data if upstreams haven't replied within this many ms.
    pub stale_answer_client_timeout_ms: u32,
    /// TTL on stale answers, seconds.
    pub stale_answer_ttl: u32,
    /// Refresh hot entries before they expire (DNS-008).
    pub prefetch: bool,
    /// Prefetch when remaining TTL drops below this percentage.
    pub prefetch_threshold_pct: u8,
    /// Minimum hits before an entry is prefetched.
    pub prefetch_min_hits: u32,
    /// Dump the cache on shutdown and reload it on start (DNS-009).
    pub persist: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_bytes: ByteSize::mib(32),
            max_entries: 0,
            min_ttl: 0,
            max_ttl: 86_400,
            negative_ttl_max: 3_600,
            servfail_ttl: 5,
            serve_stale: true,
            stale_max_age: 86_400,
            stale_answer_client_timeout_ms: 1_800,
            stale_answer_ttl: 30,
            prefetch: true,
            prefetch_threshold_pct: 10,
            prefetch_min_hits: 3,
            persist: false,
        }
    }
}

/// Where detailed query events go (`spec/12` CLU-007).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum TelemetryMode {
    /// Keep the query log on this node.
    #[default]
    Local,
    /// Ship events to the controller (store-and-forward); good for SD-card nodes.
    Ship,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct TelemetryConfig {
    pub mode: TelemetryMode,
    /// Per-worker event ring size (power of two).
    pub ring_slots: u32,
    pub qlog: QlogConfig,
    pub metrics: MetricsConfig,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            mode: TelemetryMode::Local,
            ring_slots: 65_536,
            qlog: QlogConfig::default(),
            metrics: MetricsConfig::default(),
        }
    }
}

/// Query-log store (`spec/06` §4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct QlogConfig {
    pub enabled: bool,
    /// Delete segments older than this many days.
    pub retention_days: u32,
    /// Delete oldest segments beyond this total size.
    pub retention_bytes: ByteSize,
    /// 0 full; 1 hide domains; 2 hide domains + clients; 3 aggregates only.
    pub privacy_level: u8,
    /// fsync each block flush.
    pub fsync: bool,
    /// Flush the in-progress block after this many seconds.
    pub flush_interval_secs: u32,
}

impl Default for QlogConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            retention_days: 30,
            retention_bytes: ByteSize::gib(2),
            privacy_level: 0,
            fsync: false,
            flush_interval_secs: 10,
        }
    }
}

/// Prometheus endpoint (OBS-005).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub listen: SocketAddr,
    /// Export per-client series (high cardinality; capped).
    pub per_client: bool,
    pub per_client_cap: u32,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 9153),
            per_client: false,
            per_client_cap: 256,
        }
    }
}
