//! The TelltaleDNS configuration schema (`telltale.toml`).
//!
//! REQ: OPS-005 — every struct uses `deny_unknown_fields`; defaults live here so the
//! file only needs to say what differs. Sections mirror `spec/03`, `04`, `06`, `08`, `12`.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::types::{ByteSize, Cidr, SafeString};

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
    /// Local DNS records answered authoritatively (DNS-010).
    pub record: Vec<LocalRecord>,
    /// REQ: DNS-018 (T7.22) — authoritative zones, optionally per group (split horizon).
    pub zone: Vec<ZoneConfig>,
    /// Local data settings (hosts files, PTR generation).
    pub local: LocalConfig,
    /// Filter lists: blocklists and allowlists from URLs, files, or inline rules (`spec/05`).
    pub list: Vec<FilterList>,
    /// Client groups (FLT-005). A `default` group (every list) exists even if not declared.
    pub group: Vec<GroupConfig>,
    /// REQ: FLT-010 (T7.10) — weekly schedules that groups use (`schedules` in a group).
    pub schedule: Vec<ScheduleConfig>,
    /// REQ: OBS-010 (T7.12) — alert rules and where they go.
    pub alerts: AlertsConfig,
    /// REQ: T8.2 — routers whose DHCP names devices (UniFi, OPNsense).
    pub router: Vec<RouterConfig>,
    /// Known devices and how to recognize them (FLT-006).
    pub client: Vec<ClientConfig>,
    /// Quick rules (T6.12, ADR-067): allow or block a domain for some devices, some groups,
    /// or everyone, optionally until a time. They decide before any list.
    pub rule: Vec<RuleConfig>,
    /// Client identification settings.
    pub clients: ClientsConfig,
    /// List download and compile settings.
    pub filter: FilterConfig,
    /// Who may query (refuse everyone else).
    pub access: AccessConfig,
    /// Per-client query rate limits (DNS-014).
    pub ratelimit: RateLimitConfig,
    /// REQ: OBS-022 (T12.1) — names and devices kept out of the query log and analytics.
    #[serde(skip_serializing_if = "ExclusionsConfig::is_default")]
    pub exclusions: ExclusionsConfig,
    /// REQ: DNS-005 — settings of the DNS answers themselves.
    pub dns: DnsConfig,
    /// Special-name handling (RFC 6761 etc.).
    pub special: SpecialConfig,
    /// Response cache.
    pub cache: CacheConfig,
    /// DNSSEC validation of forwarded answers (DNS-011).
    pub dnssec: DnssecConfig,
    /// AI agents and automation using agent tokens (AGT-004, AGT-009). Shared across a
    /// cluster, so `enabled = false` switches every agent off everywhere.
    pub agents: AgentsConfig,
    /// Whether to check for newer builds (OPS-004, ADR-046).
    pub updates: UpdatesConfig,
    /// Telemetry, query log, and metrics.
    pub telemetry: TelemetryConfig,
    /// REQ: OBS-016 (T11.1) — service-level objectives: how reliably and how fast DNS should
    /// answer, the error budget that leaves, and how fast it's being spent.
    pub slo: SloConfig,
    /// REQ: OBS-020 (T11.3) — synthetic probes: each DNS listener asked through its own
    /// protocol on a schedule, plus extra targets; TLS certificate expiry.
    pub probe: ProbeConfig,
    /// REQ: OBS-019 (T11.4) — second opinions: a sample of forwarded questions asked again of
    /// another upstream, and the answers compared. Off by default.
    pub upstream_check: UpstreamCheckConfig,
    /// The REST API (and, later, the web UI).
    pub api: ApiConfig,
    /// Sign-in: sessions, HTTP Basic, two-factor policy (API-003).
    pub auth: AuthConfig,
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
            record: Vec::new(),
            local: LocalConfig::default(),
            list: Vec::new(),
            group: Vec::new(),
            schedule: Vec::new(),
            zone: Vec::new(),
            alerts: AlertsConfig::default(),
            router: Vec::new(),
            client: Vec::new(),
            rule: Vec::new(),
            clients: ClientsConfig::default(),
            filter: FilterConfig::default(),
            access: AccessConfig::default(),
            ratelimit: RateLimitConfig::default(),
            exclusions: ExclusionsConfig::default(),
            dns: DnsConfig::default(),
            special: SpecialConfig::default(),
            cache: CacheConfig::default(),
            dnssec: DnssecConfig::default(),
            agents: AgentsConfig::default(),
            updates: UpdatesConfig::default(),
            telemetry: TelemetryConfig::default(),
            slo: SloConfig::default(),
            probe: ProbeConfig::default(),
            upstream_check: UpstreamCheckConfig::default(),
            api: ApiConfig::default(),
            auth: AuthConfig::default(),
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
    /// REQ: OPS-007 — on shutdown, keep answering this many seconds after reporting not ready,
    /// so load balancers and Kubernetes Services stop sending queries first (the Helm charts
    /// set 5). 0 stops as soon as in-flight lookups finish. At most 60.
    pub drain_delay_secs: u32,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            role: Role::All,
            name: SafeString::default(),
            workers: 0,
            data_dir: SafeString::from("/var/lib/telltale"),
            drain_delay_secs: 0,
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
    /// The cluster port (mTLS, node-to-node; REQ: CLU-001). Opened only once this node has
    /// joined or created a cluster (`telltale cluster init|join`). Peers dial the URLs given
    /// with `--advertise`, so map this port to those.
    pub listen: SafeString,
    /// How this node's own configuration is managed (ADR-048): `file` (edited on the node or
    /// in its UI) or `gitops` (rendered from Git, e.g. by the Helm chart under Argo CD). In a
    /// cluster whose config authority is `gitops`, only `gitops` nodes may become primary.
    pub config_source: SafeString,
    /// Create a cluster on first start when this node isn't in one (CLU-009; the Helm chart's
    /// controller). Same as `telltale cluster init`.
    pub init: Option<ClusterInitConfig>,
    /// A shared join secret, in a file (e.g. a Kubernetes Secret). A node holding the cluster
    /// key accepts it like a join token that never expires; a node with `join_url` joins with
    /// it on first start.
    pub bootstrap_secret_file: Option<SafeString>,
    /// On first start, join the cluster at this URL with `bootstrap_secret_file` (resolver
    /// pods). The node checks the primary proves it knows the secret before trusting its CA.
    pub join_url: Option<SafeString>,
    /// Join as an ephemeral member (CLU-009): never primary, never a voter, dropped from the
    /// registry `ephemeral_ttl_secs` after it was last heard from, shown grouped by site.
    /// An ephemeral node reports ready only once it has the cluster's configuration.
    pub ephemeral: bool,
    /// How long the primary keeps an ephemeral member it no longer hears from.
    pub ephemeral_ttl_secs: u32,
    /// Take the cluster's shared configuration from a Git repository (ADR-049): the primary
    /// fetches it, validates it, and publishes it to every node. Set it on every node that
    /// may become primary.
    pub git: Option<GitSourceConfig>,
}

/// `[cluster.git]`: the cluster's configuration from a file in a Git repository (ADR-049).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GitSourceConfig {
    /// The repository's HTTPS URL, e.g. `https://github.com/me/homelab`.
    pub repo: SafeString,
    /// Branch, tag, or commit ID.
    #[serde(rename = "ref", default = "default_git_ref")]
    pub git_ref: SafeString,
    /// The TelltaleDNS file with the shared settings, e.g. `telltale/shared.toml`.
    pub path: SafeString,
    /// A file with an access token (or `user:password`) for private repositories.
    #[serde(default)]
    pub credentials_file: Option<SafeString>,
    /// How often to check the ref, in seconds.
    #[serde(default = "default_git_poll")]
    pub poll_secs: u32,
    /// Accept only commits SSH-signed by a key in `allowed_signers_file`.
    #[serde(default)]
    pub require_signed: bool,
    /// `git`'s allowed-signers format: `<principal> ssh-ed25519 <key>` per line.
    #[serde(default)]
    pub allowed_signers_file: Option<SafeString>,
    /// Accept a commit that doesn't descend from the one in use (a force-push or rewind).
    #[serde(default)]
    pub allow_rewind: bool,
    /// Largest file accepted.
    #[serde(default = "default_git_max")]
    pub max_bytes: ByteSize,
    /// A file with the secret for `POST /api/v1/hooks/git` (GitHub's `X-Hub-Signature-256`),
    /// which checks the ref at once instead of at the next poll.
    #[serde(default)]
    pub webhook_secret_file: Option<SafeString>,
}

fn default_git_ref() -> SafeString {
    SafeString::from("main")
}

fn default_git_poll() -> u32 {
    60
}

fn default_git_max() -> ByteSize {
    ByteSize::mib(1)
}

/// `[cluster.init]`: create a cluster on first start.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClusterInitConfig {
    /// URLs other nodes reach this node's cluster port at.
    pub advertise: Vec<SafeString>,
    /// `api` or `gitops` (ADR-048).
    #[serde(default = "default_init_authority")]
    pub config_authority: SafeString,
}

fn default_init_authority() -> SafeString {
    SafeString::from("api")
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            name: SafeString::from("telltale"),
            site: SafeString::from("default"),
            eligible: true,
            listen: SafeString::from("0.0.0.0:8443"),
            config_source: SafeString::from("file"),
            init: None,
            bootstrap_secret_file: None,
            join_url: None,
            ephemeral: false,
            ephemeral_ttl_secs: 600,
            git: None,
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
    /// Connections open at once on this listener (default 1,024); more are refused. Not for
    /// `udp`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<u32>,
    /// Connections open at once from one client address, an IPv6 /64 counting as one (default
    /// 32; 0 = no limit), so one host can't take every slot. The address is the client's:
    /// from the PROXY header when `proxy_protocol` is on. Behind a load balancer that hides
    /// client addresses (no PROXY protocol, source NAT), raise it or set 0. Not for `udp`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connections_per_address: Option<u32>,
}

impl Listener {
    fn plain(proto: ListenProto, addr: SocketAddr) -> Self {
        Self {
            proto,
            addr,
            path: None,
            tls: None,
            proxy_protocol: false,
            max_connections: None,
            max_connections_per_address: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TlsFiles {
    pub cert: SafeString,
    pub key: SafeString,
}

/// REQ: UPS-011 (T9.9) — the DoH request method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub enum DohMethod {
    #[default]
    #[serde(rename = "post")]
    Post,
    #[serde(rename = "get")]
    Get,
}

impl DohMethod {
    pub fn is_post(&self) -> bool {
        *self == Self::Post
    }
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
    /// DNS servers used to resolve a hostname URL (UPS-009); default: the system resolvers
    /// from /etc/resolv.conf, minus our own listeners. To pin the server address instead, put
    /// the IP in the URL and set `tls_server_name`.
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
    /// REQ: UPS-011 (T9.9) — DoH request method: `post` (default) or `get` (RFC 8484 §4.1:
    /// the query in `?dns=`, which some providers and HTTP caches prefer).
    #[serde(default, skip_serializing_if = "DohMethod::is_post")]
    pub doh_method: DohMethod,
    /// Extra HTTP headers for DoH (e.g. an auth token).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<SafeString, SafeString>,
    /// Max pooled connections for TCP/DoT/DoH.
    #[serde(default = "default_pool_size")]
    pub pool_size: u16,
    /// Idle connection timeout in milliseconds.
    #[serde(default = "default_idle_timeout_ms")]
    pub idle_timeout_ms: u32,
    /// Base64 SHA-256 SPKI pins: the server's key must match one (see `docs/running.md`,
    /// "Pinning and client certificates", for how to get a server's pin).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub spki_pins: Vec<SafeString>,
    /// REQ: UPS-011 (T7.16) — a PEM file of CA certificates to trust for this upstream.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_ca: Option<SafeString>,
    /// A client certificate and key (PEM files) for servers that require one (mTLS).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_client_cert: Option<SafeString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_client_key: Option<SafeString>,
    /// Disable certificate verification (dangerous; logs a warning).
    #[serde(default)]
    pub tls_insecure_skip_verify: bool,
    /// `socks5://host:port` or `http://host:port` proxy (P1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<SafeString>,
    /// REQ: UPS-003 (T9.9) — an anonymized DNSCrypt relay for a DNSCrypt (`sdns://`)
    /// upstream: a relay stamp (`sdns://g…`) or `ip:port`. The relay sees who asks but not
    /// what; the resolver sees what is asked but not by whom.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<SafeString>,
    /// REQ: DNS-015 (T7.23) — EDNS Client Subnet: `strip` (default: clients' subnets are
    /// never sent), a subnet to send instead (`203.0.113.0/24`), so CDNs answer for that
    /// area without learning client addresses, or (T9.9) `client`: each client's own /24
    /// (IPv4) or /56 (IPv6), for public clients only, with answers cached per subnet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecs: Option<SafeString>,
    /// Free-form labels.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<SafeString>,
    /// REQ: UPS-011 (T7.16) — `exec://` only: the plugin program's arguments.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<SafeString>,
    /// REQ: DNS-012 (T7.15) — `recursive://` only: how the resolver asks the root servers
    /// and below.
    #[serde(default, skip_serializing_if = "RecursiveConfig::is_default")]
    pub recursive: RecursiveConfig,
}

/// Options for a `recursive://` upstream (`spec/03` §6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct RecursiveConfig {
    /// RFC 9156: each server sees only as much of the name as it needs.
    pub qname_minimization: bool,
    /// 0x20: random letter case in queries, checked in answers (spoofing defense; servers
    /// that don't echo the case are asked again without it).
    pub case_randomization: bool,
    /// Ask servers over IPv6 too (needs an IPv6 route to the Internet).
    pub ipv6: bool,
}

impl Default for RecursiveConfig {
    fn default() -> Self {
        Self {
            qname_minimization: true,
            case_randomization: false,
            ipv6: false,
        }
    }
}

impl RecursiveConfig {
    #[allow(clippy::trivially_copy_pass_by_ref)] // serde's skip_serializing_if signature
    fn is_default(&self) -> bool {
        *self == Self::default()
    }
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

/// A local DNS record (DNS-010). Value formats by type:
/// `A`/`AAAA`: an address; `CNAME`/`PTR`: a domain name; `TXT`: text;
/// `MX`: `"<preference> <exchange>"`; `SRV`: `"<priority> <weight> <port> <target>"`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LocalRecord {
    /// Owner name; a leading `*.` makes it a wildcard for names below it.
    pub name: SafeString,
    /// `A`, `AAAA`, `CNAME`, `PTR`, `TXT`, `MX`, or `SRV`.
    #[serde(rename = "type")]
    pub rtype: SafeString,
    pub value: SafeString,
    /// TTL in seconds (default: `[local] default_ttl`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
    /// Keep this record on this node only (CLU-006): a cluster primary doesn't share it, and
    /// a replica keeps it next to the cluster's records.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub node_only: bool,
}

/// Local data settings (`spec/03` §3 step 5).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct LocalConfig {
    /// Hosts files (`IP name [alias...]` per line) to import as A/AAAA records.
    pub hosts_files: Vec<SafeString>,
    /// Generate PTR records for every local A/AAAA record.
    pub auto_ptr: bool,
    /// TTL for local records without their own.
    pub default_ttl: u32,
}

impl Default for LocalConfig {
    fn default() -> Self {
        Self {
            hosts_files: Vec::new(),
            auto_ptr: true,
            default_ttl: 300,
        }
    }
}

/// A client group (FLT-005, `spec/05` §1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)] // independent per-group switches
pub struct GroupConfig {
    /// Unique name; `default` applies to clients that match nothing else.
    pub name: SafeString,
    /// Lists (by name) this group uses. Omitted = every enabled list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lists: Option<Vec<SafeString>>,
    /// When a client is in several groups, the union of their lists applies and other
    /// settings come from the highest-priority group.
    #[serde(default)]
    pub priority: i32,
    /// How blocked queries are answered (FLT-008).
    #[serde(default)]
    pub block_mode: BlockMode,
    /// Addresses for `block_mode = "custom_ip"` (IPv4 for A, IPv6 for AAAA).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub block_ips: Vec<IpAddr>,
    /// TTL of block answers (and of the SOA that lets clients cache a negative block).
    #[serde(default = "default_block_ttl")]
    pub block_ttl: u32,
    /// Extended DNS Error on block answers: `blocked` (15) or `filtered` (17, RFC 8914: at
    /// the client's request, e.g. parental controls).
    #[serde(default)]
    pub ede: EdeKind,
    /// Include which list blocked the name in the EDE text.
    #[serde(default = "default_true")]
    pub ede_text: bool,
    /// Networks whose devices belong to this group (ADR-050), as IPs or CIDRs, e.g.
    /// `["192.168.2.0/24"]` for a VLAN of smart-home devices. A device gets the group of the most specific
    /// matching network; a `[[client]]` entry with its own `groups` still wins.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub networks: Vec<Cidr>,
    /// Color for this group in charts and chips (`#rrggbb`); one is picked when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<SafeString>,
    /// REQ: FLT-012 (T7.9) — services this group blocks (`tiktok`, `fortnite`, ...: see
    /// `telltale services list`), on top of its lists.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked_services: Vec<SafeString>,
    /// REQ: FLT-010 (T7.10) — `[[schedule]]` names that apply to this group.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub schedules: Vec<SafeString>,
    /// REQ: FLT-011 (T7.11) — safe search: Google, Bing, DuckDuckGo, Yandex, and Pixabay
    /// answer with their safe-search service, and YouTube with Restricted Mode.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub safe_search: bool,
    /// With `safe_search`: YouTube's restriction (`strict`, `moderate`, or `off`).
    #[serde(default, skip_serializing_if = "YoutubeRestrict::is_default")]
    pub youtube_restrict: YoutubeRestrict,
    /// REQ: FLT-015 (T7.20) — DNS rebinding protection: answers in private, loopback,
    /// link-local, or shared (CGNAT) ranges are blocked for names that aren't yours.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub rebinding_protection: bool,
    /// Domains allowed to answer with private addresses (your own domain, `plex.direct`).
    /// Domains with a `[[route]]` (conditional forwarding) always are.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rebinding_allow: Vec<SafeString>,
    /// Answers inside these networks are blocked, whatever the name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub block_answer_ips: Vec<Cidr>,
    /// REQ: FLT-014 (T7.20) — rewrites: a domain answered with an address or another name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rewrite: Vec<RewriteConfig>,
    /// REQ: DNS-016 (T7.21) — DNS64 (RFC 6147): IPv6-only devices behind NAT64 get AAAA
    /// answers made from A records when a name has no AAAA.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub dns64: bool,
    /// The NAT64 prefix (a /96; default the well-known `64:ff9b::/96`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns64_prefix: Option<Cidr>,
    /// REQ: DNS-016 (T9.10) — the exclusion set (RFC 6147 §5.1.4): AAAA records in these IPv6
    /// networks count as missing (so the name gets made-up ones), and A records in these IPv4
    /// networks are never made into AAAA. `::ffff:0:0/96` is always excluded.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns64_exclude: Vec<Cidr>,
    /// REQ: FLT-016 (T12.5) — answer AAAA questions with no data, so the group's devices use
    /// IPv4 (a network with broken IPv6). Local records and zones still answer; names blocked
    /// stay blocked. Not with `dns64`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub filter_aaaa: bool,
    /// REQ: UPS-007 (T9.25) — the `[[upstream_group]]` this group's queries go to (instead of
    /// `default`). A `[[route]]` for a domain, or one that names the group, still wins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstreams: Option<SafeString>,
}

/// REQ: FLT-011 (T7.11) — YouTube Restricted Mode for a group with safe search.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum YoutubeRestrict {
    /// Strict restricted mode.
    #[default]
    Strict,
    /// Moderate restricted mode.
    Moderate,
    /// YouTube is left alone (search engines are still restricted).
    Off,
}

impl YoutubeRestrict {
    pub fn is_default(&self) -> bool {
        *self == Self::Strict
    }
}

/// REQ: FLT-010 (T7.10, `spec/05` §3) — a weekly schedule: during its windows, the groups
/// that name it block everything, or get extra lists or blocked services.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScheduleConfig {
    /// Unique name, used in a group's `schedules`.
    pub name: SafeString,
    /// What happens during the windows.
    pub action: ScheduleAction,
    /// `enable_lists`: these lists apply during the windows, and not outside them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lists: Vec<SafeString>,
    /// `block_services`: these services (`telltale services list`) are blocked during the
    /// windows.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<SafeString>,
    /// IANA time zone, e.g. `Europe/Berlin`. Default: the system's (`TZ`, `/etc/localtime`),
    /// else UTC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tz: Option<SafeString>,
    /// When it's on.
    pub window: Vec<ScheduleWindow>,
}

/// One weekly window: the days it starts on, and local start and end times. An end at or
/// before the start runs past midnight (`21:00` to `07:00`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScheduleWindow {
    /// `mon` … `sun`, or `weekdays`, `weekends`, `daily`.
    pub days: Vec<SafeString>,
    /// `HH:MM`, 24-hour.
    pub start: SafeString,
    /// `HH:MM`, 24-hour (`24:00` is the end of the day).
    pub end: SafeString,
}

/// REQ: DNS-018 (T7.22) — an authoritative zone: every name under `name` is answered from
/// it (names it doesn't have get NXDOMAIN), for everyone or only `groups`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ZoneConfig {
    /// The zone's apex (`home.example.com`).
    pub name: SafeString,
    /// An RFC 1035 zone file (BIND, Technitium's export, `PowerDNS`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<SafeString>,
    /// Records, as in `[[record]]` (names under the zone).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub record: Vec<LocalRecord>,
    /// Only these groups see this zone (split horizon); empty: everyone.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<SafeString>,
    /// TTL of negative answers (NXDOMAIN, no data), in seconds.
    #[serde(default = "default_zone_negative_ttl")]
    pub negative_ttl: u32,
}

const fn default_zone_negative_ttl() -> u32 {
    300
}

/// REQ: T8.2 — a router whose DHCP clients name devices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RouterConfig {
    /// Unique name (logs, the leases' source).
    pub name: SafeString,
    /// `unifi` (UniFi OS consoles and the Network application) or `opnsense`.
    #[serde(rename = "type")]
    pub kind: RouterKind,
    /// The console or controller: `https://192.168.1.1` (UniFi OS), `https://controller:8443`
    /// (Network application), `https://opnsense.lan`.
    pub url: SafeString,
    /// UniFi: the site (default `default`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<SafeString>,
    /// UniFi: an API key (UniFi Network 9+), or OPNsense: the API key. A file holding it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key_file: Option<SafeString>,
    /// OPNsense: the API secret (a file).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_secret_file: Option<SafeString>,
    /// UniFi without an API key: a local (read-only is enough) user and a file holding its
    /// password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<SafeString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_file: Option<SafeString>,
    /// A PEM file with the console's certificate (or its CA), for self-signed consoles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_ca: Option<SafeString>,
    /// Skip certificate verification (dangerous; logs a warning).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tls_insecure_skip_verify: bool,
    /// Seconds between reads.
    #[serde(default = "default_router_interval")]
    pub interval_secs: u32,
}

const fn default_router_interval() -> u32 {
    300
}

/// A router integration's kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RouterKind {
    Unifi,
    Opnsense,
}

/// REQ: OBS-010 (T7.12, `spec/06` §8) — alerts: rules checked on the primary (or a standalone
/// node), sent to destinations when they start and when they clear.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct AlertsConfig {
    /// How often rules are checked, in seconds.
    pub interval_secs: u32,
    /// Where alerts go.
    pub destination: Vec<AlertDestination>,
    /// What to alert on.
    pub rule: Vec<AlertRule>,
}

impl Default for AlertsConfig {
    fn default() -> Self {
        Self {
            interval_secs: 30,
            destination: Vec::new(),
            rule: Vec::new(),
        }
    }
}

/// One place alerts go.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AlertDestination {
    /// Unique name, used in a rule's `to`.
    pub name: SafeString,
    /// `webhook` (JSON POST), `ntfy`, `gotify`, `slack` (Slack-compatible webhooks:
    /// Slack, Mattermost, Discord's `/slack` endpoint), or `email`.
    #[serde(rename = "type")]
    pub kind: AlertKind,
    /// The webhook URL, the ntfy topic URL (`https://ntfy.sh/my-topic`), the Gotify server,
    /// or the mail server: `smtp://smtp.gmail.com:587` (STARTTLS), `smtps://host:465` (TLS),
    /// or `smtp+insecure://127.0.0.1:1025` (no encryption: a local mail catcher only).
    pub url: SafeString,
    /// A file holding the token (ntfy access token, Gotify application token), so it stays
    /// out of the config and Git.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_file: Option<SafeString>,
    /// REQ: OBS-010 (T9.4) — `email`: the sender address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<SafeString>,
    /// `email`: the recipients.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to: Vec<SafeString>,
    /// `email`: the mail server account, and a file holding its password (a Gmail app
    /// password, for example). Sent only over an encrypted connection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<SafeString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_file: Option<SafeString>,
    /// `email`: a PEM file with the mail server's certificate (or its CA), for a private
    /// server; public ones are trusted already.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_ca: Option<SafeString>,
}

/// A destination's kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AlertKind {
    Webhook,
    Ntfy,
    Gotify,
    Slack,
    /// REQ: OBS-010 (T9.4)
    Email,
}

/// One alert rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AlertRule {
    /// Unique name, shown in every alert.
    pub name: SafeString,
    /// The condition.
    pub when: AlertWhen,
    /// How long it must hold before the alert goes out (not for `anomaly` and
    /// `update_available`, which go out once each).
    #[serde(default = "default_alert_for")]
    pub for_secs: u32,
    /// `servfail_rate`: the percentage of queries (default 5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f64>,
    /// Destination names.
    pub to: Vec<SafeString>,
    /// Off: the rule is kept but not checked.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

const fn default_alert_for() -> u32 {
    60
}

/// What an alert rule watches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AlertWhen {
    /// An upstream's circuit breaker is open (one alert per upstream).
    UpstreamDown,
    /// A cluster node isn't connected (one alert per node).
    NodeDown,
    /// A list fails to download (one alert per list).
    ListFailing,
    /// REQ: OBS-023 (T12.3) — a URL list's content hasn't changed in `[filter]
    /// stale_after_days` (one alert per list).
    ListStale,
    /// A device anomaly was found (OBS-013; one alert per finding).
    Anomaly,
    /// SERVFAIL above `threshold` percent of queries over the last 5 minutes (at least 50).
    ServfailRate,
    /// A newer TelltaleDNS build is available (once per version).
    UpdateAvailable,
    /// REQ: OBS-010 (T9.5) — a replica is behind the primary's configuration (one alert per
    /// node; `for_secs` says for how long).
    SyncLag,
    /// A device TelltaleDNS has never seen starts asking (once per device; quiet for the
    /// first day after a fresh start, while every device is new).
    NewDevice,
    /// A node's data disk is more than `threshold` percent full (default 90; one alert per
    /// node).
    DiskFull,
    /// An AI agent's change waits for approval (`[agents] require_approval`; once per plan).
    PlanPending,
    /// REQ: OBS-016 (T11.1) — a service-level objective spends its error budget too fast:
    /// 14.4 times the sustainable rate over the last hour and 5 minutes, or 6 times over 6
    /// hours and 30 minutes (one alert per objective; `[slo]`).
    SloBurn,
    /// REQ: OBS-020 (T11.3) — a listener or extra target hasn't answered its probe twice in a
    /// row, on any node (one alert per node and target; `[probe]`).
    ProbeFailing,
    /// A DoT/DoH/DoQ listener's certificate expires within `threshold` days (default 14), on
    /// any node (one alert per node and listener).
    CertExpiring,
}

/// REQ: FLT-014 (T7.20) — one rewrite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RewriteConfig {
    /// The name (`nas.example.com`), or `*.example.com` for every name under it.
    pub domain: SafeString,
    /// An address (answered as A or AAAA) or a name (answered as a CNAME to it, with its
    /// addresses).
    pub answer: SafeString,
}

/// What a schedule does during its windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleAction {
    /// Block every name (bedtime), except quick allow rules and local names.
    BlockAll,
    /// Apply extra lists.
    EnableLists,
    /// Block extra services.
    BlockServices,
}

const fn default_block_ttl() -> u32 {
    60
}

/// Block response (FLT-008).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BlockMode {
    /// A → 0.0.0.0, AAAA → ::, anything else → NODATA (Pi-hole and Technitium default).
    #[default]
    NullIp,
    Nxdomain,
    Nodata,
    Refused,
    /// A/AAAA → `block_ips` (e.g. a "blocked" landing page); other types → NODATA.
    CustomIp,
}

/// EDE code on block answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum EdeKind {
    #[default]
    Blocked,
    Filtered,
}

/// A known device (FLT-006).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    /// Device name, shown everywhere and usable in `$client=` rules.
    pub name: SafeString,
    /// How to recognize it: an IP (`192.168.1.20`), a CIDR (`10.0.5.0/24`), a MAC
    /// (`aa:bb:cc:dd:ee:ff`), or a client ID from DoH/DoT (`id:kids-tablet`).
    #[serde(rename = "match")]
    pub match_keys: Vec<SafeString>,
    /// Groups it belongs to, highest priority first.
    /// Empty (the default): the group of the device's network (`[[group]] networks`), else
    /// `default` (ADR-050).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<SafeString>,
}

/// REQ: FLT-005, FLT-006 (T6.12, ADR-067) — a quick rule: allow or block a domain and its
/// subdomains for chosen devices, groups, or everyone, optionally until a time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuleConfig {
    /// A unique ID (the API assigns one; in a file, any unique name).
    pub id: SafeString,
    pub action: RuleAction,
    /// The domain; its subdomains are included (`example.com` covers `www.example.com`).
    pub domain: SafeString,
    /// Devices it applies to: device names (`[[client]] name`), IPs, or CIDRs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<SafeString>,
    /// Groups it applies to. With neither `devices` nor `groups`, it applies to everyone.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<SafeString>,
    /// When it stops applying (RFC 3339, e.g. `2026-10-05T21:30:00Z`). Absent: never.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<SafeString>,
    /// Why it exists ("Mom's game"), shown with every decision it makes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<SafeString>,
    /// Who made it (a user or `agent:<token>`), filled in by the API.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<SafeString>,
    /// When it was made (RFC 3339), filled in by the API.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<SafeString>,
}

/// What a quick rule does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Allow,
    Block,
}

/// Most quick rules a configuration may hold (ADR-067).
pub const MAX_RULES: usize = 1000;

/// Client identification (`spec/03` §3 step 2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct ClientsConfig {
    /// Read the kernel neighbor table (ARP/NDP) to recognize clients by MAC. Needs host
    /// networking to see real devices (inside a bridge network only the gateway shows up).
    pub neighbor_table: bool,
    /// How often the neighbor table is re-read.
    pub neighbor_refresh_secs: u32,
    /// Forwarders whose EDNS MAC option (dnsmasq `add-mac`) is trusted. Empty = ignore the
    /// option: any client could send it and claim another device's identity.
    pub trust_edns_mac_from: Vec<Cidr>,
    /// Addresses that are infrastructure, not devices: Kubernetes node and pod networks, a
    /// Docker bridge, a forwarding router. When > 90% of queries come from ≤ 3 of them, the
    /// UI warns that client IPs appear masked (OPS-003). Loopback, this host's default
    /// gateways, and `TELLTALE_NODE_IPS` (set by the Helm chart) are always included.
    pub infrastructure: Vec<Cidr>,
    /// REQ: T8.3 — name unnamed devices by the `<name>.local` they announce over mDNS
    /// (listen only). Needs to be on the LAN: a native install or host networking.
    pub mdns: bool,
    /// The mDNS port (5353; shared with avahi or the OS responder).
    pub mdns_port: u16,
}

impl Default for ClientsConfig {
    fn default() -> Self {
        Self {
            neighbor_table: true,
            neighbor_refresh_secs: 60,
            trust_edns_mac_from: Vec::new(),
            infrastructure: Vec::new(),
            mdns: false,
            mdns_port: 5353,
        }
    }
}

/// Whether a list's rules block or allow (`spec/05` §1). Exception rules (@@) allow regardless.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ListKind {
    #[default]
    Block,
    Allow,
}

/// How plain domain entries match (FLT-002).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ListMatch {
    /// The domain and every name below it (Technitium semantics).
    #[default]
    Subtree,
    /// Only the exact name (Pi-hole "exact" lists).
    Exact,
}

/// A filter list (`spec/05` §1). Exactly one source: `url`, `path`, or `rules`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilterList {
    /// Stable ID: lowercase letters, digits, `-` and `_`, at most 64 characters. Used in file
    /// names, metrics, and the API, so renaming a list re-downloads it.
    pub name: SafeString,
    /// `https://` (or `http://`) source, refreshed every `refresh_secs`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<SafeString>,
    /// Local file, re-read on every refresh.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<SafeString>,
    /// Inline rules, one per entry, in any supported syntax.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<SafeString>,
    #[serde(default)]
    pub kind: ListKind,
    /// `subtree` (default) or `exact`.
    #[serde(default, rename = "match")]
    pub match_mode: ListMatch,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// REQ: OBS-018 (T11.5) — `enforce` (the default) blocks; `shadow` compiles the list but
    /// never blocks with it: what it would have blocked is counted (Lists page), so a new list
    /// can be judged before it's turned on. Block lists only.
    #[serde(default, skip_serializing_if = "ListMode::is_enforce")]
    pub mode: ListMode,
    /// Overrides `[filter] refresh_secs` for this list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_secs: Option<u32>,
    /// Overrides `[filter] max_list_bytes` for this list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<ByteSize>,
    /// REQ: OBS-023 (T12.3) — overrides `[filter] stale_after_days` for this list (0: never
    /// stale, for a list that rarely changes on purpose).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale_after_days: Option<u32>,
}

const fn default_true() -> bool {
    true
}

/// REQ: OBS-018 (T11.5) — whether a list blocks or only counts what it would block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ListMode {
    #[default]
    Enforce,
    /// Compiled and checked, never blocks: its would-be blocks are counted.
    Shadow,
}

impl ListMode {
    #[allow(clippy::trivially_copy_pass_by_ref)] // serde's skip_serializing_if takes a reference
    pub fn is_enforce(&self) -> bool {
        *self == Self::Enforce
    }
}

/// List download settings (`spec/05` §3.4, FLT-004).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct FilterConfig {
    /// How often URL and file lists are refreshed (default 24 h, minimum 15 min).
    pub refresh_secs: u32,
    /// Lists downloaded at the same time.
    pub fetch_concurrency: u8,
    /// Time limit for one download attempt, including the body.
    pub fetch_timeout_secs: u32,
    /// Extra attempts after a failed download (network errors, HTTP 5xx, 429).
    pub fetch_retries: u8,
    /// Downloads larger than this fail and the previous copy is kept.
    pub max_list_bytes: ByteSize,
    /// A download is refused, and the previous copy kept, when more than this percentage of its
    /// rule-bearing lines is invalid (a JSON error page, a compressed body, or a mirror that
    /// changed format parses mostly to invalid lines). Cosmetic and unsupported rules don't
    /// count as invalid. 50 = refuse when invalid lines outnumber rules; 0 = refuse any list
    /// with an invalid line; 100 = accept anything that isn't empty or HTML.
    pub max_invalid_percent: u8,
    /// Most regex rules a compiled snapshot keeps (default 1,000; 0 = no limit). Every query
    /// that no exact or suffix rule settles is tried against all of them, about a microsecond
    /// per thousand, and a few thousand that share a prefix can overwhelm the matcher's
    /// automaton: in a synthetic test of patterns sharing a prefix, 1,500 cost 1.6 µs per query
    /// and 41 MiB, while 2,000 grew past 5 GiB in a minute. The rules past the limit, in list
    /// order, are left out and reported on the Lists page (and by `telltale lists compile`).
    pub max_regexes: u32,
    /// Allow list URLs on link-local addresses (169.254.0.0/16, `fe80::/10`). Off: they're
    /// refused, like cloud-metadata addresses, so a list URL (from the UI, the API, or an
    /// agent's pre-save check) can't read what a cloud instance serves there.
    pub allow_link_local_urls: bool,
    /// Threads for compiling lists (at low CPU priority). 0 = auto: half the cores, between
    /// 1 and 4 (2 on a Pi 4, which compiles 2M names in about 6 s).
    pub compile_threads: u8,
    /// Memory for sorting list entries before spilling to disk (`spec/05` §3.4).
    pub compile_memory: ByteSize,
    /// Sync a compiled snapshot's files and directory to disk before it counts as published, so
    /// a power cut can't leave a snapshot whose files are short. Costs a few hundred
    /// milliseconds per large compile on an SD card, off the query path.
    pub fsync: bool,
    /// REQ: OBS-023 (T12.3) — a URL list whose content hasn't changed in this many days is
    /// "stale": its source may be abandoned while still answering (health reason `list_stale`,
    /// alert rule `list_stale`). 0 = never. Per list: `stale_after_days`.
    pub stale_after_days: u32,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            refresh_secs: 86_400,
            fetch_concurrency: 4,
            fetch_timeout_secs: 120,
            fetch_retries: 3,
            max_list_bytes: ByteSize::mib(64),
            max_invalid_percent: 50,
            max_regexes: 1000,
            allow_link_local_urls: false,
            compile_threads: 0,
            compile_memory: ByteSize::mib(128),
            fsync: true,
            stale_after_days: 30,
        }
    }
}

/// Who may use this resolver (`spec/08` §6: never an open resolver by default).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct AccessConfig {
    /// Clients outside these networks get REFUSED. Default: private (RFC 1918), CGNAT /
    /// Tailscale (100.64/10), ULA, link-local, and loopback.
    pub allowed_networks: Vec<Cidr>,
}

impl Default for AccessConfig {
    fn default() -> Self {
        let nets = [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "100.64.0.0/10",
            "169.254.0.0/16",
            "127.0.0.0/8",
            "fc00::/7",
            "fe80::/10",
            "::1/128",
        ];
        Self {
            allowed_networks: nets.iter().filter_map(|n| Cidr::parse(n).ok()).collect(),
        }
    }
}

/// REQ: DNS-005 (review 01-12) — what TelltaleDNS advertises in its answers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct DnsConfig {
    /// The UDP payload size advertised in EDNS(0) (RFC 6891), and the largest UDP answer sent
    /// to a client that advertises at least as much; 512 to 4096 (the UDP workers' send buffer).
    /// 1232 (the DNS Flag Day 2020 value) avoids IP fragmentation on almost every path; raise
    /// it on a network known to carry larger datagrams. Needs a restart.
    pub edns_payload: u16,
    /// REQ: DNS-021 (T12.4) — answer the NSID option (RFC 5001) with this node's name, so
    /// `dig +nsid` says which node or pod answered (behind a shared address, say). Only for
    /// queries that ask for it.
    pub nsid: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            edns_payload: 1232,
            nsid: false,
        }
    }
}

/// What to do with a rate-limited query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum RateLimitAction {
    #[default]
    Refused,
    Drop,
}

/// Per-client rate limiting (DNS-014).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct RateLimitConfig {
    pub enabled: bool,
    /// Queries allowed per `window_secs` per client (token bucket; bursts up to this).
    pub queries: u32,
    pub window_secs: u32,
    pub action: RateLimitAction,
    /// Clients never limited.
    pub exempt: Vec<Cidr>,
    /// Count IPv4 clients per /N (32 = per address).
    pub ipv4_prefix: u8,
    /// Count IPv6 clients per /N (64 groups a device's rotating privacy addresses).
    pub ipv6_prefix: u8,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            queries: 1000,
            window_secs: 60,
            action: RateLimitAction::Refused,
            exempt: ["127.0.0.0/8", "::1/128"]
                .iter()
                .filter_map(|n| Cidr::parse(n).ok())
                .collect(),
            ipv4_prefix: 32,
            ipv6_prefix: 64,
        }
    }
}

/// REQ: OBS-022 (T12.1, ADR-111) — queries left out of the query log, the live view, the
/// analytics (dashboard, top lists, anomalies), and every export: noise like connectivity checks,
/// time servers, or a monitoring probe. They're still answered normally, and still counted in
/// `/metrics`. Shared by the whole cluster.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct ExclusionsConfig {
    /// Turns the exclusions on or off without losing the lists.
    pub enabled: bool,
    /// Names left out, each with its subdomains (`ntp.org` covers `pool.ntp.org`; a leading
    /// `*.` means the same).
    pub names: Vec<SafeString>,
    /// Devices left out: addresses or networks.
    pub clients: Vec<Cidr>,
}

impl Default for ExclusionsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            names: Vec::new(),
            clients: Vec::new(),
        }
    }
}

impl ExclusionsConfig {
    /// Whether this is the default (left out when the configuration is written back).
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
    /// Whether anything is excluded at all.
    pub fn active(&self) -> bool {
        self.enabled && !(self.names.is_empty() && self.clients.is_empty())
    }
}

/// Built-in handling of special names (`spec/03` §3 step 4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
// Independent on/off switches, one per rule; an enum set would only obscure the TOML.
#[allow(clippy::struct_excessive_bools)]
pub struct SpecialConfig {
    /// `use-application-dns.net` → NXDOMAIN, so Firefox doesn't switch to its own DoH.
    pub block_firefox_canary: bool,
    /// `localhost` and `*.localhost` → `127.0.0.1` / `::1` (RFC 6761 §6.3).
    pub localhost: bool,
    /// Reverse lookups for private addresses → NXDOMAIN instead of asking public upstreams,
    /// unless a local record or route covers them (Pi-hole "bogus-priv").
    pub private_ptr_nxdomain: bool,
    /// CHAOS-class `version.bind`, `id.server`, ... → REFUSED.
    pub refuse_chaos: bool,
}

impl Default for SpecialConfig {
    fn default() -> Self {
        Self {
            block_firefox_canary: true,
            localhost: true,
            private_ptr_nxdomain: true,
            refuse_chaos: true,
        }
    }
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
    /// REQ: CLU-011 (T8.1) — in a cluster, resolve this many of the cluster's hot names when
    /// this node starts, so its first clients find them cached (0: off).
    pub warm_names: u32,
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
            warm_names: 300,
        }
    }
}

/// How DNSSEC is checked (DNS-011, `spec/03` §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DnssecMode {
    /// Answers pass through as the upstream sent them (its AD bit is kept for clients that
    /// ask).
    #[default]
    Off,
    /// Validate every forwarded answer against the root trust anchor: bogus answers become
    /// SERVFAIL with EDE 6, and AD is set only on answers proven here.
    Validate,
    /// Validate and count, but serve bogus answers anyway (for trying validation out).
    Permissive,
}

/// `[dnssec]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct DnssecConfig {
    pub mode: DnssecMode,
    /// Domains not validated (negative trust anchors, RFC 7646), e.g. an internal domain
    /// forwarded to a server that isn't signed. Routes with `dnssec_nta = true` add theirs.
    pub negative_trust_anchors: Vec<SafeString>,
    /// REQ: DNS-011 (T9.8) — root trust anchors from a file instead of the built-in ones
    /// (KSK-2017 and KSK-2024): DNSKEY records in zone-file form, as `dig DNSKEY . +noall
    /// +answer` prints them or Unbound's `root.key` holds. Read at start and on reload; a
    /// file that can't be read or has no keys leaves the built-in anchors in place (logged).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_anchors_file: Option<SafeString>,
    /// REQ: DNS-011 (T9.16) — RFC 8198: answer names that validated NSEC records prove don't
    /// exist (or lack the type) from the cache, without asking upstream. On by default.
    pub aggressive_nsec: bool,
}

impl Default for DnssecConfig {
    fn default() -> Self {
        Self {
            mode: DnssecMode::Off,
            negative_trust_anchors: Vec::new(),
            trust_anchors_file: None,
            aggressive_nsec: true,
        }
    }
}

/// `[updates]` (REQ: OPS-004, ADR-046).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct UpdatesConfig {
    /// Read this build's channel's signed release index once a day to see whether a newer
    /// build exists. `false`: nothing leaves the node, and the status is `off`.
    pub check: bool,
    /// Where to read the index instead of GitHub (a mirror); its signature is still checked
    /// with the release key built into the binary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index_url: Option<SafeString>,
}

impl Default for UpdatesConfig {
    fn default() -> Self {
        Self {
            check: true,
            index_url: None,
        }
    }
}

/// `[agents]` (REQ: AGT-009, ADR-064).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct AgentsConfig {
    /// The kill switch: `false` refuses every agent token at once (users and their own
    /// tokens are unaffected).
    pub enabled: bool,
    /// Requests per minute per agent token, unless the token sets its own.
    pub rate_per_minute: u32,
    /// REQ: AGT-007 — agents' planned changes wait for an operator's approval ("Agent
    /// changes" in the web UI) before `apply_plan` succeeds.
    pub require_approval: bool,
}

impl Default for AgentsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rate_per_minute: 120,
            require_approval: false,
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
    /// Ship the query log to another cluster node (the primary by default), keeping only a
    /// small local buffer until it's delivered (store-and-forward, CLU-007): for nodes with
    /// little or wear-sensitive storage, such as a Pi on an SD card, and ephemeral pods.
    Ship,
}

/// Ship mode (`[telemetry] mode = "ship"`, CLU-007, ADR-055).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct ShipConfig {
    /// The node that stores this node's query log: a node ID or site. Default: the primary.
    pub to: Option<SafeString>,
    /// Most query log kept here while it can't be delivered; the oldest goes first beyond it.
    /// Put `[node] data_dir` on tmpfs (or accept the writes) on an SD card.
    pub buffer_bytes: ByteSize,
    /// Close and ship the query log at least this often, in seconds (it's searchable from
    /// this node until then, through the cluster).
    pub interval_secs: u32,
}

impl Default for ShipConfig {
    fn default() -> Self {
        Self {
            to: None,
            buffer_bytes: ByteSize::mib(64),
            interval_secs: 300,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct TelemetryConfig {
    pub mode: TelemetryMode,
    pub ship: ShipConfig,
    /// Event ring size per producing thread, in events of ~128 bytes (power of two, at
    /// least 1024). The default, 4096 (512 KiB), holds about 170 ms of a fully loaded
    /// worker; a full ring drops events (counted), never queries (ADR-026).
    pub ring_slots: u32,
    pub qlog: QlogConfig,
    pub metrics: MetricsConfig,
    /// Per-device anomaly detection (OBS-013): alert-only, deterministic, explainable.
    pub anomaly: AnomalyConfig,
    /// REQ: OBS-010 (T7.13) — query events copied to files, syslog, or HTTP collectors.
    pub sink: Vec<SinkConfig>,
    /// REQ: OBS-006 (T7.17) — metrics pushed to an OpenTelemetry collector.
    pub otlp: OtlpConfig,
    /// REQ: OBS-007 (T7.18) — client queries and responses as dnstap.
    pub dnstap: DnstapConfig,
}

/// Thresholds the latency objective may use, in milliseconds: the `/metrics` latency
/// histogram's bucket bounds, so Prometheus can compute the same objective (ADR-105).
pub const SLO_LATENCY_MS: &[u32] = &[1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000];

/// REQ: OBS-016 (T11.1, ADR-105, `spec/06` §8.2) — two service-level objectives over every
/// node's answers: availability (answers that aren't SERVFAIL) and latency (answers within
/// `latency_ms`). Each leaves an error budget over `window_days`; burn rates say how fast it
/// goes. Queries dropped without an answer (rate limits, junk) count for neither.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct SloConfig {
    /// Off: no objectives (nothing to show, and `slo_burn` alerts never fire).
    pub enabled: bool,
    /// Percent of answers that must not be SERVFAIL (default 99.9).
    pub availability_target: f64,
    /// Percent of answers that must arrive within `latency_ms` (default 99).
    pub latency_target: f64,
    /// The latency objective's threshold: one of 1, 5, 10, 25, 50, 100, 250, 500, 1000,
    /// 2500, 5000 ms (the bucket bounds of `telltale_query_duration_seconds`). Default 250.
    pub latency_ms: u32,
    /// Days the error budget covers (1 to 90; default 30). The burn-rate alerts are tuned
    /// for 30.
    pub window_days: u32,
}

impl Default for SloConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            availability_target: 99.9,
            latency_target: 99.0,
            latency_ms: 250,
            window_days: 30,
        }
    }
}

/// REQ: OBS-019 (T11.4, ADR-108, `spec/04` §9) — second opinions: one forwarded question in
/// `sample_every` is asked again, off the query path, of another upstream (another member of
/// the same upstream group, or the `reference` group), and the two answers are compared: the
/// same, different addresses (CDNs do this), a different response code, or filtered (one side
/// has addresses, the other none or only `0.0.0.0`/loopback). Off by default: the second
/// upstream sees the sampled names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct UpstreamCheckConfig {
    /// One forwarded question in this many gets a second opinion (0 = off, the default).
    pub sample_every: u32,
    /// The upstream group asked for second opinions. Unset: another upstream of the group
    /// that answered (a group with one upstream gets none).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<SafeString>,
    /// Disagreements kept for the API and the Upstreams page, newest first (1 to 1000).
    pub keep: u32,
}

impl Default for UpstreamCheckConfig {
    fn default() -> Self {
        Self {
            sample_every: 0,
            reference: None,
            keep: 100,
        }
    }
}

/// REQ: OBS-020 (T11.3, ADR-107, `spec/06` §9) — synthetic probes: every `interval_secs`,
/// each DNS listener is asked `probe.telltale.invalid` through its own protocol (UDP, TCP, DoT,
/// DoH, DoH3, DoQ) from this node, and so is every extra target; each TLS listener's
/// certificate expiry is read from its file. Probes don't show in the query log or analytics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct ProbeConfig {
    pub enabled: bool,
    /// Seconds between rounds (at least 5).
    pub interval_secs: u32,
    /// How long one probe may take, in milliseconds (100 to 10000).
    pub timeout_ms: u32,
    /// Extra addresses to probe, by IP: `udp://192.168.5.112:53` (a load balancer's address),
    /// `tcp://…`, `tls://…:853`, `https://…:443/dns-query`, `h3://…`, `quic://…:853`.
    /// Certificates aren't verified (the listeners' own expiry is checked from their files).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<SafeString>,
    /// A listener certificate expiring within this many days degrades the health level.
    pub cert_warn_days: u32,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 30,
            timeout_ms: 2000,
            targets: Vec::new(),
            cert_warn_days: 14,
        }
    }
}

/// REQ: OBS-007 (T7.18, `spec/06` §5) — dnstap over Frame Streams.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct DnstapConfig {
    /// A Unix socket a dnstap reader listens on (`/run/dnstap.sock`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socket: Option<SafeString>,
    /// Or a TCP reader: `tcp://host:port`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<SafeString>,
    /// One query in this many is copied (1 = every query).
    pub sample_every: u32,
    /// Copies held while the reader is slow; beyond, they're dropped.
    pub buffer: u32,
    /// REQ: OBS-007 (T9.19) — also copy queries to upstreams and their answers
    /// (`FORWARDER_QUERY`, `FORWARDER_RESPONSE`), sampled the same way.
    pub forwarder: bool,
}

impl Default for DnstapConfig {
    fn default() -> Self {
        Self {
            socket: None,
            address: None,
            sample_every: 1,
            buffer: 10_000,
            forwarder: false,
        }
    }
}

/// REQ: OBS-006 (T7.17, `spec/06` §5) — OTLP/HTTP (JSON) metrics export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct OtlpConfig {
    /// The collector's OTLP/HTTP base URL (`http://otel-collector:4318`); metrics go to
    /// `<endpoint>/v1/metrics`. Unset: no export.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<SafeString>,
    /// Seconds between exports.
    pub interval_secs: u32,
    /// Extra headers (an API key for a hosted collector).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<SafeString, SafeString>,
    /// REQ: OBS-017 (T11.6) — send 1 in this many queries as a trace to
    /// `<endpoint>/v1/traces` (0: none). Needs `endpoint`.
    pub traces_sample_every: u32,
    /// REQ: OBS-017 (T11.6) — also send every query that took at least this long (ms; 0: none).
    pub traces_slow_ms: u32,
}

impl Default for OtlpConfig {
    fn default() -> Self {
        Self {
            endpoint: None,
            interval_secs: 60,
            headers: BTreeMap::new(),
            traces_sample_every: 0,
            traces_slow_ms: 0,
        }
    }
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            mode: TelemetryMode::Local,
            ship: ShipConfig::default(),
            ring_slots: 4096,
            qlog: QlogConfig::default(),
            metrics: MetricsConfig::default(),
            anomaly: AnomalyConfig::default(),
            sink: Vec::new(),
            otlp: OtlpConfig::default(),
            dnstap: DnstapConfig::default(),
        }
    }
}

/// REQ: OBS-010 (T7.13, `spec/06` §5) — one event sink: every query event (after the query
/// log's privacy level) as one JSON object, written off the query path; a sink that can't
/// keep up drops events (counted), never slows DNS.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SinkConfig {
    /// Unique name (logs and metrics).
    pub name: SafeString,
    /// `file` (JSON lines, rotated), `syslog` (RFC 5424), or `webhook` (batched HTTP POST).
    #[serde(rename = "type")]
    pub kind: SinkKind,
    /// `file`: the file to append to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<SafeString>,
    /// `file`: rotate when the file reaches this size (to `<path>.1`, ...).
    #[serde(default = "default_sink_max_bytes")]
    pub max_bytes: ByteSize,
    /// `file`: rotated files kept.
    #[serde(default = "default_sink_keep")]
    pub keep: u32,
    /// `syslog`: `udp://host:514`, `tcp://host:514`, or (T9.11) `tls://host:6514` (RFC 5425).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<SafeString>,
    /// `syslog` over `tls://`: a PEM file of CAs trusted besides the public roots (a private
    /// collector's CA).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_ca: Option<SafeString>,
    /// `syslog`: the facility number (16 = local0).
    #[serde(default = "default_sink_facility")]
    pub facility: u8,
    /// `webhook`: where batches are posted (newline-delimited JSON, or a JSON array with
    /// `format = "json_array"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<SafeString>,
    /// `webhook`: `json_lines` (Loki-style collectors, Vector, Fluent Bit) or `json_array`.
    #[serde(default)]
    pub format: SinkFormat,
    /// `webhook`: a file holding a token sent as `Authorization: <token_scheme> <token>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_file: Option<SafeString>,
    /// `webhook`: the scheme for the token (`Bearer`; Splunk HEC uses `Splunk`).
    #[serde(default = "default_token_scheme")]
    pub token_scheme: SafeString,
    /// `webhook`: events per batch, and the most seconds an event waits for one.
    #[serde(default = "default_sink_batch")]
    pub batch: u32,
    #[serde(default = "default_sink_flush")]
    pub flush_secs: u32,
    /// Events held while the destination is slow or down; beyond it, events are dropped.
    #[serde(default = "default_sink_buffer")]
    pub max_buffer: u32,
    /// REQ: OBS-010 (T9.11) — `webhook`: keep batches the collector refused (after the
    /// retries) on disk, up to this size, and send them once it's back. Off by default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spill_max_bytes: Option<ByteSize>,
    /// Only these statuses (`blocked`, `cached`, ...); empty means all.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub statuses: Vec<SafeString>,
}

/// An event sink's kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SinkKind {
    File,
    Syslog,
    Webhook,
}

/// A webhook sink's body format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SinkFormat {
    #[default]
    JsonLines,
    JsonArray,
    /// REQ: OBS-006 (T7.17) — OpenTelemetry logs (OTLP/HTTP JSON): point `url` at
    /// `<collector>/v1/logs`.
    OtlpLogs,
}

const fn default_sink_max_bytes() -> ByteSize {
    ByteSize::mib(100)
}
const fn default_sink_keep() -> u32 {
    3
}
const fn default_sink_facility() -> u8 {
    16
}
fn default_token_scheme() -> SafeString {
    SafeString::new("Bearer").unwrap_or_default()
}
const fn default_sink_batch() -> u32 {
    500
}
const fn default_sink_flush() -> u32 {
    5
}
const fn default_sink_buffer() -> u32 {
    10_000
}

/// How readily the anomaly engine reports (`spec/06` §7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum AnomalySensitivity {
    /// Only large departures from a device's baseline.
    Low,
    #[default]
    Normal,
    /// Smaller departures too (more findings, more false alarms).
    High,
}

/// Device anomaly detection (OBS-013, ADR-019): rate spikes, heavy volume to one domain,
/// drift to many new domains, and regular phone-home beacons, each against the device's own
/// learned baseline. Findings never block anything.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct AnomalyConfig {
    pub enabled: bool,
    /// Days a device is watched before it can raise a finding.
    pub learning_days: u32,
    pub sensitivity: AnomalySensitivity,
    /// Devices with state; the least recently seen are evicted first.
    pub max_clients: u32,
    /// Registrable domains never reported (e.g. connectivity checks you expect).
    pub ignore_domains: Vec<SafeString>,
    /// REQ: OBS-009 (T7.14) — an NXDOMAIN storm: at least this many NXDOMAIN answers to one
    /// device in a minute...
    pub nxdomain_per_minute: u32,
    /// ...that are at least this percentage of its queries in that minute.
    pub nxdomain_percent: u32,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            learning_days: 7,
            sensitivity: AnomalySensitivity::Normal,
            max_clients: 1024,
            ignore_domains: Vec::new(),
            nxdomain_per_minute: 30,
            nxdomain_percent: 50,
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

/// REST API listener (API-001). It also serves `/metrics` (signed in) and the health probes,
/// only to clients in `[access] allowed_networks` (ADR-029).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct ApiConfig {
    pub enabled: bool,
    /// Where the API listens (default `0.0.0.0:8053`).
    pub listen: SocketAddr,
    /// Reverse proxies or ingress controllers in front of the API (e.g. the pod network,
    /// `10.0.0.0/8`). For requests from them, the client address comes from
    /// `X-Forwarded-For` (sign-in lockouts, break-glass networks, the audit log), and
    /// `X-Forwarded-Proto: https` counts as HTTPS (HTTP Basic, the `Secure` cookie flag); from
    /// anyone else that header is ignored. Loopback always counts for `X-Forwarded-Proto`, so
    /// a TLS terminator on the same host needs nothing here. Default: none (the connection's
    /// address is the client).
    pub trusted_proxies: Vec<Cidr>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8053),
            trusted_proxies: Vec::new(),
        }
    }
}

/// Sign-in settings (API-003, `spec/08` §6). Users, sessions, and tokens live in
/// `<data_dir>/state.db`. The first admin comes from the one-time setup token (in the log
/// and `<data_dir>/setup-token`) or from `TELLTALE_BOOTSTRAP_ADMIN_USER` with
/// `TELLTALE_BOOTSTRAP_ADMIN_PASSWORD` or `TELLTALE_BOOTSTRAP_ADMIN_PASSWORD_HASH`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct AuthConfig {
    /// A UI session ends this long after sign-in (default 168 = 7 days).
    pub session_ttl_hours: u32,
    /// ... or after this long unused (default 24).
    pub session_idle_hours: u32,
    /// Accept HTTP Basic over plain HTTP. Off: Basic only behind HTTPS (a proxy that sends
    /// `X-Forwarded-Proto: https`).
    pub allow_insecure_basic: bool,
    /// Roles that must use two-factor sign-in (TOTP), e.g. `["admin"]`.
    pub totp_required_roles: Vec<UserRole>,
    /// Days the audit log keeps entries (default 365; 0 keeps them forever). Older entries
    /// are removed hourly; the rest still verifies from a checkpoint, and each trim is
    /// itself recorded (`audit.trim`).
    pub audit_retention_days: u32,
    /// Sign-in through `OpenID Connect` providers (Keycloak, Authentik, ...; API-004).
    pub oidc: OidcConfig,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            session_ttl_hours: 168,
            session_idle_hours: 24,
            allow_insecure_basic: false,
            totp_required_roles: Vec::new(),
            audit_retention_days: 365,
            oidc: OidcConfig::default(),
        }
    }
}

/// `OpenID Connect` sign-in (API-004, `spec/08` §6, ADR-034). Each provider gets a "Sign in
/// with ..." button; users are created on first sign-in and their role comes from a claim
/// (groups) at every sign-in. Changes need a restart.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct OidcConfig {
    /// Where people open the UI, e.g. `https://dns.example.com` or `http://192.168.1.2:8053`.
    /// Each provider's redirect URI is `<public_url>/api/v1/auth/oidc/<id>/callback`, and
    /// after sign-out the provider returns to `<public_url>/`; register both with it.
    pub public_url: SafeString,
    /// Turn off password sign-in (and HTTP Basic) except for admins signing in from
    /// `allowed_admin_networks` (break-glass, for when the provider is down).
    pub disable_local_login: bool,
    /// Where break-glass admin sign-in is allowed. Default: private networks and loopback.
    pub allowed_admin_networks: Vec<Cidr>,
    pub provider: Vec<OidcProvider>,
    /// REQ: AGT-008 (T7.4) — MCP clients (AI assistants) sign in through this provider (its
    /// `id`) with OAuth 2.1: TelltaleDNS accepts the provider's JWT access tokens issued for
    /// `mcp_audience`, as an agent with the scopes the user consented to. Empty: off.
    pub mcp_provider: SafeString,
    /// The audience (`aud`) MCP access tokens must carry. Default: `<public_url>/mcp`.
    pub mcp_audience: SafeString,
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            public_url: SafeString::default(),
            disable_local_login: false,
            allowed_admin_networks: AccessConfig::default().allowed_networks,
            provider: Vec::new(),
            mcp_provider: SafeString::default(),
            mcp_audience: SafeString::default(),
        }
    }
}

/// One `OpenID Connect` provider.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OidcProvider {
    /// Short ID used in URLs: lowercase letters, digits, and `-` (`keycloak`, `authentik`).
    pub id: SafeString,
    /// Button label ("Sign in with ..."). Default: the ID.
    #[serde(default)]
    pub name: SafeString,
    /// Issuer URL (discovery is `<issuer>/.well-known/openid-configuration`).
    pub issuer: SafeString,
    pub client_id: SafeString,
    /// The client secret, or ...
    #[serde(default)]
    pub client_secret: Option<SafeString>,
    /// ... a file holding it (a mounted Kubernetes Secret). Neither: a public client (PKCE).
    #[serde(default)]
    pub client_secret_file: Option<SafeString>,
    /// Scopes to request. Default: `openid`, `profile`, `email`.
    #[serde(default = "default_oidc_scopes")]
    pub scopes: Vec<SafeString>,
    /// Claim that becomes the TelltaleDNS username (dotted paths reach into objects).
    /// Default `preferred_username`; falls back to `email`, then `sub`.
    #[serde(default = "default_username_claim")]
    pub username_claim: SafeString,
    /// Claim listing the user's groups or roles (`groups`, `roles`,
    /// `realm_access.roles`). Default `groups`.
    #[serde(default = "default_groups_claim")]
    pub groups_claim: SafeString,
    /// Group → role rules; a user gets the highest role any of their groups maps to.
    #[serde(default)]
    pub role: Vec<OidcRoleRule>,
    /// Role for users whose groups match no rule. Unset: they can't sign in.
    #[serde(default)]
    pub default_role: Option<UserRole>,
    /// Refuse users whose provider says their email isn't verified.
    #[serde(default)]
    pub require_verified_email: bool,
}

/// Users in `group` get `role`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OidcRoleRule {
    pub group: SafeString,
    pub role: UserRole,
}

fn default_oidc_scopes() -> Vec<SafeString> {
    ["openid", "profile", "email"]
        .into_iter()
        .map(SafeString::from)
        .collect()
}

fn default_username_claim() -> SafeString {
    SafeString::from("preferred_username")
}

fn default_groups_claim() -> SafeString {
    SafeString::from("groups")
}

/// What a user may do (`spec/08` §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    /// Dashboards and the query log.
    Viewer,
    /// Viewer, plus pause, cache flush, and managing lists, clients, and groups.
    Operator,
    /// Everything.
    Admin,
}

/// Prometheus endpoint (OBS-005).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub listen: SocketAddr,
    /// Export per-client series (high cardinality; capped).
    pub per_client: bool,
    /// At most this many clients get their own series (default 100); the rest are "other".
    pub per_client_cap: u32,
    /// REQ: OBS-017 (T11.6) — a scraper that asks for OpenMetrics gets it, with an exemplar
    /// (a recent query's trace ID) on each `telltale_query_duration_seconds` bucket. `false`:
    /// always the plain Prometheus text format.
    pub exemplars: bool,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 9153),
            per_client: false,
            per_client_cap: 100,
            exemplars: true,
        }
    }
}
