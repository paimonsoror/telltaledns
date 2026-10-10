# TelltaleDNS — Executive Summary

*A filtering, encrypted, observable DNS resolver that runs as one cluster across a Raspberry Pi and Kubernetes, managed from one place.*

**Mission:** give everyone who runs a home or small network an honest, real-time view of what their devices are doing, and full control over it, without trading away speed, footprint, or reliability. *See every question. Answer on your terms.*

## Standing on the shoulders of giants
TelltaleDNS exists because two projects showed what self-hosted DNS can be:
- **Pi-hole** brought network-wide ad blocking to millions of homes on a $35 computer, with a dashboard anyone can read. Its groups model, CNAME-cloaking defense, blocklist ecosystem, and Teleporter backup set the bar for home DNS filtering.
- **Technitium DNS Server** showed how complete a self-hosted DNS server can be: every encrypted transport, recursion, real zones, serve-stale and prefetch, clustering, and a capable web console.

We learned from both, read their public documentation and data formats (never their code), and import their configurations so trying TelltaleDNS takes minutes. If either already serves you well, keep using it. Our design notes on both projects are in `docs/analysis.md`.

## What TelltaleDNS is built around
A specific combination for people who run Kubernetes *and* a Raspberry Pi and want to see deeply into their network:

| Focus | What it means |
|---|---|
| A Pi-class footprint | A small static binary in an ~13 MiB image; a compact list index (a few bytes per blocked name); about 50 MB of memory on a Pi 4 with 2.7 million blocked names |
| Every core, no pauses | Rust, a per-core UDP fast path, no garbage collector |
| Encrypted DNS both ways | DoT and DoH for devices and upstreams; DNSSEC validation |
| One cluster, one management plane | A Pi and Kubernetes pods share signed, versioned configuration; any node's UI manages the whole cluster |
| Observability like an APM tool | Every query attributed to a device, explained, and timed per stage; percentiles per upstream and device; Prometheus built in |
| Config as code | Declarative TOML, GitOps mode, API parity |
| Safe automation | Scoped agent tokens and a built-in MCP server |

## Six commitments
Each is backed by a design mechanism *and* a measurable release gate (`spec/00 §5`). Performance claims are published only with numbers from the reproducible benchmark harness (`spec/09 §3`).

1. **Fast, and it stays fast while lists update.**
   - *Mechanism:* Rust (no garbage collector); a per-core UDP fast path; a cache that stores finished responses and only patches the ID and TTLs on a hit; blocklists compiled into one index whose lookup cost doesn't grow with list size; list updates built in the background and swapped in atomically.
   - *Gates:* ≥ 150k qps cache-hit on 4 cores; ≤ 250 µs p99 added latency; ≤ 10% p99 regression *during* a 2M-domain list rebuild.

2. **Light, even with big lists.**
   - *Mechanism:* the compressed list index costs a few bytes per domain, and the image is a static binary.
   - *Gates:* ≤ 20 MiB idle; ≤ 64 MiB with 1M blocked domains + 100k cached answers + full telemetry; it fits a 128 MiB Kubernetes limit and a Pi Zero 2 W.

3. **It tells you what is happening, not just how much.**
   - Every query is attributed to a device, explained (which list and line blocked it, or which upstream answered), and timed per stage (filter, cache, upstream, DNSSEC).
   - Latency percentiles per upstream, device, and query type.
   - 30-day query-log search in seconds on a Pi.
   - Per-device anomaly detection: query spikes, bursts of new domains, phone-home beacons.
   - Native Prometheus metrics and a Grafana dashboard; OpenTelemetry and dnstap are planned.

4. **One cluster across a Pi and Kubernetes, managed from one place, and DNS never goes down because the control plane did.**
   - Any node's UI manages and analyzes the whole cluster. Configuration syncs as signed, versioned snapshots.
   - Every node answers from its last snapshot even if the primary is unreachable.
   - Safe failover with two nodes needs a third vote, so TelltaleDNS uses a fenced primary with manual promotion, and elects one automatically when a tiny witness or a third node exists.

5. **Built for the platform you actually run.**
   - A Kubernetes-first Helm chart that *preserves real client IPs*, probes, ServiceMonitor, cert-manager, and GitOps mode.
   - The same signed binary and image run on the Pi.
   - Local accounts plus OIDC SSO (Authentik, Keycloak, Entra ID…) with role mapping, 2FA, and a hash-chained audit log.

6. **Built for agents, safely.**
   - A built-in MCP server on every node lets an AI agent answer questions like "why is the TV slow?" or "what did the new camera call home to?" from live analytics (read-only tools today).
   - Agent tokens are scoped, rate-limited, and need a stated reason for every change; plan/apply previews with human approval are next.

**Also:** the groups model and CNAME inspection we learned from Pi-hole; fastest and parallel upstream racing, serve-stale, and prefetch we learned from Technitium; an "explain why" for every decision; and one-command import from Pi-hole and Technitium.

## When another tool is the better choice
- **A public authoritative DNS server** (DNSSEC signing, zone transfers): Technitium is excellent at this. TelltaleDNS hosts local records and small zones only.
- **The simplest proven setup on one Pi, or very old or unusual systems:** Pi-hole has a decade of refinement, a large community, and an installer that covers more setups than ours.
- **LDAP authentication:** out of scope; use an OIDC bridge.

## Risks and how the plan addresses them
| Risk | Mitigation |
|---|---|
| Ambitious scope delays v1 | Strict P0/P1 split. Milestones front-load the core (performance, observability, Kubernetes, clustering); DoQ and recursion move to v1.x; DHCP is out of scope (routers do it) |
| Custom storage and index formats contain bugs | Versioned formats, fuzzing, golden tests, Parquet export as an escape hatch |
| HA correctness | Deterministic multi-node simulation and a chaos suite; epoch fencing tested before release |
| Benchmark claims challenged | Only harness-produced, reproducible numbers are published, with hardware and versions |
| A young project with a small team | Spec-driven repo, ADRs, requirement-ID traceability, permissive license |

## Bottom line
For a homelab running Kubernetes *and* a Raspberry Pi, TelltaleDNS aims to give you a Pi-class footprint, modern encrypted transports, one cluster with one management plane across both, and observability closer to an APM tool than to a hit counter. Every point here is a design commitment tied to a measurable gate.

*Design notes on Pi-hole and Technitium: `docs/analysis.md`. Build spec: `spec/`.*
