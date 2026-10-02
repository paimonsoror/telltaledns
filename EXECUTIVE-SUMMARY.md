# TelltaleDNS — Executive Summary

*A filtering, encrypted, observable DNS resolver that runs as one cluster across a Raspberry Pi and Kubernetes, managed from one place.*

**Mission:** give everyone who runs a home or small network an honest, real-time view of what their devices are doing, and full control over it, without trading away speed, footprint, or reliability. *See every question. Answer on your terms.*

## The position in one sentence
**Pi-hole is light but single-node and blind to encrypted DNS. Technitium is complete but heavy and coarse-grained in what it tells you. TelltaleDNS is designed to be lighter than Pi-hole per blocked domain, as protocol-complete as Technitium for resolving, and better at showing what is happening on your network than either. It runs natively on Kubernetes and a Raspberry Pi *in the same cluster*.**

## The problem with today's choices
| Need | Pi-hole v6 | Technitium v15 |
|---|---|---|
| Light enough for a Pi / small pod | ✅ tens of MB | ❌ ~150–300 MB + .NET runtime |
| Encrypted DNS (DoT/DoH/DoQ), in and out | ❌ needs sidecars (cloudflared, unbound) | ✅ |
| Recursive resolver + DNSSEC | ⚠️ DNSSEC via dnsmasq; recursion needs unbound | ✅ |
| Uses all CPU cores | ❌ single-threaded dnsmasq core | ✅ |
| Cluster / HA with one management plane | ❌ third-party sync scripts | ✅ (v14), but heavy per node |
| Kubernetes-native (Helm, probes, client-IP aware, Prometheus) | ⚠️ community charts and exporters | ⚠️ community charts; no native metrics |
| Per-query latency breakdown and percentiles | ❌ reply time only | ❌ aggregates only |
| Standard telemetry export (Prometheus/OTLP/dnstap) | ❌ | ❌ |
| Large blocklists without pain | ❌ slow gravity rebuilds; regexes checked one by one | ⚠️ memory-hungry per domain |
| Config-as-code / GitOps | ⚠️ TOML (v6) but lists live in SQLite | ❌ binary config |
| Safe extensibility | ❌ none | ⚠️ in-process plugins with full trust |
| AI-agent management (MCP, scoped tokens, previews) | ❌ | ❌ |

No product gives a homelabber all of these at once: Pi-class footprint, Kubernetes-native operation, hybrid HA, and real observability. **That gap is TelltaleDNS's reason to exist.**

## Why someone would choose TelltaleDNS — six defensible claims
Each claim is backed by a design mechanism *and* a measurable release gate (`spec/00 §5`). Claims are published only with numbers from the reproducible side-by-side benchmark (`spec/09 §3`).

1. **It's faster, and it stays fast while lists update.**
   - *Mechanism:* Rust (no garbage collector); a per-core UDP fast path; a cache that stores finished responses and only patches the ID and TTLs on a hit; blocklists compiled into one index where lookup cost doesn't grow with list size; list updates built in the background and swapped in instantly.
   - *Gates:* ≥ 150k qps cache-hit on 4 cores; ≤ 250 µs p99 added latency; ≤ 10% p99 regression *during* a 2M-domain list rebuild.
   - Pi-hole's single thread and Technitium's GC can't make that last promise structurally.

2. **It's lighter than both with big lists.**
   - *Mechanism:* the compressed list index costs ≤ 12 bytes per domain (vs. heavyweight objects or SQLite rows), memory-mapped so the OS can share and evict pages. The image is a ~10–15 MB static binary.
   - *Gates:* ≤ 20 MiB idle; ≤ 64 MiB with 1M blocked domains + 100k cached answers + full telemetry; it fits a 128 MiB Kubernetes limit and a Pi Zero 2 W.

3. **It tells you what is happening, not just how much.**
   - Every query is attributed to a device, explained (which list and rule blocked it, or which upstream answered), and timed per stage (filter, cache, upstream, DNSSEC).
   - Latency percentiles per upstream, device, and query type.
   - 30-day query-log search in seconds on a Pi.
   - First-seen-domain, NXDOMAIN-storm, and suspicious-domain detection.
   - Native Prometheus, OpenTelemetry, and dnstap, so it plugs into the Grafana stack you already run.
   - Neither incumbent offers per-stage timing, percentiles, or standard telemetry export.

4. **One cluster across a Pi and Kubernetes, managed from one place, and DNS never goes down because the control plane did.**
   - Any node's UI manages and analyzes the whole cluster. Config syncs as signed, versioned snapshots.
   - Every node answers from its last snapshot even if the primary is unreachable.
   - The HA design is honest about the owner's real two-node topology. Pure consensus can't safely fail over with two nodes, so TelltaleDNS uses a fenced primary with manual promotion, and adds automatic failover when a tiny witness or a third node exists. That beats both "no clustering" (Pi-hole) and "clustering, but every node costs 200+ MB" (Technitium).

5. **It's built for the platform you actually run.**
   - A Kubernetes-first Helm chart that *preserves real client IPs* (most DNS-on-k8s setups silently lose them, which ruins per-device analytics), probes, PDBs, autoscaling, ServiceMonitor, cert-manager, and GitOps mode.
   - The same signed container runs on the Pi.
   - Local accounts plus OIDC SSO (Authentik, Keycloak, Entra ID…) with role mapping, 2FA, and a hash-chained audit log.

6. **Built for agents, safely.**
   - A built-in MCP server on every node lets an AI agent answer questions like "why is the TV slow?" or "what did the new camera call home to?" from live analytics.
   - With plan/apply previews, impact estimates, and optional human approval, an agent can change config under least-privilege tokens with full audit attribution.
   - Neither incumbent offers an agent interface. Retrofitting one safely is far harder than designing for it.

**Plus, best of both:**
- From Pi-hole: the groups model, CNAME-cloaking defense, and simple UX.
- From Technitium: the full transport set (DoT/DoH/DoH3/DoQ) and recursion, "fastest" and parallel upstream racing, serve-stale/prefetch, and proxy/Tor upstreams.
- Additions: scheduled blocking, safe search, an "explain why" button, and custom upstreams via sandboxed out-of-process plugins.
- One-click import from Pi-hole (and Technitium) lowers switching cost to minutes.

## Where the incumbents still win (and why that's acceptable)
- **Maturity and community.** Pi-hole has a decade of users and list ecosystem; Technitium has years of production hardening. *Mitigation:* TelltaleDNS consumes the same lists and imports their configs, and v1.0 is gated on fuzzing, conformance tests, and a security review.
- **Authoritative DNS breadth.** Technitium is also a full authoritative server (DNSSEC signing, zone transfers). TelltaleDNS deliberately does not chase that in v1. It hosts local records and small zones, and defers public authoritative hosting to purpose-built servers.
- **Two-node automatic failover.** It is impossible to do safely without a third vote. TelltaleDNS makes that explicit (manual promote or a witness) instead of risking split-brain.
- **Native-install simplicity on very old/odd distros.** TelltaleDNS is container-first. A static binary exists, but Pi-hole's installer covers more exotic setups today.

## Who should *not* switch
People who need a public authoritative DNS server, people happy with a single Pi-hole and no interest in metrics, and anyone who needs LDAP authentication (explicitly out of scope; use an OIDC bridge).

## Risks and how the plan addresses them
| Risk | Mitigation |
|---|---|
| Ambitious scope delays v1 | Strict P0/P1 split. Milestones front-load the differentiators (performance, observability, k8s, clustering); DoQ/recursion/DHCP move to v1.x |
| Custom storage/index formats contain bugs | Versioned formats, fuzzing, golden tests, Parquet export as an escape hatch |
| HA correctness | Deterministic multi-node simulation + chaos suite; epoch fencing proven by checker before release |
| Benchmark claims challenged | Only harness-produced, reproducible numbers are published, with hardware and versions |
| Single-maintainer bus factor (the same weakness as Technitium) | Spec-driven repo, ADRs, requirement-ID traceability, permissive license |

## Bottom line
For a homelab running Kubernetes *and* a Raspberry Pi, TelltaleDNS is the only design that gives you:
- Pi-hole's weight class,
- Technitium's protocol reach,
- one cluster with one management pane across both,
- observability that is closer to an APM tool than to a hit counter.

Everything here is a design commitment tied to a measurable gate, not a marketing claim. That is what makes the position defensible.

*Detailed comparative analysis: `docs/analysis.md`. Build spec: `spec/`.*
