# 00 — Product Overview

## 1. Vision
**TelltaleDNS** is a filtering, encrypting, observable DNS resolver for homelabs and small networks. It aims to combine:
- **Pi-hole's** footprint and approachability, and
- **Technitium's** protocol completeness,

and to beat both on **performance, observability, and cloud-native operation**. It ships as one static Rust binary in a multi-arch container, Kubernetes-first, and runs equally well on a Raspberry Pi.

## 2. Goals (in priority order)
1. **Performance.** Sub-millisecond answers for cache hits and blocked queries; multi-core scaling; no GC pauses; zero query impact during list reloads.
2. **Lightweight footprint.** Small image, low RSS, viable on a Raspberry Pi Zero 2 W / Pi 3 / Pi 4 and on a 128 MiB Kubernetes pod limit.
3. **Observability.** Every query is attributable to a client, timed per stage, and explained (why it was blocked or allowed, which upstream answered, how long each step took). Analytics are fast over long windows and exportable with open standards (Prometheus, OTLP, dnstap).
4. **Clustering and HA with a single management plane.** Nodes of any deployment type form one cluster: a Raspberry Pi on bare metal, pods in Kubernetes, a VM. Config syncs automatically. One UI/API manages everything and shows cluster-wide analytics. **DNS answering never depends on cluster health.** The reference topology is the owner's: one Pi node plus one Kubernetes deployment, two sites, no third voter.
5. **Kubernetes-first operation.** Horizontally scalable resolvers, declarative config (GitOps), a Helm chart, real client-IP preservation, probes, PodDisruptionBudgets, and ServiceMonitor. The same container runs on a Pi via Docker/Podman.
6. **Upstream completeness.** Every upstream type Pi-hole and Technitium support (plain UDP/TCP, DoT, DoH (HTTP/2 and HTTP/3), DoQ, recursive-from-root, conditional/per-domain forwarding, SOCKS5/HTTP proxy), plus *custom* upstreams through a plugin interface.
7. **Best-of-both filtering.** Pi-hole's group model and CNAME inspection, Technitium/AdGuard-style rule syntax, compiled regex, schedules, and safe search.
8. **Agent-manageable.** A first-class API and built-in MCP server let AI agents run analytics and (with plan/apply + approval) manage the platform under least privilege and full audit.

## 3. Non-goals for v1
- Authoritative DNS hosting beyond **local records and small local zones**. Use a real authoritative server (PowerDNS, Knot, BIND) for public zones. We will **not** chase Technitium's full authoritative feature set (DNSSEC signing, zone transfers as primary) in v1.
- A DHCP server. Routers hand out addresses; TelltaleDNS reads their client lists for device names (ADR-091).
- Windows/macOS native service packaging. Containers cover those hosts.
- LDAP/Active Directory authentication. Auth is local users (basic auth) + OIDC only.
- Running HTTP block pages. HTTPS makes them ineffective; we return DNS-level block responses with EDE codes instead.

## 4. Personas
| Persona | Needs |
|---|---|
| **Homelabber (primary)** | One or two Pis or a k3s cluster; wants blocking, pretty dashboards, per-device insight, encrypted upstreams, and easy setup. |
| **Platform tinkerer** | Runs a Kubernetes cluster; wants Helm, GitOps, Prometheus/Grafana, HA, and rolling upgrades with no DNS outage. |
| **Family admin** | Per-kid device groups, bedtime schedules, safe search, a "pause blocking for 10 min" button. |
| **Small office** | Several hundred clients; SSO; audit log; conditional forwarding to AD DNS; DoH for roaming laptops. |

## 5. Success metrics (v1.0 release gates)
All performance gates are measured with the harness in `09`.
| Metric | Target |
|---|---|
| Cache-hit throughput, 4-core x86-64 | ≥ 150k qps at < 1% loss |
| Cache-hit throughput, Raspberry Pi 4 | ≥ 25k qps |
| Added latency for cache hit / blocked answer (p99, at 50% of max load) | ≤ 250 µs |
| Idle RSS, no lists | ≤ 20 MiB |
| RSS with 1M blocklist domains + 100k cache entries + telemetry on | ≤ 64 MiB |
| Compressed container image | ≤ 15 MiB per arch |
| List recompile (2M domains, Pi 4) | ≤ 8 s, with p99 query-latency regression ≤ 10% during compile |
| Cold start to serving (with compiled snapshot on disk) | ≤ 500 ms |
| Query-log search, 30 days / 50M rows, filtered by client + domain substring, Pi 4 | ≤ 2 s |
| Config change propagation, primary → all reachable nodes (incl. cross-site Pi) | ≤ 5 s p95 |
| DNS availability when the primary/controller is down | 100%: every replica keeps answering with its last snapshot |
| Primary failover (witness configured) | Config writes available again ≤ 30 s |
| Telemetry loss under sustained max load | 0% for counters/histograms; query-log sampling only if explicitly configured, and drops always counted |

## 6. Glossary
- **Data plane / resolver:** the process role that answers DNS.
- **Control plane / controller:** the process role that hosts the API, UI, analytics store, and list compiler, and distributes config.
- **All-in-one:** both roles in one process (default for a Pi or single-node install).
- **Snapshot:** an immutable, versioned, compiled bundle of config + filter data, distributed from the controller to resolvers.
- **QueryEvent:** a fixed-schema record emitted for every DNS transaction.
- **Client:** an identified requester (IP, MAC, client ID, or a named device that aggregates those).
- **Group:** a set of clients that share filtering policy, upstream policy, and schedules.

## 7. Document map
| File | Contents |
|---|---|
| `01-requirements.md` | Numbered functional and non-functional requirements (the contract) |
| `02-architecture.md` | Process model, data/control plane, threading, crates, data flow |
| `03-resolution-pipeline.md` | Listeners, parsing, policy, cache, local data, DNSSEC, recursion |
| `04-upstreams.md` | Upstream protocols, strategies, health, routing, custom upstream plugins |
| `05-filtering.md` | List formats, rule engine, compiled snapshot format, groups, schedules |
| `06-observability.md` | QueryEvent, metrics, query-log store, analytics, exports |
| `07-api-and-ui.md` | REST/streaming API, auth, UI scope |
| `08-deployment-config-security.md` | Kubernetes/Helm, Pi/Linux, config model, security |
| `13-agent-api-and-mcp.md` | Agent-ready API, MCP server, agent auth/guardrails, plan/apply |
| `12-clustering-and-ha.md` | Cluster membership, config replication, failover/fencing, federated telemetry, single management plane |
| `09-testing-and-benchmarks.md` | Test strategy, conformance, comparative benchmark harness |
| `10-roadmap-and-tasks.md` | Milestones and ordered task list with acceptance criteria |
| `11-decisions.md` | Architecture Decision Records |
