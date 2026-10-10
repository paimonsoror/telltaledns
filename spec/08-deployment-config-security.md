# 08 — Deployment, Configuration, Security

## 1. Recommendation: container-first everywhere
**Decision (ADR-004):** the primary artifact is a multi-arch OCI image, used **both** in Kubernetes and on a Raspberry Pi (Docker/Podman). The static binary is a by-product of the same build and is published too, but its support tier is "secondary".

Why this is the right path:
- **One artifact, one test matrix.** The image is `FROM scratch` + one static musl binary + CA bundle + tzdata, about 10–15 MiB. A container adds roughly no runtime overhead for a network daemon (host networking on the Pi avoids NAT entirely).
- **Pi upgrades become `docker compose pull && up -d`**, with trivial rollback by tag. That avoids distro/glibc drift (the reason Pi-hole needs per-OS install scripts, and Technitium needs a matching .NET runtime).
- The Pi joins the same cluster as the k8s pods with the same image version, which is required for CLU-010 compatibility.
- Native install remains possible for people who want it (no Docker on a Pi Zero, or appliance builds), at almost no maintenance cost, because the binary is static.

Support tiers: **Tier 1:** Helm on k8s/k3s (amd64, arm64); Docker/Podman Compose on Raspberry Pi OS / Debian / Ubuntu (arm64, armv7, amd64). **Tier 2:** static binary + systemd unit (`deploy/systemd/`) + `install.sh`. **Tier 3 (community):** Unraid/TrueNAS/Proxmox LXC templates, NixOS module.

## 2. Image (OPS-001)
- Built with `cargo zigbuild` or `cross` for `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, and `armv7-unknown-linux-musleabihf`. Release profile: `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`, `strip = true`, `opt-level = 3`. A profile-guided-optimization (PGO) build from the benchmark corpus is P1.
- `USER 65532:65532`, read-only root filesystem, `/var/lib/telltale` as the only writable volume. Needs `NET_BIND_SERVICE` only if binding < 1024 inside the container. `NET_ADMIN`/netlink is *not* needed: neighbor-table reads use unprivileged `/proc/net/arp` + netlink route dumps, which work with host networking.
- Signed with cosign (keyless), SBOM attached, provenance (SLSA level 3 via GitHub Actions).
- Tags: `X.Y.Z`, `X.Y`, `X`, `latest`, plus `edge` from main.

## 3. Kubernetes / Helm (OPS-002, OPS-003)
Chart: `deploy/helm/telltale`.

### 3.1 Shapes
| Value `mode` | Objects | Use |
|---|---|---|
| `allInOne` (default) | 1× StatefulSet (role=all, PVC) + Services | Small clusters, single replica, simplest |
| `scaled` | StatefulSet `controller` (1 replica, PVC, role=controller, eligible) + Deployment `resolver` (N replicas, role=resolver, ship telemetry) + HPA on CPU or `telltale_queries` rate + PDB (minAvailable 1) + topologySpreadConstraints/anti-affinity | Production, HA within the cluster |
| `daemonSet` | resolver as a DaemonSet with `hostNetwork: true` + controller StatefulSet | Bare-metal clusters wanting true client IPs and node-local DNS |

### 3.2 Exposure and the client-IP problem (critical for analytics)
Per-client analytics are worthless if every query appears to come from a node IP. The chart therefore:
- Creates **one** `LoadBalancer` Service with both UDP and TCP port 53 (supported since k8s 1.26 for mixed protocols), with `externalTrafficPolicy: Local` **by default**, and annotations for MetalLB (`metallb.universe.tf/loadBalancerIPs`) or kube-vip.
- Offers `hostNetwork: true` mode (DaemonSet/StatefulSet), with `dnsPolicy: ClusterFirstWithHostNet` and a port-conflict check documented for k3s (the k3s CoreDNS listens on cluster IPs only, so binding 53 on the host is fine; systemd-resolved stub conflicts are documented).
- DoH/DoT via Ingress/Gateway: requires TLS **passthrough** with PROXY protocol v2 (Traefik `IngressRouteTCP` / Gateway API `TLSRoute`) so client IPs survive. Alternatively, expose DoT/DoQ through the same LoadBalancer.
- **Validation:** `helm install` renders a `NOTES.txt` warning if `externalTrafficPolicy=Cluster`. At runtime, the resolver detects when > 90% of queries come from ≤ 3 IPs inside the pod/node CIDRs and raises a UI banner: "client IPs appear masked".

### 3.3 Config, secrets, probes
- `values.yaml → config:` renders a ConfigMap (`telltale.toml`) and enables GitOps mode if `gitops: true`. Secrets (admin bootstrap password hash, cluster join token, OIDC client secret, upstream tokens) come from existing Secrets referenced by name (`existingSecret`), so Sealed Secrets/External Secrets/SOPS work.
- Probes: `startupProbe /readyz?startup=1` (a fresh pod becomes ready only after the snapshot is applied and listeners are bound; maintenance doesn't count, OPS-010), `readinessProbe /readyz`, `livenessProbe /livez`. Resolver pods with no snapshot and no reachable controller stay unready (they never serve unfiltered DNS), unless `failOpen: true`.
- `ServiceMonitor` + `PrometheusRule` (default alerts) + Grafana dashboard ConfigMap (sidecar label) are optional.
- NetworkPolicy: allow 53/udp+tcp from configured CIDRs; 8443 cluster port between TelltaleDNS pods and from external cluster members (configurable CIDR, e.g., the Pi); egress to upstreams.
- Resources (defaults): resolver requests 50m/48Mi, limits 1 CPU/128Mi; controller requests 100m/96Mi, limits 2 CPU/512Mi (list compile). `GOMAXPROCS`-equivalent: worker threads default to `min(cpu limit, cores)`, read from the cgroup quota.
- cert-manager: an optional `Certificate` for DoH/DoT; the binary hot-reloads mounted certs.
- Upgrades: `maxUnavailable: 0, maxSurge: 1` for resolvers; `preStop` sleep 5 s plus graceful drain (OPS-007) so in-flight TCP/DoH finish.

### 3.4 Hybrid with an external Pi (the owner's topology)
```yaml
# values-k8s.yaml
mode: scaled
cluster:
  name: home
  joinTokenSecret: telltale-join          # token created on the primary (whichever node it is)
  site: k8s
  eligible: true                       # controller pod can be primary
  advertise: ["https://telltale-cluster.k8s.lan:8443"]
  peers: ["https://pi.lan:8443"]       # bootstrap peer list
  electionMode: manual                 # or "witness" with witnessUrl
service:
  dns: { type: LoadBalancer, loadBalancerIP: 192.168.1.53, externalTrafficPolicy: Local }
  cluster: { type: LoadBalancer, loadBalancerIP: 192.168.1.54 }   # 8443 reachable from the Pi
```
```yaml
# Pi: compose.yaml
services:
  telltale:
    image: ghcr.io/paimonsoror/telltale:1
    network_mode: host                 # real client IPs + MACs, no NAT
    restart: unless-stopped
    cap_add: [NET_BIND_SERVICE]
    user: "65532:65532"
    read_only: true
    volumes: ["./data:/var/lib/telltale", "./node.toml:/etc/telltale/node.toml:ro"]
    environment:
      TELLTALE_ROLE: all
      TELLTALE_CLUSTER_SITE: home-pi
      TELLTALE_CLUSTER_ELIGIBLE: "true"
      TELLTALE_TELEMETRY_MODE: local      # set "ship" if running on an SD card
```

## 4. Linux / Raspberry Pi native (OPS-004, Tier 2)
`install.sh` detects the arch, downloads + verifies (cosign/minisign) the binary, creates a `telltale` system user, and installs a hardened systemd unit with `DynamicUser`-style sandboxing (`ProtectSystem=strict`, `AmbientCapabilities=CAP_NET_BIND_SERVICE`, `NoNewPrivileges`, `MemoryMax=256M`). It also detects and offers to disable systemd-resolved's stub listener. Upgrades go through `telltale self-update` (verifies the signature, atomic swap, restart; refuses if the cluster's min version is incompatible).

**Pi guidance shipped in docs:** use `ship` telemetry or USB/SSD storage on SD-card Pis; Pi Zero 2 W: `workers=2`, cache 16 MiB, qlog retention 7 d.

## 5. Configuration model (OPS-005, OPS-009)
- **Precedence:** built-in defaults < `telltale.toml` (or cluster-replicated config) < `node.toml` (node-local allowed keys) < environment variables `TELLTALE_<SECTION>_<KEY>` < CLI flags.
- Schema in `telltale-config`, with a JSON Schema generated for editor completion (`telltale config schema`). Startup validation reports every error with its path, and `telltale config check file.toml` validates a file offline.
- Every config struct has `#[serde(deny_unknown_fields)]`. Config migrations are versioned (`config_version = 1`).
- Hot reload never drops queries: listener changes bind new sockets before closing old ones.

## 6. Security
- **Auth (API-003/004) — two supported identity sources, no LDAP:**
  1. **Local users ("basic auth"):**
     - Argon2id (m=19 MiB, t=2, p=1) passwords. UI login uses session cookies `HttpOnly; Secure; SameSite=Strict` + a CSRF token.
     - **HTTP Basic** (`Authorization: Basic`) on `/api/*` and `/metrics` is opt-in per user (`allow_basic_api = true`). It is intended for Prometheus scrapes, Homepage/Homarr widgets, and scripts, and is refused over plaintext HTTP unless `auth.allow_insecure_basic = true`. Verified credentials are cached for 60 s (keyed by a hash) so scrapes don't pay Argon2 cost each time.
     - API tokens are random 256-bit, stored hashed, scoped (`read`, `write`, `admin`, plus an optional group scope), with expiry.
     - TOTP 2FA with recovery codes (enforceable per role). Login rate limiting + lockout.
  2. **OIDC (P0):**
     - Authorization Code + PKCE, with discovery via `.well-known`, multiple providers, and a configurable claim for groups (`groups`, `roles`, or custom) → role mapping rules.
     - JIT provisioning, optional `require_verified_email`, and back-channel/RP-initiated logout.
     - The ID token is validated (iss/aud/exp/nonce, JWKS rotation). Sessions are local after login, so the IdP isn't needed per request.
     - Clustered nodes share the OIDC config via replication. Each node's redirect URI must be registered, or a single canonical `public_url` is used.
     - Optional `oidc.disable_local_login` keeps one break-glass local admin usable only from `allowed_admin_networks`.
  - LDAP is a non-goal (API-009).
- **RBAC roles:** `viewer` (dashboards, query log subject to privacy level), `operator` (pause, flush cache, manage lists/clients/groups), `admin` (everything incl. users, cluster, upstreams). A `family` role (P1) can only pause or unpause specific groups.
- **First run:** no default password. A one-time setup token is printed to logs / available via `telltale ctl setup-token`; the Helm chart can set a bootstrap admin from a Secret.
- **DNS abuse resistance:** refuse recursion for clients outside `allowed_networks` (default: RFC 1918, ULA, link-local, loopback, and pod/service CIDRs if detected). Response Rate Limiting for any listener exposed beyond the LAN. ANY minimization. Never act as an open resolver by default. The startup check warns if bound on a public IP.
- **Web:** strict CSP (no inline scripts), HSTS when TLS is on, `X-Frame-Options: DENY`. All UI rendering uses text bindings (Svelte escapes by default; no `{@html}` with user data), which directly targets the XSS/HTML-injection class Pi-hole fixed repeatedly in 2026. Config values with newlines/control chars are rejected at the schema layer (the class behind Pi-hole's 2026 newline-injection advisory).
- **Process:** non-root, read-only rootfs, no shell in the image, seccomp `RuntimeDefault`, all capabilities dropped except `NET_BIND_SERVICE`.
- **Plugins:** socket/exec plugins run as separate processes (they can run under a separate UID in native installs); WASM plugins are capability-scoped.
- **Audit log (API-006):** append-only and hash-chained (each entry includes the previous hash), replicated.
- **Vulnerability process:** `SECURITY.md`, private advisories, a 90-day disclosure policy.

## 7. DHCP (OPS-008, descoped)
**Descoped (ADR-091):** TelltaleDNS doesn't run a DHCP server; the router does. Device names come from the router's DHCP clients (`[[router]]`) and mDNS. The original text, for the record:

DHCPv4 server (static leases, options 3/6/15/42/119, lease file), disabled by default. In clusters, DHCP runs on exactly one designated node (no DHCP failover protocol in v1; documented). Leases feed client naming cluster-wide.

## 9. Node maintenance mode (OPS-010, ADR-118)
- **State, not config:** `<data_dir>/maintenance.json { until_ms, reason, by }`; default 1 h, at most 24 h; read at start, so a reboot inside the window comes back not ready. Allowed under GitOps.
- **On the node:** `/readyz` → 503 (the shutdown `ready` flag); heartbeats carry `maintenance_until` (optional field, N−1 ignores it); no candidacy in elections. Every listener keeps answering; replication, lists, probes, and the API continue.
- **A primary:** with automatic failover and another eligible node or quorum reachable, `handover = true` (default) makes it stop renewing its lease and decline candidacy, so a replica is elected within the lease window and it follows for the rest of the window; otherwise it stays primary and keeps publishing, and the UI/CLI say to promote another node first if it's going offline.
- **Elsewhere:** alert rules skip the node and its firing alerts resolve "(maintenance)"; the health level ignores its reasons and lists it under `maintenance`; Cluster-page checks skip it; alert rule `maintenance` (once on entry, resolved on exit).
- **Surfaces:** `POST`/`DELETE /api/v1/nodes/{id}/maintenance` (operator; an RPC to the target node, not via the primary), `telltale ctl maintenance start --for 2h --reason "..." [--node]` / `end`, Cluster page per-node action and banner, MCP `start_maintenance`/`end_maintenance` (`ops:maintenance`, agents ≤ 2 h), audit `node.maintenance.start|end`, `telltale_node_maintenance`, `telltale_node_maintenance_until_seconds`.
- **Kubernetes:** one readiness probe per pod serves every Service, so a controller pod in maintenance also leaves the API Service; use another node's UI or a port-forward. The startup probe asks `/readyz?startup=1`, which leaves maintenance out, so a pod restarted inside its window isn't killed (ADR-118, amended). Design: `docs/design/maintenance-mode.md`.

## 8. Backup / migration (API-007)
- `telltale ctl backup create [--include-qlog]` → a `.ttbk` (tar.zst + manifest + signature). Restore onto a new primary.
- **Importers:**
  - Pi-hole v5 (`gravity.db` + `setupVars.conf`) and Pi-hole v6 Teleporter zip (`pihole.toml` + `gravity.db`): adlists, domainlists (exact/regex, allow/deny), groups, clients, local DNS/CNAME records, upstreams, conditional forwarding. The importer reads the documented SQLite schema (data, not code).
  - Technitium (P1): backup zip → blocked/allowed zones, block-list URLs, forwarders + protocols, Advanced Blocking app config → groups.
  - The import report lists every unmapped setting.
