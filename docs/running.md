# Running TelltaleDNS

> **Status:** stable releases are listed on the [releases page](https://github.com/paimonsoror/telltaledns/releases). This page describes `main`; each release's notes say what it contains. Releases before 1.0 can still change configuration keys and APIs, and their notes call out every such change. What stands between 0.x and 1.0 is tracked in [`docs/v1-gate.md`](v1-gate.md).

## Start
```sh
telltale run                         # uses $TELLTALE_CONFIG, else /etc/telltale/telltale.toml, else defaults
telltale run -c telltale.toml        # explicit config file(s); later files override earlier ones
```
A minimal working config:
```toml
[[listen]]
proto = "udp"
addr = "127.0.0.1:5300"

[[listen]]
proto = "tcp"
addr = "127.0.0.1:5300"

[[upstream]]
name = "cloudflare"
url = "udp://1.1.1.1"

[[upstream]]
name = "quad9"
url = "udp://9.9.9.9"

[[upstream_group]]
name = "default"          # queries that match no route use this group
members = ["cloudflare", "quad9"]
strategy = "fastest"      # failover | round_robin | weighted | fastest | parallel
```
```sh
telltale run -c dev.toml
dig @127.0.0.1 -p 5300 example.com
```
Defaults without `[[listen]]`: UDP and TCP port 53 on `0.0.0.0` and `[::]`, with one worker thread per available CPU (container CPU limits are respected). Ports below 1024 need root or `CAP_NET_BIND_SERVICE`. DoT, DoH, DoQ, and DoH3 listeners are described in "[Encrypted DNS for your devices](#encrypted-dns-for-your-devices-dot-doh-and-doq)".

## Container image
`ghcr.io/paimonsoror/telltale:latest` is the newest stable release (also `:X.Y.Z`, `:X.Y`, and `:X`; `:edge` is built from every commit on `main`), for `linux/amd64`, `linux/arm64` (Raspberry Pi 3/4/5 with a 64-bit OS), and `linux/arm/v7` (32-bit Pi OS). It contains one static binary, CA certificates, and time-zone data, about 13 MiB compressed, with no shell. It runs as user `65532:65532`.
```sh
docker run -d --name telltale --restart unless-stopped \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  -p 53:53/udp -p 53:53/tcp -p 8053:8053 -p 9153:9153 \
  -v "$PWD/telltale.toml:/etc/telltale/telltale.toml:ro" \
  -v telltale-data:/var/lib/telltale \
  ghcr.io/paimonsoror/telltale:latest
```
- The config is read from `/etc/telltale/telltale.toml` when it exists; otherwise the built-in defaults apply. `/var/lib/telltale` is the only path written to.
- With `-p` (bridge networking), port 53 works with every capability dropped: Docker lets unprivileged users bind low ports inside the container's own network namespace.
- With `--network host` (useful on a Pi, so the logs show real client addresses), that exception doesn't apply. Let unprivileged users bind port 53 on the host:
  ```sh
  echo 'net.ipv4.ip_unprivileged_port_start=53' | sudo tee /etc/sysctl.d/50-telltale.conf && sudo sysctl --system
  ```
  Alternatively, run the container as root with only that one capability: `--user 0:0 --cap-drop ALL --cap-add NET_BIND_SERVICE`. Adding `NET_BIND_SERVICE` while running as `65532` doesn't work, because Docker doesn't pass added capabilities to non-root users.
- Reload with `sudo kill -HUP "$(docker inspect -f '{{with .State.Pid}}{{.}}{{end}}' telltale)"` (not `docker kill -s HUP`, see [Reload in Docker](#reload-in-docker)); stop with `docker stop` (a graceful drain, see [Stop](#stop)).

Build it yourself with `docker buildx build -t telltale:dev .` (add `--platform linux/amd64,linux/arm64,linux/arm/v7` for all three). The build cross-compiles, so it doesn't need QEMU.

## Raspberry Pi and Linux
Two ways, both with real client addresses (host networking) and port 53 without running as a full root process. Native is the simplest on a Pi or any Linux machine, because it needs no Docker; use the Docker Compose bundle (described after the native steps) if you already run Docker. Pi 3, 4, 5, and Zero 2 W are supported (64-bit or 32-bit OS); ARMv6 boards (Pi 1, Zero W) aren't.

**Native (systemd), recommended:** `deploy/systemd/install.sh` downloads the static binary for your CPU, checks the release signature (minisign) and its SHA-256, creates a `telltale` system user, installs a sandboxed systemd unit (`ProtectSystem=strict`, only `CAP_NET_BIND_SERVICE`, `MemoryMax=256M`) and the starter config (an existing `/etc/telltale/telltale.toml` is kept), then starts the service and waits until it's ready.
```sh
curl -fsSLO https://raw.githubusercontent.com/paimonsoror/telltaledns/main/deploy/systemd/install.sh
less install.sh                     # read before running as root
sudo sh install.sh                  # the latest release; --edge: builds from main
sudo -u telltale /usr/local/bin/telltale auth setup-token -c /etc/telltale/telltale.toml
```
**Guided setup.** Run in a terminal on a new machine, the installer asks one question first: press Enter for the recommended settings (the starter config: encrypted upstreams, one balanced blocklist, a 7-day query log), or choose **Walk me through the options**. Each step shows its default in `[brackets]`; Enter or `skip` keeps it:
1. **Builds:** releases or edge.
2. **Upstreams:** Cloudflare and Quad9 (encrypted, the default), one provider (Cloudflare, Quad9, Google, Mullvad, AdGuard), plain DNS for networks that block port 853, or your own server.
3. **Starting blocklists:** one or more of HaGeZi Pro (the default), Light, Pro++, Threat Intelligence, Steven Black's hosts, and OISD small, or none (add lists later on the Lists page).
4. **Where DNS listens:** every address, or one.
5. **systemd-resolved:** turn its stub listener off if it holds port 53.
6. **The first admin:** a setup token for the web UI (the default), or a username and password now.
7. **The query log:** how many days to keep, and how much it records (privacy level 0 to 3).

A summary comes before anything is installed. The answers become `/etc/telltale/telltale.toml`, checked with `telltale config check` before the service starts.
- **No guided questions** when stdin isn't a terminal (`curl … | sh`, automation), with `--yes`, or when `/etc/telltale/telltale.toml` already exists (a re-run upgrades the binary and keeps your config). One question can still come, in a terminal, even on a re-run or with `--yes`: when systemd-resolved is running with its stub listener on (Ubuntu and some Debian setups), the installer asks `[Y/n]` whether to turn the stub off. `--disable-resolved-stub` answers it in advance; without a terminal the installer leaves systemd-resolved as it is. To see the guided questions again on a machine that already has TelltaleDNS, run `sh install.sh --config-only /tmp/test.toml` (it changes nothing), or uninstall first (below).
- **Automation:** `--interactive` asks even without a terminal and reads the answers from stdin; `--config-only FILE` writes the config and stops (no root needed), to see what the answers produce.
- **The first admin "now"** is created on the service's first start from an Argon2id hash in a root-only systemd drop-in, which the installer removes once the service is up. The password itself isn't stored.

Re-running it upgrades the binary in place. `sudo telltale self-update --restart` does the same check-and-swap from the binary itself (`--channel edge` for builds from main, `--check` to only look): it verifies the signature with the release key built into the binary and the binary's SHA-256, test-runs the download, swaps it in atomically, and keeps the previous binary as `telltale.old`. In containers it refuses (pull a new image instead). `--to 0.8.0` installs that version only, from its own release page (older than the running one too: that's how to go back), and `--to 0.8.0-edge.393` an edge build while it is still the newest on the edge channel (edge binaries are replaced on every build, so an older one can't be downloaded); the release's signed `releases.json` must name the version and list the same checksum. To let the cluster upgrade the node for you, see [Upgrading from the cluster](#upgrading-from-the-cluster) (`install.sh --cluster-updates`).

**Uninstalling:** `sudo sh install.sh --uninstall` stops and disables the service and removes its unit and the binary (`telltale.old` too).
- **The system resolver:** if the install turned off systemd-resolved's stub listener, it asks to restore it (the default). `/etc/resolv.conf` is put back as the install found it (the install records the link it replaced, or keeps a copy of the file), and systemd-resolved is restarted, so the machine resolves names again without TelltaleDNS. Without a terminal or with `--yes` it restores without asking; `--keep-resolver` leaves it as the install set it. Installs from before this was recorded get the usual stub link (`/run/systemd/resolve/stub-resolv.conf`).
- **Config and data** (`/etc/telltale`, `/var/lib/telltale`: users, query log, lists) are kept, so a later install picks them up. It asks whether to delete them; `--purge` deletes them and the `telltale` user without asking.
- Point your router's DNS setting back at your previous server if it handed out this machine.

**Docker Compose:** `deploy/compose/` has `compose.yaml` and a starter `telltale.toml` (encrypted upstreams, one balanced blocklist, a 7-day query log).
```sh
mkdir telltale && cd telltale
curl -fsSLO https://raw.githubusercontent.com/paimonsoror/telltaledns/main/deploy/compose/compose.yaml
curl -fsSLO https://raw.githubusercontent.com/paimonsoror/telltaledns/main/deploy/compose/telltale.toml
docker compose up -d
docker compose exec telltale telltale auth setup-token     # then open http://<host>:8053/
```
The container uses the host network, a read-only root filesystem, and only `NET_BIND_SERVICE`, as root inside the container by default. To run it as the image's unprivileged user, set `net.ipv4.ip_unprivileged_port_start=53` on the host (`echo net.ipv4.ip_unprivileged_port_start=53 | sudo tee /etc/sysctl.d/50-telltale.conf && sudo sysctl --system`) and switch `user:` in `compose.yaml`. Updates: `docker compose pull && docker compose up -d`. Reload the config without a restart: see [Reload in Docker](#reload-in-docker).

**Port 53 already in use:** the default listeners are on `0.0.0.0` and `[::]`, and on Linux a program that listens on port 53 on any one address of the machine is enough to block them (always for TCP; for UDP, a program that also sets `SO_REUSEPORT` and runs as the same user doesn't block the bind, and then shares the port with TelltaleDNS). The start then stops with, for example, `telltale: Udp 0.0.0.0:53: Address already in use (os error 98)`, followed on the same line by what to do. To see which program holds the port (`sudo` shows the processes of every user):
```sh
sudo ss -lunp 'sport = :53'    # UDP
sudo ss -ltnp 'sport = :53'    # TCP
```
The usual ones are systemd-resolved's stub listener on `127.0.0.53` (below), `dnsmasq` (including the one libvirt starts for its virtual machine network, on the bridge's address, often `192.168.122.1` on `virbr0`), another resolver or ad blocker, and the built-in DNS service of a NAS or router. Stop the program if TelltaleDNS replaces it. To run beside it with a native install or host networking (the Compose bundle), listen on this machine's own address instead of on every address:
```toml
[[listen]]
proto = "udp"
addr = "192.168.1.2:53"   # this machine's LAN address

[[listen]]
proto = "tcp"
addr = "192.168.1.2:53"
```
With Docker Compose this goes into the bundle's `telltale.toml`, which `compose.yaml` mounts as `/etc/telltale/telltale.toml` and which has this example commented out. With `[[listen]]` set, only the listed addresses answer: the machine itself on `127.0.0.1` and a device that reaches the machine on another of its addresses (a second network, a VPN, a virtual machine network) get no answer, so list every address that should answer, IPv6 ones included. Each listed address must exist when TelltaleDNS starts (a static address, or a DHCP reservation in the router); if it isn't there yet, the start fails and systemd (`Restart=on-failure`) or Docker (`restart: unless-stopped`) tries again. With published ports (`docker run -p`, as in "Container image") the address doesn't exist inside the container, so leave `[[listen]]` as it is and publish on the one address instead: `-p 192.168.1.2:53:53/udp -p 192.168.1.2:53:53/tcp`. A reload applies listener changes, binding the new listeners before it closes the old ones; a listener other than plain UDP (tcp, dot, doh, doq, doh3) that moves between the wildcard address and one address on the same port therefore needs a restart, because the old listener still holds the port. After a failed start, a restart is the simplest way anyway (`sudo systemctl restart telltale`, `docker compose restart`).

On Ubuntu and some Debian setups, systemd-resolved's stub listener holds `127.0.0.53:53`. `install.sh` turns it off with the recommended settings of a new install in a terminal, asks in the walk-through (step 5), and asks `[Y/n]` on a re-run or with `--yes` in a terminal; without a terminal it leaves it as it is, unless `--interactive` feeds the answers of a new install; `--disable-resolved-stub` turns it off without asking (the walk-through still asks, and its answer wins). The machine then resolves through TelltaleDNS. After turning it off the installer waits up to 15 seconds for port 53 to be free before it starts the service; if something still holds it, the installer prints what (the `ss` line, with the process) and the next step; for Compose, add `DNSStubListener=no` under `[Resolve]` in `/etc/systemd/resolved.conf.d/telltale.conf` and `sudo systemctl restart systemd-resolved`.

**Small Pis and SD cards:** the query log writes continuously; keep `[telemetry.qlog] retention_days` short (the starter config uses 7) or put `/var/lib/telltale` on a USB SSD. On a Pi Zero 2 W (512 MB) also set `[node] workers = 2` and `[cache] max_bytes = "16MiB"`, and prefer smaller blocklists.

Then point your router's DHCP DNS server setting at the Pi's address so every device uses it.

## Moving from Pi-hole
`telltale import pihole PATH -o pihole.toml` turns a Pi-hole setup into TelltaleDNS configuration. PATH is a Teleporter export (Settings → Teleporter → Export: a `.zip` from Pi-hole v6, a `.tar.gz` from v5), a `gravity.db`, or a copy of `/etc/pihole`. The output is checked to load before it's written.

| Pi-hole | TelltaleDNS |
|---|---|
| Upstream DNS servers (`IP#port`) | `[[upstream]]` `pihole-N` in the `default` upstream group, strategy `fastest` (Pi-hole also prefers the fastest server) |
| Conditional forwarding (rev servers) | an upstream, an upstream group, and a `[[route]]` for the local domain and every reverse zone of the network (a /23 is two /24 zones), with a DNSSEC negative trust anchor |
| Local DNS records, CNAME records | `[[record]]` A/AAAA and CNAME (with the CNAME's TTL) |
| Adlists (`https://`, `file://`) | `[[list]]` named `pihole-<id>-<file>`, with `url` or `path`; switched-off ones stay with `enabled = false`; v6 allowlists become `kind = "allow"` |
| Allowed / denied domains, exact and regex | inline lists `pihole-allow-exact`, `pihole-deny-regex`, ..., one per set of groups. Exact entries match only that name (`match = "exact"`). Regexes keep `;querytype=` and `;invert` |
| Groups (Default → `default`) | `[[group]]` with exactly the lists Pi-hole gave it. A switched-off group gets no lists |
| Clients (IP, CIDR, MAC) | `[[client]]` named by the Pi-hole comment, in the same groups. Clients in no group (nothing is blocked for them in Pi-hole) go to `pihole-no-group`, which has no lists |
| DHCP reservations | named devices: the MAC and IP join a matching client, or become a new one named by the host name |
| DNSSEC, rate limit, blocking mode (NULL, NXDOMAIN, NODATA) | `[dnssec] mode = "validate"`, `[ratelimit]`, each group's `block_mode` |

The header lists what has no equivalent, by setting name (values, such as password hashes, are never copied):
- clients matched by host name or network interface (add their IP or MAC instead);
- the DHCP server (TelltaleDNS leaves DHCP to your router);
- privacy level, web-server, and other Pi-hole-only settings. From v6, only settings marked as changed from their defaults are listed;
- the `IP` blocking modes, entries switched off, and domain entries our regex engine can't run (backreferences and lookaround).

Query history, the admin password, and API tokens aren't imported. The output is a complete starting configuration: on a fresh install, use it as is next to your node settings (`telltale run -c telltale.toml -c pihole.toml`). Into an existing one, merge by hand: both define the `default` upstream group and group. Upstreams on the Pi-hole machine itself (`127.0.0.1#5335`, usually unbound) are flagged: keep that resolver running next to TelltaleDNS (a built-in recursive resolver is on the post-1.0 list). CI imports real exports from the official Pi-hole v6 and v5 images and checks the answers (`deploy/pihole-import-e2e.sh`).

## Moving from Technitium
`telltale import technitium http://192.168.1.2:5380 -o technitium.toml` reads a running Technitium DNS Server through its API and writes TelltaleDNS configuration. In Technitium, create an API token (Administration → Sessions → Create Token). Pass it in `TECHNITIUM_TOKEN`, or in a file with `--token-file`; it's never a command-line argument, so it doesn't show up in `ps`. The output is checked to load before it's written, and the token never appears in it.

| Technitium | TelltaleDNS |
|---|---|
| Forwarders (UDP, TCP, TLS, HTTPS; `name (ip:port)` pins the address) | `[[upstream]]` `technitium-N` in the `default` group; concurrent forwarding becomes `parallel` with the same fan-out |
| Primary zones | `[[record]]` A, AAAA, CNAME, PTR, TXT, MX, SRV, with their TTLs (SOA and apex NS aren't needed) |
| Forwarder zones (conditional forwarding) | upstreams by priority, a group, and a `[[route]]` for the zone. A negative trust anchor applies unless every forwarder of the zone validated |
| Block list URLs (`!` = allow list), blocked and allowed zones | `[[list]]`; the zones become inline lists `technitium-blocked` / `technitium-allowed` (subtree, like Technitium) |
| Blocking type (NXDOMAIN, custom address) | each group's `block_mode` |
| Advanced Blocking app groups | `[[group]]` with the group's URL lists (shared when groups use the same URL), names, and regexes. The group for `0.0.0.0/0` becomes `default`; other networks become the group's `networks`. Server-wide lists apply to every group |
| Blocking bypass list | a `technitium-bypass` group with those networks and no lists |
| DHCP reservations | named devices (MAC and IP) |
| DNSSEC validation, per-address rate limit, saving the cache | `[dnssec]`, `[ratelimit]` (queries per minute), `[cache] persist` |

The header lists what isn't imported:
- secondary and stub zones;
- forwarders given only by name;
- record types we don't serve locally;
- groups chosen by listener or DoH host name;
- per-list blocking answers;
- the DHCP server;
- encrypted listeners (set them up under Encrypted DNS for your devices);
- recursion ACLs, TSIG, zone transfers, the outgoing proxy, and other apps.

Technitium's backup files use a private binary format, so the importer reads the documented API instead (ADR-062). CI runs it against the official Technitium image (`deploy/technitium-import-e2e.sh`).

## Versions and updates
Every build says exactly what it is, the same way on every architecture:
```
$ telltale --version
telltale 0.1.0-edge.64 (commit 3f46fd4, built 2026-10-05T12:00:00Z, channel edge, aarch64-unknown-linux-musl)
```

**Version formats:**
- releases are `0.1.0`;
- builds of `main` are `0.1.0-edge.<run>`;
- a local build is `dev` with its commit.

The same build identity, and how the node was installed (`native`, `container`, or `helm`), shows in the web UI's sidebar (with the node's name and, in a cluster, whether it's the **primary** or a **replica**: changes saved on a replica's UI go to the primary) and **Settings → System → Version and updates**, in `GET /api/v1/system/info` (`build`, `update`), in `telltale_build_info{version,commit,channel,target}`, and on the Cluster page for every node.

**Update checks:**
- **How:** once a day, a node reads its channel's `releases.json` (published with every release, signed with the release key) and compares versions: `up_to_date`, `available`, `newer` (a dev build), or `unknown` (not checked yet, or failing). An index whose signature doesn't verify is ignored.
- **When:** a minute after the node starts, then every 24 hours (an hour after a failed check). To look now, an admin clicks **Check now** under **Settings → System → Version and updates** (`POST /api/v1/system/update-check`). It's handy on the edge channel, which publishes several builds a day. Clicks less than a minute apart show the last result without fetching again. Nothing is installed.
- **Where it shows:** an **update** pill next to the version in the sidebar, the Version and updates panel (with the step for your install), the Cluster page (each node's version), and `telltale_update_available` (1 when an update exists).
- **Air-gapped:** `[updates] check = false` means nothing leaves the node; `[updates] index_url` points at a mirror (still verified with the built-in key).

**Checking what you run** (NFR-005):
- **Binaries:** `SHA256SUMS` is signed with the release key (minisign; `install.sh` and `telltale self-update` check it for you). The public key is `deploy/release/telltale-release.pub`.
- **Images** are signed with [cosign](https://docs.sigstore.dev/) through GitHub's keyless signing: the signature names the repository's image workflow, and is in Sigstore's public log.
  ```sh
  cosign verify ghcr.io/paimonsoror/telltale:0.5.0 \
    --certificate-identity-regexp '^https://github\.com/paimonsoror/telltaledns/\.github/workflows/image\.yml@' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  ```
- **What's inside:** each binary carries its dependency list (`cargo audit bin telltale` reads it), and every release has a CycloneDX SBOM per binary (`telltale-<arch>-linux.cdx.json`, listed in the signed `SHA256SUMS`).
- **Rebuilding:** a release builds the same bytes from the same commit. The build date in `--version` is the commit's time. To compare, build the Dockerfile's `bin` stage with the build arguments `--version` shows (`TELLTALE_BUILD_VERSION`, `TELLTALE_BUILD_COMMIT`, `TELLTALE_BUILD_DATE`, `TELLTALE_BUILD_CHANNEL`) and `SOURCE_DATE_EPOCH` set to the commit's Unix time, then compare checksums. A nightly job builds every commit twice from scratch and fails if the two differ.

The UI never replaces a node's binary itself. The panel shows the step for your install:
- **Native:** `sudo telltale self-update --restart` (`--channel edge` for edge).
- **Container:** `docker compose pull && docker compose up -d`.
- **Helm:** `helm upgrade`, or bump the chart version in your GitOps values.

In a cluster, upgrade replicas first. A cluster can do this for its native nodes: see [Upgrading from the cluster](#upgrading-from-the-cluster).

## Backups and moving to a new machine
```sh
telltale backup create -o pi.ttbk               # safe while TelltaleDNS runs
telltale backup create --include-qlog -o pi.ttbk # also the query log (can be large)
telltale backup show pi.ttbk                     # check it and list what's in it
telltale backup restore pi.ttbk                  # on the new machine, TelltaleDNS stopped
```
Admins can also download one in the web UI (**Settings → System → Download a backup**) or with `GET /api/v1/backup`. Each download is recorded in the audit log as `backup.create`. Downloads leave out the query log; use the command for that.

**In a backup:**
- the config files the node was started with;
- users (password hashes, two-factor secrets) and API tokens;
- devices, names, and forwarded domains made in the UI;
- the audit log, statistics history, and anomaly baselines;
- the query log, with `--include-qlog`.

**Left out:**
- sign-in sessions (everyone signs in again);
- downloaded lists, compiled snapshots, and the cache, which are rebuilt;
- the cluster identity and its CA key. A restored cluster member starts on its own: run `telltale cluster init` or join it again;
- router keys pasted in the UI (`secrets/` in the data folder): after a restore, each such router says **key missing: enter it again** until an administrator pastes it again. A copy of the whole data folder, a volume snapshot, or a Kubernetes PVC snapshot does hold those keys in plain text: keep `secrets/` at mode 0700 and its files at 0600, keep such copies private, and encrypt the volume or the snapshot storage.

The file is zstd-compressed tar with a manifest of BLAKE3 checksums, written owner-only (`0600`); keep it private.

**Restore:**
- Every file is checked before anything is written, so a damaged or truncated backup changes nothing.
- Existing files are only replaced with `--force`.
- Data goes back to the directory it came from, or `--data-dir`. Config files go back where they were, or `--config-dir`.
- It refuses while TelltaleDNS is running on that data directory (it can't take the directory's lock): stop the service first.
- Files are given the data directory's owner, so a restore run as root works for the `telltale` service user.
- If you restore into a different data directory, the restored config still names the old one: restore says so, and you set `data_dir` (or add a small file that does).

## Support package
When something goes wrong, the most useful thing to attach to an issue is a **support package**: one `.tar.gz` with what a maintainer needs to see, and nothing that identifies you. It holds build and platform facts; your settings without secrets; the cluster view and its timeline; health checks and listener checks; upstream state; list names and counts (no domains); a snapshot of the metrics; aggregate statistics; this node's recent log; and the newest [watchdog dump](#when-a-node-stops-answering-the-watchdog), if the node wrote one (without its log lines at the `strict` level). Nothing is uploaded: you make it, look it over, and attach it yourself.

**Making one**
- In the web UI: **Settings → System → Support package** (admins). **Preview what it holds** lists every file with its size and what would be replaced; **Make the package** downloads it.
- From a shell: `telltale support-package` (it asks the running node, with an admin's API token in `TELLTALE_TOKEN` or `--token-file`). Add `--list` to see what it would hold and write nothing.
- With no token, or with `--offline`, it is made from the configuration files and the log files instead, without asking a running node: use that when the node won't start. It has no live state (no cluster, health, upstreams, or metrics), and says so.
- Over the API: `POST /api/v1/system/support-package` with `{"level": "strict"}` (admin; `?dryRun=true` answers with the manifest only; `"cluster": true` for every node's part). It isn't an MCP tool and no agent scope covers it.

```sh
telltale support-package                               # strict (the default): ./telltale-support-<node>-<time>.tar.gz
telltale support-package --level standard --query-sample 200 --reveal pi
telltale support-package --keep-map map.txt            # also write what each pseudonym stands for (keep it private)
telltale support-package --offline -c /etc/telltale/telltale.toml
telltale support-package --cluster                     # every node's part, in one package
```

**A package for the whole cluster** (`--cluster`, or "Every node in the cluster" on the page)
- The node you ask makes a key for this one package and sends it to every reachable node over the cluster's own authenticated connection (it is never stored). **Each node makes and redacts its own part**, so no real name or address crosses the network, and sends it back compressed. The package holds `nodes/<node>/` for each, laid out like a package from that one node, and a `MANIFEST.json` that lists every node and whether it answered.
- A device, group, or host has **the same pseudonym on every node** (`device-a3f9c2e1`: a few bytes of a keyed hash, so the nodes agree without comparing notes), and addresses are permuted the same way everywhere. A single-node package numbers its names instead (`device-3`).
- A node that doesn't answer in 45 seconds, is older than this feature, is busy making another package, or has no open connection is listed as missing, with a fixed reason; the rest of the package is complete. Ephemeral members (pods that come and go) are asked like the others but can't ask.
- The 20 MiB cap is shared: each node's part gets an equal share, the largest files are cut first, and a part is also cut to fit what the cluster connection carries (about a mebibyte compressed). The manifest says what was cut.
- Not with `--keep-map` (there is no map: the names never leave their nodes), and not with `--offline`.

**Levels** (`--level`, or the choice on the page)
| Level | What it does |
|---|---|
| `strict` (default) | IP and MAC addresses, host, device, client, group, node, pod and namespace names, e-mail addresses, URL hosts, and home paths become pseudonyms (`device-1`, `group-2`, `10.4.7.9`). No query names, no local zone contents, no free text; the log has warnings and errors only. |
| `standard` | As strict, plus the log's INFO lines, top lists with pseudonymized names, and (with `--query-sample N`, up to 1,000) a sample of recent queries with their names pseudonymized. |
| `none` | Real values. Secrets are still removed. Read it before you share it. |

In every level **secrets are removed**: passwords and hashes, API and session tokens, two-factor secrets, OIDC client secrets, private keys, the bootstrap secret, and credentials in URLs. A setting that holds a secret (an OIDC `client_secret`, an upstream's extra headers) is dropped, a `*_file` setting keeps its path and never the file's content, and a setting nobody classified is dropped and named in the manifest. `--reveal NAME` (repeat for several) keeps one name readable.

**Pseudonyms** are the same inside one package (`device-3` is one device in every file) and can't be turned back into the real value from the package. They keep what triage needs: two addresses on one /24 (or /64) stay on one, a private address stays private and a public one stays public, loopback, link-local and the well-known public resolvers (1.1.1.1, 8.8.8.8, 9.9.9.9, ...) stay as they are, and a MAC keeps its maker (its first three bytes) unless it is a randomized one. A public domain name keeps its last label (`site-4.com`); URL paths keep their words (`/dns-query`) and lose anything with a digit or a capital. `--keep-map FILE` writes the pseudonym map (`pseudonym<TAB>real value`) to a file only you hold; in the web UI **Let me download the key to the pseudonyms** keeps it in the node's memory for one download within ten minutes (never on disk). It has your real names: don't attach it.

**What's inside**
- `MANIFEST.json` lists every file, which part wrote it, whether it is whole (`ok`, `truncated`, or `missing`, with the reason), and how many values of each kind were replaced or removed (counts, never the values); `README.txt` says what the level means.
- A part that is slow or fails (each has five seconds; the whole run, 30) is marked `missing` and the rest is complete. The package is at most 20 MiB: over that, the largest files are cut first (the newest log lines are kept). It runs on a worker thread and never touches the query path.
- Free text (log lines, error messages) is redacted by pattern: the names and secrets your settings hold are replaced wherever they appear, then addresses, MACs, e-mail addresses, URLs, host names, home paths, PEM blocks and long token-looking strings are caught by shape. That is best effort, not a guarantee: look it over.

**The log.** No platform lets a process read its own stderr back (a systemd unit has no journal access, a container's log is outside it, the Helm chart's root file system is read-only), so TelltaleDNS keeps its own small log: the last 2,000 lines at INFO and above in memory from the first line it logs, whatever `TELLTALE_LOG` says, and two rotating files of about 1 MiB under `<data_dir>/logs/` (directory `0750`, files `0640`), so lines from before a restart reach the package. About 21 KB a day on a quiet node. The files are **not** redacted (they hold client addresses): the package redacts when it is made. `[support] persist_logs = false` keeps only the in-memory lines (read at start); a read-only data directory does the same on its own and the manifest says so. Writing the log never blocks DNS: a full queue drops the line and counts it.

**Who can, and the record.** Admins only. Each package is recorded in the audit log as `support.package` (the level and counts, never the content) and each map download as `support.package.map`. One package at a time per node (a second request gets 409).

## When a node stops answering (the watchdog)
Rarely, a process can hang with its service still `active`: DNS, the web UI, the metrics and the cluster port all go quiet and nothing exits, so nothing restarts it. A **watchdog** looks for that. A thread of its own, outside the runtime that serves everything, makes two checks every 5 seconds: the runtime can run a task, and this node's own first UDP listener answers a question (`probe.telltale.invalid`, the name the listener checks use; it is answered without asking an upstream and kept out of the query log and analytics). When a check hasn't passed for `stall_secs` (60 by default), the node is called stuck. The watchdog then writes a **dump** and, by default, ends the process with exit status 70 so its supervisor starts it again: systemd (`Restart=on-failure`, which the unit has), Docker or Podman Compose (`restart: unless-stopped`), or Kubernetes (a container restarts). A node started by hand in a terminal just exits. With `unless-stopped`, Docker doesn't start a container again once it has marked it as manually stopped, and a reload signaled through Docker sets that mark: see [Reload in Docker](#reload-in-docker).

```toml
[watchdog]                  # restart-only; each node has its own
enabled = true
stall_secs = 60             # 20 to 600
action = "restart"          # "dump": write the dump and keep running
max_restarts_per_hour = 6   # past it, no restart: the dump and the log say so; 0 never restarts
```

It watches only whether the node answers. A node that is slow, or busy for a few seconds, still passes; one that is stuck never does. A restart is limited to `max_restarts_per_hour` (counted from `<data_dir>/watchdog/restarts`), so a false alarm can't become an endless loop.

Know its limits. Past `max_restarts_per_hour` (6) restarts in an hour, a node that is still stuck stays stuck: it is not restarted again, and the watchdog says so. The dump's first line reads `TelltaleDNS watchdog dump: restart cap reached; not restarting`, the log gets one error line with the words `restart cap reached; not restarting` (again every hour while the node stays stuck, with no new dump) and one line when the node answers again by itself, and `telltale_watchdog_restart_cap_reached_total` counts these stalls since the process started (it starts again at 0 when the node restarts, so the log and the dump are the record, not the counter). A stuck runtime can't answer a scrape, so the counter shows after the node recovers, or while only its UDP listener is stuck; otherwise alert on the node's scrape failing, and read the log and the newest dump. A partial stall, where one worker of several is blocked and the others still run tasks, isn't seen, because the runtime check still passes. And recovery takes about a minute (`stall_secs` plus the restart), during which TCP, DoT, DoH, DoQ and every query the cache can't answer go unanswered. It is the backstop for a hang nobody has found yet. One cause is closed: a cluster read, such as a replica's read of its primary, can no longer wait on a stuck runtime for ever; it gives up at its deadline (ADR-174).

**The dump** is `<data_dir>/watchdog/hang-<UTC time>.txt` (directory `0750`, files `0640`, the newest five kept). It says which check failed and for how long, the build, the uptime, memory and load, every thread (its name, state, what the kernel has it waiting on, its CPU time), **each thread's stack as raw addresses**, the executable's mappings, and the last 200 lines of the log (see Support package). It holds no client data and no settings. A support package includes the newest dump. The log says at start when the previous run ended by the watchdog, and `telltale_watchdog_last_action_timestamp_seconds` holds the time.

**Reading the stacks.** The release binary is stripped, so the dump has addresses, not names. Every release and edge build publishes the matching debug file next to the binary, `telltale-<arch>-linux.debug.zst` (`x86_64`, `aarch64`, or `armv7`), covered by the signed `SHA256SUMS`. Take the one from the same release or edge build as `telltale --version` shows, then:

```sh
zstd -d telltale-x86_64-linux.debug.zst -o telltale.debug
addr2line -e telltale.debug -f -C -i 0x4a1b2c3 0x4a1b2d4      # function and file:line for each address
```
The addresses are the ones in the dump, as they are in a static (non-relocated) binary; if the mappings show the binary loaded at a base other than `00400000`, subtract that base first. The first frame of each thread is the call it is stuck in, and the next ones are who called it. A thread that shows "no answer" couldn't run the handler at all, which means it is stuck inside the kernel. Attach the dump (or the support package) to an issue.

**Metrics:** `telltale_watchdog_enabled`, `telltale_watchdog_check_age_seconds{check="runtime"|"listener"}` (seconds since each check last passed: near `stall_secs` means the node is about to be called stuck), `telltale_watchdog_last_action_timestamp_seconds`, and `telltale_watchdog_restart_cap_reached_total` (stalls that found the restart limit used up).

## Kubernetes (Helm)
The chart is published with every release as an OCI artifact (k8s 1.26+, amd64 and arm64).
Use a release version, or `0.1.0-edge.<n>` builds that follow `main`. Its source is in
`deploy/helm/telltale`, and `helm install telltale deploy/helm/telltale` from a checkout works too:
```sh
helm install telltale oci://ghcr.io/paimonsoror/charts/telltale --version <version> \
  -n telltale --create-namespace \
  --set service.dns.annotations."metallb\.universe\.tf/loadBalancerIPs"=192.168.1.53
kubectl -n telltale get svc telltale-dns          # EXTERNAL-IP: point clients (DHCP) here
```
**Every option** is in the chart's commented values file:
`helm show values oci://ghcr.io/paimonsoror/charts/telltale --version <version> > values.yaml`
(or [`deploy/helm/telltale/values.yaml`](../deploy/helm/telltale/values.yaml); the site's
[Helm values](https://paimonsoror.github.io/telltaledns/helm-values.html) page lists each key
with its default). Keep only what you change in your own file and install with `-f my-values.yaml`;
the chart's schema rejects a mistyped value with its path.
- **One LoadBalancer Service, UDP and TCP 53**, with `externalTrafficPolicy: Local` so the query log and per-device rules see real client addresses (verified in CI: a query through the LoadBalancer is logged with the sender's address). `Cluster` hides clients behind node addresses, and the install notes warn about it. Use your LB's annotation for a fixed IP: MetalLB `metallb.universe.tf/loadBalancerIPs`, Cilium `io.cilium/lb-ipam-ips`, kube-vip `kube-vip.io/loadbalancerIPs`.
- **`hostNetwork: true`** answers on port 53 of the node itself (no LoadBalancer, MAC addresses visible). Binding 53 there needs root with only `NET_BIND_SERVICE` kept; on Ubuntu nodes turn off systemd-resolved's stub listener first. k3s's CoreDNS doesn't conflict.
- **The UI and API**: `service.api.type: LoadBalancer`, or `ingress.enabled` with `ingress.host` (set `[api] trusted_proxies` in `config` to your ingress's network; with `disable_local_login`, read **Break-glass sign-in** under Users and sign-in first: where the ingress hides the client address, address checks can't be trusted).
- **Configuration**: `config:` is merged after the chart's own settings (listeners, data directory, ports): upstreams, lists, groups, `[auth.oidc]`, everything in `docs/configuration.md`.
- **Secrets**: `auth.bootstrapAdmin.existingSecret` creates the first admin (keys `username` and `password` or `password-hash`); `secretMounts` mounts Secrets at `/etc/telltale-secrets/<name>` (for example an OIDC `client_secret_file`).
- **Monitoring**: `serviceMonitor.enabled`, `prometheusRule.enabled` (down, all upstreams down, SERVFAIL rate, lists whose last good copy is over 48 hours old and whose latest refresh failed, lists that have never loaded, dropped telemetry, masked client IPs, device anomalies), and `grafanaDashboard.enabled` (a ConfigMap for the Grafana sidecar).
- **`networkPolicy.enabled`** limits who may query (`dnsFrom`), reach the UI (`apiFrom`), and scrape (`metricsFrom`).
- **Encrypted DNS**: `encrypted.dot.enabled` (853), `encrypted.doh.enabled` (443, plus `encrypted.doh.http3`), and `encrypted.doq.enabled` add DoT, DoH, and DoQ to the DNS Service; the certificate comes from `encrypted.tls.secretName` or a cert-manager `Certificate` (`encrypted.tls.certManager.issuerRef` and `dnsNames`; add a wildcard for client IDs) and is reloaded when renewed. `encrypted.proxyProtocol` accepts PROXY protocol v2 on TCP, DoT, and DoH.
- **One replica or many.** `mode: allInOne` (the default) is one StatefulSet with a volume for lists, the query log, and users. **`mode: scaled`** adds resolver pods:
  ```sh
  helm install telltale deploy/helm/telltale -n telltale --set mode=scaled --set resolvers.replicas=3
  ```
  - The StatefulSet becomes the cluster's **controller**: it creates the cluster on first start, keeps the volume, and serves the UI and API.
  - Each **resolver pod** joins it automatically with a Secret the chart generates (48 random characters; with `cluster.bootstrapSecret.existingSecret`, use at least 32, or the log warns). It takes the controller's configuration and compiled lists, and ships its query log to the controller's volume.
  - Resolver pods are trusted less than the controller: they never get the cluster's signing key, can't vote or be promoted, can't step the primary down, and can't change anything on other nodes (forward configuration changes, pause blocking, or flush caches). Make those changes on the controller.
  - A resolver pod reports ready only once it has the configuration, so it never answers unfiltered. Pods come and go: one that's gone for `resolvers.ephemeralTtlSeconds` (default 600) leaves the cluster's list of nodes. The Cluster page shows them grouped by site ("k8s: 3 resolver pods").
  - The DNS Service spreads queries over the controller and every resolver pod.
  - **A node outside Kubernetes** (a Pi) can join the same cluster:
    - expose the cluster port with `cluster.service.type: LoadBalancer`;
    - list that address in `cluster.advertise` (e.g. `["https://192.168.5.100:9443"]`);
    - create a token on the controller (`kubectl exec sts/telltale -- telltale cluster token create --url https://192.168.5.100:9443 -c /etc/telltale/00-chart.toml -c /etc/telltale/10-values.toml -c /etc/telltale/20-controller.toml`);
    - then run `telltale cluster join <token>` on the Pi.
  - **Staged rollouts** (off by default): `cluster.rollout.canaries: [ephemeral]` gives each change
    to the resolver pods (with the controller) first and to a node outside Kubernetes after a
    5-minute bake, pinning the cluster back if the pods start failing. See
    [Rolling a change out in stages](#rolling-a-change-out-in-stages).
  - With Argo CD (which can't keep a generated Secret stable), create the join Secret yourself and set `cluster.bootstrapSecret.existingSecret`. A changed secret applies without restarting the controller.
  - `daemonSet` (host-network resolvers on every node) comes later.
  - **Don't raise the replica count of a workload that shares one volume.** Every copy would
    share one node identity, `state.db`, and query log. Each TelltaleDNS process locks its data
    directory (`<data_dir>/telltale.lock`) for as long as it runs. A second process pointed at
    the same directory waits up to 10 s for it, then exits with an error naming the holder (pid,
    host or pod, and since when). The lock is released when the process exits, even after a
    crash. Use `mode: scaled` for more pods. With your own manifests, give a single-volume
    Deployment `strategy: Recreate`, or the new pod can't start until the old one stops.

### Scaling in Kubernetes
- **`allInOne` or `scaled`.** `allInOne` is one pod with one volume. It's simple, and it's
  enough for a home network: one pod answers tens of thousands of queries per second.
  `scaled` adds resolver pods for availability: a pod can restart or move while the others keep
  answering. The controller keeps the volume (users, the query log, lists) and the
  configuration. Resolver pods hold no state, so add or remove them freely
  (`resolvers.replicas`).
- **Don't raise `replicas` on a workload with one volume.** The pods would share one node
  identity, `state.db`, and query log. The data-directory lock stops the second pod (see
  above), so use `mode: scaled` instead.
- **Each pod has its own cache and rate limits.** A new pod starts with an empty cache, so its
  hit rate is low for its first minutes. The Cluster page shows each pod's hit rate. Per-client
  rate limits apply per pod, so a client spread over three pods can send up to three times the
  limit.
- **Spread the pods.** With `externalTrafficPolicy: Local` (needed to see real client
  addresses), each Kubernetes node sends queries only to its own pods. Use
  `resolvers.affinity` (for example podAntiAffinity on `app.kubernetes.io/component: resolver`)
  to put them on different nodes. The Cluster page's **Load balance** check flags a pod that
  takes more than twice its fair share of its site's queries.
- **What one Kubernetes node protects against:** a pod crash, an upgrade, or a pod being
  rescheduled. The other pods keep answering. It doesn't protect against the node itself going
  down. For that, run pods on several nodes, or add a node outside Kubernetes (a Pi) as a
  replica that clients use as their second DNS server.
- **On the Cluster page**, the topology shows each site with its nodes and its pods grouped by
  Kubernetes node. Each line's thickness is that node's share of the queries; amber means not
  ready or behind on configuration, and red means down. Select a pod to jump to its row (pod
  name, Kubernetes node, share of queries, cache, and restarts) and its machine. The events
  count pods joining, pods gone, and restarts in the last hour.
- **One IP for DNS, the UI, and the cluster port.** Don't give the `api` or cluster Service
  the DNS Service's IP (Cilium's `lb-ipam-sharing-key`, MetalLB's `allow-shared-ip`). With
  `externalTrafficPolicy: Local`, both only share an IP between Services that select the same
  pods. In `mode: scaled` the DNS Service also selects the resolver pods, so it loses the IP
  and DNS stops on that address. Instead set `service.dns.alsoServe.api: true` (and
  `.cluster: true` for a node outside Kubernetes). The DNS Service then carries those ports
  too, but only the controller listens on them. Keep `service.api` on `ClusterIP` (it still
  serves the ingress). The install notes warn when an `api` or cluster Service is a
  LoadBalancer in scaled mode.
  - **With pods on more than one node, take care.** With `externalTrafficPolicy: Local`, the
    load balancer announces the IP from a node that has a ready pod of that Service, and that
    node delivers only to its own pods. If it's a node that runs only a resolver pod, DNS on
    port 53 keeps working but the UI and cluster ports go nowhere, and which node announces can
    change after any restart. A node outside Kubernetes that joined through that address then
    can't reach the controller.
  - **Safe setups:** a single-node cluster; the controller on every node that can announce
    the address (`affinity`); a LoadBalancer Service with its own address for the port
    (`cluster.service.type: LoadBalancer` for the cluster port, with the nodes' `--url` pointing
    at it, and `service.api.type: LoadBalancer` or an ingress for the UI); or no resolver pods
    (`resolvers.replicas: 0`). The install notes warn when `alsoServe` is combined with
    `externalTrafficPolicy: Local` and resolver pods.
- **Pods that shut down leave the cluster.** On SIGTERM (scaled in, replaced by a rollout,
  or deleted) a resolver pod tells the controller it's leaving, and it's dropped from the
  Cluster page at once (event **Left**). A pod that dies without shutting down (a crash, an
  out-of-memory kill, a lost node) can't say so: it shows as down and expires after
  `resolvers.ephemeralTtlSeconds`, as before. Only resolver pods leave this way; the
  controller and nodes outside Kubernetes stay members across restarts.
- **Rollouts without lost lookups.** On shutdown a pod reports not ready, then keeps answering
  for `drainDelaySeconds` (default 5; passed as `TELLTALE_DRAIN_DELAY_SECS`, which is
  `[node] drain_delay_secs`) while the Service stops
  sending it queries, and only then stops. Outside Kubernetes the default is 0.
- **Metrics.** With `serviceMonitor.enabled`, Prometheus scrapes the controller and every
  resolver pod (a headless `<release>-resolver-metrics` Service), so query, SERVFAIL, and
  latency metrics cover all the traffic, and so do the alerts and SLO rules of
  `prometheusRule.enabled` (both jobs, `<release>-metrics` and `<release>-resolver-metrics`;
  before 0.5.0 they watched only the controller). With the kube-prometheus-stack
  chart, give the rules its `release` label so Prometheus loads them
  (`prometheusRule.labels: {release: <its release name>}`). On the controller, per member:
  `telltale_cluster_peer_info{kube_node, pod}`,
  `telltale_cluster_peer_queries_per_second`, `telltale_cluster_peer_cache_hit_ratio`, and
  `telltale_cluster_peer_restarts`, per member.

### Kubernetes workloads as devices
Your cluster's pods can be devices like any laptop or TV: named by the workload that runs
them, grouped, filtered, and watched. TelltaleDNS reads each pod's owner and calls the pod's
address by its **workload**: `media/deploy/jellyfin` for the Deployment `jellyfin` in the
namespace `media`, and likewise `sts`, `ds`, `job`, `cronjob` (every run of a CronJob is one
device), and `pod` for a bare pod. A Deployment's three replicas are one device, before and
after every rollout, so its top domains, anomaly baseline, rhythm, and timeline carry on when
its pods are replaced.

A new pod often asks DNS before Kubernetes reports its address. The query log still names those
first queries by the workload. The dashboard and the anomaly engine wait up to 2 seconds for an
address they don't know yet, so a CronJob's short runs count under the CronJob. While this is on,
those numbers run up to 2 seconds behind for devices outside the cluster. A restart of
TelltaleDNS keeps all of it: each node saves its workload counts hourly and at shutdown
(`workload-counts.json` in the data directory), and the restored top lists name workloads, not
the pods' addresses.

Turn it on in the chart's values:
```yaml
kubernetes:
  enabled: true
  clusterDns: 10.43.0.10     # kubectl -n kube-system get svc kube-dns -o jsonpath='{.spec.clusterIP}'
  podCidr: 10.42.0.0/16      # optional: PTR lookups for pod and Service addresses go to CoreDNS too
  serviceCidr: 10.43.0.0/16  #   (leave both out if the nodes' own DNS includes TelltaleDNS, below)
service:
  dns:
    clusterIP: 10.43.0.53    # a fixed address inside the Service network, for the kubelet setting
```
The controller (or the `allInOne` pod) then gets a service-account token and a ClusterRole that
can only `get`, `list`, and `watch` pods and namespaces. Resolver pods get no token. The
controller sends the workload table to every node in the cluster (a Pi included, so it names
the rows it ships), and the nodes ask for it again every minute. The chart also sends
`cluster.local` (and the reverse zones of `podCidr` and `serviceCidr`) on to CoreDNS, so
Service names keep working. That route is `node_only` (CLU-006): a Pi in the same cluster
doesn't get it, since it can't reach CoreDNS, and answers `cluster.local` like any other name.
Set Kubernetes options through these values, not as a `[kubernetes]` table in `config`: the
chart writes that table.

**Pods must ask TelltaleDNS directly.** If they ask CoreDNS and CoreDNS forwards to
TelltaleDNS, every query comes from CoreDNS's address. Two ways to do it:
1. **The whole cluster (recommended).** Point the kubelet's cluster DNS at TelltaleDNS's DNS
   Service first and CoreDNS second. On k3s, in `/etc/rancher/k3s/config.yaml` on every
   node, then restart k3s:
   ```yaml
   kubelet-arg:
     - "cluster-dns=10.43.0.53,10.43.0.10"   # service.dns.clusterIP, then CoreDNS
   ```
   Use `kubelet-arg`, not k3s's own `cluster-dns` option, which also moves CoreDNS's
   Service (k3s keeps its own value in the kubelet's configuration file, and the flag wins).
   Restarting k3s leaves running pods running; new pods use the setting, so restart workloads
   (`kubectl -n media rollout restart deploy`) to move the ones that are running. On kubeadm
   clusters, set `clusterDNS` in the kubelet's configuration. TelltaleDNS keeps answering
   the cluster's names through CoreDNS, so Services resolve as before. CoreDNS second keeps
   lookups working if the DNS Service has no ready pods; images based on Alpine (musl) ask
   both servers at once, so some of their lookups arrive through CoreDNS and count under it.
   To start new clusters this way, have the install script write the file before installing
   k3s (`sudo install -D -m 0600 k3s-config.yaml /etc/rancher/k3s/config.yaml`).
   TelltaleDNS's own pods keep asking CoreDNS (`kubernetes.ownPodsUseClusterDns`, on by
   default), so they never depend on their own Service.
2. **One workload at a time** (a good first step before the whole cluster). Give its pods
   their own DNS settings:
   ```yaml
   spec:
     dnsPolicy: "None"
     dnsConfig:
       nameservers: ["10.43.0.53"]
       searches: ["media.svc.cluster.local", "svc.cluster.local", "cluster.local"]
       options: [{ name: ndots, value: "5" }]
   ```
**The nodes' own DNS.** CoreDNS sends everything outside the cluster to the node's DNS
servers (its `forward . /etc/resolv.conf`), so give each node two, for example a Pi and
TelltaleDNS's LoadBalancer address. On Ubuntu with NetworkManager, add the second to the
netplan file's `nameservers.addresses`, apply it without taking the link down (`sudo netplan
generate && sudo nmcli connection reload && sudo nmcli device reapply <interface>`), then
`kubectl -n kube-system rollout restart deploy/coredns`. Once the nodes' DNS includes
TelltaleDNS, leave `kubernetes.podCidr` and `serviceCidr` out: CoreDNS passes reverse names it
doesn't know (`fallthrough in-addr.arpa`) to the node's servers, so an unknown pod address's
PTR would loop between TelltaleDNS and CoreDNS.

Traffic from a pod to a Service address keeps the pod's own address (kube-proxy and Cilium don't
rewrite it), so "Client IPs appear masked" isn't affected. With `ndots: 5` you'll see
questions like `grafana.com.media.svc.cluster.local`. They go to CoreDNS and come back
NXDOMAIN: that's how Kubernetes searches, and the traffic map shows it as it is.

**Groups.** A workload's group is the first of:
1. the label `telltaledns.io/group=<group>` on its pods;
2. the same label on its namespace (`kubectl label namespace media telltaledns.io/group=media`);
3. the first matching rule of `kubernetes.map` (`[{namespace: "media*", group: "iot"}]`, with
   optional `kind` and `name`), or one made in the UI;
4. `kubernetes.defaultGroup`;
5. otherwise its network's group, or `default`, like any device you haven't named.

A label naming a group that doesn't exist is logged once and ignored. Labels take effect within
seconds, on every node, with no configuration change. Everything a group does then applies to
the namespace: lists, quick rules, blocked services, schedules, upstreams. A `$client` rule
names a workload by its name (`||ads.example^$client=media/deploy/jellyfin`).

**In the UI**, the Clients page gets a **Workloads** tab: each workload with its kind,
namespace, group and where it came from, its pods, its queries and blocks in the last 24 hours,
and when it last asked. Click one for its day on the timeline. Everywhere a device shows, a
workload has a small cube and its name, with the pod and address on hover. "Name this device…"
is off for workloads, because Kubernetes names them. "Add to group…" previews and then saves a
rule for exactly that workload. A label is the Git way to do the same. Explain says which
workload and pod asked and where the group came from. The query log keeps each pod's own
address. Each row is named by the workload that held that address when the query was made, so
an address reused after a rollout doesn't relabel the past. Filter it by workload with
`?client=media/deploy/jellyfin`.

**API and agents.** `GET /api/v1/kubernetes/workloads` lists the workloads (filter by
`namespace` or `group`), and `GET /api/v1/kubernetes/status` says whether this node watches or
takes the table from the cluster. `PUT /api/v1/kubernetes/map/{namespace}/{kind}/{name}` with
`{"group": "iot"}` writes a rule (`*` for any kind or name). The MCP tools are `list_workloads`
and `get_workload`. `plan_assign_client` with a workload's name plans a rule. A workload's name
works as `client` in the query log, the timeline, rhythm, identity, and explain.

**When the API server can't be reached**, DNS answers as always. Pods keep the names they had,
and new pods are plain addresses until the watch is back. After 15 minutes the health level
turns **degraded** (`kubernetes_stale`), and the `TelltaleDNSKubernetesWatchStale` alert
fires. Metrics: `telltale_kubernetes_pods`, `telltale_kubernetes_workloads`,
`telltale_kubernetes_table_age_seconds`, `telltale_kubernetes_watch_errors_total`,
`telltale_kubernetes_sync_total{result}`, and `telltale_kubernetes_watching`.

Limits: one Kubernetes API per cluster; pods on the host network are the node's address and
stay that; a deleted pod's address stays its own for 30 seconds (queries still in flight), then
the history keeps who held it for 30 days; at most 20,000 pod addresses (the metric
`telltale_kubernetes_addresses_dropped` says when more are left out). TelltaleDNS doesn't answer
`cluster.local` itself: CoreDNS does.

## Seeing real client IPs
Per-device statistics, groups, and rules need each query's real sender. TelltaleDNS checks this continuously: when more than 90% of the last 10 minutes' queries (at least 100) came from 3 or fewer *infrastructure* addresses, the UI shows a "Client IPs appear masked" banner, `GET /api/v1/system/info` includes `clientIpsMasked` with the evidence, the metric `telltale_client_ips_masked` is 1, and the log says so once.

Infrastructure addresses are loopback, this host's default gateways (a Docker bridge or a Kubernetes pod's gateway; on the LAN, a router), the node addresses the Helm chart passes in `TELLTALE_NODE_IPS`, and any networks in `[clients] infrastructure`:
```toml
[clients]
infrastructure = ["10.42.0.0/16"]   # e.g. your cluster's pod network
```
Common causes and fixes:
- **Kubernetes, `externalTrafficPolicy: Cluster`**: the node rewrites the sender. Use `Local` (the chart's default) or `hostNetwork: true`.
- **Docker with a userland proxy** (IPv6 or `127.0.0.1` port publishing): run with `network_mode: host`, or publish on the LAN address.
- **A router that forwards DNS** (its own resolver points at TelltaleDNS and clients use the router): hand out TelltaleDNS's address in DHCP instead. If you can't, enable the router's EDNS MAC option (dnsmasq `add-mac`) and list the router in `[clients] trust_edns_mac_from` so devices are recognized by MAC.

## Upstream presets
Instead of looking up addresses, start from a preset:
```sh
telltale presets list                                   # Cloudflare, Google, Quad9, AdGuard, Mullvad, Control D, NextDNS, ...
telltale presets show quad9 --proto tls,https --group default >> telltale.toml
telltale presets show nextdns --param profile=abc123    # templated presets need your account ID
```
`show` prints explicit `[[upstream]]` entries plus a `fastest` group. Your config always lists exactly what's used and never depends on the catalog, which only helps you write it. The catalog covers every Pi-hole preset plus the common encrypted resolvers; a nightly job checks that every entry still answers. That includes the DoQ (`quic://`) endpoints.

## Encrypted DNS for your devices (DoT, DoH, and DoQ)
Phones, laptops, and browsers can reach TelltaleDNS over DNS over TLS (Android's "Private DNS", RFC 7858), DNS over HTTPS (browsers, iOS and macOS profiles, RFC 8484), or DNS over QUIC (RFC 9250; AdGuard and other apps, some routers), so nobody on the network path can read or change their lookups:
```toml
[[listen]]
proto = "dot"
addr = "0.0.0.0:853"
tls = { cert = "/etc/telltale/tls.crt", key = "/etc/telltale/tls.key" }

[[listen]]
proto = "doh"
addr = "0.0.0.0:443"
path = "/dns-query"                     # default; /dns-query/<client-id> also works
tls = { cert = "/etc/telltale/tls.crt", key = "/etc/telltale/tls.key" }

[[listen]]
proto = "doq"
addr = "0.0.0.0:853"                    # UDP 853 (DoT uses TCP 853: both fit)
tls = { cert = "/etc/telltale/tls.crt", key = "/etc/telltale/tls.key" }

[[listen]]
proto = "doh3"                          # DoH over HTTP/3: UDP 443 next to the TCP one
addr = "0.0.0.0:443"
tls = { cert = "/etc/telltale/tls.crt", key = "/etc/telltale/tls.key" }
```
- **Certificate:** a PEM chain (leaf first) and key, valid for the name devices use, e.g. `dns.example.com` from Let's Encrypt (DNS-01 works for internal names). Both files are re-read within 10 seconds of changing, so renewals (certbot, cert-manager) need no restart; a broken renewal keeps the old certificate and logs a warning.
- **DoH** speaks HTTP/2 and HTTP/1.1, `GET ?dns=` and `POST application/dns-message`, and answers with `Cache-Control: max-age` set to the answer's smallest TTL. DoT uses ALPN `dot` with RFC 7766 pipelining, like plain TCP. With a `doh3` listener, DoH also speaks HTTP/3 (ALPN `h3`, the same paths and client IDs), and HTTP/2 answers carry `Alt-Svc: h3=":443"` so browsers and apps that support it switch. DoQ uses ALPN `doq`: each query has its own QUIC stream, so a slow answer never holds up the others, and an idle connection closes after 30 s. 0-RTT is off (an early query could be replayed).
- **Devices identify themselves:** with a wildcard certificate (`dns.example.com` and `*.dns.example.com`), a device configured with `kids-tablet.dns.example.com` (Android Private DNS, DoT, DoH, or DoQ) or the URL `https://dns.example.com/dns-query/kids-tablet` gets the client ID `kids-tablet`, which `[[client]] match = ["id:kids-tablet"]` recognizes wherever the device is, even on mobile data. The path wins over the name.
- **Behind a load balancer:** `proxy_protocol = true` on a `tcp`, `dot`, or `doh` listener makes it read the client's address from a PROXY protocol v2 header (HAProxy, Traefik, AWS NLB, ...). Every connection must then start with one, so only enable it when the balancer sends it, and don't let clients reach the listener directly. `LOCAL` connections (the balancer's health checks) keep the socket address, and so do headers whose address family is `AF_UNSPEC` or `AF_UNIX` (no client address). Those connections are counted in `telltale_proxy_protocol_no_address_total{kind="local"|"unspec"|"unix"}`. When the socket address is loopback (a proxy on the same host), the log also says so, at most once a minute per listener (at info for `AF_UNSPEC` and `AF_UNIX`; for `LOCAL`, the health checks, at debug). Such a connection keeps the socket address, and the settings for that address apply. A `doh` listener with `trusted_proxies` refuses such headers instead (below).
- **Behind a reverse proxy** (Caddy, nginx, Traefik, HAProxy) in front of a `doh` listener: list the proxies in `trusted_proxies`, and the listener takes each client's address from them, from the PROXY header or from `X-Forwarded-For`. See [Behind a reverse proxy](#behind-a-reverse-proxy).
- **Slow and silent clients:** on `tcp` and `dot` listeners a connection that sends nothing for the idle timeout (10 s) is closed, and so is one whose client stops reading answers, so a stalled client can't hold one of the 1,024 connection slots. A query longer than 4,096 bytes (the UDP receive buffer's size; real queries are a few dozen bytes) closes the connection. Closures are counted in `telltale_tcp_idle_closed_total` and `telltale_tcp_stalled_closed_total`.
- **Connection limits, per listener** (`tcp`, `dot`, `doh`, `doh3`, `doq`): `max_connections` (default 1,024) is how many connections it holds open at once, and `max_connections_per_address` (default 32, `0` = no limit) is how many one client address may hold, so a single host can't take every slot. An IPv6 client counts per /64, and with `proxy_protocol = true` the client's address is the one in the PROXY header. Connections over a limit are refused (counted in `telltale_tcp_rejected_per_address_total`, `telltale_doh_rejected_per_address_total`, `telltale_doq_rejected_per_address_total`, next to the `*_rejected_total` counters for the overall limit). **Behind a load balancer that hides client addresses** (no PROXY protocol, source NAT, or Kubernetes `externalTrafficPolicy: Cluster`), every client looks like the balancer, so raise `max_connections_per_address` or set it to `0`. Changing a limit restarts that listener (open connections finish first).
  ```toml
  [[listen]]
  proto = "dot"
  addr = "0.0.0.0:853"
  tls = { cert = "/etc/telltale/tls.crt", key = "/etc/telltale/tls.key" }
  max_connections = 2048
  max_connections_per_address = 64
  ```
- Metrics: queries are counted per transport (`telltale_queries_total{proto="dot"|"doh"|"doq"}`), plus `telltale_doq_connections_total`, `telltale_doq_rejected_total` and `telltale_doh_rejected_total` (connections refused at the 1,024 cap, which `doq` and `doh3` enforce like `tcp`, `dot`, and `doh`), `telltale_doq_protocol_errors_total`, `telltale_doh_requests_total`, `telltale_doh_bad_requests_total`, `telltale_tls_handshake_failures_total`, `telltale_proxy_protocol_rejected_total`, `telltale_proxy_protocol_no_address_total{kind}`, and `telltale_doh_forwarded_refused_total` (behind a reverse proxy, below).
- In Kubernetes, enable `encrypted.dot` / `encrypted.doh` (plus `encrypted.doh.http3`) / `encrypted.doq` in the chart with a certificate from an existing Secret or cert-manager (`encrypted.tls.certManager`); the ports join the DNS LoadBalancer, so client addresses survive (`externalTrafficPolicy: Local`).

### Behind a reverse proxy
A reverse proxy in front of a `doh` listener (to share port 443 with other sites, to handle certificates, or to rewrite the path) makes every query look like it comes from the proxy: one client for the access list, the rate limit, groups and device statistics. List the proxies on the listener, and it takes each client's address from them (ADR-194, GitHub issue #91). The listener keeps its TLS: the proxy re-encrypts to it, on this host or across your network.

**A proxy that sends `X-Forwarded-For`** (nginx, Caddy, Traefik, HAProxy, on this host or on other machines):
```toml
[[listen]]
proto = "doh"
addr = "0.0.0.0:443"
tls = { cert = "/etc/telltale/tls.crt", key = "/etc/telltale/tls.key" }
x_forwarded_for = true
trusted_proxies = ["10.0.5.20/32", "10.0.5.21/32"]   # the proxies' own addresses
max_connections_per_address = 0                       # every connection is a proxy's
```
The client is the rightmost `X-Forwarded-For` entry that isn't one of the listed proxies, as for the web UI's `[api] trusted_proxies`; proxies in front of proxies work when each is listed. `X-Real-IP` and `Forwarded` are not read. The proxy must append the address it sees, not pass on what the client sent: in nginx, `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`, never `$http_x_forwarded_for`.

**A proxy or balancer that sends a PROXY protocol v2 header** (TLS passed through, or re-encrypted as Caddy's `reverse_proxy https://127.0.0.1:8443` with `transport http { proxy_protocol v2 }` does): keep `proxy_protocol = true` and add `trusted_proxies`, so that only that proxy connects:
```toml
[[listen]]
proto = "doh"
addr = "127.0.0.1:8443"
tls = { cert = "/etc/telltale/tls.crt", key = "/etc/telltale/tls.key" }
proxy_protocol = true
trusted_proxies = ["127.0.0.1/32"]
```
A proxy that sends PROXY headers on pooled connections must keep a connection per client (Caddy does), since the header names the connection's client. `X-Forwarded-For` names each request, so pooling and HTTP/2 are fine there.

What changes once `trusted_proxies` (or `x_forwarded_for`) is set:
- **Only the listed proxies connect.** A connection from any other address is closed at once, before anything is read.
- **Nothing is answered without a client's address.** A PROXY header that is `LOCAL` or carries no address, an `X-Forwarded-For` that is missing or unreadable where the client should be (a port, brackets or a word such as `unknown` in that entry, only listed proxies, more than 16 entries), and an unspecified or loopback client (`0.0.0.0`, `::`, `127.0.0.0/8`, `::1`) are refused: the connection is closed, or the request gets `403` (on HTTP/1.1 its connection is closed; an HTTP/2 connection, which carries the proxy's other clients, stays). So a device on the proxy's own host can't use DoH through the proxy (it can use the local listeners), and a health check that sends `LOCAL` or asks the DoH path fails: point the proxy's health check at a TCP connect, or at the web UI's `/livez`.
- **The real client is the client everywhere:** `[access] allowed_networks`, the rate limit, groups and devices, the query log, analytics and dnstap. Clients outside your allowed networks are refused (EDE 18), where before they shared the proxy's address.
- **List only your proxies, never a whole network:** each listed address can name any client, so it chooses whose policy and rate budget a request uses. `config check` refuses a prefix of 0 (`0.0.0.0/0`) and warns about a network wider than one address, about an address a loopback listener can never see, and about `max_connections_per_address` left at 32 with `x_forwarded_for` (every connection is a proxy's; raise it or set 0).
- **Behind `x_forwarded_for`** the listener sends no `Alt-Svc` (clients reach the proxy, not this node), takes client IDs from the URL path only (the name in the TLS handshake is the proxy's), and isn't probed: add the proxy's public URL to `[probe] targets` instead, which tests the whole path. `https://dns.example.com/dns-query/kids-tablet` still identifies the device through a proxy that keeps the path.
- **Refusals** are counted in `telltale_doh_forwarded_refused_total{reason="unlisted_peer"|"no_client_address"}` and logged at most once a minute per listener and reason (the line names the kind of PROXY header refused), without the header's contents. A refused PROXY header is not counted in `telltale_proxy_protocol_no_address_total`, which counts only the connections that keep the socket address.
- **In a cluster,** listener settings stay on each node and are never shared: set `trusted_proxies` on every node's `[[listen]]`. An older version refuses a configuration file that has these keys (at start it doesn't run; on a reload it keeps the running configuration), so remove them before going back to one, including through the cluster's upgrades.
- **In Kubernetes,** passing TLS through with PROXY protocol v2 stays the recommended way. An HTTP ingress that re-encrypts needs the ingress controller's addresses in `trusted_proxies`; they change with its pods, so list them only with a NetworkPolicy that lets nothing but the ingress reach the listener.

A listener without these keys behaves exactly as before. Plain HTTP for a proxy on the same host (no second TLS hop, or a Unix socket) is not available yet.

## Recursive resolution (no forwarder)
TelltaleDNS can resolve names itself, from the root servers down, like `unbound` next to a Pi-hole, so no public resolver sees your lookups:
```toml
[[upstream]]
name = "recursive"
url = "recursive://"

[[upstream_group]]
name = "default"
members = ["recursive"]

# Optional (these are the defaults):
# [upstream.recursive]
# qname_minimization = true    # each server sees only as much of the name as it needs (RFC 9156)
# case_randomization = false   # 0x20: random letter case, checked in answers (spoofing defense)
# ipv6 = false                 # also ask servers over IPv6 (needs an IPv6 route)
# stub_zone / stub_servers     # start one zone at its own servers: see Stub zones
```
- **Private by default:** with QNAME minimization the root servers see only `com`, the `com` servers only `example.com`, and only `example.com`'s own servers see `www.example.com`. If a server mishandles the shortened question, the full one is sent (relaxed mode).
- **Safe:** a random port and ID per query; records are only accepted from servers responsible for them, and server addresses ("glue") only from the zone that delegates to them. With `case_randomization` (off by default), each query asks for a random mix of upper and lower case, and only an answer that echoes it exactly is accepted: it adds about one bit of entropy per letter to the 32 bits of ID and port an off-path spoofer must guess, so it is worth turning on for a recursive resolver. An answer with the case changed is ignored like any other stray packet while the real one is awaited; only a server that never echoes the case is remembered (after one timeout) and asked without it.
- **Fast after the first time:** zone cuts and server addresses are remembered (bounded, by their TTLs), answers go to the normal cache, and servers are picked by measured response time. A first lookup in a new zone takes a few round trips (about 30 to 400 ms); after that, one.
- **Hedged:** when a server is slower than usual (1.5 times its usual response time, at least 150 ms), the next server is asked too, and the first good answer wins, so one sluggish server doesn't hold up a lookup.
- **Root priming** (RFC 8109): on first use, the built-in root server addresses are only used to ask for the root's current list, which is then remembered for a day. A root server that changes address doesn't need a new TelltaleDNS.
- **DNSSEC:** with `[dnssec] mode = "validate"` the signatures come along and are checked from the root's trust anchor, as for forwarded answers.
- It's an upstream like any other: mix it into a group with forwarders (for example `strategy = "failover"` with a public resolver as the fallback), or route only some domains through it.
- Limits that stop loops and broken zones: 16 CNAME hops, 32 referrals, 96 queries per question; servers get at most 1.2 s each.
- Non-existent names that validated NSEC records already cover are answered without asking (RFC 8198; see DNSSEC below).
- Moving from Pi-hole with unbound, or from Technitium without forwarders: the importers note it (Technitium's import uses `recursive://` directly).

## Encrypted upstreams
```toml
[[upstream]]
name = "cloudflare-dot"
url = "tls://1.1.1.1"                       # DNS over TLS, port 853
tls_server_name = "cloudflare-dns.com"      # name on the certificate

[[upstream]]
name = "quad9-doh"
url = "https://dns.quad9.net/dns-query"     # DNS over HTTPS (HTTP/2)
bootstrap = ["9.9.9.9", "149.112.112.112"]  # how to look up dns.quad9.net itself

[[upstream]]
name = "google-h3"
url = "h3://8.8.8.8/dns-query"              # DoH over HTTP/3 (or https:// with http_version = "3")
tls_server_name = "dns.google"

[[upstream]]
name = "adguard-doq"
url = "quic://94.140.14.14"                 # DNS over QUIC, port 853
tls_server_name = "dns.adguard-dns.com"
```
- Certificates are verified against the built-in Mozilla root set, so no CA files are needed, even in a minimal container. `tls_insecure_skip_verify = true` turns verification off (a warning is logged; don't use it on untrusted networks).
- **Hostname upstreams** are looked up through `bootstrap` servers, or the system resolvers from `/etc/resolv.conf` when `bootstrap` is empty (never through TelltaleDNS itself), and the result is cached for its TTL. To skip the lookup, put the IP in the URL and set `tls_server_name`.
- Connections are kept open and reused: many queries share one DoT connection (`pool_size`, default 4; closed after `idle_timeout_ms`, default 30 s), and DoH multiplexes every query over a single HTTP/2 connection. A new connection finishes its handshake even when the query that started it runs out of time, so the next query finds it ready. A connection that stops answering altogether (queries waiting 3 s with nothing coming back, as when something along the way drops it silently) is closed, and its queries retry at once on a new one. The `telltale_upstream_connections_*` metrics show how often connections open, why they close, and whether TLS sessions resume. DoQ keeps one QUIC connection per upstream with a stream per query, reconnects when it closes, and never uses 0-RTT; DoH over HTTP/3 does the same with a request per query.
- `http_version = "3"` on an `https://` upstream uses HTTP/3 only; `"auto"` (the default) and `"2"` use HTTP/2.
- `doh_method = "get"` sends DoH queries as `GET /dns-query?dns=…` (RFC 8484 §4.1) instead of POST, for providers or HTTP caches that prefer it. The query ID is 0 either way, so identical questions make identical URLs.

### DNSCrypt and DNS stamps
Use a DNSCrypt server (as dnscrypt-proxy does next to a Pi-hole), or any server from a DNS stamp list (the public list at dnscrypt.info), by pasting its `sdns://` stamp as the URL:
```toml
[[upstream]]
name = "adguard-dnscrypt"
url = "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20"
```
- **DNSCrypt stamps** become a DNSCrypt v2 upstream: the server's certificate is fetched and checked against the provider key in the stamp, then every query is encrypted (X25519 with XChaCha20-Poly1305 or XSalsa20-Poly1305, whichever the certificate offers) and padded, over UDP with TCP for large answers. Certificates are refreshed hourly and when they expire.
- **DoH, DoT, and DoQ stamps** become the matching `https://`, `tls://`, or `quic://` upstream, with the stamp's host name as the TLS name and its address (if any) pinned, so no bootstrap lookup is needed.
- **Certificate hashes in stamps are enforced:** when a DoH, DoT, or DoQ stamp lists hashes, some certificate in the chain the server presents (usually an intermediate CA) must match one of them, on top of the normal certificate check (and even with `tls_insecure_skip_verify`). If a provider changes CAs before its published stamp is updated, the upstream fails with "no certificate in the server's chain matches the stamp's hashes": take the newer stamp, or use the plain `https://` / `tls://` URL, which checks the certificate the usual way.
- Tested against AdGuard, OpenDNS, CleanBrowsing, Comodo, and cryptostorm's DNSCrypt servers. *Not supported:* DNSCrypt over IPv6-only paths without an IPv6 route.

**Anonymized DNSCrypt.** Add a relay, and the queries go through it: the relay sees your address but can't read the queries, and the resolver reads the queries but sees only the relay's address. Pick a relay run by someone other than the resolver (the public relay list at dnscrypt.info has stamps):
```toml
[[upstream]]
name = "adguard-anon"
url = "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20"
relay = "sdns://gQ8yMDMuMC4xMTMuNzo0NDM"     # a relay stamp (this one is 203.0.113.7:443), or "ip:port"
```
- Everything goes through the relay, the certificate fetch included, over UDP and over TCP for large answers.
- `relay` is only valid on a DNSCrypt (`sdns://`) upstream.

### Client subnet (ECS)
Some CDNs pick a server near the client by the subnet a resolver sends along (EDNS Client Subnet, RFC 7871). TelltaleDNS never sends your devices' subnets. When a far-away public resolver gets you slow CDN answers, you can send a subnet of your choice instead, for example your ISP's public block:
```toml
[[upstream]]
name = "quad9-ecs"
url = "tls://9.9.9.11"            # Quad9's ECS-enabled service
tls_server_name = "dns11.quad9.net"
ecs = "203.0.113.0/24"            # sent with every query (default: "strip", nothing sent)
```
- The same subnet goes with every query, so cached answers stay valid for everyone and no device's address leaves your network.
- ECS options from your devices are never forwarded, and an upstream's ECS reply never reaches them.

When TelltaleDNS serves clients on public addresses (a hosted resolver, or a VPS for a family spread over several ISPs), `ecs = "client"` sends each client's own subnet instead:
```toml
[[upstream]]
name = "quad9-ecs"
url = "tls://9.9.9.11"
tls_server_name = "dns11.quad9.net"
ecs = "client"                    # each client's /24 (IPv4) or /56 (IPv6)
```
- Only the subnet goes out: the address cut to /24 or /56, the privacy defaults RFC 7871 recommends.
- Clients on private, loopback, link-local, CGNAT (100.64.0.0/10), or ULA (fc00::/7) addresses send nothing, since their subnet would tell a CDN nothing. On a home network that's every device, so `"client"` only matters for public clients.
- Answers from an upstream group with a `"client"` member are cached per subnet, so one subnet's answer never reaches another. They're also left out of the cache file kept across restarts.
- The subnet comes from the client's address (after PROXY protocol, if enabled). ECS options your clients send are still never forwarded.

### Forwarding loops
Every query TelltaleDNS forwards to an upstream carries an EDNS option (code 65429, from the range RFC 6891 keeps for local use) with a random tag the node picks when it starts. A query that arrives with the node's own tag has come back through an upstream that forwards to TelltaleDNS: it's dropped and an error is logged (`forwarding loop detected`), so it doesn't go round until it times out. If the log reports one, fix the upstream that sends queries back. The tag doesn't catch two TelltaleDNS nodes that forward to each other (directly, or through forwarders in between): a node never passes a client's EDNS options on, so a query that one node forwards reaches the other and comes back carrying only the other node's tag, and neither node recognizes it as its own; don't make two nodes each other's upstream.

A few resolvers drop every query that carries an EDNS option they don't know (RFC 6891 asks them to ignore it), so every query to them times out (over DoH, fails with an HTTP error) and their breaker stays open, while `dig` from the same host gets answers. Leave the option out for such an upstream:
```toml
[[upstream]]
name = "strict-resolver"
url = "udp://198.51.100.53"
loop_tag = false                  # default: true
```
- Its queries and health checks go without the option, and so do the lookups of its host name through its own `bootstrap` servers. The system resolvers that look up host names for upstreams without `bootstrap` are shared, and keep it: if they drop it too, give the upstream its own `bootstrap`.
- **`loop_tag = false` doesn't fix a loop, it hides one**: a query that comes back is no longer dropped, and goes round. Keep the option on for any upstream that can reach this node: a router or another resolver that forwards to TelltaleDNS, or this node's own address. Don't turn it off to quiet `forwarding loop detected`.
- The configuration refuses `loop_tag = false` toward this node, as far as it can tell, when a URL or a `bootstrap` server is:
  - a loopback address (127.0.0.0/8, `::1`, or one mapped into IPv6);
  - an unspecified address (`0.0.0.0`, `::`);
  - the name `localhost`, or a name under it;
  - or an address a `[[listen]]` entry uses, **on any port**, so a forwarder on another port of this host (say `127.0.0.1:5353`) is refused too.

  It's also refused on a `recursive://` upstream, which never sends the option.
- It still accepts, because it doesn't check them:
  - a DNS stamp (`sdns://`) whose address is this node;
  - this node's `[api]`, `[metrics]` and `[cluster]` addresses;
  - the machine's other addresses (a node listening on `0.0.0.0` doesn't name its LAN address, and nothing reads them from the host);
  - another name for this node;
  - a resolver that forwards back.

  **Test it** (`POST /api/v1/checks/upstream`) asks a draft without these checks, so it can say "Works" for an upstream that saving refuses. In a cluster each node checks against its own listeners: see [Setting `loop_tag` in a cluster](#setting-loop_tag-in-a-cluster).
- A domain forwarded in the UI or the API keeps the option. To forward a domain to such a resolver, define an `[[upstream]]` with `loop_tag = false`, an `[[upstream_group]]` for it, and a `[[route]]` with its `match_suffix`.

#### Setting `loop_tag` in a cluster
- **Upgrade every node before you set `loop_tag` on a shared upstream.** A node on an earlier version can't read a shared configuration that has the key (only `false` is written there). It refuses that version and keeps serving the configuration it has. It refuses every later version too while the key is in it, so it stops following the cluster's changes until it's upgraded or the key is removed. An earlier build also refuses the key in its own file, so don't write it, `true` or `false`, in a file such a build reads. An upstream that doesn't set the key is shared exactly as before.
- **Each node checks the shared upstreams against its own listeners.** The primary accepts `loop_tag = false` on an upstream at a replica's `[[listen]]` address. That replica refuses the version in the same way, and every later one while the upstream stays.
- **A node that refuses a version** logs `cluster configuration not applied`, shows the error in its sync status, and adds a `sync_failed` event to the cluster's timeline. After setting the key, check on [the Cluster page](#clusters) that every node is on the new version.

### Through a proxy (Tor)
Send an upstream's traffic through a SOCKS5 or HTTP proxy, for example Tor, so the resolver never sees your address:
```toml
[[upstream]]
name = "quad9-tor"
url = "tls://dns.quad9.net"                 # the proxy resolves the name: no bootstrap, no leak
proxy = "socks5://127.0.0.1:9050"           # or "http://127.0.0.1:3128", with optional user:pass@
```
- Works with `tcp://`, `tls://`, and `https://` upstreams, and with `udp://` through a SOCKS5 proxy that supports UDP ASSOCIATE (RFC 1928 §7, e.g. Dante). A truncated UDP answer is asked again over TCP through the same proxy. A few associations are kept open and reused.
- Tor and HTTP proxies don't carry UDP: use `tcp://` (or `tls://`) with them.
- A hostname in the URL is passed to the proxy as a name, so the lookup happens at the proxy's end (with Tor, at the exit).
- Credentials in the proxy URL (`socks5://user:pass@host:port`) never appear in logs.

### Pinning and client certificates
```toml
[[upstream]]
name = "office-dot"
url = "tls://10.0.0.53"
tls_server_name = "dns.office.example"
tls_ca = "/etc/telltale/office-ca.pem"      # trust this CA for this upstream only
tls_client_cert = "/etc/telltale/client.pem" # servers that require a client certificate (mTLS)
tls_client_key = "/etc/telltale/client.key"
spki_pins = ["kXbB2F3...base64...="]        # the server's key must be one of these
```
- **Pins** are the base64 SHA-256 of the server certificate's public key (SPKI), checked after the usual verification. With `tls_insecure_skip_verify = true` only the pin is checked, which suits a self-signed server you pin. List two pins (current and next key) to rotate keys without an outage. To get a server's pin:
  ```sh
  openssl s_client -connect 10.0.0.53:853 -servername dns.office.example </dev/null 2>/dev/null \
    | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der \
    | openssl dgst -sha256 -binary | base64
  ```
- The files are read when the configuration loads (and on every reload); a missing or unreadable file is a configuration error.

### Plugin upstreams
Anything that can answer DNS can be an upstream, in any language, without linking into TelltaleDNS: a plugin speaks plain DNS messages over a stream (a 2-byte length, then the message, as DNS over TCP does) on a Unix socket.
```toml
[[upstream]]
name = "magicdns-bridge"
url = "unix:///run/magicdns.sock"           # a socket another service listens on

[[upstream]]
name = "consul"
url = "exec:///usr/local/bin/consul-dns-plugin"
args = ["--datacenter", "home"]
```
- With `exec://`, TelltaleDNS starts the program and tells it where to listen in `TELLTALE_PLUGIN_SOCKET` (under `<data_dir>/plugins/`; `TELLTALE_UPSTREAM` has the upstream's name). If it exits, it's restarted after 1 s, then 2, 4, ... up to 60 s (back to 1 s once it has run for a minute). Its output goes to TelltaleDNS's log. It's stopped when the configuration changes or TelltaleDNS stops.
- A plugin can't hurt the resolver: it's another process, every exchange has the upstream's timeout, and a dead plugin is a failing upstream like any other (health, breaker, the group's other members).
- **The health check asks a plugin the root's NS records (`. NS`)** about once a minute while no query uses it, so a plugin passes it only by answering that question with NOERROR (no records needed) or NXDOMAIN: a REFUSED or SERVFAIL counts as a failure, and on a node that sends it few queries the plugin then stays benched for longer (a plain server that refuses `. NS`, such as an authoritative-only one, belongs in a [stub zone](#stub-zones-the-zones-own-servers) instead, `"stub": true` through the API).
- **Plugin upstreams are defined in the config file** (`telltale.toml`, the Helm values, or Git), since they name a program the node starts or a socket it connects to. The UI and the API refuse an upstream with `exec://`, `unix://` or `args`, and a forwarded domain with such a server, for every role, an administrator included (422, saying which field), and **Test it** (`POST /api/v1/checks/upstream`) refuses such a draft before anything is started (ADR-180).
- **After upgrading,** a plugin upstream made earlier in the UI or the API isn't used: nothing is started for it, and an upstream of the same name in the config files is the one in effect. A forwarded domain made there keeps its other servers, under the same names (`forward:<domain>#<n>` counts a server's place among the domain's servers); with none left it isn't used, and its names go to the `default` upstream group (or a route that matches them). What named such an upstream is adjusted, so everything else made in the UI or the API stays in effect: an upstream group made there loses it as a member (left with none, the group isn't used, and the config files' group of that name, if any, is back; a `parallel` group races the members it has left, or with one uses `failover`), and a client group made there that sent its queries to a group that isn't used now goes to the config files' choice or the default. The node logs one warning for each of these, naming it, and a new change that names one of them (an upstream group's member, a client group's upstream group) is refused (422). The entries stay until you remove them (`DELETE /api/v1/upstreams/{name}` or `/api/v1/forwards/{domain}`); define the plugin in the config file instead. In a cluster, **upgrade the primary first**: a replica can't tell an entry an older primary made through the API from one in that primary's config files. On a primary that was promoted from a replica, such an entry can come with the configuration it was promoted with; `DELETE` answers 404 there, and you replace the upstream with a plain one of the same name instead (`PUT /api/v1/upstreams/{name}` with, say, a `udp://` URL).

## How a query is answered
```mermaid
flowchart LR
  Q[query] --> P{parse}
  P -- malformed --> E[FORMERR / NOTIMP / BADVERS]
  P --> C{cache}
  C -- fresh hit --> A[answer, TTLs counted down]
  C -- miss / expired --> U[upstream group]
  U -- answer --> S[cache + answer]
  U -- slow or failing, have stale data --> ST[stale answer + EDE 3]
  U -- all failed --> SF[SERVFAIL + EDE 22]
```
- **Cache:** answers are cached for their TTL (clamped by `[cache] min_ttl`/`max_ttl`). Negative answers are cached when the upstream includes an SOA. SERVFAIL is cached for 5 seconds, and never served stale afterwards: an expired failure is asked again. Hot entries are refreshed in the background just before they expire.
- **Upstreams:** if an upstream is slow, the next one is tried *in parallel* rather than after a timeout, and the first good answer wins. The last healthy upstream left to try (the only one, in a group of one) may wait for its answer for the rest of the query's 2 s (not just `timeout_ms`, 400 ms by default), so a name the upstream has to look up itself (often several hundred milliseconds) isn't cut short and answered SERVFAIL. With `strategy = "parallel"`, each healthy upstream asked at once may wait the same way, so the faster one's answer isn't thrown away. The price: one of them that stops answering is benched only after about 2 s (three timeouts) instead of almost at once, and until then a client whose other upstream answered SERVFAIL waits for it, up to the same 2 s (then up to its `timeout_ms`). An upstream that never answers costs each query up to those 2 s until three timeouts in a row bench it (in a group of one: the first three queries when they come one after another; every query started in the 2 s before those timeouts land waits the full 2 s), and then up to its `timeout_ms` for each query for as long as it still doesn't answer. Attempts still running when the client gets its answer finish in the background, each within its own timeout, so that their failures are counted: how many are in flight depends on the cache-miss rate and the 2 s budget. An upstream that fails 3 times in a row (or more than half the time) is benched for 10 seconds, doubling up to 5 minutes, then probed again (by the next query, or on a node without queries by the next health check). A SERVFAIL or REFUSED answer counts toward "more than half the time" but not toward "3 in a row", so a client retrying one broken domain can't bench a healthy upstream. A name an upstream takes longer than the 2 s to answer does count as a timeout, though: three of those in a row, with no other answer from it in between, bench even a healthy upstream for 10 seconds, and while it's benched, names it takes longer than its `timeout_ms` to look up get SERVFAIL until it's probed successfully. (Before 0.8.0 every attempt was cut at the shortest of `timeout_ms`, 3 × the upstream's usual time + 50 ms, and 1 s, often about 70 ms, so slower names counted the same way.) Identical concurrent questions share one upstream request.
- **When a shared request gets no answer,** every question waiting on it gets what a failure gets (a stale answer where one may be served, otherwise SERVFAIL). If one of them still has at least 100 ms left (its 2 s plus the 100 ms a client waits beyond it, counted from when it arrived), the request is tried once more within that time, and a question that arrives meanwhile gets that try's outcome. A request is never tried a third time.
- **Serve-stale:** if upstreams don't answer within 1.8 s (`[cache] stale_answer_client_timeout_ms`) and an expired answer is still in the cache (up to a day old by default), it's served with TTL 30 and Extended DNS Error 3 ("Stale Answer"), while the refresh continues in the background.
- **Answering recently expired names at once:** devices keep answers themselves, so most repeat questions reach the resolver just after the answer expired, and a plain cache misses them. With `stale_answer_client_timeout_ms = 0` an expired answer is given at once (TTL 30, EDE 3) while it's refreshed in the background, the way Pi-hole's cache optimizer works by default. `stale_max_age` bounds how old it may be (an hour matches Pi-hole), and `min_ttl` keeps short-lived answers a little longer (Technitium's default is 10 s):
  ```toml
  [cache]
  min_ttl = 10
  stale_answer_client_timeout_ms = 0   # answer an expired name at once, refresh it in the background
  stale_max_age = 3600
  ```
  These answers have the status `refreshed`, so `stale` keeps meaning "upstreams failed or were slow" (or the resolver was too busy to start the refresh). They cost about as much as a fresh cache hit. The trade-off is that a name whose address changed within the hour is answered once with the old address (for 30 s) while the new one is fetched. `[cache]` is per node: set it on every node of a cluster.
- **What the dashboard counts:** the **Cache hits** tile is every answer given from the cache: fresh, `refreshed`, or `stale`, out of the answers that weren't blocked or local. In the Advanced view its second line splits it ("41% fresh · 22% refreshed") and the status chart shows `refreshed` on its own. The Cache page's "Answered from the cache" is the same number per node, with the fresh share beside it. Prometheus counts a refreshed or stale answer as a cache miss plus one `telltale_cache_stale_served_total`; the Grafana dashboard's **Answered from cache** panel shows both lines.
- **Privacy:** queries to upstreams carry a fresh random ID and source port, and none of the client's EDNS options (no client subnet, cookies, or MAC addresses are forwarded).
- **Loop protection:** outbound queries carry a random per-process tag. If one comes back to us (an upstream that forwards to TelltaleDNS), it's dropped and an error is logged instead of looping forever. An upstream that drops queries carrying it can go without it: see [Forwarding loops](#forwarding-loops).

## Local records
Names on your network, answered by TelltaleDNS itself (authoritatively, before cache and upstreams):
```toml
[[record]]
name = "nas.home.arpa"
type = "A"                      # A, AAAA, CNAME, PTR, TXT, MX, SRV
value = "192.168.1.10"

[[record]]
name = "*.dev.home.arpa"        # wildcard: every name below dev.home.arpa
type = "A"
value = "192.168.1.20"

[[record]]
name = "_sip._udp.home.arpa"
type = "SRV"
value = "0 5 5060 pbx.home.arpa" # priority weight port target (MX: "preference exchange")

[local]
hosts_files = ["/etc/telltale/hosts"]   # "IP name [alias...]" lines
auto_ptr = true                          # reverse lookups for every A/AAAA (default)
default_ttl = 300
```
- A name with no record of the requested type gets an empty authoritative answer (NODATA). Names that aren't local go to the upstreams as usual.
- CNAMEs are followed within local data; if the target is elsewhere, the client follows it.
- Hosts files skip `0.0.0.0`, `::`, and loopback entries (those are blocklists or this machine, not network hosts).
- `telltale config check` validates record values and reads the hosts files.
- **In the web UI:** **Names on my network** lists every local name grouped by domain. Operators can add, edit, and remove names (A, AAAA, and CNAME in Simple; every type in Advanced), run **Set up my home domain** (home.arpa by default) for a first device, and **Send a domain to another server** (conditional forwarding). Each change is previewed in a sentence and a diagram before it's saved, and every name has a **Test** link to Explain. Names from the config files are shown read-only. Through the API: `GET /api/v1/records`, `PUT`/`DELETE /api/v1/records/{name}` with `{"records": [{"type": "A", "value": "192.168.1.10"}]}`, and `GET /api/v1/forwards`, `PUT`/`DELETE /api/v1/forwards/{domain}` with `{"servers": ["10.0.0.53"]}` (add `"stub": true` for a [stub zone](#stub-zones-the-zones-own-servers)); all take `?dryRun=true`, `If-Match`, and `Idempotency-Key` like devices.
- **Moving from another DNS server:** `telltale import zone exported.zone > records.toml` converts a zone file (Technitium's Zones → Export Zone, BIND, PowerDNS) into `[[record]]` entries for your config. The header lists anything with no local equivalent (SOA and NS aren't needed: TelltaleDNS answers these names itself). Names under the zone that you don't import still resolve normally, so a split-horizon domain keeps working: internal names answer locally, everything else publicly.

### Local zones
A zone makes TelltaleDNS the authority for a whole domain: names in it are answered from it, and names it doesn't have get NXDOMAIN (instead of going to the upstreams, as names not in `[[record]]` do).
```toml
[[zone]]
name = "lab.example.com"
file = "/etc/telltale/lab.example.com.zone"   # an RFC 1035 zone file (BIND, Technitium, PowerDNS)

[[zone]]
name = "corp.example.com"
groups = ["office"]                 # split horizon: only these groups see this zone
negative_ttl = 300
[[zone.record]]
name = "intranet.corp.example.com"
type = "A"
value = "10.10.0.5"
```
- Answers are authoritative (AA). The zone's apex and names that only have names below them exist (no data, not NXDOMAIN). Negative answers carry the zone's SOA, owned by its apex, with `negative_ttl`.
- **SOA and NS at the apex** (`dig SOA home.example`, `dig NS home.example`) answer with the zone file's own records. Without a file, or a file without them, they're made up as resolvers serving local zones do: `localhost.` as the name server, `hostmaster.<zone>` as the contact, and `negative_ttl` as the SOA minimum.
- **Split horizon:** with `groups`, only those groups' devices see the zone; everyone else resolves the domain normally (the public answer). Several zones for the same domain can serve different groups.
- The most specific zone wins (`a.corp.example.com` over `corp.example.com`). Zones are answered before filtering, like local records.
- Zone files use the record types local records support (A, AAAA, CNAME, PTR, TXT, MX, SRV), plus the apex's SOA and NS. Changes need a reload (`SIGHUP`).

## Filter lists
> **Status:** lists are downloaded, compiled, and **enforced** per client group, including names reached through a CNAME.

```toml
[[list]]
name = "hagezi-pro"                     # ID: lowercase letters, digits, - and _
url = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt"

[[list]]
name = "family-allow"
kind = "allow"                          # block (default) or allow
match = "exact"                         # subtree (default: the name and everything below it) or exact
path = "/etc/telltale/allow.txt"        # a local file, re-read on every refresh

[[list]]
name = "manual"
rules = ["||ads.example.com^", "@@||cdn.example.com^"]

[filter]
refresh_secs = 86400                    # every 24 h (per-list `refresh_secs` overrides; minimum 900)
fetch_concurrency = 4
fetch_timeout_secs = 120                # per attempt, including the download
fetch_retries = 3                       # network errors, HTTP 5xx, and 429 are retried with backoff
max_list_bytes = "64MiB"                # per-list `max_bytes` overrides
max_invalid_percent = 50                # refuse a download if more than this % of its rule lines are invalid
max_shrink_percent = 50                 # hold a download that lost more than this % of the list's lines (100 = off)
compile_threads = 0                     # 0 = auto (first compile: half the cores, 1-4; recompiles: 1)
compile_memory = "128MiB"               # sort budget before spilling to disk
fsync = true                            # sync a compiled snapshot to disk before publishing it
max_regexes = 1000                      # regex rules kept per snapshot (0 = no limit); the rest are reported
allow_link_local_urls = false           # true: allow list URLs on 169.254.0.0/16 or fe80::/10
```
- **Link-local and cloud-metadata addresses are refused** (169.254.0.0/16, fe80::/10, AWS's fd00:ec2::254), whatever name or redirect leads there, so a list URL can't read what a cloud instance serves there. Private LAN addresses are fine. When an agent's pre-save check can't reach a list or an upstream, it's told only that it was unreachable; the UI and the audit log show why.
- **Downloads are polite:** after the first download, a refresh sends `If-None-Match`/`If-Modified-Since`, so an unchanged list costs one small request. Redirects are followed, except from `https` to `http`.
- **A failed refresh never loses a list.** The last good copy stays in use. A failing list is retried after 5 minutes, then 10, 20, and so on up to hourly, instead of waiting a whole day. Inline rules that are refused (blank, or mostly not rules) have nothing to download again, so they're tried once and shown as failing until you change something: edit the rules, switch the list off and reload and then on and reload (the node has to see it off), restart, or send `SIGUSR1` (see below). An inline list that can't be stored (a full or read-only disk) isn't held: it's retried on the same 5-minute-to-hourly ladder. Responses that can't be a list are rejected: an empty body, an HTML page from a captive portal, a compressed body (`Content-Encoding` other than `identity`), or text that is mostly not rules (a JSON error from a CDN, a mirror that changed format). "Mostly" is `[filter] max_invalid_percent` (default 50: more invalid lines than rules); cosmetic and unsupported rules don't count as invalid, and `100` turns the check off.
- **A list that suddenly shrinks waits for a second look.** When a URL list's new download has lost more than `[filter] max_shrink_percent` of the stored copy's lines (default 50: a list of 2 million names arriving with fewer than 1 million), it isn't used yet: a truncated mirror or a source caught mid-rewrite would otherwise drop half your blocking. The previous copy keeps answering, the Lists page says why, and the next scheduled refresh accepts the smaller list if the source serves the same content again. `SIGUSR1` (see below) accepts it at once. Lists under 1,000 lines, local files, and inline rules are never held; `100` turns the check off.
- Lists are stored compressed in `<data_dir>/lists/` (`<name>.src.zst` plus `<name>.meta.json`). Removing a list from the config deletes its files; `enabled = false` keeps them.
- **A list read from a local file (`path`) is an administrator's to set** when it's made in the UI or the API: a write that points a list at a file it didn't read before needs an admin's sign-in or an admin API token (no agent token, whoever owns it); others get 403. The operator role still covers URL lists, inline rules, a file list's other settings (on, off, kind, mode) while it reads the same file, and deleting any list. Lists in the config files are unaffected, and their files can be anywhere. When a local file can't be used, the Lists page and `GET /api/v1/lists` show an administrator the whole message and everyone else a generic one, and the health reason and the `list_failing` alert name the list without the message; the node's log always has it (ADR-180).
- List hostnames are looked up through the system resolvers (minus TelltaleDNS's own listeners). If the system resolver *is* TelltaleDNS, the lookup goes through it, which is safe because DNS is answering before downloads start.
- Downloads run in the background. DNS starts and answers without waiting for them, and a failing download never affects answers.
- Adding, removing, or editing lists applies on reload (`SIGHUP`). `[filter]` changes need a restart.
- To refresh every list now instead of waiting for `refresh_secs` (like `pihole -g`), send `SIGUSR1` (`kill -USR1 <pid>`, in Docker the same way as a [reload](#reload-in-docker), with `-USR1`). Unchanged lists cost one conditional request each, and the filter is recompiled only if something changed.

Fetch now, outside the server (same config and data directory):
```sh
telltale lists fetch -c telltale.toml
# list                     result            bytes      lines  note
# hagezi-pro               updated         5049934     227434
# manual                   unchanged            39          2
```
### List syntax
Every common format works, and formats can be mixed in one list:

| Line | Meaning |
|---|---|
| `0.0.0.0 ads.example.com` (any IP, several names allowed) | hosts file: block `ads.example.com` (`localhost` and similar lines are skipped) |
| `ads.example.com` | the name and everything below it (or only the name, with `match = "exact"`) |
| `*.example.com` or `.example.com` | everything below `example.com`, but not `example.com` itself |
| `\|\|ads.example.com^` | AdBlock: the name and everything below it |
| `\|ads.example.com^` | AdBlock: only the name |
| `@@\|\|cdn.example.com^` | exception: allow, even in a blocklist |
| `\|\|ads.example.com^$important` | wins over ordinary allow rules |
| `\|\|example.com^$dnstype=AAAA\|~A` | only for these query types (`~` excludes) |
| `\|\|example.com^$client=192.168.1.0/24\|'Kids tablet'` | only for these clients (`~` excludes) |
| `\|\|example.com^$denyallow=mail.example.com` | block `example.com` except these names below it |
| `\|\|ads.example.com^$badfilter` | cancels the same rule without `$badfilter` |
| `\|\|nas.example^$dnsrewrite=192.168.1.20` | answer with this address instead (also an IPv6 address, a name for a CNAME, `NXDOMAIN`/`REFUSED`, or the full `NOERROR;A;…`, `NOERROR;AAAA;…`, `NOERROR;CNAME;…`, `NXDOMAIN;;` forms) |
| `@@\|\|nas.example^$dnsrewrite` | turns rewrites off for these names |
| `/^ad[0-9]+\./` | AdBlock regex |
| `(^\|\.)doubleclick\.net$` | Pi-hole regex; add `;querytype=A,AAAA` (or `=!A` to exclude) or `;invert` |
| `# ...`, `! ...`, `[Adblock Plus 2.0]` | comments |

**Rewrites in lists** (`$dnsrewrite`, AdGuard's syntax): a matching rewrite wins over blocking, and `$client`, `$dnstype`, and `$denyallow` narrow it as for other rules. Several address rewrites for one name answer together. A name rewritten only to IPv4 answers an IPv6 question with an empty NOERROR (and the other way round). A CNAME rewrite is resolved like any name. The query log shows the list. Rewrites of other record types (MX, TXT, HTTPS, …) are counted as unsupported. Rewrites in the configuration (`[[group.rewrite]]`) are per group, and come after list blocking.

Names are lowercased, internationalized names are converted to punycode, and a trailing dot is ignored. Regexes match the lowercase query name and can't use backreferences or lookaround: the regex engine runs in linear time, so a pattern can't stall a query.

Rules that only make sense in a browser are counted as *unsupported* and skipped, not treated as errors: cosmetic rules (`##`), URL paths (`||example.com/ads.js`), wildcards inside names (`ads*.example.com`), IP rules (`||192.0.2.1^`, which filter answers rather than names), and modifiers such as `$third-party` or `$ctag`. A rule with a modifier TelltaleDNS doesn't support is skipped entirely. Applying it without the modifier would block more than the list author intended.

See what a list contains and which lines were skipped:
```sh
telltale lists check -c telltale.toml
# adguard-dns: 179561 lines, 177414 rules, 1658 comments, 0 ignored, 489 unsupported, 0 invalid
#   L79 unsupported: IP address rule (response IP filtering): ||194.63.143.96^
telltale lists check -c telltale.toml --list manual --rules   # every rule in canonical form
```
It exits non-zero if any list has invalid lines.

### Compiling
Whenever a list's content changes, a list is added or removed, or a list's `kind`/`match` changes, TelltaleDNS compiles every enabled list into a new **filter snapshot** in `<data_dir>/snapshots/<version>/`. The three newest snapshots are kept. A restart with unchanged lists reuses the newest snapshot instead of compiling again, and a failed compile keeps the previous one.

- Compiling runs in the background at the lowest CPU priority (`SCHED_IDLE` on Linux), and never pauses or locks query handling. The new snapshot replaces the old one atomically: queries in flight finish with the old one, and the old one is freed on a background thread.
- **A list change answers before the snapshot is written.** Once the lists are parsed and merged, the new rules start answering ("filter active (new rules from the merge; writing the snapshot)" in the log), and the snapshot's files are written after that; the finished snapshot then takes over with the same lookup index. If writing it fails (a full disk), the previous rules answer again, so a node never serves rules it has no snapshot of. Cluster replicas get the finished snapshot, as before.
- Thread count, `[filter] compile_threads`: the default, `0`, uses half the cores (between 1 and 4, so 2 on a Pi 4) when nothing is filtering yet, so blocking starts quickly on a first start. Once a filter is serving, a recompile (list refresh, reload) uses **one** thread: it takes longer, but nobody waits for it, and more threads compete with queries for cores and memory bandwidth even at the lowest priority. Set a number to use it for every compile.
- **Regex rules are capped.** `[filter] max_regexes` (default 1,000) is the most regex rules a snapshot keeps; the ones past it, in list order, are left out, counted per list on the Lists page ("N regex rules left out"), and named in the log (the first 20) and by `telltale lists compile`. Every query that no exact or suffix rule settles is tried against all the regexes, about a microsecond per thousand (200 cost 0.4 µs at the median, 1,000 cost 1.1 µs). The matcher's automaton does not scale past a few thousand patterns that share a prefix: in a synthetic test, 1,500 cost 1.6 µs per query and 41 MiB, but 2,000 grew past 5 GiB of memory within two minutes. Raise the limit only after measuring your own lists (`matcher_bench`), and prefer plain domain rules where a list offers both.
- **Power cuts.** A snapshot's files and its directory are synced to disk (`fsync`) before it counts as published, so a power cut can't leave a snapshot whose files are short; on an SD card that adds a few hundred milliseconds to a large compile, off the query path. `[filter] fsync = false` skips it. If the newest snapshot can't be opened at a start anyway (a snapshot made with `fsync = false` before a crash, say), it is renamed `<version>.broken`, the next newest is used, and the `.broken` directory is deleted after the next successful compile. Without an older snapshot, the resolver starts unfiltered until lists compile.
- Memory stays bounded. List entries are sorted within `[filter] compile_memory` (default `"128MiB"`), and anything beyond that spills to temporary files in the snapshot directory. Each list's text is read only while it's being parsed.
- **Sizing memory limits.** Steady state, the filter costs about 20 bytes per blocked name on top of a ~17 MiB base: 30–35 MiB with HaGeZi Pro + OISD big + StevenBlack (430k names), about 70 MiB with 2.7M names. Compiling needs much more for a few seconds: about 110 MiB peak for those three lists, and about 300 MiB for 2.7M names. If you set a container memory limit, leave room for that peak (at least 256 MiB for list sets over ~1M names), or the process can be killed mid-compile. Limiting compile memory automatically is planned (ADR-025).
- Size and speed: about 9 bytes per blocked name. On a Raspberry Pi 4, a recompile of 2 million names on one thread (the default) answers with the new rules after about 4.7 s and finishes writing the snapshot at about 12.8 s. A laptop-class machine makes 2.7M names answer in about 2 s on one thread.

```sh
telltale lists compile -c telltale.toml     # compile now and show per-list numbers
# snapshot 1 in /var/lib/telltale/snapshots/1
#   names 2597518 (subtree 2597518, exact 0, subdomains 0), regexes 0, modifier rules 0, list sets 7, $badfilter removed 0
#   8.98 bytes/name; 4.56s total (parse 2.03s, merge 2.49s, tables 9.10ms) on 1 thread(s); 0 sort runs spilled
#   hagezi-tif               entries   2376001  unique   2213895  unsupported      0  invalid      0
#   hagezi-pro               entries    227420  unique    102069  unsupported      0  invalid      0
#   oisd-big                 entries    244348  unique     55809  unsupported      0  invalid      0
```
`unique` counts the names no other list has. A list with few unique names adds little beyond your other lists.

The **Lists** page and `GET /api/v1/lists` show the same per list: `unique`, `hits` (queries it decided since each node started; in a cluster, every node's added up), and `overlap` (the lists it shares names with, and how many). A list that's 95% or more inside another is marked, and one with no hits is marked "none yet".

### Blocking
A query is checked against the filter after local records and before the cache, so a blocked name never reaches an upstream:
```
$ dig @192.168.1.53 ads.example.com
;; ->>HEADER<<- opcode: QUERY, status: NOERROR
; EDE: 15 (Blocked): (blocked by list hagezi-pro)
ads.example.com.   60   IN   A   0.0.0.0
```
How blocked names are answered is set per group (the client's highest-priority group decides):

```toml
[[group]]
name = "kids"
block_mode = "null_ip"      # default: A → 0.0.0.0, AAAA → ::, other types → no records
                            # or "nxdomain", "nodata", "refused", "custom_ip"
block_ips = ["192.168.1.2", "fd00::2"]   # for "custom_ip", e.g. a "blocked" page
block_ttl = 60              # how long clients may cache the block
ede = "filtered"            # "blocked" (EDE 15, default) or "filtered" (EDE 17: parental controls)
ede_text = true             # name the list in the EDE text (set false to hide list names)
```
`null_ip` is the default, as in Pi-hole and Technitium. Apps treat it as "unreachable" and give up quickly, while NXDOMAIN makes some apps retry or fall back to another resolver.

**CNAME inspection:** if an answer leads through a CNAME to a blocked name (`www.microsoft.com` → `…edgekey.net` → `….akamaiedge.net`), the answer is replaced with the client's block answer, with EDE text `CNAME target blocked by list …`. This also applies to answers served from the cache, which is shared by every group, so one group's policy never leaks into another's.

**Pause:** blocking can be paused for everyone or for one group, for a set time, and resumes on its own. Pause and resume through the API or `telltale ctl pause --minutes 10` (`ctl resume`); the metric `telltale_filter_paused_until_seconds{group}` shows active pauses.
When rules disagree, the most important one wins:

| Wins | Rule | Example |
|---|---|---|
| 1 | important allow | `@@\|\|cdn.example.com^$important` |
| 2 | important block | `\|\|ads.example.com^$important` |
| 3 | allow (allowlists, `@@` rules) | `@@\|\|cdn.example.com^`, or a `kind = "allow"` list |
| 4 | block | everything else |

Among rules of the same kind, the one reported is an exact-name rule first, then the longest matching domain, then a regex, then the list listed first in the config.

Lookups take well under a microsecond: about 0.3 µs typically and under 1 µs at p99 on an x86 server with 2.6M blocked names. They use an in-memory index built from the snapshot (about 10 bytes per name, on top of the snapshot's 9). A new snapshot is served the moment it's loaded, and the index is swapped in about a second later, without pausing queries. Memory with HaGeZi Pro + TIF + OISD big + StevenBlack + AdGuard (2.7M names): about 85 MiB in total; HaGeZi Pro alone (227k names): about 10 MiB.

Metrics: `telltale_queries_total{status="blocked"}` (including CNAME blocks), `telltale_filter_paused_until_seconds{group}`, `telltale_filter_lookup_index_bytes` (0 while the index is being built), `telltale_filter_snapshot_version`, `telltale_filter_rules`, `telltale_filter_compile_seconds`, `telltale_list_entries{list}`, `telltale_list_source_bytes`, `telltale_list_last_success_timestamp_seconds`, `telltale_list_last_change_timestamp_seconds`, and `telltale_list_fetch_consecutive_failures`, each labeled `{list}`. Inline lists (`rules = [...]`) are never fetched, so they have no `telltale_list_last_success_timestamp_seconds`. A list that is **disabled** (`enabled = false`) isn't exported at all: its fetch state is kept, so enabling it again brings the values back, but nothing alerts for a list nobody is fetching. The Helm chart has two alerts for a list that fails to refresh. `TelltaleDNSListStale` is for a list whose last good copy is over two days old and whose latest refresh failed:
```
(time() - telltale_list_last_success_timestamp_seconds > 172800)
  and on(instance, list) (telltale_list_fetch_consecutive_failures > 0)
```
Age alone isn't enough: a list with `refresh_secs` over two days is legitimately older than that between refreshes. `TelltaleDNSListNeverLoaded` is for a list that has never succeeded, which has a failure count but no last-success time:
```
(telltale_list_fetch_consecutive_failures > 0)
  unless on(instance, list) telltale_list_last_success_timestamp_seconds
```

What these alerts cover, so you know when to rely on them:
- `TelltaleDNSListStale` fires (after 30 minutes, with the chart's `for: 30m`) when the last success is over 48 hours ago **and** the latest refresh failed. It isn't a literal "failing for 48 hours": with the default `refresh_secs` (one day) it fires about a day after the first failed refresh, and for a list refreshed less often than every two days, shortly after its first failed refresh. The last good copy keeps blocking meanwhile.
- `TelltaleDNSListNeverLoaded` fires after an hour of failures (`for: 1h`) for a list that has never succeeded on that node: a new list with a mistyped URL, or a list whose data directory was empty (a pod restarted without a persistent volume) and whose source can't be reached. The failure count starts only once the first refresh, with its download attempts, has failed, so a node still on its first fetch doesn't count. After that a failing URL or file list is retried 5, 10, 20, and 40 minutes after its previous refresh started, then hourly. With fast failures the refreshes start about 0, 5, 15, 35, and 75 minutes after the first one (refreshes that time out stretch the gaps), so an hour of failures is four failed refreshes in a row. A network that is back in time for the refresh at about 35 minutes never alerts; one that returns later can start the alert at the hour, and it clears by itself when the next refresh (about 75 minutes after the first) succeeds. An inline list whose rules can't be loaded is reported the same way (it never exports a last success either); the retry times above are not promised for it.
- A list that succeeded once, however long ago, has a last-success time: it belongs to `TelltaleDNSListStale` and never to `TelltaleDNSListNeverLoaded`, so the two don't fire for the same list.
- A list **held** by `max_shrink_percent` isn't a failed refresh (its failure count stays 0), so neither alert covers it. The in-app alert rule `list_failing` reports it, and a list that has never loaded too, without the hour's wait.
- A list that was failing when you disabled it stops alerting at once, since its metrics are no longer exported. If you enable it again and it still fails, the alerts start again.
- They are unrelated to the in-app `list_stale` (content unchanged for 30 days, see [Lists that stopped changing](#lists-that-stopped-changing)): that one is about a source that keeps answering with the same content.

### Lists that stopped changing
A list whose maintainer gave up can keep answering HTTP 200 with the same content forever: it downloads fine, so nothing fails, but it stops keeping up. A URL list whose content hasn't changed in 30 days is called **stale**:
- the **Lists** page says *unchanged for N days*, the health icon shows `list_stale` (degraded), and the alert rule `list_stale` can tell you;
- `GET /api/v1/lists` has `staleDays` for it.

Change the limit for every list, or for one that rarely changes on purpose (0 = never stale):
```toml
[filter]
stale_after_days = 30

[[list]]
name = "my-small-list"
url = "https://example.com/rarely-changes.txt"
stale_after_days = 0
```
Files and inline rules change when you change them, so they're never stale. The days count from the last time the content changed (identical downloads don't count), which is also `telltale_list_last_change_timestamp_seconds`.

### Trying a list first (shadow mode)
Not sure a list is safe for your network? Add it in **shadow mode**: it's downloaded and checked like any other, but never blocks.
```toml
[[list]]
name = "hagezi-ultimate"
url = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/ultimate.txt"
mode = "shadow"          # enforce (the default) or shadow
```
- **What you see:** the **Lists** page marks it *shadow*, and **Would have blocked** shows, per shadow list, how many queries it would have blocked, from how many devices, the names most often, and the last one. When those are names you want gone, change `mode` to `enforce` (or edit the list on the Lists page). `GET /api/v1/analytics/shadow-lists`, the MCP tool `shadow_lists`, and `telltale_list_shadow_hits_total{list}` have the same.
- **How:** shadow lists sit in the compiled snapshot but in no group's enforcing set. For each query answered normally, the telemetry thread asks the filter again with the device's group's lists plus its shadow lists; a block by a shadow list is counted. It respects groups (a shadow list only counts for groups that would use it), allow lists, and `$client`-style rules. It never runs on the query path; with no list in shadow mode it does nothing. A very busy server may skip some (dropped events are counted), never slow down. Counts start at each restart. In **explain**, a shadow list's rules say *shadow*.
- **Likely over-blocking** (on the same page, `GET /api/v1/analytics/overblocking`, the MCP tool `overblocking_suspects`): blocked names that someone seems to want. *Allowed soon after* counts devices that got the name answered within 10 minutes of a block (you paused blocking, or allowed it); *retry bursts* count devices asking for it 10 or more times within a minute while it was blocked (apps that break retry; ad libraries do too, so it's the weaker sign). With the lists that blocked them: candidates for an allowlist, or a sign a list is too aggressive.
- Names follow the query log's privacy level (hashed at 1 and above); devices aren't counted at 2 and above.
- Like every list, a shadow list is checked once the snapshot is compiled (a few seconds after start or a change): queries answered before that aren't counted. `telltale explain` marks its rules with `~`.

## Groups and devices
Decide which lists apply to which devices:
```toml
[[group]]
name = "kids"
lists = ["hagezi-pro", "family-extra"]   # omit `lists` to use every list
priority = 10                            # highest-priority group's settings win

[[group]]
name = "default"                         # optional: what unknown devices get
lists = ["hagezi-pro"]                   # (without it, unknown devices get every list)

[[client]]
name = "Kids tablet"
match = ["aa:bb:cc:dd:ee:01", "192.168.1.50", "id:kids-tablet"]
groups = ["kids"]

[[client]]
name = "Office"
match = ["10.0.5.0/24"]                  # no groups: its network's group, else "default"
```
- A device in several groups gets every list of all of them. Other settings, such as block mode, come from its highest-priority group.
- **How a query's device is recognized,** first match wins: client ID (`id:…`, from the DoH URL path `/dns-query/<id>` or the DoT/DoH server name `<id>.dns.example.com`) → MAC address, from a trusted router's EDNS option or from the MAC table (the kernel's neighbor table, then the MAC addresses your routers report: see below) → exact IP → the most specific CIDR → `default`.
- **MAC addresses** survive DHCP changes and IPv6 privacy addresses, which makes them the most dependable key for a home network. Where a query's MAC address comes from, in this order (the first that has one for the address wins):
  1. **The kernel's neighbor table** (ARP and IPv6 NDP), read every 60 s (`[clients] neighbor_refresh_secs`) while `[clients] neighbor_table` is on (the default). It only holds devices on the node's own subnets, and only with host networking (as on a Pi): in a container's bridge network or a Kubernetes pod, every query appears to come from the gateway.
  2. **The MAC addresses this node's routers report** ([Names from your router](#names-from-your-router-unifi-opnsense)): UniFi's connected clients, OPNsense's DHCP leases.
  3. **The ones another full cluster member's routers report.** Every node asks the members it has a direct stream to for what their routers know (once a minute, and every 5 seconds, for two minutes at most, until a member that reads a router has answered). A full member is one the cluster's member registry lists and that is not a resolver pod: what a node says about itself doesn't count. Replicas connect to the primary; under automatic failover (`failover = auto`, with three or more voters) the nodes that can be promoted also connect to each other, and in the default `manual` mode they don't. **A resolver pod connects to the primary alone**, so a pod gets the primary's own router view, not a replica's. A router read only by a replica reaches the primary (and, under automatic failover, the other voters), not the pods: **put the router's key on the primary** (and on the node a failover would promote).

  With a router on this node or on a member it hears, a device is also recognized by MAC where the kernel can't see it: in Docker's bridge network (rootful Docker on Linux, which keeps the device's address; rootless Docker, Podman and Docker Desktop hide it), in Kubernetes with `externalTrafficPolicy: Local` (the Helm chart's setting, which keeps the device's address; a pod through the primary's router), and on other VLANs. A device that has no entry in either table is recognized by its address, network or `default`, as before.
- **When a router's MAC doesn't count.** The kernel's table always wins over a router for an address. The routers' lists are IPv4 only (a device's IPv6 queries are recognized by MAC only through the kernel's NDP table). A router's MAC for an address is left out, and the address recognized as it would be without it (by address, network or `default`), when:
  - the client is offline;
  - the router or two of its rows give the address more than one MAC, or one MAC at two or more addresses (a range extender or bridge that shares its MAC: its devices can't be told apart, so a device named by that MAC is recognized at none of them);
  - UniFi gives only the address the client had before, not the one it has now;
  - the row's MAC is empty, all zeros, or a multicast one;
  - the router hasn't answered for 15 minutes. While a device is named by its MAC, each router is read at least every 10 minutes whatever its `interval_secs` says, so an answer is never much older than that, and a read that fails is tried again every 15 seconds, well before the 15 minutes are up. Another node's answer counts for 15 minutes too, and only if the node is listed in the member registry as a full cluster member (not a resolver pod, and not a node that merely says it is the primary) and runs this version.

  A router never makes a device: a binding only identifies a `[[client]]` that lists that MAC in `match`. This node's own routers come first: an address they bind is theirs. For an address they don't bind, another member's answer is used only if every member that has one agrees and none of them withholds it. A MAC a member withholds still counts toward "one MAC at two addresses". The rows of a router that has gone silent for 15 minutes do not: they never veto fresh data on any node, so a device that moved while such a router stays configured is recognized at its new address; the node that reads that router keeps the stale row's own address withheld, and no other node does. The kernel's table has no such rule: behind a MAC-translating extender it holds one MAC at every address behind it, and a device named by that MAC is recognized at all of them; the naming dialog flags such a MAC as shared (several IPv4 addresses with one MAC: a device's IPv6 addresses are its own, not an extender's) and doesn't preselect it.
- **A block on a device named by its MAC applies only while the MAC is vouched for.** A private address that changes, an extender, 15 minutes of router silence, a restart, or a pod that doesn't hear the router all send the device back to its address, network or `default`, and a block on its name stops applying (an allowance is just as lost). A restriction you must enforce belongs on its network's group (**Groups for your networks**), not on a MAC alone.
- **`[clients] router_macs`** (default `true`) turns the routers' MAC addresses off, leaving the kernel's table and EDNS MACs only. It's shared by the cluster and applied on reload. Set it to `false` only after every node is upgraded: an older replica refuses a shared configuration that has it (`shared configuration: unknown field …`; it keeps serving the last one it had), and an older build won't start with it in its own file. At the default the setting isn't written into what the primary shares, so older nodes aren't affected.
- **Mixed versions.** A node on an earlier version recognizes a MAC-only device through its kernel table alone. During a rolling upgrade, devices are recognized by router data once the node that reads the router (usually the primary) runs this version.
- If devices are named by MAC and no router MAC reaches a node, its log says so once, after a minute, and again only after MACs have come and gone: `devices are named by their MAC address, but no router MAC reaches this node: no router of its own is read here ... and no other full cluster member passes one on` (on a resolver pod: `... no router MAC reaches this resolver pod: a pod hears only the primary ...`). The text also names the other causes, because the same message comes from each of them: its router (or a member's, or the primary's) is silent, the members or the primary run an earlier version or haven't sent the member list yet, or the node refuses its configuration (a replica that refuses a configuration, with invalid files or a newer schema, keeps no member's bindings: it never writes the member list). A node whose configuration has no `[[router]]` is never told, in a cluster too (routers are shared settings, so a cluster with none gives every node nothing to read). The log also says when router MACs start and stop being used (`client identification: N addresses recognized by the MAC their routers report`).
- If your router forwards queries with dnsmasq's `add-mac`, trust it explicitly. Any device could send that option and impersonate another, so it's ignored by default:
  ```toml
  [clients]
  trust_edns_mac_from = ["192.168.1.1/32"]
  ```
- `$client=` rules match the device's name (`$client='Kids tablet'`), its client ID, or its IP or CIDR.
- A group can also send its questions to its own upstream servers (for example, a family-filtering resolver): see [Upstream servers per group](#upstream-servers-per-group).
- Changes apply on reload (`SIGHUP`). Metrics: `telltale_neighbors` (entries from the kernel's neighbor table, 0 while it isn't read), `telltale_router_macs{source="router"|"peer"}` (the bindings in use that this node's routers, and other full members' routers, report: 0 until a device is named by its MAC), and `telltale_router_macs_unsure` (bindings withheld, each address once).

### Groups for your networks (VLANs)
A group can own networks: every device on them belongs to it, with no per-device setup. That
makes groups a way to see *which kinds of devices* make which traffic:
```toml
[[group]]
name = "IOT"
networks = ["192.168.2.0/24"]
color = "#22c55e"                        # optional: its color in charts and chips

[[group]]
name = "Surveillance"
networks = ["192.168.7.0/24"]

[[group]]
name = "Trust"
networks = ["192.168.10.0/24"]
```
- **Which group a device gets:** the group of the most specific matching network. A
  `[[client]]` entry with its own `groups` still wins. Naming a device (in the UI or with a
  `[[client]]` entry without `groups`) keeps it in its network's group. Devices outside every
  network are in `default`.
- **Filtering doesn't change** unless you give the group `lists`: a group without `lists` uses
  every list, like `default`.
- **A network belongs to one group:** the same CIDR in two groups is a configuration error.
  Nested networks are fine; the most specific wins.
- **Where it shows:**
  - the dashboard's **Traffic by group** chart (in the Advanced view), and a group selector for its top lists;
  - each group's card on the **Groups** page: networks, queries and block rate over 24 hours,
    devices this hour, top names and top blocked;
  - a group chip on every query-log row, and a **Group** filter;
  - `group=` on `/api/v1/stats/top` and `/api/v1/queries`, and `byGroup` / `blockedByGroup` in
    timeseries buckets;
  - the metric `telltale_group_queries_total{group,status}`.
- **In a cluster**, groups and networks are shared configuration, so every node attributes devices
  the same way.

### Upstream servers per group
Each group can send its questions to its own `[[upstream_group]]` instead of `default`: a
family-filtering resolver for the kids, a privacy resolver for the trusted network, or the
ISP's resolver for streaming boxes that care where they're answered from. Make the upstream
groups first, from [presets](#upstream-presets) or by hand:
```sh
telltale presets show cloudflare-family --proto tls --group family >> telltale.toml
telltale presets show quad9 --proto tls,https --group privacy >> telltale.toml
```
Then point groups at them:
```toml
[[group]]
name = "Kids"
networks = ["192.168.20.0/24"]
upstreams = "family"
priority = 10

[[group]]
name = "Trust"
networks = ["192.168.10.0/24"]
upstreams = "privacy"
```
- **In the UI:** Groups → Edit → **Upstream servers**. *(default)* means the `default` upstream
  group. The group's card shows the choice.
- **What wins,** most specific first:
  1. a `[[route]]` for a domain (`match_suffix`), such as `home.arpa` to your router, applies
     to every group, so local names keep working;
  2. a `[[route]]` with `match_group` naming the group (for example, only its `TXT`
     questions);
  3. the group's `upstreams`;
  4. `default`.
- **A device in several groups** (a network group plus a `[[client]]` group) goes where its
  highest-priority group with `upstreams` says.
- **Caching is per upstream group.** An answer one group got from its resolver is never served
  to a group that uses another, so a family resolver's answers stay with the family group.
- **Removing an upstream group** that a group (or a route) still uses is refused; pick other
  upstream servers for that group first.
- No cost on cached answers: the choice is made only when a question goes upstream.

### Example: a home with VLANs
Networks, lists, schedules, and upstream servers combine. Each VLAN gets its own rules, and
every chart and log line shows which one a question came from:
```toml
[[group]]
name = "Trust"                    # laptops and phones
networks = ["192.168.10.0/24"]
lists = ["hagezi-pro"]
upstreams = "privacy"

[[group]]
name = "Kids"
networks = ["192.168.20.0/24"]
lists = ["hagezi-pro", "family-extra"]
blocked_services = ["tiktok", "fortnite"]
safe_search = true
schedules = ["bedtime"]
upstreams = "family"
priority = 10

[[group]]
name = "IoT"                      # TVs, plugs, cameras
networks = ["192.168.30.0/24"]
lists = ["hagezi-pro", "smart-tv"]
rebinding_protection = true

[[group]]
name = "Guest"
networks = ["192.168.40.0/24"]
lists = ["hagezi-light"]
block_mode = "nxdomain"
```
- IoT has no `upstreams`, so it uses `default`.
- To see the effect, filter the query log by group, or ask
  `from -24h | where group = Kids | top 10 upstream` (see
  [Analytics in one query](#analytics-in-one-query-vqlog)).
- Devices must reach TelltaleDNS **with their own addresses** for their network to count: route
  the VLANs to it rather than through a forwarder that rewrites them (see
  [Seeing real client IPs](#seeing-real-client-ips)).

### Blocked services
Block a whole service for a group with one setting, without finding its domains:
```toml
[[group]]
name = "kids"
networks = ["192.168.20.0/24"]
blocked_services = ["tiktok", "roblox", "fortnite"]
```
- `telltale services list` (or `GET /api/v1/services`, or the Groups page) shows every service with the domains it blocks: social networks (TikTok, Instagram, Snapchat, ...), video and music (YouTube, Netflix, Twitch, Spotify, ...), games (Roblox, Fortnite, Minecraft, Steam, Xbox, PlayStation, Discord), messaging and AI chat.
- A service blocks its domains and everything under them, for that group only. A group that uses every list still doesn't get other groups' services.
- Blocks say which service did it: the query log shows the service, and the EDE text reads `blocked service TikTok`.
- In the UI: **Groups → Manage groups → Edit → Blocked services**.
- The catalog is part of the binary (`presets/services/*.toml`); services change with updates. To block one service's extra domain, add a quick rule.

### Rewrites
Answer a name differently for a group, for example a split-horizon name or a test server:
```toml
[[group]]
name = "default"

[[group.rewrite]]
domain = "nas.example.com"           # this name...
answer = "192.168.1.10"              # ...answered with this address (A, or AAAA for IPv6)

[[group.rewrite]]
domain = "*.dev.example.com"         # every name under dev.example.com
answer = "10.1.1.1"

[[group.rewrite]]
domain = "tv.example"
answer = "cdn.example.net"           # answered as a CNAME to that name, with its addresses
```
- An exact name wins over a wildcard; the most specific wildcard wins over others. A wildcard covers names under the domain, not the domain itself.
- An address rewrite answers the other address family and other record types with no data.
- Blocks still win: a blocked name isn't rewritten. For a name everyone should get, use [local records](#local-records) instead.

### Different answers per network (split horizon)
The same name can get a different answer depending on the network a device is on: the LAN gets a server's LAN address, the VPN its VPN address. Three settings join up: a group per network ([`[[group]] networks`](#groups-for-your-networks-vlans)), the group's [rewrites](#rewrites) for single names and wildcards, and a [zone](#local-zones) that only some groups see (`[[zone]] groups`) for a whole domain of their own:
```toml
# A group per network: every device on it belongs to the group.
[[group]]
name = "lan"
networks = ["192.168.2.0/24"]

[[group.rewrite]]                    # belongs to the group above
domain = "*.internal.example.org"    # every name under internal.example.org...
answer = "192.168.2.177"             # ...answered with the reverse proxy's LAN address

[[group]]
name = "vpn"
networks = ["10.10.0.0/24"]

[[group.rewrite]]
domain = "*.internal.example.org"
answer = "10.10.0.132"               # the same names, the proxy's VPN address

# A whole domain only the LAN sees: its records, and "no such name" for the rest.
[[zone]]
name = "lab.example.org"
groups = ["lan"]

[[zone.record]]
name = "printer.lab.example.org"
type = "A"
value = "192.168.2.20"

[[zone.record]]
name = "_ipp._tcp.lab.example.org"
type = "SRV"
value = "0 5 631 printer.lab.example.org"
```
- **Devices on other networks** get the public answer for `internal.example.org` names, and resolve `lab.example.org` normally.
- **A rewrite or a zone?** A rewrite answers with an address (A, or AAAA for an IPv6 address) or a CNAME, and leaves every other name to the upstreams. A zone holds any type local records support (A, AAAA, CNAME, PTR, TXT, MX, SRV), and answers "no such name" for names it doesn't have, so the groups that see it never send that domain to a public resolver.
- **One domain for several networks, as a zone:** one `[[zone]]` with the same `name` per group, each with its own records. A zone without `groups` for the same domain answers everyone else (the groups' own zones are used first); without one, devices outside those groups resolve the domain normally. The same zone twice for the same groups is a configuration error.
- **What answers first,** for one question: [local records](#local-records) (`[[record]]`, and names added in **Names on my network**), for every device; then the zones the device's groups see; then quick rules and blocking; then the rewrites of the device's highest-priority group. So don't also give a per-network name a local record, which every network would get, and remember that a blocked name isn't rewritten while a name in a zone is answered before blocking. A device in several groups sees the zones of all of them.
- **Devices must reach TelltaleDNS with their own addresses** for their network to count: a VPN that is routed, not hidden behind one address, and no forwarder that rewrites the sender (see [Seeing real client IPs](#seeing-real-client-ips)).
- **Check it** with `telltale explain nas.internal.example.org --client 10.10.0.5 -c telltale.toml`, or **Explain** in the UI, from an address on each network.
- **Where they are set:** zones in the configuration file (or Git); rewrites there too, or through `PUT /api/v1/groups/{name}` (its body is the whole group, with the same fields as `[[group]]`, `networks` and `rewrite` included, and it replaces a file's group of that name). The UI doesn't edit either yet: the Groups page shows each group's rewrites, and **Names on my network** lists the zones and the groups that see them. File changes apply on reload (`SIGHUP`).

### DNS64
For IPv6-only devices behind a NAT64 gateway: names without an IPv6 address get one made from their IPv4 address (RFC 6147), so the gateway can reach them.
```toml
[[group]]
name = "ipv6-only"
networks = ["2001:db8:64::/64"]
dns64 = true
# dns64_prefix = "64:ff9b::/96"     # the default (well-known prefix); your NAT64's /96 otherwise
# dns64_exclude = ["2001:db8:bad::/48", "198.51.100.0/24"]
```
- An AAAA question with no AAAA answer is asked again as A, and each A record becomes an AAAA in the prefix (`192.0.2.33` → `64:ff9b::c000:221`); CNAMEs come along. Names that have real AAAA records are left alone.
- Only for the group's devices, and never for clients that set CD (they validate DNSSEC themselves, and made-up records don't validate).
- Check it with `dig AAAA ipv4only.arpa`: through DNS64 it answers `64:ff9b::c000:aa` and `64:ff9b::c000:ab`.
- Addresses that can't work through NAT64 (`0.0.0.0/8`, `127.0.0.0/8`, `169.254.0.0/16`) aren't turned into AAAA.
- **Exclusions** (`dns64_exclude`, RFC 6147 §5.1.4): IPv6 addresses in these networks count as missing, for names whose IPv6 addresses your devices can't reach (a broken tunnel, a provider's unreachable range); the name gets made-up AAAA records instead, or keeps its other real ones. IPv4-mapped addresses (`::ffff:0:0/96`) are always excluded. IPv4 networks listed here are never turned into AAAA, so those destinations stay unreachable from IPv6-only devices.
- **Reverse lookups** for addresses in the prefix follow the IPv4 address: `dig -x 64:ff9b::c000:221` answers with a CNAME to `33.2.0.192.in-addr.arpa` and that name's PTR (RFC 6147 §5.3.1). Private IPv4 addresses inside the prefix get NXDOMAIN locally, as their in-addr.arpa names would.

### No IPv6 addresses for a group
The opposite of DNS64: a network whose IPv6 is broken or half set up (pages hang, then fall back to IPv4). Answer the group's IPv6 (AAAA) questions with nothing, so its devices use IPv4 at once:
```toml
[[group]]
name = "guest"
networks = ["192.168.50.0/24"]
filter_aaaa = true
```
- AAAA questions get NOERROR with no records, from TelltaleDNS itself (no upstream asked); A and every other type are unchanged. The query log shows them as `special`.
- Your [local records](#local-records) and zones still answer AAAA (you configured those addresses), and blocked names stay blocked.
- HTTPS records (type 65) can still carry IPv6 hints, which some browsers use; this setting leaves them alone.
- Not with `dns64` (which makes AAAA answers on purpose). In the UI: **Groups**, edit the group, *No IPv6 addresses* (Advanced view).

### Rebinding protection
A website can make your browser attack devices on your network by pointing its own name at a private address (DNS rebinding). Turn on the protection per group:
```toml
[[group]]
name = "default"
rebinding_protection = true                   # refuse private answers for public names
rebinding_allow = ["plex.direct", "home.example.com"]   # names allowed to answer private addresses
block_answer_ips = ["203.0.113.0/24"]         # answers in these networks are refused for any name
```
- With `rebinding_protection`, answers in private (10/8, 172.16/12, 192.168/16, fc00::/7), loopback, link-local, CGNAT (100.64/10), and unspecified ranges are blocked, with the block answer and the reason in the query log. Your [local records](#local-records) and domains with a `[[route]]` (conditional forwarding to your router or AD server) are never affected.
- `block_answer_ips` refuses answers in any network you list, whatever the name (a known-bad range, or your own WAN address).
- Cached answers are checked too, and a paused group isn't filtered.

### Safe search
Make search engines show only safe results for a group, whatever the browser's settings:
```toml
[[group]]
name = "kids"
networks = ["192.168.20.0/24"]
safe_search = true
youtube_restrict = "strict"                 # or "moderate", or "off" to leave YouTube alone
```
- Google (every country domain), Bing, DuckDuckGo, Yandex, and Pixabay answer as a CNAME to their own safe-search service (`forcesafesearch.google.com`, `strict.bing.com`, ...), with that service's addresses, so the engine enforces it. YouTube gets Restricted Mode (`restrict.youtube.com`, or `restrictmoderate.youtube.com`).
- HTTPS records for those names get no data, so browsers use the safe-search addresses rather than hints for the normal ones.
- It applies to the group's devices only; the table is part of the binary (`presets/safesearch.toml`).
- Browsers using their own encrypted DNS bypass it (as they bypass all filtering): TelltaleDNS answers `use-application-dns.net` with NXDOMAIN so Firefox turns its own DoH off.
- In the UI: **Groups → Manage groups → Edit → Safe search**.

### Schedules
Change a group's filtering by the time of day and the day of the week: block everything at bedtime, or add a list or a service only at certain times.
```toml
[[group]]
name = "kids"
networks = ["192.168.20.0/24"]
schedules = ["bedtime", "school-hours"]

[[schedule]]
name = "bedtime"
action = "block_all"                        # everything is blocked during the windows
tz = "Europe/Berlin"                        # default: the system's time zone
window = [
  { days = ["sun", "mon", "tue", "wed", "thu"], start = "21:00", end = "07:00" },
  { days = ["fri", "sat"], start = "22:30", end = "08:00" },
]

[[schedule]]
name = "school-hours"
action = "block_services"                   # or "enable_lists" with `lists = [...]`
services = ["tiktok", "youtube", "roblox"]
window = [{ days = ["weekdays"], start = "08:00", end = "15:00" }]
```
- **Windows** are weekly: the days they start on (`mon` … `sun`, `weekdays`, `weekends`, `daily`) and local `HH:MM` times. An end at or before the start runs past midnight, so `21:00`–`07:00` on Sunday covers Sunday night into Monday morning.
- **`block_all`** blocks every name for the group (the answer says `blocked by schedule bedtime`). Quick allow rules still win, so a homework site can stay reachable, and local names (`nas.home.arpa`) still answer. Pausing a group's blocking pauses its schedules too.
- **`enable_lists`** and **`block_services`** add lists or services during the windows. A list a schedule turns on is off outside its windows for every group, even one that uses every list, unless a group names it in its own `lists`.
- Schedules are checked every 15 seconds, so a window starts or ends within 15 s of its time. No query does any time maths, and nothing is recompiled.
- The Groups page shows each group's schedules and which are **on now**; the query log shows blocks as **schedule**.
- **In the UI:** **Groups → Schedules** adds, changes, or removes schedules (windows one per line, like `weekdays 21:00-07:00`), and a group's editor picks the schedules it follows. Through the API: `PUT`/`DELETE /api/v1/schedules/{name}` with the same fields as `[[schedule]]` (agents need `config:write:groups`, and AI agents can plan one with the MCP tool `plan_set_schedule`).

### Names from your router (UniFi, OPNsense, FRITZ!Box)
TelltaleDNS doesn't hand out addresses: your router's DHCP does that, and TelltaleDNS can read its client list, so devices show up by name.

**FRITZ!Box via TR-064:**

```toml
[[router]]
name = "site-a"
type = "fritzbox"
url = "https://192.168.40.1:49443"                    # TR-064 over TLS
client_subnets = ["192.168.40.0/24"]
username = "telltale"                                 # a user of the box (System → FRITZ!Box Users)
password_file = "/etc/telltale-secrets/site-a/password"
tls_ca = "/etc/telltale/site-a.pem"                   # the box's own certificate (self-signed)
tls_server_name = "fritz.box"                         # the name in it

[[router]]                                            # or, without a sign-in (configuration file only)
name = "site-b"
type = "fritzbox"
url = "http://192.168.50.1:49000"
client_subnets = ["192.168.50.0/24"]
```

**Signed in** (a user and its password; the box asks for HTTP Digest), the whole host list comes in one file (`X_AVM-DE_GetHostListPath`), so a box read over a VPN takes a few requests, not one per host. Give it a user of the box that may read its settings, over `https://…:49443` (the TR-064 port with TLS). The box's certificate is self-signed, marked as a CA, and names `fritz.box`: TelltaleDNS accepts it as the box's own when it is an exact copy of the one in `tls_ca`. Save it (`openssl s_client -connect 192.168.40.1:49443 </dev/null | openssl x509 > site-a.pem`) as `tls_ca` and set `tls_server_name` to the name in it (`openssl x509 -in site-a.pem -noout -ext subjectAltName`). A signed-in box can also be added in the UI or the API like UniFi and OPNsense (below): the password is pasted and kept like their keys. A list longer than 1,024 hosts fails the read and keeps the last list.

**Without a sign-in:**
Add a separate entry for each router, with distinct client subnets. Enable LAN access for applications (TR-064) on the FRITZ!Box. From the TelltaleDNS host, verify that `<url>/tr64desc.xml` is reachable over the LAN or private VPN. The host count and per-host read actions require no extra TR-064 rights. This source supports endpoints that allow those reads without credentials. Keep the API on the private network. For HTTPS, configure certificate trust as for other router sources.

Only active IPv4 entries in the listed networks are used. In a Mesh, configure the Mesh Master for clients it reports. Enable the existing `[clients] router_macs` option when using these records for MAC-based policy matching. For a fleet, upgrade all members before adding this router type to shared configuration. The URL is the scheme, host and port only. A box read without a sign-in is configuration-file only: the router API and the UI take a FRITZ!Box only with a username and its password. Only full cluster members read a FRITZ!Box (not resolver pods); the other nodes hear what it says from them.

Without a sign-in, each host is one request (5 seconds each, 2 minutes for the whole list, at most 1,024 hosts; more fails the read and keeps the last list). A plain `http://` URL isn't authenticated: the configuration check warns, and while its list identifies devices by MAC the node logs a warning too, so keep the route to the box private (LAN or VPN).

Advertise TelltaleDNS as the client DNS server (FRITZ!Box **Local DNS server** in the LAN DHCP settings where supported), or set DNS directly on clients. Check the query log for their original LAN IPs. When the router forwards queries under its own IP, those queries have a router-level identity and policy.

**In the UI (admins):** **Clients → Discovered → Routers → Add router**. Pick UniFi, OPNsense or FRITZ!Box, give its `https://` address, and paste the API key (for OPNsense, the key and the secret; for UniFi without a key, a username and password; for a FRITZ!Box, a username and its password, and its client networks). TelltaleDNS saves each pasted value to a new file only it can read, `secrets/router-<name>.<key>.<random>` in the data folder (mode 0600, folder 0700), and never shows it again; the router's row says **key saved**. Editing the router later keeps the key unless you type a new one, except that changing the address, the type, the site, or the TLS settings needs the key typed again, so a saved key isn't sent to a router address or TLS setting other than the one it was entered with (where a host name resolves is another matter: see the next points). A router added or changed is read within 5 seconds after the reads in progress end, and a removed router's names go after the next round of reads, without a restart.
- **Only administrators** add, change, or remove routers: their own sign-in or an admin API token. Agent tokens can't, whatever scopes they hold. Others see the routers without their key files or user names, and whether each key is saved.
- **Paste the key; don't name a file.** The UI and the API take the key itself. A key that lives in a file elsewhere (a Docker secret in `/run/secrets/`, a Kubernetes Secret through the chart's `secretMounts`) is named in the configuration file instead.
- **`https://` only for a pasted key** (or a loopback address such as `http://127.0.0.1`): over `http://` the key could be read on the way. A self-signed console works over `https://` with `tls_ca` and `tls_server_name`, below.
- **With "Don't check the certificate", give the address as a number** (`https://192.168.1.1`, not a host name): with the certificate unchecked, whoever can change where the name resolves (a local name or a forward on this resolver, say) could choose who receives the key. A host name works with the certificate checked (`tls_ca` and `tls_server_name`).
- **The request key.** Changes sent with an `Idempotency-Key` keep a hash of a pasted key, keyed with `secrets/.request-key` in the data folder (made on the first start). On a filesystem without hard links (some SMB or FUSE volumes) that file can't be made: the node logs a warning at every start and uses a key for that run only, so a retry after a restart gets 409 instead of the first answer.
- **Open the UI over `https://` to paste a key.** On a plain-HTTP page reached from another machine, what you paste crosses the network unencrypted; the Routers editor says so ("You are on a plain-HTTP page..."). A page on the machine itself (`http://127.0.0.1`, `http://localhost`) doesn't leave it.
- **A pasted key is on the node that saved it,** the primary. It isn't copied to other nodes, and it isn't in backups. After a restore on another machine, or a failover to another primary, the router says **key missing: enter it again**, and isn't read there until an administrator pastes the key again on the node that takes configuration changes. A key kept in `/run/secrets/` or `/etc/telltale-secrets/` on every node (below) needs no re-entry. Each node removes the key files it saved once no router names them (a key replaced or a router removed): only files in the data folder's `secrets/` itself that are named like the ones it makes (`router-<name>.<key>.<random>`) and listed in its `secrets/.written`, plus the temporary files a stopped write left there (`.written.<random>.tmp`, `.request-key.<random>.tmp`) once they are ten minutes old. Anything else there (an alert's token file, `.request-key`) is never removed. While a router entry in `state.db` can't be read (a hand edit), no key file is removed, and each try logs "router keys: the sweep of key files no router names didn't run".
- Through the API: `PUT`/`DELETE /api/v1/routers/{name}` with the fields below, plus `api_key`, `api_secret`, or `password` instead of their files. `GET /api/v1/config/entries?kind=router` lists them, with each key's status in `credentials` as the node that answered sees it: `saved`; `missing` (enter it again); `file_missing` (a key file a platform mounts or a config file names isn't there: put the file there); or `not_used` (a file there that that node doesn't send for that router). A router without its key is refused by the name to paste (`api_key`, `api_secret`, `password`).
- In a cluster, upgrade every node before adding routers in the UI: an older primary refuses a router change a replica sends it.

**In the configuration file:**
```toml
[[router]]
name = "udm"
type = "unifi"                         # UniFi OS consoles (UDM, UCG, Cloud Key) and the Network application
url = "https://192.168.1.1"            # the classic Network application: https://controller:8443
api_key_file = "/etc/telltale-secrets/udm/api_key"   # UniFi Network 9+ (Settings → Control Plane → Integrations)
# username = "telltale"                # or a local read-only user...
# password_file = "/etc/telltale-secrets/udm/password"
# site = "default"
# offline_days = 30                    # also name clients that are offline now, if UniFi saw them this recently (0: only connected ones)
tls_ca = "/etc/telltale/udm.pem"       # the console's own certificate (self-signed)
tls_server_name = "unifi.local"        # the name in it (UniFi consoles name themselves unifi.local)

[[router]]
name = "firewall"
type = "opnsense"
url = "https://opnsense.lan"
api_key_file = "/etc/telltale-secrets/firewall/api_key"     # System → Access → Users → API keys
api_secret_file = "/etc/telltale-secrets/firewall/api_secret"
```
- UniFi: the connected clients, plus the offline clients UniFi still knows (its client history and configured clients), named by the alias you gave them in UniFi, else their host name. An offline client is one UniFi saw within `offline_days` (30 by default; 0 for only the connected clients; at most 365), and at most the 1,024 most recently seen are kept. It is listed only when it has a name, at its last or fixed address, and never over a connected client's address. It names the device in the query log, but it doesn't count as seen for device identification. A console without the client history (Network before 7) gives the configured clients. OPNsense: the DHCP leases (Dnsmasq, Kea, or ISC, whichever is running).
- A self-signed console: save its certificate (`openssl s_client -connect 192.168.1.1:443 </dev/null | openssl x509 > udm.pem`) as `tls_ca`. Its certificate names `unifi.local`, not the address you reach it at, so set `tls_server_name` to the name in it (`openssl x509 -in udm.pem -noout -ext subjectAltName` shows it): the console is then verified, and only that certificate is trusted. `tls_insecure_skip_verify = true` also works, but then anything on your network could pose as the console and receive the API key.
- Read every `interval_secs` (300); a router that doesn't answer is asked again after 15 seconds and keeps its last list meanwhile. While a device is named by its MAC address and `[clients] router_macs` is on (the default), the MAC addresses a router lists identify devices, so it is read at least every 10 minutes (600 seconds) whatever `interval_secs` says: a list older than 15 minutes doesn't say who holds an address, and a read that fails is asked again every 15 seconds inside that time. With `interval_secs = 3600` that makes 600 while a device is named by its MAC, and 3600 otherwise: before the first device is named by a MAC, a list is older than 15 minutes for most of each hour, and the "Name this device…" dialog offers a router's MAC only while its list is fresher than that, so the first naming may have to wait for the next read (a shorter `interval_secs` avoids it).
- Names you give devices in TelltaleDNS win; then the routers'. `GET /api/v1/dhcp/leases` lists them (`source = router`).
- **The routers' MAC addresses also recognize devices.** A device you named by its MAC address (`match = ["aa:bb:cc:dd:ee:ff"]`) is recognized at whatever address your router says it has now, so its name, groups and rules follow it when the router gives it another address, including where the kernel's neighbor table can't see it (in Docker, in a Kubernetes pod, on another VLAN: see [Groups and devices](#groups-and-devices)). A router only ever gives the address and the MAC: it never makes a device, and a host name or alias never recognizes one.
  - **Read the router often enough.** A device that moves to a new address is recognized there at the next read, so `interval_secs = 60` is a good value when that matters (a router is never read more often than every 30 seconds). A router that is silent for 15 minutes stops recognizing devices until it answers again (they are recognized by address, network or `default` meanwhile), and while a device is named by its MAC every router is read at least every 10 minutes whatever `interval_secs` says.
  - **Check the router's certificate.** A router's list is now something that decides which rules a device gets, so `tls_insecure_skip_verify = true` matters more than it did: anything on your network that poses as the console can bind any address to any MAC. The node logs a warning when a router with an unchecked certificate starts to recognize devices. Use `tls_ca` and `tls_server_name`.
  - **High availability needs the key on two nodes, and the pods hear only the primary.** What the router says reaches the other nodes through the node that reads it, and only the nodes that have a direct stream to it: a replica's router reaches the primary (and, under automatic failover, the other voters), but a resolver pod connects to the primary alone and gets the primary's own router view. So the key belongs on the primary, and, for a failover, on the node that would be promoted. If the reading node goes away, devices named only by MAC fall back to recognition by address 15 minutes later. Put the router's key in `/etc/telltale-secrets/` or `/run/secrets/` on both, with the router defined in the configuration file. A key pasted in the UI stays on the node that saved it. While two nodes read one router they poll out of phase, so a device that has just moved can be withheld on both until both have polled (a MAC then sits at two addresses in their combined view). If one of the two loses its router (a key that stops working, a changed address), its old rows stop counting after 15 minutes of silence and withhold nothing on the other nodes.
  - **Sites that reuse one private range.** Every full member's router counts, so in a cluster that spans sites using the same range (two homes both on 192.168.1.0/24), a member at another site can bind a local address to a MAC. Keep such clusters on one site's routers, or set `router_macs = false` (after every node is upgraded).
- Credentials stay in files, out of the configuration (a key pasted in the UI is saved to a file too). Keep them in `/etc/telltale-secrets/<router>/` (mode 0600, owned by the service user; the folder 0700), as above, or in `/run/secrets/` for Docker: in a cluster those are the folders a replica reads a key from (below). Routers in the file apply at start and on reload (`SIGHUP`), within 5 seconds after the reads in progress end, as do ones added or changed in the UI, and a router made in the UI with the name of one in the file replaces it until it's removed (**Revert to the file**).
- In a cluster, only one node needs to read the router (or hear mDNS) for the names. Every node asks the nodes it has a direct stream to for the device names they know, once a minute, so a resolver pod without the router's key names devices the way the primary does (a pod hears only the primary: for MAC addresses see above).
- **Which key files a node sends.** A node reads a router with a key file only if, for each of its key files: the file is in `/run/secrets/` (Docker, Compose) or `/etc/telltale-secrets/` (the Helm chart's `secretMounts`), on any node, links followed; or this node's own configuration files define that router with that file at the same address; or this node saved that key itself, through the UI, for that router and address. A key in those folders is read whatever the node's own file says (a replica's older copy of the primary's `[[router]]`, which it ignores anyway, doesn't stop it). A router made or changed in the UI may name only a key pasted there (in the data folder's `secrets/`) or the very key file and address the config file gives that router. So an override made in the UI that kept a key from the config file (in those folders or anywhere else) is used only while the config file gives that router the same key file and address: once the file moves the router to another address or removes it, the node that applies the UI's changes (a standalone node, or the primary) leaves the override out, logs a warning saying why, and the config file's router (if any) is the one in effect; the configuration it shares never carries the override, so no replica sends the key to the old address. (On a primary promoted after a failover, the configuration it was promoted with stands in for the config file.) Edit the router in the UI to save it for the new address, or remove the override (`DELETE /api/v1/routers/{name}`). An entry from the UI that names some other file in the data folder's `secrets/` (restored from a backup or edited in `state.db`, say) isn't left out: it stays in effect in place of the config file's router of that name, but no node reads it unless that node saved that key for that router and address itself; it is held back as below. A router held back is logged once as a warning, with why and what to do (information on a Helm resolver pod, which has no keys by design). On the node that takes configuration changes, its row says **key not used: enter it again** (or, when the file isn't there, **key missing** or **key file missing**). **A replica's Routers page shows the primary's status** (its own only while the primary can't be reached), not what the replica does: that is in the replica's log.
- **On a replica, or a primary promoted after a failover,** a router that only the primary's configuration file defines is read when its key files are in one of those two folders on that node. Keys kept anywhere else (`/etc/telltale/opn-secret`, as earlier versions of this guide showed) aren't read there: in a cluster of native nodes, put the files in `/etc/telltale-secrets/` (for example `/etc/telltale-secrets/firewall/api_secret`, mode 0600, owned by the service user) on each node that should read the router, and name those paths. If a key under `/etc/telltale-secrets/` is a link, it must lead to a file inside that folder (`readlink -f` shows where it goes). Defining the router in a replica's own configuration file also lets that replica send the key, but the replica then logs, as for any shared setting in its file, that the section is ignored (the shared routers come from the primary, CLU-006): the folder is the cleaner way. With the Helm chart every pod has the same configuration and the controller mounts `secretMounts`, so nothing changes there.
- Who decides that a node sends a key from those folders, and where to: whoever writes a configuration file or Git repository a node takes routers from. The UI and the API can't name a new file there for a router; an administrator's change can only keep the file a router already has, at the same address.

### Names devices announce (mDNS)
Phones, speakers, printers, and NAS boxes announce themselves on the local network (`Kitchen-HomePod.local`). TelltaleDNS can listen and use those names for devices you haven't named:
```toml
[clients]
mdns = true
```
- Listen only: TelltaleDNS never sends mDNS. It shares port 5353 with avahi or the system's responder.
- It has to hear the LAN: a native install, the Docker Compose bundle, or a pod with host networking. In a bridge or pod network nothing arrives.
- Names you give devices win, then the routers' DHCP leases, then mDNS. Names are lowercase, as mDNS compares them. At most 4096 devices are remembered (until a restart).
- `GET /api/v1/dhcp/leases` lists them with `source = mdns` (no MAC), and **Clients → Discovered** shows every device found by a router or mDNS. Naming one from there (or from any address in the UI) suggests the name it gave.
- Changing it needs a restart.

### Naming devices in the UI
The Clients page's **Last hour** tab lists every address that asked in the last hour, busiest first, with every node's queries added up. It moves with the clock in 5-minute steps rather than starting again on the hour, so at 10:02 it still shows what asked at 9:30; it always covers the full hour (60 to 65 minutes back). Its counts are exact. A node that doesn't answer (one still on an older version during an upgrade) is named above the list, as its clients aren't in it. (The API: `GET /api/v1/stats/top?kind=clients&hour=rolling`, optionally with `group`.)

Click a device's address anywhere (the dashboard's top clients, the query log, the live view, Clients) and choose **Name this device…** or **Add to group…**. The name shows everywhere at once, including on past queries: names are looked up when data is read, never written into the query log, so renaming relabels history and forgetting a device brings the address back.

Devices named this way are stored in `state.db` (next to users and the audit log) and merged with `[[client]]` entries from the config files. The files win: a device defined in a file is read-only in the UI, and the UI can't reuse its name. If a stored device stops being valid (say its group was removed from the file), TelltaleDNS logs why and runs with the file config alone until it's fixed. Operators and admins can name devices; viewers see the names.

A change is checked against the configuration this node applies: its config files (on a primary promoted after a failover, the cluster version it continues from: see [Clusters](#clusters)), everything stored in the UI, and the change. One that would stop the stored devices from applying, such as a rename that keeps an address another device still has, is refused with the reason, and nothing is stored. A stored device that isn't in effect (the files have a device of its name, or the stored devices don't apply until something is fixed) can still be deleted, with `DELETE /api/v1/clients/{name}`, and one that a device of the files hides can be renamed to a free name and address; while the stored devices don't apply, a delete is the one change accepted that doesn't fix them, and its answer says what still stops them. The log says which rows those are: after the reasons (which give places in a list, such as `client[3]`), the line `ignoring config made in the UI until this is fixed` names the stored devices they point at, and a change refused meanwhile names them too, to whoever may read every device.

**Recognize it by its MAC address, or by this address.** When the node knows the MAC address of the address you clicked (from your router, or from its own neighbor table), the dialog asks how to recognize the device:
- **Its MAC address** follows the device when its address changes: its name, groups and rules stay with it, for as long as your router (or, for a MAC only this server sees, its neighbor table) keeps reporting that MAC at one address. A router's MAC is followed for IPv4 addresses only; a MAC that is shared by several addresses, or that changes, or a router that has gone silent, is not followed, and the device falls back to its address, network or `default`. The dialog offers a router's MAC only while that router has been read within the last 15 minutes: while a device is named by its MAC the router is read at least every 10 minutes, but before any device is named by a MAC, with `interval_secs` above 900, the first naming may have to wait for a fresh read (the dialog offers the address until then). The device is saved with the MAC address alone, not the address it has now: an address key would name whoever gets that address next. For a new device it is what the dialog starts with when the MAC comes from a router (every node that hears it can use it) and isn't shared.
- **This address** stops matching if the device gets another address (a DHCP reservation in your router keeps it). It is what the dialog starts with for a device that already exists (re-saving it to change a group must not strip its address: the MAC is offered, not preselected), when only this node's own neighbor table knows the MAC (other servers in a cluster, or one in Docker or Kubernetes, won't recognize the device by it), or when the MAC is at more than one address (a range extender or bridge may share it, so it can't tell those devices apart: the router's list, or this server's neighbor table, says so). The dialog says which, and the MAC is still offered.

If the address is already recognized as a device (by its address, or by a MAC it lists), the dialog edits that device instead of making a second one, and there is nothing to choose when it already lists the MAC. When you pick a MAC another device already lists, that device is the one edited, and the dialog says so.

Some things to know about a MAC address:
- **A "private" Wi-Fi address** (many phones and laptops make one up for each network) stays the same on your network unless the device is set to change it or forgets the network. If it changes, name the device again, or turn the private address off for your network. The dialog says when the MAC is one of these.
- **A range extender or bridge** can show one MAC address for several devices; a MAC reported at more than one address recognizes none of them.
- **A device can copy another's MAC address,** and is then that device. For an allowance worth protecting, use a client ID (DoT or DoH), which a MAC address isn't.
- **A block on a device named by its MAC stops applying whenever the MAC isn't vouched for:** a private address that changes, an extender, 15 minutes of router silence, a restart, or a resolver pod that doesn't hear the router. A restriction you must enforce belongs on its network's group, not on a MAC alone.
- **A device named only by its MAC address loses some views that need an address.** It isn't covered by its group's anomaly mutes, by change previews and simulations, by the Clients page's guess of what it is, or by look-ups of its identity and rhythm by name. A device with both keys in its `match` list (through the API or the configuration file) keeps those views, at the price that its address key names whoever gets that address next.
- **Past queries are named by whoever holds the address now.** Names are looked up when data is read, so a query logged from an address that has since changed hands shows the new holder's name.

The same through the API, for scripts and agents:
```sh
curl -X PUT 'https://dns.example.com/api/v1/clients/Living%20room%20TV?dryRun=true' \
  -H "authorization: Bearer $TOKEN" -H "content-type: application/json" \
  -d '{"match": ["192.168.1.42"], "groups": ["default"]}'   # what would change; nothing is saved
```
Without `dryRun` the change is saved, applied, and audited. `GET /api/v1/clients` returns the config version as `ETag`; send it back as `If-Match` to refuse the write if someone changed the config meanwhile (412). An `Idempotency-Key` header makes retries safe: the same key replays the first answer for 24 hours, and a retry sent while the first request is still running gets 409 with `Retry-After` (retry after it for the first answer) instead of making the change twice. A key belongs to whoever sent it: a person's sessions and API tokens share theirs, and an agent token has its own. At most 32 changes run at once; one more gets 503 with `Retry-After`. To rename, send the new `name` in the body; `DELETE /api/v1/clients/{name}` forgets a device.

### What is this device?
TelltaleDNS guesses what each address is, so a new one isn't just a number. It uses what it already sees:
- the maker of the device's network card: its MAC address's vendor in the IEEE registry (from the neighbor table or your router);
- the name the device announces (to your router's DHCP, or over mDNS);
- the domains it talks to (a Roku asks `roku.com`, a Sonos speaker `sonos.com`).

These are scored against a catalog of common home devices that ships with TelltaleDNS (phones, TVs and streamers, speakers, cameras, plugs, consoles, printers, NAS boxes, network gear, and more). The Clients page then says, under the device: "Looks like a **Roku player** (likely) · Roku". **Likely** and **possibly** say how sure it is; when nothing fits, only the maker is shown. **Why?** lists the evidence: the domains that matched, the vendor and MAC prefix, the name, and a close second guess if there is one.

- **Naming:** "Name this device…" fills in the guess ("Roku player") when the device hasn't told your router a name, so you only add "living room". A guess never becomes a name by itself.
- **Groups:** give a group the kinds of device that belong in it, and devices of that kind that aren't in it yet get it suggested ("iot suggested"); "Add to group…" pre-selects it. Nothing moves on its own.
  ```toml
  [[group]]
  name = "iot"
  device_classes = ["camera", "doorbell", "plug", "bulb", "hub", "thermostat", "vacuum"]
  ```
  A kind belongs to one group at most.
- **Wrong guess?** Name the device and set **What it is** (`[[client]] kind = "camera"`, or `"unknown"` to stop guessing). That always wins and shows as set rather than guessed.
- **More devices:** `[identify] signatures_file = "/etc/telltale/devices.toml"` adds signatures in the catalog's own shape (`presets/devices.toml` in the source): an `id` the catalog uses replaces that signature, and `enabled = false` on it removes it.
  ```toml
  [[device]]
  id = "our-bike"
  name = "Exercise bike"
  class = "appliance"
  vendors = ["Acme Fitness"]          # words in the MAC vendor
  hostname_patterns = ["BIKE-*"]      # globs on the names it announces
  domains = [{ name = "acmefit.example", weight = 1.0 }]
  ```

How it works: every 10 minutes, on a thread of its own at background priority, each node scores the devices it saw in the last day (`[identify] max_clients`, 1,024 by default), from what it already keeps in memory; for a device it doesn't hold, it reads the query log (a few devices per pass). The score is 60% domains, 25% maker, 15% name: **likely** from 0.6, **possibly** from 0.35. Results are kept in `<data_dir>/devices.json` across restarts. In a cluster each node identifies the devices it sees, and the most confident guess per device is shown. It never changes how a query is answered.

Limits: phones use private Wi-Fi addresses, so their maker is unknown and the domains and name decide. Behind a router or proxy that hides client addresses, many devices look like one. It's off at query-log privacy level 1 and above, where names are hashed, and with `[identify] enabled = false`.

Through the API: `identity` on each device of `GET /api/v1/clients`, `GET /api/v1/clients/identities` for every device seen, and `GET /api/v1/clients/{address or name}/identity` with the evidence. Agents: `identify_device`, and `identity` in `get_client_profile`. New-device alerts and anomaly findings say what the device looks like. Metrics: `telltale_devices_by_class{class}`.

The MAC vendor table is built from the IEEE Registration Authority's public registry by `presets/build-oui.py`.

## Quick rules
A quick rule allows or blocks a site, and everything under it, for one device, a group, or everyone. It can last for a while or until you remove it. Some uses:
- unblock a game's server on one phone for an evening;
- block a video site on the kids' tablets until tomorrow;
- allow something a list blocks by mistake while you report it.

**Making one:**
- In the **query log**, press **Why?** on a query and use **Make a quick rule**. The site is filled in, and so is who it's for (see below): the device TelltaleDNS recognizes at the address; when it recognizes none, a device you named that the log names, but only if its own IP (or network) holds the address or its MAC address could be this one (when TelltaleDNS knows the address's MAC, the device's MAC must be that one, and a device known only by a client ID is never taken this way); otherwise the address itself. Where TelltaleDNS can tell, a name that merely matches what a router calls another device doesn't count. For a Kubernetes workload the rule starts for its group, as it is now, only when an operator placed the workload in one (a pod or namespace label, or a rule: the form says which); a workload that falls to its network's group or `default` starts from the pod's address instead, because a rule for that group would cover every device in it. Put the workload in a group first (click its name, then **Add to group…**) to make a rule for all its pods.
- On the **Quick rules** page (Filtering & DNS), which also lists what's in effect with a countdown, who made each rule, and Edit and Remove buttons.

**Who a rule can be for:**
- a **named device** (a `[[client]]`, or one you named with **Name this device…**), by its name in any case;
- an **IP address**, or a **network** such as `192.168.1.0/24`;
- a **group**, or everyone.

The name the query log shows for a device nobody named here (for example `LGwebOSTV`) is what your router's DHCP or the device itself over mDNS calls it. It's good for recognizing the device, but it isn't a device TelltaleDNS knows, so a rule can't be for it: the form fills in the address and shows that name beside it ("shown in the log as …"), and the API refuses it (422) with a hint that names the address, or, when that address is a device you named, says to use its name. A MAC address typed as the device gets words of its own: name the device with that MAC in its `match` list, then use the name. Whether a rule is accepted never depends on a node's own router or mDNS tables, so every node gives the same answer; only the hint reads them (an agent token without `querylog:read` gets the plain hint, also from a replica that forwards the change to the primary; during a rolling upgrade an older node shows the plain hint to everyone).

A rule for an address stops matching when the address changes (a new lease, a phone's private Wi-Fi address). Two ways to keep it:
- give the device a fixed address in your router (a DHCP reservation);
- **name the device** (click its address, then **Name this device…**) and make the rule for the name. Naming recognizes the device by the address it has now, so the name alone doesn't survive an address change, unless you name it by its MAC address, which follows the device when your router or the neighbor table sees it (**Name this device…** offers it when it knows the MAC: see [Naming devices in the UI](#naming-devices-in-the-ui)). What the name saves otherwise is the rules: change the device's `match` list once (in the config file, or `PUT /api/v1/clients/{name}`) instead of every rule. A device recognized by its MAC address (`match = ["aa:bb:cc:dd:ee:ff"]`) keeps its rules when its address changes, where TelltaleDNS can see MAC addresses (see **How a query's device is recognized** under Groups and devices).

In the **Why?** drawer, when the form holds an address and your router reports one MAC address for it (this node's router, or another full cluster member's), the form says so: name the device by its MAC address to make rules follow it. Its **Name this device…** opens the naming dialog with that MAC chosen, and once the device is named, the rule is for its name. There's no such hint for a MAC only this server's neighbor table holds (other servers, and a node in Docker or Kubernetes, don't see it), for a MAC reported at more than one address, or where the MAC isn't shown (query-log privacy level 2 and above).

**Changing one:** press **Edit** on the rule. The form opens filled in, with the same preview as for a new rule, and **Save changes** replaces the rule under the same ID, so it applies on the next query. The rule keeps who made it and when (the audit log records who changed it, with the rule before and after). The end time stays as it was (**Keep the current end**) unless you pick a new duration, which counts from now. There is no Edit for rules in a config file (change the file), or for a rule made through the API for several devices or groups (use `PUT /api/v1/rules/{id}`).

**How they decide:**
- Quick rules decide **before any list**, on the next query. The lists aren't recompiled.
- When several match, a rule for the **device** beats a rule for its **group**, which beats a rule for **everyone**.
- Within one of those, the more specific site wins (`docs.example.com` over `example.com`), then allow over block.
- They also decide CNAME targets, so blocking `videos.example` catches a name that's a CNAME to it.
- A group whose blocking is paused gets no blocks from quick rules either.

**Expiry and history:**
- A rule with an end time stops applying at that moment on every node, by each node's clock (the Cluster page flags clock drift).
- Within seconds it's removed, and the audit log records `rule.expire`.
- The query log shows decisions as **quick allow** or **quick block**, with the rule's note.

**Limits** (DNS can only do so much):
- DNS sees **sites, not pages**: blocking a page means blocking its whole site.
- An app often uses many sites, some shared with other apps. Unblocking one game server is precise; blocking a whole app is best done with a list.
- A rule follows a device only as well as TelltaleDNS **recognizes** it. Name the device by its MAC address (it follows the device where your router or the neighbor table reports the MAC), give it a fixed address (a DHCP reservation), or turn off its private Wi-Fi address for your network.
- Devices keep answers they already have for a few minutes, so a change can take that long to show on the device. Unblocking needs no cache flush, because blocked answers are never cached here.
- **Mobile data, a VPN, or a hard-coded DNS server** go around TelltaleDNS. To close that, have your router block outgoing DNS (ports 53 and 853) to anything but TelltaleDNS.

Quick rules aren't parental controls: there's no screen time and no content categories.

In a config file (useful with GitOps), `[[rule]]` takes the same fields. The API can't remove these rules.
```toml
[[rule]]
id = "kids-videos"
action = "block"                 # or "allow"
domain = "videos.example.com"    # and its subdomains
groups = ["kids"]                # or devices = ["Mom phone", "192.168.1.40"]; neither = everyone
expires = "2026-10-06T07:00:00Z" # optional (RFC 3339)
note = "school night"
```
Through the API (operators, or agent tokens with `config:write:rules`):
```sh
curl -X PUT https://dns.example.com/api/v1/rules/mom-game \
  -H "authorization: Bearer $TOKEN" -H "content-type: application/json" \
  -d '{"action": "allow", "domain": "game.example.com", "devices": ["Mom phone"], "forMinutes": 120, "note": "Mom'"'"'s game"}'
curl https://dns.example.com/api/v1/rules -H "authorization: Bearer $TOKEN"   # what's in effect
```
`?dryRun=true` shows what would change and how many recent queries it affects. `DELETE /api/v1/rules/{id}` removes a rule.

## Why was it blocked? (explain)
`telltale explain` shows what happens to a name for a given device, and why. It lists:
- who the device is recognized as, and its groups;
- every rule in every list that matches, with its file line, in precedence order;
- which rule decides;
- where the query would be forwarded.

It follows the same steps as the server, in the same order: access checks, local records and authoritative zones, quick rules, a schedule that blocks everything for the group, list `$dnsrewrite` rules (which win over blocking), the lists, then the group's `[[group.rewrite]]` entries and safe search. When one of the later steps answers the query instead of a list, the outcome and summary say which.

```sh
telltale explain ad.doubleclick.net --client 192.168.1.50 -c telltale.toml
# ad.doubleclick.net A from 192.168.1.50
# client   tablet (identified by ip); groups: kids
# outcome  ALLOWED: allowed by list family-allow; resolved normally
# rules    snapshot 1, in precedence order (* decides, - list not used by this client, ~ shadow list: counted, never blocks)
#   * allow  family-allow         doubleclick.net (and subdomains)
#              family-allow:1  @@||doubleclick.net^
#   - block  stevenblack          ad.doubleclick.net (and subdomains)
#              stevenblack:7102  0.0.0.0 ad.doubleclick.net
# route    upstream group default (default)
```
- Options: `-t AAAA` for another query type, `--mac aa:bb:cc:dd:ee:ff` or `--client-id` to explain for a device recognized that way, and `--json` for the same data as JSON (the format the API's `GET /api/v1/explain` returns).
- **Recognized by a MAC address:** `identified by` says how: `neighbor_mac` (a MAC the kernel's neighbor table, or `--mac`, gave) or `router_mac` (a MAC a router reported, this node's or another full member's). The API's `GET /api/v1/explain` also says where the MAC comes from, in `client.macFrom`: `given` (the request's), `neighbor`, `router` or `peer`. `client.mac` and `client.macFrom` are shown only to a caller who may read the devices (a person signed in with a session or an API token of any role, or an agent token with `config:read` that isn't restricted to a group; a display session isn't one), unless the caller gave the MAC, and not at query-log privacy level 2 and above (another reason the MAC can be missing: the caller may not read the devices there, or the node's level hides clients). The command line reads the kernel's neighbor table only, and has no router lists: for a device a router recognizes, ask the server (`GET /api/v1/explain`, or the UI's Explain).
- `GET /api/v1/clients/{address}/identity` (and the agent tool `identify_device`) says how an address is recognized now, in `recognition`: the device, how, and the MAC a device at that address could be named by (`mac`, `macFrom`, `macShared`, `macRandomized`). The MAC is shown only to a caller who may read the devices (the same rule as for explain), `macShared` is true when a router reports the MAC at more than one address or the node's own neighbor table holds it at more than one, and `recognition` is left out at query-log privacy level 2 and above. `macRandomized` (a made-up Wi-Fi address) is shown with `device` and `identifiedBy` to every caller who may read identities, including one who may not read MACs: one bit that names no device and no MAC.
- `-` marks rules from lists the device's groups don't use, so you can see what another group would get. `!` after `allow`/`block` marks `$important` rules.
- It reads the config and the data directory (the newest compiled snapshot and the stored lists), so it works whether or not the server is running. A server that hasn't loaded the newest snapshot yet may still be using the previous one.
- Line numbers come from the stored copy of each list. If a list was downloaded again after the snapshot was compiled, the output says so.
- Explain covers the query name only. CNAME targets in an upstream answer are checked too when the server answers (see [Blocking](#blocking)); explain a target name to see its rules.

## Trying a change against yesterday's traffic
Explain answers for one name. A simulation answers for a whole change: before you save it, the queries already in the query log are decided again with the change and without it, and only the differences are reported.

- **In the UI:** the quick-rule form, the device drawer ("Add to group…"), and the checked preview of a list, group, upstream, or schedule have a **What would this have done?** button. It shows four counts (newly blocked, newly allowed, a changed route, a changed answer), the names behind each with the list or rule that decided, and the devices and groups. A name links to the query log. Nothing is saved until you save the change.
- **Any dry run:** add `simulate` to a change's `?dryRun=true`. The value is a window, or `true` for the default one. The response gains `simulation`:
  ```sh
  curl -X PUT 'https://dns.example.com/api/v1/rules/kids-tiktok?dryRun=true&simulate=24h' \
    -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
    -d '{"action":"block","domain":"tiktok.com","groups":["kids"]}'
  # "simulation": {"rows": 183204, "newlyBlocked": {"queries": 412, "devices": 2,
  #   "topNames": [{"name": "www.tiktok.com", "queries": 300, "devices": 2, "list": "quick rule: tiktok.com"}]}, ...}
  ```
  The window ends now, including the second the request arrives in, so a query logged a moment ago is replayed. `simulateUntil` moves the end back (`-24h`, or an RFC 3339 time); `now` is the same as leaving it out. A change that can't affect an answer, such as an alert rule or the exclusions, answers `"applicable": false` instead of replaying anything.
- **A whole configuration:** `POST /api/v1/simulate` takes the shared sections as JSON, the way a Git commit's TOML becomes. `telltale config simulate` reads the TOML for you, so you can test a commit before pushing it:
  ```sh
  TELLTALE_TOKEN=... telltale config simulate shared.toml --window 24h --url https://dns.example.com:8053
  # 183204 logged queries from 2026-10-08T12:00:00.000Z to 2026-10-09T12:00:00.000Z
  #                  QUERIES  DEVICES
  # newly blocked    412      2
  # ...
  ```
  Node-local sections in the file are ignored.

How it works, and its limits:
- **Only the change is compiled.** The running filter is reused. Lists the change adds or edits are compiled on the side, in a temporary snapshot that is removed afterwards, and their matches are merged with the running ones by the usual precedence. A list being removed simply stops taking part.
- **What is decided again:** who may query, local records and zones, quick rules (at each query's own time), schedules (likewise), list rewrites, the lists, the AAAA filter, group rewrites and safe search, and the upstream group a query would go to. Rate-limited, malformed, and dropped queries never reached those steps and count as unchanged. A pause of blocking isn't replayed: both sides are decided as if nothing were paused.
- **Devices** are recognized again by address. A device that was recognized by its MAC address or client ID when it asked keeps the group its queries were logged with, and the result notes it. A quick rule for a device named only by its MAC address (no address among its keys) isn't counted for it, because the log holds the address a query came from, not the MAC the device was recognized by.
- **Bounds:** one simulation runs at a time per node (a second one gets `409 simulation_busy`, retry in a few seconds). Each node reads at most `[simulate] max_rows` queries, newest first, for at most `max_secs` seconds, at background priority; past either bound the answer says `partial`. The window is at most 7 days.
- **Clusters:** every node replays its own log, and a controller also replays the logs its resolver pods ship to it. The counts are added up, and a node that didn't answer is listed in `missingNodes`.
- **Local files:** a simulation run by someone who isn't an administrator can name only the local files (a list's `path`, a zone's `file`, `[local] hosts_files`, an upstream's `tls_ca`, `tls_client_cert` and `tls_client_key`) and plugin upstreams that the configuration in effect already names. Anything else is refused before it's read: `POST /api/v1/simulate` answers 422 naming the field, and a dry run's simulation answers `"available": false, "reason": "local_file"` (the dry run itself is unchanged). An administrator's simulation is unchanged (ADR-180).
- **Downloads follow this node's rules:** a list the candidate adds or changes is fetched and compiled with this node's `[filter]` settings for link-local addresses, size, time, `compile_memory` and `max_regexes` (a candidate's `[filter]` applies only after a restart), and a list's own `max_bytes` can't go past what this node allows for that list now. One simulation reads at most 4 added or changed lists by URL or from a file, whose size limits add up to no more than 4 times this node's `max_list_bytes` (the default `fetch_concurrency` is 4, so it holds no more list text than the node's own refresh does). Past that, `POST /api/v1/simulate` answers 422 naming the limit and a dry run's simulation answers `"available": false, "reason": "download_limit"`, before anything is fetched: simulate fewer list changes at a time. The one-at-a-time bound covers the downloads too. That holds for every caller (ADR-180).
- **Privacy:** at query-log privacy level 1 names are stored hashed, so a change that depends on names can't be replayed (`"available": false, "reason": "privacy_level"`). Moving a device between groups still can: its queries count as unchanged when the new groups decide alike, else as undetermined. At level 2 and above nothing can be replayed.
- DNS answering never waits for a simulation, and a simulation never asks an upstream or touches the cache. It's about decisions: it can't count names nobody asked, and it doesn't predict latency or what an upstream would answer.

Settings: `[simulate]` (Settings → Query handling → Change simulation in the UI): `enabled`, `plans_by_default` (agents' plans simulate even when they don't ask, see [Plans and approval](#plans-and-approval)), `max_secs` (1 to 300, default 20), `max_rows` (at least 1,000, default 2,000,000), and `default_window` (default `24h`, at most `7d`). Metrics: `telltale_simulations_total{outcome}`, `telltale_simulation_duration_seconds`, `telltale_simulation_rows_total`.

## Who can query, and how often
```toml
[access]
# Default: private ranges, CGNAT/Tailscale (100.64/10), link-local, loopback. Everyone else: REFUSED.
allowed_networks = ["192.168.0.0/16", "fd00::/8", "127.0.0.0/8"]

[ratelimit]
queries = 1000          # per client per window (bursts allowed up to this)
window_secs = 60
action = "refused"      # or "drop"
exempt = ["127.0.0.0/8", "::1/128"]
ipv6_prefix = 64        # a device's rotating IPv6 privacy addresses share one budget
```
TelltaleDNS is never an open resolver by default. If you widen `allowed_networks` to everything, a warning is logged at startup.

Zone transfer requests (AXFR, IXFR) are answered `REFUSED` (with the extended error "Not Supported") and never forwarded: TelltaleDNS serves no zones to transfer. An old DNS server still trying to sync a zone through TelltaleDNS shows in the query log as `TYPE252` or `TYPE251`, status special.

`[ratelimit]` applies on reload, with no restart. The default of 1,000 queries a minute per address suits homes where each device has its own address. A router or proxy that forwards for a whole network shows up as one address, and would be refused above about 17 queries a second: add it to `exempt`, or raise `queries`.

- **Adjust it in the UI:** **Settings → Query handling → Rate limit** shows the limit in effect (from the config file, or changed here) and edits it: queries per window, the window, what a limited client gets (`refused` or `drop`), the addresses never limited, and in the Advanced view how clients are grouped (`ipv4_prefix`, `ipv6_prefix`). **Check** shows what the change does first. **Revert to the file** goes back to `[ratelimit]` in the configuration. A change replaces the whole section, so fields left out take the defaults, not the file's values, and the list of exempt addresses is replaced too (keep `127.0.0.0/8` and `::1/128`).
- **Through the API:** `PUT /api/v1/ratelimit/default` with the same fields as `[ratelimit]` (add `?dryRun=true` to preview), and `DELETE` to revert; `GET /api/v1/config/entries?kind=ratelimit` shows the limit in effect and its source. Agents need `config:write:ratelimit`, and AI agents can plan a change with the MCP tool `plan_set_ratelimit`. On a node whose configuration comes from Git, the response says what to add to the repository.

### The advertised UDP size
```toml
[dns]
edns_payload = 1232     # 512 to 4096; needs a restart
```
This is the UDP payload size announced in EDNS(0) answers (RFC 6891), and the largest UDP answer sent to a client that announces at least as much; bigger answers are cut and flagged truncated, and the client retries over TCP. 1232 is the DNS Flag Day 2020 value and avoids IP fragmentation on almost every path. Raise it only on a network known to carry larger datagrams (jumbo frames, an IPv6-only network that doesn't fragment). The ceiling is 4096, the size of the UDP workers' send buffer.

### Which node answered (NSID)
```toml
[dns]
nsid = true
```
Answers carry this node's name in the NSID option (RFC 5001) when a query asks for it, so you can tell which node or pod answered when several share one address (a load balancer, resolver pods):
```
$ dig +nsid example.com @192.168.5.112
; NSID: 74 65 6c 6c 74 61 6c 65 64 6e 73 2d 72 65 73 6f 6c 76 65 72 ... ("telltaledns-resolver-786d9bf5df-c6pr8")
```
- The name is `[node] name`, or the host name (a pod's name in Kubernetes). It's added only to answers whose query asked for NSID; others are unchanged.
- Off by default: any client allowed to query sees the name. In a cluster, `[dns]` is shared, so one setting turns it on everywhere, and each node answers with its own name.

## Special names
Handled before anything else (each can be turned off under `[special]`):

| Name | Answer | Why |
|---|---|---|
| `localhost`, `*.localhost` | 127.0.0.1 / ::1 | RFC 6761 |
| `*.invalid` | NXDOMAIN | RFC 6761 |
| `use-application-dns.net` | NXDOMAIN | stops Firefox from silently switching to its own DoH (`block_firefox_canary`) |
| CHAOS class (`version.bind`, …) | REFUSED | no fingerprinting (`refuse_chaos`) |
| reverse lookups for private IPs | NXDOMAIN | your LAN layout stays off public resolvers unless a local record, a `[[route]]` or the device's group's own `upstreams` covers it (`private_ptr_nxdomain`) |
| `resolver.arpa`, `_dns.resolver.arpa`, … | NOERROR, no records | encrypted-DNS discovery (RFC 9462): answered here, never forwarded, unless a local record or a `[[route]]` for `resolver.arpa` or a name below it covers it (`resolver_arpa`) |

`.local` names are passed through unchanged (many Active Directory domains use them; route them with `[[route]]`).

`_dns.resolver.arpa` is the name a device asks to find an encrypted resolver (DDR). RFC 9462 says a resolver answers it itself, so TelltaleDNS doesn't pass it to your upstreams: their own answer, about their own encrypted endpoints, can't be validated (`[dnssec] mode = "validate"` would answer SERVFAIL). The answer says there's no encrypted endpoint to discover, and the device keeps asking TelltaleDNS as before. TelltaleDNS doesn't advertise encrypted endpoints of its own there yet.
- **To forward it anyway** (to your own DDR responder, say), add a `[[route]]` whose `match_suffix` is `resolver.arpa` (or `_dns.resolver.arpa`). Add `match_group` to forward it only for that group's devices. No other route forwards it: a route for `arpa` (every reverse lookup to your router, say) or for `.`, a group's own `upstreams`, and a `match_group` or `match_qtype` route without a suffix send their devices' other names to their upstream group, and `_dns.resolver.arpa` is still answered here, so your router's or its provider's discovery record doesn't reach your devices.
- **`[special] resolver_arpa`** (default `true`) turns this off: the name is forwarded again. It's shared by the cluster and applies without a restart. Don't write the key into a node's own file, `true` or `false`, until every node is upgraded: an older build refuses any `[special]` key it doesn't know, so it won't start with `resolver_arpa` in its file, and an older replica refuses a shared configuration that has it (`shared configuration: unknown field …`; it keeps serving the last one it had). What the primary shares has the key only when it's `false`, so at the default older nodes aren't affected.

## Routing (conditional forwarding)
```toml
[[upstream]]
name = "home-router"
url = "udp://192.168.1.1"

[[upstream_group]]
name = "lan"
members = ["home-router"]

[[route]]
match_suffix = ["home.arpa", "168.192.in-addr.arpa"]   # local names and reverse lookups
upstream_group = "lan"
```
The longest matching suffix wins; routes can also match `match_qtype = ["PTR"]`.

### Stub zones (the zone's own servers)
Forwarding asks a server to look the name up for you (recursion desired). A zone's own
**authoritative** servers won't: they answer only for their zones, refuse everything else,
and hand delegated sub-domains to other servers with a referral that a forwarder can't
follow. For those, make the domain a **stub zone** (BIND's `static-stub`, Unbound's
`stub-zone`): TelltaleDNS resolves names under it itself, starting at the zone's servers
instead of the root, and follows their delegations.
```toml
[[upstream]]
name = "corp-stub"
url = "recursive://"
[upstream.recursive]
stub_zone = "corp.example"
stub_servers = ["10.0.0.53", "10.0.0.54"]   # IP addresses, port 53

[[upstream_group]]
name = "corp"
members = ["corp-stub"]

[[route]]
match_suffix = ["corp.example"]
upstream_group = "corp"
dnssec_nta = true             # internal zones are usually unsigned
```
- **The configured servers win**, whatever the public delegation for the zone says, so an
  internal view (split horizon) is what clients get. They're asked without recursion, the
  fastest first, and a slow one is hedged.
- **Delegations are followed:** a sub-domain the servers delegate (`branch.corp.example` to
  `10.1.0.53`) is asked of its own servers, with the same bailiwick and glue checks as
  `recursive://`.
- **Names outside the zone** that an answer leads to (a CNAME to a cloud service, a server
  name in another domain) are resolved from the root servers, like `recursive://`. The root
  never sees the stub zone's own names.
- **Health checks** ask the stub's servers for the zone's SOA rather than the root's NS
  (which authoritative servers refuse, so a plain forward to them gets benched), and any
  answer except SERVFAIL counts as up, even REFUSED from servers that host only zones below
  it (a server that says it is failing for its own zone isn't up). A name under a delegated
  server that fails is a failed lookup, like with `recursive://`.
- From the UI: **Names on my network → Send a domain to another server**, and tick **These
  servers only know this domain**. Through the API:
  `PUT /api/v1/forwards/corp.example` with `{"servers": ["10.0.0.53"], "stub": true}`
  (agents: `plan_forward_domain` with `stub: true`).
- Unlike BIND's `type stub`, the zone's NS set isn't fetched from the servers: they're used
  as listed (`static-stub`). List every server you want asked.

## A warm cache after restarts
With `[cache] persist = true`, TelltaleDNS writes its cache to `<data_dir>/cache.bin` when it
stops, and reloads it when it starts. Upgrades and restarts then start with a warm cache
instead of a cold one.
- Only answers that can still be served come back (fresh, or within the serve-stale
  window), and the time spent down counts against them.
- A dump taken under different upstreams or routes isn't loaded, so an answer never reaches
  a client through the wrong upstream group.
- The file is owner-only, since it shows what was looked up. It's removed once loaded, so a
  crash never reloads old data.

**In a cluster**, a node that starts with an empty cache (a new resolver pod, a replica
after a restart) also asks the other nodes for their most-queried names, this hour and the
last, and resolves them in the background (20 a second, A and AAAA), so its first clients
find them cached. `[cache] warm_names = 300` sets how many; `0` turns it off.

## Cache tools
The **Cache** page (under System) shows each node's cache. In a cluster that's one card per
node; Kubernetes pods are told apart by pod name.
- **Per node:** the hit rate over the last hour and since start. How many answers it holds,
  and how much of its memory budget that uses. The last hour's lookups, prefetches, stale
  answers served, and evictions. Whether it started warm (how many answers it reloaded from
  the dump, or why it didn't). The `[cache]` settings in effect.
- **Charts:** the hit rate and the lookups per 15 s over the last hour, one line per node. A
  pod that just started shows a low hit rate while its cache fills.
- **What's cached:** what each cache holds by kind (answers, names that don't exist, no data,
  SERVFAIL, stale answers kept for serving stale, DNSSEC-validated), and its top 25 entries
  by hits, size, or nearest expiry. These walk the whole cache (a few milliseconds per 100,000
  entries, one shard at a time, off the query path), so they load when you open the page or
  press **Refresh**, not every few seconds. Select a name to look it up.
- The query log's **Why?** drawer has the same lookup for the name you clicked.

Each node samples its cache counters every 15 s and keeps an hour of samples (about 15 KiB).
API: `GET /api/v1/cache/stats` (with `settings`, `warmStart`, and `history`) and
`GET /api/v1/cache/entries?sort=hits|bytes|expiring&limit=25&node=`, which needs a viewer or
the agent scope `analytics:read`.
- **Look up** lists every cached answer for exactly that name: the query type (and the
  variants for clients that set DO or CD), the response code, the number of answers, whether
  DNSSEC validated it, how long it stays fresh (or how long it has been stale), and its hits.
  Looking doesn't count as a hit.
- **Flush this name** removes it; tick *and everything under it* to flush a whole subtree
  (`example.com` takes `www.example.com` with it). **Flush everything…** empties the cache
  after a confirmation. Flushing needs the operator role and is audit-logged as `cache.flush`.
- In a cluster, each node has its own cache. Stats and lookups show one row per node, and a
  flush applies to every node unless you pick one. A node that can't be reached is listed with
  the error, and the others still flush.
- Flushing doesn't clear devices' own caches; a phone or browser may keep the old answer for a
  few minutes. Blocked answers are never cached, so unblocking needs no flush. To change what a
  name resolves to, use a local record instead.

API: `GET /api/v1/cache/stats`, `GET /api/v1/cache/lookup?name=`, and
`POST /api/v1/cache/flush` with `{"name": "example.com", "subtree": true, "node": "pi"}` (every
field optional; an empty body empties every node's cache). Agents need `analytics:read` to
look and `ops:cache` to flush.

### Is the cache the right size?
Each node's card on the Cache page has a **Size** line: whether a bigger cache would answer
noticeably more lookups from memory, or a smaller one would do.
- **How it's estimated:** the cache follows a fixed sample of names (1 in 16) after they're
  evicted. When one of them is asked again while its answer would still have been fresh, the
  number of evictions in between says how much bigger the cache needed to be to still hold it.
  That gives the extra hits a cache 25%, 50%, and 100% larger would have had (the sample's count
  times 16). This is the SHARDS technique: a uniform sample of names keeps their reuse distances
  exact, so the estimate is good with a small fraction of the memory. It runs when an answer is
  stored or evicted, never on a lookup, and needs about 3 bytes per cached answer.
- **The verdict:** *could grow* when a size 25%, 50%, or 100% larger would have answered at least
  1% more lookups from memory (the smallest such size is suggested, with the `max_bytes` to set);
  *could shrink* when, after 100,000 lookups, nothing was ever evicted and the cache never held
  half its budget (it suggests the peak plus half, at least 4 MiB); *right size* otherwise;
  *learning* before 10,000 lookups.
- Since start: a restart starts the estimate over. In a cluster each node judges its own cache.
- `GET /api/v1/cache/stats` has it as `sizing`, the MCP tool `cache_advice` reads it, and
  `/metrics` has `telltale_cache_ghost_hits_total{size="1.25x"|"1.5x"|"2x"}` (estimated, cumulative)
  and `telltale_cache_peak_bytes`.

## DNSSEC validation
TelltaleDNS can check DNSSEC signatures on forwarded answers itself, instead of trusting the
upstream:
```toml
[dnssec]
mode = "validate"            # off (default) | validate | permissive
negative_trust_anchors = ["corp.example"]   # internal zones that aren't signed
```
- **Signed and valid:** the answer carries AD, for clients that ask (DO or AD set).
- **Unsigned:** it's answered as usual, without AD.
- **Signed but broken** (forged, expired, or tampered): SERVFAIL with Extended DNS Error 6
  (DNSSEC Bogus). In `permissive` mode it's answered anyway and only counted, which is
  useful for trying validation out.
- **NXDOMAIN and "no such record"** answers are checked too, using the zone's NSEC or NSEC3
  proofs.
- **Opting out:**
  - a client that sets CD (checking disabled) gets the unvalidated answer;
  - names under a negative trust anchor, or under a route with `dnssec_nta = true`, aren't
    validated. Domains forwarded from the UI's "Send a domain to another server" set that
    automatically.
- **Speed:** it works on cache misses only, and a validated answer is cached with its AD bit.
  The first lookup in a new zone fetches its keys, and a cold start fetches the root's and
  the TLD's; after that they're cached.
- **Counted** in `telltale_dnssec_validation_total{result="secure|insecure|bogus|indeterminate"}`.
  In `permissive` mode each bogus answer is also logged at INFO with its name, type, and
  EDE code (`DNSSEC: bogus answer served (permissive mode)`), so a trial shows which names
  `validate` would refuse.
- **Indeterminate** (validation couldn't finish, such as the validator's depth limit, or an
  answer that doesn't reach its question, below): served without AD, in both modes; when
  validation left nothing to serve, the answer is fetched again without validation.
- **Unsigned zones:** before refusing an answer, TelltaleDNS proves whether its zone is
  simply unsigned, and if so serves it as insecure. The proof is the parent's signed denial
  of the zone's DS, made only of records of the parent zone (or of an unsigned top-level
  domain), which must also show that the name is a delegation: the record at the name lists
  NS and neither SOA nor DS; or, in an NSEC3 Opt-Out zone such as `.com` or `.org`, the
  record of the name's parent (which must not itself be a delegation) and an Opt-Out record
  covering the name. This corrects the validation library's verdict on CNAME chains in
  unsigned zones (`www.netflix.com`, `www.amazon.com`). Names below parked domains whose
  servers answer an SOA for every name (`www.smithsonianmag.org`) were corrected the same
  way; since hickory-net 0.26.4 the library judges them insecure itself. From v0.3.0 to
  v0.7.0 the proof didn't succeed under NSEC3 Opt-Out parents. Proven zones are remembered
  per upstream group, as long as the proof's records' TTL allows and at most 15 minutes
  (ADR-098, ADR-184). A name queried while TelltaleDNS hasn't cached its parent zone's keys
  yet (right after a start, say) can still fail for up to a minute, and works again after
  that minute; and
  a parent zone whose NSEC3 records use more than 100 iterations can't prove its unsigned
  zones.
  The whole validation, proof included, ends within twice the query budget (4 s by default),
  at most 8 proofs run at once, and a name that couldn't be proven isn't tried again for a
  minute: when it can't be proven, the answer stays bogus (or, with no answer at all, stale
  or SERVFAIL as for any upstream failure).
- **Memory:** each upstream group's validation cache keeps at most 8,192 record-set proofs,
  about 13 MiB at most; the least recently used go first (ADR-196). A record set validated
  again while its proof is still kept costs no key lookups.
- **Denials behind a CNAME:** the validation library checks a "no such record" or "no such
  name" proof against the name that was asked, but after a CNAME the proof is about the chain's
  last name (`www.paypal.com AAAA`). Before refusing such an answer, TelltaleDNS validates it
  one link at a time, each as a question of its own (the CNAME at each name, then the question
  at its target), and serves only what those answers validate, with the weakest link's verdict:
  secure (with AD), or insecure when a link is in a zone proven unsigned as above
  (`c.pki.goog`). This only looks at answers the library refused or found bogus (also those
  the wildcard check below marks bogus), on cache misses, in both modes: at most 8 links, 4 such
  validations at once, within the same deadline. A link that doesn't validate, or gets no
  answer in time, leaves the answer bogus, and that question isn't validated this way again
  for a minute (ADR-188).
- **Answers that reach their question:** an answer with records is secure only when it holds
  the asked type at the name, or at the end of its CNAME chain, or a signed proof that that
  name has none (for a CNAME, DS or ANY question: a CNAME, a DS or CNAME, or any record at the
  name); otherwise it's served as it came, without AD, counted as indeterminate, and kept 300 s
  at most (its answer records' TTLs are lowered to 300 s; `[cache] min_ttl` above that, or
  serving stale answers, can keep it longer), in both modes. When validating link by link, a
  last link that holds neither leaves the answer bogus (ADR-195).
- **Wildcard answers:** every wildcard answer in a zone signed with NSEC is checked against
  RFC 4035 §5.3.4 before it is served: the zone's signed NSEC must show that no closer name
  exists, otherwise the answer is bogus and handled as any bogus answer (the unsigned-zone
  proof, then link by link when it starts with a CNAME). So an answer from a wildcard right
  above the name validates (`nasa-gov.go-vip.net A`, and `www.nasa.gov A` through its CNAME),
  and so does a wildcard CNAME further down whose chain ends in an answer, in one lookup (a
  NODATA behind one is validated link by link). An answer with a second signature
  that isn't verified (during a key or algorithm rollover) is served without AD, as elsewhere.
  The check reads only the answer itself, on cache misses, in both modes. Zones signed with
  NSEC3 are left to the validation library: the check is skipped only beside a verified NSEC3
  record of the zone that signed the answer (ADR-188). In every zone, an answer with a record
  of another name made from a wildcard is validated link by link, each name for its own
  question; in a zone signed with NSEC3, a wildcard's record set at the name needs the zone's
  NSEC3 record covering its own next closer name, otherwise the answer is bogus (ADR-195).
- **Before switching to `validate`:** run `permissive` for a while and read the log; only
  names that are really broken (like `dnssec-failed.org`) should show up.
- **Non-existent names answered locally** (RFC 8198, `aggressive_nsec`, on by default): a validated "no such name" from a zone signed with NSEC proves a whole range of names absent. A later question inside a proven range is answered from it: NXDOMAIN (or NODATA for a missing type), signed, with AD, and without asking upstream. A typical win is a home network's stray queries for made-up top-level names (`printer.lan`, `wpad.home`), which the root zone's NSEC records cover. Only proofs that validated as secure are used, only for as long as their TTL and the zone's negative TTL allow, and never below a delegation. Zones signed with NSEC3 (hashed names) still ask upstream. Counted in `telltale_dnssec_synthesized_total`; `[dnssec] aggressive_nsec = false` turns it off.
- **Why it failed:** a bogus answer's SERVFAIL says why when its signatures show it: EDE 7 (signature expired), 8 (signature not yet valid), 10 (signatures missing), else 6. A clock that's far off shows up as 7 or 8 everywhere, which is worth checking first.
- **Trust anchors:** the root's 2017 and 2024 keys are built in, so the root key rollover needs nothing from you. To use other anchors (a future key before TelltaleDNS is updated, or a test root), give a file of DNSKEY records in zone-file form, as `dig DNSKEY . +noall +answer` prints them or Unbound's `root.key` holds:
  ```toml
  [dnssec]
  mode = "validate"
  trust_anchors_file = "/etc/telltale/root.key"
  ```
  It replaces the built-in anchors; a file that can't be read or holds no key is logged and the built-in anchors stay. Automatic tracking of key changes (RFC 5011) isn't done (ADR-086).

## Clusters

Nodes can form a cluster: the first node creates it and holds the cluster's certificate
authority (it's the **primary**); others join with a token and then keep an encrypted,
mutually authenticated link (mTLS over HTTP/2) to it. **The primary's configuration and
blocklists reach every node within seconds.** Failover is manual, or automatic with a third
voter such as a small witness (below), and **every node's
dashboard and query log show the whole cluster**. Changes made in any node's UI or API go to
the primary. DNS never depends on the cluster: a node answers the same whether its peers are
up or not.

**Finding the primary.** A node dials the addresses it joined with and the ones the primary
advertises; if none answers, it attaches to another eligible node, so it still gets the
cluster's state. While it is attached to a node that isn't the primary, it looks for the
primary again every 2 to 30 seconds (jittered, backing off) and moves back as soon as it
answers, with `cluster: the primary answers again` in the log. It never moves to an address
of a node it knows is not the primary. Only the node's own link counts: the primary also opens
links to eligible nodes, and one of those doesn't stop the search. Configuration and blocklist
files always come from the primary (another replica has none to give), over the node's own
link when that's to the primary, else from the primary's addresses directly. Each time the
link comes up the log says where: `cluster: linked to a peer` with its URL and node ID.
Once it has moved back, the two replicas drop each other from their peer lists within about
18 seconds: a replica keeps a silent peer it has no stream to only if it expects to hear from
it, the primary (the node that said so when its stream opened, or the one named by the last
version the replica applied, which covers a node promoted since) and, under automatic failover,
the other voters. So a link like this one doesn't leave `TelltaleDNSClusterPeerDown` firing. A
replica that is really down is reported by the primary.

This is true of the Prometheus metrics and the peers in `/api/v1/system/info`. The Cluster
page, `/api/v1/health` and the in-app node-down alert also list the nodes the cluster registry
has and this node has no entry for, as down with no link.
On a replica that includes the other replica once it has been forgotten, as it already does for
a replica that never had a stream to it. The link-less row appears after the node you're on has
been up for about a minute and a half.

**One view of the whole cluster.** Open any node's UI and the dashboard, top lists, latency,
groups, query log, and live query stream cover every node:
- The node you're on asks its peers over the cluster link and merges what they send:
  - counts add up;
  - top lists merge their counts and error bounds;
  - latency percentiles are exact: the nodes send their latency histograms, and the merged
    histogram gives the percentiles (a node on an older version sends percentiles, which are
    weighted by its query count instead);
  - query-log rows interleave by time, and each row shows the node that answered it.
- A node that doesn't answer within 2 seconds is left out, and the page says so ("Partial
  results: pi didn't answer"). It never hangs. The API lists those nodes in `missingNodes`.
  A witness (see automatic failover, below) holds no data, so it is never asked and never
  listed.
- Other nodes are asked about a range of time up to a limit: a request for more than 256
  windows of 240 buckets a node (over 17 hours of seconds, 42 days of minutes, or 7 years of
  hours) is answered from this node alone, with the other nodes in `missingNodes`. Every range
  the API documents (15 minutes of seconds, 7 days of minutes, 400 days of hours, and every
  day) is well under it. Reads that ask many nodes about many windows are limited by count as
  well: one read makes at most 4,096 calls (a node and a window of time is one call, so all of
  history by the day is 87 calls a node, and a cluster of 48 nodes, this one and 47 others, can
  ask for it whole; the range gains a window every 240 days, and the number of nodes is 4,096
  divided by the windows, rounded down, plus this node, so it falls by one every one or two
  windows), and all the reads together have at most 32,768 calls running or holding an answer
  their read hasn't taken yet. They are limited in bytes too: the answers the other nodes send to
  one read can be at most 20 MiB, and the answers all reads hold 40 MiB. An answer that would
  pass that is dropped as it arrives, and its node is listed in `missingNodes` as one that didn't
  answer; the rest of the read is kept. On a cluster of 3 or more nodes that happens to the API's
  longest ranges (7 days of minutes or 400 days of hours, about 15 MiB of answers from each other
  node). The dashboard at 48 hours makes two minute reads on each refresh (the summary and the
  chart), each up to 2,881 buckets from every other node; a refresh stays whole while those
  buckets average under about 3.6 KB each as JSON on 3 nodes, 2.4 KB on 4 or 1.8 KB on 5 (a
  4-node home cluster measured 0.5 to 0.9 KB, about 1.8 MiB a read), and comes back partial
  above that. Two viewers refreshing at the same moment share the 40 MiB, so one of them can see
  a partial refresh, which the next poll heals. The limit is there because reading a range takes
  the node that merges it about 7 times the answers' bytes in resident memory (4 to 6 times in
  heap): on a node with no data of its own, one read at 20 MiB took it to about 185 MiB. It
  bounds the other nodes' answers only, not this node's own part of the read and not reads that
  merge at the same moment, so two such reads, or one on a node with a week of its own minutes in
  big buckets, can still pass the 256 MiB the Pi's service may use. A read over the 4,096 is
  answered from this node alone, with the other nodes in `missingNodes`, every time, and so is
  the part of a read over 20 MiB: narrow the `scope`, or ask for a coarser `step` or a shorter
  range. A read that finds too many reads waiting, the call limit spent, or the 40 MiB held is
  answered the same way, and works again a moment later. In Kubernetes, the controller counts
  each resolver pod as a node. A node that refuses cluster reads, for any of these reasons,
  says so in its log as a warning, once a minute at most, and counts them in
  `telltale_federated_refused_total{reason}` (`waits`, `spent`, `ceiling`, `bytes`).
- `scope` on a stats or query-log request narrows it: `cluster` (the default, every node),
  `site:<name>` (the nodes of one site, e.g. `site:k8s`), `node:<name or ID>` (one node, by
  site, pod, or node ID), or `node:local` (the node you're asking). For example
  `GET /api/v1/stats/summary?scope=site:home-pi`. An unknown site or node is a 400;
  `missingNodes` lists only nodes inside the scope that didn't answer.
- The live query stream follows every node too, about half a second behind for other nodes,
  each row naming its node. The rate cap is shared between the nodes. `scope=node:local`
  watches only the node you're on.
- Settings and Explain are always this node's own.
- Nodes answer each other's reads whether or not their own API is on.

**Keeping a node's query log on another node (ship mode).** A node with little or
wear-sensitive storage, such as a Pi on an SD card or a pod without a volume, can hand its
query log to another node:
```toml
[telemetry]
mode = "ship"
[telemetry.ship]
# to = "k8s"            # a node ID or site; default: the primary
# buffer_bytes = "64MiB" # kept here while the target is unreachable; the oldest goes first
# interval_secs = 300    # how often the log is closed and sent
```
- The node writes its query log as usual, but keeps at most `buffer_bytes`. At least every
  `interval_secs` it closes the current file and sends it to the target over the cluster
  link. Once the target has checked and stored the whole file, the node deletes its copy.
- The target keeps shipped logs under `<data_dir>/qlog-nodes/<node-id>/`, with its own
  retention. Its query-log search includes them, and each row shows the node it came from.
- Every row lives in one place at a time: the sender's buffer until it's delivered, then the
  target. So cluster-wide searches never count a row twice, and recent rows are searchable
  from the sender through the cluster until they're delivered.
- If the target is down, files wait in the buffer and go out when it's back; beyond
  `buffer_bytes` the oldest are dropped. Metrics: `telltale_qlog_ship_pending_segments`,
  `telltale_qlog_ship_errors_total`, and on the target
  `telltale_qlog_received_segments_total`.
- Dashboard counts go too: every `interval_secs` (at most a minute) the node sends its last
  30 minutes of per-minute counts to the target, which keeps them for 7 days. While the node
  answers, the dashboard uses its own numbers; once it's gone (a Kubernetes resolver pod
  replaced in a rollout), the target's copy keeps its traffic in the cluster's history
  instead of the totals dropping. Ranges past 7 days use what each node kept itself.
- To spare an SD card entirely, put the buffer on a RAM disk: the query log lives in
  `<data_dir>/qlog`.

**What's shared and what stays per node.** The primary shares upstreams, routes, local
records, lists, groups, devices, access rules, rate limits, and special names, including
what was added in its UI or API. Each node keeps its own `[node]`, `[[listen]]`, `[cluster]`,
`[api]`, `[auth]`, `[telemetry]`, and `[cache]` from its own config file. So:
- **Change configuration in any node's UI or API.** On a replica, a change to devices, local
  names, or forwarded domains is passed to the primary:
  - the primary applies it, and it reaches every node within seconds;
  - the answer you get is the primary's;
  - the primary's audit log shows who made it and where, e.g. `alice via pi`, and the
    replica's audit log shows it too.
  - `If-Match` uses the primary's configuration version, so it works the same on every node.
  - If the primary can't be reached, the change is refused with 503 and nothing changes; DNS
    keeps answering.
  - Config *files* are different: edit the primary's file. The shared sections of a
    replica's own file are ignored once it has synced.
- **Replicas don't download lists.** The primary compiles them, and replicas fetch only the
  parts that changed.
- **A replica keeps serving what it last received** if the primary is down, including after a
  restart (it starts answering from `<data_dir>/cluster/applied.json` in milliseconds).
- **Every version is signed** by the cluster's key; a replica rejects anything else.
- **Users and tokens are the primary's, everywhere.** Users (passwords, roles, two-factor
  settings, recovery codes) and API and agent tokens are made and changed on the primary, and
  every node takes them within seconds, so you sign in to any node with the same account and a
  token works against any node. Only hashes travel, over the cluster's encrypted channel.
  - On a replica, changing a user, a password, two-factor settings, or a token is refused with
    a pointer to the primary.
  - Sessions stay per node: signing in to a second node is a second sign-in (with SSO, a silent
    redirect).
- **Acknowledged anomalies are the primary's, everywhere** too ([Acknowledging findings](#acknowledging-findings)):
  any node takes an acknowledgement and passes it to the primary, and every node gets the set
  with the next version.
  - Users that exist only on a replica (an admin made before it joined) keep working there. If
    the primary has a user of the same name, the primary's account (and password) takes over on
    every node.
  - A promoted replica becomes the place to manage users, with everything it had synced.
- **Records for one node only:** `node_only = true` on a `[[record]]` keeps it on the node whose
  file has it. The primary doesn't share it, and a replica keeps it next to the cluster's records.
  An example is a name that should only resolve on the Pi:
  ```toml
  [[record]]
  name = "pi.home.arpa"
  type = "A"
  value = "192.168.3.2"
  node_only = true
  ```
- **Upstreams and routes for one node only:** `node_only = true` works the same way on
  `[[upstream]]`, `[[upstream_group]]`, and `[[route]]`, for a server only some nodes can reach.
  The Helm chart marks its route to CoreDNS this way (`kubernetes.enabled`), so a Pi in the
  same cluster doesn't try to reach `cluster.local` it can't get to. Nothing shared may point
  at a node-only entry: a shared group can't list a node-only upstream, and a shared route, a
  client group's `upstreams`, or `upstream_check.reference` can't name a node-only group. If a
  node's own node-only upstream or group has the same name as a shared one, the node's own is
  used.
- **Leftovers in a replica's file:** if its file still sets shared sections (upstreams, lists,
  records, groups…), the primary's replace them. The node logs a warning naming them, and the
  Cluster page's **node_settings** check fails until they're removed.

**When the primary is gone: promote another node (manual failover).**
- **Who can be promoted:** a node joined with `--eligible` using a token made with
  `telltale cluster token create --eligible` (a plain token brings a plain member). The primary
  shares the cluster's signing key with eligible nodes once they connect, so one of them can
  take over. A node that joined with the Helm chart's bootstrap secret (a resolver pod) is
  always an ephemeral member: it can't be eligible or a witness, whatever its settings say.
  Give eligible nodes `--advertise` URLs, so a returning old primary can be reached and told
  to step down.
- **How:** use **Promote this node…** on the Cluster page (admin, live; it asks for your
  password again, and your authenticator code if you use two-factor sign-in), or stop the node,
  run `telltale cluster promote`, and start it. Through the API, a signed-in session sends
  `password` (and `totp`); an API token with admin scope doesn't need them. It's refused while the primary is up, except
  over an emergency primary: a node that can publish (a Git-managed node, under the `gitops`
  authority) may take over from it while it runs.
- **What happens:**
  - the node takes a new *epoch* and continues from the last version it applied;
  - every node follows it;
  - an old primary that comes back steps down by itself when it sees the newer epoch;
  - for changes made in the UI or the API, the version it continues from counts as its config
    files: its devices, local names, forwarded domains and quick rules are read-only there (409),
    and every change is checked against that version plus what the UI stored, and refused with
    the reason when the result wouldn't apply (a renamed device that keeps an address the version
    still gives another device, say). A device stored on this node before (made in the UI while it
    was primary earlier) that the version also has isn't in effect, the version's is:
    `DELETE /api/v1/clients/{name}` removes the stored copy, or rename it to a free name and
    address to keep it as a device of its own.
- **Changes the old primary made in the meantime aren't applied anywhere.** They're listed under
  **Conflicts** on that node's Cluster page, with the settings they touched, so you can make them
  again on the current primary.

**Removing a node.** A node that is gone for good stays in the member list as a down node on the
primary and, under automatic failover, on the other voters (any other replica forgets it within
about 18 seconds, as above, unless it was the primary: a primary that is rebuilt under a new node
ID stays listed as down on a replica until that replica restarts): it counts as a voter in
automatic failover and keeps `TelltaleDNSClusterPeerDown` firing there. This
happens when you rebuild a machine and join it again, because it comes back under a new node
ID. The Cluster page lists such a record as a down node (a record that hasn't connected since
the node you're looking at started appears after about a minute and a half). Remove it:
- **How:** **Remove** on the node's row of the Cluster page (admin), `telltale ctl remove-node
  <node-id>`, or `DELETE /api/v1/cluster/nodes/<node-id>`. Use the node ID the Cluster page
  shows, not the site name. Add `--dry-run` (`?dryRun=true`) to see what would happen first. It
  works from any node (a replica sends it to the primary) and under a Git config authority,
  since the member list isn't configuration.
- **A node that is up** is refused unless you add `--force` (`?force=true`; the page asks you to
  confirm). Its connection is closed, and every node refuses it from then on, even though its
  certificate is still valid for up to 90 days. Stop it and clear its cluster directory before
  it joins again with a new token.
- **The primary can't be removed.** Promote another node first.
- **Voters:** a removed node stops voting. Automatic failover needs three voters, so removing
  one of three turns it into manual until another eligible node or a witness joins; the answer
  says so.
- **The cluster key:** an eligible node holds a copy of it. Removing the node stops the cluster
  accepting it, but if the machine is lost or can't be trusted, also run `telltale cluster
  rotate-ca`. For a record whose machine is gone, there is nothing more to do.

**Upgrading a cluster.** Upgrade one node at a time, **replicas first, then the primary**.
DNS keeps answering throughout if your clients have two DNS servers (each node is one).
- Versions one cluster protocol apart work together (N and N−1, either way round), so a
  half-upgraded cluster is fine.
- The Cluster page's **versions** check lists the mix until the last node is upgraded.
- A replica older than its primary keeps working, unless the primary starts using settings
  the older version doesn't know. Then the replica keeps serving its last version, and its
  sync status says to upgrade it.
- `telltale ctl upgrade` does the native nodes in this order for you, and the Helm chart's
  `upgradeHook` runs it before the pods roll: see
  [Upgrading from the cluster](#upgrading-from-the-cluster).

**Certificates renew themselves.** Each node's cluster certificate lasts 90 days, and a node
renews it when fewer than 30 days remain (checked every 6 hours). It keeps its key and node
ID. Nodes holding the cluster key issue their own; others ask the primary over the cluster
link, which signs only for the node asking. A renewal that fails (for example, with the primary
down) is retried every 10 minutes, and shows in the Cluster page's events and in
`telltale_cluster_cert_expiry_timestamp_seconds`. The certificate check on the Cluster page and the
Helm chart's alert warn below 14 days.

**Rotating the cluster CA.** The cluster CA lasts 10 years. To replace it (a suspected leak of
a node holding the cluster key, or policy), run on the primary while it runs:
```sh
telltale cluster rotate-ca            # start
telltale cluster rotate-ca --status   # phase, and which members it waits for
```
The primary drives three steps, each only when every member is ready, so no link breaks and
DNS keeps answering:
1. Every node trusts the new CA next to the old one (sent in the signed configuration).
   Eligible nodes also get the new key.
2. The new CA signs. Every node renews its certificate from it within a minute, keeping its
   key and node ID.
3. Every certificate is from the new CA, so the old one is retired and its key is deleted.

A member that's away holds the rotation until it's back; the Cluster page shows the rotation
and whom it waits for. Ephemeral members (resolver pods) don't hold it up. A node that's away
for the whole rotation can't connect afterwards and must join again with a token. Join tokens
made before a rotation pin the old CA, so make new ones afterwards.

Trust moves forward only. Each step comes with a new configuration version, and a node takes
the CAs of a version only if it isn't older than the one it last took them from (a new epoch,
after a failover, counts as newer whatever its number). It keeps that version in
`cluster/ca.version`; a file it can't read counts as none. So a step of an older version sent
again, by a node that was the primary or by any member, can't bring a retired CA back. One rare
case is left. A primary can crash, or fail to save `cluster/published.json`, right after it
publishes a step, and then publish the same version number again with other content. Someone who
kept both can then switch the nodes between the two until the next version.

If the primary's version goes backwards (its data directory put back from an older copy, or
`cluster/published.json` lost or unreadable, for example after its disk filled up and it
restarted), the other nodes take neither trust nor configuration from it until its version
passes theirs, and a rotation waits; DNS keeps answering. Promote another node: a new epoch
beats any version. If no other node can be promoted, stop each of the other nodes, delete its
`cluster/ca.version` and start it again. That is safe (with no mark, the next version is taken),
but configuration still waits until the primary's version passes what each node applied.

Rotation helps when the cluster key may have leaked but hasn't been used. Whoever holds the
current key can sign configuration and rotate trust to a CA of their own, exactly as the
primary does. If that may already have happened (configuration or a rotation you didn't make),
re-create the cluster: `telltale cluster init` on one node, and join the others with new tokens.

**Automatic failover (with a witness or three eligible nodes).** Two nodes can't tell "the
other node is down" from "the link between us is down", so automatic failover needs a third
vote: another eligible node, or a **witness**, a tiny vote-only process that can run on a NAS,
router, or small VM.
```sh
# On the witness host (a config with [node] data_dir and [cluster] listen is enough):
# The token from `telltale cluster token create --witness` on the primary.
telltale cluster join <token> --witness --advertise https://witness.lan:8443 -c witness.toml
telltale cluster witness -c witness.toml      # run it as a service
# On the primary, then restart it:
telltale cluster set-failover auto
```
- **How it decides:** every eligible node and witness is a voter. The primary renews a 15 s
  *lease* with a majority every 5 s, and publishes only while the lease holds. If it disappears,
  the eligible nodes wait for the lease to run out, and one is elected by a majority vote in a
  new epoch, typically within 15–25 s. When two nodes are free to stand at the same moment, the
  one whose node ID sorts first goes first and the other gives way. With three voters that
  means they don't split the vote, short of a lost or badly delayed message, a restart, or a
  disagreement over the epoch; with more voters (two witnesses, say) a split is rarer than it
  used to be but still possible. A split costs one more lease.
- **Never two primaries writing:** a voter votes once per epoch and won't vote for anyone else
  while the lease it granted runs. A primary that loses its majority (for example, cut off by a
  network split) stops taking changes before anyone else can be elected. Proven by a simulator
  that runs 10,000 random partition, crash, and clock-drift schedules on every CI run.
- **Clock changes don't matter.** Leases are timed on a clock that never jumps, so a Pi (no
  battery-backed clock) setting its time from NTP after boot, or a machine resuming from sleep,
  can't cut a lease short. A voter that restarts keeps any lease it granted for a full 15 s.
- **DNS never waits for any of this.** Every node keeps answering from its last configuration;
  only configuration changes pause (503) until a primary with a lease exists.
- **Seeing it:** the Cluster page's **Failover** line (voters reachable, the lease, the latest
  vote) and the `failover` check. Metrics: `telltale_cluster_primary`, `telltale_cluster_epoch`,
  `telltale_cluster_failover_auto`, `telltale_cluster_lease_held`.
- **A witness only votes.** What covers the whole cluster (the dashboard and the other views,
  pausing blocking, the cache's table and flushes, drills, simulations, a cluster support
  package) leaves it out, and never lists it as a node that didn't answer, up or down. The
  Cluster page and the node-down alert still show it. The Cluster page shows it as *votes
  only*, never counted as behind or not serving DNS, and the `sync_lag` alert leaves it out; a
  witness that's down still fails the `peers_up` check and raises the node-down alert.
- **Manual promotion is refused while automatic failover runs**; `telltale cluster
  set-failover manual` on the primary switches back. With fewer than three voters, `auto` acts
  as `manual`, and the Cluster page says so.
- **Under a Git config authority,** an elected node that isn't Git-managed becomes an emergency
  primary: it keeps the cluster coordinated on the last version. While a Git-managed node is
  up, the other nodes leave the election to it (they still vote), so the emergency primary
  exists only while no Git-managed node can be primary. When one is back, it takes the role
  back through the election: it asks the emergency primary to hand over (see *Where
  configuration comes from*, below).

**Configuration from a Git repository.** The cluster can take its shared settings
(upstreams, lists, groups, devices, records…) from one file in a Git repository. The primary
fetches it, checks it, and hands it to every node, so all nodes serve the same commit:
```toml
# On every node that may become primary:
[cluster.git]
repo = "https://github.com/me/homelab"
ref = "main"                              # branch, tag, or commit
path = "telltale/shared.toml"             # the shared settings, in TelltaleDNS's format
# credentials_file = "/etc/telltale/git-token"   # private repositories: a token, or user:password
# poll_secs = 60
# webhook_secret_file = "/etc/telltale/git-hook" # then add a push webhook to /api/v1/hooks/git
# require_signed = true                          # only SSH-signed commits by...
# allowed_signers_file = "/etc/telltale/allowed_signers"   # ...these keys (git's format)
# allow_rewind = false                           # refuse force-pushes and rewinds
```
- **Safe by default:** a commit is used only if its file loads and validates (merged with
  each node's own settings), and it descends from the commit in use. Anything else is
  refused: the cluster stays on the last good commit, and the Cluster page, the event log,
  and the `TelltaleDNSGitCommitRefused` alert say why.
- **Signed commits:** with `require_signed`, only commits SSH-signed by a key in
  `allowed_signers_file` are accepted (`git config gpg.format ssh`; Ed25519 keys).
- **Webhook:** point the repository's push webhook at `https://<node>/api/v1/hooks/git` with
  the secret from `webhook_secret_file`. Changes then apply within seconds, not at the next
  poll.
- **Outages don't matter to DNS:** with the repository unreachable, every node keeps serving
  the last commit (`telltale_cluster_git_failing` and an alert after 15 minutes).
- **What you see:** the Cluster page shows the repository, the commit in use (author,
  message, signer), and each node's commit. `telltale_cluster_config_commit{commit=…}` on
  every node should be the same.
- **Changes go through Git:** with a Git source the cluster is GitOps-managed, so the UI and
  API don't change shared settings (409 `gitops_managed`).
- **Failover:** any eligible node with the same `[cluster.git]` can take over and keep
  following the repository. A node configured with a different repository, ref, or path
  refuses to fetch, since the cluster is pinned to its source.
- No `git` program is needed: TelltaleDNS speaks Git's protocol over HTTPS and fetches only
  that one file.

**Where configuration comes from (config authority).**
- **Choosing it:** `telltale cluster init --config-authority gitops` (or `telltale cluster
  set-authority gitops` on the primary, then restart) says the cluster's configuration comes from
  Git.
- **What it changes:**
  - only nodes whose own configuration is Git-managed (`[cluster] config_source = "gitops"`,
    set for the Kubernetes node by its Helm values) may then publish it;
  - configuration changes through the API or UI are refused on every node (409
    `gitops_managed`);
  - another node can only be promoted as an *emergency* primary, which keeps the cluster
    coordinated on the last version and publishes nothing new until a Git-managed node is back.
    When one is back, it takes over by itself after a minute (an eligible, Git-managed node
    that sees the emergency primary up), and the emergency primary steps down. With
    `failover = manual` you can also promote it right away from its Cluster page or with
    `telltale cluster promote`.

  The default is `api`: the primary's own file and UI.

- **Taking over with automatic failover.** With `failover = auto` a role can't be set by hand
  (the votes decide, and a promoted node would hold no lease, so it couldn't publish). The
  Git-managed node takes over through the election instead: after seeing the emergency primary
  up for a minute, it asks that node to hand over. The emergency primary stops renewing its
  lease, keeps answering DNS, and the Git-managed node is elected within the usual 15 to 25
  seconds (configuration changes wait for that, DNS doesn't). Nodes that aren't Git-managed
  don't stand in that election. If the Git-managed node can't win (for example it hasn't
  received the cluster key yet), the emergency primary keeps the role after a minute and is
  asked again later; the Cluster page's event list shows `takeover` and `handover` events.
  Only an eligible, Git-managed node that is up can ask.
- **Which failover mode?** With the `gitops` authority only a Git-managed node can publish, so
  `manual` failover is enough for many clusters: replicas keep serving the last version while
  that node is away, and you promote an emergency primary only if you need the cluster
  coordinated for a long outage (certificate renewal waits for a primary). `auto` does that
  without anyone present, and the Git-managed node takes the role back by itself.

Run these as the user telltale runs as (`sudo -u telltale` for native installs,
`docker compose exec telltale` for Compose), then restart telltale.

```sh
# On the first node: create the cluster. List every URL other nodes might use to reach it.
telltale cluster init --name home --advertise https://192.168.3.2:8443 --site home-pi

# Still on the first node: a join token (reusable until it expires; treat it like a password).
telltale cluster token create --ttl 1h              # brings a plain member (follows, can't be promoted)
telltale cluster token create --ttl 1h --eligible   # may bring a node that can be promoted
telltale cluster token list              # the tokens still valid: their IDs and expiry
telltale cluster token revoke 3f9c2a1b7d0e   # stop one early (nodes that joined stay members)

# On the joining node: join, then restart it.
telltale cluster join tt_join_... --site k8s

# On any node: this node's identity.
telltale cluster status
```

- **The cluster port** is `[cluster] listen` (default `0.0.0.0:8443`). It opens only once the node
  is in a cluster. Only the first node's port must be reachable: joining nodes connect out
  to it, so they can sit behind NAT. If you also serve DoH on 8443, change one of them
  (`telltale config check` warns about the clash).
- **Trust:** the token carries the fingerprint of the cluster's CA, so a joining node can't be
  tricked into joining another server; the token's secret proves the node may join. Each node
  gets a certificate valid for 90 days.
- **State** lives in `<data_dir>/cluster/` (keys are readable only by their owner). Removing
  that directory takes a node out of the cluster.
- **The Cluster page** (and `GET /api/v1/cluster`) answers "is the cluster healthy and
  serving?" on any node. It shows:
  - every node's role and site, whether it's up, its link and round-trip time;
  - each node's configuration version and how far and for how long it's behind;
  - whether each node is serving DNS (ready, queries per second, SERVFAIL share, upstream p90),
    its version, uptime, and certificate expiry;
  - six checks (peers up, primary present, in sync, no sync errors, serving, certificate) with
    what to do when one fails;
  - a timeline of joins, connections, published and applied versions, and failures.

  The cluster's summary stays at the top; the rest is in tabs: **Nodes** (the topology and the
  node table, with Maintenance…), **Health** (checks, conflicts, machines), **Rollouts**
  (staged rollouts and versions), and **Events**. A tab with something wrong says so (failing
  checks and conflicts, a version baking or a pin, failures in the last hour), and a pin shows
  on every tab. The tab is in the address (`#/cluster?tab=health`), so it can be linked. The
  page refreshes every 5 seconds.
- **Metrics:**
  - `telltale_cluster_peers{state}`;
  - per peer: `telltale_cluster_peer_up`, `telltale_cluster_peer_rtt_seconds` and
    `telltale_cluster_peer_config_lag`. The primary lists every node; a replica lists the
    primary, the other voters under automatic failover, and any other node only while a link
    to it is open or it was heard from in the last 15 seconds;
  - this node: `telltale_cluster_config_seq`, `telltale_cluster_behind_seconds`,
    `telltale_cluster_sync_error` and `telltale_cluster_cert_expiry_timestamp_seconds`;
  - the cluster reads this node refused since it started: `telltale_federated_refused_total{reason}`,
    a counter. `waits`: too many reads were already waiting for a slow node; `spent`: the
    32,768 calls all reads may have were in use; `ceiling`: the read asked for too much at once
    (over 4,096 calls, or over 256 windows of time a node); `bytes`: it was sent, but an answer
    was dropped because it would have passed the 20 MiB a read may hold or the 40 MiB all may.
    The nodes it was for are in that read's `missingNodes`. A rate above zero for long means the
    pages show partial results: see "One view of the whole cluster" under [Clusters](#clusters).

  The Helm chart's PrometheusRule alerts on a peer down for over a minute, configuration behind
  for over 30 s, failing syncs, and a certificate within 14 days of expiry.

### Compare nodes
**Cluster → Compare** puts every node side by side over the same window (1 hour to 30 days), for when "something seems odd with that node":
- One row per measure: queries per second, the SERVFAIL share, the slow share (answers over the latency objective's threshold), the share answered from the cache, the share of upstream exchanges that failed, p50 and p99. Each cell has the window's number and a sparkline; the sparklines of a row share one scale.
- **A node that deviates is outlined**, with one line saying how and since when. With three or more nodes, a node is odd when it sits at least 3 robust standard deviations (from the median and MAD of the *other* nodes, with a floor) away from them and its own 95 % interval leaves their median out. With two nodes, it's odd when the two 95 % intervals don't overlap by a clear margin, and the worse one is marked. **Since** is when its excess over the others began.
- **A grey note** says when a node only looks worse: the same number of failures as the others on a much smaller base, such as a Pi with a tenth of the traffic.
- **Table** shows the same numbers with their 95 % intervals, such as `0.04 % (0.02–0.06 %)`: a wide interval means few answers. **Open in dashboard** opens the dashboard for that node alone. On a phone, pick one measure at a time.
- The tab says **1 odd** from any tab of the Cluster page. It's a lens, not an alarm: it doesn't change the health icon or alert. Nodes that don't answer are listed and the rest compared; one node alone has nothing to compare.
- `GET /api/v1/cluster/compare?from=-24h` and the MCP tool `compare_nodes` return the numbers and the findings. Grafana's **Nodes** row has the SERVFAIL and slow shares by node and a table that highlights a node with little traffic.

## Upgrading from the cluster
A cluster whose nodes run outside Kubernetes (installed with `install.sh`) can upgrade them for
you, one at a time, in the order a cluster needs: **replicas first, the primary last**, each back
on the new version, ready, and in sync before the next one starts. With the Helm chart's
`upgradeHook`, bumping the chart (or merging the Renovate pull request in a GitOps repository)
upgrades the native nodes first and the pods after them. It is off by default on both sides;
treat it as experimental until you have watched it upgrade (and roll back) a node of yours.

**How it works.** The node's service runs as the `telltale` user in a sandbox and can't replace
its own binary, so it doesn't: asked for a version, it writes
`/var/lib/telltale/update/request.json` (in the config's `[node] data_dir`) and nothing else. A
second, root unit installed next to it, `telltale-update.path`, sees the file and starts
`telltale-update.service`, which runs `telltale self-update --request …`. Of the data directory
it may write only that `update/` folder:
1. it reads the request (a small regular file written by `telltale`, opened without following a
   link or waiting on it) and removes it;
2. it refuses anything but a release or edge build **newer** than the one installed and on the
   node's **channel** (below), a request more than an hour old, and a version whose new build
   was installed on this node and didn't come up in the last 24 hours (a run that failed in the
   downloads doesn't count);
3. it checks that the binary sits where only root can write (owned by root, and neither it nor
   any folder above it writable by a group or others), and that the health check's address in
   its unit is one of this host's;
4. it downloads the version, checks the release signature and the checksum (the release's
   signed `releases.json` must be of the version's channel, name that version and list the same
   checksum), test-runs it, and swaps it in, keeping the old binary as `telltale.old`. All the
   downloads together get eight minutes; past that nothing is installed;
5. it restarts the node (`systemctl restart`, waited for a minute; if that command is slow or
   fails, the restart goes on in systemd and the health check decides) and waits up to **two
   minutes** for it to answer ready twice in a row (`/readyz?startup=1`) at the address
   `install.sh` wrote into its unit (below). If it doesn't, it puts `telltale.old` back and
   restarts once more: `rolled_back`;
6. it records the outcome in `/var/lib/telltale-update/result.json`: `installing`, `updated` (with
   how its health was checked), `up_to_date`, `rolled_back` (with why), `unavailable` (an edge
   build no longer served), `failed`, or `refused`, with the error. `journalctl -u
   telltale-update` has its lines. Who asked (`by`) is the node's word for it: the update service
   can't check it, and says so.

So what anyone who can write that file can do is have the node restarted on a newer signed build
of its channel. The whole run (at most about 15 minutes) fits in the unit's 16-minute limit with room to spare,
so systemd never stops it between the install and the check.

**The channel.** `install.sh` writes the node's update channel into its unit and the update
service's: `edge` when you install with `--edge`, otherwise the channel of the version it
installed (it prints which). A node on the **stable** channel takes only releases; a node on the
**edge** channel takes edge builds and newer releases, and stays on edge after a release (the next
edge build is still taken). The cluster never moves a node to the edge channel or backwards: to go
back, run `sudo telltale self-update --to <version> --restart` on the node; to move a node to
edge builds, run `sudo telltale self-update --channel edge --restart`, then
`sudo sh install.sh --edge --cluster-updates`. Without `--edge`, `install.sh` installs the newest
**release** and sets the stable channel, so on an edge node always give it `--edge`.

**The health check's address.** `install.sh` writes it into the update service's unit
(`TELLTALE_UPDATE_HEALTH_URL`) from the config's `[api]`: the `listen` address and port, with a
wildcard (`0.0.0.0`, `[::]`) asked at loopback. The request never names one. Two things make every
update roll back, so `install.sh --cluster-updates` checks the address answers before it turns
the feature on: an `[access] allowed_networks` that leaves out this host's own address (loopback
for a wildcard listen), and an API that isn't up. With the API off (`[api] enabled = false`) there
is nothing to check, so updates from the cluster aren't available: `install.sh --cluster-updates`
refuses, and the update service installs nothing (`refused: no health check configured`). A node that takes longer than two minutes to come up (very large lists on an SD card) is
rolled back; upgrade such a node by hand.

**`rolled_back` is an incident.** It means the new build didn't answer ready in time, so the
previous one was put back. That can be the build, but it can also be the node's side: the node's
own process answers the check, and any local user can occupy the port first. `ctl upgrade` stops
at it; look at the node (`journalctl -u telltale -u telltale-update`) before you ask again. The
node refuses the same version for 24 hours from that run (`update_failed_recently`; `GET` shows
it as `held`, with until when), and says which run, when, and what failed; `sudo telltale
self-update --to <version> --restart` by hand isn't held back. A run that failed before anything
was installed (a network error, the eight-minute download limit, a signature or checksum, an edge
build moved on) holds nothing back: the next request tries again.

**Turning it on.** The update service is installed and **off**. On each native node:
```sh
sudo sh install.sh --cluster-updates          # on an edge node: sudo sh install.sh --edge --cluster-updates
```
It writes the units for the node's data directory, channel and API address, and turns them on
once the node answers at that address (it prints the address it tried). It refuses, and on an
existing install changes nothing, when the binary's folder isn't root's alone (a `TELLTALE_PREFIX`
others can write; older Debian and Raspberry Pi OS images have `/usr/local` as `root:staff 2775`:
check `stat -c '%U:%G %a' /usr/local /usr/local/bin`, and fix it with `sudo chmod g-w /usr/local
/usr/local/bin`), the data directory is under `/home` or `/root` or in a folder that isn't
root's, or the API is off. On a node that runs an edge build it also refuses unless you say which
channel: `--edge` to stay on edge builds, or `--stable` to move to releases (without either, a
re-run would install the newest release, an older version). A node installed before this feature needs one upgrade by hand first, on its own channel
(`sudo telltale self-update --restart`, with `--channel edge` on an edge node), then
`install.sh` as above. (`sudo systemctl enable --now telltale-update.path` also turns it on, but
skips the check.)

**Upgrading.** From anywhere with an admin's token (or an agent token with `analytics:read` and
`cluster:upgrade`):
```sh
telltale ctl --url https://dns.example.com upgrade --to 0.8.0 --dry-run   # the order, nothing asked
telltale ctl --url https://dns.example.com upgrade --to 0.8.0
```
- It reads the Cluster page's view and leaves alone Kubernetes pods (the chart's), witnesses
  (they only vote: upgrade them by hand), containers (pull the new image), and nodes already on the
  version or newer.
- Before it asks any node it reads each one's update state. A node that is up but can't take the
  request (its update service off, a request waiting or an update running, on the stable channel
  while you ask for an edge build, or refusing the version for a day after a rollback) stops it
  there, with nothing asked and every such node named, with why and how to fix it. A node that is
  down stops it too; `--skip-down` leaves out nodes that are down, and only those.
- Then it asks each node in turn and waits (`--timeout`, 15 minutes each by default: at least the update service's longest run) until the
  node's update service has recorded `updated` for that request **and** the node is back on the
  version, ready and in sync. A node that fails, is rolled back, or refuses stops it: the nodes
  after it keep their version, and the error is the node's own. One node: `--node dns-02`.
- Each request says why, for the audit log (`X-Telltale-Reason`; `--reason`, default
  `telltale ctl upgrade --to <version>`): an agent token must.
- The same call for one node is `POST /api/v1/nodes/{id}/update {"to": "0.8.0"}` (admin;
  `?dryRun=true` checks without asking), and `GET` on the same path shows the node's version,
  channel, whether its update service is on, a request it hasn't picked up yet, and the latest
  outcome. One request at a time per node: another gets `update_in_progress` until the first is
  done. The problems a node answers with: `update_unsupported` (a container, a pod, or a local
  build), `update_not_enabled`, `update_invalid`, `update_downgrade`, `update_channel`,
  `update_in_progress`, `update_failed_recently`.
- **No maintenance window.** The node restarts without one, so a `node_down` alert can fire for
  the few seconds it takes; put the node in maintenance first if that matters to you.

**Edge builds.** An edge build can be installed only while it is the newest on the edge channel:
edge binaries are replaced on every build. If a newer one was published since, the node records
`unavailable` ("the edge channel now serves …"): ask for that one, or wait for the release.
`--skip-unavailable` leaves such a node on its version, with a loud line, and goes on (the order is
then lost for that node in that run).

**With the Helm chart.** When the controller runs in Kubernetes and the other nodes don't, turn
on the chart's hook: a Job that runs before the pods roll (`helm.sh/hook: pre-upgrade`, a
PreSync hook in Argo CD), from the **new** image, with `telltale ctl upgrade --to-self`:
```yaml
image:
  tag: sha-1a2b3c4             # pin the build (the default tag, edge, can run an older cached image)
upgradeHook:
  enabled: true
  tokenSecret:
    name: telltale-upgrade   # key `token`: an agent token with analytics:read and cluster:upgrade
  whenUnavailable: fail      # or skip (see below)
```
- It upgrades every native node to the image's version and waits for each; only then does Helm
  (or Argo CD) roll the pods. A node that fails fails the hook, and the pods keep their version.
  The Job stays after a run (until the next one replaces it), so its log can be read: `kubectl
  logs job/<release>-telltale-upgrade`.
- **The image.** `--to-self` upgrades the nodes to the version of the image the hook runs. Pin
  `image.tag` to a build (`sha-…`, or a version): with the chart's default tag (`edge`) and
  `IfNotPresent`, a node can run an older cached `:edge` image.
- **The token.** Make it in Settings → API tokens (for an AI agent) as an admin, with the scopes
  `analytics:read` and `cluster:upgrade`. `cluster:upgrade` reaches only the update route;
  `analytics:read` reads every analytics route too. The hook reads the cluster on every sync, so a
  token that expires, is revoked, or stops working (`[agents] enabled = false`) fails **every**
  sync from then on, a values-only `helm upgrade` too: make it without an expiry for this narrow
  scope, or set yourself a reminder to rotate it (a new token in the Secret, then revoke the old
  one). A missing Secret fails the hook at once ("set TELLTALE_TOKEN"). An OAuth sign-in for MCP
  never gets `cluster:upgrade`.
- **https.** The hook asks the release's API Service over plain HTTP inside the cluster; when the
  API serves TLS (`[api] tls`), set `upgradeHook.url` to its `https://` address, and with a
  self-signed certificate put the certificate in a Secret and name it in `upgradeHook.caSecret`
  (`name`, and `key`, default `ca.crt`): without it the hook can't trust the API and fails.
- **Timeouts.** Helm waits for a hook only `--timeout` (5 minutes by default), while the hook allows
  15 minutes per node and 45 in all (`activeDeadlineSeconds: 2700`: two native nodes, the pre-flight and the pod's start; raise it for more): run `helm upgrade --timeout 45m` (or more), and give Argo CD's sync at least as long.
- A NetworkPolicy that limits the API (`networkPolicy.apiFrom`) gets a rule that lets the hook in
  (only while the hook is on).
- **A native primary whose replicas are the chart's pods:** the hook upgrades native nodes first,
  so it would upgrade that primary before its pod replicas. In that shape, run `telltale ctl
  upgrade` by hand instead of the hook.

**With Argo CD (GitOps).** Argo CD runs the hook as a PreSync hook on every sync:
- **Pinned to a release:** the first sync after the bump upgrades each native node behind it,
  then rolls the pods. Every later sync finds the nodes on it and asks nothing (no request, no
  download). A node on the edge channel stays on it and takes the next edge pin.
- **Pinned to an edge build:** the same while it is the newest edge build. Once main has
  published a newer one, a native node still behind the pin can't fetch it: with
  `whenUnavailable: fail` (the default) the sync stays blocked until you pin the newest edge
  build or a release; with `skip` that node stays on its version (the hook says so loudly) and the
  pods roll. Nodes already on the pin or newer are never asked, so a pin that has gone stale
  blocks only while a node is behind it. Pin a release, or set `skip`, if you don't want a sync
  to wait on that. A node on the stable channel stops the sync at an edge pin (said in full).
- **The first install:** there is no cluster yet to make the token in. Keep the hook off until
  the token exists, or create the Secret with a placeholder value: PreSync runs before anything of
  the app exists, so nothing answers (the API Service's name doesn't resolve, or nothing listens)
  and the hook succeeds and says so. Only that is skipped: a timeout, a TLS failure, packets a
  policy drops, or a refused token fail the hook. The real Secret must exist before the first
  sync that needs it (a PreSync hook runs before the app's own resources): create it outside the
  app, or with an ExternalSecret or SealedSecret that is applied before it (an earlier sync wave
  of another app, or a PreSync resource with a lower `argocd.argoproj.io/hook-weight`).
- **The controller up but not ready:** on some CNIs (Cilium) a Service with no ready endpoints
  drops the connection instead of refusing it, so the hook fails (it doesn't skip) and the sync
  waits until the controller answers. That is intended. With the hook on and the controller
  dead, turn the hook off in the chart to roll the fix.
- **A node down:** the hook fails before asking any node (the pods keep their version) unless
  `skipDown: true`. For the first 90 seconds after the node that answers starts, a native node
  that hasn't connected since isn't listed at all, so a hook run then can pass without it.
- **A node rolled back:** every sync stops at it for 24 hours from that run (the node refuses that
  version, and says until when) unless the pin moves on. A run that failed in the downloads (a
  GitHub or DNS outage) holds nothing: the next sync tries again. Look at the node; upgrade it by hand when it is fixed.

**A known limit.** If `systemctl` itself fails without restarting anything (its binary missing,
or a refusal on the system bus), the old process is still running and passes the health check,
so the run is recorded `updated` while the old build runs; the new binary is installed, so the
next request for that version answers `up_to_date`. `journalctl -u telltale-update` shows the
restart command's error, and `telltale --version` against `GET …/update`'s version tells. Run
`sudo systemctl restart telltale` on the node to start the new build. (Comparing the node's
process before and after the restart is the planned follow-up.)

**What it doesn't do.** It doesn't upgrade containers or Compose installs (pull the new image),
it doesn't choose a version for you (that's your chart bump, or `--to`), it never downgrades or
moves a node to edge builds, and it doesn't put the node in maintenance.

## Taking a node down for maintenance
Swapping a Pi's SD card, moving a box, or upgrading a node by hand: put the node in maintenance
first. For a bounded time (an hour by default, a day at most) it:

- **reports not ready:** `/readyz` answers 503 with `{"ready":false,"reason":"maintenance"}`, so
  load balancers and Kubernetes stop sending it new queries;
- **keeps answering** every query that still arrives (a router's secondary DNS entry, a device
  with the address typed in): no listener closes;
- **is left out** of alerts (`node_down`, `sync_lag`, `probe_failing`, `cert_expiring`,
  `disk_full`, and its share of `servfail_rate`), the health level, and the Cluster page's
  checks; an alert about it that was firing resolves with "(maintenance)";
- **isn't elected** primary (it still votes);
- **stays in maintenance across a restart:** the window is in `<data_dir>/maintenance.json`,
  so a node rebooted inside it comes back not ready until the window ends or someone ends it.

Everything else carries on: the cache, lists, replication, the query log, probes (they keep
measuring), the API and UI. The Cluster page, `cluster_status`, and the health panel show the node,
its window, and its real figures the whole time.

```sh
telltale ctl maintenance start --for 30m --reason "SD card swap"           # this node
telltale ctl maintenance start --for 2h --reason "kernel upgrade" --node pi   # another node
telltale ctl maintenance status
telltale ctl maintenance end --node pi
```

Or on the Cluster page: a node's **Maintenance…** (how long, why) and **End maintenance**.
Over the API it's `POST /api/v1/nodes/{id}/maintenance` with `{"forSecs": 1800, "reason": "…"}`
and `DELETE` to end it (`id` is `local`, or a node's ID, site, or pod name). Maintenance is the
node's own state, not configuration: any node passes the request to the node it's for (a node
that's down answers 503 `node_unreachable`), it works in a GitOps-managed cluster, and it's
audit-logged as `node.maintenance.start` and `.end` on that node. AI agents use
`start_maintenance` and `end_maintenance` (`ops:maintenance`, at most 2 hours). Starting again
replaces the window. `[node] maintenance_default_secs` sets the default length.

**The primary.** Under automatic failover with another eligible node online, maintenance on the
primary hands the role over first: the primary stops renewing its lease, another node is elected
within the lease window (configuration changes pause for about 30 s, as in any failover), and the
old primary follows for the rest of the window. The form shows this as a checked box
("hand the primary role to another node first"; `handover: false` over the API keeps the role).
In manual failover, or with no other eligible node online, the primary stays primary and keeps
publishing; the answer says so. Promote another node first if you're taking it offline.

**Kubernetes.** One readiness probe serves every Service that selects a pod. A resolver pod in
maintenance leaves the DNS Service, which is the point. The controller pod in maintenance also
leaves the API Service: use another node's UI or `kubectl port-forward`. A StatefulSet rollout
waits for readiness, so a pod in maintenance holds a rollout until its window ends. The chart's
startup probe asks `/readyz?startup=1`, which leaves maintenance out, so a pod restarted inside
its window isn't killed for it. For routine controller work, `kubectl drain` and rollouts remain
the usual path; maintenance mode is for the Pi and individual pods.

**Docker Compose.** The healthcheck uses `/readyz`, so the container shows as unhealthy during
maintenance (Compose doesn't restart it for that).

**Alerts and metrics.** An alert rule with `when = "maintenance"` tells a destination when a node
enters maintenance and when it leaves (not in the defaults). `/metrics` has
`telltale_node_maintenance` (0/1), `telltale_node_maintenance_until_seconds`, and
`telltale_node_maintenance_total`, plus `telltale_cluster_peer_maintenance_until_seconds{node,site}`
for peers. The Helm chart's node alerts leave out a node whose last reported window is still open
(also when it stopped reporting), and the Grafana dashboard has a **Maintenance** timeline.

A node that's really failing during its window stays quiet until the window ends: keep windows
short.

## Failover drills
Your router hands devices two DNS servers, say the Pi and a second machine. On a healthy network
a device only ever uses its first one: most systems switch to the second only when the first stops
answering. So nothing shows whether the second one works for every device, until the day the Pi's
SD card dies. A **drill** finds out on purpose, for a short time.

For 15 seconds to 5 minutes (60 by default), one node stops answering the devices you choose
(some devices, a group, or everyone) while the other nodes keep serving:

- **UDP queries get no answer** and TCP and DoT connections are closed without one: to a device,
  the node looks dead. DoH and DoQ queries get no answer (their connections stay open, since
  other queries share them). Each such query is logged with the status **drilled**.
- **Never left unanswered:** the node itself (`127.0.0.1`, `::1`: its probes and local programs),
  its infrastructure (the default gateways, `TELLTALE_NODE_IPS`, `[clients] infrastructure`), the
  cluster's nodes, and [excluded](#keeping-names-and-devices-out-of-the-log) devices.
- **It's a maintenance window too:** the node reports not ready, its alerts pause, and a primary
  hands its role over first (as for [maintenance](#taking-a-node-down-for-maintenance)). Unlike
  maintenance, **a restart cancels a drill**: the node comes back answering everyone.

Every node keeps a record of who asked it while the drill runs, including nodes the drilled one has
no direct connection to (a resolver pod only talks to the controller, and a node outside
Kubernetes to no resolver pod): the primary passes the notice and the request for the records on
to them. A minute after the drill ends, the
drilled node gathers them into a **report**:

| Verdict | Meaning |
|---|---|
| **followed** | another node answered it after its first unanswered query, before the drill ended or within 5 seconds after: its second server works. With the time it took (`timeToFailoverMs`). |
| **stuck** | 3 or more unanswered queries and no such answer: it has no working second server, or its second server is the same node. |
| **quiet** | nothing unanswered, or too little to tell (it may have been idle, or asked only the other node). An answer elsewhere after the drill is over proves nothing: the drilled node answers again by then. |
| **elsewhere** | not targeted, but it asked another node during the drill: for information. |

**Coverage** is followed / (followed + stuck). Fifteen minutes after the drill, the report also
says whether each device that followed **came back** to the drilled node or **stayed** on the other
one (Windows stays for about 15 minutes; that's normal).

Start small: one device of your own for 30 seconds, then a group, then everyone. Devices without
a working second server lose DNS for the drill's length.

**REFUSED instead of silence.** With `"mode": "refused"` (the form's "REFUSED at once"), the
node answers its targets REFUSED (extended error 14, "failover drill") instead of nothing. It's
faster: no device waits out a timeout. It's also less realistic: some devices try their next
server on REFUSED, others just fail the lookup, so a device that is `stuck` here may still fail
over from a dead server. Use the default for the real question.

**Every month, at night.** A `[drill]` section schedules drills:

```toml
[drill]
schedule = "monthly"      # "off" (the default)
nodes = ["home-pi"]       # the nodes that drill themselves: sites, pod names, or node IDs
for_secs = 30             # 15 to 300
hour = 3                  # local hour it starts in
tz = "Europe/Berlin"      # default: the system's zone
# group = "iot"           # or clients = ["192.168.1.20"]; neither: everyone
# mode = "refused"        # default "drop"
```

Each named node drills itself once a month, during that hour, on a day in the first week picked
from its name and the month (so the day moves, and two nodes rarely share it). It tries once a
minute through the hour; if a precondition fails all hour, it skips the month. It never drills
within 7 days of another drill on the same node. To get the report, add an alert rule with
`when = "drill_report"` (it covers drills started by hand too), for example to an email
destination.

```sh
# on the Cluster page: a node's Drill… (how long, whom, why), Preview, then Start drill
curl -X POST https://pi:8443/api/v1/nodes/pi/drill?dryRun=true -d '{"forSecs":30,"targets":{"clients":["192.168.1.20"]},"reason":"does the second server work?"}'
```

A drill is refused (409 `drill_refused`, with the reason) when no other node is ready and
answering (a drill would be an outage), the node is in maintenance, a drill ran in the cluster in
the last 10 minutes, a rollout is baking or the cluster is pinned, or health is severe. Unknown
targets, or targets no device seen on the node in the last hour matches, are 422 `drill_targets`.
`?dryRun=true` runs every check and lists the devices without dropping anything. `DELETE
/api/v1/nodes/{id}/drill` ends it early (the report still comes); the **Drills** tab on the Cluster
page lists every node's reports (`GET /api/v1/drills`, `GET /api/v1/drills/{id}`). Drills are
audited as `drill.start` and `drill.end`, leave `drill.started` and `drill.ended` markers on the
charts, and need an operator; AI agents plan one with `plan_failover_drill` (the `ops:drill`
scope, which no token has by default) and read reports with `drill_report`. At privacy level 2 and
above, reports have counts only.

**Kubernetes.** A drill on a resolver pod behind one balancer address tests the balancer, not the
devices: they never see a server change. The pod reports not ready, the Service stops sending it
queries, and the report's `balancerSwitchMs` says how long that took: about 4 seconds with the
chart's readiness probe (every 2 seconds, 2 failures). For two real servers (the Pi and the
cluster's address), drill the Pi.

**Metrics.** `telltale_drill_active`, `telltale_drill_dropped_total`,
`telltale_drill_last_coverage_percent`, `telltale_drill_last_stuck`,
`telltale_drill_last_failover_ms{quantile}`, and `telltale_drills_total{result}`. A drill never
changes the health level. An alert rule with `when = "maintenance"` hears about drills too (the
reason starts with "failover drill").

**Which servers devices use.** In the Advanced view, the Clients page has a **Servers** column:
each device's queries per node over the last week, and its share on the node it uses most ("mostly
pi", "both"; `GET /api/v1/clients/affinity?window=7d`). A device that has only used one server
may still have a second one configured; most systems use their first server until it stops
answering. Run a drill to find out.

## Rolling a change out in stages
A bad change (a typo in an upstream, a list that blocks the bank) normally reaches every node
within seconds. With **canary nodes** set, a change reaches them (and the primary) first, and
every other node only after a **bake** of 5 minutes, and only if nothing went wrong meanwhile.
If something did, the cluster is **pinned** to the version before the change (next section)
and you're told why, while the other nodes never saw the bad version.

**Off until you set it.** `[cluster.rollout] canaries` is empty by default: changes reach
every node at once, as before. Name canaries in **Settings → Cluster → Staged rollouts** (a
picker with the cluster's nodes, each site, and "resolver pods"), in the config file, or in
the Helm chart's `cluster.rollout`:

```toml
[cluster.rollout]
canaries = ["ephemeral"]   # node IDs, "site:<name>", or "ephemeral" (the Kubernetes resolver pods)
bake_secs = 300            # at least 5
servfail_pct = 5           # fail when the canaries' SERVFAIL share is over max(before + 2 points, this)
require_traffic = false    # true: keep baking until the canaries answered 50 queries, then judge
max_bake_secs = 3600       # the longest bake (with require_traffic, or waiting for a canary to apply)
fail_on_disconnect = true  # a canary gone for a minute after applying fails the change
history = 20               # versions the primary keeps for pinning back to
```

`[cluster.rollout]` is shared, so every node knows the canaries. A change to these settings
is published at once and never staged itself, so a bad canary list can always be fixed.

**The primary runs a change at once.** It's where the change was made, and it serves the
version it publishes, so it's judged with the canaries. During the bake the Cluster page says
"version 125 runs on k8s-resolver-0, k8s-resolver-1 and the primary; the others stay on 124".

**The guard.** Every 5 seconds the primary looks at what each canary reports in its heartbeats.
These fail a version at once:
- a canary that can't apply it;
- a canary not ready for 15 seconds after applying it;
- a canary whose listener checks fail after applying it;
- a canary gone for a minute after applying it (with `fail_on_disconnect`).

The SERVFAIL share of the canaries and the primary during the bake is compared with their share
in the same length of time before it, as soon as there are 50 answers: the version fails when
it's over `servfail_pct` and over the earlier share by more than 2 points, so a bad change is
usually pinned back seconds after it went out, before the bake ends. A version passes at the end
of the bake. With fewer than 50 answers by then there's nothing to compare: it passes (only the
checks above apply), unless `require_traffic` keeps it baking until there are 50, or until
`max_bake_secs`, when it fails.
Latency isn't judged: a Pi and a Kubernetes pod differ too much for "slower than before" to mean
anything.

A pass gives the version to every node, as a new version number with the same content. A fail
pins the cluster to the version before it, fires the `rollout_failed` alert, and records the
reason and the readings with the version.

**Promote or abort by hand.** On the Cluster page while a version bakes: **Promote now**
(everyone gets it without waiting) or **Abort** (pin to the version before it; the primary and
the canaries ran the change, so they go back too). Both need an admin.

**Good to know:**
- **A newer change during a bake** replaces the version baking: the canaries get the newer one,
  and the bake starts over.
- **Users, tokens, and the member list** wait for the bake to end before they're published (a
  version for everyone would carry the canary's configuration).
- **No canary online:** a change waits up to a minute after the primary starts (a canary may
  still be reconnecting), then goes to every node at once ("rollout skipped: no canary online"
  in the log and on the Cluster page). Canaries set but none online for 10 minutes is the
  health condition `rollout_stuck`: changes are reaching every node without a bake.
- **A restart of the primary during a bake** starts the rollout over.
- **Older nodes** (from before this release) are never canaries, even when their site is named:
  they get each change after the bake.
- **Kubernetes** (`mode: scaled`): with `canaries: [ephemeral]` the resolver pods take each change
  at once with the controller, under the guard's watch, and nodes outside Kubernetes (a Pi that
  joined) wait out the bake. A pod rescheduled during a bake counts as a canary gone; unpin to
  try again.

```sh
telltale ctl rollout status     # the version baking, the canaries and what each runs, the time left, the guard
telltale ctl rollout promote
telltale ctl rollout abort
```

Over the API: `GET /api/v1/cluster/rollout`, `POST /api/v1/cluster/rollout/promote` and
`/abort` (admin; audited as `rollout.promote` and `rollout.abort`); the settings are
`PUT`/`DELETE /api/v1/cluster/rollout-settings/default`. AI agents read `rollout_status`.

**Metrics** (the primary reports them): `telltale_cluster_rollout_stage` (1 while a version
bakes), `telltale_cluster_rollout_info{version,started}`, and
`telltale_cluster_rollouts_total{outcome}` (`started`, `promoted`, `failed`, `aborted`,
`skipped`, `pinned`, `unpinned`). The Helm chart's PrometheusRule has `TelltaleDNSRolloutFailed`.

## Pinning the cluster to a version
A pin makes every node serve an older version again: its shared configuration and its filter
snapshot. The guard pins by itself when a rollout fails; an admin can pin any kept version.

- **A pin is a new version.** Pinning to version 124 publishes, say, version 131 with 124's
  content (version numbers never go backwards), and the primary serves it too.
- **While pinned, changes wait.** Configuration changes (the UI, the API, agents' plans) answer
  409 `cluster_pinned`, with a `diff` of what the pin holds back (JSON Patch, and in the hint one
  sentence per section). A dry run still works. A Git source keeps checking the repository but
  publishes nothing; list updates still download, but no new filter snapshot goes out.
- **It's loud.** A banner on the Cluster page (pinned to what, since when, by whom, why, and what
  it holds back), the health condition `cluster_pinned`, and the alert `cluster_pinned` (a rule
  with `when = "cluster_pinned"`; the Helm chart's `TelltaleDNSClusterPinned` fires after an hour).
- **It survives failover.** A replica promoted to primary keeps the pin, and keeps serving the
  pinned version until someone unpins it there.
- **Unpin** publishes the current configuration again, through a staged rollout when canaries are
  set. A pin doesn't rewrite your files, the entries made in the UI, or Git: undo the bad change
  there (the diff says what it was), or right after unpinning, while the new version bakes on the
  canaries.

On the Cluster page: the **Versions** table lists the kept versions (when, what made each, its
outcome and the guard's readings), with **Pin…** on each (a reason, then a preview of what
changes on every node). The pin banner has **Unpin**.

```sh
telltale ctl versions                                           # newest first; * = what every node runs
telltale ctl pin 3.124 --reason "the new list blocks the bank" --dry-run
telltale ctl pin 3.124 --reason "the new list blocks the bank"
telltale ctl unpin
```

Over the API: `GET /api/v1/cluster/versions`, `POST /api/v1/cluster/versions/{epoch}.{seq}/pin`
with `{"reason": "…"}` (`?dryRun=true` shows the diff), and `DELETE /api/v1/cluster/pin` (admin;
audited as `cluster.pin` and `cluster.unpin`). Problems: `version_unknown` (404),
`version_blobs_missing` (409, its files are no longer kept), `no_rollout` (409, promote or abort
with nothing baking). AI agents use `plan_pin_version` and `plan_unpin` (`cluster:admin`), only
where an operator approves each plan (`[agents] require_approval = true`), as for promotion.

**What's kept.** The primary keeps the last `history` versions (20) in
`<data_dir>/cluster/versions.json`, and their files in its blob store: a configuration is a few
kilobytes, and filter files that didn't change between versions are stored once. A node promoted
to primary starts its own history (plus the version it was running), so versions only the old
primary kept can't be pinned there.

**Metrics:** `telltale_cluster_pinned` (0/1) and `telltale_cluster_pinned_to{version}`.

## Monitoring
**The dashboard across restarts and upgrades.**
- Charts over time come from `<data_dir>/rollups.db`, kept by minute (7 days), hour (400 days)
  and day. That includes traffic by group, which is stored by group name, so renaming or
  reordering groups doesn't mislabel history. Minutes saved before this release have no group
  breakdown.
- The top lists (Top domains, Top blocked, Top clients) and **Active clients** follow the time
  range, by whole hours: each hour's busiest 100 are saved in `rollups.db` (400 days), and the
  hours the range overlaps are added up, with this hour from memory. So **15 min** and **1 h**
  show the hours they touch ("since 14:00"). Stored hours keep their busiest 100 only, so over
  long ranges a name or device that was never in an hour's top 100 is missing, and Active
  clients undercounts on networks with more than 100 devices an hour. With **Top lists for**
  set to a group, the lists cover this hour only (groups' lists aren't saved).
- The current and previous hour's top lists and latency are rebuilt at start from the query
  log, in the background within seconds. This needs the query log on, kept locally, at
  privacy level 0. Otherwise they start empty, and completed hours still come from the
  rollups.
- Prometheus counters restart from zero, as Prometheus expects.

**Top clients' colours.** Each device's bar in the dashboard's **Top clients** is split the way
the status chart is: red for blocked, green for answered from the cache (stale and refreshed
answers included), blue for forwarded to an upstream, and grey for the rest (local records,
special names, refused queries). Hover over a bar for the numbers. They come from the same
hourly top list as the bar's length, so a device that only just made the list (common on networks
with more than 1,000 devices) shows the queries before it joined in grey. A node on an older
version sends no split: in a cluster view its queries count in the grey. Each hour's split is
saved with its top lists in `rollups.db`.

An HTTP listener (default `0.0.0.0:9153`, set with `[telemetry.metrics] listen`) serves:

| Path | Use |
|---|---|
| `/metrics` | Prometheus scrape |
| `/livez` | the process is alive (Kubernetes liveness) |
| `/healthz` | the process is healthy |
| `/readyz` | 200 once every DNS listener is bound, 503 while starting, shutting down, or in [maintenance](#taking-a-node-down-for-maintenance), with the reason as JSON (Kubernetes readiness); `?startup=1` leaves maintenance out (the startup probe) |

This listener needs no sign-in and answers only clients inside `[access] allowed_networks`. The same `/metrics` is on the API port for signed-in users (a viewer token, or HTTP Basic for scrapers that can't send one).

Main metrics:

| Metric | What it tells you |
|---|---|
| `telltale_queries_total{proto,status}` | queries by outcome: `cached`, `refreshed` (an expired answer given at once while it's refreshed), `forwarded`, `stale`, `local`, `special`, `blocked`, `refused`, `rate_limited`, `malformed`, `servfail`, `dropped` |
| `telltale_query_duration_seconds{path}` | latency histogram per path (`cache`, `upstream`, `local`, `synthesized`) |
| `telltale_stage_duration_seconds{stage}` | time spent waiting for upstreams, per query that waited (`stage="upstream"`) |
| `telltale_responses_total{rcode}`, `telltale_queries_by_qtype_total{qtype}` | answers by RCODE; queries by type |
| `telltale_cache_*` | hits, misses, stale answers served, prefetches, entries, bytes, evictions |
| `telltale_upstream_requests_total{upstream,outcome}` | attempts per upstream, `outcome` = `success` or `failure` (timeouts, errors, SERVFAIL/REFUSED) |
| `telltale_upstream_failures_total{upstream,kind}` | the failures by kind: `timeout`, `network` (connection, TLS, socket), `bad_response` (mismatched or malformed), `unresolved` (the upstream's hostname), `servfail`, `refused`, `other_rcode` |
| `telltale_upstream_duration_seconds{upstream,protocol}` | exchange-time histogram per upstream (p50/p95/p99 in Grafana) |
| `telltale_upstream_breaker_state`, `telltale_upstream_latency_ewma_seconds` | circuit breaker (0 closed = healthy, 1 half-open = probing, 2 open = benched; the web UI says Healthy, Probing, Benched); smoothed latency |
| `telltale_upstream_connections_opened_total{upstream,outcome}`, `telltale_upstream_connect_seconds_total{upstream}` | connections opened to TCP, DoT, and DoH upstreams (`ok` or `failed`), and the time spent opening them: their ratio is the mean connect time, TCP and TLS together. Many opens per minute mean the pool keeps closing them (see below) |
| `telltale_upstream_tls_handshakes_total{upstream,kind}` | TLS handshakes, `full` or `resumed` (from a stored session, a round trip shorter) |
| `telltale_upstream_connections_closed_total{upstream,reason}`, `telltale_upstream_connections{upstream}` | pooled TCP and DoT connections ended: `idle` (unused for `idle_timeout_ms`), `server` (closed or reset by the upstream), `write_failed`, `unanswered` (queries waited 3 s with nothing at all coming back: a connection dropped silently along the way; its queries retry at once on a new one), `unused`; and how many are open |
| `telltale_upstream_connection_retries_total{upstream}` | queries sent again on a new connection because the pooled one closed just before answering |
| `telltale_blocked_total{group,list}` | blocks by the client's group and the deciding list (`list` is `quick`, `schedule`, or `answer_ip` when a quick rule, a schedule, or rebinding protection decided instead) |
| `telltale_client_queries_total{client}` | queries per client: off by default; turn on with `[telemetry.metrics] per_client = true` (at most `per_client_cap` clients, default 100; the rest are `client="other"`) |
| `telltale_list_entries{list}`, `telltale_list_regex_skipped{list}`, `telltale_filter_*` | list sizes, regex rules a list ships that the snapshot leaves out (over `max_regexes`), snapshot version, rule count, compile time, and `telltale_filter_lookup_mode{mode="indexed"|"walk"}` (1 for the lookup in use; `walk` is the slower fallback when a snapshot has more distinct list combinations than the index holds, 65,536, which is also logged as a warning) |
| `telltale_telemetry_dropped_total`, `telltale_qlog_*`, `telltale_ratelimited_total` | analytics that fell behind (answers never wait), query-log writes, rate limiting |
| `telltale_udp_*`, `telltale_tcp_*` | listener counters |
| `telltale_proxy_protocol_rejected_total`, `telltale_proxy_protocol_no_address_total{kind}` | `tcp`, `dot`, and `doh` listeners with `proxy_protocol = true`: connections closed for a missing or malformed PROXY header, and connections whose header named no client address (`kind` = `local`, `unspec`, `unix`), which keep the socket address |
| `telltale_doh_forwarded_refused_total{reason}` | `doh` listeners with `trusted_proxies` or `x_forwarded_for` ([Behind a reverse proxy](#behind-a-reverse-proxy)): connections from an address `trusted_proxies` doesn't list, closed at accept (`reason` = `unlisted_peer`), and PROXY headers or `X-Forwarded-For` headers that name no usable client, refused (`no_client_address`) |
| `telltale_resident_memory_bytes`, `telltale_uptime_seconds`, `telltale_build_info` | process |
| `telltale_config_seq`, `telltale_annotations_total{kind}`, `telltale_annotation_write_failures_total` | the configuration sequence this node applied; [change markers](#change-markers) written, and those that couldn't be |
| `telltale_process_starts_total`, `telltale_process_unclean_starts_total` | starts on this data directory, and those after a run that didn't stop cleanly (a crash, an OOM kill, a power cut); kept in `<data_dir>/runs.json`, so they count across restarts (a new pod with an empty volume starts from 1). Settings → System shows them too. |
| `telltale_host_*`, `telltale_cgroup_*`, `telltale_data_*`, `telltale_open_fds` | the machine it runs on: see [Host resources](#host-resources) |

Counters are kept per thread and summed on scrape, so recording never slows a query or allocates memory. The per-upstream, per-list, and per-client series are built by the analytics thread from query events, off the query path.

The per-group series, `telltale_group_queries_total` and `telltale_blocked_total`, follow the group's name across a reload: a group you add starts at zero, the others keep their counts wherever the new configuration puts them, and a group you remove has its series end (renaming a group removes one name and adds another). Two limits: a few queries answered at the moment of the reload can count under the previous numbering; and with more than 64 groups, the 64th and later share one row, shown under the 64th group's name, so a reload that moves groups across that line can move a whole total to another name. The built-in live views (the per-second and per-minute counts by group and upstream, the traffic flows, and each group's top lists for the hour) are still counted by position: after a reload that renumbers the groups or upstreams they can disagree with `/metrics` until those minutes and hours age out, and the stored minute that spans the reload is kept under the new names.

`telltale_upstream_duration_seconds` follows the upstream's name the same way. The router's own per-upstream counters (`telltale_upstream_requests_total` and the others) start again from zero when a reload rebuilds the router, and an upstream that keeps its name but changes protocol carries its history into its new `protocol` series.

### Traffic map
**Monitor → Traffic map** answers "what is the network reaching right now?" in one picture, which suits a wall screen:
- Each tile is a service, a site, or a name, sized by how often it was looked up this hour (or the previous clock hour). Blue tiles were answered, red ones were blocked; a stronger colour means busier.
- **Services** folds names into the services of the [blocked-services](#blocked-services) catalog (all of YouTube's names make one YouTube tile) and shows other names by site. **Sites** folds each name into its base domain (`rr3.googlevideo.com` → `googlevideo.com`). **Names** shows them as devices asked.
- It refreshes every 5 seconds. The five tiles that grew most since the previous refresh get an amber ring and a `+N`.
- Point at a tile for the names behind it; select it to open them in the query log.
- It draws the busiest 100 names (less their blocked queries) and the busiest 100 blocked names, every node of a cluster, from the same approximate top lists as the dashboard, so it adds no work to answering queries. Each hour starts every count again, so the map looks sparse just after the hour.
- Uptime monitors, phones checking their connection, and other background lookups can crowd it: [keep them out](#keeping-names-and-devices-out-of-the-log).

### Where does time go?
The dashboard's **Where time goes** section (Advanced view) has two views:
- **Percentiles:** this hour's p50, p90, p99, and max per answer path and transport, and the time spent waiting for upstreams.
- **Heatmap:** answers over time (minutes for 1 to 24 hours, hours for 7 days) in the bands of `telltale_query_duration_seconds` (50 µs to 5 s, and slower), darker where more answers landed; one path or several (**cache**, **upstream**, **local names**, **blocked & special**). The dashed line is the [latency objective](#service-level-objectives)'s threshold. Dots are real queries (exemplars): select one to open it in the query log. The ticks along the top are [change markers](#change-markers). **Table** lists the counts.
- On the **Upstreams** page, **Answer time over time** shows the same for one upstream.
- `GET /api/v1/stats/latency/heatmap?from=-6h&by=path|upstream&step=minute|hour` (minutes back 48 hours, hours back 400 days) and `GET /api/v1/stats/latency/exemplars` (the last 512 per node, newest first; agents need `querylog:read`) return the data; the MCP tool `latency_breakdown` with `histogram: true` adds the last hour's bands. Each node counts its answers into the bands as it already does for `/metrics`, once per minute bucket; older builds' minutes have no bands and the answer says `partial`.

### Heatmap
**Monitor → Heatmap** shows when queries happen: one row per day (or, with **Typical week**, one per weekday, each cell the mean of those days), one column per hour, 15 minutes, or minute of the day, in your browser's local time.
- **Network** counts every query exactly, from the dashboard's per-minute and per-hour counts: hours back 400 days, 15-minute and minute slots back 7 days. **Blocked** colours blocked queries instead.
- **Device** (an address) and **Name** come from each hour's top lists (the busiest 100), by hour. While it's in the list the count is exact; hatched hours had it below the list, so its count there is unknown, not zero. Open one from the Clients page (**When**) or the Traffic map.
- Point at a cell (or move with the arrow keys) for its count; select it (or press Enter) to open the query log from that time. The bars on the right and at the bottom sum each row and column; the small ticks are [change markers](#change-markers). **Table** shows it by hour.
- `GET /api/v1/stats/heatmap?from=-7d&grain=15m` (`kind=client|name`, `key`, `measure=blocked`) and the MCP tool `activity_heatmap` return the same as parallel arrays. A name needs privacy level 0, a device level 1 or lower.

### Flow
**Monitor → Flow** shows where queries go, as one diagram: **groups** → **decision** (cached, forwarded, blocked, local, …) → **upstream** → **response code**. The width of each band is the number of answers, and red bands end in a SERVFAIL.
- Every band is a count kept for exactly that pair as queries were answered, never an estimate: each minute counts group → decision for every answer, then decision → upstream → response code for the answers an upstream was asked for, and decision → response code for the rest. A dropped query has no response code, so it ends at its decision.
- **Network** reads those minute counts, every node of a cluster (15 minutes to 7 days). Minutes from a build before 0.5 have no flow counts: the card says some answers are missing.
- **Device** (an address) reads that device's queries in the query log, at most the last 24 hours. If the read stops early, the card says so. It needs query-log privacy level 1 or lower.
- Point at a band for its count and share (of every answer, and of where it comes from); select a node to open what's behind it (a group's settings, the lists for **blocked**, the upstreams, or the query log for a decision or a response code). Nodes under 0.5 % fold into **other** until you tick **Show small**. **Live** refreshes it every 15 seconds and shows when it last did. **Table** lists every band. On a phone the stages run top to bottom.
- `GET /api/v1/stats/flow?from=-6h` (`client` for one device) and the MCP tool `query_flow` return the nodes and links. Grafana has no built-in Sankey panel; a community Sankey plugin can draw the same from that endpoint.

### Wall display
`#/wall` (the **Wall display** button at the top right, between pause and the theme, in the Advanced view) is a full-screen page for a monitor on the wall or a tablet on a shelf: no menu, one panel at a time on a timer, and the live query stream as a ticker along the bottom.
- Panels: `map` (this hour's busiest names as tiles that move as they grow), `flow` (the last hour's query flow, with dots travelling along the bands), `slo` (each service-level objective's budget left as a ring, the last hour's burn rate under it (amber from 1×, red from 6×), and the devices that spent it), `latency` (the last hour's answer-time heatmap), and `heat` (the network's week).
- The address chooses them: `#/wall?panels=slo,flow&every=30` shows those two, in that order, 30 seconds each (default: all six, 20 seconds; 5 to 600). The sixth, `kpi`, is the "right now" tile: the last hour's queries per second, blocked share, answers from the cache, and the health word.
- **The layout fits the screen** (`?layout=auto`, the default), from the wall's size:
  - a phone or small tablet (shorter side under 600 px): one panel at a time, as before;
  - a portrait screen: two panels stacked;
  - a TV (16:9 or 16:10): a large panel and two small ones beside it (the "right now" tile and the service level);
  - an ultrawide screen (more than 2.1 × as wide as tall): a large panel in the middle and four around it;
  - a large screen (2560 × 1300 and up): all six at once, nothing rotating, and the live queries as a column beside them.

  Panels that don't fit rotate in the large panel every `every` seconds; the arrow keys move it. `?layout=single` keeps one panel at a time on any screen, `?layout=grid` the large screen's grid, and `?layout=portrait` (or `compact`, `standard`, `ultrawide`, `large`) forces one. A wall display's link can carry it. `?motion=off` (or the system's reduced-motion setting) stops every animation; the panels still change.
- **Space** pauses, the arrow keys move between panels, **Esc** or a click goes back to the dashboard. Nothing animates while the tab is hidden. Resizing or zooming the window keeps the panel you are on (unless it changes the layout); a new address or a new layout starts again from the first.
- It needs a signed-in session like any page. For a screen nobody sits at, make it a **wall display** instead (**Settings → Users → Wall displays**, admins): give it a name and, best, the screen's address or network (`192.168.2.40`, `192.168.2.0/24`), and open the link it shows once on that screen's browser. The screen then stays signed in until you revoke it (or until the days you set run out), with no idle sign-out, but it can only show the wall: the traffic map, the flow, the service level, the heatmaps, the change markers, and the live queries (it does see live query names, like a viewer). Every other page and every change is refused, and from an address outside its networks it's refused too. The link is shown once; making, opening, and revoking one is in the audit log. In a cluster, make it on the primary; every node accepts it. `POST /api/v1/displays` makes one from a script; the code only works as a link, never as an API token.
- The Grafana dashboard is the other wall.

### Change markers
Every time chart (the dashboard's, the Cache page's) draws a thin line for each thing that was done to a node, or that the node did to itself, so a change lines up with what it did to the graph:

| Marker | When it's written |
|---|---|
| Configuration applied | a change took effect: its version, where it came from (`ui` for a signed-in user, `api` for an API token, `agent`, `gitops`, `file` when the config files were reloaded), who made it, and which sections changed. On a cluster replica: the version, and `gitops` or `cluster` (a replica can't tell who; the primary's marker says) |
| Build started, node restarted | every start, and a new build the first time it starts (`uncleanShutdown` after a crash, an out-of-memory kill, or a power cut) |
| Lists refreshed | a list download changed the rules: which lists, and how many blocked names were gained or lost (a refresh that changed nothing writes none) |
| Rollout | a [staged rollout](#rolling-a-change-out-in-stages) reached its canaries, was promoted, failed and was pinned back, aborted, pinned, or unpinned (the primary's) |
| Maintenance, pauses, cache flushes | [maintenance](#taking-a-node-down-for-maintenance) entered or left; blocking paused or resumed; the cache flushed (the node asked, naming the nodes it applied to) |
| Upstream benched or recovered | an upstream was benched (its circuit breaker opened) or is answering again (at most one per upstream every 5 minutes) |
| Note | what an operator or an agent wrote (below) |

- **Hover** a marker (or tab to it) for what happened, when, who, and on which nodes; select it to open where it happened (Settings, Cluster, Lists, Upstreams). One change applied on several nodes is one marker naming them. Where more than 40 would crowd a chart, close ones share a marker with a count (`×3`).
- **Changes** in the dashboard header turns them off and on (remembered in this browser). In the Advanced view, chips pick the kinds. The node picker shows one node's markers only.
- **Settings → System → Changes** lists the last 200 from every node, filterable: the table view of every chart's markers. `GET /api/v1/annotations?from=-24h&kinds=config.applied,note` returns them (newest first, at most 2,000 a page, `nextBefore` for the next page), and the MCP tool `list_annotations`; `get_overview` includes how many fell in its window and the latest three.
- **Notes:** the **Note…** button (operators) puts your own marker on every chart of every node: a new access point, an ISP outage, a migration. 1 to 200 characters on one line, now or up to 7 days back. `POST /api/v1/annotations` with `{"text": "moved the AP", "time": "2026-10-16T14:05:00Z"}` does the same, and so does the MCP tool `annotate` (agents need the `ops:annotate` scope, which isn't in the default set). Notes are audit-logged (`annotation.note`) and can't be edited or deleted: add a correcting note. They aren't configuration, so a GitOps-managed cluster takes them too.
- Each node keeps its own in `<data_dir>/annotations.jsonl`: at most 20,000 lines and 90 days, trimmed at start and once a day. They're written beside the work they describe, never on the query path. If the file can't be written (a full or read-only disk), the node logs it once an hour, counts it in `telltale_annotation_write_failures_total`, and carries on.
- **Prometheus and Grafana:** `telltale_config_seq` is the configuration sequence the node applied (the cluster's, or a standalone node's configuration version), and `telltale_annotations_total{kind}` counts the markers written. The Grafana dashboard draws `changes(telltale_config_seq[5m]) > 0` (configuration), `changes(telltale_filter_snapshot_version[5m]) > 0` (lists), and `changes(telltale_process_starts_total[5m]) > 0` (restarts) as annotations on every panel, with no Grafana credentials.

### Host resources
Every node samples its machine every 15 seconds (off the DNS path, from `/proc`, `/sys`, and the cgroup files) and shows it on the **Cluster** page, one card per node, with the last hour as a line under each bar. A standalone node shows its own card there too. In a cluster, the samples travel in the nodes' heartbeats, so any node's page shows every machine.

| What | Where it comes from | Metric |
|---|---|---|
| Memory: total, available, swap | `/proc/meminfo` | `telltale_host_memory_bytes{kind}` |
| The container's memory limit and use, OOM kills | cgroup v2 (`memory.max`, `memory.current`, `memory.events`) or v1 | `telltale_cgroup_memory_bytes{kind}`, `telltale_cgroup_oom_kills_total` |
| CPU busy, load average, cores | `/proc/stat`, `/proc/loadavg` | `telltale_host_cpu_busy_ratio`, `telltale_host_load{window}`, `telltale_host_cpus` |
| The container's CPU quota, and how often it throttles | `cpu.max`, `cpu.stat` (v1: `cpu.cfs_*`) | `telltale_cgroup_cpu_quota_cores`, `telltale_cgroup_throttled_ratio` |
| Free space where the data lives; query log and list sizes; write rate | `statvfs` of `data_dir`; `/proc/self/io` | `telltale_data_filesystem_bytes{kind}`, `telltale_data_bytes{kind}`, `telltale_write_bytes_per_second` |
| Temperature (the hottest sensor; a Pi's SoC) | `/sys/class/thermal` | `telltale_host_temperature_celsius` |
| Open files against the limit, threads | `/proc/self` | `telltale_open_fds`, `telltale_max_fds`, `telltale_threads` |
| OS, kernel, architecture, machine uptime | `/etc/os-release`, `/proc` | `telltale_host_info{os,kernel,arch}`, `telltale_host_uptime_seconds` |
| Clock offset between nodes | heartbeat timestamps and round-trip time | (Cluster page) |

The card says what looks wrong, and the Cluster page's `host_resources` check turns red with it:
- the data disk 90% full or more;
- the host's memory, or the container's limit, 90% used or more;
- an out-of-memory kill in the last hour;
- 80 °C or more;
- a clock 2 s or more away from this node's.

With `prometheusRule.enabled`, the chart adds matching alerts:
- `TelltaleDNSDataDiskLow` (under 10% free for 10 minutes);
- `TelltaleDNSMemoryPressure` (over 90% of the limit);
- `TelltaleDNSOutOfMemoryKill`;
- `TelltaleDNSCpuThrottled` (over 25% of periods);
- `TelltaleDNSRunningHot`.

`deploy/helm/alerts-test.sh` checks them with `promtool`.

**What a node can't read is left out, not shown as zero:**
- the `FROM scratch` image has no `/etc/os-release`;
- most PCs and VMs have no temperature sensor;
- outside a container there's no cgroup limit.

The card lists what's unavailable. Older nodes in a mixed-version cluster simply show no card.

**Grafana:** import `deploy/grafana/telltale-dashboard.json` (service level, traffic by status, answer-time percentiles, where time goes, upstream latency/share/failures/breakers, blocks by list and group, cache, top clients, and the health of TelltaleDNS itself). Pick the Prometheus data source, job, and instance at the top.

**History:** once a minute, completed minutes are saved to `<data_dir>/rollups.db` (SQLite): per-minute counts for 7 days, per-hour for 400 days, per-day forever, and each hour's top domains, blocked names, NXDOMAIN names, clients, and latency percentiles. The dashboard's 7- and 30-day views, `GET /api/v1/stats/timeseries?step=hour|day`, and long `stats/summary` ranges read them, and they survive restarts. If the file can't be opened, history is limited to the 48 hours kept in memory; DNS is unaffected.

### Service-level objectives
Two promises about DNS, each with an **error budget**: the bad answers it still allows over a window (30 days by default).
```toml
[slo]
enabled = true
availability_target = 99.9   # percent of answers that aren't SERVFAIL
latency_target = 99          # percent of answers sent within latency_ms
latency_ms = 250             # 1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, or 5000
window_days = 30             # 1 to 90
```
- **What counts:** availability counts every answer (any response code) and the SERVFAIL ones; latency counts every query that got an answer and the ones slower than `latency_ms`. Queries dropped without an answer (rate limits, junk) count for neither. DNSSEC failures and domains broken at their own servers are SERVFAIL too: that's what your devices saw.
- **Burn rate:** how fast a budget is being spent. 1 spends exactly the budget over the window; 14.4 spends 2% of a 30-day budget in an hour. Each objective shows it over 5 minutes, 30 minutes, 1 hour, 6 hours, and 3 days.
- **When it warns:** a long and a short window both burn too fast (the Google SRE workbook's pairs): **fast**, 14.4× over 1 hour and 5 minutes; **slow**, 6× over 6 hours and 30 minutes; **ticket**, 1× over 3 days and 6 hours (shown only). Fast and slow turn the [health](#health) icon amber (`slo_burn`) and fire `slo_burn` [alert rules](#alerts). A pair needs at least 50 answers in its short window and 10 bad answers in its long one, so a single SERVFAIL on a quiet network doesn't warn.
- **Where:** the dashboard's **Service level** card (in the Advanced view: the Simple | Advanced switch at the top; in the menu on a phone), `GET /api/v1/stats/slo`, and the MCP tool `slo_status`. In a cluster the objectives cover every node's answers. They're worked out from the per-minute and per-hour counts the dashboard already keeps, so they cost nothing on the query path; slow answers are counted in the rollups from this release on (older hours count none).
- **Prometheus:** `telltale_slo_objective_ratio{slo}` and `telltale_slo_latency_threshold_seconds` publish the settings. With `prometheusRule.enabled`, the Helm chart adds recording rules (`telltale:slo_availability_errors:ratio_rate5m` … `_3d`, and `telltale:slo_latency_errors:…`) and alerts (`TelltaleDNSSLOAvailabilityBurnFast`, `…BurnSlow`, `…BurnTicket`, and the same for latency) with the same windows and minimums; set `prometheusRule.slo` to the same targets as `[slo]`. Without Kubernetes, load `deploy/prometheus/telltale-slo-rules.yaml` (the same rules, for a scrape job named `telltale-metrics`). The Grafana dashboard's **Service level** row shows the SLIs, the budget left over the dashboard's time range, and the burn rate.

#### Who spent it?
**Who spent it?** under each objective on the Service level card (or **Analyze → Error budget**) breaks the window's bad answers down:
- **Budget left** over the window as a line (one per node below it), with the [change markers](#change-markers), so a drop lines up with what changed.
- **Clients** and **names** that got the bad answers: approximate top lists (each count may be up to its "±" over, Space-Saving's bound), kept per hour for 400 days. Select one to open its bad answers in the query log, where the log still has them (it keeps fewer days than the window).
- **Upstreams** (`none`: no upstream on the answer, such as a SERVFAIL served from the cache), **status** (`refreshed`, `forwarded`, ...), **response code**, and **nodes**: exact, from the per-minute counts.
- In a cluster every node is asked. A node on an older build, or a resolver pod that's gone (counted from the minutes it shipped, 7 days), adds to the totals without client and name lists, and is named as partial. The lists follow the query log's privacy level: names as hashes at 1, no clients at 2, only the timeline at 3.
- `GET /api/v1/stats/slo/attribution?objective=availability&from=-30d` returns it, and the MCP tool `slo_attribution`. Counting it costs nothing on the query path: the analytics thread counts bad answers only.

### Listener checks
A listener can be bound and still not answer: a stuck TLS stack, a firewall rule, a load balancer in front of it. So every node asks each of its own DNS listeners a question the way a device would, through the listener's own protocol:
```toml
[probe]
enabled = true
interval_secs = 30
timeout_ms = 2000
cert_warn_days = 14                      # a certificate expiring sooner degrades the health level
targets = ["udp://192.168.5.112:53"]     # extra: by IP, e.g. a load balancer's address
```
- **What's asked:** `probe.telltale.invalid`, type A, which TelltaleDNS answers NXDOMAIN itself (no upstream). Any well-formed answer counts. A listener bound to `0.0.0.0` or `[::]` is asked on loopback; DoH on its `path`. Targets take `udp://`, `tcp://`, `tls://`, `https://…/dns-query`, `h3://`, and `quic://` with an IP address. Certificates aren't checked by name (probes connect by IP); a listener with `proxy_protocol = true` is skipped, since probes don't send the PROXY header.
- **Certificates:** each DoT/DoH/DoH3/DoQ listener's certificate file is read for its expiry, its SHA-256 fingerprint, and the names it covers.
- **The web UI:** with `[api] tls`, the web UI and API are checked too (`proto="api"`): a `GET /livez` over HTTPS, and their certificate like a listener's. A self-signed one shows as such (it doesn't expire); compare its fingerprint on this page with the one your browser shows before trusting it. Your own certificate's expiry warns and alerts like a DNS listener's.
- **Health:** a probe that fails twice in a row degrades the level (`probe_failing`); when every DNS listener of a node fails, the node isn't serving DNS (`not_serving`, severe unless other nodes serve; the web UI's check doesn't count toward it). A certificate within `cert_warn_days` degrades (`cert_expiring`); an expired one is severe (`cert_expired`), since encrypted clients can't connect.
- **Alerts:** `probe_failing` and `cert_expiring` rules (below); with `prometheusRule.enabled`, the Helm chart adds `TelltaleDNSListenerNotAnswering` (2 minutes) and `TelltaleDNSListenerCertExpiring` (under 14 days).
- **Where:** **Settings → System → Listener checks**, `GET /api/v1/system/probes` (every node), the MCP tool `probe_status`, and `/metrics`: `telltale_probe_success{target,proto}`, `telltale_probe_duration_seconds`, `telltale_probe_failures_total`, and `telltale_listener_cert_expiry_timestamp_seconds{target}`.
- **Cost:** a handful of queries a minute, from a background task. They count in `telltale_queries_total` like any query, but stay out of the query log, the dashboard's top lists, device analytics, and event sinks. dnstap still sees them as client queries from loopback.

### Upstream truth checks
Are your upstreams telling the truth? The **Upstreams** page's **Answer quality** card (and `GET /api/v1/analytics/upstream-checks`, the MCP tool `upstream_checks`) shows, per node and upstream since start:
- **DNSSEC verdicts** on its answers, when `[dnssec] mode` validates: secure, unsigned, bogus, undecided. An upstream with bogus answers others don't have may be tampering, or broken.
- **Error codes** it attached to its answers (Extended DNS Errors, RFC 8914). EDE 15 (Blocked), 16 (Censored), and 17 (Filtered) mean the upstream filters names itself: expected from a family filter, a surprise from a "plain" resolver.
- **Second opinions** (off by default):
  ```toml
  [upstream_check]
  sample_every = 1000          # one forwarded question in 1,000 is asked again (0 = off)
  # reference = "quad9-only"   # an upstream group to ask; default: another member of the same group
  keep = 100                   # disagreements kept
  ```
  After the device has its answer, a background task asks another upstream the same question and compares: **same**; **other addresses** (both had addresses, none in common: CDNs and geo-DNS answer differently per resolver, usually harmless); **other response** (a different response code); **filtered** (one side had addresses, the other none, or only `0.0.0.0`, `::`, or loopback: one of them filters that name); **no second answer**. The latest disagreements are listed with both answers; names follow the query log's privacy level. A group with a single upstream gets no second opinions unless `reference` names another group. At most 8 run at once; more are skipped.
- **Privacy:** the second upstream sees the sampled names, which is why it's off by default. One in 1,000 adds 0.1% to upstream traffic.
- `/metrics`: `telltale_upstream_dnssec_total{upstream,result}`, `telltale_upstream_ede_total{upstream,code}`, `telltale_upstream_check_total{upstream,result}`.
- Cost: on the path to an upstream only (never for cached or blocked answers): one look for an EDE in each upstream answer and a counter per DNSSEC verdict.

### Query events
Besides counters, every query also produces a detailed **event**: the time, the client and its group, the name and type, the outcome, the response code, which list and rule blocked or allowed it, and the timings. Every upstream exchange produces one too. Events feed the query log, top lists, and per-client analytics, which the web UI and the API (`GET /api/v1/queries`, `/api/v1/stats/...`) read.
- Each thread writes events into its own buffer without waiting or locking, and a background thread collects them every 25 ms. If a buffer ever fills, events are dropped and counted, and DNS answers are never held back. Counters and the metrics above never drop.
- `[telemetry] ring_slots` sets the buffer size per thread, in events of about 128 bytes (default `4096`, 512 KiB). That's about 170 ms of a fully loaded worker. Raise it if `telltale_telemetry_dropped_total` ever grows.
- Collected so far, in memory: per-second counts for the last 15 minutes and per-minute counts for the last 48 hours; for the current and previous hour, the top domains, blocked domains, NXDOMAIN names, clients, and each recent client's top domains; and latency percentiles by path, query type, client, and upstream.

| Metric | What it tells you |
|---|---|
| `telltale_telemetry_events_total{ring}` | events written, per thread name (`udp-<port>-<n>` for the UDP workers; Tokio's workers share `telltale-rt` and are summed) |
| `telltale_telemetry_dropped_total{ring}` | events dropped because a buffer was full (should stay 0) |
| `telltale_clock_steps_total`, `telltale_clock_last_step_seconds` | times the event clock followed a step of the system clock (a Pi setting its clock from NTP after TelltaleDNS started, a resume from suspend), and the latest step. Events, the query log, and the rollups stay on the wall clock across a step. |

### Query log
Every query event is also written to the **query log** on disk, in `<data_dir>/qlog/YYYY/MM/DD/HH-<node>-<part>.seg`: one file per hour, compressed by column, about 14 bytes per query (50 million queries take about 690 MB).
```toml
[telemetry.qlog]
enabled = true
retention_days = 30          # delete older hours
retention_bytes = "2GiB"     # and the oldest hours beyond this total
privacy_level = 0            # 0 full; 1 hide domains; 2 hide domains and clients; 3 no per-query log
flush_interval_secs = 10     # write at least this often (a crash loses at most this much detail)
fsync = false                # true: sync every write (slower on SD cards)
```
- Writes are sequential and batched, about one every 10 seconds on a quiet network, so it's gentle on SD cards. A slow or full disk never slows DNS: if the writer falls behind, rows are dropped and counted (`telltale_qlog_rows_dropped_total`). The store reports on itself too: `telltale_qlog_block_write_seconds` (the time block writes take; `rate(..._sum) / rate(..._count)` is the average), `telltale_qlog_segments` (segment files on disk), and `telltale_qlog_write_errors_total`.
- `privacy_level = 1` stores each name as a hash, so identical names still group together but can't be read back; `2` also drops client addresses; `3` keeps no per-query log at all (counters, top lists, and graphs still work).
- What the levels cover: everything TelltaleDNS keeps or shows, as on Pi-hole. The query log, the live tail, [event sinks](#event-sinks), the dashboard's top lists, a device's page, and the hourly top lists kept in `rollups.db` all show hashed names at 1 and above, and no client addresses at 2 and above (every query then counts as one client). Anomaly detection and new-device alerts are off at 1 and above: their findings name domains and devices. The masked-client warning is off at 2 and above. Counts, graphs, and latency keep working at every level.
- What level 1 protects against: the hash is keyed with a random key kept in `<data_dir>/privacy.key` (in a cluster, the primary's, which every node adopts so logs group the same everywhere). Someone holding the log but not the key can't check whether a name they suspect was queried. Anyone with the key and the log can; keep the data directory private, or use level 3.
- Search it in the web UI's **Query log**, through the API (`GET /api/v1/queries`), or from the command line:
  ```sh
  telltale qlog search doubleclick -c telltale.toml                  # names containing "doubleclick"
  telltale qlog search --client 192.168.1.50 --status blocked --since 3600
  telltale qlog search '*.example.org' --match glob -t AAAA --json    # JSON lines
  telltale qlog search --min-ms 500 --limit 20                      # slow queries
  telltale qlog search doubleclick --not-name --since 3600          # the last hour, except names containing "doubleclick"
  telltale qlog search --status blocked --not-status --since 600    # everything that was not blocked
  ```
  Results come newest first; the last line prints a `--cursor` for the next page. `--match` is `substring` (default), `exact`, `suffix` (the name or anything below it), `glob`, or `regex`.
- **"Everything except":** each filter can be turned around to keep the queries that do *not* match it: `--not-name`, `--not-client`, `--not-status`, `--not-qtype` on the command line; `nameNot`, `clientNot`, `statusNot`, `qtypeNot`, `rcodeNot` (`=true`) on `GET /api/v1/queries` (the Live stream takes all but `rcodeNot`); and on the Query log page the **Match** menu's "does not contain", "is not", "is not, or under", "does not match wildcard", "does not match regex", the **not** boxes beside Client, Type, and Rcode, and the **not** chip before the statuses. A flag needs its filter (`nameNot` needs `name`). A negated `rcode` also keeps the queries that got no response code. A negated search can't use the per-block name index (that only says "maybe here", never "not here"), so it reads every block the time range and the other filters leave, like a "contains" search does: on a long log, add a time range or another filter. In a cluster, nodes older than this version don't answer a negated search or Live view and are listed as not reached, rather than answering rows that weren't negated.
- Searching is fast because it looks at the list of names first and skips whole files that can't match: on a Raspberry Pi 4, finding a rare name in 50 million queries over 30 days takes about 0.2 s, and the slowest searches about 2 s. Searches use up to 4 threads at the lowest CPU priority, so they never slow DNS down.
- Metrics: `telltale_qlog_rows_written_total`, `_rows_dropped_total`, `_bytes_written_total`, `_segments_removed_total`, `_write_errors_total`.

### Keeping names and devices out of the log
Noise drowns out what matters: phones checking their connection, time servers, a monitoring probe asking every few seconds. Keep them out of the log and the statistics:
```toml
[exclusions]
enabled = true                                           # off keeps the lists, logs everything again
names = ["connectivitycheck.gstatic.com", "ntp.org"]     # each with its subdomains
clients = ["192.168.1.10", "10.20.0.0/24"]               # addresses or networks
```
- Their queries are still answered as usual and still counted in Prometheus (`telltale_queries_total`), but left out of the query log, the live view, the dashboard and top lists, device pages, anomalies, the event sinks, OTLP traces, and exemplars. `telltale_queries_excluded_total` counts them.
- The dashboard's totals leave them out, so they'll be lower than Prometheus's.
- From the next query on, on every node of a cluster (`[exclusions]` is shared). Queries logged before stay (and the top lists rebuilt after a restart skip them too).
- In the UI: **Settings → Query handling → Kept out of the log**, with a toggle, checked before it's applied, and *Revert to the file*. Under a Git-managed configuration, change `[exclusions]` in Git; the UI shows the TOML to commit. API: `PUT /api/v1/exclusions/default`; MCP: `plan_set_exclusions`.

### Internal names
Some names are your own network talking to itself: reverse lookups of private addresses (`20.1.168.192.in-addr.arpa`) and, in Kubernetes, the cluster's names (`postgres.db.svc.cluster.local`). A pod's search list alone turns one lookup of `api.github.com` into three failed ones under `cluster.local` first. These **internal names** get their own top list, so the dashboard's **Top domains** shows what your network reaches outside:
- The dashboard's **Top domains** list switches between **Internet** and **Internal**. The NXDOMAIN list leaves internal names out too.
- Long names stay on one line. A Kubernetes service shows as its name with the namespace beside it (`postgres` and `db` for `postgres.db.svc.cluster.local`); a pod's search-list variants of one name are a single row marked **search suffix ×3**; long hash labels are shortened and reverse lookups show the address. Tap a row's count for the full name (with a **Copy** button) and, for a merged row, each variant with its count.
- They're still in the query log, the live view, a device's own top domains, the blocked list, exports, and Prometheus: nothing is hidden, only sorted.
- Internal by default: reverse lookups of private and local addresses (the same ranges as `[special] private_ptr_nxdomain`), and `cluster.local` with `[kubernetes] enabled`. Add your own, each with its subdomains, per node (`[telemetry]` isn't shared):
  ```toml
  [telemetry]
  internal_names = ["lan", "home.arpa"]   # a Kubernetes cluster domain other than cluster.local goes here too
  ```
- API: `GET /api/v1/stats/top?kind=internal`; MCP: `top_items` with `kind: internal`. At privacy level 1 and above the list holds hashed names, sorted the same way. Top lists rebuilt from a privacy-hashed query log after a restart count those names as domains.

### OpenTelemetry (OTLP)
Push the metrics to an OpenTelemetry collector (the OpenTelemetry Collector, Grafana Alloy, a hosted backend) instead of, or as well as, having Prometheus scrape them:
```toml
[telemetry.otlp]
endpoint = "http://otel-collector:4318"    # OTLP/HTTP; metrics go to <endpoint>/v1/metrics
interval_secs = 60
# headers = { "x-api-key" = "..." }        # for hosted collectors
```
- The metric set is exactly what `/metrics` serves: counters become cumulative monotonic sums, gauges stay gauges, and histograms keep their buckets. Resource attributes: `service.name = telltaledns`, `service.version`, `host.name` (the node name).
- Encoding is OTLP/HTTP with JSON, which every OTLP receiver accepts.
- For **query events as OpenTelemetry logs**, add an event sink with `format = "otlp_logs"` (below), pointed at `<collector>/v1/logs`. Each record has a one-line body (`A example.com from 192.168.1.5: blocked`) and attributes (`dns.question.name`, `dns.question.type`, `dns.response_code`, `client.address`, `client.name`, `telltale.status`, `telltale.list`, ...); blocks are `WARN`, the rest `INFO`.
- A collector that's down costs only that interval's points; DNS never waits for it.

### Exemplars and traces
From a latency graph to the query behind it.

- **Exemplars:** each bucket of `telltale_query_duration_seconds` carries an *exemplar*, a recent query that landed in it (its trace ID, its latency, and when it happened). They're in the OpenMetrics format, which Prometheus asks for by default. Prometheus keeps them when started with `--enable-feature=exemplar-storage`, and Grafana then shows them as dots on the latency panels (the bundled dashboard turns them on). Each bucket's exemplar is replaced at most once a second, so it's a recent example from that bucket, not the slowest query. `[telemetry.metrics] exemplars = false` turns OpenMetrics off; `/metrics` then always answers the plain Prometheus text format.
- **From the dot to the query:** in Grafana's Prometheus data source, under *Exemplars*, add a link with label name `trace_id` and URL `https://<your TelltaleDNS>/#/queries?trace=${__value.raw}` (or point it at your Tempo data source when traces go there).
- **The query behind a trace ID:** open the query log with `#/queries?trace=<ID>` (or `GET /api/v1/queries?trace=<ID>`, the MCP tool `search_queries` with `trace`). The ID holds the query's start time and a hash of its query-log fields, keyed with the cluster's privacy key, so it finds the row on whichever node logged it and can't be used to confirm a guessed name.
- **Traces:** send some queries to your OpenTelemetry collector as traces (Grafana Tempo, Jaeger, and the like):
  ```toml
  [telemetry.otlp]
  endpoint = "http://otel-collector:4318"   # traces go to <endpoint>/v1/traces
  traces_sample_every = 1000                # 1 query in 1,000 (0: none, the default)
  traces_slow_ms = 250                      # and every query that took at least 250 ms (0: none)
  ```
  Each query is a server span (`DNS A`, with `dns.question.name`, `dns.question.type`, `dns.response_code`, `client.address`, `network.transport`, `telltale.status`, `telltale.group`, `telltale.node`) and, when upstreams were asked, a client span for the wait (`upstream quad9`, with `telltale.upstream` and `telltale.attempts`; it's placed at the end of the query, since the event records how long the wait was, not when it began). A SERVFAIL marks the span as an error. Its trace ID is the same as the exemplar's and the query log's.
- Spans are built from the query event on the analytics thread and sent every 5 seconds, at most 512 queries per request. At most 4,096 wait; more are dropped, never slowing DNS. `telltale_traces_total{result="sent"|"dropped"|"failed"}` counts them.
- Names and clients follow the query log's privacy level: names hashed at 1 and above, no client address at 2 and above.

### dnstap
Stream client queries and responses, as the DNS messages themselves, to a dnstap reader (`dnstap-read`, `fstrm_capture`, Vector, Logstash, a network-security monitor):
```toml
[telemetry.dnstap]
socket = "/run/dnstap.sock"     # a reader listening on a Unix socket, or:
# address = "tcp://10.0.0.5:6000"
sample_every = 1                # 1 = every query; 10 = one in ten
buffer = 10000                  # copies held while the reader is slow
```
- Each sampled query becomes a `CLIENT_QUERY` and a `CLIENT_RESPONSE` message with the client's address, the transport (UDP, TCP, DoT, DoH, DoQ), the times, and the full query and response messages.
- Frame Streams with the usual handshake; if the reader isn't there, TelltaleDNS keeps retrying (every few seconds) and drops copies meanwhile. A reader that accepts the connection but stops reading is given up on after 5 seconds and reconnected, with a warning in the log. DNS never waits for it: copies go through a bounded queue (`buffer`), and with dnstap off the query path does nothing extra. Dropped copies are counted in `telltale_dnstap_dropped_total`.
- **Upstream traffic too** (`forwarder = true` under `[telemetry.dnstap]`): each query TelltaleDNS sends to an upstream and its answer become `FORWARDER_QUERY` and `FORWARDER_RESPONSE` messages with the upstream's address, port, and protocol (UDP, TCP, DoT, DoH, DoQ, DNSCrypt), sampled like client messages. The built-in recursive resolver's own queries aren't included.
- Read at startup: restart after changing it.

### Event sinks
Copy every query event to your own log pipeline (Loki, Elastic, Splunk, Graylog, a SIEM) as it happens:
```toml
[[telemetry.sink]]
name = "archive"
type = "file"                            # JSON lines, rotated
path = "/var/log/telltale/queries.jsonl"
max_bytes = "100MiB"                     # then queries.jsonl.1, .2, ...
keep = 3

[[telemetry.sink]]
name = "siem"
type = "syslog"                          # RFC 5424
address = "udp://192.168.1.20:514"       # or tcp:// (octet-counted frames), or tls://host:6514
# tls_ca = "/etc/telltale/siem-ca.pem"   # tls://: a private collector's CA (public roots always work)
facility = 16                            # local0
statuses = ["blocked"]                   # only blocks; empty means every event

[[telemetry.sink]]
name = "loki"
type = "webhook"                         # batched HTTP POST
url = "https://logs.example.net/ingest"
format = "json_lines"                    # or json_array, or otlp_logs (OpenTelemetry)
token_file = "/run/secrets/ingest-token" # sent as "Authorization: Bearer <token>"
# token_scheme = "Splunk"                # for Splunk HEC
batch = 500                              # events per POST
flush_secs = 5                           # or whatever arrived in 5 s
# spill_max_bytes = "64MiB"              # keep refused batches on disk until the collector is back
```
- Each event is the same JSON object as a row of `GET /api/v1/queries` (`time`, `client`, `clientName`, `group`, `name`, `qtype`, `status`, `rcode`, `proto`, `list`, `rule`, `totalMs`, `upstreamMs`, `answers`, `node`), with the query log's `privacy_level` applied (names hashed at 1, clients removed at 2).
- Syslog messages are `<PRI>1 <time> <host> telltale - query - <JSON>`, with severity *notice* for blocks and *informational* for the rest.
- **Syslog over TLS** (`tls://`, RFC 5425) sends the same octet-counted frames as `tcp://`, encrypted. The collector's certificate must name the host in `address` and come from a public CA or the one in `tls_ca`.
- Sinks never slow DNS: each one has its own buffer (`max_buffer`, 10,000 events) and thread. When a destination is slow or down, the buffer fills and new events are dropped, logged once a minute (`event sink fell behind`), and counted in `telltale_sink_dropped_total{sink}`. A webhook batch that fails is retried twice (after 1 s and 2 s), then dropped.
- **Spill to disk** (webhook sinks, `spill_max_bytes`): instead of being dropped, a refused batch is appended to `<data_dir>/sinks/<name>.spill`. Once the collector accepts a batch again (or on the next quiet moment), the kept events go first, oldest first, up to 20 batches at a time; the file is removed when it's empty. Past `spill_max_bytes`, batches are dropped as before. The file survives restarts. Off by default, and best kept modest on an SD card.
- Sinks are read at startup: restart after changing them.

## Device anomalies
TelltaleDNS learns how each device usually behaves and points out when that changes (the **Anomalies** page, `GET /api/v1/analytics/anomalies`, and the metric `telltale_anomalies_total{kind}`, with `telltale_anomalies_muted_total{kind}` for findings a [mute](#muting-a-kind-of-finding-for-a-device) matched):
- **Many more queries than usual** (`rate_spike`): this hour's queries against the device's usual count for this hour of the day.
- **Unusual traffic to one domain** (`domain_volume`): queries to one registrable domain in an hour against that device's usual volume for it. A spike one domain explains is reported once, as this.
- **Many new domains** (`drift`): registrable domains the device has never contacted, per day, against its usual number of new ones.
- **Regular phone-home** (`beacon`): a domain queried at a regular interval (low jitter) for at least 4 hours, when it wasn't periodic while the device was being learned.
- **Burst of failed lookups** (`nxdomain_storm`): in one minute, at least 30 NXDOMAIN answers to a device that are at least half its queries (malware probing generated names, or a broken app). In a minute whose reverse lookups of private addresses are a sweep (next), it's judged on the device's other lookups. This one needs no learning period; it's reported at most once an hour per device.
- **Sweep of local addresses** (`reverse_sweep`): in one minute, a device's reverse lookups of private addresses (the names under `in-addr.arpa` of `10/8`, `172.16/12`, `192.168/16`, `100.64/10`, `169.254/16`, `127/8` and `0/8`, and under `ip6.arpa` of `fc00::/7`, `fe80::/10` and `::1`) clear the same bar on their own: at least 30 NXDOMAIN answers, at least half of those lookups, and at least 16 different names answered NXDOMAIN. This device looked up the names of many addresses on your network: network scanners do this, and so do some TVs and NAS boxes, on their own, often once an hour. Those lookups then leave the burst check, which is judged on the device's other names, so you can [mute](#muting-a-kind-of-finding-for-a-device) the sweep for a device and still hear about a real burst of failed lookups from it. It counts and alerts like a burst, at most once an hour per device. Not a sweep: one name asked over and over (that stays a burst), a sweep of public addresses (a burst, as before), or one slower than 30 failed lookups a minute or spread over the minute's boundary (not seen, as before).
- **Chatty loop** (`chatty_loop`, for your information): a device asks one domain at a steady rhythm faster than every 30 seconds for an hour, such as a time-sync client every 2.5 s (at least 120 queries in the hour, 80 % of the gaps in one [rhythm](#a-devices-rhythm) column from 1 to 25 seconds). Reported once until the loop stops and starts again, with its rhythm strip. It's not counted as an anomaly: the sidebar badge and the `anomaly` alert leave it out, and an alert rule with `when = "chatty_loop"` asks for it.
- **Machine-generated-looking domains** (`dga`): new domains whose names look generated (`xjwqkzpvb.com`, `a8f3k2j9x1.org`), at least 2 in an hour. The score (0 to 1) uses how English-like the letter pairs are, letter/digit mixing, consonant runs, and character variety; 0.6 and up counts (0.75 at `low` sensitivity, 0.5 at `high`). Names made of real words score low even when generated.

**New domains:** the Anomalies page also lists each device's first-seen domains (after its first day), with their scores; `GET /api/v1/analytics/new-domains?since=-24h&client=<ip>` and the MCP tool `new_domains` return the same.

Every finding shows its evidence (what was seen, the usual value ± spread, the threshold, the window). Devices are quiet for their first `learning_days` (7) while their baseline forms; an alerted spike doesn't become the new normal. Findings never block anything: act on them yourself (look at the device's queries, move it to a stricter group).
```toml
[telemetry.anomaly]
enabled = true
learning_days = 7
sensitivity = "normal"         # low | normal | high
ignore_domains = ["apple.com"] # never reported (e.g. expected connectivity checks)
nxdomain_per_minute = 30       # NXDOMAIN storm: answers per minute...
nxdomain_percent = 50          # ...that are at least this share of the device's queries
                               # (a sweep of local addresses: the same two, over its own lookups)
```
The engine runs on the telemetry thread, never on the query path, keeps a few KiB per device (at most `max_clients`, 1024 by default), and saves its baselines to `<data_dir>/anomaly.json` hourly and on shutdown, so restarts don't restart the learning period. It's off when `[telemetry.qlog] privacy_level` is 1 or above (names and devices are hidden). Replaying the same queries always gives the same findings (fixed arithmetic on event timestamps, no machine learning).

### A device's rhythm
**Clients → Last hour → Rhythm** shows how regularly a device asks for each domain it talks to most (the ones the engine tracks, up to 16): one row per domain, one column per gap between two queries, on a log scale from under a second to two hours and longer, darker where more of the gaps fall.
- A timer is one dark, outlined cell with its period in words: a time-sync loop every 2.5 s, a phone-home every 5 min. A person browsing is a smear across many columns.
- **Recent** (the default) weighs the last couple of hours (each hour's close halves what was there and adds that hour); **This hour** shows only this hour. **Table** lists the counts.
- **usual** marks a rhythm the device already had while it was being learned; **new rhythm** one that has been regular for 4 hours or more and wasn't (the beacon detector reports it on the Anomalies page, where a beacon finding shows its own strip as it was when reported).
- Select a row for that device's queries to the domain. In a cluster, every node's view of the device is added together.
- It's measured, not judged: what alerts is still the beacon detector (30 s to an hour, low jitter, 4 hours). `GET /api/v1/clients/<ip>/rhythm` returns the bins and the words; the MCP tool `get_client_profile` includes the period and share per domain, and `find_anomalies` a beacon's bins. It needs the anomaly engine, so privacy level 0.

### A device's day
**Clients → Last hour → Day** (or **See the day** on an anomaly finding, or **Day timeline** on a device's heatmap) shows one device over a window (6 hours to 7 days) as swimlanes, from the query log:
- One lane per domain it talks to (the 30 busiest; the rest in **other**), one cell per bin (5 minutes over a day), darker for more queries. A red underline marks blocked answers, an amber tick answers slower than the latency objective. A **new** tag marks where a domain was first contacted.
- Under the lanes, the device's p99 answer time per bin; above them, dots for first contacts (hollow), anomaly findings (amber), blocked bursts (red, 10 or more blocked in a bin), and a diamond when the device's [identity](#what-is-this-device) changed (it now looks like a different product or class: "now looks like Roku player (was unknown)"), and grey ticks for changes. Select a dot for the page behind it, a lane's name for that device's queries to it.
- Point at a cell for its numbers. **Table** sums the bins into at most 24 columns. Nothing older than the query log keeps can be shown: that part is grey. If a read stops early, the drawer says so.
- In a cluster it reads the query log of the node you're on, with every node's rows that reach it. The same view within 30 seconds is answered from memory. At privacy level 1 the lanes have no names; from level 2 it isn't available.
- `GET /api/v1/clients/<ip>/timeline?from=-24h` and the MCP tool `device_timeline` (24 bins by default: hours over a day) return the lanes and the events; agents need `querylog:read`.

### Acknowledging findings
Once you've looked at a finding, acknowledge it: **Acknowledge** on its card (or **Acknowledge all**), `POST /api/v1/analytics/anomalies/acknowledge` with its `id`, or the MCP tool `acknowledge_anomalies`. It stops counting as new: the sidebar badge and anomaly alerts skip it, and the page hides it unless **Show acknowledged** is on, where it shows who acknowledged it, when, and the note. **Undo acknowledge** takes it back. Acknowledging blocks nothing and changes no configuration.
- It needs the operator role (agents: `ops:anomalies`) and is recorded in the audit log as `anomaly.ack` or `anomaly.unack`.
- **In a cluster** every node learns from the queries it answers, and the Anomalies page shows every node's findings (**Found by** names them; the same finding on two nodes is one entry). An acknowledgement made on any node is recorded by the primary and reaches every node within seconds, with the next configuration version; a node that was down gets it when it reconnects. It works in a GitOps-managed cluster too. On a replica that can't reach the primary, acknowledging fails with 503, like other changes.
- Acknowledgements are kept for 60 days from the finding's window.

### Muting a kind of finding for a device
Acknowledging clears one finding; a device that does something harmless every hour makes a new one every hour (two TVs that look up the reverse name of every address on the network get a few hundred NXDOMAINs a minute, which is a sweep of local addresses to the detector and nothing to worry about). A **mute** says: this kind of finding, for this device, stops counting. On the Anomalies page choose **Mute for this device…** on a finding: the device and the kind are filled in, you pick how long (a day, a week, or until you remove it) and write why, and the preview says what it will do before you save. The list of mutes below the findings has **Remove**.
```toml
[[anomaly_mute]]
name    = "lg-tv-reverse-sweep"
devices = ["lg-tv-living", "lg-tv-bedroom"]   # device names ([[client]]), IPs or CIDRs
# groups  = ["iot"]                           # or groups: their networks and the devices that name them
kinds   = ["reverse_sweep"]                   # rate_spike, domain_volume, drift, beacon, nxdomain_storm, reverse_sweep, dga, chatty_loop
expires = "2026-12-31T00:00:00Z"              # optional: it stops applying (a finding created later counts again)
note    = "hourly reverse-DNS sweep"
```
- **Recorded, not counted.** The finding is made as before and listed (turn on **Show muted** on the page, or `GET /api/v1/analytics/anomalies?muted=true`), marked with the mute that matched (`mutedBy`). It isn't counted in the sidebar badge, the `anomaly` alert rule, the health level, or `telltale_anomalies_total`; `telltale_anomalies_muted_total{kind}` counts it, so a mute never hides that something happened. The same kind of finding for any other device counts as usual.
- **Decided when the finding is created.** Removing a mute or letting it expire doesn't change findings already recorded; ones made afterwards count. Muting is not blocking: nothing about the device's queries changes.
- **Kinds are explicit.** A mute covers the kinds it lists and no other: one of `nxdomain_storm` doesn't cover `reverse_sweep`, and one of `reverse_sweep` leaves a real burst of failed lookups from the device counted.
- **Mutes made before 0.9.** Until 0.9 a sweep of local addresses counted as a burst of failed lookups, so a mute made to quiet one lists `nxdomain_storm`. After the upgrade that mute keeps meaning exactly that: it now mutes only the device's real bursts, and its sweeps count again. Change its kinds to `reverse_sweep` (or add it). On such a sweep the Anomalies page names the mute (`stormMute` on the finding) and says why, with **Mute for this device…** (the sweep ticked) and **Remove** for the old mute. If you raised `nxdomain_per_minute` to quiet a sweep, set it back and mute the sweep instead. An Alertmanager silence on `kind="nxdomain_storm"` doesn't cover `kind="reverse_sweep"` either.
- **Narrow on purpose.** A mute names at least one device or group and at least one kind: there is no mute for everyone or for every kind (to switch the detector off, `[telemetry.anomaly] enabled = false`). A MAC address isn't accepted: a device's address changes with its lease, and findings are made from addresses. Name the device (a `[[client]]` with an IP or network in its `match`) or give its IP: a device named only by its MAC address can't be muted by name, because it has no address to match findings against (keep an address among its keys if you need a mute). A group means its networks and the devices that name it.
- **In a cluster** a mute is shared like groups and schedules: set on the primary, it reaches every node, including ones that were down. In a cluster whose configuration comes from Git the page and the API refuse the change (409 `gitops_managed`): add the `[[anomaly_mute]]` block to the repository (or the Helm values' `config:`) instead. On a single node that loads its configuration from Git, a mute made here is saved and the response includes the TOML to keep. Name `reverse_sweep` in a mute only once every node runs 0.9: a node on an older version refuses a shared configuration that names it, and an older build won't start with it in its own file. Such a node keeps serving the last version it took (DNS isn't affected), and it takes no later shared change either. Until it's upgraded, it logs `cluster configuration not applied (will retry)` with `unknown variant reverse_sweep` every few seconds. Its `sync_errors` cluster check ("Last sync failed: …") and `telltale_cluster_sync_error` show the same. Until every node is upgraded, one sweep can show twice: as a burst of failed lookups from an older node and as a sweep from a newer one.
- **Going back to an older version** after naming `reverse_sweep`: take it out of the mutes in your files first (one made on the page or through the API is skipped, with a warning, by the older version). Anomaly baselines saved after a sweep was found can't be read by an older version, so its devices learn again for 7 days; DNS isn't affected.
- **Through the API:** `PUT /api/v1/anomaly-mutes/<name>` with the same fields (add `?dryRun=true` to preview), `DELETE` to remove, `GET /api/v1/config/entries?kind=anomaly_mute` to list. The operator role; agents need `config:write:anomalies` (a mute can hide a compromised device, so it isn't part of any other scope, though `config:write:*` includes it) and use `plan_set_anomaly_mute` / `plan_remove_anomaly_mute`. Every change is audited as `config.anomaly_mute`.

## Alerts
TelltaleDNS can tell you when something needs attention: by email, on your phone through [ntfy](https://ntfy.sh) or Gotify, in a Slack-compatible channel (Slack, Mattermost, Discord's `/slack` webhook URL), or on any webhook.
```toml
[alerts]
interval_secs = 30                       # how often rules are checked

[[alerts.destination]]
name = "phone"
type = "ntfy"                            # webhook | ntfy | gotify | slack | email
url = "https://ntfy.sh/my-home-dns"
# token_file = "/run/secrets/ntfy-token" # an access token, kept out of the config

[[alerts.rule]]
name = "Upstream down"
when = "upstream_down"                   # an upstream is benched (its circuit breaker is open)
for_secs = 60                            # only if it lasts a minute
to = ["phone"]

[[alerts.rule]]
name = "Too many failures"
when = "servfail_rate"
threshold = 5                            # percent of queries over the last 5 minutes
to = ["phone"]
```
Rules watch:

| `when` | Alerts when | One alert per |
|---|---|---|
| `upstream_down` | an upstream is benched (its circuit breaker is open) | upstream |
| `node_down` | a cluster node isn't connected | node |
| `list_failing` | a list fails to update | list |
| `list_stale` | a URL list's content hasn't changed in `stale_after_days` (default 30; see [Lists that stopped changing](#lists-that-stopped-changing)) | list |
| `servfail_rate` | SERVFAIL above `threshold` % (default 5) over 5 minutes, at least 50 queries | node |
| `anomaly` | a [device anomaly](#device-anomalies) is found, unless it is acknowledged or [muted](#muting-a-kind-of-finding-for-a-device) | finding |
| `update_available` | a newer TelltaleDNS build is out | version |
| `sync_lag` | a replica (never a witness) is behind the primary's configuration (set `for_secs`, say 300, so a normal sync stays quiet) | node |
| `new_device` | a device TelltaleDNS has never seen starts asking, on any node (quiet for the first day after a fresh start, while every device is new) | device |
| `disk_full` | a node's data disk is more than `threshold` % full (default 90) | node |
| `plan_pending` | an AI agent's change waits for approval (`[agents] require_approval`) | plan |
| `slo_burn` | a [service-level objective](#service-level-objectives) spends its error budget fast (14.4× over 1 hour and 5 minutes, or 6× over 6 hours and 30 minutes) | objective |
| `probe_failing` | a [listener check](#listener-checks) (or an extra target) got no answer twice in a row, on any node | node and target |
| `cert_expiring` | a DoT/DoH/DoQ listener's certificate expires within `threshold` days (default 14), on any node | node and listener |
| `maintenance` | a node is in [maintenance](#taking-a-node-down-for-maintenance) (resolves when it leaves; use `for_secs = 0` to hear at once) | node |
| `rollout_failed` | a [staged rollout](#rolling-a-change-out-in-stages)'s guard failed a version and pinned the cluster to the one before, with the reason | version |
| `cluster_pinned` | the cluster is [pinned](#pinning-the-cluster-to-a-version) to an older version, so changes wait (raise `for_secs` if you pin on purpose for long) | cluster |
| `chatty_loop` | a device asks a domain at a steady rhythm faster than every 30 s (an informational finding the `anomaly` rule leaves out; see [Device anomalies](#device-anomalies)) | finding |
| `drill_report` | a [failover drill](#failover-drills)'s report is ready, scheduled or started by hand: followed, stuck, quiet, coverage | drill |

- **Nodes in maintenance** are left out of the per-node conditions, and an alert about one that was firing resolves with "(maintenance)". When the window ends, `for_secs` counts from zero. The Alerts page says whose alerts are paused, until when.
- A condition must hold for `for_secs` (60 by default) before the alert goes out, so a short blip stays quiet; when it clears, a "Resolved" message follows. Anomalies, updates, new devices, pending plans, and failed rollouts go out once each.
- **`upstream_down` follows the open state only:** while a benched upstream is probed again (by a query, or on a node without queries by a health check) it shows as half-open for that one attempt, so a check of the rules that lands then resolves the alert, and it fires again `for_secs` later if the upstream is still down.
- In a cluster, the primary checks the rules against the whole cluster's data and sends the alerts, so you get one message, not one per node.
- Formats: `webhook` posts JSON (`rule`, `status` = `firing` or `resolved`, `subject`, `summary`, `node`, `time`); `ntfy` posts the text with a title and priority (a token from `token_file` as a Bearer token); `gotify` posts to `<url>/message` with the application token from `token_file`; `slack` posts `{"text": ...}`. `webhook` and `slack` send no token, so they don't read a `token_file`.
- Alerts never affect DNS: a destination that's down is logged (`alert not delivered`) and skipped.
- **In the UI:** **Alerts** (under System) shows what's firing now and how the last delivery to each destination went, and adds, changes, or removes destinations and rules like other configuration (a dry run first; on a Git-managed cluster it says what to add to Git). **Send test** on a destination sends a test message and shows the result, a wrong password or an unreachable server included. When an email destination's private CA file (`tls_ca`) can't be used, only an administrator is told why (ADR-180).
- **API:** `GET /api/v1/alerts` (firing alerts and deliveries), `PUT`/`DELETE /api/v1/alerts/destinations/{name}` and `/api/v1/alerts/rules/{name}` (same fields as the configuration, with `?dryRun=true`, `If-Match`, and `Idempotency-Key`), and `POST /api/v1/alerts/destinations/{name}/test`. Agent tokens need `config:write:alerts`. Passwords and tokens stay in files on the node: only their paths go through the API.
- **Credential files are set by an administrator.** The node reads `token_file` and `password_file` when it sends and passes what they hold to the destination, so a destination that names either one, before or after the change, is added or changed in the UI or the API only by an administrator (an admin's sign-in or API token; no agent token, whoever owns it). Anyone with the operator role (agents: `config:write:alerts`) keeps every destination without one, can delete any destination, and can send a test to any. Destinations in the config files aren't affected (ADR-179).
- **Credential files set in the UI or the API live in a folder meant for secrets:** `/run/secrets/` (Docker and Compose secrets), `/etc/telltale-secrets/` (the Helm chart's `secretMounts`), or the data directory's `secrets/` folder (`/var/lib/telltale/secrets/` by default; create it with mode 0700 and the file with 0600, owned by the service's user). Give an absolute path, without `.` or `..`; links are followed, so a Kubernetes Secret's files work, and one that leads out of the folder doesn't. Anything else is refused (422, saying which field). The file doesn't have to exist yet. The folders bound where a file may be, not which secret it is: `/etc/telltale-secrets/` also holds the chart's other mounts (an OIDC client secret), and a Compose host's `/run/secrets/` can hold other services' secrets, so give a destination a file of its own.
- **Which destinations are checked when they send:** every one that names a credential file, unless this node's own config files (or, on a Git-managed primary, the commit in use) define it exactly the same way; those keep any path. So the check also covers an API override of a file's destination, a replica's **Send test**, a primary promoted after a failover (its destinations came from another node), and a primary pinned to a version (its destinations come from an earlier version of its own configuration). One that fails isn't read or sent to: the log names it once per configuration change (`not sent: ...`), and the Alerts page and **Send test** show why. **On a node that follows another,** a destination from the primary's config files whose file is outside the folders isn't sent from this node unless its own files define it the same way, and **after a failover the new primary doesn't send to it** until its file moves into a folder or that node's own files define it the same way. With the Helm chart every pod mounts the same ConfigMap, so that case doesn't arise there. **While the cluster is pinned,** editing a config-file destination whose file is outside the folders stops it being sent until the pin ends: the pinned version still has the old definition. If the check itself can't run, no destination with a credential file is sent until it can; if the config files couldn't be read at start-up, every destination with a credential file is held to the folder rule until a reload reads them.
- **After upgrading,** a destination made in the UI or the API whose file is somewhere else stops sending until an administrator saves it with a file in one of those folders. Review the destinations made in the UI or the API that have a credential file (**Alerts**, or `GET /api/v1/config/entries?kind=alert_destination`), and look in the audit log for `alert_destination.put` by someone who isn't an administrator.
- **Prefer `https://` for a destination with a credential file.** On a node whose own resolver is TelltaleDNS, anyone who may add local names or forwarded domains can change where an `http://` destination's host resolves, and a token sent over `http://` would go to that address. `https://`, `smtps://` and STARTTLS check the server's certificate.

### Email
Any mail account that allows SMTP sign-in works; you don't need a mail server of your own:
```toml
[[alerts.destination]]
name = "inbox"
type = "email"
url = "smtp://smtp.gmail.com:587"        # STARTTLS; smtps://host:465 for TLS from the start
from = "you@gmail.com"
to = ["you@gmail.com"]                   # one or more
username = "you@gmail.com"
password_file = "/run/secrets/smtp-password"
```
- **Gmail:** turn on 2-Step Verification, then make an app password (Google Account → Security → App passwords) and put it in `password_file`. Outlook.com, Fastmail, iCloud, and most providers work the same way with their SMTP host and an app password.
- **Encryption is required** whenever a password is sent: `smtp://` must offer STARTTLS (there's no fallback to plain), and `smtps://` is TLS from the first byte. Certificates are checked against the built-in public roots; for a private mail server, give its CA in `tls_ca`.
- `smtp+insecure://host:port` sends without encryption and without a password: only for a local mail catcher such as [Mailpit](https://mailpit.axllent.org) while testing (`docker run -p 8025:8025 -p 1025:1025 axllent/mailpit`, then `url = "smtp+insecure://127.0.0.1:1025"` and open http://127.0.0.1:8025).
- The message is plain text: the summary, then the rule, status, subject, node, and time (UTC). The subject starts with `[TelltaleDNS]`, which makes a mail filter easy.
- In Kubernetes, keep the password in a Secret mounted as a file, never in the values or Git.

## Web UI
Open `http://<server>:8053/` in a browser. On first start it asks for the setup token (see [Users and sign-in](#users-and-sign-in)) and creates the first admin.

| Page | What it shows |
|---|---|
| Dashboard | queries, blocked %, cache hits, upstream latency, active clients, each with its change against the previous period; one chart whose hover gives the exact figures for each moment (totals and blocked, or the split by status; the Advanced view adds traffic by group and upstream exchanges), with a **Table** view and the change markers; the [service level](#service-level-objectives) (each objective's last 30 days, error budget left, and burn rates); where time goes; top domains, blocked names, and clients with their groups, one line each (click a name to open the query log, tap a count for the full name); upstream share and health. In a cluster, **Showing** switches between every node together, one node, or one site's nodes (remembered in your browser) |
| Query log | search by name (contains, exact, subdomains, wildcard, regex, or none of these), client, status, type, response code (each can be turned around: "not"), slowness, and time; each row shows how long it took and how much of that was the upstream; **Why?** explains the decision. Filters live in the URL, so a search can be bookmarked or shared. **Live** streams new matching queries as they happen (the newest 500 stay on screen) |
| Explain | why any name is or isn't blocked for any device |
| Clients, Groups, Lists, Upstreams | devices seen and configured; groups and their lists; list download state and size; upstream health (Healthy, Benched, or Probing: the circuit breaker's closed, open, and half-open), traffic, failures by kind (timeouts, connection errors, SERVFAIL, ...), and latency |
| Settings | your password and two-factor sign-in, how domain names are drawn ([Domain icons](#domain-icons)), testing a translation of the UI ([Language packs](#language-packs-for-translators)), API tokens, users and the audit log (admins), system information, and the cache ([Cache tools](#cache-tools)) |

Every chart has a **Table** view. The UI follows the system's light or dark theme (or pick one in the header) and works on phones. Upstreams, lists, and groups can be added and changed on their pages ([Changing the configuration in the UI](#changing-the-configuration-in-the-ui)).

The menu ends with the health icon ([Health](#health)), links to the project on GitHub and its site (plain links: the UI fetches nothing from the internet), then this node's name and version.

The UI is in English. For developers, `?lang=en-XA` before the `#` (`http://<server>:8053/?lang=en-XA#/`) shows it with accented, longer text for that one page load, to find text that does not go through the translation layer; nothing is stored.

### Domain icons
A small mark sits left of each name in the dashboard's **Top domains** and **Top blocked** lists and in the query log. The page draws it from data it already has, so nothing is fetched and nothing about your queries is sent to anyone: no favicon service is involved, and the page's content security policy still allows images only from itself.
- A **brand** TelltaleDNS knows gets its colour and logo mark: `netflix.com`, `www.youtube.com`, and a CDN name such as `nflxso.net` (Netflix). About a hundred and twenty brands are known, from two packs: [Simple Icons](https://simpleicons.org) (CC0) first, and [Bootstrap Icons](https://icons.getbootstrap.com) (MIT) for the marks Simple Icons has dropped (Microsoft and Teams, Amazon, LinkedIn, Slack, OpenAI, Xbox, Bing, Skype, Windows, Nintendo); see the [third-party notices](third-party-notices.md). A few large companies' marks are in neither (Disney+, Hulu, Minecraft, Adobe, the BBC, Walmart, AWS): their names get a monogram.
- Every other name gets a **monogram**: its owner's first letter, in a colour that is always the same for that owner. A name of your own network (`.arpa`, `.lan`, `.local`, Kubernetes) gets a small house. A blocked name's mark is drained of most of its colour. When a privacy level hides names, there are no icons.
- **Settings → Account → Domain icons** picks the style (**Brand and monogram**, **Monogram only**, or **Off**) and the size (**Default**, 20 px, or **Small**, 16 px). The choice is kept for you in this browser. With **Monogram only** or **Off**, the brand marks aren't even downloaded.

### Language packs (for translators)
**Settings → Account → Test a language pack** (in the Advanced view) lets someone translating TelltaleDNS see their translation in this web UI before sending it to the project: type a language tag (`de`, `pt-BR`, `zh-Hant`), download the template (`<tag>.json`, every English text of this build) and the notes for translators, fill in the translations, choose the file, and the card checks it with the same rules the project's check applies: what breaks a rule (shown in English), what is missing, what is left over. **Use this pack…** then shows the UI in that language in this browser, and **Download for a pull request** gives the file in the exact form the project keeps. The project site's page [Write a language pack](https://paimonsoror.github.io/telltaledns/dev-languages.html) is the whole path, with examples, from the template to the pull request.
- The file stays in this browser, for this TelltaleDNS address. Nothing about it is sent to TelltaleDNS, kept on a node, copied to other nodes, backed up or written to the audit log.
- It is yours: it shows only while you are signed in. Someone else who signs in at the same browser sees their usual language, and a banner that says another user of this browser loaded a test pack.
- It is removed at the next page load after any upgrade (of the web UI or the server, a rollback or a downgrade included; after an upgrade of the server alone, at the first page after you sign in), 7 days after you loaded it (sooner if this computer's clock is set back to before that time), when the copy kept in the browser can't be read, when it could not be checked twice in a row (an error in the check itself, not a finding about your file), when a page can't be drawn with it (the page then loads once more without it), or with **Remove** in the banner or the card. A tab left open never removes or replaces a pack you loaded in another tab since.
- While it is in use, an English banner above every page names the file and its fingerprint. The sign-in, setup and two-factor screens stay in your usual language unless you choose **Show the test pack on this page** (one page load). When you sign out, or your session ends, the page reloads in your usual language (if you signed in with a sign-in provider, signing out takes you to the provider's sign-out first, and the page it sends you back to, or the one Back returns to, is in your usual language), and the pack is back when you sign in again. While a sign-out is still waiting for the server's answer, a sign-in page drawn meanwhile can show the pack's text until the answer comes, and a further click on **Sign out** waits for the same answer. `?lang=en` before the `#` shows real English for one page load.
- A pack can make a label say something other than what a button does: load only a pack you made, or one from someone you trust, and load other people's packs only on a test installation.

### Health
The icon at the bottom of the menu says how TelltaleDNS is doing, for every node of a cluster, and changes shape as well as color:

| Icon | Level | When |
|---|---|---|
| circle with a check (quiet) | healthy | nothing below |
| triangle with "!" (amber) | degraded | DNS answers, but something needs a look: one upstream isn't answering while its group still has others; a cluster node is unreachable, not serving, or behind on configuration for a minute; a list fails to download, or [hasn't changed in 30 days](#lists-that-stopped-changing); a device was rate-limited in the last 5 minutes; SERVFAIL for 5% or more of the last 5 minutes' queries; a data disk is over 90% full; a [service-level objective](#service-level-objectives) burns its error budget fast; a [listener check](#listener-checks) fails twice in a row; a listener's certificate expires within 14 days |
| octagon with "×" (red) | severe | DNS is failing for some devices: no upstream in a group answers, no node serves DNS (its listeners aren't bound, or none answers its own check), SERVFAIL for 25% or more, or a listener's certificate has expired |

Click it for every reason, its node, and a link to the page to look at. On a phone, where the menu is hidden, a dot on the menu button shows when the level isn't healthy. Device anomalies don't change the level; they have their own badge. A node in [maintenance](#taking-a-node-down-for-maintenance) is left out of the level (its conditions, and its being unreachable) and listed instead ("1 node in maintenance until 14:00 (SD card swap)"); a node in maintenance that still answers counts as serving. The same answer is at `GET /api/v1/system/health` and in the MCP tool `health`. Each condition is judged over a window it already has (the upstream's circuit breaker, the last 5 minutes, the cluster heartbeat), so one failed lookup doesn't change the icon.

The UI is part of the binary (about 100 KiB compressed). The page is served with a strict Content Security Policy and can't be framed.

### Changing the configuration in the UI
The Upstreams page (servers and upstream groups), the Lists page, and the Groups page each end with a **Manage** table: every entry with where it comes from.

| Badge | Meaning |
|---|---|
| config file | defined in `telltale.toml`; **Edit** makes an override, **Remove** hides it |
| added here | made in the UI or API; **Remove** deletes it |
| overrides the file | the UI's version replaces the file's entry of that name; **Revert to the file** brings the file's version back |
| hidden | the file's entry is left out; **Revert to the file** brings it back |

Each change is checked first: **Check** shows what it will do and any warnings (an upstream group that would lose its last member, a list no group uses), and nothing is saved until **Apply**. For upstreams and lists, **Test it** also tries the draft from this node: an upstream is asked for the root's NS records (it shows the answer and the time, or the error: a bad URL, a TLS name that doesn't match, a timeout), and a list is downloaded and parsed (how many rules, and the first lines it can't use). The API calls are `POST /api/v1/checks/upstream` and `POST /api/v1/checks/list`, with the same body as saving; agents use the MCP tools `check_upstream` and `check_list`. An agent's list check says how many lines couldn't be used and why, but not their text, since that is whatever the URL served; people see the lines in the UI. When a TLS file an upstream draft names (`tls_ca`, `tls_client_cert`, `tls_client_key`) can't be used, an administrator is told why and anyone else only that it couldn't be, not what the file holds or why (the node's log has the detail). A valid certificate file builds, so the check then answers as for any upstream. A change that would leave the configuration invalid is refused with the reason, and nothing is saved: it is checked against the configuration this node applies, its config files (on a primary promoted after a failover, the cluster version it continues from) plus everything made in the UI, with the change. Operators and admins can make changes; every change is audited and reaches every node in a cluster.

Changes are stored in `state.db`, next to named devices and local names. **The config files are never rewritten**: what's in the files stays as written, and `telltale config check` on the files alone still shows the file configuration. Simple view shows the common fields; switch to Advanced for timeouts, TLS names, refresh intervals, blocked-answer modes, priorities, and colors.

**Keep it in Git.** On a node whose configuration comes from Git (`[cluster] config_source = "gitops"`, as with the Helm chart and Argo CD or Flux), the change works at once, but a rebuild from Git won't have it. After **Apply** the UI shows the TOML to add to the repository (with the Helm chart: under `config:` in the values) with a **Copy** button, or which block to remove. Once Git has it, **Revert to the file** removes the UI's copy. The API returns the same text as `keepInGit`.

The same through the API: `PUT` or `DELETE` on `/api/v1/upstreams/{name}`, `/api/v1/upstream-groups/{name}`, `/api/v1/lists/{name}`, and `/api/v1/groups/{name}`, with `?dryRun=true` to preview. The body has the same fields as the TOML section. `GET /api/v1/config/entries?kind=list` lists the entries with their sources. Plugin upstreams (`exec://`, `unix://`) aren't made here: they're defined in the config file ([Plugin upstreams](#plugin-upstreams)).

## API
A REST API (JSON) listens on `0.0.0.0:8053` by default and also serves `/metrics` and the health probes:
```toml
[api]
enabled = true
listen = "0.0.0.0:8053"
```
- The full description is at `/api/v1/openapi.json` (OpenAPI 3.1), so any OpenAPI tool or AI agent can explore it. The same document is in the repository as `docs/api/openapi.json`.
- Every endpoint except sign-in, `/auth/status`, the OpenAPI document, and the probes needs a sign-in ([Users and sign-in](#users-and-sign-in)). The listener also answers only clients inside `[access] allowed_networks`.
- Times take RFC 3339 (`2026-10-03T12:00:00Z`) or a relative offset (`-24h`, `-15m`). Lists come back as `{"items": [...]}`; the query log pages with `nextCursor` → `cursor`. Errors are `application/problem+json` with a stable `code` and a `hint` saying what to change.

| Endpoint | What it returns |
|---|---|
| `GET /api/v1/system/info` | version, node, uptime, listeners, query log on/off, active filter snapshot |
| `GET /api/v1/system/health` | `healthy`, `degraded`, or `severe`, with every reason, its node, and where to look ([Health](#health)) |
| `GET /api/v1/analytics/anomalies?acknowledged=false` | device anomalies from every node, each with its `id` and who acknowledged it; `POST /api/v1/analytics/anomalies/acknowledge` (or `/unacknowledge`) with `{"ids": [...], "note": "..."}` marks them seen ([Acknowledging](#acknowledging-findings)); `muted=true` also lists findings an [anomaly mute](#muting-a-kind-of-finding-for-a-device) matched, each with `mutedBy` |
| `PUT` / `DELETE /api/v1/anomaly-mutes/<name>` | mute kinds of finding for devices or groups, or remove the mute ([Muting](#muting-a-kind-of-finding-for-a-device)); listed by `GET /api/v1/config/entries?kind=anomaly_mute` |
| `GET /api/v1/stats/summary?from=-24h` | queries, blocked %, cache hit %, NXDOMAIN/SERVFAIL, active clients, latency by path |
| `GET /api/v1/stats/timeseries?step=minute&from=-1h` | counts per second or minute by status, type, and response code |
| `GET /api/v1/stats/top?kind=blocked&limit=10` | top `domains`, `blocked`, `nxdomain`, or `clients` (add `client=IP` for one device's domains; `hour=previous` for the last complete hour, and for clients `hour=rolling` for the last hour whatever the clock hour) |
| `GET /api/v1/stats/latency?by=upstream` | percentiles by `path`, `qtype`, `upstream`, or `stage` |
| `GET /api/v1/queries?name=ads&status=blocked&from=-1h` | the query log, newest first (filters: `name` + `match`, `client`, `status`, `qtype`, `rcode`, `upstream`, `minLatencyMs`, `from`, `to`; `nameNot`, `clientNot`, `statusNot`, `qtypeNot`, `rcodeNot` keep what a filter does not match) |
| `GET /api/v1/audit?action=user.`, `GET /api/v1/audit/verify` | the audit log, newest first, and a check of its hash chain (admins) |
| `GET /api/v1/queries/stream?status=blocked` | live queries as Server-Sent Events (`event: query` with a query-log row, `event: dropped` with how many matching queries were skipped). Filters: `name` + `match` (not regex), `client`, `group`, `status`, `qtype`, `upstream`, `minLatencyMs`, and `nameNot`, `clientNot`, `statusNot`, `qtypeNot` to keep what a filter does not match; `rate` caps events per second (default 500, at most 2000). At most 16 streams per node; follows the query-log privacy level (level 3: off) |
| `GET /api/v1/explain?name=ads.example.com&client=192.168.1.20` | why a name is or isn't blocked for a device ([explain](#why-was-it-blocked-explain)) |
| `GET /api/v1/lists`, `/groups`, `/clients`, `/upstreams` | the running configuration with list download state and upstream health (each upstream's `failuresByKind` says whether its failures were timeouts, connection errors, bad replies, unresolved names, SERVFAIL, REFUSED, or other errors) |

The `upstream` filter (on `/queries`, the live tail, and in vqlog) takes an upstream's ID from `/api/v1/upstreams` and finds the forwarded queries it answered. When several devices ask the same name at once, one upstream answer serves them all, and each of their queries names that upstream. Queries logged by earlier builds carry none.

```sh
curl -sN -H "Authorization: Bearer $TOKEN" 'http://dns.lan:8053/api/v1/queries/stream?status=blocked'   # watch blocks live
TOKEN=tt_...   # create one under "API tokens" below
curl -s -H "Authorization: Bearer $TOKEN" 'http://dns.lan:8053/api/v1/stats/top?kind=blocked&limit=5'
curl -s -H "Authorization: Bearer $TOKEN" 'http://dns.lan:8053/api/v1/queries?client=192.168.1.20&limit=20'
```

### From the shell: `telltale ctl`
The same API from a terminal, with an API token (Settings → API tokens, or `POST /api/v1/tokens` from a signed-in session):
```sh
export TELLTALE_TOKEN=tt_...                 # or --token-file /path/to/token
telltale ctl status                          # version, uptime, the last day's numbers
telltale ctl queries --status blocked --from -1h
telltale ctl top blocked --limit 20
telltale ctl block tiktok.com --group kids --for 120 --note "homework time"
telltale ctl allow cdn.example.com --device living-room-tv
telltale ctl rules                           # quick rules; `ctl unrule <id>` removes one
telltale ctl pause --minutes 10              # `ctl resume` to undo
telltale ctl maintenance start --for 30m --reason "SD card swap"   # `ctl maintenance end` to undo
telltale ctl flush --name example.com --subtree
telltale ctl lists                           # with unique names and hits
telltale ctl plans                           # agents' pending changes; `ctl approve <id>` / `ctl reject <id>`
telltale ctl get stats/latency by=upstream   # any endpoint (raw JSON)
telltale ctl put groups/kids --data '{"lists": ["oisd-small"]}'
```
- It talks to the node in `[api] listen` from your config (or `--url http://dns.lan:8053`), prints tables, and `--json` prints the API's own JSON for scripts. Errors show the API's explanation and hint; the exit status is non-zero.
- `block` and `allow` take `--dry-run` to see what would change. Rule IDs come from the domain (`block-tiktok-com`).

## AI agents and automation
Give an AI assistant (or any automation) an **agent token** instead of your own account. Create one in **Settings → API tokens → for an AI agent**, or with `POST /api/v1/tokens` from a signed-in session (the session cookie and `X-CSRF-Token`: a token can't create tokens):
```json
{"name": "assistant", "kind": "agent", "scopes": ["analytics:read", "config:read"], "group": "kids", "ratePerMinute": 60}
```

| Scope | Allows |
|---|---|
| `analytics:read` | statistics, top lists, latency, anomalies, explain, cluster status |
| `querylog:read` | the query log and live tail: who asked for what |
| `config:read` | lists, groups, devices, upstreams, local names, forwarded domains |
| `config:write:clients`, `config:write:records`, `config:write:forwards`, `config:write:rules`, `config:write:lists`, `config:write:groups`, `config:write:upstreams`, `config:write:ratelimit`, `config:write:anomalies` (`config:write:*` for all) | name and regroup devices; change local names; send domains to other servers; make quick rules; change lists, groups, and upstreams; change the rate limit; mute kinds of device anomaly |
| `ops:pause`, `ops:cache`, `ops:anomalies`, `ops:maintenance`, `ops:annotate` | pause blocking; flush the cache; acknowledge device anomalies; start and end [node maintenance](#taking-a-node-down-for-maintenance) (at most 2 hours); leave [notes](#change-markers) on the time charts |
| `ops:drill` | start and end [failover drills](#failover-drills) (at most 5 minutes; never a default scope) |
| `cluster:admin` | promote a node to primary |
| `cluster:upgrade` | ask native nodes to [install a newer version](#upgrading-from-the-cluster) (admin level, never a default scope, never granted to an OAuth sign-in for MCP: make an agent token for it, as the chart's upgrade hook needs) |

The default is `analytics:read` and `config:read`: read-only, without the query log. A token never gets more than its owner's role allows. `config:read` also lets an agent read the MAC address of any address it asks about, through `identify_device` and explain (the same MAC addresses the device keys in `GET /api/v1/clients` show); a token limited to a group, or with `analytics:read` alone, doesn't get them. The router's lease list (`/api/v1/dhcp/leases`) stays closed to agents.

**What an agent can't do:**
- Anything not listed above is refused. That covers users, tokens, passwords, backups, and the audit log.
- With `group`, it sees and changes only that group's devices and queries, and other views are refused.
- An agent limited to a group, or without `querylog:read`, doesn't get what it couldn't read otherwise:
  - Deleting a copy stored in the UI that isn't in effect (a device of the config files, or of the cluster version a promoted primary builds on, has its name, or the devices made in the UI don't apply) answers that copy by its name only; the audit log keeps it whole.
  - A refused device change whose reasons can name devices it can't read says, instead of them, that the change conflicts with another device, which the answer doesn't name (the hint says what to do), or that the devices made through the API don't apply now; an operator sees why when making the change in the UI.
  - A delete it makes while the devices made through the API don't apply says that, without the reasons.
  - On a pinned cluster, a change it sends is refused with the pin and the sections it holds back, without the diff.

**Every change from an agent:**
- needs an `X-Telltale-Reason` header (refused with 400 without one);
- is recorded in the audit log as `agent:<token> (owner: <you>)`, with the agent software from `X-Telltale-Client`;
- can be tried first with `?dryRun=true`. That works for every change (devices, names, forwarded domains, quick rules, lists, groups, upstreams, promotion); the answer says what would change, with the numbers behind it (`impact`, `recentQueries`), and nothing changes.

**Limits:** agents get 120 requests a minute each (`[agents] rate_per_minute`, or the token's `ratePerMinute`). Over the limit, they get 429 with `Retry-After`.

**Kill switch:** `[agents] enabled = false` refuses every agent token at once, on every node of a cluster, while people and their own tokens keep working.

### MCP (Model Context Protocol)
Every node serves MCP at `http://<node>:8053/mcp` (Streamable HTTP), so agents like Claude can use TelltaleDNS directly. Authenticate with an agent token (`Authorization: Bearer tt_…`).

For agents that start their tools as a subprocess, use the stdio transport. It relays to a node (`TELLTALE_TOKEN` or `--token-file`; the address comes from `--url` or the config files):
```json
{"mcpServers": {"telltale": {"command": "telltale", "args": ["mcp", "--stdio", "--url", "http://192.168.1.2:8053"],
                             "env": {"TELLTALE_TOKEN": "tt_…"}}}}
```

| Tool | What it answers |
|---|---|
| `get_overview` | queries, blocked %, cache hits, NXDOMAIN, clients, latency for a window |
| `top_items` | top domains / blocked / NXDOMAIN / clients, per client or group |
| `search_queries` | the query log, filtered and paged (needs `querylog:read`) |
| `explain_decision` | why a name was blocked or routed for a client |
| `get_client_profile` | a device: identity, groups, recent and slow queries |
| `latency_breakdown` | percentiles by stage, upstream, client, or query type |
| `health` | healthy, degraded, or severe, and why (start here when something seems wrong) |
| `upstream_health` | upstream health (healthy, benched, probing), latency |
| `list_effectiveness` | list sizes, updates, errors, hits, unique names, and overlap |
| `find_anomalies` | device anomalies from every node with evidence (including NXDOMAIN storms and DGA-like names), optionally only the unacknowledged ones, or with `muted` also the ones a mute matched |
| `list_anomaly_mutes` | the [anomaly mutes](#muting-a-kind-of-finding-for-a-device): devices or groups, kinds, end time, note (needs `config:read`) |
| `acknowledge_anomalies` | marks findings as seen on every node, or takes it back with `undo` (needs `ops:anomalies`; changes at once, audited) |
| `new_domains` | domains devices contacted for the first time, with DGA scores |
| `vqlog` | any count, top list, percentile, or time series over the query log, in one query (needs `querylog:read`; below) |
| `cluster_status` | members, roles, sync, versions, checks, each node's maintenance window |
| `list_annotations` | what changed and when: every node's [change markers](#change-markers), newest first (needs `analytics:read`) |
| `annotate` | leave a note on every time chart (needs `ops:annotate`; changes at once, audited) |
| `start_maintenance`, `end_maintenance` | put a node in [maintenance](#taking-a-node-down-for-maintenance) for up to 2 hours (not ready, still answering, alerts paused), or end it (needs `ops:maintenance`; changes at once, audited) |
| `plan_failover_drill` | plan a [failover drill](#failover-drills): the preview lists every precondition, the baseline, and the devices (needs `ops:drill` to apply; never a default scope) |
| `drill_report` | the newest drills, or one report: who followed, who was stuck, time to failover, who came back |
| `get_config` | one configuration section (no secrets) |

### Analytics in one query (vqlog)
`vqlog` is a small query language over the query log, for agents and for you: one query instead of many narrow tools, and never SQL. Stages are separated by `|`:
```text
from -24h | where status = blocked and group = kids | top 10 name
from -7d | where client = 192.168.1.20 | bucket 1h | stats count, p95(latency)
where name under roku.com | by client | stats count, distinct(name)
from -1h | where latency > 200 | by upstream | stats count, p50(latency), p99(latency)
from -1d | where status = blocked and (client = 192.168.1.20 or name under roku.com) | top 10 name
from -180d | where status = blocked | bucket 1d | stats count
```
| Stage | |
|---|---|
| `from TIME [to TIME]` | `-30m`, `-24h`, `-7d`, or RFC 3339 (default: the last 24 hours) |
| `where FIELD OP VALUE [and …] [or …]` | `and` binds tighter than `or`; a group in parentheses, `(A or B and C)`, is one term (one level deep). Fields `name`, `client`, `group`, `status`, `qtype`, `rcode`, `upstream`, `proto`, `latency`, `upstream_latency`; `=`, `!=`, `in (a, b)`, `not in (a, b)`; names also `~` (glob: `"*.tiktok.*"`), `has` (part of the name), `under` (the name and below); a client can be a CIDR (`192.168.2.0/24`); latencies `>`, `>=`, `<`, `<=` in ms |
| `bucket 5m` (`1h`, `1d`) | a time series: one row per bucket |
| `by KEY, …` | `name`, `domain` (the registrable domain), `client`, `group`, `status`, `qtype`, `rcode`, `upstream`, `proto` (up to three) |
| `stats …` | `count`, `distinct(KEY)`, and `avg`, `min`, `max`, `p50`, `p90`, `p95`, `p99` of `latency`, `upstream_latency`, `answers`, or `bytes` |
| `top N KEY` | the same as `by KEY \| stats count \| sort count desc \| limit N` |
| `sort COLUMN [asc\|desc]`, `limit N` | by any column; at most 200 rows (default 50) |

In the web UI, **Analyze** (under Monitor) runs vqlog: type a query or pick an example, run it or only estimate its cost, and click a name, domain, or client in the result to open those queries in the query log. The URL keeps the query, so a result can be shared.

`GET /api/v1/analytics/vqlog?q=…` (or the MCP tool `vqlog`) answers with a table (`columns`, `rows`; a `client` column comes with `clientName`), the query as it was understood (`query`, with the defaults filled in), and what it cost (`cost`: the rows it could read at most, then the rows scanned and matched). `dryRun=true` (`estimateOnly` in MCP) only estimates. Mistakes come back as 400 with a hint listing the choices (the groups, the statuses, …).

**Long windows.** The query log keeps `retention_days` (30 by default). For a window that reaches back further, or with the query log off, counts by at most one of `status`, `qtype`, `rcode`, `proto`, or `group` (as the key, the filter, or both, with buckets of `1h` or longer) come from the rollups instead, which keep hours for 400 days and days for good. The answer says so (`source: "rollups"`). Other queries over such a window cover what the query log still has, and say that in `note`.

**Limits:** a query that could read more than 100 million logged queries is refused (narrow the time or filter first). A scan stops at 2 million matching queries, 100,000 groups, or 25 seconds, and says so (`truncated`, `truncatedReason`); the numbers then cover the newest queries. It needs `querylog:read`, isn't available to agents restricted to a group, and sees what the privacy level lets the query log keep. On a cluster's primary it covers the query logs replicas ship to it.

**Signing in with SSO (OAuth).** Instead of pasting an agent token, an MCP client can sign you in through your OIDC provider (MCP's OAuth 2.1 flow). Set the provider and register the MCP client with it:
```toml
[auth.oidc]
public_url = "https://dns.example.com"
mcp_provider = "keycloak"            # one of your [[auth.oidc.provider]] ids
# mcp_audience = "https://dns.example.com/mcp"   # the default
```
- TelltaleDNS publishes `/.well-known/oauth-protected-resource` (RFC 9728) naming the provider as the authorization server, and answers an unauthenticated `/mcp` with a `WWW-Authenticate` header pointing there, so MCP clients find the sign-in on their own.
- At the provider, give the MCP client an audience of `https://dns.example.com/mcp` (Keycloak: an audience mapper; Authentik and others: the resource or audience setting) and offer the TelltaleDNS scopes (`analytics:read`, `config:write:rules`, ...) as optional client scopes. You consent to the ones the agent gets; with none, it gets the read-only default.
- The access token must be a JWT signed by the provider. It's checked for signature, issuer, audience, and expiry on every request; opaque tokens aren't supported.
- It acts as an agent for **your account**: never above your role, audited as `agent:oauth:<client> (owner: <you>)`. You must have signed in to the web UI with that provider once, so your account exists.

**Resources and prompts.** Besides tools, the server offers three read-only **resources** (JSON documents an assistant can attach) and four **prompts** (ready-made requests that walk the assistant through the right tools):

| Resource | What it holds |
|---|---|
| `telltale://cluster/status` | members, roles, sync, versions, checks, each node's machine |
| `telltale://config` | the running configuration without secrets: upstreams, lists, groups (with their sources), devices, local names, forwarded domains, quick rules |
| `telltale://reports/daily` | the last 24 hours: totals, top domains, blocked names and clients, upstream health, anomalies |

| Prompt | Arguments | What it does |
|---|---|---|
| `investigate_device` | `client`, `window` | profile, anomalies, explanations, and latency for one device |
| `weekly_network_report` | | the week's numbers and the three things most worth attention |
| `tune_blocklists` | | dead or failing lists, likely false positives, and proposed plans |
| `upstream_health_review` | `window` | upstream health and latency, and a proposed strategy change |

Resources read the same REST routes with the agent's token, so scopes apply: a part the token can't read shows as an error. Prompts only suggest changes as plans; they never apply them.

**Changing things.** Write tools never change anything directly: each makes a *plan* (see [Plans and approval](#plans-and-approval)).

| Tool | Plans to | Scope |
|---|---|---|
| `plan_block_domain`, `plan_allow_domain` | block or allow a domain for everyone, devices, or groups, optionally for a while (a quick rule) | `config:write:rules` |
| `plan_rename_client`, `plan_assign_client` | rename a device; name a device and set its groups | `config:write:clients` |
| `plan_set_local_name`, `plan_remove_local_name` | answer a local name with your own records, or stop | `config:write:records` |
| `plan_forward_domain` | send a domain to other DNS servers | `config:write:forwards` |
| `plan_add_list` | add a filter list (URL or inline rules) | `config:write:lists` |
| `plan_update_group` | change a group's networks, lists, blocked answer, priority, or schedules | `config:write:groups` (+ `config:read`) |
| `plan_set_schedule` | make or change a weekly schedule (a bedtime, extra lists, blocked services) | `config:write:groups` |
| `plan_set_anomaly_mute`, `plan_remove_anomaly_mute` | mute kinds of device anomaly for devices or groups (at least one device or group and one kind; give a note and prefer an end time), or remove the mute | `config:write:anomalies` (+ `config:read`) |
| `plan_set_ratelimit` | change the per-client rate limit (queries per window, the action, exempt addresses, how clients are grouped) | `config:write:ratelimit` (+ `config:read`) |
| `plan_update_upstreams` | change or add an upstream server or upstream group | `config:write:upstreams` (+ `config:read`) |
| `apply_plan`, `discard_plan`, `list_plans` | make the planned change; drop a plan; list yours | the plan's scope |

A few low-risk operations act at once, without a plan, and are audited like any change: `flush_cache` (`ops:cache`), `pause_blocking` for 1 to 60 minutes and `resume_blocking` (`ops:pause`), `acknowledge_anomalies` (`ops:anomalies`), and `start_maintenance` for up to 2 hours and `end_maintenance` (`ops:maintenance`; the reason is shown with the window). Two checks change nothing but reach out from the node, so they're audited too and need the scope that would save the entry: `check_upstream` (`config:write:upstreams`) and `check_list` (`config:write:lists`) try a draft before a plan adds it. Every write tool needs a `reason`.

**How the tools behave:**
- **Cluster-wide by default.** `get_overview`, `top_items`, `search_queries`, `latency_breakdown`, and `get_client_profile` take `scope` (`cluster`, `site:<name>`, `node:<name>`, `node:local`), and every result has `missingNodes`: the nodes in scope that didn't answer within 2 seconds, so a partial answer is never mistaken for a whole one. Upstream health and anomalies are the connected node's own.
- **Side effects are stated.** Each tool's description starts with what it does ("Read-only.", "Plans a change", "Changes at once"), and its MCP annotations agree (`readOnlyHint`, `destructiveHint`).
- **Same checks as REST.** Every tool calls the REST API with the agent's own token, so its scopes, group restriction, rate limit, privacy level, and the kill switch all apply. A tool the token can't use answers with an error. The rate limit counts tool calls (requests to `/mcp`, and each message of a JSON-RPC batch, which holds at most 16), not the REST reads a tool makes, and the audit log records the agent's own address for changes made through a tool.
- **Capped results.** Results stop at 200 rows / 32 KiB, with a note to narrow or page.
- **Stable catalog.** It's committed as `docs/api/mcp-tools.json`, and CI checks it with the official MCP SDK (`deploy/mcp-e2e.sh`).

### Plans and approval
A `plan_*` tool asks the node what the change would do (the same dry run as `?dryRun=true`) and keeps the answer as a plan for 10 minutes. The agent gets a `planId` and a preview: before and after, how many recent queries it affects, and any warnings.

- **`apply_plan`** makes the change exactly as planned, on every node. If anything in the configuration changed since the plan was made, the plan is **stale** and nothing happens; the agent plans again. Applying twice changes nothing more.
- **Approval:** with `[agents] require_approval = true`, a plan waits for a person. Operators see **N agent changes to review** in the header and approve or reject on the **Agent changes** page (or `POST /api/v1/plans/{id}/approve` and `/reject`). Agent tokens can't approve anything, their own plans included. Approvals and rejections are audited.
- **Who did it:** the change is audited as the agent, with its owner, its MCP client, and the plan's reason. The approval is a separate audit entry under the operator's name.
- **What it would have done:** a plan tool takes `simulate` (`"24h"`, up to `"7d"`): the preview then carries `simulation`, the change replayed over the query log (see [Trying a change against yesterday's traffic](#trying-a-change-against-yesterdays-traffic)). Plans don't simulate unless the agent asks, because a simulation costs CPU on every node; an operator can make every plan simulate with `[simulate] plans_by_default = true` (Settings → Query handling → Change simulation). No agent tool can turn that on. If the node is busy with another simulation, the plan is made without it and its `note` says so. `simulate_change` previews a change's simulation without making a plan. Simulating needs the `querylog:read` scope too.
- `GET /api/v1/plans` lists plans for the last day (an agent token sees only its own).
- Plans live in the memory of the node that made them: a restart drops open plans (the agent just plans again). In a cluster, point agents at the node whose UI you use (normally the primary).

## Users and sign-in
There is no default password. On first start the server creates a one-time **setup token** and saves it in `<data_dir>/setup-token` (readable by its owner only). The log says where it is, never the token itself, because logs often end up in shared collectors. Cluster members other than the primary have no setup token: their users come from the primary.
```sh
telltale auth setup-token          # prints it
curl -s -c jar -H 'content-type: application/json' \
  -d '{"setupToken":"<token>","username":"admin","password":"a long passphrase"}' \
  http://dns.lan:8053/api/v1/auth/setup
```
That creates the first admin and signs them in; the token file is then deleted. Passwords need at least 10 characters.

For a deployment that must come up configured (Kubernetes, Ansible), create the first admin from a secret instead. These are read only while no user exists:
```sh
TELLTALE_BOOTSTRAP_ADMIN_USER=admin
TELLTALE_BOOTSTRAP_ADMIN_PASSWORD_HASH='$argon2id$v=19$...'   # from: echo 'a long passphrase' | telltale auth hash-password
# or TELLTALE_BOOTSTRAP_ADMIN_PASSWORD=...
```

**Roles.** `viewer` sees dashboards and the query log; `operator` can also pause, flush the cache, and manage lists, clients, and groups; `admin` can do everything, including users. Admins manage users at `/api/v1/users`. The last admin can't be removed or demoted. To stop a leaked token without disabling its owner, an admin opens **Settings → Users → Tokens** for that user and revokes it (`GET /api/v1/users/{id}/tokens`, `DELETE /api/v1/users/{id}/tokens/{tokenId}`, audited as `token.revoke`).

**Ways to sign in:**
- **Web UI / browser:** `POST /api/v1/auth/login` sets an `HttpOnly; SameSite=Strict` session cookie (`Secure` when the request came over HTTPS) and returns a CSRF token, which must be sent as `X-CSRF-Token` on every change. Sessions end after 7 days, or after a day unused.
- **API tokens** for scripts, dashboards, and agents: `POST /api/v1/tokens` with `{"name": "grafana", "scope": "read"}` returns `tt_<id>_<secret>` once; send it as `Authorization: Bearer ...`. Scope `read` acts as viewer, `write` as operator, `admin` as admin, never above the owner's role. Only a hash is stored. Tokens are created and revoked from a signed-in session (the web UI, or `POST /api/v1/auth/login` and its cookie and CSRF token), and so are password and two-factor changes: a token, or HTTP Basic, can use the account but not change it.
- **HTTP Basic**, for scrapers and widgets that can't send a token: off per user until an admin sets `allowBasicApi`, and refused over plain HTTP unless `[auth] allow_insecure_basic = true`. Verified credentials are cached for a minute.

**Two-factor sign-in (TOTP):** `POST /api/v1/auth/totp/setup` returns a secret and an `otpauth://` URL for an authenticator app, and `POST /api/v1/auth/totp/enable` with a current code turns it on and returns ten single-use recovery codes. To require it for a role (enrol your own account first: someone who must use it and has none set up can't sign in to enrol):
```toml
[auth]
totp_required_roles = ["admin"]
session_ttl_hours = 168
session_idle_hours = 24
allow_insecure_basic = false
```

**Lockout:** after 5 failed sign-ins for a username or from an address, through the sign-in form or HTTP Basic alike, each further attempt waits 30 s, doubling up to 15 minutes (HTTP 429). A successful sign-in clears the count.

**Busy:** checking a password takes about 19 MiB of memory, so at most four checks run at once. Beyond that a sign-in (or an uncached HTTP Basic request) is answered 503 with `Retry-After: 1`, which doesn't count as a failed sign-in. A burst of sign-in attempts can't run the node out of memory, so DNS keeps answering.

**Prometheus:** the metrics listener (`:9153`) is unchanged: no sign-in, limited to `allowed_networks`. `/metrics` on the API port needs a viewer token or Basic.

Users, sessions, and tokens are kept in `<data_dir>/state.db` (SQLite). If it can't be opened, the API stays off and DNS keeps answering.

**Sign in with Keycloak, Authentik, or another OpenID Connect provider.** Each provider gets a "Sign in with ..." button. People are created in TelltaleDNS the first time they sign in, and their role comes from their groups at every sign-in:
```toml
[auth.oidc]
public_url = "https://dns.example.com"     # where people open the UI

[[auth.oidc.provider]]
id = "authentik"                           # used in URLs
name = "Authentik"                         # the button label
issuer = "https://auth.example.com/application/o/telltale/"
client_id = "telltale"
client_secret_file = "/run/secrets/oidc"   # or client_secret = "..."
groups_claim = "groups"                    # Keycloak realm roles: "realm_access.roles"

[[auth.oidc.provider.role]]
group = "dns-admins"
role = "admin"

[[auth.oidc.provider.role]]
group = "family"
role = "viewer"
```
At the provider, create a confidential client with the redirect URI `<public_url>/api/v1/auth/oidc/<id>/callback` (here `https://dns.example.com/api/v1/auth/oidc/authentik/callback`) and allow `<public_url>/` after sign-out. Make sure the ID token carries the groups: Authentik's `profile` scope includes `groups`; in Keycloak add a "Group Membership" mapper (full group path off) to the client.

- Someone in several mapped groups gets the highest role; someone in none can't sign in unless you set `default_role`. `require_verified_email = true` refuses addresses the provider hasn't verified.
- The username comes from `preferred_username` (or `username_claim`). TelltaleDNS never attaches a provider account to an existing local user: if the name is taken, the new account is called `name@provider`.
- Signing out also signs out at the provider (Keycloak asks "Do you want to log out?"; Authentik shows its own "logged out" page).
- Provider accounts have no TelltaleDNS password; they can still create API tokens.
- `disable_local_login = true` turns off password sign-in and HTTP Basic, except for admins from `allowed_admin_networks`: a break-glass way in when the provider is down. It is not a switch that hides the form: **the list is private networks and loopback by default**, so on a home or office network, or from a Docker or Kubernetes network, the sign-in form is still shown and the local admin can still sign in. (The API only answers clients in `[access] allowed_networks`, the same list by default, so with the defaults the flag changes who may sign in with a password, not from where.) Start-up says so: a warning when the list includes whole networks (a range of more than one address, as the default list does), information when it names only this machine and single hosts. The sign-in page and Settings say so too (next paragraph). What to check before you rely on it is under **Break-glass sign-in** below.
- The provider is only contacted while signing in; sessions are local afterwards. Changes to `[auth.oidc]` need a restart. If a provider can't be set up (for example its secret file is missing), it's logged and no "Sign in with ..." button is offered. Password sign-in is then whatever `disable_local_login` and `allowed_admin_networks` say: with the flag on, the break-glass networks still decide who can use a password.

**Seeing the state.** With `disable_local_login = true` the setting is shown, not only logged:
- **On the sign-in page,** a client the password form is offered to sees "or, as an admin on a trusted network, with a password" above it (when there are "Sign in with" buttons) and "Password sign-in is limited to admins on trusted networks. Use it when your sign-in provider is down." under it. A client outside the list still sees "Password sign-in is turned off on this server."
- **In Settings, under Users (admins only),** a "Password sign-in" card lists the networks from `allowed_admin_networks`. It adds an "Includes whole networks" note when any of them is a range of more than one address (the default list is; a list of single hosts such as `192.168.1.10/32`, with or without loopback, is not), says plainly that nobody can sign in with a password when the list is empty, and, for a list that names this machine while `127.0.0.1` is not inside any `[api] trusted_proxies` network, reminds you of the proxy rule below. It describes the node you are connected to. With the flag off nothing is shown.
- **In the API,** `GET /api/v1/auth/status` (public) has `passwordLoginRestricted`: a yes or no, the same for every client (`localLogin` still says whether the form is offered to this one), with no network in it. The networks are `passwordLogin` in `GET /api/v1/users`, which needs the admin role: a viewer, an operator, a token below the admin scope, and an agent token are refused. The block is `restricted`, `networks`, `coversWholeNetworks` (some network is a range, not a single host or this machine), `includesLoopback`, and `loopbackIsTrustedProxy` (`127.0.0.1` is inside a `trusted_proxies` network). The start-up line and the card use one rule for each, so they agree.

**Break-glass sign-in.** Before you rely on `disable_local_login`:
- **Narrow the list to the machines you manage from.** For one workstation, `allowed_admin_networks = ["192.168.1.10/32"]` (a list of single addresses like this is information at start-up; any range, even a `/31`, still gets the warning); for the host itself, loopback (`["127.0.0.0/8", "::1/128"]`) and an SSH tunnel. `[]` turns password sign-in off for everyone: nobody can then sign in with a password while the provider is down, and the way back is to set `disable_local_login = false` and restart (`telltale config check` warns about an empty list). Look at the address the audit log records for your own sign-in before you narrow it: in a container the server may see the Docker network's gateway instead of your machine, and that address differs from one Docker network to the next (it is not always `172.17.0.1`).
- **A reverse proxy on the same host needs `trusted_proxies = ["127.0.0.1/32"]`.** Unless `127.0.0.1` is inside a network of `[api] trusted_proxies` (an ingress's network does not count), every browser a proxy serves appears to come from the proxy. For Caddy or nginx on `127.0.0.1` that is loopback, so a loopback-only list leaves password sign-in open to everyone the proxy serves, the Internet included if the proxy is exposed. Loopback counts on its own only for `X-Forwarded-Proto` (so HTTP Basic works behind a TLS proxy on the same host), never for `X-Forwarded-For`. When a request from this machine carries `X-Forwarded-For` and the proxy isn't listed, the log says so (an info line, at most once in ten minutes, naming the address the request came from and never the header); list the proxy and it stops. This node reads a client's address only from `X-Forwarded-For`, never from the standard `Forwarded` header, so for a proxy that sends only `Forwarded` the log says to make it send `X-Forwarded-For` first: listing it alone would silence the line and leave every client looking like the proxy.
- **List only the proxies in `trusted_proxies`, never your LAN.** For requests from a listed address the client address is read from `X-Forwarded-For`, so any other machine on the list can send that header itself and claim to be `127.0.0.1`.
- **If the proxy hides the client address, don't rely on addresses.** Behind source NAT (a Kubernetes Service with `externalTrafficPolicy: Cluster`, some ingress and load-balancer setups) every client arrives from a private address of the cluster, so a list of private networks lets everyone in. Use `allowed_admin_networks = []` there, and keep the provider, and the way back above, as your way in.
- **The gate stays in force when a provider fails to set up.** A missing secret file doesn't open password sign-in: with the list narrowed or empty you can be left without either way in. Start-up logs the break-glass line whether or not the provider was set up.
- **Turning the flag on doesn't sign anyone out.** Sessions made before (up to 7 days) and API tokens keep working from anywhere until they expire or you revoke them.
- **Turn on two-factor for the break-glass admin first, then require it.** Enrol it under Settings, Account, and only then put `admin` in `[auth] totp_required_roles`: with the role required and no code set up, that admin's sign-in is refused ("this role must use two-factor sign-in") and they can't reach Settings to enrol.
- **Sign-in lockouts are per node and kept in memory** (a restart clears them). They count the username and the address: anyone on an allowed network can lock the break-glass admin out for up to 15 minutes by failing five times, and behind a proxy with `trusted_proxies` unset every browser shares the proxy's count.

**HTTPS without a proxy.** Out of the box the UI and API on port 8053 are plain HTTP, so on a home network the sign-in form's password crosses the LAN in the clear. TelltaleDNS can serve them over HTTPS itself:
```toml
[api]
tls = { self_signed = true }                 # a certificate made on first start
# tls = { cert = "/etc/telltale/api.crt", key = "/etc/telltale/api.key" }   # or your own
```
- **Self-signed:** made once and kept in `<data_dir>/api-tls/` (`cert.pem`, `key.pem`), for `localhost`, the host's name (and `<name>.local`), and its addresses. Browsers warn until you trust it: accept the warning once, or import `cert.pem` into your computer's or browser's trusted certificates to make it go away. Delete the directory to make a new one (for a new address).
- **Your own certificate** (from your CA, or Let's Encrypt with a DNS challenge): PEM files, the server's certificate first; a renewal is picked up within 10 s, and a broken one keeps the previous certificate. With your own certificate the UI also sends HSTS (`Strict-Transport-Security`), so browsers stick to HTTPS for that name. A self-signed one doesn't: with HSTS a browser stops offering to proceed past the warning.
- The same port answers both: `http://` requests are redirected to `https://` (307, so turning TLS off later leaves no cached redirect), except `/livez`, `/readyz`, and `/healthz`, which keep answering health checks (`telltale health`, the Compose healthcheck) over plain HTTP.
- Over HTTPS the session cookie is `Secure` and HTTP Basic works, as behind a TLS proxy.
- `telltale ctl` and `telltale mcp --stdio` on the node use `https://` and trust its self-signed certificate by themselves. From another machine, copy `cert.pem` and pass `--ca-file cert.pem` (with `--url https://<node>:8053`).
- Changing `[api] tls` needs a restart. If the certificate can't be made or loaded, the API stays off (it's logged), rather than falling back to plain HTTP; DNS keeps answering.
- **Settings → System → Listener checks** shows the web UI's certificate: self-signed or yours, the names it covers, its SHA-256 fingerprint (compare it with your browser's before trusting it), and for your own, the days left, with the same health level and alerts as the DNS listeners' certificates ([Listener checks](#listener-checks)).

**Behind a reverse proxy or ingress,** tell TelltaleDNS which addresses are proxies so sign-in lockouts, break-glass networks, and the audit log use the real client address from `X-Forwarded-For` (otherwise everyone looks like the proxy, and one person's failed sign-ins lock out everyone):
```toml
[api]
trusted_proxies = ["10.42.0.5/32"]   # your ingress controller's address
```
The same list decides whose `X-Forwarded-Proto: https` counts: it is what lets HTTP Basic work and marks the session cookie `Secure` behind a TLS-terminating proxy. From anyone else the header is ignored, so a client on plain HTTP can't claim HTTPS. A proxy on the same host (Caddy or nginx on `127.0.0.1`) counts for that header without being listed, but not for `X-Forwarded-For`: to have the client address from it, list `127.0.0.1/32`. List only the proxies themselves, never your LAN, or any machine on it can forge the header. The client is the rightmost `X-Forwarded-For` entry that isn't a listed proxy. An entry that isn't a bare IPv4 or IPv6 address (one with a port, in brackets, a word such as `unknown`, an empty entry, or one that isn't text) stops the search there, and the client is then the address the request came from, the proxy's: make the proxy write bare addresses. How this matters for break-glass sign-in is under **Break-glass sign-in** above.

**Audit log.** Every change to users, passwords, two-factor sign-in, and API tokens, every sign-in, each account or address lockout, and every configuration reload that changed something is recorded: who (for API tokens, the token and its owner: `token:grafana (owner: ana)`), when, from which address, what changed (`role: viewer → operator`; reloads list the changed settings, never their values), and why, if the caller sent an `X-Telltale-Reason` header. Admins see it under **Settings → Audit log** or `GET /api/v1/audit`.

If the audit log can't be written (a full disk, a broken database), the change that failed to be recorded is logged as an error, and the next change first writes an `audit.gap` entry saying how many went unrecorded and why. Until that works, changes through the API and UI are refused with 503; DNS keeps answering.

Entries are kept for `[auth] audit_retention_days` (365 by default; 0 keeps them forever). Older ones are removed hourly, and each removal is itself recorded as `audit.trim` with a checkpoint hash. Otherwise entries can't be edited or deleted, and each is chained to the previous one with a BLAKE3 hash, so tampering with the database is detectable (after a trim, the chain is checked from the checkpoint):
```sh
telltale audit list -n 20                  # newest first; --action user. or config.reload
telltale audit verify                      # "ok: 42 entries, head 9f3c…" or "BROKEN at entry 17" (exit 1)
curl -s -H "Authorization: Bearer $TOKEN" http://dns.lan:8053/api/v1/audit/verify
```
Keep the `head` hash somewhere else from time to time: a later `verify` with a different head and fewer entries means entries were removed from the end.

## Reload without restarting
Edit the config file, then send `SIGHUP` (`kill -HUP <pid>`; with Docker see [Reload in Docker](#reload-in-docker)). A `SIGHUP` sent while the node is still starting is kept, and the reload runs once it is up:
- The whole config is validated first. If anything is wrong, the errors are logged and the **previous configuration keeps serving**.
- Applied immediately, with no dropped queries: upstreams, groups, routes, local records and hosts files, `[access]`, `[ratelimit]`, `[special]`, and `[[listen]]` (new listeners are bound before removed ones are closed, so a listener other than plain UDP (tcp, dot, doh, doq, doh3) that moves between the wildcard address and one address on the same port needs a restart; see "Port 53 already in use").
- Applied at the next restart (a warning names them): `[cache]`, `[telemetry]`, `[node]`. The cache is kept across reloads, so warm answers aren't lost.
- Upstream health starts fresh after a reload and is re-learned within a few queries.

### Reload in Docker
Signal the process from the host (Linux):
```sh
sudo kill -HUP "$(docker inspect -f '{{with .State.Pid}}{{.}}{{end}}' telltale)"
# with Compose, in the folder of compose.yaml:
sudo kill -HUP "$(docker inspect -f '{{with .State.Pid}}{{.}}{{end}}' $(docker compose ps -q telltale))"
```
The template prints the process ID only when there is one. For a container that is stopped, not started yet, or restarting, it prints nothing, and `kill` fails without signaling anything: a container that is restarting has nothing to reload yet, and reads the file when it starts.

**Not `docker kill -s HUP` or `docker compose kill -s HUP`:** Docker marks a container signaled that way as manually stopped, whatever the signal. It keeps running, but with `restart: unless-stopped` Docker then doesn't start it after a reboot, a Docker restart, or a crash. To see whether that has happened (as root): `grep -o '"HasBeenManuallyStopped":[a-z]*' /var/lib/docker/containers/$(docker inspect -f '{{.Id}}' telltale)/config.v2.json`. `docker restart telltale` (or stopping and starting it) clears the mark. Where the host can't signal the process (Docker Desktop), use `docker restart telltale`: that is a restart, not a reload, so the node stops answering while it restarts.

## Stop
`SIGTERM` or `SIGINT` (Ctrl-C) shuts down gracefully, also when it arrives while the node is still starting (it is kept, and the shutdown below runs once the node is up). A stop during a cluster join ends the join and stops the node at once (exit 0): it isn't ready yet, so there is nothing to drain. Otherwise:
1. `/readyz` turns 503, so load balancers stop sending new queries.
2. TCP listeners stop accepting and finish the queries already received.
3. Upstream lookups still in flight get up to 3 seconds to complete and reply.
4. UDP workers stop.

For planned downtime longer than a restart, [put the node in maintenance](#taking-a-node-down-for-maintenance) first: balancers move away early, and no alert fires while it's off.

In Kubernetes, pair this with a short `preStop` sleep so endpoints are removed before the drain begins (the Helm chart will set this).

## Logging
Logs go to stderr. Set the level with `TELLTALE_LOG` (`error`, `warn`, `info` (default), `debug`, `trace`).

## Error responses
| Query | Response |
|---|---|
| Opcode other than QUERY | NOTIMP |
| Malformed (bad name, QDCOUNT ≠ 1, bad OPT, …) | FORMERR |
| EDNS version > 0 | BADVERS with an OPT record of version 0 (RFC 6891) |
| No upstream group applies (none configured) | REFUSED + EDE 14 "no upstreams configured" |
| Shorter than a DNS header, or a response (QR=1) | Silently dropped |

Responses larger than the client's UDP limit are truncated (TC=1) so the client retries over TCP. TCP follows RFC 7766: pipelined queries, answers in completion order, a 10-second idle timeout, at most 64 outstanding queries per connection, and at most 1024 connections.
