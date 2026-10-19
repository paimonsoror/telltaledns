# Kubernetes workloads as devices: design notes (T15.1)

**Requirement:** FLT-017 (new, P1). **ADR:** ADR-150 (new, Proposed). **Spec sections:** `05` §5 (groups and
clients) gains "Kubernetes workloads"; `08` §3.3 gains "Pods as clients"; `06` §7 note "a workload is one
device". **Owner request:** 2026-10-18. **Builds on:** FLT-006 (identification chain), API-010 (names at read
time, ADR-125), OBS-025 (device identification), ADR-050 (network groups), ADR-120 (secrets stay off
resolver pods).

## 1. What it is, in one paragraph
A pod becomes a device TelltaleDNS can name, group, and watch, exactly like a laptop or a TV: the
controller watches the Kubernetes API for pods, maps each pod address to its **workload**
(`media/deploy/jellyfin`), and every view that shows a device shows the workload instead of a pod
address. A Deployment with three replicas is **one device**, not three, so its anomaly baseline, rhythm,
timeline, and "new device" status survive rollouts. Namespaces and labels choose the group, so the
existing filtering (lists, quick rules, blocked services, schedules, per-group upstreams) applies per
namespace with no new policy code. The question this answers is "which workload talked to which domain",
which today needs a service mesh or Hubble; here it costs one hash lookup.

## 2. Non-goals (v1)
- Answering `cluster.local` ourselves (watching Services and Endpoints). CoreDNS stays authoritative for
  the cluster domain; TelltaleDNS forwards it there (§7).
- Namespace egress allowlists as a policy type. A group whose schedule or quick rules block everything
  but an allowlist already behaves like one; a proper "allow only these names" policy mode is a
  follow-up (T15.3, not in this pack).
- Multi-cluster: one Kubernetes API per controller. A second cluster's pods are just addresses.
- Pods on the host network (`spec.hostNetwork: true`): their address is the node's and is already
  infrastructure (OPS-003). Skipped.
- The `kube` / `k8s-openapi` crates. See §5.

## 3. Identity model (decision)
A **workload** is `(namespace, kind, name)` with `kind` one of `deploy`, `sts`, `ds`, `job`, `cronjob`,
`pod` (a bare pod). It is derived from the pod's `ownerReferences` without reading other resources:
- owner `ReplicaSet` → `deploy`, name = the ReplicaSet name with `-<pod-template-hash>` removed (the
  `pod-template-hash` label gives the suffix; if the label is missing, the ReplicaSet name is the workload
  name and kind is `rs`).
- owner `StatefulSet` → `sts`; `DaemonSet` → `ds`; `Job` → `job` (a Job owned by a CronJob: kind `cronjob`,
  name = the CronJob's name from the Job's ownerReference, which the pod does not carry; **decision:** read
  the Job's owner only when the Job name ends in `-<digits>`, strip the suffix, kind `cronjob`; otherwise
  `job`).
- no owner → `pod`.
The text form is `ns/kind/name`, e.g. `media/deploy/jellyfin`, `kube-system/ds/cilium`. It is the device
name shown everywhere; the pod name is evidence (§8).

**The analytics key (decision).** Every per-device structure in the aggregator (top clients, anomalies,
identities, rhythm, timeline, recent windows, the new-device feed, T15.2's seen table) is keyed by a
16-byte client address. A workload gets a **synthetic address** in the IPv6 discard prefix (RFC 6666):
`100::/64` followed by the first 8 bytes of BLAKE3(`ns/kind/name`). (Amended at implementation: the
first draft said 12 hash bytes after `100::`, which would leave the /64 discard prefix; see ADR-150.)
It can never collide with a real client, it is
stable across rollouts and nodes, and nothing downstream changes. The aggregator substitutes it for the
pod address **for analytics only**, in one place (`agg.rs`, where an event is drained), with one
`ArcSwap<HashMap<[u8;16], Workload>>` lookup; the query-log builder keeps the real pod address (the log is
the truth, §6). At 50k q/s that is one hash lookup per event on the telemetry thread: measure it with
`bench.py sustain` and report.

**On the query path (decision).** `ClientTable::identify` (`crates/telltale-policy/src/clients.rs`) gains
a `workloads: &Workloads` argument, consulted **after** client ID, EDNS MAC, and neighbor MAC, and
**before** IP/CIDR and the network group, and only when the table is non-empty (one branch for non-
Kubernetes installs; `Neighbors` is the model). A hit returns `IdSource::Workload` and the workload's
group index (resolved at table-build time, §4) in a new `Identity.workload: Option<u32>`; the configured-
client path is untouched (`client: None` for a workload; `[[client]]` entries keyed by a pod address still
win, since `by_ip` is checked first? **No — decision:** workloads win over `by_ip`/CIDR, because a pod
address in a `[[client]]` entry is a stale config after the first rollout; a `$client` rule can name a
workload by its text form instead). The QueryEvent's `client_ref` stays 0 (unknown configured client);
`group_ids` carry the workload's group. `explain` says *recognized as Kubernetes workload
`media/deploy/jellyfin` (pod `jellyfin-7d9f4c8b6-x2k1q`), group `media` from namespace label*.

## 4. Groups (decision)
A workload's group is the first that applies:
1. the pod label `telltaledns.io/group=<group>`;
2. the namespace label `telltaledns.io/group=<group>`;
3. the first matching `[[kubernetes.map]]` rule: `{ namespace = "media*", group = "iot" }` (glob on
   namespace; optional `kind`);
4. `[kubernetes] default_group` if set;
5. otherwise no group: the pod falls to its network group (ADR-050) or `default`, as any unknown device.
A group that doesn't exist is logged once per (label value) and treated as unset. Changing a label takes
effect on the next watch event (seconds), with **no configuration version and no replication**: the
workload table is node-local operational state like the neighbor table, distributed by the controller
(§5), never by the snapshot log. Validation: `[[kubernetes.map]]` group names must exist (startup/reload
error, like `[[client]] groups`).

## 5. The watcher (decision)
- **Who:** the process holding a service-account token: the controller in `mode: scaled`, the pod in
  `allInOne`. Resolver pods and nodes outside Kubernetes never talk to the API server (they have no token:
  ADR-120). The shared `[kubernetes]` section replicates to every node; a node without
  `KUBERNETES_SERVICE_HOST` and a readable token logs one `info` line and does nothing (not a warning: the
  Pi will see this section forever).
- **How:** no new dependency. The in-cluster client is the existing rustls HTTP client used by
  `routers.rs` and the list fetcher, with the CA from
  `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`, the token from `.../token` re-read every 5
  minutes (bound tokens rotate), and the API at `https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT`.
  Calls: `GET /api/v1/pods?limit=500` (paged, `continue`) for the initial list, then
  `GET /api/v1/pods?watch=1&resourceVersion=<rv>&allowWatchBookmarks=true&timeoutSeconds=600` as a
  streaming body of JSON lines, decoded into a minimal `serde` struct (`metadata.{name,namespace,labels,
  ownerReferences}`, `spec.hostNetwork`, `status.{phase,podIPs}`). `GET /api/v1/namespaces` the same way
  for namespace labels (list + watch). A `410 Gone` or any error → full re-list after a jittered backoff
  (1 s → 60 s). A full re-list every 10 minutes regardless (drift guard). `fieldSelector=status.phase!=
  Succeeded,status.phase!=Failed` on the list. Budget: about 400 lines in a new `crates/telltale/src/
  kubernetes.rs`, with the parser unit-tested on fixture JSON (a Deployment pod, a StatefulSet pod, a
  CronJob's Job pod, a bare pod, a host-network pod, a pod with two IPs, a terminating pod).
- **Optional scope:** `[kubernetes] namespaces = ["media", "home"]` watches only those (one watch per
  namespace); default: all. `exclude_namespaces` default `[]`.
- **The table:** `Workloads` (new, `crates/telltale-policy/src/workloads.rs`): `ArcSwap` of
  `{ by_ip: HashMap<[u8;16], (workload_idx, group)>, workloads: Vec<Workload{ns, kind, name, key:
  [u8;16], pods: SmallVec<PodRef>}> }`, rebuilt on every change (debounced 500 ms; a homelab has
  hundreds of pods, not thousands). Cap: 20,000 pod addresses; beyond that log once an hour and stop
  adding (the metric says so).
- **Distribution:** the controller sends the whole table to every connected peer on change (debounced
  2 s) with a new peer call `workloads.table` on the existing cluster channel (the pattern is
  `devices.names` in `devices.rs`, in the pull direction), and peers also pull it every 60 s as a
  fallback (covers a resolver pod that started after the last push). A peer on an older build answers
  "unknown call" and is skipped. Resolver pods therefore identify pods on the query path within about
  2 s of the pod existing. The Pi receives the table too, for naming shipped rows; it never sees pod
  traffic.
- **History for names at read time (§6):** the controller also keeps `history: HashMap<[u8;16],
  SmallVec<(workload_idx, from_s, to_s)>>`, at most 8 intervals per address and 30 days, persisted to
  `<data_dir>/workloads.json` hourly and at shutdown, loaded at start. Peers get the history with the
  table (it is small: tens of KB).

## 6. Naming at read time (decision)
`device_name(ip)` (`api_backend.rs`, ADR-125) and the client chip resolve a pod address to its workload's
text form, and the synthetic key to the same text. Because a pod address is reused by a later pod, the
query log, the device timeline, and `queries/stream` resolve names with the row's time:
`device_name_at(ip, ts_s)` walks the address's intervals (§5) and names the workload that held the
address then; the current mapping is the fallback. Every other view (top lists, anomalies, identities)
is keyed by the synthetic address and needs no time.

**Query filters:** `GET /api/v1/queries?client=` and the live tail accept the workload text form and the
synthetic address; the handler expands either to the addresses the workload held in the requested window
(cap 64 addresses; `truncated: true` beyond it). `top`, `timeline`, `rhythm`, `identity` take the
synthetic address or the text form directly.

## 7. Getting pod traffic to TelltaleDNS (decision; chart + docs, no resolver change)
Pods must query TelltaleDNS **directly**; forwarding from CoreDNS hides them behind CoreDNS's address.
Two supported paths, documented in `running.md` ("Kubernetes workloads as devices") and NOTES:
1. **Cluster-wide (recommended):** point the kubelet's cluster DNS at TelltaleDNS's Service address
   (k3s: `--cluster-dns=<clusterIP>` in `/etc/rancher/k3s/config.yaml`; kubeadm: `clusterDNS` in the
   kubelet config), and let TelltaleDNS forward the cluster domain to CoreDNS. The chart writes, when
   `kubernetes.enabled`, a `[[forward]]` for `kubernetes.clusterDomain` (default `cluster.local`) and
   for the reverse zones of `kubernetes.podCidr` / `kubernetes.serviceCidr` (optional values) to
   `kubernetes.clusterDns` (**required when enabled**, the CoreDNS Service IP; the NOTES print
   `kubectl -n kube-system get svc kube-dns -o jsonpath='{.spec.clusterIP}'`), with a DNSSEC NTA, exactly
   as the UI's "send a domain to another server" does. Give the DNS Service a fixed `clusterIP`
   (`service.dns.clusterIP`, new value) so the kubelet setting survives reinstalls.
2. **Per workload:** `dnsPolicy: None` + `dnsConfig.nameservers: [<TelltaleDNS Service IP>]` with the
   cluster search domains, for the workloads you care about and nothing else.
Source addresses are preserved on pod → ClusterIP traffic by kube-proxy and Cilium (no SNAT), so the
masked-client-IP detector (OPS-003) is not affected; an e2e asserts a pod's own address in the query log.
`ndots:5` means TelltaleDNS receives `grafana.com.media.svc.cluster.local`-style questions; they route
to CoreDNS and come back NXDOMAIN, as today. **Decision:** no special casing; the probe-name exclusion
(ADR for `probe.telltale.invalid`) already keeps NXDOMAIN share honest in the log, and search-suffix
noise is a known Kubernetes shape worth seeing in the traffic map, not hiding.

## 8. Device identification, UI, API, MCP (decision)
- **OBS-025:** a workload's identity is `class: "workload"`, `product: "<kind> in <namespace>"`,
  confidence `certain`, evidence `{ source: "kubernetes", pods: [...], labels: {app.kubernetes.io/name,
  app.kubernetes.io/part-of} }`; the signature catalog is not consulted; an override still wins.
- **Clients page:** a **Workloads** tab (hidden unless the cluster has any): namespace, kind, name,
  group and where it came from (`pod label` / `namespace label` / `map` / `default`), pods now, queries
  and blocked in 24 h, last seen; click → the device timeline. Filter by namespace. The client chip gets a
  Kubernetes glyph and shows `ns/kind/name` with the pod name in the tooltip. "Name this device…" is
  disabled for workloads (the name comes from Kubernetes; the menu says so) but "Add to group…" works and
  writes a `[[kubernetes.map]]` rule for that exact workload (managed entry, dry run, If-Match,
  idempotency, audit, like other managed entries; a label on the namespace is the GitOps way and the help
  panel says so).
- **Groups page:** a group's devices list shows workloads with the glyph.
- **API:** `GET /api/v1/kubernetes/workloads` (federated: the controller's table; `missingNodes` when it
  can't be reached; `scope` as elsewhere; cursor over 200) with the fields above; `GET
  /api/v1/kubernetes/status` (`enabled`, `watching`, `lastSyncSecondsAgo`, `pods`, `workloads`,
  `namespacesWatched`, `lastError`). Problem `kubernetes_disabled` (409) with the hint to set
  `kubernetes.enabled` in the chart.
- **MCP:** `list_workloads(namespace?, group?)` (read) and `get_workload(name)` (the device profile
  under its text form; `get_client_profile` accepts the text form too). Writes go through the existing
  `plan_add_to_group`-style plan tool with the workload's text form as the device.
- **Help topic** `kubernetes-workloads`; glossary entry "workload"; site page section with the
  "pods → TelltaleDNS → CoreDNS behind it" diagram.

## 9. Chart and config (decision)
```yaml
kubernetes:
  enabled: false              # watch pods and name them as devices (controller only)
  clusterDomain: cluster.local
  clusterDns: ""              # CoreDNS Service IP; required when enabled
  podCidr: ""                 # optional: reverse zone forwarded to CoreDNS
  serviceCidr: ""
  namespaces: []              # empty: all
  excludeNamespaces: []
  defaultGroup: ""
  map: []                     # [{namespace: "media*", kind: "", group: "iot"}]
  rbac:
    create: true              # ServiceAccount + ClusterRole(pods, namespaces: get/list/watch) + binding
    serviceAccountName: ""    # use an existing one instead
service:
  dns:
    clusterIP: ""             # fixed address for the kubelet's cluster DNS
```
`kubernetes.enabled` sets `automountServiceAccountToken: true` **on the controller/allInOne pod only**;
resolver pods keep `false`. The ClusterRole is read-only on `pods` and `namespaces` and nothing else; the
values schema refuses `enabled: true` with an empty `clusterDns`. TOML (`[kubernetes]`, shared section):
`enabled`, `namespaces`, `exclude_namespaces`, `default_group`, `label = "telltaledns.io/group"`,
`[[kubernetes.map]] { namespace, kind?, group }`. A non-Kubernetes install setting `enabled = true` gets
an `info` line and nothing else (not an error: the section is shared).

## 10. Metrics, health, alerts (decision)
`telltale_kubernetes_pods` and `telltale_kubernetes_workloads` gauges, `telltale_kubernetes_table_age_
seconds`, `telltale_kubernetes_watch_errors_total`, `telltale_kubernetes_sync_total{result}`. Health
(OBS-015): `kubernetes_stale` is **degraded** when enabled on this node and the table is older than 15
minutes (reason text: "pods may be named by address until the API server is reachable"). PrometheusRule
`TelltaleDNSKubernetesWatchStale` on the same condition. No new `AlertWhen` (the health level covers it).

## 11. Performance
- Query path: one `ArcSwap` load plus one hash lookup, only when the table is non-empty. A/B
  `make bench-smoke` with an empty table (every install today) must be within noise; with 1,000 pod
  addresses loaded, the cache-hit path must stay within 2 % of baseline, reported.
- Telemetry thread: one lookup per event (`bench.py sustain` at 50k q/s, 0 drops, CPU reported).
- Memory: 1,000 pods ≈ under 300 KB for the table and history. Report RSS before/after on the VM.
- The watcher: idle most of the time; a full re-list of 1,000 pods is about 2 MB of JSON every 10
  minutes, parsed on a background task at `SCHED_IDLE` priority like the compiler.

## 12. Acceptance criteria
1. Parser: the seven fixture pods (§5) map to `media/deploy/jellyfin`, `db/sts/postgres`,
   `kube-system/ds/cilium`, `jobs/cronjob/backup`, `tools/job/once`, `tools/pod/debug`; the host-network
   pod and the terminating pod are skipped; a pod with two IPs maps both.
2. Identification: with a loaded table, a query from a pod address gets `IdSource::Workload`, the group
   from (pod label > namespace label > map rule > default_group > network group), and `explain` names the
   workload, the pod, and the group's origin; an empty table takes the existing path unchanged (the
   precedence tests of T2.5 still pass); a `[[client]]` keyed by a pod address loses to the workload.
3. Analytics: 1,000 events from three pod addresses of one Deployment produce one device in top clients,
   one anomaly baseline, one identity (`class: workload`, `certain`), one new-device entry; the query log
   rows carry the pod addresses and are named by the workload at read time; after a simulated rollout
   (addresses reused by another workload) old rows are named by the old workload and new rows by the new
   one (`device_name_at`).
4. Distribution: in `deploy/cluster/e2e.sh`, a table loaded on the primary from a fixture (a test hook,
   no API server needed) reaches the replica within 5 s; a replica started afterwards pulls it within 60 s;
   a peer on a build without the call is reported missing, not an error.
5. Watcher: against a fake API server (an in-test axum server serving list/watch fixtures): initial list,
   an ADDED and a DELETED event update the table, `410 Gone` triggers a re-list, a token file change is
   picked up, errors increment the metric and never touch a running query loop (a DNS query answered under
   a failing watcher in the same test).
6. Chart: `ct lint`; with `kubernetes.enabled: true` the rendered controller pod mounts the token and the
   resolver pods don't; the ClusterRole has exactly `pods` and `namespaces` with `get/list/watch`;
   `enabled: true` without `clusterDns` fails schema validation; `deploy/helm/e2e.sh` on kind: a busybox
   pod with `dnsConfig` pointing at the Service resolves an external name, the query-log row names
   `default/pod/busybox`, and `kubernetes.default.svc.cluster.local` resolves through the forward.
7. UI: Playwright `flt_017 workloads`: the Workloads tab lists the fixture workloads with group origin;
   "Add to group…" on one writes a map rule (dry run shown first) and the next query from it is in that
   group; the chip shows the glyph and the pod name on hover.
8. Bench: §11 numbers in the report.
9. Docs: `running.md` section with both wiring paths and the k3s snippet; site page and diagram; help
   topic; OpenAPI and MCP regenerated; ADR-150 and FLT-017 written; roadmap ticked.

## 13. Open
- **Terminating pods:** keep an address for `grace_secs` (decision: 30 s) after deletion so in-flight
  queries are still attributed, then move it to history. If the owner wants a longer tail, say so.
- **Job pods and CronJobs:** v1 collapses a CronJob's runs into one device; if per-run visibility matters
  to the owner, add a `job` evidence field with the run name rather than a device per run (decision
  unless told otherwise).
- **The kubelet change** is the owner's to make on the homelab; the design doesn't require it (per-
  workload `dnsConfig` works without it). Ask before documenting any live step as done.
