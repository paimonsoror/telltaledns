# Node maintenance mode: design notes (T13.4)

**Requirement:** OPS-010. **ADR:** ADR-118. **Task:** T13.4 in `spec/10`. **Spec section:** `08` §9.
**Owner request:** 2026-10-09, from the capability review.

Opinionated by design: *decision* means build it this way; amend ADR-118 if you can't. *Open* means
ask the owner. This is the smallest of the M13 tasks and the first to build: it introduces the
heartbeat-field and health/alert exclusion plumbing the others rely on.

## 1. What it is
"I'm about to swap this Pi's SD card / drain this Kubernetes node / move this box." Today that means
killing the process: balancers notice late, `node_down`, `probe_failing`, and `not_serving` fire for a
planned event, the health icon goes red, and with auto failover the node might get elected mid-work.
Maintenance mode is a timeboxed flag on one node that says: stop *sending me new traffic*, stop
*worrying about me*, but I'll keep answering whatever still arrives.

## 2. Principles (decision)
1. **DNS keeps answering.** Maintenance never closes a listener or refuses a query. Devices that have
   the node hard-coded or as a router's secondary DNS keep working. The only DNS-adjacent change is
   `/readyz`, which is for balancers and Kubernetes.
2. **State, not configuration.** Like pause (FLT-009) and anomaly acks (ADR-103): no config version,
   no manifest, allowed under GitOps, forwarded to the node it concerns — not to the primary.
3. **Timeboxed and persistent.** Default 1 h, maximum 24 h. The window is written to disk before it
   takes effect and read at start, so a reboot inside the window comes back **not ready**: the
   operator (or the clock), not a reboot, says when the node is back.
4. **Quiet, not blind.** Alerts about the node are suppressed and the health level ignores it, but the
   Cluster page and `cluster_status` show the node, its window, and its real figures the whole time.

## 3. On the node (decision)
- File `<data_dir>/maintenance.json`:
  ```json
  { "until_ms": 1760025600000, "since_ms": 1760022000000, "reason": "SD card swap", "by": "alice via pi" }
  ```
  Written atomically (temp + rename, like `anomaly.json`); removed on end or expiry.
- `crate::maintenance::Maintenance` (`ArcSwapOption<Window>`): `start(until, reason, by)`, `end()`,
  `current()`; an expiry task clears it at `until` (and at start, a stale file is removed). On start,
  **before** the server's `ready.store(true)` in `server.rs` (the "every listener is bound" point),
  check the file: if a window is active, leave `ready` false and log `maintenance until … (reason)`.
- **Readiness:** `ready` (the `AtomicBool` in `http::Sources`) is the only switch. `start` stores
  false; `end`/expiry stores true **only if** the node is otherwise ready (listeners bound, and for
  an ephemeral member its configuration applied). Keep one flag: introduce
  `Readiness { bound: bool, synced: bool, maintenance: bool }` behind the existing `ready` so the
  three reasons compose, and `/readyz`'s body says which one is false (`{"ready":false,"reason":
  "maintenance"}`) — handy for `kubectl describe`.
- **Heartbeats:** new optional field `maintenance_until_ms: u64` (0 = none) and `maintenance_reason`
  in `Heartbeat` (`wire.rs`; N−1 ignores unknown fields). The primary stores it per peer.
- **Elections:** a node in maintenance answers pre-vote with "not a candidate" and doesn't start an
  election (`election.rs`: the same check as "not eligible"). It still **votes**: refusing to vote
  would weaken the quorum for a planned event, which is backwards.
- **A primary hands over when it can** (owner 2026-10-09: "follow your lead"; this is the lead).
  Starting maintenance on the primary with `handover = true` (the default, shown as a checked box in
  the form) when failover is **automatic** and another eligible node (or a quorum) is reachable:
  1. the primary writes its maintenance file and flips readiness as usual;
  2. it **stops renewing its lease** and declines candidacy (`election.rs`: a `stepping_down` flag
     the renewal loop and pre-vote consult). It keeps publishing until the lease expires — a fenced
     primary never publishes anyway (ADR-056);
  3. within the lease window (15 s + margin) a replica is elected; the old primary sees the higher
     epoch, demotes, and follows for the rest of the window (ADR-051). Writes are unavailable for the
     usual 15–30 s of any failover; the API answers 503 as it does today.
  4. The response says `handover: "started"` and the Cluster page's timeline shows "maintenance
     handover" beside the epoch change.
  With **manual** failover, or no other eligible node online, or `handover = false`: maintenance is
  **allowed** (refusing would be worse UX than a note), the primary stays primary and keeps
  publishing, and the response and the form carry `note: "this node stays the primary; promote
  another node first if you're taking it offline"` with a link to Promote. Nothing automatic happens
  in manual mode: that is the mode's contract (ADR-051).
- **Everything else is unchanged:** cache, lists, replication, query log, probes (they keep measuring;
  their results are just not alerted on), the API and UI, self-update checks.

## 4. Elsewhere in the cluster (decision)
On the primary (where alerts and the health level are evaluated) and on any node answering
`/system/health`:
- **Alert rules** skip the node for `node_down`, `sync_lag`, `probe_failing`, `cert_expiring`,
  `disk_full`, `servfail_rate` (its share), and the `not_serving` condition; firing alerts about it
  are resolved with the summary suffix "(maintenance)". When the window ends, evaluation resumes and
  `for_secs` counts from zero (a node that's actually broken shows up after the usual delay).
- **Health level** (`health.rs`): reasons whose `node` is in maintenance are dropped before the level
  is computed; the response gains `maintenance: [ { node, until, reason, by } ]` and the UI panel shows
  "1 node in maintenance until 14:00 (SD card swap)". The level itself is unaffected (healthy stays
  healthy). Severe `no node serving` still counts a maintenance node as serving if it is — it answers.
- **Cluster page checks** (`load balance`, `serving`, `versions`, `node_settings`) skip the node;
  its row shows a wrench badge and the window; the topology diagram hatches it.
- **SLOs** are unchanged: its answers are real answers.
- **Alert rule `maintenance`** (`AlertWhen::Maintenance`): fires once when a node enters (subject =
  node; summary includes until and reason), resolves when it leaves. Not in the default rules; the
  owner adds it to the ntfy destination if wanted.

## 5. API, forwarding, CLI, MCP (decision)
- `POST /api/v1/nodes/{id}/maintenance { forSecs?: 3600, reason: "...", handover?: true }`
  (operator; `id = "local"` for this node) → `200 { node, until, since, reason, by, handover:
  "started" | "not_needed" | "unavailable", note? }`. `DELETE /api/v1/nodes/{id}/maintenance` ends
  it. Validation: `reason` required (1–200 chars), `60 ≤ forSecs ≤ 86400`. Starting again
  **extends/replaces** the window (new `until`, new reason, audited as a start). `handover` is ignored
  for non-primaries (`not_needed`).
- **Forwarding:** this is node state, so the entry node sends an RPC `maint.set { until_ms, reason,
  by }` / `maint.clear` to the **target node** over the existing cluster streams (the same pattern as
  the federated tail's `TailOpen` to a peer, and `cert.renew`), carrying the user's identity like
  write forwarding does (`<user> via <site>`). The target writes the file, flips readiness, and
  audits. A target that's unreachable → `503 node_unreachable`. A standalone node acts on itself.
- **Audit:** `node.maintenance.start` (until, reason) and `node.maintenance.end` (by whom, or
  `expired`) on the target node (and, as every forwarded write, the entry node's audit line names
  the forward).
- **CLI:** `telltale ctl maintenance start --for 2h --reason "SD swap" [--node <id>]`,
  `telltale ctl maintenance end [--node <id>]`, `telltale ctl maintenance status`.
- **MCP:** `start_maintenance { node, forSecs, reason }` and `end_maintenance { node, reason }`:
  immediate ops (like `pause_blocking`), scope `ops:maintenance`, agents capped at **2 h**
  (`422` with the cap in the hint), audited with the agent's reason. `cluster_status` shows each
  node's window.
- **Problem codes:** `maintenance_too_long`, `node_unreachable`, `node_unknown`.

## 6. UI
- **Cluster page:** per-node menu → "Maintenance…" (a small form: duration presets 30 m / 1 h / 2 h /
  4 h / custom, reason; when the node is the primary **and** failover is automatic with another
  eligible node online, a checked box "Hand the primary role to another node first (about 30 s
  without configuration changes)"; otherwise the note "This node is the primary; it keeps publishing.
  Promote another node first if you're taking it offline." with a link). While active: a wrench badge
  with the countdown and reason on the row, an "End maintenance" action, and a banner at the top of
  the page when **this** node (the one serving the UI) is in maintenance.
- **Health panel:** the note from §4; the icon stays as the level dictates.
- **Alerts page:** suppressed alerts aren't listed as firing; a line says "Alerts for <node> are
  paused during maintenance until …".
- Help topic `maintenance` (what changes, what doesn't, the Kubernetes single-probe note, why DNS
  keeps answering).

## 7. Kubernetes notes (document; no chart change)
- One readiness probe per pod serves every Service that selects it. A **resolver pod** in maintenance
  leaves the DNS Service: exactly what's wanted. A **controller pod** in maintenance also leaves the
  API Service: the UI is reachable from any other node (CLU-002) or `kubectl port-forward`. For
  controller work, `kubectl drain`/rollout is the normal path; maintenance mode is for the Pi and for
  individual pods.
- A StatefulSet rolling update waits for readiness; a pod in maintenance blocks a rollout until the
  window ends — expected, mention it.
- The chart needs no new values. `NOTES.txt` gets one line pointing at the docs section.

## 8. Config
None required. Optional node-local knob for the default duration:
```toml
[node]
maintenance_default_secs = 3600   # 60..86400
```
Keep it; don't add more. The feature is a verb, not a section.

## 9. Metrics
`telltale_node_maintenance` (0/1), `telltale_node_maintenance_until_seconds` (Unix time, 0 when
none), `telltale_node_maintenance_total` (starts). Per node; the Grafana cluster row gets a state
timeline. Chart alert rules are deliberately **not** added for maintenance itself; instead the
existing `TelltaleDNSNodeDown`-style rules should `unless on(node) telltale_node_maintenance == 1`
— add that to the chart's rules and to `deploy/prometheus/` and test with promtool.

## 10. Performance
Nothing on the query path (one `AtomicBool` already exists). One extra heartbeat field. An expiry
timer per node.

## 11. Tests (map to the AC in `spec/10`)
- Unit: window file round-trip and expiry; readiness composition (bound/synced/maintenance);
  `/readyz` body reasons; validation (bounds, reason, agent cap); alert exclusion and "(maintenance)"
  resolution; health reason filtering and the `maintenance` list; election: not a candidate, still a
  voter; forwarded RPC to a peer and `503` when unreachable.
- Cluster e2e (`deploy/cluster/e2e.sh` new step): start on the primary for the replica → the replica's
  file exists, `/readyz` 503, `dig` keeps answering under load (0 lost), SIGSTOP the replica → no
  `node_down`, health `healthy` with the node listed; SIGCONT, end maintenance, SIGSTOP again →
  `node_down` fires. Restart the replica inside the window → still 503 with the same `until`.
- Failover e2e: with the only eligible replica in maintenance, killing the primary elects nobody
  until maintenance ends (then it is elected). Handover: starting maintenance on the primary (auto
  mode, an eligible replica up) elects the replica within the lease window, 100 % of DNS answered,
  the old primary follows; with `handover = false` or in manual mode it stays primary and the
  response carries the note. Simulator: a stepping-down primary never publishes in the new epoch
  (mutation-check the `stepping_down` flag like the other election properties).
- Promtool: the chart's node rules stay quiet with `telltale_node_maintenance == 1`.
- Playwright: Cluster page start → banner, badge, health note → end.

## 12. Implementation order
1. `maintenance.rs` + file + readiness composition + `/readyz` body; `ctl maintenance` for `local`.
2. Heartbeat field; primary stores it; `cluster_status`/Cluster page row badge.
3. Alert exclusion + "(maintenance)" resolution; health filtering + `maintenance` list; Cluster-page
   checks skip; election candidacy.
4. Handover: `stepping_down` in `election.rs`, the simulator property, the failover e2e step.
5. RPC forwarding to a target node; API endpoints; audit; MCP tools; alert rule `maintenance`.
6. UI form/banner, help, metrics, chart rule `unless`, docs, site. Tick the task.

## 13. Decisions taken with the owner (2026-10-09)
- The owner asked for the best experience on a primary in maintenance. **Decision:** hand over when
  the cluster can do it safely (automatic failover, another eligible node or quorum reachable), on by
  default and visible as a checkbox; otherwise allow maintenance with a clear note to promote first.
  Never refuse: the operator knows why they're here.
- Agent cap of 2 h for `start_maintenance` stands (not raised as a question; change it in the tool's
  one constant if the owner disagrees).
