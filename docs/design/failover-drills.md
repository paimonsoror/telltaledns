# Failover drills and coverage reports: design notes (T15.2)

**Requirement:** CLU-014 (new, P1). **ADR:** ADR-151 (new, Proposed). **Spec sections:** `12` §8 (client-
facing HA) gains "Drills"; `06` §8.5 (new) "Failover coverage". **Owner request:** 2026-10-18. **Builds
on:** OPS-010 maintenance mode (ADR-118), OBS-033 change markers, CLU-002 federated reads, FLT-009's
lock-free `Pause` pattern, AGT-007 plan/apply.

## 1. What it is, in one paragraph
A drill makes one node stop answering a chosen set of devices (or all of them) for a bounded time, on
purpose, while the rest of the cluster keeps serving, and then reports **who followed**: which devices
moved to another node, how long each took, which kept asking the silent node until the drill ended, and
which went quiet. On a healthy network every device uses its first DNS server and never touches the
second, so this is the only honest way to learn whether the second server the router hands out actually
works for every device, before the day the Pi's SD card dies. The report is a lens on the devices and the
balancer, not a health condition; it leaves a change marker and a number on the Cluster page.

## 2. Non-goals
- Scheduled or automatic drills (**open**, §12). v1 drills are started by a person or by an agent's
  approved plan.
- Measuring unplanned outages the same way (deferred: it needs always-on per-window client counts the
  aggregator doesn't keep; §5 says what would be needed). The node-down timeline on the Cluster page is
  unchanged.
- Dropping anything but DNS. The API, cluster channel, metrics, and probes stay up; probe failures during
  a drill are expected and muted like maintenance.
- A passive "single-homed devices" health finding. §9 keeps a small affinity view with the caveat printed
  on it; it never degrades health and never alerts.

## 3. What a drill does on the node (decision)
A drill is a **maintenance window with a drop**. It reuses `maintenance.rs` end to end (readiness off,
alerts muted, left out of elections and the health level, the window file, expiry, forwarding to the
node, the Cluster page badge) and adds:
- **The drop.** For the drill's targets, the node does not answer: UDP queries are discarded after client
  identification (so group targets work) and before rate limiting; TCP, DoT, DoH, and DoQ connections
  from a target are closed without a response (the nearest thing to a dead node). Counted as a new
  QueryEvent status `drilled` (one new `u8` variant; the aggregator counts it like any status; the query
  log shows it as *drilled*, grey), so the report can say how many questions the device kept sending to
  the silent node and when the last one was.
- **The check on the query path** is one relaxed atomic load of `drill_until_ms` (0 when none); only
  when non-zero, one `ArcSwap` load of the target set and a lookup (addresses: a hash set; a group: the
  identity's group index; "everyone": no lookup). `Pause` is the model. A/B `make bench-smoke` with no
  drill must be within noise.
- **Never dropped:** `[clients] infrastructure`, the node's own addresses, loopback, other cluster nodes
  (the registry's addresses), and anything in the exclusions list (OBS-022) — those devices are not in
  the report either.
- **Bounds:** `forSecs` default 60, minimum 15, maximum 300 (a hard cap, not configurable: a drill that
  runs long is an outage). Ends on expiry or `DELETE`. The window file records `drill: true`; **on restart a
  drill is cancelled, never resumed** (readiness comes back, nothing is dropped), unlike maintenance.
- **Handover:** a drill on the primary hands over like maintenance does (ADR-118 `handover`), so writes
  keep working; with manual failover and no other eligible node, the drill still runs (DNS is what's being
  tested) and the response says `handover: "none"`.

## 4. Preconditions (decision; 409 `drill_refused` with the reason as the hint)
- At least one **other** node is `ready` and has answered a query in the last 5 minutes (a drill with
  nobody to fail over to is an outage).
- The node is not in maintenance and no drill ran anywhere in the cluster in the last 10 minutes (one
  drill at a time; let devices settle).
- The cluster isn't pinned by a failing rollout (CLU-013) and no rollout is baking.
- The health level isn't `severe`.
- Targets resolve to at least one device seen on this node in the last hour (a drill on nothing is a
  typo), unless `targets = "all"`.
Not a configuration change: allowed under GitOps authority, audited (`drill.start`, `drill.end` with the
summary), needs the `operator` role; agents need `ops:drill` (not in the default scope set) and a reason.

## 5. Measuring coverage (decision)
Three ingredients, all off the query path:

**a. The seen table** (new, `crates/telltale-telemetry/src/seen.rs`, on the telemetry thread): per
client key → `{ first_s, last_s, queries }`, capped at 4,096 clients (beyond it, `overflow` counts and
new clients aren't tracked; the report says so), persisted to `<data_dir>/clients-seen.json` hourly and
at shutdown, loaded at start, 30-day expiry. It gives the **baseline**: who used this node in the hour
before the drill. With T15.1 built, pods are keyed by their workload.

**b. The drill window map** (same module): while a drill is active **anywhere in the cluster** (every
node learns it from the drilled node's heartbeat flag; a new `Heartbeat.drill_id` field, N−1 compatible),
every node keeps `client → { first_ms, last_ms, queries, drilled }` for the window, cap 4,096, and freezes
it at the end plus a **60 s grace** (late failovers) into `<data_dir>/drills/<id>.part.json`. Nodes that
didn't notice the drill (older build, partition) are reported as missing.

**c. The report** is assembled by the drilled node 60 s after the drill ends: it asks every peer for its
part (`Read::DrillPart { id }`, federated, 2 s deadline, retried for up to 5 minutes), merges, saves
`<data_dir>/drills/<id>.json` (keep the last 50; older ones pruned), writes the annotation `drill.ended`
with the summary, and sets the metrics. Per device in the **baseline ∪ targets ∪ anyone who queried any
node during the window**, the verdict is:
| verdict | meaning |
|---|---|
| `followed` | at least one query on another node during the window, after its first dropped query (or with none dropped: it was already elsewhere) |
| `stuck` | ≥ 3 dropped queries on the drilled node and nothing anywhere else: it has no working second server (or its second server is this node again) |
| `quiet` | no queries anywhere during the window: unknown (it may just have been idle) |
| `elsewhere` | not in the baseline and not a target; it queried another node during the window: informational |
Per `followed` device: `timeToFailoverMs` = first query elsewhere − first dropped query (absent when
nothing was dropped), and `returned` = whether it queried the drilled node again within 15 minutes after
the drill (the OS went back) or stayed on the other node (`sticky`; Windows stays for about 15 minutes,
which is worth seeing). Summary: counts per verdict, coverage = followed / (followed + stuck), median and
p90 time to failover, the stuck devices with names and groups, and the per-node query counts during the
window.

**A Kubernetes resolver pod behind one balancer address** gets the same drill but a different story: its
clients never see a server change; what the report measures is the balancer. For an ephemeral node the
report adds `balancerSwitchMs` = last dropped query − drill start (how long the Service kept sending to a
not-ready pod) and labels the device verdicts "via balancer". The owner's two addresses (the Pi and
.112) are two servers from a device's point of view; the Pi is the interesting drill.

## 6. API, CLI, MCP (decision)
- `POST /api/v1/nodes/{id}/drill` `{ "forSecs": 60, "targets": "all" | { "clients": ["192.168.2.14",
  "kids-tablet"] } | { "group": "iot" }, "reason": "...", "handover": true }` → `201 { id, node, until,
  since, targetsResolved, handover }`; `id = "local"` for this node. Forwarded to the node like maintenance.
  `?dryRun=true` returns the resolved targets, the baseline size, and which preconditions pass.
- `DELETE /api/v1/nodes/{id}/drill` ends it early (the report still runs). `GET /api/v1/nodes/{id}/drill`
  → the active drill or 404.
- `GET /api/v1/drills?limit=20&cursor=` (federated: each node lists its own reports; merged by time;
  `missingNodes`) → summaries; `GET /api/v1/drills/{id}` → the full report (from the node that ran it;
  404 with a hint naming the node when it's unreachable). Privacy level 2+: verdict counts only, no
  device names.
- CLI: `telltale drill start [--for 60s] [--group iot | --client ...] --reason ...`, `telltale drill stop`,
  `telltale drill report [id]`, `telltale ctl drill ...` over the API.
- MCP: `plan_failover_drill(node, forSecs, targets, reason)` → a plan (the approval inbox applies when
  `[agents] require_approval`; the plan's impact text names the baseline size and the precondition
  results); `drill_report(id?)` (read; the newest by default); `get_overview` mentions the last drill's
  coverage in `changes` when it ran in the window.
- Problem codes: `drill_refused` (409), `drill_active` (409 on a second start), `drill_targets` (422).

## 7. UI (decision)
- **Cluster page → node card:** a **Drill…** button beside **Maintenance…** (operator+): a form with
  duration, targets (everyone / a group / pick devices from the baseline list with their names), reason,
  and a plain-language preview ("For 60 seconds this node will not answer 23 devices. Devices with a second
  DNS server switch to it within a few seconds; devices without one lose DNS until the drill ends."), then
  a live view during the drill (dropped so far, followed so far, seconds left, **End now**).
- **Cluster page → Drills:** a list of reports (when, node, targets, coverage, stuck count) and the
  report view: the summary tiles, the device table with verdict, time to failover, returned/sticky, group,
  and a chip to the device's timeline; the table **is** the table view. A small bar of time-to-failover
  (uPlot) with reduced motion respected.
- The dashboard's time charts get the `drill.started`/`drill.ended` markers for free (OBS-033).
- Help topic `failover-drill` with the diagram (device → node A silent → node B answers) and the caution
  text; the glossary gets "drill".

## 8. Metrics, alerts, health (decision)
`telltale_drill_active` (0/1), `telltale_drill_dropped_total`, `telltale_drill_last_coverage_percent`,
`telltale_drill_last_stuck`, `telltale_drill_last_failover_ms{quantile="0.5"|"0.9"}`, `telltale_drills_
total{result="completed"|"cancelled"}`. Alerts during a drill are muted exactly as in maintenance
(`maintenance` rule stays silent for drills; **decision:** a drill raises the existing `maintenance`
alert kind with "drill" in the text when `for_secs = 0`, so operators who want to hear about drills can).
Health: never changed by a drill or its report. PrometheusRule: none new (the muting is the point).

## 9. The affinity view (decision; small, honest)
`GET /api/v1/clients/affinity?window=7d` (federated over the seen tables): per device, queries per node
and the share on its most-used node; the Clients page shows it as a column ("mostly Pi", "both") in the
Advanced view with this caveat in the help panel and the API description: *"A device that has only used
one server may still have a second one configured; most systems use their first server until it stops
answering. Run a drill to find out."* No finding, no alert, no health reason.

## 10. Performance
- Query path: one relaxed load when no drill is active (A/B within noise); during a drill, one hash
  lookup for the targets, reported.
- Telemetry thread: the seen table is one hash update per event (`bench.py sustain`, 0 drops, CPU);
  the window map exists only during drills.
- Memory: 4,096 entries × ~40 B per table; report files under 200 KB.

## 11. Acceptance criteria
1. Drop: with a drill active for `{ clients: [A] }`, UDP queries from A get no answer and count as
   `drilled` in the aggregates and the query log; queries from B are answered; a TCP connection from A is
   closed without a response; infrastructure and excluded addresses are answered even under `all`.
2. Lifecycle: `forSecs` 301 → 422; a start on a node in maintenance → 409 `drill_refused`; a second start
   → 409 `drill_active`; `DELETE` ends it and the report still runs; a restart during a drill cancels it
   (readiness back, nothing dropped, `telltale_drills_total{result="cancelled"}`); the window expires by
   itself; both audit entries exist with the actor and reason; an agent without `ops:drill` → 403.
3. Preconditions: a single-node cluster → 409 with the "no other node" hint; a cluster pinned by a rollout
   → 409; `targets: { group: "nope" }` → 422.
4. Report, in `deploy/cluster/e2e.sh` (primary + replica, both answering): a test stub resolver with two
   servers and a 1 s timeout (primary first) and a second stub with the primary only; a drill on the
   primary for 20 s targeting both → the report says the first `followed` with `timeToFailoverMs` between
   900 and 3,000, the second `stuck` with ≥ 3 dropped, coverage 50 %, the replica's part merged, the
   annotation written, the metrics set; the report is listed from the replica with `missingNodes: []`;
   with the replica stopped before the grace ends, it is retried and then listed under `missingNodes`.
5. Returned/sticky: the stub that goes back to the primary after the drill is `returned: true` within the
   15-minute check (shortened by a test hook).
6. Seen table: capped at 4,096 with `overflow` counted; persists across a restart; honours exclusions;
   with T15.1, three pod addresses of one workload are one entry.
7. Heartbeat: an N−1 peer without `drill_id` is reported missing from the report, not an error.
8. UI: Playwright `clu_014 drill`: start a 15 s drill from the Cluster page on the replica with the
   preview text visible, watch the live counters, open the report, see verdicts and the marker on the
   dashboard; the affinity column appears in Advanced with its help text.
9. Bench: §10 numbers in the report; `make bench-smoke` A/B with no drill within noise.
10. Docs: `running.md` "Failover drills" (what it does to devices, the preconditions, reading a report, the
    Kubernetes balancer case) and the affinity caveat; site page and diagram; help topics; OpenAPI and MCP
    regenerated; ADR-151 and CLU-014 written; the `12` §8 and `06` §8.5 paragraphs; roadmap ticked.

## 12. Open
- **Scheduled drills** (monthly, a group at a time, report by email through the alert transports): ask
  the owner. Decision if they say yes: `[drill] schedule = "monthly"` plus `targets`, run at 03:00 node
  local time on a random day in the first week, never when any precondition fails, and never on a node
  that has run one in the last 7 days.
- **Dropping versus answering REFUSED:** the design drops because every stub resolver fails over on a
  timeout and only some on REFUSED. If the owner prefers a faster, less realistic drill, `mode:
  "refused"` is a one-line addition; don't build it unless asked.
- **The live Pi:** the obvious first real drill. Ask before running it; suggest a 30-second drill on the
  owner's own laptop first, then a group, then all.
