# Change markers (annotations): design notes (T14.7)

**Requirement:** OBS-033 (new). **ADR:** ADR-133 (new, Proposed). **Spec section:** `06` §3.1 (new)
*Annotations*; `07` §3 note "every time chart shows change markers". **Owner request:** 2026-10-16.
**Build this first:** T14.1, T14.3, T14.4, T14.8 overlay it.

## 1. What it is, in one paragraph
Every time-axis chart gets thin vertical markers for the things an operator did or the node did to
itself: a configuration version applied (and from where: UI, API, agent, GitOps), a new build
started, a restart, a list refresh that changed the rules, a rollout stage, maintenance entered or
left, blocking paused or resumed, cache flushed. Hover says what and who. The same events are
available as Prometheus signals so Grafana can draw them. Correlating "we rolled edge.232 at 02:52Z"
with "SERVFAILs stopped" by eyeballing timestamps was the thing I swore I'd never do again.

## 2. Non-goals
- A second audit log. The audit table (`audit`, hash-chained, primary-only) is about *who was
  allowed to do what*; annotations are a per-node, bounded, best-effort timeline of *what happened to
  this node*. They overlap and that is fine; annotations link to the audit entry when there is one.
- Pushing to Grafana's annotations API (needs credentials; a Prometheus-derived marker needs none).
- Editing or deleting annotations. Manual notes (§3.1) are append-only like the audit log; a wrong
  note gets a correcting note.

## 3. Data (decision)
A per-node append-only file `<data_dir>/annotations.jsonl`, written by the background tasks that
already know about each event (not the hot path, not the telemetry thread), **capped at 20,000 lines
and 90 days** (compact in place at start and once a day). One line:
```json
{"t":"2026-10-13T02:52:11Z","kind":"config.applied","seq":312,"source":"gitops","actor":"gitops","summary":"configuration 312 applied (gitops, 3 sections changed)","ref":{"audit":4181}}
```
Kinds and where to hook them (all exist as log lines or state changes today):
| kind | hook | fields |
|---|---|---|
| `config.applied` | replication apply (`applied.json` write) and the local apply path | `seq`, `source` (`ui`/`api`/`agent`/`gitops`/`file`), `actor`, changed sections |
| `build.started` | server start when `build_info` differs from the previous line's | `version`, `commit` |
| `node.restarted` | server start (always) | `uncleanShutdown` bool from the datadir lock |
| `lists.refreshed` | list fetcher after a compile that changed the snapshot | `lists` changed, `rulesDelta` |
| `rollout.stage` | rollout state transitions (ADR-116) | `stage`, `version` |
| `maintenance.entered`/`.left` | maintenance.rs | `until`, `reason` |
| `blocking.paused`/`.resumed` | blocking API | `by`, `until` |
| `cache.flushed` | cache API | `by` |
| `upstream.breaker` | breaker open/close, rate-limited to one line per upstream per 5 min | `upstream`, `state` |
| `note` | `POST /api/v1/annotations` (§3.1) | `text`, `actor` |

### 3.1 Manual notes (decision, owner 2026-10-16)
Automatic markers cover what the node can see about itself. What usually explains a DNS graph on a
home network is external — router firmware, a new access point, the ISP flapping, a migration — so
an operator or an agent can put a **note** on the time axis:
- `POST /api/v1/annotations` with `{ "text": "moved the AP", "time"?: "<RFC 3339>" }`. `text` is 1–200
  characters after trimming (422 `annotation_text` otherwise); `time` defaults to now and may be up
  to 7 days in the past, never in the future (422 `annotation_time`). The kind is always `note`;
  `actor` comes from the session or token (agents: `agent:<name> (owner: <user>)`, AGT-005).
- Scope `ops:annotate` (new; in the default agent set? **no** — read-only stays the default). An
  audit entry `annotation.note` is written too. Not configuration, so a GitOps authority doesn't
  refuse it and nothing is replicated: the receiving node appends the line with its own `node`
  label, and the federated read shows it on every node's charts.
- `PUT`/`DELETE` answer 405. No rich text, no tags, no attachments.
- MCP `annotate(text, time?)` — the tool description says "leaves a visible note on every time chart;
  use it to record why you changed something or what happened on the network".

Writes are `O_APPEND` single lines, fsync not required (losing a marker is acceptable; the audit log is
the record). A write failure logs once per hour and never affects anything else (CLU-004 spirit).

## 4. API (decision)
`GET /api/v1/annotations?from&to&kinds=&scope&limit=500` → `{ "items": [ {...line, "node": "pi"} ],
"truncated": false, "missingNodes": [] }`, federated (`Read::Annotations`), merged by time desc, cap
2,000 total. Scope `analytics:read`. `POST /api/v1/annotations` as in §3.1 (201 with the written line).
MCP `list_annotations(window, kinds)` and `annotate(text, time?)`; also inject the window's
markers into `get_overview` as `changes` (count + the last three summaries) — agents asking "what
changed?" shouldn't need a second call.

**Prometheus signals** (for Grafana, no new cardinality):
- `telltale_config_seq` gauge (the applied configuration sequence) — `changes(telltale_config_seq[5m]) > 0`
  is the marker.
- `telltale_build_info{version,commit}` already exists? If not, add it (value 1); `changes()` on it
  marks a new build.
- `telltale_filter_snapshot_version` exists → list refreshes.
- `telltale_annotations_total{kind}` counter — one per line written; `increase()` marks the rest.

## 5. UI (decision)
- `Chart.svelte` gains `markers?: Marker[]` (`{ time, kind, summary, href? }`) and draws them as 1 px
  vertical lines in `--mk-ink` from the plot top to the x axis with a small kind glyph above the axis
  (uPlot `hooks.draw`); hover within 4 px shows the summary in the existing tooltip; click opens
  `href` (`#/settings?tab=system&audit=<seq>`, `#/cluster`, `#/lists`). A chart with more than 40
  markers in view collapses them into count badges per pixel column ("×3").
- One `annotations.svelte.ts` store fetches the current dashboard window once and shares it with
  every chart on the page (one request per window change, not one per chart). Heatmaps (T14.3, T14.4)
  draw ticks in their column header from the same store; the device timeline (T14.8) draws them as a
  lane.
- A **Changes** toggle in the dashboard header (remembered in `localStorage` like `dashboard.scope`);
  default on. Kind filter chips in the Advanced view.
- Settings → System gets a **Changes** list (the last 200 lines, filterable), which doubles as the
  table view.
- Node pages (Cluster → node) show that node's markers only.
- **Add a note:** a small "Note…" button next to the Changes toggle opens a one-line form (text,
  optional time); notes draw with a distinct glyph and the actor in the tooltip.

## 6. Grafana
`build.py`: add dashboard-level annotations (Prometheus datasource) for
`changes(telltale_config_seq[5m]) > 0` ("config {{seq}}"), `changes(telltale_filter_snapshot_version[5m]) > 0`
("lists"), and `resets(process_start_time_seconds)`/build changes ("restart"). Document in
`docs/monitoring`.

## 7. Acceptance criteria
1. Unit: applying configuration 313 from GitOps writes one `config.applied` line with `seq: 313`,
   `source: "gitops"`; a restart writes `node.restarted` (and `build.started` only when the build
   changed — assert both cases); a list refresh that changes nothing writes no line.
2. Cap: 25,000 synthetic lines → file compacts to the newest 20,000 at start; lines older than 90 d
   are dropped; a read-only data dir → one warning, service unaffected (test with a mocked write
   error).
3. Federated read merges two nodes by time desc; `missingNodes` for a down node; `truncated` at the
   cap.
4. `telltale_config_seq` equals the applied sequence on every node; `telltale_annotations_total{kind}`
   increments per line.
5. Notes: a posted note appears in the federated read from another node with the writer's `node`
   label; a 201-character text → 422 `annotation_text`; a future time → 422 `annotation_time`; `PUT`
   and `DELETE` → 405; an agent token without `ops:annotate` → 403; the audit log has
   `annotation.note` with the agent's owner.
6. Playwright `obs_033 change markers`: after a config change in the e2e, the dashboard's Queries chart
   shows a marker whose hover names the sequence; the toggle hides it; Settings → System lists it; the
   "Note…" form adds a marker that shows the actor on hover.
7. Docs: `running.md` *Change markers* (incl. notes); `docs/monitoring` Grafana annotations; site
   page; help topic `change-markers`; OpenAPI/MCP regenerated; Helm chart's dashboard JSON rebuilt.

## 8. Open
Nothing. (Manual notes were decided in on 2026-10-16; `upstream.breaker` is rate-limited by
decision.)

## 9. Decided at the start of the task (owner, 2026-10-16)
Gaps found against the code, settled with the conservative option and recorded in ADR-133:
1. `seq` is the cluster's sequence on a clustered node, else `state.db`'s configuration version.
2. Only the primary or a standalone node knows a write's `source` and `actor`; a replica writes
   `gitops` (the manifest names a commit) or `cluster`, without an actor.
3. `config.applied` only when the configuration changed (not for users, tokens, acknowledgements).
4. Every node's line is kept; the UI merges one kind and `seq` across nodes into one marker.
5. `lists.refreshed` only on the node that compiles lists.
6. Notes need the operator role (agents `ops:annotate`).
7. `GET /api/v1/annotations` pages back with `before`.
