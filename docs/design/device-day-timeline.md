# Device "day in the life" timeline: design notes (T14.8)

**Requirement:** OBS-034 (new). **ADR:** ADR-134 (new, Proposed). **Spec section:** `07` §3 (Clients
→ device drawer gains *Timeline*); `06` §7 analytics table gains a row. **Owner request:** 2026-10-16.

## 1. What it is, in one paragraph
One device, one day (or any window up to 7 days), as swimlanes: a lane per registrable domain (top 30
by queries, the rest folded into "other"), 5-minute bins coloured by count, plus overlay lanes for
first-seen domains (OBS-009 feed), anomaly findings (OBS-013), identification changes (OBS-025),
blocked answers, slow answers, and the node's change markers (T14.7). For 192.168.2.14 it shows the
NTP loop starting at 14:xx UTC and nothing before: *when did this device appear, and what else did it
do?* It composes what the product already computes into a story you can scroll.

## 2. Non-goals
- A per-device rollup. The source is the query log for the window (bounded, §3); older than the log,
  the timeline says so rather than inventing bins.
- Editing anything. Every element links to the page that acts (Rules, Groups, Anomalies).

## 3. Data (decision)
Server-side aggregation, because a day of one device can be 10k rows and agents need the compact
form too:

`GET /api/v1/clients/{id}/timeline?from&to&bins=288&lanes=30&scope` — the API handler runs the
query-log column reader for that client over the window (projection: `ts`, `qname`, `status`,
`rcode`, `total_us`), block-pruned by the `client_ref` bloom filter, **newest first, capped at 500,000
rows and 5 s** (`truncated: true` beyond), and folds rows into:
- `lanes`: `[{ "domain": "pool.ntp.org", "counts": [u32 × bins], "blocked": [u16 × bins], "slow": [u16 × bins], "total": 4453, "firstSeenTime": "..." }]`,
  top `lanes` by total plus an `other` lane; `domain` is the registrable domain (the same
  `etld1` helper the anomaly engine uses).
- `events`: `[{ "time", "kind": "firstSeen|anomaly|identity|blockedBurst", "summary", "href" }]`:
  first-seen from the new-domains feed for this client, anomaly findings for this client in the window
  (`GET /analytics/anomalies` filtered), identity changes (store the previous identity's time in
  `devices.json` — add `changedAt`), and blocked bursts (≥ 10 blocked in a bin) derived from the lanes.
- `markers`: the node's annotations in the window (T14.7).
- `bins`: the start times; `source`: `querylog`; `coverageFrom`: the oldest row time the log had
  (the UI greys the part of the window before it).

Federated (`Read::ClientTimeline`): each node folds its own rows for the device (pods ship rows to
the primary; the primary's handler reads shipped rows the way `GET /queries` does); lanes are merged by
domain, counts summed per bin. Privacy: at ≥ 1 names are hashes → lanes keep `domain: null` with
counts (the shape still tells the story); at ≥ 2, 404 `privacy_level`.

Cost: one bounded log scan per request on the API thread, same class as `GET /queries`; cache the
response in memory for 30 s per (client, window) so a refreshing page doesn't rescan.

## 4. API, MCP
As above. MCP `device_timeline(client, window, lanes)` returning lanes without the per-bin arrays by
default (`bins: 24` for agents, so a day is 24 numbers per lane), plus `events`. Add it to the
"investigate device" prompt (AGT-010) when that lands. Metrics: none.

## 5. UI (decision)
- Clients page → device drawer → new **Timeline** tab (default window: last 24 h; 7 d max; the
  window picker shared with the heatmap). Deep link `#/clients?device=…&tab=timeline`, also linked
  from an anomaly finding ("see the day") and from the heatmap's device mode.
- Canvas swimlanes (`ui/src/lib/timeline.ts` layout + draw): x = time, one 18 px lane per domain, bin
  cells coloured by count with the heatmap's square-root ramp on `--hm-ink`; blocked bins get a red
  underline, slow bins an amber tick. Above the lanes, an **events rail**: dots for first-seen (hollow),
  anomaly (filled `--s-warn`), identity (diamond), blocked burst (red); change markers as grey ticks
  (T14.7). Hover a cell: "15:05–15:10 · pool.ntp.org · 120 queries, 0 blocked"; hover an event: its
  summary; click → its `href`. Click a lane label → Query log for that device and name in the window.
- A lane with `firstSeenTime` inside the window gets a small "new" tag at that time.
- Greyed region before `coverageFrom` with "the query log starts here". `truncated` → banner.
- Table view: lanes × bins. Phone: lanes scroll horizontally, labels sticky.

## 6. Grafana
None (no per-device metrics by default; `telltale_client_queries_total` is opt-in and top-N only).

## 7. Acceptance criteria
1. Fixture log: device A, 24 h, `pool.ntp.org` every 2.5 s from 14:00 to 18:30, `example.com` 10×/h all
   day, 3 blocked bursts → the `pool.ntp.org` lane has zeros before 14:00 and ≈ 120 per 5-min bin
   after; `events` has 3 `blockedBurst`, one `firstSeen` for `pool.ntp.org` at 14:00; `other` is
   absent (2 domains < 30 lanes).
2. 600k rows for one device → `truncated: true`, 5 s deadline honoured (test with a slow reader stub).
3. Privacy 1 → `domain: null` lanes; privacy 2 → 404.
4. Federation: two nodes each with half the rows → merged lane totals equal the sum; a down node →
   `missingNodes`.
5. Cache: two requests within 30 s scan once (counter in the test build).
6. Playwright `obs_034 device timeline`: the tab renders lanes; an event click navigates; a lane label
   click opens the Query log; table view; both themes.
7. Docs: `running.md` *Clients* → "A device's day"; site page; help topic `device-timeline`;
   OpenAPI/MCP regenerated.

## 8. Open
- A **latency lane** (per-bin p99 for the device) is one more fold over `total_us` — I'd include it
  (it answers "why is the TV slow?", `spec/13` §1). Ask; default include if the 5 s budget holds.

## 9. Decided at the start of the task (owner: accept all defaults, 2026-10-16)
Recorded in ADR-134:
- **Source:** three vqlog reads on the entry node (queries by domain and status, slow answers by
  domain, every query with its p99, per bin), over its query log and the rows shipped to it, like
  the flow's device mode (T14.6). No `Read::ClientTimeline`; nodes whose rows aren't there are
  `missingNodes` (vqlog's).
- **Bounds:** vqlog's own (2 million matching rows, 100,000 groups, 25 s) instead of 500,000 rows
  and 5 s; `truncated` with the reason. The slow-reader stub of §7 AC 2 isn't built.
- **Cache:** 30 s per (device, bin-aligned window, bins, lanes, privacy level), at most 64 answers.
- **The latency lane is in** (§8's default, and T14.4's deferral): p99 per bin under the lanes.
- **Identity changes aren't events yet** (they need `changedAt` in `devices.json`): deferred.
- **Agents need `querylog:read`**: a device's names bin by bin read like its query log.
- **Privacy:** level 1 lanes without a domain; level 2 `422 privacy_level` (like T14.3 and T14.6),
  not 404. `id` is an address.
- **UI:** the Clients page's device drawer has **Rhythm** and **Timeline**; the deep link is
  `#/clients?device=…&view=timeline` (`tab` is the Clients page's own). Linked from anomaly findings
  (*See the day*) and the heatmap's device mode (*Day timeline*). The events rail is HTML (each dot
  a link), the lanes a canvas. The table shows lanes × at most 24 time columns (bins summed) and a
  p99 row. `coverageFrom` comes from `retention_days`, not the oldest row.
- Bins are whole minutes aligned like vqlog's buckets (288 by default); MCP `device_timeline`
  defaults to 24 bins and 10 lanes.
