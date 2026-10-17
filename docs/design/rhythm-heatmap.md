# Rhythm heatmap (hour-of-day × day): design notes (T14.3)

**Requirement:** OBS-029 (new). **ADR:** ADR-129 (new, Proposed) — the per-minute heatmap ADR-123
left "possible later, behind a benchmark". **Spec section:** `07` §3 row *Heatmap*; `06` §3 note.
**Owner request:** 2026-10-16 ("the massive burst around 10 am to 2 pm").

## 1. What it is, in one paragraph
A grid where rows are days (or weekdays) and columns are hours (or 15-minute slots), each cell
coloured by queries — for the whole network, for one device, or for one name. A 10 am–2 pm burst is a
bright band on one row; a device that polls NTP every 2.5 s is a stripe across every day; a kid's
tablet shows its bedtime. It is the sibling of the Traffic map (OBS-026): the treemap says *what*,
the heatmap says *when*.

## 2. Non-goals
- Minute-level per-device or per-name grids over months. Bounded storage only (§3).
- Any new hot-path work. All three variants read what the rollups already keep.

## 3. Data (decision)
Three variants, three sources, each labelled with its precision in the UI:

| Variant | Source | Precision |
|---|---|---|
| **Network** | `TimeBucket.total` (and `by_status` for a blocked-only toggle), hour buckets over up to 400 d; **minute** buckets for the last 7 d (`rollup_minute`) for the 15-minute (or 1-minute) grain | exact |
| **Device** | `hour_top kind=clients` rows for that client key per hour | exact while the device is in the hour's top 100; else 0 shown as "below top list" (hatched) |
| **Name** | `hour_top kind=domains` (and `blocked`) rows for that name per hour | same caveat |

**Decision — no new per-device or per-name hourly storage.** The top lists cover what matters on a home
network (the Pi's hourly top 100 covers > 99 % of its queries today); the hatched cell is honest about
the rest. If the owner later wants exact per-device grids, that is a new rollup kind and a new ADR.

**Minute grain for the network** (the ADR-123 promise): 7 d × 1,440 minutes = 10,080 values, read in
one range query (`rollup_minute` is `start`-keyed; `shipped_minute_start` indexes the pods' rows). The
benchmark it was waiting for: on the VM, the 7-day minute read + aggregation must finish in < 150 ms
and the response stay < 200 KB (send `u32` arrays, not objects). Default grain: 15 minutes
(7 × 96 cells); 1 minute on request.

Weekday mode folds the days of the window onto Mon..Sun (sum or mean per cell; default **mean**, so a
4-week window reads as a typical week). Local time comes from the browser; the API returns UTC
starts, never local hours (nodes in different zones are the owner's eventual case).

## 4. API (decision)
`GET /api/v1/stats/heatmap?from&to&grain=hour|15m|minute&kind=network|client|name&key=&measure=queries|blocked&scope`
```json
{ "from": "...", "to": "...", "grain": "15m", "kind": "client", "key": "192.168.2.14",
  "starts": [1760572800, ...], "values": [0, 12, 1402, ...], "covered": [true, true, false, ...],
  "precision": "topList", "missingNodes": [] }
```
`starts`/`values` are parallel arrays, one per slot of the window (the client lays out the grid).
`covered[i]` is false where the key wasn't in that hour's top list (omit the array for `network`).
Limits: hour grain ≤ 400 d, 15m ≤ 30 d, minute ≤ 7 d → `422 heatmap_window` otherwise. Federated
`Read::Heatmap` summing per slot. Privacy: `kind=name` refused with `privacy_level` at ≥ 1 (hashes
only), `kind=client` at ≥ 2. MCP `activity_heatmap(kind, key, window, grain)` returning the same arrays
(they compress well; cap at 10,080 values).

## 5. UI (decision)
- New page **Heatmap** in the Monitor section (`#/heatmap`), icon `heatmap`, between Traffic map and
  Query log. Controls: kind (network / device / name — device and name pickers reuse `ClientChip` and
  the query-log name input), window (24 h, 7 d, 30 d, 90 d), grain, measure (queries / blocked),
  weekday fold toggle.
- Canvas grid (`ui/src/lib/heatmap.ts`, like `treemap.ts`: pure layout + a draw function; test the
  layout). Sequential colour scale from a single hue token (`--hm-ink`, blue for queries, red for
  blocked) with a square-root ramp (as the treemap uses) so quiet cells stay visible; hatched for
  uncovered; the empty cell is the page background. Light and dark tokens in `app.css`.
- Hover/focus: tooltip "Thu 16 Oct 15:00–15:15 · 1,402 queries"; arrow keys move the focus cell;
  click a cell → Query log for that slot and key (where the log still has it; else disabled with the
  retention tooltip). Column and row **marginals** (small bars) on the right and bottom.
- Deep links from elsewhere: Clients page device row → `#/heatmap?kind=client&key=…`; Traffic map tile
  → `#/heatmap?kind=name&key=…`; Dashboard "Queries" chart title → network heatmap.
- Change markers (T14.7) drawn as thin vertical ticks in the column header when present.
- Table view: the grid as a table (rows days, columns hours).
- Phone: rows scroll, columns fit 24 (hour grain forced below 480 px).

## 6. Grafana
The network variant exists as Grafana's heatmap panel over `rate(telltale_queries_total[5m])`; add it
to the *Overview* row with the same 15-minute bucket. Device/name variants are not exported.

## 7. Acceptance criteria
1. Fixture: 7 d of minute buckets with a 4-hour burst on day 4 → the 15m network grid has exactly 16
   cells above 3× the median, all on day 4, 14:00–18:00 UTC; sums per day equal the bucket sums.
2. Device fixture where the key drops out of the top list for 2 hours → those cells `covered=false`;
   the UI hatches them and the tooltip says "below this hour's top list".
3. Weekday fold of a 28-day fixture: each cell is the mean of 4 values (assert one cell by hand).
4. Window limits → 422 with the hint; privacy refusals as in §4.
5. VM benchmark: 7-day minute read + aggregation < 150 ms, response < 200 KB (record numbers in the
   task report; this is the ADR-123 benchmark).
6. Playwright `obs_029 heatmap`: a cell click opens the pre-filtered Query log; keyboard navigation
   moves focus; table view toggles; both themes screenshot (demo network).
7. Docs: `running.md` *Heatmap*; site monitoring page; help topic `heatmap`; OpenAPI/MCP regenerated.

## 8. Open
- Default page for the Monitor section's first visit stays the Dashboard; should the heatmap get a
  small 7×24 thumbnail on the Advanced dashboard? Cheap; ask.

## 9. Decided at the start of the task (owner: accept all defaults, 2026-10-16)
Recorded in ADR-129: devices and names have hour slots only; 15-minute and minute slots reach 7
days (the minute rollups' retention); devices by address; `blocked` for the network and names; the
current hour from memory; privacy refusals as `422 privacy_level`; no dashboard thumbnail (§8); the
query log opens from the cell's start.
