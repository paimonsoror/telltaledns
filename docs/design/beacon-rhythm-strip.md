# Rhythm strip for periodic traffic: design notes (T14.5)

**Requirement:** OBS-031 (new). **ADR:** ADR-131 (new, Proposed; amends the beaconing row of `06` §7
to match). **Spec section:** `06` §7.1 (anomaly engine) gains a *Rhythm* paragraph.
**Owner request:** 2026-10-16 (the 2.5-second NTP loop was invisible).

## 1. What it is, in one paragraph
The anomaly engine already measures inter-arrival regularity per (device, registrable domain) and
reports a *beacon* when it is new; nobody gets to see the measurement. The rhythm strip renders it:
per device, one row per tracked domain, the x axis is the period (log scale, 1 s … 2 h), brightness
is how much of that domain's traffic arrives at that period. A time-sync loop is a razor line at
2.5 s; a phone-home at 300 s ± 2 s is another; a browser is a smear. Deterministic, explainable, and
the kind of picture the Anomalies page has been missing.

## 2. Non-goals
- Changing what the engine *alerts* on. `BEACON_HOURS`, the 30–3600 s band, the 5 % jitter rule and the
  golden fixtures stay as they are (determinism, ADR-019). The strip shows more than the alert judges.
- Spectral analysis (FFT). Log-binned inter-arrival histograms are what the spec promised and what a
  Pi can afford.

## 3. Data (decision)
`Tracked` (`crates/telltale-telemetry/src/anomaly.rs`) keeps `intervals: [u16; 16]` — the last 16 gaps
in seconds. Sixteen gaps is enough to decide "regular", too thin to draw, and it saturates at 65,535 s
and floors at 1 s (a 2.5 s gap is 2 or 3). Changes, all on the telemetry thread:

1. Add to `Tracked` a **log-spaced inter-arrival histogram** `rhythm: [u16; 24]` over bins
   `[1, 1.5, 2.2, 3.3, 5, 7.5, 11, 17, 25, 38, 56, 84, 126, 190, 285, 427, 640, 960, 1440, 2160, 3240,
   4860, 7290, ∞)` seconds (ratio 1.5), counting **this hour's** gaps measured in **milliseconds**
   (`ts_us` is there; keep `last_s` and add `last_ms`). Saturating `u16`.
2. Keep a **decayed copy** `rhythm_long: [u16; 24]` folded at the hour close (`close_pairs`):
   `long = long/2 + hour` (integer, saturating) — a cheap "last ~2 hours weighted" view that gives the
   strip memory without storing history.
3. Export per device: for each tracked pair `domain, rhythm (hour), rhythm_long, regular_hours,
   known_periodic, since_s, volume.mean`, plus the dominant bin and its share. Memory: 2 × 48 B ×
   `TRACKED` (16) per device ≈ 1.5 KB; with `max_clients` 1,024 ≈ 1.5 MB worst case. Record the
   measured RSS delta in the bench report; if it exceeds 2 MiB at 1,024 clients, halve the bins to
   `u8` with saturation — don't drop the feature.
4. The existing 16-gap buffer stays (the alert uses it); don't widen it.

The `Finding` for `Beacon` gains a `rhythm` snapshot in its evidence (the 24 bins at report time) so
the Anomalies page can draw the strip for a historical finding too.

## 4. API (decision)
`GET /api/v1/clients/{id}/rhythm` → `{ "client": "...", "bins_s": [1, 1.5, ...], "domains": [ { "domain": "pool.ntp.org", "hour": [0,0,0,1402,...], "recent": [...], "dominantBin": 3, "dominantSharePct": 97.1, "regularHours": 6, "knownPeriodic": true, "sinceTime": "...", "meanPerHour": 1380 } ] }`
Federated (`Read::ClientRhythm`): each node knows the device as it saw it; merge by domain, summing
bins (devices roam between nodes). Privacy: at ≥ 1 domains are eTLD+1 hashes → return `domains` with
`domain: null` and keep the bins (the rhythm is the point); at ≥ 2, 404 `privacy_level`.
MCP: `get_client_profile` gains `rhythm` (the dominant period and share per domain, not the bins);
`find_anomalies` beacon findings carry `rhythm`.
Metric: none (per-pair series are cardinality).

## 5. UI (decision)
- Clients page → device drawer gets a **Rhythm** section; Anomalies page → a beacon finding shows the
  strip for its pair inline.
- SVG (`ui/src/lib/components/RhythmStrip.svelte`): rows = tracked domains (sorted by dominant share
  desc, max 16), columns = 24 bins; each cell a rect whose opacity is the bin's share of the row (not
  the absolute count — a chatty and a quiet domain should both show their shape), on `--rh-ink`; the
  dominant bin outlined when share ≥ 50 %; a small text "every 2.5 s" at the row's right. A toggle
  *this hour / recent* switches arrays. Period labels under the strip: `1 s · 10 s · 1 min · 10 min · 1 h`.
- A `knownPeriodic` row gets a muted badge "usual" (it was periodic during learning); a row with
  `regularHours ≥ BEACON_HOURS` and not known gets "new rhythm" in `--s-warn`.
- Click a row → Query log for that device and name (last hour).
- Table view: the bins as numbers. Phone: the strip scrolls horizontally with sticky domain labels.

## 6. Grafana
None (no per-pair metrics). Mention in `docs/monitoring` that beacon findings fire the existing
anomaly alert rule.

## 7. Acceptance criteria
1. Fixture: device A queries `pool.ntp.org` every 2.5 s ± 0.1 s for an hour and `example.com` at
   random gaps → `pool.ntp.org` has ≥ 95 % of its hour counts in bin 3 (2.2–3.3 s), dominant share
   ≥ 95; `example.com` has no bin above 30 %. The existing golden anomaly fixtures still pass
   unchanged (the alert path is untouched).
2. Hour fold: after `close_pairs`, `recent` equals `floor(prev/2) + hour` per bin; saturation at 65,535
   holds.
3. Privacy level 1: `domain: null`, bins present; level 2: 404 with hint.
4. Federation: two nodes seeing the same device sum bins; a down node → `missingNodes`.
5. Bench: aggregator per-event cost unchanged within noise (one bin index per query to a tracked pair
   only); RSS at 1,024 clients × 16 pairs reported.
6. Playwright `obs_031 rhythm strip`: the drawer shows the strip; the dominant row shows "every 2.5 s";
   the row click opens the Query log; table view; both themes.
7. Docs: `running.md` *Clients* and *Anomalies*; site page; help topic `rhythm`; OpenAPI/MCP.

## 8. Open
- Should sub-30 s regular traffic (the NTP loop) become a *finding* kind of its own ("chatty
  periodic", informational, never degraded)? It would help the owner find the loop without opening a
  drawer. Default: no new finding in this task; propose it in the report.

## 9. Decided at the start of the task (owner: accept all defaults, 2026-10-16)
Recorded in ADR-131:
- **Privacy:** the anomaly engine doesn't run at query-log privacy level 1 and above (review 04-04:
  findings name devices and domains, and hashed names would read as random), so there is no level-1
  "`domain: null`" mode to serve. The read answers `422 privacy_level` from level 1, with a hint.
- **The beacon's strip lives beside the findings** (`Engine::beacon_rhythms`, as many as findings),
  not in `Finding`, so the golden fixture stays byte-identical. The snapshot is the decayed copy
  just after the hour's fold (the hour that completed the beacon included).
- **`recent` in the API** is the stored decayed copy plus this hour (so it moves during the hour);
  the stored copy is `floor(previous / 2) + hour` at each close, as §3.
- **Memory:** 1,664 B more per device (two `[u16; 24]` and a `u64` per tracked pair), 1.63 MiB at
  1,024 devices × 16 pairs: under the 2 MiB line, so the bins stay `u16`. The per-device bound in
  `obs_013_per_client_state_is_bounded` becomes T3.13's 4 KiB plus `RHYTHM_BYTES`.
- **Bins:** 24 bins with bin 0 for gaps under 1 s (bursts, such as A and AAAA together), so bin 3
  is 2.2–3.3 s as §7 says; `binsS` carries the 23 upper bounds (like `boundsUs`).
- **Words:** `period` ("every 2.5 s") from the 16-gap mean when it agrees with the dominant bin,
  else the bin's geometric middle; only when one bin holds at least half.
- **UI:** the Clients page had no device drawer: a **Rhythm** button on *Seen this hour* rows opens
  one. Cells are shaded by their share of the row's busiest bin (the shape), the share is in the
  tooltip; the ink reuses `--hm-ink` rather than a new token.
- MCP `get_client_profile` gains `rhythm` (`?bins=false`: period and share, no bins);
  `find_anomalies` beacons carry `rhythm`. Agents read it with `analytics:read`.
- §8 (a "chatty periodic" finding for sub-30 s loops): not in this task; proposed in the report.
