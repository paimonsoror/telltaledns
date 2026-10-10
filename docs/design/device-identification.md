# Device identification: design notes (T13.3)

**Requirement:** OBS-025 (serves API-010's naming suggestions). **ADR:** ADR-117. **Task:** T13.3 in
`spec/10`. **Spec section:** `06` §7.4. **Owner request:** 2026-10-09, from the capability review.

Opinionated by design: *decision* means build it this way; amend ADR-117 if you can't. *Open* means
ask the owner. Read ADR-019/043 (deterministic anomaly engine) and ADR-080/081 (router and mDNS
names) first: this reuses their inputs and copies their determinism rules.

## 1. What it is
A new address on the network is a number. TelltaleDNS already sees three things that say what the
device is: its **MAC** (neighbor table, EDNS MAC, router leases), the **names it announces** (mDNS,
the router's DHCP client list), and **which registrable domains it talks to** (the anomaly engine's
learned set, the aggregator's per-client top domains). Identification scores those against a small
**shipped catalog of signatures** and says, with evidence, "looks like a Roku player (likely)" —
then suggests a name and, when a group asks for that class, a group. It never changes a decision.

## 2. Non-goals
- Machine learning, fingerprint databases from other projects (Fingerbank, nmap's, Wireshark's
  `manuf` — the last two are GPL; clean room, NFR-006), DHCP option fingerprinting (we run no DHCP
  server, ADR-091), TLS/SNI or traffic inspection (we see DNS only).
- Acting on the guess: no automatic group moves, no blocking. Suggestions go through the existing
  Add-to-group action and plans.
- A living, downloaded catalog. Signatures ship with releases (no network fetch), plus a local file
  for additions.

## 3. Data shipped (decision)
### 3.1 `presets/oui.bin` — MAC vendors
- Built by `presets/build-oui.py` from IEEE's public MA-L and MA-M CSV exports (the registry is
  public data; note the source URLs, download date, and that no third-party `manuf` file is used in
  the script header and in `docs/analysis.md`'s licensing notes).
- Format: a sorted table of `(prefix_bits: u8, prefix: u64, vendor_idx: u16)` with a vendor string
  table (deduplicated, UTF-8, ≤ 48 bytes each, "Inc."/"Ltd." normalized away) — binary search by
  longest prefix (MA-M 28-bit before MA-L 24-bit). Reproducible: same CSV → same bytes (sorted,
  no timestamps). Expect ~35k entries → roughly 250–350 KiB; embed with `include_bytes!` and report
  the compressed size in the PR against the 15 MiB image gate (OPS-001). If it pushes the image over,
  drop MA-M first, then zstd-compress and decompress at start (measure cold-start cost; T10.4 is
  already tight).
- `telltale_proto`-free: a tiny `oui` module in `crates/telltale/src/identify/oui.rs`.

### 3.2 `presets/devices.toml` — signatures
```toml
# TelltaleDNS device signatures (REQ: OBS-025). Clean room: written from our own observations and
# vendors' public documentation. Weights are relative within a signature.
[[device]]
id = "roku-player"
name = "Roku player"
class = "streaming"            # see classes below
vendors = ["Roku"]             # substring match on the OUI vendor, case-insensitive
hostname_patterns = ["Roku-*", "roku*"]   # glob on mDNS/DHCP names
domains = [                    # registrable domains (eTLD+1), weight
  { name = "roku.com", weight = 1.0 },
  { name = "rokutime.com", weight = 0.6 },
  { name = "ravm.tv", weight = 0.3 },
]
```
Classes (fixed enum, low-cardinality for metrics): `phone`, `tablet`, `laptop`, `desktop`, `tv`,
`streaming`, `speaker`, `console`, `camera`, `doorbell`, `plug`, `bulb`, `thermostat`, `hub`,
`vacuum`, `printer`, `nas`, `network`, `appliance`, `wearable`, `car`, `other`, `unknown`.
Ship **at least 40** signatures covering the common home devices: Apple (iPhone/iPad/Mac/Apple TV/
HomePod/Watch), Google (Pixel, Chromecast, Nest Hub/Cam/Thermostat), Amazon (Echo, Fire TV, Kindle,
Ring), Roku, Samsung (TV, phone), LG TV, Sony (Bravia, PlayStation), Microsoft (Xbox, Windows),
Nintendo Switch, Sonos, Philips Hue, TP-Link (Kasa, Tapo), Wyze, Ecobee, Tesla, HP/Brother/Canon/
Epson printers, Synology/QNAP, Ubiquiti, Eero, Roborock/iRobot, Peloton, Meta Quest, Steam Deck.
Domains come from what those devices are documented to contact (vendor docs for firewall allowlists
are a good public source) and from the owner's own query log; keep each list short (3–8 domains) and
weighted. The owner's network is the first validation set (§10).

`[identify] signatures_file = "/etc/telltale/devices.toml"` adds signatures in the same shape; an
`id` that collides with a shipped one **replaces** it (so a user can fix ours), and `enabled = false`
on a signature removes it.

## 4. Inputs per device (decision)
Collected by the identifier when it runs (§5), never on the query path:
- **Vendor:** the device's MAC from, in order, the client entry (`[[client]] mac`), the neighbor table
  (`telltale_policy::ClientTable`'s MAC view), EDNS MAC seen for the address (the aggregator records
  it on events when present), router leases (`devices.rs`). → `oui::lookup(mac)`.
- **Names:** router DHCP hostname, mDNS name (`devices.rs` leases), the user's own name if any (not
  used for scoring — it's the output we're suggesting — but shown).
- **Domains:** the aggregator's per-client top domains (`Aggregates`, this hour and the last; the 64
  most recent clients) reduced to registrable domains with the existing eTLD+1 logic from the anomaly
  engine; for devices the aggregator doesn't hold, one query-log top-K (`qlog` search, last 24 h,
  idle-priority pool, ≤ 8 such devices per pass, round-robin by staleness). The anomaly engine's
  learned set is fingerprints, not names — don't try to reverse it; use the top lists.
- Devices are keyed as the aggregator keys clients (address, or client ID), merged by MAC when the
  neighbor table shows the same MAC for several addresses (IPv4 + IPv6 of one device).

## 5. Scoring (decision)
```
domain_score   = Σ weight(d) for d in signature.domains ∩ device.domains  /  Σ weight(d) for d in signature.domains
vendor_score   = 1.0 if any vendors[] substring-matches the OUI vendor else 0.0 (0.0 when no MAC)
hostname_score = 1.0 if any hostname_patterns glob-matches a known name else 0.0
score          = 0.60 × domain_score + 0.25 × vendor_score + 0.15 × hostname_score
```
- Best signature wins; ties broken by `id` (fixed ordering). `likely` ≥ 0.60, `possibly` ≥ 0.35,
  else `unknown` (report `vendor` alone when known; `class = "unknown"`).
- A signature with `vendors` set and a **known, non-matching** vendor is penalized: `score × 0.5`
  (a Samsung MAC talking to roku.com is a Samsung TV with a Roku app, not a Roku). Signatures may set
  `vendor_required = true` to need the vendor match at all.
- **Deterministic:** f32 arithmetic, fixed iteration order (signatures by `id`, domains by name),
  inputs sorted; the same inputs produce byte-identical output on every node and architecture (golden
  test on x86-64 and arm64 in CI, like the anomaly fixture).
- **Evidence** always: matched domains with their weights, the vendor string and the MAC prefix, the
  matched name, and the runner-up when its score is within 0.1 ("could also be …").

## 6. Running it (decision)
- `crates/telltale/src/identify.rs` (`Identifier`): a background task every 10 minutes (and 60 s after
  start) over devices seen in the last 24 h, at most `max_clients` (1,024; the most recently seen).
  Each pass: gather inputs (§4), score, store `Identity { device, product_id, name, class, level,
  score, evidence, runner_up, computed_at, source: "inferred" | "override" }` in an `ArcSwap<HashMap>`
  read by the API; persist to `<data_dir>/devices.json` hourly and on shutdown (so a restart doesn't
  blank the Clients page). Per-device state ≤ 1 KiB (test).
- Off at `[telemetry.qlog] privacy_level ≥ 1` (names hashed) — the API says
  `identity: { available: false, reason: "privacy_level" }`.
- **Overrides:** `[[client]] kind = "camera"` (any class, or `"unknown"` to say "stop guessing") wins
  entirely; shown as `source = "override"` with no inference evidence. Managed like other client
  fields (the device form in the UI, `PUT /clients/{name}`, `plan_rename_client`/`plan_assign_client`
  gain `kind`). Replicates with the configuration.
- **Group suggestion:** `[[group]] device_classes = ["camera", "doorbell", "plug", "bulb", "hub"]`.
  An identity whose class is in exactly one group's list and whose device isn't already in that group
  gets `suggestedGroup`. Two groups claiming the same class is a validation error.
- **Cluster:** each node identifies the devices it sees; `GET /clients` is federated already — merge
  identities per device by highest `score` (ties: the node with the MAC). Overrides are configuration
  and therefore identical everywhere.

## 7. Surfaces
- **API:** `identity` on each row of `GET /api/v1/clients` (`product`, `class`, `level`, `score`,
  `vendor`, `suggestedGroup`, `source`); `GET /api/v1/clients/{id}/identity` with the full evidence
  and runner-up; `kind` on `PUT /clients/{name}`. OpenAPI regenerated; UI types regenerated.
- **Clients page:** a class icon in the first column (the visual refresh already reserved it); a
  sentence under the name: "Looks like a **Roku player** (likely) · Roku Inc · talks to roku.com,
  rokutime.com"; an evidence drawer; **Add to IOT?** when `suggestedGroup` is set (the existing
  Add-to-group action, pre-selected); "Not a Roku? Set what it is" → the `kind` field in the device
  form. The naming form pre-fills `product` when no router/mDNS name exists ("Roku player" → the user
  adds "living room").
- **Dashboard (Advanced):** a small "Devices by type" card (counts per class; table view).
- **Alerts/anomalies:** the `new_device` alert text and anomaly finding summaries quote the identity
  when `likely`/`possibly`: "New device 192.168.2.77 (looks like a Ring doorbell) on IOT".
- **MCP:** `identify_device { client }` (read; `analytics:read`); `get_client_profile` gains
  `identity`; `plan_assign_client` gains `kind`.
- **Metrics:** `telltale_devices_by_class{class}` gauge (≤ 23 series), `telltale_identify_runs_total`,
  `telltale_identify_duration_seconds`.
- **Docs/site:** `running.md` *What is this device?* (how it guesses, how to correct it, the catalog
  file, privacy), help topic `identify`, configuration reference, a line on the site's groups page.

## 8. Config
```toml
[identify]                    # shared
enabled = true
max_clients = 1024
signatures_file = ""          # extra or replacement signatures, same shape as presets/devices.toml

[[client]]
name = "porch-cam"
ip = "192.168.2.77"
kind = "camera"               # override: any class, or "unknown"

[[group]]
name = "iot"
device_classes = ["camera", "doorbell", "plug", "bulb", "hub", "thermostat", "vacuum"]
```

## 9. Performance and footprint
- Query path and telemetry thread: untouched (inputs are read from existing aggregates).
- A pass over 1,024 devices with aggregator inputs: target < 50 ms release build (scoring 40
  signatures × a few domains is trivial; the cost is gathering). Query-log fallback: ≤ 8 devices per
  pass at idle priority.
- Memory: ≤ 1 KiB per device × 1,024 + the catalog (~50 KiB parsed) + OUI (≈300 KiB; measure).
- Binary/image: report the delta; OPS-001's 15 MiB is the gate.

## 10. Tests (map to the AC in `spec/10`)
- Golden fixture (`crates/telltale/tests/identify.rs` + `tests/fixtures/identify/*.json`): eight
  devices → expected product/level; byte-identical output on x86-64 and arm64 in CI; ablations (no
  MAC, no domains); vendor penalty; tie order.
- Overrides win; `device_classes` suggestion rules; validation errors.
- OUI: builder reproducibility; 10 known prefixes incl. MA-M; size reported.
- Per-device state size; pass duration; privacy level.
- Federation merge by highest score.
- Playwright: a device that queries `roku.com` names in the test shows the sentence and the naming
  suggestion.
- **Owner validation (not CI):** run on the homelab and the Pi; list every device with its guess;
  fix signatures from the misses before merging. Record the hit rate in the task.

## 11. Implementation order
1. `presets/build-oui.py` + `oui.bin` + `oui.rs` lookup + tests; measure size.
2. `presets/devices.toml` (start with 20, grow to 40+ from the owner's network) + parser + validation.
3. Scoring + golden fixture (pure functions, no I/O).
4. `Identifier` task: inputs, cache, persistence, privacy gate; `[identify]`, `kind`,
   `device_classes`.
5. API + OpenAPI + federation merge; MCP tool and profile field.
6. Clients page, naming form, dashboard card, alert/anomaly text; help; docs; site. Tick the task.

## 12. Decisions taken with the owner (2026-10-09)
- **Ship the product catalog in v1** (≥ 40 signatures), so the owner's network can test it at once;
  the misses found there feed signature fixes before the task is ticked (§10, owner validation).
- `likely` identities **pre-fill the naming form only**; they don't become the device's name on their
  own (a guess shouldn't label the query log). Revisit after the first weeks of real hit rates.
