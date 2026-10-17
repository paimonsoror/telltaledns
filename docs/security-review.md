# Security review (v1.0 gate, T10.7)

Reviewed 2026-10-17: sign-in (local users, sessions, tokens, OIDC, TOTP, display tokens), the cluster channel (mTLS, join, the registry, key sharing, elections, RPCs, blob serving, log shipping, simulations), and the parsers that read untrusted bytes (DNS wire and filter names, list archives, backups, the query log, saved state). Each finding below was checked against the code before it was fixed. Each fix has a regression test named after its requirement.

## Fixed

| ID | Rating | Area | What was wrong | Fix |
|---|---|---|---|---|
| C1 | High | Cluster | A member the registry didn't list (a resolver pod that left, then reconnected with its still-valid certificate) was taken at its word. It could be recorded as eligible, and so be sent the cluster key, and its epoch could fence the primary. | Unknown members come back as plain ephemeral members: no key, no epoch announcements, no votes (ADR-143). `clu_005_an_unknown_member_is_trusted_with_nothing` |
| C2 | High | Cluster | An RPC answer was matched to its call by ID only, from any stream. Any member could answer, or fail, a call made to another one (a vote request, a federated read). | Answers count only on the stream of the peer that was asked; IDs start at a random value. `clu_002_an_answer_counts_only_from_the_peer_asked` |
| C3 | Medium | Cluster | A vote request was answered for any candidate, including a pod or a witness. | Only candidates the registry lists as eligible are answered. (in the C1 test) |
| C4 | Medium | Cluster | Resolver pods received every user's password hash, TOTP secret, and token hash, though they serve no API. | Not served to ephemeral or unknown members; pods don't fetch it, and drop old copies. `clu_003_users_and_tokens_are_not_served_to_pods` |
| C5 | Medium | Cluster | Any member could ask a node to run a simulation, naming any local file as a list, turning on link-local downloads, and choosing its own limits. | Refused from ephemeral and unknown members; only list files this node already reads, its own link-local setting, its own window and limits. |
| C6 | Medium | Cluster | Shipped query-log segments: unfinished uploads weren't counted against retention, and the number of joins (each a new sender) wasn't limited. | Four unfinished segments per sender; out-of-retention hours dropped; only registry members ship; 30 joins a minute. `clu_007_shipping_is_bounded` |
| A1 | Medium | Sign-in | Any credential (an API token, an agent token, HTTP Basic) could change the account's password and two-factor sign-in, and create or revoke its tokens. | These need a signed-in session (owner's choice; ADR-142). `api_003_account_changes_need_a_signed_in_session` |
| A2 | Medium | Sign-in | The current password in a password change or TOTP disable was checked without the sign-in limits, so a stolen session could guess it quickly. | Checked like a sign-in: bounded concurrency, failures counted, lockout. (in the A1 test) |
| A3 | Medium/low | Sign-in | A password changed or an account disabled on the primary didn't end that user's sessions on replicas. | The import ends them and drops cached Basic results. `clu_003_a_password_change_ends_replica_sessions` |
| A4 | Low | Sign-in | An agent or display token was written in two steps. If the second failed, a half-made token stayed (its secret was never shown). | The token is deleted if the second write fails. |
| A6 | Info | Sign-in | The failed-sign-in table was trimmed only of entries older than 15 minutes, so a burst of distinct names or display codes grew it. | Single misses go first when it's over its bound, then everything that isn't locked. |
| P1 | Medium | Parsers | A query name with a label containing `.` (escaped `\.`) didn't match any list rule, so it got past blocking. | It's matched as a subdomain of the labels to its right. `flt_002_a_dotted_label_does_not_bypass_the_lists` |
| P2 | Medium | Parsers | A query-log segment (one a peer shipped, say) could make a search hold far more memory than the file's size. | Name sections keep only the names they count; a segment's dictionary is capped at 64 MiB. `nfr_007_a_crafted_dictionary_is_bounded` |
| P3 | Low/medium | Parsers | A damaged `anomaly.json` could crash the anomaly thread, or make it close every hour since a stale time. | State is repaired on load; at most 48 hours are caught up. `obs_014_damaged_state_is_repaired_on_load` |
| P4 | Low | Parsers | `telltale backup restore` used the directories recorded in the archive without checking them, and read path and manifest entries of any size. | Recorded directories must be plain absolute paths (otherwise name one with `--data-dir` / `--config-dir`); path entries up to 4 KiB, the manifest up to 16 MiB. `api_007_restore_trusts_only_plain_recorded_directories` |
| P5 | Low | Parsers | An imported zip's wanted entries could each unpack to the 512 MiB limit. | 512 MiB for all of them together. |
| P6 | Info | Parsers | A cache dump entry with an impossibly short question could underflow when served. | Skipped at load. |

## Not changed (accepted or deferred)

- **C7 (low):** manifests are accepted from any connected member, not only the primary. Every manifest is still verified against the cluster CA's signature and epoch, so a member can only replay one the primary signed. The `/cluster/v1/ca` proof is an HMAC of the caller's nonce under the bootstrap secret; it shows the secret is known, never reveals it.
- **Sign-in, info:** a token that's valid but not allowed gets 403, an invalid one 401, so an attacker can tell them apart. That's the documented problem+json contract. `open_display` doesn't check `disable_local_login`: a display code is a token an admin created, not a password sign-in. The MCP OAuth token's `typ` header isn't checked; issuer, audience, signature, expiry, and a known subject are.
- **Parsers, info:** a few counter additions on paths with bounded inputs aren't checked; `dotted()` (names in log text) doesn't escape; the regex rule check's rejection loop is quadratic in the number of rejected rules (lists are size-capped).
- **Fuzzing:** targets exist for the DNS wire format, list parsing, and the query-log segment reader. Still missing: the cluster frame decoder, the backup and import archive readers, and the cache dump loader. Tracked in T10.7's note in `spec/10`.

## Before rolling this out to a cluster

C1 stops trusting members the registry doesn't list. Check first (read-only) that each node's registry lists every node: `telltale cluster status` on the primary, or the Cluster page. A node missing from it would come back as an ephemeral member.
