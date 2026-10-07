# Pass 07: configuration, deployment, release

**Output:** `docs/review/v0.2.0/07-config-deploy.md` (+ `patches/07-*`)

## Scope
Getting TelltaleDNS running and keeping it running: the configuration schema and its
validation, startup and reload, the data directory, backups, imports from Pi-hole and
Technitium, router integrations, the container image, the Helm chart, Compose, the native
installer and self-update, and the release pipeline.

- `crates/telltale-config/` (schema, validation, env overrides, shared vs node-local)
- `crates/telltale/src/`: `main.rs`, `server.rs` (start, reload, shutdown), `datadir.rs`,
  `backup/`, `archive.rs`, `import.rs`, `pihole/`, `technitium/`, `routers.rs`,
  `devices.rs`, `mdns.rs`, `selfupdate.rs`, `updates/`
- `deploy/image/` (Dockerfile, size and smoke tests), `deploy/helm/telltale/`,
  `deploy/compose/`, `deploy/systemd/install.sh`, `deploy/release/` (preflight, bump,
  verify), `.github/workflows/`

## Read first
1. `spec/08-deployment-config-security.md`, `docs/configuration.md`, `docs/releasing.md`;
   ADR-015, ADR-035, ADR-038, ADR-046, ADR-061 to ADR-063, ADR-068, ADR-091, ADR-097.
2. `crates/telltale-config/src/schema.rs` + `validate.rs` → `crates/telltale/src/server.rs`
   (`load`, `reload`).

## Look for
- **Configuration:** does validation catch every mistake that would otherwise fail at
  runtime? Defaults that surprise (security-relevant ones especially: allowed networks,
  rate limits, the API listen address, TLS verification). Reload atomicity and what a
  failed reload leaves running.
- **Upgrades and data:** data-directory locking (ADR-068), on-disk format versions, backup
  and restore round trips, what a downgrade does.
- **Installer and self-update:** signature verification before anything is replaced,
  rollback, permissions and systemd sandboxing, uninstall restoring the system resolver.
- **Helm chart:** security contexts, resource limits vs the measured footprint,
  `existingClaim` (added in 0.2.0), upgrade paths between chart versions, defaults for
  `externalTrafficPolicy`, NetworkPolicy.
- **CI and release:** reproducibility, supply chain (`cargo deny`, pinned actions,
  third-party actions' permissions), what the release `verify` job does and doesn't catch.

## Threat surface
Installer run as root from a downloaded script; self-update replacing a running binary;
secrets in values files, environment, or logs; workflow permissions (`contents: write`,
`actions: write` in `release.yml`).

## Useful
```sh
cargo test -p telltale-config
helm lint deploy/helm/telltale; helm template t deploy/helm/telltale | less
bash deploy/systemd/e2e.sh        # read the header first: it installs into a throwaway environment
sh deploy/release/verify.sh 0.2.0
```
