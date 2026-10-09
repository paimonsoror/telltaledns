// Starts a real TelltaleDNS for the Playwright suite (REQ: API-005, T3.9 AC): a fresh data
// directory, DNS on 127.0.0.1:15354, the API and UI on 127.0.0.1:18054, an inline blocklist,
// and a local record, so tests don't depend on the internet.
import { spawn } from 'node:child_process';
import { createSocket } from 'node:dgram';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '../../.e2e');
rmSync(root, { recursive: true, force: true });
mkdirSync(resolve(root, 'data'), { recursive: true });

const cfg = resolve(root, 'telltale.toml');
writeFileSync(
  cfg,
  `[node]
data_dir = "${resolve(root, 'data')}"
name = "home-dns"

[[listen]]
proto = "udp"
addr = "127.0.0.1:15354"

# Nothing listens here: tests use only blocked and local names.
[[upstream]]
name = "nowhere"
url = "udp://127.0.0.1:9"

[[upstream_group]]
name = "default"
members = ["nowhere"]

# T6.13 — a stub (below) that answers every name with 192.0.2.7, so there's something to cache.
[[upstream]]
name = "router"
url = "udp://127.0.0.1:15399"

[[upstream_group]]
name = "router"
members = ["router"]

[[route]]
match_suffix = ["cache.e2e.test"]
upstream_group = "router"
dnssec_nta = true

# ADR-050 — every e2e query comes from 127.0.0.1: a network group puts them in "lab".
[[group]]
name = "lab"
networks = ["127.0.0.0/8"]
color = "#22c55e"

# T8.6 — a group no test device is in, carrying the answer settings the Groups page shows.
[[group]]
name = "ipv6only"
networks = ["10.99.0.0/16"]
dns64 = true
rebinding_protection = true
block_answer_ips = ["203.0.113.0/24"]
[[group.rewrite]]
domain = "tv.e2e.test"
answer = "192.168.1.30"

# T8.6 — a zone for the Names page (only ipv6only sees it, so DNS tests aren't affected).
[[zone]]
name = "zone.e2e.test"
groups = ["ipv6only"]
[[zone.record]]
name = "www.zone.e2e.test"
type = "A"
value = "192.168.1.40"

[[list]]
name = "e2e-block"
rules = ["||ads.e2e.test^"]

# T11.5 — a list in shadow mode (the stub upstream answers names under cache.e2e.test).
[[list]]
name = "e2e-shadow"
rules = ["||shadow.cache.e2e.test^"]
mode = "shadow"

[[record]]
name = "nas.e2e.test"
type = "A"
value = "192.168.1.10"

[telemetry.metrics]
listen = "127.0.0.1:19154"

# T8.6 — mDNS naming on a test port (the test sends an announcement there).
[clients]
mdns = true
mdns_port = 15353

[telemetry.qlog]
flush_interval_secs = 1

[api]
listen = "127.0.0.1:18054"

# REQ: AGT-007 — agents' plans wait for an operator (the Agent changes test).
[agents]
require_approval = true

# T9.6 — rules made in the Alerts test are checked every 5 s.
[alerts]
interval_secs = 5

# T11.3 — the listener probe runs every 5 s, so the System tab shows it soon.
[probe]
interval_secs = 5
`,
);

// OIDC end-to-end (T3.6): OIDC_E2E=keycloak,authentik adds those providers (see ../oidc/),
// reachable at E2E_IDP_HOST (default 127.0.0.1).
const oidc = (process.env.OIDC_E2E ?? '').split(',').filter(Boolean);
if (oidc.length) {
  const host = process.env.E2E_IDP_HOST ?? '127.0.0.1';
  const issuers = {
    keycloak: [`http://${host}:8080/realms/telltale`, 'Keycloak'],
    authentik: [`http://${host}:9000/application/o/telltale/`, 'Authentik'],
  };
  let extra = '\n[auth.oidc]\npublic_url = "http://127.0.0.1:18054"\n';
  for (const id of oidc) {
    const [issuer, name] = issuers[id];
    extra += `
[[auth.oidc.provider]]
id = "${id}"
name = "${name}"
issuer = "${issuer}"
client_id = "telltale"
client_secret = "telltale-secret"
scopes = ["openid", "profile", "email"]
[[auth.oidc.provider.role]]
group = "dns-admins"
role = "admin"
[[auth.oidc.provider.role]]
group = "family"
role = "viewer"
`;
  }
  writeFileSync(cfg, readFileSync(cfg, 'utf8') + extra);
}

// The stub upstream: NOERROR, one A record (TTL 300) for whatever was asked.
const stub = createSocket('udp4');
stub.on('message', (q, from) => {
  if (q.length < 17) return;
  let end = 12;
  while (end < q.length && q[end] !== 0) end += q[end] + 1;
  end += 5; // the root label, QTYPE, QCLASS
  if (end > q.length) return;
  const head = Buffer.from([q[0], q[1], 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
  const answer = Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4, 192, 0, 2, 7]);
  stub.send(Buffer.concat([head, q.subarray(12, end), answer]), from.port, from.address);
});
stub.bind(15399, '127.0.0.1');

const bin = process.env.TELLTALE_BIN ?? resolve(here, '../../../target/debug/telltale');
const child = spawn(bin, ['run', '-c', cfg], { stdio: 'inherit' });
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => child.kill('SIGTERM'));
child.on('exit', (code) => process.exit(code ?? 0));
