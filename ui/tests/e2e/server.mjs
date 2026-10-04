// Starts a real TelltaleDNS for the Playwright suite (REQ: API-005, T3.9 AC): a fresh data
// directory, DNS on 127.0.0.1:15354, the API and UI on 127.0.0.1:18054, an inline blocklist,
// and a local record, so tests don't depend on the internet.
import { spawn } from 'node:child_process';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
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

[[list]]
name = "e2e-block"
rules = ["||ads.e2e.test^"]

[[record]]
name = "nas.e2e.test"
type = "A"
value = "192.168.1.10"

[telemetry.metrics]
listen = "127.0.0.1:19154"

[telemetry.qlog]
flush_interval_secs = 1

[api]
listen = "127.0.0.1:18054"
`,
);

const bin = process.env.TELLTALE_BIN ?? resolve(here, '../../../target/debug/telltale');
const child = spawn(bin, ['run', '-c', cfg], { stdio: 'inherit' });
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => child.kill('SIGTERM'));
child.on('exit', (code) => process.exit(code ?? 0));
