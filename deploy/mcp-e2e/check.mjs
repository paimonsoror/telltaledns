// REQ: AGT-006 — T6.6 acceptance with the official MCP TypeScript SDK client:
//   1. Streamable HTTP: initialize, list tools (the committed catalog), call get_overview;
//   2. the "why is the TV slow?" story (spec/13 §3.3) as a scripted agent: get_client_profile
//      finds the device and its slow queries, upstream_health shows the upstreams, and
//      explain_decision answers for a blocked name;
//   3. stdio: `telltale mcp --stdio` relays the same tools;
//   4. a tool that needs a scope the token lacks reports an error, not data.
// Usage: node check.mjs <api url> <telltale binary> <catalog json>
// Env: AGENT_TOKEN (analytics, config, query log), NARROW_TOKEN (analytics only).
import { readFileSync } from 'node:fs';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const [api, binary, catalogPath] = process.argv.slice(2);
const fail = (msg) => {
  console.log(`FAIL: ${msg}`);
  if (process.env.GITHUB_ACTIONS) console.log(`::error title=mcp-e2e::FAIL: ${msg}`);
  process.exit(1);
};
const data = (r) => r.structuredContent ?? JSON.parse(r.content?.[0]?.text ?? 'null');

async function connect(transport) {
  const c = new Client({ name: 'telltale-mcp-e2e', version: '1.0.0' });
  await c.connect(transport);
  return c;
}
const http = (token) =>
  new StreamableHTTPClientTransport(new URL(`${api}/mcp`), {
    requestInit: { headers: { Authorization: `Bearer ${token}` } },
  });

// 1. HTTP
const c = await connect(http(process.env.AGENT_TOKEN));
const info = c.getServerVersion();
if (info?.name !== 'telltaledns') fail(`server name ${JSON.stringify(info)}`);
const { tools } = await c.listTools();
const committed = JSON.parse(readFileSync(catalogPath, 'utf8')).map((t) => t.name);
const listed = tools.map((t) => t.name);
if (JSON.stringify(listed) !== JSON.stringify(committed)) fail(`tools ${listed} != committed ${committed}`);
for (const t of tools) {
  if (!t.description.startsWith('Read-only.')) fail(`${t.name} doesn't state its side effects`);
  if (t.annotations?.readOnlyHint !== true) fail(`${t.name} isn't marked read-only`);
}
const overview = await c.callTool({ name: 'get_overview', arguments: { window: '-1h' } });
if (overview.isError) fail(`get_overview: ${JSON.stringify(overview)}`);
const queries = data(overview).overview?.queries;
if (!(queries > 0)) fail(`get_overview shows ${queries} queries`);
console.log(`ok: HTTP, ${tools.length} tools, ${queries} queries in the last hour`);

// 2. "Why is the living-room TV slow?"
const profile = await c.callTool({ name: 'get_client_profile', arguments: { client: 'living-room-tv', window: '-1h' } });
const p = data(profile);
if (profile.isError || p.device?.name !== 'living-room-tv') fail(`get_client_profile: ${JSON.stringify(p).slice(0, 300)}`);
if (!(p.recentQueries?.items?.length > 0)) fail(`the profile has no recent queries: ${JSON.stringify(p.recentQueries).slice(0, 300)} device ${JSON.stringify(p.device).slice(0, 300)}`);
const health = await c.callTool({ name: 'upstream_health', arguments: {} });
if (health.isError || !Array.isArray(data(health).upstreams?.items)) fail(`upstream_health: ${JSON.stringify(data(health)).slice(0, 300)}`);
const why = await c.callTool({ name: 'explain_decision', arguments: { name: 'ads.mcp.test', client: '127.0.0.1' } });
if (why.isError || data(why).explanation?.outcome !== 'blocked') fail(`explain_decision: ${JSON.stringify(data(why)).slice(0, 300)}`);
console.log(`ok: TV story (device ${p.device.name}, ${p.recentQueries.items.length} recent queries, ${data(health).upstreams.items.length} upstreams, ads blocked)`);
await c.close();

// 3. stdio
const s = await connect(
  new StdioClientTransport({
    command: binary,
    args: ['mcp', '--stdio', '--url', api],
    env: { ...process.env, TELLTALE_TOKEN: process.env.AGENT_TOKEN },
  }),
);
const viaStdio = await s.callTool({ name: 'get_overview', arguments: {} });
if (viaStdio.isError || !(data(viaStdio).overview?.queries > 0)) fail(`stdio get_overview: ${JSON.stringify(viaStdio).slice(0, 300)}`);
console.log(`ok: stdio (${(await s.listTools()).tools.length} tools)`);
await s.close();

// 4. scopes apply inside tools
const n = await connect(http(process.env.NARROW_TOKEN));
const denied = await n.callTool({ name: 'search_queries', arguments: {} });
if (!denied.isError) fail('search_queries worked without querylog:read');
console.log('ok: scopes apply to tools');
await n.close();
console.log('PASS');
