// REQ: AGT-006 — T6.6 acceptance with the official MCP TypeScript SDK client:
//   1. Streamable HTTP: initialize, list tools (the committed catalog), call get_overview;
//   2. the "why is the TV slow?" story (spec/13 §3.3) as a scripted agent: get_client_profile
//      finds the device and its slow queries, upstream_health shows the upstreams, and
//      explain_decision answers for a blocked name;
//   3. stdio: `telltale mcp --stdio` relays the same tools;
//   4. a tool that needs a scope the token lacks reports an error, not data;
//   4b. AGT-010 (T7.2): resources (cluster status, the configuration, the daily summary) read
//      through the REST routes, and prompts fill in their arguments;
//   5. AGT-007 (T7.1): with [agents] require_approval, a writer agent plans a block, can't
//      apply it until an admin approves, then applies it (the name is blocked); a plan made
//      before another change comes back stale; the audit log names the agent, its owner, and
//      the reason.
//   6. OBS-024 (T13.1): a plan without `simulate` has no simulation, one with `simulate: "24h"`
//      has it (and a writer without querylog:read is refused), simulate_change answers without
//      a plan, and with the operator's `plans_by_default` on every plan has it; no agent can
//      turn that on.
// Usage: node check.mjs <api url> <telltale binary> <catalog json>
// Env: AGENT_TOKEN (analytics, config, query log), NARROW_TOKEN (analytics only),
//      WRITER_TOKEN (config:write:rules, analytics), SIM_TOKEN (the writer's scopes plus
//      querylog:read), ADMIN_PASSWORD (user `admin`).
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
  // AGT-009: the description and the annotations agree on side effects.
  if (t.description.startsWith('Read-only.') !== (t.annotations?.readOnlyHint === true))
    fail(`${t.name}: description and readOnlyHint disagree`);
  if (t.name.startsWith('plan_') && !t.description.startsWith('Plans a change')) fail(`${t.name} doesn't say it only plans`);
}
if (tools.find((t) => t.name === 'apply_plan')?.annotations?.destructiveHint !== true) fail('apply_plan isn\'t marked destructive');
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

// 2b. AGT-012 (T8.4): vqlog — one query for top-K, a cost-only dry run, and a mistake with a hint.
const top = data(await c.callTool({ name: 'vqlog', arguments: { query: 'from -1h | top 5 name' } }));
const tv = top.result?.rows?.find((r) => r[0] === 'tv-portal.mcp.test');
if (!tv || !(tv[1] >= 20) || top.result.columns.join() !== 'name,count') fail(`vqlog top: ${JSON.stringify(top).slice(0, 400)}`);
const byClient = data(await c.callTool({ name: 'vqlog', arguments: { query: 'from -1h | where name = tv-portal.mcp.test | by client | stats count, p95(latency)' } }));
if (!(byClient.result?.rows?.[0]?.[2] >= 20) || byClient.result.columns[3] !== 'p95(latency)') fail(`vqlog by client: ${JSON.stringify(byClient).slice(0, 400)}`);
const est = data(await c.callTool({ name: 'vqlog', arguments: { query: 'from -1h | top 5 name', estimateOnly: true } }));
if (!(est.result?.cost?.estimatedRows >= 20) || est.result.cost.rowsScanned !== 0 || est.result.rows.length !== 0) fail(`vqlog estimate: ${JSON.stringify(est).slice(0, 400)}`);
const typo = await c.callTool({ name: 'vqlog', arguments: { query: 'from -1h | top 5 colour' } });
if (!typo.isError || !JSON.stringify(typo).includes('Keys:')) fail(`vqlog error: ${JSON.stringify(typo).slice(0, 400)}`);
console.log(`ok: vqlog (tv-portal ${tv[1]} times, p95 ${byClient.result.rows[0][3]} ms, estimate ${est.result.cost.estimatedRows} rows)`);

// 4b. Resources and prompts (AGT-010).
const { resources } = await c.listResources();
const uris = resources.map((r) => r.uri).sort();
if (JSON.stringify(uris) !== JSON.stringify(['telltale://cluster/status', 'telltale://config', 'telltale://reports/daily']))
  fail(`resources ${uris}`);
const doc = async (uri) => JSON.parse((await c.readResource({ uri })).contents[0].text);
const daily = await doc('telltale://reports/daily');
if (!(daily.summary?.queries > 0)) fail(`daily summary: ${JSON.stringify(daily).slice(0, 300)}`);
const cfg = await doc('telltale://config');
if (!cfg.devices?.items?.some((d) => d.name === 'living-room-tv')) fail(`config resource: ${JSON.stringify(cfg).slice(0, 300)}`);
if (JSON.stringify(cfg).includes('password')) fail('the config resource mentions a password');
if (!(await doc('telltale://cluster/status')).system?.version) fail('cluster status resource');
const { prompts } = await c.listPrompts();
if (prompts.length !== 4) fail(`prompts: ${prompts.map((x) => x.name)}`);
const inv = await c.getPrompt({ name: 'investigate_device', arguments: { client: 'living-room-tv' } });
const text = inv.messages[0].content.text;
if (!text.includes('get_client_profile') || !text.includes('"living-room-tv"') || text.includes('{client}')) fail(`prompt: ${text.slice(0, 200)}`);
console.log(`ok: ${resources.length} resources, ${prompts.length} prompts`);
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
const deniedVq = await n.callTool({ name: 'vqlog', arguments: { query: 'top 5 name' } });
if (!deniedVq.isError) fail('vqlog worked without querylog:read');
console.log('ok: scopes apply to tools');
await n.close();

// 5. Plans (AGT-007): approval, apply, stale, audit.
const login = await fetch(`${api}/api/v1/auth/login`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ username: 'admin', password: process.env.ADMIN_PASSWORD }),
});
if (!login.ok) fail(`admin login: ${login.status}`);
const cookie = login.headers.getSetCookie().map((x) => x.split(';')[0]).join('; ');
const csrf = (await login.json()).csrfToken;
const admin = async (method, path) => {
  const r = await fetch(`${api}${path}`, { method, headers: { cookie, 'x-csrf-token': csrf } });
  return [r.status, await r.json().catch(() => null)];
};
const w = await connect(http(process.env.WRITER_TOKEN));
const call = async (name, args) => {
  const r = await w.callTool({ name, arguments: args });
  return [r.isError, data(r)];
};
const outcome = async (name) => data(await w.callTool({ name: 'explain_decision', arguments: { name, client: '127.0.0.1' } })).explanation?.outcome;
const reason = 'mcp-e2e: the owner asked to block this';
let [err, plan] = await call('plan_block_domain', { domain: 'agent.mcp.test', reason });
if (err || plan.state !== 'pending' || !plan.planId) fail(`plan_block_domain: ${JSON.stringify(plan).slice(0, 400)}`);
if (!plan.preview || plan.preview.applied !== false) fail(`no dry-run preview: ${JSON.stringify(plan).slice(0, 300)}`);
if ((await outcome('agent.mcp.test')) === 'blocked') fail('planning blocked the name already');
[err] = await call('apply_plan', { planId: plan.planId });
if (!err) fail('apply_plan worked before approval');
const [st] = await admin('POST', `/api/v1/plans/${plan.planId}/approve`);
if (st !== 200) fail(`approve: ${st}`);
const [, mine] = await call('list_plans', {});
if (mine.items?.find((p) => p.id === plan.planId)?.state !== 'approved') fail(`list_plans: ${JSON.stringify(mine).slice(0, 300)}`);
let applied;
[err, applied] = await call('apply_plan', { planId: plan.planId });
if (err || applied.state !== 'applied') fail(`apply_plan: ${JSON.stringify(applied).slice(0, 400)}`);
if ((await outcome('agent.mcp.test')) !== 'blocked') fail('the applied plan didn\'t block the name');
console.log(`ok: plan → approve → apply (${plan.summary})`);

// Stale: two plans against the same version; applying one makes the other stale.
const [, a] = await call('plan_allow_domain', { domain: 'one.mcp.test', reason });
const [, b] = await call('plan_allow_domain', { domain: 'two.mcp.test', reason });
for (const p of [a, b]) if ((await admin('POST', `/api/v1/plans/${p.planId}/approve`))[0] !== 200) fail('approve a/b');
[err] = await call('apply_plan', { planId: b.planId });
if (err) fail('apply b');
const [staleErr, stale] = await call('apply_plan', { planId: a.planId });
if (!staleErr || stale.state !== 'stale') fail(`expected stale: ${JSON.stringify(stale).slice(0, 300)}`);
// A rejected plan can't be applied; agents can't approve.
const [, c2] = await call('plan_allow_domain', { domain: 'three.mcp.test', reason });
const self = await fetch(`${api}/api/v1/plans/${c2.planId}/approve`, { method: 'POST', headers: { authorization: `Bearer ${process.env.WRITER_TOKEN}`, 'x-telltale-reason': 'x' } });
if (self.status !== 403) fail(`an agent approved its own plan: ${self.status}`);
await admin('POST', `/api/v1/plans/${c2.planId}/reject`);
if (!(await call('apply_plan', { planId: c2.planId }))[0]) fail('a rejected plan applied');
console.log('ok: stale plans and rejected plans are refused; agents can\'t approve');

// Audit: the apply names the agent, its owner, the client software, and the reason.
const [, audit] = await admin('GET', '/api/v1/audit?action=rule.put&limit=20');
const entry = audit?.items?.find((e) => e.target === 'agent-block-agent-mcp-test');
if (!entry || !entry.actor.startsWith('agent:') || !entry.actor.includes('(owner: admin)') || entry.reason !== reason)
  fail(`audit: ${JSON.stringify(entry ?? audit).slice(0, 400)}`);
const decided = (await admin('GET', '/api/v1/audit?action=plan.approve&limit=5'))[1];
if (!(decided?.items?.length > 0)) fail('approvals aren\'t audited');
console.log(`ok: audited as ${entry.actor}`);

// 6. Change simulation (OBS-024): plans simulate only when asked, unless an operator says so.
const sim = await connect(http(process.env.SIM_TOKEN));
const planSim = async (args) => {
  const r = await sim.callTool({ name: 'plan_block_domain', arguments: { reason, domain: 'sim.mcp.test', ...args } });
  return [r.isError, data(r)];
};
const blocked5 = (s) => s?.newlyBlocked?.queries >= 5 && s.newlyBlocked.topNames?.[0]?.name === 'sim.mcp.test';
let [e1, p1] = await planSim({});
if (e1 || !p1.planId || p1.preview?.simulation) fail(`a plan without simulate: ${JSON.stringify(p1).slice(0, 400)}`);
let [e2, p2] = await planSim({ simulate: '24h' });
if (e2 || !blocked5(p2.preview?.simulation)) fail(`a plan with simulate: ${JSON.stringify(p2).slice(0, 600)}`);
const [we] = await call('plan_block_domain', { domain: 'sim.mcp.test', reason, simulate: '24h' });
if (!we) fail('a plan simulated for a token without querylog:read');
const sc = data(await sim.callTool({ name: 'simulate_change', arguments: { kind: 'block_domain', change: { domain: 'sim.mcp.test' }, window: '24h' } }));
if (!blocked5(sc?.simulation)) fail(`simulate_change: ${JSON.stringify(sc).slice(0, 600)}`);
const settings = (method, headers, body) =>
  fetch(`${api}/api/v1/simulate-settings/default`, { method, headers: { 'content-type': 'application/json', ...headers }, body });
const agentFlip = await settings('PUT', { authorization: `Bearer ${process.env.SIM_TOKEN}`, 'x-telltale-reason': 'x' }, '{"plans_by_default": true}');
if (agentFlip.status !== 403) fail(`an agent changed the simulation settings: ${agentFlip.status}`);
if (tools.some((t) => /simulat\w*_settings/.test(t.name))) fail('an MCP tool changes the simulation settings');
const on = await settings('PUT', { cookie, 'x-csrf-token': csrf }, '{"plans_by_default": true}');
if (on.status !== 200) fail(`turning plans_by_default on: ${on.status} ${await on.text()}`);
let [e3, p3] = await planSim({});
if (e3 || !blocked5(p3.preview?.simulation)) fail(`with plans_by_default, a plan: ${JSON.stringify(p3).slice(0, 600)}`);
if ((await admin('DELETE', '/api/v1/simulate-settings/default'))[0] !== 200) fail('reverting the simulation settings');
let [e4, p4] = await planSim({});
if (e4 || p4.preview?.simulation) fail(`after reverting, a plan still simulates: ${JSON.stringify(p4).slice(0, 300)}`);
console.log(`ok: simulations (${p2.preview.simulation.newlyBlocked.queries} queries newly blocked, on request or by the operator's default)`);
await sim.close();

// 7. Staged rollouts and pins (CLU-013): read with rollout_status; pins are plans, and this
// node isn't in a cluster, so both say a cluster is needed.
const ro = await connect(http(process.env.CLUSTER_TOKEN));
const rs = await ro.callTool({ name: 'rollout_status', arguments: {} });
if (!rs.isError || !JSON.stringify(rs).includes('need a cluster')) fail(`rollout_status standalone: ${JSON.stringify(rs).slice(0, 400)}`);
const pin = await ro.callTool({ name: 'plan_pin_version', arguments: { epoch: 1, seq: 1, reason } });
const pd = data(pin);
if (!pin.isError || pd?.planned !== false || !JSON.stringify(pd).includes('need a cluster')) fail(`plan_pin_version standalone: ${JSON.stringify(pin).slice(0, 400)}`);
const pinNoScope = await w.callTool({ name: 'plan_pin_version', arguments: { epoch: 1, seq: 1, reason } });
if (!pinNoScope.isError) fail('plan_pin_version worked without cluster:admin');
await ro.close();
console.log('ok: rollout_status and plan_pin_version (a cluster is needed; cluster:admin required)');
await w.close();
console.log('PASS');
