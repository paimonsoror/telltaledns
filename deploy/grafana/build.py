#!/usr/bin/env python3
"""Generates telltale-dashboard.json (REQ: OBS-005, OBS-011, `spec/06` §5).

    python3 deploy/grafana/build.py           # writes deploy/grafana/telltale-dashboard.json
    python3 deploy/grafana/build.py --check   # fails if the committed file is stale

Every query uses only metrics from `spec/06` §5 as exported by TelltaleDNS. Variables:
datasource, job, instance.
"""
import json
import pathlib
import sys

OUT = pathlib.Path(__file__).with_name("telltale-dashboard.json")
# The Helm chart ships the same file (grafanaDashboard.enabled).
CHART_COPY = pathlib.Path(__file__).parents[1] / "helm/telltale/files/telltale-dashboard.json"
SEL = 'job=~"$job", instance=~"$instance"'
DS = {"type": "prometheus", "uid": "${datasource}"}

panels = []
_id = 0
_y = 0


def nid():
    global _id
    _id += 1
    return _id


def row(title):
    global _y
    panels.append({"type": "row", "title": title, "id": nid(), "collapsed": False,
                   "gridPos": {"h": 1, "w": 24, "x": 0, "y": _y}, "panels": []})
    _y += 1


def place(w, h, x):
    return {"h": h, "w": w, "x": x, "y": _y}


def target(expr, legend="", instant=False):
    t = {"datasource": DS, "expr": expr, "legendFormat": legend, "refId": chr(65 + len(_targets))}
    if instant:
        t["instant"] = True
        t["range"] = False
    _targets.append(t)
    return t


_targets = []


def targets(*pairs, instant=False):
    global _targets
    _targets = []
    return [target(e, l, instant) for e, l in pairs]


def stat(title, x, w, expr, unit, desc, thresholds=None, decimals=None):
    p = {
        "type": "stat", "title": title, "id": nid(), "datasource": DS, "description": desc,
        "gridPos": place(w, 4, x),
        "targets": targets((expr, ""), instant=True),
        "options": {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                    "colorMode": "value", "graphMode": "none", "textMode": "auto"},
        "fieldConfig": {"defaults": {"unit": unit, "color": {"mode": "thresholds"},
                                     "thresholds": {"mode": "absolute", "steps": thresholds or [
                                         {"color": "green", "value": None}]}},
                        "overrides": []},
    }
    if decimals is not None:
        p["fieldConfig"]["defaults"]["decimals"] = decimals
    panels.append(p)


def ts(title, x, w, h, exprs, unit, desc, stack=False, fill=10, overrides=None):
    panels.append({
        "type": "timeseries", "title": title, "id": nid(), "datasource": DS, "description": desc,
        "gridPos": place(w, h, x),
        "targets": targets(*exprs),
        "options": {"legend": {"displayMode": "table", "placement": "right", "calcs": ["mean", "max", "lastNotNull"]},
                    "tooltip": {"mode": "multi", "sort": "desc"}},
        "fieldConfig": {"defaults": {"unit": unit, "custom": {
            "fillOpacity": fill, "lineWidth": 1, "showPoints": "never",
            "stacking": {"mode": "normal" if stack else "none", "group": "A"}}},
            "overrides": overrides or []},
    })


def status_colors():
    colors = {"blocked": "red", "cached": "green", "forwarded": "blue", "local": "purple",
              "stale": "orange", "servfail": "dark-red", "refused": "dark-orange"}
    return [{"matcher": {"id": "byName", "options": k},
             "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": v}}]}
            for k, v in colors.items()]


def advance(h):
    global _y
    _y += h


def q(quantile, metric, by):
    return (f'histogram_quantile({quantile}, sum by (le, {by}) '
            f'(rate({metric}_bucket{{{SEL}}}[$__rate_interval])))')


# ---- Overview
row("Overview")
stat("Queries / s", 0, 4, f'sum(rate(telltale_queries_total{{{SEL}}}[5m]))', "reqps",
     "All DNS queries, every transport and outcome.", decimals=1)
stat("Blocked", 4, 4,
     f'sum(rate(telltale_queries_total{{{SEL}, status="blocked"}}[5m])) / '
     f'sum(rate(telltale_queries_total{{{SEL}}}[5m]))', "percentunit",
     "Share of queries blocked by filter lists.", decimals=1)
stat("Cache hits", 8, 4,
     f'sum(rate(telltale_cache_hits_total{{{SEL}}}[5m])) / '
     f'(sum(rate(telltale_cache_hits_total{{{SEL}}}[5m])) + sum(rate(telltale_cache_misses_total{{{SEL}}}[5m])))',
     "percentunit", "Fresh cache hits over all cache lookups.", decimals=1)
stat("Upstream p95", 12, 4,
     q(0.95, "telltale_upstream_duration_seconds", "job").replace("$__rate_interval", "5m"), "s",
     "95th percentile upstream exchange time, all upstreams.",
     thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 0.1},
                 {"color": "red", "value": 0.5}])
stat("Upstreams down", 16, 4,
     f'count(telltale_upstream_breaker_state{{{SEL}}} == 2) or vector(0)', "none",
     "Upstreams whose circuit breaker is open (benched after failures).",
     thresholds=[{"color": "green", "value": None}, {"color": "red", "value": 1}])
stat("Memory", 20, 4, f'max(telltale_resident_memory_bytes{{{SEL}}})', "bytes",
     "Resident set size of the TelltaleDNS process.")
advance(4)

ts("Queries by status", 0, 12, 8,
   [(f'sum by (status) (rate(telltale_queries_total{{{SEL}}}[$__rate_interval])) > 0', "{{status}}")],
   "reqps", "Queries per second by how they were answered.", stack=True, fill=40,
   overrides=status_colors())
ts("Responses by RCODE", 12, 12, 8,
   [(f'sum by (rcode) (rate(telltale_responses_total{{{SEL}}}[$__rate_interval])) > 0', "{{rcode}}")],
   "reqps", "Responses per second by response code.", stack=True, fill=30)
advance(8)

# ---- Latency
row("Latency")
ts("Answer time by path (p50 / p95 / p99)", 0, 12, 8,
   [(q(0.5, "telltale_query_duration_seconds", "path"), "p50 {{path}}"),
    (q(0.95, "telltale_query_duration_seconds", "path"), "p95 {{path}}"),
    (q(0.99, "telltale_query_duration_seconds", "path"), "p99 {{path}}")],
   "s", "Receive-to-answer time per answer path (cache, upstream, local, synthesized).", fill=0)
ts("Where time goes", 12, 12, 8,
   [(q(0.5, "telltale_stage_duration_seconds", "stage"), "p50 {{stage}}"),
    (q(0.95, "telltale_stage_duration_seconds", "stage"), "p95 {{stage}}"),
    (q(0.5, "telltale_query_duration_seconds", "path"), "p50 total {{path}}")],
   "s", "Stage times (waiting for upstreams) against total answer times.", fill=0)
advance(8)

# ---- Upstreams (OBS-011)
row("Upstreams")
ts("Upstream latency (p50 / p95 / p99)", 0, 12, 8,
   [(q(0.5, "telltale_upstream_duration_seconds", "upstream"), "p50 {{upstream}}"),
    (q(0.95, "telltale_upstream_duration_seconds", "upstream"), "p95 {{upstream}}"),
    (q(0.99, "telltale_upstream_duration_seconds", "upstream"), "p99 {{upstream}}")],
   "s", "Per-upstream exchange time, including prefetches (OBS-011).", fill=0)
ts("Upstream share of traffic", 12, 6, 8,
   [(f'sum by (upstream) (rate(telltale_upstream_requests_total{{{SEL}}}[$__rate_interval]))', "{{upstream}}")],
   "reqps", "Attempts per second per upstream.", stack=True, fill=40)
ts("Upstream failure rate", 18, 6, 8,
   [(f'sum by (upstream) (rate(telltale_upstream_requests_total{{{SEL}, outcome="failure"}}[$__rate_interval])) / '
     f'sum by (upstream) (rate(telltale_upstream_requests_total{{{SEL}}}[$__rate_interval]))', "{{upstream}}")],
   "percentunit", "Timeouts, errors, SERVFAIL/REFUSED as a share of attempts.", fill=0)
advance(8)
panels.append({
    "type": "state-timeline", "title": "Circuit breakers", "id": nid(), "datasource": DS,
    "description": "0 closed (healthy), 1 half-open (probing), 2 open (benched).",
    "gridPos": place(24, 5, 0),
    "targets": targets((f'max by (upstream) (telltale_upstream_breaker_state{{{SEL}}})', "{{upstream}}")),
    "options": {"showValue": "never", "mergeValues": True, "rowHeight": 0.8},
    "fieldConfig": {"defaults": {"mappings": [{"type": "value", "options": {
        "0": {"text": "closed", "color": "green"}, "1": {"text": "half-open", "color": "orange"},
        "2": {"text": "open", "color": "red"}}}], "color": {"mode": "thresholds"},
        "thresholds": {"mode": "absolute", "steps": [{"color": "green", "value": None}]}}, "overrides": []},
})
advance(5)

# ---- Filtering
row("Filtering")
ts("Blocked by list", 0, 12, 8,
   [(f'topk(10, sum by (list) (rate(telltale_blocked_total{{{SEL}}}[$__rate_interval])))', "{{list}}")],
   "reqps", "Blocks per second by the deciding list (top 10).", stack=True, fill=40)
ts("Blocked by group", 12, 6, 8,
   [(f'sum by (group) (rate(telltale_blocked_total{{{SEL}}}[$__rate_interval]))', "{{group}}")],
   "reqps", "Blocks per second by the client's group.", stack=True, fill=40)
panels.append({
    "type": "table", "title": "Lists", "id": nid(), "datasource": DS,
    "description": "Entries each list contributes, and hours since it was last confirmed current.",
    "gridPos": place(6, 8, 18),
    "targets": [
        {"datasource": DS, "expr": f'max by (list) (telltale_list_entries{{{SEL}}})', "format": "table",
         "instant": True, "range": False, "refId": "A"},
        {"datasource": DS, "expr": f'(time() - max by (list) (telltale_list_last_success_timestamp_seconds{{{SEL}}})) / 3600',
         "format": "table", "instant": True, "range": False, "refId": "B"},
    ],
    "transformations": [{"id": "merge", "options": {}},
                        {"id": "organize", "options": {"excludeByName": {"Time": True},
                                                       "renameByName": {"Value #A": "entries", "Value #B": "hours since update"}}}],
    "fieldConfig": {"defaults": {"decimals": 0}, "overrides": []},
})
advance(8)

# ---- Cache
row("Cache")
ts("Cache activity", 0, 12, 7,
   [(f'sum(rate(telltale_cache_hits_total{{{SEL}}}[$__rate_interval]))', "hits"),
    (f'sum(rate(telltale_cache_misses_total{{{SEL}}}[$__rate_interval]))', "misses"),
    (f'sum(rate(telltale_cache_stale_served_total{{{SEL}}}[$__rate_interval]))', "stale served"),
    (f'sum(rate(telltale_cache_prefetch_total{{{SEL}}}[$__rate_interval]))', "prefetches"),
    (f'sum(rate(telltale_cache_evictions_total{{{SEL}}}[$__rate_interval]))', "evictions")],
   "reqps", "Cache lookups and maintenance per second.", fill=0)
ts("Cache size", 12, 12, 7,
   [(f'sum(telltale_cache_bytes{{{SEL}}})', "bytes")],
   "bytes", "Approximate cache memory.", fill=20,
   overrides=[])
advance(7)

# ---- Clients (opt-in)
row("Clients")
ts("Top clients", 0, 24, 8,
   [(f'topk(10, sum by (client) (rate(telltale_client_queries_total{{{SEL}, client!="other"}}[$__rate_interval])))', "{{client}}")],
   "reqps", "Queries per second for the busiest clients. Needs [telemetry.metrics] per_client = true.",
   stack=False, fill=0)
advance(8)

# ---- T9.13: transports and encrypted DNS
row("Transports")
ts("Queries by transport", 0, 12, 7,
   [(f'sum by (proto) (rate(telltale_queries_total{{{SEL}}}[$__rate_interval]))', "{{proto}}")],
   "reqps", "Queries per second over UDP, TCP, DoT, DoH, and DoQ.", stack=True)
ts("Encrypted DNS problems", 12, 12, 7,
   [(f'sum(rate(telltale_tls_handshake_failures_total{{{SEL}}}[$__rate_interval]))', "TLS handshakes failed"),
    (f'sum(rate(telltale_doh_bad_requests_total{{{SEL}}}[$__rate_interval]))', "DoH bad requests"),
    (f'sum(rate(telltale_doq_protocol_errors_total{{{SEL}}}[$__rate_interval]))', "DoQ protocol errors"),
    (f'sum(rate(telltale_proxy_protocol_rejected_total{{{SEL}}}[$__rate_interval]))', "PROXY headers refused"),
    (f'sum(rate(telltale_tcp_rejected_total{{{SEL}}}[$__rate_interval]))', "TCP connections refused")],
   "ops", "Clients that couldn't talk to the encrypted listeners: an expired or wrong certificate, a broken client, or a load balancer without PROXY protocol.", fill=0)
advance(7)

# ---- Health of TelltaleDNS itself
row("TelltaleDNS")
# REQ: OBS-002 (T9.13) — restarts, counted in the data directory, so they survive restarts.
stat("Uptime", 0, 6, f'min(telltale_uptime_seconds{{{SEL}}})', "s",
     "Since the most recent start of any selected node.")
stat("Restarts", 6, 6, f'sum(increase(telltale_process_starts_total{{{SEL}}}[$__range]))', "none",
     "Starts in the selected time range, every node (a new pod with an empty data directory counts from 1).",
     thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 1}], decimals=0)
stat("After a crash or a kill", 12, 6,
     f'sum(increase(telltale_process_unclean_starts_total{{{SEL}}}[$__range]))', "none",
     "Starts after a run that didn't stop cleanly: a crash, an OOM kill, a power cut.",
     thresholds=[{"color": "green", "value": None}, {"color": "red", "value": 1}], decimals=0)
stat("OOM kills", 18, 6, f'sum(increase(telltale_cgroup_oom_kills_total{{{SEL}}}[$__range]))', "none",
     "Times the container's memory limit killed a process (cgroup v2).",
     thresholds=[{"color": "green", "value": None}, {"color": "red", "value": 1}], decimals=0)
advance(4)
ts("Telemetry and query log", 0, 12, 7,
   [(f'sum(rate(telltale_telemetry_dropped_total{{{SEL}}}[$__rate_interval]))', "events dropped"),
    (f'sum(rate(telltale_qlog_rows_written_total{{{SEL}}}[$__rate_interval]))', "log rows written"),
    (f'sum(rate(telltale_qlog_rows_dropped_total{{{SEL}}}[$__rate_interval]))', "log rows dropped"),
    (f'sum(rate(telltale_ratelimited_total{{{SEL}}}[$__rate_interval]))', "rate limited")],
   "ops", "Dropped events/rows mean the analytics fell behind; answers never wait for them.", fill=0)
ts("Memory", 12, 12, 7,
   [(f'max(telltale_resident_memory_bytes{{{SEL}}})', "RSS"),
    (f'max(telltale_host_memory_bytes{{{SEL}, kind="available"}})', "host available")],
   "bytes", "Resident memory of the process, and what the machine has left.", fill=20)
advance(7)
ts("Machine", 0, 12, 7,
   [(f'max by (instance) (telltale_host_cpu_busy_ratio{{{SEL}}})', "CPU busy {{instance}}")],
   "percentunit", "How busy each node's machine is (all cores).", fill=0)
ts("Temperature and disk", 12, 12, 7,
   [(f'max by (instance) (telltale_host_temperature_celsius{{{SEL}}})', "°C {{instance}}"),
    (f'min by (instance) (telltale_data_filesystem_bytes{{{SEL}, kind="free"}} / telltale_data_filesystem_bytes{{{SEL}, kind="total"}} * 100)', "data disk free % {{instance}}")],
   "none", "CPU temperature (a Pi throttles near 80 °C) and free space where the data directory is.", fill=0)
advance(7)

dashboard = {
    "__inputs": [],
    "title": "TelltaleDNS",
    "uid": "telltaledns",
    "description": "TelltaleDNS resolver: traffic, latency, upstream health, filtering, cache. Generated by deploy/grafana/build.py.",
    "tags": ["dns", "telltale"],
    "timezone": "browser",
    "schemaVersion": 39,
    "version": 1,
    "editable": True,
    "graphTooltip": 1,
    "refresh": "30s",
    "time": {"from": "now-6h", "to": "now"},
    "templating": {"list": [
        {"name": "datasource", "label": "Data source", "type": "datasource", "query": "prometheus",
         "current": {}, "hide": 0},
        {"name": "job", "label": "Job", "type": "query", "datasource": DS,
         "query": {"query": "label_values(telltale_build_info, job)", "refId": "job"},
         "definition": "label_values(telltale_build_info, job)", "refresh": 2, "includeAll": True,
         "multi": True, "allValue": ".*", "current": {"text": "All", "value": "$__all"}},
        {"name": "instance", "label": "Instance", "type": "query", "datasource": DS,
         "query": {"query": 'label_values(telltale_build_info{job=~"$job"}, instance)', "refId": "instance"},
         "definition": 'label_values(telltale_build_info{job=~"$job"}, instance)', "refresh": 2,
         "includeAll": True, "multi": True, "allValue": ".*", "current": {"text": "All", "value": "$__all"}},
    ]},
    "annotations": {"list": []},
    "panels": panels,
}

text = json.dumps(dashboard, indent=2) + "\n"
if "--check" in sys.argv:
    for out in (OUT, CHART_COPY):
        if not out.exists() or out.read_text() != text:
            sys.exit(f"{out} is stale: run python3 deploy/grafana/build.py")
    print(f"{OUT.name} OK ({len(panels)} panels, chart copy too)")
else:
    for out in (OUT, CHART_COPY):
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text)
    print(f"wrote {OUT} and the chart copy ({len(panels)} panels)")
