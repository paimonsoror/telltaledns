#!/usr/bin/env python3
"""Builds the TelltaleDNS project site into site/_site (ADR-012, DOC-001/004/005).

No dependencies beyond the Python standard library (3.6+). It:
  1. injects the shared header/footer partials into every page,
  2. renders the Standards table and cards from site/data/standards.json,
  3. fails if a ticked roadmap task cites a requirement whose RFCs are missing from that file,
  4. checks that every internal link and asset reference resolves,
  5. renders the "For nerds" page from site/data/architecture.json and fails if it disagrees
     with the repo (crates, Cargo dependencies, public types, ADR/requirement IDs, paths).

Usage: python3 site/build.py [--check]   (--check builds into a temp dir and only validates)
"""
import datetime
import html
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

SITE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(SITE)
PAGES = ["index.html", "start.html", "install.html", "how-it-works.html", "agents.html", "config.html", "helm-values.html", "glossary.html", "performance.html", "standards.html", "nerds.html"]
STATUS_ORDER = {"supported": 0, "partial": 1, "planned": 2}


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def build_stamp():
    sha = os.environ.get("GITHUB_SHA", "")
    if not sha:
        try:
            sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT).decode().strip()
        except Exception:
            sha = "local"
    return "{} · {}".format(datetime.date.today().isoformat(), sha[:7])


def req_link(r):
    return '<a class="req" href="https://github.com/paimonsoror/telltaledns/blob/main/spec/01-requirements.md">{}</a>'.format(
        html.escape(r)
    )


def render_standards(page, data):
    items = sorted(data["standards"], key=lambda s: (STATUS_ORDER[s["status"]], int(s["rfc"])))
    counts = {k: sum(1 for s in items if s["status"] == k) for k in STATUS_ORDER}
    summary = (
        '<p class="muted"><b>{supported}</b> supported · <b>{partial}</b> partial · <b>{planned}</b> planned</p>'.format(**counts)
    )
    rows, cards = [], []
    for s in items:
        rfc, title, status = s["rfc"], html.escape(s["title"]), s["status"]
        link = "https://www.rfc-editor.org/rfc/rfc{}".format(rfc)
        rows.append(
            '      <tr><td><a href="{link}">RFC {rfc}</a></td><td>{title}</td>'
            '<td><span class="pill {status}">{status}</span></td><td>{reqs}</td></tr>'.format(
                link=link, rfc=rfc, title=title, status=status, reqs=" ".join(req_link(r) for r in s["reqs"])
            )
        )
        svg = read(os.path.join(SITE, "diagrams", s["diagram"] + ".svg")).strip()
        cards.append(
            '    <article class="card" id="rfc{rfc}"><h3><a href="{link}">RFC {rfc}</a> '
            '<span class="pill {status}">{status}</span></h3><p><b>{title}.</b> {summary}</p>\n{svg}\n    </article>'.format(
                rfc=rfc, link=link, status=status, title=title, summary=html.escape(s["summary"]), svg=svg
            )
        )
    page = page.replace("<!-- @standards-summary -->", summary)
    page = page.replace("<!-- @standards-rows -->", "\n".join(rows))
    page = page.replace("<!-- @standards-cards -->", "\n".join(cards))
    return page


# REQ: DOC-002/003 (T4.6) — the configuration reference, rendered from the JSON Schema the
# binary prints (`telltale config schema`), committed as docs/config-schema.json and kept
# current by a test in telltale-config. Sections follow the order of a typical config.
CONFIG_ORDER = [
    "config_version", "node", "listen", "upstream", "upstream_group", "route", "list", "filter",
    "group", "client", "clients", "record", "local", "access", "ratelimit", "special", "cache",
    "telemetry", "api", "auth", "cluster",
]


def _resolve(s, defs):
    """Follows $ref / single allOf / Option (anyOf with null); returns (schema, ref name)."""
    name = None
    for _ in range(8):
        if "$ref" in s:
            name = s["$ref"].split("/")[-1]
            s = dict(defs[name], **{k: v for k, v in s.items() if k != "$ref"})
        elif "allOf" in s and len(s["allOf"]) == 1:
            s = dict(s["allOf"][0], **{k: v for k, v in s.items() if k != "allOf"})
        elif "anyOf" in s and any(x.get("type") == "null" for x in s["anyOf"]):
            rest = [x for x in s["anyOf"] if x.get("type") != "null"]
            s = dict(rest[0], **{k: v for k, v in s.items() if k != "anyOf"}) if len(rest) == 1 else s
            if len(rest) != 1:
                break
        else:
            break
    return s, name


def _enum_values(s):
    if "enum" in s:
        return [str(v) for v in s["enum"]]
    alts = s.get("oneOf") or s.get("anyOf") or []
    vals = []
    for a in alts:
        if "const" in a:
            vals.append(str(a["const"]))
        elif "enum" in a:
            vals += [str(v) for v in a["enum"]]
        else:
            return None
    return vals or None


def _type_label(s, defs):
    s, name = _resolve(s, defs)
    vals = _enum_values(s)
    if vals:
        return " | ".join('"{}"'.format(v) for v in vals)
    t = s.get("type")
    if isinstance(t, list):
        t = [x for x in t if x != "null"]
        t = t[0] if len(t) == 1 else "/".join(t)
    if t == "array":
        return "list of " + _type_label(s.get("items", {}), defs)
    if t == "object" and name:
        return name
    if t:
        return {"integer": "integer", "string": "string", "boolean": "true/false", "number": "number"}.get(t, t)
    alts = s.get("oneOf") or s.get("anyOf")
    if alts:
        kinds = sorted({a.get("type", "?") for a in alts})
        if kinds == ["integer", "string"]:
            return "size (bytes or \"32MiB\")"
        return " or ".join(kinds)
    return name or "value"


def _toml(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, str):
        return json.dumps(v)
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, list):
        return "[" + ", ".join(_toml(x) for x in v) + "]" if len(json.dumps(v)) < 60 else "[…]"
    if v is None:
        return "(none)"
    return "{…}"


def _is_table(s, defs):
    r, _ = _resolve(s, defs)
    return r.get("type") == "object" and "properties" in r


def _section(path, s, defs, array, out):
    s, _ = _resolve(s, defs)
    if s.get("type") == "array":
        s, _ = _resolve(s.get("items", {}), defs)
        array = True
    head = "[[{}]]".format(path) if array else "[{}]".format(path)
    anchor = "cfg-" + path.replace(".", "-")
    out.append('<section class="cfg" id="{}"><h3><a href="#{}"><code>{}</code></a></h3>'.format(anchor, anchor, head))
    desc = s.get("description", "")
    if desc:
        out.append("<p>{}</p>".format(_md(desc)))
    rows, nested = [], []
    for key, p in sorted(s.get("properties", {}).items()):
        r, _ = _resolve(p, defs)
        if _is_table(p, defs) or (r.get("type") == "array" and _is_table(r.get("items", {}), defs) and key not in ("rules",)):
            nested.append((key, p))
            continue
        d = p.get("default", r.get("default"))
        rows.append(
            "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                html.escape(key),
                html.escape(_type_label(p, defs)),
                "<code>{}</code>".format(html.escape(_toml(d))) if "default" in p or "default" in r else "",
                _md(p.get("description", r.get("description", ""))),
            )
        )
    if rows:
        out.append('<div class="table-wrap"><table><thead><tr><th>Key</th><th>Type</th><th>Default</th><th>Meaning</th></tr></thead><tbody>')
        out += rows
        out.append("</tbody></table></div>")
    out.append("</section>")
    for key, p in nested:
        _section(path + "." + key, p, defs, False, out)


def _md(text):
    """Backticks → <code>, the rest escaped; one paragraph."""
    parts = text.replace("\n", " ").split("`")
    return "".join("<code>{}</code>".format(html.escape(x)) if i % 2 else html.escape(x) for i, x in enumerate(parts))


def render_config(page, schema):
    defs = schema.get("$defs", {})
    props = schema["properties"]
    order = [k for k in CONFIG_ORDER if k in props] + sorted(k for k in props if k not in CONFIG_ORDER)
    out, toc = [], []
    scalars = [k for k in order if not _is_table(props[k], defs) and _resolve(props[k], defs)[0].get("type") != "array"]
    if scalars:
        out.append('<section class="cfg" id="cfg-top"><h3><a href="#cfg-top">Top level</a></h3><div class="table-wrap"><table><thead><tr><th>Key</th><th>Type</th><th>Default</th><th>Meaning</th></tr></thead><tbody>')
        for k in scalars:
            p = props[k]
            out.append("<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                k, html.escape(_type_label(p, defs)), "<code>{}</code>".format(html.escape(_toml(p["default"]))) if "default" in p else "", _md(p.get("description", ""))))
        out.append("</tbody></table></div></section>")
    for k in order:
        if k in scalars:
            continue
        array = _resolve(props[k], defs)[0].get("type") == "array"
        toc.append('<a href="#cfg-{}"><code>{}</code></a>'.format(k, ("[[{}]]" if array else "[{}]").format(k)))
        _section(k, props[k], defs, array, out)
    page = page.replace("<!-- @config-toc -->", " · ".join(toc))
    return page.replace("<!-- @config-reference -->", "\n".join(out))


# REQ: DOC-006, OPS-003 — every Helm chart value with its default and meaning, read from the
# chart's own values.yaml (its comments are the documentation), so the page can't drift.
HELM_VALUES = os.path.join(ROOT, "deploy", "helm", "telltale", "values.yaml")
HELM_SCHEMA = os.path.join(ROOT, "deploy", "helm", "telltale", "values.schema.json")
_KEY = re.compile(r'^( *)([A-Za-z0-9_.-]+|"[^"]+"):(?: +(.*))?$')
_REQ = re.compile(r"^REQ: [^—]+— ")


def _desc(lines):
    text = " ".join(x.strip() for x in lines).strip()
    text = _REQ.sub("", text)
    return text[:1].upper() + text[1:]


def parse_values(text):
    """values.yaml → [[path, default or None, description, example]], standard library only.

    Covers what the chart uses: nested maps, scalars, flow lists and maps, and `|` blocks. A
    comment block directly above a key describes it; one directly below a key and followed by
    a blank line is that key's example (commented-out YAML)."""
    lines = text.split("\n")
    rows, stack, pending, last = [], [], [], None
    i = 0
    while i < len(lines):
        raw = lines[i]
        s = raw.strip()
        if not s:
            if pending and last is not None and pending[0] == "after":
                rows[last][3] = "\n".join(pending[1:])
            pending, last = [], None
            i += 1
            continue
        if s.startswith("#"):
            if not pending:
                pending = ["after" if last is not None else "before"]
            pending.append(s[1:])
            i += 1
            continue
        m = _KEY.match(raw)
        if not m:
            i += 1
            continue
        ind, key, val = len(m.group(1)), m.group(2).strip('"'), (m.group(3) or "").strip()
        while stack and stack[-1][0] >= ind:
            stack.pop()
        path = ".".join([k for _, k in stack] + [key])
        desc = _desc(pending[1:]) if pending else ""
        pending = []
        if val.startswith("|"):
            block, i = [], i + 1
            while i < len(lines) and (not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip()) > ind):
                block.append(lines[i])
                i += 1
            while block and not block[-1].strip():
                block.pop()
            cut = min((len(b) - len(b.lstrip()) for b in block if b.strip()), default=0)
            rows.append([path, "\n".join(b[cut:] for b in block), desc, ""])
            last = len(rows) - 1
            continue
        if val:
            rows.append([path, val, desc, ""])
        else:
            stack.append((ind, key))
            rows.append([path, None, desc, ""])
        last = len(rows) - 1
        i += 1
    return rows


def helm_values_errors(rows):
    """Every key the chart's schema knows must be in values.yaml (and so on the page)."""
    schema = json.loads(read(HELM_SCHEMA))
    paths = {r[0] for r in rows}
    errs = []

    def walk(prefix, s):
        for k, p in s.get("properties", {}).items():
            path = prefix + k
            if path not in paths:
                errs.append("helm-values: {} is in values.schema.json but not in values.yaml".format(path))
            walk(path + ".", p)

    walk("", schema)
    return errs


def render_helm_values(page, rows):
    def cell(v):
        if v is None:
            return ""
        if "\n" in v:
            return "<pre><code>{}</code></pre>".format(html.escape(v))
        return "<code>{}</code>".format(html.escape(v))

    def row(r, rel):
        ex = '<pre class="ex"><code>{}</code></pre>'.format(html.escape(r[3])) if r[3] else ""
        return '<tr id="v-{}"><td><code>{}</code></td><td>{}</td><td>{}{}</td></tr>'.format(
            r[0].replace(".", "-"), html.escape(rel), cell(r[1]), _md(r[2]), ex)

    head = '<div class="table-wrap"><table><thead><tr><th>Key</th><th>Default</th><th>Meaning</th></tr></thead><tbody>'
    tops = [r for r in rows if "." not in r[0]]
    out, toc = [], []
    out.append('<section class="cfg helm" id="v-top"><h3><a href="#v-top">Top level</a></h3>' + head)
    out += [row(r, r[0]) for r in tops if r[1] is not None]
    out.append("</tbody></table></div></section>")
    for t in tops:
        if t[1] is not None:
            continue
        toc.append('<a href="#v-{0}"><code>{0}</code></a>'.format(t[0]))
        out.append('<section class="cfg helm" id="v-{0}"><h3><a href="#v-{0}"><code>{0}</code></a></h3>'.format(t[0]))
        if t[2]:
            out.append("<p>{}</p>".format(_md(t[2])))
        inner = [r for r in rows if r[0].startswith(t[0] + ".") and (r[1] is not None or r[2])]
        if inner:
            out.append(head)
            out += [row(r, r[0][len(t[0]) + 1:]) for r in inner]
            out.append("</tbody></table></div>")
        out.append("</section>")
    page = page.replace("<!-- @values-toc -->", " · ".join(toc))
    return page.replace("<!-- @values-reference -->", "\n".join(out))


# REQ: DOC-002/003 (T4.7) — the performance page shows the newest bench-full result in
# site/data/bench/ (harness numbers only) and publishes every result file next to it.
BENCH_DIR = os.path.join(SITE, "data", "bench")


def _us(v):
    return "{:.0f} µs".format(v) if v < 1000 else "{:.1f} ms".format(v / 1000)


def render_bench(page):
    files = sorted(f for f in os.listdir(BENCH_DIR) if f.endswith(".json"))
    if not files:
        sys.exit("site/data/bench has no results")
    name = files[-1]
    d = json.loads(read(os.path.join(BENCH_DIR, name)))
    host, srv, s = d["host"], d["server"], d["summary"]
    raw = "data/bench/" + name
    rev = d["git"]["rev"][:7]
    out = ['<div class="card bench">']
    out.append(
        "<p><b>{cpu}</b> ({cores} threads, {arch}, Linux {kernel}) · {workers} DNS workers · {date} · "
        'commit <a href="https://github.com/paimonsoror/telltaledns/commit/{full}">{rev}</a> · '
        '<a href="{raw}">raw results (JSON)</a></p>'.format(
            cpu=html.escape(host["cpu"]), cores=host["cores"], arch=host["arch"],
            kernel=html.escape(host["kernel"].split("-")[0]), workers=srv["workers"],
            date=d["started"][:10], full=d["git"]["rev"], rev=rev, raw=raw,
        )
    )
    out.append('<div class="table-wrap"><table><thead><tr><th>Corpus</th><th class="num">Peak qps</th>'
               '<th>Load</th><th class="num">Offered qps</th><th class="num">p50</th><th class="num">p99</th>'
               '<th class="num">Loss</th></tr></thead><tbody>')
    for corpus in ("cache-hot", "blocked", "miss-heavy"):
        c = s.get(corpus)
        if not c:
            continue
        loads = c.get("at_load") or {}
        rows = [(pct, l["offered_qps"], l["latency_us"], l["loss_pct"]) for pct, l in sorted(loads.items(), key=lambda x: int(x[0]))]
        if not rows:
            rows = [("fixed", c["qps"], c["latency_us"], c["loss_pct"])]
        for i, (pct, qps, lat, loss) in enumerate(rows):
            out.append(
                "<tr>{head}<td>{load}</td><td class=\"num\">{qps:,.0f}</td><td class=\"num\">{p50}</td>"
                "<td class=\"num\">{p99}</td><td class=\"num\">{loss:.2f}%</td></tr>".format(
                    head='<td rowspan="{n}"><code>{c}</code></td><td class="num" rowspan="{n}">{peak}</td>'.format(
                        n=len(rows), c=corpus, peak="{:,.0f}".format(c["qps"]) if loads else "—")
                    if i == 0 else "",
                    load=(pct + "%") if pct != "fixed" else "fixed rate", qps=qps,
                    p50=_us(lat["p50"]), p99=_us(lat["p99"]), loss=loss,
                )
            )
    out.append("</tbody></table></div>")
    out.append(
        "<p class=\"muted\">Server: ready in {ready:.0f} ms, filter ready in {filt:.1f} s, {idle:.0f} MiB idle and {peak:.0f} MiB peak RSS "
        "with {n} blocklists loaded. {runs} runs of {dur} s per corpus; each number is the median across runs. "
        "Load generator: dnsperf {tool}, {threads} threads, {clients} clients.</p>".format(
            ready=srv["ready_ms"], filt=srv.get("filter_ready_s", 0), idle=srv["idle_rss_kib"] / 1024,
            peak=srv["peak_rss_kib"] / 1024, n=len(srv.get("lists", [])), runs=d["params"]["runs"],
            dur=d["params"]["duration_s"], tool=html.escape(d["tools"]["dnsperf"]),
            threads=d["params"]["threads"], clients=d["params"]["clients"],
        )
    )
    out.append("</div>")
    return page.replace("<!-- @bench -->", "\n".join(out)), files


# REQ: API-011, DOC-006 (T3.11) — the glossary page, from the same file as the UI's "?" panels.
FLOW_TEXT = {
    "cache": "answered from memory",
    "local": "answered with your own names",
    "blocked": "blocked",
    "route": "sent to the server you chose for that domain",
    "upstream": "sent to a public DNS server",
    "refused": "refused",
}


def render_glossary(page):
    data = json.loads(read(os.path.join(ROOT, "docs", "help", "topics.json")))
    out = []
    for t in sorted(data["topics"], key=lambda t: t["title"].lower()):
        docs = (
            ' <a href="https://github.com/paimonsoror/telltaledns/blob/main/docs/running.md#{}">Docs</a>'.format(t["docs"])
            if t.get("docs") else ""
        )
        path = ' <span class="pill supported">{}</span>'.format(FLOW_TEXT[t["diagram"]]) if t.get("diagram") else ""
        out.append(
            '<article class="card term" id="{id}"><h3><a href="#{id}">{title}</a>{path}</h3>'
            '<p class="muted small">{term}</p><p>{summary}</p>'
            "<p><b>When:</b> {when}</p><p><b>Example:</b> {example}</p><p><b>Careful:</b> {caution}{docs}</p></article>".format(
                id=html.escape(t["id"]), title=html.escape(t["title"]), term=html.escape(t["term"]),
                summary=html.escape(t["summary"]), when=html.escape(t["when"]), example=html.escape(t["example"]),
                caution=html.escape(t["caution"]), docs=docs, path=path,
            )
        )
    return page.replace("<!-- @glossary -->", "\n".join(out))


# REQ: DOC-004, DOC-006 (T6.10) — the "For nerds" page: an interactive architecture view built
# from site/data/architecture.json and checked against the repo, so it can't drift. Arrows,
# "used by", line counts and dependency users come from the code, not from the JSON.
GH = "https://github.com/paimonsoror/telltaledns/blob/main/"
GH_TREE = "https://github.com/paimonsoror/telltaledns/tree/main/"


def cargo_deps(path):
    """Normal dependency names in one Cargo.toml (not dev- or build-dependencies)."""
    deps, on = set(), False
    for line in read(path).splitlines():
        s = line.strip()
        if s.startswith("["):
            h = s.strip("[]").strip()
            on = h == "dependencies" or (h.startswith("target.") and h.endswith(".dependencies")) or h == "workspace.dependencies"
            continue
        m = re.match(r"^([A-Za-z0-9_-]+)\s*(=|\.)", s)
        if on and m:
            deps.add(m.group(1))
    return deps


def gh_anchor(heading):
    """GitHub's heading anchor: lower case, punctuation dropped, spaces to hyphens."""
    return re.sub(r"[^a-z0-9 _-]", "", heading.lower()).replace(" ", "-")


def repo_ids():
    adrs = {}
    for line in read(os.path.join(ROOT, "spec", "11-decisions.md")).splitlines():
        m = re.match(r"^## (ADR-\d{3})\b(.*)$", line)
        if m:
            adrs[m.group(1)] = (line[3:].strip(), gh_anchor(line[3:].strip()))
    # Requirement rows: spec/01, plus the agent requirements (AGT) defined in spec/13 §2.
    reqs = {}
    for spec in ("01-requirements.md", "13-agent-api-and-mcp.md"):
        for line in read(os.path.join(ROOT, "spec", spec)).splitlines():
            m = re.match(r"\|\s*([A-Z]{3}-\d{3})\s*\|\s*(P\d)\s*\|\s*(.*?)\s*\|\s*$", line)
            if m:
                reqs[m.group(1)] = (m.group(3), spec)
    return adrs, reqs


def rust_stats(src):
    files, lines = 0, 0
    for d, _, names in os.walk(src):
        for n in names:
            if n.endswith(".rs"):
                files += 1
                with open(os.path.join(d, n), encoding="utf-8") as f:
                    lines += sum(1 for _ in f)
    return files, lines


def public_types(src):
    names = set()
    for d, _, files in os.walk(src):
        for n in files:
            if n.endswith(".rs"):
                names |= set(re.findall(r"pub(?:\([a-z]+\))?\s+(?:struct|enum|trait|type)\s+([A-Z][A-Za-z0-9_]*)", read(os.path.join(d, n))))
    return names


def nerds_errors(arch, adrs, reqs):
    errors = []
    dirs = {d for d in os.listdir(os.path.join(ROOT, "crates")) if os.path.isfile(os.path.join(ROOT, "crates", d, "Cargo.toml"))}
    listed = set(arch["crates"])
    errors += ["architecture.json: crate {} is in crates/ but not described".format(c) for c in sorted(dirs - listed)]
    errors += ["architecture.json: crate {} is described but not in crates/".format(c) for c in sorted(listed - dirs)]
    layers = {l["id"] for l in arch["layers"]}
    all_deps = cargo_deps(os.path.join(ROOT, "Cargo.toml"))
    for c in dirs:
        all_deps |= cargo_deps(os.path.join(ROOT, "crates", c, "Cargo.toml"))

    def ids(where, item):
        for a in item.get("adrs", []):
            if a not in adrs:
                errors.append("architecture.json: {} cites {}, which spec/11 doesn't have".format(where, a))
        for r in item.get("reqs", []):
            if r not in reqs:
                errors.append("architecture.json: {} cites {}, which spec/01 doesn't have".format(where, r))
        code = item.get("code")
        if code and not os.path.exists(os.path.join(ROOT, code)):
            errors.append("architecture.json: {} points at {}, which doesn't exist".format(where, code))

    for name, c in arch["crates"].items():
        ids(name, c)
        if c["layer"] not in layers:
            errors.append("architecture.json: {} has unknown layer {}".format(name, c["layer"]))
        if name in dirs and c.get("types"):
            have = public_types(os.path.join(ROOT, "crates", name, "src"))
            errors += ["architecture.json: {} lists type {}, which the crate doesn't define".format(name, t) for t in c["types"] if t not in have]
    for p in arch["pipeline"]:
        ids("pipeline " + p["id"], p)
        if p["crate"] not in arch["crates"]:
            errors.append("architecture.json: pipeline {} names unknown crate {}".format(p["id"], p["crate"]))
    for sec in ("cluster", "agents", "formats"):
        for item in arch[sec]:
            ids("{} {}".format(sec, item.get("title") or item.get("name")), item)
    for g in arch["stack"]:
        for it in g["items"]:
            if it.get("crate") and it["crate"] not in all_deps:
                errors.append("architecture.json: stack entry {} names crate {}, which no Cargo.toml depends on".format(it["name"], it["crate"]))
    return errors


def _chips(item, adrs, reqs):
    out = []
    for a in item.get("adrs", []):
        title, anchor = adrs.get(a, (a, ""))
        out.append('<a class="chip adr" href="{}spec/11-decisions.md#{}" title="{}">{}</a>'.format(GH, anchor, html.escape(title), a))
    for r in item.get("reqs", []):
        text, spec = reqs.get(r, ("", "01-requirements.md"))
        title = re.sub(r"\*\*|`", "", text)
        out.append('<a class="chip req" href="{}spec/{}" title="{}">{}</a>'.format(GH, spec, html.escape(title[:240]), r))
    return '<p class="chips">{}</p>'.format(" ".join(out)) if out else ""


def render_nerds(page, arch, adrs, reqs):
    crates = arch["crates"]
    ws = {}
    for name in crates:
        deps = cargo_deps(os.path.join(ROOT, "crates", name, "Cargo.toml"))
        ws[name] = sorted(d for d in deps if d in crates and d != name)
    users = {n: sorted(m for m in crates if n in ws[m]) for n in crates}

    # The diagram: one row per layer, crates spread evenly; arrows from a crate to what it uses.
    W, top, row_h, box_h = 1000, 10, 124, 66
    pos, labels, y = {}, [], top
    for layer in arch["layers"]:
        names = [n for n, c in crates.items() if c["layer"] == layer["id"]]
        if not names:
            continue
        labels.append('<text x="20" y="{}" class="arch-layer">{}</text>'.format(y + 12, html.escape(layer["title"])))
        n = len(names)
        bw = min(170.0, (W - 40 - (n - 1) * 14) / n) if layer["id"] != "bin" else W - 40
        total = n * bw + (n - 1) * 14
        x0 = (W - total) / 2
        for i, name in enumerate(names):
            pos[name] = (x0 + i * (bw + 14), y + 22, bw)
        y += row_h
    height = y - row_h + 22 + box_h + 16
    edges = []
    for a in crates:
        if a == "telltale":
            continue  # the binary uses nearly everything; listed in its panel instead
        for b in ws[a]:
            ax, ay, aw = pos[a]
            bx, by, bw = pos[b]
            x1, x2 = ax + aw / 2, bx + bw / 2
            if abs(ay - by) < 1:  # same row: an arc above
                y1 = ay
                d = "M{:.0f} {:.0f} C{:.0f} {:.0f} {:.0f} {:.0f} {:.0f} {:.0f}".format(x1, y1, x1, y1 - 34, x2, y1 - 34, x2, y1)
            elif ay > by:  # uses something above
                y1, y2 = ay, by + box_h
                d = "M{:.0f} {:.0f} C{:.0f} {:.0f} {:.0f} {:.0f} {:.0f} {:.0f}".format(x1, y1, x1, y1 - 40, x2, y2 + 40, x2, y2)
            else:
                y1, y2 = ay + box_h, by
                d = "M{:.0f} {:.0f} C{:.0f} {:.0f} {:.0f} {:.0f} {:.0f} {:.0f}".format(x1, y1, x1, y1 + 40, x2, y2 - 40, x2, y2)
            edges.append('<path class="arch-edge" data-from="{}" data-to="{}" d="{}" marker-end="url(#arch-arrow)"/>'.format(a, b, d))
    nodes = []
    for name, (x, yy, bw) in pos.items():
        c = crates[name]
        files, lines = rust_stats(os.path.join(ROOT, "crates", name, "src"))
        short = name.replace("telltale-", "") if name != "telltale" else "telltale (binary)"
        nodes.append(
            '<a class="arch-node layer-{layer}" href="#crate-{n}" data-crate="{n}">'
            '<rect x="{x:.0f}" y="{y}" width="{w:.0f}" height="{h}" rx="12"/>'
            # The trailing space keeps "net 2,391 lines" readable as one accessible text.
            '<text x="{cx:.0f}" y="{ty}" text-anchor="middle" class="arch-name">{short} </text>'
            '<text x="{cx:.0f}" y="{ty2}" text-anchor="middle" class="arch-meta">{lines:,} lines</text></a>'.format(
                layer=c["layer"], n=name, sum=html.escape(c["summary"]), x=x, y=yy, w=bw, h=box_h, cx=x + bw / 2,
                ty=yy + 29, ty2=yy + 51, short=html.escape(short), lines=lines,
            )
        )
    svg = (
        '<svg class="arch" viewBox="0 0 {W} {H:.0f}" role="group" aria-label="Crates and how they depend on each other">'
        '<defs><marker id="arch-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">'
        '<path d="M0 0 L10 5 L0 10 z" class="arch-arrowhead"/></marker></defs>'
        "{edges}{labels}{nodes}</svg>"
    ).format(W=W, H=height, labels="".join(labels), edges="".join(edges), nodes="".join(nodes))

    def link(n):
        return '<a href="#crate-{0}"><code>{0}</code></a>'.format(n)

    details = []
    for name, c in crates.items():
        files, lines = rust_stats(os.path.join(ROOT, "crates", name, "src"))
        layer = next(l["title"] for l in arch["layers"] if l["id"] == c["layer"])
        ext = sorted(d for d in cargo_deps(os.path.join(ROOT, "crates", name, "Cargo.toml")) if d not in crates)
        rows = []
        if c.get("types"):
            rows.append("<dt>Main types</dt><dd>{}</dd>".format(" ".join("<code>{}</code>".format(html.escape(t)) for t in c["types"])))
        if c.get("budget"):
            rows.append("<dt>Budget</dt><dd>{}</dd>".format(html.escape(c["budget"])))
        rows.append("<dt>Uses</dt><dd>{}</dd>".format(", ".join(link(d) for d in ws[name]) or "no other TelltaleDNS crate"))
        rows.append("<dt>Used by</dt><dd>{}</dd>".format(", ".join(link(d) for d in users[name]) or "nothing (it's the top)"))
        rows.append("<dt>Libraries</dt><dd>{}</dd>".format(", ".join("<code>{}</code>".format(html.escape(d)) for d in ext) or "none"))
        rows.append('<dt>Code</dt><dd><a href="{}{}">{}</a>: {:,} lines of Rust in {} files</dd>'.format(GH_TREE, c["code"], html.escape(c["code"]), lines, files))
        details.append(
            '<article class="card arch-detail" id="crate-{n}"><h3><code>{n}</code> <span class="pill layer">{layer}</span></h3>'
            "<p><b>{sum}</b></p><p>{detail}</p><dl>{rows}</dl>{chips}</article>".format(
                n=name, layer=html.escape(layer), sum=html.escape(c["summary"]), detail=html.escape(c["detail"]),
                rows="".join(rows), chips=_chips(c, adrs, reqs),
            )
        )

    pipe = []
    for i, p in enumerate(arch["pipeline"], 1):
        pipe.append(
            '<li><details><summary><span class="step-n">{i}</span> {title} <span class="muted small">{crate}</span></summary>'
            "<p>{sum}</p>{chips}</details></li>".format(
                i=i, title=html.escape(p["title"]), crate=html.escape(p["crate"]), sum=html.escape(p["summary"]), chips=_chips(p, adrs, reqs)
            )
        )

    def cards(items, key="title"):
        out = []
        for it in items:
            code = ' <a class="small" href="{}{}">code</a>'.format(GH, it["code"]) if it.get("code") else ""
            out.append('<article class="card"><h3>{}</h3><p>{}{}</p>{}</article>'.format(
                html.escape(it[key]), html.escape(it["summary"]), code, _chips(it, adrs, reqs)))
        return "\n".join(out)

    # The tech stack as one card per area: each library with why it's there, and (for Rust
    # crates) small chips naming the TelltaleDNS crates that use it, from Cargo.toml.
    stack = []
    for g in arch["stack"]:
        items = []
        for it in g["items"]:
            where = ""
            if it.get("crate"):
                used = sorted(n for n in crates if it["crate"] in cargo_deps(os.path.join(ROOT, "crates", n, "Cargo.toml")))
                where = '<p class="used">used in {}</p>'.format(" ".join(
                    '<a class="chip crate" href="#crate-{}">{}</a>'.format(u, html.escape(u.replace("telltale-", "") if u != "telltale" else "binary"))
                    for u in used))
            items.append("<li><b>{}</b><p>{}</p>{}</li>".format(html.escape(it["name"]), html.escape(it["why"]), where))
        stack.append('<article class="card stack-card"><h3>{}</h3><ul class="stack-list">{}</ul></article>'.format(
            html.escape(g["group"]), "".join(items)))
    stack = ['<div class="stack-grid">'] + stack + ["</div>"]

    # The release gates, straight from spec/00 §5.
    gates = []
    in5 = False
    for line in read(os.path.join(ROOT, "spec", "00-overview.md")).splitlines():
        if line.startswith("## 5."):
            in5 = True
            continue
        if in5 and line.startswith("## "):
            break
        m = re.match(r"^\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*$", line)
        if in5 and m and m.group(1) not in ("Metric",) and not set(m.group(1)) <= set("-: "):
            gates.append("<tr><td>{}</td><td>{}</td></tr>".format(html.escape(m.group(1)), html.escape(m.group(2))))
    if not gates:
        sys.exit("spec/00 §5 has no metrics table")

    total_files, total_lines = 0, 0
    for name in crates:
        f, l = rust_stats(os.path.join(ROOT, "crates", name, "src"))
        total_files, total_lines = total_files + f, total_lines + l
    page = page.replace("<!-- @arch-stats -->", "{} crates · {:,} lines of Rust in {} files · {} decisions recorded (ADRs)".format(
        len(crates), total_lines, total_files, len(adrs)))
    page = page.replace("<!-- @arch-diagram -->", svg)
    page = page.replace("<!-- @arch-details -->", "\n".join(details))
    page = page.replace("<!-- @arch-pipeline -->", "\n".join(pipe))
    page = page.replace("<!-- @arch-cluster -->", cards(arch["cluster"]))
    page = page.replace("<!-- @arch-agents -->", cards(arch["agents"]))
    page = page.replace("<!-- @arch-stack -->", "\n".join(stack))
    page = page.replace("<!-- @arch-formats -->", cards(arch["formats"], "name"))
    page = page.replace("<!-- @arch-gates -->", "\n".join(gates))
    return page


def expand_ids(text):
    """'UPS-001, 005, 006' -> {'UPS-001','UPS-005','UPS-006'}"""
    ids = set()
    for m in re.finditer(r"([A-Z]{3})-(\d{3})((?:\s*,\s*\d{3})*)", text):
        prefix = m.group(1)
        ids.add("{}-{}".format(prefix, m.group(2)))
        for extra in re.findall(r"\d{3}", m.group(3)):
            ids.add("{}-{}".format(prefix, extra))
    return ids


def rfcs_in(text):
    out = set()
    for m in re.finditer(r"RFC\s*(\d{4})(?:\s*[–-]\s*(\d{4}))?", text):
        lo = int(m.group(1))
        hi = int(m.group(2)) if m.group(2) else lo
        if hi - lo <= 10:
            out.update(str(n) for n in range(lo, hi + 1))
    return out


def coverage_errors(data):
    """DOC-004: every RFC cited by a requirement of a ticked task must be listed."""
    roadmap = read(os.path.join(ROOT, "spec", "10-roadmap-and-tasks.md"))
    reqs_md = read(os.path.join(ROOT, "spec", "01-requirements.md"))
    ticked = set()
    for line in roadmap.splitlines():
        if line.startswith("- [x]"):
            # Only the requirement list in *( … )*, not IDs mentioned in notes.
            for group in re.findall(r"\*\(([^)]*)\)\*", line):
                ticked |= expand_ids(group)
    row_rfcs = {}
    for line in reqs_md.splitlines():
        m = re.match(r"\|\s*([A-Z]{3}-\d{3})\s*\|", line)
        if m:
            row_rfcs[m.group(1)] = rfcs_in(line)
    listed = set()
    for s in data["standards"]:
        listed |= rfcs_in("RFC " + s["rfc"] + " " + s["title"])
    errors = []
    for req in sorted(ticked):
        for rfc in sorted(row_rfcs.get(req, ())):
            if rfc not in listed:
                errors.append("{} (ticked) cites RFC {} but site/data/standards.json does not list it".format(req, rfc))
    return errors


def link_errors(out_dir):
    errors = []
    for name in PAGES:
        text = read(os.path.join(out_dir, name))
        for ref in re.findall(r'(?:href|src)="([^"#]+)"', text):
            if re.match(r"^(https?:|mailto:)", ref):
                continue
            if not os.path.exists(os.path.join(out_dir, ref)):
                errors.append("{}: broken link {}".format(name, ref))
    return errors


def main():
    check_only = "--check" in sys.argv
    out = tempfile.mkdtemp() if check_only else os.path.join(SITE, "_site")
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out)
    shutil.copytree(os.path.join(SITE, "assets"), os.path.join(out, "assets"))
    header = read(os.path.join(SITE, "partials", "header.html"))
    footer = read(os.path.join(SITE, "partials", "footer.html")).replace("@@BUILD@@", build_stamp())
    data = json.loads(read(os.path.join(SITE, "data", "standards.json")))
    for s in data["standards"]:
        if s["status"] not in STATUS_ORDER:
            sys.exit("standards.json: bad status {!r} for RFC {}".format(s["status"], s["rfc"]))
    arch = json.loads(read(os.path.join(SITE, "data", "architecture.json")))
    adrs, reqs = repo_ids()
    values_rows = parse_values(read(HELM_VALUES))
    for name in PAGES:
        page = read(os.path.join(SITE, name))
        slug = name[:-5]
        h = header.replace('data-page="{}"'.format(slug), 'data-page="{}" aria-current="page"'.format(slug))
        # A page inside the Reference menu marks the menu as current too.
        h = re.sub(r'<details class="sub" data-group="([^"]*)">',
                   lambda m: '<details class="sub{}">'.format(" current" if slug in m.group(1).split() else ""), h)
        page = page.replace("<!-- @header -->", h).replace("<!-- @footer -->", footer)
        if name == "config.html":
            page = render_config(page, json.loads(read(os.path.join(ROOT, "docs", "config-schema.json"))))
        if name == "helm-values.html":
            page = render_helm_values(page, values_rows)
        if name == "glossary.html":
            page = render_glossary(page)
        if name == "performance.html":
            page, bench_files = render_bench(page)
            os.makedirs(os.path.join(out, "data", "bench"), exist_ok=True)
            for bf in bench_files:
                shutil.copy(os.path.join(BENCH_DIR, bf), os.path.join(out, "data", "bench", bf))
        if name == "standards.html":
            page = render_standards(page, data)
        if name == "nerds.html":
            page = render_nerds(page, arch, adrs, reqs)
        if "<!-- @" in page:
            sys.exit("{}: unreplaced marker".format(name))
        with open(os.path.join(out, name), "w", encoding="utf-8") as f:
            f.write(page)
    with open(os.path.join(out, ".nojekyll"), "w") as f:
        f.write("")
    errors = coverage_errors(data) + nerds_errors(arch, adrs, reqs) + helm_values_errors(values_rows) + link_errors(out)
    for e in errors:
        print("error: " + e, file=sys.stderr)
    if errors:
        sys.exit(1)
    sizes = {n: os.path.getsize(os.path.join(out, n)) for n in PAGES}
    for n, sz in sizes.items():
        if sz > 500 * 1024:
            sys.exit("{} is {} KiB (> 500 KiB page budget, DOC-005)".format(n, sz // 1024))
    print("site OK: " + ", ".join("{} {:.1f} KiB".format(n, sz / 1024) for n, sz in sizes.items()))
    if not check_only:
        print("built into " + out)


if __name__ == "__main__":
    main()
