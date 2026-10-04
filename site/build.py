#!/usr/bin/env python3
"""Builds the TelltaleDNS project site into site/_site (ADR-012, DOC-001/004/005).

No dependencies beyond the Python standard library (3.6+). It:
  1. injects the shared header/footer partials into every page,
  2. renders the Standards table and cards from site/data/standards.json,
  3. fails if a ticked roadmap task cites a requirement whose RFCs are missing from that file,
  4. checks that every internal link and asset reference resolves.

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
PAGES = ["index.html", "start.html", "install.html", "how-it-works.html", "config.html", "standards.html"]
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
    for name in PAGES:
        page = read(os.path.join(SITE, name))
        slug = name[:-5]
        h = header.replace('data-page="{}"'.format(slug), 'data-page="{}" aria-current="page"'.format(slug))
        page = page.replace("<!-- @header -->", h).replace("<!-- @footer -->", footer)
        if name == "config.html":
            page = render_config(page, json.loads(read(os.path.join(ROOT, "docs", "config-schema.json"))))
        if name == "standards.html":
            page = render_standards(page, data)
        if "<!-- @" in page:
            sys.exit("{}: unreplaced marker".format(name))
        with open(os.path.join(out, name), "w", encoding="utf-8") as f:
            f.write(page)
    with open(os.path.join(out, ".nojekyll"), "w") as f:
        f.write("")
    errors = coverage_errors(data) + link_errors(out)
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
