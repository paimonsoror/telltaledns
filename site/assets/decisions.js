// REQ: DOC-006 — the decisions explorer. Without JavaScript every ADR is a <details> that
// opens on its own and links work as anchors; with it: search, status and area filters,
// order, expand all, and #adr-NNN opens (and scrolls to) that record.
(function () {
  var list = document.getElementById("adr-list");
  var tools = document.querySelector(".adr-tools");
  if (!list || !tools) return;
  var items = Array.prototype.slice.call(list.querySelectorAll("details.adr"));
  var q = document.getElementById("adr-q");
  var area = document.getElementById("adr-area");
  var sort = document.getElementById("adr-sort");
  var statusBox = document.getElementById("adr-status");
  var count = document.getElementById("adr-count");
  var empty = document.getElementById("adr-empty");
  var expand = document.getElementById("adr-expand");
  var status = "";
  var text = items.map(function (d) { return d.textContent.toLowerCase(); });

  // Status buttons and area options from the records themselves.
  var statuses = {}, areas = {};
  items.forEach(function (d) {
    var s = d.getAttribute("data-status");
    statuses[s] = (statuses[s] || 0) + 1;
    (d.getAttribute("data-areas") || "").split(" ").forEach(function (a) {
      if (a) areas[a] = d.querySelector('[data-area="' + a + '"]') ? d.querySelector('[data-area="' + a + '"]').getAttribute("title") : a;
    });
  });
  function button(value, label) {
    var b = document.createElement("button");
    b.type = "button";
    b.textContent = label;
    b.setAttribute("aria-pressed", value === status ? "true" : "false");
    b.addEventListener("click", function () {
      status = value;
      Array.prototype.forEach.call(statusBox.children, function (x) { x.setAttribute("aria-pressed", "false"); });
      b.setAttribute("aria-pressed", "true");
      apply();
    });
    statusBox.appendChild(b);
  }
  button("", "All " + items.length);
  Object.keys(statuses).sort().forEach(function (s) {
    button(s, s.charAt(0).toUpperCase() + s.slice(1) + " " + statuses[s]);
  });
  Object.keys(areas).sort().forEach(function (a) {
    var o = document.createElement("option");
    o.value = a;
    o.textContent = a + " — " + areas[a];
    area.appendChild(o);
  });

  function apply() {
    var words = q.value.toLowerCase().split(/\s+/).filter(Boolean);
    var shown = 0;
    items.forEach(function (d, i) {
      var ok = (!status || d.getAttribute("data-status") === status) &&
        (!area.value || (" " + d.getAttribute("data-areas") + " ").indexOf(" " + area.value + " ") >= 0) &&
        words.every(function (w) { return text[i].indexOf(w) >= 0; });
      d.hidden = !ok;
      if (ok) shown++;
    });
    count.textContent = shown === items.length ? items.length + " decisions" : "Showing " + shown + " of " + items.length;
    empty.hidden = shown > 0;
  }
  function order() {
    var dir = sort.value === "asc" ? 1 : -1;
    items.slice().sort(function (a, b) {
      return dir * (Number(a.getAttribute("data-num")) - Number(b.getAttribute("data-num")));
    }).forEach(function (d) { list.appendChild(d); });
  }
  function openHash() {
    var m = /^#(adr-\d{3})$/.exec(location.hash);
    if (!m) return;
    var d = document.getElementById(m[1]);
    if (!d) return;
    if (d.hidden) {
      // A link to a filtered-out record shows everything again.
      q.value = ""; area.value = ""; status = "";
      Array.prototype.forEach.call(statusBox.children, function (x, i) { x.setAttribute("aria-pressed", i === 0 ? "true" : "false"); });
      apply();
    }
    d.open = true;
    d.scrollIntoView({ block: "start" });
  }

  q.addEventListener("input", apply);
  area.addEventListener("change", apply);
  sort.addEventListener("change", order);
  expand.addEventListener("click", function () {
    var open = expand.textContent === "Expand all";
    items.forEach(function (d) { if (!d.hidden) d.open = open; });
    expand.textContent = open ? "Collapse all" : "Expand all";
  });
  window.addEventListener("hashchange", openHash);
  tools.hidden = false;
  order();
  apply();
  openHash();
})();
