// Optional enhancements only (ADR-012): every page works without this file.
(function () {
  var root = document.documentElement;
  try {
    var saved = localStorage.getItem("tt-theme");
    if (saved) root.setAttribute("data-theme", saved);
  } catch (e) {}

  document.addEventListener("DOMContentLoaded", function () {
    // Theme toggle
    var btn = document.querySelector(".theme");
    if (btn) {
      btn.hidden = false;
      btn.addEventListener("click", function () {
        var dark = root.getAttribute("data-theme") === "dark" ||
          (!root.getAttribute("data-theme") && matchMedia("(prefers-color-scheme: dark)").matches);
        var next = dark ? "light" : "dark";
        root.setAttribute("data-theme", next);
        try { localStorage.setItem("tt-theme", next); } catch (e) {}
      });
    }
    // T6.10 — the header menu ships open (desktop shows it inline). On narrow screens it
    // starts closed behind ☰; the Reference menu closes on Escape or a click elsewhere.
    var menu = document.querySelector(".top .menu");
    if (menu) {
      var narrow = matchMedia("(max-width: 860px)");
      var fit = function () { menu.open = !narrow.matches; };
      fit();
      if (narrow.addEventListener) narrow.addEventListener("change", fit);
    }
    var sub = document.querySelector(".top .sub");
    if (sub) {
      document.addEventListener("click", function (e) { if (sub.open && !sub.contains(e.target)) sub.open = false; });
      document.addEventListener("keydown", function (e) {
        if (e.key === "Escape" && sub.open) { sub.open = false; sub.querySelector("summary").focus(); }
      });
    }
    // A filter box over table rows (Helm values): rows that don't match, and sections left
    // empty, are hidden. Without JS the box stays hidden and every row shows.
    document.querySelectorAll("input[data-filter]").forEach(function (input) {
      var rows = document.querySelectorAll(input.getAttribute("data-filter"));
      input.closest(".filter").hidden = false;
      input.addEventListener("input", function () {
        var q = input.value.trim().toLowerCase();
        rows.forEach(function (r) { r.hidden = q !== "" && r.textContent.toLowerCase().indexOf(q) < 0; });
        document.querySelectorAll(".reference .cfg").forEach(function (s) {
          var head = s.querySelector("h3").textContent.toLowerCase();
          var any = s.querySelectorAll("tbody tr:not([hidden])").length > 0;
          s.hidden = q !== "" && !any && head.indexOf(q) < 0;
        });
      });
    });
    // Tabs: without JS every panel is visible, stacked under its own heading.
    document.querySelectorAll(".tabs").forEach(function (box) {
      box.classList.add("js");
      var tabs = box.querySelectorAll('[role="tab"]');
      var panels = box.querySelectorAll(".panel");
      function show(i) {
        tabs.forEach(function (t, j) { t.setAttribute("aria-selected", String(i === j)); t.tabIndex = i === j ? 0 : -1; });
        panels.forEach(function (p, j) { p.hidden = i !== j; });
      }
      tabs.forEach(function (t, i) {
        t.addEventListener("click", function () { show(i); });
        t.addEventListener("keydown", function (e) {
          if (e.key === "ArrowRight") { show((i + 1) % tabs.length); tabs[(i + 1) % tabs.length].focus(); }
          if (e.key === "ArrowLeft") { show((i - 1 + tabs.length) % tabs.length); tabs[(i - 1 + tabs.length) % tabs.length].focus(); }
        });
      });
      // A link to a panel (start.html#k8s) opens that tab.
      function fromHash() {
        var id = location.hash.slice(1);
        var i = -1;
        panels.forEach(function (p, j) { if (id && (p.id === id || p.querySelector("#" + CSS.escape(id)))) i = j; });
        if (i >= 0) show(i);
        return i >= 0;
      }
      if (!fromHash()) show(0);
      window.addEventListener("hashchange", fromHash);
    });
  });
})();
