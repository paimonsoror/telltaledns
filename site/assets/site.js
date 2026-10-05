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
      show(0);
    });
  });
})();
