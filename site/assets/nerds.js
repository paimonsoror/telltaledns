// T6.10 (DOC-004): the architecture map. Without JavaScript every crate is a link to its
// description further down; with it, selecting a crate opens the description beside the map
// and highlights what it uses and what uses it.
(function () {
  var svg = document.querySelector("svg.arch");
  var panel = document.getElementById("arch-panel");
  if (!svg || !panel) return;
  var body = panel.querySelector(".arch-panel-body");
  var nodes = svg.querySelectorAll(".arch-node");
  var edges = svg.querySelectorAll(".arch-edge");
  var current = null;

  function mark(name, cls) {
    for (var i = 0; i < edges.length; i++) {
      var e = edges[i];
      var on = name && (e.getAttribute("data-from") === name || e.getAttribute("data-to") === name);
      e.classList.toggle(cls, !!on);
    }
    for (var j = 0; j < nodes.length; j++) {
      var n = nodes[j], c = n.getAttribute("data-crate");
      var linked = false;
      if (name) {
        for (var k = 0; k < edges.length; k++) {
          var ed = edges[k];
          if ((ed.getAttribute("data-from") === name && ed.getAttribute("data-to") === c) ||
              (ed.getAttribute("data-to") === name && ed.getAttribute("data-from") === c)) linked = true;
        }
      }
      n.classList.toggle(cls + "-node", c === name);
      n.classList.toggle(cls + "-linked", linked);
    }
    svg.classList.toggle("has-" + cls, !!name);
  }

  function open(name, focusPanel) {
    var src = document.getElementById("crate-" + name);
    if (!src) return;
    current = name;
    body.innerHTML = src.innerHTML;
    panel.hidden = false;
    mark(name, "sel");
    if (history.replaceState) history.replaceState(null, "", "#crate-" + name);
    if (focusPanel) panel.querySelector(".arch-close").focus();
  }

  function close() {
    var was = current;
    current = null;
    panel.hidden = true;
    mark(null, "sel");
    if (history.replaceState) history.replaceState(null, "", "#map");
    if (was) {
      var n = svg.querySelector('[data-crate="' + was + '"]');
      if (n) n.focus();
    }
  }

  for (var i = 0; i < nodes.length; i++) {
    (function (n) {
      var name = n.getAttribute("data-crate");
      n.addEventListener("click", function (ev) {
        if (ev.metaKey || ev.ctrlKey || ev.shiftKey) return;
        ev.preventDefault();
        open(name, ev.detail === 0); // keyboard activation moves focus into the panel
      });
      n.addEventListener("mouseenter", function () { mark(name, "hov"); });
      n.addEventListener("mouseleave", function () { mark(null, "hov"); });
      n.addEventListener("focus", function () { mark(name, "hov"); });
      n.addEventListener("blur", function () { mark(null, "hov"); });
    })(nodes[i]);
  }
  panel.querySelector(".arch-close").addEventListener("click", close);
  document.addEventListener("keydown", function (ev) {
    if (ev.key === "Escape" && current) close();
  });
  // Links inside the panel to other crates open them in the panel too.
  body.addEventListener("click", function (ev) {
    var a = ev.target.closest && ev.target.closest('a[href^="#crate-"]');
    if (!a) return;
    ev.preventDefault();
    open(a.getAttribute("href").slice(7), false);
  });
  var m = /^#crate-([a-z-]+)$/.exec(location.hash);
  if (m) open(m[1], false);
})();
