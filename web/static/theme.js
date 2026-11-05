// Theme: auto (system), light or dark; stored per browser. Loaded in <head>
// so the page never flashes in the wrong theme.
(function () {
  var key = "vwitch-theme", root = document.documentElement, next = { auto: "light", light: "dark", dark: "auto" };
  function get() { try { return localStorage.getItem(key) || "auto"; } catch (e) { return "auto"; } }
  function apply(t) {
    if (t === "auto") delete root.dataset.theme; else root.dataset.theme = t;
    document.querySelectorAll("[data-theme-toggle]").forEach(function (b) {
      var label = b.getAttribute("data-label-" + t);
      b.dataset.state = t; b.title = label; b.setAttribute("aria-label", label);
    });
  }
  apply(get());
  document.addEventListener("DOMContentLoaded", function () { apply(get()); });
  document.addEventListener("htmx:afterSettle", function () { apply(get()); });
  document.addEventListener("click", function (e) {
    if (!e.target.closest("[data-theme-toggle]")) return;
    var t = next[get()];
    try { localStorage.setItem(key, t); } catch (err) { /* private mode: not remembered */ }
    apply(t);
  });
})();
