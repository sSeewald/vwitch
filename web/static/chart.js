// Traffic charts from /traffic?range=&client=, drawn as SVG without a
// library. [data-chart] is the full chart (axes, tabs, readout); with
// [data-mini] it is a sparkline. Points are averaged down to the width and
// drawn as smooth curves: download as a filled area, upload as a line.
// Blocked lookups and connections are red bars along the bottom.
(function () {
  var NS = "http://www.w3.org/2000/svg", uid = 0;

  function el(name, attrs) {
    var e = document.createElementNS(NS, name);
    for (var k in attrs) e.setAttribute(k, attrs[k]);
    return e;
  }
  function bits(v) {
    var u = ["bit/s", "kbit/s", "Mbit/s", "Gbit/s"], i = 0;
    while (v >= 1000 && i < u.length - 1) { v /= 1000; i++; }
    return (v >= 10 || i === 0 ? v.toFixed(0) : v.toFixed(1)) + " " + u[i];
  }
  // a round upper bound: 1, 2 or 5 times a power of ten
  function niceMax(v) {
    if (v <= 0) return 1000;
    var p = Math.pow(10, Math.floor(Math.log10(v))), f = v / p;
    return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * p;
  }
  function when(t, span) {
    var d = new Date(t * 1000), hm = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    if (span <= 86400) return hm;
    var day = d.toLocaleDateString([], { day: "2-digit", month: "2-digit" });
    return span <= 7 * 86400 ? day + " " + hm : day;
  }
  // average groups of points so there are at most max of them
  function reduce(pts, step, max) {
    var g = Math.max(1, Math.ceil(pts.length / max)), out = [];
    for (var i = 0; i < pts.length; i += g) {
      var d = 0, u = 0, b = 0, n = 0;
      for (var j = i; j < Math.min(i + g, pts.length); j++, n++) { d += pts[j][1]; u += pts[j][2]; b += pts[j][3] || 0; }
      out.push({ t: pts[i][0], down: d * 8 / (n * step), up: u * 8 / (n * step), blocks: b });
    }
    return out;
  }
  // monotone cubic curve through the points (no overshoot below zero)
  function curve(xs, ys) {
    var n = xs.length, m = [], d = [], p = "M" + xs[0].toFixed(1) + " " + ys[0].toFixed(1);
    if (n < 3) return p + xs.slice(1).map(function (x, i) { return "L" + x.toFixed(1) + " " + ys[i + 1].toFixed(1); }).join("");
    for (var i = 0; i < n - 1; i++) d.push((ys[i + 1] - ys[i]) / (xs[i + 1] - xs[i]));
    m.push(d[0]);
    for (i = 1; i < n - 1; i++) m.push(d[i - 1] * d[i] <= 0 ? 0 : 2 / (1 / d[i - 1] + 1 / d[i]));
    m.push(d[n - 2]);
    for (i = 0; i < n - 1; i++) {
      var h = (xs[i + 1] - xs[i]) / 3;
      p += "C" + (xs[i] + h).toFixed(1) + " " + (ys[i] + m[i] * h).toFixed(1) + " " +
        (xs[i + 1] - h).toFixed(1) + " " + (ys[i + 1] - m[i + 1] * h).toFixed(1) + " " +
        xs[i + 1].toFixed(1) + " " + ys[i + 1].toFixed(1);
    }
    return p;
  }

  function draw(box, data) {
    box._data = data;
    if (!data.points.length) return;
    var mini = box.hasAttribute("data-mini");
    var plot = box.querySelector(".chart-plot") || box, tip = box.querySelector(".chart-tip");
    var W = plot.clientWidth || 300, H = plot.clientHeight || (mini ? 36 : 200);
    var padL = mini ? 0 : 56, padB = mini ? 0 : 22, padT = mini ? 2 : 10;
    var pts = reduce(data.points, data.step, Math.max(12, Math.floor((W - padL) / (mini ? 5 : 8))));
    var n = pts.length, span = data.points.length * data.step;
    var max = niceMax(Math.max.apply(null, pts.map(function (p) { return Math.max(p.down, p.up); }).concat([0])));
    var x = function (i) { return padL + (W - padL) * (n > 1 ? i / (n - 1) : 0); };
    var y = function (v) { return padT + (H - padT - padB) * (1 - v / max); };
    var xs = pts.map(function (_, i) { return x(i); });
    var down = curve(xs, pts.map(function (p) { return y(p.down); }));
    var up = curve(xs, pts.map(function (p) { return y(p.up); }));
    var base = "L" + x(n - 1) + " " + y(0) + "L" + x(0) + " " + y(0) + "Z";

    var svg = el("svg", { viewBox: "0 0 " + W + " " + H, width: W, height: H, role: "img" });
    var id = "g" + (++uid), defs = el("defs", {});
    [["d", "--accent", ".35"], ["u", "--up", ".16"]].forEach(function (g) {
      var lg = el("linearGradient", { id: id + g[0], x1: 0, x2: 0, y1: 0, y2: 1 });
      lg.appendChild(el("stop", { offset: "0", style: "stop-color:var(" + g[1] + ");stop-opacity:" + g[2] }));
      lg.appendChild(el("stop", { offset: "1", style: "stop-color:var(" + g[1] + ");stop-opacity:0" }));
      defs.appendChild(lg);
    });
    svg.appendChild(defs);
    if (!mini) {
      [0.5, 1].forEach(function (f) {
        svg.appendChild(el("line", { x1: padL, x2: W, y1: y(max * f), y2: y(max * f), class: "grid" }));
        var t = el("text", { x: padL - 8, y: y(max * f) + 4, class: "axis", "text-anchor": "end" });
        t.textContent = bits(max * f);
        svg.appendChild(t);
      });
      svg.appendChild(el("line", { x1: padL, x2: W, y1: y(0), y2: y(0), class: "base" }));
      [0, Math.floor((n - 1) / 2), n - 1].forEach(function (i, k) {
        var t = el("text", { x: x(i), y: H - 5, class: "axis", "text-anchor": ["start", "middle", "end"][k] });
        t.textContent = when(pts[i].t, span);
        svg.appendChild(t);
      });
    }
    svg.appendChild(el("path", { d: down + base, fill: "url(#" + id + "d)" }));
    svg.appendChild(el("path", { d: up + base, fill: "url(#" + id + "u)" }));
    // blocked events: bars up to a quarter of the plot (own scale)
    var maxB = Math.max.apply(null, pts.map(function (p) { return p.blocks; }).concat([0]));
    if (maxB > 0) {
      var bw = Math.max(2, (W - padL) / Math.max(n, 1) * 0.5), bh = (H - padT - padB) * (mini ? 0.45 : 0.25);
      pts.forEach(function (p, i) {
        if (!p.blocks) return;
        var h = Math.max(2, bh * p.blocks / maxB);
        svg.appendChild(el("rect", { x: Math.max(padL, Math.min(W - bw, x(i) - bw / 2)), y: y(0) - h, width: bw, height: h, rx: 1, class: "blk" }));
      });
    }
    svg.appendChild(el("path", { d: down, class: "stroke down" }));
    svg.appendChild(el("path", { d: up, class: "stroke up" }));
    plot.replaceChildren(svg);
    if (mini || !tip) return;

    var cursor = el("line", { y1: padT, y2: H - padB, class: "cursor", visibility: "hidden" });
    var dotD = el("circle", { r: 4, class: "dot down", visibility: "hidden" });
    var dotU = el("circle", { r: 4, class: "dot up", visibility: "hidden" });
    svg.append(cursor, dotD, dotU);
    function show(ev) {
      var b = svg.getBoundingClientRect(), px = (ev.clientX - b.left) / b.width * W;
      var i = Math.max(0, Math.min(n - 1, Math.round((px - padL) / (W - padL) * (n - 1))));
      [cursor, dotD, dotU].forEach(function (e) { e.setAttribute("visibility", "visible"); });
      cursor.setAttribute("x1", x(i)); cursor.setAttribute("x2", x(i));
      dotD.setAttribute("cx", x(i)); dotD.setAttribute("cy", y(pts[i].down));
      dotU.setAttribute("cx", x(i)); dotU.setAttribute("cy", y(pts[i].up));
      tip.textContent = when(pts[i].t, Math.min(span, 7 * 86400)) + " · ↓ " + bits(pts[i].down) + " · ↑ " + bits(pts[i].up) +
        (pts[i].blocks ? " · " + pts[i].blocks + " " + (box.dataset.blocked || "blocked") : "");
    }
    svg.addEventListener("pointermove", show);
    svg.addEventListener("pointerdown", show);
    svg.addEventListener("pointerleave", function () {
      [cursor, dotD, dotU].forEach(function (e) { e.setAttribute("visibility", "hidden"); });
      tip.textContent = "";
    });
  }

  function load(box) {
    var q = new URLSearchParams({ range: box.dataset.range, client: box.dataset.client || "" });
    fetch(box.dataset.src + "?" + q, { credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
      .then(function (d) { draw(box, d); }, function () {});
  }

  function init(root) {
    root.querySelectorAll("[data-chart]:not([data-ready])").forEach(function (box) {
      box.setAttribute("data-ready", "");
      box.querySelectorAll(".tab[data-range]").forEach(function (b) {
        b.addEventListener("click", function () {
          if (box.hasAttribute("data-nav")) { // the page shows the same range: reload it
            var u = new URL(location.href);
            u.searchParams.set("range", b.dataset.range);
            u.searchParams.delete("saved");
            return location.assign(u);
          }
          box.dataset.range = b.dataset.range;
          box.querySelectorAll(".tab").forEach(function (o) { o.setAttribute("aria-selected", o === b); });
          load(box);
        });
      });
      load(box);
      var timer = setInterval(function () {
        if (!box.isConnected) return clearInterval(timer);
        if (!document.hidden) load(box);
      }, 10000);
    });
  }
  document.addEventListener("DOMContentLoaded", function () { init(document); });
  document.addEventListener("htmx:afterSettle", function (e) { init(e.target); });
  window.addEventListener("resize", function () {
    document.querySelectorAll("[data-chart]").forEach(function (b) { if (b._data) draw(b, b._data); });
  });
})();
