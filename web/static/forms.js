// Admin forms: confirms a saved change, and asks before leaving a page with
// unsaved input (in-page links, other forms, reload/close of the tab).
(function () {
  var snapshots = new Map(), bypass = false, pending = null;

  // A form is guarded when it has fields a person edits (not only hidden
  // inputs and a button, like the on/off switches and delete buttons).
  function guarded() {
    return Array.prototype.filter.call(document.querySelectorAll("form[method=post]"), function (f) {
      return !f.hasAttribute("data-no-guard") &&
        f.querySelector("input:not([type=hidden]):not([type=submit]), select, textarea");
    });
  }
  function state(f) {
    var parts = [];
    new FormData(f).forEach(function (v, k) { parts.push(k + "=" + (typeof v === "string" ? v : v.name)); });
    return parts.join("&");
  }
  function snapshot() {
    snapshots = new Map();
    guarded().forEach(function (f) { snapshots.set(f, state(f)); });
  }
  function dirtyForm() {
    var found = null;
    snapshots.forEach(function (s, f) { if (!found && f.isConnected && state(f) !== s) found = f; });
    return found;
  }
  function modal() { return document.querySelector("dialog[data-unsaved]"); }

  function ask(form, then) {
    var d = modal();
    if (!d) return then();
    pending = { form: form, then: then };
    d.showModal();
  }
  function proceed() {
    var p = pending;
    pending = null;
    modal().close();
    bypass = true;
    p.then();
    setTimeout(function () { bypass = false; }, 0);
  }

  // Save submits the edited form in the background, then continues. If the
  // server rejects it, the form is submitted normally so the error shows.
  function save() {
    var f = pending.form;
    fetch(f.action, { method: "POST", body: new FormData(f), credentials: "same-origin" }).then(function (r) {
      if (r.redirected && /[?&]saved(=|&|$)/.test(r.url)) {
        snapshots.set(f, state(f));
        proceed();
        return;
      }
      pending = null;
      modal().close();
      bypass = true;
      f.requestSubmit();
      bypass = false;
    }, function () { modal().close(); pending = null; });
  }

  document.addEventListener("click", function (e) {
    var b = e.target.closest("[data-unsaved-save],[data-unsaved-discard],[data-unsaved-cancel]");
    if (b) {
      if (b.hasAttribute("data-unsaved-save")) save();
      else if (b.hasAttribute("data-unsaved-discard")) proceed();
      else { pending = null; modal().close(); }
      return;
    }
    var a = e.target.closest("a[href]");
    if (bypass || !a || a.target === "_blank" || a.getAttribute("href").charAt(0) === "#" || e.ctrlKey || e.metaKey) return;
    var f = dirtyForm();
    if (!f) return;
    e.preventDefault();
    e.stopImmediatePropagation();
    ask(f, function () { a.click(); });
  }, true);

  document.addEventListener("submit", function (e) {
    if (bypass) return;
    var f = dirtyForm(), target = e.target;
    if (!f || f === target) {
      snapshots.delete(target); // submitted: no longer unsaved
      return;
    }
    e.preventDefault();
    e.stopImmediatePropagation();
    var submitter = e.submitter;
    ask(f, function () { target.requestSubmit(submitter); });
  }, true);

  // an open action menu closes on a click elsewhere
  document.addEventListener("click", function (e) {
    document.querySelectorAll("details.menu[open]").forEach(function (m) { if (!m.contains(e.target)) m.open = false; });
  });

  // filters that apply on change
  document.addEventListener("change", function (e) {
    if (e.target.matches("select[data-autosubmit]")) e.target.form.requestSubmit();
    // a new isolated ingress gets no admin access unless switched on again
    if (e.target.matches("form[action='/ingresses'] input[name=isolated]")) {
      var adm = e.target.form.querySelector("input[name=admin]");
      if (adm) adm.checked = !e.target.checked;
    }
    // a new client's AWG 3.1 switch follows the default of the chosen ingress
    if (e.target.matches("select[data-ingress]")) {
      var o = e.target.selectedOptions[0], sw = e.target.form.querySelector("label[data-awg3]");
      if (!o || !sw) return;
      sw.hidden = o.dataset.strict === "true";
      sw.querySelector("input").checked = o.dataset.awg3 === "true";
    }
  });

  window.addEventListener("beforeunload", function (e) {
    if (!bypass && dirtyForm()) { e.preventDefault(); e.returnValue = ""; }
  });

  // after a save: drop ?saved from the address bar and fade the notice out
  function settle() {
    snapshot();
    var q = new URLSearchParams(location.search);
    if (q.has("saved")) {
      q.delete("saved");
      history.replaceState(history.state, "", location.pathname + (q.toString() ? "?" + q : ""));
    }
    document.querySelectorAll("[data-toast]").forEach(function (t) {
      setTimeout(function () { t.remove(); }, 3000);
    });
  }
  document.addEventListener("DOMContentLoaded", settle);
  document.addEventListener("htmx:afterSettle", function (e) {
    if (e.target === document.body || e.target.contains(document.querySelector("main, .wrap"))) settle();
  });
})();
