// Settings page: show and copy the API key, add and remove webhook / push address rows.
// Without JavaScript the page still saves; only these conveniences are missing.
// Re-runs on each htmx navigation (nsReady) so the Settings controls work after the page is swapped in.
nsReady(function () {
  // The Settings header sticks just below the site nav; measure the nav so the offset is right
  // even when it wraps to two rows on a phone.
  function setHeaderH() {
    var h = document.querySelector("header.site");
    if (h) { document.documentElement.style.setProperty("--header-h", h.offsetHeight + "px"); }
  }
  setHeaderH();

  // Appearance (theme) control — client-side, saved per browser; the <head> script applies it early.
  var themeBtns = document.querySelectorAll("[data-theme-opt]");
  if (themeBtns.length && window.__nsTheme) {
    var markTheme = function (v) {
      themeBtns.forEach(function (b) {
        var on = b.getAttribute("data-theme-opt") === v;
        b.classList.toggle("on", on);
        if (on) { b.setAttribute("aria-pressed", "true"); } else { b.removeAttribute("aria-pressed"); }
      });
    };
    markTheme(window.__nsTheme.get());
    themeBtns.forEach(function (b) {
      if (b.dataset.themeBound) return;
      b.dataset.themeBound = "1";
      b.addEventListener("click", function () {
        var v = b.getAttribute("data-theme-opt");
        window.__nsTheme.set(v);
        markTheme(v);
      });
    });
  }

  // Export: one period selector drives the Traffic download links. Without JS they default to 7 days.
  var exportRange = document.getElementById("export-range");
  if (exportRange) {
    var applyExportRange = function () {
      var v = exportRange.value;
      document.querySelectorAll(".export-link").forEach(function (a) {
        a.setAttribute("href", a.getAttribute("data-export") + "?format=csv&range=" + encodeURIComponent(v));
      });
    };
    exportRange.addEventListener("change", applyExportRange);
    applyExportRange();
  }

  // Global listeners are bound once: settings.js re-runs whenever htmx swaps the Settings page back in,
  // and without this guard a resize / add / remove handler would be added again on every visit.
  if (!window.__nsSettingsGlobals) {
    window.addEventListener("resize", setHeaderH);
  }

  document.querySelectorAll("[data-show]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var input = document.getElementById(btn.dataset.show);
      var show = input.type === "password";
      input.type = show ? "text" : "password";
      btn.textContent = show ? "Hide" : "Show";
    });
  });

  // navigator.clipboard needs HTTPS; the dashboard is usually plain HTTP on the LAN, so select + copy.
  document.querySelectorAll("[data-copy]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var input = document.getElementById(btn.dataset.copy);
      var type = input.type;
      input.type = "text";
      input.select();
      var ok = false;
      try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
      input.type = type;
      btn.textContent = ok ? "Copied" : "Press Ctrl+C";
      setTimeout(function () { btn.textContent = "Copy"; }, 2000);
    });
  });

  if (!window.__nsSettingsGlobals) {
    document.addEventListener("click", function (ev) {
      var remove = ev.target.closest("[data-remove]");
      if (remove) {
        remove.closest(".url-row").remove();
        return;
      }
      var add = ev.target.closest("[data-add]");
      if (add) {
        var kind = add.dataset.add;
        var row = document.getElementById(kind + "-row").content.firstElementChild.cloneNode(true);
        document.querySelector('[data-rows="' + kind + '"]').appendChild(row);
        row.querySelector("input").focus();
      }
    });
    window.__nsSettingsGlobals = true;
  }

  // Unsaved-changes guard: light up the Save bar when the form is edited, and warn before leaving the
  // page with unsaved edits (a hard reload/close via beforeunload, an in-app nav via htmx:beforeRequest).
  // Mark the invalid field itself (red border + aria-invalid), not only the helper text below it.
  document.querySelectorAll(".field-error").forEach(function (fe) {
    var lbl = fe.closest("label");
    var fld = (lbl && lbl.querySelector("input, select, textarea")) || fe.previousElementSibling;
    if (fld && fld.matches && fld.matches("input, select, textarea")) {
      fld.classList.add("input-bad");
      fld.setAttribute("aria-invalid", "true");
    }
  });

  var sform = document.getElementById("settings-form");
  if (sform) {
    var dirtyEl = document.querySelector("[data-dirty]");
    var saveBtn = document.querySelector(".set-bar-save");
    window.__nsDirty = false;
    var markDirty = function () {
      if (window.__nsDirty) return;
      window.__nsDirty = true;
      if (dirtyEl) { dirtyEl.hidden = false; }
      if (saveBtn) { saveBtn.classList.add("is-dirty"); }
      var sv = document.querySelector("[data-saved]");
      if (sv) { sv.hidden = true; }
    };
    sform.addEventListener("input", markDirty);
    sform.addEventListener("change", markDirty);
    sform.addEventListener("submit", function () { window.__nsDirty = false; });
    if (!window.__nsDirtyGlobals) {
      window.__nsDirtyGlobals = true;
      window.addEventListener("beforeunload", function (e) {
        if (window.__nsDirty) { e.preventDefault(); e.returnValue = ""; }
      });
      document.addEventListener("htmx:beforeRequest", function (e) {
        var el = e.detail && e.detail.elt;
        if (window.__nsDirty && el && el.tagName === "A" && el.getAttribute("href")) {
          if (window.confirm("Leave Settings without saving your changes?")) { window.__nsDirty = false; }
          else { e.preventDefault(); }
        }
      });
    }
  }

  // Sub-tabs: show one group of sections at a time. Hidden fields still save, so Save covers every tab.
  // Without this (no JS) every section shows and the page works exactly as before.
  var tabs = Array.prototype.slice.call(document.querySelectorAll(".set-tab"));
  if (tabs.length) {
    var sections = Array.prototype.slice.call(document.querySelectorAll("section[data-tab]"));
    var STORE = "lanward-settings-tab";
    function show(name) {
      tabs.forEach(function (t) {
        var on = t.dataset.tab === name;
        t.classList.toggle("active", on);
        if (on) { t.setAttribute("aria-current", "page"); } else { t.removeAttribute("aria-current"); }
      });
      sections.forEach(function (s) { s.classList.toggle("set-hidden", s.dataset.tab !== name); });
      // Appearance applies instantly and isn't part of the form — hide the Save controls on that tab.
      document.querySelectorAll(".set-savebar").forEach(function (el) {
        el.style.display = name === "appearance" ? "none" : "";
      });
      try { sessionStorage.setItem(STORE, name); } catch (e) { /* private mode */ }
    }
    tabs.forEach(function (t) {
      t.addEventListener("click", function () { show(t.dataset.tab); });
    });
    // Start on: the tab holding a section named in the URL hash, else the tab with the first error,
    // else the one last used, else the first tab.
    var start = null, sec;
    if (location.hash) {
      var target = document.querySelector(location.hash);
      if (target && (sec = target.closest("section[data-tab]"))) { start = sec.dataset.tab; }
    }
    if (!start) {
      var err = document.querySelector(".field-error");
      if (err && (sec = err.closest("section[data-tab]"))) { start = sec.dataset.tab; }
    }
    if (!start) { try { start = sessionStorage.getItem(STORE); } catch (e) { /* private mode */ } }
    if (!start || !tabs.some(function (t) { return t.dataset.tab === start; })) { start = tabs[0].dataset.tab; }
    show(start);
  }
});
