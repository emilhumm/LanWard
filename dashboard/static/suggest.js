// Header search. A "Search" button in the header drops a search panel under it; typing fetches
// /search/suggest and drops the matching devices under the input. Button toggles it, the input
// autofocuses, Esc / the × / an outside click close it. Document-level delegation like search.js, so
// it survives htmx swaps.
(function () {
  var MIN = 2, DEBOUNCE = 140;
  var timer = null, ctrl = null, lastQ = null;

  function $(id) { return document.getElementById(id); }
  function panel() { return $("search-panel"); }
  function items() {
    var m = $("sg-menu");
    return m ? Array.prototype.slice.call(m.querySelectorAll(".sg-item")) : [];
  }

  function closeMenu() {
    if (ctrl) { ctrl.abort(); ctrl = null; }
    lastQ = null;
    var m = $("sg-menu"), i = $("q");
    if (m) { m.hidden = true; m.innerHTML = ""; }
    if (i) i.setAttribute("aria-expanded", "false");
  }
  function openPanel() {
    var p = panel(), t = $("search-toggle");
    if (!p) return;
    p.hidden = false;
    if (t) t.setAttribute("aria-expanded", "true");
    var i = $("q");
    if (i) { i.focus(); i.select(); }
  }
  function closePanel() {
    closeMenu();
    var p = panel(), t = $("search-toggle");
    if (p) p.hidden = true;
    if (t) t.setAttribute("aria-expanded", "false");
  }

  function highlight(n) {
    var its = items();
    if (!its.length) return;
    n = (n + its.length) % its.length;
    its.forEach(function (a, j) { a.classList.toggle("sel", j === n); if (j === n) a.scrollIntoView({ block: "nearest" }); });
  }
  function selected() { return items().findIndex(function (a) { return a.classList.contains("sel"); }); }

  function fetchFor(q) {
    var form = $("q") && $("q").closest(".search-form");
    var url = form && form.getAttribute("data-suggest");
    if (!url) return;
    if (ctrl) ctrl.abort();
    ctrl = new AbortController();
    fetch(url + "?q=" + encodeURIComponent(q), { signal: ctrl.signal })
      .then(function (r) { return r.status === 204 ? "" : r.text(); })
      .then(function (html) {
        var i = $("q"), m = $("sg-menu");
        if (!i || i.value.trim() !== q || !m) return;       // a newer keystroke won
        if (!html) { closeMenu(); return; }
        m.innerHTML = html; m.hidden = false; i.setAttribute("aria-expanded", "true");
      })
      .catch(function () { /* aborted or offline */ });
  }

  // Toggle button, close button, and outside click.
  document.addEventListener("click", function (e) {
    if (!e.target.closest) return;
    if (e.target.closest("#search-toggle")) {
      e.preventDefault();
      if (panel() && panel().hidden) openPanel(); else closePanel();
      return;
    }
    if (e.target.closest("#search-close")) { e.preventDefault(); closePanel(); return; }
    if (panel() && !panel().hidden && !e.target.closest(".search-wrap") && !e.target.closest("#search-toggle")) {
      closePanel();
    }
  });

  document.addEventListener("input", function (e) {
    if (!e.target || e.target.id !== "q") return;
    var q = e.target.value.trim();
    clearTimeout(timer);
    if (q.length < MIN) { closeMenu(); return; }
    if (q === lastQ) return;
    lastQ = q;
    timer = setTimeout(function () { fetchFor(q); }, DEBOUNCE);
  });

  document.addEventListener("keydown", function (e) {
    if (!e.target || e.target.id !== "q") return;
    var m = $("sg-menu"), open = m && !m.hidden;
    if (e.key === "ArrowDown" && open) { e.preventDefault(); highlight(selected() + 1); }
    else if (e.key === "ArrowUp" && open) { e.preventDefault(); highlight(selected() - 1); }
    else if (e.key === "Enter") {
      var sel = open ? m.querySelector(".sg-item.sel") : null;
      if (sel) { e.preventDefault(); closePanel(); window.location.href = sel.getAttribute("href"); }
      // else: let the form submit to the full /search results page
    } else if (e.key === "Escape") {
      e.preventDefault();
      if (open) closeMenu(); else closePanel();   // first Esc clears suggestions, next closes the panel
    }
  });

  // Keep the row under the pointer highlighted.
  document.addEventListener("mousemove", function (e) {
    var item = e.target.closest && e.target.closest(".sg-item");
    if (!item) return;
    items().forEach(function (a) { a.classList.toggle("sel", a === item); });
  });

  // On the results page the input is pre-filled — open the panel so the query is visible.
  function autoOpen() { var i = $("q"); if (i && i.value.trim()) openPanel(); }
  if (window.nsReady) window.nsReady(autoOpen);
  else if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", autoOpen);
  else autoOpen();
})();
