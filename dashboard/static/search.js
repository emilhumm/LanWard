// LanWard front-end behaviour. Everything here uses event delegation on `document`, so it keeps working
// after htmx swaps the page content on navigation (the listeners are never torn down). Loaded once, in
// the <head>, so it is not re-run on each swap.

// nsReady(fn): run fn now (initial page) and again after every htmx navigation, so each page's setup
// re-runs on the swapped-in content. htmx does not re-execute external <script> tags on a swap, so the
// per-page scripts register through this instead of running on their own.
window.nsReady = function (fn) {
  if (window.htmx && htmx.onLoad) {
    htmx.onLoad(fn);                 // fires for the initial document and for each swapped-in fragment
  } else {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", fn);
    else fn();
  }
};

// ── client-side table filter (Devices, Everything heard, ...) ──
// <input class="table-filter"> / "filter-input"; target is data-target, else the first table after the
// input. A row matches on its text, the values typed into its inputs, and its data-search (hover-only
// detail such as the port numbers behind the port chips).
function filterTable(input) {
  let table = input.dataset.target ? document.querySelector(input.dataset.target) : null;
  if (!table) {
    table = [...document.querySelectorAll("table")].find(
      t => input.compareDocumentPosition(t) & Node.DOCUMENT_POSITION_FOLLOWING);
  }
  if (!table) return;
  const q = input.value.trim().toLowerCase();
  let shown = 0;
  table.querySelectorAll("tbody tr, [data-row]").forEach(tr => {
    const values = [...tr.querySelectorAll("input[type=text]")].map(i => i.value).join(" ");
    const text = tr.textContent + " " + values + " " + (tr.dataset.search || "");
    const match = !q || text.toLowerCase().includes(q);
    tr.style.display = match ? "" : "none";
    if (match) shown++;
  });
  // No-match message, where the page provides one (Devices)
  const empty = document.querySelector("[data-filter-empty]");
  if (empty) {
    const none = q && shown === 0;
    empty.hidden = !none;
    const qs = empty.querySelector("[data-filter-q]");
    if (none && qs) qs.textContent = input.value.trim();
  }
}

document.addEventListener("input", e => {
  if (e.target.matches && e.target.matches("input.table-filter, input.filter-input")) filterTable(e.target);
});

// ── Run scan button opens the popup. It uses data-scan-open (not hx-get) so that while a scan runs the
//    button can poll itself with hx-get without the click triggering that poll. ──
document.addEventListener("click", e => {
  const b = e.target.closest("[data-scan-open]");
  if (b && window.htmx) htmx.ajax("GET", b.getAttribute("data-scan-open"), { target: "#modal", swap: "innerHTML" });
});

// ── Devices: the pencil beside a named device swaps the link for the rename field ──
document.addEventListener("click", e => {
  const edit = e.target.closest("[data-name-edit]");
  if (!edit) return;
  const who = edit.closest(".who");
  if (!who) return;
  const view = who.querySelector("[data-name-view]");
  const form = who.querySelector("[data-name-form]");
  if (view) view.hidden = true;
  if (form) {
    form.hidden = false;
    const i = form.querySelector("input[name=label]");
    if (i) { i.focus(); i.select(); }
  }
});

// ── Run scan popup (#modal): close on a close button, a direct backdrop click, or Escape ──
function closeModal() {
  const m = document.getElementById("modal");
  if (m) m.innerHTML = "";
}
document.addEventListener("click", e => {
  if (e.target.closest("[data-close-modal]") || e.target.classList.contains("modal-backdrop")) closeModal();
});
document.addEventListener("keydown", e => {
  if (e.key === "Escape" && document.querySelector("#modal .modal-backdrop")) closeModal();
});

// ── Styled confirmation: any <form data-confirm="…"> asks in a modal-box (the Run scan popup's look)
//    instead of the browser's confirm(), so every confirmation on LanWard reads the same. Tune it with
//    data-confirm-title, data-confirm-label and data-confirm-variant ("danger" default, or "primary").
//    On confirm the form submits for real (htmx boost still applies); if there is no #modal we fall back
//    to the native confirm so the action is never un-protected. ──
let confirmForm = null;
document.addEventListener("submit", e => {
  const form = e.target;
  if (!(form instanceof HTMLFormElement) || !form.hasAttribute("data-confirm")) return;
  const message = form.getAttribute("data-confirm");
  const modal = document.getElementById("modal");
  e.preventDefault();
  if (!modal) {                                   // no modal host: don't drop the guard
    if (window.confirm(message)) { form.removeAttribute("data-confirm"); form.requestSubmit(); }
    return;
  }
  confirmForm = form;
  const variant = form.getAttribute("data-confirm-variant") === "primary" ? "primary" : "danger";
  const title = form.getAttribute("data-confirm-title") || "Are you sure?";
  const label = form.getAttribute("data-confirm-label") || "Confirm";
  const back = document.createElement("div"); back.className = "modal-backdrop";
  const box = document.createElement("div");
  box.className = "modal-box"; box.setAttribute("role", "dialog"); box.setAttribute("aria-modal", "true");
  const h = document.createElement("h3"); h.className = "modal-title"; h.textContent = title;
  const p = document.createElement("p"); p.className = "modal-sub"; p.textContent = message;
  const acts = document.createElement("div"); acts.className = "modal-actions";
  const cancel = document.createElement("button");
  cancel.type = "button"; cancel.className = "btn"; cancel.setAttribute("data-close-modal", ""); cancel.textContent = "Cancel";
  const go = document.createElement("button");
  go.type = "button"; go.className = "btn " + variant; go.setAttribute("data-confirm-go", ""); go.textContent = label;
  acts.append(cancel, go); box.append(h, p, acts); back.append(box);
  modal.innerHTML = ""; modal.append(back); go.focus();
});
document.addEventListener("click", e => {
  if (!e.target.closest("[data-confirm-go]")) return;
  const form = confirmForm;
  confirmForm = null;
  closeModal();
  if (form) { form.removeAttribute("data-confirm"); form.requestSubmit(); }
});

// ── htmx: a form that returns 400/422 (Settings validation re-renders the form with its errors) should
// still swap in, not be treated as a dead error. ──
document.addEventListener("htmx:beforeSwap", e => {
  const status = e.detail.xhr.status;
  if (status === 400 || status === 422) {
    e.detail.shouldSwap = true;
    e.detail.isError = false;
  }
});
