// Details a row shows when tapped (2026-10-27: a phone has no hover): a row with data-details opens and closes the
// element it names; its button says so to screen readers. Links in the row still just go where they point.
nsReady(() => document.querySelectorAll("[data-details]").forEach(row => {
  const panel = document.getElementById(row.dataset.details);
  const button = row.querySelector("[aria-controls]");
  if (!panel || row.dataset.detailsReady) return;
  row.dataset.detailsReady = "1";
  row.addEventListener("click", e => {
    if (e.target.closest("a")) return;
    panel.hidden = !panel.hidden;
    row.classList.toggle("open", !panel.hidden);
    if (button) button.setAttribute("aria-expanded", String(!panel.hidden));
  });
}));
