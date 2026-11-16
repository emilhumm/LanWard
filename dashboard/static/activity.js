// Overview, Network activity (and a device's page): switch the chart between devices and chatter, and between
// the periods. Without JavaScript the switches stay hidden and devices over 24 hours show.
// Re-runs on each htmx navigation (nsReady), so it works after the page is swapped in, not only on first load.
nsReady(() => {
  const panel = document.getElementById("activity");
  if (!panel || panel.dataset.ready) return;
  panel.dataset.ready = "1";
  const chosen = {};
  // A page may have only one of the switches (the device page: the period alone)
  const off = (el, key) => el.dataset[key] !== undefined && chosen[key] !== undefined && el.dataset[key] !== chosen[key];
  const show = () => panel.querySelectorAll("[data-metric], [data-range]").forEach(el => {
    el.hidden = off(el, "metric") || off(el, "range");
  });
  panel.querySelectorAll("[data-switch]").forEach(group => {
    const buttons = group.querySelectorAll("button[data-value]");
    chosen[group.dataset.switch] = buttons[0].dataset.value;
    buttons.forEach(btn => btn.addEventListener("click", () => {
      buttons.forEach(b => b.setAttribute("aria-pressed", String(b === btn)));
      chosen[group.dataset.switch] = btn.dataset.value;
      show();
    }));
    group.hidden = false;
  });
});

// Instant hover/tap readout for the activity chart. Each column carries its numbers on data-tip
// (no slow native <title>) and its point on data-cx / data-cy; on pointer move or tap we show our
// own tooltip plus a thin guide line and a dot on the point — immediate, and reachable on a phone
// (2026-10-29). Re-runs on each htmx navigation via nsReady.
nsReady(() => {
  const panel = document.getElementById("activity");
  if (!panel || panel.dataset.tipReady) return;
  panel.dataset.tipReady = "1";
  const overlays = new Map();                    // plot -> {tip, guide, dot}
  const parts = plot => {
    let o = overlays.get(plot);
    if (!o) {
      const mk = cls => { const el = document.createElement("div"); el.className = cls; plot.appendChild(el); return el; };
      o = { guide: mk("act-guide"), dot: mk("act-dot"), tip: mk("act-tip") };
      overlays.set(plot, o);
    }
    return o;
  };
  const hideAll = () => overlays.forEach(o => {
    o.tip.classList.remove("on"); o.guide.classList.remove("on"); o.dot.classList.remove("on");
  });
  const show = hit => {
    const plot = hit.closest(".act-plot");
    if (!plot) return;
    const o = parts(plot);
    const cx = hit.getAttribute("data-cx"), cy = hit.getAttribute("data-cy");
    o.tip.textContent = hit.getAttribute("data-tip") || "";
    o.tip.style.left = Math.max(6, Math.min(94, parseFloat(cx) || 0)) + "%";
    o.tip.classList.add("on");
    o.guide.style.left = cx + "%";
    o.guide.classList.add("on");
    if (cy !== null && cy !== "") { o.dot.style.left = cx + "%"; o.dot.style.top = cy + "px"; o.dot.classList.add("on"); }
    else o.dot.classList.remove("on");
  };
  panel.addEventListener("pointermove", e => {
    const hit = e.target.closest && e.target.closest(".act-hit");
    if (hit) show(hit); else hideAll();
  });
  panel.addEventListener("pointerdown", e => {
    const hit = e.target.closest && e.target.closest(".act-hit");
    if (hit) show(hit); else hideAll();
  });
  panel.addEventListener("pointerleave", hideAll);
});
