// Popups (2026-10-27): a button (the Overview's items under the status, an (i) by a title) opens its [popover]
// (the browser closes it on Esc or a click elsewhere) right under itself, kept inside the window.
// On a narrow screen the CSS makes it a sheet from the bottom instead, so nothing is placed here.
nsReady(() => document.querySelectorAll(".pop[popover]").forEach(pop => {
  if (pop.dataset.popReady) return;
  pop.dataset.popReady = "1";
  const button = document.querySelector(`[popovertarget="${pop.id}"]:not(.pop-close)`);
  const place = () => {
    pop.style.top = pop.style.left = "";
    if (!button || matchMedia("(max-width: 640px)").matches) return;
    const r = button.getBoundingClientRect();
    const room = document.documentElement.clientWidth;
    const width = pop.offsetWidth || Math.min(460, room - 32);   // 0 until it shows: a first guess, then exact
    pop.style.top = `${r.bottom + window.scrollY + 8}px`;
    pop.style.left = `${Math.max(16, Math.min(r.left - 8, room - width - 16)) + window.scrollX}px`;
  };
  pop.addEventListener("beforetoggle", e => { if (e.newState === "open") place(); });
  pop.addEventListener("toggle", e => { if (e.newState === "open") place(); });
}));
