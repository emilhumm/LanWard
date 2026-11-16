// The Network tab's links (2026-10-27, picked on the canvas: "E"): one line from the router to every card, in the
// card's colour, with right angles and a port dot where it meets the card. Drawn from where the cards really are,
// so any number of devices (any card height) works; none when the cards stack on a narrow screen.
nsReady(() => {
  const map = document.querySelector(".net-map");
  const hub = map && map.querySelector(".hub");
  if (!hub || map.dataset.linked) return;
  map.dataset.linked = "1";
  const NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("class", "net-links");
  svg.setAttribute("aria-hidden", "true");
  map.prepend(svg);

  const make = (name, attrs) => {
    const e = document.createElementNS(NS, name);
    Object.entries(attrs).forEach(([k, v]) => e.setAttribute(k, v));
    return svg.appendChild(e);
  };

  function draw() {
    svg.replaceChildren();
    if (getComputedStyle(map).gridTemplateColumns.split(" ").length < 3) return;
    const m = map.getBoundingClientRect();
    svg.setAttribute("width", m.width);
    svg.setAttribute("height", m.height);
    const box = el => {
      const r = el.getBoundingClientRect();
      return { l: r.left - m.left, r: r.right - m.left, t: r.top - m.top, b: r.bottom - m.top,
               x: (r.left + r.right) / 2 - m.left, y: (r.top + r.bottom) / 2 - m.top, h: r.height };
    };
    const h = box(hub), column = box(hub.parentElement);
    const ground = getComputedStyle(document.documentElement).getPropertyValue("--bg").trim() || "#07090F";
    const spread = h.h * 0.27;              // the cards above and below the router leave it a little higher or lower
    map.querySelectorAll(".net-group").forEach(card => {
      const c = box(card);
      let d, end;
      if (c.r <= column.l || c.l >= column.r) {   // beside the router: out of its side, turning in the gap between
        const left = c.r <= column.l;              // the columns, never behind the cards above or below it
        const sx = left ? h.l : h.r, ex = left ? c.r : c.l;
        const gx = left ? (c.r + column.l) / 2 : (column.r + c.l) / 2;
        const dy = c.y - h.y;
        const sy = Math.abs(dy) < h.h * 0.15 ? h.y : h.y + Math.sign(dy) * spread;
        d = Math.abs(c.y - sy) < 2 ? `M${sx} ${sy} H${ex}` : `M${sx} ${sy} H${gx} V${c.y} H${ex}`;
        end = [ex, c.y];
      } else if (c.b <= h.t) {               // above
        d = `M${h.x} ${h.t} V${c.b}`; end = [h.x, c.b];
      } else {                               // below
        d = `M${h.x} ${h.b} V${c.t}`; end = [h.x, c.t];
      }
      // In the group's colour (2026-11-01, "Signature"): lit to a group with devices, faint to an empty one, and
      // glowing only to one where something needs you (.needs: a device with a finding, or devices to name)
      const colour = getComputedStyle(card).getPropertyValue("--tone").trim() || "#8B93A7";
      const has = card.classList.contains("has"), needs = card.classList.contains("needs");
      const line = { d, stroke: colour, "stroke-width": 2, "stroke-opacity": needs ? 0.9 : has ? 0.6 : 0.3, fill: "none",
                     "stroke-linejoin": "round", "stroke-linecap": "round" };
      if (needs) line.style = `filter: drop-shadow(0 0 5px ${colour})`;
      if (card.classList.contains("quiet")) line["stroke-dasharray"] = "3 4";     // Nobody home: nobody there
      make("path", line);
      const dot = { cx: end[0], cy: end[1], r: 4, fill: colour, "fill-opacity": has ? 1 : 0.45, stroke: ground, "stroke-width": 2 };
      if (needs) dot.style = `filter: drop-shadow(0 0 6px ${colour})`;
      make("circle", dot);
    });
  }

  draw();
  new ResizeObserver(draw).observe(map);
  if (document.fonts) document.fonts.ready.then(draw);
});
