/* Attack-lineage renderer.

   Layered left-to-right by kill-chain rank rather than force-directed: an
   attack has a direction, and a physics simulation throws that away in exchange
   for wobble. Columns make the causality readable at a glance and the layout
   stable between messages, so the same attack always looks the same. */

const G_COLS = ["actor", "identity", "infra", "technique", "payload", "objective", "evidence"];
const G_KIND_LABEL = {
  actor: "actor", identity: "identity", infra: "infrastructure",
  technique: "technique", payload: "payload", objective: "objective",
  evidence: "evidence",
};

function wrapText(s, width) {
  const words = String(s || "").split(/\s+/);
  const lines = [];
  let cur = "";
  for (const w of words) {
    if ((cur + " " + w).trim().length > width) { if (cur) lines.push(cur); cur = w; }
    else cur = (cur + " " + w).trim();
  }
  if (cur) lines.push(cur);
  return lines.slice(0, 2);
}

let __gseq = 0;

function renderGraph(container, g) {
  // The inline graph and the expanded overlay live in the same document, so
  // element ids must not collide -- two #gtip nodes means the overlay's
  // tooltip updates the panel's.
  const uid = `g${++__gseq}`;
  const NW = 168, NH = 52, GAPX = 74, GAPY = 16, PAD = 22;

  // Evidence sits in its own trailing column; the rest follow kill-chain order.
  const cols = G_COLS.map((k) => g.nodes.filter((n) => n.kind === k))
                     .filter((c) => c.length);
  const rows = Math.max(...cols.map((c) => c.length), 1);
  const W = PAD * 2 + cols.length * NW + (cols.length - 1) * GAPX;
  const H = PAD * 2 + rows * NH + (rows - 1) * GAPY;

  const pos = {};
  cols.forEach((col, ci) => {
    const colH = col.length * NH + (col.length - 1) * GAPY;
    const y0 = (H - colH) / 2;
    col.forEach((n, ri) => {
      pos[n.id] = { x: PAD + ci * (NW + GAPX), y: y0 + ri * (NH + GAPY) };
    });
  });

  const esc = (s) => String(s ?? "").replace(/[&<>"]/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

  let edges = "";
  g.edges.forEach((e) => {
    const a = pos[e.source], b = pos[e.target];
    if (!a || !b) return;
    const x1 = a.x + NW, y1 = a.y + NH / 2, x2 = b.x, y2 = b.y + NH / 2;
    const mx = (x1 + x2) / 2;
    edges += `<path class="gedge ${e.kind === "evidence" ? "evidence" : ""}"
      d="M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}"
      marker-end="url(#arrow-${uid})"/>`;
    if (e.label && e.kind !== "evidence") {
      edges += `<text class="gedge-label" x="${mx}" y="${(y1 + y2) / 2 - 5}"
        text-anchor="middle">${esc(e.label)}</text>`;
    }
  });

  let nodes = "";
  g.nodes.forEach((n) => {
    const p = pos[n.id];
    if (!p) return;
    const lines = wrapText(n.label, 26);
    nodes += `<g class="gnode" data-kind="${esc(n.kind)}" data-id="${esc(n.id)}"
                 transform="translate(${p.x},${p.y})">
      <rect width="${NW}" height="${NH}"/>
      <text class="g-kind" x="10" y="14">${esc(G_KIND_LABEL[n.kind] || n.kind)}</text>
      ${lines.map((l, i) => `<text class="g-label" x="10" y="${29 + i * 12}">${esc(l)}</text>`).join("")}
    </g>`;
  });

  // Rendered at natural size inside a horizontally scrollable frame rather
  // than scaled to fit. A seven-column lineage squeezed into a 430px side
  // panel produces 30px nodes nobody can read; scrolling keeps them legible,
  // and the expand button gives the whole graph the width it deserves.
  container.innerHTML = `
    <div class="graph-wrap">
      <button class="btn ghost g-expand" id="exp-${uid}">Expand</button>
      <div class="graph-scroll">
      <svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img"
           aria-label="Attack lineage graph">
        <defs>
          <marker id="arrow-${uid}" viewBox="0 0 8 8" refX="7" refY="4"
                  markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M0,0 L8,4 L0,8 z" fill="var(--line)"/>
          </marker>
        </defs>
        ${edges}${nodes}
      </svg>
      </div>
      <div class="graph-legend">
        <span><i style="background:var(--critical)"></i>actor</span>
        <span><i style="background:var(--high)"></i>identity</span>
        <span><i style="background:var(--medium)"></i>infrastructure</span>
        <span><i style="background:var(--accent)"></i>technique</span>
        <span><i style="background:#a78bfa"></i>objective</span>
        <span><i style="background:var(--line)"></i>evidence</span>
      </div>
      <div class="gtip" id="tip-${uid}"></div>
    </div>`;

  // Hover detail. Every node carries the observation it came from, so the graph
  // stays inspectable rather than being a picture of the analysis.
  const tip = container.querySelector(`#tip-${uid}`);
  const wrap = container.querySelector(".graph-wrap");
  container.querySelectorAll(".gnode").forEach((el) => {
    const n = g.nodes.find((x) => x.id === el.dataset.id);
    if (!n) return;
    el.addEventListener("mouseenter", (ev) => {
      const extra = [];
      if (n.meta?.mitre?.length) extra.push("MITRE " + n.meta.mitre.join(", "));
      if (n.meta?.shap != null) extra.push("SHAP " + n.meta.shap);
      if (n.meta?.floor != null) extra.push("rule floor " + Math.round(n.meta.floor * 100) + "%");
      if (n.meta?.url) extra.push(n.meta.url);
      tip.innerHTML = `<b>${esc(n.label)}</b>${esc(n.detail || "")}` +
        (extra.length ? `<div style="margin-top:5px;opacity:.7;font-family:var(--mono);font-size:10.5px">${esc(extra.join(" · "))}</div>` : "");
      const r = wrap.getBoundingClientRect();
      tip.style.left = Math.min(ev.clientX - r.left + 12, r.width - 300) + "px";
      tip.style.top = (ev.clientY - r.top + 12) + "px";
      tip.style.opacity = "1";
    });
    el.addEventListener("mouseleave", () => { tip.style.opacity = "0"; });
  });

  container.querySelector(`#exp-${uid}`)?.addEventListener("click", () => {
    const ov = document.createElement("div");
    ov.className = "g-overlay";
    ov.innerHTML = `<div class="g-overlay-inner">
        <button class="icon-btn g-close" title="Close">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"
               stroke-width="2.6" stroke-linecap="round"><path d="M6 6l12 12M18 6L6 18"/></svg>
        </button></div>`;
    const inner = ov.querySelector(".g-overlay-inner");
    const host = document.createElement("div");
    inner.appendChild(host);
    document.body.appendChild(ov);
    renderGraph(host, g);
    host.querySelector(".g-expand")?.remove();
    const close = () => ov.remove();
    ov.querySelector(".g-close").addEventListener("click", close);
    ov.addEventListener("click", (e) => { if (e.target === ov) close(); });
    document.addEventListener("keydown", function esc(e) {
      if (e.key === "Escape") { close(); document.removeEventListener("keydown", esc); }
    });
  });

  // Entrance is CSS, deliberately not anime.js. An SVG <g> positions itself
  // with a transform attribute, and animating translateX overwrites that
  // attribute outright -- the nodes lose their coordinates and collapse into
  // the corner. CSS opacity keyframes cannot touch the transform, and cannot
  // strand a node at opacity 0 if the animation is interrupted.
  container.querySelectorAll(".gnode").forEach((el, i) => {
    el.style.animationDelay = `${Math.min(i * 40, 700)}ms`;
  });
  container.querySelectorAll(".gedge").forEach((el, i) => {
    el.style.animationDelay = `${180 + Math.min(i * 30, 500)}ms`;
  });
}

window.renderGraph = renderGraph;
