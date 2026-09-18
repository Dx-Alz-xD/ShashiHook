/* Campaign view: related messages grouped by shared infrastructure.

   Reuses the lineage renderer, because a campaign has the same shape as a
   single attack — actor, identity, infrastructure, technique — just with more
   than one message hanging off it. */

async function campOpen() {
  const ov = document.createElement("div");
  ov.className = "pg-overlay";
  ov.innerHTML = `
    <div class="pg camp">
      <div class="pg-head">
        <h2>Campaigns</h2>
        <span class="pg-sub">Messages linked by shared infrastructure or template</span>
        <div class="spacer"></div>
        <label class="camp-toggle"><input type="checkbox" id="camp-all"> include benign</label>
        <button class="icon-btn" id="camp-close" title="Close">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor"
               stroke-width="2.6" stroke-linecap="round"><path d="M6 6l12 12M18 6L6 18"/></svg>
        </button>
      </div>
      <div class="camp-body" id="camp-body">
        <p class="note" style="padding:24px">Clustering what was scanned…</p>
      </div>
    </div>`;
  document.body.appendChild(ov);
  const close = () => ov.remove();
  ov.querySelector("#camp-close").addEventListener("click", close);
  ov.addEventListener("click", (e) => { if (e.target === ov) close(); });
  ov.querySelector("#camp-all").addEventListener("change", () => campLoad());
  campLoad();
}

async function campLoad() {
  const body = document.querySelector("#camp-body");
  if (!body) return;
  body.innerHTML = `<p class="note" style="padding:24px">Clustering…</p>`;
  let d;
  try {
    d = await (await fetch("/api/campaigns?min_size=2")).json();
  } catch {
    body.innerHTML = `<p class="note" style="padding:24px">Could not cluster.</p>`;
    return;
  }
  const esc = (s) => String(s ?? "").replace(/[&<>"]/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

  if (!d.campaigns?.length) {
    body.innerHTML = `<div class="pg-empty">
      No campaigns found among the ${d.scanned} messages scored this session.<br>
      Scan more of the mailbox — campaigns emerge over months, not hours.</div>`;
    return;
  }

  body.innerHTML = `
    <p class="note" style="padding:0 0 12px">
      ${d.found} campaign(s) across ${d.scanned} scored messages. A campaign means
      these messages <em>provably share</em> a sending domain, a link domain, a
      phone number or a near-identical body — not that they merely felt similar.
    </p>
    <div class="camp-list">${d.campaigns.map((c) => `
      <div class="camp-card" data-id="${esc(c.id)}">
        <div class="camp-top">
          <span class="camp-size">${c.size}</span>
          <div>
            <div class="camp-name">${esc(c.sender_domains[0] || "mixed senders")}</div>
            <div class="camp-meta">${esc(c.links_by.join(" · ") || "single sender")}</div>
          </div>
          <span class="camp-score" style="color:${
            c.max_score >= 70 ? "var(--high)" : c.max_score >= 40
              ? "var(--medium)" : "var(--info)"}">${c.max_score.toFixed(1)}</span>
        </div>
        <div class="camp-vecs">${Object.entries(c.vectors).map(([v, n]) =>
          `<span class="tag">${esc(v.replace(/_/g, " "))} ×${n}</span>`).join("")}</div>
        <div class="camp-msgs">${c.members.slice(0, 5).map((m) =>
          `<div class="camp-msg"><span>${m.score.toFixed(1)}</span>${esc(m.subject)}</div>`
        ).join("")}${c.members.length > 5
          ? `<div class="camp-msg more">+${c.members.length - 5} more</div>` : ""}</div>
        <div class="camp-graph" id="cg-${esc(c.id)}"></div>
      </div>`).join("")}</div>`;

  body.querySelectorAll(".camp-card").forEach((card) => {
    card.addEventListener("click", async () => {
      const slot = card.querySelector(".camp-graph");
      if (slot.dataset.loaded) { slot.innerHTML = ""; delete slot.dataset.loaded; return; }
      slot.dataset.loaded = "1";
      slot.innerHTML = `<p class="note">Building graph…</p>`;
      try {
        const g = await (await fetch(
          `/api/campaign/${encodeURIComponent(card.dataset.id)}/graph`)).json();
        window.renderGraph(slot, g);
      } catch {
        slot.innerHTML = `<p class="note">Could not build the graph.</p>`;
      }
    });
  });
}

window.campOpen = campOpen;
