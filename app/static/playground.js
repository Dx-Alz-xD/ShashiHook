/* Adversarial playground.

   An editor on the left, the live verdict on the right. Every pause in typing
   re-scores the draft, so deleting the word "urgent" visibly moves the number
   and the SHAP bars redraw.

   The point is not the animation. A detector that only ever produces a verdict
   is something you either trust or don't; one you can push on until it moves
   is something you can learn the shape of. */

const PG_SAMPLES = {
  "Credential phishing": {
    sender: '"Microsoft Account Team" <security@ms-verify-login.tk>',
    subject: "Action required: unusual sign-in to your account",
    body: "We detected an unusual sign-in. Your mailbox storage quota exceeded and your "
        + "account will be suspended within 24 hours unless you verify your account.\n\n"
        + "https://ms-verify-login.tk/secure/login/account",
  },
  "BEC / gift card": {
    sender: '"Mark Hale" <markhale.ceo@gmail.com>',
    subject: "Are you available?",
    body: "I am in back-to-back meetings and cannot take calls. I need you to purchase "
        + "gift cards for a client appreciation gift. Keep this between us until the "
        + "announcement. Let me know how quickly you can get this done.",
  },
  "Callback phishing": {
    sender: '"Billing" <billing@norton-renewal-desk.top>',
    subject: "Your subscription has been renewed",
    body: "Your Norton 360 auto-renewal of $399.99 has been charged to your account. "
        + "If you did not authorize this transaction, call our refund department at "
        + "1-833-555-0142 to cancel this order within 24 hours.",
  },
  "Ordinary business mail": {
    sender: '"Priya Raman" <priya.raman@acme.com>',
    subject: "Weekly engineering sync notes",
    body: "Hi all,\n\nNotes from today's sync are in the shared drive. We agreed to move "
        + "the database migration to next sprint and Sam will own the rollback plan.\n\n"
        + "Thanks,\nPriya",
  },
};

let pgTimer = null, pgLast = null, pgBusy = false;

function pgOpen() {
  const ov = document.createElement("div");
  ov.className = "pg-overlay";
  ov.innerHTML = `
    <div class="pg">
      <div class="pg-head">
        <h2>Adversarial playground</h2>
        <span class="pg-sub">Edit the draft — ArnosAI re-scores as you type</span>
        <div class="spacer"></div>
        <select id="pg-sample"><option value="">Load a sample…</option>
          ${Object.keys(PG_SAMPLES).map((k) => `<option>${k}</option>`).join("")}
        </select>
        <button class="icon-btn" id="pg-close" title="Close">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor"
               stroke-width="2.6" stroke-linecap="round"><path d="M6 6l12 12M18 6L6 18"/></svg>
        </button>
      </div>
      <div class="pg-body">
        <div class="pg-edit">
          <label>From</label><input id="pg-sender" placeholder='"Name" &lt;user@domain.com&gt;'>
          <label>Subject</label><input id="pg-subject" placeholder="Subject line">
          <label>Body</label><textarea id="pg-body" placeholder="Paste or write an email…"></textarea>
          <p class="note" id="pg-hint">Try deleting a word like “urgent”, or changing
             the sending domain, and watch the score move.</p>
        </div>
        <div class="pg-out" id="pg-out">
          <div class="pg-empty">Start typing to score a draft.</div>
        </div>
      </div>
    </div>`;
  document.body.appendChild(ov);

  const close = () => { ov.remove(); clearTimeout(pgTimer); };
  ov.querySelector("#pg-close").addEventListener("click", close);
  ov.addEventListener("click", (e) => { if (e.target === ov) close(); });
  document.addEventListener("keydown", function esc(e) {
    if (e.key === "Escape" && document.body.contains(ov)) { close(); }
    if (!document.body.contains(ov)) document.removeEventListener("keydown", esc);
  });

  ["#pg-sender", "#pg-subject", "#pg-body"].forEach((sel) =>
    ov.querySelector(sel).addEventListener("input", pgSchedule));

  ov.querySelector("#pg-sample").addEventListener("change", (e) => {
    const s = PG_SAMPLES[e.target.value];
    if (!s) return;
    ov.querySelector("#pg-sender").value = s.sender;
    ov.querySelector("#pg-subject").value = s.subject;
    ov.querySelector("#pg-body").value = s.body;
    pgScore();
  });
}

function pgSchedule() {
  clearTimeout(pgTimer);
  // 320ms: long enough not to fire mid-word, short enough that the number
  // still feels attached to the keystroke.
  pgTimer = setTimeout(pgScore, 320);
}

async function pgScore() {
  if (pgBusy) { pgSchedule(); return; }
  const g = (s) => document.querySelector(s)?.value || "";
  const payload = { sender: g("#pg-sender"), subject: g("#pg-subject"), body: g("#pg-body") };
  if (!payload.subject.trim() && !payload.body.trim()) return;
  pgBusy = true;
  try {
    const r = await fetch("/api/score", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload) });
    pgRender(await r.json());
  } catch { /* keep the last good render */ }
  finally { pgBusy = false; }
}

function pgRender(d) {
  const out = document.querySelector("#pg-out");
  if (!out) return;
  const esc = (s) => String(s ?? "").replace(/[&<>"]/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const colour = { CRITICAL: "var(--critical)", HIGH: "var(--high)",
                   MEDIUM: "var(--medium)", LOW: "var(--low)",
                   INFORMATIONAL: "var(--info)" }[d.band];
  const prev = pgLast?.score ?? d.score;
  const delta = d.score - prev;

  const maxShap = Math.max(...d.findings.map((f) => Math.abs(f.shap)), 0.6);
  out.innerHTML = `
    <div class="pg-score">
      <span class="pg-num" id="pg-num" style="color:${colour}">${d.score.toFixed(1)}</span>
      <div>
        <div class="pg-band" style="color:${colour}">${d.band}</div>
        <div class="pg-vec">${esc(d.vector_name)}</div>
      </div>
      ${Math.abs(delta) >= 0.05
        ? `<span class="pg-delta ${delta > 0 ? "up" : "down"}">
             ${delta > 0 ? "▲" : "▼"} ${Math.abs(delta).toFixed(1)}</span>` : ""}
    </div>
    <div class="pg-formula">${esc(d.arithmetic)}</div>
    <div class="pg-terms">
      <span>intent <b>${d.intent.toFixed(3)}</b></span>
      <span>impact <b>${d.impact.toFixed(2)}</b></span>
      <span>exploit <b>${d.exploitability.toFixed(2)}</b></span>
      <span>target <b>${d.targeting.toFixed(2)}</b></span>
      <span>model alone <b>${(d.model_probability * 100).toFixed(1)}%</b></span>
    </div>
    ${d.floors.length ? `<div class="pg-floors">${d.floors.map((f) =>
      `<div class="pg-floor"><b>${esc(f.name)}</b> → floor ${Math.round(f.min * 100)}%
         <div>${esc(f.why)}</div></div>`).join("")}</div>` : ""}
    <div class="pg-bars">
      ${d.findings.map((f) => `
        <div class="pg-bar" data-feature="${esc(f.feature)}">
          <div class="pg-bar-top">
            <span class="pg-bar-v">${f.shap > 0 ? "+" : ""}${f.shap.toFixed(2)}</span>
            <span class="pg-bar-h">${esc(f.headline)}</span>
          </div>
          <div class="pg-bar-track"><i style="width:${Math.min(100, Math.abs(f.shap) / maxShap * 100)}%"></i></div>
        </div>`).join("")}
    </div>
    ${d.lexicons.length ? `<div class="pg-lex">${d.lexicons.map((l) =>
      `<span class="token">${esc(l)}</span>`).join("")}</div>` : ""}`;

  if (window.anime && pgLast && Math.abs(delta) >= 0.05) {
    // Rendered correct already; the count is a flourish over a correct value.
    anime({ targets: { n: prev }, n: d.score, duration: 420, easing: "easeOutCubic",
      update: (a) => { const el = document.querySelector("#pg-num");
        if (el) el.textContent = a.animations[0].currentValue.toFixed(1); },
      complete: () => { const el = document.querySelector("#pg-num");
        if (el) el.textContent = d.score.toFixed(1); } });
    anime({ targets: "#pg-num", scale: [1.16, 1], duration: 340, easing: "easeOutBack" });
  }
  if (window.anime) {
    anime({ targets: out.querySelectorAll(".pg-bar-track i"),
            scaleX: [0, 1], duration: 380, delay: anime.stagger(22),
            easing: "easeOutCubic" });
  }
  pgLast = d;
}

window.pgOpen = pgOpen;
