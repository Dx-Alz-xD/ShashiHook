/* ShashiHook dashboard.
   Results stream in over SSE one message at a time, so the feed fills
   progressively while ArnosAI works rather than sitting blank and then
   dumping everything at once. Animation is used to show state changing —
   a row arriving, a counter moving — never as decoration. */

const $  = (s) => document.querySelector(s);
const el = (t, c, txt) => { const n = document.createElement(t);
  if (c) n.className = c; if (txt != null) n.textContent = txt; return n; };

const BANDS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"];
const state = { rows: [], counts: {}, es: null, sel: null, sort: "severity", total: 0 };

/* ------------------------------------------------------------------ status */
async function loadStatus() {
  try {
    const s = await (await fetch("/api/status")).json();
    $("#dot-engine").className = "dot";
    $("#engine-txt").textContent =
      `ArnosAI · ${s.features} features · ${s.vectors} vectors`;
    $("#pill-engine").title =
      `blend weights — structural ${s.blend.structural.toFixed(3)}, ` +
      `wording ${s.blend.wording.toFixed(3)}\n` +
      `inbox base rate ${(s.base_rate * 100).toFixed(1)}%\n` +
      `sender history: ${s.history} domains from ${s.history_messages} messages\n` +
      `RDAP domain age: ${s.rdap ? "enabled" : "disabled"}`;

    $("#dot-mailbox").className = s.mailbox_ready ? "dot" : "dot off";
    $("#mailbox-txt").textContent = s.mailbox_ready
      ? `${s.source} connected` : "no mailbox configured";
    if (!s.mailbox_ready) {
      $("#scan").disabled = true;
      $("#empty").innerHTML =
        "<h3>No mailbox configured</h3><p>Add <code>IMAP_USER</code> and " +
        "<code>IMAP_APP_PASSWORD</code> to <code>.env</code>, then restart. " +
        "See <strong>GMAIL.md</strong> for the walkthrough.</p>";
    }
    window.__taxonomy = s.taxonomy || {};
    window.__llm = s.llm || { any: false };
    window.__autoProfile = s.auto_profile !== false;
    window.__profileMin = s.profile_min_score ?? 15;
    if (s.llm?.any) {
      const names = [s.llm.gemini && "Gemini", s.llm.groq && "Groq"].filter(Boolean);
      $("#pill-llm").style.display = "";
      $("#dot-llm").className = "dot";
      $("#llm-txt").textContent = names.join(" → ");
      $("#pill-llm").title =
        `Narrative tactic profiling. ${names.join(" first, ")} as fallback.\n` +
        `Advisory only — never changes a score.`;
    }
  } catch {
    $("#engine-txt").textContent = "engine unavailable";
  }
}

/* ---------------------------------------------------------------- counters */
function bump(id, value) {
  const node = $(id);
  const from = parseInt(node.textContent, 10) || 0;
  if (from === value) return;
  anime({ targets: { n: from }, n: value, duration: 420, easing: "easeOutCubic",
    update: (a) => { node.textContent = Math.round(a.animations[0].currentValue); } });
  anime({ targets: node, scale: [1.18, 1], duration: 300, easing: "easeOutBack" });
}

function refreshStats() {
  bump("#s-scanned", state.rows.length);
  bump("#s-flagged", state.rows.filter((r) => r.probability >= 0.5).length);
  BANDS.forEach((b) => bump(`#s-${b}`, state.counts[b] || 0));
}

/* -------------------------------------------------------------------- rows */
function rowNode(m) {
  const row = el("div", "row");
  row.dataset.band = m.band;
  row.dataset.id = m.id;

  row.appendChild(el("div", "edge"));
  row.appendChild(el("div", "score", m.score.toFixed(1)));

  const who = el("div", "who");
  who.appendChild(el("div", "subj", m.subject));
  who.appendChild(el("div", "from",
    m.display_name ? `${m.display_name} · ${m.sender}` : m.sender));
  row.appendChild(who);

  const meta = el("div", "meta");
  if (m.vector && m.vector !== "benign") {
    const t = el("span", "tag v", m.vector_name || m.vector);
    t.title = (window.__taxonomy?.[m.vector]?.description) || "";
    meta.appendChild(t);
  }
  if (m.floors.length) {
    const t = el("span", "tag rule", "rule");
    t.title = "Verdict set by a deterministic rule, not the model:\n" + m.floors.join("\n");
    meta.appendChild(t);
  }
  if (m.authenticated) {
    const t = el("span", "tag auth", "dkim");
    t.title = "Sender authentication passed and aligned with the From domain";
    meta.appendChild(t);
  }
  row.appendChild(meta);

  row.appendChild(el("div", "bandname", m.band));
  row.addEventListener("click", () => openDetail(m.id, row));
  return row;
}

function addRow(m) {
  state.rows.push(m);
  state.counts[m.band] = (state.counts[m.band] || 0) + 1;
  $("#empty")?.remove();

  const node = rowNode(m);
  insertSorted(node, m);
  anime({ targets: node, translateX: [-14, 0], duration: 360, easing: "easeOutCubic" });
  // A finding worth attention gets a brief pulse so it is not missed while
  // dozens of clean rows stream past.
  if (m.band === "CRITICAL" || m.band === "HIGH") {
    anime({ targets: node.querySelector(".edge"), scaleY: [0.3, 1],
            duration: 520, easing: "easeOutElastic(1, .6)" });
  }
  refreshStats();
}

function insertSorted(node, m) {
  const feed = $("#feed");
  if (state.sort === "arrival") { feed.appendChild(node); return; }
  const existing = [...feed.querySelectorAll(".row")];
  const target = existing.find((r) => {
    const other = state.rows.find((x) => x.id === r.dataset.id);
    return other && other.score < m.score;
  });
  target ? feed.insertBefore(node, target) : feed.appendChild(node);
}

function rerender() {
  const feed = $("#feed");
  feed.innerHTML = "";
  const rows = [...state.rows];
  if (state.sort === "severity") rows.sort((a, b) => b.score - a.score);
  rows.forEach((m) => feed.appendChild(rowNode(m)));
}

/* ------------------------------------------------------------------ detail */
async function openDetail(id, rowNodeRef) {
  document.querySelectorAll(".row.sel").forEach((r) => r.classList.remove("sel"));
  rowNodeRef?.classList.add("sel");
  const panel = $("#detail");
  $("#main").classList.add("open");
  panel.innerHTML = '<div class="sec"><p class="note">Loading analysis…</p></div>';

  let d;
  try {
    d = await (await fetch(`/api/message/${encodeURIComponent(id)}`)).json();
  } catch {
    panel.innerHTML = '<div class="sec"><p class="note">Could not load this message.</p></div>';
    return;
  }
  if (d.detail) {
    panel.innerHTML = `<div class="sec"><p class="note">${d.detail}</p></div>`;
    return;
  }
  renderDetail(panel, d);
  // Transform only — see architecture.js for why opacity entrances are unsafe.
  anime({ targets: panel.querySelectorAll(".sec"), translateY: [10, 0],
          delay: anime.stagger(28), duration: 330, easing: "easeOutCubic" });
  if ((d.card?.score ?? 0) >= window.__profileMin) loadGraph(id);
  // Fired here, not awaited above: the deterministic analysis is already on
  // screen, and the narrative fills in beside it when the provider answers.
  if (window.__llm?.any && window.__autoProfile &&
      (d.card?.score ?? 0) >= window.__profileMin) {
    loadProfile(id);
  } else if (window.__llm?.any) {
    const slot = $("#profile-slot");
    if (slot) {
      slot.innerHTML = `<h3>Why this scored low</h3>
        <p class="note">Severity ${(d.card?.score ?? 0).toFixed(1)} — below the
        alert threshold of ${window.__profileMin}, so no attack lineage is drawn
        and no tactics are claimed.</p>
        <button class="btn ghost" id="profile-anyway" style="margin-top:9px">
          Explain this verdict</button>`;
      $("#profile-anyway")?.addEventListener("click", () => {
        const gs = document.querySelector("#graph-sec");
        if (gs) gs.style.display = "";
        loadProfile(id, true);
        loadGraph(id, true);
      });
    }
  }
}

/* ---------------------------------------------------------- attack lineage */
async function loadGraph(id, force = false) {
  const slot = $("#graph-slot");
  if (!slot) return;
  slot.innerHTML = `<p class="note">Building graph…</p>`;
  try {
    const g = await (await fetch(
      `/api/graph/${encodeURIComponent(id)}${force ? "?force=true" : ""}`)).json();
    if (g.skipped) { slot.innerHTML = `<p class="note">${g.reason}</p>`; return; }
    if (!g.nodes?.length) { slot.innerHTML = `<p class="note">No lineage to draw.</p>`; return; }
    window.renderGraph(slot, g);
  } catch {
    slot.innerHTML = `<p class="note">Could not build the graph.</p>`;
  }
}

/* --------------------------------------------------------- threat profile */
async function loadProfile(id, force = false) {
  const slot = $("#profile-slot");
  if (!slot) return;
  slot.innerHTML = `
    <h3>Threat profile <span class="spin"></span></h3>
    <p class="note">ArnosAI is writing up the tactics this message uses…</p>`;
  anime({ targets: slot.querySelector(".spin"), rotate: "1turn",
          duration: 900, loop: true, easing: "linear" });

  let p;
  try {
    p = await (await fetch(`/api/profile/${encodeURIComponent(id)}${force ? "?force=true" : ""}`)).json();
  } catch (e) {
    slot.innerHTML = `<h3>Threat profile</h3><p class="note">Could not reach the profiler.</p>`;
    return;
  }
  if (slot.dataset.owner !== id) return;   // a different message was opened
  renderProfile(slot, p, id);
}

function renderProfile(slot, p, id) {
  const esc = (s) => String(s ?? "").replace(/[&<>"]/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

  if (!p.ok) {
    slot.innerHTML = `<h3>Threat profile</h3>
      <p class="note">${p.skipped ? esc(p.error)
                                  : "Unavailable — " + esc(p.error || "no provider answered")}</p>
      <button class="btn ghost" id="profile-anyway" style="margin-top:9px">
        ${p.skipped ? "Profile it anyway" : "Retry"}</button>`;
    $("#profile-anyway")?.addEventListener("click", () => loadProfile(id, true));
    return;
  }
  const balanced = p.mode === "balanced";
  let h = `<h3>${balanced ? "Why this scored low" : "Threat profile"}
      <span class="prov" title="${esc(p.model)} · ${p.latency_ms}ms">${esc(p.provider)}</span>
    </h3>`;
  if (balanced) {
    if (p.headline) h += `<p class="headline">${esc(p.headline)}</p>`;
    if (p.could_look_suspicious?.length) {
      h += `<div class="tactics">`;
      p.could_look_suspicious.forEach((c) => {
        h += `<div class="tactic balanced">
          <div class="t-head"><span class="t-icon">🔍</span>
            <span class="t-name">${esc(c.signal)}</span></div>
          ${c.evidence ? `<div class="t-ev">“${esc(c.evidence)}”</div>` : ""}
          ${c.why_it_looks_bad ? `<div class="t-w"><b>Could look wrong</b> ${esc(c.why_it_looks_bad)}</div>` : ""}
          ${c.why_it_is_fine ? `<div class="t-s"><b>Why it is fine</b> ${esc(c.why_it_is_fine)}</div>` : ""}
        </div>`;
      });
      h += `</div>`;
    }
    if (p.why_benign?.length) {
      h += `<div style="margin-top:12px"><b class="note">Why it is benign</b>
        <ul class="benign-list">${p.why_benign.map((s) => `<li>${esc(s)}</li>`).join("")}</ul></div>`;
    }
    if (p.score_justification) {
      h += `<div class="justify"><b>Why ${(window.__lastScore ?? 0).toFixed
              ? "this score" : "this score"} is right</b>${esc(p.score_justification)}</div>`;
    }
    if (p.what_would_change_it) {
      h += `<p class="note" style="margin-top:9px"><b>What would change it</b> — ${esc(p.what_would_change_it)}</p>`;
    }
    h += `<p class="note" style="margin-top:12px;opacity:.75">Written by ${esc(p.provider)}
      (${esc(p.model)}). Advisory only — it does not affect the score.</p>`;
    slot.innerHTML = h;
    anime({ targets: slot.querySelectorAll(".tactic"), translateX: [-10, 0],
            delay: anime.stagger(45), duration: 320, easing: "easeOutCubic" });
    return;
  }
  if (p.headline) h += `<p class="headline">${esc(p.headline)}</p>`;
  if (p.summary)  h += `<p class="note" style="margin-bottom:14px">${esc(p.summary)}</p>`;

  if (p.tactics?.length) {
    h += `<div class="tactics">`;
    p.tactics.forEach((t) => {
      h += `<div class="tactic">
        <div class="t-head"><span class="t-icon">${esc(t.icon)}</span>
          <span class="t-name">${esc(t.name)}</span>
          ${t.category ? `<span class="t-cat">${esc(t.category)}</span>` : ""}</div>
        ${t.evidence ? `<div class="t-ev">“${esc(t.evidence)}”</div>` : ""}
        ${t.how_it_works ? `<div class="t-w"><b>Why it works</b> ${esc(t.how_it_works)}</div>` : ""}
        ${t.how_to_spot ? `<div class="t-s"><b>How to spot it</b> ${esc(t.how_to_spot)}</div>` : ""}
      </div>`;
    });
    h += `</div>`;
  }
  if (p.who_it_targets) h += `<p class="note" style="margin-top:12px"><b>Who it targets</b> — ${esc(p.who_it_targets)}</p>`;
  if (p.legitimate_version) h += `<p class="note" style="margin-top:8px"><b>How a real organisation would do this</b> — ${esc(p.legitimate_version)}</p>`;
  if (p.if_you_engaged?.length) {
    h += `<div style="margin-top:12px"><b class="note">If you already replied or clicked</b>
      <ol class="plan" style="margin-top:8px">${p.if_you_engaged.map((s) => `<li>${esc(s)}</li>`).join("")}</ol></div>`;
  }
  h += `<p class="note" style="margin-top:12px;opacity:.75">Written by ${esc(p.provider)}
    (${esc(p.model)}) from the evidence above. Advisory only — it does not affect
    the score, which comes from the local models and rules.</p>`;
  slot.innerHTML = h;
  anime({ targets: slot.querySelectorAll(".tactic"), translateX: [-10, 0],
          delay: anime.stagger(45), duration: 320, easing: "easeOutCubic" });
}

function renderDetail(panel, d) {
  const c = d.card, v = d.verdict, sb = d.severity_breakdown;
  const colour = { CRITICAL: "var(--critical)", HIGH: "var(--high)",
                   MEDIUM: "var(--medium)", LOW: "var(--low)",
                   INFORMATIONAL: "var(--info)" }[c.band];

  const esc = (s) => String(s ?? "").replace(/[&<>"]/g,
    (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[ch]));

  let h = `
  <div class="dhead">
    <button class="icon-btn close" id="dclose" title="Close">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round"><path d="M6 6l12 12M18 6L6 18"/></svg>
    </button>
    <h2>${esc(c.subject)}</h2>
    <div class="sub">${esc(c.display_name ? c.display_name + " · " : "")}${esc(c.sender)}</div>
    <div class="verdictbar">
      <span class="bigscore" style="color:${colour}">${c.score.toFixed(1)}</span>
      <div>
        <div class="lbl" style="color:${colour}">${c.band}</div>
        <div class="sub">${esc(d.attack_vector.name)}</div>
      </div>
    </div>
  </div>

  <div class="sec">
    <h3>Verdict</h3>
    <dl class="kv">
      <dt>Confidence hostile</dt><dd>${(v.probability_malicious * 100).toFixed(1)}%</dd>
      <dt>Model alone</dt><dd>${(v.model_probability * 100).toFixed(1)}%</dd>
      <dt>Decided by</dt><dd>${esc(v.decided_by)}</dd>
      <dt>Vector confidence</dt><dd>${(d.attack_vector.confidence * 100).toFixed(0)}% · ${esc(d.attack_vector.resolved_by)}</dd>
      ${d.attack_vector.mitre_attack.length ? `<dt>MITRE ATT&amp;CK</dt><dd>${d.attack_vector.mitre_attack.join(", ")}</dd>` : ""}
    </dl>
    <p class="note" style="margin-top:11px">${esc(d.attack_vector.description)}</p>
  </div>`;

  if (v.deterministic_floors?.some((f) => f.binding)) {
    h += `<div class="sec"><h3>Caught by rule, not by the model</h3>`;
    v.deterministic_floors.filter((f) => f.binding).forEach((f) => {
      h += `<div class="floor"><div class="n">${esc(f.rule)} → floor ${(f.minimum_confidence*100).toFixed(0)}%</div>
            <div class="w">${esc(f.reason)}</div></div>`;
    });
    h += `<p class="note">The model scored this ${(v.model_probability*100).toFixed(1)}%.
          These conditions are unambiguous regardless of what it learned.</p></div>`;
  }

  h += `
  <div class="sec">
    <h3>How the score was computed</h3>
    <div class="formula">${esc(sb.substituted)}</div>
    <dl class="kv" style="margin-top:11px">
      <dt>intent</dt><dd>${sb.intent.toFixed(3)}</dd>
      <dt>impact</dt><dd>${sb.impact.toFixed(2)} · ${esc(d.attack_vector.name)}</dd>
      <dt>exploitability</dt><dd>${sb.exploitability.toFixed(2)}</dd>
      <dt>targeting</dt><dd>${sb.targeting.toFixed(2)}</dd>
    </dl>
    ${sb.exploitability_signals.length ? `<p class="note" style="margin-top:10px">${
      sb.exploitability_signals.map((s) => "+" + s.weight.toFixed(2) + " " + esc(s.reason)).join("<br>")}</p>` : ""}
  </div>`;

  h += `<div class="sec"${(c.score ?? 0) < (window.__profileMin ?? 15) ? ' style="display:none" id="graph-sec"' : ''}>
          <h3>Attack lineage</h3>
          <div id="graph-slot"><p class="note">Building graph…</p></div></div>`;

  h += `<div class="sec" id="profile-slot" data-owner="${esc(c.id)}">
          ${window.__llm?.any
            ? `<h3>Threat profile</h3><p class="note">Queued…</p>`
            : `<h3>Threat profile</h3><p class="note">Add <code>GEMINI_API_KEY</code>
               or <code>GROQ_API_KEY</code> to <code>.env</code> to see a plain-language
               write-up of the tactics this message uses.</p>`}
        </div>`;

  if (d.evidence_up?.length) {
    h += `<div class="sec"><h3>Why it was flagged</h3>`;
    d.evidence_up.forEach((e) => {
      h += `<div class="ev"><div class="ev-top">
              <span class="ev-shap">${e.shap > 0 ? "+" : ""}${e.shap.toFixed(2)}</span>
              <span class="ev-h">${esc(e.headline)}</span>
              <span class="ev-kind">${esc(e.kind)}</span></div>
            ${e.detail ? `<div class="ev-d">${esc(e.detail)}</div>` : ""}
            ${(e.quotes || []).map((q) => `<div class="ev-q">“${esc(q)}”</div>`).join("")}
            </div>`;
    });
    h += `<p class="note" style="margin-top:10px">Exact TreeSHAP values in log-odds.
          Reconstruction error ${d.model_attribution.shap_additivity_error}.</p></div>`;
  }

  if (d.evidence_down?.length) {
    h += `<div class="sec"><h3>Evidence against</h3>`;
    d.evidence_down.forEach((e) => {
      h += `<div class="ev"><div class="ev-top">
              <span class="ev-shap neg">${e.shap.toFixed(2)}</span>
              <span class="ev-h">${esc(e.headline)}</span>
              <span class="ev-kind">${esc(e.kind)}</span></div></div>`;
    });
    h += `</div>`;
  }

  if (d.counterfactuals?.length) {
    h += `<div class="sec"><h3>What would change the verdict</h3>
          <p class="note">${d.counterfactuals.map(esc).join("<br>")}</p></div>`;
  }

  if (d.tokens?.length) {
    h += `<div class="sec"><h3>Wording signal</h3><div>${
      d.tokens.map((t) => `<span class="token" title="${t.weight.toFixed(3)} log-odds">${esc(t.token)}</span>`).join("")
    }</div></div>`;
  }

  const sa = d.sender_analysis || {};
  const ctx = [];
  if (sa.mailbox_history) ctx.push(["Mailbox history", sa.mailbox_history]);
  if (sa.domain_age) ctx.push(["Domain age", sa.domain_age]);
  if (sa.authentication_results) ctx.push(["Authentication", sa.authentication_results]);
  if (sa.reply_to) ctx.push(["Reply-To", sa.reply_to]);
  (sa.notes || []).forEach((n) => ctx.push(["Sender", n]));
  if (ctx.length) {
    h += `<div class="sec"><h3>Sender context</h3>${
      ctx.map(([k, val]) => `<div class="ioc"><span class="t">${esc(k)}</span><span class="v">${esc(val)}</span></div>`).join("")
    }</div>`;
  }

  const iocs = Object.entries(d.indicators || {}).flatMap(([k, arr]) =>
    (arr || []).map((x) => [k.replace(/_/g, " "), x]));
  if (iocs.length) {
    h += `<div class="sec"><h3>Indicators</h3>${
      iocs.map(([k, val]) => `<div class="ioc"><span class="t">${esc(k)}</span><span class="v">${esc(val)}</span></div>`).join("")
    }</div>`;
  }

  if (d.response_plan?.length) {
    h += `<div class="sec"><h3>Response plan</h3><ol class="plan">${
      d.response_plan.map((s) => `<li>${esc(s)}</li>`).join("")}</ol></div>`;
  }

  panel.innerHTML = h;
  $("#dclose").addEventListener("click", () => {
    $("#main").classList.remove("open");
    document.querySelectorAll(".row.sel").forEach((r) => r.classList.remove("sel"));
  });
}

/* ------------------------------------------------------------------- scan */
function startScan() {
  state.rows = []; state.counts = {}; state.total = 0;
  $("#feed").innerHTML = "";
  $("#main").classList.remove("open");
  refreshStats();

  const q = new URLSearchParams({
    limit: $("#limit").value, query: $("#query").value, mailbox: $("#mailbox").value,
  });
  $("#scan").disabled = true;
  $("#stop").disabled = false;
  $("#scan-label").textContent = "Scanning…";
  $("#dot-engine").className = "dot busy";

  const es = new EventSource(`/api/scan/stream?${q}`);
  state.es = es;

  es.addEventListener("phase", (e) => {
    const d = JSON.parse(e.data);
    $("#feed-status").textContent = d.message;
    if (d.count) state.total = d.count;
  });
  es.addEventListener("message", (e) => {
    const m = JSON.parse(e.data);
    addRow(m);
    $("#feed-status").textContent = `analysing ${m.index} of ${m.total}`;
    $("#feed-count").textContent = `${m.index}/${m.total}`;
    anime({ targets: "#bar", width: `${(m.index / m.total) * 100}%`,
            duration: 240, easing: "linear" });
  });
  es.addEventListener("error", (e) => {
    try { console.warn("message failed:", JSON.parse(e.data).message); } catch {}
  });
  es.addEventListener("fatal", (e) => {
    const d = JSON.parse(e.data);
    $("#feed-status").textContent = `failed — ${d.message}`;
    if (!state.rows.length) {
      $("#feed").innerHTML =
        `<div class="empty"><h3>Scan failed</h3><p>${d.message}</p></div>`;
    }
    endScan();
  });
  es.addEventListener("done", (e) => {
    const d = JSON.parse(e.data);
    $("#feed-status").textContent =
      `${d.count} messages analysed in ${d.seconds}s`;
    endScan();
  });
  es.onerror = () => { if (state.es) endScan(); };
}

function endScan() {
  state.es?.close(); state.es = null;
  $("#scan").disabled = false;
  $("#stop").disabled = true;
  $("#scan-label").textContent = "Scan mailbox";
  $("#dot-engine").className = "dot";
  anime({ targets: "#bar", width: "0%", duration: 600, delay: 500, easing: "easeInQuad" });
}

/* ------------------------------------------------------------------- init */
$("#scan").addEventListener("click", startScan);
$("#stop").addEventListener("click", () => {
  endScan(); $("#feed-status").textContent = "stopped";
});
$("#sort").addEventListener("click", () => {
  state.sort = state.sort === "severity" ? "arrival" : "severity";
  $("#sort").textContent = `Sort: ${state.sort}`;
  rerender();
});
$("#playground").addEventListener("click", () => window.pgOpen());
$("#campaigns").addEventListener("click", () => window.campOpen());
$("#architecture").addEventListener("click", () => window.archOpen());
$("#theme").addEventListener("click", () => {
  const root = document.documentElement;
  root.dataset.theme = root.dataset.theme === "dark" ? "light" : "dark";
  try { localStorage.setItem("shashihook-theme", root.dataset.theme); } catch {}
});
try {
  const saved = localStorage.getItem("shashihook-theme");
  if (saved) document.documentElement.dataset.theme = saved;
} catch {}

loadStatus();
