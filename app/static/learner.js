/* Learner — practice built from the mail you actually received.

   Opened either from the toolbar (progress + whatever message is selected) or
   from a message's own "View in Learner" button.

   The scoring rule matters more than it looks: an answer counts once, on the
   first attempt, and the profile is told immediately. That is what makes the
   next lesson different from this one, and re-answering until correct would
   turn a measurement of what somebody knows into a measurement of persistence. */

const LEARN = { mid: null, lesson: null, answered: new Set() };

/* Turn a provider failure into something a person can read.

   A raw 429 renders as forty lines of JSON quoting an organisation id and a
   billing URL, which looks like the application is broken. It is not: the
   score, the evidence, the SHAP attribution and every practice mode are local
   and unaffected. Saying so is both true and the only useful thing to say. */
function llmDown(err) {
  const e = String(err || "");
  if (/429|quota|rate limit|tokens per day|TPD/i.test(e)) {
    return "Both AI providers have hit their daily limit. This affects the "
         + "written explanations only — the score, the evidence and every "
         + "practice mode below are computed locally and are unaffected.";
  }
  if (/no API key|not configured|no provider/i.test(e)) {
    return "No AI provider is configured. Add GEMINI_API_KEY or GROQ_API_KEY "
         + "to .env for written explanations; everything else works without one.";
  }
  if (/timeout|timed out/i.test(e)) {
    return "The AI provider did not answer in time. The analysis itself is "
         + "already complete above.";
  }
  return e.slice(0, 200) || "unavailable";
}

function lnEsc(s) {
  return String(s ?? "").replace(/[&<>"]/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

async function learnerOpen(mid) {
  if (mid) LEARN.mid = mid;
  // Never stack. A second panel gives the document two elements with the same
  // id, and getElementById returns the FIRST — so every later render lands in
  // the overlay underneath while the one on screen sits on "Loading…".
  document.querySelectorAll(".pg-overlay.learn-ov").forEach((el) => el.remove());
  const ov = document.createElement("div");
  ov.className = "pg-overlay learn-ov";
  ov.innerHTML = `
    <div class="pg learn">
      <div class="pg-head">
        <h2>Learner</h2>
        <span class="pg-sub">Practice on the mail you were actually sent</span>
        <div class="spacer"></div>
        <button class="icon-btn" id="ln-close" title="Close">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor"
               stroke-width="2.6" stroke-linecap="round"><path d="M6 6l12 12M18 6L6 18"/></svg>
        </button>
      </div>
      <div class="learn-body" id="ln-body"><p class="note">Loading…</p></div>
    </div>`;
  document.body.appendChild(ov);

  const close = () => ov.remove();
  ov.querySelector("#ln-close").addEventListener("click", close);
  ov.addEventListener("click", (e) => { if (e.target === ov) close(); });
  document.addEventListener("keydown", function esc(e) {
    if (e.key === "Escape") { close(); document.removeEventListener("keydown", esc); }
  });

  // Entrance only when frames will actually be delivered. anime's [from, to]
  // syntax applies `from` immediately, so a throttled requestAnimationFrame --
  // background tab, reduced power, an automated browser -- leaves the panel
  // parked at scale 0.97 forever. Skipping it costs an animation; running it
  // blind costs a permanently wrong layout.
  if (typeof anime !== "undefined" && document.visibilityState === "visible") {
    anime({ targets: ov.querySelector(".pg"), scale: [0.97, 1], translateY: [10, 0],
            duration: 260, easing: "easeOutCubic",
            complete: () => { ov.querySelector(".pg").style.transform = ""; } });
  }
  await learnerRender();
}

async function learnerRender() {
  const body = document.getElementById("ln-body");
  if (!body) return;

  let profile = null;
  try {
    profile = await (await fetch("/api/learn/profile",
      { credentials: "same-origin" })).json();
  } catch (e) { /* progress is a nicety; the lesson is the point */ }

  let h = profile ? learnerProgress(profile) : "";

  h += practiceTabs("lesson");

  if (!LEARN.mid) {
    h += `<div class="ln-empty">
      <h3>Practise now, or pick a message</h3>
      <p class="note">The four modes above draw on 81,234 labelled messages,
         so you can practise attack types that have never reached your inbox.
         For a lesson about your own mail, close this, click a scored message
         and press <strong>View in Learner</strong>.</p></div>`;
    body.innerHTML = h;
    pxWire(body);
    return;
  }

  body.innerHTML = h + `<p class="note" id="ln-loading">Building a lesson aimed at
     what you have been getting wrong…</p>`;

  let d;
  try {
    d = await (await fetch(`/api/learn/${encodeURIComponent(LEARN.mid)}`,
      { credentials: "same-origin" })).json();
  } catch (e) {
    d = { ok: false, error: String(e) };
  }
  LEARN.lesson = d;

  if (!d.ok) {
    body.innerHTML = h + `<div class="ln-empty"><h3>Could not build a lesson</h3>
      <p class="note">${lnEsc(llmDown(d.error))}</p></div>`;
    return;
  }

  const m = d.message || {};
  h += `<div class="ln-lesson">
    <div class="ln-msg">
      <span class="ln-score">${(m.score ?? 0).toFixed(1)}</span>
      <div><div class="ln-subj">${lnEsc(m.subject || "(no subject)")}</div>
      <div class="ln-from">${lnEsc(m.sender || "")} · ${lnEsc(m.vector || "")}</div></div>
    </div>
    <h3>${lnEsc(d.headline)}</h3>
    <p class="ln-brief">${lnEsc(d.briefing)}</p>`;

  if (d.focus?.length) {
    h += `<div class="ln-focus">Aimed at: ${
      d.focus.map((f) => `<span>${lnEsc(f.label)}</span>`).join("")}</div>`;
  }

  h += `<div class="ln-qs">`;
  d.questions.forEach((q, i) => {
    h += `<div class="ln-q" data-i="${i}" data-tactic="${lnEsc(q.tactic)}"
               data-answer="${q.answer}">
      <div class="ln-q-top"><span class="ln-n">${i + 1}</span>
        <span class="ln-qt">${lnEsc(q.q)}</span></div>
      <div class="ln-opts">${q.options.map((o, j) =>
        `<button class="ln-o" data-j="${j}">${lnEsc(o)}</button>`).join("")}</div>
      <div class="ln-why">${lnEsc(q.why)}</div></div>`;
  });
  h += `</div>`;

  const p = d.pattern || {};
  if (p.name) {
    h += `<div class="ln-pattern">
      <div class="ln-ptag">The pattern</div>
      <h4>${lnEsc(p.name)}</h4>
      <p>${lnEsc(p.how_it_runs)}</p>
      ${(p.tells || []).length ? `<ul class="ln-tells">${
        p.tells.map((t) => `<li>${lnEsc(t)}</li>`).join("")}</ul>` : ""}
      ${p.elsewhere ? `<p class="ln-else">${lnEsc(p.elsewhere)}</p>` : ""}
    </div>`;
  }
  if (d.takeaway) h += `<div class="ln-take">${lnEsc(d.takeaway)}</div>`;
  h += `</div>`;
  body.innerHTML = h;

  pxWire(body);
  body.querySelectorAll(".ln-q").forEach(learnerWire);
  if (typeof anime !== "undefined" && document.visibilityState === "visible") {
    anime({ targets: body.querySelectorAll(".ln-q, .ln-pattern, .ln-take"),
            translateY: [10, 0], delay: anime.stagger(55), duration: 320,
            easing: "easeOutCubic" });
  }
}

function learnerWire(card) {
  const right = Number(card.dataset.answer);
  const tactic = card.dataset.tactic;
  card.querySelectorAll(".ln-o").forEach((btn) => {
    btn.addEventListener("click", async () => {
      if (card.classList.contains("done")) return;
      card.classList.add("done");
      const picked = Number(btn.dataset.j);
      const correct = picked === right;
      card.querySelectorAll(".ln-o").forEach((b, j) => {
        if (j === right) b.classList.add("right");
        else if (j === picked) b.classList.add("wrong");
        b.disabled = true;
      });
      const why = card.querySelector(".ln-why");
      why.classList.add("show");
      if (typeof anime !== "undefined") {
        anime({ targets: why, translateY: [-6, 0], duration: 240, easing: "easeOutCubic" });
      }
      // First answer only. Recorded straight away, because this is what steers
      // the next lesson.
      try {
        const r = await fetch("/api/learn/answer", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
          body: JSON.stringify({ tactic, correct }),
        });
        if (r.ok) learnerUpdateProgress(await r.json());
      } catch (e) { /* a lost answer must not break the lesson */ }
    });
  });
}

function learnerProgress(p) {
  const pct = Math.round((p.accuracy || 0) * 100);
  return `<div class="ln-prog" id="ln-prog">
    <div class="ln-stats">
      <div><b id="ln-lvl">${lnEsc(p.level)}</b><span>level</span></div>
      <div><b id="ln-acc">${p.answered ? pct + "%" : "–"}</b><span>accuracy</span></div>
      <div><b id="ln-ans">${p.answered}</b><span>answered</span></div>
      <div><b id="ln-str">${p.streak}</b><span>streak</span></div>
    </div>
    <div class="ln-bars">${p.tactics.map((t) => `
      <div class="ln-bar" title="${lnEsc(t.label)} — ${t.correct}/${t.seen}">
        <div class="ln-bar-fill${t.settled && t.accuracy < 0.75 ? " weak" : ""}"
             style="height:${t.seen ? Math.max(Math.round(t.accuracy * 100), 4) : 0}%"></div>
        <span>${lnEsc(t.key.replace("_", " "))}</span>
      </div>`).join("")}</div>
  </div>`;
}

function learnerUpdateProgress(p) {
  const lvl = document.getElementById("ln-lvl");
  if (!lvl) return;
  lvl.textContent = p.level;
  document.getElementById("ln-acc").textContent =
    p.answered ? Math.round(p.accuracy * 100) + "%" : "–";
  document.getElementById("ln-ans").textContent = p.answered;
  const s = document.getElementById("ln-str");
  s.textContent = p.streak;
  if (typeof anime !== "undefined") {
    anime({ targets: s, scale: [1.3, 1], duration: 300, easing: "easeOutBack" });
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const b = document.getElementById("learner");
  if (b) b.addEventListener("click", () => learnerOpen(null));
});

/* ---------------------------------------------------------------- practice
   Four exercises drawn from the corpus, graded without a provider call.

   The answer key never reaches the browser with the question — the server
   withholds the label and the spans until an answer is submitted. Putting them
   in the page would hide them exactly where a curious person looks first. */

const PRACTICE = { mode: null, ex: null, triage: null };

// The progress header is rendered once and carried across mode switches.
// Rebuilding the whole body for each exercise threw it away, so the counters
// that every answer updates had nothing to write to and quietly stopped
// moving while the server-side profile carried on changing.
let PX_PROGRESS = "";

async function practiceStart(mode) {
  PRACTICE.mode = mode;
  const body = document.getElementById("ln-body");
  const existing = body.querySelector("#ln-prog");
  if (existing) PX_PROGRESS = existing.outerHTML;
  body.innerHTML = PX_PROGRESS + `<p class="note">Loading an exercise…</p>`;
  let ex;
  try {
    const r = await fetch(`/api/practice/${mode}`, { credentials: "same-origin" });
    ex = await r.json();
    if (!r.ok) throw new Error(ex.detail || "unavailable");
  } catch (e) {
    body.innerHTML = PX_PROGRESS + `<div class="ln-empty"><h3>Could not load</h3>
      <p class="note">${lnEsc(llmDown(e.message))}</p></div>` + practiceTabs(mode);
    return;
  }
  PRACTICE.ex = ex;
  ({ drill: pxDrill, twin: pxTwin, highlight: pxHighlight, triage: pxTriage }[mode])(ex);
}

function practiceTabs(active) {
  // Prepended by each mode's render, so progress survives a mode switch.
  const modes = [["lesson", "Lesson"], ["drill", "Is it hostile?"],
                 ["twin", "Twin test"], ["highlight", "Find the tell"],
                 ["triage", "Timed triage"]];
  return `<div class="px-tabs">${modes.map(([k, label]) =>
    `<button class="px-tab${k === active ? " on" : ""}" data-mode="${k}">${label}</button>`
  ).join("")}</div>`;
}

function pxWire(body) {
  body.querySelectorAll(".px-tab").forEach((b) => {
    b.addEventListener("click", () => {
      if (b.dataset.mode === "lesson") { PRACTICE.mode = null; learnerRender(); }
      else practiceStart(b.dataset.mode);
    });
  });
  const next = body.querySelector("#px-next");
  if (next) next.addEventListener("click", () => practiceStart(PRACTICE.mode));
}

function pxMsg(m, cls = "") {
  return `<div class="px-msg ${cls}" data-id="${lnEsc(m.id)}">
    <div class="px-from">${lnEsc(m.sender || "(unknown sender)")}</div>
    <div class="px-subj">${lnEsc(m.subject)}</div>
    <div class="px-body">${lnEsc(m.body)}</div>
    <div class="px-src">${m.source === "simulated"
      ? "simulated for training — not a real message"
      : "from the " + lnEsc(m.source) + " corpus"}</div></div>`;
}

async function pxSubmit(payload) {
  const r = await fetch("/api/practice/answer", {
    method: "POST", headers: { "Content-Type": "application/json" },
    credentials: "same-origin", body: JSON.stringify(payload),
  });
  const d = await r.json();
  if (r.ok && d.profile) learnerUpdateProgress(d.profile);
  return d;
}

function pxVerdict(ok, text) {
  return `<div class="px-verdict ${ok ? "ok" : "no"}">
    <b>${ok ? "Correct" : "Not this time"}</b> ${lnEsc(text)}</div>`;
}

// ------------------------------------------------------------------ drill
function pxDrill(ex) {
  const body = document.getElementById("ln-body");
  body.innerHTML = PX_PROGRESS + practiceTabs("drill") + `
    <p class="px-prompt">${lnEsc(ex.prompt)}</p>
    ${pxMsg(ex.message)}
    <div class="px-choices">${ex.options.map((o, i) =>
      `<button class="px-choice" data-hostile="${i === 0}">${lnEsc(o)}</button>`).join("")}</div>
    <div id="px-after"></div>`;
  pxWire(body);
  body.querySelectorAll(".px-choice").forEach((b) => {
    b.addEventListener("click", async () => {
      body.querySelectorAll(".px-choice").forEach((x) => { x.disabled = true; });
      const d = await pxSubmit({ mode: "drill", item_id: ex.message.id,
                                 said_hostile: b.dataset.hostile === "true" });
      b.classList.add(d.correct ? "right" : "wrong");
      document.getElementById("px-after").innerHTML =
        pxVerdict(d.correct, d.why) + pxSpanList(d.spans) +
        `<button class="btn" id="px-next">Next</button>`;
      pxWire(body);
    });
  });
}

function pxSpanList(spans) {
  if (!spans || !spans.length) return "";
  return `<div class="px-tells"><b>What the detector matched</b>${
    spans.slice(0, 6).map((s) =>
      `<span class="px-tell">${lnEsc(s.term)}<em>${lnEsc(s.lexicon)}</em></span>`
    ).join("")}</div>`;
}

// ------------------------------------------------------------------- twin
function pxTwin(ex) {
  const body = document.getElementById("ln-body");
  body.innerHTML = PX_PROGRESS + practiceTabs("twin") + `
    <p class="px-prompt">${lnEsc(ex.prompt)}
      <span class="px-sim">these two are ${Math.round(ex.similarity * 100)}% alike</span></p>
    <div class="px-pair">${ex.messages.map((m, i) =>
      `<div class="px-col"><button class="px-pick" data-i="${i}">This one</button>
       ${pxMsg(m)}</div>`).join("")}</div>
    <div id="px-after"></div>`;
  pxWire(body);
  body.querySelectorAll(".px-pick").forEach((b) => {
    b.addEventListener("click", async () => {
      body.querySelectorAll(".px-pick").forEach((x) => { x.disabled = true; });
      const chose = Number(b.dataset.i);
      const scam = ex.messages[ex.answer_index];
      const d = await pxSubmit({ mode: "twin", item_id: scam.id,
                                 said_hostile: chose === ex.answer_index });
      body.querySelectorAll(".px-pick")[ex.answer_index].classList.add("right");
      if (chose !== ex.answer_index) b.classList.add("wrong");
      document.getElementById("px-after").innerHTML =
        pxVerdict(chose === ex.answer_index,
          "The scam is the one now marked green. The other is genuine mail.") +
        pxSpanList(d.spans) + `<button class="btn" id="px-next">Next pair</button>`;
      pxWire(body);
    });
  });
}

// -------------------------------------------------------------- highlight
function pxHighlight(ex) {
  const body = document.getElementById("ln-body");
  body.innerHTML = PX_PROGRESS + practiceTabs("highlight") + `
    <p class="px-prompt">${lnEsc(ex.prompt)}
      <span class="px-sim">${ex.n_tells} to find — one is enough</span></p>
    <div class="px-msg clickable">
      <div class="px-from">${lnEsc(ex.message.sender || "(unknown sender)")}</div>
      <div class="px-subj">${lnEsc(ex.message.subject)}</div>
      <div class="px-body" id="px-clickbody">${
        [...ex.message.body].map((ch, i) =>
          `<span data-o="${i}">${lnEsc(ch)}</span>`).join("")}</div>
    </div>
    <div id="px-after"></div>`;
  pxWire(body);
  const area = document.getElementById("px-clickbody");
  area.addEventListener("click", async (e) => {
    if (area.dataset.done) return;
    const off = Number(e.target.dataset?.o);
    if (Number.isNaN(off)) return;
    area.dataset.done = "1";
    const d = await pxSubmit({ mode: "highlight", item_id: ex.message.id, offset: off });
    // Mark every real tell, not only the one they found — the others are the
    // lesson.
    (d.spans || []).forEach((s) => {
      for (let i = s.start; i < s.end; i++) {
        const c = area.querySelector(`[data-o="${i}"]`);
        if (c) c.classList.add(d.hit && s.start === d.hit.start ? "found" : "missed");
      }
    });
    document.getElementById("px-after").innerHTML =
      pxVerdict(d.correct, d.correct
        ? `That is a ${d.hit.lexicon.replace(/_/g, " ")} cue.`
        : "The phrases the detector matched are underlined.") +
      pxSpanList(d.spans) + `<button class="btn" id="px-next">Another message</button>`;
    pxWire(body);
  });
}

// ----------------------------------------------------------------- triage
function pxTriage(ex) {
  PRACTICE.triage = { i: 0, right: 0, ex, left: ex.seconds, timer: null };
  pxTriageStep();
}

function pxTriageStep() {
  const t = PRACTICE.triage;
  const body = document.getElementById("ln-body");
  if (t.i >= t.ex.messages.length || t.left <= 0) {
    clearInterval(t.timer);
    const total = Math.min(t.i, t.ex.messages.length);
    body.innerHTML = PX_PROGRESS + practiceTabs("triage") + `
      <div class="ln-empty"><h3>${t.right} of ${total} correct</h3>
      <p class="note">${t.left <= 0 ? "Time ran out. " : ""}Speed matters because
         the real failure is not being unable to tell — it is not looking,
         forty messages in.</p>
      <button class="btn btn-primary" id="px-next">Run it again</button></div>`;
    pxWire(body);
    return;
  }
  const m = t.ex.messages[t.i];
  body.innerHTML = PX_PROGRESS + practiceTabs("triage") + `
    <div class="px-timer"><span id="px-clock">${t.left}</span>s
      · ${t.i + 1} of ${t.ex.messages.length} · ${t.right} correct</div>
    ${pxMsg(m)}
    <div class="px-choices">
      <button class="px-choice" data-hostile="true">Suspicious</button>
      <button class="px-choice" data-hostile="false">Safe</button>
    </div>`;
  pxWire(body);
  if (!t.timer) {
    t.timer = setInterval(() => {
      t.left -= 1;
      const c = document.getElementById("px-clock");
      if (c) c.textContent = t.left;
      if (t.left <= 0) pxTriageStep();
    }, 1000);
  }
  body.querySelectorAll(".px-choice").forEach((b) => {
    b.addEventListener("click", async () => {
      body.querySelectorAll(".px-choice").forEach((x) => { x.disabled = true; });
      const d = await pxSubmit({ mode: "triage", item_id: m.id,
                                 said_hostile: b.dataset.hostile === "true" });
      if (d.correct) t.right += 1;
      b.classList.add(d.correct ? "right" : "wrong");
      setTimeout(() => { t.i += 1; pxTriageStep(); }, 520);
    });
  });
}
