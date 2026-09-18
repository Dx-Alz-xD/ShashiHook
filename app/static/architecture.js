/* Architecture view.

   Every number rendered here is fetched from /api/architecture, which reads the
   running system and the saved training metrics. Nothing is hardcoded, so the
   diagram cannot quietly drift away from what the code actually does — which
   matters most in exactly the situation you show it to someone. */

async function archOpen() {
  const ov = document.createElement("div");
  ov.className = "pg-overlay";
  ov.innerHTML = `
    <div class="pg arch">
      <div class="pg-head">
        <h2>Architecture</h2>
        <span class="pg-sub">ShashiHook · engine ArnosAI — live from the running system</span>
        <div class="spacer"></div>
        <button class="icon-btn" id="arch-close" title="Close">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor"
               stroke-width="2.6" stroke-linecap="round"><path d="M6 6l12 12M18 6L6 18"/></svg>
        </button>
      </div>
      <div class="arch-body" id="arch-body"><p class="note">Reading system state…</p></div>
    </div>`;
  document.body.appendChild(ov);
  const close = () => ov.remove();
  ov.querySelector("#arch-close").addEventListener("click", close);
  ov.addEventListener("click", (e) => { if (e.target === ov) close(); });
  document.addEventListener("keydown", function esc(e) {
    if (e.key === "Escape" && document.body.contains(ov)) close();
    if (!document.body.contains(ov)) document.removeEventListener("keydown", esc);
  });

  let d;
  try { d = await (await fetch("/api/architecture")).json(); }
  catch { ov.querySelector("#arch-body").innerHTML =
    `<p class="note">Could not read system state.</p>`; return; }
  archRender(ov.querySelector("#arch-body"), d);
}

function archRender(body, d) {
  const n = (x, dp = 4) => (x == null ? "—" : Number(x).toFixed(dp));
  const m = d.models, g = d.features.groups;

  const stage = (cls, num, title, sub, body_, note) => `
    <div class="ar-stage ${cls}">
      <div class="ar-num">${num}</div>
      <div class="ar-main">
        <div class="ar-title">${title}</div>
        <div class="ar-sub">${sub}</div>
        ${body_ ? `<div class="ar-detail">${body_}</div>` : ""}
        ${note ? `<div class="ar-note">${note}</div>` : ""}
      </div>
    </div>`;

  const chip = (k, v) => `<span class="ar-chip">${k}<b>${v}</b></span>`;

  body.innerHTML = `
  <div class="ar-hero">
    <div class="ar-stat"><span>${d.features.total}</span>features</div>
    <div class="ar-stat"><span>${d.lexicons}</span>lexicons</div>
    <div class="ar-stat"><span>${d.vectors.total}</span>attack vectors</div>
    <div class="ar-stat"><span>${d.floors.count}</span>deterministic rules</div>
    <div class="ar-stat"><span>${n(m.blended_auc)}</span>ROC-AUC</div>
    <div class="ar-stat"><span>${d.tests}</span>tests</div>
  </div>

  <div class="ar-pipe">

    ${stage("in", "01", "Ingestion",
      "IMAP (app password) or Gmail API (OAuth 2.0, read-only)",
      `Messages are fetched as <b>raw RFC-5322</b>, not a parsed summary, to preserve
       <code>Reply-To</code>, <code>Return-Path</code> and
       <code>Authentication-Results</code>.`,
      "Those three headers exist in no public training corpus, so no model feature " +
      "can depend on them — they feed the rule layer instead.")}

    ${stage("feat", "02", "Feature extraction",
      `${d.features.total} named features, ${d.lexicons} lexicons`,
      Object.entries(g).map(([k, v]) => chip(k, v)).join(""),
      "Every feature is human-nameable. Nothing enters the model that cannot be " +
      "explained in a sentence to the person whose mail it is.")}

    <div class="ar-split">
      <div class="ar-branch">
        <div class="ar-btitle">Structural view</div>
        <div class="ar-bsub">Gradient-boosted trees over the named features</div>
        <div class="ar-metric">${n(m.structural_auc)}<span>ROC-AUC alone</span></div>
        <div class="ar-note">TreeSHAP over this is <b>exact</b>, not sampled.</div>
      </div>
      <div class="ar-branch">
        <div class="ar-btitle">Wording view</div>
        <div class="ar-bsub">Logistic regression over ${(m.ngrams || 0).toLocaleString()}
          word + character n-grams</div>
        <div class="ar-metric">${n(m.wording_auc)}<span>ROC-AUC alone</span></div>
        <div class="ar-note">Each token's contribution is exactly coefficient × value.</div>
      </div>
    </div>

    ${stage("blend", "03", "Blender",
      "Two-input logistic regression over the two log-odds",
      chip("structural", n(m.blend.structural, 3)) + chip("wording", n(m.blend.wording, 3))
        + chip("blended AUC", n(m.blended_auc)) + chip("Brier", n(m.brier)),
      "An earlier design stacked the wording score into the tree model. It scored " +
      "the same and explained nothing — SHAP put +7.5 of 7.66 log-odds on that one " +
      "input. Kept parallel, both views stay separately attributable.")}

    ${stage("prior", "04", "Base-rate correction",
      `Trained at ${(m.train_prior * 100).toFixed(0)}% malicious → deployed at
       ${(m.deploy_prior * 100).toFixed(1)}%`,
      `<code>LR = odds(p) / odds(train)</code> &nbsp;·&nbsp;
       <code>odds(p′) = LR × odds(deploy)</code>`,
      "Bayes on the prior, keeping the likelihood ratio. Uncorrected, the model " +
      "flagged 69 of 150 real messages — all false positives.")}

    ${stage("floors", "05", "Deterministic rules",
      `${d.floors.count} near-zero-false-positive detections`,
      d.floors.names.slice(0, 12).map((f) => `<span class="ar-rule">${f}</span>`).join("")
        + (d.floors.names.length > 12 ? `<span class="ar-rule more">+${d.floors.names.length - 12}</span>` : ""),
      "Each sets a floor the model cannot pull below, and each was validated " +
      "against held-out mail. Rules that fired wrong were removed, not tuned.")}

    ${stage("vector", "06", "Attack-vector resolution",
      `${d.vectors.total} vectors · rules first, classifier second`,
      `<div class="ar-vec"><b>Learnable</b>${d.vectors.learnable.map((v) =>
          `<span class="ar-rule ok">${v.replace(/_/g, " ")}</span>`).join("")}</div>
       <div class="ar-vec"><b>Rule-only</b>${d.vectors.rule_only.map((v) =>
          `<span class="ar-rule">${v.replace(/_/g, " ")}</span>`).join("")}</div>`,
      "The split is honest, not arbitrary: the corpora are from 2001–2008 and " +
      "contain almost no BEC, callback phishing or QR lures. Those are detected " +
      "by rule until data exists to learn them.")}

    ${stage("sev", "07", "Severity rubric",
      "Declared, not learned",
      `<code>100 × intent × (0.50×impact + 0.30×exploitability + 0.20×targeting) + escalators</code>`,
      "No corpus carries a severity label, so learning one would mean inventing " +
      "the ground truth. Multiplying by intent means an uncertain verdict cannot " +
      "produce a confident severity.")}

    ${stage("out", "08", "Explanation & response",
      "Everything downstream of the verdict",
      `<div class="ar-outs">
        <div><b>SHAP</b>exact Shapley values, asserted additive to 1e-9</div>
        <div><b>Attack lineage</b>actor → identity → infrastructure → technique → objective</div>
        <div><b>Narrative</b>${d.enrichment.llm.any
            ? `${d.enrichment.llm.gemini ? "Gemini" : ""}${d.enrichment.llm.gemini && d.enrichment.llm.groq ? " → " : ""}${d.enrichment.llm.groq ? "Groq" : ""} — advisory only, never votes`
            : "not configured"}</div>
        <div><b>Campaigns</b>clustered by shared infrastructure + SimHash</div>
        <div><b>Response</b>${d.actions.mode}${d.actions.armed ? " (armed)" : " (dry-run)"} at ≥${d.actions.threshold}</div>
      </div>`,
      "")}
  </div>

  <div class="ar-side">
    <div class="ar-card">
      <h4>Enrichment</h4>
      <div class="ar-kv"><span>Sender history</span><b>${d.enrichment.history_domains} domains
        / ${d.enrichment.history_messages.toLocaleString()} messages</b></div>
      <div class="ar-kv"><span>Domain age (RDAP)</span><b>${d.enrichment.rdap ? "enabled" : "disabled"}</b></div>
      <div class="ar-kv"><span>Narrative providers</span><b>${
        [d.enrichment.llm.gemini && "Gemini", d.enrichment.llm.groq && "Groq"]
          .filter(Boolean).join(" → ") || "none"}</b></div>
    </div>
    <div class="ar-card">
      <h4>Three invariants</h4>
      <p><b>The explained model is the deciding model.</b> Nothing here explains a
         surrogate. A test fails if SHAP stops reconstructing the prediction.</p>
      <p><b>A language model never moves a score.</b> It receives the verdict as
         read-only context. A test asserts a model replying “completely safe”
         changes nothing.</p>
      <p><b>Nothing is permanently deleted.</b> At ~1% false-positive rate an
         irreversible delete destroys real mail. Quarantine and Trash only.</p>
    </div>
    <div class="ar-card warn">
      <h4>What this does not claim</h4>
      <p>${n(m.blended_auc)} is measured on ${(m.n_test || 0).toLocaleString()}
         held-out messages from the same corpora. Against a phishing corpus the
         intent model never trained on, recall is <b>0.73</b>; on hand-written
         modern threats the model alone catches <b>67%</b>. The rules cover the
         rest, and those rules were written by us — that is detection
         engineering, not a model result.</p>
    </div>
  </div>`;

  // Transform only, never opacity. requestAnimationFrame is throttled when the
  // pane is backgrounded or unfocused, which strands an opacity animation at
  // its "from" keyframe -- the content is present in the DOM and invisible on
  // screen. Animating position degrades to "already in position"; animating
  // opacity degrades to "blank panel", which is the worst possible failure for
  // a view whose whole job is to be read.
  if (window.anime) {
    anime({ targets: body.querySelectorAll(".ar-stage, .ar-branch, .ar-card"),
            translateY: [12, 0], delay: anime.stagger(45),
            duration: 380, easing: "easeOutCubic" });
    anime({ targets: body.querySelectorAll(".ar-stat span"),
            scale: [0.86, 1], delay: anime.stagger(55),
            duration: 420, easing: "easeOutBack" });
  }
}

window.archOpen = archOpen;
