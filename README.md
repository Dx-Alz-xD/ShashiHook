# ShashiHook — explainable email threat analysis

Desktop app: **ShashiHook**. Analysis engine: **ArnosAI**.
Run it with `./run.sh` — see [APP.md](APP.md).

Scores an incoming email for **threat severity**, classifies its **attack
vector**, and produces an **incident report that says exactly why**, with
SHAP attributions, quoted evidence and counterfactuals.

```bash
python -m sentinel.cli analyze message.eml           # Markdown incident report
python -m sentinel.cli analyze message.eml --json    # same content as JSON
python -m sentinel.cli demo                          # three built-in samples
uvicorn sentinel.api:app --port 8080                 # POST /analyze

python -m sentinel.cli config                        # check .env, prints no secrets
python -m sentinel.cli auth                          # one-time Gmail OAuth consent
python -m sentinel.cli scan --limit 50 --dry-run     # triage a live mailbox
```

Live Gmail setup is in **[GMAIL.md](GMAIL.md)**. Short version: Gmail has no API
key that can read a mailbox — it needs OAuth 2.0 (read-only, recommended) or an
IMAP app password. Both are supported.

---

## How it decides

Four layers. Each is separately auditable, and the report always says which one
produced the number.

```
email
  │
  ├─ 123 named features ─────────► structural model (LightGBM)  ──┐
  │  sender identity, URL                                         ├─► blender ─► calibrated
  │  structure, attachments,                                      │   (2 coefs)   P(malicious)
  │  18 lexicons, obfuscation                                     │
  └─ full text ──────────────────► wording model (tf-idf + LR) ──┘        │
                                                                          ▼
                              deterministic floors ────────────► final confidence
                              (near-zero-FP rules)                        │
                                                                          ▼
                    attack-vector taxonomy ──────────────────────► severity rubric
                    (rules first, classifier second)                      │
                                                                          ▼
                                                              incident report + SHAP
```

**Why two models instead of one.** The first version fed the wording score into
the tree model as a feature. It scored superbly and explained nothing — TreeSHAP
put +7.5 of 7.66 log-odds on that single input and every interpretable signal
vanished into noise around it. Kept parallel, the structural model reaches
0.9904 ROC-AUC on its own, so SHAP explains a model that genuinely decides.
The blender has exactly two coefficients and both are printed in every report.

**Why severity is not learned.** No corpus here carries a severity label.
Inventing a regression target would mean inventing the ground truth, so severity
is a declared rubric:

```
severity = 100 × intent × (0.50 × impact + 0.30 × exploitability + 0.20 × targeting) + escalators
```

Multiplying by intent rather than adding means an uncertain verdict cannot
produce a confident severity. Every coefficient lives in `sentinel/config.py`,
every input is returned in the breakdown, and the report prints the arithmetic
with the numbers substituted in.

---

## Results

### Held-out test set — 15,103 messages, split by content group

| | ROC-AUC | PR-AUC | Brier | Precision | Recall | FPR |
|---|---:|---:|---:|---:|---:|---:|
| structural view alone | 0.9904 | 0.9909 | 0.037 | | | |
| wording view alone | 0.9996 | 0.9996 | 0.006 | | | |
| **blended + calibrated** | **0.9995** | **0.9992** | **0.005** | 0.9909 | 0.9961 | 0.0088 |
| + deterministic floors | 0.9995 | 0.9992 | 0.005 | 0.9905 | 0.9962 | 0.0092 |

Calibration is honest — predicted 0.973 against observed 0.970 in the top bin.
This matters because severity multiplies by this number.

### Leave-one-corpus-out — the number that actually predicts transfer

| Held-out corpus | n | structural | wording |
|---|---:|---:|---:|
| ceas08 | 35,138 | 0.9115 | 0.9851 |
| enron | 29,008 | 0.7894 | 0.9560 |
| ling | 2,840 | 0.8939 | 0.9897 |
| spamassassin | 5,410 | 0.8803 | 0.9803 |
| **mean** | | **0.8760** | **0.9822** |

**0.9995 → 0.982.** The random split lets the model see every corpus during
training, so it only has to recognise more of the same. Quote the 0.982.

### Current headline numbers

| | |
|---|---:|
| Held-out corpus ROC-AUC | 0.9993 |
| Held-out corpus recall / FPR | 0.9960 / 0.0105 |
| Held-out **Nazario** phishing recall | **0.9968** |
| Modern threat probe | **18/18** |
| Live inbox (150 real messages) | 2 flagged — both deliberate test messages |
| Features · vectors · lexicons | 153 · 18 · 26 |
| Tests | 60 |

### On a real inbox

First contact with live mail (150 messages, IMAP) found the failure that no
offline metric could:

| | uncorrected | with base-rate correction |
|---|---:|---:|
| real inbox flagged | 69/150 | **0/150** |
| MEDIUM alerts (all false positives) | 18 | **0** |
| modern probe threats caught | 18/18 | 16/18 |

The model is calibrated against a 49%-malicious corpus; an inbox is 1–5%.
`SENTINEL_INBOX_BASE_RATE` re-expresses each verdict for the population being
scanned — Bayes on the prior, keeping the likelihood ratio the model learned.
Deterministic floors are exempt, so payload detections hold at any base rate.
See [GMAIL.md](GMAIL.md).

### Output coverage — what 15,103 held-out messages actually produce

7,446 flagged malicious. Every one gets a vector, a severity score and a
response plan:

| | |
|---|---:|
| vector resolved by classifier | 65.0% |
| vector resolved by rule | 32.5% |
| vector resolved by floor | 0.0% |
| left `malicious_unclassified` (routed to analyst) | **2.4%** |
| given a response plan | **100%** |
| with at least one extractable IOC | 61.0% |

Severity distribution across all 15,103 scored messages:

| Band | n | share | truly malicious |
|---|---:|---:|---:|
| HIGH | 1 | 0.0% | 0/1 |
| MEDIUM | 263 | 1.7% | 99.2% |
| LOW | 1,925 | 12.7% | 98.9% |
| INFORMATIONAL | 12,914 | 85.5% | 40.6% |

**This distribution is correct for this corpus, not evidence of a weak rubric.**
70.9% of flagged mail here is bulk spam, which carries impact 0.15 by design —
spam should not generate incidents. The 5,239 malicious messages sitting in
INFORMATIONAL are detected and deprioritised, not missed. On the modern probe
set, where the threat mix is realistic, the same rubric puts 2 messages in HIGH
and 9 in MEDIUM out of 18.

Throughput: 8.2 ms/message for the resolution path, ~93 ms with full SHAP
attribution.

### Modern threat probe — 18 hand-written contemporary attacks, 8 benign controls

| | detection | correct vector |
|---|---:|---:|
| model alone | **12/18 (67%)** — 0/3 BEC, 2/4 malware | 11/18 |
| model + deterministic floors | **18/18 (100%)** | 18/18 |

Two false positives on benign controls (a genuine Stripe newsletter, a genuine
DocuSign), both scored INFORMATIONAL by the severity rubric — the layer
separation contains them.

**This 67% is the most important number in this repository.** The training data
is from 2001–2008 and contains almost no BEC, so a linkless gift-card request
reads as ordinary business correspondence — because in Enron ham, that is
exactly what it is. No tuning fixes that; it is missing data. See `DATA.md`.

---

## Explainability

Every layer is exactly attributable, not approximated:

- **TreeSHAP** over the structural model — exact Shapley values, not sampled.
  Verified by assertion: `base_value + Σ contributions` reproduces the model's
  log-odds to within 1e-9. The test suite fails if it ever stops.
- **Exact linear attribution** over the wording model — each token's
  contribution is precisely `coefficient × tf-idf value`.
- **Counterfactuals are re-run, not read off.** SHAP answers "how much did this
  contribute relative to the baseline"; an analyst asking "what if this weren't
  here" wants the model re-evaluated, and those differ whenever features
  interact. So the model is actually re-evaluated.
- **Every claim quotes its evidence.** Lexicon matches carry exact character
  spans captured during extraction, so the report prints the sentence that
  triggered the signal rather than asserting that a signal existed.
- **Findings are tagged `indicator` or `statistical`** — "sending domain is a
  keystroke from amazon.com" is something you can hunt on; "vocabulary variety"
  is a real contributor but not actionable, and conflating the two makes a
  report sound authoritative about things it shouldn't.
- **Absence is stated as absence.** SHAP can credit a missing signal; the
  narrative says "absence of a reply thread raised the score", never "reply
  thread raised the score" when there is none.

---

## Layout

```
sentinel/
  config.py              every tunable that affects a score
  analyzer.py            orchestrator: email in, explained Analysis out
  features/
    brands.py            impersonated-brand registry, risky TLDs, extensions
    headers.py           sender identity, lookalike and brand-mismatch detection
    urls.py              URL extraction, anchor-vs-href comparison, 19 features
    text.py              structure, obfuscation, homoglyphs, 25 features
    lexicons.py          18 social-engineering lexicons with span capture
    extractor.py         canonical Email record → 123 features + evidence
  labeling/
    taxonomy.py          10 vectors, MITRE mapping, impact weights, playbooks
    weak_rules.py        30 labelling functions with weighted voting
  models/
    intent.py            structural + wording + blender + isotonic calibration
    vector.py            rules-first hybrid; LEARNABLE marks the honest boundary
  explain/
    shap_explainer.py    TreeSHAP, exact token attribution, counterfactuals
    narrative.py         attributions → English, with evidence quotes
  scoring/
    severity.py          the declared rubric
    floors.py            deterministic near-zero-FP detections
  report/incident.py     JSON (SIEM) + Markdown (human), one source
  ingest/eml.py          RFC-5322 → Email, incl. Reply-To / auth results
  ingest/gmail.py        Gmail API, OAuth 2.0, read-only, raw format
  ingest/imap_box.py     IMAP + app password, mailbox opened read-only
  mailbox.py             scan a live mailbox → triage table + reports
  settings.py            .env loading; secrets never logged or reported
  api.py, cli.py

scripts/     build_dataset, train_intent, train_vector, eval_full,
             eval_cross_corpus, eval_probe, build_gold_set, eval_gold
eval/        modern_probe.py — the contemporary threat probe set
tests/       30 tests: SHAP additivity, floor separation, mailbox
             wiring against a fake provider, and assertions that no
             credential ever reaches a generated report
```

## Reproducing

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
python scripts/build_dataset.py      # ~2 min  → artifacts/X.npy, meta.parquet
python scripts/train_intent.py       # ~4 min  → artifacts/intent_model.joblib
python scripts/train_vector.py       # ~1 min  → artifacts/vector_model.joblib
python scripts/eval_full.py          # held-out metrics, floor-by-floor FP rates
python scripts/eval_cross_corpus.py  # leave-one-corpus-out
python scripts/eval_probe.py         # modern threat probe
python -m pytest tests/ -q
```

---

## Known limitations

1. **The vector classifier is trained on weak rules, so its 98.9% is agreement
   with those rules, not accuracy.** Only four of ten vectors have enough
   support to learn from; the rest are rule-only. Run
   `scripts/build_gold_set.py`, label the sample by hand, then
   `scripts/eval_gold.py` to get a real number. Sampling is deliberately skewed
   towards unresolved and low-confidence cases.
2. **55.8% of malicious messages get no vector *rule* vote — but only 2.4% end
   up unresolved at inference.** Those two numbers measure different stages and
   should not be confused. The 55.8% is the weak-labelling pass at training
   time; the classifier then resolves 65.0% of flagged messages, rules 32.5%,
   and 2.4% are left `malicious_unclassified` and routed to a human. No message
   ever produces "no output" — an unresolved vector still carries a severity
   score, SHAP attributions, IOCs and a triage instruction.
3. **`executable_link` is the one floor that needs per-organisation tuning.**
   It fires 3 times on held-out mail and is wrong all 3 — legitimate SourceForge
   and python.net installers. It also produces the *only* HIGH-severity false
   positive in the entire held-out set: a python-win32 release announcement.
   Pass `software_allowlist={"python.net"}` (matched against both sender and
   link domain) and that message drops from HIGH 70.1 to INFORMATIONAL.
4. **The header-authentication floors are only partly measured.** `Reply-To`
   divergence, `Return-Path` mismatch and SPF/DKIM/DMARC failure exist only on
   live mail, so — unlike every other floor, validated against 15,103 held-out
   messages — their false-positive rate is not established. A first scan of a
   real inbox produced two MEDIUM false positives from click-tracking
   redirects; those are now suppressed by DMARC-style alignment checks
   (an authenticated sender cannot be impersonating itself), but keep watching.
5. **Still no live enrichment beyond headers.** Domain age, DNS, URL detonation
   and threat-intel feeds are absent. `known_bad_iocs` accepts a domain list
   today; real feeds are the obvious next integration.
6. **`malware.csv` is unused.** 138k PE samples sit on disk with nothing
   linking an email to a binary. Wiring it in makes `malware_delivery` a real
   detection rather than an extension check.
7. **English only**, and tuned on Western business mail.

## What I'd do next, in order

1. Add the Nazario corpus as raw `.eml` — it is the single highest-value
   addition, and the ingest adapter already extracts the header signals CSVs
   cannot carry.
2. Label the gold set. Right now nobody knows the vector layer's true accuracy.
3. Build synthetic BEC grounded in real Enron correspondents, and hold out a
   real labelled set to evaluate it.
4. Wire in domain age via RDAP — probably the best single feature not present.
5. Replace the hand-written brand registry with the Tranco top-1M.
