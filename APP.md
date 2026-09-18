# ShashiHook

Desktop application for email threat analysis. The engine is **ArnosAI** — the
models, rules and explainability layers in `sentinel/`.

```bash
./run.sh
```

Opens on <http://127.0.0.1:8420>.

---

## Why a local web app, not Electron or Tauri

The engine is Python: LightGBM for the structural model, scikit-learn for the
wording model, SHAP for attribution. None of that runs in a browser or in Node.

A native shell would therefore still need this exact Python process running
underneath it — Electron would add a ~120 MB Chromium runtime and a packaging
pipeline to wrap something that could not work without Python anyway, and Tauri
would still need a sidecar. Neither removes a single dependency.

A local FastAPI app is one command, one process, no build step, and the UI is
just as custom. If it ever needs to look like a native window, the same server
can be wrapped later without touching the engine.

---

## The dashboard

**Live feed.** Results stream over Server-Sent Events, one message at a time, so
the feed fills as ArnosAI works rather than sitting blank and then dumping
everything at once. Rows sort by severity as they arrive.

Each row shows severity score, band, subject, sender, the attack vector, and two
badges that matter for triage:

| Badge | Meaning |
|---|---|
| `rule` | the verdict was set by a deterministic rule, not the model — hover for which |
| `dkim` | sender authentication passed and aligned with the From domain |

**Detail panel.** Click any row for the full analysis:

- the severity formula with this message's numbers substituted in
- every SHAP contribution in log-odds, tagged *indicator* (actionable) or
  *statistical* (real but not huntable), each quoting the text that triggered it
- what the model alone scored, versus what any deterministic floor raised it to
- counterfactuals — what the verdict would have been without each signal
- sender context: mailbox history, domain age, authentication, Reply-To
- extracted indicators and the vector's response plan

Nothing in the panel is generated prose. Every number comes from the same
analysis object the CLI and the JSON API return.

---

## Narrative threat profiling

Clicking a message shows the deterministic analysis immediately — score,
formula, SHAP evidence — and then a **threat profile** fills in beside it: a
plain-language write-up of the manipulation tactics the message uses, and how
to recognise each one next time.

Set either key in `.env`; **Gemini is tried first, Groq is the fallback**:

```dotenv
GEMINI_API_KEY=          # https://aistudio.google.com/apikey
GROQ_API_KEY=            # https://console.groq.com/keys
# GEMINI_MODEL=gemini-2.0-flash
# GROQ_MODEL=llama-3.3-70b-versatile
# LLM_PRIMARY=gemini     # flip to groq to reverse the order
```

Each tactic comes back with its category, a short quote from the message as
evidence, why it works on people, and what to look for next time:

> **⏱ Manufactured urgency** · urgency
> *"Review deadline: September 18 — 6:00 PM IST"*
> **Why it works** A deadline suppresses the pause where you would check.
> **How to spot it** Real settlement teams do not give you the same afternoon.

### Three properties this was built to hold

**The model never touches a score.** The verdict, severity and attack vector are
produced by ArnosAI from measurable evidence before any API call is made, and
the profiler receives them as read-only context. If a language model could move
a score, the score would stop being auditable — and an attacker who can write
text would gain a way to argue out of a detection instead of having to evade the
filter. There is a test asserting that a model returning *"this message is
completely safe"* changes nothing.

**Email content is untrusted data.** A hostile message can contain text aimed at
the model reading it. The body is fenced with explicit markers, labelled
untrusted in both the system and user prompts, and the model is instructed never
to follow instructions found inside it.

**It fails soft.** No key, a rate limit, a timeout, malformed JSON, a provider
outage — profiling is simply unavailable and everything else is unaffected. The
detection engine never depended on a network call and does not start now.

Profiles are cached in `artifacts/threat_profiles.json` (mode 0600, gitignored),
so reopening a message costs nothing.

---

## Controls

| Control | Notes |
|---|---|
| Mailbox | INBOX, Spam, All Mail, Important |
| Query | Gmail search syntax, e.g. `is:unread newer_than:2d` |
| Limit | messages to fetch |
| Sort | severity (default) or arrival order |
| Theme | dark/light, follows your choice and persists |

---

## API

The dashboard is a client of a normal HTTP API, so the same data is available
to any other tool:

| Endpoint | Purpose |
|---|---|
| `GET /api/status` | engine readiness, feature and vector counts, blend weights |
| `GET /api/scan/stream` | SSE — one event per message as it is scored |
| `POST /api/analyze` | score a single message (`raw` RFC-822, or subject/body) |
| `GET /api/message/{id}` | full analysis for a message from this session |

```bash
curl -N "http://127.0.0.1:8420/api/scan/stream?limit=10&mailbox=INBOX"
```

---

## Privacy

- The server binds to `127.0.0.1` only. Nothing is reachable from the network.
- The only outbound connection is to your own mail server, plus RDAP if you
  explicitly enable it.
- Message bodies are held in memory for the session so the detail panel can
  render, and are not written to disk unless you export a report.
- Credentials are read from `.env` and never appear in the API, the UI or any
  report — there is a test asserting it.
