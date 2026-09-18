# Connecting Sentinel to Gmail

## First, a correction worth reading

**Gmail has no API key that can read your mailbox.** Google API keys only
authenticate requests for *public* data — they carry no user identity, so they
cannot open a private inbox. Anything that reads your mail must prove it is
acting on your behalf. Two ways to do that:

| | Option A — OAuth 2.0 | Option B — IMAP app password |
|---|---|---|
| Goes in `.env` | client ID + secret | a 16-character app password |
| Access granted | **read-only** (`gmail.readonly`) | **full** — read, send, delete |
| Setup | Google Cloud project, ~5 min | app password, ~1 min |
| Revoke | myaccount.google.com/permissions | delete the app password |
| Password in a file | no | effectively yes |

**Use Option A.** The scope is read-only and there is no code path in this
repo that can modify, label, send or delete anything. Option B exists because
it is one line of setup, but an app password cannot be scoped down — if that
file leaks, someone can send mail as you.

---

## Option A — Gmail API over OAuth 2.0

1. Go to <https://console.cloud.google.com/> and create (or pick) a project.
2. **APIs & Services → Library** → search "Gmail API" → **Enable**.
3. **APIs & Services → OAuth consent screen** → choose **External** → fill in
   the app name and your own email → under **Test users**, add your own Gmail
   address. (Leave it in Testing; no Google verification is needed for
   personal use.)
4. **Credentials → Create credentials → OAuth client ID → Desktop app.**
5. Copy the client ID and secret into `.env`:

```bash
cp .env.example .env
```

```dotenv
GMAIL_CLIENT_ID=1234567890-abcdefg.apps.googleusercontent.com
GMAIL_CLIENT_SECRET=GOCSPX-xxxxxxxxxxxxxxxx
```

6. Authorise once. A browser window opens; approve read-only access.

```bash
.venv/bin/python -m sentinel.cli auth
```

The refresh token is cached at `.gmail_token.json`, chmod `0600`, gitignored.
Revoke any time at <https://myaccount.google.com/permissions>.

---

## Option B — IMAP with an app password

Requires 2-Step Verification. Generate one at
<https://myaccount.google.com/apppasswords>, then:

```dotenv
IMAP_USER=you@gmail.com
IMAP_APP_PASSWORD=abcdefghijklmnop
```

Sentinel opens the mailbox with `readonly=True`, so fetching will not even mark
messages as read.

---

## Troubleshooting the consent screen

Google shows a "Request details" block on its error pages. If your request
contained `scope=...gmail.readonly`, `access_type=offline` and
`redirect_uri=http://localhost:<random-port>/`, the request itself was correct —
the problem is project configuration, not this code.

| Error on screen | Cause | Fix |
|---|---|---|
| **Access blocked: … has not completed the Google verification process** / `access_denied` | Your account is not a **test user**. Owning the project does not make you one. | OAuth consent screen → **Audience** → **Test users** → **Add users** → your own Gmail address → Save |
| **Error 400: redirect_uri_mismatch** | The OAuth client is a **Web application**, which only accepts pre-registered redirect URIs. A random localhost port can never match. | Create a new client of type **Desktop app**. Or add `http://localhost:8080/` to the Web client and run `sentinel auth --port 8080` |
| **Error 403: accessNotConfigured** | Gmail API not enabled on the project. | APIs & Services → Library → Gmail API → **Enable**, wait ~1 min |
| **This app is blocked** | Scope treated as sensitive on a published, unverified app. | Set publishing status back to **Testing** and use test users |

`sentinel auth` now recognises all three and prints the specific fix rather than
the raw OAuth error.

### The test-user gotcha

This is the one that catches nearly everyone, and it is counter-intuitive:
**being the owner of the Cloud project does not grant you access to your own
app.** While publishing status is *Testing*, only addresses explicitly listed
under *Test users* can complete consent — including yours. Add your own Gmail
address there and retry.

Test-user grants expire after 7 days for refresh tokens in Testing mode. If
scans start failing with `invalid_grant` about a week later, re-run
`sentinel auth`.

---

## Running a scan

```bash
.venv/bin/python -m sentinel.cli config                       # verify setup, prints no secrets
.venv/bin/python -m sentinel.cli scan --limit 25 --dry-run    # score, write nothing
.venv/bin/python -m sentinel.cli scan --limit 100             # write reports for MEDIUM+
.venv/bin/python -m sentinel.cli scan --query "is:unread newer_than:2d"
.venv/bin/python -m sentinel.cli scan --source imap --mailbox "[Gmail]/Spam"
```

Output is a triage table sorted by severity:

```
  sev  band            P       vector                 from                     subject
 75.5  HIGH        1.000  credential_phishing    security@ms-verify.tk    Unusual sign-in attempt
 53.2! MEDIUM      0.880  bec_payment_fraud      m.hale@acme.com          Re: Supplier payment
  0.0  INFORMATIONAL 0.000  benign               sam@example.com          Lunch Thursday?
! = verdict set by a deterministic rule, not the model
```

Full incident reports (Markdown + JSON) land in `reports/` for anything at or
above `SENTINEL_MIN_BAND`.

---

## What live mail unlocks that the CSVs could not

The training corpora are flat CSVs with, at best, `sender`, `subject`, `body`,
`urls`. Real RFC-5322 messages carry three headers that are among the strongest
fraud signals in existence, and Sentinel fetches messages in `raw` format
specifically to preserve them:

| Header | Detection |
|---|---|
| `Reply-To` | `reply_to_divergence` — replies route somewhere other than the sending domain |
| `Return-Path` | `return_path_mismatch` — bounces route elsewhere |
| `Authentication-Results` | `failed_authentication_with_lure` — SPF/DKIM/DMARC failure on a message asking for money or credentials |

A spoofed BEC that the **model alone scores 0.526** gets raised to **0.880**
by these three, and is correctly typed as payment fraud.

### Authentication also suppresses false positives

The first scan against a real inbox flagged two legitimate messages at MEDIUM —
a Google account notice and a Neon product announcement — both via
`link_text_mismatch`. Both were click-tracking redirects, which every marketing
platform on earth uses: the link text shows `acme.com`, the href goes through
`click.tracker.example`.

The fix uses the same headers. If DKIM or SPF passes **and aligns** with the
From domain (DMARC-style relaxed alignment, so an ESP signing as
`cio113400.neon.tech` for `neon.tech` counts), the sender has cryptographically
proved it is itself. The whole class of impersonation floors is then
meaningless and is suppressed:

| Suppressed when authenticated | Never suppressed |
|---|---|
| `link_text_mismatch` | `executable_attachment` |
| `brand_impersonation` | `double_extension` |
| `reply_to_divergence` | `macro_enable_lure` |
| `return_path_mismatch` | `password_protected_archive` |

Payload floors are deliberately excluded: an authenticated sender can still be
compromised and ship malware. Authentication proves identity, not innocence.

After this change the same 15 messages scored INFORMATIONAL across the board,
and the modern threat probe still detects 18/18 — those attacks either carry no
authentication or fail it, which is precisely the point.

**These floors remain partly unmeasured.** Every pre-existing floor was
validated against 15,103 held-out messages. The header ones could not be, since
no training message has these headers. The authentication gate removes the
biggest false-positive source, but keep watching them on your own traffic.

---

## The base-rate correction (read this before tuning)

The first 150-message scan of a real inbox flagged **69 of 150** messages and
raised **18 MEDIUM alerts — every one a false positive.** All 18 were
DKIM-authenticated payment receipts, scored on the words "payment",
"transaction" and "paid".

Nothing was broken. The model is calibrated against a training corpus that is
**49% malicious**, and a real inbox is 1–5%. Applying a 49%-prior probability
to a 2%-prior population overstates every verdict. The correction is Bayes:
keep the likelihood ratio the model learned, swap the prior.

```dotenv
SENTINEL_INBOX_BASE_RATE=0.02
```

Measured effect on the same 150 real messages, and on the modern threat probe:

| base rate | real inbox flagged | probe threats caught | probe benign FPs |
|---|---:|---:|---:|
| off (as trained) | 69/150 | 18/18 | 2/8 |
| 5% | 0/150 | 16/18 | 0/8 |
| **2% (default)** | **0/150** | **16/18** | **0/8** |

The cost is real and worth stating: two probe detections are lost — a weak
SharePoint file lure and a contentless "are you available?" probe, both of
which scored 0.526 uncorrected, right on the line. The gain is that the alert
queue stops being 46% noise. An alert queue nobody reads detects nothing.

Raise the number for a higher-risk mailbox, lower it for a quieter one.
**Deterministic floors ignore it completely** — an executable attachment, a BEC
triad or a failed-authentication lure still scores ≥0.85 at any base rate,
which is the safety net that makes the correction safe to apply.

---

## What testing against a real mailbox actually found

Three defects that no offline metric could have surfaced, each found by running
against live mail and each fixed by measuring rather than guessing.

**1. Click-tracking redirects.** 18 MEDIUM alerts, all DKIM-signed payment
receipts, all from `link_text_mismatch`. Fixed by DMARC-style alignment: a
sender that cryptographically proved it is itself cannot be impersonating
itself.

**2. Base-rate mismatch.** 69 of 150 messages flagged. The model is calibrated
on a 49%-malicious corpus; an inbox is ~2%. Fixed with a Bayesian prior
correction — see the section above.

**3. Lexicons tuned to the wrong decade.** A test message reading *"Can you
kindly send me some money, i am ed-sheeran and just requesting for 50000$"*
scored **0.0018 — completely missed**. The `payment` lexicon knew `wire
transfer`, `bank details` and `invoice`: formal 2000s scam vocabulary, with
nothing for a plain informal ask. Added a `money_request` lexicon, an
`identity_claim` lexicon, a currency pattern for suffix notation (`50000$`, not
just `$50000`), and an `unsolicited_money_request` floor.

That floor's first version was worse than the bug: **61 fires on held-out mail,
59 wrong**, every one a newsletter saying "sponsor", "donation" or
"contribution". Rewritten to require four conditions together — a direct
first-person ask, a specific sum, under 150 words, and a cold unauthenticated
contact — it now fires **0 times** on 15,103 held-out messages while still
catching the test.

Final state on the live mailbox: **2 flagged out of 150**, both of them test
messages deliberately sent to trigger it.

| | before | after |
|---|---:|---:|
| real inbox flagged | 69/150 | 2/150 (both tests) |
| MEDIUM false positives | 18 | 0 |
| held-out corpus FPR | 0.82% | 0.86% |
| modern probe | 18/18 | 18/18 |

---

## Privacy

- **Read-only.** `gmail.readonly` scope; IMAP opened `readonly=True`. No
  adapter in this repo calls a mutating endpoint.
- **Nothing leaves your machine.** Messages go provider → memory → local score
  → local disk. There is no outbound network call other than to Gmail itself.
- **Bodies are not stored by default.** Reports quote only the short evidence
  spans that drove the score. `SENTINEL_SAVE_BODIES=true` changes that, and
  then your mail is on disk in `reports/`.
- **`reports/`, `.env` and `.gmail_token.json` are gitignored.** A test asserts
  credentials never appear in generated reports.

## Expect noise on the first run

The models are trained on 2001–2008 corpora. On a modern personal inbox,
newsletters and marketing mail will score high on intent — that is the known
`marketing opt-in` false positive from the probe set. The severity rubric
should hold most of it at INFORMATIONAL, because bulk spam carries impact 0.15.

Start with `--dry-run`, read the table, and treat the first scan as
calibration rather than results.
