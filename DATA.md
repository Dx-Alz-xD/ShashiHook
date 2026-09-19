# Data: what is here, what it can teach, and what must be added

## On disk now

| Corpus | Rows used | Malicious | Era | Header fields | Notes |
|---|---:|---:|---|---|---|
| `CEAS_08.csv` | 39,154 | 21,842 | 2008 | sender, receiver, date, urls | CEAS 2008 spam challenge. The richest source here. |
| `Enron.csv` | 29,767 | 13,976 | 2001–02 | subject, body only | Enron ham + injected spam. Best source of genuine business correspondence. |
| `SpamAssasin.csv` | 5,807 | 1,716 | 2002 | sender, receiver, date, urls | Apache SpamAssassin public corpus. Ham is developer mailing lists. |
| `Nigerian_Fraud.csv` | 3,331 | 3,331 | 2002 | sender, receiver, date | 100% advance-fee fraud, no benign rows. |
| `Ling.csv` | 2,859 | 458 | 1990s | subject, body only | Linguist mailing list. Ham is academic discussion. |
| `emails.csv` (spam) | 5,728 | 1,368 | 2001–02 | none | **99.8% duplicated inside `Enron.csv`** — 5,718 of 5,728 removed by de-duplication. |
| `phishing_email.csv` | 82,480 | 42,887 | — | **none** | **Excluded from training.** A stopword-stripped, header-less concatenation of the five corpora above. Training on it alongside its own sources duplicates every row and leaks across the split. |
| `malware.csv` | 138,047 | 41,323 | — | PE header features | Not email. 54 static PE features (section entropy, imports, resources). Unused by the email pipeline — see below. |

After loading and de-duplication: **75,518 unique messages, 49.0% malicious.**

11,128 rows were removed as cross-corpus duplicates. Zero label-conflicting
duplicates were found, which is a good sign about the labels.

### What this data can and cannot teach

It supports the binary intent model very well — ROC-AUC 0.9995 on a held-out
split, 0.956–0.990 when an entire corpus is held out.

It does **not** support the attack-vector taxonomy. Weak-labelling the 37,006
malicious messages produced:

| Vector | Training rows | Verdict |
|---|---:|---|
| spam_unwanted | 7,204 | learnable |
| advance_fee_fraud | 2,983 | learnable |
| recon_probe | 1,886 | learnable |
| credential_phishing | 236 | marginal |
| bec_payment_fraud | 57 | **not learnable** |
| extortion | 24 | **not learnable** |
| malware_delivery | 14 | **not learnable** |
| vendor_invoice_fraud | 13 | **not learnable** |

These corpora predate business email compromise, MFA-fatigue phishing,
QR-code phishing, ISO/LNK malware containers and thread hijacking. The four
highest-impact vectors are precisely the four with no data. That is why the
vector layer is rules-first and why deterministic floors exist.

---

## Added since: the Nazario corpus

`data/nazario/` — 4,966 hand-classified phishing messages as raw mbox, from
<https://monkey.org/~jose/phishing/>, **CC-BY-4.0, Jose Nazario** (attribution
required). Fetch with `python scripts/fetch_corpora.py`.

**Correction to an earlier claim in this file:** the *public* files are
2004–2007, median year 2006 — **zero messages from 2015 or later**. The modern
continuation (`private-phishing4.mbox`) requires contacting the author. This
corpus therefore does *not* fix the vintage problem.

What it did deliver:

| | before | after |
|---|---:|---:|
| `credential_phishing` training rows | 236 | **1,562** |
| `malware_delivery` training rows | 14 | 54 |
| rows carrying `Reply-To` | 0 | 1,308 |
| rows carrying `Return-Path` | 0 | 3,072 |
| rows with real MIME attachments | 0 | 430 |

3,073 of the 4,966 survived de-duplication; the rest already existed in CEAS or
SpamAssassin.

**It is excluded from intent-model training.** Being phishing-only, with no
benign counterpart, adding it pushed the modern probe's false positives from 1
to 4 — a legitimate invoice, a real payment request and a genuine DocuSign all
flagged, because the wording model learned that transactional vocabulary is
hostile. It is used for the vector model, where it is unambiguously valuable.

That exclusion turns it into an honest out-of-distribution test set:

| population | n | recall @0.5 |
|---|---:|---:|
| sources the model trained on | 15,084 | **0.9939** |
| Nazario — never seen in training | 634 | **0.7303** |

**0.73 is the number to quote for "how will this do on phishing I haven't seen".**
It agrees with the 67% measured independently on the modern threat probe.

## Data to add, in order of value

### 1. Modern phishing with full headers — the biggest single gain

| Source | What it gives | Access |
|---|---|---|
| **Nazario phishing corpus** (`monkey.org/~jose/phishing/`) | Raw `.eml`, 2004–present, still updated. Full headers, MIME, attachments. | Free download |
| **SpamAssassin raw corpus** (`spamassassin.apache.org/old/publiccorpus/`) | The raw `.eml` behind the CSV you have — recovers Received chains, SPF/DKIM, real MIME parts | Free |
| **TREC Public Spam Corpora** (2005/2006/2007) | ~250k raw messages with headers, gold labels | Free, registration |
| **Bruce Guenter's spam archive** (`untroubled.org/spam/`) | Monthly raw spam, 1998–present. Gives a time axis to measure drift. | Free |
| **`ealvaradob/phishing-dataset`**, **`zefang-liu/phishing-email-dataset`** (Hugging Face) | Larger aggregated phishing sets | Free |

Raw `.eml` matters more than volume: `sentinel/ingest/eml.py` already extracts
Reply-To divergence, Return-Path mismatch and `Authentication-Results`
(SPF/DKIM/DMARC). Those are among the strongest BEC signals in existence and
**not one of them appears in any CSV you currently have**.

### 2. Business email compromise — the gap that matters most

There is no large public BEC corpus; this is a known, unsolved problem in the
field. Three viable routes, best first:

1. **Your own mail, with analyst verdicts.** A reported-phish button feeding
   labelled messages back is the highest-value data any organisation can get,
   and it is the only source that matches your actual traffic.
2. **Synthetic BEC grounded in Enron.** You already have 15,000+ genuine
   business emails. Generating BEC lures that impersonate real Enron
   correspondents produces training data whose *ham context is real*, which
   is what the synthetic-data failure mode usually gets wrong. Hold out a real
   labelled set for evaluation — never evaluate synthetic on synthetic.
3. **Published IC3/FBI BEC reports and vendor threat reports** for pattern
   documentation to drive rules, not model training.

### 3. URL and domain intelligence — makes the link half of the model real

| Source | Use |
|---|---|
| **PhishTank**, **OpenPhish** | Verified live phishing URLs; feeds `known_bad_iocs` directly |
| **URLhaus** (abuse.ch) | Malware distribution URLs |
| **Tranco list** / **Cisco Umbrella top 1M** | The benign baseline the lookalike detector needs. Would replace the hand-written 40-brand registry in `sentinel/features/brands.py` |
| **Certificate Transparency** (`crt.sh`) | Newly issued certs for lookalike domains — often visible hours before a campaign |
| **RDAP / WHOIS domain age** | Domain registered 3 days ago is one of the strongest single phishing features, and is completely absent here |

### 4. Attachments — connecting the malware data you already have

`malware/malware.csv` (138k PE samples, 54 static features) is currently
unused, because nothing links an email to a binary. To wire it in:

- Train a PE classifier on it and call it from the attachment path, so
  `malware_delivery` becomes a real detection rather than an extension check.
- **EMBER 2018/2024** (Elastic) — 1M samples, the field standard, better
  features than this CSV.
- **SOREL-20M** (Sophos/ReversingLabs) — 20M samples with labels.
- **MalwareBazaar** (abuse.ch) — live hashes, free API, good for IOC matching.
- Note the limitation: modern delivery is ISO/LNK/HTML-smuggling containers,
  not bare PEs, so a PE classifier covers the payload but not the container.

### 5. Taxonomy and enrichment

- **MITRE ATT&CK Enterprise** (STIX bundle, free) — the technique IDs in
  `sentinel/labeling/taxonomy.py` are hand-mapped; the bundle lets you
  validate them and pull mitigations automatically.
- **MISP galaxies** — threat-actor and campaign attribution.

### 6. Benign business mail — to fix false positives

Current false positives are all legitimate bulk mail (newsletters, genuine
DocuSign). The ham here is Enron and 2002 mailing lists; it contains almost no
modern transactional mail.

- **Enron full corpus** (CMU, ~500k messages) — far more than the subset here
- **Avocado Research Email Collection** (LDC2015T03, licensed) — real corporate mail
- Public mailing list archives (Apache, Debian, LKML) for technical ham
- Your own outbound and vendor mail — the only true negative distribution

---

## Legal and ethical notes

- Enron and Avocado contain real personal data. Enron is public record; Avocado
  is licensed and carries usage restrictions. Do not redistribute derived
  datasets that reproduce message bodies.
- Live mailbox data needs a lawful basis and, under GDPR, a DPIA. Prefer
  analyst-labelled reported phish over bulk mailbox ingestion.
- PhishTank and OpenPhish have attribution requirements; check terms before
  redistributing feeds.
- Never train on customer mail without explicit contractual permission.

## Writing-style profiles (stylometry)

`sentinel/stylometry.py` measures 125 topic-independent traits per message —
function-word rates, punctuation rates, sentence and layout habits, greeting and
sign-off form — and stores a running mean per sender. No message text is kept;
`artifacts/style_profiles.json` is chmod 600.

It exists for the case every header check passes: a genuine account that has
been taken over. Real address, valid SPF and DKIM, genuine history, different
person typing.

**Measured on 362 Enron senders** (`scripts/eval_stylometry.py`), profiles built
from 12 messages of 80+ words, scored against held-out mail from the same sender
and from other senders:

| method | mean per-sender AUC |
|---|---|
| cosine on corpus-normalised traits | **0.915** |
| trimmed mean absolute z-score | 0.779 |
| Burrows's Delta | 0.759 |
| per-sender z-calibration | 0.918 (worse operating point) |

Cosine wins because it compares the *shape* of a writer's habits and ignores how
emphatic any single message is.

Ranking well is not the same as accusing well:

| threshold | accuses the real author | catches an impersonator |
|---|---|---|
| 1.036 | 10% | 41% |
| 1.078 | 5% | 27% |
| 1.152 | 1% | 9% |

At a usable false-accusation rate it catches roughly one impersonation in eight.
That is why `sty_drift` is a model feature and **not** a deterministic floor —
telling someone their colleague is compromised is expensive to get wrong.

On a real mailbox the numbers are better, because automated senders are
templated and therefore far more consistent: across 11 senders and 620 held-out
messages, **0.0% of genuine mail** exceeded the shipped threshold while 25.8% of
other-sender mail did.

Build profiles with `scripts/build_style_profiles.py`; the watch daemon then
keeps them current, learning only from mail it has already cleared so that a
suspected impersonation cannot drag the baseline towards the attacker.

## The Learner

Five practice modes. Four are graded without a language model, because each is
graded against something already known to be true.

| mode | what it asks | graded on |
|---|---|---|
| Lesson | written questions about one of your own messages | model, grounded in ArnosAI's evidence |
| Is it hostile? | one corpus message, hostile or not | corpus label |
| Twin test | two look-alike messages, which is the scam | corpus label |
| Find the tell | click the phrase that gives it away | exact lexicon spans |
| Timed triage | sort a stream against a clock | corpus label |

**Only the binary label is used as an answer key.** The vector label — which
*kind* of attack — is derived from weak rules and measures about 68% against
independent labels, so grading a learner on it would mark correct answers wrong
roughly a third of the time.

**The pool** (`scripts/build_practice_pool.py`) draws 1,800 messages from the
training split: 900 benign, 900 malicious of which **720 carry a usable tell**.
A blind sample gave only 194, because most corpus spam is old pharma
advertising that matches no manipulation lexicon, so malicious messages are
sampled span-aware.

**Twins** are the interesting part. For each scam the similarity index finds the
*benign* message it most resembles — pharma spam sits at 0.89 cosine to a
legitimate course-sale email, because both are built on "limited time offer".
320 pairs at 0.64–0.97. Training that only shows lurid fakes teaches "scams look
weird", which is the belief a competent attacker relies on.

**Adaptation** is deterministic, not a request. `available_tactics()` computes
which of the ten tactic families a given message can actually demonstrate, and
the lesson prompt is required to cover the overlap with what the learner keeps
missing. Asking a model to "weight towards weak tactics" was tried first and
ignored both weak spots on a message that plainly showed one.

Progress lives in `artifacts/learners.json`, chmod 600 — what someone is
learning is personal. Every mode feeds the same profile, so missing urgency in
the timed triage changes the questions in the next written lesson.
