# Incident report — MEDIUM (68.3/100)

**Verdict:** MALICIOUS  ·  **Confidence this is hostile:** 88.0%  ·  **Attack vector:** Business Email Compromise / payment fraud

> Queue for analyst review this shift. Quarantine pending a decision.

## Message

| Field | Value |
|---|---|
| Subject | Re: Confidential |
| From | `"Mark Hale" <m.hale@acrne-corp.com>` |
| To | `finance@acme.com` |
| Date | Wed, 10 Sep 2025 11:02:00 +0000 |
| Message ID | `e68eea2bd745594e` |

## Detected by rule, not by the model

The intent model scored this message at **1.4%**. Deterministic detections raised confidence to **88.0%** because the following conditions are unambiguous regardless of what the model learned:

- **`bec_triad`** (floor 88%) — combines a payment instruction, a demand for secrecy and executive or time pressure -- the standard BEC structure

> This matters for triage: the model is trained on 2001-2008 corpora and is measurably blind to business email compromise and modern malware containers. Where a floor fires, trust the rule.

## Why it was scored this way

Severity is not a model output — it is computed by a published rubric so that every point is traceable:

```
100 x intent x (0.5 x impact + 0.3 x exploitability + 0.2 x targeting) + escalators
100 x 0.880 x (0.5 x 1.00 + 0.3 x 0.25 + 0.2 x 0.55) = 60.3  + 8 (thread hijack)  = 68.3
```

| Term | Value | Where it comes from |
|---|---|---|
| intent | 0.880 | raised to a deterministic floor (`bec_triad`); the model itself scored 1.4% |
| impact | 1.00 | taxonomy weight for *Business Email Compromise / payment fraud* |
| exploitability | 0.25 | 1 signal(s), listed below |
| targeting | 0.55 | 3 signal(s), listed below |

**Exploitability — how directly this can be acted on:**

- `+0.25` gives a concrete payment or banking instruction

**Targeting — how specifically aimed it is:**

- `+0.30` appears inside an existing conversation
- `+0.10` is framed as a reply rather than a cold approach
- `+0.15` asks the recipient to keep the request off the record

**Escalators:**

- `+8` **thread hijack** — injected into what looks like an existing thread, which borrows the trust of the real correspondents

## Why it was flagged

The verdict combines two independent views. Structural evidence contributed 18% of the pull and wording 82% (structural log-odds -2.99, wording -2.50; blend weights 0.288 / 1.584).

### Evidence that raised the score

SHAP contributions are exact Shapley values over the structural model, in log-odds. They sum with the base value to reproduce that model's output (reconstruction error 2.9e-10).

Signals marked *indicator* name a concrete property you can hunt or block on. Signals marked *statistical* are real contributors the model learned, but they describe the shape of the text rather than anything actionable.

- **Density of demand for secrecy in the body** `+1.538` *(indicator)*  
  1 match in 40 words
  > "…and I need a wire transfer processed today. Keep this between us until the announcement. I will send the bene…"
- **Density of promise of money or a prize in the body** `+1.325` *(indicator)*  
  1 match in 40 words
  > "…n us until the announcement. I will send the beneficiary account details shortly. This is time-sensit…"
- **Density of payment or banking instruction in the body** `+0.938` *(indicator)*  
  2 matches in 40 words
  > "…e are finalising an acquisition and I need a wire transfer processed today. Keep this between us until…"
  > "…n us until the announcement. I will send the beneficiary account details shortly. This is time-sensitive."
- **Density of time pressure in the body** `+0.599` *(indicator)*  
  1 match in 40 words
  > "…beneficiary account details shortly. This is time-sensitive."
- **Promise of money or a prize in the body** `+0.099` *(indicator)*  
  1 match
  > "…n us until the announcement. I will send the beneficiary account details shortly. This is time-sensit…"
- **Payment or banking instruction in the body** `+0.096` *(indicator)*  
  2 matches
  > "…e are finalising an acquisition and I need a wire transfer processed today. Keep this between us until…"
  > "…n us until the announcement. I will send the beneficiary account details shortly. This is time-sensitive."
- **Demand for secrecy in the body** `+0.077` *(indicator)*  
  1 match
  > "…and I need a wire transfer processed today. Keep this between us until the announcement. I will send the bene…"
- **Time pressure in the body** `+0.063` *(indicator)*  
  1 match
  > "…beneficiary account details shortly. This is time-sensitive."
- **Vocabulary variety raised the score** `+0.508` *(statistical)*  
  observed value: 0.925

### Evidence that argued against

- **Quoted material suggesting an existing thread lowered the score** `-4.505` *(indicator)*  
  observed value: 1
- **Subject formatted as a reply or forward lowered the score** `-2.402` *(indicator)*  
  observed value: 1
- **Number of words in the subject lowered the score** `-0.374` *(statistical)*  
  observed value: 2
- **Punctuation inserted inside words to break up keywords lowered the score** `-0.324` *(statistical)*  
  observed value: 0.025

### Wording

Phrasing most associated with hostile mail in the training corpus: "transfer", "we are", "beneficiary", "account", "the beneficiary", "details".

### What would change the verdict

- Ignoring the wording entirely and judging on structure alone, confidence would be 30.8% instead of 1.4%.

### Detection rules that fired

| Rule | Votes for | Weight | Reason |
|---|---|---|---|
| `lf_bec_payment` | bec_payment_fraud | 2.4 | short, linkless payment request carrying executive authority or secrecy framing |

## Attack vector

**Business Email Compromise / payment fraud** — confidence 90%, resolved by floor `bec_triad`.

Impersonates an executive, supplier or internal finance contact to redirect a payment, payroll deposit or gift-card purchase. Usually carries no link or attachment, which defeats URL and sandbox controls.

**MITRE ATT&CK:** T1566.002, T1534, T1656  ·  **Kill-chain phase:** delivery

## Indicators

| Type | Indicator |
|---|---|
| sender_address | `m.hale@acrne-corp.com` |
| sender_domain | `acrne-corp.com` |

## Response plan

1. Freeze any outbound payment referencing this thread and confirm the request by a phone number already on file — never one from the email.
2. Search the mail estate for other messages from the same sender or reply-to address in the last 30 days.
3. Check whether the spoofed executive's real mailbox shows a new forwarding rule or unfamiliar sign-in.

---

_Generated by Sentinel. Severity is rubric-derived, not learned; attributions are exact TreeSHAP over the structural model and exact linear contributions over the wording model._