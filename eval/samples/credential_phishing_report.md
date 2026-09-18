# Incident report — HIGH (75.5/100)

**Verdict:** MALICIOUS  ·  **Confidence this is hostile:** 100.0%  ·  **Attack vector:** Credential phishing

> Contain within the hour. Purge, block indicators, and check whether anyone interacted with the message.

## Message

| Field | Value |
|---|---|
| Subject | Unusual sign-in attempt blocked |
| From | `"Microsoft account team" <account-security@microsoft-secure.help>` |
| To | `jane.doe@acme.com` |
| Date | Fri, 12 Sep 2025 06:30:00 +0000 |
| Message ID | `dca5d42db430dfa4` |

_Deterministic detections also matched but did not change the verdict: `brand_impersonation`, `link_text_mismatch`._

## Why it was scored this way

Severity is not a model output — it is computed by a published rubric so that every point is traceable:

```
100 x intent x (0.5 x impact + 0.3 x exploitability + 0.2 x targeting) + escalators
100 x 1.000 x (0.5 x 0.85 + 0.3 x 1.00 + 0.2 x 0.15) = 75.5
```

| Term | Value | Where it comes from |
|---|---|---|
| intent | 1.000 | calibrated P(malicious) from the intent model |
| impact | 0.85 | taxonomy weight for *Credential phishing* |
| exploitability | 1.00 | 5 signal(s), listed below |
| targeting | 0.15 | 1 signal(s), listed below |

**Exploitability — how directly this can be acted on:**

- `+0.35` links to a sign-in or verification page the recipient can submit credentials to right now
- `+0.20` hides the real destination behind trusted-looking link text
- `+0.20` dresses a hostile domain up as a known brand
- `+0.20` asks outright for credentials
- `+0.10` contains at least one clickable link

**Targeting — how specifically aimed it is:**

- `+0.15` impersonates a specific named party

## Why it was flagged

The verdict combines two independent views. Structural evidence contributed 8% of the pull and wording 92% (structural log-odds +1.77, wording +3.49; blend weights 0.288 / 1.584).

### Evidence that raised the score

SHAP contributions are exact Shapley values over the structural model, in log-odds. They sum with the base value to reproduce that model's output (reconstruction error 1.3e-09).

Signals marked *indicator* name a concrete property you can hunt or block on. Signals marked *statistical* are real contributors the model learned, but they describe the shape of the text rather than anything actionable.

- **Density of request for credentials in the body** `+0.842` *(indicator)*  
  1 match in 33 words
  > "…a notification on your authenticator app to confirm your identity."
  > "Unusual sign-in attempt blocked"
- **Absence of subject formatted as a reply or forward raised the score** `+0.715` *(indicator)*  
  the model treats its absence as evidence here
- **Absence of quoted material suggesting an existing thread raised the score** `+0.703` *(indicator)*  
  the model treats its absence as evidence here
- **Request for credentials in the body** `+0.550` *(indicator)*  
  1 match
  > "…a notification on your authenticator app to confirm your identity."
  > "Unusual sign-in attempt blocked"
- **Absence of sender and recipient sharing a domain raised the score** `+0.101` *(indicator)*  
  the model treats its absence as evidence here
- **Length of the sending domain raised the score** `+1.471` *(statistical)*  
  sender: account-security@microsoft-secure.help
- **Length of the mailbox name raised the score** `+1.427` *(statistical)*  
  sender: account-security@microsoft-secure.help
- **Vocabulary variety raised the score** `+0.802` *(statistical)*  
  observed value: 0.878788
- **Proportion of the message that is link text raised the score** `+0.736` *(statistical)*  
  observed value: 0.318182

### Evidence that argued against

- **Length of the longest link lowered the score** `-1.592` *(statistical)*  
  observed value: 52
- **Number of links lowered the score** `-0.675` *(statistical)*  
  observed value: 2
- **Average link length lowered the score** `-0.524` *(statistical)*  
  observed value: 42.5
- **HTML formatting lowered the score** `-0.496` *(statistical)*  
  observed value: 1

### Wording

Phrasing most associated with hostile mail in the training corpus: "your", "you will", "you", "nigeria".

### What would change the verdict

- Ignoring the wording entirely and judging on structure alone, confidence would be 52.6% instead of 100.0%.

### Detection rules that fired

| Rule | Votes for | Weight | Reason |
|---|---|---|---|
| `lf_credential_link` | credential_phishing | 2.6 | asks the reader to verify credentials and supplies a link |
| `lf_brand_spoof_link` | credential_phishing | 2.3 | impersonates a brand it does not own and links away |
| `lf_anchor_mismatch` | credential_phishing | 2.1 | link text displays a different domain from the actual href |

## Attack vector

**Credential phishing** — confidence 100%, resolved by rule.

Drives the recipient to a counterfeit sign-in page to harvest usernames, passwords and increasingly MFA codes via reverse proxy.

**MITRE ATT&CK:** T1566.002, T1056.003, T1111  ·  **Kill-chain phase:** delivery

## Indicators

| Type | Indicator |
|---|---|
| sender_address | `account-security@microsoft-secure.help` |
| sender_domain | `microsoft-secure.help` |
| urls | `https://login.microsoftonline.com` |
| urls | `https://microsoft-secure.help/auth/verify?u=jane.doe` |
| url_domains | `microsoft-secure.help` |
| url_domains | `microsoftonline.com` |

### Sender

- display name claims 'microsoft' but the message was sent from microsoft-secure.help, which microsoft does not own

### Links

- `https://login.microsoftonline.com`
- `https://microsoft-secure.help/auth/verify?u=jane.doe`
  - path targets a sign-in or account-verification page
  - contains the brand 'microsoft' while actually resolving to microsoft-secure.help
  - link text reads 'https://login.microsoftonline.com' but the href actually goes to microsoft-secure.help

## Response plan

1. Block the landing domain and every URL in the message at the proxy and DNS layer.
2. Identify recipients who clicked; force password reset and revoke active sessions and refresh tokens for those accounts.
3. Review sign-in logs for those users for impossible-travel or new-device authentications since delivery.

---

_Generated by Sentinel. Severity is rubric-derived, not learned; attributions are exact TreeSHAP over the structural model and exact linear contributions over the wording model._