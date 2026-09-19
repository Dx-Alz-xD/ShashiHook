"""Write the practice mail, instead of dredging it out of the corpus.

The first version of the practice pool served real corpus messages, and the
first exercise anyone saw was a 2007 SourceForge SVN commit notification. That
is unanswerable: nobody can reasonably say whether an automated changeset email
from a mailing list is hostile, and the text arrives lowercased with its
punctuation spaced out because the corpus is tokenised for model training, not
for reading. Good material for fitting a classifier, useless for teaching a
person.

So the mail is generated. Two things keep that honest:

  scored      every generated message is run through ArnosAI before it is
              accepted. A "hostile" one the detector scores near zero is a bad
              exercise, and a "legitimate" one it scores high is mislabelled.
              Items that fail are dropped, and the rejection rate is printed.

  hard        the legitimate half matters more than the hostile half. Real
              password resets, real invoices, real delivery notices and real
              security alerts are what people over-flag, so those are
              generated deliberately. A pool where every safe message is a
              lunch invitation teaches nothing except that scams mention money.

This is simulated training content for the person who owns the mailbox. It is
labelled as such in the interface, stored locally, and never sent anywhere.
"""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sentinel.config import ARTIFACTS
from sentinel.features import lexicons as lx
from sentinel.practice import POOL_PATH

TELLS = {
    "urgency", "credential_request", "payment", "money_request", "threat",
    "authority", "secrecy", "reward", "identity_claim", "it_support",
    "sextortion", "crypto", "attachment_lure", "job_scam", "investment_scam",
    "tech_support_scam", "delivery_scam", "govt_impersonation", "charity_fraud",
    "romance", "impersonated_brand",
}

HOSTILE_BRIEFS = [
    ("credential_phishing", "a fake sign-in prompt for a cloud or email account"),
    ("credential_phishing", "an IT helpdesk asking you to re-authenticate"),
    ("bec_payment_fraud", "an executive asking for an urgent transfer, quietly"),
    ("vendor_invoice_fraud", "a supplier announcing changed bank details"),
    ("delivery_scam", "a parcel held for a small customs or redelivery fee"),
    ("tech_support_scam", "a security alert telling you to ring a number"),
    ("job_scam", "a remote job offer that needs an upfront fee"),
    ("advance_fee_fraud", "a windfall that needs a release payment first"),
    ("investment_fraud", "a crypto or trading opportunity with guaranteed returns"),
    ("extortion", "a claim to have compromising material, demanding payment"),
    ("govt_impersonation", "a tax or immigration notice threatening penalties"),
    ("charity_fraud", "an emotional appeal for an urgent donation"),
    ("malware_delivery", "an attachment you are pressed to open"),
    ("callback_phishing", "a subscription renewal you must phone to cancel"),
]

# The hard half. These are the shapes people wrongly flag, and a pool without
# them teaches "anything mentioning a password is a scam".
BENIGN_BRIEFS = [
    "a genuine password reset the recipient actually requested",
    "a real invoice from a known supplier, with normal payment terms",
    "a real courier notice about a delivery, with no fee",
    "a legitimate security alert about a new sign-in, informational only",
    "a real subscription renewal receipt from a service they use",
    "an ordinary internal message about a meeting or a deadline",
    "a genuine HR or payroll notice with a deadline",
    "a real newsletter from a service the recipient subscribed to",
    "a legitimate bank statement notification",
    "a colleague asking a normal work question with an attachment",
    "a real conference or event registration confirmation",
    "an actual IT maintenance window announcement",
]

SYSTEM = """You write realistic email for a security-awareness training tool. \
The reader is being trained to tell hostile mail from ordinary mail.

Write modern, specific, plausible email — 2020s, not 2005. Use concrete \
details: real-sounding names, plausible company names that are clearly \
fictional, amounts, dates, reference numbers. Vary tone, length and industry \
between messages.

For HOSTILE messages: write what an actual attacker would send today. Competent \
ones are calm, well-spelled and specific. Do not write a parody with five \
exclamation marks — an obvious fake teaches the reader the wrong lesson and is \
the exact belief real attackers rely on.

For LEGITIMATE messages: write genuinely ordinary mail, including the kinds \
people wrongly panic about — real password resets, real invoices, real \
security alerts. These must contain NO deception at all.

Never use a real company's exact domain. Invent plausible ones.

Return ONLY this JSON:
{"emails": [
  {"subject": "<subject line>",
   "sender_name": "<display name>",
   "sender": "<address@domain>",
   "body": "<the full message, 60-160 words, with line breaks as \\n>"}
]}"""


def clean(t: str) -> str:
    return re.sub(r"\n{3,}", "\n\n", str(t or "")).strip()


def generate(cfg, brief: str, hostile: bool, n: int) -> list[dict]:
    from sentinel.profiling import llm
    kind = "HOSTILE" if hostile else "LEGITIMATE"
    user = (f"Write {n} different {kind} emails. Each one: {brief}.\n\n"
            f"Make them differ from each other in sender, industry, tone and "
            f"length. Return only the JSON object.")
    # Failures were silent in the first version: rate-limit exhaustion returned
    # an empty list that looked identical to "the model wrote nothing", so a
    # run that produced 13 of 78 emails reported zero rejections and no errors.
    last = ""
    for attempt in range(6):
        res = llm.complete(cfg, SYSTEM, user)
        if res.ok:
            got = (res.data or {}).get("emails") or []
            if got:
                return got
            last = "returned no emails"
            continue
        last = res.error or "unknown"
        if "429" not in last and "rate" not in last.lower():
            break
        time.sleep(4.0 * (attempt + 1))
    print(f"    ! generation failed: {last[:90]}")
    return []


def main(per_brief: int = 3) -> None:
    from sentinel.analyzer import ThreatAnalyzer
    from sentinel.features.extractor import Email
    from sentinel.settings import settings

    az = ThreatAnalyzer()          # no settings: no translation, no vision calls
    items: list[dict] = []
    rejected = {"low": 0, "high": 0, "short": 0}

    plan = ([(v, b, True) for v, b in HOSTILE_BRIEFS]
            + [("benign", b, False) for b in BENIGN_BRIEFS])
    print(f"generating {len(plan)} briefs x {per_brief}")

    for i, (vector, brief, hostile) in enumerate(plan, 1):
        got = generate(settings, brief, hostile, per_brief)
        kept = 0
        for e in got:
            body = clean(e.get("body"))
            subject = clean(e.get("subject"))[:140]
            sender = str(e.get("sender") or "").strip()[:90]
            if len(body.split()) < 30 or not subject or "@" not in sender:
                rejected["short"] += 1
                continue
            # The detector is the referee. A hostile example it cannot see is
            # a bad exercise; a benign one it flags is mislabelled.
            a = az.analyze(Email(subject=subject, sender=sender,
                                 receiver="you@example.com", body=body))
            score = a.severity.score
            if hostile and score < 8:
                rejected["low"] += 1
                continue
            if not hostile and score >= 35:
                rejected["high"] += 1
                continue
            spans, seen = [], set()
            for h in lx.scan(body, "body"):
                if h.lexicon not in TELLS or (h.start, h.end) in seen:
                    continue
                seen.add((h.start, h.end))
                spans.append({"start": h.start, "end": h.end,
                              "lexicon": h.lexicon, "term": body[h.start:h.end][:80]})
            items.append({
                "id": f"g{len(items)}",
                "subject": subject,
                "sender": f"{e.get('sender_name', '')} <{sender}>".strip(),
                "body": body,
                "label": int(hostile),
                "vector": vector,
                "vector_confidence": 1.0,
                "source": "simulated",
                "score": round(score, 1),
                "spans": spans[:12],
            })
            kept += 1
        print(f"  [{i:>2}/{len(plan)}] {'HOSTILE ' if hostile else 'legit   '} "
              f"{brief[:44]:<46} +{kept}")
        time.sleep(2.5)     # free-tier providers limit requests per minute

    mal = [i for i in items if i["label"] == 1]
    ben = [i for i in items if i["label"] == 0]
    with_tells = [i for i in mal if i["spans"]]
    print(f"\n  kept {len(items)} ({len(mal)} hostile, {len(ben)} legitimate)")
    print(f"  {len(with_tells)} hostile carry a usable tell")
    print(f"  rejected: {rejected['low']} hostile scored too low, "
          f"{rejected['high']} benign scored too high, {rejected['short']} malformed")

    twins = []
    if mal and ben:
        from sentinel.similarity import encode
        M, B = encode([i["body"] for i in mal]), encode([i["body"] for i in ben])
        sims = M @ B.T
        best = sims.argmax(1)
        for k in np.argsort(-sims.max(1)):
            s = float(sims[k, best[k]])
            if s < 0.45:
                break
            twins.append({"malicious": mal[k]["id"], "benign": ben[best[k]]["id"],
                          "similarity": round(s, 4)})
        print(f"  {len(twins)} twin pairs "
              f"({twins[-1]['similarity']:.2f}–{twins[0]['similarity']:.2f})"
              if twins else "  no twins")

    POOL_PATH.write_text(json.dumps({"items": items, "twins": twins}))
    print(f"  -> {POOL_PATH}")


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 3)
