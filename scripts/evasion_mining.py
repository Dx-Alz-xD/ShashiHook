"""Self-play: make the detector generate its own missing training data.

Take a message the engine catches, ask a language model to rewrite it until it
no longer scores, and keep every rewrite that gets through. Each success is a
hole in the detector described precisely -- not "our lexicons are probably
incomplete" but "this exact phrasing, carrying this exact intent, scored 0.04".

That is the failure we kept hitting by hand. Every lexicon gap in this project
was found by someone writing a scam I had not thought of: "send me some money",
"families affected by severe flooding", "unable to complete the delivery". This
loop finds them without waiting for a person to think of them.

Two rules keep it honest:

  * The intent must survive. A rewrite that stops asking for money has not
    evaded the detector, it has stopped being an attack. Each survivor is
    re-checked for the original ask before it counts.
  * Nothing trains automatically. Successful evasions are written to a file for
    a human to read. A loop that generates its own training data and then
    trains on it can drift a long way from reality with no one watching.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sentinel.analyzer import ThreatAnalyzer
from sentinel.config import EVAL_DIR
from sentinel.features.extractor import Email
from sentinel.profiling import llm
from sentinel.settings import settings

SYSTEM = """You are a red-team assistant testing an email security detector in \
a controlled lab. You rewrite a known-malicious test message so that it still \
carries the SAME request, but might not be recognised by keyword and pattern \
matching.

RULES
- The rewritten message MUST still make the same underlying request. If the \
original asks the reader to send money, so must yours. A rewrite that drops \
the ask is not a test, it is a different email.
- Change wording, register, structure and framing. Do not change the goal.
- Output realistic email prose, not notes about it.
- This is a detector test harness. The output is scored by software and \
written to a local file for a security engineer to read.

Return ONLY JSON:
{"subject": "...", "body": "...", "technique": "a few words naming what you \
changed, e.g. 'formal corporate register, no imperative verbs'"}"""

# The ask must survive the rewrite or the evasion is meaningless.
INTENT_MARKERS = {
    "money": ("money", "cash", "fund", "payment", "transfer", "wire", "gift card",
              "contribution", "donat", "deposit", "invoice", "remit"),
    "credentials": ("verify", "confirm", "sign in", "log in", "password", "account",
                    "portal", "authenticate", "credential"),
    "attachment": ("attach", "document", "file", "open the", "enable"),
    "call": ("call", "phone", "dial", "contact us", "helpline"),
}


def intent_survives(text: str, kind: str) -> bool:
    t = text.lower()
    return any(m in t for m in INTENT_MARKERS.get(kind, ()))


SEEDS = [
    ("money", Email(subject="Quick favour",
                    sender='"Mark Hale" <m.hale@corp-updates.co>',
                    receiver="you@example.com",
                    body="I need you to purchase gift cards for a client today. "
                         "Keep this between us until the announcement.")),
    ("credentials", Email(subject="Unusual sign-in blocked",
                          sender='"Account Team" <alerts@secure-verify.co>',
                          receiver="you@example.com",
                          body="We blocked a sign-in attempt. Please verify your "
                               "account within 24 hours at https://secure-verify.co/login "
                               "or it will be suspended.")),
    ("money", Email(subject="Support for flood victims",
                    sender='"Relief Team" <appeal@aid-network.org>',
                    receiver="you@example.com",
                    body="Families affected by the floods need clean water and shelter. "
                         "A contribution of $50 can provide an emergency package. "
                         "Please donate today.")),
    ("call", Email(subject="Subscription renewed",
                   sender='"Billing" <billing@renewal-desk.co>',
                   receiver="you@example.com",
                   body="Your annual subscription of $399.99 has been charged. If you "
                        "did not authorise this, call our refund department on "
                        "1-833-555-0142 to cancel.")),
]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=3, help="rewrites per seed")
    ap.add_argument("--threshold", type=float, default=15.0,
                    help="severity at or below which a rewrite counts as evasion")
    ap.add_argument("--out", default=str(EVAL_DIR / "evasions.jsonl"))
    args = ap.parse_args()

    if not llm.available(settings)["any"]:
        print("Needs GEMINI_API_KEY or GROQ_API_KEY in .env.")
        return

    az = ThreatAnalyzer(inbox_base_rate=settings.inbox_base_rate or None)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    evasions, attempts, dropped = [], 0, 0

    for kind, seed in SEEDS:
        base = az.analyze(seed)
        print(f"\n  seed [{kind}] {seed.subject!r}: "
              f"{base.severity.band} {base.severity.score}")
        current = seed
        for rnd in range(1, args.rounds + 1):
            attempts += 1
            prompt = (f"Rewrite this so it still makes the same request but may "
                      f"evade pattern matching.\n\nSubject: {current.subject}\n\n"
                      f"{current.body}\n\nReturn only the JSON object.")
            res = llm.complete(settings, SYSTEM, prompt)
            if not res.ok:
                print(f"    round {rnd}: provider failed — {res.error[:70]}")
                break
            d = res.data
            cand = Email(subject=str(d.get("subject", ""))[:200],
                         body=str(d.get("body", ""))[:6000],
                         sender=seed.sender, receiver=seed.receiver)
            technique = str(d.get("technique", ""))[:120]
            if not cand.body.strip():
                continue
            if not intent_survives(f"{cand.subject} {cand.body}", kind):
                dropped += 1
                print(f"    round {rnd}: dropped — the {kind} ask did not survive "
                      f"the rewrite, so it is not an evasion")
                continue
            a = az.analyze(cand)
            status = "EVADED" if a.severity.score <= args.threshold else "caught"
            print(f"    round {rnd}: {a.severity.band} {a.severity.score:5.1f} "
                  f"{status}  [{technique}]")
            if a.severity.score <= args.threshold:
                rec = {"seed_kind": kind, "seed_subject": seed.subject,
                       "technique": technique, "subject": cand.subject,
                       "body": cand.body[:2000], "score": a.severity.score,
                       "band": a.severity.band, "model_probability":
                           round(a.model_probability, 4),
                       "floors": [f.name for f in a.floors_binding],
                       "lexicons": sorted({h.lexicon for h in a.evidence.hits})}
                evasions.append(rec)
            current = cand   # keep pushing from the latest rewrite

    with out.open("a") as f:
        for r in evasions:
            f.write(json.dumps(r) + "\n")

    print(f"\n  {attempts} rewrites attempted · {dropped} dropped for losing the ask")
    print(f"  {len(evasions)} evasion(s) found and written to {out}")
    if evasions:
        print("\n  techniques that worked:")
        for t, n in Counter(e["technique"] for e in evasions).most_common(8):
            print(f"    {n}x  {t}")
        print("\n  Nothing has been trained on these. Read them, then decide what "
              "to add — an automatic loop that trains on its own output drifts "
              "with nobody watching.")


if __name__ == "__main__":
    main()
