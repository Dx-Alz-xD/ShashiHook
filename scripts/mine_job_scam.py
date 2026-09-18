"""What EMSCAD can and cannot teach a job-scam detector.

`job_scam` is the thinnest vector in the taxonomy, so 17,880 labelled job
postings looked like the fix. They are not, and the reason is worth keeping.

A TF-IDF classifier over the postings reaches 0.9904 ROC-AUC, and reading its
coefficients shows what it bought: `link href`, `img src` and `br the` are HTML
left in the scrape, while `oil and gas`, `six sigma`, `customer service` and
`high school` are job categories. EMSCAD's fraudulent flag largely marks
postings from accounts later found fraudulent, and a large share of those
accounts CLONED real listings to harvest applicants. So the model separates
industries and scrape artefacts, not deception -- the same trap as ImageBase in
the PE model, which alone scored 0.9383.

What does transfer is the pitch itself, and only in conjunction:

    marker              fraud  genuine  precision
    upfront fee            23        2      92.0%
    work from home         89       88      50.3%
    no experience          61       78      43.9%
    few hours/day          22       23      48.9%
    messaging app           4      280       1.4%   <- "Skype interview"

    >= 1 marker    927 postings   21.1% fraudulent
    >= 2 markers   107 postings   73.8%
    >= 3 markers    19 postings  100.0%

against a 4.8% base rate. That is why the weak rule requires two lexicon hits
rather than one: the conjunction was a design guess, and this measures it.

Run this to reproduce the table before changing the job_scam lexicon.
"""
from __future__ import annotations

import html
import re
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sentinel.config import PROJECT_ROOT

SRC = PROJECT_ROOT / "data" / "kaggle" / "emscad.csv"

# Deliberately structural. A single word is a job category; these are claims
# about how the work is paid, how much of it there is, and what it costs to
# start -- the things a genuine employer has no reason to say.
MARKERS = {
    "pay-per-period": r"\$\s?[\d,]{2,}(?:\.\d\d)?\s*(?:-|to|–)?\s*\$?[\d,]*\s*(?:per|a|/)\s*(?:day|week|hour|hr)",
    "work from home": r"\b(?:work|earn)\s+from\s+home\b|\bfrom the comfort of your\b",
    "no experience":  r"\bno\s+(?:prior\s+|any\s+|work\s+)?experience\s+(?:is\s+)?(?:required|needed|necessary)",
    "upfront fee":    r"\b(?:zero|no)\s+(?:start[- ]?up|registration|joining)\s+fee|\bregistration fee\b|\bpay .{0,20}fee\b",
    "messaging app":  r"\b(?:whatsapp|telegram|hangouts?|signal|skype)\b",
    "immediate":      r"\bstart (?:immediately|today|right away)\b|\bimmediate start\b",
    "part-time cash": r"\bcash pay\b|\bpaid (?:daily|weekly) in cash\b|\bdaily payment\b",
    "few hours/day":  r"\b[1-8](?:\s*(?:-|to|–)\s*[1-8])?\s+(?:hours?|hrs?)\s+(?:a|per)\s+day\b",
}


def main() -> None:
    if not SRC.exists():
        print(f"{SRC} not found"); return
    df = pd.read_csv(SRC, low_memory=False)
    df["f"] = df["fraudulent"].astype(str).str.lower().isin(["t", "true", "1"])
    df["t"] = (df[["title", "description", "requirements"]].fillna("")
               .agg(" ".join, axis=1)
               .map(lambda s: re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ",
                                                         html.unescape(str(s)))).strip()))
    print(f"  {len(df):,} postings, {df.f.sum():,} fraudulent ({df.f.mean():.1%} base rate)\n")
    print(f"  {'marker':<18}{'fraud':>7}{'genuine':>9}{'precision':>11}")
    hits = {}
    for k, p in MARKERS.items():
        m = df["t"].str.contains(p, regex=True, case=False, na=False)
        hits[k] = m.to_numpy()
        a, b = (m & df.f).sum(), (m & ~df.f).sum()
        print(f"  {k:<18}{a:>7}{b:>9}{a/max(a+b,1):>10.1%}")

    score = np.sum(list(hits.values()), axis=0)
    print()
    for n in (1, 2, 3):
        sel = score >= n
        if sel.sum():
            print(f"  >= {n} marker(s): {sel.sum():>5,} postings, "
                  f"{(sel & df.f.to_numpy()).sum():>3} fraudulent "
                  f"({df.f.to_numpy()[sel].mean():.1%})")


if __name__ == "__main__":
    main()
