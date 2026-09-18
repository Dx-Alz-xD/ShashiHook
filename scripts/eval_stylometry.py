"""Does the style profile actually recognise a person?

The claim stylometry makes is specific: a message from this sender should sit
closer to this sender's profile than a message from anybody else does. That is
a testable claim and this tests it, before the drift value is allowed anywhere
near a score.

Enron is the right corpus for it. Real people, writing real mail over years,
hundreds of messages each -- and crucially, the negatives are other real
colleagues writing about the same business in the same register, which is a far
harder test than separating a colleague from a phisher.

The measurement is per-sender AUC: for each sender, rank their own held-out
messages against an equal number from other people, by drift from the profile.
0.5 means the profile is worthless. Anything above it is what the profile knows
about that person that a header check does not.
"""
from __future__ import annotations

import random
import sys
from collections import defaultdict
from email import message_from_string
from email.utils import getaddresses
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sentinel.config import PROJECT_ROOT, RANDOM_SEED
from sentinel.stylometry import (DRIFT_SUSPICIOUS, MIN_MESSAGES, MIN_TOKENS,
                                 StyleStore, describe_trait, traits)

SRC = PROJECT_ROOT / "data" / "kaggle" / "enron.csv"
PROFILE_ON = MIN_MESSAGES   # messages used to build the profile
MIN_HELD_OUT = 6         # own messages kept back to test with


def body_of(m) -> str:
    if m.is_multipart():
        return "\n".join(p.get_payload(decode=False) or ""
                         for p in m.walk() if p.get_content_type() == "text/plain")
    return m.get_payload(decode=False) or ""


def load(limit: int) -> dict[str, list[str]]:
    by_sender: dict[str, list[str]] = defaultdict(list)
    seen: set[str] = set()
    n = 0
    for chunk in pd.read_csv(SRC, chunksize=20_000):
        for raw in chunk["message"]:
            n += 1
            try:
                m = message_from_string(raw)
            except Exception:
                continue
            mid = (m.get("Message-ID") or "").strip()
            if not mid or mid in seen:
                continue
            seen.add(mid)
            frm = [a for _, a in getaddresses([m.get("From") or ""])]
            if not frm or "@" not in frm[0]:
                continue
            body = body_of(m)
            if traits(body) is not None:      # long enough to carry a style
                by_sender[frm[0].lower()].append(body)
        if n >= limit:
            break
    return by_sender


def main(limit: int = 250_000) -> None:
    if not SRC.exists():
        print(f"{SRC} not found"); return
    rng = random.Random(RANDOM_SEED)
    print(f"reading up to {limit:,} rows")
    by_sender = load(limit)
    need = PROFILE_ON + MIN_HELD_OUT
    usable = {a: v for a, v in by_sender.items() if len(v) >= need}
    print(f"  {len(by_sender):,} senders, {len(usable):,} with >= {need} "
          f"messages of {MIN_TOKENS}+ words")
    if len(usable) < 10:
        print("  not enough senders to measure"); return

    # Build every profile first; the population spread is what keeps a small
    # sample from manufacturing certainty, so it has to exist before scoring.
    store = StyleStore()
    held: dict[str, list[str]] = {}
    for a, msgs in usable.items():
        for b in msgs[:PROFILE_ON]:
            store.observe(a, b)
        held[a] = msgs[PROFILE_ON:]
    store.fit_population()
    print(f"  {len(store.profiles):,} profiles, population spread fitted over "
          f"{len(store.pop_sd)} traits\n")

    senders = list(usable)
    aucs, same_all, diff_all = [], [], []
    for a in senders:
        own = held[a]
        others = []
        for _ in range(len(own)):
            b = rng.choice(senders)
            while b == a:
                b = rng.choice(senders)
            others.append(rng.choice(held[b]))
        s = [store.compare(a, t).drift for t in own]
        d = [store.compare(a, t).drift for t in others]
        s = [x for x in s if x > 0]
        d = [x for x in d if x > 0]
        if not s or not d:
            continue
        same_all += s
        diff_all += d
        # AUC = P(a different-author message drifts more than an own message)
        wins = sum(1 for x in s for y in d if y > x)
        ties = sum(1 for x in s for y in d if y == x)
        aucs.append((wins + 0.5 * ties) / (len(s) * len(d)))

    same, diff = np.array(same_all), np.array(diff_all)
    wins = sum(1 for x in same for y in diff[:400] if y > x)
    print("=" * 62)
    print("DOES THE PROFILE RECOGNISE ITS OWN AUTHOR?")
    print("=" * 62)
    print(f"  senders measured            {len(aucs):,}")
    print(f"  own messages scored         {len(same):,}")
    print(f"  other-author messages       {len(diff):,}")
    print(f"\n  drift, same author          mean {same.mean():.3f}  "
          f"median {np.median(same):.3f}")
    print(f"  drift, different author     mean {diff.mean():.3f}  "
          f"median {np.median(diff):.3f}")
    print(f"\n  mean per-sender AUC         {np.mean(aucs):.4f}")
    print(f"  median per-sender AUC       {np.median(aucs):.4f}")
    print(f"  senders above 0.5           {sum(1 for x in aucs if x > .5):,}"
          f" of {len(aucs):,}")

    # What a practical threshold would cost. The question that matters is not
    # "can it rank" but "at a cutoff that almost never accuses a colleague,
    # how much impersonation does it still catch?"
    print("\n  threshold   accuses the real author   catches an impersonator")
    for q in (90, 95, 97.5, 99):
        thr = np.percentile(same, q)
        print(f"     {thr:.3f}         {100-q:>5.1f}%"
              f"                    {100*(diff > thr).mean():>5.1f}%")
    print(f"\n  shipped DRIFT_SUSPICIOUS = {DRIFT_SUSPICIOUS}: "
          f"accuses {100*(same > DRIFT_SUSPICIOUS).mean():.1f}% of genuine mail, "
          f"catches {100*(diff > DRIFT_SUSPICIOUS).mean():.1f}%")

    # Which traits do the work, averaged over genuine mismatches.
    contrib: dict[str, float] = defaultdict(float)
    for a in senders[:200]:
        for t in held[a][:2]:
            b = rng.choice(senders)
            while b == a:
                b = rng.choice(senders)
            for k, z, _, _ in store.compare(a, rng.choice(held[b])).top:
                contrib[k] += z
    print("\n  traits that most often separate two writers:")
    for k, v in sorted(contrib.items(), key=lambda x: -x[1])[:10]:
        print(f"    {v:7.1f}  {describe_trait(k)}")


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 250_000)
