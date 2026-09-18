"""Find the messages worth a human's attention.

Two uses of the same idea: a labelled example teaches the model almost nothing
when the model already gets it right, and a great deal when the model is wrong
or unsure. So rank by how badly the model is doing, not at random.

  hard negatives  benign messages the model scores HIGH. These are what a user
                  would report as false positives, and they are the examples
                  that sharpen precision.

  hard positives  malicious messages the model scores LOW. These are the
                  misses, and the ones nobody finds by looking at a random
                  sample.

  uncertain       messages sitting near the decision boundary, where a human
                  label resolves the most ambiguity per minute spent.

The gold set built earlier sampled by rule-confidence bucket, which is a
reasonable spread and a poor use of a person's time. This targets the same
budget at the examples that actually move something.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sentinel.config import ARTIFACTS, EVAL_DIR
from sentinel.models.intent import IntentModel


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=120, help="rows per category")
    ap.add_argument("--out", default=str(EVAL_DIR / "hard_cases.csv"))
    args = ap.parse_args()

    X = np.load(ARTIFACTS / "X.npy")
    meta = pd.read_parquet(ARTIFACTS / "meta.parquet")
    texts = pd.read_parquet(ARTIFACTS / "text.parquet")["text"].tolist()
    m = IntentModel.load(ARTIFACTS / "intent_model.joblib")

    # Test split only: scoring training rows measures memorisation, and a row
    # the model memorised is not hard, it is just seen.
    te = np.where((meta["split"] == "test").to_numpy())[0]
    y = meta["label"].to_numpy()[te]
    print(f"  scoring {len(te):,} held-out messages")
    p = m.predict_proba(X[te], [texts[i] for i in te])

    sub = meta.iloc[te].copy()
    sub["p"] = p
    sub["y"] = y
    sub["text"] = [texts[i] for i in te]
    sub["uncertainty"] = 1.0 - (sub["p"] - 0.5).abs() * 2

    benign, mal = sub[sub.y == 0], sub[sub.y == 1]
    picks = {
        "hard_negative": benign.nlargest(args.n, "p"),
        "hard_positive": mal.nsmallest(args.n, "p"),
        "uncertain": sub.nlargest(args.n, "uncertainty"),
    }
    frames = []
    for name, df in picks.items():
        d = df.copy()
        d["case_type"] = name
        frames.append(d)
        wrong = int(((d.p >= 0.5) != (d.y == 1)).sum())
        print(f"  {name:14} {len(d):>4} rows · model wrong on {wrong} "
              f"({wrong/max(len(d),1):.0%}) · p range "
              f"{d.p.min():.3f}-{d.p.max():.3f}")

    out = pd.concat(frames).drop_duplicates(subset="content_key")
    out["text_preview"] = out["text"].str.replace(r"\s+", " ", regex=True).str[:500]
    out["true_label"] = ""        # <- the human fills this in
    out["notes"] = ""
    cols = ["case_type", "source", "subject", "sender", "p", "y",
            "text_preview", "true_label", "notes"]
    EVAL_DIR.mkdir(parents=True, exist_ok=True)
    out[cols].sort_values("case_type").to_csv(args.out, index=False)

    # How much better than random this is, measured rather than asserted.
    base_err = float(((sub.p >= 0.5) != (sub.y == 1)).mean())
    picked_err = float(((out.p >= 0.5) != (out.y == 1)).mean())
    print(f"\n  wrote {len(out):,} rows -> {args.out}")
    print(f"  model is wrong on {base_err:.2%} of a random sample, and on "
          f"{picked_err:.1%} of this one")
    if base_err > 0:
        print(f"  -> {picked_err/base_err:.0f}x the error density per row labelled")
    print("\n  Fill `true_label` with 0 or 1. These are the rows where a label "
          "changes something.")


if __name__ == "__main__":
    main()
