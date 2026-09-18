"""Sample a stratified set for human labelling.

The vector classifier is trained on weak rules, so "98.9% accuracy" measures
agreement with those rules, not correctness. Only human labels can tell you
whether the rules themselves are right. This script produces the CSV to label.

    python scripts/build_gold_set.py --n 400
    # ... a human fills in the `true_vector` column ...
    python scripts/eval_gold.py

Sampling is deliberately skewed towards the cases where the rules are least
trustworthy -- unresolved messages and low-confidence votes -- because labelling
400 obvious pharmacy spams would measure nothing.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sentinel.config import ARTIFACTS, EVAL_DIR, RANDOM_SEED
from sentinel.labeling.taxonomy import VECTOR_KEYS


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=400)
    ap.add_argument("--out", default=str(EVAL_DIR / "gold_set_unlabelled.csv"))
    args = ap.parse_args()

    meta = pd.read_parquet(ARTIFACTS / "meta.parquet")
    meta["text"] = pd.read_parquet(ARTIFACTS / "text.parquet")["text"].values
    mal = meta[meta.label == 1].copy()

    rng = np.random.default_rng(RANDOM_SEED)
    buckets = {
        # Where the rules abstained entirely -- the biggest unknown.
        "unresolved": mal[mal.vector == "malicious_unclassified"],
        # Where they voted but hesitantly -- most likely to be wrong.
        "low_confidence": mal[(mal.vector != "malicious_unclassified")
                              & (mal.vector_confidence < 0.7)],
        # Where they were certain -- to verify the rules are actually precise.
        "high_confidence": mal[mal.vector_confidence >= 0.9],
    }
    quota = {"unresolved": 0.45, "low_confidence": 0.35, "high_confidence": 0.20}

    frames = []
    for name, df in buckets.items():
        k = min(len(df), int(args.n * quota[name]))
        if k:
            take = df.iloc[rng.choice(len(df), size=k, replace=False)].copy()
            take["sample_bucket"] = name
            frames.append(take)

    gold = pd.concat(frames, ignore_index=True).sample(frac=1.0, random_state=RANDOM_SEED)
    gold["true_vector"] = ""          # <- the human fills this in
    gold["labeller_notes"] = ""
    gold["text_preview"] = gold["text"].str.replace(r"\s+", " ", regex=True).str[:600]

    cols = ["sample_bucket", "source", "subject", "sender", "text_preview",
            "vector", "vector_confidence", "true_vector", "labeller_notes"]
    EVAL_DIR.mkdir(parents=True, exist_ok=True)
    gold[cols].to_csv(args.out, index=False)

    print(f"Wrote {len(gold):,} rows -> {args.out}")
    print("\nSampling plan:")
    print(gold["sample_bucket"].value_counts().to_string())
    print("\nRule label distribution in the sample:")
    print(gold["vector"].value_counts().to_string())
    print("\nFill the `true_vector` column with one of:")
    for k in VECTOR_KEYS:
        print(f"  {k}")
    print("\nThen run: python scripts/eval_gold.py")


if __name__ == "__main__":
    main()
