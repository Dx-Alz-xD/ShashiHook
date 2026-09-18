"""Extract features and weak vector labels for the whole corpus, then cache.

Run once; training reads the cache. Splitting is done here, not in the
trainers, so the intent model, the vector model and the calibrator all see the
identical split and no row can drift across it.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinel.config import ARTIFACTS, RANDOM_SEED, TEST_SIZE
from sentinel.data.loaders import load_all, row_to_email
from sentinel.features.extractor import FEATURE_NAMES, extract, to_vector
from sentinel.labeling.weak_rules import vote


def main() -> None:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    print("Loading corpora")
    df = load_all(verbose=True)

    print(f"\nExtracting {len(FEATURE_NAMES)} features across {len(df):,} messages")
    t0 = time.time()
    X = np.zeros((len(df), len(FEATURE_NAMES)), dtype=np.float32)
    vectors, vec_conf, lf_counts = [], [], []
    texts = []

    for i, row in enumerate(df.itertuples(index=False)):
        email = row_to_email(row)
        feats, ev = extract(email)
        X[i] = to_vector(feats)
        v, conf, _totals, contributing = vote(email, feats, ev, bool(row.label))
        vectors.append(v)
        vec_conf.append(conf)
        lf_counts.append(len(contributing))
        texts.append(email.full_text)
        if (i + 1) % 15000 == 0:
            print(f"  {i+1:,}/{len(df):,}  ({time.time()-t0:.0f}s)")

    print(f"  done in {time.time()-t0:.0f}s")

    df = df.reset_index(drop=True)
    df["vector"] = vectors
    df["vector_confidence"] = vec_conf
    df["vector_lf_count"] = lf_counts
    df["text"] = texts

    # Group-aware split: every row with the same content key lands on the same
    # side. Dedupe already removed exact repeats; this catches near-repeats that
    # share a fingerprint prefix, which is where template-reuse leakage lives.
    rng = np.random.default_rng(RANDOM_SEED)
    keys = df["content_key"].to_numpy()
    uniq = np.unique(keys)
    rng.shuffle(uniq)
    n_test = int(len(uniq) * TEST_SIZE)
    test_keys = set(uniq[:n_test].tolist())
    df["split"] = np.where(df["content_key"].isin(test_keys), "test", "train")

    # The Nazario corpus is phishing-only: it has no benign counterpart. Adding
    # ~3,000 positives with no matching ham taught the wording model that
    # transactional vocabulary -- "invoice", "payment", "account", "verify" --
    # is hostile, and the modern probe's false positives went from 1 to 4
    # (a legitimate invoice, a real payment request and a genuine DocuSign all
    # flagged). So it is excluded from the intent model, which needs a balanced
    # view, and kept for the vector model, where its labelled credential
    # phishing raised that class from 236 training rows to 1,562.
    # Everything trains the intent model now, including Nazario.
    #
    # It was excluded for a while: being phishing-only, adding 3,000 positives
    # with no matching negatives taught the wording model that transactional
    # vocabulary is hostile, and the modern probe's false positives went 1 -> 4.
    #
    # Caching ~3,000 authenticated legitimate messages from the user's own
    # mailbox (scripts/build_local_corpus.py) supplied the missing negatives,
    # and the measurement then reversed:
    #
    #   variant              FPR     recall   held-out-Nazario recall   own-mail FP
    #   Nazario excluded   0.0048    0.9498            0.4628             0/518
    #   Nazario included   0.0105    0.9960            0.9968             2/518
    #
    # Catching 99.7% of unseen phishing instead of 46.3%, for two extra false
    # positives in 518 real messages, is not a close call -- and the base-rate
    # correction and severity rubric absorb marginal positives downstream.
    #
    # Set SENTINEL_EXCLUDE_NAZARIO=1 to reproduce the excluded variant.
    import os
    _excl = os.environ.get("SENTINEL_EXCLUDE_NAZARIO", "0") == "1"
    df["use_for_intent"] = (~df["source"].str.startswith("nazario")) if _excl else True

    np.save(ARTIFACTS / "X.npy", X)
    df.drop(columns=["body"]).to_parquet(ARTIFACTS / "meta.parquet", index=False)
    df[["text"]].to_parquet(ARTIFACTS / "text.parquet", index=False)
    (ARTIFACTS / "feature_names.txt").write_text("\n".join(FEATURE_NAMES))

    n_excl = int((~df["use_for_intent"]).sum())
    print(f"\nRaw-mail rows kept for vector training but excluded from the "
          f"intent model: {n_excl:,}")
    print("\nSplit:")
    print(df.groupby(["split", "label"]).size().unstack(fill_value=0).to_string())
    print("\nWeak vector labels (malicious rows only):")
    mal = df[df.label == 1]
    vc = mal["vector"].value_counts()
    for k, n in vc.items():
        mean_c = mal.loc[mal.vector == k, "vector_confidence"].mean()
        print(f"  {k:24} {n:>7,}  ({n/len(mal):5.1%})  mean rule confidence {mean_c:.2f}")
    unresolved = int((mal["vector"] == "malicious_unclassified").sum())
    print(f"\n  unresolved by rules: {unresolved:,} of {len(mal):,} "
          f"({unresolved/len(mal):.1%})")
    print(f"\nSaved to {ARTIFACTS}")


if __name__ == "__main__":
    main()
