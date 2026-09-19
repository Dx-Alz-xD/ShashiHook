"""Train a PE classifier on malware/malware.csv -- KEPT ONLY TO REPRODUCE THE AUDIT.

The model this produces is deliberately not used anywhere. It reaches 0.9998
ROC-AUC and that number is an artefact of how the dataset was assembled:

    legitimate samples:  memtest.exe, ose.exe, setup.exe, DW20.EXE
    malicious samples:   VirusShare_4a400b747afe..., VirusShare_9bd57c82...

Two different collection processes, so the strongest features separate the
COLLECTIONS rather than hostile from harmless. SizeOfStackReserve is 0x100000
for 94% of malicious and 0x40000 for 65% of legitimate -- a linker default.
ExportNb is 0 for 99% of malicious, which means they are EXEs and the
legitimate set has DLLs. Removing all nineteen build-environment fields moves
held-out AUC from 0.9998 to 0.9997, because the contamination is everywhere,
not concentrated in a few columns.

Run scripts/build_pe_percentiles.py instead. It extracts the one property that
belongs to the bytes rather than the collection -- section entropy -- and
sentinel/pe.py reports it as a percentile against ordinary Windows binaries.

Validating a real PE classifier needs a dataset built to avoid this, EMBER or
SOREL, where both classes are collected the same way.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (average_precision_score, classification_report,
                             confusion_matrix, roc_auc_score)
from sklearn.model_selection import train_test_split

import lightgbm as lgb

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sentinel.config import ARTIFACTS, PROJECT_ROOT, RANDOM_SEED

SRC = PROJECT_ROOT / "malware" / "malware.csv"
DROP = {"Name", "md5", "legitimate"}


def main() -> None:
    if not SRC.exists():
        print(f"{SRC} not found")
        return
    df = pd.read_csv(SRC, sep="|", on_bad_lines="skip")
    print(f"  {len(df):,} samples, {len(df.columns)} columns")

    # The dataset labels 1 = legitimate. Flip it so 1 = malicious throughout,
    # matching every other model here; a silent polarity difference between two
    # models in one system is a bug waiting to happen.
    y = (1 - df["legitimate"]).to_numpy()
    feats = [c for c in df.columns if c not in DROP]
    X = df[feats].apply(pd.to_numeric, errors="coerce").fillna(0).to_numpy(np.float32)
    print(f"  {int(y.sum()):,} malicious / {int((1-y).sum()):,} legitimate "
          f"({y.mean():.1%} malicious)")

    # Split by md5 so two copies of the same binary cannot straddle the split.
    groups = df["md5"].astype(str).to_numpy()
    uniq = np.unique(groups)
    rng = np.random.default_rng(RANDOM_SEED)
    rng.shuffle(uniq)
    test_ids = set(uniq[:int(len(uniq) * 0.2)].tolist())
    te = np.array([g in test_ids for g in groups])
    tr = ~te
    print(f"  split by file hash: {tr.sum():,} train / {te.sum():,} test")

    params = dict(objective="binary", metric=["binary_logloss", "auc"],
                  learning_rate=0.05, num_leaves=96, min_data_in_leaf=40,
                  feature_fraction=0.85, bagging_fraction=0.85, bagging_freq=1,
                  lambda_l2=1.0, verbosity=-1, num_threads=0, seed=RANDOM_SEED)
    d_tr = lgb.Dataset(X[tr], label=y[tr], feature_name=feats)
    d_te = lgb.Dataset(X[te], label=y[te], feature_name=feats, reference=d_tr)
    gbm = lgb.train(params, d_tr, num_boost_round=800, valid_sets=[d_te],
                    callbacks=[lgb.early_stopping(60, verbose=False),
                               lgb.log_evaluation(200)])

    p = gbm.predict(X[te])
    pred = (p >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y[te], pred).ravel()
    print(f"\n  ROC-AUC {roc_auc_score(y[te], p):.4f}   "
          f"PR-AUC {average_precision_score(y[te], p):.4f}")
    print(classification_report(y[te], pred, target_names=["legitimate", "malicious"],
                                digits=4))
    print(f"  confusion: TN={tn:,} FP={fp:,} FN={fn:,} TP={tp:,}")
    print(f"  false-positive rate on legitimate binaries: {fp/max(fp+tn,1):.4f}")

    imp = sorted(zip(feats, gbm.feature_importance("gain")), key=lambda x: -x[1])
    print("\n  top features by gain:")
    for n, g in imp[:8]:
        print(f"    {n:34} {g:,.0f}")

    out = ARTIFACTS / "pe_model.txt"
    gbm.save_model(str(out), num_iteration=gbm.best_iteration)
    (ARTIFACTS / "pe_model_features.json").write_text(json.dumps(feats))
    (ARTIFACTS / "pe_metrics.json").write_text(json.dumps({
        "n": int(len(df)), "roc_auc": float(roc_auc_score(y[te], p)),
        "pr_auc": float(average_precision_score(y[te], p)),
        "fpr": float(fp / max(fp + tn, 1)), "best_iteration": int(gbm.best_iteration),
        "caveat": "static PE header features only; says nothing about ISO, LNK, "
                  "macro documents or HTML smuggling",
        "dataset_artifact_warning": (
            "ImageBase alone reaches 0.938 ROC-AUC on this dataset: 99% of the "
            "malicious samples use 0x400000 against 12% of the legitimate ones, "
            "which is the default for older 32-bit toolchains. A large part of "
            "this score is compiler era, not maliciousness. Do not quote 0.9998 "
            "as real-world detection; validate against EMBER or SOREL before "
            "claiming anything about live files."),
    }, indent=2))
    print(f"\n  saved -> {out}")


if __name__ == "__main__":
    main()
