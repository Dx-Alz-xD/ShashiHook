"""Train the attack-vector classifier on the learnable subset of weak labels."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix

import lightgbm as lgb

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sentinel.config import ARTIFACTS, RANDOM_SEED
from sentinel.models.vector import LEARNABLE, VectorModel


def main() -> None:
    X = np.load(ARTIFACTS / "X.npy")
    meta = pd.read_parquet(ARTIFACTS / "meta.parquet")
    texts = np.array(pd.read_parquet(ARTIFACTS / "text.parquet")["text"].tolist(), dtype=object)
    names = (ARTIFACTS / "feature_names.txt").read_text().split("\n")

    # Only rows a rule labelled confidently, and only learnable classes.
    keep = (meta.label == 1) & meta.vector.isin(LEARNABLE) & (meta.vector_confidence >= 0.5)
    tr = keep & (meta.split == "train")
    te = keep & (meta.split == "test")
    tr_i, te_i = np.where(tr)[0], np.where(te)[0]

    classes = list(LEARNABLE)
    cmap = {c: i for i, c in enumerate(classes)}
    ytr = meta.vector.iloc[tr_i].map(cmap).to_numpy()
    yte = meta.vector.iloc[te_i].map(cmap).to_numpy()

    print("Training on rule-labelled rows (confidence >= 0.5):")
    for c in classes:
        print(f"  {c:22} train={int((ytr==cmap[c]).sum()):>6,}  test={int((yte==cmap[c]).sum()):>5,}")

    word_vec = TfidfVectorizer(ngram_range=(1, 2), min_df=3, max_df=0.6,
                               max_features=200_000, sublinear_tf=True,
                               strip_accents="unicode")
    Xw = word_vec.fit_transform(texts[tr_i])
    lexical = LogisticRegression(C=4.0, max_iter=2000, solver="lbfgs").fit(Xw, ytr)

    feat_names = names + [f"wording_p_{c}" for c in classes]
    Str = np.hstack([X[tr_i], lexical.predict_proba(Xw)]).astype(np.float32)
    Ste = np.hstack([X[te_i], lexical.predict_proba(word_vec.transform(texts[te_i]))]).astype(np.float32)

    params = dict(objective="multiclass", num_class=len(classes), metric="multi_logloss",
                  learning_rate=0.06, num_leaves=64, min_data_in_leaf=25,
                  feature_fraction=0.85, bagging_fraction=0.85, bagging_freq=1,
                  lambda_l2=1.0, verbosity=-1, num_threads=0, seed=RANDOM_SEED)
    dtr = lgb.Dataset(Str, label=ytr, feature_name=feat_names)
    dte = lgb.Dataset(Ste, label=yte, feature_name=feat_names, reference=dtr)
    gbm = lgb.train(params, dtr, num_boost_round=800, valid_sets=[dte],
                    callbacks=[lgb.early_stopping(50, verbose=False), lgb.log_evaluation(200)])

    pred = gbm.predict(Ste).argmax(axis=1)
    print(f"\nHeld-out agreement with the labelling rules (best_iter={gbm.best_iteration}):")
    print(classification_report(yte, pred, target_names=classes, digits=4, zero_division=0))
    print("confusion (rows = rule label, cols = model):")
    cm = confusion_matrix(yte, pred)
    print(f"{'':22}" + "".join(f"{c[:11]:>13}" for c in classes))
    for i, c in enumerate(classes):
        print(f"{c:22}" + "".join(f"{v:>13,}" for v in cm[i]))
    print("\nNOTE: this measures agreement with the weak rules, NOT ground truth.")
    print("      Real vector accuracy needs the human-labelled gold set")
    print("      (scripts/build_gold_set.py).")

    VectorModel(word_vec, lexical, gbm, classes, feat_names).save(ARTIFACTS / "vector_model.joblib")
    (ARTIFACTS / "vector_metrics.json").write_text(json.dumps({
        "classes": classes,
        "train_counts": {c: int((ytr == i).sum()) for i, c in enumerate(classes)},
        "test_counts": {c: int((yte == i).sum()) for i, c in enumerate(classes)},
        "agreement_accuracy": float((pred == yte).mean()),
        "caveat": "agreement with weak labelling rules, not ground truth",
    }, indent=2))
    print(f"\nSaved -> {ARTIFACTS/'vector_model.joblib'}")


if __name__ == "__main__":
    main()
