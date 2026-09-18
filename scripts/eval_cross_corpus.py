"""Leave-one-corpus-out evaluation.

The headline 99.4% is measured on a random split of the same corpora the model
trained on. That number answers "can it recognise more of what it has already
seen", which is not the question a SOC is asking. Holding an entire corpus out
answers the harder one: does it generalise to mail it has never seen the style
of? The gap between the two is the honest measure of transfer.
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.sparse import hstack
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score

import lightgbm as lgb

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sentinel.config import ARTIFACTS
from sentinel.models.intent import GBM_PARAMS, build_vectorizers


def main() -> None:
    X = np.load(ARTIFACTS / "X.npy")
    meta = pd.read_parquet(ARTIFACTS / "meta.parquet")
    texts = np.array(pd.read_parquet(ARTIFACTS / "text.parquet")["text"].tolist(), dtype=object)
    names = (ARTIFACTS / "feature_names.txt").read_text().split("\n")
    y = meta["label"].to_numpy()

    print("=" * 84)
    print("LEAVE-ONE-CORPUS-OUT  --  train on every other corpus, test on the held-out one")
    print("=" * 84)
    print(f"{'held-out corpus':16} {'n':>7} {'pos rate':>9} {'structural':>11} "
          f"{'wording':>9} {'best':>8}")
    print("-" * 84)

    results = []
    for corpus in meta["source"].unique():
        te = (meta["source"] == corpus).to_numpy()
        tr = ~te
        if len(np.unique(y[te])) < 2:
            print(f"{corpus:16} {te.sum():>7,} {'single-class -- cannot score AUC':>50}")
            continue

        gbm = lgb.train(GBM_PARAMS, lgb.Dataset(X[tr], label=y[tr], feature_name=names),
                        num_boost_round=300)
        s_struct = gbm.predict(X[te], raw_score=True)

        wv, cv = build_vectorizers()
        A = hstack([wv.fit_transform(texts[tr]), cv.fit_transform(texts[tr])]).tocsr()
        B = hstack([wv.transform(texts[te]), cv.transform(texts[te])]).tocsr()
        lex = LogisticRegression(C=4.0, max_iter=2000, solver="liblinear").fit(A, y[tr])
        s_word = lex.decision_function(B)

        a_s = roc_auc_score(y[te], s_struct)
        a_w = roc_auc_score(y[te], s_word)
        results.append((corpus, int(te.sum()), a_s, a_w))
        print(f"{corpus:16} {te.sum():>7,} {y[te].mean():>9.1%} {a_s:>11.4f} "
              f"{a_w:>9.4f} {max(a_s, a_w):>8.4f}")

    if results:
        print("-" * 84)
        ms = float(np.mean([r[2] for r in results]))
        mw = float(np.mean([r[3] for r in results]))
        print(f"{'mean':16} {'':>7} {'':>9} {ms:>11.4f} {mw:>9.4f}")
        print("\nCompare with the random-split test score of ROC-AUC 0.9995.")
        print("The drop is the cost of style transfer: a random split lets the model see")
        print("messages from every corpus during training, so it only has to recognise")
        print("more of the same. Holding a corpus out removes that crutch.")


if __name__ == "__main__":
    main()
