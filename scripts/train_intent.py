"""Train and calibrate the intent model, then report honest test metrics."""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.sparse import hstack
from sklearn.calibration import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (average_precision_score, brier_score_loss,
                             classification_report, confusion_matrix, roc_auc_score)
from sklearn.model_selection import StratifiedKFold

import lightgbm as lgb

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sentinel.config import ARTIFACTS, RANDOM_SEED
from sentinel.models.intent import GBM_PARAMS, IntentModel, build_vectorizers


def main() -> None:
    X = np.load(ARTIFACTS / "X.npy")
    meta = pd.read_parquet(ARTIFACTS / "meta.parquet")
    texts = pd.read_parquet(ARTIFACTS / "text.parquet")["text"].tolist()
    names = (ARTIFACTS / "feature_names.txt").read_text().split("\n")

    y = meta["label"].to_numpy()
    # Phishing-only sources are excluded here; see build_dataset.py for the
    # measurement that motivated it.
    usable = meta.get("use_for_intent")
    usable = usable.to_numpy() if usable is not None else np.ones(len(meta), bool)
    is_train = ((meta["split"] == "train").to_numpy()) & usable
    tr_idx = np.where(is_train)[0]
    te_idx = np.where(((meta["split"] == "test").to_numpy()) & usable)[0]

    # Carve a calibration slice out of train. It never trains either model, so
    # the isotonic fit sees genuinely out-of-sample scores.
    rng = np.random.default_rng(RANDOM_SEED)
    perm = rng.permutation(tr_idx)
    n_cal = int(0.15 * len(perm))
    cal_idx, core_idx = perm[:n_cal], perm[n_cal:]
    print(f"core={len(core_idx):,}  calib={len(cal_idx):,}  test={len(te_idx):,}")

    tx = np.array(texts, dtype=object)

    # --------------------------------------------------- view 1: the wording
    print("\n[1/4] Fitting word + char n-gram vectorizers")
    t0 = time.time()
    word_vec, char_vec = build_vectorizers()
    Xw = word_vec.fit_transform(tx[core_idx])
    Xc = char_vec.fit_transform(tx[core_idx])
    Xs_core = hstack([Xw, Xc]).tocsr()
    print(f"      {Xs_core.shape[1]:,} n-gram features in {time.time()-t0:.0f}s")
    lexical = LogisticRegression(C=4.0, max_iter=2000, solver="liblinear")
    lexical.fit(Xs_core, y[core_idx])

    def word_logit(idx):
        Xq = hstack([word_vec.transform(tx[idx]), char_vec.transform(tx[idx])]).tocsr()
        return lexical.decision_function(Xq)

    # ------------------------------------------------ view 2: the structure
    print("[2/4] Training gradient-boosted trees on the 123 named features")
    dtrain = lgb.Dataset(X[core_idx], label=y[core_idx], feature_name=names)
    dvalid = lgb.Dataset(X[cal_idx], label=y[cal_idx], feature_name=names, reference=dtrain)
    gbm = lgb.train(GBM_PARAMS, dtrain, num_boost_round=1500, valid_sets=[dvalid],
                    callbacks=[lgb.early_stopping(75, verbose=False), lgb.log_evaluation(300)])
    print(f"      best iteration: {gbm.best_iteration}")

    # --------------------------------------------------------- the blender
    # Fitted on the calibration slice, which trained neither view, so the
    # blender learns how much to trust each on genuinely unseen messages.
    print("[3/4] Fitting the two-input blender")
    B_cal = np.column_stack([gbm.predict(X[cal_idx], raw_score=True), word_logit(cal_idx)])
    blender = LogisticRegression(C=1.0, max_iter=1000).fit(B_cal, y[cal_idx])
    w = blender.coef_[0]
    print(f"      structural weight = {w[0]:.4f}   wording weight = {w[1]:.4f}"
          f"   intercept = {blender.intercept_[0]:.4f}")

    print("[4/4] Isotonic calibration")
    raw_cal = blender.decision_function(B_cal)
    calibrator = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
    calibrator.fit(raw_cal, y[cal_idx])

    model = IntentModel(word_vec, char_vec, lexical, gbm, blender, calibrator, names)
    model.save(ARTIFACTS / "intent_model.joblib")

    # ------------------------------------------------------------------ report
    B_test = np.column_stack([gbm.predict(X[te_idx], raw_score=True), word_logit(te_idx)])
    raw_test = blender.decision_function(B_test)
    p_test = calibrator.predict(raw_test)
    yt = y[te_idx]

    print("\n" + "=" * 72)
    print("TEST SET PERFORMANCE  (n = {:,}, held out by content group)".format(len(yt)))
    print("=" * 72)
    print(f"{'model':32} {'ROC-AUC':>9} {'PR-AUC':>9} {'Brier':>9}")
    for nm, sc in [("structural view alone", B_test[:, 0]),
                   ("wording view alone", B_test[:, 1]),
                   ("blended, uncalibrated", raw_test),
                   ("blended, calibrated", p_test)]:
        pr = sc if sc.min() >= 0 and sc.max() <= 1 else 1 / (1 + np.exp(-sc))
        print(f"{nm:32} {roc_auc_score(yt, sc):9.4f} "
              f"{average_precision_score(yt, sc):9.4f} {brier_score_loss(yt, pr):9.4f}")

    print("\nAt the 0.5 decision threshold:")
    print(classification_report(yt, (p_test >= 0.5).astype(int),
                                target_names=["benign", "malicious"], digits=4))
    tn, fp, fn, tp = confusion_matrix(yt, (p_test >= 0.5).astype(int)).ravel()
    print(f"confusion: TN={tn:,} FP={fp:,} FN={fn:,} TP={tp:,}")

    print("\nOperating points (a SOC cares about FP rate, not accuracy):")
    print(f"{'threshold':>10} {'precision':>10} {'recall':>9} {'FP':>7} {'FN':>7} {'FPR':>8}")
    for th in (0.5, 0.7, 0.8, 0.9, 0.95, 0.99):
        pred = (p_test >= th).astype(int)
        tp_ = int(((pred==1)&(yt==1)).sum()); fp_ = int(((pred==1)&(yt==0)).sum())
        fn_ = int(((pred==0)&(yt==1)).sum()); tn_ = int(((pred==0)&(yt==0)).sum())
        print(f"{th:>10.2f} {tp_/max(tp_+fp_,1):>10.4f} {tp_/max(tp_+fn_,1):>9.4f} "
              f"{fp_:>7,} {fn_:>7,} {fp_/max(fp_+tn_,1):>8.4f}")

    print("\nCalibration check (predicted vs. observed malicious rate):")
    bins = np.linspace(0, 1, 11); idx = np.digitize(p_test, bins) - 1
    for b in range(10):
        m_ = idx == b
        if m_.sum() < 20: continue
        print(f"  p in [{bins[b]:.1f},{bins[b+1]:.1f})  n={m_.sum():>6,}  "
              f"predicted={p_test[m_].mean():.3f}  observed={yt[m_].mean():.3f}")

    metrics = {"n_test": int(len(yt)), "roc_auc": float(roc_auc_score(yt, p_test)),
               "pr_auc": float(average_precision_score(yt, p_test)),
               "brier": float(brier_score_loss(yt, p_test)),
               "structural_only_auc": float(roc_auc_score(yt, B_test[:, 0])),
               "wording_only_auc": float(roc_auc_score(yt, B_test[:, 1])),
               "blend_weights": {"structural": float(w[0]), "wording": float(w[1])},
               "best_iteration": int(gbm.best_iteration),
               "n_ngram_features": int(Xs_core.shape[1])}
    (ARTIFACTS / "intent_metrics.json").write_text(json.dumps(metrics, indent=2))
    print(f"\nSaved model -> {ARTIFACTS/'intent_model.joblib'}")


if __name__ == "__main__":
    main()
