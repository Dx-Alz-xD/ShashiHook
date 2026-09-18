"""End-to-end evaluation on the held-out split, with the floor layer active."""
from __future__ import annotations

import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (average_precision_score, classification_report,
                             confusion_matrix, roc_auc_score)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sentinel.config import ARTIFACTS
from sentinel.features.extractor import Email
from sentinel.models.intent import IntentModel
from sentinel.scoring.floors import apply as apply_floors
from sentinel.scoring.floors import applicable as applicable_floors
from sentinel.features.extractor import extract


def main() -> None:
    X = np.load(ARTIFACTS / "X.npy")
    meta = pd.read_parquet(ARTIFACTS / "meta.parquet")
    texts = np.array(pd.read_parquet(ARTIFACTS / "text.parquet")["text"].tolist(), dtype=object)
    te = np.where((meta["split"] == "test").to_numpy())[0]
    y = meta["label"].to_numpy()[te]

    model = IntentModel.load(ARTIFACTS / "intent_model.joblib")
    print(f"Scoring {len(te):,} held-out messages")
    t0 = time.time()
    p_model = model.predict_proba(X[te], list(texts[te]))
    print(f"  model pass: {time.time()-t0:.0f}s")

    # Re-extract evidence so the floor layer sees the same inputs it would at
    # inference time.
    print("  applying deterministic floors")
    sub = meta.iloc[te]
    p_final = p_model.copy()
    n_fired = n_binding = 0
    floor_names: dict[str, int] = {}
    floor_fp: dict[str, int] = {}
    for k, (i, row) in enumerate(zip(te, sub.itertuples(index=False))):
        e = Email(subject=row.subject, body=texts[i], sender=row.sender,
                  receiver=row.receiver, date=row.date, source=row.source)
        feats, ev = extract(e)
        fired = applicable_floors(e, feats, ev)
        if fired:
            n_fired += 1
        adj, binding = apply_floors(float(p_model[k]), fired)
        if binding:
            n_binding += 1
            p_final[k] = adj
            for f in binding:
                floor_names[f.name] = floor_names.get(f.name, 0) + 1
                if y[k] == 0:
                    floor_fp[f.name] = floor_fp.get(f.name, 0) + 1

    print(f"  floors matched on {n_fired:,} messages, changed the score on {n_binding:,}")

    print("\n" + "=" * 74)
    print("HELD-OUT TEST SET, FULL PIPELINE")
    print("=" * 74)
    for name, p in (("model only", p_model), ("model + deterministic floors", p_final)):
        pred = (p >= 0.5).astype(int)
        tn, fp, fn, tp = confusion_matrix(y, pred).ravel()
        print(f"\n{name}:")
        print(f"  ROC-AUC {roc_auc_score(y, p):.4f}   PR-AUC {average_precision_score(y, p):.4f}")
        print(f"  precision {tp/max(tp+fp,1):.4f}  recall {tp/max(tp+fn,1):.4f}  "
              f"FP {fp:,}  FN {fn:,}  FPR {fp/max(fp+tn,1):.4f}")

    print("\nFloor-by-floor behaviour on held-out mail")
    print(f"{'floor':32} {'fired':>8} {'on benign':>11} {'FP rate':>9}")
    for name, n in sorted(floor_names.items(), key=lambda kv: -kv[1]):
        bad = floor_fp.get(name, 0)
        print(f"{name:32} {n:>8,} {bad:>11,} {bad/n:>9.3f}")
    total_bad = sum(floor_fp.values())
    print(f"{'TOTAL':32} {sum(floor_names.values()):>8,} {total_bad:>11,}")

    # Sources excluded from intent training are a genuine out-of-distribution
    # test: a different collector, different years, never seen in any form.
    # The gap between the two lines below is the real generalisation number.
    usable = meta.get("use_for_intent")
    if usable is not None:
        is_ood = (~usable.to_numpy())[te]
        if is_ood.any():
            print("\nIn-distribution vs out-of-distribution:")
            for label, mask in (("trained-on sources", ~is_ood),
                                ("held-out sources  ", is_ood)):
                yy, pp = y[mask], p_final[mask]
                if not len(yy):
                    continue
                pos = yy == 1
                rec = float((pp[pos] >= 0.5).mean()) if pos.any() else float("nan")
                extra = ""
                if len(set(yy)) > 1:
                    extra = f"  ROC-AUC {roc_auc_score(yy, pp):.4f}"
                print(f"  {label}  n={len(yy):>6,}  recall@0.5 {rec:.4f}{extra}")

    print("\nDelta introduced by the floor layer:")
    moved = np.where(p_final != p_model)[0]
    if len(moved):
        gained = int(((p_model[moved] < 0.5) & (p_final[moved] >= 0.5) & (y[moved] == 1)).sum())
        cost = int(((p_model[moved] < 0.5) & (p_final[moved] >= 0.5) & (y[moved] == 0)).sum())
        print(f"  newly caught true positives: {gained:,}")
        print(f"  newly created false positives: {cost:,}")


if __name__ == "__main__":
    main()
