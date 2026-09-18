"""What the pipeline actually emits across the whole held-out set.

Answers the operational questions: how many messages get a resolved attack
vector, how many get a real response plan rather than "send it to a human",
and what the severity distribution looks like in practice.

SHAP is computed for a subsample only -- it does not influence the vector or
the severity, so excluding it from the sweep changes none of these counts, and
including it for all 15,103 messages would add ~20 minutes for no new number.
"""
from __future__ import annotations

import sys
import time
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sentinel.config import ARTIFACTS
from sentinel.features.extractor import Email, extract, to_vector
from sentinel.labeling.taxonomy import describe
from sentinel.labeling.weak_rules import vote
from sentinel.models.intent import IntentModel
from sentinel.models.vector import VectorModel
from sentinel.scoring.floors import apply as apply_floors
from sentinel.scoring.floors import applicable as applicable_floors
from sentinel.scoring.floors import implied_vector
from sentinel.scoring.severity import score as severity_score

BAND_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]


def main() -> None:
    X = np.load(ARTIFACTS / "X.npy")
    meta = pd.read_parquet(ARTIFACTS / "meta.parquet")
    texts = np.array(pd.read_parquet(ARTIFACTS / "text.parquet")["text"].tolist(), dtype=object)
    te = np.where((meta["split"] == "test").to_numpy())[0]
    y = meta["label"].to_numpy()[te]

    intent = IntentModel.load(ARTIFACTS / "intent_model.joblib")
    vmodel = VectorModel.load(ARTIFACTS / "vector_model.joblib")

    print(f"Running the full resolution path over {len(te):,} held-out messages")
    t0 = time.time()
    p_model = intent.predict_proba(X[te], list(texts[te]))

    rows = []
    sub = meta.iloc[te]
    for k, (i, r) in enumerate(zip(te, sub.itertuples(index=False))):
        e = Email(subject=r.subject, body=texts[i], sender=r.sender,
                  receiver=r.receiver, date=r.date, source=r.source)
        feats, ev = extract(e)
        Xr = X[i].reshape(1, -1)

        fired = applicable_floors(e, feats, ev)
        p, binding = apply_floors(float(p_model[k]), fired)
        malicious = p >= 0.5

        rule_vec, rule_conf, totals, _ = vote(e, feats, ev, malicious)
        rule_w = max(totals.values()) if totals else 0.0
        if not malicious:
            vec, vconf, vsrc = "benign", 1.0, "intent model"
        else:
            vec, vconf, vsrc = vmodel.resolve(Xr, [texts[i]], rule_vec, rule_w)
            implied, by = implied_vector(binding)
            if implied and (vsrc != "rule" or rule_w < 2.5):
                vec, vconf, vsrc = implied, 0.9, "floor"
        sev = severity_score(feats, ev, p, vec)
        rows.append({"y": int(y[k]), "p": p, "vector": vec, "src": vsrc,
                     "band": sev.band, "score": sev.score,
                     "n_actions": len(describe(vec).default_actions),
                     "n_iocs": len(ev.urls) + (1 if ev.sender.address else 0)})
        if (k + 1) % 5000 == 0:
            print(f"  {k+1:,}/{len(te):,}")
    df = pd.DataFrame(rows)
    dt = time.time() - t0
    print(f"  done in {dt:.0f}s  ({dt/len(te)*1000:.1f} ms/message, resolution path only)\n")

    flagged = df[df.p >= 0.5]
    print("=" * 74)
    print(f"OUTPUT COVERAGE  --  {len(flagged):,} of {len(df):,} messages flagged malicious")
    print("=" * 74)

    print("\nEvery flagged message gets a vector. How was it resolved?")
    for src, n in flagged["src"].value_counts().items():
        print(f"  {src:24} {n:>7,}  ({n/len(flagged):5.1%})")
    unres = int((flagged.vector == "malicious_unclassified").sum())
    print(f"\n  left unresolved          {unres:>7,}  ({unres/len(flagged):5.1%})"
          f"  <- routed to an analyst")

    print("\nAttack vector assigned:")
    for v, n in flagged["vector"].value_counts().items():
        acts = describe(v).default_actions
        print(f"  {v:24} {n:>7,}  ({n/len(flagged):5.1%})  "
              f"{len(acts)} response step(s)")

    print("\nSeverity band, all scored messages:")
    for b in BAND_ORDER:
        n = int((df.band == b).sum())
        if n:
            tp = int(((df.band == b) & (df.y == 1)).sum())
            print(f"  {b:16} {n:>7,}  ({n/len(df):5.1%})   truly malicious: "
                  f"{tp:,}/{n:,} = {tp/n:5.1%}")

    print("\nSeverity band by vector (flagged only):")
    ct = pd.crosstab(flagged["vector"], flagged["band"])
    ct = ct.reindex(columns=[b for b in BAND_ORDER if b in ct.columns], fill_value=0)
    print(ct.to_string())

    print("\nActionable output per flagged message:")
    print(f"  with a vector-specific response plan  "
          f"{int((flagged.n_actions>0).sum()):>7,}  "
          f"({(flagged.n_actions>0).mean():5.1%})")
    print(f"  with at least one extractable IOC     "
          f"{int((flagged.n_iocs>0).sum()):>7,}  ({(flagged.n_iocs>0).mean():5.1%})")
    print(f"  mean IOCs per flagged message         {flagged.n_iocs.mean():>7.1f}")

    print("\nTriage load implied by the severity bands:")
    for b in BAND_ORDER:
        n = int((df.band == b).sum())
        if n:
            print(f"  {b:16} {n:>7,}  {n/len(df)*100:5.1f}% of all mail scored")


if __name__ == "__main__":
    main()
