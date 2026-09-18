"""Mine EMSCAD for job-scam language, and test whether it transfers to email.

`job_scam` has four training examples. EMSCAD has 866 labelled-fraudulent job
postings, and the language of a fake posting is close to the language of a
job-scam email -- registration fees, no interview, immediate start, move to
WhatsApp.

Close is not the same, though. A posting has no greeting, no sender and no
recipient, and the URL model built from the malicious-URLs dataset showed what
happens when a model trained on one population is pointed at another: 0.985
held-out AUC and 93% false positives on real mail.

So this does two things and trusts only the first:

  mine       find phrases that separate fraudulent from genuine postings, for
             a human to fold into the lexicon. Phrases transfer; models may not.
  measure    train a classifier and check it against real inbox mail before
             anyone wires it anywhere.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sentinel.config import ARTIFACTS, PROJECT_ROOT, RANDOM_SEED

SRC = PROJECT_ROOT / "data" / "kaggle" / "emscad.csv"
TEXT_COLS = ["title", "company_profile", "description", "requirements", "benefits"]


def main() -> None:
    if not SRC.exists():
        print(f"{SRC} not found")
        return
    df = pd.read_csv(SRC, low_memory=False)
    df["fraudulent"] = (df["fraudulent"].astype(str).str.lower()
                        .isin(["t", "true", "1"])).astype(int)
    df["text"] = (df[TEXT_COLS].fillna("").agg(" ".join, axis=1)
                  .str.replace(r"\s+", " ", regex=True).str.strip())
    df = df[df["text"].str.split().str.len() >= 20]
    y = df["fraudulent"].to_numpy()
    print(f"  {len(df):,} postings   {y.sum():,} fraudulent ({y.mean():.1%})")

    Xtr, Xte, ytr, yte = train_test_split(df["text"], y, test_size=0.25,
                                          random_state=RANDOM_SEED, stratify=y)
    vec = TfidfVectorizer(ngram_range=(1, 3), min_df=4, max_df=0.6,
                          max_features=200_000, sublinear_tf=True,
                          strip_accents="unicode")
    A = vec.fit_transform(Xtr)
    clf = LogisticRegression(C=4.0, max_iter=2000, class_weight="balanced",
                             solver="liblinear").fit(A, ytr)
    p = clf.predict_proba(vec.transform(Xte))[:, 1]
    print(f"\n  on POSTINGS (its own distribution): ROC-AUC {roc_auc_score(yte, p):.4f}")
    print(classification_report(yte, (p >= .5).astype(int),
                                target_names=["genuine", "fraudulent"], digits=4))

    # --- the transferable part: phrases, ranked by how much they separate ----
    names = np.array(vec.get_feature_names_out())
    coef = clf.coef_[0]
    order = np.argsort(-coef)
    scam_terms = [(names[i], coef[i]) for i in order[:400]]
    # Multi-word only: single words carry too little context to become a rule.
    phrases = [(t, c) for t, c in scam_terms if " " in t][:45]
    print("  phrases that most distinguish a fraudulent posting:")
    for t, c in phrases[:30]:
        print(f"    {c:6.2f}  {t}")

    out = ARTIFACTS / "job_scam_phrases.txt"
    out.write_text("\n".join(f"{c:.3f}\t{t}" for t, c in phrases))
    print(f"\n  {len(phrases)} phrases -> {out}")

    # --- does it transfer to email? measured, not assumed -------------------
    print("\n  TRANSFER CHECK — the same model applied to real inbox mail:")
    try:
        from sentinel.ingest import imap_box
        from sentinel.settings import settings
        from sentinel.features.extractor import strip_html
        bodies = []
        for m in imap_box.fetch(settings, "newer_than:120d", 120):
            try:
                e = imap_box.to_email(m)
            except Exception:
                continue
            b = strip_html(e.body or "")
            if len(b.split()) >= 20:
                bodies.append(b)
        if bodies:
            q = clf.predict_proba(vec.transform(bodies))[:, 1]
            print(f"    {len(bodies)} legitimate messages: "
                  f"mean {q.mean():.3f}, median {np.median(q):.3f}")
            for t in (0.5, 0.8):
                print(f"      above {t}: {(q >= t).sum()} ({(q >= t).mean():.1%})")
            if (q >= 0.5).mean() > 0.15:
                print("    -> DOES NOT TRANSFER. Use the phrases, not the model.")
            else:
                print("    -> transfers acceptably; the score could be used as a signal.")
    except Exception as e:
        print(f"    skipped ({type(e).__name__})")


if __name__ == "__main__":
    main()
