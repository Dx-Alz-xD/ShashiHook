"""Train a URL classifier on 651,191 labelled URLs.

Nineteen URL features exist in this system and almost none of them carry
weight, because the email corpora are from 2002-2008 and contain no punycode,
no high-abuse TLDs and barely any credential paths -- measured, those features
fire on 0.00% of corpus mail. The model has never seen them do anything, so it
learned to ignore them.

This dataset has the opposite shape: 651k URLs, a fifth of them hostile, where
those properties are the whole signal. Training a dedicated classifier here and
feeding its score back as one feature gives the email model a URL opinion
formed on data that actually contains URLs.

Evaluation is grouped by registrable domain. A random split would put
/login and /login2 from one phishing host on both sides and report a score that
measures memorising hosts rather than recognising them.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, roc_auc_score

import lightgbm as lgb

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sentinel.config import ARTIFACTS, PROJECT_ROOT, RANDOM_SEED
from sentinel.features.headers import registrable_domain
from sentinel.features.urls import extract_urls, url_features

SRC = PROJECT_ROOT / "data" / "kaggle" / "malicious_phish.csv"


def structural(url: str) -> list[float]:
    """The same view the email pipeline takes of a link, so what is learned
    here transfers rather than describing a different object."""
    facts = extract_urls(url if "://" in url else f"http://{url}")
    f = url_features(facts)
    return [f[k] for k in sorted(f)]


def main() -> None:
    if not SRC.exists():
        print(f"{SRC} not found")
        return
    df = pd.read_csv(SRC).dropna(subset=["url", "type"])
    df["url"] = df["url"].astype(str).str.strip()
    df = df[df["url"].str.len().between(6, 500)]
    # defacement is a compromised legitimate site, not a lure sent to you --
    # a different problem, and keeping it blurs what "malicious" means here.
    df = df[df["type"].isin(["benign", "phishing", "malware"])]
    y = (df["type"] != "benign").astype(int).to_numpy()
    print(f"  {len(df):,} URLs   {y.sum():,} hostile ({y.mean():.1%})")
    print(f"  {df['type'].value_counts().to_dict()}")

    dom = df["url"].map(lambda u: registrable_domain(
        u.split("//")[-1].split("/")[0].split(":")[0].lower()))
    uniq = dom.unique()
    rng = np.random.default_rng(RANDOM_SEED)
    rng.shuffle(uniq)
    test_dom = set(uniq[:int(len(uniq) * 0.2)])
    te = dom.isin(test_dom).to_numpy()
    tr = ~te
    print(f"  grouped by domain: {tr.sum():,} train / {te.sum():,} test "
          f"({len(uniq):,} distinct domains)")

    # Character n-grams over the URL string catch the lexical shape of a lure;
    # the structural features catch what the email pipeline can also see.
    vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=5,
                          max_features=300_000, sublinear_tf=True, lowercase=True)
    Xw_tr = vec.fit_transform(df["url"][tr])
    Xw_te = vec.transform(df["url"][te])
    lex = LogisticRegression(C=4.0, max_iter=1500, solver="liblinear").fit(Xw_tr, y[tr])
    print(f"  character n-grams: {Xw_tr.shape[1]:,}")

    print("  extracting structural features …")
    S = np.array([structural(u) for u in df["url"]], dtype=np.float32)
    names = sorted(url_features([]).keys()) + ["url_lexical_score"]
    Str = np.hstack([S[tr], lex.decision_function(Xw_tr).reshape(-1, 1)]).astype(np.float32)
    Ste = np.hstack([S[te], lex.decision_function(Xw_te).reshape(-1, 1)]).astype(np.float32)

    gbm = lgb.train(
        dict(objective="binary", metric=["binary_logloss", "auc"], learning_rate=0.06,
             num_leaves=96, min_data_in_leaf=40, feature_fraction=0.85,
             bagging_fraction=0.85, bagging_freq=1, lambda_l2=1.0,
             verbosity=-1, num_threads=0, seed=RANDOM_SEED),
        lgb.Dataset(Str, label=y[tr], feature_name=names), num_boost_round=700,
        valid_sets=[lgb.Dataset(Ste, label=y[te], feature_name=names)],
        callbacks=[lgb.early_stopping(50, verbose=False), lgb.log_evaluation(200)])

    p = gbm.predict(Ste)
    print(f"\n  held-out by domain: ROC-AUC {roc_auc_score(y[te], p):.4f}")
    print(classification_report(y[te], (p >= .5).astype(int),
                                target_names=["benign", "hostile"], digits=4))
    print(f"  lexical view alone: ROC-AUC "
          f"{roc_auc_score(y[te], lex.decision_function(Xw_te)):.4f}")

    imp = sorted(zip(names, gbm.feature_importance("gain")), key=lambda x: -x[1])
    print("\n  top features by gain:")
    for n, g in imp[:8]:
        print(f"    {n:28} {g:,.0f}")

    import joblib
    joblib.dump({"vec": vec, "lex": lex, "gbm_str": gbm.model_to_string(),
                 "features": names}, ARTIFACTS / "url_model.joblib", compress=3)
    (ARTIFACTS / "url_metrics.json").write_text(json.dumps({
        "n": int(len(df)), "roc_auc": float(roc_auc_score(y[te], p)),
        "lexical_only_auc": float(roc_auc_score(y[te], lex.decision_function(Xw_te))),
        "split": "grouped by registrable domain",
    }, indent=2))
    print(f"\n  saved -> {ARTIFACTS/'url_model.joblib'}")


if __name__ == "__main__":
    main()
