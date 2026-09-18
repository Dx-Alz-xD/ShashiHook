"""A URL classifier -- TRAINED, MEASURED, AND DELIBERATELY NOT WIRED IN.

Read this before re-enabling it.

It reaches 0.9850 ROC-AUC held out by registrable domain on the
malicious-urls dataset, and on that dataset it discriminates cleanly: benign
URLs average 0.022, phishing 0.907, malware 0.967. Those numbers are real.

They do not transfer. Measured against 497 URLs taken from real, legitimate
mail in an actual inbox:

    scored above 0.5   462  (93.0%)
    scored above 0.9   428  (86.1%)
    mean 0.887, median 0.978

github.com/settings/notifications, myaccount.google.com/notifications and
about.collegeboard.org/contact-us all score 0.987.

The cause is the benign class, not the labels. That dataset's benign examples
are overwhelmingly bare domains and short paths -- "kenbarlow.net/",
"cgs.illinois.edu/people/faculty/paul-diehl". Modern legitimate mail links to
long, hyphenated, parameter-heavy URLs, which is exactly the surface shape the
model learned to call hostile. A textbook distribution shift: the training
benign class is not the deployment benign class.

Wiring it in would have flagged essentially every message in the inbox. It is
kept here, unused, because the measurement is worth more than the model -- a
held-out AUC of 0.985 said nothing about the population we actually score, and
only testing against real mail revealed it.

To make it usable: rebuild the benign class from modern legitimate URLs --
Tranco top-1M paths, or the URLs already in local_ham.parquet -- then
re-measure against real mail before trusting it again.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import numpy as np

from ..config import ARTIFACTS
from ..features.urls import UrlFact, url_features


@dataclass
class UrlOpinion:
    scored: int = 0
    max_score: float = 0.0
    mean_score: float = 0.0
    worst_url: str = ""

    def describe(self) -> str:
        if not self.scored:
            return ""
        return (f"URL model scores the most suspicious link {self.max_score:.2f} "
                f"({self.worst_url[:70]})")


class UrlModel:
    def __init__(self, path: Path = ARTIFACTS / "url_model.joblib"):
        self.ok = False
        try:
            import joblib
            import lightgbm as lgb
            d = joblib.load(path)
            self.vec, self.lex = d["vec"], d["lex"]
            self.gbm = lgb.Booster(model_str=d["gbm_str"])
            self.names = d["features"]
            self.ok = True
        except Exception:
            pass   # absent model = no opinion, which is the honest default

    def score_urls(self, facts: list[UrlFact]) -> UrlOpinion:
        op = UrlOpinion()
        if not self.ok or not facts:
            return op
        raws = [f.raw for f in facts][:12]
        try:
            Xw = self.vec.transform(raws)
            lexs = self.lex.decision_function(Xw)
            rows = []
            for f, l in zip(facts[:12], lexs):
                single = url_features([f])
                rows.append([single[k] for k in sorted(single)] + [float(l)])
            p = self.gbm.predict(np.array(rows, dtype=np.float32))
        except Exception:
            return op
        p = np.atleast_1d(p)
        op.scored = len(p)
        op.max_score = float(p.max())
        op.mean_score = float(p.mean())
        op.worst_url = raws[int(p.argmax())]
        return op


def urlmodel_features(op: UrlOpinion) -> dict[str, float]:
    return {"urm_scored": float(op.scored > 0),
            "urm_max": float(op.max_score),
            "urm_mean": float(op.mean_score)}


URLMODEL_FEATURE_NAMES = tuple(urlmodel_features(UrlOpinion()).keys())
