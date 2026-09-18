"""The intent model: is this message hostile, and how sure are we?

An earlier design fed the wording model's score into the tree model as one more
feature. It scored superbly and explained nothing: TreeSHAP assigned +7.5 of
7.66 log-odds to that single stacked feature, and every interpretable signal
was reduced to noise around it. The model was accurate and mute.

So the two views are kept parallel and combined explicitly:

  structural   gradient-boosted trees over 123 named features -- sender
               identity, URL structure, attachments, lexicon hits, obfuscation.
               TreeSHAP over this is exact and every feature means something a
               human can check.

  wording      logistic regression over word and character n-grams. Catches
               phrasing and the deliberate misspellings that defeat keyword
               rules. Each token's contribution is exactly coefficient x value.

  blender      a two-input logistic regression over the two log-odds. Two
               coefficients, both printed in every report, so "how much of this
               verdict came from wording versus structure" is a number the
               analyst can read rather than infer.

Every layer is exactly attributable. Nothing explains a surrogate.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
from scipy.sparse import hstack
from scipy.special import expit, logit
from sklearn.calibration import IsotonicRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

import lightgbm as lgb

EPS = 1e-6


@dataclass
class IntentModel:
    word_vec: TfidfVectorizer
    char_vec: TfidfVectorizer
    lexical: LogisticRegression
    gbm: lgb.Booster
    blender: LogisticRegression
    calibrator: IsotonicRegression
    feature_names: list[str]

    # -------------------------------------------------------------- the views
    def wording_logit(self, texts: list[str]) -> np.ndarray:
        Xs = hstack([self.word_vec.transform(texts), self.char_vec.transform(texts)]).tocsr()
        return self.lexical.decision_function(Xs)

    def structural_logit(self, X: np.ndarray) -> np.ndarray:
        return self.gbm.predict(X, raw_score=True)

    # ------------------------------------------------------------ the verdict
    def blend_inputs(self, X: np.ndarray, texts: list[str]) -> np.ndarray:
        return np.column_stack([self.structural_logit(X), self.wording_logit(texts)])

    def raw_score(self, X: np.ndarray, texts: list[str]) -> np.ndarray:
        return self.blender.decision_function(self.blend_inputs(X, texts))

    def predict_proba(self, X: np.ndarray, texts: list[str]) -> np.ndarray:
        """Calibrated P(malicious). Severity multiplies by this, so an
        uncalibrated 0.9 that is really 0.6 would inflate everything downstream."""
        return self.calibrator.predict(self.raw_score(X, texts))

    @property
    def blend_weights(self) -> dict[str, float]:
        w = self.blender.coef_[0]
        return {"structural": float(w[0]), "wording": float(w[1]),
                "intercept": float(self.blender.intercept_[0])}

    def contribution_share(self, X: np.ndarray, texts: list[str]) -> dict[str, float]:
        """How much of this verdict each view is responsible for, as a share of
        the total absolute pull away from the blender's intercept."""
        bi = self.blend_inputs(X, texts)[0]
        w = self.blender.coef_[0]
        cs, cw = abs(w[0] * bi[0]), abs(w[1] * bi[1])
        tot = cs + cw or 1.0
        return {"structural": cs / tot, "wording": cw / tot,
                "structural_logit": float(bi[0]), "wording_logit": float(bi[1])}

    # ------------------------------------------------------------------- i/o
    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"word_vec": self.word_vec, "char_vec": self.char_vec,
                     "lexical": self.lexical, "gbm_str": self.gbm.model_to_string(),
                     "blender": self.blender, "calibrator": self.calibrator,
                     "feature_names": self.feature_names}, path, compress=3)

    @staticmethod
    def load(path: Path) -> "IntentModel":
        d = joblib.load(path)
        return IntentModel(d["word_vec"], d["char_vec"], d["lexical"],
                           lgb.Booster(model_str=d["gbm_str"]), d["blender"],
                           d["calibrator"], d["feature_names"])


def build_vectorizers() -> tuple[TfidfVectorizer, TfidfVectorizer]:
    word_vec = TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=3,
                               max_df=0.6, max_features=300_000, sublinear_tf=True,
                               strip_accents="unicode")
    # Character n-grams catch the deliberate obfuscation this corpus is full of
    # -- "cia'lis", "erectlons", "x'p" -- which word tokens miss entirely.
    char_vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=4,
                               max_features=300_000, sublinear_tf=True, lowercase=True)
    return word_vec, char_vec


GBM_PARAMS = dict(objective="binary", metric=["binary_logloss", "auc"],
                  learning_rate=0.05, num_leaves=96, min_data_in_leaf=40,
                  feature_fraction=0.85, bagging_fraction=0.85, bagging_freq=1,
                  lambda_l2=1.0, verbosity=-1, num_threads=0)
