"""Attack-vector resolution: high-precision rules first, classifier second.

The corpora on disk are from 2001-2008 and contain almost no modern BEC,
vendor fraud or malware delivery -- 57, 13 and 14 training examples
respectively. Training a ten-class model on that would produce confident
nonsense for exactly the vectors that cost the most money.

So the vector layer is deliberately hybrid:

  * a rule fires with enough weight  -> use the rule, and say so
  * no rule fires                    -> the classifier resolves it, but only
                                        among classes it has real support for,
                                        and only above a confidence floor
  * neither                          -> "malicious_unclassified", which routes
                                        to a human instead of guessing

`LEARNABLE` is the honest boundary of what this dataset can teach. Adding data
for the other vectors moves classes into it; nothing else does.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

import lightgbm as lgb

# Classes with enough weak-labelled support in this corpus to train on.
# Adding the Nazario raw-mail corpus moved credential_phishing decisively
# across this line: 236 training rows -> 1,562, because that corpus is real
# phishing with real headers.
#
# malware_delivery is included on thin evidence: 54 training rows, 19 in test.
# Its reported F1 of 0.89 rests on 19 samples and should not be quoted as
# accuracy. It earns its place only because the alternative is misrouting every
# malware email into one of the other four classes, and because the payload
# floors override the classifier for this vector anyway.
#
# BEC (64), extortion (16) and vendor fraud (6) remain rule-only. No public
# corpus of those exists, so no amount of training changes that.
LEARNABLE: tuple[str, ...] = (
    "spam_unwanted",
    "advance_fee_fraud",
    "recon_probe",
    "credential_phishing",
    "malware_delivery",
)

# Below this, the classifier's answer is not trusted and the message is left
# unclassified for an analyst.
CONFIDENCE_FLOOR = 0.55

# A rule total at or above this is taken over any classifier output.
RULE_AUTHORITY = 1.8


@dataclass
class VectorModel:
    word_vec: TfidfVectorizer
    lexical: LogisticRegression
    gbm: lgb.Booster
    classes: list[str]
    feature_names: list[str]

    def _stack(self, X: np.ndarray, texts: list[str]) -> np.ndarray:
        lex = self.lexical.predict_proba(self.word_vec.transform(texts))
        return np.hstack([X, lex]).astype(np.float32)

    def predict(self, X: np.ndarray, texts: list[str]) -> tuple[list[str], np.ndarray]:
        proba = self.gbm.predict(self._stack(X, texts))
        proba = np.atleast_2d(proba)
        idx = proba.argmax(axis=1)
        return [self.classes[i] for i in idx], proba

    def resolve(self, X: np.ndarray, texts: list[str], rule_vector: str,
                rule_weight: float) -> tuple[str, float, str]:
        """Combine rule and classifier into one answer plus its provenance."""
        if rule_vector not in ("malicious_unclassified", "benign") and rule_weight >= RULE_AUTHORITY:
            return rule_vector, min(1.0, rule_weight / 4.0), "rule"
        labels, proba = self.predict(X, texts)
        p = float(proba[0].max())
        if p >= CONFIDENCE_FLOOR:
            return labels[0], p, "classifier"
        if rule_vector not in ("malicious_unclassified", "benign"):
            return rule_vector, min(1.0, rule_weight / 4.0), "rule (weak)"
        return "malicious_unclassified", p, "unresolved"

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"word_vec": self.word_vec, "lexical": self.lexical,
                     "gbm_str": self.gbm.model_to_string(), "classes": self.classes,
                     "feature_names": self.feature_names}, path, compress=3)

    @staticmethod
    def load(path: Path) -> "VectorModel":
        d = joblib.load(path)
        return VectorModel(d["word_vec"], d["lexical"], lgb.Booster(model_str=d["gbm_str"]),
                           d["classes"], d["feature_names"])
