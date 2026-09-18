"""Faithful attribution for the intent model.

Each layer is exact rather than approximate:

  1. TreeSHAP over the structural trees. For a tree ensemble this is an exact
     Shapley computation, not a sampling estimate, and it is additive:
     base_value + sum(contributions) reproduces the structural log-odds.

  2. The wording view is logistic regression over tf-idf, so each token's
     contribution is exactly coefficient x value. No approximation there either.

  3. Counterfactuals re-run the whole model with a feature neutralised rather
     than reading the answer off the SHAP value. SHAP answers "how much did
     this contribute to the gap from the baseline"; an analyst asking "what if
     this weren't here" wants the model re-evaluated, and the two numbers
     differ whenever features interact.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import warnings

import numpy as np
import shap

# shap emits this once per TreeExplainer construction. The changed return shape
# is handled explicitly in `explain` below, so the warning is noise -- and at
# one line per analysed message it buries real output.
warnings.filterwarnings(
    "ignore",
    message="LightGBM binary classifier with TreeExplainer.*",
    category=UserWarning,
)
from scipy.sparse import hstack

from ..models.intent import IntentModel


@dataclass
class Attribution:
    feature: str
    value: float
    shap: float            # log-odds contribution within the structural view
    rank: int

    @property
    def direction(self) -> str:
        return "raises" if self.shap > 0 else "lowers"


@dataclass
class TokenAttribution:
    token: str
    weight: float          # coefficient x tf-idf value, log-odds


@dataclass
class ExplanationBundle:
    probability: float
    structural_base: float
    structural_logit: float
    wording_logit: float
    blend: dict[str, float]
    share: dict[str, float]
    attributions: list[Attribution]
    top_tokens_up: list[TokenAttribution]
    top_tokens_down: list[TokenAttribution]
    counterfactuals: dict[str, float] = field(default_factory=dict)
    shap_sum: float = 0.0

    def positive(self, n: int = 8) -> list[Attribution]:
        return [a for a in self.attributions if a.shap > 0][:n]

    def negative(self, n: int = 5) -> list[Attribution]:
        return sorted((a for a in self.attributions if a.shap < 0),
                      key=lambda a: a.shap)[:n]

    def additivity_error(self) -> float:
        """base + every SHAP value must reproduce the structural log-odds.
        A non-trivial value means the explanation does not reconstruct the
        prediction and must not be trusted."""
        return abs(self.structural_base + self.shap_sum - self.structural_logit)


class IntentExplainer:
    def __init__(self, model: IntentModel):
        self.model = model
        self.explainer = shap.TreeExplainer(model.gbm)
        self.names = list(model.feature_names)
        self.index = {n: i for i, n in enumerate(self.names)}
        self.vocab = np.concatenate([
            model.word_vec.get_feature_names_out(),
            model.char_vec.get_feature_names_out(),
        ])
        self.coef = model.lexical.coef_[0]

    # --------------------------------------------------------------- wording
    def token_attributions(self, text: str, n: int = 15
                           ) -> tuple[list[TokenAttribution], list[TokenAttribution]]:
        x = hstack([self.model.word_vec.transform([text]),
                    self.model.char_vec.transform([text])]).tocsr()
        idx, contrib = x.indices, x.data * self.coef[x.indices]
        order = np.argsort(contrib)
        up = [TokenAttribution(str(self.vocab[idx[i]]), float(contrib[i]))
              for i in order[::-1][:n] if contrib[i] > 0]
        down = [TokenAttribution(str(self.vocab[idx[i]]), float(contrib[i]))
                for i in order[:n] if contrib[i] < 0]
        return up, down

    # ------------------------------------------------------------ main entry
    def explain(self, X_row: np.ndarray, text: str, top_k: int = 40,
                counterfactual_for: list[str] | None = None) -> ExplanationBundle:
        X = X_row.reshape(1, -1).astype(np.float32)

        sv = np.asarray(self.explainer.shap_values(X))
        if sv.ndim == 3:
            sv = sv[0, :, -1]
        elif sv.ndim == 2:
            sv = sv[0]
        base = float(np.asarray(self.explainer.expected_value).ravel()[-1])

        s_logit = float(self.model.structural_logit(X)[0])
        w_logit = float(self.model.wording_logit([text])[0])
        p = float(self.model.predict_proba(X, [text])[0])

        order = np.argsort(-np.abs(sv))
        attributions = [
            Attribution(self.names[i], float(X[0, i]), float(sv[i]), r)
            for r, i in enumerate(order[:top_k], 1) if abs(sv[i]) > 1e-9
        ]
        up, down = self.token_attributions(text)

        cfs: dict[str, float] = {}
        if counterfactual_for:
            cfs["__actual__"] = p
            for feat in counterfactual_for:
                if feat == "__wording__":
                    # Neutralise the wording view entirely: what would the
                    # structural evidence alone have concluded?
                    bi = np.array([[s_logit, 0.0]])
                    cfs[feat] = float(self.model.calibrator.predict(
                        self.model.blender.decision_function(bi))[0])
                    continue
                if feat not in self.index:
                    continue
                probe = X.copy()
                probe[0, self.index[feat]] = 0.0
                cfs[feat] = float(self.model.predict_proba(probe, [text])[0])

        return ExplanationBundle(
            probability=p,
            structural_base=base,
            structural_logit=s_logit,
            wording_logit=w_logit,
            blend=self.model.blend_weights,
            share=self.model.contribution_share(X, [text]),
            attributions=attributions,
            top_tokens_up=up,
            top_tokens_down=down,
            counterfactuals=cfs,
            shap_sum=float(sv.sum()),
        )
