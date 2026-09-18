"""Correct the model's probability for the base rate where it is deployed.

The intent model was trained on a corpus that is 49.0% malicious. Its calibrated
output is therefore P(malicious | evidence, 49% prior). A real inbox is nothing
like 49% hostile -- a few percent at most -- and applying a 49%-prior probability
to a 2%-prior population overstates every verdict.

Measured on a live mailbox, the uncorrected model flagged 46% of messages and
produced 18 MEDIUM alerts, every one of them a false positive: DKIM-authenticated
payment receipts, scored on words like "payment", "transaction" and "paid" that
are fraud-correlated in a 2008 spam corpus and simply ordinary in a bank receipt.

The fix is Bayes, not a fudge factor. The likelihood ratio the model learned is
prior-free; only the prior needs replacing:

    LR            = odds(p_model) / odds(train_prior)
    odds(p_adj)   = LR x odds(deploy_prior)

A genuine phish carries an enormous likelihood ratio and survives the
correction. A receipt that scored 0.914 on generic transactional vocabulary
does not.
"""
from __future__ import annotations

TRAIN_PRIOR = 0.49          # measured: 37,006 malicious of 75,518
EPS = 1e-9


def _odds(p: float) -> float:
    p = min(max(p, EPS), 1.0 - EPS)
    return p / (1.0 - p)


def adjust(p_model: float, deploy_prior: float,
           train_prior: float = TRAIN_PRIOR) -> float:
    """Re-express a probability under a different base rate."""
    if deploy_prior is None or deploy_prior <= 0 or deploy_prior >= 1:
        return p_model
    lr = _odds(p_model) / _odds(train_prior)
    o = lr * _odds(deploy_prior)
    return o / (1.0 + o)


def explain(p_model: float, p_adj: float, deploy_prior: float) -> str:
    return (f"model scored {p_model:.3f} against its {TRAIN_PRIOR:.0%}-malicious "
            f"training corpus; re-expressed for a {deploy_prior:.1%}-malicious "
            f"mailbox that becomes {p_adj:.3f}")
