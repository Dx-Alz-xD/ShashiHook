"""Central configuration: paths, taxonomy weights, scoring constants.

Every tunable that affects a score lives here so an analyst can audit and
version it. Nothing that influences severity is buried in code.
"""
from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS = PROJECT_ROOT / "artifacts"
EVAL_DIR = PROJECT_ROOT / "eval"

# ---------------------------------------------------------------- data sources
CORPUS_DIR = PROJECT_ROOT / "phishing emails" / "archive (6)"
SPAM_DIR = PROJECT_ROOT / "email spam"

# phishing_email.csv is deliberately absent: it is a stopword-stripped,
# header-less concatenation of the five source corpora below. Including it
# would duplicate every training row and leak across the train/test split.
SOURCES = {
    "ceas08": CORPUS_DIR / "CEAS_08.csv",
    "enron": CORPUS_DIR / "Enron.csv",
    "ling": CORPUS_DIR / "Ling.csv",
    "nigerian_fraud": CORPUS_DIR / "Nigerian_Fraud.csv",
    "spamassassin": CORPUS_DIR / "SpamAssasin.csv",
    "enron_spam": SPAM_DIR / "emails.csv",
}

DERIVED_SOURCES = {"phishing_email": CORPUS_DIR / "phishing_email.csv"}

RANDOM_SEED = 1337
TEST_SIZE = 0.2

# --------------------------------------------------------- severity constants
# severity = 100 * intent * (W_IMPACT*impact + W_EXPLOIT*exploit + W_TARGET*target)
W_IMPACT = 0.50
W_EXPLOIT = 0.30
W_TARGET = 0.20

SEVERITY_BANDS = [
    (90, "CRITICAL"),
    (70, "HIGH"),
    (40, "MEDIUM"),
    (15, "LOW"),
    (0, "INFORMATIONAL"),
]

# Escalators applied after the base formula (additive, capped at 100).
ESCALATOR_KNOWN_BAD_IOC = 25.0
ESCALATOR_EXEC_IMPERSONATION = 10.0
ESCALATOR_THREAD_HIJACK = 8.0
