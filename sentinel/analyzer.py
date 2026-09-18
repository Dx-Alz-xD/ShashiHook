"""The orchestrator: one email in, one fully-explained analysis out."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from .config import ARTIFACTS
from .explain.narrative import (Finding, build_findings, counterfactual_sentences,
                                wording_sentence)
from .explain.shap_explainer import ExplanationBundle, IntentExplainer
from .features.extractor import Email, Evidence, extract, to_vector
from .enrich.breach import BreachCache, BreachStatus
from .enrich.rdap import DomainAgeCache
from .enrich.virustotal import FileVerdict, VirusTotal
from .files import AttachmentFile, FileTracker
from .history import History
from .recipient import RecipientProfile
from .labeling.taxonomy import Vector, describe
from .labeling.weak_rules import Vote, vote
from .models.intent import IntentModel
from .models.vector import VectorModel
from .scoring.floors import Floor
from .scoring.floors import apply as apply_floors
from .scoring.floors import applicable as applicable_floors
from .scoring.floors import implied_vector
from .scoring.prior import adjust as adjust_prior
from .config import SEVERITY_BANDS
from .scoring.severity import SeverityResult
from .scoring.severity import score as severity_score

# Features worth asking "what if this weren't here" about.
COUNTERFACTUAL_CANDIDATES = [
    "url_has_credential_path", "url_has_brand_mismatch", "url_has_anchor_mismatch",
    "hdr_brand_display_mismatch", "hdr_domain_is_lookalike", "hdr_sender_tld_high_risk",
    "att_dangerous_count", "att_double_extension", "lex_urgency_count",
    "lex_credential_request_count", "lex_payment_count", "lex_secrecy_count",
]


@dataclass
class Analysis:
    email: Email
    features: dict[str, float]
    evidence: Evidence
    probability: float
    severity: SeverityResult
    vector_key: str
    vector: Vector
    vector_confidence: float
    vector_source: str
    rule_votes: list[Vote]
    explanation: ExplanationBundle
    findings_up: list[Finding]
    findings_down: list[Finding]
    counterfactuals: list[str] = field(default_factory=list)
    wording_summary: str = ""
    model_probability: float = 0.0
    prior_adjusted: float = 0.0
    floors_fired: list[Floor] = field(default_factory=list)
    floors_binding: list[Floor] = field(default_factory=list)

    @property
    def decided_by(self) -> str:
        return "deterministic rule" if self.floors_binding else "model" 

    @property
    def verdict(self) -> str:
        if self.probability >= 0.5:
            return "MALICIOUS"
        if self.probability >= 0.2:
            return "SUSPICIOUS"
        return "BENIGN"

    history_note: str = ""
    domain_age_note: str = ""
    breach: BreachStatus | None = None
    attachments: list[AttachmentFile] = field(default_factory=list)
    file_verdicts: list[FileVerdict] = field(default_factory=list)
    tracked_files: list[str] = field(default_factory=list)

    def iocs(self) -> dict[str, list[str]]:
        """Indicators an analyst can block or hunt on immediately."""
        ev = self.evidence
        return {
            "sender_address": [ev.sender.address] if ev.sender.address else [],
            "sender_domain": [ev.sender.registrable] if ev.sender.registrable else [],
            "urls": [u.raw for u in ev.urls],
            "url_domains": sorted({u.registrable for u in ev.urls if u.registrable}),
            "attachments": ev.attachments,
            "dangerous_files": ev.dangerous_attachments,
        }


class ThreatAnalyzer:
    def __init__(self, artifacts: Path = ARTIFACTS,
                 known_bad_iocs: set[str] | None = None,
                 software_allowlist: set[str] | None = None,
                 inbox_base_rate: float | None = None,
                 history: History | None = None,
                 domain_age: DomainAgeCache | None = None,
                 recipient: RecipientProfile | None = None,
                 breach: BreachCache | None = None,
                 virustotal: VirusTotal | None = None,
                 file_tracker: FileTracker | None = None):
        """`software_allowlist` exempts domains that legitimately distribute
        executables -- your own release host, an open-source project you follow.
        It is the one detection whose correctness depends on the organisation:
        on held-out mail it produced exactly one HIGH-severity false positive, a
        python-win32 release announcement linking to a pywin32 installer."""
        self.intent = IntentModel.load(artifacts / "intent_model.joblib")
        self.explainer = IntentExplainer(self.intent)
        vpath = artifacts / "vector_model.joblib"
        self.vector_model = VectorModel.load(vpath) if vpath.exists() else None
        self.known_bad_iocs = known_bad_iocs or set()
        self.software_allowlist = software_allowlist or set()
        # None = leave the model's probability as trained (49% malicious prior).
        # Set it to the realistic hostile fraction of the mail being scanned and
        # every verdict is re-expressed for that population.
        self.inbox_base_rate = inbox_base_rate
        # Built by `sentinel build-history`; absent is fine, the floors that
        # use it simply do not fire.
        if history is None:
            hp = artifacts / "sender_history.json"
            history = History.load(hp) if hp.exists() else None
        self.history = history
        # Optional live enrichment; when absent, the floors that use it simply
        # do not fire.
        self.domain_age = domain_age
        # Built by scripts/build_recipient_profile.py from mail already local.
        self.recipient = recipient if recipient is not None else RecipientProfile.load()
        self.breach = breach
        self.virustotal = virustotal
        # Registers attachments for on-disk tracking, above its own threshold.
        self.file_tracker = file_tracker

    def analyze(self, email: Email) -> Analysis:
        feats, ev = extract(email)
        X = np.array(to_vector(feats), dtype=np.float32).reshape(1, -1)
        text = email.full_text

        p_model = float(self.intent.predict_proba(X, [text])[0])

        # Re-express for the base rate where this is deployed, BEFORE floors.
        # Order matters: a floor's minimum encodes how precise that rule is,
        # which is already a deployment-relevant number and must not then be
        # discounted by a prior it never depended on.
        p_prior = (adjust_prior(p_model, self.inbox_base_rate)
                   if self.inbox_base_rate else p_model)

        # Deterministic detections set a floor the model cannot pull below.
        # Kept separate from p_model so the report can always say which of the
        # two produced the number.
        fired = applicable_floors(email, feats, ev, self.software_allowlist,
                                  self.history, self.domain_age)
        p, binding = apply_floors(p_prior, fired)
        malicious = p >= 0.5

        # Vector: rules first, classifier only where rules abstain.
        rule_vec, rule_conf, totals, votes = vote(email, feats, ev, malicious)
        rule_weight = max(totals.values()) if totals else 0.0
        if not malicious:
            vec_key, vec_conf, vec_src = "benign", 1.0, "intent model"
        elif self.vector_model is not None:
            vec_key, vec_conf, vec_src = self.vector_model.resolve(X, [text], rule_vec, rule_weight)
            # A deterministic floor names its vector with more authority than a
            # classifier restricted to the four classes this corpus could teach.
            implied, by = implied_vector(binding)
            if implied and (vec_src != "rule" or rule_weight < 2.5):
                vec_key, vec_conf, vec_src = implied, 0.9, f"floor `{by}`"
        else:
            vec_key, vec_conf, vec_src = rule_vec, rule_conf, "rule"

        sev = severity_score(feats, ev, p, vec_key, self.known_bad_iocs,
                             recipient=self.recipient)

        # --- enrichment, all of it optional and all of it failing soft -------
        breach = None
        if self.breach is not None:
            breach = BreachStatus(address=ev.sender.address)
            pw, real, n = self.breach.quoted_password(ev.body or "")
            breach.quoted_password, breach.quoted_password_breached = pw, real
            breach.quoted_password_count = n
            if email.receiver:
                acct = self.breach.account(email.receiver.split(",")[0].strip())
                breach.breached, breach.breaches = acct.breached, acct.breaches
            # Exposure is context, not evidence: millions of addresses appear in
            # breaches and almost none of their owners are under attack today.
            # A few points, never a band change on its own.
            if breach.breached or breach.quoted_password_breached:
                sev.score = round(min(100.0, sev.score + 3.0), 1)
                sev.band = next(b for t, b in SEVERITY_BANDS if sev.score >= t)

        atts, verdicts, tracked = [], [], []
        if getattr(email, "raw_message", None) is not None:
            from .files import from_message as files_from_message
            atts = files_from_message(email.raw_message)
            if self.virustotal is not None and self.virustotal.enabled:
                for f in atts:
                    verdicts.append(self.virustotal.lookup(f.sha256, f.filename, f.size))
            if self.file_tracker is not None:
                for f in atts:
                    if self.file_tracker.register(
                            f, subject=email.subject or "", sender=ev.sender.address or "",
                            severity=sev.score, vector=vec_key):
                        tracked.append(f.filename)

        # Only probe counterfactuals for features actually present -- asking
        # "what if there were no dangerous attachment" when there is none
        # wastes a model call and reads as noise in the report.
        probes = [f for f in COUNTERFACTUAL_CANDIDATES if feats.get(f, 0.0) > 0][:6]
        bundle = self.explainer.explain(X[0], text, counterfactual_for=probes + ["__wording__"])
        up, down = build_findings(bundle, ev, feats)

        return Analysis(
            email=email, features=feats, evidence=ev, probability=p, severity=sev,
            vector_key=vec_key, vector=describe(vec_key), vector_confidence=vec_conf,
            vector_source=vec_src, rule_votes=votes, explanation=bundle,
            findings_up=up, findings_down=down,
            model_probability=p_model, prior_adjusted=p_prior,
            floors_fired=fired, floors_binding=binding,
            counterfactuals=counterfactual_sentences(bundle),
            history_note=(self.history.describe(ev.sender.address)
                          if self.history and ev.sender.address else ""),
            domain_age_note=(self.domain_age.lookup(ev.sender.registrable).describe()
                             if self.domain_age and ev.sender.registrable else ""),
            breach=breach, attachments=atts, file_verdicts=verdicts,
            tracked_files=tracked,
            wording_summary=wording_sentence(bundle),
        )
