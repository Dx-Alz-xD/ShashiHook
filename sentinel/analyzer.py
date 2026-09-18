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
    # What language this arrived in and whether it was translated before
    # scoring. Always present; `translated` is False for English mail.
    language: dict = field(default_factory=dict)
    # What was recovered from images: transcribed text and decoded QR codes.
    vision: dict = field(default_factory=dict)
    # Nearest labelled messages in the corpus. Shown as evidence, never fed to
    # the model: the nearest neighbour's label is very close to the answer, so
    # training on it would be leakage rather than learning.
    neighbours: list = field(default_factory=list)

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
                 file_tracker: FileTracker | None = None,
                 settings=None):
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
        # Needed only to translate foreign mail; absent means that step is
        # skipped and the message is scored in whatever language it arrived in.
        self.settings = settings

    def _to_english(self, email: Email):
        """Translate a foreign-language message before anything reads it.

        Every lexicon is English, so a Spanish scam scores near zero on wording
        and only the structural checks still work. Translating first means one
        pipeline covers every language instead of 26 lexicon banks per
        language, kept in step forever.

        The original body is preserved on the returned object: the reader must
        see what actually arrived, and the stylometry and campaign layers need
        the real text. Only the copy handed to the feature extractor changes.

        Failure is not fatal. If no provider answers, the message is scored as
        it arrived and the verdict records that the wording signal is degraded.
        """
        from .multilingual import LanguageVerdict, detect, translate
        body = email.body or ""
        v = detect(f"{email.subject or ''}\n{body}")
        if v.is_english:
            return email, {"verdict": v, "translated": False, "note": v.note}
        if self.settings is None or not getattr(self.settings, "llm_translate", False):
            return email, {"verdict": v, "translated": False,
                           "note": f"{v.lang} detected; translation disabled, so "
                                   f"the wording signal is unreliable here"}
        t = translate(body, self.settings, subject=email.subject or "")
        if not t.ok:
            return email, {"verdict": v, "translated": False,
                           "note": f"{v.lang} detected; translation failed "
                                   f"({t.error}), so the wording signal is unreliable"}
        import copy
        scored = copy.copy(email)
        scored.body = t.english
        scored.html = None          # the translation is plain text
        return scored, {"verdict": v, "translated": True, "translation": t,
                        "original_body": body,
                        "note": f"translated from {t.language or v.lang} by "
                                f"{t.provider} before scoring"}

    def _recover_images(self, email: Email):
        """Pull the text and QR codes out of any pictures, before scoring.

        Runs ahead of translation on purpose: a scam rendered as a picture may
        also be in another language, and recovering the words first means the
        translation step sees them too.

        The recovered text is appended to the body rather than replacing it, so
        a message that is half prose and half picture is scored on both. It
        gets no special trust -- the same lexicons, URL extraction and floors
        apply to it, which is the whole point: a QR pointing at a lookalike
        domain now fires the rules a written link always would.
        """
        raw = getattr(email, "raw_message", None)
        if raw is None:
            return email, {"ran": False, "note": "no raw message to look inside"}
        from .vision import inspect as inspect_images
        cfg = self.settings
        try:
            v = inspect_images(raw, cfg,
                               read_text=bool(cfg and getattr(cfg, "llm_read_images", False)))
        except Exception as e:
            return email, {"ran": False, "note": f"image inspection failed: {e}"}
        if not v.images_found:
            return email, {"ran": False, "result": v, "note": v.note}
        recovered = v.recovered
        if not recovered:
            return email, {"ran": True, "result": v, "recovered": False, "note": v.note}
        import copy
        scored = copy.copy(email)
        scored.body = f"{email.body or ''}\n\n{recovered}".strip()
        return scored, {"ran": True, "result": v, "recovered": True,
                        "note": v.note}

    def analyze(self, email: Email) -> Analysis:
        email, vis = self._recover_images(email)
        email, lang = self._to_english(email)
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

        # Retrieval is evidence for the reader, not an input to the score. It
        # runs after everything that decides the verdict, so a missing or
        # corrupt index can change what is shown and never what is concluded.
        try:
            from .similarity import index as sim_index
            neighbours = sim_index().search(text, k=3)
        except Exception:
            neighbours = []

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
            floors_fired=fired, floors_binding=binding, language=lang,
            vision=vis, neighbours=neighbours,
            counterfactuals=counterfactual_sentences(bundle),
            history_note=(self.history.describe(ev.sender.address)
                          if self.history and ev.sender.address else ""),
            domain_age_note=(self.domain_age.lookup(ev.sender.registrable).describe()
                             if self.domain_age and ev.sender.registrable else ""),
            breach=breach, attachments=atts, file_verdicts=verdicts,
            tracked_files=tracked,
            wording_summary=wording_sentence(bundle),
        )
