"""Severity scoring.

None of the six corpora carry a severity label, so severity is not learned --
inventing a regression target would mean inventing the ground truth too. It is
computed by a declared rubric over four quantities, three of which come from
observable evidence and one from the calibrated model:

    severity = 100 x intent x (0.50 x impact + 0.30 x exploitability
                               + 0.20 x targeting)   + escalators

    intent          calibrated P(malicious) from the intent model
    impact          business damage if the lure succeeds, from the taxonomy
    exploitability  how directly the message can be acted on -- a live
                    credential page and an executable attachment are actionable,
                    a 419 narrative is not
    targeting       how specifically aimed this is -- one named recipient in a
                    hijacked thread scores far above a 40,000-address blast

Multiplying by intent rather than adding it means an uncertain verdict cannot
produce a confident severity, which is the failure mode that erodes trust in an
alerting system fastest.

Every coefficient is in config.py, every input is returned in the breakdown,
and the report prints the arithmetic. An analyst who disagrees with a score can
see precisely which term they disagree with.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..config import (ESCALATOR_EXEC_IMPERSONATION, ESCALATOR_KNOWN_BAD_IOC,
                      ESCALATOR_THREAD_HIJACK, SEVERITY_BANDS, W_EXPLOIT,
                      W_IMPACT, W_TARGET)
from ..features.extractor import Evidence
from ..labeling.taxonomy import impact_of


@dataclass
class Component:
    name: str
    value: float
    why: str


@dataclass
class SeverityResult:
    score: float
    band: str
    intent: float
    impact: float
    exploitability: float
    targeting: float
    base_score: float
    escalators: list[Component] = field(default_factory=list)
    exploit_parts: list[Component] = field(default_factory=list)
    target_parts: list[Component] = field(default_factory=list)
    recipient_multiplier: float = 1.0
    recipient_reason: str = ""
    base_impact: float = 0.0     # taxonomy weight before the recipient adjustment

    def arithmetic(self) -> str:
        """The formula with this message's numbers substituted in."""
        # `impact` already includes the multiplier; show the factors that
        # produced it, not the product multiplied a second time.
        imp = (f"{self.impact:.2f}" if self.recipient_multiplier == 1.0
               else f"({self.base_impact:.2f} x {self.recipient_multiplier:.2f})")
        s = (f"100 x {self.intent:.3f} x ({W_IMPACT} x {imp} + "
             f"{W_EXPLOIT} x {self.exploitability:.2f} + "
             f"{W_TARGET} x {self.targeting:.2f}) = {self.base_score:.1f}")
        for e in self.escalators:
            s += f"  {'+' if e.value >= 0 else '-'} {abs(e.value):.0f} ({e.name})"
        if self.escalators:
            s += f"  = {self.score:.1f}"
        return s


# Each signal contributes its weight; the sum is capped at 1.0.
EXPLOIT_SIGNALS: tuple[tuple[str, float, str], ...] = (
    ("url_has_credential_path", 0.35, "links to a sign-in or verification page the "
                                      "recipient can submit credentials to right now"),
    ("att_dangerous_count", 0.40, "carries a file that executes when opened"),
    ("att_double_extension", 0.30, "carries a double-extension file disguised as a document"),
    ("url_has_dangerous_ext", 0.35, "links directly to an executable"),
    ("url_has_anchor_mismatch", 0.20, "hides the real destination behind trusted-looking link text"),
    ("url_has_brand_mismatch", 0.20, "dresses a hostile domain up as a known brand"),
    ("lex_payment_count", 0.25, "gives a concrete payment or banking instruction"),
    ("lex_credential_request_count", 0.20, "asks outright for credentials"),
    ("url_count", 0.10, "contains at least one clickable link"),
    ("att_archive_count", 0.15, "carries an archive that can smuggle a payload past scanning"),
)

TARGET_SIGNALS: tuple[tuple[str, float, str], ...] = (
    ("txt_thread_hijack_marker", 0.30, "appears inside an existing conversation"),
    ("hdr_same_domain_as_recipient", 0.25, "claims to come from inside the recipient's own domain"),
    ("hdr_brand_display_mismatch", 0.15, "impersonates a specific named party"),
    ("lex_authority_count", 0.20, "invokes a specific role or executive"),
    ("txt_subject_is_reply", 0.10, "is framed as a reply rather than a cold approach"),
    ("lex_secrecy_count", 0.15, "asks the recipient to keep the request off the record"),
)


def _accumulate(feats: dict[str, float], signals) -> tuple[float, list[Component]]:
    total, parts = 0.0, []
    for name, weight, why in signals:
        if feats.get(name, 0.0) > 0:
            total += weight
            parts.append(Component(name, weight, why))
    return min(total, 1.0), parts


def score(feats: dict[str, float], ev: Evidence, intent: float, vector: str,
          known_bad_iocs: set[str] | None = None, recipient=None) -> SeverityResult:
    impact = impact_of(vector)

    # Impact is a property of what the reader can be made to do, not of the
    # message alone. The same gift-card request to someone who releases
    # payments and to someone who never sees an invoice is the same content and
    # a different consequence. Bounded to roughly +-35%: a profile inferred
    # from mail is an inference, not an org chart.
    base_impact = impact
    r_mult, r_reason = (recipient.multiplier(vector) if recipient else (1.0, ""))
    impact = max(0.0, min(1.0, impact * r_mult))
    exploitability, exploit_parts = _accumulate(feats, EXPLOIT_SIGNALS)
    targeting, target_parts = _accumulate(feats, TARGET_SIGNALS)

    # A message blasted to an undisclosed list is by definition untargeted,
    # whatever else it does.
    if feats.get("hdr_recipient_undisclosed", 0.0) or feats.get("lex_spam_bulk_marker_count", 0.0) >= 2:
        targeting *= 0.4
        target_parts.append(Component("bulk_delivery", -0.0,
                                      "sent as bulk mail, which caps how targeted it can be"))

    base = 100.0 * intent * (W_IMPACT * impact + W_EXPLOIT * exploitability
                             + W_TARGET * targeting)

    escalators: list[Component] = []
    iocs = known_bad_iocs or set()
    if iocs:
        observed = {u.registrable for u in ev.urls if u.registrable} | (
            {ev.sender.registrable} if ev.sender.registrable else set())
        hit = observed & iocs
        if hit:
            escalators.append(Component("known-bad indicator", ESCALATOR_KNOWN_BAD_IOC,
                                        f"matches threat intelligence: {', '.join(sorted(hit))}"))

    if feats.get("hdr_brand_display_mismatch", 0.0) and feats.get("lex_authority_count", 0.0):
        escalators.append(Component("executive impersonation", ESCALATOR_EXEC_IMPERSONATION,
                                    "impersonates a named party and invokes executive authority"))
    if feats.get("txt_thread_hijack_marker", 0.0) and intent >= 0.8:
        escalators.append(Component("thread hijack", ESCALATOR_THREAD_HIJACK,
                                    "injected into what looks like an existing thread, which "
                                    "borrows the trust of the real correspondents"))

    total = min(100.0, base + sum(e.value for e in escalators))
    band = next(b for threshold, b in SEVERITY_BANDS if total >= threshold)

    return SeverityResult(score=round(total, 1), band=band, intent=round(intent, 4),
                          impact=round(impact, 3), base_impact=round(base_impact, 3),
                          recipient_multiplier=round(r_mult, 3),
                          recipient_reason=r_reason,
                          exploitability=round(exploitability, 3),
                          targeting=round(targeting, 3), base_score=round(base, 1),
                          escalators=escalators, exploit_parts=exploit_parts,
                          target_parts=target_parts)
