"""Correctness tests for the parts where a silent bug would be invisible."""
from __future__ import annotations

import numpy as np
import pytest

from sentinel.features.brands import owns
from sentinel.features.extractor import FEATURE_NAMES, Email, extract, to_vector
from sentinel.features.headers import parse_sender, registrable_domain
from sentinel.features.lexicons import scan
from sentinel.features.urls import extract_urls
from sentinel.labeling.taxonomy import TAXONOMY
from sentinel.scoring.severity import score


# ----------------------------------------------------------------- extraction
def test_feature_vector_is_stable_and_ordered():
    a, _ = extract(Email(subject="x", body="y"))
    b, _ = extract(Email(subject="totally different", body="other text entirely"))
    assert list(a) == list(b) == list(FEATURE_NAMES)
    assert len(to_vector(a)) == len(FEATURE_NAMES)


def test_com_tld_is_not_treated_as_an_executable():
    _, ev = extract(Email(body="Reach us at https://login.microsoftonline.com or sales@x.com"))
    assert ev.dangerous_attachments == []


def test_real_executable_is_caught():
    f, ev = extract(Email(body="See report.pdf.exe and payload.scr", attachments=["a.exe"]))
    assert f["att_dangerous_count"] == 1
    assert any("payload.scr" in n for n in ev.dangerous_attachments)


def test_lexicon_hits_carry_exact_spans():
    hits = scan("Please verify your account within 24 hours", "body")
    assert hits
    for h in hits:
        assert "Please verify your account within 24 hours"[h.start:h.end] == h.term


# -------------------------------------------------------------------- identity
@pytest.mark.parametrize("domain,expected", [
    ("mail.example.co.uk", "example.co.uk"),
    ("a.b.example.com", "example.com"),
    ("example.com", "example.com"),
])
def test_registrable_domain(domain, expected):
    assert registrable_domain(domain) == expected


def test_brand_cctld_is_not_impersonation():
    assert owns("google", "google.co.uk")
    assert owns("amazon", "amazon.de")
    assert not owns("google", "google-security-alert.tk")


def test_display_name_brand_mismatch():
    p = parse_sender('"PayPal Security" <x@paypa1-verify.tk>')
    assert p.claimed_brand == "paypal" and p.brand_mismatch


def test_legitimate_sender_is_clean():
    p = parse_sender("Jane Doe <jane@acme.com>")
    assert not p.brand_mismatch and p.lookalike_of is None


# ------------------------------------------------------------------------ urls
def test_brand_in_subdomain_resolves_elsewhere():
    f = extract_urls("http://paypal.com.secure-login.ru/verify")[0]
    assert f.registrable == "secure-login.ru"
    assert any("paypal" in x for x in f.flags)


def test_anchor_text_mismatch_detected():
    facts = extract_urls("", '<a href="http://evil.ru/login">https://www.microsoft.com</a>')
    assert any("link text reads" in x for f in facts for x in f.flags)


# -------------------------------------------------------------------- severity
def test_severity_is_zero_when_intent_is_zero():
    f, ev = extract(Email(subject="hello", body="see you at lunch"))
    assert score(f, ev, 0.0, "benign").score == 0.0


def test_severity_scales_with_intent_and_bands_are_ordered():
    f, ev = extract(Email(subject="verify", body="verify your account http://x.tk/login"))
    lo = score(f, ev, 0.3, "credential_phishing")
    hi = score(f, ev, 0.95, "credential_phishing")
    assert hi.score > lo.score
    assert hi.base_score <= 100.0


def test_severity_arithmetic_reproduces_the_score():
    f, ev = extract(Email(subject="urgent wire", body="wire transfer, keep this confidential"))
    r = score(f, ev, 0.9, "bec_payment_fraud")
    expected = 100 * r.intent * (0.5 * r.impact + 0.3 * r.exploitability + 0.2 * r.targeting)
    assert abs(expected - r.base_score) < 0.05


def test_every_vector_has_impact_and_description():
    for key, v in TAXONOMY.items():
        assert 0.0 <= v.impact <= 1.0
        assert v.description and v.name
        assert key == v.key


# -------------------------------------------------------- explanation fidelity
def test_shap_reconstructs_the_structural_prediction():
    from sentinel.analyzer import ThreatAnalyzer
    az = ThreatAnalyzer()
    a = az.analyze(Email(subject="Verify your account",
                         sender='"Microsoft" <x@ms-verify.tk>',
                         body="verify your account at http://ms-verify.tk/login now"))
    # base_value + every SHAP value must equal the structural model's output.
    assert a.explanation.additivity_error() < 1e-6


def test_floors_are_reported_separately_from_the_model():
    from sentinel.analyzer import ThreatAnalyzer
    az = ThreatAnalyzer()
    a = az.analyze(Email(subject="Invoice", sender="x@y.com",
                         body="Please see attached.", attachments=["inv.pdf.exe"]))
    assert a.floors_binding, "an executable attachment must trip a floor"
    assert a.probability >= 0.9
    assert a.decided_by == "deterministic rule"
    # The model's own opinion must survive untouched for audit.
    assert a.model_probability <= a.probability


# ------------------------------------------------------- base-rate correction
def test_prior_adjustment_is_bayes_not_a_fudge():
    from sentinel.scoring.prior import TRAIN_PRIOR, adjust
    # At the training prior the correction must be a no-op.
    assert abs(adjust(0.9, TRAIN_PRIOR) - 0.9) < 1e-6
    # A lower deployment prior can only lower the probability.
    assert adjust(0.9, 0.02) < 0.9
    # Monotonic in the evidence: stronger evidence still ranks higher.
    assert adjust(0.99, 0.02) > adjust(0.90, 0.02) > adjust(0.60, 0.02)
    # Overwhelming evidence survives a small prior.
    assert adjust(0.9999, 0.02) > 0.9


def test_generic_transactional_wording_stops_being_an_alert():
    """A DKIM-signed payment receipt scored 0.914 against a 49%-malicious
    corpus. Under a realistic inbox prior it must fall below the alert line."""
    from sentinel.scoring.prior import adjust
    assert adjust(0.914, 0.02) < 0.5


def test_deterministic_floors_are_immune_to_the_prior():
    """Prior correction must never be able to suppress a hard payload
    detection -- floors encode rule precision, not the training prior."""
    from sentinel.analyzer import ThreatAnalyzer
    e = Email(subject="Invoice", sender="billing@supplier.example",
              body="Please see attached.", attachments=["Invoice.pdf.exe"])
    for rate in (None, 0.05, 0.01, 0.001):
        a = ThreatAnalyzer(inbox_base_rate=rate).analyze(e)
        assert a.probability >= 0.9, f"floor must hold at base rate {rate}"
        assert a.floors_binding


# --------------------------------------------- unsolicited money-request floor
def test_direct_money_ask_is_caught():
    """A plain 'send me money' scam. The wording model scores it 0.095 -- it
    reads like ordinary casual English -- so only the floor catches it."""
    from sentinel.analyzer import ThreatAnalyzer
    a = ThreatAnalyzer(inbox_base_rate=0.02).analyze(Email(
        subject="help needed",
        sender='"Someone" <someone@gmail.com>', receiver="me@example.com",
        body="Can you kindly send me some money, i am ed-sheeran and just "
             "requesting for 50000$, thanks."))
    assert a.probability >= 0.8
    assert any(f.name == "unsolicited_money_request" for f in a.floors_binding)
    assert a.vector_key == "advance_fee_fraud"


@pytest.mark.parametrize("body,words", [
    ("Special thanks to this week's sponsor: Verio. Donate $50 to support us. "
     + "filler " * 200, "newsletter with sponsor and donate"),
    ("Your contribution of $25 matters. Contribute today! " + "filler " * 200,
     "advocacy mailing"),
])
def test_newsletters_asking_for_money_are_not_flagged(body, words):
    """These broke an earlier version of the floor: 61 fires on held-out mail,
    59 of them newsletters. Length and the absence of a first-person ask are
    what separate them from a scam."""
    from sentinel.features.extractor import extract
    from sentinel.scoring.floors import applicable
    e = Email(subject="Weekly digest", sender="news@example.org", body=body)
    f, ev = extract(e)
    assert not any(x.name == "unsolicited_money_request" for x in applicable(e, f, ev))


def test_money_request_inside_an_existing_thread_is_not_flagged():
    """An ongoing invoice conversation is not a cold approach."""
    from sentinel.features.extractor import extract
    from sentinel.scoring.floors import applicable
    e = Email(subject="Re: Invoice 22", sender="ap@supplier.example",
              body="On Mon, Finance wrote:\n> noted\n\nPlease send us the $500 balance.")
    f, ev = extract(e)
    assert not any(x.name == "unsolicited_money_request" for x in applicable(e, f, ev))
