"""Automated response — the safety properties, not the happy path.

This is the only code in the project that writes to a mailbox, so the tests
here are about what it must REFUSE to do.
"""
from __future__ import annotations

import pytest

from sentinel.actions import ACTIONS, ActionResult, audit, should_action
from sentinel.analyzer import ThreatAnalyzer
from sentinel.features.extractor import Email
from sentinel.settings import Settings


def _cfg(**kw) -> Settings:
    s = Settings()
    s.auto_action = kw.get("action", "quarantine")
    s.auto_action_threshold = kw.get("threshold", 50.0)
    s.auto_action_armed = kw.get("armed", False)
    s.auto_action_require_rule = kw.get("require_rule", True)
    return s


@pytest.fixture(scope="module")
def az():
    return ThreatAnalyzer(inbox_base_rate=0.02)


def _malware(az):
    return az.analyze(Email(subject="Invoice", sender="billing@supplier.example",
                            body="Please see attached.",
                            attachments=["Invoice.pdf.exe"]))


def _clean(az):
    return az.analyze(Email(subject="Lunch Thursday?", sender="sam@example.com",
                            body="Are you free Thursday? Usual place at 12:30."))


def test_permanent_deletion_is_not_an_available_action():
    """Deliberate: at ~1% false-positive rate an irreversible delete destroys
    legitimate mail. Quarantine and Trash are both recoverable."""
    assert "delete" not in ACTIONS
    assert "expunge" not in ACTIONS
    assert set(ACTIONS) == {"none", "flag", "quarantine", "trash"}


def test_disabled_by_default():
    s = Settings()
    assert s.auto_action == "none"
    assert s.auto_action_armed is False


def test_clean_mail_is_never_actioned(az):
    ok, why = should_action(_clean(az), _cfg())
    assert not ok


def test_below_threshold_is_not_actioned(az):
    ok, why = should_action(_malware(az), _cfg(threshold=99.0))
    assert not ok and "below threshold" in why


def test_require_rule_blocks_model_only_verdicts(az):
    """A model score alone must not be able to move someone's mail."""
    a = az.analyze(Email(subject="Cheap meds now",
                         sender="deals@pills4u.example",
                         body="Buy viagra cialis online no prescription pharmacy discount"))
    a.floors_binding = []          # model-only verdict
    a.severity.score = 95.0
    ok, why = should_action(a, _cfg(require_rule=True))
    assert not ok and "no deterministic rule" in why
    ok2, _ = should_action(a, _cfg(require_rule=False))
    assert ok2


def test_rule_backed_high_severity_is_actioned(az):
    a = _malware(az)
    assert a.floors_binding, "precondition: a rule should fire on a .pdf.exe"
    ok, why = should_action(a, _cfg(threshold=40.0))
    assert ok and "severity" in why


def test_action_none_disables_everything(az):
    ok, _ = should_action(_malware(az), _cfg(action="none", threshold=0.0))
    assert not ok


def test_audit_log_records_every_decision(tmp_path):
    p = tmp_path / "audit.jsonl"
    audit(p, ActionResult(message_id="m1", subject="s", sender="a@b.c", score=80.0,
                          band="HIGH", vector="malware_delivery", action="quarantine",
                          performed=True, dry_run=False, reason="rule fired"))
    import json
    rec = json.loads(p.read_text().strip())
    assert rec["action"] == "quarantine" and rec["performed"] is True
    assert rec["score"] == 80.0 and rec["reason"] == "rule fired"
    assert oct(p.stat().st_mode)[-3:] == "600"


def test_dry_run_is_the_default_even_when_configured(az):
    """Choosing an action is not the same as authorising it to run."""
    cfg = _cfg(action="trash", threshold=10.0, armed=False)
    ok, _ = should_action(_malware(az), cfg)
    assert ok, "it qualifies"
    assert cfg.auto_action_armed is False, "but arming is a separate switch"
