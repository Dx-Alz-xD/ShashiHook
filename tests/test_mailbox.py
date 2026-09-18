"""Mailbox integration tests against a fake provider.

These exercise the whole live path -- raw RFC-5322 bytes in, incident report on
disk -- without touching a real account, which is the only way to verify the
Gmail/IMAP wiring before someone points it at their own mail.
"""
from __future__ import annotations

from email.message import EmailMessage
from pathlib import Path

import pytest

from sentinel.ingest.eml import from_string
from sentinel.ingest.gmail import FetchedMessage
from sentinel.mailbox import ScanResult, format_table, scan
from sentinel.settings import Settings


def _raw_phish() -> bytes:
    m = EmailMessage()
    m["Subject"] = "Action required: verify your Microsoft account"
    m["From"] = '"Microsoft Account Team" <security@ms-verify-login.tk>'
    m["To"] = "victim@example.com"
    m["Reply-To"] = "collect@totally-different.top"
    m["Return-Path"] = "<bounce@ms-verify-login.tk>"
    m["Date"] = "Tue, 16 Sep 2025 08:14:02 +0000"
    m["Message-ID"] = "<abc123@ms-verify-login.tk>"
    m["Authentication-Results"] = "mx.google.com; spf=fail; dkim=none; dmarc=fail"
    m.set_content("Your mailbox storage quota exceeded. Please verify your account "
                  "within 24 hours or it will be suspended.")
    m.add_alternative(
        '<html><body>Your mailbox storage quota exceeded. Please verify your '
        'account within 24 hours or it will be suspended. '
        '<a href="http://ms-verify-login.tk/secure/login/account">'
        'https://login.microsoftonline.com</a></body></html>', subtype="html")
    return m.as_bytes()


def _raw_benign() -> bytes:
    m = EmailMessage()
    m["Subject"] = "Lunch Thursday?"
    m["From"] = '"Sam Okafor" <sam@example.com>'
    m["To"] = "me@example.com"
    m["Date"] = "Wed, 17 Sep 2025 12:15:00 +0000"
    m.set_content("Are you free Thursday? Usual place at 12:30.")
    return m.as_bytes()


# ------------------------------------------------------------------- parsing
def test_eml_parsing_recovers_headers_the_csvs_never_had():
    e = from_string(_raw_phish().decode())
    assert e.subject.startswith("Action required")
    assert "ms-verify-login.tk" in e.sender
    # These three are the whole reason for fetching raw RFC-5322 rather than
    # Gmail's parsed format, and none of them exist in the training CSVs.
    assert e.reply_to == "collect@totally-different.top"
    assert "bounce@ms-verify-login.tk" in e.return_path
    assert "spf=fail" in e.auth_results
    assert e.html and "ms-verify-login.tk/secure/login" in e.html


def test_multipart_html_is_available_for_link_analysis():
    from sentinel.features.extractor import extract
    f, ev = extract(from_string(_raw_phish().decode()))
    assert f["url_has_anchor_mismatch"] == 1.0, "href/anchor disagreement must be caught"


# ---------------------------------------------------------------- scan wiring
@pytest.fixture
def fake_mailbox(monkeypatch):
    msgs = [FetchedMessage("m1", _raw_phish()), FetchedMessage("m2", _raw_benign())]
    monkeypatch.setattr("sentinel.ingest.gmail.fetch", lambda *a, **k: msgs)
    return msgs


def test_scan_analyses_every_message(fake_mailbox, tmp_path):
    cfg = Settings()
    cfg.report_dir = tmp_path / "reports"
    r = scan(source="gmail", cfg=cfg, write_reports=False)
    assert len(r.analyses) == 2
    assert not r.errors
    phish = max(r.analyses, key=lambda a: a.severity.score)
    assert phish.probability >= 0.5
    assert phish.vector_key == "credential_phishing"


def test_scan_writes_reports_only_above_the_band_floor(fake_mailbox, tmp_path):
    cfg = Settings()
    cfg.report_dir = tmp_path / "reports"
    cfg.min_band_to_report = "MEDIUM"
    r = scan(source="gmail", cfg=cfg)
    # The benign lunch email must not generate an incident report.
    assert len(r.reports_written) == 1
    md = r.reports_written[0].read_text()
    assert "Incident report" in md
    assert r.reports_written[0].with_suffix(".json").exists()


def test_reports_do_not_contain_credentials(fake_mailbox, tmp_path, monkeypatch):
    monkeypatch.setenv("IMAP_APP_PASSWORD", "supersecretpassword")
    monkeypatch.setenv("GMAIL_CLIENT_SECRET", "topsecretclientsecret")
    cfg = Settings()
    cfg.report_dir = tmp_path / "reports"
    r = scan(source="gmail", cfg=cfg)
    for p in r.reports_written:
        blob = p.read_text() + p.with_suffix(".json").read_text()
        assert "supersecretpassword" not in blob
        assert "topsecretclientsecret" not in blob


def test_bodies_are_not_persisted_by_default(fake_mailbox, tmp_path):
    cfg = Settings()
    cfg.report_dir = tmp_path / "reports"
    cfg.save_bodies = False
    r = scan(source="gmail", cfg=cfg)
    md = r.reports_written[0].read_text()
    assert "Message body not stored" in md


def test_settings_describe_never_prints_a_secret(monkeypatch):
    monkeypatch.setenv("GMAIL_CLIENT_SECRET", "abcdef-secret-value")
    monkeypatch.setenv("IMAP_APP_PASSWORD", "sixteencharacter")
    out = Settings().describe()
    assert "abcdef-secret-value" not in out
    assert "sixteencharacter" not in out
    assert "set (" in out


def test_one_bad_message_does_not_abort_the_scan(monkeypatch, tmp_path):
    msgs = [FetchedMessage("bad", b"this is not a valid email at all"),
            FetchedMessage("ok", _raw_benign())]
    monkeypatch.setattr("sentinel.ingest.gmail.fetch", lambda *a, **k: msgs)
    cfg = Settings()
    cfg.report_dir = tmp_path / "reports"
    r = scan(source="gmail", cfg=cfg, write_reports=False)
    assert len(r.analyses) >= 1


def test_table_renders_without_leaking_bodies(fake_mailbox, tmp_path):
    cfg = Settings()
    cfg.report_dir = tmp_path / "reports"
    t = format_table(scan(source="gmail", cfg=cfg, write_reports=False))
    assert "scanned" in t and "flagged" in t
    assert "storage quota exceeded" not in t


# ------------------------------------------------------------ imap translation
@pytest.mark.parametrize("q,expect", [
    ("newer_than:7d", "SINCE"),
    ("is:unread", "UNSEEN"),
    ("from:boss@corp.com", "FROM"),
])
def test_gmail_query_translates_to_imap(q, expect):
    from sentinel.ingest.imap_box import _to_imap_criteria
    assert expect in _to_imap_criteria(q)


# ------------------------------------------------- authentication gating
def _msg(auth: str | None, from_addr: str = '"Acme" <no-reply@acme.com>') -> str:
    lines = [f"From: {from_addr}", "To: me@example.com", "Subject: Your account"]
    if auth:
        lines.append(f"Authentication-Results: {auth}")
    lines += ["Content-Type: text/html", "",
              '<a href="http://click.tracker-xyz.com/r/123">https://www.acme.com/account</a>'
              ' Please verify your account.']
    return "\n".join(lines)


def test_authenticated_sender_is_not_accused_of_impersonating_itself():
    """Click trackers make link text differ from the href on almost every
    legitimate marketing email. An aligned DKIM pass must suppress that floor."""
    from sentinel.analyzer import ThreatAnalyzer
    az = ThreatAnalyzer()
    a = az.analyze(from_string(_msg(
        "mx.google.com; dkim=pass header.i=@acme.com header.s=k1; spf=pass")))
    assert not any(f.name == "link_text_mismatch" for f in a.floors_fired)


def test_unauthenticated_link_mismatch_still_trips_the_floor():
    # Asserts on floors_FIRED, not floors_BINDING. A floor is "binding" only
    # when it actually raised the score; here the model already scores the
    # message above the floor, so the rule matched without changing anything.
    # That distinction is deliberate -- a report must never claim a rule
    # decided the verdict when it did not.
    from sentinel.analyzer import ThreatAnalyzer
    az = ThreatAnalyzer()
    a = az.analyze(from_string(_msg(None)))
    assert any(f.name == "link_text_mismatch" for f in a.floors_fired)


def test_dkim_pass_for_a_different_domain_does_not_count():
    """A phisher can DKIM-sign as their own domain. Alignment with the From
    header is what matters, not the presence of a pass."""
    from sentinel.scoring.floors import sender_is_authenticated
    from sentinel.features.extractor import extract
    e = from_string(_msg("mx.google.com; dkim=pass header.i=@evil-sender.tk"))
    _, ev = extract(e)
    ok, _ = sender_is_authenticated(e, ev)
    assert not ok


def test_subdomain_signing_is_aligned():
    """ESPs sign as a subdomain of the sender; relaxed alignment accepts it."""
    from sentinel.scoring.floors import sender_is_authenticated
    from sentinel.features.extractor import extract
    e = from_string(_msg("mx.google.com; dkim=pass header.i=@cio113400.acme.com"))
    _, ev = extract(e)
    ok, note = sender_is_authenticated(e, ev)
    assert ok and "acme.com" in note


def test_authentication_does_not_excuse_a_malicious_payload():
    """A compromised-but-authenticated sender can still ship malware."""
    from email.message import EmailMessage
    from sentinel.analyzer import ThreatAnalyzer
    m = EmailMessage()
    m["From"] = '"Acme" <billing@acme.com>'
    m["To"] = "me@example.com"
    m["Subject"] = "Invoice"
    m["Authentication-Results"] = "mx.google.com; dkim=pass header.i=@acme.com; spf=pass"
    m.set_content("Please see the attached invoice.")
    m.add_attachment(b"MZ", maintype="application", subtype="octet-stream",
                     filename="Invoice.pdf.exe")
    a = ThreatAnalyzer().analyze(from_string(m.as_string()))
    assert a.floors_binding, "payload floors must survive authentication"
    assert a.probability >= 0.9


# ------------------------------------------------------------ sender history
def test_history_distinguishes_strangers_from_correspondents(tmp_path):
    from sentinel.history import History, Party
    h = History(
        domains={"known.com": Party(domain="known.com", received=40, sent_to=3,
                                    first_seen="2023-01-01T00:00:00+00:00")},
        addresses={"a@known.com": Party(address="a@known.com", received=40)},
    )
    assert h.signals("a@known.com")["first_contact"] is False
    assert h.signals("a@known.com")["ever_corresponded_with_domain"] is True
    assert h.signals("nobody@stranger.tk")["first_contact"] is True
    assert "first contact" in h.describe("nobody@stranger.tk")


def test_history_round_trips(tmp_path):
    from sentinel.history import History, Party
    h = History(domains={"x.com": Party(domain="x.com", received=2)},
                messages_scanned=7)
    p = tmp_path / "h.json"
    h.save(p)
    back = History.load(p)
    assert back.messages_scanned == 7
    assert back.domains["x.com"].received == 2
    assert oct(p.stat().st_mode)[-3:] == "600", "contact list must not be world-readable"


def test_first_contact_ask_fires_only_for_strangers():
    from sentinel.features.extractor import Email, extract
    from sentinel.history import History, Party
    from sentinel.scoring.floors import applicable
    e = Email(subject="Payment", sender="ap@vendor.example", receiver="me@example.com",
              body="Please process the outstanding invoice payment to our bank details.")
    f, ev = extract(e)
    empty = History()
    known = History(domains={"vendor.example": Party(
        domain="vendor.example", received=50, sent_to=5,
        first_seen="2020-01-01T00:00:00+00:00")})
    fired_stranger = [x.name for x in applicable(e, f, ev, history=empty)]
    fired_known = [x.name for x in applicable(e, f, ev, history=known)]
    assert "first_contact_ask" in fired_stranger
    assert "first_contact_ask" not in fired_known


def test_imap_folder_names_with_spaces_are_quoted():
    from sentinel.ingest.imap_box import _quote
    assert _quote("[Gmail]/Sent Mail") == '"[Gmail]/Sent Mail"'
    assert _quote("INBOX") == "INBOX"
    assert _quote('"already quoted"') == '"already quoted"'
