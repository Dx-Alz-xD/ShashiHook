"""Account security: hashing, secrecy, lockout, and mailbox isolation."""
from __future__ import annotations

import time

import pytest


@pytest.fixture
def store(tmp_path, monkeypatch):
    from sentinel import auth
    monkeypatch.setattr(auth, "KEY_PATH", tmp_path / "master.key")
    monkeypatch.delenv("SHASHIHOOK_MASTER_KEY", raising=False)
    return auth.UserStore(path=tmp_path / "users.json")


def test_passwords_are_argon2id(store):
    """Not bcrypt, not scrypt, not Argon2i — the memory-hard, side-channel
    resistant variant, which is the one OWASP names."""
    u = store.create("a@b.com", "a-long-enough-password")
    assert u.password_hash.startswith("$argon2id$")
    assert "m=65536" in u.password_hash, "64 MiB memory cost"
    assert "a-long-enough-password" not in u.password_hash


def test_wrong_password_and_unknown_account_are_indistinguishable(store):
    """Different wording turns the login form into a list of who has an account."""
    store.create("real@b.com", "a-long-enough-password")
    _, why_wrong = store.authenticate("real@b.com", "not-the-password")
    _, why_missing = store.authenticate("ghost@b.com", "not-the-password")
    assert why_wrong == why_missing


def test_account_locks_after_repeated_failures(store):
    from sentinel.auth import MAX_FAILURES
    store.create("a@b.com", "a-long-enough-password")
    for _ in range(MAX_FAILURES):
        store.authenticate("a@b.com", "wrong")
    u, why = store.authenticate("a@b.com", "a-long-enough-password")
    assert u is None and "locked" in why


def test_mailbox_password_is_encrypted_not_hashed(store):
    """It has to be recoverable: the scanner presents it to the mail server.

    So the test is that it is not stored in the clear and does round-trip --
    the opposite property from the login password.
    """
    store.create("a@b.com", "a-long-enough-password")
    store.set_mailbox("a@b.com", "imap.example.com", 993, "a@b.com", "app-pw-secret")
    u = store.users["a@b.com"]
    assert "app-pw-secret" not in u.imap_password_enc
    assert u.imap_password() == "app-pw-secret"


def test_a_wrong_key_reveals_nothing(store, tmp_path, monkeypatch):
    """A stolen database without the key file is not a stolen mailbox."""
    from sentinel import auth
    store.create("a@b.com", "a-long-enough-password")
    store.set_mailbox("a@b.com", "imap.example.com", 993, "a@b.com", "app-pw-secret")
    blob = store.users["a@b.com"].imap_password_enc
    monkeypatch.setattr(auth, "KEY_PATH", tmp_path / "different.key")
    assert auth.decrypt(blob) == "", "must fail closed, not return garbage"


def test_public_never_leaks_the_hash_or_the_ciphertext(store):
    store.create("a@b.com", "a-long-enough-password")
    store.set_mailbox("a@b.com", "imap.example.com", 993, "a@b.com", "app-pw-secret")
    pub = store.users["a@b.com"].public()
    flat = repr(pub)
    assert "password_hash" not in pub and "imap_password_enc" not in pub
    assert "argon2" not in flat and "app-pw-secret" not in flat


def test_demo_mailbox_address_is_masked(store):
    """The demo account is shared, and its mailbox is a real personal address."""
    store.create("demo@x.com", "a-long-enough-password")
    store.set_mailbox("demo@x.com", "imap.gmail.com", 993, "someone@gmail.com", "pw")
    u = store.users["demo@x.com"]
    u.is_demo = True
    assert u.public()["imap_user"] != "someone@gmail.com"
    assert u.public()["imap_user"].endswith("@gmail.com")


def test_sessions_reject_tampering(tmp_path, monkeypatch):
    from sentinel import auth
    monkeypatch.setattr(auth, "KEY_PATH", tmp_path / "master.key")
    monkeypatch.delenv("SHASHIHOOK_MASTER_KEY", raising=False)
    token = auth.issue_session("a@b.com")
    assert auth.read_session(token) == "a@b.com"
    assert auth.read_session(token[:-5] + "aaaaa") == ""
    assert auth.read_session("") == ""


def test_short_and_obvious_passwords_are_refused():
    from sentinel.auth import MIN_PASSWORD, password_problem
    assert password_problem("short")
    assert password_problem("password")
    assert password_problem("1234567890")
    assert password_problem("x" * MIN_PASSWORD) == ""


def test_user_settings_isolate_one_mailbox_from_another(store):
    """The mailbox a request reads comes from the session, never a global.

    A copy is essential: mutating the shared settings object would leak one
    user's mail server into whichever request ran next.
    """
    from app.accounts import user_settings
    from sentinel.settings import settings as shared
    store.create("a@b.com", "a-long-enough-password")
    store.set_mailbox("a@b.com", "imap.a.com", 993, "a@b.com", "pw-a")
    store.create("c@d.com", "a-long-enough-password")
    store.set_mailbox("c@d.com", "imap.c.com", 993, "c@d.com", "pw-c")

    a = user_settings(store.users["a@b.com"])
    c = user_settings(store.users["c@d.com"])
    assert (a.imap_host, a.imap_password) == ("imap.a.com", "pw-a")
    assert (c.imap_host, c.imap_password) == ("imap.c.com", "pw-c")
    assert a is not shared and c is not shared
    assert shared.imap_host != "imap.a.com" or shared.imap_password != "pw-a"


def test_a_user_with_no_mailbox_gets_no_credentials(store):
    """Never fall back to the process .env: that is one user reading another's mail."""
    from app.accounts import user_settings
    store.create("a@b.com", "a-long-enough-password")
    cfg = user_settings(store.users["a@b.com"])
    assert cfg.imap_user == "" and cfg.imap_password == ""


# ----------------------------------------------------------- learner
def test_questions_target_what_the_learner_keeps_missing():
    """The whole claim of "adaptive".

    Weak tactics that the message cannot demonstrate are excluded — asking
    about links in a message with no links would teach a fiction.
    """
    from sentinel.learning import LearnerProfile
    p = LearnerProfile(email="x@y.com")
    for _ in range(8):
        p.record("urgency", True)          # strong
        p.record("sender_identity", False)  # weak
    weak = p.weak_tactics(n=10)
    assert "sender_identity" in weak
    assert "urgency" not in weak


def test_one_unlucky_answer_does_not_make_a_weakness():
    """A tactic with two attempts is not evidence of anything."""
    from sentinel.learning import MIN_ATTEMPTS, LearnerProfile
    p = LearnerProfile(email="x@y.com")
    p.record("links", False)
    assert not p.score("links").settled
    for _ in range(MIN_ATTEMPTS):
        p.record("links", False)
    assert p.score("links").settled


def test_available_tactics_come_from_the_evidence():
    """Not from the model's imagination: a message with no attachment must
    never produce an attachment question."""
    from sentinel.analyzer import ThreatAnalyzer
    from sentinel.features.extractor import Email
    from sentinel.learning import available_tactics
    a = ThreatAnalyzer().analyze(Email(
        subject="Verify your account", sender="alerts@bank-secure.tk",
        receiver="me@example.com",
        body="Your account is suspended. Confirm your password within 24 "
             "hours at http://bank-secure.tk/verify or it will be closed."))
    t = available_tactics(a)
    assert "links" in t, "the message has a link"
    assert "attachments" not in t, "the message has no attachment"
    assert "pretext" in t, "every hostile message has a story"


def test_learner_progress_is_not_world_readable(tmp_path):
    """What somebody is learning is personal."""
    from sentinel.learning import LearnerStore
    s = LearnerStore(path=tmp_path / "learners.json")
    s.get("a@b.com").record("urgency", True)
    s.save()
    assert oct((tmp_path / "learners.json").stat().st_mode)[-3:] == "600"
    assert LearnerStore.load(tmp_path / "learners.json").get("a@b.com").answered == 1


# ----------------------------------------------------------- practice pool
def _pool():
    from sentinel.practice import PracticePool
    return PracticePool(
        items={
            "m1": {"id": "m1", "subject": "Act now", "sender": "a@b.tk",
                   "body": "Your account is suspended, verify your password now.",
                   "label": 1, "vector": "credential_phishing",
                   "vector_confidence": 0.9, "source": "test",
                   "spans": [{"start": 5, "end": 12, "lexicon": "urgency",
                              "term": "account"}]},
            "b1": {"id": "b1", "subject": "Lunch", "sender": "c@d.com",
                   "body": "Moving lunch to one o'clock, let me know.",
                   "label": 0, "vector": "benign", "vector_confidence": 1.0,
                   "source": "test", "spans": []},
        },
        twins=[{"malicious": "m1", "benign": "b1", "similarity": 0.8}])


def test_the_answer_key_never_reaches_the_browser():
    """Label and spans are withheld until an answer is submitted.

    Sending them with the question hides the answer exactly where a curious
    person looks first.
    """
    import random
    p = _pool()
    ex = p.build("drill", random.Random(1))
    assert "label" not in ex["message"]
    assert "spans" not in ex["message"]
    for m in p.build("twin", random.Random(1))["messages"]:
        assert "label" not in m


def test_drill_is_graded_on_the_corpus_label():
    p = _pool()
    assert p.mark_label("m1", said_hostile=True)["correct"] is True
    assert p.mark_label("m1", said_hostile=False)["correct"] is False
    assert p.mark_label("b1", said_hostile=False)["correct"] is True


def test_clicking_near_a_tell_counts():
    """People aim at a word, not a character offset.

    Demanding exactness would measure mouse precision rather than whether the
    learner found the tell.
    """
    from sentinel.practice import SPAN_SLACK
    p = _pool()
    assert p.mark_click("m1", 6)["correct"] is True
    assert p.mark_click("m1", 5 - SPAN_SLACK + 1)["correct"] is True
    assert p.mark_click("m1", 5 + SPAN_SLACK + 40)["correct"] is False


def test_the_scam_is_not_always_on_the_left():
    """A fixed position is learnable, and then the exercise measures nothing."""
    import random
    p = _pool()
    seen = {p.build("twin", random.Random(s))["answer_index"] for s in range(40)}
    assert seen == {0, 1}


def test_triage_does_not_teach_a_fake_base_rate():
    """A 50/50 stream trains someone to over-flag a real inbox."""
    import random
    from sentinel.practice import PracticePool
    items = {}
    for i in range(30):
        items[f"m{i}"] = {"id": f"m{i}", "subject": "s", "sender": "a@b.tk",
                          "body": "x", "label": 1, "vector": "v",
                          "vector_confidence": 1.0, "source": "t", "spans": []}
        items[f"b{i}"] = {"id": f"b{i}", "subject": "s", "sender": "c@d.com",
                          "body": "y", "label": 0, "vector": "benign",
                          "vector_confidence": 1.0, "source": "t", "spans": []}
    ex = PracticePool(items=items).build("triage", random.Random(3), n=9)
    hostile = sum(items[m["id"]]["label"] for m in ex["messages"])
    assert 1 <= hostile <= len(ex["messages"]) // 2


def test_practice_needs_no_language_model(monkeypatch):
    """These four must work when both providers are down.

    That is the point of grading against the corpus label and the spans.
    """
    import random
    from sentinel.profiling import llm
    monkeypatch.setattr(llm, "complete", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("practice must not call a provider")))
    monkeypatch.setattr(llm, "complete_vision", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("practice must not call a provider")))
    p = _pool()
    for mode in ("drill", "twin", "highlight"):
        assert p.build(mode, random.Random(2)) is not None
    assert p.mark_label("m1", True)["correct"] is True
