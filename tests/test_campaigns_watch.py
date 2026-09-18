"""Campaign clustering and the watch daemon.

The clustering tests are mostly about what must NOT merge: a view that claims
two unrelated senders are one actor is worse than no view at all.
"""
from __future__ import annotations

import json

from sentinel.analyzer import ThreatAnalyzer
from sentinel.campaigns import (MIN_WORDS_FOR_TEXT_LINK, SIMHASH_THRESHOLD,
                                SIMHASH_THRESHOLD_CROSS_SENDER, cluster,
                                _dynamic_common_hosts, hamming, simhash, to_graph)
from sentinel.features.extractor import Email
from sentinel.watch import BAND_RANK, WatchState, _alert

AZ = ThreatAnalyzer(inbox_base_rate=0.02)
LONG = ("As part of our quarterly beneficiary reconciliation your account has been "
        "selected for an additional verification review. Our automated system "
        "identified a mismatch between the beneficiary information on your profile "
        "and the information submitted during the most recent settlement cycle. To "
        "prevent the settlement from being placed into manual review please confirm "
        "the beneficiary information through the secure verification portal. The "
        "session is protected and will expire after fifteen minutes. ")


def _msg(sender, subject="Action required", body=LONG, name="Krish"):
    return AZ.analyze(Email(subject=subject, sender=sender, receiver="me@example.com",
                            body=body.replace("your account", f"{name}'s account")))


# ------------------------------------------------------------------ simhash
def test_simhash_survives_per_recipient_substitution():
    a = simhash(LONG.replace("your", "Krish's"))
    b = simhash(LONG.replace("your", "Sarah's"))
    assert hamming(a, b) <= SIMHASH_THRESHOLD


def test_simhash_separates_unrelated_text():
    a = simhash(LONG)
    b = simhash("Hi all, notes from today's engineering sync are in the shared drive "
                "and we agreed to move the migration to next sprint. " * 4)
    assert hamming(a, b) > SIMHASH_THRESHOLD * 2


def test_cross_sender_threshold_is_stricter():
    """Long messages share boilerplate. At the same-sender threshold that was
    enough to merge a College Board mailing with a TripAdvisor one."""
    assert SIMHASH_THRESHOLD_CROSS_SENDER < SIMHASH_THRESHOLD


# ----------------------------------------------------------------- clustering
def test_same_sender_template_clusters():
    a = [_msg("ap@fraud-domain.test", name=n) for n in ("Krish", "Sarah", "Tom")]
    cs = cluster(a, min_size=2, malicious_only=False)
    assert cs and cs[0].size == 3
    assert "fraud-domain.test" in cs[0].sender_domains


def test_unrelated_senders_do_not_merge():
    a = [_msg("news@alpha.test", subject="Weekly digest",
              body="Here is what shipped this month across the platform. " * 12),
         _msg("info@beta.test", subject="Product update",
              body="Our newest release includes a redesigned dashboard today. " * 12)]
    cs = cluster(a, min_size=2, malicious_only=False)
    cross = [c for c in cs if len(c.sender_domains) > 1]
    assert not cross, f"unrelated senders merged: {[c.sender_domains for c in cross]}"


def test_short_bodies_do_not_link_by_text():
    """SimHash over a handful of shingles is unreliable; two short footers can
    land close together by accident."""
    short = "Thanks, regards the team."
    assert len(short.split()) < MIN_WORDS_FOR_TEXT_LINK
    a = [_msg("a@one.test", body=short), _msg("b@two.test", body=short)]
    cs = cluster(a, min_size=2, malicious_only=False)
    assert not [c for c in cs if len(c.sender_domains) > 1]


def test_shared_hosts_are_detected_from_the_data():
    """c.gle -- Google's own shortener -- defeated a hardcoded list."""
    a = [AZ.analyze(Email(subject="x", sender=f"n@s{i}.test",
                          body=f"See https://shared-cdn.test/a{i} for details. " * 20))
         for i in range(3)]
    assert "shared-cdn.test" in _dynamic_common_hosts(a)


def test_link_domain_joins_different_senders():
    a = [AZ.analyze(Email(subject="Verify", sender=f"x@sender{i}.test",
                          receiver="me@example.com",
                          body="Please verify your account at https://evil-kit.test/login "
                               "within 24 hours or it will be suspended. " * 6))
         for i in range(2)]
    cs = cluster(a, min_size=2, malicious_only=False)
    assert cs, "two senders sharing one link domain should form a campaign"
    assert "evil-kit.test" in cs[0].link_domains


def test_campaign_graph_has_the_kill_chain_shape():
    a = [_msg("ap@fraud-domain.test", name=n) for n in ("A", "B")]
    g = to_graph(cluster(a, min_size=2, malicious_only=False)[0])
    kinds = {n["kind"] for n in g["nodes"]}
    assert "actor" in kinds and "identity" in kinds and "technique" in kinds
    assert g["edges"]


# ---------------------------------------------------------------------- watch
def test_watch_state_does_not_re_alert(tmp_path):
    p = tmp_path / "seen.json"
    s = WatchState(seen={"a", "b"}, notified=2)
    s.save(p)
    back = WatchState.load(p)
    assert back.seen == {"a", "b"} and back.notified == 2
    assert oct(p.stat().st_mode)[-3:] == "600"


def test_watch_seen_list_is_bounded(tmp_path):
    p = tmp_path / "seen.json"
    WatchState(seen={f"id-{i}" for i in range(20000)}).save(p)
    assert len(WatchState.load(p).seen) <= 8000


def test_band_ranking_orders_correctly():
    assert (BAND_RANK["CRITICAL"] > BAND_RANK["HIGH"] > BAND_RANK["MEDIUM"]
            > BAND_RANK["LOW"] > BAND_RANK["INFORMATIONAL"])


def test_alert_text_carries_what_matters():
    a = _msg('"Support" <x@verify-now.test>')
    title, subtitle, body = _alert(a)
    assert a.severity.band in title and "/100" in title
    assert subtitle == a.vector.name
    assert "from" in body


# ------------------------------------------------- quoted-thread verification
def _index(n_pad=400):
    from sentinel.threads import ThreadIndex
    ix = ThreadIndex()
    ix.add("<real1@acme.com>", "Q3 supplier payment",
           "Hi Tom, thanks for sending the revised schedule over. We will review the "
           "numbers with finance this week and revert with any questions before Friday.")
    for i in range(n_pad):
        ix.add(f"<p{i}@x.com>", f"padding {i}", f"filler message number {i} " * 12)
    return ix


QUOTE = ("On Thu 18 Sep, Tom wrote:\n> Hi Tom, thanks for sending the revised schedule "
         "over. We will review the numbers with finance this week and revert with any "
         "questions before Friday.")
FAKE = ("On Thu 18 Sep, Legal wrote:\n> Thanks Tom, we will review the renewal terms "
        "and revert shortly. Please send the updated contract when you have a moment "
        "so we can countersign before the end of the quarter.")


def test_genuine_quote_is_found_in_the_mailbox():
    from sentinel.features.extractor import Email
    from sentinel.threads import verify
    v = verify(Email(subject="Re: Q3 supplier payment", body="Sounds good.\n\n" + QUOTE),
               _index())
    assert v.claims_thread and not v.fabricated
    assert v.quote_match_ratio > 0.5


def test_fabricated_quote_is_caught():
    from sentinel.features.extractor import Email
    from sentinel.threads import verify
    v = verify(Email(subject="Re: Contract renewal", body="Here is the copy.\n\n" + FAKE),
               _index())
    assert v.fabricated and v.quote_match_ratio == 0.0


def test_a_thin_index_cannot_prove_fabrication():
    """Absence of a match only means something if the index actually covers the
    period. Otherwise 'fabricated' is an artefact of how much was indexed."""
    from sentinel.features.extractor import Email
    from sentinel.threads import verify
    v = verify(Email(subject="Re: anything", body="x\n\n" + FAKE), _index(n_pad=5))
    assert not v.fabricated and v.indeterminate
    assert "too few" in v.note


def test_message_id_resolution_clears_a_thread():
    from sentinel.features.extractor import Email
    from sentinel.threads import verify
    e = Email(subject="Re: something else", body="short reply\n\n" + FAKE)
    e.in_reply_to = "<real1@acme.com>"
    v = verify(e, _index())
    assert v.msgid_resolved and not v.fabricated


def test_no_quote_means_no_claim():
    from sentinel.features.extractor import Email
    from sentinel.threads import verify
    v = verify(Email(subject="Hello", body="Just checking in, no quoted text here."),
               _index())
    assert not v.claims_thread and not v.fabricated


def test_index_stores_no_readable_text():
    """The index must be able to confirm a quote without holding what was said."""
    ix = _index(n_pad=5)
    blob = json.dumps({"ids": list(ix.message_ids), "subjects": list(ix.subjects),
                       "shingles": list(ix.shingle_to_id)})
    assert "thanks for sending the revised schedule" not in blob.lower()
    assert all(len(sh) == 12 for sh in list(ix.shingle_to_id)[:20])


# ------------------------------------------------------ sender-profile signals
def test_reply_rate_beats_mere_receipt():
    from sentinel.history import Party
    passive = Party(domain="news.example", received=500, sent_to=0)
    real = Party(domain="colleague.example", received=40, sent_to=18)
    assert passive.reply_rate == 0.0
    assert real.reply_rate > 0.4


def test_dormant_domain_is_flagged_only_after_a_long_silence():
    from sentinel.history import Party
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    lapsed = Party(domain="old.example", received=200,
                   first_seen=(now - timedelta(days=2400)).isoformat(),
                   last_seen=(now - timedelta(days=1500)).isoformat())
    active = Party(domain="live.example", received=200,
                   first_seen=(now - timedelta(days=900)).isoformat(),
                   last_seen=(now - timedelta(days=2)).isoformat())
    assert lapsed.dormancy_days(now) and lapsed.dormancy_days(now) > 365
    assert active.dormancy_days(now) is None


def test_unusual_hour_needs_enough_history():
    from sentinel.history import Party
    thin = Party(domain="x.example", received=3, hours={"9": 3})
    assert not thin.unusual_hour(3), "3 observations cannot establish a rhythm"
    solid = Party(domain="y.example", received=60, hours={"9": 30, "10": 20, "14": 10})
    assert solid.unusual_hour(3)
    assert not solid.unusual_hour(10)


def test_corpus_scripts_disable_thread_verification():
    """Guard against a trap that cost 2,261 false positives.

    Corpus mail came from other mailboxes, so checking its quoted threads
    against this user's index always answers "absent". Training was guarded
    from day one; the evaluation was not, and the held-out false-positive rate
    silently went from 1.1% to 28.7%.
    """
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    for name in ("build_dataset.py", "eval_full.py", "eval_coverage.py"):
        src = (root / "scripts" / name).read_text()
        assert "disable_for_corpus" in src, (
            f"scripts/{name} scores corpus mail and must call "
            f"disable_for_corpus() before doing so")


def test_disable_for_corpus_really_disables_it():
    from sentinel.features.extractor import Email, extract, set_thread_index
    from sentinel.threads import ThreadIndex, disable_for_corpus

    ix = _index()                      # a populated index
    set_thread_index(ix)
    quoting = Email(subject="Re: something",
                    body="Reply text.\n\n" + FAKE)
    f_on, _ = extract(quoting)
    assert f_on["thr_fabricated"] == 1.0, "precondition: this trips with an index"

    disable_for_corpus()
    f_off, ev_off = extract(quoting)
    assert f_off["thr_fabricated"] == 0.0
    assert ev_off.thread.indeterminate, "with no index the honest answer is 'unknown'"
    set_thread_index(ix)               # restore for any later test


# --------------------------------------------------------------- job scam
def _job_hits(text: str) -> int:
    """How many job_scam lexicon patterns fire on a body."""
    import re
    from sentinel.features.lexicons import LEXICONS
    return sum(bool(re.search(p, text, re.I)) for p in LEXICONS["job_scam"])


def test_conference_registration_fee_is_not_a_job_scam():
    """A conference charging a fee is commerce, not recruitment.

    The first version of this pattern matched the bare phrase and fired on 220
    benign corpus messages against 8 malicious -- almost all of them academic
    call-for-papers announcements.
    """
    conference = (
        "Authors of accepted papers must be prepared to sign a copyright "
        "statement and must pay the registration fee for the conference. "
        "The student registration fee is kept at a low $40."
    )
    assert _job_hits(conference) == 0


def test_fee_as_a_precondition_for_work_is_a_job_scam():
    scam = (
        "To secure your position and to show us that you are serious about "
        "earning extra income at home we require a one-time registration fee "
        "of $35.00 before you start work. Only 2-3 hours a day needed."
    )
    assert _job_hits(scam) >= 2


def test_twentyfour_hours_a_day_is_not_a_part_time_pitch():
    """"24 hours a day, 7 days a week" is a support line, not a shift.

    An unbounded digit match scored 82% "precision" on the corpus purely by
    catching this boilerplate in pill and dating spam.
    """
    support = "Our customer service team is available 24 hours a day, 7 days a week."
    assert _job_hits(support) == 0
    assert _job_hits("Work just 2-3 hours a day from home") >= 1


# ----------------------------------------------------- fabricated threads
def _fab_floor_names(hist_signals):
    """Run the floor layer with thr_fabricated set and the given history."""
    from unittest.mock import MagicMock
    import sentinel.scoring.floors as F

    feats = {"thr_fabricated": 1.0}
    ev = MagicMock()
    ev.thread.note = "quotes a conversation that never happened"
    ev.sender.address = "peer@example.com"
    email = MagicMock(date="", body="", subject="")
    history = MagicMock()
    history.signals.return_value = hist_signals
    floors = F.applicable(email, feats, ev, history=history)
    return {f.name for f in floors}


def test_fabricated_thread_fires_for_an_unknown_sender():
    """The attack it was written for: a hijack from a lookalike domain."""
    assert "fabricated_thread" in _fab_floor_names(
        {"first_contact": True, "ever_corresponded_with_domain": False,
         "messages_from_domain": 0})


def test_fabricated_thread_spares_an_established_correspondent():
    """Absence of the original is not evidence of forgery.

    Against 43 real Enron mailboxes this floor called 23.3% of 26,694 genuine
    quoted replies fabricated -- every one wrong, because a mailbox holds the
    user's mail, not the whole thread. Requiring that the sender be someone the
    mailbox has not actually corresponded with drops that to 2.0%. See
    scripts/eval_thread_verify.py.
    """
    assert "fabricated_thread" not in _fab_floor_names(
        {"first_contact": False, "ever_corresponded_with_domain": True,
         "messages_from_domain": 40, "reply_rate": 0.4, "days_known": 900})
