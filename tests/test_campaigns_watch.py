"""Campaign clustering and the watch daemon.

The clustering tests are mostly about what must NOT merge: a view that claims
two unrelated senders are one actor is worse than no view at all.
"""
from __future__ import annotations

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
