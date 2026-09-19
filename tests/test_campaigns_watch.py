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
def _fabricated_floors(history):
    """Score a reply quoting an exchange no mailbox of ours contains."""
    from sentinel.features.extractor import Email, extract, set_thread_index
    from sentinel.scoring.floors import applicable
    from sentinel.threads import ThreadIndex

    idx = ThreadIndex()
    for i in range(250):                      # past verify()'s min_index guard
        idx.add(f"m{i}@corp.example", f"Weekly report {i}",
                f"Numbers for week {i} are attached, nothing unusual to flag.")
    set_thread_index(idx)
    try:
        e = Email(
            subject="Re: Updated wire instructions",
            sender="finance@vendor.example", receiver="me@example.com",
            body="As discussed below, please use the new account.\n\n"
                 "> On Tuesday, Accounts Payable wrote:\n"
                 "> Thanks for confirming the revised remittance details for the\n"
                 "> Q3 settlement. Our treasury team has approved the change and\n"
                 "> the updated beneficiary account should be used for all future\n"
                 "> invoices issued against the framework agreement we signed.\n")
        f, ev = extract(e)
        assert f.get("thr_fabricated") == 1.0, "fixture must produce a fabricated verdict"
        return {x.name for x in applicable(e, f, ev, history=history)}
    finally:
        set_thread_index(ThreadIndex())       # global; leave it as we found it


def test_fabricated_thread_fires_for_an_unknown_sender():
    """The attack it was written for: a hijack from a lookalike domain.

    The mailbox has been scanned and knows other correspondents, so "no mail
    from vendor.example" is a real finding rather than an empty store.
    """
    from sentinel.history import History, Party
    scanned = History(
        domains={"colleague.example": Party(
            domain="colleague.example", received=80, sent_to=40,
            first_seen="2020-01-01T00:00:00+00:00")},
        messages_scanned=5000)
    assert "fabricated_thread" in _fabricated_floors(scanned)


def test_fabricated_thread_spares_an_established_correspondent():
    """Absence of the original is not evidence of forgery.

    Replayed against 43 real Enron mailboxes, this floor called 23.3% of 26,694
    genuine quoted replies fabricated -- every one wrong, because a mailbox
    holds the user's mail, not the whole thread. Requiring that the sender be
    someone the mailbox has not actually corresponded with drops that to 2.0%.
    scripts/eval_thread_verify.py reproduces both numbers.
    """
    from sentinel.history import History, Party
    known = History(domains={"vendor.example": Party(
        domain="vendor.example", received=40, sent_to=12,
        first_seen="2020-01-01T00:00:00+00:00")}, messages_scanned=5000)
    assert "fabricated_thread" not in _fabricated_floors(known)


def test_fabricated_thread_stands_down_without_a_history_store():
    """No history is not evidence of a stranger.

    `hist` is empty until the mailbox has been scanned. Treating that as an
    unknown sender would fire this floor on every quoted reply a new user
    receives -- the 23.3% false rate the gate exists to prevent.
    """
    from sentinel.history import History
    assert "fabricated_thread" not in _fabricated_floors(History())


# ------------------------------------------------------------- stylometry
def test_short_messages_have_no_style():
    """A four-word reply is written the same way by everyone."""
    from sentinel.stylometry import traits
    assert traits("Sounds good, thanks!") is None
    assert traits("word " * 200) is not None


def test_quoted_text_and_signatures_are_not_the_sender_s_style():
    """A long quoted chain would otherwise profile the person being quoted."""
    from sentinel.stylometry import readable_body
    body = ("Here is my own short note about the schedule.\n\n"
            "On Tuesday, Someone Else wrote:\n"
            "> I tend to write in a completely different manner, at length,\n"
            "> with many subordinate clauses; and semicolons.\n")
    out = readable_body(body)
    assert "my own short note" in out
    assert "subordinate clauses" not in out


def test_profile_recognises_its_own_author():
    """The whole claim, in miniature.

    Measured properly across 362 Enron senders this reaches 0.915 mean
    per-sender AUC; see scripts/eval_stylometry.py. Here it only has to prefer
    the right author over a visibly different one.
    """
    from sentinel.stylometry import StyleStore
    terse = ("got it. will do. sending the file now. no changes needed. "
             "let me know. thanks. ") * 12
    formal = ("Dear colleague, I should like to confirm that the documentation "
              "has been reviewed in full; furthermore, the revised schedule "
              "remains acceptable to us. Kind regards. ") * 12
    # The population spread is taken across senders, so several are needed
    # before any trait can be called unusual -- with two writers there is no
    # such thing as an unusual writer.
    chatty = ("so anyway i think we should just go ahead and do it, whatever "
              "you reckon is fine by me really, up to you! ") * 12
    legal = ("Pursuant to clause 4.2, the party of the first part shall "
             "indemnify the party of the second part in respect thereof. ") * 12
    store = StyleStore()
    for i in range(14):
        store.observe("terse@example.com", terse + f"note {i} " * 20)
        store.observe("formal@example.com", formal + f"item {i} " * 20)
        store.observe("chatty@example.com", chatty + f"bit {i} " * 20)
        store.observe("legal@example.com", legal + f"para {i} " * 20)
    store.fit_population()
    assert store.ready
    own = store.compare("terse@example.com", terse + "one more short line here. " * 20)
    imposter = store.compare("terse@example.com", formal + "a further observation. " * 20)
    assert own.scored and imposter.scored
    assert own.drift < imposter.drift


def test_style_store_is_not_world_readable(tmp_path):
    """It describes how people write, which is information about them."""
    from sentinel.stylometry import StyleStore
    s = StyleStore()
    s.observe("a@b.com", "word " * 200)
    p = tmp_path / "style.json"
    s.save(p)
    assert oct(p.stat().st_mode)[-3:] == "600"
    assert StyleStore.load(p).profiles["a@b.com"].n == 1


def test_corpus_guard_clears_style_profiles():
    """Corpus mail has no baseline in this mailbox, so it must not be compared.

    The thread index taught this lesson the expensive way: a guard that each
    script must remember to call gets forgotten. Both are cleared together.
    """
    from sentinel.features.extractor import set_style_store, style_store
    from sentinel.stylometry import StyleStore
    from sentinel.threads import disable_for_corpus
    seeded = StyleStore()
    seeded.observe("someone@corp.example", "word " * 200)
    set_style_store(seeded)
    assert style_store().profiles
    disable_for_corpus()
    assert not style_store().profiles


def test_watch_learns_style_only_from_mail_it_cleared():
    """A suspected impersonation must not teach the profile.

    Otherwise each attack nudges the baseline towards the attacker, and the
    detector slowly trains itself to accept them.
    """
    from unittest.mock import MagicMock
    from sentinel.features.extractor import set_style_store, style_store
    from sentinel.stylometry import StyleStore
    from sentinel.watch import _learn_style

    set_style_store(StyleStore())
    email = MagicMock(body="word " * 200, html=None)

    hostile = MagicMock(probability=0.97, floors_binding=[])
    hostile.evidence.sender.address = "ceo@vendor.example"
    _learn_style(email, hostile)
    assert not style_store().profiles, "hostile mail must not shape a profile"

    clean = MagicMock(probability=0.02, floors_binding=[])
    clean.evidence.sender.address = "ceo@vendor.example"
    _learn_style(email, clean)
    assert style_store().profiles["ceo@vendor.example"].n == 1
    set_style_store(StyleStore())


# ----------------------------------------------------------- multilingual
def test_non_latin_scripts_are_decided_by_script():
    from sentinel.multilingual import detect
    hindi = ("प्रिय ग्राहक, हम आपको सूचित करना चाहते हैं कि सुरक्षा कारणों से आपका "
             "बैंक खाता अस्थायी रूप से निलंबित कर दिया गया है।")
    v = detect(hindi)
    assert not v.is_english and v.lang == "hi" and v.script == "Devanagari"


def test_chinese_is_not_dismissed_as_too_short():
    """Chinese puts no spaces between words.

    Gating on a word count first made a full paragraph of Han look like nine
    words and it was skipped entirely. Script is tested on characters instead.
    """
    from sentinel.multilingual import detect
    zh = ("尊敬的客户您好，我们通知您由于安全原因您的银行账户已被临时冻结。"
          "为了恢复对您账户的访问，您需要在四十八小时内通过下面的链接确认您的个人信息。")
    v = detect(zh)
    assert not v.is_english and v.lang == "zh"


def test_english_spam_is_not_called_foreign():
    """The expensive direction: a wrong guess spends a provider call.

    Mangled spam carries no English function words at all, so a pure ratio test
    divided by ~zero and any stray match won -- that alone mislabelled 4.23% of
    the corpus. An absolute floor and a distinct-word count bring it to 0.40%.
    """
    from sentinel.multilingual import detect
    assert detect("As simple as black and white Wonderful thing "
                  "http://bunjax.cn/a/ click here now to see more").is_english
    assert detect("Where there is love, there is God also. Visit the link "
                  "below for more information about this offer today").is_english


def test_spanish_phishing_is_detected():
    from sentinel.multilingual import detect
    v = detect("Estimado cliente, le informamos que su cuenta bancaria ha sido "
               "suspendida por motivos de seguridad. Para restablecer el acceso "
               "es necesario que confirme sus datos personales en el enlace.")
    assert not v.is_english and v.lang == "es"


def test_translation_failure_is_not_fatal(monkeypatch):
    """No provider means a degraded score with a reason, never an exception."""
    import sentinel.multilingual as M
    from sentinel.analyzer import ThreatAnalyzer
    from sentinel.features.extractor import Email
    from sentinel.settings import settings
    monkeypatch.setattr(M, "translate",
                        lambda *a, **k: M.Translation(ok=False, error="no provider"))
    az = ThreatAnalyzer(settings=settings)
    a = az.analyze(Email(
        subject="Verificacion urgente",
        sender="x@y.tk", receiver="me@example.com",
        body="Estimado cliente, le informamos que su cuenta bancaria ha sido "
             "suspendida por motivos de seguridad. Para restablecer el acceso "
             "es necesario que confirme sus datos personales en el enlace."))
    assert a.language["translated"] is False
    assert "unreliable" in a.language["note"]
    assert a.severity.score >= 0          # still produced a verdict


def test_corpus_work_never_translates():
    """An analyzer built without settings must not call a provider.

    build_dataset and eval_full construct one per run; 319 corpus messages look
    foreign, and translating them would put an API call inside the training
    loop.
    """
    from sentinel.analyzer import ThreatAnalyzer
    from sentinel.features.extractor import Email
    az = ThreatAnalyzer()
    assert az.settings is None
    a = az.analyze(Email(
        subject="Verificacion", sender="x@y.tk", receiver="me@example.com",
        body="Estimado cliente, le informamos que su cuenta ha sido suspendida "
             "por motivos de seguridad y debe confirmar sus datos personales."))
    assert a.language["translated"] is False


def test_translation_is_cached_by_content(monkeypatch):
    """The playground scores on every keystroke pause.

    Without a cache that is one provider call per keystroke for anyone drafting
    in another language, and a rescan repays for the whole mailbox.
    """
    import sentinel.multilingual as M
    from sentinel.profiling import llm as _llm
    M._CACHE.clear()
    calls = {"n": 0}

    def fake(cfg, system, user):
        calls["n"] += 1
        return _llm.LLMResult(True, "groq", "m",
                              data={"language": "Spanish", "english": "hello"})

    # translate() imports llm inside the function, so patch it at its source.
    monkeypatch.setattr(_llm, "complete", fake)
    for _ in range(5):
        assert M.translate("hola que tal", None, subject="s").english == "hello"
    assert calls["n"] == 1, f"translated {calls['n']} times, expected 1"
    M._CACHE.clear()


# ---------------------------------------------------------------- vision
def _png(text_lines, qr_url=None, size=(900, 460)):
    """A picture of an email, the way this evasion actually arrives."""
    import io
    from PIL import Image, ImageDraw
    img = Image.new("RGB", size, "white")
    d = ImageDraw.Draw(img)
    for i, ln in enumerate(text_lines):
        d.text((40, 34 + i * 34), ln, fill="black")
    if qr_url:
        import qrcode
        img.paste(qrcode.make(qr_url).resize((150, 150)), (size[0] - 250, size[1] - 210))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _msg_with_image(data, filename="notice.png", inline=False):
    from email import message_from_bytes
    from email.message import EmailMessage
    m = EmailMessage()
    m["Subject"] = "Action Required"
    m["From"] = "it@example.tk"
    m["To"] = "me@example.com"
    m.set_content("")
    if inline:
        m.add_related(data, maintype="image", subtype="png", cid="<img1>")
    else:
        m.add_attachment(data, maintype="image", subtype="png", filename=filename)
    return message_from_bytes(m.as_bytes())


def test_inline_images_are_found():
    """Text-in-image phishing arrives inline, with no filename.

    files.py walks only parts that have a filename because it catalogues
    attachments, which is why vision cannot reuse that walk.
    """
    from sentinel.vision import images_from_message
    found = images_from_message(_msg_with_image(_png(["Verify your password now"]),
                                                inline=True))
    assert len(found) == 1 and found[0].inline


def test_tracking_pixels_are_skipped():
    """A spacer costs a provider call and returns nothing."""
    from sentinel.vision import images_from_message
    assert images_from_message(_msg_with_image(_png([""], size=(1, 1)))) == []


def test_qr_codes_decode_exactly_and_locally():
    """Never delegated to a model: an almost-right URL is worse than none."""
    from sentinel.vision import decode_qr, images_from_message
    url = "https://microsoft-verify-login.tk/auth?u=8842"
    imgs = images_from_message(_msg_with_image(_png(["Scan to verify"], qr_url=url)))
    codes = decode_qr(imgs)
    assert len(codes) == 1
    assert codes[0].text == url, "a QR must decode exactly, not approximately"
    assert codes[0].is_url


def test_qr_survives_a_dead_vision_provider(monkeypatch):
    """Codes are decoded locally, so they do not depend on any provider."""
    from sentinel.profiling import llm as _llm
    from sentinel.settings import settings
    from sentinel import vision
    monkeypatch.setattr(_llm, "complete_vision",
                        lambda *a, **k: _llm.LLMResult(False, "none", error="quota"))
    url = "https://pay-now.tk/x"
    r = vision.inspect(_msg_with_image(_png(["Scan me"], qr_url=url)), settings)
    assert r.ok and [q.text for q in r.qr_codes] == [url]
    assert "quota" in r.note


def test_recovered_text_is_appended_not_substituted(monkeypatch):
    """A message that is half prose and half picture must be scored on both."""
    from sentinel.analyzer import ThreatAnalyzer
    from sentinel.features.extractor import Email
    from sentinel.profiling import llm as _llm
    from sentinel.settings import settings
    monkeypatch.setattr(_llm, "complete_vision",
                        lambda *a, **k: _llm.LLMResult(
                            True, "groq", "m",
                            data={"text": "CONFIRM YOUR PASSWORD IMMEDIATELY",
                                  "says": "a sign-in page", "asks_for": "credentials"}))
    e = Email(subject="Action Required", sender="it@example.tk",
              receiver="me@example.com", body="Please see attached.")
    e.raw_message = _msg_with_image(_png(["Confirm your password immediately"]))
    az = ThreatAnalyzer(settings=settings)
    scored, vis = az._recover_images(e)
    assert "Please see attached." in scored.body
    assert "CONFIRM YOUR PASSWORD IMMEDIATELY" in scored.body
    assert vis["recovered"] is True


# ------------------------------------------------------------ similarity
def test_embeddings_beat_word_overlap_on_paraphrase():
    """The whole reason this exists alongside SimHash.

    SimHash clusters messages that share words, which is right for one blast
    sent to many people and wrong for the same scam rewritten. Measured over
    five paraphrase pairs, embeddings ranked the true match first 5/5 against
    TF-IDF's 2/5.
    """
    import numpy as np
    from sentinel.similarity import encode
    original = ("Your account has been suspended. Verify your password "
                "within 24 hours or lose access.")
    paraphrase = ("We have temporarily locked your profile. Confirm your login "
                  "details inside one day to avoid closure.")
    unrelated = ("The quarterly gas nomination schedule is attached for your "
                 "review before Friday.")
    v = encode([original, paraphrase, unrelated])
    assert float(v[0] @ v[1]) > float(v[0] @ v[2]) + 0.25


def test_weak_matches_are_not_reported():
    """A 0.2 match is noise dressed as evidence."""
    import numpy as np
    from sentinel.similarity import MIN_USEFUL, SimilarityIndex
    ix = SimilarityIndex(
        vectors=np.zeros((2, 256), dtype=np.float16),
        labels=np.array([1, 0], dtype=np.int8),
        vector_names=["x", "y"], subjects=["a", "b"],
        senders=["s", "t"], sources=["c", "c"])
    assert ix.search("anything at all") == []
    assert MIN_USEFUL > 0.2


def test_a_missing_index_does_not_break_scoring():
    """Retrieval is evidence; the verdict must not depend on it."""
    from pathlib import Path
    from sentinel.similarity import SimilarityIndex
    ix = SimilarityIndex.load(Path("/nonexistent/similarity_index.npz"))
    assert ix.size == 0 and ix.search("hello there") == []


def test_neighbours_are_never_a_model_feature():
    """The nearest neighbour's label is close to the answer.

    Feeding it to the model would be leakage rather than learning, so it must
    not appear in the feature vector.
    """
    from sentinel.features.extractor import FEATURE_NAMES
    leaked = [n for n in FEATURE_NAMES
              if "neighbour" in n or "similar" in n or n.startswith("nn_")]
    assert leaked == [], f"retrieval leaked into the feature vector: {leaked}"


# ------------------------------------------------------------------- PE
def _fake_pe(body: bytes, name: bytes = b".text\0\0\0") -> bytes:
    """A minimal but structurally real PE image."""
    import struct
    dos = b"MZ" + b"\0" * 58 + struct.pack("<I", 64)
    coff = struct.pack("<IHHIIIHH", 0x00004550, 0x014C, 1, 0, 0, 0, 224, 0x0102)
    opt = struct.pack("<H", 0x10B) + b"\0" * 222
    sec = name + struct.pack("<IIII", len(body), 0x1000, len(body),
                             64 + 24 + 224 + 40) + b"\0" * 16
    return dos + coff + opt + sec + body


def test_entropy_separates_packed_from_ordinary_code():
    """Entropy is a property of the bytes, not of who collected them.

    This is the one signal that survived the audit of the malware dataset,
    whose classes came from a Windows install and a VirusShare dump and whose
    'best' features separated the collections.
    """
    import random
    from sentinel.pe import PACKED_ENTROPY, parse
    code = parse(_fake_pe(bytes((0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x08) * 900)))
    random.seed(1)
    packed = parse(_fake_pe(bytes(random.randrange(256) for _ in range(5400))))
    assert code.ok and packed.ok
    assert code.max_entropy < PACKED_ENTROPY < packed.max_entropy
    assert any("compressed or encrypted" in n for n in packed.notes)


def test_pe_parser_fails_closed_on_rubbish():
    """A malformed file must return a reason, never raise into the analyser."""
    from sentinel.pe import parse
    for blob in (b"", b"%PDF-1.7", b"MZ", b"MZ" + b"\xff" * 200):
        h = parse(blob)
        assert h.ok is False and h.error


def test_entropy_is_reported_as_a_percentile_not_a_verdict():
    """A percentile invites thought; a probability invites stopping.

    The reference population must be named, because it is Windows program
    files rather than "all software".
    """
    from sentinel.pe import rank
    _, high = rank(7.97)
    _, low = rank(2.25)
    assert "legitimate Windows program files" in high
    assert "%" in high and "malware" not in high.lower()
    assert "unremarkable" in low


def test_the_discredited_pe_model_is_not_reachable():
    """It scored 0.9998 by separating VirusShare from a Windows install.

    It was never callable -- nothing produced its 54 header fields -- and it is
    now removed rather than left looking usable.
    """
    import sentinel.files as files
    assert not hasattr(files, "pe_score")
    assert not hasattr(files, "file_features")


# ------------------------------------------------------------- gold set
def test_silver_labels_keep_only_agreement(tmp_path, monkeypatch):
    """A label is silver only when two independent models chose the same thing."""
    import pandas as pd
    from sentinel.config import EVAL_DIR
    import scripts.eval_gold as eg
    rows = pd.DataFrame([
        {"agree": True, "silver_vector": "credential_phishing",
         "vector": "credential_phishing", "sample_bucket": "high_confidence",
         "a_vector": "credential_phishing", "b_vector": "credential_phishing"},
        {"agree": False, "silver_vector": "",
         "vector": "spam_unwanted", "sample_bucket": "unresolved",
         "a_vector": "benign", "b_vector": "recon_probe"},
    ])
    d = tmp_path / "eval"
    d.mkdir()
    rows.to_csv(d / "gold_set_silver.csv", index=False)
    monkeypatch.setattr(eg, "EVAL_DIR", d)
    df, kind = eg.load()
    assert kind == "silver"
    assert len(df) == 1, "the disagreement must not become a label"
    assert df.iloc[0]["true_vector"] == "credential_phishing"


def test_human_labels_outrank_silver(tmp_path, monkeypatch):
    import pandas as pd
    import scripts.eval_gold as eg
    d = tmp_path / "eval"
    d.mkdir()
    pd.DataFrame([{"agree": True, "silver_vector": "spam_unwanted",
                   "vector": "spam_unwanted", "a_vector": "spam_unwanted",
                   "b_vector": "spam_unwanted"}]).to_csv(
        d / "gold_set_silver.csv", index=False)
    pd.DataFrame([{"true_vector": "credential_phishing",
                   "vector": "spam_unwanted"}]).to_csv(
        d / "gold_set_labelled.csv", index=False)
    monkeypatch.setattr(eg, "EVAL_DIR", d)
    _, kind = eg.load()
    assert kind == "human"
