"""Deterministic detections that set a floor under the model's confidence.

The intent model is trained on 2001-2008 mail and is consequently blind to
attacks that did not exist then. Measured on the modern probe set, it misses
every BEC message and half the malware containers: a linkless gift-card request
reads, lexically, exactly like ordinary business correspondence, because in the
Enron ham that is precisely what it is.

No amount of tuning fixes that -- it is missing training data, not a bad fit.
What fixes it operationally is what every production mail-security stack does:
pair the classifier with a small set of deterministic detections chosen for
near-zero false-positive rate on legitimate business mail, and let them set a
minimum confidence the model cannot pull below.

Every floor that fires is recorded and printed in the report as rule-derived,
never silently folded into the model's number. An analyst always sees which of
the two decided, and the floors are listed here in one auditable place.
"""
from __future__ import annotations

from dataclasses import dataclass

import re

from ..features.extractor import Email, Evidence

# Extensions that execute with no further container step and have no business
# arriving by mail. The wider DANGEROUS_EXTENSIONS set used for model features
# includes .js, .jar, .msi, .dll and .svg, which developer mailing lists link to
# legitimately all the time -- measured on held-out mail, a floor built on the
# wide set fired 626 times and was wrong 625 times. Floors get the narrow set.
HARD_EXECUTABLE = frozenset({
    "exe", "scr", "pif", "bat", "cmd", "vbs", "vbe", "jse", "wsf", "hta",
    "lnk", "iso", "img", "cpl", "scf", "msi", "docm", "xlsm", "pptm", "xll",
})

GIFT_CARD_REQUEST_RE = re.compile(
    r"(?i)\b(?:purchase|buy|get|pick up|obtain|send|need)\b[^.!?\n]{0,40}\bgift ?cards?\b"
    r"|\bgift ?cards?\b[^.!?\n]{0,30}\b(?:for a client|urgently|asap|right away|"
    r"and send|codes?|scratch)\b"
)
# Display names that assert an official identity rather than a person's name.
# The money_request lexicon is deliberately broad for the model, which can
# weigh a fuzzy signal. A floor cannot: built on that lexicon it fired 61 times
# on held-out mail and was wrong 59 times, every one a newsletter saying
# "sponsor", "donation" or "contribution". A floor needs the direct, first-person
# ask and nothing else.
DIRECT_MONEY_ASK_RE = re.compile(
    r"(?i)\b(?:send|wire|transfer|lend|loan|remit|spare)\s+(?:me|us)\b[^.!?\n]{0,30}"
    r"\b(?:money|cash|funds?|amount|\d)"
    r"|\bkindly\s+(?:send|transfer|remit)\b"
    r"|\brequest(?:ing)?\s+(?:for\s+)?(?:an?\s+)?(?:sum|amount|loan|\d)"
    r"|\b(?:need|require)\s+(?:some\s+)?(?:money|cash|financial (?:help|assistance))\b"
    r"|\bhelp me (?:out )?with\s+(?:some\s+)?(?:money|cash|[$£€₹])"
)

OFFICIAL_DISPLAY_RE = re.compile(
    r"(?i)\b(?:support|security|service|services|team|account|accounts|notification|"
    r"no-?reply|alert|admin|administrator|helpdesk|help desk|billing|customer care)\b"
)


DKIM_RE = re.compile(r"dkim=pass[^;]*?header\.i=@?([\w.-]+)", re.I)
DKIM_D_RE = re.compile(r"dkim=pass[^;]*?header\.d=([\w.-]+)", re.I)
SPF_RE = re.compile(r"spf=pass[^;]*?(?:smtp\.mailfrom|envelope-from)=@?([\w.-]+)", re.I)


def sender_is_authenticated(email, ev) -> tuple[bool, str]:
    """Did the sending domain prove it really sent this?

    DMARC-style relaxed alignment: a DKIM or SPF pass counts only when the
    signing domain shares a registrable domain with the From header. An ESP
    signing as cio113400.neon.tech for a From of neon.tech is aligned; a
    phisher signing as their own throwaway domain is not.

    This matters because the deception floors -- link text disagreeing with
    the href, brand impersonation, Reply-To divergence -- all ask "is this
    sender pretending to be someone else?". If the domain cryptographically
    proved it is itself, the answer is no, and what is left is a click
    tracker, which every legitimate marketing platform on earth uses.
    """
    from ..features.headers import registrable_domain

    auth = (getattr(email, "auth_results", "") or "")
    from_dom = ev.sender.registrable
    if not auth or not from_dom:
        return False, ""
    for rx, label in ((DKIM_RE, "DKIM"), (DKIM_D_RE, "DKIM"), (SPF_RE, "SPF")):
        for m in rx.finditer(auth):
            if registrable_domain(m.group(1).lower()) == from_dom:
                return True, f"{label} pass aligned with {from_dom}"
    return False, ""


@dataclass
class Floor:
    name: str
    minimum: float
    why: str


def _f(feats: dict[str, float], k: str) -> float:
    return feats.get(k, 0.0)


def _lex(feats: dict[str, float], name: str) -> float:
    """Total hits for a lexicon, body plus subject -- same definition the
    labelling functions use, so a threshold means the same thing in both."""
    return _f(feats, f"lex_{name}_count") + _f(feats, f"lexsubj_{name}")


# Linking to an executable is unambiguous in most organisations and routine in
# a few -- software vendors, open-source projects, IT distribution lists. It is
# the one floor here whose correctness depends on the organisation, so the
# sender domains that may legitimately do it are configurable rather than
# hard-coded.
DEFAULT_SOFTWARE_DISTRIBUTION_ALLOWLIST: frozenset[str] = frozenset()


def applicable(email: Email, feats: dict[str, float], ev: Evidence,
               software_allowlist: frozenset[str] | set[str] | None = None,
               history=None, domain_age=None) -> list[Floor]:
    """Every floor whose conditions this message meets."""
    out: list[Floor] = []
    body = (ev.body or "").lower()
    subj = (ev.subject or "").lower()
    both = f"{subj} {body}"

    # ---- payload floors: an executable in the mail stream is not ambiguous
    if _f(feats, "att_dangerous_count") > 0:
        out.append(Floor("executable_attachment", 0.95,
                         "carries an attachment that executes when opened: "
                         + ", ".join(ev.dangerous_attachments[:3])))
    if _f(feats, "att_double_extension") > 0:
        out.append(Floor("double_extension", 0.95,
                         "carries a double-extension file disguised as a document: "
                         + ", ".join(ev.double_extension[:2])))
    # An aligned DKIM/SPF pass means the domain is provably itself, which rules
    # out the whole class of impersonation floors below. Payload floors are NOT
    # gated: an authenticated sender can still be compromised and ship malware.
    authenticated, auth_note = sender_is_authenticated(email, ev)

    # Mailbox history, when a store has been built. A sender the user has
    # corresponded with for months is a different proposition from one that
    # has never appeared before, and no training corpus can express that.
    _hour = None
    if getattr(email, "date", ""):
        try:
            from email.utils import parsedate_to_datetime
            _hour = parsedate_to_datetime(email.date).hour
        except Exception:
            _hour = None
    hist = (history.signals(ev.sender.address, hour=_hour)
            if (history and ev.sender.address) else {})
    first_contact = bool(hist.get("first_contact"))
    # Reply rate is the real trust signal. Receiving mail is passive and says
    # nothing; replying repeatedly is a deliberate act an attacker cannot
    # manufacture retroactively.
    reply_rate = float(hist.get("reply_rate") or 0.0)
    established = bool(hist and not first_contact
                       and (hist.get("messages_from_domain", 0) >= 5
                            or reply_rate >= 0.05)
                       and (hist.get("days_known") or 0) >= 30)

    allow = software_allowlist if software_allowlist is not None else \
        DEFAULT_SOFTWARE_DISTRIBUTION_ALLOWLIST
    # The allowlist covers both who sent it and where the download points, since
    # a release announcement usually comes from a maintainer's own domain while
    # the binary sits on the project's.
    exempt = ev.sender.registrable in allow
    hard_links = [] if exempt else [u for u in ev.urls if u.registrable not in allow
                  and u.path.rsplit(".", 1)[-1].split("?")[0].lower() in HARD_EXECUTABLE
                  and "." in u.path]
    if hard_links:
        out.append(Floor("executable_link", 0.90,
                         f"links directly to an executable: {hard_links[0].raw[:90]}"))
    if _f(feats, "att_archive_count") > 0 and re.search(
            r"(?i)password (?:for|to|is)[^.!?\n]{0,40}(?:archive|attach|file|document|zip)"
            r"|(?:archive|attachment|file|zip)[^.!?\n]{0,30}password is", both):
        out.append(Floor("password_protected_archive", 0.90,
                         "supplies a password for an attached archive, which exists "
                         "only to stop the gateway from scanning it"))
    if _f(feats, "att_count") > 0 and any(
            t in both for t in ("enable editing", "enable content", "enable macro")):
        out.append(Floor("macro_enable_lure", 0.92,
                         "instructs the recipient to enable macros or leave protected view"))

    # ---- BEC floors: the model's blind spot, covered deterministically
    if GIFT_CARD_REQUEST_RE.search(both):
        out.append(Floor("gift_card_request", 0.88,
                         "asks for gift cards, which has effectively no legitimate "
                         "use in unsolicited business email"))
    secrecy = _f(feats, "lex_secrecy_count")
    payment = _f(feats, "lex_payment_count")
    authority = _f(feats, "lex_authority_count")
    urgency = _f(feats, "lex_urgency_count")
    if payment >= 1 and secrecy >= 1 and (authority >= 1 or urgency >= 1):
        out.append(Floor("bec_triad", 0.88,
                         "combines a payment instruction, a demand for secrecy and "
                         "executive or time pressure -- the standard BEC structure"))
    if payment >= 1 and _f(feats, "hdr_sender_freemail") and _f(feats, "hdr_display_name_present"):
        out.append(Floor("freemail_payment_request", 0.80,
                         "a named individual is requesting payment from a free "
                         "consumer mailbox rather than a corporate domain"))
    if any(t in both for t in ("bank details have changed", "change of bank",
                               "updated bank", "new account details",
                               "update my direct deposit", "direct deposit details",
                               "changed banks")) and payment >= 1:
        out.append(Floor("bank_detail_change", 0.85,
                         "announces changed bank or payroll deposit details, the "
                         "single most common payment-fraud pattern"))

    # ---- header-authentication floors -------------------------------------
    # These read Reply-To, Return-Path and Authentication-Results, which exist
    # only on live mail. NOTHING in the training corpora carries them, so their
    # false-positive rate is UNMEASURED here -- unlike every floor above, which
    # was validated against 15,103 held-out messages. Watch them on your own
    # traffic before trusting them.
    from ..features.headers import registrable_domain as _reg
    from_dom = ev.sender.registrable
    reply_dom = ""
    if getattr(email, "reply_to", ""):
        m = re.search(r"[\w.+-]+@([\w.-]+)", email.reply_to)
        if m:
            reply_dom = _reg(m.group(1).lower())
    if (reply_dom and from_dom and reply_dom != from_dom
            and not authenticated and not established and (
            payment >= 1 or _f(feats, "lex_credential_request_count") >= 1)):
        out.append(Floor("reply_to_divergence", 0.85,
                         f"replies would go to {reply_dom}, not the sending domain "
                         f"{from_dom}, on a message that asks for money or credentials"))

    auth = (getattr(email, "auth_results", "") or "").lower()
    auth_failed = [k for k in ("spf=fail", "spf=softfail", "dkim=fail", "dmarc=fail")
                   if k in auth]
    if auth_failed and (payment >= 1 or _f(feats, "lex_credential_request_count") >= 1
                        or _f(feats, "hdr_brand_display_mismatch")):
        out.append(Floor("failed_authentication_with_lure", 0.88,
                         f"sender authentication failed ({', '.join(auth_failed)}) on a "
                         f"message that asks for money, credentials or impersonates a brand"))

    rp = (getattr(email, "return_path", "") or "").lower()
    if rp and from_dom:
        m = re.search(r"[\w.+-]+@([\w.-]+)", rp)
        rp_dom = _reg(m.group(1)) if m else ""
        if rp_dom and rp_dom != from_dom and not authenticated and (
                payment >= 1 or _f(feats, "hdr_brand_display_mismatch")):
            out.append(Floor("return_path_mismatch", 0.80,
                             f"bounces route to {rp_dom} while the message claims to "
                             f"come from {from_dom}"))

    # A direct request for a specific sum, out of the blue, is the whole of
    # advance-fee fraud stripped of its narrative. Requires an actual amount and
    # no existing thread, so "can you send me the file" and ongoing invoice
    # conversations do not qualify.
    # Four conditions together, because any one alone is ordinary:
    #   a direct first-person ask, a specific sum, a short message, and a
    #   cold contact. Newsletters fail the length test, invoice threads fail
    #   the reply test, and corporate mail fails the freemail/auth test.
    if (DIRECT_MONEY_ASK_RE.search(both)
            and _f(feats, "txt_currency_mentions") >= 1
            and _f(feats, "txt_body_words") <= 150
            and not _f(feats, "txt_thread_hijack_marker")
            and not _f(feats, "txt_subject_is_reply")
            and (_f(feats, "hdr_sender_freemail") or not authenticated)):
        w = 0.85 if _f(feats, "lex_identity_claim_count") else 0.80
        out.append(Floor("unsolicited_money_request", w,
                         "a short, cold message asking outright for a specific sum "
                         "-- advance-fee fraud with the narrative stripped off"))

    # ---- mailbox-history floors -------------------------------------------
    # A stranger asking for money or credentials is the shape of nearly every
    # BEC and phishing attack. Neither half is alarming alone: strangers send
    # legitimate mail constantly, and known contacts discuss payments daily.
    if first_contact and not authenticated and (
            payment >= 1 or _f(feats, "lex_money_request_count") >= 1
            or _f(feats, "lex_credential_request_count") >= 1):
        out.append(Floor("first_contact_ask", 0.82,
                         "no prior mail from or to this domain, and the very first "
                         "message asks for money or credentials"))
    if first_contact and _f(feats, "att_count") > 0 and not authenticated:
        out.append(Floor("first_contact_attachment", 0.80,
                         "first ever message from this domain arrives with an "
                         "attachment"))

    # ---- domain age --------------------------------------------------------
    # Phishing infrastructure is disposable: domains are registered days before
    # a campaign and abandoned after. A legitimate business asking you to sign
    # in has almost always existed for years. Authentication does not help here
    # -- a brand-new domain can hold perfect DKIM.
    if domain_age is not None and ev.sender.registrable:
        fact = domain_age.lookup(ev.sender.registrable)
        if fact.known and fact.age_days < 30 and (
                payment >= 1 or _f(feats, "lex_credential_request_count") >= 1
                or _f(feats, "lex_money_request_count") >= 1 or _f(feats, "url_count") >= 1):
            out.append(Floor("brand_new_domain", 0.88,
                             f"the sending domain was registered {fact.age_days} days "
                             f"ago ({fact.registered[:10]}) and is already asking you "
                             f"to click, pay or sign in"))
        elif fact.known and fact.age_days < 180 and (
                _f(feats, "lex_credential_request_count") >= 1
                or _f(feats, "hdr_brand_display_mismatch")):
            out.append(Floor("young_domain_credential_ask", 0.80,
                             f"the sending domain is only {fact.age_days} days old and "
                             f"is requesting credentials or impersonating a brand"))

    # ---- pretext without an inspectable destination ------------------------
    # Both of these were missed entirely. The shared shape: a story that
    # demands an action, a call-to-action with nothing to inspect, and a sender
    # that has not proved who it is. Genuine couriers and genuine charities are
    # authenticated and link to their own domain; a lure that hides its
    # destination has a reason to.
    dlv = _lex(feats, "delivery_scam")
    chr_ = _lex(feats, "charity_fraud")
    no_inspectable_target = (_f(feats, "url_count") == 0
                             or _f(feats, "emb_cta_without_url") > 0)

    if dlv >= 3 and not authenticated and no_inspectable_target:
        out.append(Floor("delivery_pretext_no_link", 0.80,
                         "a failed-delivery story from an unauthenticated sender, "
                         "with no inspectable link -- a real courier authenticates "
                         "and links to its own tracking page"))
    elif dlv >= 2 and not authenticated and (
            _f(feats, "lex_payment_count") or _f(feats, "lex_money_request_count")):
        out.append(Floor("delivery_fee_request", 0.82,
                         "a delivery pretext asking for a fee, unauthenticated"))

    if chr_ >= 4 and not authenticated and (
            _f(feats, "lex_money_request_count") or _f(feats, "txt_currency_mentions")):
        out.append(Floor("unverified_charity_appeal", 0.78,
                         "a disaster or medical appeal asking for money from a "
                         "sender that has not proved who it is -- registered "
                         "charities authenticate their mail and link to their "
                         "own donation page"))

    # ---- callback phishing -------------------------------------------------
    # The defining shape: something to ring, a reason to ring it, and nothing to
    # click. Legitimate billing mail links to an account page; it does not rely
    # on the telephone, because the vendor wants you self-serving.
    if _f(feats, "tel_callback_shape") and _f(feats, "url_count") == 0:
        out.append(Floor("callback_phishing_shape", 0.88,
                         "a billing or renewal pretext with a phone number to call "
                         "and no link or attachment -- built specifically to leave "
                         "nothing for a scanner to inspect"))
    if re.search(r"(?i)\b(?:anydesk|teamviewer|ultraviewer|screenconnect|logmein)\b", both) \
            and not authenticated:
        out.append(Floor("remote_access_tool_named", 0.85,
                         "names a remote-access tool in an unauthenticated message, "
                         "which is how a support scam takes the machine"))

    # ---- a relationship that lapsed and came back ---------------------------
    # A domain that corresponded for years, went silent, and has just
    # reappeared is the shape of a re-registered domain or a freshly
    # compromised account. Every other history signal reads "known and safe",
    # which is exactly why this one is worth having.
    dormant = hist.get("dormant_days")
    if dormant and dormant >= 365 and (
            payment >= 1 or _f(feats, "lex_credential_request_count") >= 1
            or _f(feats, "lex_money_request_count") >= 1 or _f(feats, "att_count") > 0):
        out.append(Floor("dormant_sender_returns", 0.80,
                         f"no mail from this domain for {dormant} days, and the "
                         f"message that breaks the silence asks for money, "
                         f"credentials or carries an attachment"))

    if (hist.get("unusual_hour") and not authenticated
            and (payment >= 1 or _f(feats, "lex_credential_request_count") >= 1)):
        out.append(Floor("off_rhythm_send_time", 0.75,
                         "arrived at an hour this sender has never used before, "
                         "unauthenticated, asking for money or credentials"))

    # ---- fabricated conversation -------------------------------------------
    # A genuine reply quotes a genuine message, so a quoted exchange that is
    # nowhere in the mailbox looks like proof the attacker wrote it.
    #
    # It is not, on its own. Replayed against 43 real Enron mailboxes -- index
    # grown message by message in date order, exactly as deployment does it --
    # this called 23.3% of 26,694 genuine quoted replies fabricated. None of
    # them were. A mailbox holds the user's mail, not the whole thread: the
    # original sits in a folder that was never exported, or in the other
    # party's account, and absence of the original is not evidence of forgery.
    #
    # What survives is the conjunction. A thread hijack arrives from a
    # lookalike or freshly registered domain, because an attacker who already
    # held the real account would not need to fake the quote. Against someone
    # the mailbox has genuinely corresponded with, a missing original is far
    # more likely to mean an incomplete mailbox than a forgery, so the floor
    # stands down and the feature is left to argue its case in the model.
    #
    # That conjunction takes the same 26,694 replies from 23.3% to 2.0%,
    # suppressing 91.6% of the false positives while leaving the attack it was
    # written for untouched. scripts/eval_thread_verify.py reproduces both.
    if _f(feats, "thr_fabricated"):
        # Deliberately not the `established` above: that one is tuned for
        # deception floors and requires 30 days of acquaintance. Reusing the
        # name here would also rebind it for the anchor-mismatch floor below.
        thread_peer_known = (hist.get("ever_corresponded_with_domain")
                             and hist.get("messages_from_domain", 0) >= 3)
        # Until the mailbox has actually been scanned there is no evidence
        # either way, and "unknown sender" is the wrong default: it would fire
        # on every quoted reply a new user receives, which is the 23.3% case
        # again. An unscanned store answers first_contact=True for everyone.
        scanned = bool(getattr(history, "messages_scanned", 0)) if history else False
        if scanned and not thread_peer_known:
            out.append(Floor("fabricated_thread", 0.90,
                             ev.thread.note or "quotes a conversation that never happened"))

    # ---- identity asserted in the body -------------------------------------
    # The header layer cannot see this: the From line is truthful about whoever
    # actually sent the message, while the person the reader thinks they are
    # dealing with is named only in the text.
    if _f(feats, "emb_body_sender_mismatch") and (
            _f(feats, "lex_credential_request_count") >= 1
            or payment >= 1 or _f(feats, "lex_money_request_count") >= 1):
        out.append(Floor("body_sender_mismatch", 0.85,
                         ev.embedded.notes[0] if ev.embedded.notes
                         else "the body claims a different sender from the envelope"))

    # ---- identity floors
    # A two-character edit distance is meaningless on a short domain: "ups.com"
    # sits within two edits of dozens of real domains. Require a long enough
    # domain that the near-miss is genuinely improbable.
    reg = ev.sender.registrable or ""
    if (_f(feats, "hdr_domain_is_lookalike")
            and len(reg) >= 9
            and ev.sender.lookalike_distance <= (1 if len(reg) < 12 else 2)):
        out.append(Floor("lookalike_sender_domain", 0.85,
                         ev.sender.notes[-1] if ev.sender.notes
                         else "sending domain is a near-miss of a legitimate one"))
    # A brand word in a display name is not impersonation by itself -- the Ling
    # corpus contains a genuine "Apple-ISS Research Center" mailing list. Require
    # the display name to also assert an official support identity.
    #
    # Deliberately NOT gated on authentication: DKIM alignment proves the sender
    # controls the From domain, not that they are the brand they claim to be.
    # A phisher registering "microsoft-secure.help" and signing for it passes
    # alignment perfectly while impersonating Microsoft.
    if (_f(feats, "hdr_brand_display_mismatch")
            and OFFICIAL_DISPLAY_RE.search(ev.sender.display_name or "")
            and (_f(feats, "lex_credential_request_count")
                 or _f(feats, "url_has_anchor_mismatch"))):
        out.append(Floor("brand_impersonation", 0.85,
                         "impersonates a brand it does not own and directs the "
                         "recipient elsewhere"))
    if _f(feats, "url_has_anchor_mismatch") and not authenticated and not established:
        out.append(Floor("link_text_mismatch", 0.85,
                         "displays one domain in the link text while the href goes "
                         "somewhere else"))
    if _f(feats, "txt_homoglyph_chars") >= 6 or "xn--" in (ev.sender.domain or ""):
        out.append(Floor("homoglyph_or_punycode", 0.82,
                         "uses lookalike characters or punycode to imitate a real name"))

    # ---- credential-capture floors
    if any(t in both for t in ("scan the qr", "qr code", "scan the code", "[qr code")) and (
            _f(feats, "lex_credential_request_count") or _f(feats, "lex_it_support_count")):
        out.append(Floor("qr_credential_lure", 0.85,
                         "moves the victim to a QR code to defeat URL inspection, "
                         "paired with a credential or IT-support pretext"))
    if (_f(feats, "url_has_credential_path") and _f(feats, "url_has_high_risk_tld")
            and _f(feats, "lex_credential_request_count")):
        out.append(Floor("signin_page_on_abuse_tld", 0.88,
                         "hosts a sign-in page on a high-abuse top-level domain"))

    # A thread-hijack floor was tried here and removed: it fired six times on
    # held-out mail and was wrong every time, while adding nothing, because a
    # genuine hijack with a deceptive link already trips `link_text_mismatch`.
    # A redundant floor with a 100% false-positive rate is pure cost.
    return out


# A floor that fires is strong evidence of a specific vector. The vector
# classifier only knows the four classes this corpus could teach it, so without
# this map a password-protected archive gets resolved to whichever of those four
# it resembles most -- which is none of them.
FLOOR_VECTOR: dict[str, str] = {
    "executable_attachment": "malware_delivery",
    "double_extension": "malware_delivery",
    "executable_link": "malware_delivery",
    "password_protected_archive": "malware_delivery",
    "macro_enable_lure": "malware_delivery",
    "gift_card_request": "bec_payment_fraud",
    "bec_triad": "bec_payment_fraud",
    "freemail_payment_request": "bec_payment_fraud",
    "bank_detail_change": "vendor_invoice_fraud",
    "lookalike_sender_domain": "credential_phishing",
    "brand_impersonation": "credential_phishing",
    "link_text_mismatch": "credential_phishing",
    "homoglyph_or_punycode": "credential_phishing",
    "qr_credential_lure": "credential_phishing",
    "unsolicited_money_request": "advance_fee_fraud",
    "body_sender_mismatch": "credential_phishing",
    "fabricated_thread": "credential_phishing",
    "dormant_sender_returns": "bec_payment_fraud",
    "off_rhythm_send_time": "bec_payment_fraud",
    "callback_phishing_shape": "callback_phishing",
    "delivery_pretext_no_link": "delivery_scam",
    "delivery_fee_request": "delivery_scam",
    "unverified_charity_appeal": "charity_fraud",
    "brand_new_domain": "credential_phishing",
    "young_domain_credential_ask": "credential_phishing",
    "remote_access_tool_named": "tech_support_scam",
    "reply_to_divergence": "bec_payment_fraud",
    "failed_authentication_with_lure": "credential_phishing",
    "return_path_mismatch": "credential_phishing",
    "signin_page_on_abuse_tld": "credential_phishing",
}


def implied_vector(floors: list[Floor]) -> tuple[str | None, str | None]:
    """The vector implied by the highest-confidence floor that names one."""
    ranked = sorted((f for f in floors if f.name in FLOOR_VECTOR),
                    key=lambda f: -f.minimum)
    return (FLOOR_VECTOR[ranked[0].name], ranked[0].name) if ranked else (None, None)


def apply(probability: float, floors: list[Floor]) -> tuple[float, list[Floor]]:
    """Raise the probability to the highest applicable floor.

    Returns the adjusted probability and only those floors that actually
    changed it, so the report never claims a rule mattered when it did not.
    """
    if not floors:
        return probability, []
    binding = [f for f in floors if f.minimum > probability]
    if not binding:
        return probability, []
    return max(f.minimum for f in binding), binding
