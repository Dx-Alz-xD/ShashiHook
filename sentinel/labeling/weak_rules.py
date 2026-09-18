"""Weak supervision for the attack-vector taxonomy.

None of the six corpora carry a vector label -- they are binary phishing/ham.
Rather than invent labels by hand for 37,000 hostile messages, this module
applies a bank of high-precision labelling functions, each of which either
votes for one vector with a stated weight or abstains. A weighted vote decides
the training label.

The honest consequence: the vector model's ceiling is the precision of these
rules, not of human judgement. `scripts/build_gold_set.py` samples a stratified
set for human labelling so that ceiling can actually be measured.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..features.extractor import Email, Evidence
from .taxonomy import VECTOR_KEYS

# Corpus-level priors. Nigerian_Fraud.csv is 100% advance-fee by construction,
# so provenance alone is strong evidence there and nowhere else.
SOURCE_PRIOR: dict[str, tuple[str, float]] = {
    "nigerian_fraud": ("advance_fee_fraud", 2.5),
    "enron_spam": ("spam_unwanted", 0.8),
    "spamassassin": ("spam_unwanted", 0.5),
}

MACRO_TERMS = ("enable editing", "enable content", "enable macro", "protected view")
INVOICE_TERMS = ("invoice", "purchase order", "remittance", "statement of account",
                 "receipt", "billing statement", "proforma")
BANK_CHANGE_TERMS = ("bank details", "banking details", "account details",
                     "change of bank", "updated bank", "new account details",
                     "payment details have changed")
RECON_OPENERS = ("are you available", "are you at your desk", "quick favour",
                 "quick favor", "do you have a moment", "can you assist",
                 "let me know if you get this", "are you in the office",
                 "i need a favour", "i need a favor", "kindly confirm receipt")


@dataclass
class Vote:
    lf: str
    vector: str
    weight: float
    why: str


def _n(f: dict[str, float], k: str) -> float:
    return float(f.get(k, 0.0))


def _lex(f: dict[str, float], name: str) -> float:
    return _n(f, f"lex_{name}_count") + _n(f, f"lexsubj_{name}")


def apply_lfs(email: Email, f: dict[str, float], ev: Evidence) -> list[Vote]:
    """Run every labelling function. Each appends a Vote or stays silent."""
    from ..scoring.floors import sender_is_authenticated

    votes: list[Vote] = []
    # A DKIM/SPF-aligned sender is provably itself, so link-deception rules say
    # nothing about it -- every marketing platform rewrites hrefs for click
    # tracking. Without this, authenticated payment receipts were being typed
    # as credential phishing.
    authenticated, _ = sender_is_authenticated(email, ev)
    body_low = (ev.body or "").lower()
    subj_low = (ev.subject or "").lower()
    both = f"{subj_low} {body_low}"
    words = _n(f, "txt_body_words")
    n_urls = _n(f, "url_count")

    sext = _lex(f, "sextortion")
    crypto = _lex(f, "crypto")
    threat = _lex(f, "threat")
    reward = _lex(f, "reward")
    payment = _lex(f, "payment")
    authority = _lex(f, "authority")
    secrecy = _lex(f, "secrecy")
    cred = _lex(f, "credential_request")
    itsup = _lex(f, "it_support")
    lure = _lex(f, "attachment_lure")
    adult = _lex(f, "spam_adult")
    pharma = _lex(f, "spam_pharma")
    finance = _lex(f, "spam_finance")
    commercial = _lex(f, "spam_commercial")
    bulk_marker = _lex(f, "spam_bulk_marker")
    spam_total = adult + pharma + finance + commercial
    romance = _lex(f, "romance")
    urgency = _lex(f, "urgency")

    # ---------------------------------------------------------------- malware
    if _n(f, "att_dangerous_count") > 0 or _n(f, "att_double_extension") > 0:
        votes.append(Vote("lf_dangerous_attachment", "malware_delivery", 3.0,
                          "message carries an executable or double-extension attachment"))
    elif _n(f, "att_dangerous_named_in_body") > 0:
        votes.append(Vote("lf_executable_named", "malware_delivery", 1.6,
                          "body names an executable file"))
    if _n(f, "url_has_dangerous_ext") > 0:
        votes.append(Vote("lf_executable_link", "malware_delivery", 2.2,
                          "a link points straight at an executable file"))
    if any(t in both for t in MACRO_TERMS):
        votes.append(Vote("lf_macro_lure", "malware_delivery", 2.4,
                          "instructs the reader to enable macros or leave protected view"))
    if lure >= 1 and _n(f, "url_has_archive_ext") > 0:
        votes.append(Vote("lf_archive_lure", "malware_delivery", 1.4,
                          "attachment language paired with an archive download"))

    # -------------------------------------------------------------- extortion
    if sext >= 2 or (sext >= 1 and crypto >= 1):
        votes.append(Vote("lf_sextortion", "extortion", 3.0,
                          "claims compromising recordings and demands cryptocurrency"))
    elif crypto >= 1 and threat >= 1 and words < 700:
        votes.append(Vote("lf_crypto_threat", "extortion", 1.8,
                          "threat paired with a cryptocurrency payment demand"))

    # ------------------------------------------------------- advance-fee (419)
    if reward >= 2 and words > 120:
        votes.append(Vote("lf_advance_fee", "advance_fee_fraud", 2.2,
                          "long narrative promising an inheritance, prize or fund transfer"))
    # "beneficiary" and "transfer the funds" are ordinary banking words -- they
    # appeared in a legitimate-looking BEC wire request and pulled it to 419.
    # Only the narrative-specific markers belong here.
    if reward >= 1 and any(t in both for t in ("next of kin", "late husband",
                                               "deceased client", "barrister",
                                               "unclaimed estate", "my late father",
                                               "consignment box")):
        votes.append(Vote("lf_419_narrative", "advance_fee_fraud", 2.6,
                          "uses the classic 419 inheritance narrative"))
    if romance >= 2 and reward >= 1:
        votes.append(Vote("lf_romance_fraud", "advance_fee_fraud", 1.5,
                          "romance approach combined with a money request"))

    # ------------------------------------------------------- invoice / vendor
    supplier_context = any(t in both for t in INVOICE_TERMS) or any(
        t in both for t in ("supplier", "vendor", "account manager", "our records",
                            "your account with us", "contract no")
    )
    if any(t in both for t in BANK_CHANGE_TERMS) and payment >= 1:
        # A bank-detail change is vendor fraud only when it sits in a supplier
        # or invoice context. The same words inside a secretive executive
        # request are BEC, and the two demand different containment.
        if supplier_context:
            votes.append(Vote("lf_bank_change", "vendor_invoice_fraud", 2.8,
                              "announces changed bank details in a supplier or "
                              "invoice context"))
        elif secrecy == 0 and authority == 0:
            votes.append(Vote("lf_bank_change_weak", "vendor_invoice_fraud", 1.2,
                              "references changed bank or remittance details"))
    elif any(t in both for t in INVOICE_TERMS) and (lure >= 1 or _n(f, "att_count") > 0):
        votes.append(Vote("lf_invoice_attachment", "vendor_invoice_fraud", 1.6,
                          "invoice or purchase-order language with an attachment"))

    # ------------------------------------------------------------------- BEC
    if payment >= 1 and (authority >= 1 or secrecy >= 1) and n_urls <= 1 and words < 400:
        w = 2.4 if secrecy >= 1 else 1.9
        votes.append(Vote("lf_bec_payment", "bec_payment_fraud", w,
                          "short, linkless payment request carrying executive "
                          "authority or secrecy framing"))
    if "gift card" in both or "gift cards" in both:
        votes.append(Vote("lf_gift_card", "bec_payment_fraud", 2.6,
                          "asks for gift cards, a hallmark of executive impersonation"))
    if authority >= 1 and secrecy >= 1 and urgency >= 1 and n_urls == 0:
        votes.append(Vote("lf_exec_pressure", "bec_payment_fraud", 1.7,
                          "executive authority, secrecy and urgency with no link to click"))

    if any(t in both for t in ("direct deposit", "payroll", "salary account")) and any(
            t in both for t in ("changed banks", "change my bank", "update my direct deposit",
                                "new bank", "different bank", "update my account",
                                "new routing number", "new account number")):
        votes.append(Vote("lf_payroll_diversion", "bec_payment_fraud", 2.7,
                          "asks to redirect salary or direct-deposit payments to a "
                          "different account"))

    if _n(f, "att_archive_count") > 0 and "password" in both:
        votes.append(Vote("lf_password_archive", "malware_delivery", 2.5,
                          "supplies a password for an attached archive, which exists "
                          "only to stop the gateway scanning what is inside"))

    # --------------------------------------------------- credential phishing
    if cred >= 1 and n_urls >= 1:
        w = 2.6 if _n(f, "url_has_credential_path") else 1.8
        votes.append(Vote("lf_credential_link", "credential_phishing", w,
                          "asks the reader to verify credentials and supplies a link"))
    if n_urls >= 1 and not authenticated and (
            _n(f, "hdr_brand_display_mismatch") or _n(f, "url_has_brand_mismatch")):
        votes.append(Vote("lf_brand_spoof_link", "credential_phishing", 2.3,
                          "impersonates a brand it does not own and links away"))
    if itsup >= 1 and n_urls >= 1:
        votes.append(Vote("lf_it_support_link", "credential_phishing", 1.9,
                          "IT-support pretext -- quota, expiry, migration -- plus a link"))
    if any(t in both for t in ("qr code", "scan the qr", "scan the code", "[qr code")) and (
            cred >= 1 or itsup >= 1):
        # A QR code moves the victim to a URL the gateway never sees. Absence of
        # a link is the point, so the link-based rules above cannot fire.
        votes.append(Vote("lf_qr_credential_lure", "credential_phishing", 2.5,
                          "directs the reader to a QR code instead of a link, "
                          "defeating URL inspection, with a credential pretext"))

    if _n(f, "url_has_anchor_mismatch") and not authenticated:
        votes.append(Vote("lf_anchor_mismatch", "credential_phishing", 2.1,
                          "link text displays a different domain from the actual href"))

    # ------------------------------------------------- callback phishing (TOAD)
    if _n(f, "tel_callback_shape"):
        votes.append(Vote("lf_callback_shape", "callback_phishing", 3.0,
                          "a billing pretext, an instruction to call, and a phone "
                          "number -- with nothing to click, which is the point"))
    elif (_n(f, "tel_count") >= 1 and _n(f, "tel_call_to_action")
          and n_urls == 0 and _n(f, "att_count") == 0
          and (_lex(f, "threat") or _lex(f, "payment"))):
        votes.append(Vote("lf_phone_only_lure", "callback_phishing", 2.0,
                          "pushes the reader to a phone number with no link or "
                          "attachment anywhere in the message"))

    # ------------------------------------------------------- tech support scam
    tech = _lex(f, "tech_support_scam")
    if tech >= 2:
        w_ = 2.8 if _n(f, "tel_count") else 2.0
        votes.append(Vote("lf_tech_support", "tech_support_scam", w_,
                          "claims the device is infected or a security licence "
                          "has lapsed"))
    if re.search(r"(?i)\b(?:anydesk|teamviewer|ultraviewer|screenconnect|logmein)\b", both):
        votes.append(Vote("lf_remote_access_tool", "tech_support_scam", 2.6,
                          "names a remote-access tool, which is how the victim "
                          "hands over the machine"))

    # ---------------------------------------------------------- investment fraud
    inv = _lex(f, "investment_scam")
    if inv >= 2:
        votes.append(Vote("lf_investment_promise", "investment_fraud", 2.4,
                          "promises guaranteed or outsized investment returns"))
    elif inv >= 1 and crypto >= 1:
        votes.append(Vote("lf_crypto_investment", "investment_fraud", 2.2,
                          "crypto investment pitch"))

    # ------------------------------------------------------------- job scam
    job = _lex(f, "job_scam")
    if job >= 2:
        w_ = 2.6 if re.search(r"(?i)\b(?:registration|security|training|processing) fee\b", both) \
            else 2.0
        votes.append(Vote("lf_job_offer", "job_scam", w_,
                          "unsolicited job or paid-task offer"))
    if job >= 1 and re.search(r"(?i)\b(?:what ?s ?app|telegram)\b", both):
        votes.append(Vote("lf_offplatform_move", "job_scam", 2.4,
                          "pushes the conversation onto WhatsApp or Telegram, "
                          "where nothing is logged"))

    # ------------------------------------------------- government impersonation
    gov = _lex(f, "govt_impersonation")
    if gov >= 2:
        votes.append(Vote("lf_govt_impersonation", "government_impersonation", 2.5,
                          "impersonates a tax, immigration or court authority"))
    elif gov >= 1 and threat >= 1:
        votes.append(Vote("lf_govt_threat", "government_impersonation", 2.2,
                          "authority pretext paired with a threat of penalty or arrest"))

    # ----------------------------------------------------------- delivery scam
    dlv = _lex(f, "delivery_scam")
    if dlv >= 2:
        w_ = 2.5 if (payment >= 1 or n_urls >= 1) else 1.8
        votes.append(Vote("lf_delivery_hold", "delivery_scam", w_,
                          "claims a parcel is held pending a small fee"))

    # ------------------------------------------------------------ charity fraud
    if _lex(f, "charity_fraud") >= 2:
        votes.append(Vote("lf_charity_appeal", "charity_fraud", 2.0,
                          "solicits donations for a disaster or medical appeal"))

    # ------------------------------------------------------------ romance fraud
    if romance >= 2 and (reward >= 1 or payment >= 1
                         or _lex(f, "money_request") >= 1 or crypto >= 1):
        votes.append(Vote("lf_romance_money", "romance_fraud", 2.6,
                          "an emotional approach that arrives at a money request"))

    # ------------------------------------------------------------------ spam
    if adult >= 2:
        votes.append(Vote("lf_adult_spam", "spam_unwanted", 2.2,
                          "adult-content solicitation"))
    if pharma >= 2:
        votes.append(Vote("lf_pharma_spam", "spam_unwanted", 2.2,
                          "unlicensed pharmacy or diet-product solicitation"))
    if finance >= 2:
        votes.append(Vote("lf_finance_spam", "spam_unwanted", 2.0,
                          "penny-stock, loan, insurance or gambling solicitation"))
    if commercial >= 2:
        votes.append(Vote("lf_commercial_spam", "spam_unwanted", 1.9,
                          "bulk commercial content -- replica goods, OEM software, "
                          "degree mills or SEO services"))
    if spam_total == 1 and cred == 0 and payment == 0 and sext == 0:
        votes.append(Vote("lf_commercial_weak", "spam_unwanted", 0.9,
                          "single commercial solicitation term, no credential or "
                          "payment request"))
    if bulk_marker >= 1 and cred == 0 and payment == 0 and spam_total >= 1:
        votes.append(Vote("lf_bulk_footer", "spam_unwanted", 1.2,
                          "carries bulk-mail machinery -- unsubscribe link, mailing "
                          "list footer or advertisement disclaimer"))
    if romance >= 2 and reward == 0 and payment == 0:
        votes.append(Vote("lf_dating_spam", "spam_unwanted", 1.1,
                          "dating or companionship solicitation"))
    # Evasion is itself evidence: words broken up to defeat keyword filters are
    # the signature of bulk spam, not of a targeted attack.
    if (_n(f, "txt_intraword_punct_rate") > 0.12 or _n(f, "txt_spaced_letter_runs") >= 2
            or _n(f, "txt_leet_tokens") >= 4) and cred == 0 and payment == 0:
        votes.append(Vote("lf_obfuscated_bulk", "spam_unwanted", 1.3,
                          "words deliberately broken up with punctuation, spacing or "
                          "digit substitution to evade keyword filters"))

    # ----------------------------------------------------------------- recon
    # A probe is defined by the *absence* of a lure, so any meaningful lexicon
    # signal disqualifies it -- otherwise every short extortion or gift-card
    # demand would be read as reconnaissance.
    lure_signal = sum((sext, crypto, threat, reward, payment, cred, itsup,
                       lure, spam_total, romance))
    if words < 30 and n_urls == 0 and _n(f, "att_count") == 0 and lure_signal <= 1:
        w = 2.0 if any(t in both for t in RECON_OPENERS) else 1.0
        votes.append(Vote("lf_contentless_opener", "recon_probe", w,
                          "almost no content, no link and no attachment -- a probe "
                          "to confirm a live, responsive mailbox"))

    # ---------------------------------------------------------- corpus prior
    prior = SOURCE_PRIOR.get(email.source)
    if prior:
        vec, w = prior
        votes.append(Vote("lf_corpus_prior", vec, w,
                          f"provenance: the {email.source} corpus is predominantly {vec}"))
    return votes


def vote(email: Email, f: dict[str, float], ev: Evidence, is_malicious: bool
         ) -> tuple[str, float, dict[str, float], list[Vote]]:
    """Aggregate labelling functions into one vector label.

    Returns (vector, confidence, per-vector weight totals, contributing votes).
    Confidence is the winner's share of total weight scaled by its margin over
    the runner-up, so a lone weak vote never looks certain.
    """
    if not is_malicious:
        return "benign", 1.0, {"benign": 1.0}, []

    votes = apply_lfs(email, f, ev)
    if not votes:
        return "malicious_unclassified", 0.0, {}, []

    totals: dict[str, float] = {k: 0.0 for k in VECTOR_KEYS}
    for v in votes:
        totals[v.vector] += v.weight
    ranked = sorted(totals.items(), key=lambda kv: kv[1], reverse=True)
    top, top_w = ranked[0]
    second_w = ranked[1][1] if len(ranked) > 1 else 0.0
    total_w = sum(totals.values()) or 1.0

    if top_w < 1.0:
        return "malicious_unclassified", 0.0, totals, votes

    share = top_w / total_w
    margin = (top_w - second_w) / top_w
    confidence = round(min(1.0, share * (0.55 + 0.45 * margin)), 4)
    contributing = [v for v in votes if v.vector == top]
    return top, confidence, {k: v for k, v in totals.items() if v}, contributing
