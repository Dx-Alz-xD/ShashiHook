"""Turn SHAP attributions into sentences an analyst can act on.

The rule this module follows: never assert a signal without quoting the thing
that produced it. "Urgency language detected" is a claim; "urgency language --
'within 24 hours', 'URGENT' -- contributed +0.93 log-odds" is evidence. Every
phrase, URL and sender fact printed here was captured during the same
extraction that produced the score, so the narrative and the number cannot
drift apart.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..features.extractor import Evidence
from ..features.lexicons import LEXICON_NAMES
from .shap_explainer import Attribution, ExplanationBundle

# Human names for each lexicon, used in prose.
LEXICON_LABEL = {
    "urgency": "time pressure",
    "authority": "appeal to authority",
    "credential_request": "request for credentials",
    "payment": "payment or banking instruction",
    "secrecy": "demand for secrecy",
    "threat": "threat of loss or consequence",
    "reward": "promise of money or a prize",
    "sextortion": "sextortion claim",
    "crypto": "cryptocurrency payment demand",
    "it_support": "IT-support pretext",
    "attachment_lure": "instruction to open an attachment",
    "spam_adult": "adult-content solicitation",
    "spam_pharma": "pharmacy or diet-product solicitation",
    "spam_finance": "stock, loan or gambling solicitation",
    "spam_commercial": "bulk commercial solicitation",
    "spam_bulk_marker": "bulk-mail machinery",
    "romance": "romance or companionship approach",
    "money_request": "direct request for money",
    "identity_claim": "claim to be a specific person or authority",
    "job_scam": "unsolicited job or paid-task offer",
    "investment_scam": "investment or trading pitch",
    "tech_support_scam": "claim that the device is infected or unprotected",
    "delivery_scam": "parcel-delivery pretext",
    "govt_impersonation": "tax, immigration or court authority pretext",
    "charity_fraud": "donation appeal",
    "impersonated_brand": "reference to a commonly impersonated brand",
}

# Plain-language descriptions for the non-lexicon features.
FEATURE_LABEL: dict[str, str] = {
    "hdr_sender_present": "presence of a sender address",
    "hdr_display_name_present": "presence of a display name",
    "hdr_brand_display_mismatch": "display name claiming a brand the sending domain does not own",
    "hdr_domain_is_lookalike": "sending domain within a keystroke or two of a real one",
    "hdr_sender_freemail": "sent from a free consumer mail provider",
    "hdr_sender_tld_high_risk": "sending domain on a high-abuse top-level domain",
    "hdr_sender_domain_digits": "digits embedded in the sending domain",
    "hdr_sender_domain_len": "length of the sending domain",
    "hdr_sender_subdomain_depth": "depth of subdomains on the sending host",
    "hdr_sender_local_entropy": "randomness of the mailbox name before the @",
    "hdr_sender_local_len": "length of the mailbox name",
    "hdr_sender_local_digit_ratio": "proportion of digits in the mailbox name",
    "hdr_recipient_count": "number of named recipients",
    "hdr_recipient_missing": "absence of any named recipient",
    "hdr_recipient_undisclosed": "recipients hidden behind an undisclosed-recipients header",
    "hdr_same_domain_as_recipient": "sender and recipient sharing a domain",
    "hdr_date_missing": "missing date header",
    "emb_body_sender_count": "a sender identity stated inside the body",
    "emb_body_sender_mismatch": "a body sender that contradicts the actual sender",
    "emb_bracket_cta": "a call to action with no visible destination",
    "emb_cta_without_url": "a call to action in a message containing no links at all",
    "tel_count": "phone numbers in the message",
    "tel_toll_free": "a toll-free number, rentable anonymously for a campaign",
    "tel_international": "an international phone number",
    "tel_call_to_action": "an instruction to telephone the sender",
    "tel_billing_pretext": "a billing, renewal or refund pretext",
    "tel_callback_shape": "the callback-phishing shape: a number to ring, a reason "
                          "to ring it, and nothing to click",
    "url_count": "number of links",
    "url_unique_domains": "number of distinct link domains",
    "url_has_ip_literal": "a link pointing at a bare IP address",
    "url_has_shortener": "a shortened link hiding its destination",
    "url_has_punycode": "punycode in a hostname, which can render as a lookalike",
    "url_has_userinfo": "credentials embedded before the hostname in a link",
    "url_has_credential_path": "a link path aimed at a sign-in or verification page",
    "url_has_high_risk_tld": "a link on a high-abuse top-level domain",
    "url_has_brand_mismatch": "a brand name in the link that does not match where it resolves",
    "url_has_anchor_mismatch": "link text displaying a different domain from the real href",
    "url_has_dangerous_ext": "a link straight to an executable file",
    "url_has_archive_ext": "a link to an archive file",
    "url_has_hex_encoding": "heavy percent-encoding obscuring a link's path",
    "url_deep_subdomain": "the real domain buried under many subdomain levels",
    "url_max_len": "length of the longest link",
    "url_mean_len": "average link length",
    "url_https_ratio": "proportion of links using HTTPS",
    "url_flag_density": "number of suspicious traits per link",
    "url_legit_domain_ratio": "proportion of links going to known-legitimate domains",
    "txt_subject_len": "subject length",
    "txt_subject_words": "number of words in the subject",
    "txt_subject_upper_ratio": "proportion of the subject in capitals",
    "txt_subject_is_reply": "subject formatted as a reply or forward",
    "txt_subject_exclaim": "exclamation marks in the subject",
    "txt_subject_empty": "an empty subject",
    "txt_body_len": "body length",
    "txt_body_words": "number of words in the body",
    "txt_body_upper_ratio": "proportion of the body in capitals",
    "txt_body_exclaim_rate": "exclamation marks per word",
    "txt_body_question_rate": "question marks per word",
    "txt_has_html": "HTML formatting",
    "txt_html_hidden_style": "text hidden by CSS -- zero font size, transparency or display:none",
    "txt_html_tag_ratio": "density of HTML tags",
    "txt_zero_width_chars": "invisible zero-width characters inserted into the text",
    "txt_homoglyph_chars": "letters borrowed from another alphabet that look Latin",
    "txt_non_ascii_ratio": "proportion of non-ASCII characters",
    "txt_link_char_ratio": "proportion of the message that is link text",
    "txt_thread_hijack_marker": "quoted material suggesting an existing thread",
    "txt_leet_tokens": "digit-for-letter substitutions",
    "txt_intraword_punct_rate": "punctuation inserted inside words to break up keywords",
    "txt_spaced_letter_runs": "words spelled out letter by letter to evade filters",
    "txt_repeat_char_runs": "runs of repeated characters",
    "txt_currency_mentions": "explicit sums of money",
    "txt_all_caps_words": "words written entirely in capitals",
    "txt_mean_word_len": "average word length",
    "txt_unique_word_ratio": "vocabulary variety",
    "att_count": "number of attachments",
    "att_dangerous_count": "attachments that execute on open",
    "att_archive_count": "archive attachments",
    "att_double_extension": "a double file extension disguising an executable",
    "att_dangerous_named_in_body": "executable filenames named in the body",
    "att_any_named_in_body": "filenames named in the body",
}


# Features that name a concrete, checkable property of the message. An analyst
# can act on these directly. Everything else -- lengths, ratios, vocabulary
# variety -- is a real statistical signal the model uses, but it is not an
# indicator anyone can hunt on, and conflating the two makes a report look
# authoritative about things it should not be.
DIRECT_INDICATORS: frozenset[str] = frozenset({
    "hdr_brand_display_mismatch", "hdr_domain_is_lookalike", "hdr_sender_freemail",
    "hdr_sender_tld_high_risk", "hdr_recipient_undisclosed", "hdr_recipient_missing",
    "hdr_same_domain_as_recipient", "hdr_date_missing",
    "url_has_ip_literal", "url_has_shortener", "url_has_punycode", "url_has_userinfo",
    "url_has_credential_path", "url_has_high_risk_tld", "url_has_brand_mismatch",
    "url_has_anchor_mismatch", "url_has_dangerous_ext", "url_has_archive_ext",
    "url_has_hex_encoding", "url_deep_subdomain",
    "txt_html_hidden_style", "txt_zero_width_chars", "txt_homoglyph_chars",
    "txt_thread_hijack_marker", "txt_spaced_letter_runs", "txt_subject_is_reply",
    "emb_body_sender_mismatch", "emb_bracket_cta", "emb_cta_without_url",
    "tel_count", "tel_toll_free", "tel_international", "tel_call_to_action",
    "tel_billing_pretext", "tel_callback_shape",
    "att_count", "att_dangerous_count", "att_archive_count", "att_double_extension",
    "att_dangerous_named_in_body",
})


def is_direct(feature: str) -> bool:
    return feature in DIRECT_INDICATORS or _lexicon_of(feature) is not None


@dataclass
class Finding:
    """One line of the 'why' -- a claim with its evidence and its weight."""
    headline: str
    detail: str
    contribution: float
    feature: str
    quotes: list[str]
    direct: bool = True

    @property
    def kind(self) -> str:
        return "indicator" if self.direct else "statistical"

    def as_text(self) -> str:
        sign = "+" if self.contribution > 0 else ""
        out = f"{self.headline} ({sign}{self.contribution:.2f})"
        if self.detail:
            out += f"\n      {self.detail}"
        for q in self.quotes:
            out += f'\n      > "{q}"'
        return out


def _lexicon_of(feature: str) -> str | None:
    for name in LEXICON_NAMES:
        if feature in (f"lex_{name}_count", f"lex_{name}_rate", f"lexsubj_{name}"):
            return name
    return None


def describe(attr: Attribution, ev: Evidence,
             feats: dict[str, float] | None = None) -> Finding:
    """Render one attribution as a claim backed by what was actually found."""
    f, v = attr.feature, attr.value
    quotes: list[str] = []

    lex = _lexicon_of(f)
    if lex:
        label = LEXICON_LABEL.get(lex, lex)
        where = "the subject" if f.startswith("lexsubj_") else "the body"
        if v == 0:
            # SHAP can credit the *absence* of a signal. Saying "urgency in the
            # body raised the score" when there is none inverts the meaning, so
            # absence is stated as absence.
            return Finding(f"No {label} found in {where}",
                           "the model treats its absence as evidence here",
                           attr.shap, f, [], True)
        if f.endswith("_rate"):
            headline = f"Density of {label} in {where}"
            n_hits = int((feats or {}).get(f.replace("_rate", "_count"), 0))
            n_words = int((feats or {}).get("txt_body_words", 0))
            detail = (f"{n_hits} match{'es' if n_hits != 1 else ''} in {n_words} words"
                      if n_words else f"{v:.0f} matches per 1,000 words")
        else:
            headline = f"{label.capitalize()} in {where}".replace("  ", " ")
            detail = f"{int(v)} match{'es' if v != 1 else ''}"
        quotes = ev.quote_for(lex, limit=2)
        return Finding(headline[0].upper() + headline[1:], detail, attr.shap, f,
                       quotes, True)

    label = FEATURE_LABEL.get(f, f)
    detail = ""

    if f.startswith("hdr_"):
        if ev.sender.notes and f in ("hdr_brand_display_mismatch", "hdr_domain_is_lookalike",
                                     "hdr_sender_tld_high_risk") and v:
            detail = "; ".join(ev.sender.notes)
        elif ev.sender.address:
            detail = f"sender: {ev.sender.address}"
    elif f.startswith("url_"):
        # Only cite link flags for the boolean flag features. Saying "4
        # suspicious link traits found" next to "average link length" would
        # attach evidence to a signal that had nothing to do with it.
        if f in DIRECT_INDICATORS and v:
            key = f.replace("url_has_", "").replace("_", " ")
            matching = [fl for u in ev.urls for fl in u.flags]
            detail = matching[0] if matching else f"link trait present: {key}"
            quotes = [u.raw[:110] for u in ev.urls if u.flags][:2]
        else:
            detail = f"observed value: {v:g}"
            if ev.urls:
                quotes = [u.raw[:110] for u in ev.urls[:1]]
    elif f.startswith("emb_"):
        detail = "; ".join(ev.embedded.notes) or f"observed value: {v:g}"
        quotes = ev.embedded.claimed_addresses[:2] or ev.embedded.bracket_ctas[:2]
    elif f.startswith("tel_"):
        if v and ev.phones:
            detail = "; ".join(fl for p_ in ev.phones for fl in p_.flags) or \
                     f"{len(ev.phones)} number(s) found"
            quotes = [p_.raw for p_ in ev.phones[:2]]
        else:
            detail = f"observed value: {v:g}"
    elif f.startswith("att_"):
        if ev.dangerous_attachments:
            detail = "files: " + ", ".join(ev.dangerous_attachments[:3])
        elif ev.attachments:
            detail = "files: " + ", ".join(ev.attachments[:3])

    if not detail:
        detail = f"observed value: {v:g}"

    verb = "raised" if attr.shap > 0 else "lowered"
    if v == 0 and (f in DIRECT_INDICATORS or f.startswith(("att_", "url_has_", "hdr_"))):
        headline = f"Absence of {label} {verb} the score"
        detail = "the model treats its absence as evidence here"
    else:
        headline = f"{label[0].upper() + label[1:]} {verb} the score"
    return Finding(headline, detail, attr.shap, f, quotes, is_direct(f))


def build_findings(bundle: ExplanationBundle, ev: Evidence,
                   feats: dict[str, float] | None = None,
                   n_up: int = 9, n_down: int = 4) -> tuple[list[Finding], list[Finding]]:
    """Direct indicators first, then incidental statistics, each still carrying
    its true SHAP value. Reordering the presentation does not alter the
    attribution -- the numbers are unchanged and still sum correctly."""
    up_all = [describe(a, ev, feats) for a in bundle.positive(n_up * 2)]
    down_all = [describe(a, ev, feats) for a in bundle.negative(n_down * 2)]
    up = sorted(up_all, key=lambda f: (not f.direct, -abs(f.contribution)))[:n_up]
    down = sorted(down_all, key=lambda f: (not f.direct, -abs(f.contribution)))[:n_down]
    return up, down


def wording_sentence(bundle: ExplanationBundle) -> str:
    """One sentence summarising what the wording view keyed on."""
    if not bundle.top_tokens_up:
        return "The wording model found nothing notable."
    toks = [t.token.strip() for t in bundle.top_tokens_up if len(t.token.strip()) > 2][:8]
    seen, uniq = set(), []
    for t in toks:
        if t.lower() in seen:
            continue
        seen.add(t.lower())
        uniq.append(t)
    return ("Phrasing most associated with hostile mail in the training corpus: "
            + ", ".join(f'"{t}"' for t in uniq[:6]) + ".")


def counterfactual_sentences(bundle: ExplanationBundle) -> list[str]:
    """What the verdict would have been without each of the top signals."""
    out: list[str] = []
    actual = bundle.counterfactuals.get("__actual__")
    if actual is None:
        return out
    for feat, p in bundle.counterfactuals.items():
        if feat == "__actual__":
            continue
        delta = actual - p
        if abs(delta) < 0.005:
            continue
        if feat == "__wording__":
            out.append(f"Ignoring the wording entirely and judging on structure alone, "
                       f"confidence would be {p:.1%} instead of {actual:.1%}.")
        else:
            label = FEATURE_LABEL.get(feat, feat)
            out.append(f"Remove {label} and confidence falls to {p:.1%} "
                       f"(a drop of {delta*100:.1f} points).")
    return out
