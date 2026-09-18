"""Structural, stylistic and obfuscation features of the message body.

These carry the signals that survive translation and template churn: shouting,
hidden text, mixed-script characters, and the shape of a hijacked thread.
"""
from __future__ import annotations

import re
import unicodedata

ZERO_WIDTH = "​‌‍‎‏﻿⁠᠎"
ZERO_WIDTH_RE = re.compile(f"[{ZERO_WIDTH}]")
HTML_TAG_RE = re.compile(r"<[^>]+>")
HIDDEN_STYLE_RE = re.compile(
    r"(?i)(?:font-size\s*:\s*0(?:\.0*)?(?:px|pt|em)?\b|display\s*:\s*none|"
    r"visibility\s*:\s*hidden|opacity\s*:\s*0(?:\.0*)?\b|"
    r"color\s*:\s*#?(?:fff(?:fff)?|white)\b)"
)
THREAD_MARKER_RE = re.compile(
    r"(?im)^\s*(?:-{2,}\s*original message\s*-{2,}|on .{0,60}wrote:|"
    r"from:.*\n(?:sent|date):|>{1,}\s)"
)
REPLY_SUBJECT_RE = re.compile(r"(?i)^\s*(?:re|fw|fwd)\s*:")
LEET_RE = re.compile(r"(?i)\b[a-z]*[0134578@$]{1,}[a-z]+\b")
REPEAT_RUN_RE = re.compile(r"(.)\1{3,}")
# Spam evasion: punctuation inserted inside a word ("cia'lis", "or-der"), and
# words broken into single characters ("b u y n o w"). Both defeat naive
# keyword filters while staying readable to a human, which makes their presence
# itself a strong signal.
INTRAWORD_PUNCT_RE = re.compile(r"(?i)\b[a-z]{1,}[\'\-\.\|_]+[a-z]{1,}\b")
SPACED_LETTERS_RE = re.compile(r"(?i)(?:\b[a-z]\s){3,}[a-z]\b")
# Amounts are written both ways in the wild: "$50,000" and "50000$". The
# suffix form was missing, so a scam asking for "50000$" registered no sum at all.
CURRENCY_RE = re.compile(
    r"(?i)(?:[$£€₹]\s?[\d,]+(?:\.\d+)?(?:\s?(?:k|m|million|billion|bn))?|"
    r"\b[\d,]+(?:\.\d+)?\s?[$£€₹]|"
    r"\b\d[\d,]*(?:\.\d+)?\s?(?:usd|eur|gbp|inr|dollars|pounds|euros|rupees)\b)"
)
# Latin-looking characters borrowed from other scripts.
CONFUSABLE_SCRIPTS = ("CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE")


def strip_html(s: str) -> str:
    return HTML_TAG_RE.sub(" ", s)


def homoglyph_count(s: str) -> int:
    """Characters from a non-Latin script sitting inside otherwise-Latin text."""
    n = 0
    for ch in s:
        if ch.isascii() or not ch.isalpha():
            continue
        try:
            name = unicodedata.name(ch)
        except ValueError:
            continue
        if any(name.startswith(sc) for sc in CONFUSABLE_SCRIPTS):
            n += 1
    return n


def _letter_counts(s: str) -> tuple[int, int]:
    """(letters, uppercase letters) in a single pass.

    Replaces materialising a per-character list and then walking it a second
    time to count capitals -- on a 1.6 kB body that was two full Python-level
    loops and a throwaway list per message.
    """
    n = up = 0
    for c in s:
        if c.isalpha():
            n += 1
            if c.isupper():
                up += 1
    return n, up


def text_features(subject: str, body: str) -> dict[str, float]:
    subject = subject or ""
    body = body or ""
    has_html = bool(HTML_TAG_RE.search(body))
    visible = strip_html(body) if has_html else body

    n_letters, n_upper = _letter_counts(visible)
    n_subj_letters, n_subj_upper = _letter_counts(subject)
    words = visible.split()
    n_words = len(words) or 1

    # Zero-width characters, homoglyphs and the non-ASCII ratio are all zero by
    # definition when the text is pure ASCII, and str.isascii() settles that in
    # one C-level scan. Ordinary business mail takes this path, which skips
    # three character-by-character walks -- one of which calls
    # unicodedata.name() per character.
    body_ascii = body.isascii()
    visible_ascii = visible.isascii()
    subject_ascii = subject.isascii()

    link_chars = sum(len(m) for m in re.findall(r"https?://\S+", body))

    return {
        "txt_subject_len": float(len(subject)),
        "txt_subject_words": float(len(subject.split())),
        "txt_subject_upper_ratio": (
            n_subj_upper / n_subj_letters if n_subj_letters else 0.0
        ),
        "txt_subject_is_reply": float(bool(REPLY_SUBJECT_RE.match(subject))),
        "txt_subject_exclaim": float(subject.count("!")),
        "txt_subject_empty": float(not subject.strip()),
        "txt_body_len": float(len(visible)),
        "txt_body_words": float(len(words)),
        "txt_body_upper_ratio": (
            n_upper / n_letters if n_letters else 0.0
        ),
        "txt_body_exclaim_rate": float(visible.count("!") / n_words),
        "txt_body_question_rate": float(visible.count("?") / n_words),
        "txt_has_html": float(has_html),
        "txt_html_hidden_style": float(bool(HIDDEN_STYLE_RE.search(body))) if has_html else 0.0,
        "txt_html_tag_ratio": float(len(HTML_TAG_RE.findall(body)) / n_words) if has_html else 0.0,
        "txt_zero_width_chars": (
            0.0 if body_ascii else float(len(ZERO_WIDTH_RE.findall(body)))
        ),
        "txt_homoglyph_chars": (
            0.0 if (subject_ascii and visible_ascii)
            else float(homoglyph_count(subject + " " + visible))
        ),
        "txt_non_ascii_ratio": (
            0.0 if visible_ascii
            else sum(not c.isascii() for c in visible) / len(visible)
        ),
        "txt_link_char_ratio": float(link_chars / max(len(body), 1)),
        "txt_thread_hijack_marker": float(bool(THREAD_MARKER_RE.search(body))),
        "txt_leet_tokens": float(len(LEET_RE.findall(visible))),
        "txt_intraword_punct_rate": float(len(INTRAWORD_PUNCT_RE.findall(visible)) / n_words),
        "txt_spaced_letter_runs": float(len(SPACED_LETTERS_RE.findall(visible))),
        "txt_repeat_char_runs": float(len(REPEAT_RUN_RE.findall(visible))),
        "txt_currency_mentions": float(len(CURRENCY_RE.findall(visible))),
        "txt_all_caps_words": float(
            sum(1 for w in words if len(w) > 3 and w.isupper())
        ),
        "txt_mean_word_len": float(sum(len(w) for w in words) / n_words),
        "txt_unique_word_ratio": float(len({w.lower() for w in words}) / n_words),
    }


TEXT_FEATURE_NAMES = tuple(text_features("", "").keys())
