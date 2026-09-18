"""Canonical email record and the single feature-extraction entry point.

One call produces both halves of what the system needs: a fixed-order numeric
vector for the models, and an evidence bundle holding the spans, URLs and
sender facts that justify every non-zero value in that vector. Explanations are
built from the same extraction that produced the score, never re-derived.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from . import lexicons as lx
from .brands import ARCHIVE_EXTENSIONS, DANGEROUS_EXTENSIONS
from .embedded import (EMBEDDED_FEATURE_NAMES, EmbeddedIdentity, analyse as analyse_embedded,
                       embedded_features)
from .headers import HEADER_FEATURE_NAMES, SenderProfile, header_features, parse_sender
from .phones import PHONE_FEATURE_NAMES, PhoneFact, extract_phones, phone_features
from ..enrich.urlmodel import UrlOpinion
from ..threads import THREAD_FEATURE_NAMES, ThreadIndex, ThreadVerdict
from ..threads import thread_features, verify as verify_thread
from .text import TEXT_FEATURE_NAMES, strip_html, text_features
from .urls import URL_FEATURE_NAMES, UrlFact, extract_urls, url_features

# ".com" is both a DOS executable and the commonest TLD. Scanning free text for
# filenames therefore uses the extension set minus "com"; a real MIME part is
# matched on its full filename, where the ambiguity does not arise.
_BODY_EXTENSIONS = sorted((DANGEROUS_EXTENSIONS | ARCHIVE_EXTENSIONS) - {"com"})
FILENAME_RE = re.compile(
    r"(?i)(?<![\w.@/])[\w\-]{1,50}(?:\.[\w\-]{1,8}){0,2}\.("
    + "|".join(_BODY_EXTENSIONS)
    + r")\b(?![\w.-])"
)
DOUBLE_EXT_RE = re.compile(
    r"(?i)(?<![\w.@/])[\w\-]{1,50}\.(?:pdf|doc|docx|xls|xlsx|jpg|jpeg|png|txt|rtf)\."
    r"(" + "|".join(sorted(DANGEROUS_EXTENSIONS)) + r")\b(?![\w.-])"
)


@dataclass
class Email:
    """Provider-agnostic email record. Every ingest adapter produces one."""
    subject: str = ""
    body: str = ""
    sender: str = ""
    receiver: str = ""
    date: str = ""
    html: str | None = None
    attachments: list[str] = field(default_factory=list)
    message_id: str = ""
    source: str = "unknown"
    # Present only for live mail. The training CSVs carry none of these, so no
    # model feature depends on them -- they are consumed by the deterministic
    # floor layer, where a rule can use a signal the model never saw.
    reply_to: str = ""
    return_path: str = ""
    auth_results: str = ""
    in_reply_to: str = ""
    references: str = ""
    # The parsed MIME message, when the source had one. Attachment bytes are
    # only reachable from here, and only live mail has them.
    raw_message: object | None = None

    @property
    def uid(self) -> str:
        h = hashlib.sha256()
        h.update((self.subject or "").encode("utf-8", "ignore"))
        h.update(b"\x00")
        h.update((self.body or "")[:20000].encode("utf-8", "ignore"))
        return h.hexdigest()[:16]

    @property
    def full_text(self) -> str:
        return f"{self.subject}\n\n{strip_html(self.body) if self.html or '<' in self.body else self.body}"


@dataclass
class Evidence:
    """Everything needed to explain a score, captured during extraction."""
    sender: SenderProfile
    urls: list[UrlFact]
    phones: list[PhoneFact]
    embedded: EmbeddedIdentity
    thread: ThreadVerdict
    url_opinion: UrlOpinion
    hits: list[lx.Hit]
    attachments: list[str]
    dangerous_attachments: list[str]
    double_extension: list[str]
    subject: str
    body: str

    def hits_for(self, lexicon: str) -> list[lx.Hit]:
        return [h for h in self.hits if h.lexicon == lexicon]

    def quote_for(self, lexicon: str, limit: int = 2) -> list[str]:
        out, seen = [], set()
        for h in self.hits_for(lexicon):
            text = self.subject if h.field == "subject" else self.body
            q = h.quote(text)
            key = q.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(q)
            if len(out) >= limit:
                break
        return out


def _attachment_features(email: Email, body_text: str) -> tuple[dict[str, float], list[str], list[str]]:
    names = list(email.attachments)
    # In corpora without real attachments, filenames named in the body are the
    # only available signal. Flagged separately so the model can weigh them
    # differently from a genuine MIME part.
    mentioned = [m.group(0) for m in FILENAME_RE.finditer(body_text)]
    doubles = list(dict.fromkeys(
        m.group(0) for m in DOUBLE_EXT_RE.finditer(body_text + " " + " ".join(names))
    ))

    def ext(n: str) -> str:
        return n.rsplit(".", 1)[-1].lower() if "." in n else ""

    dangerous = [n for n in names if ext(n) in DANGEROUS_EXTENSIONS]
    archives = [n for n in names if ext(n) in ARCHIVE_EXTENSIONS]
    dangerous_mentioned = [n for n in mentioned if ext(n) in DANGEROUS_EXTENSIONS]
    seen: set[str] = set()
    evidence_names = [n for n in dangerous + dangerous_mentioned
                      if not (n.lower() in seen or seen.add(n.lower()))]

    feats = {
        "att_count": float(len(names)),
        "att_dangerous_count": float(len(dangerous)),
        "att_archive_count": float(len(archives)),
        "att_double_extension": float(len(doubles)),
        "att_dangerous_named_in_body": float(len(dangerous_mentioned)),
        "att_any_named_in_body": float(len(mentioned)),
    }
    return feats, evidence_names, doubles


ATTACHMENT_FEATURE_NAMES = ("att_count", "att_dangerous_count", "att_archive_count",
                            "att_double_extension", "att_dangerous_named_in_body",
                            "att_any_named_in_body")

LEXICON_FEATURE_NAMES = tuple(
    f"lex_{n}_{suffix}" for n in lx.LEXICON_NAMES for suffix in ("count", "rate")
) + tuple(f"lexsubj_{n}" for n in lx.LEXICON_NAMES)

# Fixed feature order. The models, the SHAP explainer and the narrative layer
# all index against this one tuple.
FEATURE_NAMES: tuple[str, ...] = (
    HEADER_FEATURE_NAMES
    + URL_FEATURE_NAMES
    + PHONE_FEATURE_NAMES
    + EMBEDDED_FEATURE_NAMES
    + THREAD_FEATURE_NAMES
    + TEXT_FEATURE_NAMES
    + ATTACHMENT_FEATURE_NAMES
    + LEXICON_FEATURE_NAMES
)
N_FEATURES = len(FEATURE_NAMES)
FEATURE_INDEX = {n: i for i, n in enumerate(FEATURE_NAMES)}


# Loaded once. Absent index = every thread verdict is "indeterminate", which is
# exactly what should happen when there is nothing to check against.
_THREAD_INDEX: ThreadIndex | None = None


def thread_index() -> ThreadIndex:
    global _THREAD_INDEX
    if _THREAD_INDEX is None:
        _THREAD_INDEX = ThreadIndex.load()
    return _THREAD_INDEX


def set_thread_index(ix: ThreadIndex) -> None:
    """Override the index. Training MUST call this with an empty index.

    Corpus messages came from other people's mailboxes. Checking their quoted
    threads against this user's index would mark every legitimate reply in the
    corpus as fabricated, and the model would learn that quoting a real
    conversation is evidence of fraud -- precisely backwards. An empty index
    makes every verdict "indeterminate", which is the truth: there is nothing
    to check those messages against.
    """
    global _THREAD_INDEX
    _THREAD_INDEX = ix


def extract(email: Email) -> tuple[dict[str, float], Evidence]:
    """Extract features and the evidence that justifies them."""
    body_raw = email.body or ""
    html = email.html if email.html is not None else (body_raw if "<" in body_raw and ">" in body_raw else None)
    body_text = strip_html(body_raw) if html else body_raw
    subject = email.subject or ""

    sender = parse_sender(email.sender)
    urls = extract_urls(body_text, html)
    phones = extract_phones(f"{subject}\n{body_text}")
    embedded = analyse_embedded(body_text, sender.address)
    thread = verify_thread(email, thread_index())

    hits = lx.scan(body_text, "body") + lx.scan(subject, "subject")

    feats: dict[str, float] = {}
    feats.update(header_features(email.sender, email.receiver, email.date, profile=sender))
    feats.update(url_features(urls))
    feats.update(phone_features(f"{subject}\n{body_text}", phones))
    feats.update(embedded_features(embedded, len(urls)))
    feats.update(thread_features(thread))

    feats.update(text_features(subject, body_raw))

    att_feats, dangerous, doubles = _attachment_features(email, body_text)
    feats.update(att_feats)

    n_words = max(len(body_text.split()), 1)
    body_counts = lx.counts([h for h in hits if h.field == "body"])
    subj_counts = lx.counts([h for h in hits if h.field == "subject"])
    # Emitted in exactly the order LEXICON_FEATURE_NAMES declares: all body
    # count/rate pairs, then all subject counts. to_vector indexes by name so
    # the model is unaffected either way, but a dict whose order silently
    # disagrees with FEATURE_NAMES is a trap for anything that zips the two.
    for name in lx.LEXICON_NAMES:
        feats[f"lex_{name}_count"] = float(body_counts[name])
        feats[f"lex_{name}_rate"] = float(body_counts[name]) * 1000.0 / n_words
    for name in lx.LEXICON_NAMES:
        feats[f"lexsubj_{name}"] = float(subj_counts[name])

    ev = Evidence(
        sender=sender,
        urls=urls,
        phones=phones,
        embedded=embedded,
        thread=thread,
        url_opinion=UrlOpinion(),
        hits=hits,
        attachments=list(email.attachments),
        dangerous_attachments=dangerous,
        double_extension=doubles,
        subject=subject,
        body=body_text,
    )
    return feats, ev


def to_vector(feats: dict[str, float]) -> list[float]:
    return [float(feats.get(n, 0.0)) for n in FEATURE_NAMES]
