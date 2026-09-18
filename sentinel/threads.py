"""Verify that a quoted conversation actually happened.

Thread hijacking works because the message quotes a real-looking exchange --
"On Thu 18 Sep, Legal wrote: > Thanks Tom, we'll revert". Every detector treats
a quoted thread as evidence of an established relationship, including this one:
`txt_thread_hijack_marker` has been a feature since the beginning and has never
once checked whether the quoted thread exists.

It is checkable. The mailbox is right there. Either that exchange is in it or
the attacker wrote it.

A fabricated quote looks like proof of fraud, because a genuine reply quotes a
genuine message. Measured, it is not. Replayed against 43 real Enron mailboxes,
growing each index message by message in date order, this called 23.3% of
26,694 genuine quoted replies fabricated -- every one of them wrong. A mailbox
holds the user's mail, not the whole thread, and the original is routinely in a
folder that was never exported or in the other party's account.

So absence is not evidence here, and the floor in scoring/floors.py no longer
treats it as though it were: it fires only when the sender is not an established
correspondent, which is 2.0% instead of 23.3%. The remaining surface is a reply
to mail sent from a device that never synced, a forwarded chain from outside the
mailbox, or an index built over too narrow a window; each is handled below.

The index stores hashes and short fingerprints, never message bodies.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .config import ARTIFACTS

INDEX_PATH = ARTIFACTS / "thread_index.json"

# "On <date>, <name> wrote:" / "-----Original Message-----" / pasted header block
QUOTE_INTRO_RE = re.compile(
    r"(?im)^\s*(?:on\s+.{4,80}?\s+wrote\s*:"
    r"|-{2,}\s*original message\s*-{2,}"
    r"|-{2,}\s*forwarded message\s*-{2,}"
    r"|\s*from\s*:\s*.{3,80}\n\s*(?:sent|date)\s*:)",
)
QUOTED_LINE_RE = re.compile(r"(?m)^\s*>+\s?(.*)$")
MSGID_RE = re.compile(r"<([^<>@\s]+@[^<>\s]+)>")
TOKEN_RE = re.compile(r"[a-z0-9']+")


def shingles(text: str, k: int = 5, limit: int = 400) -> set[str]:
    """Hashed word k-shingles. Short hashes, so the index holds no readable
    text -- it can confirm a quote matches without storing what was said."""
    toks = TOKEN_RE.findall((text or "").lower())
    out = set()
    for i in range(min(len(toks) - k + 1, limit)):
        h = hashlib.blake2b(" ".join(toks[i:i + k]).encode(), digest_size=6)
        out.add(h.hexdigest())
    return out


@dataclass
class ThreadIndex:
    """message-id -> minimal record, plus a flat shingle set for the mailbox."""
    message_ids: set[str] = field(default_factory=set)
    subjects: set[str] = field(default_factory=set)
    shingle_to_id: dict[str, str] = field(default_factory=dict)
    messages_indexed: int = 0

    def add(self, message_id: str, subject: str, body: str) -> None:
        mid = (message_id or "").strip().strip("<>").lower()
        if mid:
            self.message_ids.add(mid)
        subj = _norm_subject(subject)
        if subj:
            self.subjects.add(subj)
        for sh in shingles(body):
            self.shingle_to_id.setdefault(sh, mid or subj or "?")
        self.messages_indexed += 1

    # ------------------------------------------------------------------ i/o
    def save(self, path: Path = INDEX_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "message_ids": list(self.message_ids),
            "subjects": list(self.subjects),
            "shingle_to_id": self.shingle_to_id,
            "messages_indexed": self.messages_indexed,
        }))
        path.chmod(0o600)

    @staticmethod
    def load(path: Path = INDEX_PATH) -> "ThreadIndex":
        if not path.exists():
            return ThreadIndex()
        try:
            d = json.loads(path.read_text())
        except Exception:
            return ThreadIndex()
        return ThreadIndex(set(d.get("message_ids", [])), set(d.get("subjects", [])),
                           d.get("shingle_to_id", {}), int(d.get("messages_indexed", 0)))


def disable_for_corpus(reason: str = "") -> None:
    """Turn thread verification off for corpus work.

    Corpus mail came from other people's mailboxes. Checking whether its quoted
    threads exist in THIS user's index answers a question nobody asked, and the
    answer is always no -- on held-out mail that produced 2,266 fabricated-thread
    hits, 2,261 of them on benign messages, because a 2002 mailing-list reply
    obviously does not appear in a 2026 Gmail account.

    Every script that scores the corpus must call this. Training already did;
    the evaluation did not, and the false-positive rate went from 1.1% to 28.7%
    before anyone noticed.
    """
    from .features.extractor import set_thread_index
    set_thread_index(ThreadIndex())


def _norm_subject(s: str) -> str:
    s = re.sub(r"(?i)^\s*(?:re|fw|fwd)\s*:\s*", "", (s or "").strip())
    return re.sub(r"[^a-z0-9 ]+", "", s.lower()).strip()[:80]


@dataclass
class ThreadVerdict:
    claims_thread: bool = False
    quoted_text: str = ""
    in_reply_to: str = ""
    references: list[str] = field(default_factory=list)
    msgid_resolved: bool = False
    quote_match_ratio: float = 0.0
    subject_known: bool = False
    fabricated: bool = False
    indeterminate: bool = True
    note: str = ""


def extract_quoted(body: str) -> str:
    """The text the message attributes to a previous exchange."""
    body = body or ""
    lines = QUOTED_LINE_RE.findall(body)
    if lines:
        return " ".join(l.strip() for l in lines if l.strip())
    m = QUOTE_INTRO_RE.search(body)
    if m:
        # No ">" markers: take what follows the attribution line.
        return body[m.end():m.end() + 1500].strip()
    return ""


def verify(email, index: ThreadIndex, min_index: int = 200) -> ThreadVerdict:
    """Did the exchange this message claims to continue actually happen?"""
    v = ThreadVerdict()
    body = getattr(email, "body", "") or ""
    subject = getattr(email, "subject", "") or ""

    v.in_reply_to = (getattr(email, "in_reply_to", "") or "").strip().strip("<>").lower()
    v.references = [r.lower() for r in MSGID_RE.findall(getattr(email, "references", "") or "")]
    v.quoted_text = extract_quoted(body)
    is_reply_subject = bool(re.match(r"(?i)^\s*(?:re|fw|fwd)\s*:", subject))
    v.claims_thread = bool(v.quoted_text) or bool(v.in_reply_to) or is_reply_subject
    if not v.claims_thread:
        v.indeterminate = False
        return v

    # An index that does not cover the relevant period cannot prove absence.
    # Saying "indeterminate" is the honest answer; claiming fabrication would
    # be an artefact of how much mail was indexed.
    if index.messages_indexed < min_index:
        v.note = (f"thread index holds only {index.messages_indexed} messages -- "
                  f"too few to conclude anything from an absent match")
        return v

    v.subject_known = _norm_subject(subject) in index.subjects
    for mid in [v.in_reply_to, *v.references]:
        if mid and mid in index.message_ids:
            v.msgid_resolved = True
            break

    if v.quoted_text:
        q = shingles(v.quoted_text)
        if q:
            hit = sum(1 for sh in q if sh in index.shingle_to_id)
            v.quote_match_ratio = hit / len(q)

    if v.msgid_resolved or v.quote_match_ratio >= 0.25 or v.subject_known:
        v.indeterminate = False
        v.note = ("the quoted exchange is present in this mailbox"
                  if v.quote_match_ratio >= 0.25 or v.msgid_resolved
                  else "a thread with this subject exists in this mailbox")
        return v

    # Quoted substance, no trace of it anywhere, and no matching subject.
    if len(TOKEN_RE.findall(v.quoted_text)) >= 25:
        v.fabricated = True
        v.indeterminate = False
        v.note = ("this message quotes a conversation that does not exist in "
                  "this mailbox -- no matching message, message-id or subject")
    else:
        v.note = "quoted fragment too short to judge"
    return v


def thread_features(v: ThreadVerdict) -> dict[str, float]:
    return {
        "thr_claims_thread": float(v.claims_thread),
        "thr_msgid_resolved": float(v.msgid_resolved),
        "thr_quote_match": float(v.quote_match_ratio),
        "thr_fabricated": float(v.fabricated),
    }


THREAD_FEATURE_NAMES = tuple(thread_features(ThreadVerdict()).keys())
