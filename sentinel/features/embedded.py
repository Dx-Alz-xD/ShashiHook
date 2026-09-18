"""Sender identity claimed inside the message body.

A scam that survives header inspection often states its identity in the body
instead: a "From: / Email:" block, a signature with a different address, or a
pasted header set. The envelope then belongs to whoever actually sent it --
a compromised account, a mailing service, or the victim themselves -- while the
person the reader believes they are dealing with appears only in the text.

Nothing in the header layer can see this, because the header layer is looking
at a From line that is entirely truthful about the wrong thing.

Detecting it is cheap and precise: pull every address the body asserts as its
own origin, and compare with the address the envelope actually used.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .headers import registrable_domain

# "From: X", "Email: x@y", "Sent by", plus the common markdown/HTML decorations
# that survive a plain-text conversion.
# Anchored at a line start OR at a markdown emphasis marker, because the label
# is often written "*From:*" and a plain-text conversion can collapse the whole
# message onto one line, which defeats a "^"-only anchor.
BODY_FROM_RE = re.compile(
    r"(?im)(?:^|[*_]|\n)\s*\*?(?:from|e-?mail|sender|sent by|reply[- ]to)\*?"
    r"\s*[:：]\s*\*?(.{0,120}?)(?=\*(?:from|e-?mail|subject|sender)\b|\n|$)"
)
ADDR_RE = re.compile(r"[\w.+-]+@[\w.-]+\.\w{2,}")
# A call to action whose link was stripped: "[Review beneficiary information]".
BRACKET_CTA_RE = re.compile(
    r"(?:\*?\[([^\]\n]{4,60})\]\*?|\bclick\s+(?:the\s+)?(?:button|link)\s+below\b)"
)


@dataclass
class EmbeddedIdentity:
    claimed_addresses: list[str] = field(default_factory=list)
    claimed_domains: list[str] = field(default_factory=list)
    envelope_domain: str = ""
    mismatch: bool = False
    bracket_ctas: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def analyse(body: str, envelope_address: str) -> EmbeddedIdentity:
    out = EmbeddedIdentity()
    body = body or ""
    env = (envelope_address or "").lower().strip()
    out.envelope_domain = registrable_domain(env.rpartition("@")[2]) if "@" in env else ""

    # Only the head of the message. A forged header block leads the text -- that
    # is the whole point of it. A conference announcement naming an organiser at
    # another university puts that contact further down, and scanning the whole
    # body flagged seven such mailing-list messages on held-out mail and was
    # wrong every time. "Contact:" was dropped from the labels for the same
    # reason: it is the one label that is almost always legitimate.
    HEAD = 500
    seen: set[str] = set()
    for m in BODY_FROM_RE.finditer(body[:HEAD]):
        for a in ADDR_RE.findall(m.group(1)):
            a = a.lower()
            if a == env or a in seen:
                continue
            seen.add(a)
            out.claimed_addresses.append(a)
            d = registrable_domain(a.rpartition("@")[2])
            if d and d not in out.claimed_domains:
                out.claimed_domains.append(d)

    if out.claimed_domains and out.envelope_domain and \
            out.envelope_domain not in out.claimed_domains:
        out.mismatch = True
        out.notes.append(
            f"the body presents itself as coming from "
            f"{out.claimed_addresses[0]}, but the message was actually sent from "
            f"{env or 'an unknown address'}")

    out.bracket_ctas = [t.strip() for t in BRACKET_CTA_RE.findall(body) if t and t.strip()][:5]
    if out.bracket_ctas:
        out.notes.append(
            f"carries a call to action with no visible destination: "
            f"'{out.bracket_ctas[0]}'")
    return out


def embedded_features(e: EmbeddedIdentity, n_urls: int) -> dict[str, float]:
    return {
        "emb_body_sender_count": float(len(e.claimed_addresses)),
        "emb_body_sender_mismatch": float(e.mismatch),
        "emb_bracket_cta": float(len(e.bracket_ctas)),
        # A call to action with no link at all: either the href was stripped in
        # conversion, or the destination is deliberately not shown.
        "emb_cta_without_url": float(bool(e.bracket_ctas) and n_urls == 0),
    }


EMBEDDED_FEATURE_NAMES = tuple(embedded_features(EmbeddedIdentity(), 0).keys())
