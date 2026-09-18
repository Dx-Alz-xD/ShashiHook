"""Sender-identity analysis.

Answers the questions a human analyst asks first: who does this claim to be,
who actually sent it, and do those two agree?
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

from .brands import (BRAND_DOMAINS, BRAND_TOKENS, FREEMAIL_DOMAINS,
                     HIGH_RISK_TLDS, LEGIT_DOMAINS, owns)

ADDR_RE = re.compile(r"<\s*([^<>@\s]+@[^<>\s]+?)\s*>|(\b[^<>@\s,;]+@[^<>\s,;]+\b)")
DISPLAY_RE = re.compile(r'^\s*"?([^"<]*?)"?\s*<')


@dataclass
class SenderProfile:
    raw: str = ""
    display_name: str = ""
    address: str = ""
    local_part: str = ""
    domain: str = ""
    registrable: str = ""
    tld: str = ""
    claimed_brand: str | None = None
    brand_mismatch: bool = False
    lookalike_of: str | None = None
    lookalike_distance: int = 0
    is_freemail: bool = False
    notes: list[str] = field(default_factory=list)


def _levenshtein(a: str, b: str, cap: int = 3) -> int:
    """Edit distance, short-circuited once it exceeds `cap`."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > cap:
            return cap + 1
        prev = cur
    return prev[-1]


# Lookalike comparison only ever considers domains of a similar length (the
# loop below rejects anything more than 2 characters different), so the
# candidate set is bucketed by length once at import instead of being filtered
# on every parse. Sorted, so a tie between two equidistant domains resolves the
# same way on every run -- frozenset iteration order does not guarantee that.
_LOOKALIKE_BY_LEN: dict[int, tuple[str, ...]] = {}


def _lookalike_candidates(length: int) -> tuple[str, ...]:
    hit = _LOOKALIKE_BY_LEN.get(length)
    if hit is None:
        hit = tuple(d for d in sorted(LEGIT_DOMAINS)
                    if len(d) >= 8 and abs(len(d) - length) <= 2)
        _LOOKALIKE_BY_LEN[length] = hit
    return hit


def registrable_domain(domain: str) -> str:
    """Best-effort eTLD+1 without a network call.

    Handles the common two-label public suffixes (co.uk, com.au, gov.uk …);
    anything else falls back to the last two labels.
    """
    parts = [p for p in domain.lower().strip(".").split(".") if p]
    if len(parts) <= 2:
        return ".".join(parts)
    two_label_suffixes = {
        "co", "com", "net", "org", "gov", "edu", "ac", "mil", "or", "ne", "go",
    }
    if parts[-2] in two_label_suffixes and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def parse_sender(raw: str | None) -> SenderProfile:
    p = SenderProfile(raw=(raw or "").strip())
    if not p.raw:
        p.notes.append("no sender header present")
        return p

    m = ADDR_RE.search(p.raw)
    if m:
        p.address = (m.group(1) or m.group(2) or "").strip().strip("<>").lower()
    dm = DISPLAY_RE.match(p.raw)
    if dm:
        p.display_name = dm.group(1).strip()
    elif not m:
        p.display_name = p.raw

    if "@" in p.address:
        p.local_part, _, p.domain = p.address.rpartition("@")
        p.domain = p.domain.strip(">").strip()
        p.registrable = registrable_domain(p.domain)
        p.tld = p.registrable.rsplit(".", 1)[-1] if "." in p.registrable else ""
        p.is_freemail = p.registrable in FREEMAIL_DOMAINS

    # Does the display name claim a brand the sending domain does not own?
    if p.display_name:
        dn = re.sub(r"[^a-z0-9 ]", "", p.display_name.lower())
        for token, brand in BRAND_TOKENS.items():
            if re.search(rf"\b{re.escape(token)}\b", dn):
                p.claimed_brand = brand
                if p.registrable and not owns(brand, p.registrable):
                    p.brand_mismatch = True
                    p.notes.append(
                        f"display name claims '{brand}' but the message was sent "
                        f"from {p.registrable}, which {brand} does not own"
                    )
                break

    # Is the sending domain a near-miss of a real one?
    if p.registrable and p.registrable not in LEGIT_DOMAINS and len(p.registrable) >= 8:
        # Edit distance alone is useless on short domains: "acme.com" is two
        # edits from Apple's "me.com", and flagging that made the lookalike
        # signal wrong 96% of the time on held-out mail. Require comparable
        # length and a distance small relative to it.
        best, best_d = None, 99
        for legit in _lookalike_candidates(len(p.registrable)):
            d = _levenshtein(p.registrable, legit, cap=2)
            if d < best_d:
                best, best_d = legit, d
        if best and 0 < best_d <= 2 and best_d / len(best) <= 0.25:
            p.lookalike_of, p.lookalike_distance = best, best_d
            p.notes.append(
                f"sending domain {p.registrable} is {best_d} character(s) from "
                f"the legitimate {best}"
            )

    if p.tld in HIGH_RISK_TLDS:
        p.notes.append(f"sending domain uses .{p.tld}, a high-abuse TLD")

    return p


def header_features(sender: str | None, receiver: str | None, date: str | None,
                    profile: SenderProfile | None = None) -> dict[str, float]:
    """`profile` lets a caller that has already parsed this sender hand the
    result in. `extract` parses it for the evidence bundle either way, and
    parsing is the most expensive step here -- it runs an edit-distance
    comparison against every brand domain of a similar length."""
    p = profile if profile is not None else parse_sender(sender)
    recv = (receiver or "").strip().lower()
    n_recipients = len([x for x in re.split(r"[,;]", recv) if "@" in x])

    digits = sum(ch.isdigit() for ch in p.registrable)
    return {
        "hdr_sender_present": float(bool(p.address)),
        "hdr_display_name_present": float(bool(p.display_name)),
        "hdr_brand_display_mismatch": float(p.brand_mismatch),
        "hdr_domain_is_lookalike": float(p.lookalike_of is not None),
        "hdr_sender_freemail": float(p.is_freemail),
        "hdr_sender_tld_high_risk": float(p.tld in HIGH_RISK_TLDS),
        "hdr_sender_domain_digits": float(digits),
        "hdr_sender_domain_len": float(len(p.registrable)),
        "hdr_sender_subdomain_depth": float(max(0, p.domain.count(".") - p.registrable.count("."))),
        "hdr_sender_local_entropy": shannon_entropy(p.local_part),
        "hdr_sender_local_len": float(len(p.local_part)),
        "hdr_sender_local_digit_ratio": (
            sum(ch.isdigit() for ch in p.local_part) / len(p.local_part) if p.local_part else 0.0
        ),
        "hdr_recipient_count": float(n_recipients),
        "hdr_recipient_missing": float(n_recipients == 0),
        "hdr_recipient_undisclosed": float("undisclosed" in recv or "recipients" in recv),
        "hdr_same_domain_as_recipient": float(
            bool(p.registrable) and bool(recv) and p.registrable in recv
        ),
        "hdr_date_missing": float(not (date or "").strip()),
    }


HEADER_FEATURE_NAMES = tuple(header_features(None, None, None).keys())
