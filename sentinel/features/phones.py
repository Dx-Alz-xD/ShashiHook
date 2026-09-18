"""Phone-number extraction and callback-lure analysis.

Telephone-Oriented Attack Delivery (TOAD, or callback phishing) is the fastest
growing email fraud class and is structurally invisible to everything else in
this system. A fake Norton or Geek Squad renewal notice carries no link, no
attachment and no spoofed login page -- just an invoice-looking PDF or plain
text and a phone number. The victim calls, and the rest of the attack happens
on the phone, where no email gateway can see it.

Every URL feature scores zero on these. So the number itself has to become a
signal: its presence, how urgently the message pushes you to dial it, and
whether the surrounding text is a billing pretext.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# Deliberately permissive about separators, strict about length, and anchored so
# it does not swallow order numbers, dates, prices or tracking IDs.
PHONE_RE = re.compile(r"""
    (?<![\w.])
    (?:
        \+\d{1,3}[\s.\-]?\(?\d{1,4}\)?[\s.\-]?\d{3,4}[\s.\-]?\d{3,4}(?:[\s.\-]?\d{2,4})?
      | \(?\d{3}\)?[\s.\-]\d{3}[\s.\-]\d{4}
      | \b1[\s.\-]8(?:00|33|44|55|66|77|88)[\s.\-]\d{3}[\s.\-]?\d{4}
      | \b8(?:00|33|44|55|66|77|88)[\s.\-]\d{3}[\s.\-]\d{4}
    )
    (?![\w.])
""", re.VERBOSE)

# "call us", "dial", "contact our support line" -- the instruction that turns a
# number into a lure.
CALL_TO_ACTION_RE = re.compile(
    r"(?i)\b(?:call|dial|phone|contact|reach|speak (?:to|with)|talk to|ring)\b"
    r"[^.!?\n]{0,60}(?:\b(?:us|our|support|helpline|help ?desk|toll[- ]?free|"
    r"customer (?:care|service|support)|representative|agent|billing|refund)\b"
    r"|[\+\(\d])"
    r"|\b(?:toll[- ]?free|helpline|customer care number|support number|"
    r"contact number)\b"
)

# Cancel-or-be-charged framing: the engine of the refund/renewal scam.
BILLING_PRETEXT_RE = re.compile(
    r"(?i)\b(?:auto[- ]?renew(?:al|ed|s)?|subscription (?:renew|charge|fee|expir)"
    r"|your (?:order|plan|membership|subscription) (?:has been|was|is) "
    r"(?:renewed|charged|activated|confirmed)"
    r"|(?:debited|charged) (?:from )?your (?:account|card)"
    r"|to (?:cancel|stop|decline) (?:this|the|your) (?:order|subscription|renewal|charge|transaction)"
    r"|if you (?:did ?n[o']t|do not) (?:authori[sz]e|recognise|recognize|want)"
    r"|refund (?:department|team|request|process)"
    r"|cancellation (?:department|request|fee))"
)

TOLL_FREE_PREFIXES = ("800", "833", "844", "855", "866", "877", "888")


@dataclass
class PhoneFact:
    raw: str
    digits: str = ""
    toll_free: bool = False
    international: bool = False
    flags: list[str] = field(default_factory=list)


def extract_phones(text: str) -> list[PhoneFact]:
    out: list[PhoneFact] = []
    seen: set[str] = set()
    for m in PHONE_RE.finditer(text or ""):
        raw = m.group(0).strip()
        digits = re.sub(r"\D", "", raw)
        # 7 digits is a local number; 15 is the E.164 maximum.
        if not (7 <= len(digits) <= 15):
            continue
        if digits in seen:
            continue
        seen.add(digits)
        f = PhoneFact(raw=raw, digits=digits)
        core = digits[1:] if digits.startswith("1") and len(digits) == 11 else digits
        f.toll_free = core[:3] in TOLL_FREE_PREFIXES
        f.international = raw.strip().startswith("+")
        if f.toll_free:
            f.flags.append("a toll-free number, which anyone can rent anonymously "
                           "for the length of a campaign")
        if f.international:
            f.flags.append("an international number")
        out.append(f)
    return out


def phone_features(text: str, phones: list[PhoneFact]) -> dict[str, float]:
    text = text or ""
    n = len(phones)
    return {
        "tel_count": float(n),
        "tel_toll_free": float(any(p.toll_free for p in phones)),
        "tel_international": float(any(p.international for p in phones)),
        "tel_call_to_action": float(bool(CALL_TO_ACTION_RE.search(text))),
        "tel_billing_pretext": float(bool(BILLING_PRETEXT_RE.search(text))),
        # The signature of callback phishing: a number to ring, an instruction
        # to ring it, a billing story, and nothing to click.
        "tel_callback_shape": float(
            n > 0 and bool(CALL_TO_ACTION_RE.search(text))
            and bool(BILLING_PRETEXT_RE.search(text))),
    }


PHONE_FEATURE_NAMES = tuple(phone_features("", []).keys())
