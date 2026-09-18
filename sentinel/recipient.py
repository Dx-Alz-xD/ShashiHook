"""What the recipient is actually exposed to.

Severity has so far been a property of the message alone. That is wrong in a
way that matters: the same gift-card request sent to an intern and to the
person who actually releases payments has the same content and wildly
different consequences. Impact is a property of what the reader can be made to
do.

Enterprise products approximate this with a hand-maintained VIP list, which is
stale the day it is written. The recipient's own mail says it better. Someone
who receives invoices, payment confirmations and remittance advice every week
is finance-exposed whatever their title; someone who receives password resets,
MFA prompts and admin notifications holds credentials worth taking.

The profile is built from mail already on this machine and never leaves it.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .config import ARTIFACTS

PROFILE_PATH = ARTIFACTS / "recipient_profile.json"

EXPOSURE_PATTERNS = {
    "finance": re.compile(
        r"(?i)\b(?:invoice|remittance|purchase order|payment (?:received|confirmation|"
        r"due|request)|accounts payable|wire transfer|bank details|statement of account|"
        r"payroll|reimbursement|expense report|receipt for)\b"),
    "credentials": re.compile(
        r"(?i)\b(?:password (?:reset|changed|expires)|verification code|"
        r"one-?time (?:code|password)|two-?factor|authenticator|sign-?in (?:alert|attempt)|"
        r"security alert|account recovery|api key|access token|admin(?:istrator)? (?:access|console))\b"),
    "vendor": re.compile(
        r"(?i)\b(?:supplier|vendor|contract (?:renewal|signature)|procurement|"
        r"quotation|tender|service agreement|sow\b|statement of work)\b"),
    "hr": re.compile(
        r"(?i)\b(?:offer letter|onboarding|employee|benefits enrol|leave request|"
        r"performance review|resignation|new starter)\b"),
    "executive": re.compile(
        r"(?i)\b(?:board (?:meeting|pack|deck)|shareholder|acquisition|due diligence|"
        r"quarterly results|investor)\b"),
}

# How much each exposure amplifies a given attack vector. A BEC lands hardest
# on someone who already handles payments; credential phishing lands hardest on
# someone whose mailbox is full of authentication traffic.
VECTOR_EXPOSURE = {
    "bec_payment_fraud": ("finance", 0.35),
    "vendor_invoice_fraud": ("finance", 0.30),
    "callback_phishing": ("finance", 0.20),
    "credential_phishing": ("credentials", 0.30),
    "malware_delivery": ("credentials", 0.15),
    "government_impersonation": ("finance", 0.15),
    "job_scam": ("hr", 0.20),
    "investment_fraud": ("finance", 0.15),
}


@dataclass
class RecipientProfile:
    address: str = ""
    messages: int = 0
    exposure: dict = field(default_factory=dict)      # area -> raw hit count
    built_at: str = ""

    def rate(self, area: str) -> float:
        """Share of this person's mail touching an area, capped for stability."""
        if not self.messages:
            return 0.0
        return min(1.0, self.exposure.get(area, 0) / max(self.messages * 0.15, 1))

    @property
    def dominant(self) -> str:
        if not self.exposure:
            return "unknown"
        return max(self.exposure, key=self.exposure.get)

    def multiplier(self, vector: str) -> tuple[float, str]:
        """Impact adjustment for this vector against this person.

        Returns a factor in roughly 0.85-1.35 and the reason. Deliberately
        bounded: a profile built from mail is an inference, not an org chart,
        and it should nudge a score rather than decide it.
        """
        if self.messages < 50:
            return 1.0, ""
        area_weight = VECTOR_EXPOSURE.get(vector)
        if not area_weight:
            return 1.0, ""
        area, weight = area_weight
        r = self.rate(area)
        if r >= 0.5:
            return 1.0 + weight, (
                f"this mailbox handles {area} traffic heavily "
                f"({self.exposure.get(area,0)} of {self.messages} recent messages), "
                f"so a successful {vector.replace('_',' ')} here costs more")
        if r <= 0.05:
            return 1.0 - weight * 0.4, (
                f"this mailbox almost never sees {area} traffic, so the practical "
                f"impact of {vector.replace('_',' ')} is lower than the vector's "
                f"baseline")
        return 1.0, ""

    def describe(self) -> str:
        if not self.messages:
            return "no recipient profile built"
        parts = [f"{a}: {self.rate(a):.0%}" for a in EXPOSURE_PATTERNS
                 if self.exposure.get(a)]
        return (f"{self.messages} messages profiled; "
                + ("; ".join(parts) if parts else "no strong exposure"))

    def save(self, path: Path = PROFILE_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(self)))
        path.chmod(0o600)

    @staticmethod
    def load(path: Path = PROFILE_PATH) -> "RecipientProfile":
        if not path.exists():
            return RecipientProfile()
        try:
            return RecipientProfile(**json.loads(path.read_text()))
        except Exception:
            return RecipientProfile()


def build(messages, address: str = "") -> RecipientProfile:
    """messages: iterable of (subject, body)."""
    from datetime import datetime, timezone
    p = RecipientProfile(address=address,
                         built_at=datetime.now(timezone.utc).isoformat())
    for subject, body in messages:
        text = f"{subject or ''} {body or ''}"[:6000]
        p.messages += 1
        for area, rx in EXPOSURE_PATTERNS.items():
            if rx.search(text):
                p.exposure[area] = p.exposure.get(area, 0) + 1
    return p
