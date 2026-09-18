"""Breach exposure, from two free sources.

Two different questions, with very different privacy costs:

  account exposure  Has this mailbox appeared in a public breach? Answered by
                    XposedOrNot, which is free and needs no key -- but which
                    receives the full address. That is a real disclosure, so it
                    is off by default and the result is cached so an address is
                    sent at most once.

  quoted password   Sextortion mail quotes a real password to prove a breach
                    ("I know your password is Summer2019!"). HIBP's range API
                    answers whether that password appears in breach corpora
                    while receiving only the first five characters of its SHA-1
                    -- k-anonymity, so the password never leaves the machine.

The second is the more useful of the two and costs nothing in privacy. A quoted
password that really is breached tells the reader something worth acting on:
the claim is recycled from a dump, not from their device, and that password
needs changing wherever it was reused.

Exposure nudges severity a little. It is context, not evidence: millions of
addresses are in breaches and almost none of their owners are being attacked
today.
"""
from __future__ import annotations

import hashlib
import json
import re
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

XON_URL = "https://api.xposedornot.com/v1/check-email/{email}"
PWNED_RANGE = "https://api.pwnedpasswords.com/range/{prefix}"
TIMEOUT = 10.0
UA = "sentinel-email-analysis/1.0"

# "your password is X" / "password: X" -- how these messages present the proof.
QUOTED_PW_RE = re.compile(
    r"(?i)(?:password|passcode|pwd)\s*(?:is|:|was)\s*[\"'“]?([^\s\"'”,.<>]{6,40})")


def _ctx() -> ssl.SSLContext:
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def _get(url: str) -> tuple[int, str]:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=_ctx()) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return 0, ""


@dataclass
class BreachStatus:
    address: str = ""
    breached: bool = False
    breaches: list[str] = field(default_factory=list)
    quoted_password: str = ""
    quoted_password_breached: bool = False
    quoted_password_count: int = 0
    error: str = ""

    def describe(self) -> str:
        bits = []
        if self.breached:
            shown = ", ".join(self.breaches[:4])
            more = f" and {len(self.breaches) - 4} more" if len(self.breaches) > 4 else ""
            bits.append(f"address appears in {len(self.breaches)} public breach(es): "
                        f"{shown}{more}")
        if self.quoted_password:
            if self.quoted_password_breached:
                bits.append(f"the password quoted in this message appears in breach "
                            f"corpora {self.quoted_password_count:,} times -- it was "
                            f"taken from a dump, not from your device, and should be "
                            f"changed anywhere it is still used")
            else:
                bits.append("the password quoted in this message does not appear in "
                            "any known breach corpus -- likely fabricated")
        return "; ".join(bits)


class BreachCache:
    def __init__(self, path: Path, enabled: bool = False):
        self.path, self.enabled = path, enabled
        self._d: dict = {}
        if path.exists():
            try:
                self._d = json.loads(path.read_text())
            except Exception:
                self._d = {}

    def _save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self._d))
            self.path.chmod(0o600)
        except Exception:
            pass

    # ------------------------------------------------------------- account
    def account(self, address: str) -> BreachStatus:
        addr = (address or "").strip().lower()
        s = BreachStatus(address=addr)
        if not addr or "@" not in addr:
            return s
        if addr in self._d:
            s.breached = bool(self._d[addr])
            s.breaches = list(self._d[addr])
            return s
        if not self.enabled:
            s.error = "account breach lookup disabled"
            return s
        code, body = _get(XON_URL.format(email=urllib.parse.quote(addr)))
        if code != 200:
            s.error = f"lookup failed ({code})"
            return s
        try:
            data = json.loads(body)
            found = data.get("breaches") or []
            if found and isinstance(found[0], list):
                found = found[0]
            s.breaches = [str(b) for b in found][:40]
            s.breached = bool(s.breaches)
        except Exception:
            s.error = "unparseable response"
            return s
        self._d[addr] = s.breaches
        self._save()
        return s

    # ------------------------------------------------ password quoted in mail
    @staticmethod
    def quoted_password(body: str) -> tuple[str, bool, int]:
        """k-anonymous: only the first five SHA-1 characters are transmitted."""
        m = QUOTED_PW_RE.search(body or "")
        if not m:
            return "", False, 0
        pw = m.group(1)
        h = hashlib.sha1(pw.encode("utf-8", "ignore")).hexdigest().upper()
        code, text = _get(PWNED_RANGE.format(prefix=h[:5]))
        if code != 200:
            return pw, False, 0
        for line in text.splitlines():
            suffix, _, count = line.partition(":")
            if suffix.strip() == h[5:]:
                return pw, True, int(count.strip() or 0)
        return pw, False, 0


def breach_features(s: BreachStatus) -> dict[str, float]:
    return {
        "brc_account_breached": float(s.breached),
        "brc_breach_count": float(min(len(s.breaches), 40)),
        "brc_quoted_password": float(bool(s.quoted_password)),
        "brc_quoted_password_real": float(s.quoted_password_breached),
    }


BREACH_FEATURE_NAMES = tuple(breach_features(BreachStatus()).keys())
import urllib.parse  # noqa: E402  (used in account())
