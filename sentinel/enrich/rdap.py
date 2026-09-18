"""Domain age via RDAP.

A domain registered three days ago that is asking you to sign in is one of the
single strongest phishing signals available, and nothing in a static corpus can
provide it -- registration dates are a live fact about the world.

RDAP is the IETF replacement for WHOIS: JSON over HTTPS, no rate-limit keys for
modest use, and rdap.org bootstraps to the correct registry automatically.

PRIVACY: this makes an outbound request naming the domain being analysed. The
RDAP operator therefore learns which domains you are looking at (not who you
are, nor any message content). It is off by default and must be enabled
explicitly with SENTINEL_ENABLE_RDAP=true.

Failure is always soft. No network, a timeout, a registry that does not answer --
all yield "unknown", never an exception and never a guess. An enrichment that
crashes the analyser is worse than no enrichment.
"""
from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

def _ssl_context() -> ssl.SSLContext:
    """A verifying context that works on a stock macOS python.org install.

    Those builds ship without a usable CA store, so the default context fails
    every HTTPS request with CERTIFICATE_VERIFY_FAILED. certifi's bundle fixes
    it properly. Verification is never disabled -- an enrichment that accepts
    any certificate is an enrichment an attacker can forge.
    """
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


RDAP_BOOTSTRAP = "https://rdap.org/domain/{domain}"
USER_AGENT = "sentinel-email-analysis/1.0 (+local security tooling)"
TIMEOUT = 6.0

# Registration events are named inconsistently across registries.
REGISTRATION_EVENTS = ("registration", "registered", "created", "last changed")


@dataclass
class DomainFact:
    domain: str
    registered: str | None = None     # ISO date
    age_days: int | None = None
    registrar: str = ""
    status: tuple[str, ...] = ()
    error: str = ""

    @property
    def known(self) -> bool:
        return self.age_days is not None

    def describe(self) -> str:
        if not self.known:
            return f"registration date unavailable ({self.error or 'no data'})"
        years = self.age_days / 365.25
        age = (f"{self.age_days} days old" if self.age_days < 400
               else f"{years:.1f} years old")
        reg = f", registrar {self.registrar}" if self.registrar else ""
        return f"registered {self.registered[:10]} — {age}{reg}"


class DomainAgeCache:
    """On-disk cache. Registration dates never change, so this is cheap and
    means a repeated scan costs no network at all."""

    def __init__(self, path: Path, enabled: bool = False):
        self.path = path
        self.enabled = enabled
        self._data: dict[str, dict] = {}
        if path.exists():
            try:
                self._data = json.loads(path.read_text())
            except Exception:
                self._data = {}

    def save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self._data))
        except Exception:
            pass

    def lookup(self, domain: str) -> DomainFact:
        domain = (domain or "").strip().lower()
        if not domain or "." not in domain:
            return DomainFact(domain=domain, error="not a domain")
        if domain in self._data:
            return DomainFact(domain=domain, **self._data[domain])
        if not self.enabled:
            return DomainFact(domain=domain, error="RDAP disabled")

        fact = self._fetch(domain)
        # Cache successes and hard negatives; do not cache transient failures,
        # or one flaky minute poisons the store permanently.
        if fact.known or fact.error in ("not found", "no registration event"):
            self._data[domain] = {"registered": fact.registered, "age_days": fact.age_days,
                                  "registrar": fact.registrar,
                                  "status": list(fact.status), "error": fact.error}
        return fact

    @staticmethod
    def _fetch(domain: str) -> DomainFact:
        req = urllib.request.Request(RDAP_BOOTSTRAP.format(domain=domain),
                                     headers={"User-Agent": USER_AGENT,
                                              "Accept": "application/rdap+json"})
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT,
                                        context=_ssl_context()) as r:
                payload = json.loads(r.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            return DomainFact(domain=domain,
                              error="not found" if e.code == 404 else f"http {e.code}")
        except Exception as e:
            return DomainFact(domain=domain, error=type(e).__name__)

        registered = None
        for ev in payload.get("events", []) or []:
            action = str(ev.get("eventAction", "")).lower()
            if action in REGISTRATION_EVENTS and ev.get("eventDate"):
                if action in ("registration", "registered", "created"):
                    registered = ev["eventDate"]
                    break
                registered = registered or ev["eventDate"]
        if not registered:
            return DomainFact(domain=domain, error="no registration event")

        try:
            dt = datetime.fromisoformat(re.sub(r"Z$", "+00:00", registered))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            age = max(0, (datetime.now(timezone.utc) - dt).days)
        except Exception:
            return DomainFact(domain=domain, error="unparseable date")

        registrar = ""
        for ent in payload.get("entities", []) or []:
            if "registrar" in [r.lower() for r in ent.get("roles", [])]:
                for item in ent.get("vcardArray", [[], []])[1]:
                    if item and item[0] == "fn":
                        registrar = str(item[3])[:60]
                        break
        return DomainFact(domain=domain, registered=registered, age_days=age,
                          registrar=registrar,
                          status=tuple(payload.get("status", []) or []))


def age_features(fact: DomainFact) -> dict[str, float]:
    """Bucketed, because the risk is wildly non-linear: a week-old domain is
    alarming, and 3 years versus 9 years means nothing."""
    if not fact.known:
        return {"dom_age_known": 0.0, "dom_age_days": 0.0,
                "dom_age_under_30d": 0.0, "dom_age_under_180d": 0.0}
    return {
        "dom_age_known": 1.0,
        "dom_age_days": float(min(fact.age_days, 10000)),
        "dom_age_under_30d": float(fact.age_days < 30),
        "dom_age_under_180d": float(fact.age_days < 180),
    }
