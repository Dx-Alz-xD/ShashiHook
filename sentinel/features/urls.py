"""URL extraction and risk analysis.

Where a link claims to go versus where it actually goes is the single most
productive signal in credential phishing, so every derived fact here is kept
alongside the URL that produced it for later quoting.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import unquote, urlsplit

from .brands import (
    ARCHIVE_EXTENSIONS,
    BRAND_DOMAINS,
    BRAND_TOKENS,
    DANGEROUS_EXTENSIONS,
    HIGH_RISK_TLDS,
    LEGIT_DOMAINS,
    URL_SHORTENERS,
    owns,
)
from .headers import registrable_domain

URL_RE = re.compile(
    r"""(?i)\b(?:(?:https?|ftp)://|www\d{0,3}\.)"""
    r"""[^\s<>"'`\]\)]+""",
)
# Anchors in raw HTML: capture href and the visible text separately so the two
# can be compared.
ANCHOR_RE = re.compile(
    r"""(?is)<a\b[^>]*\bhref\s*=\s*["']?([^"'\s>]+)["']?[^>]*>(.*?)</a>"""
)

CREDENTIAL_PATH_RE = re.compile(
    r"(?i)/(?:login|log-?in|signin|sign-?in|auth|verify|verification|validate|"
    r"account|accounts|secure|security|update|confirm|recover|reset|password|"
    r"webmail|owa|portal|session|billing|unlock|myaccount)\b"
)
HEX_ESCAPE_RE = re.compile(r"%[0-9a-fA-F]{2}")


@dataclass
class UrlFact:
    raw: str
    scheme: str = ""
    host: str = ""
    registrable: str = ""
    tld: str = ""
    path: str = ""
    anchor_text: str | None = None
    flags: list[str] = field(default_factory=list)

    def note(self, s: str) -> None:
        self.flags.append(s)


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def extract_urls(text: str, html: str | None = None) -> list[UrlFact]:
    """Pull every URL out of plain text, plus href/anchor pairs out of HTML."""
    facts: list[UrlFact] = []
    seen: set[str] = set()

    anchors: dict[str, str] = {}
    if html:
        for href, inner in ANCHOR_RE.findall(html):
            visible = re.sub(r"<[^>]+>", " ", inner)
            anchors[href.strip()] = re.sub(r"\s+", " ", visible).strip()

    candidates = [(u, None) for u in URL_RE.findall(text or "")]
    candidates += [(h, t) for h, t in anchors.items()]

    for raw, anchor_text in candidates:
        raw = raw.rstrip(".,;:!?)\"'>")
        if not raw or raw.lower() in seen:
            continue
        seen.add(raw.lower())
        norm = raw if "://" in raw else f"http://{raw}"
        try:
            sp = urlsplit(norm)
        except ValueError:
            continue
        f = UrlFact(raw=raw, scheme=sp.scheme.lower(), anchor_text=anchor_text)
        userinfo, _, hostport = sp.netloc.rpartition("@")
        f.host = hostport.split(":")[0].lower()
        f.path = sp.path + (("?" + sp.query) if sp.query else "")
        f.registrable = registrable_domain(f.host)
        f.tld = f.registrable.rsplit(".", 1)[-1] if "." in f.registrable else ""

        if userinfo:
            f.note(f"embeds credentials before the host ('{userinfo}@'), a classic "
                   f"trick to make the URL read as a trusted domain")
        if _is_ip_literal(f.host):
            f.note("points at a bare IP address instead of a hostname")
        if f.registrable in URL_SHORTENERS:
            f.note(f"uses the URL shortener {f.registrable}, hiding the real destination")
        if "xn--" in f.host:
            f.note("uses punycode, which can render as a lookalike of a real domain")
        if f.tld in HIGH_RISK_TLDS:
            f.note(f"resolves to a .{f.tld} domain, a high-abuse TLD")
        if CREDENTIAL_PATH_RE.search(f.path):
            f.note("path targets a sign-in or account-verification page")
        if len(HEX_ESCAPE_RE.findall(raw)) >= 4:
            f.note("is heavily percent-encoded, obscuring the real path")
        if f.host.count(".") >= 4:
            f.note(f"buries the real domain under {f.host.count('.')} subdomain levels")

        # Brand name in the subdomain or path but not in the registrable domain:
        # "paypal.com.secure-login.ru" is the canonical example.
        hay = unquote(f.host + f.path).lower()
        for token, brand in BRAND_TOKENS.items():
            if len(token) < 4:
                continue
            if token in hay and not owns(brand, f.registrable):
                f.note(f"contains the brand '{brand}' while actually resolving to "
                       f"{f.registrable}")
                break

        ext = f.path.rsplit(".", 1)[-1].split("?")[0].lower() if "." in f.path else ""
        if ext in DANGEROUS_EXTENSIONS:
            f.note(f"links directly to a .{ext} file, which executes on open")
        elif ext in ARCHIVE_EXTENSIONS:
            f.note(f"links to a .{ext} archive, commonly used to bypass scanning")

        if anchor_text:
            at = anchor_text.strip().lower().rstrip("/")
            if "." in at and " " not in at and at not in ("", f.host):
                shown = registrable_domain(at.replace("https://", "").replace("http://", "").split("/")[0])
                if shown and shown != f.registrable and "." in shown:
                    f.note(f"link text reads '{anchor_text.strip()}' but the href "
                           f"actually goes to {f.registrable}")
        facts.append(f)
    return facts


def url_features(facts: list[UrlFact]) -> dict[str, float]:
    n = len(facts)
    domains = {f.registrable for f in facts if f.registrable}
    flat = [fl for f in facts for fl in f.flags]

    def has(sub: str) -> float:
        return float(any(sub in fl for fl in flat))

    return {
        "url_count": float(n),
        "url_unique_domains": float(len(domains)),
        "url_has_ip_literal": has("bare IP"),
        "url_has_shortener": has("URL shortener"),
        "url_has_punycode": has("punycode"),
        "url_has_userinfo": has("embeds credentials"),
        "url_has_credential_path": has("sign-in or account-verification"),
        "url_has_high_risk_tld": has("high-abuse TLD"),
        "url_has_brand_mismatch": has("while actually resolving to"),
        "url_has_anchor_mismatch": has("link text reads"),
        "url_has_dangerous_ext": has("executes on open"),
        "url_has_archive_ext": has("archive, commonly used"),
        "url_has_hex_encoding": has("percent-encoded"),
        "url_deep_subdomain": has("subdomain levels"),
        "url_max_len": float(max((len(f.raw) for f in facts), default=0)),
        "url_mean_len": float(sum(len(f.raw) for f in facts) / n) if n else 0.0,
        "url_https_ratio": (
            sum(1 for f in facts if f.scheme == "https") / n if n else 0.0
        ),
        "url_flag_density": float(len(flat) / n) if n else 0.0,
        "url_legit_domain_ratio": (
            sum(1 for f in facts if f.registrable in LEGIT_DOMAINS) / n if n else 0.0
        ),
    }


URL_FEATURE_NAMES = tuple(url_features([]).keys())
