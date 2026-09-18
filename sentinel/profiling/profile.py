"""Narrative threat profiling.

This layer is deliberately advisory. The verdict, the severity and the attack
vector are produced by ArnosAI from measurable evidence and are not touched
here. What a language model adds is the part measurement is bad at: naming the
manipulation in a way a person can learn from, so the next message like it is
recognised by the reader rather than only by the detector.

Keeping the two apart matters. If a model could move a score, the score would
stop being auditable, and an attacker who can write text could argue their way
out of a detection by writing to the model rather than past the filter.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ..analyzer import Analysis
from ..settings import Settings
from . import llm
from .prompts import SYSTEM, build_user_prompt

TACTIC_ICONS = {
    "authority": "👔", "urgency": "⏱", "fear": "⚠", "trust-building": "🤝",
    "legitimacy-props": "🏷", "social-proof": "👥", "obfuscation": "🫥",
    "technical": "⚙", "reciprocity": "🎁", "personalisation": "🎯",
    "choice-architecture": "🔀",
}


@dataclass
class Tactic:
    name: str
    category: str = ""
    evidence: str = ""
    how_it_works: str = ""
    how_to_spot: str = ""

    @property
    def icon(self) -> str:
        return TACTIC_ICONS.get((self.category or "").lower().strip(), "•")


@dataclass
class ThreatProfile:
    ok: bool = False
    headline: str = ""
    summary: str = ""
    tactics: list[Tactic] = field(default_factory=list)
    who_it_targets: str = ""
    if_you_engaged: list[str] = field(default_factory=list)
    legitimate_version: str = ""
    provider: str = ""
    model: str = ""
    latency_ms: int = 0
    error: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["tactics"] = [{**asdict(t), "icon": t.icon} for t in self.tactics]
        return d


def _evidence_lines(a: Analysis) -> list[str]:
    out = [f"{f.headline} ({f.contribution:+.2f})" for f in a.findings_up[:6]
           if "Absence" not in f.headline]
    out += [f"rule fired: {f.name} — {f.why}" for f in a.floors_binding]
    if a.history_note:
        out.append(f"mailbox history: {a.history_note}")
    if a.domain_age_note:
        out.append(f"domain age: {a.domain_age_note}")
    for u in a.evidence.urls[:3]:
        for fl in u.flags[:2]:
            out.append(f"link: {fl}")
    for p in a.evidence.phones[:2]:
        out.append(f"phone number in message: {p.raw}")
    return out


def _cache_key(a: Analysis) -> str:
    h = hashlib.sha256()
    h.update((a.email.subject or "").encode("utf-8", "ignore"))
    h.update((a.email.body or "")[:4000].encode("utf-8", "ignore"))
    return h.hexdigest()[:20]


class ProfileCache:
    """Profiles cost an API call and never change for the same message."""

    def __init__(self, path: Path):
        self.path = path
        self._d: dict[str, dict] = {}
        if path.exists():
            try:
                self._d = json.loads(path.read_text())
            except Exception:
                self._d = {}

    def get(self, key: str) -> dict | None:
        return self._d.get(key)

    def put(self, key: str, value: dict) -> None:
        self._d[key] = value
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self._d))
            self.path.chmod(0o600)
        except Exception:
            pass


def profile(a: Analysis, cfg: Settings, cache: ProfileCache | None = None,
            force: bool = False) -> ThreatProfile:
    key = _cache_key(a)
    if cache and not force:
        hit = cache.get(key)
        if hit:
            p = ThreatProfile(**{k: v for k, v in hit.items() if k != "tactics"})
            p.tactics = [Tactic(**{k: v for k, v in t.items() if k != "icon"})
                         for t in hit.get("tactics", [])]
            return p

    if not llm.available(cfg)["any"]:
        return ThreatProfile(error="No GEMINI_API_KEY or GROQ_API_KEY configured "
                                   "in .env — narrative profiling is unavailable.")

    user = build_user_prompt(
        subject=a.email.subject or "", sender=a.email.sender or "",
        body=a.evidence.body or a.email.body or "",
        verdict=a.verdict, severity=a.severity.score, band=a.severity.band,
        vector_name=a.vector.name, vector_description=a.vector.description,
        evidence=_evidence_lines(a),
    )
    res = llm.complete(cfg, SYSTEM, user)
    if not res.ok:
        return ThreatProfile(error=res.error, provider=res.provider,
                             model=res.model, latency_ms=res.latency_ms)

    d = res.data
    tactics = []
    for t in (d.get("tactics") or [])[:12]:
        if not isinstance(t, dict) or not t.get("name"):
            continue
        tactics.append(Tactic(
            name=str(t.get("name", ""))[:80],
            category=str(t.get("category", ""))[:40],
            evidence=str(t.get("evidence", ""))[:200],
            how_it_works=str(t.get("how_it_works", ""))[:400],
            how_to_spot=str(t.get("how_to_spot", ""))[:400],
        ))

    p = ThreatProfile(
        ok=True,
        headline=str(d.get("headline", ""))[:240],
        summary=str(d.get("summary", ""))[:900],
        tactics=tactics,
        who_it_targets=str(d.get("who_it_targets", ""))[:300],
        if_you_engaged=[str(s)[:240] for s in (d.get("if_you_engaged") or [])[:8]],
        legitimate_version=str(d.get("legitimate_version", ""))[:400],
        provider=res.provider, model=res.model, latency_ms=res.latency_ms,
        error=res.error,
    )
    if cache:
        cache.put(key, p.to_dict())
    return p
