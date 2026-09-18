"""Scan a live mailbox and triage what comes back.

Privacy posture, because this reads real mail:

  * Read-only everywhere. The OAuth scope is gmail.readonly, the IMAP mailbox
    is opened with readonly=True, and no adapter calls a mutating command.
  * Nothing leaves the machine. Messages go from the provider into memory, are
    scored locally, and the output lands on local disk.
  * Reports quote only the short evidence spans that drove the score, never the
    whole message, unless SENTINEL_SAVE_BODIES is turned on deliberately.
  * Credentials are never written into a report or a log line.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .analyzer import Analysis, ThreatAnalyzer
from .enrich.rdap import DomainAgeCache
from .report.incident import to_json, to_markdown
from .settings import Settings, settings as default_settings

BAND_RANK = {"INFORMATIONAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


@dataclass
class ScanResult:
    analyses: list[Analysis] = field(default_factory=list)
    reports_written: list[Path] = field(default_factory=list)
    source: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def flagged(self) -> list[Analysis]:
        return [a for a in self.analyses if a.probability >= 0.5]

    def by_severity(self) -> list[Analysis]:
        return sorted(self.analyses, key=lambda a: -a.severity.score)

    def counts(self) -> dict[str, int]:
        c = {b: 0 for b in BAND_RANK}
        for a in self.analyses:
            c[a.severity.band] += 1
        return c


def _fetch(source: str, cfg: Settings, query: str | None, limit: int | None):
    if source == "gmail":
        from .ingest import gmail
        return [gmail.to_email(m) for m in gmail.fetch(cfg, query, limit)]
    if source == "imap":
        from .ingest import imap_box
        return [imap_box.to_email(m) for m in imap_box.fetch(cfg, query, limit)]
    raise ValueError(f"unknown source {source!r} (expected 'gmail' or 'imap')")


def _slug(analysis: Analysis) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    subject = SAFE_NAME.sub("-", (analysis.email.subject or "no-subject"))[:48].strip("-")
    return f"{stamp}_{analysis.severity.band}_{analysis.severity.score:05.1f}_{subject}"


def scan(source: str = "gmail", query: str | None = None, limit: int | None = None,
         cfg: Settings | None = None, analyzer: ThreatAnalyzer | None = None,
         write_reports: bool = True) -> ScanResult:
    cfg = cfg or default_settings
    az = analyzer or ThreatAnalyzer(
        known_bad_iocs=cfg.load_iocs(),
        software_allowlist=cfg.load_software_allowlist(),
        inbox_base_rate=cfg.inbox_base_rate or None,
        domain_age=DomainAgeCache(Path(cfg.report_dir).parent / "artifacts"
                                  / "domain_age_cache.json", enabled=cfg.enable_rdap)
        if cfg.enable_rdap else None,
    )
    result = ScanResult(source=source)

    emails = _fetch(source, cfg, query, limit)
    for e in emails:
        try:
            result.analyses.append(az.analyze(e))
        except Exception as exc:                       # one bad message must not
            result.errors.append(                      # abort the whole scan
                f"{(e.subject or '(no subject)')[:60]}: {type(exc).__name__}: {exc}")

    if write_reports:
        floor = BAND_RANK.get(cfg.min_band_to_report, 2)
        outdir = Path(cfg.report_dir)
        for a in result.analyses:
            if BAND_RANK[a.severity.band] < floor:
                continue
            outdir.mkdir(parents=True, exist_ok=True)
            base = outdir / _slug(a)
            md = to_markdown(a)
            if not cfg.save_bodies:
                md += ("\n\n_Message body not stored. Set SENTINEL_SAVE_BODIES=true "
                       "to include full context in future reports._\n")
            base.with_suffix(".md").write_text(md)
            base.with_suffix(".json").write_text(to_json(a))
            result.reports_written.append(base.with_suffix(".md"))
    return result


def format_table(result: ScanResult, show: int = 40) -> str:
    """Compact triage table. Subjects are truncated; bodies never appear."""
    rows = result.by_severity()[:show]
    if not rows:
        return "No messages scanned."
    L = [f"{'sev':>5}  {'band':<14} {'P':>6}  {'vector':<22} {'from':<34} subject",
         "-" * 118]
    for a in rows:
        sender = (a.evidence.sender.address or a.email.sender or "(none)")[:33]
        subj = (a.email.subject or "(no subject)").replace("\n", " ")[:38]
        flag = "!" if a.floors_binding else " "
        L.append(f"{a.severity.score:5.1f}{flag} {a.severity.band:<14} "
                 f"{a.probability:6.3f}  {a.vector_key:<22} {sender:<34} {subj}")
    c = result.counts()
    L.append("-" * 118)
    L.append(f"{len(result.analyses)} scanned  ·  {len(result.flagged)} flagged  ·  "
             + "  ".join(f"{b}={c[b]}" for b in
                         ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL") if c[b]))
    L.append("! = verdict set by a deterministic rule, not the model")
    if result.errors:
        L.append(f"\n{len(result.errors)} message(s) failed to analyse:")
        L += [f"  {e}" for e in result.errors[:5]]
    return "\n".join(L)
