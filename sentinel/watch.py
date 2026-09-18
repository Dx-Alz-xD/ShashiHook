"""Background mailbox watch with native desktop notifications.

Turns ShashiHook from something you open into something that tells you. Polls
on an interval, scores anything new, and raises a macOS notification for
messages at or above a band you choose.

Two things it deliberately does not do:

  * It does not re-alert. Every message id it has already notified about is
    remembered on disk, so a restart or an overlapping poll cannot produce a
    duplicate. An alerter that cries twice gets muted, and a muted alerter is
    worse than none.
  * It does not act. Any quarantine or trash behaviour comes from the
    auto-action layer and its own separate arming switch; the watcher only
    looks and tells.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .analyzer import Analysis, ThreatAnalyzer
from .config import ARTIFACTS
from .enrich.breach import BreachCache
from .enrich.rdap import DomainAgeCache
from .enrich.virustotal import VirusTotal
from .files import FileTracker
from .settings import Settings

BAND_RANK = {"INFORMATIONAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SEEN_PATH = ARTIFACTS / "watch_seen.json"


@dataclass
class WatchState:
    seen: set[str] = field(default_factory=set)
    notified: int = 0
    polls: int = 0
    started: str = ""

    @staticmethod
    def load(path: Path = SEEN_PATH) -> "WatchState":
        s = WatchState(started=datetime.now(timezone.utc).isoformat())
        if path.exists():
            try:
                d = json.loads(path.read_text())
                s.seen = set(d.get("seen", []))
                s.notified = int(d.get("notified", 0))
            except Exception:
                pass
        return s

    def save(self, path: Path = SEEN_PATH) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            # Bounded: keeping every id forever would grow without limit.
            recent = list(self.seen)[-8000:]
            path.write_text(json.dumps({"seen": recent, "notified": self.notified}))
            path.chmod(0o600)
        except Exception:
            pass


def notify(title: str, subtitle: str, body: str, sound: bool = True) -> bool:
    """Native macOS notification. Returns False where that is unavailable, and
    the caller falls back to printing -- a watcher that crashes on a headless
    box is not useful."""
    if not shutil.which("osascript"):
        return False

    def esc(s: str) -> str:
        return (s or "").replace("\\", "\\\\").replace('"', '\\"')[:220]

    script = (f'display notification "{esc(body)}" with title "{esc(title)}" '
              f'subtitle "{esc(subtitle)}"' + (' sound name "Basso"' if sound else ""))
    try:
        subprocess.run(["osascript", "-e", script], check=False, timeout=8,
                       capture_output=True)
        return True
    except Exception:
        return False


def _alert(a: Analysis) -> tuple[str, str, str]:
    sender = a.evidence.sender.address or a.email.sender or "unknown sender"
    title = f"{a.severity.band} · {a.severity.score:.0f}/100"
    subtitle = a.vector.name
    body = f"{(a.email.subject or '(no subject)')[:70]}\nfrom {sender[:60]}"
    return title, subtitle, body


def poll_once(az: ThreatAnalyzer, cfg: Settings, state: WatchState,
              min_band: str, limit: int, query: str, mailbox: str,
              on_event=print) -> list[Analysis]:
    from .ingest import imap_box
    floor = BAND_RANK.get(min_band.upper(), 2)
    state.polls += 1
    fresh: list[Analysis] = []
    try:
        msgs = imap_box.fetch(cfg, query, limit, mailbox=mailbox)
    except Exception as e:
        on_event(f"  poll failed: {type(e).__name__}: {e}")
        return fresh

    for m in msgs:
        try:
            e = imap_box.to_email(m)
        except Exception:
            continue
        key = e.message_id or e.uid
        if key in state.seen:
            continue
        state.seen.add(key)
        try:
            a = az.analyze(e)
        except Exception:
            continue
        fresh.append(a)
        # Learn this sender's writing style AFTER scoring it, never before.
        # A message folded into the profile first would be compared against a
        # baseline it had just helped define, so it could never look unusual --
        # the same self-match that made the thread-verification harness read
        # 83.5% until the index was grown in arrival order instead.
        _learn_style(e, a)
        if BAND_RANK.get(a.severity.band, 0) >= floor:
            t, st, body = _alert(a)
            if not notify(t, st, body):
                on_event(f"  !! {t} — {st} — {(e.subject or '')[:60]}")
            state.notified += 1
            on_event(f"  ALERT {a.severity.band} {a.severity.score:.1f} "
                     f"{a.vector_key} — {(e.subject or '')[:56]}")
    state.save()
    _save_style()
    return fresh


def _learn_style(email, analysis) -> None:
    """Fold a message into its sender's writing-style profile.

    Skipped for anything the analyser found hostile: a profile is meant to
    describe the real correspondent, and letting a suspected impersonation
    teach it would move the baseline towards the attacker -- slowly training
    the detector to accept them.
    """
    try:
        if analysis.probability >= 0.5 or analysis.floors_binding:
            return
        from .features.extractor import strip_html, style_store
        body = email.body or ""
        if email.html:
            body = strip_html(body)
        addr = (analysis.evidence.sender.address or "").strip().lower()
        if addr:
            style_store().observe(addr, body)
    except Exception:
        pass          # profiling is advisory; it must never break a poll


def _save_style() -> None:
    try:
        from .features.extractor import style_store
        store = style_store()
        if store.profiles:
            store.fit_population()
            store.save()
    except Exception:
        pass


def _sweep_files(tracker: FileTracker, on_event) -> None:
    """Check whether any tracked attachment has appeared on disk or changed.

    Runs on the same tick as the mailbox poll. The watcher is already awake and
    already the thing the user leaves running, so a separate daemon for this
    would be a second process to forget about.

    Only files from mail that scored above the tracking threshold are looked
    for. Watching every download would be surveillance with a security label
    on it.
    """
    for ev in tracker.sweep():
        kind = ev.get("event")
        name = ev.get("filename", "?")
        if kind == "appeared_on_disk":
            title = "Tracked attachment downloaded"
            body = f"{name}\n{ev.get('path','')}"
            if ev.get("quarantine"):
                body += f"\n{ev['quarantine']}"
        elif kind == "process_running_from_path":
            title = "Tracked file is RUNNING"
            body = f"{name}\n{ev.get('path','')}"
        else:
            title = "Tracked file changed"
            body = f"{name}\n{ev.get('path','')}"
        if not notify(title, "ShashiHook file tracking", body):
            on_event(f"  !! {title}: {name}")
        on_event(f"  FILE {kind}: {name} — {ev.get('path','')}")


def run(cfg: Settings, interval: int = 300, min_band: str = "MEDIUM",
        limit: int = 30, query: str = "newer_than:1d", mailbox: str = "INBOX",
        once: bool = False, on_event=print) -> None:
    watch_dirs = ([Path(d.strip()).expanduser() for d in cfg.file_watch_dirs.split(",")
                   if d.strip()] or None)
    tracker = FileTracker(min_severity=cfg.file_track_min_severity,
                          **({"watch_dirs": watch_dirs} if watch_dirs else {}))
    az = ThreatAnalyzer(
        known_bad_iocs=cfg.load_iocs(),
        software_allowlist=cfg.load_software_allowlist(),
        inbox_base_rate=cfg.inbox_base_rate or None,
        domain_age=DomainAgeCache(ARTIFACTS / "domain_age_cache.json",
                                  enabled=cfg.enable_rdap),
        breach=BreachCache(ARTIFACTS / "breach_cache.json",
                           enabled=cfg.breach_check_account),
        virustotal=VirusTotal(cfg.virustotal_api_key, cfg.virustotal_allow_upload,
                              ARTIFACTS / "vt_cache.json"),
        file_tracker=tracker,
    )
    state = WatchState.load()
    on_event(f"Watching {mailbox} every {interval}s · alerting at {min_band.upper()}+")
    on_event(f"Also sweeping {', '.join(str(d) for d in tracker.watch_dirs)} for "
             f"attachments from mail scoring >= {cfg.file_track_min_severity:g}")
    on_event(f"{len(state.seen):,} message ids already seen — these will not re-alert.")
    if not shutil.which("osascript"):
        on_event("osascript unavailable: alerts will print here instead.")

    # The first poll marks everything currently present as seen without
    # alerting, so starting the watcher does not fire a notification for every
    # old message in the window.
    first = True
    try:
        while True:
            t0 = time.time()
            if first:
                from .ingest import imap_box
                try:
                    for m in imap_box.fetch(cfg, query, limit, mailbox=mailbox):
                        try:
                            e = imap_box.to_email(m)
                            state.seen.add(e.message_id or e.uid)
                        except Exception:
                            pass
                    state.save()
                    on_event(f"  baseline: {len(state.seen):,} ids marked seen, no alerts")
                except Exception as e:
                    on_event(f"  baseline failed: {e}")
                first = False
            else:
                fresh = poll_once(az, cfg, state, min_band, limit, query, mailbox, on_event)
                _sweep_files(tracker, on_event)
                on_event(f"  poll {state.polls}: {len(fresh)} new · "
                         f"{state.notified} alerts total · "
                         f"{len(tracker.files)} file(s) tracked · "
                         f"{time.time()-t0:.1f}s")
            if once:
                return
            time.sleep(max(30, interval))
    except KeyboardInterrupt:
        on_event(f"\nstopped after {state.polls} polls, {state.notified} alerts")
        state.save()
