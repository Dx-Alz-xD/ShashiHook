"""Automated response — the only part of this system that writes to a mailbox.

Everything else in ShashiHook is read-only by construction. This module is not,
so it is built to be hard to misuse:

  * Disabled by default. It does nothing until SENTINEL_AUTO_ACTION names an
    action AND a threshold is set.
  * Dry-run by default. Even enabled, it reports what it would do and changes
    nothing until SENTINEL_AUTO_ACTION_ARM=true.
  * Nothing is permanently deleted, ever. "delete" moves the message to Trash,
    where the provider keeps it for ~30 days. The detector's false-positive
    rate on real mail is around 1%; at that rate a hard delete means a
    legitimate message destroyed with no way back, and no severity threshold
    makes that an acceptable trade. If you genuinely want irreversible
    deletion, it has to be written deliberately -- it is not going to happen by
    leaving a setting at its default.
  * Deterministic-rule verdicts can be required, so a model score alone never
    moves mail.
  * Every action is appended to an audit log with the score, the vector and the
    reason, so anything that disappears can be explained and undone.
"""
from __future__ import annotations

import imaplib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .analyzer import Analysis
from .ingest.imap_box import _quote
from .settings import Settings

ACTIONS = ("none", "flag", "quarantine", "trash")
BAND_RANK = {"INFORMATIONAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass
class ActionResult:
    message_id: str
    subject: str
    sender: str
    score: float
    band: str
    vector: str
    action: str
    performed: bool = False
    dry_run: bool = True
    error: str = ""
    reason: str = ""


@dataclass
class ActionPlan:
    action: str = "none"
    threshold: float = 100.0
    armed: bool = False
    require_rule: bool = False
    quarantine_folder: str = "ShashiHook/Quarantine"
    results: list[ActionResult] = field(default_factory=list)

    @property
    def performed(self) -> int:
        return sum(1 for r in self.results if r.performed)


def should_action(a: Analysis, cfg: Settings) -> tuple[bool, str]:
    """Whether this message meets every condition for an automated action."""
    if cfg.auto_action not in ACTIONS or cfg.auto_action == "none":
        return False, "auto-action disabled"
    if a.severity.score < cfg.auto_action_threshold:
        return False, (f"severity {a.severity.score:.1f} below threshold "
                       f"{cfg.auto_action_threshold:g}")
    if cfg.auto_action_require_rule and not a.floors_binding:
        # The model alone can be confidently wrong on mail unlike its training
        # data. A deterministic rule naming a concrete, checkable property is a
        # much safer basis for touching someone's mailbox.
        return False, "no deterministic rule fired (require_rule is on)"
    if a.vector_key == "benign":
        return False, "vector is benign"
    return True, (f"severity {a.severity.score:.1f} >= {cfg.auto_action_threshold:g}"
                  + (f", rule {a.floors_binding[0].name}" if a.floors_binding else ""))


class MailboxActions:
    """IMAP write operations. Opened read-write only when actually arming."""

    def __init__(self, cfg: Settings):
        self.cfg = cfg
        self.conn: imaplib.IMAP4_SSL | None = None

    def __enter__(self) -> "MailboxActions":
        self.conn = imaplib.IMAP4_SSL(self.cfg.imap_host, self.cfg.imap_port)
        self.conn.login(self.cfg.imap_user, self.cfg.imap_password)
        return self

    def __exit__(self, *exc) -> None:
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass
            self.conn.logout()

    def ensure_folder(self, name: str) -> None:
        try:
            self.conn.create(_quote(name))
        except Exception:
            pass   # already exists, which is the normal case

    def apply(self, uid: str, action: str, mailbox: str = "INBOX") -> str:
        """Returns "" on success, or an error string. Never expunges."""
        c = self.conn
        typ, _ = c.select(_quote(mailbox), readonly=False)
        if typ != "OK":
            return f"cannot open {mailbox} read-write"
        try:
            if action == "flag":
                c.store(uid, "+FLAGS", "\\Flagged")
                return ""
            if action == "quarantine":
                self.ensure_folder(self.cfg.quarantine_folder)
                typ, _ = c.copy(uid, _quote(self.cfg.quarantine_folder))
                if typ != "OK":
                    return "copy to quarantine failed"
                c.store(uid, "+FLAGS", "\\Deleted")   # removes from INBOX view
                return ""
            if action == "trash":
                # Gmail's Trash retains for ~30 days; this is recoverable.
                typ, _ = c.copy(uid, _quote("[Gmail]/Trash"))
                if typ != "OK":
                    return "copy to Trash failed"
                c.store(uid, "+FLAGS", "\\Deleted")
                return ""
            return f"unknown action {action}"
        except Exception as e:
            return f"{type(e).__name__}: {e}"


def audit(path: Path, r: ActionResult) -> None:
    line = json.dumps({"at": datetime.now(timezone.utc).isoformat(),
                       "action": r.action, "performed": r.performed,
                       "dry_run": r.dry_run, "score": r.score, "band": r.band,
                       "vector": r.vector, "subject": r.subject[:120],
                       "sender": r.sender[:120], "reason": r.reason,
                       "error": r.error})
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as f:
            f.write(line + "\n")
        path.chmod(0o600)
    except Exception:
        pass
