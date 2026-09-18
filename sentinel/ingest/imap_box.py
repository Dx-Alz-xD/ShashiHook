"""IMAP adapter for an app password.

Simpler to set up than OAuth and works from a single .env value, at a real cost:
a Gmail app password grants full mailbox access -- read, send and delete -- and
cannot be scoped down. Nothing in this module calls a mutating command, and
the mailbox is opened read-only so that merely fetching a message cannot mark
it as seen.
"""
from __future__ import annotations

import email as email_lib
import imaplib
import re
from datetime import datetime, timedelta

from ..settings import Settings
from .eml import from_message
from .gmail import FetchedMessage

# Gmail search syntax the API understands, mapped to IMAP where an equivalent
# exists. Anything unmapped is dropped rather than silently mistranslated.
_NEWER = re.compile(r"newer_than:(\d+)([dmy])")

def _quote(mailbox: str) -> str:
    """IMAP folder names with spaces must be quoted, e.g. "[Gmail]/Sent Mail"."""
    if mailbox.startswith('"') and mailbox.endswith('"'):
        return mailbox
    return f'"{mailbox}"' if (" " in mailbox or "]" in mailbox) else mailbox



def _to_imap_criteria(query: str) -> list[str]:
    crit: list[str] = []
    q = query or ""
    m = _NEWER.search(q)
    if m:
        n, unit = int(m.group(1)), m.group(2)
        days = n * {"d": 1, "m": 30, "y": 365}[unit]
        since = (datetime.now() - timedelta(days=days)).strftime("%d-%b-%Y")
        crit += ["SINCE", since]
    if "is:unread" in q:
        crit.append("UNSEEN")
    if "has:attachment" in q:
        # No portable IMAP equivalent; filtered after fetch instead.
        pass
    fm = re.search(r"from:(\S+)", q)
    if fm:
        crit += ["FROM", fm.group(1)]
    return crit or ["ALL"]


def fetch(cfg: Settings, query: str | None = None, limit: int | None = None,
          mailbox: str | None = None) -> list[FetchedMessage]:
    if not cfg.has_imap:
        raise RuntimeError("Set IMAP_USER and IMAP_APP_PASSWORD in .env "
                           "(app password, not your account password).")
    n = limit if limit is not None else cfg.limit
    box = mailbox or cfg.mailbox or "INBOX"

    conn = imaplib.IMAP4_SSL(cfg.imap_host, cfg.imap_port)
    try:
        conn.login(cfg.imap_user, cfg.imap_password)
        # readonly=True: fetching must not mark anything as read.
        conn.select(_quote(box), readonly=True)
        typ, data = conn.search(None, *_to_imap_criteria(
            query if query is not None else cfg.query))
        if typ != "OK":
            return []
        uids = data[0].split()[-n:]
        out: list[FetchedMessage] = []
        for uid in reversed(uids):
            typ, payload = conn.fetch(uid, "(RFC822)")
            if typ != "OK" or not payload or not isinstance(payload[0], tuple):
                continue
            out.append(FetchedMessage(provider_id=uid.decode(), raw=payload[0][1]))
        return out
    finally:
        try:
            conn.close()
        except Exception:
            pass
        conn.logout()


def to_email(fetched: FetchedMessage):
    e = from_message(email_lib.message_from_bytes(fetched.raw), source="imap")
    if not e.message_id:
        e.message_id = fetched.provider_id
    e.provider_id = fetched.provider_id          # type: ignore[attr-defined]
    return e
