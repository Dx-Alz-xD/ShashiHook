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
          mailbox: str | None = None, sequential: bool = False
          ) -> list[FetchedMessage]:
    """Fetch messages. Concurrent and batched unless `sequential` is set."""
    if not sequential:
        try:
            return fetch_concurrent(cfg, query, limit, mailbox)
        except Exception:
            pass   # fall through to the single-connection path
    return _fetch_sequential(cfg, query, limit, mailbox)


def _fetch_sequential(cfg: Settings, query: str | None = None,
                      limit: int | None = None,
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


# ---------------------------------------------------------------------------
# Concurrent fetching.
#
# Measured: a sequential fetch runs at roughly 1 message/second, which is 385x
# the cost of scoring the same message. Almost all of that is round-trip
# latency, not bandwidth -- the client asks for one message, waits, asks for
# the next. Two changes fix it:
#
#   batching  ask for many UIDs in a single FETCH, so one round trip returns
#             many messages instead of one
#   parallel  run several connections at once, each taking a slice
#
# Gmail allows up to 15 simultaneous IMAP connections per account and throttles
# beyond that, so the default is deliberately well under the limit. Exceeding
# it gets the account temporarily locked out, which is far worse than a slow
# scan.
# ---------------------------------------------------------------------------
from concurrent.futures import ThreadPoolExecutor  # noqa: E402

# Measured against this account: throughput plateaus at ~11 msg/s and does not
# improve past 4 connections -- 10 performs the same and 12 is slower. Gmail
# throttles per account, not per connection, so extra sockets buy nothing and
# only bring the 15-connection limit closer. 4 is the sweet spot.
#
#   conns  batch   rate
#     1      -     2.2 msg/s   (sequential)
#     4     40    11.5 msg/s
#    10     40    11.2 msg/s
#    12    100     9.3 msg/s
#
# ~5x is therefore the realistic ceiling for mailbox scanning, and it is a
# server-side limit: no amount of client optimisation moves it.
MAX_CONNECTIONS = 4
BATCH = 40


def _fetch_slice(cfg: Settings, mailbox: str, uids: list[bytes]) -> list[FetchedMessage]:
    out: list[FetchedMessage] = []
    if not uids:
        return out
    conn = imaplib.IMAP4_SSL(cfg.imap_host, cfg.imap_port)
    try:
        conn.login(cfg.imap_user, cfg.imap_password)
        conn.select(_quote(mailbox), readonly=True)
        for i in range(0, len(uids), BATCH):
            chunk = uids[i:i + BATCH]
            try:
                typ, payload = conn.fetch(b",".join(chunk), "(RFC822)")
            except Exception:
                continue
            if typ != "OK" or not payload:
                continue
            # A batched FETCH returns interleaved tuples and separators; only
            # the tuples carry a message.
            idx = 0
            for item in payload:
                if isinstance(item, tuple) and len(item) > 1 and item[1]:
                    uid = chunk[idx].decode() if idx < len(chunk) else "?"
                    out.append(FetchedMessage(provider_id=uid, raw=item[1]))
                    idx += 1
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass
        try:
            conn.logout()
        except Exception:
            pass
    return out


def fetch_concurrent(cfg: Settings, query: str | None = None, limit: int | None = None,
                     mailbox: str | None = None,
                     connections: int = MAX_CONNECTIONS) -> list[FetchedMessage]:
    """Same contract as fetch(), many times faster. Read-only throughout."""
    if not cfg.has_imap:
        raise RuntimeError("Set IMAP_USER and IMAP_APP_PASSWORD in .env.")
    n = limit if limit is not None else cfg.limit
    box = mailbox or cfg.mailbox or "INBOX"

    search = imaplib.IMAP4_SSL(cfg.imap_host, cfg.imap_port)
    try:
        search.login(cfg.imap_user, cfg.imap_password)
        search.select(_quote(box), readonly=True)
        typ, data = search.search(None, *_to_imap_criteria(
            query if query is not None else cfg.query))
        uids = list(reversed(data[0].split()[-n:])) if typ == "OK" and data[0] else []
    finally:
        try:
            search.close()
        except Exception:
            pass
        search.logout()

    if not uids:
        return []
    k = max(1, min(connections, (len(uids) + BATCH - 1) // BATCH))
    slices = [uids[i::k] for i in range(k)]
    out: list[FetchedMessage] = []
    with ThreadPoolExecutor(max_workers=k) as pool:
        for part in pool.map(lambda s: _fetch_slice(cfg, box, s), slices):
            out.extend(part)
    return out
