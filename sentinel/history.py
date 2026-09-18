"""Sender reputation built from the mailbox's own past.

Almost every BEC and credential-phishing attack arrives from a domain the
recipient has never corresponded with. Nothing in the trained model knows that,
because a flat CSV corpus has no notion of "have I heard from this sender
before" -- that question only has an answer inside a real mailbox.

This module answers it. It walks the mailbox once, header-only, and records for
every sender address and registrable domain: when it was first and last seen,
how many messages have arrived, and -- the strongest trust signal available --
whether the user has ever sent *to* that domain. A domain you have emailed is a
domain you chose to deal with.

Like the authentication headers, these facts feed the deterministic layer and
the report, never the trained model: no training corpus contains them, so a
model feature built on them would have nothing to learn from.

Privacy: the store is a list of everyone the user corresponds with. It stays on
local disk, is gitignored, and holds no message content -- addresses, counts and
dates only.
"""
from __future__ import annotations

import imaplib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

from .features.headers import registrable_domain
from .settings import Settings

ADDR_RE = re.compile(r"[\w.+-]+@[\w.-]+\.\w+")
HEADER_FIELDS = "(FROM TO CC DATE)"

def _quote(mailbox: str) -> str:
    """IMAP folder names with spaces must be quoted, e.g. "[Gmail]/Sent Mail"."""
    if mailbox.startswith('"') and mailbox.endswith('"'):
        return mailbox
    return f'"{mailbox}"' if (" " in mailbox or "]" in mailbox) else mailbox



@dataclass
class Party:
    address: str = ""
    domain: str = ""
    received: int = 0          # messages from them
    sent_to: int = 0           # messages the user sent to them
    first_seen: str = ""
    last_seen: str = ""
    # Hour-of-day histogram of when this party sends, in the user's local time.
    # A domain that has only ever arrived on weekday mornings and suddenly
    # lands at 03:00 has changed in a way no content signal would show.
    hours: dict = field(default_factory=dict)
    weekdays: dict = field(default_factory=dict)

    @property
    def is_known(self) -> bool:
        return self.received > 0 or self.sent_to > 0

    @property
    def is_corresponded(self) -> bool:
        """The user has actually written to this party -- strong trust."""
        return self.sent_to > 0

    @property
    def reply_rate(self) -> float:
        """Replies sent per message received.

        Far stronger than "have I ever written to this domain". Receiving mail
        is passive and says nothing -- anyone can send to you. Replying is a
        deliberate act repeated over time, and an attacker cannot manufacture
        it retroactively.
        """
        return min(1.0, self.sent_to / self.received) if self.received else 0.0

    def dormancy_days(self, now=None) -> int | None:
        """Days between the previous message and the most recent one.

        A domain that sent 200 messages through 2021, went silent for three
        years and suddenly reappeared is the classic shape of a lapsed domain
        that has been re-registered, or an account that has just been taken
        over. Nothing in the message body shows it.
        """
        if not self.last_seen or not self.first_seen or self.received < 3:
            return None
        try:
            first = datetime.fromisoformat(self.first_seen)
            last = datetime.fromisoformat(self.last_seen)
        except ValueError:
            return None
        span = (last - first).days
        if span <= 0:
            return None
        typical = span / max(self.received - 1, 1)
        now = now or datetime.now(timezone.utc)
        gap = (now - last).days
        # Reported only when the latest gap dwarfs this sender's own rhythm.
        return gap if gap > max(120, typical * 8) else None

    def unusual_hour(self, hour: int) -> bool:
        """True when this hour is outside everything this party has ever used."""
        if sum(self.hours.values()) < 8:
            return False
        seen = {int(h) for h, n in self.hours.items() if n > 0}
        return hour not in seen and not any(abs(hour - s) <= 1 for s in seen)


@dataclass
class History:
    addresses: dict[str, Party] = field(default_factory=dict)
    domains: dict[str, Party] = field(default_factory=dict)
    built_at: str = ""
    messages_scanned: int = 0

    # ------------------------------------------------------------ queries
    def lookup(self, address: str) -> tuple[Party, Party]:
        addr = (address or "").lower().strip()
        dom = registrable_domain(addr.rpartition("@")[2]) if "@" in addr else ""
        return (self.addresses.get(addr, Party(address=addr)),
                self.domains.get(dom, Party(domain=dom)))

    def days_known(self, address: str) -> int | None:
        a, d = self.lookup(address)
        seen = a.first_seen or d.first_seen
        if not seen:
            return None
        try:
            first = datetime.fromisoformat(seen)
        except ValueError:
            return None
        return max(0, (datetime.now(timezone.utc) - first).days)

    def signals(self, address: str, hour: int | None = None
                ) -> dict[str, float | bool | int | None]:
        a, d = self.lookup(address)
        return {
            "sender_known": a.is_known,
            "domain_known": d.is_known,
            "first_contact": not d.is_known,
            "ever_corresponded_with_domain": d.is_corresponded,
            "messages_from_domain": d.received,
            "messages_sent_to_domain": d.sent_to,
            "days_known": self.days_known(address),
            "reply_rate": round(d.reply_rate, 3),
            "dormant_days": d.dormancy_days(),
            "unusual_hour": d.unusual_hour(hour) if hour is not None else False,
        }

    def describe(self, address: str) -> str:
        s = self.signals(address)
        if s["first_contact"]:
            return "first contact — no prior mail from or to this domain"
        bits = [f"{s['messages_from_domain']} message(s) received from this domain"]
        if s["messages_sent_to_domain"]:
            bits.append(f"{s['messages_sent_to_domain']} sent to it "
                        f"(reply rate {s['reply_rate']:.0%})")
        if s["days_known"] is not None:
            bits.append(f"known for {s['days_known']} days")
        if s["dormant_days"]:
            bits.append(f"but silent for {s['dormant_days']} days before this")
        return "; ".join(bits)

    # --------------------------------------------------------------- i/o
    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "built_at": self.built_at, "messages_scanned": self.messages_scanned,
            "addresses": {k: asdict(v) for k, v in self.addresses.items()},
            "domains": {k: asdict(v) for k, v in self.domains.items()},
        }))
        path.chmod(0o600)

    @staticmethod
    def load(path: Path) -> "History":
        if not path.exists():
            return History()
        d = json.loads(path.read_text())
        return History(
            addresses={k: Party(**v) for k, v in d.get("addresses", {}).items()},
            domains={k: Party(**v) for k, v in d.get("domains", {}).items()},
            built_at=d.get("built_at", ""),
            messages_scanned=int(d.get("messages_scanned", 0)),
        )


def _stamp(raw: str) -> str:
    try:
        dt = parsedate_to_datetime(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        return ""


def _touch(store: dict[str, Party], key: str, *, is_domain: bool,
           received: int, sent_to: int, when: str) -> None:
    p = store.get(key)
    if p is None:
        p = Party(domain=key) if is_domain else Party(address=key)
        store[key] = p
    p.received += received
    p.sent_to += sent_to
    if when:
        if not p.first_seen or when < p.first_seen:
            p.first_seen = when
        if not p.last_seen or when > p.last_seen:
            p.last_seen = when
        if received:
            try:
                dt = datetime.fromisoformat(when)
                h, wd = str(dt.hour), str(dt.weekday())
                p.hours[h] = p.hours.get(h, 0) + 1
                p.weekdays[wd] = p.weekdays.get(wd, 0) + 1
            except ValueError:
                pass


def build(cfg: Settings, folders: tuple[str, ...] = ("INBOX", "[Gmail]/Sent Mail"),
          limit_per_folder: int = 20000, progress=print) -> History:
    """Walk the mailbox header-only and build the reputation store.

    Only FROM/TO/CC/DATE are fetched -- never a body -- which keeps this fast
    over IMAP and means no message content is read to build the store.
    """
    h = History(built_at=datetime.now(timezone.utc).isoformat())
    conn = imaplib.IMAP4_SSL(cfg.imap_host, cfg.imap_port)
    conn.login(cfg.imap_user, cfg.imap_password)
    own = (cfg.imap_user or "").lower()
    try:
        for folder in folders:
            is_sent = "sent" in folder.lower()
            try:
                typ, _ = conn.select(_quote(folder), readonly=True)
                if typ != "OK":
                    progress(f"  {folder}: cannot open, skipping")
                    continue
            except Exception as e:
                progress(f"  {folder}: {e}, skipping")
                continue
            typ, data = conn.search(None, "ALL")
            if typ != "OK":
                continue
            uids = data[0].split()[-limit_per_folder:]
            progress(f"  {folder}: {len(uids):,} messages")

            for start in range(0, len(uids), 500):
                chunk = uids[start:start + 500]
                typ, resp = conn.fetch(
                    b",".join(chunk), f"(BODY.PEEK[HEADER.FIELDS {HEADER_FIELDS}])")
                if typ != "OK":
                    continue
                for item in resp:
                    if not isinstance(item, tuple):
                        continue
                    text = item[1].decode("utf-8", "replace")
                    when = ""
                    m = re.search(r"(?im)^Date:\s*(.+)$", text)
                    if m:
                        when = _stamp(m.group(1).strip())
                    froms = re.search(r"(?im)^From:\s*(.+)$", text)
                    tos = re.findall(r"(?im)^(?:To|Cc):\s*(.+)$", text)

                    if is_sent:
                        # Recipients of the user's own mail are trusted parties.
                        for line in tos:
                            for a in ADDR_RE.findall(line):
                                a = a.lower()
                                if a == own:
                                    continue
                                _touch(h.addresses, a, is_domain=False,
                                       received=0, sent_to=1, when=when)
                                _touch(h.domains, registrable_domain(a.rpartition("@")[2]),
                                       is_domain=True, received=0, sent_to=1, when=when)
                    elif froms:
                        found = ADDR_RE.findall(froms.group(1))
                        if found:
                            a = found[0].lower()
                            if a != own:
                                _touch(h.addresses, a, is_domain=False,
                                       received=1, sent_to=0, when=when)
                                _touch(h.domains, registrable_domain(a.rpartition("@")[2]),
                                       is_domain=True, received=1, sent_to=0, when=when)
                    h.messages_scanned += 1
                progress(f"    {min(start+500, len(uids)):,}/{len(uids):,}", end="\r")
            progress("")
    finally:
        try:
            conn.close()
        except Exception:
            pass
        conn.logout()
    return h
