"""Accounts, sessions, and the mailbox credentials that make them useful.

Two secrets live here and they are handled in opposite ways, which is the whole
design:

  the login password    is HASHED with Argon2id and never recoverable. Nothing
                        in this system ever needs to know it; it only needs to
                        recognise it, and a hash does that.

  the IMAP app password is ENCRYPTED with AES-256-GCM and is recoverable,
                        because the scanner has to present it to the mail
                        server on every connection. There is no version of
                        this that stores a one-way hash and still works.

That second one deserves to be stated plainly rather than buried. Encrypting
with a server-held key means an attacker who takes both the database and the
key file gets every mailbox password. The alternative -- deriving the key from
the user's login password, so it is only readable while they are signed in --
is genuinely stronger and would break the background watch daemon, which must
reconnect at 3am with nobody signed in. This build chose the daemon. The key
lives outside the database, the file is 0600, and users are told to use a
provider app password scoped to mail rather than their real account password.

Argon2id parameters follow the OWASP recommendation: 64 MiB of memory, 3
iterations, 4 lanes. Memory-hardness is the point -- it is what makes a GPU
farm no better at this than the laptop it runs on.
"""
from __future__ import annotations

import base64
import json
import os
import re
import secrets
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from argon2 import PasswordHasher, low_level
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import ARTIFACTS

USERS_PATH = ARTIFACTS / "users.json"
KEY_PATH = ARTIFACTS / "master.key"

# OWASP's Argon2id baseline. Raising memory costs an attacker far more than it
# costs the login page: 64 MiB per attempt is nothing once, and ruinous a
# billion times.
HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4,
                        hash_len=32, salt_len=16, type=low_level.Type.ID)

SESSION_HOURS = 12
MIN_PASSWORD = 10

# Failed attempts before an account stops answering, and for how long. Counted
# per account rather than per IP: an attacker rotates addresses freely, and
# locking by IP punishes everyone behind one office router.
MAX_FAILURES = 6
LOCKOUT_SECONDS = 900

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def master_key() -> bytes:
    """The key that encrypts stored mailbox passwords.

    Generated on first use and kept outside the user database, so a leaked
    database alone is not enough. Set SHASHIHOOK_MASTER_KEY to hold it in the
    environment instead, which is what a real deployment should do.
    """
    env = os.environ.get("SHASHIHOOK_MASTER_KEY", "").strip()
    if env:
        raw = base64.urlsafe_b64decode(env + "=" * (-len(env) % 4))
        if len(raw) != 32:
            raise ValueError("SHASHIHOOK_MASTER_KEY must decode to 32 bytes")
        return raw
    if KEY_PATH.exists():
        return base64.urlsafe_b64decode(KEY_PATH.read_text().strip() + "==")
    key = AESGCM.generate_key(bit_length=256)
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    KEY_PATH.write_text(base64.urlsafe_b64encode(key).decode().rstrip("="))
    try:
        KEY_PATH.chmod(0o600)
    except OSError:
        pass
    return key


def encrypt(plaintext: str) -> str:
    """AES-256-GCM. The nonce is random per call and stored with the text."""
    if not plaintext:
        return ""
    nonce = secrets.token_bytes(12)
    blob = AESGCM(master_key()).encrypt(nonce, plaintext.encode(), None)
    return base64.urlsafe_b64encode(nonce + blob).decode()


def decrypt(token: str) -> str:
    if not token:
        return ""
    try:
        raw = base64.urlsafe_b64decode(token)
        return AESGCM(master_key()).decrypt(raw[:12], raw[12:], None).decode()
    except Exception:
        # A wrong key or a tampered record: report nothing rather than guess.
        return ""


def password_problem(password: str) -> str:
    """Why this password is not acceptable, or "" if it is.

    Length carries far more entropy than character-class rules, which mostly
    teach people to write Password1! and reuse it everywhere. The only other
    check is against the handful of passwords that appear in every breach list.
    """
    if len(password) < MIN_PASSWORD:
        return f"use at least {MIN_PASSWORD} characters"
    common = {"password", "12345678", "qwertyuiop", "letmein123",
              "iloveyou", "administrator", "shashihook", "changeme123"}
    if password.lower().strip() in common or password.lower().isdigit():
        return "that is one of the first passwords an attacker tries"
    return ""


@dataclass
class User:
    email: str = ""
    password_hash: str = ""
    created_at: float = 0.0
    last_login: float = 0.0
    display_name: str = ""
    # Mailbox connection. The password is ciphertext; see the module docstring.
    imap_host: str = ""
    imap_port: int = 993
    imap_user: str = ""
    imap_password_enc: str = ""
    imap_verified: bool = False
    is_demo: bool = False
    failures: int = 0
    locked_until: float = 0.0

    @property
    def has_mailbox(self) -> bool:
        return bool(self.imap_host and self.imap_user and self.imap_password_enc)

    @property
    def locked(self) -> bool:
        return time.time() < self.locked_until

    def imap_password(self) -> str:
        return decrypt(self.imap_password_enc)

    def public(self) -> dict:
        """Everything the browser may see. No hash, no ciphertext, ever.

        The demo account's mailbox address is masked. It is a real personal
        address and the account is shared, so printing it in full would publish
        somebody's email to every visitor who clicks "try the demo".
        """
        shown = self.imap_user
        if self.is_demo and "@" in shown:
            local, _, domain = shown.partition("@")
            shown = f"{local[:2]}{'*' * max(len(local) - 2, 3)}@{domain}"
        return {
            "email": self.email,
            "display_name": self.display_name or self.email.split("@")[0],
            "has_mailbox": self.has_mailbox,
            "imap_host": self.imap_host,
            "imap_user": shown,
            "imap_verified": self.imap_verified,
            "is_demo": self.is_demo,
            "created_at": self.created_at,
        }


@dataclass
class UserStore:
    users: dict[str, User] = field(default_factory=dict)
    path: Path = USERS_PATH

    @staticmethod
    def load(path: Path = USERS_PATH) -> "UserStore":
        store = UserStore(path=path)
        if path.exists():
            try:
                for rec in json.loads(path.read_text()).get("users", []):
                    u = User(**{k: v for k, v in rec.items()
                                if k in User.__dataclass_fields__})
                    store.users[u.email] = u
            except (json.JSONDecodeError, OSError, TypeError):
                pass
        return store

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(
            {"users": [asdict(u) for u in self.users.values()]}, indent=2))
        tmp.replace(self.path)
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    # ------------------------------------------------------------- accounts
    def create(self, email: str, password: str, display_name: str = "") -> User:
        email = (email or "").strip().lower()
        if not EMAIL_RE.match(email):
            raise ValueError("that does not look like an email address")
        if email in self.users:
            raise ValueError("an account already exists for that address")
        problem = password_problem(password)
        if problem:
            raise ValueError(problem)
        u = User(email=email, password_hash=HASHER.hash(password),
                 created_at=time.time(), display_name=display_name.strip()[:60])
        self.users[email] = u
        self.save()
        return u

    def authenticate(self, email: str, password: str) -> tuple[User | None, str]:
        """Check a password. Returns (user, reason-it-failed)."""
        email = (email or "").strip().lower()
        u = self.users.get(email)
        if u is None:
            # Spend the time anyway. Returning instantly for unknown addresses
            # turns the login form into a list of who has an account here.
            HASHER.hash(password or "x")
            return None, "no account matches that address and password"
        if u.locked:
            wait = int(u.locked_until - time.time())
            return None, (f"too many failed attempts — locked for another "
                          f"{wait // 60}m {wait % 60}s")
        try:
            HASHER.verify(u.password_hash, password or "")
        except (VerifyMismatchError, InvalidHashError):
            u.failures += 1
            if u.failures >= MAX_FAILURES:
                u.locked_until = time.time() + LOCKOUT_SECONDS
                u.failures = 0
            self.save()
            return None, "no account matches that address and password"
        # Argon2 parameters get raised over time; rehash on the next successful
        # login so existing accounts move up without anyone being locked out.
        if HASHER.check_needs_rehash(u.password_hash):
            u.password_hash = HASHER.hash(password)
        u.failures = 0
        u.locked_until = 0.0
        u.last_login = time.time()
        self.save()
        return u, ""

    def set_mailbox(self, email: str, host: str, port: int, user: str,
                    password: str, verified: bool = False) -> None:
        u = self.users[email.strip().lower()]
        u.imap_host = host.strip()
        u.imap_port = int(port or 993)
        u.imap_user = user.strip()
        if password:
            u.imap_password_enc = encrypt(password)
        u.imap_verified = verified
        self.save()

    def clear_mailbox(self, email: str) -> None:
        u = self.users[email.strip().lower()]
        u.imap_host = u.imap_user = u.imap_password_enc = ""
        u.imap_verified = False
        self.save()

    def change_password(self, email: str, old: str, new: str) -> str:
        u, why = self.authenticate(email, old)
        if u is None:
            return why or "current password is wrong"
        problem = password_problem(new)
        if problem:
            return problem
        u.password_hash = HASHER.hash(new)
        self.save()
        return ""


# --------------------------------------------------------------- sessions
def signer():
    from itsdangerous import URLSafeTimedSerializer
    return URLSafeTimedSerializer(
        base64.urlsafe_b64encode(master_key()).decode(), salt="shashihook-session")


def issue_session(email: str) -> str:
    return signer().dumps({"email": email, "iat": int(time.time())})


def read_session(token: str) -> str:
    """The email this token belongs to, or "" if it is invalid or expired."""
    if not token:
        return ""
    try:
        data = signer().loads(token, max_age=SESSION_HOURS * 3600)
        return str(data.get("email") or "")
    except Exception:
        return ""
