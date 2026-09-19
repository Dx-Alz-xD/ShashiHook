"""Accounts, sessions and per-user mailboxes for the web application.

The engine was written for one machine and one mailbox, configured in .env.
Putting it on the web changes one thing that matters: which mailbox a request
is allowed to read. Everything here exists to make that answer come from the
signed-in session rather than from a global.

`user_settings()` is the whole idea. It clones the process settings and
overwrites the mail-server fields with the ones belonging to the signed-in
user, so every downstream call -- fetch, watch, profile -- talks to that
person's mailbox and no other. The alternative, threading a user through forty
call sites, would leave one of them reading the global and nobody would notice
until it mattered.

Cookies are HttpOnly and SameSite=Lax: a session that JavaScript cannot read
cannot be exfiltrated by a script injected into a page, and Lax stops another
site from firing authenticated requests at this one while still allowing an
ordinary link to work.
"""
from __future__ import annotations

import copy
import time

from fastapi import APIRouter, Cookie, HTTPException, Request, Response
from fastapi.responses import FileResponse, RedirectResponse
from pydantic import BaseModel

from sentinel.auth import (SESSION_HOURS, User, UserStore, issue_session,
                           password_problem, read_session)
from sentinel.settings import settings

router = APIRouter()
COOKIE = "shashihook_session"

_store: UserStore | None = None


def store() -> UserStore:
    global _store
    if _store is None:
        _store = UserStore.load()
        seed_demo(_store)
    return _store


def seed_demo(s: UserStore) -> None:
    """Create the demo account from whatever .env already had configured.

    It exists so the application can be opened and understood without anyone
    handing over a mailbox password first. It is marked `is_demo` and the UI
    says so, because a shared account is not a private one and a visitor should
    know whose mail they are looking at.
    """
    email = "demo@shashihook.app"
    if email in s.users:
        return
    if not (settings.imap_user and settings.imap_password):
        return
    u = s.create(email, "shashihook-demo-2026", "Demo")
    u.is_demo = True
    s.set_mailbox(email, settings.imap_host, settings.imap_port,
                  settings.imap_user, settings.imap_password, verified=True)


def current_user(token: str | None) -> User | None:
    email = read_session(token or "")
    return store().users.get(email) if email else None


def require_user(session: str | None = Cookie(default=None, alias=COOKIE)) -> User:
    """FastAPI dependency for anything that touches mail."""
    u = current_user(session)
    if u is None:
        raise HTTPException(401, "sign in to continue")
    return u


def user_settings(u: User):
    """Process settings, with this user's mailbox substituted in.

    A copy, never the global: mutating the shared object would leak one user's
    mail server into whichever request ran next.
    """
    cfg = copy.copy(settings)
    if u.has_mailbox:
        cfg.imap_host = u.imap_host
        cfg.imap_port = u.imap_port
        cfg.imap_user = u.imap_user
        cfg.imap_password = u.imap_password()
    else:
        cfg.imap_user = ""
        cfg.imap_password = ""
    return cfg


def _set_cookie(resp: Response, email: str) -> None:
    resp.set_cookie(
        COOKIE, issue_session(email),
        max_age=SESSION_HOURS * 3600,
        httponly=True,        # unreadable from JavaScript
        samesite="lax",       # not sent on cross-site POSTs
        secure=False,         # served over http://localhost; set True behind TLS
        path="/")


# ------------------------------------------------------------------ models
class Credentials(BaseModel):
    email: str
    password: str
    display_name: str = ""


class MailboxBody(BaseModel):
    host: str = "imap.gmail.com"
    port: int = 993
    user: str
    password: str = ""


class PasswordChange(BaseModel):
    current: str
    new: str


# ------------------------------------------------------------------ routes
@router.post("/api/auth/signup")
def signup(body: Credentials, response: Response) -> dict:
    try:
        u = store().create(body.email, body.password, body.display_name)
    except ValueError as e:
        raise HTTPException(400, str(e))
    _set_cookie(response, u.email)
    return {"ok": True, "user": u.public()}


@router.post("/api/auth/login")
def login(body: Credentials, response: Response) -> dict:
    u, why = store().authenticate(body.email, body.password)
    if u is None:
        # 401 with the same wording the store produced: "which half was wrong"
        # is exactly what an attacker wants and a user never needs.
        raise HTTPException(401, why)
    _set_cookie(response, u.email)
    return {"ok": True, "user": u.public()}


@router.post("/api/auth/demo")
def demo_login(response: Response) -> dict:
    """Sign straight into the shared demo account.

    "Try the demo" used to lead to the sign-in form with the details printed
    beside it, which asked the reader to type out a password we had just shown
    them. The credentials are public either way, so the form was friction
    without a purpose.
    """
    s = store()
    u = next((x for x in s.users.values() if x.is_demo), None)
    if u is None:
        raise HTTPException(503, "no demo account is configured on this server")
    _set_cookie(response, u.email)
    return {"ok": True, "user": u.public()}


@router.post("/api/auth/logout")
def logout(response: Response) -> dict:
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


@router.get("/api/auth/me")
def me(session: str | None = Cookie(default=None, alias=COOKIE)) -> dict:
    u = current_user(session)
    return {"signed_in": u is not None, "user": u.public() if u else None}


@router.post("/api/auth/password")
def change_password(body: PasswordChange,
                    session: str | None = Cookie(default=None, alias=COOKIE)) -> dict:
    u = current_user(session)
    if u is None:
        raise HTTPException(401, "sign in to continue")
    if u.is_demo:
        raise HTTPException(403, "the demo account cannot be changed")
    problem = store().change_password(u.email, body.current, body.new)
    if problem:
        raise HTTPException(400, problem)
    return {"ok": True}


@router.post("/api/mailbox")
def connect_mailbox(body: MailboxBody,
                    session: str | None = Cookie(default=None, alias=COOKIE)) -> dict:
    """Store a mailbox after proving the credentials actually work.

    Verified before saving on purpose. A password that is wrong now will still
    be wrong at 3am inside the watch daemon, where the failure is a log line
    nobody reads rather than a message on the screen of the person who typed it.
    """
    u = current_user(session)
    if u is None:
        raise HTTPException(401, "sign in to continue")
    if u.is_demo:
        raise HTTPException(403, "the demo mailbox cannot be changed")
    password = body.password or u.imap_password()
    if not password:
        raise HTTPException(400, "an app password is required")

    import imaplib
    try:
        with imaplib.IMAP4_SSL(body.host, int(body.port), timeout=20) as m:
            m.login(body.user, password)
            m.select("INBOX", readonly=True)
    except imaplib.IMAP4.error as e:
        raise HTTPException(400, f"the mail server rejected those details: "
                                 f"{str(e)[:120]}")
    except Exception as e:
        raise HTTPException(400, f"could not reach {body.host}: "
                                 f"{type(e).__name__}")
    store().set_mailbox(u.email, body.host, body.port, body.user,
                        password, verified=True)
    return {"ok": True, "user": store().users[u.email].public()}


@router.delete("/api/mailbox")
def disconnect_mailbox(session: str | None = Cookie(default=None, alias=COOKIE)) -> dict:
    u = current_user(session)
    if u is None:
        raise HTTPException(401, "sign in to continue")
    if u.is_demo:
        raise HTTPException(403, "the demo mailbox cannot be changed")
    store().clear_mailbox(u.email)
    return {"ok": True}
