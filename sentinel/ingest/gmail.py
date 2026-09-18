"""Gmail API adapter (OAuth 2.0, read-only).

Messages are fetched in `raw` format, which hands back the original RFC-5322
bytes. That matters: it preserves the Received chain, Reply-To, Return-Path and
Authentication-Results headers that carry the SPF/DKIM/DMARC verdicts. Those are
among the strongest signals available and none of them survive Gmail's parsed
`full` format, let alone the CSV corpora the models were trained on.

The scope is gmail.readonly and nothing here calls a mutating endpoint. There is
no code path in this file that can modify, label, send or delete mail.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from pathlib import Path

from ..settings import GMAIL_SCOPES, Settings
from .eml import from_message

from email import message_from_bytes


@dataclass
class FetchedMessage:
    provider_id: str
    raw: bytes
    labels: tuple[str, ...] = ()
    thread_id: str = ""


# Google's OAuth errors arrive as opaque strings. These map the three that
# account for almost every failed first-time setup onto the actual fix.
OAUTH_HINTS: tuple[tuple[str, str], ...] = (
    ("redirect_uri_mismatch",
     "The OAuth client is probably a 'Web application', not a 'Desktop app'.\n"
     "  A Desktop client accepts any localhost port; a Web client only accepts\n"
     "  redirect URIs you registered in advance.\n"
     "  Fix A (best): create a new OAuth client ID of type 'Desktop app'.\n"
     "  Fix B: keep the Web client, add http://localhost:8080/ to its\n"
     "         Authorised redirect URIs, then run: sentinel auth --port 8080"),
    ("access_denied",
     "Your Google account is not on the app's test-user list.\n"
     "  Owning the Cloud project does NOT make you a test user -- you have to\n"
     "  add yourself explicitly.\n"
     "  Fix: APIs & Services -> OAuth consent screen -> Audience -> Test users\n"
     "       -> Add users -> your own Gmail address -> Save. Then retry."),
    ("accessnotconfigured",
     "The Gmail API is not enabled on this project.\n"
     "  Fix: APIs & Services -> Library -> search 'Gmail API' -> Enable.\n"
     "       Wait a minute for it to propagate, then retry."),
)


def explain_oauth_error(exc: Exception) -> str:
    """Turn a raw OAuth failure into the specific console change that fixes it."""
    blob = f"{type(exc).__name__}: {exc}".lower()
    for needle, hint in OAUTH_HINTS:
        if needle in blob.replace("_", "").replace(" ", "") or needle in blob:
            return hint
    return ("No specific cause recognised. The three usual ones are:\n"
            "  1. OAuth client is 'Web application' instead of 'Desktop app'\n"
            "  2. your address is not under OAuth consent screen -> Test users\n"
            "  3. Gmail API not enabled on the project")


def _credentials(cfg: Settings, interactive: bool = False, port: int = 0):
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow

    token_path = Path(cfg.gmail_token_path)
    creds = None
    if token_path.exists():
        creds = Credentials.from_authorized_user_file(str(token_path), GMAIL_SCOPES)

    if creds and creds.valid:
        return creds
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
        token_path.write_text(creds.to_json())
        token_path.chmod(0o600)
        return creds

    if not interactive:
        raise RuntimeError(
            "No usable Gmail token. Run `python -m sentinel.cli auth` once to "
            "authorise read-only access.")

    if cfg.gmail_credentials_file:
        flow = InstalledAppFlow.from_client_secrets_file(
            cfg.gmail_credentials_file, GMAIL_SCOPES)
    elif cfg.gmail_client_id and cfg.gmail_client_secret:
        flow = InstalledAppFlow.from_client_config({
            "installed": {
                "client_id": cfg.gmail_client_id,
                "client_secret": cfg.gmail_client_secret,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": ["http://localhost"],
            }
        }, GMAIL_SCOPES)
    else:
        raise RuntimeError(
            "Set GMAIL_CLIENT_ID and GMAIL_CLIENT_SECRET (or "
            "GMAIL_CREDENTIALS_FILE) in .env. Note that a Google *API key* "
            "cannot read a mailbox -- Gmail requires OAuth.")

    creds = flow.run_local_server(port=port, prompt="consent",
                                  authorization_prompt_message="")
    token_path.write_text(creds.to_json())
    token_path.chmod(0o600)
    return creds


def authorise(cfg: Settings, port: int = 0) -> str:
    """Run the consent flow once and cache the refresh token.

    `port` defaults to 0 (any free port), which a Desktop-app client accepts.
    Pass a fixed port when the client is a Web application, so it matches a
    redirect URI registered in the console.
    """
    from googleapiclient.discovery import build
    creds = _credentials(cfg, interactive=True, port=port)
    profile = build("gmail", "v1", credentials=creds,
                    cache_discovery=False).users().getProfile(userId="me").execute()
    return profile.get("emailAddress", "unknown")


def fetch(cfg: Settings, query: str | None = None, limit: int | None = None,
          label: str | None = None) -> list[FetchedMessage]:
    from googleapiclient.discovery import build

    creds = _credentials(cfg)
    svc = build("gmail", "v1", credentials=creds, cache_discovery=False)
    q = query if query is not None else cfg.query
    n = limit if limit is not None else cfg.limit
    label_ids = [label or cfg.mailbox] if (label or cfg.mailbox) else None

    ids: list[dict] = []
    page = None
    while len(ids) < n:
        resp = svc.users().messages().list(
            userId="me", q=q or None, labelIds=label_ids,
            maxResults=min(500, n - len(ids)), pageToken=page).execute()
        ids.extend(resp.get("messages", []))
        page = resp.get("nextPageToken")
        if not page:
            break

    out: list[FetchedMessage] = []
    for m in ids[:n]:
        msg = svc.users().messages().get(userId="me", id=m["id"], format="raw").execute()
        out.append(FetchedMessage(
            provider_id=m["id"],
            raw=base64.urlsafe_b64decode(msg["raw"].encode("ascii")),
            labels=tuple(msg.get("labelIds", ())),
            thread_id=msg.get("threadId", ""),
        ))
    return out


def to_email(fetched: FetchedMessage):
    email = from_message(message_from_bytes(fetched.raw), source="gmail")
    if not email.message_id:
        email.message_id = fetched.provider_id
    email.provider_id = fetched.provider_id      # type: ignore[attr-defined]
    email.labels = fetched.labels                # type: ignore[attr-defined]
    return email
