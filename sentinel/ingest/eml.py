"""Parse real RFC-5322 messages into the canonical Email record.

The training corpora are flat CSVs, but production input is .eml or an API
payload. This adapter is where the signals the CSVs could not carry -- real
MIME attachments, Reply-To, Return-Path, authentication results -- enter the
pipeline.
"""
from __future__ import annotations

from email import message_from_bytes, message_from_string
from email.header import decode_header, make_header
from email.message import Message
from pathlib import Path

from ..features.extractor import Email


def _decode(value: str | None) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def _walk_bodies(msg: Message) -> tuple[str, str | None]:
    """Return (plain text, html). Prefers text/plain, keeps HTML for link analysis."""
    plain_parts: list[str] = []
    html_parts: list[str] = []
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        if part.get_filename():
            continue
        ctype = part.get_content_type()
        try:
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            charset = part.get_content_charset() or "utf-8"
            text = payload.decode(charset, errors="replace")
        except Exception:
            continue
        if ctype == "text/plain":
            plain_parts.append(text)
        elif ctype == "text/html":
            html_parts.append(text)
    html = "\n".join(html_parts) if html_parts else None
    plain = "\n".join(plain_parts)
    if not plain and html:
        plain = html
    return plain, html


def _attachments(msg: Message) -> list[str]:
    out: list[str] = []
    for part in msg.walk():
        name = part.get_filename()
        if name:
            out.append(_decode(name))
    return out


def from_message(msg: Message, source: str = "eml") -> Email:
    body, html = _walk_bodies(msg)
    sender = _decode(msg.get("From"))
    reply_to = _decode(msg.get("Reply-To"))
    return_path = _decode(msg.get("Return-Path"))

    email = Email(
        subject=_decode(msg.get("Subject")),
        body=body,
        html=html,
        sender=sender,
        receiver=_decode(msg.get("To")),
        date=_decode(msg.get("Date")),
        attachments=_attachments(msg),
        message_id=_decode(msg.get("Message-ID")),
        source=source,
        reply_to=reply_to,
        return_path=return_path,
        auth_results=_decode(msg.get("Authentication-Results")),
        in_reply_to=_decode(msg.get("In-Reply-To")),
        references=_decode(msg.get("References")),
        raw_message=msg,
    )
    return email


def from_file(path: str | Path) -> Email:
    return from_message(message_from_bytes(Path(path).read_bytes()),
                        source=f"file:{Path(path).name}")


def from_string(raw: str) -> Email:
    return from_message(message_from_string(raw), source="raw")
