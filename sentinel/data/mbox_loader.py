"""Load raw mbox corpora into the canonical schema.

The CSV corpora lost everything above the subject line. An mbox keeps the whole
RFC-5322 message, so this loader recovers Reply-To, Return-Path, the Received
chain and real MIME attachments -- the signals the deterministic layer uses and
the flat corpora could never carry.

Source: the Nazario phishing corpus (https://monkey.org/~jose/phishing/),
CC-BY-4.0, hand-classified by Jose Nazario. Attribution is required and is
recorded in DATA.md.
"""
from __future__ import annotations

import mailbox
import re
from pathlib import Path

import pandas as pd

from ..features.extractor import Email
from ..ingest.eml import from_message

NAZARIO_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "nazario"
# Later files in the series are newer; the year is not in the filename, so the
# message Date header is the only ordering available.
YEAR_RE = re.compile(r"(19|20)\d{2}")


def _to_row(e: Email, source: str) -> dict:
    return {
        "source": source,
        "sender": e.sender or "",
        "receiver": e.receiver or "",
        "date": e.date or "",
        "subject": e.subject or "",
        "body": e.body or "",
        "label": 1,
        "reply_to": e.reply_to or "",
        "return_path": e.return_path or "",
        "auth_results": e.auth_results or "",
        "n_attachments": len(e.attachments),
        "attachments": "|".join(e.attachments),
    }


def load_mbox(path: Path, label: int = 1, limit: int | None = None) -> list[dict]:
    rows: list[dict] = []
    try:
        box = mailbox.mbox(str(path))
    except Exception as exc:
        print(f"  {path.name}: cannot open ({exc})")
        return rows
    for i, msg in enumerate(box):
        if limit and len(rows) >= limit:
            break
        try:
            e = from_message(msg, source=path.stem)
        except Exception:
            continue
        if not (e.body or "").strip() and not (e.subject or "").strip():
            continue
        r = _to_row(e, f"nazario:{path.stem}")
        r["label"] = label
        rows.append(r)
    return rows


def load_nazario(directory: Path = NAZARIO_DIR, verbose: bool = True) -> pd.DataFrame:
    if not directory.exists():
        raise FileNotFoundError(
            f"{directory} not found. Download the corpus first:\n"
            f"  python scripts/fetch_corpora.py")
    frames: list[dict] = []
    for p in sorted(directory.glob("*.mbox")):
        rows = load_mbox(p)
        if verbose:
            with_hdr = sum(1 for r in rows if r["sender"])
            print(f"  {p.name:22} {len(rows):>6,} messages  "
                  f"({with_hdr:,} with a From header)")
        frames.extend(rows)
    df = pd.DataFrame(frames)
    if verbose and len(df):
        years = df["date"].str.extract(r"((?:19|20)\d{2})", expand=False).dropna()
        if len(years):
            vc = years.value_counts().sort_index()
            span = f"{vc.index.min()}-{vc.index.max()}"
            print(f"  {'TOTAL':22} {len(df):>6,} messages, spanning {span}")
    return df
