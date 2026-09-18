"""Load the six source corpora into one canonical schema.

Each file on disk has a different shape; this module normalises them, records
where every row came from, and removes the cross-corpus duplicates that would
otherwise leak between the train and test splits.
"""
from __future__ import annotations

import hashlib
import re
import warnings

import pandas as pd

from ..config import SOURCES
from ..features.extractor import Email

warnings.filterwarnings("ignore", category=UserWarning)

CANON_COLUMNS = ["source", "sender", "receiver", "date", "subject", "body", "label"]
# Columns that only raw-mail sources can supply. The CSV corpora leave them
# blank; the deterministic layer uses them when present.
HEADER_COLUMNS = ["reply_to", "return_path", "auth_results", "attachments"]


def _read(path, **kw) -> pd.DataFrame:
    # The C parser handles the embedded newlines in these bodies correctly;
    # the Python fallback parser silently shreds Enron.csv and SpamAssasin.csv
    # into thousands of fragment rows.
    return pd.read_csv(path, engine="c", on_bad_lines="skip", **kw)


def _coerce_label(s: pd.Series) -> pd.Series:
    return pd.to_numeric(s, errors="coerce")


def load_source(name: str) -> pd.DataFrame:
    path = SOURCES[name]
    if not path.exists():
        raise FileNotFoundError(path)

    if name == "enron_spam":
        df = _read(path).rename(columns={"text": "body", "spam": "label"})
        # Rows are one flattened line beginning "Subject: ...". There is no
        # newline to split on -- the subject ends at the first run of two or
        # more spaces -- so splitting on a line break would delete the message.
        split = df["body"].astype(str).str.extract(
            r"^\s*Subject:\s*(?P<subject>.*?)(?:\r?\n|\s{2,})(?P<rest>.*)$",
            expand=True, flags=re.S,
        )
        df["subject"] = split["subject"].fillna("")
        df["body"] = split["rest"].fillna(df["body"].astype(str))
        df["sender"] = ""
        df["receiver"] = ""
        df["date"] = ""
    else:
        df = _read(path)
        for col in ("sender", "receiver", "date", "subject", "body"):
            if col not in df.columns:
                df[col] = ""

    df["label"] = _coerce_label(df["label"])
    df = df[df["label"].isin([0, 1])].copy()
    df["label"] = df["label"].astype(int)
    df["source"] = name

    for col in ("sender", "receiver", "date", "subject", "body"):
        df[col] = df[col].fillna("").astype(str)

    df = df[df["body"].str.strip().str.len() > 0]
    return df[CANON_COLUMNS]


def _content_key(subject: str, body: str) -> str:
    """Normalised fingerprint used for cross-corpus de-duplication.

    Lowercased, punctuation-free, whitespace-collapsed, first 400 characters of
    subject+body. Robust to the re-encoding differences between corpora while
    still distinguishing genuinely different messages.
    """
    blob = f"{subject} {body}".lower()
    blob = re.sub(r"[^a-z0-9 ]+", " ", blob)
    blob = re.sub(r"\s+", " ", blob).strip()[:400]
    return hashlib.sha1(blob.encode("utf-8", "ignore")).hexdigest()


def load_all(dedupe: bool = True, verbose: bool = True,
             include_raw: bool = True) -> pd.DataFrame:
    frames = []
    for name in SOURCES:
        df = load_source(name)
        for c in HEADER_COLUMNS:
            df[c] = ""
        if verbose:
            n1 = int((df["label"] == 1).sum())
            print(f"  {name:16} {len(df):>7,} rows   malicious={n1:>6,}  benign={len(df)-n1:>6,}")
        frames.append(df)

    if include_raw:
        try:
            from .mbox_loader import load_nazario
            nz = load_nazario(verbose=False)
            if len(nz):
                nz = nz[CANON_COLUMNS + HEADER_COLUMNS]
                if verbose:
                    print(f"  {'nazario (mbox)':16} {len(nz):>7,} rows   "
                          f"malicious={len(nz):>6,}  benign={0:>6,}   "
                          f"[raw RFC-5322, carries headers]")
                frames.append(nz)
        except FileNotFoundError:
            if verbose:
                print("  nazario           not downloaded "
                      "(run scripts/fetch_corpora.py) — skipping")

        # Legitimate mail cached from the user's own mailbox. This is what gives
        # the phishing-only Nazario corpus a matching negative set, and it is the
        # only modern, header-complete ham available. Never committed.
        from ..config import ARTIFACTS
        local = ARTIFACTS / "local_ham.parquet"
        if local.exists():
            lh = pd.read_parquet(local)
            if len(lh):
                for c in CANON_COLUMNS + HEADER_COLUMNS:
                    if c not in lh.columns:
                        lh[c] = ""
                lh = lh[CANON_COLUMNS + HEADER_COLUMNS]
                if verbose:
                    print(f"  {'local_ham':16} {len(lh):>7,} rows   malicious={0:>6,}  "
                          f"benign={len(lh):>6,}   [your own mailbox, stays local]")
                frames.append(lh)

    all_df = pd.concat(frames, ignore_index=True)
    before = len(all_df)
    all_df["content_key"] = [
        _content_key(s, b) for s, b in zip(all_df["subject"], all_df["body"])
    ]

    if dedupe:
        # Keep the first occurrence; source order in config puts the
        # header-bearing corpora first, so the richer copy survives.
        conflicting = (
            all_df.groupby("content_key")["label"].nunique().pipe(lambda s: s[s > 1]).index
        )
        n_conflict = len(conflicting)
        all_df = all_df[~all_df["content_key"].isin(conflicting)]
        all_df = all_df.drop_duplicates(subset="content_key", keep="first").reset_index(drop=True)
        if verbose:
            print(f"  {'dedupe':16} {before:,} -> {len(all_df):,} "
                  f"({before - len(all_df):,} removed, of which {n_conflict:,} "
                  f"were label-conflicting duplicates dropped entirely)")

    if verbose:
        n1 = int((all_df["label"] == 1).sum())
        print(f"  {'TOTAL':16} {len(all_df):>7,} rows   malicious={n1:>6,} "
              f"({n1/len(all_df):.1%})  benign={len(all_df)-n1:>6,}")
    return all_df


def row_to_email(row) -> Email:
    """Canonical row -> Email, carrying raw-mail headers when the source had them."""
    atts = getattr(row, "attachments", "") or ""
    return Email(
        subject=row.subject,
        body=row.body,
        sender=row.sender,
        receiver=row.receiver,
        date=row.date,
        source=row.source,
        reply_to=getattr(row, "reply_to", "") or "",
        return_path=getattr(row, "return_path", "") or "",
        auth_results=getattr(row, "auth_results", "") or "",
        attachments=[a for a in atts.split("|") if a],
    )


def frame_to_emails(df: pd.DataFrame) -> list[Email]:
    return [row_to_email(r) for r in df.itertuples(index=False)]
