"""Cache legitimate mail from your own mailbox as training data.

Why this exists: adding the Nazario phishing corpus to the intent model made it
worse, because it is 3,000 positives with no matching negatives -- the wording
model concluded that transactional vocabulary is hostile and started flagging
genuine invoices. Positives need matching ham from the same era and the same
kind of mail stream.

The best available source of modern, header-complete, legitimate mail is the
user's own inbox. It is real, it is current, it is DKIM-signed, and it matches
the exact distribution the model will be deployed against.

PRIVACY, because this is personal correspondence:
  * Everything stays on this machine. The cache is written to artifacts/ and
    gitignored, chmod 0600.
  * Only mail from DKIM/SPF-authenticated senders is kept, which both raises
    label quality and excludes the spoofed mail that should not be labelled
    benign.
  * Trained model weights derived from it are also local. Do not publish a model
    trained on private mail without understanding that text can be partially
    recovered from model parameters.
  * Delete artifacts/local_ham.parquet at any time; nothing else depends on it.

Labelling caveat: INBOX is treated as benign. Gmail has already moved obvious
spam to the Spam folder, but marketing and graymail remain and will be labelled
benign here. For a threat detector that is defensible -- newsletters are not
attacks -- but it is a real assumption, not a certainty.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sentinel.config import ARTIFACTS
from sentinel.features.extractor import strip_html
from sentinel.ingest import imap_box
from sentinel.scoring.floors import sender_is_authenticated
from sentinel.features.extractor import extract
from sentinel.settings import settings


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=3000)
    ap.add_argument("--folder", default="INBOX")
    ap.add_argument("--query", default="")
    ap.add_argument("--authenticated-only", action="store_true", default=True)
    args = ap.parse_args()

    if not settings.has_imap:
        print("Needs IMAP. Set IMAP_USER and IMAP_APP_PASSWORD in .env.")
        return

    print(f"Fetching up to {args.limit:,} messages from {args.folder}")
    print("This is YOUR mail. It stays on this machine and is gitignored.\n")
    msgs = imap_box.fetch(settings, args.query, args.limit, mailbox=args.folder)
    print(f"  fetched {len(msgs):,}")

    rows, skipped_unauth, skipped_empty = [], 0, 0
    for i, m in enumerate(msgs):
        try:
            e = imap_box.to_email(m)
        except Exception:
            continue
        body = strip_html(e.body or "")
        if len(body.split()) < 3:
            skipped_empty += 1
            continue
        if args.authenticated_only:
            _, ev = extract(e)
            ok, _ = sender_is_authenticated(e, ev)
            if not ok:
                skipped_unauth += 1
                continue
        rows.append({
            "source": "local_ham", "sender": e.sender or "", "receiver": e.receiver or "",
            "date": e.date or "", "subject": e.subject or "", "body": body, "label": 0,
            "reply_to": e.reply_to or "", "return_path": e.return_path or "",
            "auth_results": e.auth_results or "",
            "attachments": "|".join(e.attachments),
        })
        if (i + 1) % 500 == 0:
            print(f"  processed {i+1:,}/{len(msgs):,}")

    df = pd.DataFrame(rows)
    out = ARTIFACTS / "local_ham.parquet"
    df.to_parquet(out, index=False)
    out.chmod(0o600)

    print(f"\n  kept    {len(df):,} authenticated legitimate messages")
    print(f"  skipped {skipped_unauth:,} unauthenticated, {skipped_empty:,} empty")
    print(f"  saved   {out} (mode 0600, gitignored)")
    if len(df):
        doms = df["sender"].str.extract(r"@([\w.-]+)", expand=False).str.lower()
        print(f"\n  {doms.nunique():,} distinct sending domains; top 8:")
        for d, n in doms.value_counts().head(8).items():
            print(f"    {d:34} {n:>5}")
    print("\nRe-run scripts/build_dataset.py and scripts/train_intent.py to use it.")


if __name__ == "__main__":
    main()
