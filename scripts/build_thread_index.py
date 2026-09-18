"""Index the mailbox so a quoted conversation can be verified.

Stores hashed 5-word shingles, message-ids and normalised subjects -- never
message text. The index can confirm that a quote matches something you
received without holding what was said.

Coverage matters: absence of a match only means fabrication if the index
actually spans the period the message claims to continue. Index generously.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sentinel.features.extractor import strip_html
from sentinel.ingest import imap_box
from sentinel.settings import settings
from sentinel.threads import INDEX_PATH, ThreadIndex


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=1500)
    ap.add_argument("--query", default="newer_than:365d")
    ap.add_argument("--folders", default="INBOX,[Gmail]/Sent Mail")
    args = ap.parse_args()
    if not settings.has_imap:
        print("Needs IMAP. Set IMAP_USER and IMAP_APP_PASSWORD in .env.")
        return

    ix = ThreadIndex()
    t0 = time.time()
    for folder in args.folders.split(","):
        folder = folder.strip()
        print(f"  indexing {folder} …", flush=True)
        try:
            msgs = imap_box.fetch(settings, args.query, args.limit, mailbox=folder)
        except Exception as e:
            print(f"    skipped: {e}")
            continue
        for m in msgs:
            try:
                e = imap_box.to_email(m)
            except Exception:
                continue
            ix.add(e.message_id, e.subject, strip_html(e.body or ""))
        print(f"    {len(msgs)} messages")

    ix.save()
    print(f"\n  {ix.messages_indexed:,} messages indexed in {time.time()-t0:.0f}s")
    print(f"  {len(ix.message_ids):,} message-ids · {len(ix.subjects):,} subjects "
          f"· {len(ix.shingle_to_id):,} text fingerprints")
    print(f"  saved to {INDEX_PATH} (mode 0600, gitignored — hashes only, no message text)")


if __name__ == "__main__":
    main()
