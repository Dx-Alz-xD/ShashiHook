"""Profile what the recipient is actually exposed to, from local mail."""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sentinel.config import ARTIFACTS
from sentinel.recipient import build
from sentinel.settings import settings


def main() -> None:
    src = ARTIFACTS / "local_ham.parquet"
    if not src.exists():
        print("Needs artifacts/local_ham.parquet — run scripts/build_local_corpus.py first.")
        return
    df = pd.read_parquet(src)
    p = build(zip(df.subject.fillna(""), df.body.fillna("")), address=settings.imap_user)
    p.save()
    print(f"Recipient profile for {p.address or '(unknown)'}")
    print(f"  {p.describe()}")
    print(f"  dominant exposure: {p.dominant}")
    print(f"\n  saved to {ARTIFACTS/'recipient_profile.json'} (mode 0600, gitignored)")


if __name__ == "__main__":
    main()
