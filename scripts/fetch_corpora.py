"""Download the public raw-mail corpora used for training.

Nazario phishing corpus -- https://monkey.org/~jose/phishing/ -- CC-BY-4.0,
hand-classified by Jose Nazario. Attribution required; see DATA.md.
"""
from __future__ import annotations

import sys
import urllib.request
from pathlib import Path

BASE = "https://monkey.org/~jose/phishing/"
FILES = ("phishing0.mbox", "phishing1.mbox", "phishing2.mbox",
         "phishing3.mbox", "20051114.mbox", "LICENSE.txt")
DEST = Path(__file__).resolve().parent.parent / "data" / "nazario"


def main() -> None:
    DEST.mkdir(parents=True, exist_ok=True)
    for name in FILES:
        out = DEST / name
        if out.exists() and out.stat().st_size > 0:
            print(f"  {name}: already present ({out.stat().st_size/1e6:.1f} MB)")
            continue
        print(f"  fetching {name} …", flush=True)
        urllib.request.urlretrieve(BASE + name, out)
        print(f"    {out.stat().st_size/1e6:.1f} MB")
    print(f"\nSaved to {DEST}")
    print("Nazario phishing corpus, CC-BY-4.0 — attribution required.")


if __name__ == "__main__":
    main()
