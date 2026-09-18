"""Learn how each of your correspondents writes.

Run this once over the mailbox, then again whenever it is worth refreshing.
It reads mail, measures the habits described in sentinel/stylometry.py, and
stores a few hundred floats per sender. No message text is kept -- the profile
is rates and averages, and the file it writes is chmod 600 because knowing how
somebody writes is still information about them.

What it buys: if a colleague's account is taken over, the headers stay perfect
-- real address, valid SPF, valid DKIM, genuine history -- and the only thing
that changes is the writing. That is the gap this closes.

What it does not buy: certainty. Measured across 362 Enron senders, at a
threshold that mislabels 1% of genuine mail this catches about 12% of messages
written by somebody else. It is corroboration, not an accusation, which is why
it is a model feature and not a deterministic floor.
"""
from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sentinel.ingest import imap_box
from sentinel.settings import settings
from sentinel.stylometry import (MIN_MESSAGES, MIN_TOKENS, StyleStore, traits)


def main(query: str = "newer_than:730d", limit: int = 4000) -> None:
    store = StyleStore.load()
    before = len(store.profiles)
    seen = Counter()
    usable = 0

    print(f"Reading mail ({query}, up to {limit:,})")
    for raw in imap_box.fetch(settings, query, limit):
        try:
            e = imap_box.to_email(raw)
        except Exception:
            continue
        body = e.body or ""
        if e.html:
            from sentinel.features.extractor import strip_html
            body = strip_html(body)
        addr = (getattr(e, "sender_address", "") or e.sender or "")
        if "<" in addr:
            addr = addr.split("<")[-1].rstrip(">")
        addr = addr.strip().lower()
        if not addr:
            continue
        seen[addr] += 1
        if traits(body) is not None:
            store.observe(addr, body)
            usable += 1

    # The population spread has to be fitted after every profile exists: it is
    # what makes one trait comparable to another, and it is taken across
    # senders so no single prolific correspondent defines "normal".
    store.fit_population()
    ready = [p for p in store.profiles.values() if p.ready]
    store.save()

    print(f"\n  messages read            {sum(seen.values()):,}")
    print(f"  long enough to measure   {usable:,} ({MIN_TOKENS}+ words)")
    print(f"  senders seen             {len(seen):,}")
    print(f"  profiles held            {len(store.profiles):,} "
          f"({len(store.profiles) - before:+,} new)")
    print(f"  ready to judge           {len(ready):,} "
          f"(need {MIN_MESSAGES} long messages each)")
    print(f"  traits calibrated        {len(store.pop_sd):,}")
    if ready:
        print("\n  best-covered senders:")
        for p in sorted(ready, key=lambda x: -x.n)[:8]:
            print(f"    {p.address[:46]:<48}{p.n:>4} messages")
    else:
        print("\n  No sender has enough long messages yet. Style comparison "
              "stays off until one does, which is the correct behaviour "
              "rather than a failure.")


if __name__ == "__main__":
    q = sys.argv[1] if len(sys.argv) > 1 else "newer_than:730d"
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 4000
    main(q, n)
