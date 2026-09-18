"""Measure how often thread verification calls a genuine reply fabricated.

`fabricated_thread` is close to proof of fraud when it is right, and it was
badly wrong once already: 2,266 hits on held-out mail, 2,261 of them benign,
because a 2002 mailing-list reply is not in a 2026 Gmail account. That was a
corpus artefact and `disable_for_corpus()` exists because of it. It left the
real question open -- on a genuine mailbox, verifying genuine replies, how
often does this fire?

The raw Enron export answers it. 150 real mailboxes, real reply chains, and
nothing in them is a thread hijack. Every fabricated verdict here is a false
positive, so the rate this prints is the feature's real-world FP rate.

Note the export carries no In-Reply-To or References headers -- JavaMail
stripped them, they are at 0.0%. So this exercises the quoted-text path only,
which is the path that matters: message-id resolution is the easy case.

Deployment is simulated in time order, not leave-one-out: each mailbox is split
by date, the earlier share builds the index and the later share is verified.
Indexing a message and then verifying it would let its own quoted text match
itself, which would prove nothing.
"""
from __future__ import annotations

import re
import sys
from collections import defaultdict
from email import message_from_string
from email.utils import parsedate_to_datetime
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sentinel.config import PROJECT_ROOT
from sentinel.threads import ThreadIndex, extract_quoted, verify

SRC = PROJECT_ROOT / "data" / "kaggle" / "enron.csv"
MIN_MAILBOX = 400


class Msg:
    """The handful of attributes verify() reads."""
    def __init__(self, subject, body, in_reply_to="", references=""):
        self.subject, self.body = subject, body
        self.in_reply_to, self.references = in_reply_to, references


def body_of(m) -> str:
    if m.is_multipart():
        return "\n".join(p.get_payload(decode=False) or ""
                         for p in m.walk() if p.get_content_type() == "text/plain")
    return m.get_payload(decode=False) or ""


def main(limit: int = 250_000) -> None:
    if not SRC.exists():
        print(f"{SRC} not found"); return
    boxes: dict[str, list] = defaultdict(list)
    # Deduplicate WITHIN a mailbox, never across. Enron stores a message in both
    # the sender's and the recipient's folder, and a global seen-set hands it to
    # whichever mailbox is read first -- stripping from the other mailbox exactly
    # the originals its replies quote, which is a flaw in the harness, not the
    # feature. It read 83.5% false before this was corrected.
    seen: dict[str, set[str]] = defaultdict(set)
    n = 0
    for chunk in pd.read_csv(SRC, chunksize=20_000):
        for path, raw in zip(chunk["file"], chunk["message"]):
            n += 1
            user = str(path).split("/")[0]
            try:
                m = message_from_string(raw)
            except Exception:
                continue
            mid = (m.get("Message-ID") or "").strip().strip("<>")
            if not mid or mid in seen[user]:
                continue
            seen[user].add(mid)
            try:
                dt = parsedate_to_datetime(m.get("Date") or "")
            except Exception:
                continue
            boxes[user].append((dt, mid, m.get("Subject") or "", body_of(m)))
        if n >= limit:
            break
    boxes = {u: v for u, v in boxes.items() if len(v) >= MIN_MAILBOX}
    print(f"scanned {n:,} rows -> {sum(len(v) for v in seen.values()):,} mailbox-messages, "
          f"{len(boxes)} mailboxes with >= {MIN_MAILBOX}")

    tot = defaultdict(int)
    per_box = []
    for user, msgs in boxes.items():
        msgs.sort(key=lambda r: (r[0] is None, r[0]))
        idx = ThreadIndex()
        fab = claims = 0
        # Verify, then index. A fixed 70/30 split cannot see a reply whose
        # original also fell in the held-out tail, which is most of them; in
        # deployment the index grows with every message that arrives.
        for _, mid, subj, body in msgs:
            if not extract_quoted(body):
                idx.add(mid, subj, body)
                continue
            v = verify(Msg(subj, body), idx)
            idx.add(mid, subj, body)
            if not v.claims_thread:
                continue
            claims += 1
            tot["claims"] += 1
            tot["genuine"] += int(not v.fabricated and not v.indeterminate)
            tot["indeterminate"] += int(v.indeterminate)
            if v.fabricated:
                fab += 1; tot["fabricated"] += 1
        if claims:
            per_box.append((fab / claims, user, fab, claims))

    c = tot["claims"]
    if not c:
        print("no quoted replies found"); return
    print(f"\n  quoted replies verified      {c:,}")
    print(f"    matched the mailbox        {tot['genuine']:,} ({tot['genuine']/c:.1%})")
    print(f"    indeterminate              {tot['indeterminate']:,} ({tot['indeterminate']/c:.1%})")
    print(f"    FLAGGED FABRICATED         {tot['fabricated']:,} ({tot['fabricated']/c:.1%})  <-- all false")
    per_box.sort(reverse=True)
    print("\n  worst mailboxes by false-fabrication rate:")
    for r, u, f, cl in per_box[:8]:
        print(f"    {u:<16}{r:>7.1%}  ({f}/{cl})")


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 250_000)
