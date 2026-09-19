"""Build the pool of real messages the Learner practises on.

The Learner could only ever teach from whatever happened to be in the user's
mailbox, which for most people is newsletters. 81,234 labelled messages were
sitting unused. This turns them into exercises.

One decision governs everything here, and it is about which labels can be
trusted as an answer key:

    label   (malicious / benign)  is the corpus's own ground truth. Reliable.
    vector  (which kind of attack) is derived from weak rules, and measured
            against independent labels at roughly 68%. NOT reliable.

So the deterministic exercises -- is this hostile, which of these two is the
scam, where is the tell -- are graded against `label` and against the exact
character spans the lexicons matched. Nothing here grades a learner against
the vector, because being marked wrong for a correct answer is worse than not
asking the question.

Twins are the interesting part. For each malicious message the index finds the
BENIGN message it most resembles, and the pair becomes a side-by-side. Pharma
spam sits at 0.89 cosine to a legitimate course-sale email, because both are
built on "limited time offer" -- and that is exactly the discrimination people
fail at. Training that only shows obvious fakes teaches "scams look weird",
which is the wrong lesson and the one attackers rely on.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sentinel.config import ARTIFACTS, RANDOM_SEED
from sentinel.features import lexicons as lx

POOL_PATH = ARTIFACTS / "practice_pool.json"

# Long enough to reason about, short enough to read on screen.
MIN_WORDS, MAX_CHARS = 25, 1400
N_ITEMS = 900          # per class
N_TWINS = 320

# Lexicons whose matches are a genuine "tell" a person could be asked to find.
# Bulk-mail furniture is excluded: an unsubscribe footer is not a tell.
TELL_LEXICONS = {
    "urgency", "credential_request", "payment", "money_request", "threat",
    "authority", "secrecy", "reward", "identity_claim", "it_support",
    "sextortion", "crypto", "attachment_lure", "job_scam", "investment_scam",
    "tech_support_scam", "delivery_scam", "govt_impersonation", "charity_fraud",
    "romance", "impersonated_brand",
}


def clean(t: str) -> str:
    return re.sub(r"\s+", " ", str(t or "")).strip()


# Traffic nobody can sensibly be asked to judge. The first exercise anyone saw
# was a 2007 SourceForge SVN commit notification -- automated changeset mail
# with a diff in it. "Is this hostile?" has no answer a person could reason to,
# and being marked wrong on it teaches nothing but distrust of the exercise.
JUNK_RE = re.compile(
    r"(?i)(\[[\w.-]+-(?:checkins|commits|dev|users|announce|list)\]"
    r"|sf\.net svn|svn commit|revision:\s*\d+|modified paths"
    r"|^-{10,}|diff --git|\+\+\+ |--- trunk|cvs commit"
    r"|unsubscribe from this list|list-unsubscribe"
    r"|mailman/listinfo|majordomo|/mailman/|to unsubscribe,? (?:e-?mail|send)"
    r"|^_{20,}|\bdigest\b.{0,20}\bvol\b|reply-to:\s*<?[\w.-]+-list)")

# The corpora are tokenised for model training: lowercased, punctuation spaced
# out ("2 : 00 pm meeting"). That is fine for fitting a classifier and unusable
# as something a person is asked to read.
# Almost every mailing list prefixes its subject with a bracketed tag --
# [opensuse], [ILUG], [UAI]. The first filter only caught tags ending in
# -list or -dev, so the drill kept serving list threads about printer drivers.
LIST_SUBJECT_RE = re.compile(r"^\s*(?:(?:re|fw|fwd)\s*:\s*)*\[[\w .+-]{2,24}\]", re.I)


def readable(body: str, subject: str = "") -> bool:
    if LIST_SUBJECT_RE.match(subject or ""):
        return False
    if JUNK_RE.search(subject or "") or JUNK_RE.search(body):
        return False
    letters = sum(c.isalpha() for c in body)
    if letters < len(body) * 0.55:          # code, diffs, base64, markup
        return False
    if len(re.findall(r"\s[:,.;!?]\s", body)) > 4:   # spaced punctuation
        return False
    if sum(c.isupper() for c in body if c.isalpha()) < letters * 0.01:
        return False                        # fully lowercased = tokenised
    return True


def main() -> None:
    meta = pd.read_parquet(ARTIFACTS / "meta.parquet")
    text = pd.read_parquet(ARTIFACTS / "text.parquet")["text"].astype(str)
    meta = meta.assign(text=text.values)

    # Training split only. A held-out message is what the evaluation scores
    # against, and practising on it would quietly contaminate that.
    meta = meta[meta.split == "train"]
    meta = meta[meta.text.str.split().str.len().between(MIN_WORDS, 400)]
    before = len(meta)
    keep = [readable(clean(t)[:MAX_CHARS], clean(su))
            for t, su in zip(meta.text, meta.subject)]
    meta = meta[keep]
    print(f"{before:,} candidates -> {len(meta):,} readable "
          f"({before - len(meta):,} dropped as list traffic, code or tokenised)")

    rng = np.random.default_rng(RANDOM_SEED)

    def sample(df, n):
        n = min(n, len(df))
        return df.iloc[rng.choice(len(df), size=n, replace=False)]

    # Malicious messages are drawn span-aware. A blind sample gave 194 of 900
    # with a usable tell -- most corpus spam is old pharma advertising that
    # matches no manipulation lexicon -- which is too thin a pool for an
    # exercise that asks the learner to find one. So a wider candidate set is
    # scanned first and the ones carrying a tell are preferred, with a minority
    # of plain ones kept so the pool is not only vivid examples.
    def spans_for(body: str) -> list[dict]:
        hits = [h for h in lx.scan(body, "body") if h.lexicon in TELL_LEXICONS]
        seen, out = set(), []
        for h in hits:
            key = (h.start, h.end)
            if key in seen or h.end <= h.start:
                continue
            seen.add(key)
            out.append({"start": h.start, "end": h.end, "lexicon": h.lexicon,
                        "term": body[h.start:h.end][:80]})
        return out[:12]

    cand = sample(meta[meta.label == 1], min(len(meta[meta.label == 1]), N_ITEMS * 6))
    cand = cand.assign(bodytext=[clean(t)[:MAX_CHARS] for t in cand.text])
    cand = cand.assign(tellspans=[spans_for(b) for b in cand.bodytext])
    rich = cand[cand.tellspans.str.len() > 0]
    plain = cand[cand.tellspans.str.len() == 0]
    n_rich = min(len(rich), int(N_ITEMS * 0.8))
    mal = pd.concat([rich.iloc[:n_rich], sample(plain, N_ITEMS - n_rich)])
    print(f"  malicious pool: {n_rich} with a tell, {len(mal) - n_rich} without")

    ben = sample(meta[meta.label == 0], N_ITEMS)
    ben = ben.assign(bodytext=[clean(t)[:MAX_CHARS] for t in ben.text])
    ben = ben.assign(tellspans=[[] for _ in range(len(ben))])
    picked = pd.concat([mal, ben])

    items = []
    for row in picked.itertuples():
        # Spans were computed on the SAME string the browser will show, so the
        # offsets line up with what the learner actually clicks.
        body = row.bodytext
        spans = list(row.tellspans)
        items.append({
            "id": f"c{len(items)}",
            "subject": clean(row.subject)[:140] or "(no subject)",
            "sender": clean(row.sender)[:90],
            "body": body,
            "label": int(row.label),
            "vector": str(row.vector),
            "vector_confidence": float(row.vector_confidence or 0),
            "source": str(row.source),
            "spans": spans[:12],
        })

    with_tells = [i for i in items if i["label"] == 1 and i["spans"]]
    print(f"  {len(items):,} items  ({len(with_tells):,} malicious with usable spans)")

    # ---------------------------------------------------------------- twins
    twins = []
    try:
        from sentinel.similarity import encode
        mal = [i for i in items if i["label"] == 1]
        ben = [i for i in items if i["label"] == 0]
        M = encode([i["body"] for i in mal])
        B = encode([i["body"] for i in ben])
        sims = M @ B.T
        best = sims.argmax(1)
        order = np.argsort(-sims.max(1))
        for k in order[:N_TWINS]:
            s = float(sims[k, best[k]])
            # Below this they are simply two unrelated messages, and the
            # exercise degenerates into "which one looks odd".
            if s < 0.55:
                break
            twins.append({"malicious": mal[k]["id"], "benign": ben[best[k]]["id"],
                          "similarity": round(s, 4)})
        print(f"  {len(twins):,} twin pairs "
              f"(similarity {twins[-1]['similarity']:.2f}–{twins[0]['similarity']:.2f})"
              if twins else "  no twins")
    except Exception as e:
        print(f"  twins skipped: {type(e).__name__}: {e}")

    # Keep anything already generated: it is better material and cost tokens.
    if POOL_PATH.exists():
        try:
            prev = json.loads(POOL_PATH.read_text())
            gen = [i for i in prev.get("items", []) if i.get("source") == "simulated"]
            gen_ids = {i["id"] for i in gen}
            items = gen + items
            twins = [t for t in prev.get("twins", [])
                     if t["malicious"] in gen_ids and t["benign"] in gen_ids] + twins
            print(f"  kept {len(gen)} previously generated items")
        except (json.JSONDecodeError, OSError):
            pass

    POOL_PATH.write_text(json.dumps({"items": items, "twins": twins}))
    print(f"  -> {POOL_PATH} ({POOL_PATH.stat().st_size / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
