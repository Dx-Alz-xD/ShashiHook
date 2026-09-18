"""Embed the corpus so a new message can be compared against what is known.

Runs once over the 81,234 labelled messages and writes a float16 matrix. The
model is a static embedding table rather than a transformer, so this is minutes
rather than hours and needs no GPU.

Only the training split is indexed. Held-out messages are what the evaluation
scores against, and an index containing them would let a message retrieve
itself -- the same self-match that made the thread-verification harness read
83.5% before it was grown in arrival order.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sentinel.config import ARTIFACTS
from sentinel.similarity import INDEX_PATH, SimilarityIndex, encode

BATCH = 2000


def main(limit: int = 0) -> None:
    meta = pd.read_parquet(ARTIFACTS / "meta.parquet")
    text = pd.read_parquet(ARTIFACTS / "text.parquet")["text"].astype(str)
    keep = (meta.split == "train").to_numpy()
    idx = np.where(keep)[0]
    if limit:
        idx = idx[:limit]
    print(f"indexing {len(idx):,} training messages "
          f"({int((meta.label.to_numpy()[idx] == 1).sum()):,} malicious)")

    t0 = time.time()
    chunks = []
    for s in range(0, len(idx), BATCH):
        part = idx[s:s + BATCH]
        chunks.append(encode([text.iloc[i] for i in part]).astype(np.float16))
        done = s + len(part)
        print(f"  {done:,}/{len(idx):,}  {done/max(time.time()-t0,1e-9):,.0f} msg/s",
              end="\r", flush=True)
    vectors = np.vstack(chunks)
    print()

    def col(name, default=""):
        if name not in meta.columns:
            return [default] * len(idx)
        return [str(meta[name].iloc[i])[:120] for i in idx]

    ix = SimilarityIndex(
        vectors=vectors,
        labels=meta.label.to_numpy()[idx].astype(np.int8),
        vector_names=col("vector"), subjects=col("subject"),
        senders=col("sender"), sources=col("source"))
    ix.save()
    mb = INDEX_PATH.stat().st_size / 1e6
    print(f"  {ix.size:,} vectors x {vectors.shape[1]} dims -> {INDEX_PATH} ({mb:.1f} MB)")
    print(f"  built in {time.time()-t0:.0f}s")


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 0)
