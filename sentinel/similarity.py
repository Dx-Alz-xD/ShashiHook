"""Have we seen this message before?

The models give a probability and the floors give a rule, but neither can show
the reader a thing. This can: the nearest message in 81,234 labelled examples,
with its subject, its label and how close it is. "This is 0.87 similar to a
known advance-fee scam, here it is" is evidence a person can check, which is a
different kind of argument from a number between zero and one.

Why embeddings rather than the SimHash already in campaigns.py: SimHash is
lexical, so it clusters messages that share words. That is the right tool for
spotting one blast sent to many people, and the wrong one for spotting the same
scam rewritten. On five hand-written paraphrase pairs -- the same pretext in
different words -- embeddings ranked the true match first 5 times out of 5 and
TF-IDF managed 2, with TF-IDF's margin (0.025 against 0.014 for an unrelated
message) too small to act on. The two live side by side: SimHash for identical
blasts, this for reworded ones.

The model is static and local. `potion-base-8M` is a distilled embedding table
rather than a transformer, so there is no torch dependency, no GPU and no
network call at scoring time -- it encodes a message in single-digit
milliseconds. Nothing about a message ever leaves the machine to be compared,
which matters for a tool pointed at somebody's mailbox.

Vectors are stored as float16. At 81,234 messages and 256 dimensions that is
42MB rather than 83MB, and the precision lost is far below the distance between
a match and a non-match.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from .config import ARTIFACTS

INDEX_PATH = ARTIFACTS / "similarity_index.npz"
MODEL_NAME = "minishlab/potion-base-8M"

# Below this, "nearest" means nothing. Two unrelated messages sit around 0.13;
# a genuine paraphrase of the same scam sits near 0.54 and a near-copy above
# 0.9. Reporting a 0.2 match would be noise dressed as evidence.
MIN_USEFUL = 0.45

# Only the first part of a message is encoded. Quoted chains and footers push
# every long message towards every other long message, which flattens exactly
# the distinctions this is for.
MAX_CHARS = 2000

_MODEL = None


def model():
    global _MODEL
    if _MODEL is None:
        from model2vec import StaticModel
        _MODEL = StaticModel.from_pretrained(MODEL_NAME)
    return _MODEL


def encode(texts: list[str]) -> np.ndarray:
    """Unit-normalised vectors, so a dot product is a cosine similarity."""
    v = model().encode([(t or "")[:MAX_CHARS] for t in texts])
    v = np.asarray(v, dtype=np.float32)
    n = np.linalg.norm(v, axis=1, keepdims=True)
    return v / np.maximum(n, 1e-9)


@dataclass
class Neighbour:
    similarity: float = 0.0
    label: int = 0
    vector: str = ""
    subject: str = ""
    sender: str = ""
    source: str = ""

    @property
    def malicious(self) -> bool:
        return self.label == 1


@dataclass
class SimilarityIndex:
    """Embedded corpus, held in memory and searched by dot product.

    81,234 vectors of 256 dimensions is a 21M-element matrix; a full scan is a
    single BLAS call of a few milliseconds, so there is no approximate index to
    build, tune or get subtly wrong.
    """
    vectors: np.ndarray = field(default_factory=lambda: np.zeros((0, 0), np.float16))
    labels: np.ndarray = field(default_factory=lambda: np.zeros(0, np.int8))
    vector_names: list[str] = field(default_factory=list)
    subjects: list[str] = field(default_factory=list)
    senders: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    @property
    def size(self) -> int:
        return int(self.vectors.shape[0])

    def search(self, text: str, k: int = 3) -> list[Neighbour]:
        if not self.size or not (text or "").strip():
            return []
        q = encode([text])[0]
        sims = (self.vectors.astype(np.float32) @ q)
        k = min(k, self.size)
        top = np.argpartition(-sims, k - 1)[:k]
        top = top[np.argsort(-sims[top])]
        out = []
        for i in top:
            s = float(sims[i])
            if s < MIN_USEFUL:
                continue
            out.append(Neighbour(
                similarity=round(s, 4), label=int(self.labels[i]),
                vector=self.vector_names[i] if i < len(self.vector_names) else "",
                subject=self.subjects[i] if i < len(self.subjects) else "",
                sender=self.senders[i] if i < len(self.senders) else "",
                source=self.sources[i] if i < len(self.sources) else ""))
        return out

    def save(self, path: Path = INDEX_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        np.savez_compressed(
            path, vectors=self.vectors.astype(np.float16), labels=self.labels,
            meta=np.array([json.dumps({
                "vector_names": self.vector_names, "subjects": self.subjects,
                "senders": self.senders, "sources": self.sources})], dtype=object),
            allow_pickle=True)

    @staticmethod
    def load(path: Path = INDEX_PATH) -> "SimilarityIndex":
        if not path.exists():
            return SimilarityIndex()
        try:
            z = np.load(path, allow_pickle=True)
            meta = json.loads(z["meta"][0])
            return SimilarityIndex(
                vectors=z["vectors"], labels=z["labels"],
                vector_names=meta.get("vector_names", []),
                subjects=meta.get("subjects", []),
                senders=meta.get("senders", []),
                sources=meta.get("sources", []))
        except Exception:
            # A corrupt or half-written index must not take the analyser down;
            # an empty one simply returns no neighbours.
            return SimilarityIndex()


_INDEX: SimilarityIndex | None = None


def index() -> SimilarityIndex:
    global _INDEX
    if _INDEX is None:
        _INDEX = SimilarityIndex.load()
    return _INDEX


def set_index(ix: SimilarityIndex) -> None:
    global _INDEX
    _INDEX = ix


def describe(neighbours: list[Neighbour]) -> str:
    """One sentence a person can act on."""
    if not neighbours:
        return "nothing in the corpus resembles this message"
    n = neighbours[0]
    kind = (f"a known {n.vector.replace('_', ' ')}" if n.malicious and n.vector
            else "a known malicious message" if n.malicious
            else "ordinary legitimate mail")
    return (f"{n.similarity:.0%} similar to {kind} "
            f"in the {n.source} corpus: “{n.subject[:70]}”")
