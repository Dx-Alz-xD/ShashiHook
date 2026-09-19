"""Four exercises drawn from real mail, graded without a language model.

The Learner's lesson mode asks a model to write questions about one message.
That is good for depth and it costs a network call, a few seconds, and a
provider being up. These four cost none of that, because each is graded
against something already known to be true:

  drill      is this message hostile?            graded on the corpus label
  twin       which of these two is the scam?     graded on the corpus label
  highlight  click the phrase that gives it away graded on lexicon spans
  triage     sort a stream, against a clock      graded on the corpus label

Only the binary label is used as an answer key. The vector label -- which kind
of attack -- comes from weak rules and measures about 68% against independent
labels, so grading a learner on it would mark correct answers wrong roughly a
third of the time. That is worse than not asking.

`twin` is the one that earns its place. It pairs each scam with the legitimate
message it most resembles, found by embedding similarity, so the learner is
choosing between two messages that share a shape -- an expiring offer, an
account notice -- rather than between something obviously strange and
something obviously fine. Awareness training that only ever shows lurid fakes
teaches "scams look weird", which is precisely the belief a competent attacker
is counting on.
"""
from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from pathlib import Path

from .config import ARTIFACTS

POOL_PATH = ARTIFACTS / "practice_pool.json"

# A click within this many characters of a real span counts. People aim at a
# word, not a character offset, and demanding exactness would measure mouse
# precision rather than whether they found the tell.
SPAN_SLACK = 12

MODES = ("drill", "twin", "highlight", "triage")

# Which tactic each lexicon teaches, so an answer feeds the same profile the
# lesson mode uses and the two modes reinforce rather than ignore each other.
LEXICON_TACTIC = {
    "urgency": "urgency", "threat": "urgency",
    "authority": "authority", "identity_claim": "authority",
    "impersonated_brand": "sender_identity", "govt_impersonation": "authority",
    "credential_request": "credentials", "it_support": "credentials",
    "payment": "payment", "money_request": "payment", "crypto": "payment",
    "reward": "pretext", "secrecy": "pretext", "romance": "pretext",
    "charity_fraud": "pretext", "investment_scam": "pretext",
    "sextortion": "pretext", "job_scam": "reply_channel",
    "attachment_lure": "attachments", "delivery_scam": "pretext",
    "tech_support_scam": "reply_channel",
}


@dataclass
class PracticePool:
    items: dict[str, dict] = field(default_factory=dict)
    twins: list[dict] = field(default_factory=list)

    @property
    def ready(self) -> bool:
        return bool(self.items)

    @staticmethod
    def load(path: Path = POOL_PATH) -> "PracticePool":
        if not path.exists():
            return PracticePool()
        try:
            raw = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return PracticePool()
        return PracticePool(items={i["id"]: i for i in raw.get("items", [])},
                            twins=raw.get("twins", []))

    # ------------------------------------------------------------- helpers
    def _card(self, item: dict, reveal: bool = False) -> dict:
        """What the browser is allowed to see.

        The label and the spans are withheld until the learner has answered.
        Sending them with the question would put the answer key in the page,
        where anyone curious enough to open the console would find it -- and
        the people most likely to do that are the ones this is for.
        """
        card = {"id": item["id"], "subject": item["subject"],
                "sender": item["sender"], "body": item["body"],
                "source": item["source"]}
        if reveal:
            card["label"] = item["label"]
            card["spans"] = item["spans"]
        return card

    def _pick(self, rng, label=None, needs_spans=False) -> dict | None:
        pool = [i for i in self.items.values()
                if (label is None or i["label"] == label)
                and (not needs_spans or i["spans"])]
        return rng.choice(pool) if pool else None

    # --------------------------------------------------------------- modes
    def drill(self, rng) -> dict | None:
        """One message. Hostile or not?"""
        item = self._pick(rng)
        if item is None:
            return None
        return {"mode": "drill", "message": self._card(item),
                "prompt": "Is this message hostile?",
                "options": ["Hostile — I would not act on this",
                            "Legitimate — this looks like ordinary mail"]}

    def twin(self, rng) -> dict | None:
        """Two messages that resemble each other. One is a scam."""
        if not self.twins:
            return None
        pair = rng.choice(self.twins)
        mal, ben = self.items.get(pair["malicious"]), self.items.get(pair["benign"])
        if not mal or not ben:
            return None
        cards = [self._card(mal), self._card(ben)]
        order = [0, 1]
        rng.shuffle(order)          # otherwise the scam is always on the left
        return {"mode": "twin",
                "messages": [cards[i] for i in order],
                "answer_index": order.index(0),
                "similarity": pair["similarity"],
                "prompt": "One of these is a scam. Which one?"}

    def highlight(self, rng) -> dict | None:
        """Click the phrase that gives it away."""
        item = self._pick(rng, label=1, needs_spans=True)
        if item is None:
            return None
        return {"mode": "highlight", "message": self._card(item),
                "prompt": "Click the phrase that gives this away.",
                "n_tells": len(item["spans"])}

    def triage(self, rng, n: int = 8) -> dict | None:
        """A short run of messages, sorted against a clock."""
        mal = [i for i in self.items.values() if i["label"] == 1]
        ben = [i for i in self.items.values() if i["label"] == 0]
        if len(mal) < n or len(ben) < n:
            return None
        # Roughly a third hostile. A 50/50 stream teaches a base rate no real
        # inbox has, and someone who learns to expect it will over-flag.
        k = max(1, n // 3)
        chosen = rng.sample(mal, k) + rng.sample(ben, n - k)
        rng.shuffle(chosen)
        return {"mode": "triage", "seconds": 12 * n,
                "messages": [self._card(i) for i in chosen],
                "prompt": "Sort each one. The clock is the point."}

    def build(self, mode: str, rng=None, n: int = 8) -> dict | None:
        rng = rng or random.Random()
        if mode == "drill":
            return self.drill(rng)
        if mode == "twin":
            return self.twin(rng)
        if mode == "highlight":
            return self.highlight(rng)
        if mode == "triage":
            return self.triage(rng, n)
        return None

    # -------------------------------------------------------------- marking
    def mark_label(self, item_id: str, said_hostile: bool) -> dict | None:
        item = self.items.get(item_id)
        if item is None:
            return None
        correct = bool(item["label"] == 1) == said_hostile
        return {"correct": correct, "label": item["label"],
                "spans": item["spans"], "vector": item["vector"],
                "why": ("This one is hostile." if item["label"] == 1
                        else "This one is ordinary mail."),
                "tactic": self.tactic_of(item)}

    def mark_click(self, item_id: str, offset: int) -> dict | None:
        """Did the click land on a tell?"""
        item = self.items.get(item_id)
        if item is None:
            return None
        for sp in item["spans"]:
            if sp["start"] - SPAN_SLACK <= offset <= sp["end"] + SPAN_SLACK:
                return {"correct": True, "hit": sp, "spans": item["spans"],
                        "tactic": LEXICON_TACTIC.get(sp["lexicon"], "pretext")}
        return {"correct": False, "hit": None, "spans": item["spans"],
                "tactic": self.tactic_of(item)}

    def tactic_of(self, item: dict) -> str:
        """Which tactic an answer about this message should be credited to."""
        for sp in item["spans"]:
            t = LEXICON_TACTIC.get(sp["lexicon"])
            if t:
                return t
        return "pretext"


_POOL: PracticePool | None = None


def pool() -> PracticePool:
    global _POOL
    if _POOL is None:
        _POOL = PracticePool.load()
    return _POOL
