"""How a specific person writes, and whether this message matches.

The behavioural half of sender profiling already exists in history.py: how
often this domain writes, whether the user replies, what hours it sends at.
That catches a stranger wearing a familiar name. It does not catch the case
this module is for -- a real account, genuinely compromised, sending real mail
from the real address with correct SPF and DKIM. Every header check passes,
because nothing about the headers is false. What changes is the person at the
keyboard.

Writing style is measurable and, importantly, mostly unconscious. Whether
someone writes "Hi Tom," or "Tom -", whether they put one space after a full
stop or two, how often they reach for a semicolon, whether they say "cannot" or
"can't" -- these are habits, not decisions, and an attacker imitating a tone
does not know they are being scored on them.

Two rules govern what counts as a trait here:

  topic-independent   Word choice drifts with subject matter. A colleague who
                      normally discusses scheduling and today writes about an
                      invoice has not been compromised. So the traits are
                      function words, punctuation and layout -- the parts of
                      writing that stay put when the subject changes.

  length-robust       Everything is a rate per token or per sentence, and short
                      messages are refused outright rather than guessed at. A
                      four-word reply carries no style signal, and pretending
                      otherwise produces confident nonsense.

What this deliberately does not do is move a score on its own. Style drift is
weak evidence in isolation -- people write differently from their phone, when
rushed, or when angry -- and the false-positive cost of telling someone their
colleague is compromised is high. It earns its keep in conjunction, which is
why the drift value is exposed as a feature rather than wired to a floor.
"""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path

from .config import ARTIFACTS

STYLE_PATH = ARTIFACTS / "style_profiles.json"

# Below this the message is refused. Style is a distribution, and a handful of
# tokens does not have one -- "Sounds good, thanks" is written that way by
# everyone. Raising this from 40 to 80 words moved detection at a fixed 1%
# false-accusation rate from 8.7% to 11.7% on Enron.
MIN_TOKENS = 80

# Messages needed before a profile is allowed to judge anything. Larger
# profiles are better -- 25 reaches 13.9% -- but each step costs coverage,
# and in a real mailbox most senders never reach 25 long messages.
MIN_MESSAGES = 12

# The 99th percentile of same-author drift measured across 362 Enron senders.
# A genuine message from the real author exceeds this 1% of the time, and it
# catches 11.7% of messages written by somebody else. That ratio is why this
# is a feature and not a floor: useful as corroboration, useless as an accusation.
DRIFT_SUSPICIOUS = 1.16

# Classic authorship-attribution features. These carry style precisely because
# they carry almost no meaning: their rate is a habit of the writer rather than
# a property of the subject. Mosteller and Wallace settled the disputed
# Federalist papers on function words alone.
FUNCTION_WORDS = (
    "a", "about", "after", "all", "also", "an", "and", "any", "are", "as",
    "at", "be", "because", "been", "but", "by", "can", "could", "did", "do",
    "for", "from", "get", "had", "has", "have", "here", "how", "i", "if",
    "in", "into", "is", "it", "its", "just", "know", "like", "make", "may",
    "me", "more", "most", "much", "my", "no", "not", "now", "of", "on",
    "only", "or", "other", "our", "out", "over", "should", "so", "some",
    "such", "than", "that", "the", "their", "them", "then", "there", "these",
    "they", "this", "those", "through", "to", "up", "us", "very", "was",
    "we", "well", "what", "when", "which", "while", "who", "will", "with",
    "would", "you", "your",
)

PUNCTUATION = {
    "comma": ",", "period": ".", "semicolon": ";", "colon": ":",
    "exclaim": "!", "question": "?", "apostrophe": "'", "quote": '"',
    "paren": "(", "slash": "/", "ampersand": "&",
}

TOKEN_RE = re.compile(r"[A-Za-z']+")
SENTENCE_RE = re.compile(r"[.!?]+[\s\"')\]]+|\n{2,}")
CONTRACTION_RE = re.compile(
    r"\b(?:i'm|i've|i'd|i'll|you're|you've|we're|we've|they're|it's|that's|"
    r"there's|here's|don't|doesn't|didn't|won't|can't|cannot|couldn't|"
    r"shouldn't|wouldn't|isn't|aren't|wasn't|weren't|haven't|hasn't|hadn't|"
    r"let's|what's|who's)\b", re.I)
EMOJI_RE = re.compile("[\U0001F300-\U0001FAFF☀-➿]")

# Quoted history and signatures belong to somebody else, or to a template. Both
# would otherwise dominate the measurement: a long quoted chain scores the
# person being quoted, and a corporate footer scores the mail system.
QUOTED_LINE_RE = re.compile(r"(?m)^\s*>.*$")
QUOTE_INTRO_RE = re.compile(
    r"(?im)^\s*(?:on\s+.{4,80}?\s+wrote\s*:"
    r"|-{2,}\s*(?:original|forwarded)\s+message\s*-{2,}"
    r"|from\s*:\s*.{3,80}$)")
SIGNATURE_RE = re.compile(r"(?m)^\s*(?:--\s*$|__+\s*$)")
URL_RE = re.compile(r"https?://\S+|www\.\S+")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")

GREETINGS = {
    "dear": r"^\s*dear\b", "hi": r"^\s*hi\b", "hello": r"^\s*hello\b",
    "hey": r"^\s*hey\b", "good": r"^\s*good\s+(?:morning|afternoon|evening)\b",
    "name_only": r"^\s*[A-Z][a-z]+\s*[,:-]", "none": r"",
}
SIGNOFFS = {
    "thanks": r"\b(?:thanks|thank you|thx)\b\s*[,.!]*\s*$",
    "regards": r"\b(?:regards|best regards|kind regards|br)\b\s*[,.!]*\s*$",
    "best": r"\bbest\b\s*[,.!]*\s*$",
    "cheers": r"\bcheers\b\s*[,.!]*\s*$",
    "sincerely": r"\b(?:sincerely|yours)\b\s*[,.!]*\s*$",
}


def readable_body(text: str) -> str:
    """The part of the message this sender actually wrote, this time."""
    text = text or ""
    m = QUOTE_INTRO_RE.search(text)
    if m:
        text = text[:m.start()]
    text = QUOTED_LINE_RE.sub("", text)
    m = SIGNATURE_RE.search(text)
    if m:
        text = text[:m.start()]
    # URLs and addresses are content, not style, and a single long link would
    # otherwise swing the character-level rates.
    text = URL_RE.sub(" ", text)
    text = EMAIL_RE.sub(" ", text)
    return text.strip()


def traits(text: str) -> dict[str, float] | None:
    """Rates that describe how this was written, not what it says.

    Returns None when the message is too short to have a style.
    """
    body = readable_body(text)
    tokens = TOKEN_RE.findall(body.lower())
    n = len(tokens)
    if n < MIN_TOKENS:
        return None

    out: dict[str, float] = {}
    counts: dict[str, int] = {}
    for t in tokens:
        counts[t] = counts.get(t, 0) + 1
    for w in FUNCTION_WORDS:
        out[f"fw_{w}"] = 1000.0 * counts.get(w, 0) / n

    chars = max(len(body), 1)
    for name, ch in PUNCTUATION.items():
        out[f"pn_{name}"] = 1000.0 * body.count(ch) / chars

    sentences = [s for s in SENTENCE_RE.split(body) if s.strip()]
    lens = [len(TOKEN_RE.findall(s)) for s in sentences] or [n]
    mean_len = sum(lens) / len(lens)
    out["st_sentence_len"] = mean_len
    out["st_sentence_sd"] = math.sqrt(
        sum((x - mean_len) ** 2 for x in lens) / len(lens))
    out["st_word_len"] = sum(len(t) for t in tokens) / n
    out["st_long_words"] = 100.0 * sum(1 for t in tokens if len(t) > 6) / n
    out["st_hapax"] = 100.0 * sum(1 for c in counts.values() if c == 1) / n

    words_raw = re.findall(r"\S+", body)
    out["st_allcaps"] = 100.0 * sum(
        1 for w in words_raw if len(w) > 2 and w.isupper()) / max(len(words_raw), 1)
    out["st_contractions"] = 1000.0 * len(CONTRACTION_RE.findall(body)) / n
    out["st_digits"] = 100.0 * sum(c.isdigit() for c in body) / chars
    out["st_emoji"] = 1000.0 * len(EMOJI_RE.findall(body)) / n

    lines = body.split("\n")
    out["st_blank_lines"] = 100.0 * sum(1 for l in lines if not l.strip()) / max(len(lines), 1)
    out["st_line_len"] = sum(len(l) for l in lines) / max(len(lines), 1)
    # Two spaces after a full stop is a typewriter habit people keep for life.
    out["st_double_space"] = 100.0 * len(re.findall(r"[.!?]  +", body)) / max(
        len(re.findall(r"[.!?] ", body)), 1)
    # Starting a sentence lowercase is a strong, stable personal habit.
    starts = re.findall(r"(?:^|[.!?]\s+)([A-Za-z])", body)
    out["st_lower_start"] = 100.0 * sum(1 for c in starts if c.islower()) / max(len(starts), 1)

    first = next((l for l in lines if l.strip()), "")
    for name, pat in GREETINGS.items():
        out[f"gr_{name}"] = float(bool(pat and re.search(pat, first, re.I)))
    tail = "\n".join(lines[-4:])
    for name, pat in SIGNOFFS.items():
        out[f"sg_{name}"] = float(bool(re.search(pat, tail, re.I | re.M)))
    return out


TRAIT_NAMES: tuple[str, ...] = tuple(
    (traits("word " * (MIN_TOKENS + 10)) or {}).keys())


@dataclass
class StyleProfile:
    """Running mean and variance of one sender's habits.

    Welford's method, so a profile updates per message without keeping any of
    them. What is stored is a few hundred floats describing tendencies -- no
    message text is retained, which matters for a tool that reads a mailbox.
    """
    address: str = ""
    n: int = 0
    mean: dict[str, float] = field(default_factory=dict)
    m2: dict[str, float] = field(default_factory=dict)

    def update(self, t: dict[str, float]) -> None:
        self.n += 1
        for k, v in t.items():
            mu = self.mean.get(k, 0.0)
            delta = v - mu
            mu += delta / self.n
            self.mean[k] = mu
            self.m2[k] = self.m2.get(k, 0.0) + delta * (v - mu)

    def sd(self, key: str) -> float:
        if self.n < 2:
            return 0.0
        return math.sqrt(max(self.m2.get(key, 0.0), 0.0) / (self.n - 1))

    @property
    def ready(self) -> bool:
        return self.n >= MIN_MESSAGES


@dataclass
class DriftResult:
    """How far this message sits from the sender's usual habits.

    `drift` is a cosine distance in normalised trait space, so 0 is a perfect
    match and 1 means the two style vectors are unrelated. Cosine beat the two
    obvious alternatives on Enron by a wide margin -- 0.920 mean per-sender AUC
    against 0.759 for Burrows's Delta and 0.779 for a trimmed mean of absolute
    z-scores -- because it compares the SHAPE of someone's habits and ignores
    how emphatic any one message happens to be.
    """
    scored: bool = False
    drift: float = 0.0            # cosine distance, 0 = identical habits
    messages_seen: int = 0
    note: str = ""
    # The handful of traits that moved most, for the explanation layer.
    top: list[tuple[str, float, float, float]] = field(default_factory=list)


READABLE = {
    "st_sentence_len": "average sentence length",
    "st_sentence_sd": "variation in sentence length",
    "st_word_len": "average word length",
    "st_long_words": "share of long words",
    "st_hapax": "vocabulary variety",
    "st_allcaps": "use of capitals",
    "st_contractions": "use of contractions",
    "st_digits": "density of numbers",
    "st_emoji": "use of emoji",
    "st_blank_lines": "paragraph spacing",
    "st_line_len": "line length",
    "st_double_space": "spacing after full stops",
    "st_lower_start": "starting sentences in lower case",
}


def describe_trait(key: str) -> str:
    if key in READABLE:
        return READABLE[key]
    if key.startswith("fw_"):
        return f'use of the word "{key[3:]}"'
    if key.startswith("pn_"):
        return f"use of the {key[3:].replace('_', ' ')}"
    if key.startswith("gr_"):
        return f"opening the message with {key[3:].replace('_', ' ')}"
    if key.startswith("sg_"):
        return f"signing off with {key[3:]}"
    return key


def compare(profile: StyleProfile, text: str,
            pop_mean: dict[str, float] | None = None,
            pop_sd: dict[str, float] | None = None) -> DriftResult:
    """Score this message against what this sender usually does.

    Both the sender's centroid and the message are first expressed in units of
    how much that trait varies ACROSS senders, then compared by angle. The
    population statistics are what make a trait comparable: a one-point
    difference in comma rate is enormous, a one-point difference in average
    sentence length is nothing, and only the corpus can say which is which.

    Normalising per sender instead was tried and is slightly worse (0.918
    against 0.920 AUC, and 6.6% against 8.5% detection at a fixed 1%
    false-accusation rate). A dozen messages is not enough to estimate one
    person's own spread, so that variant mostly measures its own noise.
    """
    r = DriftResult(messages_seen=profile.n)
    if not profile.ready:
        r.note = (f"only {profile.n} message(s) from this sender so far -- "
                  f"{MIN_MESSAGES} needed before style means anything")
        return r
    t = traits(text)
    if t is None:
        r.note = (f"message is shorter than {MIN_TOKENS} words -- "
                  f"too short to carry a style")
        return r
    if not pop_mean or not pop_sd:
        r.note = "no population statistics -- cannot tell which traits matter"
        return r

    msg, cent, devs = [], [], []
    for k in TRAIT_NAMES:
        sd = pop_sd.get(k, 0.0)
        if sd <= 1e-9 or k not in t or k not in profile.mean:
            continue
        mu = pop_mean.get(k, 0.0)
        zm = (t[k] - mu) / sd
        zc = (profile.mean[k] - mu) / sd
        msg.append(zm)
        cent.append(zc)
        devs.append((k, abs(zm - zc), t[k], profile.mean[k]))
    if len(msg) < 10:
        r.note = "not enough comparable traits"
        return r

    dot = sum(a * b for a, b in zip(msg, cent))
    na = math.sqrt(sum(a * a for a in msg))
    nb = math.sqrt(sum(b * b for b in cent))
    if na <= 1e-9 or nb <= 1e-9:
        r.note = "style vector is degenerate"
        return r
    r.drift = 1.0 - dot / (na * nb)
    devs.sort(key=lambda x: -x[1])
    r.top = devs[:6]
    r.scored = True
    r.note = f"compared against {profile.n} previous messages from this sender"
    return r


@dataclass
class StyleStore:
    """Every sender's profile, plus the spread of each trait across senders."""
    profiles: dict[str, StyleProfile] = field(default_factory=dict)
    pop_mean: dict[str, float] = field(default_factory=dict)
    pop_sd: dict[str, float] = field(default_factory=dict)

    def observe(self, address: str, text: str) -> None:
        t = traits(text)
        if t is None:
            return
        addr = (address or "").strip().lower()
        if not addr:
            return
        self.profiles.setdefault(addr, StyleProfile(address=addr)).update(t)

    def compare(self, address: str, text: str) -> DriftResult:
        p = self.profiles.get((address or "").strip().lower())
        if p is None:
            return DriftResult(note="no prior mail from this sender")
        return compare(p, text, self.pop_mean, self.pop_sd)

    def fit_population(self) -> None:
        """How much each trait varies from one writer to the next.

        Taken over sender means rather than raw messages, so one prolific
        correspondent cannot define what 'normal' looks like for everyone.
        """
        ready = [p for p in self.profiles.values() if p.ready]
        if len(ready) < 3:
            return
        for k in TRAIT_NAMES:
            vals = [p.mean[k] for p in ready if k in p.mean]
            if len(vals) < 3:
                continue
            mu = sum(vals) / len(vals)
            self.pop_mean[k] = mu
            self.pop_sd[k] = math.sqrt(
                sum((v - mu) ** 2 for v in vals) / (len(vals) - 1))

    @property
    def ready(self) -> bool:
        return bool(self.pop_sd)

    def save(self, path: Path = STYLE_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "pop_mean": self.pop_mean,
            "pop_sd": self.pop_sd,
            "profiles": {a: {"n": p.n, "mean": p.mean, "m2": p.m2}
                         for a, p in self.profiles.items()},
        }
        path.write_text(json.dumps(payload))
        try:
            path.chmod(0o600)      # it describes how people write; keep it private
        except OSError:
            pass

    @staticmethod
    def load(path: Path = STYLE_PATH) -> "StyleStore":
        s = StyleStore()
        if not path.exists():
            return s
        try:
            raw = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return s
        s.pop_mean = raw.get("pop_mean", {})
        s.pop_sd = raw.get("pop_sd", {})
        for a, d in raw.get("profiles", {}).items():
            s.profiles[a] = StyleProfile(address=a, n=d.get("n", 0),
                                         mean=d.get("mean", {}),
                                         m2=d.get("m2", {}))
        return s


def style_features(r: DriftResult) -> dict[str, float]:
    return {
        "sty_scored": float(r.scored),
        "sty_drift": float(r.drift if r.scored else 0.0),
    }


STYLE_FEATURE_NAMES = tuple(style_features(DriftResult()).keys())
