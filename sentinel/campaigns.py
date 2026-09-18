"""Group related messages into campaigns.

A single hostile email is an incident. Fourteen of them sharing a link domain
across three years is an actor, and that is a different thing to respond to:
blocking one sender achieves nothing if the same infrastructure is still
delivering under six others.

Messages are joined when they share something an attacker has to pay for or
reuse:

  * a sending registrable domain
  * a link domain (excluding the obvious shared hosts -- half the internet
    links to google.com, and joining on that would merge everything)
  * a phone number
  * a near-identical body, by SimHash over token shingles

Union-find merges those pairwise links into components. The result is
deliberately conservative: a campaign here means "these messages provably share
infrastructure", not "these felt similar".
"""
from __future__ import annotations

import hashlib
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from .analyzer import Analysis
from .features.brands import LEGIT_DOMAINS, URL_SHORTENERS

# Domains too widely shared to imply a relationship between two messages.
COMMON_HOSTS = LEGIT_DOMAINS | URL_SHORTENERS | frozenset({
    "googleapis.com", "gstatic.com", "cloudfront.net", "akamaihd.net",
    "sendgrid.net", "mailchimp.com", "mailgun.org", "amazonses.com",
    "list-manage.com", "mcusercontent.com", "substack.com", "medium.com",
    "twitter.com", "x.com", "unsubscribe.com", "cdn.jsdelivr.net",
})

# A link domain seen under this many DIFFERENT sending domains is shared
# infrastructure, whoever owns it, and must not imply a relationship between
# two messages. Derived from the data rather than from a hand-kept list:
# c.gle -- Google's own shortener -- slipped through a hardcoded list and
# merged Kaggle mail into a Google cluster.
#
# Counting alone cannot tell "two senders share this because it is a CDN" from
# "two senders share this because one actor rotates domains". At a threshold of
# 2 the second case -- exactly what this feature exists to find -- was being
# discarded as infrastructure.
#
# Authentication separates them. Legitimate shared infrastructure is used by
# senders that pass DKIM/SPF alignment; a phishing kit's senders do not. So a
# domain is treated as shared when it appears under 3+ senders, OR under 2+
# senders that are ALL authenticated.
SHARED_HOST_SENDERS = 3

# SimHash over a very short body is unreliable: with few shingles, one changed
# word moves the hash a long way, and two unrelated footers can land close
# together. Below this word count, text similarity is not used as a link.
MIN_WORDS_FOR_TEXT_LINK = 60

TOKEN_RE = re.compile(r"[a-z0-9']+")
SIMHASH_BITS = 64
# Hamming distance at or below this counts as the same template.
#
# Calibrated on 44 real messages (946 pairs), not guessed. A first attempt at 3
# was far too tight -- a template with only the recipient name swapped already
# measures 4, so it would have missed the exact case this exists to catch.
#
#   threshold   same-sender merges   cross-sender false merges
#        3               7                      0
#        8              10                      0
#       12              17                      0     <- chosen
#       14              19                      2
#       18              21                      4
#
# 12 is the last value that still merges nothing across unrelated senders.
SIMHASH_THRESHOLD = 12

# Across different sending domains, template similarity has to clear a much
# higher bar. Long messages share a lot of boilerplate -- privacy footers,
# unsubscribe blocks, address lines -- and at the same-sender threshold that
# was enough to merge a College Board mailing with a TripAdvisor one.
SIMHASH_THRESHOLD_CROSS_SENDER = 6


def simhash(text: str, shingle: int = 3) -> int:
    """SimHash over word shingles -- near-duplicate detection that survives the
    small per-recipient substitutions bulk senders make."""
    toks = TOKEN_RE.findall((text or "").lower())
    if len(toks) < shingle:
        return 0
    v = [0] * SIMHASH_BITS
    for i in range(len(toks) - shingle + 1):
        s = " ".join(toks[i:i + shingle])
        h = int.from_bytes(hashlib.blake2b(s.encode(), digest_size=8).digest(), "big")
        for b in range(SIMHASH_BITS):
            v[b] += 1 if (h >> b) & 1 else -1
    out = 0
    for b in range(SIMHASH_BITS):
        if v[b] > 0:
            out |= 1 << b
    return out


def hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


class _Union:
    def __init__(self, n: int):
        self.p = list(range(n))

    def find(self, x: int) -> int:
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[rb] = ra


@dataclass
class CampaignMember:
    index: int
    subject: str
    sender: str
    domain: str
    date: str
    score: float
    band: str
    vector: str


@dataclass
class Campaign:
    id: str
    members: list[CampaignMember] = field(default_factory=list)
    sender_domains: list[str] = field(default_factory=list)
    link_domains: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)
    vectors: dict[str, int] = field(default_factory=dict)
    links_by: list[str] = field(default_factory=list)
    max_score: float = 0.0
    first_seen: str = ""
    last_seen: str = ""

    @property
    def size(self) -> int:
        return len(self.members)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "size": self.size,
            "members": [m.__dict__ for m in self.members],
            "sender_domains": self.sender_domains, "link_domains": self.link_domains,
            "phones": self.phones, "vectors": self.vectors, "links_by": self.links_by,
            "max_score": self.max_score,
            "first_seen": self.first_seen, "last_seen": self.last_seen,
        }


def _dynamic_common_hosts(items: list[Analysis]) -> set[str]:
    """Link domains that are shared infrastructure rather than a shared actor."""
    from .scoring.floors import sender_is_authenticated

    senders: dict[str, set[str]] = defaultdict(set)
    unauth: dict[str, int] = defaultdict(int)
    for a in items:
        sd = a.evidence.sender.registrable or ""
        ok, _ = sender_is_authenticated(a.email, a.evidence)
        for u in a.evidence.urls:
            if not u.registrable:
                continue
            senders[u.registrable].add(sd)
            if not ok:
                unauth[u.registrable] += 1

    out: set[str] = set()
    for d, sd in senders.items():
        if len(sd) >= SHARED_HOST_SENDERS:
            out.add(d)
        elif len(sd) >= 2 and unauth[d] == 0:
            # Two senders, both provably themselves: a CDN or an ESP, not an
            # actor rotating throwaway domains.
            out.add(d)
    return out


def _facts(a: Analysis) -> tuple[str, set[str], set[str]]:
    dom = a.evidence.sender.registrable or ""
    links = {u.registrable for u in a.evidence.urls
             if u.registrable and u.registrable not in COMMON_HOSTS}
    phones = {p.digits for p in a.evidence.phones}
    return dom, links, phones


def cluster(analyses: list[Analysis], min_size: int = 2,
            malicious_only: bool = True) -> list[Campaign]:
    items = [a for a in analyses
             if (not malicious_only) or a.probability >= 0.5 or a.severity.score >= 15]
    n = len(items)
    if n < 2:
        return []

    shared = COMMON_HOSTS | _dynamic_common_hosts(items)
    facts = []
    for a in items:
        dom, links, phones = _facts(a)
        facts.append((dom, {l for l in links if l not in shared}, phones))

    # Only hash bodies long enough for the hash to mean anything.
    hashes = []
    for a in items:
        body = a.evidence.body or ""
        hashes.append(simhash(f"{a.email.subject} {body}")
                      if len(body.split()) >= MIN_WORDS_FOR_TEXT_LINK else 0)
    uf = _Union(n)
    reasons: dict[int, set[str]] = defaultdict(set)

    by_sender: dict[str, list[int]] = defaultdict(list)
    by_link: dict[str, list[int]] = defaultdict(list)
    by_phone: dict[str, list[int]] = defaultdict(list)
    for i, (dom, links, phones) in enumerate(facts):
        if dom:
            by_sender[dom].append(i)
        for l in links:
            by_link[l].append(i)
        for p in phones:
            by_phone[p].append(i)

    for store, label in ((by_sender, "sending domain"), (by_link, "link domain"),
                         (by_phone, "phone number")):
        for key, idxs in store.items():
            for j in idxs[1:]:
                uf.union(idxs[0], j)
            if len(idxs) > 1:
                for j in idxs:
                    reasons[uf.find(j)].add(f"{label} {key}")

    # Template similarity is O(n^2); fine at inbox scale, and it is the only
    # link that catches a campaign which rotates every domain between sends.
    for i in range(n):
        if not hashes[i]:
            continue
        for j in range(i + 1, n):
            if not hashes[j]:
                continue
            same_sender = facts[i][0] and facts[i][0] == facts[j][0]
            limit = SIMHASH_THRESHOLD if same_sender else SIMHASH_THRESHOLD_CROSS_SENDER
            if hamming(hashes[i], hashes[j]) <= limit:
                uf.union(i, j)
                reasons[uf.find(i)].add("near-identical body text")

    groups: dict[int, list[int]] = defaultdict(list)
    for i in range(n):
        groups[uf.find(i)].append(i)

    out: list[Campaign] = []
    for root, idxs in groups.items():
        if len(idxs) < min_size:
            continue
        c = Campaign(id=f"campaign-{root}")
        sd, ld, ph = Counter(), Counter(), Counter()
        for i in idxs:
            a = items[i]
            dom, links, phones = facts[i]
            c.members.append(CampaignMember(
                index=i, subject=(a.email.subject or "(no subject)")[:110],
                sender=a.evidence.sender.address or a.email.sender or "",
                domain=dom, date=a.email.date or "", score=a.severity.score,
                band=a.severity.band, vector=a.vector_key))
            if dom:
                sd[dom] += 1
            ld.update(links)
            ph.update(phones)
            c.max_score = max(c.max_score, a.severity.score)
        c.sender_domains = [d for d, _ in sd.most_common(8)]
        c.link_domains = [d for d, _ in ld.most_common(8)]
        c.phones = [p for p, _ in ph.most_common(4)]
        c.vectors = dict(Counter(m.vector for m in c.members))
        c.links_by = sorted(reasons.get(root, set()))[:6]
        dates = sorted(d for d in (m.date for m in c.members) if d)
        c.first_seen, c.last_seen = (dates[0], dates[-1]) if dates else ("", "")
        c.members.sort(key=lambda m: -m.score)
        out.append(c)

    out.sort(key=lambda c: (-c.max_score, -c.size))
    return out


def to_graph(c: Campaign) -> dict:
    """Campaign as nodes and edges, for the same renderer the lineage uses."""
    nodes, edges = [], []

    def add(nid, label, kind, detail="", meta=None):
        if not any(n["id"] == nid for n in nodes):
            nodes.append({"id": nid, "label": label, "kind": kind, "detail": detail,
                          "severity": c.max_score, "meta": meta or {},
                          "rank": {"actor": 0, "identity": 1, "infra": 2,
                                   "technique": 3, "objective": 5,
                                   "evidence": 6}.get(kind, 6)})
        return nid

    root = add("campaign", f"Campaign — {c.size} messages", "actor",
               (f"Linked by {', '.join(c.links_by)}." if c.links_by else "")
               + (f" Seen {c.first_seen[:16]} to {c.last_seen[:16]}."
                  if c.first_seen else ""),
               {"size": c.size, "max_score": c.max_score})
    for d in c.sender_domains:
        edges.append({"source": root, "target": add(f"sd:{d}", d, "identity",
                                                    "Sending domain used by this campaign."),
                      "label": "sends from", "kind": "flow"})
    for d in c.link_domains:
        nid = add(f"ld:{d}", d, "infra", "Link infrastructure shared across the campaign.")
        src = f"sd:{c.sender_domains[0]}" if c.sender_domains else root
        edges.append({"source": src, "target": nid, "label": "links to", "kind": "flow"})
    for p in c.phones:
        nid = add(f"ph:{p}", p, "infra", "Phone number shared across the campaign.")
        edges.append({"source": root, "target": nid, "label": "directs to", "kind": "flow"})
    for v, n_ in sorted(c.vectors.items(), key=lambda kv: -kv[1]):
        nid = add(f"v:{v}", v.replace("_", " "), "technique", f"{n_} message(s).")
        anchor = (f"ld:{c.link_domains[0]}" if c.link_domains
                  else (f"sd:{c.sender_domains[0]}" if c.sender_domains else root))
        edges.append({"source": anchor, "target": nid, "label": "used for", "kind": "flow"})
    for m in c.members[:8]:
        nid = add(f"m:{m.index}", m.subject[:44], "evidence",
                  f"{m.band} {m.score:.1f} · {m.sender}")
        edges.append({"source": nid, "target": f"v:{m.vector}"
                      if any(n["id"] == f"v:{m.vector}" for n in nodes) else root,
                      "label": "instance", "kind": "evidence"})
    return {"nodes": nodes, "edges": edges}
