"""Attack lineage as a graph.

A report is a list. An attack is a structure: an actor stands behind an
identity, the identity carries infrastructure, the infrastructure delivers a
technique, the technique produces an outcome. Reading that as bullet points
loses the shape, and the shape is what makes an attack recognisable.

This builds that structure from one analysis -- every node traceable to
something actually observed, never decorative. Nodes carry a `kind` so the
renderer can rank them left to right along the kill chain:

    actor → identity → infrastructure → technique → payload → objective

with the evidence nodes (rules, SHAP findings, history, domain age) hanging off
whichever node they justify.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .analyzer import Analysis

# Column order in the rendered graph; also the kill-chain reading order.
RANK = {"actor": 0, "identity": 1, "infra": 2, "technique": 3,
        "payload": 4, "objective": 5, "evidence": 6}


@dataclass
class Node:
    id: str
    label: str
    kind: str
    detail: str = ""
    severity: float = 0.0
    meta: dict = field(default_factory=dict)


@dataclass
class Edge:
    source: str
    target: str
    label: str = ""
    kind: str = "flow"      # flow | evidence


@dataclass
class AttackGraph:
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)

    def add(self, n: Node) -> str:
        if not any(x.id == n.id for x in self.nodes):
            self.nodes.append(n)
        return n.id

    def link(self, a: str, b: str, label: str = "", kind: str = "flow") -> None:
        if a and b and not any(e.source == a and e.target == b for e in self.edges):
            self.edges.append(Edge(a, b, label, kind))

    def to_dict(self) -> dict:
        return {"nodes": [{**asdict(n), "rank": RANK.get(n.kind, 6)} for n in self.nodes],
                "edges": [asdict(e) for e in self.edges]}


def build(a: Analysis) -> AttackGraph:
    g = AttackGraph()
    ev, sev = a.evidence, a.severity
    s = sev.score

    # --- actor -------------------------------------------------------------
    actor_label = "Unattributed sender"
    actor_detail = "No attribution available from a single message."
    if ev.sender.claimed_brand and ev.sender.brand_mismatch:
        actor_label = f"Actor impersonating {ev.sender.claimed_brand.title()}"
        actor_detail = (f"Presents as {ev.sender.claimed_brand.title()} from a domain "
                        f"that brand does not own.")
    elif ev.embedded.mismatch and ev.embedded.claimed_addresses:
        actor_label = "Actor posing as a named individual"
        actor_detail = ev.embedded.notes[0] if ev.embedded.notes else ""
    actor = g.add(Node("actor", actor_label, "actor", actor_detail, s))

    # --- identity ----------------------------------------------------------
    dom = ev.sender.registrable or "(no sender domain)"
    ident = g.add(Node(f"id:{dom}", dom, "identity",
                       "; ".join(ev.sender.notes) or "Sending domain.", s,
                       {"address": ev.sender.address,
                        "freemail": ev.sender.is_freemail,
                        "lookalike_of": ev.sender.lookalike_of}))
    g.link(actor, ident, "sends from")

    if a.email.reply_to:
        rt = g.add(Node("id:replyto", a.email.reply_to[:60], "identity",
                        "Replies route here, not to the sending domain.", s))
        g.link(ident, rt, "replies divert to")

    # --- infrastructure ----------------------------------------------------
    infra_ids: list[str] = []
    for u in ev.urls[:6]:
        if not u.registrable:
            continue
        nid = g.add(Node(f"url:{u.registrable}", u.registrable, "infra",
                         "; ".join(u.flags) or u.raw[:110], s,
                         {"url": u.raw[:300], "flags": u.flags}))
        g.link(ident, nid, "links to")
        infra_ids.append(nid)
    for p in ev.phones[:3]:
        nid = g.add(Node(f"tel:{p.digits}", p.raw, "infra",
                         "; ".join(p.flags) or "Phone number to call.", s))
        g.link(ident, nid, "directs to")
        infra_ids.append(nid)
    for att in (ev.dangerous_attachments or ev.attachments)[:4]:
        nid = g.add(Node(f"att:{att}", att, "infra", "Attachment carried by the message.", s))
        g.link(ident, nid, "carries")
        infra_ids.append(nid)

    # --- technique ---------------------------------------------------------
    tech = g.add(Node(f"tech:{a.vector_key}", a.vector.name, "technique",
                      a.vector.description, s,
                      {"mitre": list(a.vector.mitre),
                       "kill_chain": a.vector.kill_chain,
                       "confidence": a.vector_confidence,
                       "resolved_by": a.vector_source}))
    for nid in (infra_ids or [ident]):
        g.link(nid, tech, "used for")

    # --- payload / objective ----------------------------------------------
    outcome = {
        "credential_phishing": ("Harvested credentials", "Username, password and "
                                "increasingly the MFA code, captured on a counterfeit page."),
        "malware_delivery": ("Code execution on the endpoint",
                             "The payload runs, and the mailbox becomes a foothold."),
        "bec_payment_fraud": ("Funds transferred to the attacker",
                              "A payment is redirected; recovery windows are hours, not days."),
        "vendor_invoice_fraud": ("Payment redirected to a false account",
                                 "Future invoices route to the attacker until noticed."),
        "callback_phishing": ("Remote access and account takeover",
                              "The victim is talked through installing remote-access software."),
        "tech_support_scam": ("Remote access to the device",
                              "The attacker operates the machine directly."),
        "investment_fraud": ("Deposits into a fake platform",
                             "Balances are fabricated; withdrawal triggers new fees."),
        "job_scam": ("Identity documents or money-mule recruitment",
                     "Documents harvested, or the victim used to launder funds."),
        "advance_fee_fraud": ("An up-front fee, then silence", ""),
        "extortion": ("Cryptocurrency payment under threat", ""),
        "delivery_scam": ("Card details entered to pay a small fee", ""),
        "government_impersonation": ("Payment or identity documents under threat of penalty", ""),
        "romance_fraud": ("Sustained transfers to a fabricated relationship", ""),
        "charity_fraud": ("A donation that reaches no cause", ""),
        "recon_probe": ("A confirmed live, responsive mailbox",
                        "No payload yet — this establishes that a human reads this address."),
        "spam_unwanted": ("Attention and a click-through", ""),
    }.get(a.vector_key, ("Compromise", ""))
    obj = g.add(Node("objective", outcome[0], "objective", outcome[1], s,
                     {"impact": a.vector.impact}))
    g.link(tech, obj, "leads to")

    # --- evidence ----------------------------------------------------------
    for f in a.floors_binding[:4]:
        nid = g.add(Node(f"rule:{f.name}", f.name, "evidence", f.why, s,
                         {"floor": f.minimum}))
        g.link(nid, tech, "proves", "evidence")
    for f in a.findings_up[:4]:
        if "Absence" in f.headline or f.kind != "indicator":
            continue
        nid = g.add(Node(f"ev:{f.feature}", f.headline, "evidence",
                         f.detail + (f"  “{f.quotes[0]}”" if f.quotes else ""),
                         s, {"shap": round(f.contribution, 3)}))
        g.link(nid, tech, "supports", "evidence")
    if a.history_note:
        nid = g.add(Node("ev:history", "Mailbox history", "evidence", a.history_note, s))
        g.link(nid, ident, "context", "evidence")
    if a.domain_age_note:
        nid = g.add(Node("ev:age", "Domain age", "evidence", a.domain_age_note, s))
        g.link(nid, ident, "context", "evidence")
    return g
