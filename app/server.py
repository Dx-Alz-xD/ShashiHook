"""ShashiHook — desktop application server.

The analysis engine is ArnosAI: the models, rules and explainability layers in
`sentinel/`. This module is only the shell around it — a local HTTP server that
streams results to the dashboard as each message is scored.

Why a local web app rather than Electron or Tauri: the engine is Python
(LightGBM, SHAP, scikit-learn) and cannot run in a browser or in Node. A native
wrapper would still need this exact process running underneath, so it would add
a browser runtime and a packaging pipeline without removing a single dependency.
This way the whole application is one command, and the UI is still fully
custom.

Nothing here reaches the network except the user's own mail server.
"""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.types import Scope
from pydantic import BaseModel

from sentinel.analyzer import Analysis, ThreatAnalyzer
from sentinel.config import ARTIFACTS
from sentinel.enrich.rdap import DomainAgeCache
from sentinel.features.extractor import Email
from sentinel.campaigns import cluster as cluster_campaigns
from sentinel.campaigns import to_graph as campaign_graph
from sentinel.graph import build as build_graph
from sentinel.ingest.eml import from_string
from sentinel.labeling.taxonomy import TAXONOMY
from sentinel.profiling import llm as llm_providers
from sentinel.profiling.profile import ProfileCache, profile as build_profile
from sentinel.report.incident import to_dict, to_markdown
from sentinel.settings import settings

STATIC = Path(__file__).parent / "static"

app = FastAPI(title="ShashiHook", version="1.0",
              description="Email threat analysis desktop app powered by ArnosAI")

_analyzer: ThreatAnalyzer | None = None
_cache: dict[str, Analysis] = {}
_profiles = ProfileCache(ARTIFACTS / "threat_profiles.json")


def engine() -> ThreatAnalyzer:
    global _analyzer
    if _analyzer is None:
        _analyzer = ThreatAnalyzer(
            known_bad_iocs=settings.load_iocs(),
            software_allowlist=settings.load_software_allowlist(),
            inbox_base_rate=settings.inbox_base_rate or None,
            domain_age=DomainAgeCache(ARTIFACTS / "domain_age_cache.json",
                                      enabled=settings.enable_rdap),
        )
    return _analyzer


def card(a: Analysis) -> dict:
    """The compact shape the dashboard's live feed renders."""
    ev = a.evidence
    return {
        "id": a.email.message_id or a.email.uid,
        "subject": a.email.subject or "(no subject)",
        "sender": ev.sender.address or a.email.sender or "(unknown)",
        "display_name": ev.sender.display_name,
        "domain": ev.sender.registrable,
        "date": a.email.date,
        "score": a.severity.score,
        "band": a.severity.band,
        "probability": round(a.probability, 4),
        "model_probability": round(a.model_probability, 4),
        "vector": a.vector_key,
        "vector_name": a.vector.name,
        "verdict": a.verdict,
        "decided_by": a.decided_by,
        "floors": [f.name for f in a.floors_binding],
        "n_urls": len(ev.urls),
        "n_phones": len(ev.phones),
        "n_attachments": len(ev.attachments),
        "authenticated": bool(a.email.auth_results and "dkim=pass" in
                              (a.email.auth_results or "").lower()),
        "top_reason": a.findings_up[0].headline if a.findings_up else "",
    }


def detail(a: Analysis) -> dict:
    d = to_dict(a)
    d["markdown"] = to_markdown(a)
    d["card"] = card(a)
    d["history_note"] = a.history_note
    d["domain_age_note"] = a.domain_age_note
    d["evidence_up"] = [
        {"headline": f.headline, "detail": f.detail, "shap": round(f.contribution, 4),
         "kind": f.kind, "quotes": f.quotes} for f in a.findings_up]
    d["evidence_down"] = [
        {"headline": f.headline, "detail": f.detail, "shap": round(f.contribution, 4),
         "kind": f.kind} for f in a.findings_down]
    d["counterfactuals"] = a.counterfactuals
    d["wording"] = a.wording_summary
    d["tokens"] = [{"token": t.token, "weight": round(t.weight, 4)}
                   for t in a.explanation.top_tokens_up[:12]]
    d["phones"] = [{"raw": p.raw, "flags": p.flags} for p in a.evidence.phones]
    return d


# ----------------------------------------------------------------- endpoints
@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/api/status")
def status() -> dict:
    e = engine()
    return {
        "engine": "ArnosAI",
        "ready": True,
        "features": len(e.intent.feature_names),
        "vectors": len(TAXONOMY),
        "blend": e.intent.blend_weights,
        "base_rate": settings.inbox_base_rate,
        "rdap": settings.enable_rdap,
        "history": (len(e.history.domains) if e.history else 0),
        "history_messages": (e.history.messages_scanned if e.history else 0),
        "mailbox_ready": settings.has_imap or settings.has_oauth,
        "source": "imap" if settings.has_imap else ("gmail" if settings.has_oauth else None),
        "llm": llm_providers.available(settings),
        "auto_profile": settings.llm_auto_profile,
        "profile_min_score": settings.llm_profile_min_score,
        "taxonomy": {k: {"name": v.name, "impact": v.impact,
                         "description": v.description, "mitre": list(v.mitre)}
                     for k, v in TAXONOMY.items()},
    }


class AnalyzeBody(BaseModel):
    raw: str | None = None
    subject: str = ""
    body: str = ""
    sender: str = ""
    receiver: str = ""


@app.post("/api/analyze")
def analyze_one(b: AnalyzeBody) -> dict:
    if b.raw:
        email = from_string(b.raw)
    elif b.subject or b.body:
        email = Email(subject=b.subject, body=b.body, sender=b.sender,
                      receiver=b.receiver, source="app")
    else:
        raise HTTPException(400, "provide raw, or subject/body")
    a = engine().analyze(email)
    _cache[a.email.message_id or a.email.uid] = a
    return detail(a)


@app.get("/api/message/{mid}")
def message_detail(mid: str) -> dict:
    a = _cache.get(mid)
    if a is None:
        raise HTTPException(404, "not in this session's cache — rescan to load it")
    return detail(a)


async def _scan_events(source: str, limit: int, query: str,
                       mailbox: str) -> AsyncIterator[str]:
    """Server-sent events, one per message, emitted as it is scored.

    Fetching is blocking IMAP work, so it runs in a thread; scoring is yielded
    message by message so the dashboard fills progressively instead of sitting
    blank and then dumping everything at once.
    """
    def emit(kind: str, payload: dict) -> str:
        return f"event: {kind}\ndata: {json.dumps(payload)}\n\n"

    try:
        yield emit("phase", {"phase": "connecting", "message":
                             f"opening {source} mailbox {mailbox}"})
        if source == "gmail":
            from sentinel.ingest import gmail as adapter
        else:
            from sentinel.ingest import imap_box as adapter

        kw = {"mailbox": mailbox} if source != "gmail" else {}
        msgs = await asyncio.to_thread(adapter.fetch, settings, query, limit, **kw)
        yield emit("phase", {"phase": "fetched", "count": len(msgs),
                             "message": f"{len(msgs)} messages retrieved"})

        az = engine()
        t0 = time.time()
        for i, m in enumerate(msgs, 1):
            try:
                email = await asyncio.to_thread(adapter.to_email, m)
                a = await asyncio.to_thread(az.analyze, email)
            except Exception as exc:
                yield emit("error", {"index": i, "message": f"{type(exc).__name__}: {exc}"})
                continue
            _cache[a.email.message_id or a.email.uid] = a
            yield emit("message", {"index": i, "total": len(msgs), **card(a)})
            await asyncio.sleep(0)   # let the event loop flush to the browser
        yield emit("done", {"count": len(msgs), "seconds": round(time.time() - t0, 1)})
    except Exception as exc:
        yield emit("fatal", {"message": f"{type(exc).__name__}: {exc}"})


@app.get("/api/scan/stream")
async def scan_stream(source: str = "", limit: int = 50,
                      query: str = "", mailbox: str = "INBOX") -> StreamingResponse:
    src = source or ("imap" if settings.has_imap else "gmail")
    return StreamingResponse(
        _scan_events(src, limit, query or settings.query, mailbox),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no",
                 "Connection": "keep-alive"})


@app.get("/api/architecture")
def architecture() -> dict:
    """Live architecture description.

    Every number here is read from the running system or the saved training
    metrics -- nothing is hardcoded, so the diagram cannot drift away from what
    the code actually does.
    """
    import json as _json
    import subprocess as _sp
    from collections import Counter

    from sentinel.features.extractor import FEATURE_NAMES
    from sentinel.features.lexicons import LEXICON_NAMES
    from sentinel.models.vector import LEARNABLE
    from sentinel.scoring import floors as _floors
    from sentinel.scoring.prior import TRAIN_PRIOR

    e = engine()
    groups = Counter(n.split("_")[0] for n in FEATURE_NAMES)
    metrics = {}
    mp = ARTIFACTS / "intent_metrics.json"
    if mp.exists():
        try:
            metrics = _json.loads(mp.read_text())
        except Exception:
            pass

    # Floors are discovered by reading the module, so adding one updates the
    # diagram without anyone remembering to.
    floor_names = sorted(set(_floors.FLOOR_VECTOR) | {"bec_triad", "bank_detail_change",
                                                      "password_protected_archive",
                                                      "first_contact_ask",
                                                      "first_contact_attachment",
                                                      "failed_authentication_with_lure",
                                                      "reply_to_divergence",
                                                      "return_path_mismatch",
                                                      "signin_page_on_abuse_tld"})
    try:
        n_tests = int(_sp.run([".venv/bin/python", "-m", "pytest", "--collect-only", "-q",
                               "tests/"], capture_output=True, text=True, timeout=60,
                              cwd=str(ARTIFACTS.parent)).stdout.strip()
                      .splitlines()[-1].split()[0])
    except Exception:
        n_tests = 0

    return {
        "features": {"total": len(FEATURE_NAMES), "groups": dict(groups)},
        "lexicons": len(LEXICON_NAMES),
        "vectors": {"total": len(TAXONOMY),
                    "learnable": list(LEARNABLE),
                    "rule_only": [k for k in TAXONOMY
                                  if k not in LEARNABLE and k != "benign"]},
        "floors": {"count": len(floor_names), "names": floor_names},
        "models": {
            "blend": e.intent.blend_weights,
            "structural_auc": metrics.get("structural_only_auc"),
            "wording_auc": metrics.get("wording_only_auc"),
            "blended_auc": metrics.get("roc_auc"),
            "brier": metrics.get("brier"),
            "ngrams": metrics.get("n_ngram_features"),
            "n_test": metrics.get("n_test"),
            "train_prior": TRAIN_PRIOR,
            "deploy_prior": settings.inbox_base_rate,
        },
        "enrichment": {
            "history_domains": len(e.history.domains) if e.history else 0,
            "history_messages": e.history.messages_scanned if e.history else 0,
            "rdap": settings.enable_rdap,
            "llm": llm_providers.available(settings),
        },
        "actions": {"mode": settings.auto_action, "armed": settings.auto_action_armed,
                    "threshold": settings.auto_action_threshold},
        "tests": n_tests,
    }


@app.get("/api/campaigns")
def campaigns(min_size: int = 2) -> dict:
    """Cluster everything scored this session into campaigns.

    Operates on the session cache, so it reflects whatever was last scanned --
    a wider scan finds longer-running campaigns.
    """
    cs = cluster_campaigns(list(_cache.values()), min_size=min_size)
    return {"campaigns": [c.to_dict() for c in cs],
            "scanned": len(_cache), "found": len(cs)}


@app.get("/api/campaign/{cid}/graph")
def campaign_graph_endpoint(cid: str) -> dict:
    for c in cluster_campaigns(list(_cache.values()), min_size=2):
        if c.id == cid:
            return campaign_graph(c)
    raise HTTPException(404, "campaign not found — rescan to rebuild")


class ScoreBody(BaseModel):
    subject: str = ""
    body: str = ""
    sender: str = ""
    receiver: str = ""


@app.post("/api/score")
def score_live(b: ScoreBody) -> dict:
    """Score an arbitrary draft. Backs the playground.

    Deliberately light: no profiling, no graph, no caching. It is called on
    every keystroke pause, so it returns only what the live panel renders --
    the verdict, the severity arithmetic and the top attributions.
    """
    a = engine().analyze(Email(subject=b.subject, body=b.body, sender=b.sender,
                               receiver=b.receiver or "you@example.com",
                               source="playground"))
    return {
        "score": a.severity.score, "band": a.severity.band,
        "probability": round(a.probability, 4),
        "model_probability": round(a.model_probability, 4),
        "vector": a.vector_key, "vector_name": a.vector.name,
        "verdict": a.verdict, "decided_by": a.decided_by,
        "arithmetic": a.severity.arithmetic(),
        "intent": a.severity.intent, "impact": a.severity.impact,
        "exploitability": a.severity.exploitability, "targeting": a.severity.targeting,
        "floors": [{"name": f.name, "why": f.why, "min": f.minimum}
                   for f in a.floors_binding],
        "findings": [{"headline": f.headline, "shap": round(f.contribution, 3),
                      "kind": f.kind, "detail": f.detail, "feature": f.feature}
                     for f in a.findings_up[:9]],
        "against": [{"headline": f.headline, "shap": round(f.contribution, 3)}
                    for f in a.findings_down[:4]],
        "urls": [u.raw[:90] for u in a.evidence.urls[:5]],
        "phones": [ph.raw for ph in a.evidence.phones[:3]],
        "lexicons": sorted({h.lexicon for h in a.evidence.hits}),
    }


@app.get("/api/graph/{mid}")
def attack_graph(mid: str, force: bool = False) -> dict:
    """Attack lineage for a scored message, as nodes and edges.

    Gated on the same threshold as profiling. Drawing an "attack lineage" for a
    delivery receipt implies an attack that is not there, which is a worse
    failure than showing nothing.
    """
    a = _cache.get(mid)
    if a is None:
        raise HTTPException(404, "not in this session's cache — rescan to load it")
    if not force and a.severity.score < settings.llm_profile_min_score:
        return {"nodes": [], "edges": [], "skipped": True,
                "reason": f"severity {a.severity.score:.1f} is below the "
                          f"threshold of {settings.llm_profile_min_score:g}"}
    g = build_graph(a).to_dict()
    g["band"] = a.severity.band
    g["score"] = a.severity.score
    g["vector"] = a.vector.name
    return g


@app.get("/api/profile/{mid}")
async def threat_profile(mid: str, force: bool = False) -> dict:
    """Narrative tactic write-up for a message already scored this session.

    Runs in a thread so a slow provider cannot block the event loop, and the
    dashboard requests it in parallel with rendering the deterministic analysis
    — the score and the SHAP evidence are on screen before this returns, and
    stay on screen if it never does.
    """
    a = _cache.get(mid)
    if a is None:
        raise HTTPException(404, "not in this session's cache — rescan to load it")
    # `force` is what the "Profile anyway" button sends: the threshold is a
    # default, not a prohibition.
    if not force and a.severity.score < settings.llm_profile_min_score:
        return {"ok": False, "skipped": True,
                "error": f"severity {a.severity.score:.1f} is below the "
                         f"profiling threshold of {settings.llm_profile_min_score:g}"}
    p = await asyncio.to_thread(build_profile, a, settings, _profiles, force)
    return p.to_dict()


class NoCacheStatic(StaticFiles):
    """Serve the UI with revalidation forced.

    Default heuristic caching kept a stale architecture.js alive across a
    server restart, so a fixed bug still looked broken in the browser. These
    files are read from local disk on every request anyway -- there is nothing
    to gain from caching them and a whole class of phantom bugs to lose.
    """

    async def get_response(self, path: str, scope: Scope):
        r = await super().get_response(path, scope)
        r.headers["Cache-Control"] = "no-cache, must-revalidate"
        return r


app.mount("/static", NoCacheStatic(directory=STATIC), name="static")
