"""HTTP service.

    uvicorn sentinel.api:app --port 8080

POST /analyze  with {"raw": "<full RFC-822 message>"} or the parsed fields.
Returns the same incident dictionary the CLI writes, so a SIEM and an analyst
see identical content.
"""
from __future__ import annotations

from functools import lru_cache

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .analyzer import ThreatAnalyzer
from .features.extractor import Email
from .ingest.eml import from_string
from .report.incident import to_dict, to_markdown

app = FastAPI(title="Sentinel", version="1.0",
              description="Explainable email threat analysis")


@lru_cache(maxsize=1)
def analyzer() -> ThreatAnalyzer:
    return ThreatAnalyzer()


class AnalyzeRequest(BaseModel):
    raw: str | None = Field(None, description="Full RFC-822 message source")
    subject: str = ""
    body: str = ""
    sender: str = ""
    receiver: str = ""
    date: str = ""
    html: str | None = None
    attachments: list[str] = Field(default_factory=list)
    format: str = Field("json", pattern="^(json|markdown)$")


@app.get("/health")
def health() -> dict:
    a = analyzer()
    return {"status": "ok",
            "intent_features": len(a.intent.feature_names),
            "vector_model": a.vector_model is not None,
            "blend_weights": a.intent.blend_weights}


@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    if req.raw:
        email = from_string(req.raw)
    elif req.body or req.subject:
        email = Email(subject=req.subject, body=req.body, sender=req.sender,
                      receiver=req.receiver, date=req.date, html=req.html,
                      attachments=req.attachments, source="api")
    else:
        raise HTTPException(400, "provide either 'raw' or at least 'subject'/'body'")

    result = analyzer().analyze(email)
    if req.format == "markdown":
        return {"markdown": to_markdown(result)}
    return to_dict(result)
