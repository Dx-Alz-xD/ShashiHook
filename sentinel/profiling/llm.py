"""Provider abstraction: Gemini first, Groq as fallback.

Fallback is per-request and automatic. If Gemini is unconfigured, rate-limited,
erroring or slow, the same prompt goes to Groq. If neither answers, profiling is
simply unavailable and the rest of the application is unaffected -- the verdict,
the severity and the SHAP explanation never depended on a language model and
must keep working when one is absent.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

import requests

from ..settings import Settings

GEMINI_URL = ("https://generativelanguage.googleapis.com/v1beta/models/"
              "{model}:generateContent")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"


@dataclass
class LLMResult:
    ok: bool
    provider: str = ""
    model: str = ""
    data: dict = field(default_factory=dict)
    raw: str = ""
    error: str = ""
    latency_ms: int = 0


def _extract_json(text: str) -> dict | None:
    """Models wrap JSON in prose or fences more often than they should."""
    if not text:
        return None
    t = text.strip()
    t = re.sub(r"^```(?:json)?\s*|\s*```$", "", t, flags=re.MULTILINE).strip()
    try:
        return json.loads(t)
    except Exception:
        pass
    start, depth = t.find("{"), 0
    if start < 0:
        return None
    for i in range(start, len(t)):
        if t[i] == "{":
            depth += 1
        elif t[i] == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(t[start:i + 1])
                except Exception:
                    return None
    return None


def _call_gemini(cfg: Settings, system: str, user: str) -> LLMResult:
    if not cfg.gemini_api_key:
        return LLMResult(False, "gemini", error="no API key")
    import time
    t0 = time.time()
    try:
        r = requests.post(
            GEMINI_URL.format(model=cfg.gemini_model),
            params={"key": cfg.gemini_api_key},
            json={
                "systemInstruction": {"parts": [{"text": system}]},
                "contents": [{"role": "user", "parts": [{"text": user}]}],
                "generationConfig": {"temperature": 0.2, "maxOutputTokens": 2048,
                                     "responseMimeType": "application/json"},
            },
            timeout=cfg.llm_timeout,
        )
        ms = int((time.time() - t0) * 1000)
        if r.status_code != 200:
            return LLMResult(False, "gemini", cfg.gemini_model,
                             error=f"HTTP {r.status_code}: {r.text[:180]}", latency_ms=ms)
        payload = r.json()
        text = "".join(
            p.get("text", "")
            for c in payload.get("candidates", [])
            for p in c.get("content", {}).get("parts", []))
        data = _extract_json(text)
        if data is None:
            return LLMResult(False, "gemini", cfg.gemini_model, raw=text[:400],
                             error="response was not JSON", latency_ms=ms)
        return LLMResult(True, "gemini", cfg.gemini_model, data=data, raw=text, latency_ms=ms)
    except Exception as e:
        return LLMResult(False, "gemini", cfg.gemini_model,
                         error=f"{type(e).__name__}: {e}",
                         latency_ms=int((time.time() - t0) * 1000))


def _call_groq(cfg: Settings, system: str, user: str) -> LLMResult:
    if not cfg.groq_api_key:
        return LLMResult(False, "groq", error="no API key")
    import time
    t0 = time.time()
    try:
        r = requests.post(
            GROQ_URL,
            headers={"Authorization": f"Bearer {cfg.groq_api_key}",
                     "Content-Type": "application/json"},
            json={"model": cfg.groq_model, "temperature": 0.2, "max_tokens": 2048,
                  "response_format": {"type": "json_object"},
                  "messages": [{"role": "system", "content": system},
                               {"role": "user", "content": user}]},
            timeout=cfg.llm_timeout,
        )
        ms = int((time.time() - t0) * 1000)
        if r.status_code != 200:
            return LLMResult(False, "groq", cfg.groq_model,
                             error=f"HTTP {r.status_code}: {r.text[:180]}", latency_ms=ms)
        text = r.json()["choices"][0]["message"]["content"]
        data = _extract_json(text)
        if data is None:
            return LLMResult(False, "groq", cfg.groq_model, raw=text[:400],
                             error="response was not JSON", latency_ms=ms)
        return LLMResult(True, "groq", cfg.groq_model, data=data, raw=text, latency_ms=ms)
    except Exception as e:
        return LLMResult(False, "groq", cfg.groq_model,
                         error=f"{type(e).__name__}: {e}",
                         latency_ms=int((time.time() - t0) * 1000))


def complete(cfg: Settings, system: str, user: str) -> LLMResult:
    """Gemini, then Groq. Errors from the first are carried into the second's
    message so a failure is diagnosable rather than silently swallowed."""
    order = [_call_gemini, _call_groq]
    if cfg.llm_primary == "groq":
        order.reverse()
    errors: list[str] = []
    for fn in order:
        res = fn(cfg, system, user)
        if res.ok:
            if errors:
                res.error = f"(fell back after: {'; '.join(errors)})"
            return res
        errors.append(f"{res.provider}: {res.error}")
    # Every failure, not just the first. Reporting only the primary's error hid
    # the fallback's error completely and made a two-provider outage look like a
    # one-provider outage.
    return LLMResult(False, "none",
                     error=" | ".join(errors) or "no provider configured")


def list_models(cfg: Settings) -> dict:
    """What each configured provider will actually serve right now.

    Exists because a retired model id fails as an opaque 404 at request time.
    `sentinel config` calls this so the problem is visible before a scan.
    """
    out: dict = {"gemini": [], "groq": [], "errors": []}
    if cfg.gemini_api_key:
        try:
            r = requests.get("https://generativelanguage.googleapis.com/v1beta/models",
                             params={"key": cfg.gemini_api_key}, timeout=15)
            if r.status_code == 200:
                out["gemini"] = [m["name"].replace("models/", "")
                                 for m in r.json().get("models", [])
                                 if "generateContent" in m.get("supportedGenerationMethods", [])]
            else:
                out["errors"].append(f"gemini list: HTTP {r.status_code}")
        except Exception as e:
            out["errors"].append(f"gemini list: {type(e).__name__}")
    if cfg.groq_api_key:
        try:
            r = requests.get("https://api.groq.com/openai/v1/models",
                             headers={"Authorization": f"Bearer {cfg.groq_api_key}"},
                             timeout=15)
            if r.status_code == 200:
                out["groq"] = sorted(m["id"] for m in r.json().get("data", []))
            else:
                out["errors"].append(f"groq list: HTTP {r.status_code}")
        except Exception as e:
            out["errors"].append(f"groq list: {type(e).__name__}")
    return out


def available(cfg: Settings) -> dict:
    return {"gemini": bool(cfg.gemini_api_key), "groq": bool(cfg.groq_api_key),
            "primary": cfg.llm_primary,
            "any": bool(cfg.gemini_api_key or cfg.groq_api_key)}
