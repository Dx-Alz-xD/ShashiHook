"""VirusTotal lookups, hash-first.

Two very different operations behind one API:

  hash lookup   Sends a SHA-256 and nothing else. VirusTotal either recognises
                the file or does not. Private, free within the public quota,
                and the default here.

  file upload   Sends the file itself. VirusTotal shares uploaded samples with
                its security-industry partners, permanently. An attachment can
                be a contract, a payslip or a medical letter, so uploading one
                is a disclosure decision the user has to make deliberately --
                it is off unless explicitly enabled, and even then only for
                files the engine already considers dangerous.

A hash miss means "not seen before", never "safe". Novel malware is unknown to
VirusTotal by definition, and targeted samples usually stay unknown.
"""
from __future__ import annotations

import hashlib
import json
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

API = "https://www.virustotal.com/api/v3"
TIMEOUT = 25.0


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ctx() -> ssl.SSLContext:
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


@dataclass
class FileVerdict:
    sha256: str = ""
    filename: str = ""
    size: int = 0
    known: bool = False
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    type_tag: str = ""
    names: list[str] = field(default_factory=list)
    first_seen: str = ""
    error: str = ""

    @property
    def detection_ratio(self) -> float:
        total = self.malicious + self.suspicious + self.harmless + self.undetected
        return (self.malicious + self.suspicious) / total if total else 0.0

    def describe(self) -> str:
        if self.error:
            return f"VirusTotal: {self.error}"
        if not self.known:
            return ("VirusTotal has never seen this file. That is not a clean "
                    "verdict -- novel and targeted samples are unknown by "
                    "definition.")
        return (f"VirusTotal: {self.malicious} engines flag this malicious, "
                f"{self.suspicious} suspicious, of "
                f"{self.malicious + self.suspicious + self.harmless + self.undetected} "
                f"({self.detection_ratio:.0%})"
                + (f", type {self.type_tag}" if self.type_tag else ""))


class VirusTotal:
    def __init__(self, api_key: str = "", allow_upload: bool = False,
                 cache_path: Path | None = None):
        self.key = (api_key or "").strip()
        self.allow_upload = allow_upload
        self.cache_path = cache_path
        self._cache: dict = {}
        if cache_path and cache_path.exists():
            try:
                self._cache = json.loads(cache_path.read_text())
            except Exception:
                self._cache = {}
        self._last_call = 0.0

    @property
    def enabled(self) -> bool:
        return bool(self.key)

    def _throttle(self) -> None:
        # Public quota is 4 requests/minute. Exceeding it gets the key blocked,
        # which is a worse outcome than a slow scan.
        wait = 16.0 - (time.time() - self._last_call)
        if wait > 0:
            time.sleep(wait)
        self._last_call = time.time()

    def _save(self) -> None:
        if not self.cache_path:
            return
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps(self._cache))
            self.cache_path.chmod(0o600)
        except Exception:
            pass

    def lookup(self, digest: str, filename: str = "", size: int = 0) -> FileVerdict:
        v = FileVerdict(sha256=digest, filename=filename, size=size)
        if digest in self._cache:
            return FileVerdict(**{**self._cache[digest], "filename": filename})
        if not self.enabled:
            v.error = "no VIRUSTOTAL_API_KEY configured"
            return v

        self._throttle()
        req = urllib.request.Request(f"{API}/files/{digest}",
                                     headers={"x-apikey": self.key,
                                              "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT, context=_ctx()) as r:
                d = json.loads(r.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                v.known = False
                self._cache[digest] = {k: getattr(v, k) for k in
                                       ("sha256", "size", "known", "malicious",
                                        "suspicious", "harmless", "undetected",
                                        "type_tag", "names", "first_seen", "error")}
                self._save()
                return v
            v.error = f"HTTP {e.code}"
            return v
        except Exception as e:
            v.error = f"{type(e).__name__}"
            return v

        attr = (d.get("data") or {}).get("attributes") or {}
        stats = attr.get("last_analysis_stats") or {}
        v.known = True
        v.malicious = int(stats.get("malicious", 0))
        v.suspicious = int(stats.get("suspicious", 0))
        v.harmless = int(stats.get("harmless", 0))
        v.undetected = int(stats.get("undetected", 0))
        v.type_tag = str(attr.get("type_tag", ""))[:40]
        v.names = [str(n)[:80] for n in (attr.get("names") or [])[:5]]
        fs = attr.get("first_submission_date")
        if fs:
            v.first_seen = time.strftime("%Y-%m-%d", time.gmtime(int(fs)))
        self._cache[digest] = {k: getattr(v, k) for k in
                               ("sha256", "size", "known", "malicious", "suspicious",
                                "harmless", "undetected", "type_tag", "names",
                                "first_seen", "error")}
        self._save()
        return v


def vt_features(v: FileVerdict) -> dict[str, float]:
    return {
        "vt_known": float(v.known),
        "vt_malicious": float(v.malicious),
        "vt_detection_ratio": float(v.detection_ratio),
    }


VT_FEATURE_NAMES = tuple(vt_features(FileVerdict()).keys())
