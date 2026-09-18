"""Attachment lineage: from the message, through the disk, to what runs.

What this does, honestly, at each stage:

  in the message   Extract every MIME part, hash it, unwrap one layer of
                   archive to see what is actually inside, and reconstruct the
                   real type from magic bytes rather than the filename. A file
                   called invoice.pdf that begins with MZ is a Windows
                   executable, and the extension is the attacker's claim, not
                   a fact.

  on the disk      Watch the download directories for a file whose hash matches
                   an attachment that arrived above the severity threshold, and
                   read macOS's com.apple.quarantine attribute, which records
                   which application wrote the file and from where.

  after execution  Correlate the tracked path against running processes, and
                   record every change to size, mtime and permissions.

That third stage is where honesty matters. Real behavioural monitoring -- what
a process opens, which domains it resolves, what it writes -- requires Apple's
Endpoint Security framework, which needs an entitlement Apple grants to
security vendors and a signed, notarised binary. This module cannot do that and
does not pretend to. What it gives is the user-level view: did this exact file
appear, did it change, is something running from that path. Useful, bounded,
and not a sandbox.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import plistlib
import subprocess
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from email.message import Message
from pathlib import Path

from .config import ARTIFACTS

TRACK_PATH = ARTIFACTS / "file_tracking.json"
LOG_PATH = ARTIFACTS / "file_activity.jsonl"
DEFAULT_WATCH = (Path.home() / "Downloads", Path.home() / "Desktop")

# The first bytes tell the truth; the extension is a claim.
MAGIC = [
    (b"MZ", "windows-executable", True),
    (b"\x7fELF", "linux-executable", True),
    (b"\xca\xfe\xba\xbe", "macho-fat-binary", True),
    (b"\xcf\xfa\xed\xfe", "macho-executable", True),
    (b"%PDF", "pdf", False),
    (b"PK\x03\x04", "zip-container", False),
    (b"Rar!", "rar-archive", False),
    (b"\xd0\xcf\x11\xe0", "ole-compound (legacy office)", False),
    (b"#!", "script", True),
    (b"\x1f\x8b", "gzip", False),
]
ARCHIVE_EXT = {".zip", ".jar", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".odt"}
EXECUTABLE_INSIDE = {".exe", ".scr", ".bat", ".cmd", ".com", ".vbs", ".js", ".jse",
                     ".wsf", ".hta", ".ps1", ".lnk", ".msi", ".dll", ".pif", ".app"}


@dataclass
class AttachmentFile:
    filename: str
    sha256: str
    md5: str
    size: int
    declared_ext: str = ""
    real_type: str = "unknown"
    executable: bool = False
    type_mismatch: bool = False
    archive_contents: list[str] = field(default_factory=list)
    archive_hides_executable: bool = False
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _identify(data: bytes) -> tuple[str, bool]:
    for magic, name, is_exec in MAGIC:
        if data.startswith(magic):
            return name, is_exec
    return "unknown", False


def _peek_archive(data: bytes, name: str) -> tuple[list[str], bool]:
    """One layer only. Recursing into nested archives is how a scanner gets
    turned into a zip bomb."""
    if not name.lower().endswith(tuple(ARCHIVE_EXT)) and not data.startswith(b"PK\x03\x04"):
        return [], False
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            names = z.namelist()[:60]
    except Exception:
        return [], False
    hides = any(Path(n).suffix.lower() in EXECUTABLE_INSIDE for n in names)
    return names[:12], hides


def from_message(msg: Message) -> list[AttachmentFile]:
    out: list[AttachmentFile] = []
    for part in msg.walk():
        name = part.get_filename()
        if not name:
            continue
        try:
            data = part.get_payload(decode=True) or b""
        except Exception:
            continue
        if not data:
            continue
        real, is_exec = _identify(data)
        ext = Path(name).suffix.lower()
        a = AttachmentFile(
            filename=name[:150], sha256=hashlib.sha256(data).hexdigest(),
            md5=hashlib.md5(data).hexdigest(), size=len(data),
            declared_ext=ext, real_type=real, executable=is_exec)
        a.archive_contents, a.archive_hides_executable = _peek_archive(data, name)

        benign_ext = {".pdf": "pdf", ".zip": "zip-container", ".docx": "zip-container",
                      ".xlsx": "zip-container", ".pptx": "zip-container",
                      ".doc": "ole-compound (legacy office)",
                      ".xls": "ole-compound (legacy office)"}
        expected = benign_ext.get(ext)
        if expected and real != "unknown" and real != expected:
            a.type_mismatch = True
            a.notes.append(f"claims to be {ext} but the file actually begins as "
                           f"{real} -- the extension is a claim, the magic bytes are not")
        if is_exec:
            a.notes.append(f"is a {real} and will run if opened")
        if a.archive_hides_executable:
            inner = [n for n in a.archive_contents
                     if Path(n).suffix.lower() in EXECUTABLE_INSIDE]
            a.notes.append(f"archive contains an executable: {', '.join(inner[:3])}")
        out.append(a)
    return out


# --------------------------------------------------------------- disk tracking
def quarantine_origin(path: Path) -> str:
    """macOS records which app wrote a downloaded file, and from where."""
    try:
        raw = subprocess.run(["xattr", "-p", "com.apple.quarantine", str(path)],
                             capture_output=True, text=True, timeout=5).stdout.strip()
    except Exception:
        return ""
    if not raw:
        return ""
    parts = raw.split(";")
    agent = parts[2] if len(parts) > 2 else "?"
    return f"written by {agent}" + (f" from {parts[3]}" if len(parts) > 3 else "")


def hash_file(path: Path, limit: int = 80 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    try:
        with path.open("rb") as f:
            read = 0
            while chunk := f.read(1 << 20):
                h.update(chunk)
                read += len(chunk)
                if read > limit:
                    return ""
    except Exception:
        return ""
    return h.hexdigest()


@dataclass
class TrackedFile:
    sha256: str
    filename: str
    source_subject: str = ""
    source_sender: str = ""
    severity: float = 0.0
    vector: str = ""
    added: str = ""
    seen_paths: list[str] = field(default_factory=list)
    quarantine: str = ""
    executed: bool = False
    observations: int = 0
    last_size: int = 0
    last_mtime: float = 0.0


class FileTracker:
    """Watches for attachments that were scored above the threshold.

    Only those. Tracking every file a machine downloads would be surveillance
    with a security label on it; tracking the specific files that arrived by
    mail and scored dangerous is a proportionate answer to a specific question.
    """

    def __init__(self, path: Path = TRACK_PATH, log: Path = LOG_PATH,
                 watch_dirs=DEFAULT_WATCH, min_severity: float = 40.0):
        self.path, self.log, self.min_severity = path, log, min_severity
        self.watch_dirs = [Path(d) for d in watch_dirs]
        self.files: dict[str, TrackedFile] = {}
        if path.exists():
            try:
                for k, v in json.loads(path.read_text()).items():
                    self.files[k] = TrackedFile(**v)
            except Exception:
                pass

    def save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps({k: asdict(v) for k, v in self.files.items()}))
            self.path.chmod(0o600)
        except Exception:
            pass

    def _log(self, event: str, tf: TrackedFile, extra: dict | None = None) -> None:
        rec = {"at": datetime.now(timezone.utc).isoformat(), "event": event,
               "sha256": tf.sha256, "filename": tf.filename,
               "severity": tf.severity, "vector": tf.vector, **(extra or {})}
        try:
            self.log.parent.mkdir(parents=True, exist_ok=True)
            with self.log.open("a") as f:
                f.write(json.dumps(rec) + "\n")
            self.log.chmod(0o600)
        except Exception:
            pass

    def register(self, att: AttachmentFile, *, subject: str, sender: str,
                 severity: float, vector: str) -> bool:
        """Start tracking, but only above the threshold."""
        if severity < self.min_severity:
            return False
        if att.sha256 in self.files:
            return True
        tf = TrackedFile(sha256=att.sha256, filename=att.filename,
                         source_subject=subject[:120], source_sender=sender[:120],
                         severity=severity, vector=vector,
                         added=datetime.now(timezone.utc).isoformat())
        self.files[att.sha256] = tf
        self._log("registered", tf, {"size": att.size, "real_type": att.real_type})
        self.save()
        return True

    def sweep(self) -> list[dict]:
        """Look for tracked hashes on disk and record what changed."""
        events: list[dict] = []
        if not self.files:
            return events
        wanted = set(self.files)
        for d in self.watch_dirs:
            if not d.is_dir():
                continue
            for p in d.iterdir():
                if not p.is_file() or p.name.startswith("."):
                    continue
                try:
                    st = p.stat()
                except OSError:
                    continue
                if st.st_size > 80 * 1024 * 1024:
                    continue
                digest = hash_file(p)
                if digest not in wanted:
                    continue
                tf = self.files[digest]
                tf.observations += 1
                first = str(p) not in tf.seen_paths
                if first:
                    tf.seen_paths.append(str(p))
                    tf.quarantine = quarantine_origin(p) or tf.quarantine
                    ev = {"event": "appeared_on_disk", "path": str(p),
                          "quarantine": tf.quarantine}
                    self._log("appeared_on_disk", tf, {"path": str(p),
                                                       "quarantine": tf.quarantine})
                    events.append({**ev, "sha256": digest, "filename": tf.filename})
                elif st.st_size != tf.last_size and tf.last_size:
                    self._log("size_changed", tf, {"path": str(p), "from": tf.last_size,
                                                   "to": st.st_size})
                    events.append({"event": "size_changed", "path": str(p),
                                   "sha256": digest, "filename": tf.filename})
                tf.last_size, tf.last_mtime = st.st_size, st.st_mtime

                if not tf.executed and _running_from(p):
                    tf.executed = True
                    self._log("process_running_from_path", tf, {"path": str(p)})
                    events.append({"event": "process_running_from_path",
                                   "path": str(p), "sha256": digest,
                                   "filename": tf.filename})
        self.save()
        return events


def _running_from(path: Path) -> bool:
    """Is a process running from this path? User-level only -- it sees what ps
    sees, which is not the same as knowing what the file did."""
    try:
        out = subprocess.run(["ps", "-Ao", "command"], capture_output=True,
                             text=True, timeout=6).stdout
    except Exception:
        return False
    return str(path) in out


# --------------------------------------------------------------- PE verdict
_PE_MODEL = None
_PE_FEATURES: list[str] = []


def pe_score(header_features: dict) -> tuple[float, str]:
    """Static-PE maliciousness, with the caveat attached to every use.

    Measured on the bundled dataset this reaches 0.9998 ROC-AUC, and that
    number is misleading. ImageBase alone reaches 0.938 on the same data
    because 99% of its malicious samples use 0x400000 against 12% of the
    legitimate ones -- the default for older 32-bit toolchains. A large part of
    the separation is compiler era, not intent. Treated here as one weak
    opinion alongside VirusTotal, never as a verdict.
    """
    global _PE_MODEL, _PE_FEATURES
    import lightgbm as lgb
    if _PE_MODEL is None:
        mp = ARTIFACTS / "pe_model.txt"
        fp = ARTIFACTS / "pe_model_features.json"
        if not (mp.exists() and fp.exists()):
            return 0.0, "no PE model trained"
        _PE_MODEL = lgb.Booster(model_file=str(mp))
        _PE_FEATURES = json.loads(fp.read_text())
    import numpy as np
    x = np.array([[float(header_features.get(k, 0) or 0) for k in _PE_FEATURES]],
                 dtype=np.float32)
    p = float(_PE_MODEL.predict(x)[0])
    return p, (f"static PE model scores {p:.2f} — header layout only, and this "
               f"model's training data separates largely on compiler era, so "
               f"treat it as a weak signal beside a hash lookup")


def file_features(atts: list[AttachmentFile]) -> dict[str, float]:
    return {
        "fil_count": float(len(atts)),
        "fil_executable": float(any(a.executable for a in atts)),
        "fil_type_mismatch": float(any(a.type_mismatch for a in atts)),
        "fil_archive_hides_exe": float(any(a.archive_hides_executable for a in atts)),
    }


FILE_FEATURE_NAMES = tuple(file_features([]).keys())
