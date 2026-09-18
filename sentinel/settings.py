"""Configuration loaded from the environment / .env.

Nothing in here is ever logged or written into a report. Credentials are read
once, used to open a connection, and not retained beyond that.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

from .config import PROJECT_ROOT

ENV_PATH = PROJECT_ROOT / ".env"
load_dotenv(ENV_PATH)

# OAuth scope. Deliberately read-only: this tool has no reason to modify,
# label, send or delete anything, and a narrower scope is a smaller blast
# radius if the token ever leaks.
GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


def _get(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def _flag(name: str, default: bool = False) -> bool:
    v = _get(name).lower()
    return default if not v else v in ("1", "true", "yes", "on")


@dataclass
class Settings:
    # --- Gmail API (OAuth 2.0) ---------------------------------------------
    gmail_client_id: str = field(default_factory=lambda: _get("GMAIL_CLIENT_ID"))
    gmail_client_secret: str = field(default_factory=lambda: _get("GMAIL_CLIENT_SECRET"))
    gmail_token_path: Path = field(
        default_factory=lambda: Path(_get("GMAIL_TOKEN_PATH", str(PROJECT_ROOT / ".gmail_token.json"))))
    gmail_credentials_file: str = field(default_factory=lambda: _get("GMAIL_CREDENTIALS_FILE"))

    # --- IMAP (app password) ------------------------------------------------
    imap_host: str = field(default_factory=lambda: _get("IMAP_HOST", "imap.gmail.com"))
    imap_port: int = field(default_factory=lambda: int(_get("IMAP_PORT", "993")))
    imap_user: str = field(default_factory=lambda: _get("IMAP_USER"))
    # Google displays app passwords grouped as "abcd efgh ijkl mnop". People
    # paste them with the spaces, and some IMAP servers reject that, so the
    # spaces are stripped here rather than becoming a mystery login failure.
    imap_password: str = field(
        default_factory=lambda: _get("IMAP_APP_PASSWORD").replace(" ", ""))

    # --- scan behaviour -----------------------------------------------------
    mailbox: str = field(default_factory=lambda: _get("SENTINEL_MAILBOX", "INBOX"))
    query: str = field(default_factory=lambda: _get("SENTINEL_QUERY", "newer_than:7d"))
    limit: int = field(default_factory=lambda: int(_get("SENTINEL_LIMIT", "50")))
    min_band_to_report: str = field(
        default_factory=lambda: _get("SENTINEL_MIN_BAND", "MEDIUM").upper())
    report_dir: Path = field(
        default_factory=lambda: Path(_get("SENTINEL_REPORT_DIR", str(PROJECT_ROOT / "reports"))))
    save_bodies: bool = field(default_factory=lambda: _flag("SENTINEL_SAVE_BODIES", False))
    # Realistic hostile fraction of the mail being scanned. The model was
    # trained at 49%; a normal inbox is 1-5%. Set to 0 to disable correction.
    # Off by default: enabling it tells the RDAP operator which domains you are
    # analysing. No message content is ever sent.
    enable_rdap: bool = field(default_factory=lambda: _flag("SENTINEL_ENABLE_RDAP", False))
    inbox_base_rate: float = field(
        default_factory=lambda: float(_get("SENTINEL_INBOX_BASE_RATE", "0.02")))

    # --- narrative profiling (Gemini primary, Groq fallback) ----------------
    # Advisory only. These keys being absent disables the tactic write-up and
    # changes no score: the verdict, severity and vector are produced by the
    # local models and rules, never by a language model.
    gemini_api_key: str = field(default_factory=lambda: _get("GEMINI_API_KEY"))
    gemini_model: str = field(
        default_factory=lambda: _get("GEMINI_MODEL", "gemini-2.0-flash"))
    groq_api_key: str = field(default_factory=lambda: _get("GROQ_API_KEY"))
    groq_model: str = field(
        default_factory=lambda: _get("GROQ_MODEL", "llama-3.3-70b-versatile"))
    llm_primary: str = field(default_factory=lambda: _get("LLM_PRIMARY", "gemini").lower())
    llm_timeout: float = field(default_factory=lambda: float(_get("LLM_TIMEOUT", "30")))
    llm_auto_profile: bool = field(default_factory=lambda: _flag("LLM_AUTO_PROFILE", True))

    # --- enrichment ---------------------------------------------------------
    ioc_file: str = field(default_factory=lambda: _get("SENTINEL_IOC_FILE"))
    software_allowlist_file: str = field(
        default_factory=lambda: _get("SENTINEL_SOFTWARE_ALLOWLIST_FILE"))

    # ------------------------------------------------------------------ views
    @property
    def has_oauth(self) -> bool:
        return bool((self.gmail_client_id and self.gmail_client_secret)
                    or self.gmail_credentials_file)

    @property
    def has_imap(self) -> bool:
        return bool(self.imap_user and self.imap_password)

    def load_iocs(self) -> set[str]:
        return self._read_domain_file(self.ioc_file)

    def load_software_allowlist(self) -> set[str]:
        return self._read_domain_file(self.software_allowlist_file)

    @staticmethod
    def _read_domain_file(path: str) -> set[str]:
        if not path or not Path(path).exists():
            return set()
        return {ln.strip().lower() for ln in Path(path).read_text().splitlines()
                if ln.strip() and not ln.lstrip().startswith("#")}

    def describe(self) -> str:
        """Human-readable status with no secret values in it."""
        def mask(v: str) -> str:
            return f"set ({len(v)} chars)" if v else "not set"
        return "\n".join([
            f"  .env file                {ENV_PATH}  "
            f"{'found' if ENV_PATH.exists() else 'MISSING'}",
            f"  GMAIL_CLIENT_ID          {mask(self.gmail_client_id)}",
            f"  GMAIL_CLIENT_SECRET      {mask(self.gmail_client_secret)}",
            f"  GMAIL_CREDENTIALS_FILE   {self.gmail_credentials_file or 'not set'}",
            f"  token cache              {self.gmail_token_path}  "
            f"{'present' if self.gmail_token_path.exists() else 'absent (run: sentinel auth)'}",
            f"  IMAP_USER                {self.imap_user or 'not set'}",
            f"  IMAP_APP_PASSWORD        {mask(self.imap_password)}",
            f"  mailbox / query          {self.mailbox} / {self.query!r}",
            f"  report dir               {self.report_dir}",
            f"  save message bodies      {self.save_bodies}",
            f"  RDAP domain age          {'enabled' if self.enable_rdap else 'disabled'}",
            f"  GEMINI_API_KEY           {mask(self.gemini_api_key)}  "
            f"({self.gemini_model})",
            f"  GROQ_API_KEY             {mask(self.groq_api_key)}  ({self.groq_model})",
            f"  LLM primary              {self.llm_primary}",
            f"  inbox base rate          {self.inbox_base_rate:.1%} "
            f"(model trained at 49%)",
        ])


settings = Settings()
