"""Command-line entry point.

    python -m sentinel.cli analyze message.eml     score one .eml file
    cat message.eml | python -m sentinel.cli analyze -
    python -m sentinel.cli demo                    three built-in samples

    python -m sentinel.cli config                  check .env without printing secrets
    python -m sentinel.cli auth                    one-time Gmail OAuth consent
    python -m sentinel.cli scan --limit 50         triage a live mailbox
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .analyzer import ThreatAnalyzer
from .ingest.eml import from_file, from_string
from .report.incident import to_json, to_markdown


def _load_iocs(path: str | None) -> set[str]:
    if not path:
        return set()
    return {ln.strip().lower() for ln in Path(path).read_text().splitlines()
            if ln.strip() and not ln.startswith("#")}


def cmd_analyze(args: argparse.Namespace) -> int:
    email = from_string(sys.stdin.read()) if args.path == "-" else from_file(args.path)
    analyzer = ThreatAnalyzer(known_bad_iocs=_load_iocs(args.iocs),
                              software_allowlist=_load_iocs(args.software_allowlist))
    analysis = analyzer.analyze(email)
    out = to_json(analysis) if args.json else to_markdown(analysis)
    if args.out:
        Path(args.out).write_text(out)
        print(f"wrote {args.out}  [{analysis.severity.band} {analysis.severity.score}]")
    else:
        print(out)
    return 0 if analysis.severity.band in ("INFORMATIONAL", "LOW") else 2


def cmd_config(args: argparse.Namespace) -> int:
    from .settings import settings
    print("Sentinel configuration\n")
    print(settings.describe())
    print()
    if settings.has_oauth:
        state = "ready" if Path(settings.gmail_token_path).exists() else "needs `sentinel auth`"
        print(f"  Gmail API (OAuth, read-only): configured — {state}")
    else:
        print("  Gmail API (OAuth, read-only): not configured")
    print(f"  IMAP (app password):          "
          f"{'configured' if settings.has_imap else 'not configured'}")
    if not (settings.has_oauth or settings.has_imap):
        print("\n  Neither path is set up. Copy .env.example to .env and fill in one.")
        print("  Note: a Google API key cannot read a mailbox — Gmail needs OAuth")
        print("  or an IMAP app password.")
        return 1
    return 0


def cmd_auth(args: argparse.Namespace) -> int:
    from .ingest.gmail import authorise
    from .settings import settings
    if not settings.has_oauth:
        print("Set GMAIL_CLIENT_ID and GMAIL_CLIENT_SECRET in .env first "
              "(see .env.example).")
        return 1
    print("Opening your browser for Google consent (read-only Gmail scope)…")
    if args.port:
        print(f"Using fixed redirect http://localhost:{args.port}/ — this must be "
              f"registered on the OAuth client.")
    try:
        addr = authorise(settings, port=args.port)
    except Exception as exc:
        from .ingest.gmail import explain_oauth_error
        print(f"\nAuthorisation failed: {exc}\n")
        print(explain_oauth_error(exc))
        print("\nFull walkthrough: GMAIL.md")
        return 1
    print(f"Authorised as {addr}")
    print(f"Refresh token cached at {settings.gmail_token_path} (mode 0600, gitignored).")
    print("Revoke any time at https://myaccount.google.com/permissions")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    from .mailbox import BAND_RANK, format_table, scan
    from .settings import settings

    source = args.source
    if source == "auto":
        source = "gmail" if settings.has_oauth else "imap" if settings.has_imap else ""
        if not source:
            print("No mailbox configured. Run `sentinel config` for the checklist.")
            return 1

    print(f"Scanning {source} · mailbox={args.mailbox or settings.mailbox} · "
          f"query={args.query or settings.query!r} · limit={args.limit or settings.limit}")
    if args.dry_run:
        print("(dry run: fetching and scoring, writing nothing to disk)")

    settings.mailbox = args.mailbox or settings.mailbox
    result = scan(source=source, query=args.query, limit=args.limit,
                  cfg=settings, write_reports=not args.dry_run)

    print()
    print(format_table(result))
    if result.reports_written:
        print(f"\n{len(result.reports_written)} report(s) written to {settings.report_dir}/")
        for p in result.reports_written[:10]:
            print(f"  {p.name}")
    worst = max((BAND_RANK[a.severity.band] for a in result.analyses), default=0)
    return 2 if worst >= BAND_RANK["MEDIUM"] else 0


def cmd_build_history(args: argparse.Namespace) -> int:
    from .config import ARTIFACTS
    from .history import build
    from .settings import settings
    if not settings.has_imap:
        print("Sender history is built over IMAP. Set IMAP_USER and "
              "IMAP_APP_PASSWORD in .env.")
        return 1
    folders = tuple(args.folders.split(",")) if args.folders else \
        ("INBOX", "[Gmail]/Sent Mail")
    print("Reading FROM/TO/DATE headers only — no message bodies are fetched.")
    h = build(settings, folders=folders, limit_per_folder=args.limit)
    out = ARTIFACTS / "sender_history.json"
    h.save(out)
    corresponded = sum(1 for p in h.domains.values() if p.is_corresponded)
    print(f"\n{h.messages_scanned:,} messages -> {len(h.addresses):,} addresses, "
          f"{len(h.domains):,} domains, {corresponded:,} corresponded with")
    print(f"Saved to {out} (mode 0600, gitignored — it lists your contacts)")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    from .features.extractor import Email
    samples = [
        Email(subject="Action required: unusual sign-in to your Microsoft account",
              sender='"Microsoft Account Team" <security-alert@ms-verify-login.tk>',
              receiver="jane.doe@acme.com", date="Tue, 16 Sep 2025 08:14:02 +0000",
              body='Your mailbox storage quota exceeded and your account will be '
                   'suspended within 24 hours unless you verify your account. '
                   '<a href="http://ms-verify-login.tk/secure/login/account">'
                   'https://login.microsoftonline.com/verify</a>'),
        Email(subject="Re: Q3 supplier payment", sender='"Mark Hale" <m.hale@acrne-corp.com>',
              receiver="finance@acme.com",
              body="On Mon 15 Sep, Finance wrote:\n> the schedule is attached\n\n"
                   "Are you at your desk? I need you to process a wire transfer today. "
                   "Our bank details have changed. Keep this between us until the "
                   "announcement."),
        Email(subject="Weekly engineering sync notes",
              sender='"Priya Raman" <priya@acme.com>', receiver="eng@acme.com",
              body="Hi all, notes from today's sync are in the shared drive. "
                   "We agreed to move the migration to next sprint. Thanks, Priya"),
    ]
    analyzer = ThreatAnalyzer()
    for e in samples:
        a = analyzer.analyze(e)
        print(f"\n{'='*70}")
        print(f"{a.severity.band:14} {a.severity.score:5.1f}  P={a.probability:.3f}  "
              f"{a.vector.name}")
        print(f"  {a.email.subject}")
        print(f"  {a.severity.arithmetic()}")
        for f in a.findings_up[:3]:
            print(f"    {f.contribution:+6.2f} {f.headline}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="sentinel", description="Email threat analysis")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="analyze an .eml file (use - for stdin)")
    a.add_argument("path")
    a.add_argument("--json", action="store_true", help="emit JSON instead of Markdown")
    a.add_argument("--out", help="write to a file instead of stdout")
    a.add_argument("--iocs", help="newline-separated file of known-bad domains")
    a.add_argument("--software-allowlist",
                   help="newline-separated domains that may legitimately link to "
                        "executables (your release host, projects you follow)")
    a.set_defaults(func=cmd_analyze)

    d = sub.add_parser("demo", help="score three built-in sample messages")
    d.set_defaults(func=cmd_demo)

    bh = sub.add_parser("build-history",
                        help="mine the mailbox for sender reputation (headers only)")
    bh.add_argument("--folders", help="comma-separated IMAP folders "
                                      "(default: INBOX,[Gmail]/Sent Mail)")
    bh.add_argument("--limit", type=int, default=20000, help="max messages per folder")
    bh.set_defaults(func=cmd_build_history)

    c = sub.add_parser("config", help="show mailbox configuration (no secrets printed)")
    c.set_defaults(func=cmd_config)

    au = sub.add_parser("auth", help="one-time Gmail OAuth consent (read-only)")
    au.add_argument("--port", type=int, default=0,
                    help="fixed local redirect port (needed only if the OAuth "
                         "client is a 'Web application' rather than 'Desktop app')")
    au.set_defaults(func=cmd_auth)

    sc = sub.add_parser("scan", help="fetch and triage a live mailbox")
    sc.add_argument("--source", choices=["auto", "gmail", "imap"], default="auto")
    sc.add_argument("--query", help="Gmail search syntax, e.g. 'is:unread newer_than:2d'")
    sc.add_argument("--limit", type=int, help="max messages to fetch")
    sc.add_argument("--mailbox", help="label or IMAP folder (default INBOX)")
    sc.add_argument("--dry-run", action="store_true",
                    help="score and print, write no reports to disk")
    sc.set_defaults(func=cmd_scan)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
