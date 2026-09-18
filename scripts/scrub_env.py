"""Move any filled-in secret out of .env.example and into .env.

Run after accidentally editing the template instead of the real file.
"""
from __future__ import annotations

import sys
from pathlib import Path

SECRET = ("GEMINI_API_KEY", "GROQ_API_KEY", "IMAP_APP_PASSWORD", "IMAP_USER",
          "GMAIL_CLIENT_ID", "GMAIL_CLIENT_SECRET")
ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    env, ex = ROOT / ".env", ROOT / ".env.example"
    if not ex.exists():
        print(".env.example not found")
        return 1
    have = {}
    if env.exists():
        for line in env.read_text().splitlines():
            k, _, v = line.partition("=")
            if v.strip():
                have[k.strip()] = v.strip()

    moved, out = [], []
    for line in ex.read_text().splitlines():
        st = line.strip()
        if not st.startswith("#") and "=" in st:
            k, _, v = st.partition("=")
            k, v = k.strip(), v.strip()
            if k in SECRET and v:
                if k not in have:
                    have[k] = v
                    moved.append(k)
                out.append(f"{k}=")
                continue
        out.append(line)
    ex.write_text("\n".join(out) + "\n")

    if moved:
        lines = env.read_text().splitlines() if env.exists() else []
        present = {l.split("=", 1)[0].strip() for l in lines if "=" in l}
        for k in moved:
            if k not in present:
                lines.append(f"{k}={have[k]}")
        env.write_text("\n".join(lines) + "\n")
        env.chmod(0o600)
        print(f"Moved into .env: {', '.join(moved)}")
    else:
        print(".env.example is already clean.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
