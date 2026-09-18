#!/usr/bin/env bash
# Launch ShashiHook and open it.
cd "$(dirname "$0")"
PORT="${PORT:-8420}"
echo "ShashiHook — engine ArnosAI"
echo "  http://127.0.0.1:$PORT"
( sleep 1.5; command -v open >/dev/null && open "http://127.0.0.1:$PORT" ) &
exec .venv/bin/python -m uvicorn app.server:app --host 127.0.0.1 --port "$PORT" --log-level warning
