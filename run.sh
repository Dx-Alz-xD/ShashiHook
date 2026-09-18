#!/usr/bin/env bash
# Launch ShashiHook and open it.
#
# --reload watches the sentinel/ and app/ trees and restarts on any change.
# Without it, edits and retrained models are invisible to a running server —
# the engine is loaded once and cached, so the UI keeps serving the old
# verdicts and the fix looks like it did not work.
cd "$(dirname "$0")"
PORT="${PORT:-8420}"
RELOAD="${RELOAD:-1}"

echo "ShashiHook — engine ArnosAI"
echo "  http://127.0.0.1:$PORT"
[ "$RELOAD" = "1" ] && echo "  auto-reload on code and model changes (RELOAD=0 to disable)"

( sleep 2; command -v open >/dev/null && open "http://127.0.0.1:$PORT" ) &

ARGS=(-m uvicorn app.server:app --host 127.0.0.1 --port "$PORT" --log-level warning)
if [ "$RELOAD" = "1" ]; then
  ARGS+=(--reload --reload-dir sentinel --reload-dir app --reload-include '*.joblib')
fi
exec .venv/bin/python "${ARGS[@]}"
