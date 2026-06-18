#!/usr/bin/env bash
# IronGuard launcher — deploy the always-on workspace auditor.
#
#   ./run.sh <WORKSPACE_DIR>
#
# It:
#   1. Installs audit.py / serve.py / dashboard.html into $IRONGUARD_HOME (~/ironguard).
#   2. Runs one audit now (populates the SQLite DB).
#   3. Starts the dashboard web server at http://127.0.0.1:$IRONGUARD_PORT (default 8787).
#   4. Installs a cron entry so audits keep running every $IRONGUARD_INTERVAL_MIN minutes.
#
# Env: IRONGUARD_HOME, IRONGUARD_PORT (8787), IRONGUARD_INTERVAL_MIN (5).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${IRONGUARD_HOME:-$HOME/ironguard}"
PORT="${IRONGUARD_PORT:-8787}"
INTERVAL_MIN="${IRONGUARD_INTERVAL_MIN:-5}"
WORKSPACE="$(cd "${1:-$HOME/code}" && pwd)"

mkdir -p "$OUT"
cp "$HERE/audit.py" "$HERE/ai_analyze.py" "$HERE/serve.py" "$HERE/dashboard.html" "$OUT/"

echo "==> Running initial audit of $WORKSPACE"
python3 "$OUT/audit.py" "$WORKSPACE" "$OUT"

echo "==> Starting dashboard server on port $PORT"
if lsof -ti "tcp:$PORT" >/dev/null 2>&1; then
  echo "    (already running on :$PORT)"
else
  IRONGUARD_PORT="$PORT" nohup python3 "$OUT/serve.py" >"$OUT/serve.log" 2>&1 &
  echo "    started (logs: $OUT/serve.log)"
fi

echo "==> Installing cron entry (every $INTERVAL_MIN min)"
CRON_LINE="*/$INTERVAL_MIN * * * * cd '$OUT' && IRONGUARD_AI=0 /usr/bin/env python3 audit.py '$WORKSPACE' '$OUT' >> '$OUT/cron.log' 2>&1 # ironguard"
if command -v crontab >/dev/null 2>&1; then
  ( crontab -l 2>/dev/null | grep -v '# ironguard'; echo "$CRON_LINE" ) | crontab - \
    && echo "    cron installed" \
    || echo "    cron install failed — you can run the loop instead: while true; do python3 '$OUT/audit.py' '$WORKSPACE' '$OUT'; sleep $((INTERVAL_MIN*60)); done"
else
  echo "    no crontab available — run the loop instead:"
  echo "      while true; do python3 '$OUT/audit.py' '$WORKSPACE' '$OUT'; sleep $((INTERVAL_MIN*60)); done"
fi

echo
echo "IronGuard is live ▶  http://127.0.0.1:$PORT   (auditing $WORKSPACE every $INTERVAL_MIN min)"
