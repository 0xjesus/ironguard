#!/usr/bin/env bash
# IronGuard watch — set up (or update) the always-on cron audit of a workspace.
#
#   bash watch.sh <WORKSPACE> [ai]
#
# Installs/updates the 5-min cron that audits <WORKSPACE>, (re)starts the dashboard,
# and prints the local dashboard URL. Pass `ai` (or IRONGUARD_AI=1) to make the
# recurring cron scan also run the LLM code-vulnerability analysis (uses NEAR AI credits);
# default is the fast/free deterministic pass (secrets + OSV dependency/malware).
#
# This script lives next to audit.py/serve.py (the runtime dir), so it is path-independent.
set -euo pipefail

OUT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"     # the IronGuard runtime dir (has audit.py, serve.py)
PORT="${IRONGUARD_PORT:-8787}"
MIN="${IRONGUARD_INTERVAL_MIN:-5}"

# stop: remove the recurring cron and stop the dashboard server (scan history is kept in SQLite).
if [ "${1:-}" = "stop" ]; then
  if command -v crontab >/dev/null 2>&1; then
    ( crontab -l 2>/dev/null | grep -v '# ironguard' ) | crontab - 2>/dev/null || true
  fi
  lsof -ti "tcp:$PORT" 2>/dev/null | xargs -r kill 2>/dev/null || true
  echo "🛑 IronGuard stopped: the 5-min cron was removed and the dashboard server on :$PORT was stopped."
  echo "   Scan history stays in the SQLite DB. Restart anytime: bash $OUT/watch.sh <workspace> [ai]"
  exit 0
fi

if [ $# -lt 1 ]; then echo "usage: bash watch.sh <WORKSPACE> [ai]   |   bash watch.sh stop" >&2; exit 1; fi
WS="$(cd "$1" 2>/dev/null && pwd || true)"
if [ -z "$WS" ]; then echo "error: workspace '$1' not found" >&2; exit 1; fi

AI=0
[ "${2:-}" = "ai" ] && AI=1
[ "${IRONGUARD_AI:-}" = "1" ] && AI=1

echo "==> Initial audit of $WS (AI=$AI)"
IRONGUARD_AI="$AI" python3 "$OUT/audit.py" "$WS" "$OUT"

echo "==> Dashboard on :$PORT"
if lsof -ti "tcp:$PORT" >/dev/null 2>&1; then
  echo "    (already running)"
else
  IRONGUARD_PORT="$PORT" nohup python3 "$OUT/serve.py" >"$OUT/serve.log" 2>&1 &
  echo "    started"
fi

echo "==> Cron every $MIN min (AI=$AI)"
CRON="*/$MIN * * * * cd '$OUT' && IRONGUARD_AI=$AI python3 audit.py '$WS' '$OUT' >> '$OUT/cron.log' 2>&1 # ironguard"
if command -v crontab >/dev/null 2>&1; then
  ( crontab -l 2>/dev/null | grep -v '# ironguard'; echo "$CRON" ) | crontab - && echo "    installed"
else
  echo "    no crontab — loop fallback: while true; do IRONGUARD_AI=$AI python3 '$OUT/audit.py' '$WS' '$OUT'; sleep $((MIN*60)); done"
fi

echo
echo "✅ IronGuard is watching $WS every $MIN min (AI layer: $([ "$AI" = 1 ] && echo ON || echo off))."
echo "   Live dashboard ▶ http://127.0.0.1:$PORT"
