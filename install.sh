#!/usr/bin/env bash
# IronGuard — one-command installer.
#
#   bash install.sh [WORKSPACE_DIR]        # default workspace: $HOME/code
#
# Runs on a VANILLA IronClaw — no binary patches, no special profile, no manual config.
# It installs the always-on workspace auditor (exposed secrets + OSV dependency/malware
# audit + optional LLM code scan) with a live dashboard and a cron, and registers the
# `ironguard` IronClaw skill into any IronClaw home it finds so the agent can run it too.
#
# The auditor is plain Python (urllib) — it talks to OSV.dev and (optionally) NEAR AI
# directly, so it does NOT depend on any IronClaw network/WASM patch. It even works with
# no IronClaw installed at all.
#
# Env: IRONGUARD_HOME (default ~/ironguard), IRONGUARD_PORT (8787),
#      IRONGUARD_INTERVAL_MIN (5), IRONGUARD_AI (0/1 — AI code scan on the initial run).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/skill"
OUT="${IRONGUARD_HOME:-$HOME/ironguard}"
PORT="${IRONGUARD_PORT:-8787}"
INTERVAL_MIN="${IRONGUARD_INTERVAL_MIN:-5}"
WS_IN="${1:-$HOME/code}"

command -v python3 >/dev/null 2>&1 || { echo "error: python3 is required." >&2; exit 1; }
WORKSPACE="$(cd "$WS_IN" 2>/dev/null && pwd || true)"
if [ -z "$WORKSPACE" ]; then
  echo "error: workspace '$WS_IN' not found. Pass a real directory:" >&2
  echo "       bash install.sh /path/to/your/code" >&2
  exit 1
fi

echo "==> Installing IronGuard auditor to $OUT"
mkdir -p "$OUT"
cp "$SRC/audit.py" "$SRC/ai_analyze.py" "$SRC/serve.py" "$SRC/dashboard.html" "$SRC/watch.sh" "$OUT/"
chmod +x "$OUT/watch.sh" 2>/dev/null || true

# --- Register the IronClaw skill into every IronClaw home we can find (best-effort) ---
echo "==> Registering the IronClaw 'ironguard' skill (best-effort)"
skill_installed=0
declare -a BASES=()
[ -n "${IRONCLAW_REBORN_HOME:-}" ] && BASES+=("$IRONCLAW_REBORN_HOME")
for d in "$HOME"/.ironclaw-reborn* "$HOME/.ironclaw"; do [ -d "$d" ] && BASES+=("$d"); done
for base in "${BASES[@]:-}"; do
  [ -d "$base" ] || continue
  while IFS= read -r skills_dir; do
    mkdir -p "$skills_dir/ironguard"
    # bake the real absolute auditor path into the skill (the agent shell's $HOME is unreliable)
    sed "s#__IRONGUARD_HOME__#$OUT#g" "$SRC/SKILL.md" > "$skills_dir/ironguard/SKILL.md"
    echo "    + $skills_dir/ironguard/SKILL.md"
    skill_installed=1
  done < <(find "$base" -type d -name skills 2>/dev/null)
done
[ "$skill_installed" -eq 0 ] && echo "    (no IronClaw home found — the auditor still runs standalone)"

# --- Initial audit (populates SQLite + dashboard) ---
echo "==> Initial audit of $WORKSPACE"
IRONGUARD_AI="${IRONGUARD_AI:-0}" python3 "$OUT/audit.py" "$WORKSPACE" "$OUT" || true

# --- Dashboard server ---
echo "==> Dashboard server on :$PORT"
if lsof -ti "tcp:$PORT" >/dev/null 2>&1; then
  echo "    (already running)"
else
  IRONGUARD_PORT="$PORT" nohup python3 "$OUT/serve.py" >"$OUT/serve.log" 2>&1 &
  echo "    started (logs: $OUT/serve.log)"
fi

# --- Cron (always-on) ---
echo "==> Installing cron (every $INTERVAL_MIN min)"
CRON_AI="${IRONGUARD_AI:-0}"   # set IRONGUARD_AI=1 to include the LLM code scan in the recurring cron
CRON="*/$INTERVAL_MIN * * * * cd '$OUT' && IRONGUARD_AI=$CRON_AI python3 audit.py '$WORKSPACE' '$OUT' >> '$OUT/cron.log' 2>&1 # ironguard"
if command -v crontab >/dev/null 2>&1; then
  ( crontab -l 2>/dev/null | grep -v '# ironguard'; echo "$CRON" ) | crontab - \
    && echo "    installed" \
    || echo "    cron install failed — loop fallback: while true; do python3 '$OUT/audit.py' '$WORKSPACE' '$OUT'; sleep $((INTERVAL_MIN*60)); done"
else
  echo "    no crontab available — loop fallback:"
  echo "      while true; do python3 '$OUT/audit.py' '$WORKSPACE' '$OUT'; sleep $((INTERVAL_MIN*60)); done"
fi

echo
echo "✅ IronGuard is live ▶  http://127.0.0.1:$PORT   (watching $WORKSPACE every $INTERVAL_MIN min)"
if [ "$skill_installed" -eq 1 ]; then
  echo "   In the IronClaw chat you can also ask: \"audit <path> with ironguard\""
  echo "   (the skill runs: python3 $OUT/audit.py <path>)"
fi
