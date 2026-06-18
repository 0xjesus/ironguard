#!/usr/bin/env bash
# Build the IronGuard WASM tool and install it into the local Reborn home.
#
# Reproducible installer: builds the WASM component, lays out the extension
# payload (manifest + wasm + schemas + prompts) under the Reborn home's
# local-dev system extensions, and registers + activates it.
#
# Requirements: rustup target wasm32-wasip2, cargo-component, and the
# ironclaw-reborn debug binary already built at target/debug/ironclaw-reborn.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
HOME_DIR="${IRONCLAW_REBORN_HOME:-$HOME/.ironclaw-reborn-demo}"
EXT="$HOME_DIR/local-dev/system/extensions/ironguard"
BIN="$REPO/target/debug/ironclaw-reborn"

echo "==> Building WASM component"
cargo component build --release --target wasm32-wasip2 --manifest-path "$HERE/Cargo.toml"

echo "==> Laying out extension payload at $EXT"
# `extension remove` clears any prior install state AND deletes the on-disk dir,
# so refresh state first, then recreate the payload from the repo.
unset IRONCLAW_REBORN_PROFILE
export IRONCLAW_REBORN_HOME="$HOME_DIR"
"$BIN" extension remove ironguard >/dev/null 2>&1 || true
rm -rf "$EXT"
mkdir -p "$EXT/wasm"
cp "$HERE/target/wasm32-wasip2/release/ironguard_tool.wasm" "$EXT/wasm/ironguard_tool.wasm"
cp -R "$HERE/extension/." "$EXT/"

echo "==> Registering with Reborn (default profile)"
"$BIN" extension install ironguard
"$BIN" extension activate ironguard

echo "==> Done. Restart 'serve' (run-reborn-local.sh) to load the tool into the agent."
