#!/usr/bin/env bash
set -euo pipefail

# Resolve the repo root from this script's own location (artifacts/ -> repo root).
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ACCOUNT="${VARA_ACCOUNT:-chupachups}"
NETWORK="${VARA_NETWORK:-testnet}"
WASM="$ROOT/crates/verifier-app/target/wasm32-gear/release/zk_verifier.opt.wasm"
IDL="$ROOT/crates/verifier-app/target/wasm32-gear/release/zk_verifier.idl"
ARGS="$(cat "$ROOT/artifacts/deploy_args.json")"

printf '\n%s\n  STEP 4/5 - VERIFIER - deploy the Sails actor to Vara testnet\n%s\n' \
  "======================================================================" \
  "======================================================================"

echo "wasm bytes: $(wc -c < "$WASM")"
echo "args bytes: ${#ARGS}"

vara-wallet --account "$ACCOUNT" --network "$NETWORK" program upload \
  "$WASM" --idl "$IDL" --args "$ARGS"
