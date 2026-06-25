#!/usr/bin/env bash
set -euo pipefail

# Resolve the repo root from this script's own location (artifacts/ -> repo root).
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ACCOUNT="${VARA_ACCOUNT:-chupachups}"
NETWORK="${VARA_NETWORK:-testnet}"
IDL="$ROOT/crates/verifier-app/target/wasm32-gear/release/zk_verifier.idl"
# Live testnet deployment; override with PROGRAM_ID after your own deploy.
PID="${PROGRAM_ID:-0x8d84679b79b6eae0f76f18cd8e1045b7c3482725c47f27b73ecd8f5f32d502eb}"

printf '\n%s\n  STEP 5/5 - CLIENT - drive (h, proof) to the actor; read the verdict\n%s\n' \
  "======================================================================" \
  "======================================================================"

echo "=== query VkFingerprint (confirms init succeeded) ==="
vara-wallet --network "$NETWORK" call "$PID" Verifier/VkFingerprint --idl "$IDL"

echo "=== build Verify args ==="
H=$(jq -r .h_hex "$ROOT/artifacts/public.json")
A=$(jq -r .a "$ROOT/artifacts/proof.json")
B=$(jq -r .b "$ROOT/artifacts/proof.json")
C=$(jq -r .c "$ROOT/artifacts/proof.json")
ARGS=$(jq -cn --arg h "0x$H" --arg a "0x$A" --arg b "0x$B" --arg c "0x$C" \
  '[$h, {a:$a, b:$b, c:$c}, "agent-verify-1"]')

echo "=== call Verifier/Verify (real on-chain verification) ==="
vara-wallet --account "$ACCOUNT" --network "$NETWORK" call "$PID" Verifier/Verify --args "$ARGS" --idl "$IDL"
