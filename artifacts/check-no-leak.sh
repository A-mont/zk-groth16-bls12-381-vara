#!/usr/bin/env bash
# Assert the witness never leaks into any public artifact.
#
# The demo secret is w = 42. As a BLS12-381 field element its canonical
# (little-endian) serialization is 0x2a followed by 31 zero bytes. This greps
# every published artifact for that pattern and fails if it appears.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
# w = 42 -> Fr little-endian, 32 bytes
NEEDLE="2a00000000000000000000000000000000000000000000000000000000000000"

FILES=(public.json proof.json vk_prepared.json deploy_args.json)
leaked=0
for f in "${FILES[@]}"; do
  p="$DIR/$f"
  [ -f "$p" ] || continue
  if grep -qi "$NEEDLE" "$p"; then
    echo "LEAK: witness bytes found in $f"
    leaked=1
  fi
done

# binary proof too
if [ -f "$DIR/proof.bin" ] && xxd -p "$DIR/proof.bin" | tr -d '\n' | grep -qi "$NEEDLE"; then
  echo "LEAK: witness bytes found in proof.bin"
  leaked=1
fi

if [ "$leaked" -eq 0 ]; then
  echo "OK: witness w never appears in any published artifact."
else
  exit 1
fi
