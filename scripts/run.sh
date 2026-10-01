#!/usr/bin/env bash
# Build (if needed) and run the batch forgery demonstration for one level.
#
#   export SUBMISSION=/path/to/Origami/Implementations/Reference_Implementation
#   ./scripts/run.sh <128|256|384|512> [keys] [msgs_per_key]
#
# forge_demo generates fresh keypairs, forges a signature for each message from
# the PUBLIC KEY ALONE, and checks it against the shipped sig_verify. Per forgery
# three negative controls must reject (flip a signature byte, flip a salt byte,
# verify against a different message). It also cross-checks the official KAT key.
set -euo pipefail

LVL="${1:?usage: run.sh <128|256|384|512> [keys] [msgs]}"
KEYS="${2:-100}"
MSGS="${3:-3}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/build/Origami-$LVL/forge_demo"
[ -x "$BIN" ] || "$ROOT/scripts/build.sh" "$LVL"

echo "== Origami-$LVL: $KEYS keys x $MSGS messages, forged from the public key alone =="
"$BIN" "$KEYS" "$MSGS"
