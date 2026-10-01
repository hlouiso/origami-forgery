#!/usr/bin/env bash
# Trust-separated check: forge against a key whose seed the forger never sees.
#
#   export SUBMISSION=/path/to/Origami/Implementations/Reference_Implementation
#   ./scripts/blind_challenge.sh <128|256|384|512>
#
# 1. keygen_pk draws a fresh random seed, writes the secret to a private file,
#    and prints ONLY the public key and a message.
# 2. forge_from_pk receives ONLY that public key and message, and produces a
#    signature -- it never reads the seed or the secret key.
# 3. verify_pk runs the shipped sig_verify plus three negative controls.
#
# (In a single script the seed exists on the same machine; the separation here
# is that the forger binary is handed only the public key and message. A fully
# independent two-party version is described in docs/REPRODUCE.md.)
set -euo pipefail

LVL="${1:?usage: blind_challenge.sh <128|256|384|512>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/build/Origami-$LVL"
[ -x "$OUT/forge_from_pk" ] || "$ROOT/scripts/build.sh" "$LVL"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PRIV="$WORK/secret.private"          # the challenger's secret; the forger does not read it

# 1. generate: stdout carries only PK and MSG
"$OUT/keygen_pk" "$PRIV" 56 > "$WORK/handoff.txt"
PK=$(awk -F= '$1=="PK"{print $2}' "$WORK/handoff.txt")
MSG=$(awk -F= '$1=="MSG"{print $2}' "$WORK/handoff.txt")
echo "published: pk (${#PK} hex), msg (${#MSG} hex); secret kept in a file the forger never opens"

# 2. forge from the public key alone
SIG=$("$OUT/forge_from_pk" "$PK" "$MSG")
echo "forged:    sig (${#SIG} hex) from pk + msg only"

# 3. verify with the shipped verifier, plus a control on a different message
first=${MSG:0:1}; rest=${MSG:1}                 # flip the first hex digit -> a guaranteed-distinct message
if [ "$first" = "0" ]; then MSG2="1$rest"; else MSG2="0$rest"; fi
echo "== verification (unmodified sig_verify) =="
"$OUT/verify_pk" "$PK" "$SIG" "$MSG" "$MSG2"
