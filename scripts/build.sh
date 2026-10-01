#!/usr/bin/env bash
# Build the forgery tools against an official Origami submission tree.
#
#   export SUBMISSION=/path/to/Origami/Implementations/Reference_Implementation
#   ./scripts/build.sh <128|256|384|512>
#
# The Origami reference sources are NOT part of this repository; they come from
# the official submission package (see README). We only compile our own tools
# (src/*.c) and link them against the submission's object files.
set -euo pipefail

LVL="${1:?usage: build.sh <128|256|384|512>}"
: "${SUBMISSION:?set SUBMISSION to the unpacked .../Implementations/Reference_Implementation directory}"

DIR="$SUBMISSION/Origami-$LVL"
[ -d "$DIR" ] || { echo "error: $DIR not found (is SUBMISSION correct and the level built?)" >&2; exit 1; }

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/build/Origami-$LVL"
mkdir -p "$OUT"

# Compile the submission's units (their code, built locally, never committed here).
OBJ=""
for u in origami_ref symmetric_iccs auxfunc aes drng SIG_AlgorithmInstance; do
  gcc -std=c11 -O2 -I"$DIR" -DORIGAMI_OPT=REF -c "$DIR/$u.c" -o "$OUT/$u.o"
  OBJ="$OBJ $OUT/$u.o"
done

# Link our tools.
for tool in forge_from_pk verify_pk keygen_pk forge_demo; do
  gcc -std=c11 -O2 -I"$DIR" -DORIGAMI_OPT=REF "$ROOT/src/$tool.c" $OBJ -o "$OUT/$tool"
done

echo "built -> $OUT"
ls -1 "$OUT" | sed 's/^/  /'
