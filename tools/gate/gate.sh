#!/usr/bin/env bash
# usage: S=<scratch dir holding golden_base/> gate.sh [repo-dir]
# Builds the release binary in repo-dir, reruns the corpus, and diffs it against $S/golden_base.
# Make a baseline once with: golden.sh <binary built from the reference commit> $S/golden_base
set -u
S=${S:?set S to a scratch dir holding golden_base}
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "${1:-$HERE/../..}" && pwd)
MAIN=$(cd "$HERE/../.." && pwd)
(cd "$REPO" && CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 \
  cargo build --release --bin gpurify 2>&1 | grep -E '^error' | head -20)
OUT=$(mktemp -d "$S/golden_new.XXXX")
bash "$REPO/tools/gate/golden.sh" "$REPO/target/release/gpurify" "$OUT"
# Report headers carry absolute paths; a worktree prints its own.
[ "$REPO" != "$MAIN" ] && grep -rl "$REPO" "$OUT" | xargs -r sed -i "s|$REPO|$MAIN|g"
if diff -r "$S/golden_base" "$OUT" > "$OUT.diff"; then
  echo "GATE PASS: corpus output byte-identical"
else
  echo "GATE FAIL: $(grep -c '^diff\|^Only' "$OUT.diff") files differ, see $OUT.diff"; head -40 "$OUT.diff"; exit 1
fi
