#!/usr/bin/env bash
# usage: gate.sh [repo-dir]  -> builds release bin in that tree, reruns corpus, diffs vs golden_base
S=/tmp/claude-1000/-home-omare-Documents-Projects-Rust-GPurify/35498cb0-197f-47ef-9353-f5a68560d8eb/scratchpad
REPO=${1:-/home/omare/Documents/Projects/Rust/GPurify}
cd $REPO && CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 cargo build --release --no-default-features --bin gpurify 2>&1 | grep -E '^error|warning: unused' | head -20
OUT=$(mktemp -d $S/golden_new.XXXX)
$S/golden.sh $REPO/target/release/gpurify $OUT
# paths in headers differ per repo dir; normalise
grep -rl "$REPO" $OUT | xargs -r sed -i "s|$REPO|/home/omare/Documents/Projects/Rust/GPurify|g"
if diff -r $S/golden_base $OUT > $OUT.diff; then echo "GATE PASS: corpus output byte-identical"; else echo "GATE FAIL: $(grep -c '^diff\|^Only' $OUT.diff) files differ, see $OUT.diff"; head -40 $OUT.diff; fi
