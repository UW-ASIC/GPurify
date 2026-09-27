#!/usr/bin/env bash
# usage: golden.sh <gpurify-binary> <outdir>
# Runs every corpus cell through every output the CLI has and writes one file per run.
set -u
BIN=$1; OUT=$2
R=$(cd "$(dirname "$0")/../../tests/fixtures" && pwd)
D=$R/params.deck
mkdir -p "$OUT"
for d in drc erc lvs pex; do for g in "$R"/$d/*.gds; do
  id=$(basename "$g" .gds)
  $BIN all "$g" --deck "$D" --grid 1000 --no-strict-layers --format json > "$OUT/$id.all.json" 2>"$OUT/$id.all.err"; echo "exit $?" >> "$OUT/$id.all.err"
  if [ $d = pex ]; then
    $BIN pex "$g" --deck "$D" --grid 1000 --no-strict-layers --format spef > "$OUT/$id.spef" 2>&1
    nets=$(grep "^\*D_NET" "$OUT/$id.spef" | awk '{print $2}' | head -8)
    qs=""; for n in $nets; do qs="$qs --quasistatic $n"; done
    [ -n "$qs" ] && $BIN pex "$g" --deck "$D" --grid 1000 --no-strict-layers --format spef $qs > "$OUT/$id.qs.spef" 2>&1
    [ -n "$qs" ] && $BIN pex "$g" --deck "$D" --grid 1000 --no-strict-layers --format spef $qs --quasistatic-inductance > "$OUT/$id.qsl.spef" 2>&1
  fi
  if [ $d = lvs ]; then
    $BIN lvs "$g" --reference "$R/lvs_inv.cdl" --deck "$D" --grid 1000 --no-strict-layers --format json > "$OUT/$id.lvs.json" 2>&1
  fi
done; done
