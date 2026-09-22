#!/usr/bin/env bash
# usage: golden.sh <bin> <outdir>
set -u
BIN=$1; OUT=$2; R=/home/omare/Documents/Projects/Rust/GPurify/tests/fixtures
mkdir -p $OUT
for d in drc erc lvs pex; do for g in $R/$d/*.gds; do
  id=$(basename $g .gds)
  $BIN all $g --deck $R/params.json --grid 1000 --no-strict-layers --threads 1 --format json > $OUT/$id.all.json 2>$OUT/$id.all.err; echo "exit $?" >> $OUT/$id.all.err
  if [ $d = pex ]; then
    $BIN pex $g --deck $R/params.json --grid 1000 --no-strict-layers --threads 1 --format spef > $OUT/$id.spef 2>&1
    nets=$(grep "^\*D_NET" $OUT/$id.spef | awk "{print \$2}" | head -8)
    qs=""; for n in $nets; do qs="$qs --quasistatic $n"; done
    [ -n "$qs" ] && $BIN pex $g --deck $R/params.json --grid 1000 --no-strict-layers --threads 1 --format spef $qs > $OUT/$id.qs.spef 2>&1
    [ -n "$qs" ] && $BIN pex $g --deck $R/params.json --grid 1000 --no-strict-layers --threads 1 --format spef $qs --quasistatic-inductance > $OUT/$id.qsl.spef 2>&1
  fi
  if [ $d = lvs ]; then
    $BIN lvs $g --reference $R/lvs_inv.cdl --deck $R/params.json --grid 1000 --no-strict-layers --threads 1 --format json > $OUT/$id.lvs.json 2>&1
  fi
done; done
