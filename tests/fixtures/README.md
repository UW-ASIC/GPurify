# Verification conformance fixtures

This directory contains 160 standalone GDS cases described by `manifest.json`:

- `drc/`: 94 cases covering every registered DRC family and polygon validity.
- `lvs/`: 16 independent layout/reference-netlist comparisons.
- `erc/`: 23 cases covering every layout-derived ERC heuristic.
- `pex/`: 27 analytical resistance/capacitance and negative-golden cases.

The source library under `_source/` exists only to make fixture generation
deterministic. Test code always opens the per-case GDS named after the manifest
ID.

## Run every conformance fixture

From the repository root, this single command runs all 160 GDS cases through
GPUVerify:

```sh
cargo test -p gdsverify \
  --test fixture_corpus \
  --test verify_drc \
  --test verify_lvs \
  --test verify_erc \
  --test verify_pex
```

Cargo reports 11 top-level tests because each conformance test iterates a
manifest section. The cases actually executed are:

| Harness | GDS cases |
| --- | ---: |
| DRC | 94 |
| LVS | 16 |
| ERC | 23 |
| Analytical PEX | 27 |
| **Total** | **160** |

The DRC determinism test runs all 94 DRC cases a second time. The corpus test
also reads all 160 files and checks deterministic bytes, IDs, units, hierarchy,
and the single expected top cell.

To see test and geometry warnings while the suite runs, append `-- --nocapture`.

## Run every conformance fixture plus live KLayout parity

Set `KLAYOUT_BIN` to a KLayout 0.30.8 executable and run the same complete
suite:

```sh
KLAYOUT_BIN=/path/to/klayout \
  cargo test -p gdsverify \
  --test fixture_corpus \
  --test verify_drc \
  --test verify_lvs \
  --test verify_erc \
  --test verify_pex \
  -- --nocapture
```

This still runs all 160 cases through GPUVerify. In addition, the live oracle
runs 39 DRC cases across the nine rule families that map directly to native
KLayout `Region` checks. ERC, analytical PEX, custom DRC rules, and LVS are not
silently described as KLayout-qualified when no equivalent live oracle exists.

To run just the live KLayout portion:

```sh
KLAYOUT_BIN=/path/to/klayout \
  cargo test -p gdsverify --test verify_drc \
  klayout_native_drc_oracle_matches_directly_mappable_rules -- --exact --nocapture
```

## Run all workspace tests

The conformance tests are also registered with the `gdsverify` package, so the
complete workspace suite includes them:

```sh
cargo test --workspace
```

Without `KLAYOUT_BIN`, the live external-oracle test returns successfully after
printing that it was skipped; all 160 hermetic GPUVerify cases still run.

## Run one harness

```sh
cargo test -p gdsverify --test fixture_corpus
cargo test -p gdsverify --test verify_drc
cargo test -p gdsverify --test verify_lvs
cargo test -p gdsverify --test verify_erc
cargo test -p gdsverify --test verify_pex
```

## Regenerate fixtures

Regenerate every per-case GDS after intentionally changing the source library
or manifest:

```sh
cargo test -p gdsverify --test fixture_corpus regenerate_fixtures -- --ignored --exact
```

The oracle is qualified against KLayout 0.30.8, the version pinned when this
corpus was created. See `PLAN.md` for the coverage boundary and fixture matrix.
