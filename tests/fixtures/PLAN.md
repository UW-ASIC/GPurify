# Verification fixture plan

## Goal and coverage boundary

This corpus is the executable contract for layout verification. Every case is a
standalone, complete GDSII library with exactly one top cell. No behavioral test
selects a cell from a shared "everything" layout: a failure must be reproducible
by opening one small GDS in GPUVerify or KLayout.

"Exhaustive" means every rule family registered by the current DRC, LVS, ERC,
and analytical PEX public APIs has positive, negative, and meaningful boundary
coverage. It does not mean every possible polygon. The corpus includes exact
thresholds and the geometry where semantics change: merged versus separate
shapes, concavity, hierarchy, paths, diagonal edges, negative coordinates,
malformed boundaries, disconnected nets, and device symmetry.

The analytical PEX API is covered here. The quasi-static layout-to-3D bridge is
currently staged and falls back to analytical extraction; it needs a separate
field-solver characterization corpus when that bridge becomes a real extraction
path. ERC checks requiring foundry-qualified stimulus are covered by their typed
unit tests; the GDS corpus covers layout-derived ERC checks.

## Corpus invariants

1. File names are stable case IDs under `drc/`, `lvs/`, `erc/`, and `pex/`.
2. A fixture contains the case cell and the transitive closure of SREF/AREF
   dependencies, with the case cell as the only top cell.
3. GDS units are 1 nm/DBU and every file has a complete record envelope.
   Deliberate zero-area, self-contact, and keyhole boundaries use compatibility
   geometry parsing so DRC can inspect the source evidence.
4. `manifest.json` is the only expectation index: it records the check, expected
   cardinality or value, tolerance, and source cell.
5. IDs and paths are unique. Every referenced GDS exists; orphan GDS files fail
   the corpus-integrity test.
6. Every registered DRC family and layout-derived ERC check has a manifest case.
   Inventory tests fail when the registries drift.
7. Expected failures are deliberate negative cases, never ignored tests.
8. PEX comparisons use explicit tolerances and reject NaN/infinity.
9. Checked-in goldens keep normal Cargo tests hermetic. Setting `KLAYOUT_BIN`
   enables live KLayout 0.30.8 parity for directly mappable native DRC checks.

## DRC matrix: 94 cases

| Rule family | Coverage |
| --- | --- |
| `min_width` | pass/fail, L-neck, zero width, bent PATH, diagonal pass/fail |
| `min_spacing` | pass/fail, merged-notch versus separate-space, coincident, strict, hierarchy, nested hierarchy, PATH |
| `min_spacing_diff` | cross-layer pass/fail |
| `min_enclosure` | pass/fail, unhosted inner, concave host, well enclosure |
| `min_extension` | vertical and horizontal pass/fail |
| `min_area` | pass, fail, exact threshold |
| `max_width` | pass/fail |
| `notch` | pass/fail, merged/separate, coincident, strict merge |
| `min_edge_length` | pass/fail |
| `off_grid` | pass/fail and adversarial off-grid point |
| `angle` | Manhattan, forbidden angle, self-contact, acute angle |
| `min_density` / `max_density` | pass/fail, multiple windows, gradient boundary |
| `overlap` | pass/fail |
| `corner_to_corner` | pass/fail diagonal separation |
| `antenna` | below/above ratio |
| `antenna_car` | below/above cumulative ratio and diode waiver |
| `eol_spacing` | pass/fail, wide-line and side-neighbor exclusions |
| `wide_dependent_spacing` | narrow pass, wide fail, wide sufficiently spaced |
| `prl_spacing` | below/above PRL threshold |
| `asymmetric_enclosure` | one-side pass/fail |
| `min_enclosed_area` | legal/undersized keyhole hole |
| `cheesing` | slotted pass, unslotted fail, below-area exemption |
| `redundant_via` | cluster pass, isolated fail |
| `via_array_spacing` | array pass/fail around count threshold |
| `max_distance_to_tap` | all corners covered / far corner |
| `multi_patterning` | colorable / uncolorable conflict graph |
| polygon validity | self-intersection, zero-area, valid keyhole |

## LVS matrix: 16 layout/reference pairs

- Clean inverter and graph-isomorphic ordering.
- Source/drain permutation.
- Device-count and topology mismatches.
- Intentional short and open.
- Matching/mismatching fingers; series and parallel reduction.
- Within/outside W/L tolerance.
- HVT match/mismatch and LVT match.

Each fixture retains GDS TEXT labels and recognition markers. The reference
netlist lives beside the case in the manifest.

## ERC matrix: 23 cases

The corpus covers all 13 layout-derived heuristic checks: floating gate,
floating well, missing tie, supply short, unconnected pin, soft connection,
multiple drivers, tie high/low, electrical antenna, missing ESD path, HV-domain
crossing, EM width/current-density proxy, and point-to-point resistance.

Checks with no meaningful clean geometry in the current heuristic have a single
negative GDS; clean/no-input behavior stays covered by unit tests. Typed power,
CMP, reliability, and ESD signoff analyses are not assigned fake GDS-only
goldens because their verdict requires explicit external stimulus/evidence.

## PEX matrix: 27 cases

- M1/M2 resistance: nominal, length/width scaling, differential, negative.
- Via resistance: one/two vias and negative.
- Area/fringe capacitance: M1 plate/fill, M2 plate, negative.
- Lateral coupling: nominal, spacing scaling, orientation, negative.
- M2 coupling and inter-layer crossover: positive/negative.
- Per-net aggregation: positive and deliberately wrong map goldens.

Negative PEX goldens prove the harness detects wrong numbers; they are expected
mismatches, not extractor failures.

## Harness order

1. Deterministically split fixtures and verify byte-for-byte currency.
2. Validate envelope, units, single-top structure, IDs, paths, and inventory.
3. Run DRC, LVS, ERC, and analytical PEX conformance.
4. With `KLAYOUT_BIN`, run native KLayout parity on directly mappable DRC rules.
5. Run the complete workspace test suite.
