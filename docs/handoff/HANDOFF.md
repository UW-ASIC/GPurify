# Simplification handoff (branch `simplify`)

Delete this directory when the work is done. `audit_*.md` are the per-crate audits
(data in/out, dead code, SIMD candidates) written against `main` @ 41b2a1e; line numbers
are pre-Wave-A. `WAVE_*_RULES.md` are the agent specs. `golden.sh`/`gate.sh` are the accuracy gate.

## Accuracy gate
`golden.sh <bin> <outdir>` runs the CLI over every corpus cell (tests/fixtures/{drc,erc,lvs,pex}):
`all` JSON, LVS against lvs_inv.cdl, PEX SPEF, field-solved SPEF, field-solved + inductance SPEF.
Baseline = binary built from `main` @ 41b2a1e (`cargo build --release --no-default-features`).
Regenerate the baseline from a `main` checkout, then `gate.sh <repo>` must print `GATE PASS`.
Edit the scratchpad paths at the top of both scripts first.

## Done (Wave A, per-crate, byte-identical corpus output, all tests green)
src 50.1k → 28.3k lines, tests 36k → 26.8k. GPU/vulkano deleted (CPU only).
Behaviour fixes: ERC electromigration `blech_limit` indexed per layer (was per row; panicked /
misread on multi-layer rows, e.g. pdks/generic_finfet.json); ingest `Xform::compose` checked
arithmetic (nested magnification overflow used to wrap silently).

## Wave B — cross-crate seams (not started; see WAVE_B_RULES.md for target API)
- geom: delete `expr` (Evaluator, DerivedExpr, LayerRef, DerivedError) + `boolean::offset_into`;
  drop `Design::derived`, `Extracted::derived`, `recognise_into`'s unused `derived`. `ValidatedLayer::get`
  unused `store` param. `rects::Rect` → `Bbox`. Observer traits once seams gone.
- test-only src items → testgen: `push_rect`, `NetTable::from_assignment` + `PartialEq`, `PortTable: PartialEq`,
  `PolygonRef::area`, `StrTable::with_capacity`, `gds::detect`, `LayerTable::name`, `export::gds::write_store`.
- ingest: pipeline onto split API (`read_gds_bytes` → `Library::parse` → `parse_deck` once → `flatten`),
  kills the double deck parse. Unread `Netlist` columns (keep `self.net(..)` calls). `run.rs:198` grid fallback.
  `ingest/tests/intern.rs` belongs in geom. `args.rs:55` stale `read_deck` mention.
- check/drc: `RuleSet::run(&GeometryStore)`; drop `drc::Design`/`Scratch` from API. `record_run` pub(crate).
  One `csr_run` (copies in erc/power.rs, lvs/graph.rs).
- check/erc: single `erc::check` entry (run.rs ~400-512); `SolveConfig` → constants; `facts.rs:179-241`
  duplicates intent supply columns; testgen builds `NetNetworks` field by field.
- check/lvs: one `compare(&Graph,&Graph,&opts)` (drop-bulk+reduce inside); delete `LayoutGraph`/`RefGraph`,
  `TieBreak`, `match_names` (tests/engine sets them); unused `strings` param of `from_reference_into`;
  intern the 8 rule ids properly instead of sentinel ids + `name_lvs_check_rows` + `intern_report_ids`;
  `Discrepancy::DuplicateName` never constructed (check run-row order before dropping its id);
  `check_device_counts`/`check_parametric` only emit Skipped rows (tests/test_all.rs asserts them).
- extract: writers call `capacitance_per_net()` once (SPEF/DSPF currently O(nets×elements));
  `Accuracy.backend`/`.residual` + one-variant `Backend`; `EngineError::Mesh` unreachable;
  unused `DeviceTable` param of `analytical::extract_into`.
- root: `--threads` / `RunOptions::threads` is read by nothing → `--check-determinism` compares two
  identical runs. Remove the flag (or make it real) and fix README claim.

## Known bugs to fix (behaviour changes — own commits)
- PEX merge (`src/engine/run.rs` `merge_field_solved_into`): assumes the analytical pass never emits
  cross-net elements, but `couple_into` does. Field-solving a net but not its coupled neighbour:
  lower-id neighbour → debug panic / release node `u32::MAX` in export; otherwise coupling silently dropped.
  Corpus doesn't hit it (golden selects all nets). Move merge into extract and fix.
- Silent drop: with `--no-strict-layers`, shapes on undeclared layers vanish uncounted (`Layout.dropped` deleted).
- `tests/fixtures/expectations.json` still describes the old blech bug.

## Wave C — fearless_simd 1.0 (not started)
Candidates, bit-exact only (no FMA; keep reduction order unless a tolerance is accepted):
- extract `field/matvec.rs` 1/r panel P2P sum: lanes = target rows, sequential over sources; + rayon rows. Main win.
- geom `linalg::axpy`, bbox min/max folds (`Bbox` = one i64x4), index layer-extent union.
- ingest `emit` vertex transform (now checked arithmetic — needs a range pre-check to vectorise).
- erc CG `axpy` / `p = z + βp`. `dot`/`nrm2`/`spmv` change bits if vectorised.
- drc `poly_dist2` (i64 path exact only for limits < 2^31), density windows (bin first).
- LVS: nothing worth it.

## Wave D — docs (not started)
Per-crate data in/out doc (ARCHITECTURE.md), delete docs/GPU.md, VOCABULARY.md, CORRECTNESS_MAP.md;
shrink NEED_TESTING.md; fix README (GPU section, test counts, `--format gds` removed, `--threads`),
TESTING.md + tests/fixtures/README.md stale paths; `.github/workflows/ci.yml` gpu comment.

## Leftover risk notes from Wave A agents
- ERC: ESD clamp machinery deleted (no deck could populate it); `esd_latchup`/`esd_topological` flag every
  pad net (same as before from any deck). Clamp params still validated, unused.
- ERC: `antenna_row` merge and dense-table → `position()` replacement have no dedicated unit test.
- ERC network builders NOT merged: edge order feeds the solver.
- ingest: OASIS → `UnknownFormat`; `MissingCell` reported at parse end; error offsets now `usize`.
- `cargo fmt --all --check` not yet run over the merged tree.

## From the Philis session (downstream consumer)
- Philis pins GPurify via git default branch; picks up `simplify` only after it lands on main + `cargo update -p gpurify`.
- Philis's sky130 deck gained licon.7/.9/.11/.14, diff/tap.11, npc, polyc/rbody derived layers — consider porting into `pdks/sky130.json`.
