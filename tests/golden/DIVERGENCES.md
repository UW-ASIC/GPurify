# Intentional behaviour divergences, `crates/` -> `crates_clean/`

Goldens freeze bugs by design: they prove the rewrite changed nothing, they
cannot prove the original was right. Every intentional change of behaviour is
recorded here, with the reason. Nothing is ever "fixed" by regenerating a
golden file.

---

## `core::exact` — `general_boolean` deleted (2026-08-01)

**What changed.** `PolygonSet::{union, intersection, subtraction}` no longer
dispatch arbitrary-angle input to `general_boolean`. All three now call
`rectilinear_boolean` unconditionally, so non-rectilinear input returns
`ExactGeometryError::Unsupported` instead of an approximate answer.

**Why.** `general_boolean` failed **open** in three places, which disqualifies
it from a signoff tool:

| site (original) | behaviour |
|---|---|
| `boolean.rs:677-681` | a hole with no containing outer ring was silently dropped — area disappears from a verification result with no error |
| `boolean.rs:848-853` | `Ring::new` failing on a split-produced sliver was silently skipped (`Err(_) => {}`) — boundary disappears |
| `boolean.rs:596-604` | shared boundary edges skipped for all three ops on an unproven "the rest will close correctly" argument |

Plus `point.rs:79 try_snap` *rounded* intersection points to the integer grid,
so the arrangement was approximate while the module header advertised
exactness, and `sort_along_edge` (`boolean.rs:782`) computed a sum of two
products of coordinate differences in `i64` — `2^83` at `Dbu`, an overflow by
20 bits that would silently produce a wrong sort order, a wrong arrangement and
a wrong verdict.

**Reachability.** Zero production callers. `PolygonSet::{union, intersection,
subtraction}` had no call site anywhere in `crates/`; `Polygon::offset` (its
other caller) had none either. Every production boolean names `rectilinear_*`
explicitly — `drc/derived.rs:381`, `drc/rules/overlap.rs:67`, and 54 further
`rectilinear_*` references — and those already fail closed on arbitrary-angle
input.

**Golden impact.** None. No fixture reaches the deleted path.

**Test coverage lost.** The seven `general_boolean_*` tests in
`crates/core/src/exact/mod.rs:349-480`, plus the two
`segment_intersection_rational_*` tests. None corresponds to a reachable
production path.

**If an all-angle boolean is ever genuinely needed** it comes back as
Bentley-Ottmann with exact rationals and no silent drops — not as this.

Also deleted with it, all zero-caller outside `exact/`'s own tests:
`RationalPoint` / `try_snap` / `segment_intersection_rational`,
`Polygon::offset` / `OffsetKernel`, `Polygon::deterministic_fracture`,
`validate_simple_sweep`, `ring_signed_area2` (now private), `classify_edge` /
`EdgeKind`, `orientation` / `Orientation`, `classify_point_in_ring` (now
private), and `ExactGeometryError::{SweepLineDegenerate, RationalOverflow}`.

---

## `core::exact::Ring` — error variant on a fully degenerate ring (2026-08-01)

**What changed.** `Ring::new` merges redundant collinear vertices in one `O(V)`
pass instead of the original's `O(V^2)` remove-and-rescan loop. The original
stopped removing at exactly three vertices; the single pass has no such floor,
so a walk that reduces to fewer than three corners now returns
`DegenerateRing` where the original returned `DegenerateRing`,
`TooFewVertices` or `SelfIntersection` depending on which vertices its floor
happened to leave behind.

**Why.** The floor was an artefact of the removal loop, not a decision. A walk
with fewer than three corners has at most two distinct edge directions in a
closed cycle, so it goes out and comes straight back: zero area either way.

**Impact.** The ring is rejected in both trees; only the error variant and its
message differ. No accepted geometry changes. `Ring::validate` (the new
check-only entry) reports edge indices against the caller's walk rather than
the collinear-merged one, which is the more useful diagnostic and is documented
on the function.

---

## `core::exact::Ring` — new `OutOfRange` variant (2026-08-01)

**What changed.** `ExactGeometryError` gained `OutOfRange(geometry::OutOfRange)`
and `Ring::new`/`Ring::validate` reject any vertex outside `+/-2^40`.

**Why.** New requirement of the `i32 -> Dbu` port. `Ring::new` takes a
caller-built `Vec<Point>` that never passed through `GeometryStore` ingest, so
it is a boundary and must establish the guard itself — every `i128` kernel
below it is proven only under `|c| <= MAX_ABS_DBU`. The check is folded into
the pass that already computes the bounding box, so it is free.

**Impact.** Only on coordinates that were already outside the domain the exact
predicates are proven for. Fail-closed.

---

## `core::layout_hash` — digest value differs from `equivalent_layout_hash` (2026-08-01)

**What changed.** `layout_hash(&GeometryStore) -> u64` replaces
`HierarchyIndex::equivalent_layout_hash` (`crates/core/src/hierarchy_index/index.rs:197`).
The FNV-1a-64 mixing, the little-endian integer encoding and the `u64` string
length prefix are ported byte-for-byte, but the **digest value differs**:

| difference | reason |
|---|---|
| coordinates hashed as `i64`, not `i32` (`candidate.rs:48`) | the `Dbu` port |
| `element_index` / `part_index` / `IndexedShapeKind` dropped from the identity | the store has no such columns; the kind was hashed at `candidate.rs:39` and matched nothing on the read side |
| path is the interned segment text, with `column`/`row` baked into the segment string | the store carries a `PathId` per polygon; the original re-materialised a `Vec<InstancePathEntry>` per candidate (`index.rs:381`) |
| infallible; no `LayoutError::Malformed` on an empty top | an empty store digests as the empty store, which is the answer |

**Reachability.** Digest-vs-digest only. The sole consumers in `crates/` are
`io/read/oasis.rs:2112, 2113, 2121, 2122` — one GDS<->OASIS round-trip
equivalence test that compares two digests produced by the same build. No
frozen constant anywhere in `crates/`, `tools/` or `tests/golden/`; no golden
file contains the value.

**Golden impact.** None. The property under test (two readers of the same
layout agree) is preserved exactly; only the number differs.

**Still to verify.** The differential against the original cannot run until
`core::io` is ported and can produce an annotated store from a GDS/OASIS file.
Current coverage is 11 hand-built stores exercising each identity component
independently.

---

## Deleted with it: the other 2506 lines of `hierarchy_index/` (2026-08-01)

`index.rs`, `grid.rs`, `tile.rs`, `tile_candidates.rs`, `options.rs`,
`candidate.rs`, `instance_path.rs`, `layer_identity.rs`, `shape_kind.rs`,
`mod.rs`. `query` / `query_bounded` / `query_parallel` are `flatten_gds_library`
with extra allocation — proven by the module's own assertions at
`hierarchy_index/mod.rs:173, 180`. `TileGrid`, `VerificationTile`,
`halo_from_deck`, `owner_of_marker` and `content_hash` have zero callers and DRC
already has its own tiling at `drc/src/results.rs:392`. `stable_identity`,
`top_cells()`, `path_to_string`, `path_depth`, `IndexedShapeKind` and
`HierarchyIndexOptions` have zero or one caller each.

---

## `core::sort_scan` — deleted, not ported (2026-08-01)

**What changed.** `crates/core/src/sort_scan.rs` has no counterpart in
`crates_clean/`.

**Why.** Zero external callers for all three functions, and
`grid_bin_candidates` (`sort_scan.rs:93-112`) fails **open**: it bins a shape by
its centroid and searches only the +/-1 cell ring, so any bbox wider than one
cell can miss an overlapping neighbour and report a spacing violation as clean.
Its own test (`sort_scan.rs:264`) caps the extent at 30 against a cell of ~33,
so the bug never fires under test. `prefix_sum_exclusive` (`:29`) uses
`saturating_add`, which corrupts a gatherer's write spans instead of failing.
All three are `i32`.

**Replacement.** `crates_clean/core/src/geometry/sweep.rs:73
candidate_pairs_into` — a sorted sweep with no binning heuristic.

**Golden impact.** None; nothing called it.

---

## `core::io::read` — the GDS and OASIS readers (2026-08-01)

**Gate.** `crates_clean/core/tests/reader_diff.rs` replays all 161 fixtures
through the new reader and compares against `tools/reader_diff_ref`, which dumps
what the frozen `crates/` reader extracts. **296 cells / 959 polygons agree
exactly** — layer id, vertex walk, polygon order and hierarchy path string.
Everything below is a case the corpus does not contain, or a default that was
deliberately inverted.

1. **Non-multiple-of-90 GDS `ANGLE` -> `Unsupported`.** Was: accepted, then
   decided per coordinate by `exact_i32`, whose tolerance `min(1e-10|v|, 1e-6)`
   let a general-angle placement load whenever its vertices happened to land
   within 1e-6 DBU of an integer. `Xform` is exact integer; `exact_i32` and the
   `f64` `Affine` are deleted. Corpus contains exactly one angle value: 90.0.

2. **Diagonal `PATH` segment -> `Unsupported`** (was `NonIntegralTransform`).
   The stroke offset is `h/sqrt(2)`, irrational for every integer `h > 0`, so
   `stroke_diagonal_segment` (65 lines) rejected 100% of its inputs already.
   Both reject; only the kind differs. Corpus: 0 diagonal segments in 8.

3. **Missing `UNITS` -> `Malformed`.** Was: a fabricated `{1e-3, 1e-9}`, so a
   headerless stream silently became a 1 nm layout. All 161 fixtures carry
   `UNITS (1e-3, 1e-9)`.

4. **The HEADER/BGNLIB/LIBNAME/UNITS/ENDLIB envelope is mandatory.**
   `GdsReadMode::Compatibility` is deleted: 161/161 fixtures carry the full
   envelope, so it had no users.

5. **An unhandled record is an error at *parse*, with a byte offset.** Was: at
   flatten, with none. Verdict unchanged. Consequence of deleting the GDS
   writer (~250 lines, zero production callers), which was the only thing that
   ever needed the retained raw bytes.

6. **Unmapped `(layer, datatype)` -> `UnmappedLayer` error by default.** Was:
   counted, `Ok` — so one typo in a layer table left the store empty and every
   rule reporting clean. `UnmappedPolicy::Count` is the named opt-in. Corpus
   has 0 unmapped pairs across 161 files.

7. **`GeometryPolicy::Strict` is the default.** Was: the only public entry
   point hardcoded `PreserveInvalidForPolygonValidity`. The legacy DRC corpus
   genuinely needs the permissive policy — 14 fixture tops carry deliberately
   invalid rings — and now names it explicitly.

8. **An empty layout is `EmptyLayout`, not `Ok`.** `read_gds(&[], lt)` returned
   `Ok` with zero cells. Same for a library with no structures, and for one
   where no structure contributed a shape.

9. **Instance nesting is bounded (`max_depth`, default 4096).** Both recursions
   in the original were unbounded; `expansion_limit` bounded *visits*, never
   *depth*, so a deep `SREF` chain aborted the process — no verdict at all.

10. **Errors are typed at the public boundary.** The `map_err(|e| e.to_string())`
    at `gds.rs:75-76` and `io/read/mod.rs:62` is gone; `LayoutErrorKind`
    survives to the caller.

11. **A deck may now express a non-integer nanometre limit.** Consequence of
    the physical-units deck: a `0.5 nm` limit on a 1 nm grid fails to load with
    `GridError::OffGrid`. New capability, intended fail-closed behaviour, no
    current deck uses one.

**OASIS.** No `.oas` fixture exists, so no golden constrains any of it. Fixed
fail-open defects, each of which a real file can trigger: repetition counts
formed as `unsigned()? as i64 + 2` wrapped negative and made the whole
repetition **vanish with an `Ok`** (`oasis.rs:1521-1522,1541,1555,1569,1585`);
`PROPERTY_REPEAT` was a no-op while the element reader drained the pending list,
so the second element silently got no properties (`:601-604`); a CBLOCK's
declared size went straight to `Vec::with_capacity` (`:1619` — a process abort)
and nested CBLOCKs recursed to a stack overflow (`:620`); `has_cell &&
has_ref_num` read an N-string where the spec has a reference number and
misparsed the rest of the cell (`:1278-1283,1355-1360`); `mag == 0` collapsed a
placed cell to a point and deleted all its geometry (`:1383`); a library of N
empty cells passed (`:543-548`). Also **added**: repetition type 0 (reuse
previous), which was `Unsupported` and rejects mainstream files (`:1604`), and
`START` unit real types 4 (positive ratio), which the original falsely rejected
(`:410-418`).

---

## `pex` analytical — D1: parasitic emission order pinned ascending by `LayerId` (2026-08-01)

**What changed.** `extract_into` iterates `PexTable.layer` (a `Vec<LayerId>`,
ascending by construction, `core/src/io/deck_json.rs:1000`). The original
iterated `HashMap<LayerId, PexLayerParams>` (`crates/core/src/io/pdk.rs:618`,
std `RandomState`, per-process seed) and `rule::run_rules`
(`crates/pex/src/rule.rs:31`) preserved the rules-slice order, so the hash draw
*became* the golden array order.

**Why.** 8 runs of the same binary on `PEX_NEG_R` produced 5 distinct orders;
only 3 matched the committed golden. Two independent failures: the block order
(`for layer in HashMap-order { for factory in FACTORIES }`), and the row
*content* — `extract_interlayer_cap` (`analytical/mod.rs:656-662`) read
`pex_layers[i]`/`[j]` in draw order, so `layer_a`/`layer_b` swapped in 5 of 8
runs (`met2`/`met1` instead of the golden's `met1`/`met2`).

**Golden impact.** None. The committed files already encode ascending
`LayerId` (met1 = 6, via1 = 7, met2 = 8 — `LayerTable` sorts by
`(gds_layer, gds_datatype)`); they were dumped in one lucky process. Re-running
the original's `golden_dump` today would rewrite roughly 8 of the 27 files.
That is the bug, not the fix. Regression test:
`pex/tests/golden.rs::emission_order_is_reproducible_within_a_process`.

## `pex` analytical — D2: per-net f64 accumulation order pinned (2026-08-01)

**What changed.** `aggregate_by_net_into` accumulates in `PexRows.rows` index
order, which D1 pinned. `aggregate_by_net` (`analytical/mod.rs:412-432`) walked
the same process-random `Vec`.

**Why.** `cap_af` is a many-term `f64 +=` per net (AreaCap plus every
CouplingCap and InterlayerCap touching the polygon), so its last ulp drifted run
to run. The original has no defined answer to reproduce; this pins one.

**Golden impact.** None — no golden covers the per-net path. Live-caller impact:
none. The only consumer, `erc/rules/p2p_resistance.rs:236`, passes an identity
net map and reads `r_ohm` only (at most two terms, both from one layer's rule
block), so it was already deterministic.

## `pex` analytical — D3: `length_nm` / `width_nm` / `spacing_nm` widened `i32` -> `i64` (2026-08-01)

**What changed.** The three integer report fields, and the clamp ceiling in
`report_dimension_nm`, move from `i32::MAX` (2.1 m) to `i64::MAX`.

**Why.** Forced by `Dbu = i64`: an equivalent length or a spacing gap can exceed
`i32::MAX` nm. `spacing_nm` additionally now goes through
`report_dimension_nm(grid.dbu_to_nm(gap))` rather than a raw `as i32` of the DBU
value, so it means nanometres on every grid rather than only on a 1 nm one.

**Golden impact.** None. JSON is identical for every value below 2.1 m, and the
corpus grid is 1 nm where `dbu_to_nm` is the identity (asserted bit-exactly by
`pex/src/metrics.rs::tests::nanometre_grid_scale_is_bit_exactly_one`).

## `pex` analytical — D4: `InterlayerCap` pair order pinned lexicographic (2026-08-01)

**What changed.** `candidate_pairs_cross_into` output is `sort_unstable`d before
emission, so pairs come out in `(a_index, b_index)` order.

**Why.** The original used `crates/`'s `candidate_pairs`
(`geometry/mod.rs:82`), whose `sort_unstable_by_key(|it| it.0)` tie-break is
pdqsort-internal and toolchain-defined; `crates_clean`'s `sweep.rs` can
additionally pick the other sweep axis. The emitted *set* is invariant, the
order is not.

**Golden impact.** None. Every fixture emits at most one `InterlayerCap` row, so
no golden observes the order — which is exactly why it needed pinning before a
deck with more crossings arrives.

## `pex` analytical — D5: the quasi-static fail-open fallback is deleted (2026-08-01)

**What changed.** `run_pex` returns `PexError::MethodUnavailable` when the deck
selects `PexMethod::FieldSolver`. `run_pex_by_net` returns
`PexError::UnsupportedGeometry` (carrying the row table) instead of a partial
numeric map.

**Why.** `crates/pex/src/lib.rs:92-98` logged a bridge failure through
`warn_fallback_once` (`bridge.rs:654-661`, a **process-wide `Once`**) and
silently downgraded to the analytical model — so a batch of N cells warned once
and degraded in silence for cells 2..N. `CLAUDE.md`: fail closed.

**Golden impact.** None. `tests/fixtures/params.json` has no `pex_method` key,
so every golden is `Analytical`.

## `pex` analytical — D6: the f32 `Backend::Gpu` coupling path is removed (2026-08-01)

**What changed.** `rules/coupling_cap.rs:99-156` and its GLSL shader are gone;
the exact-integer path is the only path.

**Why.** The comment at `:96` claimed the f32 path was "numerically identical to
the exact-integer fallback". It is not — f32 loses exactness above 2^24 nm =
16.7 mm, inside a reticle — and with `Dbu = i64` it is unusable outright. It was
also unreachable from `run_pex`, which always passed `Backend::Cpu`
(`analytical/mod.rs:326`). See `docs/GPU.md`.

**Golden impact.** None; the branch required `Backend::Gpu` and 2^18 pairs.

## `pex` quasi-static — D7: GMRES `converged` is consumed, not discarded (2026-08-01)

**What changed.** Every Krylov call site now reads `GmresResult::converged` and
fails closed. New typed variants: `cap::SolveError::NotConverged { conductor,
residual, tol, iterations }` and `henry::SolveError::NotConverged { frequency,
node, residual, tol, iterations }`.

**Why.** `crates/pex/src/quasistatic/cap/fmm_solver.rs:168` was
`gmres(...).x` — it discarded `converged`, `residual` and `iterations` outright;
same at `cap/solver.rs:123` and `henry/solver.rs:463`. GMRES that exhausts
`max_restarts: 50` returns `converged: false` **plus the best iterate**
(`krylov.rs:190`), and the bridge's only guard was
`!cap_af.is_finite() || cap_af < 0.0` (`bridge.rs:434`). A non-converged σ
therefore yielded a finite, positive, plausible capacitance with no error — on
the **large-problem branch** (`bridge.rs:399`, panels >= 500), i.e. every
realistic layout. `docs/GPU.md` requirement 4 ("f64 residual, reported never
assumed") is a requirement the CPU path already failed.

**Golden impact.** None — no quasi-static golden exists yet. Behaviour impact:
inputs that previously produced a silently-wrong number now produce an error.

## `pex` quasi-static — D8: the `LowRankApprox::apply_add` reassociation is NOT taken (2026-08-01)

**What changed.** Nothing, deliberately. `linalg.rs:392,397` stay as scalar
`.map().sum()` folds even though `simd::dot` sits in the same crate, is tested,
and would give an expected 3–5x on **56.75%** of a quasi-static run (26.8 GIr
callgrind profile, `PEX_NEG_AC`; the fold disassembles to 11 `mulsd` + 11
`addsd`, 0 packed, 0 FMA — latency-bound on one 4-cycle `addsd` chain).

**Why not.** Swapping it is a *reassociation* of an f64 reduction, and there is
no quasi-static golden to bound the resulting drift against. The measurement
exists so the entry can be completed when there is: `linalg::tests::
simd_swap_relative_error_bound` reports **max relative error 0.0e0 over n³ = 64
and 125 all-positive `1/r` M2L rows** (both lengths land on identical bit
patterns at this condition number; the analytic bound `63·u·Σ|aᵢbᵢ|/|Σaᵢbᵢ|`
gives ~7e-15 × κ, κ ≈ 1 here). Order to land it: (1) `tests/golden/pex_qs/`,
(2) the swap, (3) re-measure on real M2L operators and record the number here.

## `pex` quasi-static — D9: at ω = 0 the inductance kernel and the branch LU are skipped (2026-08-01)

**What changed.** `henry::solve_full` computes `dc_only = freqs.iter().all(|f|
2πf == 0.0)`. When true it never assembles `L`, never materialises `Zb`, and
solves the branch system as `x[b] = rhs[b] / Complex64::new(r[b], 0.0)`.

**Why.** The PEX bridge pins `fmin = fmax = 0`, so `Zb = R + j·0·L = diag(R)`
exactly — yet `assemble_inductance` (`henry/solver.rs:246`) still ran the full
`O(nb²)` Grover/Hoer mutual kernel and multiplied it by zero, then pushed the
*diagonal* `Zb` through a dense `O(nb³)` LU (`:437`). Bridge segments are
mutually disconnected, so that was `O(npoly³)` for `npoly` independent
single-resistor circuits — the largest algorithmic defect in the module.

**Bit-identity.** On a diagonal matrix LU with partial pivoting never moves a
row (every off-diagonal candidate is 0.0, so `m > max` is false), the rank-1
update subtracts exactly `0.0 * pivot_row[j]` from every trailing entry, and
both substitution passes reduce to the single division above. Verified by
`tests/henry_validation.rs::dc_only_sweep_still_gives_exact_resistance`, which
asserts `to_bits()` equality against the closed-form DC resistance.

**Not fixed.** The second LU, on the reduced nodal admittance `Yn`, is still
`O(nred³)` on a matrix that is diagonal on the bridge path. Named with a
`ponytail:` comment at the call site; the fix is a sparse `Yn` (at most two
entries per branch by construction), not a special case.

## `pex` quasi-static — D10: a NaN pivot is singular, not a plausible answer (2026-08-01)

**What changed.** `LuDecomposition::factor`'s singularity test is `!(max > 0.0)`
instead of `max == 0.0` (`crates/pex/src/quasistatic/linalg.rs:191`). Same shape
applied to the DC resistance check in `henry::solve_full`.

**Why.** A NaN entry fails every `>` comparison, so the pivot search left `max`
NaN, `NaN == 0.0` was false, and the factorization proceeded to produce a matrix
of NaNs that only the bridge's late `is_finite` guard could catch — after it had
poisoned the whole solve. Covered by
`linalg::tests::nan_pivot_is_singular_not_a_plausible_answer`.

**Not changed:** the threshold is still exact zero, not an epsilon. A 1e-300
pivot still factors. Raising it would reject systems the original accepted, and
that needs an oracle.

## `pex` quasi-static — D11: an unmapped polygon is refused, not joined to net 4294967295 (2026-08-01)

**What changed.** `bridge::extract_quasistatic` returns
`BridgeError::UnmappedPolygon { polygon, net_count }` when `net_of_poly` has no
in-range entry for a polygon.

**Why.** `crates/pex/src/bridge.rs:92` was
`net_of_poly.get(polygon).copied().unwrap_or(u32::MAX)`, which silently merged
every orphan polygon into one imaginary net `4294967295` and then reported R and
C for it. Covered by
`tests/bridge.rs::polygon_with_no_net_is_refused_not_joined_to_net_max`.

## `pex` quasi-static — D12: `mesh_analysis::solve_ports` returns a `Result` (2026-08-01)

**What changed.** `.expect("singular mesh system")`
(`crates/pex/src/quasistatic/henry/mesh_analysis.rs:173`) is
`MeshError::Singular`, surfaced through `SolveError::Mesh`.

**Why.** A singular `M Z Mᵀ` is an input condition, not a bug. `CONVENTIONS` §3:
library errors are typed, never a panic.

## `pex` quasi-static — D13: the M2L truncation / GMRES tolerance mismatch is recorded, not fixed (2026-08-01)

**What changed.** Nothing. `bbfmm.rs:150`'s
`eps = (1e-3 · 0.1^n).max(1e-14)` at the bridge's `order = 4` gives an M2L
truncation error of **1e-7**, while `bridge.rs:403` drives GMRES at tol
**1e-8** — the solver is pushed 10x tighter than the operator it is solving with
is accurate, so its residual is meaningless at that level.

**Why not fixed.** Both candidate fixes (raise the Chebyshev order, relax the
tolerance) move every extracted capacitance, and there is no quasi-static golden
to measure the move against. Silently changing a signoff number without an
oracle is precisely what `CLAUDE.md` forbids. Marked with a `ponytail:` comment
at `LaplaceFmm::precompute_m2l`.

## `pex` — D14: `run_pex_by_net` dispatches on `deck.pex.method` (2026-08-01)

**What changed.** `run_pex_by_net` is a DISPATCHER: `PexMethod::FieldSolver`
routes to `bridge::extract_quasistatic`, `PexMethod::Analytical` to the
analytical row table. A bridge refusal surfaces as the new
`PexError::FieldSolver(BridgeError)`. `run_pex` is unchanged and still returns
`PexError::MethodUnavailable` under a field-solver deck, because it returns the
analytical row table, which the field solver does not emit.

**Why.** Landing the two halves in parallel left the seam unwired: the field
solver was reachable only by calling `bridge::extract_quasistatic` by hand, and
every caller that went through the public entry point got
`MethodUnavailable` — the same fail-closed refusal a *missing* solver gives, so
"not built" and "built but not connected" were indistinguishable.

**Not a golden change.** `tests/fixtures/params.json` carries no `pex_method`
key, so all 27 goldens are `PexMethod::Analytical` and take the untouched arm.
Verified: 27/27 still bit-identical across 694 numeric fields after the wiring
(`tools/pex_golden_diff`).

**Still not the original's behaviour, deliberately.** The original's
`run_pex_by_net_with_accuracy` caught every bridge error and returned the
*analytical* numbers under a field-solver deck, so a refused extrusion read as
a completed 3-D solve. That is D5; this entry only records where the choice now
lives. Covered by
`tests/bridge.rs::run_pex_by_net_routes_a_field_solver_deck_to_the_bridge` and
`::a_bridge_refusal_is_not_downgraded_to_the_analytical_answer`.

## `pex` analytical — D15: `tests/golden/pex/` is not reproducible from `crates/` — second measurement (2026-08-01)

**Not a new divergence. Independent evidence for D1 and D4**, recorded here
because it was measured on the whole 27-fixture corpus rather than on
`PEX_NEG_R` alone, and because it is the reason
`tools/golden_dump` now needs a `pex_qs` subcommand: dumping the quasi-static
oracle must not rewrite the analytical goldens as a side effect.

**The defect, in `crates/`.** `Deck.pex` is
`HashMap<LayerId, PexLayerParams>` (`crates/core/src/io/pdk.rs:618`) built on
std's `RandomState`, which seeds itself per process. Two runs of the *same
binary* on the *same* fixture therefore walk the PEX layers in two different
orders.

`extract_interlayer_cap` (`crates/pex/src/analytical/mod.rs:657`) is the site
that reads that order directly:

```rust
let pex_layers: Vec<(LayerId, &PexLayerParams)> =
    deck.pex.iter().map(|(&lid, p)| (lid, p)).collect();
```

and then pairs `(i, j)` with `j > i`, emitting `layer_a = pex_layers[i]`,
`layer_b = pex_layers[j]`.

**Two observable effects.**

1. Output row order varies — the `out` push order changes, and the report's
   canonical sort does not fully separate rows that differ only in which layer
   landed in `layer_a`.
2. `Parasitic::InterlayerCap`'s `layer_a` / `layer_b` swap, together with the
   `[pa.0, pb.0]` polygon pair, whenever the hash order of two layers flips.

**Evidence.** 6 runs of the same `tools/golden_dump` binary over the 27 PEX
fixtures: **4 of 6 differed**. Across those, **8 files had genuinely different
rows** and **2 differed only in row order**. Consistent with D1's separate
measurement (8 runs of `PEX_NEG_R`, 5 distinct orders, 3 matching the committed
golden) and with D1's estimate that a re-run would rewrite "roughly 8 of the 27
files".

**Severity: reproducibility, not a wrong number.** `af` is unchanged. `coeff` is
symmetric in the pair — an average when both layers set
`interlayer_cap_af_um2`, a sum when one is zero — and `overlap_area_um2` is a
bbox intersection, also symmetric. So the *magnitude* of every interlayer
capacitance is the same whichever way round the pair comes out; what moves is
which layer name is printed first and which row prints first. It is a defect
because a signoff report that is not byte-reproducible cannot be diffed between
two runs, and because a golden generated from it is a coin flip — not because a
capacitance is wrong.

**`crates_clean/` fixes it for free.** `PexTable` (`crates_clean/core/src/io/deck.rs:466-473`)
is SoA with `layer: Vec<LayerId>` documented and built ascending —
`rows.sort_by_key(|&(id, _)| id)` at
`crates_clean/core/src/io/deck_json.rs:1000` — plus a `layer_to_row: Vec<u16>`
side index for the O(1) lookup the `HashMap` was there for. There is no hash
seed anywhere on the path, so pair order is `(lower LayerId, higher LayerId)`
every run on every machine. No code was written for this; it is a consequence of
`CONVENTIONS` §1 "tables > trees > graphs, indices not pointers".

**Not applicable to the quasi-static path.** `bridge::extract_quasistatic`
groups conductors in a `BTreeMap<(u32, LayerId), _>` in both trees, and
`ProcessStack::from_deck` (`crates/pex/src/analytical/process_stack.rs:44`)
already sorts `deck.pex.keys()` by `LayerId` before building the stack. The
`tests/golden/pex_qs/` oracle was dumped 13 times — 9 back-to-back plus
`RAYON_NUM_THREADS` ∈ {1, 2, 4, 16} — and was byte-identical every time.
