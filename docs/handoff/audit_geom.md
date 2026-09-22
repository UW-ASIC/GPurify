# Audit: crates/geom (`gpurify-geom`)

Read-only audit. How usage was checked: a Python word-boundary scan over `crates/{check,extract,ingest}/src/**` and `src/**`, with `#[cfg(test)]` items removed ("prod"). It was compared against `crates/*/tests`, `tests/`, `crates/testgen/src` and the in-src test modules ("test"). `gpurify-testgen` is a `[dev-dependencies]` entry in every crate, so it counts as test code. Common method names (`area`, `get`, `width`) were confirmed with targeted receiver patterns. Scripts: `scratchpad/usage.py`, `scratchpad/pat.py`.

Size: src 6,571 lines, of which 5,730 are non-test and 841 are in-src `#[cfg(test)]`. The integration tests in `tests/` are 5,574 lines. The non-test code carries **830 lines of `debug_assert!`** (282 macro sites), **~820 doc-comment lines** and **~470 inline-comment lines**.

---

## 1. DATA IN / DATA OUT

**In (from `ingest`):**
- Raw ring columns `&[Dbu] xs, &[Dbu] ys` plus `LayerId`, passed to `GeometryStoreBuilder::push`.
- Raw `&[i64]` keyhole rings, passed to `boolean::canonical_rings_into`.
- Deck numbers: `i64` dbu/µm to `Grid::new`, `Qty<Length,P>` to `Grid::to_dbu`, names (`&str`) to `StrTable::intern`.
- Edge lists `&[(u32,u32)]` to `connectivity::components_into`, and CSR/f64 vectors to `linalg`.

**Out:**
- `GeometryStore`: SoA `verts_x/verts_y: Vec<Dbu>`, `poly_layer`, `poly_vert_start/len`, `poly_bbox: Vec<Bbox>`, and CSR `layer_start`. `finish` also returns the permutation `Vec<u32>`.
- `ValidatedLayer` (rings grouped outer+holes), read through `PolygonRef` and `RingRef`.
- Candidate pairs `Vec<(PolyId,PolyId)>`, `Vec<Rect>` plus CSR `poly_start`, `Vec<ComponentLabel>`, and exact integer measures (`DbuArea`, `Dbu`, `bool`).

### Real API: pub items used by non-test code outside geom

| Module | Used in prod (callers) |
|---|---|
| dbu | `Dbu` (`new`, `new_unchecked`, `raw`, `abs`, `mul_wide`, `+ - neg`), `DbuArea` (`new`, `raw`, `+ -`), `MAX_ABS_DBU`, `Grid` (`new`, `dbu_per_um`, `to_dbu`, `to_length`), `GridError` (ingest/deck.rs) |
| qty/arith | `Qty` (`new`, `raw`, `base`, `to`, `is_finite`, ops, Display, serde), `Length Area Voltage Current Resistance Capacitance Inductance CurrentDensity Temperature`, `celsius` (src/engine/run.rs), `prefix::{FEMTO,PICO,NANO,MICRO,MILLI,BASE}` |
| intern | `StrId`, `StrTable` (`default`, `intern`, `get`, `resolve`, `len`) |
| ids | `LayerId`, `PolyId` (`.0`, `idx`) |
| bbox | `Bbox` (fields, `EMPTY`, `point`, `include`, `union`, `overlaps`, `contains`, `within`, `intersection`, `width`, `height`, `area`, `of_points`, `is_empty`) |
| store | `GeometryStore` (`poly_count`, `layer_count`, `polys_on_layer`, `poly_verts`, `poly_bbox`, `poly_layer`, `layer_bboxes`, `poly_contains_point`, `append_layer`), `GeometryStoreBuilder` (`with_capacity`, `push`, `finish`) |
| view | `validate_layer_into`, `ValidatedLayer` (`default`, `len`, `is_empty`, `get`, `bboxes`), `PolygonRef` (`outer`, `holes`, `bbox`, `provenance`), `RingRef` (`coords`, `area2`), `ValidityError` (check/drc/rules/overlay.rs) |
| ops | `Point`, `Seg`, `Winding`, `segments_intersect`, `point_in_ring`, `area2`, `winding_of`, `point_seg_dist2`, `seg_seg_dist2`, `isqrt` |
| index | `SpatialIndex` (`default`, `build_into`, `is_empty`), `candidate_pairs_into`, `cross_layer_pairs_into` |
| boolean | `union_into`, `intersection_into`, `subtraction_into`, `canonical_rings_into`, `BooleanError` |
| rects | `Rect`, `decompose_into`, `covered_area`, `clipped_area` |
| connectivity | `components_into`, `ComponentLabel` |
| linalg | `dot`, `nrm2`, `axpy`, `spmv` (check/erc/power.rs, extract/field via re-export) |
| observe | `Observer`, `NoObserve`: only as the base of *other crates'* test seams (check/lvs/refine.rs, extract/field/matvec.rs) |
| expr | `Evaluator` (type, `evaluate`, `get`), `LayerRef`, `DerivedError`: **named but never populated**, see §3 |

---

## 2. Module map

| File | Lines (non-test / in-src test) | Purpose |
|---|---|---|
| lib.rs | 58 | Re-exports, `prefix` consts, `narrow()` |
| dbu.rs | 258 | `Dbu`/`DbuArea` i64/i128 coords, `Grid` µm↔dbu exact conversion |
| qty.rs | 218 | `Qty<D,P>` f64 physical quantity, dimensions, Display/serde |
| arith.rs | 54 | Cross-dimension `Mul`/`Div` impls (Ohm's law etc.) |
| intern.rs | 140 / 31 | `StrTable`, a string interner with a sorted + pending index |
| ids.rs | 35 | `PolyId`, `VertId`, `RingId`, `LayerId` newtypes |
| observe.rs | 20 | `Observer` trait with const `ENABLED`, `NoObserve` |
| bbox.rs | 257 | `Bbox` with inclusive predicates, area, fold constructors |
| store.rs | 389 | `GeometryStore` SoA + builder (counting sort by layer), point-in-poly |
| view.rs | 488 | `validate_layer_into`: ring classification, hole binding, `ValidatedLayer` |
| ops.rs | 530 | Exact integer predicates: cross, seg-intersect, pip, shoelace, dist² |
| index.rs | 666 / 236 | Two-level uniform grid `SpatialIndex`, candidate pairs + observer seam |
| boolean.rs | 1167 / 225 | Rectilinear slab-sweep booleans, offset, ring tracing, keyhole split |
| rects.rs | 305 | Slab decomposition into `Rect`, covered/clipped area |
| connectivity.rs | 152 / 133 | Union-find components + observer seam |
| linalg.rs | 69 / 48 | f64 `dot`, `nrm2`, `axpy`, `spmv` |
| expr.rs | 497 / 168 | `DerivedExpr` tree, `Evaluator` (Kahn plan, cached eval) |
| prefilter.rs | 415 | Bbox prefilter for boolean operands, with provenance recovery |

Test files: core/{bbox_laws 382, boolean_laws 425, connectivity_components 200, index_pairs 354, ops_predicates 596, rects_decomposition 355, store_layout 362, view_validation 350}, derived/{expr_laws 735, plan 272, prefilter 259}, units/{arith 213, dbu 201, grid 360, qty 382, serde 138}.

---

## 3. DEAD CODE (not reachable from any production path)

### 3a. Whole modules

| Item | Where | Evidence | Deletable |
|---|---|---|---|
| **`prefilter` module** (`candidates_into`, `candidates_observed`, `ObservePrefilter`, `OperandIndex`, `provenance_into`, `match_layer`, `embedding_is_unique`, `check_recovered`) | prefilter.rs:1-415 | 0 prod refs in any crate. Used only by tests/derived/prefilter.rs | 415 src, 259 test, and `mod prefilter` in lib.rs:57 |
| **`expr` module in practice**: `Evaluator::plan`, `DerivedExpr`, `eval`, `operand`, `resolve`, `combine`, `scratch_slots`, `cycle_member`, `csr_offsets`, `referenced_names`, `index_of` | expr.rs:1-497 | `Evaluator::plan` has **0 prod callers**. The pipeline only does `out.derived.evaluate(&store)` on a `Default` Evaluator (src/engine/pipeline.rs:66,258), so `evaluate` loops over zero rows. `derived.get(name)` (check/erc/rules/supply.rs:711, topology.rs:205) therefore always returns `None`. `DerivedExpr` has 0 prod refs. `LayerRef::Named(..)` is **never constructed** in prod, only matched (check/erc/mod.rs:99, antenna.rs:624, supply.rs:711, topology.rs:204). `check/topology/device.rs:175` takes `derived: &Evaluator` and never reads it (`#[allow(unused_variables)]`). Derived layers are actually materialised by ingest calling `boolean::*_into` directly (ingest/src/layout.rs:131-139) | 497 src, 168 in-src test, 735 (expr_laws) and 272 (plan) test. Cross-crate follow-up: delete `Design.derived` (check/src/lib.rs:30), `Pipeline.derived` and `DerivedError` wiring (src/engine/pipeline.rs:66,258,325), the `derived` param in device.rs:175 and supply.rs:702, and the `LayerRef::Named` arms. `LayerRef` then collapses to `LayerId` |

### 3b. Items only used by tests, or not at all

| Item | file:line | Prod refs | Test refs | Lines |
|---|---|---|---|---|
| `boolean::offset_into` plus its only helpers `grown_edges_into`, `difference_over`, `clamp_dbu` | boolean.rs:52-142, 144-151, 578-624, 263-269 | 0 (only `expr.rs` Offset, itself dead) | boolean.rs in-src tests 1199-1289, boolean_laws.rs (2) | ~155 src, ~90 in-src test |
| `Grid::to_dbu_into` | dbu.rs:231-257 | 0 | units/grid.rs (11 refs) | 27 |
| `connectivity::component_count` | connectivity.rs:616-637 | 0 | connectivity_components.rs (9) | 22 |
| `ObserveUnionFind` trait, `components_observed` indirection, the `O::ENABLED` arms in `find` | connectivity.rs:512-526, 529-548, 550-591 | 0 (test seam) | in-src tests 639-773 | ~30 src, 133 test |
| `ObservePairs`, `report_prune`, `candidate_pairs_observed`, `cross_layer_pairs_observed`, `coarse_base`, `bucket_base`, the `O::ENABLED` branches, `Grid::bucket_count` | index.rs:352-367, 383-409, 439-448, 495-513, 529-546, 598-603, 631-662, 323-326 | 0 (test seam) | in-src tests 664-902 | ~85 src. Of the 236 test lines, keep the two O(n²) completeness tests (~100) rewritten against `candidate_pairs_into`/`cross_layer_pairs_into` |
| `rects::owner_of` | rects.rs:808-835 | 0 | rects_decomposition.rs (4) | 28 |
| `ops::orientation`, `ops::Orientation` | ops.rs:21-28, 83-103 | 0 (the "orientation" hits in extract/ingest are comments) | ops_predicates.rs (7+13) | 29 |
| `ops::self_intersects` as **pub** | ops.rs:236 | 0 external (used by view.rs:472) | ops_predicates, view_validation | 0 (make it private) |
| `ids::RingId`, `ids::VertId`, `view::is_outer` | ids.rs:104-109, view.rs:484-488 (and the no-op assert at view.rs:132-135) | 0 | view_validation.rs (RingId 5, is_outer 3) | ~15 |
| `RingRef::winding()` accessor | view.rs:194-196 | 0 | view_validation (7) | 3 |
| `PolygonRef::area` | view.rs:160-176 | 0 (the ingest/layout.rs:2052,2108 hits are inside `#[cfg(test)]` starting at 1612) | many | 17 (or move it to testgen) |
| `ValidatedLayer.layer` field | view.rs:32-34, 412 | written, never read (only feeds the derived `PartialEq`) | – | ~4 |
| `ValidatedLayer.ring_winding` column | view.rs:49, 115, 184, 439 | redundant: ring 0 is always CCW and the rest always CW by construction (view.rs:381,385) | – | ~8 |
| `Bbox::of_polys_into` as pub | bbox.rs:224-256 | 0 external. One caller (store.rs:614) | bbox_laws.rs (3) | ~20 once inlined into `finish` |
| `GeometryStoreBuilder::push_rect` | store.rs:529-542 | 0 | geom store_layout/prefilter, tests/engine/pipeline.rs (4), extract/tests/field/bridge.rs (1) | 14 (move to testgen) |
| `StrTable::with_capacity` | intern.rs:313-320 | 0 | ingest/tests/intern.rs | 8 |
| `StrTable::is_empty` | intern.rs:402-404 | 0 | – | 3 (clippy `len_without_is_empty` wants it, so keep only if that lint is on) |
| `prefix::{ATTO,KILO,MEGA,GIGA}` | lib.rs:19,26-28 | 0 direct, but read by `qty::prefix_letter` for Display | tests | keep (Display depends on them) |
| `Dimension` trait (as a *named* API) | qty.rs:265 | 0 (the extract "Dimension" hit is a comment) | tests | keep, bound on `Qty` |
| `observe` module | observe.rs | used only by the check/extract test seams | – | 20. Delete when the workspace drops all `Observe*` seams |

### 3c. Unreachable branches and checks

- **boolean.rs:292-349 `push_ring`.** The skew check (`ring_dx/ring_dy` masks, 325-343) can never fire. Every input is a `ValidatedLayer` ring, and `classify_ring` (view.rs:475) already refuses non-rectilinear rings; boolean outputs are rectilinear by construction. The `n == 0` branch (296-299) is also unreachable because validated rings have ≥ 3 vertices. The staging copy into `sweep.ring_x/ring_y` is only there to feed that check. The function reduces to two `extend`s plus a CSR push, **~50 lines saved**. After that, `BooleanError::NotRectilinear` is only produced by `canonical_rings_into`. The `Sweep` fields `ring_x`, `ring_y`, `ring_dx`, `ring_dy` go away.
- **boolean.rs:1127.** `sort_dedup(&mut axis)` right after `axis_into`, which already sorts and dedups.
- **view.rs:70-81 `ValidatedLayer::get(store, idx)`.** The `store` param exists only for a debug_assert. Dropping it touches about 10 prod call sites.
- **index.rs:395-398, 641-648.** `layer.expect(...)` on `Option<LayerId>` is there only to catch a `default()` index that was never built. Keep it or not as the owner prefers; it is a real fail-closed guard.

---

## 4. BLOAT

| # | What | Where | Deletable lines |
|---|---|---|---|
| B1 | **`debug_assert!` noise.** 830 lines in non-test src. Examples: re-checking a sort just performed (index.rs:317-320, ops.rs:272-275, 283-290), "columns parallel" after the zip that made them (rects.rs:328-343), O(n) re-scans inside O(n) loops (rects.rs:714-725 is O(n²) per slab in debug; prefilter.rs:136-142), postconditions that restate the preceding line (store.rs:404-419, 622-633). Keep the `assert!`s that guard silent wrong answers: store.rs:363-374 and 495, bbox.rs:209, boolean.rs:833 and 928 and 947, and the index `expect`s | ~600 after the dead modules go (prefilter 114, expr 59 already counted there) |
| B2 | **Doc and comment volume.** ~820 doc lines and ~470 inline-comment lines, often a paragraph per line of code. Examples: boolean.rs:776-800 (25-line doc on `successors_into`), boolean.rs:1055-1087 (33 lines), index.rs:418-423 (perf history), view.rs:290-305 (an induction proof restated twice), rects.rs:691-703, bbox.rs:160-167. Stale references: bbox.rs:166 names a crate `gpurify-units` that does not exist. view.rs:90, expr.rs:372 and connectivity.rs:640 say `core::boolean` or `crates/core/tests`. index.rs:665 says `gpurify-core` | ~450 (cut ~40% of what remains) |
| B3 | **Duplicate point-in-polygon.** `store::point_in_verts` (store.rs:423-466) is the same even-odd + on-edge algorithm as `ops::point_in_ring` (ops.rs:140-191). They are equivalent: `point_in_ring`'s extra `side != 0` guard only differs when `on_edge` is already true. Make `point_in_ring` take `(xs, ys, p)` and call it from both places | ~45 |
| B4 | **`Rect` duplicates `Bbox`.** Same four `Dbu` fields (rects.rs:576-602). `Rect::area` equals `Bbox::area` for non-inverted boxes, and decomposition never emits inverted ones. Use `Bbox`; check's `Rect` users are drc/mod.rs and antenna.rs | ~27 |
| B5 | **Duplicate `in_domain`.** ops.rs:42-44 duplicates dbu.rs:12-14 | 4 |
| B6 | **Hand-rolled unsafe branchless compacts, x4.** view.rs:281-309 (hole candidates, not hot), rects.rs:676-713, index.rs:450-478, prefilter.rs:102-130 (dead). Replace with `retain` / `filter().collect()`. Their comments claim 1.06-1.19x on rects/index; if that matters, keep it in one generic `compact_by(&mut Vec<T>, pred)` helper rather than three copies. Results are unchanged either way | ~70 (view ~28, rects ~30, index ~22) |
| B7 | **Test-only observer seams.** `Observer` + `ObserveUnionFind` + `ObservePairs` + `ObservePrefilter` add generic parameters, `O::ENABLED` branches, `*_observed` wrappers and replay passes (`report_prune` x2). They exist only for in-src tests (§3b) | ~120 src |
| B8 | **`emit` vs `canonical_rings_into` duplicate the trace pipeline.** Both run `segments → successors_into → link` (boolean.rs:969-983 and 1132-1146). Factor out `trace(xs, region, sweep)` | ~15 |
| B9 | **`StrTable` sorted/pending two-run index with a sqrt merge** (intern.rs:299-423). The stated reason is "iteration order must be identical", but no API iterates the table. Ids are assigned in arrival order either way, so `HashMap<Box<str>, StrId>` + `Vec<Box<str>>` gives identical ids and results. The only visible difference is lookup performance | ~60 |
| B10 | **`index::Grid` recomputes its shape per query.** `dims()` (index.rs:329-335) calls `axis_cells` twice per gathered row; store `nx, ny` in `Grid` instead. `Level` (index.rs:77-102) is a one-user struct. The private type name `Grid` collides with the public `dbu::Grid` | ~15 |
| B11 | **`bbox.rs` const `min`/`max` helpers (6-25)** exist so `Bbox` methods can be `const fn`. No const context in prod calls them. Dropping `const` lets them use `i64::min/max` | ~20 |
| B12 | **`linalg` doc about the solver history** (linalg.rs:1-16) and `nrm2` as a separate one-liner | ~12 |
| B13 | **`GeometryStoreBuilder::push` debug-only domain scan** (store.rs:496-506), plus three separate u32 overflow `expect`s per push (508-517) | ~15 |
| B14 | **`view::validate_layer_into` builds a full `SpatialIndex` plus candidate pairs just to bind holes** (view.rs:271-275). Fine algorithmically. Just note that the per-call allocation (`outers`, `holes`, `outer_slot`, `owned`, `pairs`, `nested`, `best_area`, `best_slot`) is fresh every call despite the `_into` API style | 0 lines, perf note |

Total estimate: **~2,600 of 6,571 src lines deletable**, taking non-test src from ~5,730 to ~3,100. **~1,950 test lines** become obsolete (see §5).

---

## 5. PROPOSED SIMPLE API

Plain data plus free functions over slices. The only retained state is the store/layer tables themselves.

```text
// numbers
Dbu(i64), DbuArea(i128), MAX_ABS_DBU, Grid{new,dbu_per_um,to_dbu,to_length}, GridError
Qty<D,P> + 9 dimensions + celsius + prefix::*        // keep as-is (report/serde contract)
StrId, StrTable{intern,get,resolve,len}               // HashMap-backed
LayerId(u16), PolyId(u32)

// geometry tables
Bbox{xlo,ylo,xhi,yhi; EMPTY, point, include, union, overlaps, contains, within,
     intersection, width, height, area, of_points}     // also replaces rects::Rect
GeometryStore{poly_count, layer_count, polys_on_layer, poly_verts, poly_bbox,
              poly_layer, layer_bboxes, poly_contains_point, append_layer}
GeometryStoreBuilder{with_capacity, push, finish(layer_count) -> (store, perm)}
ValidatedLayer{len, is_empty, get(idx), bboxes};  PolygonRef{outer, holes, bbox, provenance};
RingRef{coords, area2};  ValidityError
validate_layer_into(&store, layer, &mut ValidatedLayer) -> Result

// predicates (all exact integer)
Point, Seg, Winding
segments_intersect, point_in_ring(xs,ys,p), area2(xs,ys), winding_of(xs,ys),
point_seg_dist2, seg_seg_dist2, isqrt

// pairs / sets / measures
SpatialIndex{default, build_into, is_empty}; candidate_pairs_into; cross_layer_pairs_into
union_into, intersection_into, subtraction_into, canonical_rings_into, BooleanError
decompose_into(&layer) -> (Vec<Bbox>, CSR);  covered_area; clipped_area
components_into(n, edges, &mut Vec<ComponentLabel>), ComponentLabel
linalg::{dot, nrm2, axpy, spmv}
```

Removed: `expr` (Evaluator, DerivedExpr, LayerRef, DerivedError), `prefilter`, `observe`, `offset_into`, `to_dbu_into`, `component_count`, `owner_of`, `orientation`/`Orientation`, `RingId`/`VertId`/`is_outer`, `RingRef::winding`, `PolygonRef::area` (move it to testgen if tests need it), `push_rect` (move to testgen), `Rect`, `of_polys_into` (made private), `StrTable::with_capacity`.

### Tests that become obsolete

| Test file | Fate |
|---|---|
| tests/derived/expr_laws.rs (735), tests/derived/plan.rs (272), expr.rs in-src (168) | delete with `expr` |
| tests/derived/prefilter.rs (259), tests/derived/main.rs (5) | delete with `prefilter` |
| boolean.rs in-src offset tests (1199-1289, ~90). Offset cases in core/boolean_laws.rs (2 refs) | delete. Keep the union/intersection and keyhole tests |
| connectivity.rs in-src (133) | delete. Labels are covered by core/connectivity_components.rs |
| index.rs in-src (236) | reduce to ~100: keep the O(n²) completeness oracles, drop the `Recorder` |
| core/connectivity_components.rs `component_count` tests (9 refs) | delete or inline a count |
| core/ops_predicates.rs `orientation` tests (~20 refs) | delete. `self_intersects` tests stay if made `pub(crate)` and tested in-src, or run through `validate_layer_into` |
| core/rects_decomposition.rs `owner_of` tests (4 refs) | delete |
| units/grid.rs `to_dbu_into` tests (11 refs) | delete |
| core/view_validation.rs `RingId`/`is_outer`/`.winding()` asserts | rewrite (small) |
| core/bbox_laws.rs `of_polys_into` (3 refs) | move to a store test |
| store_layout.rs, prefilter, tests/engine/pipeline.rs, extract/tests/field/bridge.rs `push_rect` | switch to a testgen helper |
| ingest/tests/intern.rs `with_capacity` | switch to `default()` |

Rough total: **~1,950 test lines**.

---

## 6. SIMD CANDIDATES (`fearless_simd` 1.0)

`Dbu` is `#[repr(transparent)] i64` and `Bbox` is 4×`Dbu`, which is exactly one `i64x4`. Integer min/max/compare are exact and order-independent, so all integer candidates below give bit-identical results.

| # | file:line | Op | Elem | Typical N | Dependency | Layout | Verdict |
|---|---|---|---|---|---|---|---|
| S1 | linalg.rs:205-210 `axpy` | `y += a*x` | f64 | 1e4-1e6 (ERC power CG, extract GMRES) | none | SoA contiguous | **Best.** Bit-identical as long as mul+add stay separate (no FMA) |
| S2 | linalg.rs:187-194 `dot` (and `nrm2`) | Σ x·y | f64 | same | accumulator | contiguous | **Accuracy-sensitive**: the fold order is documented interface (CG alpha, convergence verdict). Only with a fixed-lane order *and* re-baselined goldens |
| S3 | linalg.rs:227-234 `spmv` | per-row Σ v[col]·val | f64 | rows 1e4-1e6, ~5 nnz/row | accumulator + gather | CSR | poor (short rows, gather). Same reassociation caveat |
| S4 | view.rs:459-467 `classify_ring` | adjacent-pair `==`, AND/OR reduce | i64 | per ring 4-~1000; runs on every `validate_layer_into` (28 prod call sites, per rule per layer) | reduction (bool, exact) | SoA contiguous (`poly_verts`) | **good**: compare `xs[i]` vs `xs[i-1]` lanes. Exact |
| S5 | bbox.rs:208-222 `of_points` (via store.rs:614 `finish` and store.rs:393 `append_layer`) | min/max fold | i64 | total verts 1e5-1e8, 4-200 per polygon | accumulator (min/max, exact) | SoA contiguous | good for long rings. Needs a `&[Dbu]` → `&[i64]` cast. Short rings will be dominated by the tail |
| S6 | index.rs:127-130 (extent union) and index.rs:150-159 (`box_extent` + `widest`) | union = lane min over `[xlo,ylo,-xhi,-yhi]` | i64x4 per `Bbox` | polys per layer 1e3-1e6 | accumulator (min/max, exact) | AoS `&[Bbox]` = one vector per element | good. AoS is already the natural `i64x4` shape |
| S7 | index.rs:461-473 prune compact, `Bbox::within` over gathered pairs | 4 compares + mask | i64x4 per pair | up to 2.5M pairs per layer (the comment's own figure) | none per pair; the compact write is serial | pairs → random `poly_bbox[a]`, `poly_bbox[b]` loads | moderate. Vectorise within one pair (2×`i64x4` load, compare, all-true); keep the compact scalar. Gather-bound |
| S8 | boolean.rs:1107-1110 `canonical_rings_into` skew fold | adjacent `!=` on x and y, OR reduce | i64 | every GDS BOUNDARY in ingest, 4-thousands of verts | reduction (exact) | SoA contiguous | small win. The twin in `push_ring` should be deleted, not vectorised (§3c) |
| S9 | rects.rs:795-799 `clipped_area` | per-rect clip min/max, then product | i64 → i128 | rects per polygon 1-1e3; density windows | accumulator in **i128** | AoS `Rect` | clip part only; the i128 multiply-add stays scalar. Low value |
| S10 | ops.rs:306-351 `area2`; ops.rs:140-191 `point_in_ring`; store.rs:424-466 | shoelace / cross | i128 | per ring | accumulator / parity | SoA | **not a candidate**: exactness needs i128 (products reach 2^82). No i128 lanes |
| – | connectivity `find`, boolean `merge_deltas`/`intervals_into`/`link`, store counting sort | – | – | – | chain / scatter | – | not SIMD |

---

## 7. ACCURACY-SENSITIVE: keep semantics exactly

- **ops.rs**:
  - `cross` stays in i128.
  - `segments_intersect` is inclusive of endpoints and collinear overlap.
  - `point_in_ring` counts the boundary as inside, with the half-open vertex rule. The same holds for store.rs `point_in_verts` while it exists.
  - `point_seg_dist2` rounds **up** (zero ⇔ on segment), and so does `ceil_sq_div`'s 256-bit path.
  - `isqrt` truncates and clamps.
  - `seg_seg_dist2` returns exactly 0 on touching.
- **bbox.rs**:
  - `overlaps` and `within` are inclusive; `within(_,0) == overlaps`.
  - `EMPTY` sentinel = ±`MAX_ABS_DBU`.
  - `area` clamps each span at 0 before multiplying.
  - `of_points` asserts lengths in release.
- **index.rs**:
  - Cell sizing (median, `side`), `cell_span` clamping, the `pad = (d/cell+1)*cell` rounding up, and the bucket skip via `cell_bbox().within()`. A mistake here silently drops candidate pairs, i.e. missed DRC violations or missed net connections.
  - Output is sorted, deduped, and `a<b` for same-layer.
- **store.rs `finish`**: a *stable* counting sort by layer. `PolyId` order and the returned permutation drive provenance and report order.
- **view.rs**:
  - `classify_ring` error precedence (Degenerate → SelfIntersecting → NotRectilinear → zero-area Degenerate).
  - Hole binding = innermost containing outer, with ties going to the lower row.
  - Ring order: outer first, then holes ascending.
  - `OrphanHole` is an error.
  - `self_intersects` sweep window.
- **boolean.rs**:
  - Nonzero-winding occupancy.
  - `combine_slabs` endpoint logic.
  - `segments` run merging.
  - `successors_into` **left-turn at degree-4 pinches**: it decides ring structure, and therefore polygon count and provenance.
  - `link` / `successors_into` release asserts.
  - `emit` revalidation.
  - `canonical_rings_into` keyhole semantics (ingest).
  - The `RESULT_LAYER` provenance: lowest contributing `PolyId`.
- **rects.rs `decompose_into`**: canonical vertical-slab decomposition. Rect order and boundaries feed area/density/antenna; `clipped_area` clips per axis with max(0).
- **connectivity.rs**: labels = minimum node index (canonical nets, determinism gate).
- **linalg.rs**: strict left-fold order in `dot`, `nrm2`, `spmv` (see S2/S3). `axpy` element-wise, no FMA.
- **dbu.rs `Grid::to_dbu`**:
  - Check order (finite → range → exact).
  - Separate power-of-ten multiply/divide.
  - Underflow-to-zero is rejected.
  - `to_length` is exact over the domain.
- **qty.rs / arith.rs**:
  - `to()` single-multiply scaling.
  - `Display` format (reports are diffed).
  - Serialize refuses non-finite.
  - Zero-denominator gives inf rather than an error.
- **intern.rs**: id assignment in arrival order (B9 keeps this).
- Every `debug_assert` removal is semantics-neutral in release. The release `assert!`/`expect` calls listed in B1 are fail-closed guards and should stay.
