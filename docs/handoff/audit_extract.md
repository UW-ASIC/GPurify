# Audit: `crates/extract` (PEX)

Read-only audit at HEAD `41b2a1e`. Every "dead" call below was checked by grep over `crates/*/src`, `src/` and `tests/`, plus the crate's own `tests/`. Line numbers refer to HEAD.

Crate size: **src 8,301 lines** (1,706 comment lines = 20.5%; 208 `debug_assert*` statements spanning **599 lines**), tests 3,934 lines, plus `shaders/p2p_laplace.{comp,spv}`.

---

## 1. Data in and data out: the real API

### What root `src/` uses outside tests

All of it is called from `src/engine/run.rs` and `src/export/{parasitic,netlist}.rs`:

| Item | Where used | What is used |
|---|---|---|
| `ParasiticNetwork` | run.rs:8, export/parasitic.rs, export/netlist.rs | fields `node_net, node_layer, from, to, value`; methods `node_count`, `element_count`, `push`, `sort_canonical`, `net_capacitance` |
| `Parasitic` (4 variants), `network::NodeId` | export/*, run.rs | all variants |
| `analytical::extract_into` | run.rs:799, 829 | the only analytical entry point |
| `quasistatic::extract_into` | run.rs:841 | capacitance field solve plus network |
| `quasistatic::CapMatrix` | run.rs:839 | only `Default`. The matrix is dropped after the solve (run.rs:778 says so) |
| `quasistatic::Accuracy` | run.rs:899 | only `.tolerance`, `.asymmetry`, `.iterations`. `.residual` and `.backend` are never read outside tests |
| `quasistatic::solve::Options` | run.rs:847 | only `::default()` |
| `quasistatic::solve::SolveError` | run.rs:1109 | error variant |
| `quasistatic::mesh::MeshError` | run.rs:1111 | **cannot be produced**: `field/mod.rs:171-175` maps every `MeshError` to `SolveError::Breakdown(0)` |
| `quasistatic::{extract_inductance_into, InductMatrix, InductanceOptions}` | run.rs:866-878 | only `Default` options; the matrix is dropped |

### Inputs

- `&GeometryStore`, which supplies polygon bboxes, vertex rings and layers.
- `&NetTable` (`polys_of`, `net_of`, `same_net`, `net_count`).
- `&DeviceTable`, which is passed to `extract_devices_into`. That function does nothing (analytical.rs:764-796).
- `&Connectivity` (`conductors`, `via_cut`, `via_connects`).
- `&ProcessStack`: SoA columns `sheet_res_ohm_sq, area_cap_af_um2, fringe_cap_af_um, thickness_nm, height_nm, dielectric_k`, indexed by `LayerId`.
- `Grid` (dbu per µm).
- The field path also takes `selected: &[NetId]`, the nets named by `--quasistatic` on the CLI.

### Outputs

`ParasiticNetwork` in SoA form: node columns `node_net`/`node_layer`, and element columns `from`/`to: Option`/`value: Parasitic`. Values are stored as ohm, fF and pH.

- The analytical path gives n+1 nodes per net (one per polygon boundary): a series R per polygon, a ground C per polygon, lateral and interlayer coupling C, and via R.
- The field path gives one node per net, a ground C equal to the Maxwell row sum, and a coupling C of −C_ij. With `--quasistatic-inductance` each net also gets a second node, with series L and R between the two nodes.
- The field path also returns `Accuracy` (residual, tolerance, iterations, backend, asymmetry) and a `CapMatrix`. Root drops both except for the reciprocity check.

### How `run.rs` drives it (`run_pex`, run.rs:769-893)

1. With no `--quasistatic` nets it calls `analytical::extract_into` on the whole design.
2. Otherwise it resolves net names (refusing any unknown name), runs the analytical extraction on the whole design, then `quasistatic::extract_into` on the selection.
3. `reciprocity_refusal` (run.rs:899-921) refuses the result when `asymmetry` is non-finite or greater than `tolerance`.
4. When `quasistatic_inductance` is set, it runs `extract_inductance_into` on the same `solved` network.
5. `merge_field_solved_into` (run.rs:936-1068, plus `replaced_node_count` at 1070-1077; about 145 lines) replaces the analytical rows of every solved net with the field rows, then calls `sort_canonical`.

**Bug found (accuracy/correctness):** the merge's premise at run.rs:1020, "`analytical::extract_into` emits nothing spanning two nets", is false. `couple_into` (analytical.rs:395-500) emits `CouplingCap` between two nets. When a selected net couples analytically to an unselected neighbour:

- If the unselected net has the lower `NetId`, `from` survives and `to` maps to `DROPPED_NODE`. A debug build panics at run.rs:1026. A release build pushes an element with `to = NodeId(u32::MAX)`, a dangling node that the export then writes out.
- If the selected net is lower, the element is dropped silently. The field solve never meshed the neighbour, so that coupling is lost completely.

The only end-to-end test (`tests/engine/checks.rs:617`) selects **both** nets of PEX_COUPLING_C, so it never reaches this case.

**Model caveat, for the record:** the BEM mesh contains only the selected conductors and has no ground plane or substrate. The "ground" capacitance is therefore capacitance to infinity, and unselected neighbours are invisible to the solve.

The CLI **can reach the inductance (henry) path**: `src/bin/gpurify/args.rs:161` (`--quasistatic-inductance`) → `RunOptions.quasistatic_inductance` → run.rs:866 → `quasistatic.rs:122` → `field/henry/bridge.rs:98` → `solver::solve_with(nl, Method::Direct)`. Only this narrow slice of the FastHenry port is reachable: Direct + Nodal, one frequency, 1×1 filaments, no ground plane.

---

## 2. Module map

| File | Lines | Purpose | Production-reachable? |
|---|---:|---|---|
| lib.rs | 17 | module list plus re-exports | yes |
| network.rs | 240 | `ParasiticNetwork`, `Parasitic`, `NodeId`, canonical sort, `net_capacitance` | yes |
| analytical.rs | 827 | closed-form R/C/coupling/via extraction | yes (except `extract_devices_into`, a no-op) |
| reduce.rs | 610 | network reduction (series/parallel/lump) | **no, test-only** |
| quasistatic.rs | 197 | wrapper: `CapMatrix` to network; inductance to network; re-exports `field::*` | yes |
| field/mod.rs | 487 | `CapMatrix`, `Accuracy`, `extract_into`, `columns_into`, mesh sizing heuristics | yes |
| field/mesh.rs | 638 | box-to-panel meshing, proximity refinement, Morton ordering | yes |
| field/matvec.rs | 329 | `MatVec` trait, `CpuMatVec` dense P2P kernel, `select`, `ObserveMatVec` | yes (trait and observer overbuilt) |
| field/solve.rs | 471 | restarted GMRES plus mixed-precision `refine` | yes |
| field/gpu.rs | 681 | vulkano f32 P2P adapter (+ shader) | yes, when a Vulkan device is present and panels ≥ 256 |
| field/henry/bridge.rs | 286 | GeometryStore to FastHenry `Netlist` to per-net L, R | yes (`--quasistatic-inductance`) |
| field/henry/solver.rs | 595 | filament build, L assembly, Zb, nodal/mesh solve, sweep | partly (Direct/Nodal only) |
| field/henry/netlist.rs | 335 | `.inp` data types plus **text parser** | types yes, parser **no** |
| field/henry/mesh_analysis.rs | 226 | FastHenry mesh (loop) formulation | **no** |
| field/henry/units.rs | 16 | `.units` parsing | **no** (parser only) |
| field/henry/mod.rs | 31 | re-exports plus `run()` | `run` **no** |
| field/integrals/filament.rs | 498 | Grover/Hoer-Love/quadrature mutual inductance | yes (`mutual`, `self_inductance`) |
| field/integrals/mod.rs | 12 | mod | n/a |
| field/krylov.rs | 912 | real and complex GMRES, batched complex GMRES | **no** (Iterative only) |
| field/operator.rs | 209 | dense and block-Jacobi operators, real and complex | **no** (Iterative only) |
| field/kernel.rs | 60 | `laplace`, `laplace_grad`, operator traits | **no** |
| field/linalg.rs | 464 | `DenseMatrix`, `LuDecomposition`, `LowRankApprox`, cdot helpers | LU yes; rest **no** |
| field/geometry.rs | 140 | `Vec3`, `Frame` | Vec3 yes; Frame **no** |
| field/constants.rs | 20 | MU0, EPS0 … | only `MU0_OVER_4PI` |

There are two unrelated GMRES stacks: `field/solve.rs` (production, capacitance) and `field/krylov.rs` (FastHenry port, unreachable). There are also two Laplace kernels: `CpuMatVec` and `kernel::laplace`, which is dead.

---

## 3. Dead code: used by tests only, or by nothing

| Item | file:line | Lines | Used by |
|---|---|---:|---|
| whole `reduce` module (`reduce_into`, `collapse_series_into`, `merge_parallel_into`, `total_capacitance`, `Order`) | reduce.rs:1-610 | 610 | tests/pex/network.rs (13 tests), tests/pex/analytical.rs:25 (`total_capacitance`) |
| `extract_devices_into` (a no-op with 5 asserts) | analytical.rs:764-796, call at :248 | 35 | nothing |
| `CapMatrix::get` | field/mod.rs:56-61 | 6 | tests |
| `CapMatrix::energy` | field/mod.rs:96-118 | 23 | tests (3 energy tests) |
| `mesh::conductor_area` | mesh.rs:540-560 | 21 | tests |
| `Panel::normal` field (written, never read in src) | mesh.rs:16-17, 422-427 | ~6 | tests only; 24 of every 64 bytes per panel |
| `ObserveMatVec` trait + `apply_observed` indirection (only `NoObserve` impl) | matvec.rs:174-280, 312-326 | ~25 | nothing |
| `EngineError::Mesh` (unreachable, see §1) | src/engine/run.rs:1111 | 2 | nothing; fix by propagating `MeshError` |
| `GPURIFY_REFINE_TRACE` eprintln | solve.rs:408-418 | 11 | debug env var |
| `krylov.rs` entire (`gmres` real, `gmres_complex`, `gmres_complex_batched`, `GmresResultMeta`, `consume_*`) | krylov.rs:1-912 | 912 | only `Method::Iterative` (tests) and its own unit tests |
| `operator.rs` entire (`DenseOperator`, `BlockJacobi`, `DenseComplexOperator`, `BlockJacobiComplex`) | operator.rs:1-209 | 209 | Iterative only |
| `kernel.rs` entire (`laplace`, `laplace_grad`, `apply_vec`, 2 traits) | kernel.rs:1-60 | 60 | nothing / Iterative |
| `linalg::LowRankApprox` ("for the FMM", which does not exist) | linalg.rs:270-428 | ~160 | nothing |
| `impl Field for f32` | linalg.rs:58-76 | 19 | nothing |
| `cdot`, `cdot_conj`, `caxpy`, re-export of `axpy/dot/nrm2` | linalg.rs:430-464 | 35 | Iterative only |
| `LuDecomposition::solve_many`, `DenseMatrix::identity/matvec/get/set` | linalg.rs:~113-146, 264-268 | ~30 | check each; `solve_many` has 0 callers |
| `geometry::Frame` | geometry.rs:118-140 | 23 | nothing |
| `constants::EPS0`, `ONE_OVER_4PI_EPS0`, `MU0` | constants.rs:10-20 | ~10 | nothing (only `MU0_OVER_4PI` live) |
| `filament::mutual_parallel_equal_grover` | filament.rs:127-160 | ~30 | nothing |
| `henry::netlist::parse` + `kv/getf/get_count/ParseError` | netlist.rs:123-335 | ~210 | tests/field/henry_validation.rs only |
| `henry::units` | units.rs | 16 | parser only |
| `henry::mesh_analysis` + `Formulation::Mesh` | mesh_analysis.rs:1-226, solver.rs:38-44, 431-436 | ~235 | 1 test |
| `Method::Iterative`, `auto_method`, `branch_count`, `solve`, `solve_full`, `henry::run` | solver.rs:46-56, 310-335, 441-465; henry/mod.rs:27-31 | ~60 | tests |
| ground-plane images (`mirror_point`, `mirror_filament`, image branches); bridge never sets `ground_plane` | solver.rs:239-300 (image parts) | ~45 | tests |
| sub-filament partition / skin-effect (`filament_partition`, `rw/rh`); bridge always uses 1×1 | solver.rs:156-238 | ~60 of 85 | tests |
| `FreqSweep` sweep expansion beyond one point; `SolveResult` per-f matrices | netlist.rs:60-95, solver.rs:80-117 | ~40 | single-point in production |
| string-named nodes plus `HashMap node_index` round-trip; bridge formats names that the solver then looks up | bridge.rs, netlist.rs:104-121 | n/a | replace with indices |

**Dead-code subtotal ≈ 2,900 src lines**: reduce 610, henry/numerics ≈ 2,100, misc ≈ 170.

---

## 4. Bloat

### 4a. GPU (vulkano) path: recommendation is to delete it

Cost:

- field/gpu.rs is 681 lines.
- shaders/p2p_laplace.comp is 67 lines, plus the committed .spv.
- Glue adds about 45 lines: `matvec::select`, `Backend::GpuF32`, `field/mod.rs:188-209` cfg block, `quasistatic.rs:10-11`, the Cargo feature and comment.
- Tests: tests/field/gpu.rs is 386 lines; parts of tests/field/quasistatic.rs:591-642 and tests/pex/quasistatic.rs reference `Device`/`Backend`.
- **Total about 1,180 lines**, plus `vulkano` (the heaviest dependency in the workspace), which is on by default.

Problems:

1. **Output depends on the machine.** Backend selection is automatic (`crossover = 256` panels, gpu.rs:275). A machine with a Vulkan device solves the correction equation in f32. Refinement converges to the same 1e-10 tolerance, but along a different trajectory, so the low bits of C differ from a CPU-only machine. That contradicts the crate's own "determinism is an interface constraint" (lib.rs:6). CI (no GPU) and a laptop (GPU) produce different bytes.
2. `Device::find()` creates a Vulkan instance on **every** field solve (field/mod.rs:194).
3. The measured win is 1.6× at 256 panels and 22× at 8,192 panels, against a **single-threaded, scalar** CPU kernel (matvec.rs:240-258 has no rayon). A rayon-over-rows plus f64x4 SIMD-over-targets CPU kernel is bit-exact with today's CPU output (§6) and should be about 4 × (cores) faster: roughly 60-100× on the i9-14900HX it was measured on. That matches or beats the f32 GPU while staying f64 and deterministic.
4. With the GPU gone, `solve::refine`'s two-operator design has one user with `accurate == fast`. It reduces to restarted GMRES with an extra outer residual loop: `refine` at solve.rs:305-440 (about 120 lines), `Backend`, `INNER_TOLERANCE`, and `columns_into`'s two generic operators. **Accuracy-sensitive**: replacing `refine` with a bare `gmres` changes the iteration trajectory, so the low bits of the output change within tolerance. It can be done as a separate, labelled commit, or `refine` can be kept.

### 4b. Henry (inductance)

The CLI reaches it, so keep the physics. About 2,100 lines of a general FastHenry port serve a call that is always `solve_with(nl, Direct)` at one frequency on 1×1 filaments. The minimal implementation is:

bridge (bbox to filament) → `assemble_inductance` (`filament::mutual`, `self_inductance`) → Zb = R + jωL → complex LU → nodal Y → port Z.

That is about 500 lines (filament.rs ≈ 350 kept, solver core ≈ 150, `LuDecomposition` + `DenseMatrix` ≈ 120, `Vec3` ≈ 80). It can also build indices directly instead of the string/HashMap `Netlist` round-trip. **Deletable: about 2,000 src lines** plus henry_validation.rs (345). Port 2-3 physics oracles (DC R exact, single-bar Grover, which tests/field/bridge.rs already has, and L flat versus f) to the bridge API.

### 4c. One-user abstractions

- The `MatVec` trait has two impls today and one after the GPU goes. Make `CpuMatVec::apply` a plain function.
- `ObserveMatVec` exists only for `NoObserve`.
- `quasistatic.rs` is a 197-line wrapper over `field::extract_into`. Merge it into one module.
- It duplicates the "lowest layer anchor" loop at quasistatic.rs:55-63 and :130-140.
- `InductanceOptions.method`, `solve::Options.{restart,max_iterations}` and `MeshOptions.proximity_refine == max_edge` are only ever defaults, so they can be consts.
- `analytical.rs` exposes `segment_resistance`, `via_resistance`, `ground_capacitance`, `coupling_capacitance`, `extract_net_into` and `stack_row` as `pub` for tests only. Make them private or `pub(crate)`.

### 4d. Defensive checks that cannot fire, and debug_assert noise

In total, 208 statements occupy **599 lines** (analytical 213, field/mod 72, mesh 61, network 44, matvec 43, solve 42, reduce 86). Most restate a constructor invariant ("a Grid is positive by construction", "SoA columns must agree", "one permittivity per panel"), repeated at every layer. Examples:

- `stack_row` (analytical.rs:799-827) runs 5 column-length asserts on **every** call, which is per polygon.
- `ParasiticNetwork::push` computes the counts twice and asserts after each push (network.rs:125-135).
- `sort_canonical` re-checks its sort (network.rs:207-221).
- `CpuMatVec::apply_observed` runs a full O(n) finiteness scan per matvec, and `build` has two O(n) block asserts.
- `field/mod.rs:365-367` asserts a value that was just `clamp`ed.

Keep about 10 that guard real cross-module invariants. Keep also the release-mode checks: `checked_add` at analytical.rs:626, `total.is_finite()` at field/mod.rs:305, the reslices in the matvec, and the NaN-aware `asymmetry` fold.

**Estimated deletable: ~550 lines.**

### 4e. Overlong comments

1,706 comment lines (20.5%). The worst:

- `matvec.rs:119-158` (40 lines on rectangular-panel self-potential error) and `:176-235` (60 lines on the two-medium Green's function).
- `gpu.rs` header (145 comment lines).
- `solve.rs`, `field/mod.rs` `mesh_options` doc.

These carry **real accuracy caveats**: capacitance under-reported by 3.5-64% on slivers, and coupling under-predicted by 14-159% within one metal level because there are no reflected images. Condense each to 2-3 lines and keep the numbers, but not the essay. **Estimated removable: ~900 lines.**

### 4f. Performance defect outside the crate, worth fixing here

`ParasiticNetwork::net_capacitance` scans every element (network.rs:143-178). The export calls it once per net (export/parasitic.rs:283, 389), so DSPF/SPEF writing is **O(nets × elements)**. A single pass that buckets per net keeps the per-net summation order, so it is bit-identical.

### 4g. `merge_field_solved_into` (run.rs, about 145 lines)

This logic belongs inside extract, alongside the fix for the bug in §1. `extract` knows which nets are field-solved. It can skip their polygons in `extract_net_into`, and it can decide the coupling policy for mixed pairs; the likely choice is to keep the analytical coupling to unselected neighbours. That shrinks run.rs's PEX section to about 20 lines.

### Deletion estimate (src)

| Bucket | Lines |
|---|---:|
| reduce.rs | 610 |
| henry general-purpose port (krylov, operator, kernel, mesh_analysis, parser, units, LowRank, sweep, images, formulations) | ~2,000 |
| GPU path | ~800 src (+386 tests +~80 test glue) |
| refine + Backend + MatVec trait + observer (once the GPU is gone; accuracy-sensitive) | ~170 |
| misc dead (devices no-op, get/energy, conductor_area, Frame, constants, grover eq, trace) | ~170 |
| debug_assert noise | ~550 |
| comment condensation | ~900 |
| **Total** | **≈ 5,200 of 8,301 (~63%)**, leaving about 3.1k lines. |

Tests: about 1,500 of 3,934 lines are made obsolete (see §5).

---

## 5. Proposed simple API

```rust
// lib.rs — the whole public surface
pub struct ParasiticNetwork { pub node_net, pub node_layer, pub from, pub to, pub value }  // + node_count/element_count/push/clear(pub)/sort_canonical
pub enum Parasitic { Resistance, GroundCap, CouplingCap, Inductance }
pub struct NodeId(pub u32);

pub struct FieldRequest<'a> { pub nets: &'a [NetId], pub inductance: bool }
pub struct FieldReport { pub matrix: CapMatrix, pub residual: f64, pub iterations: u32, pub asymmetry: f64 }

#[derive(thiserror::Error)]
pub enum PexError {
    Mesh(MeshError), Solve(SolveError), NotReciprocal { asymmetry: f64, tolerance: f64, iterations: u32 },
    Inductance(InductanceError),
}

/// Analytical everywhere; field-solved (and optionally inductance) on `field.nets`,
/// merged into one canonical network.
pub fn extract_into(store: &GeometryStore, nets: &NetTable, conn: &Connectivity,
                    stack: &ProcessStack, grid: Grid, field: Option<FieldRequest>,
                    out: &mut ParasiticNetwork) -> Result<Option<FieldReport>, PexError>;

/// Per-net capacitance in one pass (replaces N calls to net_capacitance).
pub fn net_capacitances(net: &ParasiticNetwork, out: &mut Vec<f64>);
```

- The `DeviceTable` parameter is dropped because it is consumed by a no-op.
- The reciprocity refusal moves into extract.
- run.rs keeps name-to-`NetId` resolution only, and maps `PexError::NotReciprocal`/`Inductance` to `StageStatus::Refused`.
- The `field` module becomes private (`mod field;`).
- `quasistatic.rs` is folded in.

### Tests made obsolete or needing a rewrite

| File | Tests | Fate |
|---|---:|---|
| tests/pex/network.rs:255-601 | 13 (reduce) | delete; keep 5 network tests (lines 68-253) |
| tests/pex/analytical.rs:25, 340-347 | 1 helper use | replace `total_capacitance` with an inline sum |
| tests/field/gpu.rs | 6 (386 lines) | delete |
| tests/field/quasistatic.rs:591-642 | `no_device_means_the_host…` etc. | delete |
| tests/field/quasistatic.rs:470-530, 415-431, 532-590 | energy ×3, `get`, `conductor_area` ×2 | delete, or compute inline |
| tests/pex/quasistatic.rs:31 | backend assertions | drop the backend part |
| tests/field/solve.rs:339 (`refinement_reaches…`) | 1 | delete if `refine` goes |
| tests/field/henry_validation.rs | 11 (345 lines) | delete; port DC-R and L-vs-f oracles to the bridge API (skin effect, ground plane, mesh formulation and Iterative are unreachable) |
| krylov.rs:727-912 (in-src unit tests) | 3 | delete with krylov |
| gpu.rs:626-681 (in-src) | 3 | delete |
| reduce.rs:584-610 (in-src) | 1 | delete |
| **Add** | 1 | partial-selection field solve with an unselected coupled neighbour (the bug in §1) |

---

## 6. SIMD candidates (`fearless_simd` 1.0)

"Bit-exact" means the SIMD version produces identical output bits to the current scalar code. That requires the same per-element operation order and **no fused multiply-add** (use separate `mul`/`add`, never `mul_add`/`madd`). IEEE sqrt and div are correctly rounded in both SIMD and scalar, so they match.

| # | Kernel | file:line | Type | Typical N | Dependency | Layout | Verdict |
|---|---|---|---|---|---|---|---|
| 1 | **P2P Laplace matvec** `CpuMatVec::apply_observed` | field/matvec.rs:240-258 | f64 | panels n = 1e3-1e5 (cap 2^20). Cost is n² pairs per matvec × (≈10-50 iterations + refine passes) × conductors | per-row **accumulator** (chain in j) | `Collocation` AoS 40 B `{centre[3], radius, coefficient}` | **Top target.** Vectorize **over targets i** (lane = row), keep j sequential and broadcast source j. Each lane keeps its own strict ascending-j fold, so the result is **bit-identical** to today. Add `rayon` over blocks of i (also bit-identical; today the loop is single-threaded). Layout: keep sources AoS (broadcast); load target rows as 5 SoA columns `cx, cy, cz, r, k`, a one-time transpose in `build`. Preserve exact op order: `r2 = ((dx*dx + dy*dy) + dz*dz) + ri*rj`, `num = ((2*ki)*kj)*xj`, `den = (ki+kj)*sqrt(r2)`, `acc += num/den`. Throughput is bound by sqrt+div, about 4 pairs per ~5-8 cycles on AVX2. Vectorizing **over j** (lane accumulators) would be 1-2× faster again but **changes output bits**. |
| 2 | GMRES `norm` / `dot` | field/solve.rs:282-298 | f64 | n panels | accumulator chain; strict left fold is documented as an interface | contiguous | **Skip.** O(n·k) against the matvec's O(n²), under 1% of runtime, and lane accumulators change bits. |
| 3 | GMRES axpy/scale: `w -= h*v`, `x += y*v`, `v = r*inv`, `x += d` | solve.rs:164, 188, 241, 272, 403 | f64 | n | none | contiguous slices | bit-exact if FMA is avoided, but negligible, and LLVM already autovectorizes the `zip` form. Leave it. |
| 4 | Band charge sum and Maxwell row sum | field/mod.rs:298-302; quasistatic.rs:73-77 | f64 | band size / n conductors (small) | accumulator | contiguous | skip (tiny; changes bits) |
| 5 | `near_another_conductor` | field/mesh.rs:339-352 | i64 bbox compares, `\|=` reduction | S² for S = polygons in the selection (10-1e3) | OR-reduction, order-free, so bit-exact | AoS `Solid{bbox,z,eps,conductor}`; needs SoA `xlo,xhi,ylo,yhi,conductor` | low priority; O(S²) is fine at these sizes |
| 6 | `mesh_box` panel emission, `morton_keys`/`spread3` | mesh.rs:384-437, 455-530 | f64 / u64 | panels, once per mesh | none | AoS output | skip (O(n) once) |
| 7 | `CpuMatVec::build` (`sqrt(A)/shape`, `1/(4πε0ε)`) | matvec.rs:~132-160 | f64 | n, once | none | AoS | skip |
| 8 | Analytical formulas (`segment_resistance`, `ground_capacitance`, `coupling_capacitance`) | analytical.rs:73-210, used in 395-500, 608-760 | f64 | pairs from spatial index | none, but gathered through `store.poly_bbox` inside pair loops with data-dependent guards | not SoA | **skip**: dominated by index build and pair enumeration; the perimeter loop is i128 `isqrt` |
| 9 | `net_capacitance` | network.rs:143-178 | f64 | elements, × nets | accumulator | SoA columns + enum match | fix the algorithm first (§4f); SIMD would change bits |
| 10 | Henry `assemble_inductance` → `filament::mutual` | henry/solver.rs:266-310; filament.rs:85-365 | f64 | nb² for nb = polygons in the selection (tens) | none per pair | AoS `Filament` | skip: transcendental (asinh/ln/atan), branchy dispatch, tiny N; already rayon |
| 11 | Complex LU row update | linalg.rs:210-222 | Complex64 (AoS re/im) | nb (tens-hundreds) | none in j | interleaved complex | skip: small N, and would need re/im split |
| 12 | krylov.rs complex GMRES | — | — | — | — | — | dead, delete |

In short, #1 is the only kernel worth writing. Rayon plus SIMD-over-targets gives an estimated 50-100× on the machine the GPU was benchmarked on, produces bit-identical output, and makes the GPU path redundant.

---

## 7. Accuracy-sensitive code

Changing any of the following changes output bits. Items marked * could also change the printed text.

| Code | file:line | Why |
|---|---|---|
| P2P fold order: ascending j per row, exact op order, no FMA | matvec.rs:246-256 | every C entry; GMRES trajectory |
| Panel order = Morton key + `spatial_cmp` tiebreak within each conductor band | mesh.rs:207-231, 440-560 | defines the j order of #1. Removing or changing the Morton sort (tempting, since the dense direct matvec has no locality benefit) changes bits |
| Mesh sizing: `finest_feature`, `budget_edge`, `nm_to_dbu`, `MAX_PANELS`, proximity halving | field/mod.rs:336-482; mesh.rs:193-197 | changes the mesh and therefore the answer (not only the bits) |
| Rectangle-as-square self-potential `radius = sqrt(A)/SELF_POTENTIAL_SHAPE` | matvec.rs:156 | known one-sided error. Fixing it moves C by up to 64% on slivers (an accuracy improvement) |
| Harmonic-mean dielectric coefficient | matvec.rs:257 | same (known 14-159% coupling under-prediction) |
| GMRES `norm`/`dot` strict folds, Givens, back-substitution | solve.rs:120-275, 282-298 | iteration trajectory and therefore low bits |
| `refine` vs bare `gmres`, `INNER_TOLERANCE`, stall break | solve.rs:305-440 | trajectory |
| **GPU backend auto-selection** | field/mod.rs:192-209; gpu.rs:275 | **today output bits depend on whether a Vulkan device exists** |
| Zero initial guess per column (no warm start) | field/mod.rs:275 | column independence |
| Band charge sum, Maxwell row sum, `-C_ij` coupling | field/mod.rs:298-307; quasistatic.rs:70-90 | reported fF |
| `asymmetry` NaN-poison fold | field/mod.rs:67-93 | gates the reciprocity refusal; keep the semantics |
| `ground_capacitance` as two separate products, then `/1000` (not `*1e-3`) | analytical.rs:155-160 | superposition equality is tested |
| Equivalent-rectangle `(long, short)` from the i128 isqrt | analytical.rs:680-697 | PEX_WIRE_R expects exact 1.0 Ω |
| `LATERAL_HALO_THICKNESSES = 10` | analytical.rs:26 | which pairs couple |
| `sort_canonical` key (value bits as tiebreak) | network.rs:66-80 | element order, hence summation order in `net_capacitance` |
| `net_capacitance` ascending-element fold | network.rs:159-171 | * printed `*D_NET` / `*\|NET` totals |
| Henry: `assemble_inductance` (rayon indexed collect, order-preserving), LU partial pivoting, rayon per-row update | solver.rs:266-310; linalg.rs:176-230 | L, R values |

**How floats are printed:** `src/export/json.rs:316` `format_f64` is `{value:.6}`, fixed 6 decimals in the stored unit (fF, Ω, pH). A change of about 1 ulp flips printed text only when a value lies within 1 ulp of a 5e-7 rounding boundary, which is rare but possible. That is why the items marked * matter.

**How tests compare:**

- **Corpus** (`tests/fixtures/expectations.json` pex cases): relative/absolute `tol: 1e-6`.
- **Unit tests** use `assert_close*`.
- **Byte-identity tests** (`a_field_solve_is_byte_identical_across_runs` in tests/pex/quasistatic.rs:152, `meshing_is_byte_identical…` in tests/field/quasistatic.rs:353, `two_extractions_are_bit_identical` in tests/field/bridge.rs:71, `sort_canonical_maps_every_permutation…`) compare **run against run**, not against committed golden files. **No golden SPEF/DSPF snapshots exist.**

So a summation-order change will not fail any test, but it silently changes output bytes relative to earlier binaries. Keep such changes in separate, labelled commits. Every simplification in §4 **except** removing `refine`, removing the GPU (on GPU machines only), and touching the Morton/mesh order is bit-neutral.
