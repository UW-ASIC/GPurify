# quasiss

A unified, GPU-ready Rust workspace that replaces **FastHenry2** (inductance /
resistance) and **FastCap2** (capacitance) with a single shared numerical core.

The premise, following the design report: both tools are *the same machine
underneath* — a boundary/integral-equation discretization of the Laplace kernel
`G(x,x') = 1/‖x−x'‖`, a dense matrix-vector product, and a preconditioned Krylov
solve. This workspace builds that machine once; `fasthenry` and `fastcap` are
thin front ends differing only in physics.

## Status

This is a complete, compiling, **validated** implementation of the report's
**Stage 0 + Stage 1 core** — the dense FP64 reference solver that both front ends
share — with the GPU/SIMD/FMM architecture wired in behind real traits. What is
proven by the test suite runs today; what is scaffolded for later stages is
labelled as such below. Nothing is faked: every number the validation suite
prints is computed by the code.

```
cargo test          # 22 tests, all green (analytic + physics validation)
cargo build --release
./target/release/fasthenry examples/wire.inp
./target/release/fastcap  examples/parallel_plates.qui
```

**Cross-validated against the real C tools.** We built FastHenry2 and FastCap2
from source and ran identical inputs through both. On the same mesh the Rust core
matches **FastHenry2 resistance to 5–6 digits, inductance to <0.3%, and FastCap2
capacitance to 4 digits** — and the dense solver runs several times faster than
the originals on small/medium problems. Full tables and the dense-vs-FMM crossover
are in [`COMPARISON.md`](COMPARISON.md).

## What works and is validated

**Shared core (`quasiss-core`)**
- `Vec3` geometry, the Laplace kernel and its gradient.
- **Analytic near-field integrals** — the accuracy foundation the report calls
  "the single most important detail for agreement with the originals":
  - Wilton (1984) closed-form polygon potential integral for panels — validated
    to 1e-12 against the exact unit-square value and to 5e-4 against fine
    quadrature.
  - Grover/Hoer parallel-filament partial-inductance closed form (+ Neumann
    quadrature for non-parallel pairs, + Grover/Rosa rectangular-bar self term) —
    the general routine reproduces the classic Grover closed form to 1e-12.
- Dense FP64 linear algebra (LU with partial pivoting) generic over **real and
  complex** fields — real for capacitance, complex for frequency-domain `Z(ω)`.
- Restarted **GMRES(m)** with a block-Jacobi preconditioner, operating purely
  through a `LinearOperator` trait (dense today; FMM/H²/GPU later, no solver
  change).

**Inductance front end (`fasthenry`)**
- FastHenry `.inp` parser (`.units`, nodes, segments with `nhinc/nwinc`,
  `.default`, `.external`, `.freq`, `.end`).
- Filament-bundle discretization, dense partial `R + jωL` assembly, per-component
  grounded nodal solve for the multiport `Z(ω) = R + jωL`.
- Validated: DC resistance exact to 1e-9; single-bar self-inductance matches the
  Grover formula to machine precision; subdivided bundle within 0.002 %; **skin
  effect** raises AC resistance 3.7× at 1 GHz; `Z` symmetric to 1e-16.

**Capacitance front end (`fastcap`)**
- FastCap `.qui` panel-geometry parser (Q/T panels, conductor names).
- Potential-coefficient assembly with exact Wilton entries, per-conductor solve
  for the Maxwell capacitance matrix; direct and iterative (GMRES) paths agree to
  1e-15.
- Validated: isolated-sphere self-capacitance converges to `4πε₀a` (4.9 % at 80
  panels → 1.3 % at 320, monotone); parallel-plate mutual capacitance matches
  `ε₀A/d` plus physical fringing.

**CLI (`quasiss-cli`)** — drop-in `fasthenry` and `fastcap` binaries.

## Also implemented and validated (second round)

- **Complex GMRES + iterative FastHenry** — the frequency-domain impedance system
  Z(ω) solved through a `ComplexOperator` trait with a complex block-Jacobi
  preconditioner; matches the dense LU path to 1e-7 (`Method::Iterative`).
- **Mesh analysis `M Z Mᵀ`** — FastHenry's authentic fundamental-loop
  formulation (spanning forest → mesh matrix → loop solve); reproduces the nodal
  result to machine precision (`Formulation::Mesh`).
- **FastCap dielectrics** — multi-dielectric BEM (conductor potential + normal-D
  continuity), validated against the dielectric-coated-sphere closed form (4.9%
  at 320 panels).
- **FastCap list files** — `.lst` with `C`/`D` sub-file includes, per-file
  permittivity and translation.
- **FastHenry `.equiv`** (node merging, exact) and an **ideal ground plane** via
  image filaments (matches an explicit two-wire image loop to 2.8%).
- **Mixed-precision iterative refinement** — f32 LU factorization + f64 residual
  refinement recovers full f64 accuracy in ~2 steps; plus row/column
  **equilibration** for badly-scaled systems.
- **GPU hot kernels** — P2P, gemv, batched-GEMM (M2L), axpy/dot, block-Jacobi
  written as CPU-tested per-thread functions, with `#[kernel]` wrappers that are
  the same functions plus a thread index and address-space annotations.

## FMM — near-linear scaling (implemented)

The **black-box (kernel-independent) FMM** for the Laplace kernel is implemented
(`quasiss_core::fmm`): Chebyshev interpolation, a uniform octree with
neighbor/interaction lists, and the full P2M→M2M→M2L→L2L→L2P + P2P pipeline,
rayon-parallel. It implements `LinearOperator`, so it drops into GMRES exactly
like the dense apply. Accuracy is set by the Chebyshev order (spectral
convergence: order 3 → 2e-3, order 6 → 6e-6 vs the dense matvec). FastCap uses it
through a precorrected split — far field via the FMM, near field via exact Wilton
integrals — and reproduces the dense capacitance to 7e-4 while still hitting the
analytic sphere.

Measured matvec scaling (points on a sphere, order 4), dense `O(N²)` vs FMM:

```
      N   L | dense(ms)   fmm(ms)  speedup |  rel_err
   2000   3 |     14.6      44.8     0.33x |  4.1e-4
  10000   4 |    373.5     194.4     1.92x |  5.8e-4
  20000   5 |   1465.3     687.0     2.13x |  6.3e-4
  40000   5 |   5955.6     781.0     7.63x |  6.9e-4     (crossover ~10k, widening)
```

`cargo run --release --example fmm_bench -p quasiss-core` reproduces it.

## What remains for later stages

- **GPU execution** — the `krnl` `#[kernel]`s are written and their logic
  CPU-validated, but the SPIR-V compile/run needs a Vulkan device + `krnlc`,
  absent here. The Rust-CUDA PTX path is a documented contract only.
- **Inductance formula** — kept as the Grover/Rosa approximation (self ~0.02% vs
  FastHenry's exact Hoer-Love, ~0.2% for bundles), by request.
- **FMM refinements** — the octree is uniform (an adaptive tree would help highly
  non-uniform geometries) and the operator is FP64-only so far; an H²-matrix /
  HODLR algebraic variant and a complex-kernel FMM (for the FastHenry impedance
  matvec) are natural follow-ons.
- Remaining smaller items: FastHenry's exact geometric filament partition, a
  PATRAN `.neu` reader, higher-order/Galerkin panels, and hand-written AVX/NEON
  intrinsics (autovectorization only today).

## Crate map

| crate | role |
|-------|------|
| `quasiss-core` | geometry, kernel, analytic integrals, dense + GMRES solvers, operator seam |
| `quasiss-simd` | CPU SoA P2P kernel + scalar reference |
| `quasiss-gpu`  | `ComputeBackend` trait, CPU backend, krnl AOT GPU backend, AOT contract |
| `fasthenry`        | `.inp` parser, MQS assembly, nodal solve, frequency sweep |
| `fastcap`          | `.qui` parser, collocation assembly, capacitance solve, mesh generators |
| `quasiss-cli`  | `fasthenry` / `fastcap` binaries |

## Precision & the FP64 reality

Everything numeric is FP64 to match the originals. The GPU P2P kernel is f32 by
design — that is the correct precision for the *far-field* in the report's
mixed-precision scheme (FP32 far-field + FP64 near-field analytic terms on the
CPU + FP64 GMRES accumulation with iterative refinement), because consumer-GPU
FP64 is ~1/64 throughput. Accuracy is recovered by keeping the singular/near
terms in FP64 on the CPU, not by forcing f64 on the GPU.

## Roadmap (from the design report)

- **Stage 0 — reference & harness** ✅ parsers + dense FP64 solver + analytic
  integrals + analytic-benchmark validation.
- **Stage 1 — shared core + CPU FMM/H-matrix** — dense done and validated; the
  FMM/H² accelerator behind `LinearOperator` is the next addition.
- **Stage 2 — GPU offload** — `krnl` P2P kernel written; wire M2L batched-GEMM
  and measure FP64 behavior on real hardware.
- **Stage 3 — AOT** — realized via `krnl`/`krnlc` (SPIR-V) with the Rust-CUDA
  PTX path as the NVIDIA FP64 alternative.
- **Stage 4 — mixed precision & scale** — the seam and precision enum are in
  place.

## License

MIT OR Apache-2.0.
