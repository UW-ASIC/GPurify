# GPU scope and design contract

**GPU acceleration exists for quasi-static PEX only, and is optional there.**
DRC, ERC and LVS are CPU-only.

---

## Why the original path was ~1000x slower than CPU

Audited against the pre-rewrite tree (3,462 LOC of GPU code, 54 `#[cfg(gpu)]` blocks
across 21 files, 5 shaders totalling 86 lines). The kernels were not the
problem — the dispatch model was.

| Cause | Evidence |
|---|---|
| **Synchronous readback after every dispatch** | `backend/src/gpu.rs:259` `.wait(None)`; `pex/…/vulkano_backend.rs:534,556` read the output buffer immediately after dispatch. GMRES runs 50–100 iterations per solve, so one solve became 50–100 PCIe round trips. |
| **Per-call buffer allocation and re-upload** | `vulkano_backend.rs:523-525,545-547` allocate and upload the input vector on *every* `gemv`/`gemm` call, despite the matrix already being resident. |
| **No dispatch batching** | `vulkano_backend.rs:560-578` — each GEMM in a batch is a separate dispatch plus wait. |
| **f64↔f32 conversion per call** | `vulkano_backend.rs:495-503`. |

Two further problems made it worse than merely slow:

- **Silent precision downgrade.** PEX GPU results were computed in f32 and
  never re-verified on CPU. On a tapeout signoff path that is an accuracy
  regression, not a performance trade.
- **Effectively unverified.** Nearly every GPU-vs-CPU equality test was
  `#[ignore]`d, so nothing proved the two paths agreed.

## Why DRC/ERC/LVS GPU is not coming back

Those kernels were *advisory prefilters*: the GPU flagged candidates and the
exact CPU check then ran over them anyway. The best case is saving part of the
work while paying all of the transfer cost, on operations with near-zero
arithmetic intensity (one `i32` modulo per element, for the off-grid check).
That is a ceiling imposed by the architecture, and no tuning clears it.

## Why quasi-static PEX is different

It is the only workload in the tree with real arithmetic intensity: dense BEM
matrices and an FMM near-field. Of the five original shaders, **P2P Laplace was
the only genuinely GPU-suitable kernel** — embarrassingly parallel, one thread
per target, high flop-per-byte when the source count is large.

---

## The precision constraint, and the design it forces

The development target is an **RTX 4060 (Ada, consumer)**, where FP64 runs at
**1/64 of FP32 rate** — roughly 0.5 TFLOPS against ~15 TFLOPS. The host is an
**i9-14900HX**, good for order 1 TFLOPS of f64 with AVX2.

**A straight f64 GPU port would therefore be slower than the CPU.** That is
almost certainly why the original chose f32 — but it did so silently, on a
signoff path, with no error bound.

The resolution is **mixed-precision iterative refinement**, which is the
standard technique for exactly this hardware situation:

- the GMRES matvec — the expensive part — runs on the GPU in **f32**;
- the residual and the correction are computed on the **host in f64**;
- iteration continues until the f64 residual meets tolerance.

This recovers f64-accurate answers at close to f32 speed, and — the important
part — the residual is a *measured* accuracy bound rather than an assumption.

## Contract for the GPU path

It does not land unless all of these hold:

1. **Persistent buffers.** Matrix and vector buffers are allocated once per
   solve and reused across iterations. No allocation inside the iteration loop.
2. **Async submission.** No host wait between dependent dispatches; the fence is
   waited on once, where the result is genuinely needed.
3. **Batched dispatch.** The FMM M2L batch is one dispatch, not one per block.
4. **f64 residual.** Accuracy is bounded by an f64 residual check on the host,
   and the achieved residual is reported, never assumed.
5. **CPU-equality tests that actually run.** Not `#[ignore]`d. Where the GPU
   path is unavailable in CI, the test asserts the fallback was taken; where a
   device exists, it asserts agreement with the CPU path within the documented
   tolerance.
6. **A measured crossover.** GPU is selected only above the problem size where
   it was benchmarked to win. Below it, CPU — automatically, not by a flag.

Failing any of these, the CPU path is the answer, and saying so is a complete
result.

---

## Status: the path exists and runs

All six hold. `crates/extract/src/field/gpu.rs` is the adapter,
`crates/extract/shaders/p2p_laplace.comp` the kernel,
`crates/extract/tests/field/gpu.rs` the tests — none of them `#[ignore]`d.

| # | How it is met |
|---|---|
| 1 | `GpuMatVec::upload` allocates all four buffers **and records the command buffer**; `apply` neither allocates nor records. |
| 2 | One dispatch per `apply`, one fence, at the end. |
| 3 | The whole matvec is one dispatch. There is no far field — this is direct P2P; the FMM is still filed. |
| 4 | `solve::refine` takes **two** operators. See below. |
| 5 | Five tests, each with a no-device branch asserting the fallback and a device branch asserting agreement with `CpuMatVec`. Which branch ran is printed. |
| 6 | Measured on an RTX 4060 Laptop against an i9-14900HX, `--release`. |

### The measured crossover

| panels | host µs | device µs | winner |
|---:|---:|---:|---|
| 64 | 11.1 | 216.8 | host |
| 256 | 410.7 | 254.9 | device, 1.6× |
| 512 | 1959.5 | 398.1 | device, 4.9× |
| 1024 | 4148.3 | 353.0 | device, 11.8× |
| 2048 | 11441.1 | 738.9 | device, 15.5× |
| 4096 | 45722.4 | 2762.8 | device, 16.6× |
| 8192 | 183065.7 | 8286.6 | device, 22.1× |

`MEASURED_CROSSOVER = 256`, the first sampled count at which the device won.
Measured in `--release`: the same sweep in a debug build gives the same crossover
but a 66× figure at 8192, because it is timing an unoptimised host fold. A
crossover measured against a debug host would be too *low*, which is the
fail-open direction.

End to end, `cargo test -p gpurify-extract --test pex quasistatic` runs in
**18.3 s on the host and 3.05 s with the device**.

### Item 4 is what made the rest usable

The first time the adapter ran a real solve it **refused**: residual stalled at
`7.87e-7` against a `1e-10` tolerance, `NotConverged` after 400 iterations.
`solve::refine` took one operator, so `solve::residual` formed `b − A x` with the
same `f32` adapter as the inner solve and the bound carried that adapter's own
error. Fail-closed — a refusal, not a wrong capacitance — and useless, because
every solve above the crossover refused.

This document already specified the fix: the matvec in `f32` on the device, the
residual and the correction in `f64` on the host. `refine` now takes both, and
`field::columns_into` builds `CpuMatVec` unconditionally to be the accurate
one. Two further findings came out of the same trace:

- **The inner solve must never restart.** A restart inside the correction
  equation recomputes `rhs − A_fast d` and carries on — which is what an outer
  refinement pass does, except with the inaccurate operator. Measured: uncapped,
  passes 2 and 3 took 179 and 196 inner steps for the same three decades pass 1
  got in 21. Capped at one Krylov cycle, the whole solve goes from 3 decades in
  400 steps to 9.1.
- **The inner tolerance is a property of the fast operator, not a constant.**
  `Backend::Cpu` asks for the full tolerance and converges in one outer pass —
  which is exactly the plain GMRES `refine` used to be. `Backend::GpuF32` asks
  for `1e-3`. A constant in either direction was measured to break the other
  path.

The device path needs about 440 iterations where the host needs 400, for the
same `1e-10`. More iterations of a much cheaper kind is what mixed-precision
refinement *is*.

### Two things the build had to work around

- **`vulkano-shaders` is not a dependency.** It pulls in `shaderc-sys`, which
  needs a system `libshaderc` or `cmake`, and neither is present outside
  `nix develop` — so depending on it would make `cargo build` fail for every
  crate downstream of `pex` outside the dev shell. The kernel is compiled by
  `glslc` and the SPIR-V committed; the regeneration command is in the shader's
  header, and two unit tests check the blob is a SPIR-V compute module.
- **`vulkano` is `default-features = false`.** The default `x11` feature pulls
  `x11-dl` and `x11rb` in and makes every binary downstream link `-lxcb`, which
  fails at the link step outside the dev shell. This is headless compute and
  needs none of it.

The Vulkan loader is only on `LD_LIBRARY_PATH` inside `nix develop`, so
`cargo test` outside the dev shell exercises the **fallback** branch of every
test above. Both were run for this work and both are recorded.
