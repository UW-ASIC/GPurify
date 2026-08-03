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
