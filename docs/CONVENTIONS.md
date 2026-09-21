# GPUVerify code conventions

The rubric for the data-oriented rewrite. Every function and struct in the
workspace is held to this. It is derived from Fabian's _Data-Oriented Design_
(the table/transform vocabulary), Acton's five questions, and the SIMD loop
shape — specialised to what this codebase actually is: **a pipeline that turns
layout geometry into verification verdicts.**

The exemplars already in-tree are `crates/geom/src/bbox.rs` and
`crates/geom/src/store.rs`. When in doubt, make the code you are writing look
like those.

---

## 0. The five questions

Answer all five in the doc comment before writing a new type or transform.
If you cannot state the transformation in bytes-in/bytes-out terms, you do not
yet understand the problem.

1. **What goes in, what comes out?**
2. **How many?** Where there is one, there are many. Design for the collection.
3. **What is the access pattern?** Which fields are read together decides
   SoA vs AoS.
4. **What is the lifetime?** Phase (reusable buffer), program (static), or
   individual. Match the allocation to it.
5. **Is it parallelisable?** Disjoint partitions of the same transform → say so.

---

## 1. Layout

**SoA by default.** Parallel `Vec`s per field. Switch to AoS only when every
field is read together in the same loop. `GeometryStore` is the reference: a
polygon is an index range, not an object.

**Hot/cold split is mandatory.** A field touched once per run does not live in
a struct iterated per element. Cold data goes in a side table keyed by the same
index. The specific smell in this codebase:

```rust
// NO — 48 bytes of Vec header per polygon, before a single string exists,
// and the same path is repeated for every polygon under one instance.
poly_hierarchy_path: Vec<Vec<String>>,

// YES — one u32 per polygon into a deduplicated table.
poly_path: Vec<PathId>,
paths: PathTable,
```

**Indices, not pointers.** `u32` handles into flat arrays. No `Rc`, no
`RefCell`, no `Box<Node>` graphs. Newtype every index (`PolyId`, `LayerId`,
`NetId`) so two id spaces cannot be confused.

**Smallest integer that fits.** `u32` for element counts, `u16` for layer
numbers, `u8` for enum tags. Never default to `usize` in a stored struct —
`usize` is for the loop counter, not the field. Use `NonZeroU32` where zero is
invalid so `Option<Id>` costs nothing.

**Existence-based processing.** If a shape participates in a rule, it is in
that rule's array. No `active: bool`, no `Option<T>` that exists only to be
skipped. Iterate what exists.

**Strings are cold, always.** Net names, cell names, rule ids and hierarchy
paths are identity, not data. Intern once at the boundary to a `u32`; compare
and hash the `u32`; resolve back to text only when writing a report to a human.
`HashMap<String, T>` in a loop is a defect.

---

## 2. Transforms

Name the pattern in the doc comment. The vocabulary:

| Pattern                         | Use when                                                                                                                |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| **A-to-B**                      | Input still needed after; new schema or row count. The default.                                                         |
| **In-place**                    | Same schema and count out as in, previous values dead on read.                                                          |
| **Generative**                  | Produces a table from a seed/id/filename, not a table.                                                                  |
| **Dispatcher**                  | Code path depends on a value in the row → split into one output table per branch, then run a uniform transform on each. |
| **Tasker**                      | Table too big for one worker, results need not merge.                                                                   |
| **Gatherer**                    | As tasker, but results land in one container. Pre-count if order must be preserved.                                     |
| **Sorted / multi-sorted table** | Locating rows, read far more than written; one entry per required query order.                                          |

**The kernel rule.** A transform must compile as a compute kernel: constants
hoisted above the loop as uniforms, each row's output a function of its own
input and those uniforms, locals only, any row order legal, each output row
written once. The moment row N reads what row N-1 wrote, it is serial — take
two passes instead, one producing a uniform and one writing.

This is not decoration. `rectilinear_occupancy` was 43% of a signoff run
because a per-polygon transform scanned rows belonging to other polygons.

---

## 3. Types

**Parse, don't validate.** Validate once at the boundary, return a refined type
whose invariant is in its private field. Downstream takes the refined type and
never re-checks. `Ring`/`Polygon` already do this — the rest of the workspace
must stop re-deriving what they guarantee.

**Sum types over flag-bags.** An `enum` beats a struct of `bool`s whose
combinations are mostly illegal.

**Encode, don't polymorphize.** Closed `enum` + `match` in any loop. `dyn Trait`
only for a genuinely open, cold set — never per shape, per edge, or per net.

**`Option` is absence, `Result` is failure.** A lookup miss is `None`. Library
errors are typed (`thiserror`), never stringly. Fail closed: an unsupported
input is a typed error, never a silently-empty clean result.

---

## 4. Memory

**Caller owns the allocation.** The primitive is `fn f_into(.., out: &mut Vec<T>)`;
the allocating `fn f(..) -> Vec<T>` is a thin convenience wrapper on top. Every
transform called in a loop must have the `_into` form so the caller can reuse
one buffer.

**Nothing allocates per iteration.** Hoist the buffer above the loop and
`clear()` it — `clear` keeps capacity, a fresh `Vec` does not. `.collect()`
inside a nested loop is a defect.

**Reserve up front.** `with_capacity` when the count is known or boundable.

**Group by lifetime.** Per-run scratch is one reused buffer set, not a thousand
short-lived allocations.

---

## 5. SIMD

Do not hand-vectorise on a hunch. The order is fixed:

1. **Triage** — state the element type, the typical length, and classify the
   loop-carried dependency as _none_, _accumulator_, or _chain_. A chain is a
   blocker: report it and stop.
2. **Layout first** — SIMD needs the scanned field contiguous. If the data is
   AoS, fixing the layout _is_ the optimisation, and usually the larger win.
3. **Check the compiler** — read the asm before writing intrinsics. If it
   already vectorised, the work is done. Note that float reductions do _not_
   autovectorise on stable (IEEE reassociation); integer kernels do.
4. **Write the shape** — splat, chunk, lane op, reduce, scalar tail. The scalar
   loop stays as both tail and reference implementation.
5. **Verify** — differential test against the scalar version across lengths
   `0 ..= 3 × lane_count`, plus a benchmark. **A vectorised loop that measures
   slower is a normal outcome: report the number and keep the scalar version.**

Below a few hundred elements the scalar loop is the right answer, and saying so
is a complete result. `wide` is the stable-SIMD dependency (already used by
`pex`); prefer autovectorisation over intrinsics.

---

## 6. Abstraction

**Compression, not anticipation.** An abstraction is _discovered_ by repetition
that already exists, never introduced for a use case that might arrive. No
trait with one implementer. No factory. No config for a value that never
changes. Delete before you add.

**No hidden control flow.** Every allocation and branch visible at the call
site. No `Deref` tricks, no operator overloading that allocates.

**Mark deliberate shortcuts.** A known ceiling gets a `ponytail:` comment naming
the ceiling _and_ the upgrade path:

```rust
// ponytail: O(n²) all-pairs scan, fine below ~10k edges.
// Upgrade to Bentley-Ottmann if profiling says otherwise.
```

However, try your best to not take shortcuts at all.

---

## 7. Verification

Every change is gated on:

- `cargo test --workspace` — the Testing-Phase suite is the contract. Until the
  Implementation-Phase it is red by construction: every body is `todo!()`.
- `cargo clippy --workspace --all-targets` — the workspace lint policy is
  `deny(correctness)`, `warn(pedantic)`.
- For any change to a numeric or geometric kernel: a law from `docs/TESTING.md`
  proving the output is *correct*, not merely plausible — area conservation for
  a boolean, matrix symmetry for a field solve. A checksum proves two runs
  agree; a law proves they agree with physics.

A refactor that changes a verification verdict is a bug, not a refactor.
