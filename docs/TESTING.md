# Testing strategy

The rewrite is gated on this. It exists because the previous suite did not
catch logic changes, which is the only thing a test suite is for.

`crates/` is gone and is **not** an oracle. Nothing here compares against it.

---

## What was wrong with the previous suite

Measured, not guessed:

| suite | cases | assert only "nothing found" | check any measured value |
|---|---|---|---|
| drc | 94 | 45 (48%) | 30 (32%) |
| erc | 23 | 10 | **0** |
| lvs | 16 | — | **0** |
| pex | 27 | — | **0** |

- **ERC/LVS/PEX compared counts and statuses only.** A rule flagging the wrong
  shape, at the wrong coordinate, with the wrong measurement passed as long as
  it flagged the right *number* of them.
- **Half the DRC corpus asserted absence.** A rule that never fires passed all
  45. This is why `RuleRun` exists: "clean" now means *this rule ran and
  examined N shapes*, which is a different and checkable claim.
- **Tautology tests** — `assert_eq!(FACTORIES.len(), 19)` — measured the
  manifest, not the code.

---

## The oracle

An oracle states the correct answer **independently of the code under test**.
This project has three, all self-contained. No KLayout, no ngspice, no
FasterCap: an external tool is a version-pinned dependency that cannot run in
an inner loop, and it answers a slightly different question than we asked.

### 1. Closed form

An analytic solution the test computes directly:

- parallel-plate capacitance `εA/d`; an isolated sphere at `4πε₀r`
- sheet resistance of a known rectangle: `R□ × squares`
- series and parallel resistor networks
- the area of a known polygon

### 2. Law

A conservation or symmetry property that holds for **any** input, so it works
on realistic geometry where no closed form exists. These are the strongest
tests here, because they need no constructed answer.

Geometry and booleans:

- `(a − b) ∪ (a ∩ b) == a`
- `a ∩ b ⊆ a` and `a ∪ b ⊇ a`
- union and intersection commute; self-union is idempotent
- `area(a ∪ b) + area(a ∩ b) == area(a) + area(b)`
- results are invariant under translation of every input
- ring winding and signed area agree in sign

Electrical:

- the Maxwell capacitance matrix is **symmetric** by reciprocity, for any
  geometry — `CapMatrix::asymmetry` exists to check exactly this
- it is diagonally dominant with non-positive off-diagonals
- electrostatic energy `½VᵀCV` is non-negative for every `V`
- effective resistance obeys the triangle inequality and Rayleigh monotonicity
- Kirchhoff's laws hold at every node of a solved power grid
- network reduction preserves total capacitance and driving-point resistance

Parsers:

- `parse → write → parse` is the identity on the store
- interning is idempotent

### 3. Construct-from-answer

The generator builds an input whose correct output it already knows:

- a layout emitted from a netlist must extract back to that netlist
- a violation placed deliberately must be found **at that coordinate with that
  measurement**
- a graph built with a known partition must produce those components

This is where `gpurify-testgen`'s seeded scale generator earns its keep twice:
it is the benchmark corpus and the oracle, so there is one tool rather than two.

---

## Test adapters

Some behaviour is invisible in a return value, and those places get an adapter
at the seam. See `crates/core/src/observe.rs`.

| Seam | Property it makes testable |
|---|---|
| `core::index` candidate pairs | the prune never rejects a pair the exact predicate would accept |
| `derived::prefilter` | same, for the bbox prefilter |
| rule dispatch | "clean" means this rule ran and examined N shapes |
| allocation / work counters | the kernel rule and "nothing allocates per iteration" become assertions |

The gate is an associated `const`, the null adapter is zero-sized, and the
generic sits on a *private* entry point so the public interface does not widen.
Adapter tests are therefore unit tests inside their crate — a deliberate trade.

**A null adapter must be proven absent, not cheap.** For the two hot seams, the
check is a disassembly comparison of the `bench` profile against a build with
the seam removed by `cfg`; identical instruction sequence or it does not merge.
For the wider seams, a benchmark within noise on the scale corpus. The failure
mode being checked for is the observer parameter blocking inlining or defeating
vectorisation — not a leftover call, which a symbol check would find.

---

## Gates

A module is not done until all three hold.

1. **Coverage** — every interface has at least one definitive test, or an entry
   in `NEED_TESTING.md` naming what is missing and why.
2. **Mutation** — no undocumented survivor in the module's files. A survivor is
   a missing test *or* an equivalent mutant; decide which every time, and record
   an equivalence argument **at the site in the source** so it is not
   re-litigated. A contrived test against an equivalent mutant inflates the
   score without adding safety.
3. **Determinism** — output byte-identical across two runs at two thread counts.
   This is the gate that would have caught the defect where 8 of 27 parasitic
   outputs differed between runs of the same binary.

**Performance is recorded, not gated.** Every module's benchmark number on the
scale corpus is written down as it lands. That is a deliberate choice: the
number is watched by a human rather than by CI.

### Running mutation testing

**A post-processing pass per crate, never inside the edit loop.** The previous
workspace generated 12,830 mutants; at one test run each that is over 20 hours
even at `-j16`. Scope it to the file being changed:

```sh
nix develop -c cargo mutants -p gpurify-core -j 8 --timeout 120 -f src/bbox.rs
```

---

## Order of work

Tests lead. A rewrite verified by a suite that does not catch logic changes is
a green checkmark that means nothing.

The four phases (see `CLAUDE.md`) enforce that ordering structurally: signatures
freeze in the Definition-Phase, tests are written against them in the
Testing-Phase, and the Implementation-Phase is done when those tests pass — not
before.

---

## What the suite covers

As the Testing-Phase closed: **678 tests**, none `#[ignore]`d, across fourteen
crates. `cargo test --workspace --no-run` compiles and
`cargo clippy --workspace --all-targets` is clean. Every one of the 678 panics
when run, because every body outside `gpurify-testgen` is still `todo!()`. That
is the phase's expected state.

Each test opens with a comment naming its oracle. The counts below are counts of
those annotations, not of tests: a few tests name two oracles and a few name
none, so a row can differ from its test count by a handful. Determinism is
counted separately from the three oracles because it is a gate rather than an
oracle — it proves two runs agree, not that either is right.

| crate | tests | closed form | law | construct-from-answer | determinism | adapter seam |
|---|---:|---:|---:|---:|---:|---:|
| units | 42 | 19 | 19 | 2 | 2 | — |
| core | 77 | 12 | 39 | 17 | 6 | 3 |
| ingest | 41 | — | 15 | 25 | 1 | — |
| derived | 32 | 1 | 13 | 14 | 2 | 2 |
| topology | 16 | — | 1 | 13 | 2 | — |
| report | 21 | 2 | 11 | 8 | — | — |
| drc | 105 | 11 | 6 | 71 | 4 | — |
| erc | 92 | 15 | 21 | 52 | 5 | — |
| lvs | 48 | — | 18 | 30 | — | — |
| pex | 65 | 18 | 36 | 6 | 5 | — |
| export | 57 | 1 | 16 | 27 | 13 | — |
| engine | 19 | — | 2 | 15 | 2 | — |
| cli | 34 | — | 1 | 30 | 3 | — |
| testgen | 29 | 8 | 10 | 5 | 4 | — |
| **total** | **678** | **87** | **208** | **315** | **49** | **5** |

Where the weight sits, and why:

- **`pex` and `units` are law-and-closed-form crates.** Capacitance,
  resistance and the field solve have analytic answers, and where the unit chain
  does not close (see `NEED_TESTING.md`) the closed form degrades to a scaling
  law rather than being dropped. `units` splits evenly because half its surface
  is grid arithmetic with an exact answer and half is dimensional algebra whose
  content is the law that the dimensions compose.
- **`drc` and `cli` are construct-from-answer crates.** A DRC rule has no
  closed form; it has a violation placed on purpose at a coordinate with a
  measurement, which is what `gpurify-testgen`'s violation module builds. All
  twenty-six rules are covered this way, including the four combinatorial ones
  the ledger expected to fail — `multi_patterning`, `cheesing`, `redundant_via`
  and `via_array_spacing`.
- **`core` and `lvs` are law crates.** Boolean area conservation, CSR and
  transpose invariants, and graph-partition properties hold for any input, which
  is what makes them worth stating on generated geometry.
- **`export` carries the determinism weight** (13 of 48), because it owns every
  writer. Each is run twice, again on a second thread, and again across a
  wall-clock second boundary.
- **`topology` has one law and thirteen construct-from-answer tests** because
  net extraction has no conservation property to state: the answer is the
  partition the generator built the layout from.

The workspace has six private `*_observed` entry points, and all six are tested
through a recording adapter, as unit tests inside their own crates — the trade
recorded in `crates/core/src/observe.rs`.
`core::index::candidate_pairs_observed` and `cross_layer_pairs_observed`,
`core::connectivity::components_observed`,
`derived::prefilter::candidates_observed`, `lvs::refine::refine_observed` and
`drc::record_run`. The adapter column above counts only the tests that name the
seam itself as their oracle; the rest are annotated construct-from-answer,
because their fixtures state the merge sequence, the round sequence or the
violation count before the call.

`pex::matvec::ObserveMatVec` is the exception and has no test. The trait exists
and `NoObserve` implements it, but no function in the workspace takes one, so
there is nothing to install an adapter at. That is a signature defect, not a
coverage decision, and it is recorded in both `NEED_TESTING.md` and
`SIGNATURE_DEFECTS.md`.

**Two of the three gates are met.** Coverage holds: every interface has a
definitive test or an entry in `NEED_TESTING.md` naming what is missing.
Determinism holds where a thread count exists — only `engine::run` takes one, so
that is the single place the two-thread-count clause is stated, and the other
crates substitute two OS threads and a reused output table. Mutation testing has
not run: `cargo mutants` needs bodies, so it belongs to the Implementation-Phase
and is the first thing to do once the suite goes green.
