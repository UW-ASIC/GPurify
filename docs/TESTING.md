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

**This is history, not an open hole.** The 160 fixture cells survived the
deletion, and the weakness above was a property of the *assertions*, not of the
geometry. Both are now closed — see the next section.

---

## The fixture corpus

The 160 cells the old suite ran against are back, asserted through
`tests/corpus/`, and the corpus has since grown to **167** (drc 94 / erc 30 /
pex 27 / lvs 16). They are not a fourth oracle: they are construct-from-answer
(DRC/ERC/LVS) and closed form (PEX) applied to layout somebody drew for a real
PDK rather than to geometry a generator emitted. Both halves are needed — the
hand-written end-to-end tests would pass on a tool that got every real rule
wrong, and the 167 would pass on a tool whose JSON writer was not
deterministic.

**The old tree's answers are still not an oracle.** `manifest.json` is the
deleted implementation's output and nothing in the suite reads it.
`expectations.json` re-derives every case from the geometry and the rule's
frozen doc comment, then records the comparison against the manifest in a
`corroboration` field rather than folding it into the value. Where the two
disagree the derived value stands and a `dispute` field names which side is
wrong. 119 of the 167 agree with the manifest and therefore rest on two
independent routes to the same number; 24 disagree and say why.
`tests/fixtures/README.md` is the full account.

### What the corpus closed

| | old suite | now |
|---|---|---|
| DRC cases asserting only absence | 45 of 94 | 0 — every case carries `expect_outcome` and `examined_min` |
| zero-violation cases asserting `examined > 0` | — | 49 of 73 |
| DRC positive cases checking coordinate *and* measurement | 30 of 94 | all 40 |
| ERC cases checking a measured value | 0 | all 6 positive cases, plus the layer the finding is reported on |
| PEX cases checking a value | 0 | 15 closed-form values, 8 deliberate mismatches, 1 per-net pair; the other 3 through the coupling law |
| LVS cases checking anything but a verdict | 0 | 16 device-and-net counts |

The 24 zero-violation cases whose `examined_min` is 0 are not a residue of the
old weakness. Each has a stated reason and the reason is checkable: 6 expect
`Outcome::Refused` (the geometry is unrepresentable, so no rule row exists to
examine anything), 9 expect `Skipped(NoDesignIntent)`, and 9 run over a
genuinely empty jurisdiction — a spacing rule on a cell with one shape has
nothing to pair. Asserting `examined > 0` there would be asserting a falsehood.
The other 49 zero-violation geometry cases do assert `examined_min > 0`.

Five cases are marked `underivable` and say so in the file: two intent-gated ERC
rules that need per-net voltages, and three lateral-coupling cases for which
`StackJson` carries no coefficient. They assert only what does follow — the skip
status, and the 1/S law *between* the coupling cases, which is exact even when
no absolute value is.

`strength` grades every case, and a `vacuous` or `blocked` grade is a claim the
corpus makes about itself rather than a test that quietly passes.

**LVS `expect_match` is still not asserted, and the corpus says why.** No
reference netlist ships with the fixtures — the sixteen live only inside
`manifest.json`, which nothing here reads. The device and net counts are
asserted instead, and they fail on the same three defects a graph mismatch would
report, one stage earlier and with a readable message.

### Where the corpus stands

All 167 cases pass:

| domain | passing |
|---|---|
| drc | 94 / 94 |
| erc | 30 / 30 |
| lvs | 16 / 16 |
| pex | 27 / 27 |

That is the end of a work list rather than the end of the argument. A case whose
`dispute` reads `code_wrong` was the corpus disagreeing with the code and being
right, which is the outcome the split between `manifest.json` and
`expectations.json` exists to make possible. `keyhole_rejected` closed that way:
the reader now decomposes a GDSII keyhole into the outer and the hole it
denotes, so `DRC_MEA_FAIL` reports the `Area(10000)` at `(150, 150)` that its
derivation predicted while the tree could not reach it.

**The defect ledger has outlived two of its entries.** `bbox_only_enclosure` and
`notch_no_outer_merge` are still listed in `known_defects`, and their four cases
are graded `strong`, expect the physics, and pass. Their notes still say the
frozen path yields 0. Whatever closed them did not clear the ledger, so the
entries and the `dispute: code_wrong` markers on those cases now describe a tree
that no longer exists. Re-deriving those four is the cheapest outstanding work
in this file.

**Green is not the same as strong.** `strength` still grades every case, and 45
of the 167 are something other than `strong`: 11 `blocked`, 10 `vacuous`, 7
`skipped`, 7 `weak`, 5 `refused`, 5 `underivable`. A suite that reports only its
pass rate hides exactly that distribution, which is why the grade is a field
rather than a comment.

**The `counts` block is derived, and drifted once.** It is a cache of the
`cases` arrays and nothing reads it at run time, so it went two cases stale
without any test noticing: it claimed 11 `refused` and 72 `strong` for DRC where
the cases held 9 and 74. It has been recomputed. Anything quoting it, this
document included, was quoting the cache rather than the corpus.

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
at the seam. See `crates/geom/src/observe.rs`.

| Seam | Property it makes testable |
|---|---|
| `geom::index` candidate pairs | the prune never rejects a pair the exact predicate would accept |
| `geom::prefilter` | same, for the bbox prefilter |
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
nix develop -c cargo mutants -p gpurify-geom -j 8 --timeout 120 -f src/bbox.rs
```

---

## Order of work

Tests lead. A rewrite verified by a suite that does not catch logic changes is
a green checkmark that means nothing.

The four phases enforce that ordering structurally: signatures
freeze in the Definition-Phase, tests are written against them in the
Testing-Phase, and the Implementation-Phase is done when those tests pass — not
before.

---

## What the suite covers

Today: **874 tests**, none `#[ignore]`d, all passing, across six crates.

Everything from here to the end of this section is the **Testing-Phase record**,
kept as written. Read it as history, not as the current shape of the tree: it
predates both the crate merge and the Implementation-Phase, so its fourteen
crates are now six and its counts are superseded by the line above.

As the Testing-Phase closed: **678 tests**, none `#[ignore]`d, across fourteen
crates. `cargo test --workspace --no-run` compiles and
`cargo clippy --workspace --all-targets` is clean. Every one of the 678 panicked
when run, because every body outside `gpurify-testgen` was still `todo!()`. That
was the phase's expected state; the Implementation-Phase is what turns it green.

The table below counts those 678 and is the Testing-Phase record. It does not
count the workspace-root targets, which belong to no crate: `tests/test_all.rs`
carries 11 end-to-end tests plus 5 that drive the fixture corpus,
`tests/bench_all.rs` 5, and `tests/pdk_decks.rs` 6.

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

The workspace has six `*_observed` entry points, and all six are tested through
a recording adapter — the trade recorded in `crates/geom/src/observe.rs`.
`geom::index::candidate_pairs_observed` and `cross_layer_pairs_observed`,
`geom::connectivity::components_observed`,
`geom::prefilter::candidates_observed`, `lvs::refine::refine_observed` and
`drc::record_run`. The private ones are unit tests inside their own crate;
`prefilter`'s seam is `pub`, so its tests sit in
`crates/geom/tests/derived/prefilter.rs` and can use `gpurify-testgen`, which
depends on `gpurify-geom` and so cannot reach a unit test there. The adapter
column above counts only the tests that name the seam itself as their oracle;
the rest are annotated construct-from-answer, because their fixtures state the
merge sequence, the round sequence or the violation count before the call.

`extract::field::matvec::ObserveMatVec` is the exception and has no test. The
trait exists and `NoObserve` implements it, but no function in the workspace
takes one, so there is nothing to install an adapter at. That is a signature
defect, not a coverage decision, and it is recorded in `NEED_TESTING.md`.

**Two of the three gates are met.** Coverage holds: every interface has a
definitive test or an entry in `NEED_TESTING.md` naming what is missing.
Determinism holds where a thread count exists — only `engine::run` takes one, so
that is the single place the two-thread-count clause is stated, and the other
crates substitute two OS threads and a reused output table. Mutation testing has
not run: `cargo mutants` needs bodies, so it belongs to the Implementation-Phase
and is the first thing to do once the suite goes green.
