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

This is where `tools/`'s seeded scale generator earns its keep twice: it is the
benchmark corpus and the oracle, so there is one tool rather than two.

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
