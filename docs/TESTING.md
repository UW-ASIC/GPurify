# Testing strategy

The rewrite in `crates_clean/` is gated on this. It exists because the original
suite did not catch logic changes, which is the only thing a test suite is for.

---

## What was wrong with the original suite

Measured, not guessed:

| suite | cases | assert only "nothing found" | check any measured value |
|---|---|---|---|
| drc | 94 | 45 (48%) | 30 (32%) |
| erc | 23 | 10 | **0** |
| lvs | 16 | — | **0** |
| pex | 27 | — | **0** |

- **ERC/LVS/PEX conformance compared counts and statuses only.** A rule that
  flags the wrong shape, at the wrong coordinate, with the wrong measurement
  passes as long as it flags the right *number* of them.
- **Half the DRC corpus asserts absence.** A rule that never fires passes all 45.
- **Tautology tests** — `assert_eq!(FACTORIES.len(), 19)`,
  `assert_eq!(cases.len(), 94)` — break whenever anything is added and catch no
  logic error ever. They measure the manifest, not the code.
- The one real check (`measured`) was a **subset** test, and was skipped
  entirely for the 64 cases whose manifest entry omits values.

---

## The four layers

### 1. Golden reports — the refactoring oracle

All four report types derive `Serialize`, and reports sort into a canonical
order before emission. So the whole report — every violation, its rule, layer,
coordinates, measurement, limit and marker geometry — is snapshotted per fixture
into `tests/golden/<suite>/<case>.json`.

Generated from the **original** `crates/` implementation, these are what
`crates_clean/` must reproduce byte for byte.

> **This layer freezes bugs, by design.**
>
> A golden proves the rewrite *changed nothing*. It cannot prove the original
> was right — where the original is wrong, the golden is wrong in exactly the
> same way, and the rewrite is required to reproduce the error.
>
> That is the correct tool for verifying a behaviour-preserving rewrite, and the
> wrong tool for finding bugs. It is why layers 2 and 3 exist. Any intentional
> divergence must be recorded in `tests/golden/DIVERGENCES.md` with the reason,
> so an updated golden is never confused with a silent regression.

### 2. Property tests — the correctness oracle

Invariants that must hold for *any* input, independent of both implementations.
These are the layer that can find a bug the original also had. Deterministic
generator, seeded, no new dependency.

Geometry and booleans:

- `(a − b) ∪ (a ∩ b) == a`
- `a ∩ b ⊆ a` and `a ∪ b ⊇ a`
- union/intersection are commutative; self-union is idempotent
- `area(a ∪ b) + area(a ∩ b) == area(a) + area(b)`
- ring winding and signed area agree in sign; a validated ring is simple
- decomposition is coordinate-independent under translation

Parsers:

- GDS/OASIS parse → write → parse is the identity on the store
- every fixture in the corpus round-trips

### 3. Differential — old vs new, and vs KLayout

- **Old vs new:** both trees run the same 160 fixtures; reports are diffed.
  Two separate processes comparing JSON, so `crates_clean/` keeps the original
  package names and swaps in without renaming.
- **vs KLayout:** `tests/fixtures/klayout/drc_oracle.rb` is an *independent*
  correctness reference for the directly equivalent native DRC operations —
  the one oracle not derived from our own code.

### 4. Mutation score — the acceptance gate

The others are inputs; this is the measurement. `cargo mutants` rewrites the
logic and checks whether anything fails. It answers the actual question —
*does a logic change break a test?* — with a number instead of a feeling.

`cargo-mutants` is provided by the dev shell (`flake.nix`), so run it as
`nix develop -c cargo mutants ...`.

**Scope it — a full-workspace run is not viable.** The workspace generates
**12,830 mutants** (core 3636, pex 4246, lvs 2774, drc 1718, erc 456). At the
cost of one workspace test run each that is over 20 hours even at `-j16`. So
mutation testing is used **per file, on the code actually being changed**, not
as a nightly whole-tree number:

```sh
nix develop -c cargo mutants -f crates_clean/core/src/geometry/bbox.rs
```

**Gate:** a surviving mutant is a missing test. A module is not done while a
mutation to its logic survives. Record each module's score in
`tests/golden/MUTATION_BASELINE.md` as it is rewritten, so the direction of
travel stays visible without ever needing the full-tree run.

### What the first probe measured

A hand-probe of the original tree scored **5/6 caught** in core and DRC —
inverting `Ring::winding` broke 31 tests, flipping `MinWidth`'s comparison broke
1, an `isqrt` off-by-one broke 3. The core geometry and DRC paths are better
covered than the manifest table above suggests.

One mutant was correctly **discarded as provably equivalent** rather than
recorded as a survivor: in `rectilinear_occupancy`, `ylo*2 < cy2` → `<=` is
unreachable because `cy2` falls strictly between two grid lines. Equivalent
mutants must be identified and excluded, or the score lies.

The one genuine survivor, and the first thing to fix:

> **`Bbox::within` / `Bbox::overlaps` (`geometry/bbox.rs:71`) is effectively
> untested.** Making the proximity test strict on one axis — "touch or overlap"
> becoming "strictly overlap", shifting every spacing prune by one DBU —
> produced **zero failures across all 403 tests.**

It is invisible because every consumer re-verifies exactly afterwards, so a
wrong prune costs correctness margin silently rather than failing. It feeds
`candidate_pairs`, DRC spacing pruning, LVS connectivity and PEX overlap.

**ERC, LVS and PEX were never probed** — and those are the suites that assert
counts and aggregate sums only. Their true coverage is unmeasured, and should
not be assumed to resemble DRC's.

---

## Order of work

Tests lead. A rewrite verified by a suite that does not catch logic changes is
a green checkmark that means nothing.

1. Goldens generated from `crates/` (layer 1) — the oracle to rewrite against.
2. Property tests (layer 2) — these run against *both* trees.
3. Mutation baseline (layer 4) — records where the original is untested.
4. Then, and only then, `crates_clean/` per crate, in dependency order
   `backend → core → pex → lvs → {drc, erc} → engine`, each gated on layers 1–4.
