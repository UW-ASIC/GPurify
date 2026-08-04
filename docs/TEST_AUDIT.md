# Implementation-Phase test audit

> **`core::bulk` is gone.** Every reference below to `core::bulk`,
> `crates/core/src/bulk.rs`, `crates/core/tests/bulk_combinators.rs`, a
> *combinator*, or `references/bulk-combinators.md` names something that no
> longer exists: the module was inlined across all its call sites and deleted,
> and the bulk-loop rule is now enforced per site. See `docs/BULK_MEASUREMENTS.md`
> and `bulk-loops.md` in the project-libraries skill. This page is left as the
> record it was written as.

The Testing-Phase wrote 677 tests against frozen signatures while every body was
`todo!()`, so no inherited test could have been shaped by an implementation.
That is the whole epistemic value of the suite, and the Implementation-Phase —
96 agents, 422 bodies — is exactly the pressure that destroys it. This audit
diffed every test file in the workspace against `8bc3870`, the commit that
closed the Testing-Phase, and read all 64 changed hunks across 23 files against
the frozen doc that each one claims as its authority. **No assertion was bent.**
Every changed expected value is either forced by a signature that moved during
the Definition-reopening and is recorded as `RESOLVED` in
`docs/SIGNATURE_DEFECTS.md`, or is a correction toward a document that was
frozen before any body existed and was not touched afterwards. The single
strongest piece of evidence is negative: `crates/testgen/src/violation.rs` — the
module that claims authority over every reported coordinate in as many words at
`:13`, "**`at` is the midpoint of the thing being measured**" — is byte-identical
to its Testing-Phase state, and all nine DRC coordinate edits move *toward* it.
Had the suite been bent, that file is what would have moved, because it is
cheaper to edit one sentence than nine tests. It did not. What the audit did
find is three things the per-file pass could not see, because it looked only at
files that *changed*: 29 tests that did not exist at all when the phase began,
one of the two remaining oracles edited, and a new public module behind the
bulk-loop rule.

---

## Findings

None of the three is a bent assertion. Each is a gap in what the suite's headline
number means.

**1 — 29 of the 706 tests were authored in the Implementation-Phase, after the
bodies existed.** `8bc3870` carries 677 `#[test]` markers; the tree carries 706.
The 29 break down as: `tests/test_all.rs` (11) and `tests/bench_all.rs` (4),
both of which were **empty files** at `8bc3870`; `crates/lvs/tests/terminal_order.rs`
(3) and `crates/core/tests/bulk_combinators.rs` (4), both new files;
`crates/lvs/src/refine.rs` (2), `crates/topology/src/net.rs` (1),
`crates/topology/src/port.rs` (1) and `crates/core/src/bulk.rs` (1), unit tests
for constructors that did not exist to be tested; and one each in
`crates/engine/tests/pipeline.rs` and `crates/pex/tests/analytical.rs`. Each is
individually defensible — the four constructor tests cover signatures added by a
recorded resolution, and
`analytical.rs:130` states `1.7 × 36 + 0.4 × 26 = 71.6 aF` from the doc'd formula
and nothing else — but they carry none of the guarantee the other 677 do, and
"705 passed" reports one population. The right thing is to count them
separately in `docs/TESTING.md`, not to delete them.

**2 — the one red test is one of the 29, so every inherited test is green.**
`tests/test_all.rs:103`, `a_run_missing_its_optional_inputs_reports_skipped_and_does_not_pass`,
fails on `rules_skipped > 0`. It is an Implementation-Phase test in a file that
was empty at `8bc3870`. 677 of 677 inherited tests pass. That is the expected
outcome of a correct phase and it is also the expected outcome of a bent one, so
it is not evidence either way — which is worth writing down, because a single
surviving failure reads like proof of honesty and here it is not.

**3 — an oracle moved: `crates/testgen/src/scale.rs:151-152`.** The scale corpus
is both the benchmark input and the oracle (`:1-9`), and Phase 4 changed the
block side from `(fingers + 1) * FINGER_PITCH` to the `max` of that and
`bands * BAND_PITCH`. This is the only change in the workspace that moves a test's
*input* rather than its expected value, and it shifts the geometry under every
`scale_corpus` test in `pex`, `drc/tests/determinism.rs` and `tests/bench_all.rs`.
It is legitimate: the module doc at `:14-16` promises "no two nets share a
polygon and **none of them touch**", and the frozen expression does not deliver
it. At 1000 polygons over 62 nets at depth 2 the numbers are `fingers = 7`,
`block_side = 8 × 400 = 3200`, `blocks = 4`, `bands = ceil(62/4) = 16`, vertical
extent `16 × 1000 = 16000` — five times the block side, so bands spill into the
block above and a cut bridges two combs. That is arithmetic against the frozen
doc, not against an implementation, and the failure direction is *fewer* nets,
which is fail-open for anything that trusts the partition. It still deserves a
second reader, because a corpus edit is the one change that can make a whole
crate's tests agree with a wrong body without any test file being touched.

**Adjacent, not a finding:** `crates/core/src/bulk.rs` is a new public module.
The bulk-loop rule in `CLAUDE.md` mandates `gpurify-core::bulk` and
`.claude/skills/project-libraries/references/bulk-combinators.md` documents it as
version 0.1.0, but no such module existed at signature freeze. Signatures were
added, not changed; `crates/core/tests/bulk_combinators.rs` is the caller-side
test for it and could not have been written earlier.

---

## Flagged and then refuted

Every hunk below was read as a candidate bent assertion and survives only
because the evidence against it is independent of the implementation.

- **The nine DRC coordinate edits** — `width_rules.rs:204`, `spacing_rules.rs:515`,
  `overlay_rules.rs:82`, `area_rules.rs:214`, `area_rules.rs:412`, `:482`, `:513`.
  Refuted by `docs/SIGNATURE_DEFECTS.md` at `8bc3870:255-268`, which tabulated
  all five conflicts between the rule docs and `testgen::violation` *before* any
  body existed and stated "the suite follows testgen, since it is the designated
  authority". `crates/testgen/src/violation.rs` is unchanged; the rule docs moved
  to it (`crates/drc/src/rules/mod.rs:58-72`).
- **`check_density` at `(1000, 1000)` rather than `(500, 500)`** — the window spans
  `[500, 1500]` on both axes, so the centre is `(1000, 1000)`. Arithmetic.
- **`check_asymmetric_enclosure` at `(230, 150)` rather than `(100, 100)`** —
  pre-registered as an open coordinate in `docs/NEED_TESTING.md@8bc3870:657-658`.
  Inner `(100,100)-(200,200)`, outer `(60,0)-(260,300)`; margins 40 left, 60
  right, 100 both vertical; worst axis is x, its better side is the right strip
  `x ∈ [200,260], y ∈ [100,200]`, midpoint `(230, 150)`. Arithmetic, and the old
  value was the inner shape's lower-left corner, which the frozen authority
  forbids.
- **`ops_predicates.rs:347` moving `isqrt(n² + 1)` inside `n > 0`** — at `n = 0`
  the value is `isqrt(1)`, which is `1`, not `0`. The old assertion was
  arithmetically false and would fail against any correct body.
- **`erc/tests/topological_rules.rs:220` reordering a fixture's terminals** — the
  only edit that moves a test's *input*. `DeviceSpec::terminals` is documented at
  `crates/testgen/src/netlist.rs:49-51` as "in the order the recogniser will
  report them", and `docs/SIGNATURE_DEFECTS.md@8bc3870:199-201` fixes that order
  as "Mos = Gate, Source, Drain, Bulk". The old fixture wrote `(Drain, 2)` in
  slot 1, which is Source, so it put the shared net on a source while asserting
  a drain contention. Self-contradictory before any body existed.
- **`erc/tests/supply_rules.rs:73` widening `via_cut` to one row per join** —
  `crates/engine/src/pipeline.rs@8bc3870:239-243` already carried the
  `debug_assert` that the two columns arrive in step. The old fixture was an
  input that panics, not an expectation.
- **`engine/tests/pipeline.rs:54` narrowing `Deck(_) | NoGrid` to `Deck(_)`** — a
  strengthening. `LoadError::NoGrid` was unreachable at `8bc3870:447` and the
  resolution that made it reachable also gained it its own test at `:63`.
- **The `..Default::default()` additions** — `engine/tests/checks.rs:77`,
  `ingest/tests/netlist.rs:64`, `lvs/tests/graph.rs:253`. Forced by `Netlist`
  gaining instance columns, a defect filed at `8bc3870:133`.
- **`lvs/tests/common/mod.rs:476` flipping `DuplicateName`'s side** — forced by
  the variant gaining `side: Side`, filed at `docs/NEED_TESTING.md@8bc3870:998-1005`.
- **Every `grid()` / `operating_temperature()` / `stack()` argument added across
  `pex` and `erc`** — mechanical, from three resolutions filed at
  `8bc3870:25`, `:302` and `:308`. No expected value changed with them; the pex
  laws still hold at the same tolerances.
- **`EmCurrentDensityTable::max_current_per_cut`** — from the resolution of a
  dimensionally wrong via edge, `docs/SIGNATURE_DEFECTS.md:412`.
- **`crates/lvs/tests/terminal_order.rs` in its entirety** — a new file, so it
  proves nothing about the bodies, but it is not a test built to fit one. It
  covers a blind spot named at `8bc3870:367-372` ("asserts the MOS role *set*
  rather than the order ... not a transposed drain and source"), its expected
  answer is `Verdict::Match` before anything runs, its third case is a negative
  control, and the frozen `Discrepancy::TerminalMismatch` carries a `role` and
  no slot index (`crates/lvs/src/verdict.rs:44-48`) — so matching by role rather
  than by slot is what the frozen type already said.
- **The three doc-comment-only rewrites** — `core/tests/boolean_laws.rs:7-19`,
  `store_layout.rs:210`, `pex/tests/analytical.rs:7`. No assertion changed in any
  of them; each retires a "this cannot be expressed" note that a resolution made
  false. `store_layout.rs` now documents that its assertion is *weaker* than the
  contract rather than at odds with it, which is the honest reading.
- **`check_angle` was left alone.** The suite follows testgen on `at` and the
  rule doc on `measured`, an asymmetry recorded at `8bc3870:270-277`. A blanket
  "make the tests agree with the code" pass would have flattened it. It survives.

---

## Files judged clean

All 23 files carrying test edits, all 64 hunks:

`crates/core/tests/boolean_laws.rs`, `crates/core/tests/ops_predicates.rs`,
`crates/core/tests/store_layout.rs`, `crates/core/tests/bulk_combinators.rs`,
`crates/drc/tests/area_rules.rs`, `crates/drc/tests/overlay_rules.rs`,
`crates/drc/tests/spacing_rules.rs`, `crates/drc/tests/width_rules.rs`,
`crates/engine/tests/checks.rs`, `crates/engine/tests/pipeline.rs`,
`crates/erc/tests/common/mod.rs`, `crates/erc/tests/dispatch.rs`,
`crates/erc/tests/electrical_limits.rs`, `crates/erc/tests/intent_gate.rs`,
`crates/erc/tests/supply_rules.rs`, `crates/erc/tests/topological_rules.rs`,
`crates/ingest/tests/netlist.rs`, `crates/lvs/tests/common/mod.rs`,
`crates/lvs/tests/graph.rs`, `crates/lvs/tests/terminal_order.rs`,
`crates/pex/tests/analytical.rs`, `crates/pex/tests/common/mod.rs`,
`crates/pex/tests/quasistatic.rs`.

No assertion was deleted without a replacement. No tolerance was loosened. No
`#[ignore]` was added.
