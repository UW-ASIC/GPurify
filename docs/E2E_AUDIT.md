# End-to-end audit

> **`core::bulk` is gone.** Every reference below to `core::bulk`,
> `crates/core/src/bulk.rs`, `crates/core/tests/bulk_combinators.rs`, a
> *combinator*, or `references/bulk-combinators.md` names something that no
> longer exists: the module was inlined across all its call sites and deleted,
> and the bulk-loop rule is now enforced per site. See `docs/BULK_MEASUREMENTS.md`
> and `bulk-loops.md` in the project-libraries skill. This page is left as the
> record it was written as.

Sixty-three files were upgraded by isolated agents and two blockers were closed
in the same run. This audit re-ran the workspace gate first, because nothing
below any of those reports is worth reading until the gate is verified
independently of the agent that claims it.

The suite is **not** regressed. It is also not what its headline number says it
is: 45 of its 722 tests were authored by the same runs that wrote the bodies
they test, up from 29 at the last audit, and the fifteen that reach the pipeline
end to end sit on a fixture built so that four of the five things they claim to
check are constants.

Separately, the `ponytail:` sweep spent 203 of 268 markers. Thirteen of the 65
survivors are not performance ceilings at all. They are places where the code
computes a knowingly wrong answer, and four of them compound onto one rule in
the fail-open direction without any of the four comments naming another.

---

## The gate

```
$ cargo build --workspace 2>&1 | tail -10
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.04s

$ cargo test --workspace --no-fail-fast 2>&1 | grep -E '^test result' | awk ...
passed 721 failed 1 ignored 1

$ grep -rc 'ponytail:' --include='*.rs' crates | awk -F: '{s+=$2} END {print s}'
65
```

|  | passed | failed | ignored | `ponytail:` |
|---|---|---|---|---|
| baseline entering this run | 705 | 1 | — | 268 |
| now | **721** | **1** | 1 | **65** |

No regression. +16 passing, the same one failure, and 203 markers spent. The one
ignored is the pre-existing `crates/drc/src/rules/mod.rs` doctest. The one
failure is `tests/test_all.rs:103`, unchanged, and §4 says why closing the
blockers did not close it.

`cargo clippy` is not installed on this machine. No statement in this file is
backed by a clippy run.

The 268 baseline is not verifiable from git. `git grep -c 'ponytail:' HEAD` is
**12**; the other 256 arrived in the working tree with the bodies. Only the 65 is
measured.

---

## 1. Why the e2e suite is suspect

`tests/test_all.rs` and `tests/bench_all.rs` are the empty blob at the commit
that closed the Testing-Phase, and they are still the empty blob at `HEAD`:

```
$ git ls-tree -r 8bc3870 tests/ | grep -v fixtures
100644 blob e69de29bb2d1d6434b8b29ae775ad8c2e48c5391	tests/bench_all.rs
100644 blob e69de29bb2d1d6434b8b29ae775ad8c2e48c5391	tests/test_all.rs
$ git ls-tree -r HEAD tests/ | grep -v fixtures     # byte-identical
```

`e69de29` is git's empty blob. `tests/common/` and the `src/lib.rs` facade are
untracked. The entire end-to-end suite exists only as an uncommitted working-tree
diff, written during the Implementation-Phase beside the code it tests.

Two of its own claims are therefore false as written:

- `tests/test_all.rs` module doc — "Red until the Implementation-Phase … Every
  body outside `gpurify-testgen` is `todo!()`, so each test here panics." The
  file did not exist while that was true.
- `tests/test_all.rs:207`'s doc — "this test asserted the wrong stage until the
  Implementation-Phase." There was no earlier version. That is an invented
  revision history, attached to the one assertion that was tuned against a
  running implementation.

### The population split

`git grep -c '#\[test\]' 8bc3870` is **677**. The tree carries **722**. The 45
that did not exist when the Testing-Phase closed:

| file | at `8bc3870` | now |
|---|---:|---:|
| `tests/test_all.rs` | 0 | 11 |
| `tests/bench_all.rs` | 0 | 4 |
| `crates/core/src/boolean.rs` | 0 | 5 |
| `crates/core/tests/bulk_combinators.rs` | 0 | 4 |
| `crates/lvs/tests/terminal_order.rs` | 0 | 3 |
| `crates/pex/src/quasistatic/mesh.rs` | 0 | 3 |
| `crates/engine/tests/checks.rs` | 6 | 9 |
| `crates/lvs/src/refine.rs` | 5 | 7 |
| `crates/topology/src/net.rs` | 0 | 2 |
| `crates/derived/src/expr.rs` | 3 | 4 |
| `crates/engine/tests/pipeline.rs` | 6 | 7 |
| `crates/pex/tests/analytical.rs` | 18 | 19 |
| `crates/core/src/bulk.rs`, `crates/erc/src/power.rs`, `crates/erc/src/rules/antenna.rs`, `crates/ingest/src/intern.rs`, `crates/topology/src/port.rs` | 0 | 1 each |

**677 of 722 are blind-authored and carry the guarantee. 45 do not.** Sixteen of
those 45 were authored in *this* run: three by the blocker agent in
`crates/engine/tests/checks.rs`, thirteen by the `ponytail:` agents as unit tests
inside the files they had just folded. The agents were told never to edit a test
and did not; adding one is a different act and the instruction did not cover it.
It is not misconduct, and five of the thirteen —
`crates/core/src/boolean.rs`'s `a_union_conserves_area_against_its_intersection`
and its four siblings — are law tests on the strongest oracle in the project. But
they were written by the author of the body, and "721 passed" now reports two
populations rather than one.

`docs/TEST_AUDIT.md` read all 64 changed hunks across 23 files and found no bent
assertion. That finding stands and this audit does not revisit it. What follows
is about the 15 tests in `tests/`, which that audit could not read because it
diffed only files that *changed* and these two files never have.

---

## 2. What three clean-room reconstructions agreed and disagreed with

Three authors reconstructed the suite from the frozen artefact alone. On the
values, they corroborate the suspect suite completely.

### Agreed — 12 shared claims, 0 disagreements on any expected value

| claim | authority |
|---|---|
| min-width `at` is the shape centre | `check_min_width`: "reported at the narrowest one"; `crates/testgen/src/violation.rs:13` — "`at` is the midpoint of the thing being measured" |
| min-width `measured` is the minimum span | `narrowest_width`: "A rectangle gives `min(width, height)`" |
| `limit` is the deck's nm converted to `Dbu` | `crates/ingest/src/deck.rs:429` — "Lengths are **physical nanometres** and convert exactly or not at all" |
| `severity` on a DRC row is `Error` | assumed by all four authors; no frozen source states it. Corroborated as an assumption, not derived |
| a clean run is `Outcome::Ran` **and** `examined > 0` | `RuleRun::examined`: "'Clean' has to mean *this rule executed, examined N shapes, and found nothing*" |
| LVS selected with no reference is `StageStatus::Skipped(_)` | `Inputs::reference`: "Absent means LVS is skipped" |
| `Skipped` implies `!passed()` | `Summary::passed`: "A skipped rule is **not** a pass" |
| `NotSelected` everywhere implies `passed()` and `rules_skipped == 0` | same doc: "a caller … says so explicitly by not selecting the check" |
| 1 thread and 4 threads serialise to identical bytes, `timestamp: None` | `RunOptions::threads`; `docs/TESTING.md` gate 3 |
| `parse → write → parse` is the identity on the **store**, not the file | `gds::write_store`: "Round-tripping therefore returns the flattened store, not the original file" |
| the domain edge reachable through GDSII is `i32::MAX`, not `MAX_ABS_DBU` | the GDSII XY record is `i32`. This is the suspect suite's best test, and CR-3 reached it independently |
| an unknown rule kind is refused at `run_checks`, not at load | `crates/ingest/src/deck.rs` module doc: "`ingest` does not know what `min_width` means"; both `KINDS` arrays live above `ingest` |

Nothing is bent. Every number the suspect suite states is derivable from a doc
comment frozen before any body existed.

### Disagreed — 3, all about construction, none about a value

**D1 — the off-grid fixture is built so its assertion cannot fail.**
`tests/common/mod.rs:116` writes `"limit": { "nm": 300.5 }` on a 1 nm grid and
`tests/test_all.rs:226` matches `OffGrid(_, _)` with both fields wildcarded.
CR-2 t11 and CR-3 t15 both used an integer 47 nm on a 5 nm grid
(`dbu_per_um = 200`) and pinned the reported value.

Authority: the variant is `OffGrid(String, i64)`
(`crates/ingest/src/deck.rs:37`) and `crates/ingest/src/deck.rs:620` does
`let stated = nm as i64;`. So `300.5` is reported through the `Display` at
`crates/ingest/src/deck.rs:36`:

> `rule off-grid-rule: limit 300 nm is not an exact multiple of the grid`

300 **is** an exact multiple of a 1 nm grid. The message shown to a user is
false and sends them to the wrong number. Both wildcards mean the test cannot
see it. The clean-room construction — integer nm, coarse grid — makes the
message truthful and asserts it.

**D2 — `tests/test_all.rs:103` is wrong for the fixture it is attached to.**
`assert!(summary.rules_skipped > 0, "the intent-gated ERC rules cannot have
run")`, against a fixture whose `checks` is
`Checks { drc: true, erc: false, lvs: true, pex: false }`
(`tests/common/mod.rs:365`) and whose deck holds one DRC rule on a populated
layer.

Authority: `run_checks` folds `rules_skipped` out of `out.runs`. ERC is
`NotSelected` and contributes no rows; LVS contributes no `RuleRun` at all; the
one DRC rule `Ran`. `rules_skipped` is 0 by construction, and the stated
justification is false for this fixture. No clean-room author wrote this
assertion against this fixture.

**D3 — CR-2 filed as a defect what the suspect suite asserted as behaviour.**
The suspect suite expects `EngineError::Drc(DrcError::UnknownKind{..})` from
`run_checks`; CR-2 defect 7 recorded that the variant did not exist and the
fail-closed guarantee therefore stopped at the engine seam. Both read the
semantics identically. This run closed it — see §4 — so the disagreement is now
about which of the two was describing the tree at the time, and CR-2 was.

---

## 3. Coverage the suspect suite does not have

Nine subsystems are reached by no test in `tests/`. `grep -c` across
`tests/test_all.rs` and `tests/common/mod.rs` returns **0** for every one of
these: `reference: Some`, `intent: Some`, `Verdict`, `Provenance`, `SkipReason`,
`sort_canonical`, `unknown_layers`, `erc: true`, `pex: true`,
`engine::run::run`. The single hit for `spacing` is the word inside a doc
comment at `tests/test_all.rs:221`.

### Why the fixture cannot see what it claims to check

`tests/common/mod.rs:262` — "The deck every well-formed fixture uses: one layer,
one `min_width` rule." One layer, one rule, one polygon, one violation,
`dbu_per_um = 1000`. Consequences, each checkable:

- **One layer makes every `LayerId` assertion a constant.** `found.layer ==
  run.met1` is `LayerId(0) == LayerId(0)`. CR-1 t2 puts the narrow shape on
  `poly` and only wide shapes on `met1`, then asserts `expected.layer != met1`,
  so a mis-resolved lookup reports clean rather than passing.
- **`dbu_per_um = 1000` makes every grid conversion the identity.** 1 dbu = 1 nm,
  so `Length(300)` from `"nm": 300` holds whether or not `to_dbu` does anything.
  CR-2 and CR-3 both chose 200 dbu/µm deliberately; CR-3 t15 runs one deck at two
  grids and asserts `Dbu(200)` and `Dbu(40)`.
- **One violation gives the determinism gate zero ordering power.** Two runs of a
  one-row table are byte-identical under any sort. `sort_canonical` appears
  nowhere. CR-3 t11 files three rows in the order 30k/10k/20k and asserts `at.y`
  comes back ascending.
- **Every fixture is a rectangle**, the one shape class where the formula
  `crates/drc/src/rules/width.rs`'s module doc exists to condemn — "It is not
  exact for an L, a T or a comb, and every one of those is a real metal shape" —
  agrees with the correct facing-pair scan.
- **`Run::summary()` re-runs the whole pipeline.** `tests/common/mod.rs:193`
  calls `load`, `extract_into` and `run_checks` a second time and returns *that*
  `Summary`, cross-checking only the violation *count* against the run it was
  asked about. No test in the suite observes the `Summary` of the `Outputs` it
  asserts on.

### The twenty tests all three clean-room authors have and this suite does not

| # | missing test | written by | why it matters |
|---:|---|---|---|
| 1 | a spacing violation at a hand-computed gap midpoint | CR-1, CR-2, CR-3 | the only test all three wrote. `spacing.rs`: a wrongly-dropped pair "is never looked at again by anyone, and the rule reports clean. That is fail-open on a spacing rule." There is no spacing coverage here at all |
| 2 | a gap exactly at the limit is `Ran` and clean | CR-2, CR-3 | pins `Bbox::within`'s inclusive prune and `LimitSense::Minimum` at the boundary |
| 3 | a provenance permutation survives `finish` | CR-1, CR-3 | `ingest`: "Provenance columns … **must** be permuted to match, or a violation is reported against the wrong cell … it has no compiler behind it." The suspect module doc names "a permutation applied once too often" as its reason to exist, then never touches `Provenance` |
| 4 | deck names and layout names share one `StrId` space | CR-1, CR-3 | `Loaded`: "One `StrTable` for the whole run." `load_into` parses the deck twice into two tables and its own comment says so |
| 5 | a CSR range per declared layer, including an empty one | CR-1, CR-3 | `finish`: "`layer_count` comes from the deck, not from the geometry" |
| 6 | every reported point lies inside the shapes its row names | CR-1 | `Violation::at`: "Always inside or on the geometry the marker names" |
| 7 | a rule on a declared-but-empty layer is not silent | CR-1, CR-2 | `SkipReason::EmptyLayer` is constructed nowhere in the suite |
| 8 | a reused `Outputs` does not carry the previous run forward | CR-1, CR-2 | `crates/engine/src/run.rs:371-382` is "the one place" `out` and `runs` are cleared |
| 9 | the staged run and the one-call `run()` agree | CR-1 | `gpurify::engine::run::run` is called by no test in `tests/` |
| 10 | an unreadable or non-layout file is an error, never an empty clean result | CR-1, CR-2 | `ingest`: "an empty clean report is never allowed to mean 'we could not read this'" |
| 11 | a rule naming an undeclared layer fails the run | CR-1 | `LayerTable::id`: "A rule referencing one is a deck error, not a new layer" |
| 12 | geometry on an undeclared layer is refused | CR-3 | `Inputs::unknown_layers` was added during the Testing-Phase reopening for exactly this, and no test sets it |
| 13 | LVS `Ran` with a `Mismatch` verdict | CR-2 | CR-2 pinned it as a fail-open; this run closed it (§4) and nothing end to end verifies the closure |
| 14 | the summary counts reconcile with the run table | CR-1, CR-2 | `errors + warnings == violations`, `rules_clean == count(Ran && 0)`, `runs.len() == rule_count` |
| 15 | the serialised report names every rule that ran and carries the measurement | CR-1 | `json::Report`: "without it an empty violation list is ambiguous between 'clean' and 'nothing ran'" |
| 16 | determinism across a wall-clock second and a differently-named tmpdir | CR-3 | `export`: "Write no timestamp, hostname or absolute path into a body." The suspect `Header` hard-codes `"deck.json"`/`"layout.gds"`, so a real path leak is invisible |
| 17 | translation invariance of a verdict | CR-3 | `docs/TESTING.md`: "results are invariant under translation of every input". Catches an `f32`/`i32` coordinate at 2e9 |
| 18 | an area larger than `i64` is measured, not wrapped | CR-3 | the `i128`/`MAX_ABS_DBU` invariant `CLAUDE.md` names as load-bearing, untested end to end |
| 19 | two instances of a cell flatten to two shapes with distinct `PathId`s | CR-3 | `ingest::layout`: "Flattening happens here, during the read." No suspect fixture has hierarchy |
| 20 | one deck against two grids | CR-3 | every suspect fixture is 1 dbu = 1 nm |

The first three are the ones to add: all three authors wrote all three
independently.

---

## 4. The two blockers closed, and what they unblocked

**Blocker 1 — the shared `RuleTable`.** `crates/engine/src/run.rs:290`,
`reject_unknown_rule_kinds`, called from `crates/engine/src/run.rs:366` before
either rule set is built. It scans `gpurify_drc::ruleset::KINDS` (26 entries,
`crates/drc/src/ruleset.rs:911`) and `gpurify_erc::ruleset::KINDS` (19 entries,
`crates/erc/src/ruleset.rs:24`) and refuses a kind in neither. Each domain's
`from_deck` now steps over the other's rows instead of rejecting them.

Unblocked: one deck may hold a DRC rule and an ERC rule. Two new tests in
`crates/engine/tests/checks.rs` cover it, both green.

Cost, recorded and not hidden: both closing `debug_assert_eq!`s in the two
`from_deck`s were weakened to filter by `KINDS`, and
`crates/erc/tests/dispatch.rs`'s drift detector changed what it detects — the
`ErcError::UnknownKind` fail-closed assertion moved out of `erc` and onto
`run_checks`, while `crates/erc/src/lib.rs:90`'s doc comment still claims that
crate fails closed on it.

**Blocker 2 — an LVS mismatch was not an error.** `crates/engine/src/run.rs:702`
now maps every `Discrepancy` in a `Verdict::Mismatch` through
`record_discrepancies` (`crates/engine/src/run.rs:777`) into `out.violations`,
so a mismatch fails the run. One new test in `crates/engine/tests/checks.rs`,
green.

**Neither unblocked the red test.** `tests/test_all.rs:103` still fails on
`assert!(summary.rules_skipped > 0)` for the reason in D2: the parse-level
blocker is gone, but `tests/common/mod.rs` was written *around* it and has not
caught up. `deck_with_rule` emits one `min_width` rule and `build_with` hardcodes
`erc: false` at `tests/common/mod.rs:365`. No ERC rule is configured, so nothing
can be skipped. The module doc at `tests/common/mod.rs:13-20` still states the
retired "One domain per deck" restriction as fact.

**A new defect the fix introduced.** `"antenna"` is in *both* `KINDS` arrays —
`crates/drc/src/ruleset.rs:933` and `crates/erc/src/ruleset.rs:25` — and both
`from_deck`s build a table for it (`crates/drc/src/ruleset.rs:1118`,
`crates/erc/src/ruleset.rs:482`). With `drc: true, erc: true`, one deck row named
`antenna` runs twice and files two `RuleRun` rows under one rule id. The engine's
guard does not catch it: `append_stage` (`crates/engine/src/run.rs:481`) asserts
`runs.len() == rule_count` *per stage*, not per deck row. The one test that would
see it is `tests/test_all.rs:243`,
`every_rule_in_the_deck_appears_in_the_run_record_exactly_once`, and its fixture
is a single `min_width` rule.

---

## 5. Correctness gaps wearing a `ponytail:` label

Thirteen of the 65 survivors are not performance ceilings. The code computes a
knowingly wrong answer and the comment says so, which makes the shortcut read as
deliberate — a decision someone weighed — when what is actually recorded is a
defect nobody has costed. This is the most valuable thing this run found.

### 5.1 Four fail-opens compound onto electromigration, and none names another

`check_electromigration` (`crates/erc/src/rules/electrical.rs:765`) reads a
`Solved` power grid and an `operating_temperature`. Four separate `ponytail:`
comments, in three crates, each argue their own error is bounded. All four err in
the same direction, and the composition is stated nowhere:

| site | what it does | direction |
|---|---|---|
| `crates/engine/src/run.rs:170` | sign-off temperature is 85 °C, hard-coded. `sign_off_temperature()` at `:180` returns `celsius(85.0)`, wired at `:646` | "a part signed off at 125 °C derates less here than it should, so an electromigration limit reads more generous than the corner allows" — its own words |
| `crates/erc/src/rules/electrical.rs:741` | one temperature for the whole run, no thermal solve, no self-heating | "it errs *open*: a self-heated wire runs hotter than the applied point and so derates further than this computes, which passes branches a thermal solve would fail" — its own words |
| `crates/erc/src/power.rs:1091` | the current budget spreads uniformly over the rail's attach points; `extract_into` builds the `PowerGrid` the check reads (`crates/engine/src/run.rs:601`) | "makes a hot spot read cooler than it is wherever the real draw is concentrated" — its own words |
| `crates/erc/src/power.rs:1302` | the pad anchor is inferred as the first node of the rail's first shape, because `Connectivity` carries no pad marker | "under-reports drop near the true pad" — its own words |

Two of the four use the phrase *fail-open* about themselves. `docs/VOCABULARY.md`
names fail-open as "the defect class this project fears". Each comment argues
its own error is small; nothing states the product. A marginal net can pass an
electromigration check at a hotter corner, on a hotter wire, carrying a current
the model spread away from it, referenced to a pad that is not where the pad is.

This is not a body-writing decision. Three of the four are blocked on a frozen
signature and are filed in `docs/SIGNATURE_DEFECTS.md`. What is not filed
anywhere is that they land on the same rule.

### 5.2 The PEX quasi-static path is wrong on every real input

- **`crates/pex/src/quasistatic/matvec.rs:180`** — the square-panel shape factor
  applied to a rectangle. The comment states the error against the closed form
  below it: "low by 3.5% at 2:1, 12.5% at 4:1, 28% at 10:1 and 64% at 100:1",
  and "a sliver panel is not rare — the side face of a thin layer is
  (footprint × thickness)". It also records that the comment it replaced
  "claimed ~2% at 4:1 and that the error was inside the centroid kernel's; both
  are wrong." A `ponytail:` label was actively misinforming for the duration of
  the phase. This one was found and corrected by an agent doing its job; the
  point is that the label is not self-validating.
- **`crates/pex/src/quasistatic/matvec.rs:238`** — no layered-dielectric Green's
  function. `Mesh::epsilon` gives one permittivity per panel, so the image series
  a real stack needs is unreachable. Every real stack is layered.
- **`crates/pex/src/quasistatic.rs:376`** — the mesh resolution is chosen here
  because the frozen `extract_into` takes `solve::Options` and no `MeshOptions`.
  Half a micrometre of panel edge, no proximity refinement. "a process whose
  features sit far below half a micrometre is under-meshed" — every process this
  tool targets has features far below half a micrometre.

Three ceilings, none of which is reached only at the extreme; all three are
breached by ordinary input.

### 5.3 One PEX stage reports `Ran` for work it did not do

`crates/engine/src/run.rs:867` — a non-empty `quasistatic_nets` selection
produces the field-solved network for those nets *only*, and the analytical
network for every other net is not merged in. `pex` exposes no merge and
concatenating would break `ParasiticNetwork`'s contiguous-ascending node-order
invariant, which every writer scans on. The `CapMatrix` is dropped because
`Outputs` has no slot for it.

The stage still reports `Ran`. `RuleRun::examined`'s frozen doc is explicit that
"'Clean' has to mean *this rule executed, examined N shapes, and found
nothing*". "You did not ask for these nets" and "these nets have no parasitics"
are the same output. The comment names this itself as a second-order cost.

### 5.4 Two writers disagree about the same violation

`crates/cli/src/format.rs:155` — the CLI converts only `Measurement::Length` and
labels an area `dbu^2`, while `crates/export/src/json.rs:211` privately squares
the grid factor and emits `nm^2`. On any grid that is not 1 nm per unit, the same
area violation reads one number on the terminal and a different one in the JSON
report. The comment states that the drift its predecessor was written to prevent
already exists. Blocked on `Grid::to_area` in `gpurify-units`, which does not
exist.

`crates/cli/src/format.rs:132` — an LVS verdict prints through `Debug` because
`gpurify-lvs` is not a dependency of `gpurify-cli` and `gpurify_engine`
re-exports `Outputs` without `Verdict`. `Debug` reaches every discrepancy and
stops at `StrId(7)`: a human reading a mismatch on the terminal is shown
integers where the model, net and parameter names should be.

### 5.5 Two others

- **`crates/drc/src/rules/antenna.rs:842`** — the per-stage connectivity rebuild
  this rule's own doc describes is unreachable: `Design` carries a store, an
  `Evaluator`, a `NetTable` and a `DeviceTable` and no bridge to the deck's
  `Connectivity`. Every fabrication stage reads the *final* net partition. This
  one errs **closed** — it over-reports the ratio and never under-reports — and
  is the only correctness gap in the thirteen that does.
- **`crates/core/src/bbox.rs:226`** — `Bbox::width()` on a domain-spanning box is
  `2^41`, one bit past the `debug_assert!(in_domain(raw))` inside
  `Dbu::new_unchecked` (`crates/units/src/dbu.rs:74`). The comment states that
  `Bbox::EMPTY.width()` is already past it, so a public const of the type panics
  its own accessor in a debug build. No test calls it —
  `grep -rn 'EMPTY.width' crates` returns only the comment.

  A second agent reached the same defect from the other side, in another crate:
  `Dbu::mul_wide` asserts `in_domain` on both *operands*
  (`crates/units/src/dbu.rs:98-99`) while `Dbu::Add`/`Sub` are documented as
  legally producing results outside `±MAX_ABS_DBU`. `Bbox::area`
  (`crates/core/src/bbox.rs:247`) routes around `mul_wide` deliberately and says
  why, so the area path is safe. Two isolated agents, two crates, one boundary,
  neither able to close it from where it stood. This is the invariant `CLAUDE.md`
  names as load-bearing.

---

## 6. The `ponytail:` sweep — the other three cases

268 → 65. Five of the 65 are not markers at all but prose citing the pass by name
in a `docs/SIGNATURE_DEFECTS.md` cross-reference —
`crates/core/src/bulk.rs:150`, `crates/lvs/src/graph.rs:233` and `:477`,
`crates/erc/src/facts.rs:423` and `:486`. Sixty real markers survive:

| case | count | what it means |
|---|---:|---|
| **1 — an absent `core::bulk` shape** | 29 | scatter-accumulate, segmented reduce, payload-carrying compact, two-column map, scan, segmented gather. The upgrade is an entry point in `crates/core/src/bulk.rs`, decided there against every segmented caller at once |
| **2 — a chain** | 5 | loop-carried dependence, the `/simd-loops` triage blocker. Two are marked permanent |
| **3 — a correctness gap** | 13 | §5 |
| **4 — a frozen signature or an absent dependency** | 13 | no scratch parameter, no column, no re-export, no `rayon`, no Vulkan device |

**Case 1 (29).** `crates/core/src/index.rs:270` and `:556`;
`crates/core/src/bbox.rs:302`; `crates/core/src/store.rs:248`;
`crates/core/src/boolean.rs` ×9 at `:426, :461, :539, :579, :627, :653, :697,
:745, :997`; `crates/ingest/src/provenance.rs:245`;
`crates/drc/src/rules/antenna.rs` ×6 at `:211, :355, :432, :503, :533, :616`;
`crates/drc/src/rules/area.rs:261` and `:695`;
`crates/drc/src/rules/overlay.rs:515` and `:933`;
`crates/drc/src/rules/width.rs:682` and `:800`;
`crates/erc/src/rules/antenna.rs:252`; `crates/pex/src/reduce.rs:218` and `:493`.

Two of these are marked as shapes `core::bulk` states it will **never** wrap
rather than does not have yet — `crates/core/src/index.rs:270` and
`crates/drc/src/rules/antenna.rs:355`, both scatter-accumulate. The other 27 are
absent-for-now, and 21 of them want two combinators: a segmented reduce and a
payload-carrying compact. That is the highest-leverage two functions in the
workspace right now, and both are one file.

**Case 2 (5).** `crates/core/src/connectivity.rs:109` and `:153` (union-find,
both permanent); `crates/core/src/boolean.rs:504` (two-cursor merge) and `:899`
(boundary following); `crates/core/src/view.rs:448` (early `Err` return —
`compact_into`'s predicate would have to panic to fail closed, which the callback
contract bans).

**Case 4 (13).** `crates/core/src/index.rs:465`;
`crates/topology/src/net.rs:279`, `:669`, `:721`; `crates/drc/src/lib.rs:127`;
`crates/drc/src/rules/patterning.rs:206`; `crates/drc/src/rules/width.rs:463`;
`crates/erc/src/rules/electrical.rs:338`; `crates/erc/src/power.rs:475`;
`crates/export/src/netlist.rs:138`;
`crates/pex/src/quasistatic/matvec.rs:94`; `crates/pex/src/quasistatic/solve.rs:348`;
`crates/pex/src/quasistatic/gpu.rs:67`.

Eight of the thirteen are the same shape: a transform allocates scratch per call
because its frozen signature has nowhere to hang a reusable buffer.
`crates/pex/src/quasistatic/solve.rs:348` is the odd one — it is not a shortcut
at all but an argument that restarted GMRES already *is* the refinement loop, so
a second outer loop would recompute the same residual. Keeping a `ponytail:`
marker on a refutation makes the grep-ledger read one entry worse than the tree
is.

**The grep is not a complete ledger.** Multiple agents reported raw bulk loops
whose exemption is written as plain prose without the token — nine in
`gpurify-core` alone (`ops.rs:314`, `:335`; `store.rs:211`, `:217`, `:228`;
`view.rs:340`, `:407`, `:478`; `rects.rs:137`, `:177`, `:185`;
`boolean.rs:781`, `:799`; `connectivity.rs:76`), three in `gpurify-drc`
(`via.rs:176`, `:205`; `spacing.rs:487`), one in `gpurify-engine`
(`run.rs:779`). `grep -c 'ponytail:'` undercounts the exemptions and overcounts
the debt, in opposite directions, and nobody has reconciled the two.

---

## 7. Still open

1. **`tests/test_all.rs:103` is red and the fixture is what is wrong.** Not a
   3-line change: `tests/common/mod.rs` is shared by all eleven tests in the
   file, so `only_violation`'s exactly-one count, `deck_rule_ids` and the byte
   comparison in `two_runs_at_two_thread_counts_serialise_to_identical_bytes` all
   move with it. The module doc at `tests/common/mod.rs:13-20` also still states
   the retired restriction as fact.
2. **The `"antenna"` collision between the two `KINDS` arrays** (§4). One deck
   row, two rule sets, two `RuleRun` rows, no assert that fires.
3. **The four-way electromigration fail-open** (§5.1). Three of the four are
   filed individually in `docs/SIGNATURE_DEFECTS.md`; the composition is filed
   nowhere.
4. **The three PEX quasi-static correctness ceilings** (§5.2) are breached by
   ordinary input, not by an extreme one. `docs/NEED_TESTING.md` should say so
   next to the capacitance laws that currently pass around them.
5. **`crates/erc/src/lib.rs:90`'s `ErcError::UnknownKind` doc is stale** after
   blocker 1 moved the assertion to `run_checks` — or the fail-closed check was
   dropped in the move. One grep in `engine` settles it.
6. **Twenty missing end-to-end tests** (§3). The first three — spacing midpoint,
   provenance permutation, one `StrTable` — were written independently by all
   three clean-room authors.
7. **The `ponytail:` grep-ledger does not reconcile** with the raw-loop
   exemptions (§6).
8. **45 of 722 tests are not blind-authored**, sixteen of them from this run.
   `docs/TESTING.md`'s table still reports 678 as one population.
9. **`cargo clippy` is not installed.** `CONVENTIONS.md §7` gates every change on
   a clippy run that has never happened on this machine.
