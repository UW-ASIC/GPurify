# Correctness map

What the suite cannot see, and what would close it. Produced by a 64-agent
workflow (~4.2M tokens) plus a partial `cargo-mutants` sweep. The workflow's own
synthesis step died on a session limit; this document was reassembled from its
journal, and the coverage numbers in it were **re-derived by hand after an agent
caught the first version being wrong**. See "Errors in the first pass" below —
they are recorded because the method that produced them is the method a reader
would otherwise repeat.

## 1. Why this exists

`cargo-mutants` mutates code that exists. A missing case produces **zero
mutants**, and a wrong algorithm produces mutants that die against tests
asserting the wrong answer. It measures test tightness against the current
implementation — necessary, not sufficient.

The partial sweep bears this out. `units` came back 96% caught; the one real
find was `prefix::FEMTO`/`PICO` surviving a deleted minus sign, because every
test touching them was a round-trip (sign-cancelling) or a letter lookup. That
is a *test* defect. The constant was always right. Every genuine *correctness*
finding this project has ever had — the 3 DRC disagreements, F1–F13, the 13
known-wrong extraction sites, the mirrored-SREF winding bug — came from
physics-derived expectations instead.

Measured sweep results, before it was stopped (OOM, `-j 12` over-subscribed):

| crate | mutants tested | missed | rate |
|---|---|---|---|
| `units` | 124 | 5 → 3 after fix | 4% |
| `drc` | 967 of 1181 | 200 | 20.7% |

## 2. Rule-kind coverage (corrected)

Measured through the real join: manifest/expectations `rule`/`check` →
`tests/common/mod.rs::deck_rule_of` → `params.json` row → `kind`. Both
`manifest.json` and `expectations.json` agree.

- **DRC: 0 of 24 kinds uncovered.** Every kind has 2–10 cases.
- **ERC: 5 of 18 were uncovered** — `density_cmp`, `electromigration`,
  `esd_latchup`, `ir_drop`, `reliability`. **Now 4 of 18**: `density_cmp` is
  covered (2 cases, both `Ran`), and the other four have deck rows, harness arms
  and one corpus case each that asserts `Skipped(NoDesignIntent)` — accounted
  for, not covered. §3 has the detail.

The corpus is **167** cases (drc 94 / erc 30 / pex 27 / lvs 16), up from 160.
The newest is `ERC_EMIG_DEV` on `ERC_EM_DEV`, the first corpus cell to draw a
`licon` — see §3's fifth fail-open, which it exists to make coverable.

`layer_validity` is the only manifest label mapping to no deck row, and
`deck_rule_of` returns `None` for it deliberately — it is a validity check, not
a deck rule.

### Errors in the first pass

The first coverage table claimed **9** uncovered kinds. Four were wrong, all
from the same mistake: matching manifest `rule` strings *literally* against the
`KINDS` tables, which are different namespaces.

| claimed uncovered | actually |
|---|---|
| DRC `density` | 7 cases, spelled `min_density` (4) + `max_density` (3) |
| ERC `antenna` | 2 cases |
| ERC `esd_topological` | 2 cases |
| ERC `hv_domain` | 2 cases |

A subagent caught this and reported it as `premise-error` rather than answering
the question it was given. That is the workflow earning its cost.

## 3. The finding that matters most — **resolved, and the diagnosis was wrong twice**

**Four of the five uncovered kinds could not produce a verdict, and the gate was
one line in the harness, not a missing fixture.**

`case_inputs` hardcoded `intent: None` for every corpus case, so
`IntentMap::declared` was false and the six intent-gated ERC rules —
`check_ir_drop`, `check_em_current_density`, `check_electromigration`
(`electrical.rs:320, 694, 868`), `check_reliability`, `check_hv_domain`,
`check_esd_latchup` (`reliability.rs:211, 386, 529`) — recorded
`Skipped(NoDesignIntent)` no matter what was on disk. Adding a design intent
file to `tests/fixtures/` would have changed nothing. That was F9's real shape:
filed as a missing fixture, actually a hardcoded harness constant.

**Unhooked.** `case_inputs` now takes `intent: Option<PathBuf>` and
`tests/common/mod.rs::run_case_with_intent` supplies one, written to a scratch
file so intent reaches the engine through the same `read_intent` a user's run
uses. `run_case` still passes `None`, so all 166 corpus cases are byte-for-byte
the run they were. The proof is
`a_corpus_case_with_design_intent_reaches_an_intent_gated_rule`
(`tests/test_all.rs`, green): the same cell, the same pipeline, `hv_domain`
`Skipped(NoDesignIntent)` without an intent file and `Ran` with one. Both halves
are load-bearing — asserting only `Ran` would also pass against a harness that
had deleted the gate, and `check_hv_domain`'s own doc says an undeclared design
reads clean.

Deck rows and `deck_rule_of` arms now exist for **all five** kinds
(`met1.density_cmp`, `met1.electromigration`, `esd_latchup`, `ir_drop`, `bti`),
and six corpus cases name them.

| kind | reachable | state today |
|---|---|---|
| `density_cmp` | **covered** | 2 cases, both `Ran` and green: `ERC_DENSITY_CMP_PASS` (0 violations, examined 2) and `ERC_DENSITY_CMP_FAIL` (10 violations, examined 6, every `measured`/`at`/`layer` asserted) |
| `electromigration` | **covered**, on a second cell | two corpus cases assert `Skipped`. `black_and_blech_decide_a_met1_rail_that_carries_a_device_terminal` is the coverage: `ERC_EM_DEV`, the corpus's first drawn `licon`, at 1000 / 500 / 1.0 µA — `examined 1` with one violation of `Current(1000.0)` against `Current(670.4133044734676)` at `(650,100)`, `examined 1` clean, and `examined 0` Blech-exempt. The fifth fail-open on `ERC_EM` is **closed**, not pinned: `a_discarded_current_budget_refuses_the_rules_that_read_a_branch_current` asserts `Refused`, and `a_terminal_less_rail_with_no_stated_budget_still_reaches_a_verdict` is the false side |
| `esd_latchup` | **covered** | corpus case asserts `Skipped`; `an_unclamped_pad_and_an_undersized_guard_ring_are_both_found_on_the_same_cell` asserts examined 2 and both violations in full. The pad half is the empty-clamp *ceiling*, not a physics claim |
| `ir_drop` | **covered** | corpus case asserts `Skipped`; `a_stated_current_budget_drops_ohms_law_across_a_known_poly_rail` asserts 241.0 mV at `(225,100)` over three runs — firing, zero-current, and slack-limit |
| `reliability` | **covered** | corpus case asserts `Skipped`; `the_reliability_model_derates_a_cool_part_upward_and_an_overstressed_one_below_its_floor` asserts both Arrhenius halves, 5091.597 h and 450.701 h |

**Ran paths are now written** (`tests/test_all.rs`, all green, +4 tests). Each
runs the same cell as its corpus case through `run_case_with_intent`, so the pair
is load-bearing: the corpus half proves the gate still closes without intent, the
ran half proves the rule computes the right answer with it. `measurement_matches`
in `tests/common/mod.rs` gained `Voltage`/`Current`/`Resistance` arms — its
`_ => false` fallthrough is fail-closed and was kept.

**A FIFTH fail-open was found writing them, and it is not one of the four
magnitude fail-opens.** Two blind derivations of `ERC_EMIG_MET1` disagreed — prior said
`examined == 1`, independent said `examined == 0` — and the code sided with the
independent one. `crates/erc/src/power.rs:1612` does
`if attach.is_empty() { continue; }` *above* the first read of
`budget_current_ua`, and `attach` comes from `devices_on(net)`, which is
terminal-based. A rail fed from off-chip through a pad — the ordinary shape of a
supply rail — has no device terminal, so its declared budget is silently
discarded and `check_electromigration` reports `Ran` having examined nothing.
Unlike the other four this discards the input rather than biasing it, and
`Ran` with `examined: 0` is indistinguishable from a rule with nothing in scope.
**It is now fixed, body-only, and both of the original diagnoses were wrong.**
`power::discarded_budget` detects it exactly — a net declaring a non-zero
`budget_current_ua` whose `node_load` column sums to `0.0` — and `check_ir_drop`,
`check_em_current_density` and `check_electromigration` return `Outcome::Refused`,
a variant that already existed and already meant this. No `Connectivity` pad
marker was needed: a pad names where current *enters*, and every branch current
is set by where it *leaves*. No numeric fix is correct either — injecting at the
inferred pad anchor is refuted by construction, since `solve_into` builds the RHS
only over unknowns and never reads a pad node's `node_load`. The blast radius was
also under-reported: **four** rules, not two, and the worst was
`check_em_current_density`, which reported `Ran` with a *full* `examined`
population. Discrimination was measured by mutation — deleting the gate, dropping
either conjunct of the detector, and adding a blanket refusal to
`check_reliability` are each caught by a different test leg.

The prior `note` in `expectations.json` has been corrected in place rather
than deleted, so the wrong derivation and its refutation sit together.

The corpus half of each pair remains a regression guard on the gate, not coverage
of the rule, and
each says so in its own `note`. They are tripwires by design: the day a case is
written against `run_case_with_intent` they flip to `Ran` and go red, which
forces the derivation to be finished rather than assumed.

**Two blockers this document named are stale, both found by writing the cases:**

- `esd_latchup` / `clamp_model` unspellable from a deck (`ruleset.rs:627`) — not
  a blocker. An empty clamp list *degrades the verdict* rather than refusing the
  row (`ruleset.rs:621-630`), `ClampGraph::resolve` on an empty edge list returns
  `Ok`, and `lowest_resistance` returns `None` loudly. The derived count of 2 is
  the empty-clamp **ceiling**, not a statement about `ERC_HV`; a configured clamp
  drops it to 1 when `ParamValue::Name(StrId)` lands.
- `density_cmp` needs a `"density_cmp" => "met2.density_cmp"` arm — the arm
  exists and names `met1.density_cmp`. `met2` was a guess.

**The remaining blocker for `ir_drop` and `reliability` is the harness, again.**
`measurement_matches` (`tests/common/mod.rs:1273-1282`) has arms for `Length`,
`Area`, `Count` and `Ratio` only — no `Voltage`, `Current` or `Resistance` — so
**no corpus case can assert an electrical measurement**. `reliability` reports
`Ratio`, so it escapes; `ir_drop` reports a voltage and does not. Adding an arm
is a change to the harness, not to a frozen signature.

Derivations sitting ready in `expectations.json` `note` fields:

- `ir_drop` — `LVS_INV`'s poly rail, two nodes, `250/50 = 5.0` squares at
  48.2 Ω/sq = 241.0 Ω, 1000 µA ⇒ 241.0 mV at `(225, 100)` on poly.
- `reliability` — `5091.597 h` predicted against a `1000 h` floor for the 1800 mV
  intent; `Ratio(450.70)` at 3300 mV, at `(500, 250)` on met1.
- `esd_latchup` — examined 2, violations `Count(0)` vs required 1 at `(200,200)`
  on met1 and `Length(500)` vs 1000 at `(0,0)` on nwell.
- `electromigration` — **no absolute violation count is derivable today.** Four
  fail-opens land on it, composing to ~100× on the pass-more side. What survives
  is the outcome, the examined population and the *direction*: a violation it
  reports is real, a clean one is not evidence.

Also surfaced, unfiled: `params.json` declares no `prBoundary`/die layer, so the
die is `engine::run::design_extent`'s fallback — the union of every polygon bbox
(`run.rs:257`), **documented fail-open for a min-density floor**.

Two more, unfiled, found while deriving the four skipped cases:

- `check_esd_latchup` measures a guard ring as bbox min span
  (`reliability.rs:722`), which for an actual annulus — the only shape its own
  doc comment names — is the **outer diameter**, not the conductor width. A 10 µm
  ring drawn from a 200 nm trace measures 10000 and passes any real limit.
  Fail-open on exactly the geometry the rule exists for.
- an `electromigration` deck row naming **two** layers trips the
  `debug_assert_eq` at `electrical.rs:860` and slice-indexes out of bounds at
  `:899` in release — `ruleset.rs:586` pushes `blech_limit` once per row while
  the other columns extend once per layer. Both sit *above* the intent gate, so
  it would panic every case in the corpus, in both profiles. The two existing
  unit tests build the table by hand and never go through `from_deck`.

## 4. Metamorphic laws that survived adversarial review

7 survived of 34 proposed. Each was attacked by a skeptic instructed to default
to refuted. Every one below has `can_actually_fail: true` — a law that holds for
an implementation returning nothing was rejected.

**All 7 are implemented and green.** Where each lives:

| law | test |
|---|---|
| 1 rigid motion of the extraction | `crates/topology/tests/laws.rs :: a_rigid_motion_of_every_vertex_leaves_the_extraction_bit_identical` |
| 2 `PolyId` permutation | `crates/topology/tests/laws.rs :: permuting_arrival_order_gives_the_same_partition_and_the_same_net_ids` |
| 3 integer scale | `crates/topology/tests/laws.rs :: an_anisotropic_integer_scale_moves_only_the_measured_area` |
| 4 global transform equivariance | `crates/ingest/src/layout.rs :: wrapping_the_root_in_one_transformed_instance_transforms_the_whole_store` (inline, as the scope note requires) |
| 5 translation equivariance | `crates/drc/tests/overlay_laws.rs :: translating_the_overlay_design_across_the_origin_moves_only_the_report` |
| 6 uniform scale of geometry and deck | `crates/drc/tests/overlay_laws.rs :: scaling_the_overlay_geometry_and_deck_together_scales_only_the_measurements` |
| 7 rigid motion of spacing | subsumed — laws 5 and 6 plus `crates/drc/tests/determinism.rs` |

`overlay_laws.rs` carries two further tests that are **guards on the fixture,
not laws**: `the_fixture_reports_at_odd_negative_midpoints` and
`the_tap_distance_is_an_exact_integer`. Law 5's whole value is the odd-parity
origin straddle (see its scope note); a fixture that lost that property would
leave law 5 passing and vacuous, so the property is asserted directly.

None of the seven found a defect. That is the expected outcome for a law over
code that has already been through the corpus; they are regression guards on
properties nothing else in the tree asserts. **Only law 4's sibling records a
discrimination check** — `a_mirror_and_a_rotation_split_across_two_levels_do_not_commute`
was verified to fail both with the ring reversal disabled and with `compose`'s
quadrant negation collapsed. The other six have no recorded "this fails when the
mechanism is broken" experiment; a law that has never been seen red is a law
whose power is asserted, not measured. Doing that sweep is cheap and unfinished.

### topology extraction (3)

`topology` had the weakest oracle coverage in the tree (1 of 16 declared oracles
was law/closed-form), and F1–F8 are largely topology findings. That is the gap
`crates/topology/tests/laws.rs` was written to close: three metamorphic laws,
green, over `extract_into` as a whole rather than over any one function.

1. **Rigid-motion invariance of the whole extraction.** Translation, `k·90°`
   rotation, mirror in x or y applied to every vertex ⇒ `NetTable`, `DeviceTable`
   (incl. `DeviceMeasure::Area`) bit-identical. Justified by `net.rs`'s own join
   rule: touching and overlapping are set-intersection, and an isometry is a
   bijection of the plane.
   *Scope:* demote translation — `SpatialIndex::build_into` takes the origin from
   `extent.xlo/ylo` (`index.rs:178`), so the grid translates with the data and is
   bit-identical; already covered by `index_pairs.rs:289`. **Mirror and rotation
   carry the power** — mirroring moves the grid's ragged last cell to the other
   end, so the candidate superset genuinely differs while the answer must not.
   Drop `bind_ports_into` (reads only `provenance.labels()`, no geometry). Apply
   T at the store level, never by re-ingesting a mirrored file — that drags in
   the flattener's `at.flip` reversal and the winding-derived hole bit.

2. **`PolyId` permutation gives the same partition and the same canonical ids.**
   Permuting arrival order within a layer ⇒ partition maps through π exactly,
   `net_count` and the net-size multiset unchanged, and ids are *pinned* not
   merely isomorphic.
   *Scope:* `DeviceId` is the marker's rank, so device rows **reorder** — compare
   as a multiset keyed on π's image, never positionally. `recognise_into`'s
   terminal binding is legitimately order-dependent (`device.rs:296-298` iterates
   `.rev()`, lowest PolyId wins), so exclude `terminal_net`/`terminals_of` or
   build the fixture so exactly one shape per terminal layer meets each marker —
   *asserting terminal invariance on an F3-shaped cell asserts a bug*. Requires a
   **strictly nested intersecting pair** or it only tests the sorts, which are
   already tested.

3. **Uniform integer scale leaves the netlist alone and squares only the area.**
   Scale every coordinate by integer `s ≥ 2`, deck unchanged ⇒ `NetTable`
   bit-identical, `Area(a) → Area(s²·a)` exactly.
   *Scope:* use an **anisotropic** `(sx, sy)`, `sx ≠ sy` — `box_extent` is
   `max(dx,dy)` (`index.rs:65`), so anisotropy genuinely reassigns boxes between
   index levels where `s·I` barely does. At GDS level the bound is `i32`, not
   `MAX_ABS_DBU` (`gds.rs:56`, `layout.rs:428`) — nine bits tighter.

### ingest flatten/transform (1)

4. **Global transform equivariance.** Wrap the root cell in a new outermost cell
   holding one `SREF` carrying any representable `W = mag · R_q · Fʳ · p + (dx,dy)`
   ⇒ store rows identical in count and layer; vertices are `W(v)` in order when
   `r=0` and `[W(v₀), W(v_{n-1}), …, W(v₁)]` when `r=1`. Holds at arbitrary depth
   because reversing `[1..]` is an involution and `compose` XORs flip parity.
   *Scope:* put `mag > 1` only in `W`, never also nested — two nested `1e6`
   magnifications give `a·child.dx ≈ 2^71` and **wrap `i64` silently in release**
   (separate finding, file it). "Refusal is a pass" must be spelled
   `Err(LayoutError::CoordinateOutOfRange(_))` *and* at least one `W` asserted
   **not** to refuse, or a reader that refuses everything passes — fail-open. Must
   be an inline `#[cfg(test)]` test: `LayerTable` has private fields and no public
   constructor.

### drc enclosure/overlap (2)

5. **Translation equivariance.** `Outcome`, `examined`, violation sequence and
   every field bit-identical; `at` exactly `(x+dx, y+dy)`.
   *Scope, and this is the whole value:* **the shift must straddle the origin with
   odd parity.** The only way `at` can fail is a midpoint flooring toward zero
   instead of `div_euclid` — the exact bug `drc/src/rules/mod.rs:119` names.
   `determinism.rs:137` makes precisely this mistake: `SHIFT = 1_000_000` on a
   layout already at `x,y ≥ -100`, so nothing ever straddles and a `/`-based mid
   passes it. Needs negative coordinates shifted positive, and odd-width strips.

6. **Uniform scale of geometry and deck together.** Scale coordinates and every
   overlay limit by integer `k > 1` ⇒ same violation count and order, identical
   `shapes`, `measured` exactly `k×`.
   *Scope:* **drop `at` for the four lithographic rules** — `mid()` is
   `(a+b).div_euclid(2)` and even `k` does not save it; for odd `a+b` the answers
   differ by `k/2`. Keep `at` for `check_max_distance_to_tap`, which reports a raw
   vertex. Bound the scaled *limit*, not just coordinates: `pair_layers`
   (`overlay.rs:418`) `debug_assert`s `distance <= MAX_ABS_DBU`, so `k·limit`
   crossing `2^40` panics in debug. Free strengthening: `Outcome` and `examined`
   are exactly invariant too.

### drc spacing (1)

7. **Rigid-motion invariance.** Survived attack on all six spacing rules; the
   proposer's three noted risks all dissolved on reading the code.

## 5. Laws refuted (27)

Recorded so they are not re-proposed. The dominant kill reasons:

- **Already covered, more sharply, by an existing construct test** — the most
  common. `splitting a drawn conductor figure is invisible to the net partition`,
  `flat and hierarchical expressions of one figure`, `winding_is_a_property_of_the_cell`,
  `flatten_is_additive_over_placements`, `closure_to_identity_across_depth`,
  `vertex_zero_is_the_fixed_point`, `translation_equivariance` (spacing),
  `distant_duplication_doubles`.
- **False against a *correct* implementation** — the valuable class:
  - `polygon-order permutation` — `overlay.rs:534-543`'s best-host fold breaks
    ties by lowest `PolyId`, so `at` legitimately moves.
  - `D4 equivariance (enclosure/overlap)` — `check_min_extension`'s
    no-protrusion fallback (`overlay.rs:812-825`) filters to the strictly
    positive subset and returns a sentinel when empty.
  - `mirror_is_invariant_only_with_ring_reversal` — `area.rs:310` reports `at`
    at the centre of the *first* rectangle.
  - `figure_merge_absorbs_an_internal_cut` — false for all three named rules;
    `parallel_run_length`, `corner_to_corner`'s diagonal predicate and
    `gap_midpoint` all see the cut.
  - `split a figure into two abutting rectangles` — the well clause is false for
    a conforming `check_max_distance_to_tap`.
  - `non-convex host against its own bounding box` — geometrically wrong for two
    of five rules.
  - `limit_monotonicity_and_exact_filter` — `examined` is not equal between runs
    for `prl_spacing`, `corner_to_corner`, `wide_dependent_spacing`.
  - `element_order_permutes_rows` — `path_of`/`props_of` return interned ids.
  - `a distant duplicate doubles everything` — false for any layout with more
    than one non-empty layer; `finish` counting-sorts rows by layer.
  - `an_aref_is_exactly_its_enumerated_srefs` — GDSII defines no enumeration
    order for AREF.
  - `a port table is a function of the (net, name) set` — `StrId` is assigned in
    interning-encounter order.
- **Unfalsifiable / vacuous** — `uniform_integer_scale_of_geometry_and_deck`
  (refuted *as unfalsifiable, not as false* — nothing in the covered path can
  violate it), `distant duplicate (superposition)`,
  `uniform_scale_of_geometry_and_deck`, `via cut multiplicity`.

## 6. Priority

Ordered by correctness value per hour. **Items 1–6 of the original list are
done**; what follows is what the doing of them left behind.

<details>
<summary>The original six, all closed</summary>

1. ~~Unhook `intent: None`.~~ Done — `case_inputs` takes an `Option<PathBuf>`,
   `run_case_with_intent` supplies one, `a_corpus_case_with_design_intent_reaches_an_intent_gated_rule` proves it.
2. ~~Laws 5 and 6 (drc enclosure/overlap).~~ Done — `crates/drc/tests/overlay_laws.rs`.
3. ~~Laws 1–3 (topology).~~ Done — `crates/topology/tests/laws.rs`.
4. ~~Law 4 (ingest global transform).~~ Done — inline in `crates/ingest/src/layout.rs`.
5. ~~`density_cmp` corpus case.~~ Done — two, `PASS` and `FAIL`, both `Ran`.
6. ~~The other four uncovered kinds.~~ Deck rows, arms and one `Skipped` case each.

</details>

What is now at the front:

1. **A `Voltage` arm in `measurement_matches`** (`tests/common/mod.rs:1273`).
   Without it no corpus case can assert an electrical measurement, which blocks
   `ir_drop` coverage outright and blocks the interesting half of `reliability`.
   Harness change, not a signature change. *Hours.*
2. ~~**The four `Skipped` cases' `Ran` paths**, against `run_case_with_intent`.~~
   Done, all four. `electromigration` was the one this list said "cannot produce
   an absolute count at all" — true of `ERC_EM`, and false of `ERC_EM_DEV`, which
   was drawn to make it derivable. The absolute count *is* asserted there,
   because the fail-open that made it underivable is the fifth one — a discarded
   budget, not a magnitude bias — and drawing a `licon` closes it. The four
   four magnitude fail-opens remain, and the test's doc comment
   says which of its claims survive them.
3. **Discrimination checks for laws 1, 2, 3, 5, 6.** Break the mechanism each
   guards, confirm the law goes red, revert. None has ever been seen red.
   *Hours.*
4. **File the nested-`mag` `i64` overflow.** Law 4's scope note names it —
   two nested `1e6` magnifications give `a·child.dx ≈ 2^71` and **wrap silently
   in release**. Still unfiled.
5. **File the two `esd_latchup`/`electromigration` findings in §3.** The guard-ring
   bbox fail-open and the two-layer `electromigration` row that panics in both
   profiles. Both are unfiled. *Minutes.*
6. **Resume the mutation sweep at `-j 4`.** `erc`, `core`, `pex`, `lvs` are
   entirely unmeasured. *Days of wall clock, hours of attention.*

Corpus cost, measured by the feasibility agent: tooling is ~1h once (the GDSII
writer already exists in `crates/ingest/src/layout.rs`'s `#[cfg(test)] mod tests`
at line 1626 — `record`/`boundary`/`label`/`gds_labelled`, spec-derived and
copyable). Per cell: 10–20 min wiring, **30–90 min physics derivation, which
dominates and does not amortise**. `export::gds::write_store` cannot author these
— its constants table has no `TEXT`/`TEXTTYPE`/`STRING`.

Six things move in lockstep per new case, including `gen_fixtures.rs:82`
`CASE_COUNT` (asserted twice, now 167) and a `deck_rule_of` arm — the arm only
when the case names a rule kind no existing arm maps.

## 7. What this map does NOT cover

- **LVS.** No laws were proposed for it. F8 — `compare_params` returning `Match`
  while comparing zero parameters — is still the single worst defect in the tree
  and is untouched by anything here.
- **PEX.** The quasi-static path is wrong on every real
  input (square-panel shape factor on rectangles, no layered-dielectric Green's
  function, half-micrometre mesh). No law addresses that; only a reference
  solution would.
- **The 13 known-wrong extraction sites**, including the four fail-opens
  compounding onto `check_electromigration`. These are capability gaps behind
  frozen signatures.
- **An independent oracle.** Every law here is self-referential to this
  implementation's *contract*. Differential testing against KLayout remains the
  only thing that could distinguish "self-consistent" from "correct".
- **The mutation sweep**, abandoned at `units` + 82% of `drc`. `erc` (2372
  mutants), `core` (1153), `pex` (864), `lvs` (486) are unmeasured. Re-run at
  `-j 4`, not `-j 12`.
