# Definition-Phase defects

> **`core::bulk` is gone.** Every reference below to `core::bulk`,
> `crates/core/src/bulk.rs`, `crates/core/tests/bulk_combinators.rs`, a
> *combinator*, or `references/bulk-combinators.md` names something that no
> longer exists: the module was inlined across all its call sites and deleted,
> and the bulk-loop rule is now enforced per site. See `docs/BULK_MEASUREMENTS.md`
> and `bulk-loops.md` in the project-libraries skill. This page is left as the
> record it was written as.

Signatures froze at the end of the Definition-Phase. Writing the suite against
them turned up places where the frozen artefact was wrong, self-contradictory,
or could not express the thing its own doc comment promised.

**They are being resolved, one crate at a time, before the Implementation-Phase
starts.** The entries below carry their state. A **RESOLVED** entry names the
file and line of the fix and stays on the page, because the workaround it
displaced is still recorded in `docs/NEED_TESTING.md` and the two have to be
read together. An entry with no marker is still open, and the Implementation-
Phase must not paper over it with a body.

**Nothing was resolved by widening a signature to make a test pass.** Each
resolution is either a doc sentence pinning a convention, or an addition that
made an already-documented promise reachable — a missing constructor, a missing
`Grid` parameter, a missing enum variant. Where a resolution invalidated a test
that had asserted the defective behaviour, the test moved; that is listed at the
end of each section.

The three that were load-bearing far beyond the crate owning them:

- **RESOLVED** — `deck::LayerTable` has a constructor,
  `LayerTable::build` (`crates/ingest/src/deck.rs:138`) and the reverse
  accessor `stream_of` (`:114`). This unblocked `drc::RuleSet::from_deck`,
  `export::gds::write_store` on geometry, `engine::pipeline::load_into` and the
  `parse -> write -> parse` law.
- **RESOLVED** — `NetTable::from_assignment` (`crates/topology/src/net.rs:129`)
  and `PortTable::build` (`crates/topology/src/port.rs:72`), both with real
  bodies. This unblocked `lvs::checks`, both `drc` antenna rules, and the `erc`
  ESD rules.
- **RESOLVED** — a `Grid` now reaches `pex::analytical`
  (`crates/pex/src/analytical.rs:66`), `erc`'s electromigration rules
  (`crates/erc/src/rules/electrical.rs:229`), and `report::Measurement`'s
  `Display` resolved the other way: it prints raw database units
  (`crates/report/src/measure.rs:92`) and the writer that holds a grid does the
  conversion.

---

## units

**RESOLVED — the 45 nm example contradicted its own arithmetic.**
`crates/units/src/lib.rs:17-19` now reads 47 nm, with 45 nm on a 5 nm grid
spelled out as the counter-example. `CLAUDE.md` no longer repeats the old
sentence.

**RESOLVED — `Qty`'s `Display` doc gave three examples no single format string
produces.** Pinned at `crates/units/src/qty.rs:164-179` to `f64`'s own
`Display`: shortest round-trip decimal, no padding, so `3 aF` and not `3.0 aF`,
and the numeric head parses back to `raw()` exactly. Two further things the same
doc left open are pinned there as well — micro is ASCII `u`, matching the `ohm`
precedent in the `dimensions!` table, and an exponent outside `crate::prefix`
has no letter and is written on the value (`1.8e7 V`).

**RESOLVED — `Grid::to_dbu` had no documented answer for a non-finite length.**
New variant `GridError::NotFinite` (`crates/units/src/dbu.rs:146`) and the
order of checks made part of the interface (`:169-178`): `Qty::is_finite` first,
then the coordinate range, then exactness. `to_dbu_into` inherits it as the bulk
form. A `NaN` reaching an exactness test compares false against everything and
would have been refused as `NotOnGrid` by accident, which is the fail-open shape
the variant closes.

**`Grid::new` is a `todo!()` body behind a private field.** Not a signature
defect — the signature is right and this is Phase-4 work. Until then a
`read_deck` / `pex` / `erc` test failure points at `units` rather than at its own
crate.

---

## core

**RESOLVED — `boolean`'s output parameter could not represent a boolean
result.** `ValidatedLayer` now owns its coordinates: private `verts_x`,
`verts_y`, `ring_vert_start`, `ring_vert_len` columns at
`crates/core/src/view.rs:75-88`, with the rationale in the module doc at `:11-24`
and in `crates/core/src/boolean.rs:14-21`. Chosen by elimination over the two
other candidates `NEED_TESTING` named: an owned result type breaks the "usable
as the next operand with no revalidation" property the interface exists for, and
a `GeometryStoreBuilder` output is not readable until `finish` consumes it, so a
chain cannot read its own intermediate. **Zero public signatures changed.**

Two consequences of that fix, neither previously filed:

- `PolygonRef::bbox` and the prune had no bbox column on a derived layer.
  Private `poly_bbox` column plus `ValidatedLayer::bboxes` —
  `crates/core/src/view.rs:89-93`, `:126-133`.
- `ring_poly` has no meaning for a boolean-produced ring. Documented as
  provenance rather than identity — the lowest contributing input `PolyId` —
  at `crates/core/src/view.rs:81-87`.

**`gpurify-testgen` is unusable inside `#[cfg(test)]` modules of
`gpurify-core`.** Still open. The dev-dependency cycle (core → testgen → core)
makes Cargo build a second `gpurify-core` instance for testgen, so
`gpurify_testgen::shapes::LayerId` is a distinct type from `crate::ids::LayerId`.
The resolution is a `gpurify-testgen-core` crate split, which is a workspace-level
decision rather than a core-local patch, and every crate owning a private
`*_observed` seam hits it. The adapter tests in `src/index.rs` carry a
self-contained SplitMix64 lattice generator in the meantime.

**RESOLVED — `GeometryStoreBuilder::finish` did not state whether its sort is
stable within a layer.** Now promised stable, and the permutation restricted to
a layer range is strictly ascending — `crates/core/src/store.rs:130-136`.

**RESOLVED (the load-bearing half) — `ValidatedLayer` had no `PartialEq`.**
Derived, and documented as **structural** — same coordinates, same rings, same
order, explicitly not region equality — at `crates/core/src/view.rs:64-72`.

The other half of that entry, enumerating a result's polygons other than by
index, is left: `len()` plus `get(store, idx)` already enumerates, and an
iterator would be a convenience widening.

**`ValidatedLayer::get`'s `store` parameter is now vestigial for coordinates.**
It survives only as the provenance and pairing route, documented as such at
`crates/core/src/view.rs:114-121`. Removing it touches `derived`, `drc`, `erc`,
`pex` and their tests.

**`bulk` has four entry points and `lvs::refine` wants two it does not have.**
Still open, and both are additions to a frozen interface rather than bodies, so
the ponytail pass through `crates/lvs/src/refine.rs` left the raw loops standing
and filed them here.

- **Segmented reduce.** `refine::push_signatures`
  (`crates/lvs/src/refine.rs:225`) folds one node's CSR terminal range into a
  signature. The inner fold *is* a `bulk::reduce`; the outer walk over segments
  is a bulk loop over devices and nets with no combinator to go through.
  `bulk.rs`'s own module doc already names this shape as wanted
  (`Bbox::of_polys_into`, `antenna`'s stack ranges, `power`'s node ranges), so
  `refine` is a fourth site, not a second. The shape wants `starts`/`lens`
  columns plus a per-segment init, and it cannot be faked at a call site because
  the callback contract bans the slicing its body would need.
- **A compact whose kept row includes the row index.** `Partition::pairs`
  (`crates/lvs/src/refine.rs:531`) keeps `(node, ref_first[class_of(node)])` and
  `Partition::unresolved` (`:559`) keeps `(class, mine, theirs)`.
  `compact_into` writes `C::Item`, so every kept field has to arrive as a
  column, and the index is not one — `Cols` has no index source and the callback
  contract bans depending on the index. The accumulator-carried counter that
  unblocked the fold in `refine_observed` (`crates/lvs/src/refine.rs:418`, now a
  four-accumulator `bulk::reduce`) does not transfer, because `compact_into`'s
  `keep` is an `Fn` with no accumulator to carry one in. This is a *different*
  gap from the payload-carrying compact `bulk.rs` already lists for `spacing`'s
  measured distance, and the cheaper fix of the two is an index-column impl on
  `Cols` rather than a fifth entry point.

Not filed as a defect, for the record: the scatter in `refine::signature_round`
and the scatter-accumulate in `refine::tally_into` stay raw loops permanently.
`bulk.rs` states that a data-dependent output index will not be wrapped, and the
comments at those two sites now say so rather than reading as unspent debt.

---

## ingest

**RESOLVED — `export::gds::write_store` could not be implemented as signed.**
`LayerTable::stream_of(LayerId) -> (u16, u16)` at
`crates/ingest/src/deck.rs:108-116` is the direction the writer needs.

**RESOLVED — the `parse -> write -> parse` law had no location it could be
written in.** `LayerTable::build(&[(StrId, u16, u16)])` at
`crates/ingest/src/deck.rs:118-146`, with a **real body**. `by_name` is
redefined as sorted by `StrId` rather than by name bytes, so `build` needs no
`StrTable` and `id` binary-searches a `u32`. An integration test now has both
the right type identity and a way to construct the value.

**RESOLVED — `read_deck` had no in-memory form and no documented file schema.**
`parse_deck(&str, Grid, &mut StrTable)` at `crates/ingest/src/deck.rs:301-356`
carries a full JSON schema, a tagged `ParamValue` encoding (`{"nm":45}` /
`{"ratio":…}` / `{"count":…}` / `{"layer":…}` / bool) and a clause per
`DeckError` variant, so `OffGrid`, `UnknownLayer`, `MissingParam` and
`DuplicateRule` are each reachable. `read_deck` is the file-reading wrapper.

**RESOLVED — `read_intent` was in the same position.**
`parse_intent(&str, &mut StrTable)` at `crates/ingest/src/intent.rs:110-158`,
with a JSON schema and a clause per `IntentError`. `supplies` and `limits` are
arrays, so a repeated net is expressible and therefore refusable.

**RESOLVED — `UnknownLayers::Drop`'s reporting half was in no signature.**
`Layout::dropped: u32` at `crates/ingest/src/layout.rs:28-38`, with the variant
doc pointing at it (`:73-75`).

**RESOLVED — `Netlist` could not represent a subcircuit instance.**
`RefInstanceId` plus five columns — `instance_name`, `instance_of`,
`instance_subckt`, `instance_terminal_start`, `instance_terminal_net` — and
`instance_terminals_of`, at `crates/ingest/src/netlist.rs:54-57`, `:100-137`,
`:170-173`. The parent is a column, as it is for nets, rather than a CSR off the
subcircuit: an empty instance table then means exactly "nothing is instantiated"
for any subcircuit count, so `..Netlist::default()` fixtures stay valid. This
also unblocks `lvs::PlanError::Cyclic`, `Inconclusive::AmbiguousTop` and
`Netlist::top`.

**RESOLVED — `Provenance::paths` handed out a shared reference where
`PathTable::intern` needs `&mut`.** `Provenance::intern_path(&mut self, &[StrId])
-> PathId` at `crates/ingest/src/provenance.rs:106-124`, with a real body.

**OPEN, and not to be resolved by widening — `Provenance` has no freeze point,
so `label` must sort on insert.** `labels(&self) -> &[(PolyId, StrId)]`
(`crates/ingest/src/provenance.rs`) promises ascending `PolyId` on a table that
may never have been permuted: `topology::port` binds against it without sorting
and `engine::pipeline.rs:204` asserts over it. With no `&mut` method guaranteed
to run between the last `label` and the first `labels`, the column has to be
ascending at all times, so the O(labels) `Vec::insert` memmove is what the
shared slice costs, not a shortcut. The obvious amortisation — push unsorted,
sort in `permute` — is wrong rather than slow: it hands reader-encounter order
to every caller that does not permute, which is the nondeterministic binding the
column exists to prevent. A real fix needs a `finish`/`freeze` method on
`Provenance`, and it buys nothing until a reader bulk-attaches labels out of
order — attached ascending, `insert` already lands at the end and is a push.
Recorded so the next reader does not "fix" the memmove.

**RESOLVED — `param`'s unit convention was unstated.** SI base units, SPICE
scale suffixes expanded at parse, so `w=1u` is `1e-6` and a bare `w=1` is one
metre — `crates/ingest/src/netlist.rs:107-116`. The ambiguity was a factor of a
million in every parametric LVS comparison.

**RESOLVED — `LoadError::NoGrid`'s "deck declares no grid resolution".**
`Deck::grid` is documented at `crates/ingest/src/deck.rs:46-53` as echoing the
grid `parse_deck` was handed; a deck file does not declare a resolution. The
engine side of the same defect is under `## engine`.

**RESOLVED — `DeviceRecognition` could not express a terminal's role.** (Filed
under `## topology`.) Role-by-position table per `DeviceKind` on
`DeviceRecognition`'s doc at `crates/ingest/src/deck.rs:218-238`: Mos = gate,
source, drain, bulk; Bjt = base, emitter, collector; two-terminal = pin 0, pin 1.

**RESOLVED — `Netlist` carried no terminal roles.** (Filed under `## lvs`.)
Card-order table on `terminal_net` at `crates/ingest/src/netlist.rs:86-104`:
Mos = **drain, gate, source, bulk**, which is SPICE's `M` card order and was
confirmed against `reference/pre-rewrite:crates/lvs/src/spice.rs:112`; Bjt =
collector, base, emitter. Explicitly *not* `DeviceRecognition`'s order — a
recogniser lists gate first because geometry names it first, a card lists drain
first — and the two meet in `lvs`.

**RESOLVED — DRC and ERC rules share one `RuleTable` and both `from_deck`s
failed closed on an unknown kind.** The refusal moved rather than the schema.
Neither `from_deck` can refuse a kind, because the other domain's rows are
unrecognised to it: `drc::RuleSet::from_deck` (`crates/drc/src/ruleset.rs:338`)
and `erc::RuleSet::from_deck` (`crates/erc/src/ruleset.rs:731`) now skip a row
whose kind is outside their own `KINDS` and file the rest. The union check lives
one layer up at `gpurify_engine::run::reject_unknown_rule_kinds`
(`crates/engine/src/run.rs:234`), called at the top of `run_checks` *before*
`options.checks` is read, so a misspelled ERC kind cannot hide behind a DRC-only
run. No domain column on `RuleSpec`, no second table on `Deck`, so every `Deck` /
`RuleSpec` literal in `erc/tests/dispatch.rs`, `engine/tests/pipeline.rs` and
`ingest/src/layout.rs` still compiles. `parse_deck`'s doc
(`crates/ingest/src/deck.rs:413-426`) records where the refusal went.

Two things it costs, both stated rather than papered over:

- **Each crate's closing `debug_assert_eq!` had to weaken.** It compared
  `rule_count()` against `rules.spec.len()`; it now compares against the rows
  whose kind is in that crate's `KINDS` (`crates/drc/src/ruleset.rs:683`,
  `crates/erc/src/ruleset.rs:744`). It still trips on a `KINDS` entry with no
  match arm, which is the drift it existed to catch.
- **`erc/tests/dispatch.rs`'s drift detector had to change tell.** It was
  `Err(UnknownKind)`, which can no longer occur, so it would have gone vacuously
  green. It is now `Ok` with `rules.len() != 1`.

**RESOLVED — `"antenna"` was in both `KINDS` lists.** Found by the resolution
above and pre-existing to it: `drc::ruleset::KINDS` (26) ∩ `erc::ruleset::KINDS`
(19) = `{"antenna"}`, with two mutually exclusive schemas, so a row spelled that
way was filed by *both* `from_deck`s and failed one of them. Not resolved by
renaming: the two were the **same physical check implemented twice**, and one
copy is deleted. `erc` owns the antenna family; `crates/drc/src/rules/antenna.rs`
and the `"antenna"` and `"antenna_car"` entries of `drc::ruleset::KINDS` (now
24) are gone. See `## the antenna family` at the end of this file for what moved
with them and what did not.

**`oasis::read` has no fixture path.** Needs an OASIS writer in `export`.

---

## derived

**RESOLVED — `Evaluator.name` asked for two orders at once.** A third column
`lookup: Vec<u32>` — indices into `name`, sorted by `StrId` — at
`crates/derived/src/expr.rs:110-115`. `name`'s doc now states topological order
only (`:104-107`) and `plan`'s doc says it fills both (`:127-130`). `get`
binary-searches `lookup`, `evaluate` forward-scans `name`. No existing column
was reordered.

**RESOLVED — `DerivedError::Recursive` and `Undefined` carried a `String` no
parameter could produce.** The payload is a `StrId`
(`crates/derived/src/expr.rs:74-79`), with an enum doc saying why: `plan` never
gets a `StrTable`, and a name is a `u32` until a report reaches a human. Chosen
over adding a `&StrTable` parameter to `plan`, which would have broken both call
sites in `tests/plan.rs`. `matches!` on the variant still compiles, and the
payload is now assertable.

**RESOLVED — `DerivedExpr` derived no `PartialEq`.**
`crates/derived/src/expr.rs:27`.

**RESOLVED — `DerivedExpr::Outside`'s doc comment was self-inconsistent.**
Decided as the area/clipping reading at `crates/derived/src/expr.rs:37-66`:
`Inside` is `Intersection` under the deck's name, `Outside` is
`(operand ∩ universe) − region`. Evidence rather than a coin flip —
`core::boolean` exposes only union / intersection / subtraction / offset, so no
frozen primitive can select whole shapes; the universe paragraph's own argument
is only true under complement semantics; and
`reference/pre-rewrite:crates/drc/src/derived.rs:250-264` evaluated the pair as
exactly `Intersection` / `Subtraction`, keeping a separate `Interacting` for
whole-shape selection. The `universe` field is kept.

**RESOLVED, and worth a second opinion — `Outside` with a universe smaller than
its operand.** Documented as deliberate truncation rather than an error at
`crates/derived/src/expr.rs:60-65`, on the ground that the universe is the extent
the deck itself declared. Truncation loses area, which is fail-open for any rule
consuming the derived layer; the alternative is a new `DerivedError` variant plus
a containment check on every `Outside`.

**`Evaluator::plan`'s output order is not observable through the public
interface.** Left. The unit tests in `src/expr.rs` cover the ordering, and a
public `order()` accessor would be a widening with no consumer.

**`ValidatedLayer` exposes no provenance, so `prefilter` guesses it — and the
guess is fail-open.** Still open, and a correctness gap rather than a cost.
`derived::prefilter::candidates_into` returns `(PolyId, PolyId)`, and the only
route from a validated polygon back to a store row is
`provenance_into` (`crates/derived/src/prefilter.rs:289`), which matches the
operand's bounding-box column against every layer's. Two consequences. A layer a
boolean produced has no preimage at all, so it falls back to the operand's own
index: values in `PolyId`'s space that name no store row and that no caller can
tell apart from ones that do. And a box column embeds in a layer's column more
than one way whenever shapes repeat — an array of vias, a drawn/pin layer pair —
so the recovered row can be a real row that is not the polygon's. The second is
now detected in-file (the embedding must agree matched from both ends,
`:429`), the first cannot be. `ValidatedLayer` already holds the answer in its
private `ring_poly` column; closing this is
`ValidatedLayer::provenance(&self) -> &[PolyId]` in `core`. It also turns the
recovery from O(store rows) per operand into O(operand).

**`candidates_into` has nowhere to hang scratch.** Still open, low severity.
`candidates_into(store, a, b, out)` allocates its two provenance columns, its
operand index and its two pair buffers per call
(`crates/derived/src/prefilter.rs:87`), because the frozen signature carries no
reusable buffer and the workspace bans hidden statics. Every other transform in
the tree takes its scratch as a parameter. `core::index::candidate_pairs_into`
records the same trade.

**`Evaluator::evaluate`'s allocate-once claim is unverified.** Needs the
allocation-counter adapter from `docs/TESTING.md` threaded through `evaluate`
the way `ObservePrefilter` is threaded through the prune. A TESTING.md adapter
decision, not a signature defect.

---

## topology

**RESOLVED — `DeviceRecognition` could not express a terminal's role.** The
table is written on `TerminalRole` itself at
`crates/topology/src/device.rs:25`: Mos = Gate/Source/Drain/Bulk, Bjt =
Base/Emitter/Collector, `Resistor` and `Capacitor` = `Pin(k)`, anything past a
family's row = `Pin(k)`. On the type rather than on `recognise_into` because
`lvs` needs the same mapping from SPICE card order, and two crates inferring it
separately is how a drain and a source transpose. `recognise_into` points at it
(`device.rs:144`); the `ingest` half is under `## ingest`.

**`Diode`'s two roles are excluded from that table, deliberately.** `Pin` is
documented as interchangeable by definition, so giving a diode pins lets a
comparison match one wired backwards — fail-open. The fix is an `Anode` /
`Cathode` variant pair, which is a Definition decision and breaks exhaustive
matches. Named as unresolved in the doc comment at the site.

**RESOLVED — `extract_nets_into` did not say what net a non-conductor polygon
gets.** New "Which polygons get a net" section at
`crates/topology/src/net.rs:199`: only layers in `Connectivity::conductors`,
everything else `NetId::NONE`. The sentinel is at `crates/topology/src/net.rs:45`,
and `net_count` / `net_of` / `polys_of` / `same_net` now state that it is outside
`0..net_count`, listed by no net, and false under `same_net` against anything
including itself — fail-closed in both directions. `bind_ports_into`
(`port.rs:98`) states that a label on such a shape is `PortError::OrphanLabel`,
which makes the variant constructible. The sentinel was chosen over
`net_of -> Option<NetId>` because `net_of` is asked per candidate pair by every
`drc` spacing rule.

**No thread-count parameter exists anywhere in this crate.** Nothing to do here:
the determinism gate's "two thread counts" clause belongs at `engine::run`,
which owns the `threads` parameter.

**RESOLVED — `NetTable` and `PortTable` had no constructor and no `PartialEq`.**
`NetTable::from_assignment` (`crates/topology/src/net.rs:129`, counting-sort CSR
rebuild, `NetId::NONE` rows excluded) and `PortTable::build`
(`crates/topology/src/port.rs:72`), both with real bodies and both covered by a
`#[cfg(test)]` case. `impl PartialEq for NetTable` is hand-written
(`net.rs:178`) over `poly_net` / `net_start` / `polys` only — the `edges` and
`labels` scratch survives a call and is not part of the value, so a derive would
make a reused table compare unequal to a fresh one holding the same nets, which
is exactly the comparison the determinism gate makes. `PortTable` has no scratch
and derives it (`port.rs:21`).

**RESOLVED, and found here rather than filed — `NetId`'s doc contradicted the
CSR it indexes.** It said "the minimum polygon index in the component", but
`net_start[n]..net_start[n+1]` is dense and `tests/extraction.rs` iterates
`NetId(0..net_count)`. Sharpened at `crates/topology/src/net.rs:18` to "a dense
rank, numbered `0..net_count` ascending by each net's smallest `PolyId`", which
is canonical under either reading and is what
`tests/extraction.rs:212` already reasons out. `NetId::idx()` added at
`net.rs:51` to match the `core::ids` family.

**`DeviceParam` / `params_of`'s measurement convention, and two recognisers on
one marker layer.** Both `NEED_TESTING`-only. The first needs a stated
channel-direction and measurement-geometry convention, which is a real
Definition decision; the second's resolution lands on `ingest`'s
`DeviceRecognition` doc.

**`recognise_into`'s `derived: &Evaluator` cannot be read, and so is not.**
Found closing the crate out, once `#![allow(unused_variables)]` came off and it
was the only warning left. `DeviceRecognition` names its marker and terminal
layers as `LayerId`s into the `GeometryStore`, while `Evaluator::get` is keyed by
the `StrId` the deck named a derived layer with. Neither frozen signature carries
a bridge between the two id spaces, so a recogniser cannot name a derived layer
at all — which is a real capability gap, not just an unused parameter: a device
recognised on `poly AND active` is the ordinary case in a PDK, and today it
cannot be expressed.

Not worked around. Inventing a `LayerId`-to-`StrId` map inside the body would be
a Definition decision made in Phase 4, and it would be made invisibly. The
parameter keeps its name rather than becoming `_derived`, with a scoped
`#[allow(unused_variables)]` and the argument at the site
(`crates/topology/src/device.rs:189`); an underscore would read as this body
declining to bother rather than as two frozen types having no seam between them.
Resolution is a `LayerId` column on the `Evaluator`'s output, or a
`DeviceRecognition` that names layers by `StrId`.

**No transform in `net.rs` can be handed reusable scratch, so four of them
allocate per call.** `intra_layer_edges_into(store, layer, out)`,
`via_edges_into(store, cut, connects, out)` and `cuts_landing_on` each build a
`SpatialIndex` and one or two pair buffers per call, and `rings_meet_sweep`
(`crates/topology/src/net.rs`) adds six more on the large-ring path. Every one
of them is called in a loop — once per conductor layer, once per via layer, or
once per candidate pair — so "nothing allocates per iteration" cannot be met
from inside the bodies. `extract_nets_into` carries the same defect one level
up: `NetTable` holds its own `edges`/`labels` scratch, but the two builders
clear the buffer they are handed, so the accumulator cannot also be their
output and a per-layer copy out of a hoisted `scratch` is the best the frozen
shape allows.

Two resolutions, and they are not the same size. The small one is a `scratch`
parameter on the two public builders, matching the `_into` convention the rest
of the tree uses. The large one is an *appending* form of the builders — `out`
extended rather than cleared — which would delete the copy in
`extract_nets_into` as well, and which changes what `out.clear()` at the top of
each builder means to every existing caller and test. Neither is a Phase-4 edit.

Not worked around. The specific thing this blocks is the exact-intersection
sweep: `polys_intersect` is reached from a `bulk::compact_into` predicate, and
the callback contract bans an `&mut` capture, so scratch cannot be threaded to
it from any caller no matter how the private helpers are shaped. The sweep
therefore allocates, and is gated behind an edge-count budget
(`DIRECT_PAIR_BUDGET`) chosen so the allocation is reached only where the
quadratic scan it replaces costs far more — a bound on the defect, not a fix
for it.

---

## report

**RESOLVED — `Measurement`'s `impl Display` promised an input it does not
take.** Resolution B from `NEED_TESTING`, doc only, no signature edit:
`crates/report/src/measure.rs:72-91` states that `Display` prints raw database
units with a `dbu` / `dbu^2` suffix and that the nanometre conversion belongs to
whoever holds the grid. Chosen over adding `fn format(&self, grid: Grid)`
because both writers already carry one — `export::json::Report.grid` and
`cli::format::write_violations(.., grid: Grid, ..)` — so a second conversion
site would be the duplication. A per-variant table there also pins `Ratio` (`{}`
on the `f64`), `Count` (a bare integer, no suffix) and the electrical delegation
to `Qty`.

**Consequence for the two writers.** `export::json::write_report` and
`cli::format::write_violations` are now responsible for the dbu-to-nm
conversion, and neither doc comment says which unit its output carries. Open.

**RESOLVED — `sort_canonical`'s ordering of the second shape slot was
unstated.** `None` sorts before `Some`, Rust's derived `Option` order —
`crates/report/src/violation.rs:96-99`.

**RESOLVED — `Violations` derived no `PartialEq`.**
`crates/report/src/violation.rs:50-55`, with a doc line stating the comparison
is element-wise in column order and is meaningful precisely because
`sort_canonical` puts the order in the interface. `testgen::assert_violations_eq`
stays: it prints a readable row diff that `assert_eq!` cannot.

---

## drc

**`RuleSet::from_deck(&Deck, &StrTable)` is untestable as written.** Unblocked
in principle by `ingest`'s `LayerTable::build` and `parse_deck`; the `drc` side
needs no edit, and the seven `DrcError` variants become reachable once a test
builds a deck through the new schema. Not yet written.

**`ParamValue` cannot spell an area, so a deck states the three area limits as a
length and `from_deck` squares it.** Open. `min_area`, `min_enclosed_area` and
`cheesing` all land in a `DbuArea` column (`crates/drc/src/rules/area.rs:44`,
`:57`, `:72`) — the type is right, and it was chosen precisely so an area and a
distance stop being comparable. The deck side is not: `ParamValue`
(`crates/ingest/src/deck.rs:240`) has `Length`, `Ratio`, `Count`, `Flag` and
`Layer`, so the only value `ingest` converts against the grid is a length, and
the `square` closure at `crates/drc/src/ruleset.rs:235` reads the limit as the
**side of the equivalent square**.

The expressible set is therefore the perfect squares of integer coordinates,
which no real foundry area rule lands in — 0.088 µm² of metal on a 1 nm grid is
88 000 dbu² and has no integer root. The deck author rounds, and the rounding is
not symmetric in consequence: **down** under-states the two minima and **up**
over-states `cheesing`'s maximum, and both of those are the direction that
reports nothing. That makes it a fail-open expressiveness gap rather than a
precision one, and `drc` cannot close it from inside a body — it has no way to
know which area was meant.

The fix is a `ParamValue::Area(DbuArea)` variant converted in `ingest` against
`grid²`, which costs one match arm in `parse_deck`, one in each `square` call
site here, and nothing in the `DbuArea` columns downstream. A variant on a
frozen enum in another crate, so a bug report and not a body. The `ponytail:`
comment that used to carry this as spendable debt
(`crates/drc/src/ruleset.rs:173`) now points here instead.

**`color_into`'s `Exhausted` arm cannot be reached deterministically.** Left,
deliberately. `COLOR_SEARCH_BUDGET` is a crate const *by decision*, documented at
the site — "a caller that could raise it would be tempted to raise it until the
answer came out clean". Making it a parameter would undo the decision. The law
that survives either verdict is the right cover.

Narrower now than when it was filed: `colors == 2` no longer searches at all —
the bipartite pass in `crates/drc/src/rules/patterning.rs` answers it exactly —
so `Exhausted` is unreachable for the double-patterning case and the arm is only
live from three masks up.

**`color_into` has nowhere to hang reusable scratch, so it allocates per call.**
`color_into(node_count, conflicts, colors, out)`
(`crates/drc/src/rules/patterning.rs`) builds a CSR adjacency, a
saturation-by-colour matrix, a three-column search stack and a `SatQueue` on
every call, and `check_multi_patterning` calls it once per rule row. "Nothing
allocates per iteration" cannot be met from inside the body. The resolution is a
`ColorScratch` parameter, matching the `Scratch` the twenty-six `check_*`
transforms already take — a signature change, so not a Phase-4 edit. The
`ponytail:` comment at the site is the marker.

**`ValidatedLayer` cannot map a validated polygon back to the store row it came
from.** `ring_poly` is the provenance column and it is private
(`crates/core/src/view.rs:81-87`); `get(store, idx) -> PolygonRef` hands out
coordinates, a bbox and an area, and no `PolyId`. The consequence is in
`check_multi_patterning`, whose colouring nodes have to be *store rows* rather
than validated polygons, because a `Violation` names a `PolyId`. A hole is drawn
as its own row, so it becomes its own colouring node and can be pushed onto a
different mask from the shape it is a hole in — a constraint the layer does not
have. Adding a node the physical layer does not have is the same non-monotone
move as skipping a figure merge, and it can turn an odd cycle on or off, so the
direction is **fail-open**, not merely coarse.

The touching-figure half of that gap is now fixed without the provenance
(`components_into` over the same candidate list the spacing family uses, labels
being the minimum row so a figure still resolves to a `PolyId`). The hole half is
not reachable that way: it needs containment, which is exactly what validation
already computed and then hid. A `PolygonRef::source() -> PolyId`, or a
`ValidatedLayer::poly_source(idx)` beside `bboxes()`, is the addition — a
widening, so not a Phase-4 edit.

**MOVED — `check_antenna` and `check_antenna_car` cannot reach the ratio**, and
**`check_antenna_car` cannot reach the per-stage connectivity its own doc comment
promises.** Both entries were about `crates/drc/src/rules/antenna.rs`, which is
deleted: the antenna family is `erc`'s. The connectivity half is still open and
is restated against `erc::Design` under `## the antenna family` at the end of
this file. `drc::Design` still carries `nets` and `devices` — a frozen signature
— and no rule in the crate now reads either; that is recorded at
`crates/drc/src/lib.rs:97`.

**RESOLVED — five rule doc comments conflicted with the frozen
`testgen::violation` module doc**, which claims authority explicitly. Resolved in
favour of testgen in every case, because a midpoint has no winding, no pair
order and no four-way corner sharing between windows:

| rule | now reports at | site |
|---|---|---|
| `check_min_edge_length` | the edge's midpoint | `crates/drc/src/rules/width.rs:769` |
| `check_corner_to_corner` | the midpoint of the closest vertex pair's segment | `crates/drc/src/rules/spacing.rs:871` |
| `check_min_enclosure` | the midpoint of the deficient margin | `crates/drc/src/rules/overlay.rs:200` |
| `check_min_enclosed_area` | the centre of the hole's bounding box | `crates/drc/src/rules/area.rs:162` |
| `check_density` | the centre of the window | `crates/drc/src/rules/area.rs:196` |

The root cause is fixed once rather than five times: a "Where a violation is
reported" section at `crates/drc/src/rules/mod.rs:57` states the crate-wide
convention — `at` is the midpoint of the thing measured — and names
`check_off_grid` and `check_angle` as the two deliberate vertex exceptions. That
covers every rule whose doc stated no coordinate at all (`min_spacing_diff`,
`eol`, `prl`, `wide_dependent`, `min_extension`, `overlap`,
`max_distance_to_tap`, `via_array_spacing`).

Note the earlier claim that "the suite follows testgen throughout" was wrong:
all five tests were written to the *rule* docs and overrode
`case.expected.at`. The test side is what moved.

**RESOLVED — the four coordinates `NEED_TESTING` recorded as left open.**
`min_enclosed_area` by the table above; `check_asymmetric_enclosure` restates its
own coordinate at `crates/drc/src/rules/overlay.rs:220` (the midpoint of the
margin `worst_axis_best_side` named); `check_multi_patterning` fixes all three
of its unstated columns at `crates/drc/src/rules/patterning.rs:124` (`at` = the
centre of the named shape's bbox, `measured` = `Count(colors + 1)`, `limit` =
`Count(colors)`, `shape_b` = `None`); and `check_min_area` / `check_cheesing`
(`crates/drc/src/rules/area.rs:137`, `:178`) report at the centre of the **first
rectangle of the figure's canonical decomposition** — derivable, canonical and
always inside, which a bbox centre is not for an L or a U.

One more vague point was aligned in passing: `check_redundant_via`
(`crates/drc/src/rules/via.rs:91`, the centre of the cut). The same was done for
`check_antenna` / `check_antenna_car`, which have since been deleted with the
rest of `drc`'s antenna family.

**`check_angle`'s measurement conflicts with `ShapeKind::Angle`, and here the
suite resolves it the other way.** The rule doc is explicit and principled:
measure the count of allowed directions matched (zero) against a limit of one,
because an inexact angle in degrees is the tolerance band wearing a different
hat. The `drc` side is already correct; the edit lands in `testgen`'s
`ShapeKind::Angle` doc.

**RESOLVED — the deck's rule-kind strings were stated nowhere.** (Filed under
`## engine`.) `pub const KINDS` at `crates/drc/src/ruleset.rs:188` and
`crates/erc/src/ruleset.rs:20`; `RuleSet::from_deck` points at it
(`crates/drc/src/ruleset.rs:105`).

**RESOLVED — `Violations` derives no `PartialEq`.** See `## report`.

**`Scratch`'s no-allocation-per-row claim is unverified.** Would need an
allocation-counter `*_observed` seam in this crate. That is a new interface
rather than a defect resolution, and `docs/TESTING.md`'s gate for it cannot run
until Phase 4. The one `drc` item needing a design decision rather than a
sentence.

---

## erc

**RESOLVED — `IntentMap::is_usable`'s doc comment said the opposite of the
name.** `crates/erc/src/facts.rs:229-239` now reads "True when there **is**
something here to check against", names the six-rule gate, and states the sense
explicitly. Matches what the tests and all four call sites already assumed.

**RESOLVED — `check_ir_drop`'s doc comment contradicted itself on `examined`.**
Resolved toward the last line, which is the reading the tests assert:
`crates/erc/src/rules/electrical.rs:171-178`. A net with none of the three
limits is out of scope, its nodes are not counted, and a deck limiting nothing
yields `examined == 0`. Consistent with `check_em_current_density`, which
already stated that convention for an unlimited layer.

**RESOLVED — `check_em_current_density` and `check_electromigration` took no
`Grid`.** Added as argument three to both —
`crates/erc/src/rules/electrical.rs:229` and `:276` — with the doc stating that
`Grid::to_length` is the only `Dbu`-to-`Length` route and that neither `Solved`
nor `IntentMap` carries one. `RunInputs::grid` at
`crates/erc/src/ruleset.rs:150` supplies it from the dispatcher.

**RESOLVED — `check_electromigration` and `check_reliability` took no
temperature input.** `operating_temperature: Qty<Temperature, {prefix::BASE}>`
at `crates/erc/src/rules/electrical.rs:276` and
`crates/erc/src/rules/reliability.rs:169`, plus
`RunInputs::operating_temperature` at `crates/erc/src/ruleset.rs:158`. Chosen
over the two other candidates: a per-edge `PowerGrid` column would silently
desynchronise every test-built grid, since the columns are pushed individually,
and neither `SolveConfig` nor `IntentMap` has a source for it either. The
reference-versus-applied distinction is written down, because collapsing the two
makes the derating unity — fail-open. A `ponytail:` comment names the ceiling
(uniform, no self-heating) and the upgrade path.

**RESOLVED — `EmCurrentDensityTable` gave a via edge a dimensionally wrong
density.** New column `max_current_per_cut` at
`crates/erc/src/rules/electrical.rs:94`, parallel to `max_density` in the same
CSR and mirroring `ElectromigrationTable`. `check_em_current_density`'s doc
(`:200-215`) states the compare per `EdgeKind`: metal against `max_density`, via
against `max_current_per_cut`, never crossed.

**RESOLVED — `Scratch::shrink` and `SolveScratch::shrink` have no observable
effect.** Recorded as accepted equivalent-mutant sites at the source, per
`NEED_TESTING`'s own second option — `crates/erc/src/lib.rs:205-215` and
`crates/erc/src/power.rs:346-349`. Deliberately *not* resolved with a capacity
accessor: that widens the interface of a type whose doc says which buffers exist
is an implementation question.

**`resolve_intent_into` cannot be reached with a non-empty `DesignIntent`.**
Unblocked in principle by `ingest::parse_intent`; the `erc` tests have not been
rewritten onto it yet. Nothing in `crates/erc/` could have made it reachable.

**`check_reliability` cannot vary the applied temperature per node.**
`operating_temperature` is one scalar for the whole run
(`crates/erc/src/rules/reliability.rs`). A design with a hot spot ages faster
there than the model can say, and the Arrhenius factor is the term most
sensitive to it. The upgrade needs a temperature column keyed the same way as
`PowerGrid::node_voltage`, or an applied-temperature field on `IntentMap` — both
Definition-Phase decisions, and the same one `check_electromigration` needs. The
ponytail pass left the code as it is and rewrote the comment to point here.

**`SpatialIndex` cannot index a net-filtered subset of a layer, and has no
nearest query.** `SpatialIndex::build_into(store, layer, out)`
(`crates/core/src/index.rs:73`) takes a `LayerId` and files every row on it;
`candidate_pairs_into` / `cross_layer_pairs_into` are distance-*bounded*, and
`gather_near` is private. `reliability::nearest_supply` wants the nearest
polygon on a *declared supply net* — a subset of one or more layers — and wants
the exact distance even when it exceeds the row's `max_tap_distance`, because
that distance is the reported measurement. So the indexed form is unreachable:
it needs either a `build_into` over a `PolyId` column, or a nearest query on
`SpatialIndex`. The ponytail pass took the reachable half — the supply bounding
boxes are gathered once per call into `Scratch::boxes` and scanned as one
contiguous `bulk::reduce`, instead of re-walking each supply net's polygon list
per ring — and left the asymptotic ceiling here.

**`core::bulk` has no payload-carrying compact, and four sites in
`rules/reliability.rs` want one.** `check_reliability`'s node loop,
`check_hv_domain`'s device loop and both halves of `check_esd_latchup` keep a
row only to write something the predicate computed, at a data-dependent row
count. The combinator reference names the shape as absent and settles it against
a real body in the Implementation-Phase. A note, not a defect in a frozen
signature: the four sites are correct as raw loops until it exists, and their
comments now say so rather than reading as debt this file owes.

**Three one-sentence gaps `NEED_TESTING` names and this file does not.** Each
would unlock a closed form and each freezes a numeric convention, so each wants
a decision rather than a default: `AntennaElectricalTable::diode_credit`'s area
unit, `AntennaMeasure::Sidewall`'s perimeter-times-thickness convention, and
`DensityCmpTable`'s window iteration order.

---

## lvs

**RESOLVED — `hierarchical::ComparisonPlan` had three private columns, no
accessor and no `PartialEq`.** The three columns are `pub`, the type derives
`PartialEq, Eq`, and the row-parallelism and non-increasing-depth invariant is
stated — `crates/lvs/src/hierarchical.rs:29-45`. The order is directly assertable
and a plan is hand-buildable for `run`.

**RESOLVED — `PlanError::Cyclic`, `Inconclusive::AmbiguousTop` and
`MissingSubcircuit`.** The root cause was `ingest::Netlist` having no cell-to-cell
edge; the instance table under `## ingest` supplies one and `lvs::plan` needs no
change. Not yet exercised by a test.

**`hierarchical::run` takes one graph pair for a multi-cell plan.** Still open,
and not a one-sentence fix. `pairs: &[(LayoutGraph, RefGraph)]` parallel to the
plan rows is the obvious shape, but the module doc also promises that a matched
cell is *abstracted into its parent's graph* and a failed one *flattened into
it*, which needs mutable per-cell graphs or a graph-provider seam. Guessing here
would freeze the wrong one and invalidate `tests/hierarchical.rs`.

**RESOLVED — `compare::interpret` had no constructible `Partition`.**
`Partition::from_classes(Vec<ClassId>, Vec<ClassId>) -> Self` at
`crates/lvs/src/refine.rs:143-176`, with a real body; `class_count` is derived
via `bulk::reduce` so a caller cannot state a count that disagrees with the
columns. Two inline `#[cfg(test)]` cases cover it.

**`checks.rs` in its entirety is unreachable from a test.** Unblocked by the
`topology` constructors; the `lvs` tests have not been rewritten onto them yet.

**`check_topology`'s `Violation` shape is unresolvable as an addition.** Still
open. `Violation` needs `rule: StrId`, `layer`, `at` and `shape_a`, and
`check_topology` takes only a `LayoutGraph` — no `StrTable` and no rule table, so
it cannot even name itself. The workspace-grain fix is a `rule: StrId` uniform on
all six checks, matching how every DRC rule gets its id from its table, plus
`&DeviceTable` and `&GeometryStore` to turn a device row into a point via
`marker`. Three new parameters across six signatures; it wants a decision.

**RESOLVED — `Netlist` carried no terminal roles.** The position-to-role table
is stated on `from_reference_into`'s doc at `crates/lvs/src/graph.rs:114-133`,
agreeing with `topology::recognise_into`. The `ingest` half is under
`## ingest`.

**RESOLVED — `from_layout_into`'s projection was unstated.** Now
"index-preserving": graph device row `k` is `DeviceId(k)`, net row `k` is
`NetId(k)`, terminal order preserved, `port_net` ascending —
`crates/lvs/src/graph.rs:94-102`. This is the half of the `check_topology`
defect above that costs nothing: the index correspondence a `DeviceTable`
parameter would have to rely on is now stated.

**RESOLVED — `Graph`, `Partition` and `ComparisonPlan` derived `Debug` but not
`PartialEq`.** `Graph` / `LayoutGraph` / `RefGraph` derive `PartialEq` only, not
`Eq`, because `param` holds an `f64` — `crates/lvs/src/graph.rs:33-38`, `:92`,
`:96`. `Partition`'s is hand-written over `class_count` / `layout_class` /
`ref_class` (`crates/lvs/src/refine.rs:48-63`) for the same reason `NetTable`'s
is: the scratch columns are not part of the value.

**RESOLVED — `Discrepancy::DuplicateName` could not say which side.**
`side: Side` at `crates/lvs/src/verdict.rs:57-67`.

**RESOLVED — `Discrepancy::ClassImbalance` had no stated emission rule.**
Documented at `crates/lvs/src/verdict.rs:73-79`: emitted only when the class
holds more than one node per side. Anything attributable is `UnpairedDevice` or
`UnpairedNet`, and both forms for one class is a double count.

**`Partition` publishes no `members(ClassId)`.** Still open, and it costs
`compare::interpret` two things at once. A class holding equal counts on both
sides is a symmetry refinement could not break; its members are unpaired without
being unpairable, and with no way to name them they cannot be held back from the
unpaired scan — so the whole comparison degrades to
`Inconclusive::UnresolvedSymmetry` and any genuine discrepancy sharing that
partition is masked (`crates/lvs/src/compare.rs`, the `unresolved()` loop). The
same absence makes the emission rule above unenforceable in the other direction:
a class that emits `ClassImbalance` also has every one of its members counted
individually by `report_unpaired`, which is the double count `verdict.rs:73-79`
forbids. Both are fail-closed — an over-report and an `Inconclusive`, never a
false `Match` — which is why they ship. The shape is
`fn members(&self, class: ClassId) -> (&[u32], &[u32])` over a CSR the tallies
pass already builds.

**`Discrepancy` cannot say "declared on one side only".** Open, and it bounds
what `compare::compare_params` is entitled to conclude. That body now joins the
two sides by parameter name rather than by slot, which removed a silent
`min(len, len)` truncation, but a name only one side declares is still passed
over: `ParameterMismatch` carries `layout_value: f64` and `ref_value: f64`, so
reporting a one-sided parameter means inventing a number for the side that has
none. `ParameterAbsent { side, layout_device, ref_device, param, value }` is the
shape. Widening it is blocked upstream in any case: `graph::from_layout_into`
projects no layout parameter at all — stated in its own body, for want of a
`StrTable` and a `Dbu` scale — so an outer join would today report every
reference parameter of every device as a difference.

---

## pex

**RESOLVED — `matvec::ObserveMatVec` had no entry point.** Private
`CpuMatVec::apply_observed<O: ObserveMatVec>` with `MatVec::apply` delegating
through `&mut NoObserve` — `crates/pex/src/quasistatic/matvec.rs:104-111`,
`:127-129`, matching `core::index::candidate_pairs_into`. `CpuMatVec::build(&Mesh)`
was added alongside (`:80-92`) because the seam is inert without it: `Default`
was the only constructor, so `dim` was always zero and an adapter test observed
nothing. **Its body is `todo!()`** — `CpuMatVec` declares no fields, so the FMM
structures are a Phase-4 decision, as is `GpuMatVec::upload`.

**RESOLVED — `ground_capacitance` and `coupling_capacitance` took no `Grid`.**
`crates/pex/src/analytical.rs:54-77` and `:86-102`, each with a Units paragraph
closing the aF/µm²-to-`Dbu` chain. `extract_into` (`:115-125`),
`extract_net_into` (`:127-147`) and `extract_devices_into` (`:149-166`) thread
it through.

**RESOLVED — `extract_net_into` and `extract_devices_into` had no stated buffer
contract.** Both **append and do not clear**, at
`crates/pex/src/analytical.rs:127-147` and `:149-166`. That is the only choice
that composes with `extract_into`, which clears once and then calls per net.

**`analytical::extract_devices_into` has no device-model parameter.** Still
open. No device-model type exists anywhere in the workspace and `ProcessStack`
has no gate-oxide column, so documenting the per-family formula would mean
picking Cox from `dielectric_k[gate]` and `thickness_nm[gate]` *and* deciding
which `DeviceParam` rows carry W and L — and that second half is itself
unresolved under `## topology`. Blocked on that.

**RESOLVED — `quasistatic::mesh::build_into` produced metres from grid units
with no `Grid`.** `stack: &ProcessStack` and `grid: Grid` added at
`crates/pex/src/quasistatic/mesh.rs:80-102`; without the stack there is no z
extent (the store is 2-D), no source for `Mesh::epsilon`, and
`MeshError::MissingThickness` was unraisable regardless.
`quasistatic::extract_into` gained `grid` to hand down
(`crates/pex/src/quasistatic.rs:106-121`).

**`MeshError::MissingThickness` still cannot distinguish absent from zero.**
`ProcessStack::thickness_nm: Vec<f64>` cannot express absent. That column is
`crates/ingest/src/deck.rs:227` — an `ingest` edit.

**`MeshError::EmptyConductor` is still unreachable.** Every net a `NetTable`
yields has geometry, and an out-of-range `NetId` is a bounds bug rather than this
condition.

**RESOLVED — `ParasiticNetwork` had no `PartialEq` and no stated node-order
invariant.** `PartialEq` at `crates/pex/src/network.rs:63`; the invariant at
`:45-62` — each net's nodes are one contiguous ascending-`NetId` range,
established by both `extract_into`s, not enforced by `push` and not restored by
`sort_canonical`. That is the invariant `export::parasitic::write_dspf` was
already written as if held.

**RESOLVED — `topology::NetTable` has no constructor.** See `## topology`. The
`pex` tests still route through `extract_nets_into`, so the coupling noted here
remains until they are rewritten.

**`analytical::extract_into` cannot emit a coupling element.** Open, and it is
the one shortfall in this crate that changes a reported number:
`coupling_capacitance` is implemented and exercised and nothing calls it, so an
analytical total is short by the whole lateral term. Two signatures hold it
shut, and closing either alone is not enough:

- `analytical::extract_net_into` allocates one net's nodes *and* writes that
  net's elements in one pass, so the higher net of a pair has no node yet when
  the lower one is written. A later pass would put small `from` values behind
  large ones, and `from`-ascending-without-a-sort is what
  `tests/analytical.rs::extraction_emits_the_order_sort_canonical_would_have_produced`
  pins. The shape is node allocation split out — an `alloc_nodes_into` taking
  the whole `NetTable`, then a per-node emission pass — which changes
  `extract_net_into`'s signature.
- `ingest::deck::ProcessStack` has no lateral column, so
  `coupling_capacitance`'s `coefficient_af_um` has no source in the deck.
  `dielectric_k` and `thickness_nm` describe the interconnect dielectric, not a
  per-layer coupling coefficient. Same objection as
  `extract_devices_into`: synthesising the number is worse than the shortfall.
  A `lateral_cap_af_um: Vec<f64>` beside the other five is an `ingest` edit and
  a deck-schema addition.

Stated at `crates/pex/src/analytical.rs`, under `# Coupling is not emitted by
this path`; the ledger entry is in `docs/NEED_TESTING.md`.

**`analytical::extract_net_into` has nowhere to hang scratch, so its nodes are
chained in `PolyId` order.** Open. A comb's fingers come out in series where
they are really parallel stubs off the rail; the net's total resistance is
right, its distribution is not. The fix is a spanning tree over the touch graph
plus a buffer to merge the tree's edges against the ground terms so the emitted
elements stay `from`-ascending — two allocations, in a function `extract_into`
calls once per net, which is the per-iteration allocation `CONVENTIONS.md` §4
bans. Exactly the scratch-parameter defect already recorded for
`topology::intra_layer_edges_into` and `topology::via_edges_into`, and it wants
the same resolution: one `Scratch` parameter, added in the same pass as theirs.

The other half of that site's old ceiling is **closed** in a body and needs no
signature: area and perimeter are now the polygon's own — `core::ops::area2`
over the vertex ring and a `bulk::reduce` fold of edge lengths — and the
resistive length and width are the sides of the rectangle with that area and
that perimeter rather than the sides of the bounding box.

---

## export

**RESOLVED — `deck::LayerTable` and `PortTable` had no constructor.** See
`## ingest` and `## topology`. `gds::write_store`'s signature was correct as
frozen and needed no change here.

**RESOLVED — `WriteError` derived no `PartialEq`.** `PartialEq, Eq` at
`crates/export/src/lib.rs:38`; all three payloads (`String`, `&'static str`,
`u32`) are `Eq`.

**RESOLVED — `format_f64`'s precision was unstated.** Six digits after the
decimal point, never an exponent (`{:.6}`), with the sub-`5e-7` collapse named —
`crates/export/src/json.rs:61`. `write_report`'s "fixed precision" sentence
(`json.rs:36`) points at it rather than restating it. Decimal places rather than
significant figures because six significant figures would round `7654321` to
`7654320`, which `tests/json_report.rs` searches for as a literal.

**RESOLVED — `ParasiticNetwork`'s node grouping had no stated invariant.** The
invariant belongs on the producer and is now there; see `## pex`.

**`format_f64` on a non-finite input is unspecified.** New, not previously
filed. `{:.6}` on a `NaN` yields `NaN`, which is not valid JSON — fail-open. Two
defensible resolutions: writers must never hand it a non-finite value, enforced
by `debug_assert`; or it returns `WriteError::Unrepresentable`, which means
changing `fn format_f64(f64, &mut String)` to return a `Result`. Picking one
freezes a decision the Definition-Phase did not make.

**The SPEF / DSPF / JSON record schema is unstated, and was not guessed at.**
SPEF is IEEE 1481; inventing a subset fixes which tools can parse our output,
which is a Plan-Phase-sized decision rather than a doc sentence. The cheaper
resolution `NEED_TESTING` itself suggests is a `gpurify-ingest` SPEF reader,
turning it into the same `parse -> write -> parse` law the GDS path uses.

**`netlist::write_spice` takes no `Grid`.** New, not previously filed. A
`DeviceMeasure::Length(Dbu)` therefore has no unit in the emitted SPICE — the
same defect class as `pex::analytical`, `erc`'s electromigration rules and
`report::Measurement`, all now resolved. Recorded in a test doc comment at
`crates/export/tests/netlist.rs:93`. Adding the parameter breaks
`tests/netlist.rs` and `tests/determinism.rs`; it should land in the same pass
as those two files.

**`ParasiticNetwork` has no node position column, so a DSPF sub-node record
cannot carry one.** New, filed by the `ponytail:` spend-down pass over
`crates/export/src/parasitic.rs`. DSPF's `*|S` record is `(subnode_name x y)`,
and the old tree emitted exactly that
(`reference/pre-rewrite:crates/pex/src/analytical/dspf.rs:69`, from a node that
had an `x` and a `y`). The new `ParasiticNetwork` has `node_net` and
`node_layer` and no coordinate column, and
`write_dspf(network, ports, strings, header, out)` is handed no geometry to
recover one from — so the writer emits `*|S (name L3)`, a layer number sitting
where the format's reader expects a position. Three options from inside
`export`, all bad: the wrong token (what it does), a short record that parses
into a different circuit, or refusing every DSPF outright. The fix is a
`node_x` / `node_y` column on `ParasiticNetwork`
(`crates/pex/src/network.rs:63`) filled by both `extract_into`s — a frozen
signature in `pex`, not a body in `export`. Stated at the site, in
`write_dspf`'s sub-node loop.

**RESOLVED, and it was a correctness gap — SPEF and DSPF accepted different
networks.** Found by the same pass. `spef_section` refuses a `*RES` or `*INDUC`
row whose `to` is `None` (`far_optional == false`), because a resistance joins
two nodes by definition. `write_dspf` carded every absent far end to `GROUND`
unconditionally, so the same broken row was a typed error in one file and a
perfectly plausible resistor-to-ground in the other — a wrong-but-plausible
parasitic file, which the module doc names as its whole reason to exist. Closed
where both writers route through rather than in the DSPF arm:
`every_far_node_present` (a `bulk::reduce` over `to` and `value`, kind-tested
through the existing `as_farads` so a fifth capacitive variant cannot diverge)
is now a third refusal in `check_canonical`, with the same
`WriteError::Unrepresentable` message `spef_section` already used. The DSPF
ground arm keeps a `debug_assert` naming the precondition. `spef_section`'s
own per-row refusal stays as defence in depth. No signature changed; the export
suite is unmoved at 57 green.

**`ParasiticNetwork` has no terminal-to-node column, so a device terminal cannot
be placed on the node it actually sits on.** New, filed by the `ponytail:`
spend-down pass over `crates/export/src/netlist.rs`. A net's parasitic nodes are
named `net:index`; the bare net name is not one of them. `write_spice` in
`Detail::WithParasitics` was carding device terminals with the bare net name, so
every device sat on a node no parasitic element touched — the RC network hung
off nothing, every device saw zero parasitics, and the file was still valid
SPICE that still simulated. That was a correctness gap, not a simplification,
and it is closed at the site: `put_terminal_node`
(`crates/export/src/netlist.rs`) attaches a terminal to its net's *first* node
through the same `parasitic::node_name` the element rows use, so both halves of
the file address the same nodes by the same text, and falls back to the plain
net name for a net the extraction produced no nodes for. The `.subckt` pin list
routes through the same function for the same reason — a pin declared as `VDD`
against devices on `VDD:0` is a floating port in a file that still simulates.
In `Detail::Schematic` the two spellings are the same string, so no byte of the
schematic output moved.

What survives is the lumping: which node a given source or drain sits on is not
knowable from `write_spice`'s parameters, so all terminals of a net land on node
zero. Resolution is a terminal-to-node column on `ParasiticNetwork`
(`crates/pex/src/network.rs:62-74`) filled by both `extract_into`s — a frozen
signature in `pex`, not a body in `export`. Note the consequence already latent
in `parasitic::put_net_name`: it refuses an anonymous net, so a `WithParasitics`
run over a design with an unnamed parasitic net is refused outright even though
SPICE numbers anonymous nets elsewhere. Pre-existing, fails closed, left as
found.

**`PortTable` publishes no iterator, so `.subckt`'s pin list is built by asking
every net whether it is a pin.** New, filed by the same pass. `PortTable`'s
`net` and `name` columns are private and the only reads are `name_of(NetId)`,
`net_of(StrId)` and `len()`. The port list is the named nets in ascending
`NetId` — a cell's pins, hundreds — but `write_spice` has to walk `0..net_count`
(millions) and binary-search each one, so the scan is the wrong way round by the
ratio of nets to pins. No search over this interface does better: `name_of` is a
membership test and membership is not monotone in `NetId`, so there is nothing
to bisect on. Resolution is an iterator or a row accessor on `PortTable`
(`crates/topology/src/port.rs:37-78`) yielding `(NetId, StrId)` in the ascending
order the columns are already kept in. `PortTable::net_of`'s own linear-scan
`ponytail:` (`port.rs:55-59`) wants the same widening from the other direction.

---

## engine

**RESOLVED — `pipeline::LoadError::NoGrid` was unreachable.**
`Inputs::grid: Option<Grid>` at `crates/engine/src/pipeline.rs:21-31`, the
variant's message and doc rewritten (`:145-152`), the ordering consequence
stated on `load_into` (`:113-121`) and a postcondition on `Loaded::grid`
(`:75-80`). Not a judgement call: `ingest::read_deck(path, grid, strings)` takes
a `Grid` by value and no `ingest` interface yields one before a `Deck` exists,
so `load_into` was unimplementable, not merely untestable. `Option` rather than a
bare `Grid` is what keeps `NoGrid` reachable and `Inputs: Default` honest.

**RESOLVED — `Common::strict_layers` had no landing place.** (Filed under
`## cli`; the edit lands here.) `Inputs::unknown_layers: UnknownLayers` at
`crates/engine/src/pipeline.rs:37-47`, plus a hand-written `impl Default for
Inputs` (`:50-64`) defaulting it to `Reject` — a derived one would have picked
whichever variant `ingest` declared first, and the wrong one drops geometry
silently. `UnknownLayers` rather than the `bool` `NEED_TESTING` named, because it
is the exact value `read_layout` takes, so `load_into` is a pass-through rather
than a remap. The cli mapping is stated at the site.

**RESOLVED — `run::EngineError` had no variant for `DrcError` or `ErcError`.**
`Drc(#[from] …)` and `Erc(#[from] …)` at `crates/engine/src/run.rs:169-181`, with
`run_checks` stating that a `from_deck` failure is an error and never a skipped
rule (`:133-140`). Both inner types are `Debug + Clone + Error`, so
`EngineError: Clone` survives.

**RESOLVED — `run::Summary` derives no `PartialEq`.**
`crates/engine/src/run.rs:86`.

**`run::Summary` still derives no `Default`.** Skipped deliberately: it needs
`StageStatus: Default`, and the only candidate is `NotSelected`, which makes
`Summary::default().passed() == true` — a default that passes. Nothing in the
suite uses it.

**RESOLVED — `Summary::passed` ignored the LVS verdict.** The mapping, not the
verdict field: `run_lvs` turns every `Discrepancy` of a `Verdict::Mismatch` into
one `Severity::Error` row of `Outputs::violations`
(`record_discrepancies`, `crates/engine/src/run.rs:691`), so a mismatch is a
nonzero `Summary::errors` and `errors == 0` was already in the criterion. No new
`Summary` field, no signature change, and `clean_run()`'s literal in
`tests/summary.rs` still holds — `passed()` itself is untouched. Chosen over the
verdict field because a bool tells a reader nothing about *which* device
mismatched, while a violation row puts the finding in the report a human opens
rather than only in the exit code a CI job reads. The doc at
`crates/engine/src/run.rs:120-132` now states the criterion instead of the
fail-open.

**`report::Violation` cannot describe a finding that is not geometric.** New,
filed by the resolution above. `layer`, `at` and `shapes` assume a DRC/ERC
finding; an LVS discrepancy is a difference between two netlist graphs and has
none of the three. The convention chosen is out-of-range sentinels, stated at
`crates/engine/src/run.rs:647-678`: `LayerId(u16::MAX)`, `PolyId(u32::MAX)` and
`None` for the second shape. Two consequences are real and neither is papered
over:

- **`at` is the origin, and that is a coordinate this finding does not have.**
  It is the one field that cannot be filled honestly. `layer` and `shape_a` are
  the sentinels that tell a reader not to navigate to it. The fix is a
  `Violation::at: Option<Point>`, or a `Location` sum type with a
  `Node { side, index }` arm — a frozen signature, so it is filed rather than
  taken.
- **Two discrepancies of one kind produce two identical rows.** `Violation` has
  no field for a device or net index, so the attribution stays on
  `Outputs::lvs`. Byte-determinism survives (identical rows permute to the same
  table), but a reader counting rows learns the number of differences and not
  which ones. Same fix as above.

`export::gds::write_markers` refuses a table holding these rows with
`WriteError::Unrepresentable`. That is deliberate and correct — there is no
marker geometry to draw for a netlist difference — and no caller in the tree hits
it: the CLI does not write markers.

**`run_checks` cannot intern the rule id of a violation it originates.** New,
same resolution. It borrows `Loaded` shared, so `StrTable::intern` is not
callable, and `StrTable::resolve` panics on an id the table never issued.
Worked around rather than fixed: `load_into` interns the six names of
`run::LVS_RULE_IDS` (`crates/engine/src/pipeline.rs:214`), which covers every run
that read its inputs from disk, and `lvs_rule_id` falls back to `StrId(u32::MAX)`
for a `Loaded` assembled by hand — a loud panic in a writer, chosen over
`StrId(0)` silently attributing the mismatch to whatever name was interned first.
The fix is `run_checks` taking `&mut StrTable`, or a `Violation::rule` that can
carry a `&'static str`; both are frozen signatures.

**RESOLVED — `pex::ParasiticNetwork` has no `PartialEq`.** See `## pex`.

**RESOLVED — the deck's rule-kind strings were stated nowhere.** See `## drc`.

**RESOLVED — `Summary::rules_clean` was unassertable.** One sentence at
`crates/engine/src/run.rs:110-113`: `rules_clean` is evidence, not criterion.
Not a new decision —
`tests/summary.rs::selecting_no_check_at_all_is_a_pass_because_nothing_was_denied`
already fixed it with `rules_clean: 0` and an expected pass.

---

## cli

**RESOLVED — `fn main() -> ExitCode` held the exit-code contract with no pure
function for it.** `fn exit_code(&Result<Summary, EngineError>) -> ExitCode` at
`crates/cli/src/main.rs:36-56`, with a real body; `main`'s doc delegates the
criterion to it (`:21-33`).

**RESOLVED — `crates/cli/Cargo.toml` had no dev-dependency on `gpurify-core`.**
Added. `LayerId` and `PolyId` can now be named in this crate; `format.rs`'s
`push_row!` macro and `scale_corpus` fixture remain as they are, and are now a
choice rather than a workaround.

**RESOLVED — `Args`, `Command`, `Common` and `ArgError` derived no
`PartialEq`.** `PartialEq, Eq` on all four —
`crates/cli/src/args.rs:10`, `:24`, `:47`, `:89` — matching `Format`, which
already had them.

**RESOLVED — `parse(argv: &[String])` did not say whether `argv` includes the
program name.** Fixed as excluded at `crates/cli/src/args.rs:83-87`, matching
what the test module already assumed.

**RESOLVED — `main.rs` said "`clap` lives here and only here" and `clap` is not
a dependency.** Rewritten at `crates/cli/src/main.rs:12-16`: the parser is
hand-written in `args.rs`, no parser crate is a dependency, which is what keeps
`parse` a pure `&[String]` function.

**RESOLVED — `write_violations` said nothing about the non-violation half of
`Outputs`.** All four columns' treatment is stated at
`crates/cli/src/format.rs:11-34`. `lvs` is rendered here because it is forced,
not chosen: `write_summary(&Summary, &mut String)` takes no `StrTable` and no
`Verdict`, so this is the only text function that *can* print a `Discrepancy`.
`parasitics` is stated as not rendered — that is export's SPEF and DSPF.

**RESOLVED — `--check-determinism` had no callable form.** Not a signature
defect after all: the second of the two shapes the entry named — the loop
hoisted out of `main` — needs nothing from `engine` that is not already public,
because `main` calls `load_into` / `extract_into` / `run_checks` itself and so
owns every buffer a second pass has to re-fill. `crates/cli/src/main.rs` now
runs the pipeline inside a two-pass loop with fresh buffers per pass. No
`engine::run_twice`; `engine::run::run` would not have served either, since it
drops the `Loaded` the renderers need.

Both open questions are answered at the site, with the reasoning in the comment
above the loop. *What is compared*: the rendered report, byte for byte, plus the
`Summary` beside it — rendered bytes are what `export` promises to reproduce, so
comparing them covers the writers as well as the checks, and the `Summary` is
where the exit code comes from. *Which two thread counts*: whatever `to_inputs`
produced, then any other value, flipped between passes. `RunOptions::threads`
names byte-identical output *at any value of it* as the property the flag exists
to catch, so a re-run at the same count would pass a run whose results depend on
how the work was divided.

---

## topology, from the `ponytail:` spend-down pass

**`core::bulk` has no payload-carrying compact, no segmented reduce and no
segmented two-column write, and `recognise_into` needs all three.** Two raw
loops survive in `crates/topology/src/device.rs` for exactly this reason, both
now commented as filed rather than as debt:

- `device.rs:~300` compacts marker polygons whose terminal slots are all bound.
  The predicate is a fold over a per-marker *run* of `bind` (segmented reduce)
  and the survivors carry a payload the predicate did not compute
  (payload-carrying compact).
- `device.rs:~345` writes `width` rows into `terminal_net` and `terminal_role`
  from one input row (segmented two-column write).

`crates/core/src/bulk.rs`'s own decision table names all three as missing and
says the shape is settled "against a real body". This is that body — but a
fifth entry point is a new interface in `gpurify-core`, not a Phase-4 body, so
it is filed here instead of invented. `lvs::graph` (`graph.rs:225`) is the
second caller for the two-column write, so the shape now has the two adapters
the two-adapter rule asks for.

**RESOLVED — `net::polys_intersect` was private and `device.rs` needed it, so it
was written twice.** Not a signature defect at all in the end: both copies were
private helpers, so the fix was inside the crate the whole time and only looked
blocked because each agent saw one file. `polys_intersect` is now
`pub(crate)` in `net` and `device.rs`'s `polys_meet` is deleted along with the
`rings_meet`, `ring_edge` and `point_inside` it dragged with it — 110 lines, and
one place for the fail-open argument rather than two. `device` already imported
`NetId`/`NetTable` from `net`, so the fold adds no coupling.

The two copies were not identical, and the survivor is the better one:
`device`'s `rings_meet` was the naive O(n×m) scan, `net`'s is that same scan
below `DIRECT_PAIR_BUDGET` and a plane sweep above it. Device recognition now
gets the sweep for free on a large marker, and cannot regress on a small one —
`net::tests::the_sweep_and_the_exhaustive_scan_agree_on_every_ring_pair` is the
differential test pinning the two paths to one answer, and it now covers both
callers.

**`DeviceRecognition` still cannot state a channel direction, so `Width`,
`Length` and `Fingers` remain unmeasurable.** Narrowed, not resolved:
`DeviceParam::Area` is now measured from the marker polygon
(`crates/topology/src/device.rs`, the per-device loop), because "one polygon on
the marker layer is exactly one device" makes the marker the device's extent and
its area needs no convention to be invented. Separating `W` from `L` still does.

## drc, from the `ponytail:` spend-down pass

**`ValidatedLayer` publishes no store-row provenance, so
`drc::rules::spacing::wide_flags_into` cannot give a hole its own polygon's
wide verdict.** `validate_layer_into` folds each clockwise store row into the
counter-clockwise boundary it punctures, and `ValidatedLayer` then exposes
`len()`, `get(idx)` and `bboxes()` — nothing that maps a validated polygon back
to the store rows it was built from, and nothing that names the boundary a hole
was bound to.

`wide_flags_into` needs one flag per *store* row, because the candidate pairs it
serves are store rows. It gets there by walking the layer, recomputing the
winding, and counting the counter-clockwise rows to recover the index into
`ValidatedLayer` — which works for boundaries and leaves holes with no verdict
of their own. A hole therefore inherits the whole layer's widest verdict. That
direction fails closed (over-applying the wide limit costs a re-check;
under-applying it misses a violation), so it ships, but it is imprecision the
signature forces rather than a choice.

Resolution is a store-row column on `ValidatedLayer` — `poly_store_row: Vec<u32>`
plus a `ring_owner` for the holes, or a single `store_row -> Option<u32>` map
over the layer. Either is a widened interface in `gpurify-core`, so it is filed
here rather than worked around. The same column would delete the winding
recomputation and the prefix count in `wide_flags_into` outright.

**`core::bulk` has no scan, and `wide_flags_into`'s row loop is one.** Secondary
to the above and moot if it is fixed: the running count of counter-clockwise
rows is a prefix sum, and none of `map_into` / `reduce` / `compact_into` /
`update_in_place` can carry a value from row N-1 into row N. A raw loop survives
there, commented as a shape rather than as debt. `topology`'s entry above files
the other three absent shapes; this is the fourth.

**FAIL-OPEN — every overlay measurement is taken on bounding boxes, and the same
missing provenance accessor is why.** `crates/drc/src/rules/overlay.rs`. Two
distinct rules, one blocker, and both are correctness gaps rather than costs:

- `check_min_enclosure` and `check_asymmetric_enclosure` accept a host on
  `Bbox::contains` and measure `margins(inner_box, host_box)`
  (`overlay.rs:438`). A non-convex host's box is larger than the host, so an
  L-shaped pad that leaves a via's corner uncovered reports an enclosure it does
  not give — a minimum overstated is a violation not reported. The doc on
  `margins` claimed for the whole Implementation-Phase that the transforms used
  the box "only as a prune" and confirmed containment exactly with
  `ops::point_in_ring`; **no such confirmation was ever written**, and the claim
  has now been corrected in place.
- `check_overlap` measures the *box* intersection of each pair, where
  `OverlapTable`'s own doc promises the exact boolean one and specifically names
  box-intersection over-reporting as what the old tree's `lvs` evaluator did
  wrong on the path feeding device recognition. Same direction: over-reported
  overlap, sliver passes.

Neither is reachable from `drc`. `ops::point_in_ring` takes a
`core::view::RingRef`, whose fields are private and whose only constructor is
`ValidatedLayer::get(store, idx)` on a *validated* index; a candidate pair
carries a store `PolyId`, and nothing maps one to the other.
`boolean::intersection_into` produces a `ValidatedLayer` whose `ring_poly`
provenance is private, so a figure cannot name the two shapes
`Violation::shapes` promises. Both close on the accessor the two entries above
already ask for — `ValidatedLayer::provenance(&self) -> &[PolyId]` in `core` —
which makes this the fourth site blocked on one three-line widening.

Until then the boxes are exact for the rectangles a real via, pad, tap, endcap
or strap crossing is, which is most of a signoff run and none of the cases a
signoff run is afraid of.

**`core::bulk` has no segmented reduce, and two overlay rules are one.**
`check_enclosure_rows` folds each inner shape's own run of the pair list to its
best host, and `check_max_distance_to_tap` folds each well's run to its nearest
tap. Both folds already go through `bulk::reduce`; what stays a raw loop is the
walk that cuts `pairs` into runs, because `run_of` carries a cursor from row N-1
into row N. That is the same absent shape `core::bulk`'s own decision table
names — "the fold is over a per-row *range* (`starts`/`lens`) → **none yet**".

Resolution is `bulk::reduce_segments(src, seg_starts, init, f)` in
`gpurify-core`, which is a new public interface there and so is filed rather
than worked around. `check_min_extension` needed no such thing and was moved to
`bulk::compact_into` in this pass: one pair measures one protrusion, so its
measurement is a plain filter over bulk data, and splitting the rare violation
construction into a second pass over the survivors is what made the bulk pass
branchless.

### `crates/drc/src/rules/grid.rs`

**`OffGridTable` cannot express a per-layer manufacturing pitch.** The table is
`rule: Vec<StrId>` and `pitch: Vec<Dbu>` and nothing else, so `check_off_grid`
applies one lattice to every vertex in the design. Real nodes grid metal and
poly differently, and the checker currently has to be handed the finer of the
two — which passes coarse-grid layers that are genuinely off their own pitch,
or, handed the coarser, reports every fine-grid vertex. Resolution is a
`layer: Vec<LayerId>` column plus one row per layer, which is a new public field
on a frozen table and a new column for `RuleSet::from_deck` to fill, so it is
filed rather than invented. The transform already scans one row at a time; the
row gaining a layer and the scan narrowing to `polys_on_layer` is the whole
change.

**`GeometryStore` publishes no whole-design vertex column, so both grid
transforms keep a per-polygon outer loop.** `poly_verts(poly)` hands out one
polygon's coordinates at a time and there is no accessor for `verts_x` /
`verts_y` entire, nor any `verts_layer` mapping a vertex back to its layer. Both
rules are pure per-vertex (off-grid) and per-edge (angle) arithmetic with no
pairing at all, so each *would* be one flat scan over the design's two
coordinate columns. Instead each is a raw loop over polygons wrapping a
combinator, and the per-polygon `bulk` call re-pays its `reserve` and its trip
count on rings that are typically four vertices long. Resolution is
`verts_layer: Vec<LayerId>` on `GeometryStore` plus accessors for the whole
columns — a widened interface in `gpurify-core`, filed here. Nothing about the
rules' shape changes when it lands; the outer loop is deleted, not rewritten.

**`Cols` stops at three columns, and an adjacent-pair scan over a ring needs
four.** `core::bulk`'s own doc gives the recipe as
`((&xs[..n-1], &xs[1..]), (&ys[..n-1], &ys[1..]))`, which does not typecheck:
`Cols` is implemented for `(&[A], &[B])` and `(&[A], &[B], &[C])`, and that is a
tuple of tuples. `check_angle` works around it by packing the ring into a
`Vec<Point>` with `bulk::map_into` first, so the pairing becomes the two-column
`(&ring[..n-1], &ring[1..])`. The workaround is correct and stays, but it costs
one extra pass and one 16-byte-per-vertex buffer that a fourth `Cols` impl would
delete. `core::ops::area2`'s shoelace and `core::ops::self_intersects` want the
same impl for the same reason. `bulk.rs` already says "a fourth column is an
impl, not a redesign" — it is still an addition to a sealed trait in
`gpurify-core`, so it is filed rather than made here.

---

## erc, from the `ponytail:` spend-down pass

Cases the spend-down pass could not resolve inside the frozen signatures. Each
is recorded rather than worked around, and none was papered over with a widened
parameter list.

### `crates/erc/src/rules/electrical.rs`

**`check_ir_drop` has no scratch to compact into, so the node loop stays raw.**
The named upgrade is one `bulk::compact_into` per stated limit, gathering the
node indices in scope for that limit into a caller-owned index buffer and
pushing violations over the survivors. The signature is
`(power, intent, table, out, runs)` — `out` is the violation table and `runs`
is the run log; there is no third caller-owned buffer, and a locally allocated
one would be an allocation per rule row that CONVENTIONS §4 puts on the caller.

Two things to weigh before resolving it, because the upgrade is not obviously a
win. The per-node cost that dominates is `IntentMap::limits_of`, a binary search
over the sorted `limit_net` column; the compact form runs it once per limit
rather than once per node, so it triples that search on a net stating all three.
And the three `if let Some(..)` branches it would remove are on design intent,
which is per net and therefore constant across every node of a supply — the
predictor owns them after the first node, which is the escape valve the
surviving comment already names.

Resolution, if it is wanted, is a `scratch: &mut Vec<u32>` parameter, or a
`Scratch` field of the kind `check_p2p_resistance` already takes — that rule has
the precedent, and it would make the two intent-gated node passes look alike.

**`PowerGrid` has no temperature column, so electromigration derates every edge
at one applied temperature.** `check_electromigration` takes a scalar
`operating_temperature` and hands it to `arrhenius_derating` once per rule row.
That is a DC signoff's honest ceiling, but the direction matters: self-heating
raises a carrying conductor above the applied point, a hotter conductor derates
*further*, so a uniform temperature over-states the allowed current and passes
branches a thermal solve would fail. Fail-**open**, bounded by however far
self-heating moves the edge.

Resolution is a per-edge `edge_temperature: Vec<Qty<Temperature, BASE>>` column
on `PowerGrid`, written by `power::extract_into` from a thermal model, with
`arrhenius_derating` moving inside the edge loop of `check_branches` — which
then needs the Arrhenius parameters rather than a computed `derate`. Both the
column and its writer are outside this file and frozen. Nothing below the
derating factor changes; only where the number comes from.

### `crates/erc/src/rules/supply.rs`

**`Design` carries no `Connectivity`, so
`check_soft_connection` decides conductor adjacency geometrically instead of
electrically.** The rule removes a net's resistive layers and asks whether what
is left falls into more than one component. Building that component graph needs
to know which layer pairs actually conduct into one another — the same
`deck::Connectivity` that `topology::extract_nets_into` was handed. `Design` is
`{ store, derived, nets, devices }`; `NetTable` publishes `polys_of` and
`net_of` and no adjacency, so the graph has to be rebuilt from geometry.

The spend-down pass upgraded the predicate from bounding-box overlap to the
exact shared-point test (`polys_meet`, `crates/erc/src/rules/supply.rs`), which
closed the larger half of the gap: two conductors whose boxes met and whose
outlines did not were being merged into one component, which *under*-reported
the bridge. What survives is the other direction — two conductors on
layers the deck does not connect, overlapping in plan view with no via between
them, are still read as one conductor. That is also fail-**open** for this rule
(fewer components, fewer bridges reported), and it is not reachable from this
signature.

Resolution is a `connectivity: &'a Connectivity` field on `erc::Design`, or a
`NetTable` accessor publishing the polygon adjacency extraction already
computed and discarded. The second is the better one — the edges exist during
`extract_nets_into` and are rebuilt here from scratch.

**`core::index::SpatialIndex` builds over a store layer, so a derived tap layer
cannot be indexed through it.** `check_missing_tie` accepts a derived tap —
`nsdm AND diff` is how a real deck spells one — and a `ValidatedLayer` has no
rows in a `GeometryStore`. `SpatialIndex::build_into(store, layer, out)` takes
the store and a `LayerId`, and `Scratch::index_b` exists for exactly this rule
and cannot be used by it.

The pass resolved this locally: `TapGrid` in
`crates/erc/src/rules/supply.rs` is a uniform grid over the tap *segments*, with
the same CSR shape and the same cell-size recipe as `SpatialIndex`, built and
probed inside this module. That is duplication, and it is filed here as such.

Resolution is a second entry point on `SpatialIndex` over an already-validated
layer — `build_over_layer(&ValidatedLayer, &mut Self)` — or over a bare `&[Bbox]`
with the caller owning the row numbering. `derived::prefilter` wants the same
one.

**`deck::ParamValue` can spell a length, a ratio, a count, a flag and a layer —
and nothing else, so three columns of `erc::RuleSet::from_deck` are unreachable
from a deck.** One gap, three sites in `crates/erc/src/ruleset.rs`, all filed
during the `ponytail:` spend-down rather than worked around with an invented
deck schema:

- **`antenna.collector_measure` is uniform across a row's collecting set.** The
  column is per collector because a stage can mix an area collector with a
  sidewall one, but a row carries one value per parameter name and `ParamValue`
  has no sequence variant, so the single `sidewall_thickness` a row can state is
  applied to every collector. Mixing them costs one deck row per measure.
- **`esd_latchup.clamp_model` and `esd_topological.clamp_model` are always
  empty.** A clamp is identified by a device *model name*; `ParamValue` carries
  no string and no other variant names a device, so the CSR body has nothing to
  fill it from. The guard-ring half of `check_esd_latchup` needs no clamp and
  runs; the discharge-path half then finds no path from any pad and flags every
  one of them. That is loud rather than falsely clean, which is why the row is
  still accepted at load — but a deck-configured `esd_latchup` reports a
  violation per pad and cannot be made to report otherwise.
- **`reliability.mechanism` is the rule's own id.** The mildest of the three: it
  is a report label, nothing indexes on it, and a deck already spells these rows
  `bti.nmos`. Naming a mechanism apart from the rule needs the same variant.

Resolution is `ParamValue::Name(StrId)` for the two name-shaped gaps and a
sequence variant, or a repeated-key convention on `RuleTable::param`, for the
first. Both are `gpurify-ingest` interface changes; `RuleTable::param` returning
the *first* match by name is what makes the repeated-key form unreachable today.

The fourth site on the same page resolved instead of filing:
`Row::head` now reads a `warning` flag, so `Severity::Warning` is reachable from
a deck (`crates/erc/src/ruleset.rs`, `fn head`). `ParamValue::Flag` already
existed, which is the whole difference between that entry and these three.

---

## `DeviceKind` has no variant for a Spectre built-in that is not one of five families

`crates/ingest/src/netlist.rs`, `fn spectre_primitive` — found executing that
site's `ponytail:` upgrade path ("extend this list when a netlist names a
primitive outside it").

The list now covers every Spectre built-in device master that lands in one of
`DeviceKind`'s five families: the compact MOS models (`bsim1`..`bsim4v5`,
`bsimsoi`, `bsimcmg`, `mos0`..`mos9`, `hisim*`, `psp`, `ekv`), the BJT models
(`vbic`, `hicum`, `mextram`), and the `res`/`cap` spellings of `resistor` and
`capacitor`. That exhausts the upgrade *within* the frozen enum.

What is left cannot be added here. `inductor`, `vsource`, `isource`, the four
controlled sources, `switch` and `tline` have no `DeviceKind`
(`crates/ingest/src/deck.rs:327`) variant to land in, so a netlist naming one is
refused wholesale with `Unsupported` — including a netlist whose only offending
statement sits in a testbench wrapper the LVS comparison would never reach.

Refusing is the *correct* behaviour today, not a fail-open: `DeviceKind` is
what a geometry recogniser can produce, and no layout extracts a voltage source,
so there is nothing for LVS to compare one against. The defect is that the two
meanings share one enum — "a device family LVS compares" and "a device family a
reference netlist may state" are not the same set, and only the first is
modelled. Resolution is either a `DeviceKind::Unmatched` variant carrying the
master's `StrId`, or a second enum on the netlist side that the LVS projection
narrows. Both are `gpurify-ingest` interface changes.

---

## cli, from the `ponytail:` spend-down pass

Both filed from `crates/cli/src/format.rs`. Neither is a shortcut the file can
spend down on its own: each needs a signature that lives in another crate.

**`units` has no `Grid::to_area`, and the two report writers have already
drifted apart because of it.** `export::json::write_measurement`
(`crates/export/src/json.rs:211-222`) derives the square of `Grid::to_length`'s
factor privately and emits `nm^2`; the cli's text renderer
(`crates/cli/src/format.rs`, `fn write_measurement`) has no such derivation and
prints the raw `dbu^2` that `Measurement`'s own `Display` gives it. On any grid
that is not one database unit per nanometre the same area violation is reported
as two different numbers in two different units by two writers over one run —
`12000 dbu^2` in the text report against `3000` in the JSON one at
`dbu_per_um == 2000`. Both carry their unit, so neither is a lie and neither is
fail-open; they are simply not the same report. This is the same defect the
already-**RESOLVED** `report::Measurement` entry closed for `Length`, left open
for `Area` because `Length` had `Grid::to_length` to route through and `Area`
had nothing. Resolution: `Grid::to_area(self, DbuArea) -> Qty<Area, ...>` in
`crates/units/src/dbu.rs` beside `to_length`, with `json.rs`'s private
`nm_per_dbu` square deleted in favour of it and a second arm added in the cli.
Fixing it inside the cli alone would make a third private derivation of one
conversion, which is the failure rather than the fix.

**An LVS `Verdict` cannot be named in `gpurify-cli`, so it prints through
`Debug` with its `StrId`s unresolved.** `engine::Outputs::lvs` is
`Option<gpurify_lvs::Verdict>`, `crates/engine/src/lib.rs:35-36` re-exports
`Outputs` but not `Verdict`, and `gpurify-lvs` is not a dependency of
`gpurify-cli` — so `write_violations` can hold the value and cannot match on
it. `{verdict:?}` does reach every `Discrepancy`, but every name inside one is a
`StrId`: `UnpairedDevice { model }`, `UnpairedNet { name }`,
`ParameterMismatch { param }`, `DuplicateName { name }` and
`Inconclusive::MissingSubcircuit` all render as `StrId(7)` while the `StrTable`
that resolves them is a parameter of the same function. `write_summary` reports
only whether the stage ran, so this is the only place the verdict is readable at
all, and a mismatch also arrives as one unbroken `Debug` line however many
discrepancies it holds. Resolution: re-export `Verdict`, `Discrepancy`,
`Inconclusive` and `Side` from `gpurify_engine` — cheaper than a new manifest
edge, and `Outputs` already exposes the type in its public field — then a
`match` in `format.rs` that resolves each `StrId` through `strings` and prints
one discrepancy per line.

**`Common` has no field for a grid, so the `gpurify` binary cannot complete a
single run.** Filed from `crates/cli/src/args.rs` (`to_inputs`, the `grid: None`
line). `gpurify_engine::Inputs::grid` is `Option<Grid>` and `load_into` reads it
first, before either path is opened (`crates/engine/src/pipeline.rs:146`), so
`None` is `LoadError::NoGrid` for every subcommand, every layout and every deck
— `crates/cli/src/main.rs:104-106` already spells out that a `Loaded` without a
grid cannot exist. The value has no source anywhere below this line: a deck file
does not declare a resolution (`Deck::grid` merely echoes what `parse_deck` was
handed, `crates/ingest/src/deck.rs:46-53`), and `Args` / `Common` carry nothing
that could hold one.

Fail-**closed**, which is why it ships rather than being worked around: the run
stops with a typed error naming the missing grid, and the alternative — picking
a `dbu_per_um` here — silently reinterprets every limit in the deck by whatever
factor the guess is wrong by, which is a wrong verdict rather than no verdict.

Resolution: `pub grid: Option<Grid>` on `Common` plus a `--grid <dbu_per_um>`
option in `parse`, routed through `Grid::new` so `GridError::NonPositive` is a
usage error rather than a panic. `gpurify-units` is already a dependency of
`gpurify-cli`, so nothing else moves. Two decisions belong to whoever unfreezes
it, and both are why this was not invented in a body: whether the flag is
**required** — which is the honest spelling, and which invalidates `BASE` and
every `parse_ok` row in `crates/cli/src/args.rs`'s test module, since the
grammar table there fixes a command line with no `--grid` as legal — or optional
with the `NoGrid` error preserved for its absence, which keeps the suite green
and keeps the binary dead by default. The second question is the unit: `Grid` is
constructed from database units per micrometre, so `--grid 2000` is a bare
integer with the unit only in the help text.

**`Common` has no field for a marker layer, so `--format gds` cannot be
written.** Filed from `crates/cli/src/main.rs`, where the format is refused
before the run starts. `export::gds::write_markers`
(`crates/export/src/gds.rs:170`) takes `marker_layer: LayerId` from its caller
deliberately — the number has to agree with whatever the viewer is configured to
show, so it is not the writer's to invent — and nothing on the command line
supplies one.

Two things the refusal's old comment named as the obstacle are not the obstacle,
and both are worth striking so the next reader does not chase them. Naming the
type is not it: `gpurify-core` is a dev-dependency here, but `LayerTable::id`
(`crates/ingest/src/deck.rs:111`) returns `Option<LayerId>` from a name and the
value flows through a `let` without ever being spelled. A conventional layer
name resolved through `deck.layers` is not it either: the marker layers a deck
declares are *device-recognition* markers — one polygon is one device
(`crates/topology/src/device.rs`) — which is a different concept from a
violation overlay, and no name for the latter exists anywhere in the tree or in
the deck format. Picking one here would invent a foundry convention.

Fail-**closed**, which is why it ships refused: an empty marker library opens in
a viewer as a clean layout, which is the false-clean failure the exit code
exists to prevent, and it would arrive on the one path where nobody re-reads the
number.

Resolution: `pub marker_layer: Option<String>` on `Common` plus a
`--marker-layer <name>` option in `parse`, resolved through
`loaded.deck.layers.id(&loaded.strings, name)` after the load and refused as a
usage error when the deck does not declare it. Also needed at the same time, and
the reason this is more than one field: `main`'s output tail renders into a
`String` and writes `text.as_bytes()`, so a binary format needs the payload
widened to `Vec<u8>` and the stdout arm moved off `print!`. That part is a body
and can follow the flag in one commit.

---

## lvs::checks, from the `ponytail:` spend-down pass

`crates/lvs/src/checks.rs`. Four of the file's five `ponytail:` comments were
blocked on a parameter or an accessor rather than on a body, and are recorded
here rather than worked around. The fifth was executed: the floating-net scan
now carries its predicate and its payload in one per-net `PolyId` column,
scatters the device half from `DeviceTable::terminal_net` instead of probing the
reverse CSR per net, and compacts through `bulk::compact_into`.

**`PortTable` publishes no iterator and no column, so three checks enumerate it
with a binary search per net.** `PortTable` exposes `name_of(net)`,
`net_of(name)`, `len` and `is_empty` and nothing else; both of its columns are
private. `check_floating_nets`, `check_label_conflicts` and
`check_net_seed_conflicts` each therefore walk `0 .. nets.net_count()` calling
`name_of`, which is `O(nets · log ports)` to read a table holding `ports.len()`
rows — hundreds, against net counts in the millions. It also forces the raw loop:
`Cols` is built from slices, so a term that arrives through a method call cannot
be handed to a combinator, and `name_of`'s panic edge cannot ride a callback.

Resolution is `fn entries(&self) -> (&[NetId], &[StrId])` on `PortTable`, or the
two columns made `pub` the way `DeviceTable`'s forward columns already are. With
it, `check_label_conflicts` drops its gather loop outright — the table is already
sorted by net, so the name-ordered copy is one `map_into` plus a sort —
`check_net_seed_conflicts`'s count becomes a `bulk::reduce`, and
`check_floating_nets`'s gather loses one of its two calls.

**`NetTable` publishes no per-net polygon-count column, so the floating-net
gather stays a raw loop.** Narrowed, not resolved. Two of the three predicate
terms were removed from the per-net body — the device term is now a scatter over
the public `terminal_net`, and the fail-closed reverse-index probe is one call
above the loop instead of one per net — but `polys_of(net)` is still a call into
a private CSR, so the surviving loop cannot become a `map_into`. Resolution is
`fn net_start(&self) -> &[u32]` on `NetTable`, which makes the lowest polygon per
net an adjacent-pair `map_into` over two offset views, the same shape
`check_topology` already uses on `device_terminal_start`.

**`check_device_counts` and `check_parametric` take no `deck: &Deck`, so neither
can execute.** Both are one combinator wide and have no second operand.
`check_device_counts` is a `bulk::reduce` count per family against a per-family
limit; `check_parametric` is a `compact_into` over `DeviceTable::param` against a
per-model range. The limits live in the deck, there is no other source for them,
and inventing one produces a limit every layout passes — the fail-open defect
`RuleRun` exists to make impossible. Both therefore record
`Outcome::Skipped(SkipReason::NotInDeck)` with `examined = 0`.

This is a *fourth* parameter beyond the `rule: StrId`, `&DeviceTable` and
`&GeometryStore` the `## lvs` section above already asks for on all six checks;
the earlier entry does not name it. Half of `check_parametric`'s old blocker has
since cleared on its own: `topology::recognise_into` now measures the marker
polygon's area as `DeviceParam::Area`, one row per device, so the param column is
populated and only the limit is missing. `Width`, `Length` and `Fingers` remain
unmeasurable for the reason filed under
`## topology, from the ponytail: spend-down pass`.

---

## core, from the `ponytail:` spend-down pass

**`candidate_pairs_into` and `cross_layer_pairs_into` allocate one scratch
`Vec<(PolyId, PolyId)>` per call, and the signature has nowhere to hang a
reusable one.** Both take `(store, index.., distance, out: &mut Vec<..>)`
(`crates/core/src/index.rs`). The scratch holds the *raw* gathered pairs, before
`bulk::compact_into` filters them with the exact predicate into `out`, and it
cannot be folded away:

- It cannot be `out`. `compact_into` needs a source distinct from its
  destination, and swapping the two buffers only moves which allocation is
  freed.
- It cannot be filtered during the gather instead. That would put the exact
  predicate inside a raw scatter loop, deleting the one `bulk` call site this
  function has, and it would leave `report_prune` with no rejected pairs to
  replay — the observer seam exists precisely to see them.
- It must not become a `thread_local`. That is hidden state, which the signature
  rule bans outright.

The cost is one allocation per call, and the callers call per rule per layer:
`drc::rules::spacing.rs:365,559`, `via.rs:146,275`, `patterning.rs:817`,
`overlay.rs:416`, `topology::net.rs:676,795`, `topology::device.rs:271`. Every
one of them already threads a caller-owned `SpatialIndex` and pair buffer, so a
`&mut PairScratch` would sit beside those with no new lifetime.

Resolution: a `PairScratch` parameter (or reuse of the existing per-rule scratch
struct in `drc::Scratch` / `topology`) on both functions and on the two private
`*_observed` forms behind them. Not fixable from inside a body.

## erc/rules/topology.rs, from the `ponytail:` spend-down pass

Two blockers the file could not resolve inside its own frozen signatures.
Neither was papered over; both rules were upgraded as far as the interface
allows and the residue is recorded here.

**`core::index::SpatialIndex` builds over a store layer, so `check_floating_well`
cannot index its tap column either.** This is the same defect already filed
above against `check_missing_tie`, hit at a second site: the tap is a
`LayerRef`, a derived `nsdm AND diff` is the ordinary case, and the resolved tap
column lands in `Scratch::boxes` as a bare `&[Bbox]` with no `GeometryStore`
rows behind it.

The pass resolved it locally and in the other direction: rather than index the
taps, the rule now indexes the *well layer's rings* — a `ring_order` column of
row ids sorted by low x, stabbed by each tap's centre through a
`partition_point`. That replaced the O(wells x taps) all-pairs scan and it also
happens to be what the hole fix needed, so no grid was duplicated here. The
residue is only that a `SpatialIndex` would have been the right tool and was
unreachable, exactly as recorded for `supply.rs`.

Resolution is the same one: `SpatialIndex::build_over(&[Bbox], &mut Self)` with
the caller owning the row numbering.

**`core::bulk` has no compact that hands back the surviving row *indices*, so
three rules keep a raw filter-and-append loop over bulk data.**
`check_floating_gate` scans nets, `check_unconnected_pin` scans a layer's
polygons and `check_floating_well`'s third pass scans a layer's rings; each
tests a predicate per row and pushes a `Violation` naming *which* row failed.
`compact_into` returns surviving `C::Item`s, and there is no `NetId` or `PolyId`
column in any of the three to compact — the id is the loop index. This is the
"payload-carrying compact" that `bulk`'s own decision table lists as missing,
and the workspace has three callers for it now rather than one.

Not filed as a signature *change*: `compact_into` is fine as it stands, the gap
is a fifth entry point. The same paragraph applies to the segmented reduce the
decision table also lists as missing — `check_multiple_drivers`' group collapse
is the second caller that would want one, and the pass hoisted that collapse
above the rule rows instead, which removed the per-row rescan but not the raw
loop.

## drc/rules/via.rs, from the `ponytail:` spend-down pass

**Two more callers for the index-returning compact recorded above.** Both via
rules end in a raw loop over bulk data whose body pushes a `Violation`.

`check_redundant_via`'s judging pass scans the per-cut neighbour counts and has
to name *which* cut was under-served; the cut id is `cuts.start + slot`, i.e.
the loop index, and `compact_into`'s `dst` element type is pinned to the source
column's, so there is nothing to compact but the counts themselves. Same shape
as `check_floating_gate` / `check_unconnected_pin` / `check_floating_well`.

`check_via_array_spacing`'s judging pass is the other half of the same gap and
one step worse: it folds `examined` *and* emits rows in one walk of the
candidate-pair list. Splitting it into a `bulk::reduce` plus a `compact_into`
would walk millions of pairs twice, and the compact has nowhere to land anyway
— `Scratch` holds exactly one `Vec<(PolyId, PolyId)>` and it is the source.

Not a signature *change* in either case: `compact_into` is correct as written.
The gap is the fifth entry point, now with five callers, plus — for the second
rule — a `Scratch` with a second pair buffer, which is a `drc` decision rather
than a `core::bulk` one.

The measurement side of both rules *was* moved onto the combinator in this pass:
`poly_dist2` over the candidate-pair list now goes through `bulk::map_into` in
both, which is the call site `poly_dist2`'s own doc comment names.

## erc/power.rs, from the `ponytail:` spend-down pass

Two upgrade paths in `crates/erc/src/power.rs` are blocked on an input that
does not exist. Neither is a defect in a frozen signature *of this crate* — both
are a missing column upstream, so the code was left alone and recorded here.

**`Connectivity` names no pad-marker layer.** `power::extract_into` has to
anchor each supply grid at a fixed-voltage node, and the only input that could
say where the pads are is `gpurify_ingest::deck::Connectivity`, which carries
`conductors`, `via_cut`, `via_connects` and `intra_layer_touch` and nothing
else. The transform therefore infers the anchor as the first tap of the first
shape on the rail — deterministic, and wrong wherever the real pads sit. The
consequence is directional and it is the bad direction: drop is under-reported
near the true pad, which is where the current is densest.

Wanted: a `pad_marker: Vec<LayerId>` (or a marker-layer id) on `Connectivity`.
`extract_into` would filter the rail's shapes by it and push those as
`source_node`; nothing else in `power.rs` moves, and `PowerGrid`'s columns do
not change.

**No per-terminal current column.** `power::extract_into` spreads each net's
`budget_current_ua` uniformly over its device attach points, because a
net-level budget is all `IntentMap` states. A hot spot therefore reads cooler
than it is. Wanted: a per-instance power file read by `ingest` into a
per-terminal current column on `DeviceTable`, which `extract_into` would sum per
attach point instead of dividing. Only `node_load` changes.

**Not blocked, and not taken: `bulk::segmented_reduce`.** `power::spmv` folds
over a per-row CSR range, the shape `core::bulk`'s own decision table names as
absent. The inner fold is already a `bulk::reduce` over a gather, so the only
raw thing left is the row boundary. The combinator that would remove it lives in
`gpurify-core`, not here.

## ingest, from the `ponytail:` spend-down pass

**`bulk::Cols` is sealed in `gpurify-core`, so `ingest` cannot present its own
column type to a combinator.** `gds::points` (`crates/ingest/src/layout.rs`)
turns an `XY` payload — a run of eight-byte big-endian `(x, y)` pairs — into two
`i64` columns, and does it in two `chunks_exact(8)` passes over the same bytes.
One pass is not reachable from this crate for two independent reasons:

- `Cols` has impls for `()`, `&[T]`, `(&[A], &[B])` and `(&[A], &[B], &[C])`
  and a private supertrait. Nothing outside `gpurify-core` can add the
  `&[[u8; 8]]` impl that would let the payload be read as one column of points.
  The sealing is deliberate — the combinators elide bounds checks on the
  strength of the four impls — so this is a request for a fifth impl in `core`,
  not for unsealing.
- There is no two-column `map_into`. `docs/BULK_MEASUREMENTS.md` and the
  combinator reference both list it as an absent shape whose signature is a
  Phase-4 decision. `gds::points` is a caller for it, as is
  `drc::rules::antenna::gate_areas_into`.

Resolution is either of those, in `gpurify-core`. The cost of not having them is
one extra L1-resident pass per `XY` record, which is why the two-pass form was
left in place rather than replaced with a raw loop.

**`gds`'s hierarchy walk is private to `gds`, so `oasis` cannot flatten
through it.** `Library`, `Cell`, `Ref`, `Xform` and `Flatten`
(`crates/ingest/src/layout.rs`) are the format-independent half of the reader —
cell table, instance transforms, cycle detection, the `GeometryStoreBuilder`
permutation — and every one of them is private to the `gds` module. `oasis` is a
sibling module, so when it is implemented it either duplicates all of that or
those items move up to `layout` and become `pub(super)`. The second is correct
and is a body-and-visibility change, not a signature one; it is recorded here so
it is decided once rather than discovered by whoever writes the OASIS reader.

---

## lvs::graph, from the `ponytail:` spend-down pass

`crates/lvs/src/graph.rs`. Four `ponytail:` comments. Two were executed inside
the frozen signatures — the counting-sort transpose lost a whole pass over the
nets, and `from_reference_into`'s four-column device loop became three
`bulk::map_into` calls plus one surviving segmented walk. The other two are
recorded here rather than worked around.

**`PortTable` publishes no iterator and no column, so `from_layout_into`
enumerates it with a binary search per net.** The same missing accessor already
filed under `## lvs::checks, from the ponytail: spend-down pass`, hit at a fourth
site and in the hottest of them: this is the *projection*, so it runs
`nets.net_count()` calls to `name_of` on every cell of every comparison, at
`O(nets · log ports)` to read a table of `ports.len()` rows. It also forces the
raw loop — `Cols` is built from slices, and a term arriving through a method
call with a panic edge cannot ride a callback.

Resolution is the one already named there: `fn entries(&self) -> (&[NetId],
&[StrId])`, or the two columns made `pub` the way `DeviceTable`'s forward
columns are. With it, `net_name` and `port_net` come out of a single linear merge
of the port column against `0 .. net_count` — no search at all — and the merge is
the shape `bulk` would call a two-column map, which the decision table already
lists as missing for other reasons. What the pass could do without it was narrow
`port_net`'s scratch from `net_count` rows to `ports.len()`, which is millions to
hundreds; the search itself stands.

**`RefGraph` has no scratch column, so `from_reference_into` allocates a
`Vec<u32>` sized by the whole netlist's nets on every call.** `graph_net` maps a
*global* reference row to this subcircuit's net rank, and it is indexed by
`Netlist::terminal_net` and `Netlist::port_net`, which are global. So it cannot
be narrowed to the subcircuit's own net count, it cannot be folded into any
column `Graph` already carries — every one of those is `net_count` rows, not
`rows` — and it must not become a `thread_local`, which the signature rule bans
outright. Hierarchical comparison calls this once per cell, so the allocation
scales with cells × netlist nets.

Resolution: a `&mut Vec<u32>` scratch parameter on `from_reference_into`, or a
`pub` scratch column on `RefGraph` beside the ones it already owns. Same shape
and same argument as the `PairScratch` entry under `## core, from the ponytail:
spend-down pass`.

**`gpurify-lvs` does not depend on `rayon`, so the transpose histogram stays
single-threaded.** Not a signature defect and not code that can be written from
inside a body: `transpose_into`'s count pass is a per-net histogram over every
terminal, and the parallel form is per-thread counts merged before the prefix
sum — deterministic, since integer counts merge in a fixed bucket order and the
scatter that follows is untouched. `rayon` is a workspace dependency
(`Cargo.toml:70`) but not one of `crates/lvs/Cargo.toml`'s, so writing it is a
manifest edit. Recorded so the next reader knows the ceiling is a dependency
edge rather than a missing idea.

## erc/facts.rs, from the `ponytail:` spend-down pass

Two entries, both in `resolve_intent_into`
(`crates/erc/src/facts.rs`). They share one root cause: the join this transform
performs is between *the names design intent declared* and *the names the layout
labelled*, and **neither side can be enumerated**. `PortTable` publishes
`name_of(NetId)`, `net_of(StrId)`, `len` and `is_empty`
(`crates/topology/src/port.rs:37-78`); `DesignIntent` publishes `supply_role`,
`limits`, `domain_voltage`, `domain_count` and `is_empty`, every one of them
taking a key and answering about it, with all seven columns private
(`crates/ingest/src/intent.rs:52-66`). A join with no iterable side is written
by probing every net, which is what the code does.

**Correctness — `IntentMap::undeclared` is unconditionally empty, and that is
fail-open.** Its own doc says an unlabelled supply "**is** reported, because
'checked, clean' on a supply that does not exist in this layout is the same
false confidence as a skipped rule pretending to be clean". Nothing is reported.
Intent naming `VDD` and `VSS` against a layout labelling only `VDD` re-keys one
supply, leaves `IntentMap::is_usable` true, and the six intent-gated rules run
and report clean about a rail nothing ever checked.

The extreme case is safe by accident — a layout labelling *no* declared supply
leaves both columns empty, `is_usable` false, and all six rules record
`Skipped(NoDesignIntent)`. It is partial coverage that goes unreported, which is
the case a real block sees.

No proxy closes it either. `domain_count` is public and the loader refuses
`DomainWithoutSupply`, so a whole domain losing every supply *is* detectable by
comparing distinct domains in `out.supply_domain` against `intent.domain_count()`
— but a domain that keeps one labelled supply and loses another is invisible to
that count, and `undeclared` is `Vec<StrId>`, so even a detected loss has no name
to record: `domain_name` is private and unexposed. Deliberately **not** papered
over with a `debug_assert`, because a block-level run legitimately sees only some
of a chip's supplies and the assert would fire on correct input.

Resolution: an enumerating accessor on `DesignIntent` — `supply_names() ->
&[StrId]` is enough, and `resolve_intent_into` would then drive the join off it
through the `PortTable::net_of` that already exists, pushing every name that
misses into `undeclared`. That is an `ingest` signature change. `docs/NEED_TESTING.md`
§`resolve_intent_into` records the matching hole: the column has no test at all,
because nothing can make it non-empty.

**Performance — the re-key walks every extracted net.** The same missing
enumeration forces `for row in 0..nets.net_count()` with a `PortTable::name_of`
binary search per row: hundreds of thousands of searches to reach the hundreds of
named nets, O(N log P) where the join is O(P log P). It runs once per run, not
once per rule, which is why it was left rather than worked around.

Resolution is either accessor. A `ports.rows() -> (&[NetId], &[StrId])` on
`topology` lets the loop walk named nets only; the `supply_names()` above lets it
walk declared names only and use `net_of`. Either collapses the pass to the
hundreds of rows that can produce output. Both are signature changes, and
`net_of`'s own `ponytail:` (`crates/topology/src/port.rs:55`) names the
name-ordered permutation column that would make the second one cheap.

**Not a defect, recorded so it is not re-litigated: `classify_nets_into`'s raw
loop.** The output index is `terminal_net[i]`, so the pass is a
scatter-accumulate — the shape `core::bulk` names as deliberately absent and
states will not be wrapped, since it is unvectorisable without lane-conflict
detection and a combinator would wrap the loop and buy nothing. The comment's
former upgrade path, sort-then-segment-reduce, needs `bulk::segmented_reduce`,
which lives in `gpurify-core`; it is already recorded there against
`power::spmv`. The gather reading is strictly worse: a per-net fold would walk
`devices_on(net)` and re-read every terminal of each device to find the ones
landing back on `net`. The comment now names the exception instead of a debt.

## pex, from the `ponytail:` spend-down pass

**`core::index` has no build-from-bbox-column seam, so nothing outside
`GeometryStore` can be spatially indexed.** `mesh::near_another_conductor`
(`crates/pex/src/quasistatic/mesh.rs`) asks, for each solid of a selected net,
whether any solid of a *different* conductor lies within `proximity_refine` of
it. That is the query `core::index` exists for, and the site's `ponytail:`
comment named `SpatialIndex` as the upgrade. It is not reachable:

- `SpatialIndex::build_into(store: &GeometryStore, layer: LayerId, out: &mut Self)`
  (`crates/core/src/index.rs`) takes its rows from `store.layer_bboxes(layer)`
  and `store.polys_on_layer(layer)`. A mesh's solids are a *derived* row set:
  one per polygon of a selected net, spanning every layer those nets touch, with
  a conductor id the store has never heard of. No `LayerId` names them.
- `candidate_pairs_into` answers in `(PolyId, PolyId)` over one layer. The
  meshing query is cross-layer and its answer is a `bool` per solid, not a pair
  list.

The fix is an entry point that indexes a caller-owned `&[Bbox]` — the shape
`Grid::build_into` already has privately, as `(bboxes, first_row, extent, cell,
min_ext, out)`. Exposing that, or an equivalent `SpatialIndex::build_from_bboxes`,
serves this caller and any other derived column. Widening it was refused here:
this is not the Definition-Phase, and the alternative — a second uniform grid
written privately inside `mesh.rs` — duplicates the two-level split, the filing
bound and the counting sort that `core::index` already carries and already
tests.

Cost of not having it: the scan stays O(n²) in the polygons of the selected
nets. It is also currently unreachable — `quasistatic::mesh_options`
(`crates/pex/src/quasistatic.rs`) hardcodes `proximity_refine` to zero and every
test does the same, so the refinement path ships with no coverage at all. That
belongs in `docs/NEED_TESTING.md`, and it is why the local-index alternative was
judged the worse trade rather than merely the larger one: 150 lines of index
arithmetic that no test in the tree can execute.

**Not blocked, and not taken: an expand combinator in `core::bulk`.**
`mesh::mesh_box` turns one face into `nu * nv` panels — a generator, the shape
the combinator reference lists alongside scatter-accumulate as deliberately
absent. Forcing it through `map_into` costs a materialised index column and a
copy per face and removes no raw loop from the tree, so the loop stays and its
comment now names the exception instead of promising an upgrade. The fallible
map that used to sit in `build_into` needed no new entry point either: hoisting
the per-layer extrusion into a uniform table turned the per-polygon step into a
gather, so it is now a `bulk::reduce` for the fault plus a `bulk::map_into` for
the emit.

## pex/quasistatic.rs, from the `ponytail:` spend-down pass

**`extract_into` has no `MeshOptions` parameter, so mesh resolution is a
constant no caller can reach.** `quasistatic::extract_into`
(`crates/pex/src/quasistatic.rs`) takes `solve::Options` — tolerance, restart,
iteration budget — and nothing that describes the discretisation. So
`mesh_options` picks the resolution itself: half a micrometre of panel edge
derived from the run's `Grid`, proximity refinement off, and a `1 << 20` panel
ceiling.

Every one of those three is a knob the caller owns everywhere else in the tree,
and none of them is reachable:

- `max_edge` is the accuracy knob. A process whose features sit well below half
  a micrometre is under-meshed and one well above it pays for panels it does not
  need. The discretisation error surfaces in `CapMatrix::asymmetry`, which the
  caller is handed, so it is never a silently wrong number — but a caller who
  reads an asymmetry it does not like has no way to act on it.
- `proximity_refine` is hardcoded to zero, which is what makes
  `mesh::near_another_conductor` unreachable — the same fact the `mesh.rs`
  section above records from the other end.
- `max_panels` is the cost ceiling. `1 << 20` is refused rather than truncated,
  so it fails closed, but a caller who wants a coarse-but-finishing solve on a
  large selection cannot ask for one.

The site's `ponytail:` comment already named the upgrade as a signature change,
and it was refused here for that reason: this is not the Definition-Phase.
Deriving `max_edge` from `ProcessStack::thickness_nm` instead was considered and
also refused — it is a *different* guess, not a caller's choice, and on the
test stack (100 nm layers on a 1 nm grid) it is a five-fold refinement and a
twenty-five-fold panel count against an O(n²) matvec, which is a cost decision
no comment in the file authorises.

The fix is a `mesh::MeshOptions` parameter on `extract_into`, beside the
`solve::Options` already there. `mesh::build_into` takes one already, so nothing
below the signature changes; `mesh_options` and its `Grid`-derived default
become the caller's business.

---

## export::gds, from the `ponytail:` spend-down pass

**Neither GDSII writer can reach the design's `Grid`, so the `UNITS` record is
hard-coded to a 1 nm grid.** `gds::write_store(&GeometryStore, &LayerTable,
&str, &mut Vec<u8>)` and `gds::write_markers(&Violations, &GeometryStore,
LayerId, &mut Vec<u8>)` are the only entry points, and no parameter of either
carries a `Grid`: `GeometryStore` holds coordinate, layer, offset and bbox
columns and nothing about physical scale, and `deck::LayerTable` holds names and
stream pairs. So `USER_UNITS_PER_DBU` / `METRES_PER_DBU`
(`crates/export/src/gds.rs`) are constants at `1e-3` / `1e-9`, the workspace's
own `Grid::new(1000)`.

Omitting `UNITS` is not an option — the format requires the record, and a reader
that does not find one applies a default of its own choosing, which is the same
defect with no evidence left behind.

What it costs, precisely: `ingest`'s reader reads `UNITS` and discards it
(`crates/ingest/src/layout.rs:488`), so the `parse -> write -> parse` law is
untouched. The exposure is a viewer: a marker file written for a design on a
5 nm grid declares 1 nm, and the overlay is scaled differently from the design
it overlays. Coordinates are correct in database units in both files; only the
declared physical scale disagrees.

Resolution is a `Grid` parameter on both writers, or a `Grid` on
`GeometryStore`. Both are signature changes, which is why this is a record and
not a commit.

**`GeometryStore` exposes `poly_layer(PolyId) -> LayerId` but no `&[LayerId]`
column.** The layer column cannot be handed to a `bulk` combinator, so a
"reject every row on an undeclared layer" pass over the whole store has no
combinator form. `write_store` no longer needs one — it walks `polys_on_layer`
ranges instead, which makes the check per-layer rather than per-row — but the
missing accessor is what forced that shape, and any other caller wanting to fold
over layers hits the same wall. `poly_bbox` has the same shape and the same gap;
`layer_bboxes` is the per-layer slice accessor that exists for `Bbox` and has no
`LayerId` counterpart.

---

## engine::run, from the `ponytail:` spend-down pass

**No input carries a sign-off temperature, so every ERC derating in a full run
is computed at a hard-coded 85 °C.** `erc::RunInputs::operating_temperature`
(`crates/erc/src/ruleset.rs:167`) is required, positive and finite, and is what
`rules/electrical.rs:768` and `rules/reliability.rs:191` derate against.
Nothing in `engine::Inputs`, `engine::RunOptions` or `ingest::deck::Deck`
declares a corner — `Deck` holds `grid`, `layers`, `rules`, `connectivity`,
`devices`, `stack`, and no operating condition — so `run::sign_off_temperature`
(`crates/engine/src/run.rs:176`) returns `celsius(85.0)`, matching what
`crates/erc/tests/common/mod.rs:75` characterises at.

This is not only a convenience. A part signed off at 125 °C derates *less* here
than the corner requires, so an electromigration or reliability limit reads more
generous than it is and a marginal net passes a check it would fail. The
direction is fail-open.

Resolution is a `sign_off_temperature: Qty<Temperature, { prefix::BASE }>` field
on `RunOptions`, which `cli::args` then has to fill. Both are Definition-Phase
changes, which is why this is a record and not a commit.

**Nothing declares a die boundary, so the density denominator is inferred.**
`erc::RunInputs::die` (`crates/erc/src/ruleset.rs:148`) is the denominator of
every density and the region `rules/antenna.rs`'s window sweep covers. Neither
`engine::Inputs` nor the deck schema (`crates/ingest/src/deck.rs:365`, whose
`"layers"` map is name-to-stream-pair and carries no outline declaration) states
one.

`run::design_extent` now reads the extent of the deck's outline layer when the
deck declares one under any of `prBoundary`, `DIEAREA` or `die`
(`crates/engine/src/run.rs`, `DIE_LAYER_NAMES`), which closes the gap for a deck
that names it. **A deck that names none still falls back to the union of every
polygon's bounding box, and that fallback is fail-open for a minimum-density
rule**: the margin between the outermost shape and the real die edge is never
swept, so a region that would fail a fill floor is not evaluated and the run
reports clean over ground it never covered. The old tree refused rather than
inferred — `DensityCmpReport::not_run("die boundary and density/CMP rules were
not supplied")`, `reference/pre-rewrite:crates/erc/src/rules/density_cmp.rs:358`
— which is the fail-closed shape this cannot reach from a body.

Resolution is a `die: Option<Bbox>` on `Inputs`, or an outline declaration in
the deck schema so "no die was declared" is distinguishable from "the deck names
no outline layer" and the density rules can record themselves skipped. Both are
Definition-Phase changes.

**`pex` exposes no network merge and `Outputs` has no capacitance-matrix
field, so a quasi-static run drops every net it was not asked about.** With a
non-empty `RunOptions::quasistatic_nets`, `run_pex`
(`crates/engine/src/run.rs`) calls `pex::quasistatic::extract_into` for the
selection and never calls `pex::analytical::extract_into` at all. The two
networks cannot be concatenated: `ParasiticNetwork`'s node-order invariant
(`crates/pex/src/network.rs:55` — every net's nodes one contiguous ascending
range) is what every writer scans on, and appending would break it. The solve's
`quasistatic::CapMatrix` is dropped for the same reason: `Outputs` has no slot.

The reporting cost is the sharper half. The stage still returns
`StageStatus::Ran`, so a net absent from `Outputs::parasitics` because it was
never asked for reads exactly like a net that was extracted and found to carry
no parasitics — the "empty result that cannot be told from not checked" shape,
in an exported artefact rather than in a verdict. No field of `Outputs` or
`Summary` can carry the distinction.

Resolution is a `pex::network::merge_into` that renumbers nodes while preserving
the contiguity invariant, plus a matrix field on `Outputs`. Both are
Definition-Phase changes.

**`gpurify_core::bulk` has no "one row into N output columns" combinator, so
`run::record_discrepancies` is a raw loop.** Not a defect to resolve so much as
one to record beside the other two sites that hit it: `Violations::extend`
(`crates/report/src/violation.rs:109`, eight `extend_from_slice` calls) and
`lvs::compare::report_unpaired`. The `bulk` decision table names two-column map
and payload-carrying compact as absent by design, and the callback contract bans
the push a fan-out needs. A fifth combinator is a `core` addition, i.e. a
signature, not a body.

## pex quasistatic, from the `ponytail:` spend-down pass

All three entries are `crates/pex/src/quasistatic/matvec.rs`. Each is a named
upgrade path whose blocker is a frozen signature, not an unwritten body, so the
code was left as it stands and the `ponytail:` comments now point here.

**`CpuMatVec` cannot become an FMM behind `build` and `Accuracy` as frozen.**
`CpuMatVec::build(mesh: &Mesh) -> Self` is infallible and carries no accuracy
parameter; `quasistatic::Accuracy` carries `residual`, `tolerance`,
`iterations`, `backend` and `asymmetry` and no field for the operator's own
error. An FMM buys its asymptotics by *truncating* the far field, so the
adapter stops evaluating the `P_ij` this module's own header states and starts
evaluating an approximation of it. That is exactly the trade the module exists
to make visible — "the precision boundary and the module boundary coincide",
and the accuracy is "measured, not assumed" — and behind these two signatures
there is nowhere to state the expansion order that bounds the truncation, and
nowhere to report the truncation that resulted. `CpuMatVec` is also documented
as the exact `f64` reference the GPU `f32` adapter is differentially tested
against (`gpu.rs` module header, item 3); an approximate host reference stops
that comparison from isolating the device's error, which is the only thing it
is there to measure.

Wanted: an expansion-order (or target-error) parameter on `CpuMatVec::build`,
and a far-field truncation field on `Accuracy` that `extract_into` fills from
the adapter. `MatVec`, `apply`, the observer and `select` do not move — the
seam is right, the two signatures either side of it are the ones that cannot
carry the trade.

Cost of not having them: the stated ceiling stands, ~1e4 panels before the
quadratic term dominates a 400-iteration GMRES. Note also that no test in
`crates/pex/tests` meshes more than 144 panels, three orders below that
ceiling, so an FMM landed today would ship a far-field path the suite never
enters.

**`mesh::Panel` keeps a panel's area and drops its two edge lengths.**
`Collocation::radius` is the effective radius of a panel's self-potential, and
the closed form for a rectangle `a × b` is
`A / (2a·ln((b + √(a²+b²))/a) + 2b·ln((a + √(a²+b²))/b))`, which collapses to
the `√A / (4 ln(1 + √2))` in the code exactly when `a == b`. `mesh_box` has
both edges in hand as `du` and `dv` and stores only their product, so the
aspect ratio is gone by the time the operator is built and cannot be recovered
from a centroid, a normal and an area.

The `ponytail:` comment stated the cost as "~2% low at 4:1, inside the error the
centroid kernel already carries". Both halves are wrong, and the comment has
been corrected in place. `√(ab)/(4 ln(1 + √2))` against the closed form is low by
3.5% at 2:1, **12.5% at 4:1**, 28% at 10:1 and 64% at 100:1 — and it is the
*diagonal* of `P`, the entry the solve is most sensitive to and the one the
softening `ρ_i ρ_j` is built out of. Sliver panels are not a corner case here:
`mesh_box` bounds a panel edge from above only, so a face narrower than
`max_edge` is emitted uncut at whatever aspect the stack gives it, and the side
face of a layer is (footprint × thickness). A 50 nm layer under a 0.5 µm edge
limit is 10:1 on every side face it has.

Wanted: `Panel { extent: [f64; 2] }`, the in-plane edge lengths, filled by
`mesh_box` from `du`/`dv`. `matvec` then reads them instead of `area.sqrt()`
and nothing else moves. Not free: `Panel` is constructed literally in
`crates/pex/tests/quasistatic.rs` (`cube`, and the panels
`conductor_area` is checked against), so the test corpus moves with it — which
is why this is a signature decision rather than a body.

**The operator sees one permittivity per panel, so it cannot carry a layered
Green's function.** The pair coefficient is the arithmetic mean
`½(k_i + k_j)`, `k = 1/(4πε₀ε_r)`, chosen because it has to be *some* symmetric
function of the two panels and it is exact on a uniform stack. The upgrade is
the layered-dielectric Green's function, which is an image series over the
dielectric interfaces — it needs each interface plane and the permittivity on
both sides of it. `Mesh::epsilon` is one number per panel, the permittivity
*above* it, and `CpuMatVec::build` is handed the `Mesh` and nothing else, so
the stack that `mesh::build_into` read is not reachable from the operator.

Wanted: `CpuMatVec::build(mesh: &Mesh, stack: &ProcessStack)`, or the interface
planes travelling on `Mesh` the way `epsilon` already does. `MatVec::apply`
does not move.

Worth deciding at the same time, and not decided here because it has no oracle
in the suite: for two panels either side of a planar interface the standard
two-medium result averages the *permittivities*, `1/(4πε₀·½(ε_i + ε_j))`, which
is the harmonic mean of the coefficients rather than the arithmetic mean the
code takes. Both are symmetric and both are exact on a uniform stack, so every
test in `crates/pex/tests` is blind to the difference.

---

## drc/rules/width.rs, from the `ponytail:` spend-down pass

**`narrowest_width` and `narrowest_notch` take no scratch parameter, so the
facing-pair sweep allocates per call.** The `O(E²)` pair scan under those two
decisions is now an `O(E log E)` scanline sweep, and a sweep needs three
columns — the polygon's edges, the event stream, the active list. `check_facing`
hoists one `FacingScratch` above its polygon loop and refills it, which is the
whole point of the shape. The two public decisions cannot: `narrowest_width(poly)
-> Dbu` and `narrowest_notch(poly) -> Option<Dbu>` name only the polygon, so
each call builds the buffers and drops them.

That is paid for real. `spacing::wide_flags_into`
(`crates/drc/src/rules/spacing.rs:1003`) calls `narrowest_width` once per
counter-clockwise row of a layer, so a wide-shape prefilter over a metal layer
pays three small allocations per polygon where it previously paid none. The work
it replaces — a quadratic pair scan that rebuilt the ring-walk iterator on every
inner step — is much larger on any polygon past a few edges, so this is a
regression only for rectangles.

Resolution is a `&mut` scratch parameter on both, or an allocation-free active
list. Both are signature changes, which is why this is a record and not a
commit.

**`ValidatedLayer` stores `ring_poly` and exposes no accessor, so a width rule
recovers the mapping by replaying the shoelace.** `OuterRows`
(`crates/drc/src/rules/width.rs`) walks the layer's store rows and re-runs
`winding_of` on each to rebuild "which `PolyId` did validated polygon *i* come
from" — the column `validate_layer_into` already filled and kept private. It is
one extra pass over the layer's coordinates per rule row, and it is exact,
because validation emits one polygon per counter-clockwise row in ascending row
order and this replays that filter. There is no cheaper body: the answer is a
field of a frozen type with no reader. Same defect as the hole-provenance gap
already recorded for `spacing::wide_flags_into`; the fix is one accessor.

## core/bbox.rs, from the `ponytail:` spend-down pass

Both `ponytail:` comments in `crates/core/src/bbox.rs` name an upgrade that
lands outside the file — one in `gpurify-units`, one in `crates/core/src/bulk.rs`
— and both are interface additions rather than bodies. The code is unchanged;
this is the record.

**`Bbox::width` / `Bbox::height` cannot construct their own result without
tripping a `debug_assert` on a legal box** (`crates/core/src/bbox.rs:233,237`).
Both are `const fn -> Dbu`, so the only constructor reachable from them is
`Dbu::new_unchecked` (`crates/units/src/dbu.rs:70`), which asserts
`in_domain(raw)`, i.e. `|raw| <= MAX_ABS_DBU == 2^40`. A width is a *difference*
of two in-domain coordinates and legally reaches `2^41`, which `dbu.rs` says
outright at the `Sub` impl (`:119`): "a result outside the legal range is caught
where it re-enters the tree, not here." `Sub for Dbu` is exactly the unchecked
subtraction wanted here — and it is not a `const` impl, so a `const fn` cannot
spell it.

The consequence is a debug-build panic on input the type system accepts, not a
wrong answer: release is correct, because `2^41` sits nowhere near `i64`. The
reachable cases are a box spanning more than half the coordinate domain (the
documented ceiling, 1.1 km on a side at a 1 nm grid) and, more cheaply,
`Bbox::EMPTY.width()`, which is `-2^40 - 2^40 == -2^41` and fires the assert. No
test in the suite folds an empty box into `width`, so nothing is red today; the
callers that would meet it are `erc/power.rs:1933,1982,1988`,
`drc/rules/width.rs:521`, `drc/rules/overlay.rs:852` and
`erc/rules/reliability.rs:712`.

Resolution is one addition to `gpurify-units`: a `pub const fn Dbu::sub(self,
Self) -> Self`, unchecked in the same way and for the same stated reason as the
existing `Sub` impl, with `width`/`height` calling it. Widening `in_domain`, or
dropping `const` from `width`/`height`, are both wrong — the first destroys the
`2^80` bound `MAX_ABS_DBU` exists to buy, the second changes a frozen signature.

**`bulk` has no segmented reduce, so `Bbox::of_polys_into` keeps a raw loop over
bulk data** (`crates/core/src/bbox.rs:309`). The fold is over a per-row *range*
(`starts`/`lens`), which `bulk`'s own decision table lists as absent, and
`map_into` is ruled out by name in `bulk.rs`'s doc comment: the callback would
have to slice `xs`/`ys`, and a slice is a panic edge the callback contract bans.
The inner fold does reach `bulk::reduce` through `Bbox::of_points`; only the
walk over the range list is raw, one iteration per polygon.

The second and third callers the comment predicted both exist — `drc`'s antenna
stack ranges and `erc::power`'s node ranges — so the shape is no longer
hypothetical. It is still a new public item in the frozen four-function
combinator module, and whoever adds it inherits two constraints: each segment
folds strictly left-to-right in ascending index order, like `reduce`, or
`export` loses byte-reproducibility for every `f64` accumulation downstream; and
output rows land in segment order, because `of_polys_into` promises one row per
polygon in `starts` order.

---

## pex quasistatic/solve.rs, from the `ponytail:` spend-down pass

One entry, `crates/pex/src/quasistatic/solve.rs:341` (`refine`). It is a named
upgrade path whose blocker is a frozen struct, not an unwritten body, so the
code was left as it stands and the `ponytail:` comment now points here.

**`Workspace` cannot hold an outer refinement iteration, so `refine` is one
call to `gmres`.** The comment's claim is correct and is the reason the body is
one line: a restarted GMRES cycle forms `b − A x` on the host in `f64`, builds
a Krylov basis from it, solves the correction equation with the operator and
adds the correction to `x` — the refinement iteration, term for term. The
ceiling it accepts is that the inner solve gets no tolerance of its own; it
runs `options.restart` Arnoldi steps and stops.

The upgrade — an outer loop with its own tolerance — needs `r` (the frozen
right-hand side of the correction equation) and `d` (its solution) as two
`n`-length buffers that survive across the inner `gmres` call. Every field of
`Workspace` is live inside that call: `krylov` and `hessenberg` are cleared and
resized at entry, `correction` is the Arnoldi work vector, and `residual` is
refilled by `residual()` at the top of every cycle. `r` in particular cannot be
`workspace.residual`, because `gmres` takes `b` by shared reference and
`workspace` by exclusive reference in the same call. So the upgrade is a field
addition on `Workspace`, and the only alternative — two `Vec`s local to
`refine` — allocates `2 × panels × 8` bytes per conductor in
`quasistatic::columns_into`'s per-column loop, which is the cost `Workspace`'s
own doc comment ("allocated once per *matrix*, not once per column") exists to
remove.

Wanted: `Workspace { r: Vec<f64>, d: Vec<f64> }`, private like the other five,
plus somewhere for the inner tolerance to live — either a field on `Options` or
a second `Options` parameter on `refine`. `gmres`, `residual`, `MatVec` and
`Converged` do not move.

Worth stating because it is what decides whether the upgrade is ever worth
taking: **`refine`'s doc comment claims more than one `MatVec` can deliver.**
It says the residual "is formed in `f64` on the host from the exact right-hand
side" and that iterating "recovers `f64` accuracy at close to `f32` speed".
Only the subtraction is `f64` — `A x` inside `residual` goes through the same
`operator` as the inner solve, so under a `GpuF32` adapter the residual carries
that adapter's ~1e-7 relative error and no amount of outer iteration removes
it. Classic mixed-precision refinement needs two operators: an accurate one for
the residual and a fast one for the correction. `refine` takes one. This is
**fail-closed** and not a wrong number — the achieved residual stalls above the
default `tolerance: 1e-10` and the caller gets `SolveError::NotConverged`
rather than a silently `f32`-accurate capacitance — but it means the outer
tolerance the upgrade above would add is the *only* part of the mixed-precision
story that is reachable without also widening the seam to two operators.
Neither half is exercised today: `GpuMatVec` is the only `f32` path and no test
in `crates/pex/tests` instantiates it.

## erc/lib.rs, from the `ponytail:` spend-down pass

**`erc::Scratch` cannot be made per-worker without changing eleven frozen
signatures** (`crates/erc/src/lib.rs:154`). The comment named the ceiling
correctly — one `Scratch` threaded through `RuleSet::run` serialises the
nineteen rule transforms even though `RuleSet`'s own doc comment
(`crates/erc/src/ruleset.rs:94`) states the tables are disjoint and the
transforms independent. The upgrade it pointed at is not a body:

- Eleven transforms take `scratch: &mut Scratch`
  (`rules/topology.rs`, `rules/supply.rs`, `rules/antenna.rs`,
  `rules/electrical.rs`, `rules/reliability.rs`), and they reach the private
  fields directly — `scratch.boxes`, `scratch.edges`, `scratch.net_marks`.
  One `&mut Scratch` does not split into eleven disjoint ones, and
  `RuleSet::run` receives exactly one.
- Making `Scratch` hold an internal worker pool does not help: the field
  accesses above are what would have to be re-pointed, i.e. the same eleven
  signatures.
- `gpurify-erc` has no `rayon` dependency, so even the correct signature buys
  nothing until `Cargo.toml` gains one.

The merge half already exists and is not the blocker: `Violations::extend`
(`crates/report/src/violation.rs:109`) is the gatherer, and `record_run` derives
each row's count from a caller-supplied `violations_before`, so a per-worker
violation table merges without renumbering.

Resolution, when a profile on the scale corpus asks for it: `scratch: &mut
Scratch` becomes the per-worker parameter it already is in shape, `RuleSet::run`
takes `&mut [Scratch]` (one per worker, caller-owned as everything else here
is), and the nineteen calls become a parallel iterator over the non-empty
tables. Not attempted here — this is not the Definition-Phase.

## drc/rules/mod.rs, from the `ponytail:` spend-down pass

**`poly_dist2` cannot go sub-quadratic without a scratch parameter**
(`crates/drc/src/rules/mod.rs`). The comment named the ceiling correctly — a
double loop over the cross product of two rings — and the spend-down pass closed
the affordable half of it: every edge pair is now bounded by a box gap before it
reaches `seg_seg_dist2`, and the outer loop bounds each edge of `a` against the
whole of `b` first. On rectilinear input the bound is exact, so the expensive
call fires only on a strict improvement of the running best.

What is left needs a signature:

```rust
pub(crate) fn poly_dist2(store: &GeometryStore, a: PolyId, b: PolyId) -> DbuArea
```

Dropping below `O(n * m)` means indexing one ring's edges — a grid, a sorted
interval list, a BVH — and every one of those is a buffer. There is nowhere to
put it:

- Allocating it inside the call is banned twice over. `rules/mod.rs`'s own
  header says nothing allocates per row, and all three call sites
  (`rules/spacing.rs:252`, `rules/via.rs:167,312`, `rules/patterning.rs:833`)
  invoke this from inside a `bulk::map_into` callback, where the callback
  contract forbids allocation outright.
- Caching it across calls needs interior mutability, which defeats the `Fn`
  bound the same contract relies on, and would make the result order-dependent
  inside a combinator that is documented as order-independent.
- `Scratch` is already threaded to every `check_*` transform, so the buffer has
  an obvious owner — but `poly_dist2` would have to take `&mut Scratch`, and the
  three callers would have to hand it one from inside a closure that currently
  captures `store` immutably.

Resolution, when a profile on a corpus with thousand-vertex polygons asks for
it: `poly_dist2` grows an `edges: &mut EdgeIndex` parameter built once per
polygon rather than once per pair, and the call sites move the build above the
`map_into`. Not attempted here — this is not the Definition-Phase.

`gpurify_core::index::SpatialIndex` is not the reusable piece: it indexes
polygons of a layer by bounding box, and the unit needed here is one ring's
edges.

## pex/network.rs, from the `ponytail:` spend-down pass

**`ParasiticNetwork::sort_canonical` takes no scratch, so it allocates once per
call.** The site's `ponytail:` comment named two ceilings and one upgrade path
each. Pre-keying the rows was taken — `sort_canonical`
(`crates/pex/src/network.rs`) now decorates with `canonical_key` in one
`bulk::map_into` pass and sorts on the precomputed key, instead of handing
`sort_unstable_by_key` an extractor the sort re-runs on every comparison. The
other half is refused here.

`sort_canonical(&mut self)` is the frozen signature. Three parallel element
columns cannot be permuted in place without a buffer, and there is no parameter
to put one in, so every call builds a `Vec<KeyedRow>` and drops it. Hoisting it
into a `&mut Vec<_>` scratch parameter is the fix, and it is a signature change;
this is not the Definition-Phase.

Cost of not having it: one allocation per call, sized `element_count()` rows of
56 bytes. It is paid once per network today — `export`'s writers and the
determinism gate each sort a finished network once — so the ceiling is only
reached if a full-chip run ever sorts per net in a loop, which is the same
condition the original comment named. Note the decoration made the allocation
larger, not smaller: 56 bytes a row against the 32 the bare row occupied. That
is the decorate trade and it is why the two halves are recorded together.

**Secondary, and also a type change rather than a body: `Parasitic` has no
`#[repr(u8)]`, so the canonical sort tag cannot be the discriminant.**
`canonical_key` orders the kinds by declaration, which is exactly the
discriminant value, but Rust exposes no integer for a data-carrying enum without
a `repr`. Release asm at `-C target-cpu=x86-64-v3` shows LLVM hoisting the `Qty`
payload load above the match — every variant carries one `Qty` at the same
offset — and leaving a four-way jump table whose only product is the tag
constant. It survives on the predicts-well valve, recorded at the site:
`analytical::extract_into` emits one resistance and one ground capacitance per
node, so the kind column is a period-2 pattern. Adding the `repr` would change
the layout of a frozen type.

---

## engine::pipeline, from the `ponytail:` spend-down pass

**`layout::read_layout` owns the string table it fills, so `load_into` parses
the deck twice.** `read_layout(&Path, &Deck, UnknownLayers) -> Result<Layout,
LayoutError>` interns cell, property and label names into a `StrTable` it
creates and returns inside `Layout`; it takes no `&mut StrTable`. But it also
needs a `Deck` *during* the read, because layer mapping happens there rather
than after it. Those two facts are jointly unsatisfiable for a run that wants
one id space: the run's table can only be the layout's, and any deck parsed
before the layout is interned against a table that is about to be discarded.

So `engine::pipeline::load_into` parses the deck once into a throwaway
`StrTable::default()` purely to map layers during `read_layout`, then parses the
same source a second time into `layout.strings`. The two agree on every
`LayerId` because `deck::build_layers` assigns them by sorted layer *name bytes*
rather than by intern order — that is what makes the double parse safe, and it
is asserted at the site.

Remapping instead of re-parsing is not reachable from `engine` either, which is
why this is a record and not a workaround. Going one way, `Deck`'s `StrId`
columns would have to be walked from outside `ingest`, duplicating knowledge of
its layout in the crate above it. Going the other way, `Provenance` keeps
`props`, `labelled` and its `PathTable` private and exposes no remap, and
`StrTable` offers `intern`/`get`/`resolve` and no merge that yields an old-to-new
map.

Resolution is `read_layout` taking the caller's `&mut StrTable`, which is a
signature change. The cost of not having it is one extra parse of a small JSON
per run — one file, once, outside every loop.

---

## the antenna family

Not a Definition-Phase *omission* — a Definition-Phase **duplication**. The
antenna family was defined twice, once in `drc` and once in `erc`, under the same
deck kind name, each crate's module doc arguing for its own ownership without
knowing the other existed. `crates/erc/src/rules/antenna.rs:8` had a section
headed "Why these are here and not in `drc`" while
`crates/drc/src/rules/antenna.rs` implemented the same rule.

**Resolved: `erc` owns the family. `crates/drc/src/rules/antenna.rs` is
deleted.** The reason is `erc`'s own — an antenna ratio accumulates the
collecting area of everything electrically joined to a gate *at the stage that
layer is etched*, which is a net question with a layer cut-off, not a geometry
question. `drc` stays pure geometry, which is how `CLAUDE.md` frames it.

`drc::ruleset::KINDS` went from 26 names to 24 (`"antenna"` and `"antenna_car"`
removed, every later dispatch index shifted down by two, every
`debug_assert_eq!(KINDS[kind], ..)` kept and still passing). The two `KINDS`
arrays are now disjoint, which is what makes "a deck row belongs to exactly one
domain" true.

Two things `drc`'s implementation had that `erc`'s does not. Neither is silently
dropped; both are open signature defects.

### 1. A gate is a device, not a layer — open

`erc::AntennaTable::gate` and `AntennaElectricalTable::gate` are
`Vec<LayerRef>`: the deck names a layer and the rule sums the area of whatever
sits on it. `drc` instead took the gate from
`topology::DeviceTable` — a recognised MOS device, area = the measured
`DeviceParam::Area`, net = the terminal whose role is `TerminalRole::Gate`. That
is exact and canonical, it is the same number `lvs` and the device recognisers
already agree on, and it works whatever the deck calls its layers. The
layer-named form measures the wrong polygon on a deck that draws its gate
differently, and nothing at all on one that has no such layer — under-reporting
the denominator, which raises the ratio, or over-reporting it, which lowers it.
The second direction is fail-**open**.

`erc::Design` already carries the `DeviceTable`, so the input is present. What is
frozen is the `gate` column itself and the deck schema behind it — `layers[0]` is
the gate and `layers[1..]` the collectors, in `RuleSet::from_deck`
(`crates/erc/src/ruleset.rs:482`, `:509`). Replacing the column with a
device-derived gate-area table is a signature change and is therefore filed here
rather than made by a body.

The deleted implementation is the starting point, not a rewrite from scratch:
`git show 9abb3e2:crates/drc/src/rules/antenna.rs`, functions `gate_of`,
`gate_areas_into` and `gate_rows_into`. `gate_areas_into` in particular is a
tested transform — three transistors, two on one net, coming back as two rows
ascending by net with the shared net carrying the sum — and its test went with
the file.

### 2. The cumulative ratio is per fabrication stage — half open

At the moment metal *k* is etched, only layers up to *k* exist, so a wire later
tied to a huge upper plane is at that instant just itself. A cumulative check is
one measurement per stage, worst stage winning, not one measurement over the
final stack.

The **accumulation** half is expressible today and is now tested:
`AntennaTable`'s collectors are a CSR list, so a cumulative rule is one row per
stage with row `k` naming everything present when layer `k` is etched. Each stage
gets its own `RuleRun` and its own limit, which is more legible than one row
folding a worst-stage maximum. `antenna_electrical` takes the same list plus the
diode terms, so a per-stage rule *with* a protection diode is one
`antenna_electrical` row per stage. No third table is needed and none was added.
Stated at `crates/erc/src/rules/antenna.rs` (module doc and both table docs) and
pinned by
`a_cumulative_antenna_check_measures_each_fabrication_stage_over_what_exists_at_it`
in `crates/erc/tests/antenna_and_density.rs`.

The **connectivity** half is still open, and the entry moves here unchanged from
`## drc`: `erc::Design` (`crates/erc/src/lib.rs:129`) carries a `GeometryStore`,
an `Evaluator`, a `NetTable` and a `DeviceTable`, and no bridge to the deck's
`Connectivity` — the conductor layers, the via cuts and the pair each cut joins.
Rebuilding the net partition at stage `k` needs exactly that type, and
`topology::extract_nets_into` is already the right callee and already takes it.
Without it every stage reads the **final** partition, which is a superset of
every stage's, so a stage is credited with area a rebuilt graph would have left
disconnected: the ratio comes out too high, never too low. That direction is loud
rather than silently clean, which is why the rule ships under it — but a deck
tuned against it will see false violations on long lower-level collectors.

### 3. `drc` refused a design with no gates; `erc` runs over it — open

Not one of the two the consolidation was asked to carry, found while carrying
them. `drc::check_antenna` recorded `Outcome::Skipped(SkipReason::EmptyLayer)`
for a design with no recognised MOS device, on the argument that a ratio with no
denominator has no verdict and that a deck whose device recognisers never matched
is exactly the deck that would otherwise look fully checked.
`erc::check_antenna` records `Outcome::Ran` with `examined == 0` for the same
design.

Neither is silent — `examined == 0` is in the report — so this is a reporting
convention, not a lost check. It is not resolved here because
`crates/erc/tests/dispatch.rs`'s
`without_intent_exactly_the_six_gated_kinds_record_themselves_skipped` pins
`Outcome::Ran` for `antenna` and `antenna_electrical` over a `NetTable::default()`
cell, and that test is the specification. Changing the convention means changing
that test, which is a decision above a body's pay grade.

---

## erc, second `ponytail:` spend-down pass — `rules/electrical.rs`

Two markers in the file, one spent in place, one re-confirmed as blocked.

**Spent.** The `check_ir_drop` per-node `IntentMap::limits_of` binary search is
gone: `crates/erc/src/rules/electrical.rs:335` now builds a dense
`NetId`-keyed `limit_row_of_net` column plus a `limits_by_row` table whose row
`0` is the all-`None` sentinel, both hoisted above the rule-row loop because
design intent is a uniform of the whole transform. The node body is two indexed
loads and no data-dependent branch, which is the shape `check_branches` already
uses for its layers. No signature moved. Note that this **weakens** the "the
compact form triples the search" argument recorded in the previous pass against
compacting the node loop: the search it would have tripled no longer exists, so
that entry should be re-costed against the dense lookup, not against a binary
search.

**Still blocked, and sharpened: `PowerGrid` has no per-edge temperature.** The
existing entry above stands unchanged — a scalar `operating_temperature` derates
every edge identically and that is fail-**open**, because self-heating puts a
carrying conductor above the applied point and a hotter conductor derates
further. What this pass adds is how small the missing datum is. Two of the three
factors in the self-heating term are *already in this file*: the Joule power of
an edge is `solution.branch_current[edge]^2 * power.edge_resistance[edge]`, both
columns read in `check_branches` today. The only thing absent is the thermal
resistance that turns watts into kelvin — one number per layer, `K/W`,
alongside `max_density` and `blech_limit` in `ElectromigrationTable`'s CSR
columns.

So the resolution has two rungs, not one, and the cheap rung is not the one the
previous entry names:

  1. `thermal_resistance: Vec<Qty<..., K/W>>` on `ElectromigrationTable`,
     parallel to `max_density`. `arrhenius_derating` moves inside the edge loop
     of `check_branches`, which then takes the Arrhenius parameters instead of a
     precomputed `derate`, and the operating temperature per edge is
     `operating_temperature + I^2 * R * theta`. This is one new CSR column on a
     table in this file and one deck field to read it; no other crate changes,
     and it closes the fail-open direction with the data already in hand.
  2. `edge_temperature: Vec<Qty<Temperature, BASE>>` on `PowerGrid`, written by
     `power::extract_into` from a real thermal model. Strictly better, strictly
     more expensive, and it needs a model this workspace does not have.

Rung 1 is the one to price first. Both are frozen signatures; neither was made
by this pass, and the `ponytail:` marker at
`crates/erc/src/rules/electrical.rs:730` stays because the ceiling is still
being paid.

## drc/rules/patterning.rs, from the `ponytail:` spend-down pass

One `ponytail:` comment in the file, at `color_into`'s counting sort. It is the
`ColorScratch` entry already filed above under `## drc`, and the spend-down pass
could not spend it. Three things the earlier entry did not say.

**The arity is pinned by the suite, not only by the freeze.**
`crates/drc/tests/patterning_rules.rs` calls `color_into(nodes, &edges, palette,
&mut colours)` at five sites across four tests —
`a_graph_built_from_a_colouring_is_coloured_completely_and_properly`,
`an_odd_cycle_is_proved_infeasible_and_leaves_no_partial_colouring_behind`,
`the_node_an_infeasible_graph_names_is_the_same_on_every_run` and
`a_graph_with_a_four_clique_is_never_reported_three_colourable`. A fifth
parameter does not compile against them. The suite is the specification, so this
is not a signature a body may widen even with the freeze lifted; it is a test
edit first and a signature change second.

**What a caller-owned buffer would actually buy.** Thirteen allocations per
call: `adj_start` and its `cursor` clone (`n + 1` u32 each), `adj` (`2E` u32),
`adjacent` (`n × k` u32), `sat`/`pick` (`n` u32 each), `next`/`used` (`n`/`n + 1`
u8), and `SatQueue`'s five (`by_rank`, `rank` at `n` u32; `bits`,
`summary` at `(k + 1)` bitsets; `count` at `k + 1`). Plus `two_color_into`'s
`frontier` on the `colors == 2` path. The malloc count is the small half — the
dominant term is zeroing `adjacent`, `n × k` u32, which a reused buffer still has
to clear on entry. A full-reticle metal layer at two million shapes and three
masks is 24 MB memset per rule row either way. The parameter removes the
allocator traffic and the page faults, not the clear.

**No partial fix inside the body.** Dropping the `cursor` clone (fill through
`adj_start` and shift it back) removes one of the thirteen and replaces a memcpy
with a serial backwards shift, which is not obviously a win and costs the
counting sort its legibility. Coalescing the rest into one arena is blocked by
the mixed element types. The comment stays as debt, marking the one interface
that cannot meet `docs/CONVENTIONS.md` §4 from inside.

## pex quasistatic/matvec.rs, second `ponytail:` spend-down pass

The three entries under "pex quasistatic, from the `ponytail:` spend-down pass"
above were re-examined against the frozen signatures. Two stand unchanged. The
third was half executable inside them and has been executed; what is recorded
here is the residue plus one blocker the earlier pass did not name.

**The FMM blocker has a second, independent half: the byte-gated left fold.**
The recorded blocker is that neither `CpuMatVec::build` nor `Accuracy` can carry
the far-field truncation. Correct, and there is a second one that no accuracy
parameter would resolve. `apply_observed`'s inner loop is a strict left fold in
ascending `j`, and its comment says why: `Accuracy` and the exported netlist are
byte-gated, so the sum must not be reassociated — which is also why the loop is
deliberately not vectorised. An FMM does not fold in ascending `j`. It sums a
near-field block, then adds a multipole contribution accumulated in tree order,
which is a different association of the same terms and therefore a different
`f64`. So even given an expansion-order parameter and a truncation field, an FMM
adapter could not be bit-compared against the direct one, and the direct
adapter's own output bits would move the day the tree replaced it.

Consequence for whoever takes the upgrade: the FMM is a *third* adapter behind
`MatVec`, not a replacement of `CpuMatVec`'s body. `CpuMatVec` stays the exact
`f64` reference the `f32` device path is differentially tested against, and the
byte-reproducibility claim stays attached to it rather than to the seam.

The same argument rules out the one asymptotic win that needs no new signature:
`P` is symmetric, so evaluating the upper triangle and scattering each kernel
value into both `y[i]` and `y[j]` halves the kernel evaluations exactly. It also
accumulates `y[i]` in an order that is neither ascending `j` nor fixed, so it is
reassociation by another name. Not taken.

**`mesh::Panel`'s missing edge lengths stand as recorded, and they are a
correctness gap, not a performance ceiling.** Nothing on `Panel` — a centroid, a
unit normal, an area and a conductor id — recovers an aspect ratio, and
`CpuMatVec::build` is handed the `Mesh` and nothing else, so the closed-form
rectangle self-potential is unreachable from this file. The diagonal of `P` is
therefore low by 12.5% at 4:1 and 64% at 100:1, on the entry the solve is most
sensitive to. `Panel { extent: [f64; 2] }` remains the wanted change.

**The layered-dielectric entry's second half was executable and has been taken.**
That entry closed with a sub-decision left open: "for two panels either side of a
planar interface the standard two-medium result averages the *permittivities*
… which is the harmonic mean of the coefficients rather than the arithmetic mean
the code takes". It needs no signature change — both means are functions of the
two `Collocation::coefficient` values already in hand — so it is a body, and the
body has been changed. `apply_observed` now evaluates
`2 k_i k_j/(k_i + k_j)` where it evaluated `½(k_i + k_j)`.

It is the closed form, not a second arbitrary symmetric function. A charge in
`ε_i` observed across a planar interface from `ε_j` produces
`q/(4πε₀ ½(ε_i + ε_j) r)` — Jackson §4.4, transmitted image of strength
`2ε_j/(ε_i + ε_j)` — and `1/(4πε₀ ½(ε_i + ε_j))` is `2 k_i k_j/(k_i + k_j)`.
Symmetric, so reciprocity and `Accuracy::asymmetry` are untouched; equal to `k`
when `ε_i = ε_j`, so a uniform stack is unmoved. As the earlier entry predicted,
every test in `crates/pex/tests` builds a uniform stack
(`uniform_stack(3, 1.0, 0.25)`, and `epsilon: vec![1.0; _]` at the three places
a `Mesh` is written by hand), so the suite is blind to the difference and the
change is invisible to it: 70 passed before, 70 after. It ships without a
definitive test for the non-uniform case, which is the `docs/NEED_TESTING.md`
shape — the oracle that would catch it is a two-half-space closed form, and no
fixture in the crate can express two half-spaces.

What is left of that entry is the genuine signature blocker and is narrower than
it was: a full layered Green's function is an image series over *every*
interface the field crosses, and needs the interface planes and the permittivity
either side of each. `Mesh::epsilon` gives one value above one panel.
`CpuMatVec::build(mesh: &Mesh, stack: &ProcessStack)` remains the wanted change.
The `ponytail:` comment at the kernel now marks that residue only, and states
the ceiling it accepts: exact for two half-spaces and for a uniform stack,
under-resolved for a pair separated by more than one interface.

---

## export/netlist.rs, from the `ponytail:` spend-down pass

**Re-verified, still blocked: `PortTable` publishes no iterator, so `.subckt`'s
pin list is built by asking every net whether it is a pin.** The entry above
under `## export` stands unchanged; the ceiling is real, the upgrade is a row
accessor on `PortTable` (`crates/topology/src/port.rs:29-42`), and the signature
is frozen, so `crates/export/src/netlist.rs:138` keeps its `ponytail:`. Two
things this pass adds.

**One route sidesteps `net_count` and is wrong.** `StrTable`'s ids are dense
`0..len()` and `resolve` is total over them (`crates/ingest/src/intern.rs:149`),
so a writer could walk every interned string, ask `PortTable::net_of` about
each, and sort the hits by `NetId` — `O(S log P)` against `O(N log P)`, with the
string count in the thousands where the net count is in the millions. It drops a
pin. `net_of` answers with the *lower* net when one label reaches two
(`port.rs:89-100`), and `bind_ports_into` refuses only the converse — one net
carrying two labels (`PortError::ConflictingLabels`) — so two nets sharing a
label is a representable table whose second net this route never sees. Recorded
so the next pass does not rediscover it as an upgrade. A row accessor has no
such ambiguity; that is still the resolution.

**A port bound outside `0..net_count` was silently dropped, and is now
refused.** Found while spending the comment above, and fixed in place rather
than filed: the scan only visits nets the extraction has, so a binding whose
`NetId` is the `NetId::NONE` sentinel or belongs to a different extraction never
answers, its pin never reaches the `.subckt` line, and every device card still
names the node — a port demoted to an internal node in a file that parses,
simulates, and answers a different circuit. The old entry assert
(`ports.len() <= net_count`) caught only the count overflowing the range and
caught it as a debug panic, which is the wrong failure and unreachable by a test
of the refusal. `write_spice` now counts the pins the scan emitted and returns
`WriteError::Unrepresentable` when that is fewer than `ports.len()`; the count is
the only evidence this interface can produce that the scan saw every binding. No
signature moved — `Unrepresentable` was already in the return type.

---

## cli, second `ponytail:` spend-down pass over `crates/cli/src/format.rs`

Both entries in `## cli, from the ponytail: spend-down pass` above are revisited
here. One is closed from the cli's side; the other is confirmed unfixable in
this file and left alone.

**NARROWED — `units` has no `Grid::to_area`.** The *drift* the entry describes
is gone; the missing signature is not. `crates/cli/src/format.rs`'s
`write_measurement` grew a `Measurement::Area` arm, so the text report now
states an area in `nm^2` and states the same number the JSON report of the same
run does — `12000 dbu^2` against `3000 nm^2` at `dbu_per_um == 2000` was two
reports of one run in two units, and is now one.

The entry above rejected this on the grounds that it would be "a third private
derivation of one conversion". It is not, because the arm does not derive
anything: it reads the factor back out of the public conversion,
`grid.to_length(Dbu::new_unchecked(1)).raw()`, and squares that. There is one
statement of the physics in `gpurify-cli` and it is `Grid::to_length` — the same
one the `Length` arm beside it uses. It is bit-identical to
`export::json::nm_per_dbu` (`1.0 * 1000.0 / per_um` reassociates to nothing;
`1.0 * 1000.0` is exact), so the two writers cannot disagree on a value even
before the shared function exists.

What is still open is the same signature as before, and its remaining reader is
now only `export`: `Grid::to_area(self, DbuArea) -> Qty<Area, …>` in
`crates/units/src/dbu.rs` beside `to_length`, with `json.rs:257`'s private
`nm_per_dbu` and its squaring deleted in favour of it. `gpurify-cli` would route
through it too, but it no longer *needs* to.

`units::arith`'s `Length * Length => Area` is not that function and cannot be
made into it: it yields `Qty<Area, 0>` — square metres — and this crate's prefix
model puts the prefix on the value rather than under the exponent, so a `nm^2`
reading would have to be spelled `Qty<Area, -18>` and would `Display` as
`am^2`. An attometre squared is `10^-36 m^2`. That is a wrong label rather than
an unfamiliar one, which is why the cli arm formats its own suffix and why
`Grid::to_area` needs a return type chosen deliberately.

Pinned by
`crates/cli/src/format.rs::tests::an_area_is_converted_through_the_same_grid_factor_a_length_is`
— closed form, on a 2000-unit micrometre: one unit is 0.5 nm, so 4 dbu is 2 nm
and 48 dbu^2 is 12 nm^2.

**UNCHANGED — an LVS `Verdict` cannot be named in `gpurify-cli`.** Confirmed
still true and confirmed unfixable inside `format.rs`: both halves of the stated
resolution are edits to other files (a `pub use` in `crates/engine/src/lib.rs`,
or a manifest edge in `crates/cli/Cargo.toml`). Nothing in the cli's five
dependencies re-exports the type either — `gpurify-export` depends on
`gpurify-lvs` and never names `Verdict` in its own public surface, so there is
no back door through the writer crate.

Two facts checked while confirming it, both of which bound how bad the entry is
and neither of which was recorded above:

- It is not a lost finding. `engine::run_lvs` already turns every `Discrepancy`
  of a `Verdict::Mismatch` into a `Severity::Error` row of `Outputs::violations`
  (`record_discrepancies`), which `write_violations` prints above the `Debug`
  line with the rule name resolved; and `Verdict::Inconclusive` is mapped into
  the stage's own `StageStatus`, which `write_summary` prints. The `Debug` line
  is a supplement to both, not the sole record, so the entry above overstates
  the consequence when it calls this "the only place the verdict is readable at
  all". The unresolved `StrId`s are a legibility cost, not a fail-open.
- `crates/cli/src/main.rs:132-133` calls `write_violations` and `write_summary`
  as a pair on every path, so there is no caller that sees one without the
  other.

The comment at the site was rewritten to drop the `ponytail:` prefix — it names
a module-graph fact, not a corner this file cut — and to state both bounds.

**Unrelated, found while confirming the above: `export::json` does not write the
LVS verdict at all.** `crates/export/src/json.rs` never names `Verdict` or
`Discrepancy`, so the machine-readable report of a run carries the mismatch only
as the sentinel-coordinate violation rows `record_discrepancies` produced —
`LayerId(u16::MAX)`, `PolyId(u32::MAX)`, origin — with no statement of which
verdict was reached. A consumer parsing the JSON cannot tell `Match` from
`Inconclusive`: both are zero LVS rows. That is the false-clean shape, one
format over. Not filed as a signature defect, because nothing is frozen against
it: `gpurify-export` already depends on `gpurify-lvs` and already holds the
`StrTable`, so a `"lvs"` object is a body in `json.rs` and not an interface
change anywhere.

## report/violation.rs, from the `ponytail:` spend-down pass

**`Violations::sort_canonical` takes no scratch, so it allocates once per
column per call.** The same shape as the `pex/network.rs` entry above, and it
gets the same split: the affordable half was taken, the half that needs a
signature is refused.

Taken — `sort_canonical` (`crates/report/src/violation.rs`) now sorts the
permutation with `sort_by_cached_key` instead of `sort_unstable_by_key`.
`sort_unstable_by_key` is defined to call its extractor on every comparison, and
the extractor here is `row_key`: nine gathers across nine columns plus two
`Measurement` matches, assembling an eighty-odd-byte tuple. On a table the type's
own doc comment sizes at tens of thousands of rows that is ~2·n·log n rebuilds
where n is enough. Caching makes it one per row. Unstable was not load-bearing:
`measurement_key` is injective on all seven variants, so two rows with equal
`RowKey`s agree in all eight columns and their relative order is unobservable —
which is exactly the claim `sort_canonical`'s doc comment already makes.

Refused:

```rust
pub fn sort_canonical(&mut self)
```

`permute_column` gathers `new[i] = old[perm[i]]` into a fresh `Vec` and moves it
over the column, eight times. There is no parameter a reused buffer could arrive
in, and unlike the `pex` twin — three columns of two element types — the eight
columns here hold eight distinct element types, so even a single hoisted buffer
would have to become eight. Resolution, when a profile asks: `sort_canonical`
grows a `scratch: &mut ViolationScratch` parameter owning the eight typed
buffers, and `permute_column` takes its own as `&mut Vec<T>`. That is a signature
change; this is not the Definition-Phase.

Permuting in place is *not* the way out and was not taken. Cycle-chasing needs a
visited set and makes row N read what row N-1 wrote — the serial case
CONVENTIONS §2 sends to two passes — and it replaces a branch-free gather whose
only data dependence is the load address with a loop-carried chain carrying a
data-dependent exit. Fewer bytes, worse kernel.

## drc/rules/width.rs, second `ponytail:` spend-down pass

The entry under `## drc/rules/width.rs, from the ponytail: spend-down pass`
stands: `ValidatedLayer::ring_poly` is a filled column of a frozen type with no
reader, and `OuterRows` (`crates/drc/src/rules/width.rs`) still replays the
winding filter to rebuild it, once per rule row, for both `check_facing` and
`check_min_edge_length`. Removing that pass is still one accessor —
`ValidatedLayer::provenance(&self) -> &[PolyId]`, the same fix already recorded
for `spacing::wide_flags_into`, `overlay` and `patterning` — and still not a
body. Two corrections this pass makes to it.

**"There is no cheaper replay" was too strong, and the cheaper replay is now
in.** The claim conflated the pass with the shoelace inside it. `winding_of`
answers for a ring of any shape and pays a widening `i128` multiply per vertex;
every ring `OuterRows` reads has already been through `validate_layer_into`,
which refuses non-simple, non-rectilinear and zero-area input, and on *that*
domain the winding is read off the bottom edge — the interior lies above every
horizontal edge at the ring's minimum `y`, so such an edge travels `+x` exactly
when the ring is counter-clockwise. `ring_winding` folds that in two integer
compares and two selects per edge over the two coordinate columns, with no
data-dependent branch and no multiply at all. A horizontal edge at the minimum
`y` always exists: the vertex there cannot carry two vertical edges, because
both would leave it upwards from the same `x` and overlap over a positive
stretch, which is the self-intersection `classify_ring` already refuses. The
function ends by asserting its answer against `winding_of`, so every debug and
test run differentially checks the fast path against the shoelace it replaced,
on every ring the width family reads. That is a body, and it landed; the pass it
sits in is what remains blocked, so the site's comment now names the block
rather than wearing a `ponytail:` prefix.

**The replay is exact, and the argument is worth keeping written down**, because
the cheap-looking alternatives are not. `validate_layer_into` emits one polygon
per counter-clockwise row of the layer, in ascending row order, and `OuterRows`
replays exactly that filter over exactly those rows — so index *i* of
`ValidatedLayer::get` is the *i*-th counter-clockwise row, with nothing to tie
break. Two routes that avoid the pass entirely do not survive: matching the
validated `bboxes()` column against `GeometryStore::poly_bbox` row by row can
bind a validated polygon to a *hole* whose box happens to coincide with some
other outer's, and matching on the first vertex alone can collide an outer with
a hole that touches it there. Comparing the whole coordinate run is exact —
`push_ring` copies verbatim, identical coordinates force identical winding — but
it is another pass over the same coordinates, so it buys nothing the accessor
would not buy outright. Recorded so the next pass does not rediscover any of the
three as an upgrade.

---

## core::index, second `ponytail:` spend-down pass

**RESOLVED — the scratch `Vec` in `candidate_pairs_into` /
`cross_layer_pairs_into` is gone, and it was never a signature defect.** The
entry under *`## core, from the ponytail: spend-down pass`* above rests on one
premise that has since expired: *"It cannot be `out`. `compact_into` needs a
source distinct from its destination."* `bulk::compact_into` no longer exists —
the module was inlined and deleted — and the hand-written compact at the site
has no such requirement. The write cursor `w` never outruns the read cursor `i`,
because `w` advances by `usize::from(p) ∈ {0, 1}` each iteration, so a survivor
is only ever written into a slot that has already been read. `prune_pairs`
(`crates/core/src/index.rs`) now gathers the raw superset straight into `out`,
sorts and dedups it there, and compacts in place with a `truncate`. The other
two bullets of the old entry stand and were not touched: the predicate still is
not folded into the gather, and no `thread_local` was introduced.

Consequence for the seam: `report_prune` runs *before* the compact rather than
after, since the compact is now what destroys the examined list. It takes the
pairs as a shared slice, so the observed and unobserved answers are still
identical by construction — pinned by
`installing_an_observer_does_not_change_the_pairs_that_come_back`.

**`gpurify-core` cannot host the parallel form of either loop in
`crates/core/src/index.rs`, and this is a manifest decision, not a body.** Two
sites, both left sequential and both now commented as facts rather than as debt:

- `Grid::build_into`'s bucket histogram. The parallel form is per-thread counts
  merged before the prefix sum.
- `prune_pairs`'s outer row loop, which `gather_level` feeds. Each `a` writes
  only its own pairs, so it is already a gatherer; the parallel form is a
  per-worker `Vec` reduced before the existing sort, and the sort is what keeps
  the result deterministic whichever way the workers interleave.

`gpurify-core` sits at the base of the module graph with two dependencies,
`gpurify-units` and `thiserror`. Adding `rayon` there is the same open decision
already filed for `crates/lvs/src/graph.rs` (net-terminal histogram) and
`erc::Scratch` (the nineteen rule transforms) — this is the third and lowest
site, and the one every other crate's geometry work routes through, so if the
decision is ever taken it should be taken here first.

**Not a defect, recorded so the next pass does not re-open it:** the duplicate
pair filings `gather_level` produces cannot be removed by emitting a row only
from its "home" cell. A box is filed under every cell it overlaps precisely
because the cell nearest the querying box is the one that survives the
`cell_bbox(..).within(a_box, distance)` test, and that cell is not in general
the home cell — the home cell can sit outside the query window while another
filed cell sits inside it. Dropping the extra filings is fail-open; the
`sort_unstable` + `dedup` in `prune_pairs` is the cheap end of that trade.

### A release-only fail-open, fixed

`candidate_pairs_observed` and `cross_layer_pairs_observed` carried a
`debug_assert!(index.layer.is_some(), ..)` whose own comment named the hazard
exactly — *"Returning an empty list for it would report a clean check that never
ran — the fail-open shape `docs/VOCABULARY.md` §3 names"* — and then returned an
empty list anyway, because the assertion is compiled out of a release build and
the `let .. else { return }` under it is not. A signoff run is a release build.
An index that was never built therefore answered every spacing and overlay query
with "no candidate pairs", which is indistinguishable from a clean layer at
every layer above.

Both are now `Option::expect`. The signature returns `()` and has no error
channel, so a panic is the only fail-closed answer available from inside a body;
the cost is one perfectly-predicted test per *query call*, not per pair. No
caller in the workspace queries an unbuilt index — `drc::rules::{spacing,
overlay, via, patterning}`, `topology::{net, device}` and `core::view` all call
`SpatialIndex::build_into` first — so this closes a hole rather than changing
any current behaviour.

## pex quasistatic/gpu.rs, from the `ponytail:` spend-down pass

One `ponytail:` comment in the file, at `Device::find`. It is not a signature
defect — every signature in `gpu.rs` is already the one the finished adapter
wants, and the comment says so ("No signature above this line changes"). It is
recorded here because it is the other blocked kind: **the upgrade path exists,
is fully specified, and no step of it can be taken from inside the file.**

**What blocks it, step by step.**

1. *Add `vulkano` and `vulkano-shaders` to `crates/pex/Cargo.toml`.* Both are
   pinned in the workspace manifest at 0.35 and neither is a dependency of
   `gpurify-pex`, so there is no path from `find` to a Vulkan instance. A
   manifest edit, not a body edit.
2. *AOT-compile the P2P Laplace shader.* Needs a `build.rs` and a `.comp`
   source file, i.e. two new files in the crate. `docs/GPU.md` found this the
   only GPU-suitable kernel of the original five, and it is already written in
   `f64` as the inner loop of `matvec::CpuMatVec::apply_observed` — the port is
   a transcription, not a derivation.
3. *Probe for a compute queue and enough device memory.* This one genuinely is
   a body, and it is the only step that would land in `gpu.rs`. It is dead
   weight without step 1.
4. *Benchmark the crossover and return it from `Device::crossover`.* Needs a
   device. `docs/GPU.md` contract item 6 requires the number to be *measured*;
   `matvec::select` carries a `debug_assert` that a crossover of zero is not a
   measured number, and any invented value is the same fail-open error one
   notch further along.

**The comment's contract accounting was wrong and has been corrected in place.**
It claimed items 3, 4 and 6 could not be met. Items 4 and 5 are met today and
are met on the host, so no device gates them: `solve::refine` bounds the answer
with an `f64` residual, `Accuracy::backend` is read off the adapter that
actually ran, and
`pex/tests/quasistatic.rs::the_device_is_selected_only_above_its_own_measured_crossover`
runs unignored and asserts the fallback on its no-device branch — which is
contract item 5 discharged, not deferred. The genuinely open items are 1, 2, 3
(all device-side) and 6.

**A determinism constraint the port inherits, recorded because it is cheapest to
know before the kernel is written.** `CpuMatVec::apply_observed` folds over `j`
strictly left to right, because `a_field_solve_is_byte_identical_across_runs`
byte-gates the assembled matrix. A device kernel therefore needs a *fixed*
reduction order — a tree reduction over a fixed lane assignment qualifies, an
atomic accumulation whose order depends on scheduling does not. Neither will
agree bit-for-bit with the host fold, and neither has to: contract item 5 asks
for agreement "within the documented tolerance", and `Backend` exists precisely
so a run's numbers are attributed to the adapter that produced them.

**Not filed as a correctness gap.** Every fallback here is fail-*closed*.
`find` returns `Ok(None)`, `crossover` returns `usize::MAX` so `select`'s
`panels >= crossover` never fires, `upload` returns `Err(NoDevice)`, and
`quasistatic::extract_into` lands on `CpuMatVec` through all three. The
fail-open direction would be a small invented crossover routing a signoff
number onto an unvalidated `f32` path, and nothing in the file points that way.

The `ponytail:` marker stays. The ceiling — the host runs every solve at every
size — is real and is still being paid.

---

## lvs::graph, second `ponytail:` spend-down pass

`crates/lvs/src/graph.rs`, revisiting the three entries under `## lvs::graph,
from the ponytail: spend-down pass`. One of them is closed without touching a
signature; the other two stand, with the argument for why sharpened so neither
gets re-attempted from inside a body.

**CLOSED IN-BODY, no signature change — `from_reference_into`'s per-call
`Vec<u32>`.** The entry above asked for `&mut Vec<u32>` on the signature or a
`pub` scratch column on `RefGraph`, on the grounds that `graph_net` is indexed by
*global* reference row and so cannot be folded into any column `Graph` carries,
"every one of those is `net_count` rows, not `rows`". That last clause is what
was wrong: a `Vec<u32>`'s *capacity* is not tied to the length its column
eventually holds. `Graph::net_terminal_start` is a `Vec<u32>`, it is caller-owned
inside `RefGraph`, and nothing reads it between the top of `from_reference_into`
and `transpose_into`, which clears and rebuilds it from the histogram. So the
rank table borrows it for the length of the projection and `transpose_into`
recycles the capacity into the offset column it is nominally for. Hierarchical
comparison ran this once per cell, so the allocation scaled with
cells × netlist-nets; it is now one allocation per `RefGraph` across a whole run,
and `reserve` + `push` also drops the memset `vec![u32::MAX; rows]` paid for a
column it overwrote in full.

The cost is a stated window in which the struct is not self-consistent, and it
is written at the site rather than left to be tripped over: between the rank
pass and `transpose_into`, `net_terminal_start` holds `rows` ranks and not
`net_count + 1` offsets, so `Graph::net_count` and `Graph::terminals_on` would
each fail their own `debug_assert`. Nothing in that window calls either. A future
edit that adds such a call gets a debug-build panic, not silence, which is why
the window is acceptable at all.

**STANDS — `PortTable` publishes no column, so `from_layout_into` searches per
net.** Unchanged in substance, but two things about it were being read wrongly.

First, the `O(nets)` factor is not the debt and must not be "optimised" away.
The column being filled is `net_name`, one row per net; the pass is owed
whatever the lookup costs. Only the `log ports` factor is debt, and a linear
merge of the port column against `0 .. net_count` collapses it.

Second, the search is not reducible from inside the body, so nobody should spend
an afternoon trying. `PortTable`'s whole surface is `name_of(NetId)`,
`net_of(StrId)`, `len` and `is_empty`. Every one of those answers membership at a
point; none answers "how many ports below this net". With no rank oracle there is
nothing to gallop on and no way to narrow the next search's range with what the
last one returned, even though the queries arrive in ascending net order against
an ascending column. It takes `fn entries(&self) -> (&[NetId], &[StrId])`, or the
two columns made `pub`, or it stays a search per net.

**STANDS, and the comment is no longer a `ponytail:` — the transpose histogram.**
`gpurify-lvs`'s manifest does not carry `rayon`; the workspace's does. The
`ponytail:` prefix means debt that the file could pay, and this file cannot: the
parallel form is fully known (per-thread counts merged in bucket order before the
prefix sum, deterministic, scatter untouched), so what is missing is a dependency
edge, not an idea. The comment at the site now states that as a fact about the
module graph rather than wearing a debt marker. The entry above remains the
record.

### Not in `graph.rs`, found while reading it: `Graph::port_net` has no consumer

`Graph::port_net`'s own doc comment (`crates/lvs/src/graph.rs:78`) says "Matching
is anchored on these, so they are held separately rather than found by scanning
names." Nothing anchors on them. Both projections write the column —
`from_layout_into` ascending, `from_reference_into` in the subcircuit's declared
port order — and `grep port_net` across `crates/lvs` and `crates/engine` finds no
read outside `graph.rs` and the tests.

`refine::signature_round` seeds every net into one initial class and folds only
`(role, class)` multisets; `net_name` reaches the comparison exactly once, in
`compare::compare_net_name`, which reports a name difference between two nets the
refinement has *already* paired. So declared names are checked after the fact and
never constrain the search. A cell with two structurally identical halves is
resolved by `TieBreak`, or refused, when its port names determine the answer
outright.

Not fixed here: the fix is an initial colouring in `crates/lvs/src/refine.rs`
that separates port nets from anonymous ones — outside this pass's file, and a
behaviour change to the matcher rather than a debt spend-down. Recorded so the
doc comment and the code stop disagreeing silently.

---

## engine::run, second `ponytail:` spend-down pass

The two markers left in `crates/engine/src/run.rs` were re-examined against the
entries already recorded above under *engine::run, from the `ponytail:`
spend-down pass*. One is closed in the body; the other stands, and stands for a
narrower reason than it was first filed under.

**Closed: the quasi-static path no longer drops the nets it was not asked
about.** The earlier entry says "the two networks cannot be concatenated" and
proposes `pex::network::merge_into`. Concatenation is indeed illegal —
`ParasiticNetwork`'s node-order invariant (`crates/pex/src/network.rs:55`) is
what the writers scan on — but a *merge* is not, and it needs no signature:
every column of `ParasiticNetwork` is `pub`, `push` and `sort_canonical` are
`pub`, and `analytical::extract_into` emits nothing that spans two nets, so a
net's rows can be lifted out whole.

`run::merge_field_solved_into` now runs the analytical extraction over the whole
design first, then overlays the field-solved nets on it: a two-way merge of the
two node columns by `NetId`, which reproduces the contiguous-ascending invariant
rather than restoring it, plus a renumbering compaction over each element
column. Membership is read off `solved.node_net` rather than off
`RunOptions::quasistatic_nets`, so a net the caller selected and the mesh
produced no node for keeps its coarse rows instead of losing both.

The reporting half of the old entry — "a net absent from `Outputs::parasitics`
because it was never asked for reads exactly like a net extracted and found to
carry no parasitics" — is closed by construction: with the merge, a partial
selection still describes every net, so `StageStatus::Ran` is true of the whole
design and the ambiguity has no state to live in. `pex::network::merge_into`
remains the right *home* for the transform; it is no longer a blocker for the
answer.

What is still open from that entry is only the matrix: `quasistatic::CapMatrix`
is still dropped, because `Outputs` has no field for it. The coupling it
summarises does survive, as `Parasitic::CouplingCap` rows in the merged network,
so what is lost is the off-diagonal matrix form and not the physics.
**Resolution is a matrix field on `Outputs`, a Definition-Phase change.**

**Still open, and no in-body route exists: the sign-off temperature.** Recorded
here as re-examined rather than re-filed — the entry above states it correctly.
Every candidate source was checked in this pass and none carries an operating
corner: `engine::Inputs` (`crates/engine/src/pipeline.rs:18`) holds `layout`,
`deck`, `grid`, `reference`, `intent` and `unknown_layers`; `RunOptions` holds
`checks`, `lvs`, `quasistatic_nets` and `threads`; `ingest::deck::Deck`
(`crates/ingest/src/deck.rs:48`) holds `grid`, `layers`, `rules`,
`connectivity`, `devices` and `stack`. The only temperature the deck states is
per rule row — `reference_temperature`, read at `crates/erc/src/ruleset.rs:576`
and `:702` — and that is the *characterisation* point each row was derated from.
Reading it as the applied corner collapses the Arrhenius factor to unity, which
`crates/erc/src/rules/reliability.rs:165` names as a lifetime overstated rather
than a lifetime unmeasured: strictly more fail-open than the hard-coded 85 °C
is.

Nor can the constant be moved in the safe direction from inside the body. A
hotter default — 125 °C — derates more and would be the conservative choice, but
it is a number no input stated, and it changes every ERC limit in the suite,
which is the specification. `run::sign_off_temperature` therefore keeps its
`ponytail:` marker and its 85 °C. **Resolution is unchanged: a
`sign_off_temperature: Qty<Temperature, { prefix::BASE }>` field on
`RunOptions`, filled by `cli::args`.**

---

## topology/net.rs, from the `ponytail:` spend-down pass

**RESOLVED — the "no transform in `net.rs` can be handed reusable scratch"
entry above was wrong about why.** It recorded two resolutions, a `scratch`
parameter on the two public builders and an appending form of them, and called
both signature changes. The second is not: the appending form only has to be
*private*. `crates/topology/src/net.rs` now carries

- `EdgeScratch` — one `SpatialIndex` for the conductor layer, one for the cut
  layer, and four pair columns, held as a private field of `NetTable` beside the
  `edges`/`labels` scratch that was already there;
- `intra_layer_edges_append` and `via_edges_append` — the bodies, appending to
  `out` and borrowing an `&mut EdgeScratch`;
- `cuts_landing_on`, which is private and so simply took the index and the
  candidate column as parameters.

The two public builders are byte-for-byte the same interface: each is now
`out.clear()` plus a call to its appending form with `&mut
EdgeScratch::default()`, which is precisely what their bodies used to do inline.
`extract_nets_into` calls the appending pair directly, so a whole extraction
allocates one working set instead of one per conductor layer and one per via
layer, and the per-layer `extend_from_slice` copy out of a staging buffer is
gone. A second extraction into the same table allocates nothing at all, which is
what `extract_nets_into`'s doc comment already promised.

Two things the split needed and which are worth naming, because the same shape
will come up at every other site filed under "no scratch parameter":

- `via_edges_into` ended in `out.sort_unstable(); out.dedup()`. An appending
  builder owns only the rows it just wrote, so that became `sort_dedup_from(out,
  base)` — stdlib's pair restricted to a suffix, since `Vec::dedup` has no
  ranged form and `slice::partition_dedup` is unstable. The compact is
  branchless and `net::tests::deduplicating_a_run_leaves_the_rows_before_it_untouched`
  is the differential test against `sort_unstable` + `dedup`.
- `EdgeScratch` is destructured at the two `cuts_landing_on` calls. The borrow
  checker splits fields of a `&mut` struct but not fields reached through a
  call, so a scratch struct passed whole cannot also supply the callee's `out`.

**Still open, and genuinely blocked: `rings_meet_sweep`'s six per-call
allocations.** Unchanged from the entry above. `polys_intersect` is reached from
`retain_intersecting_into`, whose signature carries no scratch and which
`topology::device` also calls, so threading one is a change to a frozen
interface rather than a private refactor. The `DIRECT_PAIR_BUDGET` gate remains
the bound on it.

**Still open: the two public builders themselves.** `erc::power` and
`crates/topology/tests/edges.rs` call `intra_layer_edges_into` /
`via_edges_into` in loops of their own and still get a fresh `EdgeScratch` each
time. Fixing that is the *first* resolution above — a `scratch` parameter on a
public signature — and is unchanged by this pass. The cross-reference at
`crates/pex/src/analytical.rs:411` therefore still points at a live defect.

## pex quasistatic/solve.rs, re-examined in the second `ponytail:` spend-down pass

Re-opened to execute the upgrade path, not to re-decide it. **It is still
blocked, and the block is narrower and harder than the entry above states.**
Line reference corrected: the marker is `crates/pex/src/quasistatic/solve.rs:385`,
inside `refine` at `:378`. The `:341` above is stale.

Three things this pass established that the earlier entry did not.

**The first paragraph of the comment is a theorem, not a shortcut.** Restarted
GMRES is iterative refinement with the inner solver fixed at one GMRES(m) cycle,
term for term: `gmres` entered at a non-zero `x` forms `r = b − A x` in `f64` at
`:139`, builds the Krylov basis from it at `:176`, solves the least-squares
correction, and adds it at `:311`. An outer loop written as
`r = b − A x; gmres(A, r, opts, d, ws); x += d` reproduces that exactly when the
inner solve runs one cycle. So the *only* thing an outer loop can add is a
different inner stopping rule — which is why the whole upgrade rests on the
tolerance parameter and not on the loop.

**The buffer half cannot be worked around by moving the `Vec`s.**
`std::mem::take(&mut workspace.residual)` frees `r` from the borrow conflict the
entry above names, but the inner `gmres` then finds `workspace.residual` empty
and `residual()` reallocates it at `:420`. Capacity survives within one `refine`
call and dies with it, so the cost is one `panels × 8`-byte allocation per
conductor — the same cost as a local `Vec` and the same cost `Workspace` exists
to remove. `columns_into` (`crates/pex/src/quasistatic.rs:331`) allocates one
`Workspace` per *call* and reuses it across all `n` columns, so a per-column
allocation inside `refine` would be the only one in that loop. `d` has no
candidate at all: `krylov`, `hessenberg` and `givens` are cleared and resized at
`gmres` entry (`:115`–`:120`), and `correction` is the Arnoldi work vector.

**The tolerance half is a public interface change and there is no in-body
route.** `Options` is `pub` with three `pub` fields and is constructed by name in
`crates/pex/tests/solve.rs` and `crates/pex/tests/quasistatic.rs`. Deriving an
inner tolerance from `options.tolerance` inside the body — `sqrt`, a fixed
decade, anything — is inventing the number the caller was never asked for, which
is the class of decision the Implementation-Phase may not make.

Resolution unchanged and now stated as one change, since neither half is useful
alone: `Workspace { r: Vec<f64>, d: Vec<f64> }` (private, like the other five)
**plus** an inner tolerance on `Options`. `gmres`, `residual`, `MatVec` and
`Converged` do not move.

**Not a correctness gap.** Checked in this pass: `refine` cannot return a wrong
answer, only refuse to produce one. `gmres` checks convergence before the
iteration budget (`:147` before `:154`), reports the explicitly recomputed
residual rather than the recurrence estimate, and turns a rank-deficient
least-squares problem into `Breakdown` at `:304` rather than an unchanged `x`.
The `f32`-residual exposure the entry above describes stays latent: `Device`
compiles no device support (`crates/pex/src/quasistatic/gpu.rs:67`), so
`select` never returns `Backend::GpuF32` and `GpuMatVec` is never constructed.

## core/bbox.rs, second `ponytail:` spend-down pass

Re-examination of the `Bbox::width` / `Bbox::height` entry above (`## core/bbox.rs,
from the ponytail: spend-down pass`). It stands, unchanged, and this pass could
not close it from inside `crates/core/src/bbox.rs` either. What is new is the
proof that no in-file route exists, and two reachability facts the first pass
did not have.

**Line numbers.** The `ponytail:` comment is now `crates/core/src/bbox.rs:226`
and the two bodies are `:236` (`width`) and `:239` (`height`); the entry above
cites `:233,237` from before the file grew its `min`/`max` const helpers. The
second `ponytail:` that entry records — the missing segmented reduce in
`of_polys_into` — no longer exists: `gpurify-core::bulk` was inlined and deleted,
so the raw loop at `:320` is now the tree's ordinary per-site bulk discipline and
carries no debt marker. One `ponytail:` remains in the file.

**No const constructor in `gpurify-units` admits an out-of-domain `i64`.**
Exhaustively, the const surface is `Dbu::new` (returns `None` outside the
domain), `Dbu::new_unchecked` (`debug_assert!(in_domain(raw))`), `Dbu::raw`,
`Dbu::abs` (needs a `Dbu` already), `Dbu::mul_wide` (returns `DbuArea`) and
`DbuArea::new`/`raw` (wrong type). `Add`, `Sub` and `Neg` are non-const trait
impls and a `const fn` body cannot call one. The only in-file spelling left is
`unsafe { transmute::<i64, Dbu>(..) }`, which `Dbu`'s `repr(transparent)` would
make sound and which is nonetheless the wrong answer: it constructs another
crate's newtype past its private field, defeats the `in_domain` assert for every
future caller of `width` rather than for the one legal case, and violates the
parse-don't-validate seam `docs/CONVENTIONS.md` §3 puts at the crate edge. The
resolution named above — a `pub const fn Dbu::sub(self, Self) -> Self` in
`gpurify-units`, unchecked for the reason its `Sub` impl already states — is
still the only correct one, and it is still that crate's change.

**The suite already builds the box that fires it.**
`crates/core/tests/bbox_laws.rs:82` constructs `whole = bbox(-MAX_ABS_DBU,
-MAX_ABS_DBU, MAX_ABS_DBU, MAX_ABS_DBU)` and asserts `whole.area() == 2^82`.
`whole.width()` is `2^41` and would panic in a debug build; the test happens not
to ask for it. The defect is one assertion away from red, not four orders of
magnitude of layout away.

**`Bbox::EMPTY` reaches it without any large layout, through `of_points`.**
`Bbox::of_points(&[], &[])` returns `EMPTY`, whose `width()` is
`-MAX_ABS_DBU - MAX_ABS_DBU == -2^41` and fires the same assert. No caller in
the tree feeds an empty run to `width` today — `drc/rules/overlay.rs:886`,
`drc/rules/width.rs:594`, `erc/rules/reliability.rs:722` and
`erc/power.rs:2106,2155,2161` all take the box of a real polygon — so nothing is
red, but the path is a two-line reproduction rather than a hypothetical.

**Adjacent, and separately open: `Bbox::EMPTY` and the full-domain box have the
same `area()`.** Both are `±2^82`, because `area` multiplies the two bound
differences with no empty test: `EMPTY` differs from `whole` only in the sign of
each difference, and the signs cancel in the product. `EMPTY.width()` is
likewise `-2^41`, a negative width. So the largest possible area and "no area at
all" are the same `DbuArea`, which is the shape `docs/VOCABULARY.md` §3 calls
fail-open — a result that cannot be told from "not checked". This pass did not
change it: no caller passes an empty box, the suite specifies `area` as the
unconditional product of the differences
(`crates/core/tests/bbox_laws.rs:88-90, 258-262`), and picking `0` for the empty
case is a semantics decision, not a body. `drc/rules/overlay.rs:887`'s
`debug_assert!(smaller >= 0, "a non-empty figure has non-negative sides")` is the
one place in the tree that would currently catch it. Recording it here so the
decision is made where it is cheap, rather than by an implementation.

---

## pex/quasistatic.rs, second `ponytail:` spend-down pass

**Still open, and narrowed: `extract_into` has no `MeshOptions` parameter.** The
entry above (`## pex/quasistatic.rs, from the ponytail: spend-down pass`) stands
on its head — no parameter of the frozen signature carries a discretisation, so
`mesh_options` still chooses one and no caller can reach it. The fix is
unchanged: a `mesh::MeshOptions` beside the `solve::Options` already there.

What changed is the *default* it chooses, and one paragraph of that entry is now
wrong and is retracted here rather than edited in place.

**Retracted: "deriving `max_edge` from `ProcessStack::thickness_nm` … was
considered and also refused".** That refusal was a cost decision taken without
the cost, and this pass was directed to spend the shortcut down. `mesh_options`
(`crates/pex/src/quasistatic.rs:411`) now reads the resolution off the process:
the smallest length the stack states — any layer's `thickness_nm`, or any
positive gap between one layer's ceiling and another's floor — floored at one
database unit, and coarsened by `budget_edge` until the estimated panel count
fits `MAX_PANELS`. `proximity_refine` is the panel edge itself rather than zero.
`max_panels` is unchanged at `1 << 20`.

The measurement the refusal was missing, on `extracted(73, 24, 2)` against
`uniform_stack(3, ..)` — 100 nm layers on a 1 nm grid, so the chosen edge is
100 dbu against the 500 dbu the `Grid`-derived constant gave:

| panel edge | panels | GMRES iterations, both columns | `C[0][0]` | asymmetry |
|---|---|---|---|---|
| 500 dbu (the old constant) | 144 | 68 | 2.3613e-16 | 2.1e-12 |
| 250 dbu | 216 | 108 | 2.3883e-16 | 8.6e-12 |
| **100 dbu (chosen)** | **928** | **773** | **2.4229e-16** | **1.7e-11** |
| 60 dbu | — | over budget | `NotConverged` | — |

So the old default was 2.6% low on the self term and had not converged in the
mesh; neither has the new one, which is 1.4% off the resolution below it.

**And the claim the old `ponytail:` comment made for it is false.** It read
"[both halves of the ceiling] surface as `TooManyPanels` or as a discretisation
error in `CapMatrix::asymmetry`, which the caller is handed; neither is a
silently wrong number." The table says otherwise: asymmetry at 500 dbu was
2.1e-12, an *order of magnitude better* than at 100 dbu, while the capacitance
it accompanied was 2.6% low. Asymmetry measures reciprocity, and a uniformly
coarse mesh is uniformly coarse for both of a pair — it is symmetric about its
own error. Nothing in `Accuracy` reports under-meshing, so an under-meshed run
returns a confidently symmetric, systematically low capacitance and no caller
can tell. The honest disclosure is a mesh-convergence number — the same solve at
half the edge, and the change between them — which is a second solve and a field
on `Accuracy` that is not there. Recorded, not built.

The
cost is real and is stated here rather than discovered later: the `pex` test
binary goes from 0.04 s to 14.4 s in a debug build, all of it in the two
`extract_into` tests.

**The consequence to read before touching this again: the solver's iteration
budget, not the panel budget, is what now bounds the resolution.**
`solve::Options::max_iterations` is 400 in both tests and the chosen mesh spends
386 of it per column — 96%. One resolution finer is `SolveError::NotConverged`,
which is a refusal and not a wrong number, so the failure direction is right.
But it means the two `extract_into` tests pass with 4% headroom on a budget
nothing in the signature relates to the mesh, and the next change to either end
lands on it. Two ways out, both outside this file:

- `solve::refine` (`crates/pex/src/quasistatic/solve.rs`) runs GMRES with no
  preconditioner. The observed iteration count grows as roughly `n^1.1` against
  the `n^0.5` an unpreconditioned first-kind BEM operator is expected to need,
  and the operator's diagonal is its self-potential term — a Jacobi
  preconditioner is one vector and is the cheapest thing that would move this.
- the `MeshOptions` parameter this section opens with. A caller who owns both
  knobs can trade them against each other; `mesh_options` cannot, and
  deliberately does not try — a discretisation chosen to fit an iteration budget
  is a fitted constant wearing physics.

**Also still open, from the entry above: `core::index` has no
build-from-bbox-column seam.** It is no longer *unreachable*, though — that
entry records `proximity_refine` hardcoded to zero as the reason
`mesh::near_another_conductor`'s O(n²) scan ships with no coverage. It is now on
for every quasi-static run, so the scan executes; the two `extract_into` tests
place their conductors 400 dbu apart against a 100 dbu refinement distance, so
what they cover is the scan finding nothing. The refinement *path* — a solid
that is near another conductor and is meshed at half the edge — is still
untested. `docs/NEED_TESTING.md`.

## erc/power.rs, second `ponytail:` spend-down pass

Four comments went into this pass and none of them came out as a signature
defect *of this crate*. Two were spent, one was restated as a model fact, and
one is the same missing upstream column already recorded above. What follows is
the part that is new.

**The supply-grid anchor was worse than the entry above says, and is now
better.** The earlier entry records that `Connectivity` names no pad-marker
layer, which is still true and still wanted. What it also recorded — that "the
first tap of the first shape on the rail" is *the only choice deterministic
without one* — was wrong. `Process` already carries the `ProcessStack`, and
`height_nm` says which conducting layer is on top. Supply enters a die from the
top, through bumps or bond pads on the highest metal, so `extract_into` now
anchors at the centre tap of the rail's widest shape on its highest conducting
layer: highest metal, then largest bounding-box area, then lowest shape index.
Every tie is broken by data rather than by the order a reader emitted polygons
in.

That is a mitigation, not a closure, and the wanted column is unchanged: a
`pad_marker` on `Connectivity`, filtered in `extract_into`, pushing the marked
shapes as `source_node`. The residual is one anchor where a real rail has many,
and that direction is the safe one — fewer anchors means a longer path to every
load, so drop is over-reported. The direction the old shape had was the unsafe
one.

**The per-terminal current column is still the blocker it was.** Re-confirmed
against `IntentMap`: `budget_current_ua` is per net and there is no per-instance
or per-terminal current anywhere in `intent` or `DeviceTable`, so the uniform
spread is what the input supports and not a shortcut taken over a better one.
The comment in `extract_into` no longer carries a `ponytail:` prefix, because
the prefix means spendable debt and this is not spendable from inside this
crate. Nothing about the wanted column changes.

**Not a defect, spent instead: the bounding-box chain width.** A polygon's chain
resistance came from `min(bbox.width, bbox.height)`, which is the polygon's own
width only when the polygon is a rectangle. An L-shaped route has a square box,
so a `100 x 100` outline on ten-wide arms was spending one square where it has
9.1 — a resistance nine times low, in the fail-open direction, for all four
rules that read a solved grid. `ChainProfile` now integrates `∫ ds / w(s)` over
the polygon's actual cross-section, by the same vertical-slab sweep
`core::rects::decompose_into` uses and for the same reason. `decompose_into`
itself is not reachable from here: it takes a `ValidatedLayer` and emits
rectangles for a whole layer, where this needs a width profile for one polygon
across an arbitrary cross-layer subset. No signature moved, and a rectangle
profiles to exactly what it profiled to before.

**Not a defect, spent instead: the Jacobi preconditioner.** `solve_into` now
preconditions with an incomplete Cholesky factorisation at zero fill rather than
with the diagonal. The comment that stood there argued the upgrade was a trade —
a direct sparse Cholesky buys iterations with unbounded fill-in — and that is
true of a *complete* factorisation and not of an incomplete one: IC(0) keeps the
matrix's own sparsity pattern exactly, so memory stays a function of the edge
count. Existence is guaranteed rather than hoped for, because the eliminated
Laplacian is a symmetric positive-definite M-matrix. A non-positive pivot can
therefore only be rounding, and `factorise_into` throws the whole factor away
when it sees one, which drops the solve back to the diagonal it used to use.
`SolveScratch`'s fields are private and its doc comment already said which
buffers exist is an implementation question, so nothing in the interface moved.

---

## export/netlist.rs, third `ponytail:` spend-down pass

**STANDS, third confirmation — `PortTable` publishes no column and no iterator,
so `.subckt`'s pin list is a binary search per net.** Re-verified against
`crates/topology/src/port.rs:29-42`: the fields `net`, `name`, `by_name` and
`by_name_net` are all private, and the whole public surface is `name_of(NetId)`,
`net_of(StrId)`, `len`, `is_empty` and `build`. `build` constructs, it does not
read back. There is no fourth route; two previous passes and this one have each
looked for one.

**This is the same defect as `crates/lvs/src/graph.rs:239`, not a second one.**
Filed separately only because two crates hit it. The two entries are now aligned
on all three claims, and the comments at both sites say the same thing in the
same order:

- the ceiling is `O(nets · log ports)`;
- only the `log ports` factor is debt — the `O(nets)` factor is owed regardless,
  because both loops have a per-net obligation (`net_name`'s row in `lvs`, the
  emit-or-not decision in `export`) and "optimising" it away would drop work
  rather than search;
- the resolution is `fn entries(&self) -> (&[NetId], &[StrId])` on `PortTable`,
  or the two columns made `pub`, and nothing weaker. Every accessor that exists
  answers membership at a *point*; none answers rank ("how many ports below this
  net"), so there is no galloping and no way to narrow the next search's range
  with the last one's result, even though both call sites issue their queries in
  ascending net order against an ascending column. The upgrade is a linear merge
  of the port column against `0 .. net_count`, which needs the column.

The same accessor also closes `## lvs::checks` (three sites) and
`## erc/facts.rs`. **Superseded on the count**: this paragraph said five call
sites and omitted `lvs/graph.rs:276` itself. It is **six**, across `lvs`,
`export` and `erc`, and `## PortTable has no enumerable surface, third pass`
lower in this file is the consolidated record — read the table there, not this
count. One missing accessor; whoever unfreezes it should expect to spend all six
in one commit. The `port.rs:29-42` line references above also predate `net_of`
becoming a `partition_point`; the consolidated entry corrects them.

**Nothing else in `netlist.rs` moved.** No correctness gap found on this pass:
the port-bound-outside-`0..net_count` fail-open that the previous pass found and
closed is still closed (`pins != ports.len()` returns
`WriteError::Unrepresentable`), and `net_name`'s fallback is still injective over
`NetId` — `FALLBACK_PAD` is not a digit, so `n7`, `n7_` and `n71` remain three
names however many rounds a hostile label set forces. The only edit is the
comment at `crates/export/src/netlist.rs:136`, which previously pointed a reader
at `## topology` in this document where the filings actually live under
`## export`, and which now carries the `log ports`-is-the-debt distinction the
`lvs` comment already carried.

---

## engine/run.rs, third `ponytail:` spend-down pass — the sign-off temperature

**Still open, still blocked, and now stated in both directions.** The two
entries above (`engine::run, from the ponytail: spend-down pass`, and the
re-examination in the `pex` pass) are correct and the resolution is unchanged.
This entry records only what the third pass adds: the cost when the process runs
*colder*, the reason the last in-body route is closed, and the agreement with
the sibling marker in `erc`.

**The field.** `sign_off_temperature: Qty<Temperature, { prefix::BASE }>` on
`engine::RunOptions` (`crates/engine/src/run.rs:40`). Absolute temperature,
kelvin, base prefix — the same type and unit
`erc::RunInputs::operating_temperature` (`crates/erc/src/ruleset.rs:167`)
already requires, and constructed through `gpurify_units::celsius` so a Celsius
number cannot reach `1 / T`. `cli::args` fills it. `RunOptions` and not
`engine::Inputs`: `Inputs` is the design (layout, deck, grid, reference,
intent), and the corner is a property of the run, not of the artefact.

**Who reads it.** `RunInputs::operating_temperature` validates it positive and
finite (`ruleset.rs:989`) and hands it to exactly two rules:
`check_electromigration` (`crates/erc/src/rules/electrical.rs:806`, via
`ruleset.rs:1100`) and the reliability check
(`crates/erc/src/rules/reliability.rs:191`, via `ruleset.rs:1111`). Both derate
through `arrhenius_derating` (`electrical.rs:738`), which holds
`MTTF = A J^-n exp(Ea / kT)` equal across the two temperatures. Every other ERC
rule is temperature-independent.

**What the constant costs, both ways.** The derating is monotone in the applied
temperature: hotter derates the allowed current *down*. So

- **hotter than 85 °C** — a 125 °C part derates *less* here than its corner
  requires. The limit reads more generous than it is, and a marginal net passes
  a check it would fail. Fail-open, silent, and the reason this is a defect.
- **colder than 85 °C** — a 55 °C part derates *more* than its corner requires
  and fails nets the corner permits. Fail-closed, loud, and a human argues with
  it rather than shipping past it.

Only the first direction is dangerous, but both are wrong answers that look like
right ones, which is why the field is wanted rather than a better constant.

**The last in-body route is closed.** Prior passes rejected reading a rule row's
`reference_temperature` (`ruleset.rs:576`, `:702`) as the applied corner,
because that collapses the Arrhenius factor to unity. The variant not yet
rejected was `max(85 °C, max_row_reference_temperature)`, which is never looser
than today and so looked like a free fail-closed move. It is not: for
electromigration the characterisation point is an *accelerated* oven, routinely
hundreds of degrees above any use condition. Taking its maximum as the applied
corner would derate every limit against a temperature the part never sees, and
turn the whole EM ruleset into false failures. `reference_temperature` is not a
proxy for the applied corner in any direction. There is nothing left to try from
inside a body.

**Agreement with the sibling marker.** The `ponytail:` comment on
`check_electromigration` (`crates/erc/src/rules/electrical.rs:783`) is this same
scalar seen from the other end: it records that one temperature covers every
edge, where a self-heated wire runs hotter than the applied point, and asks for
a per-edge `edge_temperature` column on `PowerGrid` (filed above under the
`erc/power.rs` passes). The two are independent and compose in the same
direction — one puts the applied point below the part's corner, the other puts
every edge at the applied point rather than at its own junction temperature, and
both under-state the temperature of a hot wire in a hot part. Closing either
leaves the other open. `RunOptions::sign_off_temperature` is the outer of the
two and the cheaper one: it is a scalar a caller already knows, where the
per-edge column needs a thermal model that does not exist yet.

## pex quasistatic/solve.rs, revisited — the `Workspace { r, d }` want is withdrawn

Supersedes the "Wanted" paragraph of *pex quasistatic/solve.rs, from the
`ponytail:` spend-down pass* above. `refine` is no longer a `ponytail:` site;
its comment now states a structural fact and carries no upgrade path.

**Withdrawn: `Workspace { r: Vec<f64>, d: Vec<f64> }` and an inner tolerance.**
The earlier entry accepted the comment's stated ceiling — that the correction
equation cannot be solved to a looser tolerance than the outer one — and priced
the outer loop that would lift it. That ceiling is not real, for two reasons,
neither of which is a body:

1. **A looser inner tolerance is `options.restart`.** When the inner solve is a
   Krylov method, "solve the correction equation more loosely" means "take
   fewer Arnoldi steps", which is exactly what `restart` bounds, and the cycle
   already exits early at `estimate <= options.tolerance`. A separate inner
   tolerance is a second knob for one thing. It earns its keep in classic
   iterative refinement because there the inner solve is a *factorisation*
   whose accuracy is fixed by the precision it was computed in and cannot be
   dialled by iterating. There is no factorisation here.
2. **The outer loop cannot improve the residual.** Refinement differs from
   restarting only when the residual is formed more accurately than the
   correction. `refine` has one `operator`, and `residual()` calls it, so the
   residual inherits the operator's precision. Under a `GpuF32` adapter, an
   outer loop recomputes an `f32`-accurate residual and hands it to an
   `f32`-accurate correction solve; the ~1e-7 floor survives any number of
   outer steps. Wilkinson's extended-precision residual is unreachable for the
   same reason — `MatVec::apply` fills `&mut [f64]` and there is no way to ask
   it for more.

So two `n`-length `Workspace` fields would be allocated per matrix to feed a
loop that computes the same numbers the restart loop already computes. Not
wanted.

**Still open, unchanged: the seam carries one operator, not two.**
`refine<M: MatVec>(operator: &M, ..)` passes the same `M` to the residual and to
the correction solve. Genuine mixed-precision refinement needs two:
`refine<A: MatVec, F: MatVec>(accurate: &A, fast: &F, ..)`, with `residual()`
taking `accurate` and the Arnoldi step taking `fast`. That is the *whole* of the
mixed-precision story that is blocked, and it is one signature. `Workspace`,
`Options`, `gmres`, `residual` and `Converged` do not move.

Consequence, restated because it is the reason the block is tolerable: with one
operator the behaviour is fail-**closed**. A `GpuF32` adapter stalls above the
default `tolerance: 1e-10` and the caller gets `SolveError::NotConverged`, not a
silently `f32`-accurate capacitance. What a caller does *not* get is a true
`f64` residual — `Converged.residual` and `Accuracy::residual` are measured with
whichever operator ran, so under `GpuF32` at a loose tolerance they describe a
perturbed system. Unreachable today: `Device::find` yields `Ok(None)`,
`GpuMatVec::upload` always refuses, and no `f32` `MatVec` exists.

**`refine`'s doc comment is wrong and is frozen.** It says "the residual is
formed in `f64` on the host from the exact right-hand side" and that iterating
"recovers `f64` accuracy at close to `f32` speed". Only the subtraction inside
`residual()` is independent of the operator; `A x` is not. The comment describes
the two-operator seam above, not the one that exists. Correcting it is a doc
comment change, which this phase does not make — filed here instead.

---

## `PortTable` has no enumerable surface, third pass

Consolidates four earlier entries that are the same defect seen from four
crates: `## export`, `## lvs::checks, from the ponytail: spend-down pass`,
`## lvs::graph, from the ponytail: spend-down pass`, `## lvs::graph, second
ponytail: spend-down pass`, and the joint half of `## erc/facts.rs, from the
ponytail: spend-down pass`. Nothing below reverses any of them. This pass
re-verified the blocker against the current `crates/topology/src/port.rs`,
counted the sites, and corrected two stale claims.

**The defect.** `PortTable` (`crates/topology/src/port.rs:29-41`) holds four
private columns — `net`/`name` in ascending `NetId`, and `by_name`/`by_name_net`
the same rows re-sorted by name. Its whole read surface is `name_of(NetId)`,
`net_of(StrId)`, `len` and `is_empty` (`:84-108`); the only other `pub` item is
`build`, a constructor. Every one of those answers about a point. None of them
yields a row, a column, or an iterator, so **a table of hundreds of rows can only
be enumerated by asking millions of nets whether they are in it.**

**Resolution, unchanged from the earlier entries:**

```rust
impl PortTable {
    /// The bindings, ascending by `NetId`.
    pub fn entries(&self) -> (&[NetId], &[StrId]);
}
```

or `net` and `name` made `pub` the way `DeviceTable`'s forward columns already
are. `by_name`/`by_name_net` stay private — they are a derived permutation and
nothing outside wants them. This is a widening of a frozen signature in
`topology` and is therefore filed, not taken.

**The six sites, `O(nets · log ports)` each:**

| Site | What it is enumerating |
|---|---|
| `crates/lvs/src/graph.rs:276` (`from_layout_into`) | `net_name` and `port_net`, the whole projection |
| `crates/lvs/src/checks.rs:162` (`check_floating_nets`) | one term of the per-net predicate |
| `crates/lvs/src/checks.rs:257` (`check_label_conflicts`) | the name-ordered gather |
| `crates/lvs/src/checks.rs:340` (`check_net_seed_conflicts`) | a count of named nets |
| `crates/export/src/netlist.rs:156` (`write_spice`) | the `.subckt` pin list |
| `crates/erc/src/facts.rs:436` (`resolve_intent_into`) | the layout side of the intent join |

`crates/export/src/netlist.rs:377` and `crates/export/src/parasitic.rs:195` also
call `name_of`, and are **not** sites: both resolve one known net, which is what
a point query is for.

`lvs::graph.rs:276` is the hottest of the six — it is the projection, so it runs
once per cell of every comparison — and it is the one whose upgrade is most
mechanical: `net_name` and `port_net` fall out of a single linear merge of the
port column against `0 .. net_count`, no search at all. The `O(nets)` factor
there is owed and must not be "optimised" away; the column being filled is one
row per net. Only `log ports` is debt.

**Correction — `net_of` is no longer a linear scan.** The `## export` entry ends
"`PortTable::net_of`'s own linear-scan `ponytail:` (`port.rs:55-59`) wants the
same widening from the other direction." That is stale: `net_of` is now a
`partition_point` over the `by_name` index (`port.rs:93-100`) and carries no
`ponytail:`. The name-to-net direction is fixed; only the enumeration is open.
Every `port.rs` line reference in the four earlier entries (`:37-78`, `:29-42`,
`:55-59`) predates that change and should be read against the table above.

**Correction — the earlier entries undercount.** `## lvs::graph` says "three
further sites" and scopes the defect to `lvs`. It is six, across `lvs`, `export`
and `erc`. One accessor closes all six.

**Not reducible from inside any of the six bodies.** Re-confirmed, so nobody
spends another afternoon on it:

- No rank oracle. `name_of` answers membership at a point and never "how many
  ports below this net", so there is nothing to gallop on and no way to narrow
  the next search's range with what the last one returned — even though the
  queries arrive in ascending net order against an ascending column.
- Membership is not monotone in `NetId`, so there is nothing to bisect on
  either.
- The `StrTable` route is wrong, not merely unavailable: walking the dense
  interned ids and asking `net_of` about each is `O(S log P)`, but `net_of`
  answers with the *lower* net when one label reaches two, and `bind_ports_into`
  refuses only the converse (one net, two labels — `PortError::ConflictingLabels`),
  so two nets sharing a label is a representable table whose second net that
  route never sees. It drops a port. `lvs::graph::from_layout_into` is handed no
  `StrTable` at all, so the route is not even reachable there.
- `Cols` is built from slices, so a term arriving through a method call cannot be
  handed to a combinator, and `name_of`'s panic edge cannot ride a callback.
  That is why all six are raw loops.

**Latent, filed rather than fixed: a port bound outside `0 .. net_count` is
dropped by `from_layout_into`, and the signature cannot say so.** The same hole
`export/netlist.rs` closed by counting emitted pins and returning
`WriteError::Unrepresentable`. Here the scan visits only the nets the extraction
has, so a binding whose `NetId` is `NetId::NONE` or belongs to a different
extraction never answers, and `port_net` comes back silently short.
`from_layout_into` returns `()`, so the only evidence available is the exit
`debug_assert_eq!(named, ports.len())` already at `graph.rs:284` — a debug panic,
not a refusal. Unreachable through `bind_ports_into`, which cannot mint such a
row; reachable through the `PortTable::build` constructor reopened for the
Testing-Phase. Inert today because `Graph::port_net` has no consumer (see
`## lvs::graph, second ponytail: spend-down pass`). It stops being inert the
moment `refine` takes the initial colouring that entry asks for, at which point a
dropped port is an unanchored net. Resolution is `-> Result<(), _>` on
`from_layout_into`, or `entries()` above, which removes the scan and with it the
whole failure mode.

## erc/rules/electrical.rs, from the `ponytail:` spend-down pass — the size of the temperature gap

Still blocked, and blocked twice over: `PowerGrid` has no temperature column and
`RunOptions` has no sign-off corner. Both entries above stand. Nothing was
widened. What this pass adds is the *magnitude*, because three previous passes
recorded the direction (fail-open) without recording how far, and the exponent
makes it much larger than "one temperature for the whole run" suggests.

**The arithmetic.** `arrhenius_derating`
(`crates/erc/src/rules/electrical.rs:738`) returns
`exp(Ea / (n·k) · (1/T − 1/T_ref))` and multiplies the allowed current by it.
Computing at `T_applied` when the conductor sits at `T_actual` therefore
over-states the allowed current by exactly
`exp(Ea / (n·k) · (1/T_applied − 1/T_actual))`. Off an 85 °C applied point, at
`Ea = 0.9 eV` (copper):

| `T_actual − T_applied` | `n = 1` | `n = 2` |
|---|---|---|
| +5 K — the self-heat budget a foundry rule typically states | 1.5× | 1.2× |
| +10 K | 2.2× | 1.5× |
| +40 K — 85 °C applied against a 125 °C junction | 19× | 4.3× |

At `Ea = 0.7 eV` the same three rows read 1.4×/1.9×/9.8× at `n = 1`. A 5 K
self-heat is not a rounding error on this rule; it is a 50 % over-statement of
the current an interconnect may carry.

**Which rules are sensitive, and by how much.** Four are, and they are not
sensitive to the same degree — a reader who lumps them together will spend
effort in the wrong place:

- `check_electromigration` — the table above. Steepest thing in the crate.
- `check_reliability` (`crates/erc/src/rules/reliability.rs:191`) — the same
  Arrhenius factor with no `1/n`, applied to a predicted lifetime rather than to
  a current. 19× at `Ea = 0.9 eV` over 40 K, 7.1× at `Ea = 0.6 eV`. Equal worst
  case, and it reaches it at every activation energy a `n = 2` EM row would have
  damped.
- `check_ir_drop` and `check_p2p_resistance` — sensitive through
  `PowerGrid::edge_resistance`, which `power::extract_into` computes as sheet
  resistance times squares with no TCR term (`crates/erc/src/power.rs:1780`).
  Copper is ~12 % more resistive at 125 °C than at 85 °C, so both read fail-open
  by ~1.12×. Real, bounded, two orders of magnitude smaller than the EM gap.
  Fixing it needs a TCR column on the process stack, which is an `ingest`
  signature, not an `erc` one — filed here only so the next reader does not
  re-derive that it is the small one.
- `check_em_current_density` takes no temperature and is *not* wrong by any of
  these factors. It derates by nothing, so it inherits whatever corner the deck
  characterised `max_density` at and has no way to state which. That is a
  documentation gap in the deck schema, not a fail-open in this rule.

**The two halves compose, and the product is what a part sees.** The 85 °C in
`run::sign_off_temperature` puts the applied point below the part's corner; the
missing `PowerGrid` column puts every edge at the applied point rather than at
its own junction. A 125 °C part with a 5 K self-heat gets both: ~28× at
`Ea = 0.9 eV`, `n = 1`. Closing either alone still leaves a rule that passes
branches a signoff would fail. The two markers —
`crates/erc/src/rules/electrical.rs:783` and
`crates/engine/src/run.rs:170` — now say this the same way and cross-reference
each other, which they did not before this pass.

**Cheapest rung, unchanged from the previous pass and still not taken.** A
`thermal_resistance` (K/W) column on `ElectromigrationTable` parallel to
`max_density`, with the per-edge point `operating_temperature + I²R·θ` built
from `solution.branch_current` and `power.edge_resistance` — both already read
in `check_branches`. That closes the self-heating half using data in hand and
needs no thermal model; it is one CSR column on a table in this file plus one
deck field, and it is frozen. The `RunOptions::sign_off_temperature` field
closes the other half and is a scalar the caller already knows.

## pex quasistatic/gpu.rs, re-examined in the second `ponytail:` spend-down pass

Re-opened to execute the upgrade path. **Still blocked, for the reason the
entry above gives — no step of it can be taken from inside the file — and this
pass adds three facts that entry did not have.** Line reference unchanged:
`crates/pex/src/quasistatic/gpu.rs:67`, inside `Device::find` at `:66`. No
device exists on this machine, so everything specified below is untested by
construction and is written as a specification for the body, not as code.

**The comment's contract accounting was wrong about item 4, and is corrected in
place.** It claimed items 4 and 5 were "already met, and met on the *host*, so a
device does not gate them", citing `solve::refine` as bounding the answer with
an `f64` residual. Item 5 is met. Item 4 is met for the host adapter only. The
`A x` inside `solve::residual` (`crates/pex/src/quasistatic/solve.rs:422`) goes
through the *same* operator as the inner solve, so under a `GpuF32` adapter the
reported `Accuracy::residual` is a residual against the `f32` operator, not
against the `f64` one — the same finding already filed under "pex
quasistatic/solve.rs", reached here from the other end. It is fail-closed (the
achieved residual stalls above the default `1e-10` and the caller gets
`SolveError::NotConverged`, not a quietly `f32`-accurate capacitance) and it is
latent (`Device::find` yields no device, so `GpuMatVec` is never constructed).
But `docs/GPU.md` item 4 says the residual is computed "on the **host** in
`f64`", and one `MatVec` parameter cannot deliver that. A comment in `gpu.rs`
asserting the item was met would have let a future device port ship believing
its own accuracy bound.

**Two `DeviceError` variants have no reachable return site, and neither is an
omission — both are frozen-signature facts.**

- `OutOfMemory { needed, available }` cannot come from `find`. `find` takes no
  arguments, so it does not know the panel count and cannot size a heap against
  a solve. Only `upload` has the mesh. This is the right shape and is recorded
  only so a future body does not try to invent a size in `find`.
- `Lost` ("device lost during a solve") has no reachable return site anywhere.
  `MatVec::apply` is `fn apply(&self, x: &[f64], y: &mut [f64])` — it returns
  `()`. An adapter whose device is lost mid-matvec can only panic, or write a
  partial `y` and let GMRES measure it. The second is fail-closed by luck
  rather than by design: a garbage `y` makes the residual stall and the solve
  refuses with `NotConverged`, so the wrong number is never reported, but the
  *reason* is lost and the user sees a convergence failure for a hardware
  fault. Wanted, if a device path ever lands: `MatVec::apply` returning
  `Result<(), DeviceError>`, or a `fn health(&self) -> Result<(), DeviceError>`
  the solve checks once per restart cycle. `MatVec` is implemented by
  `CpuMatVec` and `GpuMatVec` and is generic-bounded in `solve::gmres`,
  `solve::residual`, `solve::refine` and `quasistatic::columns_into`, so the
  first form moves five signatures and the second moves one. Until then the
  enum promises a report the interface cannot deliver, and a body writing
  `Err(DeviceError::Lost)` will not compile at the only place it would arise.

**What an honest probe does when Vulkan is present, specified so the body is a
transcription.** The frozen return type `Result<Option<Self>, DeviceError>`
already separates the two answers a user must be able to tell apart, and the
split is:

- no loader, or an instance enumerating zero physical devices → `Ok(None)`,
  "no GPU here";
- a physical device that exists and is then *rejected* → `Err`, naming the
  requirement it missed: "a GPU is here, and this is why it did not run".

Per device, check a queue family with `QueueFlags::COMPUTE` (`TRANSFER` is
implied by it; `GRAPHICS` is not needed), then the two limits the P2P Laplace
kernel reads — `max_compute_work_group_invocations` and
`max_compute_work_group_size[0]` against the workgroup size the shader was
compiled for, and `max_storage_buffer_range` against the five `f32` panel
columns plus the two vectors. `shader_float64` is deliberately *not* required:
an `f32` matvec inside host `f64` refinement is the design, and demanding `f64`
on the device would reject the `docs/GPU.md` development target (an Ada
consumer part, `f64` at 1/64 rate) for a feature this path does not use.
Rejections carry `MissingFeature` with the limit named and both numbers.

**The reason is stated at the seam and then discarded one caller up.** This is
the part of "fall back with a stated reason rather than a silent one" that
`gpu.rs` cannot close. `quasistatic::extract_into`
(`crates/pex/src/quasistatic.rs:237`) reads `gpu::Device::find().ok().flatten()`,
which collapses every `Err` into the same `None` as "no device"; its own comment
says why, and the reason is frozen — `extract_into` returns
`Result<Accuracy, solve::SolveError>` and `SolveError` has no device variant, and
a solve that ran correctly on the host is not a failure to report. `Accuracy`
has no field for it either. So a fully-implemented probe would distinguish "no
GPU here" from "GPU present and rejected, because X" and a user reading a run's
output still could not: both arrive as `Accuracy::backend == Backend::Cpu`.

Wanted: a field on `Accuracy` — `fallback: Option<DeviceError>`, or the flatter
`device: DeviceStatus` enum — filled by `extract_into` from the `Err` it
currently drops. `Device::find`, `DeviceError`, `MatVec`, `select` and
`SolveError` do not move; only `Accuracy` and the one `.ok().flatten()` do.
Cost of not having it: contract item 6 says selection is automatic and never a
flag, which is right, but it makes the *absence* of GPU acceleration
unattributable — a user on a machine with a working card that this probe
rejected for a missing limit gets exactly the output of a user with no card at
all, and the only way to tell them apart is to read this file.

---

## drc, from the `ponytail:` spend-down pass (second entry)

**`RuleSet::run` has nowhere to receive a worker count, so DRC cannot be
parallelised without making `RunOptions::threads` a lie.** New, filed against
the `ponytail:` marker on `Scratch` (`crates/drc/src/lib.rs`), which is the
last un-actioned shortcut `docs/NEED_TESTING.md` names as unblocked. It is not
unblocked; the earlier comment reasoned about the exclusive borrow and stopped
there.

**What the upgrade needs.** Rules are twenty-four independent tables over shared
read-only inputs. Concurrency wants three things, and two of them are free:

- *Per-worker scratch.* `Scratch` grows a private `Vec<Scratch>` of slots, each
  slot a full `Scratch` whose own slot vector is empty, so the thirty-eight
  `scratch.<field>` reads across `rules/*.rs` are untouched. Private, licensed
  by the type's own doc ("which buffers exist is an implementation question"),
  and `shrink` releases the slots with everything else.
- *Merge order.* `Violations` needs none: `Violations::sort_canonical`'s
  `row_key` covers all nine columns, not the six the summary names, so equal
  keys mean rows equal in every column and the sorted table is a function of the
  multiset. `runs: Vec<RuleRun>` needs table order — nothing inside
  `RuleSet::run` sorts it and its doc promises dispatch order — which is a
  twenty-four-slot concatenation in field order, not coordination.
- *A worker count.* This is the blocker.

**Which signature blocks it.** Two, on the same route:

- `gpurify_drc::RuleSet::run(&self, Design<'_>, &mut Scratch, &mut Violations,
  &mut Vec<RuleRun>)` carries no thread budget.
- `gpurify_engine::run::run_drc(&Loaded, &Extracted, &mut Outputs)`
  (`crates/engine/src/run.rs:531`) does not receive `&RunOptions`, so even a
  `Scratch` constructor taking a worker count could not be called with the
  user's value — and `Scratch`'s only public surface today is `Default` and
  `shrink`, so adding one is itself a widening.

`RunOptions::threads` is public, CLI-exposed (`--threads`), and documented as
"affects speed only: byte-identical output at any value of it".
`crates/cli/src/main.rs` flips it between the two `--check-determinism` passes
specifically to prove output does not depend on how work was divided.
`crates/engine/src/run.rs:368` states the current position honestly — the field
"is read here and nowhere else because nothing below this line is parallel" —
which is a design intending the route to exist once something is.

**Why not just call `available_parallelism`.** It fails open on the gate.
`--check-determinism` would run both passes at the machine's real worker count
regardless of the flipped `threads` value, so the flag would compare a run
against itself and report a determinism guarantee it never exercised — the
false-clean shape this project is built against, one level up. It also breaks
the knob for the case it exists for: a signoff run pinned to its scheduler's
slot allocation would oversubscribe the host.

**What the change would be.** Either

- a `threads: usize` (or `Option<NonZeroUsize>`) parameter on `RuleSet::run`,
  plus `options: &RunOptions` on `run_drc` to feed it — the smaller diff, and it
  puts the budget in the signature where the caller can see it; or
- the budget on `Scratch` at construction (`Scratch::with_workers(n)`), which
  keeps `run`'s parameter list frozen but still needs `run_drc` widened to
  reach `options`, and hides a performance-relevant decision in a buffer set.

The first is preferred: `RuleSet::run`'s doc already discusses "any future
decision to run the tables in parallel", so the budget belongs beside the data
it divides. `gpurify_erc::RuleSet::run` is the same shape and would take the
same parameter; `gpurify-drc` also does not depend on `rayon`, though
`std::thread::scope` needs no dependency at all.

Until then the marker stays on `Scratch` and DRC runs on one core.

## pex quasistatic, `mesh::Panel` extents — second pass

Follow-up to "**`mesh::Panel` keeps a panel's area and drops its two edge
lengths**" above. The wanted signature is unchanged — `Panel { extent: [f64; 2] }`
filled by `mesh_box` from `du`/`dv` — and the closed form and the four error
figures in that entry were re-derived independently and stand. Three things it
does not say, all of which change how the open defect should be read.

**The error has a sign, and the sign is optimistic.** `Collocation::radius` is
ρ, and the diagonal of `P` is `k_i / ρ_i`. A ρ low by 3.5 / 12.5 / 28 / 64 % at
2:1 / 4:1 / 10:1 / 100:1 is a self-potential high by 3.6 / 14 / 39 / 180 %, and
a `P` with an inflated diagonal inverts to a `C` that is too small. So the
square factor never over-states a capacitance; it under-states one, on exactly
the panels it is worst on. For a signoff flow that is the wrong direction —
under-reported coupling is optimistic timing and optimistic crosstalk — and it
is why this entry is worth more than its 12.5 % headline suggests.

**The aspect ratios are set by `mesh_box`, and the bad ones are bounded away
from the good ones.** `du = wu / ceil(wu / edge)`, so `wu >= edge` puts `du` in
`(edge/2, edge]`. A face both of whose dimensions reach `max_edge` is therefore
cut below 2:1 in every case, and costs at most 3.5 %. Every figure above 3.5 %
comes from a face dimension *below* the edge limit, which `cuts` passes through
uncut at `n.max(1)`. Two such faces are ordinary rather than pathological:

- a layer's side face is (footprint × thickness) — a 50 nm layer under a 0.5 µm
  edge limit is 5:1 to 10:1, i.e. 19–39 % on the diagonal, and side faces are
  the ones carrying lateral coupling between neighbouring wires;
- a wire narrower than the edge limit is a sliver on its *top* face as well, so
  a 100 nm wire under the same limit is meshed as slivers on every face it has,
  not just its sides.

So the defect is not a tail case that a finer `max_edge` removes. Refining
`max_edge` shrinks the good panels and leaves the thickness-limited ones at
their aspect, which makes the sliver *fraction* of the mesh go up.

**The extents cannot be reconstructed inside `matvec`, so no body closes this.**
The one route that looked open is inference from the column: panels of one face
share `normal` and a plane coordinate and sit on a regular grid, so centroid
spacing gives an edge back. It gives an edge back only along an axis the face
was cut more than once on — and a face cut more than once on an axis has that
edge in `(edge/2, edge]` by the bound above, which is precisely the case that
was never in error. A 1×1 face, the worst case, has no neighbour to measure
against. Inference recovers exactly the information that is not needed.

Only the field addition closes it. Left as filed; the `ponytail:` comment at
`crates/pex/src/quasistatic/matvec.rs` now carries the sign, the bound and the
non-recoverability.

---

## pex quasistatic/matvec.rs, third `ponytail:` spend-down pass

One entry, `crates/pex/src/quasistatic/matvec.rs` (`CpuMatVec`, the
direct-O(n²) `ponytail:`). Re-examined against the frozen signatures for the
third time. Still blocked, and the earlier filings were wrong about *which*
signatures block it — one blocker they named is not one, and the resolution the
second pass recommended is itself blocked by a signature neither pass looked at.
The code is unchanged; the `ponytail:` comment has been rewritten to carry the
corrected list.

**The resolution the second pass recommended — "the FMM is a third adapter
behind `MatVec`, not a replacement of `CpuMatVec`'s body" — is blocked by
`Backend` and `select`.** That framing is right, and it was filed as though it
needed no signature change. It needs two.

`Backend` is `pub enum Backend { Cpu, GpuF32 }`, no `#[non_exhaustive]`, and
`quasistatic::extract_into` matches the result of `select` exhaustively over
both arms (`crates/pex/src/quasistatic.rs:238`). A third adapter has nothing to
return from `MatVec::backend`, which is a required method of the frozen trait,
and nothing to put in `Accuracy::backend`, whose doc comment states its whole
purpose is that "a run's numbers can be attributed". Returning `Backend::Cpu`
from an FMM adapter is that attribution lying — the same defect class as
`GpuMatVec::backend`'s comment refuses ("an adapter that misnames itself makes
every attribution downstream a lie"), and it would leave
`tests/quasistatic.rs::the_host_adapter_reports_the_host` and
`a_field_solve_obeys_reciprocity_and_reports_the_backend_that_ran_it` green
while the host ran an approximate operator.

`select(panels: usize, device: Option<&gpu::Device>) -> Backend` is the entire
dispatch decision, deliberately — its doc comment refuses to make the choice a
user flag. An FMM crossover is a property of neither of its two parameters: it
is a function of the panel count *and* the requested far-field accuracy, and
there is nowhere to put the second.

Wanted, in addition to the two already filed (`build` taking an expansion order
or target error, `Accuracy` gaining a far-field truncation field): a `Backend`
variant for the adapter, and a `select` that can reach it. Four frozen
signatures in total. `MatVec`, `apply` and `ObserveMatVec` still do not move —
the seam is right, and `near_blocks`/`far_expansions` were designed for exactly
this adapter.

**Withdrawn: the byte-gated left fold is not a blocker.** The second pass filed
it as "a second, independent half" of the FMM blocker that "no accuracy
parameter would resolve" — an FMM sums a near block and then a tree-order
multipole contribution, which is a different association of the same terms and
therefore a different `f64`. The association claim is correct. The conclusion
drawn from it is not, and it matters, because as filed it says the upgrade is
impossible in principle rather than blocked on four signatures.

Every determinism gate in the workspace compares *two runs of one input*:
`a_field_solve_is_byte_identical_across_runs`,
`meshing_is_byte_identical_across_runs_and_across_a_reused_buffer`,
`solving_the_same_system_twice_gives_bit_identical_answers`,
`reduction_is_byte_identical_across_runs_and_across_a_reused_buffer`. None
compares against a stored value, and none compares two operators. A tree whose
traversal order is a deterministic function of the geometry — which is what
`extract_into`'s own doc comment already promises of the mesh — satisfies all of
them exactly as the ascending-`j` fold does. `network::net_capacitance`'s
bit-identical claim is likewise "across runs" and is downstream of the solve,
not of the fold. What the fold is interface against is *nondeterministic*
reassociation — rayon, fast-math, an atomic device accumulation, the same three
`gpu.rs` names when it says the device kernel needs "a *fixed* reduction order —
a tree reduction qualifies, an atomic accumulation does not". A fixed tree is in
the qualifying category.

The genuine numerical blocker is the one the *first* pass named and is narrower
than "the fold": `CpuMatVec` is the exact `f64` reference the `f32` device path
is differentially tested against (`gpu.rs` header, contract item 5), so it
specifically cannot become approximate — an approximate reference stops that
comparison isolating the device's error, which is the only thing it measures.
That is an argument about this one adapter's role, not about the seam, and it is
why the third-adapter framing is the right resolution and why the `Backend`
blocker above is what actually stops it.

**Also withdrawn as a consequence: the upper-triangle halving.** The second pass
ruled it out as "reassociation by another name", on the same reasoning. The
reasoning is withdrawn, but the conclusion stands for a different and smaller
reason: scattering each pair into both `y[i]` and `y[j]` is still deterministic,
but it halves the kernel evaluations only by making the *reference* adapter's
bits differ from the operator every other test in the crate reasons about, for a
constant factor of two and no change in asymptotics. Not worth the churn on the
one adapter whose bit pattern is load-bearing. Recorded so the next pass does not
re-derive it from the withdrawn argument and reach the wrong conclusion for the
wrong reason.

Cost of not having the four signatures: unchanged, ~1e4 panels before the
quadratic term dominates a 400-iteration GMRES, and no test in `crates/pex/tests`
meshes more than 144 panels.

**Unrelated, noticed while spending this comment and not fixed here:
`apply_observed` has no observing caller.** Its doc comment says it was added in
the Testing-Phase because `near_blocks`, `far_expansions` and
`bytes_transferred` were otherwise unobservable, and that "adapter tests are
therefore unit tests in this crate". There is no `#[cfg(test)]` module in
`matvec.rs`, and the only caller is `MatVec::apply` passing `NoObserve`. The
three observations are still unobserved; the seam exists and nothing looks
through it. Not a signature defect — the fix is a unit test in that file, which
is outside this pass's boundary.

## pex quasistatic, layered Green's function — from the third `ponytail:` spend-down pass

Supersedes the third entry of "pex quasistatic, from the `ponytail:` spend-down
pass" above, which is stale in two ways: the pair coefficient it describes (the
arithmetic mean `½(k_i + k_j)`) was replaced by the harmonic mean in a later
pass, and the question it left open — "worth deciding at the same time, and not
decided here" — was decided in favour of the harmonic mean, which is the
two-medium closed form rather than a convenient symmetric function. The blocker
it names is unchanged and the cost of the blocker is now measured.

**`CpuMatVec::build(mesh: &Mesh)` cannot see the dielectric stack, so the
operator has no layered Green's function and is wrong for *same-medium* pairs,
not only for pairs across an interface.** This is the correction that matters:
the `ponytail:` comment claimed the kernel was "exact for two half-spaces and
for a uniform stack" and that it "under-resolves a panel pair separated by more
than one interface". The second clause is true and unimportant; the first is
false in the case that carries every coupling number.

`P_ij = 2 k_i k_j/(k_i + k_j) / √(|Δc|² + ρ_i ρ_j)` is the *transmitted* image
across a planar interface — Jackson §4.4 — and it is exact for a pair
straddling that interface. A pair on the *same* side of it needs the
*reflected* image too, `K/|r − r'*|` with `K = (ε_i − ε_j)/(ε_i + ε_j)` and
`r'*` the source mirrored in the plane. The kernel emits none of it, because
both panels of such a pair carry the same `ε` and the harmonic mean collapses
to `k`. Two coplanar wires in one metal level, the geometry the whole coupling
matrix is made of, therefore get the homogeneous free-space answer with no
layering correction at all.

Measured against the image series (validated at three limits: uniform stack →
ratio 1, `ε → ∞` below → the classic grounded-plane single image, and
separation → ∞ → the surrounding medium's `ε`):

| stack | 30 nm | 50 nm | 100 nm | 200 nm | asymptote |
|---|---|---|---|---|---|
| ILD ε 2.7, 180 nm, SiN ε 7.0 either side, panels at mid-height | +14% | +24% | +54% | +105% | +159% |
| ILD ε 2.4, 120 nm, barrier ε 6.5 either side | +22% | +40% | +87% | +143% | +171% |
| oxide ε 3.9, panels 50 nm above Si ε 11.9 | +17% | +29% | +56% | +83% | +97% |

Columns are lateral panel separation; the figure is how much higher `P_ij` is
here than the layered answer. `C = P⁻¹`, so coupling capacitance is
*under-predicted* by that much, and the error grows with separation rather than
decaying — it is worst on exactly the long-range terms a crosstalk or a
coupled-line delay number is sensitive to. The asymptote is
`ε_surrounding/ε_layer − 1`, reached once separation outruns the slab
thickness.

Nothing in `crates/pex/tests` can see this. The correction vanishes as
separation goes to zero, so the self-potential and diagonal checks are clean;
it is symmetric in `i` and `j`, so every reciprocity and asymmetry gate is
clean; and it is identically zero on a uniform stack, which is what the fixture
decks describe. The suite is not weak here, it is blind by construction — the
oracle is a layered-medium Green's function that does not exist in the tree.

Wanted: `CpuMatVec::build(mesh: &Mesh, stack: &ProcessStack)`, or the interface
planes travelling on `Mesh` the way `epsilon` already does — a `Vec<f64>` of
interface z in ascending order plus a `Vec<f64>` of the permittivity above each,
which `mesh::extrusion_table` already has in hand and discards. `MatVec`,
`apply`, `Backend`, the observer and `select` do not move; the seam is right.
The stack is one argument away at the only call site:
`quasistatic::extract_into` (`crates/pex/src/quasistatic.rs:247`) takes
`stack: &ProcessStack` and calls `matvec::CpuMatVec::build(&mesh)` two hundred
lines later. `gpu::GpuMatVec::upload(device, &mesh)` takes the same `&Mesh` and
would need the same second argument, and its five `f32` panel columns become
seven plus a per-solve interface table.

Not recoverable from `Mesh` as frozen, and worth stating so nobody tries: the
mesh carries centroids, normals, areas and one `ε` per panel. The interface
planes are not derivable from it — a panel's `ε` is the permittivity *above*
its own layer, the layer's z extent is dropped at `mesh_box`, the dielectric
rows for layers holding no selected geometry never produce a panel, and the
substrate produces none ever. Reconstructing a stack by clustering panel
centroids would invent interfaces where the selection happens to have
conductors and miss them everywhere else, which is a worse failure than the
homogeneous kernel because it varies with the net selection.

Cost of not having it: the table above, on every coupling term the field solver
produces. Note the sibling finding **F11** — `analytical::extract_into` emits no
coupling at all — which makes this kernel the only source of coupling
capacitance anywhere in the tree, so there is no second path whose agreement
could bound the error.

## core/bbox.rs, third `ponytail:` spend-down pass

Two things, and only the first is a defect entry. The second is recorded here
because it was found while re-proving the first, and it is already fixed.

**`Bbox::width` / `Bbox::height` — still blocked, and now bounded.** The entries
`## core/bbox.rs, from the ponytail: spend-down pass` and `## core/bbox.rs,
second ponytail: spend-down pass` both stand. This pass re-walked the const
surface of `gpurify-units` and reached the same enumeration: `Dbu::new`,
`new_unchecked`, `raw`, `abs`, `mul_wide`, `DbuArea::new`/`raw`, and three
non-const operator impls. No const constructor admits an out-of-domain `i64`,
so a `const fn -> Dbu` in `gpurify-core` cannot return a `2^41` span. The
resolution is unchanged: `pub const fn Dbu::sub(self, Self) -> Self` in
`crates/units/src/dbu.rs`, unchecked for the reason the existing `Sub` impl
already states, with `width`/`height` calling it. That is `gpurify-units`'
change to make.

What this pass adds is the severity, which neither earlier entry stated. **It is
not a fail-open and not a wrong answer.** `2^41` sits 22 bits inside `i64`, so
the subtraction never wraps and a release build returns the exact width — there
is no "width wraps to a small number and a spacing rule passes" here. The only
failure is the `debug_assert` inside `Dbu::new_unchecked`, which is loud and
fail-closed. The defect is that `Dbu` models a *coordinate* and a width is a
*span*; the frozen signature returns the coordinate type for a quantity whose
range is twice as wide. Widening `in_domain` would spend the `2^80` bound
`MAX_ABS_DBU` exists to buy, and is still the wrong answer.

Caller audit, since the earlier entry listed reachable sites without saying
whether any is exposed: `pex/src/quasistatic.rs:569` clamps `width()`/`height()`
at zero before widening; `erc/src/rules/reliability.rs:722`,
`drc/src/rules/overlay.rs:886`, `erc/src/power.rs:2394,2629` and
`drc/src/rules/width.rs:594` all take `.raw()` or compare two `Dbu`, so none
re-enters a checked constructor. `engine/src/run.rs:600` and
`erc/src/power.rs:1938` both guard on `is_empty()` before measuring. Nothing in
the tree is red today; `crates/core/tests/bbox_laws.rs:82` builds the box that
would fire it and happens not to ask for its width.

**Found and fixed in the same pass: `Bbox::area` returned a sentinel wearing a
real answer** (`crates/core/src/bbox.rs`, `area`). The body was
`(xhi - xlo) as i128 * (yhi - ylo) as i128` with no clamp, so on `Bbox::EMPTY`
the two inverted spans multiplied back to `+2^82` — bit-identical to the area of
a box spanning the whole coordinate domain, and past every `min_area` limit a
deck can express. A box empty on one axis only inverted one span and returned a
*negative* area, which subtracts real coverage from any density that sums these.
Both results are indistinguishable from a measurement, which is what makes it a
correctness gap rather than a rough edge.

The fix is `max(span, 0)` per axis before the product, which is the arithmetic
`rects::clipped_area` already spells out per rectangle and documents by name as
the reason `Bbox::EMPTY` "lands on zero". Two call sites had already hand-rolled
the same guard against this function — `pex/src/quasistatic.rs:569` and
`rects::clipped_area` — which is the tell that it belonged in `Bbox::area`,
once, where every caller routes through. `max` is the file's existing const
branchless helper, so the clamp is two selects and no branch. Signature
unchanged; `debug_assert!(!self.is_empty() || area == 0)` is the new shape
assert, and a point and a segment still measure zero while remaining non-empty.
Suite unchanged at 733 passed / 4 failed, the four being the corpus findings.

## engine/run.rs, `run_pex` — the whole `Accuracy`, not only the matrix

**Fixed first, and it is a correctness gap rather than a signature one:
`run_pex` discarded the [`Accuracy`] the field solve returns, so nothing ever
compared `CapMatrix::asymmetry` against anything.** The call read
`quasistatic::extract_into(..)?;` — the `?` propagates the error and drops the
`Ok`. `extract_into`'s own doc says "a caller that ignores it is asserting the
answer is good without having looked, which is exactly what went wrong before",
and `asymmetry`'s says "an asymmetry above the solver's tolerance means the
answer has not converged, whatever the residual says". There was exactly one
caller and it ignored it.

Reciprocity is not the residual. `solve::refine` converges each column against
its own right-hand side and `columns_into` refuses a column that did not, so a
returned matrix has already passed a per-column residual test; `C[i][j]` and
`C[j][i]` come out of two *different* solves and physics says they are one
number. A mesh that couples two conductors differently in each direction
converges twice and disagrees with itself, and `CapMatrix::asymmetry` is the
only place in the tree that disagreement is measured. The run reported
`StageStatus::Ran` and wrote `Outputs::parasitics` over it — a clean result
indistinguishable from a checked one.

`asymmetry`'s NaN-poison arm made this worse rather than better: it is built to
return NaN for a matrix nothing could check, on the stated reasoning that "NaN
is below no tolerance any caller compares against". No caller compared.

Resolved in-body, no signature moved: `reciprocity_refusal`
(`crates/engine/src/run.rs`) is a pure decision over one `Accuracy`, and
`run_pex` returns `StageStatus::Refused` before the merge, so nothing a failed
solve produced reaches `Outputs::parasitics`. The bound is
`Accuracy::tolerance`, which travels on the value for exactly this comparison.
The test is `a_matrix_that_is_not_reciprocal_is_refused_and_a_non_finite_one_too`.
Note the predicate is `!is_finite() || > tolerance` and not `!(<= tolerance)`:
the negated form is what `clippy::neg_cmp_op_on_partial_ord` names, and the
plain `>` alone would pass an infinite or NaN asymmetry — the fail-open shape.

**Still open, and the reason the `ponytail:` comment stays: `Outputs` has no
field for anything the solve measured about itself.** The entry above records
`CapMatrix`; this widens it to the whole of `Accuracy`. Four fields have nowhere
to land and no in-body substitute:

- `residual` and `iterations` — how hard the answer was to get. A solve at the
  tolerance after 999 iterations and one at 1e-14 after 3 are the same
  `StageStatus::Ran`.
- `backend` — its own doc gives the reason it exists: "so a CI job with no
  device can assert the fallback was taken rather than silently passing". No CI
  job can, because `matvec::Backend` reaches no engine, export or CLI type. A
  run's numbers cannot be attributed after the fact, which is precisely the
  `f32`-GPU failure the type was added to prevent.
- `asymmetry` — now *checked*, but still not *reported*. A run one decade under
  the tolerance and a run three decades under are indistinguishable in the
  artefact.

Resolution is an `Option<Accuracy>` field on `Outputs` beside `parasitics`, plus
a matrix field, both Definition-Phase changes. The gate above is the fail-closed
half and is all a body can reach; the disclosure half needs the signature. And
neither closes what `docs/SIGNATURE_DEFECTS.md` already records twice — a
uniformly coarse mesh is symmetric about its own error, so no reciprocity gate
detects under-meshing, and the mesh-convergence number that would is a second
solve and a field on `Accuracy` that does not exist.

## drc/rules/patterning.rs, third `ponytail:` pass — mostly executed

The `ponytail:` comment at `color_into`'s counting sort is **gone**. Two earlier
passes recorded it as unspendable; that was right about the frozen signature and
wrong about the reach. What was actually blocked is narrower than what was
filed, and the rest has been executed.

**Executed.** `crates/drc/src/rules/patterning.rs` now carries a private
`ColorScratch` holding all fourteen buffers, and a `pub(crate) color_into_with(
scratch, node_count, conflicts, colors, out)`. `check_multi_patterning` hoists
one `ColorScratch` above its rule-row loop, so the production path — the one
that colours every patterned layer of a chip — allocates one set per *run*
instead of one per *row*. The frozen `pub fn color_into(node_count, conflicts,
colors, out)` is untouched and is now a five-line wrapper that builds a
`ColorScratch::default()` for the length of the call; all five call sites in
`crates/drc/tests/patterning_rules.rs` compile and pass unchanged, and no test
was edited. `SatQueue::new` became `SatQueue::reset(&mut self, ..)`, and
`two_color_into` takes its breadth-first `frontier` as a parameter.

Every buffer is `clear()` then `resize()`, never `resize()` alone: `resize` down
truncates and keeps the head of the previous graph's answer, which is the exact
leak a reused scratch invites.
`patterning::tests::a_reused_color_scratch_answers_what_a_fresh_one_does`
differences a reused scratch against a fresh one over five graphs whose node
counts shrink and grow (7, 4, 6, 3, 5) and whose palettes do the same; deleting
one `clear()` fails it. `SatQueue::reset` additionally asserts its bitset
population is exactly `n`, so a bit surviving the previous graph trips at the
site rather than as a wrong verdict downstream.

**The numbers this closes.** A full-reticle metal layer at two million shapes,
three masks and four conflict candidates per shape:

| buffer | size | at n = 2e6, k = 3, E = 4e6 |
|---|---|---|
| `adj_start`, `cursor` | `(n + 1)` u32 each | 8 MB each |
| `adj` | `2E` u32 | 32 MB |
| `adjacent` | `n × k` u32 | 24 MB |
| `sat`, `pick`, `by_rank`, `rank` | `n` u32 each | 8 MB each |
| `next`, `used` | `n` / `(n + 1)` u8 | 2 MB each |
| `bits`, `summary`, `count` | `(k + 1)` bitsets over `n` ranks | ~1 MB |
| `frontier` (`colors == 2` only) | `n` u32 | 8 MB |

~101 MB on the three-mask path, ~56 MB on the two-mask one. A deck patterns the
layers below the single-exposure pitch — the lower metals and their cuts, six to
twelve rule rows in practice. Before: fourteen mallocs per row, ~1.2 GB of fresh
`mmap` and `munmap` across the rows, and every byte of it a first-touch fault —
~300 000 page faults at 4 KB, or the THP equivalent. After: fourteen on the
first row, and a later row reallocates only when its layer is bigger than every
layer before it, so the total is bounded by the largest layer rather than by
their sum. The **memsets do not go away** — the earlier entry was right that a
reused `adjacent` still has to be cleared, 24 MB per row either way — but they
are now writes to resident pages rather than faults on new ones.

**Still blocked, and it is the smaller half.** The public `color_into` allocates
a set per call and cannot not: its four parameters are frozen, and
`crates/drc/tests/patterning_rules.rs` pins the arity at five call sites, so a
fifth parameter is a test edit before it is a signature change. Any caller
outside this crate colouring in a loop pays what `check_multi_patterning` no
longer does. The resolution is unchanged from the entry above — a `ColorScratch`
parameter on the public entry point, matching the `Scratch` the twenty-six
`check_*` transforms take — and `ColorScratch` is now the concrete type that
would go in it, so the change is one parameter and no new design.

**This is a departure from the project's own convention, and naming it is the
point.** `CLAUDE.md`'s signature rule says the caller owns the memory: inputs,
outputs and mutated buffers are all parameters. `color_into` is the one
transform in `drc` that allocates its own working set, and it does so because
the interface frozen in Phase 2 has no slot for one. The wrapper makes the
departure a property of one five-line function instead of the whole search,
which is as far as Phase 4 can take it. It does not make the interface conform.

`ColorScratch` is deliberately *not* a field on `drc::Scratch`. `Scratch` is
shared across all twenty-six transforms and none of the other twenty-five colours
anything, so a field there would be dead capacity on every rule row in the crate
and would inherit `crates/drc/src/lib.rs`'s open ceiling about a single `Scratch`
pinning the dispatcher to one core. The lifetime that fits these buffers is one
`check_multi_patterning` call.

## `GeometryStore` has no hole bit, so hole-ness is inferred from winding — open

`validate_layer_into` reads a clockwise ring as a hole. GDSII carries no such
signal. The Feb-87 manual states no winding for `BOUNDARY` — its one use of
"clockwise" is at `ANGLE` — and the format has no containment rule either: a
boundary drawn inside another is a second filled boundary, not a cutout. No tool
infers hole-ness from a boundary record. KLayout stores an explicit hole bit and
treats winding as a *derived, re-normalised* view of it; gdstk and gdspy have no
hole concept on input at all; Magic runs a wrap-number scanline. The only
hole encodings GDSII has are the keyhole slit and the butting-edge fracture.

So the conformant model is **every boundary is a filled region**, and holes
arrive from a keyhole ring and from a same-layer merge. Reaching it means a hole
bit on a `GeometryStore` row and a changed meaning for a `ValidatedLayer`
polygon — a Plan-level change, not a body.

This is the shared root of three entries that have been filed separately:

- `keyhole_rejected` in `tests/fixtures/expectations.json` — `ops::self_intersects`
  (`crates/core/src/ops.rs:287`) tests *touching* where the admissible class is
  weakly simple, i.e. proper crossing only. GDSII permits a self-touching ring
  and KLayout's own writer emits one via `db::resolve_holes`, so this tree
  currently refuses KLayout's GDS. Different file, different mechanism, no
  shared edit — fix it on its own diff, because it changes a predicate feeding
  `classify_ring`, the `Degenerate`/`SelfIntersecting` split and boolean, and
  wants `winding_of` re-reasoned over a keyhole ring first.
- `notch_no_outer_merge` — the width family never merges touching outers, so
  three abutting rects are three convex figures rather than one notched
  conductor.
- `mirrored_sref_winding`, now closed at the symptom.

**What was fixed, and what was not.** `crates/ingest/src/layout.rs :: emit`
reverses `[1..]` of a flattened ring when the composed transform's determinant
is negative — `strans` bit 0 is `diag(1, −1)` before the rotation, so
`Xform::linear` is det −1 exactly when `flip` (rotations are det +1, `mag >= 1`
enforced at `:973` and re-asserted at `:1231`). That is a symptom fix against
the store's existing CW-is-a-hole contract, stated plainly. It is still worth
having under any future hole model, because what it restores is
spec-independent: **a cell's rings have the same orientation wherever the cell
is instantiated**, which the flattener was breaking. `[1..]` and not `[..]`
because `erc::first_vertex` (`crates/erc/src/lib.rs:258`) documents vertex 0 as
a shape's canonical report point; a full reversal would move every per-shape ERC
coordinate under a mirror. Whole-ring reversal is safe on a keyhole either way —
outer and inner sub-loops both flip, relative orientation unchanged — so no
keyhole special case is needed in either order of landing.

Round trip is unaffected: `export::gds::write_store` emits one flat cell of
`BOUNDARY` records and never an `SREF`, so the re-read runs at
`Xform::IDENTITY`, det +1, and the reversal cannot fire.

Before the fix, `flatten`, `Xform::linear` and `Xform::compose` had **zero** unit
coverage — no `SREF`, `AREF` or `STRANS` constant appeared in any test in the
workspace, which is why this reached the corpus. Three tests now cover it, in
`crates/ingest/src/layout.rs`'s `mod tests` (they need a populated `LayerTable`,
which has private fields and no out-of-crate constructor):
`a_mirrored_instance_keeps_the_orientation_the_cell_was_drawn_with`,
`a_doubly_mirrored_instance_is_the_cell_as_drawn`, and
`a_mirror_composed_with_each_quarter_turn_still_flattens_counter_clockwise`.

---

## `Xform::compose` wraps `i64` on nested magnification — open, fail-open in release

Found while writing `wrapping_the_root_in_one_transformed_instance_transforms_the_whole_store`
(`crates/ingest/src/layout.rs`, the global-transform-equivariance law). It is
**not** what that law tests; the law's fixture deliberately keeps `mag > 1` in
the wrapping transform only, so it never trips this. Filed separately because it
is a different defect with a different fix.

**The arithmetic.** `crates/ingest/src/layout.rs:356`:

```rust
dx: a * child.dx + b * child.dy + self.dx,
```

`(a, b, c, e) = self.linear()`, whose entries are `±self.mag` or `0`. The
reader accepts any magnification that is integral and in `1..=1e6`
(`layout.rs:1120`), and `compose` multiplies them: `mag: self.mag * child.mag`.
So two nested `1e6` instances give a composed `mag` of `10^12`, and the *next*
level down multiplies that by a raw `SREF` `XY` offset, which GDSII bounds at
`i32` — up to `2_147_483_647`. The product reaches `2.1·10^21 ≈ 2^71`, and
`i64::MAX` is `9.22·10^18 ≈ 2^63`.

**Verified, not derived.** A four-cell library — `LEAF` drawing
`(0,0), (1,0), (0,1)`; `C2` placing `LEAF` at `dx = 18_446_743`; `C1` placing
`C2` at `mag = 1e6`; `TOP` placing `C1` at `mag = 1e6` — read through
`gds::read`:

| profile | result |
|---|---|
| debug | panics, `attempt to multiply with overflow` at `layout.rs:356` — an unhandled arithmetic panic, not a `LayoutError` |
| **release** | **`Ok`**, one polygon, vertices `x = [-1073709551616, -73709551616, -1073709551616]`, `y = [0, 0, 1000000000000]` |

The true offset is `10^12 · 18_446_743 = 18_446_743_000_000_000_000` (`2^63.0`),
which wraps to `-1_073_709_551_616`. That is inside `±MAX_ABS_DBU = 2^40 =
1_099_511_627_776`, so `emit`'s range check — which runs *after* the
composition — passes it, and the reader reports success for geometry it placed
`1.8·10^19` dbu from where the file says.

`18_446_743` is not adversarial beyond fitting `i32`: it is simply the smallest
offset whose wrapped residue lands back inside the domain. Any offset above
`9_223_373` already overflows; most wrap to a value the range check then
refuses, which is a *wrong error* rather than a wrong answer — still not a
correct read.

**Why the existing guards do not cover it.** `MAX_ABS_DBU` bounds a *vertex*, and
it is checked in `emit` against the already-composed transform. Nothing bounds
the intermediate `a * child.dx`, and nothing bounds the composed `mag` — four
nested `1e6` instances overflow `self.mag * child.mag` on its own (`10^24`), at
which point `emit`'s `debug_assert!(at.mag >= 1)` is the only guard and is
absent from exactly the profile where the wrong answer does damage. That is the
same shape as the `Bbox::area()` clamp recorded above, and it wants the same
treatment: an every-profile check, not a `debug_assert`.

**Why it is not fixed here.** The fix is a refusal, and refusal needs a variant
to refuse with. `LayoutError::CoordinateOutOfRange(i64)` carries the offending
coordinate, and there is no coordinate to carry — the value never existed. The
honest report is `UnsupportedTransform` ("instance transform is not
representable exactly", which is precisely true) with `checked_mul`/`checked_add`
throughout `compose` and `linear`, but `compose` returns `Self`, not
`Result<Self, LayoutError>`, and `linear` returns `(i64, i64, i64, i64)`. Both
signatures are frozen, and both are called from `Flatten::visit`
(`layout.rs:1364`), `Flatten::emit` (`:1450`) and `Flatten::place` (`:1398`).
Changing them is a Definition-Phase edit, so it is filed rather than committed.

The cheap alternative that needs no signature change: bound the *accepted*
magnification so no composition can overflow. `1e6` per instance is already the
reader's own limit; the composed product is what is unbounded. A running check
in `visit` — refuse when `at.mag` exceeds a depth-independent ceiling — is one
`if` on the path that already returns `Result<(), LayoutError>`. It is a
narrower fix (it does not bound `a * child.dx` for a legal `mag`), so it is
written here as the fallback, not the answer.

Not covered by any test today. Adding one is awkward on purpose: the debug
profile panics rather than returning, so a test would have to be
`#[cfg(not(debug_assertions))]` or assert a panic in one profile and a wrong
`Ok` in the other. That is worth having once the refusal exists; asserting the
current release behaviour would be asserting the bug.

---

## erc, from the ERC corpus-coverage pass

Five findings surfaced while deriving corpus cases for the five uncovered ERC
rule kinds. None is patched. The first two are defects in shipped behaviour; the
last three are a doc/schema/harness cluster.

### `electromigration` panics on any row naming two or more layers

`crates/erc/src/ruleset.rs` parses the row per-layer for three columns and
per-row for the fourth:

```rust
table.layer.extend_from_slice(layers);                             // N
table.max_density.extend(layers.iter().map(|_| max_density));      // N
table.max_current_per_cut.extend(layers.iter().map(|_| per_cut));  // N
table.blech_limit.push(blech);                                     // 1
```

`crates/erc/src/rules/electrical.rs:860` then
`debug_assert_eq!(table.layer.len(), table.blech_limit.len())`, and `:899`
slices `blech: &table.blech_limit[span]` where `span` is the *layer* span. So a
two-layer row panics on the assert in debug **and on the slice bound in
release** — this is not a debug-only fail-closed guard, it is a crash in every
profile. `em_current_density` directly below it has the same three per-layer
columns and no fourth, which is why it is unaffected.

The sibling columns say which side is wrong: `blech_limit` is a per-layer
physical quantity (the Blech length is a property of the metal), so the fix is
`extend`, not a refusal of multi-layer rows. That is a body change, not a
signature change — `ElectromigrationTable` already stores `blech_limit` as a
`Vec` indexed by the layer CSR.

`tests/fixtures/params.json`'s `met1.electromigration` names **one** layer and
must keep naming one until this is fixed; `ERC_EMIG_MET1`'s `note` records why.
Both sites sit *above* the intent gate, so the panic is reachable by any deck
that configures the rule, whether or not design intent is declared.

### `esd_latchup` measures a guard ring's width as its bounding box's minor span

`crates/erc/src/rules/reliability.rs:722`:

```rust
let box_of = store.poly_bbox(ring);
// The narrow side of the ring is what an injected carrier has to
// cross, so the width of a ring is the smaller of its two spans.
let width = Measurement::Length(box_of.width().min(box_of.height()));
```

The comment's reasoning is right and its implementation is the bounding box. For
a solid bar the two coincide. For an **annulus** — a ring, the shape the rule is
named for and the only shape a guard ring is ever drawn as — the bbox is the
outer rectangle, so the reported width is the ring's *outer dimension* rather
than its trace width. A 200 nm trace enclosing a 20 µm well measures 20 µm.

That is **fail-open** on exactly the geometry the rule exists to check: the
narrower the ring relative to what it encloses, the more generous the
measurement, and a ring far too thin to stop injection passes a
`min_guard_ring_width` floor it should fail.

`ERC_ESD_LATCHUP` cannot cover this — `ERC_HV`'s guard shape is a solid square,
the degenerate case where bbox minor span and trace width agree. Covering it
needs a cell drawing a real annulus.

### `include_partial_windows` cites a check that does not exist and cannot exist there

`DensityCmpTable::include_partial_windows`'s doc comment says `RuleSet::from_deck`
rejects `false` when the steps do not cover both die edges exactly. No such check
is in `crates/erc/src/ruleset.rs`, and none can be: `from_deck` never sees a die
extent — the die arrives at `check_density_cmp` from `engine::run::design_extent`,
long after the deck is parsed. Pass three of `check_density_cmp` has no `counted`
gate and cites the same non-existent check as its justification, so with the flag
`false` an excluded window still emits and still receives neighbour-delta
violations.

Related, and load-bearing for both `density_cmp` cases: `params.json` declares no
`prBoundary`/`DIEAREA`/die layer, so `design_extent` falls back to the union of
every polygon bbox (`crates/engine/src/run.rs:257`), which its own comment marks
fail-open for a min-density floor. Both corpus cases state the die extent they
assume in their `note`.

### `CmpModel::nominal_thickness` is mandatory and never read

`crates/erc/src/ruleset.rs:543` requires it; `check_density_cmp` never reads it.
Under the model the excursion is `sensitivity · (d − target)` — measured from the
calibration point, not from nominal — so the column has no consumer. A schema
wart rather than a physics bug, but a deck author cannot tell that from the
parser. `met1.density_cmp` supplies met1's own 400 nm so the value is at least
not a fiction.

### `measurement_matches` cannot assert an electrical measurement

`tests/common/mod.rs` matches `Length`, `Area`, `Count` and `Ratio`, and falls to
`_ => false` for everything else. `Measurement::Voltage`, `Current` and
`Resistance` therefore can never be asserted by a corpus case. This is the
remaining blocker on `ir_drop` coverage — it reports a voltage — while
`reliability` escapes it by reporting a `Ratio`.

This is the harness, not a frozen signature, so it is a small fix. It is filed
rather than taken because a corpus case that silently compares nothing is the
same fail-open shape as the rest of this section, and the arm should land
together with the case that needs it.

### a declared current budget is silently discarded on any rail without a device terminal

**This is a fifth fail-open landing on the same rules as `E2E_AUDIT` §5.1's four,
and it is not one of them.** Found by two blind derivations of `ERC_EMIG_MET1`
disagreeing: the prior one predicted `examined == 1`, the independent one
predicted `examined == 0` for *every* intent. The code agrees with the second.

`crates/erc/src/power.rs:1612`:

```rust
// Surviving `if`: once per declared supply. A rail nothing attaches to
// draws nothing, and the division below would be by zero.
if attach.is_empty() {
    continue;
}
```

`attach` is filled at `:1596` from `devices.devices_on(net)`, which is
**terminal-based** — a device counts only if one of its terminals lands on the
net. `params.json` binds terminals to `poly` and `diff`. So a rail drawn on
`li`/`met1` and fed from off-chip through a pad has an empty `attach`, the
`continue` fires **before** `budget_current_ua` is first read at `:1626`, and the
declared budget never enters the solve.

The comment states the fail-open as if it were the safe reading: *"a rail nothing
attaches to draws nothing"*. A rail with no device terminal on it is not a rail
that draws nothing — it is the ordinary shape of a **supply rail fed through a
pad**, which draws everything. Current enters from outside the extracted netlist,
which is exactly the case `devices_on` cannot see.

Downstream, every branch current is zero, so:

- `check_electromigration` computes `blech_product = |I|·(L/W) = 0`, which is
  under any `blech_limit`, so every branch is immortal and
  `crates/erc/src/rules/electrical.rs:598`'s `examined += u64::from(!immortal)`
  totals **zero**. The rule reports `Outcome::Ran` having examined nothing.
- `check_ir_drop` sees zero drop everywhere and reports clean.

`RuleRun::examined`'s frozen doc says "'Clean' has to mean *this rule executed,
examined N shapes, and found nothing*". Here N is zero and the outcome is still
`Ran`, so "your budget never reached the solver" and "this rail is within its
electromigration limit" are the same output. That is the false-clean failure this
tool is built against.

Two things make it worse than the four in §5.1. It is silent — no `Skipped`, no
diagnostic, and `Ran` with `examined: 0` is indistinguishable from a rule with
nothing in scope. And it is not a bounded numerical error like the other four; it
discards the input entirely, so no amount of derating analysis reaches it.

### RESOLVED — fail-closed, and both of the paragraphs that stood here were wrong

**The two claims this section used to make are withdrawn.** It said a tripwire
test pinned the behaviour green and would have to stay that way, and it said the
fix "is not obvious enough to take from a body" because `Connectivity` wants a
pad marker. An audit refuted both.

**No signature change was needed.** `Outcome::Refused` already exists
(`crates/report/src/violation.rs:361`) and is documented "Refused because the
input was outside what the tool represents exactly … Fail closed." That is the
right word and it was already in the vocabulary.

**The pad-marker diagnosis was wrong.** A pad marker names where current
*enters*; every branch current is determined by where it *leaves*. With the pad
known and the loads still unknown the right-hand side is still all zeros, so the
marker would improve the anchor inference — a separate, real finding — and do
nothing here. Same missing noun, different missing quantity.

**No numeric fix is correct, and that is settled rather than assumed.** Injecting
the budget at the inferred pad anchor is refuted by construction: `solve_into`
eliminates pads from the unknowns and builds the RHS only over unknowns, so a pad
node's `node_load` is never read and the solve is still identically zero.
Spreading the budget over the rail's own taps fabricates load positions and is
not conservative — a uniform spread reads *lower* per edge than a concentrated
distal load on every edge but one, making EM on distal segments more fail-open,
not less. The three situations that produce an empty `attach` — pad-fed rail with
loads outside the extraction, loads present but recognition failed (F2: no pmos is
recognised anywhere in the corpus), and a genuinely unloaded net — are
indistinguishable from the available data. Refusal is therefore the only correct
behaviour, not merely the loudest.

**What landed, all bodies:**

- `crates/erc/src/power.rs` — `pub(crate) fn discarded_budget(grid, intent)`.
  Exact, not heuristic: a scatter-accumulate of `node_load` per supply net, true
  when a net declares a non-zero `budget_current_ua` and its column sums to
  `0.0`. `parse_intent` already rejects a non-finite or non-positive budget
  (`ingest/src/intent.rs:194`) and one net carries one sign, so no cancellation
  can fake a zero.
- `crates/erc/src/lib.rs` — `refuse_rows`, the twin of `skip_rows`, writing
  `Outcome::Refused` with `examined: 0`, one `RuleRun` per row.
- `check_ir_drop`, `check_em_current_density` and `check_electromigration`
  refuse. The gate sits *below* the existing `intent.is_usable()` skip, so a run
  with no intent still reports `Skipped(NoDesignIntent)` rather than `Refused`.
- `check_reliability` deliberately still runs. Zero current puts every node at
  nominal, which is the *maximum* stress that model takes, so it was already
  fail-closed; refusing would replace a conservative verdict with none.
- The dead `if attach.is_empty() { continue; }` guard is gone with its comment,
  which was wrong on both counts — the physics claim was false and the
  division-by-zero claim was vacuous, since the `share` it computed was stored
  only by a loop that iterates zero times in exactly that case.

**A blast-radius correction:** this section originally named two affected rules.
There are four, and the worst was unfiled. `check_em_current_density` reported
`Ran` with a **full** `examined` population and no findings, because
`limits.blech` is empty for that rule so nothing is ever immortal — byte-identical
to a genuinely checked clean design. `check_electromigration`'s `examined == 0`
at least looks odd; that one did not.

**Granularity, and its cost stated plainly.** The row refuses whole. A budget is
per net and a row covers layers, so this over-refuses: one un-modellable rail
suppresses that rule's genuine findings on every other rail. `Outcome` carries no
payload, so the alternative — "Ran over the nets whose budget landed" — is a row
indistinguishable from a complete check while silently dropping the affected
rails, which is the defect's own shape. Refusing is recoverable; a false clean is
not.

Covered by `a_discarded_current_budget_refuses_the_rules_that_read_a_branch_current`
and `a_terminal_less_rail_with_no_stated_budget_still_reaches_a_verdict`
(`tests/test_all.rs`). The second is the load-bearing one: a terminal-less rail
with **no** budget declared must still report `Ran`, or a fix that refuses
unconditionally would pass every other leg. Discrimination was measured by
mutation, not asserted — deleting the gate, dropping either conjunct of the
detector, and adding a blanket refusal to `check_reliability` are each caught by
a different leg.

**Still open, and separate:** the anchor inference would genuinely benefit from a
pad marker in `Connectivity`; and a per-terminal current column on `DeviceTable`,
fed by an `ingest` reader for a per-instance power file, is the change that would
let a real budget be *modelled* rather than refused. Neither is needed for the
fail-closed behaviour above.

---

# The signature freeze was lifted, and here is what moved

Authorised explicitly, for filed defects only. Every entry below closes a
finding that was recorded in this file or in
`tests/fixtures/expectations.json`'s `blocking_findings`, and every one landed
with its regression test written **first and seen red**.

## `lvs::verdict::Discrepancy` gained `UndeclaredParam` — F8

`compare_params` walked the *intersection* of the two sides' parameter names and
passed over the symmetric difference. A reference card declaring `W L` against a
layout device declaring nothing therefore compared **zero** parameters, found
nothing, and returned `Verdict::Match` — the one outcome `crates/lvs/src/lib.rs`
forbids in as many words. Reachable from every parametric run in the tree,
because `graph::from_layout_into` projects no layout parameter at all.

The old doc comment reasoned that a name only one side declares is the two
sides' own business and that `Discrepancy` had no variant able to say
"declared on one side only" — which was true, and was the thing to fix rather
than the reason not to.

- `Discrepancy::UndeclaredParam { side, layout_device, ref_device, param }`.
  `side` is the side that *declared* it, matching `UnpairedDevice`'s reading of
  the same field.
- `compare_params` now reports the mismatched name and drains **both** tails, so
  the report is the mirror image of the reversed comparison.
- `engine::run::LVS_RULE_IDS` is `[&str; 7]`, `lvs.undeclared_param` inserted at
  index 4. `lvs_measurement` gives it the `Count(1)` against `Count(0)` form —
  one occurrence where none is allowed — because a missing declaration is not a
  value that disagreed.

Tests: `a_parameter_only_one_side_declares_is_not_evidence_of_agreement` and
`the_side_that_declared_the_lone_parameter_is_the_side_the_report_names`,
`crates/lvs/tests/compare.rs`.

## `analytical::extract_into` gained a `&Connectivity` — F11

Coupling and via extraction both need to know which layers are conductors and
which are cuts, and that is a deck fact rather than something derivable from a
`ProcessStack` keyed by `LayerId`. The parameter sits between `devices` and
`stack`. Two call sites in `engine::run::run_pex`, thirteen in
`crates/pex/tests/analytical.rs`.

## `core::view::PolygonRef` gained `provenance()` — the store row to blame

Read-only, and exactly what the `ring_poly` column's own doc comment says it
exists for: "lets a rule on a derived layer still blame a violation on real
geometry". `drc::rules::width::check_facing` needs it because a merged figure is
a row of no layer, so `OuterRows` cannot name it.

## Two node-model changes inside `pex`, both body-only but worth recording

`analytical::extract_net_into` places nodes at segment **boundaries**, so a net
of `n` polygons has `n + 1` nodes rather than `n`. The `<= store.poly_count()`
assert in `extract_into` became `<= poly_count() + net_count()`. Nothing
outside that function depended on the old bound; `reduce::lump_rows` already
documented "the net's total series resistance stands between its first and last
node", which is this model and not the old one.

`extract_into` now calls `ParasiticNetwork::sort_canonical` before returning.
The doc comment always promised "the order `sort_canonical` would have
produced"; it is now that order by construction rather than by argument, which
is what let coupling be emitted in a pass after every net has its nodes.

## Still open, and narrowed rather than closed

- **`overlay::margins` is still bounding-box.** `ring_contains_ring` now
  decides *hosting* exactly, so a shape stranded in a concave host's notch
  measures zero instead of a comfortable pass. The remaining optimism is the
  *margin* of a genuinely contained shape in a concave host: the box's far side
  may be further away than the host's material is. Closing it needs a distance
  from the inner ring to the host's boundary, which is a body change, not a
  signature one.
- **`ring_contains_ring` does not see holes.** A store row is one ring, so a
  host hole lying strictly inside the inner shape crosses nothing, puts no
  vertex outside, and reads as contained. That needs the *validated* host rather
  than its outer ring, and the route from a store `PolyId` to a `PolygonRef`
  still does not exist — the same gap `pair_layers` records.
- **`check_facing` merges outers for the notch sense only.** Merging is
  defensible for width too — two touching 50-unit rectangles are a 100-unit
  plate, and measuring them apart reports two false 50-unit widths — but that
  direction is fail-*closed* and no case in the corpus exhibits it, so it was
  left alone rather than changed with nothing to measure the change against.
- **`analytical::LATERAL_HALO_THICKNESSES` is a guess.** Ten times the layer's
  own thickness, because no deck in this tree states a coupling halo. Upgrade
  path: a `coupling_halo_nm` in the deck's `pex` section.

---

# The LVS blockers: mapped, then closed

`every_lvs_cell_in_the_corpus_extracts_the_devices_it_draws` went from **27
disagreements across 16 cells to 2**, and the two survivors are the same finding
stated twice. What follows is the map that was made first and the order it turned
out to need, because the order was not the numbering and getting it wrong made
things worse rather than slower.

## The order was F3 → F2 → F7 → F1, and F4 is still open

**F3, the keystone — closed.** `terminals: [poly, diff, diff]` bound one slot per
terminal *layer*, so source and drain both took the lowest `PolyId` on `diff`
under the marker and every extracted MOS had `Source == Drain`. Binding the two
positions to two different *polygons* could not fix it: probed, `LVS_INV` drew the
nmos diffusion as **one rectangle** `(0, 0)–(500, 200)` on a single net spanning
the channel.

The conductor that needed to exist was `diff NOT poly`. That needed the deck to
be able to *name* a derived layer, and `ingest::deck` had no derived support at
all — no section, no parse path — while `crates/derived` had a full `DerivedExpr`
operator set nothing could reach. Closed by giving derived layers real `LayerId`s
and materialising them into the `GeometryStore` at load time
(`ingest::layout::derive_layers_into`, `core::GeometryStore::append_layer`), so
`NetTable`'s `PolyId` indexing and every downstream rule work unchanged.

`DerivedExpr` could **not** be used: `gpurify-derived` depends on
`gpurify-ingest`, and materialisation has to live in `ingest`. The deck carries a
flat op-plus-operands table instead — the shape SVRF and KLayout decks use — and
derived ids come after every base id, so declaration order *is* evaluation order
and a cycle is unspellable.

**F2 — closed, with F3.** Dropping `nwell` from the pfet's `terminals` makes it
3-terminal like the nfet beside it. Measured on its own it took LVS from 27 to 19,
and it was deliberately *held back* until F3 because it closes no LVS case alone
and moves two ERC expectations that were written against the broken device
population.

**F7 — closed, and it was a *deck* defect.** Three code-only fixes were probed
and rejected; the reasons are in `blocking_findings.F7`. The marker has to *be*
the channel, which is a `derived` row now that F3 exists: `gate = poly AND diff`,
`gate_n = gate AND nsdm`, `gate_p = gate AND psdm`. No code changed for it. One
real fail-open was found alongside — a marker carrying *more* terminal polygons
than the recogniser has positions was silently truncated, losing a transistor and
possibly mis-wiring the survivor — and now refuses instead.

**F1 — closed, and it had to go last.** Adding the licon cuts before F3 would have
made the corpus *worse*: contacting `LVS_INV`'s output strap to an unsplit diff
merges VSS into Y, so the net count falls *past* the derived 4 rather than
reaching it. 35 cuts across ten cells, plus 18 `TEXT` deletions that were forced
rather than cosmetic — a cut merging two labelled shapes puts two names on one
net, which is `PortError::ConflictingLabels` and aborts the load.

**F4 — closed, on the third attempt, and my own diagnosis of it was wrong.**
`refine::role_code` now collapses `Source` and `Drain` to one code: a MOS channel
is symmetric, which end is the source is decided by *bias* rather than by layout,
and an extractor reading geometry has nothing to decide it with. It is the
mechanism `TerminalRole::Pin` already uses for a resistor's two ends.

The first two attempts were reverted because the collapse creates *genuine*
automorphisms and three tests turned a **deleted device** into
`Inconclusive(UnresolvedSymmetry)`. The real blocker was never the tie-break.
`compare::interpret` returned on the **first** balanced unresolved class it saw,
so a symmetry anywhere in the graph masked every genuine discrepancy sharing the
partition. The two conditions are independent: a class holding the same count on
both sides is a symmetry — either pairing of its members is right, so nothing in
it is a difference — while a class holding different counts is a difference no
pairing can mend, and **the second must survive the first**.

`Partition::symmetric_nodes()` is the accessor that separates them, and it is
deliberately *not* the `members(ClassId)` the old comment asked for: `interpret`
wants a per-node verdict, not a per-class list, so one tally pass plus two
branchless compacts beats an O(classes × nodes) query. Its members are **held
back** from the unpaired scan — on both sides, and in `compare_terminals` too,
without which the fix trades one bug for another and invents `TerminalMismatch`
rows on a transistor with nothing wrong with it.

**The claim that `TieBreak::LowestIndex` "was not enough for `mos_and_bjt`" is
withdrawn — it was mine, and it was wrong.** Measured: under `LowestIndex`,
`symmetric_nodes` comes back *empty* on that fixture, every surviving unresolved
class is genuinely imbalanced, and the tie-break resolved the symmetric channel
outright. What had left the class unbroken was an early return that a previous
pass had already fixed. No `TieBreak` change was needed.

Two fixtures were **not rigid** once the collapse landed, and both were the
fixture's fault rather than the assertion's. A bare S/D chain reversed end to end
maps every terminal onto one of the same code, so `chain` now diode-connects
device 0's gate to one end of its own channel — the smallest anchor that
distinguishes the two ends, and what a real mirror stack is anchored by. Both
tests then passed *unmodified*. `stacked_pair` had an order-2 automorphism its
own doc comment denied — refinement was returning the *other* correct pairing and
the expectation called it wrong — so the relabelling test moved to `chain(3)` and
`stacked_pair`'s doc now names its automorphism.

**F5 is the only remaining LVS disagreement**, and both survivors state it
cleanly: `LVS_SERIES_MERGE` and `LVS_PARALLEL_MERGE` each extract 2 devices where
the geometry draws 1. That is a netlist *transformation* missing on top of a
correct extraction, not an extraction fault. `LVS_SERIES_MERGE` used to **agree by
coincidence** — the extractor dropped a finger while the expectation held the
post-merge count, two errors cancelling.

## Three corpus numbers that were right for the wrong reason

Worth stating together, because each cost real time and the pattern repeats:
`LVS_SERIES_MERGE`'s device count (above); `ERC_P2P_PASS`, marked `strength:
vacuous` precisely because `LVS_INV` had too few attach points to examine; and
`a_stated_current_budget_drops_ohms_law_across_a_known_poly_rail`, whose "the poly
rail has two taps" premise held only while F2 left the pfet unrecognised — its own
message said so.

## A landmine in `tests/fixtures/params.json`

The `angle` rule's params are **two entries under the same key**:

```json
"params": { "angle": { "count": 0 }, "angle": { "count": 90 } }
```

`drc::ruleset` reads *one allowed direction per `angle` parameter*, so the
repeated key is how the deck says "axis-aligned only". A JSON object with
duplicate keys is legal and its resolution is parser-defined: serde reads every
pair, and most JSON libraries — Python's `json` among them — keep only the last.

**Do not round-trip this file through a library that collapses them.** Doing so
silently drops the horizontal direction, and every horizontal edge in every
design becomes an angle violation: it turned three DRC corpus cases red in a
domain the change had nothing to do with, and the failure names the `angle` rule
rather than the edit. There is no comment mechanism to warn in the file itself —
the deck parser is `deny_unknown_fields` and rejects a `_comment` key, which is
the right behaviour and is why this note lives here.


## `cli` had no `--grid`, so no invocation could reach any stage — RESOLVED

`crates/cli/src/args.rs` set `grid: None` unconditionally, with a comment
explaining that `Common` had no field to park a value in and that adding one was
"a widening of a frozen struct". A deck file does **not** declare a resolution —
`read_deck` is *handed* one — so every run of the binary stopped at
`LoadError::NoGrid` before a file was opened. Measured: no CLI invocation could
reach DRC, ERC, LVS or PEX.

`--grid <dbu-per-um>` now exists, and the grammar decision is the whole of it:
**optional, never defaulted**. Making it required would invalidate every command
line that already parses; defaulting it would silently reinterpret every limit in
the deck — a 100 nm rule read against the wrong resolution is a different rule —
turning a loud dead binary into a quiet wrong one. Absent means absent, and
`load_into` still refuses, which is what makes optional safe.

Verified end to end, not just parsed:

```
$ gpurify lvs LVS_CLEAN_MATCH.gds --deck params.json --grid 1000 \
      --no-strict-layers --reference lvs_inv.cdl
  lvs: ran
  3 rules skipped
  5 rules clean
  12 violations: 12 errors, 0 warnings
```

Without the flag the same command still reports `no grid resolution:
Inputs::grid is absent and nothing else establishes one`.

Three tests in the `args` module: the value reaches `Inputs`, absence leaves it
absent, and `0`/`-4`/`eleven`/`1.5` are refused — the parser rejects a
non-positive resolution first, so the `Grid::new` conversion in `to_inputs`
cannot fail.
