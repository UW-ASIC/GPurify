# Rules without a definitive test

A **definitive test** is one backed by an oracle from `docs/TESTING.md` — a
closed form, a law, or a generator that built the answer it expects.

Some rules have none. They ship anyway, and they are listed here.

That is a deliberate choice over the two alternatives. Deleting them loses real
checks a foundry asks for. Marking them `experimental` in a manifest hides them
behind a flag nobody reads, which is the false-clean failure mode wearing a
different hat. A ledger is the honest option: the rule runs, and anyone
depending on it can see exactly what is and is not established about it.

**A rule stays here until it has an oracle, or until someone argues it needs
none.** Moving one off this list requires naming the oracle.

Most entries are blocked on an interface rather than on arithmetic: a type a
test cannot construct, a doc comment that states two incompatible things, or a
number whose unit is written down nowhere. Where an entry says a signature has
to change, it means the gap cannot close without a breaking API change — the
entry records the gap, not a promise about when it closes.

Some entries name an interface that has since been widened, so the test is now
writable and has simply not been written. Those say so, and they are the
cheapest entries here to retire.

---

## Format

Each entry states what the rule checks, why no oracle applies yet, and what
*is* verified about it — usually construct-from-answer on the simple cases,
with the hard cases unverified.

```
### <rule id> — <crate>

**Checks.** What it looks for.
**Missing.** Why no closed form or law applies.
**Verified.** What testing does exist.
**Would need.** What an oracle for this would have to look like.
```

---

## Entries

Grouped by the area that owns the interface, in module-graph order. An area is
no longer one crate each: `core` and `derived` are `gpurify-geom`; `topology`,
`report`, `drc`, `erc` and `lvs` are `gpurify-check`; `pex` and `quasistatic`
are `gpurify-extract`; `engine`, `export` and `cli` are the root `gpurify`
package.

Absence from this list is a claim of coverage, not of perfection. The
twenty-six DRC rules — `multi_patterning`, `cheesing`, `redundant_via`,
`via_array_spacing` and the rest — carry construct-from-answer coverage: a
violation placed deliberately and asserted at its coordinate with its
measurement. What is below is what that treatment does not reach.

---

## core

### `boolean`'s four transforms on arbitrary operands — core

**Checks.** Exact rectilinear union, intersection, subtraction and offset over
two validated layers.
**Missing.** Nothing structural. `ValidatedLayer` owns its coordinates
(`crates/geom/src/view.rs`) and derives a `PartialEq` documented as structural,
so a result whose geometry is *new* — two rectangles that partially overlap
union into an L that exists in no input store — is readable, and every law in
`boolean`'s own doc comment is writable over arbitrary operands. The suite has
not been widened onto it.
**Verified.** Only the configurations whose results are expressible as spans
over the input store, in `crates/geom/tests/core/boolean_laws.rs`: idempotence
of a layer against itself; identical layers, which is total overlap; a
contained layer, where the union is the container and the intersection the
contained; and disjoint layers, where the union is the concatenation. Region
equality is asserted as "each difference is empty and the areas agree", which
needs only the empty result to be expressible, and that is what lets
commutativity and `(a − b) ∪ (a ∩ b) == a` run at all. No test hands the four
transforms a pair of partially overlapping operands. `offset_into` is verified
at zero only.
**Would need.** The same laws re-stated over generated geometry that overlaps
partially, comparing whole regions rather than areas.

### `index`'s adapter seam cannot use `gpurify-testgen` — core

**Checks.** Nothing about the product code. This records why the adapter tests
in `crates/geom/src/index.rs` build their geometry by hand.
**Missing.** `candidate_pairs_observed` is private, so its tests must live
inside `gpurify-geom`. But `gpurify-testgen` depends on `gpurify-geom`, and the
dev-dependency cycle makes Cargo compile a *second* instance of `gpurify-geom`
for the generator to link against. Its `LayerId` is then a different type from
the one under test, and nothing from the generator type-checks in a unit test
inside this crate. `gpurify-testgen` depends on `gpurify-geom`,
`gpurify-ingest` and `gpurify-check`, so the same holds for a unit test inside
any of those three. Integration tests are unaffected — they link the crate from
outside — which is why `prefilter`'s tests live in
`crates/geom/tests/derived/prefilter.rs` rather than in
`crates/geom/src/prefilter.rs`; only the private side of a seam is stuck.
**Verified.** The seam's own property — no rejected pair would have passed the
exact predicate — against a deterministic lattice scatter written out in the
test module and fixed arithmetically from a seed. Reproducible, but it is a
second generator and not the one the rest of the suite is calibrated against.
**Would need.** Either the seam made `pub` so its test can move to
`crates/geom/tests/`, as `prefilter`'s did, or a generator crate below
`gpurify-geom` that a crate can dev-depend on without a cycle. Every crate that
owns a private seam will hit this.

### `GeometryStoreBuilder::finish`'s row order within one layer — core

**Checks.** The order rows take among the other rows of the same layer.
**Missing.** Nothing structural. `finish` documents the sort as stable and a
layer's permutation slice as strictly ascending (`crates/geom/src/store.rs`),
so "the third shape pushed is `PolyId(2)`" is a writable assertion. Nothing in
`crates/geom/tests/core/store_layout.rs` makes it — every test there addresses
rows through the permutation rather than by position, which is exactly the
indirection the guarantee exists to remove.
**Verified.** That the grouping loses no row and invents none, over four hundred
generated shapes; that the permutation is a bijection carrying every row's layer
and coordinates; and that two builds of the same pushes agree column for column,
with and without `with_capacity`.
**Would need.** One construct-from-answer test naming a shape by its position
within its layer. Every test in the workspace that does the same depends on the
guarantee holding.

### `Bbox::EMPTY.width()` and `Bbox::EMPTY.height()` — core

**Checks.** The span of a bounding box, as a `Dbu`.
**Missing.** Not an oracle gap — a live defect with no test at the boundary.
`Bbox::width` builds its answer with `Dbu::new_unchecked`
(`crates/geom/src/bbox.rs`), whose `debug_assert!(in_domain(raw))`
(`crates/geom/src/dbu.rs`) rejects the `2^41` a domain-spanning box produces,
and `Bbox::EMPTY` is exactly that box. The comment at the site says the empty
box is already past it. A debug build panics; a release build hands back a
coordinate outside the domain every other interface assumes.
**Verified.** Nothing. `grep -rn 'EMPTY.width' crates` finds only the comment,
so no test calls it.
**Would need.** A decision — saturate, return an `Option`, or document the
precondition — and then one case at `Bbox::EMPTY` and one at `±MAX_ABS_DBU`. The
same boundary reached from the other side is `Dbu::mul_wide`, which asserts
`in_domain` on both *operands* while `Add` and `Sub` are documented as legally
exceeding `±MAX_ABS_DBU`. `Bbox::area` routes around `mul_wide` on purpose and
says why, so the area path is safe and the accessor is not.

---

## ingest

### `deck::LayerTable` — ingest

**Checks.** Maps layer names and GDS stream pairs to `LayerId`.
**Missing.** Nothing structural. `LayerTable::build(&[(StrId, u16, u16)])` and
`stream_of(LayerId) -> (u16, u16)` are both public with real bodies
(`crates/ingest/src/deck.rs`), and `build` needs no `StrTable` because `by_name`
is sorted by `StrId`. No test calls either. This was the single most
load-bearing blocker in the file — it gated `drc::RuleSet::from_deck`,
`export::gds::write_store` on geometry, `engine::pipeline::load_into` and every
ERC rule-construction path below — and all of those now wait on test authorship
rather than on an interface.
**Verified.** Nothing. `tests/export/gds.rs` and
`tests/export/determinism.rs` still construct `LayerTable::default()`,
the empty table, and `gpurify-testgen` still sidesteps the type by handing back
the deck *fragments* whose types were always constructible — `Connectivity`,
`DeviceRecognition`, `ProcessStack`.
**Would need.** A test that builds a populated `LayerTable` and reads a
`LayerId` back through `of_stream` and `stream_of` in both directions.

### `Provenance::push` — ingest

**Checks.** Records the hierarchy path and stream properties of one polygon.
**Missing.** Nothing structural.
`Provenance::intern_path(&mut self, &[StrId]) -> PathId` is public with a real
body (`crates/ingest/src/provenance.rs`), so a non-`ROOT` `PathId` is reachable
from outside the crate. Nothing calls it, so hierarchy provenance — and
therefore `bind_ports_into` against a labelled instance — is still unexercised.
**Verified.** The `ROOT` path, plus the permutation of the hierarchy-path column
in a unit test inside `provenance.rs`.
**Would need.** A test interning a two-component path, attaching it to a
polygon, and reading it back after the layer sort.

### `export::gds::write_store` and the `parse -> write -> parse` law — ingest, export

**Checks.** That a store written as GDSII and read back is the same store.
**Missing.** Nothing structural. `stream_of` gives the writer the
`LayerId -> (u16, u16)` direction it was missing, and `LayerTable::build` gives
an integration test — which has the right type identity — a way to construct the
value. The law has a location and no occupant: every writer test still passes
`LayerTable::default()` over a zero-layer store.
**Verified.** `layout::tests::a_library_holding_a_known_layout_reads_back_as_that_exact_store`
keeps the half that was load-bearing: four shapes are stated twice, once as the
store `GeometryStoreBuilder` makes of them and once as the GDSII library the
Calma format specification says holds them, and the reader must turn the second
into the first vertex by vertex. Its oracle is the published format rather than
this workspace's own writer, which is the stronger of the two. Reader
determinism is covered separately.
**Would need.** The round trip written down: build a populated `LayerTable`,
write a store holding polygons, read it back, and compare the two stores column
for column.

### `read_deck`'s validation errors — ingest

**Checks.** `DeckError::OffGrid` for a limit that is not an exact multiple of
the grid, `UnknownLayer` for a rule naming an undeclared layer, and
`MissingParam` / `DuplicateRule`.
**Missing.** Nothing structural. `parse_deck(&str, Grid, &mut StrTable)` has a
documented JSON schema and a clause per variant
(`crates/ingest/src/deck.rs`), so `OffGrid`, `UnknownLayer`, `MissingParam` and
`DuplicateRule` are each reachable from a string literal. No test names any of
the four.
**Verified.** The io refusal
(`a_deck_that_cannot_be_opened_is_an_error_rather_than_an_empty_deck`), and the
fail-closed lookup underneath the `UnknownLayer` case:
`deck::tests::a_name_the_deck_does_not_declare_resolves_to_no_layer_at_all`
shows an interned but undeclared name resolving to `None` rather than to a fresh
layer. `RuleTable`'s CSR accessors are covered in full, its columns being
public.
**Would need.** Four short decks, each with one defect, each asserting the exact
error. The off-grid case is one rule and two grids.

### `DesignIntent` with anything declared — ingest

**Checks.** Supply roles, domain voltages and per-net limits once an intent file
states them.
**Missing.** Nothing structural. `parse_intent(&str, &mut StrTable)`
(`crates/ingest/src/intent.rs`) builds a populated `DesignIntent` from a string,
with `supplies` and `limits` as arrays so a repeated net is expressible and
therefore refusable. No test calls it, so `is_empty` is still only ever shown
true, and `DomainConflict`, `DomainWithoutSupply` and `BadLimit` are still
unexercised.
**Verified.** Absence, completely.
`an_absent_intent_declares_nothing_and_every_accessor_says_so` checks that
`is_empty` holds and that each accessor answers not-declared rather than a
plausible default, which is what makes six ERC rules report `Skipped` instead of
clean. `limits_are_total_over_every_net_id_even_with_nothing_declared` covers
the empty-column lookup. The io refusal is covered.
**Would need.** One intent string per refusal, plus one well-formed intent read
back through every accessor.

### `UnknownLayers::Drop`'s drop count — ingest

**Checks.** The doc comment says dropped rows are reported and never dropped
silently.
**Missing.** Nothing structural. `Layout::dropped: u32`
(`crates/ingest/src/layout.rs`) is the count, and the variant doc points at it.
No test reads the field, so the "never silent" half of the mode is observable
and unobserved.
**Verified.** The geometric half:
`an_undeclared_layer_is_refused_under_reject_and_dropped_under_drop` asserts
that `Drop` keeps exactly the shape on the declared layer and that `Reject`
names the undeclared stream pair, and
`the_two_unknown_layer_settings_agree_when_every_layer_is_declared` asserts the
doc's claim that the two settings are not a correctness switch.
**Would need.** One line in
`an_undeclared_layer_is_refused_under_reject_and_dropped_under_drop` asserting
`dropped` is the number of rows the fixture put on undeclared layers, and zero
when every layer is declared.

### `oasis::read` — ingest

**Checks.** Reading an OASIS file into a store and a provenance table.
**Missing.** No test builds OASIS bytes. The format has variable-length integers
and modal state carried between records, so a hand-assembled fixture is a
partial encoder rather than a few dozen lines, and there is no writer in the
tree to produce one. Every reader assertion would also need the `LayerTable`
fixture, so it is blocked behind that as well.
**Verified.** `oasis::detect` only: it accepts the OASIS magic, refuses a GDSII
header, refuses an empty prefix, and never accepts a prefix `gds::detect` also
accepts, over 512 seeded random prefixes.
**Would need.** An OASIS writer in `export`, which would make the same
round-trip law available for it, or a checked-in fixture file with a stated
expected store.

### The SPICE and Spectre readers on input they accept — ingest

**Checks.** That a well-formed netlist produces the right subcircuits, devices,
terminals and parameters.
**Missing.** Both conventions the readers used to leave open are now stated —
`param` is SI base units with SPICE scale suffixes expanded at parse, and an `X`
card is a row in the instance table (`crates/ingest/src/netlist.rs`) — and the
card-for-card test deliberately sidesteps both. Its own doc says so: every
parameter value in its deck is a bare number, "so neither case folding nor
SPICE's suffix multipliers … can change what the correct answer is". So the
suffix expansion that turns `w=1u` into `1e-6`, and the `X`-card row, have no
assertion on them.
**Verified.** `a_subcircuit_of_two_transistors_reads_back_card_for_card` over a
suffix-free, lower-case deck: ports in order, four-terminal devices in terminal
order, two occurrences of one name being one net. Plus the fail-closed half with
the line number rather than only the variant — a `.subckt` defined twice is
`Redefined` at the redefining line, a call to an undefined subcircuit is
`UndefinedSubckt` at the call, and a Spectre `alter` statement is `Unsupported`
at its line. `Netlist`'s own CSR accessors are covered directly.
**Would need.** The same deck with `w=1u`, `l=0.18u` and a mixed-case model
name, asserting the expanded SI values; and one `X` card asserted into
`instance_of` / `instance_subckt`.

### `Netlist::top` where a subcircuit is instantiated — ingest

**Checks.** That the top cell is the one nothing else instantiates.
**Missing.** Nothing structural. The instance table — `instance_of` and
`instance_subckt` among five public columns
(`crates/ingest/src/netlist.rs`) — is the cell-to-cell edge `top` searches, so a
two-level hierarchy is buildable. No test builds one:
`the_top_subcircuit_is_the_uninstantiated_one_and_ambiguity_is_refused` uses a
fixture whose instance columns are empty, so the search itself never runs over
an edge.
**Verified.** The three cases that need no instantiation: no subcircuits is no
top, one subcircuit is that subcircuit, and two subcircuits neither of which
instantiates the other is an ambiguity refused rather than resolved by taking
the first or the last.
**Would need.** A two-level netlist — a cell instantiating another — whose top
is decided before the call.

### `DeckError::OffGrid` reports a number that is not off the grid — ingest

**Checks.** The message a user sees when a deck states a limit the grid cannot
express exactly.
**Missing.** Not an oracle gap — a defect with no assertion on it. `to_limit`
(`crates/ingest/src/deck.rs`) narrows the stated nanometre value with
`let stated = nm as i64;` before putting it in `OffGrid(String, i64)`, so a deck
saying `300.5` on a 1 nm grid is refused with *"limit 300 nm is not an exact
multiple of the grid"* — and 300 is an exact multiple of a 1 nm grid. The
refusal is right and the number in it is unusable.
**Verified.** Nothing about the reported value. The refusal itself is reachable
from `parse_deck`, but see the validation-errors entry above: no test names the
variant.
**Would need.** Either an `f64` in the variant or a rounded-to-grid pair, and a
test on an integer nanometre limit against a coarse grid (`dbu_per_um = 200`),
where truncation cannot hide the bug, with the reported value pinned.

---

## derived

### `DerivedExpr::Inside` and `DerivedExpr::Outside` — derived

**Checks.** Selecting the shapes of an operand by their relationship to a
region, against an explicit finite universe.
**Missing.** The interpretation is settled — `crates/geom/src/expr.rs`
documents the area/clipping reading, `Inside` being `Intersection` under the
deck's name and `Outside` being `(operand ∩ universe) − region` — and no test
exercises the case the two readings disagree on.
`inside_and_outside_partition_the_operand_they_select_from` runs on
`cleanly_split_store()`, and its own doc says every operand shape there lies
wholly within the region or wholly clear of it, "which is what lets the law be
stated without first settling whether the two operators select whole shapes or
clip area". A whole-shape implementation would still pass it.
**Verified.** The partition law — `Union(Inside, Outside) == operand` with
`Intersection(Inside, Outside)` empty — on a fixture where the two readings
agree by construction.
**Would need.** One construct-from-answer case with a shape deliberately
straddling the region edge and the clipped area written down. Ten lines against
the documented reading.

### `DerivedExpr::Outside` with a universe that does not contain its operand — derived

**Checks.** Nothing states what happens when the universe is smaller than the
operand.
**Missing.** Nothing structural. Truncation is documented as deliberate rather
than an error (`crates/geom/src/expr.rs`), on the ground that the universe is
the extent the deck declared, so the truncated area is a closed form a test can
compute. No test measures it — and the decision is worth a second opinion as
well as an assertion, because truncation loses area, which is fail-open for
every rule consuming the layer.
**Verified.** Only the case where the universe contains everything with four
thousand units of margin, which is the configuration De Morgan and the partition
law are stated in. Under that configuration truncation never fires.
**Would need.** One operand deliberately reaching outside its universe, with the
surviving area written down before the call.

### `Evaluator::plan`'s evaluation order — derived

**Checks.** Ordering the deck's named definitions so every dependency is
evaluated before the definition naming it.
**Missing.** Two things at once. The order is invisible through the public
interface — `get` takes a name and `Evaluator`'s columns are private — so
`crates/geom/tests/derived/plan.rs` can only assert acceptance, rejection, and
that every accepted definition has a result afterwards. Separately, the field
comment on `Evaluator::name` asks for two orders at once: "names in evaluation
order, so a lookup is a binary search" holds only when the topological order
happens to be ascending by `StrId`, which no deck guarantees. A diamond whose
topological order is the reverse of its name order is the counterexample, and
it is the fixture the unit tests use.
**Verified.** Topological ordering, permutation, and name-to-expression
pairing, all against the private columns from a `#[cfg(test)] mod` inside
`crates/geom/src/expr.rs`. Acceptance and cycle rejection publicly.
**Would need.** For the ordering: nothing, the unit tests cover it. For the
field comment: a decision on which of the two orders `name` is in, since `get`
cannot binary-search a topologically ordered column.

### `prefilter::candidates_observed`'s null adapter — derived

**Checks.** That `NoObserve` costs a production build nothing, which is the
condition `docs/TESTING.md` attaches to every test-adapter seam.
**Missing.** This is not something a `#[test]` can state. The gate is a
disassembly comparison of the `bench` profile against a build with the seam
removed by `cfg`, and nothing in the workspace performs one. "It is cheap" is
explicitly not the standard.
**Verified.** The seam's behavioural property is fully instrumented: no rejected
pair overlaps, every overlapping pair survives, `kept` agrees with the emitted
list. The cost of the instrument is not.
**Would need.** The check named in `docs/TESTING.md`: identical instruction
sequences in the `bench` profile, compared by a tool rather than by a test. The
failure mode is the observer parameter blocking inlining, not a leftover call.

### `Evaluator::evaluate`'s allocation behaviour — derived

**Checks.** The doc comment promises this "allocates once on first call and
never again", which is the whole reason the two scratch buffers are fields
rather than locals.
**Missing.** No allocation-counter adapter exists in this crate. The claim is
invisible in every return value, and no public interface exposes buffer
capacity.
**Verified.** That re-evaluating a plan on an evaluator which already holds
results reproduces those results byte for byte, which catches scratch
contamination but not reallocation.
**Would need.** The allocation-counter seam `docs/TESTING.md` lists in its
adapter table, threaded through this entry point the way `ObservePrefilter` is
threaded through the prune.

---

## topology

### `NetTable`, `PortTable`, `NetNetworks` — topology, erc

**Checks.** The extracted net partition, its names, and one net's resistor
network.
**Missing.** `NetTable` and `PortTable` have private fields and no constructor,
so a test cannot build the *expected* table and compare tables directly. Nor do
`Violations` or `NetNetworks` derive `PartialEq`, so neither can be compared
with `assert_eq!`. This entry is cited by `drc`, `lvs`, `pex` and `erc` below:
it is the second-largest blocker in the file after `deck::LayerTable`.
**Verified.** `gpurify-testgen` states its net answers as `Vec<Vec<PolyId>>` and
compares through `NetTable::polys_of` and `same_net`, and
`assertions::assert_violations_eq` compares `Violations` column by column. Both
work, and both are more code than a derive would have been.
**Would need.** `PartialEq` on `Violations` and `NetNetworks`; a test-only
constructor on `NetTable` and `PortTable` if whole-table comparison is ever
wanted.

### `DeviceTable::params_of`, `DeviceParam`, `DeviceMeasure` — topology

**Checks.** The measured geometry of a recognised device: width, length, area,
perimeter, finger count, exact and in layout units.
**Missing.** No oracle can be stated. `DeviceRecognition` names a marker layer
and a list of terminal layers and nothing else — there is no measurement layer,
no channel-direction convention, and no doc comment saying which `DeviceParam`
rows a given `DeviceKind` is expected to produce or how a width is derived from
a marker-and-terminal intersection. A test would have to invent that
convention, and a test that invents its own answer checks nothing.
**Verified.** Nothing. Every *other* column of `DeviceTable` is checked against
`gpurify_testgen::layout_from_netlist`'s answer: kind, model, marker polygon,
terminal roles, terminal nets, and the `devices_on` reverse index.
**Would need.** Either a documented convention on `recognise_into` stating which
parameters each `DeviceKind` measures and from which geometry, or an
`expected_params` column on `gpurify_testgen::netlist::ExpectedDevice` computed
from the floorplan's closed-form stub dimensions.

### `DeviceRecognition` with two recognisers on one marker layer — topology

**Checks.** How many devices a deck produces when two recogniser rows name the
same marker layer and the layout holds one marker polygon per device.
**Missing.** `DeviceRecognition`'s doc comment says only "the marker layer whose
polygons each identify one device", and `topology::device` restates it as "one
polygon on the recogniser's marker layer is exactly one device". Read literally
that gives *recognisers × markers* devices, not one per marker. The reading the
tests use — a recogniser fires only where every one of its terminal layers has a
shape under the marker — is derived from the signature rather than documented:
`DeviceTable::terminal_net` is a `Vec<NetId>` with no absent-terminal value, so
a recogniser matching a marker whose terminal layers are empty has no row it
could legally write. That derivation is sound but it is not stated anywhere a
reader would find it.
**Verified.**
`two_identical_devices_on_two_marker_polygons_are_two_devices_not_one` sidesteps
the question entirely by using a single recogniser row, so the
one-device-per-marker rule is tested on its own. The two tests that use
`layout_from_netlist`'s multi-row recogniser carry the derivation as a comment.
**Would need.** One sentence in `DeviceRecognition`'s doc comment saying whether
a recogniser whose terminal layers are absent under a marker skips that marker
or is a deck error.

### `PortError::OrphanLabel` — topology

**Checks.** A label attached to a shape that lies on no extracted net.
**Missing.** Nothing structural. A polygon on a layer absent from
`Connectivity::conductors` gets the sentinel `NetId::NONE`
(`crates/check/src/topology/net.rs`), and `bind_ports_into` states that a label
on such a shape is `OrphanLabel` (`crates/check/src/topology/port.rs`), so the
orphan is constructible on purpose. No test in `crates/check/tests/topology/`
names the variant.
**Verified.** The other variant only: `ConflictingLabels` is constructed
deliberately, on a rail and the stub a via joins to it, and asserted to name
that exact net. The success path and the repeated-same-label boundary are both
covered.
**Would need.** A label attached to a shape on a non-conductor layer, asserted
to come back as `OrphanLabel` naming that shape.

### The two-thread-count half of the determinism gate — topology

**Checks.** That output is byte-identical across two runs at two thread counts.
**Missing.** No entry point in this crate takes a thread count.
`extract_nets_into`, `recognise_into` and `bind_ports_into` take only data, so
there is no parameter a test can vary and no way to force the pair-finding pass
onto a different number of workers from outside the crate.
**Verified.** The half that can be stated here.
`extraction_is_identical_across_runs_reused_tables_and_threads` compares a full
rendering of the `NetTable` across a first run, a second run into the same table
(which is where surviving scratch buffers would show), a run into a fresh table,
and two concurrent runs on separate OS threads.
`binding_twice_into_one_table_gives_the_same_table` does the same for
`PortTable`.
**Would need.** Nothing structural in this crate: the thread-count gate belongs
at `engine::run`, which owns the `threads` parameter, and should be stated there
against the whole pipeline rather than duplicated per crate.

### The mapping from recogniser terminal position to `TerminalRole` — topology

**Checks.** Which `TerminalRole` `recognise_into` assigns to terminal `k` of a
recogniser.
**Missing.** The position-to-role table now lives on `TerminalRole` itself
(`crates/check/src/topology/device.rs`), so `topology` and `lvs` read one
source rather than inheriting the testgen builder's convention — except for
`Diode`, which is deliberately excluded and named as unresolved at the site.
`Pin` is interchangeable by definition, so a diode gets pins, and pins match a
diode wired backwards. Anode-and-cathode is the orientation a real check needs
and nothing states it.
**Verified.** The documented families, end to end: roles come back in recogniser
terminal order and are compared element by element against the spec that emitted
the layout, so a different convention fails loudly rather than agreeing
silently.
**Would need.** A decision on diode terminal orientation, then one reversed
diode that must not match a forward one.

---

## report

### `Measurement`'s `Display` — report

**Checks.** How a measured quantity prints in a report: `200 nm`, `1.8 V`,
`12.4 ohm`.
**Missing.** Nothing structural. `Display` is documented to print raw database
units with a `dbu` / `dbu^2` suffix and to leave the grid to whoever holds one
(`crates/check/src/report/measure.rs`), which also pins `Ratio`, `Count` and
the electrical delegation. So every variant has an expected string and no test
writes one down.
**Verified.** Nothing about the text.
`crates/check/tests/report/measurement.rs` covers comparison, dimensional
mismatch and finiteness; every geometric variant is asserted through
`PartialEq` instead, which is what `assert_only_violation` compares.
**Would need.** A table of one expected string per variant, plus one assertion
that no grid factor is applied here. The two writers that *do* apply one —
`export::json::write_report` and `cli::format::write_violations`, both emitting
`nm` and `nm^2` — are covered separately, and nothing compares them against
each other; see the `cli` entry below.

### `Violations::sort_canonical`'s ordering of the second shape slot — report

**Checks.** Where a one-shape row (`shape_b: None`) sorts against a two-shape
row that agrees with it on rule, layer, `at.y`, `at.x` and `shape_a`.
**Missing.** Nothing structural. The doc now names the answer — `None` sorts
before `Some`, Rust's derived `Option` order
(`crates/check/src/report/violation.rs`) — and no test asserts it.
`sort_canonical_orders_by_rule_then_layer_then_y_then_x_then_shapes` builds its
expected order from `ordered_corpus()`, whose every row carries
`Some(shape_b)`, so the one-shape case never appears in an ordering assertion.
**Verified.** Totality over the field, not placement:
`sort_canonical_gives_one_byte_sequence_whatever_order_the_rows_arrived_in` runs
a corpus in which every two-shape row has a one-shape twin, over many shuffles,
so the rows land in the same place every time. Which place is untested.
**Would need.** One `None`-bearing row in `ordered_corpus()`, placed where the
doc says it belongs.

---

## drc

### `antenna` and `antenna_car` — RETIRED, the rules are deleted — drc

`drc` implemented the antenna family a second time, under `erc`'s deck kind
names — one deck row spelled `antenna` was filed by both `from_deck`s and ran
twice. `crates/check/src/drc/rules/antenna.rs` and its five tests
(`crates/check/tests/drc/antenna_rules.rs`) are deleted; `erc` owns the family,
and the two `KINDS` arrays are now disjoint. What is and is not verified about
an antenna ratio is entirely under `## erc` below.

One thing is worth carrying forward. `gate_areas_into` was a **tested**
transform — three transistors, two of them on
one net, coming back as two rows ascending by net with the shared net carrying
the sum, both buffers cleared even when pre-filled — and the test went with the
file, because the transform it covered no longer exists. It is recoverable at
`git show 9abb3e2:crates/drc/tests/antenna_rules.rs` and is the test to restore
when `erc` gains a device-derived gate.

### `multi_patterning` — `Coloring::Exhausted` — drc

**Checks.** That a colouring search which runs out of budget records
`Outcome::Refused` on the rule row, and never a clean result.
**Missing.** `COLOR_SEARCH_BUDGET` is a crate constant rather than a parameter
of `color_into` — deliberately, so a caller cannot raise it until the answer
comes out clean. The consequence is that no test can construct an input
guaranteed to exhaust it: whether a given hard instance runs past 2²⁰ search
steps is a property of the search strategy, not of the rule. A test asserting
`Exhausted` on a heuristically hard graph would be asserting on the
implementation's speed rather than on its correctness, and would flip verdict on
any future ordering change.
**Verified.** `Coloring::Infeasible` is definitive: a triangle over two masks is
uncolourable by construction, the buffer comes back empty, and the same graph
over three masks is `Complete`. The reported node is asserted stable across two
runs. The `Exhausted` arm is covered only by the law that survives it — a graph
containing a four-clique is never reported three-colourable, whichever of the
two non-`Complete` verdicts comes back, and leaves no partial colouring in the
buffer.
**Would need.** A budget parameter on a test-visible entry point, or a
documented worst-case instance family the search is committed to exhausting on.
Either turns the assertion from a guess about runtime into a
construct-from-answer.

### `RuleSet::from_deck` and the whole `DrcError` family — drc

**Checks.** Filing every deck rule into the table for its kind, and rejecting
rather than skipping an unknown kind, a missing or mistyped parameter, the wrong
layer count, a non-positive limit, a duplicate rule id, or an angle no integer
vector expresses.
**Missing.** Nothing structural: `ingest::parse_deck` and `LayerTable::build`
make a `Deck` constructible from a string, so `drc`'s twenty-six-way load-time
dispatcher and all seven `DrcError` variants are reachable. Nothing in
`crates/check/tests/drc/` calls `from_deck` at all — the word does not appear
there — so the load-time half of the crate has no test of its own. This is the
larger half: `from_deck` is where fail-closed is enforced, and a deck with one
silently ignored rule is the exact failure the crate is built against.
**Verified.** The run-time dispatcher, which is what `from_deck` feeds: a
`RuleSet` with one row in each of the twenty-six tables produces twenty-six run
rows, one per id, nothing repeated and nothing missing. Separately,
`Direction::from_degrees` is tested exhaustively over two full turns, so the
decision behind `DrcError::UnrepresentableAngle` is definitive even though the
error it raises is not.
**Would need.** Seven short decks, one defect each, asserting the exact error;
plus one well-formed deck asserted to file every row into the table for its
kind.

### `Scratch` — the no-allocation-per-row claim — drc

**Checks.** That nothing in the twenty-six transforms allocates per row, and
that every buffer a row needs is cleared rather than reallocated.
**Missing.** `docs/TESTING.md` lists allocation and work counters as a seam that
makes the kernel rule an assertion, but `drc` has no such seam: `Scratch`'s
fields are private storage with no accessor, and no `Observe*` trait is defined
in this crate. So the claim in `Scratch`'s doc comment and in `rules/mod.rs`
cannot be observed from any test, inside the crate or out.
**Verified.** The behavioural consequence, not the mechanism: a run against a
`Scratch` that has already been used reaches the same verdict as a run against a
fresh one, and so does a run after `Scratch::shrink`. That catches a transform
reading what its predecessor left behind, which is the correctness failure. It
does not catch a transform that allocates.
**Would need.** An allocation counter behind the gate constant, wired through a
private `*_observed` entry point in this crate, the way `geom::index` and
`geom::prefilter` do it. Then "nothing allocates per iteration" becomes an
assertion instead of a comment.

### Violation coordinates the rule doc comments leave open — drc

**Checks.** Where `Violation::at` points for four of the twenty-six rules.
**Missing.** Most of the crate fixes the point exactly — `check_min_spacing`
says "the midpoint of the closest approach", `check_off_grid` says "at that
vertex" — and those are assertable to the unit. Four are not:

- `check_min_enclosed_area` says "a vertex of the hole ring" without saying
  which of the four.
- `check_asymmetric_enclosure` states only that it shares
  `check_min_enclosure`'s *pairing*, and never restates its own coordinate.
- `check_multi_patterning` says "at the shape named by `Coloring::Infeasible`",
  which names a polygon and not a point on it, and names no measurement at all —
  so neither `at` nor `measured` has a derivable expected value.
- `check_min_area` and `check_cheesing` say "a point inside it", which is a
  containment claim rather than a coordinate.

All four are now covered by a crate-wide convention — `at` is the midpoint of
the thing measured, stated once at `crates/check/src/drc/rules/mod.rs`, with
`check_off_grid` and `check_angle` named as the deliberate vertex exceptions —
so each has a single expected coordinate. The tests were written against the
weaker per-rule claims and have not been tightened onto it.
**Verified.** Every one of the four to the strongest claim its *old* doc comment
made: the hole case against the set of four hole vertices, the asymmetric case
against its sibling's convention, the colouring case against "one row, naming
one shape, marked somewhere on one of the three in the cycle", and the area
cases against the figure's own bounding box. All the other columns — rule,
layer, severity, measurement and limit — are asserted exactly throughout.
**Would need.** Each of those four set-membership assertions replaced by an
equality against the midpoint the convention names.

### Nothing stands where the deleted antenna rules stood — drc, erc

**Checks.** That a deck row spelled `antenna` reaches `erc` and is not silently
dropped by `drc`.
**Missing.** Not an oracle gap — the test that would catch a regression went out
with the module it covered. `drc`'s copy of the antenna family was deleted
because `"antenna"` was in two `KINDS` lists with two incompatible schemas, and
both `from_deck`s now skip a row outside their own vocabulary. Skipping is the
right behaviour and it is also what a lost rule looks like.
**Verified.** That a kind in *neither* vocabulary is refused
(`tests/engine/checks.rs`), and that one deck may hold a DRC rule and an
ERC rule. Neither says where an `antenna` row ends up.
**Would need.** A deck with one `antenna` row, run with both stages selected,
asserting exactly one `RuleRun` for it and that it is `erc`'s.

### Two `unsafe` inductions hold only through an unstated aliasing of `n` — drc, erc

**Checks.** The bulk-compact loops that size a slice from a length computed
above them.
**Missing.** No assertion can see the dependency. Both sites are sound today and
neither states why at the source:

- `crates/check/src/drc/rules/grid.rs` takes `n` from the *first* operand of a
  `zip` (`let verts = xs.len()`, `let interior = tail.len()`), so `zip`'s
  truncation can only shorten the run. Reading `ys.len()` or `head.len()`
  instead is undefined behaviour with no compile error and no failing test.
- `crates/check/src/erc/power.rs` has two sites satisfying the capacity
  precondition through `Vec::new()` freshness rather than an explicit
  `clear()`. A `push` inserted above either makes `spare_capacity_mut()[..n]`
  panic rather than corrupt, so it fails safe — but it fails, and nothing
  states the dependency at the site.

**Verified.** The `debug_assert!(w <= i)` in every compact, which catches a
doubled cursor. It does not catch a slice sized from the wrong operand, because
the slice is what the assert is measured against.
**Would need.** A comment naming the aliasing at each site, and — for the `zip`
pair — a fixture with operands of deliberately unequal length.

---

## erc

### `power::extract_into` and `power::extract_nets_into` — erc

**Checks.** Layout plus a process stack turned into resistive networks: the
supply grid the four solve-reading rules share, and the per-net network
`p2p_resistance` probes.
**Missing.** The doc comment states the model — "a polygon becomes a chain of
resistors along its long bounding-box axis, tapped wherever something connects
to it", segment resistance being sheet resistance times a length-to-width ratio
— but not enough of it to write down an answer. It does not say which node a via
cut contributes, where the sheet resistance of a cut layer comes from (the only
via column is `EdgeKind::Via { cuts }`, and `ProcessStack` has one
`sheet_res_ohm_sq` per layer), nor how a tap that lands on a polygon's end
differs from one that lands in its middle. So "sheet resistance of a known
rectangle" cannot be applied without first guessing three things the interface
leaves open.
**Verified.** Nothing directly. Every electrical test builds its `PowerGrid` or
`NetNetworks` column by column, so the solve, the probe and all four rules over
them are covered against closed forms and laws; the geometry-to-network step in
front of them is not.
**Would need.** Two sentences on `extract_nets_into`: where a tap node sits on
the polygon it taps, and which layer's sheet resistance a via edge uses. Then a
single rectangle with two taps is `R□ × squares` and the test is three lines.

### `RuleSet::from_deck` on the sixteen kinds that take parameters — erc

**Checks.** A deck row turning into a row of the kind's table, with its limits
converted.
**Missing.** The parameter *names* a rule row must carry. `RuleTable::param`
looks a parameter up by interned name and `ErcError::MissingParam` reports one,
but nothing public says whether the antenna limit is spelled `max_ratio`,
`ratio` or `antenna_ratio`. A test would have to invent the spelling and would
then be asserting its own guess.
**Verified.** The three kinds that take no parameter at all — `floating_gate`,
`tie_high_low`, `ir_drop` — are built from a hand-written `Deck` and filed under
the right table; `UnknownKind` and `DuplicateRule` are asserted exactly; and
every name in `KINDS` is checked to be a name `from_deck` recognises, which is
what catches the manifest and the match drifting apart.
**Would need.** The parameter names written into each table's doc comment, where
the columns they fill already are.

### `check_esd_topological` — erc

**Checks.** Every net reaching a bond pad must also reach one of the deck's
clamp models.
**Missing.** No oracle gap — a coverage gap. It needs a store carrying a pad
marker layer *and* a `DeviceTable` whose private `net_start` / `net_device`
reverse index is populated, which only `topology::device::recognise_into`
produces. testgen's `layout_from_netlist` assigns its own dense layer table with
no spare marker layer, so a case has to be hand-drawn with its own
`DeviceRecognition` rather than reused from the generator.
**Verified.** Only that the kind dispatches and records one `RuleRun` with
`Outcome::Ran`, in `dispatch.rs`'s every-kind run.
**Would need.** A hand-built layout with a pad marker layer, device markers and
a `DeviceRecognition` naming two models, one on the clamp list and one not.
Roughly the netlist builder plus one extra layer; a `Floorplan` option for spare
marker layers on `layout_from_netlist` would make it reusable.

### `check_esd_latchup`'s discharge path and guard-ring measurement — erc

**Checks.** Lowest-resistance path from each pad net to a declared supply
through the clamp graph, and each guard ring's width and tap distance.
**Missing.** The path search sums clamp on-resistance with the interconnect
resistance `NetNetworks` gives per net on the way, so an oracle needs a
multi-net `NetNetworks` whose rows correspond to nets an extracted `NetTable`
actually produced — and `NetTable` has no constructor, so the two have to be
tied together through a full layout. The guard-ring half additionally needs ring
geometry with a tap in it.
**Verified.** The intent gate in both directions, and the examined count (pad
nets plus guard rings) on a four-net layout where no device is on the clamp
list, so every pad is unprotected (`intent_gate.rs`). The measurement column is
unasserted.
**Would need.** A layout with two pads, one reaching a clamp of known
on-resistance through a strap of known effective resistance and one reaching
nothing, so the reported path resistance is a series sum the test computes and
the pad with no path is the one reported with an absent measurement.

### `check_em_current_density` and `check_electromigration` — the absolute limit — erc

**Checks.** Branch current per unit conductor width against a per-layer limit in
amps per metre.
**Missing.** Nothing structural. Both transforms take `grid: Grid`
(`crates/check/src/erc/rules/electrical.rs`), and `EmCurrentDensityTable`
carries `max_current_per_cut` so a via edge has a dimensionally correct limit,
so the A/m closed form — branch current over conductor width, both in SI — is
writable. The tests are still the scale-free ones written when it was not.
**Verified.** Scope and monotonicity, which hold under any unit convention:
`examined` counts exactly the edges on limited layers and never reports one on
an unlimited layer; an unreachably small limit reports every limited edge and an
unreachably large one reports none (`electrical_limits.rs`).
**Would need.** One rectangle of stated width carrying a stated current against
a stated A/m limit, with the reported density asserted absolutely.

### `check_electromigration`'s temperature derating — erc

**Checks.** The foundry limit scaled by the Arrhenius factor between the edge's
temperature and `reference_temperature`.
**Missing.** The input exists —
`operating_temperature: Qty<Temperature, {prefix::BASE}>`
(`crates/check/src/erc/rules/electrical.rs`), supplied by
`RunInputs::operating_temperature` — and is deliberately distinct from each
row's `reference_temperature`, because collapsing the two makes the derating
unity, which is fail-open. Nothing asserts the factor itself, so an
implementation that collapsed them would pass every test here. The Blech
exemption is likewise unasserted.
**Verified.** The fail-closed half only: a `reference_temperature` of 0 K or -40
(a Celsius reading pasted in unconverted) must record `Outcome::Refused`, while
358.15 K records `Ran` (`electrical_limits.rs`).
**Would need.** Two runs over one grid at two operating temperatures, with the
ratio of the two derated limits asserted against the Arrhenius factor computed
in the test; plus one edge under the Blech length asserted exempt.

### `AntennaTable::gate` names a layer, not a device — erc

**Checks.** The denominator of every antenna ratio: the oxide area the collected
charge is referred to.
**Missing.** The gate is whatever sits on the layer the deck names. A gate is
really a recognised MOS device — area = the measured `DeviceParam::Area`, net =
the terminal whose role is `TerminalRole::Gate` — which is exact, canonical, and
independent of what the deck calls its layers. `erc::Design` already carries the
`DeviceTable`, so this is a column that points at the wrong thing rather than a
missing input — closing it is a breaking change to `AntennaTable`. Until it is
closed, no test can state an antenna denominator the way `lvs` and the device
recognisers state it, and a deck drawing its gate on an unnamed layer reads
clean.
**Verified.** The layer-named denominator itself, on a one-micrometre-square
gate, at exactly four (`antenna_and_density.rs`). Separately, the per-stage
accumulation: two rule rows over one gate under a two-level stack report exactly
two and exactly twelve, which is the claim a rule measuring the final stack at
every stage fails and a rule collecting only the layer a stage names also fails;
plus the law that a later stage never measures less than an earlier one.
**Would need.** The gate column replaced by a device-derived gate-area table.
Given one, the oracle is construct-from-answer: `gate_areas_into`'s deleted test
restored (`git show 9abb3e2:crates/drc/tests/antenna_rules.rs`), plus a netlist
whose per-net oxide totals the generator picked.

### `AntennaElectricalTable`'s diode credit and bonus — erc

**Checks.** `ratio = collecting_area / gate_area - credit * diode_area - bonus`.
**Missing.** `diode_credit` is a bare `f64` multiplying a diode area, and the
area's unit is not stated: `DbuArea`, square micrometres and the ratio's own
dimensionless scale all give different answers, and nothing in the signature or
doc comment picks one. A closed form cannot be written until it does.
**Verified.** The no-diode case, which reduces to the same division as the
per-stage rule and must report the identical ratio of exactly four
(`antenna_and_density.rs`).
**Would need.** One sentence on `diode_credit` naming the unit of the area it
multiplies, or a `DbuArea`-typed credit.

### `AntennaMeasure::Sidewall` — erc

**Checks.** Vertical etched sidewall area: union perimeter times the layer's
finished thickness.
**Missing.** The union perimeter of a collecting set is not a quantity any other
interface exposes, so there is nothing to state the expected value against
except a hand-computed perimeter — which is available, but the product of a
`Dbu` perimeter and a `Dbu` thickness has no stated unit relative to the gate
area it is divided by, so the ratio's scale is undetermined.
**Verified.** Nothing. Only `AntennaMeasure::Area` is exercised.
**Would need.** A stated convention for perimeter times thickness against gate
area. Both are `DbuArea` if the product is taken widening, and saying so makes a
rectangle's sidewall ratio a closed form.

### `DensityCmpTable`'s `max_neighbour_delta`, `cmp` and `include_partial_windows` — erc

**Checks.** The gradient between adjacent windows, the CMP thickness model, and
whether a window clipped by the die edge is evaluated or skipped.
**Missing.** No oracle gap for the gradient — it is a difference of two
densities this suite already computes — but the window adjacency order is not
stated, so a test cannot say which pair a reported delta belongs to.
`CmpModel`'s `thickness_sensitivity` is "thickness change for a density one full
unit above target", which is a closed form, but nothing states which window's
density the model is evaluated at when several windows exist.
**Verified.** `min_density`, `max_density` and the window count, on an
exactly-half-covered die, on a quartered die, and on generated geometry whose
covered area the generator computed while placing it
(`antenna_and_density.rs`).
**Would need.** A sentence fixing window iteration order (row-major from the
die's lower-left is the obvious one), which makes the neighbour delta a
construct-from-answer test over two adjacent windows of known density.

### `check_reliability`'s lifetime model — erc

**Checks.** Predicted hours from the inverse-power-and-Arrhenius model, against
`required_lifetime_hours`.
**Missing.** Nothing structural. The applied temperature is a parameter
(`crates/check/src/erc/rules/reliability.rs`) and the applied stress is the
worst solved node voltage on the domain, so the predicted lifetime is pure
arithmetic over the row's six coefficients and is computable by a test. No test
computes it: the model itself has never been evaluated independently of the
implementation.
**Verified.** The absolute voltage cap, which the doc comment says is checked
directly rather than through the model: every reported measurement exceeds the
cap and equals one of the grid's own solved node voltages. Plus the two
fail-closed paths — a duty cycle outside `0.0..=1.0` is `Refused` — and the
intent gate.
**Would need.** One row of stated coefficients at a stated temperature and duty
cycle, with the predicted hours computed in the test and compared against
`required_lifetime_hours` on both sides of the boundary.

### `resolve_intent_into` with a non-empty `DesignIntent` — erc, ingest

**Checks.** Re-keying declared supplies and per-net limits from interned names
onto extracted `NetId`s, and collecting the names extraction produced no net for
into `IntentMap::undeclared`.
**Missing.** Nothing structural: `ingest::parse_intent` builds a non-empty
`DesignIntent` from a string, so the re-keying itself — the binary search, the
port lookup, and the undeclared column — is reachable. The `erc` tests still
pass `None` or `Default::default()`, so `IntentMap::undeclared` has no test at
all.
**Verified.** The `None` path completely: `declared` is false, `is_usable` is
false, `supply_count` is zero, and every lookup answers `None` or an all-`None`
`NetLimits`. The populated side is covered only by building `IntentMap`
directly, which skips the transform under test.
**Would need.** One intent naming two supplies and a per-net limit, re-keyed
against an extracted `NetTable`, with one name extraction produced no net for so
`undeclared` is non-empty.

### Two deck columns no `erc` test exercises — erc

**Checks.** `HvDomainTable::isolation` and
`ElectromigrationTable::max_current_per_cut`, both of which change a verdict and
are only ever set to their inert value by the suite.
**Missing.** No oracle gap for either — both are coverage gaps, recorded so
they are not mistaken for something harder. `isolation` is a closed form.
`max_current_per_cut` is dimensionally settled: the column is
`EmCurrentDensityTable`'s own and `check_em_current_density` states the
per-`EdgeKind` compare (`crates/check/src/erc/rules/electrical.rs`). What is
missing for the second is an `EdgeKind::Via` edge, which no test builds.
**Verified.** Each column's inert setting, through the tests that set it:
`isolation: None`, and metal edges only.
**Would need.** One HV domain with isolation declared, and one grid carrying a
via edge with a per-cut limit.

### Electromigration has four independent fail-opens and no test on their product — erc, engine

**Checks.** Whether a current concentration near a pad, at a real sign-off
corner, is reported.
**Missing.** Each of the four is documented at its own site as a deliberate
simplification that errs *open*. Individually each is defensible; nothing checks
what they do together, and every one of them biases the answer the same way.

- `src/engine/run.rs` — the sign-off temperature is hard-coded to 85 °C,
  because nothing in `Inputs` or `RunOptions` carries a corner. A part signed
  off at 125 °C derates less than it should.
- `crates/check/src/erc/rules/electrical.rs` — one temperature for the whole
  run, no self-heating. Its own doc: "it errs *open*".
- `crates/check/src/erc/power.rs` — the current budget spreads uniformly over
  the rail's attach points, so a hot spot reads cooler than it is.
- `crates/check/src/erc/power.rs` — the pad anchor is inferred as the first
  node of the rail's first shape, which under-reports drop near the true pad.

**Verified.** Each simplification is stated at its site. None of the four is
measured, and the composition is measured nowhere.
**Would need.** A construct-from-answer case placing a known current
concentration at a known distance from a known pad at a known corner, asserting
the check fires. The four bias in one direction, so the composed error is the
sum, not a cancellation.

---

## lvs

### `checks`'s six layout-only findings — lvs

**Checks.** `check_floating_nets`, `check_label_conflicts`,
`check_net_seed_conflicts`, `check_device_counts`, `check_parametric` and
`check_topology`: a net with no device on it, two labels resolving to one net, a
connectivity split wearing a naming symptom, device counts per family,
parameters outside the model's declared range, and structural sanity of the
extracted graph.
**Missing.** Five of the six take `&NetTable` and/or `&PortTable`, and both are
now constructible — `NetTable::from_assignment` and `PortTable::build`
(`crates/check/src/topology/net.rs`, `crates/check/src/topology/port.rs`) have
real bodies. The `lvs` tests have not been rewritten onto them, so the only
value any of the five is ever passed is an empty table, which exercises
nothing. `check_topology` is a separate problem: its `Violations` output has no
defined rule id, layer, coordinate or measurement in any doc comment, so a test
cannot state what a correct row looks like.
**Verified.** `check_topology`'s row count and the `RuleRun` beside it —
`crates/check/tests/lvs/checks.rs` covers the clean case and one terminal
naming a net past the end of the net table, both with the rule asserted to have
run and examined a nonzero count. The other five have no test that calls them.
**Would need.** Five construct-from-answer cases over a populated `NetTable` and
`PortTable`; plus, for `check_topology`, a documented `Violation` shape stating
the rule id, which layer a graph-structure finding reports against, and what
`at` means when the finding has no geometry.

### `check_topology`'s violation coordinate — lvs

**Checks.** Where a structural extraction fault is, in the layout.
**Missing.** `Violation` requires an `at: Point`, a `layer: LayerId` and a
`shape_a: PolyId`, and `check_topology`'s only input is a `LayoutGraph`, which
carries no coordinates, no layers and no polygon ids at all. No expected value
for any of those three columns can be derived, so the coordinate-and-measurement
assertion every other rule in the workspace is held to cannot be stated here.
**Verified.** The row count, and the `RuleRun` beside it.
**Would need.** A `DeviceTable` parameter, whose `marker` column is the `PolyId`
of the polygon that recognised the device, plus a `GeometryStore` to turn that
into a point.

### `Inconclusive::AmbiguousTop` and `Inconclusive::MissingSubcircuit` — lvs

**Checks.** The two refusals that come from the reference hierarchy rather than
from refinement: no unique top-level subcircuit to compare against, and a
subcircuit the layout needs that the reference does not define.
**Missing.** No public entry point of the crate can produce either. `compare`
takes two `Graph`s and never sees a `Netlist`. `hierarchical::run` takes a plan
and one graph pair, and `plan` returns `PlanError`, not a `Verdict`.
`AmbiguousTop` would have to come from `Netlist::top`, which nothing in `lvs`
calls; and since no subcircuit instantiates another, `top` is undefined for
every netlist a caller can build.
**Verified.** Nothing. The two `Inconclusive` variants that *are* reachable,
`RoundLimit` and `UnresolvedSymmetry`, are both tested, each paired with a test
showing the same graphs conclude when the cause is removed.
**Would need.** An entry point that takes a `Netlist` and returns a `Verdict`,
so "the reference could not be resolved" has somewhere to be reported from. As
frozen, the two variants are declared but no code path can reach them.

Both are properties of the cell-to-cell edge, which `ingest::Netlist`'s
instance table now carries (`crates/ingest/src/netlist.rs`), so a reference
hierarchy that is ambiguous or incomplete is buildable. What is still absent is
the entry point: no public function of this crate takes a `Netlist` and returns
a `Verdict`, so the two variants remain declared with no code path reaching
them.

### `Discrepancy::DuplicateName` — lvs

**Checks.** Two nets carrying the same declared name.
**Missing.** Nothing structural: the variant carries `side: Side`
(`crates/check/src/lvs/verdict.rs`), matching `UnpairedDevice` and
`UnpairedNet`, and the symmetry law's `flip` helper exchanges it like every
other side-bearing variant. No test constructs a duplicate name.
`crates/check/tests/lvs/compare.rs` mentions the variant once, in a negative
assertion that a fixture carrying no net names must not report one.
**Verified.** Nothing positive. Name comparison itself is covered: the default
options ignore net names, and turning `match_names` on makes a single renamed
net a difference that the report blames on that net.
**Would need.** A fixture with two nets sharing one declared name, asserted to
report `DuplicateName` on the side that carries the duplicate.

### `Discrepancy::ClassImbalance` — lvs

**Checks.** A refinement class holding unequal node counts on the two sides,
described in its own doc comment as the general form the specific variants are
extracted from.
**Missing.** Nothing structural: the emission rule is stated
(`crates/check/src/lvs/verdict.rs`) — the general form only when the class
holds more than one node per side, anything attributable being `UnpairedDevice`
or `UnpairedNet`, and both forms for one class being a double count. No test
builds a class with more than one node per side, so the variant has never been
observed, and neither has the double-count rule that forbids emitting both.
**Verified.** The imbalances themselves, through the specific variants: a
deleted device is reported as `UnpairedDevice` on the side that still has it,
and the three nets it orphaned are reported by index.
**Would need.** One partition holding a class of two-against-three, asserted to
report `ClassImbalance` and *not* to also report the specific variants for its
members.

---

## pex

### `analytical::extract_devices_into` — pex

**Checks.** Parasitics intrinsic to a recognised device: gate capacitance,
junction capacitance, terminal resistance.
**Missing.** The formulae are stated as per-family and "from the device model",
but nothing in the signature carries a device model — only `DeviceTable` and
`ProcessStack`, so closing this needs a breaking change. Which coefficient a MOS gate capacitance is computed from is not
derivable from the interface, so no expected value can be constructed. The doc
comment also does not say whether `out` is cleared or appended to, so even the
buffer contract is unstateable.
**Verified.** Nothing. `DeviceTable` is constructible (public fields,
`Default`), so the fixture exists; the expected answer does not. `extract_into`
is exercised with an empty `DeviceTable` throughout, which covers the wire half
and states nothing about this one.
**Would need.** A documented per-family formula naming which `ProcessStack`
column each term reads, or a device-model parameter on the signature. Either
makes it a closed form immediately.

### `matvec::CpuMatVec` — pex

**Checks.** The host `f64` FMM matvec, and the reference every GPU number is
differentially tested against.
**Missing.** Nothing structural: `CpuMatVec::build(mesh: &Mesh) -> Self`
(`crates/extract/src/field/matvec.rs`) has a real body, matching
`GpuMatVec::upload`, so the operator can be assembled from a `Mesh` and
applied. Only the device-gated tests in `crates/extract/tests/field/gpu.rs`
call it, and those skip on a machine with no Vulkan device — which is every
machine this has run on. The Green's-function laws the host operator satisfies
are asserted nowhere.
**Verified.** `backend()`, which reports the host. The *solver* on top of it is
fully covered against dense operators written out in
`crates/extract/tests/field/solve.rs`: `MatVec` is a public trait and `gmres`
is generic over it, so every law about the solve is stated through a third
adapter rather than through this one.
**Would need.** The operator's own laws stated on the host and run
unconditionally: a panel's influence on itself dominates its row, and the
operator is symmetric for a symmetric kernel.

### `matvec::ObserveMatVec` — pex

**Checks.** Near-field blocks evaluated, far-field expansions, and bytes
transferred inside one matvec.
**Missing.** Nothing structural: the seam has its entry point.
`CpuMatVec::apply_observed<O: ObserveMatVec>` is private with `MatVec::apply`
delegating through `&mut NoObserve` (`crates/extract/src/field/matvec.rs`),
matching the `*_observed` pattern `geom::index`, `geom::connectivity`,
`geom::prefilter` and `lvs::refine` already use. No test installs an adapter
at it, so none of the three counters — near-field blocks, far-field expansions,
bytes transferred — has ever been read.
**Verified.** Nothing. Deliberately not tested rather than tested
tautologically.
**Would need.** A counting adapter over a built `CpuMatVec`, asserting the
near-field block count against the mesh's own CSR and that the far-field count
falls as the expansion order rises.

### `gpu::GpuMatVec` and the CPU/GPU differential — pex

**Checks.** That the `f32` device matvec agrees with `CpuMatVec` inside host
`f64` refinement, within the documented tolerance.
**Missing.** No device on this machine or in CI. `docs/GPU.md` contract item 5
allows exactly this and prescribes the substitute, which is what was written.
**Verified.** The fallback is asserted rather than skipped, and no test is
`#[ignore]`d: `select(n, None)` is `Backend::Cpu` at every size including 2²⁴;
`CpuMatVec::backend()` reports `Cpu`; the device-present branch asserts
selection at and below `Device::crossover()`; and the full field solve asserts
`Accuracy::backend == Backend::Cpu` whenever `Device::find()` returns `None`.
**Would need.** A machine with a Vulkan compute device in the loop. The
differential assertion itself is a two-line addition to the branch that already
exists in `the_device_is_selected_only_above_its_own_measured_crossover`.

### `field::mesh::build_into` and `MeshError` — pex

**Checks.** Panel emission per conductor, the spatial sort that makes panel
order canonical, and the three refusals (`TooManyPanels`, `MissingThickness`,
`EmptyConductor`).
**Missing.** `build_into` takes `stack: &ProcessStack` and `grid: Grid`
(`crates/extract/src/field/mesh.rs`), which is where the z extent,
`Mesh::epsilon` and the metres come from, so the `DbuArea`-to-metres chain now
closes. What is still unstated is the panelisation itself: how many panels a
rectangle becomes at a given `max_edge`, and where their centres sit. So the
tiling law can be asserted on a hand-built `Mesh` but not on the mesh
`build_into` produces. Two of the three refusals stay unreachable:
`MissingThickness` needs a `ProcessStack` with a hole in it, which the
`Vec<f64>` columns cannot express, and `EmptyConductor` is unreachable
regardless — every net a `NetTable` hands back has geometry, and a `NetId` past
the end of the table is an out-of-bounds index rather than the condition the
variant names.
**Verified.** `conductor_area` against a hand-built mesh: a cube of side two
sums to 24 exactly, is unchanged when one face is refined into four quarters,
and reads only the conductor it was asked about (two cubes of different sides,
each reporting its own surface area and both summing to the whole panel column).
That is the tiling law, asserted where the answer is analytic. Every law that
compares one mesh against another of the same solid holds: conductor area is
invariant under halving `max_edge` while the panel count does not fall, the CSR
partitions the panel column exactly, normals are unit length, areas are
positive, `TooManyPanels` refuses rather than truncating, and two builds are
byte-identical.
**Would need.** A stated panelisation rule — edges per `max_edge`, centre
placement — which makes a rectangle's panel set a construct-from-answer; and,
for `MissingThickness`, an `Option` column on `ProcessStack::thickness_nm` so
absent is expressible as against zero.

### The quasi-static ceilings are breached by ordinary input — pex, quasistatic

**Checks.** The accuracy of the field-solved capacitance a report prints.
**Missing.** Two documented approximations, both reached by input this tool
targets rather than by extreme input:

- `crates/extract/src/field/matvec.rs` applies the **square-panel shape factor
  to a rectangle**. Exact at unit aspect ratio; the comment at the site puts
  the self-potential low by 3.5% at 2:1, 12.5% at 4:1, 28% at 10:1 and 64% at
  100:1, and the side face of a thin layer is a sliver by construction.
- `crates/extract/src/field/matvec.rs` uses **no layered-dielectric Green's
  function**; `Mesh::epsilon` gives one permittivity per panel. Every real
  stack is layered.

**Verified.** The capacitance laws in `crates/extract/tests/field/` pass around
both, because a law that holds for any input holds for a wrong one too:
reciprocity, energy positivity, the quadratic scaling of energy, and the
surface-area tiling.
**Would need.** A closed-form test at a stated aspect ratio and a stated stack —
a parallel-plate value the test computes — so the error is measured rather than
asserted to be small.

---

## export

### `gds::write_store` with geometry — export

**Checks.** A `GeometryStore` written as a flat GDSII library, and the
`parse -> write -> parse` identity it gives `ingest`.
**Missing.** Nothing structural: `LayerTable::build` and `stream_of` supply
both halves of the mapping (`crates/ingest/src/deck.rs`). Every test here still
passes `LayerTable::default()` over a zero-layer store, so no polygon has ever
been written to a GDS file by this writer.
**Verified.** The library skeleton over an empty zero-layer store: even-length
record stream for an odd-length cell name, `ingest`'s own `gds::detect`
recognises the output, the cell name reaches the file, reading it back gives a
store with no polygons, and the bytes are identical across two runs, two threads
and a wall-clock second.
**Would need.** A populated `LayerTable` in `tests/export/fixture/`,
after which the geometry half of the round trip is a two-line extension of the
existing test.

### `write_spef` and `write_dspf` field layout — export

**Checks.** SPEF and DSPF as a timing tool parses them.
**Missing.** Neither format's record layout is stated anywhere in the crate, so
no test may assert a key name, section header or field order without inventing
the schema it is meant to check. The same applies to the JSON report's object
keys.
**Verified.** Everything the doc comments commit to: every element value comes
back out as the text `format_f64` produces for it, every net is named the way
`net_name` names it, the two files disagree with each other, the header is the
only place a timestamp appears, and an anonymous net is `WriteError::UnnamedNet`
carrying that net's number.
**Would need.** A documented output schema, or a `gpurify-ingest` SPEF reader,
which would turn the question into the same `parse -> write -> parse` law the
GDS path uses.

### `format_f64`'s precision — export

**Checks.** How many digits of an `f64` reach a report.
**Missing.** Nothing structural. The precision is named — six digits after the
decimal point, never an exponent (`{:.6}`), with the sub-`5e-7` collapse spelt
out (`src/export/json.rs`) — so every value has an expected string.
`tests/export/format_f64.rs` was written before that and still states its
strongest claim as a relative tolerance
(`six_significant_digits_survive_the_round_trip`), which passes under either
reading of "fixed precision".
**Verified.** The consequences: one bit pattern maps to one string however
computed, that string parses back as a finite number, formatting is monotone,
two values a report must distinguish do not collapse, negative zero is stable.
**Would need.** A table of expected strings, including one value that the
decimal-places reading and the significant-figures reading disagree on.

### The two-thread-count clause of the determinism gate — export

**Checks.** That output is byte-identical at two thread counts.
**Missing.** No writer in this crate takes a thread count, a pool, or anything
else a test could set to two values. They are single-pass transcribers over
tables somebody else built in parallel.
**Verified.** The two failure modes the clause exists for, in the form this
crate can state them: every writer is run again on a second thread, which
catches thread-local scratch and a thread id in the output, and again after the
wall clock has crossed a second boundary, which catches a writer that consulted
the clock instead of its `Header`.
**Would need.** Nothing in `export`. The clause belongs to `engine`, where the
thread count is a real parameter.

### Coordinates between `i32::MAX` and `MAX_ABS_DBU` survive no file — export

**Checks.** That a coordinate at the edge of the database-unit domain survives
a write and a read exactly, rather than being truncated.
**Missing.** The domain is `±MAX_ABS_DBU` (`2^40`); a GDSII coordinate is a
signed 32-bit database unit, and `export::gds::write_store` refuses anything
wider (`src/export/gds.rs`) rather than truncating it. So no GDSII file
can carry a coordinate above `i32::MAX`, and the round trip is only assertable
up to there. The three orders of magnitude between the format's ceiling and the
domain's are exercised by nothing that writes bytes.
**Verified.** That the widest coordinate the format holds survives the write and
the read exactly, on both signs, with nothing outside it
(`tests/test_all.rs::coordinates_at_the_domain_edge_survive_the_file_round_trip`),
which is the truncation that test exists to catch. The refusal above `i32::MAX`
is itself asserted.
**Would need.** A writer for a format whose coordinates are wider — OASIS, which
is unimplemented — at which point the `2^40` claim becomes testable through a
file rather than only in memory.

---

## engine

### `pipeline::load_into` — a successful load — engine

**Checks.** Reads deck, layout, optional reference netlist and optional design
intent into one `Loaded`, in an order the doc comment fixes.
**Missing.** `gpurify-testgen` writes no layout file, so no test in this crate
can construct an `Inputs` that loads: only the failure path is reachable from
`tests/engine/`. The deck half is no longer a blocker —
`ingest::parse_deck` has a documented schema — but a load needs a layout on
disk.
**Verified.** The stated ordering: with both deck and layout unreadable the
error must be `LoadError::Deck` or `LoadError::NoGrid` and never
`LoadError::Layout`, since the deck establishes the grid the layout is mapped
against.
**Would need.** A testgen builder that emits a GDS file, so a layout can be
written and loaded back inside this crate's own suite.

### `run_checks`'s DRC and ERC `Ran` path — engine

**Checks.** That a requested check with a deck configuring it executes, reports
`StageStatus::Ran`, and leaves one `RuleRun` per rule with a nonzero `examined`.
**Missing.** Half the vocabulary. Reaching this needs a `Deck` whose
`RuleTable` holds a rule, and `RuleSet::from_deck` resolves both the rule
*kind* and each parameter *name* through `StrTable::get`. The kinds are now
public — `pub const KINDS` in both dispatchers
(`crates/check/src/drc/ruleset.rs`, `crates/check/src/erc/ruleset.rs`) — and
`ingest::parse_deck` has a JSON schema, so a deck whose rules dispatch is
buildable. The parameter *names* per kind are still written down nowhere:
`DrcError::MissingParam { param: &'static str }` says the names exist and are
owned by `drc` without saying what they are, so a test naming `value` is
guessing, and a wrong guess fails as `MissingParam` rather than as the thing
under test.
**Verified.** The `Ran` path through LVS, which needs no deck: a reference
netlist is a `Netlist` with public columns, so it can be built in memory and the
comparison's verdict is decided before the call. Every DRC and ERC status this
crate is tested on is `NotSelected` or `Skipped`.
**Would need.** Each kind's parameter names written into its table's doc
comment, where the columns they fill already are. That also unblocks `drc`'s own
suite, which has the same problem one crate lower.

### `run::run_checks` determinism on a deck that configures rules — engine

**Checks.** Byte-identical `Summary` and `Outputs` across two runs and two
thread counts.
**Missing.** The same missing parameter vocabulary as the entry above. A test
in this crate can build a `Deck` whose kinds dispatch, but not one whose rules
carry limits, so the determinism comparison still runs over a deck that
configures nothing.
**Verified.** The determinism comparison itself, column by column over `Summary`
and all four `Outputs` members, exercised at threads 1 against 4 and at 2
against 2 — on an empty deck, where it can only catch a status assembled in a
nondeterministic order.
**Would need.** Each kind's parameter names stated in its table's doc comment,
or a testgen builder that emits a `RuleTable` for a named kind.

### An LVS violation's rule id is never resolved through a writer — engine

**Checks.** That the rule ids `run_lvs` files on a discrepancy row —
`run::LVS_RULE_IDS` — resolve to text when the report is written.
**Missing.** A fixture, not an interface. A `Verdict::Mismatch` does fail a
run: `run_lvs` turns every `Discrepancy` into one `Severity::Error` row of
`Outputs::violations` (`record_discrepancies`, `src/engine/run.rs`), so a
mismatch is a nonzero `Summary::errors` and `passed()` is false through the
criterion that was already there. But the test that pins it hand-assembles its
`Loaded`, so the string table carries none of `LVS_RULE_IDS` and every row
names the `StrId(u32::MAX)` sentinel. The interning `load_into` does is covered
only by its own `debug_assert`, and nothing renders an LVS violation through
`cli::format` or `export::json` to prove the id resolves rather than printing a
sentinel to a user.
**Verified.**
`tests/engine/checks.rs::an_lvs_mismatch_is_an_error_in_the_report_and_fails_the_run`
— one violation row per discrepancy, every row an error, no warnings, and
`passed() == false`. Attribution is covered too: the verdict names the unpaired
device by side and index.
**Would need.** A fixture pairing a layout on disk with a reference netlist that
disagrees with it, run through a writer, with the rendered rule id asserted to
be the name and not the sentinel.

### ERC skipped for want of design intent — engine

**Checks.** `Inputs::intent` absent disables the intent-dependent ERC rules and
says so.
**Missing.** The doc places this at two levels at once — `StageStatus::Skipped`
names "no design intent for the electrical ERC rules", while
`Outcome::Skipped(SkipReason::NoDesignIntent)` is per rule. Which one
`run_checks` sets when some ERC rules need intent and others do not is not
stated, so a test asserting either would be fixing an open interface.
**Verified.** The equivalent for LVS, where the input is all-or-nothing and the
answer is unambiguous: a `Loaded` with no reference netlist gives
`StageStatus::Skipped`, no `Verdict`, and a failing run.
**Would need.** One sentence fixing whether a partially intent-dependent ERC
stage is `Ran`-with-skipped-rules or `Skipped`. The deck half is no longer a
blocker — a deck may hold both domains' rules, and `run_erc` in practice returns
`StageStatus::Ran` and leaves the gate to the per-rule
`Outcome::Skipped(SkipReason::NoDesignIntent)`, which is a defensible reading of
the doc but is not what the doc says.

### `run_pex` reports `Ran` for nets it did not extract — engine

**Checks.** That a stage reporting `Ran` examined what it was asked to examine.
**Missing.** Not an oracle gap — a fail-open with no assertion on it. A
non-empty `RunOptions::quasistatic_nets` produces the field-solved network for
those nets only (`src/engine/run.rs`); the analytical network for the rest is
not merged, and the `CapMatrix` is dropped for want of a slot on `Outputs`. The
stage still reports `Ran`, so "not asked for" and "no parasitics" are the same
output — against `RuleRun::examined`'s own doc, which is explicit that clean
must mean "this ran and examined N".
**Verified.** That the stage runs and that the selected nets come back. Nothing
about the unselected ones.
**Would need.** A slot on `Outputs` for the matrix, or a documented statement
that a selective PEX run reports only what it solved; then a two-net run with
one net selected, asserting the other is reported as unexamined rather than as
clean.

### `Run::summary` re-runs the pipeline to answer a question about a finished run — engine

**Checks.** The four `StageStatus` fields of a completed run.
**Missing.** `run_checks` returns the `Summary` and `Run::execute` returns
`Outputs`, which carries none of the four statuses. Nothing in `Outputs` can
reconstruct them, and inventing one is the false clean this suite is written
against. So `tests/common/mod.rs` re-runs load, extract and check, and asserts
the re-run agrees with the run it was asked about. That is sound only because
the pipeline's determinism is gated one test up
(`two_runs_at_two_thread_counts_serialise_to_identical_bytes`) — the second
run's summary is the first's, or that gate is red. It is a dependency between
two tests that neither states.
**Verified.** The statuses, of a second identical run.
**Would need.** `Outputs` carrying the `Summary`, or `execute` returning both.
Either is a breaking change, and either removes the coupling.

### Hierarchy provenance is reached by no end-to-end test — engine

**Checks.** That a polygon's hierarchy path and stream properties survive the
whole pipeline, not just the reader.
**Missing.** A fixture. `grep -c Provenance` over `tests/test_all.rs` and
`tests/common/mod.rs` is zero: every end-to-end fixture is flat, so no run
carries a non-`ROOT` `PathId` past `ingest`. The reader half is covered inside
`ingest` (see `Provenance::push` above); the pipeline half is covered nowhere.
**Verified.** Nothing end to end.
**Would need.** A hierarchical GDS fixture — one cell instantiated by another —
with a violation reported on a shape inside the child and its path asserted in
the output.

---

## cli

### `main` — cli

**Checks.** Maps a finished run to a process exit code. `0` only when every
selected check ran and passed.
**Missing.** Nothing structural. The mapping is extracted: `fn
exit_code(&Result<Summary, EngineError>) -> ExitCode`
(`src/bin/gpurify/main.rs`) is a pure function and `main`'s doc delegates the
criterion to it. No test calls it, so nothing checks that an `EngineError`
exits nonzero, or that `Summary::passed` is what is consulted rather than the
violation count.
**Verified.** `gpurify::engine::Summary::passed`, by seven tests in the same
file — clean passes, a skipped rule does not, a skipped or refused stage does
not, `NotSelected` does not block a pass, an error-severity violation fails, a
warning alone does not. The function under this entry is the layer above those.
**Would need.** Two lines: `exit_code(&Ok(clean))` is success,
`exit_code(&Err(_))` is not, and neither agrees with a run that merely found no
violations.

### `Common::strict_layers` — cli

**Checks.** Reject geometry on layers the deck does not describe rather than
dropping it. On by default.
**Missing.** Nothing structural. `Inputs::unknown_layers: UnknownLayers`
(`src/engine/pipeline.rs`) carries it, with a hand-written `Default` of
`Reject` — `UnknownLayers` rather than a `bool`, because it is the exact value
`read_layout` takes, so `to_inputs` is a pass-through rather than a remap. No
test follows the flag past the parser, so nothing shows that
`--no-strict-layers` actually reaches the loader and changes what a run does
with an undeclared layer.
**Verified.** Parsing only: the default is on, `--strict-layers` keeps it on,
`--no-strict-layers` turns it off.
**Would need.** One end-to-end pair over a layout carrying an undeclared layer —
refused under the default, dropped under the flag.

### `--check-determinism` — cli

**Checks.** Run twice, at one thread and at many, and fail if the outputs
differ. The determinism gate, exposed so a human can run it.
**Missing.** The behaviour is two `engine::run` calls and a byte comparison, and
it can only live in `main`. There is no pure function to test and no way to
invoke the run loop without a process.
**Verified.** That the flag parses to `Common::check_determinism` and defaults
off. The comparison it triggers is untested here, though `write_summary` and
`write_violations` each have their own byte-identity test.
**Would need.** A `fn run_twice(inputs, options) -> Result<Outputs, ...>` on
`engine`, or the loop hoisted out of `main` into something callable.

### `format::write_violations`, the non-violation half of `Outputs` — cli

**Checks.** Renders findings from an `&Outputs`, which also carries
`runs: Vec<RuleRun>`, `lvs: Option<Verdict>` and `parasitics`.
**Missing.** All four columns' treatment is now stated
(`src/bin/gpurify/format.rs`): violations and `runs` are rendered, `parasitics`
is not — that is export's SPEF and DSPF — and `lvs` is rendered here because it
is forced, `write_summary(&Summary, &mut String)` taking no `StrTable` and no
`Verdict`. What has no test is the `lvs` arm, and it is the weakest one: the
verdict prints through `Debug` because the renderer never names
`gpurify_check::lvs::Verdict`, so no `match` is writable and every name in a
discrepancy reaches the user as a raw `StrId(7)`. Nothing in the binary renders
a mismatch.
**Verified.** The violation half: canonical row order, every row's coordinate,
measurement and limit surviving to the text, and byte-identical output across
two renderings. The `runs` column is asserted to the extent the binary's own
false-clean test needs it — a clean run must still name the rule that ran and
the shape count it examined.
**Would need.** `Verdict` named in the renderer so the arm can `match` and
resolve names, and one rendering of a mismatch asserted to contain them.

### Nothing compares the two report writers on one violation — cli, export

**Checks.** That `cli::format::write_violations` and
`export::json::write_report` describe the same finding the same way.
**Missing.** Not an oracle gap — a coverage gap between two writers neither of
which owns the pair. Both now convert database units through the run's grid and
both label areas `nm^2` (`src/bin/gpurify/format.rs`,
`src/export/json.rs`), but they compute the factor separately: the CLI
asks `Grid::to_length` for one unit and squares it, the JSON writer divides
`1000` by `dbu_per_um` and squares that. Nothing in the workspace runs one
violation through both and compares. A divergence on any grid that is not 1 nm
per unit would be invisible.
**Verified.** Each writer on its own, including a worked case on a 0.5 nm grid
in `cli`.
**Would need.** One violation, one grid that is not 1 nm per unit, both
writers, and the two numbers asserted equal. A `Grid::to_area` in
`gpurify-geom` would remove the duplication the test is guarding.

---

## workspace

### The tooling gates in `CONVENTIONS.md §7` have not all run — workspace

**Checks.** The two gates that stand outside the test suite.
**Missing.** `cargo clippy` is **not installed on the machine this was
developed on** (Nix cargo, no rustup), so no clippy result claimed anywhere in
these docs is backed by a run. `cargo mutants` has bodies to mutate and a green
suite to mutate them against, which was its stated precondition, and has still
not been run — so the strength of this suite against small wrong changes is
unmeasured, and the entries above that say "nothing asserts this" have not been
confirmed the hard way.
**Verified.** `cargo build --workspace` and `cargo test --workspace
--no-fail-fast`, which is what the entries above are written against.
**Would need.** A toolchain with clippy, and one mutation run. The mutation run
is the more valuable of the two: every entry here is a claim about what a test
would catch, and that is exactly what `cargo mutants` measures.
