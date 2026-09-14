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

Where an entry blames a frozen signature, the signature itself is recorded in
`docs/SIGNATURE_DEFECTS.md`, which is the list to work through before the
Implementation-Phase starts. This file says what is unverified; that one says
what has to change for it to become verifiable.

**An entry ending in `**Resolved.**` had its blocking signature fixed.** The
body above the marker is kept as written — it says what the suite currently
asserts, which is still true and still weaker than it needs to be. The marker
says what changed and where, so the test that was worked around can now be
written. `**Unblocked.**` is the weaker form: another crate's fix made the entry
reachable and nothing here has been rewritten onto it yet.

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

The ledger is not empty. It is also not the list this file predicted before the
Testing-Phase began.

The four combinatorial DRC rules named in the placeholder — `multi_patterning`,
`cheesing`, `redundant_via` and `via_array_spacing` — all landed with
construct-from-answer coverage and are **not** entries here. A violation is
placed deliberately and asserted at its coordinate with its measurement, which
is what the placeholder expected to be straightforward and was. The one piece of
`multi_patterning` that resisted is the search-budget refusal, and it appears
below on its own.

What is here instead is almost entirely a different shape of gap: a frozen type
a test cannot construct, or a doc comment that states two incompatible things
and so has no expected value to assert. Sixty-odd entries, grouped by the crate
that owns the interface, in module-graph order.

---

## units

### `Qty`'s `serde::Serialize` and `serde::Deserialize` — units

**Checks.** A quantity serialises as the bare number, with the dimension and the
prefix carried as schema rather than repeated per row.
**Missing.** `serde` alone provides no format. `gpurify-units` depends on
`serde` but ships no serializer, and its only dev-dependency is
`gpurify-testgen`, which does not re-export one either. New dependencies are out
of scope for this phase, so nothing in reach can turn a `Qty` into bytes and
back.
**Verified.** Nothing. The two impls are the only interfaces in the crate with
no test at all.
**Would need.** `serde_json` as a dev-dependency of `gpurify-units`, or a
re-export of one through `gpurify-testgen`. The test is then one line of law,
`from_str(&to_string(q)) == q`, plus a closed form asserting the emitted text is
the bare number and carries no dimension tag.

**Resolved.** `serde_json` is already a dev-dependency of `gpurify-units`, so
the round-trip law and the bare-number closed form are both writable now. This
entry was stale, not open.

### `Qty`'s `Debug` and `Display` — units

**Checks.** How a physical quantity prints.
**Missing.** Both are `todo!()`, so `Debug`-formatting a
`Measurement::Voltage`, `Current` or `Resistance` panics. Every assertion helper
in `gpurify-testgen` formats the row it is failing on, so an electrical
assertion that fails in the Testing-Phase panics inside its own failure message
and prints nothing useful.
**Verified.** The geometric variants, which format through derived `Debug`.
**Would need.** Nothing structural — this resolves itself in the
Implementation-Phase. Recorded because until it does, an electrical assertion
failure is unreadable rather than merely red.

**Resolved, in part.** `Display`'s number format is pinned
(`crates/units/src/qty.rs:164-179`): `f64`'s own shortest round-trip decimal,
ASCII `u` for micro, and an out-of-table exponent written on the value. The
unreadable-failure half stands until the bodies exist in Phase 4.

---

## core

### `boolean`'s four transforms on arbitrary operands — core

**Checks.** Exact rectilinear union, intersection, subtraction and offset over
two validated layers.
**Missing.** The output type cannot hold the answer. `ValidatedLayer` stores
ring spans and polygon spans — indices — and `ValidatedLayer::get` takes the
`GeometryStore` as a parameter, so a result whose geometry is *new* has nowhere
to live and no test can read one back. Two rectangles that partially overlap
union into an L that exists in no store. Every law in `boolean`'s own doc
comment is stated over arbitrary operands, and none of them can be asserted that
way.
**Verified.** The configurations whose results *are* expressible as spans over
the input store, in `tests/boolean_laws.rs`: idempotence of a layer against
itself; identical layers, which is total overlap; a contained layer, where the
union is the container and the intersection the contained; and disjoint layers,
where the union is the concatenation. Region equality is asserted as "each
difference is empty and the areas agree", which needs only the empty result to
be expressible, and that is what lets commutativity and `(a − b) ∪ (a ∩ b) == a`
run at all. `offset_into` is verified at zero only.
**Would need.** Somewhere for a boolean to put coordinates: an owned result
type, a `GeometryStoreBuilder` output parameter, or coordinate columns on
`ValidatedLayer`. Any of the three turns every law in the module's doc comment
into a test over generated geometry.

**Resolved.** `ValidatedLayer` owns its coordinates as of the Testing-Phase
(`crates/core/src/view.rs:75-88`), so a result whose geometry is new is
readable and every law is writable over arbitrary operands. `PartialEq` is
derived and documented as structural (`:64-72`). `tests/boolean_laws.rs` is now
narrower than it needs to be rather than as wide as it can be.

### `index`'s adapter seam cannot use `gpurify-testgen` — core

**Checks.** Nothing about the product code. This records why the adapter tests
in `crates/core/src/index.rs` build their geometry by hand.
**Missing.** `candidate_pairs_observed` is private, so its tests must live
inside `gpurify-core`. But `gpurify-testgen` depends on `gpurify-core`, and the
dev-dependency cycle makes Cargo compile a *second* instance of `gpurify-core`
for the generator to link against. Its `LayerId` is then a different type from
the one under test, and nothing from the generator type-checks in a unit test
inside this crate. The integration tests in `crates/core/tests/` are unaffected;
only the private side of a seam is.
**Verified.** The seam's own property — no rejected pair would have passed the
exact predicate — against a deterministic lattice scatter written out in the
test module and fixed arithmetically from a seed. Reproducible, but it is a
second generator and not the one the rest of the suite is calibrated against.
**Would need.** A `gpurify-testgen-core` split holding only the generators that
need nothing above `gpurify-units`, so a crate can dev-depend on it without a
cycle. Every crate that owns a private seam will hit this.

### `GeometryStoreBuilder::finish`'s row order within one layer — core

**Checks.** The order rows take among the other rows of the same layer.
**Missing.** The doc comment promises grouping by layer and the permutation back
to arrival order, but says nothing about stability. A test cannot assert arrival
order within a layer without pinning behaviour the interface never promised, and
asserting it would make a correct unstable implementation look wrong.
**Verified.** That the grouping loses no row and invents none, over four hundred
generated shapes; that the permutation is a bijection carrying every row's layer
and coordinates; and that two builds of the same pushes agree column for column,
with and without `with_capacity`.
**Would need.** One sentence on `finish` saying whether the sort is stable.
Every construct-from-answer test in the workspace that names a shape by position
rather than by handle depends on the answer.

**Resolved.** The sort is stable and a layer's permutation slice is strictly
ascending — `crates/core/src/store.rs:130-136`. "The third shape pushed is
`PolyId(2)`" is a writable assertion.

---

## ingest

### `deck::LayerTable` — ingest

**Checks.** Maps layer names and GDS stream pairs to `LayerId`.
**Missing.** Every field is private and there is no constructor. `read_deck` is
the only producer and it takes a `&Path`, so a `Deck` cannot be built in memory.
This is the single most load-bearing entry in the file: it is what blocks
`drc::RuleSet::from_deck`, `export::gds::write_store` on geometry,
`engine::pipeline::load_into` and every ERC rule-construction path below.
**Verified.** Nothing. `gpurify-testgen` sidesteps it by handing back the deck
*fragments* whose types are constructible — `Connectivity`,
`DeviceRecognition`, `ProcessStack` — which is what the transforms under test
actually take.
**Would need.** A constructor on `LayerTable`, or a `read_deck` variant taking
`&str` and a documented schema so a test can write the deck inline.

**Resolved.** `LayerTable::build(&[(StrId, u16, u16)])` with a real body, and
`stream_of(LayerId) -> (u16, u16)` — `crates/ingest/src/deck.rs:118-146` and
`:108-116`. `by_name` is sorted by `StrId`, so `build` needs no `StrTable`.

### `Provenance::push` — ingest

**Checks.** Records the hierarchy path and stream properties of one polygon.
**Missing.** It takes a `PathId`, and the only producer of one is
`PathTable::intern`, which needs `&mut PathTable`. `Provenance::paths` hands out
a shared reference only, so no caller outside `ingest` can create a non-`ROOT`
path. Hierarchy provenance — and therefore `bind_ports_into` against a labelled
instance — is unreachable from an integration test.
**Verified.** The `ROOT` path, plus the permutation of the hierarchy-path column
in a unit test inside `provenance.rs`, which is the only place the type identity
works out.
**Would need.** `Provenance::intern_path(&mut self, &[StrId]) -> PathId`, or a
`paths_mut`.

**Resolved.** `Provenance::intern_path(&mut self, &[StrId]) -> PathId`, real
body, at `crates/ingest/src/provenance.rs:106-124`. A non-`ROOT` `PathId` is
reachable from outside the crate.

### `export::gds::write_store` and the `parse -> write -> parse` law — ingest, export

**Checks.** That a store written as GDSII and read back is the same store.
**Missing.** Two independent blockers. `LayerTable` exposes no
`LayerId -> (u16, u16)` accessor — only `of_stream`, which runs the other way —
so the writer has no way to map a store row to a GDS stream pair and cannot be
implemented as signed. And `LayerTable` is only constructible inside `ingest`,
where the dev-dependency cycle makes it a different type from the one `export`
links against, so the call does not type-check there either. The law has no
location it can be written in.
**Verified.** `layout::tests::a_library_holding_a_known_layout_reads_back_as_that_exact_store`
keeps the half that was load-bearing: four shapes are stated twice, once as the
store `GeometryStoreBuilder` makes of them and once as the GDSII library the
Calma format specification says holds them, and the reader must turn the second
into the first vertex by vertex. Its oracle is the published format rather than
this workspace's own writer, which is the stronger of the two. Reader
determinism is covered separately.
**Would need.** A `LayerTable::stream_of(LayerId) -> (u16, u16)`, plus either a
public `LayerTable` constructor or a `read_deck` variant taking `&str`, so the
writer can be called from an integration test where the two crates agree on the
type.

**Resolved.** Both halves: `stream_of` gives the writer the direction it needed
and `LayerTable::build` gives an integration test — which has the right type
identity — a way to construct the value. The law has a location now.

### `read_deck`'s validation errors — ingest

**Checks.** `DeckError::OffGrid` for a limit that is not an exact multiple of
the grid, `UnknownLayer` for a rule naming an undeclared layer, and
`MissingParam` / `DuplicateRule`.
**Missing.** `read_deck` is the only producer of a `Deck` and takes a `&Path` to
a file whose schema is documented nowhere. Writing a deck inline would mean
inventing that schema, which is a Definition-Phase decision, not a test.
**Verified.** The io refusal
(`a_deck_that_cannot_be_opened_is_an_error_rather_than_an_empty_deck`), and the
fail-closed lookup underneath the `UnknownLayer` case:
`deck::tests::a_name_the_deck_does_not_declare_resolves_to_no_layer_at_all`
shows an interned but undeclared name resolving to `None` rather than to a fresh
layer. `RuleTable`'s CSR accessors are covered in full, its columns being
public.
**Would need.** A documented deck schema and a `read_deck` variant taking
`&str`. The off-grid case is then one rule and two grids.

**Resolved.** `parse_deck(&str, Grid, &mut StrTable)` with a full JSON schema
and a clause per variant — `crates/ingest/src/deck.rs:301-356`. `OffGrid`,
`UnknownLayer`, `MissingParam` and `DuplicateRule` are each reachable from a
string.

### `DesignIntent` with anything declared — ingest

**Checks.** Supply roles, domain voltages and per-net limits once an intent file
states them.
**Missing.** `DesignIntent` has private fields and no constructor, and
`read_intent` takes a `&Path` to a file whose schema is undocumented. So the
only intent a test can build is the absent one: `is_empty` can be shown true but
never false, and `DomainConflict`, `DomainWithoutSupply` and `BadLimit` are all
unreachable.
**Verified.** Absence, completely.
`an_absent_intent_declares_nothing_and_every_accessor_says_so` checks that
`is_empty` holds and that each accessor answers not-declared rather than a
plausible default, which is what makes six ERC rules report `Skipped` instead of
clean. `limits_are_total_over_every_net_id_even_with_nothing_declared` covers
the empty-column lookup. The io refusal is covered.
**Would need.** A documented intent schema and a `read_intent` variant taking
`&str`, or public columns as `RuleTable` and `Netlist` already have.

**Resolved.** `parse_intent(&str, &mut StrTable)` at
`crates/ingest/src/intent.rs:110-158`, with `supplies` and `limits` as arrays so
a repeated net is expressible and therefore refusable.

### `UnknownLayers::Drop`'s drop count — ingest

**Checks.** The doc comment says dropped rows are reported and never dropped
silently.
**Missing.** `gds::read` and `read_layout` return `Result<Layout, LayoutError>`,
and neither `Layout` nor anything it holds carries a count of dropped rows.
There is nothing in the signature to assert against, so the "never silent" half
of the mode is unobservable.
**Verified.** The geometric half:
`an_undeclared_layer_is_refused_under_reject_and_dropped_under_drop` asserts
that `Drop` keeps exactly the shape on the declared layer and that `Reject`
names the undeclared stream pair, and
`the_two_unknown_layer_settings_agree_when_every_layer_is_declared` asserts the
doc's claim that the two settings are not a correctness switch.
**Would need.** A dropped-row count on `Layout`, or a `RuleRun`-shaped record
the reader emits.

**Resolved.** `Layout::dropped: u32` — `crates/ingest/src/layout.rs:28-38`,
with the variant doc pointing at it (`:73-75`).

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
**Missing.** The mapping from a card to a `Netlist` row is convention-laden in
two places the signatures do not fix. `param` is documented as holding values
"in the netlist's own units", which leaves `w=1u` as either 1e-6 or 1 with no
way to tell; and `DeviceKind` has no subcircuit-instance variant, so how an `X`
card is represented at all is undetermined. A positive-parse test would be
asserting a convention this phase is not entitled to choose.
**Verified.** The fail-closed half, with the line number rather than only the
variant: a `.subckt` defined twice is `Redefined` at the redefining line, a call
to an undefined subcircuit is `UndefinedSubckt` at the call, and a Spectre
`alter` statement is `Unsupported` at its line. `Netlist`'s own CSR accessors
are covered directly, its columns being public.
**Would need.** A stated unit convention for `param`, and a documented
representation for a subcircuit instance. Then a small netlist and its expected
tables is a straightforward construct-from-answer test.

**Resolved.** Both conventions are stated: `param` is SI base units with SPICE
scale suffixes expanded at parse (`crates/ingest/src/netlist.rs:107-116`), and
an `X` card is a row in the new instance table (`:139-173`). The
construct-from-answer test is now three columns of arithmetic.

### `Netlist::top` where a subcircuit is instantiated — ingest

**Checks.** That the top cell is the one nothing else instantiates.
**Missing.** `Netlist` has no representation for a subcircuit instance:
`DeviceKind` is `Mos`, `Bjt`, `Resistor`, `Capacitor`, `Diode`, and nothing
points a device row at a `SubcktId`. So no netlist a test can build contains an
instantiation, and the search `top` is named for has no input that exercises it.
**Verified.** The three cases that do not need one: no subcircuits is no top,
one subcircuit is that subcircuit, and two subcircuits neither of which
instantiates the other is an ambiguity refused rather than resolved by taking
the first or the last.
**Would need.** A device kind or column that names an instantiated `SubcktId`.
The test is then a two-level hierarchy whose top is decided when it is written.

**Resolved.** The instance table — `instance_of` and `instance_subckt` among
five columns at `crates/ingest/src/netlist.rs:139-173` — is the cell-to-cell
edge `top` searches. A two-level hierarchy is buildable.

---

## derived

### `DerivedExpr::Inside` and `DerivedExpr::Outside` — derived

**Checks.** Selecting the shapes of an operand by their relationship to a
region, against an explicit finite universe.
**Missing.** The doc comment states two incompatible things. "Shapes of
`operand` that lie inside `region`" is a whole-shape selection, which needs no
universe at all; the paragraph beneath mandates a universe, which is only
meaningful if the operator clips area. A shape straddling the region boundary is
returned whole under the first reading and cut under the second, and nothing in
the frozen interface decides which.
**Verified.** The partition law — `Union(Inside, Outside) == operand` with
`Intersection(Inside, Outside)` empty — over a fixture where every operand shape
lies wholly inside the region or wholly clear of it. Both readings agree exactly
there, so the test measures the partition rather than the interpretation.
**Would need.** A decision, then a construct-from-answer case with one shape
deliberately straddling the region edge and the expected area written down. The
decision is a Definition-Phase one; the test is ten lines once it exists.

**Resolved.** The area/clipping reading, decided on evidence rather than
preference at `crates/derived/src/expr.rs:37-66`: `Inside` is `Intersection`
under the deck's name, `Outside` is `(operand ∩ universe) − region`.

### `DerivedExpr::Outside` with a universe that does not contain its operand — derived

**Checks.** Nothing states what happens when the universe is smaller than the
operand.
**Missing.** Not specified anywhere. Under the clipping reading the result is
silently truncated, which is fail-open and is the class of surprise the explicit
universe was introduced to remove; under the selection reading the universe is
inert and the argument is dead weight.
**Verified.** Only the case where the universe contains everything with four
thousand units of margin, which is the configuration De Morgan and the partition
law are stated in.
**Would need.** Either a documented truncation rule and a construct-from-answer
case measuring the truncated area, or a typed error, at which point the test is
a `matches!` on the variant.

**Resolved, and worth a second opinion.** Documented as deliberate truncation
rather than an error at `crates/derived/src/expr.rs:60-65`, on the ground that
the universe is the extent the deck declared. Truncation loses area, which is
fail-open for any rule consuming the layer.

### `Evaluator::plan`'s evaluation order — derived

**Checks.** Ordering the deck's named definitions so every dependency is
evaluated before the definition naming it.
**Missing.** Two things at once. The order is invisible through the public
interface — `get` takes a name and `Evaluator`'s columns are private — so
`tests/plan.rs` can only assert acceptance, rejection, and that every accepted
definition has a result afterwards. Separately, the field comment on
`Evaluator::name` asks for two orders at once: "names in evaluation order, so a
lookup is a binary search" holds only when the topological order happens to be
ascending by `StrId`, which no deck guarantees. A diamond whose topological
order is the reverse of its name order is the counterexample, and it is the
fixture the unit tests use.
**Verified.** Topological ordering, permutation, and name-to-expression pairing,
all against the private columns from a `#[cfg(test)] mod` inside `src/expr.rs`.
Acceptance and cycle rejection publicly.
**Would need.** For the ordering: nothing, the unit tests cover it. For the
field comment: a decision on which of the two orders `name` is in, since `get`
cannot binary-search a topologically ordered column.

### `prefilter::candidates_observed`'s null adapter — derived

**Checks.** That `NoObserve` costs a production build nothing, which is the
condition `docs/TESTING.md` attaches to every test-adapter seam.
**Missing.** This is not a test and cannot be written in the Testing-Phase. The
gate is a disassembly comparison of the `bench` profile against a build with the
seam removed by `cfg`, and both sides are `todo!()` until Phase 4. "It is cheap"
is explicitly not the standard.
**Verified.** The seam's behavioural property is fully instrumented: no rejected
pair overlaps, every overlapping pair survives, `kept` agrees with the emitted
list. The cost of the instrument is not.
**Would need.** The Implementation-Phase check named in `docs/TESTING.md`:
identical instruction sequences in the `bench` profile, run once the loop
exists. The failure mode is the observer parameter blocking inlining, not a
leftover call.

### `Evaluator::evaluate`'s allocation behaviour — derived

**Checks.** The doc comment promises this "allocates once on first call and
never again", which is the whole reason the two scratch buffers are fields
rather than locals.
**Missing.** No allocation-counter adapter exists in this crate. The claim is
invisible in every return value, and nothing in the frozen interface exposes
buffer capacity.
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
a marker-and-terminal intersection. A test would have to invent that convention,
and inventing it here is the Definition-Phase decision the freeze exists to
prevent.
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
**Missing.** The interface does not say which polygons lack a net.
`NetTable::net_of` is total over `PolyId` and `poly_net` is a dense column, so
it is unstated whether a polygon on a non-conductor layer gets a singleton net,
a sentinel, or no row at all. Without that, no test can construct an orphan on
purpose, and one that guessed would be asserting on the guess.
**Verified.** The other variant is: `ConflictingLabels` is constructed
deliberately, on a rail and the stub a via joins to it, and asserted to name
that exact net. The success path and the repeated-same-label boundary are both
covered.
**Would need.** A stated rule on `extract_nets_into` for what happens to a
polygon on a layer absent from `Connectivity::conductors` — either a documented
sentinel `NetId`, or a `NetTable::net_of` returning `Option<NetId>`.

**Resolved.** A non-conductor polygon gets `NetId::NONE`
(`crates/topology/src/net.rs:45`, `:199`), and `bind_ports_into` states that a
label on such a shape is `OrphanLabel` (`crates/topology/src/port.rs:98`). The
variant is constructible.

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
**Missing.** `DeviceRecognition` carries only `LayerId`s for terminals;
`TerminalRole` lives in `topology` and appears in no deck type. So the mapping
is derived from `DeviceKind` plus terminal position, and that convention is
written down nowhere in a frozen signature. The tests here assume the one
`gpurify_testgen::netlist` was built around: Mos terminals in the order Gate,
Source, Drain, Bulk, and a symmetric two-terminal device as `Pin(0)`, `Pin(1)`.
**Verified.** The assumed convention is asserted end to end: roles come back in
recogniser terminal order and are compared element by element against the spec
that emitted the layout. If the implementation picks a different convention the
tests fail loudly rather than silently agreeing.
**Would need.** One sentence on `recognise_into` or on `DeviceKind` fixing the
position-to-role table per family. Until then the convention is defined by the
testgen builder and this test suite, which is a weaker place for it to live.

**Resolved.** The table is on `TerminalRole` itself
(`crates/topology/src/device.rs:25`), so `topology` and `lvs` read one source.
`Diode` is deliberately excluded and named as unresolved at the site: `Pin` is
interchangeable by definition, and giving a diode pins matches one wired
backwards.

---

## report

### `Measurement`'s `Display` — report

**Checks.** How a measured quantity prints in a report: `200 nm`, `1.8 V`,
`12.4 ohm`.
**Missing.** The doc comment says layout units are printed in nanometres
"against the run's grid, which the formatter is given", but the impl is
`fmt(&self, f: &mut Formatter<'_>)` and no `Grid` reaches it. A `Dbu` is a grid
index, not a length, so there is no expected string for `Length` or `Area` to
assert against: the same `Dbu(200)` is 200 nm on one grid and 20 nm on another.
`Ratio` and `Count` have no documented format either, and the three electrical
variants delegate to `Qty`'s `Display`, whose own text is stated in `units` and
tested there.
**Verified.** Nothing. No `Display` assertion is written, because any expected
string would be invented by the test rather than derived from the interface.
Every geometric variant is asserted on through `PartialEq` instead, which is
what `assert_only_violation` compares.
**Would need.** A `Grid` on the formatting path — either a
`fn format(&self, grid: Grid) -> impl Display` alongside the `Display` impl, or
a documented convention that `Measurement`'s `Display` prints raw database units
and the grid is applied by the writer in `export`.

**Resolved.** Resolution B, doc only: `Display` prints raw database units with
a `dbu` / `dbu^2` suffix and the grid is applied by whoever holds one —
`crates/report/src/measure.rs:72-91`, which also pins `Ratio`, `Count` and the
electrical delegation. The conversion is now `export::json::write_report`'s and
`cli::format::write_violations`' job, and neither says which unit it emits.

### `Violations::sort_canonical`'s ordering of the second shape slot — report

**Checks.** Where a one-shape row (`shape_b: None`) sorts against a two-shape
row that agrees with it on rule, layer, `at.y`, `at.x` and `shape_a`.
**Missing.** The doc states the key tuple down to `shape_b` but not how `None`
orders against `Some`. Rust's derived `Option` order puts `None` first; nothing
says the implementation must use it, so a test asserting either answer would be
pinning a decision the interface has not made.
**Verified.**
`sort_canonical_gives_one_byte_sequence_whatever_order_the_rows_arrived_in` runs
a 128-row corpus in which every two-shape row has a one-shape twin, over 32
shuffles, so the key is proven *total* over that field: the rows land in the
same place every time. Which place is untested.
**Would need.** One sentence in the `sort_canonical` doc comment naming which of
the two comes first. Then it is a two-line construct-from-answer test.

**Resolved.** `None` sorts before `Some`, Rust's derived `Option` order —
`crates/report/src/violation.rs:96-99`.

---

## drc

### `antenna` and `antenna_car` — RETIRED, the rules are deleted — drc

`drc` implemented the antenna family a second time, under `erc`'s deck kind
names. `crates/drc/src/rules/antenna.rs` and its five tests
(`crates/drc/tests/antenna_rules.rs`) are deleted; `erc` owns the family. The
ledger for what is and is not verified about an antenna ratio is now entirely
under `## erc`, and what `drc`'s copy had that `erc`'s does not is filed in
`docs/SIGNATURE_DEFECTS.md` under `## the antenna family`.

The one thing worth carrying into this ledger rather than that one:
`gate_areas_into` was a **tested** transform — three transistors, two of them on
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
steps is a property of the search strategy, which is a Phase-4 decision. A test
asserting `Exhausted` on a heuristically hard graph would be asserting on the
implementation's speed, not on its correctness, and would flip verdict on any
future ordering change.
**Verified.** `Coloring::Infeasible` is definitive: a triangle over two masks is
uncolourable by construction, the buffer comes back empty, and the same graph
over three masks is `Complete`. The reported node is asserted stable across two
runs. The `Exhausted` arm is covered only by the law that survives it — a graph
containing a four-clique is never reported three-colourable, whichever of the
two non-`Complete` verdicts comes back, and leaves no partial colouring in the
buffer.
**Would need.** A budget parameter on a test-visible entry point, or a
documented worst-case instance family the Implementation-Phase commits to
exhausting on. Either turns the assertion from a guess about runtime into a
construct-from-answer.

### `RuleSet::from_deck` and the whole `DrcError` family — drc

**Checks.** Filing every deck rule into the table for its kind, and rejecting
rather than skipping an unknown kind, a missing or mistyped parameter, the wrong
layer count, a non-positive limit, a duplicate rule id, or an angle no integer
vector expresses.
**Missing.** It takes a `&Deck`, and `Deck` cannot be built in memory —
`deck::LayerTable` has private fields, no constructor, and `read_deck` is its
only producer, already recorded for `ingest`. So `drc`'s twenty-six-way
load-time dispatcher and all seven `DrcError` variants are unreachable from a
test. This is the `drc`-side cost of that `ingest` defect and it is the larger
half: `from_deck` is where fail-closed is enforced, and a deck with one silently
ignored rule is the exact failure the crate is built against.
**Verified.** The run-time dispatcher, which is what `from_deck` feeds: a
`RuleSet` with one row in each of the twenty-six tables produces twenty-six run
rows, one per id, nothing repeated and nothing missing. Separately,
`Direction::from_degrees` is tested exhaustively over two full turns, so the
decision behind `DrcError::UnrepresentableAngle` is definitive even though the
error it raises is not.
**Would need.** A `read_deck` variant taking `&str` against a documented schema,
or a constructor on `LayerTable`. Either makes all seven error variants
construct-from-answer: write a deck with the defect, assert the exact error.

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
private `*_observed` entry point in this crate, the way `core::index` and
`derived::prefilter` do it. Then "nothing allocates per iteration" becomes an
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

Separately, five rule doc comments and the frozen `testgen::violation` module doc
name *different* points for the same finding. The suite follows testgen, which
claims authority explicitly, and the conflict is listed in
`docs/SIGNATURE_DEFECTS.md`.
**Verified.** Every one of the four to the strongest claim its doc comment
actually makes: the hole case against the set of four hole vertices, the
asymmetric case against its sibling's convention, the colouring case against
"one row, naming one shape, marked somewhere on one of the three in the cycle",
and the area cases against the figure's own bounding box. All the other columns
— rule, layer, severity, measurement and limit — are asserted exactly
throughout.
**Would need.** One clause per rule, in the doc comment where the rest of the
convention already lives. Each turns a set-membership assertion into an
equality.

**Resolved.** All four, plus the five that conflicted with `testgen::violation`
and two more aligned in passing. The crate-wide convention — `at` is the
midpoint of the thing measured — is stated once at
`crates/drc/src/rules/mod.rs:57`, with `check_off_grid` and `check_angle` named
as the deliberate vertex exceptions. Per-rule sites are listed in
`docs/SIGNATURE_DEFECTS.md`.

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
but no frozen signature says whether the antenna limit is spelled `max_ratio`,
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
**Missing.** Definition-Phase defect. `CurrentDensity` is `Current / Length`,
and the only route from `PowerGrid::edge_width` (a `Dbu`) to a `Qty<Length>` is
`Grid::to_length`. Neither transform takes a `Grid`, and neither `Solved` nor
`IntentMap` carries one, so the number cannot be stated in closed form from
outside the crate. The same shape as the `pex` analytical entry below.
**Verified.** Scope and monotonicity, which are scale-free: `examined` counts
exactly the edges on limited layers and never reports one on an unlimited layer;
an unreachably small limit reports every limited edge and an unreachably large
one reports none (`electrical_limits.rs`).
**Would need.** A `Grid` parameter on both transforms, or a documented
convention that `max_density` is stated per database unit of width.

**Resolved.** Both take `grid: Grid` —
`crates/erc/src/rules/electrical.rs:229` and `:276` — and
`EmCurrentDensityTable` gained `max_current_per_cut` (`:94`) so a via edge has a
dimensionally correct limit. The A/m closed form is writable.

### `check_electromigration`'s temperature derating — erc

**Checks.** The foundry limit scaled by the Arrhenius factor between the edge's
temperature and `reference_temperature`.
**Missing.** Definition-Phase defect. The doc comment says the limit is scaled
"by the Arrhenius factor between the edge's temperature and the row's
reference", but nothing in the signature carries an edge temperature:
`PowerGrid` has no temperature column, `IntentMap` has none, and the table holds
only the reference. The derating is therefore unspecified and untestable as
written.
**Verified.** The fail-closed half only: a `reference_temperature` of 0 K or -40
(a Celsius reading pasted in unconverted) must record `Outcome::Refused`, while
358.15 K records `Ran` (`electrical_limits.rs`). The Blech exemption is likewise
unverified.
**Would need.** A temperature input — a per-edge column on `PowerGrid`, or an
operating-point field on `IntentMap` or `SolveConfig` — plus the `Grid` noted
above.

**Resolved.** `operating_temperature: Qty<Temperature, {prefix::BASE}>` at
`crates/erc/src/rules/electrical.rs:276`, supplied by
`RunInputs::operating_temperature` (`crates/erc/src/ruleset.rs:158`). The
applied point is distinct from each row's `reference_temperature`; collapsing
the two makes the derating unity, which is fail-open.

### `AntennaTable::gate` names a layer, not a device — erc

**Checks.** The denominator of every antenna ratio: the oxide area the collected
charge is referred to.
**Missing.** The gate is whatever sits on the layer the deck names. A gate is
really a recognised MOS device — area = the measured `DeviceParam::Area`, net =
the terminal whose role is `TerminalRole::Gate` — which is exact, canonical, and
independent of what the deck calls its layers. `erc::Design` already carries the
`DeviceTable`, so this is a frozen-column problem and not a missing input;
`docs/SIGNATURE_DEFECTS.md` under `## the antenna family` has the full entry and
the git path to the deleted implementation. Until it is resolved, no test can
state an antenna denominator the way `lvs` and the device recognisers state it,
and a deck drawing its gate on an unnamed layer reads clean.
**Verified.** The layer-named denominator itself, on a one-micrometre-square
gate, at exactly four (`antenna_and_density.rs`). Separately, the per-stage
accumulation: two rule rows over one gate under a two-level stack report exactly
two and exactly twelve, which is the claim a rule measuring the final stack at
every stage fails and a rule collecting only the layer a stage names also fails;
plus the law that a later stage never measures less than an earlier one.
**Would need.** The gate column replaced by a device-derived gate-area table.
Given one, the oracle is construct-from-answer: `gate_areas_into`'s deleted test
restored, plus a netlist whose per-net oxide totals the generator picked.

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
**Missing.** The applied stress is "the worst solved node voltage on each
domain" and the applied temperature is "the edge temperature at that node" — the
same missing temperature input as electromigration. Without it the model cannot
be evaluated independently, so the predicted lifetime has no oracle.
**Verified.** The absolute voltage cap, which the doc comment says is checked
directly rather than through the model: every reported measurement exceeds the
cap and equals one of the grid's own solved node voltages. Plus the two
fail-closed paths — a duty cycle outside `0.0..=1.0` is `Refused` — and the
intent gate.
**Would need.** The temperature input above. With it the model is pure
arithmetic over the row's six coefficients and becomes a closed form.

**Resolved, in part.** The applied temperature is a parameter
(`crates/erc/src/rules/reliability.rs:169`), so the Arrhenius half of the model
has its input. What the lifetime model itself asserts is unchanged.

### `resolve_intent_into` with a non-empty `DesignIntent` — erc, ingest

**Checks.** Re-keying declared supplies and per-net limits from interned names
onto extracted `NetId`s, and collecting the names extraction produced no net for
into `IntentMap::undeclared`.
**Missing.** `DesignIntent`'s fields are all private and its only producer is
`read_intent`, which takes a `&Path`. A test can pass `None` or
`Default::default()` and nothing else, so the re-keying itself — the binary
search, the port lookup, and the undeclared column — is unreachable. The same
shape as the `deck::LayerTable` entry.
**Verified.** The `None` path completely: `declared` is false, `is_usable` is
false, `supply_count` is zero, and every lookup answers `None` or an all-`None`
`NetLimits`. The populated side is covered by building `IntentMap` directly,
which is what every intent-gated rule actually reads.
**Would need.** A constructor or a `read_intent` variant taking `&str` with a
documented schema. Until then `IntentMap::undeclared` has no test at all.

**Unblocked.** `ingest::parse_intent` builds a non-empty `DesignIntent` from a
string (`crates/ingest/src/intent.rs:110-158`). The `erc` tests have not been
rewritten onto it.

### `Scratch::shrink` and `SolveScratch::shrink` — erc

**Checks.** Dropping every scratch buffer's capacity, for a long-lived process
running many decks.
**Missing.** Both return nothing and neither type exposes a capacity, a length
or any other observable. There is no assertion a test can make about either that
would fail if the body were left empty.
**Verified.** Indirectly, that a reused scratch is correct across two solves and
two probes: one scratch solving two grids gives each its own answer, and a
second probe replaces rather than appends to the caller's buffer
(`power_grid_laws.rs`, `effective_resistance_laws.rs`). That is the property
that matters for a verdict; the memory reclamation is not observable.
**Would need.** A capacity accessor, or acceptance that this is an
equivalent-mutant site and an argument recorded at the source.

**Resolved.** Taken as accepted equivalent-mutant sites, per this entry's own
second option, recorded at the source — `crates/erc/src/lib.rs:205-215` and
`crates/erc/src/power.rs:346-349`. Deliberately not resolved with a capacity
accessor.

### Two deck columns no `erc` test exercises — erc

**Checks.** `HvDomainTable::isolation` and
`ElectromigrationTable::max_current_per_cut`, both of which change a verdict and
are only ever set to their inert value by the suite.
**Missing.** Nothing, for the first: isolation is a closed form and this is a
coverage gap rather than an oracle gap, recorded so it is not mistaken for one.
The second needs an `EdgeKind::Via` edge, which no test builds, *and* is
dimensionally unresolved — see the `EmCurrentDensityTable` entry in
`docs/SIGNATURE_DEFECTS.md`.
**Verified.** Each column's inert setting, through the tests that set it:
`isolation: None`, and metal edges only.
**Would need.** Tests for the first. For the second, the signature fix as well.

**Resolved, for the second.** `EmCurrentDensityTable` now carries its own
`max_current_per_cut` (`crates/erc/src/rules/electrical.rs:94`) and
`check_em_current_density` states the per-`EdgeKind` compare (`:200-215`), so
the dimensional question is closed. Building an `EdgeKind::Via` edge is still a
coverage gap. The first column is unchanged.

---

## lvs

### `checks`'s six layout-only findings — lvs

**Checks.** `check_floating_nets`, `check_label_conflicts`,
`check_net_seed_conflicts`, `check_device_counts`, `check_parametric` and
`check_topology`: a net with no device on it, two labels resolving to one net, a
connectivity split wearing a naming symptom, device counts per family,
parameters outside the model's declared range, and structural sanity of the
extracted graph.
**Missing.** Five of the six take `&NetTable` and/or `&PortTable`. Both have
private fields, no constructor and no test-only builder, and their only
producers, `extract_nets_into` and `bind_ports_into`, are `todo!()`. So the only
value a test can pass is `NetTable::default()`, and an empty table exercises
nothing. `check_topology` takes a `LayoutGraph`, which is constructible, but its
`Violations` output has no defined rule id, layer, coordinate or measurement in
any doc comment, so a test cannot state what a correct row looks like.
**Verified.** `check_topology`'s row count and the `RuleRun` beside it —
`tests/checks.rs` covers the clean case and one terminal naming a net past the
end of the net table, both with the rule asserted to have run and examined a
nonzero count. The other five have no test that calls them.
**Would need.** A test-only constructor on `NetTable` and `PortTable`, already
recorded for `topology` and `erc`; plus, for `check_topology`, a documented
`Violation` shape stating the rule id, which layer a graph-structure finding
reports against, and what `at` means when the finding has no geometry.

**Unblocked.** `NetTable::from_assignment` and `PortTable::build`
(`crates/topology/src/net.rs:129`, `crates/topology/src/port.rs:72`) both have
real bodies. The `lvs` tests have not been rewritten onto them.

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

### `graph::from_layout_into` — lvs

**Checks.** Projects a `topology` extraction into the shared matching graph,
which is the layout half of every comparison.
**Missing.** The same wall. It takes `&NetTable`, `&DeviceTable` and
`&PortTable`; two of the three cannot be built outside `topology`.
**Verified.** Nothing directly. The shape it must produce is covered from the
other side: `from_reference_into` is tested row by row against a hand-written
`Netlist`, and the CSR and transpose laws every `Graph` must satisfy are
asserted over generated graphs in `tests/graph.rs`.
**Would need.** The same `NetTable` and `PortTable` constructors. With those,
the strongest oracle available is the round trip through
`testgen::layout_from_netlist`: emit geometry from a stated netlist, extract,
project, and compare against the reference projection of the netlist it came
from.

**Resolved.** The projection is index-preserving and says so —
`crates/lvs/src/graph.rs:94-102`: device row `k` is `DeviceId(k)`, net row `k`
is `NetId(k)`, terminal order preserved, `port_net` ascending.

### `hierarchical::plan` ordering, and `PlanError::Cyclic` — lvs

**Checks.** Pairs layout cells with reference subcircuits and orders them bottom
up, deepest first; refuses a hierarchy containing a cycle.
**Missing.** Two separate problems. The order is unobservable:
`ComparisonPlan`'s `layout_cell`, `ref_subckt` and `depth` are private, there is
no accessor and no `PartialEq`. And a cycle cannot be constructed at all,
because neither input carries a cell-to-cell edge. `Netlist::device_kind` is the
closed `DeviceKind` enum with no subcircuit-instance variant, and `layout_cells`
is a flat `&[StrId]`, so every cell is a leaf, every depth is zero, and
`PlanError::Cyclic` is unreachable from any input a caller can build.
**Verified.** The pairing decision, which is observable through the `Result`:
both cells pairing gives `Ok`, an unpairable layout cell gives
`Err(Unpairable)`, and a reference subcircuit the layout never uses is not an
error. The order is asserted indirectly through the sequence of `CellResult`
rows `run` writes, which is the only place it reaches a caller, and the
determinism of that sequence across two calls into one buffer.
**Would need.** An accessor on `ComparisonPlan`, or `PartialEq` plus a test-only
constructor, to check the order directly. For the cycle, an instance
representation in `Netlist`: either a `DeviceKind::Subckt(SubcktId)` variant or
a separate instance table.

**Resolved, and now actually tested.** `ComparisonPlan`'s three columns are
`pub` and it derives `PartialEq, Eq` (`crates/lvs/src/hierarchical.rs:29-45`),
and `ingest::Netlist`'s instance table supplies the cell-to-cell edge a cycle
needs. Both are now exercised:
`a_child_cell_is_planned_before_the_parent_that_instantiates_it` reads the
`depth` column directly, and
`two_cells_that_instantiate_each_other_are_refused_rather_than_ordered` covers
`PlanError::Cyclic` for the first time. The stale claim that the order is
"asserted indirectly through the sequence of `CellResult` rows" is withdrawn —
and it was worse than indirect: the three tests that read those rows were
**vacuous**, feeding `stacked_pair()` to both sides so `Match` was the right
answer whatever `run` did. All three stayed green with the `compare` call
deleted from `run` outright.

`hierarchical::run` taking one graph pair for a multi-cell plan is still a
design decision and stays open, but it is no longer a *fail-open*: a plan longer
than one cell now reports every row as `Inconclusive::UncomparedCell(cell)`
rather than repeating one comparison's verdict N times and handing N−1 cells a
`Match` they were never entitled to.

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

**Unblocked.** Both are properties of the cell-to-cell edge, which
`ingest::Netlist`'s instance table now carries
(`crates/ingest/src/netlist.rs:139-173`).

### `Discrepancy::DuplicateName` — lvs

**Checks.** Two nets carrying the same declared name.
**Missing.** The variant carries `name` and `nets: (u32, u32)` and no `Side`, so
a duplicate in the layout and a duplicate in the reference produce
indistinguishable rows. A test can build the input but cannot state which side
its expected row is about, and asserting a row that could have come from either
side is exactly the count-only assertion this suite exists to replace.
**Verified.** Nothing. Name comparison itself is covered: the default options
ignore net names, and turning `match_names` on makes a single renamed net a
difference that the report blames on that net.
**Would need.** A `side: Side` field, matching `UnpairedDevice` and
`UnpairedNet`. Alternatively a documented rule that duplicate names are only
ever reported for the layout, in which case the test is three lines.

**Resolved.** `side: Side` — `crates/lvs/src/verdict.rs:57-67`. The symmetry
law's `flip` helper exchanges it like every other side-bearing variant.

### `Discrepancy::ClassImbalance` — lvs

**Checks.** A refinement class holding unequal node counts on the two sides,
described in its own doc comment as the general form the specific variants are
extracted from.
**Missing.** Nothing states when the comparator emits the general form instead
of the specific one. Every imbalance a test can construct is also expressible as
`UnpairedDevice` or `UnpairedNet`, so a test asserting `ClassImbalance` would be
asserting a choice the implementation has not been told to make, and would fail
against a correct implementation that reported the specific variant.
**Verified.** The imbalances themselves, through the specific variants: a
deleted device is reported as `UnpairedDevice` on the side that still has it,
and the three nets it orphaned are reported by index.
**Would need.** A stated rule for when the general form is used, most plausibly
"when the class holds more than one node per side and neither side's members can
be individually attributed".

**Resolved.** The emission rule is stated at `crates/lvs/src/verdict.rs:73-79`:
only when the class holds more than one node per side. Anything attributable is
`UnpairedDevice` or `UnpairedNet`, and both forms for one class is a double
count.

### `compare::interpret` as an independent decision — lvs

**Checks.** Turning a stable partition into discrepancies. Its doc comment says
it is separate from `compare` because it is the part worth a table of cases:
constructed partitions in, expected discrepancy lists out, no refinement
involved.
**Missing.** A partition cannot be constructed. All six of `Partition`'s columns
are private and `Default` is its only constructor, so the only non-empty
partition a test can obtain is one `refine_into` produced. The table of cases
the doc comment describes cannot be written.
**Verified.** The composition, which is what a caller sees: `interpret` run on
the partition `compare` left behind reproduces `compare`'s verdict, and running
it twice on the same partition gives the same answer, so it is a function of the
partition and nothing else. Checked on a matching pair and on a deleted-device
pair.
**Would need.** A test-only constructor on `Partition` taking the two class
vectors, or a builder that states a partition as a list of classes with their
layout and reference members.

**Resolved.** `Partition::from_classes(Vec<ClassId>, Vec<ClassId>)` with a real
body at `crates/lvs/src/refine.rs:143-176`; `class_count` is derived from the
columns so a caller cannot state one that disagrees. `PartialEq` is hand-written
over the three value columns (`:48-63`), the scratch being no part of the value.

---

## pex

### `analytical::ground_capacitance` and `analytical::coupling_capacitance` — pex

**Checks.** Area-plus-fringe capacitance to the plane below, and coupling
between two neighbouring conductors.
**Missing.** Both take deck coefficients per square micrometre and per
micrometre against geometry in `DbuArea` and `Dbu`, with no `Grid` parameter. No
unit chain closes, so neither the parallel-plate value `ε₀ k A / d` nor any
absolute femtofarad number can be stated.
**Verified.** Every law the doc comments claim, all of which are invariant under
whatever unit convention the Implementation-Phase picks: superposition of the
area and fringe terms; linearity in each coefficient separately; the fringe
share of a square plate falling monotonically and reaching within 1e-5 of the
pure area term at a side of 1e9 dbu, which is the parallel-plate limit stated as
a limit; coupling proportional to facing length and to its coefficient, and
strictly decreasing over five separations. `testgen::plate_answer` computes
`ε₀ k A / d` and the deck coefficient realising it, and its own unit chain is
tested; what is untested is the function that would consume them.
**Would need.** A `Grid` parameter on both, or a documented convention that the
coefficients are per database unit. Then `testgen::plate_answer` becomes a
direct oracle and the absolute value is checkable.

**Resolved.** Both take `grid: Grid` — `crates/pex/src/analytical.rs:54-77` and
`:86-102` — each with a Units paragraph closing the aF/µm²-to-`Dbu` chain.
`tests/analytical.rs` now carries the worked value alongside the laws.

### `analytical::extract_devices_into` — pex

**Checks.** Parasitics intrinsic to a recognised device: gate capacitance,
junction capacitance, terminal resistance.
**Missing.** The formulae are stated as per-family and "from the device model",
but nothing in the signature carries a device model — only `DeviceTable` and
`ProcessStack`. Which coefficient a MOS gate capacitance is computed from is not
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
**Missing.** The struct has no fields and no constructor. `Default` is the only
way to obtain one, and nothing in the frozen interface hands it a `Mesh`, so
`dim` can only ever be zero and `apply` has no operator to apply.
**Verified.** `backend()`, which is the only method a default-constructed
adapter can answer honestly. The solver itself is fully covered against dense
operators written out in `tests/solve.rs`: `MatVec` is a public trait and `gmres`
is generic over it, so every law about the solve is stated through a third
adapter rather than through this one.
**Would need.** `CpuMatVec::build(mesh: &Mesh) -> Self`, matching
`GpuMatVec::upload`. With it, the two adapters become comparable and the
Green's-function laws — a panel's influence on itself dominates, the operator is
symmetric for a symmetric kernel — become assertable.

### `matvec::ObserveMatVec` — pex

**Checks.** Near-field blocks evaluated, far-field expansions, and bytes
transferred inside one matvec.
**Missing.** The seam trait exists and `NoObserve` implements it, but no
function anywhere in the workspace takes an `ObserveMatVec`. Every other seam in
the tree has a private `*_observed` entry point (`core::index`,
`core::connectivity`, `derived::prefilter`, `lvs::refine`); this one has none,
so there is nothing to install an adapter at and nothing to observe. A test
could only assert that `NoObserve` implements the trait, which measures the
declaration, not the code.
**Verified.** Nothing. Deliberately not tested rather than tested tautologically.
**Would need.** A private `apply_observed<O: ObserveMatVec>` on `CpuMatVec`, or
the counters threaded through a private entry point in
`quasistatic::extract_into`, matching the `*_observed` pattern the other four
seams already use.

**Resolved.** Private `CpuMatVec::apply_observed<O: ObserveMatVec>` with
`MatVec::apply` delegating through `&mut NoObserve` —
`crates/pex/src/quasistatic/matvec.rs:104-111`, `:127-129`, matching
`core::index::candidate_pairs_into`. `CpuMatVec::build(&Mesh)` was added
alongside (`:80-92`) because the seam is inert without a non-empty matrix; its
body is `todo!()`, the FMM structures being a Phase-4 decision.

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

### `quasistatic::mesh::build_into` and `MeshError` — pex

**Checks.** Panel emission per conductor, the spatial sort that makes panel
order canonical, and the three refusals (`TooManyPanels`, `MissingThickness`,
`EmptyConductor`).
**Missing.** `build_into` takes `MeshOptions`, but the panel geometry it
produces from a conductor is specified nowhere: how many panels a rectangle
becomes at a given `max_edge`, or where their centres sit, is an
Implementation-Phase choice. So the tiling law can be asserted on a `Mesh` but
not on the mesh `build_into` produces, because there is no stated relation
between `DbuArea` geometry and the metres a `Panel::centre` is in without a
`Grid` on the signature. `MissingThickness` needs a `ProcessStack` with a hole
in it, which the `Vec<f64>` columns cannot express. `EmptyConductor` is likewise
unreachable: every net a `NetTable` hands back has geometry, and a `NetId` past
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
**Would need.** A stated panelisation rule (edges per `max_edge`, centre
placement) plus a `Grid` on `build_into`, or an `Option` column in
`ProcessStack` for the missing-thickness path.

**Resolved, in part.** `build_into` takes `stack: &ProcessStack` and
`grid: Grid` (`crates/pex/src/quasistatic/mesh.rs:80-102`), which is where the z
extent, `Mesh::epsilon` and the metres come from.
`MeshError::MissingThickness` stays unreachable until
`ProcessStack::thickness_nm` can express absent as against zero — an `ingest`
edit — and `EmptyConductor` stays unreachable regardless.

---

## export

### `gds::write_store` with geometry — export

**Checks.** A `GeometryStore` written as a flat GDSII library, and the
`parse -> write -> parse` identity it gives `ingest`.
**Missing.** The signature takes a `deck::LayerTable` to map a `LayerId` onto a
GDS layer and datatype, and that type has private fields and no constructor
outside `ingest`. A store holding polygons therefore has no layer table to be
written against.
**Verified.** The library skeleton over an empty zero-layer store: even-length
record stream for an odd-length cell name, `ingest`'s own `gds::detect`
recognises the output, the cell name reaches the file, reading it back gives a
store with no polygons, and the bytes are identical across two runs, two threads
and a wall-clock second.
**Would need.** The `LayerTable` constructor already asked for in the `ingest`
entry. Nothing else: the geometry half of the round trip is a two-line extension
of the existing test.

**Resolved.** `LayerTable::build` and `stream_of`
(`crates/ingest/src/deck.rs:118-146`, `:108-116`) supply both halves.

### `write_spef` and `write_dspf` field layout — export

**Checks.** SPEF and DSPF as a timing tool parses them.
**Missing.** Neither format's record layout is stated in the frozen signatures,
so no test may assert a key name, section header or field order without
inventing the schema it is meant to check. The same applies to the JSON report's
object keys.
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
**Missing.** The doc comment says "a fixed precision" without saying how many
digits, or whether they are decimal places or significant figures. The two
readings differ for every value below 1.0, so no test can name the expected text
of one.
**Verified.** The consequences: one bit pattern maps to one string however
computed, that string parses back as a finite number, formatting is monotone,
two values a report must distinguish do not collapse, and six significant digits
survive — stated as a relative tolerance so it fails against either reading of
"fixed".
**Would need.** One sentence naming the digit count, after which the table
becomes a table of expected strings.

**Resolved.** Six digits after the decimal point, never an exponent (`{:.6}`),
with the sub-`5e-7` collapse named — `crates/export/src/json.rs:61`. Decimal
places rather than significant figures, because six significant figures would
round `7654321` to `7654320` and `tests/json_report.rs` searches for that
literal.

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

---

## engine

### `pipeline::load_into` — a successful load — engine

**Checks.** Reads deck, layout, optional reference netlist and optional design
intent into one `Loaded`, in an order the doc comment fixes.
**Missing.** No frozen interface states the deck's schema (already recorded for
`LayerTable`), and `gpurify-testgen` writes no layout file. So no test can
construct an `Inputs` that loads. Only the failure path is reachable.
**Verified.** The stated ordering: with both deck and layout unreadable the
error must be `LoadError::Deck` or `LoadError::NoGrid` and never
`LoadError::Layout`, since the deck establishes the grid the layout is mapped
against.
**Would need.** A documented deck schema (or a `read_deck` variant taking
`&str`) plus a testgen builder that emits a GDS file, so a layout could be
written and loaded back.

### `pipeline::LoadError::NoGrid` — engine

**Checks.** A deck that declares no grid resolution is rejected rather than
defaulted.
**Missing.** Unreachable through any frozen interface. `read_deck` takes the
`Grid` as an input parameter, nothing in `ingest` reads a grid out of a deck
file or a layout header, and `Inputs` carries no grid — so `load_into` has no
way to discover that the deck declared none.
**Verified.** Nothing. The variant is admitted as an acceptable answer in the
load-ordering test so that test does not prejudge which of the two deck-side
failures fires first.
**Would need.** An `ingest` interface that yields a deck's grid (a peek
function, or a grid field on `Deck` populated before conversion), or a `Grid` on
`Inputs`.

**Resolved.** `Inputs::grid: Option<Grid>` —
`crates/engine/src/pipeline.rs:21-31` — with the ordering consequence stated on
`load_into` (`:113-121`): the grid is read before either file, so an absent one
is `NoGrid` and a present one with two unreadable paths is `Deck`. Both halves
are now separate tests in `tests/pipeline.rs`.

### `run_checks`'s DRC and ERC `Ran` path — engine

**Checks.** That a requested check with a deck configuring it executes, reports
`StageStatus::Ran`, and leaves one `RuleRun` per rule with a nonzero `examined`.
**Missing.** Reaching it needs a `Deck` whose `RuleTable` holds a rule, and
`RuleSet::from_deck` resolves both the rule *kind* and each parameter *name*
through `StrTable::get`. Neither vocabulary appears in a frozen signature:
`DrcError::UnknownKind` and `DrcError::MissingParam { param: &'static str }` say
the names exist and are owned by `drc`, without saying what they are. A test
naming `min_width` and `value` is guessing at two conventions the
Definition-Phase never wrote down, and a guess that is wrong fails as
`MissingParam` rather than as the thing under test.
**Verified.** The `Ran` path through LVS, which needs no deck: a reference
netlist is a `Netlist` with public columns, so it can be built in memory and the
comparison's verdict is decided before the call. Every DRC and ERC status this
crate is tested on is `NotSelected` or `Skipped`.
**Would need.** The rule-kind list and each kind's parameter names written down
as `pub const`s in `drc` and `erc`, or as a documented deck schema. That also
unblocks `drc`'s own suite, which has the same problem one crate lower.

**Unblocked.** `pub const KINDS` in both dispatchers
(`crates/drc/src/ruleset.rs:188`, `crates/erc/src/ruleset.rs:20`) and
`ingest::parse_deck`'s JSON schema (`crates/ingest/src/deck.rs:301-356`) between
them give a test a deck whose rules dispatch. The parameter *names* per kind are
still unwritten; see the `erc` `from_deck` entry.

### `run::run_checks` determinism on a deck that configures rules — engine

**Checks.** Byte-identical `Summary` and `Outputs` across two runs and two
thread counts.
**Missing.** The same missing vocabulary as the entry above. A test can build a
`Deck`, but not one whose rules dispatch to any DRC or ERC table, so every check
runs over zero rules.
**Verified.** The determinism comparison itself, column by column over `Summary`
and all four `Outputs` members, exercised at threads 1 against 4 and at 2
against 2 — on an empty deck, where it can only catch a status assembled in a
nondeterministic order.
**Would need.** The deck's rule-kind names stated in `drc`'s and `erc`'s doc
comments (they are already the dispatcher's contract), or a testgen builder that
emits a `RuleTable` for a named kind.

**Unblocked.** Same two: `KINDS` and `parse_deck`'s schema.

### `run::Summary::rules_clean` — engine

**Checks.** How many rules ran and found nothing — the doc calls it evidence the
run did work.
**Missing.** `Summary::passed`'s criterion does not mention it, so no assertion
can distinguish an implementation that reads it from one that ignores it without
inventing a rule the doc does not state. A run with every stage `Ran`, zero
violations and zero clean rules is left unasserted deliberately.
**Verified.** Only that it is carried through `run_checks` unchanged between two
identical runs.
**Would need.** A sentence in `Summary::passed`'s doc comment saying whether a
run in which no rule was clean can pass. It is the one remaining false-clean
vector at this seam.

**Resolved.** One sentence at `crates/engine/src/run.rs:110-113`: `rules_clean`
is evidence, not criterion. Not a new decision —
`tests/summary.rs::selecting_no_check_at_all_is_a_pass_because_nothing_was_denied`
already fixed it with `rules_clean: 0` and an expected pass.

### `Summary::passed` against an LVS verdict — engine

**Checks.** Whether a run whose extracted netlist disagrees with the reference
is a pass.
**Missing.** `Summary` carries a `StageStatus` per check and counts of
violations, errors and warnings. It has no field for the LVS verdict, and
`Outputs::lvs` is not part of the summary, so `passed()` cannot see a
`Verdict::Mismatch` — a comparison that ran and found two different netlists
reports `StageStatus::Ran`, zero violations, and a pass. Whether that is
intended is a Definition-Phase question, and until it is answered no test can
assert either way without inventing the criterion.
**Verified.** That the mismatch is produced and is attributable: the verdict is
`Mismatch` and names the unpaired device by side and index.
**Would need.** Either an `lvs: Verdict`-derived field on `Summary`, or one
sentence on `passed()` stating that the LVS verdict is deliberately outside the
pass criterion and which caller is expected to read it.

**Resolved — the mapping was taken.** `run_lvs` turns every `Discrepancy` of a
`Verdict::Mismatch` into one `Severity::Error` row of `Outputs::violations`
(`record_discrepancies`, `crates/engine/src/run.rs:691`), so a mismatch is a
nonzero `Summary::errors` and fails the run through the criterion that was
already there. `passed()` is unchanged; its doc
(`crates/engine/src/run.rs:120-132`) now states the criterion rather than the
fail-open. The convention for the fields an LVS discrepancy has no value for —
`layer`, `at`, `shapes` — and the two things it costs are filed under `## engine`
in `docs/SIGNATURE_DEFECTS.md`.

**Verified.**
`crates/engine/tests/checks.rs::an_lvs_mismatch_is_an_error_in_the_report_and_fails_the_run`
— one violation row per discrepancy, every row an error, no warnings, and
`passed() == false`.

**Still thin in one place.** That test's `Loaded` is hand-assembled, so its
string table carries none of `run::LVS_RULE_IDS` and the rows name the
`StrId(u32::MAX)` sentinel. The interning `load_into` does is covered only by its
own `debug_assert`; nothing renders an LVS violation through `cli::format` or
`export::json` to prove the id resolves. That needs a fixture pairing a layout
on disk with a reference netlist that disagrees with it, which the end-to-end
suite does not have.

### ERC skipped for want of design intent — engine

**Checks.** `Inputs::intent` absent disables the intent-dependent ERC rules and
says so.
**Missing.** The doc places this at two levels at once — `StageStatus::Skipped`
names "no design intent for the electrical ERC rules", while
`Outcome::Skipped(SkipReason::NoDesignIntent)` is per rule. Which one
`run_checks` sets when some ERC rules need intent and others do not is not
stated, and with a deck that configures no ERC rules (see above) the case cannot
be reached at all.
**Verified.** The equivalent for LVS, where the input is all-or-nothing and the
answer is unambiguous: a `Loaded` with no reference netlist gives
`StageStatus::Skipped`, no `Verdict`, and a failing run.
**Would need.** A deck carrying ERC rules (blocked as above), plus one sentence
fixing whether a partially intent-dependent ERC stage is `Ran`-with-skipped-rules
or `Skipped`.

**Half unblocked.** The deck half is resolved — a deck may now carry both
domains' rules; see the close-out entry below. The sentence is not: `run_erc`
returns `StageStatus::Ran` and leaves the gate to the per-rule
`Outcome::Skipped(SkipReason::NoDesignIntent)`, which is a defensible reading of
the doc but is still not what the doc says. Reaching it end to end also needs the
fixture work named in that entry.

---

## cli

### `main` — cli

**Checks.** Maps a finished run to a process exit code. `0` only when every
selected check ran and passed.
**Missing.** `fn main() -> ExitCode` takes no arguments and is not callable from
a test. The criterion underneath it is reachable, but the mapping from
`Result<Summary, EngineError>` to a number is not, so nothing checks that an
`EngineError` exits nonzero or that `Summary::passed` is the thing consulted
rather than the violation count.
**Verified.** Seven tests pin `gpurify_engine::Summary::passed`, which its own
doc names as the single place the pass criterion is written: clean passes, a
skipped rule does not, a skipped or refused stage does not, `NotSelected` does
not block a pass, an error-severity violation fails, a warning alone does not.
**Would need.** A pure `fn exit_code(result: &Result<Summary, EngineError>) -> ExitCode`,
or `main` reduced to one line over it. Not extracted here: signatures are
frozen.

**Resolved.** `fn exit_code(&Result<Summary, EngineError>) -> ExitCode` with a
real body at `crates/cli/src/main.rs:36-56` — the resolution this entry names.
`main`'s doc delegates the criterion to it.

### `Common::strict_layers` — cli

**Checks.** Reject geometry on layers the deck does not describe rather than
dropping it. On by default.
**Missing.** Neither `engine::Inputs` nor `engine::RunOptions` has a field for
it, so `to_inputs` has nowhere to put it and no test can assert it reaches the
loader. The flag is parsed and then unrepresentable, which is the fail-open
shape the flag exists to prevent, one layer up.
**Verified.** Parsing only: the default is on, `--strict-layers` keeps it on,
`--no-strict-layers` turns it off.
**Would need.** A `strict_layers: bool` on `Inputs` (it is a load-time decision,
not a check-time one), or a documented statement that the CLI enforces it itself
before calling `engine`.

**Resolved.** `Inputs::unknown_layers: UnknownLayers` at
`crates/engine/src/pipeline.rs:37-47`, with a hand-written `Default` of `Reject`
(`:50-64`). `UnknownLayers` rather than the `bool` this entry names, because it
is the exact value `read_layout` takes, so `to_inputs` is a pass-through rather
than a remap.

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
**Missing.** The doc comment describes only the violation table. Whether the
function is meant to print the per-rule run records, the LVS verdict or the
parasitic network is unstated, so there is no answer to assert against. Guessing
would fix an interface the Definition-Phase deliberately left open.
**Verified.** The violation half: canonical row order, every row's coordinate,
measurement and limit surviving to the text, and byte-identical output across
two renderings. The `runs` column is asserted to the extent the crate's own
false-clean test needs it — a clean run must still name the rule that ran and
the shape count it examined.
**Would need.** A sentence in the doc comment saying what `write_violations`
does with `runs`. If it prints skipped rules, that is the same false-clean
property `write_summary` already has a test for and it should get one too.

**Resolved.** All four columns' treatment is stated at
`crates/cli/src/format.rs:11-34`. `lvs` is rendered here because it is forced:
`write_summary(&Summary, &mut String)` takes no `StrTable` and no `Verdict`, so
this is the only text function that can print a `Discrepancy`. `parasitics` is
not rendered — that is export's SPEF and DSPF.

---

# Implementation-Phase close-out

Everything below was found at the final gate, after all thirteen crates had
been closed out individually. Each is something that ships without a definitive
test, or a test that ships red, with the reason stated rather than papered over.

`cargo clippy` is **not installed on this machine** (Nix cargo, no rustup). No
statement anywhere in this section is backed by a clippy run.

### One deck cannot hold rules of two domains — ingest / drc / erc

**Checks.** `ingest::deck::parse_deck` produces one `RuleTable`. `drc::RuleSet::from_deck`
and `erc::RuleSet::from_deck` each read all of it.
**Missing.** `RuleSpec` has no domain column, and both `from_deck`s are
documented fail-closed on a kind they do not recognise. So each sees the other's
rows and rejects them:

```
drc  = Err("rule supply_droop: unknown rule kind ir_drop")
erc  = Err("rule narrow_metal: unknown rule kind min_width")
```

A deck holding both a DRC rule and an ERC rule cannot be run at all. This was
recorded as open at `crates/ingest/src/deck.rs:420-425` during the
Testing-Phase; the gate confirms it empirically.

**What it costs.** `tests/test_all.rs::a_run_missing_its_optional_inputs_reports_skipped_and_does_not_pass`
**is red and stays red.** It needs one fixture that carries a DRC rule (so the
run has something to do) *and* an intent-gated ERC rule (so `rules_skipped > 0`
when design intent is withheld), which is exactly the deck that cannot be
parsed into two rule sets. It is the false-clean test in its most dangerous
form — a run that could not check everything it was asked to check must not
report a pass — so making it green some other way would be making it pass for
the wrong reason. Every fixture in `tests/common/mod.rs` is therefore DRC-only
with `checks.erc` off, and that restriction is stated in the module doc.

**Would need.** A domain column on `RuleSpec`, or a second table on `Deck`, or
`from_deck` returning which rows it declined. All three are Definition-Phase
signature changes, which Phase 4 may not make.

**Resolved, and none of the three was needed.** The refusal moved instead of the
schema. Both `from_deck`s now skip a row outside their own `KINDS`
(`crates/drc/src/ruleset.rs:338`, `crates/erc/src/ruleset.rs:731`) and the union
check lives at `run_checks` (`crates/engine/src/run.rs:234`, called at `:310`
before `options.checks` is read). A deck holding a DRC rule and an ERC rule is
parsed and run by both — pinned by
`crates/engine/tests/checks.rs::one_deck_may_hold_a_drc_rule_and_an_erc_rule`,
with the refusal itself pinned outside both stage `if`s by
`a_kind_in_neither_domains_vocabulary_is_refused_whatever_was_selected`. Full
account, including the two `debug_assert_eq!`s that had to weaken and the
`"antenna"` name collision the change exposed — since fixed by deleting `drc`'s
copy of the family — in `docs/SIGNATURE_DEFECTS.md` under `## ingest` and
`## the antenna family`.

**Still red, for a second reason, and it is now the only one.**
`a_run_missing_its_optional_inputs_reports_skipped_and_does_not_pass` fails at
`tests/test_all.rs:103` on `rules_skipped > 0`. The blocker above is gone but
`tests/common/mod.rs` was written around it: every deck it emits holds one
`min_width` rule and `build_with` sets `checks.erc = false`
(`tests/common/mod.rs:365`), so no ERC rule is configured and nothing can be
skipped. `run_erc` does record the intent gate — `resolve_intent_into` over an
absent `Loaded::intent` and each electrical rule filing
`Outcome::Skipped(SkipReason::NoDesignIntent)` — so the assertion is right and
the fixture is what has not caught up.

**Would need.** A second rule in `deck_with_rule`'s `"rules"` object naming an
intent-gated ERC kind, and `checks.erc` turned on. Not a three-line change: the
fixture is shared by all eleven tests in the file, so `only_violation`'s
exactly-one count, `deck_rule_ids`, and the byte-comparison in
`two_runs_at_two_thread_counts_serialise_to_identical_bytes` all move with it,
and the module doc at `tests/common/mod.rs:13-20` still states the retired
restriction. It belongs to whoever owns `tests/`.

### The unknown-kind refusal is at `run_checks`, not at load

**Checks.** A deck naming a kind in neither `drc::ruleset::KINDS` nor
`erc::ruleset::KINDS` is refused rather than skipped.
**What changed.** `tests/test_all.rs::a_deck_naming_an_unknown_rule_kind_is_refused_rather_than_skipped`
asserted `LoadError::Deck(DeckError::Malformed(_))` out of `Run::load`. That is
unreachable by construction: `parse_deck` is documented to intern a kind
verbatim and not to interpret it, because both `KINDS` arrays live above
`ingest` in the module graph, and `LoadError` has no variant for it. The
assertion now names `EngineError::Drc(DrcError::UnknownKind { .. })` out of
`Run::execute`, which is where `run_checks`' own doc says the refusal lives.
The property is unchanged — refused, never skipped, and no check runs — only the
stage is corrected.

### The domain-edge round trip is at `i32::MAX`, not at `MAX_ABS_DBU`

**Checks.** `tests/test_all.rs::coordinates_at_the_domain_edge_survive_the_file_round_trip`.
**Missing.** The test's doc says `±MAX_ABS_DBU`. A GDSII coordinate is a signed
32-bit database unit and `export::gds::write_store` refuses anything wider
(`crates/export/src/gds.rs:48-56`) rather than truncating it, so no GDSII file
can carry `2^40` and the fixture cannot write one. `Run::at_domain_edge` draws
`±i32::MAX`, the edge reachable *through a file*, and says so at the site.
**Verified.** That the widest coordinate the format holds survives the write and
the read exactly, present on both signs, with nothing outside it — which is the
truncation this test exists to catch.
**Would need.** Nothing, unless a reader that is not GDSII (OASIS) is ever
implemented, at which point the `2^40` claim becomes testable through it.

### `Run::summary` re-runs the pipeline

**Checks.** The four `StageStatus` fields of a completed run.
**Missing.** `run_checks` returns the `Summary` and `Run::execute` is documented
to return `Outputs`, which carries none of the four statuses. Nothing in
`Outputs` can reconstruct them, and inventing one is the false-clean this suite
is written against. `Run::summary` therefore re-runs load, extract and check,
and asserts the re-run agrees with the run it is being asked about.
**Why it is sound.** The pipeline's determinism is itself gated one test up
(`two_runs_at_two_thread_counts_serialise_to_identical_bytes`), so the second
run's summary is the first's or that gate is red.
**Would need.** `Outputs` carrying the `Summary`, or `execute` returning both —
a Definition-Phase change either way.

### The scale corpus was overlapping its own blocks

**Not a missing test — a generator bug the gate found.** `testgen::scale_corpus`
sized each leaf block from the finger geometry alone
(`block_side = (fingers + 1) * FINGER_PITCH`) while dealing `ceil(nets / blocks)`
bands of `BAND_PITCH` into it. At 1000 polygons over 62 nets that is 16 bands of
1000 into a 3200-wide block, so band 8 of one block landed inside the block
above, a via cut there bridged two combs, and **62 expected nets extracted as
52**. The module doc's "no two nets share a polygon and none of them touch" —
the claim the whole corpus-as-oracle rests on — was false at every size the
benchmark sweeps.

Fixed at `crates/testgen/src/scale.rs` by sizing the block on the taller axis.
Worth recording because of the direction: an over-joining corpus is wrong toward
*fewer* nets, which is the fail-open direction for anything that trusts the
partition, and the three other tests in `tests/bench_all.rs` all passed
throughout.

`tests/bench_all.rs::net_extraction_stays_canonical_and_records_its_cost` also
asserted the wrong convention. `NetId` is documented as the **dense rank** of a
component — `0 .. net_count` ascending by smallest `PolyId` — not the component
label. The test compared `net_of(poly)` against the minimum `PolyId` itself. It
now asserts the two halves the rank actually promises: one id per component, and
the id ordering agreeing with the minimum-`PolyId` ordering.

### `isqrt(1)` is 1, and one test said 0

`crates/core/tests/ops_predicates.rs` swept `isqrt(n² + 1) == n` over `n` from
zero. At `n == 0` that asks for `isqrt(1) == 0`, and `1` is a perfect square
whose exact root is `1` — the sibling test in the same file
(`isqrt_satisfies_its_defining_inequality_for_arbitrary_values`) forbids `r = 0`
at `v = 1`, so the two contradicted each other at exactly one value. The
`n > 0` guard already on the line above now covers both neighbour cases, with a
comment saying why the "above" case needs it and is not an off-by-one.

### Two ERC fixtures contradicted the shapes they were built from

Both were fixture bugs, not rule bugs, and both had been diagnosed during the
per-crate close-out without being fixed:

- `crates/erc/tests/supply_rules.rs`'s `via_connectivity` built a ragged
  `Connectivity` — one `via_cut` row against one `via_connects` row per joined
  layer. `Connectivity` is documented as parallel columns and both
  `build_connectivity` and `extract_nets_into` assert it, so the two supply
  tests panicked in `topology` before reaching any ERC code.
- `crates/erc/tests/topological_rules.rs`'s `contended_output` listed terminals
  as `[Gate, Drain, Source, Bulk]`. `DeviceSpec::terminals` is "the order the
  recogniser will report them" and `topology::role_at` maps position 1 to
  `Source`, so the shared net extracted as the shared *source* and the test was
  unsatisfiable by any implementation. Now in canonical MOS order.

### Stale prose about `todo!()`

`grep -rn 'todo!()' crates` reports 22 hits and every one is the word inside a
comment. Many of those sentences assert that some body "is a frozen signature
over a `todo!()` body until the Implementation-Phase" and explain a workaround
built around that. The workarounds are harmless; the sentences are now false.
Correcting them edits frozen doc comments in eleven files for no behavioural
change, so they were left. A reader should treat any such sentence as
Testing-Phase archaeology.

---

# Unverified after the end-to-end audit

Appended by the audit in `docs/E2E_AUDIT.md`. Everything below is a claim the
suite currently makes no check against, or makes one that cannot fail.

## The end-to-end suite is not blind-authored

`tests/test_all.rs` and `tests/bench_all.rs` are the empty blob `e69de29` at
`8bc3870` **and at `HEAD`**; `tests/common/` and `src/lib.rs` are untracked. All
fifteen tests were written during the Implementation-Phase, against running
bodies. `git grep -c '#[test]' 8bc3870` is 677 against 722 in the tree, so 45
tests in total carry none of the phase's guarantee — sixteen of them added in the
`ponytail:` sweep and blocker run, thirteen as unit tests inside the files their
author had just folded. Not misconduct; the instruction was never to *edit* a
test. But `docs/TESTING.md`'s table reports 678 as one population and it is two.

## The e2e fixture cannot observe four of the five things it checks

`tests/common/mod.rs:262` — one layer, one `min_width` rule, one polygon, one
violation, `dbu_per_um = 1000`. Therefore:

- **layer resolution is untested.** `found.layer == run.met1` is
  `LayerId(0) == LayerId(0)`.
- **grid conversion is untested.** 1 dbu = 1 nm, so every conversion is the
  identity and `Length(300)` holds whether or not `to_dbu` does anything.
- **the canonical sort is untested.** One violation row is byte-identical under
  any ordering; `sort_canonical` appears nowhere in `tests/`.
- **the condemned width formula is untested.** Every fixture is a rectangle, the
  one shape class where `min(bbox.width, bbox.height)` and the correct
  facing-pair scan agree. `crates/drc/src/rules/width.rs`'s module doc exists to
  condemn that formula for L, T and comb shapes.
- **the `Summary` under test is a different run's.** `tests/common/mod.rs:193`
  re-runs `load` / `extract_into` / `run_checks` and returns *that* `Summary`,
  cross-checking only the violation count.

## Nine subsystems reached by no end-to-end test

`grep -c` over `tests/test_all.rs` and `tests/common/mod.rs` returns 0 for
`reference: Some`, `intent: Some`, `Verdict`, `Provenance`, `SkipReason`,
`sort_canonical`, `unknown_layers`, `erc: true`, `pex: true` and
`engine::run::run`. There is no spacing coverage of any kind. The twenty tests
three independent clean-room reconstructions wrote and this suite lacks are
tabulated in `docs/E2E_AUDIT.md` §3; the first three — a spacing violation at a
hand-computed gap midpoint, a provenance permutation surviving `finish`, and
deck names sharing one `StrId` space with layout names — were written by all
three authors independently and are the ones to add first.

## `OffGrid` reports a number that is not off the grid

`tests/common/mod.rs:116` builds the fixture with `"nm": 300.5` on a 1 nm grid.
`crates/ingest/src/deck.rs:620` does `let stated = nm as i64;` and the variant is
`OffGrid(String, i64)` (`:37`), so the message a user sees is *"limit 300 nm is
not an exact multiple of the grid"* — and 300 is an exact multiple of a 1 nm
grid. `tests/test_all.rs:226` wildcards both fields, so no assertion can see it.
The fix is the clean-room construction: an integer nm on a coarse grid
(`dbu_per_um = 200`), with the reported value pinned.

## `"antenna"` was in both `KINDS` arrays — FIXED

One deck row spelled `antenna` was filed by both `from_deck`s, so with
`drc: true, erc: true` it ran twice and filed two `RuleRun` rows under one rule
id. `append_stage`'s `debug_assert_eq!(runs.len(), rule_count)`
(`crates/engine/src/run.rs:490`) counts per stage and did not fire, and
`tests/test_all.rs:243`,
`every_rule_in_the_deck_appears_in_the_run_record_exactly_once`, has a fixture of
one `min_width` rule and so did not either.

Fixed by deleting `drc`'s copy of the family rather than by renaming: the two
were the same physical check implemented twice. `drc::ruleset::KINDS` is 24 names
and the two arrays are disjoint. The test hole is still a hole — the fixture is
still one `min_width` rule — but there is no longer a name for it to catch.

## Electromigration has four independent fail-opens and no test on their product

Each is filed on its own in `docs/SIGNATURE_DEFECTS.md`; the composition is filed
nowhere and checked nowhere.

- `crates/engine/src/run.rs:170` — sign-off temperature hard-coded to 85 °C.
  A part signed off at 125 °C derates less than it should.
- `crates/erc/src/rules/electrical.rs:741` — one temperature for the whole run,
  no self-heating. Its own doc: "it errs *open*".
- `crates/erc/src/power.rs:1091` — the current budget spreads uniformly over the
  rail's attach points, so a hot spot reads cooler than it is.
- `crates/erc/src/power.rs:1302` — the pad anchor is inferred as the first node
  of the rail's first shape, which under-reports drop near the true pad.

What is needed is a construct-from-answer test that places a known current
concentration at a known distance from a known pad at a known corner, and
asserts the check fires. No such test exists.

## The PEX quasi-static ceilings are breached by ordinary input, not extreme input

- `crates/pex/src/quasistatic/matvec.rs:180` — square-panel shape factor on a
  rectangle: "low by 3.5% at 2:1, 12.5% at 4:1, 28% at 10:1 and 64% at 100:1",
  and the side face of a thin layer is a sliver by construction. The comment this
  replaced claimed ~2% at 4:1 and was wrong, which is on record at the site.
- `crates/pex/src/quasistatic/matvec.rs:238` — no layered-dielectric Green's
  function; `Mesh::epsilon` gives one permittivity per panel. Every real stack is
  layered.
- `crates/pex/src/quasistatic.rs:376` — half a micrometre of panel edge, chosen
  here because the frozen `extract_into` takes no `MeshOptions`. Every process
  this tool targets has features far below that.

The capacitance laws in `crates/pex/tests/` pass around all three, because a law
that holds for any input holds for a wrong one too. What is missing is a
closed-form test at a stated aspect ratio and a stated stack.

## `run_pex` reports `Ran` for nets it did not extract

`crates/engine/src/run.rs:867` — a non-empty `quasistatic_nets` produces the
field-solved network for those nets only; the analytical network for the rest is
not merged, and the `CapMatrix` is dropped for want of a slot on `Outputs`. The
stage still reports `Ran`, so "not asked for" and "no parasitics" are the same
output — against `RuleRun::examined`'s frozen doc, which is explicit that clean
must mean "this ran and examined N".

## The CLI and the JSON report disagree about an area

`crates/cli/src/format.rs:155` labels an area `dbu^2`;
`crates/export/src/json.rs:211` squares the grid factor privately and emits
`nm^2`. On any grid that is not 1 nm per unit the same violation reads two
different numbers. No test compares the two writers on one violation. Blocked on
`Grid::to_area` in `gpurify-units`.

`crates/cli/src/format.rs:132` — an LVS verdict prints through `Debug` and stops
at `StrId(7)`, because `gpurify-lvs` is not a dependency of `gpurify-cli` and
`gpurify_engine` re-exports `Outputs` without `Verdict`. Untested; nothing in
`crates/cli/tests` renders a mismatch.

## `Bbox::EMPTY.width()` panics in a debug build

`crates/core/src/bbox.rs:238` calls `Dbu::new_unchecked`, whose
`debug_assert!(in_domain(raw))` (`crates/units/src/dbu.rs:74`) rejects the `2^41`
a domain-spanning box produces. The comment at `:231` says `Bbox::EMPTY.width()`
is already past it. `grep -rn 'EMPTY.width' crates` returns only the comment, so
no test calls it.

Reached independently from the other side: `Dbu::mul_wide` asserts `in_domain` on
both *operands* (`crates/units/src/dbu.rs:98-99`) while `Add`/`Sub` are
documented as legally exceeding `±MAX_ABS_DBU`. `Bbox::area`
(`crates/core/src/bbox.rs:247`) routes around `mul_wide` on purpose and says why,
so the area path is safe and the accessor is not. This is the invariant
`CLAUDE.md` names as load-bearing and it has no test at the boundary.

## `ErcError::UnknownKind`'s doc may be stale, or its check was dropped

Closing the shared-`RuleTable` blocker moved the fail-closed assertion from
`erc` onto `crates/engine/src/run.rs:290`. `crates/erc/src/lib.rs:90` still
carries a doc comment claiming that crate fails closed on it, and
`crates/erc/tests/dispatch.rs`'s
`a_deck_naming_a_kind_this_crate_does_not_implement_is_refused` was renamed to
`..._files_no_row`. Either the doc is stale or the check was lost in the move.
One grep in `engine` settles it; nobody has run it.

## The `ponytail:` grep is not a ledger

`grep -c 'ponytail:'` is 65, of which 5 are prose citing the pass by name rather
than marking anything. It simultaneously **overcounts** the debt — the marker on
`crates/pex/src/quasistatic/solve.rs:348` sits on a refutation, not a shortcut —
and **undercounts** the exemptions: at least fifteen raw bulk loops carry their
justification as plain prose without the token
(`crates/core/src/ops.rs:314`, `:335`; `store.rs:211`, `:217`, `:228`;
`view.rs:340`, `:407`, `:478`; `rects.rs:137`, `:177`, `:185`;
`boolean.rs:781`, `:799`; `connectivity.rs:76`;
`crates/drc/src/rules/via.rs:176`, `:205`; `spacing.rs:487`;
`crates/engine/src/run.rs:779`). The two have never been reconciled, so no grep
over the tree states the bulk-loop rule's true compliance.

## Mutation testing has still not run, and clippy cannot

`cargo mutants` needs bodies and now has them; it is the first thing to do once
`tests/test_all.rs` is green. `cargo clippy` is not installed on this machine
(Nix cargo, no rustup), so `CONVENTIONS.md §7`'s second gate has never been met
and no statement anywhere in these docs is backed by a clippy run.

---

# Added at the final gate

The gate ran `cargo build --workspace`, `cargo test --workspace
--no-fail-fast`, and three greps. Build clean, **728 passed / 0 failed / 1
ignored**. What follows is what the gate could *not* verify.

## The `ponytail:` ledger entries above are stale, and one survivor is unblocked

The two sections above quote 65 markers and 5 prose entries. The tree now
carries **14**, of which 1 is prose (`crates/lvs/src/graph.rs:243`). The
`crates/pex/src/quasistatic/solve.rs` refutation still wears a marker but has
been rewritten to state a real blocker (a `Workspace` field addition), so it is
no longer the overcount that entry describes. The undercount is untouched: the
raw bulk loops carrying prose justifications without the token were never
re-listed after `gpurify_core::bulk` was inlined and deleted, and their line
numbers have all moved. Nobody has re-derived the bulk-loop rule's true
compliance against the current tree.

**WITHDRAWN — `crates/drc/src/lib.rs:130` is blocked after all, and this
section's header is wrong.** The claim below reasoned from the comment's own
"no signature blocks", which the third spend-down pass disproved:
`RuleSet::run(&self, Design, &mut Scratch, &mut Violations, &mut Vec<RuleRun>)`
carries no thread budget and `gpurify_engine::run::run_drc` is not handed
`&RunOptions` (`crates/engine/src/run.rs:531`), so nothing can tell the
dispatcher how many workers to use. Defaulting to `available_parallelism`
instead is worse than not doing it: `crates/cli/src/main.rs` flips
`RunOptions::threads` between the two `--check-determinism` passes precisely to
prove output does not depend on how work was divided, and a self-chosen worker
count would run both passes identically — the gate would compare a run against
itself and report a guarantee it never exercised. `Scratch`'s public surface is
`Default` + `shrink`, so a `with_workers` constructor is itself a widening.
Filed as `## drc, from the ponytail: spend-down pass (second entry)` in
`docs/SIGNATURE_DEFECTS.md`. **Zero survivors are un-actioned shortcuts**; all
11 real markers in the tree are filed or structural, and `CLAUDE.md` carries the
per-site table. The stale original follows:

> **`crates/drc/src/lib.rs:130` is the one survivor that is not blocked.** Its own
> comment says the upgrade path "no signature blocks": one `Scratch` is one
> exclusive borrow, so `RuleSet::run` drives all rules on one core. The stated
> reason it is unspent is that its edit site is `ruleset.rs` rather than that
> file, which is a scope note, not a blocker. It is a live, un-actioned shortcut
> and it is the only one.

## `tests/test_all.rs` and `tests/common/` were rewritten and never re-audited

`docs/E2E_AUDIT.md` §1 and §4 audit a version of these files that no longer
exists. Both are an **empty blob at `HEAD`** — the whole 300-line suite and the
fixture beneath it are uncommitted. The
`a_run_missing_its_optional_inputs_reports_skipped_and_does_not_pass` failure
recorded in `CLAUDE.md` is now green, but nothing has checked *how*: the
fixture, not the test, is what §4 said was wrong, and no audit has confirmed the
fix went into the fixture rather than into the assertion. §1's finding that four
of the five things this suite checks are constants of its fixture has not been
re-tested against the new fixture either.

## Nine of the 728 tests came from workflows this gate did not run

`tests/pdk_decks.rs` (6) and `crates/lvs/tests/terminal_order.rs` (3) are both
untracked and were authored by concurrent runs. The tally reconciles exactly —
714 baseline + 1 (`pex::reduce` compact bound) + 4 (`erc::power` profile and
factorisation) + 6 + 3 = 728 — but the nine carry no audit from this gate and
are not covered by `docs/TEST_AUDIT.md`.

## The DRC antenna deletion has no test standing where the rules stood

`crates/drc/src/rules/antenna.rs` and `crates/drc/tests/antenna_rules.rs` are
both deleted, correctly: `"antenna"` was in two `KINDS` lists with two
incompatible schemas. What is not verified is that a deck row spelled `antenna`
now reaches `erc` and is *not* silently dropped by `drc`. The test that would
have caught a regression here went out with the module.

## Two `unsafe` inductions are sound only through an unstated aliasing of `n`

Re-verified mechanically at all 35 sites and all 35 hold. Two are fragile in a
way no assert or test catches:

- `crates/drc/src/rules/grid.rs:319` (`let verts = xs.len()`) and `:484`
  (`let interior = tail.len()`) take `n` from the *first* operand of a `zip`, so
  `zip`'s truncation can only shorten the run. Reading `ys.len()` /
  `head.len()` instead is UB with no compile error and no failing test.
- `crates/erc/src/power.rs` has two sites satisfying the capacity precondition
  through `Vec::new()` freshness rather than an explicit `clear()`. A `push`
  inserted above either makes `spare_capacity_mut()[..n]` panic rather than
  corrupt, so it fails safe — but it fails, and nothing states the dependency at
  the site.

The `debug_assert!(w <= i)` in every compact catches a doubled cursor. It does
not catch a slice sized from the wrong operand, because the slice is what the
assert is measured against.

## `cargo clippy` still cannot run, and `cargo mutants` still has not

Unchanged, and now the only two gates in `CONVENTIONS.md §7` that remain unmet.
`cargo clippy` is not installed (Nix cargo, no rustup); **no clippy result
anywhere in these docs is backed by a run**, and the claim in `CLAUDE.md` that
the Definition-Phase was "workspace clippy clean" has been withdrawn rather than
re-run. `cargo mutants` has bodies and a green suite, which was the stated
precondition, so it is now the first thing to do.
