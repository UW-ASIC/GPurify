# Definition-Phase defects

Signatures froze at the end of the Definition-Phase. Writing the suite against
them turned up places where the frozen artefact is wrong, self-contradictory, or
cannot express the thing its own doc comment promises.

**Nothing here was edited.** An agent quietly widening a signature to make its
own test easier is the failure mode the freeze exists to prevent, so every one
of these was worked around and written down instead. The workarounds are
recorded in `docs/NEED_TESTING.md`, which says what is consequently unverified;
this file says what has to change for it to become verifiable.

**Resolve these before the Implementation-Phase starts.** Most are one sentence
of doc comment. The ones that are not — a missing constructor, a missing `Grid`
parameter, a missing enum variant — are cheap now and expensive once bodies
exist.

Three of them are load-bearing far beyond the crate that owns them:

- `deck::LayerTable` has no constructor, which blocks `drc::RuleSet::from_deck`,
  `export::gds::write_store` on geometry, `engine::pipeline::load_into` and the
  `parse -> write -> parse` law.
- `NetTable` and `PortTable` have no constructor, which blocks `lvs::checks`
  entirely, both `drc` antenna rules, and the `erc` ESD rules.
- No `Grid` reaches `pex::analytical`, `erc`'s electromigration rules, or
  `report::Measurement`'s `Display`, so every absolute number they compute is
  unstateable.

---

## units

**The 45 nm example contradicts its own arithmetic.** `crates/units/src/lib.rs`
module doc, repeated verbatim in `CLAUDE.md`: "a deck that asks for a 45 nm
limit on a 5 nm grid is an error, not a rounding." 45 nm is exactly nine units
of 5 nm. An implementer taking that sentence literally will reject an on-grid
limit. `tests/grid.rs::an_on_grid_length_converts_exactly` asserts the correct
answer, `Ok(Dbu(9))` at `dbu_per_um = 200`, and
`an_off_grid_length_is_refused_rather_than_rounded` uses 47 nm for the rejection
the sentence was reaching for. Doc text only, no signature edited.

**`Qty`'s `Display` doc gives three examples no single format string
produces.** `1.8 V`, `3.0 aF` and `200 mohm`. `3.0` keeps a trailing zero and
`200` does not, so the value's spelling is unspecified.
`tests/qty.rs::a_quantity_prints_its_value_followed_by_its_prefixed_symbol`
works around it by parsing the numeric head back to an `f64` and asserting only
the prefixed symbol as a literal, which is the part the doc says this impl
exists to write down. Pin the number format and the test tightens for free.

**`Grid::to_dbu` has no documented answer for a non-finite length.** `GridError`
carries `NotOnGrid`, `OutOfRange` and `BadResolution`, and none names a `NaN` or
an infinity. This is a fail-open shape: an implementation checking
`fract() == 0.0` first returns `NotOnGrid` for a `NaN` by accident rather than
by decision. Nothing is asserted about it, because guessing which variant is
correct would freeze a choice the Definition-Phase did not make. `Qty::is_finite`
exists for exactly this and is tested, but no signature routes a length through
it before conversion.

---

## core

**`boolean`'s output parameter cannot represent a boolean result.**
`union_into`, `intersection_into`, `subtraction_into` and `offset_into` all take
`&mut ValidatedLayer`, which holds only ring and polygon spans into a
`GeometryStore`, and `ValidatedLayer::get(&self, store, idx)` takes the store
from the caller. A union of two partially overlapping rectangles produces
coordinates that exist in no store, so the general case of every law in
`boolean`'s doc comment is unwritable. Tests are restricted to the identical,
contained and disjoint configurations whose results are expressible as spans
over the input store.

**`gpurify-testgen` is unusable inside `#[cfg(test)]` modules of
`gpurify-core`.** The dev-dependency cycle (core → testgen → core) makes Cargo
build a second `gpurify-core` instance for testgen, so
`gpurify_testgen::shapes::LayerId` is a distinct type from `crate::ids::LayerId`.
The brief's instruction to use testgen and its instruction to put adapter tests
inside the crate are mutually exclusive as the workspace is laid out. The
adapter tests in `src/index.rs` therefore carry a self-contained deterministic
SplitMix64-hash lattice generator, about thirty lines and no dependency.

**`GeometryStoreBuilder::finish` does not state whether its sort is stable
within a layer.** Several natural construct-from-answer assertions ("the third
shape pushed is `PolyId(2)`") are unwritable as a result; tests route through
`LayoutBuilder` handles or place shapes on distinct layers instead.

**`ValidatedLayer` and `PolygonRef` expose no way to enumerate a result's
polygons other than by index, and `ValidatedLayer` has no `PartialEq`.** Region
comparison goes through areas and per-polygon (bbox, area, hole-count)
fingerprints. Workable, but a boolean that produced the right region with the
wrong polygon decomposition is caught only by the fingerprint determinism test,
not by the law tests.

---

## ingest

**`export::gds::write_store` cannot be implemented as signed.** It takes
`(&GeometryStore, &LayerTable, &str, &mut Vec<u8>)` and has to map each store
row's `LayerId` to a GDS layer/datatype pair, but `LayerTable`'s only stream
accessor is `of_stream(u16, u16) -> Option<LayerId>`, which runs the other way.
There is no `stream_of(LayerId)`. This blocks the round-trip law before the type
identity problem below is even reached.

**The `parse -> write -> parse` law has no location it can be written in.** It
needs a populated `LayerTable`, which only `ingest`'s own `#[cfg(test)]` code
can build (private fields, no constructor, no in-memory producer); but the
`ingest`/`export` dev-dependency cycle means the lib-test build of `ingest` is a
distinct crate instance from the `ingest` that `export` links, so `write_store`
rejects the fixture with
`expected gpurify_ingest::deck::LayerTable, found LayerTable`. An integration
test has the right type identity and cannot construct the value; a unit test can
construct the value and has the wrong type identity. Adding `gpurify-export` as
a dev-dependency, which the plan called for, was already done and does not
resolve it.

**`read_deck(&Path, Grid, &mut StrTable)` has no in-memory form and no
documented file schema**, so `DeckError::OffGrid`, `UnknownLayer`,
`MissingParam` and `DuplicateRule` are all unreachable from a test. The plan's
`Deck` item is unimplementable as stated for that reason.

**`read_intent(&Path, &mut StrTable)` is in the same position**, and
`DesignIntent`'s fields are private with no constructor. A non-empty intent
cannot be built, so `is_empty` can be shown true but never false, and
`supply_role`, `limits` and `domain_voltage` are only testable in their absent
state.

**`UnknownLayers::Drop`'s reporting half is in no signature.** It is documented
as "Drop, and report how many rows were dropped. Never silent", but `gds::read`,
`oasis::read` and `read_layout` return `Result<Layout, LayoutError>` and neither
`Layout` nor `Provenance` carries a count.

**`Netlist` cannot represent a subcircuit instance.** `DeviceKind` is a closed
enum of five device families and no column points a device at a `SubcktId`.
`Netlist::top`, defined as "the one nothing else instantiates", therefore has no
input in which anything is instantiated. It also means the SPICE reader has
nowhere to put an `X` card, which is why
`a_call_to_an_undefined_subcircuit_is_refused_rather_than_left_dangling` asserts
only the refusal.

**`Provenance::paths(&self) -> &PathTable` hands out a shared reference and
`PathTable::intern` needs `&mut`**, so no caller outside `ingest` can build a
non-`ROOT` `PathId` to pass to `Provenance::push`. The permutation test for the
hierarchy-path column had to be a unit test inside `provenance.rs` for this
reason.

**`Grid` has one constructor, `Grid::new`, whose body is `todo!()`, and a
private field.** Anything taking a `Grid` by value, `read_deck` among them, can
only be called from a test that panics inside `Grid::new` before reaching the
code under test. Harmless in this phase, since the whole suite is red anyway,
but it means a `read_deck` failure points at `units` rather than at `ingest`
until Phase 4.

---

## derived

**`Evaluator.name` asks for two orders at once.** The field doc says "names in
evaluation order, so a lookup is a binary search and evaluation is a forward
scan". A topological order and an order sorted by `StrId` coincide only by
accident, and there is no third column carrying the other one, so `plan` cannot
satisfy both. The unit tests in `src/expr.rs` assert the topological property,
because a forward scan over a non-topological order reads results that do not
exist yet, whereas a linear scan in `get` is merely slower. Resolving this means
adding a sorted index beside the order, not reordering the column.

**`DerivedError::Recursive(String)` and `Undefined(String)` carry a layer name,
but `Evaluator::plan(&[StrId], &[DerivedExpr])` is never handed a `StrTable`**
and cannot resolve a `StrId` to text. The "named cycle" the plan-phase asked for
is not constructible from the parameters. Every error test therefore matches the
variant and says nothing about the payload, which is weaker than intended.

**`Evaluator::plan`'s output order is not observable through the public
interface.** `Evaluator` hands results out by name, never by position, so the
ordering assertions had to move into a `#[cfg(test)] mod` inside `src/expr.rs`.
`tests/plan.rs` can see acceptance and rejection only.

**`DerivedExpr` derives `Debug` and `Clone` but not `PartialEq`**, so two
expressions cannot be compared directly. The ordering test works around it by
writing a distinguishing base `LayerId` into the left spine of each definition
and reading it back, which is more code than a derive would have been.

**`ValidatedLayer` has no equality either**, so every layer comparison in
`tests/expr_laws.rs` goes through a sorted bounding-box-plus-area signature. That
separates every shape these fixtures build, but two distinct polygons sharing a
box and an area would compare equal.

**`DerivedExpr::Outside`'s doc comment is self-inconsistent**: the summary line
describes a whole-shape selection, which requires no universe, while the
paragraph below mandates one.

---

## topology

**`DeviceRecognition` (ingest::deck) cannot express a terminal's role.** It has
`terminal: Vec<LayerId>` and no role column, while `TerminalRole` is a
`topology` type appearing in no deck signature. `recognise_into` must therefore
infer the role from `DeviceKind` plus terminal index, and no frozen signature or
doc comment states that table. The tests assume the testgen convention: Mos =
Gate, Source, Drain, Bulk in order; two-terminal = `Pin(0)`, `Pin(1)`.

**`extract_nets_into` does not say what net a polygon on a non-conductor layer
gets.** `NetTable::net_of` is total over `PolyId`, so a cut or marker polygon
must map to something, and which is unstated. This makes
`PortError::OrphanLabel` unconstructible from outside the crate and forces every
net assertion to be written as "these polygons are exactly this net" rather than
against `net_count`.

**No thread-count parameter exists anywhere in this crate**, so the determinism
gate's "two thread counts" clause cannot be stated at this seam. Substituted two
concurrent OS threads plus a reused-table run, which catches hidden shared state
but not a work-partitioning bug.

**`NetTable` and `PortTable` have private fields, no constructor and no
`PartialEq`**, so no test can build an expected table and compare whole tables.
Every assertion goes through `polys_of` / `net_of` / `same_net` / `name_of`
instead, which works and is more code than a derive would have been.

---

## report

**`Measurement`'s `impl Display` (`crates/report/src/measure.rs:77`) promises an
input it does not take.** The doc comment says layout units print in nanometres
"against the run's grid, which the formatter is given", but
`fmt(&self, f: &mut Formatter<'_>)` takes no `Grid` and one cannot be threaded
through `std::fmt`. `Dbu` is a grid index, so `Length` and `Area` have no unit
until a `Grid` says so, and the promised output is unstateable as written.

---

## drc

**`RuleSet::from_deck(&Deck, &StrTable)` is untestable as written.** `Deck` is
unconstructible outside `ingest` (`deck::LayerTable` has private fields and no
constructor), so the load-time dispatcher and all seven `DrcError` variants —
`UnknownKind`, `MissingParam`, `WrongParamType`, `WrongLayerCount`,
`NonPositiveLimit`, `UnrepresentableAngle`, `DuplicateRule` — have no reachable
test. Worked around by building `RuleSet` through its public table fields, which
is why the dispatch adapter test exists at all.

**`color_into`'s `Exhausted` arm cannot be reached deterministically.**
`COLOR_SEARCH_BUDGET` is a crate const rather than a parameter (deliberate, per
its doc), so whether an input exhausts it depends on the Phase-4 search
strategy. Worked around with the law that survives either verdict: a graph
containing a four-clique is never reported three-colourable.

**`check_antenna` and `check_antenna_car` cannot reach the ratio.** Both need a
`NetTable` to resolve a gate's net to its collecting shapes, and `NetTable` has
private fields with no constructor. Worked around by testing `gate_areas_into`,
whose only input is the public-columned `DeviceTable`, plus the fail-closed
no-devices path.

**Five rule doc comments conflict with the frozen `testgen::violation` module
doc**, which claims authority explicitly ("a rule reporting a different point is
failing a test, not revealing a bad test"):

| rule | rule doc says | `ShapeKind` says |
|---|---|---|
| `check_min_edge_length` | the edge's first vertex | the edge's midpoint |
| `check_corner_to_corner` | the vertex of the first shape | the midpoint of the corner-to-corner segment |
| `check_min_enclosure` | its lower-left corner | the midpoint of the deficient margin |
| `check_min_enclosed_area` | a vertex of the hole ring | the centre of the hole |
| `check_density` | the window's lower-left corner | the centre of the window |

The suite follows testgen throughout, since it is the designated authority and
consistency matters more than which point wins. One of the two documents has to
be corrected, and it is a one-line decision in each case, not a test failure.

**`check_angle`'s measurement conflicts with `ShapeKind::Angle`, and here the
suite resolves it the other way.** The rule doc is explicit and principled:
measure the count of allowed directions matched (zero) against a limit of one,
because an inexact angle in degrees is the tolerance band wearing a different
hat. testgen's `Angle` kind puts the requested angle in degrees into
`expected.measured`. The suite follows the rule doc and overrides the two
measurement fields on the generated expectation. Called out at the site.

**`Violations` derives no `PartialEq`.** Every table comparison in this crate
goes through `testgen::assert_violations_eq` column by column, and every clean
check reads the public columns directly, because `Violations::len` / `get` /
`push` are frozen bodies that panic in this phase.

---

## erc

**`IntentMap::is_usable`'s doc comment says the opposite of the name.** It reads
"True when there is nothing here for an intent-dependent rule to check against",
which describes `!is_usable`. All four call-site doc comments say "Records
`Skipped(NoDesignIntent)` when `IntentMap::is_usable` is false", meaning true is
usable. The tests are written to the name and the call sites. Until the word is
changed, an implementer following the prose literally inverts six rules' gate.

**`check_ir_drop`'s doc comment contradicts itself on `examined`.** The last
line says "examined is the number of nodes on nets with at least one stated
limit", while the third paragraph says "A net with none of the three contributes
to examined and produces no violation". Those cannot both hold. The tests assert
only the first reading, and only on nets that do state a limit, so they are
neutral on the second — but one of the two sentences is wrong.

**`check_em_current_density` and `check_electromigration` take no `Grid`.**
`CurrentDensity` is `Current / Length` and `edge_width` is a `Dbu`; the only
`Dbu`-to-`Length` conversion is `Grid::to_length`, and neither `Solved` nor
`IntentMap` carries a `Grid`. The stated limit unit (A/m) is therefore not
computable inside either transform.

**`check_electromigration` and `check_reliability` take no temperature input.**
Both doc comments derate against "the edge temperature at that node", and no
parameter of either signature carries a temperature: `PowerGrid` has no
temperature column and `IntentMap` has no operating point. Only
`reference_temperature` is present, which is the characterisation point, not the
applied one.

**`EmCurrentDensityTable` gives a via edge a dimensionally wrong density.** The
doc says density is "`|current| / edge_width` for a metal edge and
`|current| / cuts` for a via". Current over a dimensionless cut count is a
`Current`, and it is compared against `max_density`, a `CurrentDensity`.
`ElectromigrationTable` resolves this with a separate `max_current_per_cut`
column; `EmCurrentDensityTable` has no equivalent, so a via edge on a limited
layer has no representable limit. The tests use metal edges only.

**`resolve_intent_into` cannot be reached with `Some(&DesignIntent)` carrying
any content.** `DesignIntent`'s fields are private and `read_intent` takes a
`&Path`, so a test can only pass `None` or an empty default.
`IntentMap::undeclared`, the port lookup and the ascending-supply invariant are
all unreachable from outside `ingest`.

**`Scratch::shrink` and `SolveScratch::shrink` have no observable effect.**
Neither returns anything and neither type exposes capacity, so the two functions
have no testable postcondition. Candidate equivalent-mutant sites; they need an
equivalence argument recorded at the source in the Implementation-Phase rather
than a test.

---

## lvs

**`hierarchical::ComparisonPlan` has three private columns, no accessor and no
`PartialEq`**, so `plan`'s output is unreadable from outside the crate. Its own
doc comment calls it table-testable, which as frozen it is not: only the
`Result` can be asserted.

**`PlanError::Cyclic` is unreachable.** `Netlist` has no way to say that one
subcircuit instantiates another: `device_kind` is the closed `DeviceKind` enum
with no subcircuit variant, and `plan`'s only other input is a flat `&[StrId]`.
There is no edge between cells anywhere in the inputs, so no cycle can be built,
every depth is zero, and "bottom-up, deepest first" has no content.
`Netlist::top`, documented as "the one nothing else instantiates", is undefined
for the same reason, and with it `Inconclusive::AmbiguousTop`.

**`hierarchical::run` takes one `&LayoutGraph` and one `&RefGraph` for a whole
multi-cell plan**, so it has no way to fetch a different graph pair per cell.
Either the plan is meant to index something the signature does not carry, or the
abstraction-and-flattening the module documents has no input to read. The tests
work around it by planning cells whose comparison is a graph against itself.

**`compare::interpret` takes `&Partition`, whose six columns are private with
`Default` as the only constructor.** The doc comment's stated reason for the
function existing separately, that it is worth a table of constructed
partitions, cannot be acted on.

**`checks.rs` in its entirety is unreachable from a test**: five of the six
functions take `&NetTable` or `&PortTable`, both of which have private fields,
no constructor, and only `todo!()` producers.

**`Netlist` carries no terminal roles**, only `terminal_net: Vec<RefNetId>`,
while `Graph` carries `terminal_role: Vec<TerminalRole>`. The mapping from a
device card's terminal position to a `TerminalRole` is therefore undefined by
the frozen types, and it is not stated in prose either. The projection test
asserts the MOS role *set* rather than the order, which catches an invented or
repeated role but not a transposed drain and source.

**`Graph`, `Partition` and `ComparisonPlan` derive `Debug` but not
`PartialEq`**, so the determinism assertions compare `format!("{:?}")` output.
That works and it reads badly. A `PartialEq` derive on the three would be one
line each.

---

## pex

**`matvec::ObserveMatVec` has no entry point.** The trait and its `NoObserve`
impl exist, but no function in the workspace is generic over it, unlike
`core::index::candidate_pairs_observed`, `core::connectivity::components_observed`,
`derived::prefilter::candidates_observed` and `lvs::refine::refine_observed`,
which all pair a public wrapper with a private `*_observed` generic. As it
stands the seam cannot be installed at, so `near_blocks`, `far_expansions` and
`bytes_transferred` are unobservable and the adapter test the plan calls for
cannot be written.

**`analytical::ground_capacitance` and `coupling_capacitance` take
per-micrometre deck coefficients against `Dbu` / `DbuArea` geometry with no
`Grid`**, so no absolute value is stateable. Confirmed from the consuming side:
every closed form for these two had to be downgraded to a scaling law or a
limit.

**`analytical::extract_devices_into` has no device-model parameter**, so the
per-family formulae its doc comment refers to are not reachable from the
signature. Its buffer contract is also unstated: `extract_into` says "cleared
and refilled", `extract_devices_into` and `extract_net_into` say nothing, so a
test cannot tell whether a second call into the same buffer should replace or
append. `extract_net_into` is tested with a fresh buffer each time to avoid
asserting on a choice.

**`quasistatic::mesh::build_into` produces `Panel` centres in metres from
`DbuArea` / `Dbu` geometry with no `Grid` parameter**, the same gap as the two
capacitance functions. `MeshError::MissingThickness` is also unreachable:
`ProcessStack::thickness_nm` is a `Vec<f64>`, which cannot express a layer whose
thickness is absent as opposed to zero.

**`topology::NetTable` has private fields and no constructor**, so every `pex`
test needing one routes through `topology::extract_nets_into`. That couples
`pex`'s extraction tests to `topology`'s correctness — a construct-from-answer
chain rather than a direct fixture. Workable via `testgen::scale_corpus`, and
noted so the coupling is visible when a `pex` test fails for a `topology`
reason.

---

## export

**`deck::LayerTable` (ingest) has private fields and no constructor**, so
`gds::write_store` cannot be tested against any store that holds geometry.
`export` is the second victim of that defect.

**`PortTable` (topology) has private fields and no constructor**, so the only
route to a named net is the full
`extract_nets_into -> Provenance::label -> bind_ports_into` chain. That chain
works and the tests use it, but it makes every export test transitively depend
on three other crates' implementations being right before a writer test can go
green in Phase 4.

**`WriteError` derives `Debug`/`Clone` but not `PartialEq`**, so every error
assertion is a match arm plus an `assert_eq` on the payload rather than
`assert_eq` on the value. Works, costs four lines per case.

**`ParasiticNetwork::node_net` and `node_layer` are public columns but there is
no stated invariant tying node index to net grouping**, so a fixture that lays
nodes out net by net is guessing at a convention the signature does not state.
The tests do not depend on it beyond node-to-net membership.

---

## engine

**`pipeline::LoadError::NoGrid` is unreachable.** Its message is "deck declares
no grid resolution", but `ingest::deck::read_deck(path, grid, strings)` takes
the `Grid` as an input, no `ingest` interface extracts a grid from a deck file
or a layout header, and `pipeline::Inputs` has no grid field. `load_into`
therefore cannot observe the condition the variant names.

**`run::EngineError` has no variant for `gpurify_drc::DrcError` or
`gpurify_erc::ErcError`.** Both are documented as fail-closed construction-time
errors from `RuleSet::from_deck`, and `run_checks` — which receives the `Deck`
inside `Loaded` — is the only place that can call it. A deck naming an unknown
rule kind has nowhere to be reported, so the fail-closed guarantee stops at the
engine seam.

**`run::Summary` derives neither `PartialEq` nor `Default`.** The determinism
gate compares two summaries, so `crates/engine/tests/checks.rs` writes the
comparison out field by field.

**`pex::ParasiticNetwork` has no `PartialEq`**, so the determinism comparison of
`Outputs::parasitics` is written column by column. It is compared with a bare
`==` inside `assert!` rather than `assert_eq!`, because `Parasitic` wraps a
`Qty` whose `Debug` is `todo!()` and formatting it on failure would panic inside
the failure message.

**The deck's rule-kind strings are stated nowhere.** `RuleSet::from_deck`
matches `RuleSpec::kind` against names it looks up in the `StrTable`, but those
names appear in no signature, no doc comment and nothing in `docs/`. Combined
with `LayerTable` having no constructor, no test outside `drc` can build a deck
whose rules reach a rule table.

---

## cli

**`fn main() -> std::process::ExitCode` holds the exit-code contract and there
is no pure function for it.** `Summary::passed` covers the pass criterion; the
`Result<Summary, EngineError>` to `ExitCode` mapping is untestable.

**`crates/cli/Cargo.toml` has no dev-dependency on `gpurify-core`**, so
`LayerId` and `PolyId` cannot be named anywhere in this crate. A
`gpurify_report::Violation` therefore cannot be written out by hand in a cli
test. Worked around by taking real ids off a `gpurify_testgen::scale_corpus`,
and by pushing rows through a macro so the types never appear in a signature.

**`Args`, `Command`, `Common` and `ArgError` derive no `PartialEq`.** Every
table test compares variant by variant and field by field instead of
`assert_eq!` on the whole parse, and the purity test compares `Debug` strings.
`Format` does derive it and is the exception that shows the cost.

**`Common::strict_layers` has no landing place** in `engine::Inputs` or
`engine::RunOptions`, so `to_inputs` cannot carry it anywhere. The flag is
parseable and unroutable.

**`parse(argv: &[String])` does not say whether `argv` includes the program
name.** The tests fix it as excluded (`argv[0]` is the subcommand) and say so in
the test module's doc comment, because nothing else in the tree states it.

**`main.rs` says "`clap` lives here and only here", but `clap` is not among the
crate's dependencies** and `parse` takes `&[String]`. The doc comment describes
a dependency that does not exist.
