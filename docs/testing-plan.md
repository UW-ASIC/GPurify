# Testing plan

*Written 2026-10-10 against `be14a73`. This applies §2.6 of
`~/Documents/Projects/Zig/TESTING-METHODOLOGY.md` (2026-10-03) to the tree as it
is now. Every fact about the repo has a file reference. The cumulative list of
checks the tool must handle, and the sources it comes from, is in
[check-sources.md](check-sources.md).*

The goal is to find bugs through oracles we own (coverage, fuzzing, properties,
differential and metamorphic checks) instead of through users. Every layer
below names its **oracle**: the independent thing that says an output is wrong.
A layer without one is not a test.

---

## 1. What is being tested

| | |
|---|---|
| **Input** | GDSII (`crates/ingest/src/layout.rs:70`), a rule deck (`deck/parse.rs:95`), a SPICE/CDL or Spectre reference netlist (`netlist.rs:737`, `:760`), a JSON design-intent file (`intent.rs:160`), and a Liberty spec (`src/liberty/spec.rs:376`). All of it is untrusted text or binary. |
| **Output** | A byte-deterministic report: per-rule `Ran / Skipped{…} / Refused` with the number of shapes examined, violations with measured value, limit and location, an LVS verdict with discrepancies, SPEF, and `.lib`/Verilog. Plus the exit code. |
| **Correct means** | (1) No violation that the foundry's rule defines is missed (false negative, the costly direction). (2) No violation is reported that the rule does not define (false positive). (3) Every rule that could not look at the layout says so. (4) LVS says *match* only when the circuits are equivalent up to declared reductions and tolerances. (5) Extracted R/C/L lies within a stated tolerance of physics. (6) Same input, same bytes. |
| **State / concurrency** | Batch and single-shot. DRC, ERC and LVS are single-threaded. Rayon runs only in the field solver (`extract/field/matvec.rs:67`, `henry.rs:225,288,428`), and a thread pool drives ngspice (`src/liberty/spice.rs:303`). |
| **Targets** | x86-64 and aarch64 CPUs. SIMD goes through `fearless_simd`. There is no GPU path any more (removed in `0db5f44`; the comment at `ci.yml:20-21` is stale). |

**Domains it touches** (from the test-plan skill's DOMAINS.md):
- geometry/EDA (all checks);
- parsers and file formats (GDS, deck, netlists, intent, Liberty spec);
- numerical solvers (field solve, IR/EM networks, Liberty characterisation);
- SIMD (matvec, width scans).

---

## 2. Where testing stands

**What exists and is good:**
- 757 `#[test]` when this plan was written, 11 of them `#[ignore]` (timing and diagnostics only; since B28 those are examples, and the `--ignored` tier holds only tests that assert).
- Per-rule accounting, which makes vacuous passes visible.
- The corpus records evidence grades and derivations.
- Closed-form ERC tests (`tests/erc_closed_form.rs`).
- Construct-from-answer DRC tests on foundry wording (`tests/drc_kinds.rs`, `tests/sky130_rules.rs`).
- Scalar-vs-SIMD equivalence tests.
- The `testgen` generators.

**Problems found while writing this plan.** Each one becomes a task in §8.

| # | Finding | Where | Why it matters |
|---|---|---|---|
| F1 | **Subcircuit instances in the reference netlist are dropped from the LVS graph.** `from_reference` takes only the top subcircuit's own devices; `X` cards are parsed (`netlist.rs:506`) but never flattened. | `crates/check/src/lvs/graph.rs:180`, called from `src/engine/run.rs:333` | A layout missing a whole sub-block that the schematic places by `X` instance can match. This is a false clean, the worst LVS bug class. **Fixed in B2:** the reference is flattened below its top at load (`Netlist::flatten_top`). |
| F2 | **The LVS corpus never asserts `expect_match`.** Its 16 cases check only device and net counts. Inside the corpus the full compare runs once, on `lvs_inv.cdl` (`test_all.rs:197`). Outside it, `tests/engine/main.rs:193,450,467` and the 22 tests in `crates/check/tests/lvs/compare.rs` check verdicts on hand-built graphs. | `tests/common/mod.rs:1053-1106`, stated in `crates/check/tests/lvs/reduce.rs:4-7` | The corpus cells, the ones with derived answers, have no verdict oracle. **Fixed in B1:** every corpus case asserts its verdict; X5 adds the planted-fault matrix. |
| F3 | GDS hierarchy traversal recurses with a cycle check but **no depth limit**. | `crates/ingest/src/layout.rs:1313` (`visit`) | A deep, legal hierarchy overflows the stack. This is the same class as SQLite's `median()` quicksort bug: found after full coverage and fuzzing, because fuzzers prefer small inputs. **Fixed in C1:** `MAX_HIERARCHY_DEPTH` and `MAX_FLAT_POLYGONS`, counted before expansion. |
| F4 | The corpus GDS uses **invented layer numbers** (1/0–14/0) and a synthetic deck (`params.deck`). The README calls it "real GDSII cells drawn for a real PDK". | `tests/fixtures/_source/conformance.gds`, `README.md` Accuracy section | The shipped foundry decks (`pdks/*.deck`) run only on hand-drawn rectangles for a few rules (`tests/sky130_rules.rs`, `tests/engine/main.rs:397`, `tests/derived_layers.rs:287`), never on foundry test structures or real designs. Spec misunderstanding of a foundry rule is the class nothing currently sees. |
| F5 | **Counts have drifted.** README says 24 DRC / 19 ERC kinds; the code has 35 / 24 (`drc/ruleset.rs:915`, `erc/ruleset.rs:20`). The fixtures README says 161/160 cases; there are 167. The stored `counts` block in `expectations.json` is stale for ERC, and README copies it. `known_defects` cite paths that no longer exist. | `README.md:89,148-156,240`, `tests/fixtures/README.md:3,7,81-91` | Documentation is an output too. Every one of these numbers can be computed by a test. **Fixed in A2:** `tests/doc_counts.rs` computes every count. |
| F6 | Only DRC and ERC cases carry `expect_outcome` and `examined_min`. LVS and PEX cases have neither, and PEX cases run only the analytical path. | `tests/common/mod.rs:583-590,1174` | The "no vacuous pass" guarantee covers 124 of 167 cases. |
| F7 | Nothing automated runs `--check-determinism`, `tools/gate/*`, `drc_oracle.rb`, `cargo-mutants` (described as "the acceptance gate" at `flake.nix:36`), or any benchmark. | `ci.yml` | A gate that never runs is not a gate. **Fixed in G1 and F1:** CI runs the merge tier on every pull request and the nightly tier (fuzzing, mutation, coverage, the oracle differentials) nightly and on a pull request labelled `heavy`; `drc_oracle.rb` is retired in favour of the generated mirror deck; determinism is checked by the golden test. |
| F8 | There are no fuzz targets, no shrinking, and fixed seeds only. Each generated test runs one seed for 8–2048 iterations. | `crates/testgen` | Property tests cannot scale up at night, and a failure gives no minimal case. **Fixed in C2 and E1:** properties take named seeds with committed regression seeds and shrinking (`testgen::prop`), and every untrusted entry point has a cargo-fuzz target whose crashers and seeds replay on stable. |
| F9 | Assertion density is low: 17 production asserts in geom, 7 in check, 2 in extract, 2 in ingest. | grep | Fuzzers and property tests can only see what an assertion or a comparison flags. |
| F10 | `docs/limitations.md:102` says no test checks `esd_latchup` numbers, but `test_all.rs:770` does. `pdks/README.md` is referenced but missing. | | The doc says less than the tests prove. **Fixed in A2.** |
| F11 | **sky130's antenna rows came from the wrong foundry table.** `ar.met3.1` used Table Ic (the three-metal S8TM flow, met3 FLT 2.0 µm), and met4/met5 used Magic's drawn thicknesses. sky130A is an S8P*/S8PIR* flow: met5 is its top metal, and its met5 minimum (`m5.1`, 1.6 µm) belongs only to S8PF*/S8PIR*. Its table is Ig: met3 and met4 0.8 µm, met5 1.2 µm. Philis's vendored correction (845 nm, the drawn thickness) was also not the rule. **Fixed in B7**, with a test pinning every row to Table Ig. | `pdks/sky130.deck` antenna block; SkyWater `docs/rules/antenna/table-Ig-antenna-rules-s8p12.csv` | A rule value cited from the wrong process flow passes review because it *has* a source. The oracle is the right row of the right table, not physical consistency: FLT is the rule's convention, so the "sidewall = PEX thickness" idea was wrong (met1 is 0.35 µm in every table and 0.36 µm drawn). |
| F12 | **The reference netlist never series-reduces, and the layout does.** `from_reference` names every reference net (`graph.rs:194`), and `join_series` refuses any named node (`reduce.rs:403`). A drawn transistor stack with an unlabelled internal node merges into one device with L summed, while its reference twin stays as two devices. No test pairs a layout series stack with a reference one. | `crates/check/src/lvs/graph.rs:194`, `crates/check/src/lvs/reduce.rs:403` | **False mismatch** on valid stacked circuits (B8). A likely fix is to refuse series merges only at reference *ports*, not at every named net. The L2 planted-fault matrix needs a "stack vs stack → match" case. **Fixed in B4:** a series merge stops only at ports, and `compare` makes a reference net a port when a layout label names it. |
| F13 | **`lvs.net_seed_conflict` can never fire.** Port binding already errors out on two names on one net (`topology/port.rs:72`), so `resolved == seeds` always holds. | `crates/check/src/lvs/checks.rs:214-233` | A rule that reports `Ran` but cannot find anything is exactly the hollow pass the accounting is meant to rule out. Mutation testing (L10) flags such a rule as a surviving mutant; delete it or make it reachable. **Fixed in B5:** binding keeps a net's several names; `lvs.net_seed_conflict` reports each pair of names on a net, at the first label's shape. |
| F14 | **A short between two labelled nets aborts extraction** (`PortError::ConflictingLabels`, `pipeline.rs:181`): the run fails with a net id, with no report row and no location. Separately, **`PortTable::net_of` resolves a name on several nets to the lowest one** (`port.rs:33-37`). That affects `--quasistatic` (`run.rs:384`), Liberty (`src/liberty/circuit.rs:106`) and the netlist exporter (`src/export/netlist.rs:326-345`). Intent is not affected: `resolve_intent_into` visits every piece (`erc/facts.rs:154-199`). | `src/engine/pipeline.rs:181`, `crates/check/src/topology/port.rs:33-37` | The first does not pass, but it cannot be debugged from the report. The second field-solves, characterises or exports only one piece of a split net. **Fixed in B5:** a labelled short extracts and every run reports it as `lvs.net_seed_conflict` (both labelled shapes, a location); ERC refuses intent on it, Liberty refuses two pins on one net. A name on several nets is an open: `PortTable::nets_of` gives every piece and `net_of` none; `--quasistatic` refuses it, Liberty joins the pieces at the pin, `write_spice` refuses it. |
| F15 | **Diode anode/cathode and capacitor plates are interchangeable in LVS.** Diodes and capacitors get `Pin(0)`/`Pin(1)` roles (`graph.rs:301`), and every `Pin(_)` shares one role code (`refine.rs:69`), so a reversed diode matches. | `crates/check/src/lvs/graph.rs:291-302`, `crates/check/src/lvs/refine.rs:58-69` | **False clean** (B7). Netgen permutes resistor ends but not capacitor plates; nobody permutes a diode. **Fixed in B3:** each `Pin(n)` has its own role code, and the graph builders write a resistor's two ends as `Pin(0)`. |
| F16 | **LVS compares few device parameters.** Extraction gives MOS `w`/`l` and the marker `area` only (`topology/device.rs:301-329`). No resistor R/W/L, capacitor C, perimeter, `nf` or BJT emitter area. A parameter only the reference declares becomes `undeclared_param`, and the positional `R1 a b 1k` form is refused (`netlist.rs:447-453`). | `crates/check/src/topology/device.rs:301-329`, `crates/check/src/lvs/compare.rs:255-313` | Wrong-size passives match (B9). Catalog rows LVS-060–064. **Partly fixed in B6:** `R1 a b 1k rpoly` and `C1 a b 1p cmim` read as r and c. The device statement takes optional `sheet` (resistor) and `area_cap`/`fringe_cap` (capacitor). The layout measures resistor w/l (bounding box along its first end), MOS nf = 1 per channel, every marker's perim, r = sheet·l/w and c = area_cap·area + fringe_cap·perim. Open (B27): MOS as/ad/ps/pd, BJT emitter area. **Fixed in B27:** MOS `as/ad/ps/pd` from the source/drain polygon (holes out, every ring; `ps`/`pd` include the gate edge, as BSIM4's default `perMod=1` and KLayout do), a shared diffusion split evenly (KLayout); bipolar `ae/pe` from the emitter terminal's polygon. Parallel merges sum them end by end, `m` folds into them with W, series merges of devices stating them are refused. Left: capacitor w/l (no orientation is defined), terminals drawn in pieces. |
| F17 | **No run that selects LVS with a reference could pass.** `check_layout` recorded three rows the deck cannot configure (`lvs.device_count_mos`, `lvs.device_count_bjt`, `lvs.parametric`) as `Skipped(NotInDeck)`, and a skipped rule fails the run, so even a clean match exited 1. **Fixed in B8:** a row is recorded only for a configured check; the missing checks stay in the catalog (LVS-068) and `limitations.md`. | `crates/check/src/lvs/checks.rs` (`check_layout`) | Every LVS golden exited 1 before the fix. No test covered a passing LVS run, which is why this went unnoticed. |
| F18 | **`min_edge_length` measures each drawn polygon without merging.** A jog that exists only where overlapping shapes meet is missed, and an edge two abutting shapes share is flagged. | `crates/check/src/drc/rules/width.rs` (`min_edge_length`) | False clean and false violation (B1, B2). The bitmap oracle (C5) sees both. **Fixed in B15:** `min_edge_length` merges the layer and measures every edge of each figure, holes included, on the lowest drawn row under it; `examined` counts figure edges. |
| F19 | **`min_extension` ignores the sides where A does not protrude past B** (`smallest_protrusion`), so poly ending inside diffusion at one end passes if the other end extends far enough. **`overlap`** flags bounding boxes that only touch, and measures boxes that overlap where the shapes do not. | `crates/check/src/drc/rules/overlay.rs` | False clean beyond the documented bounding-box limit. **Fixed in B15:** `min_extension` and `overlap` measure the figures of merged A ∩ B, not row boxes. `overlap` measures each shared figure as `min_width` measures a figure; `min_extension` measures each gate per crossed axis (A's run past each B edge, 0 flush), the least over its crossed axes, and 0 when A ends inside B. A gate that bends or has a stub inside B fails closed at 0. |
| F20 | **LVS parallel merging sums only `W` and `nf`, for every device kind.** Two parallel resistors or capacitors without a `W` collapse into one device with the same R or C. Diodes wired in opposite directions merge, because every `Pin(_)` role is interchangeable (F15). | `crates/check/src/lvs/reduce.rs` (`join_parallel`) | **False clean**: one drawn device matches two in the schematic. **Fixed in B9:** parallel merge by kind: MOS sums W and nf; other kinds keep their value and count devices in `m` (a card without one counts 1), merging only when `m` is named. Values are counted, not added. |
| F21 | **A card's `m` is dropped when the device has no `W` to fold it into.** A reference card with `m=2` matches one drawn device. | `lvs/reduce.rs` (`fold_multiplier`) | **False clean.** **Fixed in B9:** only a MOS's `m` folds into W; any other `m` is kept as the count; `m=1` is dropped. |
| F22 | **A parameter declared on any reference card is measured on every layout device.** One diode with `area=` makes every layout MOS carry `area` and report `undeclared_param`. | `lvs/graph.rs` (`from_layout`) | False mismatch. **Fixed in B9:** `compare` keeps a layout parameter only where the reference declares it for that kind and model. |
| F23 | **Inductance filaments join only where endpoints coincide exactly on one layer.** A net drawn as two touching rectangles (an L-shape) reads L = 0 H and R = 0 Ω with no refusal; vias never join layers. | `crates/extract/src/field/henry.rs` | A wrong number that does not crash: the class that needs an oracle (FastHenry, L6). **Fixed in B11:** filaments come from each net's merged rectangles, joined through shared edges and through every via cut on both plates (one filament per cut at the stack's per-cut R); a net that is not one circuit is refused (`InductanceError::Disconnected`). |
| F24 | **The field solve has no substrate ground plane.** A field-solved net's "ground" capacitance is to infinity, which undercuts usage.md's "more accurate". | `crates/extract/src/field/matvec.rs` | Systematic PEX error (B12). **Fixed in B11:** the field kernel images every panel in a grounded substrate plane at z = 0, so ground C is to the substrate (8 µm plate: 11.74 fF against its 8.84 fF column). A conductor at height 0 is refused (`MeshError::OnSubstrate`); modelling wells and diffusion as junctions is F73. |
| F25 | **The Blech exemption is too generous.** Every supply shape is tapped at its centre, and the Blech length is the distance between adjacent taps, not the via-to-via line, so a segment can be called immortal that is not. | `crates/check/src/erc/power.rs`, `erc/rules/electrical.rs` | False clean on electromigration (B10). **Fixed in B10:** the Blech L is the line between diffusion barriers (a via landing, the feed point, a loaded device tap, or the line's end), not the gap between adjacent grid taps; a branched line counts every branch, which errs mortal. |
| F26 | **Guard-ring width is the bounding box.** A ring drawn as one closed polygon is measured by its outer size, so a ring that is too narrow passes. | `erc/rules/reliability.rs` (`esd_latchup`) | False clean. **Fixed in B10:** guard-ring width is the merged ring's narrowest band, measured as DRC `width` measures it; the tap distance is still a bounding-box gap. |
| F27 | **`soft_connection` treats any two touching shapes as joined,** including overlapping shapes on different layers with no via, which can hide a soft connection. | `erc/rules/supply.rs` | False clean. **Fixed in B10:** `soft_connection` re-extracts nets from the deck's connectivity with the soft layers removed, so a strap over a shape with no via joins nothing. |
| F28 | **`multiple_drivers` with `max: 1` (all three shipped decks) flags NAND/NOR outputs**, whose drains are gated by different inputs. Source and drain are assigned by polygon order under the marker, so this rule and `tie_high_low` depend on drawing order. | `erc/rules/topology.rs`, `topology/device.rs` | False violations on every standard cell; results depend on drawing order. **Partly fixed in B10:** a driver is a pull network (drain on the net plus everything below its source), and networks sharing a gate net are one driver, so NAND and NOR pass at `max: 1`. Open: source and drain are in extraction order, so `multiple_drivers` and `tie_high_low` still depend on drawing order. Options: rails from intent (both rules skip without it; 167 goldens move), rails named by the deck, or leave it documented. A decision. **Fixed in B22:** channels are oriented by the rails design intent declares. A driver is a channel-connected path from the net to a rail, source and drain alike; networks sharing a gate net are one driver; a pass gate that reaches no rail drives nothing by itself; a rail is not examined. `tie_high_low` flags a declared rail that reaches a gate. Without a declared supply both rules record `Skipped`; 167 goldens moved. A consequence, by definition: an SRAM bit line reads one driver per access transistor. |
| F29 | **Antenna areas double-count overlapping polygons:** collector areas are summed per drawn polygon without merging. | `erc/rules/antenna.rs` | Over-report on collectors, under-report on an overlapping gate layer. **Fixed in B10:** gate, collector and diode areas are merged-figure areas, counted once per net. |
| F30 | **Analytical extraction is fail-open:** a conductor with no `pex` row contributes zero R and C silently, while the field solver refuses it, and the SPEF/DSPF writers do not check for NaN or infinity. | `crates/extract/src/analytical.rs`, `src/export/parasitic.rs` | A missing deck line reads as a perfect wire. **Fixed in B11:** analytical extraction refuses a conductor layer holding a net's shape, or a via layer joining two conductors, with no positive sheet resistance (PEX `Refused`, naming the layer); SPEF, DSPF and SPICE refuse NaN and infinity. |
| F31 | **Naming a `--quasistatic` net twice aborts the run** (`NotConverged`, `EngineError::Solve`). A label on several disconnected nets (F14) writes duplicate `*D_NET` blocks in SPEF/DSPF, and `write_spice` panics on it in debug builds. | `src/engine/run.rs` (`run_pex`), `src/export/parasitic.rs` | A user input crashes the run instead of being refused. **Fixed in B11:** `run_pex` deduplicates the `--quasistatic` selection; SPEF, DSPF and SPICE refuse a label on several nets (`WriteError::SplitLabel`). |
| F32 | **`lvs.terminal_net` cannot fire on a graph the pipeline builds,** because device recognition already drops any device with a terminal on no net (the F13 pattern). | `lvs/checks.rs`, `topology/device.rs` | A row that reports `Ran` but cannot find anything. **Fixed in B9:** unbound markers are listed in `DeviceTable::refused` and reported by `lvs.terminal_net` on the marker. |
| F33 | **A source or drain polygon drawn twice is ignored only when its copy is numbered after the other terminal's polygon;** numbered earlier, it takes a terminal slot and the device is silently not recognised. | `topology/device.rs` | A missing device with no report; it depends on drawing order. **Fixed in B9:** with a surplus of polygons, a marker binds by distinct net, independent of drawing order. |
| F34 | DRC details: `Owners::lowest_within` can name an island in a figure's hole as the violating shape (`min_area`, `cheesing`, `min_enclosed_area`); `max_distance_to_tap` measures hole rings as wells (over-report only); `color_into` returns `Complete` on a self-loop with three or more colours. | `drc/rules/area.rs`, `erc/rules/supply.rs`, `drc/rules/patterning.rs` | Wrong attribution and a public-API trap; no false clean known. **Fixed in B16:** `min_area`, `cheesing` and `min_enclosed_area` name the lowest drawn outer row overlapping the figure (`owners_of`), never an island in its hole; `untied_points` skips hole rows, so a ring well is reported once; `color_into` returns `Infeasible` at the lowest self-looped node. |
| F35 | Small ones: <br>• `write_blackbox` emits a trailing comma (a Verilog syntax error) for a spec with supply pins and no signal pins;<br>• `tests/liberty.rs` fails alone in a fresh checkout (fixtures not generated);<br>• testgen's `density` applies twice (1.0 panics) and its `Angle` triangle winds clockwise;<br>• intent's `BadLimit` and `DomainConflict` messages name the wrong cause;<br>• `resolve_labels` duplicates labels when called twice;<br>• a reference cycle no root reaches is skipped silently;<br>• `density_cmp`'s `partial_windows` is ignored for neighbour deltas;<br>• `CmpModel::nominal_thickness` is read by nothing;<br>• `diode_bonus` is subtracted with no diode on the net;<br>• the leakage error always blames the DC operating point. | various | Each needs a one-line test and a fix. ERC items fixed in B12: `BadLimit` names the limit's key and a repeated supply says so; `partial_windows` governs neighbour deltas; `CmpModel::nominal_thickness` and `cmp: (thickness:)` are gone; `diode_bonus` applies only with diode area on the net. Export items fixed in B12: the blackbox comma, `tests/liberty.rs` fixtures, and the leakage message. **Fixed in B12:** testgen `density` is the expected coverage (√density each for fill and size; 1.0 fills every cell) and the `Angle` triangle winds counter-clockwise; `resolve_labels` rebinds instead of appending; a reference cycle no root reaches is `CyclicHierarchy`. |
| F36 | **An AREF is expanded without a budget.** A 32767 × 32767 array is about 10⁹ placements per child shape; flattening runs until the u32 polygon id overflows and panics, rather than refusing. | `crates/ingest/src/layout.rs` (`Flatten::visit`), `geom` store builder | A crafted layout hangs or panics the run (B14). **Fixed in C1:** the flat count is taken from the hierarchy before anything is expanded, and a layout over `MAX_FLAT_POLYGONS` (2²⁸) is refused. |
| F37 | **A boolean whose result has a hole touching its outer boundary at a vertex failed** with "self-intersecting boundary", which `boolean.rs` documents as an internal fault that cannot happen. At a checkerboard vertex the walk takes the left turn, which keeps two separate cells apart, but when the two diagonal cells are one region it stitched the outer ring and the hole into one ring through the vertex twice. Found on its first run by the random boolean property (shrunk to three rectangles). **Fixed in C3:** a ring that comes back through a pinch has the loop since the first visit split off as its own ring. | `crates/geom/src/boolean.rs` (`link`) | A derived layer or rule over such geometry failed the run instead of answering (B4). |
| F38 | **A gap in a chain of shapes joined only at corners is reported by nothing.** Booleans keep corner-touching shapes as separate figures, but the spacing rules join them into one component; so with squares at (0,0)–(10,10), (10,10)–(20,20) and (20,0)–(30,10), the 10-wide gap between the first and third is not a `notch` (separate figures) and not a `space` (one component), at any limit. KLayout's default reports it. | `drc/rules/spacing.rs` (`prepare`) vs `geom/boolean.rs` | **False clean** (B1). One coherence for both is the fix; KLayout's and foundry decks' is to treat corner contact as connecting. **Fixed in B20:** one corner model, "connected": `successors_into` takes the right turn at a corner where four edges meet, so corner-touching shapes are one figure and the gap between their parts is a notch, never a space. |
| F39 | **`.with_width()` measures facing edges only**, while deck.md says "as `width` measures it", which also counts Euclidean necks. Two squares overlapping at a corner have a neck `width` sees and `with_width` does not. | `geom/width.rs` (`narrowest_width`) | A derived-layer selection that differs from the rule it is documented to match. **Fixed in B16** (with F55): `narrowest_width` takes the lesser of the facing width and any narrower diagonal neck, floored to a whole unit as `width` reports it. |
| F40 | **The density die includes derived layers** when no boundary layer is given, so `layer x = met1.sized(1um)` enlarges it and adds empty windows. deck.md says "the whole layout". | `drc/rules/area.rs` (`die_of`) | False density violations at the layout's edge. X2 measured it: met1 at 70% of `[0,1000]²` plus an unused `met1.sized(500nm)` reads 0.206, so `global_density <= 60%` passes (a **false clean**), `>= 50%` flags, and `density` reports 14 windows for 6. The field's rustdoc says "every layer's", contradicting deck.md. **Fixed in B16:** `RuleSet::first_derived`; without a boundary the die is the drawn layers' extent. The engine's fallback die for ERC densities and the Liberty area (`design_extent`) skips derived layers too. |
| F41 | **`min_extension` judges pairs that only touch:** a line abutting the side of its reference is measured by its far protrusion. | `drc/rules/overlay.rs` | False violation (B2); F19 covered it for `overlap` only. **Fixed in B15:** shapes that only touch share no area, so they make no gate and are not measured. |
| F42 | **`eol_spacing` reads ends of line from drawn rows:** an edge two abutting rows share is taken as a line end whose keep-out runs through its own figure. | `drc/rules/spacing.rs` | False violation, the F18 pattern. X1 also found the strip case: a 300-wide end drawn as three 100-wide strips is three ends of line. **Fixed in B14:** ends of line are the merged layer's edges shorter than `eol_width`; a drawn row lies on one where its edge shares the end's line, direction and a stretch of it, and is measured from that stretch. A line end drawn as strips is one edge; an edge two shapes share is none. |
| F43 | **`corner_to_corner` can miss an L-shaped shape** whose bounding box overlaps its neighbour on one axis but whose real corner is diagonal to it. | `drc/rules/spacing.rs` | **False clean**, and corner limits are usually larger than space limits. **Fixed in B14:** corners are the merged layer's convex corners, each with the diagonal it faces; a pair is measured between its nearest corners that face each other, so an L's real corner is seen whatever its box. For two rectangles this is the old box test. |
| F44 | **The PEX closed forms read each drawn polygon, not the merged conductor.** A 12×1 µm bar cut into 2, 3 or 4 abutting pieces reads C = 1.42, 1.50, 1.58 fF for 1.34, since each shared edge counts as fringe on both sides; an L of two overlapping bars reads R 3.2 Ω for 3.1 and C 3.52 fF for 3.335; a piece shorter than it is wide still counts one square, so four 750 nm pieces of a 3-square bar read 0.533 Ω for 0.3. | `crates/extract` (analytical R and C) | Wrong parasitics whenever a conductor is drawn as more than one polygon. Found by X6. **Fixed in B19:** R and ground C per merged region of each net and layer (`conductor::Regions`); coupling and vias are measured on the regions' rectangles; a non-rectilinear conductor layer is refused. |
| F45 | **A field-solved polygon is one filament along its bounding box.** An L drawn as one polygon reads R = 0.125 Ω and L = 6.28 pH for 3.5 Ω and 25.7 pH, and the filament R replaces the analytical R, which was right. | `crates/extract/src/field` | Wrong R and L for any non-rectangular conductor under `--quasistatic`. Found by X6. **Fixed in B19:** each rectangle of the merged conductor is a filament along its centre line, joined to touching rectangles through the middle of the shared edge; the L reads 3.5 Ω and Grover's L to 1.4e-4. |
| F46 | **The field-solve mesh depends on absolute position.** A face's panel count is the ceiling of a width taken from absolute coordinates in metres, so a 6000 nm face at x = 1 mm reads 12.000000000000293 panels and gets 13. Moving three conductors 1 mm changes C by about 1e-4. Counting panels from the integer width fixes it. | `crates/extract/src/field/mesh.rs` | Translation changes the answer. Found by X6. **Fixed in B13:** `cuts` takes a width within a millionth of an edge over a whole number of edges as that number. |
| F47 | **The reciprocity gate refuses ordinary layouts.** It holds each off-diagonal's own relative asymmetry to the 1e-10 residual, so the weakest pair trips it: four small conductors are refused at asymmetry 2.6e-10 for an entry off by 8e-12 fF (1.6e-11 of the diagonal). Normalising by √(Cii·Cjj) fixes it. | `src/engine/run.rs` (`reciprocity_refusal`) | A false refusal under `--quasistatic`. Found by X6. **Fixed in B13:** `CapMatrix::asymmetry` divides by √(Cii·Cjj). |
| F48 | **`eol_spacing` points a hole edge's keep-out into the material.** `eol_hit` flips the keep-out for clockwise rings, but the store keeps a hole clockwise with the material on its left, so the flip aims a hole's end of line inward: a 100-wide slot with an island 90 inside the hole is missed, and a 50-thick band past a slot's end is flagged at 80 against a shape beyond it. | `drc/rules/spacing.rs` (`eol_hit`) | **False clean** and false violation. Found by X1. **Fixed in B14:** ends are read off the merged layer, whose edges all have their material on the left, so the keep-out points out of the material, into the hole for a hole's edge. |
| F49 | **`prl_spacing` and `spacing_table` read the parallel run off each drawn polygon's box.** A wire running 2000 beside another, drawn as four 500-long segments, has no run over a 600 threshold, so `prl_spacing` finds 0 of 4, and `spacing_table` reads the wrong column (180 for 220) and finds 0 of 4. The rule's rustdoc says the box reading errs strict; for split segments it errs lenient. | `drc/rules/spacing.rs` (`parallel_run_length` callers) | **False clean**, the F18 pattern. Found by X1. **Fixed in B14:** the run is read off the merged figures' bounding boxes, so a wire drawn as segments runs its whole length; the box reading still errs strict. Facing-edge projection (KLayout `projection`, LEF) is not measured. **Fixed in B24:** the run is facing-edge projection (decided): the longest overlap of two parallel edges of the merged figures facing each other at most the limit (`prl_spacing`) or the cell (`spacing_table`, per row and column) apart; a box no longer overstates an L's run. "At most" is inclusive, as LEF counts every facing stretch. |
| F50 | **`off_grid` checks derived layers too.** A layout drawn wholly on a 10 nm grid fails once the deck derives `met1.sized(5nm)`, and one off-grid drawn vertex is reported again on every derived layer that keeps it. The rustdoc's "every row on every layer" says so literally; foundry decks check drawn layers. | `drc/rules/grid.rs` | False violations, duplicated rows. Found by X1; not fixtured, a decision first. **Fixed in B16:** `off_grid` checks rows on drawn layers only; `examined` counts drawn vertices (52 goldens moved for that count alone). |
| F51 | **Corner contact is read two ways.** `min_spacing` treats two figures that meet only at a corner as one, while `notch`, `min_width` and `min_area` treat them as two, so the gaps between them are reported by neither: three cells `.#.\|#.#` (rows top to bottom) have a 100 nm gap that neither `space >= 120nm` nor `notch >= 150nm` reports, and a 3×3 checkerboard is clean on both. | `drc/rules/spacing.rs` (figure grouping) against `union_into` | **False clean** under any reading of corner contact. Found by X3. The same defect as F38, found by enumeration; fixed together. **Fixed in B20:** booleans join material at a corner, as spacing and nets did: `.#.|#.#` is one figure, its 100 nm gap reported by `notch >= 150nm`, the corner a width of 0, `min_area` 30 000; the bitmap oracle's figures are 8-connected and its F51/F53 markers are gone. |
| F52 | **A figure that touches itself at a corner is `Refused`.** Seven cells `###\|#.#\|.##` make `min_width`, `notch`, `min_area`, `min_enclosed_area`, and `min_enclosure` on its outer layer, record `Refused`, though the input is ordinary rectangles and `union_into` promises valid rings for valid input. Until fixed, whether a ring closed only at a corner encloses a hole cannot be tested. | `geom::boolean` (`link`) and `view::validate_layer_into` | Rules examine nothing on common layouts (refusals, not false cleans). Found by X3. **Fixed in C3**, which landed after X3 branched: a hole touching its outer ring at a vertex is now a ring of its own, and nothing is refused. What remains is F53. |
| F53 | **A ring closed only at a corner encloses a hole in the engine, and no hole in the bitmap oracle.** For `###\|#.#\|.##` the engine reports the centre cell as a 10 000 nm² hole and a width of 0 at the corner where the figure touches itself; the oracle, like `KLayout`'s default merge (`min_coherence` off), lets empty space pass through the corner, so there is no hole and the width is the narrowest run, 100. F51 is the same question between two figures. One corner model has to be chosen and applied by `union_into`, connectivity and every rule. | `geom::boolean` (`link`, the C3 pinch split), `drc/rules` | The engine answers both ways: `0357` gets a hole, `3d9f` (the same corner orientation) does not, because the C3 pinch split depends on where the ring walk starts. The `min_width` patterns carry this finding; the `min_enclosed_area` patterns whose holes depend on the corner model are left out of `bitmap.rs` until it is chosen (`closes_at_a_corner`). A decision, then a fix. **Fixed in B20:** a ring closed only at a corner encloses a hole (empty space 4-connected), the same under every symmetry, drawing order and ring start; the C3 split is gone, validation admits a ring passing a corner twice, and the oracle's `closes_at_a_corner` patterns are back. KLayout's source documents `min_coherence` as "less holes, more polygons", so its default should keep this hole: F1 verifies it. |
| F54 | **`extents()` merges shapes whose boxes overlap.** Two interlocking Ls with boxes `[0,1000]²` and `[200,1200]²` become one 1 360 000 nm² shape; deck.md, `DerivedOp::Extents` ("the bounding box of each shape") and `KLayout` give two 1 µm² boxes. `extents_into` documents "merged". | `geom/src/derive.rs` (`extents_into`) | Wrong input to every rule that reads a layer as stored: `forbidden`, enclosure's inner layer, `redundant_via`, `via_array_space`, `tap_distance`. Found by X2. **Fixed in B16:** `extents_into` keeps one box per merged figure, unmerged, as KLayout's `Region#extents`. |
| F55 | **`with_width` misses the corner neck `width` measures.** Two plates overlapping 50×50 at a corner: `width(a) >= 100nm` reports 70 at the neck, but `a.with_width(< 100nm)` selects nothing, because `with_width_into` calls `narrowest_width` and never `narrowest_neck`. | `geom` (`with_width_into`) | **False clean** for any rule written on a `with_width` selection. Found by X2. The same defect as F39, found by fixture; fixed together. **Fixed in B16** with F39. |
| F56 | **`min_extension` and `overlap` pair drawn pieces, not merged material.** A legal gate over a diffusion drawn as `[0,450]` + `[450,1000]` gets two false 50 nm findings at the seam; an `a` drawn as two abutting pieces that together overlap `b` by 100 gets two false 50 nm findings. | `drc/rules/overlay.rs` | False violations, the F18 pattern; a different cause from F19's boxes. Found by X2. **Fixed in B15:** A is merged and B enters the intersection whole, so pieces drawn abutting are one material. |
| F57 | **Parallel MOS whose source and drain share a net never merge.** `group_is_sound` counts distinct surviving channel nets (1, not 2) and dissolves the group: layout `nmos(g=a; s=d=b)` ×2 at W=1000 against `M0 b a b b nmos W=2000n` mismatches, and a 2.1 % W error on one such finger is judged per finger. | `lvs/reduce.rs` (`group_is_sound`) | **False mismatch.** Found by X5. **Fixed in B17:** parallel groups are not re-validated and keep the head's terminals; shorted fingers merge. |
| F58 | **The greedy symmetry break never backtracks.** It pairs devices across classes refinement cannot split, so `nmos(n0;n0,n0) + nmos(n1;n1,n2) + nmos(n2;n1,n2)` against its own netlist with the cards reversed mismatches, and so does a 3-cycle with one device 1.9 % wide. | `lvs/refine.rs` (tie break) | **False mismatch**, order-dependent. Found by X5. **Fixed in B17:** a tie-break pairing is a trial while a match is possible, undone and retried (up to 8 per stall) when it leaves a class short of layout nodes or pairs disagreeing devices. Depth one only. |
| F59 | **The cumulative antenna ratio divides all metal by all gates at the top layer.** IHP's Figure 7.1 sums one ratio per layer over the gates connected at that layer: with every gate 1 µm², M1(i) 100, M2(i) 50, M1(ii)/(iii) 2, M2(ii) 4 and M3(i) 30, IHP gives G1 160, and GPurify computes 188/3 ≈ 62.7 and passes it at a limit of 100. The rustdoc's "can under-report" names it; no finding did. | `erc/rules/antenna.rs` | **False clean.** Found by X4. **Fixed in B18:** one ratio term per etch stage, each over the gate area on the gate's net at that stage, summed per gate; IHP Figure 7.1 gives 160, and LEF C-20 gives G1 10.0 and G2 9.5. |
| F60 | **An `antenna` row cannot see a protection diode,** so a gate with one is held to the no-diode limit: IHP Ant.b flags a 2.0 ratio at 1.5 where only Ant.e (100) applies. | `erc/rules/antenna.rs` | False violation. Found by X4; the catalog notes had it. **Fixed in B18:** `antenna` takes a required `diode: layer | none`; with a layer, a gate whose net reaches it is skipped (KLayout `antenna_check`). Every shipped deck says `diode: none`: which IHP layer marks an antenna diode is a deck decision. |
| F61 | **IR drop on a ground rail is not exact on power-of-two resistances.** A 1.75 mV drop solves as 1.7500000000000002 mV, so a node exactly at a 1.75 mV limit is flagged; the same ladder on a power rail is exact, as `tests/erc_closed_form.rs` claims for both. | `erc/rules/ir.rs` | False violation at the limit. Found by X4. **Fixed in B18:** the IC(0) preconditioner is L·D·Lᵀ with no square roots, so a tree with binary-exact values solves exactly on either rail. |
| F62 | **`hv_domain` isolation drawn exactly on a device's marker does not exempt it.** The rustdoc exempts a marker "wholly covered"; the code treats the shared edge as crossing, and a 1500 mV finding is reported. | `erc/rules/domain.rs` | False violation. Found by X4. **Fixed in B18:** isolation covers a marker when one polygon's area clipped to the marker box equals the box's area, edges included. |
| F63 | **`angle` with no layer also reads derived layers,** the F50 class: a met1 rectangle with `layer copy = met1 not met2` and `angle(; allowed: [45deg, 135deg])` gives 8 findings, its 4 corners twice. | `drc/rules/grid.rs` (`angle`) | Duplicated rows. Found by B16. **Fixed in B24:** with no layer, `angle` checks the drawn layers' rows only, as `off_grid` does. |
| F64 | **A density violation can name a hole row as its shape.** A met1 ring `[0,3000]²` with hole `[1000,2000]²` under `density(met1; window: 1um, step: 1um) >= 50%`: the centre window names the hole row, not the ring's outer row (`Owners::lowest_within(window)`). | `drc/rules/area.rs` | Wrong attribution only. Found by B16. **Fixed in B24:** a density window names the lowest outer row whose box lies in it, else the layer's lowest outer row, never a hole row. |
| F65 | **A `with_width` bound loses its strictness.** Bounds are stored as whole-number inclusive limits (`> n` becomes `>= n+1`), so with the neck floored, a neck between n and n+1 (70.7 nm) is selected by `with_width(<= 70nm)` and missed by `with_width(> 70nm)`. Keeping each bound's strictness and comparing the squared neck against the stated limit is exact. | `ingest/deck` (`DerivedOp::WithWidth`), `geom/width.rs` | A selection off by one unit at a non-integer neck. Found by B16; a decision. **Fixed in B24** (as decided): bounds are squared at parse before their strictness applies, and `with_width` compares the exact squared width (`narrowest_width2`): a 70.7 nm neck is `> 70nm` and not `<= 70nm`. |
| F66 | **A spacing marker can sit on a different gap from the one measured.** Findings are placed at the middle of the gap between the rows' bounding boxes, so for a non-rectangle the marker can be away from the measured pair: `corner_to_corner/corner_beside_an_edge_gap` reports 84 at (1025, 500) for corners at (1000,1000) and (1060,1060). | `drc/rules/spacing.rs` | Usability; the rustdoc documents the placement. Found by B14. **Fixed in B24:** every spacing-family finding sits at the midpoint of the two nearest points the kind measured (a facing stretch's middle; the longest stretch, then the first found). |
| F67 | **A series merge of unsized MOS loses the stack count.** Two nmos in series, gates strapped, middle node unlabelled, against `M0 d g s s nmos` with no `l` anywhere: match. Options: refuse a series merge with no L to sum (flips corpus case `LVS_SERIES_MERGE`), or keep a stack count. | `lvs/reduce.rs` (`join_series`) | **False clean** on unsized decks. Found by B9; a decision. **Fixed in B21:** a series merge needs L stated on both devices (decided), so an unsized stack stays two; corpus `LVS_SERIES_MERGE` corrected to a mismatch (its reference states no L). |
| F68 | **Parameter presence: the X5 oracle compares `area` per paired device, the tool per kind and model.** Two `dpn` cards, one with `area=` and one without, against two drawn diodes: the tool reports `undeclared_param` on the second, the oracle says match. No fixture covers it. | `lvs/compare.rs` (`keep_declared_params`), `tests/exhaustive/lvs.rs` | Oracle and tool disagree. Found by B9; a decision. **Fixed in B21:** presence is per device (decided): a paired device is compared on the parameters its own card states, and the tie-break does the same. |
| F69 | **A duplicated terminal binds by net, not by shape.** A channel with its source drawn twice and no drain binds as a shorted device (S = D) instead of being refused. | `topology/device.rs` | A device recognised that is not drawn. Found by B9. **Fixed in B21:** a marker's polygons on a layer are grouped into shapes (touching or overlapping is one); each position needs a shape of its own, otherwise the marker is refused (`lvs.terminal_net`). |
| F70 | **`lvs.floating_net` and `lvs.label_conflict` report no layer or location.** | `lvs/checks.rs` | Usability; a location would move goldens. Found by B9. **Fixed in B21:** both rows sit at their first shape's first vertex, on its layer; `label_conflict` names the labelled polygon on each of the two nets. |
| F71 | **SPEF/DSPF name a shorted net by its first label** (`name_of`), dropping the other. The run fails on `lvs.net_seed_conflict`, so not a false pass. | `src/export/parasitic.rs` | The file loses a name. Found by B9. **Fixed in B23:** SPEF has no way to give a net a second name (`*D_NET` and `*NAME_MAP` take one), so the write is refused: `check_labels_one_to_one` returns `WriteError::ShortedLabels` with every label, before anything is written, for SPEF, DSPF and SPICE. |
| F72 | **An antenna gate attaches to metal routed over it.** A non-conductor gate joins the topmost conductor it overlaps, so an unconnected met1 strip over a gate captures it: `antenna(gate, met1; max_ratio: 1.0, sidewall: none, diode: none)` reports 6.0 where the definition gives 2.0. | `erc/rules/antenna.rs` | False violation or **false clean**. Found by B10. **Fixed in B22:** a non-conductor layer joins one conductor it overlaps: a cut, one its `connect via` rows name; any other layer, the topmost overlapped conductor that no other overlapped conductor reaches upward through the stack's cuts, so a gate is on its poly, never on metal drawn over it. |
| F73 | **A conductor at height 0 cannot be field-solved** since the substrate plane (F24): wells and diffusion in sky130, IHP, `generic_finfet` and `params.deck` are refused (`MeshError::OnSubstrate`). Their capacitance to the substrate is a junction (depletion) capacitance, not electrostatic: model them in the closed form and leave them out of the field solve, keeping the net's metal in it. | `crates/extract/src/field`, `src/engine/run.rs` | A refusal on ordinary nets. Found by B11; decided: junctions in closed form. **Fixed in B23** (as decided): a shape at height 0 is a junction: the mesh leaves it out and its closed form Ca·A + Cf·P sits on its net's capacitance-matrix diagonal, so the engine and `lib` both carry it; R through it is unchanged; `MeshError::OnSubstrate` is gone. |
| F74 | **Negative `pex` coefficients are accepted**, and their capacitance is silently dropped: `area_cap -25aF/um2 fringe_cap -40aF/um` on m1 gives ground C = 0; a negative thickness removes lateral coupling. | `ingest/deck` (`pex` row) | Fail-open on a malformed deck. Found by B11. **Fixed in B23:** the parser refuses, at the value, a pex thickness ≤ 0 and any other value < 0. Open: `dielectric 0` still means "not stated" (generic_finfet); the correct form is an optional dielectric, with 0 refused (B25). **Fixed in B25:** `dielectric` is the one optional pex key: left out it reads 0.0 (not stated); stated it must be positive, so `dielectric 0` is refused at the value. generic_finfet leaves it out. |
| F75 | **A `--quasistatic` net that cannot be meshed aborts the run** (exit 1, no report) instead of becoming a PEX refusal, and the message names the layer `LayerId(n)`. | `src/engine/run.rs` (`run_pex`) | No report. Found by B11. **Fixed in B23:** every solve error from the quasistatic solve is a PEX `Refused`; mesh refusals name the deck layer; `EngineError::Solve` is removed. |
| F76 | **The closed-form resistance of a corner-joined conductor carries current through a 0-width point.** Two bars (0,0)-(4,1) and (4,1)-(8,2) on one net are one region of area 8 and perimeter 20, read as about 9 squares (before B20, two regions chained at 8). Neither is physical; the field solver refuses the same net. | `crates/extract/src/conductor.rs`, `analytical.rs` | Low; no golden moved. Found by B20. **Fixed in B25:** a merged region is split at the corners it touches itself at (its edge-connected pieces), so the two bars are two 4-square regions chained as any two regions of a net (8 squares; C unchanged). The corner is a joint of no resistance, as the Connected corner model (B20) makes it a connection; such a layout fails DRC `width` at 0. |
| F77 | **The field solve does not converge monotonically.** A 1 µm cube reads −2.0, −0.30, +0.15, +0.20, +0.15 and +0.10 % against its published capacitance at 2, 4, 8, 16, 32 and 63 panels a side; near panels interact centroid to centroid through a softened distance rather than a panel integral. Inside the stated envelope (C6 test). Integrating near pairs exactly over the rectangle would fix it. | `crates/extract/src/field` | Accuracy, bounded. Found by B23. **Fixed in B25:** near pairs (within 3.05× the summed half-diagonals) and the diagonal take the Galerkin coefficient of potential (closed-form rectangle potential, 4×4 Gauss over the other panel, closed-form self integral); far pairs unchanged. The cube reads −1.79, −0.75, −0.27, −0.078, −0.014 % at 2–32 panels a side; C6 asserts a monotone rise with no tolerance. 27 quasistatic goldens moved (71/72 net totals fall 0.2–2.4 %; worst error against refined references 1.9 % → 1.0 %). |
| F78 | **`lib`'s PEX refusals do not name the layer:** `LibError::Pex` and `LibError::Solve` pass messages through. | `src/liberty` | Usability. Found by B23. **Fixed in B25:** `LibError::Pex` and `LibError::Solve` carry the engine's refusal text, so `lib` names the layer as `pex` does. |
| F79 | **A field-solved net that reaches a `connect global` layer is refused** (the global layer has no `pex` row, while the closed forms treat it as carrying no parasitics): in sky130, `--quasistatic VSS` through ptap and psub. Correct: leave global layers out of the mesh, as junctions are. | `crates/extract/src/field` | A refusal on the ground net. Found by B23. **Fixed in B25:** the field solves take the connectivity; global-layer shapes are out of the mesh, the junctions, the panel estimate and the inductance filaments, need no pex row, and anchor no node. sky130 VSS through ptap/psub solves; a net whose pieces join only through the substrate is refused. |
| F80 | **A net of junctions only, solved with another net, gets a coupling of −0.0,** which SPEF prints as `-0.000000`. | `crates/extract/src/field`, `src/export/parasitic.rs` | Cosmetic. Found by B23 (by reading). **Fixed in B25:** the coupling is written 0 − C_ij at the source, so a zero is +0.0 and SPEF prints no -0.000000. |
| F81 | **A derived gate lands on the diffusion in a deck with a direct diffusion–poly cut.** `ANTENNA_PROCESS` plus `connect via bc [diff, poly]`, a derived gate, `antenna(gated, met1; max_ratio: 1.0, ...)`: nothing found where 2.0 is expected. Conductors and vias alone cannot tell poly over diffusion from metal over poly. Correct: take the gate's conductor from the MOS `device` rows' gate terminal layer, which the deck already states. | `erc/rules/antenna.rs` | **False clean** in such decks; no shipped deck has the cut. Found by B22. **Fixed in B26:** the antenna stack carries each `device mos` row's gate terminal layer (its first), and a non-conductor shape over one is on it; only a shape over none falls back to the conductor-and-cut rule. |
| F82 | **Marker follow-ups from B24.** `via_array_spacing` still marks at the middle of the two cut boxes' gap (the F66 pattern, in `via.rs`); two nearest stretches of equal length pick the marker by ring order, so it is not symmetric under mirroring (`min_spacing/tucked_into_l`); `narrowest_neck` floors through an f64 square root, inexact past a squared gap of 2^53 (necks over about 94 mm on a 1 nm grid). | `drc/rules/via.rs`, `drc/rules/spacing.rs`, `geom/width.rs` | Low. Found by B24. **Fixed in B26:** `via_array_spacing` marks with the spacing family's `whole_at`; `nearest` keeps every pair at the best key and marks the middle of the box bounding their midpoints, a point that maps with the layout under all eight symmetries (for a self-mirrored pair it may lie off the gap); `narrowest_neck` floors with `isqrt` of the exact squared gap, which was also a false clean in `width` at a limit of n. |
| F83 | **Unsized MOS in parallel lose their count**, the parallel twin of F67: corpus `LVS_PARALLEL_MERGE` (two nfets in parallel against `M0 D A S S nfet_01v8`, no w anywhere) matches. Correct: keep the count in `m`, as passives do since B9, so it matches `m=2`, not one card. | `lvs/reduce.rs` | **False clean.** Found by B6/B21; decided. **Fixed in B27:** a MOS stating no W merges in parallel as a passive does, its count summed into `m`, so two unsized fingers match a card with `m=2` and not a bare card; a missing `m` reads as 1 on both sides. Corpus `LVS_PARALLEL_MERGE` encoded the bug and is corrected to a mismatch (manifest_wrong). |
| F84 | **Sized MOS merge only when both `w` and `l` are named somewhere in the run:** `LVS_SERIES` against `M0 D A S S nfet_01v8 L=100n` (no W) mismatches, with `W=200n L=100n` it matches. Correct: a parallel merge needs W, a series merge needs L, each alone. | `lvs/reduce.rs` (`ParamNames`) | False mismatch. Found by B6/B21. **Fixed in B27:** a parallel merge of MOS stating W needs only the W name; a series merge needs only L stated on both devices. `LVS_SERIES` matches `L=100n` alone and `LVS_PARALLEL` matches `W=400n` alone. |
| F85 | **A device marker with a hole is measured wrong:** a diff ring 0..2000 with a 200 wall as a diode reads area 4 000 000 for 1 440 000 and perim 8000 for 14 400, and the hole is taken as a second marker and reported as a spurious `lvs.terminal_net`. | `topology/device.rs` | Wrong parameters, a spurious row. Found by B6/B21. **Fixed in B27:** a hole row is never a marker; marker area is the outer ring less its holes and perimeter is every ring (the ring reads 1 440 000 and 14 400). |
| F86 | **A card with a value and no model (`R1 a b 1k`) is refused:** it has no deck model to pair with. Correct: bind it to the deck's one recogniser of that kind (resistor, capacitor, diode); refuse only when there are none or several. | `ingest/netlist.rs`, `lvs/graph.rs` | A legal netlist refused. Found by B6/B21; decided. **Fixed in B27:** an R, C or D SPICE card naming no model is the deck's one recogniser of its kind; none or several is `NetlistError::NoModel`, naming them. A D card with a bare number and no model stays refused: SPICE requires a diode to name its model (ngspice manual, `DXXXXXXX n+ n- mname`). |
| F87 | **Parameter-name aliases:** a diode perimeter is `pj` in ngspice and `P` (area `A`) in KLayout, so such references fail with `lvs.undeclared_param`. Correct: read them as `perim` and `area`. | `ingest/netlist.rs` | False mismatch on references written by other tools. Found by B6/B21; decided. **Fixed in B27:** on SPICE R/C/D cards, `a` reads as `area` and `p`/`pj` as `perim`; a parameter stated twice under any of its names is refused. |
| F88 | **An implementation difference with KLayout: a via cut that lands on one of its two layers.** A cut on two met1 shapes with nothing on met2, or two touching cuts that each land on one, joins those shapes in KLayout (its cut is a net member) and not in GPurify (a cut joins one shape of each of its two layers where it lands on both; `deck.md`, `topology/net.rs`). Repro: met1 (0,0)-(500,500) and (550,0)-(1050,500), via1 (450,200)-(600,300), `space(met1; nets: different) >= 100nm` reports 50. | `crates/check/src/topology/net.rs` | **Closed: a documented difference, not a defect.** Each tool follows its own documented model, and no documentation settles what an ill-formed via (one the via-enclosure rule flags) connects. The KLayout differential reports it as a difference. Found by F1. |
| F89 | **`Netlist::flatten_top` has no size limit.** 20 cells each placing the next twice, the last holding one `R`: 766 bytes give 2^20 devices (17.6 s, 370 MB in a debug build); depth 30 would exhaust memory. Count first and refuse, as GDS flattening does. | `ingest/netlist.rs` | Unbounded memory on a small input. Found by E1. **Fixed in B28:** `flatten_top` counts, before expanding and saturating, the flat devices, flat nets and instances placed, and past `MAX_FLAT_ELEMENTS` (2²⁸, the layout's cap) refuses with `NetlistError::TooLarge(count)`; a device count alone would let a device-free chain expand one net per placement. The netlist fuzz oracle checks the refusal with the same count. |
| F90 | **`flatten_labels` with `LabelDepth::All` walks arrays of cells holding only text without limit.** The pipeline uses `Top`; the limit is in the rustdoc. | `ingest/layout.rs` | Unbounded time on a crafted input, off the default path. Found by E1. **Fixed in B28:** under `LabelDepth::All` more than 2²⁸ placed labels is `LayoutError::TooManyLabels(count)` before anything is expanded, and the walk skips only cells holding neither polygons nor texts. |
| F91 | **The nightly `--ignored` run includes 9 timing and diagnostic tests that assert nothing,** and `dump_corpus` writes about 1 MB into `crates/check/`. A test that asserts nothing is not a test: move them out of the suite (examples or a bench binary). | `tests/bench_all.rs`, `crates/check/tests/lvs/digest.rs`, others | Hollow tests in a gate. Found by E1. **Fixed in B28:** the stage, per-rule and flatten timings are `examples/bench_all.rs`; the LVS corpus dump and timings are `crates/check/examples/lvs_corpus.rs` and `lvs_timing.rs`; six SIMD micro-benchmarks of private kernels are deleted (each kernel is held bit for bit by the differential test beside it). The nightly `--ignored` run holds only tests that assert, plus the bench gate `tests/scaling.rs`. |
| F92 | **A nearest stretch split into pieces is marked at its longest piece, not the whole stretch.** `space(met1) >= 101nm` on polygon (0,0),(1000,0),(1000,300),(1000,1000),(0,1000) beside rect (1050,0,2000,1000): expected 50 at (1025, 500), got (1025, 650) under every placement; `wide_at` likewise, and its wide-part rectangles depend on orientation. Merge collinear nearest pieces into whole stretches first. | `drc/rules/spacing.rs` (`nearest`, `wide_at`) | A marker off the measured stretch. Found by B26. **Fixed in B29:** `nearest` merges collinear touching stretches before taking the longest, so a side split by a vertex or by the wide part's rectangles is marked at the middle of the whole stretch; B26's tie box is kept. |
| F93 | **`liberty::circuit::node_polys` assumes one analytical node per polygon,** while the extractor allocates one per region since B20 (and per edge-connected piece since F76). One net drawn as two abutting met1 rectangles, `lib --accuracy spice`: a debug build fires the "analytical network's node allocation changed" assertion; a release build lands couplings on the wrong polygons. | `src/liberty/circuit.rs` | Wrong Liberty parasitics in release. Found by B25 (by reading). **Fixed in B29:** `analytical::node_rects` reports each region's rectangles with the node `extract_into` gives it; Liberty maps rectangles to nodes by region and places each coupling between the closest rectangles of the two regions. `node_polys` is gone. |
| F94 | **The mesh demands a positive thickness and dielectric for a junction (height-0) layer it never meshes:** the JUNCTION deck with the m1 row's `dielectric` removed, field-solving the diffusion net A, reports "layer m1: no pex row … permittivity". | `crates/extract/src/field/mesh.rs` | A false refusal. Found by B25. **Fixed in B29:** the mesh's thickness and permittivity check uses `in_field`, the predicate that decides what gets panels, so a junction or global layer needs neither. |
| F95 | **`Netlist::flatten_top` does quadratic work in the instances it places:** it scans every instance card each time it expands a subcircuit and allocates a net map the size of all nets per placement. `.subckt top a` with 100 000 `Xi a leaf` lines costs N². Index instances by their parent subcircuit and reuse one net map along the chain. | `ingest/netlist.rs` | Slow on large flat references. Found by B28. |
| F96 | **`flatten_top` recurses once per nesting level with no depth cap:** 10 000 nested `.subckt cK a` / `X1 a cK+1` / `.ends` overflows the stack (a crash on a small input). Refuse past `MAX_HIERARCHY_DEPTH` as GDS does, or walk iteratively. | `ingest/netlist.rs` | **A crash.** Found by B28. |
| F97 | **A Spectre primitive with no `model` card keeps its primitive name as its model** (`R1 (a b) resistor r=1k` never pairs with a deck resistor named `rpoly`): a false mismatch. Correct, as F86 decided for SPICE: bind it to the deck's one recogniser of its kind; none or several is `NoModel`. | `ingest/netlist.rs` (Spectre) | False mismatch. Found by B27. |
| F98 | **Asymmetric diffusions on structurally symmetric channel nets mismatch:** a lone MOS with `as=1p` on net n1 and `ad=2p` on n2 against the mirrored card (2p on n1, 1p on n2) is the same circuit once n1 and n2 swap, yet LVS reports a parameter mismatch. The tie-break must try the source/drain orientation that pairs the diffusions. | `lvs/refine.rs`, `lvs/compare.rs` | False mismatch, never a false match. Found by B27. |
| F99 | **Device counts are compared within the 2 % parameter tolerance:** `m=50` and `m=51` agree. A count is an integer: compare `m` (and `nf`) exactly. | `lvs/compare.rs` | **False clean** on large multipliers. Found by B27. |
| F100 | **Liberty measures source/drain diffusion itself** (bounding-box contact, Manhattan perimeter, holes ignored), so its values can differ from topology's `as/ad/ps/pd` on holes, diagonals or pieces. Use topology's measures. | `src/liberty/circuit.rs` | Two measures of one quantity. Found by B27. |
| F101 | **`nf` on unsized MOS:** two unsized parallel fingers keep their count in `m`, so they match `m=2` but not a card stating `nf=2` alone. No source settles whether `nf` with no W is a count of channels; recorded as documented behaviour (`docs/usage.md`), not a defect. | `lvs/reduce.rs` | **Closed: a documented behaviour.** Found by B27. |
| F102 | **SPEF had no `*DATE`** when no timestamp was given, and the CLI never gives one. IEEE 1481 `header_def` requires `*DATE qstring`; OpenSTA's grammar has no empty alternative, so it rejected every SPEF the CLI wrote. **Fixed in P1:** `*DATE ""`. | `src/export/parasitic.rs` | **Reader rejects the file.** Found by P1. |
| F103 | **SPEF stated `*L_UNIT 1 PH`**, a unit IEEE 1481 does not define (inductance: HENRY, MH, UH); OpenSTA warns (1644) and ignores the scale. **Fixed in P1:** `*L_UNIT 0.000001 UH`, every value unchanged. | `src/export/parasitic.rs` | **Wrong inductance scale in readers.** Found by P1. |
| F104 | **A deck grid with a long mantissa overflowed when squared** for an area rule (`grid 55555555555555555555555555nm`, then any area): a panic, not a typed error. **Fixed:** the square is a checked multiply that refuses with a diagnostic; the fuzz input is kept in `fuzz/regressions/deck/`. | `crates/ingest/src/deck/parse.rs` | **Panic on hostile input.** Found by the `deck` fuzz target (B30's heavy run). |

---

## 3. Bug classes and their oracles

Every row needs an oracle that does **not** recompute the answer the way the
code does.

| # | Bug class | Severity | Oracle(s) | Layer (§4) |
|---|---|---|---|---|
| B1 | **Missed violation**: the rule exists, the geometry violates it, nothing is reported | critical | planted defect at known coordinates; bitmap reference DRC; KLayout foundry decks on foundry test structures; limit monotonicity | L2, L3, L5, L6 |
| B2 | False violation | high | the same oracles in the other direction; foundry-clean open designs (standard-cell libraries) must stay clean | L3, L6 |
| B3 | **Spec misunderstanding**: the rule is implemented differently from the manual (for example, `extension`/`overlap` measure bounding boxes) | critical | foundry pass/fail test structures plus foundry KLayout decks (differential); catalog clause audit ([check-sources.md](check-sources.md)) | L6, L9 |
| B4 | Geometry robustness: booleans, touching or collinear edges, zero-area shapes, holes, huge coordinates, off-grid input | high | boolean laws in exact integer arithmetic; asserted invariants; bitmap oracle | L1, L3 |
| B5 | Rule silently examines nothing | critical | already guarded for DRC/ERC by `examined_min` and accounting; extend to LVS/PEX (F6) | L2 |
| B6 | Missing check kind (a fault of omission) | high | the catalog: every row is implemented, explicitly `Refused`, or listed in `limitations.md` | L9 |
| B7 | **LVS false match**: hierarchy (F1), reductions, symmetric tie-breaks, tolerance boundaries | critical | planted faults (short, open, extra or missing device, model swap, ΔW above tolerance) must mismatch; metamorphic invariances must keep the verdict; Netgen differential | L2, L5, L6 |
| B8 | LVS false mismatch | medium | the same metamorphic set; Netgen | L5, L6 |
| B9 | Device recognition and parameter extraction (W/L/nf/area/perimeter) | high | construct-from-answer; KLayout/Magic extraction differential | L2, L6 |
| B10 | ERC electrical value wrong (IR, EM, P2P, antenna ratio, lifetime) | high | closed forms (Ohm, Black + Blech, Arrhenius, LEF antenna ratios); metamorphic scaling; a naive dense nodal solve as reference | L2, L3, L5 |
| B11 | ERC topology wrong (floating, supply short, ESD path, domain crossing) | high | planted topology from `testgen::netlist`; a naive BFS reference over the extracted graph | L2, L3 |
| B12 | PEX value wrong | medium | analytic forms; Maxwell-matrix sign and dominance properties; mesh-refinement convergence; FastCap/FasterCap and FastHenry differential | L2, L3, L6 |
| B13 | **Nondeterminism**: PolyId order, hash order, rayon reductions | high | run twice and byte-compare; `RAYON_NUM_THREADS=1` vs N; GDS element order shuffled → identical report | L7 |
| B14 | Parser crash, hang, out-of-memory or stack overflow (F3) | high | fuzzing with "no panic, typed error, bounded time and memory"; adversarial-size inputs; GDS write→read round trip | L4, L7 |
| B15 | Deck language accepts a typo and makes a rule that does nothing | high | deck fuzzing with "every accepted rule appears in the run table"; error-span snapshots | L4 |
| B16 | Report or CLI contract drift (exit codes, JSON schema, counts in docs) | medium | snapshot (golden) of report bytes; a test that recomputes README/fixture counts | L8 |
| B17 | Performance cliffs (O(n²) paths marked `ponytail:`) | medium | scale corpus with time budgets; the bench gate | L7 |
| B18 | Liberty tables wrong | medium | ngspice re-simulation (differential); monotonic delay in load and slew; setup/hold sanity | L6, L3 |
| B19 | Tests that cannot fail | — | mutation testing | L10 |

---

## 4. The stack

The layers are listed cheapest first. Stop adding layers once §7 holds.

### L1. Assertions in production code

Assert the invariants that make B4 and B13 visible to every other layer. The
release build keeps `debug_assert!` out; the test profile turns
`overflow-checks` on.
- **geom:** after every boolean, the output rings are closed, correctly oriented, non-self-intersecting, on-grid and canonical. Holes lie inside their hull. `area(out) ≤ area(a) + area(b)` holds. `SpatialIndex` pairs are a superset of the true overlaps (debug builds, small inputs).
- **connectivity:** the net partition covers every conductor shape exactly once.
- **check:** every violation's location lies inside the layout extent. `examined ≥ 1` whenever violations > 0. A `Ran` row on an empty layer is impossible (it must be `Skipped{EmptyLayer}`).
- **extract:** the capacitance matrix is symmetric, has a positive diagonal and a non-positive off-diagonal. Resistances are > 0. GMRES returns `Converged` or an error, never a silent iteration cap.
- **Target:** at least 2 asserts per non-trivial pub fn in `geom` and `check` (TigerStyle). Count it in the review, not in CI.

### L2. Example tests at the public seams (exists; extend)

- **The corpus** (`tests/test_all.rs`): add `expect_outcome` and `examined_min` to the LVS and PEX cases (F6). **Assert `expect_match`** for every LVS case (F2). Run the quasistatic path on every PEX case that has a closed form. Generate the `counts` block and fail on drift (F5).
- **One test per catalog row:** for each DRC/ERC kind, a **pass exactly at the limit**, a **fail at limit − 1 grid step**, a **vacuous case** (empty layer → `Skipped`), and the **shape a plausible wrong implementation gets wrong** (L-shape for extension, concave corner for enclosure, touching shapes for spacing, a hole for area). `tests/drc_kinds.rs` already follows this pattern; extend its `run(deck, rects)` helper to every kind.
- **LVS planted-fault matrix** on `lvs_inv.cdl` and a hierarchical reference:
  - must mismatch: short, open, extra device, missing device, model swap, W off by 2.1%, a missing `X` instance (F1, fixed in B2), a **reversed diode** (F15, fixed in B3);
  - must match: W off by 1.9%, S/D swap, a layout series stack against a reference series stack (F12, fixed in B4).
- **Every bug fixed gets a regression test named after the bug.**

### L3. Property and reference-oracle tests (testgen, seed-scaled)

Keep `testgen`, the house generator with no dependencies. Add three things:
1. Each property runs a fast default count in `cargo test`. A `#[ignore]`d twin runs 10⁵ cases for the nightly tier (`cargo test -- --ignored`), so there are no environment knobs.
2. A failing seed is printed. It is committed to `tests/regressions/<property>.seeds`, which every run replays.
3. A ~40-line **layout shrinker** in `testgen`: drop shapes one at a time, then halve coordinates, while the failure persists. Shrinking a list of shapes is the useful kind here, and proptest's value shrinking would not do it.

Properties:
- **Boolean laws over random operands** (`crates/geom/tests/core/boolean_laws.rs`, now limited to "Phase-4" configurations):
  - A∪B = B∪A;
  - A∩(B∪C) = (A∩B)∪(A∩C);
  - A−B = A∩¬B within a bounding frame;
  - area(A∪B) = area(A) + area(B) − area(A∩B), exactly in DBU;
  - idempotence;
  - de Morgan.
  Use `random_rectilinear_layer` with holes, touching and collinear edges, and coordinates near `i32::MAX/2`.
- **Bitmap reference DRC.** This is the main new oracle. It rasterises a small layout (≤ 2000×2000 DBU) at grid resolution and implements width, space, notch, enclosure, extension, overlap, area, hole area and edge length by brute force from the *documented* semantics in `docs/deck.md`, never from the engine code. The width metric must be pinned first (Euclidean or projection; see check-sources.md §DRC semantics). The comparison is the set of violating shape ids per rule, plus violation regions up to marker placement. This would have caught the bounding-box `extension` issue.
  ```rust
  // tests/drc_reference.rs
  #[test]
  fn engine_agrees_with_bitmap_reference() {
      for seed in testgen::seeds("drc_reference") {          // env-scaled, prints on failure
          let mut rng = Rng::new(seed);
          let layout = testgen::shapes::random_small_layout(&mut rng, &["met1", "via1"]);
          let rule = testgen::rules::random_rule(&mut rng);  // kind + limit near feature sizes
          let engine = run(&rule.deck(), &layout.rects());
          let reference = bitmap::check(&rule, &layout);
          assert_eq!(engine.violating_shapes(&rule.id), reference.violating_shapes,
                     "seed {seed}: {}", testgen::shrink(&layout, |l| disagrees(&rule, l)));
      }
  }
  ```
- **Limit monotonicity:** for a minimum rule, violations(limit = a) ⊆ violations(limit = b) whenever a ≤ b. The reverse holds for maximum rules. It costs nothing and needs no reference.
- **ERC references:** a naive dense nodal solve (Gaussian elimination, ≤ 200 nodes) against `ir_drop`/`p2p_resistance`/the effective-resistance code; naive BFS over the extracted graph against the floating, supply_short, esd_topological, domain_crossing and voltage-range rules.
- **PEX:** for every field solve, the Maxwell matrix is symmetric, has a positive diagonal and non-positive off-diagonals, and its row sums are ≥ 0. Capacitance increases with overlap area and decreases with spacing (monotonicity). Capacitance converges under panel refinement, with an observed order recorded per geometry.
- **Liberty:** delay and transition are monotonic in output load and input slew. Each `.lib` table is finite and non-negative.

### L4. Fuzzing at every untrusted boundary

Use `cargo-fuzz` (nightly toolchain only in the fuzz job) plus `arbitrary`, with a `fuzz/` directory and one target per entry point:

| Target | Entry | Oracle beyond "no panic" |
|---|---|---|
| `gds` | `gds::Library::parse` (`layout.rs:589`); `read_gds_bytes` (`:70`) only gunzips a path | Typed error, never a panic. Bounded allocation (cap by input size). Accepted input → `write_store` → read gives an equal store (round trip). |
| `gds_structured` | an `arbitrary` hierarchy (SREF/AREF, depth, cycles, huge AREF counts) → writer → reader | No stack overflow (F3). A cycle is an error. Flattened shape count = Σ instances × shapes, computed independently. |
| `deck` | `deck::parse_deck` (`deck/parse.rs:95`) | Every accepted `rule` appears in the run table (B15). Every error has a span inside the input. |
| `netlist_spice`, `netlist_spectre` | `netlist.rs:737`, `:760` | Typed error. Device count = number of device cards (counted independently). |
| `intent` | `intent::parse_intent` (`intent.rs:160`) | Typed error. |
| `liberty_spec` | `liberty::spec::parse` (`src/liberty/spec.rs:376`) | Typed error. |
| `drc_e2e` | `arbitrary` small layout + one rule → engine vs bitmap reference | The L3 oracle, now coverage-guided. |

- Seed each target with the corpus GDS cells, the four `pdks/*.deck`, `lvs_inv.cdl` and the docs examples.
- Commit minimised crashers under `fuzz/regressions/<target>/`.
- A plain `#[test]` replays that directory on stable, so the merge gate needs no nightly toolchain.

### L5. Metamorphic relations (whole corpus plus generated layouts)

Each relation is a transform of the input and a predicted transform of the
output.

**DRC/ERC geometry:**
- translation by a random vector;
- rotation by 90°, 180° and 270°, and mirroring in x and y (expected markers transformed; direction-dependent rules excluded and listed);
- scaling by an integer k with every rule length × k and area × k²;
- GDS element order shuffled;
- one polygon split into abutting rectangles (touching shapes are one shape, `docs/deck.md`);
- hierarchy vs flattened GDS;
- GDS layer renumbering with the deck remapped;
- unrelated geometry added farther away than the largest rule distance (existing violations unchanged).

**LVS:**
- device order and net names permuted;
- S/D swapped on MOS;
- the layout transformed;
- parallel devices split into fingers (verdict unchanged);
- the reference flattened vs hierarchical (catches F1).

**ERC/PEX:**
- sheet resistance × k → IR drop × k;
- a parallel conductor added → P2P resistance never increases;
- a protection diode added → antenna violations never increase;
- the dielectric constant × k → C × k (homogeneous stack).

### L6. Differential against independent tools (nightly)

A differential test runs at most two external tool processes at a time and kills any it
starts when it finishes or times out. One that ran a Netgen per core (32 at about 850 MB each)
exhausted a 31 GB machine.

The tools are open and in nixpkgs. Add a `nix develop .#oracles` shell with
`klayout`, `magic-vlsi`, `netgen-vlsi` and `ngspice`, plus FasterCap/FastHenry
built from source.

- **Foundry decks on foundry test structures.** This is the most important new oracle (B3). For each of `sky130`, `gf180mcu` and `ihp_sg13g2`, run the foundry's own KLayout DRC deck and GPurify's `pdks/*.deck` on (a) the PDK's DRC test-structure GDS and (b) open standard-cell libraries and one open chip. Compare violation counts and markers **per rule id**.
  - **The test structures exist** ([check-sources.md](check-sources.md) §2.3):
    - IHP: `testing/testcases/unit/<table>.gds` plus `unit_golden`, one per rule table, and ~316 LVS GDS/CDL pairs;
    - GF180 `fd_pv`: 59 unit GDS with golden `.lyrdb`, and ~132 LVS test files;
    - sky130: `test_violators.gds` and efabless `lvs/testing`.
  - **The goldens are a second oracle.** The foundry deck's own golden results let GPurify be compared without running KLayout.
  - **Pin versions.** Pin each repo to a commit in the `.#oracles` shell.
  - Every disagreement is triaged into a ledger (`tests/fixtures/xcheck/<pdk>.json`) as GPurify-wrong, reference-wrong or semantics-differ, with a reason, like the corpus's `dispute` field.
  - Agreement count is a ratchet: it never decreases.
  - Rules with no counterpart are listed with the reason.
- **Mirror deck: GPurify deck → generated KLayout script** (`tests/klayout/translate.rs`, which replaced the hand-written families in `drc_oracle.rb`).
  - **Shape:** one translation per DRC kind, with every semantic pinned explicitly: metric (`euclidian`/`square`/`projection`), `whole_edges`, shielding, merged semantics, `min_projection`.
  - **Inputs:** the corpus plus L3's random small layouts plus the §6 at-limit/limit−1 layouts.
  - **Oracle:** per rule id, the same violating shapes and markers within one grid step.
  - **What it catches:** *implementation* bugs on any deck, for every kind. It does not catch spec misreadings: the translator encodes our reading, so the foundry-deck comparison above stays the spec oracle.
  - **Validating the translator:** each kind's mapping is reviewed once, and KLayout must also pass the §6 cells.
  - **Skip list, with reasons:**
    - `multi_patterning`: KLayout has no colouring solver; the oracle is brute-force k-colouring of small conflict graphs;
    - ERC electrical kinds: KLayout has no electrical solve; closed forms and the naive nodal solve stay the oracle;
    - net-aware spacing and soft connection: allowed only if the pinned KLayout version supports them; check this first.
  - **ERC:** `antenna_check` covers `antenna`/`antenna_electrical`. Floating, short and unconnected-pin checks are scripted over KLayout's extracted netlist.
- **LVS:** Netgen (and KLayout LVS) on the LVS cells and on generated netlist→layout pairs (`testgen::netlist::layout_from_netlist`). Compare verdicts; every disagreement is triaged.
- **Extraction:** Magic `ext2spice` and KLayout device extraction against GPurify device W/L/nf and net partition on the PDK test structures.
- **PEX:** FasterCap (C) and FastHenry (L/R) on the 27 PEX cells and on generated crossovers and parallel lines. The tolerance is stated per geometry class. Known model gaps (no reflected images, `matvec.rs:59-61`) are carried as annotated expected deviations until fixed.
- **Liberty:** ngspice re-simulation of a sample of table points (the one-off in `docs/liberty.md:129-160`, automated).

### L7. Determinism, scale and adversarial size

- **Determinism gate:** the golden test (L8) runs every corpus case twice and byte-compares the runs. A test builds one rayon pool with 1 thread and one with all threads, and byte-compares the field-solve outputs.
- **Scale:** `testgen::scale_corpus` at 10⁴, 10⁵ and 10⁶ polygons with time and memory budgets per stage (the bench gate `tests/scaling.rs`: ns/poly at 16× within 3× of 1× in one run; tables in `examples/bench_all.rs`). Each `ponytail:` O(n²) comment gets a scale test that fails when n crosses its documented ceiling.
- **Adversarial inputs:** a GDS hierarchy 10⁵ levels deep (F3); one polygon with 10⁶ vertices; an AREF of 10⁹ elements (must refuse or stream, never allocate 10⁹); coordinates at ±2³¹; a deck with 10⁴ rules; a netlist with 10⁵ parallel devices (reduction must stay near-linear).

### L8. Golden snapshots (report contract)

- Check in `tests/golden/<domain>/<case>.<output>`, one file per corpus case and CLI output (the runs the deleted `tools/gate/golden.sh` made), reviewed once.
- `tests/golden.rs` runs the real binary and diffs bytes. A missing file is written and fails the test, so a new golden is always reviewed. To re-bless an intended change, delete the files and rerun; the diff shows in review. Plain files are enough; insta adds nothing here.
- A doc-count test computes the rule-kind counts, corpus counts and strength table, and fails when `README.md` or `tests/fixtures/README.md` disagree (F5, F10).

### L9. Catalog traceability (fault-of-omission control)

[check-sources.md](check-sources.md) is the requirements list. A test
(`tests/catalog.rs`) loads its machine-readable table (`docs/check-catalog.tsv`)
and asserts:
- every name in the `gpurify` column that is not a tagged feature (`deck:`, `erc:`, `lvs:`, `pex:`, `ingest:`, `lib:`) exists in `drc/ruleset.rs` `KINDS`, `erc/ruleset.rs` `KINDS` or the LVS ids (`checks.rs:21`);
- every one of those kinds appears in at least one row (no undocumented kinds);
- every `implemented`/`partial` row has at least one test that names its id;
- every `missing` and `partial` row appears in `docs/limitations.md`;
- there are no `verify` rows at release (§7);
- the status counts in check-sources.md §1 match the file.

The current status counts are the table in check-sources.md §1, which this test checks.

This turns "what the foundries and tools check that we don't" into a list
that cannot drift.

### L9b. Rust decks and custom rules (planned feature)

The text deck stays fast and non-scriptable. The escape hatch, always
available, is a **deck built in Rust**:
- a builder producing the same `Deck` the parser does (`crates/ingest/src/deck/mod.rs:47`);
- overrides by rule id (`replace`/`remove`/`add`; replacing an absent id is an error);
- a `Rule::Custom { id, inputs, check: fn(&View, &mut Findings) }` kind;
- the user ships their own binary via `gpurify::cli::main_with(deck)`.

User code is a new input surface, so the hook has its own tests:

| Property | Oracle |
|---|---|
| Text and Rust decks are the same thing | Every shipped `pdks/*.deck` has a Rust-built twin in a test; `parse(text) == build(rust)` field by field |
| The builder validates like the parser | Every `DeckError` variant has a builder test that triggers the same error (no unit, impossible bounds, `<=` on a minimum, unknown layer, duplicate id) |
| A shared deck survives printing | Deck printer round trip: `parse(print(d)) == d` for every shipped deck and for generated decks (fuzz target `deck` gains this as a second oracle). Printing a deck with custom rules refuses or names them, and never drops them silently. |
| Consumers read what the checker enforces | For every rule in every shipped deck, the query API's value (`min_spacing(layer)`, spacing-table lookup at random width/run) equals the limit the checker reports in a violation's `limit` field on a planted case |
| Overrides are explicit | `replace` of an absent id errors; `remove` then `add` of the same id equals `replace`; override order does not change the result |
| Accounting survives user code | A custom rule on an empty input layer reports `Skipped{EmptyLayer}`, never `Ran`. Examined counts come from the runner. A custom rule that finds nothing on a populated layer reports `Ran` with examined > 0. |
| Determinism survives user code | A custom rule returning findings out of order or duplicated still yields canonical bytes. A deliberately nondeterministic custom rule (time-seeded) fails the run-twice byte comparison the golden test uses. |
| A failing custom rule fails the run | The release profile is `panic = "abort"` (`Cargo.toml:73`). A panic hook names the custom rule that was running, and the run exits non-zero, never passing silently. Debug/test builds unwind, and there the rule becomes `Refused` and the report continues. |
| Findings are sane | A finding outside the layout extent, or on a layer the rule did not declare as input, is an assertion failure (L1) |

Custom rules have no KLayout mirror by default. A custom rule may carry an
optional KLayout snippet for L6. A custom rule without one is listed in the
cross-check output as *unverified*, so a user's deck shows which of its rules
nothing independent checks. A catalog kind marked `missing` can be prototyped
as a custom rule. It is promoted to a built-in kind only with the full §6
matrix.

### L10. Coverage and mutation (measurement, not targets)

- **Coverage:** `cargo llvm-cov` region coverage on `crates/geom` and `crates/check`, as a ratchet stored in `tools/coverage-floor.txt`. Branch coverage (`-Zcoverage-options=branch`) runs nightly for information. Every uncovered region is tested, asserted unreachable, or deleted.
- **Mutation:** `cargo mutants` (already in `flake.nix`) weekly on `crates/check/src/{drc,erc,lvs}` and `crates/geom/src`, with `--in-diff` on PRs that touch them. Every surviving mutant is either killed by a new test or recorded in `tools/mutants-accepted.txt` with a reason.

---

## 5. Gates

The tiers follow the methodology's "Not Rocket Science Rule": main always
passes, and the merge result is what gets tested.

| Tier | Budget | Contents |
|---|---|---|
| **Local** | < 30 s | `cargo test -p <crate>` for the crate touched; `cargo fmt --check` |
| **Merge** (required) | < 15 min | fmt, clippy (`clippy::correctness` deny, as now); `cargo test --workspace` (debug, `overflow-checks` on; it covers the corpus, goldens and determinism); fuzz regression replay; L3 properties at the default count; L5 metamorphic on the corpus; doc-count test; catalog test; `cargo mutants --in-diff` when `check`/`geom` changed |; `cargo doc`; the fuzz crate compiles on stable; `cargo mutants --in-diff` on geom and check against each crate's own tests (a missed mutant fails)
| **Nightly** | hours | `cargo fuzz run` for 1 h per target; `cargo test -- --ignored` (L3 at 10⁵ cases per property, seeds logged); L6 differential (KLayout, Netgen, Magic, FasterCap, FastHenry, ngspice) in `nix develop .#oracles`; scale budgets and the bench threshold; branch coverage; ratchet checks |. As wired in `.github/workflows/nightly.yml`: `cargo fuzz run` 1 h per target (nightly toolchain only in that job, corpus cached); `cargo mutants` on a rotating tenth of geom and check, score (caught+timeouts)/(caught+timeouts+missed) ≥ 75 % geom, ≥ 65 % check; `cargo llvm-cov` region coverage ≥ 96 % geom, ≥ 95 % check (measured 2026-10-10: mutation 82.4/76.6 % geom, 69.9/67.5 % check on shards 0 and 5; coverage 97.0 % geom, 96.3 % check). The L6 differentials (`tests/klayout`, and F3's) run in the release tier. Heavy work runs on GitHub Actions, not a developer machine: `nightly.yml` also runs on a pull request labelled `heavy`, and its `oracles` job runs the L6 differentials in `nix develop .#oracles`
| **Weekly** | a day | full `cargo mutants` on `check` and `geom`; fuzz for 8 h per target |
| **Release** | unbounded | §7 checklist; all three PDK cross-checks with the ledger reviewed; aarch64 run (native or qemu); one soak of 24 h fuzz per target |

**Flaky policy:** a flaky test is quarantined the same day with an issue. The
merge gate never retries silently. Every random test prints its seed, so a
"flaky" failure can be reproduced from the seed.

---

## 6. Per-check test matrix template

Every row of the catalog gets these cells. A missing cell is a visible gap,
not an oversight.

| Cell | DRC/ERC kind | LVS feature | PEX quantity |
|---|---|---|---|
| Pass at limit | ✔ | match at tolerance −ε | within tolerance |
| Fail at limit − 1 step | ✔ | mismatch at tolerance +ε | — |
| Vacuous → `Skipped` | ✔ | empty cell → `Inconclusive`/skipped | no nets → refused |
| Wrong-implementation shape | ✔ (L, concave, hole, touching) | symmetric ambiguity | non-rectangular conductor |
| Reference oracle | bitmap, naive solve, closed form | Netgen | FasterCap/FastHenry/analytic |
| Metamorphic | L5 set | L5 set | L5 set |
| Foundry cross-check | KLayout deck on test structures | Netgen on PDK cells | — |

---

## 7. Release exit criteria

Every criterion is a number or a yes/no that a script can check.

1. The corpus passes with zero unannotated failures. Every case in all four domains carries `expect_outcome`; every LVS case asserts its verdict.
2. F1–F43 are closed, each with a regression test.
3. Boolean laws and every L5 relation have passed ≥ 10⁶ generated cases in total, with no failure in the last 7 nightlies.
4. The bitmap-reference differential has shown no disagreement over ≥ 10⁵ random layouts per supported DRC kind.
5. Each fuzz target has run ≥ 24 CPU-h with no new crash and coverage flat for the last 25% of the run.
6. Foundry cross-check: per-rule agreement on each PDK's test structures is ≥ the last release's, and every disagreement in the ledger has a reason. Foundry-clean standard cells report zero GPurify errors.
7. Netgen agrees on every LVS fixture and on ≥ 10³ generated netlist/layout pairs.
8. PEX is within the stated tolerance of FasterCap/FastHenry on every PEX cell, or carries an annotated model gap.
9. The determinism gate is green: byte-identical reports twice, with 1 and N threads, and with shuffled element order.
10. Region coverage of `geom` and `check` is not below the floor. The mutation-survivor list is triaged with zero unexplained entries.
11. The catalog test is green: every `missing` row is in `limitations.md`, and every implemented kind has its §6 cells.
12. Scale budgets are met at 10⁶ polygons.
13. The README, fixtures README and `limitations.md` numbers come from the doc-count test.
14. Once Rust decks ship: every `pdks/*.deck` equals its Rust twin, every `DeckError` has a builder twin, and the custom-rule contract tests (L9b) are green.

---

## 8. Order of work and progress

Since 2026-10-11 the work runs in parallel on branches `agent/<id>`, each a
draft pull request into `verification-hardening`, built and tested only by
GitHub Actions (the merge tier on every push; the nightly tier on a pull
request labelled `heavy`); nothing is built on the development machine.

This is one ordered list covering this plan and the
[deck-library plan](deck-library-plan.md). Work happens on branch
`verification-hardening`, with one commit per line. Each commit also updates
the docs it affects: this table, catalog rows, `limitations.md`, README
counts. A refactor never lands before the safety net that guards it: the
golden snapshots (A3) come before any LVS or deck change.

Status: `todo`, `doing`, `done`, `dropped` (with a reason). Each commit's subject ends with its id, so `git log --grep '(A3)'` finds the work for a line.

| # | Item | Plan refs | Status |
|---|---|---|---|
| A1 | Planning docs: this plan, check-sources.md, check-catalog.tsv, deck-library-plan.md | — | done |
| A2 | Doc-count test; fix the stale counts and claims (README kinds, fixtures README, `counts` block, `limitations.md` esd_latchup, `ci.yml` GPU comment) | F5, F10, L8 | done |
| A3 | Golden report snapshots run by plain `cargo test` (`tests/golden/`; delete a file and rerun to re-bless; no env vars, no scripts); every corpus case run twice and byte-compared; RAYON 1 vs N; `tools/gate/` deleted | F7, L7, L8 | done |
| A5 | Every `implemented`/`partial` catalog row cites a test that names its id; `tests/catalog.rs` asserts it | L9 | done: `every_supported_catalog_row_is_proved` (`tests/exhaustive/main.rs`) covers every implemented/partial/expressible row of every domain, flow included; a `PROVED_BY_TEST` test's doc names its row |
| S1 | Minimal CLI. Runtime flags are only the required inputs (`<layout>`, `--deck`, `--reference`, `--intent`; `lib`: `--spec`, `--lef`, `--output-dir`), the output form (`--format`) and the method choice (`--quasistatic <net>` for PEX, `--accuracy` for `lib`). Grid from the GDS UNITS record; unknown-layer policy in the deck (`ignore gds(L, D)`); `--output`, `--quasistatic-inductance`, `--check-determinism`, `--work` removed | user direction | done |
| A4 | `tests/catalog.rs` (L9 assertions); `limitations.md` lists every missing/partial catalog row | L9, B6 | done |
| B8 | LVS: rows only for configured checks, so a clean LVS run can pass | F17 | done |
| R1 | Rustdoc pass. Crate docs that explain the project; every DRC/ERC kind and LVS discrepancy documented with its definition (what it measures, deck spelling, the foundry and tool sources from check-sources.md, the catalog id); `missing_docs` and broken intra-doc links denied by crate attributes, so `cargo doc` alone enforces it | user direction | done |
| B1 | LVS: every corpus case asserts its verdict against its own reference netlist (the planted-fault matrix moves to X5) | F2, L2 | done |
| B2 | LVS: flatten reference `X` instances | F1 | done |
| B3 | LVS: diode/capacitor polarity | F15 | done |
| B4 | LVS: series reduction symmetric between sides | F12 | done |
| B5 | LVS: dead `net_seed_conflict`; labelled short reported, not aborted; split-name lookup | F13, F14 | done |
| B6 | LVS: passive parameters (R/W/L, C, perimeter), positional values | F16 | done (the rest in B27) |
| B7 | sky130 deck: antenna rows triaged against the source and corrected to Table Ig; a test pins them | F11 | done |
| B9 | LVS: passive and polarity-aware reduction (sum R/C by the device's law; no merging across polarity); `m` without `W`; parameter presence per kind; dead `lvs.terminal_net`; order-independent terminal recognition | F20, F21, F22, F32, F33 | done |
| B10 | ERC: Blech length via-to-via; guard-ring width measured, not bounding-boxed; soft connection only through declared joins; `multiple_drivers` that understands complementary gates; antenna areas merged | F25–F29 | done (F28 closed in B22) |
| B11 | PEX and export: filaments joined through touching shapes and vias, or refused; a substrate plane in the field solve; no fail-open conductors; duplicate quasistatic names refused; split-label nets refused in SPEF/DSPF | F23, F24, F30, F31 | done |
| B12 | The small ones | F34, F35 | done |
| B13 | PEX: the field-solve mesh is translation invariant; the reciprocity gate is relative to the diagonal | F46, F47 | done |
| B14 | DRC spacing from merged figures: ends of line, hole edges, parallel run, corner-to-corner | F42, F43, F48, F49 | done |
| B15 | DRC overlay and edge rules from merged material: extension, overlap, touching pairs, edge length (closes C5's first item) | F18, F19, F41, F56 | done |
| B16 | Derived layers and the die: `extents` per shape, `with_width` as `width` measures, density die from drawn layers, `off_grid` on drawn layers; the F34 details | F34, F39, F40, F50, F54, F55 | done |
| B17 | LVS: shorted-channel parallel merge, a tie break that cannot pair across unsplittable classes | F57, F58 | done |
| B18 | ERC: IHP's per-layer cumulative antenna ratio, protection diodes on `antenna`, exact IR at the limit, `hv_domain` isolation on the marker's edge | F59, F60, F61, F62 | done |
| B19 | PEX: closed forms over merged conductors; a field-solved polygon as its own filaments | F44, F45 | done |
| B20 | Geometry: one corner model for booleans, connectivity and every rule. **Decided: Connected** — corner contact joins material; a ring closed only at a corner encloses a hole; the touch point is a 0-width neck | F38, F51, F53 | done |
| B21 | LVS follow-ups: an unsized series merge is refused (decided); parameter presence per device (decided); a duplicated terminal binds by shape; floating_net and label_conflict located | F67, F68, F69, F70 | done |
| B22 | ERC follow-ups: drivers oriented by intent's rails, Skipped without intent (decided); an antenna gate joins only metal connected to it | F28, F72 | done |
| B23 | PEX follow-ups: wells and diffusion as closed-form junctions outside the field solve (decided); negative pex coefficients refused; an unmeshable net a PEX refusal; SPEF keeps every name of a shorted net | F71, F73, F74, F75 | done |
| B24 | DRC follow-ups: parallel run by facing-edge projection (decided); with_width keeps each bound's strictness (decided); angle on drawn layers; density and spacing markers on the measured shapes | F49, F63, F64, F65, F66 | done |
| B25 | PEX and deck follow-ups: an optional dielectric with 0 refused; global layers out of the mesh; layer names in `lib`'s refusals; no −0.0 coupling; near-panel integrals; closed-form R of a corner-joined conductor | F74, F76, F77, F78, F79, F80 | done |
| B26 | Small follow-ups: an antenna gate's conductor from the MOS device rows; via_array_spacing markers on the measured pair; ties broken symmetrically; an exact integer neck | F81, F82 | done |
| B27 | LVS follow-ups: unsized parallel MOS keep a count; W and L needed per merge kind; markers with holes; model-less cards bound to the deck's one recogniser; pj/A/P aliases; MOS as/ad/ps/pd and BJT emitter area (B6's rest) | F16, F83, F84, F85, F86, F87 | done |
| B28 | Infra follow-ups: a bench gate that asserts ns/poly stays flat across sizes within one run (decided, no stored baseline); `flatten_top` counted before expanding; label flattening bounded; hollow timing tests out of the suite | F89, F90, F91 | done |
| B29 | PEX and DRC follow-ups: Liberty's node map per region; the mesh asks nothing of a layer it does not mesh; a nearest stretch merged before it is marked | F92, F93, F94 | done |
| C1 | GDS hierarchy depth limit; adversarial-size inputs | F3, L7 | done |
| C2 | testgen `prop`: seeds by property name, committed regression seeds replayed every run, greedy shrinking (rectangle layouts); `#[ignore]`d nightly twins instead of env knobs | F8, L3 | done |
| C3 | Boolean laws over random operands | L3 | done |
| C4 | L5 metamorphic relations: every corpus cell under the seven other symmetries and a translation (`tests/exhaustive/corpus.rs`); limit monotonicity is the X1/X2 limit sweeps | L3, L5 | done |
| C5 | Bitmap reference DRC, kind by kind; fix what it finds (bbox `extension`/`overlap` first) | L3, B1, B3 | done: the bitmap reference (X3) and its first fixes (B15) |
| C6 | ERC naive references (dense nodal solve, BFS); PEX matrix properties and monotonicity | L3 | done: ERC (erc_reference.rs: dense nodal solve, graph search) and PEX (X6 laws; mesh convergence and passivity) |
| C7 | Assertion pass on `geom` and `check` (runs alongside C3–C6) | F9, L1 | doing (agent/c7) |
| X0 | Exhaustive-fixture harness `tests/exhaustive/`: fixtures run in memory through the real reader, symmetry and translation transforms, expected-failure markers tied to findings, catalog-row coverage per complete domain; `min_width` as the worked example | user direction, §6 | done |
| X1 | Exhaustive fixtures: DRC dimension, spacing and integrity kinds | DRC-001…038 | done |
| X2 | Exhaustive fixtures: DRC overlay, cut, density, presence and edge kinds, and the derived-layer operations | DRC-040…123 | done |
| X3 | Exhaustive fixtures: a bitmap reference DRC and every pattern of small cell grids (supersedes C5) | C5, L3 | done |
| X4 | Exhaustive fixtures: every ERC kind, closed forms and enumerated topologies (supersedes C6 for ERC) | ERC-* | done |
| X5 | Exhaustive fixtures: LVS over every small circuit and every single fault, against a brute-force isomorphism; device classes, reductions, hierarchy | LVS-* | done |
| X6 | Exhaustive fixtures: PEX analytic geometries, matrix laws, refinement convergence (supersedes C6 for PEX) | PEX-* | done |
| D1 | Deck library P0: `gpurify::pdks` constants | deck §5 | doing (agent/d) |
| D2 | Deck library P1: `CompiledDeck`, engine takes it, validation on typed rules | deck §5 | doing (agent/d) |
| D3 | Deck library P2: query API with the shared spacing-threshold function | deck §5 | doing (agent/d) |
| D4 | Deck library P3: builder, overrides with provenance, printer, macro kind table | deck §5, L9b | doing (agent/d) |
| D5 | Deck library P4: custom rules, `gpurify::cli::main_with` | deck §5, L9b | doing (agent/d) |
| E1 | `fuzz/` targets + stable regression replay (deck round trip needs D4) | L4 | done (the deck round trip waits for D4's printer) |
| F1 | `.#oracles` nix shell; KLayout mirror-deck translator per [klayout-mirror.md](klayout-mirror.md) (23 kinds exact, 11 approximate, `multi_patterning` none); retire the stale `drc_oracle.rb` families | L6 | done: tests/klayout (release tier: corpus, merge-depth DRC fixtures, 3000 random layouts; 23 kinds exact, 11 approximate, multi_patterning none); reconciled with B24 (angle on drawn layers, with_width measured exactly); found F88 |
| F2 | Foundry-deck cross-check: sky130, gf180mcu, IHP, with ledgers | L6, F4 | doing (agent/f2) |
| F3 | Netgen and FasterCap/FastHenry differential; Liberty ngspice spot checks | L6 | done: netgen_differential (all 4223 X5 circuits × every single fault + 17 curated; series-MOS merge and near-equal-L parallel merge are documented differences), fastcap_differential (FastCap 2.0 with image conductors, 25 geometries / 74 entries, 2.5 % default mesh, 0.5 % fine cube), fasthenry_differential (12 geometries, R 1e-4, L 1 %), ngspice_differential (inverter, 16 table points within 0.5 % + 0.1 ps, leakage 1e-4); FastCap 2.0 is the reference (FasterCap is not packaged); the full Netgen run is nightly-only, and a disagreement it finds is triaged, never allowed |
| O1 | ERC against open-source tools: antenna ratios against KLayout `antenna_check` and OpenROAD's antenna checker; IR drop against OpenROAD PDNSim; topology rules (floating gates, multiple drivers) against KLayout's netlist and Yosys where they express them. Each kind's oracle, setup and tolerance documented | L6, ERC-* | doing (agent/o1) |
| O2 | Analytical PEX against Magic's extraction (`extract`, `ext2spice` with R and C) under a tech file carrying the same coefficients; FastCap/FastHenry cover the field solve (F3) | L6, PEX-001…005 | done: `magic_differential` (Magic 8.3.629: extract with capacitance, coupling and lumped R, ext2spice cthresh 0) on X6's analytical geometries x8 symmetries and 300 seeded random-wire layouts, one GDS; C within 1e-4 + 5e-6 fF (1 aF below 1 aF), R within 1e-4 + 2 mΩ; documented differences: Magic's overlap shields the upper plate's area C, Magic's lumped R omits vias and lumps a layer's pieces, Magic's sidehalo is exclusive |
| P1 | A second independent oracle for every check no open tool performs (`check-sources.md` §4a): LVS-020, LVS-066, LVS-071, ERC-D3, ERC-F6, ERC-F12, PEX-010, FLOW-005; `tests/catalog.rs` `EVIDENCE_GAPS` may only shrink | §4a, L9 | done: each row has a second independent oracle: LVS-020/066/071 MR, ERC-D3/F6/F12 NV (a search from each net over 300 random circuits), PEX-010 SE (an IEEE 1481 reader), FLOW-005 FR + MR; `EVIDENCE_GAPS` is empty. No OpenSTA differential: it is not packaged alone in the pinned nixpkgs (it builds only inside OpenROAD) |
| T1 | Test audit: every test has an oracle; delete those that assert nothing, have no oracle, duplicate another exactly, test nothing of this project, or test dead behaviour (each deletion and its reason in the commit body); past-bug regression tests and golden snapshots stay | methodology, L1–L10 | done: 14 of 897 tests deleted (asserted nothing that can fail, no oracle, exact duplicates, or tested only std/derived code), each with its reason in the commit body; no catalog row lost its proof |
| T2 | Test audit follow-ups: an `Oracle:` line on the 267 useful tests that lack one; strengthen the doubtful ones (an infeasible colouring names its documented node; `net_spacing` without nets asserts its row count; drop the duplicated case from `an_unreducible_graph_comes_through_byte_identical`); the LVS digest locks state their review log as their oracle; fix the stale docs T1 listed | methodology | done (PR #3): every #[test] (895) has an Oracle: line (347 added), tests/oracles.rs fails on one without; the doubtful tests assert their documented answers; the stale docs fixed. Three oracles are weak and stated as such: a load error order no doc states, a seed-independence test that compares one draw per seed, and the 4223-circuit count from a one-off Python enumeration not in the repo (T3) |
| T3 | Strengthen the three weak oracles T2 named: document (or test against) the order `load` refuses deck and layout errors; make the seed-independence test compare streams as its doc says; commit an independent count of the 4223 canonical circuits (a second enumeration by a different method) | methodology | done (PR #19): load's rustdoc says which error wins with several inputs at fault is not a contract, and the test asserts each missing input is its own variant; the seed test compares the first 64 draws of 256 adjacent seed pairs (SplitMix64 avalanche within Binomial(256, 1/2) at 6 sd); the 4223 count is derived in the repo by Burnside counting per net count (9 / 221 / 1354 / 2639) |
| B30 | Netlist flattening: a depth cap or an iterative walk, and linear expansion | F95, F96 | doing (agent/b30) |
| B31 | LVS follow-ups: Spectre model-less primitives bound as SPICE's (decided); a diffusion-aware source/drain orientation; counts compared exactly (decided); Liberty reads topology's diffusion measures | F97, F98, F99, F100 | doing (agent/b31) |
| G1 | Coverage floor, mutation gate, bench thresholds; nightly CI workflow | L10, §5 | done; bench gate `tests/scaling.rs` (ns/poly at 16× within 3× of 1×, one run, alone on the runner) |
| H | Catalog gaps in the priority order of check-sources.md §4, one kind per commit | check-sources §4 | doing, in nine branches: agent/h1 DRC spacing; h2 DRC overlay and cut; h3 DRC dimension, integrity, density, device, chip; h4 DRC multi-patterning, DFM, infra; h5 ERC antenna and EM; h6 ERC voltage, DRC net, PERC; h7 ERC ESD and latch-up; h8 LVS; h9 PEX and flow |
| H10 | Cheap wins brought into scope: DRC-068 (GDS-vs-GDS XOR, cut-area conservation between two databases), PEX-007 (temperature-dependent R from PDK coefficients, CMP thickness variation), DRC-113 (litho/CMP hotspots, as far as public models allow) | catalog | done: DRC-068 partial (`gpurify xor`, KLayout differential; sky130's per-connector cut-count tolerance is not written: its text gives an area limit in µm and no definition of a connector), PEX-007 partial (deck `temperature` + per-layer tc1/tc2, also driving EM derating; CMP, via-current and colour effects need foundry data), DRC-113 partial (`density_cmp` is the first-order public CMP hotspot model, Ouma 2002; litho needs foundry models) |
| H11 | Reliability and power brought into scope: ERC-E11 (vectorless dynamic IR), ERC-E13 (thermal-aware and statistical EM, self-heating) | catalog | todo |
| H12 | All-angle geometry brought into scope: DRC-038 (diagonal width and spacing) and DRC-116 (curvilinear / all-angle tolerance); every geometric rule handles 45-degree, then arbitrary-angle edges, checked against KLayout | catalog | todo |
| H13 | Multi-die and system brought into scope: LVS-073 (3D / system LVS across dies), ERC-C12 (package / 2.5D / 3D ESD), ERC-C13 (system-level ESD) | catalog | todo |
| B32 | LVS and PEX cases carry the no-vacuous-pass guard DRC and ERC have (expected outcome, minimum examined) | F6 | doing (agent/b32) |
| R2 | Catalog refresh: public commercial-tool material (Calibre, ICV, Pegasus, StarRC, Quantus, RedHawk, Voltus, PathFinder datasheets, public user-guide excerpts, papers; never leaked manuals) compared against the catalog; missing checks added as rows with their sources | catalog | todo |
| S2 | Shipped decks gain the foundry rules the new kinds make expressible (each with its source), checked by F2's foundry cross-check | F4, limitations | todo: after the H branches merge |
| R3 | Settle DRC-076 (sky130 waffle-window step and band edges) and DRC-068 (sky130 per-connector cut-area tolerance) from public sources and the public decks implementing them; implement what they settle, record what they do not | catalog | doing (agent/r3) |
| H14 | Cell-name scoping and exemptions (DRC-092; with it DRC-097's cell-name and pcell rules): each flattened polygon keeps the cell it came from | catalog | doing (agent/h14) |

**How code on this branch is written:**
- **Data-oriented.** Answer the six questions (data in/out, how many, how wide, access pattern, lifetime, parallelism) before writing. SoA tables, the narrowest type the range allows, caller-owned `_into` buffers, indices not pointers, as the existing crates do.
- **SIMD where a loop earns it.** Through `fearless_simd`, with the scalar loop kept as tail, fallback and oracle. Differential-tested over lengths 0 to 3× the lane count, and benchmarked; a slower vector loop is reported and dropped.
- **Docs ship with code.** Every public item a commit adds or changes has rustdoc that carries a fact the signature cannot (rank: precondition, invalidation, ownership, failure, cost, why). User docs (`docs/*.md`, README) change in the same commit.
- **Plain cargo.** `cargo test` is the suite and `cargo build --release` the shipped binary (fat LTO stays), with no env overrides, scripts or extra flags in the flow.

Decisions taken for the deck library (deck-library-plan §6), using the
recommended options:
- typed constructors from one macro table;
- the code lives in `gpurify-check`, re-exported from `gpurify`;
- custom rules are `fn` pointers;
- no text overlays.

---

## 9. Out of scope, stated

- Foundry signoff equivalence on production silicon. The commercial decks are under NDA; see check-sources.md for what can and cannot be verified.
- Non-rectilinear geometry: a 45° layout loads and `angle` checks it; every other geometric rule records `Refused` on such a layer (limitations.md, "Geometry"). Its tests check those refusals, not that 45° geometry is measured.
- Bit-exactness of the field solver across architectures: tolerance only, stated per quantity.
