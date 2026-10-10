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
- 757 `#[test]`, 11 of them `#[ignore]` (timing and diagnostics only).
- Per-rule accounting, which makes vacuous passes visible.
- The corpus records evidence grades and derivations.
- Closed-form ERC tests (`tests/erc_closed_form.rs`).
- Construct-from-answer DRC tests on foundry wording (`tests/drc_kinds.rs`, `tests/sky130_rules.rs`).
- Scalar-vs-SIMD equivalence tests.
- The `testgen` generators.

**Problems found while writing this plan.** Each one becomes a task in §8.

| # | Finding | Where | Why it matters |
|---|---|---|---|
| F1 | **Subcircuit instances in the reference netlist are dropped from the LVS graph.** `from_reference` takes only the top subcircuit's own devices; `X` cards are parsed (`netlist.rs:506`) but never flattened. | `crates/check/src/lvs/graph.rs:180`, called from `src/engine/run.rs:333` | A layout missing a whole sub-block that the schematic places by `X` instance can match. This is a false clean, the worst LVS bug class. |
| F2 | **The LVS corpus never asserts `expect_match`.** Its 16 cases check only device and net counts. Inside the corpus the full compare runs once, on `lvs_inv.cdl` (`test_all.rs:197`). Outside it, `tests/engine/main.rs:193,450,467` and the 22 tests in `crates/check/tests/lvs/compare.rs` check verdicts on hand-built graphs. | `tests/common/mod.rs:1053-1106`, stated in `crates/check/tests/lvs/reduce.rs:4-7` | The corpus cells, the ones with derived answers, have no verdict oracle. |
| F3 | GDS hierarchy traversal recurses with a cycle check but **no depth limit**. | `crates/ingest/src/layout.rs:1313` (`visit`) | A deep, legal hierarchy overflows the stack. This is the same class as SQLite's `median()` quicksort bug: found after full coverage and fuzzing, because fuzzers prefer small inputs. |
| F4 | The corpus GDS uses **invented layer numbers** (1/0–14/0) and a synthetic deck (`params.deck`). The README calls it "real GDSII cells drawn for a real PDK". | `tests/fixtures/_source/conformance.gds`, `README.md` Accuracy section | The shipped foundry decks (`pdks/*.deck`) run only on hand-drawn rectangles for a few rules (`tests/sky130_rules.rs`, `tests/engine/main.rs:397`, `tests/derived_layers.rs:287`), never on foundry test structures or real designs. Spec misunderstanding of a foundry rule is the class nothing currently sees. |
| F5 | **Counts have drifted.** README says 24 DRC / 19 ERC kinds; the code has 35 / 24 (`drc/ruleset.rs:915`, `erc/ruleset.rs:20`). The fixtures README says 161/160 cases; there are 167. The stored `counts` block in `expectations.json` is stale for ERC, and README copies it. `known_defects` cite paths that no longer exist. | `README.md:89,148-156,240`, `tests/fixtures/README.md:3,7,81-91` | Documentation is an output too. Every one of these numbers can be computed by a test. |
| F6 | Only DRC and ERC cases carry `expect_outcome` and `examined_min`. LVS and PEX cases have neither, and PEX cases run only the analytical path. | `tests/common/mod.rs:583-590,1174` | The "no vacuous pass" guarantee covers 124 of 167 cases. |
| F7 | Nothing automated runs `--check-determinism`, `tools/gate/*`, `drc_oracle.rb`, `cargo-mutants` (described as "the acceptance gate" at `flake.nix:36`), or any benchmark. | `ci.yml` | A gate that never runs is not a gate. |
| F8 | There are no fuzz targets, no shrinking, and fixed seeds only. Each generated test runs one seed for 8–2048 iterations. | `crates/testgen` | Property tests cannot scale up at night, and a failure gives no minimal case. |
| F9 | Assertion density is low: 17 production asserts in geom, 7 in check, 2 in extract, 2 in ingest. | grep | Fuzzers and property tests can only see what an assertion or a comparison flags. |
| F10 | `docs/limitations.md:102` says no test checks `esd_latchup` numbers, but `test_all.rs:770` does. `pdks/README.md` is referenced but missing. | | The doc says less than the tests prove. |
| F11 | **sky130 `ar.met3.1` antenna sidewall is 2000 nm, but the same deck's `pex met3` thickness is 845 nm.** met4 and met5 agree with their thickness; met1 and met2 are 350 nm against a PEX thickness of 360 nm (`:469,471` vs `:626,628`). Philis's vendored copy corrects it to 845 nm, citing Magic's sky130A.tech. Philis's copy also differs from GPurify's in 39 lines (`# PHILIS:` edits). | `pdks/sky130.deck:473` vs `:630`; `Philis/pdks/decks/sky130.deck` | Probably a deck bug; confirm against the deck's antenna source table (Table Ic). This is also a cheap oracle class, **deck self-consistency**: where a deck states the same physical quantity twice (antenna sidewall vs PEX thickness, EM width vs min width), a test checks they agree or carry an annotation. |
| F12 | **The reference netlist never series-reduces, and the layout does.** `from_reference` names every reference net (`graph.rs:194`), and `join_series` refuses any named node (`reduce.rs:403`). A drawn transistor stack with an unlabelled internal node merges into one device with L summed, while its reference twin stays as two devices. No test pairs a layout series stack with a reference one. | `crates/check/src/lvs/graph.rs:194`, `crates/check/src/lvs/reduce.rs:403` | **False mismatch** on valid stacked circuits (B8). A likely fix is to refuse series merges only at reference *ports*, not at every named net. The L2 planted-fault matrix needs a "stack vs stack → match" case. |
| F13 | **`lvs.net_seed_conflict` can never fire.** Port binding already errors out on two names on one net (`topology/port.rs:72`), so `resolved == seeds` always holds. | `crates/check/src/lvs/checks.rs:214-233` | A rule that reports `Ran` but cannot find anything is exactly the hollow pass the accounting is meant to rule out. Mutation testing (L10) flags such a rule as a surviving mutant; delete it or make it reachable. |
| F14 | **A short between two labelled nets aborts extraction** (`PortError::ConflictingLabels`, `pipeline.rs:181`): the run fails with a net id, with no report row and no location. Separately, **`PortTable::net_of` resolves a name on several nets to the lowest one** (`port.rs:33-37`). That affects `--quasistatic` (`run.rs:384`), Liberty (`src/liberty/circuit.rs:106`) and the netlist exporter (`src/export/netlist.rs:326-345`). Intent is not affected: `resolve_intent_into` visits every piece (`erc/facts.rs:154-199`). | `src/engine/pipeline.rs:181`, `crates/check/src/topology/port.rs:33-37` | The first does not pass, but it cannot be debugged from the report. The second field-solves, characterises or exports only one piece of a split net. |
| F15 | **Diode anode/cathode and capacitor plates are interchangeable in LVS.** Diodes and capacitors get `Pin(0)`/`Pin(1)` roles (`graph.rs:301`), and every `Pin(_)` shares one role code (`refine.rs:69`), so a reversed diode matches. | `crates/check/src/lvs/graph.rs:291-302`, `crates/check/src/lvs/refine.rs:58-69` | **False clean** (B7). Netgen permutes resistor ends but not capacitor plates; nobody permutes a diode. |
| F16 | **LVS compares few device parameters.** Extraction gives MOS `w`/`l` and the marker `area` only (`topology/device.rs:301-329`). No resistor R/W/L, capacitor C, perimeter, `nf` or BJT emitter area. A parameter only the reference declares becomes `undeclared_param`, and the positional `R1 a b 1k` form is refused (`netlist.rs:447-453`). | `crates/check/src/topology/device.rs:301-329`, `crates/check/src/lvs/compare.rs:255-313` | Wrong-size passives match (B9). Catalog rows LVS-060–064. |

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
  - must mismatch: short, open, extra device, missing device, model swap, W off by 2.1%, a missing `X` instance (fails today, F1), a **reversed diode** (fails today, F15);
  - must match: W off by 1.9%, S/D swap, a layout series stack against a reference series stack (fails today, F12).
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
- **Mirror deck: GPurify deck → generated KLayout script** (`tools/klayout/translate.rs`, replacing the 9 hand-written families in `drc_oracle.rb`).
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
- **Scale:** `testgen::scale_corpus` at 10⁴, 10⁵ and 10⁶ polygons with time and memory budgets per stage (`tests/bench_all.rs` becomes a gated nightly job with a ±10% threshold against a rolling baseline). Each `ponytail:` O(n²) comment gets a scale test that fails when n crosses its documented ceiling.
- **Adversarial inputs:** a GDS hierarchy 10⁵ levels deep (F3); one polygon with 10⁶ vertices; an AREF of 10⁹ elements (must refuse or stream, never allocate 10⁹); coordinates at ±2³¹; a deck with 10⁴ rules; a netlist with 10⁵ parallel devices (reduction must stay near-linear).

### L8. Golden snapshots (report contract)

- Check in `tests/golden/<domain>/<case>.<output>`, one file per corpus case and CLI output (the runs `tools/gate/golden.sh` made), reviewed once.
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

As of 2026-10-10 there are 237 rows: 68 implemented, 6 expressible, 65 partial, 88 missing, 0 verify, 10 out of scope.

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
| **Merge** (required) | < 15 min | fmt, clippy (`clippy::correctness` deny, as now); `cargo test --workspace` (debug, `overflow-checks` on; it covers the corpus, goldens and determinism); fuzz regression replay; L3 properties at the default count; L5 metamorphic on the corpus; doc-count test; catalog test; `cargo mutants --in-diff` when `check`/`geom` changed |
| **Nightly** | hours | `cargo fuzz run` for 1 h per target; `cargo test -- --ignored` (L3 at 10⁵ cases per property, seeds logged); L6 differential (KLayout, Netgen, Magic, FasterCap, FastHenry, ngspice) in `nix develop .#oracles`; scale budgets and the bench threshold; branch coverage; ratchet checks |
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
2. F1–F16 are closed, each with a regression test.
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
| A3 | Golden report snapshots run by plain `cargo test` (`tests/golden/`; delete a file and rerun to re-bless; no env vars, no scripts); every corpus case run twice and byte-compared; RAYON 1 vs N; `tools/gate/` deleted | F7, L7, L8 | todo |
| S1 | Minimal CLI. Runtime flags are only the required inputs (`<layout>`, `--deck`, `--reference`, `--intent`; `lib`: `--spec`, `--lef`, `--output-dir`), the output form (`--format`) and the method choice (`--quasistatic <net>` for PEX, `--accuracy` for `lib`). Grid from the GDS UNITS record; unknown-layer policy in the deck (`ignore gds(L, D)`); `--output`, `--quasistatic-inductance`, `--check-determinism`, `--work` removed | user direction | todo |
| A4 | `tests/catalog.rs` (L9 assertions); `limitations.md` lists every missing/partial catalog row | L9, B6 | todo |
| R1 | Rustdoc pass. Crate docs that explain the project; every DRC/ERC kind and LVS discrepancy documented with its definition (what it measures, deck spelling, the foundry and tool sources from check-sources.md, the catalog id); `missing_docs` and broken intra-doc links denied by crate attributes, so `cargo doc` alone enforces it | user direction | todo |
| B1 | LVS: assert `expect_match` in the corpus; planted-fault matrix | F2, L2 | todo |
| B2 | LVS: flatten reference `X` instances | F1 | todo |
| B3 | LVS: diode/capacitor polarity | F15 | todo |
| B4 | LVS: series reduction symmetric between sides | F12 | todo |
| B5 | LVS: dead `net_seed_conflict`; labelled short reported, not aborted; split-name lookup | F13, F14 | todo |
| B6 | LVS: passive parameters (R/W/L, C, perimeter), positional values | F16 | todo |
| B7 | sky130 deck: antenna sidewall vs PEX thickness, triaged against the source; deck self-consistency test | F11 | todo |
| C1 | GDS hierarchy depth limit; adversarial-size inputs | F3, L7 | todo |
| C2 | testgen: env-scaled seeds, seed replay, layout shrinker | F8, L3 | todo |
| C3 | Boolean laws over random operands | L3 | todo |
| C4 | Limit monotonicity; L5 metamorphic relations on the corpus and on generated layouts | L3, L5 | todo |
| C5 | Bitmap reference DRC, kind by kind; fix what it finds (bbox `extension`/`overlap` first) | L3, B1, B3 | todo |
| C6 | ERC naive references (dense nodal solve, BFS); PEX matrix properties and monotonicity | L3 | todo |
| C7 | Assertion pass on `geom` and `check` (runs alongside C3–C6) | F9, L1 | todo |
| D1 | Deck library P0: `gpurify::pdks` constants | deck §5 | todo |
| D2 | Deck library P1: `CompiledDeck`, engine takes it, validation on typed rules | deck §5 | todo |
| D3 | Deck library P2: query API with the shared spacing-threshold function | deck §5 | todo |
| D4 | Deck library P3: builder, overrides with provenance, printer, macro kind table | deck §5, L9b | todo |
| D5 | Deck library P4: custom rules, `gpurify::cli::main_with` | deck §5, L9b | todo |
| E1 | `fuzz/` targets + stable regression replay (deck round trip needs D4) | L4 | todo |
| F1 | `.#oracles` nix shell; KLayout mirror-deck translator | L6 | todo |
| F2 | Foundry-deck cross-check: sky130, gf180mcu, IHP, with ledgers | L6, F4 | todo |
| F3 | Netgen and FasterCap/FastHenry differential; Liberty ngspice spot checks | L6 | todo |
| G1 | Coverage floor, mutation gate, bench thresholds; nightly CI workflow | L10, §5 | todo |
| H | Catalog gaps in the priority order of check-sources.md §4, one kind per commit | check-sources §4 | todo |

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
- Non-rectilinear geometry: refused by design (`limitations.md:9`). Its tests check that refusal happens, not that 45° geometry is measured.
- Bit-exactness of the field solver across architectures: tolerance only, stated per quantity.
