# Audit: `crates/check/src/erc/` (READ-ONLY)

All paths relative to `/home/omare/Documents/Projects/Rust/GPurify/crates/check/src/erc/` unless stated.
Grep scope for "used": `crates/*/src`, `src/`, `tests/`, `crates/check/tests/` (non-test src = code above each file's `#[cfg(test)]`).

---

## 0. Headline findings

1. **Live bug on the shipped PDK deck (accuracy).** `ruleset.rs:467` pushes `blech_limit` **once per row**. The other EM columns are extended **once per layer** (`ruleset.rs:462-466`). `rules/electrical.rs:659` asserts `layer.len() == blech_limit.len()`, and `:705` slices `blech_limit[span]` using the *layer* span. `pdks/generic_finfet.json:129-133` has 2- and 4-layer `electromigration` rows. Consequences:
   - A debug build panics on any ERC run with that deck, because the assert sits above the intent gate.
   - A release build with intent reads the *wrong row's* Blech limit (row 0 gets `[em_li, em_met1]`, so licon uses met1's Blech). By row 3 it slices out of bounds and panics.
   - `tests/fixtures/expectations.json` already records this in prose. No code test covers it.
   - Fix (1 line): `table.blech_limit.extend(layers.iter().map(|_| blech));`. The row-parallel assert at `ruleset.rs:768` then becomes layer-parallel.
2. **~420 lines of `esd_latchup` / `esd_topological` "clamp" machinery can never run from a deck.**
   - `ruleset.rs:502-515` always closes `clamp_start` over an empty `clamp_model`, because `ParamValue` cannot carry a model name.
   - So `ClampGraph`, `PathSearch`, `attach_terminal`, `interconnect` and Dijkstra (`rules/reliability.rs:705-1074`) never see an edge. `lowest_resistance` returns `None` on `lo == hi` (`:975`), so every pad net is flagged `Count(0)`.
   - No test ever fills the latchup clamp columns either: `dispatch.rs:204-208` and `intent_gate.rs:505-509` leave them empty.
3. **Every `LayerRef::Named` branch in ERC is unreachable.**
   - `from_deck` only ever writes `LayerRef::Base(..)` (`ruleset.rs:381-384, 399-402, 443, 525-526, 546-547, 611-612, 619-620`).
   - No ERC test builds a `Named` layer (0 grep hits in `crates/check/tests/erc`).
   - So `base_layer`, `base_layers_into`, `tap_geometry`'s derived arm, and 9 `Outcome::Refused` arms are dead. The tables should hold `LayerId`.
4. **Two builders for the same resistor model.**
   - `power::extract_into` (`power.rs:1189-1603`, 415 lines) and `power::extract_nets_into` (`:2348-2588`, 241 lines) repeat the same passes: conductor compact, connections, centre/metal/via taps, device taps via `TapIndex`, `TapTable::finish`, `ChainProfile` chain edges, metal-link edges, via edges.
   - Supply nets are extracted twice.
5. **Defensive noise.**
   - 431 `debug_assert*` statements over 1,173 lines.
   - ~2,000 comment lines out of 9,423 non-test lines.
   - 10 hand-rolled `unsafe` "branchless compact" loops (~20 lines each) where `filter().collect()` gives identical output.

---

## 1. DATA IN / DATA OUT

### Inputs (as assembled by `src/engine/run.rs:400-512` `run_erc`)

| Input | Type | Source | Read by |
|---|---|---|---|
| deck rules | `gpurify_ingest::deck::Deck` + `StrTable` | `loaded.deck` | `RuleSet::from_deck` (`ruleset.rs:339`) |
| geometry | `GeometryStore` | `loaded.store` | everything (via `Design`) |
| derived layers | `Evaluator` | `extracted.derived` | only via the unreachable `LayerRef::Named` arms (`topology.rs:205`, `supply.rs:711`) |
| nets | `NetTable` | `extracted.nets` | facts, power, all topo rules |
| devices | `DeviceTable` | `extracted.devices` | facts, power (device taps), multiple_drivers, hv_domain, esd |
| ports | `PortTable` | `extracted.ports` | `resolve_intent_into` only |
| design intent | `Option<&DesignIntent>` | `loaded.intent` | `resolve_intent_into` into `IntentMap` |
| process | `Process { grid: Grid, stack: &ProcessStack, connectivity: &Connectivity }` | deck | power extraction (sheet_res_ohm_sq, height_nm, conductors, via_cut/via_connects, intra_layer_touch) |
| die | `Bbox` | `design_extent(loaded)` | density_cmp only |
| grid | `Grid` | `run_grid` | em_current_density, electromigration (A/m × width) |
| temperature | `Qty<Temperature>` | `sign_off_temperature()` (hard-coded 85 °C) | electromigration, reliability |

Derived intermediate tables that the engine builds and threads through:
- `NetFacts` from `classify_nets_into`.
- `IntentMap` from `resolve_intent_into`.
- `NetNetworks` from `extract_nets_into`.
- `PowerGrid` from `extract_into`.
- `PowerSolution` from `solve_into`.
- These are packed into `Solved` and `RunInputs`.

### Outputs
- `Violations` (appended) and `Vec<RuleRun>` (appended, one per configured row: `Ran`, `Skipped(NoDesignIntent)` or `Refused`).
- Error returns:
  - `ErcError` at deck parse. This fails the engine.
  - `PowerError`: the engine maps it to `StageStatus::Refused(String)`.

### Real API: pub items used outside `erc/` in non-test code

| Item | User |
|---|---|
| `RuleSet::from_deck`, `RuleSet::run`, `RuleSet::len` | `src/engine/run.rs:407,492-509` |
| `ruleset::KINDS` | `src/engine/run.rs:209`; `tests/bench_all.rs` |
| `ErcError` | `src/engine/run.rs:1107` |
| `Design` (re-export of `crate::Design`), `Scratch::default` | `run.rs:421,491` |
| `NetFacts`, `classify_nets_into` | `run.rs:433-434` |
| `IntentMap`, `resolve_intent_into` | `run.rs:440-441` |
| `NetNetworks`, `PowerGrid`, `PowerSolution`, `Solved`, `PowerError` (Display) | `run.rs:448-489` |
| `power::{Process, extract_nets_into, extract_into, solve_into, SolveScratch, SolveConfig::default}` | `run.rs:427-483` |
| `RunInputs` | `run.rs:494` |
| `power::NetNetworks` | `crates/testgen/src/electrical.rs:3` (test-data generator) |

Everything else under `pub` is used only inside `erc/` or by tests: the 19 table structs, the `check_*` fns, `RoleMask`, `EdgeKind`, `effective_resistance_into`, `RuleHead`, etc. The engine is a thin sequencer of 7 calls that `erc` could do itself.

---

## 2. Module map

| File | Lines (total / non-test) | Comments (non-test) | debug_assert (stmts / lines) | Purpose |
|---|---|---|---|---|
| `mod.rs` | 212 / 212 | 63 | 5 / 17 | `ErcError`, `Scratch`, report helpers (`first_vertex`, `centre`, `push_net_violations`, `skip_rows`, `refuse_rows`) |
| `facts.rs` | 352 / 352 | 86 | 22 / 68 | `RoleMask` per net; `IntentMap` = intent re-keyed onto `NetId` |
| `ruleset.rs` | 979 / 979 | 106 | 66 / 113 | `KINDS`, `RuleSet` (19 tables), deck parser, dispatcher |
| `power.rs` | 3365 / 3128 | 720 | 111 / 402 | Layout into resistor networks; CG+IC(0) supply solve; Kron+Cholesky effective resistance |
| `rules/mod.rs` | 7 | 1 | 0 | module list |
| `rules/topology.rs` | 570 | 126 | 29 / 95 | floating_gate, floating_well, multiple_drivers, unconnected_pin |
| `rules/supply.rs` | 1361 | 269 | 63 / 132 | supply_short, soft_connection, missing_tie (tap grid + branch-and-bound), tie_high_low, esd_topological |
| `rules/antenna.rs` | 1080 / 992 | 201 | 51 / 132 | antenna, antenna_electrical, density_cmp |
| `rules/electrical.rs` | 711 | 200 | 38 / 113 | p2p_resistance, ir_drop, em_current_density, electromigration |
| `rules/reliability.rs` | 1103 | 251 | 46 / 101 | reliability (lifetime model), hv_domain, esd_latchup |
| **Total** | **9,740 / 9,423** | **~2,020** | **431 / 1,173** | |

Tests: `crates/check/tests/erc/*` is 5,168 lines over 11 files, about 115 tests. Coverage notes:
- The power laws, effective-resistance laws, dispatch and intent gate are well covered.
- **Not covered:**
  - multi-layer `electromigration` through `from_deck` (the bug in §0.1);
  - any `LayerRef::Named`;
  - any latchup clamp;
  - `extract_into` / `extract_nets_into` are covered only end-to-end (`tests/test_all.rs`, `tests/engine/pipeline.rs`).

### `power.rs`: what it does, and what is essential

About 3,128 non-test lines: 720 comment, 402 `debug_assert`, 186 blank, **about 1,820 lines of code**.

| Section | Lines | What | Essential? |
|---|---|---|---|
| Types (`PowerError`, `Process`, `EdgeKind`, `PowerGrid`, `NetNetworks`, `SolveConfig`, `PowerSolution`, `SolveScratch`) | 36-495 | SoA output tables and workspace | Yes. ~150 code lines once the 95-line assert blocks in `node_count`/`edge_count`/`len`/`edges_of` go |
| `ElimGraph` (Kron elimination, half-edge pool, min-degree) + `cholesky_inverse_into` | 497-726 | Exact effective resistance for p2p | Yes. **Order-sensitive** |
| `assemble_into`, `factorise_into` (IC(0)), `precondition`, `conjugate_gradient` | 728-1117 | Supply-grid DC solve | Yes. **Bit-sensitive** |
| `Solved`, `discarded_budget`, `load_on` | 1119-1172 | Budget-never-reached detector | Yes (small) |
| `extract_into` | 1174-1603 | Supply grid build (loads, pads, per-edge width/len/layer/kind) | Yes, but ~60% duplicates `extract_nets_into` |
| `TapIndex` | 1605-1844 | Nearest-shape ring search (device to shape) | Yes |
| helpers: `conductor_mask`, `sheet_resistances`, `Connections`, `TapTable`, `tap_on`, `tap_point`, `ChainProfile`, `conductor_width`, `run_length`, `via_length`, `squares` | 1846-2339 | Chain model | Yes |
| `extract_nets_into`, `net_slice` | 2341-2603 | Per-net CSR networks | Yes, but duplicates the above |
| `solve_into` | 2605-2894 | Validation, pad elimination, rhs, CG, scatter back, currents | Yes |
| `effective_resistance_into` | 2896-3127 | Probe | Yes |

Essential code after the cuts is about **1,450-1,550 lines**. That removes the ~180 duplicate lines, 3 unsafe compacts (~60), `fixed_voltage`, `SolveConfig`, `shrink`, write-only fields (~40), and all asserts and most comments. So power.rs could shrink from 3,128 to about 1,600 non-test lines with no algorithm change.

---

## 3. Dead code (verified by grep)

"Test-only" means no non-test reference outside its own definition.

| Location | Item | Status |
|---|---|---|
| `mod.rs:86-88` | `Scratch::shrink` | **No caller anywhere** (the only `.shrink()` call is the drc Scratch in `tests/drc/determinism.rs:129`) |
| `power.rs:487-495` | `SolveScratch::shrink` | **No caller anywhere** |
| `power.rs:212-227` | `PowerGrid::fixed_voltage` | test-only (`tests/erc/power_grid_laws.rs`) |
| `power.rs:342-363` | `SolveConfig` (+ `Default`) | only `SolveConfig::default()` is ever constructed (`run.rs:479`, tests). Make it 2 consts |
| `power.rs:376-377` | `PowerSolution::iterations` | write-only outside tests |
| `power.rs:377` | `PowerSolution::relative_residual` | read only by the `is_finite` check in `is_consistent_with` |
| `power.rs:99-102` | `EdgeKind::Via { cuts }` | `cuts` is always `1` (`power.rs:1574`), so `allowed_current` (`electrical.rs:366`) multiplies by 1.0. Reduce to `Via` |
| `facts.rs:219-224` | `IntentMap::supply_count` | test-only (`intent_gate.rs`) |
| `facts.rs:191,282` | `IntentMap::undeclared` | never written (comment `:320` admits it), never read |
| `facts.rs:82-87,143-153` | `NetFacts::terminals` | computed, read only by `tests/erc/net_facts.rs:279`. The doc claims multiple_drivers uses it; it does not |
| `facts.rs:106-116` | `NetFacts::role_of` | used only by `is_device_connected` (inline it) |
| `facts.rs:33` | `RoleMask::ANY` | test-only |
| `facts.rs:178,196-199` | `IntentMap::supply_domain`, `supply_of` | only caller is the dead clamp path `reliability.rs:791` |
| `rules/reliability.rs:42`, `ruleset.rs:595,776` | `ReliabilityTable::mechanism` | write-only (it duplicates `head.rule`) |
| `rules/reliability.rs:86-95,445-498,705-1074` | `clamp_start/model/resistance/capacity/voltage`, `ClampGraph`, `PathSearch`, `ClampEdge`, `push`, `clamp_row`, `attach_terminal` | unreachable from a deck (§0.2); never tested with data |
| `rules/reliability.rs:97-100`, `ruleset.rs:488-490` | `required_current`, `max_path_resistance`, `max_clamp_voltage` | parsed and validated, but only ever compared against the empty clamp columns, so they cannot affect a verdict |
| `rules/supply.rs:69-72,617-618,666-670` | `EsdTopologicalTable::clamp_start/clamp_model` | always empty from a deck, so `protected` is always false. Only `supply_rules.rs:620-700` fills it by hand |
| `mod.rs:96-101` + 12 call sites | `base_layer` and every `LayerRef::Named` / `Refused` arm | unreachable (§0.3): `topology.rs:186-189,194-213`; `supply.rs:96-101,213-230,423-435,700-713`; `antenna.rs:119-136,539-550,621-643,742-753` |
| `rules/antenna.rs:27-34,375-378,541-543` | `AntennaMeasure::Sidewall` | parsed from the deck, then always `Refused`. Could be a per-row `refused: bool` |
| `mod.rs:135-140` | `ascending()` | only feeds the `(net, T)` tuples whose `T` is never read by `push_net_violations` (`mod.rs:148-179` reads only `.0`) |

Count: about **620 lines** (clamps ~420, Named ~80, the rest ~120), plus the fields' test fixtures.

---

## 4. Bloat

| # | Location | What | Est. deletable |
|---|---|---|---|
| B1 | all files | 431 `debug_assert*`, 1,173 lines. Almost all are column-parity checks on SoA structs (e.g. `power.rs:147-206` spends 55 lines on two `len()` getters; `ruleset.rs:688-801` `debug_assert_shape` is 114 lines; `rules/reliability.rs:133-142,387-403` are header blocks). Keep maybe 10 that guard real invariants (`fixed_voltage`/`source_node` ascending, `TapTable` order) | **~1,100** |
| B2 | all files | ~2,020 comment lines. Many are multi-paragraph rationale on private fns (`power.rs:1129-1142`, `electrical.rs:614-640`, `supply.rs:1188-1210`) and repeated SAFETY/induction prose (the same 6 lines × 10 sites) | **~1,100** (keep ~1 line per item) |
| B3 | `topology.rs:97-121`; `supply.rs:136-156,251-269,284-301,554-574,637-655`; `power.rs:1238-1264,1288-1327,2383-2404` | 10 hand-rolled `unsafe` MaybeUninit compacts. `iter().filter().collect()` / `retain` gives identical, stably ordered output | **~170**, and removes all `unsafe` in erc |
| B4 | `power.rs:1189-1603` vs `2348-2588` | Duplicate network builder (§0.4). One `build_rows(shapes_by_net, links, devices)` producing per-net CSR with all edge columns. The supply grid = the supply nets' rows plus loads/pads. **See §7 A5: edge order must be preserved for bit-exact CG** | **~180-220** |
| B5 | `reliability.rs:705-1074` + table fields + `ruleset.rs:488-490,502-507` + `supply.rs:617-670` | Dead clamp machinery (§0.2) | **~420** |
| B6 | `antenna.rs:502-581` vs `589-682` | `check_antenna` and `check_antenna_electrical` are the same loop with an optional diode. `AntennaTable` and `AntennaElectricalTable` should be one table with `diode: Option`, `credit`, `bonus` (0 for plain antenna) | **~80** |
| B7 | `electrical.rs:522-575` vs `641-711`; tables `:57-96` | `em_current_density` = `electromigration` with `blech=[]`, `derate=1`. One table with optional Blech/Arrhenius columns | **~50** |
| B8 | `mod.rs:184-208` | `skip_rows` / `refuse_rows` twins, so use one `fill_rows(head, outcome, ..)` | ~12 |
| B9 | `electrical.rs:246-276` | Dense `limit_row_of_net` table plus the assert that it equals `intent.limits_of` (`:293-297`). Use `intent.limits_of(net)` (binary search; same answer) | ~30 |
| B10 | `electrical.rs:403-426` | Dense `limit_of_layer` plus its own equivalence assert. `layer.iter().position()` over ≤4 layers has the same "first wins" semantics | ~20 |
| B11 | `electrical.rs:27`, `reliability.rs:26` | `BOLTZMANN_EV_PER_K` defined twice | 3 |
| B12 | `power.rs:1206-1222, 2359-2368` | 15- and 10-line field-by-field `.clear()` blocks: `*out = Default::default()` or a `clear()` method (capacity reuse is irrelevant at 1 call per run) | ~20 |
| B13 | `power.rs:743-842` | `assemble_into`'s "bin past the last row" branchless trick (`cursor`, `diag` sized `n+1`, `col/value` sized `nnz+1`, `both*…+(1-both)*nnz`) is 100 lines. An `if a != NONE && b != NONE` version is ~40, with the same float op order | ~50 |
| B14 | `power.rs:2641-2733` | Four "fold a flag, then `position()` again to name the culprit" blocks. `position()` alone does it | ~40 |
| B15 | `ruleset.rs:118-138,334-338,640-651` | `narrow()`, `close_csr` assert, `too_many_lines` allow prose, deck-count assert | ~20 |
| B16 | `ruleset.rs:843-971` | 19 `if !head.is_empty()` guards. `check_*` already loop 0 rows. Keep a guard only where work is hoisted above the row loop (multiple_drivers, esd_latchup, ir_drop's dense table). Otherwise use a direct call | ~40 |
| B17 | Parallel representations | (a) `PowerGrid` vs `NetNetworks`: same chain model, two SoA layouts (flat vs CSR-per-net). (b) Three nearest-neighbour grids: `power::TapIndex` (points, i128), `supply::TapGrid` (segments), and the dead `reliability::attach_terminal` (linear). (c) `IntentMap` re-keys `DesignIntent`, which already has the same `supply_net/supply_domain/supply_role` SoA (`crates/ingest/src/intent.rs:46,71-77`) | (a) covered by B4; (b) `attach_terminal` goes with B5 |
| B18 | `facts.rs:20-27` | `BULK/BASE/EMITTER/COLLECTOR/PIN` exist only so `of()` gives distinct bits. No rule distinguishes them; `NONE`, `GATE`, `SOURCE`, `DRAIN` and "other" suffice | ~8 (optional) |
| B19 | `src/engine/run.rs:400-512` | 110 lines of engine code sequencing 7 erc calls (see §5) | ~80 moved/removed |

**Total ERC deletable, estimated: about 3,300-3,500 of 9,423 non-test lines (~36%)**, with no verdict change. The table rows overlap somewhat, so this is lower than the arithmetic sum.

---

## 5. Proposed simple API

```rust
// crates/check/src/erc/mod.rs — the whole public surface
pub use ruleset::{RuleSet, KINDS};           // RuleSet::from_deck(&Deck, &StrTable) -> Result<Self, ErcError>
pub use power::PowerError;
pub struct Inputs<'a> {
    pub design: Design<'a>,                  // store, nets, devices (+derived, unused by erc)
    pub ports: &'a PortTable,
    pub intent: Option<&'a DesignIntent>,
    pub process: power::Process<'a>,         // grid, stack, connectivity
    pub die: Bbox,
    pub temperature: Qty<Temperature, { prefix::BASE }>,
}
/// Build facts, intent map, per-net networks, supply grid; solve; run every row.
pub fn check(rules: &RuleSet, inputs: Inputs<'_>, out: &mut Violations, runs: &mut Vec<RuleRun>)
    -> Result<(), PowerError>;
```

- The engine's `run_erc` shrinks to: `from_deck`, the grid/die skips, then `erc::check(..).map_or_else(|e| Refused(e.to_string()), |()| Ran)`.
- `NetFacts`, `IntentMap`, `NetNetworks`, `PowerGrid`, `PowerSolution`, `Solved`, `RunInputs`, `Scratch`, `SolveScratch`, `SolveConfig`, the 19 table types and all `check_*` become `pub(crate)`. `Scratch` becomes a local inside `check`.
- Keep eager extract and solve inside `check`: currently a `PowerError` refuses the whole stage even when no electrical rule is configured. Making it lazy would change a stage status. That is a behaviour change, so do not do it silently.
- `crates/testgen/src/electrical.rs:3` needs `NetNetworks`. Either keep `pub mod power` as `#[doc(hidden)]`, or have testgen emit its own edge list.

**Tests made obsolete or needing rewrite:**
- **Delete:**
  - `net_facts.rs`: the 6 `RoleMask` algebra tests plus `terminal_counts_*` (2 tests), if `NetFacts::terminals` goes.
  - `supply_rules.rs:665` (`every_pad_net_reaching_a_listed_clamp_model_is_clean`).
  - `intent_gate.rs`: the `supply_count` and `undeclared` assertions.
  - `power_grid_laws.rs`: the `SolveConfig` / `iterations` / `relative_residual` reads.
- **Rewrite through `check()` or crate-internal unit tests:**
  - every test that hand-builds tables with `LayerRef::Base(..)` or clamp fields: `dispatch.rs`, `intent_gate.rs`, `supply_rules.rs`, `topological_rules.rs`, `antenna_and_density.rs`, `electrical_limits.rs`, `p2p_resistance_rule.rs`. That is ~2,500 lines of table-construction fixtures.
  - The law tests (`power_grid_laws.rs`, `effective_resistance_laws.rs`) call `solve_into` / `effective_resistance_into` directly. Move them to `#[cfg(test)]` in `power.rs`, or keep a `#[doc(hidden)] pub` shim.
- **Add:** one `from_deck` test with a 2-layer `electromigration` row (would have caught §0.1).

---

## 6. SIMD candidates (`fearless_simd` 1.0)

Only one real hot loop exists: the CG iteration. Everything else is small N, gathers, i128, or transcendental.

| # | Location | Op | Elem | Typical N | Dependency class | Contiguity | Verdict |
|---|---|---|---|---|---|---|---|
| S1 | `crates/geom/src/linalg.rs:38-43` `axpy`, called at `power.rs:1087,1090` | `y += a·x` | f64 | unknowns = grid nodes − pads, 10³–10⁶; ×2 per CG iteration; up to 20,000 iterations | lane-independent | contiguous `&[f64]` | **Yes.** Bit-exact if you use separate mul+add, **no FMA** |
| S2 | `power.rs:1094-1096` `p = z + β·p` | xpay | f64 | same | lane-independent | contiguous | **Yes**, bit-exact without FMA. Could reuse `axpy`-style kernel |
| S3 | `linalg.rs:20-28` `dot`, called at `power.rs:1071,1079,1092` | Σ a·b | f64 | same; ×2 per iteration | reduction | contiguous | **Yes, but changes bits.** The fold order is documented as interface (`linalg.rs:9-16`). A fixed 4-lane block sum is deterministic but moves every solved number at the ULP level, and can move the iteration count. Needs an owner decision |
| S4 | `linalg.rs:31-33` `nrm2`, called at `power.rs:1073,1098` | √Σ r² | f64 | same; ×1 per iteration | reduction | contiguous | Same as S3. Also fusable into the `dot(r,z)` pass (one read of `r`) |
| S5 | `power.rs:971-975` diagonal preconditioner `z = r·d⁻¹` | mul | f64 | same | lane-independent | contiguous | Bit-exact, but only runs on IC(0) breakdown (rare) |
| S6 | `linalg.rs:46-68` `spmv`, and `power.rs:979-997` IC(0) forward/back substitution | CSR row dot / triangular solve | f64 | nnz ≈ 5·N | gather (`v[col[k]]`), rows ~3-7 long; the triangular solves are **sequential** | indirect | **No.** These dominate CG time, so S1-S4 buy maybe 20-35% of CG wall time |
| S7 | `power.rs:389-398`, `2648-2654`, `2676-2679` finite/positive folds | bool AND-reduce | f64 → mask | N nodes / edges, once per solve | order-independent reduction | contiguous | Bit-exact, but O(N) once, so negligible |
| S8 | `power.rs:2857-2862` `node_drop = nominal − v` | sub | f64 | N once | lane-independent | contiguous | Autovectorises already |
| S9 | `rules/electrical.rs:428-496` `check_branches` | abs, L/W divide, compare | f64 plus i64→f64 | edges 10⁴–10⁶ per row | lane-independent except the gather `limit_of_layer[edge_layer]` and the push | contiguous columns | Possible: compute a violation mask in SIMD, then push scalar. Small win, once per rule row |
| S10 | `power.rs:681-726` `cholesky_inverse_into` | dense dot | f64 | k = terminals per component, 2-100 | reduction | contiguous row | No: N too small, and changes bits |
| S11 | `rules/antenna.rs:174-200` `net_areas_into`, `:254-289` ratios | area2 in **i128** | i128 | polys/nets | reduction | gather via `polys_of` | **No** (i128; no `fearless_simd` lane type) |
| S12 | `rules/antenna.rs:857-940` density/window loop, `:952-976` neighbour Δ | i128/i128 → f64; abs diff | i128, f64 | windows 10²–10⁵ | lane-independent | contiguous | Numerator is i128, so no. The Δ pass (f64) could vectorise along x, but N is small |
| S13 | `rules/supply.rs:1110-1125` `nybucket` (`point_seg_dist2`) | exact i128 distance | i128 | bucket ~16 segs | reduction (min) | contiguous `segs` | No (i128 exactness is load-bearing) |
| S14 | `rules/reliability.rs:209-213` lifetime per node | `powf`, `exp` | f64 | nodes | lane-independent | contiguous | No: `fearless_simd` has no powf/exp, and a libm swap changes bits |
| S15 | `power.rs:1166-1172` `load_on` | masked Σ over all nodes, per limit net | f64 | nodes × limit_nets | reduction | contiguous | The fix is algorithmic (one bucketed pass), not SIMD. Only `== 0.0` is compared |

---

## 7. Accuracy-sensitive code (do not "simplify" without bit-exact regression)

| Location | Why |
|---|---|
| **`ruleset.rs:467` + `electrical.rs:659,705`** | **BUG**: Blech limit is per row but indexed per layer (§0.1). The shipped `pdks/generic_finfet.json` triggers it |
| `power.rs:42` `UA_PER_MV_OHM = 1000` | Unit scaling; getting it wrong scales every drop ×10⁶ and still passes the law tests |
| `linalg.rs:20-43`, `power.rs:1071-1099` | CG fold order is interface. Stop test `!(residual <= goal)` (NaN = refuse). Tolerance 1e-10 and cap 20,000 |
| `power.rs:857-951` IC(0) + empty-factor fallback; `:2764-2771` nominal as initial guess | Changing the preconditioner or the start point changes the converged bits and the relative-residual meaning |
| `power.rs:2793-2806` rhs via `g·v·f64::from(bool)` | Adds ±0.0. A rewrite to `if` is equivalent except for the sign of zero; verify bitwise |
| `power.rs:743-842` `assemble_into` | Duplicate columns left unmerged (the matvec sums them); `factorise_into` merges. Diagonal accumulation order = edge order |
| A5: B4 dedup of `extract_into` / `extract_nets_into` | Node numbering would match (taps are sorted by `(shape, along)`), but **edge order differs**. The supply grid lists all chains, then all metal links in `connections_into` order, then all vias. The per-net builder sorts links by `(net, a, b, layer)`. CG assembly order follows the edge order, so a merged builder must re-emit edges in the old global order to stay bit-exact. Terminal/load counting also differs by design: supply loads count `here` terminals per device (`:1384`); nets count a device once (`:2473`). Keep both |
| `power.rs:2995-3024` Kron min-degree order with the `(degree, v)` tiebreak; `:633-636` ascending fold | Rounding of effective resistance |
| `power.rs:2153-2282` `ChainProfile` slab sweep; `max(1)` floors in `:1518,2223,2289,2299,2326` | Resistance and width; floors keep Blech from exempting zero-length segments |
| `power.rs:1452-1501` pad anchor (highest layer, then widest, then lowest index); `:1394-1404` uniform budget share | Changes which node is fixed, which moves every drop |
| `power.rs:1744-1843` `TapIndex::nearest` (i128 exact, tie → lowest index); `:2006-2010` sort keys with index | Determinism |
| `power.rs:1143-1172` `discarded_budget` `== 0.0` (relies on `-0.0 == 0.0`) | Refusal gate for 3 rules |
| `topology.rs:539-570` `inside_ring` (boundary exclusive) vs `supply.rs:804-830` `point_in_region` (boundary inclusive) | Documented opposite on purpose. **Do not unify** |
| `supply.rs:837-870` `isqrt_ceil`, `prunes`, `NO_TAP_IN_RANGE`; `:1211-1354` branch-and-bound | Exact maximum distance; rounding direction matters |
| `antenna.rs:302-423` `positions`, `window_span` (exclusive touch), `window_touch_span` (inclusive), `div_euclid` | Window membership; clipped denominator |
| `antenna.rs:174-200` doubled i128 areas; `:267` `/2` for diode area | Ratio exactness |
| `electrical.rs:587-612`, `reliability.rs:180-201` | Arrhenius sign and `usable` gates; Boltzmann constant |
| `electrical.rs:143-148` `p2p` worst-pair left fold (earliest wins ties) | Reported shape pair |
| `topology.rs:366-417` multiple_drivers: `NO_GATE = u32::MAX` sorts last in the group | Driver count |
| `facts.rs:136-153` scrap-row clamp for `NetId::NONE` | Roles must not leak onto real nets |
