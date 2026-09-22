# Audit: `crates/check/src` excluding `erc/` and `lvs/` (DRC, topology, report)

Scope: 8,573 source lines (drc 6,216 / topology 1,783 / report 541 / lib 33) and 7,618 test lines
(`tests/drc` 4,433, `tests/topology` 2,378, `tests/report` 807).

How this was verified: grep over `crates/*/src`, `src/`, `crates/*/tests` and `tests/`, plus two compile experiments on a
copy of the repo in the scratchpad (the real repo was not touched):
1. **Rooted dead-code scan.** I made `drc`, `report` and `topology` private, re-exported only the items other crates
   actually use, and ran `cargo check`. The result is the list of items nothing live reaches.
2. **Deletion check.** I deleted each candidate item and ran `cargo check --workspace --lib --bins`, then again with
   `--all-targets`. The first run finds non-test users and the second finds test users.

---

## 1. Data in and data out

### DRC
| | Type | Notes |
|---|---|---|
| IN | `gpurify_ingest::deck::Deck` + `StrTable` → `RuleSet::from_deck` | Rules arrive as `RuleTable` rows (`RuleSpec` with interned kind string, layers CSR, params CSR of `ParamValue::{Length,Ratio,Count,Flag}`); already grid-converted by ingest. **Grid is never read by DRC.** |
| IN | `Design { store: &GeometryStore, derived: &Evaluator, nets: &NetTable, devices: &DeviceTable }` (lib.rs:26) | **DRC reads only `design.store`**: grep shows zero reads of `design.derived/nets/devices` under `drc/`. The other three fields exist for ERC. |
| IN | `&mut Scratch` (drc/mod.rs:72) | 12 reusable buffers. The engine creates a fresh one on every call (src/engine/run.rs:387), so buffer reuse across runs never happens. |
| OUT | `Violations` (report/violation.rs:35), stored as 8 separate columns (`rule, layer, severity, at, measured, limit, shape_a, shape_b`) | Rules append to it. `RuleSet::run` clears it first. |
| OUT | `Vec<RuleRun { rule, outcome: Ran/Skipped(reason)/Refused, examined: u64, violations: u32 }>` | One row per configured rule. The engine then does `sort_by_key(rule)` (run.rs:297), so the order rules are dispatched in does not affect the output. |
| ERR | `DrcError` (7 variants), load-time only. | |

### Topology extraction
| Fn | In | Out |
|---|---|---|
| `net::extract_nets_into` (net.rs:160) | `&GeometryStore`, `&Connectivity{conductors, via_cut, via_connects, intra_layer_touch}` | `&mut NetTable` (`poly_net: Vec<NetId>` plus the reverse CSR `net_start/polys`, plus 3 scratch fields) |
| `device::refuse_conducting_channels` (device.rs:531) | store, `&Connectivity`, `&DeviceRecognition` | `Result<(), ChannelError>` |
| `device::recognise_into` (device.rs:173) | store, `&Evaluator` (**unused**), `&NetTable`, `&DeviceRecognition` | `&mut DeviceTable` (kind/marker/model columns, terminal CSR, param CSR, net→device reverse CSR) |
| `port::bind_ports_into` (port.rs:131) | `&NetTable`, `&Provenance` (labels) | `&mut PortTable` or `PortError` |

### The real API: what live, non-test code outside this scope uses
From `src/`, `crates/extract/src`, `crates/testgen/src`, plus `erc/` and `lvs/` inside this crate:
- **topology:** `NetId` (+`NONE`, `idx`), `NetTable::{net_count, net_of, polys_of, same_net}`, `DeviceTable` (+`len, terminals_of, params_of, devices_on`, pub columns), `DeviceId`, `DeviceParam`, `DeviceMeasure`, `TerminalRole`, `PortTable::{name_of, net_of, len}`, `Extraction`, `ChannelError`, `PortError`, `device::{refuse_conducting_channels, recognise_into}`, `net::extract_nets_into`, `port::bind_ports_into`, `net::{intra_layer_edges_into, via_edges_into}` (only erc/power.rs uses these two).
- **report:** `Violation`, `Violations::{push, extend, get, len, is_empty, sort_canonical}` + pub columns (json.rs/gds.rs read the columns directly), `RuleRun`, `Outcome`, `SkipReason` (all 3 variants), `Severity` (both), `Measurement` (+`violates`, `is_finite`, `Display`, which format.rs:139 uses), `LimitSense`, `record_run`.
- **drc:** `RuleSet::{from_deck, rule_count, run}`, `ruleset::KINDS`, `DrcError` (UnknownKind is constructed by the engine), `Design`, `Scratch::default`.
- **Everything else that is `pub` exists only for tests.** That covers the 24 `check_*` functions, the 24 `*Table` structs with pub fields, and `narrowest_*`, `shortest_edge`, `Margins`, `margins`, `parallel_run_length`, `color_into`, `Coloring`, `Direction`, `COLOR_SEARCH_BUDGET`, `Scratch::shrink`, `RuleSet::is_empty`, `NetTable::from_assignment`, `PortTable::build`, and `PartialEq` on `NetTable` and `PortTable`.

---

## 2. Module map
| File | Lines | Purpose |
|---|---|---|
| lib.rs | 33 | `Design` borrow bundle; declares the 5 modules |
| drc/mod.rs | 109 | `DrcError`, `Scratch` (12 buffers), `record_run` re-export |
| drc/ruleset.rs | 888 (315 are tests) | `RuleSet` with 24 table fields, `from_deck` (304-line function built on the `deck_arms!` macro), the `dispatch!` macro, `KINDS` |
| drc/rules/mod.rs | 210 | `row_columns!` (len/is_empty), `mid`, `gap_midpoint`, `centre`, `ring_segs`, `seg_bbox`, `bbox_gap2`, `poly_dist2` (the exact polygon-distance kernel) |
| drc/rules/width.rs | 792 | min/max width, notch (facing-edge scanline sweep), min edge length, `OuterRows`, `ring_winding` |
| drc/rules/spacing.rs | 1,084 | min_spacing, diff-layer spacing, eol, prl, corner_to_corner, wide-dependent. Six near-copies of one pipeline. |
| drc/rules/area.rs | 636 | min_area, min_enclosed_area, cheesing, density (merge, rect decomposition, window sweep) |
| drc/rules/overlay.rs | 861 | min/asymmetric enclosure, extension, overlap, max distance to tap (bounding-box margins) |
| drc/rules/grid.rs | 454 | off_grid, angle (`Direction` plus a CSR list of allowed directions) |
| drc/rules/via.rs | 314 | redundant_via, via_array_spacing |
| drc/rules/patterning.rs | 868 (48 are tests) | Graph colouring (2 colours by BFS; 3+ by DSATUR with backtracking, `SatQueue` bitset buckets) |
| topology/mod.rs | 28 | re-exports, `csr_run`, `Extraction` |
| topology/net.rs | 839 (136 are tests) | Net extraction: same-layer touches plus via landings, union-find, canonical ids, exact ring intersection (direct scan + sweep) |
| topology/device.rs | 632 | Device recognition, terminal binding, W/L/area params, channel-short refusal |
| topology/port.rs | 284 (24 are tests) | Label→net binding, name index |
| report/mod.rs | 20 | re-exports |
| report/measure.rs | 91 | `Measurement`, `violates`, `LimitSense`, `Display` |
| report/violation.rs | 430 (84 are tests) | `Violations` table, canonical sort, `RuleRun`/`Outcome`/`SkipReason`, `record_run` |

---

## 3. Dead code (no live non-test user; confirmed by the deletion check)
| file:line | Item | Users | Lines |
|---|---|---|---|
| drc/mod.rs:97-106 | `Scratch::shrink` | tests/drc/determinism.rs only | 10 |
| drc/mod.rs:13-19 | `#[allow(unused_imports)] use crate::report::{Outcome,RuleRun,Violations}`, imported only so doc links resolve | none | 5 |
| drc/ruleset.rs:461-463 | `RuleSet::is_empty` | the in-file unit test only | 3 |
| drc/ruleset.rs:572-888 | in-file `mod tests` (5 tests, a hand-written 24-table fixture) | test | 315 |
| drc/rules/width.rs:457-468 | `narrowest_notch` | tests/drc/width_rules.rs | 12 |
| drc/rules/width.rs:470-481, 489-520 | `shortest_edge`, `ring_shortest_edge` | tests/drc/width_rules.rs | 45 |
| drc/rules/overlay.rs:146-155 | `Margins::worst`, `Margins::worst_axis_best_side` | tests/drc/overlay_rules.rs | 10 |
| drc/rules/patterning.rs:89-102 | `color_into` (pub wrapper) | tests/drc/patterning_rules.rs + the in-file test | 14 |
| drc/rules/patterning.rs:346-383, 616-626 | `dsatur_pick` + `SatQueue::pick_checked`: a reference implementation that runs only as a debug oracle and makes debug-build colouring O(n²) | debug builds only | 50 |
| drc/rules/patterning.rs:821-868 | in-file test comparing `color_into` against `color_into_with` | test | 48 |
| topology/net.rs:82-105 | `NetTable::from_assignment` | tests only (check/tests/topology/laws.rs, extract/tests/field/bridge.rs, extract/tests/pex/analytical.rs). Other crates' tests use it as a fixture constructor, so move it to testgen or accept it as a test hook. | 24 |
| topology/net.rs:144-153 | `impl PartialEq/Eq for NetTable` | tests only (laws.rs, tests/test_all.rs) | 10 |
| topology/net.rs:464-491 | `point_inside`: a duplicate of `GeometryStore::poly_contains_point` (geom/store.rs:85). The crossing rule is identical, and because it is only called after `rings_meet` returned false, the point cannot be on the boundary, so the inclusive and strict versions agree exactly. | live but redundant | 28 |
| topology/net.rs:658-678 (+test 743-766) | `sort_dedup_from`: a hand-rolled branchless dedup that `tail.sort_unstable(); tail.dedup()` on a `split_off` tail replaces | live but redundant | 45 |
| topology/device.rs:169-175 | `derived: &Evaluator` parameter of `recognise_into` plus its `#[allow(unused_variables)]` ("the signature is frozen") | never read | 6 |
| topology/mod.rs:8-9 | re-exports `extract_nets_into`, `bind_ports_into` | callers use the full path; the compiler reports them as unused imports | 2 |
| topology/port.rs:84-126, 261-284 | `PortTable::build` + its test | **no user anywhere** except its own unit test | 67 |
| topology/port.rs:9 | `PartialEq, Eq` derive on `PortTable` | tests/test_all.rs only | 0 (derive) |
| report/violation.rs:346-430 | `record_run_tests`, which overlap tests/report/rule_run.rs | test | 84 |

**Should not be `pub`** (live only inside the crate, pub only so tests can reach them): the 24 `check_*` functions, all 24 table structs and their fields, `parallel_run_length` (spacing.rs:266), `margins` and `Margins` (overlay.rs:108/371), `Coloring`, `COLOR_SEARCH_BUDGET`, `Direction` (with `from_degrees`, `parallel_to`), `AngleTable::allowed_of`, `narrowest_width`, `topology::csr_run` (already pub(crate)), `Scratch`, and `Design` as far as DRC is concerned.

**Verified live** (keep): `Display for Measurement` (src/bin/gpurify/format.rs:139), `Violations::get` (format.rs:55), `Violations::extend` (run.rs:366), `SkipReason::NotInDeck` (lvs/checks.rs), `Severity::Warning` (erc), `NetTable::same_net` (extract/analytical.rs:437).

---

## 4. Bloat

### 4.1 Numbers
- **350 `debug_assert*` calls taking 1,011 lines**, which is 11.8% of the scope. By file: spacing 123, patterning 116, width 108, net 100, area 95, port 77, device 75, overlay 72, via 71, grid 70, violation 53. About 95% of them either restate something that holds by construction (for example "one distance per pair" right after `for p in pairs { push }`, or "compact kept what it counted" right after `set_len(w)`) or re-derive a column length. Keep about 10: the i128 domain headroom notes, `ring_winding` agreeing with the shoelace, and the colouring validity check at patterning.rs:329. **About 950 lines can go.**
- **1,852 comment lines** (1,214 doc, 638 line comments), which is 22% of the scope. Typical examples: a 7-line SAFETY comment repeated at 15 sites, the `#[allow(... reason = "...")]` essays at ruleset.rs:120-125 and 203-208, and "why this is not X" paragraphs on almost every struct. Trimming to about 600 lines saves **about 1,250**.
- **15 hand-rolled `unsafe` branchless compactions** (`spare_capacity_mut` + `get_unchecked_mut` + `set_len`), each about 20 lines including SAFETY text: spacing.rs:338-361, 433-454, 520-543, 579-599, 743-764, 769-786, 852-874, 879-896, 1029-1050, 1055-1072; grid.rs:225-251, 362-389; area.rs:540-566; overlay.rs:598-639; net.rs:271-303. Each one becomes `v.extend(xs.iter().filter(p))` or a single `if p { push }` pass that produces the same order. The claimed "1.19x at 8k" is on loops that are cheap next to the `poly_dist2`/`isqrt` work around them. **About 300 lines can go, removing 20 `unsafe` blocks.**

### 4.2 Duplicate logic across the 24 rule kinds
1. **The per-row skeleton is repeated in every `check_*` (24 copies):** `for row in 0..t.len() { let before = out.len(); if validate(..).is_err() { record_run(Refused,0); continue } ... record_run(Ran, examined) }` plus 3-6 debug asserts. One `for_each_row(rows, |row| -> (Outcome, examined))` helper that owns `before` and `record_run` saves **about 250 lines**.
2. **Spacing (spacing.rs, 1,084 lines) is one pipeline written six times.** `prepare_same_layer` → a compact `judged = separate_figures & extra(a,b)` → a compact `d2 < limit2` → `spacing_violation`. prl (697-798), corner_to_corner (807-908) and wide (977-1084) differ only in one `extra` predicate; min_spacing (291-370) only in "examined = all candidates". A single kernel `same_layer_spacing(row, judge: impl Fn(a,b)->bool, examined_is_judged: bool)` with one loop (`if judge { examined += 1; if d2 < limit2 { push } }`) keeps the pair order and each rule's `examined`. **1,084 → about 350 lines.**
3. **Measuring every pair is written 4 times:** spacing.rs:121 `pair_distances_into`, via.rs:103-107, via.rs:231-235, patterning.rs:731-737. One shared helper.
4. **"Touching pairs → union-find labels" is written twice:** spacing.rs:142-173 `label_figures` and patterning.rs:743-753 (same `ra + touching*(rb-ra)` trick). Via-array does the same at via.rs:241-256 with a different predicate.
5. **Ring-edge iterators exist 4 times:** rules/mod.rs:98 `ring_segs`, width.rs:117 `ring_edges`/`poly_edges`, net.rs:308 `ring_edge`, and grid.rs:344-352 (packs a `Vec<Point>` just to zip two offset views of it). Keep `ring_segs`.
6. **Tables:** 24 structs × (`rule: Vec<StrId>`, `layer`, params), plus the `row_columns!` macro, plus hand-written `len`/`is_empty` for OffGrid and Angle (grid.rs:135-176), plus 24 `RuleSet` fields, plus a 24-term `rule_count` sum (ruleset.rs:434-459), plus the `deck_arms!` and `dispatch!` macros. Ten tables have the identical shape `{rule, layer, limit: Dbu}`. Replace all of it with `enum Rule { MinWidth{layer,limit}, … }` and `Vec<(StrId, Rule)>`, stably sorted by kind index at load (the engine re-sorts runs by rule id anyway), and dispatch with one `match`. **ruleset.rs 573 non-test lines plus about 300 table/macro lines → about 200.**
7. **The angle rule is over-general** (grid.rs:30-176, 299-454). Only 4 lines are expressible (0/45/90/135 degrees), so the allowed set fits in a 4-bit mask. The i128 cross product `parallel_to` against a `Direction` becomes exact integer compares: `dy==0`, `dx==dy`, `dx==0`, `dx==-dy`. This is equivalent for every non-zero edge, and `measured` is always `Count(0)` on a violation. That removes `Direction`, the CSR columns, `allowed_of`, `columns_agree` and `directions_matched`: **about 120 lines.**
8. **width.rs's 3 thin wrappers** (`check_min_width`/`max_width`/`notch` → `check_facing`, 527-548, 671-692, 771-792) are about 60 lines that go away once rows are dispatched by enum.
9. **Enclosure wrappers** (overlay.rs:499-553) are 55 lines and collapse the same way.
10. **Every rule re-validates its layer:** `validate_layer_into` has 17 call sites, and a deck with N rules on M1 validates M1 N times. Validating each layer once per run is a performance point, not a line-count one.
11. **PortTable** keeps 4 columns plus a scratch column plus a separate name index. The conflict scan at port.rs:188-210 uses "two offset views + min trick" where `bound.windows(2).find(|w| w[0].0 == w[1].0)` gives the same answer, because `bound` is sorted by net so the first hit is the minimum. **284 → about 110 lines.**
12. **NetTable holds scratch fields** `edges`, `labels`, `scratch: EdgeScratch` (net.rs:43-45). Their only purpose is allocation reuse, and they force the hand-written `PartialEq`. If extraction returns by value, both go.

### 4.3 Defensive code that cannot fire
- ruleset.rs:405-413: the `_ => UnknownKind` arm is unreachable, since `kind < 24` and every index is covered. It can be `unreachable!()`, or disappears with the enum.
- ruleset.rs:41, 292, 312, 356, 374, 388: `debug_assert_eq!(KINDS[k], "...")` six times.
- ruleset.rs:419-427 and 530-536: post-condition row counts.
- area.rs:419-425: density `side<=0 || stride<=0 || !limit.is_finite()`. `from_deck` already rejects all three, so only hand-built test tables can reach it.
- area.rs:448-458: second `EmptyLayer` skip after `polys_on_layer` was already checked non-empty and the merge succeeded. Likely unreachable.
- overlay.rs:725-733: `let-else` with `debug_assert!(false)`. The distance-0 prune is `overlaps`, so the pair always intersects.
- via.rs:139-143: `assert_eq!(rect_start.len(), n)` directly after `rect_start.resize(n, 0)`.
- grid.rs:204: `assert!(pitch > 0)`. Guaranteed by `from_deck`.
- patterning.rs:167-169: `colors == 0 → Infeasible`. `from_deck` refuses 0.
- net.rs:253-255: empty-ring guard. Store rings have at least 3 vertices.
- width.rs:248-250 and similar: `u32::try_from(...).expect(...)` on indices already bounded by u32 PolyId.

### 4.4 Deletable total (estimates overlap, so this is deduplicated)
About **4,500 of 8,573 source lines (about 52%)**: debug_asserts about 950, comments about 1,250, the unsafe compactions about 300, the spacing kernel about 400, the enum `RuleSet` about 650, the row driver about 250, in-source tests 607, dead items about 180, the angle mask about 120. Behaviour stays byte-identical as long as §7 is respected.

---

## 5. Proposed simple API

```rust
// drc
pub const KINDS: [&str; 24];
pub enum DrcError { … }                               // unchanged
pub struct RuleSet(Vec<(StrId, Rule)>);               // Rule is a private enum
impl RuleSet {
    pub fn from_deck(deck: &Deck, strings: &StrTable) -> Result<Self, DrcError>;
    pub fn len(&self) -> usize;
}
pub fn run_drc(store: &GeometryStore, rules: &RuleSet, out: &mut Violations, runs: &mut Vec<RuleRun>);
//  (append-style to match engine::append_stage; Scratch becomes a local inside run_drc)

// topology
pub fn refuse_conducting_channels(store: &GeometryStore, c: &Connectivity, r: &DeviceRecognition) -> Result<(), ChannelError>;
pub fn extract_nets(store: &GeometryStore, c: &Connectivity) -> NetTable;
pub fn recognise_devices(store: &GeometryStore, nets: &NetTable, r: &DeviceRecognition) -> DeviceTable; // drop `derived`
pub fn bind_ports(nets: &NetTable, p: &Provenance) -> Result<PortTable, PortError>;
pub(crate) fn intra_layer_edges_into / via_edges_into   // erc::power only
// types: NetId, NetTable{net_count,net_of,polys_of,same_net}, DeviceTable(+3 accessors), DeviceId,
//        TerminalRole, DeviceParam, DeviceMeasure, PortTable{name_of,net_of,len}, Extraction, ChannelError, PortError

// report: unchanged public surface (Violation(s), RuleRun, Outcome, SkipReason, Severity, Measurement, LimitSense);
//         record_run -> pub(crate)
```
Changes this implies elsewhere:
- `src/engine/run.rs:379-391` (DRC no longer needs a `Design`)
- `src/engine/pipeline.rs:263-293` (four calls; return by value)
- `crates/check/tests/drc/common/mod.rs` (`Env`/`Sink`)
- `lib.rs` `Design` stays for ERC only

**Tests this makes obsolete or forces to change.** All of `tests/drc/*` (4,433 lines) calls the `check_*` functions with hand-built tables. They need a small `deck!`/`RuleSet` builder, or a `#[doc(hidden)] RuleSet::push(StrId, Rule)` test hook.
- Deleted outright:
  - determinism.rs's `shrink` test
  - patterning_rules.rs's `color_into` tests (9 uses)
  - overlay_rules.rs `Margins::worst*` / `margins` tests (8+7 uses)
  - spacing_rules.rs `parallel_run_length` tests (10 uses)
  - grid_rules.rs `Direction::parallel_to`/`from_degrees` tests (13+5 uses)
  - width_rules.rs `narrowest_notch`/`shortest_edge` tests
  - ruleset.rs, patterning.rs, net.rs (`sort_dedup_from`), port.rs and violation.rs in-file tests (607 lines)
  - tests/report/rule_run.rs `every_outcome_and_every_skip_reason_is_its_own_verdict` (it only tests `derive(PartialEq)`)
- Kept, retargeted to the new signatures: tests/topology/* (extraction, devices, ports, laws, and edges via `pub(crate)` or through erc)
- Kept unchanged: tests/report/violation_table.rs and measurement.rs.

---

## 6. SIMD candidates (`fearless_simd` 1.0)
Checked in the crate source: `i64x2/x4/x8` has `add/sub/mul/min/max/abs/simd_lt/eq/select/reduce_min/reduce_sum`, and there are f64 lanes. **There is no i128 and no integer division.** Most exact DRC arithmetic is `DbuArea` (i128), so SIMD only applies where i64 is provably exact.

| # | Location | Loop | Elem | Typical N | Dependency | Layout | Verdict |
|---|---|---|---|---|---|---|---|
| 1 | area.rs:513-517 → geom rects.rs:265-269 `clipped_area` | every density window × **every** rectangle on the layer | i64 coords, i128 area sum | windows 10^3-10^6 × rects 10^4-10^7 | accumulator (sum) | `Rect` is AoS `[xlo,ylo,xhi,yhi]` → needs a 4-column transpose | **Top candidate, but fix the algorithm first:** this is O(W·R). Bin rectangles per window (or 2-D prefix sums) before vectorising. i64 is exact when `side² < 2^63` (side < 3.03e9 dbu); check that once per rule and fall back otherwise. f64 is exact only when side < 9.4e7 dbu. |
| 2 | rules/mod.rs:162-210 `poly_dist2` (called for **every** candidate pair by min_spacing, the 5 same-layer spacing rules, diff spacing, both via rules, patterning) | O(n·m) segment pairs with a box-gap prune | i64 vertex columns, i128 d² | rings of 4-100 vertices; pairs 10^5-10^7 per layer | accumulator (min) | `verts_x`/`verts_y` are SoA and contiguous per polygon (store.rs:55), so shifted views give the edges | **Good.** On the validated rectilinear domain a segment's distance equals the gap between its bounding boxes, so d² = gx² + gy² exactly. Saturating gx, gy at 2^31 keeps i64 exact, and every consumer only tests `== 0`, `< limit²` or `<= within²` and reports `isqrt` for violators (always below the limit). That is exact while `limit < 2^31`. Accuracy-sensitive: gate it on the limit. |
| 3 | spacing.rs:648-691 `eol_hit` inner loop | `zone.overlaps(seg_bbox(far))` then `seg_seg_dist2` | i64 / i128 | ring size | min accumulator | SoA | Medium: vectorise the overlap filter as an i64 compare mask. |
| 4 | grid.rs:232-244 off_grid | `rem_euclid(pitch)` per vertex | i64 | every store vertex (10^6-10^8), per rule | none (independent) + count | SoA, and the whole store is contiguous `verts_x/verts_y` | **Poor**: no SIMD integer division. The only easy case is a power-of-two pitch (mask), or f64 floor-division proven exact (|x| < 2^52 and a correctly rounded quotient). A flat scan of the whole store instead of per-polygon (grid.rs:211) is the easier win. |
| 5 | grid.rs:356-382 angle | edge classification over shifted vertex views | i64 dx, dy | every store edge | none + count | SoA shifted views | **Good after §4.2 item 7**: four i64 `simd_eq` tests plus a mask. No multiply needed. |
| 6 | width.rs:729-748 min_edge_length | `abs(dx)+abs(dy) < limit` per edge | i64 | edges on the layer | none + compact | SoA per ring | Good, small win (the push of violations stays scalar). |
| 7 | area.rs:124-141 `lowest_row_within` | min over **all** of the layer's bounding boxes, called once per violating figure or window | i64 box compares → u32 min | N = polygons on the layer (10^4-10^6) × violators | accumulator (min) | `poly_bbox` AoS slice `&[Bbox]` | Quadratic hot spot. SIMD helps (4 i64 compares plus select-min); a spatial index query is better. |
| 8 | overlay.rs:821-833 tap distance | for each well vertex, min over taps of `point_box_dist2` | i64 → i128 | vertices × taps in reach (small) | min | taps are **gathered** by PolyId, not contiguous | Poor: i128 and a gather. |
| 9 | area.rs:513-517 fraction map, `wide_flags_into` OR-fold (spacing.rs:958-964), port.rs:199-206 min-scan | trivial maps and folds | f64 / u8 / u32 | small | none / accumulator | contiguous | Not worth it; the compiler already autovectorises these. |
| 10 | net.rs:335-455 `rings_meet*`, 464 `point_inside`; the i128 compaction predicates in spacing.rs | orientation tests, `d2 < limit2` | i128 | — | — | — | Not SIMD-able as written (i128). |

Beyond SIMD, the order that matters for speed is:
1. density O(W·R)
2. `lowest_row_within` O(violators·N)
3. re-validating the same layer once per rule
4. `poly_dist2` O(n·m) per pair
5. `ring_contains_ring` O(n·m) per host candidate (overlay.rs:342)

---

## 7. Accuracy-sensitive: preserve bit for bit
- **Comparisons are on squared distances**:
  - spacing uses `d2 < limit.mul_wide(limit)`
  - redundant_via uses `<=`
  - the reported value is `isqrt`, rounded toward zero (spacing.rs:195, via.rs:291)
  - tap distance is reported with `ceil_sqrt`, rounded up, plus the `OUT_OF_REACH = 2^80` sentinel (overlay.rs:215-245)
- **Report coordinates** come from `mid` (`div_euclid` floor), `gap_midpoint`, `centre`, `strip_midpoint`, the first-rect centre (area.rs:189-205) and the vertex for off_grid/angle. They are compared by testgen expectations, so tie-breaking must stay exactly as it is:
  - `min_by_key` keeps the first, and the vertical sweep runs before the horizontal (width.rs:321)
  - `Reverse(row)` picks the lowest host (overlay.rs:440-453)
  - strict `>` keeps the first worst vertex (overlay.rs:830)
- **Each rule's `examined` means something different, and any shared kernel must keep it:**
  - min_spacing and diff spacing: every candidate pair
  - eol: separate pairs that have an end-of-line edge
  - prl: separate pairs with `run >= threshold`
  - corner_to_corner: separate, diagonal pairs
  - wide: separate pairs with a wide member
  - via_array: pairs inside a qualifying cluster
  - redundant_via: cuts
  - width/notch: *pre-merge* polygon count
  - min_edge_length: edges
  - area/cheesing: merged figures
  - enclosed_area: holes
  - density: windows
  - multi_patterning: shapes, **including when Refused**; every other rule records 0 on Refused
- **Outcome choices:**
  - `Skipped(EmptyLayer)` is used by density, max_distance_to_tap and multi_patterning only
  - the via rules never validate, so they never Refuse
  - DSATUR budget exhaustion maps to `Exhausted → Refused`
- **Density:**
  - the window count rounds *up* (`positions`)
  - a sweep that would leave the coordinate domain is refused
  - the fraction is `to_f64(i128 sum) / to_f64(side²)` computed per window. Do not reorder it into a sum of per-rect fractions.
  - the comparison is strict `<` through `Measurement::violates`
  - a window that encloses no polygon is attributed to the layer's first row
- **The notch rule measures the *merged* layer (`union_into`), the width rule measures the unmerged one** (width.rs:612-620).
- **Figure labelling** joins on `d2 == 0` (touching). The component label is the *minimum member index*; via_array indexes counts by it (via.rs:263) and patterning's blend relies on it (patterning.rs:768-771).
- **`wide_flags_into`** gives a hole row the layer-wide "wide" verdict (spacing.rs:910-970). This is a known imprecision that fails closed; changing it changes results.
- **Overlay rules work on bounding boxes.** Known fail-open cases are documented at overlay.rs:273-278 and 717-722. "Simplifying" these to exact geometry would change results.
- **`ring_winding` and `OuterRows`** (width.rs:348-436) assume validation emits one polygon per counter-clockwise row, in ascending order.
- **eol:** `NO_EOL = i128::MAX` excludes a pair from `examined`, an edge `>= eol_width` is not an end of line, and diagonal edges are skipped (spacing.rs:672).
- **`parallel_run_length`** clamps at `MAX_ABS_DBU` (spacing.rs:279).
- **Extraction:**
  - net ids are canonical: rank by the minimum PolyId (net.rs:199-221)
  - the exact re-test `retain_intersecting_into` must stay; a box-only merge fails open
  - device dedup uses a *stable* sort, so the earlier recogniser wins (device.rs:351-352)
  - MOS W/L comes from the bounding box plus the axis voted by the first source/drain polygon
- **Area limits** are deck-stated as the side of the equivalent square, then squared (ruleset.rs:127-132, 182-190).
- **`sort_canonical`'s key** covers all 9 fields plus the `f64_key` total order (violation.rs:175-242). It is the byte-determinism gate.
- **Replacing the `unsafe` compactions with `filter`/`push` is order-preserving and safe.** Replacing `point_inside` with `poly_contains_point` is exact (see §3). The angle mask is exact (§4.2 item 7). The i64 fast path for `poly_dist2` is exact **only** with the `limit < 2^31` gate and on validated (rectilinear) layers. The via rules do **not** validate their layer, so they would need a validity check before using it.
