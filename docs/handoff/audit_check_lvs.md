# Audit: crates/check/src/lvs (read-only)

Scope: `crates/check/src/lvs/*` (3607 lines), `crates/check/tests/lvs/*` (3345 lines incl. common),
the LVS path in `src/engine/run.rs` (lines 510-765) and `src/engine/pipeline.rs:164-185`.

Headline: **~2150 of 3607 src lines (~60%) can go with no change to what a production run reports.**
The production path only ever runs `CompareOptions::default()` (`src/bin/gpurify/args.rs:415`,
no CLI knob exists). That makes `TieBreak::Refuse`, `match_names`, the whole "held back / symmetric"
third state, the observer seam and all of `hierarchical.rs` unreachable outside tests.

---

## 1. DATA IN / DATA OUT

### In
| Input | From | Used for |
|---|---|---|
| `NetTable`, `DeviceTable`, `PortTable` | `extracted.*` (topology) | `graph::from_layout_into` + the 6 `checks::*` |
| `StrTable` | `loaded.strings` | gates which measured params are emitted (`strings.get("w")` etc.), graph.rs:223 |
| `Option<Grid>` | `run_grid(loaded)` | dbu -> metres for params, graph.rs:211 |
| `Netlist` + `SubcktId` | `loaded.reference`, `reference.top()` | `graph::from_reference_into` |
| `CompareOptions` | `RunOptions.lvs`, always `Default` in the binary | `max_rounds=1000`, `tie_break=LowestIndex`, `param_tolerance=0.02`, `match_names=false` |

### Out
- `Verdict` (`Match | Mismatch(Vec<Discrepancy>) | Inconclusive(Inconclusive)`) stored in `Outputs.lvs`,
  **printed verbatim via `{:?}`** in `src/bin/gpurify/format.rs:97-98` (so discrepancy *order* is user-visible).
- `Discrepancy` rows mapped to `Violation`s by `run.rs:700 record_discrepancies` using `LVS_RULE_IDS` (7 names).
- 8 `RuleRun` rows + `Violation`s from `checks.rs`, filed under sentinel `StrId(u32::MAX - k)` and renamed by
  `run.rs:649 name_lvs_check_rows` via `LVS_CHECK_RULE_IDS` (8 names). Both tables interned in `pipeline.rs:171`.

### The real API (non-test uses outside `lvs/`, all in `src/engine/run.rs`)
| Item | Site |
|---|---|
| `lvs::LayoutGraph`, `lvs::RefGraph` (Default) | run.rs:533,574,585,587 |
| `lvs::graph::from_layout_into` | run.rs:534 |
| `lvs::graph::from_reference_into` | run.rs:575 |
| `lvs::graph::drop_unextracted_bulk` | run.rs:583 |
| `lvs::reduce::reduce_into` (x2) | run.rs:586,588 |
| `lvs::refine::Partition` (Default, scratch only) | run.rs:590 |
| `lvs::compare`, `lvs::CompareOptions` | run.rs:591, 40 |
| `lvs::Verdict`, `lvs::Discrepancy`, `lvs::verdict::Inconclusive` | run.rs:4-5, 572, 596-607, 726-765 |
| `lvs::checks::{check_floating_nets, check_label_conflicts, check_net_seed_conflicts, check_device_counts, check_parametric, check_topology}` | run.rs:544-565 |

Nothing else. `TieBreak` is named only by `tests/engine/{checks,pipeline}.rs` to spell out the default.
The caller hand-sequences 7 steps (project x2, drop bulk, reduce x2, alloc partition, compare) that are
always done together: that sequence belongs inside one `compare`.

---

## 2. Module map

| File | Lines | Purpose |
|---|---|---|
| mod.rs | 17 | re-exports |
| graph.rs | 653 | `Graph` SoA+CSR, `LayoutGraph`/`RefGraph` newtypes, layout/reference projection, `transpose_into`, `drop_unextracted_bulk`, `card_role` |
| reduce.rs | 680 | series/parallel MOS merge to fixed point (union-find, sort-grouping) |
| refine.rs | 891 | hash partition refinement + tie-break; `Partition` readers; 290 lines of in-crate observer tests |
| compare.rs | 537 | `CompareOptions`, `compare`, `interpret` (pairs -> terminal/param/identity joins -> discrepancies) |
| hierarchical.rs | 246 | bottom-up plan + `run` — **never called in production** |
| checks.rs | 491 | 6 layout-only checks writing 8 rule rows |
| verdict.rs | 92 | `Verdict`, `Inconclusive`, `Discrepancy`, `Side` |

Density: 155 `debug_assert*` (checks 26, compare 22, graph 41, hier 20, reduce 22, refine 24);
~700 comment lines; 10 `unsafe` (graph 2, checks 8), all for hand-rolled branchless compaction.

---

## 3. DEAD CODE (grep over `crates/*/src`, `src/`, `tests/`, `crates/*/tests`)

| file:line | Item | Status |
|---|---|---|
| hierarchical.rs:1-246 | `plan`, `run`, `ComparisonPlan`, `PlanError`, `CellResult`, `first_subckt_named`, `hierarchy_depths`, `relax_depths` | tests only (`tests/lvs/hierarchical.rs`). `run` does not even compare multi-cell plans; it reports `UncomparedCell` for every row. |
| verdict.rs:29 | `Inconclusive::MissingSubcircuit` | never constructed anywhere |
| verdict.rs:32 | `Inconclusive::UncomparedCell` | only by dead `hierarchical::run` |
| verdict.rs:76 | `Discrepancy::DuplicateName` | never constructed in src; only mapped (run.rs:733), and pattern-matched in tests. Its rule id `lvs.duplicate_name` (run.rs:622) is interned but can never be emitted. |
| graph.rs:24-29 | `enum Node` | unused (only mentioned in a doc comment in tests/lvs/common) |
| graph.rs:374-376 | `strings` param of `from_reference_into` | explicitly unread (`let _ = strings`) |
| refine.rs:56-66, 79-87, 291-298, 353-355, 403-412, 443-445 | `ObserveRefine`, `NoObserve` impl, `refine_observed` generic, all `O::ENABLED` blocks | only the in-crate tests at refine.rs:634-891 (258 lines) observe |
| refine.rs:36-42 | manual `PartialEq for Partition` | tests only |
| refine.rs:461-478 | `Partition::from_classes` | tests only (compare.rs tests, in-crate test) |
| refine.rs:602-632 | `partition_tests` | tests of the above |
| compare.rs:79 | `interpret` as `pub` | only `compare` + tests/lvs/compare.rs; should be private |
| refine.rs:47-52, 96-98, 418-427 | `TieBreak::Refuse`, `Refinement::Symmetric` | production uses `LowestIndex` only |
| compare.rs:22-24, 190-197, 483-506 | `match_names` + `compare_net_name` | production default `false`, no knob |
| compare.rs:76, 120-159, 204-217; refine.rs:269-271, 536-580 | `HELD_BACK`, `symmetric_nodes`, `is_symmetric` skip, `UnresolvedSymmetry` branch of `interpret` | **unreachable under LowestIndex** (proof below) |
| refine.rs:91-95 | `Refinement::Complete` vs `Discrepant` distinction | both go to `interpret` (compare.rs:65); only tests look |
| graph.rs:33, 119, 124 | `#[derive(PartialEq)]` on `Graph`/newtypes | only `debug_assert_eq!(out, src)` reduce.rs:185 and tests |

Proof that HELD_BACK / symmetric nodes cannot occur with `LowestIndex`: refine.rs loop only exits stable via
`stalls == 0` (no unresolved class at all) or `lowest == u32::MAX` (every stalled class has
`mine != theirs`, so `is_symmetric(mine, theirs) = mine == theirs && mine > 1` is false for all).
`Exhausted` returns before `interpret`. So `symmetric_nodes()` always returns empty vectors,
`HELD_BACK` is never written, the `is_symmetric` `continue` at compare.rs:106 never fires, and
`Inconclusive::UnresolvedSymmetry` from compare.rs:217 is unreachable. It only exists for `Refuse`
and hand-built `from_classes` partitions.

Semi-dead (produce output rows, but do no work):
- checks.rs:281-321 `check_device_counts`, `check_parametric`: each only records `Skipped(NotInDeck)` rows
  (3 rows total). 41 lines, 4 asserts. Keep the 3 rows in ~5 lines, or drop them (changes the report:
  `tests/test_all.rs:495-504` asserts they exist). Owner decision.

---

## 4. BLOAT

### 4a. Structural
| Where | What | Replace with | Saves |
|---|---|---|---|
| graph.rs:117-124 + every `.0` | `LayoutGraph`/`RefGraph` newtypes | plain `Graph`; `compare(layout, reference)` param names suffice (report is mirror-symmetric) | ~15 + noise at ~25 call sites |
| graph.rs:398-576 | `from_reference_into` borrows `net_terminal_start` as rank scratch ("graph is NOT readable" invariant) | local `Vec<u32>` rank | clarity; ~10 lines of warning comment |
| graph.rs:432-451 | unsafe `spare_capacity_mut` compaction of `net_name` | `graph.net_name.extend((0..rows).filter(|&r| netlist.net_subckt[r]==subckt).map(|r| Some(netlist.net_name[r])))` | ~18, 2 unsafe |
| graph.rs:470-529 | `span` closure, `get(..).unwrap_or(&[])`, `wrapping_sub` rebasing, then pushing a terminator "if empty" | `start[first..=last].iter().map(|o| o - start[first])` (panic on malformed netlist is fine: ingest owns validity) | ~25 |
| graph.rs:253-266 | always-store/conditionally-advance `port_net` fill | `if let Some(n) = name { port_net.push(id) }` | ~6 + 11-line ponytail comment |
| reduce.rs:79-87 | `kind_tag` duplicates refine.rs:133 `kind_code` (both = discriminant) | one fn, or `kind as u8` (same values: Mos..Diode = 0..4) | 10 |
| reduce.rs:204-221 | `copy_into` (11 column copies) | `#[derive(Clone)]` on `Graph`, `out.clone_from(src)` | 16 |
| reduce.rs:180-202 | first-pass special case + budget loop | `out.clone_from(src); while plan_into(out) { emit_into(out,..,&mut spare); swap }` | ~10 |
| reduce.rs:635-640 | `remap` | `new_net.get(n).copied().unwrap_or(u32::MAX)` inline | 6 |
| reduce.rs:1-31 | 31-line module doc incl. ponytail essay | 5 lines | 25 |
| refine.rs:482-599 | `pairs()`, `unresolved()`, `symmetric_nodes()` each re-run `tallies()` (4 Vec allocs each, 3x per compare) though `refine_observed` just computed identical `layout_tally/ref_tally/first` | have refine return the final tallies/firsts; `interpret` reads them | ~70 |
| refine.rs:455-599 + compare.rs | `Partition` as a pub type with pub readers | private struct inside compare | API |
| compare.rs:43-69 | `compare` taking `&mut Partition` scratch | allocate inside; the only caller creates a fresh one per call (run.rs:590), so reuse buys nothing | 1 param |
| checks.rs:110-128, 191-207, 354-372, 423-442 | 4 identical unsafe branchless compactions into a temp Vec, then a second loop pushing Violations | push the Violation directly in the first loop (`if keep { out.push(..) }`) | ~70, 8 unsafe |
| checks.rs:21-42 + run.rs:626-679 + pipeline.rs:171-185 | sentinel rule ids counted down from `u32::MAX`, renamed afterwards with an order-coupling assert | pass the 8 interned `StrId`s (or `&StrTable`) into the checks | ~45 (checks 10, run.rs 35) |
| checks.rs:32-42 vs run.rs:680-697 | `NOWHERE/NO_LAYER/NO_SHAPE` defined twice | one shared const set in `report` | ~15 |
| checks.rs:469-491 | `adjacent`, `examined` helpers | `windows(2)`, `as u64` | ~15 |
| checks.rs:82-89 | "fail-closed probe" whose result is only fed to a debug_assert | delete | 8 |
| hierarchical.rs | whole file | delete | 246 |

### 4b. debug_assert noise
155 in lvs/. Nearly all restate CSR lengths the constructors just wrote, re-check a sort just done
(`windows(2).all(..)` after `sort_unstable`, compare.rs:353-360, 417-424), or assert `w <= i` inside
a loop whose only purpose was a branchless compact. None can fire on data built by the two
constructors. Keep at most ~5 (e.g. transpose_into total count, reduce fixed-point budget).
Estimated ~420 lines (asserts are multi-line with messages).

### 4c. Comments
~700 comment lines of 3607. Many paragraphs defend a micro-choice ("`narrow`, not `as`", "Widened,
not narrowed: a narrowing compare would be the assert agreeing with the bug", 10-line `#[expect]`
reasons at graph.rs:204-220, refine.rs:495-502). Keep the invariant-carrying ones (listed in section 7).
Estimated ~400 deletable.

### 4d. Is the algorithm implementable more directly? Yes.
The algorithm itself is sound and minimal in shape: project -> drop bulk -> reduce both -> hash
refinement with lowest-class tie-break -> join-based verification. Nothing needs replacing. What
goes is the scaffolding around it:
1. One `Graph` type (already true) without newtypes; net-side CSR built internally.
2. One `compare()` that does steps 3-6 of the caller's sequence.
3. Refinement returns final per-class tallies + first-node; interpret builds `mate[]` from them
   (two states: paired / unpaired). No `Partition` API, no observer, no `Refuse`.
4. `Refinement` becomes `Option<tallies>` (None = round limit).

### Estimated deletable lines (src)
| File | Now | After | Deleted |
|---|---|---|---|
| hierarchical.rs | 246 | 0 | 246 |
| refine.rs | 891 | ~250 | ~640 (incl. 290 in-crate tests) |
| compare.rs | 537 | ~250 | ~290 |
| graph.rs | 653 | ~280 | ~370 |
| reduce.rs | 680 | ~400 | ~280 |
| checks.rs | 491 | ~170 | ~320 |
| verdict.rs | 92 | ~60 | ~30 |
| **lvs total** | **3607** | **~1450** | **~2150** |
| run.rs LVS part | ~255 | ~150 | ~105 |

---

## 5. PROPOSED SIMPLE API

```rust
// lvs/mod.rs — everything else private
pub struct Graph { /* device_kind, device_model, device_terminal_start, terminal_net,
                      terminal_role, device_param_start, param, net_name, port_net */ }
impl Graph {
    pub fn from_layout(nets: &NetTable, devices: &DeviceTable, ports: &PortTable,
                       strings: &StrTable, grid: Option<Grid>) -> Graph;
    pub fn from_reference(netlist: &Netlist, subckt: SubcktId) -> Graph;
}
pub struct CompareOptions { pub max_rounds: u32, pub param_tolerance: f64 }  // Default 1000 / 0.02
/// drop_unextracted_bulk + reduce both + refine + interpret.
pub fn compare(layout: &Graph, reference: &Graph, opts: CompareOptions) -> Verdict;
/// The 6 layout checks; `ids` = the 8 interned rule names in fixed order.
pub fn check_layout(layout: &Graph, nets: &NetTable, devices: &DeviceTable, ports: &PortTable,
                    ids: &[StrId; 8], out: &mut Violations, runs: &mut Vec<RuleRun>);
pub use verdict::{Verdict, Inconclusive /* RoundLimit, AmbiguousTop */, Discrepancy, Side};
```
Out-parameter `_into` style can stay on `from_*` if allocation reuse matters; the engine creates
fresh graphs every run (run.rs:533-590), so it currently buys nothing.

`run_lvs` shrinks to: build layout graph, `check_layout`, `match reference.top()`, build ref graph,
`compare`, map verdict. `name_lvs_check_rows` and sentinel ids disappear.

Engine-visible behavior: identical, provided hash codes/constants are kept bit-exact (section 7).

### Tests made obsolete
| Test file | Lines | Fate |
|---|---|---|
| tests/lvs/hierarchical.rs | 350 | delete (10 tests) |
| refine.rs in-crate `tests` + `partition_tests` | 290 | delete (observer/from_classes/PartialEq) |
| tests/lvs/refine.rs | 366 | 11 tests on `refine_into`/`Partition::pairs/unresolved`; 4 use `Refuse`. Rewrite the useful ones (convergence, round limit, permutation invariance) through `compare()`; drop the rest |
| tests/lvs/compare.rs | 971 | 28 tests. Obsolete: those on `interpret`+`from_classes` (lines ~253-350: 3 tests), `Refuse` (781, 831, 888: 3 tests), `match_names` (690: 1), `interpret` re-read (914: 1). ~8 tests, ~250 lines. The swap/terminal/param/bulk/BJT tests stay |
| tests/lvs/graph.rs, reduce.rs, checks.rs, terminal_order.rs | 1030 | keep; mechanical edits (drop newtypes, `from_*` returns) |
| tests/engine/{checks,pipeline}.rs | — | drop `tie_break`/`match_names` fields from literals |
| tests/test_all.rs:495-504 | — | only if device_count/parametric skipped rows are removed |

---

## 6. SIMD CANDIDATES (`fearless_simd` 1.0)

Honest answer: **none worth it.** Every hot loop is gather/scatter over CSR or a sort.

| file:line | Loop | Elem | Typical N | Dependency | Contiguity | Verdict |
|---|---|---|---|---|---|---|
| refine.rs:159-185 | per-node neighbour hash `mix(role<<8 ^ class[net]<<16)` summed | u64 | terminals, 1e2-1e6 per round | independent per terminal, segmented sum per node | **gather** on `class[net]` | no: needs gather + 64-bit multiply (no native u64 mul on AVX2/NEON); per-node runs are 2-4 wide |
| refine.rs:235 | `signature.sort_unstable()` of `(u64,u32)` | 12B | nodes, every round | sort | contiguous | dominant cost; SIMD N/A. Algorithmic win instead: re-hash only nodes adjacent to a class that split, or radix sort |
| refine.rs:242-247 | class renumber | u64 cmp -> scatter | nodes | serial prefix count + scatter | scatter | no |
| refine.rs:275-289 | `tally_into` histogram + min | u32 | nodes | scatter conflicts | scatter | no |
| graph.rs:301-332 | transpose histogram / prefix / fill | u32 | terminals | serial prefix, scatter | scatter | no |
| graph.rs:407-413 | reference rank = prefix count of a mask | u32 | ref nets (1e2-1e4) | prefix scan | contiguous | could be SIMD prefix, but N tiny, runs once |
| checks.rs:357-369 | `terminal_net >= net_count` filter | u32 | terminals | independent | contiguous | autovectorizes already if written as plain filter; runs once |
| compare.rs:450-452 | param tolerance compare | f64 | a few per device | independent | tiny | no |

Real performance lever (not SIMD): refinement re-signs and re-sorts **all** nodes every round for
up to `diameter` rounds (O(R · N log N)). Worklist refinement that only re-signs neighbours of split
classes is the standard fix. Out of scope for simplification; mention only.

---

## 7. ACCURACY-SENSITIVE CODE (do not change semantics while simplifying)

1. **Hash constants and codes are observable.** refine.rs:105-109 `mix`, 121-131 `role_code`,
   133-141 `kind_code`, 145-147 tags, 153-155 `neighbour`, 159-185 signature composition. Signatures
   determine sort order -> `ClassId` numbering -> which class the tie-break picks (`lowest` class,
   refine.rs:393) -> which nodes are paired in symmetric structures -> which devices/nets a `Mismatch`
   names. Keep bit-exact. (`kind as u64` equals `kind_code`, so that swap is safe.)
2. **S/D collapse** (`role_code` Source=Drain=1, `Pin(_)`=7) and **Emitter != Collector**. reduce.rs:49
   `CHANNEL = 8` must stay > every role code: `split_keys` (reduce.rs:129) relies on it.
3. **Tie-break**: lowest balanced class, lowest node index per side (refine.rs:381-448); one class per round.
   `stable = count == class_count` (refine.rs:360).
4. **Signature sort tie on node index** (refine.rs:235) keeps it deterministic.
5. **compare_terminals** (compare.rs:294-389): `checked_add` catches `u32::MAX` (NetId::NONE) terminals;
   key `(role_code, mate, slot)`; both tails reported (mirror symmetry).
6. **compare_params** (compare.rs:399-471): *stable* sort by name; `spread <= tol * max(|a|,|b|)`; NaN fails;
   one-sided names -> `UndeclaredParam`.
7. **Param projection** (graph.rs:204-237): emitted only if the SPICE name is interned; metres via
   `1e-6/dbu_per_um`, area scaled by `scale*scale`; nothing emitted without a grid.
8. **drop_unextracted_bulk** condition (graph.rs:602-609) and its position before reduce (run.rs:583).
9. **card_role** order (graph.rs:639-653): drain-first MOS, collector-first BJT.
10. **reduce refusals** (reduce.rs:286-288, 345-396, 429-493): parameterised devices never merge; unnamed,
    non-port 2-terminal nets only; same kind/model/non-channel terminals; parallel-through-both-nets guard;
    `dissolve_invalid` for rings. Root = lowest index -> emission order.
11. **interpret output order**: ClassImbalance first, then per-pair identity/terminal/param, then unpaired
    layout, then unpaired reference; `ClassImbalance` double-report is deliberate. Order is user-visible
    through `format.rs:98` `{:?}`.
12. **Checks run on the unreduced layout graph** (run.rs:543 before 586).
13. **Rule-id order** coupling: `LVS_RULE_IDS` index = `Discrepancy` variant; `LVS_CHECK_RULE_IDS[k]` =
    sentinel `u32::MAX-k`. Removing `lvs.duplicate_name` from the interned list shifts later StrIds; run
    rows are sorted by `StrId` (run.rs:294), relative order of the rest is preserved only if StrTable ids
    are sequential. Verify before removing.
14. **check_topology** measured/limit values (checks.rs:388-389, 455-456), `LEGAL_WIDTHS` table.
15. `from_reference_into` keeps **subckt port order** (graph.rs:564-572), layout keeps ascending; only
    reduce's `is_port` reads it, so order is irrelevant to the verdict, but keep it if `port_net` gains a user.
