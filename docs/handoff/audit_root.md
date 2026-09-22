# Audit: root package, testgen, root tests, docs

Scope: `src/` (5,035 lines), `crates/testgen` (~2.7k), `tests/` (root), `docs/` (6 files, ~2.9k).
Method: read every file in `src/`, grepped callers across the workspace. Nothing edited.

---

## 1. End-to-end data flow

```
argv: Vec<String>
  └─ args::parse(&[String]) -> Result<Args, ArgError>            src/bin/gpurify/args.rs:88
       Args { command: Command{Drc|Erc{intent}|Lvs{reference}|Pex{quasistatic,quasistatic_inductance}|All{reference,intent}},
              common: Common{layout, deck, format: Format, output, threads, check_determinism, strict_layers, grid: Option<u32>} }
  └─ args::to_inputs(&Args) -> (Inputs, RunOptions)               args.rs:331
       Inputs     { layout: PathBuf, deck: PathBuf, grid: Option<Grid>, reference: Option<PathBuf>,
                    intent: Option<PathBuf>, unknown_layers: UnknownLayers }          engine/pipeline.rs:13
       RunOptions { checks: Checks{drc,erc,lvs,pex: bool}, lvs: CompareOptions,
                    quasistatic_nets: Vec<String>, quasistatic_inductance: bool, threads: Option<usize> }  engine/run.rs:38
  └─ pipeline::load_into(&Inputs, &mut Loaded) -> Result<(), LoadError>              pipeline.rs:97
       fs::read_to_string(deck)
       parse_deck(src, grid, &mut throwaway StrTable)      -> staging Deck   (parse #1)
       read_layout(path, &staging, unknown) -> Layout{strings, store, provenance}  (opens + reads GDS/OASIS itself)
       parse_deck(src, grid, &mut layout.strings)          -> Deck           (parse #2)
       provenance.resolve_labels(&store, &deck.connectivity)
       read_reference (SPICE/Spectre sniff) / read_intent  -> interned into the same StrTable
       intern_report_ids(&mut strings)                     (15 LVS rule names)
       Loaded { strings: StrTable, grid: Option<Grid>, deck: Deck, store: GeometryStore,
                provenance: Provenance, reference: Option<Netlist>, intent: Option<DesignIntent> }
  └─ pipeline::extract_into(&Loaded, &mut Extracted) -> Result<(), ExtractError>     pipeline.rs:249
       derived.evaluate(&store)          (Evaluator is always Default -> no-op, see 3.1)
       refuse_conducting_channels -> extract_nets_into -> recognise_into -> bind_ports_into
       Extracted { derived: Evaluator, nets: NetTable, devices: DeviceTable, ports: PortTable }
  └─ run::run_checks(&Loaded, &Extracted, &RunOptions, &mut Outputs) -> Result<Summary, EngineError>  run.rs:226
       reject_unknown_rule_kinds; clear Outputs column-by-column
       run_drc  : drc::RuleSet::from_deck -> rules.run(Design, Scratch, &mut Violations, &mut Vec<RuleRun>)
       run_erc  : erc::RuleSet::from_deck, design_extent (die), classify_nets_into, resolve_intent_into,
                  power::extract_nets_into, power::extract_into, power::solve_into -> rules.run(RunInputs..)
       run_lvs  : graph::from_layout_into, 6 lvs::checks (sentinel StrIds renamed), from_reference_into,
                  drop_unextracted_bulk, reduce_into x2, lvs::compare -> Verdict; Mismatch -> Violations rows
       run_pex  : analytical::extract_into  [+ quasistatic::extract_into, reciprocity check,
                  optional extract_inductance_into, merge_field_solved_into]
       sort_canonical; count severities / clean / skipped
       Outputs { violations: Violations (SoA), runs: Vec<RuleRun>, lvs: Option<Verdict>, parasitics: Option<ParasiticNetwork> }
       Summary { drc/erc/lvs/pex: StageStatus{Ran|NotSelected|Skipped(&str)|Refused(String)},
                 violations, errors, warnings, rules_clean, rules_skipped: u32 }
  └─ writers (all append into a caller String)
       text : format::write_violations(&Outputs, &StrTable, Grid, &mut String)       bin/gpurify/format.rs:15
              format::write_summary(&Summary, &mut String)                            format.rs:162
       json : export::json::write_report(&Report{header,violations,runs,strings,grid}, &mut String)  export/json.rs:29
       spef : export::parasitic::write_spef(&ParasiticNetwork, &PortTable, &StrTable, &Header, &mut String)  parasitic.rs:241
       dspf : export::parasitic::write_dspf(same)                                     parasitic.rs:359
       gds  : parsed, then refused in main.rs:25 (write_markers never reached)
       spice: export::netlist::write_spice — no production caller
  └─ main: fs::write(output) or print!; exit 0 iff Summary::passed()
```

Also `engine::run::run(&Inputs,&RunOptions,&mut Outputs)` (run.rs:1080) does the three steps in one call; the CLI does not use it (it re-implements it inline at main.rs:47-60 because it needs `loaded.strings`/`grid` afterwards for rendering — a sign the coarse call returns too little).

---

## 2. Module map

### src/ (5,035 lines; ~828 comment lines, 103 debug_asserts)

| file | lines (non-test / test) | purpose |
|---|---|---|
| src/lib.rs | 24 | re-exports 4 crates + `engine`, `export`, `prelude` |
| src/engine/mod.rs | 10 | re-exports |
| src/engine/pipeline.rs | 332 / 0 | Inputs, Loaded, Extracted, load_into, extract_into, netlist dialect sniff, errors |
| src/engine/run.rs | 1115 / 72 | Checks, RunOptions, StageStatus, Outputs, Summary, run_checks, run_drc/erc/lvs/pex, LVS id tables, PEX merge, run(), EngineError |
| src/export/mod.rs | 43 | WriteError, Header, `narrow`, `INFALLIBLE` |
| src/export/json.rs | 325 | hand-written JSON report writer + escape tables + `format_f64` |
| src/export/parasitic.rs | 462 | SPEF + DSPF writers |
| src/export/netlist.rs | 340 | SPICE writer (test-only callers) |
| src/export/gds.rs | 314 | GDSII writer: `write_store` (test fixture use) + `write_markers` (test-only) |
| src/bin/gpurify/main.rs | 198 / 101 | CLI driver, determinism loop, exit code |
| src/bin/gpurify/args.rs | 423 / 630 | hand-rolled argv parser + to_inputs |
| src/bin/gpurify/format.rs | 224 / 344 | text renderer |
| src/bin/probe_conformance.rs | 78 | ad-hoc debug print of net-size histogram; unreferenced |

(testgen and tests tables: see sections 4-5.)

---

## 3. Dead code / bloat in src/

Estimated deletable lines are for the file as it stands; totals at the end.

### 3.1 Dead or production-unreachable items

| where | what | evidence | delete |
|---|---|---|---|
| src/bin/probe_conformance.rs:1-78 | whole binary | no reference anywhere (grep); hard-coded paths; `println!` debug | 78 |
| src/export/netlist.rs:1-340 | `write_spice`, `Detail`, `net_name` | only callers: tests/export/netlist.rs, tests/export/determinism.rs:117. CLI has no spice format | 340 (+ ~330 test lines) |
| src/export/gds.rs:122-170 `write_markers` | marker GDS | CLI refuses `--format gds` at main.rs:25-32; only tests call it | ~50 (+ tests) |
| src/export/gds.rs:52 `write_store` | layout GDS writer | only used by tests to synthesize fixture layouts (tests/common/mod.rs:457, test_all.rs:191, derived_layers.rs:64). Move to testgen | move ~260 out of src |
| src/bin/gpurify/args.rs:63-83, 305-317, 719-755; main.rs:23-32, 104 | `Format::Gds` variant | parsed only to be refused | ~45 |
| src/export/json.rs:105-120 `write_summary` | | only tests/export/determinism.rs:75 | 17 |
| src/lib.rs:19-24 `prelude` | | zero users | 6 |
| src/engine/run.rs:47-49, main.rs:139-164, args.rs `--threads` | `RunOptions::threads` | read nowhere except a debug_assert (run.rs:243). No rayon pool is built from it. So `--threads` is a no-op and `--check-determinism` runs the SAME configuration twice (it flips a field nothing reads) | field+flag+loop ~70 |
| src/engine/pipeline.rs:66, :258; ExtractError::Derived | `Extracted::derived: Evaluator` | always `Evaluator::default()`; nothing in src/ or tests ever calls `Evaluator::plan` into it (comment at :255 admits it). Derived layers are materialised into the store by `ingest` (deck.rs:535 build_derived; tests/derived_layers.rs). This is a second, dead derived-layer path that `check::Design.derived` also carries | ~10 here; more in check crate (other auditor) |
| run.rs:124, 196-199, 409-411, 793-795 | `NO_GRID`, `run_grid`, two `Skipped(NO_GRID)` arms | `load_into` returns `LoadError::NoGrid` before a `Loaded` exists, and sets both `loaded.grid` and `deck.grid` to the same value. Only reachable by a hand-built `Loaded`. Make `Loaded.grid: Grid` | ~15, plus the `.expect` in main.rs:66 |
| pipeline.rs:149-171 `intern_report_ids` (pub) | exists for "an embedder building Loaded by hand" | no such embedder; see 3.3 | folded into 3.3 |
| run.rs:1080-1094 `run()` | coarse call | no production caller (CLI inlines it). Keep but make it the thing the CLI uses (section 7) | 0 |

### 3.2 The `*_into` / reuse-buffer pattern — never exploited

- Production: `main.rs:47-49` builds fresh `Loaded/Extracted/Outputs` every pass (comment says reuse would be wrong). `run()` (run.rs:1087-1090) builds fresh. `bench_all.rs:689` even does `outputs = Outputs::default()` before every `run_checks`.
- The only exploitation is a test asserting reuse works: `tests/engine/pipeline.rs:164 extracting_twice_into_one_buffer_gives_the_same_answer_as_extracting_once`.
- Cost of the pattern: run.rs:252-268 (clears 8 SoA columns by name because `Violations` has no `clear`), run.rs:950-956 (clears 5 `ParasiticNetwork` columns by name because `clear` is crate-private), pipeline.rs:98-100 (grid reset "for a caller that kept the buffer"), `Loaded.grid: Option` + `Default` impls on Loaded/Extracted/Outputs, the `.expect` at main.rs:66, the reuse test.
- Verdict: return by value. `fn load(&Inputs) -> Result<Loaded>`, `fn extract(&Loaded) -> Result<Extracted>`, `fn check(..) -> Result<(Outputs, Summary)>`, `merge_field_solved(..) -> ParasiticNetwork`. ~45 lines in src, ~40 in tests, and removes a class of "stale buffer" bugs rather than guarding against it. (Keep `_into` inside the hot kernels in `check`/`extract` where scratch reuse is real — not this layer's concern.)

### 3.3 LVS_RULE_IDS interning dance (run.rs:611-737, pipeline.rs:149-171)

Current mechanics: `run_checks` borrows `Loaded` shared so it cannot intern; therefore (a) `load_into` pre-interns 15 names via `intern_report_ids`; (b) `lvs::checks` (in `check` crate) files rows under sentinel `StrId(u32::MAX - k)`; (c) `name_lvs_check_rows` maps sentinels back through `LVS_CHECK_RULE_IDS` with 2 debug_asserts on ordering; (d) `lvs_rule_id` maps each `Discrepancy` variant through `LVS_RULE_IDS` with a `StrId(u32::MAX)` fallback. Order coupling between two crates is enforced only by a debug_assert.

Fix: pass the string table mutably to the LVS step (split borrow: `lvs(&mut loaded.strings, &loaded.reference, &extracted, ..)`, or intern in the check crate given `&mut StrTable`). The check functions take the `StrId` they file under, or intern their own `&'static str` name. Deletes: `LVS_CHECK_RULE_IDS`, `name_lvs_check_rows`, `intern_report_ids`, sentinel counting in `check::lvs::checks`, fallback in `lvs_rule_id` (match can return `strings.intern("lvs.unpaired_device")` directly). ~110 lines in src + tests/engine/pipeline.rs:269-378 (two tests about interning) + sentinel code in check crate.

### 3.4 Double deck parse (pipeline.rs:112-127)

`read_layout` returns its own `StrTable`, so the deck is parsed once into a throwaway table (to map layers during the read) and again into the layout's table, plus a debug_assert that both parses agree. Fix in `ingest`: `read_layout(bytes: &[u8], deck: &Deck, strings: &mut StrTable, unknown)` — parse the deck once into the run's table, then read the layout into the same table. Also takes file I/O out of `ingest` (caller owns I/O). ~15 lines here; the comment block alone is 5.

### 3.5 debug_asserts (103 in src)

Most restate the line above or a type invariant another crate already owns. Categories:
- Counter-only-for-assert: `recorded`/`written` counters in format.rs:27-50, 52-89; `before`/`after` in run.rs:701-718; append_stage row count (run.rs:360). The loop cannot drop rows.
- Restating another crate's invariant: pipeline.rs:74, 227-231, 238-248; run.rs:232-246, 435-438, 941-948, 1051-1063 (plus the whole `replaced_node_count` helper run.rs:1066-1077, which exists only to feed an assert), parasitic.rs:44, 95, 121, json.rs:31-42, 252-258, 283.
- Tautologies: run.rs:162-169, 189-192 (bbox runs low to high), main.rs:46, 172, 185; args.rs:239-240, 268, 332-336, 405-406; json.rs:283 (escaped text is longer).
Keep ~10: the ones that guard a real cross-crate contract cheaply (e.g. merge's "nets are one ascending range" at run.rs:941, and `is_finite` before writing). Estimated ~250 lines deletable (asserts are 3-6 lines each with messages).

### 3.6 Comments

828 of 5,035 lines are `//` comments, plus `///` docs averaging 4-8 lines per private fn. Many narrate history or defend decisions ("Hand-written for one field...", "Parsed twice, into two string tables...", the 10-line ponytail blocks at run.rs:778-786, 858-865). Several are stale — they name crates that no longer exist:
- format.rs:93-97 "`gpurify-lvs` is not a dependency and `gpurify_engine` re-exports…" — false: `gpurify::check::lvs::Verdict` is reachable. The `{verdict:?}` Debug print can become a real match.
- format.rs:221-223 "`gpurify-core` is not a dependency" — no such crate; `gpurify::geom::{LayerId,PolyId}` is nameable, so the `push_row!` macro (format.rs:238-253) is unnecessary.
- args.rs:410-415 `#[expect(clippy::default_trait_access, reason = "...gpurify_check is not a dependency of cli...")]` — `gpurify::check::lvs::CompareOptions::default()` is nameable.
- args.rs:54 references `gpurify_ingest::layout::LoadError` (does not exist; it is `engine::pipeline::LoadError`).
- run.rs:15-16 "CONVENTIONS §3".
Target: one line per pub item, zero on private fns unless non-obvious. ~550 lines deletable.

### 3.7 args.rs (1,053) and main.rs (299)

- args.rs non-test is 423 lines for 5 subcommands and 11 flags. Two structs (`Args{Command, Common}`) exist only to be flattened again in `to_inputs` (90 lines of tuple-building, args.rs:331-422). Per-subcommand "refuse" matrix (args.rs:199-248) is 50 lines.
- Proposal: parse straight into `(Inputs, RunOptions, Format, Option<PathBuf> output)`. One `while let Some(tok)` loop with `it.next()` for values; subcommand sets `Checks`. Drop the "refuse --intent on drc" matrix (or keep one line: reject flags not in the subcommand's allow-list string). Result: ~110 lines. No new dependency needed (clap would be ~40 lines but adds a heavy dep; not worth it).
- args.rs tests (630 lines, 18 tests) → one table test of ~15 argv→result rows, ~60 lines. Tests like `parsing_the_same_argv_twice_gives_the_same_answer` (args.rs:878) and `permuting_the_options_does_not_change_the_parse` (:839) test a pure function for purity.
- main.rs: with `--threads` inert, the determinism loop (main.rs:36-165) is a 2-pass comparison of identical configurations. Either wire `threads` to a `rayon::ThreadPoolBuilder` (then the gate means something) or delete the loop, flag, and field. Deleting: main.rs → ~70 lines. The 7 `Summary::passed` tests in main.rs:199-299 test engine logic from the binary; move 2 of them next to `Summary` (the other 5 duplicate tests/engine/summary.rs — see section 5).
- Estimated: args+main 1,352 → ~250. Saves ~1,100.

### 3.8 format.rs (568)

- 224 lines of renderer, 344 of tests. The renderer is reasonable but carries 9 debug_asserts, counter variables, and a `write_measurement` area branch that re-derives nm/dbu with 2 asserts and an `#[expect]` (format.rs:108-143) — json.rs:161-208 does the same conversion again (`nm_per_dbu`). One shared `Measurement -> (f64, unit)` helper in `export` serves both.
- Tests: 10 tests incl. two "renders identically twice" (format.rs:347, 521). Keep one golden-text test (~40 lines).
- Estimated 568 → ~140.

### 3.9 export/ writers

- json.rs: hand-written JSON (escape table ESCAPE/CONTROL 256+32 entries, json.rs:243-297; `write_int`, `columns_agree` duplicating `Violations`' private one). `serde_json` is already a dependency of this package. `serde_json::to_writer` on a `#[derive(Serialize)]` view struct is deterministic (field order = declaration order) and handles escaping. Caveat: `format_f64` prints `{:.6}`; a serde path needs a `serialize_with` for floats to keep bytes identical, or re-baseline golden files. 325 → ~90.
- parasitic.rs: `is_non_decreasing` (parasitic.rs:25-32) = `slice::is_sorted()` (already used in run.rs:942); `every_far_node_present` = one `iter().zip().all()`. ~30 lines. Comment density 83/462.
- export/mod.rs: `narrow` + `INFALLIBLE` constants for `write!` into String — use `let _ =` (format.rs already does) or `.unwrap()`; ~8 lines.
- Estimated export/ total 1,484 → ~600 after removing netlist.rs, moving write_store to testgen, deleting write_markers, serde for json.

### 3.10 run.rs other

- `Checks` 4 bools + `ALL` const fine. `append_stage` (run.rs:351-368) exists because DRC/ERC `run` clear their output; with by-value returns from those crates it becomes `out.violations.extend(..)`.
- Severity counting loops (run.rs:299-319) are written branchless over tiny arrays; `iter().filter().count()` is 4 lines vs 20.
- `merge_field_solved_into` (run.rs:936-1064, 130 lines): legitimate, but belongs in `gpurify_extract` next to `ParasiticNetwork` (it needs the crate-private `clear`, and its invariants are that crate's). `reciprocity_refusal` likewise: `quasistatic::extract_into` should return `Err` on asymmetry itself.
- LVS sentinels `NO_LAYER/NO_LOCATION/NO_SHAPE` (run.rs:681-696): consequence of forcing LVS discrepancies into the DRC `Violations` table; acceptable, but 16 lines of doc for 3 consts.

### 3.11 Totals for src/

| item | lines |
|---|---|
| probe_conformance | 78 |
| netlist.rs (no prod caller) | 340 |
| write_markers + Format::Gds | ~95 |
| write_store moved to testgen | ~260 (moved, not deleted) |
| threads/--threads/determinism loop | ~70 |
| reuse-buffer pattern | ~45 |
| LVS id dance | ~110 |
| double parse, derived Evaluator, NO_GRID | ~40 |
| debug_asserts | ~250 |
| comments | ~550 |
| args.rs + main.rs rewrite (beyond above) | ~800 |
| format.rs | ~430 |
| json via serde, parasitic stdlib | ~270 |
| **src/ total** | **~3,100 of 5,035 deleted or moved (~62%)** |

---

## 4. testgen (crates/testgen, 2,750 lines; 1,835 code, ~460 self-test lines / 29 tests)

| file | lines | main consumers |
|---|---|---|
| rng.rs | 173 | `Rng` — 33 files (geom, ingest, check/lvs, extract) |
| shapes.rs | 460 | `LayoutBuilder`, `rect`, `hole`, `l_/plus_/u_shape`, `random_rectilinear_layer` — ~32 files (geom, check/drc, root) |
| assertions.rs | 292 | `assert_close*`, `assert_rule_ran`, `assert_clean`, `assert_only_violation`, `assert_violations_eq`, `assert_bytes_identical` — check, extract, root |
| violation.rs | 659 | `layout_with_violation` + `Amount/ShapeKind/ViolationShape/ViolationCase` — all check/drc/*_rules.rs (7 files) |
| netlist.rs | 402 | `layout_from_netlist`, `DeviceSpec/NetlistSpec/Floorplan` — check/erc, check/topology (7-8 files) |
| scale.rs | 253 | `scale_corpus` — extract/{field,pex}/common, tests/bench_all.rs:48, format.rs tests |
| graph.rs | 188 | `graph_with_partition` — 1 file (geom connectivity_components.rs:12) |
| electrical.rs | 299 | `ladder_network` — 1 file (check/erc effective_resistance_laws.rs:16) |
| lib.rs | 24 | re-exports |

Used by ~70 test files across all 4 crates + root. **Unused pub items**: the entire parallel-plate section of electrical.rs — `EPSILON_0` (:12), `PlateCase` (:106), `PlateAnswer` (:115), `PlateSpec` (:130), `plate_answer` (:145), `parallel_plate` (:189); only its own tests use it (~155 lines incl. :243-299).

Verdict: **keep the crate, trim it.** Cargo integration tests cannot share a `tests/common` across crates, so a shared dev-crate is the right shape. Delete the plate section (~155). Optionally delete the 29 self-tests of test helpers (~460; keep `violation.rs:633` and `graph.rs:170`, which pin behaviour consumers rely on). Move `export::gds::write_store` here from `src/` (it is a fixture-writing tool, not a product feature). Candidates to inline into their single user: `graph.rs` (1 user), `ladder_network` (1 user) — ~250 lines leave testgen but land in a test file; net zero, only worth it for locality.

---

## 5. Tests

### 5.1 The accuracy gate (keep, untouched)

All in `tests/test_all.rs`, driven by `tests/common/mod.rs`:

| test | line | covers |
|---|---|---|
| `every_drc_case_in_the_corpus_agrees_with_its_geometry` | :326 | 94 DRC cases |
| `every_erc_case_in_the_corpus_agrees_with_its_geometry` | :346 | 30 ERC cases |
| `every_lvs_cell_in_the_corpus_extracts_the_devices_it_draws` | :368 | 16 LVS cells (device/net counts) |
| `a_real_extraction_and_a_reference_netlist_reach_a_verdict_and_eight_run_rows` | :422 | LVS verdict vs `lvs_inv.cdl` |
| `every_pex_case_in_the_corpus_agrees_with_its_closed_form` | :571 | 27 PEX cases |
| `lateral_coupling_halves_when_the_gap_doubles_and_ignores_the_axis` | :591 | 1/S law for 3 `underivable` cases |
| `a_field_solve_obeys_the_coupling_laws_a_closed_form_cannot_state` | :666 | quasi-static PEX |
| intent-gated ERC end-to-end (hv_domain, ir_drop, bti, esd_latchup, EM/Blech) | :783, :979, :1152, :1267, :1428, :1534, :1730 | only end-to-end coverage of intent-gated rules |

Mechanism: `common::load_corpus()` (common/mod.rs:761) deserialises `expectations.json`; `gen_fixtures::fixtures()` splits `_source/conformance.gds` into per-case GDS using `manifest.json` (`gds_file`, `cell` only); each case runs through `run_case` (:834) → `check_geometry_case` (:1091) / `check_lvs_case` (:1456) / `check_pex_case` (:1583), filtered by the case's `assert` list; failures aggregated by `report_domain` (:1843).

Crate-level oracles that are STRONGER than the corpus and must stay: DRC per-rule files (off-by-one boundary cases via `layout_with_violation`), ERC per-rule files (21 of 30 ERC corpus cases are not `strong`), LVS compare.rs.

### 5.2 Plumbing tests and redundancy (root)

| file | lines | tests | kind / note |
|---|---|---|---|
| test_all.rs :46-291 + :1870 | ~300 | 12 | plumbing via hand-built `common::Run` |
| engine/checks.rs | 681 | 10 | StageStatus/determinism on `Extracted::default()` |
| engine/pipeline.rs | 378 | 9 | load order, buffer reuse (:164), interning (:269-378) — most vanish with section 7 |
| engine/summary.rs | 243 | 7 | `Summary::passed` truth table — also duplicated by 7 tests in src/bin/gpurify/main.rs:199-299 |
| export/determinism.rs | 205 | 9 | 7 copies of one pattern, one per writer |
| export/netlist.rs | 312 | 12 | tests a writer with no production caller |
| export/gds.rs | 239 | 8 | tests `write_markers` (unreachable) + `write_store` |
| export/json_report.rs | 345 | 10 | plumbing |
| export/parasitic.rs | 265 | 10 | plumbing |
| export/format_f64.rs | 175 | 8 | tests `format!("{:.6}")` |
| export/fixture/mod.rs | 392 | 0 | builder for export tests |
| derived_layers.rs | 245 | 4 | real semantics (deck derived layers through GDS round-trip) — keep |
| pdk_decks.rs | 424 | 8 | lints every shipped PDK deck — keep |
| bench_all.rs | 804 | 6 | NOT a bench: 6 `#[test]`s under plain `cargo test`, 100k-polygon corpora in debug, timings printed not gated |
| common/gen_fixtures.rs | 436 | 1 | its one test is compiled into 2 binaries (test_all + engine/main.rs:6-7) and is near-circular |

Redundant / vacuous:
- `test_all:130` = `engine/checks.rs:93` = `engine/summary.rs:154` (nothing selected ⇒ pass).
- `test_all:229` = `engine/checks.rs:597` (unknown rule kind refused).
- `test_all:160` "same bytes at 1 and 4 threads" = `engine/checks.rs:404` = `export/determinism.rs:60` — **and all three are vacuous**, because `RunOptions::threads` is read by nothing (section 3.1). They compare a run with itself.
- `test_all:1870` ≈ `engine/pipeline.rs:164` ≈ `engine/checks.rs:429` ≈ extract/check crate determinism tests (determinism is tested in ≥6 places).
- `engine/summary.rs` (7) + main.rs tests (7) → one table test.
- Purity tests of pure fns: `export/netlist.rs:189`, `export/parasitic.rs:216`, `export/format_f64.rs:54,:70,:135`, `args.rs:839,:878`, `format.rs:347,:521`.
- Crate duplicates of corpus: `crates/extract/tests/pex/analytical.rs` — 1-ohm ten-square wire (= PEX_WIRE_R), width doubling (= PEX_WIDTH_100/400), via cuts (= PEX_VIA_R/R2), coupling vs spacing (= test_all:591). ~120 lines.
- Corpus plumbing: `manifest.json` (1,588 lines) is read only for `gds_file` + `cell`; put `cell` into expectations.json and delete it (+~60 lines of Manifest code). `klayout/drc_oracle.rb` unused. `tests/common/mod.rs` has no dead fns, but `with_unknown_rule_kind`, `execute_with_threads`, `serialise` (~80 lines) die with the redundant tests. `run_case_field_solved` (:936-990) duplicates `run_case_inputs` (:886) except RunOptions.

Estimated root-test deletions without losing any accuracy check: export/netlist.rs 312 + gds marker tests ~100 + engine/pipeline reuse/interning ~150 + summary/main dupes ~300 + determinism collapse ~110 + purity tests ~120 + test_all redundant + Run ctors ~200 + bench_all 804 (or `#[ignore]`) + manifest path ~60 ≈ **2,100 lines**, plus ~40% comment density in test_all.rs (809 comment lines) and 28% in common/mod.rs.

---

## 6. docs/

| doc | lines | verdict |
|---|---|---|
| NEED_TESTING.md | 1,562 | real to-do list: 79 entries at ~20 lines each, grouped by pre-merge crate names (`core`,`pex`,`lvs`,`cli`…). `antenna` entry is RETIRED; `Run::summary`/`Run::execute` no longer exist. → one line per item (~120) or GitHub issues |
| CORRECTNESS_MAP.md | 428 | log of finished work; every line number checked has drifted; references `units/core/pex/lvs` crates; its priority item 1 is already done. → delete, salvage priority items 3-6 (~15 lines) |
| TESTING.md | 352 | stale: cites `tests/corpus/` (does not exist), `keyhole_rejected` (not found), ~100-line history table of a 14-crate layout; contradicts CORRECTNESS_MAP on mutation testing. → ~80 lines: oracles, gates, how to run |
| CONVENTIONS.md | 192 | titled "GPUVerify"; §7 says every test body is `todo!()`; claims `wide` is used (no crate depends on it). Rubric §0-6 is sound. → ~100 |
| VOCABULARY.md | 181 | phase vocabulary for retired phases + copy of a skill + index into CONVENTIONS. → delete, move ~10-line "rejected terms" to CONVENTIONS |
| GPU.md | 170 | cites deleted `backend/src/gpu.rs`, `vulkano_backend.rs`. Crossover table + contract unique. → ~50, or a section of ARCHITECTURE |
| README.md | 322 | keep, trim to ~200 (overlaps TESTING/GPU; "874 tests" vs 875) |
| tests/fixtures/README.md | 142 | most stale: 161 gds (168), ERC 23 (30), 160 cases (167), strength table contradicts expectations.json `counts`. → ~40, no hard-coded counts |

Total 3,349 → ~740.

Proposed structure:
```
README.md            ~200  install, CLI, accuracy summary, pointer to docs
docs/ARCHITECTURE.md ~150  one section per crate, each exactly:
    ## <crate>
    In:  <data types / files it consumes>
    Out: <data types it produces>
    Entry: <3-6 fns, signatures>
    Invariants: <≤3 bullets>
  geom    In: Dbu coords, rect/poly builders   Out: GeometryStore, Bbox, Qty      Entry: GeometryStoreBuilder::finish, boolean, index::candidate_pairs
  ingest  In: deck JSON, GDS/OASIS bytes, SPICE/Spectre, intent JSON  Out: Deck, GeometryStore+Provenance, Netlist, DesignIntent  Entry: parse_deck, read_layout, netlist::{spice,spectre}::read, read_intent
  check   In: store, deck, extraction, netlist, intent  Out: Violations+RuleRun, Verdict, NetTable/DeviceTable/PortTable  Entry: topology::{extract_nets,recognise,bind_ports}, drc/erc::RuleSet::{from_deck,run}, lvs::compare
  extract In: store, nets, ProcessStack, Grid  Out: ParasiticNetwork, CapMatrix  Entry: analytical::extract, quasistatic::extract (+GPU crossover note)
  root    In: Inputs  Out: Report  Entry: load, extract, drc, erc, lvs, pex, run; writers json/spef/dspf/text
  testgen In: seed+spec  Out: layout with known answer
docs/CONVENTIONS.md  ~100
docs/TESTING.md      ~80   (absorbs fixtures README rules: manifest vs expectations, read `assert` first)
docs/TODO_TESTS.md   ~120  one line per open item
```
Alternatively put each crate's In/Out/Entry block in its `lib.rs` `//!` (it then cannot drift from the code) and make ARCHITECTURE.md a 30-line index.

---

## 7. Proposed simple root API

Principles (api-design): immediate mode, no retained state, caller owns I/O, every coarse call = 2-4 granular calls, return values not out-params at this layer.

```rust
// ---- data ----
pub struct Sources<'a> {            // caller did the I/O
    pub deck: &'a str,
    pub layout: &'a [u8],           // GDS or OASIS, gz ok
    pub reference: Option<(&'a str, Dialect)>,
    pub intent: Option<&'a str>,
}
pub struct Options {
    pub grid: Grid,                 // required, not Option: NoGrid disappears
    pub unknown_layers: UnknownLayers,
    pub lvs: CompareOptions,
    pub pex: PexOptions,            // { quasistatic_nets: Vec<String>, inductance: bool }
}
pub struct Design {                 // = today's Loaded, grid non-optional, no Default
    pub strings: StrTable, pub grid: Grid, pub deck: Deck, pub store: GeometryStore,
    pub provenance: Provenance, pub reference: Option<Netlist>, pub intent: Option<DesignIntent>,
}
pub struct Extraction { pub nets: NetTable, pub devices: DeviceTable, pub ports: PortTable } // no Evaluator
pub struct Findings { pub violations: Violations, pub runs: Vec<RuleRun> }
pub enum Stage<T> { Ran(T), Skipped(&'static str), Refused(String) }   // NotSelected = not called

// ---- granular (each pure, each returns by value) ----
pub fn load(src: &Sources, opt: &Options) -> Result<Design, LoadError>;           // parse_deck once, read_layout into same StrTable
pub fn extract(d: &Design) -> Result<Extraction, ExtractError>;
pub fn drc(d: &Design, x: &Extraction) -> Result<Findings, EngineError>;
pub fn erc(d: &Design, x: &Extraction) -> Result<Stage<Findings>, EngineError>;
pub fn lvs(d: &mut Design /* interns rule ids */, x: &Extraction, o: &CompareOptions) -> Stage<(Verdict, Findings)>;
pub fn pex(d: &Design, x: &Extraction, o: &PexOptions) -> Result<Stage<ParasiticNetwork>, EngineError>;

// ---- coarse ----
pub struct Report {
    pub drc: Option<Stage<Findings>>, pub erc: Option<Stage<Findings>>,
    pub lvs: Option<Stage<(Verdict, Findings)>>, pub pex: Option<Stage<ParasiticNetwork>>,
}
impl Report {
    pub fn merged(&self) -> Findings;       // sorted canonically; replaces Outputs.violations/runs
    pub fn summary(&self) -> Summary;       // counts + passed(); computed, not stored
}
pub fn check(d: &mut Design, x: &Extraction, which: Checks, o: &Options) -> Result<Report, EngineError>; // = drc+erc+lvs+pex
pub fn run(src: &Sources, which: Checks, o: &Options) -> Result<(Design, Extraction, Report), EngineError>; // = load+extract+check

// ---- writers (append to caller's String) ----
export::json::write(&Report, &Design, &Header, &mut String)
export::parasitic::{write_spef, write_dspf}(&ParasiticNetwork, &PortTable, &StrTable, &Header, &mut String)
export::text::write(&Report, &Design, &mut String)          // moved out of the bin
```

What this removes: `Inputs` paths + both file-reading helpers in the engine (CLI reads files, ~20 lines), `Option<Grid>`/`NoGrid`/`NO_GRID`/`run_grid`, `*_into` + manual column clears, `Outputs`, `StageStatus::NotSelected` (an unselected stage is `None`), sentinel LVS ids + `intern_report_ids`, `RunOptions::threads`, `Extracted::derived`. `run` returns `Design` so the CLI can render without re-implementing the pipeline (today's reason main.rs:47-60 bypasses `run`). The CLI becomes: read files → `args::parse` → `run` → one writer → exit `summary.passed()`; ~100 lines total for main+args.

Accuracy note: every change above is structural. The numeric paths (`RuleSet::run`, `lvs::compare`, `analytical/quasistatic::extract_into`, `merge_field_solved`) are untouched, and the section 5.1 gate must stay green byte-for-byte except where JSON float formatting is deliberately re-baselined.

---

## Grand total (in scope)

| area | now | deletable/movable |
|---|---|---|
| src/ | 5,035 | ~3,100 |
| testgen | 2,750 | ~155 (safe) to ~600 |
| root tests (excl. fixtures) | ~9,300 | ~2,100 + comment trim |
| crate tests duplicating corpus | — | ~120 |
| docs + READMEs | 3,349 | ~2,600 |
| fixtures/manifest.json | 1,588 | 1,588 (fold `cell` into expectations.json) |
