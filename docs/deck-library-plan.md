# Decks as a library: Rust decks, overrides, custom rules, sharing

*Design plan, 2026-10-10, against `be14a73`. Progress is tracked as D1–D5 in the testing-plan §8 ledger.
Its tests are the testing plan's L9b ([testing-plan.md](testing-plan.md)), and
it fills catalog rows FLOW-005, FLOW-006 and DRC-115
([check-catalog.tsv](check-catalog.tsv)).*

## 1. What this is for

The text deck stays the fast, strict, non-scriptable default. Three things
get added around it:

1. **Rust decks.** Write a deck in Rust, or start from a shipped one and add,
   replace or remove rules. This must always be available: KLayout is
   scriptable, the deck language deliberately is not, and Rust is the escape
   hatch that costs no speed.
2. **Custom rules.** A rule kind GPurify does not ship, written as a Rust
   function, that still obeys GPurify's guarantees: it reports whether it ran
   and what it examined, its output is deterministic, and it never passes by
   silence.
3. **One shared deck.** A consumer such as Philis gets the deck, its typed
   rules and its layers from GPurify, with no deck copy and no parser of its
   own. It can share or ship a deck as text or as a crate.

**Not in scope:**
- loading plugins at runtime (Rust has no stable ABI);
- making the text deck scriptable;
- a second rule language.

## 2. Why now: the consumer that exists

Philis (`~/Documents/Projects/Rust/Philis`) already uses GPurify as a library,
and shows all three needs:

- **Vendored, drifting decks.** `Philis/pdks/decks/*.deck` are copies of
  `GPurify/pdks/*.deck`. The sky130 copy differs in 39 lines, marked
  `# PHILIS:`:
  - an added layer (`npn`);
  - three added latch-up rules (`LU.2`, `LU.2.1`, `LU.3`);
  - one changed value (`ar.met3.1` sidewall 845 nm vs 2000 nm, which is
    probably a GPurify bug; testing-plan F11).

  The same diff also adds three derived `lu_*` layers, two `device bjt`
  recognisers and three `pex` rows (`rbody_*`). So overrides must cover
  layers, devices and PEX rows, not only rules: the override feature, done
  today by copying the file.
- **Re-derived rule values.** `backend/verify/src/pdk.rs:479-929` has about 25
  functions that walk `deck.rules.spec`, matching kinds and parameters by
  string (`"min_area"`, `"wide_dependent_spacing"`, `"width_threshold"`). The
  value Philis's router keeps is decided by Philis's code, not by the
  checker's. When the two disagree, Philis's router produces layouts that
  GPurify then flags. A renamed kind or parameter in GPurify becomes a silent
  `None` in Philis, not a compile error.
- **Its own sidecar** (`pdks/*.json`) holds only what the deck does not carry.
  That part stays Philis's.

## 3. How it works today

| Piece | Where | Shape |
|---|---|---|
| Parsed deck | `gpurify_ingest::deck::Deck` (`crates/ingest/src/deck/mod.rs:47`) | `layers`, `rules: RuleTable`, `connectivity`, `devices`, `stack`. Kinds and parameters are **interned strings**, "never interpreted here" (`mod.rs:5`). Lengths are already `Dbu` on the grid the deck was parsed against. |
| Parser | `deck::parse_deck(source, grid, &mut StrTable)` (`parse.rs:95`) | Syntax, units and dimensions, from the per-kind table in `deck/kinds.rs`. |
| Typed DRC rules | `gpurify_check::drc::RuleSet { rules: Vec<(StrId, Rule)>, tables }`, `Rule` enum (`drc/ruleset.rs:13`) | Built by `RuleSet::from_deck` (`:254`), which also does the semantic checks: positive limits, layer counts, monotone tables, duplicate ids. |
| Typed ERC rules | `gpurify_check::erc::RuleSet`, one SoA table per kind (`erc/ruleset.rs:67`) | Built by `erc::RuleSet::from_deck`. |
| Engine | `run_checks(&Loaded, &Extracted, &RunOptions)` (`src/engine/run.rs:156`) | Calls both `from_deck`s on every run (`run.rs:230`, `:245`), after `reject_unknown_rule_kinds`. |
| CLI | `src/bin/gpurify/{main,args,format}.rs` | Private to the binary. |

The typed rules already exist; only the text path can create them today.
That gives the seam.

## 4. Design

### 4.1 One compiled deck, two front ends, one printer

```
text ──parse_deck──▶ Deck ──from_deck──┐
                                       ├──▶ CompiledDeck ──▶ engine, query API, printer
Rust ──DeckBuilder─────────────────────┘
```

`CompiledDeck` (new, in `gpurify-check`, re-exported from `gpurify`):

```rust
pub struct CompiledDeck {
    pub grid: Grid,
    pub layers: LayerTable,           // from ingest, unchanged
    pub connectivity: Connectivity,
    pub devices: DeviceRecognition,
    pub stack: ProcessStack,
    pub drc: drc::RuleSet,            // typed
    pub erc: erc::RuleSet,            // typed
    pub custom: Vec<CustomRule>,      // §4.4; empty for a text deck
}
pub fn compile(source: &str, grid: Grid, strings: &mut StrTable) -> Result<CompiledDeck, DeckError>;
```

- The engine takes a `CompiledDeck` instead of compiling inside
  `run_drc`/`run_erc`. Text and Rust decks then run the same code from there
  on.
- `RuleTable` becomes the parser's intermediate. Nothing downstream reads it.
- Philis's `pdk.rs` stops reading it too (§4.6).
- **Semantic validation moves onto the typed values.** Today it lives inside
  `from_deck`. It becomes `drc::Rule::validate(&self, …)` and the equivalent
  per ERC table, so `from_deck` and the builder call the same checks. Units are
  not re-validated, because a Rust caller passes `Dbu`, not text.

### 4.2 Rust deck builder

```rust
use gpurify::deck::{DeckBuilder, nm, um2, gds};
use gpurify::deck::drc::{width, space, enclosure, area};

let mut d = DeckBuilder::new(Grid::nm(5));
let met1 = d.layer("met1", gds(68, 20))?;          // returns a typed handle
let via1 = d.layer("via1", gds(68, 44))?;
let huge = d.derived("huge_met1", met1.sized(-nm(1500)).sized(nm(1500)))?;
d.rule("m1.1", width(met1).ge(nm(140)))?;
d.rule("m1.6", area(met1).ge(um2(0.083)))?;
d.rule("via.4a", enclosure(via1, met1).ge(nm(55)))?;
for (m, w) in [(met1, 140), (met2, 140), (met3, 300)] {
    d.rule(format!("{}.space", d.name(m)), space(m).ge(nm(w)))?;
}
let deck: CompiledDeck = d.finish()?;
```

- **Typed constructors build the existing `drc::Rule` / ERC table rows.** No
  new rule representation. A misspelt kind is a compile error, and a missing
  parameter is a missing argument.
- **Layers are handles** (`LayerRef`), so an undeclared layer cannot be named.
  A derived layer is an expression over handles, built into the same
  `DerivedOp` rows the parser makes.
- **Errors carry the caller's location** (`#[track_caller]`) instead of a deck
  line and column. All are reported at `finish()`, as the parser reports up to
  50.
- **Generate the constructors to avoid drift.** One constructor per rule kind
  is 59 functions today. Generate them, and the `kinds.rs` rows, from one
  `macro_rules!` table, so adding a kind is one row everywhere, not only in
  the parser table (see below). Until that refactor lands, a stop-gap is
  `d.rule_text("m1.1", "width(met1) >= 140nm")`, which runs the existing parser
  on one rule. It costs almost nothing and is useful for porting text decks.
- **What "one row" means today.** The `kinds.rs:1-3` promise covers only the
  parser table. A new kind also needs:
  - an entry in `KINDS` (`drc/ruleset.rs:915` or `erc/ruleset.rs:20`);
  - a `Rule` variant or an ERC table;
  - a `from_deck` arm;
  - the check itself.

  The macro table should own the first three, so that a new kind is the macro
  row plus its check.

### 4.3 Overrides

```rust
let mut d = DeckBuilder::from(gpurify::pdks::sky130(Grid::nm(1))?);
let npn = d.layer("npn", gds(82, 20))?;                                     // add a layer
d.add("LU.2", tap_distance(d.get("lu_ndiff")?, d.get("ptap")?).le(um(15)))?;
d.replace("ar.met3.1", antenna(gate, [met3]).max_ratio(400.0).sidewall(nm(845)))?;
d.remove("x.18")?;
```

| Operation | On an id that exists | On an id that does not |
|---|---|---|
| `add` | error (`DuplicateRule` exists today) | adds |
| `replace` | swaps the rule; its kind may change | **error**, never a silent add |
| `remove` | removes it | **error** |

- **The result must not depend on override order, and today it would.** The
  report sorts by `StrId` (`run.rs:182`), which is interning order ("interning
  order is report order": `netlist.rs:458`, `layout.rs:698`). So `finish()`
  keeps the base deck's interning: a replaced id keeps its `StrId`, and
  added ids are interned in sorted order. An L9b test permutes override calls
  and byte-compares the reports.
- **Layers, devices and PEX rows have the same three operations** (`layer`,
  `device`, `pex_row`), because Philis's diff needs all three (§2).
- `deck.provenance()` lists each rule as shipped, added or replaced, so a
  report can say which rules a consumer changed. A Philis report would show
  "3 added, 1 replaced vs sky130 as shipped".

### 4.4 Custom rules

```rust
fn guard_ring_closed(ctx: &CustomCtx, out: &mut Findings) {
    for ring in ctx.shapes(ctx.input(0)) {
        if !ctx.is_closed_ring(ring) { out.flag(ring, Measure::None); }
    }
}
d.custom("GR.closed", &[gr], Severity::Error, guard_ring_closed)?;
```

- **Dispatch is a plain `fn` pointer.** No trait objects, which matches the
  data-oriented house style: one indirect call per rule, and the loop over
  shapes stays inside the user's function. A generic `trait CustomRules`
  monomorphised through `main_with::<R>()` is the alternative. Choose it only
  if a profile shows the call matters, which it will not at one call per rule.
- **`CustomCtx` is the stable, read-only surface:**
  - `shapes(layer)`, and `validated(input) -> Option<&ValidatedLayer>`. The DRC cache fills lazily through `&mut` (`drc/mod.rs:73-80`), so the runner validates a custom rule's **declared** inputs before calling it, and the context hands out shared references only. This also enforces "findings only on declared layers";
  - `pairs_within(a, b, distance)`, which wraps `SpatialIndex` and the exact distance;
  - `nets()`, for net-aware rules;
  - `grid()` and `strings()`.

  Nothing mutable is exposed.
- **The runner owns the accounting**, so user code cannot break GPurify's
  guarantees:
  - every input layer empty → `Skipped{EmptyLayer}`, and the function is never called;
  - `examined` = shapes on the input layers, counted by the runner;
  - findings are sorted canonically and deduplicated;
  - a finding outside the layout extent, or on a layer the rule did not declare, makes the rule `Refused`;
  - **a panic:** the release profile is `panic = "abort"` (`Cargo.toml:73`). A panic hook therefore names the custom rule that was running, and the run exits non-zero; it never passes. Under unwinding builds (tests, debug), `catch_unwind` turns the rule into `Refused` and the report continues. Switching the release profile to unwinding is a separate decision, not part of this work.
- **Determinism** is the user's responsibility, enforced by
  `--check-determinism` and by the L9b test that feeds it a deliberately
  nondeterministic rule.
- **ERC custom rules** come in phase 5. They need intent and voltage access,
  and that surface should wait until a real rule needs it.

### 4.5 Shipping a binary with your deck

```rust
fn main() -> std::process::ExitCode {
    gpurify::cli::main_with(&[("philis-sky130", philis_sky130)])
}
// philis-sky130 my.gds --deck philis-sky130    (a builtin name, or a path to a text deck as today)
```

- **Move the CLI into the library.** `src/bin/gpurify/{args,format}.rs` and
  `main`'s `render` become `gpurify::cli`. The `gpurify` binary turns into a
  one-line `main_with(&[])`. Every user binary then has the same flags, report
  and exit codes for free.
- **Ship the decks as constants.** `gpurify::pdks::{SKY130, GF180MCU,
  IHP_SG13G2, GENERIC_FINFET}` (the last is ASAP7, `pdks/generic_finfet.deck`) are the `include_str!` texts of `pdks/*.deck`, and
  `gpurify::pdks::sky130(grid)` returns them compiled. Philis then deletes
  `pdks/decks/` and its build-time `GPURIFY_DIR` lookup (`pdk.rs:105-123`).

### 4.6 The query API: read what the checker enforces

This replaces Philis's `pdk.rs` string-walking.

| Query | Returns | Same code path as |
|---|---|---|
| `deck.layer("met1")`, `layers()`, `derivation(layer)` | `LayerRef`, `(DerivedOp, &[LayerRef])` | the parser's table |
| `deck.drc_on(layer)` / `erc_on(layer)` | `impl Iterator<Item = (RuleId, &Rule)>` | the rule sets |
| `deck.min_width(layer)`, `min_area(layer)`, `min_enclosed_area(layer)` | `Option<Dbu>` / `Option<DbuArea>`: the largest limit over every rule of that kind on the layer | `drc::Rule` values |
| `deck.required_spacing(layer, SpacingQuery { width_a, width_b, run_length, end_of_line })` | `Dbu`: the largest of `min_spacing`, `wide_dependent_spacing`, `attached_wide_spacing`, `prl_spacing`, `spacing_table` and `eol_spacing` that apply | **the threshold functions the spacing rules call**, so the router and the checker cannot disagree |
| `deck.enclosure(inner, outer)` | `{ all_sides: Dbu, opposite: Option<Dbu> }` | overlay rules |
| `deck.via_array_spacing(cut)`, `density(layer)`, `em_limit(layer)`, `antenna(layer)`, `fet_limits(model)`, `stack(layer)` | typed rows | ERC tables, `ProcessStack` |

- **Shared threshold code.** For `required_spacing` to match the checker, the
  spacing rules' "which limit applies to this pair" logic must be a pure
  function both call. Factoring it out is the main refactor in this plan.
- **Units.** Every value is in the `Dbu` of the grid the deck was compiled for.
  Philis compiles at 1 nm (`pdk.rs:16`), so nothing changes for it.
- **The oracle** (testing-plan L9b, "consumers read what the checker
  enforces"): for every rule in every shipped deck, draw geometry exactly at
  the queried value and check it is clean; draw one grid step under and check
  it is flagged, with the violation's `limit` field equal to the query.

### 4.7 Printer

`print(&CompiledDeck) -> Result<String, HasCustomRules>` writes the deck
language. `print_lossy` writes each custom rule as a comment naming its Rust
function (`std::any::type_name`).

- It is the inverse of the parser: `compile(print(d)) == d` for every shipped
  deck, every Rust twin and every fuzzer-generated deck. That gives the deck
  fuzzer a round-trip oracle (testing-plan L4).
- It walks the typed `Rule` enums with an exhaustive `match`, so a new rule
  variant that the printer does not handle fails to compile.
- With it, a Rust-built or overridden deck can be shared as plain text, with
  or without GPurify's Rust API.

### 4.8 Stability

- The builder, `CompiledDeck`, the query API and `CustomCtx` become a public
  contract. They follow semver on the `gpurify` crate.
- `drc::Rule`, the ERC table enums and `SpacingQuery` get
  `#[non_exhaustive]`. GPurify can then add a kind without breaking a
  consumer's `match`, while GPurify's own printer still matches exhaustively.
- **Not now:** a version line in the deck language. Add it with the first
  breaking syntax change; no change has needed one yet.

## 5. Phases

Each phase ships on its own, runs under the merge gate, and leaves the
golden-snapshot test (testing-plan L8) byte-identical unless the phase says
otherwise.

| Phase | Delivers | Exit test | Philis gets |
|---|---|---|---|
| **P0** | `gpurify::pdks` constants; triage the 39-line sky130 diff (upstream the genuine fixes: F11, the latch-up rules if sourced) | each shipped deck compiles from its constant; the doc-count test | deletes `pdks/decks/` and `GPURIFY_DIR`; drift ends |
| **P1** | `CompiledDeck` + `compile()`; engine takes it; validation moved onto typed rules | golden snapshots byte-identical before and after (a pure refactor); every `DrcError`/`ErcError` still produced | nothing yet |
| **P2** | Query API, with the shared spacing-threshold function | "query == checker limit" over every rule in all four decks | rewrites `pdk.rs` queries; about 25 string walks deleted |
| **P3** | `DeckBuilder` with typed constructors from one macro table, overrides with provenance, printer | Rust twin of each shipped deck equals its compiled text; builder error twin per `DeckError`; `compile(print(d)) == d`; override algebra (L9b) | its `# PHILIS:` edits as Rust overrides |
| **P4** | `CustomRule` + `CustomCtx` + runner accounting; `gpurify::cli::main_with` | L9b contract tests: empty → Skipped; panic → Refused; unsorted/duplicate findings → canonical bytes; nondeterministic rule caught by `--check-determinism`; out-of-extent finding → Refused | a Philis binary with its own deck name |
| **P5** (when needed) | ERC custom rules; optional KLayout snippet per custom rule for the mirror-deck oracle (L6); text overlay decks if a non-Rust consumer asks | per feature | — |

P0 is a few hours and ends the drift. P1 and P2 are where the value is for
Philis. P3 and P4 are the features you asked for.

## 6. Decisions

Recommended answers first. Each one changes the work above.

1. **Builder rule syntax:** typed constructors over the existing typed rules,
   generated from one macro table (recommended), or deck-syntax strings only
   (`rule_text`, cheaper but stringly typed). The plan ships `rule_text` in P3
   either way, as a porting aid.
2. **Where it lives:** in `gpurify-check`, re-exported from `gpurify`
   (recommended: no new crate, and Philis's viewer still needs only
   `gpurify-geom`), or a new `gpurify-deck` crate. Split only if a consumer
   needs the deck without the check crate's compile weight.
3. **Custom rule dispatch:** `fn` pointer (recommended) or a generic trait.
4. **Text overlays** (`import "sky130.deck"` plus `replace rule …` in the deck
   language): no, until a non-Rust consumer needs them. Philis is Rust.

## 7. Risks

- **The shared spacing-threshold function (P2) touches the hottest DRC code.**
  The golden snapshots plus the bitmap oracle (testing-plan L3) must be in
  place first, so P2 (D3) follows A3 and C5 in the testing-plan §8 ledger.
- **Moving the CLI into the library (P4) makes its output format a library
  contract.** The golden snapshots already pin it.
- **`catch_unwind` (unwinding builds only) needs `AssertUnwindSafe` around
  `CustomCtx`.** That is sound, because the context hands out only shared
  references to pre-validated inputs, and the runner discards a panicking
  rule's partial findings.
- **Deck values are grid-resolved at compile time.** A consumer that compiles
  at 1 nm and checks at 5 nm sees different `Dbu` values. `CompiledDeck::grid`
  makes this explicit, and the query API documents it.
