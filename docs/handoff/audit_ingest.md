# Audit: crates/ingest

Read-only audit. Line numbers are against HEAD `41b2a1e`. "Non-test" means `crates/*/src` and `src/` outside `#[cfg(test)]` modules. `testgen` counts as test support.

Size today: 6,047 src lines, of which 1,706 are in-src `#[cfg(test)]` modules (layout.rs 1612-3136, deck.rs 1067-1175, provenance.rs 424-495). That leaves **~4,340 production lines**, plus 1,195 lines in `crates/ingest/tests/`.

| file | prod lines | debug_assert! | lines inside debug_asserts (approx.) | `//` comment lines |
|---|---|---|---|---|
| layout.rs | 1611 | 26 | 62 | 294 |
| deck.rs | 1066 | 32 | 120 | 228 |
| netlist.rs | 879 | 31 | 81 | 107 |
| provenance.rs | 423 | 23 | 114 | 92 |
| intent.rs | 317 | 21 | 32 | 61 |
| lib.rs | 45 | 2 | 10 | 14 |
| **total** | **4341** | **135** | **~420** | **~800** (+ `///` docs) |

---

## 1. Data in / data out

### Inputs
| format | entry point | notes |
|---|---|---|
| GDSII, optionally gzip (`.gds.gz`, via `flate2::MultiGzDecoder`) | `layout::read_layout(&Path, &Deck, UnknownLayers)` → `gds::read(&[u8], &Deck, UnknownLayers)` | Supported: BOUNDARY, BOX, PATH (axis-parallel, even width, pathtype 0/2/4), SREF, AREF, TEXT. NODE is skipped. Transforms must be exact: integral mag, quarter-turn angles, no absolute STRANS. |
| OASIS | `oasis::read` | **Detected and then always refused** (`UnsupportedRecord`). No reader exists. |
| JSON deck | `deck::parse_deck(&str, Grid, &mut StrTable)`, `deck::read_deck(&Path, ..)` | Sections: layers, derived, rules, connectivity, device_recognition, pex, and `cell` (ignored). |
| JSON design intent | `intent::parse_intent(&str, &mut StrTable)`, `intent::read_intent(&Path, ..)` | |
| SPICE/CDL netlist | `netlist::spice::read(&str, &mut StrTable)` | |
| Spectre netlist | `netlist::spectre::read(&str, &mut StrTable)` | |

### Outputs (types)
- `Layout { store: GeometryStore, provenance: Provenance, strings: StrTable, dropped: u32 }`
- `Deck { grid: Option<Grid>, layers: LayerTable, rules: RuleTable, connectivity: Connectivity, devices: DeviceRecognition, stack: ProcessStack }`
- `DesignIntent` (private SoA: domains, supplies, limits)
- `Netlist` (public SoA columns, CSR)
- Errors: `LayoutError`, `DeckError`, `IntentError`, `NetlistError`, `LabelError`

### The real API: what non-test code outside the crate uses
| item | used by (non-test) |
|---|---|
| `StrId`, `StrTable` (re-exported from geom) | everywhere |
| `deck::parse_deck` | `src/engine/pipeline.rs:111,116` |
| `Deck.{layers, rules, connectivity, devices, stack}` | check, extract, `src/engine/run.rs` |
| `Deck.grid` | `src/engine/run.rs:198` only, as `loaded.grid.or(loaded.deck.grid)`. Redundant: `load_into` sets both to the same value. |
| `LayerTable::{len, is_derived, stream_of}` | `src/export/gds.rs:54-95` |
| `LayerTable::id` | `src/engine/run.rs:156` |
| `RuleTable.spec`, `RuleTable::{layers_of, params_of, param}`, `RuleSpec.{id, kind}`, `ParamValue` | `check/drc/ruleset.rs`, `check/erc/ruleset.rs`, `run.rs:206` |
| `Connectivity`, `DeviceRecognition`, `DeviceKind`, `ProcessStack` | check (topology, erc, lvs), extract, `src/export/netlist.rs` |
| `layout::read_layout`, `UnknownLayers`, `LayoutError` | `pipeline.rs`, `bin/gpurify/args.rs`, `bin/probe_conformance.rs` |
| `Layout.{store, provenance, strings}` | `pipeline.rs:115-117` |
| `Provenance::resolve_labels`, `Provenance::labels`, `LabelError` | `pipeline.rs:128`, `check/topology/port.rs:136` |
| `intent::read_intent`, `DesignIntent::{supply_role, limits, domain_voltage, is_empty}`, `DomainId`, `SupplyRole`, `NetLimits`, `IntentError` | `pipeline.rs:139`, `check/erc/facts.rs`, `check/erc/power.rs`, `check/erc/rules/electrical.rs` |
| `netlist::{spice, spectre}::read`, `NetlistError` | `pipeline.rs:208-210` |
| `Netlist` + `SubcktId`, `Netlist::{subckt_count, devices_of, top}` | `check/lvs/{graph, hierarchical}.rs`, `run.rs:569` |
| `Netlist` fields actually read | `subckt_name, subckt_port_start, port_net, subckt_device_start (through devices_of), device_kind, device_model, device_terminal_start, terminal_net, device_param_start, param, instance_of, instance_subckt, net_name, net_subckt` |

Everything else that is `pub` is test-only or crate-internal (see §3).

---

## 2. Module map

| file | lines (total / prod) | purpose |
|---|---|---|
| `lib.rs` | 45 / 45 | Module list, re-exports, `narrow` (usize to u32), `csr` (one CSR row slice) |
| `deck.rs` | 1175 / 1066 | JSON deck to `Deck`: layer table with name and stream indexes, derived-layer table, rule SoA, connectivity, device recognisers, PEX stack. Includes the `Pairs<T>` serde visitor that keeps duplicate keys. |
| `layout.rs` | 3136 / 1611 | `read_layout` (file, gzip, magic dispatch), `derive_layers_into` (deck boolean layers), `gds` (record parser, keyhole decomposition, clockwise normalisation, PATH stroking, SREF/AREF, TEXT, hierarchy flatten), `oasis` stub. About 1.5k lines of in-src tests. |
| `netlist.rs` | 879 / 879 | Shared SPICE/Spectre lexer and two-pass card reader to `Netlist` SoA |
| `provenance.rs` | 495 / 423 | Per-polygon hierarchy path and stream properties (`PathTable`, CSR props, `permute`), plus TEXT labels and `resolve_labels` (point-in-polygon binding) |
| `intent.rs` | 317 / 317 | JSON intent to `DesignIntent` (domains, supplies, per-net limits) |

---

## 3. Dead code (no non-test user; checked by grep across `crates/*/src`, `src/`, `tests/`, `crates/*/tests`)

### 3a. The biggest item: hierarchy-path and property provenance is written and never read
No non-test code calls `path_of`, `props_of`, `paths()`, `intern_path` (except the reader itself), `PathTable`, `PathId` or `placed_labels`. The only provenance consumers are `labels()` (port.rs) and `resolve_labels` (pipeline). So the following exist only to feed tests:

| file:line | item |
|---|---|
| provenance.rs:30-129 | `PathId`, `PathTable` (intern, get, ROOT) |
| provenance.rs:134-139,146 | `poly_path`, `prop_start`, `props`, `paths` fields |
| provenance.rs:150-167 | `Provenance::push` |
| provenance.rs:192-282 | `Provenance::permute`. Labels are bound *after* the permutation (pipeline.rs:128), so even its label-remap branch at 234-261 never has any work to do. |
| provenance.rs:284-312 | `len`, `is_empty`, `path_of`, `props_of` (len/is_empty are only used in debug_asserts) |
| provenance.rs:327-330, 413-421 | `placed_labels`, `paths`, `intern_path` |
| layout.rs:1313-1317, 1393-1399, 1413, 1428 | `Flatten.chain` and path interning in `visit` |
| layout.rs:1368-1376 | the `permutation` handling in `flatten` |
| layout.rs:1570-1573 | `provenance.push` in `emit` |
| layout.rs:162-176 | the provenance rows pushed in `derive_layers_into` |
| layout.rs:289-291, 399, 630-642, 672-674, 709, 794, 888-897, 928-929, 1153-1154 | `Elem.prop_*`, `Library.props`, PROPATTR/PROPVALUE storage. The records must still be *accepted*; they just do not need to be stored. |
| lib.rs:8-9 (doc invariant), 24-40 | `csr()`. Its only users are provenance props (dead) and the dead netlist accessors below. |

### 3b. Other dead or test-only pub items
| file:line | item | status |
|---|---|---|
| layout.rs:24, 1312, 1493 | `Layout.dropped` | Computed, **never read**: the pipeline discards it. See §7: the CLI default is `Drop`, so dropped geometry is silent. |
| layout.rs:117 | `derive_layers_into` (pub) | Only caller is `gds::read`. Make it private. |
| layout.rs:1579-1607 | `oasis` module, `oasis::detect`/`read` | Always refuses. Only `tests/layout.rs` touches it. |
| layout.rs:261-264 | `gds::detect` (pub) | Only `read_layout` and tests use it |
| layout.rs:51-52 | `LayoutError::Io` | Goes away once file I/O leaves the crate |
| deck.rs:1053-1064 | `read_deck` | Unused: pipeline reads the file itself. Only `tests/deck.rs:189` and a doc comment in args.rs mention it. |
| deck.rs:28-29 | `DeckError::Io` | Only constructed by the pipeline and `read_deck` |
| deck.rs:114-117 | `LayerTable::name` | Test-only (`tests/pdk_decks.rs`, deck.rs tests) |
| deck.rs:122 | `LayerTable::of_stream` (pub) | Crate-internal plus `tests/derived_layers.rs` |
| deck.rs:152, 171, 224 | `LayerTable::{derived, push_derived, build}` (pub) | Crate-internal only |
| deck.rs:278-337 | `DerivedOp`, `DerivedTable` + `len/is_empty/row/operands_of` (pub) | Crate-internal only |
| deck.rs:93, 316 | `LayerTable::is_empty`, `DerivedTable::is_empty` | Unused |
| intent.rs:100-103 | `DesignIntent::domain_count` | Test-only (`tests/intent.rs:31`) |
| intent.rs:20-21, 307-317 | `IntentError::Io`, `read_intent` | Replace with a caller-side read |
| netlist.rs:131-148 | `Netlist::{terminals_of, params_of, instance_terminals_of}` | Test-only. check's `.params_of`/`.terminals_of` hits belong to check's own `DeviceTable`. |
| netlist.rs:46, 52 | `RefDeviceId`, `RefInstanceId` | Test-only |
| netlist.rs:66 | `Netlist.device_name` | Written, never read outside the crate. **Its interning must stay** (see §7). |
| netlist.rs:89, 98-99 | `instance_name`, `instance_terminal_start`, `instance_terminal_net` | Only read by the reader's own arity check (netlist.rs:772-819). Nothing downstream reads them. |
| netlist.rs:14 | `SourceSpan.column` | Set, never displayed: every error message prints only `.line` |
| netlist.rs:29-30 | `NetlistError::Io` | Only built by pipeline.rs:197. Belongs in `LoadError`. |
| deck.rs:959-961 | `DeckJson.cell` | Must stay: it is a deliberate ignored section, and `deny_unknown_fields` needs the name |

### 3c. Dead after 3a/3b are removed
- `crate::csr`: all remaining users are gone.
- `Provenance::label` (provenance.rs:170): only `resolve_labels` calls it. It can become a `push` followed by one stable sort at the end.

---

## 4. Bloat

Estimated deletable production lines, excluding moves:

| # | location | what | est. lines |
|---|---|---|---|
| B1 | provenance.rs, layout.rs, lib.rs (§3a) | Remove path/props provenance and `permute`. Provenance shrinks to `{ placed: Vec<PlacedLabel>, labelled: Vec<(PolyId, StrId)> }` plus `resolve_labels`. | **~380** |
| B2 | all files | 135 `debug_assert!`s. About 120 of them restate a push made two lines earlier ("columns agree", "one row per declared X", CSR terminators, "the gather dropped a row"). Examples: deck.rs:76-90 (three asserts on every `len()` call), deck.rs:204-217, 242-261, 541-556; intent.rs:210, 253-257, 286-303; netlist.rs:774-793, 822-854; provenance.rs:57-109, 197-281; layout.rs:499, 604-611, 1002, 1036, 1058, 1063, 1087-1091, 1108-1109, 1137-1146, 1369-1373, 1480-1484, 1503-1506, 1518-1519, 1551. **Keep** layout.rs:1559-1563 (det<0 iff flip, the orientation invariant) and the `assert!`s in `push_derived` if that function survives. | ~330 after B1 overlap |
| B3 | all files | Comments: ~800 `//` lines plus long `///` blocks (e.g. layout.rs:842-855 and 903-917, 31 lines of rationale for two `if`s; deck.rs:467-527, a 60-line schema doc). Cut to one line of *why* each. **Keep** the rationale lines listed in §7. | ~350 |
| B4 | layout.rs:69-108, 1579-1607; deck.rs:1053-1064; intent.rs:307-317; `Io` variants | File I/O and OASIS out. The caller reads bytes and handles gzip (~10 lines in pipeline). | ~100 |
| B5 | deck.rs:46-337 | `LayerTable` keeps two sorted indexes, and `DerivedTable` is its own CSR struct with 4 accessors. Decks hold tens of layers. `by_name` → linear `position` over `name` (duplicates are already refused, so the result is the same). `DerivedTable` → `Vec<(LayerId, DerivedOp, Vec<LayerId>)>`. **Keep `by_stream`**: it is hit once per GDS element and its lowest-id tie-break matters. Also delete `derived_start` bookkeeping asserts and `push_derived`'s sorted insert. | ~130 |
| B6 | intent.rs:38-111, 194-305 | `DesignIntent` as 7 parallel Vecs → 3 sorted `Vec<(StrId, ..)>` (domains, supplies, limits). The copy loops at 245-252 and 280-285 disappear because the sorted tuple Vecs *are* the storage. | ~60 |
| B7 | netlist.rs:151-180 | `top()` uses branchless select arithmetic over a bool Vec. Replace with `let free: Vec<_> = (0..n).filter(|r| !inst[r]).collect(); (free.len()==1).then(..)`. Same result. | ~20 |
| B8 | netlist.rs:769-819 | Instance arity check: smear/`min` branchless offender scan, then recomputation. Replace with a plain `for` loop that returns on the first mismatch (same "earliest offender" semantics). Store per-instance terminal counts instead of `instance_terminal_*` columns. | ~35 |
| B9 | netlist.rs:131-148, 46, 52 | Dead accessors and ids (§3b) | ~25 |
| B10 | layout.rs:1508-1550 | `emit` makes 5 passes (rx, ry, worst, tx, ty) and keeps 4 scratch Vecs. `Dbu` is `#[repr(transparent)]`, so it can be one fused pass that writes `Dbu` directly with the bound check inline. Two scratch Vecs remain. | ~25 |
| B11 | layout.rs:681-696 | `text()` decodes XY by pushing into `lib.xs` and then truncating twice. Decode the 8 bytes directly. | ~10 |
| B12 | layout.rs:1332-1338 vs 1410-1412 | Every `Ref` is resolved with `lib.find` twice: once in the pre-pass, then again **on every visit** (one binary search per instance placement, millions for a big array). Store the child index in `Ref` during the pre-pass. | ~5, also a perf win |
| B13 | layout.rs:255-259 | `const fn offset(at: usize) -> u64` exists to "justify a cast once". Make `Truncated`/`UnsupportedRecord` carry `usize`. | ~8 |
| B14 | layout.rs:1226-1243 | COLROW and SREF XY decode duplicate `word`/`points` logic inline | ~8 |
| B15 | lib.rs:17-22 | `narrow` is fine. Keep it. | 0 |
| B16 | deck.rs:340-402 | `RuleSpec` stores CSR offsets into `RuleTable`'s side arrays. External users only reach them through `layers_of`/`params_of`/`param`. A `Rule { id, kind, layers: Vec<LayerId>, params: Vec<(StrId, ParamValue)> }` would remove 4 fields and 2 accessors, but touches check's `drc/ruleset.rs` and `erc/ruleset.rs`. | ~30 (cross-crate) |
| **Total prod** | | | **~1,400 of 4,340 (~32%)** |

### Other bloat notes
- **`#[expect(clippy::...)]` blocks.** There are 7 (layout.rs:458, 631, 1195, 1211, 1216; deck.rs:735). Each is 4-6 lines and wraps a single cast. `rem_euclid(4) as u8` needs no justification block.
- **Misplaced tests.** `crates/ingest/tests/intern.rs:28-167` tests `gpurify_geom::StrTable`. They belong in geom, if they are kept at all.
- **Three hand-rolled GDS writers.** `src/export/gds.rs` (production), layout.rs:1622-1890 (test constants plus the `record/gds_real/ascii/gds_hierarchy/text_records` writer), and the fixtures in `tests/derived_layers.rs`. The in-src test writer could reuse `export::gds::put_*` if those were `pub(crate)`-reachable. That is not possible across crates, so leave it. At least drop the duplicated tag constants.
- **Pipeline redundancy outside this crate but caused by it.** `check/erc/facts.rs:179-241` copies `DesignIntent`'s supply columns into its own `supply_net/supply_domain/supply_role` and re-implements `supply_role`. One of the two is redundant.

### Double deck parse (pipeline.rs:105-122): making it one pass
The deck is parsed twice today: once into a scratch `StrTable` so `read_layout` can map layers, and again into `layout.strings`. This is not really about cost (the deck is a few kB). The problem is the ownership inversion: `read_layout` creates the run's `StrTable`.

What `flatten` needs from the deck is `layers.of_stream` (returns `LayerId`, no `StrId`) and `layers.derived()` (only `LayerId`s). `gds::parse` needs nothing from the deck. So split the GDS reader along that line:

```rust
let mut strings = StrTable::default();
let lib  = gds::parse(&bytes, &mut strings)?;              // interns every layout string, as today
let deck = parse_deck(&deck_src, grid, &mut strings)?;     // deck strings interned after, as today
let layout = gds::flatten(&lib, &deck, unknown)?;          // store, labels, dropped; interns nothing
```

This keeps the **exact** current `StrId` numbering (layout strings first, then deck), so violation order is byte-identical (see §7). It removes the staging parse, the `debug_assert_eq!` at pipeline.rs:119-123, the comment at 105-110, and `Layout.strings`.

The deck-first shape the owner suggested, `read_gds(bytes, &Deck, &mut StrTable)`, is simpler still (one call). But it moves every deck string ahead of the layout strings. The relative order of rule ids is unchanged **except** when a rule id string also appears in the layout (a cell name, TEXT or PROPVALUE). In that case the canonical violation order and `runs` order (both sorted by rule `StrId`, run.rs:296-297) change. Verdicts do not. Take it only if report order may shift in that edge case.

---

## 5. Proposed simple API

```rust
// lib.rs: re-exports only
pub use gpurify_geom::{StrId, StrTable};

// deck
pub fn parse_deck(src: &str, grid: Grid, strings: &mut StrTable) -> Result<Deck, DeckError>;
pub struct Deck { pub layers: LayerTable, pub rules: RuleTable, pub connectivity: Connectivity,
                  pub devices: DeviceRecognition, pub stack: ProcessStack }   // `grid` dropped (run.rs:198 uses Loaded.grid)
impl LayerTable { pub fn len(&self)->usize; pub fn id(&self,&StrTable,&str)->Option<LayerId>;
                  pub fn is_derived(&self,LayerId)->bool; pub fn stream_of(&self,LayerId)->(u16,u16); }

// layout (GDSII only; bytes already decompressed by the caller)
pub fn parse_gds(bytes: &[u8], strings: &mut StrTable) -> Result<GdsLibrary, LayoutError>;
pub fn flatten(lib: &GdsLibrary, deck: &Deck, unknown: UnknownLayers) -> Result<Layout, LayoutError>;
pub struct Layout { pub store: GeometryStore, pub labels: Labels, pub dropped: u32 }
// Labels = { placed: Vec<PlacedLabel>, bound: Vec<(PolyId, StrId)> }
pub fn bind_labels(labels: &mut Labels, store: &GeometryStore, c: &Connectivity) -> Result<(), LabelError>;
//   (or keep it as a Labels method; check/topology/port.rs takes &[(PolyId, StrId)])

// netlist
pub fn parse_spice(src: &str, strings: &mut StrTable) -> Result<Netlist, NetlistError>;
pub fn parse_spectre(src: &str, strings: &mut StrTable) -> Result<Netlist, NetlistError>;
// Netlist: drop device_name/instance_name/instance_terminal_* from the pub surface; keep top/devices_of/subckt_count

// intent
pub fn parse_intent(src: &str, strings: &mut StrTable) -> Result<DesignIntent, IntentError>;
```

The caller (pipeline.rs) reads files, detects gzip (the `[0x1f,0x8b]` peek plus `MultiGzDecoder`, ~8 lines), and turns I/O errors into `LoadError::Io { path, why }`. The `spice::`/`spectre::` single-function modules become two functions.

### Tests that become obsolete or need rewriting
| test | fate |
|---|---|
| `crates/ingest/tests/layout.rs` (all 6: detector exclusivity, magic, neither-format, cannot-open, prefix) | Obsolete, since OASIS, detect and file I/O are gone. Replace with one pipeline test that covers "unknown format / unreadable file", and **add a gzip test**: none exists anywhere today. |
| `tests/deck.rs::a_deck_that_cannot_be_opened...` (189-198) | Obsolete (moves to pipeline) |
| `tests/intent.rs::an_intent_file_that_cannot_be_opened...` (74-82) | Obsolete |
| `tests/intern.rs` path tests (169-217) | Obsolete. StrTable tests (28-167) move to geom or go. |
| `tests/provenance.rs` tests 1-2 (29-125: props through sort, empty props) | Obsolete |
| `tests/provenance.rs` tests 3-4 (label ordering via `label`) | Rewrite against `bind_labels`, or drop |
| `tests/netlist.rs::every_csr_accessor...` (74-107) | Obsolete. Other netlist tests use `Netlist` fields; check which still apply after removing fields. |
| layout.rs in-src: `each_polygons_stream_properties_follow_it_through_the_layer_sort` (2225), `every_polygon_read_has_a_provenance_row_of_its_own` (2312), path assertions via `path_text` (2864) in `wrapping_the_root...` (2898) | Obsolete, or strip the path/props asserts and keep the geometry ones |
| layout.rs in-src `read_layout_dispatches...` (2276) | Obsolete |
| `tests/common/mod.rs:556-561` `load_bytes`, `tests/derived_layers.rs:65` | Switch to `parse_gds` + `flatten` |
| `tests/derived_layers.rs:216-245` (`of_stream`) | Keep if `of_stream` stays pub; otherwise test through `flatten` |

---

## 6. SIMD candidates (`fearless_simd` 1.0: `i64x4`, `i32x8`, `u8x32`, `widen_i32x8`, `deinterleave_i32x8`, `swizzle_dyn_within_blocks_u8x32`, `mask64x4::to_bitmask` are all present. **`mul_i64x4` is a scalar fallback on AVX2**, so avoid i64 multiplies.)

| # | file:line | kernel | element type | typical N per call | dependency | contiguity | verdict |
|---|---|---|---|---|---|---|---|
| S1 | layout.rs:1508-1550 (`Flatten::emit`) | affine `x' = a·x + b·y + dx`, `y' = c·x + e·y + dy`, then max-abs bound reduction, then write `Dbu` | i64 SoA (`lib.xs`, `lib.ys`) | 4-8 per element today. **Batching per cell placement** (a cell's elements are contiguous, so their vertex runs are one contiguous block of `lib.xs`) gives 10²-10⁵. | lanes independent; one `max` reduction | contiguous, 2 columns | **Best candidate.** Do the scalar fusion (B10) first. With `mag == 1`, the (a,b,c,e) are 0/±1: x' = select(swap, y, x) · sign + dx, which needs `select`/`neg`/`add` and no multiply. Bound check: `abs` + `max` then `reduce`. With `mag > 1` (rare), stay scalar. |
| S2 | layout.rs:480-501 (`points`) | GDS XY decode: 8 bytes → (i32 BE, i32 BE) → (i64, i64) | u8 in, i64 out | 5 (rect with closing point), up to 8191 (65535 B record max). Typical 5-20. | independent | contiguous bytes, interleaved x/y | Mechanically clean: `u8x32` byte-reverse swizzle within 4-byte groups → `i32x8` → `deinterleave` → `widen` → i64x4 ×2. **Low payoff**: N is tiny and the record loop around it (a sequential length-prefixed walk, not SIMD-able) dominates. Check first whether LLVM already vectorises the `chunks_exact(8)` maps. |
| S3 | provenance.rs:367-388 (`resolve_labels` bbox prune) | point-in-bbox scan for first hit | `Bbox` = 4×i64 (`store.layer_bboxes(layer)`, a contiguous `&[Bbox]`) | polygons on the conductor layer: 10⁴-10⁷, per label (10²-10⁴ labels) | independent; **first-match** semantics | contiguous AoS, one Bbox = one i64x4 | Good fit: v = [x,y,x,y], d = (v − [xlo,ylo,xhi,yhi]) with the hi lanes negated, and a hit is all lanes ≥ 0 → bitmask → first set lane → exact `poly_contains_point`, else continue from the next bbox. **Requires `#[repr(C)]` on `geom::Bbox`** (currently not repr(C), so field order is not guaranteed). The algorithm is still O(labels × polys). Sorting labels or a point query on the spatial index is the bigger win. Must preserve "lowest matching row wins". |
| S4 | layout.rs:773-782 (`ring_is_clockwise`) | shoelace | i128 accumulation | 4-8 | reduction | contiguous | No: i128 has no SIMD path, and N is tiny |
| S5 | layout.rs:743-751, 1041-1127 | keyhole duplicate scan (sort), PATH stroking | i64 pairs | <10-50 | mixed | — | No |
| S6 | layout.rs:1414-1427 | AREF placement offsets | i64 | cols×rows | independent | generated | No: each placement recurses into `visit`, which dominates |
| S7 | netlist.rs:233-286 (`lex`) | separator/comment scan | u8 | file bytes (MB) | independent | contiguous | No: `str::split`/`find` already use memchr-class code, and netlists are small |
| — | bbox computation | — | — | — | — | — | Not in this crate: `GeometryStoreBuilder::finish` in geom computes bboxes |

---

## 7. Accuracy-sensitive (do not change semantics while simplifying)

1. **StrId numbering drives output order.** Violations are sorted by rule `StrId` first (check/report/violation.rs:124-140), and `runs` by rule `StrId` (run.rs:297). Interning order is: layout strings (cell names, TEXT strings, PROPVALUEs, in file order) → deck → reference netlist → intent → LVS rule ids. Anything that adds, removes or reorders an `intern` call can reorder the report when strings collide. That includes dropping PROPVALUE interning (B1), dropping `device_name` interning (netlist.rs:537), or deck-first loading. Verdicts are unaffected. To stay byte-identical, keep `intern` calls in place even when the value is not stored, or accept the order shift deliberately.
2. **Netlist nets created by instance terminals** (netlist.rs:592-594). If `instance_terminal_net` storage is removed, `self.net(..)` must **still be called**. Otherwise nets that appear only on X cards disappear from `net_name/net_subckt`, which changes the LVS graph.
3. **Clockwise normalisation** (layout.rs:918-921) reverses the whole ring (vertex 0 moves). **Mirror reversal** (layout.rs:1564-1567) reverses `[1..]` so vertex 0 stays. Vertex 0 is the ERC report point (`erc::first_vertex`). Keep both exactly.
4. **Keyhole path** (layout.rs:856-901): gated on `len ≥ 10` and on a repeated vertex, and it falls back to the plain path when `canonical_rings_into` fails or returns ≤1 ring. Changing the gate changes which shapes are decomposed and their vertex order.
5. **Closing-point drop** (layout.rs:822-830). The expectations fixture depends on it ("rectangle stores 4 vertices").
6. **`of_stream` tie-break**: the lowest `LayerId` wins when two deck names share a stream pair (deck.rs:120-131). Derived layers are excluded from `by_stream`.
7. **LayerId assignment** by sorted layer-name *bytes* (deck.rs:626-650), with derived ids after all base ids in declaration order. Every id in every report depends on this.
8. **`to_limit`**: exact nm→dbu conversion, or `OffGrid` (deck.rs:733). No rounding.
9. **`spice_number`**: `meg`/`mil` before `m` (netlist.rs:322-343). Unknown suffix → `None`.
10. **PATH stroking** (layout.rs:1018-1134): even width, pathtype 0/2/4, miter formula, right-forward/left-back ring order (counter-clockwise).
11. **Exact transform refusal**: MAG integral in [1,1e6], ANGLE a multiple of 90°, STRANS absolute refused, AREF step exact.
12. **`resolve_labels`**: boundary is inclusive, first conductor pairing row then lowest `PolyId` wins, and a claimed-but-unbound label is an error (provenance.rs:355-404). Labels must stay ascending by `PolyId`, with arrival order kept for equal ids. If `label()` becomes push-then-sort, use a **stable** sort.
13. **`MultiGzDecoder`, not `GzDecoder`** (layout.rs:88-93). Keep this when gzip moves to the caller.
14. **`deny_unknown_fields` and `Pairs<T>`** (deck.rs:900-962). These are how misspelled sections and duplicate rules/layers are refused. Do not replace them with `serde_json::Map`.
15. **Latent overflow (existing bug, not a simplification risk).** `Xform::compose` multiplies `mag` and the offsets with unchecked `*` (layout.rs:371, 380-381, 1511, 1516). Nested magnifications (e.g. 1e6 at three levels) overflow i64. That panics in debug, and in release it **wraps**, so the wrapped value can pass the `MAX_ABS_DBU` check and be stored as bogus geometry. Use `checked_mul` → `UnsupportedTransform`/`CoordinateOutOfRange`. This does not change any valid result.
16. **Silent drop (existing behaviour gap).** The CLI default is `UnknownLayers::Drop` (args.rs:400-404: Reject only with `--strict-layers`). The dropped-polygon count `Layout.dropped` is never reported, although the doc says "Never silent". Geometry on undeclared layers disappears without a trace in the default run. Recommend surfacing it in the pipeline output rather than deleting the field.
