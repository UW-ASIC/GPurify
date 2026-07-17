# GPUVerify

GPU-accelerated physical verification engine for integrated circuit layouts. Runs DRC, LVS, PEX, and ERC checks on any process node via PDK-driven JSON rule decks.

Written in Rust. CPU by default, optional CUDA acceleration via CubeCL (`--features gpu`).

## What it does

- **DRC** — 25+ rule types: width, spacing, enclosure, extension, area, density, antenna, EOL, multi-patterning, etc.
- **LVS** — device extraction (MOS, BJT, resistor, diode, capacitor), netlist comparison, SPICE/CDL/Spectre parsing, series/parallel reduction
- **PEX** — parasitic R/C extraction (sheet resistance, area/fringe/coupling/interlayer capacitance, via resistance), SPEF/DSPF output
- **ERC** — antenna, electromigration, IR drop, ESD/latch-up, floating gate/well, supply shorts, missing ties

## Project structure

```
crates/
  backend/          CPU and GPU (CubeCL/CUDA) backends, Session, Rule trait
  core/             Geometry store (SoA), GDS/OASIS I/O, exact booleans, schema parsing
  drc/              Design rule checking
  lvs/              Layout vs. schematic
  pex/              Parasitic extraction
  erc/              Electrical rule checking
engine/             Facade crate (re-exports, load_gds, run_lvs)
macros/             Proc macros (#[verify_kernel], #[kernel_fn])
pdks/               PDK rule decks (JSON)
conformance/        Per-engine conformance test suites
```

## Quick start

```sh
# Enter the dev shell (Rust + CUDA + Vulkan)
nix develop

# Build
cargo build --workspace

# Run all tests
cargo test --workspace

# Run a single engine's tests
cargo test -p gdsverify-drc

# Run per-engine conformance harness
cargo run -p gdsverify-conformance-drc
cargo run -p gdsverify-conformance-lvs
```

## Usage

Two ways to feed geometry into the engine:

### 1. Direct API (recommended for integration)

Build a `GeometryStore` in code and run checks without touching GDS files.

```rust
use gdsverify::{Deck, GeometryStore, run_drc, run_pex};

// Load a PDK deck from JSON
let json = std::fs::read_to_string("pdks/sky130.json").unwrap();
let deck = Deck::from_json(&json).unwrap();

// Build geometry directly — coordinates are i32 database units (nm)
let mut store = GeometryStore::new();

let met1 = deck.layers.id("met1").unwrap();
let met2 = deck.layers.id("met2").unwrap();
let via1 = deck.layers.id("via1").unwrap();

// add_rect(layer, x, y, width, height)
store.add_rect(met1, 0, 0, 500, 200);
store.add_rect(via1, 100, 50, 170, 170);
store.add_rect(met2, 0, 0, 500, 200);

// Arbitrary polygons: add_polygon(layer, &[(x,y), ...])
// Vertices form a closed ring; do NOT repeat the first point.
store.add_polygon(met1, &[(0, 0), (1000, 0), (1000, 500), (500, 500), (500, 200), (0, 200)]);

// Run DRC
let drc_report = run_drc(&store, &deck);
for v in &drc_report.violations {
    println!("{}: {} at ({}, {})", v.rule_id, v.kind, v.x, v.y);
}

// Run PEX
let pex_report = run_pex(&store, &deck);
for p in &pex_report.parasitics {
    println!("R={:.3} ohm, C={:.3} fF", p.resistance_ohm, p.capacitance_ff);
}
```

#### Net labels (for LVS)

```rust
let p = store.add_rect(met1, 0, 0, 500, 200);
store.net_labels.insert(p.0, "VDD".into());

// Text labels also work (placed at a point on the target layer)
store.add_text(68, 20, 250, 100, "VDD".into()); // GDS layer 68 datatype 20 = met1
```

#### GPU backend

```rust
use gdsverify::{run_drc_backend, Backend};

let backend = *gdsverify::available_backends().last().unwrap();
let report = run_drc_backend(&store, &deck, backend);
```

### 2. From GDS files (quick path)

Read a GDS file and run checks. Simpler but requires writing/reading a file on disk.

```rust
use gdsverify::{Deck, load_gds, run_drc};

let deck = Deck::from_json(&std::fs::read_to_string("pdks/sky130.json").unwrap()).unwrap();
let layout = load_gds("design.gds", &deck).unwrap();

for (name, store) in &layout.cells {
    let report = run_drc(store, &deck);
    println!("{name}: {} violations", report.violations.len());
}
```

## PDK decks

PDK decks live in `pdks/`. Each JSON file defines layers, DRC rules, connectivity, device recognition, and PEX coefficients.

| Deck | Node | Notes |
|------|------|-------|
| `sky130.json` | SkyWater 130nm | Full sky130A layer map, MOS/BJT/resistor/cap/diode devices |
| `generic_finfet.json` | Generic FinFET | Same layer stack, fewer device variants |

## Data model

`GeometryStore` is struct-of-arrays (SoA). All coordinates are `i32` database units. Polygons are flat index ranges into shared vertex arrays — no per-shape heap objects, no pointers. Cache-friendly on CPU, trivially uploadable to GPU as flat buffers.

```
verts_x / verts_y     — every vertex of every polygon (hot path)
poly_layer            — LayerId per polygon
poly_vert_start/len   — index range into vertex arrays
poly_bbox             — axis-aligned bounding box per polygon
```
