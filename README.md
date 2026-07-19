# GPUVerify

GPUVerify is a Rust workspace for physical-design verification directly from
GDSII/OASIS layout data. The public `gdsverify` facade combines:

- DRC — geometric design-rule checking.
- LVS — layout extraction and comparison with a reference netlist.
- ERC — layout-derived electrical checks and typed tapeout signoff analyses.
- PEX — analytical parasitic extraction plus quasi-static numerical solvers.

The repository currently provides a Rust library API rather than a standalone
command-line application. The facade package lives in `crates/engine` and
re-exports the specialized workspace crates under stable module paths.

## Status and accuracy boundary

The checked-in conformance corpus contains 160 independent GDS files covering
all currently registered DRC families, the LVS comparison matrix, every
layout-derived ERC heuristic, and all analytical PEX result families. A live
KLayout 0.30.8 oracle additionally checks the directly equivalent native DRC
operations.

Analytical PEX is covered by the GDS conformance suite. Quasi-static per-net PEX
is wired through the same lumped `NetParasitics` API: rectilinear conductors are
extruded from layout DBU into the deck's 3-D process stack, capacitance is solved
as one Maxwell BEM system with a substrate reference, and sheet resistance is
solved as DC FastHenry segments. Fixed via/contact resistance remains a deck
contribution because it is an interface-device parameter rather than a metal
volume. Use the checked API for signoff so unsupported geometry or solver
failure cannot select the compatibility fallback.

ERC power, reliability, CMP, and ESD/latch-up analyses require explicit
qualified stimulus/evidence; missing inputs report `NotRun` rather than a false
clean result.

## Workspace layout

| Path | Purpose |
| --- | --- |
| `crates/engine` | Public `gdsverify` facade |
| `crates/core` | Geometry, exact predicates, hierarchy, GDSII/OASIS and PDK parsing |
| `crates/drc` | Design-rule engine and rule registry |
| `crates/lvs` | Connectivity/device extraction and netlist comparison |
| `crates/erc` | Electrical heuristics and typed signoff analyses |
| `crates/pex` | Analytical and quasi-static parasitic extraction code |
| `crates/backend` | CPU/GPU backend selection and telemetry |
| `pdks` | Example JSON PDK decks |
| `tests/fixtures` | Standalone conformance GDS corpus and expectations |

## Build

The recommended development environment is the repository's Nix flake:

```sh
nix develop
cargo build --workspace
```

With an existing stable Rust toolchain, the CPU build only requires:

```sh
cargo build --workspace
```

The optional `gpu` feature enables the GPU paths and their native Vulkan/CUDA
dependencies:

```sh
cargo build -p gdsverify --features gpu
```

## Library usage

Load and verify a top-level GDS cell with a JSON deck:

```rust,no_run
use gdsverify::{load_gds_strict, run_drc, run_pex, Deck};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let deck_json = std::fs::read_to_string("pdks/sky130.json")?;
    let deck = Deck::from_json(&deck_json)?;
    let layout = load_gds_strict("design.gds", &deck)?;

    let top_name = layout
        .top_cells
        .first()
        .ok_or("GDS has no top cell")?;
    let top = layout
        .cells
        .get(top_name)
        .ok_or("top cell was not flattened")?;

    let drc = run_drc(top, &deck);
    println!("DRC violations: {}", drc.violations.len());

    let pex = run_pex(top, &deck); // detailed analytical report
    println!("extracted capacitance: {} aF", pex.total_cap());
    Ok(())
}
```

`load_gds_strict` checks the complete GDS envelope, representable geometry, and
that the GDS database unit matches the deck. `load_gds` is the compatibility
entry point for legacy DRC inputs that intentionally retain malformed geometry
for polygon-validity reporting.

For LVS, construct or parse a reference netlist and call `run_lvs`. For ERC,
call `run_erc` with a `SignoffConfig`; checks without required qualified inputs
remain blocking as `NotRun`. The facade re-exports the lower-level extraction,
hierarchy, SPICE/Spectre, result, and backend APIs for more specialized flows.

### Analytical or quasi-static per-net PEX

`run_pex_by_net` is the drop-in dispatcher. It reads the deck-level method:

```json
{
  "pex_method": "field_solver"
}
```

After connectivity extraction, the same API returns lumped ohms and
attofarads for either engine:

```rust,no_run
use gdsverify::{extract_netlist, run_pex_by_net_checked, Deck, GeometryStore};

fn extract(
    layout: &GeometryStore,
    deck: &Deck,
) -> Result<(), Box<dyn std::error::Error>> {
    let nets = extract_netlist(layout, deck)?;
    let parasitics = run_pex_by_net_checked(layout, deck, &nets.net_of_poly)?;
    for (net, rc) in parasitics {
        println!("net {net}: R={} ohm, C={} aF", rc.r_ohm, rc.cap_af);
    }
    Ok(())
}
```

`"pex_method": "analytical"` is the default. Call
`run_pex_by_net_with_accuracy` or its checked variant to override the deck for
one run. The unchecked functions preserve compatibility by logging a field
solver failure once and falling back to analytical extraction; the checked
functions return an extraction diagnostic instead.

## PDK decks

A deck defines:

- GDS layer/datatype mappings.
- Typed DRC rule instances and limits.
- Conductive layers and via connectivity.
- MOS/BJT/resistor/diode/capacitor recognition rules.
- LVS extraction policy and tolerances.
- ERC thresholds.
- Analytical PEX process constants and quasi-static
  `thickness_nm`/`height_nm`/`dielectric_k` geometry.

Example decks are available under `pdks/`. GDS coordinates are never silently
rescaled: the file's database unit must agree with `Deck::dbu_nm`.

## Run all conformance tests

The following runs every one of the 160 standalone GDS fixtures:

```sh
cargo test -p gdsverify \
  --test fixture_corpus \
  --test verify_drc \
  --test verify_lvs \
  --test verify_erc \
  --test verify_pex
```

Cargo reports 11 top-level test functions because the harnesses iterate the
manifest: 94 DRC + 16 LVS + 23 ERC + 27 analytical PEX cases are executed.

Run all 160 GPUVerify cases and the live KLayout parity subset together:

```sh
KLAYOUT_BIN=/path/to/klayout \
  cargo test -p gdsverify \
  --test fixture_corpus \
  --test verify_drc \
  --test verify_lvs \
  --test verify_erc \
  --test verify_pex \
  -- --nocapture
```

See `tests/fixtures/README.md` for exact coverage, running individual harnesses,
KLayout scope, and deterministic fixture regeneration.

## Run the complete workspace suite

```sh
cargo test --workspace
```

This includes the conformance corpus along with unit, integration, numerical,
and documentation tests for every crate.

To run only the layout-to-quasi-static PEX wiring and dispatch tests:

```sh
cargo test -p gdsverify-pex --test bridge
```
