# GPurify

Physical verification for integrated circuits (DRC, LVS, ERC and PEX), written
in Rust, data-oriented, and built around one idea: a clean result has to mean
something.

The failure this exists to prevent is the false clean. An empty violation table
is also what a run that never executed produces, and a tool that cannot tell
those apart will eventually sign off a chip it did not check. Every rule here
records whether it ran and what it examined, and says why if it stopped. A run
that could not check everything it was asked to check does not pass, and the exit
code says so.

## Getting started

The dev shell is the supported environment. It pins the toolchain and supplies
`clippy`, `cargo-mutants` and the Vulkan libraries the PEX GPU path links
against:

```sh
nix develop
cargo build --release
cargo test --workspace
```

A plain stable toolchain builds and tests the CPU paths fine, but `cargo clippy`
will not exist outside the shell, and the workspace lints are part of the
definition of correct here.

## Usage

```
gpurify <check> --deck <deck.json> <layout.gds> [options]
```

| Subcommand | Purpose | Extra input |
|---|---|---|
| `drc` | Design rule check | none |
| `erc` | Electrical rule check | `--intent <file>` for the intent-gated rules |
| `lvs` | Layout versus schematic | reference netlist, required |
| `pex` | Parasitic extraction | `--quasistatic <net>…` selects field-solved nets |
| `all` | Everything | both optional; an absent input marks its check *skipped* rather than *passed* |

Shared flags: `--format text|json|gds`, `--output <path>` (default stdout),
`--threads <n>`, `--check-determinism`, `--strict-layers`.

`--format gds` writes violation markers as a layout you can open in a viewer.
`--strict-layers` rejects geometry on layers the deck does not describe instead
of silently dropping it; it defaults on, because a signoff run wants it.

## The deck

One JSON file describes the process. Exactly five sections, and an unknown key is
a hard error. A misspelled `"conectivity"` would otherwise give you a deck with
no connectivity at all, which extracts every shape as its own net and reports a
clean LVS for a chip that is not connected.

```json
{
  "layers": { "met1": [68, 20] },
  "rules": {
    "met1_min_width": {
      "kind": "min_width",
      "layers": ["met1"],
      "params": { "limit": { "nm": 140 } }
    }
  },
  "connectivity": { "conductors": ["met1"], "intra_layer_touch": true, "vias": [] },
  "device_recognition": [
    { "kind": "mos", "marker": "poly", "model": "nfet", "terminals": ["diff", "poly"] }
  ],
  "pex": {
    "met1": { "thickness_nm": 360, "height_nm": 936, "sheet_res_ohm_sq": 0.125,
              "area_cap_af_um2": 25.6, "fringe_cap_af_um": 40.9, "dielectric_k": 4.1 }
  }
}
```

The vocabulary is 24 DRC kinds and 19 ERC kinds, in `drc::ruleset::KINDS` and
`erc::ruleset::KINDS`. The two lists are disjoint, and a kind in neither is
refused by the engine rather than skipped.

An absent section leaves its table empty, which has consequences worth knowing: a
deck with no `pex` stack gives current-carrying layers no sheet resistance, and
ERC then refuses its whole stage rather than reporting rules it never ran.
