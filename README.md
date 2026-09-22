# GPurify

Physical verification for integrated circuits: DRC, LVS, ERC and PEX, in one
tool.

Most verification tools tell you how many violations they found. The number you
actually need is a different one: how much of your chip did the tool look at?
An empty violation table and a run that never executed produce the same report,
and a tool that cannot tell those apart will eventually sign off a chip it did
not check.

GPurify reports both. Every rule says whether it ran and how many shapes it
examined. A run that could not check everything you asked it to check does not
pass, and the exit code says so.

## Install

```sh
nix develop
cargo build --release
```

The binary lands at `target/release/gpurify`. The dev shell pins the toolchain
and supplies the Vulkan libraries the PEX GPU path links against. A plain stable
Rust toolchain builds the CPU paths fine.

## Run a check

```sh
gpurify drc --deck my_process.json --grid 1000 my_layout.gds
```

```
rules:
  met1.min_width: ran, examined 1 shapes, found 1 violations
  met1.min_edge_length: ran, examined 4 shapes, found 2 violations
  met1.min_spacing: ran, examined 0 shapes, found 0 violations
  met1.min_area: ran, examined 1 shapes, found 0 violations
  off_grid: ran, examined 4 shapes, found 0 violations
  diff.li.max_distance_to_tap: skipped, the layer it names holds no geometry, examined 0 shapes, found 0 violations
  ...
violations: 4
  met1.min_width error layer 7 at (40 nm, 500 nm) measured 80 nm against limit 100 nm on shape 0
  met1.min_edge_length error layer 7 at (40 nm, 0 nm) measured 80 nm against limit 100 nm on shape 0
summary:
  drc: ran
  erc: not selected
  lvs: not selected
  pex: not selected
  1 rules skipped
  22 rules clean
  4 violations: 4 errors, 0 warnings
```

Read the third line from the bottom before you read the violation count. One
rule skipped means one rule did not look at your layout, and the run does not
pass even if nothing was found.

### Commands

| Command | What it checks | Extra input |
|---|---|---|
| `drc` | Design rules: widths, spacings, areas, density | none |
| `erc` | Electrical rules: antenna, ties, shorts, power grid | `--intent <file>` for some rules |
| `lvs` | Layout against your schematic | a reference netlist, required |
| `pex` | Parasitic resistance and capacitance | `--quasistatic <net>…` to field-solve a net |
| `all` | Everything | a missing input marks its check skipped, never passed |

Common flags: `--format text|json|gds`, `--output <path>`, `--threads <n>`,
`--check-determinism`, `--strict-layers`.

`--format gds` writes the violations as a layout you can open in a viewer.
`--strict-layers` refuses geometry on layers your process file does not
describe, instead of quietly dropping it. It is on by default.

### Exit codes

`0` only when every check you selected ran and passed. Anything else is `1`:
violations found, a rule skipped, an input missing, a file it could not read.
There is no exit code that means "mostly fine".

### The same input gives the same file

`--threads` changes speed and nothing else. The same inputs produce
byte-identical output at any thread count, and `--check-determinism` runs the
job twice and fails if the two differ.

This matters because a report that differs from itself cannot be diffed against
yesterday's, so you cannot tell a fixed violation from one that merely vanished.
The previous implementation had exactly this problem: 8 of its 27 parasitic
reports changed between runs of the same binary on the same input.

## Accuracy

GPurify is tested against 167 real GDSII cells drawn for a real PDK, each
containing a deliberate defect at a known coordinate with a measurement worked
out by hand. All 167 agree with their expected answer.

```
DRC   ██████████████████████████████████████  94
ERC   ████████████                            30
PEX   ███████████                             27
LVS   ██████                                  16
```

### The test that matters

The point of the per-rule accounting is that it closes a hole most suites have.
In the previous implementation, 45 of 94 design-rule cases asserted only that
nothing was found, so a rule that never executed passed all 45 of them:

```
Cases that would still pass if the rule never ran

before  ████████████████████████  45 of 94   (48%)
now     ▏                          0 of 94   (0%)
```

### Not every passing test proves the same amount

A suite that reports only pass or fail flatters itself, so each case carries a
grade for how much evidence is actually behind it:

```
strong       ███████████████████████████████████  111   the rule ran, had real geometry to look at, and the measurement came close to the limit
blocked      ████                                  13   the expected answer is sound but the tool cannot currently reach it
vacuous      ███                                   11   the rule ran but never came close to the limit
refused      ███                                   11   the rule correctly refuses this input rather than guessing
weak         ███                                    9   nothing to check, for a legitimate reason
skipped      ██                                     7   the rule reported skipped, and a clean count here would be a lie
underivable  ██                                     5   nothing in the test data determines the answer
```

Two thirds of the suite genuinely discriminates. The rest is accounted for by
name, which is not the same as being counted as a pass.

Expected answers were worked out from the geometry and the physics first, then
compared against the previous implementation's output. 115 cases agree, which
means two independent routes reached the same number. 27 disagree, and each one
records which side is wrong and why.

## Speed

The thing you want to know about a verification tool is whether it falls over on
a large design. Run on 1,000 then 10,000 then 100,000 polygons, the cost per
polygon falls rather than climbs:

```
                          1k        10k       100k
building the layout     283.5      300.6      113.9   ns per polygon
extracting nets         759.5      564.0      358.1
finding shape pairs      22.4       16.3        6.5
```

Ten times the input costs this much more time:

```
building the layout      10.6×  then   3.8×
extracting nets           7.4×  then   6.3×
finding shape pairs       7.3×  then   4.0×

linear would be          10.0×        10.0×
quadratic would be      100.0×       100.0×
```

Nothing here is quadratic, which is the failure mode that makes a tool unusable
on a real chip rather than merely slow.

Measured on one release build on an Intel i9-14900HX. Timings are recorded, not
enforced: no run fails a build for being slow. `cargo test --release --test
bench_all` reprints these tables on your own machine, including a per-rule
breakdown of which rule costs what.

## Describing your process

One JSON file, five sections. An unknown key is an error rather than a warning,
because a misspelled `"conectivity"` would otherwise give you a file with no
connectivity at all, which extracts every shape as its own net and reports a
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

Three things catch people out, all deliberate:

- The JSON key is the rule name and the kind is a field, so two rules of the
  same kind on different layers need different names. Violations are reported by
  name.
- `layers` is always a list, even with one entry.
- Numbers carry their unit: `{"nm": 140}`, never a bare `140`. A bare `45`
  cannot be told apart from a ratio of `45`.

There are 24 design-rule kinds and 19 electrical-rule kinds. A kind that is in
neither list is refused rather than skipped.

### Included process files

Four, in `pdks/`, to get you started:

| File | Layers | Rules | Devices |
|---|---:|---:|---:|
| `ihp_sg13g2` | 49 | 177 | 5 |
| `gf180mcu` | 38 | 136 | 6 |
| `sky130` | 21 | 114 | 3 |
| `generic_finfet` | 17 | 105 | 2 |

None of these is sign-off quality, and none records which PDK release its
numbers came from. Treat every limit as approximately right and unattributed.
`pdks/README.md` lists what each one is missing.

## What it cannot do yet

This is a working tool that has not been proven on production silicon. Do not
sign off a tapeout with it. Specifically:

- The included process files are starting points, not qualified decks. Among
  other gaps, no shipped deck configures the supply-short rule, so a short
  between two supply nets goes unreported by all four.
- 79 rules ship without a definitive test, because the right answer is a foundry
  convention rather than something derivable from physics. They are listed with
  reasons in `docs/NEED_TESTING.md`.
- Four electrical rule kinds (electromigration, ESD latch-up, IR drop,
  reliability) are wired up and accounted for but not yet covered by a test.
- Mutation testing, the intended final gate, has only been run in part.

There is no licence file yet.

## GPU

One GPU path, used only for field-solved parasitic extraction, and optional
there. A machine with no Vulkan device takes the CPU path and tells you which
one it took.

Everything else is CPU on purpose. The rest of this work is branchy
pointer-chasing over irregular geometry, which a GPU is bad at. The previous
implementation's GPU path was about a thousand times slower than its own CPU
path, and it computed in reduced precision without checking the result, which on
a sign-off path is an accuracy problem rather than a speed tradeoff.

## More detail

| File | What is in it |
|---|---|
| `docs/TESTING.md` | How correctness is established, and the three gates. |
| `docs/CORRECTNESS_MAP.md` | Where correctness is established, and where it is not. |
| `docs/NEED_TESTING.md` | Every rule shipping without a definitive test, and why. |
| `docs/GPU.md` | Why the GPU survives only in quasi-static PEX. |
| `docs/CONVENTIONS.md` | The code rubric, for contributors. |
| `docs/VOCABULARY.md` | Shared terms, used exactly. |
| `pdks/README.md` | Per-process coverage and gaps. |
| `tests/fixtures/README.md` | The test corpus and how each expected answer was derived. |

```sh
cargo test --workspace                    # 870 tests
cargo test --release --test bench_all     # the timing tables above
```
