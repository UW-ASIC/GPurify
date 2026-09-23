# GPurify

Physical verification for integrated circuits: DRC, LVS, ERC and PEX, in one
tool.

Most verification tools tell you how many violations they found. The number you
actually need is a different one: how much of your chip did the tool look at? An
empty violation table and a run that never executed produce the same report, and
a tool that cannot tell those apart will eventually sign off a chip it did not
check. GPurify reports both. Every rule says whether it ran and how many shapes
it examined, and a run that could not check everything you asked it to check
does not pass.

## Install

```sh
cargo build --release
```

The binary lands at `target/release/gpurify`. Any stable Rust toolchain builds
it; `nix develop` gives you a pinned one.

## Run a check

```sh
gpurify drc my_layout.gds --deck my_process.deck --grid 1000
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

Read `1 rules skipped` before you read the violation count. One rule skipped
means one rule did not look at your layout, and the run does not pass even
though nothing was found.

| Command | What it checks | Extra input |
|---|---|---|
| `drc` | Design rules: widths, spacings, areas, density | none |
| `erc` | Electrical rules: antenna, ties, shorts, power grid | `--intent <file>` for some rules |
| `lvs` | Layout against your schematic | a reference netlist, required |
| `pex` | Parasitic resistance and capacitance | `--quasistatic <net>…` to field-solve a net |
| `all` | Everything | a missing input marks its check skipped, never passed |

Every option, the report format and the design intent file are described in
[docs/usage.md](docs/usage.md).

The exit code is `0` only when every check you selected ran and passed. Anything
else is `1`: violations found, a rule skipped, an input missing, a file it could
not read. There is no exit code that means "mostly fine".

## Describing your process

A deck is a plain-text description of your process: layers, connectivity,
devices, the parasitic stack and the rules.

```
grid 5nm
layer met1 = gds(68, 20)
layer via1 = gds(68, 44)

rule m1.1 width(met1) >= 140nm
rule m1.2 space(met1) >= 140nm
rule m1.6 area(met1)  >= 0.083um2
rule via.4a enclosure(via1, met1) >= 55nm
```

It is strict. Every parameter must be written out, every number carries its
unit, and a typo is an error with a line and column, never a rule that silently
does nothing. There are 24 design-rule kinds and 19 electrical-rule kinds.
[docs/deck.md](docs/deck.md) covers the language and every rule.

Four decks ship in `pdks/` to start from:

| File | Layers | Rules | Devices |
|---|---:|---:|---:|
| `ihp_sg13g2` | 49 | 177 | 5 |
| `gf180mcu` | 38 | 136 | 6 |
| `sky130` | 21 | 114 | 3 |
| `generic_finfet` | 17 | 105 | 2 |

None is signoff quality, and none records which PDK release its numbers came
from.

## The same input gives the same file

The same inputs produce a byte-identical report on every run, and
`--check-determinism` runs the job twice and fails if the two differ. A report
that differs from itself cannot be diffed against yesterday's, so you could not
tell a fixed violation from one that merely vanished.

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

Expected answers were derived from the geometry and the physics first, then
compared against the previous implementation's output. 119 agree, so two
independent routes reached the same number. 24 disagree, and each records which
side is wrong and why.

### The test that matters

Per-rule accounting closes a hole most suites have. In the previous
implementation, 45 of 94 design-rule cases asserted only that nothing was found,
so a rule that never executed passed all 45 of them:

```
Cases that would still pass if the rule never ran

before  ████████████████████████  45 of 94   (48%)
now     ▏                          0 of 94   (0%)
```

### Not every passing test proves the same amount

A suite that reports only pass or fail flatters itself, so each case carries a
grade for how much evidence is behind it:

```
strong       ███████████████████████████████████  122   the rule ran, had real geometry to look at, and the measurement came close to the limit
blocked      ███                                   11   the expected answer is sound but the tool cannot currently reach it
vacuous      ███                                   10   the rule ran but never came close to the limit
skipped      ██                                     7   the rule reported skipped, and a clean count here would be a lie
weak         ██                                     7   nothing to check, for a legitimate reason
refused      █                                      5   the rule correctly refuses this input rather than guessing
underivable  █                                      5   nothing in the test data determines the answer
```

Nearly three quarters genuinely discriminates. The rest is accounted for by
name, which is not the same as being counted as a pass.

### Checked against KLayout

An independent reference matters more than our own suite, so 43 of the 94
design-rule cases were re-run through KLayout 0.30.8, using the nine rule
families whose semantics map onto KLayout region operations. Both tools are
scored against the same physics-derived answer, independent of either:

```
GPurify  ███████████████████████████████████████████  43 / 43
KLayout  ██████████████████████████████████████████   42 / 43
```

That is not GPurify being more correct. The one difference is
`DRC_MW_DIAG_FAIL`, a shape drawn at 45 degrees: KLayout measures it at 80.6 nm
against a 100 nm limit and flags it, correctly, while GPurify is
rectilinear-only and refuses the input. It scores the point only because
refusing is the documented expectation. KLayout is right about the physics
there, and GPurify cannot answer at all.

On the other 42, two independently written tools reach the same number.

## Speed

Whether a tool falls over on a large design is the question worth asking. Across
1,000 then 10,000 then 100,000 polygons, the cost per polygon falls rather than
climbs:

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

### Against KLayout

Same rule (`min_width`, 100 nm, one layer), same files, both tools single
threaded, median of five runs, identical violation counts at every size. The
layouts were written by KLayout itself, so this is reproducible without any file
GPurify prepared for itself:

```
              KLayout    GPurify     end to end
   1,000 pt    1061 ms     4.7 ms        226x
  10,000 pt    1083 ms    13.0 ms         83x
 100,000 pt    1309 ms    72.4 ms         18x
1,000,000 pt   3653 ms   661.9 ms        5.5x
```

Most of that gap is not the checking. KLayout pays about 1,056 ms of Ruby and Qt
startup per invocation, measured with an empty script, against GPurify's 3.8 ms
floor. Subtract each tool's own floor and only the geometry work is left:

```
 100,000 pt   KLayout 253 ms   GPurify  68.5 ms   3.7x
1,000,000 pt  KLayout 2597 ms  GPurify 658.1 ms   3.9x
```

So the honest number is about four times faster on the actual checking, with a
much larger margin per invocation in a scripted flow that starts the tool once
per cell. At a thousand polygons neither tool is doing enough work to measure.

This is one rule on synthetic rectilinear layout. It does not exercise KLayout's
hierarchical or tiled modes and is not a claim about its DRC engine in general.
KLayout's DRC is a programmable Ruby DSL, so it can express rules a fixed
vocabulary of 24 kinds cannot; a rule count is not a comparison between the two.

Everything above is one release build on an Intel i9-14900HX. Timings are
recorded, not enforced: no run fails a build for being slow. `cargo test
--release --test bench_all` reprints these tables on your own machine, including
a per-rule breakdown of which rule costs what.

## What it cannot do yet

This is a working tool that has not been proven against foundry signoff on
production silicon. Do not tape out on its verdict alone. Layouts must be
rectilinear, several rules measure less than a foundry deck does, and the
shipped decks are incomplete. [docs/limitations.md](docs/limitations.md) lists
every known gap.

There is no licence file yet.

## Documentation

| File | What is in it |
|---|---|
| [docs/usage.md](docs/usage.md) | Commands, options, reading the report, design intent, parasitics. |
| [docs/deck.md](docs/deck.md) | Writing a deck, and what every rule checks. |
| [docs/limitations.md](docs/limitations.md) | What GPurify cannot check yet. |
| [tests/fixtures/README.md](tests/fixtures/README.md) | The test corpus and how each expected answer was derived. |

```sh
cargo test --workspace --release          # the test suite
cargo test --release --test bench_all     # the timing tables above
```
