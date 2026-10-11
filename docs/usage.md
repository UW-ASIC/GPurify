# Running GPurify

```sh
gpurify <command> <layout.gds> --deck <process.deck> [options] > report
```

| Command | Checks | Needs |
|---|---|---|
| `drc` | Design rules: width, spacing, enclosure, area, density, grid, angle, vias | the deck |
| `erc` | Electrical rules: antenna, ties, floating gates and wells, shorts, power grid | the deck; `--intent` for the voltage, ESD and power-grid rules |
| `lvs` | The layout's devices and connections against your schematic | `--reference <netlist>` |
| `pex` | Parasitic resistance and capacitance; inductance for field-solved nets | the deck's `pex` lines |
| `all` | All four | a check whose input is missing is reported as skipped, never as passed |
| `lib` | Nothing: writes a macro's Liberty files, see [liberty.md](liberty.md) | `--spec`, `--output-dir` |

## Options

The options are the files a run reads, the report's form, and one choice of
method. Everything else is stated where it already lives: the grid is the
layout's own (its GDS `UNITS` record), and layers to skip are listed in the
deck (`ignore gds(L, D)`, see [deck.md](deck.md#layers)). The report goes to
standard output.

| Option | Meaning |
|---|---|
| `--deck <file>` | The process deck. Required. See [deck.md](deck.md). |
| `--reference <file>` | The schematic netlist for LVS (SPICE or Spectre). |
| `--intent <file>` | Design intent: supply voltages and per-net limits. See below. |
| `--format text\|json\|spef\|dspf` | Report format. `spef` and `dspf` need a `pex` run. Default `text`. |
| `--quasistatic <net>` | Field-solve this net's capacitance and inductance instead of using the closed-form estimate. Repeat for more nets. |

A shape on a GDS layer the deck neither declares nor ignores refuses the
layout, naming the layer. A layout whose database unit is not a whole fraction
of a micrometre is refused too.

## Reading the report

Every rule in the deck reports one of three outcomes, and the count of shapes
it examined:

- **ran**: the rule looked at your layout. Its violations are listed.
- **skipped**: the rule could not run, and the reason is given: the layer it
  names holds no geometry, or it needs design intent you did not supply.
- **refused**: the input is outside what the rule can decide correctly, for
  example a 45° shape on a rectilinear check. GPurify will not guess.

Read the skipped and refused counts before the violation count. A skipped
rule looked at nothing, so zero violations from it proves nothing, and the run
does not pass.

```
rules:
  m1.1: ran, examined 1 shapes, found 1 violations
  m1.2: ran, examined 0 shapes, found 0 violations
  tap_distance: skipped, the layer it names holds no geometry, examined 0 shapes, found 0 violations
violations: 1
  m1.1 error layer 7 at (40 nm, 500 nm) measured 80 nm against limit 140 nm on shape 0
summary:
  drc: ran
  1 rules skipped
  1 rules clean
  1 violations: 1 errors, 0 warnings
```

Each violation gives the rule, the layer, a point on the offending shape, what
was measured and the limit it broke.

## LVS reduction

Before matching, both sides are reduced, mostly the way netgen reduces them
(the differences are listed below):

- **Parallel:** devices of one model with every terminal on the same nets
  become one device. Source and drain are interchangeable, and so are a
  resistor's ends. For transistors, W and `nf` are summed, and every other
  parameter, L included, must agree. Any other device keeps its value and
  counts: two equal capacitors in parallel are one with `m=2`, which matches
  a card with `m=2` but not one card of twice the capacitance. A transistor
  whose card states no W has no width to sum and counts the same way: two
  unsized transistors in parallel match a card with `m=2`, not a card
  without it. A transistor's source and drain diffusions (`as`, `ad`, `ps`,
  `pd`) are summed with its W, each on its own net, whichever end each
  finger calls its source.
- **Series:** transistors stacked through a node nothing else touches, with
  their gates strapped, become one device whose L is the sum, if every other
  parameter agrees. Both must state L: with no length to add, two transistors
  in series stay two, so a stack does not match one unsized transistor.
  Transistors stating a diffusion do not merge in series: the diffusion
  between them would vanish, and no rule says what becomes of it.
- **Multiplier:** a transistor card's `m` multiplies its `W` and diffusions
  where it states a W, and `m` is then dropped (`nf` is untouched). Any other card's `m`, an
  unsized transistor's included, is its count of devices in parallel, so `m=2` matches two drawn devices and not one. `m=1` is the
  same as no `m`, and a card without `m` is one device whatever other cards
  state.

The parameter names are `w`, `l`, `nf` and `m`. Each merge needs only what
it adds: transistors stating W merge in parallel whether or not anything
states L, and transistors stating L merge in series whether or not anything
states W. The report lists every merge
under `lvs merges:` with the device rows it joined, so a paired device can be
traced back to what was drawn.

Where netgen (1.5.323) differs, given the setup that otherwise states these
rules (`tests/exhaustive/lvs/netgen.rs`, which checks every verdict against
netgen's):

- netgen never merges transistors in series, even with `series enable`, so a
  stack matches one long transistor here and not in netgen;
- netgen's `l critical` merges parallel transistors whose L agree within its
  tolerance; here L must be equal;
- netgen measures a parameter's difference against the mean of the two
  values, and this tool against the larger, so netgen's `2t/(2 − t)`
  (2.0202 % for 2 %) is this tool's `t`;
- netgen matches the top cell's pins by name; this tool never compares names;
- when the deck extracts no bulk, the reference's bulks are dropped here;
  netgen has no such rule, so its setup must tie every bulk to one net on
  both sides.

## LVS parameters

The layout's devices are sized from what is drawn: transistor and resistor
`w` and `l`, a transistor's `nf` (one per drawn channel) and its source and
drain diffusions `as`, `ad`, `ps` and `pd`, a bipolar's emitter `ae` and
`pe`, every device's `area` and `perim`, and a resistor's `r` and a
capacitor's `c` where the deck gives their coefficients (see
[deck.md](deck.md#devices)). A diffusion is compared on the net it is drawn
on: a card that writes the transistor drain first gives its `as` to that
net. Each parameter a
schematic card states is compared on that device, within 2 % of the larger
value. A card that
leaves a parameter out says nothing about it, whatever other cards of the
same model state, and a parameter the layout does not measure is reported
(`lvs.undeclared_param`) rather than passed.

An `R` or `C` card may give its value positionally, between its nets and
its model: `R1 a b 1k rpoly` is `R1 a b rpoly r=1k`. Devices are paired by
model, so an `R`, `C` or `D` card that names none (`R1 a b 1k`, `D1 a b`)
is the deck's one device of its kind; where the deck has none of that kind,
or several, the card is refused, and the message names them. On a
resistor, capacitor or diode card, other tools' names for the area and
perimeter are read as this tool's: KLayout's `A` and `P`, and ngspice's
diode `pj`, are `area`, `perim` and `perim`. A parameter stated twice, under
any of its names, is refused.

## Exit code

`0` only when every selected check ran, no rule was skipped or refused, and
no error was found; findings from rules the deck marks `warning` are reported
but do not fail the run. Anything else is `1`: an error, a skipped rule, a
missing input, a file that could not be read.

## Design intent

Some electrical rules need facts about the chip that no process deck can know:
`ir_drop`, `em_current_density`, `electromigration`, `reliability`,
`hv_domain`, `esd_latchup`, `esd_topological`, `gate_oxide`, `drain_source`,
`well_bias`, `missing_level_shifter`, `domain_crossing`, and
`multiple_drivers` and `tie_high_low`, which read the supplies as the rails
that orient each transistor channel. Without `--intent` they report skipped.

```json
{
  "domains":  { "core": { "voltage_mv": 1800 } },
  "supplies": [
    { "net": "VDD", "domain": "core", "role": "power" },
    { "net": "VSS", "domain": "core", "role": "ground" }
  ],
  "limits": [
    { "net": "VDD", "max_drop_mv": 90, "max_drop_fraction": 0.05,
      "max_overvoltage_mv": 100, "budget_current_ua": 2000 }
  ]
}
```

Net names are the text labels in your layout. A ground net sits at 0 V and its
drop is how far it rises (ground bounce); `max_drop_fraction` is a fraction of
its domain's voltage for either role. A limit you leave out on a net
means that net is not checked for it, not that it is unlimited. A current
budget on a net that no device terminal reaches is refused rather than
ignored, because zero current would pass every limit.

The supplies also set the voltages the overstress and domain rules check. A
power net sits at its domain's voltage and a ground net at 0 V. Every other
net can reach anything between the lowest and highest supply connected to it
through transistor source and drain, resistors, diodes and bipolar
transistors; gates and capacitors pass nothing. Each power net's domain is
the power domain of the signals it drives, so give every separately powered
supply its own domain. A file may declare at most 64 domains.

## Parasitics

`pex --format spef` writes a SPEF file for a timing tool, and `--format dspf`
writes a DSPF file for a simulator. Every net is extracted with closed-form
resistance and capacitance. Nets named with `--quasistatic` are solved from
the field instead, which is slower and more accurate, and their coupling to
nets that were not field-solved is kept. A field-solved net also gets its
inductance, and its resistance and inductance follow the wire's centre line
through every bend and every via, however the wire was cut into polygons. A
field-solved net whose shapes do not join into one circuit (two pieces that
meet only at a corner) is refused, and so is one with a shape the solve
cannot mesh (a layer above the substrate whose `pex` line states no
dielectric, or a diagonal edge), naming the layer, and a solve that does not
converge: PEX reports
the refusal and the rest of the report is still written. The field solve
holds the substrate at ground as a plane at height 0, so a field-solved
net's capacitance to ground
is to the substrate, as the closed forms' is. A shape on a layer at height 0
(a well or a diffusion) is a junction in that plane, whose capacitance is a
depletion capacitance rather than a field: it is left out of the solve, and
the net's capacitance to ground adds the closed form from that layer's `pex`
line (area and fringe), while its resistance through the shape is computed
as for any other. So a net of metal and diffusion field-solves its metal,
and the field reads every junction as part of the grounded substrate. A
shape on a `connect global` layer (the substrate as a net) carries no
parasitics in the field solve either: it is left out and needs no `pex`
line, so a ground net tied to the substrate through its taps solves through
its other shapes, and one whose pieces join only through the substrate is
not one circuit and is refused. A net named twice is solved once.

A net with no text label in the layout has no name to write, and the run
refuses it rather than inventing one. A label on two nets that are not
connected cannot name either in a SPEF or DSPF file, which would merge them,
so the file is refused, naming the label. Two labels on one net, a short
that fails the run anyway, cannot both name it, as both formats give a net
one name: the file is refused too, naming both, rather than written under
one.

A wire is measured as drawn, not as cut into polygons: a net's shapes on one
layer are merged first, so pieces that abut or overlap read as the one
conductor they draw. Two pieces that meet only at a corner are one net but
two conductors, since a point carries no current: each is measured on its
own, and the closed forms chain them as they chain any two conductors of a
net. A conductor layer with a diagonal edge cannot be merged exactly, and
PEX is refused for it.

Every conductor layer that carries a net, and every via layer whose cuts join
two conductors, needs a `pex` line with a positive sheet resistance (see
[deck.md](deck.md#parasitic-stack)). A layer without one has unknown
parasitics, not zero ones, so PEX is refused and names the layer. Layers in
`connect global` (the substrate) carry no parasitics and need no line.

The same inputs always give a byte-identical report.
