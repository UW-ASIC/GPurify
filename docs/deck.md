# Writing a deck

A deck describes your process: its layers, how they connect, what a device
looks like, the metal stack for parasitics, and the rules a layout must meet.
It is plain text. Four examples ship in `pdks/`.

The format is strict on purpose. Every parameter of every rule must be
written out; there are no defaults. A missing parameter, a misspelled one, a
layer that was never declared, a number without a unit, or a unit of the
wrong kind is an error that points at the line and column. A deck that loads
means what it says.

## Example

```
# sky130 (excerpt)
grid 5nm

layer nwell = gds(64, 20)
layer diff  = gds(65, 20)
layer poly  = gds(66, 20)
layer licon = gds(66, 44)
layer li    = gds(67, 20)
layer mcon  = gds(67, 44)
layer met1  = gds(68, 20)
layer met2  = gds(69, 20)
layer met3  = gds(70, 20)
layer met1_label = gds(68, 5)
layer nsdm  = gds(93, 44)
layer psdm  = gds(94, 20)

layer ngate       = poly and diff and nsdm
layer diff_active = diff not poly

rule nwell.1  width(nwell)            >= 840nm
rule nwell.2a space(nwell)            >= 1270nm
rule m1.1     width(met1)             >= 140nm
rule m1.4     enclosure(mcon, met1)   >= 30nm
rule m1.5     enclosure(mcon, met1, opposite) >= 60nm
rule m1.6     area(met1)              >= 0.083um2

let metals = [(met1, 140nm), (met2, 140nm), (met3, 300nm)]
for (m, w) in metals {
    rule {m}.width width(m) >= w
}

rule em.li electromigration(li, licon,
    max_density: 0.28mA/um, max_current_per_cut: 80uA, blech_limit: 15mA,
    reference_temperature: 378K, activation_energy: 0.9eV, current_exponent: 2)

connect conductors [diff_active, poly, li, met1]
connect touch_within_layer
connect via licon [diff_active, li]
connect via mcon  [li, met1]

device mos ngate model "sky130_fd_pr__nfet_01v8" terminals [poly, diff_active, diff_active]

connect label met1_label names met1

pex met1 thickness 360nm height 1376nm sheet 0.125ohm dielectric 3.9 area_cap 25.8aF/um2 fringe_cap 40.5aF/um
```

## Basics

One statement per line. `#` starts a comment. A long rule can continue onto
the next lines inside its parentheses.

`grid 5nm` is your manufacturing grid. Every length in a rule must be a
multiple of it, so `142nm` on a 5 nm grid is an error, not a rounding.

Numbers carry units. `140nm`, `0.14um` and `0.00014mm` are the same length.

| Kind of value | Units |
|---|---|
| length | `nm`, `um`, `mm` |
| area | `nm2`, `um2`, `mm2` |
| voltage | `mV`, `V` |
| current | `nA`, `uA`, `mA`, `A` |
| current per width | `uA/um`, `mA/um`, `A/m` |
| resistance | `mohm`, `ohm`, `kohm`, `Mohm` |
| capacitance per area | `aF/um2`, `fF/um2` |
| capacitance per length | `aF/um`, `fF/um` |
| temperature | `K`, or `C` |
| energy | `eV` |
| time | `h` |
| fraction | `%`, or a bare number from 0 to 1 |
| angle | `deg` |

A count (number of cuts, colours, drivers) and a plain ratio or exponent are
bare numbers.

## Layers

```
layer met1 = gds(68, 20)                 # a drawn layer: GDS layer and datatype
layer ngate = poly and diff and nsdm     # a derived layer
layer diff_active = diff not poly
layer m12 = (met1 or met2) not blockage
```

Derived layers combine earlier layers with `and`, `or` and `not`, left to
right; use parentheses to group. A layer must be declared before anything
uses it.

Operations follow a layer after a `.` and chain left to right:

```
layer huge_met1 = met1.sized(-1.5um).sized(1.5um)   # the parts of met1 wider than 3um
layer tap_gate  = poly.interacting(tap).not_interacting(licon)
layer big_diff  = (diff not poly).with_area(>= 1um2, < 4um2)
layer butt      = nsdm.edges() and psdm.edges()
```

Shapes that touch or overlap count as one shape before an operation looks at
them. Operations on shapes:

| Operation | Result |
|---|---|
| `.sized(len)` | Every shape grown by `len` on all sides, corners square. A negative `len` shrinks, and a part no wider than twice the shrink disappears. `.sized(-a).sized(a)` keeps the parts wider than `2a`. |
| `.interacting(L)` | The shapes that touch or overlap a shape on `L`. Sharing only a corner counts. |
| `.not_interacting(L)` | The shapes that do not. |
| `.inside(L)` | The shapes entirely covered by `L`. A shape may touch `L`'s boundary from inside. |
| `.outside(L)` | The shapes sharing no area with `L`. A shape that only touches `L` is outside. |
| `.holes()` | Each hole, filled. A hole with an island in it is filled over the island. |
| `.extents()` | The bounding box of each shape. |
| `.with_area(bounds)` | The shapes whose area, not counting holes, is within the bounds. |
| `.with_width(bounds)` | The shapes whose narrowest width, as `width` measures it, is within the bounds. |
| `.edges()` | The boundary of each shape, as an edge layer. |

Bounds are one or two comparisons with `>=`, `>`, `<=`, `<`, or a single `==`:
`with_area(>= 1um2)`, `with_width(> 1um, <= 3um)`. Bounds that nothing can
satisfy are an error.

An edge layer holds the boundary segments of shapes, each knowing which side
its shape was on. It combines only with other edge layers:

| Operation | Result |
|---|---|
| `E and F` | The parts of `E` that coincide with `F`, whichever side each shape is on. The edges where two layers butt are `A.edges() and B.edges()`. |
| `E not F` | The parts of `E` that do not coincide with `F`. |
| `E or F` | Both, with the shared parts once. |
| `.inside_part(L)` | The parts of each edge strictly inside `L`. Parts on `L`'s boundary are in neither this nor `outside_part`. |
| `.outside_part(L)` | The parts of each edge strictly outside `L`. |
| `.interacting(L)` / `.not_interacting(L)` | The whole edges that touch or lie in a shape on `L`, or that do not. |
| `.with_length(bounds)` | The edges whose length is within the bounds. |

A check that takes an edge layer says so. Every other check refuses one.

## Rules

```
rule <id> <check>
rule <id> warning <check>        # ERC only: report as a warning, not an error
```

The id is your name for the rule, and it is how violations are reported. Use
the foundry's rule numbers (`m1.1`, `licon.5a`) so a report reads like the
manual.

A check with one limit is written as a comparison: `>=` for a minimum, `<=`
for a maximum. Writing `<=` on a minimum rule is an error, not a flipped rule.
Other parameters are named, after a `;` or a `,`:

```
rule m1.eol eol_space(met1; eol_width: 200nm) >= 170nm
rule grid   off_grid(; pitch: 5nm)
```

### Reuse

`let` names a value, and `for` repeats statements over a list you write in the
deck. `{name}` inside a rule id is replaced by the loop value.

```
let metals = [(met1, 140nm), (met2, 140nm), (met3, 300nm)]
for (m, w) in metals {
    rule {m}.width width(m) >= w
    rule {m}.space space(m) >= w
}
```

A name can be bound once. Loops only run over lists written in the deck, so a
deck always finishes loading.

## Design rules

| Check | What it flags |
|---|---|
| `width(L) >= len` | A shape narrower than the limit anywhere. |
| `width(L) <= len` | A shape wider than the limit. |
| `edge_length(L) >= len` | An edge shorter than the limit. |
| `notch(L) >= len` | A gap narrower than the limit between two parts of the same shape. |
| `space(L) >= len` | Two shapes on one layer closer than the limit. |
| `space(A, B) >= len` | A shape on `A` closer than the limit to a shape on `B`. |
| `eol_space(L; eol_width: len) >= len` | Space from an end of line (an edge shorter than `eol_width`) below the limit. |
| `prl_space(L; prl: len) >= len` | Two shapes that run side by side for at least `prl`, closer than the limit. |
| `corner_space(L) >= len` | Two shapes whose corners are closer than the limit. |
| `wide_space(L; width: len) >= len` | Space below the limit next to a shape at least `width` wide. |
| `area(L) >= area` | A shape smaller than the limit. |
| `hole_area(L) >= area` | A hole in a shape smaller than the limit. |
| `cheesing(L) <= area` | A shape larger than the limit with no slot in it. |
| `density(L; window: len, step: len) >= frac` | A window, swept in steps, with less coverage than the limit. Use `<=` for a maximum. |
| `enclosure(inner, outer) >= len` | An `inner` shape not surrounded by `outer` by the limit on every side. |
| `enclosure(inner, outer, opposite) >= len` | An `inner` shape without the limit on the required sides. |
| `extension(A, B) >= len` | `A` not extending past `B` by the limit, as poly past diffusion. |
| `overlap(A, B) >= len` | `A` and `B` overlapping by less than the limit. |
| `tap_distance(well, tap) <= len` | Part of a well further than the limit from a tap. |
| `off_grid(; pitch: len)` | A vertex off the manufacturing grid. |
| `angle(; allowed: [0deg, 90deg])` | An edge at an angle not in the list (multiples of 45°). |
| `redundant_via(L; within: len) >= count` | A cut with fewer than `count` cuts, itself included, within `within`. |
| `via_array_space(L; array: count) >= len` | Cuts in a cluster larger than `array`, closer than the limit. |
| `patterning(L; colors: count) >= len` | Shapes that cannot be split into `colors` masks with same-mask shapes at least the limit apart. |

## Electrical rules

Every parameter below is required. Where a parameter may be absent, write
`none`; leaving it out is still an error.

`models` is a list of device model names in quotes, each declared by a
`device` statement: `["sky130_fd_pr__nfet_01v8", "sky130_fd_pr__pfet_01v8"]`.
A name no device declares is an error.

The voltage rules read what each net can reach from the supplies in the
intent file (see [usage.md](usage.md#design-intent)). A device whose terminals
no supply reaches through a transistor channel, resistor or diode is not
checked.

```
let thin = ["sky130_fd_pr__nfet_01v8", "sky130_fd_pr__pfet_01v8"]
rule ox.thin  gate_oxide(; models: thin, max: 1.98V)
rule ds.thin  drain_source(; models: thin, max: 1.98V)
rule wb       well_bias(; pmos: ["sky130_fd_pr__pfet_01v8"], nmos: ["sky130_fd_pr__nfet_01v8"])
rule ls       missing_level_shifter(; shifters: ["ls_nfet", "ls_pfet"])
rule xing     domain_crossing()
rule esd.pad  esd_topological(pad; clamps: ["esd_diode", "rail_clamp"])
```

| Check | What it flags |
|---|---|
| `antenna(gate, collectors…; max_ratio: n, sidewall: len \| none)` | A gate connected to more collector area than `max_ratio` times its own. |
| `antenna_electrical(gate, collectors…; max_ratio: n, diode: layer \| none, diode_credit: n, diode_bonus: n)` | The cumulative antenna ratio, with credit for protection diodes. |
| `density_cmp(L; window: len x len, step: len x len, min: frac \| none, max: frac \| none, max_delta: frac \| none, partial_windows: true \| false, cmp: none \| (target: frac, thickness: len, sensitivity: len, max_delta: len))` | Metal density out of range, a jump between neighbouring windows, or a predicted polish thickness out of range. |
| `electromigration(layers…; max_density: current per width, max_current_per_cut: current, blech_limit: current, reference_temperature: temp, activation_energy: eV, current_exponent: n)` | A wire or cut carrying more current than its rated limit at the operating temperature. Needs `--intent`. |
| `em_current_density(layers…; max_density: current per width, max_current_per_cut: current)` | A wire or cut above its instantaneous current limit. Needs `--intent`. |
| `ir_drop()` | A node whose voltage drop or overvoltage exceeds its net's stated limit. Needs `--intent`. |
| `p2p_resistance(; max: resistance)` | Two points on one net further apart in resistance than the limit. |
| `reliability(; required_lifetime: h, reference_lifetime: h, reference_stress: voltage, stress_exponent: n, reference_temperature: temp, activation_energy: eV, max_abs_voltage: voltage, duty_cycle: frac)` | A device whose predicted lifetime is below `required_lifetime`. Needs `--intent`. |
| `hv_domain(; max_delta: voltage, isolation: layer \| none)` | A device whose terminals reach supply domains more than `max_delta` apart, directly or through other devices' channels. Needs `--intent`. |
| `esd_latchup(pad, guard_ring; min_guard_ring_width: len, max_tap_distance: len, clamps: models)` | A guard ring too narrow or too far from a supply tap, and a pad net short of a clamp path (as `esd_topological`). Needs `--intent`. |
| `esd_topological(pad; clamps: models)` | A pad net with no path through `clamps` devices to both a power and a ground supply. The path is a clamp from the pad to a supply, then any rail clamps between supplies. Needs `--intent`. |
| `floating_gate()` | A net that only connects to gates. |
| `floating_well(well, tap)` | A well with no tap in it. |
| `missing_tie(well, diff; max_distance: len)` | A region further than `max_distance` from a tap. |
| `multiple_drivers(; max: count)` | A net driven by more than `max` separate drivers. |
| `soft_connection(layers…)` | A net held together only through the listed high-resistance layers. |
| `supply_short(tap_a, tap_b)` | A net that touches both kinds of tap, such as an n-tap and a p-tap. |
| `tie_high_low()` | A net that reaches a gate and a transistor source but no drain: a gate tied straight to a rail instead of through a tie cell. |
| `unconnected_pin(layers…)` | A shape on the listed layers that reaches no device. |
| `gate_oxide(; models: models, max: voltage)` | A device of those models whose gate can differ from its source, drain or bulk by more than `max`. Needs `--intent`. |
| `drain_source(; models: models, max: voltage)` | A device of those models whose drain can differ from its source by more than `max`. Needs `--intent`. |
| `well_bias(; pmos: models \| none, nmos: models \| none)` | A `pmos` device whose well can sit below its source or drain, or an `nmos` device whose substrate can sit above them. Needs `--intent`. |
| `missing_level_shifter(; shifters: models \| none)` | A transistor whose gate is driven from a power domain its source and drain are not in, unless its model is one of `shifters`. Needs `--intent`. |
| `domain_crossing()` | A device whose source-to-drain path joins two power domains. Needs `--intent`. |

## Connectivity

```
connect conductors [diff_active, poly, li, met1]   # layers that carry signal
connect touch_within_layer                         # shapes that touch on one layer are one net
connect via mcon [li, met1]                        # a cut joins the two layers it overlaps
connect label met1_label names met1                # text on met1_label names the met1 net under it
```

Name your nets with text labels in the layout. LVS, SPEF and the intent file
all refer to nets by those names.

## Devices

```
device mos ngate model "sky130_fd_pr__nfet_01v8" terminals [poly, diff_active, diff_active]
```

A device is found wherever its marker layer (`ngate`) has shapes. Its
terminals are the listed layers, in order: gate, source, drain for `mos`.
Kinds: `mos`, `bjt`, `resistor`, `capacitor`, `diode`. The model name is what
LVS compares against your schematic.

## Parasitic stack

```
pex met1 thickness 360nm height 1376nm sheet 0.125ohm dielectric 3.9 area_cap 25.8aF/um2 fringe_cap 40.5aF/um
```

One line per conducting layer, with all six values: thickness, height above
the substrate, sheet resistance per square, the dielectric constant around it,
and the area and fringe capacitance to substrate.

## Errors

Every problem is reported with its line, column and a marker under the
offending text, and all of them are reported together (up to 50), so you can
fix a deck in one pass:

```
pdks/sky130.deck:41:28: m1.5: enclosure needs a length, got 60 (no unit)
rule m1.5 enclosure(mcon, met1, opposite) >= 60
                                             ^^
```
