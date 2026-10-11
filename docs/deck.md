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
| temperature coefficient | `/K` (first order), `/K2` (second order) |
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
ignore gds(81, 4)                        # a stream pair to drop, not refuse
```

A shape on a GDS layer the deck does not declare refuses the layout, so a
layer nobody wrote rules for cannot slip past every check. A layer the deck
deliberately leaves out, such as a marker no rule reads, is listed with
`ignore gds(L, D)`, and its shapes and texts are dropped. A pair cannot be
both ignored and declared, and cannot be ignored twice.

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
them. Meeting only at a corner is touching: two shapes that share just a
corner point are one shape, joined there by a neck of width 0. Space does not
pass through such a corner, so a ring of shapes closed only at a corner
encloses a hole. Every operation, every check and net extraction read shapes
this way. Operations on shapes:

| Operation | Result |
|---|---|
| `.sized(len)` | Every shape grown by `len` on all sides, corners square. A negative `len` shrinks, and a part no wider than twice the shrink disappears. `.sized(-a).sized(a)` keeps the parts wider than `2a`. |
| `.interacting(L)` | The shapes that touch or overlap a shape on `L`. Sharing only a corner counts. |
| `.not_interacting(L)` | The shapes that do not. |
| `.inside(L)` | The shapes entirely covered by `L`. A shape may touch `L`'s boundary from inside. |
| `.outside(L)` | The shapes sharing no area with `L`. A shape that only touches `L` is outside. |
| `.holes()` | Each hole, filled. A hole with an island in it is filled over the island. |
| `.extents()` | The bounding box of each shape. Boxes that overlap stay separate shapes, as in KLayout: `forbidden` reports each, and an operation or a check that merges its layer merges them. |
| `.with_area(bounds)` | The shapes whose area, not counting holes, is within the bounds. |
| `.with_width(bounds)` | The shapes whose narrowest width, as `width` measures it, is within the bounds. The diagonal neck where two shapes overlap at a corner counts, at its exact length: a 70.7 nm neck is `> 70nm` and not `<= 70nm`. |
| `.with_bbox_max(bounds)` | The shapes whose bounding box's longer side is within the bounds: a straight feature's length, as sky130 mf.2 "length of fuse" or IHP Rsil.f "min. RES length", and KLayout's `with_bbox_max`. |
| `.with_bbox_min(bounds)` | The same on the shorter side (`with_bbox_min`). |
| `.rectangles()` / `.squares()` | The shapes that are one axis-aligned rectangle with no hole, or one with equal sides, as KLayout's `rectangles` and `squares`. Touching pieces that make one rectangle are one; two rectangles meeting only at a corner are one shape that is none. `forbidden(capm.non_rectangles())` is sky130 capm.7 "only rectangular capacitors" and LEF58 `RECTONLY`. |
| `.non_rectangles()` / `.non_squares()` | The other shapes. |
| `.with_text(T, "pattern")` | The shapes holding a text on layer `T` that matches `pattern`, as IHP picks devices by their text. `*` matches any run of characters and `?` one; everything else matches itself, case included. A text on a shape's edge counts. `T` must be a drawn layer. |
| `.without_text(T, "pattern")` | The shapes holding no such text. |
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
| `.horizontal()` / `.vertical()` | The edges running along that axis, as KLayout's `with_angle(0)` and `with_angle(90)`. A width between horizontal edges is measured vertically. |

A check that takes an edge layer says so (see [Edge checks](#edge-checks)).
Every other check refuses one.

Wherever a rule takes a layer, it can take a layer expression instead:
`forbidden(licon and poly and (diff or tap))` is the same as declaring that
layer and naming it.

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

A check that counts touching shapes as one counts shapes meeting only at a
corner as one too (see [Layers](#layers)). So for two squares that touch at a
corner, `width` reports 0 at the corner, `area` measures both together,
`space` never measures between them, and a gap between two parts of such a
shape is a `notch`. A ring closed only at a corner has a hole for `hole_area`.

| Check | What it flags |
|---|---|
| `width(L) >= len` | A shape narrower than the limit anywhere. |
| `width(L) <= len` | Any part of a shape wider than the limit in every direction, counting touching shapes as one (a plate with a thin tab is as wide as the plate). |
| `size(L) == len x len` | A cut that is not exactly that rectangle, either way round. Touching cuts count as one shape, so two abutting squares are a slot. |
| `width(L; allowed: [len, ..])` | A shape whose width, its narrowest as `width` measures it, is none of the listed widths: sky130 rpm.1b-1f, the legal widths of a precision resistor (a list of one gives one type's exact width). Touching shapes count as one; a shape with parts of several widths is judged by its narrowest. |
| `size(L; allowed: [w x h, ..])` | A cut that is none of the listed sizes, each either way round: sky130 via.1b's three square via sizes, and LEF58 `CUTCLASS`. Touching cuts count as one shape. |
| `edge_length(L) >= len` | An edge shorter than the limit. |
| `min_step(L; max_edges: n) >= len` | More than `n` edges shorter than the limit in a row: LEF `MINSTEP .. MAXEDGES`. |
| `min_step(L; corner: outside, length_sum: len \| none) >= len` | Two or more edges shorter than the limit in a row at an outside (convex) corner, the two long edges either side turning left: LEF `MINSTEP .. OUTSIDECORNER`, its default. `corner: inside` is a concave corner (`INSIDECORNER`); `corner: step` one or more short edges between long edges running the same way (`STEP`). With `length_sum`, a run passes while its total length is at most that (`LENGTHSUM`). An end of line is no corner and no step. |
| `notch(L) >= len` | A gap narrower than the limit between two parts of the same shape. |
| `space(L) >= len` | Two shapes on one layer closer than the limit. |
| `space(A, B) >= len` | A shape on `A` closer than the limit to a shape on `B`. |
| `eol_space(L; eol_width: len) >= len` | Space from an end of line (an edge shorter than `eol_width`) below the limit. |
| `prl_space(L; prl: len) >= len` | Two shapes that run side by side for at least `prl`, closer than the limit. The run is how far their facing edges, at most the limit apart, project onto each other (LEF `PARALLELRUNLENGTH`), with touching shapes merged first: a wire drawn as segments runs its whole length. |
| `corner_space(L) >= len` | Two shapes whose corners are closer than the limit. |
| `wide_space(L; width: len) >= len` | Space below the limit from the part of a shape at least `width` wide (where a `width` square fits), as sky130's huge metal. |
| `wide_space(L; width: len, attached: len) >= len` | The same, also from the rest of the shape within `attached` of its wide part, as sky130 m1.3a "features attached to or extending from huge_met1 for a distance of up to 0.28 µm". |
| `space(L; nets: same) >= len` | Two shapes on the same net closer than the limit, as gf180 NW.2a. Nets are the extracted ones, joined through vias and other layers. `L` must be a conductor. |
| `space(L; nets: different) >= len` | Two shapes on different nets closer than the limit, as gf180 NW.2b. |
| `space_table(L; prl: [len, ..], width: [len, ..], space: [[len, ..], ..])` | Two shapes closer than their table cell (see below). |
| `area(L) >= area` | A shape smaller than the limit. |
| `hole_area(L) >= area` | A hole in a shape smaller than the limit. |
| `cheesing(L) <= area` | A shape larger than the limit with no slot in it. |
| `density(L; window: len, step: len) >= frac` | A window, swept in steps across the whole layout, with less coverage than the limit. Use `<=` for a maximum. A window hanging past the edge counts the outside as empty. The whole layout is the extent of the drawn layers: a derived layer, such as one grown past the drawing, does not widen it. |
| `density(L, boundary; window: len, step: len) >= frac` | The same, with the windows tiling the extent of the `boundary` layer (the die outline). |
| `total_area(L) <= area` | More area on `L` in the whole layout than the limit, overlaps counted once and holes not at all: IHP MIM.gR's total MIM area per chip. Reported once, at the centre of the drawn layers' extent. |
| `aspect_ratio(L) <= r` | A shape whose bounding box is more than `r` times as long as it is wide (longer side over shorter, as KLayout's `with_bbox_aspect_ratio`), touching shapes counting as one: sky130 capm.6 and li.2. `r` is a bare number. |
| `count(L) <= n` | More than `n` shapes on `L` in the whole layout, touching shapes counting as one: a per-chip limit, as IHP's npn13G2.bR on the number of npn13G2 emitters. Use `>=` for a minimum; "one seal ring per chip" is `count(seal) <= 1` with `count(seal) >= 1`. Reported once, at the centre of the drawn layers' extent. |
| `region_density(L, R) <= frac` | A shape of `R` inside which `L` covers more than the limit of its area, each shape measured on its own: the pattern density over a device, as sky130 vpp.5a "max pattern density of met3.dg over capacitor.dg". Use `>=` for a minimum (vpp.11). |
| `global_density(L) >= frac` | Coverage of the whole layout (the drawn layers' extent, as for `density`) below the limit. Add a boundary layer, `global_density(L, boundary)`, to measure over the die outline. Use `<=` for a maximum. |
| `enclosure(inner, outer) >= len` | An `inner` shape not surrounded by `outer` by the limit on every side, measured to the outer shape's real edges, holes included. |
| `enclosure(inner, outer, opposite) >= len` | An `inner` shape without the limit on both sides of at least one axis (sky130 m1.5 "two opposite sides"). |
| `extension(A, B) >= len` | `A` not extending past `B` by the limit, as poly past diffusion. |
| `overlap(A, B) >= len` | `A` and `B` overlapping by less than the limit. |
| `tap_distance(well, tap) <= len` | Any point of a well further than the limit from a tap. |
| `off_grid(; pitch: len)` | A vertex of a drawn shape off the manufacturing grid. Derived layers are not checked: they repeat the drawn vertices, and sizing by less than the grid would put on-grid drawing off it. |
| `angle(; allowed: [0deg, 90deg])` | An edge at an angle not in the list (multiples of 45°), on any drawn layer. Derived layers are not checked: they repeat the drawn edges. |
| `angle(L; allowed: [0deg, 90deg])` | The same, on layer `L` only. |
| `interior_angle(L) >= deg` | A corner whose angle inside its shape is under the limit, as IHP 3.1 "shapes with acute angles <87 degree are not allowed": 90 at a rectangle's corner, 270 at an L's inner corner, 45 at a right isosceles triangle's acute corners. Drawn shapes are read as drawn, diagonal ones included; write `interior_angle() >= deg` for every drawn layer. |
| `valid(L)` | A drawn polygon that crosses itself or encloses no area (IHP 3.1 "self-intersecting polygons must be avoided"), named one by one, where every other rule on its layer is refused. Write `valid()` for every drawn layer. |
| `redundant_via(L; within: len) >= count` | A cut with fewer than `count` cuts, itself included, within `within`. |
| `via_array_space(L; array: count) >= len` | Cuts in a cluster larger than `array`, closer than the limit. |
| `patterning(L; colors: count) >= len` | Shapes that cannot be split into `colors` masks with same-mask shapes at least the limit apart. |
| `forbidden(L)` | Every shape on `L`, reported with its area. Write the forbidden overlap as the layer: `forbidden(licon and poly and (diff or tap))`. On an edge layer, every edge. |
| `contains(outer, inner) >= count` | An `outer` shape holding fewer than `count` `inner` shapes entirely, as sky130 licon.16 "every tap must enclose at least one licon". An inner shape across the outer's edge is not held, and touching inner shapes count as one. |
| `inside(inner, outer)` | An `inner` shape not entirely inside `outer`, reported with the area left outside, as licon.18 "npc must enclose poly_licon". Touching `outer`'s edge from inside is inside. |

A spacing table, as a LEF `SPACINGTABLE PARALLELRUNLENGTH` or IHP Metal1
M1.b/e/f:

```
rule M1.bef space_table(met1;
    prl:   [0um, 1um, 10um],
    width: [0um, 0.3um, 10um],
    space: [[180nm, 180nm, 180nm],
            [180nm, 220nm, 220nm],
            [180nm, 220nm, 600nm]])
```

A pair of shapes needs the cell in the last row whose `width` the wider shape
exceeds and the last column whose `prl` the two shapes' run alongside each
other exceeds; the first row and column always apply. The run is measured as
for `prl_space`, over the facing edges at most the cell it would select apart:
edges 230 nm apart do not make a run for a 200 nm cell. "Exceeds" is strict, as
the foundry writes "wider than 0.3 µm": a shape exactly 0.3 µm wide is in the
first row. A row's width is measured on the part of the shape that wide, so a
thin tab of a wide plate is held to the thin row. `prl` and `width` start at
0 and rise, there is one row per width and one cell per run length, and no
cell is smaller than the one before it in its row or column.

### Edge checks

These take an edge layer, such as the butting edges `tap.edges() and
diff.edges()`. A finding is placed on the edge and names no shape.

| Check | What it flags |
|---|---|
| `length(E) >= len` | An edge shorter than the limit, as sky130 difftap.4 "min tap bound by one diffusion" on the butting edges. |
| `space(E) >= len` | Two parallel edges of `E` closer than the limit, measured edge to edge and end to end, whatever side their shapes are on. Edges that touch are not measured. As difftap.5 "min tap bound by two diffusions". |
| `space(E, F) >= len` | The same between an edge of `E` and one of `F`, as difftap.7. |
| `enclosure(E, L) >= len` | An edge whose outside is not covered by `L` for the limit, measured straight out from the edge along its length, as n/psd.5a "enclosure of diff by nsdm, except for butting edge" with `diff.edges() not tap.edges()`. |
| `width(E) >= len` | Two parallel edges facing each other across their shapes (each edge's shape lies toward the other), overlapping along their length, closer than the limit, measured straight across. With `layer gate = poly and diff`, a channel length is `width(gate.edges() not diff.edges())` (sky130 poly.1b, IHP Gat.a1) and a channel width `width(gate.edges() and diff.edges())` (difftap.2); a vertical width is `width(met4.edges().horizontal())` (ASAP7 M4.W.1). Every pair counts: an edge between two others does not shield them. |
| `facing_space(E) >= len` | The same with the shapes turned away from each other: a gap between shapes, or a notch in one, measured between the chosen edges. A horizontal spacing is `facing_space(met4.edges().vertical())` (ASAP7 M4.S.2). `space(E)` measures whatever the sides. |
| `forbidden(E)` | Every edge, as n/psd.6 `forbidden((tap.edges() and diff.edges()).outside_part(psdm))`. |

## Electrical rules

Every parameter below is required. Where a parameter may be absent, write
`none`; leaving it out is still an error.

`models` is a list of device model names in quotes, each declared by a
`device` statement: `["sky130_fd_pr__nfet_01v8", "sky130_fd_pr__pfet_01v8"]`.
A name no device declares is an error.

The voltage rules read what each net can reach from the supplies in the
intent file (see [usage.md](usage.md#design-intent)). A device whose terminals
no supply reaches through a transistor channel, resistor or diode is not
checked. A transistor whose `device` row states `on_gate_min` or
`on_gate_max` (see [Devices](#devices)) passes voltage only while its gate
can turn it on.

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
| `antenna(gate, collectors…; max_ratio: n, sidewall: len \| none, diode: layer \| none)` | A gate whose collector-to-gate area ratio is above `max_ratio`. The ratio has one term per etch step the collectors span, each counting only what is connected to the gate when that layer is etched, and the terms are summed (LEF's CAR, IHP's `AreaRatio`). Overlapping shapes count once. With `sidewall`, collector area is perimeter times that thickness. With `diode`, a gate connected to that layer is skipped, left to a row for protected gates (IHP Ant.b and Ant.e). Name the gate as a derived `poly and diffusion` layer. The gate is connected through the layer a `device mos` row names as its gate terminal (`poly`) where it overlaps it; with no such row, through the conductor it lies on, which is the diffusion when a `connect via` joins diffusion and poly directly. |
| `antenna_electrical(gate, collectors…; max_ratio: n, diode: layer \| none, diode_credit: n, diode_bonus: n)` | The cumulative antenna ratio, with credit for protection diodes. |
| `density_cmp(L; window: len x len, step: len x len, min: frac \| none, max: frac \| none, max_delta: frac \| none, partial_windows: true \| false, cmp: none \| (target: frac, sensitivity: len, max_delta: len))` | Metal density out of range, a jump between neighbouring windows, or a predicted polish thickness out of range. |
| `electromigration(layers…; max_density: current per width, max_current_per_cut: current, blech_limit: current, reference_temperature: temp, activation_energy: eV, current_exponent: n)` | A wire or cut carrying more current than its rated limit at the operating temperature. Needs `--intent`. |
| `em_current_density(layers…; max_density: current per width, max_current_per_cut: current)` | A wire or cut above its instantaneous current limit. Needs `--intent`. |
| `ir_drop()` | A node whose voltage drop or overvoltage exceeds its net's stated limit. Needs `--intent`. |
| `p2p_resistance(; max: resistance)` | Two points on one net further apart in resistance than the limit. |
| `reliability(; required_lifetime: h, reference_lifetime: h, reference_stress: voltage, stress_exponent: n, reference_temperature: temp, activation_energy: eV, max_abs_voltage: voltage, duty_cycle: frac)` | A supply-grid node whose voltage stress predicts a lifetime below `required_lifetime` (inverse power law in voltage times Arrhenius in temperature), or whose voltage exceeds `max_abs_voltage`. It reads the solved supply grid, not individual devices. Needs `--intent`. |
| `hv_domain(; max_delta: voltage, isolation: layer \| none)` | A device whose terminals reach supply domains more than `max_delta` apart, directly or through other devices' channels. Needs `--intent`. |
| `esd_latchup(pad, guard_ring; min_guard_ring_width: len, max_tap_distance: len, clamps: models)` | A guard ring too narrow or too far from a supply tap, and a pad net short of a clamp path (as `esd_topological`). Needs `--intent`. |
| `esd_topological(pad; clamps: models)` | A pad net with no path through `clamps` devices to both a power and a ground supply. The path is a clamp from the pad to a supply, then any rail clamps between supplies. Needs `--intent`. |
| `floating_gate(; labels_are_ports: bool)` | A net that only connects to gates. With `labels_are_ports: true`, a labelled net is a block input driven from outside the cell and is skipped. |
| `floating_well(well, tap)` | A well with no tap in it. |
| `missing_tie(region, tap; max_distance: len)` | A point of a `region` shape (a device polarity's active area, say) further than `max_distance` from the nearest `tap` edge. |
| `multiple_drivers(; max: count)` | A net driven by more than `max` separate drivers. A driver is a path through transistor channels from the net to a supply the intent file declares; networks that share a gate net (an inverter, a NAND's pull-up and pull-down) are one driver, and a pass gate that reaches no supply drives nothing by itself. Which end of a channel is the source does not matter. Needs `--intent`. |
| `soft_connection(layers…)` | A net held together only through the listed high-resistance layers. |
| `supply_short(tap_a, tap_b[, within])` | A net that touches both kinds of tap, such as an n-tap and a p-tap. With `within`, a `tap_a` shape counts only when its centre lies in a `within` shape (sky130: n-taps in a well holding a PMOS, so a PNP's base contact is not a short). |
| `tie_high_low()` | A supply the intent file declares that reaches a transistor gate: a gate tied straight to a rail instead of through a tie cell. Needs `--intent`. |
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
all refer to nets by those names. One name on two nets the layout does not
join is an open (`lvs.label_conflict`), and a field solve or netlist export of
that name is refused. Two names on one net is a short between them
(`lvs.net_seed_conflict`, reported by every run).

```
connect global psub                                # every psub shape is one net: the substrate
connect via psub_tie [ptap, psub]                  # taps join it like any cut
```

A global layer is one net however many shapes it holds, and a device terminal
can name it (a diode's anode, later a MOS bulk). It is net-only, not a
conductor: it carries no modelled current and no parasitics, so neither it nor
a via into it needs a sheet resistance, and it cannot also be listed in
`connect conductors`.

## Devices

```
device mos ngate model "sky130_fd_pr__nfet_01v8" terminals [poly, diff_active, diff_active]
device resistor rbody model "rpoly" terminals [poly_c, poly_c] sheet 300ohm
device capacitor cmim model "cmim" terminals [met4, met3] area_cap 2fF/um2 fringe_cap 0.2fF/um
```

A device is found wherever its marker layer (`ngate`) has shapes. Its
terminals are the listed layers, in order: gate, source, drain for `mos`;
base, emitter, collector for `bjt`; anode, cathode for `diode`, which LVS
compares as polar (a reversed diode is a mismatch), as it does a capacitor's
two plates. A resistor's two ends may be written either way round.
Kinds: `mos`, `bjt`, `resistor`, `capacitor`, `diode`. The model name is what
LVS compares against your schematic; a schematic resistor, capacitor or
diode card that names no model is the deck's one `device` of its kind. A `mos` row's gate terminal is also where
an `antenna` row's gate connects.

Each terminal needs a shape of its own under the marker, and shapes that
touch or overlap are one shape. A source drawn twice with no drain is not a
transistor with its source and drain shorted: it is no device, and LVS
reports the marker (`lvs.terminal_net`).

A resistor may give its body's resistance per square, `sheet`, and a
capacitor its capacitance per area and per perimeter, `area_cap` and
`fringe_cap`, in the units of a `pex` line. Each is optional, given once,
and only on its own kind. LVS measures every device from what is drawn, and
compares each value a schematic card states under the card's name for it:

| Name | Device | Measured |
|---|---|---|
| `w`, `l` | `mos`, `resistor` | The marker's extent across and along the current, which runs toward the first source or drain (a resistor's first end). Exact for a straight rectangle; a bent resistor body reads its bounding box. |
| `nf` | `mos` | 1: a marker is one channel, and fingers in parallel add up. |
| `area`, `perim` | every kind | The marker's area, less any hole in it, and its perimeter, a hole's edge included. A hole is part of its marker, never a device of its own. A resistor, capacitor or diode card may also write them `A` and `P` (KLayout), or the perimeter `pj` (ngspice). |
| `as`, `ad`, `ps`, `pd` | `mos` | The area and perimeter of the source's and the drain's polygon on its terminal layer, the edge along the channel included. A diffusion between fingers is shared evenly by the transistors it serves, as KLayout shares it, so fingers in parallel add up to it. |
| `ae`, `pe` | `bjt` | The area and perimeter of the emitter's polygon, the second terminal layer's. |
| `r` | `resistor` with `sheet` | `sheet × l / w`. |
| `c` | `capacitor` with `area_cap` or `fringe_cap` | `area_cap × area + fringe_cap × perim`, of the terms given. |

A source, drain or emitter is measured only where it is one polygon that no
other polygon of its layer touches; drawn in pieces, it is not measured.
The terminal layers are the deck's own: list the source and drain diffusion
(for example `diff not poly`) as a `mos`'s second and third terminal, and
the emitter region as a `bjt`'s second, and these are their measures.

A value the deck does not give is not computed, never taken as zero, so a
schematic that states it is reported (`lvs.undeclared_param`). Nothing
measures a capacitor's `w` and `l`.

A `mos` may state when it conducts, for the voltage rules:

```
device mos ngate model "nfet" terminals [poly, diff, diff] on_gate_min 1V
device mos pgate model "pfet" terminals [poly, diff, diff] on_gate_max 0V
```

`on_gate_min 1V` is an n-channel switch: on while its gate can reach 1 V or
more, off when its gate stays below. `on_gate_max 0V` is a p-channel switch:
on while its gate can fall to 0 V or less. This is Calibre PERC's conditional
voltage propagation as its public white paper states it (Siemens 81822,
figure 1). The gate's reach is the range its net can take from the declared
supplies, so a switch turns on in propagation if its gate can reach the
condition at any time. A gate no supply can reach, such as an input to the
cell, may be anything, so its transistor conducts. A transistor gives one of
the two, or neither (it always conducts). When on, a channel passes its full
range: there is no threshold drop.

## Parasitic stack

```
pex met1 thickness 360nm height 1376nm sheet 0.125ohm dielectric 3.9 area_cap 25.8aF/um2 fringe_cap 40.5aF/um
```

One line per conducting layer: thickness, height above the substrate, sheet
resistance per square, the dielectric constant around it, and the area and
fringe capacitance to substrate. Every value is required but the dielectric,
which a process that does not publish one leaves out, and the temperature
coefficients `tc1` and `tc2` (see [Temperature](#temperature)).

Every value must be one a process can have: the thickness positive, a stated
dielectric positive, a temperature coefficient of either sign, the rest zero
or more. A zero means the deck does not
state that value, and a layer whose sheet resistance is not stated is refused
when PEX reads it. A line with no dielectric gives no closed-form coupling and,
above the substrate, a layer the field solve refuses (how `generic_finfet`
says it extracts no capacitance). A negative value, or a dielectric of 0, is
an error at the value, rather than a capacitance or gap that drops out.

A layer at height 0 (a well or a diffusion) is a junction in the substrate:
its `area_cap` and `fringe_cap` are its junction capacitance, which a field
solve (`--quasistatic`) adds in closed form rather than solving, so it needs
no dielectric.

### Temperature

```
temperature 85C nominal 30C
pex met1 thickness 360nm height 1376nm sheet 0.125ohm dielectric 3.9 area_cap 25.8aF/um2 fringe_cap 40.5aF/um tc1 3.179e-3/K tc2 3.094e-7/K2
```

`temperature T nominal T0` says the run is signed off at `T`, and that every
`sheet` is the value at `T0`. Each `pex` row then gives its temperature
coefficients, and its resistance is read at `T` as

    R(T) = R(T0) · (1 + tc1·(T − T0) + tc2·(T − T0)²)

the law of the ngspice resistor model and of the coefficients PDKs publish:
the example is sky130's met1 (`tc1rm1`, `tc2rm1` at `tnom = 30` in
`sky130_fd_pr__model__r+c.model.spice`). Extraction, the power grid and
`lib` all read the resistance at `T`, and `electromigration` and
`reliability` derate to `T`. A deck without a `temperature` reads every
`sheet` as written and derates to 85 °C.

Stated, the temperature needs `tc1` and `tc2` on every `pex` row (write
`tc1 0/K tc2 0/K2` for a resistance that does not vary); without it, no row
may give them. Either coefficient may be negative, but not so far that a
resistance reaches zero at `T`. `lib` extracts once, at `T`, whatever
temperatures its corners name.

Only resistance moves with temperature. Thickness variation from CMP,
current-dependent via resistance and mask-shift (colour) effects need
calibration data no open PDK publishes, and are not modelled.

## Errors

Every problem is reported with its line, column and a marker under the
offending text, and all of them are reported together (up to 50), so you can
fix a deck in one pass:

```
pdks/sky130.deck:41:28: m1.5: enclosure needs a length, got 60 (no unit)
rule m1.5 enclosure(mcon, met1, opposite) >= 60
                                             ^^
```
