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
rule m1.5     enclosure(mcon, met1, adjacent) >= 60nm
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
| capacitance | `aF`, `fF`, `pF` |
| capacitance per area | `aF/um2`, `fF/um2` |
| capacitance per length | `aF/um`, `fF/um` |
| temperature | `K`, or `C` |
| temperature coefficient | `/K` (first order), `/K2` (second order) |
| energy | `eV` |
| thermal conductivity | `W/mK` |
| time | `h` |
| electric field | `V/um`, `V/nm`, `MV/cm` |
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
| `.sized(dx, dy)` | Every shape grown by `dx` left and right and by `dy` above and below, as KLayout's `sized(dx, dy)`. Both negative shrinks. One growing and one shrinking is an error: chain two `sized` for that. |
| `.interacting(L)` | The shapes that touch or overlap a shape on `L`. Sharing only a corner counts. |
| `.not_interacting(L)` | The shapes that do not. |
| `.inside(L)` | The shapes entirely covered by `L`. A shape may touch `L`'s boundary from inside. |
| `.outside(L)` | The shapes sharing no area with `L`. A shape that only touches `L` is outside. `.not_overlapping(L)` is the same. |
| `.overlapping(L)` | The shapes sharing area with `L`, as KLayout's `overlapping`. Touching is not overlapping. |
| `.covering(L)` | The shapes that hold a whole shape of `L`, as KLayout's `covering`. The shape of `L` may touch the holder's boundary from inside. |
| `.not_covering(L)` | The shapes that do not. |
| `.holes()` | Each hole, filled. A hole with an island in it is filled over the island. |
| `.extents()` | The bounding box of each shape. Boxes that overlap stay separate shapes, as in KLayout: `forbidden` reports each, and an operation or a check that merges its layer merges them. |
| `.with_area(bounds)` | The shapes whose area, not counting holes, is within the bounds. |
| `.with_width(bounds)` | The shapes whose narrowest width, as `width` measures it, is within the bounds. The diagonal neck where two shapes overlap at a corner counts, at its exact length: a 70.7 nm neck is `> 70nm` and not `<= 70nm`. |
| `.with_bbox_max(bounds)` | The shapes whose bounding box's longer side is within the bounds: a straight feature's length, as sky130 mf.2 "length of fuse" or IHP Rsil.f "min. RES length", and KLayout's `with_bbox_max`. |
| `.with_bbox_min(bounds)` | The same on the shorter side (`with_bbox_min`). |
| `.with_rect(w x h)` | The shapes with room for an axis-aligned `w` x `h` rectangle, either way round, its edges allowed on theirs: Calibre's `ENCLOSE RECTANGLE` ("select all polygons that can fit an X by Y rectangle", as KLayout's forum states it, thread 2141). Touching shapes count as one. A shape too small for the box anywhere is `forbidden(L.without_rect(w x h))`. Both sides are positive; non-rectilinear shapes are refused, as for `sized`. |
| `.without_rect(w x h)` | The other shapes. |
| `.rectangles()` / `.squares()` | The shapes that are one axis-aligned rectangle with no hole, or one with equal sides, as KLayout's `rectangles` and `squares`. Touching pieces that make one rectangle are one; two rectangles meeting only at a corner are one shape that is none. `forbidden(capm.non_rectangles())` is sky130 capm.7 "only rectangular capacitors" and LEF58 `RECTONLY`. |
| `.non_rectangles()` / `.non_squares()` | The other shapes. |
| `.with_text(T, "pattern")` | The shapes holding a text on layer `T` that matches `pattern`, as IHP picks devices by their text. `*` matches any run of characters and `?` one; everything else matches itself, case included. A text on a shape's edge counts. `T` must be a drawn layer. |
| `.without_text(T, "pattern")` | The shapes holding no such text. |
| `.in_cells("pattern", ...)` | The shapes of a drawn layer placed under a cell whose name matches one of the patterns: the cell the shape is drawn in, or any cell above it, the top included. A pattern is a glob over the whole name, case included: `*` matches any run of characters and `?` one. `[`, `]`, `{`, `}` and `\` are refused, since KLayout reads them as classes, alternatives and escapes. Shapes are taken as drawn, before they merge. This is KLayout's `source.select("-", "+pattern")`, and how a foundry rule written "for cell names ..." or "except inside cell ..." is stated. A maximum name length n is `forbidden(L.in_cells("?…?*"))` with n + 1 `?`; it sees only a cell holding or placing a shape on `L`. At most 64 per deck. |
| `.not_in_cells("pattern", ...)` | The other shapes of the layer, as KLayout's `select("-pattern")`: with `.in_cells` of the same patterns, it splits the layer. |
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
| `.extended(begin: len, end: len, out: len, in: len)` | A box round each edge, as KLayout's `extended`: the edge lengthened by `begin` before its start and `end` past its end, and widened by `out` away from its shape and `in` into it. The result is a polygon layer, one box per edge, not merged. An edge runs with its shape on its left (counter-clockwise round a shape), so `begin` is at the corner it leaves. Every length is 0 or more, and `out` or `in` is above 0. |

A check that takes an edge layer says so (see [Edge checks](#edge-checks)).
Every other check refuses one.

### 45-degree geometry

Layer operations take edges at 45° as well as horizontal and vertical ones;
an edge at any other angle makes the layer's derived layers fail to compute.
Every result keeps its vertices on the grid and its edges at multiples of 45°:

- Where a rising and a falling 45° edge cross between grid points (at a
  half-grid point), the result's vertex there is replaced by the two grid
  points half a diagonal step from it along its edges, joined by a one-unit
  horizontal or vertical edge. A convex corner loses, and a concave corner
  gains, a quarter-unit triangle; two shapes meeting at such a point are
  joined by a one-unit neck. IHP SG13G2 rule 3.1 states the same requirement
  of drawn data ("all features are on a drawing grid"; "design elements,
  which are snapped to grid must not violate any geometries"). KLayout rounds
  such a point to the nearest grid point instead, so the two differ inside
  that one unit square.
- `.sized(len)` grows by the square `len` on each side, as for rectilinear
  shapes: a 45° edge moves `len` in x and in y, which is `len·√2` along its
  normal. KLayout's `sized` moves every edge `len` along its normal, so the
  two differ on 45° edges.
- `.with_length` measures a 45° edge exactly (`k` grid steps long is
  `k·√2`), and `.inside_part` / `.outside_part` end a part cut between grid
  points at the last grid point inside it.
- `.with_width` measures a 45° shape as `width` does (below).

Of the checks, `width`, `notch`, `space`, `area`, `hole_area`,
`edge_length`, `forbidden`, `inside`, `contains` and `enclosure` (every side,
`noncoincident`, `opposite`, `adjacent`) measure 45° shapes; every other check refuses a layer
with a 45° edge. `enclosure` is the Euclidean distance from the inner shape to
its host's boundary, a 45° edge of either included. `noncoincident`,
`opposite` and `adjacent` read the edge pairs the foundries' KLayout decks
check them by (`enclosing` without touching edges, `enclosed` and `enclosing`
by projection), so an inner edge pairs with a host edge at 45° to it as well
as a parallel one; `opposite` and `adjacent` take rectangular inner shapes
(cuts) and refuse one with a 45° edge. `full_width` and an enclosure with
`width:` or `below:` still refuse. `inside` reports the area left outside
rounded up, so half a unit outside reads 1. `width` is the distance between facing edges, measured square to
them, a neck between two inside corners measured corner to corner, 0 at a
corner sharper than 90°, and, for an axis edge and a 45° edge at 135° to each
other (a chamfer and the side across from it), the distance between the parts
of each on the other's inner side, as KLayout's Euclidean `width` measures it
and the foundry decks check it: a box chamfered next to a side shorter than
the limit is too narrow there. Distances to a 45° edge can fall
between whole units and are compared exactly; a reported value is floored.

Wherever a rule takes a layer, it can take a layer expression instead:
`forbidden(licon and poly and (diff or tap))` is the same as declaring that
layer and naming it.

## Rules

```
rule <id> <check>
rule <id> warning <check>        # report as a warning, not an error
```

The id is your name for the rule, and it is how violations are reported. Use
the foundry's rule numbers (`m1.1`, `licon.5a`) so a report reads like the
manual.

A rule written `warning` reports its findings as warnings: they are listed
and counted, but do not fail the run. This is how a foundry's recommended
rules are carried, the ones IHP marks with an `R` suffix (`TM2.bR`), sky130
flags `RR` or `RC`, and ASAP7 gives rule type `R`, beside the required rule
they relax: `rule M1.bR warning space(met1) >= 220nm`. A warning rule that
cannot look at the layout (skipped or refused) still fails the run.

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

`if` reads a block only when a name is bound to `true`, and `if not` only
when it is `false`: a deck switch, flipped where it is bound, as a Calibre
deck's `#DEFINE` and `#IFDEF` or a foundry KLayout deck's run-time variables
(sky130's floating-metal and seal-ring switches) turn rule groups on and off.
A block switched off is not read.

```
let floating_labels = false
if not floating_labels {
    rule x.22 unconnected_pin(met1)
}
```

### Waivers

```
layer waive_m1_1 = gds(255, 1)
waive m1.1 waive_m1_1
```

A waiver is a shape in the layout on a layer the deck names for a rule: a
violation of that rule whose marker lies on a waiver shape (its boundary
included) is waived. It is reported apart, as `waived`, and does not fail
the run; its rule's count drops by one. Because the waiver is geometry, a
waiver drawn inside a cell (an IP block's known exceptions) waives at every
placement of the cell, however it is turned or mirrored, as Calibre
Auto-Waivers' waivers on their own geometry layer do. A rule may have
several waiver layers, and the rule must be one of the deck's: a waiver for
a misspelled rule would waive nothing, so the deck is refused.

### Stages

```
stage gross
rule m1.1 width(met1) >= 140nm
rule m1.2 space(met1) >= 140nm
stage signoff
rule m1.eol eol_space(met1; eol_width: 200nm) >= 170nm
```

A `stage` line starts a stage: the rules written after it, up to the next
`stage` line, are checked together, stages in the order written. Once a
stage finds an error, the rules of every later stage are not checked and
report `skipped`, an earlier stage having found errors: on an early, dirty
design you fix the gross errors first and the report does not bury them
under thousands of fine ones. This is the early run of Calibre
nmDRC-Recon and IC Validator Explorer, with the subset written in the deck
rather than picked by the tool. A staged deck puts every rule in a stage
(no rule before the first `stage` line) and writes each stage's rules
together (a stage name once). A deck with no `stage` line checks every rule.
DRC stops running at its first stage with an error; ERC runs whole and the
later stages' ERC results are withdrawn.

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
| `protrusion_width(L; wide: len) >= len` | A part of a shape narrower than the limit (where no square that wide fits) attached to a part at least `wide` wide (where a `wide` square fits), a corner counting: LEF `PROTRUSIONWIDTH width1 LENGTH 0 WIDTH width2`. Reported once per such part with its narrowest width. A protrusion's length is not read: LEF's positive `LENGTH`, which exempts a long protrusion, is not modelled. |
| `notch(L) >= len` | A gap narrower than the limit between two parts of the same shape. |
| `space(L) >= len` | Two shapes on one layer closer than the limit. |
| `space(A, B) >= len` | A shape on `A` closer than the limit to a shape on `B`. |
| `space(A, B, projection) >= len` | The same, measured only across edges that face each other and overlap in projection (KLayout's `projection` metric): corner to corner is not measured. sky130's own KLayout deck writes lvtn.3b "spacing of lvtn to pfet along the S/D direction" so. Touching or overlapping shapes measure 0. |
| `eol_space(L; eol_width: len) >= len` | Space from an end of line (an edge shorter than `eol_width`) below the limit. |
| `eol_space(L; eol_width: len, within: len, parallel: none, end_to_end: none) >= len` | LEF's end-of-line rule (`SPACING ENDOFLINE eolWidth WITHIN eolWithin`): an end of line is an edge shorter than `eol_width` with both corners convex, and its keep-out reaches the limit straight out from it and `within` past each of its sides (less than). An edge of another shape facing the end inside the keep-out is measured by its depth from the end's line. |
| `eol_space(L; eol_width: len, within: len, parallel: (space: len, within: len, two_edges: bool), end_to_end: len \| none) >= len` | The same, applied to an end only where an edge runs beside its line (LEF `PARALLELEDGE`): at a corner, an edge facing the line's side less than `space` from it, overlapping the stretch from `within` behind the end to the end's `within` past it; `two_edges: true` needs one on both sides (`TWOEDGES`). With `end_to_end`, two ends of line facing each other need that space instead of the limit (LEF58 `ENDTOEND`). |
| `prl_space(L; prl: len) >= len` | Two shapes that run side by side for at least `prl`, closer than the limit. The run is how far their facing edges, at most the limit apart, project onto each other (LEF `PARALLELRUNLENGTH`), with touching shapes merged first: a wire drawn as segments runs its whole length. |
| `corner_space(L) >= len` | Two shapes whose corners are closer than the limit. |
| `corner_space(L; corner_to_corner: bool, except_eol: len \| none) >= len` | LEF58 `CORNERSPACING CONVEXCORNER`: two shapes whose facing convex corners are closer than the limit on both axes (the larger axis gap), or Euclidean with `corner_to_corner: true`. With `except_eol`, a corner of a line end shorter than that, on either shape, is exempt. |
| `wide_space(L; width: len) >= len` | Space below the limit from the part of a shape at least `width` wide (where a `width` square fits), as sky130's huge metal. |
| `wide_space(L; width: len, attached: len) >= len` | The same, also from the rest of the shape within `attached` of its wide part, as sky130 m1.3a "features attached to or extending from huge_met1 for a distance of up to 0.28 µm". |
| `space(L; nets: same) >= len` | Two shapes on the same net closer than the limit, as gf180 NW.2a. Nets are the extracted ones, joined through vias and other layers. `L` must be a conductor. |
| `space(L; nets: different) >= len` | Two shapes on different nets closer than the limit, as gf180 NW.2b. |
| `space(A, B; nets: different) >= len` | The same between a shape on `A` and one on `B`, overlap included, as sky130 nwell.7 "nwell and deep nwell on separate nets". Both layers must be conductors. `nets: same` is refused here: one net's shapes on two layers overlap wherever a cut joins them. |
| `space_table(L; prl: [len, ..], width: [len, ..], space: [[len, ..], ..])` | Two shapes closer than their table cell (see below). |
| `pitch(L, vertical) == len` | Two neighbouring rectangles, one above the other and overlapping across, whose centre lines are not exactly `len` apart, as ASAP7 FIN.S.1 "exact vertical FIN pitch". The neighbours of a rectangle are the nearest ones past it; a missing line between two is a pitch of twice `len`. Every shape on `L` must be a rectangle, or the rule is refused. `pitch(L, horizontal) == len` is the same side by side (GATE.S.1). |
| `span_length(L; x: [len, ..], y: [len, ..])` | A span of a shape, the length of material a horizontal (`x`) or vertical (`y`) line cuts through it, that is not on its list: every length but the last is legal exactly, the last and longer are legal, as LEF58 `SPANLENGTHTABLE`. For a LEF layer with `DIRECTION HORIZONTAL`, `y` is its `SPANLENGTHTABLE` and `x` its `WRONGDIRECTION` one; the other way round for a vertical layer. Reported once per region of the shape where the span stays the same, with the shortest legal span above it as the limit. |
| `two_width_table(L; width: [len, ..], prl: [none \| len, ..], space: [[len, ..], ..])` | Two shapes closer than the cell both their widths select, as a LEF `SPACINGTABLE TWOWIDTHS` (see below). |
| `tip_space_table(L; length: [len, ..], space: [[len, ..], ..])` | Two shapes whose facing edges are closer than the cell the two edges' lengths select: tip to tip, tip to side, side to side (see below). |
| `eol_keep_out(L; eol_width: len, backward: len, side: len, forward: len)` | Another shape inside the keep-out box of an end of line (an edge shorter than `eol_width` with both corners convex): the end widened by `side` each way, from `backward` behind it to `forward` past it, as LEF58 `EOLKEEPOUT`. Touching the box is not inside it. Reported with the area inside. |
| `forbidden_space(L; min: len, max: len, prl: len)` | Two shapes whose facing edges run alongside each other for more than `prl` at a gap from `min` to `max`, both included: a forbidden range, as LEF58 two-wire forbidden spacing. A wider gap is legal, and so is a narrower one, which `space` judges. Edges face each other as in a tip table. |
| `area(L) >= area` | A shape smaller than the limit. |
| `hole_area(L) >= area` | A hole in a shape smaller than the limit. |
| `cheesing(L) <= area` | A shape larger than the limit with no slot in it. |
| `density(L; window: len, step: len) >= frac` | A window, swept in steps across the whole layout, with less coverage than the limit. Use `<=` for a maximum. A window hanging past the edge counts the outside as empty. The whole layout is the extent of the drawn layers: a derived layer, such as one grown past the drawing, does not widen it. |
| `density(L, boundary; window: len, step: len) >= frac` | The same, with the windows tiling the extent of the `boundary` layer (the die outline). |
| `total_area(L) <= area` | More area on `L` in the whole layout than the limit, overlaps counted once and holes not at all: IHP MIM.gR's total MIM area per chip. Reported once, at the centre of the drawn layers' extent. |
| `aspect_ratio(L) <= r` | A shape whose bounding box is more than `r` times as long as it is wide (longer side over shorter, as KLayout's `with_bbox_aspect_ratio`), touching shapes counting as one: sky130 capm.6 and li.2. `r` is a bare number. |
| `origin(L)` | A layer whose shapes' bounding box does not start at the origin: sky130 x.19 "Lower left corner of the seal ring should be at origin", `origin(seal)`. Reported once, at the box's lower-left corner, with its distance from the origin. |
| `count(L) <= n` | More than `n` shapes on `L` in the whole layout, touching shapes counting as one: a per-chip limit, as IHP's npn13G2.bR on the number of npn13G2 emitters. Use `>=` for a minimum; "one seal ring per chip" is `count(seal) <= 1` with `count(seal) >= 1`. Reported once, at the centre of the drawn layers' extent. |
| `region_density(L, R) <= frac` | A shape of `R` inside which `L` covers more than the limit of its area, each shape measured on its own: the pattern density over a device, as sky130 vpp.5a "max pattern density of met3.dg over capacitor.dg". Use `>=` for a minimum (vpp.11). |
| `global_density(L) >= frac` | Coverage of the whole layout (the drawn layers' extent, as for `density`) below the limit. Add a boundary layer, `global_density(L, boundary)`, to measure over the die outline. Use `<=` for a maximum. |
| `critical_area(L; radius: len) <= area` | Too much short-circuit critical area: the area where the centre of a square defect of half-side `radius` makes it touch two shapes of `L` at once, the shapes grown by `radius` and intersected pair by pair. Two parallel lines of length `l`, a gap `s` apart, give `(l + 2·radius)(2·radius − s)`. Shorts only, for one defect size. |
| `density_balance(A, B; window: len, step: len) >= frac` | A window, swept as for `density`, where the lesser of `A`'s and `B`'s coverage over the greater is below the limit: two masks of a multi-patterned layer out of balance (1 is equal coverage, 0 is one mask missing). A window neither covers is skipped. Add a third layer for the die outline. Each mask's own density is `density(A; ..)`. |
| `enclosure(inner, outer) >= len` | An `inner` shape not surrounded by `outer` by the limit on every side, measured to the outer shape's real edges, holes included. |
| `enclosure(inner, outer, opposite) >= len` | An `inner` shape without the limit on both sides of at least one axis (LEF `ENCLOSURE` "on two opposite sides"). Each edge is measured straight out to the outer shape, so an L-shaped inner needs the limit past every vertical edge, or past every horizontal one. LEF `ENCLOSURE o1 o2` is this rule at `o1` plus `enclosure(inner, outer) >= o2`. |
| `enclosure(inner, outer, adjacent) >= len` | An `inner` shape with a corner where neither edge meeting it has the limit, each edge read straight out at that corner (sky130 m1.5 "on one of two adjacent sides", as the foundry's sky130A_mr.drc reads it). Where the outer shape does not step along a rectangle's sides this is `opposite`; where it steps, a side far enclosed at one corner and short at the other is read at each. |
| `enclosure(inner, outer[, opposite]; width: len, below: len) >= len` | Either enclosure, only for an `inner` shape lying on a part of `outer` at least `width` wide and not on a part `below` wide: where a square that wide fits around all of it (LEF `ENCLOSURE ... WIDTH minWidth`). Either bound can be left out. LEF applies the rule with the largest `minWidth` the wire reaches, so write one row per band, each `below` the next one's `width`; a shape on no `outer` falls in the lowest band. GF180 CO.6 "Metal1 (< 0.34 µm) end-of-line overlap" is `enclosure(contact, metal1, opposite; below: 340nm) >= 60nm`. |
| `enclosure(inner, outer, noncoincident) >= len` | An `inner` shape closer than the limit to `outer`'s edge, except where its edges lie on `outer`'s edge, as sky130 lvtn.10 "(exclude coincident edges)": each edge is measured to the parallel `outer` edges facing the same way beyond it, and pairs that touch (coincident edges, a corner on the edge) are not measured. |
| `full_width(inner, outer)` | An `inner` shape that does not span `outer`'s full width along one axis: on one axis, every edge of `inner` must meet `outer`'s edge, as ASAP7 V1.M2.AUX.2 "V1 must exactly be the same width as M2 along the direction perpendicular to the M2 length". Reported with the widest gap on the better axis. An `inner` shape on no `outer` shape is for `inside`. |
| `enclosure(inner, outer) <= len` | An `outer` shape reaching further than the limit from the `inner` shapes it holds, in any direction, corners included (inside their union grown by the limit with square corners), as sky130 npc.5 "Max enclosure of poly overlapping slotted_licon by npcm". Two inner shapes under one outer shape are measured together. An outer shape that holds no inner shape is not checked. Reported on the outer shape with the furthest reach, rounded up. |
| `extension(A, B) >= len` | `A` not extending past `B` by the limit, as poly past diffusion. |
| `bend(A, B)` | `A` turning a corner on `B`: a concave corner of `A` inside `B`'s material, where their shared area turns too, as sky130 poly.11 "No 90 deg turns of poly on diff" (GF180 PL.6, ASAP7 GATE.AUX.1). A stub off a gate is two such corners; a turn on `B`'s edge is none. Each corner is reported where it is. |
| `covers_corner(A, B)` | `A` covering an inner (concave) corner of `B`, so their shared area turns there, as sky130 poly.10 "Poly can't overlap inner corners of diff". |
| `overlap(A, B) >= len` | `A` and `B` overlapping by less than the limit. |
| `tap_distance(well, tap) <= len` | Any point of a well further than the limit from a tap. |
| `off_grid(; pitch: len)` | A vertex of a drawn shape off the manufacturing grid. Derived layers are not checked: they repeat the drawn vertices, and sizing by less than the grid would put on-grid drawing off it. |
| `angle(; allowed: [0deg, 90deg])` | An edge at an angle not in the list (multiples of 45°), on any drawn layer. Derived layers are not checked: they repeat the drawn edges. |
| `angle(L; allowed: [0deg, 90deg])` | The same, on layer `L` only. |
| `interior_angle(L) >= deg` | A corner whose angle inside its shape is under the limit, as IHP 3.1 "shapes with acute angles <87 degree are not allowed": 90 at a rectangle's corner, 270 at an L's inner corner, 45 at a right isosceles triangle's acute corners. Drawn shapes are read as drawn, diagonal ones included; write `interior_angle() >= deg` for every drawn layer. |
| `valid(L)` | A drawn polygon that crosses itself or encloses no area (IHP 3.1 "self-intersecting polygons must be avoided"), named one by one, where every other rule on its layer is refused. Write `valid()` for every drawn layer. |
| `redundant_via(L; within: len) >= count` | A cut with fewer than `count` cuts, itself included, within `within`. |
| `min_cuts(cut, wide, other; width: len) >= count` | A via with fewer than `count` cuts on a part of `wide` wider than `width` (LEF `MINIMUMCUT count WIDTH width`). A via is the cuts joining one `wide` shape to one `other` shape, so `other` is the metal on its far side (`FROMABOVE`, `FROMBELOW`; write both for LEF's default). Add `within: len` to count only cuts closer than that together (LEF `WITHIN`). Each cut of a short via is reported with the count. |
| `via_stack(cut1, cut2, ..) <= count` | A stack of overlapping cuts taller than `count` (LEF `MAXVIASTACK`), the cut layers listed bottom to top: a cut stacks on a cut of the layer before it that it overlaps. The cut at height `count + 1` of each taller stack is reported with the stack's height. Every cut counts as a single-cut via. |
| `via_array_space(L; array: count) >= len` | Cuts in a cluster larger than `array`, closer than the limit. |
| `space(L, center) >= len` | Two cuts whose centres are closer than the limit (LEF `SPACING CENTERTOCENTER`). Cuts are taken as drawn; the centre is the middle of a cut's bounding box. |
| `adjacent_space(L; cuts: count, within: len) >= len` | Two cuts closer than the limit, where either has at least `cuts` other cuts strictly closer than `within` (LEF `SPACING ADJACENTCUTS count WITHIN within`): `cuts: 3` lets a 2x2 array keep tight spacing and holds a 2x3 one. Distances are boundary to boundary. |
| `adjacent_space(L, center; cuts: count, within: len) >= len` | The same, with every distance centre to centre. |
| `keep_out_zone(L; class: s x l, to: s x l \| none, end_side: len, end_forward: len, side_side: len, side_forward: len)` | Another cut inside the keep-out zones of a cut of `class` (`s` x `l` either way round, `s` below `l`), as LEF58 `KEEPOUTZONE CUTCLASS c1 TO c2 ENDEXTENSION endSide endForward SIDEEXTENSION sideSide sideForward` as OpenROAD's router reads it: the side zone is the cut lengthened by `side_forward` at both ends and widened by `side_side`, the end zone lengthened by `end_side` and widened by `end_forward`. With `to`, only cuts of that size count. Touching a zone is not inside it. Reported with the other cut's area inside the zones, once per cut of `class` and intruder. |
| `cut_class_space(L; short: [len, ..], long: [len, ..], space: [[len, ..], ..])` | Two cuts closer than their cell of a cut-class table (LEF58 `SPACINGTABLE` with `CUTCLASS`; see below). |
| `patterning(L; colors: count) >= len` | Shapes that cannot be split into `colors` masks with same-mask shapes at least the limit apart. A shape whose own notch is narrower than the limit counts: on one mask its two sides are too close. |
| `patterning(L, A1, A2, ..; colors: count) >= len` | Pre-coloured shapes whose masks no split can honour. A shape overlapping one on `A1` must take mask 1, on `A2` mask 2, and so on (a LEF/DEF `MASK`); one no anchor touches may take any. With two masks the finding names the two anchored shapes whose chain of conflicts has the wrong parity (an anchor path), or one shape two anchor layers both claim. A layer no split exists for at all is the first form's to report. |
| `forbidden(L)` | Every shape on `L`, reported with its area. Write the forbidden overlap as the layer: `forbidden(licon and poly and (diff or tap))`. On an edge layer, every edge. |
| `contains(outer, inner) >= count` | An `outer` shape holding fewer than `count` `inner` shapes entirely, as sky130 licon.16 "every tap must enclose at least one licon". An inner shape across the outer's edge is not held, and touching inner shapes count as one. |
| `contains(outer, inner) <= count` | An `outer` shape holding more than `count` `inner` shapes, counted the same way, as sky130 rpm.1g "only 1 licon is allowed in xhrpoly_0p35 prec_resistor_terminal". |
| `contains(outer, inner) == count` | An `outer` shape holding any other number of `inner` shapes than `count`. |
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

A two-width table, as LEF `SPACINGTABLE TWOWIDTHS`, where the space two
shapes need depends on the widths of both, not only the wider, and a width
can also ask for a run alongside:

```
rule M2.S two_width_table(met2;
    width: [0nm, 250nm, 1500nm, 3000nm],
    prl:   [none, 0nm, 1500nm, 3000nm],
    space: [[150nm, 200nm, 500nm, 1000nm],
            [200nm, 250nm, 500nm, 1000nm],
            [500nm, 500nm, 600nm, 1000nm],
            [1000nm, 1000nm, 1000nm, 1200nm]])
```

The widths head both the rows and the columns. A width applies to a shape
that is wider than it (exactly 250 nm is not wider than 250 nm) when, if it
has a run, the two shapes run alongside each other for more than that run,
measured as for `space_table`; `none` asks for no run, and the first width is
0 with `none`. A pair needs the cell at the last width that applies to one
shape and the last that applies to the other. A width is measured on the part
of the shape that wide, so a thin tab of a wide plate is held as thin. Widths
and runs never fall, every cell is positive, no cell falls along its row, and
the table is symmetric.

A tip table, as ASAP7 M1.S.1 to M1.S.5, where the space two shapes need
depends on the lengths of the two edges that face each other, so a line end
(a tip) can need more room than a long side:

```
rule M1.S tip_space_table(met1;
    length: [0nm, 24nm, 37nm],
    space:  [[31nm, 31nm, 25nm],
             [31nm, 27nm, 25nm],
             [25nm, 25nm, 18nm]])
```

Two edges of different shapes face each other when they are parallel, each
faces away from its own shape toward the other, and they overlap along their
length; the gap is the distance between them. Edges are whole, with touching
shapes merged first, so a line end drawn as two strips is one end. An edge's
class is the last `length` it reaches, here below 24 nm, 24 to 36 nm, or
37 nm and more, and a pair of facing edges needs the cell at its two classes.
`length` starts at 0 and rises, `space` has one row and one column per class,
and the table is symmetric; it need not rise. Edges that meet only at a
diagonal do not face: `corner_space` measures those.

A cut-class table, as sky130 licon.2 to licon.2d (square licons 170 nm
apart; slotted 0.19 x 2.0 µm licons 350 nm apart end to end, 510 nm
otherwise, and 510 nm from a square licon):

```
rule licon.2 cut_class_space(licon;
    short: [170nm, 190nm],
    long:  [170nm, 2000nm],
    space: [[170nm, 170nm, 510nm, 510nm],
            [170nm, 170nm, 510nm, 510nm],
            [510nm, 510nm, 350nm, 510nm],
            [510nm, 510nm, 510nm, 510nm]])
```

Each class is a cut size, `short` x `long` either way round; a cut of no
class is not checked by this rule. `space` has two rows and two columns per
class, in class order: its END, then its SIDE. Two cuts apart along y face
each other with the sides across y, so a cut faces with its SIDE (a long side)
when it is wider than tall, and otherwise with its END (a square always does);
apart along x, the same with taller than wide. A pair apart along both axes
needs the larger of its two cells, and a pair that touches or overlaps the
largest cell of its classes. Distances are edge to edge. The table must be
symmetric.

### Multi-patterning

A multi-patterned layer is checked by one row per kind of error, so each is
reported under its own id. With the layer `m1`, and its masks drawn or marked
as `m1_c1` and `m1_c2`:

```
rule M1.DP.opp  space(m1) >= 40nm                          # closer than any two masks allow
rule M1.DP.self notch(m1) >= 80nm                          # a shape too close to itself for one mask
rule M1.DP.odd  patterning(m1; colors: 2) >= 80nm          # no split exists (an odd cycle)
rule M1.DP.anc  patterning(m1, m1_c1, m1_c2; colors: 2) >= 80nm   # the pre-coloured shapes cannot be honoured
rule M1.S.same  space(m1 and m1_c1) >= 80nm                # same-mask spacing of coloured shapes
rule M1.S.diff  space(m1 and m1_c1, m1 and m1_c2) >= 40nm  # different-mask spacing
rule M1.ST.ov   overlap(m1_c1, m1_c2) >= 10nm              # a stitch overlaps at least this far
rule M1.ST.sp   space(m1_c1 and m1_c2, m1.not_interacting(m1_c1 and m1_c2)) >= 80nm   # and not near other shapes
rule M1.D.bal   density_balance(m1_c1, m1_c2; window: 10um, step: 5um) >= 0.8   # the masks' coverage in balance
```

These follow the error classes Calibre publishes (minimum opposite-mask
spacing, self-conflict, odd cycle, anchor path and anchor self-conflict),
LEF/DEF's `MASK` and `SAMEMASK`, and the stitch overlap of the
decomposition literature. A trim or cut layer is written with the ordinary
checks, as ASAP7's gate cut: `extension(GCUT, GATE) >= 17nm` and
`forbidden(GCUT.not_interacting(GATE))`.

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
| `antenna(gate, collectors…; max_ratio: n, sidewall: len \| none, diode: layer \| none)` | A gate whose collector-to-gate area ratio is above `max_ratio`. The ratio has one term per etch step the collectors span, each counting only what is connected to the gate when that layer is etched, and the terms are summed (LEF's CAR, IHP's `AreaRatio`). Overlapping shapes count once. A cut is etched with the conductor under it, so listing cuts with the metals accumulates metal and cut damage as one ratio (LEF's `ANTENNACUMROUTINGPLUSCUT`). With `sidewall`, collector area is perimeter times that thickness; a cut always collects by its area. With `diode`, a gate connected to that layer is skipped, left to a row for protected gates (IHP Ant.b and Ant.e). Name the gate as a derived `poly and diffusion` layer. The gate is connected through the layer a `device mos` row names as its gate terminal (`poly`) where it overlaps it; with no such row, through the conductor it lies on, which is the diffusion when a `connect via` joins diffusion and poly directly. |
| `antenna_electrical(gate, collectors…; max_ratio: n, sidewall: len \| none, cut_factor: n, diode: layer \| none, diode_credit: n, diode_bonus: n, area_minus_diode: n, gate_plus_diode: n, diode_reduce: [(area, n), …] \| none, diode_max_ratio: [(area, n), …] \| none, exempt: layer \| none)` | The ratio `antenna` measures, less credit for a protection diode. Each collector layer adds `(factor × area × reduce - area_minus_diode × diode area) / (gate area + gate_plus_diode × diode area)` for the gate's net as that layer is etched (LEF's `ANTENNAAREAMINUSDIFF` and `ANTENNAGATEPLUSDIFF`; gf180's ANT.16 multiplying factor is `gate_plus_diode`, one row per gate oxide), cuts after the conductor they stand on, and the running sum never drops below zero. `factor` is `cut_factor` for a cut (LEF's `ANTENNAAREAFACTOR`), else 1. `reduce` is `diode_reduce` read at the diode area (LEF's `ANTENNAAREADIFFREDUCEPWL`), else 1. A gate is flagged when `ratio - diode_credit × diode area - diode_bonus` is above its limit, the diode area being the `diode` layer's area connected to the gate when the row's highest collector is etched, in µm² (sky130's EGAR; `diode_credit` is its `K`). The limit is `max_ratio`, or with diode area and a `diode_max_ratio` table, the table read at the diode area (LEF's `ANTENNADIFFAREARATIO PWL`). A table is `(area, value)` points with the areas rising, read linearly between points and as the end value beyond them. A gate with no diode area gets no `diode_bonus`. A gate connected to the `exempt` layer when the highest collector is etched is not checked (sky130's .ar.1: nothing connected to a `pAntennaShort` substrate tap). |
| `conditional_tie(region, tap, well, other; within: len, spacing: [len, ..], max_distance: [len, ..])` | A `region` polygon further from a `tap` than its band allows, measured as `missing_tie` measures it. The band comes from `x`, the least distance from an `other` polygon within `within` of the region to a `well` polygon: below the first `spacing` threshold the first `max_distance`, and so on; with no `other` polygon that near, the last. gf180mcu LU.4 is `conditional_tie(pcomp_in_nwell, ntap, nwell, ncomp_outside_nwell; within: 50um, spacing: [1um, 2um], max_distance: [15um, 30um, 50um])`. |
| `density_cmp(L; window: len x len, step: len x len, min: frac \| none, max: frac \| none, max_delta: frac \| none, partial_windows: true \| false, cmp: none \| (target: frac, sensitivity: len, max_delta: len))` | Metal density out of range, a jump between neighbouring windows, or a predicted polish thickness out of range. |
| `electromigration(layers…; max_density: current per width, max_current_per_cut: current, blech_limit: current, reference_temperature: temp, activation_energy: eV, current_exponent: n)` | A wire or cut carrying more current than its rated limit at the operating temperature. Needs `--intent`. |
| `em_rms(layers…; frequency: [freq, …], width: [len, …], density: [[current per width, …], …], max_current_per_cut: current)`, `em_peak(…)` the same | A wire or cut above its RMS (`em_rms`) or peak (`em_peak`) current limit: LEF's `ACCURRENTDENSITY RMS` or `PEAK` table, one `density` row per `frequency` and one cell per `width`, interpolated linearly on both axes (held at the ends) at the wire's width and its net's `frequency_mhz` (needed when the table has more than one frequency), times the width; `max_current_per_cut` per cut. The currents are the grid solved with the intent's `rms_current_ua` or `peak_current_ua` per net in place of its budget. Skipped when no net states that current. Needs `--intent`. |
| `em_current_density(layers…; max_density: current per width, max_current_per_cut: current, narrow: (width: len, current: current) \| none)` | A wire or cut above its instantaneous current limit: `max_density` times the wire's width, or with `narrow`, `current` for a wire at most `width` wide (IHP's IMAX below its JMAX band); `max_current_per_cut` per cut. Needs `--intent`. |
| `ir_drop()` | A node whose voltage drop or overvoltage exceeds its net's stated limit. Needs `--intent`. |
| `dynamic_ir_drop()` | A node whose drop in its net's worst clock cycle, static plus dynamic, exceeds the net's `dynamic` `max_drop_mv`. Every load on the net switches at once, drawing its share of `budget_current_ua` over the cycles it switches in (`toggle_rate`) as a triangular pulse `rise_time_ps` wide, against the net's `decap_pf`; an RC grid, with no inductance. Needs `--intent`. |
| `em_thermal(layers…; max_density: current per width, max_current_per_cut: current, blech_limit: current, reference_temperature: temp, activation_energy: eV, current_exponent: n, thermal_conductivity: W/mK, spreading: n, sigma: n, limit_failure: frac, max_failure: frac)` | As `electromigration`, but each wire is derated at its own temperature, the run's plus its Joule self-heating `I² R t / (K L (W + spreading × t))` (`t` its layer's `pex` height, `K` the dielectric's conductivity), a cut at the hotter metal at its ends; and the chip, whose wires each fail lognormally (`sigma`, `limit_failure` at a wire exactly at its limit), when its chance of any EM failure exceeds `max_failure`. Needs `--intent`. |
| `p2p_resistance(; max: resistance)` | Two points on one net further apart in resistance than the limit. |
| `reliability(; required_lifetime: h, reference_lifetime: h, reference_stress: voltage, stress_exponent: n, reference_temperature: temp, activation_energy: eV, max_abs_voltage: voltage, duty_cycle: frac)` | A supply-grid node whose voltage stress predicts a lifetime below `required_lifetime` (inverse power law in voltage times Arrhenius in temperature), or whose voltage exceeds `max_abs_voltage`. It reads the solved supply grid, not individual devices. Needs `--intent`. |
| `forward_diode(marker; models: models)` | A diode of `models` whose anode the declared supplies can raise above its cathode (forward-biased in some state) and whose marker no one `marker` polygon covers (gf180mcu §14.3.3's Latchup_MK). Check the rings round the marked diodes with `guard_ring`. Needs `--intent`. |
| `guard_ring(target, ring; max_space: len \| none, min_width: len \| none, pad: layer \| none, near: layer \| none, within: len \| none, clear: layer \| none)` | A `target` polygon that lies in no hole of the merged `ring` layer (no closed ring surrounds it); with `max_space`, one whose ring's inner edge is further than that from it on some side (box to box); with `min_width`, a surrounding ring narrower than that. With `pad`, only targets on a net that holds a `pad` polygon count (a diffusion directly connected to an I/O pad); with `near` and `within`, only targets within that distance of a `near` polygon (gf180mcu LU.5: a native device within 50 um of an n-well). With `clear`, a target whose ring's hole holds area of the `clear` layer outside the target (LU.5: "No other NCOMP, NWELL in between the NAT and PCOMP guard ring"). |
| `guard_ring_bias(ring; power: true \| false)` | A polygon of `ring` (a guard ring or tap, on a conducting layer) not on the supply its type needs: with `power: true` (an n-type ring) a declared power supply held at the highest voltage of any declared supply, with `power: false` (a p-type ring) a declared ground. Needs `--intent`. |
| `hv_domain(; max_delta: voltage, isolation: layer \| none)` | A device whose terminals reach supply domains more than `max_delta` apart, directly or through other devices' channels. Needs `--intent`. |
| `hv_tag(L, tag; voltage: v)` | A shape of the conductor `L` (touching shapes as one) whose net can reach `voltage` or more, not entirely inside `tag`, reported with the area left outside: sky130 hv.X.1 "high voltage source/drain regions must be tagged" and hvnwell.11. Anything joined to a high-voltage net through a conducting device can reach its voltage, so it is a high-voltage feature too (hv.X.4). Needs `--intent`. |
| `undriven_gate()` | A net with a transistor gate on it that a supply reaches with every supply on, but none reaches in one of the intent's power states: the gate floats there, as the output of a tristate buffer whose enable is held low. Needs `--intent` with `states` (see [usage.md](usage.md#design-intent)). |
| `missing_isolation(; isolation: models \| none)` | A transistor, not of an `isolation` model, whose gate floats in one of the intent's power states (as for `undriven_gate`) while a power supply still reaches its source or drain there: a powered input left floating by a switched-off domain or a disabled driver, which leaks. Needs `--intent` with `states`. |
| `mixed_tag(L, tag)` | A shape of the conductor `L` (touching shapes as one) that shares no area with `tag`, on a net that also holds a shape that does: sky130 hvnwell.10, a low-voltage n-well on the net of a high-voltage one (`mixed_tag(nwell, hvi)`). Nets joined through a resistor count as one net, as hvnwell.10 asks. |
| `esd_latchup(pad, guard_ring; min_guard_ring_width: len, max_tap_distance: len, clamps: models)` | A guard ring too narrow or too far from a supply tap, and a pad net short of a clamp path (as `esd_topological`). Needs `--intent`. |
| `esd_topological(pad; clamps: models)` | A pad net with no path through `clamps` devices to both a power and a ground supply. The path is a clamp from the pad to a supply, then any rail clamps between supplies. A diode the declared supplies forward-bias (anode held above cathode, a pad sitting between ground and every power supply) is no clamp. Needs `--intent`. |
| `esd_cross_domain(; diodes: models, local: models \| none, resistors: models \| none, min_series: resistance \| none, max_ground_resistance: resistance \| none, coupling_resistance: resistance \| none)` | A receiver, a transistor whose gate a power domain reaches that reaches neither end of its channel, whose driver's ground and its own are not coupled by anti-parallel `diodes` pairs (as `esd_ground_coupling` couples grounds): TR18-01 check 5.1.3. With `local`, also a receiver with no device of those models from its gate's net to a ground of its own domain (the local clamp a charged-device discharge needs at the interface). Needs `--intent`. With `min_series`, a receiver whose effective series resistance from its driving nets (through the `resistors` devices) is below that; with `max_ground_resistance` (and `coupling_resistance`, each coupling diode's on-resistance), a driver/receiver pair whose ground resistance (a unit current from the driver's ground attach to the receiver's, through both grounds and their coupling diodes) is above it. |
| `esd_exposed(pad; clamps: models, resistors: models \| none, rated: models \| none, min_series: resistance \| none)` | A transistor whose gate is on a pad net, or behind `resistors` from one, and whose gate's net has no path through `clamps` to both a power and a ground supply (as `esd_topological` walks it: the primary clamps at the pad, local clamps behind a resistor); and a transistor with its source or drain on a pad net that is neither `rated` (ESD-rated, gf180mcu's ESD_MK) nor a clamp. Needs `--intent`. With `min_series`, an exposed gate whose effective series resistance from the pad (through the `resistors` devices, each `sheet × l / w`) is below that: the secondary stage. |
| `esd_ground_coupling(; diodes: models)` | A declared ground supply that no chain of anti-parallel diode pairs of the `diodes` models (one diode each way between two grounds) joins to the lowest-numbered ground: a ground-to-ground pin pair with no ESD path. Needs `--intent`. |
| `esd_parasitic(pad, diffusion; min_spacing: len)` | A `diffusion` polygon on a pad net (a net holding a `pad` polygon) closer than `min_spacing` to a `diffusion` polygon of another net: a parasitic bipolar or field device the pad's stress can conduct through. The spacing is a foundry's, under NDA; the deck states it. |
| `esd_path(pad[, source]; clamps: models \| none, current: current, clamp_resistance: resistance, max_resistance: resistance \| none, clamp_it2: current per width \| none, max_density: current per width \| none, max_current_per_cut: current \| none, max_voltage: voltage \| none, min_width: len \| none, clamp_voltage: voltage \| none)` | A discharge path that cannot carry a forced current. `current` (1.33A is a 2 kV HBM zap) is forced in at each `pad` polygon (with `source`, each `source` polygon instead: a guard ring under JESD78's ±100mA injection, written with `clamps: none`) and out at every declared supply its net reaches through `clamps` (as `esd_topological` walks them), its own net included when it is a supply: out at that supply's own `pad` polygons, held at 0 V, or with none at its feed point (the centre of its highest, then widest, shape). Each clamp is `clamp_resistance` between its nets, so parallel clamps share the current. Flags a pair whose resistance, the source's voltage over `current`, is above `max_resistance`, or whose source rises above `max_voltage` (the failure voltage of what it reaches, less a clamp's holding voltage, which is not modelled); a clamp whose share of the current is above `clamp_it2` (its It2 per unit size, such as gf180mcu's mA/um in §14.5) times its size, a transistor's width or any other device's perimeter; and a wire carrying more than `max_density` times its width, or a via cut more than `max_current_per_cut`, of the pulse. Needs `--intent`. With `min_width`, a wire segment carrying the stress current narrower than that (the minimum ESD metal width). With `clamp_voltage`, each conducting clamp also holds that voltage (a diode's turn-on, a snapback clamp's holding voltage), and `max_voltage` reads the pin voltage with it. |
| `esd_pin_pair(pad; clamps: models, current: current, clamp_resistance: resistance, max_resistance: resistance)` | Two signal pins (nets holding a `pad` polygon, supplies aside) that share a supply through their clamps, whose path resistance under `current` forced from each pin of one to the other's pins (held at 0 V), through every net either reaches and each clamp at `clamp_resistance`, is above `max_resistance`: the pin-to-pin P2P check. Needs intent. |
| `esd_clamp_resistance(pad; clamps: models, max_resistance: resistance)` | A pad and a clamp of a listed model on its net whose interconnect resistance, a unit current forced from the pad to the clamp's attach point, is above `max_resistance`: a clamp too far from its pad (Siemens's pin-to-clamp check). |
| `floating_gate(; labels_are_ports: bool)` | A net that only connects to gates. With `labels_are_ports: true`, a labelled net is a block input driven from outside the cell and is skipped. |
| `fanout(; max: count)` | A net driving more than `max` transistor gates. |
| `supply_path(; both: bool)` | A net whose path (nets joined through MOS source and drain pins and resistor pins, ending at the intent's supplies) reaches no supply; with `both: true`, one that misses power or misses ground. Calibre `ERC PATHCHK`'s check, as Mentor's PERC patent defines paths. Needs intent. |
| `power_switch(; models: models)` | A transistor of a listed model (a power switch) whose channel does not join an always-on supply to a switched one of the same role (a supply is switched when a declared power state turns it off), or whose gate no supply reaches in some declared power state (its control is not on an always-on path). Needs intent with power states. |
| `matching(group; tolerance: len)` | In each `group` polygon (the MOS transistors whose marker centre lies in it): a unit of another model, width or length than the first (gf180mcu MP.1, MP.2a), a unit whose channel runs across the first's (MP.7), and a device (units sharing model and nets) whose area-weighted marker centroid lies more than `tolerance` from the first device's on either axis (common centroid). |
| `floating_supply()` | A piece of a declared supply (its label on a net cut off from the rest) other than the piece holding the supply's feed point, its highest then widest shape: OpenROAD `check_power_grid`'s unconnected shapes and instance pins. Needs intent. |
| `combinational_loop()` | A cycle of channel-connected components (nets joined through MOS source and drain pins, never through a supply), each driving the next through a transistor gate: Yosys `check`'s logic loop at transistor level. Latches, keepers, SRAM cells and diode-connected transistors are loops by this definition. Needs intent. |
| `gate_path(; ground: bool, max_devices: count)` | A transistor gate whose shortest path to a ground (`ground: false`: to a power supply), through MOS source and drain pins and resistor pins, passes more than `max_devices` devices, or that has none. Needs intent. |
| `floating_well(well, tap)` | A well with no tap in it. |
| `latchup_victim(aggressor, region, tap; within: len, max_distance: len, pad: layer \| none, bias: layer \| none, forward: above \| below \| none)` | A `region` polygon within `within` of an `aggressor` polygon (with `pad`, only an aggressor on a net that holds a `pad` polygon: a diffusion connected to an I/O pad) that has a point further than `max_distance` from a `tap`, measured as `missing_tie` measures it. gf180mcu IO.1 (b) is `latchup_victim(ncomp, pcomp_in_nwell, ntap; within: 15um, max_distance: 2um, pad: pad)`. With `bias` and `forward`, only an aggressor whose net the intent's voltages can forward-bias against the `bias` polygon it lies in (`above`: rise above that polygon's lowest voltage, a P+ in an N-well; `below`: fall below its highest, an N+ in the substrate). |
| `missing_tie(region, tap; max_distance: len)` | A point of a `region` shape (a device polarity's active area, say) further than `max_distance` from the nearest `tap` edge. |
| `multiple_drivers(; max: count)` | A net driven by more than `max` separate drivers. A driver is a path through transistor channels from the net to a supply the intent file declares; networks that share a gate net (an inverter, a NAND's pull-up and pull-down) are one driver, and a pass gate that reaches no supply drives nothing by itself. Which end of a channel is the source does not matter. Needs `--intent`. |
| `soft_connection(layers…)` | A net held together only through the listed high-resistance layers. |
| `supply_short(tap_a, tap_b[, within])` | A net that touches both kinds of tap, such as an n-tap and a p-tap. With `within`, a `tap_a` shape counts only when its centre lies in a `within` shape (sky130: n-taps in a well holding a PMOS, so a PNP's base contact is not a short). |
| `tie_area(region, contact, channel; min_ratio: frac)` | A figure of the merged `region` (a well, or a guard ring) in which the area of `contact` (tap contacts) is less than `min_ratio` of the area of `channel` (what injects substrate current: the gates; for a guard ring, the ring itself). Only what lies inside the figure counts, overlaps once. A figure with no channel is not checked. |
| `tie_high_low()` | A supply the intent file declares that reaches a transistor gate: a gate tied straight to a rail instead of through a tie cell. Needs `--intent`. |
| `unconnected_pin(layers…)` | A shape on the listed layers that reaches no device. |
| `gate_oxide(; models: models, max: voltage)` | A device of those models whose gate can differ from its source, drain or bulk by more than `max`. Needs `--intent`. |
| `drain_source(; models: models, max: voltage)` | A device of those models whose drain can differ from its source by more than `max`. Needs `--intent`. |
| `well_bias(; pmos: models \| none, nmos: models \| none)` | A `pmos` device whose well can sit below its source or drain, or an `nmos` device whose substrate can sit above them. Needs `--intent`. |
| `missing_level_shifter(; shifters: models \| none)` | A transistor whose gate is driven from a power domain its source and drain are not in, unless its model is one of `shifters`. Needs `--intent`. |
| `domain_crossing()` | A device whose source-to-drain path joins two power domains. Needs `--intent`. |
| `dielectric_field(L; max_field: f)` | Two shapes on `L` on different nets whose worst-case voltage apart, over their gap, exceeds `max_field`: the gap is below `ΔV / max_field`. Reported as the gap against that limit, rounded up to the grid. Needs `--intent`. |
| `dielectric_field(A, B; max_field: f)` | The same between a shape on `A` and one on `B`, through the dielectric between the two layers: the separation is `sqrt(gap² + t²)`, `t` the upper layer's `pex` height less the lower layer's height and thickness, so both need a `pex` row. A pair whose voltage `t` alone holds needs no gap. |
| `voltage_space(L; voltage: [v, ..], space: [len, ..])` | Two shapes on `L` on different nets closer than the space the voltage between their nets needs (see below). Needs `--intent`. |
| `voltage_space(A, B; voltage: [v, ..], space: [len, ..])` | The same between a shape on `A` and one on `B`, overlap included. |

A voltage table, as LEF `LEF58_VOLTAGESPACING`:

```
rule m1.vs voltage_space(met1; voltage: [0V, 3.3V, 5V], space: [140nm, 300nm, 600nm])
```

From each voltage up, two shapes on different nets need the space in the same
place in `space`: here 140 nm below 3.3 V, 300 nm from 3.3 V, and 600 nm from
5 V. The voltage between two nets is the worst case of the ranges the intent's
supplies give them: the highest one can reach minus the lowest the other can.
A difference exactly at a step's voltage needs that step's space, and a gap
exactly at the space passes. A pair whose difference is below the first
voltage needs nothing from the row, and a pair with a net no supply reaches is
not checked. Voltages start at 0 V or more and rise, spaces never fall, and
there is one space per voltage. Like `space(L; nets: ..)`, the layers must be
conductors.

## Connectivity

```
connect conductors [diff_active, poly, li, met1]   # layers that carry signal
connect touch_within_layer                         # shapes that touch on one layer are one net
connect via mcon [li, met1]                        # a cut joins the two layers it overlaps
connect label met1_label names met1                # text on met1_label names the met1 net under it
```

Name your nets with text labels in the layout. LVS, SPEF and the intent file
all refer to nets by those names. One name on two nets the layout does not
join is an open (`lvs.label_conflict`; a warning for a must-connect name, see
[LVS controls](#lvs-controls)), and a field solve or netlist export of
that name is refused. Two names on one net is a short between them
(`lvs.net_seed_conflict`, reported by every run), and where the short runs
follows as `lvs.short_path`: the fewest shapes joining the two labelled
ones, one row per step from shape to shape (a via joins the shapes it
lands on and is no step itself).

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

## LVS controls

```
lvs tolerance "nfet" w relative 1%
lvs tolerance "nfet" l relative 0.5% absolute 5nm
lvs tolerance "rpoly" r absolute 10ohm
lvs ignore_parameter "nfet" as
lvs asymmetric "nfet_ldmos"
lvs permute "cmim" top bottom
lvs ignore "sky130_fd_pr__decap"
lvs ignore_shorted "nfet"
lvs ports_by_name
lvs range "nfet" w >= 420nm <= 100um
lvs topology relaxed
lvs connect_implicit "VDD*"
lvs connect_explicit "VSS" "GND"
```

An `lvs` statement changes how LVS compares the devices of one model, which
a `device` statement must declare.

**`lvs tolerance "model" param relative r absolute a`** sets how far apart
one parameter may be on the layout and the schematic and still agree:
`|a - b| <= absolute + relative × max(|a|, |b|)`. Give `relative`,
`absolute`, or both; the parts add, as in KLayout's `tolerance`. The row
replaces the default for that parameter of that model, 2 % of the larger
value, so a part it leaves out is zero: `absolute 10ohm` alone allows 10
ohms and nothing relative. `relative` is a fraction from 0 to 1, or a
percentage. `absolute` is written in the parameter's unit: a length for
`w`, `l`, `ps`, `pd`, `pe` and `perim`, an area for `area`, `as`, `ad` and
`ae`, a resistance for `r`, a capacitance (`aF`, `fF`, `pF`) for `c`, a
bare count for `m` and `nf`; any other parameter takes a relative
tolerance only. A parameter has at most one row per model.

**`lvs ignore_parameter "model" param`** leaves a parameter out of the
comparison for one model, as KLayout's `ignore_parameter` and Netgen's
`property ... remove` do: it is dropped from both sides before devices are
merged, so it is never compared and never stops a merge, whatever the
schematic cards state. `m` counts devices and cannot be ignored, and an
ignored parameter cannot also have a tolerance.

**`lvs asymmetric "model"`** declares a transistor whose source and drain
are not interchangeable, such as an LDMOS (KLayout's DMOS devices): its
source only ever pairs with a schematic source and its drain with a drain,
where any other transistor's two ends trade places freely. Such transistors
merge in parallel only source on source and drain on drain, and never in
series, so a drawn stack of them does not match one long schematic device.
The model must be a `mos` device.

**`lvs permute "model" pin pin`** makes two pins of the model's devices
interchangeable, as Netgen's `permute` and KLayout's `equivalent_pins` do:
a symmetric capacitor's plates, say, or a bipolar whose emitter and
collector may be wired either way. Pins are named as Netgen names them:

| Kind | Pins |
|---|---|
| `mos` | `gate`, `source`, `drain`, `bulk` |
| `bjt` | `base`, `emitter`, `collector` |
| `resistor` | `end_a`, `end_b` |
| `capacitor` | `top`, `bottom` |
| `diode` | `anode`, `cathode` |

Pins already interchangeable stay so (a transistor's source and drain, a
resistor's ends), and permutations chain: permuting `gate` with `source`
makes all three of gate, source and drain interchangeable. Devices whose
interchangeable pins are other than a transistor's source and drain merge
in parallel either way round, and never in series. An asymmetric
transistor's source and drain cannot be permuted.

**`lvs ignore "model"`** leaves every device of the model out of LVS on
both sides, as Netgen's `ignore class` and KLayout's `same_device_classes`
with `nil` do: fill, decap or tap cells that one side draws and the other
does not state. A net that only those devices touched is then left out
too, unless it is a schematic port or carries a layout label, which must
still pair. The model need not be a `device` of the deck, since a
schematic may hold devices the layout has no recogniser for. The layout's
own checks (`lvs.floating_net` and the others) still see the devices.

**`lvs ports_by_name`** holds each port of the schematic's top cell to the
layout net its name labels, as KLayout's `flag_missing_ports` does, so
swapped pad labels or a missing label are reported (`lvs.unpaired_net`)
rather than matched by structure. Without it, names only break ties between
nets nothing else tells apart, and are never compared.

**`lvs range "model" param >= min <= max`** holds every layout device of
the model to bounds on what is drawn, as a foundry states each device's
legal sizes: `w`, `l`, `perim`, `ps`, `pd` and `pe` take lengths, `area`,
`as`, `ad` and `ae` areas, and `nf` a count, measured as the table in
[Devices](#devices) says. Give `>=`, `<=` or both; a value at a bound is
legal. A device out of range is reported as `lvs.param_range` on its
marker; one whose parameter could not be measured (a source drawn in
pieces) makes the row refused rather than passed. The row exists only in
a deck that states a range, and runs with LVS.

**`lvs topology relaxed`** lets parallel passives match by value, as
Netgen's `property topology relaxed` does: a resistor, capacitor, diode or
bipolar whose schematic states its value (`r`, `c`, `area`, `ae`) merges
with others of its model on the same nets into one of the combined value,
resistances harmonically (two of 200 ohm are one of 100) and the rest by
adding (two of 0.5 fF are one of 1 fF); a resistor's `w`, and `area`,
`perim` and `pe`, add along. A card's `m` folds into the value first, so
`c=0.5f m=2` is `c=1f`. One that states no value keeps its count. `lvs
topology strict`, the default, never combines values: two capacitors are
one of the same value with `m=2`. Passives never merge in series either
way.

**`lvs connect_implicit "pattern"`** declares must-connect nets, as
KLayout's `connect_implicit` does: layout nets whose label matches the
pattern (`*` any run of characters, `?` one) are one net for the comparison
with every other net of that label, as rails that are connected only above
this layout are. **`lvs connect_explicit "a" "b" ...`** joins the nets
labelled with any of the names. The layout keeps its open, and
`lvs.label_conflict` still reports it, as a warning rather than an error,
as KLayout warns for a top cell's must-connect nets.

**`lvs ignore_shorted "model"`** leaves out only the model's dummies: each
device whose every terminal is on one net, as Netgen's `ignore shorted`
does. The terminals counted are those LVS compares, so where the deck
extracts no bulk, a transistor with its gate, source and drain on one net
is a dummy whatever its schematic bulk is.

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

The dielectrics make a stratified stack for the field solve: each line's
dielectric fills the stack from its `height` up to the next line's height
(the dielectric the layer sits in, up to the next layer), the lowest line's
reaching down to the substrate and the highest line's up without end. Two
lines at one height must state the same dielectric, or the field solve is
refused naming the layer. Where the dielectric changes with height, the
field solve meshes that interface and solves the polarisation on it; a
stack of one dielectric has none.

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

### Process corners

```
corner cmax met1 thickness 396nm sheet 0.11ohm area_cap 28.4aF/um2 fringe_cap 44.6aF/um
corner cmin met1 thickness 324nm sheet 0.14ohm
```

A process corner (StarRC's and Calibre's word; OpenROAD's extractor calls
them process corners too) is the stack at the edge of the process window.
A `corner` line gives some of one layer's `pex` values at a named corner,
in the keys and units of a `pex` line and within the same bounds; every
value it does not give is the nominal row's. A corner names each layer at
most once, states at least one value, and varies only a layer that has a
`pex` line. `pex` extracts the nominal stack and every corner, the same
nets the same way (`--quasistatic` too), and SPEF writes each value as the
`min:typ:max` triplet of IEEE 1481: the smallest value at any corner or the
nominal, the nominal, and the largest. DSPF, which has no triplets, is the
nominal stack's.

Every corner is at the deck's one `temperature`. A corner's `sheet`, like a
row's, is the value at the nominal temperature, and is read at the operating
one by the corner line's `tc1` and `tc2` if it gives them (both, or
neither), else by the row's.

### Extraction type

```
extraction rcc coupling_threshold 0.1fF
```

Which parasitics `pex` writes, at most one line. The types are Calibre's:

| Type | Writes |
|---|---|
| `rcc` | resistance, capacitance to ground and coupling capacitance: everything (the default) |
| `rc` | resistance and capacitance to ground; every coupling is grounded |
| `r` | resistance only, no capacitance |
| `cc` | capacitance only, one node per net, with the coupling between nets ("C+CC") |
| `c` | capacitance to ground only, one node per net, every coupling grounded |

A field-solved net's inductance and mutual inductance stay wherever its
resistance does. To ground a coupling capacitance is to put the same
capacitance from each of its two nets to ground, so every net keeps its total
capacitance. `coupling_threshold` grounds every coupling below it, as
OpenROAD's extractor does (`extract_parasitics -coupling_threshold`); it is
legal only with a type that keeps coupling (`cc`, `rcc`), and zero or more.
Without an `extraction` line the output is `rcc` with nothing grounded.

### Metal fill

```
layer met1_fill = gds(68, 28)
connect conductors [met1, met1_fill, ...]
pex met1_fill thickness 360nm height 1376nm sheet 0.125ohm dielectric 3.9 area_cap 25.8aF/um2 fringe_cap 40.5aF/um
pex_fill met1_fill floating
```

`pex_fill <layer> floating|grounded|ignored` says how PEX treats metal
fill: a net drawn only on that conductor layer is a fill piece, not a
signal. `floating` leaves each piece floating, so a net's coupling through
it is in series with the piece's other capacitances (two nets each coupled
to a piece by `c₁` and `c₂`, the piece to ground by `c_g`, couple by
`c₁c₂ / (c₁ + c₂ + c_g)`); pieces coupled to each other are eliminated
together. `grounded` ties each piece to ground, so a net's coupling to it
is capacitance to ground. `ignored` leaves the fill out. Either way the
fill's own nets are gone from the output. The layer must be a conductor
with a `pex` line, and each layer is stated once. Which treatment a
foundry signs off with is its own; no open deck states one.

### Through-silicon vias

```
connect via tsv [met1, backside_metal]
pex tsv thickness 100nm height 0nm sheet 0.02ohm area_cap 0aF/um2 fringe_cap 0aF/um
pex_tsv tsv length 50um liner 200nm liner_k 3.9
```

`pex_tsv <cut layer> length <l> liner <t> liner_k <k>` says a via cut
layer is a through-silicon via: each cut is a copper cylinder through the
silicon, of the radius of the circle of its drawn area, inside an oxide
liner. PEX adds the liner's capacitance to the via's net, `2π ε₀ k l /
ln((r + t) / r)` (Katti et al., IEEE TED 2010), and its resistance is the
`pex` row's per cut. All three values are required and positive; the
layer must be a `connect via` cut layer, stated once. No open PDK has a
TSV, so the values are the deck's to state.

### Device-region capacitance

```
pex_device "sky130_fd_pr__nfet_01v8" gate_contact_cap 0.3aF/um gate_diffusion_cap 0.2aF/um
```

`pex_device "<model>" gate_contact_cap <c> gate_diffusion_cap <c>` gives a
MOS model's capacitance inside the transistor that its SPICE model leaves
to extraction: from the gate to the source/drain contact, and from the
gate to the diffusion beside it, each per µm of gate width. PEX adds
`(gate_contact_cap + gate_diffusion_cap) · W` from the gate's net to the
source's and again to the drain's (a net the gate is on gets nothing).
Both values are required; they come from the foundry's device
cross-section, which no open PDK publishes. The model must be a
`device mos` model, stated once.

## Errors

Every problem is reported with its line, column and a marker under the
offending text, and all of them are reported together (up to 50), so you can
fix a deck in one pass:

```
pdks/sky130.deck:41:28: m1.5: enclosure needs a length, got 60 (no unit)
rule m1.5 enclosure(mcon, met1, adjacent) >= 60
                                             ^^
```
