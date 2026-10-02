# What GPurify cannot check yet

GPurify has not been proven against foundry signoff on production silicon. Do
not tape out on its verdict alone. This page lists what it misses, so a clean
report can be read for what it is.

## Geometry

Layouts must be rectilinear. A shape with a 45° edge is refused, so a design
with diagonal routing cannot be checked at all.

## Rules that can pass a layout signoff would flag

These rule kinds exist but measure less than a foundry deck does. A clean
result from them is weaker than it looks.

| Check | What it misses |
|---|---|
| `enclosure(inner, outer, opposite)` | An inner shape that is not a rectangle is held to the every-side limit instead. |
| `extension`, `overlap` | Measure bounding boxes, so an L-shaped shape can pass. |
| `enclosure(E, L)` on an edge layer | Measures straight out from each edge, so a gap in `L` diagonally off a corner of the shape is not seen. Pair it with the shape `enclosure` where the corner matters. |
| `antenna_electrical` | A row with a diode and a non-zero `diode_credit` is refused: the unit of the credit is not settled. |
| `esd_topological`, `esd_latchup` | Only checks that a clamp path exists. The resistance and current capacity of the path are not checked, and a clamp is any device of a listed model, however it is wired. |
| `gate_oxide`, `drain_source`, `well_bias`, `missing_level_shifter`, `domain_crossing` | A net's voltage range is the span of every supply it connects to through a device channel, ignoring threshold drops, switching and power-down, so these rules can over-report. A net that reaches no supply that way, such as a primary input with no ESD diode, is not checked, and neither is a device whose terminals sit on such nets. |

## Checks that do not exist yet

- Derived layers have no selection by net, angle or shape class
  (rectangles, squares), no `covering`/`overlapping`, and `sized` grows both
  axes by the same amount.
- Edge layers cannot be extended, so sky130 difftap.6 "diff and tap are not
  allowed to extend beyond their abutting edge" cannot be written.
- Spacing that depends on the voltage between two nets.
- A way to state the voltage or domain of an input signal in the intent file,
  and checks for inputs driven from a powered-down domain.

## Power grid

- Each supply net is fed from one point: the centre of its highest, then
  widest, shape. A rail fed from several pads reads more drop and more current
  near that point than it really has.
- A net's current budget is shared equally among the devices on it, so one
  device that draws more than its share reads cooler than it is.
- `electromigration` and `reliability` use one temperature for the whole run,
  85 °C, with no self-heating.

## Shipped decks

Each deck in `pdks/` names, in its header, the rule manual and open decks its
numbers come from, pinned to a release or commit. Rule ids are the foundry's.
None has been compared against foundry signoff results.

- Rules that need a check the language does not have yet are written out,
  commented, near the end of each deck with the reason: net spacing between
  two layers or on wells (no deck connects wells as nets), rules that depend
  on direction, shape-class and exact-count rules, gate-length rules, and
  maximum areas. Each deck also lists the manual rules it leaves out, and why.
- Only sky130 connects wells as nets: the p-substrate (`connect global
  psub`), each n-well through its n-taps, and each isolated p-well in deep
  n-well, so its transistors have a bulk terminal and it carries
  `well_bias`. Its pd2nw diodes and bipolars still have no recogniser. The
  other decks' transistors have no bulk terminal and no `well_bias`. The
  substrate carries no modelled current: a supply reached only through it is
  an island to the power grid, and a field solve refuses a net that holds it.
- No deck carries `esd_latchup`: none of the manuals states a pad guard-ring
  width and tap distance in the form the rule takes.
- `gate_oxide` and `drain_source` use the operating voltages the PDK
  documents (sky130's model limits, the nominal supplies for gf180mcu and
  IHP), not an absolute maximum rating.
- sky130: maximum metal density (met1-met4, 70% in 700um windows) is the
  standard-cell tech LEF's router limit, not a manual rule, so it is an ERC
  warning over whole windows, not a DRC error.
- sky130: the periphery rules also apply inside SRAM cores (`areaid.ce`).
  The implant-enclosure rules nsd/psd.5a and 5b on diffusion and taps that
  butt each other are measured straight out from each edge (see
  `enclosure(E, L)` above); nsd/psd.7 is checked only on shapes that butt
  nothing. poly.4 measures corner to corner
  where the manual measures parallel edges only, so it can over-report, and
  covers only poly that touches no diffusion.
- IHP: parasitic area capacitance other than Metal1 is computed from the
  documented layer heights and dielectric constants, and fringe capacitance
  is zero. A gate with an antenna diode is held to the no-diode limit.
- `generic_finfet` is ASAP7, a predictive process no fab builds. It
  recognises no transistors and extracts no capacitance: the manual gives no
  resistance for the gate and local-interconnect layers and no capacitance at
  all. Its metal heights are stacked from the manual's widths and the 2:1
  aspect ratio, not from a published cross-section.

## Test coverage

`ir_drop`, `electromigration` and `reliability` are checked against numbers
worked out by hand from Ohm's law, Black's equation with the Blech exemption,
and the power-law and Arrhenius lifetime model, including values exactly at
the limit. `esd_latchup` runs and reports, but no test yet checks its numbers
against an independent answer. Many other rules have limits that are foundry
conventions rather than physics, so their tests prove the rule runs and
measures, not that the limit is right for your process.
