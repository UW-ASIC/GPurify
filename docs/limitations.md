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
| `wide_space` | Does not also hold shapes attached to the wide part (sky130 m1.3b "within 0.28 µm of huge metal") to the wide spacing. |
| `antenna_electrical` | A row with a diode and a non-zero `diode_credit` is refused: the unit of the credit is not settled. |
| `esd_topological`, `esd_latchup` | Only checks that a clamp path exists. The resistance and current capacity of the path are not checked, and a clamp is any device of a listed model, however it is wired. |
| `gate_oxide`, `drain_source`, `well_bias`, `missing_level_shifter`, `domain_crossing` | A net's voltage range is the span of every supply it connects to through a device channel, ignoring threshold drops, switching and power-down, so these rules can over-report. A net that reaches no supply that way, such as a primary input with no ESD diode, is not checked, and neither is a device whose terminals sit on such nets. |

## Checks that do not exist yet

- No check takes an edge layer yet, so edge layers can be derived but not
  checked.
- Derived layers have no selection by text label, net, angle or shape class
  (rectangles, squares), no `covering`/`overlapping`, and `sized` grows both
  axes by the same amount.
- A rule that flags any overlap between two layers at all, and a rule that
  requires every shape on one layer to contain a shape on another.
- Spacing that depends on whether two shapes are on the same net, spacing
  tables indexed by width and run length, and rules conditional on text
  labels.
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

The decks in `pdks/` are starting points, not qualified decks, and none
records which PDK release its numbers came from.

- Rule ids are descriptive (`met1_min_width`) rather than the foundry's rule
  numbers.
- No shipped deck configures `supply_short`, so a short between two supplies
  goes unreported.
- No shipped deck declares an ESD clamp device, so none carries
  `esd_topological` or `esd_latchup`, and none carries the voltage rules
  (`gate_oxide` and the rest). Add `device` statements for your clamp and
  I/O devices and the rows that name them.
- `sky130.deck` lacks about 35 rules from the periphery rule manual, among
  them licon.5a to licon.18, difftap.8 to difftap.11, npc and the poly resistor rules.

## Test coverage

`ir_drop`, `electromigration` and `reliability` are checked against numbers
worked out by hand from Ohm's law, Black's equation with the Blech exemption,
and the power-law and Arrhenius lifetime model, including values exactly at
the limit. `esd_latchup` runs and reports, but no test yet checks its numbers
against an independent answer. Many other rules have limits that are foundry
conventions rather than physics, so their tests prove the rule runs and
measures, not that the limit is right for your process.
