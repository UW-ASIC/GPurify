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
| `enclosure(inner, outer, opposite)` | Needs the margin on one side of each axis. Foundry decks such as sky130 m1.5 need it on both sides of one axis, so a via with margin only on its left and bottom passes. |
| `enclosure` (both forms) | Measures bounding boxes, so an L-shaped outer shape can pass around a via it does not cover. |
| `wide_space` | Treats a shape as wide only if the whole shape is. A large plate with a thin tab is never checked as wide. |
| `width(L) <= len` | Checks the narrowest width, so a rectangular contact passes a rule that requires an exact square. |
| `density` | Sweeps windows over the layer's own extent, not the die, so empty parts of the die are not checked for minimum density. There is no whole-die density check. |
| `tap_distance` | Measures from the corners of the well, so a point midway between two taps can be too far and still pass. `missing_tie` measures the exact furthest point and does not have this problem. |
| `antenna` | Sidewall (perimeter) collectors are refused, which blocks gf180 and sky130 style rules. Diodes are credited before the metal that reaches them exists. |
| `angle` | Applies to every layer at once, so you cannot allow 45° on metal while forbidding it on diffusion and vias. |
| `esd_topological`, `esd_latchup` | Only checks that a clamp path exists. The resistance and current capacity of the path are not checked, and a clamp is any device of a listed model, however it is wired. |
| `gate_oxide`, `drain_source`, `well_bias`, `missing_level_shifter`, `domain_crossing` | A net's voltage range is the span of every supply it connects to through a device channel, ignoring threshold drops, switching and power-down, so these rules can over-report. A net that reaches no supply that way, such as a primary input with no ESD diode, is not checked, and neither is a device whose terminals sit on such nets. |

## Checks that do not exist yet

- Derived layers only support `and`, `or` and `not`. Sizing, `interacting`,
  `inside`/`outside`, holes and edge operations are reserved words in the deck
  and are refused until they exist. About a third of sky130's rules need them.
- A rule that flags any overlap between two layers at all, and a rule that
  requires every shape on one layer to contain a shape on another.
- Spacing that depends on whether two shapes are on the same net, spacing
  tables indexed by width and run length, and rules conditional on text
  labels.
- A way to state the voltage or domain of an input signal in the intent file,
  and checks for inputs driven from a powered-down domain.

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

`electromigration`, `esd_latchup`, `ir_drop` and `reliability` run and report,
but no test yet checks their numbers against an independent answer. Many
other rules have limits that are foundry conventions rather than physics, so
their tests prove the rule runs and measures, not that the limit is right for
your process.

## Speed

LVS on a highly symmetric design can take many refinement rounds, one per
ambiguous match it has to break.
