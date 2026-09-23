# Running GPurify

```sh
gpurify <command> <layout.gds> --deck <process.deck> --grid <n> [options]
```

| Command | Checks | Needs |
|---|---|---|
| `drc` | Design rules: width, spacing, enclosure, area, density, grid, angle, vias | the deck |
| `erc` | Electrical rules: antenna, ties, floating gates and wells, shorts, power grid | the deck; `--intent` for six of them |
| `lvs` | The layout's devices and connections against your schematic | `--reference <netlist>` |
| `pex` | Parasitic resistance, capacitance and, optionally, inductance | the deck's `pex` lines |
| `all` | All four | a check whose input is missing is reported as skipped, never as passed |

## Options

| Option | Meaning |
|---|---|
| `--deck <file>` | The process deck. Required. See [deck.md](deck.md). |
| `--grid <n>` | Layout database units per micron, as the GDS was written. `1000` means 1 dbu = 1 nm. |
| `--reference <file>` | The schematic netlist for LVS (SPICE or Spectre). |
| `--intent <file>` | Design intent: supply voltages and per-net limits. See below. |
| `--format text\|json\|spef\|dspf` | Report format. `spef` and `dspf` need a `pex` run. Default `text`. |
| `--output <file>` | Write the report there instead of to standard output. |
| `--quasistatic <net>` | Field-solve this net's capacitance instead of using the closed-form estimate. Repeat for more nets. |
| `--quasistatic-inductance` | Also solve inductance for the `--quasistatic` nets. |
| `--strict-layers` / `--no-strict-layers` | Refuse, or ignore, shapes on layers the deck does not declare. Strict is the default. |
| `--check-determinism` | Run twice and fail if the two reports differ. |

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

## Exit code

`0` only when every selected check ran, no rule was skipped or refused, and
nothing was found. Anything else is `1`: a violation, a skipped rule, a
missing input, a file that could not be read.

## Design intent

Six electrical rules need facts about the chip that no process deck can know:
`ir_drop`, `em_current_density`, `electromigration`, `reliability`,
`hv_domain` and `esd_latchup`. Without `--intent` they report skipped.

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

## Parasitics

`pex --format spef` writes a SPEF file for a timing tool, and `--format dspf`
writes a DSPF file for a simulator. Every net is extracted with closed-form
resistance and capacitance. Nets named with `--quasistatic` are solved from
the field instead, which is slower and more accurate, and their coupling to
nets that were not field-solved is kept. A net with no text label in the
layout has no name to write, and the run refuses it rather than inventing one.

The same inputs always give a byte-identical report.
