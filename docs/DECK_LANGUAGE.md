# The deck language

A deck says what the process is (layers, how they connect, what devices look
like, the PEX stack) and what must hold (DRC and ERC rules). It replaces the
JSON decks. There is one format; `gpurify deck convert old.json` writes the
equivalent `.deck` once, and the JSON reader is then deleted.

Design constraints, in priority order:

1. **Strict.** Every parameter of every rule is required. There are no
   defaults. A missing parameter, an unknown parameter, an unknown layer, a
   bare number where a unit belongs, or a unit of the wrong dimension is an
   error that points at the line and column.
2. **Declarative.** No general computation, no I/O, no recursion. Every deck
   terminates and means the same thing on every machine.
3. **Short.** One line per rule for the common case. A metal stack is a loop,
   not twelve copies.

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
rule licon.1  cut_size(licon)         == 170nm x 170nm

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

pex met1 thickness 360nm height 1376nm sheet 0.125ohm dielectric 3.9
    area_cap 25.8aF/um2 fringe_cap 40.5aF/um
```

## Lexical

- Comments run from `#` to end of line.
- Identifiers: `[A-Za-z_][A-Za-z0-9_.]*`. Rule ids may contain `.` (`m1.3b`)
  and `{name}` interpolation inside a `for` body.
- Strings: `"..."`, no escapes except `\"` and `\\`. Only model names use them.
- Numbers: decimal, optional fraction and exponent. A number is always
  followed by a unit, except a **count** (unsigned integer) and a **scalar**
  (a dimensionless ratio or exponent, written with a fraction or as `%`).
- Newlines end a statement unless inside `(`, `[` or `{`.

## Units

A quantity is a number immediately followed by its unit. The unit fixes the
dimension; each parameter declares the dimension it accepts.

| Dimension | Units |
|---|---|
| length | `nm`, `um`, `mm` |
| area | `nm2`, `um2`, `mm2` |
| voltage | `mV`, `V` |
| current | `nA`, `uA`, `mA`, `A` |
| current per width | `uA/um`, `mA/um`, `A/m` |
| resistance | `mohm`, `ohm`, `kohm`, `Mohm` |
| capacitance per area | `aF/um2`, `fF/um2` |
| capacitance per length | `aF/um`, `fF/um` |
| temperature | `K`, `C` (converted to kelvin at parse) |
| energy | `eV` |
| time | `h` |
| fraction | `%` (0–100) or a scalar 0–1 |
| angle | `deg` |

Lengths must land on the grid: `grid 5nm` makes `142nm` an error. Values are
converted to the engine's internal units exactly as the JSON reader did; the
conversion is the proof, because the corpus output must be byte-identical
after `deck convert`.

## Statements

```
deck      = { stmt NEWLINE }
stmt      = grid | let | layer | rule | for | connect | device | pex
grid      = "grid" length
let       = "let" IDENT "=" value
layer     = "layer" IDENT "=" ( "gds" "(" count "," count ")" | layer_expr )
rule      = "rule" RULE_ID [ "warning" ] check
for       = "for" pattern "in" list "{" { stmt NEWLINE } "}"
connect   = "connect" ( "conductors" layer_list
                      | "touch_within_layer"
                      | "via" IDENT layer_list )
device    = "device" DEVICE_KIND IDENT "model" STRING "terminals" layer_list
pex       = "pex" IDENT { PEX_KEY value }
```

`let` binds a value (quantity, layer, list or tuple) that later statements
read. Names are bound once; rebinding is an error. `for` expands its body once
per element of a list written in the deck, so a loop is bounded by the
deck's own text.

Layers must be declared before use and derived layers may only name layers
above them. A cycle cannot be written.

### Layer expressions

```
layer_expr = term { ("and" | "or" | "not") term }     # left fold, as today
term       = IDENT | "(" layer_expr ")" | term "." op
```

Available now: `and`, `or`, `not`.

Reserved for the derived-operation work (each is an error saying "not yet
supported" until the engine implements it, never silently ignored):
`.sized(length)`, `.sized(-length).sized(length)`, `.interacting(layer)`,
`.not_interacting(layer)`, `.inside(layer)`, `.outside(layer)`, `.holes()`,
`.extents()`, `.with_area(range)`, `.with_width(range)`.

### Checks

Two forms. A kind with one limit uses a comparison; a kind with several
parameters uses named arguments. Both can be combined.

```
check      = KIND "(" layer_args [ ";" named_args ] ")" [ CMP value ]
           | KIND "(" layer_args ")" "(" named_args ")"
named_args = IDENT ":" value { "," IDENT ":" value }
CMP        = ">=" | "<=" | "=="
```

The comparison supplies the kind's `limit` parameter. `>=` is only legal on a
minimum kind, `<=` on a maximum kind; the wrong one is an error, not a flip.
Named arguments are matched by name, all are required, and each is checked
against its declared dimension.

## Kind table

Every kind the engine runs today, with its layer arguments and parameters.
The JSON name is on the right for `deck convert`.

### DRC

| Kind | Layers | Parameters | JSON |
|---|---|---|---|
| `width(L) >= len` | 1 | — | `min_width` |
| `width(L) <= len` | 1 | — | `max_width` |
| `edge_length(L) >= len` | 1 | — | `min_edge_length` |
| `notch(L) >= len` | 1 | — | `notch` |
| `space(L) >= len` | 1 | — | `min_spacing` |
| `space(A, B) >= len` | 2 | — | `min_spacing_diff` |
| `eol_space(L; eol_width: len) >= len` | 1 | eol_width | `eol_spacing` |
| `prl_space(L; prl: len) >= len` | 1 | prl | `prl_spacing` |
| `corner_space(L) >= len` | 1 | — | `corner_to_corner` |
| `wide_space(L; width: len) >= len` | 1 | width | `wide_dependent_spacing` |
| `area(L) >= area` | 1 | — | `min_area` |
| `hole_area(L) >= area` | 1 | — | `min_enclosed_area` |
| `cheesing(L) <= area` | 1 | — | `cheesing` |
| `density(L; window: len, step: len) >= frac` (or `<=`) | 1 | window, step | `density` |
| `enclosure(inner, outer) >= len` | 2 | — | `min_enclosure` |
| `enclosure(inner, outer, opposite) >= len` | 2 | — | `asymmetric_enclosure` |
| `extension(A, B) >= len` | 2 | — | `min_extension` |
| `overlap(A, B) >= len` | 2 | — | `overlap` |
| `tap_distance(well, tap) <= len` | 2 | — | `max_distance_to_tap` |
| `off_grid(; pitch: len)` | 0 | pitch | `off_grid` |
| `angle(; allowed: [angle, …])` | 0 | allowed | `angle` |
| `redundant_via(L; within: len) >= count` | 1 | within | `redundant_via` |
| `via_array_space(L; array: count) >= len` | 1 | array | `via_array_spacing` |
| `patterning(L; colors: count) >= len` | 1 | colors | `multi_patterning` |

The JSON `angle` repeated an `angle` count per allowed direction; the deck
writes the set, `allowed: [0deg, 90deg]`, each a multiple of 45°. The limits
of `min_area`, `min_enclosed_area` and `cheesing` were lengths in JSON (the
side of the equivalent square); the deck writes an area, and `deck convert`
squares it. JSON `density`'s `maximum: true` is `<=`, `false` is `>=`.

### ERC

All parameters required. The JSON reader's optional parameters and defaults
become required named arguments; `deck convert` writes out the value the
default supplied.

| Kind | Layers | Parameters | JSON |
|---|---|---|---|
| `antenna(gate, metal; max_ratio: scalar, sidewall: len \| none)` | 2 | | `antenna` |
| `antenna_electrical(layers…; max_ratio, diode: layer \| none, diode_credit: scalar, diode_bonus: scalar)` | n | | `antenna_electrical` |
| `density_cmp(L; window: len x len, step: len x len, min: frac \| none, max: frac \| none, max_delta: frac \| none, partial_windows: bool, cmp: none \| (target: frac, thickness: len, sensitivity: len, max_delta: len))` | 1 | | `density_cmp` |
| `electromigration(layers…; max_density: A/m, max_current_per_cut: current, blech_limit: current, reference_temperature: temp, activation_energy: eV, current_exponent: scalar)` | n | | `electromigration` |
| `em_current_density(layers…; max_density, max_current_per_cut)` | n | | `em_current_density` |
| `esd_latchup(pad, diff; min_guard_ring_width: len, max_tap_distance: len)` | 2 | | `esd_latchup` |
| `esd_topological(pad)` | 1 | | `esd_topological` |
| `floating_gate()` | 0 | | `floating_gate` |
| `floating_well(well, tap)` | 2 | | `floating_well` |
| `hv_domain(; max_delta: voltage, isolation: layer \| none)` | 0 | | `hv_domain` |
| `ir_drop()` | 0 | | `ir_drop` |
| `missing_tie(well, diff; max_distance: len)` | 2 | | `missing_tie` |
| `multiple_drivers(; max: count)` | 0 | | `multiple_drivers` |
| `p2p_resistance(; max: resistance)` | 0 | | `p2p_resistance` |
| `reliability(; required_lifetime: h, reference_lifetime: h, reference_stress: voltage, stress_exponent: scalar, reference_temperature: temp, activation_energy: eV, max_abs_voltage: voltage, duty_cycle: frac)` | 0 | | `reliability` |
| `soft_connection(A, B)` | 2 | | `soft_connection` |
| `supply_short()` | 0 | | `supply_short` |
| `tie_high_low()` | 0 | | `tie_high_low` |
| `unconnected_pin(layers…)` | n | | `unconnected_pin` |

`none` is an explicit absence and only legal where the table says so. It is
not a default: leaving the argument out is still an error.

The three `esd_latchup` parameters the engine validates but never reads
(`required_current`, `max_path_resistance`, `max_clamp_voltage`) are
dropped, not carried forward.

JSON listed enclosure layers outer first (`["met1", "mcon"]`); the deck writes
`enclosure(inner, outer)`, so `deck convert` swaps them.

`warning` after the rule id sets the severity. Without it a rule is an error.

## Errors

Every error names the file, line and column, prints the line, and puts a
caret under the span:

```
pdks/sky130.deck:41:28: m1.5: enclosure needs a length, got 60 (no unit)
rule m1.5 enclosure(mcon, met1, opposite) >= 60
                                             ^^
```

The parser keeps going after an error and reports every one it finds, up to
50, so a deck is fixed in one pass rather than one error per run.

## Implementation notes

- Hand-written lexer and recursive-descent parser in `crates/ingest/src/deck/`.
  No parser-generator or diagnostics crate. Errors are a `Vec<DeckError>` with
  byte spans; the caret rendering is a few lines.
- The parser lowers into the same `Deck` the JSON reader builds. No second IR.
- `for`/`let` are expanded during parsing; the lowered `Deck` never sees them.
- `gpurify deck convert <json>` exists only until every deck in `pdks/` and
  `tests/fixtures/` is converted and the gate passes, then it and the JSON
  reader are deleted in the same commit.
- Design intent (`--intent`) stays JSON for now. It is per-design, not per-process.
