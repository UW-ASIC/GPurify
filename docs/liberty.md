# Liberty for a hard macro

`gpurify lib` writes the timing and power model a digital flow needs to place
an analog or custom macro: one `.lib` per PVT corner, and a Verilog blackbox
with the same ports. The numbers come from your layout, extracted and
simulated, at the accuracy you choose.

```sh
gpurify lib strongarm.gds --deck pdks/sky130.deck --grid 1000 \
    --spec strongarm.json --accuracy spice --output-dir lib/ \
    --reference strongarm.spice --lef strongarm.lef
```

```
spice: wrote lib/strongarm.v
spice: wrote lib/strongarm__tt_025C_1v80.lib
spice: wrote lib/strongarm__ss_100C_1v60.lib
spice: wrote lib/strongarm__ff_n40C_1v95.lib
spice: wrote lib/min/strongarm__tt_025C_1v80.lib
...
```

| Option | Meaning |
|---|---|
| `--spec <file>` | The macro spec, below. Required. |
| `--accuracy <level>` | `interface`, `analytical`, `field`, `spice`, `statistical`, or `0` to `4`, or `all`. Default `spice`. |
| `--output-dir <dir>` | Where the files go. With `--accuracy all`, one subdirectory per level. |
| `--reference <netlist>` | A `.subckt` whose ports must match the spec's pins. |
| `--lef <file>` | A LEF whose `MACRO`'s pins must match the spec's pins. |
| `--work <dir>` | Keep the simulator decks and logs here. Without it they go to a temporary directory that is removed on success and kept on failure. |

The layout options (`--deck`, `--grid`, `--no-strict-layers`) are the other
commands'.

## Accuracy

| Level | Pin capacitance | Arcs | Leakage |
|---|---|---|---|
| `interface` (0) | none | none | none |
| `analytical` (1) | closed-form wire C + each device's static model C | none | simulated |
| `field` (2) | field-solved wire C + each device's static model C | none | simulated |
| `spice` (3) | charge drawn on the extracted RC netlist | NLDM delay and transition, setup and hold, internal energy | simulated |
| `statistical` (4) | as `spice` | as `spice`, plus Monte Carlo LVF sigma | simulated |

`interface` is enough for floorplanning and the power grid. The STA you sign
off with wants `spice` or `statistical`. Each level costs more than the one
below. On an i9-14900HX, sky130's `inv_1` takes 0.1 s, 12 s, 12 s and 30 s
from `interface` to `spice`.

**Static device capacitance** (`analytical`, `field`) is each device on a pin
simulated alone, with the pin's terminal swept across the pin's swing and
every other terminal held at a rail. It is the model's own gate, overlap and
junction capacitance with no Miller term, averaged over the swing.

**The extracted RC netlist** (`spice`, `statistical`) is built like this:

- Every conductor polygon is cut into rectangles, one node each. Neighbouring
  rectangles are joined through the sheet resistance between their centres,
  and every via cut is its own resistor.
- Ground capacitance comes from the stack, per rectangle. Coupling capacitance
  comes from the analytical extractor's polygon pairs, placed between the two
  closest rectangles. The whole design is then field-solved, wires only, and
  every net's ground and every net pair's coupling is rescaled to the solved
  totals.
- Rectangles of one net that overlap, from shapes drawn over each other,
  are joined. A net whose resistor network still falls into pieces is
  refused by name, because a terminal on the detached piece would float.
- Each device terminal sits on the rectangle touching its channel.
- Each MOS gets its drain and source area and perimeter from its diffusions,
  with shared diffusion split between the fingers that share it. It also gets
  its BSIM4 `sa`/`sb` (length-of-diffusion stress), the distance from each gate
  edge to the isolation edge. On sky130 that last one moves a delay by about
  15 %.

Diffusions and wells are left out of the field solve. Their capacitance is the
device model's.

## How each number is measured

The conventions are sky130_fd_sc_hd's, so the result can be diffed against a
shipped library:

- **Delay**: the related pin crossing `input_threshold_pct`, to the output
  crossing `output_threshold_pct`.
- **Transition**: `slew_lower_pct` to `slew_upper_pct`, not derated. An
  input transition of `s` is a linear ramp whose full swing takes
  `s / (upper − lower)`.
- **Pin capacitance**: the charge the pin's source delivers while the pin
  swings, less its static current, divided by the swing. Rise and fall are
  measured separately and averaged over every state the pin switches in.
  Integrating past the ramp would make rise and fall equal by charge
  conservation.
- **Analog pin capacitance**: `−Im(I)/ω` at the pin's bias and
  `analog_frequency_hz`, Miller included.
- **Internal energy**: supply energy over the edge and its settling, less the
  static power over that window, less `½·C·V²` of the load, which a timer
  adds itself. In pJ.
- **Setup and hold**: the smallest data-to-clock offset at which the check pin
  still reaches its value and its clock-to-check delay stays within
  `pushout_pct` (10 %) of the relaxed delay. Found by bisection to 0.5 ps.
- **Leakage**: `V·I` of every supply. A one-vector state is a DC operating
  point. A sequence is simulated and averaged once settled.
- **Limits**: `max_transition` is the largest characterized input
  transition. An output's `max_capacitance` is the largest load, and its
  `max_transition` is the largest transition it produced.

When the cases of an arc disagree, as a data-dependent comparator's do, the
main file carries the worst case at every table point and `min/` the best,
for `read_liberty -min`. The `min/` library is named `<cell>__<corner>__min`,
because OpenSTA skips a second library whose name it has already read. A measurement the simulator could not make, such as
an output that never switched, is an error naming the arc, case and table
point. It never becomes a zero in a table.

**Simulator settings**: reltol 1e-6, trtol 1, and steps of at most 10 ps that
follow the truncation error. Against a reltol 1e-6 run with 0.1 ps steps they
agree to 0.03 % on a 10 ps edge into 0.5 fF, and to 0.0002 % on a 1.5 ns edge.
They cost a fifth of a fixed sub-picosecond step.

**Field solve**:

- `field` solves the pin nets' wiring together, with 50 nm panels.
- `spice` and `statistical` solve every net in a 3 µm window, with 200 nm
  panels halved near other conductors. That is converged to within 0.8 % of
  wire capacitance.
- Each net is driven once, with its conductors at one volt together.
- A conductor's overlapping shapes are merged first.
- Via cuts are left out. A cut's end faces sit on the plates it joins.

## Checked against

OpenSTA 3.1.0 reads the files with no warning. `report_checks` times through
the NLDM tables, and with `set sta_pocv_mode normal` it applies the LVF sigma.
On sky130's `inv_1`, A→Y rises in 127.3 ps nominal and 137.5 ps at +3σ.

The cells also diff against sky130_fd_sc_hd's shipped `tt_025C_1v80` library,
characterized from their GDS at `spice` accuracy on the shipped load indices:

| Cell | Delay, mean \|error\| | Transition | Internal energy, worst point | Input C |
|---|---|---|---|---|
| `inv_1` | rise +7.4 %, fall −5.4 % | +5.6 %, −4.7 % | 0.005 pJ | +10…+18 % |
| `nand2_1` | rise +4.8 %, fall −3.1 % | +3.8 %, −3.6 % | 0.010 pJ | +8…+18 % |
| `dfxtp_1` | CLK→Q rise +1.9 %, fall +0.8 % | +3.0 %, −3.4 % | 0.023 pJ | −10…+5 % |

Setup and hold on `dfxtp_1`, against the shipped 3×3 tables, are mostly within
5 to 20 ps. The worst point is hold on a falling D at slow slews, which is
80 ps more pessimistic than shipped.

The shipped library is not ground truth for these models. On the bare device
netlist with no layout, today's ngspice sky130 models already give a pfet that
is slower and an nfet that is faster than the shipped tables. They also give
input capacitance within 10 % of the shipped value before any wire is added,
and leakage that differs by up to two orders of magnitude. On `dfxtp_1`, the
shipped device netlist alone draws 0.6 nA in a state the shipped table puts at
5 pA. The residual above is that gap.

Two things the comparison caught, which the extraction now does:

- BSIM4 `sa`/`sb`. Without them, rise was +24 % and fall −21 %.
- Integrating pin charge over the input ramp only. Integrating past it made
  rise and fall capacitance equal.

## The spec

A layout names its pins. It cannot say which one is a clock, which one is
analog, what arcs exist, or what each supply is at in each corner. The spec
says those things. It is JSON, and an unknown key is an error.

```json
{
  "cell": "strongarm",
  "substrate": "vss",
  "pins": [
    {"name": "vinp", "role": "analog", "direction": "input", "bias": 0.9,
     "power": "vdd", "ground": "vss"},
    {"name": "vinn", "role": "analog", "direction": "input", "bias": 0.9,
     "power": "vdd", "ground": "vss"},
    {"name": "outp", "role": "output", "power": "vdd", "ground": "vss"},
    {"name": "outn", "role": "output", "power": "vdd", "ground": "vss"},
    {"name": "clk",  "role": "clock",  "power": "vdd", "ground": "vss"},
    {"name": "vdd",  "role": "power"},
    {"name": "vss",  "role": "ground"}
  ],
  "arcs": [
    {"from": "clk", "to": "outp", "kind": "rising_edge", "cases": [
      {"vectors": [{"clk": "0", "vinp": 0.95, "vinn": 0.85}], "output": "fall"},
      {"vectors": [{"clk": "0", "vinp": 0.905, "vinn": 0.895}], "output": "fall"}
    ]}
  ],
  "corners": [
    {"name": "tt_025C_1v80", "temperature": 25,
     "supplies": {"vdd": 1.8, "vss": 0},
     "models": [".lib \"/path/to/sky130.lib.spice\" tt"],
     "mc_models": [".lib \"/path/to/sky130.lib.spice\" tt_mm"]}
  ]
}
```

**Pins**, in port order. That order is the Verilog blackbox's.

| Key | Meaning |
|---|---|
| `role` | `power`, `ground`, `nwell`, `pwell` (each a `pg_pin`), or `input`, `clock`, `output`, `analog`. |
| `power`, `ground` | The related supplies. Required on every signal pin. They set its logic levels and thresholds. |
| `direction` | Analog pins only: `input`, `output` or `inout` (the default). |
| `bias` | Analog pins only, and required: its DC voltage while everything else is measured. Its capacitance is taken there. |
| `function` | An output's Liberty `function`, copied through unread. |

An analog pin gets a direction and a capacitance and never an arc, so STA
leaves it unconstrained. It is also marked `is_analog : true`. OpenSTA does not
read that attribute, so in OpenSTA the pin is simply an arcless pin.

**Arcs**: `kind` is the Liberty `timing_type`: `combinational`,
`rising_edge`, `falling_edge`, `setup_rising`, `hold_rising`,
`setup_falling` or `hold_falling`. `from` is the input or clock and `to` is
the output or constrained data pin. Each case is one measurement:

| Key | Meaning |
|---|---|
| `vectors` | Pin values applied in order, `vector_ns` apart, before the measured edge. The first gives every digital input a value. A value is `"0"`, `"1"` (the pin's rails), or a number of volts. |
| `edge` | Combinational only: `rise` or `fall` of `from`. A clocked arc's edge comes from its kind. |
| `output` | Delay arcs: the edge `to` must make. |
| `data`, `check` | Constraints: the edge the data pin makes, and `{"pin", "value"}` that a correct capture produces. |

A latch's state is its history, so the vectors are a sequence. A self-timed
`go → done` is a `combinational` arc with one case per data pattern. The main
file gets the slowest and `min/` the fastest.

**Corners**: one `.lib` each, named `<cell>__<name>.lib` so LibreLane's
corner globs match. `models` is written verbatim into the deck. `mc_models`
is the same with variation switched on, and is needed only for
`statistical`.

**`substrate`** ties the deck's global substrate net to a supply pin.
Without it, a substrate that no label names would float in simulation.

**`leakage_states`** is a list of vector sequences. By default it is every
case's preparation.

**`characterization`** overrides any of: `slews_ns`, `loads_pf`,
`constraint_slews_ns`, `input_threshold_pct`, `output_threshold_pct`,
`slew_lower_pct`, `slew_upper_pct`, `pushout_pct`, `vector_ns`, `settle_ns`,
`constraint_window_ns`, `mc_samples` and `analog_frequency_hz`. Defaults are
sky130_fd_sc_hd's tables and thresholds.

**`simulator`** overrides any of:

- `binary`: default `ngspice`.
- `scale`: `.option scale`, default `1e-6`.
- `prefix`: the card letter of an extracted device, default `X` for a
  subcircuit model.
- `options`: extra `.option` lines.
- `workers`: how many simulator processes run at once. Default is every core.

## The cross-check

Before anything is measured, the spec's pins are compared with:

- **The layout's labels**: every label must be a spec pin, and every spec pin
  must be found. The `substrate` pin may be found as the substrate instead.
- **The reference `.subckt`'s ports**, with `--reference`.
- **The LEF macro's pins**, with `--lef`.

Any difference is an error that names what each side lacks. The Verilog
blackbox is written from the spec, so it cannot drift. When one of these
files and the layout disagree about a name, the integration fails late and
confusingly, so the check is made first.

## What it does not do yet

- `min_pulse_width`, recovery and removal checks, and input-pin internal power
  are not characterized.
- CCS and ECSM are not written. Only NLDM.
- The `.lib` does not carry antenna data. OpenROAD reads that from the LEF,
  which this command checks but does not write.
- The field solve is a dense boundary-element solve. Each window costs the
  square of its panel count, so a very dense layout is slow at `spice`.
- `sa`/`sb` are read along the channel's centre line. An irregular active
  region wants BSIM4's width-weighted average.
- Poly over a channel stays in the field solve, which counts about 1 % of a
  gate's capacitance twice.
- OpenSTA misspells `ocv_sigma_*_constraint` as `constraiint` when it reads,
  so it drops constraint sigma. The tables are written under the Liberty name
  anyway.
