//! Characterization: what each Liberty number is, measured.
//!
//! Every measurement is one transient (or AC, or DC) analysis on a
//! [`Session`], so every function here needs ngspice: the pins are driven
//! through the spec's preparation vectors, then the measured edge.
//! Conventions are `sky130_fd_sc_hd`'s, so the result diffs against a shipped
//! library:
//!
//! - delay, ns: the related pin's `input_threshold_pct` crossing to the
//!   output's `output_threshold_pct` crossing. Transition, ns:
//!   `slew_lower_pct` to `slew_upper_pct`, not derated
//!   (`slew_derate_from_library : 1`). An input transition of `s` is a linear
//!   ramp whose full swing takes `s / (upper − lower)`.
//! - pin capacitance, pF: charge the pin's source delivers while the pin
//!   swings, less the static current it drew before, over the swing; rise and
//!   fall separately, averaged over every state the pin switches in.
//!   Integrating past the ramp would make rise and fall equal by charge
//!   conservation.
//! - internal energy, pJ: supply energy over the edge and its settling, less
//!   the static power over that window, less `½·C_load·V²` (the switching
//!   energy a timer adds itself).
//! - setup and hold, ns: the smallest data-to-clock offset at which the check
//!   pin still reaches its value and its clock-to-check delay stays within
//!   `pushout_pct` of the relaxed delay; found by bisection to
//!   [`Effort::resolution`]. See [`Bench::constraint_point`].
//! - leakage, nW: `V·I` summed over every supply.
//!
//! A measurement the simulator could not make is an error naming the arc,
//! case and table point. It never becomes a zero in a table.

use std::fmt::Write as _;

use crate::liberty::spec::{ArcSpec, CaseSpec, CornerSpec, Edge, Level, MacroSpec, Role, Vector};
use crate::liberty::spice::{pin_load, pin_source, si, Results, Session, SimError};

/// Time between preparation vectors' ramps start and end, s.
const PREP_RAMP: f64 = 50e-12;

/// How hard each transient works.
#[derive(Debug, Clone, Copy)]
pub struct Effort {
    /// The largest step, s. Within it the step follows the truncation error.
    pub max_step: f64,
    /// Bisection stops below this, s.
    pub resolution: f64,
}

/// One corner's measurement context. Every method runs on a [`Session`] that
/// has this corner's deck loaded, written by
/// [`write_deck`](crate::liberty::spice::write_deck) from the same `spec`, so
/// pin `i` is the deck's node `p<i>`.
pub struct Bench<'a> {
    /// The spec, as [`parse`](crate::liberty::spec::parse) validated it:
    /// pin names and case shapes are trusted, and a spec that skipped
    /// validation can panic here.
    pub spec: &'a MacroSpec,
    /// The corner whose supply voltages set every pin's rails.
    pub corner: &'a CornerSpec,
    /// Transient step and bisection resolution.
    pub effort: Effort,
    /// The deck's `reltol`, restored after a relaxed retry.
    pub reltol: f64,
}

/// A pin's drive over time.
type Pwl = Vec<(f64, f64)>;

/// Pin `i`'s low and high rail voltages.
fn rails(spec: &MacroSpec, corner: &CornerSpec, i: usize) -> (f64, f64) {
    let pin = &spec.pins[i];
    let v = |name: &Option<String>| name.as_ref().map_or(0.0, |n| corner.supplies[n]);
    (v(&pin.ground), v(&pin.power))
}

fn index_of(spec: &MacroSpec, name: &str) -> usize {
    spec.pins
        .iter()
        .position(|p| p.name == name)
        .expect("the spec validated every pin name")
}

impl Bench<'_> {
    fn volts(&self, i: usize, level: Level) -> f64 {
        let (lo, hi) = rails(self.spec, self.corner, i);
        match level {
            Level::Low => lo,
            Level::High => hi,
            Level::Volts(v) => v,
        }
    }

    /// A threshold of pin `i`'s swing, `pct` percent of the way up.
    fn threshold(&self, i: usize, pct: f64) -> f64 {
        let (lo, hi) = rails(self.spec, self.corner, i);
        lo + pct / 100.0 * (hi - lo)
    }

    /// The full-swing ramp time of a `slew` (ns) transition, s.
    fn ramp(&self, slew_ns: f64) -> f64 {
        let c = &self.spec.characterization;
        slew_ns * 1e-9 / ((c.slew_upper_pct - c.slew_lower_pct) / 100.0)
    }

    /// Every driven pin's waveform through `vectors`, and the time they end.
    /// Undriven analog pins sit at their bias.
    fn prepare(&self, vectors: &[Vector]) -> (Vec<Option<Pwl>>, f64) {
        let spec = self.spec;
        let period = spec.characterization.vector_ns * 1e-9;
        let mut waves: Vec<Option<Pwl>> = spec
            .pins
            .iter()
            .map(|pin| match pin.role {
                Role::Input | Role::Clock => Some(Vec::new()),
                Role::Analog => Some(vec![(0.0, pin.bias.unwrap_or(0.0))]),
                _ => None,
            })
            .collect();
        for (k, vector) in vectors.iter().enumerate() {
            #[expect(clippy::cast_precision_loss, reason = "a handful of vectors")]
            let t = k as f64 * period;
            for (name, &level) in vector {
                let i = index_of(spec, name);
                let v = self.volts(i, level);
                let wave = waves[i].as_mut().expect("vectors drive inputs only");
                set(wave, t, v);
            }
        }
        #[expect(clippy::cast_precision_loss, reason = "a handful of vectors")]
        let end = vectors.len() as f64 * period;
        (waves, end)
    }

    /// The commands that load `waves` and every output's load.
    fn drive(&self, waves: &[Option<Pwl>], load_on: Option<(usize, f64)>, out: &mut String) {
        for (i, wave) in waves.iter().enumerate() {
            if let Some(points) = wave {
                let _ = write!(out, "alter @{}[pwl] = [", pin_source(i));
                if points.is_empty() {
                    out.push_str(" 0 0");
                }
                for &(t, v) in points {
                    let _ = write!(out, " {} {}", si(t), si(v));
                }
                out.push_str(" ]\n");
            }
        }
        for (i, pin) in self.spec.pins.iter().enumerate() {
            if pin.role == Role::Output {
                let c = match load_on {
                    Some((j, c)) if j == i => c,
                    _ => 1e-18,
                };
                let _ = writeln!(out, "alter {} = {}", pin_load(i), si(c));
            }
        }
    }

    /// A transient to a little past `stop`, so a measurement *at* `stop` is
    /// inside the simulated interval however the last step rounds.
    fn tran(&self, stop: f64, out: &mut String) {
        let step = self.effort.max_step;
        let _ = writeln!(
            out,
            "tran {} {} 0 {}",
            si(step),
            si(stop + 4.0 * step),
            si(step)
        );
    }

    fn error(&self, why: String) -> SimError {
        SimError::Measure {
            corner: self.corner.name.clone(),
            why,
        }
    }
}

/// A sequence's final value of every pin it names.
pub fn merged(sequence: &[Vector]) -> Vector {
    let mut state = Vector::new();
    for vector in sequence {
        state.extend(vector.iter().map(|(k, v)| (k.clone(), *v)));
    }
    state
}

/// Hold `wave` at its current value until `t`, then ramp to `v` over
/// [`PREP_RAMP`]; the first point of a wave is its value from time zero.
fn set(wave: &mut Pwl, t: f64, v: f64) {
    match wave.last() {
        None => wave.push((0.0, v)),
        Some(&(_, old)) if (old - v).abs() < 1e-12 => {}
        Some(&(last_t, old)) => {
            if t > last_t {
                wave.push((t, old));
            }
            wave.push((t.max(last_t) + PREP_RAMP, v));
        }
    }
}

/// Append a ramp from the wave's last value to `v`, starting at `t` and
/// taking `ramp`.
fn ramp_to(wave: &mut Pwl, t: f64, ramp: f64, v: f64) {
    let &(last_t, old) = wave.last().expect("a prepared wave has a start");
    debug_assert!(t > last_t, "an edge before the preparation ended");
    wave.push((t, old));
    wave.push((t + ramp, v));
}

fn value(wave: &Pwl) -> f64 {
    wave.last().map_or(0.0, |&(_, v)| v)
}

fn need(results: &Results, key: &str) -> Option<f64> {
    results.get(key).copied().flatten()
}

/// Why leakage state `k` has no supply current: the analysis it is read from
/// did not converge, a DC operating point for one vector, a transient for a
/// sequence.
fn unmeasured_leakage(k: usize, state: &[Vector]) -> String {
    if state.len() == 1 {
        format!("the DC operating point of leakage state {k} did not converge")
    } else {
        format!("the transient of leakage state {k} did not converge")
    }
}

fn rise_fall(edge: Edge) -> &'static str {
    match edge {
        Edge::Rise => "RISE",
        Edge::Fall => "FALL",
    }
}

/// One input-slew row of a delay case's tables: one value per load, in
/// [`loads_pf`](crate::liberty::spec::Characterization::loads_pf) order.
#[derive(Debug, Clone)]
pub struct Grid {
    /// Delay, ns.
    pub delay: Vec<f64>,
    /// Output transition, ns.
    pub transition: Vec<f64>,
    /// Internal energy, pJ.
    pub energy: Vec<f64>,
}

/// The related pin's edge in a case: the clock edge of a clocked arc, else
/// the case's own `edge`.
///
/// # Panics
///
/// Panics on a combinational case with no `edge`, which
/// [`parse`](crate::liberty::spec::parse) refuses.
pub fn input_edge(arc: &ArcSpec, case: &CaseSpec) -> Edge {
    arc.kind
        .clock_edge()
        .or(case.edge)
        .expect("the spec validated every case's edge")
}

impl Bench<'_> {
    /// Supplies whose energy counts: every supply above ground.
    fn energy_supplies(&self) -> Vec<(usize, f64)> {
        self.spec
            .pins
            .iter()
            .enumerate()
            .filter(|(_, p)| p.role.is_supply())
            .map(|(i, p)| (i, self.corner.supplies[&p.name]))
            .filter(|&(_, v)| v != 0.0)
            .collect()
    }

    /// Measures row `row` of a delay case's delay, transition and energy
    /// tables: the input slew `slews_ns[row]` into every load, one transient
    /// per load, sent to `session` as one batch. `label` names the arc and
    /// case in every error.
    ///
    /// # Errors
    ///
    /// [`SimError::Measure`] when the case's vectors already leave the related
    /// pin where its edge would take it, when the output does not make its
    /// edge within `settle_ns` of the input edge, when it never completes its
    /// swing, or when a supply's charge was not measured. Any error of
    /// [`Session::run`].
    pub fn delay_row(
        &self,
        session: &mut Session,
        arc: &ArcSpec,
        case: &CaseSpec,
        row: usize,
        label: &str,
    ) -> Result<Grid, SimError> {
        let c = &self.spec.characterization;
        let (from, to) = (index_of(self.spec, &arc.from), index_of(self.spec, &arc.to));
        let edge = input_edge(arc, case);
        let output = case.output.expect("a delay case has an output edge");
        let (out_lo, out_hi) = rails(self.spec, self.corner, to);
        let supplies = self.energy_supplies();
        let mut grid = Grid {
            delay: Vec::new(),
            transition: Vec::new(),
            energy: Vec::new(),
        };
        {
            let (si_, slew) = (row, c.slews_ns[row]);
            let mut commands = String::new();
            let ramp = self.ramp(slew);
            let (mut waves, start) = self.prepare(&case.vectors);
            let from_wave = waves[from].as_mut().expect("the related pin is driven");
            let target = match edge {
                Edge::Rise => rails(self.spec, self.corner, from).1,
                Edge::Fall => rails(self.spec, self.corner, from).0,
            };
            if (value(from_wave) - target).abs() < 1e-9 {
                return Err(self.error(format!(
                    "{label}: the vectors leave {} already {}, so it cannot {}",
                    arc.from,
                    if edge == Edge::Rise { "high" } else { "low" },
                    edge.name()
                )));
            }
            let t_edge = start + c.vector_ns * 1e-9;
            ramp_to(from_wave, t_edge, ramp, target);
            let stop = t_edge + ramp + c.settle_ns * 1e-9;
            let window = stop - t_edge;
            let vin = self.threshold(from, c.input_threshold_pct);
            let vout = self.threshold(to, c.output_threshold_pct);
            let (v_lo, v_hi) = (
                self.threshold(to, c.slew_lower_pct),
                self.threshold(to, c.slew_upper_pct),
            );
            for (li, &load) in c.loads_pf.iter().enumerate() {
                let key = format!("{si_}_{li}");
                self.drive(&waves, Some((to, load * 1e-12)), &mut commands);
                self.tran(stop, &mut commands);
                let td = si(t_edge);
                let _ = writeln!(
                    commands,
                    "meas tran d TRIG v({n_in}) VAL={vin} TD={td} {ie}=1 TARG v({n_out}) VAL={vout} TD={td} {oe}=1",
                    n_in = crate::liberty::spice::pin_node(from),
                    n_out = crate::liberty::spice::pin_node(to),
                    vin = si(vin),
                    vout = si(vout),
                    ie = rise_fall(edge),
                    oe = rise_fall(output),
                );
                for (name, v) in [("tlo", v_lo), ("thi", v_hi)] {
                    let _ = writeln!(
                        commands,
                        "meas tran {name} WHEN v({})={} TD={td} {}=1",
                        crate::liberty::spice::pin_node(to),
                        si(v),
                        rise_fall(output)
                    );
                }
                for &(s, _) in &supplies {
                    let src = pin_source(s);
                    let _ = writeln!(
                        commands,
                        "meas tran q{s} INTEG i({src}) FROM={td} TO={}",
                        si(stop)
                    );
                    let _ = writeln!(
                        commands,
                        "meas tran i{s} AVG i({src}) FROM={} TO={}",
                        si(stop - 0.05 * window),
                        si(stop)
                    );
                }
                let mut echo = format!("echo \"RES d{key} $&d\"\necho \"RES lo{key} $&tlo\"\necho \"RES hi{key} $&thi\"\n");
                for &(s, _) in &supplies {
                    let _ = write!(
                        echo,
                        "echo \"RES q{s}_{key} $&q{s}\"\necho \"RES i{s}_{key} $&i{s}\"\n"
                    );
                }
                commands.push_str(&echo);
                commands.push_str("destroy all\n");
            }
            let results = session.run(&commands)?;
            for (li, &load) in c.loads_pf.iter().enumerate() {
                let key = format!("{si_}_{li}");
                let at = || format!("{label} at slew {slew} ns, load {load} pF");
                let delay = need(&results, &format!("d{key}")).ok_or_else(|| {
                    self.error(format!(
                        "{}: {} did not {} within {} ns of the edge (characterization.settle_ns, if it is only slow)",
                        at(),
                        arc.to,
                        output.name(),
                        c.settle_ns
                    ))
                })?;
                let (lo, hi) = (
                    need(&results, &format!("lo{key}")),
                    need(&results, &format!("hi{key}")),
                );
                let (Some(lo), Some(hi)) = (lo, hi) else {
                    return Err(self.error(format!(
                        "{}: {} never completed its swing after the edge; if it was still \
                         moving when the edge came, the preparation vectors need longer \
                         (characterization.vector_ns)",
                        at(),
                        arc.to
                    )));
                };
                let mut energy = 0.0;
                for &(s, volts) in &supplies {
                    let q = need(&results, &format!("q{s}_{key}"));
                    let i = need(&results, &format!("i{s}_{key}"));
                    let (Some(q), Some(i)) = (q, i) else {
                        return Err(self.error(format!("{}: supply charge was not measured", at())));
                    };
                    // Delivered charge is minus the current into the source.
                    energy += volts * (-q + i * window);
                }
                let swing = out_hi - out_lo;
                let switching = 0.5 * load * 1e-12 * swing * swing;
                grid.delay.push(delay * 1e9);
                grid.transition.push((hi - lo).abs() * 1e9);
                grid.energy.push((energy - switching) * 1e12);
            }
        }
        Ok(grid)
    }
}

/// Rise and fall capacitance of one pin, pF.
#[derive(Debug, Clone, Copy, Default)]
pub struct Cap {
    /// Charge drawn while the pin rises, over the swing, pF.
    pub rise: f64,
    /// Charge returned while the pin falls, over the swing, pF.
    pub fall: f64,
}

/// A state the pin is switched in, and the edge it switches with.
pub struct Context {
    /// The preparation sequence that sets up the state.
    pub vectors: Vec<Vector>,
    /// The pin's first edge in that state; the measurement then switches it
    /// back.
    pub edge: Edge,
}

impl Bench<'_> {
    /// The states each digital input switches in: its arcs' cases, else the
    /// leakage states, else everything low.
    pub fn contexts(&self, pin: &str) -> Vec<Context> {
        let spec = self.spec;
        let mut out = Vec::new();
        for arc in &spec.arcs {
            for case in &arc.cases {
                if arc.from == pin && !arc.kind.is_constraint() {
                    out.push(Context {
                        vectors: case.vectors.clone(),
                        edge: input_edge(arc, case),
                    });
                }
                if arc.to == pin && arc.kind.is_constraint() {
                    out.push(Context {
                        vectors: case.vectors.clone(),
                        edge: case.data.expect("a constraint case has a data edge"),
                    });
                }
            }
        }
        if out.is_empty() {
            let states = if spec.leakage_states.is_empty() {
                vec![vec![self.all_low()]]
            } else {
                spec.leakage_states.clone()
            };
            for vectors in states {
                let last = vectors.iter().rev().find_map(|v| v.get(pin).copied());
                let low = last.is_none_or(|l| l == Level::Low);
                out.push(Context {
                    vectors,
                    edge: if low { Edge::Rise } else { Edge::Fall },
                });
            }
        }
        out
    }

    /// Every digital input low: the state used when the spec names none.
    pub fn all_low(&self) -> Vector {
        self.spec
            .pins
            .iter()
            .filter(|p| p.role.is_digital_input())
            .map(|p| (p.name.clone(), Level::Low))
            .collect()
    }

    /// Charge-integrated rise and fall capacitance of a digital input: in each
    /// of its [`contexts`](Bench::contexts), the edge and then back, both
    /// measured at the middle input slew of `slews_ns`, then averaged over the
    /// contexts.
    ///
    /// # Errors
    ///
    /// [`SimError::Measure`] when a charge was not measured, or any error of
    /// [`Session::run`].
    pub fn input_cap(&self, session: &mut Session, pin: &str) -> Result<Cap, SimError> {
        let c = &self.spec.characterization;
        let i = index_of(self.spec, pin);
        let slew = c.slews_ns[c.slews_ns.len() / 2];
        let ramp = self.ramp(slew);
        let settle = c.settle_ns.min(2.0) * 1e-9;
        let (lo, hi) = rails(self.spec, self.corner, i);
        let (mut rise, mut fall) = (Vec::new(), Vec::new());
        let mut commands = String::new();
        let contexts = self.contexts(pin);
        let mut windows = Vec::new();
        for (k, context) in contexts.iter().enumerate() {
            let (mut waves, start) = self.prepare(&context.vectors);
            let wave = waves[i].as_mut().expect("an input is driven");
            let first = context.edge;
            let t0 = start + c.vector_ns * 1e-9;
            let t1 = t0 + PREP_RAMP + settle;
            let t2 = t1 + ramp + settle;
            let stop = t2 + ramp + settle;
            let (a, b) = match first {
                Edge::Rise => (lo, hi),
                Edge::Fall => (hi, lo),
            };
            // A context whose state already holds the pin at the far rail
            // starts from the near one instead.
            if (value(wave) - a).abs() > 1e-9 {
                ramp_to(wave, t0, PREP_RAMP, a);
            }
            ramp_to(wave, t1, ramp, b);
            ramp_to(wave, t2, ramp, a);
            self.drive(&waves, None, &mut commands);
            self.tran(stop, &mut commands);
            let src = pin_source(i);
            // The charge the pin draws while it swings: what its driver sees.
            for (name, from) in [("qa", t1), ("qb", t2)] {
                let _ = writeln!(
                    commands,
                    "meas tran {name} INTEG i({src}) FROM={} TO={}",
                    si(from),
                    si(from + ramp)
                );
            }
            let _ = writeln!(
                commands,
                "meas tran qi AVG i({src}) FROM={} TO={}",
                si(t1 - 0.5 * settle),
                si(t1)
            );
            let _ = writeln!(
                commands,
                "echo \"RES qa{k} $&qa\"\necho \"RES qb{k} $&qb\"\necho \"RES qi{k} $&qi\"\ndestroy all"
            );
            windows.push((first, ramp));
        }
        let results = session.run(&commands)?;
        for (k, &(first, window)) in windows.iter().enumerate() {
            let get = |key: &str| {
                need(&results, &format!("{key}{k}")).ok_or_else(|| {
                    self.error(format!("capacitance of {pin}: the charge was not measured"))
                })
            };
            // Less the static current the pin drew before it moved.
            let base = get("qi")? * window;
            let qa = -(get("qa")? - base);
            let qb = -(get("qb")? - base);
            let swing = hi - lo;
            let (up, down) = match first {
                Edge::Rise => (qa / swing, -qb / swing),
                Edge::Fall => (qb / swing, -qa / swing),
            };
            rise.push(up * 1e12);
            fall.push(down * 1e12);
        }
        let mean =
            |v: &[f64]| v.iter().sum::<f64>() / f64::from(u32::try_from(v.len()).expect("few"));
        Ok(Cap {
            rise: mean(&rise),
            fall: mean(&fall),
        })
    }

    /// An analog pin's small-signal capacitance, pF, at its bias and
    /// `analog_frequency_hz`: `−Im(I)/ω`, Miller included. Every other pin
    /// sits in the final state of the spec's first `leakage_states` entry, or
    /// all digital inputs low when the spec gives none.
    ///
    /// # Errors
    ///
    /// [`SimError::Measure`] when the AC analysis gave no value, or any error
    /// of [`Session::run`].
    pub fn analog_cap(&self, session: &mut Session, pin: &str) -> Result<f64, SimError> {
        let c = &self.spec.characterization;
        let i = index_of(self.spec, pin);
        let state = self
            .spec
            .leakage_states
            .first()
            .map_or_else(|| self.all_low(), |sequence| merged(sequence));
        let (waves, _) = self.prepare(&[state]);
        let mut commands = String::new();
        self.drive(&waves, None, &mut commands);
        let src = pin_source(i);
        let f = si(c.analog_frequency_hz);
        let _ = writeln!(
            commands,
            "alter @{src}[acmag] = 1\nac lin 1 {f} {f}\nlet cpin = -imag({src}#branch)/(2*pi*{f})\necho \"RES c $&cpin\"\ndestroy all\nalter @{src}[acmag] = 0"
        );
        let results = session.run(&commands)?;
        need(&results, "c")
            .map(|farads| farads * 1e12)
            .ok_or_else(|| self.error(format!("capacitance of analog pin {pin} was not measured")))
    }

    /// Static power in each state, nW, in `states` order: every supply's
    /// `V·I`, summed. A one-vector state is a DC operating point; a sequence
    /// is simulated and its supply current averaged over the last tenth of
    /// `settle_ns` after it, as a latch only holds a state it was driven into.
    ///
    /// # Errors
    ///
    /// [`SimError::Measure`] when a supply current was not measured (the
    /// operating point or transient did not converge), or any error of
    /// [`Session::run`].
    pub fn leakage(
        &self,
        session: &mut Session,
        states: &[Vec<Vector>],
    ) -> Result<Vec<f64>, SimError> {
        let supplies: Vec<(usize, f64)> = self
            .spec
            .pins
            .iter()
            .enumerate()
            .filter(|(_, p)| p.role.is_supply())
            .map(|(i, p)| (i, self.corner.supplies[&p.name]))
            .collect();
        let mut commands = String::new();
        let settle = self.spec.characterization.settle_ns * 1e-9;
        for (k, state) in states.iter().enumerate() {
            let (waves, end) = self.prepare(state);
            self.drive(&waves, None, &mut commands);
            if state.len() == 1 {
                commands.push_str("op\n");
                for &(s, _) in &supplies {
                    let _ = writeln!(
                        commands,
                        "let l{s} = {}#branch\necho \"RES l{s}_{k} $&l{s}\"",
                        pin_source(s)
                    );
                }
            } else {
                let stop = end + settle;
                self.tran(stop, &mut commands);
                for &(s, _) in &supplies {
                    let _ = writeln!(
                        commands,
                        "meas tran l{s} AVG i({}) FROM={} TO={}\necho \"RES l{s}_{k} $&l{s}\"",
                        pin_source(s),
                        si(stop - 0.1 * settle),
                        si(stop)
                    );
                }
            }
            commands.push_str("destroy all\n");
        }
        let results = session.run(&commands)?;
        let mut out = Vec::with_capacity(states.len());
        for (k, state) in states.iter().enumerate() {
            let mut watts = 0.0;
            for &(s, volts) in &supplies {
                let i = need(&results, &format!("l{s}_{k}"))
                    .ok_or_else(|| self.error(unmeasured_leakage(k, state)))?;
                watts += volts * -i;
            }
            out.push(watts * 1e9);
        }
        Ok(out)
    }
}

impl Bench<'_> {
    /// Setup or hold of one constraint case at one table point, ns: clock
    /// transition `clock_slew` and data transition `data_slew`, both ns.
    ///
    /// The offset is between the midpoints of the clock and data ramps:
    /// the data edge that far before the clock for setup, after it for hold.
    /// A trial at an offset passes when the case's check pin ends on the same
    /// side of its `output_threshold_pct` as the value it should capture, and
    /// its clock-to-check delay stays within `pushout_pct` of the delay with
    /// the data a whole `constraint_window_ns` clear. The result is the
    /// smallest passing offset in `±constraint_window_ns`, found by bisection
    /// to [`Effort::resolution`] and taken from the passing end, so it is
    /// pessimistic by at most that and never optimistic. Bisection assumes
    /// passing is monotone in the offset. A capture that passes even at
    /// `-constraint_window_ns` returns that bound. A transient that does not finish, a latch caught
    /// metastable, is retried at `reltol = 1e-3` and then counted as a
    /// failed capture, which can only lengthen the constraint.
    ///
    /// # Errors
    ///
    /// [`SimError::Measure`] when the capture fails even with the data a
    /// whole window clear of the clock, so the case describes no capture.
    /// Any error of [`Session::run`].
    pub fn constraint_point(
        &self,
        session: &mut Session,
        arc: &ArcSpec,
        case: &CaseSpec,
        clock_slew: f64,
        data_slew: f64,
        label: &str,
    ) -> Result<f64, SimError> {
        let c = &self.spec.characterization;
        let window = c.constraint_window_ns * 1e-9;
        let mut probe =
            |tau: f64| self.constraint_trial(session, arc, case, clock_slew, data_slew, tau);
        let relaxed = probe(window)?;
        let reference = match relaxed {
            Trial::Pass(delay) => delay,
            Trial::Fail => {
                return Err(self.error(format!(
                    "{label} at clock {clock_slew} ns, data {data_slew} ns: the check fails even \
                     with the data {} ns clear of the clock, so the case describes no capture",
                    c.constraint_window_ns
                )))
            }
        };
        let passes = |trial: Trial| match trial {
            Trial::Fail => false,
            Trial::Pass(delay) => match (delay, reference) {
                (Some(d), Some(r)) => d <= r * (1.0 + c.pushout_pct / 100.0),
                (None, Some(_)) => false,
                (_, None) => true,
            },
        };
        let (mut lo, mut hi) = (-window, window);
        let mut probe =
            |tau: f64| self.constraint_trial(session, arc, case, clock_slew, data_slew, tau);
        if passes(probe(lo)?) {
            return Ok(lo * 1e9);
        }
        while hi - lo > self.effort.resolution {
            let mid = 0.5 * (lo + hi);
            if passes(probe(mid)?) {
                hi = mid;
            } else {
                lo = mid;
            }
        }
        Ok(hi * 1e9)
    }

    /// One trial: the data edge `tau` before (setup) or after (hold) the clock.
    fn constraint_trial(
        &self,
        session: &mut Session,
        arc: &ArcSpec,
        case: &CaseSpec,
        clock_slew: f64,
        data_slew: f64,
        tau: f64,
    ) -> Result<Trial, SimError> {
        let spec = self.spec;
        let c = &spec.characterization;
        let (clock, data) = (index_of(spec, &arc.from), index_of(spec, &arc.to));
        let check = case.check.as_ref().expect("a constraint case has a check");
        let watch = index_of(spec, &check.pin);
        let clock_edge = arc.kind.clock_edge().expect("a constraint is clocked");
        let data_edge = case.data.expect("a constraint case has a data edge");
        let (clock_ramp, data_ramp) = (self.ramp(clock_slew), self.ramp(data_slew));
        let window = c.constraint_window_ns * 1e-9;
        let (mut waves, start) = self.prepare(&case.vectors);
        let clock_mid = start + c.vector_ns * 1e-9 + window + data_ramp + clock_ramp;
        let data_mid = if arc.kind.is_hold() {
            clock_mid + tau
        } else {
            clock_mid - tau
        };
        let target = |i: usize, edge: Edge| {
            let (lo, hi) = rails(spec, self.corner, i);
            if edge == Edge::Rise {
                hi
            } else {
                lo
            }
        };
        let clock_start = clock_mid - 0.5 * clock_ramp;
        let data_start = data_mid - 0.5 * data_ramp;
        // Two edges on the timeline, in time order.
        let mut edges = [
            (clock_start, clock, clock_ramp, target(clock, clock_edge)),
            (data_start, data, data_ramp, target(data, data_edge)),
        ];
        edges.sort_by(|a, b| a.0.total_cmp(&b.0));
        for (t, pin, ramp, v) in edges {
            let wave = waves[pin].as_mut().expect("clock and data are driven");
            ramp_to(wave, t, ramp, v);
        }
        let stop = clock_mid + window + c.settle_ns * 1e-9;
        let mut commands = String::new();
        self.drive(&waves, None, &mut commands);
        self.tran(stop, &mut commands);
        let want = self.volts(watch, check.value);
        let vth = self.threshold(watch, c.output_threshold_pct);
        let rising = want > vth;
        let node = crate::liberty::spice::pin_node(watch);
        let _ = writeln!(
            commands,
            "meas tran vend FIND v({node}) AT={}\nmeas tran tchk WHEN v({node})={} TD={} {}=LAST\necho \"RES v $&vend\"\necho \"RES t $&tchk\"\ndestroy all",
            si(stop),
            si(vth),
            si(clock_start),
            if rising { "RISE" } else { "FALL" }
        );
        let mut results = session.run(&commands)?;
        if need(&results, "v").is_none() {
            // A transient that did not finish is a latch caught at its
            // metastable point. Retried at a looser tolerance, and if it still
            // cannot finish, counted as a failed capture: that can only
            // lengthen the constraint, never shorten it.
            let relaxed = format!(
                "option reltol=1e-3\n{commands}option reltol={}\n",
                si(self.reltol)
            );
            results = session.run(&relaxed)?;
        }
        let Some(end) = need(&results, "v") else {
            return Ok(Trial::Fail);
        };
        if (end > vth) != rising {
            return Ok(Trial::Fail);
        }
        Ok(Trial::Pass(need(&results, "t").map(|t| t - clock_mid)))
    }
}

/// A trial's outcome: failed, or passed with the clock-to-check delay (if the
/// check pin moved after the clock).
#[derive(Debug, Clone, Copy)]
enum Trial {
    Fail,
    Pass(Option<f64>),
}

/// Monte Carlo prologue: redraws every statistical parameter of the loaded
/// circuit, seeding the simulator with `sample + 1` so a sample number names
/// one draw.
///
/// # Errors
///
/// Any error of [`Session::run`].
pub fn redraw(session: &mut Session, sample: u32) -> Result<(), SimError> {
    session
        .run(&format!("setseed {}\nreset\n", sample + 1))
        .map(|_| ())
}

/// The sample standard deviation (divisor `n − 1`) of each column across
/// `samples`, one value per column. Fewer than two samples give zeros.
///
/// # Panics
///
/// Panics if a row is shorter than the first.
pub fn sigma(samples: &[Vec<f64>]) -> Vec<f64> {
    let n = samples.len();
    if n < 2 {
        return vec![0.0; samples.first().map_or(0, Vec::len)];
    }
    let count = f64::from(u32::try_from(n).expect("few samples"));
    (0..samples[0].len())
        .map(|k| {
            let mean = samples.iter().map(|s| s[k]).sum::<f64>() / count;
            let var = samples.iter().map(|s| (s[k] - mean).powi(2)).sum::<f64>() / (count - 1.0);
            var.sqrt()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{set, sigma, unmeasured_leakage};

    /// A leakage state of one vector is a DC operating point and a sequence
    /// a transient, so a missing supply current names the analysis that
    /// produced neither (F35: it always blamed the operating point).
    ///
    /// Oracle: `docs/liberty.md`, Leakage: "A one-vector state is a DC
    /// operating point. A sequence is simulated", so each message names its own
    /// analysis.
    #[test]
    fn a_missing_leakage_names_the_analysis_it_came_from() {
        let vector = crate::liberty::spec::Vector::new();
        let dc = unmeasured_leakage(0, std::slice::from_ref(&vector));
        assert!(dc.contains("DC operating point"), "{dc}");
        let sequence = unmeasured_leakage(1, &[vector.clone(), vector]);
        assert!(
            sequence.contains("transient") && !sequence.contains("operating point"),
            "{sequence}"
        );
    }

    /// Oracle: hand-derived from `set`'s doc: the first point is the value from
    /// time zero, a change at 2 ns holds 0 until then and reaches 1.8
    /// `PREP_RAMP` later, and setting 1.8 again adds no point.
    #[test]
    fn a_wave_holds_then_ramps_and_skips_a_repeat() {
        let mut wave = Vec::new();
        set(&mut wave, 0.0, 0.0);
        set(&mut wave, 2e-9, 1.8);
        set(&mut wave, 4e-9, 1.8);
        assert_eq!(
            wave,
            vec![(0.0, 0.0), (2e-9, 0.0), (2e-9 + super::PREP_RAMP, 1.8)]
        );
    }

    /// Oracle: closed form. The sample standard deviation (n - 1) of {1, 3} is
    /// sqrt(2), and of {5, 5} is 0.
    #[test]
    fn sigma_is_the_sample_standard_deviation() {
        let s = sigma(&[vec![1.0, 5.0], vec![3.0, 5.0]]);
        assert!((s[0] - 2f64.sqrt()).abs() < 1e-12 && s[1] == 0.0);
    }
}
