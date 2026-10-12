//! The simulator: the macro as a subcircuit, one testbench deck per corner,
//! and a pool of sessions, each a series of ngspice batch runs of that deck.
//!
//! Every pin is driven by a source the characterizer rewrites (`alter`) before
//! each analysis. A measurement is a block of commands, run as the deck's
//! `.control` section in one batch run, whose results come back as
//! `RES <key> <value>` lines; a value the simulator could not measure comes
//! back empty and reads as `None`, never as zero.
//!
//! The simulator must be ngspice, run in batch mode (`ngspice -b`, the
//! ngspice manual's "Batch mode", for unattended runs: it opens no graphics
//! interface, so it runs on a machine with no display), found as
//! [`Simulator::binary`] on `PATH`. Every value written to it is in SI base
//! units (seconds, volts, ohms, farads), except device lengths and areas,
//! which are divided by [`Simulator::scale`] and its square for
//! `.option scale` to multiply back.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use crate::liberty::circuit::{Circuit, Param};
use crate::liberty::spec::{CornerSpec, MacroSpec, Role, Simulator};

/// Why a simulation gave no answer.
#[derive(Debug, Clone, thiserror::Error)]
pub enum SimError {
    /// The binary (`.0`) could not be started, usually because it is not on
    /// `PATH`; `.1` is the operating system's reason.
    #[error("could not start {0}: {1}")]
    Spawn(String, String),
    /// The process closed its output or its input mid-run: it crashed, or the
    /// deck made it quit. Its standard error is in the log.
    #[error("the simulator stopped answering (corner {corner}): {why}; its log is {log}")]
    Died {
        /// The corner whose deck was loaded.
        corner: String,
        /// What went wrong: the run that stopped short, or the pipe error.
        why: String,
        /// The path of the session's log file.
        log: String,
    },
    /// The simulator ran but a value could not be measured: an output that
    /// never switched, an operating point that did not converge, a capture
    /// that never passes. `why` names the arc, case and table point.
    #[error("corner {corner}: {why}")]
    Measure {
        /// The corner being measured.
        corner: String,
        /// What was not measured, and where.
        why: String,
    },
    /// The session's log file could not be created.
    #[error("io: {0}")]
    Io(String),
}

/// A node name; node 0 is ground.
fn node(n: u32) -> String {
    if n == 0 {
        "0".to_owned()
    } else {
        format!("n{n}")
    }
}

/// A number as the simulator reads it: exponent notation with the shortest
/// digits that round-trip (`1.8e0`), never an SI suffix, which SPICE reads
/// without case (`M` is milli, not mega).
pub fn si(value: f64) -> String {
    format!("{value:e}")
}

/// Appends the macro as `.subckt <cell>`, ports in spec order. Device cards
/// are `<prefix>d<i>`, wire resistors `Rw<i>` and capacitors `Cw<i>`; node 0
/// is ground and every other node `n<k>`. Lengths are written divided by the
/// simulator's `scale`, areas by its square.
pub fn write_subckt(circuit: &Circuit, spec: &MacroSpec, sim: &Simulator, out: &mut String) {
    let _ = write!(out, ".subckt {}", spec.cell);
    for &n in &circuit.pin_node {
        let _ = write!(out, " {}", node(n));
    }
    out.push('\n');
    for (i, device) in circuit.devices.iter().enumerate() {
        let _ = write!(out, "{}d{i}", sim.prefix);
        for &n in &device.nodes {
            let _ = write!(out, " {}", node(n));
        }
        let _ = write!(out, " {}", device.model);
        for &(key, value) in &device.params {
            let v = match value {
                Param::Length(m) => si(m / sim.scale),
                Param::Area(m2) => si(m2 / (sim.scale * sim.scale)),
                Param::Count(n) => n.to_string(),
            };
            let _ = write!(out, " {key}={v}");
        }
        out.push('\n');
    }
    for (i, &(a, b, ohms)) in circuit.resistors.iter().enumerate() {
        let _ = writeln!(out, "Rw{i} {} {} {}", node(a), node(b), si(ohms));
    }
    for (i, &(a, b, farads)) in circuit.capacitors.iter().enumerate() {
        let _ = writeln!(out, "Cw{i} {} {} {}", node(a), node(b), si(farads));
    }
    let _ = writeln!(out, ".ends {}", spec.cell);
}

/// The `.option scale` line, or `None` when the scale is exactly one.
pub fn scale_option(sim: &Simulator) -> Option<String> {
    #[expect(clippy::float_cmp, reason = "1.0 is the exact no-scale value")]
    let unscaled = sim.scale == 1.0;
    (!unscaled).then(|| format!(".option scale={}", si(sim.scale)))
}

/// The testbench node of spec pin `i`: `p<i>`.
pub fn pin_node(i: usize) -> String {
    format!("p{i}")
}
/// The voltage source on spec pin `i`, `vp<i>`: DC on a supply, a PWL the
/// characterizer rewrites on an input, clock or analog pin. Its branch
/// current is what charge and leakage are read from.
pub fn pin_source(i: usize) -> String {
    format!("vp{i}")
}
/// The load capacitor on output pin `i`, `cp<i>`: 1 aF in the deck until a
/// measurement sets it.
pub fn pin_load(i: usize) -> String {
    format!("cp{i}")
}

/// Simulator accuracy: tolerances every analysis runs at.
#[derive(Debug, Clone, Copy)]
pub struct Precision {
    /// Relative tolerance of every current and voltage.
    pub reltol: f64,
    /// Absolute current tolerance, A.
    pub abstol: f64,
    /// Absolute voltage tolerance, V.
    pub vntol: f64,
    /// Truncation-error overestimate factor; 1 trusts the error estimate
    /// fully, so steps shrink where the waveform bends and nowhere else.
    pub trtol: f64,
}

/// Appends one corner's testbench: its model lines (`mc_models` when
/// `statistical`), the macro as `xdut`, a DC source on every supply, a
/// rewritable PWL source on every input, clock and analog pin (an analog pin
/// starts at its bias), and a load on every output. It ends in `.end`, and
/// sets no analysis: [`Session::run`] sends those.
///
/// # Panics
///
/// Panics if `corner` gives a supply pin no voltage, which
/// [`parse`](crate::liberty::spec::parse) refuses.
pub fn write_deck(
    spec: &MacroSpec,
    corner: &CornerSpec,
    subckt: &str,
    sim: &Simulator,
    precision: Precision,
    statistical: bool,
    out: &mut String,
) {
    let _ = writeln!(out, "* {} at {}", spec.cell, corner.name);
    let models = if statistical {
        &corner.mc_models
    } else {
        &corner.models
    };
    for line in models {
        let _ = writeln!(out, "{line}");
    }
    if let Some(line) = scale_option(sim) {
        let _ = writeln!(out, "{line}");
    }
    let _ = writeln!(
        out,
        ".option reltol={} abstol={} vntol={} trtol={}",
        si(precision.reltol),
        si(precision.abstol),
        si(precision.vntol),
        si(precision.trtol)
    );
    for option in &sim.options {
        let _ = writeln!(out, ".option {option}");
    }
    let _ = writeln!(out, ".temp {}", si(corner.temperature));
    out.push_str(subckt);
    let _ = write!(out, "xdut");
    for i in 0..spec.pins.len() {
        let _ = write!(out, " {}", pin_node(i));
    }
    let _ = writeln!(out, " {}", spec.cell);
    for (i, pin) in spec.pins.iter().enumerate() {
        match pin.role {
            r if r.is_supply() => {
                let _ = writeln!(
                    out,
                    "{} {} 0 DC {}",
                    pin_source(i),
                    pin_node(i),
                    si(corner.supplies[&pin.name])
                );
            }
            Role::Output => {
                let _ = writeln!(out, "{} {} 0 1e-18", pin_load(i), pin_node(i));
            }
            _ => {
                let start = pin.bias.unwrap_or(0.0);
                let _ = writeln!(
                    out,
                    "{} {} 0 PWL(0 {}) AC 0",
                    pin_source(i),
                    pin_node(i),
                    si(start)
                );
            }
        }
    }
    out.push_str(".end\n");
}

/// A corner's deck, run in ngspice batch mode once per [`Session::run`]. The
/// state a run leaves (`alter`ed sources, `option`s, a `setseed` and `reset`)
/// is replayed before the next run's commands, so a session behaves as one
/// simulator that keeps it; analyses, measurements and vectors are not.
pub struct Session {
    binary: String,
    /// The deck without its closing `.end`.
    deck: String,
    /// Every state command run so far, in order.
    state: String,
    serial: u64,
    corner: String,
    log: PathBuf,
}

/// The ngspice commands whose effect outlives the run that issues them: a
/// source or load rewritten, an option, the random seed and the circuit
/// redrawn from it.
const STATE_COMMANDS: [&str; 5] = ["alter", "altermod", "option", "setseed", "reset"];

/// Appends to `state` the [`STATE_COMMANDS`] lines of `commands`, in order. A
/// setting rewritten (`alter X = …`, `option reltol=…`) replaces the line
/// that set it before, so the state a session replays stays the size of the
/// circuit's settings however many runs it has made.
fn remember(state: &mut String, commands: &str) {
    for line in commands.lines() {
        let word = line.split_whitespace().next().unwrap_or_default();
        if !STATE_COMMANDS.contains(&word) {
            continue;
        }
        if let Some((target, _)) = line.split_once('=') {
            let target = target.trim_end();
            let mut kept = String::with_capacity(state.len());
            for old in state.lines() {
                if old.split_once('=').map(|(t, _)| t.trim_end()) != Some(target) {
                    kept.push_str(old);
                    kept.push('\n');
                }
            }
            *state = kept;
        }
        state.push_str(line);
        state.push('\n');
    }
}

/// Measured values by key; `None` is a measurement that failed.
pub type Results = BTreeMap<String, Option<f64>>;

impl Session {
    /// Reads `deck` and runs it once, with no commands, in `sim.binary -b`,
    /// its standard error going to `log`.
    ///
    /// # Errors
    ///
    /// [`SimError::Io`] when `deck` cannot be read or `log` created,
    /// [`SimError::Spawn`] when the binary cannot be started, and
    /// [`SimError::Died`] when it stops before the end of the deck.
    pub fn start(
        sim: &Simulator,
        deck: &Path,
        corner: &str,
        log: PathBuf,
    ) -> Result<Self, SimError> {
        let io = |e: std::io::Error| SimError::Io(e.to_string());
        let text = std::fs::read_to_string(deck).map_err(io)?;
        std::fs::File::create(&log).map_err(io)?;
        let body = text.trim_end().strip_suffix(".end").unwrap_or(&text);
        let mut session = Self {
            binary: sim.binary.clone(),
            deck: body.to_owned(),
            state: String::new(),
            serial: 0,
            corner: corner.to_owned(),
            log,
        };
        session.run("")?;
        Ok(session)
    }

    /// Runs the deck in ngspice batch mode with the state commands of every
    /// earlier run, then `commands`, as its `.control` section, and returns
    /// every `RES <key> <value>` line they echoed. A key echoed twice keeps
    /// its last value; a value that does not parse or is not finite reads
    /// `None`. The run's deck is written beside the log and kept only when
    /// the run fails, its output then appended to the log. There is no
    /// timeout: a simulation that never ends blocks the caller.
    ///
    /// # Errors
    ///
    /// [`SimError::Io`] when the run's deck or the log cannot be written,
    /// [`SimError::Spawn`] when the binary cannot be started, and
    /// [`SimError::Died`] when it stops before the last command.
    pub fn run(&mut self, commands: &str) -> Result<Results, SimError> {
        self.serial += 1;
        let marker = format!("@@END{}", self.serial);
        let io = |e: std::io::Error| SimError::Io(e.to_string());
        let path = self.log.with_extension(format!("{}.cir", self.serial));
        let text = format!(
            "{}\n.control\nset noaskquit\n{}{commands}\necho \"{marker}\"\n.endc\n.end\n",
            self.deck, self.state
        );
        std::fs::write(&path, text).map_err(io)?;
        let append = || {
            std::fs::OpenOptions::new()
                .append(true)
                .open(&self.log)
                .map_err(io)
        };
        let output = Command::new(&self.binary)
            .arg("-b")
            .arg(&path)
            .env("OMP_NUM_THREADS", "1")
            .stdin(Stdio::null())
            .stderr(append()?)
            .output()
            .map_err(|e| SimError::Spawn(self.binary.clone(), e.to_string()))?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.lines().any(|line| line.trim_end() == marker) {
            let _ = writeln!(
                append()?,
                "---- {} ({})\n{stdout}",
                path.display(),
                output.status
            );
            return Err(SimError::Died {
                corner: self.corner.clone(),
                why: format!("{} ended before its last command", path.display()),
                log: self.log.display().to_string(),
            });
        }
        let _ = std::fs::remove_file(&path);
        let mut results = Results::new();
        for line in stdout.lines() {
            if let Some(rest) = line.trim_end().strip_prefix("RES ") {
                let mut words = rest.split_whitespace();
                if let Some(key) = words.next() {
                    let value = words.next().and_then(|w| w.parse::<f64>().ok());
                    results.insert(key.to_owned(), value.filter(|v| v.is_finite()));
                }
            }
        }
        remember(&mut self.state, commands);
        Ok(results)
    }

    /// The name of the corner whose deck this session loaded.
    pub fn corner(&self) -> &str {
        &self.corner
    }
}

/// A unit of work run on one session. It must leave the session's options and
/// source settings as it found them, because the next task on that session
/// starts from whatever it left.
pub type Task<'a, T> = Box<dyn FnOnce(&mut Session) -> Result<T, SimError> + Send + 'a>;

/// Runs `tasks` on `workers` sessions of `deck`, each its own ngspice
/// process, and returns their results in task order.
///
/// `min(workers, tasks)` sessions start, at least one, and each loads the
/// deck once. Tasks are handed out in order to whichever session is free.
/// Session `w` logs to the deck's path with extension `<w>.log`. No task
/// means no process.
///
/// # Errors
///
/// The first error any session or task returns. It stops every session
/// before its next task; tasks already running finish first.
pub fn run_pool<'a, T: Send>(
    sim: &Simulator,
    deck: &Path,
    corner: &str,
    workers: usize,
    tasks: Vec<Task<'a, T>>,
) -> Result<Vec<T>, SimError> {
    let count = tasks.len();
    if count == 0 {
        return Ok(Vec::new());
    }
    let queue: Mutex<Vec<Option<Task<'a, T>>>> = Mutex::new(tasks.into_iter().map(Some).collect());
    let results: Mutex<Vec<Option<T>>> = Mutex::new((0..count).map(|_| None).collect());
    // The first failure stops every worker and is what the pool returns.
    let failure: Mutex<Option<SimError>> = Mutex::new(None);
    let next = AtomicUsize::new(0);
    let fail = |error: SimError| {
        let mut slot = failure.lock().expect("unpoisoned");
        slot.get_or_insert(error);
    };
    std::thread::scope(|scope| {
        for w in 0..workers.min(count).max(1) {
            let (queue, results, next, failure, fail) = (&queue, &results, &next, &failure, &fail);
            scope.spawn(move || {
                let log = deck.with_extension(format!("{w}.log"));
                let mut session = match Session::start(sim, deck, corner, log) {
                    Ok(session) => session,
                    Err(e) => return fail(e),
                };
                while failure.lock().expect("unpoisoned").is_none() {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= count {
                        return;
                    }
                    let task = queue.lock().expect("unpoisoned")[i]
                        .take()
                        .expect("taken once");
                    match task(&mut session) {
                        Ok(value) => results.lock().expect("unpoisoned")[i] = Some(value),
                        Err(e) => return fail(e),
                    }
                }
            });
        }
    });
    if let Some(error) = failure.into_inner().expect("unpoisoned") {
        return Err(error);
    }
    Ok(results
        .into_inner()
        .expect("unpoisoned")
        .into_iter()
        .map(|r| r.expect("with no failure every task ran"))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::remember;

    /// Oracle: construct-from-answer. A batch run keeps nothing, so a session
    /// replays the state its earlier runs left: the sources and loads they
    /// `alter`ed, the `option`s they set, the seed and the circuit redrawn
    /// from it, in order. Analyses, measurements, echoes and vector commands
    /// are not state and are not replayed. A setting written again replaces
    /// its earlier line, so the last write wins and the state stays small.
    #[test]
    fn a_session_replays_what_earlier_runs_set_and_nothing_else() {
        let mut state = String::new();
        remember(
            &mut state,
            "alter @vp0[pwl] = [ 0 0 1e-9 1.8 ]\nalter cp1 = 1e-15\ntran 1e-12 2e-9\n\
             meas tran d WHEN v(p1)=0.9\necho \"RES d $&d\"\ndestroy all\n",
        );
        remember(
            &mut state,
            "setseed 3\nreset\noption reltol=1e-3\nalter cp1 = 2e-15\nop\nlet p = 1\n",
        );
        remember(&mut state, "option reltol=1e-6\n");
        assert_eq!(
            state,
            "alter @vp0[pwl] = [ 0 0 1e-9 1.8 ]\nsetseed 3\nreset\nalter cp1 = 2e-15\n\
             option reltol=1e-6\n"
        );
    }
}
