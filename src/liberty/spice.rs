//! The simulator: the macro as a subcircuit, one testbench deck per corner,
//! and a pool of persistent ngspice processes driven over a pipe.
//!
//! Every pin is driven by a source the characterizer rewrites (`alter`) before
//! each analysis, so a corner's models load once per process, not once per
//! measurement. A measurement is a block of commands whose results come back as
//! `RES <key> <value>` lines; a value the simulator could not measure comes
//! back empty and reads as `None`, never as zero.
//!
//! The simulator must be ngspice, run in pipe mode (`ngspice -p`), found as
//! [`Simulator::binary`] on `PATH`. Every value written to it is in SI base
//! units (seconds, volts, ohms, farads), except device lengths and areas,
//! which are divided by [`Simulator::scale`] and its square for
//! `.option scale` to multiply back.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
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
        /// What the pipe reported.
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

/// One ngspice process with a corner's deck loaded. Dropping it sends `quit`
/// and waits for the process to exit.
pub struct Session {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    serial: u64,
    corner: String,
    log: PathBuf,
}

/// Measured values by key; `None` is a measurement that failed.
pub type Results = BTreeMap<String, Option<f64>>;

impl Session {
    /// Starts `sim.binary -p` with its standard error going to `log`, and
    /// sources `deck`.
    ///
    /// # Errors
    ///
    /// [`SimError::Io`] when `log` cannot be created, [`SimError::Spawn`]
    /// when the binary cannot be started, and [`SimError::Died`] when it
    /// exits while loading the deck.
    pub fn start(
        sim: &Simulator,
        deck: &Path,
        corner: &str,
        log: PathBuf,
    ) -> Result<Self, SimError> {
        let stderr = std::fs::File::create(&log).map_err(|e| SimError::Io(e.to_string()))?;
        let mut child = Command::new(&sim.binary)
            .arg("-p")
            .env("OMP_NUM_THREADS", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(stderr)
            .spawn()
            .map_err(|e| SimError::Spawn(sim.binary.clone(), e.to_string()))?;
        let stdin = child.stdin.take().expect("piped");
        let stdout = BufReader::new(child.stdout.take().expect("piped"));
        let mut session = Self {
            child,
            stdin,
            stdout,
            serial: 0,
            corner: corner.to_owned(),
            log,
        };
        session.run(&format!("set noaskquit\nsource {}\n", deck.display()))?;
        Ok(session)
    }

    /// Sends `commands` and blocks until ngspice has run them all, returning
    /// every `RES <key> <value>` line they echoed. A key echoed twice keeps
    /// its last value; a value that does not parse or is not finite reads
    /// `None`. There is no timeout: a simulation that never ends blocks the
    /// caller.
    ///
    /// # Errors
    ///
    /// [`SimError::Died`] when the process stops reading or closes its
    /// output.
    pub fn run(&mut self, commands: &str) -> Result<Results, SimError> {
        self.serial += 1;
        let marker = format!("@@END{}", self.serial);
        let died = |s: &Self, why: String| SimError::Died {
            corner: s.corner.clone(),
            why,
            log: s.log.display().to_string(),
        };
        let sent = self
            .stdin
            .write_all(commands.as_bytes())
            .and_then(|()| writeln!(self.stdin, "echo \"{marker}\""))
            .and_then(|()| self.stdin.flush());
        if let Err(e) = sent {
            return Err(died(self, e.to_string()));
        }
        let mut results = Results::new();
        let mut line = String::new();
        loop {
            line.clear();
            match self.stdout.read_line(&mut line) {
                Ok(0) => return Err(died(self, "end of output".to_owned())),
                Ok(_) => {}
                Err(e) => return Err(died(self, e.to_string())),
            }
            let text = line.trim_end();
            if text == marker {
                return Ok(results);
            }
            if let Some(rest) = text.strip_prefix("RES ") {
                let mut words = rest.split_whitespace();
                if let Some(key) = words.next() {
                    let value = words.next().and_then(|w| w.parse::<f64>().ok());
                    results.insert(key.to_owned(), value.filter(|v| v.is_finite()));
                }
            }
        }
    }

    /// The name of the corner whose deck this session loaded.
    pub fn corner(&self) -> &str {
        &self.corner
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = writeln!(self.stdin, "quit");
        let _ = self.stdin.flush();
        let _ = self.child.wait();
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
