//! The simulator: the macro as a subcircuit, one testbench deck per corner,
//! and a pool of persistent ngspice processes driven over a pipe.
//!
//! Every pin is driven by a source the characterizer rewrites (`alter`) before
//! each analysis, so a corner's models load once per process, not once per
//! measurement. A measurement is a block of commands whose results come back as
//! `RES <key> <value>` lines; a value the simulator could not measure comes
//! back empty and reads as `None`, never as zero.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use crate::liberty::circuit::{Circuit, Param};
use crate::liberty::spec::{CornerSpec, MacroSpec, Role, Simulator};

#[derive(Debug, Clone, thiserror::Error)]
pub enum SimError {
    #[error("could not start {0}: {1}")]
    Spawn(String, String),
    #[error("the simulator stopped answering (corner {corner}): {why}; its log is {log}")]
    Died {
        corner: String,
        why: String,
        log: String,
    },
    #[error("corner {corner}: {why}")]
    Measure { corner: String, why: String },
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

/// A number as the simulator reads it: shortest round-trip, SI.
pub fn si(value: f64) -> String {
    format!("{value:e}")
}

/// The macro as `.subckt`, ports in spec order. Lengths are written divided by
/// the simulator's `scale`, areas by its square.
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

/// `.option scale`, unless the scale is one.
pub fn scale_option(sim: &Simulator) -> Option<String> {
    #[expect(clippy::float_cmp, reason = "1.0 is the exact no-scale value")]
    let unscaled = sim.scale == 1.0;
    (!unscaled).then(|| format!(".option scale={}", si(sim.scale)))
}

/// The testbench node and source of spec pin `i`.
pub fn pin_node(i: usize) -> String {
    format!("p{i}")
}
pub fn pin_source(i: usize) -> String {
    format!("vp{i}")
}
pub fn pin_load(i: usize) -> String {
    format!("cp{i}")
}

/// Simulator accuracy: tolerances every analysis runs at.
#[derive(Debug, Clone, Copy)]
pub struct Precision {
    pub reltol: f64,
    pub abstol: f64,
    pub vntol: f64,
    /// Truncation-error overestimate factor; 1 trusts the error estimate
    /// fully, so steps shrink where the waveform bends and nowhere else.
    pub trtol: f64,
}

/// One corner's testbench: models, the macro, a DC source on every supply, a
/// rewritable PWL source on every input and analog pin, a load on every output.
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

/// One ngspice process with a corner's deck loaded.
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

    /// Send `commands`, then collect every `RES` line up to a sentinel.
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

/// A unit of work run on one session.
pub type Task<'a, T> = Box<dyn FnOnce(&mut Session) -> Result<T, SimError> + Send + 'a>;

/// Run `tasks` on `workers` sessions of `deck`; results in task order.
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
