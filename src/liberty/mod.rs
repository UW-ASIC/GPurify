//! Liberty generation for a hard macro: one `.lib` per PVT corner and a
//! Verilog blackbox, measured from the layout at a chosen [`Accuracy`].
//!
//! This is what `gpurify lib` runs. It checks no rules. It turns an analog or
//! custom block into the timing and power model a digital flow needs to place
//! and time it. The user guide, with the measured agreement against
//! `sky130_fd_sc_hd`'s shipped library, is
//! [liberty.md](https://github.com/UW-ASIC/GPurify/blob/main/docs/liberty.md).
//!
//! # Inputs and outputs
//!
//! In: the [`Loaded`] layout and its [`Extracted`] nets and devices, as
//! [`crate::engine::pipeline::load`] and [`crate::engine::pipeline::extract`]
//! give them, plus a [`Request`]: the [`spec::MacroSpec`] (what a layout cannot
//! say about itself: which pin is a clock, which is analog, the arcs, each
//! corner's supply voltages and model lines), the accuracy, and optionally the
//! LEF text. A reference netlist, when [`Loaded`] carries one, is cross-checked
//! too.
//!
//! Out: a [`Generated`], in memory, for the caller to write under an output
//! directory: `<cell>.v`, then `<cell>__<corner>.lib` per corner. When the
//! cases of an arc disagree, as a data-dependent comparator's do, the main
//! file carries the worst case at every table point and
//! `min/<cell>__<corner>.lib` the best, for `read_liberty -min`. Units in every
//! `.lib`: ns, pF, V, mA, nW, and pJ for internal energy.
//!
//! # The accuracy ladder
//!
//! | Accuracy | Pin capacitance | Arcs | Leakage |
//! |---|---|---|---|
//! | `interface` (0) | none | none | none |
//! | `analytical` (1) | closed-form wire C + each device's static model C | none | simulated |
//! | `field` (2) | field-solved wire C + each device's static model C | none | simulated |
//! | `spice` (3) | charge drawn on the extracted RC netlist | NLDM delay and transition, setup/hold, internal energy | simulated |
//! | `statistical` (4) | as `spice` | as `spice`, plus Monte Carlo LVF sigma | simulated |
//!
//! Each level costs more than the one below. `interface` is enough for
//! floorplanning and the power grid; sign-off STA wants `spice` or
//! `statistical`. [`measure`] defines each number, [`circuit`] how the layout
//! becomes the RC netlist the `spice` levels simulate, and [`mod@write`] the NLDM
//! table conventions.
//!
//! # The simulator
//!
//! Every level above `interface` runs ngspice: the spec's
//! [`spec::Simulator::binary`], `ngspice` on `PATH` by default, driven in pipe
//! mode (`-p`). The corner's model lines are written into the deck verbatim,
//! so the models they name must be readable. `statistical` also needs each
//! corner's [`spec::CornerSpec::mc_models`].
//!
//! # Examples
//!
//! ```no_run
//! use gpurify::engine::pipeline::{extract, load, Inputs};
//! use gpurify::liberty::{generate, spec, Accuracy, Request};
//!
//! let inputs = Inputs {
//!     layout: "strongarm.gds".into(),
//!     deck: "pdks/sky130.deck".into(),
//!     reference: Some("strongarm.spice".into()),
//!     ..Inputs::default()
//! };
//! let loaded = load(&inputs)?;
//! let extracted = extract(&loaded)?;
//! let spec = spec::parse(&std::fs::read_to_string("strongarm.json")?)?;
//! let work = std::env::temp_dir().join("strongarm-lib");
//! let request = Request {
//!     spec: &spec,
//!     accuracy: Accuracy::Spice,
//!     lef: None,
//!     work: &work,
//!     tool_version: "my-flow 1.0",
//! };
//! let generated = generate(&loaded, &extracted, &request)?;
//! for (path, text) in &generated.files {
//!     let path = std::path::Path::new("lib").join(path);
//!     if let Some(dir) = path.parent() {
//!         std::fs::create_dir_all(dir)?;
//!     }
//!     std::fs::write(&path, text)?;
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! Before anything is measured, the spec's pins are checked against the
//! layout's labels, the reference `.subckt`'s ports and the LEF's pins: name
//! drift between these is the integration failure this exists to stop.

pub mod circuit;
pub mod measure;
pub mod spec;
pub mod spice;
pub mod write;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::engine::{Extracted, Loaded};
use circuit::{Circuit, CircuitError, Wires};
use gpurify_check::topology::{NetId, TerminalRole};
use gpurify_extract::ParasiticNetwork;
use measure::{Bench, Effort, Grid};
use spec::{ArcKind, ArcSpec, CornerSpec, Edge, Level, MacroSpec, Role, Vector};
use spice::{Precision, SimError, Task};
use write::{Cell, InternalPower, Library, NamedTable, Pin, Table, Timing};

/// How much is measured, and how. Ordered cheapest first: a higher level
/// measures everything a lower one does, more exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Accuracy {
    /// Pins, `pg_pin`s, directions and area. No simulator runs, so there is no
    /// capacitance, arc or leakage. Enough for floorplanning and the power grid.
    Interface,
    /// Pin capacitance as closed-form wire capacitance plus each touching
    /// device's static model capacitance, averaged over the pin's swing.
    /// Leakage is simulated. No arcs.
    Analytical,
    /// As [`Accuracy::Analytical`], with the signal pins' wiring field-solved
    /// together (50 nm panels) instead of taken from closed forms.
    Field,
    /// The extracted RC netlist simulated: NLDM delay and transition, setup
    /// and hold, internal energy, charge-integrated pin capacitance and
    /// leakage.
    Spice,
    /// As [`Accuracy::Spice`], plus LVF `ocv_sigma_*` tables: each point's
    /// sample standard deviation over
    /// [`spec::Characterization::mc_samples`] Monte Carlo redraws. Needs
    /// every corner's [`spec::CornerSpec::mc_models`].
    Statistical,
}

impl Accuracy {
    /// Every level, cheapest first: the order `--accuracy all` runs them, and
    /// the numbering `0`..`4` [`Accuracy::parse`] reads.
    pub const ALL: [Self; 5] = [
        Self::Interface,
        Self::Analytical,
        Self::Field,
        Self::Spice,
        Self::Statistical,
    ];

    /// The level's command-line spelling: also its subdirectory under
    /// `--accuracy all`, and the word in each `.lib`'s header comment.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Interface => "interface",
            Self::Analytical => "analytical",
            Self::Field => "field",
            Self::Spice => "spice",
            Self::Statistical => "statistical",
        }
    }

    /// One line on what the level measured, written into each `.lib`'s header
    /// comment so a reader of the file knows what its numbers are.
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Interface => "pins, supplies and area only",
            Self::Analytical => {
                "closed-form wire capacitance plus static device capacitance; no arcs"
            }
            Self::Field => "field-solved wire capacitance plus static device capacitance; no arcs",
            Self::Spice => "SPICE characterization of the extracted RC netlist",
            Self::Statistical => {
                "SPICE characterization of the extracted RC netlist, plus Monte Carlo sigma"
            }
        }
    }

    /// Parses a level from its [`name`](Accuracy::name) (`interface` ..
    /// `statistical`) or its number (`0` .. `4`). `None` for anything else,
    /// including `all`, which the command line expands to [`Accuracy::ALL`]
    /// itself.
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .enumerate()
            .find(|(level, a)| a.name() == text || level.to_string() == text)
            .map(|(_, a)| a)
    }
}

/// Why [`generate`] produced nothing. A run never returns part of its
/// output: the first failure, in any corner, ends it.
#[derive(Debug, Clone, thiserror::Error)]
pub enum LibError {
    /// The spec's pins disagree with the reference netlist or the LEF: the
    /// reference has no unique top `.subckt`, its top is named other than the
    /// spec's `cell`, or its ports are not exactly the spec's pins; or the LEF
    /// has no `MACRO <cell>`, or that macro's `PIN`s are not exactly the
    /// spec's. The message names what each side lacks. A spec pin missing
    /// from the layout is [`CircuitError::MissingPin`] instead.
    #[error("pin cross-check: {0}")]
    Mismatch(String),
    /// The layout cannot be made into a circuit. At every level, a spec pin
    /// no layout label names ([`CircuitError::MissingPin`]) or two pins the
    /// layout shorts ([`CircuitError::ShortedPins`]); at `spice` and
    /// `statistical`, also a conductor layer that is not valid geometry or a
    /// net whose resistor network falls apart.
    #[error(transparent)]
    Circuit(#[from] CircuitError),
    /// The simulator could not be started, stopped answering, or could not
    /// make a measurement, such as an output that never switched or a capture
    /// that fails even with the data a whole window clear of the clock. Never
    /// at `interface`.
    #[error(transparent)]
    Sim(#[from] SimError),
    /// The field solve of the wiring failed (`field`, `spice`,
    /// `statistical`): a layer it cannot mesh, named as the deck names it,
    /// or a solve that did not converge. The message is the one `pex`
    /// reports for the same refusal.
    #[error("{0}")]
    Solve(String),
    /// The closed-form extraction of the wiring refused a conductor or via
    /// layer with no `pex` row, or a conductor it cannot merge (every level
    /// but `interface`). The message names the layer as the deck does, as
    /// `pex` reports it.
    #[error("{0}")]
    Pex(String),
    /// `statistical` was asked of a corner with no
    /// [`mc_models`](spec::CornerSpec::mc_models).
    #[error("{0}")]
    Refused(String),
    /// [`Request::work`] could not be created, or a deck could not be written
    /// into it.
    #[error("io: {0}")]
    Io(String),
}

/// What [`generate`] produced. Nothing has been written to an output
/// directory: the caller writes `files`.
#[derive(Debug, Default)]
pub struct Generated {
    /// `(path, text)`, each path relative to the output directory:
    /// `<cell>.v` first, then for each corner in spec order
    /// `<cell>__<corner>.lib`, followed by `min/<cell>__<corner>.lib` when
    /// that corner's arc cases disagree. The `min/` library is named
    /// `<cell>__<corner>__min`, because `OpenSTA` skips a second library whose
    /// name it has already read.
    pub files: Vec<(PathBuf, String)>,
    /// What the user should hear that did not stop the run: layout labels the
    /// spec does not list, taken as internal nets, and constraints clamped to
    /// `-constraint_window_ns` because the capture passed even that far on
    /// the wrong side of the clock.
    pub notes: Vec<String>,
}

/// Everything a run needs besides the layout. The reference netlist is not
/// here: it arrives with the [`Loaded`] layout (from
/// [`Inputs::reference`](crate::engine::Inputs::reference)), and its top
/// `.subckt` is cross-checked whenever it is present.
pub struct Request<'a> {
    /// The macro spec. It must come from [`spec::parse`], which validates
    /// it; see [`generate`]'s panics.
    pub spec: &'a MacroSpec,
    /// What to measure, and how exactly.
    pub accuracy: Accuracy,
    /// The LEF's text. When given, the `PIN`s of its `MACRO <cell>` must be
    /// exactly the spec's pins.
    pub lef: Option<&'a str>,
    /// Where testbench decks and simulator logs go. Created if missing, at
    /// every level, and never removed: the caller decides whether to keep it,
    /// which is worth doing after a failure, since the logs hold what the
    /// simulator said.
    pub work: &'a Path,
    /// The version string written into the header comment of every `.lib` and
    /// of the blackbox.
    pub tool_version: &'static str,
}

/// Generates the Verilog blackbox and one Liberty model per corner at
/// `request.accuracy`.
///
/// The pins are cross-checked first, against the layout's labels, the
/// reference `.subckt` and the LEF, so a name mismatch fails before any
/// simulation. Above `interface`, each corner's measurements run on a pool of
/// [`spec::Simulator::workers`] ngspice processes (default: every core), one
/// corner after another.
///
/// # Errors
///
/// Every [`LibError`] variant, under the conditions each one states. Above
/// `interface`, ngspice must be on `PATH` (or at the spec's
/// [`spec::Simulator::binary`]), or the run fails with [`LibError::Sim`].
///
/// # Panics
///
/// Panics on a [`MacroSpec`] built by hand that [`spec::parse`] would have
/// refused: an arc naming a pin the spec lacks, or a corner with no voltage
/// for a supply pin.
///
/// # Cost
///
/// `interface` does no simulation. `analytical` and `field` run a leakage
/// simulation and an AC sweep of the pins' devices per corner, and `field`
/// adds a field solve of the signal pins' wiring. `spice` field-solves every
/// net in a 3 µm window, a dense boundary-element solve whose cost grows with
/// the square of its panel count, then runs one transient per load for each
/// input slew of every delay case, and a bisection of transients for each
/// point of every constraint case.
/// `statistical` repeats the arc work
/// [`mc_samples`](spec::Characterization::mc_samples) times.
pub fn generate(
    loaded: &Loaded,
    extracted: &Extracted,
    request: &Request<'_>,
) -> Result<Generated, LibError> {
    let spec = request.spec;
    let mut generated = Generated::default();
    cross_check(loaded, extracted, request, &mut generated.notes)?;
    let area = area_um2(loaded);

    let mut verilog = String::new();
    write::write_blackbox(&spec.cell, &spec.pins, request.tool_version, &mut verilog);
    generated
        .files
        .push((PathBuf::from(format!("{}.v", spec.cell)), verilog));

    std::fs::create_dir_all(request.work).map_err(|e| LibError::Io(e.to_string()))?;
    let prepared = Prepared::new(loaded, extracted, request)?;

    for corner in &spec.corners {
        let (worst, best) = prepared.corner(corner, &mut generated.notes)?;
        // The best case is its own library: OpenSTA ignores a second library
        // of a name it has read, so `read_liberty -min` needs a new one.
        let library = |cell: Cell, suffix: &str| Library {
            name: format!("{}__{}{suffix}", spec.cell, corner.name),
            corner: corner.clone(),
            thresholds: spec.characterization.clone(),
            accuracy: request.accuracy,
            tool_version: request.tool_version,
            cell: Cell {
                area_um2: area,
                ..cell
            },
        };
        let mut text = String::new();
        write::write_liberty(&library(worst, ""), &mut text);
        generated.files.push((
            PathBuf::from(format!("{}__{}.lib", spec.cell, corner.name)),
            text,
        ));
        if let Some(best) = best {
            let mut text = String::new();
            write::write_liberty(&library(best, "__min"), &mut text);
            generated.files.push((
                PathBuf::from(format!("min/{}__{}.lib", spec.cell, corner.name)),
                text,
            ));
        }
    }
    Ok(generated)
}

/// Spec pins against the layout's labels, the reference `.subckt`'s ports and
/// the LEF's pins. The last two must match exactly.
fn cross_check(
    loaded: &Loaded,
    extracted: &Extracted,
    request: &Request<'_>,
    notes: &mut Vec<String>,
) -> Result<(), LibError> {
    let spec = request.spec;
    let wanted: BTreeSet<&str> = spec.pins.iter().map(|p| p.name.as_str()).collect();
    let compare = |source: &str, found: &BTreeSet<String>| {
        let found: BTreeSet<&str> = found.iter().map(String::as_str).collect();
        let missing: Vec<&str> = wanted.difference(&found).copied().collect();
        let extra: Vec<&str> = found.difference(&wanted).copied().collect();
        if missing.is_empty() && extra.is_empty() {
            return Ok(());
        }
        Err(LibError::Mismatch(format!(
            "{source} lacks [{}] and has [{}] that the spec does not",
            missing.join(", "),
            extra.join(", ")
        )))
    };

    // Layout: every spec pin must be found (the substrate pin may stand on the
    // substrate instead of a label). A label the spec does not list may name
    // an internal net, so it is reported, not refused.
    let mut labelled = BTreeSet::new();
    for net in 0..extracted.nets.net_count() {
        let net = NetId(u32::try_from(net).expect("a net id is a u32"));
        for &name in extracted.ports.names_of(net) {
            labelled.insert(loaded.strings.resolve(name).to_owned());
        }
    }
    let unlisted: Vec<&str> = labelled
        .iter()
        .map(String::as_str)
        .filter(|name| !wanted.contains(name))
        .collect();
    if !unlisted.is_empty() {
        notes.push(format!(
            "the layout labels nets the spec does not list, taken as internal: {}",
            unlisted.join(", ")
        ));
    }
    circuit::pin_nets(loaded, extracted, spec)?;

    if let Some(reference) = &loaded.reference {
        let Some(top) = reference.top() else {
            return Err(LibError::Mismatch(
                "the reference netlist has no unique top subcircuit".to_owned(),
            ));
        };
        let row = top.0 as usize;
        let ports: BTreeSet<String> = reference.port_net[reference.subckt_port_start[row] as usize
            ..reference.subckt_port_start[row + 1] as usize]
            .iter()
            .map(|&net| {
                loaded
                    .strings
                    .resolve(reference.net_name[net.0 as usize])
                    .to_owned()
            })
            .collect();
        let name = loaded.strings.resolve(reference.subckt_name[row]);
        if name != spec.cell {
            return Err(LibError::Mismatch(format!(
                "the reference's top subcircuit is {name}, the spec's cell {}",
                spec.cell
            )));
        }
        compare("the reference .subckt", &ports)?;
    }
    if let Some(lef) = request.lef {
        compare("the LEF macro", &lef_pins(lef, &spec.cell)?)?;
    }
    Ok(())
}

/// The `PIN` names of `MACRO cell` in a LEF.
fn lef_pins(lef: &str, cell: &str) -> Result<BTreeSet<String>, LibError> {
    let mut inside = false;
    let mut found = false;
    let mut pins = BTreeSet::new();
    for line in lef.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        match words.as_slice() {
            ["MACRO", name, ..] if *name == cell => {
                inside = true;
                found = true;
            }
            ["END", name, ..] if inside && *name == cell => inside = false,
            ["PIN", name, ..] if inside => {
                pins.insert((*name).to_owned());
            }
            _ => {}
        }
    }
    if found {
        Ok(pins)
    } else {
        Err(LibError::Mismatch(format!("the LEF has no MACRO {cell}")))
    }
}

/// The die area: the deck's outline layer if drawn, else every drawn shape's box.
fn area_um2(loaded: &Loaded) -> f64 {
    let die = crate::engine::run::design_extent(loaded);
    if die.is_empty() {
        return 0.0;
    }
    #[expect(clippy::cast_precision_loss, reason = "a die below 2^40 dbu a side")]
    let (w, h) = (die.width().raw() as f64, die.height().raw() as f64);
    #[expect(clippy::cast_precision_loss, reason = "a resolution is a small count")]
    let per_um = loaded.grid.dbu_per_um() as f64;
    w * h / (per_um * per_um)
}

/// Corner-independent work, done once: extraction and the circuit.
struct Prepared<'a> {
    request: &'a Request<'a>,
    /// Wire capacitance per net, fF (L1, L2).
    wire_ff: Vec<f64>,
    /// The circuit leakage and (L3+) everything else is measured on.
    circuit: Option<Circuit>,
    workers: usize,
}

impl<'a> Prepared<'a> {
    fn new(
        loaded: &'a Loaded,
        extracted: &'a Extracted,
        request: &'a Request<'a>,
    ) -> Result<Self, LibError> {
        let accuracy = request.accuracy;
        let spec = request.spec;
        let mut prepared = Self {
            request,
            wire_ff: Vec::new(),
            circuit: None,
            workers: spec.simulator.workers.unwrap_or_else(|| {
                std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
            }),
        };
        if accuracy == Accuracy::Interface {
            return Ok(prepared);
        }
        let mut analytical = ParasiticNetwork::default();
        gpurify_extract::analytical::extract_into(
            &loaded.store,
            &extracted.nets,
            &loaded.deck.connectivity,
            &loaded.deck.stack,
            loaded.grid,
            &mut analytical,
        )
        .map_err(|why| LibError::Pex(crate::engine::run::pex_refusal(loaded, why)))?;
        let pin_nets = circuit::pin_nets(loaded, extracted, spec)?;
        match accuracy {
            Accuracy::Interface => unreachable!("returned above"),
            Accuracy::Analytical | Accuracy::Field => {
                let mut network = analytical;
                if accuracy == Accuracy::Field {
                    let mut selected: Vec<NetId> = spec
                        .pins
                        .iter()
                        .zip(&pin_nets)
                        .filter(|(p, _)| !p.role.is_supply())
                        .flat_map(|(_, nets)| nets.iter().copied())
                        .filter(|&net| !extracted.nets.is_global_only(net))
                        .collect();
                    selected.sort_unstable();
                    selected.dedup();
                    let solved = field_solve(loaded, extracted, &selected, FIELD)?;
                    gpurify_extract::quasistatic::overlay(&mut network, &solved);
                }
                prepared.wire_ff = network.capacitance_per_net();
                prepared.circuit = Some(circuit::build(loaded, extracted, spec, Wires::Lumped)?);
            }
            Accuracy::Spice | Accuracy::Statistical => {
                let selected: Vec<NetId> = (0..extracted.nets.net_count())
                    .map(|n| NetId(u32::try_from(n).expect("a net id is a u32")))
                    .filter(|&net| !extracted.nets.is_global_only(net))
                    .collect();
                let solved = field_solve(loaded, extracted, &selected, SPICE_FIELD)?;
                prepared.circuit = Some(circuit::build(
                    loaded,
                    extracted,
                    spec,
                    Wires::Distributed {
                        analytical: &analytical,
                        field: Some(&solved),
                    },
                )?);
            }
        }
        Ok(prepared)
    }

    /// Tolerances every analysis runs at. Against a reltol 1e-6, 0.1 ps-step
    /// reference these agree to 0.03 % on a 10 ps edge into 0.5 fF and to
    /// 0.0002 % on a 1.5 ns one, at a fifth of a fixed sub-ps step's cost:
    /// the step shrinks where a waveform bends and nowhere else.
    const PRECISION: Precision = Precision {
        reltol: 1e-6,
        abstol: 1e-15,
        vntol: 1e-7,
        trtol: 1.0,
    };

    const EFFORT: Effort = Effort {
        max_step: 10e-12,
        resolution: 0.5e-12,
    };

    /// Write a corner's testbench deck; its path.
    fn deck(&self, corner: &CornerSpec, statistical: bool) -> Result<PathBuf, LibError> {
        let spec = self.request.spec;
        let circuit = self
            .circuit
            .as_ref()
            .expect("a measured accuracy has a circuit");
        let mut subckt = String::new();
        spice::write_subckt(circuit, spec, &spec.simulator, &mut subckt);
        let mut deck = String::new();
        spice::write_deck(
            spec,
            corner,
            &subckt,
            &spec.simulator,
            Self::PRECISION,
            statistical,
            &mut deck,
        );
        let suffix = if statistical { "_mc" } else { "" };
        let path = self
            .request
            .work
            .join(format!("{}__{}{suffix}.cir", spec.cell, corner.name));
        std::fs::write(&path, deck).map_err(|e| LibError::Io(e.to_string()))?;
        Ok(path)
    }

    /// One corner's cell, worst case, and best case when cases disagree.
    fn corner(
        &self,
        corner: &CornerSpec,
        notes: &mut Vec<String>,
    ) -> Result<(Cell, Option<Cell>), LibError> {
        enum Out {
            Cap(usize, measure::Cap),
            Analog(usize, f64),
            Leakage(Vec<f64>),
            Row(usize, usize, usize, Grid),
            Constraint(usize, usize, usize, usize, f64),
        }
        let spec = self.request.spec;
        let mut cell = Cell {
            name: spec.cell.clone(),
            area_um2: 0.0,
            leakage_nw: None,
            leakage_states: Vec::new(),
            pins: spec.pins.iter().cloned().map(Pin::bare).collect(),
        };
        let accuracy = self.request.accuracy;
        if accuracy == Accuracy::Interface {
            return Ok((cell, None));
        }
        let bench = Bench {
            spec,
            corner,
            effort: Self::EFFORT,
            reltol: Self::PRECISION.reltol,
        };
        let states = leakage_states(spec, &bench);
        let deck = self.deck(corner, false)?;
        if accuracy < Accuracy::Spice {
            let leakage = spice::run_pool(
                &spec.simulator,
                &deck,
                &corner.name,
                1,
                vec![Box::new(|s: &mut spice::Session| bench.leakage(s, &states))
                    as Task<'_, Vec<f64>>],
            )?
            .remove(0);
            set_leakage(&mut cell, spec, &states, &leakage);
            self.static_caps(corner, &mut cell)?;
            return Ok((cell, None));
        }

        // Everything independent goes on the pool at once.
        let c = &spec.characterization;
        let mut tasks: Vec<Task<'_, Out>> = Vec::new();
        let bench = &bench;
        for (i, pin) in spec.pins.iter().enumerate() {
            match pin.role {
                Role::Input | Role::Clock => {
                    let name = pin.name.as_str();
                    tasks.push(Box::new(move |s| {
                        Ok(Out::Cap(i, bench.input_cap(s, name)?))
                    }));
                }
                Role::Analog => {
                    let name = pin.name.as_str();
                    tasks.push(Box::new(move |s| {
                        Ok(Out::Analog(i, bench.analog_cap(s, name)?))
                    }));
                }
                _ => {}
            }
        }
        let states = &states;
        tasks.push(Box::new(move |s| {
            Ok(Out::Leakage(bench.leakage(s, states)?))
        }));
        for (a, arc) in spec.arcs.iter().enumerate() {
            for (k, case) in arc.cases.iter().enumerate() {
                let label = format!(
                    "{} arc {} -> {} case {k}",
                    arc.kind.liberty(),
                    arc.from,
                    arc.to
                );
                if arc.kind.is_constraint() {
                    for (i, &cs) in c.constraint_slews_ns.iter().enumerate() {
                        for (j, &ds) in c.constraint_slews_ns.iter().enumerate() {
                            let label = label.clone();
                            tasks.push(Box::new(move |s| {
                                let v = bench.constraint_point(s, arc, case, cs, ds, &label)?;
                                Ok(Out::Constraint(a, k, i, j, v))
                            }));
                        }
                    }
                } else {
                    for row in 0..c.slews_ns.len() {
                        let label = label.clone();
                        tasks.push(Box::new(move |s| {
                            Ok(Out::Row(
                                a,
                                k,
                                row,
                                bench.delay_row(s, arc, case, row, &label)?,
                            ))
                        }));
                    }
                }
            }
        }
        let outs = spice::run_pool(&spec.simulator, &deck, &corner.name, self.workers, tasks)?;

        let mut grids = Grids::new(spec);
        let mut leakage = Vec::new();
        for out in outs {
            match out {
                Out::Cap(i, cap) => cell.pins[i].capacitance = Some((cap.rise, cap.fall)),
                Out::Analog(i, farads) => cell.pins[i].capacitance = Some((farads, farads)),
                Out::Leakage(l) => leakage = l,
                Out::Row(a, k, row, grid) => grids.put_row(a, k, row, &grid),
                Out::Constraint(a, k, i, j, v) => grids.put_constraint(a, k, i, j, v),
            }
        }
        set_leakage(&mut cell, spec, states, &leakage);
        for (a, arc) in spec.arcs.iter().enumerate() {
            for (k, _) in arc.cases.iter().enumerate() {
                if arc.kind.is_constraint() {
                    let window = c.constraint_window_ns;
                    if grids.constraint[a][k].iter().any(|&v| v <= -window) {
                        notes.push(format!(
                            "{}: arc {} -> {} case {k} passes even {window} ns on the wrong side \
                             of the clock; its constraint is clamped to -{window} ns",
                            corner.name, arc.from, arc.to
                        ));
                    }
                }
            }
        }

        let sigma = if accuracy == Accuracy::Statistical {
            Some(self.monte_carlo(corner, bench)?)
        } else {
            None
        };
        let worst = assemble(spec, cell.clone(), &grids, sigma.as_ref(), f64::max);
        let disagree = spec.arcs.iter().any(|arc| {
            let mut seen = BTreeSet::new();
            arc.cases
                .iter()
                .any(|case| !seen.insert(case.output.or(case.data)))
        });
        let best = disagree.then(|| assemble(spec, cell, &grids, sigma.as_ref(), f64::min));
        Ok((worst, best))
    }

    /// Per point, the standard deviation over `mc_samples` redraws.
    fn monte_carlo(&self, corner: &CornerSpec, bench: &Bench<'_>) -> Result<Grids, LibError> {
        enum Out {
            Row(u32, usize, usize, usize, Grid),
            Constraint(u32, usize, usize, usize, usize, f64),
        }
        let spec = self.request.spec;
        if corner.mc_models.is_empty() {
            return Err(LibError::Refused(format!(
                "statistical accuracy needs corner {}'s mc_models: the model lines with \
                 variation switched on",
                corner.name
            )));
        }
        let deck = self.deck(corner, true)?;
        let c = &spec.characterization;
        let samples = c.mc_samples;
        let mut tasks: Vec<Task<'_, Out>> = Vec::new();
        for sample in 0..samples {
            for (a, arc) in spec.arcs.iter().enumerate() {
                for (k, case) in arc.cases.iter().enumerate() {
                    let label = format!(
                        "{} arc {} -> {} case {k} sample {sample}",
                        arc.kind.liberty(),
                        arc.from,
                        arc.to
                    );
                    if arc.kind.is_constraint() {
                        for (i, &cs) in c.constraint_slews_ns.iter().enumerate() {
                            for (j, &ds) in c.constraint_slews_ns.iter().enumerate() {
                                let label = label.clone();
                                tasks.push(Box::new(move |s| {
                                    measure::redraw(s, sample)?;
                                    let v = bench.constraint_point(s, arc, case, cs, ds, &label)?;
                                    Ok(Out::Constraint(sample, a, k, i, j, v))
                                }));
                            }
                        }
                    } else {
                        for row in 0..c.slews_ns.len() {
                            let label = label.clone();
                            tasks.push(Box::new(move |s| {
                                measure::redraw(s, sample)?;
                                Ok(Out::Row(
                                    sample,
                                    a,
                                    k,
                                    row,
                                    bench.delay_row(s, arc, case, row, &label)?,
                                ))
                            }));
                        }
                    }
                }
            }
        }
        let outs = spice::run_pool(&spec.simulator, &deck, &corner.name, self.workers, tasks)?;
        let mut per_sample: Vec<Grids> = (0..samples).map(|_| Grids::new(spec)).collect();
        for out in outs {
            match out {
                Out::Row(n, a, k, row, grid) => per_sample[n as usize].put_row(a, k, row, &grid),
                Out::Constraint(n, a, k, i, j, v) => {
                    per_sample[n as usize].put_constraint(a, k, i, j, v);
                }
            }
        }
        let mut sigma = Grids::new(spec);
        for (a, arc) in spec.arcs.iter().enumerate() {
            for k in 0..arc.cases.len() {
                let column = |pick: &dyn Fn(&Grids) -> Vec<f64>| -> Vec<f64> {
                    measure::sigma(&per_sample.iter().map(pick).collect::<Vec<_>>())
                };
                sigma.delay[a][k] = column(&|g| g.delay[a][k].clone());
                sigma.transition[a][k] = column(&|g| g.transition[a][k].clone());
                sigma.constraint[a][k] = column(&|g| g.constraint[a][k].clone());
            }
        }
        Ok(sigma)
    }

    /// L1/L2: wire capacitance plus every device terminal's static model
    /// capacitance, averaged over the pin's swing.
    fn static_caps(&self, corner: &CornerSpec, cell: &mut Cell) -> Result<(), LibError> {
        use std::fmt::Write as _;
        let spec = self.request.spec;
        let circuit = self
            .circuit
            .as_ref()
            .expect("measured accuracies have a circuit");
        let points = 9u32;
        let mut deck = String::new();
        for line in &corner.models {
            let _ = writeln!(deck, "{line}");
        }
        if let Some(line) = spice::scale_option(&spec.simulator) {
            let _ = writeln!(deck, "{line}");
        }
        let _ = writeln!(deck, ".temp {}", spice::si(corner.temperature));
        // A net's DC voltage when it is pinned by the spec, else unknown.
        let pinned = |net: NetId| -> Option<f64> {
            spec.pins
                .iter()
                .zip(&circuit.pin_nets)
                .find(|(_, nets)| nets.contains(&net))
                .and_then(|(p, _)| match p.role {
                    r if r.is_supply() => Some(corner.supplies[&p.name]),
                    Role::Input | Role::Clock => {
                        Some(p.ground.as_ref().map_or(0.0, |g| corner.supplies[g]))
                    }
                    Role::Analog => p.bias,
                    _ => None,
                })
        };
        let mut biases: Vec<f64> = Vec::new();
        let bias_node = |v: f64, biases: &mut Vec<f64>| -> String {
            // The same rail, bit for bit, shares one source.
            let k = biases
                .iter()
                .position(|b| b.to_bits() == v.to_bits())
                .unwrap_or_else(|| {
                    biases.push(v);
                    biases.len() - 1
                });
            format!("b{k}")
        };
        // (pin, swing) per test source.
        let mut tests: Vec<(usize, Vec<f64>)> = Vec::new();
        let mut cards = String::new();
        for (p, pin) in spec.pins.iter().enumerate() {
            if pin.role.is_supply() || pin.role == Role::Output {
                continue;
            }
            let nets = &circuit.pin_nets[p];
            let swing: Vec<f64> = if pin.role == Role::Analog {
                vec![pin.bias.unwrap_or(0.0)]
            } else {
                let (lo, hi) = (
                    pin.ground.as_ref().map_or(0.0, |g| corner.supplies[g]),
                    pin.power.as_ref().map_or(0.0, |g| corner.supplies[g]),
                );
                (0..points)
                    .map(|k| lo + (hi - lo) * f64::from(k) / f64::from(points - 1))
                    .collect()
            };
            for device in &circuit.devices {
                if !device.nets.iter().any(|n| nets.contains(n)) {
                    continue;
                }
                let t = tests.len();
                let bulk = device
                    .roles
                    .iter()
                    .position(|&r| r == TerminalRole::Bulk)
                    .and_then(|i| pinned(device.nets[i]))
                    .unwrap_or(0.0);
                let _ = write!(cards, "{}t{t}", spec.simulator.prefix);
                for &net in &device.nets {
                    let node = if nets.contains(&net) {
                        format!("t{t}")
                    } else {
                        bias_node(pinned(net).unwrap_or(bulk), &mut biases)
                    };
                    let _ = write!(cards, " {node}");
                }
                let _ = write!(cards, " {}", device.model);
                for &(key, value) in &device.params {
                    let s = spec.simulator.scale;
                    let v = match value {
                        circuit::Param::Length(m) => spice::si(m / s),
                        circuit::Param::Area(m2) => spice::si(m2 / (s * s)),
                        circuit::Param::Count(n) => n.to_string(),
                    };
                    let _ = write!(cards, " {key}={v}");
                }
                cards.push('\n');
                let _ = writeln!(cards, "vt{t} t{t} 0 DC {} AC 1", spice::si(swing[0]));
                tests.push((p, swing.clone()));
            }
        }
        for (k, v) in biases.iter().enumerate() {
            let _ = writeln!(deck, "vb{k} b{k} 0 DC {}", spice::si(*v));
        }
        deck.push_str(&cards);
        deck.push_str(".end\n");
        let path = self
            .request
            .work
            .join(format!("{}__{}_devices.cir", spec.cell, corner.name));
        std::fs::write(&path, deck).map_err(|e| LibError::Io(e.to_string()))?;

        let f = spice::si(spec.characterization.analog_frequency_hz);
        let mut commands = String::new();
        for k in 0..points as usize {
            for (t, (_, swing)) in tests.iter().enumerate() {
                let v = swing.get(k).copied().unwrap_or(swing[0]);
                let _ = writeln!(commands, "alter vt{t} dc = {}", spice::si(v));
            }
            let _ = writeln!(commands, "ac lin 1 {f} {f}");
            for t in 0..tests.len() {
                let _ = writeln!(
                    commands,
                    "let c{t} = -imag(vt{t}#branch)/(2*pi*{f})\necho \"RES c{t}_{k} $&c{t}\""
                );
            }
            commands.push_str("destroy all\n");
        }
        let results = if tests.is_empty() {
            spice::Results::new()
        } else {
            spice::run_pool(
                &spec.simulator,
                &path,
                &corner.name,
                1,
                vec![Box::new(|s: &mut spice::Session| s.run(&commands)) as Task<'_, _>],
            )?
            .remove(0)
        };
        for (p, pin) in spec.pins.iter().enumerate() {
            if pin.role.is_supply() || pin.role == Role::Output {
                continue;
            }
            let wire_pf: f64 = circuit.pin_nets[p]
                .iter()
                .map(|n| self.wire_ff.get(n.idx()).copied().unwrap_or(0.0))
                .sum::<f64>()
                * 1e-3;
            let mut device_pf = 0.0;
            for (t, (owner, swing)) in tests.iter().enumerate() {
                if *owner != p {
                    continue;
                }
                let values: Vec<f64> = (0..swing.len())
                    .map(|k| {
                        results
                            .get(&format!("c{t}_{k}"))
                            .copied()
                            .flatten()
                            .ok_or_else(|| {
                                LibError::Sim(SimError::Measure {
                                    corner: corner.name.clone(),
                                    why: format!("static capacitance of {}'s devices", pin.name),
                                })
                            })
                    })
                    .collect::<Result<_, _>>()?;
                // Trapezoid mean over the swing: charge over swing.
                let mean = if values.len() == 1 {
                    values[0]
                } else {
                    let n = values.len() - 1;
                    let inner: f64 = values[1..n].iter().sum();
                    (0.5 * (values[0] + values[n]) + inner)
                        / f64::from(u32::try_from(n).expect("few"))
                };
                device_pf += mean * 1e12;
            }
            let total = wire_pf + device_pf;
            cell.pins[p].capacitance = Some((total, total));
        }
        Ok(())
    }
}

/// `field`: the pin nets' wiring, solved together, converged to 0.05 %.
const FIELD: FieldMesh = FieldMesh {
    edge_nm: 50,
    window_nm: None,
};

/// `spice`, `statistical`: every net, each in a 3 µm window, converged to
/// 0.8 % of its wire capacitance (a 200 nm edge, halved near another
/// conductor), about 0.15 % of a node's total once devices are counted. The
/// dense solve's cost grows as the edge's inverse fourth power.
const SPICE_FIELD: FieldMesh = FieldMesh {
    edge_nm: 200,
    window_nm: Some(3000),
};

/// How the wiring is field-solved.
#[derive(Debug, Clone, Copy)]
struct FieldMesh {
    /// Largest panel edge, nm; halved near another conductor.
    edge_nm: i64,
    /// `Some(halo)`: each net's solve meshes only the conductors within `halo`
    /// nm of it, so cost grows with the net count rather than the square of
    /// the layout. `None`: every net's solve meshes all the selected wiring.
    window_nm: Option<i64>,
}

/// Field-solve the wiring of `targets`: one node per layout net, its ground
/// and coupling capacitance. Wells, diffusions and substrate are left out of
/// the mesh: their capacitance is the device models' (the deck gives them no
/// area or fringe coefficient), and a well touching its own diffusion is two
/// conductors at zero gap, which no boundary-element system converges on.
/// A net is driven as one: all the conductors the cut splits it into at one
/// volt, in one solve, which is the column of the net with them shorted. Its
/// total charge is its capacitance to ground; the charge on each other net is
/// their coupling, and a pair's coupling is the mean of what each side's solve
/// saw (collocation is not exactly reciprocal, and windows differ).
///
/// ponytail: poly over a channel stays in the mesh, so a gate net counts its
/// oxide-area field capacitance (about 1 % of an input's) on top of the
/// model's; subtract the channels with a boolean if that ever matters.
fn field_solve(
    loaded: &Loaded,
    extracted: &Extracted,
    targets: &[NetId],
    how: FieldMesh,
) -> Result<ParasiticNetwork, LibError> {
    use std::collections::BTreeMap;
    let store = &loaded.store;
    let deck = &loaded.deck;
    let stack = &deck.stack;
    let mut solved = ParasiticNetwork::default();
    if targets.is_empty() {
        return Ok(solved);
    }
    // Via cuts are left out too: a cut's end faces coincide with the plates it
    // joins, two panels of one conductor at one place, and that near-singular
    // system is what stalls the solve on a large via array. A net's layers
    // become separate conductors, which fold back below; the cuts' own
    // sidewall capacitance is what is lost, a fraction of a percent.
    let wire = |layer: gpurify_geom::LayerId| {
        let row = layer.idx();
        deck.connectivity.conductors.contains(&layer)
            && row < stack.area_cap_af_um2.len()
            && (stack.area_cap_af_um2[row] > 0.0 || stack.fringe_cap_af_um[row] > 0.0)
    };
    // Windowed, every net's wiring is a potential neighbour.
    let mut meshed = vec![how.window_nm.is_some(); extracted.nets.net_count()];
    for net in targets {
        meshed[net.idx()] = true;
    }
    let mut builder = gpurify_geom::GeometryStoreBuilder::with_capacity(store.poly_count(), 0);
    let mut origin = Vec::new();
    for row in 0..store.poly_count() {
        let poly = gpurify_geom::PolyId(u32::try_from(row).expect("a poly id is a u32"));
        let net = extracted.nets.net_of(poly);
        if net == NetId::NONE || !meshed[net.idx()] || !wire(store.poly_layer(poly)) {
            continue;
        }
        let (xs, ys) = store.poly_verts(poly);
        builder.push(store.poly_layer(poly), xs, ys);
        origin.push(net);
    }
    let (drawn, permutation) = builder.finish(store.layer_count());
    let origin: Vec<NetId> = permutation
        .iter()
        .map(|&old| origin[old as usize])
        .collect();
    let (wires, origin) = merge_overlaps(&drawn, &origin, &deck.connectivity);
    let mut nets = gpurify_check::topology::NetTable::default();
    gpurify_check::topology::net::extract_nets_into(&wires, &deck.connectivity, &mut nets);
    // Conductors, ascending, with their layout net and footprint.
    let mut conductors = Vec::new();
    let mut owner = Vec::new();
    let mut extent = Vec::new();
    for net in 0..nets.net_count() {
        let net = NetId(u32::try_from(net).expect("a net id is a u32"));
        let polys = nets.polys_of(net);
        if let Some(&first) = polys.first() {
            conductors.push(net);
            owner.push(origin[first.idx()]);
            extent.push(polys.iter().fold(gpurify_geom::Bbox::EMPTY, |b, &p| {
                b.union(wires.poly_bbox(p))
            }));
        }
    }
    let per_um = loaded.grid.dbu_per_um();
    let edge = gpurify_geom::Dbu::new_unchecked((how.edge_nm * per_um / 1000).max(1));
    let meshing = gpurify_extract::field::mesh::MeshOptions {
        max_edge: edge,
        proximity_refine: edge,
        max_panels: 1 << 22,
    };
    // A relative residual of 1e-7 leaves the charge, and so every
    // capacitance, good to that: four orders below the mesh's own error.
    let solver = gpurify_extract::field::solve::Options {
        tolerance: 1e-7,
        ..gpurify_extract::field::solve::Options::default()
    };
    let mut ground: BTreeMap<NetId, f64> = BTreeMap::new();
    // `(from, to)`: what `from`'s solve saw on `to`.
    let mut seen: BTreeMap<(NetId, NetId), f64> = BTreeMap::new();
    let mut matrix = gpurify_extract::quasistatic::CapMatrix::default();
    let mut groups: Vec<NetId> = targets.to_vec();
    groups.sort_unstable();
    groups.dedup();
    // One solve per net: its conductors at one volt together, the window's
    // at ground. The window is every meshed conductor, or those within the
    // halo of the net.
    let halo = how
        .window_nm
        .map(|nm| gpurify_geom::Dbu::new_unchecked(nm * per_um / 1000));
    let solves: Vec<(Vec<NetId>, Vec<NetId>)> = groups
        .iter()
        .map(|&target| {
            let mine = |c: &usize| owner[*c] == target;
            let driven: Vec<NetId> = (0..conductors.len())
                .filter(mine)
                .map(|c| conductors[c])
                .collect();
            let reach = (0..conductors.len())
                .filter(mine)
                .fold(gpurify_geom::Bbox::EMPTY, |b, c| b.union(extent[c]));
            let window: Vec<NetId> = (0..conductors.len())
                .filter(|&c| halo.is_none_or(|h| extent[c].within(reach, h)))
                .map(|c| conductors[c])
                .collect();
            (window, driven)
        })
        .filter(|(_, driven)| !driven.is_empty())
        .collect();
    for (window, driven) in &solves {
        gpurify_extract::field::extract_columns_into(
            &wires,
            &nets,
            &deck.connectivity,
            window,
            std::slice::from_ref(driven),
            stack,
            loaded.grid,
            meshing,
            solver,
            &mut matrix,
        )
        .map_err(|why| LibError::Solve(crate::engine::run::solve_refusal(loaded, why)))?;
        let owner_of = |conductor: NetId| {
            owner[conductors
                .binary_search(&conductor)
                .expect("a meshed conductor")]
        };
        // The net's column: by reciprocity its row, so its total is its
        // capacitance to ground and each other net's share its coupling.
        let source = owner_of(driven[0]);
        for row in 0..matrix.net.len() {
            let charge = matrix.value[row];
            *ground.entry(source).or_insert(0.0) += charge;
            let other = owner_of(matrix.net[row]);
            if other != source {
                *seen.entry((source, other)).or_insert(0.0) += -charge;
            }
        }
    }
    // A pair seen from both sides is the mean; from one side, that side.
    let mut coupling: BTreeMap<(NetId, NetId), f64> = BTreeMap::new();
    for (&(a, b), &f) in &seen {
        let key = if a < b { (a, b) } else { (b, a) };
        let mirror = seen.get(&(b, a)).copied();
        let value = mirror.map_or(f, |m| 0.5 * (f + m));
        coupling.insert(key, value);
    }
    solved.node_net = ground.keys().copied().collect();
    solved.node_layer = vec![gpurify_geom::LayerId(u16::MAX); solved.node_net.len()];
    let node = |net: NetId, solved: &ParasiticNetwork| {
        gpurify_extract::network::NodeId(
            u32::try_from(
                solved
                    .node_net
                    .binary_search(&net)
                    .expect("every owner has a node"),
            )
            .expect("a node id is a u32"),
        )
    };
    let femto = |farads: f64| gpurify_geom::Qty::new(farads * 1e15);
    for (&net, &farads) in &ground {
        let at = node(net, &solved);
        solved.push(
            at,
            None,
            gpurify_extract::Parasitic::GroundCap(femto(farads)),
        );
    }
    for (&(a, b), &farads) in &coupling {
        if let (Ok(_), Ok(_)) = (
            solved.node_net.binary_search(&a),
            solved.node_net.binary_search(&b),
        ) {
            let (from, to) = (node(a, &solved), node(b, &solved));
            solved.push(
                from,
                Some(to),
                gpurify_extract::Parasitic::CouplingCap(femto(farads)),
            );
        }
    }
    solved.sort_canonical();
    Ok(solved)
}

/// The same wiring with every conductor's overlapping shapes on a layer
/// merged into one outline, and each outline's layout net. Two shapes drawn
/// over each other put panels inside metal, coincident with the other
/// shape's: a boundary-element system that never converges.
fn merge_overlaps(
    drawn: &gpurify_geom::GeometryStore,
    origin: &[NetId],
    connectivity: &gpurify_ingest::deck::Connectivity,
) -> (gpurify_geom::GeometryStore, Vec<NetId>) {
    use gpurify_geom::{GeometryStoreBuilder, LayerId, PolyId, ValidatedLayer};
    let mut nets = gpurify_check::topology::NetTable::default();
    gpurify_check::topology::net::extract_nets_into(drawn, connectivity, &mut nets);
    // Shapes by (layer, conductor), in PolyId order.
    let mut groups: std::collections::BTreeMap<(LayerId, NetId), Vec<PolyId>> =
        std::collections::BTreeMap::new();
    for row in 0..drawn.poly_count() {
        let poly = PolyId(u32::try_from(row).expect("a poly id is a u32"));
        groups
            .entry((drawn.poly_layer(poly), nets.net_of(poly)))
            .or_default()
            .push(poly);
    }
    let mut builder = GeometryStoreBuilder::with_capacity(drawn.poly_count(), 0);
    let mut owners = Vec::new();
    let (mut alone, mut merged, empty) = (
        ValidatedLayer::default(),
        ValidatedLayer::default(),
        ValidatedLayer::default(),
    );
    for ((layer, _), polys) in &groups {
        let owner = origin[polys[0].idx()];
        let overlapping = polys.iter().enumerate().any(|(i, &a)| {
            polys[i + 1..].iter().any(|&b| {
                let (x, y) = (drawn.poly_bbox(a), drawn.poly_bbox(b));
                x.xlo.raw().max(y.xlo.raw()) < x.xhi.raw().min(y.xhi.raw())
                    && x.ylo.raw().max(y.ylo.raw()) < x.yhi.raw().min(y.yhi.raw())
            })
        });
        let mut outline = || -> Option<()> {
            let mut scratch = GeometryStoreBuilder::with_capacity(polys.len(), 0);
            for &p in polys {
                let (xs, ys) = drawn.poly_verts(p);
                scratch.push(LayerId(0), xs, ys);
            }
            let (scratch, _) = scratch.finish(1);
            gpurify_geom::view::validate_layer_into(&scratch, LayerId(0), &mut alone).ok()?;
            gpurify_geom::boolean::union_into(&alone, &empty, &mut merged).ok()?;
            for i in 0..merged.len() {
                for ring in merged.poly_rings(u32::try_from(i).expect("a polygon index is a u32")) {
                    let (xs, ys) = ring.coords();
                    builder.push(*layer, xs, ys);
                    owners.push(owner);
                }
            }
            Some(())
        };
        // A group the union cannot take is meshed as drawn, as before.
        if !(overlapping && outline().is_some()) {
            for &p in polys {
                let (xs, ys) = drawn.poly_verts(p);
                builder.push(*layer, xs, ys);
                owners.push(origin[p.idx()]);
            }
        }
    }
    let (store, permutation) = builder.finish(drawn.layer_count());
    let owners = permutation
        .iter()
        .map(|&old| owners[old as usize])
        .collect();
    (store, owners)
}

/// The states leakage is taken in: the spec's, else each case's preparation,
/// else everything low; duplicates once.
fn leakage_states(spec: &MacroSpec, bench: &Bench<'_>) -> Vec<Vec<Vector>> {
    if !spec.leakage_states.is_empty() {
        return spec.leakage_states.clone();
    }
    let mut states: Vec<Vec<Vector>> = Vec::new();
    for case in spec.arcs.iter().flat_map(|a| &a.cases) {
        if !states.contains(&case.vectors) {
            states.push(case.vectors.clone());
        }
    }
    if states.is_empty() {
        states.push(vec![bench.all_low()]);
    }
    states
}

fn set_leakage(cell: &mut Cell, spec: &MacroSpec, states: &[Vec<Vector>], leakage: &[f64]) {
    if leakage.is_empty() {
        return;
    }
    let count = f64::from(u32::try_from(leakage.len()).expect("few states"));
    cell.leakage_nw = Some(leakage.iter().sum::<f64>() / count);
    // A `when` per state only when every state is a distinct logic state.
    let whens: Vec<String> = states
        .iter()
        .map(|s| when(spec, &measure::merged(s)))
        .collect();
    let distinct: BTreeSet<&String> = whens.iter().collect();
    if states.len() > 1 && distinct.len() == states.len() && whens.iter().all(|w| !w.is_empty()) {
        cell.leakage_states = whens.into_iter().zip(leakage.iter().copied()).collect();
    }
}

/// A state as a Liberty boolean of its logic-level inputs.
fn when(spec: &MacroSpec, state: &Vector) -> String {
    spec.pins
        .iter()
        .filter_map(|p| match state.get(&p.name) {
            Some(Level::High) => Some(p.name.clone()),
            Some(Level::Low) => Some(format!("!{}", p.name)),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// Every case's tables, by arc then case; row-major.
#[derive(Clone)]
struct Grids {
    delay: Vec<Vec<Vec<f64>>>,
    transition: Vec<Vec<Vec<f64>>>,
    energy: Vec<Vec<Vec<f64>>>,
    constraint: Vec<Vec<Vec<f64>>>,
    loads: usize,
    constraint_n: usize,
}

impl Grids {
    fn new(spec: &MacroSpec) -> Self {
        let c = &spec.characterization;
        let shape = |n: usize| -> Vec<Vec<Vec<f64>>> {
            spec.arcs
                .iter()
                .map(|arc| arc.cases.iter().map(|_| vec![0.0; n]).collect())
                .collect()
        };
        let delay_n = c.slews_ns.len() * c.loads_pf.len();
        let constraint_n = c.constraint_slews_ns.len();
        Self {
            delay: shape(delay_n),
            transition: shape(delay_n),
            energy: shape(delay_n),
            constraint: shape(constraint_n * constraint_n),
            loads: c.loads_pf.len(),
            constraint_n,
        }
    }

    fn put_row(&mut self, a: usize, k: usize, row: usize, grid: &Grid) {
        let at = row * self.loads;
        self.delay[a][k][at..at + self.loads].copy_from_slice(&grid.delay);
        self.transition[a][k][at..at + self.loads].copy_from_slice(&grid.transition);
        self.energy[a][k][at..at + self.loads].copy_from_slice(&grid.energy);
    }

    fn put_constraint(&mut self, a: usize, k: usize, i: usize, j: usize, v: f64) {
        self.constraint[a][k][i * self.constraint_n + j] = v;
    }
}

/// Arc `a`'s tables of cases `ks`.
fn gather<'g>(g: &'g [Vec<Vec<f64>>], a: usize, ks: &[usize]) -> Vec<&'g Vec<f64>> {
    ks.iter().map(|&k| &g[a][k]).collect()
}

/// Fold the cases of one arc that share an edge, point by point.
fn fold(tables: &[&Vec<f64>], pick: fn(f64, f64) -> f64) -> Option<Vec<f64>> {
    let (first, rest) = tables.split_first()?;
    let mut out = (*first).clone();
    for t in rest {
        for (o, v) in out.iter_mut().zip(t.iter()) {
            *o = pick(*o, *v);
        }
    }
    Some(out)
}

/// Build the cell's timing and power groups from the measured grids.
fn assemble(
    spec: &MacroSpec,
    mut cell: Cell,
    grids: &Grids,
    sigma: Option<&Grids>,
    pick: fn(f64, f64) -> f64,
) -> Cell {
    let c = &spec.characterization;
    let delay_table = |values: Vec<f64>| Table {
        index_1: c.slews_ns.clone(),
        index_2: c.loads_pf.clone(),
        values,
    };
    let constraint_table = |values: Vec<f64>| Table {
        index_1: c.constraint_slews_ns.clone(),
        index_2: c.constraint_slews_ns.clone(),
        values,
    };
    for (a, arc) in spec.arcs.iter().enumerate() {
        let to = spec
            .pins
            .iter()
            .position(|p| p.name == arc.to)
            .expect("validated");
        let cases = |edge: Edge| -> Vec<usize> {
            arc.cases
                .iter()
                .enumerate()
                .filter(|(_, case)| case.output.or(case.data) == Some(edge))
                .map(|(k, _)| k)
                .collect()
        };
        let mut timing = Timing {
            related: arc.from.clone(),
            kind: arc.kind,
            sense: sense(arc),
            tables: Vec::new(),
        };
        let mut power = InternalPower {
            related: arc.from.clone(),
            rise: None,
            fall: None,
        };
        for edge in [Edge::Rise, Edge::Fall] {
            let ks = cases(edge);
            let e = edge.name();
            let mut push = |group: String, sigma_type: Option<&'static str>, table: Table| {
                timing.tables.push(NamedTable {
                    group,
                    sigma: sigma_type,
                    table,
                });
            };
            if arc.kind.is_constraint() {
                if let Some(v) = fold(&gather(&grids.constraint, a, &ks), pick) {
                    push(format!("{e}_constraint"), None, constraint_table(v));
                }
                if let Some(s) = sigma.and_then(|s| fold(&gather(&s.constraint, a, &ks), f64::max))
                {
                    for side in ["early", "late"] {
                        push(
                            format!("ocv_sigma_{e}_constraint"),
                            Some(side),
                            constraint_table(s.clone()),
                        );
                    }
                }
                continue;
            }
            if let Some(v) = fold(&gather(&grids.delay, a, &ks), pick) {
                push(format!("cell_{e}"), None, delay_table(v));
            }
            if let Some(v) = fold(&gather(&grids.transition, a, &ks), pick) {
                push(format!("{e}_transition"), None, delay_table(v));
            }
            if let Some(s) = sigma {
                if let Some(v) = fold(&gather(&s.delay, a, &ks), f64::max) {
                    for side in ["early", "late"] {
                        push(
                            format!("ocv_sigma_cell_{e}"),
                            Some(side),
                            delay_table(v.clone()),
                        );
                    }
                }
                if let Some(v) = fold(&gather(&s.transition, a, &ks), f64::max) {
                    for side in ["early", "late"] {
                        push(
                            format!("ocv_sigma_{e}_transition"),
                            Some(side),
                            delay_table(v.clone()),
                        );
                    }
                }
            }
            let energy = fold(&gather(&grids.energy, a, &ks), pick).map(delay_table);
            match edge {
                Edge::Rise => power.rise = energy,
                Edge::Fall => power.fall = energy,
            }
        }
        let pin = &mut cell.pins[to];
        if !arc.kind.is_constraint() {
            let worst_transition = timing
                .tables
                .iter()
                .filter(|t| t.group.ends_with("_transition") && t.sigma.is_none())
                .flat_map(|t| t.table.values.iter().copied())
                .fold(0.0, f64::max);
            pin.max_capacitance_pf = c.loads_pf.last().copied();
            pin.max_transition_ns =
                Some(pin.max_transition_ns.unwrap_or(0.0).max(worst_transition));
            if power.rise.is_some() || power.fall.is_some() {
                pin.power.push(power);
            }
        }
        pin.timing.push(timing);
        let from = spec
            .pins
            .iter()
            .position(|p| p.name == arc.from)
            .expect("validated");
        let limit = if arc.kind.is_constraint() {
            c.constraint_slews_ns.last().copied()
        } else {
            c.slews_ns.last().copied()
        };
        for i in [from, if arc.kind.is_constraint() { to } else { from }] {
            let pin = &mut cell.pins[i];
            pin.max_transition_ns = match (pin.max_transition_ns, limit) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
        }
    }
    cell
}

/// A combinational arc's unateness from its cases; `None` for a clocked one.
fn sense(arc: &ArcSpec) -> Option<&'static str> {
    if arc.kind != ArcKind::Combinational {
        return None;
    }
    let same = arc.cases.iter().all(|c| c.edge == c.output);
    let opposite = arc.cases.iter().all(|c| c.edge.map(Edge::flip) == c.output);
    Some(if same {
        "positive_unate"
    } else if opposite {
        "negative_unate"
    } else {
        "non_unate"
    })
}

#[cfg(test)]
mod tests {
    use super::{lef_pins, Accuracy};

    /// Oracle: `Accuracy::parse`'s doc: a name or a level `0` to `4`, so
    /// `field` is `Field`, `4` is `Statistical` and `5` is nothing.
    #[test]
    fn accuracy_parses_by_name_and_level() {
        assert_eq!(Accuracy::parse("field"), Some(Accuracy::Field));
        assert_eq!(Accuracy::parse("4"), Some(Accuracy::Statistical));
        assert_eq!(Accuracy::parse("5"), None);
    }

    /// Oracle: construct-from-answer, by LEF's `MACRO` ... `END` scoping: `m`
    /// holds `a` and `vdd`, `other`'s `x` is not among them, and a macro the
    /// file lacks is an error.
    #[test]
    fn lef_pins_are_read_inside_the_named_macro_only() {
        let lef = "MACRO other\n PIN x\n END x\nEND other\nMACRO m\n PIN a\n  DIRECTION INPUT ;\n END a\n PIN vdd\n END vdd\nEND m\n";
        let pins = lef_pins(lef, "m").expect("found");
        assert_eq!(pins.into_iter().collect::<Vec<_>>(), ["a", "vdd"]);
        assert!(lef_pins(lef, "nope").is_err());
    }
}
