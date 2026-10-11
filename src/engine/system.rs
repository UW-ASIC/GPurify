//! `gpurify system`: several dies placed into one assembly and checked as
//! one: system LVS (catalog LVS-073) and package- and system-level ESD
//! (ERC-C12, ERC-C13). The checks and their definitions are in
//! [`gpurify_check::system`].
//!
//! Data in: a system description ([`gpurify_ingest::system`]) naming each
//! die's layout, deck, design intent and placement, its bonded faces and its
//! package face; and the system netlist, a SPICE or Spectre reference whose
//! unique top subcircuit places one instance per die, named as the die, and
//! whose ports are the package pins. Data out: [`Outputs`] and a
//! [`Summary`], as [`run`](super::run::run) gives them for one die: the
//! comparison is the LVS stage, the ESD rows the ERC stage.
//!
//! A run:
//!
//! 1. reads every die (layout, deck, intent) into one string table, then the
//!    system netlist, whose model-less cards bind to the recognisers of every
//!    die's deck together;
//! 2. extracts each die and projects it to an LVS graph whose labelled nets
//!    are named `<die>.<label>`, as flattening names a die's internal nets;
//! 3. places every bonded face's bumps and bonds them
//!    (`system.unbonded_bump`), merges the dies' graphs through the bonds,
//!    and compares the pins by name (`system.open`, `system.short`);
//! 4. compares the merged graph with the flattened system netlist as
//!    single-die LVS does, with every net of the top subcircuit a port, so no
//!    series merge crosses a die boundary on one side only;
//! 5. with an `esd` section, holds die-to-die bumps to their own die's
//!    clamps and package pins to the assembly's (`system.esd_d2d`,
//!    `system.esd_package`, `system.esd_iec`), every rail a supply some
//!    die's intent declares.

use crate::engine::pipeline::{
    extract_layout, load_die, read_reference, Die, Extracted, LoadError,
};
use crate::engine::run::{param_names, summarize, Outputs, StageStatus, Summary};
use gpurify_check::lvs::graph::{from_layout, from_reference, Graph};
use gpurify_check::lvs::{compare_logged, record_discrepancies, CompareOptions, Verdict};
use gpurify_check::report::{Outcome, RuleRun, SkipReason, Violations};
use gpurify_check::system::{
    assemble, bumps_into, check_bonds, check_pins, esd_pads_into, Bump, Pin, Placement, GROUND,
    NOWHERE, POWER,
};
use gpurify_check::topology::NetId;
use gpurify_check::Design;
use gpurify_geom::ops::Point;
use gpurify_geom::{prefix, Grid, Length, Qty};
use gpurify_ingest::deck::DeviceRecognition;
use gpurify_ingest::intent::SupplyRole;
use gpurify_ingest::netlist::{Netlist, SubcktId};
use gpurify_ingest::system::{Face, System, SystemFileError};
use gpurify_ingest::{DesignIntent, StrId, StrTable};
use std::collections::BTreeMap;
use std::path::Path;

/// What a system run produced, with the table its names are in and the grid
/// its locations are on.
#[derive(Debug)]
pub struct SystemRun {
    /// Every name the run knows.
    pub strings: StrTable,
    /// The grid every die shares; the rows' locations are on it.
    pub grid: Grid,
    /// The rows: `system.*`, and `lvs.*` for the flat comparison.
    pub outputs: Outputs,
    /// LVS and ERC as the comparison and the ESD rows ran; DRC and PEX not
    /// selected.
    pub summary: Summary,
}

/// Why a system produced no report.
#[derive(Debug, thiserror::Error)]
pub enum SystemError {
    /// The system description.
    #[error(transparent)]
    File(#[from] SystemFileError),
    /// A die's layout, deck or intent, or the system netlist.
    #[error("{what}: {error}")]
    Load {
        /// The die, or the system netlist.
        what: String,
        /// What its reader refused.
        error: LoadError,
    },
    /// A die's extraction.
    #[error("die {die}: {error}")]
    Extract {
        /// The die.
        die: String,
        /// What extraction refused.
        error: crate::engine::pipeline::ExtractError,
    },
    /// The dies and the netlist do not make one assembly: dies on different
    /// grids, an origin off the grid, a face on a layer its deck lacks, a
    /// bump that is not a rectangle on a net, a system netlist with no unique
    /// top, an instance no die is named for, or a system pin no package bump
    /// carries.
    #[error("{0}")]
    Assembly(String),
}

/// Reads a system description and the system netlist from files, then
/// [`check`]s them.
///
/// # Errors
///
/// [`SystemError::File`], [`SystemError::Load`], then whatever [`check`]
/// returns.
pub fn run(system: &Path, reference: &Path) -> Result<SystemRun, SystemError> {
    let spec = gpurify_ingest::system::read_system(system)?;
    let mut strings = StrTable::default();
    let mut dies = Vec::with_capacity(spec.dies.len());
    let mut intents = Vec::with_capacity(spec.dies.len());
    for die in &spec.dies {
        let load = |error: LoadError| SystemError::Load {
            what: format!("die {}", die.name),
            error,
        };
        dies.push(load_die(&die.layout, &die.deck, &mut strings).map_err(load)?);
        intents.push(match &die.intent {
            None => None,
            Some(path) => Some(
                gpurify_ingest::intent::read_intent(path, &mut strings)
                    .map_err(|why| load(why.into()))?,
            ),
        });
    }
    let reference = read_reference(reference, &all_models(&dies), &mut strings).map_err(|why| {
        SystemError::Load {
            what: "the system netlist".to_owned(),
            error: why.into(),
        }
    })?;
    let grid = dies[0].grid;
    let (outputs, summary) = check(&spec, &dies, &intents, &reference, &mut strings)?;
    Ok(SystemRun {
        strings,
        grid,
        outputs,
        summary,
    })
}

/// Every die deck's device models together, which a model-less card or an
/// `X` card calling a device of the system netlist binds to.
pub fn all_models(dies: &[Die]) -> DeviceRecognition {
    let mut models = DeviceRecognition::default();
    for die in dies {
        models.kind.extend_from_slice(&die.deck.devices.kind);
        models.model.extend_from_slice(&die.deck.devices.model);
    }
    models
}

/// One die, extracted and projected, with where it sits.
struct Placed {
    extracted: Extracted,
    graph: Graph,
    placement: Placement,
}

/// Checks a system whose dies are read: `dies[i]` and `intents[i]` belong
/// to `spec.dies[i]`, `reference` is the system netlist as read (not
/// flattened), and every name is in `strings`.
///
/// # Errors
///
/// [`SystemError::Load`] for a system netlist that does not flatten
/// (a cycle, or too large), [`SystemError::Extract`] for a die that does not
/// extract, and [`SystemError::Assembly`] for dies and a netlist that do not
/// make one assembly, as it lists.
///
/// # Panics
///
/// When `dies` or `intents` does not hold one entry per die of `spec`.
pub fn check(
    spec: &System,
    dies: &[Die],
    intents: &[Option<DesignIntent>],
    reference: &Netlist,
    strings: &mut StrTable,
) -> Result<(Outputs, Summary), SystemError> {
    assert_eq!(dies.len(), spec.dies.len(), "one read die per die");
    assert_eq!(intents.len(), spec.dies.len(), "one intent slot per die");
    let grid = dies[0].grid;
    for (die, read) in spec.dies.iter().zip(dies) {
        if read.grid != grid {
            return Err(SystemError::Assembly(format!(
                "die {} is on a grid of {} units per µm and die {} on {}: every die \
                 of a system shares one grid",
                die.name,
                read.grid.dbu_per_um(),
                spec.dies[0].name,
                grid.dbu_per_um()
            )));
        }
    }
    let Some(top) = reference.top() else {
        return Err(SystemError::Assembly(
            "the system netlist has no unique top subcircuit".to_owned(),
        ));
    };
    let instance_of = instances(spec, reference, top, strings)?;
    let flat = reference
        .flatten_top(top, strings)
        .map_err(|why| SystemError::Load {
            what: "the system netlist".to_owned(),
            error: why.into(),
        })?;
    gpurify_check::lvs::intern_rule_ids(strings);
    gpurify_check::system::intern_rule_ids(strings);

    let placed = place(spec, dies, grid, strings)?;
    let faces: Vec<[Vec<Bump>; 2]> = spec
        .bonds
        .iter()
        .map(|[a, b]| {
            Ok([
                bumps(spec, dies, &placed, a, strings)?,
                bumps(spec, dies, &placed, b, strings)?,
            ])
        })
        .collect::<Result<_, SystemError>>()?;
    let package = spec
        .package
        .as_ref()
        .map(|face| bumps(spec, dies, &placed, face, strings))
        .transpose()?
        .unwrap_or_default();

    let mut out = Outputs::default();
    let bonds: Vec<[&[Bump]; 2]> = faces.iter().map(|[a, b]| [&a[..], &b[..]]).collect();
    let pairs = check_bonds(&bonds, strings, &mut out.violations, &mut out.runs);
    let mut offset = Vec::with_capacity(placed.len());
    let mut nets = 0u32;
    for die in &placed {
        offset.push(nets);
        nets += u32::try_from(die.graph.net_count()).expect("a die's nets fit a u32");
    }
    let mut joins = Vec::new();
    for ((bond, [a, b]), pairs) in spec.bonds.iter().zip(&faces).zip(&pairs) {
        for &(i, j) in pairs {
            joins.push((
                offset[bond[0].die] + a[i as usize].net.0,
                offset[bond[1].die] + b[j as usize].net.0,
            ));
        }
    }
    let graphs: Vec<&Graph> = placed.iter().map(|die| &die.graph).collect();
    let (layout, class) = assemble(&graphs, &joins);
    let system_net = |die: usize, net: NetId| class[(offset[die] + net.0) as usize];

    // A pin's place: the first bump on its die's net, bonded faces first.
    let mut first_bump: BTreeMap<(usize, NetId), Point> = BTreeMap::new();
    for ([a, b], bond) in faces.iter().zip(&spec.bonds) {
        for (face, side) in bond.iter().zip([a, b]) {
            for bump in side {
                first_bump
                    .entry((face.die, bump.net))
                    .or_insert_with(|| centre(bump));
            }
        }
    }
    if let Some(face) = &spec.package {
        for bump in &package {
            first_bump
                .entry((face.die, bump.net))
                .or_insert_with(|| centre(bump));
        }
    }
    let pin = |die: usize, name: StrId, reference: u32| {
        let net = placed[die].extracted.ports.nets_of(name).first().copied();
        Pin {
            reference,
            layout: net.map_or(u32::MAX, |net| system_net(die, net)),
            at: net
                .and_then(|net| first_bump.get(&(die, net)).copied())
                .unwrap_or(NOWHERE),
        }
    };
    let mut pins = Vec::new();
    for (die, &instance) in instance_of.iter().enumerate() {
        let Some(instance) = instance else { continue };
        let callee = reference.instance_of[instance].0 as usize;
        let ports = reference.subckt_port_start[callee] as usize
            ..reference.subckt_port_start[callee + 1] as usize;
        let passed = reference.instance_net_start[instance] as usize
            ..reference.instance_net_start[instance + 1] as usize;
        for (&port, &net) in reference.port_net[ports]
            .iter()
            .zip(&reference.instance_net[passed])
        {
            pins.push(pin(die, reference.net_name[port.0 as usize], net.0));
        }
    }
    // The top's ports are the package pins, labelled on the package face's die.
    if let Some(face) = &spec.package {
        let row = top.0 as usize;
        let ports = reference.subckt_port_start[row] as usize
            ..reference.subckt_port_start[row + 1] as usize;
        for &port in &reference.port_net[ports] {
            pins.push(pin(face.die, reference.net_name[port.0 as usize], port.0));
        }
    }
    check_pins(&pins, strings, &mut out.violations, &mut out.runs);

    let lvs = compare(&layout, &flat, reference, top, strings, &mut out);

    let erc = match &spec.esd {
        None => StageStatus::NotSelected,
        Some(esd) => {
            let clamps: Vec<StrId> = esd.clamps.iter().map(|m| strings.intern(m)).collect();
            let rated: Vec<StrId> = esd
                .system_clamps
                .iter()
                .map(|m| strings.intern(m))
                .collect();
            let named: Vec<StrId> = esd.system_pins.iter().map(|p| strings.intern(p)).collect();
            let rule = |name: &str| strings.get(name).expect("interned above");
            let rules = [
                rule("system.esd_d2d"),
                rule("system.esd_package"),
                rule("system.esd_iec"),
            ];
            if intents.iter().all(Option::is_none) {
                let configured = if named.is_empty() { 2 } else { 3 };
                for &rule in &rules[..configured] {
                    out.runs.push(RuleRun {
                        rule,
                        outcome: Outcome::Skipped(SkipReason::NoDesignIntent),
                        examined: 0,
                        violations: 0,
                    });
                }
            } else {
                let supply: Vec<Vec<u8>> = placed
                    .iter()
                    .zip(intents)
                    .map(|(die, intent)| rails(die, intent.as_ref()))
                    .collect();
                let mut assembled = vec![0u8; layout.net_count()];
                for (die, rails) in supply.iter().enumerate() {
                    for (net, &bits) in rails.iter().enumerate() {
                        assembled[system_net(die, NetId(narrow(net))) as usize] |= bits;
                    }
                }
                // Die-to-die bumps, each through its own die alone.
                let mut d2d: Vec<Vec<(u32, Point)>> = vec![Vec::new(); placed.len()];
                for (bond, sides) in spec.bonds.iter().zip(&faces) {
                    for (face, side) in bond.iter().zip(sides) {
                        d2d[face.die].extend(side.iter().map(|b| (b.net.0, centre(b))));
                    }
                }
                let mut run = |rule: StrId, held: &dyn Fn(&mut Violations) -> u64| {
                    let before = out.violations.len();
                    let examined = held(&mut out.violations);
                    out.runs.push(RuleRun {
                        rule,
                        outcome: Outcome::Ran,
                        examined,
                        violations: u32::try_from(out.violations.len() - before)
                            .unwrap_or(u32::MAX),
                    });
                };
                run(rules[0], &|rows| {
                    (0..placed.len())
                        .map(|die| {
                            esd_pads_into(
                                rules[0],
                                &placed[die].graph,
                                &supply[die],
                                &clamps,
                                &d2d[die],
                                rows,
                            )
                        })
                        .sum()
                });
                let face = spec.package.as_ref().expect("esd needs a package face");
                let pads: Vec<(u32, Point)> = package
                    .iter()
                    .map(|b| (system_net(face.die, b.net), centre(b)))
                    .collect();
                run(rules[1], &|rows| {
                    esd_pads_into(rules[1], &layout, &assembled, &clamps, &pads, rows)
                });
                if !named.is_empty() {
                    let ports = &placed[face.die].extracted.ports;
                    let exposed: Vec<(u32, Point)> = package
                        .iter()
                        .filter(|b| ports.names_of(b.net).iter().any(|n| named.contains(n)))
                        .map(|b| (system_net(face.die, b.net), centre(b)))
                        .collect();
                    for (&name, text) in named.iter().zip(&esd.system_pins) {
                        let on_a_bump = package
                            .iter()
                            .any(|b| ports.names_of(b.net).contains(&name));
                        if !on_a_bump {
                            return Err(SystemError::Assembly(format!(
                                "system pin {text} labels no bump of the package face"
                            )));
                        }
                    }
                    run(rules[2], &|rows| {
                        esd_pads_into(rules[2], &layout, &assembled, &rated, &exposed, rows)
                    });
                }
            }
            StageStatus::Ran
        }
    };

    let summary = summarize(
        &mut out,
        [StageStatus::NotSelected, erc, lvs, StageStatus::NotSelected],
    );
    Ok((out, summary))
}

/// A row count as a `u32`, as every table here is indexed.
fn narrow(rows: usize) -> u32 {
    u32::try_from(rows).expect("a table indexes its rows with a u32")
}

/// A bump's place: its placed rectangle's centre.
fn centre(bump: &Bump) -> Point {
    Point {
        x: gpurify_geom::Dbu::new_unchecked(i64::midpoint(bump.at.xlo.raw(), bump.at.xhi.raw())),
        y: gpurify_geom::Dbu::new_unchecked(i64::midpoint(bump.at.ylo.raw(), bump.at.yhi.raw())),
    }
}

/// Per die of `spec`, the top instance of the system netlist named as it,
/// if any. Every instance the top places must be a die.
fn instances(
    spec: &System,
    reference: &Netlist,
    top: SubcktId,
    strings: &StrTable,
) -> Result<Vec<Option<usize>>, SystemError> {
    let mut instance_of = vec![None; spec.dies.len()];
    for instance in 0..reference.instance_of.len() {
        if reference.instance_subckt[instance] != top {
            continue;
        }
        let name = strings.resolve(reference.instance_name[instance]);
        match spec.dies.iter().position(|die| die.name == name) {
            Some(die) => instance_of[die] = Some(instance),
            None => {
                return Err(SystemError::Assembly(format!(
                    "the system netlist places instance {name}, which is no die of the system"
                )))
            }
        }
    }
    Ok(instance_of)
}

/// Extracts every die, projects it to a graph whose labelled nets are named
/// `<die>.<label>`, and converts its placement onto the grid.
fn place(
    spec: &System,
    dies: &[Die],
    grid: Grid,
    strings: &mut StrTable,
) -> Result<Vec<Placed>, SystemError> {
    let mut placed = Vec::with_capacity(dies.len());
    for (die, read) in spec.dies.iter().zip(dies) {
        let extracted =
            extract_layout(&read.store, &read.deck, &read.provenance).map_err(|error| {
                SystemError::Extract {
                    die: die.name.clone(),
                    error,
                }
            })?;
        let mut graph = from_layout(
            &extracted.nets,
            &extracted.devices,
            &extracted.ports,
            strings,
            Some(grid),
        );
        for name in &mut graph.net_name {
            if let Some(label) = *name {
                let qualified = format!("{}.{}", die.name, strings.resolve(label));
                *name = Some(strings.intern(&qualified));
            }
        }
        let [dx, dy] = die
            .origin_nm
            .map(|nm| grid.to_dbu(Qty::<Length, { prefix::NANO }>::new(nm)));
        let (Ok(dx), Ok(dy)) = (dx, dy) else {
            return Err(SystemError::Assembly(format!(
                "die {}: origin_nm {:?} is not a whole number of grid units",
                die.name, die.origin_nm
            )));
        };
        placed.push(Placed {
            extracted,
            graph,
            placement: Placement {
                mirror: die.mirror,
                quarter_turns: die.quarter_turns,
                dx,
                dy,
            },
        });
    }
    Ok(placed)
}

/// The bumps of one face, placed.
fn bumps(
    spec: &System,
    dies: &[Die],
    placed: &[Placed],
    face: &Face,
    strings: &StrTable,
) -> Result<Vec<Bump>, SystemError> {
    let name = &spec.dies[face.die].name;
    let read = &dies[face.die];
    let Some(layer) = read.deck.layers.id(strings, &face.layer) else {
        return Err(SystemError::Assembly(format!(
            "die {name}: its deck has no layer {}",
            face.layer
        )));
    };
    let die = &placed[face.die];
    let design = Design {
        store: &read.store,
        nets: &die.extracted.nets,
        devices: &die.extracted.devices,
    };
    let mut out = Vec::new();
    bumps_into(design, layer, die.placement, &mut out)
        .map_err(|why| SystemError::Assembly(format!("die {name}, layer {}: {why}", face.layer)))?;
    Ok(out)
}

/// The flat comparison: `layout` against the flattened system netlist, every
/// net of its top subcircuit a port. Records the discrepancies and the
/// verdict in `out` and returns the LVS stage's status.
fn compare(
    layout: &Graph,
    flat: &Netlist,
    reference: &Netlist,
    top: SubcktId,
    strings: &StrTable,
    out: &mut Outputs,
) -> StageStatus {
    let mut schematic = from_reference(flat, SubcktId(0));
    // The top's own nets are the flattened netlist's first rows: each joins
    // pins of dies, as a bonded net joins labelled ones in the layout.
    let top_nets = reference.net_subckt.iter().filter(|&&s| s == top).count();
    let mut is_port = vec![false; top_nets];
    for &net in &schematic.port_net {
        if let Some(slot) = is_port.get_mut(net as usize) {
            *slot = true;
        }
    }
    for (net, port) in is_port.iter().enumerate() {
        if !port {
            schematic.port_net.push(narrow(net));
        }
    }
    let options = CompareOptions {
        params: param_names(strings),
        ..CompareOptions::default()
    };
    let (verdict, merges) = compare_logged(layout, &schematic, options);
    out.lvs_merges = merges;
    let status = match &verdict {
        Verdict::Match => StageStatus::Ran,
        Verdict::Mismatch(found) => {
            record_discrepancies(found, strings, &mut out.violations);
            StageStatus::Ran
        }
        Verdict::Inconclusive(why) => {
            StageStatus::Refused(format!("the comparison did not conclude: {why:?}"))
        }
    };
    out.lvs = Some(verdict);
    status
}

/// A die's supply bits per net, from the labels its intent declares.
fn rails(die: &Placed, intent: Option<&DesignIntent>) -> Vec<u8> {
    let nets = die.graph.net_count();
    let mut bits = vec![0u8; nets];
    let Some(intent) = intent else { return bits };
    for (net, slot) in bits.iter_mut().enumerate() {
        for &name in die.extracted.ports.names_of(NetId(narrow(net))) {
            *slot |= match intent.supply_role(name) {
                Some((_, SupplyRole::Power)) => POWER,
                Some((_, SupplyRole::Ground)) => GROUND,
                None => 0,
            };
        }
    }
    bits
}
