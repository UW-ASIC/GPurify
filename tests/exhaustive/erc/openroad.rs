//! Antenna ratios against `OpenROAD`'s antenna checker (`check_antennas`, the
//! `ant` module; testing-plan §4 L6, ledger O1), gate by gate, on seeded
//! boards ([`super::antenna_board`]).
//!
//! **What `OpenROAD` is given.** A LEF and a DEF written from the board's own
//! description, never from anything `GPurify` extracted:
//!
//! - the stack poly, cont, met1, via1, met2, via2, met3; every cut and metal
//!   carries `ANTENNAAREAFACTOR 1000` and each metal `ANTENNASIDEAREAFACTOR
//!   1000` and `THICKNESS 0.35` (the boards' sidewall). The factor scales
//!   every reported ratio by 1000, so the report's two decimals resolve a
//!   ratio to 1e-5 (`ant::AntennaChecker::calculateWirePar` multiplies the
//!   area by it; the comparison divides it out);
//! - each gate a cell of its own whose one `INPUT` pin has `ANTENNAGATEAREA`
//!   the gate's area and a port on poly exactly at its contact; each diode a
//!   cell whose pin has `ANTENNADIFFAREA` the diffusion's area, its port at
//!   its contact. The cell's inside (the gate's poly, the diode's diffusion)
//!   is not routing, as in any LEF abstract;
//! - every metal rectangle of the board a `RECT` routing element, and every
//!   cut a via whose metal enclosures are the cut itself (inside the metal
//!   it joins, so it adds no area). A contact is a via from poly to met1:
//!   its poly enclosure is the pin, which the checker subtracts from the
//!   wires (`avoidPinIntersection`), so the pin joins the contact and adds
//!   nothing.
//!
//! All boards of a batch are one DEF net side by side: the checker works on
//! connected nodes inside a net, so nodes that do not touch stay apart.
//!
//! **Oracle.** LEF/DEF 5.8 Appendix C as `OpenROAD` implements it: per gate
//! and layer, the area (side area) of the layer's nodes joined to the gate
//! through that layer and those below, over the gate area joined to them
//! (PAR, PSR), a cut's nodes joined through the conductor below; the
//! cumulative ratio of the metals and, separately, of the cuts, the sum of a
//! gate's ratios up to a layer (CAR, CSR). A board's `GPurify` rows carry the
//! same definitions (`erc::rules::antenna`), so each row is read off the
//! report: `par.<layer>`, `psr.<metal>` that layer's PAR or PSR, and the
//! cumulative rows (`car.met`, `car.via`, `csr.met`) the CAR or CSR at the
//! highest layer a gate reaches (each ratio is non-negative, so that is the
//! largest). `par.poly` is not compared: poly is inside the cells.
//!
//! A diode: with `ANTENNAAREARATIO` and no `ANTENNADIFFAREARATIO`, a node
//! with diffusion area is held to the absent limit and never flagged
//! (`checkPAR`), which is `GPurify`'s `diode: diff` (and `KLayout`'s): a
//! second run sets a tiny `ANTENNAAREARATIO` on the metals and reads which
//! gates the checker flags (`dio.<metal>`).
//!
//! **H5's diode terms** (`antenna_electrical`, the `h5*` rows). Two more
//! runs carry, on every layer, `ANTENNAAREAMINUSDIFF` (`area_minus_diode`,
//! times the factor), `ANTENNAGATEPLUSDIFF` (`gate_plus_diode`),
//! `ANTENNAAREADIFFREDUCEPWL` (`diode_reduce`), and on the cuts the factor
//! times `cut_factor` (`ANTENNAAREAFACTOR`); the second adds `max_ratio` and
//! the `ANTENNADIFFAREARATIO PWL` table (`diode_max_ratio`) on the metals,
//! both times the factor, for the `h5lim` verdicts. `calculateWirePar` and
//! `calculateViaPar` then give a node with diffusion `(factor · area ·
//! reduce − minus · diff) / (gate + plus · diff)`, `GPurify`'s partial ratio.
//! Three of H5's terms have no counterpart here and are not compared:
//! `ANTENNACUMROUTINGPLUSCUT` (OpenROAD 26Q2 sums metals and cuts apart, so
//! the cumulative `h5` rows list only metals or only cuts), the truncation
//! of a negative running sum at zero (the parameters keep every partial
//! ratio positive, so it never applies), and sky130's credit, bonus and
//! exemption, which LEF does not state.
//!
//! **Through the macro pins** (ERC-A14). A second test gives `GPurify` the
//! very LEF and DEF `OpenROAD` reads: it draws the DEF's wiring and the
//! cells' pins, and takes each gate from its pin's `ANTENNAGATEAREA` and
//! each diode from its pin's `ANTENNADIFFAREA` (`MacroPinAntenna`), on a
//! deck of the LEF's layer names with the same rows ([`def_deck`]). Its
//! findings sit at the gates' pins, the contacts. `OpenROAD` 26Q2 reads
//! no `ANTENNAPARTIAL*` or `ANTENNAMAX*CAR` (`AntennaChecker.cc` has no
//! use of them), so those are checked against Appendix C's examples
//! alone (`tests/engine/def.rs`).
//!
//! **Compared.** Per row, per group of gates on one net at the row's stage
//! (the board's construction, [`Board::group`]): the checker gives every
//! gate of the group the same ratio; the group carries exactly one `GPurify`
//! violation, at one of its gates, when that ratio is above the row's limit,
//! and none otherwise; the two ratios agree to `0.0051 / 1000` (two printed
//! decimals at the factor) plus 1e-9 relative.

use super::antenna_board::{
    area, contains, Board, BoardRow, Findings, Gate, Profile, H5, H5_DIODE_MAX, H5_MAX, LIMIT,
    ROWS, THICKNESS,
};
use super::Rect;
use crate::harness;
use gpurify::check::report::Measurement;
use gpurify_testgen::oracle;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

/// Seeded boards per run, from [`FIRST_SEED`]: a different draw from the
/// `KLayout` differential's.
const BOARDS: u64 = 300;
const FIRST_SEED: u64 = 1_000_000;

/// Boards per DEF.
const BATCH: usize = 50;

/// Boards are placed this far apart, nm.
const SPACING: i64 = 40_000;

/// How long one `OpenROAD` run may take; it takes seconds.
const LIMIT_TIME: Duration = Duration::from_mins(10);

/// The factor every area and side area is scaled by.
const FACTOR: f64 = 1000.0;

/// The report's resolution at [`FACTOR`]: two decimals, rounded.
const PRINTED: f64 = 0.0051;

/// The routing and cut layers, bottom-up, with each one's antenna rule
/// (`true` for a metal: side area too).
const LAYERS: [(&str, bool); 7] = [
    ("poly", false),
    ("cont", false),
    ("met1", true),
    ("via1", false),
    ("met2", true),
    ("via2", false),
    ("met3", true),
];

/// Micrometres of a nanometre coordinate, exact to the LEF grid.
fn um(nm: i64) -> String {
    #[allow(clippy::cast_precision_loss, reason = "coordinates far below 2^53")]
    let v = nm as f64 / 1000.0;
    format!("{v}")
}

/// Which of the four runs a LEF is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Run {
    /// Every ratio printed, nothing flagged: the plain rows' values.
    Values,
    /// A tiny `ANTENNAAREARATIO` on the metals: the plain diode verdicts.
    Verdicts,
    /// LEF's diode terms ([`H5`]) on every layer, nothing flagged.
    H5Values,
    /// The same, with [`H5_MAX`] and the [`H5_DIODE_MAX`] table on the
    /// metals: the `h5lim` verdicts.
    H5Verdicts,
}

/// A piecewise-linear table as LEF writes it, areas in µm², each value
/// scaled by `scale`.
fn pwl(points: &[(i64, f64)], scale: f64) -> String {
    #[allow(clippy::cast_precision_loss, reason = "areas far below 2^53")]
    let p: Vec<String> = points
        .iter()
        .map(|&(a, v)| format!("( {} {} )", a as f64 / 1e6, v * scale))
        .collect();
    format!("( {} )", p.join(" "))
}

/// The technology and every cell, for one run.
fn lef(boards: &[Board], run: Run) -> String {
    let mut s = String::from(
        "VERSION 5.8 ;\nBUSBITCHARS \"[]\" ;\nDIVIDERCHAR \"/\" ;\n\
         UNITS\n  DATABASE MICRONS 1000 ;\nEND UNITS\nMANUFACTURINGGRID 0.001 ;\n",
    );
    for (name, metal) in LAYERS {
        let _ = writeln!(s, "LAYER {name}");
        if name == "poly" || metal {
            let direction = if name == "met2" {
                "VERTICAL"
            } else {
                "HORIZONTAL"
            };
            let _ = writeln!(
                s,
                "  TYPE ROUTING ;\n  DIRECTION {direction} ;\n  PITCH 0.4 ;\n  WIDTH 0.2 ;"
            );
        } else {
            let _ = writeln!(s, "  TYPE CUT ;");
        }
        if name != "poly" {
            let h5 = matches!(run, Run::H5Values | Run::H5Verdicts);
            let ratio = match run {
                Run::Verdicts if metal => "0.000001".to_owned(),
                Run::H5Verdicts if metal => format!("{}", H5_MAX * FACTOR),
                _ => "1000000000".to_owned(),
            };
            let (cut, minus, plus, reduce) = H5;
            let factor = if h5 && !metal { cut * FACTOR } else { FACTOR };
            let _ = writeln!(
                s,
                "  ANTENNAAREAFACTOR {factor} ;\n  ANTENNAAREARATIO {ratio} ;"
            );
            if h5 {
                let _ = writeln!(
                    s,
                    "  ANTENNAAREAMINUSDIFF {} ;\n  ANTENNAGATEPLUSDIFF {plus} ;\n  ANTENNAAREADIFFREDUCEPWL {} ;",
                    minus * FACTOR,
                    pwl(&reduce, 1.0)
                );
            }
            if run == Run::H5Verdicts && metal {
                let _ = writeln!(
                    s,
                    "  ANTENNADIFFAREARATIO PWL {} ;",
                    pwl(&H5_DIODE_MAX, FACTOR)
                );
            }
            if metal {
                let _ = writeln!(
                    s,
                    "  THICKNESS {} ;\n  ANTENNASIDEAREAFACTOR {FACTOR} ;\n  ANTENNASIDEAREARATIO 1000000000 ;",
                    um(THICKNESS)
                );
            }
        }
        let _ = writeln!(s, "END {name}");
    }
    for (cut, lower, upper) in [
        ("cont", "poly", "met1"),
        ("via1", "met1", "met2"),
        ("via2", "met2", "met3"),
    ] {
        let _ = writeln!(s, "VIA {cut}_v DEFAULT");
        for layer in [lower, cut, upper] {
            let _ = writeln!(s, "  LAYER {layer} ;\n    RECT 0 0 0.2 0.2 ;");
        }
        let _ = writeln!(s, "END {cut}_v");
    }
    for (k, board) in boards.iter().enumerate() {
        let dx = SPACING * i64::try_from(k).expect("small");
        for (g, gate) in board.gates.iter().enumerate() {
            let mut cell = |name: String, property: &str, nm2: i64, port: Rect| {
                #[allow(clippy::cast_precision_loss, reason = "areas far below 2^53")]
                let um2 = nm2 as f64 / 1e6;
                let _ = writeln!(
                    s,
                    "MACRO {name}\n  CLASS CORE ;\n  ORIGIN 0 0 ;\n  SIZE 0.2 BY 0.2 ;\n  \
                     PIN A\n    DIRECTION INPUT ;\n    USE SIGNAL ;\n    {property} {um2} ;\n    \
                     PORT\n      LAYER poly ;\n        RECT {} {} {} {} ;\n    END\n  END A\nEND {name}",
                    um(port.0 + dx),
                    um(port.1),
                    um(port.2 + dx),
                    um(port.3)
                );
            };
            cell(
                format!("G{k}_{g}"),
                "ANTENNAGATEAREA",
                area(gate.marker),
                gate.cont,
            );
            if let Some((diff, cont)) = gate.diode {
                cell(format!("D{k}_{g}"), "ANTENNADIFFAREA", area(diff), cont);
            }
        }
    }
    s.push_str("END LIBRARY\n");
    s
}

/// The boards side by side, every pin and shape on one net.
fn def(boards: &[Board]) -> String {
    let mut components = Vec::new();
    let mut pins = String::new();
    let mut routes: Vec<String> = Vec::new();
    for (k, board) in boards.iter().enumerate() {
        let dx = SPACING * i64::try_from(k).expect("small");
        let via = |cut: &str, r: Rect| {
            let lower = match cut {
                "cont" => "poly",
                "via1" => "met1",
                _ => "met2",
            };
            format!("{lower} ( {} {} ) {cut}_v", r.0 + dx, r.1)
        };
        for (g, gate) in board.gates.iter().enumerate() {
            components.push(format!("- g{k}_{g} G{k}_{g} + PLACED ( 0 0 ) N ;"));
            let _ = write!(pins, " ( g{k}_{g} A )");
            routes.push(via("cont", gate.cont));
            if let Some((_, cont)) = gate.diode {
                components.push(format!("- d{k}_{g} D{k}_{g} + PLACED ( 0 0 ) N ;"));
                let _ = write!(pins, " ( d{k}_{g} A )");
                routes.push(via("cont", cont));
            }
        }
        for &(layer, r) in &board.wires {
            routes.push(if layer.starts_with("via") {
                via(layer, r)
            } else {
                format!(
                    "{layer} ( {} {} ) RECT ( 0 0 {} {} )",
                    r.0 + dx,
                    r.1,
                    r.2 - r.0,
                    r.3 - r.1
                )
            });
        }
    }
    let width = SPACING * i64::try_from(boards.len()).expect("small");
    let mut s = format!(
        "VERSION 5.8 ;\nDIVIDERCHAR \"/\" ;\nBUSBITCHARS \"[]\" ;\nDESIGN boards ;\n\
         UNITS DISTANCE MICRONS 1000 ;\nDIEAREA ( 0 0 ) ( {width} 20000 ) ;\n\
         COMPONENTS {} ;\n{}\nEND COMPONENTS\nNETS 1 ;\n- all{pins}\n  + ROUTED {}",
        components.len(),
        components.join("\n"),
        routes.join("\n    NEW ")
    );
    s.push_str("\n  ;\nEND NETS\nEND DESIGN\n");
    s
}

/// Which of a pin's ratios a report line gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Par,
    Psr,
    Car,
    Csr,
}

/// Per `(instance, layer, kind)`: the printed value and whether it is
/// flagged.
type Report = BTreeMap<(String, String, Kind), (f64, bool)>;

/// The `-verbose` report: `Pin:` and `Layer:` headers, then per ratio a value
/// line and a `Required ratio` line naming which ratio it was.
fn parse(text: &str) -> Result<Report, String> {
    let mut out = Report::new();
    let (mut pin, mut layer, mut value) = (None::<String>, None::<String>, None::<f64>);
    for line in text.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("Pin:") {
            let inst = rest.split_whitespace().next().unwrap_or_default();
            pin = Some(inst.split('/').next().unwrap_or_default().to_owned());
        } else if let Some(rest) = line.strip_prefix("Layer:") {
            layer = Some(rest.trim().to_owned());
        } else if let Some(rest) = line
            .strip_prefix("Partial area ratio:")
            .or_else(|| line.strip_prefix("Cumulative area ratio:"))
        {
            value = Some(
                rest.trim()
                    .parse()
                    .map_err(|_| format!("not a number: {line}"))?,
            );
        } else if line.starts_with("Required ratio:") {
            let kind = if line.contains("(Gate area)") {
                Kind::Par
            } else if line.contains("(Side area)") {
                Kind::Psr
            } else if line.contains("(Cumulative area)") {
                Kind::Car
            } else if line.contains("(Cumulative side area)") {
                Kind::Csr
            } else {
                return Err(format!("unknown ratio: {line}"));
            };
            let (Some(p), Some(l), Some(v)) = (&pin, &layer, value.take()) else {
                return Err(format!("a ratio outside a pin and layer: {line}"));
            };
            out.insert(
                (p.clone(), l.clone(), kind),
                (v, line.contains("(VIOLATED)")),
            );
        }
    }
    Ok(out)
}

/// The value `OpenROAD`'s report gives `row` for gate `g` of board `k`, at
/// the factor; zero where the gate reaches none of the row's layers.
fn reported(report: &Report, k: usize, g: usize, row: &BoardRow) -> f64 {
    let inst = format!("g{k}_{g}");
    let read = |layer: &str, kind: Kind| {
        report
            .get(&(inst.clone(), layer.to_owned(), kind))
            .map_or(0.0, |v| v.0)
    };
    let collectors: Vec<&str> = row.collectors.split(", ").collect();
    let (one, cumulative) = if row.sidewall {
        (Kind::Psr, Kind::Csr)
    } else {
        (Kind::Par, Kind::Car)
    };
    if let &[layer] = collectors.as_slice() {
        read(layer, one)
    } else {
        collectors
            .iter()
            .map(|&l| read(l, cumulative))
            .fold(0.0, f64::max)
    }
}

/// What the comparisons found.
#[derive(Default)]
struct Tally {
    boards: usize,
    /// Groups compared, and of those flagged by both.
    groups: usize,
    flagged: usize,
    broken: Vec<String>,
}

/// One board's `GPurify` violations per row: `(ratio, at)`.
fn gpurify(seed: u64) -> BTreeMap<String, Findings> {
    let fixture = super::klayout::board_fixture(seed);
    let ran = harness::run(&fixture).unwrap_or_else(|why| panic!("{}: {why}", fixture.name));
    for (id, outcome, _) in &ran.rows {
        assert_eq!(
            *outcome,
            gpurify::check::report::Outcome::Ran,
            "{}: {id} did not run",
            fixture.name
        );
    }
    let mut out: BTreeMap<String, Findings> = BTreeMap::new();
    for (id, measured, at) in ran.findings {
        if let Measurement::Ratio(r) = measured {
            out.entry(id).or_default().push((r, at));
        }
    }
    out
}

/// Compares one row of one board: per group of gates at the row's stage,
/// `value(g)` (scaled by [`FACTOR`]) and `flagged(g)` against `GPurify`'s
/// violations, each found at the gate whose `site` holds it.
fn compare_row(
    board: &Board,
    row: &BoardRow,
    site: fn(&Gate) -> Rect,
    findings: &[(f64, (i64, i64))],
    value: impl Fn(usize) -> f64,
    flagged: impl Fn(usize) -> bool,
    tally: &mut Tally,
) {
    let at = |what: String| format!("board {} {}: {what}", board.seed, row.id);
    let mut groups: BTreeMap<(u8, usize), Vec<usize>> = BTreeMap::new();
    for g in 0..board.gates.len() {
        groups
            .entry(board.group(g, row.grouped_at))
            .or_default()
            .push(g);
    }
    let mut hits: BTreeMap<(u8, usize), Vec<f64>> = BTreeMap::new();
    for &(ratio, point) in findings {
        let Some(g) = (0..board.gates.len()).find(|&g| contains(site(&board.gates[g]), point))
        else {
            tally.broken.push(at(format!(
                "GPurify flags {ratio} at {point:?}, on no gate"
            )));
            continue;
        };
        hits.entry(board.group(g, row.grouped_at))
            .or_default()
            .push(ratio);
    }
    for (key, gates) in &groups {
        tally.groups += 1;
        let theirs = value(gates[0]);
        if let Some(&g) = gates.iter().find(|&&g| (value(g) - theirs).abs() > PRINTED) {
            tally.broken.push(at(format!(
                "OpenROAD gives gates {} and {g} of one net {theirs} and {}",
                gates[0],
                value(g)
            )));
        }
        let ours = hits.get(key).map_or(&[][..], Vec::as_slice);
        match (flagged(gates[0]), ours) {
            (false, []) => {}
            (true, [r]) => {
                tally.flagged += 1;
                if (r * FACTOR - theirs).abs() > PRINTED + 1e-9 * theirs.abs() {
                    tally.broken.push(at(format!(
                        "gates {gates:?}: GPurify measures {r}, OpenROAD {theirs} at a factor of {FACTOR}"
                    )));
                }
            }
            (want, got) => tally.broken.push(at(format!(
                "gates {gates:?}: OpenROAD {} ({theirs} at a factor of {FACTOR}), GPurify reports {got:?}",
                if want { "flags them" } else { "does not flag them" }
            ))),
        }
    }
}

/// The deck `GPurify` reads the boards' LEF and DEF with: the LEF's layer
/// names, poly and the metals conductors joined by their cuts, `gate` and
/// `diff` drawn layers that the DEF leaves empty (the pins carry their
/// areas), and every row of the board deck.
fn def_deck() -> String {
    format!(
        "grid 1nm\nlayer poly = gds(1, 0)\nlayer cont = gds(2, 0)\nlayer met1 = gds(3, 0)\n\
         layer via1 = gds(4, 0)\nlayer met2 = gds(5, 0)\nlayer via2 = gds(6, 0)\n\
         layer met3 = gds(7, 0)\nlayer gate = gds(8, 0)\nlayer diff = gds(9, 0)\n\
         connect conductors [poly, met1, met2, met3]\nconnect touch_within_layer\n\
         connect via cont [poly, met1]\nconnect via via1 [met1, met2]\n\
         connect via via2 [met2, met3]\n\
         connect label poly names poly\nconnect label met1 names met1\n\
         connect label met2 names met2\nconnect label met3 names met3\n{}\n",
        super::antenna_board::rows()
    )
}

/// `GPurify` on the batch's own `boards.def` and `values.lef` in `dir`:
/// per board, each row's violations at board-local points.
fn def_findings(dir: &Path, boards: usize) -> Result<Vec<BTreeMap<String, Findings>>, String> {
    use gpurify::engine::run::{run, Checks, RunOptions, StageStatus};
    std::fs::write(dir.join("gpurify.deck"), def_deck()).map_err(|e| e.to_string())?;
    let inputs = gpurify::engine::pipeline::Inputs {
        layout: dir.join("boards.def"),
        lef: vec![dir.join("values.lef")],
        deck: dir.join("gpurify.deck"),
        ..gpurify::engine::pipeline::Inputs::default()
    };
    let options = RunOptions {
        checks: Checks {
            drc: false,
            erc: true,
            lvs: false,
            pex: false,
        },
        lvs: gpurify::check::lvs::CompareOptions::default(),
        quasistatic_nets: Vec::new(),
    };
    let (loaded, _, outputs, summary) = run(&inputs, &options).map_err(|e| e.to_string())?;
    if summary.erc != StageStatus::Ran {
        return Err(format!("GPurify's ERC on the DEF: {:?}", summary.erc));
    }
    if let Some(run) = outputs
        .runs
        .iter()
        .find(|r| r.outcome != gpurify::check::report::Outcome::Ran)
    {
        return Err(format!("{} did not run", loaded.strings.resolve(run.rule)));
    }
    let mut out = vec![BTreeMap::<String, Findings>::new(); boards];
    let v = &outputs.violations;
    for k in 0..v.len() {
        let Measurement::Ratio(r) = v.measured[k] else {
            return Err("an antenna finding that is no ratio".into());
        };
        let (x, y) = (v.at[k].x.raw(), v.at[k].y.raw());
        let board = usize::try_from(x / SPACING).map_err(|e| e.to_string())?;
        let local = (x - SPACING * i64::try_from(board).expect("small"), y);
        out.get_mut(board)
            .ok_or_else(|| format!("a finding at {x}, past the boards"))?
            .entry(loaded.strings.resolve(v.rule[k]).to_owned())
            .or_default()
            .push((r, local));
    }
    Ok(out)
}

/// One batch: `GPurify` on every board (each its own GDS, or, `through_pins`,
/// all of them as the batch's LEF and DEF), `OpenROAD` on the batch's DEF
/// four times (ratios and verdicts, plain and with LEF's diode terms),
/// every row compared.
fn batch(openroad: &Path, seeds: &[u64], through_pins: bool) -> Tally {
    let boards: Vec<Board> = seeds.iter().map(|&s| Board::random(s)).collect();
    let dir = oracle::scratch("openroad-antenna");
    let write = |name: &str, text: &str| {
        std::fs::write(dir.join(name), text).expect("the scratch directory is writable");
    };
    write("boards.def", &def(&boards));
    let mut reports = Vec::new();
    for (name, run) in [
        ("values", Run::Values),
        ("verdicts", Run::Verdicts),
        ("h5values", Run::H5Values),
        ("h5verdicts", Run::H5Verdicts),
    ] {
        write(&format!("{name}.lef"), &lef(&boards, run));
        write(
            &format!("{name}.tcl"),
            &format!(
                "read_lef {name}.lef\nread_def boards.def\n\
                 check_antennas -verbose -report_file {name}.rpt\n"
            ),
        );
        oracle::run(
            openroad,
            &["-no_init", "-no_splash", "-exit", &format!("{name}.tcl")],
            &dir,
            LIMIT_TIME,
        );
        let text = std::fs::read_to_string(dir.join(format!("{name}.rpt"))).unwrap_or_default();
        reports.push(parse(&text));
    }
    let mut tally = Tally::default();
    let from_def = if through_pins {
        match def_findings(&dir, boards.len()) {
            Ok(found) => Some(found),
            Err(why) => {
                tally.broken.push(why);
                tally.broken.push(super::kept(&dir));
                return tally;
            }
        }
    } else {
        None
    };
    let site: fn(&Gate) -> Rect = if through_pins {
        |gate| gate.cont
    } else {
        |gate| gate.marker
    };
    match (&reports[0], &reports[1], &reports[2], &reports[3]) {
        (Ok(values), Ok(verdicts), Ok(h5values), Ok(h5verdicts)) => {
            for (k, board) in boards.iter().enumerate() {
                tally.boards += 1;
                let found = match &from_def {
                    Some(all) => all[k].clone(),
                    None => gpurify(board.seed),
                };
                for row in &ROWS {
                    if row.id == "par.poly" {
                        continue;
                    }
                    let findings = found.get(row.id).map_or(&[][..], Vec::as_slice);
                    let violated = |report: &Report, g: usize| {
                        report
                            .get(&(format!("g{k}_{g}"), row.collectors.to_owned(), Kind::Par))
                            .is_some_and(|v| v.1)
                    };
                    let (from, verdict) = match (row.profile, row.diode) {
                        (Profile::Plain, true) => (values, Some(verdicts)),
                        (Profile::Plain, false) => (values, None),
                        (Profile::H5, _) => (h5values, None),
                        (Profile::H5Limited, _) => (h5values, Some(h5verdicts)),
                    };
                    compare_row(
                        board,
                        row,
                        site,
                        findings,
                        |g| reported(from, k, g, row),
                        |g| match verdict {
                            Some(report) => violated(report, g),
                            None => reported(from, k, g, row) > LIMIT * FACTOR,
                        },
                        &mut tally,
                    );
                }
            }
        }
        (a, b, c, d) => tally.broken.push(format!(
            "OpenROAD's reports do not read: {:?} {:?} {:?} {:?}",
            a.as_ref().err(),
            b.as_ref().err(),
            c.as_ref().err(),
            d.as_ref().err()
        )),
    }
    if tally.broken.is_empty() {
        let _ = std::fs::remove_dir_all(&dir);
    } else {
        tally.broken.push(super::kept(&dir));
    }
    tally
}

/// 300 seeded boards: every ratio of every gate group, each layer's own, the
/// side areas and the cumulative ones, agrees with `OpenROAD`'s
/// `check_antennas`, and a net with a diode is exempt in both.
///
/// Oracle: differential against `OpenROAD`'s antenna checker (module docs).
/// The nightly `oracles` job runs it.
#[test]
#[ignore = "release tier: needs openroad (nix develop .#oracles)"]
fn openroad_antenna_differential_on_random_boards() {
    differential(false);
}

/// The same 300 boards, `GPurify` reading `OpenROAD`'s own LEF and DEF:
/// each gate a macro pin's `ANTENNAGATEAREA`, each diode a pin's
/// `ANTENNADIFFAREA`, every ratio of every gate group as `OpenROAD` gives
/// it (ERC-A14).
///
/// Oracle: differential against `OpenROAD`'s antenna checker on the same
/// files (module docs). The nightly `oracles` job runs it.
#[test]
#[ignore = "release tier: needs openroad (nix develop .#oracles)"]
fn openroad_antenna_differential_through_macro_pins() {
    differential(true);
}

/// [`batch`] over every board, in parallel, and the tally checked.
fn differential(through_pins: bool) {
    let openroad = oracle::tool("openroad");
    let seeds: Vec<u64> = (FIRST_SEED..FIRST_SEED + BOARDS).collect();
    let chunks: Vec<&[u64]> = seeds.chunks(BATCH).collect();
    let next = AtomicUsize::new(0);
    let total = Mutex::new(Tally::default());
    std::thread::scope(|scope| {
        for _ in 0..oracle::MAX_RUNNING {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(chunk) = chunks.get(i) else {
                    break;
                };
                let found = batch(&openroad, chunk, through_pins);
                let mut total = total.lock().expect("not poisoned");
                total.boards += found.boards;
                total.groups += found.groups;
                total.flagged += found.flagged;
                total.broken.extend(found.broken);
            });
        }
    });
    let total = total.into_inner().expect("not poisoned");
    println!(
        "openroad antenna{}: {} boards, {} gate groups compared, {} flagged by both, {} broken",
        if through_pins {
            " through macro pins"
        } else {
            ""
        },
        total.boards,
        total.groups,
        total.flagged,
        total.broken.len()
    );
    assert!(
        total.broken.is_empty(),
        "{} disagreements (first 60):\n{}",
        total.broken.len(),
        total.broken[..total.broken.len().min(60)].join("\n")
    );
    assert_eq!(total.boards, seeds.len(), "every board ran");
    assert!(
        total.flagged > 3000,
        "too few comparisons: {}",
        total.flagged
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every row of the board deck runs on 40 boards, and the H5 rows read
    /// as the plain ones where LEF's diode terms vanish: on a gate with no
    /// diode, `h5.cont` is `cut_factor` (2.5) times `par.cont`, and each
    /// `h5.<metal>` is `par.<metal>`.
    ///
    /// Oracle: LEF/DEF 5.8 Appendix C's PAR with `diff_area = 0`
    /// (`ANTENNAAREAMINUSDIFF` and `ANTENNAGATEPLUSDIFF` multiply it, and
    /// `ANTENNAAREADIFFREDUCEPWL` is 1 at 0 in [`H5`]), against `GPurify`'s
    /// own plain rows.
    #[test]
    fn the_board_deck_runs_and_its_h5_rows_reduce_to_the_plain_ones() {
        let mut compared = 0;
        for seed in 0..40 {
            let found = gpurify(seed);
            let board = Board::random(seed);
            for g in 0..board.gates.len() {
                let at_gate = |id: &str| {
                    found.get(id).and_then(|f| {
                        f.iter()
                            .find(|(_, p)| contains(board.gates[g].marker, *p))
                            .map(|v| v.0)
                    })
                };
                if board.gates[g].diode.is_some() {
                    continue;
                }
                if let (Some(h5), Some(par)) = (at_gate("h5.cont"), at_gate("par.cont")) {
                    assert!(
                        (h5 - H5.0 * par).abs() <= 1e-9 * h5,
                        "board {seed} gate {g}"
                    );
                    compared += 1;
                }
                // A met1 run without any diode: the terms vanish on it.
                let run = board.gates[g].run;
                let diode_free = board
                    .gates
                    .iter()
                    .all(|o| o.run != run || o.diode.is_none());
                if diode_free {
                    if let (Some(h5), Some(par)) = (at_gate("h5.met1"), at_gate("par.met1")) {
                        assert!((h5 - par).abs() <= 1e-9 * h5, "board {seed} gate {g}");
                        compared += 1;
                    }
                }
            }
        }
        assert!(compared > 40, "too few gates compared: {compared}");
    }

    /// The report reader on the checker's own format
    /// (`AntennaChecker::checkPAR` and its siblings), a pin with a violated
    /// partial ratio whose cumulative line is then left out.
    ///
    /// Oracle: hand-written report text in the format strings of
    /// `src/ant/src/AntennaChecker.cc` (`OpenROAD` 26Q2).
    #[test]
    fn the_verbose_report_reads_per_pin_layer_and_ratio() {
        let text = "Net: all\n  Pin:   g0_1/A (G0_1)\n    Layer: met1\n      \
                    Partial area ratio: 2000.00\n      Required ratio: 1000000000.00 (Gate area) \n      \
                    Cumulative area ratio: 2000.00\n      Required ratio:    0.00 (Cumulative area) \n      \
                    Partial area ratio:  952.00\n      Required ratio: 1000000000.00 (Side area) \n\n    \
                    Layer: met2\n      Partial area ratio:   40.50\n      Required ratio:    0.00 (Gate area) (VIOLATED)\n";
        let report = parse(text).expect("it reads");
        let get = |layer: &str, kind| report[&("g0_1".to_owned(), layer.to_owned(), kind)];
        assert_eq!(get("met1", Kind::Par), (2000.0, false));
        assert_eq!(get("met1", Kind::Car), (2000.0, false));
        assert_eq!(get("met1", Kind::Psr), (952.0, false));
        assert_eq!(get("met2", Kind::Par), (40.5, true));
        assert_eq!(report.len(), 4);
    }
}
