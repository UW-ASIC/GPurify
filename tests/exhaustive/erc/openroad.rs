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
//! **Compared.** Per row, per group of gates on one net at the row's stage
//! (the board's construction, [`Board::group`]): the checker gives every
//! gate of the group the same ratio; the group carries exactly one `GPurify`
//! violation, at one of its gates, when that ratio is above the row's limit,
//! and none otherwise; the two ratios agree to `0.0051 / 1000` (two printed
//! decimals at the factor) plus 1e-9 relative.

use super::antenna_board::{area, contains, Board, BoardRow, Findings, LIMIT, ROWS, THICKNESS};
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

/// The technology and every cell, for one run. `verdict` swaps the ratios
/// for a tiny `ANTENNAAREARATIO` on the metals (the diode run).
fn lef(boards: &[Board], verdict: bool) -> String {
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
            let ratio = if verdict && metal {
                "0.000001"
            } else {
                "1000000000"
            };
            let _ = writeln!(
                s,
                "  ANTENNAAREAFACTOR {FACTOR} ;\n  ANTENNAAREARATIO {ratio} ;"
            );
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
    for (id, outcome) in &ran.rows {
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
/// violations.
fn compare_row(
    board: &Board,
    row: &BoardRow,
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
        let Some(g) = (0..board.gates.len()).find(|&g| contains(board.gates[g].marker, point))
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

/// One batch: `GPurify` on every board, `OpenROAD` twice on the batch's DEF
/// (ratios, then the diode verdicts), every row compared.
fn batch(openroad: &Path, seeds: &[u64]) -> Tally {
    let boards: Vec<Board> = seeds.iter().map(|&s| Board::random(s)).collect();
    let dir = oracle::scratch("openroad-antenna");
    let write = |name: &str, text: &str| {
        std::fs::write(dir.join(name), text).expect("the scratch directory is writable");
    };
    write("boards.def", &def(&boards));
    let mut reports = Vec::new();
    for (run, verdict) in [("values", false), ("verdicts", true)] {
        write(&format!("{run}.lef"), &lef(&boards, verdict));
        write(
            &format!("{run}.tcl"),
            &format!(
                "read_lef {run}.lef\nread_def boards.def\n\
                 check_antennas -verbose -report_file {run}.rpt\n"
            ),
        );
        oracle::run(
            openroad,
            &["-no_init", "-no_splash", "-exit", &format!("{run}.tcl")],
            &dir,
            LIMIT_TIME,
        );
        let text = std::fs::read_to_string(dir.join(format!("{run}.rpt"))).unwrap_or_default();
        reports.push(parse(&text));
    }
    let mut tally = Tally::default();
    match (&reports[0], &reports[1]) {
        (Ok(values), Ok(verdicts)) => {
            for (k, board) in boards.iter().enumerate() {
                tally.boards += 1;
                let found = gpurify(board.seed);
                for row in &ROWS {
                    if row.id == "par.poly" {
                        continue;
                    }
                    let findings = found.get(row.id).map_or(&[][..], Vec::as_slice);
                    if row.diode {
                        let layer = row.collectors;
                        compare_row(
                            board,
                            row,
                            findings,
                            |g| reported(values, k, g, row),
                            |g| {
                                verdicts
                                    .get(&(format!("g{k}_{g}"), layer.to_owned(), Kind::Par))
                                    .is_some_and(|v| v.1)
                            },
                            &mut tally,
                        );
                    } else {
                        compare_row(
                            board,
                            row,
                            findings,
                            |g| reported(values, k, g, row),
                            |g| reported(values, k, g, row) > LIMIT * FACTOR,
                            &mut tally,
                        );
                    }
                }
            }
        }
        (a, b) => tally.broken.push(format!(
            "OpenROAD's reports do not read: {:?} {:?}",
            a.as_ref().err(),
            b.as_ref().err()
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
                let found = batch(&openroad, chunk);
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
        "openroad antenna: {} boards, {} gate groups compared, {} flagged by both, {} broken",
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
