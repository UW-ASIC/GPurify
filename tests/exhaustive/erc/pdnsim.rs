//! The supply grid's DC solve against `OpenROAD`'s `PDNSim`
//! (`analyze_power_grid`, the `psm` module; testing-plan §4 L6, ledger O1):
//! the voltage at every load and the current in every via cut and wire
//! segment, on seeded meshes.
//!
//! **The meshes** ([`Mesh`]). One to three horizontal met1 rails, one to
//! three vertical met2 straps across them, a via1 cut at some crossings
//! (every rail to the first strap, every strap to the first rail, the rest
//! by coin), a met3 pad on the first strap through one via2 cut, and one to
//! four loads per rail, each a resistor whose marker is centred on the
//! rail's centre line at least 800 nm from any strap. The supply is VDD at
//! 1.8 V carrying a budget `B` shared equally by the loads. Every shape is a
//! rectangle on a 100 nm lattice, every cut centred on the crossing it
//! joins.
//!
//! **What `PDNSim` is given.** A LEF and a DEF written from the mesh, never
//! from anything `GPurify` extracted: each layer's `RESISTANCE` (met1 0.125
//! Ω/sq, via1 0.0625 Ω per cut, met2 0.0625 Ω/sq, via2 0.05 Ω per cut, met3
//! 0.03 Ω/sq, the deck's `pex` sheets), the rails and straps as special-net
//! `RECT`s, each cut a via, the pad as the net's block pin (`PDNSim` holds
//! every met3 node the pin covers at 1.8 V: the pad's one node), and each
//! load an instance whose power pin sits on the
//! rail at the load, drawing `B / n` (`set_pdnsim_inst_power`, the power
//! over 1.8 V). The metals' `PITCH` sets `PDNSim`'s node-merge radius to
//! 5 nm (met1, met2: nodes here are 100 nm apart or coincide) and 5 µm on
//! met3, where it adds no filler node to the 200 nm pad.
//!
//! **Oracle.** Ohm's and Kirchhoff's laws as `PDNSim` assembles them: a
//! node at each rectangle's centre, each cut's centre and each pin; a wire
//! segment between neighbouring nodes of one rectangle of `Rs · length /
//! width`, a cut of its layer's resistance per cut, solved by sparse LU.
//! `GPurify` (`erc::power`) taps each polygon at its centre, at each
//! connection and at each load, with the same segments, and solves by
//! conjugate gradients to 1e-10. One connection `PDNSim` adds is encoded
//! here: an instance's current enters at its own node, joined to the pin's
//! grid node through 1 mΩ (`psm::TermConnection::kResistance`), so an
//! instance reads `1.8 V − drop − (B / n) · 1 mΩ`.
//!
//! **Compared.** Every load's voltage in `PDNSim`'s `-voltage_file` (six
//! decimals of a volt) against `GPurify`'s drop at that load (`ir_drop` at a
//! limit far below every drop) to 0.6 µV; every via cut's current
//! (`-em_outfile`, three significant digits) against `GPurify`'s
//! (`em_current_density` at a limit far below every current) to 6e-4
//! relative, in both directions; and every wire segment `GPurify` reports
//! against a `PDNSim` segment on the same layer ending at the same node, to
//! the same tolerance.

use super::{load, rect, Rect, ERC};
use crate::harness::{self, Fixture, Layout};
use gpurify::check::report::Measurement;
use gpurify_testgen::{oracle, Rng};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

/// Seeded meshes per run, from [`FIRST_SEED`].
const MESHES: u64 = 100;
const FIRST_SEED: u64 = 0x0D_5000;

/// How long one `OpenROAD` run may take; it takes a second.
const LIMIT: Duration = Duration::from_mins(5);

/// The supply, mV.
const VDD_MV: f64 = 1800.0;

/// An instance's join to its pin in `PDNSim`, Ω.
const PIN_OHMS: f64 = 0.001;

/// A voltage agrees to this, V: the file's six decimals.
const VOLTS: f64 = 0.6e-6;

/// A current agrees to this, relative: the file's three significant digits.
const AMPS: f64 = 6e-4;

/// The rails' extent in x, nm.
const X0: i64 = 1000;
const X1: i64 = 41_000;

/// Each layer's resistance: Ω per square for a metal, Ω per cut for a cut.
const SHEETS: [(&str, f64); 5] = [
    ("met1", 0.125),
    ("via1", 0.0625),
    ("met2", 0.0625),
    ("via2", 0.05),
    ("met3", 0.03),
];

/// The deck: the five layers with their sheets, a load resistor (marker over
/// a rail and a private poly stub), `ir_drop` and `em_current_density` at
/// limits far below anything a mesh carries.
fn deck() -> String {
    let mut s = String::from(
        "grid 1nm
layer met1 = gds(1, 0)
layer via1 = gds(2, 0)
layer met2 = gds(3, 0)
layer via2 = gds(4, 0)
layer met3 = gds(5, 0)
layer poly = gds(6, 0)
layer mk = gds(7, 0)
layer m3txt = gds(5, 1)
connect conductors [met1, met2, met3, poly]
connect touch_within_layer
connect via via1 [met1, met2]
connect via via2 [met2, met3]
connect label m3txt names met3
device resistor mk model \"load\" terminals [met1, poly]
",
    );
    for (i, (layer, sheet)) in SHEETS.iter().enumerate() {
        let _ = writeln!(
            s,
            "pex {layer} thickness 100nm height {}nm sheet {sheet}ohm dielectric 3.9 area_cap 1aF/um2 fringe_cap 1aF/um",
            100 * (i + 1)
        );
    }
    s.push_str(
        "pex poly thickness 100nm height 50nm sheet 8ohm dielectric 3.9 area_cap 1aF/um2 fringe_cap 1aF/um
rule ir ir_drop()
rule em em_current_density(met1, via1, met2, via2, met3; max_density: 0.000001uA/um, max_current_per_cut: 0.000001uA)
",
    );
    s
}

/// A seeded mesh.
struct Mesh {
    seed: u64,
    /// `(centre y, width)` per rail.
    rails: Vec<(i64, i64)>,
    /// `(centre x, width)` per strap.
    straps: Vec<(i64, i64)>,
    /// `(rail, strap)` per via1 cut.
    vias: Vec<(usize, usize)>,
    /// `(rail, x)` per load.
    loads: Vec<(usize, i64)>,
    /// The pad's centre y, on the first strap.
    pad: i64,
    /// The supply's budget, µA.
    budget: f64,
}

/// A centred square of side 200 nm.
fn cut((x, y): (i64, i64)) -> Rect {
    (x - 100, y - 100, x + 100, y + 100)
}

impl Mesh {
    fn random(seed: u64) -> Mesh {
        let mut rng = Rng::new(seed);
        let width = |rng: &mut Rng| 100 * rng.range(4, 13);
        let rails: Vec<(i64, i64)> = (0..=rng.range(0, 3))
            .map(|r| (3000 + 6000 * r, width(&mut rng)))
            .collect();
        let mut slots: Vec<i64> = (0..9).map(|k| 5000 + 4000 * k).collect();
        rng.shuffle(&mut slots);
        let count = usize::try_from(1 + rng.range(0, 3)).expect("small");
        let mut xs: Vec<i64> = slots[..count].to_vec();
        xs.sort_unstable();
        let straps: Vec<(i64, i64)> = xs.into_iter().map(|x| (x, width(&mut rng))).collect();
        let mut vias = Vec::new();
        for r in 0..rails.len() {
            for s in 0..straps.len() {
                if r == 0 || s == 0 || rng.below(2) == 1 {
                    vias.push((r, s));
                }
            }
        }
        let mut loads = Vec::new();
        for r in 0..rails.len() {
            let mut here: Vec<i64> = Vec::new();
            let want = 1 + rng.range(0, 4);
            while i64::try_from(here.len()).expect("small") < want {
                let x = 100 * rng.range(15, 406);
                let clear = straps.iter().all(|&(s, _)| (x - s).abs() >= 800)
                    && here.iter().all(|&o| (x - o).abs() >= 300);
                if clear {
                    here.push(x);
                }
            }
            here.sort_unstable();
            loads.extend(here.into_iter().map(|x| (r, x)));
        }
        let pad = match rails.get(1) {
            Some(&(y1, _)) => i64::midpoint(rails[0].0, y1),
            None => rails[0].0 + rails[0].1 / 2 + 600,
        };
        #[allow(clippy::cast_precision_loss, reason = "a small whole number")]
        let budget = (100 * rng.range(10, 201)) as f64;
        Mesh {
            seed,
            rails,
            straps,
            vias,
            loads,
            pad,
            budget,
        }
    }

    /// The straps' extent in y: a micrometre past the outer rails.
    fn strap_span(&self) -> (i64, i64) {
        let (first, last) = (self.rails[0], self.rails[self.rails.len() - 1]);
        (first.0 - first.1 / 2 - 1000, last.0 + last.1 / 2 + 1000)
    }

    fn rail_rect(&self, r: usize) -> Rect {
        let (y, w) = self.rails[r];
        (X0, y - w / 2, X1, y + w / 2)
    }

    fn strap_rect(&self, s: usize) -> Rect {
        let (x, w) = self.straps[s];
        let (lo, hi) = self.strap_span();
        (x - w / 2, lo, x + w / 2, hi)
    }

    fn via_at(&self, (r, s): (usize, usize)) -> (i64, i64) {
        (self.straps[s].0, self.rails[r].0)
    }

    fn pad_at(&self) -> (i64, i64) {
        (self.straps[0].0, self.pad)
    }

    fn fixture(&self) -> Fixture {
        let mut l = Layout::default();
        for r in 0..self.rails.len() {
            rect(&mut l, "met1", self.rail_rect(r));
        }
        for s in 0..self.straps.len() {
            rect(&mut l, "met2", self.strap_rect(s));
        }
        for &v in &self.vias {
            rect(&mut l, "via1", cut(self.via_at(v)));
        }
        rect(&mut l, "via2", cut(self.pad_at()));
        rect(&mut l, "met3", cut(self.pad_at()));
        l = l.label("m3txt", self.pad_at().0, self.pad_at().1, "VDD");
        for &(r, x) in &self.loads {
            load(&mut l, x, self.rails[r].0);
        }
        let mut f = Fixture::new(
            &format!("erc/pdnsim/{}", self.seed),
            &["ERC-E1", "ERC-E2", "ERC-E8", "ERC-E10"],
            &deck(),
            ERC,
        )
        .layout(l);
        f.intent = Some(super::intent(
            &[("core", VDD_MV)],
            &[("VDD", "core", "power")],
            &[format!(
                r#"{{"net":"VDD","max_drop_mv":1e-9,"budget_current_ua":{}}}"#,
                self.budget
            )],
        ));
        f
    }

    /// Each load's current, A.
    fn load_amps(&self) -> f64 {
        #[allow(clippy::cast_precision_loss, reason = "a handful of loads")]
        let n = self.loads.len() as f64;
        self.budget * 1e-6 / n
    }

    fn lef() -> String {
        let mut s = String::from(
            "VERSION 5.8 ;\nBUSBITCHARS \"[]\" ;\nDIVIDERCHAR \"/\" ;\n\
             UNITS\n  DATABASE MICRONS 1000 ;\nEND UNITS\nMANUFACTURINGGRID 0.001 ;\n",
        );
        for (layer, sheet) in SHEETS {
            if layer.starts_with("via") {
                let _ = writeln!(
                    s,
                    "LAYER {layer}\n  TYPE CUT ;\n  RESISTANCE {sheet} ;\nEND {layer}"
                );
            } else {
                // A pitch of 1 nm merges met1 and met2 nodes within 5 nm;
                // met3's 1 µm keeps filler nodes off the pad.
                let (direction, pitch) = match layer {
                    "met2" => ("VERTICAL", "0.001"),
                    "met1" => ("HORIZONTAL", "0.001"),
                    _ => ("HORIZONTAL", "1"),
                };
                let _ = writeln!(
                    s,
                    "LAYER {layer}\n  TYPE ROUTING ;\n  DIRECTION {direction} ;\n  PITCH {pitch} ;\n  \
                     WIDTH 0.1 ;\n  RESISTANCE RPERSQ {sheet} ;\nEND {layer}"
                );
            }
        }
        for (cut, lower, upper) in [("via1", "met1", "met2"), ("via2", "met2", "met3")] {
            let _ = writeln!(s, "VIA {cut}_c DEFAULT");
            for layer in [lower, cut, upper] {
                let _ = writeln!(s, "  LAYER {layer} ;\n    RECT -0.1 -0.1 0.1 0.1 ;");
            }
            let _ = writeln!(s, "END {cut}_c");
        }
        s.push_str(
            "MACRO load\n  CLASS CORE ;\n  ORIGIN 0 0 ;\n  SIZE 0.1 BY 0.1 ;\n  PIN VDD\n    \
             DIRECTION INOUT ;\n    USE POWER ;\n    PORT\n      LAYER met1 ;\n        \
             RECT -0.05 -0.05 0.05 0.05 ;\n    END\n  END VDD\nEND load\nEND LIBRARY\n",
        );
        s
    }

    fn def(&self) -> String {
        let (px, py) = self.pad_at();
        let mut s = format!(
            "VERSION 5.8 ;\nDIVIDERCHAR \"/\" ;\nBUSBITCHARS \"[]\" ;\nDESIGN mesh ;\n\
             UNITS DISTANCE MICRONS 1000 ;\nDIEAREA ( 0 0 ) ( 42000 20000 ) ;\n\
             COMPONENTS {} ;\n",
            self.loads.len()
        );
        for (i, &(r, x)) in self.loads.iter().enumerate() {
            let _ = writeln!(s, "- l{i} load + PLACED ( {x} {} ) N ;", self.rails[r].0);
        }
        let _ = write!(
            s,
            "END COMPONENTS\nPINS 1 ;\n- VDD + NET VDD + SPECIAL + DIRECTION INOUT + USE POWER\n  \
             + LAYER met3 ( -100 -100 ) ( 100 100 )\n  + FIXED ( {px} {py} ) N ;\nEND PINS\n\
             SPECIALNETS 1 ;\n- VDD"
        );
        for i in 0..self.loads.len() {
            let _ = write!(s, " ( l{i} VDD )");
        }
        s.push_str("\n  + USE POWER\n");
        let rects = (0..self.rails.len())
            .map(|r| ("met1", self.rail_rect(r)))
            .chain((0..self.straps.len()).map(|t| ("met2", self.strap_rect(t))))
            .chain(std::iter::once(("met3", cut(self.pad_at()))));
        for (layer, (a, b, c, d)) in rects {
            let _ = writeln!(s, "  + RECT {layer} ( {a} {b} ) ( {c} {d} )");
        }
        let mut vias: Vec<String> = self
            .vias
            .iter()
            .map(|&v| {
                let (x, y) = self.via_at(v);
                format!("met1 0 ( {x} {y} ) via1_c")
            })
            .collect();
        vias.push(format!("met2 0 ( {px} {py} ) via2_c"));
        let _ = writeln!(s, "  + ROUTED {}\n  ;", vias.join("\n    NEW "));
        s.push_str("END SPECIALNETS\nEND DESIGN\n");
        s
    }

    fn tcl(&self) -> String {
        let mut s = String::from(
            "read_lef mesh.lef\nread_def mesh.def\nset_pdnsim_net_voltage -net VDD -voltage 1.8\n",
        );
        let watts = self.load_amps() * VDD_MV / 1000.0;
        for i in 0..self.loads.len() {
            let _ = writeln!(s, "set_pdnsim_inst_power -inst l{i} -power {watts:e}");
        }
        s.push_str(
            "analyze_power_grid -net VDD -voltage_file voltage.csv -enable_em -em_outfile em.csv\n",
        );
        s
    }
}

/// Nanometres of a printed micrometre value.
fn nm(text: &str) -> Option<i64> {
    let v: f64 = text.trim().parse().ok()?;
    #[allow(clippy::cast_possible_truncation, reason = "a rounded coordinate")]
    let n = (v * 1000.0).round() as i64;
    Some(n)
}

/// One `GPurify` report on a mesh: drops (mV) by node, and currents (µA) by
/// edge layer and first node.
struct Ours {
    drop: BTreeMap<(i64, i64), f64>,
    current: Vec<(String, (i64, i64), f64)>,
}

fn ours(fixture: &Fixture) -> Ours {
    let ran = harness::run(fixture).unwrap_or_else(|why| panic!("{}: {why}", fixture.name));
    let v = &ran.outputs.violations;
    let strings = &ran.loaded.strings;
    let mut out = Ours {
        drop: BTreeMap::new(),
        current: Vec::new(),
    };
    for i in 0..v.len() {
        let at = (v.at[i].x.raw(), v.at[i].y.raw());
        match (strings.resolve(v.rule[i]), v.measured[i]) {
            ("ir", Measurement::Voltage(mv)) => {
                out.drop.insert(at, mv.raw());
            }
            ("em", Measurement::Current(ua)) => {
                let layer = strings
                    .resolve(ran.loaded.deck.layers.name(v.layer[i]))
                    .to_owned();
                out.current.push((layer, at, ua.raw()));
            }
            (rule, m) => panic!("{}: unexpected {rule} {m:?}", fixture.name),
        }
    }
    for (id, outcome) in &ran.rows {
        assert_eq!(
            *outcome,
            gpurify::check::report::Outcome::Ran,
            "{}: {id} did not run",
            fixture.name
        );
    }
    out
}

/// One `PDNSim` segment: each end's layer and position, and its current, A.
struct Segment {
    ends: [(String, (i64, i64)); 2],
    amps: f64,
}

/// `-em_outfile`: a header, then `layer,x,y,layer,x,y,current`.
fn segments(text: &str) -> Result<Vec<Segment>, String> {
    text.lines()
        .skip(1)
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let f: Vec<&str> = line.split(',').map(str::trim).collect();
            let bad = || format!("unreadable: {line}");
            if f.len() != 7 {
                return Err(bad());
            }
            let end = |i: usize| -> Result<(String, (i64, i64)), String> {
                Ok((
                    f[i].to_owned(),
                    (nm(f[i + 1]).ok_or_else(bad)?, nm(f[i + 2]).ok_or_else(bad)?),
                ))
            };
            Ok(Segment {
                ends: [end(0)?, end(3)?],
                amps: f[6].parse().map_err(|_| bad())?,
            })
        })
        .collect()
}

/// `-voltage_file`: a header, then `instance,terminal,layer,x,y,voltage`.
fn voltages(text: &str) -> Result<BTreeMap<String, f64>, String> {
    text.lines()
        .skip(1)
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let f: Vec<&str> = line.split(',').map(str::trim).collect();
            match (f.first(), f.get(5).and_then(|v| v.parse::<f64>().ok())) {
                (Some(inst), Some(v)) if f.len() == 6 => Ok(((*inst).to_owned(), v)),
                _ => Err(format!("unreadable: {line}")),
            }
        })
        .collect()
}

fn close_amps(a: f64, b: f64) -> bool {
    (a - b).abs() <= AMPS * a.abs().max(b.abs()) + 1e-9
}

/// What the comparisons found.
#[derive(Default)]
struct Tally {
    meshes: usize,
    loads: usize,
    cuts: usize,
    wires: usize,
    broken: Vec<String>,
}

/// One mesh through both tools.
fn compare(openroad: &Path, mesh: &Mesh) -> Tally {
    let mut tally = Tally {
        meshes: 1,
        ..Tally::default()
    };
    let ours = ours(&mesh.fixture());
    let dir = oracle::scratch("pdnsim");
    for (name, text) in [
        ("mesh.lef", Mesh::lef()),
        ("mesh.def", mesh.def()),
        ("run.tcl", mesh.tcl()),
    ] {
        std::fs::write(dir.join(name), text).expect("the scratch directory is writable");
    }
    oracle::run(
        openroad,
        &["-no_init", "-no_splash", "-exit", "run.tcl"],
        &dir,
        LIMIT,
    );
    let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap_or_default();
    let at = |what: String| format!("mesh {}: {what}", mesh.seed);
    let (theirs_v, theirs_i) = match (voltages(&read("voltage.csv")), segments(&read("em.csv"))) {
        (Ok(v), Ok(i)) => (v, i),
        (v, i) => {
            tally.broken.push(at(format!(
                "PDNSim's files do not read: {:?} {:?}",
                v.err(),
                i.err()
            )));
            tally.broken.push(super::kept(&dir));
            return tally;
        }
    };

    // Every load: PDNSim's instance voltage is the grid's, less its pin.
    for (i, &(r, x)) in mesh.loads.iter().enumerate() {
        tally.loads += 1;
        let node = (x, mesh.rails[r].0);
        let Some(&drop) = ours.drop.get(&node) else {
            tally.broken.push(at(format!(
                "GPurify reports no drop at the load at {node:?}"
            )));
            continue;
        };
        let want = VDD_MV / 1000.0 - drop / 1000.0 - mesh.load_amps() * PIN_OHMS;
        match theirs_v.get(&format!("l{i}")) {
            Some(&v) if (v - want).abs() <= VOLTS => {}
            other => tally.broken.push(at(format!(
                "load {i} at {node:?}: GPurify's drop {drop} mV makes it {want} V, PDNSim {other:?}"
            ))),
        }
    }

    // Every cut, both ways: a segment whose ends lie on two layers at one
    // point.
    let is_cut = |s: &Segment| s.ends[0].0 != s.ends[1].0 && s.ends[0].1 == s.ends[1].1;
    let cut_layer = |s: &Segment| {
        if s.ends.iter().any(|e| e.0 == "met3") {
            "via2"
        } else {
            "via1"
        }
    };
    for (layer, point, ua) in &ours.current {
        let amps = ua * 1e-6;
        if layer.starts_with("via") {
            tally.cuts += 1;
            let found = theirs_i
                .iter()
                .find(|s| is_cut(s) && cut_layer(s) == layer.as_str() && s.ends[0].1 == *point);
            if !found.is_some_and(|s| close_amps(s.amps, amps)) {
                tally.broken.push(at(format!(
                    "{layer} cut at {point:?}: GPurify {ua} µA, PDNSim {:?} A",
                    found.map(|s| s.amps)
                )));
            }
        } else {
            tally.wires += 1;
            let candidates: Vec<f64> = theirs_i
                .iter()
                .filter(|s| {
                    s.ends.iter().all(|e| e.0 == *layer)
                        && s.ends[0].1 != s.ends[1].1
                        && s.ends.iter().any(|e| e.1 == *point)
                })
                .map(|s| s.amps)
                .collect();
            if !candidates.iter().any(|&c| close_amps(c, amps)) {
                tally.broken.push(at(format!(
                    "{layer} segment from {point:?}: GPurify {ua} µA, PDNSim's segments there {candidates:?} A"
                )));
            }
        }
    }
    for s in theirs_i.iter().filter(|s| is_cut(s) && s.amps > 1e-6) {
        let layer = cut_layer(s);
        let point = s.ends[0].1;
        if !ours
            .current
            .iter()
            .any(|(l, p, _)| l == layer && *p == point)
        {
            tally.broken.push(at(format!(
                "PDNSim's {layer} cut at {point:?} carries {} A; GPurify reports none",
                s.amps
            )));
        }
    }
    if tally.broken.is_empty() {
        let _ = std::fs::remove_dir_all(&dir);
    } else {
        tally.broken.push(super::kept(&dir));
    }
    tally
}

/// 100 seeded meshes: every load's voltage, every cut's current and every
/// wire segment's current agree with `OpenROAD`'s `PDNSim`.
///
/// Oracle: differential against `PDNSim`'s `analyze_power_grid` (module
/// docs). The nightly `oracles` job runs it.
#[test]
#[ignore = "release tier: needs openroad (nix develop .#oracles)"]
fn pdnsim_differential_on_random_meshes() {
    let openroad = oracle::tool("openroad");
    let seeds: Vec<u64> = (FIRST_SEED..FIRST_SEED + MESHES).collect();
    let next = AtomicUsize::new(0);
    let total = Mutex::new(Tally::default());
    std::thread::scope(|scope| {
        for _ in 0..oracle::MAX_RUNNING {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(&seed) = seeds.get(i) else {
                    break;
                };
                let found = compare(&openroad, &Mesh::random(seed));
                let mut total = total.lock().expect("not poisoned");
                total.meshes += found.meshes;
                total.loads += found.loads;
                total.cuts += found.cuts;
                total.wires += found.wires;
                total.broken.extend(found.broken);
            });
        }
    });
    let total = total.into_inner().expect("not poisoned");
    println!(
        "pdnsim: {} meshes, {} load voltages, {} cut currents, {} wire currents compared, {} broken",
        total.meshes,
        total.loads,
        total.cuts,
        total.wires,
        total.broken.len()
    );
    assert!(
        total.broken.is_empty(),
        "{} disagreements (first 60):\n{}",
        total.broken.len(),
        total.broken[..total.broken.len().min(60)].join("\n")
    );
    assert_eq!(total.meshes, seeds.len(), "every mesh ran");
    assert!(
        total.loads > 200 && total.cuts > 150 && total.wires > 500,
        "too few comparisons"
    );
}
