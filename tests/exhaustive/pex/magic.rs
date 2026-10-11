//! The closed forms against Magic 8.3's extractor (testing-plan §4 L6,
//! ledger O2), on X6's analytical geometries (the bars, bends, abutting
//! pieces and vias of the fixtures, the coupled pairs and plates of the
//! coupling laws) and on seeded random wires.
//!
//! **What Magic is given.** The same GDS bytes `GPurify` reads, every case
//! side by side in one cell, and a tech file ([`tech`]) whose extraction style
//! carries [`STACK`]'s coefficients in Magic's terms (Magic Technology Manual
//! #2, "Extract section"; `units microns` reads every value per µm): `resist`
//! is the sheet resistance in mΩ/□, `areacap` and `perimc ... space` the
//! `area_cap` and `fringe_cap` to the substrate, `sidewall` the lateral
//! coefficient `ε₀εr·t` at a 1 µm gap within `sidehalo` (ten thicknesses), and
//! `overlap` the plate coefficient `ε₀εr/d`. Magic runs `extract all` with
//! capacitance, coupling and lumped R on, and `ext2spice cthresh 0`.
//!
//! **What both define alike**, so is compared:
//!
//! - a net's R: Magic's lumped node resistance (Tutorial #8, "Resistance";
//!   `ExtBasic.c` `extSetResist`) is, per resistance class, the rectangle
//!   with the class's area and perimeter, summed over classes: `GPurify`'s
//!   `Rs·L/W` per region wherever a net has at most one region per layer;
//! - a net's ground C: `areacap·A + perimc·P` over the merged outline, a
//!   contact counted as its residue on each plane (`extNodeAreaFunc`);
//! - lateral coupling: `sidewall·L/S` over the facing run, accumulated from
//!   each of the two edges with half the coefficient (`ExtTech.c` under
//!   `units microns`; `ExtCouple.c` `extSideCommon`);
//! - interlayer coupling: `overlap` times the overlap area (`extAddOverlap`).
//!
//! **Documented differences, encoded in the comparison** (and in
//! `gpurify_extract`'s "Against Magic's extractor"):
//!
//! - Magic's overlap takes the upper plate's area capacitance over a lower
//!   conductor, of any net, off its ground capacitance (`extAddOverlap`);
//!   `GPurify`'s plate ignores what lies beneath it. Magic's ground C of a net
//!   is `GPurify`'s less `areacap(m2)` times its `m2` area over `m1`
//!   ([`shielded`]).
//! - Magic's lumped R leaves contacts out ("neither is used by the normal
//!   Magic extractor", Manual #2 on `contact`); `GPurify` adds `Rcut/n` per via
//!   array. Magic's R of a via case is `GPurify`'s less that term.
//! - Magic's `sidehalo` is exclusive (`extWalkRight` and its siblings search
//!   strictly inside it); `GPurify` couples a pair exactly ten thicknesses
//!   apart. Those pairs are compared against zero, and `GPurify`'s coupling
//!   must stay positive.
//!
//! **Left out, because the two define them differently:** a net with two
//! regions on one layer (Magic lumps them into one rectangle; X6's via
//! chain, ground C only); pieces meeting only at a corner (one net here, two
//! Magic nodes: Magic connects across edges only); a cut off one of its plates
//! (a Magic contact is metal on both planes); a coupling a third shape
//! shields (Magic's sidewall stops at the nearest edge, `extWalk*`; random
//! layouts that have one are redrawn); and Magic's default distributed fringe
//! (`EXT_DOFRINGEHALO`), which takes the fringe a neighbour blocks off the
//! ground C: `GPurify`'s fringe is the whole perimeter's, so Magic runs with
//! `extract no all` and only capacitance, coupling and lumped R back on.
//!
//! **The stack** is X6's [`PARAMS`] with every resistance a thousand times
//! larger: Magic writes a node's R in whole milliohms (`rscale 1`), so a square
//! of 0.1 Ω would carry 1 % of rounding.
//!
//! **Tolerances**, from what Magic prints:
//!
//! - [`C_REL`] 1e-4 and [`C_ABS`] 5e-6 fF: `ext2spice` prints five decimals of
//!   an SI unit (`esSIvalue`): of fF below 100 fF, within 5e-6 fF; of pF
//!   above, within 5e-6 pF, at most 5e-5 of the value. The `.ext` it reads
//!   carries six significant digits (5e-6), and Magic's µm-to-λ factor is a
//!   single-precision 0.001 (1e-7).
//! - [`R_REL`] 1e-4 and [`R_ABS`] 2 mΩ: `extSetResist` solves the rectangle in
//!   single precision, which loses about 5e-8 per square of `L/W` (the
//!   `2^-24` of `P² − 16A` carried into `P − s = 4W`), 5e-5 at the 1000
//!   squares of the longest bars; and the node's R is truncated to whole
//!   milliohms per class, two classes at most.

use super::{
    bars, bends, deck, parallel, pieces, vias, Metal, Row, Stack, EPSILON0_AF_PER_UM, PARAMS, PEX,
};
use crate::harness::{self, Depth, Fixture, Layout, Symmetry};
use gpurify::check::topology::NetId;
use gpurify::engine::run::StageStatus;
use gpurify::extract::network::NodeId;
use gpurify::extract::Parasitic;
use gpurify_testgen::{oracle, Rng};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;
use std::time::Duration;

/// A capacitance against Magic, relative.
const C_REL: f64 = 1e-4;
/// A capacitance against Magic, absolute, in fF.
const C_ABS: f64 = 5e-6;
/// A resistance against Magic, relative.
const R_REL: f64 = 1e-4;
/// A resistance against Magic, absolute, in Ω.
const R_ABS: f64 = 2e-3;

/// [`PARAMS`] with every resistance a thousand times larger.
const STACK: Stack = Stack {
    m1: Row {
        sheet: 100.0,
        ..PARAMS.m1
    },
    v1: Row {
        sheet: 5_000.0,
        ..PARAMS.v1
    },
    m2: Row {
        sheet: 80.0,
        ..PARAMS.m2
    },
};

/// The lateral coupling reach on both metals, nm: ten of [`STACK`]'s 400 nm
/// thicknesses.
const HALO: i64 = 4_000;

/// Seeded random-wire layouts.
const SEEDS: u64 = 300;

/// What Magic runs: read the GDS, extract with the fringe halo off, write
/// the SPICE netlist with every capacitance, and quit whatever happened.
const SCRIPT: &str = "\
if {[catch {
    drc off
    gds read layout.gds
    load TOP
    extract no all
    extract do capacitance
    extract do coupling
    extract do lumped
    extract all
    ext2spice cthresh 0
    ext2spice
} message]} {
    puts stderr \"O2 script: $message\"
}
quit -noprompt
";

/// Magic's tech file for `stack`: `m1` and `m2` on two planes joined by the
/// contact `v1`, read from the deck's GDS pairs (labels on datatype 5), with
/// one internal unit a nanometre, and the extraction style of the module docs.
fn tech(stack: Stack) -> String {
    let um = |nm: f64| nm / 1e3;
    #[allow(clippy::cast_possible_truncation, reason = "a whole number of mΩ")]
    let milliohm = |row: Row| {
        let value = (row.sheet * 1e3).round();
        assert!(
            (value - row.sheet * 1e3).abs() < 1e-6,
            "Magic reads a sheet resistance in whole milliohms"
        );
        value as i64
    };
    let lateral = |row: Row| EPSILON0_AF_PER_UM * row.k * um(row.thickness);
    let plate = EPSILON0_AF_PER_UM * stack.m1.k
        / um(stack.m2.height - stack.m1.height - stack.m1.thickness);
    let (m1, m2) = (stack.m1, stack.m2);
    let mut out = String::from(
        "tech\n  format 35\n  gpurify_o2\nend\n\n\
         version\n  version 1\n  description \"GPurify O2: the analytical PEX differential\"\nend\n\n\
         planes\n  metal1\n  metal2\nend\n\n\
         types\n  metal1 metal1,m1\n  metal2 metal2,m2\n  metal1 via1,v1\nend\n\n\
         contact\n  v1 m1 m2\nend\n\n\
         styles\n  styletype mos\nend\n\n\
         compose\nend\n\n\
         connect\n  m1,v1 m1,v1\n  m2,v1 m2,v1\nend\n\n\
         cifoutput\nstyle gds\n  scalefactor 1 nanometers\nend\n\n\
         cifinput\nstyle gds\n  scalefactor 1 nanometers\n\
         \x20 layer m1 M1\n    labels M1L\n  layer m2 M2\n    labels M2L\n  layer v1 V1\n\
         \x20 calma M1 7 0\n  calma M1L 7 5\n  calma M2 9 0\n  calma M2L 9 5\n  calma V1 8 0\nend\n\n\
         drc\nend\n\n",
    );
    let _ = write!(
        out,
        "extract\n  style o2\n  cscale 1\n  rscale 1\n  lambda 0.1\n  units microns\n  step 100\n\
         \x20 sidehalo {halo}\n  planeorder metal1 0\n  planeorder metal2 1\n\
         \x20 resist m1 {r1}\n  resist m2 {r2}\n\
         \x20 areacap m1 {a1}\n  areacap m2 {a2}\n\
         \x20 perimc m1 space {f1}\n  perimc m2 space {f2}\n\
         \x20 sidewall m1 space space m1 {s1}\n  sidewall m2 space space m2 {s2}\n\
         \x20 overlap m2 m1 {plate}\nend\n",
        halo = um(10.0 * m1.thickness),
        r1 = milliohm(m1),
        r2 = milliohm(m2),
        a1 = m1.area,
        a2 = m2.area,
        f1 = m1.fringe,
        f2 = m2.fringe,
        s1 = lateral(m1),
        s2 = lateral(m2),
    );
    out
}

/// One geometry, and what of it is compared.
struct Case {
    name: String,
    /// Labels on the deck's label layers, one per net.
    layout: Layout,
    /// `Some(via)`: compare each net's R, Magic's being `GPurify`'s less `via`,
    /// the closed-form via resistance of the case's one net. `None`: a net
    /// has two regions on one layer, which the two lump differently.
    r: Option<f64>,
    /// The case's coupling is a facing pair exactly [`HALO`] apart, which
    /// Magic's exclusive halo leaves out.
    at_halo: bool,
}

/// X6's closed-form fixtures at the origin under every symmetry (the
/// translated copies are the same geometry once placed), less the layouts the
/// two tools connect or lump differently.
fn fixtures() -> Vec<Case> {
    [
        bars(Depth::Nightly),
        bends(Depth::Nightly),
        pieces(),
        vias(Depth::Nightly),
    ]
    .concat()
    .into_iter()
    .filter(|f| {
        !f.name.contains("+(")
            && !f.name.starts_with("pex/pieces/corner_joined/")
            && !f.name.starts_with("pex/via/cuts_2_and_a_stray/")
    })
    .map(|f| {
        let cuts = f.layout.shapes.iter().filter(|(l, _)| l == "v1").count();
        let r = if f.name.starts_with("pex/via/chain") {
            None
        } else if cuts == 0 {
            Some(0.0)
        } else {
            // One array: every cut joins the same two bars.
            Some(STACK.v1.sheet / cuts as f64)
        };
        Case {
            name: f.name,
            layout: f.layout,
            r,
            at_halo: false,
        }
    })
    .collect()
}

/// The layouts of X6's coupling laws under every symmetry: two parallel
/// 6 x 1 µm bars on either metal, the halo's edge among their gaps, and an
/// `m2` plate over an `m1` plate at four offsets.
fn coupled() -> Vec<Case> {
    let mut out = Vec::new();
    let mut every = |name: String, layout: Layout, at_halo: bool| {
        for symmetry in Symmetry::ALL {
            out.push(Case {
                name: format!("{name}/{}", symmetry.name()),
                layout: layout.transformed(symmetry, 0, 0),
                r: Some(0.0),
                at_halo,
            });
        }
    };
    for metal in [Metal::M1, Metal::M2] {
        for gap in [100, 250, 1_000, 3_900, HALO, 4_100] {
            for shift in [0_i64, 1_500, -2_000, 6_500] {
                every(
                    format!("pair/{}/gap{gap}/shift{shift}", metal.name()),
                    parallel(metal, 6_000, 1_000, gap, shift),
                    gap == HALO && shift.abs() < 6_000,
                );
            }
        }
    }
    for (x, y) in [(1_000, 500), (0, 0), (-500, 1_500), (3_000, 2_000)] {
        every(
            format!("plates/{x}_{y}"),
            Layout::default()
                .rect("m1", 0, 0, 3_000, 2_000)
                .rect("m2", x, y, x + 4_000, y + 3_000)
                .label("m1_label", 100, 100, "A")
                .label("m2_label", x + 3_900, y + 2_900, "B"),
            false,
        );
    }
    out
}

/// The area two `[xlo, ylo, xhi, yhi]` rectangles share: zero when they only
/// touch or are apart.
fn overlap(a: [i64; 4], b: [i64; 4]) -> i64 {
    let wide = a[2].min(b[2]) - a[0].max(b[0]);
    let tall = a[3].min(b[3]) - a[1].max(b[1]);
    wide.max(0) * tall.max(0)
}

/// Whether both tools define every coupling of `wires` alike: no two on one
/// layer touch (they would be one net), no facing pair is exactly [`HALO`]
/// apart, and no third wire lies between a facing pair within it.
fn comparable(wires: &[(Metal, [i64; 4])]) -> bool {
    for (i, &(metal, a)) in wires.iter().enumerate() {
        for (j, &(other, b)) in wires.iter().enumerate().skip(i + 1) {
            if metal.name() != other.name() {
                continue;
            }
            let dx = a[0].max(b[0]) - a[2].min(b[2]);
            let dy = a[1].max(b[1]) - a[3].min(b[3]);
            if dx <= 0 && dy <= 0 {
                return false;
            }
            let (gap, between) = if dx > 0 && dy < 0 {
                (
                    dx,
                    [
                        a[2].min(b[2]),
                        a[1].max(b[1]),
                        a[0].max(b[0]),
                        a[3].min(b[3]),
                    ],
                )
            } else if dy > 0 && dx < 0 {
                (
                    dy,
                    [
                        a[0].max(b[0]),
                        a[3].min(b[3]),
                        a[2].min(b[2]),
                        a[1].max(b[1]),
                    ],
                )
            } else {
                continue;
            };
            let blocked = wires.iter().enumerate().any(|(k, &(third, c))| {
                k != i && k != j && third.name() == metal.name() && overlap(c, between) > 0
            });
            if gap == HALO || (gap < HALO && blocked) {
                return false;
            }
        }
    }
    true
}

/// Two to five straight wires, each its own net, of seed `seed`: on `m1` or
/// `m2`, 100 nm to 1.5 µm wide, one to 120 squares long, either way round, in
/// a 20 µm window on a 10 nm grid; redrawn until [`comparable`].
fn wires(seed: u64) -> Case {
    let mut rng = Rng::new(seed);
    loop {
        let n = rng.range(2, 6);
        let wires: Vec<(Metal, [i64; 4])> = (0..n)
            .map(|_| {
                let metal = if rng.below(2) == 0 {
                    Metal::M1
                } else {
                    Metal::M2
                };
                let width = 10 * rng.range(10, 150);
                let length = 10 * rng.range(width / 10, 1_200);
                let (wide, tall) = if rng.below(2) == 0 {
                    (length, width)
                } else {
                    (width, length)
                };
                let (x, y) = (10 * rng.range(0, 2_000), 10 * rng.range(0, 2_000));
                (metal, [x, y, x + wide, y + tall])
            })
            .collect();
        if !comparable(&wires) {
            continue;
        }
        let mut layout = Layout::default();
        for (i, &(metal, [xlo, ylo, xhi, yhi])) in wires.iter().enumerate() {
            layout = layout.rect(metal.name(), xlo, ylo, xhi, yhi).label(
                metal.label(),
                (xlo + xhi) / 2,
                (ylo + yhi) / 2,
                &format!("W{i}"),
            );
        }
        return Case {
            name: format!("wires/seed{seed}"),
            layout,
            r: Some(0.0),
            at_halo: false,
        };
    }
}

/// Every case.
fn cases() -> Vec<Case> {
    let mut out = fixtures();
    out.extend(coupled());
    out.extend((0..SEEDS).map(wires));
    out
}

/// `[xlo, ylo, xhi, yhi]` of `points`.
fn bbox(points: &[(i64, i64)]) -> [i64; 4] {
    points.iter().fold(
        [i64::MAX, i64::MAX, i64::MIN, i64::MIN],
        |[xlo, ylo, xhi, yhi], &(x, y)| [xlo.min(x), ylo.min(y), xhi.max(x), yhi.max(y)],
    )
}

/// Each net's `m2` area over `m1`, in µm²: what Magic's `overlap` rule takes
/// off the upper plate's ground capacitance. An `m2` rectangle is the net of
/// the `m2` label inside it, or the case's one net when it has none; the
/// `m1` rectangles under one `m2` rectangle are disjoint in every case here.
fn shielded(layout: &Layout) -> BTreeMap<String, f64> {
    let on = |layer: &'static str| {
        layout
            .shapes
            .iter()
            .filter(move |(l, _)| l == layer)
            .map(move |(_, points)| {
                assert_eq!(
                    points.len(),
                    4,
                    "{layer} over or under the other metal: a rectangle"
                );
                bbox(points)
            })
    };
    let mut out = BTreeMap::new();
    let has = |layer: &str| layout.shapes.iter().any(|(l, _)| l == layer);
    if !has("m1") || !has("m2") {
        return out;
    }
    let lower: Vec<[i64; 4]> = on("m1").collect();
    let texts: BTreeSet<&String> = layout.labels.iter().map(|(.., text)| text).collect();
    for upper in on("m2") {
        let under: Vec<[i64; 4]> = lower
            .iter()
            .copied()
            .filter(|&l| overlap(upper, l) > 0)
            .collect();
        for (i, &a) in under.iter().enumerate() {
            for &b in &under[i + 1..] {
                assert_eq!(overlap(a, b), 0, "m1 rectangles under one m2 overlap");
            }
        }
        let area: i64 = under.iter().map(|&l| overlap(upper, l)).sum();
        if area == 0 {
            continue;
        }
        let net = layout
            .labels
            .iter()
            .find(|(l, x, y, _)| {
                l == "m2_label"
                    && (upper[0]..=upper[2]).contains(x)
                    && (upper[1]..=upper[3]).contains(y)
            })
            .map(|(.., text)| text)
            .or_else(|| {
                if texts.len() == 1 {
                    texts.first().copied()
                } else {
                    None
                }
            })
            .expect("an m2 rectangle names its net");
        *out.entry(net.clone()).or_insert(0.0) += area as f64 / 1e6;
    }
    out
}

/// Every case side by side in rows, 20 µm (five halos) apart so no two couple,
/// each case's labels suffixed `_k` with its index `k`: one GDS, one name per
/// net.
fn combine(cases: &[Case]) -> Layout {
    const SPACING: i64 = 20_000;
    const ROW: i64 = 20_000_000;
    let mut out = Layout::default();
    let (mut x, mut y, mut tallest) = (0, 0, 0);
    for (k, case) in cases.iter().enumerate() {
        let points: Vec<(i64, i64)> = case
            .layout
            .shapes
            .iter()
            .flat_map(|(_, points)| points.iter().copied())
            .chain(case.layout.labels.iter().map(|&(_, lx, ly, _)| (lx, ly)))
            .collect();
        let [xlo, ylo, xhi, yhi] = bbox(&points);
        if x > 0 && x + (xhi - xlo) > ROW {
            (x, y, tallest) = (0, y + tallest + SPACING, 0);
        }
        let placed = case
            .layout
            .transformed(Symmetry::IDENTITY, x - xlo, y - ylo);
        out.shapes.extend(placed.shapes);
        out.labels.extend(
            placed
                .labels
                .into_iter()
                .map(|(layer, lx, ly, text)| (layer, lx, ly, format!("{text}_{k}"))),
        );
        x += xhi - xlo + SPACING;
        tallest = tallest.max(yhi - ylo);
    }
    // Magic's tile plane spans ±2^30 internal units, nanometres here.
    assert!(y + tallest < 1 << 29, "the cases fit Magic's plane");
    out
}

/// One tool's answer, by net label.
#[derive(Debug, Default)]
struct Values {
    /// Capacitance to the substrate, fF.
    ground: BTreeMap<String, f64>,
    /// Coupling capacitance, fF, by label pair in order.
    coupling: BTreeMap<(String, String), f64>,
    /// Resistance, Ω.
    ohm: BTreeMap<String, f64>,
}

/// `(a, b)` in order.
fn pair(a: &str, b: &str) -> (String, String) {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    (lo.to_owned(), hi.to_owned())
}

/// `GPurify`'s network, summed per labelled net and per pair of them.
fn ours(ran: &harness::Ran, labels: &BTreeSet<String>) -> Values {
    let network = ran.outputs.parasitics.as_ref().expect("PEX ran");
    let mut name: BTreeMap<NetId, &str> = BTreeMap::new();
    for label in labels {
        let net = ran
            .loaded
            .strings
            .get(label)
            .and_then(|id| ran.extracted.ports.net_of(id))
            .unwrap_or_else(|| panic!("GPurify has no net labelled {label}"));
        assert!(
            name.insert(net, label.as_str()).is_none(),
            "{label} shares a net"
        );
    }
    let of = |node: NodeId| {
        *name
            .get(&network.node_net[node.0 as usize])
            .expect("every net is labelled")
    };
    let mut out = Values::default();
    for (k, value) in network.value.iter().enumerate() {
        let near = of(network.from[k]).to_owned();
        match (value, network.to[k]) {
            (Parasitic::GroundCap(c), None) => *out.ground.entry(near).or_insert(0.0) += c.raw(),
            (Parasitic::Resistance(r), _) => *out.ohm.entry(near).or_insert(0.0) += r.raw(),
            (Parasitic::CouplingCap(c), Some(far)) => {
                *out.coupling.entry(pair(&near, of(far))).or_insert(0.0) += c.raw();
            }
            _ => {}
        }
    }
    out
}

/// A SPICE value as `ext2spice` prints it, a number and an optional SI
/// suffix, in its base unit.
fn si(text: &str) -> f64 {
    let scale = match text.as_bytes().last() {
        Some(b'f') => 1e-15,
        Some(b'p') => 1e-12,
        Some(b'n') => 1e-9,
        Some(b'u') => 1e-6,
        Some(b'm') => 1e-3,
        Some(b'k') => 1e3,
        Some(b'G') => 1e9,
        _ => 1.0,
    };
    let number = text.trim_end_matches(|c: char| c.is_ascii_alphabetic());
    number
        .parse::<f64>()
        .unwrap_or_else(|_| panic!("{text}: not a SPICE value"))
        * scale
}

/// Magic's answer for the GDS `gds`: R from the `.ext` node lines, C from
/// `ext2spice`'s capacitors. A capacitor between two labels is a coupling,
/// one between a label and anything else (the ground node) a ground C.
fn theirs(tool: &Path, gds: &[u8], labels: &BTreeSet<String>) -> Values {
    let dir = oracle::scratch("magic");
    for (name, bytes) in [
        ("o2.tech", tech(STACK).into_bytes()),
        ("o2.tcl", SCRIPT.as_bytes().to_vec()),
        ("layout.gds", gds.to_vec()),
    ] {
        std::fs::write(dir.join(name), bytes).expect("the scratch directory is writable");
    }
    oracle::run(
        tool,
        &[
            "-dnull",
            "-noconsole",
            "-rcfile",
            "/dev/null",
            "-T",
            "o2",
            "o2.tcl",
        ],
        &dir,
        Duration::from_mins(10),
    );
    let read = |name: &str| {
        std::fs::read_to_string(dir.join(name)).unwrap_or_else(|why| {
            let log = |file: &str| std::fs::read_to_string(dir.join(file)).unwrap_or_default();
            panic!(
                "Magic wrote no {name} ({why}):\n{}\n{}",
                log("stdout.txt"),
                log("stderr.txt")
            )
        })
    };
    let (ext, spice) = (read("TOP.ext"), read("TOP.spice"));
    let mut out = Values::default();
    let mut rscale = 1.0;
    for line in ext.lines() {
        match line.split_whitespace().collect::<Vec<_>>()[..] {
            ["scale", r, ..] => rscale = r.parse().expect("an rscale"),
            // `node "name" R C x y type ...`, R in mΩ times rscale.
            ["node", name, r, ..] => {
                let milliohm: f64 = r.parse().expect("a resistance");
                out.ohm
                    .insert(name.trim_matches('"').to_owned(), milliohm * rscale / 1e3);
            }
            _ => {}
        }
    }
    for line in spice.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        let [element, a, b, value, ..] = words[..] else {
            continue;
        };
        if !(element.len() > 1
            && element.starts_with('C')
            && element[1..].bytes().all(|c| c.is_ascii_digit()))
        {
            continue;
        }
        let ff = si(value) * 1e15;
        // An unlabelled node lands in `ground` under its own name, for the
        // caller to report.
        match (labels.contains(a), labels.contains(b)) {
            (true, true) => *out.coupling.entry(pair(a, b)).or_insert(0.0) += ff,
            (false, true) => *out.ground.entry(b.to_owned()).or_insert(0.0) += ff,
            _ => *out.ground.entry(a.to_owned()).or_insert(0.0) += ff,
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    out
}

/// How many of one quantity were compared, and the worst deviation as a
/// share of its tolerance.
#[derive(Default)]
struct Tally {
    compared: usize,
    worst: f64,
    at: String,
}

impl Tally {
    /// Records `got` against `want` for `what`; true when within
    /// `rel · |want| + abs`.
    fn check(&mut self, what: &str, got: f64, want: f64, rel: f64, abs: f64) -> bool {
        self.compared += 1;
        let share = (got - want).abs() / (rel * want.abs() + abs);
        if share > self.worst {
            self.worst = share;
            self.at = format!("{what}: {got}, want {want}");
        }
        share <= 1.0
    }
}

/// Every net's ground C and R, and every pair's coupling, of every case:
/// Magic's within its printed precision of `GPurify`'s, less the documented
/// differences of the module docs.
///
/// Oracle: differential against an independent implementation, Magic 8.3's
/// extractor (`extract`, `ext2spice`) under a tech file carrying the same
/// coefficients. It fails if a closed form drifts (a square or a perimeter
/// counted twice is 1e-3 or more, ten times the tolerance), if a coupling is
/// dropped or doubled, if the lateral halo moves, or if the tech file
/// misstates a coefficient.
#[test]
#[ignore = "release tier: needs magic (nix develop .#oracles)"]
fn magic_differential_every_analytical_geometry() {
    let tool = oracle::tool("magic");
    assert!(
        ((10.0 * STACK.m1.thickness) - HALO as f64).abs() < 0.5
            && ((10.0 * STACK.m2.thickness) - HALO as f64).abs() < 0.5,
        "one sidehalo serves both metals"
    );
    let cases = cases();
    let layout = combine(&cases);
    let labels: BTreeSet<String> = layout
        .labels
        .iter()
        .map(|(.., text)| text.clone())
        .collect();
    let fixture = Fixture::new(
        "pex/magic",
        &["PEX-001", "PEX-002", "PEX-003"],
        &deck(STACK, &[], ""),
        PEX,
    )
    .layout(layout);
    let (gds, ..) = harness::written(&fixture).unwrap_or_else(|why| panic!("{why}"));
    let ran = harness::run(&fixture).unwrap_or_else(|why| panic!("{why}"));
    assert_eq!(ran.summary.pex, StageStatus::Ran, "{:?}", ran.summary.pex);
    let ours = ours(&ran, &labels);
    let theirs = theirs(&tool, &gds, &labels);

    let mut broken = Vec::new();
    let (mut ground, mut coupling, mut ohm) =
        (Tally::default(), Tally::default(), Tally::default());
    for (k, case) in cases.iter().enumerate() {
        let nets: BTreeSet<&str> = case
            .layout
            .labels
            .iter()
            .map(|(.., t)| t.as_str())
            .collect();
        let shield = shielded(&case.layout);
        for &net in &nets {
            let n = format!("{net}_{k}");
            let what = format!("{}: {net}", case.name);
            let Some(&magic_ohm) = theirs.ohm.get(&n) else {
                broken.push(format!("{what}: Magic has no node {n}"));
                continue;
            };
            let want = ours.ground.get(&n).copied().unwrap_or(0.0)
                - STACK.m2.area * shield.get(net).copied().unwrap_or(0.0) / 1e3;
            let got = theirs.ground.get(&n).copied().unwrap_or(0.0);
            if !ground.check(&what, got, want, C_REL, C_ABS) {
                broken.push(format!("{what}: ground C {got} fF, want {want}"));
            }
            if let Some(via) = case.r {
                let want = ours.ohm.get(&n).copied().unwrap_or(0.0) - via;
                if !ohm.check(&what, magic_ohm, want, R_REL, R_ABS) {
                    broken.push(format!("{what}: R {magic_ohm} ohm, want {want}"));
                }
            }
        }
        let nets: Vec<&str> = nets.into_iter().collect();
        for (i, a) in nets.iter().enumerate() {
            for b in &nets[i + 1..] {
                let key = pair(&format!("{a}_{k}"), &format!("{b}_{k}"));
                let what = format!("{}: {a}-{b}", case.name);
                let gpurify = ours.coupling.get(&key).copied().unwrap_or(0.0);
                if case.at_halo && gpurify <= 0.0 {
                    broken.push(format!("{what}: no coupling at the halo's edge"));
                }
                let want = if case.at_halo { 0.0 } else { gpurify };
                let got = theirs.coupling.get(&key).copied().unwrap_or(0.0);
                if !coupling.check(&what, got, want, C_REL, C_ABS) {
                    broken.push(format!("{what}: coupling {got} fF, want {want}"));
                }
            }
        }
    }
    let case_of = |net: &str| net.rsplit_once('_').map(|(_, k)| k.to_owned());
    for (a, b) in ours.coupling.keys().chain(theirs.coupling.keys()) {
        if case_of(a.as_str()) != case_of(b.as_str()) {
            broken.push(format!("{a} and {b}, of two cases, couple"));
        }
    }
    for net in theirs.ohm.keys().chain(theirs.ground.keys()) {
        if !labels.contains(net) {
            broken.push(format!("Magic's node {net} is no labelled net"));
        }
    }

    for (quantity, tally) in [("ground C", &ground), ("coupling", &coupling), ("R", &ohm)] {
        println!(
            "{quantity}: {} compared, worst {:.3} of its tolerance ({})",
            tally.compared, tally.worst, tally.at
        );
    }
    assert!(
        broken.is_empty(),
        "{} disagreements with Magic (first 60):\n{}",
        broken.len(),
        broken[..broken.len().min(60)].join("\n")
    );
    assert!(
        ground.compared > 2_000 && coupling.compared > 400 && ohm.compared > 2_000,
        "too few comparisons: {} ground, {} coupling, {} R",
        ground.compared,
        coupling.compared,
        ohm.compared
    );
}
