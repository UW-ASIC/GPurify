//! Several dies placed into one assembly (2.5D, 3D, chiplets on an
//! interposer), checked as one: system LVS (catalog LVS-073) and the
//! package-level and system-level ESD checks (ERC-C12, ERC-C13).
//!
//! Data in: each die's extraction and its [`Graph`], where it sits
//! ([`Placement`]), and which of its layers face another die or the package.
//! Data out: violation rows and one [`RuleRun`] per check, as the single-die
//! checks give them. Locations are in the assembly's coordinates; a row has
//! no layer, since layer ids belong to one die's deck.
//!
//! # System LVS (LVS-073)
//!
//! As Calibre 3DSTACK defines it in its public material (Siemens, *Calibre
//! 3DSTACK* fact sheet 82850-D2, 2022, and the *Design with Calibre* blog,
//! "HDAP connectivity verification", 2018-01-23): every die is placed by its
//! position and orientation, the interface geometry of two facing dies
//! (bumps, through-silicon-via landings, hybrid-bond pads) connects where it
//! overlaps, the text label at a bump names the die's pin, and the assembled
//! connectivity is compared against a system netlist; floating bumps, opens,
//! shorts and missing labels are errors. Here:
//!
//! - a bump is a shape on a bonded face's layer, a rectangle on a net of its
//!   die ([`bumps_into`]); two bumps of facing dies bond when their placed
//!   rectangles overlap with positive area ([`bonded_pairs`]), and a bump
//!   that bonds nothing is `system.unbonded_bump` ([`check_bonds`]);
//! - the dies' graphs become one flat graph, the nets of every bonded pair
//!   merged ([`assemble`]), which the comparison of [`crate::lvs`] holds to
//!   the flattened system netlist, device by device;
//! - names, which that comparison never reads, are compared pin by pin
//!   ([`check_pins`]): every port of every die instance the system netlist
//!   places, and every port of its top subcircuit (the package pins), must
//!   be connected in the assembly exactly as the netlist connects them:
//!   `system.open` and `system.short`.
//!
//! # Package, 2.5D and 3D ESD (ERC-C12)
//!
//! What ESDA TR18.0-01-25 calls the integrity of the ESD protection network
//! at the package pins, of a multi-die package, and of 2.5D/3D chiplets
//! (§6.3, §6.5, §6.7; only its table of contents was read): internal
//! die-to-die pins and external die-to-package pins are told apart, and the
//! discharge path of a package pin may cross dies. The path is the pad ESD
//! topology of ERC-C1 (TR18.0-01 §4.5.2–4.5.4): a clamp from the pad to a
//! supply, then any chain of clamps between supplies, both a power and a
//! ground reached ([`rails_reached`]):
//!
//! - `system.esd_package`: every package pin, through the assembled system:
//!   wires, bonds and the clamps of any die. A packaged component is stressed
//!   at its pins (ANSI/ESDA/JEDEC JS-001, JS-002), wherever its clamps are.
//! - `system.esd_d2d`: every die-to-die bump, through its own die alone. A
//!   die-to-die interface meets ESD only while its die is handled on its own,
//!   before it is bonded (JEP196, Industry Council White Paper 2 Part II,
//!   2023, executive summary and §3.3), so the other die's clamps are not
//!   there to help; JEP196 §6.2 checks such a bump's topology as a signal
//!   bump's.
//!
//! A pin whose net reaches no device terminal has nothing to protect (an
//! interposer's routing) and is not examined.
//!
//! # System-level ESD (ERC-C13)
//!
//! IEC 61000-4-2 stresses a finished product at the points a user can touch.
//! What reaches a pin is set by the board's protection, its traces and the
//! enclosure, and Industry Council White Paper 3 Part I (2010) §6.3.1 holds
//! that the unknown pulse shape and energy per pin make it impossible to
//! guarantee system-level robustness by on-chip design; TR18.0-01 §7 checks
//! it by simulation of TVS, board, IC and pulse models. None of that is in a
//! layout. What is: the pins exposed to the outside world (WP3 §1.6: the
//! external pins, which the OEM and the IC supplier must name, Q26) carry
//! on-chip protection. `system.esd_iec` holds each named package pin to the
//! package path above, through clamps of the models the system names as
//! rated for system-level stress only.
//!
//! # Limits
//!
//! A bump must be a rectangle; any other shape refuses the assembly. Bump
//! alignment, size and spacing across dies (3DSTACK's dimensional checks)
//! are DRC and are not checked. The ESD checks find whether a path exists:
//! its resistance, its current capacity and the clamps' sizes (ERC-C2 to
//! ERC-C8), the CDM target levels JEP196 sets per assembly process (and a
//! wafer-on-wafer process that may need no die-to-die protection, §4.3), and
//! the package's own R, L and C (TR18.0-01 §6.4, §6.6) are not.

use crate::erc::centre;
use crate::lvs::graph::{narrow, transpose_into, Graph};
use crate::report::{record_run, Measurement, Outcome, RuleRun, Severity, Violation, Violations};
use crate::topology::NetId;
use crate::Design;
use gpurify_geom::ops::{area2, isqrt, Point};
use gpurify_geom::{Bbox, Dbu, DbuArea, LayerId, PolyId};
use gpurify_ingest::{StrId, StrTable};
use std::collections::HashMap;

/// Every rule id a system run reports under, besides the `lvs.*` ids of the
/// flat comparison ([`crate::lvs::RULE_IDS`]). Not deck rule kinds: the
/// catalog names them by the feature tags `lvs:system` (LVS-073) and
/// `erc:system` (ERC-C12, ERC-C13).
pub const RULE_IDS: [&str; 8] = [
    "system.unbonded_bump",
    "system.bump_offset",
    "system.bump_space",
    "system.open",
    "system.short",
    "system.esd_d2d",
    "system.esd_package",
    "system.esd_iec",
];

/// Interns every [`RULE_IDS`] entry; call it before a check here writes a
/// row, as [`crate::lvs::intern_rule_ids`] is called for LVS.
pub fn intern_rule_ids(strings: &mut StrTable) {
    for name in RULE_IDS {
        strings.intern(name);
    }
}

/// An id [`intern_rule_ids`] missed is `u32::MAX`, which `resolve` panics on.
fn rule_id(strings: &StrTable, name: &str) -> StrId {
    strings.get(name).unwrap_or(StrId(u32::MAX))
}

/// A system row has no layer: layer ids belong to one die's deck.
const NO_LAYER: LayerId = LayerId(u16::MAX);
/// No shape: a row about a net or a pin.
const NO_SHAPE: PolyId = PolyId(u32::MAX);
/// A pin with no bump has no place.
pub const NOWHERE: Point = Point {
    x: Dbu::new_unchecked(0),
    y: Dbu::new_unchecked(0),
};

/// Where one die sits in the assembly: reflected in its x axis (`y` to `-y`)
/// when `mirror`, then turned counter-clockwise by `quarter_turns`, then
/// moved by `(dx, dy)`, the order a GDSII reference applies them in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Placement {
    /// Reflect in the x axis first: a die flipped face down.
    pub mirror: bool,
    /// Counter-clockwise quarter turns; only the count modulo 4 is read.
    pub quarter_turns: u8,
    /// Where the die's origin lands, x.
    pub dx: Dbu,
    /// Where the die's origin lands, y.
    pub dy: Dbu,
}

impl Placement {
    /// A point of the die in the assembly's coordinates.
    pub fn apply(self, p: Point) -> Point {
        let (mut x, mut y) = (p.x.raw(), p.y.raw());
        if self.mirror {
            y = -y;
        }
        for _ in 0..self.quarter_turns % 4 {
            (x, y) = (-y, x);
        }
        Point {
            x: Dbu::new_unchecked(x + self.dx.raw()),
            y: Dbu::new_unchecked(y + self.dy.raw()),
        }
    }

    /// A box of the die in the assembly's coordinates: a quarter turn and a
    /// reflection map a box onto a box.
    pub fn apply_box(self, b: Bbox) -> Bbox {
        let lo = self.apply(Point { x: b.xlo, y: b.ylo });
        let hi = self.apply(Point { x: b.xhi, y: b.yhi });
        Bbox::point(lo.x, lo.y).include(hi.x, hi.y)
    }
}

/// One bump of a face: its shape and net on its own die, and where it lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bump {
    /// The shape, a row of its die's store.
    pub poly: PolyId,
    /// The net of its die it is on.
    pub net: NetId,
    /// The rectangle, placed.
    pub at: Bbox,
}

/// Why a face's shapes are not bumps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BumpError {
    /// A shape that is not a rectangle, or a hole: overlap is decided on
    /// rectangles exactly, and on nothing else.
    #[error("shape {0:?} is not a rectangle")]
    NotRectangle(PolyId),
    /// A shape on no net: the layer is not a conductor of the deck.
    #[error("shape {0:?} is on no net: the layer is not a conductor")]
    NoNet(PolyId),
}

/// Every shape of `layer` as a [`Bump`], placed by `placement`, in store
/// order, into `out` (cleared first). A layer the store does not have holds
/// none.
///
/// # Errors
///
/// [`BumpError`] at the first shape that is not a counter-clockwise
/// rectangle, or is on no net.
pub fn bumps_into(
    design: Design<'_>,
    layer: LayerId,
    placement: Placement,
    out: &mut Vec<Bump>,
) -> Result<(), BumpError> {
    out.clear();
    if layer.idx() >= design.store.layer_count() {
        return Ok(());
    }
    for row in design.store.polys_on_layer(layer) {
        let poly = PolyId(row);
        let (xs, ys) = design.store.poly_verts(poly);
        let bbox = design.store.poly_bbox(poly);
        // Four vertices enclosing the box's whole area, counter-clockwise.
        if xs.len() != 4 || area2(xs, ys).raw() != 2 * bbox.area().raw() {
            return Err(BumpError::NotRectangle(poly));
        }
        let net = design.nets.net_of(poly);
        if net == NetId::NONE {
            return Err(BumpError::NoNet(poly));
        }
        out.push(Bump {
            poly,
            net,
            at: placement.apply_box(bbox),
        });
    }
    Ok(())
}

/// Whether two boxes share area; touching is not bonding.
fn bond(a: Bbox, b: Bbox) -> bool {
    a.intersection(b).is_some_and(|meet| meet.area().raw() > 0)
}

/// Every `(i, j)` whose bumps `a[i]` and `b[j]` overlap with positive area,
/// ascending.
///
/// `b` is filed in a hash grid whose cell is its widest bump, so each bump
/// of `b` sits in at most four cells and the cost is linear in the bumps
/// for bumps of one size.
pub fn bonded_pairs(a: &[Bump], b: &[Bump]) -> Vec<(u32, u32)> {
    let cell = b
        .iter()
        .map(|bump| bump.at.width().raw().max(bump.at.height().raw()))
        .max()
        .unwrap_or(0)
        .max(1);
    let cells = |at: Bbox| {
        let xs = at.xlo.raw().div_euclid(cell)..=at.xhi.raw().div_euclid(cell);
        let ys = at.ylo.raw().div_euclid(cell)..=at.yhi.raw().div_euclid(cell);
        xs.flat_map(move |x| ys.clone().map(move |y| (x, y)))
    };
    let mut grid: HashMap<(i64, i64), Vec<u32>> = HashMap::new();
    for (j, bump) in b.iter().enumerate() {
        for key in cells(bump.at) {
            grid.entry(key).or_default().push(narrow(j));
        }
    }
    let mut pairs = Vec::new();
    for (i, bump) in a.iter().enumerate() {
        for key in cells(bump.at) {
            for &j in grid.get(&key).map_or(&[][..], Vec::as_slice) {
                if bond(bump.at, b[j as usize].at) {
                    pairs.push((narrow(i), j));
                }
            }
        }
    }
    pairs.sort_unstable();
    pairs.dedup();
    pairs
}

/// Bonds each pair of facing faces, and records `system.unbonded_bump`.
///
/// Returns, per bond, the [`bonded_pairs`] of its two faces. Every bump that
/// bonds nothing on the facing die is a row at its placed centre, measured 0
/// bumps against 1, shape its die's row: a floating bump, missing its mate
/// or misaligned. Records one [`RuleRun`], examining every bump of every
/// bonded face.
pub fn check_bonds(
    bonds: &[[&[Bump]; 2]],
    strings: &StrTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) -> Vec<Vec<(u32, u32)>> {
    let rule = rule_id(strings, "system.unbonded_bump");
    let before = out.len();
    let mut examined = 0u64;
    let mut all = Vec::with_capacity(bonds.len());
    for [a, b] in bonds {
        let pairs = bonded_pairs(a, b);
        let mut bonded = [vec![false; a.len()], vec![false; b.len()]];
        for &(i, j) in &pairs {
            bonded[0][i as usize] = true;
            bonded[1][j as usize] = true;
        }
        for (face, flags) in [*a, *b].into_iter().zip(&bonded) {
            examined += face.len() as u64;
            for (bump, _) in face.iter().zip(flags).filter(|(_, &paired)| !paired) {
                out.push(Violation {
                    rule,
                    layer: NO_LAYER,
                    severity: Severity::Error,
                    at: centre(bump.at),
                    measured: Measurement::Count(0),
                    limit: Measurement::Count(1),
                    shapes: (bump.poly, None),
                });
            }
        }
        all.push(pairs);
    }
    record_run(runs, out, before, rule, Outcome::Ran, examined);
    all
}

/// Holds each bond's bumps to its limits, `(max offset, min space)` in grid
/// units, `None` where the bond states none (catalog DRC-129, Calibre
/// 3DSTACK's alignment and spacing between dies): `system.bump_offset` for
/// two bonded bumps whose centres are more than the offset apart, at the
/// middle of the two centres (floored), measuring their distance (floored);
/// `system.bump_space` for a bump closer than the space to a bump of the
/// facing die it does not bond, at the middle of their gap, measuring it.
/// A row is recorded only when some bond states its limit, examining the
/// bonded pairs (offset) or the facing bumps (space) of those bonds.
///
/// # Panics
///
/// When `pairs` or `limits` is not one entry per bond.
// ponytail: every facing pair of bumps, O(a·b) per bond; file the far face in
// a hash grid as `bonded_pairs` does if packages of 10^5 bumps make it slow.
pub fn check_alignment(
    bonds: &[[&[Bump]; 2]],
    pairs: &[Vec<(u32, u32)>],
    limits: &[(Option<Dbu>, Option<Dbu>)],
    strings: &StrTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    assert!(
        bonds.len() == pairs.len() && bonds.len() == limits.len(),
        "one entry per bond"
    );
    let twice = |b: Bbox| {
        (
            i128::from(b.xlo.raw()) + i128::from(b.xhi.raw()),
            i128::from(b.ylo.raw()) + i128::from(b.yhi.raw()),
        )
    };
    if limits.iter().any(|l| l.0.is_some()) {
        let rule = rule_id(strings, "system.bump_offset");
        let before = out.len();
        let mut examined = 0u64;
        for (([a, b], pairs), &(max, _)) in bonds.iter().zip(pairs).zip(limits) {
            let Some(max) = max else {
                continue;
            };
            for &(i, j) in pairs {
                examined += 1;
                let (p, q) = (twice(a[i as usize].at), twice(b[j as usize].at));
                let (dx, dy) = (p.0 - q.0, p.1 - q.1);
                // At twice the scale: 4 d² against (2 max)².
                let d4 = DbuArea::new(dx * dx + dy * dy);
                if d4.raw() > 4 * max.mul_wide(max).raw() {
                    let mid = |u: i128, v: i128| {
                        Dbu::new_unchecked(
                            i64::try_from((u + v).div_euclid(4)).expect("on the grid"),
                        )
                    };
                    out.push(Violation {
                        rule,
                        layer: NO_LAYER,
                        severity: Severity::Error,
                        at: Point {
                            x: mid(p.0, q.0),
                            y: mid(p.1, q.1),
                        },
                        measured: Measurement::Length(Dbu::new_unchecked(isqrt(d4).raw() / 2)),
                        limit: Measurement::Length(max),
                        shapes: (a[i as usize].poly, Some(b[j as usize].poly)),
                    });
                }
            }
        }
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
    if limits.iter().any(|l| l.1.is_some()) {
        let rule = rule_id(strings, "system.bump_space");
        let before = out.len();
        let mut examined = 0u64;
        for (([a, b], pairs), &(_, min)) in bonds.iter().zip(pairs).zip(limits) {
            let Some(min) = min else {
                continue;
            };
            examined += (a.len() + b.len()) as u64;
            for (i, bump) in a.iter().enumerate() {
                for (j, other) in b.iter().enumerate() {
                    if pairs.binary_search(&(narrow(i), narrow(j))).is_ok() {
                        continue;
                    }
                    let gap2 = gap2(bump.at, other.at);
                    if gap2.raw() < min.mul_wide(min).raw() {
                        out.push(Violation {
                            rule,
                            layer: NO_LAYER,
                            severity: Severity::Error,
                            at: gap_middle(bump.at, other.at),
                            measured: Measurement::Length(isqrt(gap2)),
                            limit: Measurement::Length(min),
                            shapes: (bump.poly, Some(other.poly)),
                        });
                    }
                }
            }
        }
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// The squared gap between two boxes; 0 when they touch or overlap.
fn gap2(a: Bbox, b: Bbox) -> DbuArea {
    let axis = |lo: Dbu, hi: Dbu, olo: Dbu, ohi: Dbu| {
        i128::from((olo.raw() - hi.raw()).max(lo.raw() - ohi.raw()).max(0))
    };
    let (dx, dy) = (
        axis(a.xlo, a.xhi, b.xlo, b.xhi),
        axis(a.ylo, a.yhi, b.ylo, b.yhi),
    );
    DbuArea::new(dx * dx + dy * dy)
}

/// The middle of the gap between two boxes, per axis the middle of the gap
/// or of the overlap, floored.
fn gap_middle(a: Bbox, b: Bbox) -> Point {
    let mid = |lo: Dbu, hi: Dbu, olo: Dbu, ohi: Dbu| {
        let (from, to) = if ohi < lo {
            (ohi, lo)
        } else if hi < olo {
            (hi, olo)
        } else {
            (lo.max(olo), hi.min(ohi))
        };
        Dbu::new_unchecked((from.raw() + to.raw()).div_euclid(2))
    };
    Point {
        x: mid(a.xlo, a.xhi, b.xlo, b.xhi),
        y: mid(a.ylo, a.yhi, b.ylo, b.yhi),
    }
}

/// One flat graph of every die's, the nets of each `joins` pair merged.
///
/// A die's net `n` is net `offset + n` of the joined numbering, `offset`
/// the net count of the dies before it; `joins` pairs such numbers. Returns
/// the graph and, per joined net, its net in the graph. The graph's nets are
/// the merged classes, numbered by their lowest member; a class takes the
/// name of its lowest named member, and is a port when any member is.
/// Devices keep their order, die after die, with their kinds, models, roles
/// and parameters.
///
/// # Panics
///
/// When a join names a net past the dies' total, or a die graph breaks the
/// [`Graph`] invariants.
pub fn assemble(dies: &[&Graph], joins: &[(u32, u32)]) -> (Graph, Vec<u32>) {
    let total: usize = dies.iter().map(|die| die.net_count()).sum();
    let mut parent: Vec<u32> = (0..narrow(total)).collect();
    let root = |parent: &mut Vec<u32>, mut net: u32| {
        while parent[net as usize] != net {
            let up = parent[parent[net as usize] as usize];
            parent[net as usize] = up;
            net = up;
        }
        net
    };
    for &(a, b) in joins {
        let (a, b) = (root(&mut parent, a), root(&mut parent, b));
        // The lower root wins, so every root is its class's lowest member.
        parent[a.max(b) as usize] = a.min(b);
    }
    let mut graph = Graph::default();
    let mut class = vec![u32::MAX; total];
    for net in 0..total {
        let top = root(&mut parent, narrow(net)) as usize;
        if class[top] == u32::MAX {
            class[top] = narrow(graph.net_name.len());
            graph.net_name.push(None);
        }
        class[net] = class[top];
    }
    graph.device_terminal_start.push(0);
    graph.device_param_start.push(0);
    let mut offset = 0usize;
    for die in dies {
        let at = |net: u32| {
            if net == u32::MAX {
                net
            } else {
                class[offset + net as usize]
            }
        };
        graph.device_kind.extend_from_slice(&die.device_kind);
        graph.device_model.extend_from_slice(&die.device_model);
        let terminals = narrow(graph.terminal_net.len());
        graph.device_terminal_start.extend(
            die.device_terminal_start
                .iter()
                .skip(1)
                .map(|&start| terminals + start),
        );
        graph
            .terminal_net
            .extend(die.terminal_net.iter().map(|&net| at(net)));
        graph.terminal_role.extend_from_slice(&die.terminal_role);
        let params = narrow(graph.param.len());
        graph.device_param_start.extend(
            die.device_param_start
                .iter()
                .skip(1)
                .map(|&start| params + start),
        );
        graph.param.extend_from_slice(&die.param);
        for (net, &name) in die.net_name.iter().enumerate() {
            let slot = &mut graph.net_name[at(narrow(net)) as usize];
            if slot.is_none() {
                *slot = name;
            }
        }
        graph
            .port_net
            .extend(die.port_net.iter().map(|&net| at(net)));
        offset += die.net_count();
    }
    graph.port_net.sort_unstable();
    graph.port_net.dedup();
    let nets = graph.net_name.len();
    transpose_into(&mut graph, nets);
    (graph, class)
}

/// One pin of the system netlist, with where the assembly put it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pin {
    /// The system netlist's net the pin is on (any numbering one netlist
    /// gives its nets).
    pub reference: u32,
    /// The assembled net the label naming the pin is on, or `u32::MAX` when
    /// no label of its die names it.
    pub layout: u32,
    /// Where to look: a bump of the pin's net, or [`NOWHERE`].
    pub at: Point,
}

/// Compares the assembly's connectivity with the system netlist's, pin by
/// pin, and records `system.open` and `system.short`.
///
/// - `system.open`: a pin no label names, measured 0 nets against 1; and a
///   system net whose pins land on several assembled nets, one row per
///   assembled net past the first, at its first pin, measured 2 against 1.
/// - `system.short`: an assembled net holding pins of several system nets,
///   one row per system net past the first, at its first pin, measured 2
///   against 1.
///
/// "First" is `pins` order. Records one [`RuleRun`] per id, each examining
/// every pin.
pub fn check_pins(pins: &[Pin], strings: &StrTable, out: &mut Violations, runs: &mut Vec<RuleRun>) {
    let row = |rule, at, measured| Violation {
        rule,
        layer: NO_LAYER,
        severity: Severity::Error,
        at,
        measured: Measurement::Count(measured),
        limit: Measurement::Count(1),
        shapes: (NO_SHAPE, None),
    };
    let examined = pins.len() as u64;
    let mut order: Vec<usize> = (0..pins.len()).collect();

    let open = rule_id(strings, "system.open");
    let before = out.len();
    order.sort_by_key(|&i| (pins[i].reference, i));
    for group in order.chunk_by(|&a, &b| pins[a].reference == pins[b].reference) {
        let mut pieces: Vec<u32> = Vec::new();
        for pin in group.iter().map(|&i| pins[i]) {
            if pin.layout == u32::MAX {
                out.push(row(open, pin.at, 0));
            } else if !pieces.contains(&pin.layout) {
                if !pieces.is_empty() {
                    out.push(row(open, pin.at, 2));
                }
                pieces.push(pin.layout);
            }
        }
    }
    record_run(runs, out, before, open, Outcome::Ran, examined);

    let short = rule_id(strings, "system.short");
    let before = out.len();
    order.sort_by_key(|&i| (pins[i].layout, i));
    for group in order.chunk_by(|&a, &b| pins[a].layout == pins[b].layout) {
        if pins[group[0]].layout == u32::MAX {
            continue;
        }
        let mut nets: Vec<u32> = Vec::new();
        for pin in group.iter().map(|&i| pins[i]) {
            if !nets.contains(&pin.reference) {
                if !nets.is_empty() {
                    out.push(row(short, pin.at, 2));
                }
                nets.push(pin.reference);
            }
        }
    }
    record_run(runs, out, before, short, Outcome::Ran, examined);
}

/// A supply rail: the net's bit in a supply column is set.
pub const POWER: u8 = 1;
/// A ground rail.
pub const GROUND: u8 = 2;

/// How many of the two rail kinds (power, ground) `pad` reaches through
/// devices whose model is in `clamps`: a clamp from the pad to a supply, then
/// any chain of clamps between supplies (rail clamps). A clamp joins all its
/// terminals, however it is wired; another signal net is not a path. This
/// is `esd_topological`'s search (ERC-C1), on a [`Graph`].
///
/// `supply` holds [`POWER`] and [`GROUND`] bits per net of `graph`; `seen`
/// and `stack` are scratch.
pub fn rails_reached(
    graph: &Graph,
    supply: &[u8],
    clamps: &[StrId],
    pad: u32,
    seen: &mut Vec<bool>,
    stack: &mut Vec<u32>,
) -> u32 {
    // ponytail: O(nets) reset per pad; pads are few next to nets.
    seen.clear();
    seen.resize(graph.net_count(), false);
    stack.clear();
    stack.push(pad);
    seen[pad as usize] = true;
    let mut reached = 0u8;
    while let Some(net) = stack.pop() {
        let rails = supply[net as usize];
        reached |= rails;
        if rails == 0 && net != pad {
            continue;
        }
        for &(device, _) in graph.terminals_on(net) {
            if !clamps.contains(&graph.device_model[device as usize]) {
                continue;
            }
            for &next in graph.terminals_of(device).0 {
                if next != u32::MAX && !seen[next as usize] {
                    seen[next as usize] = true;
                    stack.push(next);
                }
            }
        }
    }
    u32::from(reached & POWER != 0) + u32::from(reached & GROUND != 0)
}

/// Holds every pad in `pads` (a net of `graph` and where to report it) to
/// [`rails_reached`] through `clamps`, appending a row under `rule` for
/// each that reaches fewer than both rail kinds: at the pad's first place,
/// measured the kinds reached against 2. A net listed twice is held once,
/// and a net no device terminal reaches is not examined. Returns the nets
/// examined; the caller records the run, which may span several graphs.
pub fn esd_pads_into(
    rule: StrId,
    graph: &Graph,
    supply: &[u8],
    clamps: &[StrId],
    pads: &[(u32, Point)],
    out: &mut Violations,
) -> u64 {
    let (mut seen, mut stack) = (Vec::new(), Vec::new());
    let mut held = vec![false; graph.net_count()];
    let mut examined = 0u64;
    for &(pad, at) in pads {
        if held[pad as usize] || graph.terminals_on(pad).is_empty() {
            continue;
        }
        held[pad as usize] = true;
        examined += 1;
        let rails = rails_reached(graph, supply, clamps, pad, &mut seen, &mut stack);
        if rails < 2 {
            out.push(Violation {
                rule,
                layer: NO_LAYER,
                severity: Severity::Error,
                at,
                measured: Measurement::Count(rails),
                limit: Measurement::Count(2),
                shapes: (NO_SHAPE, None),
            });
        }
    }
    examined
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::topology::TerminalRole;
    use gpurify_ingest::deck::DeviceKind;

    fn d(v: i64) -> Dbu {
        Dbu::new_unchecked(v)
    }

    fn rect(xlo: i64, ylo: i64, xhi: i64, yhi: i64) -> Bbox {
        Bbox::point(d(xlo), d(ylo)).include(d(xhi), d(yhi))
    }

    fn bump(net: u32, at: Bbox) -> Bump {
        Bump {
            poly: PolyId(net),
            net: NetId(net),
            at,
        }
    }

    /// Oracle: hand-derived. The point (3, 1) reflected in the x axis is
    /// (3, -1); a quarter turn counter-clockwise takes (x, y) to (-y, x), so
    /// (3, 1) turns to (-1, 3), two turns to (-3, -1), and five turns are one;
    /// the move is added last. A box's corners map to the placed box's.
    #[test]
    fn a_placement_reflects_then_turns_then_moves() {
        let p = Point { x: d(3), y: d(1) };
        let place = |mirror, quarter_turns, dx, dy| Placement {
            mirror,
            quarter_turns,
            dx: d(dx),
            dy: d(dy),
        };
        let at = |placement: Placement| {
            let q = placement.apply(p);
            (q.x.raw(), q.y.raw())
        };
        assert_eq!(at(Placement::default()), (3, 1));
        assert_eq!(at(place(true, 0, 0, 0)), (3, -1));
        assert_eq!(at(place(false, 1, 0, 0)), (-1, 3));
        assert_eq!(at(place(false, 2, 0, 0)), (-3, -1));
        assert_eq!(at(place(false, 5, 0, 0)), (-1, 3));
        // Reflected to (3, -1), then turned to (1, 3), then moved.
        assert_eq!(at(place(true, 1, 10, 20)), (11, 23));
        assert_eq!(
            place(true, 1, 10, 20).apply_box(rect(0, 0, 4, 2)),
            rect(10, 20, 12, 24)
        );
    }

    /// Oracle: hand-derived overlaps. Bumps of one size on a pitch: each of
    /// `a` overlaps the one of `b` drawn on it, a bump shifted half a width
    /// still shares area, a bump only touching shares none, and one far away
    /// nothing; the result is ascending whatever order `b` is in.
    #[test]
    fn bumps_bond_where_they_share_area_and_not_where_they_touch() {
        let a = [
            bump(0, rect(0, 0, 10, 10)),
            bump(1, rect(100, 0, 110, 10)),
            bump(2, rect(200, 0, 210, 10)),
            bump(3, rect(300, 0, 310, 10)),
        ];
        let b = [
            bump(9, rect(305, 5, 315, 15)),
            bump(8, rect(210, 0, 220, 10)),
            bump(7, rect(100, 0, 110, 10)),
            bump(6, rect(0, 0, 10, 10)),
            bump(5, rect(5000, 0, 5010, 10)),
        ];
        assert_eq!(bonded_pairs(&a, &b), [(0, 3), (1, 2), (3, 0)]);
        assert!(bonded_pairs(&a, &[]).is_empty());
        assert!(bonded_pairs(&[], &b).is_empty());
        // A pad wider than the cells of `b` still finds every bump under it.
        let pad = [bump(0, rect(-50, -50, 400, 60))];
        assert_eq!(bonded_pairs(&pad, &b), [(0, 0), (0, 1), (0, 2), (0, 3)]);
    }

    /// Oracle: hand-derived from `check_bonds`' rustdoc: of two faces of two
    /// bumps each, one pair bonds, so the other bump of each face is a row,
    /// at its centre, measured 0 against 1; all four were examined.
    #[test]
    fn a_bump_with_no_mate_is_unbonded() {
        let mut strings = StrTable::default();
        intern_rule_ids(&mut strings);
        let a = [bump(0, rect(0, 0, 10, 10)), bump(1, rect(100, 0, 110, 10))];
        let b = [bump(2, rect(0, 0, 10, 10)), bump(3, rect(200, 0, 210, 10))];
        let (mut out, mut runs) = (Violations::default(), Vec::new());
        let pairs = check_bonds(&[[&a[..], &b[..]]], &strings, &mut out, &mut runs);
        assert_eq!(pairs, [vec![(0, 0)]]);
        assert_eq!(runs.len(), 1);
        assert_eq!((runs[0].examined, runs[0].violations), (4, 2));
        let found: Vec<(i64, i64, PolyId)> = (0..out.len())
            .map(|i| (out.at[i].x.raw(), out.at[i].y.raw(), out.shape_a[i]))
            .collect();
        assert_eq!(found, [(105, 5, PolyId(1)), (205, 5, PolyId(3))]);
        assert!(out.measured.iter().all(|&m| m == Measurement::Count(0)));
    }

    /// A die graph by hand: `devices` as `(model, terminal nets)`, all
    /// `Pin` roles, `names` per net, ports the named nets.
    fn die(devices: &[(u32, &[u32])], names: &[Option<u32>]) -> Graph {
        let mut graph = Graph::default();
        graph.device_terminal_start.push(0);
        graph.device_param_start.push(0);
        for &(model, nets) in devices {
            graph.device_kind.push(DeviceKind::Diode);
            graph.device_model.push(StrId(model));
            graph.terminal_net.extend_from_slice(nets);
            graph.terminal_role.extend(
                (0..nets.len()).map(|k| TerminalRole::Pin(u8::try_from(k).expect("few terminals"))),
            );
            graph
                .device_terminal_start
                .push(narrow(graph.terminal_net.len()));
            graph.param.push((StrId(0), f64::from(model)));
            graph.device_param_start.push(narrow(graph.param.len()));
        }
        graph.net_name = names.iter().map(|n| n.map(StrId)).collect();
        graph.port_net = (0..narrow(names.len()))
            .filter(|&n| names[n as usize].is_some())
            .collect();
        transpose_into(&mut graph, names.len());
        graph
    }

    /// Oracle: hand-derived. Die A (nets 0..3) and die B (nets 3..5 joined)
    /// with A's net 1 joined to B's net 0 and A's 2 to B's 1: the five nets
    /// become three classes {0}, {1, 3}, {2, 4}, numbered by lowest member;
    /// B's device lands on classes 1 and 2; the class of A's unnamed net 1
    /// takes B's name, and is a port.
    #[test]
    fn assembling_merges_bonded_nets_and_keeps_every_device() {
        let a = die(&[(7, &[0, 1]), (8, &[1, 2])], &[Some(10), None, Some(12)]);
        let b = die(&[(9, &[0, 1])], &[Some(20), Some(21)]);
        let (graph, class) = assemble(&[&a, &b], &[(1, 3), (4, 2)]);
        assert_eq!(class, [0, 1, 2, 1, 2]);
        assert_eq!(graph.net_count(), 3);
        assert_eq!(graph.device_count(), 3);
        assert_eq!(graph.terminals_of(2).0, [1, 2]);
        assert_eq!(graph.terminals_of(1).0, [1, 2]);
        assert_eq!(graph.device_model, [StrId(7), StrId(8), StrId(9)]);
        assert_eq!(graph.params_of(2), [(StrId(0), 9.0)]);
        assert_eq!(
            graph.net_name,
            [Some(StrId(10)), Some(StrId(20)), Some(StrId(12))]
        );
        assert_eq!(graph.port_net, [0, 1, 2]);
        assert_eq!(
            graph.terminals_on(1),
            [
                (0, TerminalRole::Pin(1)),
                (1, TerminalRole::Pin(0)),
                (2, TerminalRole::Pin(0))
            ]
        );
        // Nothing joined: the dies side by side.
        let (apart, class) = assemble(&[&a, &b], &[]);
        assert_eq!(class, [0, 1, 2, 3, 4]);
        assert_eq!(apart.terminals_of(2).0, [3, 4]);
    }

    /// Oracle: hand-derived from `check_pins`' rustdoc. System nets 0 and 1
    /// over pins p0..p4: p0, p1 on system net 0 land on assembled nets 5 and
    /// 6 (an open: one row, at p1, measured 2), p2 on system net 1 lands on 6
    /// with p1 (a short: one row, at p2), p3 on system net 1 has no label
    /// (an open measured 0), and p4 on system net 1 lands on 6 too.
    #[test]
    fn pins_split_or_joined_against_the_netlist_are_opens_and_shorts() {
        let mut strings = StrTable::default();
        intern_rule_ids(&mut strings);
        let at = |x| Point { x: d(x), y: d(0) };
        let pin = |reference, layout, x| Pin {
            reference,
            layout,
            at: at(x),
        };
        let pins = [
            pin(0, 5, 0),
            pin(0, 6, 1),
            pin(1, 6, 2),
            pin(1, u32::MAX, 3),
            pin(1, 6, 4),
        ];
        let (mut out, mut runs) = (Violations::default(), Vec::new());
        check_pins(&pins, &strings, &mut out, &mut runs);
        let rows: Vec<(&str, i64, Measurement)> = (0..out.len())
            .map(|i| {
                (
                    strings.resolve(out.rule[i]),
                    out.at[i].x.raw(),
                    out.measured[i],
                )
            })
            .collect();
        assert_eq!(
            rows,
            [
                ("system.open", 1, Measurement::Count(2)),
                ("system.open", 3, Measurement::Count(0)),
                ("system.short", 2, Measurement::Count(2)),
            ]
        );
        assert_eq!(runs.len(), 2);
        assert!(runs.iter().all(|run| run.examined == 5));
        // The netlist's own connectivity: nothing to report.
        let (mut out, mut runs) = (Violations::default(), Vec::new());
        check_pins(
            &[pin(0, 5, 0), pin(0, 5, 1), pin(1, 6, 2)],
            &strings,
            &mut out,
            &mut runs,
        );
        assert!(out.is_empty());
    }

    /// Oracle: hand-derived on the documented search. Nets: 0 pad, 1 power,
    /// 2 ground, 3 a signal, 4 a second ground. Clamp model 1 joins the pad
    /// to power, power to ground; model 2 is no clamp. Through a signal net
    /// nothing passes, and a clamp joins every terminal it has.
    #[test]
    fn rails_are_reached_through_clamps_and_supplies_only() {
        let supply = [0, POWER, GROUND, 0, GROUND];
        let (mut seen, mut stack) = (Vec::new(), Vec::new());
        let mut reach = |devices: &[(u32, &[u32])], clamps: &[StrId]| {
            let graph = die(devices, &[None; 5]);
            rails_reached(&graph, &supply, clamps, 0, &mut seen, &mut stack)
        };
        let clamp = [StrId(1)];
        assert_eq!(reach(&[(1, &[0, 1]), (1, &[1, 2])], &clamp), 2);
        assert_eq!(reach(&[(1, &[0, 1])], &clamp), 1);
        assert_eq!(reach(&[(2, &[0, 1]), (2, &[1, 2])], &clamp), 0);
        // Pad to a signal net, the signal net clamped to both rails: blocked.
        assert_eq!(
            reach(&[(1, &[0, 3]), (1, &[3, 1]), (1, &[3, 2])], &clamp),
            0
        );
        // One three-terminal clamp from the pad to both rails.
        assert_eq!(reach(&[(1, &[1, 0, 4])], &clamp), 2);
        assert_eq!(reach(&[(1, &[1, 0, 4])], &[]), 0);
    }

    /// Oracle: hand-derived from `esd_pads_into`'s rustdoc: of pads on nets
    /// 0 (clamped to power only), 0 again, 3 (no device) and 5 (clamped to
    /// both), net 0 is one row measured 1 at its first place, net 3 is not
    /// examined, and two nets were.
    #[test]
    fn an_esd_row_holds_each_pad_net_once() {
        let mut strings = StrTable::default();
        intern_rule_ids(&mut strings);
        let rule = rule_id(&strings, "system.esd_package");
        let graph = die(&[(1, &[0, 1]), (1, &[5, 1]), (1, &[5, 2])], &[None; 6]);
        let supply = [0, POWER, GROUND, 0, 0, 0];
        let at = |x| Point { x: d(x), y: d(0) };
        let mut out = Violations::default();
        let examined = esd_pads_into(
            rule,
            &graph,
            &supply,
            &[StrId(1)],
            &[(0, at(1)), (0, at(2)), (3, at(3)), (5, at(4))],
            &mut out,
        );
        assert_eq!(examined, 2);
        assert_eq!(out.len(), 1);
        assert_eq!(
            (out.at[0].x.raw(), out.measured[0]),
            (1, Measurement::Count(1))
        );
    }
}
