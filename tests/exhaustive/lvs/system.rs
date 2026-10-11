//! Multi-die systems (catalog LVS-073, ERC-C12, ERC-C13): dies drawn as the
//! enumeration draws a circuit, with bumps wired to their nets' tracks, read
//! back through the real reader, placed and checked by
//! `gpurify::engine::system::check`.
//!
//! - Hand-derived stacks: a two-die stack matches, and a missing or a
//!   mis-ordered bump does not, with the rows `system.unbonded_bump`,
//!   `system.open` and `system.short` the definitions give; the same stack
//!   under every symmetry of the whole assembly gives the same rows, moved
//!   (a metamorphic relation).
//! - The brute-force oracle ([`equivalent`]) on the flattened system: every
//!   stack of two enumerated circuits, bonded net to net, against its own
//!   system netlist, every single fault of either die's subcircuit, and
//!   every missing and swapped bump; the oracle reads a flat circuit the test
//!   builds from the circuits and the bumps it drew, never from the tool.
//! - ESD: hand-derived package and die-to-die cases, and the same stacks
//!   with every die's `n0` a power and `n1` a ground rail held to a search
//!   written here over the circuits as drawn.
//!
//! [`netgen_cases`] gives the stacks to the Netgen differential.

use super::{
    circuits, draw, equivalent, faults, subckt, track, Circuit, Dev, Model, EXTRA_DECK, MOS_DECK,
};
use crate::harness::{self, Fixture, Layout, NONE};
use gpurify::check::lvs::Verdict;
use gpurify::check::report::{Measurement, Outcome, SkipReason};
use gpurify::engine::pipeline::{read_die, read_reference_text, Die};
use gpurify::engine::run::{Outputs, Summary};
use gpurify::engine::system::{all_models, check, SystemError};
use gpurify_ingest::intent::parse_intent;
use gpurify_ingest::system::parse_system;
use gpurify_ingest::{DesignIntent, StrTable};
use gpurify_testgen::Rng;
use std::fmt::Write as _;
use std::path::Path;

/// The deck of every die: the enumeration's, with two bump faces, `bump`
/// toward the other die and `c4` toward the package, each reached from met1
/// through its own cut.
fn deck() -> String {
    format!(
        "{MOS_DECK}{EXTRA_DECK}layer bump = gds(20, 0)
layer vbump = gds(21, 0)
layer c4 = gds(22, 0)
layer vc4 = gds(23, 0)
connect conductors [bump, c4]
connect via vbump [met1, bump]
connect via vc4 [met1, c4]
"
    )
}

/// The first bump slot's x; every device the drawer places lies left of it.
const BUMP_X: i64 = 40_000;

/// The placed centre of bump slot `slot`: slots are 200 nm squares 1000 nm
/// apart on y = 0.
fn slot_centre(slot: usize) -> (i64, i64) {
    (
        BUMP_X + 1000 * i64::try_from(slot).expect("few slots") + 100,
        100,
    )
}

/// `layout` with a 200 nm bump in `slot` on `face` (`bump` or `c4`), wired to
/// `net`'s met2 track: the track runs on to the slot, a met1 strap drops
/// from it through `via1` to the bump's cut.
fn bumped(layout: Layout, net: usize, slot: usize, face: &str) -> Layout {
    let (x, _) = slot_centre(slot);
    let x = x - 100;
    let t = track(net);
    let cut = if face == "bump" { "vbump" } else { "vc4" };
    layout
        .rect("met2", -1000, t, x + 200, t + 200)
        .rect("via1", x, t, x + 200, t + 200)
        .rect("met1", x, 0, x + 200, t + 200)
        .rect(cut, x, 0, x + 200, 200)
        .rect(face, x, 0, x + 200, 200)
}

/// A circuit drawn, with bumps `(net, slot, face)`.
fn die_layout(c: &Circuit, bumps: &[(usize, usize, &str)]) -> Layout {
    bumps.iter().fold(draw(c), |layout, &(net, slot, face)| {
        bumped(layout, net, slot, face)
    })
}

/// A placement as the system file states it: reflect in x when `mirror`,
/// turn `turns` quarter turns counter-clockwise, move by `(dx, dy)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Place {
    mirror: bool,
    turns: u8,
    dx: i64,
    dy: i64,
}

impl Place {
    fn apply(self, (mut x, mut y): (i64, i64)) -> (i64, i64) {
        if self.mirror {
            y = -y;
        }
        for _ in 0..self.turns {
            (x, y) = (-y, x);
        }
        (x + self.dx, y + self.dy)
    }

    fn undo(self, (x, y): (i64, i64)) -> (i64, i64) {
        let (mut x, mut y) = (x - self.dx, y - self.dy);
        for _ in 0..self.turns {
            (x, y) = (y, -x);
        }
        if self.mirror {
            y = -y;
        }
        (x, y)
    }

    /// `self` after `before`: one placement doing both, worked out from
    /// `g(p(q)) = R^g M^g (R^p M^p q + d_p) + d_g` and `M R^k = R^-k M`.
    fn after(self, before: Place) -> Place {
        let turns = if self.mirror {
            (self.turns + 4 - before.turns) % 4
        } else {
            (self.turns + before.turns) % 4
        };
        let (dx, dy) = self.apply((before.dx, before.dy));
        Place {
            mirror: self.mirror != before.mirror,
            turns,
            dx,
            dy,
        }
    }

    fn json(self) -> String {
        format!(
            r#""origin_nm": [{}, {}], "rotate": {}, "mirror": {}"#,
            self.dx,
            self.dy,
            u32::from(self.turns) * 90,
            self.mirror
        )
    }
}

/// `layout` drawn so that `place` puts it back where it was: every point
/// through [`Place::undo`], a reflected outline reversed to stay
/// counter-clockwise.
fn unplaced(layout: &Layout, place: Place) -> Layout {
    Layout {
        shapes: layout
            .shapes
            .iter()
            .map(|(layer, points)| {
                let mut out: Vec<_> = points.iter().map(|&p| place.undo(p)).collect();
                if place.mirror {
                    out.reverse();
                }
                (layer.clone(), out)
            })
            .collect(),
        labels: layout
            .labels
            .iter()
            .map(|(layer, x, y, text)| {
                let (x, y) = place.undo((*x, *y));
                (layer.clone(), x, y, text.clone())
            })
            .collect(),
    }
}

/// One die of a test system.
struct DieSpec {
    name: &'static str,
    layout: Layout,
    place: Place,
    intent: Option<String>,
}

/// A die at the origin, unturned, with no intent.
fn die(name: &'static str, layout: Layout) -> DieSpec {
    DieSpec {
        name,
        layout,
        place: Place::default(),
        intent: None,
    }
}

/// What a system run gave, names resolved.
struct Ran {
    outputs: Outputs,
    summary: Summary,
    strings: StrTable,
}

impl Ran {
    /// Every row as `(rule, at, measured)`, in report order.
    fn rows(&self) -> Vec<(String, (i64, i64), Measurement)> {
        let v = &self.outputs.violations;
        (0..v.len())
            .map(|i| {
                (
                    self.strings.resolve(v.rule[i]).to_owned(),
                    (v.at[i].x.raw(), v.at[i].y.raw()),
                    v.measured[i],
                )
            })
            .collect()
    }

    /// The rows of one rule, sorted.
    fn of(&self, rule: &str) -> Vec<((i64, i64), Measurement)> {
        let mut rows: Vec<_> = self
            .rows()
            .into_iter()
            .filter(|(r, ..)| r == rule)
            .map(|(_, at, m)| (at, m))
            .collect();
        rows.sort_by_key(|&(at, _)| at);
        rows
    }

    /// One rule's `(outcome, examined, violations)`.
    fn run_of(&self, rule: &str) -> (Outcome, u64, u32) {
        let run = self
            .outputs
            .runs
            .iter()
            .find(|run| self.strings.resolve(run.rule) == rule)
            .unwrap_or_else(|| panic!("no {rule} row"));
        (run.outcome, run.examined, run.violations)
    }

    fn matched(&self) -> bool {
        match &self.outputs.lvs {
            Some(Verdict::Match) => true,
            Some(Verdict::Mismatch(_)) => false,
            other => panic!("no verdict: {other:?}"),
        }
    }
}

/// The dies read back into one table, and their intents.
fn read(dies: &[DieSpec], strings: &mut StrTable) -> (Vec<Die>, Vec<Option<DesignIntent>>) {
    let deck = deck();
    let mut read = Vec::new();
    let mut intents = Vec::new();
    for die in dies {
        let fixture =
            Fixture::new("system/die", &["LVS-073"], &deck, NONE).layout(die.layout.clone());
        let (bytes, ..) = harness::written(&fixture).expect("the writer takes the die");
        read.push(read_die(&bytes, &deck, "system.deck", strings).expect("the die reads back"));
        intents.push(
            die.intent
                .as_deref()
                .map(|text| parse_intent(text, strings).expect("a legal intent")),
        );
    }
    (read, intents)
}

/// A face of a die: `(die, layer)`.
type FaceOf<'a> = (&'a str, &'a str);

/// The system file for `dies`, its bonds (two faces each), an optional
/// package face and `esd` section.
fn system_json(
    dies: &[DieSpec],
    bonds: &[(FaceOf<'_>, FaceOf<'_>)],
    package: Option<FaceOf<'_>>,
    esd: Option<&str>,
) -> String {
    let mut out = String::from(r#"{ "dies": ["#);
    for (i, die) in dies.iter().enumerate() {
        let _ = write!(
            out,
            r#"{}{{ "name": "{}", "layout": "{0}.gds", "deck": "d.deck", {} }}"#,
            if i == 0 { "" } else { ", " },
            die.name,
            die.place.json()
        );
    }
    out.push_str(r#"], "bonds": ["#);
    for (i, ((a, la), (b, lb))) in bonds.iter().enumerate() {
        let _ = write!(
            out,
            r#"{}{{ "a": {{ "die": "{a}", "layer": "{la}" }}, "b": {{ "die": "{b}", "layer": "{lb}" }} }}"#,
            if i == 0 { "" } else { ", " }
        );
    }
    out.push(']');
    if let Some((die, layer)) = package {
        let _ = write!(
            out,
            r#", "package": {{ "die": "{die}", "layer": "{layer}" }}"#
        );
    }
    if let Some(esd) = esd {
        let _ = write!(out, r#", "esd": {esd}"#);
    }
    out.push_str(" }");
    out
}

/// The dies read and checked against `reference`.
fn check_dies(dies: &[DieSpec], system: &str, reference: &str) -> Result<Ran, SystemError> {
    let mut strings = StrTable::default();
    let (read, intents) = read(dies, &mut strings);
    let spec = parse_system(system, Path::new("")).expect("a legal system file");
    let netlist = read_reference_text(reference, false, &all_models(&read), &mut strings)
        .expect("a legal system netlist");
    let (outputs, summary) = check(&spec, &read, &intents, &netlist, &mut strings)?;
    Ok(Ran {
        outputs,
        summary,
        strings,
    })
}

/// A circuit whose nets are named `names`, every one a port.
fn named(names: &[&str], devs: Vec<Dev>) -> Circuit {
    Circuit {
        devs,
        names: names.iter().map(|&n| n.to_owned()).collect(),
        ports: vec![true; names.len()],
    }
}

/// A system netlist: one subcircuit per `(cell, circuit)`, then the top
/// `SYS` with `ports`, placing instance `name` of `cell` on `nets`.
fn system_spice(
    cells: &[(&str, &Circuit)],
    ports: &[&str],
    instances: &[(&str, &str, Vec<String>)],
) -> String {
    let mut out = String::from("* generated by tests/exhaustive/lvs/system.rs\n");
    for (cell, c) in cells {
        subckt(&mut out, cell, c, &(0..c.devs.len()).collect::<Vec<_>>());
        out.push_str(".ends\n");
    }
    let _ = writeln!(out, ".subckt SYS {}", ports.join(" "));
    for (name, cell, nets) in instances {
        let _ = writeln!(out, "{name} {} {cell}", nets.join(" "));
    }
    out.push_str(".ends\n");
    out
}

fn strings(names: &[&str]) -> Vec<String> {
    names.iter().map(|&n| n.to_owned()).collect()
}

// ---------------------------------------------------------------------------
// Hand-derived stacks
// ---------------------------------------------------------------------------

/// Die `XA`: an inverter from `in` to `out`. Die `XB`: an inverter from `a`
/// to `q`. `XA.out` drives `XB.a` through bump slot 0; `vss` and `vdd` meet
/// in slots 1 and 2.
fn inverters() -> (Circuit, Circuit, String) {
    use Model::{N, P};
    let a = named(
        &["in", "out", "vss", "vdd"],
        vec![Dev::mos(N, 0, 2, 1), Dev::mos(P, 0, 3, 1)],
    );
    let b = named(
        &["a", "q", "vss", "vdd"],
        vec![Dev::mos(N, 0, 2, 1), Dev::mos(P, 0, 3, 1)],
    );
    let reference = system_spice(
        &[("INV_A", &a), ("INV_B", &b)],
        &["in", "q", "vss", "vdd"],
        &[
            ("XA", "INV_A", strings(&["in", "mid", "vss", "vdd"])),
            ("XB", "INV_B", strings(&["mid", "q", "vss", "vdd"])),
        ],
    );
    (a, b, reference)
}

/// `XA` and `XB` bonded face to face, `XB` drawn so that `place` puts its
/// bumps on `XA`'s; `b_slots` gives `XB`'s slot for `a`, `vss` and `vdd`
/// (`None` leaves the bump out).
fn inverter_stack(place: Place, b_slots: [Option<usize>; 3]) -> (Vec<DieSpec>, String) {
    let (a, b, _) = inverters();
    let top = die_layout(&a, &[(1, 0, "bump"), (2, 1, "bump"), (3, 2, "bump")]);
    let bumps: Vec<(usize, usize, &str)> = [0, 2, 3]
        .into_iter()
        .zip(b_slots)
        .filter_map(|(net, slot)| slot.map(|slot| (net, slot, "bump")))
        .collect();
    let bottom = DieSpec {
        name: "XB",
        layout: unplaced(&die_layout(&b, &bumps), place),
        place,
        intent: None,
    };
    let dies = vec![die("XA", top), bottom];
    let system = system_json(&dies, &[(("XA", "bump"), ("XB", "bump"))], None, None);
    (dies, system)
}

/// `XB` reflected face down, turned a quarter, and moved off the origin.
const FLIP: Place = Place {
    mirror: true,
    turns: 1,
    dx: 7000,
    dy: -3000,
};

/// Catalog LVS-073: system LVS across dies.
///
/// Oracle: hand-derived from the system netlist and the bumps drawn (the
/// definitions in `gpurify_check::system`). Correct: every bump bonds, every
/// pin is where the netlist puts it, and the flat circuits are the same, so
/// a match with no row. `XB.a`'s bump left out: `XA.out`'s bump (slot 0)
/// bonds nothing, the netlist's net `mid` is in two pieces (an open at
/// `XB.a`, which has no bump, so at the origin), and `XB`'s inverter input
/// floats: a mismatch. `XB.a` and `XB.vss` swapped (slots 1 and 0):
/// `XA.out` lands on `XB.vss` and `XA.vss` on `XB.a`, so `mid` and `vss`
/// are each split (two opens, at `XB.a`'s and `XB.vss`'s bumps) and each
/// assembled net joins two netlist nets (two shorts, at the second pin of
/// each, `XB.vss` and `XB.a`), and `XA` now drives `XB`'s source rail: a
/// mismatch.
#[test]
fn a_two_die_stack_matches_and_a_missing_or_misordered_bump_does_not() {
    let (_, _, reference) = inverters();
    let ran = |slots| {
        let (dies, system) = inverter_stack(FLIP, slots);
        check_dies(&dies, &system, &reference).expect("an assembly")
    };
    let none: Vec<((i64, i64), Measurement)> = Vec::new();
    let count = |n| Measurement::Count(n);

    let good = ran([Some(0), Some(1), Some(2)]);
    assert!(good.matched());
    assert_eq!(good.rows(), []);
    assert_eq!(good.run_of("system.unbonded_bump"), (Outcome::Ran, 6, 0));
    assert_eq!(good.run_of("system.open"), (Outcome::Ran, 8, 0));
    assert!(good.summary.passed());

    let missing = ran([None, Some(1), Some(2)]);
    assert!(!missing.matched());
    assert_eq!(
        missing.of("system.unbonded_bump"),
        [(slot_centre(0), count(0))]
    );
    assert_eq!(missing.of("system.open"), [((0, 0), count(2))]);
    assert_eq!(missing.of("system.short"), none);
    assert!(!missing.summary.passed());

    let swapped = ran([Some(1), Some(0), Some(2)]);
    assert!(!swapped.matched());
    assert_eq!(swapped.of("system.unbonded_bump"), none);
    assert_eq!(
        swapped.of("system.open"),
        [(slot_centre(0), count(2)), (slot_centre(1), count(2))]
    );
    assert_eq!(
        swapped.of("system.short"),
        [(slot_centre(0), count(2)), (slot_centre(1), count(2))]
    );
}

/// The eight symmetries of the square, each with a move.
fn symmetries() -> Vec<Place> {
    (0..8u8)
        .map(|k| Place {
            mirror: k >= 4,
            turns: k % 4,
            dx: 11_000 * i64::from(k),
            dy: -5_000,
        })
        .collect()
}

/// Oracle: metamorphic. Placing the whole mis-ordered stack under any
/// symmetry of the square and a move (every die's placement composed with
/// it) bonds the same bumps, so it gives the same verdict and the same rows,
/// each system row moved with the assembly.
#[test]
fn placing_the_whole_assembly_anywhere_changes_nothing() {
    let (_, _, reference) = inverters();
    let slots = [Some(1), Some(0), Some(2)];
    let (dies, system) = inverter_stack(FLIP, slots);
    let base = check_dies(&dies, &system, &reference).expect("an assembly");
    for g in symmetries() {
        let (mut dies, _) = inverter_stack(FLIP, slots);
        for die in &mut dies {
            die.place = g.after(die.place);
        }
        let system = system_json(&dies, &[(("XA", "bump"), ("XB", "bump"))], None, None);
        let moved = check_dies(&dies, &system, &reference).expect("an assembly");
        assert_eq!(moved.matched(), base.matched(), "{g:?}");
        let mut want: Vec<_> = base
            .rows()
            .into_iter()
            .map(|(rule, at, m)| {
                let at = if rule.starts_with("system.") {
                    g.apply(at)
                } else {
                    at
                };
                (rule, at, m)
            })
            .collect();
        let mut have = moved.rows();
        want.sort_by(|a, b| (&a.0, a.1).cmp(&(&b.0, b.1)));
        have.sort_by(|a, b| (&a.0, a.1).cmp(&(&b.0, b.1)));
        assert_eq!(have, want, "{g:?}");
    }
}

/// Oracle: hand-derived. `Place::after` composes as its rustdoc derives:
/// for every pair of symmetries and a point, placing by the composite is
/// placing by one, then the other; and `undo` inverts `apply`.
#[test]
fn composed_placements_are_one_then_the_other() {
    let p = (123, -45);
    for g in symmetries() {
        assert_eq!(g.undo(g.apply(p)), p);
        for h in symmetries() {
            assert_eq!(
                g.after(h).apply(p),
                g.apply(h.apply(p)),
                "{g:?} after {h:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The brute-force oracle on the flattened system
// ---------------------------------------------------------------------------

/// Two enumerated circuits stacked: die `XA`'s net `bonds[s].0` meets die
/// `XB`'s net `bonds[s].1` in bump slot `s`.
#[derive(Debug, Clone)]
struct Stack {
    a: Circuit,
    b: Circuit,
    bonds: Vec<(usize, usize)>,
}

/// Each net of two circuits of `na` and `nb` nets (`a`'s, then `b`'s), as
/// numbered once the pairs in `joined` (`a` net, `b` net) are merged: a
/// class per merged set, by its lowest member. Returns the numbering and the
/// class count.
fn classes(na: usize, nb: usize, joined: &[(usize, usize)]) -> (Vec<usize>, usize) {
    let root = |parent: &[usize], mut x: usize| {
        while parent[x] != x {
            x = parent[x];
        }
        x
    };
    let mut parent: Vec<usize> = (0..na + nb).collect();
    for &(i, j) in joined {
        let (x, y) = (root(&parent, i), root(&parent, na + j));
        parent[x.max(y)] = x.min(y);
    }
    let mut class = vec![usize::MAX; na + nb];
    let mut next = 0;
    for k in 0..na + nb {
        let r = root(&parent, k);
        if class[r] == usize::MAX {
            class[r] = next;
            next += 1;
        }
        class[k] = class[r];
    }
    (class, next)
}

/// Two dies' circuits as flattened: `a`'s nets, then `b`'s, the pairs in
/// `joined` (`a` net, `b` net) merged ([`classes`]); every net a port.
fn flat(a: &Circuit, b: &Circuit, joined: &[(usize, usize)]) -> Circuit {
    let (class, next) = classes(a.nets(), b.nets(), joined);
    let mut devs = Vec::new();
    for (c, base) in [(a, 0), (b, a.nets())] {
        for dev in &c.devs {
            let mut dev = dev.clone();
            for p in &mut dev.pins {
                *p = class[base + *p];
            }
            devs.push(dev);
        }
    }
    Circuit::new(next, devs)
}

/// The drawn joins: for every slot both dies have a bump in, its two nets.
fn drawn_joins(a_slots: &[(usize, usize)], b_slots: &[(usize, usize)]) -> Vec<(usize, usize)> {
    a_slots
        .iter()
        .filter_map(|&(net, slot)| {
            b_slots
                .iter()
                .find(|&&(_, s)| s == slot)
                .map(|&(other, _)| (net, other))
        })
        .collect()
}

/// The stack's system netlist with `fa` and `fb` as the two dies' cells,
/// wired by name: a bond's two pins share the top net `t<s>`, every other
/// port is a top net of its own. Returns the text and the flat circuit it
/// means: the pins of a bond whose name a fault removed join nothing.
fn stack_reference(stack: &Stack, fa: &Circuit, fb: &Circuit) -> (String, Circuit) {
    let top = |c: &Circuit, die: &str, base: &Circuit, side: usize| -> Vec<String> {
        c.names
            .iter()
            .zip(&c.ports)
            .filter(|(_, &port)| port)
            .map(|(name, _)| {
                let bond = stack.bonds.iter().position(|bond| {
                    let net = if side == 0 { bond.0 } else { bond.1 };
                    &base.names[net] == name
                });
                bond.map_or_else(|| format!("{die}_{name}"), |s| format!("t{s}"))
            })
            .collect()
    };
    let (ta, tb) = (top(fa, "XA", &stack.a, 0), top(fb, "XB", &stack.b, 1));
    let mut ports: Vec<&str> = ta.iter().chain(&tb).map(String::as_str).collect();
    ports.sort_unstable();
    ports.dedup();
    let text = system_spice(
        &[("DA", fa), ("DB", fb)],
        &ports,
        &[("XA", "DA", ta.clone()), ("XB", "DB", tb.clone())],
    );
    let index = |c: &Circuit, base: &Circuit, net: usize| {
        c.names.iter().position(|name| *name == base.names[net])
    };
    let joined: Vec<(usize, usize)> = stack
        .bonds
        .iter()
        .filter_map(|&(i, j)| index(fa, &stack.a, i).zip(index(fb, &stack.b, j)))
        .collect();
    (text, flat(fa, fb, &joined))
}

/// One verdict the oracle decides: a stack drawn with `XB`'s bumps in
/// `b_slots`, against a netlist with these cells.
struct Case {
    name: String,
    a_slots: Vec<(usize, usize)>,
    b_slots: Vec<(usize, usize)>,
    reference: String,
    layout_flat: Circuit,
    reference_flat: Circuit,
}

/// The stack against its own netlist, against every single fault of either
/// die's cell (as the enumeration faults one circuit), and drawn with each
/// bump of `XB` missing and each pair of neighbours swapped.
fn stack_cases(stack: &Stack, label: &str) -> Vec<Case> {
    let a_slots: Vec<(usize, usize)> = stack
        .bonds
        .iter()
        .enumerate()
        .map(|(s, b)| (b.0, s))
        .collect();
    let b_slots: Vec<(usize, usize)> = stack
        .bonds
        .iter()
        .enumerate()
        .map(|(s, b)| (b.1, s))
        .collect();
    let mut out = Vec::new();
    let mut push = |name: String, b_slots: Vec<(usize, usize)>, fa: &Circuit, fb: &Circuit| {
        let (reference, reference_flat) = stack_reference(stack, fa, fb);
        let layout_flat = flat(&stack.a, &stack.b, &drawn_joins(&a_slots, &b_slots));
        out.push(Case {
            name: format!("{label}/{name}"),
            a_slots: a_slots.clone(),
            b_slots,
            reference,
            layout_flat,
            reference_flat,
        });
    };
    push("base".to_owned(), b_slots.clone(), &stack.a, &stack.b);
    for (fault, fa, _) in faults(&stack.a) {
        push(format!("a/{fault}"), b_slots.clone(), &fa, &stack.b);
    }
    for (fault, fb, _) in faults(&stack.b) {
        push(format!("b/{fault}"), b_slots.clone(), &stack.a, &fb);
    }
    for s in 0..b_slots.len() {
        let mut missing = b_slots.clone();
        missing.remove(s);
        push(format!("missing/{s}"), missing, &stack.a, &stack.b);
        if s + 1 < b_slots.len() {
            let mut swapped = b_slots.clone();
            swapped[s].1 = s + 1;
            swapped[s + 1].1 = s;
            push(format!("swapped/{s}"), swapped, &stack.a, &stack.b);
        }
    }
    out
}

/// Stacks of two enumerated circuits of at most two devices each, drawn by
/// `seed`: the first `min(2, nets)` nets of `XA` bonded to distinct nets of
/// `XB`, so the flattened system has at most six nets, seven after a fault,
/// within the oracle's reach.
fn stacks(count: usize, seed: u64) -> Vec<Stack> {
    let small: Vec<Circuit> = circuits()
        .into_iter()
        .filter(|c| c.devs.len() <= 2)
        .collect();
    let mut rng = Rng::new(seed);
    let mut pick = |n: usize| usize::try_from(rng.below(n as u64)).expect("few");
    (0..count)
        .map(|_| {
            let a = small[pick(small.len())].clone();
            let b = small[pick(small.len())].clone();
            let k = a.nets().min(b.nets()).min(2);
            let mut free: Vec<usize> = (0..b.nets()).collect();
            let bonds = (0..k).map(|i| (i, free.remove(pick(free.len())))).collect();
            Stack { a, b, bonds }
        })
        .collect()
}

/// The tool's verdict on one case, with the dies drawn as it says.
fn verdict(case: &Case, stack: &Stack) -> Result<bool, String> {
    let bump = |slots: &[(usize, usize)]| -> Vec<(usize, usize, &str)> {
        slots
            .iter()
            .map(|&(net, slot)| (net, slot, "bump"))
            .collect()
    };
    let dies = [
        die("XA", die_layout(&stack.a, &bump(&case.a_slots))),
        die("XB", die_layout(&stack.b, &bump(&case.b_slots))),
    ];
    let system = system_json(&dies, &[(("XA", "bump"), ("XB", "bump"))], None, None);
    let ran = check_dies(&dies, &system, &case.reference).map_err(|why| why.to_string())?;
    match &ran.outputs.lvs {
        Some(Verdict::Match) => Ok(true),
        Some(Verdict::Mismatch(_)) => Ok(false),
        other => Err(format!("no verdict ({other:?})")),
    }
}

/// Every case of `count` stacks drawn by `seed`, the tool against the oracle;
/// fails listing every disagreement.
fn agree(count: usize, seed: u64) {
    let mut broken = Vec::new();
    let mut matched = 0;
    let mut total = 0;
    for (k, stack) in stacks(count, seed).iter().enumerate() {
        for case in stack_cases(stack, &format!("stack{k}")) {
            let want = equivalent(&case.layout_flat, &case.reference_flat);
            let have = verdict(&case, stack);
            total += 1;
            matched += usize::from(want);
            if have != Ok(want) {
                broken.push(format!(
                    "{}: tool {have:?}, oracle {want} ({stack:?})",
                    case.name
                ));
            }
        }
    }
    assert!(
        broken.is_empty(),
        "{} of {total} cases disagree:\n{}",
        broken.len(),
        broken[..broken.len().min(40)].join("\n")
    );
    assert!(matched > 0 && matched < total, "both verdicts occur");
}

/// Oracle: the brute-force isomorphism of the LVS enumeration
/// ([`equivalent`]) on the flattened system: the test flattens the two
/// circuits through the bumps it drew, and the netlist's two cells through
/// the bonds it wrote, and the tool's verdict on the drawn dies must be the
/// oracle's, on a seeded sample of stacks with every die fault and every
/// missing and swapped bump.
#[test]
fn system_lvs_agrees_with_the_brute_force_oracle_on_the_flattened_system() {
    agree(6, 0x5_7AC6);
}

/// The same at nightly depth: a hundred stacks.
///
/// Oracle: the brute-force isomorphism of the LVS enumeration on the
/// flattened system, as in the merge-depth test, over a hundred stacks.
#[test]
#[ignore = "nightly: a hundred stacks"]
fn system_lvs_agrees_with_the_brute_force_oracle_at_nightly_depth() {
    agree(100, 0x5_7AC7);
}

/// The merge-depth stacks for the Netgen differential: each case's name, the
/// tool's verdict on the drawn dies, and the two flat circuits the oracle
/// read.
pub(super) fn netgen_cases() -> Vec<(String, Result<bool, String>, Circuit, Circuit)> {
    let mut out = Vec::new();
    for (k, stack) in stacks(6, 0x5_7AC6).iter().enumerate() {
        for case in stack_cases(stack, &format!("system/stack{k}")) {
            let ours = verdict(&case, stack);
            out.push((case.name, ours, case.layout_flat, case.reference_flat));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Package, die-to-die and system-level ESD
// ---------------------------------------------------------------------------

/// Both rails of one domain, by the dies' own labels.
const RAILS: &str = r#"{ "domains": { "core": { "voltage_mv": 1800 } },
  "supplies": [ { "net": "vdd", "domain": "core", "role": "power" },
                { "net": "vss", "domain": "core", "role": "ground" } ] }"#;

/// Diodes and the rail clamp guard the die-to-die and package pins; only a
/// bipolar is rated for system-level stress, on the pin `pad`.
const ESD: &str = r#"{ "clamps": ["dpn", "nmos_hvt"], "system_clamps": ["npn"],
  "system_pins": ["pad"] }"#;

/// What a die carries: a diode from its pad net up to power, one down from
/// ground, a system-rated bipolar across both, and a rail clamp.
#[derive(Clone, Copy)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "four independent devices, each there or not"
)]
struct Guard {
    up: bool,
    down: bool,
    bipolar: bool,
    clamp: bool,
}

/// A two-die stack: `XT`'s inverter input `sig` reaches the package pin
/// `pad` of the base die `XB` through bump slot 0, the rails through slots 1
/// and 2; `XB`'s `pad`, `vdd` and `vss` are package bumps (slots 10 to 12).
/// Each die gets its `Guard`'s devices. Returns the dies, the system file and its netlist.
fn esd_stack(top: Guard, base: Guard, esd: &str) -> (Vec<DieSpec>, String, String) {
    use Model::{D, H, N, P, Q};
    let guarded = |mut devs: Vec<Dev>, guard: Guard| {
        if guard.up {
            devs.push(Dev::pins(D, &[0, 1]));
        }
        if guard.down {
            devs.push(Dev::pins(D, &[2, 0]));
        }
        if guard.bipolar {
            devs.push(Dev::pins(Q, &[0, 2, 1]));
        }
        if guard.clamp {
            devs.push(Dev::mos(H, 2, 2, 1));
        }
        devs
    };
    let t = named(
        &["sig", "vdd", "vss", "out"],
        guarded(vec![Dev::mos(N, 0, 2, 3), Dev::mos(P, 0, 1, 3)], top),
    );
    let b = named(&["pad", "vdd", "vss"], guarded(Vec::new(), base));
    let rails = [(0, 0, "bump"), (1, 1, "bump"), (2, 2, "bump")];
    let mut base_bumps = rails.to_vec();
    base_bumps.extend([(0, 10, "c4"), (1, 11, "c4"), (2, 12, "c4")]);
    let with = |name, layout| DieSpec {
        intent: Some(RAILS.to_owned()),
        ..die(name, layout)
    };
    let dies = vec![
        with("XT", die_layout(&t, &rails)),
        with("XB", die_layout(&b, &base_bumps)),
    ];
    let system = system_json(
        &dies,
        &[(("XT", "bump"), ("XB", "bump"))],
        Some(("XB", "c4")),
        Some(esd),
    );
    let reference = system_spice(
        &[("DT", &t), ("DB", &b)],
        &["pad", "vdd", "vss"],
        &[
            ("XT", "DT", strings(&["pad", "vdd", "vss", "tout"])),
            ("XB", "DB", strings(&["pad", "vdd", "vss"])),
        ],
    );
    (dies, system, reference)
}

const FULL: Guard = Guard {
    up: true,
    down: true,
    bipolar: true,
    clamp: true,
};
const BARE: Guard = Guard {
    up: false,
    down: false,
    bipolar: false,
    clamp: false,
};

/// Catalog ERC-C12: package, 2.5D and 3D ESD.
///
/// Oracle: hand-derived from the definitions in `gpurify_check::system`
/// (TR18.0-01 §6.5 and §6.7, JEP196 §3.3 and §6.2). Both dies guarded:
/// every die-to-die bump net of `XT` (3) and of `XB` (3) and every package
/// pin (3) reaches both rails, the netlist matches, and the run passes. `XT`
/// bare but for its rail clamp: its `sig` bump (slot 0) reaches no rail on
/// its own die, though the package pin reaches `XB`'s diodes across the bond.
/// `XB` bare: its nets reach no device on `XB` and are not examined, and the
/// package pin `pad` is protected by `XT`'s diodes across the bond. `XT`
/// with the ground diode and no rail clamp, `XB` bare: nothing joins the
/// rails, so `sig`, `vdd` and `vss` each reach one rail kind, on the die (the
/// bumps in slots 0 to 2) and at the package (slots 10 to 12).
#[test]
fn die_to_die_and_package_pins_need_their_esd_paths() {
    let count = |n| Measurement::Count(n);
    let ran = |top, base| {
        let (dies, system, reference) = esd_stack(top, base, ESD);
        check_dies(&dies, &system, &reference).expect("an assembly")
    };
    let both = ran(FULL, FULL);
    assert!(both.matched());
    assert_eq!(both.rows(), []);
    assert_eq!(both.run_of("system.esd_d2d"), (Outcome::Ran, 6, 0));
    assert_eq!(both.run_of("system.esd_package"), (Outcome::Ran, 3, 0));
    assert!(both.summary.passed());

    let top_bare = ran(
        Guard {
            clamp: true,
            ..BARE
        },
        FULL,
    );
    assert!(top_bare.matched());
    assert_eq!(top_bare.of("system.esd_d2d"), [(slot_centre(0), count(0))]);
    assert_eq!(top_bare.of("system.esd_package"), []);

    let base_bare = ran(FULL, BARE);
    assert!(base_bare.matched());
    assert_eq!(base_bare.of("system.esd_d2d"), []);
    assert_eq!(base_bare.run_of("system.esd_d2d"), (Outcome::Ran, 3, 0));
    assert_eq!(base_bare.of("system.esd_package"), []);

    let one_rail = ran(Guard { down: true, ..BARE }, BARE);
    let ones = |slots: [usize; 3]| slots.map(|s| (slot_centre(s), count(1)));
    assert_eq!(one_rail.of("system.esd_d2d"), ones([0, 1, 2]));
    assert_eq!(one_rail.of("system.esd_package"), ones([10, 11, 12]));

    // No intent on any die: every ESD row is skipped, and the run fails.
    let (mut dies, system, reference) = esd_stack(FULL, FULL, ESD);
    for die in &mut dies {
        die.intent = None;
    }
    let blind = check_dies(&dies, &system, &reference).expect("an assembly");
    for rule in ["system.esd_d2d", "system.esd_package", "system.esd_iec"] {
        assert_eq!(
            blind.run_of(rule),
            (Outcome::Skipped(SkipReason::NoDesignIntent), 0, 0),
            "{rule}"
        );
    }
    assert!(!blind.summary.passed());
}

/// Catalog ERC-C13: system-level ESD, the part a layout shows.
///
/// Oracle: hand-derived from the definition of `system.esd_iec`
/// (WP3 Part I §1.6 and §6.3.1): the pin `pad` the system names must reach
/// both rails through a system-rated clamp (`npn`). With the bipolar on the
/// base die it does; with only diodes on either die it reaches none (the
/// diodes are not rated), a row at the package bump (slot 10) measured 0,
/// though `system.esd_package` passes. A named pin no package bump carries
/// refuses the assembly.
#[test]
fn a_system_pin_needs_a_system_rated_clamp() {
    let ran = |top, base, esd| {
        let (dies, system, reference) = esd_stack(top, base, esd);
        check_dies(&dies, &system, &reference)
    };
    let rated = ran(BARE, FULL, ESD).expect("an assembly");
    assert_eq!(rated.run_of("system.esd_iec"), (Outcome::Ran, 1, 0));
    let diodes = Guard {
        bipolar: false,
        ..FULL
    };
    let unrated = ran(diodes, diodes, ESD).expect("an assembly");
    assert_eq!(
        unrated.of("system.esd_iec"),
        [(slot_centre(10), Measurement::Count(0))]
    );
    assert_eq!(unrated.of("system.esd_package"), []);
    let typo = ran(
        FULL,
        FULL,
        r#"{ "clamps": ["dpn"], "system_clamps": ["npn"], "system_pins": ["usb"] }"#,
    );
    let why = typo.err().expect("refused").to_string();
    assert!(why.contains("system pin usb labels no bump"), "{why}");
}

/// The rail kinds `pad` reaches in `c` through devices of `clamps`, with
/// `supply` bits (1 power, 2 ground) per net: searched here from the
/// definition, over the circuit as drawn.
fn reached(c: &Circuit, supply: &[u8], clamps: &[Model], pad: usize) -> u32 {
    let mut seen = vec![false; c.nets()];
    let mut stack = vec![pad];
    seen[pad] = true;
    let mut bits = 0;
    while let Some(net) = stack.pop() {
        bits |= supply[net];
        if supply[net] == 0 && net != pad {
            continue;
        }
        for dev in c.devs.iter().filter(|d| clamps.contains(&d.model)) {
            if dev.pins.contains(&net) {
                for &next in &dev.pins {
                    if !seen[next] {
                        seen[next] = true;
                        stack.push(next);
                    }
                }
            }
        }
    }
    u32::from(bits & 1) + u32::from(bits >> 1 & 1)
}

/// Rail bits of a circuit whose `n0` is power and `n1` ground.
fn enumerated_rails(c: &Circuit) -> Vec<u8> {
    (0..c.nets())
        .map(|k| [1, 2].get(k).copied().unwrap_or(0))
        .collect()
}

/// Oracle: naive reference. On the merge-depth stacks, every die's `n0` a
/// power and `n1` a ground rail, `nmos` the clamps and `pmos` the
/// system-rated ones, every net of `XA` a package pin and `n0` the system
/// pin: the tool's ESD rows hold exactly the pads a search written here over
/// the circuits as drawn (each die alone for its bonded nets, the flattened
/// stack for the package pins) finds short of both rails, with the measured
/// kinds.
#[test]
fn esd_rows_agree_with_a_search_of_the_circuits() {
    use Model::{N, P};
    let esd = r#"{ "clamps": ["nmos"], "system_clamps": ["pmos"], "system_pins": ["n0"] }"#;
    for (k, stack) in stacks(12, 0xE5D).iter().enumerate() {
        let intent = |c: &Circuit| {
            let mut supplies = vec![r#"{ "net": "n0", "domain": "d", "role": "power" }"#];
            if c.nets() > 1 {
                supplies.push(r#"{ "net": "n1", "domain": "d", "role": "ground" }"#);
            }
            format!(
                r#"{{ "domains": {{ "d": {{ "voltage_mv": 1000 }} }}, "supplies": [{}] }}"#,
                supplies.join(", ")
            )
        };
        let mut a_bumps: Vec<(usize, usize, &str)> = stack
            .bonds
            .iter()
            .enumerate()
            .map(|(s, b)| (b.0, s, "bump"))
            .collect();
        a_bumps.extend((0..stack.a.nets()).map(|net| (net, 10 + net, "c4")));
        let b_bumps: Vec<(usize, usize, &str)> = stack
            .bonds
            .iter()
            .enumerate()
            .map(|(s, b)| (b.1, s, "bump"))
            .collect();
        let dies = [
            DieSpec {
                intent: Some(intent(&stack.a)),
                ..die("XA", die_layout(&stack.a, &a_bumps))
            },
            DieSpec {
                intent: Some(intent(&stack.b)),
                ..die("XB", die_layout(&stack.b, &b_bumps))
            },
        ];
        let system = system_json(
            &dies,
            &[(("XA", "bump"), ("XB", "bump"))],
            Some(("XA", "c4")),
            Some(esd),
        );
        let (reference, _) = stack_reference(stack, &stack.a, &stack.b);
        let ran = check_dies(&dies, &system, &reference).expect("an assembly");

        let short = |rails: u32| (rails < 2).then_some(Measurement::Count(rails));
        // Die to die: each die alone, its bonded nets once each.
        let mut d2d = Vec::new();
        for (c, side) in [(&stack.a, 0), (&stack.b, 1)] {
            let mut pads: Vec<usize> = stack
                .bonds
                .iter()
                .map(|b| if side == 0 { b.0 } else { b.1 })
                .collect();
            pads.sort_unstable();
            pads.dedup();
            let supply = enumerated_rails(c);
            d2d.extend(
                pads.iter()
                    .filter_map(|&p| short(reached(c, &supply, &[N], p))),
            );
        }
        // The package: the stack flattened, rails joined where their nets are.
        let joined = flat(&stack.a, &stack.b, &stack.bonds);
        let mut supply = vec![0u8; joined.nets()];
        let map = flat_nets(stack);
        for (die, c) in [&stack.a, &stack.b].into_iter().enumerate() {
            for (net, bits) in enumerated_rails(c).into_iter().enumerate() {
                supply[map[die][net]] |= bits;
            }
        }
        let mut pins: Vec<usize> = (0..stack.a.nets()).map(|net| map[0][net]).collect();
        pins.sort_unstable();
        pins.dedup();
        let package: Vec<Measurement> = pins
            .iter()
            .filter_map(|&p| short(reached(&joined, &supply, &[N], p)))
            .collect();
        let iec: Vec<Measurement> = short(reached(&joined, &supply, &[P], map[0][0]))
            .into_iter()
            .collect();

        let measured = |rule: &str| {
            let mut m: Vec<Measurement> = ran.of(rule).into_iter().map(|(_, m)| m).collect();
            m.sort_by_key(|m| format!("{m:?}"));
            m
        };
        let sorted = |mut m: Vec<Measurement>| {
            m.sort_by_key(|m| format!("{m:?}"));
            m
        };
        assert_eq!(
            measured("system.esd_d2d"),
            sorted(d2d),
            "stack{k} {stack:?}"
        );
        assert_eq!(
            measured("system.esd_package"),
            sorted(package),
            "stack{k} {stack:?}"
        );
        assert_eq!(measured("system.esd_iec"), iec, "stack{k} {stack:?}");
        assert_eq!(
            ran.run_of("system.esd_package").1,
            pins.len() as u64,
            "stack{k}: every package pin examined"
        );
    }
}

/// Each die's nets as numbered in [`flat`]`(a, b, bonds)`.
fn flat_nets(stack: &Stack) -> [Vec<usize>; 2] {
    let na = stack.a.nets();
    let (class, _) = classes(na, stack.b.nets(), &stack.bonds);
    [class[..na].to_vec(), class[na..].to_vec()]
}
