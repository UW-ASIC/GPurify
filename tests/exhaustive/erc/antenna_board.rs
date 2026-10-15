//! Seeded antenna boards for the differentials against `KLayout` and
//! `OpenROAD` (ledger O1): gates on poly, each contacted once to its own met1
//! stub; met1 bars join runs of adjacent gates, met2 bars join runs and met3
//! bars join met2 groups, through risers and single cuts; a gate may carry a
//! protection diode (diffusion contacted to its stub).
//!
//! Every shape is a rectangle on a 10 nm lattice in [`super::ANTENNA_PROCESS`].
//! The construction keeps the three tools' conventions apart from the
//! answer: shapes of one layer and one net always overlap with positive area
//! where they meet (never a corner or an edge alone), so no layer encloses a
//! hole (a bar meets every other shape of its run, and any three shapes that
//! meet pairwise share a point), and every cut lies wholly inside one shape
//! of each conductor it joins. Shapes of different nets stay at least 300 nm
//! apart.
//!
//! The board knows each gate's net at every etch stage by construction
//! ([`Board::group`]): the `OpenROAD` differential needs it, because its
//! report names gates but not nets.

use super::{antenna_deck, rect, Rect};
use crate::harness::Layout;
use gpurify_testgen::Rng;

/// The limit of every row of [`ROWS`]: far below any ratio a board draws
/// (the least is a 0.04 µm² cut on a 1 µm² gate), so `GPurify` reports every
/// gate with collecting area on its net, with the ratio it measured.
pub(super) const LIMIT: f64 = 1e-6;

/// The sidewall thickness of the `psr`/`csr` rows, nm: 0.35 µm, as `OpenROAD`
/// reads the LEF `THICKNESS`.
pub(super) const THICKNESS: i64 = 350;

/// The etch stage a row's ratio is taken at, by the conductor etched last.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Stage {
    /// Diffusion and poly: a gate's net is its own poly.
    Poly,
    /// met1 and the contacts under it: the gates of one met1 run.
    Met1,
    /// met2 and via1.
    Met2,
    /// met3 and via2.
    Met3,
}

/// Which kind of row, and with what parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Profile {
    /// `antenna` at [`LIMIT`].
    Plain,
    /// `antenna_electrical` with LEF's every diode term ([`H5`]) at
    /// [`LIMIT`]: every gate reported with its value.
    H5,
    /// The same at [`H5_MAX`], with [`H5_DIODE_MAX`] for a gate with a
    /// diode: the verdicts.
    H5Limited,
}

/// The `antenna_electrical` parameters of the [`Profile::H5`] rows: a cut
/// area factor, `area_minus_diode`, `gate_plus_diode`, and the
/// `diode_reduce` table as `(nm², factor)`. Small enough that no layer's
/// partial ratio goes negative, so the truncation at zero never applies.
pub(super) const H5: (f64, f64, f64, [(i64, f64); 3]) = (
    2.5,
    0.1,
    3.0,
    [(0, 1.0), (300_000, 0.6), (100_000_000, 0.6)],
);

/// The [`Profile::H5Limited`] rows' `max_ratio`.
pub(super) const H5_MAX: f64 = 5.0;

/// The [`Profile::H5Limited`] rows' `diode_max_ratio`, `(nm², limit)`.
pub(super) const H5_DIODE_MAX: [(i64, f64); 3] = [(0, 1.0), (600_000, 40.0), (100_000_000, 40.0)];

/// One row of the board deck: its id, collectors, sidewall and diode, and
/// the finest stage among its collectors' (the gates it groups).
pub(super) struct BoardRow {
    /// The rule id.
    pub id: &'static str,
    /// The deck's collector list.
    pub collectors: &'static str,
    /// Sidewall instead of area.
    pub sidewall: bool,
    /// The row skips a gate whose net reaches diffusion (`diode: diff`).
    pub diode: bool,
    /// Gates on one net at this stage share the row's ratio.
    pub grouped_at: Stage,
    /// The kind of row.
    pub profile: Profile,
}

const fn row(
    id: &'static str,
    collectors: &'static str,
    sidewall: bool,
    diode: bool,
    grouped_at: Stage,
) -> BoardRow {
    BoardRow {
        id,
        collectors,
        sidewall,
        diode,
        grouped_at,
        profile: Profile::Plain,
    }
}

const fn h5(
    id: &'static str,
    collectors: &'static str,
    grouped_at: Stage,
    profile: Profile,
) -> BoardRow {
    BoardRow {
        id,
        collectors,
        sidewall: false,
        diode: true,
        grouped_at,
        profile,
    }
}

/// Every row a board is run with: each layer's own ratio (LEF PAR/PSR), the
/// cumulative ratios over the metals and over the cuts (CAR/CSR, IHP
/// `AreaRatio`), and the metals with the diffusion as a protection diode.
pub(super) const ROWS: [BoardRow; 27] = [
    row("par.poly", "poly", false, false, Stage::Poly),
    row("par.cont", "cont", false, false, Stage::Poly),
    row("par.met1", "met1", false, false, Stage::Met1),
    row("par.via1", "via1", false, false, Stage::Met1),
    row("par.met2", "met2", false, false, Stage::Met2),
    row("par.via2", "via2", false, false, Stage::Met2),
    row("par.met3", "met3", false, false, Stage::Met3),
    row("psr.met1", "met1", true, false, Stage::Met1),
    row("psr.met2", "met2", true, false, Stage::Met2),
    row("psr.met3", "met3", true, false, Stage::Met3),
    row("car.met", "met1, met2, met3", false, false, Stage::Met1),
    row("car.via", "cont, via1, via2", false, false, Stage::Poly),
    row("csr.met", "met1, met2, met3", true, false, Stage::Met1),
    row("dio.met1", "met1", false, true, Stage::Met1),
    row("dio.met2", "met2", false, true, Stage::Met2),
    row("dio.met3", "met3", false, true, Stage::Met3),
    h5("h5.cont", "cont", Stage::Poly, Profile::H5),
    h5("h5.met1", "met1", Stage::Met1, Profile::H5),
    h5("h5.via1", "via1", Stage::Met1, Profile::H5),
    h5("h5.met2", "met2", Stage::Met2, Profile::H5),
    h5("h5.via2", "via2", Stage::Met2, Profile::H5),
    h5("h5.met3", "met3", Stage::Met3, Profile::H5),
    h5("h5car.met", "met1, met2, met3", Stage::Met1, Profile::H5),
    h5("h5car.via", "cont, via1, via2", Stage::Poly, Profile::H5),
    h5("h5lim.met1", "met1", Stage::Met1, Profile::H5Limited),
    h5("h5lim.met2", "met2", Stage::Met2, Profile::H5Limited),
    h5("h5lim.met3", "met3", Stage::Met3, Profile::H5Limited),
];

/// A table as the deck writes it: `[(a nm2, v), ..]`.
fn table(points: &[(i64, f64)]) -> String {
    let p: Vec<String> = points
        .iter()
        .map(|(a, v)| format!("({a}nm2, {v})"))
        .collect();
    format!("[{}]", p.join(", "))
}

/// The board deck: [`super::ANTENNA_PROCESS`] and [`rows`].
pub(super) fn deck() -> String {
    antenna_deck(&rows())
}

/// Every row of [`ROWS`] at [`LIMIT`], as deck lines.
pub(super) fn rows() -> String {
    let rows: Vec<String> = ROWS
        .iter()
        .map(|r| {
            let sidewall = if r.sidewall {
                format!("{THICKNESS}nm")
            } else {
                "none".to_owned()
            };
            let diode = if r.diode { "diff" } else { "none" };
            let (cut, minus, plus, reduce) = H5;
            let (max, diode_max) = match r.profile {
                Profile::Plain => {
                    return format!(
                        "rule {} antenna(gate, {}; max_ratio: {LIMIT}, sidewall: {sidewall}, diode: {diode}, diode_area: none, diode_min: none)",
                        r.id, r.collectors
                    )
                }
                Profile::H5 => (LIMIT, "none".to_owned()),
                Profile::H5Limited => (H5_MAX, table(&H5_DIODE_MAX)),
            };
            format!(
                "rule {} antenna_electrical(gate, {}; max_ratio: {max}, sidewall: none, \
                 cut_factor: {cut}, diode: diff, diode_credit: 0, diode_bonus: 0, \
                 area_minus_diode: {minus}, gate_plus_diode: {plus}, diode_reduce: {}, \
                 diode_max_ratio: {diode_max}, exempt: none)",
                r.id,
                r.collectors,
                table(&reduce)
            )
        })
        .collect();
    rows.join("\n")
}

/// One gate: its marker, the poly under it, its one contact, and its diode.
pub(super) struct Gate {
    /// The gate marker, inside its poly.
    pub marker: Rect,
    /// The gate's poly line.
    pub poly: Rect,
    /// The contact from the poly to the gate's met1 stub.
    pub cont: Rect,
    /// The diode on the stub: its diffusion and its contact.
    pub diode: Option<(Rect, Rect)>,
    /// The met1 run the gate is on.
    pub run: usize,
}

/// A seeded board: its gates, the metal tree over them, and every metal and
/// cut shape.
pub(super) struct Board {
    /// The seed it was drawn from.
    pub seed: u64,
    /// The gates, left to right; drawing order is index order.
    pub gates: Vec<Gate>,
    /// Per met1 run: the met2 group it is lifted into, if any.
    pub run_group: Vec<Option<usize>>,
    /// Per met2 group: the met3 group it is lifted into, if any.
    pub group_top: Vec<Option<usize>>,
    /// Every metal and via shape: `(layer, rectangle)`, layer one of met1,
    /// via1, met2, via2, met3.
    pub wires: Vec<(&'static str, Rect)>,
}

/// The board's origin, nm: everything lies at positive coordinates.
const ORIGIN: i64 = 2000;
/// Gate pitch, nm.
const PITCH: i64 = 4000;

/// A multiple of 10 in `lo..=hi`.
fn step(rng: &mut Rng, lo: i64, hi: i64) -> i64 {
    lo + 10 * rng.range(0, (hi - lo) / 10 + 1)
}

/// `true` with probability one half.
fn coin(rng: &mut Rng) -> bool {
    rng.below(2) == 1
}

/// Consecutive runs of `0..n`, each cut after an element with probability
/// one half: the run index of each element.
fn runs(rng: &mut Rng, n: usize) -> Vec<usize> {
    let mut out = Vec::with_capacity(n);
    let mut run = 0;
    for i in 0..n {
        if i > 0 && coin(rng) {
            run += 1;
        }
        out.push(run);
    }
    out
}

impl Board {
    /// The board drawn from `seed`: one to five gates.
    pub fn random(seed: u64) -> Board {
        let mut rng = Rng::new(seed);
        let n = 1 + usize::try_from(rng.below(5)).expect("small");
        let run_of = runs(&mut rng, n);
        let mut gates = Vec::with_capacity(n);
        let mut wires = Vec::new();
        // Per gate: the stub's left and right reach past the contact.
        let mut reach = Vec::with_capacity(n);
        for (g, &run) in run_of.iter().enumerate() {
            let x = ORIGIN + PITCH * i64::try_from(g).expect("small");
            let y = ORIGIN;
            let (w, h) = (step(&mut rng, 200, 1000), step(&mut rng, 200, 1000));
            let (a, b) = (step(&mut rng, 0, 1000), step(&mut rng, 600, 1000));
            wires.push(("met1", (x - a, y + 1600, x + 200 + b, y + 2100)));
            reach.push((x - a, x + 200 + b));
            let diode = (rng.below(4) == 0).then(|| {
                wires.push(("met1", (x + 200, y + 1650, x + 2000, y + 2050)));
                (
                    (x + 1450, y + 1700, x + 1950, y + 2000),
                    (x + 1600, y + 1750, x + 1800, y + 1950),
                )
            });
            gates.push(Gate {
                marker: (x, y, x + w, y + h),
                poly: (x, y, x + w, y + 2000),
                cont: (x, y + 1700, x + 200, y + 1900),
                diode,
                run,
            });
        }
        let x_of = |g: usize| ORIGIN + PITCH * i64::try_from(g).expect("small");
        let run_count = run_of.last().map_or(0, |r| r + 1);
        // The first and last gate of each run.
        let span = |run: usize| {
            let first = run_of.iter().position(|&r| r == run).expect("a run");
            let last = run_of.iter().rposition(|&r| r == run).expect("a run");
            (first, last)
        };
        for run in 0..run_count {
            let (first, last) = span(run);
            if first != last {
                let (hb, t) = (step(&mut rng, 200, 800), step(&mut rng, 0, 1500));
                let y = ORIGIN + 2000;
                wires.push(("met1", (reach[first].0, y, reach[last].1 + t, y + hb)));
            }
        }
        // met2: runs grouped; a group of several runs always gets a bar, a
        // lone run half the time. Each member is lifted at its first gate.
        let mut run_group = vec![None; run_count];
        let group_of = runs(&mut rng, run_count);
        let mut lifted = 0;
        for group in 0..group_of.last().map_or(0, |g| g + 1) {
            let members: Vec<usize> = (0..run_count).filter(|&r| group_of[r] == group).collect();
            if members.len() < 2 && !coin(&mut rng) {
                continue;
            }
            let y = ORIGIN;
            for &r in &members {
                run_group[r] = Some(lifted);
                let x = x_of(span(r).0);
                wires.push(("met1", (x + 300, y + 1800, x + 700, y + 3400)));
                wires.push(("via1", (x + 400, y + 3100, x + 600, y + 3300)));
            }
            let (h2, t2) = (step(&mut rng, 400, 1000), step(&mut rng, 0, 1500));
            let (lo, hi) = (
                x_of(span(members[0]).0),
                x_of(span(*members.last().expect("a member")).0),
            );
            wires.push(("met2", (lo + 300, y + 3000, hi + 700 + t2, y + 3000 + h2)));
            lifted += 1;
        }
        // met3: met2 groups grouped the same way, each lifted at the first
        // gate of its first run.
        let mut group_top = vec![None; lifted];
        let first_gate = |group: usize| {
            let run = run_group
                .iter()
                .position(|&g| g == Some(group))
                .expect("a lifted run");
            span(run).0
        };
        let top_of = runs(&mut rng, lifted);
        let mut tops = 0;
        for top in 0..top_of.last().map_or(0, |t| t + 1) {
            let members: Vec<usize> = (0..lifted).filter(|&m| top_of[m] == top).collect();
            if members.len() < 2 && !coin(&mut rng) {
                continue;
            }
            let y = ORIGIN;
            for &m in &members {
                group_top[m] = Some(tops);
                let x = x_of(first_gate(m));
                wires.push(("met2", (x + 300, y + 3000, x + 700, y + 4400)));
                wires.push(("via2", (x + 400, y + 4100, x + 600, y + 4300)));
            }
            let (h3, t3) = (step(&mut rng, 400, 1000), step(&mut rng, 0, 1500));
            let (lo, hi) = (
                x_of(first_gate(members[0])),
                x_of(first_gate(*members.last().expect("a member"))),
            );
            wires.push(("met3", (lo + 300, y + 4000, hi + 700 + t3, y + 4000 + h3)));
            tops += 1;
        }
        Board {
            seed,
            gates,
            run_group,
            group_top,
            wires,
        }
    }

    /// The board as a layout on [`super::ANTENNA_PROCESS`]'s layers, gates
    /// drawn first in index order.
    pub fn layout(&self) -> Layout {
        let mut l = Layout::default();
        for g in &self.gates {
            rect(&mut l, "gate", g.marker);
        }
        for g in &self.gates {
            rect(&mut l, "poly", g.poly);
            rect(&mut l, "cont", g.cont);
            if let Some((diff, cont)) = g.diode {
                rect(&mut l, "diff", diff);
                rect(&mut l, "cont", cont);
            }
        }
        for &(layer, r) in &self.wires {
            rect(&mut l, layer, r);
        }
        l
    }

    /// Which gates share a net with gate `g` when `stage` is etched, as a key
    /// equal for exactly those gates: its own index at the poly stage, then
    /// its met1 run, then the met2 group it is lifted into (its run if none),
    /// then the met3 group (its met2 group, or its run, if none).
    pub fn group(&self, g: usize, stage: Stage) -> (u8, usize) {
        let run = self.gates[g].run;
        let lifted = self.run_group[run];
        match (stage, lifted, lifted.and_then(|m| self.group_top[m])) {
            (Stage::Poly, ..) => (0, g),
            (Stage::Met1, ..) | (Stage::Met2 | Stage::Met3, None, _) => (1, run),
            (Stage::Met2, Some(m), _) | (Stage::Met3, Some(m), None) => (2, m),
            (Stage::Met3, Some(_), Some(t)) => (3, t),
        }
    }
}

/// `GPurify`'s violations of one row: `(ratio, at)` each.
pub(super) type Findings = Vec<(f64, (i64, i64))>;

/// A rectangle's area, nm².
pub(super) fn area((xlo, ylo, xhi, yhi): Rect) -> i64 {
    (xhi - xlo) * (yhi - ylo)
}

/// Whether `(x, y)` lies in the closed rectangle.
pub(super) fn contains((xlo, ylo, xhi, yhi): Rect, (x, y): (i64, i64)) -> bool {
    (xlo..=xhi).contains(&x) && (ylo..=yhi).contains(&y)
}
