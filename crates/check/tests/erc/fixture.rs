//! A deck-and-layout fixture run through this crate's own reader path: the
//! deck parsed and compiled, the layout drawn in memory, labels bound, nets
//! and devices extracted, and `erc::check` run, as the engine does it after
//! reading GDSII. The ported fixtures in [`super::ported`] state what each
//! run must report; nothing here states an answer.
//!
//! It mirrors the root crate's `tests/exhaustive/harness.rs` (flat layouts
//! and ERC only), so a fixture moves between the two unchanged but for its
//! `Checks` argument. The point of having it here: `cargo mutants` runs only
//! this crate's tests against this crate's code.

#![allow(
    dead_code,
    reason = "each test binary links only the fixtures it names"
)]

use gpurify_check::deck::CompiledDeck;
use gpurify_check::erc::{self, Process};
use gpurify_check::report::{Measurement, Outcome, RuleRun, Violations};
use gpurify_check::topology::{self, DeviceTable, NetTable, PortTable};
use gpurify_check::Design;
use gpurify_geom::{celsius, Bbox, Grid, LayerId};
use gpurify_ingest::deck::parse_deck;
use gpurify_ingest::layout::derive_layers;
use gpurify_ingest::{Provenance, StrTable};
use gpurify_testgen::{point, LayoutBuilder};

/// How much to generate. Only the merge share runs in this crate; the
/// nightly enumerations stay in the root crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Depth {
    /// Every curated case and a bounded sample of each enumeration.
    Merge,
}

/// A flat layout: polygons and labels on deck layer names, in nanometres.
#[derive(Debug, Clone, Default)]
pub struct Layout {
    /// `(layer, outline)`, counter-clockwise.
    pub shapes: Vec<(String, Vec<(i64, i64)>)>,
    /// `(layer, x, y, text)`: a text label naming the net under it.
    pub labels: Vec<(String, i64, i64, String)>,
}

impl Layout {
    /// Adds an axis-aligned rectangle.
    pub fn rect(mut self, layer: &str, xlo: i64, ylo: i64, xhi: i64, yhi: i64) -> Self {
        assert!(xlo < xhi && ylo < yhi, "{layer}: an empty rectangle");
        self.shapes.push((
            layer.to_owned(),
            vec![(xlo, ylo), (xhi, ylo), (xhi, yhi), (xlo, yhi)],
        ));
        self
    }

    /// Adds a polygon, counter-clockwise.
    pub fn polygon(mut self, layer: &str, points: &[(i64, i64)]) -> Self {
        self.shapes.push((layer.to_owned(), points.to_vec()));
        self
    }

    /// Adds a text label.
    pub fn label(mut self, layer: &str, x: i64, y: i64, text: &str) -> Self {
        self.labels.push((layer.to_owned(), x, y, text.to_owned()));
        self
    }

    /// The layout under one of the eight symmetries of the square, then
    /// translated. Outlines stay counter-clockwise.
    pub fn transformed(&self, symmetry: Symmetry, dx: i64, dy: i64) -> Self {
        let map = |p: (i64, i64)| {
            let (x, y) = symmetry.apply(p);
            (x + dx, y + dy)
        };
        Layout {
            shapes: self
                .shapes
                .iter()
                .map(|(layer, points)| {
                    let mut out: Vec<_> = points.iter().copied().map(map).collect();
                    if symmetry.mirror {
                        out.reverse();
                    }
                    (layer.clone(), out)
                })
                .collect(),
            labels: self
                .labels
                .iter()
                .map(|(layer, x, y, text)| {
                    let (x, y) = map((*x, *y));
                    (layer.clone(), x, y, text.clone())
                })
                .collect(),
        }
    }
}

/// One of the eight symmetries of the square: a quarter-turn count, then an
/// optional mirror in the y axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Symmetry {
    /// Counter-clockwise quarter turns, 0 to 3.
    pub turns: u8,
    /// Mirror x after turning.
    pub mirror: bool,
}

impl Symmetry {
    /// The identity.
    pub const IDENTITY: Symmetry = Symmetry {
        turns: 0,
        mirror: false,
    };

    /// Maps a point.
    pub fn apply(self, (mut x, mut y): (i64, i64)) -> (i64, i64) {
        for _ in 0..self.turns {
            (x, y) = (-y, x);
        }
        if self.mirror {
            x = -x;
        }
        (x, y)
    }
}

/// What a rule's row must say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Want {
    /// `Outcome::Ran`.
    Ran,
    /// `Outcome::Skipped`, for any reason.
    Skipped,
    /// `Outcome::Refused`.
    Refused,
}

/// One finding a rule must report.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Finding {
    /// The measured value, exact for lengths, areas and counts.
    pub measured: Option<Measurement>,
    /// The marker, in nanometres, mapped with the layout.
    pub at: Option<(i64, i64)>,
}

impl Finding {
    /// A finding with nothing pinned but its existence.
    pub fn any() -> Self {
        Finding {
            measured: None,
            at: None,
        }
    }

    /// A finding with a measured area, in square nanometres.
    pub fn area(nm2: i128) -> Self {
        Finding {
            measured: Some(Measurement::Area(gpurify_geom::DbuArea::new(nm2))),
            at: None,
        }
    }

    /// Pins the marker location.
    pub fn at(mut self, x: i64, y: i64) -> Self {
        self.at = Some((x, y));
        self
    }
}

/// One claim about a rule's row: its outcome, exactly these findings in any
/// order, and where the definition fixes it, its examined count.
#[derive(Debug, Clone, PartialEq)]
pub enum Expect {
    /// A rule's row.
    Rule {
        /// The rule id as the deck writes it.
        id: String,
        /// Its outcome.
        outcome: Want,
        /// Exactly these findings.
        findings: Vec<Finding>,
        /// Exactly this many items examined; `None` claims nothing.
        examined: Option<u64>,
    },
}

impl Expect {
    /// A rule that runs and finds exactly `findings`.
    pub fn rule(id: &str, findings: Vec<Finding>) -> Self {
        Expect::Rule {
            id: id.to_owned(),
            outcome: Want::Ran,
            findings,
            examined: None,
        }
    }

    /// A rule that runs and finds nothing.
    pub fn clean(id: &str) -> Self {
        Expect::rule(id, Vec::new())
    }

    /// A rule that records `outcome` and finds nothing.
    pub fn outcome(id: &str, outcome: Want) -> Self {
        Expect::Rule {
            id: id.to_owned(),
            outcome,
            findings: Vec::new(),
            examined: None,
        }
    }

    /// Also claims the row examined exactly `count` items.
    pub fn examined(mut self, count: u64) -> Self {
        let Expect::Rule { examined, .. } = &mut self;
        *examined = Some(count);
        self
    }
}

/// One fixture: an ERC run's inputs and what it must report.
#[derive(Debug, Clone)]
pub struct Fixture {
    /// Unique and path-like.
    pub name: String,
    /// The catalog rows (`docs/check-catalog.tsv`) this fixture proves.
    pub catalog: Vec<&'static str>,
    /// The whole deck.
    pub deck: String,
    /// The layout.
    pub layout: Layout,
    /// Design-intent JSON for the intent-gated rules.
    pub intent: Option<String>,
    /// What the run must report.
    pub expect: Vec<Expect>,
}

impl Fixture {
    /// A fixture with no intent.
    pub fn new(name: &str, catalog: &[&'static str], deck: &str) -> Self {
        Fixture {
            name: name.to_owned(),
            catalog: catalog.to_vec(),
            deck: deck.to_owned(),
            layout: Layout::default(),
            intent: None,
            expect: Vec::new(),
        }
    }

    /// Sets the layout.
    pub fn layout(mut self, layout: Layout) -> Self {
        self.layout = layout;
        self
    }

    /// Adds a claim.
    pub fn expect(mut self, expect: Expect) -> Self {
        self.expect.push(expect);
        self
    }

    /// The fixture under one symmetry and translation; every pinned marker
    /// moves with it. A rule's numbers are invariant under these.
    pub fn transformed(&self, symmetry: Symmetry, dx: i64, dy: i64) -> Self {
        let mut out = self.clone();
        out.name = format!(
            "{}/{}{}+({dx},{dy})",
            self.name,
            if symmetry.mirror { "m" } else { "r" },
            u32::from(symmetry.turns) * 90
        );
        out.layout = self.layout.transformed(symmetry, dx, dy);
        for Expect::Rule { findings, .. } in &mut out.expect {
            for finding in findings {
                if let Some(at) = finding.at {
                    let (x, y) = symmetry.apply(at);
                    finding.at = Some((x + dx, y + dy));
                }
            }
        }
        out
    }
}

/// What a run produced, with names resolved.
pub struct Ran {
    /// Each rule row: `(id, outcome, examined)`.
    pub rows: Vec<(String, Outcome, u64)>,
    /// Each finding: `(rule id, measured, at in nm)`.
    pub findings: Vec<(String, Measurement, (i64, i64))>,
}

/// The die outline layers the engine reads, first match wins.
const DIE_LAYER_NAMES: [&str; 3] = ["prBoundary", "DIEAREA", "die"];

/// Runs a fixture's ERC rows in memory.
///
/// # Errors
///
/// A message naming the stage that refused the inputs.
pub fn run(fixture: &Fixture) -> Result<Ran, String> {
    let grid = Grid::new(1000).expect("a 1 nm grid");
    let mut strings = StrTable::default();
    let deck =
        parse_deck(&fixture.deck, grid, &mut strings).map_err(|why| format!("deck: {why}"))?;
    let layer_of = |strings: &StrTable, name: &str| {
        deck.layers
            .id(strings, name)
            .ok_or_else(|| format!("layout: {name} is not a deck layer"))
    };
    let mut builder = LayoutBuilder::new(deck.layers.len());
    for (layer, points) in &fixture.layout.shapes {
        let id = layer_of(&strings, layer)?;
        let (xs, ys): (Vec<i64>, Vec<i64>) = points.iter().copied().unzip();
        builder.push(id, &xs, &ys);
    }
    let (mut store, _) = builder.finish();
    let mut provenance = Provenance::default();
    for (layer, x, y, text) in &fixture.layout.labels {
        let id = layer_of(&strings, layer)?;
        let name = strings.intern(text);
        provenance.place_label(point(*x, *y), id, name);
    }
    derive_layers(&mut store, &deck, &provenance, &strings).map_err(|why| format!("{why}"))?;
    provenance
        .resolve_labels(&store, &deck.connectivity)
        .map_err(|why| format!("labels: {why}"))?;
    let intent = match &fixture.intent {
        None => None,
        Some(text) => Some(
            gpurify_ingest::intent::parse_intent(text, &mut strings)
                .map_err(|why| format!("intent: {why}"))?,
        ),
    };
    let deck =
        CompiledDeck::from_deck(deck, grid, &strings).map_err(|why| format!("compile: {why}"))?;

    topology::device::refuse_conducting_channels(&store, &deck.connectivity, &deck.devices)
        .map_err(|why| format!("extract: {why}"))?;
    let mut nets = NetTable::default();
    topology::extract_nets_into(&store, &deck.connectivity, &mut nets);
    let mut devices = DeviceTable::default();
    topology::device::recognise_into(&store, &nets, &deck.devices, &mut devices);
    let mut ports = PortTable::default();
    topology::port::bind_ports_into(&nets, &provenance, &mut ports)
        .map_err(|why| format!("extract: {why}"))?;
    if intent.is_some() && ports.shorted_net().is_some() {
        return Err("erc: one net carries two labels".to_owned());
    }

    let declared = DIE_LAYER_NAMES
        .iter()
        .find_map(|name| deck.layers.id(&strings, name))
        .filter(|layer| layer.idx() < store.layer_count())
        .map(|layer| union(store.layer_bboxes(layer)))
        .filter(|outline| !outline.is_empty());
    let die = declared.unwrap_or_else(|| {
        (0..store.layer_count())
            .map(|layer| LayerId(u16::try_from(layer).expect("a LayerId is a u16")))
            .filter(|&layer| !deck.layers.is_derived(layer))
            .fold(Bbox::EMPTY, |die, layer| {
                die.union(union(store.layer_bboxes(layer)))
            })
    });
    let temperature = intent
        .as_ref()
        .and_then(gpurify_ingest::DesignIntent::temperature)
        .or(deck.temperature)
        .unwrap_or_else(|| celsius(85.0));
    let inputs = erc::Inputs {
        antenna_pins: &[],
        strings: &strings,
        design: Design {
            store: &store,
            nets: &nets,
            devices: &devices,
        },
        ports: &ports,
        intent: intent.as_ref(),
        process: Process {
            grid,
            stack: &deck.stack,
            connectivity: &deck.connectivity,
        },
        die,
        temperature,
    };
    let (mut out, mut runs): (Violations, Vec<RuleRun>) = (Violations::default(), Vec::new());
    erc::check(&deck.erc, inputs, &mut out, &mut runs).map_err(|why| format!("erc: {why}"))?;

    let name = |id| strings.resolve(id).to_owned();
    Ok(Ran {
        rows: runs
            .iter()
            .map(|run| (name(run.rule), run.outcome, run.examined))
            .collect(),
        findings: (0..out.len())
            .map(|i| {
                (
                    name(out.rule[i]),
                    out.measured[i],
                    (out.at[i].x.raw(), out.at[i].y.raw()),
                )
            })
            .collect(),
    })
}

fn union(boxes: &[Bbox]) -> Bbox {
    boxes.iter().fold(Bbox::EMPTY, |acc, &b| acc.union(b))
}

/// A measurement as one number, for tolerant comparison.
fn magnitude(m: Measurement) -> f64 {
    #[allow(
        clippy::cast_precision_loss,
        reason = "test magnitudes fit an f64 exactly"
    )]
    match m {
        Measurement::Length(d) => d.raw() as f64,
        Measurement::Area(a) => a.raw() as f64,
        Measurement::Ratio(r) => r,
        Measurement::Count(c) => f64::from(c),
        Measurement::Voltage(q) => q.raw(),
        Measurement::Current(q) => q.raw(),
        Measurement::Resistance(q) => q.raw(),
    }
}

/// Whether two measurements agree: exactly for the integer variants, to a
/// relative 1e-9 for the floating ones.
fn same(a: Measurement, b: Measurement) -> bool {
    match (a, b) {
        (Measurement::Length(_), Measurement::Length(_))
        | (Measurement::Area(_), Measurement::Area(_))
        | (Measurement::Count(_), Measurement::Count(_)) => a == b,
        _ if std::mem::discriminant(&a) == std::mem::discriminant(&b) => {
            let (x, y) = (magnitude(a), magnitude(b));
            (x - y).abs() <= 1e-9 * x.abs().max(y.abs()).max(1e-30)
        }
        _ => false,
    }
}

/// Every claim of `fixture` that its run breaks, or the run's error.
pub fn violations_of(fixture: &Fixture) -> Vec<String> {
    let ran = match run(fixture) {
        Ok(ran) => ran,
        Err(why) => return vec![format!("the run did not complete: {why}")],
    };
    let mut broken = Vec::new();
    for Expect::Rule {
        id,
        outcome,
        findings,
        examined,
    } in &fixture.expect
    {
        let rows: Vec<(Outcome, u64)> = ran
            .rows
            .iter()
            .filter(|(rule, ..)| rule == id)
            .map(|&(_, outcome, examined)| (outcome, examined))
            .collect();
        let &[(got, got_examined)] = rows.as_slice() else {
            broken.push(format!("{id}: {} rows", rows.len()));
            continue;
        };
        if !matches!(
            (outcome, got),
            (Want::Ran, Outcome::Ran)
                | (Want::Skipped, Outcome::Skipped(_))
                | (Want::Refused, Outcome::Refused)
        ) {
            broken.push(format!("{id}: outcome {got:?}, want {outcome:?}"));
        }
        if let Some(want) = examined.filter(|&want| want != got_examined) {
            broken.push(format!("{id}: examined {got_examined}, want {want}"));
        }
        let mut actual: Vec<(Measurement, (i64, i64))> = ran
            .findings
            .iter()
            .filter(|(rule, ..)| rule == id)
            .map(|(_, measured, at)| (*measured, *at))
            .collect();
        if actual.len() != findings.len() {
            broken.push(format!(
                "{id}: {} findings, want {}: {actual:?}",
                actual.len(),
                findings.len(),
            ));
            continue;
        }
        // Greedy one-to-one pairing; findings are few per rule.
        for want in findings {
            let found = actual.iter().position(|(measured, at)| {
                want.measured.is_none_or(|m| same(m, *measured)) && want.at.is_none_or(|p| p == *at)
            });
            match found {
                Some(index) => {
                    actual.swap_remove(index);
                }
                None => broken.push(format!("{id}: no finding {want:?} among {actual:?}")),
            }
        }
    }
    broken
}

/// Runs every fixture, panicking with every broken claim.
///
/// # Panics
///
/// When any fixture breaks a claim, or two share a name.
pub fn check_all(fixtures: &[Fixture]) {
    let mut names: Vec<&str> = fixtures.iter().map(|f| f.name.as_str()).collect();
    names.sort_unstable();
    let before = names.len();
    names.dedup();
    assert_eq!(names.len(), before, "fixture names are unique");
    let failures: Vec<String> = fixtures
        .iter()
        .filter_map(|fixture| {
            let broken = violations_of(fixture);
            (!broken.is_empty()).then(|| format!("{}: {}", fixture.name, broken.join("; ")))
        })
        .collect();
    assert!(
        failures.is_empty(),
        "{} of {} fixtures broke a claim:\n{}",
        failures.len(),
        fixtures.len(),
        failures.join("\n")
    );
}
