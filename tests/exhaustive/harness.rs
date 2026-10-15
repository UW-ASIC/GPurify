#![allow(
    dead_code,
    reason = "a shared harness: each domain module uses its own subset"
)]

//! The fixture type, the run, and the comparison every domain module shares.
//!
//! A [`Fixture`] is everything one run needs and everything it must produce:
//! a deck, a layout drawn in nanometres, an optional reference netlist and
//! design intent, the catalog rows it proves, and what the run must report.
//! The expectation is derived from the rule's definition (the deck language,
//! the rustdoc, the foundry rule), never from a run of `GPurify`: a fixture whose
//! expectation was copied from the tool proves nothing.
//!
//! Each fixture runs in memory through the real reader: the layout is written
//! as GDSII and read back, the deck parsed, nets and devices extracted, and the
//! selected checks run, exactly as the CLI does it.

use gpurify::check::lvs::{CompareOptions, Verdict};
use gpurify::check::report::{Measurement, Outcome};
use gpurify::engine::pipeline::{extract, intern_report_ids, Extracted, Loaded};
use gpurify::engine::run::{run_checks, Checks, Outputs, RunOptions, Summary};
use gpurify::extract::Parasitic;
use gpurify::geom::{Dbu, Grid, LayerId};
use gpurify_ingest::deck::{parse_deck, Deck};
use gpurify_ingest::layout::{gds, UnknownLayers};
use gpurify_ingest::StrTable;
use gpurify_testgen::gds::{write_library, write_store_labelled, Label, Placement, Structure};
use gpurify_testgen::LayoutBuilder;

/// The grid every fixture is drawn on: 1 nm, the GDS writer's `UNITS`.
pub const NM: i64 = 1;

/// How much to generate: the merge gate's share, or the nightly's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Depth {
    /// Every curated case and a bounded sample of each enumeration.
    Merge,
    /// Every enumeration in full (`cargo test -- --ignored`).
    Nightly,
}

/// A layout: polygons and labels on deck layer names, in nanometres.
#[derive(Debug, Clone, Default)]
pub struct Layout {
    /// `(layer, outline)`, counter-clockwise, at least three vertices.
    pub shapes: Vec<(String, Vec<(i64, i64)>)>,
    /// `(layer, x, y, text)`: a text label naming the net under it.
    pub labels: Vec<(String, i64, i64, String)>,
    /// Placements in this layout's frame: `(cell, orientation, dx, dy)`, the
    /// cell's points mapped by the orientation, then moved.
    pub instances: Vec<(String, Symmetry, i64, i64)>,
    /// The cells `instances` name, each in its own frame, with the cells
    /// their own instances name. A layout with neither is written as one
    /// flat cell; with them, as a GDS hierarchy under `TOP`.
    pub cells: Vec<(String, Layout)>,
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

    /// Defines a cell this layout, or a cell below it, may place.
    pub fn cell(mut self, name: &str, layout: Layout) -> Self {
        self.cells.push((name.to_owned(), layout));
        self
    }

    /// Places a cell: its points under `orientation`, then moved by `(dx, dy)`.
    pub fn place(mut self, cell: &str, orientation: Symmetry, dx: i64, dy: i64) -> Self {
        self.instances.push((cell.to_owned(), orientation, dx, dy));
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
                    if symmetry.mirrors() {
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
            // Each placement composes with the transform; a cell's own
            // frame is untouched.
            instances: self
                .instances
                .iter()
                .map(|(cell, orientation, x, y)| {
                    let (x, y) = map((*x, *y));
                    (cell.clone(), orientation.then(symmetry), x, y)
                })
                .collect(),
            cells: self.cells.clone(),
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
    /// All eight, identity first.
    pub const ALL: [Symmetry; 8] = [
        Symmetry {
            turns: 0,
            mirror: false,
        },
        Symmetry {
            turns: 1,
            mirror: false,
        },
        Symmetry {
            turns: 2,
            mirror: false,
        },
        Symmetry {
            turns: 3,
            mirror: false,
        },
        Symmetry {
            turns: 0,
            mirror: true,
        },
        Symmetry {
            turns: 1,
            mirror: true,
        },
        Symmetry {
            turns: 2,
            mirror: true,
        },
        Symmetry {
            turns: 3,
            mirror: true,
        },
    ];

    /// The identity.
    pub const IDENTITY: Symmetry = Symmetry::ALL[0];

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

    /// Whether it reverses orientation.
    pub fn mirrors(self) -> bool {
        self.mirror
    }

    /// `self`, then `outer`: the one of the eight that maps both unit
    /// vectors as the two in turn do.
    pub fn then(self, outer: Symmetry) -> Symmetry {
        let both = |p| outer.apply(self.apply(p));
        *Symmetry::ALL
            .iter()
            .find(|s| s.apply((1, 0)) == both((1, 0)) && s.apply((0, 1)) == both((0, 1)))
            .expect("the eight symmetries are closed under composition")
    }

    /// As a GDS placement: `STRANS` reflects about the x axis before the
    /// quarter turns. A mirror in y after `t` turns is the reflection
    /// followed by `2 - t` turns, since `x → -x` is a half turn after
    /// `y → -y`, and a reflection reverses the turns it passes.
    pub fn gds(self) -> (bool, u8) {
        if self.mirror {
            (true, (6 - self.turns) % 4)
        } else {
            (false, self.turns)
        }
    }

    /// A short name for fixture names: `r0`, `r90`, `m180`, ...
    pub fn name(self) -> String {
        format!(
            "{}{}",
            if self.mirror { "m" } else { "r" },
            u32::from(self.turns) * 90
        )
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
    /// The marker, in nanometres, mapped with the layout when a fixture is
    /// transformed.
    pub at: Option<(i64, i64)>,
}

impl Finding {
    /// A finding with a measured length.
    pub fn length(nm: i64) -> Self {
        Finding {
            measured: Some(Measurement::Length(Dbu::new_unchecked(nm))),
            at: None,
        }
    }

    /// A finding with a measured area, in square nanometres.
    pub fn area(nm2: i128) -> Self {
        Finding {
            measured: Some(Measurement::Area(gpurify::geom::DbuArea::new(nm2))),
            at: None,
        }
    }

    /// A finding with nothing pinned but its existence.
    pub fn any() -> Self {
        Finding {
            measured: None,
            at: None,
        }
    }

    /// Pins the marker location.
    pub fn at(mut self, x: i64, y: i64) -> Self {
        self.at = Some((x, y));
        self
    }
}

/// A parasitic quantity of one net.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quantity {
    /// The sum of the net's resistance elements, in ohms.
    Resistance,
    /// The sum of the net's capacitance to ground, in femtofarads.
    GroundCap,
    /// The sum of the net's inductance elements, in picohenries.
    Inductance,
    /// The sum of the mutual inductances between the net and another, in
    /// picohenries: every mutual element on either of its ends.
    Mutual,
}

/// One claim about the run.
#[derive(Debug, Clone, PartialEq)]
pub enum Expect {
    /// A rule's row: its outcome, and exactly these findings (in any order).
    Rule {
        /// The rule id as the deck writes it.
        id: String,
        /// Its outcome.
        outcome: Want,
        /// Exactly these findings.
        findings: Vec<Finding>,
        /// Exactly this many items examined (`RuleRun::examined`), where the
        /// fixture's definition fixes the count: a clean row from a rule that
        /// examined nothing is not a clean layout. `None` claims nothing.
        examined: Option<u64>,
    },
    /// The LVS verdict: matched, or not.
    Lvs(bool),
    /// A parasitic total on a named net, within a relative tolerance.
    Parasitic {
        /// The net's label.
        net: String,
        /// What is summed.
        quantity: Quantity,
        /// The expected total.
        value: f64,
        /// Relative tolerance.
        rel: f64,
    },
    /// Whether the whole run passes.
    Passes(bool),
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

    /// This rule claim, also claiming the row examined exactly `count`
    /// items. A symmetry or translation keeps the count, so
    /// [`Fixture::transformed`] leaves it.
    ///
    /// # Panics
    ///
    /// On a claim that is not [`Expect::Rule`]: only a rule row examines.
    pub fn examined(mut self, count: u64) -> Self {
        match &mut self {
            Expect::Rule { examined, .. } => *examined = Some(count),
            other => panic!("only a rule row has an examined count, not {other:?}"),
        }
        self
    }
}

/// One fixture: a run's inputs and what it must report.
#[derive(Debug, Clone)]
pub struct Fixture {
    /// Unique and path-like: `min_width/l_shape/below/r90`.
    pub name: String,
    /// The catalog rows (`docs/check-catalog.tsv`) this fixture proves.
    pub catalog: Vec<&'static str>,
    /// The whole deck.
    pub deck: String,
    /// The layout.
    pub layout: Layout,
    /// SPICE text for LVS.
    pub reference: Option<String>,
    /// Structural Verilog files read over `reference` as its cell library
    /// (`engine::pipeline::read_references`); empty for none.
    pub verilog: Vec<String>,
    /// Design-intent JSON for the intent-gated ERC rules.
    pub intent: Option<String>,
    /// Nets to field-solve.
    pub quasistatic: Vec<String>,
    /// The checks to run.
    pub checks: Checks,
    /// What the run must report.
    pub expect: Vec<Expect>,
    /// A finding (`"F18"`) that makes this fixture fail today. It must fail;
    /// one that holds is reported, so a fix is recorded rather than unnoticed.
    pub known: Option<&'static str>,
}

/// No checks.
pub const NONE: Checks = Checks {
    drc: false,
    erc: false,
    lvs: false,
    pex: false,
};

/// DRC alone.
pub const DRC: Checks = Checks { drc: true, ..NONE };

impl Fixture {
    /// A fixture with no reference, intent or field solve.
    pub fn new(name: &str, catalog: &[&'static str], deck: &str, checks: Checks) -> Self {
        Fixture {
            name: name.to_owned(),
            catalog: catalog.to_vec(),
            deck: deck.to_owned(),
            layout: Layout::default(),
            reference: None,
            verilog: Vec::new(),
            intent: None,
            quasistatic: Vec::new(),
            checks,
            expect: Vec::new(),
            known: None,
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

    /// Marks the fixture as failing today because of `finding`.
    pub fn known(mut self, finding: &'static str) -> Self {
        self.known = Some(finding);
        self
    }

    /// The fixture under one symmetry and translation; every pinned marker
    /// moves with it. A rule's numbers are invariant under these, so the rest of
    /// the expectation is unchanged.
    pub fn transformed(&self, symmetry: Symmetry, dx: i64, dy: i64) -> Self {
        let mut out = self.clone();
        out.name = format!("{}/{}{}", self.name, symmetry.name(), offset_name(dx, dy));
        out.layout = self.layout.transformed(symmetry, dx, dy);
        for expect in &mut out.expect {
            if let Expect::Rule { findings, .. } = expect {
                for finding in findings {
                    if let Some(at) = finding.at {
                        let (x, y) = symmetry.apply(at);
                        finding.at = Some((x + dx, y + dy));
                    }
                }
            }
        }
        out
    }

    /// The fixture under all eight symmetries, each also translated by
    /// `(dx, dy)`.
    pub fn every_symmetry(&self, dx: i64, dy: i64) -> Vec<Self> {
        Symmetry::ALL
            .iter()
            .map(|&symmetry| self.transformed(symmetry, dx, dy))
            .collect()
    }
}

fn offset_name(dx: i64, dy: i64) -> String {
    if dx == 0 && dy == 0 {
        String::new()
    } else {
        format!("+({dx},{dy})")
    }
}

/// What a run produced, with names resolved.
pub struct Ran {
    /// Each rule row: `(id, outcome, examined)`.
    pub rows: Vec<(String, Outcome, u64)>,
    /// Each finding: `(rule id, measured, at in nm)`.
    pub findings: Vec<(String, Measurement, (i64, i64))>,
    /// The LVS verdict, if LVS ran to one.
    pub lvs: Option<Verdict>,
    /// The parasitic network, if PEX ran.
    pub outputs: Outputs,
    /// The pass verdict.
    pub summary: Summary,
    /// The run's loaded inputs, for name lookups.
    pub loaded: Loaded,
    /// Nets, devices and ports, for parasitic claims by net label.
    pub extracted: Extracted,
}

/// Runs a fixture through the real reader and engine, in memory.
///
/// # Errors
///
/// A message naming the stage that refused the inputs: a deck that does not
/// parse, a layout the reader refuses, a netlist or intent that does not read,
/// or a run that errors. Some fixtures expect exactly that, through
/// [`Expect::Passes`]` (false)` and a stage refusal.
pub fn run(fixture: &Fixture) -> Result<Ran, String> {
    let (bytes, deck, mut strings) = written(fixture)?;
    let grid = Grid::new(1000).expect("a 1 nm grid");
    let library =
        gds::Library::parse(&bytes, &mut strings).map_err(|why| format!("gds read: {why}"))?;
    let (store, mut provenance) = library
        .flatten(&deck, &strings, UnknownLayers::Reject)
        .map_err(|why| format!("flatten: {why}"))?;
    let boxes = library
        .black_boxes(&deck.lvs.blackbox, &deck, &strings)
        .map_err(|why| format!("black boxes: {why}"))?;
    provenance.set_black_boxes(boxes);
    provenance
        .resolve_labels(&store, &deck.connectivity)
        .map_err(|why| format!("labels: {why}"))?;
    let reference = match &fixture.reference {
        None => None,
        Some(text) => {
            // SPICE or Spectre, picked as the pipeline picks it, and any
            // Verilog over it.
            let verilog: Vec<&str> = fixture.verilog.iter().map(String::as_str).collect();
            let (netlist, top) = gpurify::engine::pipeline::read_references(
                Some((text, false)),
                &verilog,
                &deck.devices,
                &mut strings,
            )
            .map_err(|why| format!("reference: {why}"))?;
            // As `engine::pipeline::load` does: LVS compares the flattened top.
            Some(match top {
                Some(top) => netlist
                    .flatten_top_with(top, &deck.lvs.blackbox, &mut strings)
                    .map_err(|why| format!("reference: {why}"))?,
                None => netlist,
            })
        }
    };
    let intent = match &fixture.intent {
        None => None,
        Some(text) => Some(
            gpurify_ingest::intent::parse_intent(text, &mut strings)
                .map_err(|why| format!("intent: {why}"))?,
        ),
    };
    intern_report_ids(&mut strings);
    let deck = gpurify::deck::CompiledDeck::from_deck(deck, grid, &strings)
        .map_err(|why| format!("compile: {why}"))?;
    let loaded = Loaded {
        strings,
        grid,
        deck,
        store,
        provenance,
        reference,
        intent,
        design: None,
    };
    let extracted = extract(&loaded).map_err(|why| format!("extract: {why}"))?;
    let options = RunOptions {
        checks: fixture.checks,
        lvs: CompareOptions::default(),
        quasistatic_nets: fixture.quasistatic.clone(),
    };
    let (outputs, summary) = run_checks(&loaded, &extracted, &options);

    let name = |id| loaded.strings.resolve(id).to_owned();
    let v = &outputs.violations;
    let findings = (0..v.len())
        .map(|i| {
            (
                name(v.rule[i]),
                v.measured[i],
                (v.at[i].x.raw(), v.at[i].y.raw()),
            )
        })
        .collect();
    let rows = outputs
        .runs
        .iter()
        .map(|run| (name(run.rule), run.outcome, run.examined))
        .collect();
    Ok(Ran {
        rows,
        findings,
        lvs: outputs.lvs.clone(),
        outputs,
        summary,
        loaded,
        extracted,
    })
}

/// The fixture's layout as the GDSII bytes [`run`] reads back, with its deck
/// parsed on the 1 nm grid and the strings that deck interned.
///
/// # Errors
///
/// A deck that does not parse, a layer the deck does not declare, or a
/// layout the writer refuses.
pub fn written(fixture: &Fixture) -> Result<(Vec<u8>, Deck, StrTable), String> {
    let grid = Grid::new(1000).expect("a 1 nm grid");
    let mut strings = StrTable::default();
    let deck =
        parse_deck(&fixture.deck, grid, &mut strings).map_err(|why| format!("deck: {why}"))?;

    if !fixture.layout.instances.is_empty() || !fixture.layout.cells.is_empty() {
        let mut cells = Vec::new();
        structures("TOP", &fixture.layout, &deck, &strings, &mut cells)?;
        let mut bytes = Vec::new();
        write_library(&cells, &mut bytes).map_err(|why| format!("gds write: {why}"))?;
        return Ok((bytes, deck, strings));
    }

    let mut builder = LayoutBuilder::new(deck.layers.len());
    for (layer, points) in &fixture.layout.shapes {
        let id = deck
            .layers
            .id(&strings, layer)
            .ok_or_else(|| format!("layout: {layer} is not a deck layer"))?;
        let xs: Vec<i64> = points.iter().map(|p| p.0 * NM).collect();
        let ys: Vec<i64> = points.iter().map(|p| p.1 * NM).collect();
        builder.push(id, &xs, &ys);
    }
    let (store, _) = builder.finish();
    let label_layers: Vec<LayerId> = fixture
        .layout
        .labels
        .iter()
        .map(|(layer, ..)| {
            deck.layers
                .id(&strings, layer)
                .ok_or_else(|| format!("layout: label layer {layer} is not a deck layer"))
        })
        .collect::<Result<_, _>>()?;
    let labels: Vec<Label<'_>> = fixture
        .layout
        .labels
        .iter()
        .zip(&label_layers)
        .map(|((_, x, y, text), &layer)| Label {
            layer,
            x: *x,
            y: *y,
            text,
        })
        .collect();
    let mut bytes = Vec::new();
    write_store_labelled(&store, &deck.layers, &labels, "TOP", &mut bytes)
        .map_err(|why| format!("gds write: {why}"))?;
    Ok((bytes, deck, strings))
}

/// `layout` as the structure `name`, then every cell it defines, each name
/// once: a hierarchy for `write_library`. Only rectangles are written, and
/// each label as a `TEXT` of the cell it is in: the top's name its nets, a
/// cell's are its own (a black box's pins).
fn structures(
    name: &str,
    layout: &Layout,
    deck: &Deck,
    strings: &StrTable,
    out: &mut Vec<Structure>,
) -> Result<(), String> {
    let coordinate =
        |v: i64| i32::try_from(v * NM).map_err(|_| format!("layout: {name}: {v} is past i32"));
    let mut rects = Vec::new();
    for (layer, points) in &layout.shapes {
        let id = deck
            .layers
            .id(strings, layer)
            .ok_or_else(|| format!("layout: {layer} is not a deck layer"))?;
        let (gds_layer, datatype) = deck.layers.stream_of(id);
        let (xs, ys): (Vec<i64>, Vec<i64>) = points.iter().copied().unzip();
        let (xlo, xhi) = (
            *xs.iter().min().expect("a shape"),
            *xs.iter().max().expect("a shape"),
        );
        let (ylo, yhi) = (
            *ys.iter().min().expect("a shape"),
            *ys.iter().max().expect("a shape"),
        );
        let corners = [(xlo, ylo), (xhi, ylo), (xhi, yhi), (xlo, yhi)];
        if points.len() != 4 || !corners.iter().all(|c| points.contains(c)) {
            return Err(format!(
                "layout: {name}: a hierarchical cell holds rectangles only"
            ));
        }
        rects.push((
            gds_layer,
            datatype,
            [
                coordinate(xlo)?,
                coordinate(ylo)?,
                coordinate(xhi)?,
                coordinate(yhi)?,
            ],
        ));
    }
    let mut refs = Vec::new();
    for (cell, orientation, dx, dy) in &layout.instances {
        let (reflect, quarter_turns) = orientation.gds();
        refs.push(Placement {
            cell: cell.clone(),
            reflect,
            quarter_turns,
            mag: 1,
            at: (coordinate(*dx)?, coordinate(*dy)?),
            array: None,
        });
    }
    let mut texts = Vec::new();
    for (layer, x, y, text) in &layout.labels {
        let id = deck
            .layers
            .id(strings, layer)
            .ok_or_else(|| format!("layout: {layer} is not a deck layer"))?;
        let (gds_layer, texttype) = deck.layers.stream_of(id);
        texts.push((
            gds_layer,
            texttype,
            coordinate(*x)?,
            coordinate(*y)?,
            text.clone(),
        ));
    }
    out.push(Structure {
        name: name.to_owned(),
        rects,
        refs,
        texts,
    });
    for (cell, inner) in &layout.cells {
        if !out.iter().any(|s| s.name == *cell) {
            structures(cell, inner, deck, strings, out)?;
        }
    }
    Ok(())
}

/// A measurement as one number, for sorting and tolerant comparison.
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

/// Every claim of `fixture` that `ran` breaks, or the run's error; and,
/// whatever it claims, every element of its parasitic network that is not
/// passive ([`passivity`]).
pub fn violations_of(fixture: &Fixture, ran: &Result<Ran, String>) -> Vec<String> {
    let ran = match ran {
        Ok(ran) => ran,
        Err(why) => {
            // A refused input satisfies only `Passes(false)` and nothing else.
            return if fixture.expect.iter().all(|e| *e == Expect::Passes(false)) {
                Vec::new()
            } else {
                vec![format!("the run did not complete: {why}")]
            };
        }
    };
    let mut broken = Vec::new();
    for expect in &fixture.expect {
        match expect {
            Expect::Rule {
                id,
                outcome,
                findings,
                examined,
            } => {
                let rows: Vec<(Outcome, u64)> = ran
                    .rows
                    .iter()
                    .filter(|(rule, ..)| rule == id)
                    .map(|&(_, outcome, examined)| (outcome, examined))
                    .collect();
                let (got, got_examined) = match rows.as_slice() {
                    [one] => *one,
                    [] => {
                        broken.push(format!("{id}: no row"));
                        continue;
                    }
                    _ => {
                        broken.push(format!("{id}: {} rows", rows.len()));
                        continue;
                    }
                };
                let matches = matches!(
                    (outcome, got),
                    (Want::Ran, Outcome::Ran)
                        | (Want::Skipped, Outcome::Skipped(_))
                        | (Want::Refused, Outcome::Refused)
                );
                if !matches {
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
                        "{id}: {} findings, want {}: {:?}",
                        actual.len(),
                        findings.len(),
                        actual
                    ));
                    continue;
                }
                // Greedy one-to-one pairing; findings are few per rule.
                for want in findings {
                    let found = actual.iter().position(|(measured, at)| {
                        want.measured.is_none_or(|m| same(m, *measured))
                            && want.at.is_none_or(|p| p == *at)
                    });
                    match found {
                        Some(index) => {
                            actual.swap_remove(index);
                        }
                        None => broken.push(format!("{id}: no finding {want:?} among {actual:?}")),
                    }
                }
            }
            Expect::Lvs(matched) => {
                let got = ran.lvs.as_ref().map(|v| matches!(v, Verdict::Match));
                if got != Some(*matched) {
                    broken.push(format!(
                        "lvs: verdict {:?}, want match = {matched}",
                        ran.lvs
                    ));
                }
            }
            Expect::Parasitic {
                net,
                quantity,
                value,
                rel,
            } => match parasitic_total(ran, net, *quantity) {
                None => broken.push(format!("pex: no net {net} in the parasitic network")),
                Some(total) => {
                    if (total - value).abs() > rel * value.abs().max(1e-30) {
                        broken.push(format!(
                            "pex {net} {quantity:?}: {total}, want {value} ±{rel}"
                        ));
                    }
                }
            },
            Expect::Passes(pass) => {
                if ran.summary.passed() != *pass {
                    broken.push(format!("passes: {}, want {pass}", ran.summary.passed()));
                }
            }
        }
    }
    broken.extend(passivity(ran));
    broken
}

/// C6: an extracted network is passive. A resistance, a capacitance to
/// ground or to another net, or an inductance below zero is an element that
/// returns more energy than it stores, so every one must be zero or more
/// (NaN fails too), and so every net's capacitance to ground, their sum, is
/// zero or more. This is element by element, which a passive network need
/// not be (a Maxwell matrix may carry a slightly positive off-diagonal and
/// stay positive definite), but the network SPEF carries is its elements.
/// A mutual inductance is signed by its ports' orientation, so its law is
/// the pair's: `M² ≤ L₁L₂`, the inductance matrix of the two positive
/// semidefinite (each `L` the series inductance on the mutual's node).
fn passivity(ran: &Ran) -> Vec<String> {
    let Some(network) = ran.outputs.parasitics.as_ref() else {
        return Vec::new();
    };
    let inductance_at = |node: gpurify::extract::network::NodeId| {
        network
            .value
            .iter()
            .zip(&network.from)
            .find_map(|(value, &from)| match value {
                Parasitic::Inductance(q) if from == node => Some(q.raw()),
                _ => None,
            })
            .unwrap_or(f64::NAN)
    };
    network
        .value
        .iter()
        .enumerate()
        .filter(|&(row, value)| match value {
            Parasitic::Resistance(q) | Parasitic::SubstrateResistance(q) => !(q.raw() >= 0.0),
            Parasitic::GroundCap(q) | Parasitic::CouplingCap(q) => !(q.raw() >= 0.0),
            Parasitic::Inductance(q) => !(q.raw() >= 0.0),
            Parasitic::MutualInductance(q) => {
                let first = inductance_at(network.from[row]);
                let second = network.to[row].map_or(f64::NAN, inductance_at);
                !(q.raw() * q.raw() <= first * second)
            }
        })
        .map(|(row, value)| format!("pex: element {row}, {value:?}, is not passive"))
        .collect()
}

/// The total of one quantity over a net's elements, by the net's label.
pub fn parasitic_total(ran: &Ran, net: &str, quantity: Quantity) -> Option<f64> {
    let network = ran.outputs.parasitics.as_ref()?;
    let wanted = ran.loaded.strings.get(net)?;
    let net_id = ran.extracted.ports.net_of(wanted)?;
    let mut total = 0.0;
    let mut seen = false;
    let on_net =
        |node: gpurify::extract::network::NodeId| network.node_net[node.0 as usize] == net_id;
    for (index, value) in network.value.iter().enumerate() {
        let near = on_net(network.from[index]);
        // A mutual inductance belongs to both of its nets.
        let far = quantity == Quantity::Mutual && network.to[index].is_some_and(on_net);
        if !near && !far {
            continue;
        }
        seen = true;
        match (quantity, value) {
            (Quantity::Resistance, Parasitic::Resistance(r)) => total += r.raw(),
            (Quantity::GroundCap, Parasitic::GroundCap(c)) => total += c.raw(),
            (Quantity::Inductance, Parasitic::Inductance(l)) => total += l.raw(),
            (Quantity::Mutual, Parasitic::MutualInductance(m)) => total += m.raw(),
            _ => {}
        }
    }
    seen.then_some(total)
}

/// Runs a fixture and reports what is wrong with it, honouring `known`.
pub fn check(fixture: &Fixture) -> Option<String> {
    let ran = run(fixture);
    let broken = violations_of(fixture, &ran);
    match (fixture.known, broken.is_empty()) {
        (None, true) | (Some(_), false) => None,
        (None, false) => Some(format!("{}: {}", fixture.name, broken.join("; "))),
        (Some(finding), true) => Some(format!(
            "{}: expected to fail until {finding} is fixed, and it now holds; drop the \
             `known` marker and record {finding} as fixed",
            fixture.name
        )),
    }
}
