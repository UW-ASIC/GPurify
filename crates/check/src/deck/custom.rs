//! Custom rules: a rule kind `GPurify` does not ship, written as a Rust
//! function, held to the guarantees every rule keeps (deck-library plan
//! §4.4; catalog FLOW-006).
//!
//! The function sees the layout through [`CustomCtx`], read-only, and
//! reports into [`Findings`]. The runner ([`run_custom`]) owns the
//! accounting, so user code cannot break the report's contract:
//!
//! - a rule whose input layers are all empty is
//!   [`Skipped`](crate::report::Outcome::Skipped) with
//!   [`EmptyLayer`](crate::report::SkipReason::EmptyLayer), and its function
//!   is never called;
//! - `examined` is the shapes and edges on the input layers, counted by the
//!   runner;
//! - findings are put in the canonical order and duplicates dropped, so the
//!   report's bytes do not depend on the order the function found them in;
//! - a finding on a layer the rule did not declare, naming a shape off
//!   them, outside the layout's extent, or measured as no finite number
//!   makes the rule [`Refused`](crate::report::Outcome::Refused), its
//!   findings discarded;
//! - a function that panics never passes. Under unwinding (tests, debug
//!   builds) the rule is `Refused` and the run goes on; under the release
//!   profile's `panic = "abort"` a panic hook names the rule and the process
//!   exits non-zero.
//!
//! Determinism is the function's own: the same layout must give the same
//! findings. The determinism test (run twice, compare the bytes) catches one
//! that does not.
//!
//! # Examples
//!
//! ```
//! use gpurify_check::deck::{rules, CustomCtx, DeckBuilder, Findings};
//! use gpurify_check::report::{Measurement, Severity};
//! use gpurify_geom::{Grid, StrTable};
//!
//! /// Every shape of the first input with fewer than 1000 square grid units.
//! fn small(ctx: &CustomCtx<'_>, out: &mut Findings) {
//!     for shape in ctx.shapes(ctx.input(0)) {
//!         let area = ctx.area(shape);
//!         if area < 1000 {
//!             out.flag(ctx, shape, Measurement::Count(u32::try_from(area).unwrap_or(0)));
//!         }
//!     }
//! }
//!
//! let mut strings = StrTable::default();
//! let mut d = DeckBuilder::new(Grid::new(1000)?, &mut strings);
//! let met1 = d.layer("met1", (68, 20));
//! let width = d.length(140.0);
//! d.rule("m1.1", rules::min_width(met1, width));
//! d.custom("m1.small", &[met1], Severity::Error, small);
//! let deck = d.finish()?;
//! assert_eq!(deck.rule_count(), 2);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::drc::rules::poly_dist2;
use crate::report::{
    record_run, Measurement, Outcome, RuleRun, Severity, SkipReason, Violation, Violations,
};
use crate::topology::NetTable;
use gpurify_geom::index::{candidate_pairs_into, cross_layer_pairs_into, SpatialIndex};
use gpurify_geom::ops::Point;
use gpurify_geom::view::validate_layer_into;
use gpurify_geom::{
    Bbox, Dbu, GeometryStore, Grid, LayerId, PolyId, StrId, StrTable, ValidatedLayer,
};
use std::cell::RefCell;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Once;

/// A custom rule's check: reads the layout through the context, reports
/// into the findings. A plain function pointer: one indirect call per rule,
/// and the loop over shapes stays in the function.
pub type CustomCheck = fn(&CustomCtx<'_>, &mut Findings);

/// A rule kind written in Rust. Built with
/// [`DeckBuilder::custom`](super::DeckBuilder::custom), run in the DRC stage
/// by [`run_custom`].
#[derive(Debug, Clone)]
pub struct CustomRule {
    /// The rule's id, interned: what its findings and its `RuleRun` row are
    /// reported under.
    pub id: StrId,
    /// The layers it reads, the only ones its findings may name.
    pub inputs: Vec<LayerId>,
    /// The severity of every finding.
    pub severity: Severity,
    /// The check.
    pub check: CustomCheck,
}

/// Equal when the id, inputs and severity are, and the check is the same
/// function.
impl PartialEq for CustomRule {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.inputs == other.inputs
            && self.severity == other.severity
            && std::ptr::fn_addr_eq(self.check, other.check)
    }
}

/// One finding of a custom rule, as the report will carry it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Finding {
    /// The layer it is reported on: one of the rule's inputs.
    pub layer: LayerId,
    /// Where to look, inside the layout's extent.
    pub at: Point,
    /// The shapes it names: rows on the inputs, `PolyId(u32::MAX)` for none.
    pub shapes: (PolyId, Option<PolyId>),
    /// What was measured; finite.
    pub measured: Measurement,
    /// The limit it was held to; finite, the same variant as `measured`.
    pub limit: Measurement,
}

/// What a custom rule found, in any order and with repeats: the runner puts
/// it in canonical order and drops the repeats.
#[derive(Debug, Default)]
pub struct Findings {
    rows: Vec<Finding>,
}

impl Findings {
    /// Records a finding.
    pub fn push(&mut self, finding: Finding) {
        self.rows.push(finding);
    }

    /// Flags `shape` at its first vertex, on its layer, with `measured`
    /// against a limit of the same kind and zero: a shape that should not be
    /// there.
    pub fn flag(&mut self, ctx: &CustomCtx<'_>, shape: PolyId, measured: Measurement) {
        let (xs, ys) = ctx.store.poly_verts(shape);
        let limit = match measured {
            Measurement::Length(_) => Measurement::Length(Dbu::new_unchecked(0)),
            Measurement::Area(_) => Measurement::Area(gpurify_geom::DbuArea::new(0)),
            Measurement::Ratio(_) => Measurement::Ratio(0.0),
            Measurement::Count(_) => Measurement::Count(0),
            Measurement::Voltage(_) => Measurement::Voltage(gpurify_geom::Qty::new(0.0)),
            Measurement::Current(_) => Measurement::Current(gpurify_geom::Qty::new(0.0)),
            Measurement::Resistance(_) => Measurement::Resistance(gpurify_geom::Qty::new(0.0)),
        };
        self.push(Finding {
            layer: ctx.store.poly_layer(shape),
            at: Point { x: xs[0], y: ys[0] },
            shapes: (shape, None),
            measured,
            limit,
        });
    }

    /// How many findings were recorded, repeats included.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether nothing was recorded.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

/// What a custom rule may read: the layout, read-only, with its declared
/// input layers validated before it is called.
#[derive(Debug, Clone, Copy)]
pub struct CustomCtx<'a> {
    store: &'a GeometryStore,
    inputs: &'a [LayerId],
    validated: &'a [Option<ValidatedLayer>],
    nets: Option<&'a NetTable>,
    grid: Grid,
    strings: &'a StrTable,
}

impl<'a> CustomCtx<'a> {
    /// The rule's `k`th input layer. Panics past the rule's inputs.
    pub fn input(&self, k: usize) -> LayerId {
        self.inputs[k]
    }

    /// The rule's input layers, as declared.
    pub fn inputs(&self) -> &'a [LayerId] {
        self.inputs
    }

    /// The layout, read-only: vertices, boxes and layers of every row.
    pub fn store(&self) -> &'a GeometryStore {
        self.store
    }

    /// The rows on `layer`, in store order; none for a layer the rule did not
    /// declare.
    pub fn shapes(&self, layer: LayerId) -> impl Iterator<Item = PolyId> + 'a {
        let rows = if self.inputs.contains(&layer) {
            self.store.polys_on_layer(layer)
        } else {
            0..0
        };
        rows.map(PolyId)
    }

    /// A row's area in square grid units, holes as their own (negative,
    /// clockwise) rows: twice the shoelace sum, halved.
    pub fn area(&self, shape: PolyId) -> i128 {
        let (xs, ys) = self.store.poly_verts(shape);
        gpurify_geom::ops::area2(xs, ys).raw() / 2
    }

    /// The `k`th input, merged and validated as the DRC rules read a layer;
    /// `None` when it does not validate (a non-rectilinear or
    /// self-intersecting shape, or an edge layer).
    pub fn validated(&self, k: usize) -> Option<&'a ValidatedLayer> {
        self.validated.get(k).and_then(Option::as_ref)
    }

    /// Every pair of rows, one on input `a` and one on input `b` (both on `a`
    /// when they are the same input, each pair once), whose boundaries come
    /// within `distance`, exactly; ascending.
    pub fn pairs_within(&self, a: usize, b: usize, distance: Dbu) -> Vec<(PolyId, PolyId)> {
        let (a, b) = (self.inputs[a], self.inputs[b]);
        let mut index_a = SpatialIndex::default();
        SpatialIndex::build_into(self.store, a, &mut index_a);
        let mut pairs = Vec::new();
        if a == b {
            candidate_pairs_into(self.store, &index_a, distance, &mut pairs);
        } else {
            let mut index_b = SpatialIndex::default();
            SpatialIndex::build_into(self.store, b, &mut index_b);
            cross_layer_pairs_into(self.store, &index_a, &index_b, distance, &mut pairs);
        }
        let limit = distance.mul_wide(distance);
        pairs.retain(|&(p, q)| poly_dist2(self.store, p, q) <= limit);
        pairs
    }

    /// The extracted nets, when the run has them.
    pub fn nets(&self) -> Option<&'a NetTable> {
        self.nets
    }

    /// The layout grid.
    pub fn grid(&self) -> Grid {
        self.grid
    }

    /// The run's names.
    pub fn strings(&self) -> &'a StrTable {
        self.strings
    }
}

thread_local! {
    /// The custom rule running on this thread, for the panic hook to name.
    static RUNNING: RefCell<Option<String>> = const { RefCell::new(None) };
}

static HOOK: Once = Once::new();

/// Installs, once, a panic hook that names the custom rule running when a
/// panic happens, then hands on to the hook that was there. Under
/// `panic = "abort"` that line is the run's last word.
fn install_hook() {
    HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let running = RUNNING.with(|running| running.borrow().clone());
            if let Some(rule) = running {
                eprintln!("error: custom rule `{rule}` panicked; the run has no verdict");
            }
            previous(info);
        }));
    });
}

/// Runs every custom rule over one layout, appending exactly one
/// [`RuleRun`] per rule to `runs` and the findings, canonical, to `out`.
/// `nets` is what [`CustomCtx::nets`] answers.
pub fn run_custom(
    rules: &[CustomRule],
    store: &GeometryStore,
    nets: Option<&NetTable>,
    grid: Grid,
    strings: &StrTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    if rules.is_empty() {
        return;
    }
    install_hook();
    let layers = store.layer_count();
    let extent = (0..layers)
        .map(|layer| LayerId(u16::try_from(layer).expect("a LayerId is a u16")))
        .flat_map(|layer| store.layer_bboxes(layer).iter().copied())
        .fold(Bbox::EMPTY, Bbox::union);
    for rule in rules {
        let before = out.len();
        if rule.inputs.iter().any(|layer| layer.idx() >= layers) {
            record_run(runs, out, before, rule.id, Outcome::Refused, 0);
            continue;
        }
        let examined: u64 = rule
            .inputs
            .iter()
            .map(|&layer| {
                let rows = store.polys_on_layer(layer);
                u64::from(rows.end - rows.start) + store.edges_on_layer(layer).len() as u64
            })
            .sum();
        if examined == 0 {
            let skipped = Outcome::Skipped(SkipReason::EmptyLayer);
            record_run(runs, out, before, rule.id, skipped, 0);
            continue;
        }
        let validated: Vec<Option<ValidatedLayer>> = rule
            .inputs
            .iter()
            .map(|&layer| {
                let mut layer_out = ValidatedLayer::default();
                validate_layer_into(store, layer, &mut layer_out)
                    .ok()
                    .map(|()| layer_out)
            })
            .collect();
        let ctx = CustomCtx {
            store,
            inputs: &rule.inputs,
            validated: &validated,
            nets,
            grid,
            strings,
        };
        let mut findings = Findings::default();
        RUNNING.with(|running| *running.borrow_mut() = Some(strings.resolve(rule.id).to_owned()));
        // The context hands out shared references only, and a panicking
        // rule's findings are discarded, so nothing torn is observed after.
        let called = catch_unwind(AssertUnwindSafe(|| (rule.check)(&ctx, &mut findings)));
        RUNNING.with(|running| *running.borrow_mut() = None);
        if called.is_err() || !findings.rows.iter().all(|f| sane(f, rule, store, extent)) {
            record_run(runs, out, before, rule.id, Outcome::Refused, examined);
            continue;
        }
        let mut table = Violations::default();
        for finding in findings.rows {
            table.push(Violation {
                rule: rule.id,
                layer: finding.layer,
                severity: rule.severity,
                at: finding.at,
                measured: finding.measured,
                limit: finding.limit,
                shapes: finding.shapes,
            });
        }
        table.sort_canonical();
        let mut last: Option<Violation> = None;
        for row in 0..table.len() {
            let violation = table.get(row);
            if last != Some(violation) {
                out.push(violation);
                last = Some(violation);
            }
        }
        record_run(runs, out, before, rule.id, Outcome::Ran, examined);
    }
}

/// Whether a finding is one the report can carry for this rule: on a
/// declared layer, naming rows on declared layers, inside the layout's
/// extent, and finite.
fn sane(finding: &Finding, rule: &CustomRule, store: &GeometryStore, extent: Bbox) -> bool {
    let declared = |shape: PolyId| {
        shape.0 == u32::MAX
            || ((shape.0 as usize) < store.poly_count()
                && rule.inputs.contains(&store.poly_layer(shape)))
    };
    let at = finding.at;
    rule.inputs.contains(&finding.layer)
        && declared(finding.shapes.0)
        && finding.shapes.1.is_none_or(declared)
        && at.x >= extent.xlo
        && at.x <= extent.xhi
        && at.y >= extent.ylo
        && at.y <= extent.yhi
        && finding.measured.is_finite()
        && finding.limit.is_finite()
        && std::mem::discriminant(&finding.measured) == std::mem::discriminant(&finding.limit)
}
