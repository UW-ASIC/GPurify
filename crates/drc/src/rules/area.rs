//! Area family: how much material there is, and where.
//!
//! All four rules go through `core::rects::decompose_into`, because area over a
//! polygon with holes is awkward and area over disjoint rectangles is a sum.
//! The rectangles are disjoint by construction, so they add with no
//! inclusion–exclusion correction, and the decomposition is canonical — the
//! same polygon always decomposes the same way, which the determinism gate
//! needs.
//!
//! # Merged, not per-polygon
//!
//! [`check_min_area`] measures *connected figures*, not input polygons. Two
//! overlapping rectangles each below the limit are one shape that is above it,
//! and summing their fragment areas separately reports two violations that do
//! not exist while a genuinely thin figure split across three fragments reports
//! none. The union is exact (`core::boolean`), not a bounding-box
//! approximation.

use super::{COLUMNS_DIVERGED, centre};
use crate::{record_run, Design, Scratch};
use gpurify_core::boolean::{union_into, BooleanError};
use gpurify_core::rects::{clipped_area, covered_area, decompose_into};
use gpurify_core::view::validate_layer_into;
use gpurify_core::{Bbox, LayerId, PolyId};
use gpurify_ingest::StrId;
use gpurify_report::{
    LimitSense, Measurement, Outcome, RuleRun, Severity, SkipReason, Violation, Violations,
};
use gpurify_units::{Dbu, DbuArea};

/// Minimum area of a connected figure.
///
/// A shape too small to hold a printed feature. Measured after merging, which
/// is what makes it a rule about figures rather than about how the layout
/// happened to be fractured.
#[derive(Debug, Default)]
pub struct MinAreaTable {
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    /// [`DbuArea`] rather than [`Dbu`]: an area limit is a squared coordinate
    /// and does not fit `i64` at the top of the domain. The old tree's `i64`
    /// limit was the same type as its coordinates, which is how an area and a
    /// distance ended up comparable.
    pub limit: Vec<DbuArea>,
}

/// Minimum enclosed area: a hole smaller than this cannot be etched open.
///
/// The complement of [`MinAreaTable`], and it measures the *hole*, not the
/// figure. Only real holes count — a ring of material around a void — not a
/// same-polarity shape nested inside another, which is material and encloses
/// nothing.
#[derive(Debug, Default)]
pub struct MinEnclosedAreaTable {
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    pub limit: Vec<DbuArea>,
}

/// Cheesing: a plate above this area must carry slots or holes.
///
/// Large unbroken metal dishes during chemical-mechanical polish, so the
/// foundry requires it be perforated. The evidence has to be in the polygon's
/// own boundary: a smaller same-polarity shape drawn on top is more material,
/// not relief.
#[derive(Debug, Default)]
pub struct CheesingTable {
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    /// The largest a figure may be while still unperforated. Violated above,
    /// and only when the figure has no hole.
    pub max_unslotted: Vec<DbuArea>,
}

/// Windowed density: the fraction of a moving window a layer covers.
///
/// Both senses live in one table, because unlike width-versus-max-width the two
/// share every step of the computation — the same window sweep and the same
/// coverage fraction, differing only in the final comparison. One `sense`
/// column read once per row as a uniform is not a branch in the loop.
#[derive(Debug, Default)]
pub struct DensityTable {
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    /// Side of the square window. Density is meaningless without one: a layer
    /// that is 30% dense globally can be 0% dense over a millimetre and still
    /// dish.
    pub window: Vec<Dbu>,
    /// How far the window advances between evaluations. Usually half the
    /// window, so every point is covered by four overlapping windows. Stated
    /// rather than derived, because a deck that sweeps in whole-window steps
    /// misses exactly the straddling hot spot the rule is for.
    pub step: Vec<Dbu>,
    /// Covered fraction, in `0.0 ..= 1.0`. A ratio, so `f64` — this is one of
    /// the two dimensionless limits in the crate, alongside the antenna ratio.
    pub limit: Vec<f64>,
    /// Which side of `limit` is the violation. A minimum-density rule wants
    /// enough metal for planarisation; a maximum-density rule wants little
    /// enough for etch loading.
    pub sense: Vec<LimitSense>,
}

impl MinAreaTable {
    pub fn len(&self) -> usize {
        debug_assert_eq!(self.rule.len(), self.layer.len(), "{COLUMNS_DIVERGED}");
        debug_assert_eq!(self.rule.len(), self.limit.len(), "{COLUMNS_DIVERGED}");
        self.rule.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl MinEnclosedAreaTable {
    pub fn len(&self) -> usize {
        debug_assert_eq!(self.rule.len(), self.layer.len(), "{COLUMNS_DIVERGED}");
        debug_assert_eq!(self.rule.len(), self.limit.len(), "{COLUMNS_DIVERGED}");
        self.rule.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl CheesingTable {
    pub fn len(&self) -> usize {
        debug_assert_eq!(self.rule.len(), self.layer.len(), "{COLUMNS_DIVERGED}");
        debug_assert_eq!(
            self.rule.len(),
            self.max_unslotted.len(),
            "{COLUMNS_DIVERGED}"
        );
        self.rule.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl DensityTable {
    pub fn len(&self) -> usize {
        debug_assert_eq!(self.rule.len(), self.layer.len(), "{COLUMNS_DIVERGED}");
        debug_assert_eq!(self.rule.len(), self.window.len(), "{COLUMNS_DIVERGED}");
        debug_assert_eq!(self.rule.len(), self.step.len(), "{COLUMNS_DIVERGED}");
        debug_assert_eq!(self.rule.len(), self.limit.len(), "{COLUMNS_DIVERGED}");
        debug_assert_eq!(self.rule.len(), self.sense.len(), "{COLUMNS_DIVERGED}");
        self.rule.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ---------------------------------------------------------------------------
// The merge every rule in this file starts from.
// ---------------------------------------------------------------------------

/// Merge one layer into connected figures and decompose each into disjoint
/// rectangles.
///
/// **Transform, A-to-B.** Fills `scratch.layer_a` with the validated input,
/// `scratch.layer_out` with the merged figures, and `scratch.rects` /
/// `scratch.rect_start` with the CSR decomposition of those figures: figure `i`
/// owns `rects[rect_start[i] .. rect_start[i + 1]]`.
///
/// **Self-union is the merge.** `a ∪ a` is exactly the region the layer covers,
/// with two overlapping input polygons traced as one boundary — which is what
/// makes [`check_min_area`] and [`check_cheesing`] rules about figures rather
/// than about how the layout happened to be fractured. It is also the only
/// merge that is exact: a bounding-box grouping would over-count area, and
/// summing fragment areas would double-count every overlap.
///
/// Errors are the caller's [`Outcome::Refused`]; nothing here is recoverable
/// into a clean result.
fn merge_layer(
    design: Design<'_>,
    layer: LayerId,
    scratch: &mut Scratch,
) -> Result<(), BooleanError> {
    let Scratch {
        layer_a,
        layer_out,
        rects,
        rect_start,
        ..
    } = scratch;

    validate_layer_into(design.store, layer, layer_a)?;
    let operand: &_ = layer_a;
    union_into(operand, operand, layer_out)?;
    decompose_into(layer_out, design.store, rects, rect_start);

    debug_assert_eq!(
        rect_start.len(),
        layer_out.len() + 1,
        "one CSR offset per merged figure, plus the trailing one"
    );
    debug_assert_eq!(
        rect_start[rect_start.len() - 1] as usize,
        rects.len(),
        "the trailing CSR offset is the rectangle count"
    );
    Ok(())
}

/// The input polygon a merged figure — or a window — is attributed to.
///
/// The lowest store row on the layer the figure's box contains. That is the same
/// "lowest contributing [`PolyId`]" convention `core::view` documents for a
/// boolean's ring provenance, restated here because that provenance names the
/// one-layer store `core::boolean` emits through and not this design's, and a
/// [`ValidatedLayer`](gpurify_core::ValidatedLayer) exposes no map back.
///
/// `inputs` is [`GeometryStore::layer_bboxes`](gpurify_core::GeometryStore::layer_bboxes)
/// for the layer and `first_row` is the `start` of the same layer's
/// [`polys_on_layer`](gpurify_core::GeometryStore::polys_on_layer) range, so the
/// store row of `inputs[j]` is `first_row + j` — arithmetic, not a materialised
/// column. Passing the range's base rather than an enumerated `Vec<u32>` is what
/// keeps this loop free of a second stream and the callers free of a per-rule
/// allocation.
fn lowest_row_within(inputs: &[Bbox], first_row: u32, region: Bbox) -> u32 {
    let n = inputs.len();
    debug_assert!(
        u32::try_from(n).is_ok_and(|len| first_row.checked_add(len).is_some()),
        "the layer's rows are a u32 range, so its last row is below u32::MAX"
    );

    // Branchless: a row the region does not contain is smeared to `u32::MAX`,
    // which loses the `min` to every real row. No `if`, so the fold is one
    // compare-and-blend per row. Scalar rather than a lane op: `inputs` is
    // `Bbox`-shaped, so the four coordinates `contains` compares are strided
    // 32 bytes apart and would have to be gathered before they could be
    // widened — a layout change in `core::store`, not a rewrite here.
    let mut best = u32::MAX;
    // An induction variable rather than a cast of `i`: the row column is an
    // arithmetic sequence, and the assert above is what says it never reaches
    // the `u32::MAX` sentinel.
    let mut row = first_row;
    for &input in inputs {
        let outside = u32::from(!region.contains(input)).wrapping_neg();
        best = best.min(row | outside);
        row = row.wrapping_add(1);
    }
    best
}

/// Report one violation per merged figure the decision rejects, and say how many
/// figures were looked at.
///
/// **Transform, gatherer.** [`check_min_area`] and [`check_cheesing`] differ in
/// nothing but `violates`: both measure a merged figure's area exactly, both
/// report at the centre of the first rectangle of that figure's canonical
/// decomposition, and both count merged figures in `examined`. `violates` is
/// handed the area and whether the figure has a hole, which is everything either
/// of them reads.
fn report_figures(
    design: Design<'_>,
    layer: LayerId,
    rule: StrId,
    limit: DbuArea,
    scratch: &Scratch,
    out: &mut Violations,
    violates: impl Fn(DbuArea, bool) -> bool,
) -> u64 {
    let store_rows = design.store.polys_on_layer(layer);
    let inputs = design.store.layer_bboxes(layer);
    debug_assert_eq!(
        inputs.len(),
        (store_rows.end - store_rows.start) as usize,
        "one box per row on the layer"
    );

    let figures = scratch.layer_out.len();

    for figure in 0..figures {
        let lo = scratch.rect_start[figure] as usize;
        let hi = scratch.rect_start[figure + 1] as usize;
        debug_assert!(
            lo < hi,
            "a validated figure decomposes into at least one rectangle"
        );

        let area = covered_area(&scratch.rects[lo..hi]);
        debug_assert!(area.raw() > 0, "a merged figure covers a positive area");

        let poly = scratch.layer_out.get(
            design.store,
            u32::try_from(figure).expect("a merged layer's figure count fits a u32"),
        );
        let has_hole = poly.holes().next().is_some();

        // Escape valve: one branch per *figure*, and the taken side is a
        // violation push plus an O(rows) attribution scan. A signoff-clean layer
        // never takes it, so it predicts at very nearly 100%.
        if !violates(area, has_hole) {
            continue;
        }

        let first = scratch.rects[lo];
        let owner = lowest_row_within(inputs, store_rows.start, scratch.layer_out.bboxes()[figure]);
        debug_assert_ne!(
            owner,
            u32::MAX,
            "a merged figure contains the polygons it was merged from"
        );
        out.push(Violation {
            rule,
            layer,
            severity: Severity::Error,
            at: centre(Bbox {
                xlo: first.xlo,
                ylo: first.ylo,
                xhi: first.xhi,
                yhi: first.yhi,
            }),
            measured: Measurement::Area(area),
            limit: Measurement::Area(limit),
            shapes: (PolyId(owner), None),
        });
    }

    u64::try_from(figures).expect("a merged layer's figure count fits a u64")
}

/// Check every minimum-area rule.
///
/// **Transform.** Merges the layer into connected figures, decomposes each into
/// disjoint rectangles, sums, compares. One violation per offending figure,
/// reported at the centre of the first rectangle of that figure's canonical
/// decomposition — the centre of an area, per the module doc, and a point
/// always *inside* the figure, which the centre of the bounding box is not for
/// a U or an L. For the single rectangle a small figure usually is, the two
/// coincide.
///
/// `examined` counts merged figures, not input polygons. That is the number a
/// test asserts on, and it differs from the polygon count exactly when merging
/// did something — which is the property worth being able to see.
///
/// `Outcome::Refused` if the union cannot be computed exactly. Never a clean
/// result: the old tree emitted a violation-shaped marker for a geometry error,
/// which put a fabrication defect and a tool failure in the same column.
pub fn check_min_area(
    design: Design<'_>,
    table: &MinAreaTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let runs_before = runs.len();

    // Each rule row's three columns are read once here and are uniforms over the
    // figure loop inside `report_figures`.
    for row in 0..table.len() {
        let (rule, layer, limit) = (table.rule[row], table.layer[row], table.limit[row]);
        debug_assert!(limit.raw() > 0, "an area limit of zero passes everything");
        let violations_before = out.len();

        if merge_layer(design, layer, scratch).is_err() {
            record_run(runs, out, violations_before, rule, Outcome::Refused, 0);
            continue;
        }

        let examined = report_figures(
            design,
            layer,
            rule,
            limit,
            scratch,
            out,
            |area, _has_hole| {
                Measurement::Area(area).violates(Measurement::Area(limit), LimitSense::Minimum)
            },
        );
        record_run(runs, out, violations_before, rule, Outcome::Ran, examined);
    }

    debug_assert_eq!(
        runs.len() - runs_before,
        table.len(),
        "one run row per rule row, whatever the outcome"
    );
}

/// Check every minimum-enclosed-area rule.
///
/// One violation per offending hole, reported at the centre of the hole's
/// bounding box — the centre of the area being measured, per the module doc,
/// and a point inside the hole for every rectilinear ring this tool represents.
/// A vertex of the ring is shared with two edges and does not say which hole is
/// meant when two touch at a corner.
///
/// `examined` counts holes, which is zero for a layer of simply-connected
/// shapes and is a legitimate clean result that a test can distinguish from not
/// having run.
pub fn check_min_enclosed_area(
    design: Design<'_>,
    table: &MinEnclosedAreaTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let runs_before = runs.len();

    // Every `if` in this loop is per rule, not per shape.
    for row in 0..table.len() {
        let (rule, layer, limit) = (table.rule[row], table.layer[row], table.limit[row]);
        debug_assert!(limit.raw() > 0, "an area limit of zero passes everything");
        let violations_before = out.len();

        if merge_layer(design, layer, scratch).is_err() {
            record_run(runs, out, violations_before, rule, Outcome::Refused, 0);
            continue;
        }

        let store_rows = design.store.polys_on_layer(layer);
        let inputs = design.store.layer_bboxes(layer);

        // A walk over figures and their holes. `poly.holes()` yields ring
        // *views*, not a stored column, so there is nothing contiguous to sweep;
        // the elementwise work is one level down, in `area2` and
        // `Bbox::of_points` over the ring's own coordinates.
        let mut examined = 0u64;
        for figure in 0..scratch.layer_out.len() {
            let index = u32::try_from(figure).expect("a merged layer's figure count fits a u32");
            let poly = scratch.layer_out.get(design.store, index);
            let region = scratch.layer_out.bboxes()[figure];

            for hole in poly.holes() {
                examined += 1;

                // A hole winds clockwise, so its doubled signed area is
                // negative and the magnitude is what the rule measures. The
                // halving is exact: a rectilinear ring has integer area.
                let doubled = hole.area2().raw();
                debug_assert!(doubled < 0, "a hole ring winds clockwise");
                debug_assert!(doubled % 2 == 0, "a rectilinear ring has integer area");
                let area = DbuArea::new(-doubled / 2);

                let (xs, ys) = hole.coords();
                let box_ = Bbox::of_points(xs, ys);
                debug_assert!(!box_.is_empty(), "a hole ring has at least three vertices");

                // Escape valve: one branch per hole, and most holes are legal
                // vias and slots, so it predicts at very nearly 100%. The taken
                // side is a push plus an O(rows) attribution scan.
                if !Measurement::Area(area)
                    .violates(Measurement::Area(limit), LimitSense::Minimum)
                {
                    continue;
                }

                let owner = lowest_row_within(inputs, store_rows.start, region);
                debug_assert_ne!(
                    owner,
                    u32::MAX,
                    "a merged figure contains the polygons it was merged from"
                );
                out.push(Violation {
                    rule,
                    layer,
                    severity: Severity::Error,
                    at: centre(box_),
                    measured: Measurement::Area(area),
                    limit: Measurement::Area(limit),
                    shapes: (PolyId(owner), None),
                });
            }
        }

        record_run(runs, out, violations_before, rule, Outcome::Ran, examined);
    }

    debug_assert_eq!(
        runs.len() - runs_before,
        table.len(),
        "one run row per rule row, whatever the outcome"
    );
}

/// Check every cheesing rule.
///
/// A figure violates when its area is above the limit **and** it has no hole.
/// Both halves are needed: area alone flags every legitimate slotted plate, and
/// holes alone flags nothing.
///
/// Reported where [`check_min_area`] reports, for the same reason: the centre
/// of the first rectangle of the figure's canonical decomposition.
///
/// `examined` counts merged figures.
pub fn check_cheesing(
    design: Design<'_>,
    table: &CheesingTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let runs_before = runs.len();

    // Every `if` in this loop is per rule, not per shape.
    for row in 0..table.len() {
        let (rule, layer, limit) = (table.rule[row], table.layer[row], table.max_unslotted[row]);
        debug_assert!(limit.raw() > 0, "an area limit of zero fails everything");
        let violations_before = out.len();

        if merge_layer(design, layer, scratch).is_err() {
            record_run(runs, out, violations_before, rule, Outcome::Refused, 0);
            continue;
        }

        let examined = report_figures(design, layer, rule, limit, scratch, out, |area, has_hole| {
            // Both halves, and `&` rather than `&&` because neither side has a
            // side effect: area alone flags every legitimately slotted plate,
            // and relief alone flags nothing at all.
            let oversized =
                Measurement::Area(area).violates(Measurement::Area(limit), LimitSense::Maximum);
            oversized & !has_hole
        });
        record_run(runs, out, violations_before, rule, Outcome::Ran, examined);
    }

    debug_assert_eq!(
        runs.len() - runs_before,
        table.len(),
        "one run row per rule row, whatever the outcome"
    );
}

/// Check every density rule.
///
/// Sweeps a `window`-sided square across the layer's extent in `step`
/// increments and measures the covered fraction in each, via
/// `core::rects::clipped_area` over that polygon's own rectangle slice. The
/// slice is passed per polygon precisely so this cannot read another polygon's
/// rows — the kernel-rule violation that made the old `rectilinear_occupancy`
/// 43% of a signoff run.
///
/// One violation per offending window, reported at the centre of that window
/// with the fraction as the measurement. The centre, not a corner: a corner is
/// shared with three neighbouring windows in a half-step sweep, so it does not
/// name which window the fraction belongs to. Windows overlap, so one hot
/// spot produces several adjacent violations; that is honest, and merging them
/// would need a second pass that hides where the worst point is.
///
/// `examined` counts windows evaluated. `Outcome::Skipped(SkipReason::EmptyLayer)`
/// when the layer has no geometry, because a density fraction over an empty
/// extent is undefined rather than zero.
pub fn check_density(
    design: Design<'_>,
    table: &DensityTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let runs_before = runs.len();

    // The sweep's three columns, hoisted above the rule-row loop so a deck of
    // tens of density rules allocates once rather than once per row. Each pass
    // below clears and reserves its own destination, so carrying the previous
    // row's contents across is not a hazard.
    let mut windows: Vec<Bbox> = Vec::new();
    let mut fractions: Vec<f64> = Vec::new();
    let mut hits: Vec<(Bbox, f64)> = Vec::new();

    // Every `if` before the sweep below is per rule, not per window.
    for row in 0..table.len() {
        let (rule, layer) = (table.rule[row], table.layer[row]);
        let (side, stride) = (table.window[row].raw(), table.step[row].raw());
        let (limit, sense) = (table.limit[row], table.sense[row]);
        let violations_before = out.len();

        // Fail closed on a deck that reached here with a degenerate sweep: a
        // zero window has no denominator and a zero step never advances, and
        // both would report a clean layer for a check that never ran.
        if side <= 0 || stride <= 0 || !limit.is_finite() {
            record_run(runs, out, violations_before, rule, Outcome::Refused, 0);
            continue;
        }
        // A density fraction over an empty extent is undefined, not zero.
        if design.store.polys_on_layer(layer).is_empty() {
            record_run(
                runs,
                out,
                violations_before,
                rule,
                Outcome::Skipped(SkipReason::EmptyLayer),
                0,
            );
            continue;
        }
        if merge_layer(design, layer, scratch).is_err() {
            record_run(runs, out, violations_before, rule, Outcome::Refused, 0);
            continue;
        }

        // Strict left fold in ascending index order. `Bbox::union` is min/max on
        // integers so the order does not change the answer, but the order is
        // still what the determinism gate reads.
        let boxes = scratch.layer_out.bboxes();
        let mut extent = Bbox::EMPTY;
        for &figure in boxes {
            extent = extent.union(figure);
        }
        if extent.is_empty() {
            record_run(
                runs,
                out,
                violations_before,
                rule,
                Outcome::Skipped(SkipReason::EmptyLayer),
                0,
            );
            continue;
        }

        let (x0, y0) = (extent.xlo.raw(), extent.ylo.raw());
        let cols = positions(extent.xhi.raw() - x0, side, stride);
        let ways = positions(extent.yhi.raw() - y0, side, stride);

        // The far corner of the last window. A layer within one window of the
        // coordinate domain's edge cannot be swept without leaving it, and
        // clamping the window would shrink the numerator while leaving the
        // denominator alone — a layer reported sparser than it is.
        let (xmax, ymax) = (x0 + (cols - 1) * stride + side, y0 + (ways - 1) * stride + side);
        if Dbu::new(xmax).is_none() || Dbu::new(ymax).is_none() {
            record_run(runs, out, violations_before, rule, Outcome::Refused, 0);
            continue;
        }

        // Fail closed on a sweep whose position count does not fit an index. A
        // one-unit window over a full-domain extent is `2^41` positions per
        // axis, so the product leaves `i64` — and a count that wrapped would
        // size the column below to a fraction of the sweep and report the rest
        // of the layer clean without ever looking at it.
        let Some(sweep) = cols.checked_mul(ways).and_then(|n| usize::try_from(n).ok()) else {
            record_run(runs, out, violations_before, rule, Outcome::Refused, 0);
            continue;
        };

        // Uniforms, hoisted above the sweep. The window is square, so its area
        // is the same denominator for every position.
        let window_area = i128::from(side) * i128::from(side);
        let denominator = to_f64(window_area);
        let store_rows = design.store.polys_on_layer(layer);
        let inputs = design.store.layer_bboxes(layer);
        let rects: &[_] = &scratch.rects;

        // The sweep is a column, not a nested loop: the positions are
        // materialised once, and every pass over them afterwards is linear.
        windows.clear();
        windows.reserve(sweep);
        windows.extend((0..ways).flat_map(|iy| {
            (0..cols).map(move |ix| {
                let (wx, wy) = (x0 + ix * stride, y0 + iy * stride);
                Bbox {
                    xlo: Dbu::new_unchecked(wx),
                    ylo: Dbu::new_unchecked(wy),
                    xhi: Dbu::new_unchecked(wx + side),
                    yhi: Dbu::new_unchecked(wy + side),
                }
            })
        }));
        debug_assert_eq!(windows.len(), sweep, "one window per swept position");

        // Transform, A-to-B: one covered fraction per window. The rectangles are
        // disjoint across figures because the layer was merged first, so one
        // `clipped_area` over the whole decomposition is exactly the sum of the
        // per-figure slices — and the kernel-rule hazard `rects` documents does
        // not arise, because the output row here is a window and not a polygon.
        let n = windows.len();
        fractions.clear();
        fractions.reserve(n);
        fractions.extend(
            windows[..n]
                .iter()
                .map(|&w| to_f64(clipped_area(rects, w).raw()) / denominator),
        );
        debug_assert_eq!(fractions.len(), n, "one fraction per swept window");

        // The per-window asserts, restated over the finished column so the sweep
        // body carries no panic edge.
        debug_assert!(
            {
                let mut ok = true;
                for &f in &fractions[..n] {
                    ok &= (0.0..=1.0).contains(&f);
                }
                ok
            },
            "a window cannot be more than fully covered, and a positive window \
             has a denominator"
        );

        // Transform, gatherer: the offending windows, carrying the fraction the
        // predicate measured. The payload rides along, so the clip is not
        // recomputed for the report — which matters for a minimum-density rule,
        // where most windows survive. The commit is branchless: the store is
        // unconditional and the write index carries the predicate, so the `if`
        // this replaced is gone rather than relocated.
        debug_assert_eq!(
            windows.len(),
            fractions.len(),
            "the two columns are parallel"
        );
        let (ws, fs) = (&windows[..n], &fractions[..n]);
        hits.clear();
        // Reserved for the whole sweep, not for the survivors: that
        // over-reservation is what pays for the unconditional store below.
        hits.reserve(n);
        debug_assert!(hits.capacity() >= n, "reserve must cover the whole sweep");
        let slots = &mut hits.spare_capacity_mut()[..n];

        let mut w = 0usize;
        for i in 0..n {
            let (window, fraction) = (ws[i], fs[i]);
            let p = Measurement::Ratio(fraction).violates(Measurement::Ratio(limit), sense);
            // `w <= i` by induction: `w == i == 0` on entry, and each iteration
            // advances `w` by `usize::from(p)`, which Rust guarantees is 0 or 1
            // because `bool` is 0 or 1. So `w` never outruns `i`.
            debug_assert!(w <= i);
            // SAFETY: `w <= i < n == slots.len()`, from the induction above.
            // Rejected slots stay uninitialised and are never read, because
            // `set_len(w)` truncates them away; `(Bbox, f64)` is `Copy`, so
            // there is nothing there to drop either.
            unsafe { slots.get_unchecked_mut(w) }.write((window, fraction));
            w += usize::from(p);
        }

        // SAFETY: slot `k` was written on the iteration where `w == k`, for
        // every `k` in `0 .. w`, and `w <= n <= capacity`.
        unsafe { hits.set_len(w) };
        debug_assert!(hits.len() <= sweep, "a window is reported at most once");

        // One push per *violation* rather than one per window: the output index
        // is data-dependent, which is what the compact above already paid for.
        for &(window, fraction) in &hits {
            // A window is not a shape, so the marker names the lowest polygon
            // the window encloses; a window enclosing none — which only a
            // minimum-density rule can flag — falls back to the layer's first
            // row so the violation is still attributable. Escape valve: a
            // select, not a jump — both sides are a register read, so this
            // lowers to a `cmov`.
            let enclosed = lowest_row_within(inputs, store_rows.start, window);
            let miss = u32::from(enclosed == u32::MAX).wrapping_neg();
            let owner = (enclosed & !miss) | (store_rows.start & miss);

            out.push(Violation {
                rule,
                layer,
                severity: Severity::Error,
                at: centre(window),
                measured: Measurement::Ratio(fraction),
                limit: Measurement::Ratio(limit),
                shapes: (PolyId(owner), None),
            });
        }

        let examined = u64::try_from(sweep).expect("a window sweep is a positive count");
        debug_assert!(examined > 0, "a non-empty extent is swept by at least one window");
        record_run(runs, out, violations_before, rule, Outcome::Ran, examined);
    }

    debug_assert_eq!(
        runs.len() - runs_before,
        table.len(),
        "one run row per rule row, whatever the outcome"
    );
}

/// An exact area as the `f64` a ratio is computed in.
///
/// The one place a `DbuArea` stops being exact, and it is confined to a function
/// so the loss is named rather than scattered through the sweep. A density
/// fraction is dimensionless and the deck states its limit as an `f64`, so the
/// comparison happens in binary floating point whatever this does; an area past
/// `2^53` square units is a window 94 million units on a side, four orders of
/// magnitude beyond a reticle.
#[allow(
    clippy::cast_precision_loss,
    reason = "a density fraction is an f64 by the deck's own limit column; \
              the exactness that matters is in the DbuArea this reads"
)]
fn to_f64(area: i128) -> f64 {
    debug_assert!(area >= 0, "an area is not negative");
    area as f64
}

/// How many window origins a sweep of `span` takes.
///
/// **Decision** — three integers in, one count out. At least one: a layer
/// smaller than the window is still measured, over the single window that
/// covers it, rather than reported clean by a sweep that evaluated nothing.
///
/// **The count rounds up, and that is the whole point.** Truncating division
/// stops the sweep at the last origin that fits, which leaves `span - window`
/// modulo `step` units at the far edge that no window ever covers — a hot spot
/// there is reported clean by a rule that claims to have run. Rounding up walks
/// the last window past the extent instead, which costs nothing: the extra span
/// is empty by construction, so it moves the numerator not at all, and the
/// caller has already refused the sweep if that overshoot leaves the coordinate
/// domain.
fn positions(span: i64, window: i64, step: i64) -> i64 {
    debug_assert!(span >= 0, "an extent's span runs low to high");
    debug_assert!(window > 0 && step > 0, "a sweep has a positive window and step");
    // Branchless: `max(0)` is what turns a layer narrower than the window into
    // the single covering window rather than a negative count.
    // `(a + step - 1) / step` is the round-up, spelled out because signed
    // `div_ceil` is unstable on this toolchain. No overflow: `span` is bounded
    // by `2 * MAX_ABS_DBU` and `step` by `MAX_ABS_DBU`, so the sum stays under
    // `2^43`.
    let count = ((span - window).max(0) + step - 1) / step + 1;
    debug_assert!(
        (count - 1) * step + window >= span,
        "the sweep covers the extent it was asked about"
    );
    count
}
