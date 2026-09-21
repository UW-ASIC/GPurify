//! Area family: how much material there is, and where.
//!
//! All four rules go through `core::rects::decompose_into`: area over a polygon
//! with holes is awkward and area over disjoint rectangles is a sum. The
//! decomposition is canonical, which the determinism gate needs.
//!
//! [`check_min_area`] measures *connected figures*, not input polygons: two
//! overlapping rectangles each below the limit are one shape that is above it.
//! The union is exact (`core::boolean`), not a bounding-box approximation.

use super::{centre, row_columns, COLUMNS_DIVERGED};
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

/// Minimum area of a connected figure, measured after merging.
#[derive(Debug, Default)]
pub struct MinAreaTable {
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    /// [`DbuArea`] rather than [`Dbu`]: an area limit is a squared coordinate
    /// and does not fit `i64` at the top of the domain.
    pub limit: Vec<DbuArea>,
}

/// Minimum enclosed area: a hole smaller than this cannot be etched open.
///
/// Measures the *hole*, not the figure, and only real holes — not a
/// same-polarity shape nested inside another, which is material.
#[derive(Debug, Default)]
pub struct MinEnclosedAreaTable {
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    pub limit: Vec<DbuArea>,
}

/// Cheesing: a plate above this area must carry slots or holes.
///
/// The evidence has to be in the polygon's own boundary: a smaller
/// same-polarity shape drawn on top is more material, not relief.
#[derive(Debug, Default)]
pub struct CheesingTable {
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    /// The largest a figure may be while still unperforated.
    pub max_unslotted: Vec<DbuArea>,
}

/// Windowed density: the fraction of a moving window a layer covers.
///
/// Both senses live in one table because they share every step but the final
/// comparison.
#[derive(Debug, Default)]
pub struct DensityTable {
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    /// Side of the square window.
    pub window: Vec<Dbu>,
    /// How far the window advances between evaluations; stated, never derived.
    pub step: Vec<Dbu>,
    /// Covered fraction, in `0.0 ..= 1.0`.
    pub limit: Vec<f64>,
    /// Which side of `limit` is the violation.
    pub sense: Vec<LimitSense>,
}

row_columns! {
    MinAreaTable { rule, layer, limit },
    MinEnclosedAreaTable { rule, layer, limit },
    CheesingTable { rule, layer, max_unslotted },
    DensityTable { rule, layer, window, step, limit, sense },
}

/// Merge one layer into connected figures and decompose each into disjoint
/// rectangles.
///
/// The CSR decomposition is `scratch.rects` / `scratch.rect_start`: figure `i`
/// owns `rects[rect_start[i] .. rect_start[i + 1]]`. Errors are the caller's
/// [`Outcome::Refused`]; nothing here is recoverable into a clean result.
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

/// The input polygon a merged figure — or a window — is attributed to: the
/// lowest store row on the layer whose box `region` contains.
///
/// `inputs` is the layer's `layer_bboxes` and `first_row` the `start` of the
/// same layer's `polys_on_layer` range, so the store row of `inputs[j]` is
/// `first_row + j`. Returns `u32::MAX` when the region contains nothing.
fn lowest_row_within(inputs: &[Bbox], first_row: u32, region: Bbox) -> u32 {
    let n = inputs.len();
    debug_assert!(
        u32::try_from(n).is_ok_and(|len| first_row.checked_add(len).is_some()),
        "the layer's rows are a u32 range, so its last row is below u32::MAX"
    );

    // Branchless: a row the region does not contain is smeared to `u32::MAX`,
    // which loses the `min` to every real row.
    let mut best = u32::MAX;
    let mut row = first_row;
    for &input in inputs {
        let outside = u32::from(!region.contains(input)).wrapping_neg();
        best = best.min(row | outside);
        row = row.wrapping_add(1);
    }
    best
}

/// Report one violation per merged figure `violates` rejects, returning how
/// many figures were looked at.
///
/// Reports at the centre of the first rectangle of the figure's canonical
/// decomposition. `violates` is handed the figure's area and whether it has a
/// hole.
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
/// One violation per offending figure, at the centre of the first rectangle of
/// that figure's canonical decomposition — a point always *inside* the figure,
/// which the centre of the bounding box is not for a U or an L. `examined`
/// counts merged figures, not input polygons; [`Outcome::Refused`] if the union
/// cannot be computed exactly, never a clean result.
pub fn check_min_area(
    design: Design<'_>,
    table: &MinAreaTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let runs_before = runs.len();

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
/// One violation per offending hole, at the centre of the hole's bounding box.
/// `examined` counts holes, which is legitimately zero for a layer of
/// simply-connected shapes.
pub fn check_min_enclosed_area(
    design: Design<'_>,
    table: &MinEnclosedAreaTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let runs_before = runs.len();

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

                if !Measurement::Area(area).violates(Measurement::Area(limit), LimitSense::Minimum)
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
/// Reported where [`check_min_area`] reports. `examined` counts merged figures.
pub fn check_cheesing(
    design: Design<'_>,
    table: &CheesingTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let runs_before = runs.len();

    for row in 0..table.len() {
        let (rule, layer, limit) = (table.rule[row], table.layer[row], table.max_unslotted[row]);
        debug_assert!(limit.raw() > 0, "an area limit of zero fails everything");
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
            |area, has_hole| {
                let oversized =
                    Measurement::Area(area).violates(Measurement::Area(limit), LimitSense::Maximum);
                oversized & !has_hole
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

/// Check every density rule: a `window`-sided square swept across the layer's
/// extent in `step` increments, measuring the covered fraction in each.
///
/// One violation per offending window, at its centre. Windows overlap, so one
/// hot spot produces several adjacent violations.
///
/// `examined` counts windows evaluated.
/// `Outcome::Skipped(SkipReason::EmptyLayer)` when the layer has no geometry,
/// because a density fraction over an empty extent is undefined, not zero.
pub fn check_density(
    design: Design<'_>,
    table: &DensityTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let runs_before = runs.len();

    // The sweep's three columns, hoisted above the rule-row loop so a deck of
    // tens of density rules allocates once rather than once per row.
    let mut windows: Vec<Bbox> = Vec::new();
    let mut fractions: Vec<f64> = Vec::new();
    let mut hits: Vec<(Bbox, f64)> = Vec::new();

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
        let (xmax, ymax) = (
            x0 + (cols - 1) * stride + side,
            y0 + (ways - 1) * stride + side,
        );
        if Dbu::new(xmax).is_none() || Dbu::new(ymax).is_none() {
            record_run(runs, out, violations_before, rule, Outcome::Refused, 0);
            continue;
        }

        // Fail closed on a sweep whose position count does not fit an index: a
        // count that wrapped would size the column below to a fraction of the
        // sweep and report the rest of the layer clean unexamined.
        let Some(sweep) = cols.checked_mul(ways).and_then(|n| usize::try_from(n).ok()) else {
            record_run(runs, out, violations_before, rule, Outcome::Refused, 0);
            continue;
        };

        // The window is square, so its area is the same denominator throughout.
        let window_area = i128::from(side) * i128::from(side);
        let denominator = to_f64(window_area);
        let store_rows = design.store.polys_on_layer(layer);
        let inputs = design.store.layer_bboxes(layer);
        let rects: &[_] = &scratch.rects;

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

        // One covered fraction per window. The rectangles are disjoint across
        // figures because the layer was merged first, so one `clipped_area` over
        // the whole decomposition is exactly the sum of the per-figure slices.
        let n = windows.len();
        fractions.clear();
        fractions.reserve(n);
        fractions.extend(
            windows[..n]
                .iter()
                .map(|&w| to_f64(clipped_area(rects, w).raw()) / denominator),
        );
        debug_assert_eq!(fractions.len(), n, "one fraction per swept window");

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

        // The offending windows, carrying the fraction the predicate measured so
        // the clip is not recomputed for the report.
        debug_assert_eq!(
            windows.len(),
            fractions.len(),
            "the two columns are parallel"
        );
        let (ws, fs) = (&windows[..n], &fractions[..n]);
        hits.clear();
        // The whole sweep, not the survivors: the over-reservation is what pays
        // for the unconditional store below.
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

        for &(window, fraction) in &hits {
            // A window is not a shape, so the marker names the lowest polygon
            // the window encloses; one enclosing none falls back to the layer's
            // first row so the violation is still attributable.
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
        debug_assert!(
            examined > 0,
            "a non-empty extent is swept by at least one window"
        );
        record_run(runs, out, violations_before, rule, Outcome::Ran, examined);
    }

    debug_assert_eq!(
        runs.len() - runs_before,
        table.len(),
        "one run row per rule row, whatever the outcome"
    );
}

/// An exact area as the `f64` a ratio is computed in — the one place a
/// `DbuArea` stops being exact, confined to a function so the loss is named.
#[allow(
    clippy::cast_precision_loss,
    reason = "a density fraction is an f64 by the deck's own limit column; \
              the exactness that matters is in the DbuArea this reads"
)]
fn to_f64(area: i128) -> f64 {
    debug_assert!(area >= 0, "an area is not negative");
    area as f64
}

/// How many window origins a sweep of `span` takes; always at least one.
///
/// The count rounds **up**: truncating would leave `(span - window) % step`
/// units at the far edge that no window covers, so a hot spot there would be
/// reported clean by a rule claiming to have run. The overshoot is empty by
/// construction and the caller has already refused a sweep that leaves the
/// coordinate domain.
fn positions(span: i64, window: i64, step: i64) -> i64 {
    debug_assert!(span >= 0, "an extent's span runs low to high");
    debug_assert!(
        window > 0 && step > 0,
        "a sweep has a positive window and step"
    );
    // `max(0)` turns a layer narrower than the window into the single covering
    // window rather than a negative count. `(a + step - 1) / step` is the
    // round-up, spelled out because signed `div_ceil` is unstable here.
    let count = ((span - window).max(0) + step - 1) / step + 1;
    debug_assert!(
        (count - 1) * step + window >= span,
        "the sweep covers the extent it was asked about"
    );
    count
}
