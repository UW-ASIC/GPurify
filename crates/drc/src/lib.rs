//! DRC engine.
//!
//! Every rule lives in its own file under `rules/`, implements the shared
//! [`crate::rule::Rule`] trait over [`DrcCtx`], and is discovered by the
//! compile-time glob in `build.rs` (see the generated `drc_rules.rs`): adding a
//! rule = adding one file exposing a `FACTORY`. The public entry `run_drc`
//! resolves the deck's `DrcRuleParam`s through the glob's factories and runs
//! the rules rayon-parallel over the SoA `GeometryStore`.
//!
//! Algorithm choices follow the research:
//!   * width / spacing / notch  -> edge-pair distance (scanline-pruned by bbox)
//!   * enclosure / overlap / ext -> layer-vs-layer edge/bbox relations
//!   * area                      -> shoelace
//!   * edge length / angle / grid-> per-edge / per-vertex predicates
//!   * density                   -> windowed coverage fraction

// Re-exports so internal `crate::*` paths resolve after workspace split
pub use gdsverify_backend as backend;
pub use gdsverify_backend::rule;
pub use gdsverify_core::geometry;
pub use gdsverify_core::params;
pub use gdsverify_lvs as lvs;

use crate::backend::Backend;
use crate::geometry::*;
use crate::params::{Deck, DrcRuleParam, LayerTable};

pub mod cmp;
pub mod coloring;
pub mod derived;
pub mod fill;
#[cfg(feature = "gpu")]
pub mod gpu;
pub mod production;
pub mod results;

/// The crate's public error surface. Wraps the geometry-capacity errors the
/// rule kernels can hit and the completeness check on the incremental result DB.
/// The deck/rule schema (`production::DeckError`, `production::RunError`), fill
/// (`fill::FillError`), and result-DB (`results::ResultDbError`) errors remain
/// their own typed enums — this is only the surface that was previously
/// `Result<_, String>`.
#[derive(Debug, thiserror::Error)]
pub enum DrcError {
    /// Geometry outside the declared numeric limits of the exact kernels.
    #[error(transparent)]
    Geometry(#[from] gdsverify_core::exact::ExactGeometryError),
    /// The incremental result database is missing tiles.
    #[error("expected {expected} tiles, database has {records} records")]
    IncompleteResults { expected: usize, records: usize },
}

/// Everything a DRC rule reads. Copy — plain borrowed refs.
#[derive(Clone, Copy)]
pub struct DrcCtx<'a> {
    pub store: &'a GeometryStore,
    pub deck: &'a Deck,
}

// ponytail: GPU prefilter staged for phase-2 vulkano.
// The per-run canonical device edge pool (DeviceEdges/build_device_edges) was
// deleted with the session seam; rules take the exact CPU path directly.

/// A boxed DRC rule, generic over the context lifetime.
pub type BoxedRule = Box<dyn for<'a> crate::rule::Rule<DrcCtx<'a>, Finding = Violation>>;

/// One file per rule, globbed at compile time by build.rs.
pub mod rules {
    use super::BoxedRule;
    /// Build a rule from a deck param, or `None` if the param belongs to
    /// another rule file. The strict flag threads through from
    /// [`super::run_drc_backend_strict`].
    pub type Factory = fn(&crate::params::DrcRuleParam, bool) -> Option<BoxedRule>;
    include!(concat!(env!("OUT_DIR"), "/drc_rules.rs"));
}

/// Maximum number of sliding density windows evaluated by one rule/recheck.
/// Each window performs at least one exact boolean operation, so this shares
/// the rectilinear kernel's explicit 16M-work ceiling.
pub const MAX_DENSITY_WINDOW_WORK: usize = gdsverify_core::exact::MAX_RECTILINEAR_BOOLEAN_CELLS;

pub(crate) fn density_window_work(
    xmin: i32,
    ymin: i32,
    xmax: i32,
    ymax: i32,
    window: i32,
    step: i32,
) -> Result<usize, gdsverify_core::exact::ExactGeometryError> {
    let axis_count = |lo: i32, hi: i32| -> Option<u128> {
        let span = u128::try_from(i64::from(hi) - i64::from(lo)).ok()?;
        let window = u128::try_from(window).ok()?;
        let step = u128::try_from(step).ok()?;
        if span == 0 || window == 0 || step == 0 {
            return None;
        }
        let remaining = span.saturating_sub(window);
        remaining
            .checked_add(step - 1)?
            .checked_div(step)?
            .checked_add(1)
    };
    let requested = axis_count(xmin, xmax)
        .and_then(|nx| axis_count(ymin, ymax).and_then(|ny| nx.checked_mul(ny)))
        .ok_or(gdsverify_core::exact::ExactGeometryError::ArithmeticOverflow)?;
    if requested > MAX_DENSITY_WINDOW_WORK as u128 {
        return Err(
            gdsverify_core::exact::ExactGeometryError::CapacityExceeded {
                cells: usize::try_from(requested).unwrap_or(usize::MAX),
                limit: MAX_DENSITY_WINDOW_WORK,
            },
        );
    }
    usize::try_from(requested)
        .map_err(|_| gdsverify_core::exact::ExactGeometryError::ArithmeticOverflow)
}

/// A single rule violation. Flat, serializable, comparable against the manifest.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Violation {
    pub rule_id: String,
    pub kind: String,
    pub layer: String,
    pub measured: i64, // measured value in DBU (or -1 where N/A, e.g. angle)
    pub limit: i64,    // the rule limit
    pub x: i32,        // a representative location
    pub y: i32,
    #[serde(default)]
    pub hierarchy_path: Option<String>,
    #[serde(default)]
    pub source_polygons: Vec<u32>,
    #[serde(default)]
    pub marker: Option<results::MarkerGeometry>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct DrcReport {
    pub violations: Vec<Violation>,
}

impl DrcReport {
    #[must_use]
    pub fn by_kind(&self, kind: &str) -> Vec<&Violation> {
        self.violations.iter().filter(|v| v.kind == kind).collect()
    }

    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        let mut sorted = self.violations.clone();
        sorted.sort_by(|a, b| {
            a.rule_id
                .cmp(&b.rule_id)
                .then(a.kind.cmp(&b.kind))
                .then(a.layer.cmp(&b.layer))
                .then(a.measured.cmp(&b.measured))
                .then(a.x.cmp(&b.x))
                .then(a.y.cmp(&b.y))
        });
        serde_json::to_string_pretty(&sorted).unwrap_or_default()
    }
}

/// Run the whole deck against the store. Restricting to a set of polygons (one cell) is done
/// by the caller building a store that only contains that cell.
pub fn run_drc(store: &GeometryStore, deck: &Deck) -> DrcReport {
    run_drc_backend(store, deck, Backend::Cpu)
}

/// Same as [`run_drc`], with an explicit backend. `Backend::Gpu` uses the CUDA edge-pair
/// prefilter for the spacing scans when a device is available; the report is identical to
/// the CPU one either way (kernels are advisory prefilters, verdicts stay exact).
pub fn run_drc_backend(store: &GeometryStore, deck: &Deck, backend: Backend) -> DrcReport {
    run_drc_backend_strict(store, deck, backend, deck.strict)
}

pub fn run_drc_backend_strict(
    store: &GeometryStore,
    deck: &Deck,
    backend: Backend,
    strict: bool,
) -> DrcReport {
    run_drc_impl(store, deck, backend, strict, |_| true)
}

/// In-loop variant: density rules skipped. The engine's convergence loop always
/// waives density (whole-die density is meaningless mid-iteration), so computing
/// the window clips every iteration is a full-geometry pass of pure waste.
pub fn run_drc_no_density(store: &GeometryStore, deck: &Deck) -> DrcReport {
    run_drc_impl(store, deck, Backend::Cpu, deck.strict, |r| {
        !matches!(
            r,
            DrcRuleParam::MinDensity { .. } | DrcRuleParam::MaxDensity { .. }
        )
    })
}

fn run_drc_impl(
    store: &GeometryStore,
    deck: &Deck,
    backend: Backend,
    strict: bool,
    keep: impl Fn(&DrcRuleParam) -> bool + Sync,
) -> DrcReport {
    // Capacity validation must precede every legacy kernel. Several W1 rule
    // result types still use i32/i64 measurements, so geometry outside those
    // declared numeric limits is a typed error, never an invitation to execute
    // overflowing candidate arithmetic.
    let mut violations = check_polygon_validity(store, &deck.layers);
    if violations
        .iter()
        .any(|violation| violation.kind == "geometry_capacity")
    {
        return DrcReport { violations };
    }
    // Resolve each deck param through the compile-time glob of rules/.
    let rules: Vec<BoxedRule> = deck
        .drc_rules
        .iter()
        .filter(|p| keep(p))
        .map(|p| {
            rules::FACTORIES
                .iter()
                .find_map(|f| f(p, strict))
                .unwrap_or_else(|| panic!("no rule file registered for deck param {p:?}"))
        })
        .collect();
    // Rules are independent read-only scans over the store; run them in parallel
    // and concatenate in rule order so the report is deterministic.
    // ponytail: GPU prefilter staged for phase-2 vulkano — rules take the exact
    // CPU path directly; `backend` still threads through for telemetry.
    let ctx = DrcCtx { store, deck };
    violations.extend(crate::rule::run_rules(&rules, &ctx, backend));
    // Coincident identical polygons (e.g. two pins of one device sharing a pad)
    // are one merged shape in real DRC; each copy reports the same violation.
    // Exact duplicates are double counts, never two distinct defects.
    violations.sort_unstable_by(|a, b| {
        (&a.rule_id, &a.kind, &a.layer, a.measured, a.limit, a.x, a.y)
            .cmp(&(&b.rule_id, &b.kind, &b.layer, b.measured, b.limit, b.x, b.y))
    });
    violations.dedup_by(|a, b| {
        a.rule_id == b.rule_id
            && a.kind == b.kind
            && a.layer == b.layer
            && a.measured == b.measured
            && a.limit == b.limit
            && a.x == b.x
            && a.y == b.y
    });
    DrcReport { violations }
}

/// Parse-don't-validate at the geometry boundary: every polygon is scanned once,
/// on load, for the degeneracies the rule kernels are not defined over —
/// self-crossing boundaries and zero-area shapes. Keyhole slits (legal GDS holes)
/// pass; proper bow-tie crossings do not.
pub(crate) fn check_polygon_validity(store: &GeometryStore, lt: &LayerTable) -> Vec<Violation> {
    use gdsverify_core::exact::{ExactGeometryError, SegmentIntersection};

    let mut out = Vec::new();
    for p in 0..store.poly_count() {
        let pid = PolyId(p as u32);
        let bb = store.poly_bbox[p];
        let issue = match store.poly_as_exact(pid) {
            Ok(polygon) => {
                let area = polygon.area2() / 2;
                let span_x = i64::from(bb.xmax) - i64::from(bb.xmin);
                let span_y = i64::from(bb.ymax) - i64::from(bb.ymin);
                (span_x > i64::from(i32::MAX)
                    || span_y > i64::from(i32::MAX)
                    || area > i128::from(i64::MAX))
                .then_some("geometry_capacity")
            }
            Err(ExactGeometryError::DegenerateRing) => Some("zero_area"),
            // The admitted compatibility GDS adapter deliberately retains a
            // collapsed boundary so this always-on scan can diagnose it. A
            // zero-width rectangle reaches the exact constructor as duplicate
            // consecutive vertices, but its physical defect is still zero
            // area. Preserve that stable measurement without weakening the
            // rejection of nonzero malformed contacts.
            Err(
                ExactGeometryError::DuplicateConsecutiveVertex { .. }
                | ExactGeometryError::TooFewVertices { .. },
            ) if store.signed_area2_exact(pid) == Some(0) => Some("zero_area"),
            Err(ExactGeometryError::ArithmeticOverflow)
            | Err(ExactGeometryError::CapacityExceeded { .. }) => Some("geometry_capacity"),
            Err(ExactGeometryError::SelfIntersection {
                kind: SegmentIntersection::Proper,
                ..
            }) => Some("self_intersecting"),
            Err(_) => Some("invalid_boundary_contact"),
        };
        if let Some(kind_detail) = issue {
            out.push(Violation {
                rule_id: "__geometry__".into(),
                kind: if kind_detail == "geometry_capacity" {
                    "geometry_capacity".into()
                } else {
                    "polygon_validity".into()
                },
                layer: lt.name(store.poly_layer[p]).into(),
                measured: if kind_detail == "zero_area" { 0 } else { 1 },
                limit: 0,
                x: bb.xmin,
                y: bb.ymin,
                hierarchy_path: None,
                source_polygons: Vec::new(),
                marker: None,
            });
        }
    }
    if !out
        .iter()
        .any(|violation| violation.kind == "geometry_capacity")
        && store.poly_count() > 0
    {
        let mut extent = Bbox::empty();
        for bbox in &store.poly_bbox {
            extent.include(bbox.xmin, bbox.ymin);
            extent.include(bbox.xmax, bbox.ymax);
        }
        // This is also the rule-arithmetic contract: with every coordinate
        // delta <= i32::MAX, the worst diagonal cross is < 2*extent² and its
        // square, dot products, rational sample numerators and distances all
        // fit i128. Larger layouts are rejected before any legacy kernel.
        if extent.width_i64() > i64::from(i32::MAX)
            || extent.height_i64() > i64::from(i32::MAX)
            || !legacy_rule_arithmetic_fits(&extent)
        {
            out.push(Violation {
                rule_id: "__geometry__".into(),
                kind: "geometry_capacity".into(),
                layer: lt.name(store.poly_layer[0]).into(),
                measured: 1,
                limit: 0,
                x: extent.xmin,
                y: extent.ymin,
                hierarchy_path: None,
                source_polygons: Vec::new(),
                marker: None,
            });
        }
    }
    out
}

pub(crate) fn legacy_rule_arithmetic_fits(extent: &Bbox) -> bool {
    let span = i128::from(extent.width_i64().max(extent.height_i64()).max(0));
    span.checked_mul(span)
        .and_then(|square| square.checked_mul(2))
        .and_then(|cross_bound| cross_bound.checked_mul(cross_bound))
        .is_some()
}

/// Scan facing parallel edge pairs of one polygon; return (distance, mid_x, mid_y) for
/// each pair with positive overlap span. `interior` selects pairs whose gap midpoint lies
/// inside the polygon (width measurements) vs outside (notch gaps). This midpoint
/// disambiguation is what stops a U-shape's notch from being reported as a narrow width
/// and its arm widths from being reported as notches.
// ponytail: 1-dbu gaps have no strict-interior sample point and classify as exterior;
// far below any real rule limit, so accepted.
pub(crate) fn facing_gaps(
    store: &GeometryStore,
    p: PolyId,
    interior: bool,
) -> Result<Vec<(i64, i32, i32)>, gdsverify_core::exact::ExactGeometryError> {
    use gdsverify_core::exact::ExactGeometryError;

    let edges = poly_edges(store, p);
    let n = edges.len();
    let mut out = Vec::new();
    for i in 0..n {
        for j in (i + 1)..n {
            let a = &edges[i];
            let b = &edges[j];
            let (d, mx, my) = if a.is_vertical() && b.is_vertical() {
                let ylo = a.y0.min(a.y1).max(b.y0.min(b.y1));
                let yhi = a.y0.max(a.y1).min(b.y0.max(b.y1));
                if ylo >= yhi {
                    continue;
                }
                (
                    (i64::from(a.x0) - i64::from(b.x0)).abs(),
                    midpoint_i32(a.x0, b.x0)?,
                    midpoint_i32(ylo, yhi)?,
                )
            } else if a.is_horizontal() && b.is_horizontal() {
                let xlo = a.x0.min(a.x1).max(b.x0.min(b.x1));
                let xhi = a.x0.max(a.x1).min(b.x0.max(b.x1));
                if xlo >= xhi {
                    continue;
                }
                (
                    (i64::from(a.y0) - i64::from(b.y0)).abs(),
                    midpoint_i32(xlo, xhi)?,
                    midpoint_i32(a.y0, b.y0)?,
                )
            } else {
                // parallel diagonal edges (45° routing): perpendicular gap where
                // the edges overlap tangentially. All projection/distance/sample
                // arithmetic stays exact in i128; the marker alone is rounded.
                let (adx, ady) = (i128::from(a.dx_i64()), i128::from(a.dy_i64()));
                let (bdx, bdy) = (i128::from(b.dx_i64()), i128::from(b.dy_i64()));
                if adx * bdy - ady * bdx != 0 {
                    continue;
                } // not parallel
                let len2 = adx * adx + ady * ady;
                if len2 == 0 {
                    continue;
                }
                let t = |px: i32, py: i32| {
                    (i128::from(px) - i128::from(a.x0)) * adx
                        + (i128::from(py) - i128::from(a.y0)) * ady
                };
                let (tb0, tb1) = (t(b.x0, b.y0), t(b.x1, b.y1));
                let lo = tb0.min(tb1).max(0);
                let hi = tb0.max(tb1).min(len2);
                if lo >= hi {
                    continue;
                } // no tangential overlap
                  // signed offset of b's line along a's left normal (−ady, adx): d×w
                let cross = adx * (i128::from(b.y0) - i128::from(a.y0))
                    - ady * (i128::from(b.x0) - i128::from(a.x0));
                let cross2 = cross
                    .checked_mul(cross)
                    .ok_or(ExactGeometryError::ArithmeticOverflow)?;
                let distance2 = cross2 / len2;
                let d = isqrt(
                    i64::try_from(distance2).map_err(|_| ExactGeometryError::ArithmeticOverflow)?,
                );
                // Middle of tangential overlap, halfway between the lines:
                // q = a0 + (v*(lo+hi) + normal*cross) / (2*|v|²).
                let denominator = len2
                    .checked_mul(2)
                    .ok_or(ExactGeometryError::ArithmeticOverflow)?;
                let tangent = lo + hi;
                let dx_num = adx
                    .checked_mul(tangent)
                    .and_then(|value| ady.checked_mul(cross).and_then(|n| value.checked_sub(n)))
                    .ok_or(ExactGeometryError::ArithmeticOverflow)?;
                let dy_num = ady
                    .checked_mul(tangent)
                    .and_then(|value| adx.checked_mul(cross).and_then(|n| value.checked_add(n)))
                    .ok_or(ExactGeometryError::ArithmeticOverflow)?;
                let mx_offset = round_ratio_i128(dx_num, denominator)?;
                let my_offset = round_ratio_i128(dy_num, denominator)?;
                let mx = checked_i32(i128::from(a.x0) + mx_offset)?;
                let my = checked_i32(i128::from(a.y0) + my_offset)?;
                (d, mx, my)
            };
            if d == 0 {
                continue;
            }
            if point_in_poly(store, p, mx, my) == interior {
                out.push((d, mx, my));
            }
        }
    }
    Ok(out)
}

pub(crate) fn midpoint_i32(
    a: i32,
    b: i32,
) -> Result<i32, gdsverify_core::exact::ExactGeometryError> {
    checked_i32((i128::from(a) + i128::from(b)) / 2)
}

pub(crate) fn checked_i32(value: i128) -> Result<i32, gdsverify_core::exact::ExactGeometryError> {
    i32::try_from(value).map_err(|_| gdsverify_core::exact::ExactGeometryError::ArithmeticOverflow)
}

pub(crate) fn round_ratio_i128(
    numerator: i128,
    denominator: i128,
) -> Result<i128, gdsverify_core::exact::ExactGeometryError> {
    use gdsverify_core::exact::ExactGeometryError;
    if denominator <= 0 {
        return Err(ExactGeometryError::ArithmeticOverflow);
    }
    let half = denominator / 2;
    if numerator >= 0 {
        numerator
            .checked_add(half)
            .map(|value| value / denominator)
            .ok_or(ExactGeometryError::ArithmeticOverflow)
    } else {
        numerator
            .checked_sub(half)
            .map(|value| value / denominator)
            .ok_or(ExactGeometryError::ArithmeticOverflow)
    }
}

pub(crate) fn push_geometry_capacity(
    store: &GeometryStore,
    lt: &LayerTable,
    polygon: PolyId,
    out: &mut Vec<Violation>,
) {
    let bbox = store.poly_bbox[polygon.0 as usize];
    out.push(Violation {
        rule_id: "__geometry__".into(),
        kind: "geometry_capacity".into(),
        layer: lt.name(store.poly_layer[polygon.0 as usize]).into(),
        measured: 1,
        limit: 0,
        x: bbox.xmin,
        y: bbox.ymin,
        hierarchy_path: None,
        source_polygons: Vec::new(),
        marker: None,
    });
}

/// Is polygon `inner` strictly inside polygon `outer`? All vertices strictly interior —
/// exact for the disjoint-boundary cases this is used on (a touching boundary counts as
/// "not strictly inside", which is the conservative answer for both callers).
pub(crate) fn poly_strictly_inside(store: &GeometryStore, inner: PolyId, outer: PolyId) -> bool {
    let polygon = |poly: PolyId| {
        gdsverify_core::exact::Polygon::from_outer(
            store
                .vertices(poly)
                .map(|(x, y)| gdsverify_core::exact::Point::new(x, y))
                .collect(),
        )
    };
    let (Ok(inner), Ok(outer)) = (polygon(inner), polygon(outer)) else {
        return false;
    };
    let inner_ring = inner.outer().vertices();
    let outer_ring = outer.outer().vertices();
    inner_ring.iter().all(|&point| {
        outer.classify_point(point) == gdsverify_core::exact::PointClassification::Inside
    }) && (0..inner_ring.len()).all(|i| {
        (0..outer_ring.len()).all(|j| {
            gdsverify_core::exact::classify_segment_intersection(
                inner_ring[i],
                inner_ring[(i + 1) % inner_ring.len()],
                outer_ring[j],
                outer_ring[(j + 1) % outer_ring.len()],
            ) == gdsverify_core::exact::SegmentIntersection::None
        })
    })
}

pub(crate) fn candidate_pairs(
    store: &GeometryStore,
    pa: &[PolyId],
    pb: Option<&[PolyId]>,
    min: i32,
) -> Vec<(PolyId, PolyId)> {
    crate::geometry::candidate_pairs(store, pa, pb, min)
}

// --- same-layer merge groups --------------------------------------------------
/// Union-find over a layer's polygons where touching/overlapping polys (distance
/// 0, directly or transitively) form one merged shape. Real DRC merges before
/// checking, so a sub-min gap between parts of one merged shape is not a
/// SPACING violation — it is a NOTCH of the merged compound, and
/// the min_spacing rule reports it as such so nothing escapes.
pub(crate) fn merge_groups(
    store: &GeometryStore,
    cands: &[(PolyId, PolyId)],
    far: Option<&Vec<bool>>,
    n_polys: usize,
    idx_of: &std::collections::HashMap<u32, u32>,
) -> Vec<u32> {
    let mut parent: Vec<u32> = (0..n_polys as u32).collect();
    fn find(parent: &mut [u32], x: u32) -> u32 {
        let mut r = x;
        while parent[r as usize] != r {
            parent[r as usize] = parent[parent[r as usize] as usize];
            r = parent[r as usize];
        }
        r
    }
    for (k, &(pa, pb)) in cands.iter().enumerate() {
        if far.is_some_and(|f| f[k]) {
            continue;
        } // clearly apart: cannot touch
        if poly_poly_dist2_within(store, pa, pb, 1) == 0 {
            let (ia, ib) = (idx_of[&pa.0], idx_of[&pb.0]);
            let (ra, rb) = (find(&mut parent, ia), find(&mut parent, ib));
            if ra != rb {
                parent[ra as usize] = rb;
            }
        }
    }
    (0..n_polys as u32).map(|i| find(&mut parent, i)).collect()
}

/// The open region between two near bboxes: the facing band when they overlap
/// on one axis, else the box between nearest corners.
pub(crate) fn gap_rect(a: Bbox, b: Bbox) -> Bbox {
    let ix0 = a.xmin.max(b.xmin);
    let ix1 = a.xmax.min(b.xmax);
    let iy0 = a.ymin.max(b.ymin);
    let iy1 = a.ymax.min(b.ymax);
    if ix1 > ix0 {
        // x-overlap, gap in y
        Bbox {
            xmin: ix0,
            ymin: a.ymax.min(b.ymax),
            xmax: ix1,
            ymax: a.ymin.max(b.ymin),
        }
    } else if iy1 > iy0 {
        Bbox {
            xmin: a.xmax.min(b.xmax),
            ymin: iy0,
            xmax: a.xmin.max(b.xmin),
            ymax: iy1,
        }
    } else {
        // diagonal: box between nearest corners
        Bbox {
            xmin: a.xmax.min(b.xmax),
            ymin: a.ymax.min(b.ymax),
            xmax: a.xmin.max(b.xmin),
            ymax: a.ymin.max(b.ymin),
        }
    }
}

/// True if a single OTHER polygon (rectangle) on the layer covers the whole
/// gap region between `pa` and `pb` — the merged shape is solid there.
pub(crate) fn gap_region_covered(
    store: &GeometryStore,
    polys: &[PolyId],
    pa: PolyId,
    pb: PolyId,
) -> bool {
    let g = gap_rect(
        store.poly_bbox[pa.0 as usize],
        store.poly_bbox[pb.0 as usize],
    );
    polys.iter().any(|&p| {
        if p == pa || p == pb {
            return false;
        }
        // rectangle covers == bbox covers; restrict to 4-vertex polys so an
        // L-shape's bbox cannot fake coverage
        let (s, e) = store.poly_range(p);
        if e - s != 4 {
            return false;
        }
        let b = store.poly_bbox[p.0 as usize];
        b.xmin <= g.xmin && b.ymin <= g.ymin && b.xmax >= g.xmax && b.ymax >= g.ymax
    })
}

/// Gap boxes of same-shape sub-min gaps (notches). Both sides belong to one
/// merged same-net shape, so filling the gap with metal is always electrically
/// safe — used as a post-merge DRC repair (pad-row corner slivers etc.).
pub fn same_shape_gap_fills(
    store: &GeometryStore,
    deck: &Deck,
) -> Result<Vec<(LayerId, Bbox)>, gdsverify_core::exact::ExactGeometryError> {
    if store.poly_count() > 0 {
        let mut extent = Bbox::empty();
        for bbox in &store.poly_bbox {
            extent.include(bbox.xmin, bbox.ymin);
            extent.include(bbox.xmax, bbox.ymax);
        }
        let required = extent.width_i64().max(extent.height_i64()).max(0);
        if required > i64::from(i32::MAX) || !legacy_rule_arithmetic_fits(&extent) {
            return Err(
                gdsverify_core::exact::ExactGeometryError::CapacityExceeded {
                    cells: usize::try_from(required).unwrap_or(usize::MAX),
                    limit: i32::MAX as usize,
                },
            );
        }
    }
    let mut fills = Vec::new();
    for r in &deck.drc_rules {
        let DrcRuleParam::MinSpacing { layer, min, .. } = r else {
            continue;
        };
        let (layer, min) = (*layer, *min);
        let polys: Vec<PolyId> = store.polys_on_layer(layer).collect();
        let min2 = (min as i64) * (min as i64);
        let cands = candidate_pairs(store, &polys, None, min);
        let idx_of: std::collections::HashMap<u32, u32> = polys
            .iter()
            .enumerate()
            .map(|(i, p)| (p.0, i as u32))
            .collect();
        let group = merge_groups(store, &cands, None, polys.len(), &idx_of);
        for &(pa, pb) in &cands {
            let d2 = poly_poly_dist2_within(store, pa, pb, min);
            if d2 == 0 || d2 >= min2 {
                continue;
            }
            if poly_strictly_inside(store, pa, pb) || poly_strictly_inside(store, pb, pa) {
                continue;
            }
            if group[idx_of[&pa.0] as usize] != group[idx_of[&pb.0] as usize] {
                continue; // different nets — not fillable
            }
            if gap_region_covered(store, &polys, pa, pb) {
                continue; // already solid
            }
            let g = gap_rect(
                store.poly_bbox[pa.0 as usize],
                store.poly_bbox[pb.0 as usize],
            );
            if g.xmax > g.xmin && g.ymax > g.ymin {
                // Inflate by min/2 so the fill overlaps both sides and is
                // itself min_width-clean; stays inside the pair's hull, where
                // foreign metal would already be a spacing violation.
                let h = i64::from(min / 2);
                let clamp =
                    |value: i64| value.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32;
                let fill = Bbox {
                    xmin: clamp(i64::from(g.xmin) - h),
                    ymin: clamp(i64::from(g.ymin) - h),
                    xmax: clamp(i64::from(g.xmax) + h),
                    ymax: clamp(i64::from(g.ymax) + h),
                };
                let required = fill.width_i64().max(fill.height_i64()).max(0);
                if required > i64::from(i32::MAX) {
                    return Err(
                        gdsverify_core::exact::ExactGeometryError::CapacityExceeded {
                            cells: usize::try_from(required).unwrap_or(usize::MAX),
                            limit: i32::MAX as usize,
                        },
                    );
                }
                fills.push((layer, fill));
            }
        }
    }
    Ok(fills)
}

// ponytail: GPU prefilter staged for phase-2 vulkano.
// The advisory f32 kernels (pt_seg_d2, edge_pair_near, facing_gap_near) and the
// session-based prefilters (gpu_far_mask, gpu_poly_clean_mask, edge_cols) were
// deleted with the cubecl/session seam. DRC already has the exact CPU predicate
// path these prefiltered for (candidate_pairs + poly_poly_dist2_within +
// facing_gaps); rules route straight to it.

/// Min squared distance between two polygons' edge sets, exact below `cutoff`.
/// Returns exactly `cutoff²` when the true distance is >= cutoff — every caller
/// only branches on distances below its rule limit, so the far side needs no
/// precision. Bounding the search is what kills the |Ea|×|Eb| blowup: b-edges
/// are bucketed on a uniform grid and each a-edge only visits buckets within
/// `cutoff` of its bbox. Two 16k-edge interlocked combs drop from 256M seg-seg
/// evaluations to ~zero when nothing is within the limit.
pub(crate) fn poly_poly_dist2_within(
    store: &GeometryStore,
    pa: PolyId,
    pb: PolyId,
    cutoff: i32,
) -> i64 {
    poly_poly_dist2_within_wide(store, pa, pb, i64::from(cutoff))
}

pub(crate) fn poly_poly_dist2_within_wide(
    store: &GeometryStore,
    pa: PolyId,
    pb: PolyId,
    cutoff: i64,
) -> i64 {
    let ea = poly_edges(store, pa);
    let eb = poly_edges(store, pb);
    let cutoff = cutoff.max(1);
    let cut2 = cutoff.checked_mul(cutoff).unwrap_or(i64::MAX);

    // small pairs (rects vs rects): brute force beats grid setup
    if ea.len() * eb.len() <= 1024 {
        let mut best = cut2;
        for x in &ea {
            for y in &eb {
                best = best.min(seg_seg_dist2(x, y));
                if best == 0 {
                    return 0;
                }
            }
        }
        return best;
    }

    // bucket b-edges by bbox on a cutoff-sized grid. The floor keeps tiny cutoffs
    // (the touch test uses 1nm) from exploding long edges into thousands of cells.
    let cell = cutoff.saturating_mul(4).max(512);
    let key = |x: i64, y: i64| ((x.div_euclid(cell)) as i32, (y.div_euclid(cell)) as i32);
    let mut grid: std::collections::HashMap<(i32, i32), Vec<u32>> =
        std::collections::HashMap::new();
    for (j, e) in eb.iter().enumerate() {
        let (x0, x1) = (e.x0.min(e.x1) as i64, e.x0.max(e.x1) as i64);
        let (y0, y1) = (e.y0.min(e.y1) as i64, e.y0.max(e.y1) as i64);
        let (kx0, ky0) = key(x0, y0);
        let (kx1, ky1) = key(x1, y1);
        for kx in kx0..=kx1 {
            for ky in ky0..=ky1 {
                grid.entry((kx, ky)).or_default().push(j as u32);
            }
        }
    }

    let mut best = cut2;
    let mut stamp = vec![u32::MAX; eb.len()]; // dedupe candidates per a-edge
    for (i, a) in ea.iter().enumerate() {
        let (ax0, ax1) = (a.x0.min(a.x1) as i64, a.x0.max(a.x1) as i64);
        let (ay0, ay1) = (a.y0.min(a.y1) as i64, a.y0.max(a.y1) as i64);
        let (kx0, ky0) = key(ax0.saturating_sub(cutoff), ay0.saturating_sub(cutoff));
        let (kx1, ky1) = key(ax1.saturating_add(cutoff), ay1.saturating_add(cutoff));
        for kx in kx0..=kx1 {
            for ky in ky0..=ky1 {
                let Some(cands) = grid.get(&(kx, ky)) else {
                    continue;
                };
                for &j in cands {
                    if stamp[j as usize] == i as u32 {
                        continue;
                    }
                    stamp[j as usize] = i as u32;
                    let b = &eb[j as usize];
                    // bbox lower bound before the exact kernel
                    let (bx0, bx1) = (b.x0.min(b.x1) as i64, b.x0.max(b.x1) as i64);
                    let (by0, by1) = (b.y0.min(b.y1) as i64, b.y0.max(b.y1) as i64);
                    let dx = (bx0 - ax1).max(ax0 - bx1).max(0);
                    let dy = (by0 - ay1).max(ay0 - by1).max(0);
                    if dx * dx + dy * dy >= best {
                        continue;
                    }
                    best = best.min(seg_seg_dist2(a, b));
                    if best == 0 {
                        return 0;
                    }
                }
            }
        }
    }
    best
}

pub(crate) fn poly_edges(store: &GeometryStore, p: PolyId) -> Vec<Edge> {
    store.edges_of(p).collect()
}

/// Extract actual keyhole cycles from a single GDS boundary walk. Separate
/// same-polarity boundaries are filled material, never negative-space evidence.
/// Shared by the min_enclosed_area and cheesing rules.
pub(crate) fn keyhole_hole_rings(
    store: &GeometryStore,
    polygon: PolyId,
) -> Vec<gdsverify_core::exact::Ring> {
    store
        .poly_as_exact(polygon)
        .map(|component| component.holes().to_vec())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_shape_gap_repairs_saturate_at_min_and_report_wide_capacity() {
        let deck = Deck::from_json(
            r#"{"layers":{"m1":{"layer":1,"datatype":0}},"drc":{
                "S":{"kind":"min_spacing","layer":"m1","min":10}}}"#,
        )
        .unwrap();
        let layer = deck.layers.id("m1").unwrap();

        let base = i32::MIN + 1;
        let mut near_min = GeometryStore::new();
        near_min.add_rect(layer, base, base, 10, 10);
        near_min.add_rect(layer, base + 15, base, 10, 10);
        near_min.add_rect(layer, base, base + 8, 25, 2);
        let fills = same_shape_gap_fills(&near_min, &deck).unwrap();
        assert_eq!(fills.len(), 1);
        assert_eq!(fills[0].1.ymin, i32::MIN);

        let mut too_wide = GeometryStore::new();
        too_wide.add_polygon(
            layer,
            &[(0, i32::MIN), (10, i32::MIN), (10, i32::MAX), (0, i32::MAX)],
        );
        too_wide.add_polygon(
            layer,
            &[
                (15, i32::MIN),
                (25, i32::MIN),
                (25, i32::MAX),
                (15, i32::MAX),
            ],
        );
        too_wide.add_rect(layer, 0, 0, 25, 1);
        assert!(matches!(
            same_shape_gap_fills(&too_wide, &deck),
            Err(gdsverify_core::exact::ExactGeometryError::CapacityExceeded { .. })
        ));
    }
}
