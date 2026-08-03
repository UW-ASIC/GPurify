//! Layouts containing exactly one deliberate violation, at a known coordinate,
//! with a known measurement.
//!
//! The oracle is construct-from-answer. Nothing here runs a rule; the geometry
//! is placed so that only one answer is arithmetically available, and the
//! [`Violation`] that comes back is that answer written down.
//!
//! # This module fixes the reported coordinate
//!
//! A rule could report a spacing violation at either shape's edge, at the gap's
//! midpoint, or at a corner, and every one of those is defensible. The suite
//! cannot assert on a coordinate until one of them is chosen, so it is chosen
//! here: **`at` is the midpoint of the thing being measured** — the middle of a
//! gap, the centre of an area, the midpoint of an edge, the middle of an
//! overlap. Each variant below says which. The Implementation-Phase satisfies
//! that; a rule reporting a different point is failing a test, not revealing a
//! bad test.
//!
//! # Which of the twenty-six rules each shape serves
//!
//! Eighteen shapes rather than twenty-six because several rules measure the
//! same configuration and differ only in which limit they apply to it.
//!
//! | Shape | Rules |
//! |---|---|
//! | [`ShapeKind::Width`] | `min_width`, `max_width`, `cheesing` |
//! | [`ShapeKind::EdgeLength`] | `min_edge_length` |
//! | [`ShapeKind::Spacing`] | `min_spacing`, `min_spacing_diff`, `prl_spacing`, `wide_dependent_spacing`, `via_array_spacing` |
//! | [`ShapeKind::Notch`] | `notch` |
//! | [`ShapeKind::EndOfLine`] | `eol_spacing` |
//! | [`ShapeKind::CornerToCorner`] | `corner_to_corner` |
//! | [`ShapeKind::Area`] | `min_area` |
//! | [`ShapeKind::EnclosedArea`] | `min_enclosed_area` |
//! | [`ShapeKind::Enclosure`] | `min_enclosure`, `asymmetric_enclosure` |
//! | [`ShapeKind::Extension`] | `min_extension` |
//! | [`ShapeKind::Overlap`] | `overlap` |
//! | [`ShapeKind::Separation`] | `max_distance_to_tap` |
//! | [`ShapeKind::OffGrid`] | `off_grid` |
//! | [`ShapeKind::Angle`] | `angle` |
//! | [`ShapeKind::Density`] | `density` |
//! | [`ShapeKind::Antenna`] | `antenna`, `antenna_car` |
//! | [`ShapeKind::ViaArray`] | `redundant_via` |
//! | [`ShapeKind::OddCycle`] | `multi_patterning` |

use gpurify_core::{GeometryStore, LayerId};
use gpurify_ingest::StrId;
use gpurify_report::{Measurement, Severity, Violation};
use gpurify_units::{prefix, Current, Qty, Resistance, Voltage};

use crate::shapes::{
    area, dbu, hole, point, rect, u_shape, Handle, Ids, LayoutBuilder,
};

/// A measured quantity in the plain integers this crate computes in.
///
/// [`Measurement`] wraps `Dbu` and `DbuArea`, whose accessors are frozen
/// signatures with `todo!()` bodies until the Implementation-Phase — so a
/// generator handed a `Measurement` could not read the number back out of it.
/// This is the same set of cases in types the generator can do arithmetic on,
/// and [`Amount::measurement`] is the one-way conversion.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Amount {
    /// A distance in database units.
    Length(i64),
    /// An area in database units squared.
    Area(i128),
    /// Dimensionless: an antenna ratio, a density fraction, an angle in
    /// degrees.
    Ratio(f64),
    /// A count of things.
    Count(u32),
    /// Millivolts, microamps, ohms — the fixed prefixes `report::measure`
    /// chose so a report column has one scale.
    Millivolts(f64),
    Microamps(f64),
    Ohms(f64),
}

impl Amount {
    /// The frozen form.
    #[must_use]
    pub fn measurement(self) -> Measurement {
        match self {
            Self::Length(v) => Measurement::Length(dbu(v)),
            Self::Area(v) => Measurement::Area(area(v)),
            Self::Ratio(v) => Measurement::Ratio(v),
            Self::Count(v) => Measurement::Count(v),
            Self::Millivolts(v) => {
                Measurement::Voltage(Qty::<Voltage, { prefix::MILLI }>::new(v))
            }
            Self::Microamps(v) => Measurement::Current(Qty::<Current, { prefix::MICRO }>::new(v)),
            Self::Ohms(v) => Measurement::Resistance(Qty::<Resistance, { prefix::BASE }>::new(v)),
        }
    }

    /// # Panics
    ///
    /// When the amount is not a length. A generator asked to realise a spacing
    /// of "3.5 ohms" has been handed a test that does not mean anything, and
    /// saying so loudly beats building geometry that ignores half the request.
    fn length(self, what: &str) -> i64 {
        match self {
            Self::Length(v) => v,
            other => panic!("{what} needs a Length, got {other:?}"),
        }
    }

    /// # Panics
    ///
    /// When the amount is not an area.
    fn area(self, what: &str) -> i128 {
        match self {
            Self::Area(v) => v,
            other => panic!("{what} needs an Area, got {other:?}"),
        }
    }

    /// # Panics
    ///
    /// When the amount is not a ratio.
    fn ratio(self, what: &str) -> f64 {
        match self {
            Self::Ratio(v) => v,
            other => panic!("{what} needs a Ratio, got {other:?}"),
        }
    }

    /// # Panics
    ///
    /// When the amount is not a count.
    fn count(self, what: &str) -> u32 {
        match self {
            Self::Count(v) => v,
            other => panic!("{what} needs a Count, got {other:?}"),
        }
    }
}

/// What to build, and which rule is expected to find it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ViolationShape {
    /// The deck's id for the rule under test, interned by the caller.
    pub rule: StrId,
    pub severity: Severity,
    pub kind: ShapeKind,
}

/// The geometric configuration to realise.
///
/// Every field is a *secondary* dimension — one the measurement does not pin
/// down. The measured quantity itself comes from `measured`, so a caller states
/// the number the rule must report and this decides everything else.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ShapeKind {
    /// A rectangle `measured` wide and `run` long. `at` is its centre.
    ///
    /// Two shapes' worth of rules use this: a width limit measured across the
    /// narrow span, and `cheesing`, where a large `run` makes an unslotted
    /// plate.
    Width { layer: LayerId, run: i64 },

    /// A rectangle whose bottom edge is exactly `measured` long, standing
    /// `body` tall. `at` is the midpoint of that edge.
    EdgeLength { layer: LayerId, body: i64 },

    /// Two `extent`-sided squares on one layer, facing across a gap of
    /// `measured`. `at` is the midpoint of the gap.
    Spacing { layer: LayerId, extent: i64 },

    /// A U whose internal gap is `measured`. `at` is the centre of the notch
    /// void, which is inside the polygon's bounding box and outside the
    /// polygon — the coordinate a viewer needs and a bounding-box
    /// implementation cannot produce.
    Notch {
        layer: LayerId,
        arm: i64,
        thickness: i64,
    },

    /// A line `width` wide whose end faces a wide neighbour across
    /// `measured`. `at` is the midpoint of the gap. Distinct from
    /// [`ShapeKind::Spacing`] because the rule's limit applies only to the
    /// narrow end, which is a property of the shape and not of the gap.
    EndOfLine {
        layer: LayerId,
        width: i64,
        extent: i64,
    },

    /// Two `size`-sided squares whose nearest corners are `legs` apart on the
    /// two axes. `at` is the midpoint of the corner-to-corner segment.
    ///
    /// `legs` must be a Pythagorean pair for `measured`: an exact diagonal
    /// distance between integer coordinates exists only then, and a test
    /// asserting on a rounded one is asserting on the rounding.
    CornerToCorner {
        layer: LayerId,
        size: i64,
        legs: (i64, i64),
    },

    /// A rectangle of area `measured` and width `width`. `at` is its centre.
    Area { layer: LayerId, width: i64 },

    /// A ring whose hole has area `measured`, of width `hole_width`, with
    /// `margin` of material around it. `at` is the centre of the hole.
    EnclosedArea {
        layer: LayerId,
        margin: i64,
        hole_width: i64,
    },

    /// An `inner_size` square on `inner`, enclosed by a shape on `outer` that
    /// clears it by `measured` on the left and generously elsewhere. `at` is
    /// the midpoint of the deficient margin.
    Enclosure {
        outer: LayerId,
        inner: LayerId,
        inner_size: i64,
    },

    /// A line on `line` crossing a bar on `crossed` and running past it by
    /// `measured`. `at` is the midpoint of the overhanging stub.
    Extension {
        line: LayerId,
        crossed: LayerId,
        width: i64,
    },

    /// Two rectangles on two layers overlapping by `measured` in x. `at` is the
    /// centre of the overlap.
    Overlap {
        a: LayerId,
        b: LayerId,
        extent: i64,
    },

    /// A shape on `a` and a shape on `b`, `measured` apart. `at` is the
    /// midpoint of the gap. The cross-layer twin of [`ShapeKind::Spacing`],
    /// for the rule that asks how far a device is from its nearest tap.
    Separation {
        a: LayerId,
        b: LayerId,
        size: i64,
    },

    /// A `size` square whose lower-left corner sits `measured` off a `grid`
    /// multiple. `at` is that corner — the offending vertex, not the shape's
    /// centre, because there is nothing else to point at.
    OffGrid {
        layer: LayerId,
        size: i64,
        grid: i64,
    },

    /// A right triangle whose hypotenuse rises `run.1` over `run.0`, making an
    /// angle of `measured` degrees. `at` is the vertex the offending edge
    /// leaves from.
    Angle { layer: LayerId, run: (i64, i64) },

    /// A `window`-sided window holding `filled` squares of side `cell`, so the
    /// covered fraction is `measured`. `at` is the centre of the window.
    Density {
        layer: LayerId,
        window: i64,
        cell: i64,
        filled: u32,
    },

    /// A `gate_side` square on `gate` overlapped by a metal square on `metal`,
    /// sized so the area ratio is `measured`. `at` is the centre of the gate.
    Antenna {
        gate: LayerId,
        metal: LayerId,
        gate_side: i64,
    },

    /// `measured` cut squares of side `size` in a row at `pitch`. `at` is the
    /// centre of the first cut. One cut is the `redundant_via` violation; two
    /// at a short pitch is the array-spacing one.
    ViaArray {
        cut: LayerId,
        size: i64,
        pitch: i64,
    },

    /// Three `size` squares, pairwise within `gap` on both axes — an odd cycle
    /// in the conflict graph, so no two-colouring exists. `at` is the centre of
    /// the first square. `measured` is the cycle length, three.
    OddCycle {
        layer: LayerId,
        size: i64,
        gap: i64,
    },
}

/// A layout with one violation in it, and the violation.
#[derive(Debug)]
pub struct ViolationCase {
    pub store: GeometryStore,
    /// Resolves the handles below, for a test that wants to name a shape the
    /// expected violation does not.
    pub ids: Ids,
    /// The one violation the rule must report.
    pub expected: Violation,
    /// Every shape in the layout. A `RuleRun::examined` assertion is written
    /// against this: a rule that reports the violation but examined fewer
    /// shapes than exist has pruned something it should not have.
    pub shapes: u32,
}

/// Build a layout whose only violation is the stated one.
///
/// # Panics
///
/// When the measurement cannot be realised exactly on an integer grid — an odd
/// gap, an area that does not divide by the requested width, a corner distance
/// that is not the hypotenuse of the stated legs. Every one of those is a test
/// asking for a coordinate that does not exist, and rounding it would make the
/// expected answer a fiction.
#[must_use]
pub fn layout_with_violation(
    kind: ViolationShape,
    at: (i64, i64),
    measured: Amount,
    limit: Amount,
) -> ViolationCase {
    let mut layout = LayoutBuilder::new(layer_count(kind.kind));
    let (a, b) = build(&mut layout, kind.kind, at, measured);
    let shapes = layout.len();
    let (store, ids) = layout.finish();
    let expected = Violation {
        rule: kind.rule,
        layer: primary_layer(kind.kind),
        severity: kind.severity,
        at: point(at.0, at.1),
        measured: measured.measurement(),
        limit: limit.measurement(),
        shapes: (ids.of(a), b.map(|h| ids.of(h))),
    };
    ViolationCase {
        store,
        ids,
        expected,
        shapes,
    }
}

/// The layer a violation is reported against: the first one the shape names.
fn primary_layer(kind: ShapeKind) -> LayerId {
    match kind {
        ShapeKind::Width { layer, .. }
        | ShapeKind::EdgeLength { layer, .. }
        | ShapeKind::Spacing { layer, .. }
        | ShapeKind::Notch { layer, .. }
        | ShapeKind::EndOfLine { layer, .. }
        | ShapeKind::CornerToCorner { layer, .. }
        | ShapeKind::Area { layer, .. }
        | ShapeKind::EnclosedArea { layer, .. }
        | ShapeKind::OffGrid { layer, .. }
        | ShapeKind::Angle { layer, .. }
        | ShapeKind::Density { layer, .. }
        | ShapeKind::OddCycle { layer, .. } => layer,
        ShapeKind::Enclosure { inner, .. } => inner,
        ShapeKind::Extension { line, .. } => line,
        ShapeKind::Overlap { a, .. } | ShapeKind::Separation { a, .. } => a,
        ShapeKind::Antenna { gate, .. } => gate,
        ShapeKind::ViaArray { cut, .. } => cut,
    }
}

/// The second layer, where the shape uses one.
fn secondary_layer(kind: ShapeKind) -> Option<LayerId> {
    match kind {
        ShapeKind::Enclosure { outer, .. } => Some(outer),
        ShapeKind::Extension { crossed, .. } => Some(crossed),
        ShapeKind::Overlap { b, .. } | ShapeKind::Separation { b, .. } => Some(b),
        ShapeKind::Antenna { metal, .. } => Some(metal),
        _ => None,
    }
}

/// A layer table just wide enough for the layers the shape names.
fn layer_count(kind: ShapeKind) -> usize {
    let primary = primary_layer(kind).idx();
    let secondary = secondary_layer(kind).map_or(0, LayerId::idx);
    primary.max(secondary) + 1
}

/// Half of an even span.
///
/// # Panics
///
/// When the span is not positive and even. Everything this module centres on a
/// coordinate needs an exact midpoint, and there is no integer midpoint of an
/// odd span — so the alternative is an expected coordinate off by half a unit,
/// which is exactly the class of silent error the suite exists to catch.
fn half(span: i64, what: &str) -> i64 {
    assert!(
        span > 0 && span % 2 == 0,
        "{what} is {span}; it must be positive and even so its midpoint is a coordinate"
    );
    span / 2
}

#[allow(
    clippy::too_many_lines,
    reason = "one arm per rule-shape family; splitting the match would spread \
              eighteen four-line constructions over eighteen functions and make \
              the coordinate conventions harder to read side by side, which is \
              the one thing a reader of this file comes for"
)]
fn build(
    layout: &mut LayoutBuilder,
    kind: ShapeKind,
    at: (i64, i64),
    measured: Amount,
) -> (Handle, Option<Handle>) {
    let (ax, ay) = at;
    match kind {
        ShapeKind::Width { layer, run } => {
            let w = half(measured.length("a width"), "the width");
            let h = half(run, "the run");
            (layout.rect(layer, ax - w, ay - h, ax + w, ay + h), None)
        }

        ShapeKind::EdgeLength { layer, body } => {
            let e = half(measured.length("an edge length"), "the edge length");
            assert!(body > 0, "the body height must be positive");
            (layout.rect(layer, ax - e, ay, ax + e, ay + body), None)
        }

        ShapeKind::Spacing { layer, extent } => {
            let (a, b) = crate::shapes::spaced_pair(
                layout,
                layer,
                at,
                measured.length("a spacing"),
                extent,
            );
            (a, Some(b))
        }

        ShapeKind::Notch {
            layer,
            arm,
            thickness,
        } => {
            let gap = measured.length("a notch");
            let g = half(gap, "the notch");
            // The void spans y from y0 + thickness to y0 + arm, so its centre is
            // y0 + (thickness + arm) / 2 and centring it on `ay` fixes y0.
            let y0 = ay - half(thickness + arm, "the notch void span");
            let x0 = ax - g - thickness;
            (
                layout.shape(layer, &u_shape(x0, y0, arm, thickness, gap)),
                None,
            )
        }

        ShapeKind::EndOfLine {
            layer,
            width,
            extent,
        } => {
            let g = half(measured.length("an end-of-line spacing"), "the spacing");
            let w = half(width, "the line width");
            assert!(extent > 0, "the extent must be positive");
            let line = layout.rect(layer, ax - w, ay - g - extent, ax + w, ay - g);
            let facing = layout.rect(layer, ax - extent, ay + g, ax + extent, ay + g + extent);
            (line, Some(facing))
        }

        ShapeKind::CornerToCorner { layer, size, legs } => {
            let d = measured.length("a corner distance");
            assert_eq!(
                legs.0 * legs.0 + legs.1 * legs.1,
                d * d,
                "legs {legs:?} are not the legs of a right triangle with hypotenuse {d}"
            );
            let (dx, dy) = (half(legs.0, "the x leg"), half(legs.1, "the y leg"));
            assert!(size > 0, "the square side must be positive");
            let a = layout.rect(layer, ax - dx - size, ay - dy - size, ax - dx, ay - dy);
            let b = layout.rect(layer, ax + dx, ay + dy, ax + dx + size, ay + dy + size);
            (a, Some(b))
        }

        ShapeKind::Area { layer, width } => {
            let target = measured.area("an area");
            assert!(width > 0, "the width must be positive");
            assert_eq!(
                target % i128::from(width),
                0,
                "area {target} is not a whole number of {width}-wide rows"
            );
            let height = i64::try_from(target / i128::from(width))
                .expect("the derived height exceeds the coordinate domain");
            let (w, h) = (half(width, "the width"), half(height, "the height"));
            (layout.rect(layer, ax - w, ay - h, ax + w, ay + h), None)
        }

        ShapeKind::EnclosedArea {
            layer,
            margin,
            hole_width,
        } => {
            let target = measured.area("an enclosed area");
            assert!(margin > 0 && hole_width > 0, "margin and width are positive");
            assert_eq!(
                target % i128::from(hole_width),
                0,
                "hole area {target} is not a whole number of {hole_width}-wide rows"
            );
            let hole_height = i64::try_from(target / i128::from(hole_width))
                .expect("the derived hole height exceeds the coordinate domain");
            let (w, h) = (
                half(hole_width, "the hole width"),
                half(hole_height, "the hole height"),
            );
            let outer = layout.shape(
                layer,
                &rect(ax - w - margin, ay - h - margin, ax + w + margin, ay + h + margin),
            );
            layout.shape(layer, &hole(ax - w, ay - h, ax + w, ay + h));
            (outer, None)
        }

        ShapeKind::Enclosure {
            outer,
            inner,
            inner_size,
        } => {
            let enc = measured.length("an enclosure");
            let e = half(enc, "the enclosure");
            assert!(inner_size > 0, "the inner square side must be positive");
            // The deficient margin is on the left, centred on `at`; every other
            // side clears by a full inner width so only one margin is short.
            let left = ax + e;
            let bottom = ay - inner_size / 2;
            let top = bottom + inner_size;
            let inner_handle = layout.rect(inner, left, bottom, left + inner_size, top);
            let outer_handle = layout.rect(
                outer,
                left - enc,
                bottom - inner_size,
                left + 2 * inner_size,
                top + inner_size,
            );
            (inner_handle, Some(outer_handle))
        }

        ShapeKind::Extension {
            line,
            crossed,
            width,
        } => {
            let ext = measured.length("an extension");
            let e = half(ext, "the extension");
            let w = half(width, "the line width");
            let bar = layout.rect(crossed, ax - e - width, ay - 2 * width, ax - e, ay + 2 * width);
            let stripe = layout.rect(line, ax - e - 3 * width, ay - w, ax + e, ay + w);
            (stripe, Some(bar))
        }

        ShapeKind::Overlap { a, b, extent } => {
            let ov = measured.length("an overlap");
            let o = half(ov, "the overlap");
            let h = half(extent, "the extent");
            let left = layout.rect(a, ax - extent, ay - h, ax + o, ay + h);
            let right = layout.rect(b, ax - o, ay - h, ax + extent, ay + h);
            (left, Some(right))
        }

        ShapeKind::Separation { a, b, size } => {
            let g = half(measured.length("a separation"), "the separation");
            assert!(size > 0, "the shape side must be positive");
            let left = layout.rect(a, ax - g - size, ay - size, ax - g, ay + size);
            let right = layout.rect(b, ax + g, ay - size, ax + g + size, ay + size);
            (left, Some(right))
        }

        ShapeKind::OffGrid { layer, size, grid } => {
            let off = measured.length("a grid offset");
            assert!(grid > 0 && size > 0, "grid and size are positive");
            assert_eq!(
                ax.rem_euclid(grid),
                off,
                "the corner at x = {ax} is not {off} off a multiple of {grid}"
            );
            (layout.rect(layer, ax, ay, ax + size, ay + size), None)
        }

        ShapeKind::Angle { layer, run } => {
            let degrees = measured.ratio("an angle");
            assert!(run.0 != 0 && run.1 != 0, "an axis-aligned run has no angle");
            #[allow(
                clippy::cast_precision_loss,
                reason = "an edge vector is a layout dimension, far below 2^53"
            )]
            let actual = (run.1 as f64).atan2(run.0 as f64).to_degrees();
            assert!(
                (actual - degrees).abs() < 1e-9,
                "the run {run:?} subtends {actual} degrees, not {degrees}"
            );
            (
                layout.push(
                    layer,
                    &[ax, ax + run.0, ax + run.0],
                    &[ay, ay + run.1, ay],
                ),
                None,
            )
        }

        ShapeKind::Density {
            layer,
            window,
            cell,
            filled,
        } => {
            let fraction = measured.ratio("a density");
            assert!(window > 0 && cell > 0, "window and cell are positive");
            let covered = f64::from(filled) * cell_area(cell);
            #[allow(
                clippy::cast_precision_loss,
                reason = "a window side is a layout dimension, far below 2^53"
            )]
            let window_area = (window as f64) * (window as f64);
            assert!(
                (covered / window_area - fraction).abs() < 1e-12,
                "{filled} cells of side {cell} in a {window} window is {} of it, not {fraction}",
                covered / window_area
            );
            // Row-major inside the window, one clear unit between cells so they
            // stay distinct polygons.
            let per_row = window / (cell + 1);
            assert!(per_row > 0, "a {cell} cell does not fit a {window} window");
            let corner = half(window, "the window");
            let origin = (ax - corner, ay - corner);
            let mut first = None;
            for i in 0..filled {
                let (col, row) = (i64::from(i) % per_row, i64::from(i) / per_row);
                assert!(
                    (row + 1) * (cell + 1) <= window,
                    "{filled} cells of side {cell} do not fit a {window} window"
                );
                let x = origin.0 + col * (cell + 1);
                let y = origin.1 + row * (cell + 1);
                let handle = layout.rect(layer, x, y, x + cell, y + cell);
                first.get_or_insert(handle);
            }
            (first.expect("a density case needs at least one shape"), None)
        }

        ShapeKind::Antenna {
            gate,
            metal,
            gate_side,
        } => {
            let ratio = measured.ratio("an antenna ratio");
            assert!(gate_side > 0, "the gate side must be positive");
            let gate_area = cell_area(gate_side);
            let metal_area = gate_area * ratio;
            let metal_side = metal_area.sqrt();
            #[allow(
                clippy::cast_possible_truncation,
                reason = "the side is checked against the exact ratio immediately below"
            )]
            let metal_side = metal_side.round() as i64;
            assert!(
                (cell_area(metal_side) / gate_area - ratio).abs() < 1e-12,
                "no integer metal side gives a ratio of exactly {ratio} against a \
                 {gate_side} gate; pick a ratio that is a square of a rational"
            );
            let g = half(gate_side, "the gate side");
            let m = half(metal_side, "the derived metal side");
            let gate_handle = layout.rect(gate, ax - g, ay - g, ax + g, ay + g);
            let metal_handle = layout.rect(metal, ax - m, ay - m, ax + m, ay + m);
            (gate_handle, Some(metal_handle))
        }

        ShapeKind::ViaArray { cut, size, pitch } => {
            let cuts = measured.count("a via count");
            assert!(cuts > 0, "an array needs at least one cut");
            assert!(size > 0 && pitch > size, "pitch must exceed the cut side");
            let s = half(size, "the cut side");
            let mut first = None;
            for i in 0..i64::from(cuts) {
                let cx = ax + i * pitch;
                let handle = layout.rect(cut, cx - s, ay - s, cx + s, ay + s);
                first.get_or_insert(handle);
            }
            (first.expect("at least one cut"), None)
        }

        ShapeKind::OddCycle { layer, size, gap } => {
            assert_eq!(
                measured.count("an odd cycle"),
                3,
                "the smallest odd cycle is three; longer ones are a different case"
            );
            assert!(size > 0 && gap > 0, "size and gap are positive");
            let s = half(size, "the square side");
            let step = size + gap;
            // Three squares at the corners of an L. The two axis-aligned pairs
            // are `gap` apart by construction, and the diagonal pair is `gap`
            // apart on both axes — so all three conflict and no two-colouring
            // exists.
            let a = layout.rect(layer, ax - s, ay - s, ax + s, ay + s);
            let b = layout.rect(layer, ax - s + step, ay - s, ax + s + step, ay + s);
            layout.rect(layer, ax - s, ay - s + step, ax + s, ay + s + step);
            (a, Some(b))
        }
    }
}

/// The area of a square of the given side, as an `f64`.
#[allow(
    clippy::cast_precision_loss,
    reason = "a layout dimension is far below 2^53, so the square is exact to \
              well past the tolerances used against it"
)]
fn cell_area(side: i64) -> f64 {
    (side as f64) * (side as f64)
}

#[cfg(test)]
mod tests {
    use super::{half, Amount};

    /// Oracle: closed form. The midpoint of an even span is exact, and an odd
    /// span has none — the generator must refuse the second rather than round
    /// it, because a rounded expected coordinate is a test that cannot fail
    /// for the right reason.
    #[test]
    fn half_refuses_a_span_with_no_integer_midpoint() {
        assert_eq!(half(40, "a gap"), 20);
        assert!(std::panic::catch_unwind(|| half(41, "a gap")).is_err());
        assert!(std::panic::catch_unwind(|| half(0, "a gap")).is_err());
    }

    /// Oracle: construct-from-answer. An `Amount` must survive the trip into a
    /// `Measurement` unchanged for the geometric cases, which are the ones
    /// every DRC assertion compares on. The electrical cases cannot be checked
    /// here: `Qty`'s comparison is a frozen signature with a `todo!()` body.
    #[test]
    fn geometric_amounts_convert_to_the_measurement_they_name() {
        use gpurify_report::Measurement;
        assert!(matches!(
            Amount::Ratio(0.25).measurement(),
            Measurement::Ratio(v) if (v - 0.25).abs() < f64::EPSILON
        ));
        assert!(matches!(
            Amount::Count(7).measurement(),
            Measurement::Count(7)
        ));
    }

    /// Oracle: construct-from-answer. Asking for a spacing in ohms is a broken
    /// test, and the generator says so instead of building something that
    /// ignores half the request.
    #[test]
    fn an_amount_of_the_wrong_dimension_is_refused() {
        assert!(std::panic::catch_unwind(|| Amount::Ohms(3.5).length("a spacing")).is_err());
        assert!(std::panic::catch_unwind(|| Amount::Length(3).area("an area")).is_err());
    }
}
