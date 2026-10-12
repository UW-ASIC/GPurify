//! The rule set: one [`Rule`] per deck row, the deck parser, and the driver.

use crate::drc::rules::{
    area, edge, facing, grid, overlay, pattern, patterning, presence, spacing, via, width,
};
use crate::drc::{DrcError, Scratch};
use crate::report::{
    record_run, LimitSense, Measurement, Outcome, RuleRun, Severity, Violation, Violations,
};
use crate::topology::NetTable;
use gpurify_geom::{Bbox, Dbu, DbuArea, GeometryStore, LayerId};
use gpurify_ingest::deck::{Deck, ParamValue, RuleSpec};
use gpurify_ingest::{StrId, StrTable};

/// One configured DRC rule: a deck row, typed. [`RuleSet::from_deck`] builds
/// it and [`RuleSet::run`] checks it.
///
/// # What every variant keeps
///
/// - Lengths are in grid units (the layout's database unit), areas in square
///   grid units. Every limit is positive; [`Rule::validate`] refuses
///   anything else.
/// - A value exactly at its limit passes. Only a strict excess violates.
/// - "Merged" means that shapes on the layer that touch or overlap become one
///   figure before the rule looks at them. Meeting only at a corner is
///   touching: the corner joins the two into one figure, as a neck of width
///   0, and empty space does not pass it, so a ring closed only at a corner
///   encloses a hole ([`gpurify_geom::boolean::union_into`]'s corner model).
///   Every variant that groups shapes into figures, spacing included, reads
///   them this way, and so does net extraction.
/// - A distance between shapes is Euclidean, boundary to boundary, unless the
///   variant says otherwise. The comparison is exact. `measured` is floored to
///   a whole grid unit, so a report never overstates a gap.
/// - A pair's "measured points" are the two nearest points of what the
///   variant measured between the pair, one on each side, and the finding
///   sits at their midpoint (floored to the grid). Where the two run
///   alongside each other at that distance, the nearest points are a
///   stretch, and the finding sits at its middle; among several nearest
///   stretches the longest. A stretch is whole however the sides along it
///   were cut (a collinear vertex, or the rectangles a part is cut into):
///   collinear pieces that touch are one. So a marker lies in the gap that
///   was measured, not where the shapes' bounding boxes face. Equally long
///   stretches are one answer, not a pick by drawing order: the finding sits
///   at the middle of the box bounding their midpoints, which is between
///   them on their line when they share one. Stretches on different lines
///   put it between them: two crossing shapes, measured 0 at the points
///   where their boundaries cross, are marked in the middle of those points,
///   and a pair symmetric across a diagonal (a square tucked into an L's
///   corner) on that diagonal, off the gap. A marker that maps with the
///   layout under every symmetry of the square cannot pick a side.
/// - `shapes` names store rows ([`PolyId`](gpurify_geom::PolyId)). A hole of a
///   drawn polygon is a row of its own, so a pair may name a hole's ring.
/// - Every finding is a [`Severity::Error`], unless the deck writes the row
///   `warning` (a recommended rule, [`RuleSet::warnings`]): then every finding
///   of the row is a [`Severity::Warning`], which does not fail the run.
/// - The rule records [`Outcome::Refused`] when a layer it reads fails
///   validation (a degenerate, self-intersecting or non-rectilinear polygon,
///   or a hole outside every outer ring) or a boolean on it fails. Each
///   variant says when it can also record [`Outcome::Skipped`].
/// - [`RuleRun::examined`] counts what the variant says it counts.
///
/// Each variant gives its deck spelling
/// ([deck.md](https://github.com/UW-ASIC/GPurify/blob/main/docs/deck.md)),
/// the rows of the [check catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv)
/// it covers, and foundry rules it implements.
/// [check-sources.md](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md)
/// says where each manual is. Where the catalog marks a row partial, a
/// Limits paragraph says what the variant misses
/// ([limitations.md](https://github.com/UW-ASIC/GPurify/blob/main/docs/limitations.md)).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Rule {
    /// A shape narrower than `limit` anywhere.
    ///
    /// Deck: `width(L) >= len`, kind `min_width`. The layer is merged first,
    /// so abutting rectangles are one shape and a rectangle drawn inside
    /// another adds no width of its own. Width is the gap between two parallel
    /// edges facing each other across material with overlapping projections,
    /// and also the Euclidean gap between two concave corners facing each
    /// other across material (the neck where two rectangles overlap at a
    /// corner, `KLayout`'s Euclidean width). Where two parts of a figure meet
    /// only at a corner, that neck is 0 wide.
    ///
    /// One violation per merged figure narrower than `limit`, at the middle of
    /// its narrowest gap. `measured` is that width, `shapes.0` the lowest drawn
    /// row under the figure. `examined` counts drawn polygons before the merge.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-010, DRC-073, DRC-090, DRC-095, DRC-096, ERC-C11. Rules: sky130
    /// m1.1, GF180 Mn.1, IHP M1.a, ASAP7 M1.W.1; LEF `WIDTH` and `MINWIDTH`;
    /// `KLayout` `width`.
    MinWidth {
        /// The layer measured, drawn or derived.
        layer: LayerId,
        /// The narrowest legal width, in grid units; positive.
        limit: Dbu,
    },
    /// A part of a shape wider than `limit` in both axes at once.
    ///
    /// Deck: `width(L) <= len`, kind `max_width`. The layer is merged first. A
    /// part is too wide where an axis-aligned square of side `limit + 1` fits,
    /// so a plate with a thin tab is as wide as the plate, and two abutting
    /// rectangles are as wide as their union.
    ///
    /// One violation per connected region where such a square fits, at the
    /// middle of the region's narrowest gap. `measured` is that gap (always
    /// above `limit`), `shapes.0` the lowest drawn row under the region.
    /// `examined` counts drawn polygons.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-012. Rules: sky130 m1.11, GF180 DF.2b, IHP Slt.c, ASAP7 M4.W.2;
    /// LEF `MAXWIDTH`.
    MaxWidth {
        /// The layer measured, drawn or derived.
        layer: LayerId,
        /// The widest legal width, in grid units; positive.
        limit: Dbu,
    },
    /// A cut that is not exactly a `width` x `height` rectangle, either way
    /// round.
    ///
    /// Deck: `size(L) == w x h`, kind `cut_size`. The layer is merged first, so
    /// two abutting square cuts are one slot and fail a square size.
    ///
    /// One violation per wrong figure, at the centre of its bounding box. A
    /// box whose short or long side is off reports that side, with `limit` the
    /// side it should be. A non-rectangle with the right box reports its area
    /// against `width * height`. `shapes.0` is the lowest drawn row under the
    /// figure. `examined` counts merged figures.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-013, DRC-014. Rules: sky130 licon.1, ct.1, via.1a; GF180 CO.1,
    /// Vn.1; IHP Cnt.a, V1.a; `LEF58_CUTCLASS`.
    ///
    /// One legal size per rule: a rule per size flags the cuts of every other
    /// size, so a layer with several legal sizes (sky130 via.1b) is one
    /// [`Rule::CutClass`].
    CutSize {
        /// The cut layer.
        layer: LayerId,
        /// One side of the legal cut, in grid units; positive.
        width: Dbu,
        /// The other side, in grid units; positive.
        height: Dbu,
    },
    /// An edge of a shape shorter than `limit`: a step or jog.
    ///
    /// Deck: `edge_length(L) >= len`, kind `min_edge_length`. The layer is
    /// merged first and every edge of each figure is measured, holes
    /// included: a jog where two overlapping shapes meet is an edge, and a
    /// side two abutting shapes share is not.
    ///
    /// One violation per short edge, at its midpoint. `measured` is its
    /// length, `shapes.0` the lowest drawn row under its figure. `examined`
    /// counts the figures' edges.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-020. Rules: GF180 DF.11; LEF `MINSTEP` and `MINSIZE`;
    /// `LEF58_MINSTEP`.
    ///
    /// The `MINSTEP` variants (`INSIDECORNER`, `OUTSIDECORNER`, `STEP`,
    /// `LENGTHSUM`, `MAXEDGES`) are [`Rule::MinStep`].
    MinEdgeLength {
        /// The layer measured, drawn or derived.
        layer: LayerId,
        /// The shortest legal edge, in grid units; positive.
        limit: Dbu,
    },
    /// A gap inside one shape narrower than `limit`.
    ///
    /// Deck: `notch(L) >= len`, kind `notch`. The layer is merged first, so a
    /// U built from three touching rectangles has a notch, while the gap
    /// between two separate shapes is spacing, not a notch. A notch is the gap
    /// between two parallel edges of one figure facing each other across empty
    /// space with overlapping projections; a hole narrower than `limit` is one
    /// too, and so is a gap between parts of a figure joined only at a
    /// corner. Corner-to-corner gaps are not measured.
    ///
    /// One violation per merged figure, at the middle of its narrowest notch.
    /// `measured` is that gap, `shapes.0` the lowest drawn row under the
    /// figure. `examined` counts drawn polygons before the merge.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-024. Rules: sky130 x.6, IHP M1.b; LEF `NOTCHLENGTH` and
    /// `ENDOFNOTCHWIDTH`; `KLayout` `notch`.
    Notch {
        /// The layer measured, drawn or derived.
        layer: LayerId,
        /// The narrowest legal notch, in grid units; positive.
        limit: Dbu,
    },
    /// Two shapes on one layer closer than `limit`.
    ///
    /// Deck: `space(L) >= len`, kind `min_spacing`. Shapes that touch,
    /// overlap or nest are one figure and have no gap between them. An island
    /// inside another shape's hole keeps its gap to the hole's edge.
    ///
    /// One violation per pair of rows in different figures closer than
    /// `limit`, at the midpoint of its measured points (`shapes` is the
    /// pair). `examined` counts every pair of rows whose boxes come within
    /// `limit`, pairs inside one figure included.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-023, DRC-060. Rules: sky130 m1.2 and ct.2, GF180 Mn.2a, IHP M1.b,
    /// ASAP7 M1.S.1; LEF `SPACING`; `KLayout` `space`.
    MinSpacing {
        /// The layer measured, drawn or derived.
        layer: LayerId,
        /// The smallest legal gap, in grid units; positive.
        limit: Dbu,
    },
    /// A shape on `a` closer than `limit` to a shape on `b`.
    ///
    /// Deck: `space(A, B) >= len`, kind `min_spacing_diff`. Nothing is
    /// exempt: a pair that touches or overlaps, or one nested in the other,
    /// measures 0 and is a violation.
    ///
    /// One violation per offending pair, reported on layer `a`, at the
    /// midpoint of its measured points: for a pair that touches or crosses,
    /// where the boundaries meet; for one nested in the other, the middle of
    /// the overlap of their bounding boxes. `examined` counts pairs whose
    /// boxes come within `limit`.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-047, DRC-065, DRC-073, DRC-090, ERC-C11. Rules: sky130 poly.4 and licon.11,
    /// GF180 DF.16, IHP NW.d and Gat.d, ASAP7 GATE.ACTIVE.S.4; `KLayout`
    /// `separation`.
    ///
    /// Limits: LEF `SPACING ... LAYER ... STACK`, which lets aligned
    /// same-net cuts of two layers stack, is not modelled; the stack-count
    /// limit is [`Rule::ViaStack`].
    MinSpacingDiff {
        /// The first layer; findings are reported on it.
        a: LayerId,
        /// The second layer.
        b: LayerId,
        /// The smallest legal gap, in grid units; positive.
        limit: Dbu,
    },
    /// A shape on `a` closer than `limit` to a shape on `b` across facing
    /// edges.
    ///
    /// Deck: `space(A, B, projection) >= len`, kind `projection_spacing`:
    /// `KLayout`'s `projection` metric, the reading sky130's own `KLayout`
    /// deck gives lvtn.3b "Min spacing of lvtn to pfet along the S/D
    /// direction" (`lvtn.separation(diff.and(nwell).not(poly), 0.235,
    /// projection)`). Shapes are as drawn. A pair is measured across each
    /// edge of one and each edge of the other that are parallel, face each
    /// other across the gap and overlap in projection by a positive length;
    /// the pair's distance is the least such gap. Corner to corner is not
    /// measured, so shapes offset diagonally pass however close. A pair that
    /// touches, overlaps or nests measures 0, as [`Rule::MinSpacingDiff`].
    ///
    /// One violation per offending pair, reported on layer `a`, midway
    /// between the two edges at the middle of their shared projection (where
    /// the boundaries meet, for a pair at 0). `examined` counts pairs whose
    /// boxes come within `limit`.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-055. Rules: sky130 lvtn.3b as its `KLayout` deck writes it;
    /// `KLayout` `separation` with `projection`.
    ///
    /// Limits: the S/D direction is not derived from the gate: facing edges
    /// are measured along both axes, as sky130's own deck measures them.
    ProjectionSpacing {
        /// The first layer; findings are reported on it.
        a: LayerId,
        /// The second layer.
        b: LayerId,
        /// The smallest legal gap, in grid units; positive.
        limit: Dbu,
    },
    /// Too little space in front of an end of line.
    ///
    /// Deck: `eol_space(L; eol_width: len) >= len`, kind `eol_spacing`. An end
    /// of line is an edge of the merged layer strictly shorter than
    /// `eol_width`, so a line end drawn as several strips is one edge, and an
    /// edge two touching shapes share is none. Its keep-out is the edge's own
    /// span pushed `limit` straight out of the material: away from the shape
    /// for an outer edge, into the hole for a hole's edge. Two shapes in
    /// different merged figures are a pair when an edge of one reaches into
    /// the keep-out of an end of line the other lies on, and the pair measures
    /// the nearest such approach, from the part of the end that shape draws.
    ///
    /// One violation per pair closer than `limit`, at the midpoint of its
    /// measured points (on the end of line and the edge in its keep-out).
    /// `examined` counts the pairs.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-029, DRC-031. Rules: ASAP7 M1.S.2 to M1.S.5; LEF
    /// `SPACING ENDOFLINE`; `LEF58_SPACING ENDOFLINE`.
    ///
    /// Limits: basic end of line only. `PARALLELEDGE`, `TWOEDGES`,
    /// `ENCLOSECUT` and `ENDTOEND` are missing, and the keep-out has no
    /// sideways `WITHIN` reach. One `eol_width` per rule, so each width class
    /// is its own rule, and tip-to-side is not told apart from tip-to-tip.
    EolSpacing {
        /// The layer measured, drawn or derived.
        layer: LayerId,
        /// An edge strictly shorter than this is an end of line, in grid
        /// units; positive.
        eol_width: Dbu,
        /// The space an end of line needs, in grid units; positive.
        limit: Dbu,
    },
    /// Two shapes that run alongside each other for at least `prl_threshold`,
    /// closer than `limit`.
    ///
    /// Deck: `prl_space(L; prl: len) >= len`, kind `prl_spacing`. Pairs are
    /// shapes in different merged figures. The run of two figures is facing
    /// edge projection, as LEF `PARALLELRUNLENGTH` and `KLayout`'s
    /// `projection` take it: the longest length over which an edge of one
    /// merged figure and an edge of the other, parallel, facing each other
    /// across a gap of at most `limit`, project onto each other. Edges
    /// are of the merged layer, so a wire drawn as short segments runs its
    /// whole length; an L whose far arm runs beside a shape past the limit
    /// runs only where it comes closer. A pair whose figures run at least
    /// `prl_threshold` is held to `limit`.
    ///
    /// One violation per offending pair, at the midpoint of its measured
    /// points. `examined` counts pairs whose run reaches `prl_threshold`.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-026. Rules: IHP CntB.b1; LEF `SPACINGTABLE PARALLELRUNLENGTH`;
    /// `KLayout` `projection`.
    PrlSpacing {
        /// The layer measured, drawn or derived.
        layer: LayerId,
        /// The run, in grid units, at and above which `limit` applies;
        /// positive.
        prl_threshold: Dbu,
        /// The smallest legal gap for such a pair, in grid units; positive.
        limit: Dbu,
    },
    /// Two shapes whose corners are closer than `limit`.
    ///
    /// Deck: `corner_space(L) >= len`, kind `corner_to_corner`. Corners are
    /// the convex corners of the merged layer, so a corner of one shape that
    /// another touching shape covers is none. Two shapes in different merged
    /// figures are a pair when a corner at a vertex of one and a corner at a
    /// vertex of the other face each other: each lies beyond the other on
    /// both axes, out along its own diagonal. The pair measures its nearest
    /// such corners, Euclidean. Shapes facing each other only across an edge
    /// are [`Rule::MinSpacing`]'s; for two rectangles, those are the pairs
    /// whose bounding boxes overlap on an axis.
    ///
    /// One violation per offending pair, midway between its nearest facing
    /// corners. `examined` counts the pairs with facing corners.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-032. Rules: ASAP7 M1.S.6, GF180 MT30.3; `LEF58_CORNERSPACING`;
    /// `KLayout` `corners`.
    ///
    /// Limits: `LEF58_CORNERSPACING CONVEXCORNER`, which measures the larger
    /// axis gap and can exempt ends of line, is
    /// [`Rule::ConvexCornerSpacing`]; `CONCAVECORNER` is missing. sky130
    /// poly.4, which the manual measures between parallel edges only,
    /// over-reports when written with this kind.
    CornerToCorner {
        /// The layer measured, drawn or derived.
        layer: LayerId,
        /// The smallest legal corner gap, in grid units; positive.
        limit: Dbu,
    },
    /// Too little space from the wide part of a shape.
    ///
    /// Deck: `wide_space(L; width: len) >= len`, kind
    /// `wide_dependent_spacing`. The wide part is where an axis-aligned
    /// `width_threshold` square fits in the merged layer (sky130 `huge_met1 =
    /// met1.sized(-1.5um).sized(1.5um)`), so a shape exactly that wide counts.
    /// A plate with a thin tab is wide where the plate is, and the tab is not
    /// held to this limit. Pairs are shapes in different merged figures where
    /// either has a wide part, measured from that part to the other shape.
    ///
    /// One violation per offending pair, at the midpoint of its measured
    /// points (one on a wide part). `examined` counts the pairs.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-025. Rules: sky130 m1.3b and m3.3c, GF180 Mn.2b, IHP M1.e and
    /// M1.f; LEF `SPACING RANGE`.
    WideDependentSpacing {
        /// The layer measured, drawn or derived.
        layer: LayerId,
        /// The side of the square that makes a part wide, in grid units;
        /// positive.
        width_threshold: Dbu,
        /// The smallest legal gap from a wide part, in grid units; positive.
        limit: Dbu,
    },
    /// A shape smaller than `limit`.
    ///
    /// Deck: `area(L) >= area`, kind `min_area`. The layer is merged first, and
    /// a figure's area does not count its holes.
    ///
    /// One violation per merged figure, at the centre of one of its
    /// rectangles (always on its material). `measured` is the area, `shapes.0`
    /// the lowest drawn outer row under the figure (an island in its hole is
    /// not under it). `examined` counts merged figures.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-017, ERC-A9. Rules: sky130 m1.6, GF180 Mn.3, IHP M1.d and Ant.g
    /// (protection-diode size), ASAP7 M1.A.1; LEF `AREA`; `KLayout`
    /// `with_area`. The `LEF58_AREA` exceptions
    /// (`EXCEPTMINWIDTH`, `EXCEPTRECTANGLE`, ...) are not modelled.
    MinArea {
        /// The layer measured, drawn or derived.
        layer: LayerId,
        /// The smallest legal area, in square grid units; positive.
        limit: DbuArea,
    },
    /// A hole smaller than `limit`.
    ///
    /// Deck: `hole_area(L) >= area`, kind `min_enclosed_area`. The holes are
    /// those of the merged layer, so a hole closed only by several touching
    /// shapes counts, and so does one closed only at a corner.
    ///
    /// One violation per small hole, at the centre of the hole's bounding
    /// box. `measured` is the hole's area, `shapes.0` the lowest drawn outer
    /// row under its figure (an island in the hole is not under it).
    /// `examined` counts holes.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-019. Rules: sky130 m1.7, GF180 DF.10, IHP Act.e; LEF
    /// `MINENCLOSEDAREA`; `KLayout` `holes`.
    MinEnclosedArea {
        /// The layer measured, drawn or derived.
        layer: LayerId,
        /// The smallest legal hole, in square grid units; positive.
        limit: DbuArea,
    },
    /// A shape larger than `max_unslotted` with no slot in it.
    ///
    /// Deck: `cheesing(L) <= area`, kind `cheesing`. The layer is merged
    /// first. Any hole counts as a slot, whatever its size or place.
    ///
    /// One violation per merged figure strictly larger than `max_unslotted`
    /// and holding no hole, at the centre of one of its rectangles.
    /// `measured` is the area, `shapes.0` the lowest drawn outer row under
    /// the figure (an island in its hole is not under it). `examined` counts
    /// merged figures.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-075, ERC-E12. Rules: sky130 m1.11 and m1.12, GF180 MSLOT, IHP
    /// Slt.a to Slt.i.
    ///
    /// Limits: only the requirement that a slot exists. Slot size, spacing
    /// and placement are written with the generic kinds, and stress-voiding
    /// rules beyond slotting are missing.
    Cheesing {
        /// The layer measured, drawn or derived.
        layer: LayerId,
        /// The largest area a figure may have with no slot, in square grid
        /// units; positive.
        max_unslotted: DbuArea,
    },
    /// A window of the die whose covered fraction is outside `limit`.
    ///
    /// Deck: `density(L[, boundary]; window: len, step: len) >= frac` (or
    /// `<=` for a maximum), kind `density`. The die is the bounding box of
    /// every shape on `boundary`, or of the whole layout: every shape on a
    /// drawn layer, none on a derived one ([`RuleSet::first_derived`]), so a
    /// layer grown past the drawing does not move it. `window`-sided
    /// square windows start at the die's lower-left corner and step by `step`
    /// on both axes, as many as it takes to cover the die's far edges. A
    /// window's density is the merged layer's area inside the die and the
    /// window, over the whole window, so a window hanging past the die counts
    /// the outside as empty (`KLayout`'s `padding_zero`). An empty layer on a
    /// non-empty die has density 0 everywhere.
    ///
    /// One violation per offending window, at its centre. `measured` and
    /// `limit` are fractions; `shapes.0` is the lowest outer row on the layer
    /// (a drawn polygon, never a hole) whose box lies within the window, else
    /// the layer's lowest outer row, else `PolyId(u32::MAX)` for an empty
    /// layer. `examined` counts windows.
    /// Records [`Outcome::Skipped`] with
    /// [`SkipReason::EmptyLayer`](crate::report::SkipReason::EmptyLayer) when
    /// the die is empty, and [`Outcome::Refused`] when the windows would
    /// leave the coordinate domain.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-071. Rules: sky130 m1.pd.2a and m1.pd.2b, IHP MFil.h; LEF
    /// `DENSITYCHECKWINDOW` and `DENSITYCHECKSTEP`; `KLayout` `with_density`.
    /// The die is one box for the whole layer, so density per device (DRC-072)
    /// cannot be measured.
    Density {
        /// The layer whose coverage is measured, drawn or derived.
        layer: LayerId,
        /// The layer whose extent is the die; `None` takes the drawn layers'.
        boundary: Option<LayerId>,
        /// The window's side, in grid units; positive.
        window: Dbu,
        /// The distance between window origins, in grid units; positive.
        step: Dbu,
        /// The density limit as a fraction of a window; positive and finite.
        limit: f64,
        /// Whether `limit` is a minimum (deck `>=`) or a maximum (`<=`).
        sense: LimitSense,
    },
    /// Coverage of the whole die outside `limit`.
    ///
    /// Deck: `global_density(L[, boundary]) >= frac` (or `<=` for a maximum),
    /// kind `global_density`. The die is as for [`Rule::Density`]; the density
    /// is the merged layer's area inside the die over the die's area.
    ///
    /// At most one violation, at the die's centre. `shapes.0` is the layer's
    /// first row, or `PolyId(u32::MAX)` for an empty layer. `examined` is 1.
    /// Records [`Outcome::Skipped`] with
    /// [`SkipReason::EmptyLayer`](crate::report::SkipReason::EmptyLayer) when
    /// the die is empty.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-070. Rules: sky130 m1.13, GF180 PL.8 and Mn.4, IHP M1.j and M1.k;
    /// LEF `MINIMUMDENSITY` and `MAXIMUMDENSITY`.
    GlobalDensity {
        /// The layer whose coverage is measured, drawn or derived.
        layer: LayerId,
        /// The layer whose extent is the die; `None` takes the drawn layers'.
        boundary: Option<LayerId>,
        /// The density limit as a fraction of the die; positive and finite.
        limit: f64,
        /// Whether `limit` is a minimum (deck `>=`) or a maximum (`<=`).
        sense: LimitSense,
    },
    /// Too much short-circuit critical area for one defect size.
    ///
    /// Deck: `critical_area(L; radius: len) <= area`, kind `critical_area`.
    /// A defect is a square of half-side `radius` (the L-infinity "defect of
    /// radius r"); it shorts two merged figures of the layer when it overlaps
    /// both. The critical area is the area where its centre does that: the
    /// union, over every pair of figures, of the intersection of the two
    /// figures each grown by `radius` with square corners. Two parallel
    /// lines of length `L` a gap `s` apart give `(L + 2r)(2r - s)` for
    /// `2r >= s`.
    ///
    /// One violation per layer when the critical area is above `limit`,
    /// at the centre of that area's bounding box, naming no shape, with
    /// `measured` the area. `examined` counts merged figures.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-112. Critical area for shorts: E. Papadopoulou and D. T. Lee,
    /// "Critical Area Computation via Voronoi Diagrams", IEEE TCAD 18(4),
    /// 1999 ("The critical region for radius r is the locus of points where
    /// if the center of a square defect of radius r is placed it causes a
    /// short, i.e., the defect overlaps with two polygons in different
    /// nets"); I. and Z. Koren, "Defect Tolerance in VLSI Circuits", Proc.
    /// IEEE 86(9), 1998, p. 1821 (adjacent polygons "expanded by x/2 and the
    /// intersection of the expanded polygons is the critical area for
    /// short-circuit faults of diameter x"); Calibre `YieldAnalyzer` (Siemens
    /// white paper 81850, average critical area over a defect density).
    ///
    /// Limits: shorts only, for one defect size, between figures of one
    /// layer rather than nets. Opens, the average over a defect-size
    /// distribution, and yield are not computed.
    CriticalArea {
        /// The layer measured, drawn or derived.
        layer: LayerId,
        /// The defect's half-side, in grid units; positive.
        radius: Dbu,
        /// The largest legal critical area, in square grid units; positive.
        limit: DbuArea,
    },
    /// A window where two masks' coverage is out of balance.
    ///
    /// Deck: `density_balance(A, B[, boundary]; window: len, step: len) >=
    /// frac`, kind `density_balance`. Windows tile the die as for
    /// [`Rule::Density`]. In each, the balance is the lesser of the two
    /// layers' covered areas (each merged) over the greater: 1 when the masks
    /// cover alike, 0 when one is missing. A window neither covers is not
    /// judged. Write each mask's own density as `density(A; ..)`.
    ///
    /// One violation per window whose balance is below `limit`, on layer `a`,
    /// at the window's centre, naming no shape (`PolyId(u32::MAX)`).
    /// `measured` and `limit` are fractions. `examined` counts windows; an
    /// empty die is [`Outcome::Skipped`].
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-104. The colour density ratio of multi-patterning: "The density
    /// ratio between the two colors may need to meet certain uniformity
    /// requirements" (J. Abercrombie, "Balancing on the color density
    /// tightrope", Siemens Calibre blog, 2015-05-26); Yu et al., ICCAD 2013
    /// (arXiv:1402.2890, Def. 1), take a bin's "local density uniformity" as
    /// `max{d_kc} / min{d_kc}` over the colours, of which this balance is the
    /// reciprocal, so `>= 1/r` bounds it by `r`. No public source gives a
    /// foundry value.
    DensityBalance {
        /// The first mask's layer; findings are reported on it.
        a: LayerId,
        /// The second mask's layer.
        b: LayerId,
        /// The layer whose extent is the die; `None` takes the drawn layers'.
        boundary: Option<LayerId>,
        /// The window side, in grid units; positive.
        window: Dbu,
        /// The window step, in grid units; positive.
        step: Dbu,
        /// The least balance, a fraction; positive and finite.
        limit: f64,
    },
    /// An `inner` shape not surrounded by `outer` by `limit` on every side.
    ///
    /// Deck: `enclosure(inner, outer) >= len`, kind `min_enclosure`. Each
    /// drawn inner polygon is measured on its own. Its host is a figure of the
    /// merged `outer` layer that covers all of its area, so a ring drawn as
    /// abutting bands hosts what sits inside it; among several hosts, the one
    /// giving the most enclosure counts. Enclosure is the Euclidean distance
    /// from the inner polygon to the host's boundary, holes and concave
    /// corners included. An inner polygon no host covers measures 0.
    ///
    /// `enclosure(inner, outer; width: len, below: len) >= len` (either bound
    /// alone too) holds only the inner polygons its [`WireBand`] selects: LEF
    /// `ENCLOSURE ... WIDTH minWidth`, an enclosure that applies by the width
    /// of the wire around the cut.
    ///
    /// One violation per offending inner polygon, reported on the `inner`
    /// layer. A rectangle is marked in the middle of the strip on its least
    /// enclosed side, any other shape at the centre of its bounding box.
    /// `shapes` is the inner row and the host's drawn row (`None` when
    /// unhosted). `examined` counts the inner polygons the band holds.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-040, DRC-043, DRC-090, DRC-096. Rules: sky130 ct.4, m1.4 and
    /// licon.5a, GF180 CO.3, IHP M1.c and V1.c, ASAP7 V3.M4.EN.2; LEF
    /// `ENCLOSURE`, and `ENCLOSURE ... WIDTH` (LEF/DEF 5.8, Example 1-3);
    /// `KLayout` `enclosing`.
    MinEnclosure {
        /// The enclosing layer, merged; the deck's second argument.
        outer: LayerId,
        /// The enclosed layer; findings are reported on it.
        inner: LayerId,
        /// The smallest legal enclosure, in grid units; positive.
        limit: Dbu,
        /// The wire widths at which the rule holds an inner polygon.
        wire: WireBand,
    },
    /// An `inner` shape closer than `limit` to `outer`'s boundary, edges that
    /// coincide with it apart.
    ///
    /// Deck: `enclosure(inner, outer, noncoincident) >= len`, kind
    /// `noncoincident_enclosure`, as sky130 lvtn.10 "Min enclosure of lvtn by
    /// (nwell not overlapping `Var_channel`) (exclude coincident edges)". Hosts
    /// are chosen as for [`Rule::MinEnclosure`]. Each edge of the inner
    /// polygon is measured to each edge of the host that is parallel to it,
    /// faces the same way and lies at or beyond its line, Euclidean, end to
    /// end too (`KLayout`'s `enclosing` edge pairs, `euclidian`); a pair that
    /// touches measures nothing, so an inner edge on the host's boundary, and
    /// an inner corner on it, are exempt (`KLayout`'s
    /// `without_touching_edges`, "coincident edges will not yield errors").
    /// Without such contact this is [`Rule::MinEnclosure`]'s distance: a
    /// rectilinear host's nearest boundary point faces an inner edge along a
    /// parallel host edge, or is a concave corner of the host where two meet.
    /// An inner polygon whose every edge lies on its host's boundary passes;
    /// one no host covers measures 0.
    ///
    /// One violation per offending inner polygon, on the `inner` layer, in the
    /// middle of the gap between the boxes of the pair that measured it, or
    /// at the centre of its box when unhosted. `shapes` is the inner row and
    /// the host's drawn row (`None` when unhosted). `examined` counts inner
    /// polygons.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-054. Rules: sky130 lvtn.10; `KLayout` `enclosing` with
    /// `without_touching_edges`.
    NoncoincidentEnclosure {
        /// The enclosing layer, merged; the deck's second argument.
        outer: LayerId,
        /// The enclosed layer; findings are reported on it.
        inner: LayerId,
        /// The smallest legal enclosure, in grid units; positive.
        limit: Dbu,
    },
    /// An `inner` shape that does not span its host's full width along one
    /// axis.
    ///
    /// Deck: `full_width(inner, outer)`, kind `full_width`, as ASAP7
    /// V1.M2.AUX.2 "V1 must exactly be the same width as M2 along the
    /// direction perpendicular to the M2 length". Hosts are chosen as for
    /// [`Rule::MinEnclosure`] (the one reading least). Each edge of the inner
    /// polygon is read straight out to the nearest host edge facing it, as
    /// [`Rule::AsymmetricEnclosure`] reads it; the inner spans its host along
    /// x when every vertical edge reads 0 (it meets the host's edge on both
    /// sides), along y likewise, and the rule measures the better axis's
    /// widest reading, `min(max(left, right), max(bottom, top))` for a
    /// rectangle, which must be 0. An inner shape no host covers is not
    /// measured: `inside(inner, outer)` is that rule (ASAP7 V1.AUX.1).
    ///
    /// One violation per offending inner polygon, on the `inner` layer, in the
    /// middle of the strip past the widest-reading edge of the better axis,
    /// with `limit` 0. `shapes` is the inner row and the host's drawn row.
    /// `examined` counts inner polygons.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-053. Rules: ASAP7 V1.M2.AUX.2.
    ///
    /// Limits: `LEF58_SPACING ... EXACTALIGNED`, a spacing rule for exactly
    /// aligned line ends, is not this rule and is not modelled.
    FullWidth {
        /// The host layer, merged; the deck's second argument.
        outer: LayerId,
        /// The layer that must span it; findings are reported on it.
        inner: LayerId,
    },
    /// An `inner` shape without `min_one_side` of enclosure on both sides of
    /// at least one axis.
    ///
    /// Deck: `enclosure(inner, outer, opposite) >= len`, kind
    /// `asymmetric_enclosure`. Hosts are chosen as for [`Rule::MinEnclosure`].
    /// Each edge of the inner polygon, holes included, is read straight out
    /// from its outside to the nearest host edge facing it (the projection
    /// metric). The inner is enclosed along x by the least reading of its
    /// vertical edges and along y by the least of its horizontal edges, and
    /// the rule measures the better axis: `max(min(left, right), min(bottom,
    /// top))` for a rectangle. An L-shaped inner's concave edges count as its
    /// outer ones do. LEF `ENCLOSURE overhang1 overhang2` is two rows: this
    /// one at `overhang1` and a [`Rule::MinEnclosure`] row at `overhang2`
    /// (sky130 m1.4 beside m1.5), which together hold exactly when one axis
    /// has `overhang1` on both sides and every side has `overhang2`.
    ///
    /// For a rectangle, "on one of two adjacent sides" (sky130 m1.5, via.5a,
    /// licon.5c, licon.7, licon.8a, li.5) is this rule: no two adjacent sides
    /// fall short exactly when one axis has the limit on both sides. sky130's
    /// own `KLayout` deck checks those rows as two opposite edges too.
    ///
    /// With `width:` and `below:`, the rule holds only the inner polygons its
    /// [`WireBand`] selects, as [`Rule::MinEnclosure`]'s: LEF `ENCLOSURE
    /// overhang1 overhang2 WIDTH minWidth`.
    ///
    /// One violation per offending inner polygon, on the `inner` layer, in the
    /// middle of the strip past the least enclosed edge of the better axis.
    /// `shapes` is the inner row and the host's drawn row (`None` when
    /// unhosted). `examined` counts the inner polygons the band holds.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-041, DRC-042, DRC-043. Rules: sky130 m1.5, via.5a and licon.5c, ASAP7
    /// V1.M1.EN.1, IHP M1.c1 and V1.c1; LEF `ENCLOSURE` with two overhangs
    /// (LEF/DEF 5.8, "ENCLOSURE"); `KLayout` `enclosed` with `projection`.
    ///
    /// Limits: end-cap enclosure that depends on the host's end of line
    /// (`LEF58_ENCLOSURE EOL`) is not modelled. One of two adjacent sides,
    /// read at each corner, is [`Rule::AdjacentEnclosure`].
    AsymmetricEnclosure {
        /// The enclosing layer, merged; the deck's second argument.
        outer: LayerId,
        /// The enclosed layer; findings are reported on it.
        inner: LayerId,
        /// The enclosure both sides of one axis need, in grid units; positive.
        min_one_side: Dbu,
        /// The wire widths at which the rule holds an inner polygon.
        wire: WireBand,
    },
    /// An `outer` shape reaching further than `limit` from the `inner` shapes
    /// it holds.
    ///
    /// Deck: `enclosure(inner, outer) <= len`, kind `max_enclosure`: a
    /// maximum enclosure, as sky130 npc.5 "Max enclosure of poly overlapping
    /// `slotted_licon` by npcm" or IHP LU.c "Max. extension of an abutted `NWell`
    /// tie beyond Cont". Both layers are merged. An outer figure holds the
    /// inner figures it covers entirely, and must lie within `limit` of them
    /// in every direction, corners included: inside the union of its held
    /// inner figures grown by `limit` with square corners (`KLayout`
    /// `sized`), the reading a deck's `outer not inner.sized(limit)` gives.
    /// So two cuts under one host are measured together, the host's part
    /// between them included (npc.5's "merge between adjacent short edges").
    /// An outer figure that holds no inner shape is not measured.
    ///
    /// One violation per offending outer figure, on the `outer` layer, at the
    /// centre of a rectangle of its part beyond `limit`. `measured` is the
    /// least whole distance the held figures would have to be grown by to
    /// cover it (the furthest reach, rounded up, so an exceeded limit never
    /// reads as met); `shapes.0` is the lowest drawn outer row under the
    /// figure. `examined` counts the outer figures that hold an inner one.
    ///
    /// Min-and-max rules (IHP Sdiod.a "Min. and max. PWell:block enclosure
    /// of `ContBar`") are this row beside a [`Rule::MinEnclosure`] row.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-044. Rules: sky130 npc.5, IHP LU.c, LU.c1 and Sdiod.a to Sdiod.c;
    /// `KLayout` `sized` and boolean `-`.
    ///
    /// Limits: a maximum space (IHP Rppd.c, GF180 NP.3d "min/max space") is
    /// not this rule and cannot be written.
    MaxEnclosure {
        /// The enclosing layer, merged; findings are reported on it.
        outer: LayerId,
        /// The enclosed layer, merged.
        inner: LayerId,
        /// The furthest the outer figure may reach past what it holds, in
        /// grid units; positive.
        limit: Dbu,
    },
    /// An `inner` shape with a corner where neither side meeting it has
    /// `min_one_side` of enclosure.
    ///
    /// Deck: `enclosure(inner, outer, adjacent) >= len`, kind
    /// `adjacent_enclosure`: sky130 m1.5 "Mcon must be enclosed by Met1 on
    /// one of two adjacent sides by at least 0.060 um" (periphery rules,
    /// google/skywater-pdk docs/rules/periphery/periphery.csv; li.5, licon.5c,
    /// licon.7, licon.8a, via.5a, m2.5, via2.5 and via3.5 alike). Hosts are
    /// chosen as for [`Rule::MinEnclosure`]. Each edge of the inner polygon
    /// is read straight out to the host at each of its two ends, and the rule
    /// measures the least, over the inner's convex corners, of the better of
    /// the two edges meeting there, each read at that corner. A rectangle in
    /// a host that does not step along its sides measures what
    /// [`Rule::AsymmetricEnclosure`] does; a host that steps is read at the
    /// corner, as the foundry's `sky130A_mr.drc` does (a corner of short
    /// enclosed edges flags), so an enclosing shape reaching far past one
    /// corner but not another is held at each.
    ///
    /// One violation per offending inner polygon, on the `inner` layer, in the
    /// middle of the strip past the better edge of the worst corner. `shapes`
    /// is the inner row and the host's drawn row (`None` when unhosted).
    /// `examined` counts inner polygons.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-042. Rules: sky130 li.5, m1.5, via.5a, licon.5c; Magic `surround
    /// directional`.
    AdjacentEnclosure {
        /// The enclosing layer, merged; the deck's second argument.
        outer: LayerId,
        /// The enclosed layer; findings are reported on it.
        inner: LayerId,
        /// The enclosure one side at each corner needs, in grid units; positive.
        min_one_side: Dbu,
    },
    /// `layer` not extending past `reference` by `limit`, as poly past
    /// diffusion.
    ///
    /// Deck: `extension(A, B) >= len`, kind `min_extension`. Both layers are
    /// merged, and each figure of the area they share (a gate) is measured.
    /// A crosses B along an axis when every gate edge facing along that axis
    /// lies on B's boundary; each such edge measures how far A runs on past
    /// it, straight out (0 where A stops flush with B). The gate measures the
    /// least over the axes A crosses; where A crosses B along neither, A ends
    /// inside B and the gate measures 0. So a gate measures the shorter of
    /// its two end caps, a poly that stops inside diffusion at one end
    /// measures 0 however far its other end runs, and shapes that only touch
    /// make no gate.
    ///
    /// One violation per offending gate, on layer A, in the middle of the
    /// strip past the measured edge, or at the centre of the gate's bounding
    /// box when it measures 0 for ending inside B. `shapes` is the lowest A
    /// row and the lowest B row under the gate. `examined` counts the gates.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-045. Rules: sky130 poly.7 and poly.8, GF180 PL.4, IHP Gat.c, ASAP7
    /// GATE.ACTIVE.EX.1.
    ///
    /// Limits: a gate that bends or carries a stub inside B has edges inside
    /// B along both axes, so A crosses B along neither and the gate measures
    /// 0 (fails closed); [`Rule::GateCorner`]'s `bend` reports the bend
    /// itself.
    MinExtension {
        /// The extending layer (A); findings are reported on it.
        layer: LayerId,
        /// The layer it must extend past (B).
        reference: LayerId,
        /// The smallest legal extension, in grid units; positive.
        limit: Dbu,
    },
    /// A concave corner of the area two layers share that is a concave corner
    /// of `layer` (it turns on `reference`) or of `reference` (it covers an
    /// inner corner of `reference`).
    ///
    /// Deck: `bend(A, B)` (`of_reference` false) and `covers_corner(A, B)`
    /// (true), kind `gate_corner`. Both layers are merged, and the area they
    /// share is the gate. A concave corner of a rectilinear intersection is a
    /// concave corner of one operand (both, where they coincide), so a gate
    /// is a rectangle exactly when neither form finds a corner on it. `bend`
    /// finds where A turns 90 degrees on B, the corner lying in B's material:
    /// an L-shaped poly bent over diffusion, or a stub off a gate (two
    /// corners). A turn on B's edge leaves the gate a rectangle and is not
    /// one. `covers_corner` finds an inner corner of B under A's material, as
    /// a gate over a jog in the diffusion's edge. Corners of holes count.
    ///
    /// One violation per corner, at it, on layer A, `measured` `Count(1)`
    /// against a `limit` of `Count(0)`. `shapes` is the lowest A row and the
    /// lowest B row under its gate. `examined` counts the gates.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-052. Rules: sky130 poly.11 "No 90 deg turns of poly on diff" and
    /// poly.10 "Poly can't overlap inner corners of diff", GF180 PL.6 "90 deg
    /// bends on the COMP are not allowed", IHP Gat.f, ASAP7 GATE.AUX.1 "GATE
    /// may not bend"; `KLayout` `corners`.
    ///
    /// Limits: 45-degree turns (IHP Gat.f) cannot occur: every rule but
    /// [`Rule::Angle`] refuses a non-rectilinear layer.
    GateCorner {
        /// The layer that bends or covers (A); findings are reported on it.
        layer: LayerId,
        /// The layer it lies on (B).
        reference: LayerId,
        /// Corners of `reference` (`covers_corner`), else of `layer` (`bend`).
        of_reference: bool,
    },
    /// `a` and `b` overlapping by less than `limit`.
    ///
    /// Deck: `overlap(A, B) >= len`, kind `overlap`. Both layers are merged,
    /// and each figure of the area they share is measured as
    /// [`Rule::MinWidth`] measures a figure, so two rectangles overlap by the
    /// shorter side of their intersection. Shapes that only touch share no
    /// area and are not measured, and the shared areas of two pairs that
    /// touch are one figure.
    ///
    /// One violation per figure narrower than `limit`, on layer A, at the
    /// middle of its narrowest gap. `shapes` is the lowest A row and the
    /// lowest B row under the figure. `examined` counts the figures.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-046. Rules: IHP pSD.e, GF180 NP.5a, sky130 hv.poly.7; `KLayout`
    /// `overlap`.
    Overlap {
        /// The first layer; findings are reported on it.
        a: LayerId,
        /// The second layer.
        b: LayerId,
        /// The smallest legal overlap, in grid units; positive.
        limit: Dbu,
    },
    /// A point of a well further than `limit` from every tap.
    ///
    /// Deck: `tap_distance(well, tap) <= len`, kind `max_distance_to_tap`.
    /// Every point of each well polygon counts, not only its vertices, and the
    /// distance is to the nearest edge of any tap shape, holes included. A
    /// well with no tap on the layer at all measures `2^40`.
    ///
    /// One violation per offending well polygon, at its furthest point, on its
    /// outer row and the `well` layer. `measured` is rounded up, so an
    /// exceeded limit never reads as met. `examined` counts well polygons; a
    /// hole row is not a well of its own. Records
    /// [`Outcome::Skipped`] with
    /// [`SkipReason::EmptyLayer`](crate::report::SkipReason::EmptyLayer) when
    /// the well layer is empty (an empty tap layer is not skipped), and
    /// [`Outcome::Refused`] when either layer fails validation.
    ///
    /// A point inside a tap measures to the tap's edge, not 0, and a well's
    /// hole is measured as if filled, so the rule can over-report (fails
    /// closed).
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// ERC-D1. Rules: GF180 LU.1 to LU.4, IHP LU.a and LU.b, ASAP7
    /// ACTIVE.LUP.1; ESDA TR18.0-02 3.1.1.
    MaxDistanceToTap {
        /// The well layer; findings are reported on it.
        well: LayerId,
        /// The tap layer.
        tap: LayerId,
        /// The furthest a point of a well may be from a tap, in grid units;
        /// positive.
        limit: Dbu,
    },
    /// A vertex off the manufacturing grid.
    ///
    /// Deck: `off_grid(; pitch: len)`, kind `off_grid`. Every vertex of every
    /// row on every drawn layer must lie on the lattice of multiples of
    /// `pitch` from the origin, on both axes. A derived layer is not checked
    /// ([`RuleSet::first_derived`]): it is computed from drawn ones, so it
    /// would repeat their off-grid vertices, and sizing a drawn layer by less
    /// than the pitch would put on-grid drawing off it.
    ///
    /// One violation per off-grid vertex, at it, on its row's layer.
    /// `measured` is the vertex's Chebyshev distance to the nearest lattice
    /// point, `limit` is 0. `examined` counts vertices. Never records
    /// `Refused` or `Skipped`.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-001. Rules: sky130 x.1a and x.1b, GF180 GRID and OFFGRID, IHP 3.1;
    /// LEF `MANUFACTURINGGRID`; `KLayout` `ongrid`.
    OffGrid {
        /// The manufacturing grid, in grid units; positive.
        pitch: Dbu,
    },
    /// An edge at an angle not in the allowed list.
    ///
    /// Deck: `angle([L]; allowed: [0deg, 90deg])`, kind `angle`. Every
    /// non-zero edge of every row on `layer`, or with no layer on every drawn
    /// layer, must lie along an allowed line. With no layer, a derived layer
    /// is not checked ([`RuleSet::first_derived`]): it repeats the edges of
    /// the drawn layers it is computed from.
    ///
    /// One violation per offending edge, at its first vertex in store order,
    /// on its row's layer. `measured` is `Count(0)` (no allowed line matched)
    /// against a `limit` of `Count(1)`. `examined` counts non-zero edges.
    /// Never records `Refused` or `Skipped`.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-002, DRC-003, DRC-037. Rules: sky130 x.2 and x.3, IHP 3.1, GF180
    /// ACUTE; `KLayout` `with_angle`.
    ///
    /// A layout with 45-degree or acute edges loads, and this rule checks
    /// them; it is the one geometric rule that does not validate its layer,
    /// so it never records `Refused` for a non-rectilinear one.
    Angle {
        /// The layer whose edges are checked; `None` checks every drawn layer.
        layer: Option<LayerId>,
        /// Bit `i` allows the line at `45 * i` degrees, for `i` in `0..4`. A
        /// line has no direction, so 180 degrees is 0. Non-zero: `from_deck`
        /// refuses an empty list and an angle that is not a multiple of 45.
        allowed: u8,
    },
    /// A cut with too few cuts near it.
    ///
    /// Deck: `redundant_via(L; within: len) >= count`, kind `redundant_via`.
    /// Each row on the layer is a cut, as drawn and not merged. Its count is
    /// the cuts, itself included, at most `within` from it, boundary to
    /// boundary. Cuts are counted on geometry, not nets.
    ///
    /// One violation per cut whose count is below `min_count`, at the centre
    /// of its bounding box, with `measured` the count. `examined` counts cuts.
    /// The layer is not validated, so this rule never records `Refused`.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-066, DRC-117. Rules: sky130 x.18, GF180 MT30.8a; LEF `MINIMUMCUT`;
    /// `LEF58_MINIMUMCUT`.
    ///
    /// Limits: the width-triggered `MINIMUMCUT` forms (`FROMABOVE`,
    /// `FROMBELOW`, `LENGTH WITHIN`) are missing, and there is no DFM via
    /// scoring or via doubling.
    RedundantVia {
        /// The cut layer.
        layer: LayerId,
        /// The fewest cuts each cut needs near it, itself included; at least 1.
        min_count: u16,
        /// How far, in grid units, a cut counts as near; positive and
        /// inclusive.
        within: Dbu,
    },
    /// A via on a wide wire with fewer than `min_count` cuts.
    ///
    /// Deck: `min_cuts(cut, wide, other; width: len) >= count`, and with
    /// `within: len`, kind `minimum_cut`: LEF `MINIMUMCUT numCuts WIDTH width
    /// [WITHIN cutDistance]` on layer `wide`, "the number of cuts a via must
    /// have when it is on a wide wire or pin whose width is greater than
    /// width". `other` is the metal on the via's far side, so `FROMABOVE` and
    /// `FROMBELOW` are the choice of `other`; LEF's default, both, is two
    /// rows. Cuts are the rows on `cut`, as drawn, read by their bounding
    /// boxes. A via is the cuts joining one figure of merged `wide` to one
    /// figure of merged `other` (the lowest of each it overlaps; a cut on no
    /// `other` figure joins the others like it); with `within`, the via splits
    /// into groups of cuts closer than `within` to one another ("numCuts via
    /// cuts must be less than cutDistance from each other in order to be
    /// counted together"). A via is held when one of its cuts overlaps the
    /// part of `wide` wider than `width`: where a `width + 1` square fits,
    /// strictly wider, as LEF says.
    ///
    /// One violation per cut of a held via with too few cuts, at the cut's
    /// centre, `measured` the via's cut count. `examined` counts the held
    /// vias. Records [`Outcome::Refused`] when `wide` or `other` fails
    /// validation.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-066. Rules: LEF `MINIMUMCUT` (LEF/DEF 5.8, Minimum Cut Rule
    /// Examples 1 to 3); GF180 MT30.8a, "single top via ... at one location
    /// cannot exist under the thick (3um thick) metal", is `width: 1nm` with
    /// `>= 2` on the thick metal.
    ///
    /// Limits: the `LENGTH length WITHIN distance` form (thin wires near a
    /// wide one) and `LEF58_MINIMUMCUT`'s cut classes and `AREA` are missing.
    MinimumCut {
        /// The cut layer.
        cut: LayerId,
        /// The metal whose width triggers the rule; findings name its cuts.
        wide: LayerId,
        /// The metal on the vias' far side.
        other: LayerId,
        /// The wire width, in grid units, strictly above which the rule
        /// holds a via; positive.
        width: Dbu,
        /// How close, in grid units, cuts must be to count together; `None`
        /// counts every cut of a via.
        within: Option<Dbu>,
        /// The fewest cuts a held via needs; at least 1.
        min_count: u16,
    },
    /// A stack of overlapping cuts taller than `max_height`.
    ///
    /// Deck: `via_stack(cut1, cut2, ..) <= count`, the cut layers bottom to
    /// top, kind `via_stack`: LEF `MAXVIASTACK value [RANGE bottomLayer
    /// topLayer]`, "the maximum number of single-cut stacked vias that are
    /// allowed on top of each other ... A via is considered to be in a stack
    /// with another via if the cut of the first via overlaps any part of the
    /// cut of the second via". Cuts are the rows on each layer, as drawn,
    /// read by their bounding boxes; a cut stacks on a cut of the layer
    /// listed before it when the two overlap with positive area. A stack's
    /// height through a cut is the longest chain of stacked cuts through it,
    /// one per layer. The layers listed are the `RANGE`.
    ///
    /// One violation per cut at the height `max_height + 1` of a taller stack,
    /// at its centre and on its layer, `measured` the tallest stack through
    /// it. `examined` counts the cuts. The layers are not validated, so this
    /// rule never records `Refused`.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-065. Rules: LEF `MAXVIASTACK` (LEF/DEF 5.8, "Maximum Via Stack",
    /// Example 1-34).
    ///
    /// Limits: every cut counts as a single-cut via, so a double-cut via does
    /// not interrupt a stack (it fails closed: a stack LEF would split is
    /// read as one).
    ViaStack {
        /// Index into [`RuleSet::stacks`]: the cut layers, bottom to top.
        stack: u32,
        /// The tallest legal stack; at least 1.
        max_height: u16,
    },
    /// Cuts in a large array closer than `limit`.
    ///
    /// Deck: `via_array_space(L; array: count) >= len`, kind
    /// `via_array_spacing`. Cuts are the rows on the layer, as drawn. A
    /// cluster is the cuts joined by gaps of at most `limit`, and it is an
    /// array when it has more than `array_threshold` cuts.
    ///
    /// One violation per pair inside an array closer than `limit`, at the
    /// midpoint of the measured points (as the spacing family; for a cut
    /// that is not rectilinear, the middle of the gap between the boxes of
    /// the two nearest edges). `examined` counts the pairs inside arrays. The layer is not validated, so this rule never
    /// records `Refused`.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-062. Rules: IHP Cnt.b1 and V1.b1, GF180 CO.2b; LEF `ADJACENTCUTS`
    /// and `ARRAYSPACING`; `LEF58_ARRAYSPACING`.
    ///
    /// Limits: the `ADJACENTCUTS WITHIN` variants are unverified.
    ViaArraySpacing {
        /// The cut layer.
        layer: LayerId,
        /// A cluster must have strictly more cuts than this to be an array; 0
        /// makes every cluster one.
        array_threshold: u16,
        /// The smallest legal gap inside an array, in grid units; positive.
        limit: Dbu,
    },
    /// Two cuts closer than `limit`, centre to centre or edge to edge, where
    /// the rule holds either of them.
    ///
    /// Deck: `space(L, center) >= len` (LEF `SPACING CENTERTOCENTER`),
    /// `adjacent_space(L; cuts: count, within: len) >= len` (LEF `SPACING
    /// ADJACENTCUTS count WITHIN within`), and `adjacent_space(L, center;
    /// cuts: count, within: len) >= len` (both), kind `cut_spacing`. Cuts are
    /// the rows on the layer, as drawn and not merged. With `center`, every
    /// distance is between the centres of the two cuts' bounding boxes (LEF
    /// "computes the cutSpacing or cutWithin distances from cut-center to
    /// cut-center"); without, it is boundary to boundary, 0 for cuts that
    /// touch, overlap or nest. Without `cuts`, the rule holds every cut. With
    /// it, a cut is held when at least `cuts` other cuts lie strictly closer
    /// than `within` (LEF: "applies the spacing rule only when the cut has
    /// two, three, or four via cuts that are less than cutWithin distance"),
    /// so `cuts: 3` waives a 2x2 array and holds a 2x3 one whose diagonal is
    /// beyond `within` (LEF/DEF 5.8, Figure 1-6). A pair is checked when
    /// either cut is held.
    ///
    /// One violation per pair closer than `limit`, at the midpoint of its
    /// measured points: the two centres, or the nearest points of the two
    /// boundaries as the spacing family marks them. `measured` is the
    /// distance floored. `examined` counts the cuts held. The layer is not
    /// validated, so this rule never records `Refused`.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-061, DRC-062. Rules: LEF cut-layer `SPACING` with `CENTERTOCENTER`
    /// and `ADJACENTCUTS ... WITHIN` (LEF/DEF 5.8, "SPACING", Spacing Rule
    /// Examples 2 to 4); `LEF58_SPACING ADJACENTCUTS` as `OpenROAD`'s
    /// detailed router checks it (`checkLef58CutSpacing_spc_adjCut`).
    ///
    /// Limits: `EXCEPTSAMEPGNET` (the rule waived between cuts of one power
    /// or ground net) is not modelled.
    CutSpacing {
        /// The cut layer.
        layer: LayerId,
        /// Distances between cut centres, else between cut boundaries.
        center: bool,
        /// How many other cuts closer than `within` hold a cut to `limit`; 0
        /// holds every cut.
        adjacent: u16,
        /// The reach of `adjacent`, in grid units; positive when `adjacent`
        /// is not 0, else unused.
        within: Dbu,
        /// The smallest legal distance, in grid units; positive.
        limit: Dbu,
    },
    /// Two cuts closer than their cell of a cut-class spacing table.
    ///
    /// Deck: `cut_class_space(L; short: [len, ..], long: [len, ..], space:
    /// [[len, ..], ..])`, kind `cut_class_spacing`. Cuts are the rows on the
    /// layer, as drawn. A cut's class is the first whose `short` x `long`
    /// matches its bounding box either way round (`LEF58_CUTCLASS WIDTH ...
    /// LENGTH ...`); a cut of no class is not checked. Each class has two rows
    /// and two columns of `space`, in class order: its END, then its SIDE. Two
    /// cuts apart along y face each other with their sides across y, so a cut
    /// faces with its SIDE (a long side) when it is wider than tall, else
    /// with its END; apart along x, when it is taller than wide. A square cut
    /// always faces with its END. A pair apart along both axes is held to
    /// both readings, the larger cell, as `OpenROAD`'s detailed router checks
    /// a `LEF58_SPACINGTABLE` of `CUTCLASS` SIDE/END entries
    /// (`checkLef58CutSpacingTbl_helper`). A pair that touches or overlaps is
    /// held to the largest cell of its two classes. Distances are boundary
    /// to boundary, Euclidean. So sky130 licon.2 to licon.2d are one table:
    /// slotted licons end to end 350 nm apart, otherwise 510 nm, and 510 nm
    /// to a square licon.
    ///
    /// One violation per pair closer than its cell, at the midpoint of its
    /// measured points, with `limit` the cell. `examined` counts the pairs of
    /// classed cuts whose boxes come within the table's largest cell. The
    /// layer is not validated, so this rule never records `Refused`.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-063, DRC-064. Rules: sky130 licon.2, licon.2b, licon.2c and
    /// licon.2d; `LEF58_SPACINGTABLE` on a cut layer with `CUTCLASS` entries,
    /// and `LEF58_CUTCLASS`, as `OpenROAD` reads them.
    ///
    /// Limits: the second, parallel-run value of a cell (`PRL`), the
    /// `CENTERTOCENTER` and `CENTERANDEDGE` cells, same-net, same-metal and
    /// cross-layer (`LAYER`) tables, `EXACTALIGNEDSPACING` and LEF's
    /// `SPACINGTABLE ORTHOGONAL` are missing. A bar of free length (IHP
    /// `CntB`) has no class.
    CutClassSpacing {
        /// The cut layer.
        layer: LayerId,
        /// Index into [`RuleSet::cut_tables`].
        table: u32,
    },
    /// Shapes that cannot be split onto `colors` masks with same-mask shapes
    /// at least `color_spacing` apart.
    ///
    /// Deck: `patterning(L; colors: count) >= len`, kind `multi_patterning`.
    /// Shapes that touch, overlap or nest print as one and are one figure;
    /// two figures closer than `color_spacing` conflict, and a figure whose
    /// own notch (two of its edges facing across empty space, as
    /// [`Rule::Notch`] measures it) is narrower than `color_spacing`
    /// conflicts with itself, so no number of masks splits it. Two masks are decided
    /// exactly by bipartiteness. Three or more are decided exactly by a search
    /// with a step budget, `max(2^20, 64 * rows)`, and running out of it
    /// records [`Outcome::Refused`], never a pass.
    ///
    /// At most one violation per layer, on one shape of the conflict (see
    /// [`Coloring::Infeasible`](crate::drc::rules::patterning::Coloring::Infeasible)),
    /// at the centre of its bounding box. `measured` is `colors + 1` masks
    /// against a `limit` of `colors`. `examined` counts the layer's rows,
    /// also when refused. Records [`Outcome::Skipped`] with
    /// [`SkipReason::EmptyLayer`](crate::report::SkipReason::EmptyLayer) on an
    /// empty layer.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-100, DRC-101. Defined by Kahng et al. (2008) and the commercial
    /// decks (Calibre, IC Validator); no open foundry manual or `KLayout` deck
    /// has a colouring rule. The self-conflict, a polygon with "notch spaces
    /// between themselves that violate minimum same-mask spacing", "an odd
    /// cycle error of one", is Calibre's (J. Abercrombie, "Five Steps to
    /// Double Patterning Debug Success", Siemens Calibre blog, 2016-03-02).
    ///
    /// Limits: one finding says that no colouring exists, not which class
    /// of error stops it. Write each class as its own row to have it located:
    /// `notch(L) >= len` for self-conflicts and `space(L) >= len` for the
    /// minimum opposite-mask spacing. Pre-coloured `MASK` shapes (DRC-102)
    /// and stitches are not modelled.
    MultiPatterning {
        /// The layer to split.
        layer: LayerId,
        /// The number of masks; at least 1.
        colors: u8,
        /// The smallest gap between two shapes on one mask, in grid units;
        /// positive.
        color_spacing: Dbu,
    },
    /// Pre-coloured shapes whose masks no split of the layer can honour.
    ///
    /// Deck: `patterning(L, A1[, A2, ..]; colors: count) >= len`, kind
    /// `anchored_patterning`. The conflict graph is [`Rule::MultiPatterning`]'s.
    /// A figure sharing area with a shape of the `i`-th anchor layer is
    /// anchored to mask `i`, as a LEF/DEF `MASK i` shape is pre-coloured; a
    /// figure no anchor touches may take any mask, as LEF/DEF's uncoloured
    /// shapes ("can be assigned to an arbitrary mask as long as they do not
    /// have a spacing conflict"). A component of the graph that `colors` masks
    /// can split, but not with every anchored figure on its own mask, is an
    /// anchor conflict. A component no split exists for is
    /// [`Rule::MultiPatterning`]'s to report, not this rule's.
    ///
    /// One violation per anchor conflict, `measured` `colors + 1` masks
    /// against a `limit` of `colors`. With two masks it names the conflict:
    /// the lowest anchored figure and the first anchored figure whose path of
    /// conflicts to it has the wrong parity for their anchors (an odd number
    /// of conflicts between two figures anchored alike, an even number
    /// between two anchored apart: Calibre's anchor path), at the middle of
    /// the gap between their boxes; or one figure that two anchor layers
    /// both anchor (anchor self-conflict), at the centre of its box. With more
    /// masks it decides exactly, colouring the component with one node per
    /// mask, joined as a clique, and each anchored figure joined to every
    /// mask node but its own, and names the lowest anchored figure; a search
    /// that runs out of budget records [`Outcome::Refused`]. `examined`
    /// counts the layer's rows. Records [`Outcome::Skipped`] on an empty
    /// layer.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-101, DRC-102. The anchor path, "a path of interacting polygons
    /// between the two anchors that cannot be colored in alternating colors
    /// to align with the anchor masks", and the anchor self-conflict, "a
    /// single polygon with two color anchor markers", are Calibre's
    /// (J. Abercrombie, Semiconductor Engineering, 2012-06-29, and the
    /// Siemens Calibre blog, 2016-03-02); the parity test is US8473873B2
    /// claims 1(e) and 2(i); LEF/DEF 5.8 `MASK` (p. 132) defines pre-coloured
    /// and uncoloured shapes.
    ///
    /// Limits: a figure is anchored by any overlap with an anchor shape, so
    /// a partial marker (Calibre's seed) anchors as a full one does.
    AnchoredPatterning {
        /// The layer to split.
        layer: LayerId,
        /// The anchor layer of mask `i + 1` at index `i`; `None` past the
        /// last. At least one, and no more than `colors`.
        anchors: [Option<LayerId>; 4],
        /// The number of masks; at least 1.
        colors: u8,
        /// The smallest gap between two shapes on one mask, in grid units;
        /// positive.
        color_spacing: Dbu,
    },
    /// Every shape on the layer, and every edge of an edge layer.
    ///
    /// Deck: `forbidden(L)`, kind `forbidden`. Write what is forbidden as the
    /// layer: `forbidden(licon and poly and (diff or tap))`, a maximum area as
    /// `forbidden(L.with_area(> area))`, or rectangle-only shapes as
    /// `forbidden(L.non_rectangles())`. Shapes are reported as the store holds
    /// them, not merged.
    ///
    /// One violation per polygon, at a vertex of its outer ring, with
    /// `measured` its area (holes excluded) against a `limit` of 0. One per
    /// edge of an edge layer, at its midpoint, with `measured` its length,
    /// naming no shape (`PolyId(u32::MAX)`). `examined` counts polygons plus
    /// edges.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-005, DRC-006, DRC-018, DRC-050, DRC-074, DRC-090, DRC-095,
    /// DRC-097, ERC-A10. Rules: sky130 x.8, licon.6, licon.17, capm.7 and
    /// x.23a, IHP 3.2, Cnt.j and LBE.h, GF180 PL.9; LEF58 `RECTONLY`;
    /// `KLayout` `overlapping` and `non_rectangles`.
    ///
    /// Limits: device-family and seal-ring geometry is expressible through
    /// marker layers, but device-parameter rules and "one seal ring per chip,
    /// nothing outside it" are not.
    Forbidden {
        /// The layer, or edge layer, that must be empty.
        layer: LayerId,
    },
    /// An `outer` shape holding fewer than `min_count`, or more than
    /// `max_count`, `inner` shapes.
    ///
    /// Deck: `contains(outer, inner) >= count` (a minimum), `<= count` (a
    /// maximum) or `== count` (exactly that many), kind `must_contain`. Both
    /// layers are merged, so touching inner shapes count as one. An inner
    /// figure is held when one outer figure covers all of it; one across the
    /// outer's edge is held by none.
    ///
    /// One violation per outer figure holding too few or too many, on the
    /// `outer` layer, at the centre of one of its rectangles. `measured` is
    /// the count held and `limit` the bound it broke, `shapes.0` the lowest
    /// drawn outer row under the figure. `examined` counts outer figures.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-048, DRC-049, DRC-085, DRC-090. Rules: sky130 licon.4, licon.16 and
    /// nwell.4, IHP Cnt.g and Cnt.h, GF180 DN.3; the maximum is sky130 rpm.1g
    /// to rpm.1k ("only 1 licon is allowed in `xhrpoly_0p35`
    /// `prec_resistor_terminal`"); `KLayout` `covering` and `not_covering` with
    /// a count range.
    MustContain {
        /// The holding layer; findings are reported on it.
        outer: LayerId,
        /// The held layer.
        inner: LayerId,
        /// The fewest inner figures each outer figure must hold; 0 for no
        /// minimum.
        min_count: u32,
        /// The most it may hold, at least `min_count` and at least 1;
        /// `u32::MAX` for no maximum.
        max_count: u32,
    },
    /// An `inner` shape not entirely inside `outer`.
    ///
    /// Deck: `inside(inner, outer)`, kind `must_be_inside`. Both layers are
    /// merged. An inner figure passes when one outer figure covers all of it;
    /// touching the outer's edge from inside is inside.
    ///
    /// One violation per inner figure left partly or wholly outside, on the
    /// `inner` layer, at the centre of one of its rectangles. `measured` is
    /// the area left outside against a `limit` of 0, `shapes.0` the lowest
    /// drawn inner row under the figure. `examined` counts inner figures.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-007, DRC-048. Rules: sky130 licon.18 and x.5, IHP Pin.a to Pin.h;
    /// `KLayout` `inside`.
    ///
    /// Limits: a pin drawn inside its shape can be checked, but the spacing
    /// of pin centres cannot, and a label on no net aborts extraction rather
    /// than reporting here.
    MustBeInside {
        /// The layer that must lie inside; findings are reported on it.
        inner: LayerId,
        /// The layer that must cover it.
        outer: LayerId,
    },
    /// Two shapes on the same net, or on different nets, closer than `limit`.
    ///
    /// Deck: `space(L; nets: same | different) >= len`, kind `net_spacing`,
    /// or `space(A, B; nets: different) >= len` between two layers. Nets are
    /// the extracted ones, joined through vias and other layers, so every
    /// layer must be a conductor. On one layer the pairs are shapes in
    /// different merged figures; across two, every pair of a shape on
    /// `layer` and one on `other`, overlap included (a distance of 0), as
    /// [`Rule::MinSpacingDiff`] measures them. Either way only pairs whose
    /// net relation is the one asked for are judged. Two layers take only
    /// `nets: different` ([`DrcError::WrongParamType`] on `same_net`): one
    /// net's shapes overlap wherever a cut joins them.
    ///
    /// One violation per offending pair, at the midpoint of its measured
    /// points, on `layer`. `examined` counts the pairs of the asked relation. Records [`Outcome::Refused`] when the run has no nets
    /// ([`RuleSet::run`]) or a shape on a layer carries no net.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-080, DRC-081. Rules: GF180 NW.2a, NW.2b and DN.2a, IHP NW.b; LEF
    /// `SPACING SAMENET`; `KLayout` `nets` with `props_eq` or `props_ne`;
    /// between two layers, sky130 nwell.7 ("Min spacing between nwell and
    /// deep nwell on separate nets") and hvnwell.8, IHP NW.b1 and NBL.c.
    ///
    /// A derived layer's shape on no net of its own takes the net of the
    /// conductor shapes it is computed from (the drawn layers in its
    /// expression) that it overlaps with a positive area, when they are on
    /// one net: so `hv_nwell = nwell.interacting(hvi)` carries its n-well's
    /// net, and sky130 hvnwell.8 ("Min space between HV_nwell and any nwell
    /// on different nets") is `space(hv_nwell, nwell; nets: different)`. A
    /// shape over no such conductor, or over several nets, is on no net, and
    /// the rule records `Refused`.
    ///
    /// Limits: a layer computed only from layers that are no conductor
    /// (sky130's deep n-well, which its deck does not connect) carries no
    /// nets.
    NetSpacing {
        /// The conductor layer measured, and the one findings are reported on.
        layer: LayerId,
        /// The second conductor layer; `None` for pairs within `layer`.
        other: Option<LayerId>,
        /// `true` checks pairs on one net (deck `nets: same`), `false` pairs
        /// on different nets.
        same_net: bool,
        /// The smallest legal gap, in grid units; positive.
        limit: Dbu,
    },
    /// Two shapes closer than their cell of a spacing table.
    ///
    /// Deck: `space_table(L; prl: [..], width: [..], space: [[..], ..])`, kind
    /// `spacing_table`. Pairs are shapes in different merged figures, never a
    /// polygon and its own hole. In each row, a pair takes the column of the
    /// last `prl` its run strictly exceeds, the run measured as for
    /// [`Rule::PrlSpacing`] on the edges facing each other across a gap
    /// of at most that column's cell in that row (the spacing it judges).
    /// It is held, for each row above the first, to that row's cell, measured
    /// from the part of either shape strictly wider than the row's width
    /// (where a `width + 1` square fits in the merged layer): past the first
    /// column, on a stretch of the wide part facing the other figure that runs
    /// past the column's length, its gap read on that same stretch
    /// (projected); in the first column, at any distance; and to the
    /// first row's cell measured from the whole shapes, the column from their
    /// run. A thin tab of a wide plate is held to the first row only, and so
    /// is a thin line beside a wide part too short to run past the column's
    /// length (IHP M1.e "at least one line is wider than 0.3 um and the
    /// parallel run is more than 1.0 um", SG13G2 layout rules 5.16; as
    /// IHP's `5_16_metal1.drc` measures it, projected from the wide part).
    ///
    /// One violation per pair, at its highest failing row, with `limit` that
    /// row's cell and `measured` the distance that row measured, at the
    /// midpoint of the points that row measured. `examined` counts the pairs.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-025, DRC-026, DRC-027. Rules: IHP M1.b, M1.e and M1.f; LEF
    /// `SPACINGTABLE PARALLELRUNLENGTH`.
    ///
    /// The row is keyed on the wider shape only; LEF `SPACINGTABLE
    /// TWOWIDTHS`, keyed on both widths, is [`Rule::TwoWidthSpacingTable`].
    SpacingTable {
        /// The layer measured, drawn or derived.
        layer: LayerId,
        /// Index into [`RuleSet::tables`].
        table: u32,
    },
    /// Too little space from the wide part of a shape, or from what is
    /// attached to it.
    ///
    /// Deck: `wide_space(L; width: len, attached: len) >= len`, kind
    /// `attached_wide_spacing`. As [`Rule::WideDependentSpacing`], with each
    /// wide part grown by `attached` (square corners) and clipped to its own
    /// merged figure, so stubs extending from the wide part are held to the
    /// limit too (sky130 m1.3a "features attached to or extending from
    /// `huge_met1` for a distance of up to 0.28 um").
    ///
    /// One violation per offending pair, at the midpoint of its measured
    /// points (one on a grown wide part). `examined` counts pairs where either
    /// shape has a wide part.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-028. Rules: sky130 m1.3a; LEF `SPACING RANGE INFLUENCE`.
    ///
    /// This is LEF `SPACING spacing RANGE minWidth maxWidth INFLUENCE
    /// influenceLength` with its plain `RANGE` row: "any length of the stub
    /// wire that is less than or equal to influenceLength from the wide wire
    /// inherits the wide wire spacing" (LEF/DEF 5.8, `SPACING`), for a wide
    /// part at least `width_threshold` wide.
    ///
    /// Limits: the stub-width `RANGE stubMinWidth stubMaxWidth` and LEF
    /// `SPACINGTABLE INFLUENCE` (spacing between two stubs near a wide wire)
    /// are missing, and so is the wide range's upper bound. The growth is
    /// square, so near a corner of the wide part a little more of a stub is
    /// held than LEF's distance asks (fails closed).
    AttachedWideSpacing {
        /// The layer measured, drawn or derived.
        layer: LayerId,
        /// The side of the square that makes a part wide, in grid units;
        /// positive.
        width_threshold: Dbu,
        /// How far from the wide part, in grid units, the rest of the figure
        /// counts as attached; positive.
        attached: Dbu,
        /// The smallest legal gap, in grid units; positive.
        limit: Dbu,
    },
    /// An edge of an edge layer shorter than `limit`.
    ///
    /// Deck: `length(E) >= len`, kind `edge_min_length`, as sky130 difftap.4
    /// on the butting edges `tap.edges() and diff.edges()`.
    ///
    /// One violation per short edge, at its midpoint, naming no shape
    /// (`PolyId(u32::MAX)`). `examined` counts edges. Records
    /// [`Outcome::Refused`] when an edge is not axis-aligned.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-021, DRC-051. Rules: sky130 difftap.4 and mf.2, IHP Rsil.f and
    /// Rppd.e, GF180 DF.3b.
    ///
    /// Limits: a straight feature's length is its box's longer side,
    /// `forbidden(L.with_bbox_max(< len))`; a bent feature's length along its
    /// path is not measured, and edge layers cannot be extended (sky130
    /// difftap.6).
    EdgeMinLength {
        /// The edge layer.
        layer: LayerId,
        /// The shortest legal edge, in grid units; positive.
        limit: Dbu,
    },
    /// Two parallel edges closer than `limit`.
    ///
    /// Deck: `space(E[, F]) >= len`, kind `edge_spacing`. Pairs are parallel
    /// edges of `a`, or one of `a` and one of `b`, measured edge to edge
    /// (Euclidean, so end to end too), whatever side their shapes are on.
    /// Edges that touch are not a spacing, and perpendicular edges are not
    /// measured, as `KLayout`'s default.
    ///
    /// One violation per pair closer than `limit`, on layer `a`, at the middle
    /// of the gap between their bounding boxes, naming no shape. `examined`
    /// counts the parallel pairs within reach. Records [`Outcome::Refused`]
    /// when an edge is not axis-aligned.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-051. Rules: sky130 difftap.5 and difftap.7, IHP pSD.e to pSD.g.
    ///
    /// Limits: edge layers cannot be extended (sky130 difftap.6).
    EdgeSpacing {
        /// The first edge layer; findings are reported on it.
        a: LayerId,
        /// The second edge layer; `None` pairs the edges of `a` with each
        /// other.
        b: Option<LayerId>,
        /// The smallest legal gap, in grid units; positive.
        limit: Dbu,
    },
    /// An edge whose outside is not covered by `outer` for `limit`.
    ///
    /// Deck: `enclosure(E, L) >= len`, kind `edge_enclosure`, as sky130
    /// nsd/psd.5a on `diff.edges() not tap.edges()`. Each edge is measured
    /// straight out from itself along its whole length, on the side away from
    /// its shape: the depth to which the merged `outer` layer covers that
    /// strip without a gap.
    ///
    /// One violation per edge covered less than `limit` deep, on the edge
    /// layer, at the edge's midpoint, naming no shape. `measured` is the
    /// covered depth. `examined` counts edges. Records [`Outcome::Refused`]
    /// when an edge is not axis-aligned or `outer` fails validation.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-051. Rules: sky130 nsd.5a, psd.5a and licon.5b, GF180 NP.3d.
    ///
    /// Limits: a gap in `outer` diagonally off a corner of the shape is not
    /// seen. Pair it with [`Rule::MinEnclosure`] where the corner matters.
    EdgeEnclosure {
        /// The edge layer.
        edges: LayerId,
        /// The polygon layer that must cover the strip; merged.
        outer: LayerId,
        /// The depth the strip must be covered, in grid units; positive.
        limit: Dbu,
    },
    /// Too many, or too few, shapes on a layer in the whole layout.
    ///
    /// Deck: `count(L) <= n` or `count(L) >= n`, kind `count`. The layer is
    /// merged first, so touching shapes, and shapes meeting at a corner, are
    /// one; the count is of the merged figures in the whole layout, a
    /// quantity per chip. Write a device count on its marker layer, and "one
    /// seal ring per chip" as `count(seal) <= 1` with `count(seal) >= 1`.
    ///
    /// One violation when the count is above a maximum or below a minimum, at
    /// the centre of the die (the extent of the drawn layers, as
    /// [`Rule::GlobalDensity`] takes it without a boundary), `measured` the
    /// count. `shapes.0` is the layer's first row, or none on an empty layer.
    /// `examined` counts figures. Records [`Outcome::Skipped`] when nothing is
    /// drawn.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-091, DRC-095. Rules: IHP npn13G2.bR ("max. recommended total
    /// number of npn13G2 emitters per chip") and Seal.m ("only one sealring
    /// per chip"); `KLayout` `count` on a merged layer.
    Count {
        /// The layer counted, drawn or derived.
        layer: LayerId,
        /// The count, a minimum or a maximum by `sense`; zero is legal.
        limit: u32,
        /// `Minimum` for `>=`, `Maximum` for `<=`.
        sense: LimitSense,
    },
    /// A shape whose bounding box is more than `limit` times as long as it is
    /// wide.
    ///
    /// Deck: `aspect_ratio(L) <= r`, kind `aspect_ratio`, `r` a bare number.
    /// The layer is merged first. A figure's aspect ratio is its bounding
    /// box's longer side over its shorter, so it is at least 1 and a square
    /// box reads 1 whichever way round, as `KLayout`'s
    /// `with_bbox_aspect_ratio` reads it. A plate's length over its width is
    /// this ratio for a rectangle, which a rectangle-only rule
    /// ([`Rule::Forbidden`] on `L.non_rectangles()`) can require.
    ///
    /// One violation per merged figure whose ratio is above `limit`, at the
    /// centre of its first rectangle (inside the figure), `measured` the
    /// ratio. `shapes.0` is the lowest drawn row under the figure. `examined`
    /// counts figures. The ratio is the nearest `f64` to the quotient of the
    /// two sides, and the limit the nearest to the deck's number, so a figure
    /// exactly at the limit passes.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-022. Rules: sky130 capm.6 ("maximum aspect ratio (length/width)"
    /// of a `MiM` capacitor) and li.2 ("max ratio of length to width of LI
    /// without licon or mcon", 10); `KLayout` `with_bbox_aspect_ratio` and
    /// `bbox_aspect_ratio`.
    AspectRatio {
        /// The layer measured, drawn or derived.
        layer: LayerId,
        /// The largest legal ratio; positive and finite.
        limit: f64,
    },
    /// More area on a layer, in the whole layout, than `limit`.
    ///
    /// Deck: `total_area(L) <= area`, kind `total_area`. The layer is merged
    /// first, so overlapping shapes count once and holes not at all: the
    /// area `L` covers in the whole layout, a quantity per chip.
    ///
    /// One violation when the area is above `limit`, at the centre of the die
    /// (the extent of the drawn layers, as [`Rule::Count`] places it),
    /// `measured` the area. `shapes.0` is the layer's first row, or none on an
    /// empty layer. `examined` counts figures. Records [`Outcome::Skipped`]
    /// when nothing is drawn.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-091. Rules: IHP MIM.gR ("max. recommended total MIM area per
    /// chip", 174800 µm²); `KLayout` `area` on a layer ("the total area of
    /// all polygons", merged).
    TotalArea {
        /// The layer measured, drawn or derived.
        layer: LayerId,
        /// The largest legal area, in square grid units; positive.
        limit: DbuArea,
    },
    /// A cut whose size is none of the legal classes.
    ///
    /// Deck: `size(L; allowed: [w x h, ..])`, kind `cut_class`. The layer is
    /// merged first, as for [`Rule::CutSize`], so two abutting cuts are one
    /// slot. A figure passes when it is a rectangle with no hole whose shorter
    /// and longer sides are one listed size's, either way round: a cut class
    /// as LEF58 `CUTCLASS` defines one (a cut belongs to the class whose
    /// width is its shorter side and length its longer, as `OpenROAD` matches
    /// it).
    ///
    /// One violation per figure in no class, at the centre of its bounding
    /// box, `measured` the number of classes it matches (0) against a `limit`
    /// of 1. `shapes.0` is the lowest drawn row under the figure. `examined`
    /// counts figures.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-014. Rules: sky130 via.1b ("three sizes of square vias allowed
    /// inside areaid:mt: 0.150um, 0.230um and 0.280um"); LEF58 `CUTCLASS`.
    /// `OpenROAD` raises nothing for a cut in no class; this rule does, as
    /// via.1b requires.
    CutClass {
        /// The cut layer.
        layer: LayerId,
        /// Index into [`RuleSet::classes`].
        classes: u32,
    },
    /// Two edges facing each other across their shapes' material, closer
    /// than `limit`: a width measured between chosen edges.
    ///
    /// Deck: `width(E) >= len` on an edge layer, kind `edge_width`. A pair is
    /// two parallel edges of `E` whose inner sides face each other (each
    /// edge's shape lies toward the other: `KLayout`'s "back to back" relation
    /// for `width` on an edge layer), with projections overlapping by a
    /// positive length, measured straight across. Every such pair counts:
    /// an edge between them does not shield them, as on a `KLayout` edge
    /// layer, where shielding does not apply.
    ///
    /// The edges choose the width measured. A transistor's channel length is
    /// the gap between the gate's sides inside the diffusion,
    /// `width(gate.edges() not diff.edges())`, and its channel width the gap
    /// between the sides on the diffusion's edge,
    /// `width(gate.edges() and diff.edges())`, each exact for a straight gate;
    /// a width along one axis only is `width(L.edges().horizontal())`.
    ///
    /// One violation per pair closer than `limit`, at the middle of the gap
    /// between their bounding boxes, naming no shape. `examined` counts the
    /// parallel pairs within reach. Records [`Outcome::Refused`] when an edge
    /// is not axis-aligned.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-011, DRC-016, DRC-090. Rules: sky130 poly.1b ("min channel length (poly
    /// width)") and difftap.2 ("minimum channel width (diff and poly)"), IHP
    /// Gat.a1 to Gat.a4 (channel length per device), GF180 PL.2 ("gate width
    /// (channel length)"); ASAP7 M4.W.1 and M4.W.5 (vertical and horizontal
    /// width); `KLayout` `width` on an edge layer.
    EdgeWidth {
        /// The edge layer.
        layer: LayerId,
        /// The narrowest legal gap, in grid units; positive.
        limit: Dbu,
    },
    /// Two edges whose outer sides face each other, closer than `limit`: a
    /// spacing measured between chosen edges.
    ///
    /// Deck: `facing_space(E) >= len`, kind `edge_facing_space`. As
    /// [`Rule::EdgeWidth`] with the sides turned out: each edge's shape lies
    /// away from the other (`KLayout`'s "face to face" relation for `space`
    /// on an edge layer), so a gap between shapes, or a notch in one, is
    /// measured, and a shape's own width is not. [`Rule::EdgeSpacing`]
    /// measures whatever the sides.
    ///
    /// `facing_space(E; prl: len) >= len` judges only the pairs whose
    /// projections overlap by more than `prl`; the plain form is `prl: 0nm`,
    /// any positive overlap. With the edges across a layer's direction
    /// (`L.edges().vertical()` on a horizontal layer) and those shorter than
    /// a length left out (`.with_length(>= w)`), this is `LEF58_SPACING s
    /// WRONGDIRECTION [NONEOL w] [PRL p]` as `OpenROAD` `TritonRoute` checks
    /// it (`checkMetalSpacing_wrongDir`): edges whose orientation is not the
    /// layer's, either one shorter than `w` skipped, a pair exempt when its
    /// overlap is at most `p`, a violation when the two segments are closer
    /// than `s`, which over a positive overlap is the gap straight across.
    ///
    /// One violation per pair closer than `limit`, at the middle of the gap
    /// between their bounding boxes, naming no shape. `examined` counts the
    /// parallel pairs within reach that run alongside each other longer than
    /// `prl`. Records [`Outcome::Refused`] when an edge is not axis-aligned.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-016. Rules: ASAP7 M4.S.1 and M4.S.2 ("minimum vertical (horizontal)
    /// spacing between two M4 layer polygons' edges"), `LEF58_SPACING ..
    /// WRONGDIRECTION [NONEOL] [PRL]`; `KLayout` `space` on an edge layer.
    ///
    /// Limits: `LEF58_SPACING ... WRONGDIRECTION ... LENGTH` is not modelled:
    /// no public text defines it, and `TritonRoute` drops a rule that states
    /// it (DRT-333), as it drops a negative `PRL` (DRT-334).
    EdgeFacingSpace {
        /// The edge layer.
        layer: LayerId,
        /// The smallest legal gap, in grid units; positive.
        limit: Dbu,
        /// The overlap a pair must exceed to be judged, in grid units; 0 or
        /// more.
        prl: Dbu,
    },
    /// A shape of `region` inside which `layer` covers too little, or too
    /// much, of the area.
    ///
    /// Deck: `region_density(L, R) >= frac`, or `<=` for a maximum, kind
    /// `region_density`. Both layers are merged. Each figure of `R` is
    /// measured on its own: the area of `L` inside it over its own area,
    /// holes excluded, the pattern density over a device that
    /// [`Rule::Density`] cannot take, since its boundary reduces to one
    /// extent for the whole layer.
    ///
    /// One violation per region figure outside the limit, on the `region`
    /// layer, at the centre of the figure's first rectangle, `measured` the
    /// fraction. `shapes.0` is the lowest drawn region row under the figure.
    /// `examined` counts region figures.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-072, DRC-075. Rules: sky130 vpp.5a to vpp.5c ("max pattern density
    /// of met3.dg over capacitor.dg", 0.25, 0.3, 0.4) and vpp.11 ("min pattern
    /// density of (poly and diff) over capacitor.dg", 0.87); IHP Slt.i ("min.
    /// Metal:slit density for any Metal plate bigger than 35 µm x 35 µm", 6 %).
    RegionDensity {
        /// The layer whose coverage is measured.
        layer: LayerId,
        /// The regions, each measured on its own; findings are reported on it.
        region: LayerId,
        /// The fraction; finite, in `0..=1`.
        limit: f64,
        /// `Minimum` for `>=`, `Maximum` for `<=`.
        sense: LimitSense,
    },
    /// A shape whose width is none of the legal widths.
    ///
    /// Deck: `width(L; allowed: [w, ..])`, kind `allowed_width`. The layer is
    /// merged first. A figure's width is its narrowest width as
    /// [`Rule::MinWidth`] measures it (facing edges, and the Euclidean neck
    /// between two concave corners), compared exactly: for a rectangle, its
    /// shorter side. A figure with parts of several widths is judged by its
    /// narrowest.
    ///
    /// `width(L; allowed: [w, ..], open_last: true)` leaves the last width
    /// open: it and any wider width are legal, the others exact. This is
    /// LEF58 `WIDTHTABLE {width} ...` (LEF/DEF 5.8 Language Reference, "Width
    /// Table Rules": "All the given widths are exact width values, except
    /// for the last one, which is equal to or greater than the value"; in its
    /// Figure 1-32 `WIDTHTABLE 0.10 0.15 0.20 0.25 0.30 0.40` admits 0.42,
    /// which only `MAXWIDTH 0.40`, a [`Rule::MaxWidth`] row, rejects).
    ///
    /// One violation per figure whose width is not legal, at the centre of
    /// its first rectangle, `measured` the width (floored) against the nearest
    /// listed width (the smaller on a tie). `shapes.0` is the lowest drawn
    /// row under the figure. `examined` counts figures.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-015, DRC-090. Rules: sky130 rpm.1b to rpm.1f ("min/max
    /// `prec_resistor` width" 0.35, 0.69, 1.41, 2.85, 5.73 µm, one per
    /// resistor type: one rule per type with a one-width list, or one rule
    /// with all five); LEF58 `WIDTHTABLE`.
    ///
    /// Limits: LEF58 `WIDTHTABLE` checks "only the shorter dimension of the
    /// rectangles" a polygon "will be fractured into", and neither the LEF
    /// text nor `OpenROAD` (whose `TritonRoute` reads only an `ORTHOGONAL`
    /// table's first width) says how to fracture: maximal rectangles give
    /// two overlapping bars a width neither has, and slabs depend on their
    /// axis. So a figure is judged by its narrowest width, which is LEF's
    /// reading on a rectangle. `WRONGDIRECTION` (a list for wires across the
    /// layer's direction) needs a wire's direction, which is that fracture's,
    /// and `ORTHOGONAL` is not checked. ASAP7 M4.W.3 and M4.W.4 (no even
    /// multiple of the minimum width) are not a list.
    AllowedWidth {
        /// The layer measured, drawn or derived.
        layer: LayerId,
        /// Index into [`RuleSet::widths`].
        widths: u32,
        /// Whether the last width and every wider one are legal, rather
        /// than the last exactly.
        open_last: bool,
    },
    /// A design whose redundant-via rate is below `limit`.
    ///
    /// Deck: `via_redundancy(cut, lower, upper; pitch: len, space: len) >=
    /// frac`, kind `via_redundancy`. A via is the merged `cut` figures on a
    /// connector, a merged `lower` figure and a merged `upper` figure that
    /// overlap (as [`Rule::CutAreaChange`] reads them). A single-cut via is
    /// dead when no redundant cut can go beside it: none of its cut's four
    /// neighbours, its box moved `pitch` left, right, up or down, lies wholly
    /// on both of its figures at least `space` from every cut, its own
    /// included. The rate is `1 - dead / vias`, the redundant-via rate of
    /// Xu, Huang and Wong (ASP-DAC 2005), which counts the single vias that
    /// cannot be doubled. Values deck-supplied; no public deck states them:
    /// where a second cut may go is the foundry's via-doubling rule.
    ///
    /// At most one violation, on `cut`, at the centre of the first dead
    /// via's cut, `measured` the rate against `limit`, naming no shape.
    /// `examined` counts vias.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-117. Rules: Calibre `YieldAnalyzer`'s via redundancy, Xu et al.
    /// (ASP-DAC 2005).
    ViaRedundancy {
        /// The cut layer.
        cut: LayerId,
        /// The layer under the cuts.
        lower: LayerId,
        /// The layer over the cuts.
        upper: LayerId,
        /// How far a redundant cut sits from the one it doubles, centre to
        /// centre along one axis, in grid units; positive.
        pitch: Dbu,
        /// The least gap from a redundant cut to any cut, in grid units;
        /// 0 or more.
        space: Dbu,
        /// The least rate, from 0 to 1.
        limit: f64,
    },
    /// A design whose DFM score over a recommended rule's findings is below
    /// `limit`.
    ///
    /// Deck: `dfm_score(L[, outer]; check: space | width | enclosure,
    /// required: len, recommended: len, rate: frac) >= score`, kind
    /// `dfm_score`. The check runs at the recommended value (`space(L)`,
    /// `width(L)`, or `enclosure(L, outer)`, as [`Rule::MinSpacing`],
    /// [`Rule::MinWidth`] and [`Rule::MinEnclosure`] measure them); each of
    /// its findings scores 0 at or below the required value and 1 at the
    /// recommended one, linearly between, and the design's score is the
    /// product over the findings of `1 - rate * (1 - score)`. This is the DFM
    /// scoring of Tripathi et al., "In Design DFM Rule Scoring and Fixing
    /// Method using ICV" (SNUG 2017, arXiv:1805.10016): a violation "at DRC
    /// margin or below" scores 0, one "meeting DFM requirement" 1, "between
    /// 0-1" between, and the design score is a product over violations of a
    /// function of each score and the rule's failure rate (its Equation 2,
    /// a Poisson yield model), signed off at a value such as 0.99. The paper
    /// prints neither the curve between the margins nor that function: the
    /// line between them and `1 - rate * (1 - score)` (each finding fails
    /// with the rule's failure rate at the required value, never at the
    /// recommended one) are GPurify's reading. Values deck-supplied; no
    /// public deck states them.
    ///
    /// At most one violation, on `L`, at the lowest-scoring finding's
    /// marker, `measured` the design's score against `limit`, naming that
    /// finding's shapes. `examined` is the check's.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-111. Rules: GlobalFoundries' DFM scoring with IC Validator
    /// (arXiv:1805.10016), Calibre `YieldAnalyzer`'s recommended-rule scoring.
    DfmScore {
        /// The check the score reads.
        check: DfmCheck,
        /// The layer measured; the inner layer of an enclosure.
        layer: LayerId,
        /// The outer layer of an enclosure; `None` for the others.
        outer: Option<LayerId>,
        /// The rule's required value (a score of 0), in grid units;
        /// positive and below `recommended`.
        required: Dbu,
        /// The recommended value (a score of 1), in grid units.
        recommended: Dbu,
        /// The rule's failure rate, from 0 to 1.
        rate: f64,
        /// The least score that signs off, from 0 to 1.
        limit: f64,
    },
    /// A place where the layer matches a deck-supplied pattern.
    ///
    /// Deck: `pattern(L; window: w x h, shapes: [x0 x y0, x1 x y1, ..],
    /// ignore: [x0 x y0, x1 x y1, ..] | none)`, kind `pattern_match`. A
    /// pattern is a window `[0, w] x [0, h]` and the shapes of `L` inside it,
    /// rectangles given by two opposite corners each, with optional
    /// don't-care boxes the same way, as the pattern-matching patents state it
    /// (US7757190B2: a pattern is the layout inside a window about an anchor,
    /// matched in its eight orientations; don't-care regions match anything).
    /// A match is a placement of the window, in any of the eight orientations
    /// of the square, where `L` clipped to the window equals the shapes
    /// outside the don't-care boxes, exactly. Placements are tried with the
    /// pattern's anchor (the least corner of its merged shapes strictly inside
    /// the window and off every don't-care box) on each corner of the merged
    /// layer, which every match puts there. Every value, the pattern library
    /// included, is the deck's: values deck-supplied; no public deck states
    /// them (foundry hotspot libraries are not public).
    ///
    /// One violation per distinct matching window, at its centre (floored),
    /// `measured` the pattern's shape area against a `limit` of 0, naming no
    /// shape. `examined` counts the placements tried.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-114. Rules: Calibre Pattern Matching, IC Validator and Pegasus
    /// pattern DRC, as US7757190B2, US11487930B2 and US9171126B1 describe them.
    ///
    /// Limits: one layer per pattern, and edges matched exactly: the patents'
    /// ranged (fuzzy) edges and multi-layer patterns are not modelled. A
    /// pattern needs a corner strictly inside its window off every don't-care
    /// box ([`DrcError::BadTable`] otherwise).
    PatternMatch {
        /// The layer searched, drawn or derived.
        layer: LayerId,
        /// Index into [`RuleSet::patterns`].
        pattern: u32,
    },
    /// A connector whose cut area changed between two databases by more than
    /// its cut count allows.
    ///
    /// Deck: `cut_area_change(pre, post, lower, upper; cuts: [count, ..],
    /// change: [area, ..])`, kind `cut_area_change`. The two databases are
    /// two layers of one layout (the first's cuts on `pre`, the second's on
    /// `post`, as an XOR flow streams both in on separate layers). A
    /// connector is a merged `lower` figure and a merged `upper` figure that
    /// overlap; its footprint is where they overlap, its cuts the merged
    /// `pre` figures overlapping the footprint (a cut over two connectors
    /// counts in each). Its change is the difference, either way, between
    /// the `pre` area and the `post` area inside the footprint. The cut count
    /// picks a band of [`CutAreaBands`], the last whose `cuts` it reaches,
    /// and a change above that band's `change` is a violation; a connector
    /// with fewer cuts than the first band is not judged. sky130 ct.irdrop.1-3
    /// ("For 1 <= n <= 10 contacts on the same connector, mcon area pre- and
    /// post- Cu conversion must differ by no more than 0.2", 11-100 0.3, over
    /// 100 0.7) and via.irdrop to via4.irdrop are this rule. Values
    /// deck-supplied; no public deck states them: the manual names no
    /// connector, and its unit (µm, for an area) was added by a script
    /// (skywater-pdk 9039be3); the rule applies to a copper back end sky130
    /// does not offer (flags CU, IR).
    ///
    /// One violation per failing connector, on `pre`, at the centre of its
    /// footprint's box (floored), `measured` the change against the band's
    /// limit, naming no shape. `examined` counts connectors.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-068. Rules: sky130 ct.irdrop.1-3, via.irdrop.1-4 to
    /// via4.irdrop.1-4.
    CutAreaChange {
        /// The first database's cuts.
        pre: LayerId,
        /// The second database's cuts.
        post: LayerId,
        /// The layer under the cuts.
        lower: LayerId,
        /// The layer over the cuts.
        upper: LayerId,
        /// Index into [`RuleSet::cut_area_bands`].
        bands: u32,
    },
    /// Too much mean short-circuit critical area over a defect-size
    /// distribution.
    ///
    /// Deck: `critical_area(L; radii: [len, ..], weights: [frac, ..]) <=
    /// area`, kind `mean_critical_area`. The mean is `Σ weight · A(radius)`,
    /// each `A` the critical area [`Rule::CriticalArea`] measures for a square
    /// defect of that half-side: the average critical area over a defect-size
    /// distribution (Stapper, IBM J. Res. Dev. 27(6), 1983; Papadopoulou and
    /// Lee, IEEE TCAD 18(4), 1999; Calibre `YieldAnalyzer` averages it the
    /// same way, Siemens white paper 81850), the distribution discretised by
    /// the deck at the radii it lists, with the weight of each (a defect
    /// density over size, such as Stapper's `1/r³`, sampled and normalised by
    /// the deck). Values deck-supplied; no public deck states them.
    ///
    /// One violation when the mean is above `limit`, at the centre of the box
    /// of every radius's critical area, `measured` the mean floored. The
    /// comparison is exact in `f64`. `examined` counts figures.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-112.
    ///
    /// Limits: shorts only, as [`Rule::CriticalArea`]; figures stand for
    /// nets.
    MeanCriticalArea {
        /// The layer measured.
        layer: LayerId,
        /// Index into [`RuleSet::defect_sizes`].
        sizes: u32,
        /// The largest legal mean, in square grid units; positive.
        limit: DbuArea,
    },
    /// A window whose density on `layer` is below what its coverage by
    /// `cover` asks for.
    ///
    /// Deck: `cover_density(L, C[, boundary]; window: len, step: len, cover:
    /// [frac, ..], density: [frac, ..], inclusive: bool)`, kind
    /// `cover_density`. Windows are swept as for [`Rule::Density`], over the
    /// die (the drawn layers' extent, or `boundary`'s), the outside of the die
    /// counting as empty. In each window the merged `cover`'s coverage picks
    /// a band of [`CoverBands`]: the last whose `cover` fraction it reaches
    /// (`inclusive`) or exceeds (not `inclusive`); the merged `layer`'s
    /// coverage below that band's `density` is a violation, and a window
    /// below every band is not judged. sky130 m1.- to m4.- ("An entire
    /// 700x700 window is covered by cmm1 waffleDrop, and metX PD < 70% for
    /// same window. 80-100% of 700x700 window is covered ..., and metX PD <
    /// 65% ..." down to 30-40% and 30%) is this rule with a 700 µm window:
    /// the manual states no window step and does not say which band a
    /// coverage of exactly 80% is in, so the deck states both. Values
    /// deck-supplied; no public deck states them, and Cadence's public sky130
    /// DRM (2025-07-22) lists the rule as obsolete.
    ///
    /// One violation per failing window, on `layer`, at the window's centre
    /// (floored), `measured` the `layer` coverage against the band's
    /// `density`, naming no shape. Fractions compare in `f64`, as for
    /// [`Rule::Density`]. `examined` counts windows; an empty die is
    /// [`Outcome::Skipped`].
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-076. Rules: sky130 m1.- to m4.- (waffle drop, flag RC).
    CoverDensity {
        /// The layer whose density is held.
        layer: LayerId,
        /// The layer whose coverage picks the band.
        cover: LayerId,
        /// The die outline; `None` takes the drawn layers' extent.
        boundary: Option<LayerId>,
        /// The window's side, in grid units; positive.
        window: Dbu,
        /// The sweep step, in grid units; positive.
        step: Dbu,
        /// Index into [`RuleSet::cover_bands`].
        bands: u32,
    },
    /// A layer whose drawing does not start at the layout's origin.
    ///
    /// Deck: `origin(L)`, kind `origin`. The lower-left corner of the
    /// bounding box of every shape on `L` must be `(0, 0)`: sky130 x.19
    /// "Lower left corner of the seal ring should be at origin i.e (0,0)",
    /// written on the seal ring's layer. A layer is placed as drawn, so the
    /// rule reads the flattened coordinates, after every placement.
    ///
    /// One violation, at that corner, `measured` its distance from the
    /// origin (floored) against a `limit` of 0. `shapes.0` is the layer's
    /// first row. `examined` counts the layer's rows; an empty layer is
    /// [`Outcome::Skipped`] with
    /// [`SkipReason::EmptyLayer`](crate::report::SkipReason::EmptyLayer).
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-095, DRC-097. Rules: sky130 x.19.
    Origin {
        /// The layer whose box must start at the origin, drawn or derived.
        layer: LayerId,
    },
    /// A narrow part of a shape attached to its wide part: a protrusion
    /// narrower than `limit` from a wire at least `wide` wide.
    ///
    /// Deck: `protrusion_width(L; wide: len) >= len`, kind
    /// `protrusion_width`. The layer is merged first. A figure's wide part is
    /// where a `wide` square fits in it, as for [`Rule::WideDependentSpacing`];
    /// its narrow parts are what no `limit` square covers. Each narrow part
    /// that touches the wide part, a corner counting, is a protrusion
    /// narrower than `limit` from a wire at least `wide` wide, and a
    /// violation: LEF `PROTRUSIONWIDTH width1 LENGTH 0 WIDTH width2`, which
    /// LEF/DEF 5.8 (p. 76-77) defines as "the width of the protrusion wire
    /// should always be checked independent of the length of the wire" when
    /// the protrusion "connects to a wire that has a width greater than or
    /// equal to width2". A part exactly `limit` wide is legal, and a wire
    /// exactly `wide` wide is wide.
    ///
    /// One violation per protrusion, at the centre of its bounding box
    /// (floored), `measured` its narrowest width as [`Rule::MinWidth`]
    /// measures it (floored). `shapes.0` is the lowest drawn row under it.
    /// `examined` counts merged figures.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-125. Rules: LEF `PROTRUSIONWIDTH`.
    ///
    /// Limits: a positive `LENGTH`, which exempts a protrusion at least that
    /// long, is not modelled: LEF/DEF 5.8 measures the length "by the
    /// shortest possible path among all of the protrusion wires with width
    /// smaller width1 ... by the shortest outside edges of the wires" and
    /// settles the reading only by figure; no open tool checks it
    /// (`OpenROAD` parses and stores the statement and checks nothing).
    ProtrusionWidth {
        /// The layer measured, drawn or derived.
        layer: LayerId,
        /// The width from which a wire is wide (LEF `width2`), in grid
        /// units; positive.
        wide: Dbu,
        /// The least legal protrusion width (LEF `width1`), in grid units;
        /// positive.
        limit: Dbu,
    },
    /// A corner whose angle inside its shape is below `limit` degrees: an
    /// acute angle.
    ///
    /// Deck: `interior_angle(L) >= deg`, or `interior_angle() >= deg` for
    /// every drawn layer, kind `min_interior_angle`. Reads each store row as
    /// drawn, as [`Rule::Angle`] does (a derived layer repeats its operands'
    /// corners), so it measures 45-degree and other diagonal geometry and
    /// never refuses. A corner's interior angle is measured on its shape's
    /// side, 0 to 360 degrees: 90 at a rectangle's corner, 270 at an L's
    /// inner corner, 45 at a right isosceles triangle's acute corners, 0 at a
    /// spike that doubles back. A corner on a hole's ring is measured on the
    /// shape's side too, so a hole's corner is never acute.
    ///
    /// One violation per vertex below the limit, at the vertex, `measured`
    /// its angle in degrees, rounded to 1e-9 degree so a right angle reads
    /// exactly 90. A zero-length edge is skipped. `examined` counts the
    /// vertices measured.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-003. Rules: IHP 3.1 ("shapes with acute angles <87 degree are not
    /// allowed on any layer"), GF180 SH.2 ("avoid … shapes with acute angles
    /// (angles <90 deg)"); Calibre `FLAG ACUTE`; `KLayout`'s polygon form of
    /// `with_angle`, as IHP's deck uses it, and `corners` (by the turn).
    MinInteriorAngle {
        /// One layer's rows, or `None` for every drawn layer.
        layer: Option<LayerId>,
        /// The smallest legal angle, in degrees; positive and finite.
        limit: f64,
    },
    /// A drawn polygon that is no valid polygon: it crosses or touches
    /// itself, or it encloses no area.
    ///
    /// Deck: `valid(L)`, or `valid()` for every drawn layer, kind
    /// `polygon_validity`. Each store row is checked as drawn, as the layer
    /// validation every other rule runs checks it
    /// ([`gpurify_geom::view::ring_defect`]): fewer than three vertices, two
    /// equal consecutive vertices or zero signed area is degenerate, and two
    /// non-adjacent edges sharing a point, other than a pinch where two parts
    /// meet at a corner, is a self-intersection. Its angles are not asked: a
    /// 45-degree polygon is valid. Where another rule records
    /// [`Outcome::Refused`] for such a layer, this one names each polygon.
    ///
    /// One violation per invalid row, at its first vertex, `measured`
    /// `Count(0)` against a `limit` of 1, `shapes.0` the row. `examined`
    /// counts rows. Never refuses.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-004. Rules: IHP 3.1 ("self-intersecting polygons must be
    /// avoided"); Calibre `FLAG NONSIMPLE`; `KLayout` `odd_polygons`.
    PolygonValidity {
        /// One layer's rows, or `None` for every drawn layer.
        layer: Option<LayerId>,
    },
    /// A run of short edges that LEF `MINSTEP` rejects.
    ///
    /// Deck: `min_step(L; max_edges: n) >= len`, or `min_step(L; corner:
    /// outside | inside | step, length_sum: len | none) >= len`, kind
    /// `min_step`. The layer is merged first. An edge is short when it is
    /// shorter than `limit` (LEF's minStepLength), and a run is a maximal
    /// sequence of consecutive short edges along a ring, holes included. The
    /// two long edges on either side of a run make it an outside corner (a
    /// left turn from the first to the second, a convex corner), an inside
    /// corner (a right turn) or a step (both running the same way); an end of
    /// line, where they run opposite ways, is none of these. Per LEF 5.8:
    /// `MAXEDGES` flags more than `n` short edges in a row; `OUTSIDECORNER`
    /// and `INSIDECORNER` "two or more consecutive edges" of that corner;
    /// `STEP` "one or more consecutive edges of a step"; with `LENGTHSUM`, a
    /// corner or step run only when its total length exceeds the sum. A ring
    /// with no long edge is one run of a corner of no kind, which only
    /// `max_edges` holds. [`Rule::MinEdgeLength`] is `MINSTEP` alone, every
    /// short edge flagged.
    ///
    /// One violation per offending run, at the centre of the box of its
    /// vertices. `measured` is the run's edge count against `max_edges`, or
    /// against the most a corner (1) or step (0) may have; with `length_sum`,
    /// the run's total length against it. `shapes.0` is the lowest drawn row
    /// under the figure. `examined` counts the runs.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-020. Rules: LEF 5.8 `MINSTEP minStepLength [INSIDECORNER |
    /// OUTSIDECORNER | STEP] [LENGTHSUM maxLength] | [MAXEDGES maxEdges]` and
    /// its Example 1-16 and Figure 1-15.
    ///
    /// Limits: `LEF58_MINSTEP`'s qualifiers are [`Rule::MinStepAdjacent`].
    MinStep {
        /// The layer measured, drawn or derived.
        layer: LayerId,
        /// The shortest edge that is not short, in grid units; positive.
        limit: Dbu,
        /// Which runs are rejected.
        kind: StepKind,
        /// `LENGTHSUM`: a corner or step run's total length allowed; `None`
        /// for no allowance, and always `None` with [`StepKind::MaxEdges`].
        length_sum: Option<Dbu>,
    },
    /// A short edge beside another short edge, or two short edges either
    /// side of a short end of line, as `LEF58_MINSTEP`'s qualifiers reject
    /// them.
    ///
    /// Deck: `min_step(L; adjacent: len, except_rectangle: bool) >= len`,
    /// the same with `adjacent_eol: len` after `adjacent`, or
    /// `min_step(L; between_eol: len) >= len`, kind `min_step_adjacent`. The layer is merged first; every ring, holes
    /// included, is walked edge by edge, and an edge is short when it is
    /// shorter than `limit` (`minStepLength`). An end of line is an edge
    /// whose two corners are both convex. No public LEF text defines these
    /// qualifiers; this is `OpenROAD` `TritonRoute`'s reading
    /// (`checkMetalShape_lef58MinStep_minAdjLength` and `_noBetweenEol`,
    /// `FlexGC_main.cpp`):
    ///
    /// - [`StepNeighbour::Adjacent`] (`MINSTEP minStepLength
    ///   MINADJACENTLENGTH minAdjLength [EXCEPTRECTANGLE]`): a short edge
    ///   whose edge before or after is shorter than `length`, or, with `eol`
    ///   (`NOADJACENTEOL eolWidth`), is an end of line shorter than `eol`.
    ///   With `except_rectangle`, a figure whose outer ring has four corners
    ///   is not checked.
    /// - [`StepNeighbour::BetweenEol`] (`NOBETWEENEOL eolWidth`): a short
    ///   edge, then an end of line shorter than the width, then another short
    ///   edge, in ring order.
    ///
    /// One violation per offending short edge (the first of the three for
    /// `between_eol`), at the centre of the box of that edge and the edges
    /// that made it offend, `measured` the short edge's length against
    /// `limit`. `shapes.0` is the lowest drawn row under the figure.
    /// `examined` counts the short edges.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-020. Rules: `LEF58_MINSTEP` (`OpenROAD` `lefTechLayerMinStepParser`
    /// and `TritonRoute`).
    ///
    /// Limits: `MINADJACENTLENGTH`'s `CONVEXCORNER`, `CONCAVECORNER` and
    /// second length, `MINBETWEENLENGTH` and `EXCEPTSAMECORNERS`, and
    /// `NOADJACENTEOL` without `MINADJACENTLENGTH`, are parsed by `OpenROAD`
    /// but never checked by `TritonRoute`, and no public text defines them,
    /// so they are missing; `MAXEDGES` beside these qualifiers is not read
    /// either, as `TritonRoute` does not.
    MinStepAdjacent {
        /// The layer measured, drawn or derived.
        layer: LayerId,
        /// The shortest edge that is not short, in grid units; positive.
        limit: Dbu,
        /// What a short edge may not have beside it.
        neighbour: StepNeighbour,
    },
    /// Two shapes whose facing edges are closer than the cell the two edges'
    /// lengths select: tip to tip, tip to side and side to side, each by
    /// width class.
    ///
    /// Deck: `tip_space_table(L; length: [..], space: [[..], ..])`, kind
    /// `tip_spacing_table`. Edges are the merged layer's, each whole however
    /// it was drawn, so a line end drawn as two strips is one end. Two edges
    /// of different merged figures face each other when they are parallel,
    /// each faces out of its own material toward the other across empty
    /// space, and their spans overlap by a positive length; their gap is the
    /// distance between their lines. Edges that meet only diagonally do not
    /// face ([`Rule::CornerToCorner`] measures those). Each edge takes the
    /// class of the last `length` its own length reaches, so `[0nm, 24nm,
    /// 37nm]` classes edges below 24 nm, from 24 to 36 nm, and above 36 nm,
    /// and a facing pair needs `space[class of one][class of the other]`. The
    /// table is square and symmetric, and need not rise: a tip may need more
    /// space than a side.
    ///
    /// One violation per pair of merged figures with a facing pair closer
    /// than its cell: `measured` the smallest such gap, `limit` that pair's
    /// cell (the largest among equally near pairs), at the middle of the
    /// stretch the two edges face each other over. `shapes` is the lowest
    /// drawn row under each figure. `examined` counts facing pairs of edges
    /// in different figures closer than the table's largest cell.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-031. Rules: ASAP7 M1.S.1 to M1.S.5, side to side when both edges
    /// are over 36 nm, tip to side when one is at most 36 nm, tip to tip by
    /// the two tips' classes (ASAP7 DRM r1p7, Table 3.12.1 and Fig. 3.12.1).
    ///
    /// Limits: the facing edges' own lengths pick the cell, so a line end
    /// that steps is classed by the step's edge. ASAP7 M4.S.3 and M4.S.4,
    /// tip to tip between lines on adjacent tracks, measure ends that do not
    /// face each other and are not this table.
    TipSpacingTable {
        /// The layer measured, drawn or derived.
        layer: LayerId,
        /// Index into [`RuleSet::class_tables`].
        table: u32,
    },
    /// Two shapes whose facing edges run alongside each other at a gap in a
    /// forbidden range.
    ///
    /// Deck: `forbidden_space(L; min: len, max: len, prl: len)`, kind
    /// `forbidden_spacing`. Edges and facing are as for
    /// [`Rule::TipSpacingTable`]: whole edges of the merged layer, of
    /// different merged figures, parallel and facing each other across empty
    /// space over a positive run. A facing pair whose run (the length over
    /// which their spans overlap) is longer than `prl`, and whose gap lies
    /// from `min` to `max`, both included, is forbidden. A wider gap is
    /// legal, and so is a narrower one, which the minimum-spacing rule
    /// judges. This is `OpenROAD` `TritonRoute`'s reading of
    /// `LEF58_TWOWIRESFORBIDDENSPACING`: the range is closed
    /// (`isForbiddenSpacing`) and the run strictly longer (`isValidPrl`).
    ///
    /// One violation per pair of merged figures with a forbidden facing
    /// pair: `measured` the smallest such gap and `limit` `max` plus one grid
    /// unit (the narrowest legal gap above the range), at the middle of the
    /// stretch the two edges face each other over. `shapes` is the lowest
    /// drawn row under each figure. `examined` counts facing pairs of edges
    /// in different figures at most `max` apart that run longer than `prl`.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-033. Rules: `LEF58_TWOWIRESFORBIDDENSPACING` and the range of
    /// `LEF58_FORBIDDENSPACING`.
    ///
    /// Limits: no preferred direction, so both orientations are checked. The
    /// qualifiers on which wires the range binds are missing: the two-wire
    /// form's `MINSPANLENGTH` and `MAXSPANLENGTH`, and
    /// `LEF58_FORBIDDENSPACING`'s `WIDTH`, `WITHIN` and `TWOEDGES`.
    /// `TritonRoute` reports a `LEF58_FORBIDDENSPACING` pair only when a
    /// third shape lies in its gap; that reading is not modelled.
    ForbiddenSpacing {
        /// The layer measured, drawn or derived.
        layer: LayerId,
        /// The narrowest forbidden gap, in grid units; positive.
        min: Dbu,
        /// The widest forbidden gap, in grid units; at least `min`.
        max: Dbu,
        /// The run a facing pair must exceed to be judged, in grid units; 0
        /// or more.
        prl: Dbu,
    },
    /// Too little space in front of an end of line, as LEF `SPACING
    /// ENDOFLINE` defines it: a keep-out widened past the end's sides, which
    /// may apply only beside parallel edges, with its own space between two
    /// ends.
    ///
    /// Deck: `eol_space(L; eol_width: len, within: len, parallel: none |
    /// (space: len, within: len, two_edges: bool), end_to_end: len | none) >=
    /// len`, kind `eol_within_spacing`. An end of line is an edge of the
    /// merged layer strictly shorter than `eol_width` whose two corners are
    /// convex: a line's end, not the floor of a notch (`TritonRoute`'s
    /// `checkMetalEndOfLine_eol_isEolEdge`). Its keep-out spans the end
    /// widened by `within` on each side, both ends open, and reaches straight
    /// out of the material from the end's line, open at its far side (LEF
    /// 5.8: "spacing greater than or equal to eolSpace beyond the EOL
    /// anywhere within (that is, less than) eolWithin distance"). An edge of
    /// another merged figure, parallel to the end and facing it, at a depth
    /// of 0 or more out from the end's line, whose span overlaps the widened
    /// span by a positive length, violates when its depth is below the space
    /// it needs: `end_to_end` when that edge is itself an end of line and
    /// `end_to_end` is given (`LEF58_SPACING ENDOFLINE ... ENDTOEND`), else
    /// `limit`.
    ///
    /// With `parallel`, the rule applies to an end only where a parallel
    /// edge runs beside its line (LEF `PARALLELEDGE parSpace WITHIN
    /// parWithin`): at a corner of the end, an edge of the merged layer, of
    /// any figure (the line's own included), parallel to the line's side
    /// there and facing it, less than `space` out from that side's line,
    /// whose span overlaps by a positive length the stretch from the
    /// parallel `within` back behind the end's line to the end's own
    /// `within` past it. With `two_edges`, both corners need one
    /// (`TWOEDGES`).
    ///
    /// One violation per pair of merged figures with such an approach, from
    /// either figure's end: `measured` the smallest depth (straight out from
    /// the end, not Euclidean, as the keep-out is a box), `limit` the space
    /// it needed, at the middle of the stretch where the facing edge overlaps
    /// the widened span, midway between their lines. `shapes` is the lowest
    /// drawn row under each figure. `examined` counts the ends of line the
    /// rule applies to.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-029. Rules: LEF `SPACING eolSpace ENDOFLINE eolWidth WITHIN
    /// eolWithin [PARALLELEDGE parSpace WITHIN parWithin [TWOEDGES]]` (LEF/DEF
    /// 5.8 Language Reference, Figures 1-17 to 1-19 and Example 1-18);
    /// `LEF58_SPACING ENDOFLINE ... ENDTOEND`; `TritonRoute` `FlexGC_eol.cpp`.
    ///
    /// Limits: `ENCLOSECUT`, the `LEF58_SPACING ENDOFLINE` qualifiers
    /// `MINLENGTH`, `MAXLENGTH`, `ENDPRLSPACING` and `WRONGDIRSPACING`, and
    /// the `ENDTOEND` extensions are missing. An edge beside the line, behind
    /// the end's line, is not in the keep-out; the minimum spacing measures
    /// it, and LEF asks `eolWithin` to be under that spacing.
    EolWithinSpacing {
        /// The layer measured, drawn or derived.
        layer: LayerId,
        /// An edge strictly shorter than this, with convex corners, is an end
        /// of line, in grid units; positive.
        eol_width: Dbu,
        /// How far past each side of the end the keep-out reaches, exclusive,
        /// in grid units; 0 or more.
        within: Dbu,
        /// The parallel-edge condition; `None` applies the rule to every end.
        parallel: Option<EolParallel>,
        /// The space between two ends of line facing each other, in grid
        /// units; positive. `None` holds them to `limit`.
        end_to_end: Option<Dbu>,
        /// The space an end of line needs, in grid units; positive.
        limit: Dbu,
    },
    /// Material of another shape inside the keep-out box of an end of line.
    ///
    /// Deck: `eol_keep_out(L; eol_width: len, backward: len, side: len,
    /// forward: len)`, kind `eol_keep_out`. An end of line is as for
    /// [`Rule::EolWithinSpacing`]: an edge of the merged layer strictly
    /// shorter than `eol_width` with both corners convex. Its keep-out is the
    /// box spanning the end widened by `side` on each side, from `backward`
    /// behind the end's line (into its line) to `forward` past it. Material
    /// of another merged figure overlapping the box with a positive area is a
    /// violation; touching it is not (`LEF58_EOLKEEPOUT eolWidth EXTENSION
    /// backwardExt sideExt forwardExt`, as `OpenROAD` `TritonRoute` checks it:
    /// `getEolKeepOutQueryBox`, and `checkMetalEOLkeepout_helper`'s
    /// interior intersection with another pin's rectangles).
    ///
    /// One violation per end of line and intruding figure: `measured` the
    /// area of that figure inside the box against a `limit` of 0, at the
    /// centre of the bounding box of that area (floored). `shapes` is the
    /// lowest drawn row under the end's figure, then under the intruder's.
    /// `examined` counts ends of line.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-030. Rules: `LEF58_EOLKEEPOUT`.
    ///
    /// Limits: the `EXCEPTWITHIN`, `CORNERONLY` and `CLASS` qualifiers are
    /// missing, and so is `LEF58_EOLEXTENSIONSPACING`.
    EolKeepOut {
        /// The layer measured, drawn or derived.
        layer: LayerId,
        /// An edge strictly shorter than this, with convex corners, is an end
        /// of line, in grid units; positive.
        eol_width: Dbu,
        /// How far the box reaches behind the end's line, in grid units; 0 or
        /// more.
        backward: Dbu,
        /// How far the box reaches past each side of the end, in grid units;
        /// 0 or more.
        side: Dbu,
        /// How far the box reaches past the end's line, in grid units;
        /// positive.
        forward: Dbu,
    },
    /// Another cut inside the keep-out zone of a cut of one class.
    ///
    /// Deck: `keep_out_zone(L; class: short x long, to: short x long | none,
    /// end_side: len, end_forward: len, side_side: len, side_forward: len)`,
    /// kind `keep_out_zone`. A cut is a drawn row of `L` read as its bounding
    /// box, of a class when that box is the class's size either way round,
    /// as for [`Rule::CutClassSpacing`]. Round each cut of `class` lie two
    /// zones: the side zone, the cut lengthened by `side_forward` at each end
    /// of its long axis and widened by `side_side` on each side; and the end
    /// zone, the cut lengthened by `end_side` and widened by `end_forward`.
    /// Another cut, of class `to` when one is given, overlapping either zone
    /// with a positive area is a violation; touching a zone is not
    /// (`LEF58_KEEPOUTZONE CUTCLASS c1 [TO c2] ENDEXTENSION endSide
    /// endForward SIDEEXTENSION sideSide sideForward`, as `OpenROAD`'s
    /// detailed router builds the zones, `checKeepOutZone_main`, and its
    /// `odb::Rect::overlaps`, which is strict).
    ///
    /// One violation per cut of `class` and other cut in its zones:
    /// `measured` the area of the other cut inside the two zones against a
    /// `limit` of 0, at the centre of the bounding box of that area
    /// (floored). Two cuts of `class` in each other's zones are two
    /// violations, one each way, as the router checks every via. `shapes` is
    /// the cut, then the other. `examined` counts cuts of `class`. The layer
    /// is not validated, so this rule never records `Refused`.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-126. Rules: `LEF58_KEEPOUTZONE` (`OpenROAD` `odb`
    /// `KeepOutZoneParser`, `drt` `FlexGC_cut.cpp`).
    ///
    /// Limits: a square class has no long axis and the router skips it, so
    /// `class` must be oblong. `EXTENSION side forward` (the form without
    /// `ENDEXTENSION`), `SPIRALEXTENSION` and `EXCEPTEXACTALIGNED` have a
    /// grammar but no public semantics (the router reads none of them), and
    /// are not modelled.
    KeepOutZone {
        /// The cut layer, drawn or derived.
        layer: LayerId,
        /// The class whose cuts own zones, `(short, long)` in grid units;
        /// `short < long`.
        class: (Dbu, Dbu),
        /// The class of the cuts held out, `(short, long)`; `None` holds out
        /// every cut.
        to: Option<(Dbu, Dbu)>,
        /// The end zone: `(side, forward)`, grown along the cut's long axis
        /// by `side` and across it by `forward`, in grid units; 0 or more.
        end: (Dbu, Dbu),
        /// The side zone: `(side, forward)`, grown across the cut's long
        /// axis by `side` and along it by `forward`, in grid units; 0 or
        /// more.
        side: (Dbu, Dbu),
    },
    /// Two shapes closer than their cell of a two-width spacing table: the
    /// space depends on the widths of both shapes, and per width on the run
    /// between them.
    ///
    /// Deck: `two_width_table(L; width: [..], prl: [none | len, ..], space:
    /// [[..], ..])`, kind `two_width_spacing_table`. The same widths head the
    /// rows and the columns, each with its optional run (LEF: the table
    /// "implicitly has the same widths (and optional parallel run lengths)
    /// for the row and column headings"). Pairs are shapes in different
    /// merged figures, never a polygon and its own hole. A shape is wider
    /// than a width where a `width + 1` square fits in the merged layer, as
    /// [`Rule::SpacingTable`] reads width, and every shape is wider than the
    /// first width, 0. A width applies to a shape when the shape is wider
    /// than it and, where the width states a run, the two figures run
    /// alongside each other for more than that run (measured as for
    /// [`Rule::SpacingTable`], on the edges facing each other at most the cell
    /// apart). Each cell whose row applies to one shape and whose column to
    /// the other holds the pair to it, measured between the parts of the two
    /// shapes that wide (a whole shape for the first row or column). The
    /// cells never fall, so this is LEF's rule, the cell at the last row and
    /// the last column that apply, with each part held to its own width: a
    /// thin tab of a wide plate is held as thin.
    ///
    /// One violation per pair, at its highest failing cell (the largest space
    /// it fails, the nearest of those), with `limit` that cell and `measured`
    /// the distance there, at the midpoint of the points it measured.
    /// `examined` counts the pairs.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-027. Rules: LEF `SPACINGTABLE TWOWIDTHS {WIDTH width [PRL
    /// runLength] {spacing} ...}` (LEF/DEF 5.8 Language Reference, "Two-Width
    /// Spacing Tables", with its worked example).
    ///
    /// Limits: a negative run, which LEF lets reach diagonal pairs, cannot be
    /// written; a width with no run is `none`. The table must be symmetric,
    /// as which shape is the first is not a property of the pair.
    TwoWidthSpacingTable {
        /// The layer measured, drawn or derived.
        layer: LayerId,
        /// Index into [`RuleSet::class_tables`].
        table: u32,
    },
    /// A span of a shape whose length is not on the layer's list of legal
    /// spans.
    ///
    /// Deck: `span_length(L; x: [..], y: [..])`, kind `span_length`. A span
    /// is the length of a maximal run of material along a horizontal (x) or
    /// vertical (y) line through a figure of the merged layer: every chord
    /// such a line cuts from the figure, so an L has the spans of both its
    /// arms, and a ring the width of its band as well as its outer size. A
    /// horizontal span must be one of `x` exactly, or at least the last of
    /// them; a vertical one the same with `y` (`LEF58_SPANLENGTHTABLE`: "All of
    /// the given span lengths are exact values, except for the last one,
    /// which is greater than equal to the value. All of the possible span
    /// lengths of an object in both directions should be checked"). For a LEF
    /// layer whose `DIRECTION` is horizontal, `y` is its `SPANLENGTHTABLE` and
    /// `x` its `SPANLENGTHTABLE ... WRONGDIRECTION` (the same list when it has
    /// none), and the other way round for a vertical layer.
    ///
    /// One violation per maximal region of a figure over which one illegal
    /// span runs unchanged (a rectangle: the chord, swept across the lines it
    /// is the chord of), at its centre (floored). `measured` is the span and
    /// `limit` the shortest legal span longer than it. `shapes.0` is the
    /// lowest drawn row under the figure. `examined` counts the regions of
    /// unchanged span, both axes.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-036. Rules: `LEF58_SPANLENGTHTABLE {spanLength} ... [WRONGDIRECTION]`
    /// (LEF/DEF 5.8 Language Reference, "Span Length Table Rule" and Figure
    /// 1-31).
    ///
    /// Limits: `ORTHOGONAL` (a length between two inside facing corners) and
    /// `EXCEPTOTHERSPAN` are missing.
    SpanLength {
        /// The layer measured, drawn or derived.
        layer: LayerId,
        /// Index into [`RuleSet::span_tables`].
        table: u32,
    },
    /// Two shapes whose facing convex corners are closer than `limit`, as
    /// `LEF58_CORNERSPACING CONVEXCORNER` measures them.
    ///
    /// Deck: `corner_space(L; corner_to_corner: bool, except_eol: len | none) >= len`,
    /// kind `convex_corner_spacing`. Corners are as for
    /// [`Rule::CornerToCorner`]: convex corners of the merged layer, of
    /// different merged figures, facing each other (each beyond the other on
    /// both axes, out along opposite diagonals). Their distance is the larger
    /// of their two axis gaps (`TritonRoute`'s `maxXY`, the longer side of
    /// the box between a corner and the other shape), or with
    /// `corner_to_corner: true` the Euclidean one (`CORNERTOCORNER`). With
    /// `except_eol`, a corner of an end of line (an edge at the corner
    /// strictly shorter than `except_eol` whose two corners are convex) on
    /// either shape is exempt (`EXCEPTEOL eolWidth`).
    ///
    /// One violation per pair of merged figures with facing corners closer
    /// than `limit`: `measured` the smallest such distance (floored when
    /// Euclidean), at the midpoint of those two corners; among equally near
    /// pairs, the Euclidean nearest, and among those the middle of the box
    /// bounding their midpoints. `shapes` is the lowest drawn row under each
    /// figure. `examined` counts the facing pairs of corners judged.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-032. Rules: `LEF58_CORNERSPACING CONVEXCORNER [CORNERTOCORNER]
    /// [EXCEPTEOL eolWidth] WIDTH 0 SPACING spacing`; `TritonRoute`
    /// `checkMetalCornerSpacing_main`.
    ///
    /// Limits: one spacing for every width (the `WIDTH` table by the
    /// corner's shape width, and separate horizontal and vertical spacings,
    /// are missing); `CONCAVECORNER`, `SAMEMASK`, `CORNERONLY`,
    /// `EXCEPTJOGLENGTH`, `EXCEPTSAMENET` and `EXCEPTSAMEMETAL` are missing.
    ConvexCornerSpacing {
        /// The layer measured, drawn or derived.
        layer: LayerId,
        /// Whether the distance is Euclidean (`CORNERTOCORNER`) rather than
        /// the larger axis gap.
        corner_to_corner: bool,
        /// Ends of line strictly shorter than this exempt their corners, in
        /// grid units; positive. `None` exempts none.
        except_eol: Option<Dbu>,
        /// The smallest legal corner distance, in grid units; positive.
        limit: Dbu,
    },
    /// Two neighbouring rectangles whose centres are not exactly `pitch`
    /// apart along one axis.
    ///
    /// Deck: `pitch(L, vertical) == len` or `pitch(L, horizontal) == len`,
    /// kind `exact_pitch`. Every figure of the merged layer must be a
    /// rectangle, as fins and gates are (ASAP7 FIN.AUX.1 and GATE.AUX.1, "may
    /// not bend"); a layer with any other figure is refused. Along the axis
    /// (y for `vertical`), the neighbours of a rectangle are the rectangles
    /// that overlap it on the other axis by a positive length and lie past
    /// it, nearest first: those whose low side is the lowest among them. A
    /// rectangle and each neighbour must have their centre lines exactly
    /// `pitch` apart. A missing line between two others is a pitch of twice
    /// the value, and a violation.
    ///
    /// One violation per rectangle and neighbour off the pitch, in the middle
    /// of the gap between them over their overlap. `measured` is the
    /// distance between their centre lines, floored when it is a half unit;
    /// `limit` is `pitch`. `shapes` is the lowest drawn row under each.
    /// `examined` counts the neighbouring pairs.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-035. Rules: ASAP7 FIN.S.1 ("Exact vertical FIN pitch", 27 nm) and
    /// GATE.S.1 ("Exact horizontal GATE pitch", 54 nm), DRM r1p7 Tables 3.3.1
    /// and 3.4.1.
    ///
    /// Limits: the pitch is between neighbours, not to a track grid: LEF
    /// `PITCH` tracks, `LEF58_PITCH FIRSTLASTPITCH` and
    /// `LEF58_RIGHTWAYONGRIDONLY` (wires on the routing grid) are missing.
    ExactPitch {
        /// The layer measured, drawn or derived.
        layer: LayerId,
        /// Whether the pitch is along y (between lines stacked vertically)
        /// rather than along x.
        vertical: bool,
        /// The exact centre-to-centre distance, in grid units; positive.
        pitch: Dbu,
    },
}

/// The measurement a [`Rule::DfmScore`] scores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DfmCheck {
    /// Space between shapes of one layer, as [`Rule::MinSpacing`].
    Space,
    /// A shape's width, as [`Rule::MinWidth`].
    Width,
    /// Enclosure of the inner layer by the outer, as [`Rule::MinEnclosure`].
    Enclosure,
}

/// A pattern of [`Rule::PatternMatch`]: a window from the origin, the
/// shapes inside it, and don't-care boxes, in grid units.
///
/// Every pattern in a [`RuleSet`] passed [`Pattern::is_valid`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    /// The window's width and height; positive.
    pub window: (Dbu, Dbu),
    /// The shapes, each a rectangle inside the window with positive sides.
    pub shapes: Vec<Bbox>,
    /// Don't-care boxes inside the window: whatever the layout holds there
    /// matches.
    pub ignore: Vec<Bbox>,
}

impl Pattern {
    /// Whether the window is positive, every shape and don't-care box a
    /// rectangle with positive sides inside it, and the shapes have a corner
    /// to anchor on: strictly inside the window and off every don't-care box.
    /// [`RuleSet::from_deck`] refuses a pattern that is not
    /// ([`DrcError::BadTable`]).
    pub fn is_valid(&self) -> bool {
        let (w, h) = (self.window.0.raw(), self.window.1.raw());
        let inside = |b: &Bbox| {
            b.xlo < b.xhi
                && b.ylo < b.yhi
                && b.xlo.raw() >= 0
                && b.ylo.raw() >= 0
                && b.xhi.raw() <= w
                && b.yhi.raw() <= h
        };
        w > 0
            && h > 0
            && !self.shapes.is_empty()
            && self.shapes.iter().all(inside)
            && self.ignore.iter().all(inside)
            && self.anchor().is_some()
    }

    /// The corner a match puts on a corner of the layout: the least `(x,
    /// y)` corner of the merged shapes strictly inside the window and off
    /// every don't-care box (their edges included), in grid units; `None`
    /// when there is none.
    pub fn anchor(&self) -> Option<(i64, i64)> {
        crate::drc::rules::pattern::anchor_of(self)
    }
}

/// The bands of [`Rule::CutAreaChange`]: per band, the cut count from which
/// it applies and the area change it allows.
///
/// Every table in a [`RuleSet`] passed [`CutAreaBands::is_valid`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CutAreaBands {
    /// The cut count each band starts at: at least 1, rising strictly.
    pub cuts: Vec<u32>,
    /// The largest change each band allows, in square grid units; 0 or more.
    pub change: Vec<DbuArea>,
}

impl CutAreaBands {
    /// Whether there is a band, one change per band, every start at least 1
    /// and rising strictly, and no change negative. [`RuleSet::from_deck`]
    /// refuses a table that is not ([`DrcError::BadTable`]).
    pub fn is_valid(&self) -> bool {
        self.cuts.first().is_some_and(|&first| first >= 1)
            && self.cuts.len() == self.change.len()
            && self.cuts.windows(2).all(|pair| pair[0] < pair[1])
            && self.change.iter().all(|change| change.raw() >= 0)
    }

    /// The change a connector of `cuts` cuts may have, or `None` below every
    /// band.
    pub fn limit(&self, cuts: u32) -> Option<DbuArea> {
        self.cuts
            .iter()
            .rposition(|&start| cuts >= start)
            .map(|band| self.change[band])
    }
}

/// The defect sizes of [`Rule::MeanCriticalArea`]: each radius (a square
/// defect's half-side) with its weight.
///
/// Every table in a [`RuleSet`] passed [`DefectSizes::is_valid`].
#[derive(Debug, Clone, PartialEq)]
pub struct DefectSizes {
    /// The radii, in grid units: positive and rising strictly.
    pub radius: Vec<Dbu>,
    /// One weight per radius, from 0 to 1.
    pub weight: Vec<f64>,
}

impl DefectSizes {
    /// Whether there is a size, one weight each, every radius positive and
    /// rising strictly, every weight from 0 to 1.
    pub fn is_valid(&self) -> bool {
        self.radius.first().is_some_and(|r| r.raw() > 0)
            && self.radius.len() == self.weight.len()
            && self.radius.windows(2).all(|pair| pair[0] < pair[1])
            && self.weight.iter().all(|w| (0.0..=1.0).contains(w))
    }
}

/// The bands of [`Rule::CoverDensity`]: per band, the coverage of the
/// covering layer from which it applies and the density it asks of the
/// held layer.
///
/// Every table in a [`RuleSet`] passed [`CoverBands::is_valid`]; one built
/// by hand must too.
#[derive(Debug, Clone, PartialEq)]
pub struct CoverBands {
    /// The coverage each band starts at, from 0 to 1, rising strictly.
    pub cover: Vec<f64>,
    /// The density each band asks, from 0 to 1 (0 asks nothing), one per
    /// band.
    pub density: Vec<f64>,
    /// `true`: a coverage exactly at a band's start is in that band; `false`:
    /// it is in the band below.
    pub inclusive: bool,
}

impl CoverBands {
    /// Whether there is a band, one density per band, every value a fraction
    /// in `0..=1`, and the starts rising strictly. [`RuleSet::from_deck`]
    /// refuses a table that is not ([`DrcError::BadTable`]).
    pub fn is_valid(&self) -> bool {
        let fraction = |v: &f64| (0.0..=1.0).contains(v);
        !self.cover.is_empty()
            && self.cover.len() == self.density.len()
            && self.cover.iter().all(fraction)
            && self.density.iter().all(fraction)
            && self.cover.windows(2).all(|pair| pair[0] < pair[1])
    }

    /// The density a window covered to `coverage` asks for, or `None` below
    /// every band.
    pub fn need(&self, coverage: f64) -> Option<f64> {
        let reaches = |start: &f64| {
            if self.inclusive {
                coverage >= *start
            } else {
                coverage > *start
            }
        };
        self.cover
            .iter()
            .rposition(reaches)
            .map(|band| self.density[band])
    }
}

/// The legal spans of [`Rule::SpanLength`], per axis: every listed length but
/// the last is legal exactly, and the last and anything longer are legal.
///
/// Every table in a [`RuleSet`] passed [`SpanTable::is_valid`]; one built by
/// hand must too, or [`RuleSet::run`] may judge every span illegal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpanTable {
    /// The legal lengths of horizontal spans, in grid units: positive and
    /// rising strictly.
    pub x: Vec<Dbu>,
    /// The legal lengths of vertical spans, in grid units: positive and
    /// rising strictly.
    pub y: Vec<Dbu>,
}

impl SpanTable {
    /// Whether both lists are non-empty, positive and strictly rising.
    /// [`RuleSet::from_deck`] refuses a table that is not
    /// ([`DrcError::BadTable`]).
    pub fn is_valid(&self) -> bool {
        [&self.x, &self.y].into_iter().all(|legal| {
            legal.first().is_some_and(|first| first.raw() > 0)
                && legal.windows(2).all(|pair| pair[0] < pair[1])
        })
    }

    /// The shortest legal span on `legal` longer than `span`, or `None` when
    /// `span` itself is legal.
    pub(crate) fn next_legal(legal: &[Dbu], span: i64) -> Option<i64> {
        let last = legal.last()?.raw();
        if span >= last || legal.iter().any(|length| length.raw() == span) {
            return None;
        }
        legal
            .iter()
            .map(|length| length.raw())
            .find(|&length| length > span)
    }
}

/// The parallel-edge condition of an end-of-line rule (LEF `PARALLELEDGE
/// parSpace WITHIN parWithin [TWOEDGES]`), read by
/// [`Rule::EolWithinSpacing`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EolParallel {
    /// How far out from the line's side a parallel edge may lie, exclusive,
    /// in grid units; positive.
    pub space: Dbu,
    /// How far back from the end's line the parallel edge's stretch reaches,
    /// exclusive, in grid units; 0 or more.
    pub within: Dbu,
    /// Whether both sides of the line need a parallel edge.
    pub two_edges: bool,
}

/// Which runs of short edges a [`Rule::MinStep`] rejects, after LEF
/// `MINSTEP`'s keywords.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepKind {
    /// `MAXEDGES n`: more than `n` short edges in a row, whatever the corner.
    MaxEdges(u16),
    /// `OUTSIDECORNER`: two or more at a convex corner, LEF's default.
    OutsideCorner,
    /// `INSIDECORNER`: two or more at a concave corner.
    InsideCorner,
    /// `STEP`: one or more between two long edges running the same way.
    Step,
}

/// What a short edge may not have beside it, after `LEF58_MINSTEP`'s
/// qualifiers, read by [`Rule::MinStepAdjacent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepNeighbour {
    /// `MINADJACENTLENGTH length [EXCEPTRECTANGLE]`, with `NOADJACENTEOL eol`
    /// when `eol` is given: an edge before or after shorter than `length`,
    /// or an end of line shorter than `eol`.
    Adjacent {
        /// An edge before or after shorter than this offends, in grid units;
        /// positive.
        length: Dbu,
        /// An end of line before or after shorter than this offends too, in
        /// grid units; positive.
        eol: Option<Dbu>,
        /// Whether a figure whose outer ring is a rectangle is exempt.
        except_rectangle: bool,
    },
    /// `NOBETWEENEOL eolWidth`: an end of line shorter than this between two
    /// short edges, in grid units; positive.
    BetweenEol(Dbu),
}

/// The wire widths at which an enclosure rule holds an inner polygon (LEF
/// `ENCLOSURE ... WIDTH minWidth`: "the enclosure rule only applies when the
/// width of the routing layer is greater than or equal to minWidth").
///
/// An inner polygon lies on a wire at least `w` wide when the part of the
/// merged outer layer where an axis-aligned `w` square fits (sky130's
/// `sized(-w/2).sized(w/2)`, `KLayout`'s opening) covers all of it, as
/// [`Rule::WideDependentSpacing`] reads a wide part. The band holds the inner
/// polygons that lie on a wire at least `from` wide and not on one `below`
/// wide. LEF applies "the largest minWidth rule that is still less than or
/// equal to the wire width", so a deck writes one row per band, each `below`
/// the next one's `from`, and every inner polygon falls in exactly one; one
/// no host covers falls in the lowest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireBand {
    /// The narrowest wire held, in grid units; 0 holds every width.
    pub from: Dbu,
    /// The wire width, in grid units and above `from`, at and above which an
    /// inner polygon is no longer held; `None` for no upper bound.
    pub below: Option<Dbu>,
}

impl WireBand {
    /// Every wire width: the rule holds every inner polygon.
    pub const ANY: Self = Self {
        from: Dbu::new_unchecked(0),
        below: None,
    };
}

/// A spacing table, LEF `SPACINGTABLE PARALLELRUNLENGTH`: the required space
/// for a pair is `space[row][column]`, with `row` the last width exceeded by
/// the wider shape and `column` the last run length exceeded by the pair; the
/// first row and column always apply. Cells never fall along a row or column.
/// [`Rule::SpacingTable`] says how a pair's width and run are measured.
///
/// Every table in a [`RuleSet`] passed [`SpacingTable::is_valid`]; one built by
/// hand must too, or [`RuleSet::run`] may panic indexing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpacingTable {
    /// Run lengths heading the columns, in grid units: starts at 0 and
    /// strictly rises.
    pub prl: Vec<Dbu>,
    /// Widths heading the rows, in grid units: starts at 0 and strictly rises.
    pub width: Vec<Dbu>,
    /// Row-major, `width.len()` rows of `prl.len()` cells, each a positive
    /// space in grid units.
    pub space: Vec<Dbu>,
}

impl SpacingTable {
    /// Whether the table is complete and monotone, as the struct states.
    /// [`Rule::validate`] refuses a table that is not
    /// ([`DrcError::BadTable`]).
    pub fn is_valid(&self) -> bool {
        let starts_and_rises = |steps: &[Dbu]| {
            steps.first().is_some_and(|first| first.raw() == 0)
                && steps.windows(2).all(|pair| pair[0] < pair[1])
        };
        let columns = self.prl.len();
        starts_and_rises(&self.prl)
            && starts_and_rises(&self.width)
            && self.space.len() == columns * self.width.len()
            && self.space.iter().all(|cell| cell.raw() > 0)
            && self
                .space
                .chunks(columns)
                .all(|row| row.windows(2).all(|p| p[0] <= p[1]))
            && self.space.windows(columns + 1).all(|w| w[0] <= w[columns])
    }

    /// The cell at `row`, `column`.
    pub(crate) fn at(&self, row: usize, column: usize) -> Dbu {
        self.space[row * self.prl.len() + column]
    }

    /// The side of the square that makes a part of a shape wide enough for
    /// `row`: one unit past the row's width, since a row holds what is
    /// strictly wider. The check finds those parts with this square, and
    /// [`Rule::required_spacing`] compares a width with it ([`is_wide`]).
    pub(crate) fn row_square(&self, row: usize) -> Dbu {
        self.width[row] + Dbu::new_unchecked(1)
    }

    /// The column a pair takes in `row`: the last whose run length the
    /// pair's run strictly exceeds, the run read by `run_at` off the edges at
    /// most that column's cell apart; column 0 when it exceeds none. The
    /// check reads the run off the layout, [`Rule::required_spacing`] takes
    /// the asked one.
    pub(crate) fn column(&self, row: usize, run_at: impl Fn(Dbu) -> i64) -> usize {
        (1..self.prl.len())
            .rev()
            .find(|&column| self.prl[column].raw() < run_at(self.at(row, column)))
            .unwrap_or(0)
    }
}

/// Whether a shape `width` wide holds an axis-aligned `side` square: the
/// part a wide-spacing rule measures from ([`Rule::WideDependentSpacing`],
/// and a [`Rule::SpacingTable`] row through
/// [`row_square`](SpacingTable::row_square)). The checks find that part with
/// the square; this is the same condition on a width.
pub(crate) fn is_wide(width: Dbu, side: Dbu) -> bool {
    width >= side
}

/// Whether two shapes whose facing edges run `run` grid units alongside each
/// other are held to a [`Rule::PrlSpacing`] whose run is `threshold`.
pub(crate) fn prl_holds(run: i64, threshold: Dbu) -> bool {
    run >= threshold.raw()
}

/// Whether an edge `length` grid units long is an end of line to a
/// [`Rule::EolSpacing`] of `eol_width`: strictly shorter.
pub(crate) fn is_end_of_line(length: i64, eol_width: Dbu) -> bool {
    length < eol_width.raw()
}

/// Two shapes on one layer, as the spacing rules tell them apart: what
/// decides which of a layer's spacing limits the pair is held to
/// ([`Rule::required_spacing`]).
///
/// A shape's width is the side of the largest axis-aligned square that fits
/// in it (the narrower side of a rectangle), as the wide-spacing rules
/// measure it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SpacingQuery {
    /// The width of one shape, in grid units.
    pub width_a: Dbu,
    /// The width of the other.
    pub width_b: Dbu,
    /// How far, in grid units, the shapes' facing edges project onto each
    /// other.
    pub run_length: Dbu,
    /// The length of the edge facing the other shape, when it may be a line
    /// end: an edge shorter than a rule's `eol_width` is that rule's end of
    /// line. `None` when the shapes face along sides no end-of-line rule
    /// reads.
    pub end_of_line: Option<Dbu>,
}

/// A cut-class spacing table, `LEF58_SPACINGTABLE` on a cut layer with
/// `CUTCLASS` SIDE/END entries: class `i` is the cut size `short[i]` x
/// `long[i]`, and `space` is square, two rows and columns per class (its END,
/// then its SIDE), the space two cuts facing that way need.
/// [`Rule::CutClassSpacing`] says how a pair's classes and facings are read.
///
/// Every table in a [`RuleSet`] passed [`CutClassTable::is_valid`]; one built
/// by hand must too, or [`RuleSet::run`] may panic indexing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CutClassTable {
    /// Each class's shorter side, in grid units; positive.
    pub short: Vec<Dbu>,
    /// Each class's longer side, in grid units; at least its `short`.
    pub long: Vec<Dbu>,
    /// Row-major, `2n` rows of `2n` positive cells for `n` classes; the
    /// space for row `r`, column `c` is the space for column `r`, row `c`.
    pub space: Vec<Dbu>,
}

impl CutClassTable {
    /// Whether the table is complete and symmetric, with distinct classes, as
    /// the struct states. [`RuleSet::from_deck`] refuses one that is not
    /// ([`DrcError::BadTable`]).
    pub fn is_valid(&self) -> bool {
        let n = self.short.len();
        let classes: Vec<(Dbu, Dbu)> = self
            .short
            .iter()
            .copied()
            .zip(self.long.iter().copied())
            .collect();
        n > 0
            && self.long.len() == n
            && classes.iter().all(|&(s, l)| s.raw() > 0 && s <= l)
            && (0..n).all(|i| !classes[..i].contains(&classes[i]))
            && self.space.len() == 4 * n * n
            && self.space.iter().all(|cell| cell.raw() > 0)
            && (0..2 * n).all(|r| (0..2 * n).all(|c| self.at(r, c) == self.at(c, r)))
    }

    /// The cell at `row`, `column`.
    pub(crate) fn at(&self, row: usize, column: usize) -> Dbu {
        self.space[row * 2 * self.short.len() + column]
    }

    /// The class a `w` x `h` cut belongs to, either way round.
    pub(crate) fn class_of(&self, w: Dbu, h: Dbu) -> Option<usize> {
        let (short, long) = (w.min(h), w.max(h));
        (0..self.short.len()).find(|&i| self.short[i] == short && self.long[i] == long)
    }
}

/// A square table indexed by a class of each of two edges or shapes, for
/// [`Rule::TipSpacingTable`] (classes by edge length) and
/// [`Rule::TwoWidthSpacingTable`] (classes by width, each with an optional
/// run): a pair needs `space[i][j]`, with `i` the class of one and `j` that
/// of the other. Classes start at 0, so every edge or shape has one.
///
/// Every table in a [`RuleSet`] passed its kind's check
/// ([`ClassTable::is_valid_tips`], [`ClassTable::is_valid_two_widths`]); one
/// built by hand must too, or [`RuleSet::run`] may panic indexing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassTable {
    /// The class thresholds, in grid units: starts at 0 and rises.
    pub class: Vec<Dbu>,
    /// Per class, a run a pair must exceed for the class to apply; `None`
    /// checks no run. Empty for a table that reads no runs.
    pub prl: Vec<Option<Dbu>>,
    /// Row-major, `class.len()` rows of `class.len()` cells, each a positive
    /// space in grid units; symmetric.
    pub space: Vec<Dbu>,
}

impl ClassTable {
    /// Whether the table is square, symmetric and positive, with classes
    /// from 0 rising strictly and no runs: what [`Rule::TipSpacingTable`]
    /// reads. [`RuleSet::from_deck`] refuses one that is not
    /// ([`DrcError::BadTable`]).
    pub fn is_valid_tips(&self) -> bool {
        self.prl.is_empty()
            && self.is_square()
            && self.class.windows(2).all(|pair| pair[0] < pair[1])
    }

    /// Whether the table is square, symmetric and positive, its cells never
    /// fall along a row (nor, by symmetry, a column), its widths start at 0
    /// and never fall, and its runs start with none (the first width states
    /// no run) and never fall among those stated, each 0 or more: what
    /// [`Rule::TwoWidthSpacingTable`] reads (LEF: "The width and runLength
    /// values must be the same or increasing", the spacings "the same or
    /// increasing from left to right, and from top to bottom").
    /// [`RuleSet::from_deck`] refuses one that is not
    /// ([`DrcError::BadTable`]).
    pub fn is_valid_two_widths(&self) -> bool {
        let n = self.class.len();
        let runs: Vec<Dbu> = self.prl.iter().flatten().copied().collect();
        self.prl.len() == n
            && self.prl.first().is_some_and(Option::is_none)
            && runs.iter().all(|run| run.raw() >= 0)
            && runs.windows(2).all(|pair| pair[0] <= pair[1])
            && self.is_square()
            && self.class.windows(2).all(|pair| pair[0] <= pair[1])
            && (0..n).all(|i| (1..n).all(|j| self.at(i, j - 1) <= self.at(i, j)))
    }

    /// Classes from 0, one row and column per class, every cell positive and
    /// mirrored across the diagonal.
    fn is_square(&self) -> bool {
        let n = self.class.len();
        self.class.first().is_some_and(|first| first.raw() == 0)
            && self.space.len() == n * n
            && self.space.iter().all(|cell| cell.raw() > 0)
            && (0..n).all(|i| (0..i).all(|j| self.at(i, j) == self.at(j, i)))
    }

    /// The cell for classes `i` and `j`.
    pub(crate) fn at(&self, i: usize, j: usize) -> Dbu {
        self.space[i * self.class.len() + j]
    }
}

/// Every DRC rule the deck configures, in deck order.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct RuleSet {
    /// Each rule with its deck id, in deck order: the order of the
    /// [`RuleRun`] rows [`RuleSet::run`] produces. Ids are unique.
    pub rules: Vec<(StrId, Rule)>,
    /// The tables [`Rule::SpacingTable`] names.
    pub tables: Vec<SpacingTable>,
    /// The cut classes each [`Rule::CutClass`] names: `(short, long)` sides
    /// in grid units, each positive, sorted, without repeats, never empty.
    pub classes: Vec<Vec<(Dbu, Dbu)>>,
    /// The width lists each [`Rule::AllowedWidth`] names: grid units, each
    /// positive, sorted, without repeats, never empty.
    pub widths: Vec<Vec<Dbu>>,
    /// The tables [`Rule::TipSpacingTable`] names.
    /// The tables [`Rule::TipSpacingTable`] and
    /// [`Rule::TwoWidthSpacingTable`] name.
    pub class_tables: Vec<ClassTable>,
    /// The tables [`Rule::SpanLength`] names.
    pub span_tables: Vec<SpanTable>,
    /// The bands each [`Rule::CoverDensity`] names.
    pub cover_bands: Vec<CoverBands>,
    /// The bands each [`Rule::CutAreaChange`] names.
    pub cut_area_bands: Vec<CutAreaBands>,
    /// The patterns each [`Rule::PatternMatch`] names.
    pub patterns: Vec<Pattern>,
    /// Per derived layer a [`Rule::NetSpacing`] reads, the drawn layers it is
    /// computed from: a shape of it on no net of its own takes the one net of
    /// the shapes of these it overlaps.
    pub net_sources: Vec<(LayerId, Vec<LayerId>)>,
    /// The defect sizes each [`Rule::MeanCriticalArea`] names.
    pub defect_sizes: Vec<DefectSizes>,
    /// The tables [`Rule::CutClassSpacing`] names.
    pub cut_tables: Vec<CutClassTable>,
    /// The cut layers, bottom to top, of each [`Rule::ViaStack`].
    pub stacks: Vec<Vec<LayerId>>,
    /// The ids of the rules the deck writes `warning` (`rule <id> warning
    /// <check>`): each finding of these is a [`Severity::Warning`], reported
    /// and counted but not failing the run. This is how a recommended rule is
    /// carried: IHP's rules with an `R` suffix (Layout Rules §4.1), sky130's
    /// `RR`/`RC` flags, ASAP7's rule type `R`, LEF `PREFERENCLOSURE`. The
    /// row's outcome is unchanged, so a recommended rule that cannot look
    /// still fails the run. Catalog DRC-110.
    pub warnings: Vec<StrId>,
    /// The deck's first derived layer: it and every higher id are computed,
    /// and the layers below it are drawn. `None` when every layer is drawn,
    /// as in a rule set built in code. A [`Rule::Density`] or
    /// [`Rule::GlobalDensity`] without a boundary takes its die from the drawn
    /// layers, and [`Rule::OffGrid`] and an [`Rule::Angle`] without a layer
    /// check drawn rows only.
    pub first_derived: Option<LayerId>,
}

impl RuleSet {
    /// Builds one [`Rule`] per deck row whose kind is in [`KINDS`], and holds
    /// each to [`Rule::validate`]. Other kinds belong to ERC and are stepped
    /// over; [`CompiledDeck::from_deck`](crate::deck::CompiledDeck::from_deck)
    /// refuses a kind neither domain spells.
    ///
    /// Area limits arrive as areas (`ParamValue::Area`).
    ///
    /// # Errors
    ///
    /// The first problem, in deck order, and within a row in this order:
    /// - [`DrcError::DuplicateRule`] when two rows of any domain share an id;
    /// - [`DrcError::WrongLayerCount`] when a row names too few or too many
    ///   layers;
    /// - [`DrcError::MissingParam`] or [`DrcError::WrongParamType`] when a
    ///   parameter is absent, of the wrong kind, or a count too large for its
    ///   field;
    /// - [`DrcError::UnrepresentableAngle`] when an allowed angle is not a
    ///   multiple of 45 degrees;
    /// - what [`Rule::validate`] refuses: a limit that is not positive, or a
    ///   spacing table that is not complete and monotone;
    /// - [`DrcError::BadTable`] when a class or span table fails its kind's
    ///   check, a forbidden range has `min` above `max`, or a cut-class
    ///   table is not complete and symmetric.
    pub fn from_deck(deck: &Deck, strings: &StrTable) -> Result<Self, DrcError> {
        let rules = &deck.rules;
        let name_of = |id: StrId| strings.resolve(id).to_owned();

        let mut ids: Vec<StrId> = rules.spec.iter().map(|spec| spec.id).collect();
        ids.sort_unstable();
        if let Some(pair) = ids.windows(2).find(|pair| pair[0] == pair[1]) {
            return Err(DrcError::DuplicateRule(name_of(pair[0])));
        }

        let wrong_type = |spec: &RuleSpec, param| DrcError::WrongParamType {
            rule: name_of(spec.id),
            param,
        };
        let value = |spec: &RuleSpec, param: &'static str| {
            strings
                .get(param)
                .and_then(|interned| rules.param(spec, interned))
                .ok_or_else(|| DrcError::MissingParam {
                    rule: name_of(spec.id),
                    param,
                })
        };
        // Each reads a value of its type only: what values a rule can hold is
        // `Rule::validate`'s, which a rule built in code meets too.
        let length = |spec: &RuleSpec, param| -> Result<Dbu, DrcError> {
            match value(spec, param)? {
                ParamValue::Length(limit) => Ok(limit),
                _ => Err(wrong_type(spec, param)),
            }
        };
        // Every length a row states under `param`, in order: a list's elements.
        let lengths = |spec: &RuleSpec, param: &'static str| -> Result<Vec<Dbu>, DrcError> {
            let wanted = strings.get(param);
            rules
                .params_of(spec)
                .iter()
                .filter(|&&(name, _)| Some(name) == wanted)
                .map(|&(_, stated)| match stated {
                    ParamValue::Length(length) => Ok(length),
                    _ => Err(wrong_type(spec, param)),
                })
                .collect()
        };
        let area_limit = |spec: &RuleSpec, param| -> Result<DbuArea, DrcError> {
            match value(spec, param)? {
                ParamValue::Area(area) => Ok(area),
                _ => Err(wrong_type(spec, param)),
            }
        };
        let ratio = |spec: &RuleSpec, param| -> Result<f64, DrcError> {
            match value(spec, param)? {
                ParamValue::Ratio(limit) => Ok(limit),
                _ => Err(wrong_type(spec, param)),
            }
        };
        let count = |spec: &RuleSpec, param, ceiling: u32| -> Result<u32, DrcError> {
            match value(spec, param)? {
                ParamValue::Count(found) if found <= ceiling => Ok(found),
                _ => Err(wrong_type(spec, param)),
            }
        };
        let layers = |spec: &RuleSpec, expected: u32| {
            if spec.layer_len == expected {
                Ok(())
            } else {
                Err(DrcError::WrongLayerCount {
                    rule: name_of(spec.id),
                    expected,
                    found: spec.layer_len,
                })
            }
        };
        let layer = |spec: &RuleSpec, nth: usize| rules.layers_of(spec)[nth];
        // Layer count first, then each parameter in field order.
        let one = |spec: &RuleSpec| layers(spec, 1).map(|()| layer(spec, 0));
        let two = |spec: &RuleSpec| layers(spec, 2).map(|()| (layer(spec, 0), layer(spec, 1)));
        // A density layer, then an optional die boundary layer.
        let bounded = |spec: &RuleSpec| match spec.layer_len {
            1 => Ok((layer(spec, 0), None)),
            _ => two(spec).map(|(layer, boundary)| (layer, Some(boundary))),
        };
        // An enclosure's optional wire band, `width:` and `below:`.
        let wire = |spec: &RuleSpec| -> Result<WireBand, DrcError> {
            let bound =
                |param: &'static str| match strings.get(param).and_then(|p| rules.param(spec, p)) {
                    Some(_) => length(spec, param).map(Some),
                    None => Ok(None),
                };
            let from = bound("wire_width")?.unwrap_or(Dbu::new_unchecked(0));
            let below = bound("wire_below")?;
            if let Some(below) = below.filter(|&below| below <= from) {
                return Err(DrcError::NonPositiveLimit {
                    rule: name_of(spec.id),
                    limit: (below - from).raw(),
                });
            }
            Ok(WireBand { from, below })
        };
        // A length that may be 0, as a run a pair must exceed.
        let at_least_zero = |spec: &RuleSpec, param| -> Result<Dbu, DrcError> {
            let ParamValue::Length(value) = value(spec, param)? else {
                return Err(wrong_type(spec, param));
            };
            if value.raw() < 0 {
                return Err(DrcError::NonPositiveLimit {
                    rule: name_of(spec.id),
                    limit: value.raw(),
                });
            }
            Ok(value)
        };
        // A parameter a row may leave out (`none` in the deck).
        let optional = |spec: &RuleSpec, param: &'static str| {
            strings
                .get(param)
                .and_then(|interned| rules.param(spec, interned))
        };
        let flag = |spec: &RuleSpec, param| -> Result<bool, DrcError> {
            match value(spec, param)? {
                ParamValue::Flag(set) => Ok(set),
                _ => Err(wrong_type(spec, param)),
            }
        };
        let sense = |spec: &RuleSpec| -> Result<LimitSense, DrcError> {
            let ParamValue::Flag(maximum) = value(spec, "maximum")? else {
                return Err(wrong_type(spec, "maximum"));
            };
            Ok(if maximum {
                LimitSense::Maximum
            } else {
                LimitSense::Minimum
            })
        };

        let mut set = Self {
            first_derived: (0..deck.layers.len())
                .map(|id| LayerId(u16::try_from(id).expect("a LayerId is a u16")))
                .find(|&layer| deck.layers.is_derived(layer)),
            ..Self::default()
        };
        for spec in &rules.spec {
            let rule = match strings.resolve(spec.kind) {
                "min_width" => Rule::MinWidth {
                    layer: one(spec)?,
                    limit: length(spec, "limit")?,
                },
                "max_width" => Rule::MaxWidth {
                    layer: one(spec)?,
                    limit: length(spec, "limit")?,
                },
                "cut_size" => Rule::CutSize {
                    layer: one(spec)?,
                    width: length(spec, "width")?,
                    height: length(spec, "height")?,
                },
                "min_edge_length" => Rule::MinEdgeLength {
                    layer: one(spec)?,
                    limit: length(spec, "limit")?,
                },
                "notch" => Rule::Notch {
                    layer: one(spec)?,
                    limit: length(spec, "limit")?,
                },
                "min_spacing" => Rule::MinSpacing {
                    layer: one(spec)?,
                    limit: length(spec, "limit")?,
                },
                "min_spacing_diff" => {
                    let (a, b) = two(spec)?;
                    Rule::MinSpacingDiff {
                        a,
                        b,
                        limit: length(spec, "limit")?,
                    }
                }
                "projection_spacing" => {
                    let (a, b) = two(spec)?;
                    Rule::ProjectionSpacing {
                        a,
                        b,
                        limit: length(spec, "limit")?,
                    }
                }
                "eol_spacing" => Rule::EolSpacing {
                    layer: one(spec)?,
                    eol_width: length(spec, "eol_width")?,
                    limit: length(spec, "limit")?,
                },
                "prl_spacing" => Rule::PrlSpacing {
                    layer: one(spec)?,
                    prl_threshold: length(spec, "prl_threshold")?,
                    limit: length(spec, "limit")?,
                },
                "corner_to_corner" => Rule::CornerToCorner {
                    layer: one(spec)?,
                    limit: length(spec, "limit")?,
                },
                "wide_dependent_spacing" => Rule::WideDependentSpacing {
                    layer: one(spec)?,
                    width_threshold: length(spec, "width_threshold")?,
                    limit: length(spec, "limit")?,
                },
                "min_area" => Rule::MinArea {
                    layer: one(spec)?,
                    limit: area_limit(spec, "limit")?,
                },
                "min_enclosed_area" => Rule::MinEnclosedArea {
                    layer: one(spec)?,
                    limit: area_limit(spec, "limit")?,
                },
                "cheesing" => Rule::Cheesing {
                    layer: one(spec)?,
                    max_unslotted: area_limit(spec, "max_unslotted")?,
                },
                "density" => {
                    let (layer, boundary) = bounded(spec)?;
                    let (window, step) = (length(spec, "window")?, length(spec, "step")?);
                    Rule::Density {
                        layer,
                        boundary,
                        window,
                        step,
                        limit: ratio(spec, "limit")?,
                        sense: sense(spec)?,
                    }
                }
                "global_density" => {
                    let (layer, boundary) = bounded(spec)?;
                    Rule::GlobalDensity {
                        layer,
                        boundary,
                        limit: ratio(spec, "limit")?,
                        sense: sense(spec)?,
                    }
                }
                "critical_area" => Rule::CriticalArea {
                    layer: one(spec)?,
                    radius: length(spec, "radius")?,
                    limit: area_limit(spec, "limit")?,
                },
                "via_redundancy" => {
                    layers(spec, 3)?;
                    Rule::ViaRedundancy {
                        cut: layer(spec, 0),
                        lower: layer(spec, 1),
                        upper: layer(spec, 2),
                        pitch: length(spec, "pitch")?,
                        space: at_least_zero(spec, "space")?,
                        limit: ratio(spec, "limit")?,
                    }
                }
                "dfm_score" => {
                    let check = match count(spec, "check", 2)? {
                        0 => DfmCheck::Space,
                        1 => DfmCheck::Width,
                        _ => DfmCheck::Enclosure,
                    };
                    let outer = if check == DfmCheck::Enclosure {
                        layers(spec, 2)?;
                        Some(layer(spec, 1))
                    } else {
                        layers(spec, 1)?;
                        None
                    };
                    let (required, recommended) =
                        (length(spec, "required")?, length(spec, "recommended")?);
                    if required >= recommended {
                        return Err(DrcError::BadTable(name_of(spec.id)));
                    }
                    Rule::DfmScore {
                        check,
                        layer: layer(spec, 0),
                        outer,
                        required,
                        recommended,
                        rate: ratio(spec, "rate")?,
                        limit: ratio(spec, "limit")?,
                    }
                }
                "pattern_match" => {
                    let layer = one(spec)?;
                    // Rectangles by two opposite corners each, in order.
                    let boxes =
                        |xs: &'static str, ys: &'static str| -> Result<Vec<Bbox>, DrcError> {
                            let (xs, ys) = (lengths(spec, xs)?, lengths(spec, ys)?);
                            if xs.len() != ys.len() || xs.len() % 2 != 0 {
                                return Err(DrcError::BadTable(name_of(spec.id)));
                            }
                            Ok(xs
                                .chunks(2)
                                .zip(ys.chunks(2))
                                .map(|(x, y)| Bbox {
                                    xlo: x[0].min(x[1]),
                                    ylo: y[0].min(y[1]),
                                    xhi: x[0].max(x[1]),
                                    yhi: y[0].max(y[1]),
                                })
                                .collect())
                        };
                    let pattern = Pattern {
                        window: (length(spec, "window_w")?, length(spec, "window_h")?),
                        shapes: boxes("shape_x", "shape_y")?,
                        ignore: boxes("ignore_x", "ignore_y")?,
                    };
                    if !pattern.is_valid() {
                        return Err(DrcError::BadTable(name_of(spec.id)));
                    }
                    set.patterns.push(pattern);
                    Rule::PatternMatch {
                        layer,
                        pattern: u32::try_from(set.patterns.len() - 1)
                            .expect("a deck has few patterns"),
                    }
                }
                "cut_area_change" => {
                    layers(spec, 4)?;
                    let counts = |param: &'static str| -> Result<Vec<u32>, DrcError> {
                        let wanted = strings.get(param);
                        rules
                            .params_of(spec)
                            .iter()
                            .filter(|&&(name, _)| Some(name) == wanted)
                            .map(|&(_, stated)| match stated {
                                ParamValue::Count(n) => Ok(n),
                                _ => Err(wrong_type(spec, param)),
                            })
                            .collect()
                    };
                    let wanted = strings.get("change");
                    let change = rules
                        .params_of(spec)
                        .iter()
                        .filter(|&&(name, _)| Some(name) == wanted)
                        .map(|&(_, stated)| match stated {
                            ParamValue::Area(area) => Ok(area),
                            _ => Err(wrong_type(spec, "change")),
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let bands = CutAreaBands {
                        cuts: counts("cuts")?,
                        change,
                    };
                    if !bands.is_valid() {
                        return Err(DrcError::BadTable(name_of(spec.id)));
                    }
                    set.cut_area_bands.push(bands);
                    Rule::CutAreaChange {
                        pre: layer(spec, 0),
                        post: layer(spec, 1),
                        lower: layer(spec, 2),
                        upper: layer(spec, 3),
                        bands: u32::try_from(set.cut_area_bands.len() - 1)
                            .expect("a deck has few tables"),
                    }
                }
                "mean_critical_area" => {
                    let layer = one(spec)?;
                    let wanted = strings.get("weights");
                    let weight = rules
                        .params_of(spec)
                        .iter()
                        .filter(|&&(name, _)| Some(name) == wanted)
                        .map(|&(_, stated)| match stated {
                            ParamValue::Ratio(v) => Ok(v),
                            _ => Err(wrong_type(spec, "weights")),
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let sizes = DefectSizes {
                        radius: lengths(spec, "radii")?,
                        weight,
                    };
                    if !sizes.is_valid() {
                        return Err(DrcError::BadTable(name_of(spec.id)));
                    }
                    set.defect_sizes.push(sizes);
                    Rule::MeanCriticalArea {
                        layer,
                        sizes: u32::try_from(set.defect_sizes.len() - 1)
                            .expect("a deck has few tables"),
                        limit: area_limit(spec, "limit")?,
                    }
                }
                "cover_density" => {
                    let boundary = if spec.layer_len == 2 {
                        None
                    } else {
                        layers(spec, 3)?;
                        Some(layer(spec, 2))
                    };
                    let fractions = |param: &'static str| -> Result<Vec<f64>, DrcError> {
                        let wanted = strings.get(param);
                        rules
                            .params_of(spec)
                            .iter()
                            .filter(|&&(name, _)| Some(name) == wanted)
                            .map(|&(_, stated)| match stated {
                                ParamValue::Ratio(v) => Ok(v),
                                _ => Err(wrong_type(spec, param)),
                            })
                            .collect()
                    };
                    let bands = CoverBands {
                        cover: fractions("cover")?,
                        density: fractions("density")?,
                        inclusive: flag(spec, "inclusive")?,
                    };
                    if !bands.is_valid() {
                        return Err(DrcError::BadTable(name_of(spec.id)));
                    }
                    set.cover_bands.push(bands);
                    Rule::CoverDensity {
                        layer: layer(spec, 0),
                        cover: layer(spec, 1),
                        boundary,
                        window: length(spec, "window")?,
                        step: length(spec, "step")?,
                        bands: u32::try_from(set.cover_bands.len() - 1)
                            .expect("a deck has few tables"),
                    }
                }
                "density_balance" => {
                    let boundary = if spec.layer_len == 2 {
                        None
                    } else {
                        layers(spec, 3)?;
                        Some(layer(spec, 2))
                    };
                    let (a, b) = (layer(spec, 0), layer(spec, 1));
                    Rule::DensityBalance {
                        a,
                        b,
                        boundary,
                        window: length(spec, "window")?,
                        step: length(spec, "step")?,
                        limit: ratio(spec, "limit")?,
                    }
                }
                "min_enclosure" => {
                    let (outer, inner) = two(spec)?;
                    Rule::MinEnclosure {
                        outer,
                        inner,
                        limit: length(spec, "limit")?,
                        wire: wire(spec)?,
                    }
                }
                "full_width" => {
                    let (outer, inner) = two(spec)?;
                    Rule::FullWidth { outer, inner }
                }
                "noncoincident_enclosure" => {
                    let (outer, inner) = two(spec)?;
                    Rule::NoncoincidentEnclosure {
                        outer,
                        inner,
                        limit: length(spec, "limit")?,
                    }
                }
                "asymmetric_enclosure" => {
                    let (outer, inner) = two(spec)?;
                    Rule::AsymmetricEnclosure {
                        outer,
                        inner,
                        min_one_side: length(spec, "min_one_side")?,
                        wire: wire(spec)?,
                    }
                }
                "max_enclosure" => {
                    let (outer, inner) = two(spec)?;
                    Rule::MaxEnclosure {
                        outer,
                        inner,
                        limit: length(spec, "limit")?,
                    }
                }
                "adjacent_enclosure" => {
                    let (outer, inner) = two(spec)?;
                    Rule::AdjacentEnclosure {
                        outer,
                        inner,
                        min_one_side: length(spec, "min_one_side")?,
                    }
                }
                "min_extension" => {
                    let (layer, reference) = two(spec)?;
                    Rule::MinExtension {
                        layer,
                        reference,
                        limit: length(spec, "limit")?,
                    }
                }
                "gate_corner" => {
                    let (layer, reference) = two(spec)?;
                    let ParamValue::Flag(of_reference) = value(spec, "of_reference")? else {
                        return Err(wrong_type(spec, "of_reference"));
                    };
                    Rule::GateCorner {
                        layer,
                        reference,
                        of_reference,
                    }
                }
                "overlap" => {
                    let (a, b) = two(spec)?;
                    Rule::Overlap {
                        a,
                        b,
                        limit: length(spec, "limit")?,
                    }
                }
                "max_distance_to_tap" => {
                    let (well, tap) = two(spec)?;
                    Rule::MaxDistanceToTap {
                        well,
                        tap,
                        limit: length(spec, "limit")?,
                    }
                }
                "off_grid" => {
                    layers(spec, 0)?;
                    Rule::OffGrid {
                        pitch: length(spec, "pitch")?,
                    }
                }
                "angle" => {
                    let layer = match spec.layer_len {
                        0 => None,
                        _ => Some(one(spec)?),
                    };
                    let wanted = strings.get("angle");
                    let mut allowed = 0u8;
                    for &(param, stated) in rules.params_of(spec) {
                        if Some(param) != wanted {
                            continue;
                        }
                        let ParamValue::Count(degrees) = stated else {
                            return Err(wrong_type(spec, "angle"));
                        };
                        let degrees = i32::try_from(degrees % 360).expect("under a full turn");
                        if degrees.rem_euclid(45) != 0 {
                            return Err(DrcError::UnrepresentableAngle {
                                rule: name_of(spec.id),
                                degrees,
                            });
                        }
                        allowed |= 1 << (degrees.rem_euclid(180) / 45);
                    }
                    if allowed == 0 {
                        return Err(DrcError::MissingParam {
                            rule: name_of(spec.id),
                            param: "angle",
                        });
                    }
                    Rule::Angle { layer, allowed }
                }
                "redundant_via" => {
                    let layer = one(spec)?;
                    let min_count = count(spec, "min_count", u16::MAX.into())?;
                    Rule::RedundantVia {
                        layer,
                        min_count: u16::try_from(min_count).expect("checked against the ceiling"),
                        within: length(spec, "within")?,
                    }
                }
                "minimum_cut" => {
                    layers(spec, 3)?;
                    let width = length(spec, "width")?;
                    let within = match strings.get("within").and_then(|p| rules.param(spec, p)) {
                        Some(_) => Some(length(spec, "within")?),
                        None => None,
                    };
                    let min_count = count(spec, "min_count", u16::MAX.into())?;
                    Rule::MinimumCut {
                        cut: layer(spec, 0),
                        wide: layer(spec, 1),
                        other: layer(spec, 2),
                        width,
                        within,
                        min_count: u16::try_from(min_count).expect("checked against the ceiling"),
                    }
                }
                "via_stack" => {
                    if spec.layer_len < 2 {
                        return Err(DrcError::WrongLayerCount {
                            rule: name_of(spec.id),
                            expected: 2,
                            found: spec.layer_len,
                        });
                    }
                    let max_height = count(spec, "max_height", u16::MAX.into())?;
                    set.stacks.push(rules.layers_of(spec).to_vec());
                    Rule::ViaStack {
                        stack: u32::try_from(set.stacks.len() - 1).expect("a deck has few stacks"),
                        max_height: u16::try_from(max_height).expect("checked against the ceiling"),
                    }
                }
                "via_array_spacing" => {
                    let layer = one(spec)?;
                    // Zero is legal: it makes every cluster an array.
                    let threshold = count(spec, "array_threshold", u16::MAX.into())?;
                    Rule::ViaArraySpacing {
                        layer,
                        array_threshold: u16::try_from(threshold).expect("checked"),
                        limit: length(spec, "limit")?,
                    }
                }
                "cut_spacing" => {
                    let layer = one(spec)?;
                    let ParamValue::Flag(center) = value(spec, "center")? else {
                        return Err(wrong_type(spec, "center"));
                    };
                    // No `adjacent` holds every cut.
                    let stated = strings
                        .get("adjacent")
                        .and_then(|p| rules.param(spec, p))
                        .is_some();
                    let (adjacent, within) = if stated {
                        let cuts = count(spec, "adjacent", u16::MAX.into())?;
                        (
                            u16::try_from(cuts).expect("checked against the ceiling"),
                            length(spec, "within")?,
                        )
                    } else {
                        (0, Dbu::new_unchecked(0))
                    };
                    Rule::CutSpacing {
                        layer,
                        center,
                        adjacent,
                        within,
                        limit: length(spec, "limit")?,
                    }
                }
                "multi_patterning" => {
                    let layer = one(spec)?;
                    let colors = count(spec, "colors", u8::MAX.into())?;
                    Rule::MultiPatterning {
                        layer,
                        colors: u8::try_from(colors).expect("checked against the ceiling"),
                        color_spacing: length(spec, "color_spacing")?,
                    }
                }
                "anchored_patterning" => {
                    let all = rules.layers_of(spec);
                    let colors = count(spec, "colors", u8::MAX.into())?;
                    let most = colors.min(4);
                    if all.len() < 2 || all.len() > 1 + most as usize {
                        return Err(DrcError::WrongLayerCount {
                            rule: name_of(spec.id),
                            expected: 1 + most,
                            found: spec.layer_len,
                        });
                    }
                    let mut anchors = [None; 4];
                    for (slot, &anchor) in anchors.iter_mut().zip(&all[1..]) {
                        *slot = Some(anchor);
                    }
                    Rule::AnchoredPatterning {
                        layer: all[0],
                        anchors,
                        colors: u8::try_from(colors).expect("checked against the ceiling"),
                        color_spacing: length(spec, "color_spacing")?,
                    }
                }
                "forbidden" => Rule::Forbidden { layer: one(spec)? },
                "must_contain" => {
                    let (outer, inner) = two(spec)?;
                    // `==` states `count`, `>=` `min_count`, `<=` `max_count`.
                    let bound = |param: &'static str| match strings
                        .get(param)
                        .and_then(|p| rules.param(spec, p))
                    {
                        Some(_) => count(spec, param, u32::MAX).map(Some),
                        None => Ok(None),
                    };
                    let (min_count, max_count) = match bound("count")? {
                        Some(exact) => (Some(exact), Some(exact)),
                        None => (bound("min_count")?, bound("max_count")?),
                    };
                    if min_count.is_none() && max_count.is_none() {
                        return Err(DrcError::MissingParam {
                            rule: name_of(spec.id),
                            param: "min_count",
                        });
                    }
                    Rule::MustContain {
                        outer,
                        inner,
                        min_count: min_count.unwrap_or(0),
                        max_count: max_count.unwrap_or(u32::MAX),
                    }
                }
                "must_be_inside" => {
                    let (inner, outer) = two(spec)?;
                    Rule::MustBeInside { inner, outer }
                }
                "net_spacing" => {
                    let (layer, other) = bounded(spec)?;
                    let ParamValue::Flag(same_net) = value(spec, "same_net")? else {
                        return Err(wrong_type(spec, "same_net"));
                    };
                    // One net's shapes on two layers overlap wherever a cut
                    // joins them, and overlap is a distance of 0: across two
                    // layers only different nets are spaced.
                    if same_net && other.is_some() {
                        return Err(wrong_type(spec, "same_net"));
                    }
                    for read in std::iter::once(layer).chain(other) {
                        if deck.layers.is_derived(read)
                            && !set.net_sources.iter().any(|&(at, _)| at == read)
                        {
                            let mut drawn = Vec::new();
                            let mut todo = vec![read];
                            while let Some(next) = todo.pop() {
                                if deck.layers.is_derived(next) {
                                    todo.extend_from_slice(deck.layers.operands(next));
                                } else if !drawn.contains(&next) {
                                    drawn.push(next);
                                }
                            }
                            drawn.sort_unstable();
                            set.net_sources.push((read, drawn));
                        }
                    }
                    Rule::NetSpacing {
                        layer,
                        other,
                        same_net,
                        limit: length(spec, "limit")?,
                    }
                }
                "spacing_table" => {
                    let layer = one(spec)?;
                    set.tables.push(SpacingTable {
                        prl: lengths(spec, "prl")?,
                        width: lengths(spec, "width")?,
                        space: lengths(spec, "space")?,
                    });
                    Rule::SpacingTable {
                        layer,
                        table: u32::try_from(set.tables.len() - 1).expect("a deck has few tables"),
                    }
                }
                "cut_class_spacing" => {
                    let layer = one(spec)?;
                    let table = CutClassTable {
                        short: lengths(spec, "class_short")?,
                        long: lengths(spec, "class_long")?,
                        space: lengths(spec, "space")?,
                    };
                    if !table.is_valid() {
                        return Err(DrcError::BadTable(name_of(spec.id)));
                    }
                    set.cut_tables.push(table);
                    Rule::CutClassSpacing {
                        layer,
                        table: u32::try_from(set.cut_tables.len() - 1)
                            .expect("a deck has few tables"),
                    }
                }
                "attached_wide_spacing" => Rule::AttachedWideSpacing {
                    layer: one(spec)?,
                    width_threshold: length(spec, "width_threshold")?,
                    attached: length(spec, "attached")?,
                    limit: length(spec, "limit")?,
                },
                "edge_min_length" => Rule::EdgeMinLength {
                    layer: one(spec)?,
                    limit: length(spec, "limit")?,
                },
                "edge_spacing" => {
                    let (a, b) = match spec.layer_len {
                        1 => (one(spec)?, None),
                        _ => two(spec).map(|(a, b)| (a, Some(b)))?,
                    };

                    Rule::EdgeSpacing {
                        a,
                        b,
                        limit: length(spec, "limit")?,
                    }
                }
                "edge_enclosure" => {
                    let (edges, outer) = two(spec)?;
                    Rule::EdgeEnclosure {
                        edges,
                        outer,
                        limit: length(spec, "limit")?,
                    }
                }
                "count" => Rule::Count {
                    layer: one(spec)?,
                    limit: count(spec, "limit", u32::MAX)?,
                    sense: sense(spec)?,
                },
                "aspect_ratio" => Rule::AspectRatio {
                    layer: one(spec)?,
                    limit: ratio(spec, "limit")?,
                },
                "total_area" => Rule::TotalArea {
                    layer: one(spec)?,
                    limit: area_limit(spec, "limit")?,
                },
                "cut_class" => {
                    let layer = one(spec)?;
                    let sides = |param: &'static str| -> Result<Vec<Dbu>, DrcError> {
                        let wanted = strings.get(param);
                        rules
                            .params_of(spec)
                            .iter()
                            .filter(|&&(name, _)| Some(name) == wanted)
                            .map(|&(_, stated)| match stated {
                                ParamValue::Length(side) if side.raw() > 0 => Ok(side),
                                ParamValue::Length(side) => Err(DrcError::NonPositiveLimit {
                                    rule: name_of(spec.id),
                                    limit: side.raw(),
                                }),
                                _ => Err(wrong_type(spec, param)),
                            })
                            .collect()
                    };
                    let (widths, heights) = (sides("width")?, sides("height")?);
                    if widths.is_empty() || widths.len() != heights.len() {
                        return Err(DrcError::MissingParam {
                            rule: name_of(spec.id),
                            param: "allowed",
                        });
                    }
                    let mut classes: Vec<(Dbu, Dbu)> = widths
                        .iter()
                        .zip(&heights)
                        .map(|(&w, &h)| (w.min(h), w.max(h)))
                        .collect();
                    classes.sort_unstable();
                    classes.dedup();
                    set.classes.push(classes);
                    Rule::CutClass {
                        layer,
                        classes: u32::try_from(set.classes.len() - 1)
                            .expect("a deck has few class lists"),
                    }
                }
                "edge_width" => Rule::EdgeWidth {
                    layer: one(spec)?,
                    limit: length(spec, "limit")?,
                },
                "edge_facing_space" => Rule::EdgeFacingSpace {
                    layer: one(spec)?,
                    limit: length(spec, "limit")?,
                    prl: match optional(spec, "prl") {
                        Some(_) => at_least_zero(spec, "prl")?,
                        None => Dbu::new_unchecked(0),
                    },
                },
                "allowed_width" => {
                    let layer = one(spec)?;
                    let wanted = strings.get("width");
                    let mut widths = rules
                        .params_of(spec)
                        .iter()
                        .filter(|&&(name, _)| Some(name) == wanted)
                        .map(|&(_, stated)| match stated {
                            ParamValue::Length(width) if width.raw() > 0 => Ok(width),
                            ParamValue::Length(width) => Err(DrcError::NonPositiveLimit {
                                rule: name_of(spec.id),
                                limit: width.raw(),
                            }),
                            _ => Err(wrong_type(spec, "allowed")),
                        })
                        .collect::<Result<Vec<Dbu>, DrcError>>()?;
                    if widths.is_empty() {
                        return Err(DrcError::MissingParam {
                            rule: name_of(spec.id),
                            param: "allowed",
                        });
                    }
                    widths.sort_unstable();
                    widths.dedup();
                    set.widths.push(widths);
                    Rule::AllowedWidth {
                        layer,
                        widths: u32::try_from(set.widths.len() - 1)
                            .expect("a deck has few width lists"),
                        open_last: optional(spec, "open_last").is_some()
                            && flag(spec, "open_last")?,
                    }
                }
                "min_interior_angle" => Rule::MinInteriorAngle {
                    layer: match spec.layer_len {
                        0 => None,
                        _ => Some(one(spec)?),
                    },
                    limit: ratio(spec, "limit")?,
                },
                "polygon_validity" => Rule::PolygonValidity {
                    layer: match spec.layer_len {
                        0 => None,
                        _ => Some(one(spec)?),
                    },
                },
                "min_step_adjacent" => {
                    let layer = one(spec)?;
                    let limit = length(spec, "limit")?;
                    let neighbour = if optional(spec, "between_eol").is_some() {
                        StepNeighbour::BetweenEol(length(spec, "between_eol")?)
                    } else {
                        StepNeighbour::Adjacent {
                            length: length(spec, "adjacent")?,
                            eol: match optional(spec, "adjacent_eol") {
                                Some(_) => Some(length(spec, "adjacent_eol")?),
                                None => None,
                            },
                            except_rectangle: flag(spec, "except_rectangle")?,
                        }
                    };
                    Rule::MinStepAdjacent {
                        layer,
                        limit,
                        neighbour,
                    }
                }
                "min_step" => {
                    let layer = one(spec)?;
                    let limit = length(spec, "limit")?;
                    let stated = |param: &str| {
                        strings
                            .get(param)
                            .and_then(|name| rules.param(spec, name))
                            .is_some()
                    };
                    let kind = if stated("max_edges") {
                        let most = count(spec, "max_edges", u16::MAX.into())?;
                        StepKind::MaxEdges(
                            u16::try_from(most).expect("checked against the ceiling"),
                        )
                    } else {
                        match count(spec, "corner", 2)? {
                            0 => StepKind::OutsideCorner,
                            1 => StepKind::InsideCorner,
                            _ => StepKind::Step,
                        }
                    };
                    let length_sum = if stated("length_sum") {
                        Some(length(spec, "length_sum")?)
                    } else {
                        None
                    };
                    Rule::MinStep {
                        layer,
                        limit,
                        kind,
                        length_sum,
                    }
                }
                "region_density" => {
                    let (layer, region) = two(spec)?;
                    Rule::RegionDensity {
                        layer,
                        region,
                        limit: ratio(spec, "limit")?,
                        sense: sense(spec)?,
                    }
                }
                "tip_spacing_table" => {
                    let layer = one(spec)?;
                    let table = ClassTable {
                        class: lengths(spec, "length")?,
                        prl: Vec::new(),
                        space: lengths(spec, "space")?,
                    };
                    if !table.is_valid_tips() {
                        return Err(DrcError::BadTable(name_of(spec.id)));
                    }
                    set.class_tables.push(table);
                    Rule::TipSpacingTable {
                        layer,
                        table: u32::try_from(set.class_tables.len() - 1)
                            .expect("a deck has few tables"),
                    }
                }
                "eol_within_spacing" => {
                    let layer = one(spec)?;
                    let eol_width = length(spec, "eol_width")?;
                    let within = at_least_zero(spec, "eol_within")?;
                    let parallel = match optional(spec, "par_space") {
                        None => None,
                        Some(_) => Some(EolParallel {
                            space: length(spec, "par_space")?,
                            within: at_least_zero(spec, "par_within")?,
                            two_edges: flag(spec, "two_edges")?,
                        }),
                    };
                    let end_to_end = match optional(spec, "end_to_end") {
                        None => None,
                        Some(_) => Some(length(spec, "end_to_end")?),
                    };
                    Rule::EolWithinSpacing {
                        layer,
                        eol_width,
                        within,
                        parallel,
                        end_to_end,
                        limit: length(spec, "limit")?,
                    }
                }
                "two_width_spacing_table" => {
                    let layer = one(spec)?;
                    let wanted = strings.get("prl");
                    let prl = rules
                        .params_of(spec)
                        .iter()
                        .filter(|&&(name, _)| Some(name) == wanted)
                        .map(|&(_, stated)| match stated {
                            ParamValue::Length(run) => Ok(Some(run)),
                            ParamValue::Flag(false) => Ok(None),
                            _ => Err(wrong_type(spec, "prl")),
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let table = ClassTable {
                        class: lengths(spec, "width")?,
                        prl,
                        space: lengths(spec, "space")?,
                    };
                    if !table.is_valid_two_widths() {
                        return Err(DrcError::BadTable(name_of(spec.id)));
                    }
                    set.class_tables.push(table);
                    Rule::TwoWidthSpacingTable {
                        layer,
                        table: u32::try_from(set.class_tables.len() - 1)
                            .expect("a deck has few tables"),
                    }
                }
                "exact_pitch" => Rule::ExactPitch {
                    layer: one(spec)?,
                    vertical: flag(spec, "vertical")?,
                    pitch: length(spec, "limit")?,
                },
                "convex_corner_spacing" => {
                    let layer = one(spec)?;
                    let corner_to_corner = flag(spec, "corner_to_corner")?;
                    let except_eol = match optional(spec, "except_eol") {
                        None => None,
                        Some(_) => Some(length(spec, "except_eol")?),
                    };
                    Rule::ConvexCornerSpacing {
                        layer,
                        corner_to_corner,
                        except_eol,
                        limit: length(spec, "limit")?,
                    }
                }
                "span_length" => {
                    let layer = one(spec)?;
                    let table = SpanTable {
                        x: lengths(spec, "x_spans")?,
                        y: lengths(spec, "y_spans")?,
                    };
                    if !table.is_valid() {
                        return Err(DrcError::BadTable(name_of(spec.id)));
                    }
                    set.span_tables.push(table);
                    Rule::SpanLength {
                        layer,
                        table: u32::try_from(set.span_tables.len() - 1)
                            .expect("a deck has few tables"),
                    }
                }
                "keep_out_zone" => {
                    let layer = one(spec)?;
                    // A class is a size either way round: shorter side first.
                    let sorted = |a: Dbu, b: Dbu| (a.min(b), a.max(b));
                    let class = sorted(length(spec, "short")?, length(spec, "long")?);
                    let to = match optional(spec, "to_short") {
                        None => None,
                        Some(_) => {
                            Some(sorted(length(spec, "to_short")?, length(spec, "to_long")?))
                        }
                    };
                    Rule::KeepOutZone {
                        layer,
                        class,
                        to,
                        end: (
                            at_least_zero(spec, "end_side")?,
                            at_least_zero(spec, "end_forward")?,
                        ),
                        side: (
                            at_least_zero(spec, "side_side")?,
                            at_least_zero(spec, "side_forward")?,
                        ),
                    }
                }
                "origin" => Rule::Origin { layer: one(spec)? },
                "protrusion_width" => Rule::ProtrusionWidth {
                    layer: one(spec)?,
                    wide: length(spec, "wide")?,
                    limit: length(spec, "limit")?,
                },
                "eol_keep_out" => Rule::EolKeepOut {
                    layer: one(spec)?,
                    eol_width: length(spec, "eol_width")?,
                    backward: at_least_zero(spec, "backward")?,
                    side: at_least_zero(spec, "side")?,
                    forward: length(spec, "forward")?,
                },
                "forbidden_spacing" => {
                    let layer = one(spec)?;
                    let (min, max) = (length(spec, "min")?, length(spec, "max")?);
                    let prl = at_least_zero(spec, "prl")?;
                    if min > max {
                        return Err(DrcError::BadTable(name_of(spec.id)));
                    }
                    Rule::ForbiddenSpacing {
                        layer,
                        min,
                        max,
                        prl,
                    }
                }
                other => {
                    assert!(
                        !KINDS.contains(&other),
                        "KINDS names {other} but it has no arm"
                    );
                    continue;
                }
            };
            rule.validate(strings.resolve(spec.id), &set.tables)?;
            match strings
                .get("warning")
                .and_then(|name| rules.param(spec, name))
            {
                None | Some(ParamValue::Flag(false)) => {}
                Some(ParamValue::Flag(true)) => set.warnings.push(spec.id),
                Some(_) => return Err(wrong_type(spec, "warning")),
            }
            set.rules.push((spec.id, rule));
        }
        Ok(set)
    }

    /// The number of `RuleRun` rows [`RuleSet::run`] produces.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// [`Self::run_with_nets`] without nets: a [`Rule::NetSpacing`] row records
    /// [`Outcome::Refused`].
    pub fn run(&self, store: &GeometryStore, out: &mut Violations, runs: &mut Vec<RuleRun>) {
        self.run_with_nets(store, None, out, runs);
    }

    /// Runs every rule, one at a time. `out` and `runs` are cleared first, then
    /// `runs` gains exactly one row per rule, in rule order, and `out` the
    /// rules' violations in that order (not yet in canonical order; see
    /// [`Violations::sort_canonical`]). Each layer is validated at most once per
    /// call and dropped after the last rule that reads it.
    ///
    /// # Panics
    ///
    /// When `nets` is not the extraction of `store` and misses a row a
    /// [`Rule::NetSpacing`] layer holds, when a [`Rule::SpacingTable`] names a
    /// table that is missing or fails [`SpacingTable::is_valid`], or when a
    /// [`Rule::CutClass`] or [`Rule::AllowedWidth`] names a list that is
    /// missing.
    /// [`Rule::NetSpacing`] layer holds, or when a [`Rule::SpacingTable`] or
    /// [`Rule::CutClassSpacing`] names a table that is missing or fails its
    /// `is_valid`.
    pub fn run_with_nets(
        &self,
        store: &GeometryStore,
        nets: Option<&NetTable>,
        out: &mut Violations,
        runs: &mut Vec<RuleRun>,
    ) {
        *out = Violations::default();
        runs.clear();
        let s = &mut Scratch::default();
        // Layers `0..drawn` are drawn; the rest are the deck's derived ones.
        let drawn = self.first_derived.map_or(store.layer_count(), |layer| {
            layer.idx().min(store.layer_count())
        });
        // The last rule reading each layer; its validation is dropped after that rule.
        let mut last_use: Vec<usize> = Vec::new();
        for (at, (_, rule)) in self.rules.iter().enumerate() {
            for layer in rule
                .layers()
                .into_iter()
                .chain(rule.more_layers())
                .flatten()
            {
                if last_use.len() <= layer.idx() {
                    last_use.resize(layer.idx() + 1, 0);
                }
                last_use[layer.idx()] = at;
            }
        }
        for (at, &(id, rule)) in self.rules.iter().enumerate() {
            let before = out.len();
            // A rule on a derived layer that could not be computed refuses;
            // the rest run (N-H12-1).
            let uncomputed = rule
                .layers()
                .into_iter()
                .flatten()
                .any(|l| store.is_uncomputed(l));
            let (outcome, examined) = if uncomputed {
                (Outcome::Refused, 0)
            } else {
                match rule {
                    Rule::MinWidth { layer, limit } => {
                        width::facing(store, id, layer, limit, true, s, out)
                    }
                    Rule::MaxWidth { layer, limit } => {
                        width::max_width(store, id, layer, limit, s, out)
                    }
                    Rule::CutSize {
                        layer,
                        width,
                        height,
                    } => width::cut_size(store, id, layer, width, height, s, out),
                    Rule::Notch { layer, limit } => {
                        width::facing(store, id, layer, limit, false, s, out)
                    }
                    Rule::MinEdgeLength { layer, limit } => {
                        width::min_edge_length(store, id, layer, limit, s, out)
                    }
                    Rule::MinSpacing { layer, limit } => {
                        spacing::min_spacing(store, id, layer, limit, s, out)
                    }
                    Rule::MinSpacingDiff { a, b, limit } => {
                        spacing::min_spacing_diff(store, id, a, b, limit, s, out)
                    }
                    Rule::ProjectionSpacing { a, b, limit } => {
                        spacing::projection_spacing(store, id, (a, b), limit, s, out)
                    }
                    Rule::EolSpacing {
                        layer,
                        eol_width,
                        limit,
                    } => spacing::eol_spacing(store, id, layer, eol_width, limit, s, out),
                    Rule::PrlSpacing {
                        layer,
                        prl_threshold,
                        limit,
                    } => spacing::prl_spacing(store, id, layer, prl_threshold, limit, s, out),
                    Rule::CornerToCorner { layer, limit } => {
                        spacing::corner_to_corner(store, id, layer, limit, s, out)
                    }
                    Rule::WideDependentSpacing {
                        layer,
                        width_threshold,
                        limit,
                    } => spacing::wide_dependent(
                        store,
                        id,
                        layer,
                        (width_threshold, Dbu::new_unchecked(0)),
                        limit,
                        s,
                        out,
                    ),
                    Rule::MinArea { layer, limit } => {
                        area::min_area(store, id, layer, limit, s, out)
                    }
                    Rule::MinEnclosedArea { layer, limit } => {
                        area::min_enclosed_area(store, id, layer, limit, s, out)
                    }
                    Rule::Cheesing {
                        layer,
                        max_unslotted,
                    } => area::cheesing(store, id, layer, max_unslotted, s, out),
                    Rule::Density {
                        layer,
                        boundary,
                        window,
                        step,
                        limit,
                        sense,
                    } => area::density(
                        store,
                        id,
                        (layer, boundary, drawn),
                        (window, step),
                        limit,
                        sense,
                        s,
                        out,
                    ),
                    Rule::GlobalDensity {
                        layer,
                        boundary,
                        limit,
                        sense,
                    } => area::global_density(
                        store,
                        id,
                        (layer, boundary, drawn),
                        limit,
                        sense,
                        s,
                        out,
                    ),
                    Rule::CriticalArea {
                        layer,
                        radius,
                        limit,
                    } => area::critical_area(store, id, layer, radius, limit, s, out),
                    Rule::MeanCriticalArea {
                        layer,
                        sizes,
                        limit,
                    } => area::mean_critical_area(
                        store,
                        id,
                        layer,
                        &self.defect_sizes[sizes as usize],
                        limit,
                        s,
                        out,
                    ),
                    Rule::ViaRedundancy {
                        cut,
                        lower,
                        upper,
                        pitch,
                        space,
                        limit,
                    } => via::via_redundancy(
                        store,
                        id,
                        (cut, lower, upper),
                        (pitch, space),
                        limit,
                        s,
                        out,
                    ),
                    Rule::DfmScore {
                        check,
                        layer,
                        outer,
                        required,
                        recommended,
                        rate,
                        limit,
                    } => {
                        let found = match (check, outer) {
                            (DfmCheck::Space, _) => {
                                spacing::min_spacing(store, id, layer, recommended, s, out)
                            }
                            (DfmCheck::Width, _) => {
                                width::facing(store, id, layer, recommended, true, s, out)
                            }
                            (DfmCheck::Enclosure, Some(outer)) => overlay::enclosure(
                                store,
                                id,
                                (outer, layer),
                                (recommended, WireBand::ANY),
                                overlay::Mode::EverySide,
                                s,
                                out,
                            ),
                            (DfmCheck::Enclosure, None) => (Outcome::Refused, 0),
                        };
                        dfm_scored(out, before, (required, recommended), rate, limit);
                        found
                    }
                    Rule::PatternMatch {
                        layer,
                        pattern: index,
                    } => pattern::pattern_match(
                        store,
                        id,
                        layer,
                        &self.patterns[index as usize],
                        s,
                        out,
                    ),
                    Rule::CutAreaChange {
                        pre,
                        post,
                        lower,
                        upper,
                        bands,
                    } => via::cut_area_change(
                        store,
                        id,
                        (pre, post, lower, upper),
                        &self.cut_area_bands[bands as usize],
                        s,
                        out,
                    ),
                    Rule::CoverDensity {
                        layer,
                        cover,
                        boundary,
                        window,
                        step,
                        bands,
                    } => area::cover_density(
                        store,
                        id,
                        (layer, cover, boundary, drawn),
                        (window, step),
                        &self.cover_bands[bands as usize],
                        s,
                        out,
                    ),
                    Rule::DensityBalance {
                        a,
                        b,
                        boundary,
                        window,
                        step,
                        limit,
                    } => area::density_balance(
                        store,
                        id,
                        (a, b, boundary, drawn),
                        (window, step),
                        limit,
                        s,
                        out,
                    ),
                    Rule::MinEnclosure {
                        outer,
                        inner,
                        limit,
                        wire,
                    } => overlay::enclosure(
                        store,
                        id,
                        (outer, inner),
                        (limit, wire),
                        overlay::Mode::EverySide,
                        s,
                        out,
                    ),
                    Rule::FullWidth { outer, inner } => overlay::enclosure(
                        store,
                        id,
                        (outer, inner),
                        (Dbu::new_unchecked(0), WireBand::ANY),
                        overlay::Mode::FullWidth,
                        s,
                        out,
                    ),
                    Rule::NoncoincidentEnclosure {
                        outer,
                        inner,
                        limit,
                    } => overlay::enclosure(
                        store,
                        id,
                        (outer, inner),
                        (limit, WireBand::ANY),
                        overlay::Mode::NonCoincident,
                        s,
                        out,
                    ),
                    Rule::AsymmetricEnclosure {
                        outer,
                        inner,
                        min_one_side,
                        wire,
                    } => overlay::enclosure(
                        store,
                        id,
                        (outer, inner),
                        (min_one_side, wire),
                        overlay::Mode::Opposite,
                        s,
                        out,
                    ),
                    Rule::AdjacentEnclosure {
                        outer,
                        inner,
                        min_one_side,
                    } => overlay::enclosure(
                        store,
                        id,
                        (outer, inner),
                        (min_one_side, WireBand::ANY),
                        overlay::Mode::Adjacent,
                        s,
                        out,
                    ),
                    Rule::MaxEnclosure {
                        outer,
                        inner,
                        limit,
                    } => overlay::max_enclosure(store, id, (outer, inner), limit, s, out),
                    Rule::MinExtension {
                        layer,
                        reference,
                        limit,
                    } => overlay::min_extension(store, id, layer, reference, limit, s, out),
                    Rule::GateCorner {
                        layer,
                        reference,
                        of_reference,
                    } => overlay::gate_corner(store, id, (layer, reference), of_reference, s, out),
                    Rule::Overlap { a, b, limit } => {
                        overlay::overlap(store, id, a, b, limit, s, out)
                    }
                    Rule::MaxDistanceToTap { well, tap, limit } => {
                        overlay::max_distance_to_tap(store, id, well, tap, limit, s, out)
                    }
                    Rule::OffGrid { pitch } => grid::off_grid(store, id, pitch, drawn, out),
                    Rule::Angle { layer, allowed } => {
                        grid::angle(store, id, (layer, drawn), allowed, out)
                    }
                    Rule::RedundantVia {
                        layer,
                        min_count,
                        within,
                    } => via::redundant_via(store, id, layer, min_count, within, s, out),
                    Rule::ViaArraySpacing {
                        layer,
                        array_threshold,
                        limit,
                    } => via::via_array_spacing(store, id, layer, array_threshold, limit, s, out),
                    Rule::CutSpacing {
                        layer,
                        center,
                        adjacent,
                        within,
                        limit,
                    } => via::cut_spacing(
                        store,
                        id,
                        (layer, center),
                        (adjacent, within),
                        limit,
                        s,
                        out,
                    ),
                    Rule::MinimumCut {
                        cut,
                        wide,
                        other,
                        width,
                        within,
                        min_count,
                    } => via::minimum_cut(
                        store,
                        id,
                        (cut, wide, other),
                        (width, within),
                        min_count,
                        s,
                        out,
                    ),
                    Rule::ViaStack { stack, max_height } => {
                        via::via_stack(store, id, &self.stacks[stack as usize], max_height, out)
                    }
                    Rule::CutClassSpacing { layer, table } => via::cut_class_spacing(
                        store,
                        id,
                        layer,
                        &self.cut_tables[table as usize],
                        s,
                        out,
                    ),
                    Rule::KeepOutZone {
                        layer,
                        class,
                        to,
                        end,
                        side,
                    } => via::keep_out_zone(store, id, layer, class, to, end, side, out),
                    Rule::MultiPatterning {
                        layer,
                        colors,
                        color_spacing,
                    } => patterning::multi_patterning(
                        store,
                        id,
                        layer,
                        colors,
                        color_spacing,
                        s,
                        out,
                    ),
                    Rule::AnchoredPatterning {
                        layer,
                        anchors,
                        colors,
                        color_spacing,
                    } => {
                        let anchors: Vec<LayerId> = anchors.into_iter().flatten().collect();
                        patterning::anchored_patterning(
                            store,
                            id,
                            (layer, &anchors),
                            colors,
                            color_spacing,
                            s,
                            out,
                        )
                    }
                    Rule::Forbidden { layer } => presence::forbidden(store, id, layer, s, out),
                    Rule::MustContain {
                        outer,
                        inner,
                        min_count,
                        max_count,
                    } => presence::must_contain(
                        store,
                        id,
                        (outer, inner),
                        (min_count, max_count),
                        s,
                        out,
                    ),
                    Rule::MustBeInside { inner, outer } => {
                        presence::must_be_inside(store, id, inner, outer, s, out)
                    }
                    Rule::NetSpacing {
                        layer,
                        other,
                        same_net,
                        limit,
                    } => match nets {
                        Some(nets) => {
                            let sources = |read: LayerId| {
                                self.net_sources
                                    .iter()
                                    .find(|&&(at, _)| at == read)
                                    .map_or(&[][..], |(_, drawn)| drawn.as_slice())
                            };
                            spacing::net_spacing(
                                store,
                                nets,
                                id,
                                (layer, other),
                                (sources(layer), other.map_or(&[][..], sources)),
                                same_net,
                                limit,
                                s,
                                out,
                            )
                        }
                        None => (Outcome::Refused, 0),
                    },
                    Rule::SpacingTable { layer, table } => spacing::spacing_table(
                        store,
                        id,
                        layer,
                        &self.tables[table as usize],
                        s,
                        out,
                    ),
                    Rule::AttachedWideSpacing {
                        layer,
                        width_threshold,
                        attached,
                        limit,
                    } => spacing::wide_dependent(
                        store,
                        id,
                        layer,
                        (width_threshold, attached),
                        limit,
                        s,
                        out,
                    ),
                    Rule::EdgeMinLength { layer, limit } => {
                        edge::min_length(store, id, layer, limit, out)
                    }
                    Rule::EdgeSpacing { a, b, limit } => edge::spacing(store, id, a, b, limit, out),
                    Rule::EdgeEnclosure {
                        edges,
                        outer,
                        limit,
                    } => edge::enclosure(store, id, edges, outer, limit, s, out),
                    Rule::Count {
                        layer,
                        limit,
                        sense,
                    } => area::count(store, id, (layer, drawn), limit, sense, s, out),
                    Rule::AspectRatio { layer, limit } => {
                        area::aspect_ratio(store, id, layer, limit, s, out)
                    }
                    Rule::TotalArea { layer, limit } => {
                        area::total_area(store, id, (layer, drawn), limit, s, out)
                    }
                    Rule::CutClass { layer, classes } => {
                        width::cut_class(store, id, layer, &self.classes[classes as usize], s, out)
                    }
                    Rule::EdgeWidth { layer, limit } => edge::facing(
                        store,
                        id,
                        layer,
                        (limit, Dbu::new_unchecked(0)),
                        true,
                        out,
                    ),
                    Rule::EdgeFacingSpace { layer, limit, prl } => {
                        edge::facing(store, id, layer, (limit, prl), false, out)
                    }
                    Rule::RegionDensity {
                        layer,
                        region,
                        limit,
                        sense,
                    } => area::region_density(store, id, (layer, region), limit, sense, s, out),
                    Rule::AllowedWidth {
                        layer,
                        widths,
                        open_last,
                    } => width::allowed_width(
                        store,
                        id,
                        layer,
                        (&self.widths[widths as usize], open_last),
                        s,
                        out,
                    ),
                    Rule::Origin { layer } => grid::origin(store, id, layer, out),
                    Rule::ProtrusionWidth { layer, wide, limit } => {
                        width::protrusion_width(store, id, layer, wide, limit, s, out)
                    }
                    Rule::MinInteriorAngle { layer, limit } => {
                        grid::min_interior_angle(store, id, (layer, drawn), limit, out)
                    }
                    Rule::PolygonValidity { layer } => {
                        grid::polygon_validity(store, id, (layer, drawn), out)
                    }
                    Rule::MinStep {
                        layer,
                        limit,
                        kind,
                        length_sum,
                    } => width::min_step(store, id, layer, (limit, kind, length_sum), s, out),
                    Rule::MinStepAdjacent {
                        layer,
                        limit,
                        neighbour,
                    } => width::min_step_adjacent(store, id, layer, (limit, neighbour), s, out),
                    Rule::TipSpacingTable { layer, table } => facing::tip_spacing_table(
                        store,
                        id,
                        layer,
                        &self.class_tables[table as usize],
                        s,
                        out,
                    ),
                    Rule::ForbiddenSpacing {
                        layer,
                        min,
                        max,
                        prl,
                    } => facing::forbidden_spacing(store, id, layer, (min, max, prl), s, out),
                    Rule::EolWithinSpacing {
                        layer,
                        eol_width,
                        within,
                        parallel,
                        end_to_end,
                        limit,
                    } => facing::eol_within_spacing(
                        store,
                        id,
                        layer,
                        (eol_width, within, limit),
                        (parallel, end_to_end),
                        s,
                        out,
                    ),
                    Rule::ExactPitch {
                        layer,
                        vertical,
                        pitch,
                    } => facing::exact_pitch(store, id, layer, vertical, pitch, s, out),
                    Rule::ConvexCornerSpacing {
                        layer,
                        corner_to_corner,
                        except_eol,
                        limit,
                    } => facing::convex_corner_spacing(
                        store,
                        id,
                        layer,
                        (corner_to_corner, except_eol),
                        limit,
                        s,
                        out,
                    ),
                    Rule::SpanLength { layer, table } => facing::span_length(
                        store,
                        id,
                        layer,
                        &self.span_tables[table as usize],
                        s,
                        out,
                    ),
                    Rule::TwoWidthSpacingTable { layer, table } => spacing::two_width_table(
                        store,
                        id,
                        layer,
                        &self.class_tables[table as usize],
                        s,
                        out,
                    ),
                    Rule::EolKeepOut {
                        layer,
                        eol_width,
                        backward,
                        side,
                        forward,
                    } => facing::eol_keep_out(
                        store,
                        id,
                        layer,
                        eol_width,
                        (backward, side, forward),
                        s,
                        out,
                    ),
                }
            };
            if self.warnings.contains(&id) {
                out.severity[before..].fill(Severity::Warning);
            }
            record_run(runs, out, before, id, outcome, examined);
            // A rule over every layer (`angle` with none named, `off_grid`, `via_stack`)
            // declares none.
            let declared = rule.layers();
            debug_assert!(
                declared == [None, None, None]
                    || out.layer[before..]
                        .iter()
                        .all(|&layer| declared.contains(&Some(layer))),
                "rule {id:?} reports only on a layer it reads, {declared:?}"
            );
            for layer in rule
                .layers()
                .into_iter()
                .chain(rule.more_layers())
                .flatten()
            {
                if last_use[layer.idx()] == at {
                    s.validated.forget(layer);
                }
            }
        }
    }
}

/// A [`Rule::DfmScore`]'s rows: the check's findings past `before` are
/// replaced by at most one, the design's score, at the lowest-scoring
/// finding's marker, when it is below `limit`.
fn dfm_scored(
    out: &mut Violations,
    before: usize,
    (required, recommended): (Dbu, Dbu),
    rate: f64,
    limit: f64,
) {
    #[allow(
        clippy::cast_precision_loss,
        reason = "grid lengths are far below 2^52"
    )]
    let score = |measured: Measurement| match measured {
        Measurement::Length(m) => {
            let span = (recommended - required).raw() as f64;
            (((m - required).raw() as f64) / span).clamp(0.0, 1.0)
        }
        _ => 0.0,
    };
    let scores: Vec<f64> = out.measured[before..].iter().map(|&m| score(m)).collect();
    let worst = scores
        .iter()
        .enumerate()
        .min_by(|a, b| a.1.total_cmp(b.1))
        .map(|(at, _)| before + at);
    let design: f64 = scores.iter().map(|s| 1.0 - rate * (1.0 - s)).product();
    let kept = worst.filter(|_| design < limit).map(|at| out.get(at));
    out.truncate(before);
    if let Some(row) = kept {
        out.push(Violation {
            measured: Measurement::Ratio(design),
            limit: Measurement::Ratio(limit),
            ..row
        });
    }
}

impl Rule {
    /// The layers a rule reads past [`Self::layers`]: the anchors of
    /// [`Rule::AnchoredPatterning`], the boundary of
    /// [`Rule::DensityBalance`].
    fn more_layers(&self) -> [Option<LayerId>; 4] {
        match *self {
            Rule::AnchoredPatterning { anchors, .. } => anchors,
            Rule::DensityBalance { boundary, .. } | Rule::CoverDensity { boundary, .. } => {
                [boundary, None, None, None]
            }
            Rule::CutAreaChange { upper, .. } => [Some(upper), None, None, None],
            _ => [None; 4],
        }
    }

    /// Whether the rule's values are ones its kind can hold, as each variant
    /// states: every length, area and fraction positive (a fraction also
    /// finite), every required count at least 1, an angle rule allowing some
    /// angle, and a [`Rule::SpacingTable`] naming a table of `tables` that is
    /// [`SpacingTable::is_valid`]. [`RuleSet::from_deck`] holds every row to
    /// it; a rule built in code is held to the same.
    ///
    /// `rule` is the rule's id, for the error.
    ///
    /// # Errors
    ///
    /// The first value that fails, in field order:
    /// [`DrcError::NonPositiveLimit`] for a value that is not positive,
    /// [`DrcError::MissingParam`] for an angle rule allowing nothing, and
    /// [`DrcError::BadTable`] for a missing or invalid table.
    ///
    /// # Examples
    ///
    /// ```
    /// use gpurify_check::drc::{DrcError, Rule};
    /// use gpurify_geom::{Dbu, LayerId};
    ///
    /// let width = |nm| Rule::MinWidth { layer: LayerId(0), limit: Dbu::new_unchecked(nm) };
    /// assert!(width(140).validate("m1.1", &[]).is_ok());
    /// assert_eq!(
    ///     width(0).validate("m1.1", &[]),
    ///     Err(DrcError::NonPositiveLimit { rule: "m1.1".into(), limit: 0 })
    /// );
    /// ```
    pub fn validate(&self, rule: &str, tables: &[SpacingTable]) -> Result<(), DrcError> {
        let refuse = |limit: i64| DrcError::NonPositiveLimit {
            rule: rule.to_owned(),
            limit,
        };
        let length = |value: Dbu| {
            if value.raw() > 0 {
                Ok(())
            } else {
                Err(refuse(value.raw()))
            }
        };
        let area = |value: DbuArea| {
            if value.raw() > 0 {
                Ok(())
            } else {
                Err(refuse(i64::try_from(value.raw()).unwrap_or(i64::MIN)))
            }
        };
        // `!(x > 0)` also refuses NaN, which would compare clean everywhere.
        let fraction = |value: f64| {
            if value > 0.0 && value.is_finite() {
                Ok(())
            } else {
                #[allow(clippy::cast_possible_truncation, reason = "shown to a human only")]
                let shown = value as i64;
                Err(refuse(shown))
            }
        };
        let count = |value: u32| if value > 0 { Ok(()) } else { Err(refuse(0)) };
        match *self {
            Rule::MinWidth { limit, .. }
            | Rule::MaxWidth { limit, .. }
            | Rule::MinEdgeLength { limit, .. }
            | Rule::Notch { limit, .. }
            | Rule::MinSpacing { limit, .. }
            | Rule::MinSpacingDiff { limit, .. }
            | Rule::ProjectionSpacing { limit, .. }
            | Rule::CornerToCorner { limit, .. }
            | Rule::MinEnclosure { limit, .. }
            | Rule::NoncoincidentEnclosure { limit, .. }
            | Rule::MaxEnclosure { limit, .. }
            | Rule::AsymmetricEnclosure {
                min_one_side: limit,
                ..
            }
            | Rule::AdjacentEnclosure {
                min_one_side: limit,
                ..
            }
            | Rule::MinExtension { limit, .. }
            | Rule::Overlap { limit, .. }
            | Rule::MaxDistanceToTap { limit, .. }
            | Rule::OffGrid { pitch: limit }
            | Rule::NetSpacing { limit, .. }
            | Rule::ViaArraySpacing { limit, .. }
            | Rule::EdgeMinLength { limit, .. }
            | Rule::EdgeSpacing { limit, .. }
            | Rule::EdgeEnclosure { limit, .. }
            | Rule::EdgeWidth { limit, .. }
            | Rule::EdgeFacingSpace { limit, .. } => length(limit),
            Rule::MinStep {
                limit, length_sum, ..
            } => length(limit).and(length_sum.map_or(Ok(()), length)),
            Rule::MinStepAdjacent {
                limit, neighbour, ..
            } => length(limit).and(match neighbour {
                StepNeighbour::Adjacent { length: adj, eol, .. } => {
                    length(adj).and(eol.map_or(Ok(()), length))
                }
                StepNeighbour::BetweenEol(eol) => length(eol),
            }),
            Rule::CutSize { width, height, .. } => length(width).and(length(height)),
            Rule::EolSpacing {
                eol_width: first,
                limit,
                ..
            }
            | Rule::PrlSpacing {
                prl_threshold: first,
                limit,
                ..
            }
            | Rule::WideDependentSpacing {
                width_threshold: first,
                limit,
                ..
            } => length(first).and(length(limit)),
            Rule::AttachedWideSpacing {
                width_threshold,
                attached,
                limit,
                ..
            } => length(width_threshold)
                .and(length(attached))
                .and(length(limit)),
            Rule::MinArea { limit, .. }
            | Rule::MinEnclosedArea { limit, .. }
            | Rule::TotalArea { limit, .. } => area(limit),
            Rule::Cheesing { max_unslotted, .. } => area(max_unslotted),
            Rule::Density {
                window,
                step,
                limit,
                ..
            }
            | Rule::DensityBalance {
                window,
                step,
                limit,
                ..
            } => length(window).and(length(step)).and(fraction(limit)),
            // The bands are checked where they are filed.
            Rule::CoverDensity { window, step, .. } => length(window).and(length(step)),
            Rule::CutAreaChange { .. } | Rule::PatternMatch { .. } => Ok(()),
            Rule::MeanCriticalArea { limit, .. } => area(limit),
            Rule::ViaRedundancy {
                pitch,
                space,
                limit,
                ..
            } => length(pitch)
                .and(if space.raw() < 0 {
                    Err(refuse(space.raw()))
                } else {
                    Ok(())
                })
                .and(fraction(limit)),
            Rule::DfmScore {
                required,
                recommended,
                rate,
                limit,
                ..
            } => length(required)
                .and(length(recommended - required))
                .and(fraction(rate))
                .and(fraction(limit)),
            Rule::GlobalDensity { limit, .. }
            | Rule::AspectRatio { limit, .. }
            | Rule::RegionDensity { limit, .. }
            | Rule::MinInteriorAngle { limit, .. } => fraction(limit),
            Rule::Angle { allowed, .. } => {
                if allowed == 0 {
                    Err(DrcError::MissingParam {
                        rule: rule.to_owned(),
                        param: "angle",
                    })
                } else {
                    Ok(())
                }
            }
            Rule::RedundantVia {
                min_count, within, ..
            } => count(min_count.into()).and(length(within)),
            Rule::MultiPatterning {
                colors,
                color_spacing,
                ..
            }
            | Rule::AnchoredPatterning {
                colors,
                color_spacing,
                ..
            } => count(colors.into()).and(length(color_spacing)),
            Rule::CriticalArea { radius, limit, .. } => length(radius).and(area(limit)),
            Rule::MinimumCut {
                width,
                within,
                min_count,
                ..
            } => length(width)
                .and(within.map_or(Ok(()), length))
                .and(count(min_count.into())),
            Rule::ViaStack { max_height, .. } => count(max_height.into()),
            Rule::CutSpacing {
                adjacent,
                within,
                limit,
                ..
            } => length(limit).and(if adjacent == 0 {
                Ok(())
            } else {
                length(within)
            }),
            // The bound stated: `max_count` when there is one, else `min_count`.
            Rule::MustContain {
                min_count,
                max_count,
                ..
            } => count(if max_count == u32::MAX {
                min_count
            } else {
                max_count
            }),
            // A shape count of zero is a limit: none allowed, or at least none.
            // The cut and width lists, the class and span tables, the runs
            // that may be 0 and a forbidden range's order are checked where
            // they are filed.
            Rule::Forbidden { .. }
            | Rule::MustBeInside { .. }
            | Rule::Origin { .. }
            | Rule::Count { .. }
            | Rule::CutClass { .. }
            | Rule::AllowedWidth { .. }
            | Rule::PolygonValidity { .. }
            | Rule::TipSpacingTable { .. }
            | Rule::TwoWidthSpacingTable { .. }
            | Rule::SpanLength { .. }
            | Rule::FullWidth { .. }
            | Rule::GateCorner { .. }
            // A cut-class table is checked where it is filed.
            | Rule::CutClassSpacing { .. } => Ok(()),
            Rule::ForbiddenSpacing { min, max, .. } => length(min).and(length(max)),
            Rule::EolWithinSpacing {
                eol_width,
                parallel,
                end_to_end,
                limit,
                ..
            } => length(eol_width)
                .and(parallel.map_or(Ok(()), |parallel| length(parallel.space)))
                .and(end_to_end.map_or(Ok(()), length))
                .and(length(limit)),
            Rule::EolKeepOut {
                eol_width, forward, ..
            } => length(eol_width).and(length(forward)),
            Rule::ProtrusionWidth { wide, limit, .. } => length(wide).and(length(limit)),
            Rule::KeepOutZone {
                class: (short, long),
                to,
                end,
                side,
                ..
            } => {
                // An oblong class: a square one has no long axis to grow along.
                let at_least_zero = |value: Dbu| {
                    if value.raw() < 0 {
                        Err(refuse(value.raw()))
                    } else {
                        Ok(())
                    }
                };
                length(short)
                    .and(length(long - short))
                    .and(to.map_or(Ok(()), |(short, _)| length(short)))
                    .and(at_least_zero(end.0))
                    .and(at_least_zero(end.1))
                    .and(at_least_zero(side.0))
                    .and(at_least_zero(side.1))
            }
            Rule::ConvexCornerSpacing {
                except_eol, limit, ..
            } => except_eol.map_or(Ok(()), length).and(length(limit)),
            Rule::ExactPitch { pitch, .. } => length(pitch),
            Rule::SpacingTable { table, .. } => {
                if tables
                    .get(table as usize)
                    .is_some_and(SpacingTable::is_valid)
                {
                    Ok(())
                } else {
                    Err(DrcError::BadTable(rule.to_owned()))
                }
            }
        }
    }

    /// The space this rule requires between two shapes on `layer` that
    /// `query` describes: the `limit` its check reports for such a pair.
    ///
    /// `None` when the rule does not hold such a pair: it is not a same-layer
    /// spacing rule on `layer` ([`Rule::MinSpacing`],
    /// [`Rule::WideDependentSpacing`], [`Rule::AttachedWideSpacing`],
    /// [`Rule::PrlSpacing`], [`Rule::EolSpacing`], [`Rule::SpacingTable`]),
    /// or the pair is not wide enough, does not run far enough, or faces no
    /// end of line short enough. Each condition is the function the check
    /// itself calls, so a router reading this and the checker cannot
    /// disagree. A [`Rule::SpacingTable`] names a table of `tables`.
    ///
    /// # Examples
    ///
    /// ```
    /// use gpurify_check::drc::ruleset::{Rule, SpacingQuery};
    /// use gpurify_geom::{Dbu, LayerId};
    ///
    /// let nm = Dbu::new_unchecked;
    /// let wide = Rule::WideDependentSpacing { layer: LayerId(0), width_threshold: nm(3000), limit: nm(400) };
    /// let narrow = SpacingQuery { width_a: nm(140), width_b: nm(140), run_length: nm(5000), end_of_line: None };
    /// assert_eq!(wide.required_spacing(LayerId(0), &[], &narrow), None);
    /// let plate = SpacingQuery { width_a: nm(3000), ..narrow };
    /// assert_eq!(wide.required_spacing(LayerId(0), &[], &plate), Some(nm(400)));
    /// ```
    pub fn required_spacing(
        &self,
        layer: LayerId,
        tables: &[SpacingTable],
        query: &SpacingQuery,
    ) -> Option<Dbu> {
        let wider = query.width_a.max(query.width_b);
        match *self {
            Rule::MinSpacing { layer: on, limit } if on == layer => Some(limit),
            Rule::WideDependentSpacing {
                layer: on,
                width_threshold,
                limit,
            }
            | Rule::AttachedWideSpacing {
                layer: on,
                width_threshold,
                limit,
                ..
            } if on == layer => is_wide(wider, width_threshold).then_some(limit),
            Rule::PrlSpacing {
                layer: on,
                prl_threshold,
                limit,
            } if on == layer => prl_holds(query.run_length.raw(), prl_threshold).then_some(limit),
            Rule::EolSpacing {
                layer: on,
                eol_width,
                limit,
            } if on == layer => query
                .end_of_line
                .is_some_and(|edge| is_end_of_line(edge.raw(), eol_width))
                .then_some(limit),
            Rule::SpacingTable { layer: on, table } if on == layer => {
                let table = &tables[table as usize];
                (0..table.width.len())
                    .filter(|&row| row == 0 || is_wide(wider, table.row_square(row)))
                    .map(|row| table.at(row, table.column(row, |_| query.run_length.raw())))
                    .max()
            }
            _ => None,
        }
    }

    /// The kind name a deck row resolves to for this variant, its entry of
    /// [`KINDS`]: `min_width` for [`Rule::MinWidth`].
    pub fn kind(&self) -> &'static str {
        match self {
            Rule::MinWidth { .. } => "min_width",
            Rule::MaxWidth { .. } => "max_width",
            Rule::CutSize { .. } => "cut_size",
            Rule::MinEdgeLength { .. } => "min_edge_length",
            Rule::Notch { .. } => "notch",
            Rule::MinSpacing { .. } => "min_spacing",
            Rule::MinSpacingDiff { .. } => "min_spacing_diff",
            Rule::ProjectionSpacing { .. } => "projection_spacing",
            Rule::EolSpacing { .. } => "eol_spacing",
            Rule::PrlSpacing { .. } => "prl_spacing",
            Rule::CornerToCorner { .. } => "corner_to_corner",
            Rule::WideDependentSpacing { .. } => "wide_dependent_spacing",
            Rule::MinArea { .. } => "min_area",
            Rule::MinEnclosedArea { .. } => "min_enclosed_area",
            Rule::Cheesing { .. } => "cheesing",
            Rule::Density { .. } => "density",
            Rule::GlobalDensity { .. } => "global_density",
            Rule::MinEnclosure { .. } => "min_enclosure",
            Rule::NoncoincidentEnclosure { .. } => "noncoincident_enclosure",
            Rule::FullWidth { .. } => "full_width",
            Rule::AsymmetricEnclosure { .. } => "asymmetric_enclosure",
            Rule::MaxEnclosure { .. } => "max_enclosure",
            Rule::AdjacentEnclosure { .. } => "adjacent_enclosure",
            Rule::MinExtension { .. } => "min_extension",
            Rule::GateCorner { .. } => "gate_corner",
            Rule::Overlap { .. } => "overlap",
            Rule::MaxDistanceToTap { .. } => "max_distance_to_tap",
            Rule::OffGrid { .. } => "off_grid",
            Rule::Angle { .. } => "angle",
            Rule::RedundantVia { .. } => "redundant_via",
            Rule::MinimumCut { .. } => "minimum_cut",
            Rule::ViaStack { .. } => "via_stack",
            Rule::ViaArraySpacing { .. } => "via_array_spacing",
            Rule::CutSpacing { .. } => "cut_spacing",
            Rule::CutClassSpacing { .. } => "cut_class_spacing",
            Rule::MultiPatterning { .. } => "multi_patterning",
            Rule::AnchoredPatterning { .. } => "anchored_patterning",
            Rule::CriticalArea { .. } => "critical_area",
            Rule::DensityBalance { .. } => "density_balance",
            Rule::CoverDensity { .. } => "cover_density",
            Rule::MeanCriticalArea { .. } => "mean_critical_area",
            Rule::CutAreaChange { .. } => "cut_area_change",
            Rule::PatternMatch { .. } => "pattern_match",
            Rule::DfmScore { .. } => "dfm_score",
            Rule::ViaRedundancy { .. } => "via_redundancy",
            Rule::Forbidden { .. } => "forbidden",
            Rule::MustContain { .. } => "must_contain",
            Rule::MustBeInside { .. } => "must_be_inside",
            Rule::NetSpacing { .. } => "net_spacing",
            Rule::SpacingTable { .. } => "spacing_table",
            Rule::AttachedWideSpacing { .. } => "attached_wide_spacing",
            Rule::EdgeMinLength { .. } => "edge_min_length",
            Rule::EdgeSpacing { .. } => "edge_spacing",
            Rule::EdgeEnclosure { .. } => "edge_enclosure",
            Rule::Count { .. } => "count",
            Rule::AspectRatio { .. } => "aspect_ratio",
            Rule::TotalArea { .. } => "total_area",
            Rule::CutClass { .. } => "cut_class",
            Rule::EdgeWidth { .. } => "edge_width",
            Rule::EdgeFacingSpace { .. } => "edge_facing_space",
            Rule::RegionDensity { .. } => "region_density",
            Rule::AllowedWidth { .. } => "allowed_width",
            Rule::MinInteriorAngle { .. } => "min_interior_angle",
            Rule::PolygonValidity { .. } => "polygon_validity",
            Rule::MinStep { .. } => "min_step",
            Rule::MinStepAdjacent { .. } => "min_step_adjacent",
            Rule::TipSpacingTable { .. } => "tip_spacing_table",
            Rule::ForbiddenSpacing { .. } => "forbidden_spacing",
            Rule::EolWithinSpacing { .. } => "eol_within_spacing",
            Rule::EolKeepOut { .. } => "eol_keep_out",
            Rule::ProtrusionWidth { .. } => "protrusion_width",
            Rule::Origin { .. } => "origin",
            Rule::KeepOutZone { .. } => "keep_out_zone",
            Rule::TwoWidthSpacingTable { .. } => "two_width_spacing_table",
            Rule::SpanLength { .. } => "span_length",
            Rule::ConvexCornerSpacing { .. } => "convex_corner_spacing",
            Rule::ExactPitch { .. } => "exact_pitch",
        }
    }

    /// Every layer the rule reads: one to three, `None` past them (an
    /// [`Rule::OffGrid`] reads none of its own; an [`Rule::Angle`] without a
    /// layer reads every drawn one).
    pub fn layers(&self) -> [Option<LayerId>; 3] {
        match *self {
            Rule::MinWidth { layer, .. }
            | Rule::MaxWidth { layer, .. }
            | Rule::CutSize { layer, .. }
            | Rule::MinEdgeLength { layer, .. }
            | Rule::Notch { layer, .. }
            | Rule::MinSpacing { layer, .. }
            | Rule::EolSpacing { layer, .. }
            | Rule::PrlSpacing { layer, .. }
            | Rule::CornerToCorner { layer, .. }
            | Rule::WideDependentSpacing { layer, .. }
            | Rule::MinArea { layer, .. }
            | Rule::MinEnclosedArea { layer, .. }
            | Rule::Cheesing { layer, .. }
            | Rule::CriticalArea { layer, .. }
            | Rule::MeanCriticalArea { layer, .. }
            | Rule::RedundantVia { layer, .. }
            | Rule::ViaArraySpacing { layer, .. }
            | Rule::CutSpacing { layer, .. }
            | Rule::CutClassSpacing { layer, .. }
            | Rule::MultiPatterning { layer, .. }
            | Rule::AnchoredPatterning { layer, .. }
            | Rule::Forbidden { layer }
            | Rule::SpacingTable { layer, .. }
            | Rule::AttachedWideSpacing { layer, .. }
            | Rule::EdgeMinLength { layer, .. }
            | Rule::Count { layer, .. }
            | Rule::AspectRatio { layer, .. }
            | Rule::TotalArea { layer, .. }
            | Rule::CutClass { layer, .. }
            | Rule::EdgeWidth { layer, .. }
            | Rule::EdgeFacingSpace { layer, .. }
            | Rule::AllowedWidth { layer, .. }
            | Rule::MinStep { layer, .. }
            | Rule::MinStepAdjacent { layer, .. }
            | Rule::TipSpacingTable { layer, .. }
            | Rule::ForbiddenSpacing { layer, .. }
            | Rule::EolWithinSpacing { layer, .. }
            | Rule::EolKeepOut { layer, .. }
            | Rule::KeepOutZone { layer, .. }
            | Rule::ProtrusionWidth { layer, .. }
            | Rule::Origin { layer }
            | Rule::PatternMatch { layer, .. }
            | Rule::TwoWidthSpacingTable { layer, .. }
            | Rule::SpanLength { layer, .. }
            | Rule::ConvexCornerSpacing { layer, .. }
            | Rule::ExactPitch { layer, .. } => [Some(layer), None, None],
            Rule::EdgeSpacing { a, b, .. }
            | Rule::NetSpacing {
                layer: a, other: b, ..
            } => [Some(a), b, None],
            Rule::Density {
                layer, boundary, ..
            }
            | Rule::GlobalDensity {
                layer, boundary, ..
            } => [Some(layer), boundary, None],
            Rule::MinSpacingDiff { a, b, .. }
            | Rule::ProjectionSpacing { a, b, .. }
            | Rule::DensityBalance { a, b, .. }
            | Rule::CoverDensity {
                layer: a, cover: b, ..
            }
            | Rule::Overlap { a, b, .. }
            | Rule::MinEnclosure {
                outer: a, inner: b, ..
            }
            | Rule::AsymmetricEnclosure {
                outer: a, inner: b, ..
            }
            | Rule::MaxEnclosure {
                outer: a, inner: b, ..
            }
            | Rule::AdjacentEnclosure {
                outer: a, inner: b, ..
            }
            | Rule::NoncoincidentEnclosure {
                outer: a, inner: b, ..
            }
            | Rule::FullWidth { outer: a, inner: b }
            | Rule::MinExtension {
                layer: a,
                reference: b,
                ..
            }
            | Rule::GateCorner {
                layer: a,
                reference: b,
                ..
            }
            | Rule::MaxDistanceToTap {
                well: a, tap: b, ..
            }
            | Rule::MustContain {
                outer: a, inner: b, ..
            }
            | Rule::MustBeInside { inner: a, outer: b }
            | Rule::RegionDensity {
                layer: a,
                region: b,
                ..
            }
            | Rule::EdgeEnclosure {
                edges: a, outer: b, ..
            } => [Some(a), Some(b), None],
            Rule::MinimumCut {
                cut, wide, other, ..
            } => [Some(cut), Some(wide), Some(other)],
            Rule::CutAreaChange {
                pre, post, lower, ..
            } => [Some(pre), Some(post), Some(lower)],
            Rule::DfmScore { layer, outer, .. } => [Some(layer), outer, None],
            Rule::ViaRedundancy {
                cut, lower, upper, ..
            } => [Some(cut), Some(lower), Some(upper)],
            Rule::Angle { layer, .. }
            | Rule::MinInteriorAngle { layer, .. }
            | Rule::PolygonValidity { layer } => [layer, None, None],
            // Raw rows, never validated: nothing to forget.
            Rule::OffGrid { .. } | Rule::ViaStack { .. } => [None, None, None],
        }
    }
}

pub use crate::deck::rules::DRC_KINDS as KINDS;
