//! The rule set: one [`Rule`] per deck row, the deck parser, and the driver.

use crate::drc::rules::{area, edge, grid, overlay, patterning, presence, spacing, via, width};
use crate::drc::{DrcError, Scratch};
use crate::report::{record_run, LimitSense, Outcome, RuleRun, Violations};
use crate::topology::NetTable;
use gpurify_geom::{Dbu, DbuArea, GeometryStore, LayerId};
use gpurify_ingest::deck::{Deck, ParamValue, RuleSpec};
use gpurify_ingest::{StrId, StrTable};

/// One configured DRC rule: a deck row, typed. [`RuleSet::from_deck`] builds
/// it and [`RuleSet::run`] checks it.
///
/// # What every variant keeps
///
/// - Lengths are in grid units (the layout's database unit), areas in square
///   grid units. Every limit is positive; `from_deck` refuses anything else.
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
/// - `shapes` names store rows ([`PolyId`](gpurify_geom::PolyId)). A hole of a
///   drawn polygon is a row of its own, so a pair may name a hole's ring.
/// - Every finding is a [`Severity::Error`](crate::report::Severity::Error).
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
    /// Limits: one legal size per rule. A layer with several legal cut
    /// classes (sky130 via.1b) cannot be checked, because a rule per size
    /// flags the cuts of every other size.
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
    /// Limits: the `MINSTEP` variants (`INSIDECORNER`, `OUTSIDECORNER`,
    /// `LENGTHSUM`, `MAXEDGES`, `MINADJACENTLENGTH`) are missing.
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
    /// `limit`, at the middle of the gap between their bounding boxes
    /// (`shapes` is the pair). `examined` counts every pair of rows whose boxes
    /// come within `limit`, pairs inside one figure included.
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
    /// One violation per offending pair, reported on layer `a`, at the middle
    /// of the gap between their bounding boxes. `examined` counts pairs whose
    /// boxes come within `limit`.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-047, DRC-065, DRC-073, ERC-C11. Rules: sky130 poly.4 and licon.11,
    /// GF180 DF.16, IHP NW.d and Gat.d, ASAP7 GATE.ACTIVE.S.4; `KLayout`
    /// `separation`.
    ///
    /// Limits: cross-layer spacing only; the via stack-count limit of DRC-065
    /// (LEF `MAXVIASTACK`) is missing.
    MinSpacingDiff {
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
    /// One violation per pair closer than `limit`, at the middle of the gap
    /// between their bounding boxes. `examined` counts the pairs.
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
    /// One violation per offending pair, at the middle of the gap between
    /// their bounding boxes. `examined` counts pairs whose run reaches
    /// `prl_threshold`.
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
    /// One violation per offending pair, at the middle of the gap between
    /// their bounding boxes. `examined` counts the pairs with facing corners.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-032. Rules: ASAP7 M1.S.6, GF180 MT30.3; `LEF58_CORNERSPACING`;
    /// `KLayout` `corners`.
    ///
    /// Limits: the `CONVEXCORNER`, `CONCAVECORNER` and `EXCEPTEOL` variants
    /// are missing. sky130 poly.4, which the manual measures between
    /// parallel edges only, over-reports when written with this kind.
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
    /// One violation per offending pair, at the middle of the gap between
    /// their bounding boxes. `examined` counts the pairs.
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
    /// DRC-017. Rules: sky130 m1.6, GF180 Mn.3, IHP M1.d, ASAP7 M1.A.1; LEF
    /// `AREA`; `KLayout` `with_area`. The `LEF58_AREA` exceptions
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
    /// One violation per offending inner polygon, reported on the `inner`
    /// layer. A rectangle is marked in the middle of the strip on its least
    /// enclosed side, any other shape at the centre of its bounding box.
    /// `shapes` is the inner row and the host's drawn row (`None` when
    /// unhosted). `examined` counts inner polygons.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-040, DRC-090, DRC-096. Rules: sky130 ct.4, m1.4 and licon.5a,
    /// GF180 CO.3, IHP M1.c and V1.c, ASAP7 V3.M4.EN.2; LEF `ENCLOSURE`;
    /// `KLayout` `enclosing`.
    MinEnclosure {
        /// The enclosing layer, merged; the deck's second argument.
        outer: LayerId,
        /// The enclosed layer; findings are reported on it.
        inner: LayerId,
        /// The smallest legal enclosure, in grid units; positive.
        limit: Dbu,
    },
    /// An `inner` shape without `min_one_side` of enclosure on both sides of
    /// at least one axis.
    ///
    /// Deck: `enclosure(inner, outer, opposite) >= len`, kind
    /// `asymmetric_enclosure`. Hosts are chosen as for [`Rule::MinEnclosure`].
    /// For a rectangular inner polygon, each side's enclosure is read straight
    /// out from that side to the nearest host edge facing it, and the rule
    /// measures `max(min(left, right), min(bottom, top))`. Write the every-side
    /// minimum as its own [`Rule::MinEnclosure`] row (sky130 m1.4 beside m1.5).
    ///
    /// One violation per offending inner polygon, on the `inner` layer, in the
    /// middle of the strip on the less enclosed side of the better axis.
    /// `shapes` is the inner row and the host's drawn row (`None` when
    /// unhosted). `examined` counts inner polygons.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-041, DRC-042. Rules: sky130 m1.5, via.5a and licon.5c, ASAP7
    /// V1.M1.EN.1, IHP M1.c1 and V1.c1; LEF `ENCLOSURE` with two overhangs.
    ///
    /// Limits: an inner polygon that is not a rectangle is held to
    /// `min_one_side` on every side, as [`Rule::MinEnclosure`] measures (fails
    /// closed). Only the two-opposite-sides form exists: one of two adjacent
    /// sides and end-cap-only enclosure cannot be written.
    AsymmetricEnclosure {
        /// The enclosing layer, merged; the deck's second argument.
        outer: LayerId,
        /// The enclosed layer; findings are reported on it.
        inner: LayerId,
        /// The enclosure both sides of one axis need, in grid units; positive.
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
    /// 0 (fails closed).
    MinExtension {
        /// The extending layer (A); findings are reported on it.
        layer: LayerId,
        /// The layer it must extend past (B).
        reference: LayerId,
        /// The smallest legal extension, in grid units; positive.
        limit: Dbu,
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
    /// Cuts in a large array closer than `limit`.
    ///
    /// Deck: `via_array_space(L; array: count) >= len`, kind
    /// `via_array_spacing`. Cuts are the rows on the layer, as drawn. A
    /// cluster is the cuts joined by gaps of at most `limit`, and it is an
    /// array when it has more than `array_threshold` cuts.
    ///
    /// One violation per pair inside an array closer than `limit`, at the
    /// middle of the gap between their bounding boxes. `examined` counts the
    /// pairs inside arrays. The layer is not validated, so this rule never
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
    /// Shapes that cannot be split onto `colors` masks with same-mask shapes
    /// at least `color_spacing` apart.
    ///
    /// Deck: `patterning(L; colors: count) >= len`, kind `multi_patterning`.
    /// Shapes that touch, overlap or nest print as one and are one figure;
    /// two figures closer than `color_spacing` conflict. Two masks are decided
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
    /// has a colouring rule.
    ///
    /// Limits: reports that no colouring exists, not its class (anchor path,
    /// self-conflict, same-mask spacing). Pre-coloured `MASK` shapes (DRC-102)
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
    /// Every shape on the layer, and every edge of an edge layer.
    ///
    /// Deck: `forbidden(L)`, kind `forbidden`. Write what is forbidden as the
    /// layer: `forbidden(licon and poly and (diff or tap))`, or a maximum area
    /// as `forbidden(L.with_area(> area))`. Shapes are reported as the store
    /// holds them, not merged.
    ///
    /// One violation per polygon, at a vertex of its outer ring, with
    /// `measured` its area (holes excluded) against a `limit` of 0. One per
    /// edge of an edge layer, at its midpoint, with `measured` its length,
    /// naming no shape (`PolyId(u32::MAX)`). `examined` counts polygons plus
    /// edges.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-006, DRC-018, DRC-050, DRC-074, DRC-090, DRC-095, ERC-A10. Rules:
    /// sky130 x.8, licon.6 and licon.17, IHP 3.2 and Cnt.j, GF180 PL.9;
    /// `KLayout` `overlapping`.
    ///
    /// Limits: device-family and seal-ring geometry is expressible through
    /// marker layers, but device-parameter rules and "one seal ring per chip,
    /// nothing outside it" are not.
    Forbidden {
        /// The layer, or edge layer, that must be empty.
        layer: LayerId,
    },
    /// An `outer` shape holding fewer than `min_count` `inner` shapes.
    ///
    /// Deck: `contains(outer, inner) >= count`, kind `must_contain`. Both
    /// layers are merged, so touching inner shapes count as one. An inner
    /// figure is held when one outer figure covers all of it; one across the
    /// outer's edge is held by none.
    ///
    /// One violation per outer figure holding too few, on the `outer` layer,
    /// at the centre of one of its rectangles. `measured` is the count held,
    /// `shapes.0` the lowest drawn outer row under the figure. `examined`
    /// counts outer figures.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-048, DRC-049, DRC-085. Rules: sky130 licon.4, licon.16 and
    /// nwell.4, IHP Cnt.g and Cnt.h, GF180 DN.3; `KLayout` `covering`.
    ///
    /// Limits: a minimum count only. An exact or maximum count (sky130 rpm.1g
    /// to rpm.1k, via.13) cannot be written.
    MustContain {
        /// The holding layer; findings are reported on it.
        outer: LayerId,
        /// The held layer.
        inner: LayerId,
        /// The fewest inner figures each outer figure must hold; at least 1.
        min_count: u32,
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
    /// Deck: `space(L; nets: same | different) >= len`, kind `net_spacing`.
    /// Nets are the extracted ones, joined through vias and other layers, so
    /// `L` must be a conductor. Pairs are shapes in different merged figures
    /// whose net relation is the one asked for.
    ///
    /// One violation per offending pair, at the middle of the gap between
    /// their bounding boxes. `examined` counts the pairs of the asked
    /// relation. Records [`Outcome::Refused`] when the run has no nets
    /// ([`RuleSet::run`]) or a shape on the layer carries no net.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-080. Rules: GF180 NW.2a, NW.2b and DN.2a, IHP NW.b; LEF
    /// `SPACING SAMENET`; `KLayout` `nets` with `props_eq` or `props_ne`.
    NetSpacing {
        /// The conductor layer measured.
        layer: LayerId,
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
    /// (where a `width + 1` square fits in the merged layer), and to the first
    /// row's cell measured from the whole shapes. A thin tab of a wide plate
    /// is held to the first row only.
    ///
    /// One violation per pair, at its highest failing row, with `limit` that
    /// row's cell and `measured` the distance that row measured, at the
    /// middle of the gap between their bounding boxes. `examined` counts the
    /// pairs.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-025, DRC-026, DRC-027. Rules: IHP M1.b, M1.e and M1.f; LEF
    /// `SPACINGTABLE PARALLELRUNLENGTH`.
    ///
    /// Limits: the row is keyed on the wider shape only. LEF
    /// `SPACINGTABLE TWOWIDTHS` keys on both widths and cannot be written.
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
    /// One violation per offending pair, at the middle of the gap between
    /// their bounding boxes. `examined` counts pairs where either shape has a
    /// wide part.
    ///
    /// [Catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv):
    /// DRC-028. Rules: sky130 m1.3a; LEF `SPACING RANGE INFLUENCE`.
    ///
    /// Limits: equivalence with LEF `INFLUENCE` is unverified.
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
    /// Limits: the length of a whole feature cannot be measured, only of its
    /// edges, and edge layers cannot be extended (sky130 difftap.6).
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
    /// [`RuleSet::from_deck`] refuses a table that is not
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
}

/// Every DRC rule the deck configures, in deck order.
#[derive(Debug, Default)]
pub struct RuleSet {
    /// Each rule with its deck id, in deck order: the order of the
    /// [`RuleRun`] rows [`RuleSet::run`] produces. Ids are unique.
    pub rules: Vec<(StrId, Rule)>,
    /// The tables [`Rule::SpacingTable`] names.
    pub tables: Vec<SpacingTable>,
    /// The deck's first derived layer: it and every higher id are computed,
    /// and the layers below it are drawn. `None` when every layer is drawn,
    /// as in a rule set built in code. A [`Rule::Density`] or
    /// [`Rule::GlobalDensity`] without a boundary takes its die from the drawn
    /// layers, and [`Rule::OffGrid`] and an [`Rule::Angle`] without a layer
    /// check drawn rows only.
    pub first_derived: Option<LayerId>,
}

impl RuleSet {
    /// Builds one [`Rule`] per deck row whose kind is in [`KINDS`]. Other kinds
    /// belong to ERC and are stepped over; the engine refuses a kind neither
    /// domain spells.
    ///
    /// Area limits arrive as areas (`ParamValue::Area`).
    ///
    /// # Errors
    ///
    /// The first problem, in deck order:
    /// - [`DrcError::DuplicateRule`] when two rows of any domain share an id;
    /// - [`DrcError::WrongLayerCount`] when a row names too few or too many
    ///   layers;
    /// - [`DrcError::MissingParam`] or [`DrcError::WrongParamType`] when a
    ///   parameter is absent, of the wrong kind, or a count too large for its
    ///   field;
    /// - [`DrcError::NonPositiveLimit`] when a length, area, fraction or
    ///   required count is not positive (or a fraction is not finite);
    /// - [`DrcError::UnrepresentableAngle`] when an allowed angle is not a
    ///   multiple of 45 degrees;
    /// - [`DrcError::BadTable`] when a spacing table fails
    ///   [`SpacingTable::is_valid`].
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
        let length = |spec: &RuleSpec, param| -> Result<Dbu, DrcError> {
            let ParamValue::Length(limit) = value(spec, param)? else {
                return Err(wrong_type(spec, param));
            };
            if limit.raw() <= 0 {
                return Err(DrcError::NonPositiveLimit {
                    rule: name_of(spec.id),
                    limit: limit.raw(),
                });
            }
            Ok(limit)
        };
        let area_limit = |spec: &RuleSpec, param| match value(spec, param)? {
            ParamValue::Area(area) if area.raw() > 0 => Ok(area),
            ParamValue::Area(area) => Err(DrcError::NonPositiveLimit {
                rule: name_of(spec.id),
                limit: i64::try_from(area.raw()).unwrap_or(i64::MIN),
            }),
            _ => Err(wrong_type(spec, param)),
        };
        let ratio = |spec: &RuleSpec, param| -> Result<f64, DrcError> {
            let ParamValue::Ratio(limit) = value(spec, param)? else {
                return Err(wrong_type(spec, param));
            };
            // `!(x > 0)` also rejects NaN, which would compare clean everywhere.
            if !(limit > 0.0) || !limit.is_finite() {
                #[allow(clippy::cast_possible_truncation, reason = "shown to a human only")]
                let shown = limit as i64;
                return Err(DrcError::NonPositiveLimit {
                    rule: name_of(spec.id),
                    limit: shown,
                });
            }
            Ok(limit)
        };
        let count = |spec: &RuleSpec, param, ceiling: u32| -> Result<u32, DrcError> {
            match value(spec, param)? {
                ParamValue::Count(found) if found <= ceiling => Ok(found),
                _ => Err(wrong_type(spec, param)),
            }
        };
        let positive = |spec: &RuleSpec, found: u32| {
            if found == 0 {
                return Err(DrcError::NonPositiveLimit {
                    rule: name_of(spec.id),
                    limit: 0,
                });
            }
            Ok(found)
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
                "min_enclosure" => {
                    let (outer, inner) = two(spec)?;
                    Rule::MinEnclosure {
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
                    let min_count = positive(spec, count(spec, "min_count", u16::MAX.into())?)?;
                    Rule::RedundantVia {
                        layer,
                        min_count: u16::try_from(min_count).expect("checked against the ceiling"),
                        within: length(spec, "within")?,
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
                "multi_patterning" => {
                    let layer = one(spec)?;
                    let colors = positive(spec, count(spec, "colors", u8::MAX.into())?)?;
                    Rule::MultiPatterning {
                        layer,
                        colors: u8::try_from(colors).expect("checked against the ceiling"),
                        color_spacing: length(spec, "color_spacing")?,
                    }
                }
                "forbidden" => Rule::Forbidden { layer: one(spec)? },
                "must_contain" => {
                    let (outer, inner) = two(spec)?;
                    Rule::MustContain {
                        outer,
                        inner,
                        min_count: positive(spec, count(spec, "min_count", u32::MAX)?)?,
                    }
                }
                "must_be_inside" => {
                    let (inner, outer) = two(spec)?;
                    Rule::MustBeInside { inner, outer }
                }
                "net_spacing" => {
                    let layer = one(spec)?;
                    let ParamValue::Flag(same_net) = value(spec, "same_net")? else {
                        return Err(wrong_type(spec, "same_net"));
                    };
                    Rule::NetSpacing {
                        layer,
                        same_net,
                        limit: length(spec, "limit")?,
                    }
                }
                "spacing_table" => {
                    let layer = one(spec)?;
                    let lengths = |param: &'static str| -> Result<Vec<Dbu>, DrcError> {
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
                    let table = SpacingTable {
                        prl: lengths("prl")?,
                        width: lengths("width")?,
                        space: lengths("space")?,
                    };
                    if !table.is_valid() {
                        return Err(DrcError::BadTable(name_of(spec.id)));
                    }
                    set.tables.push(table);
                    Rule::SpacingTable {
                        layer,
                        table: u32::try_from(set.tables.len() - 1).expect("a deck has few tables"),
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
                other => {
                    assert!(
                        !KINDS.contains(&other),
                        "KINDS names {other} but it has no arm"
                    );
                    continue;
                }
            };
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
    /// [`Rule::NetSpacing`] layer holds, or when a [`Rule::SpacingTable`]
    /// names a table that is missing or fails [`SpacingTable::is_valid`].
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
            for layer in rule.layers().into_iter().flatten() {
                if last_use.len() <= layer.idx() {
                    last_use.resize(layer.idx() + 1, 0);
                }
                last_use[layer.idx()] = at;
            }
        }
        for (at, &(id, rule)) in self.rules.iter().enumerate() {
            let before = out.len();
            let (outcome, examined) = match rule {
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
                Rule::MinArea { layer, limit } => area::min_area(store, id, layer, limit, s, out),
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
                } => {
                    area::global_density(store, id, (layer, boundary, drawn), limit, sense, s, out)
                }
                Rule::MinEnclosure {
                    outer,
                    inner,
                    limit,
                } => overlay::enclosure(store, id, outer, inner, limit, false, s, out),
                Rule::AsymmetricEnclosure {
                    outer,
                    inner,
                    min_one_side,
                } => overlay::enclosure(store, id, outer, inner, min_one_side, true, s, out),
                Rule::MinExtension {
                    layer,
                    reference,
                    limit,
                } => overlay::min_extension(store, id, layer, reference, limit, s, out),
                Rule::Overlap { a, b, limit } => overlay::overlap(store, id, a, b, limit, s, out),
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
                Rule::MultiPatterning {
                    layer,
                    colors,
                    color_spacing,
                } => patterning::multi_patterning(store, id, layer, colors, color_spacing, s, out),
                Rule::Forbidden { layer } => presence::forbidden(store, id, layer, s, out),
                Rule::MustContain {
                    outer,
                    inner,
                    min_count,
                } => presence::must_contain(store, id, outer, inner, min_count, s, out),
                Rule::MustBeInside { inner, outer } => {
                    presence::must_be_inside(store, id, inner, outer, s, out)
                }
                Rule::NetSpacing {
                    layer,
                    same_net,
                    limit,
                } => match nets {
                    Some(nets) => {
                        spacing::net_spacing(store, nets, id, layer, same_net, limit, s, out)
                    }
                    None => (Outcome::Refused, 0),
                },
                Rule::SpacingTable { layer, table } => {
                    spacing::spacing_table(store, id, layer, &self.tables[table as usize], s, out)
                }
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
            };
            record_run(runs, out, before, id, outcome, examined);
            for layer in rule.layers().into_iter().flatten() {
                if last_use[layer.idx()] == at {
                    s.validated.forget(layer);
                }
            }
        }
    }
}

impl Rule {
    /// Every layer the rule reads.
    fn layers(&self) -> [Option<LayerId>; 2] {
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
            | Rule::RedundantVia { layer, .. }
            | Rule::ViaArraySpacing { layer, .. }
            | Rule::MultiPatterning { layer, .. }
            | Rule::Forbidden { layer }
            | Rule::NetSpacing { layer, .. }
            | Rule::SpacingTable { layer, .. }
            | Rule::AttachedWideSpacing { layer, .. }
            | Rule::EdgeMinLength { layer, .. } => [Some(layer), None],
            Rule::EdgeSpacing { a, b, .. } => [Some(a), b],
            Rule::Density {
                layer, boundary, ..
            }
            | Rule::GlobalDensity {
                layer, boundary, ..
            } => [Some(layer), boundary],
            Rule::MinSpacingDiff { a, b, .. }
            | Rule::Overlap { a, b, .. }
            | Rule::MinEnclosure {
                outer: a, inner: b, ..
            }
            | Rule::AsymmetricEnclosure {
                outer: a, inner: b, ..
            }
            | Rule::MinExtension {
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
            | Rule::EdgeEnclosure {
                edges: a, outer: b, ..
            } => [Some(a), Some(b)],
            Rule::Angle { layer, .. } => [layer, None],
            Rule::OffGrid { .. } => [None, None],
        }
    }
}

/// Every DRC rule kind, by the name a deck row resolves to (`min_width` for
/// `width(L) >= len`), in [`Rule`] variant order. Disjoint from
/// [`crate::erc::ruleset::KINDS`]. The engine refuses a deck row whose kind is
/// in neither ([`DrcError::UnknownKind`]); [`RuleSet::from_deck`] alone steps
/// over it.
pub const KINDS: [&str; 35] = [
    "min_width",
    "max_width",
    "cut_size",
    "min_edge_length",
    "notch",
    "min_spacing",
    "min_spacing_diff",
    "eol_spacing",
    "prl_spacing",
    "corner_to_corner",
    "wide_dependent_spacing",
    "min_area",
    "min_enclosed_area",
    "cheesing",
    "density",
    "global_density",
    "min_enclosure",
    "asymmetric_enclosure",
    "min_extension",
    "overlap",
    "max_distance_to_tap",
    "off_grid",
    "angle",
    "redundant_via",
    "via_array_spacing",
    "multi_patterning",
    "forbidden",
    "must_contain",
    "must_be_inside",
    "net_spacing",
    "spacing_table",
    "attached_wide_spacing",
    "edge_min_length",
    "edge_spacing",
    "edge_enclosure",
];
