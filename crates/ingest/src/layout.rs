//! GDSII reader: a record stream to one flat, layer-sorted `GeometryStore`.
//!
//! Data in: GDSII bytes (gzip or plain) and a deck's [`LayerTable`] mapping stream pairs to layers.
//! Data out: [`gds::Library::flatten`]'s store with deck-derived layers appended, and placed
//! labels. An inexact transform is an error, never rounded.
//!
//! Three steps, in order: [`read_gds_bytes`] loads and un-gzips the file,
//! [`gds::Library::parse`] reads the records with the hierarchy intact and
//! states the grid ([`gds::Library::grid`]), and [`gds::Library::flatten`]
//! places every shape in the root frame on the deck's layers. Coordinates stay
//! in the file's database units throughout; nothing is scaled.

use crate::deck::{DerivedOp, LayerTable};
use crate::provenance::{PlacedLabel, Provenance};
use gpurify_geom::boolean::{intersection_into, subtraction_into, union_into, BooleanError};
use gpurify_geom::derive::{
    covering_into, edge_boolean_into, edge_interacting_into, edge_part_into, edges_into,
    extents_into, holes_into, inside_into, interacting_into, merge_into, outside_into,
    overlapping_into, rectangles_into, sized_into, with_area_into, with_bbox_into,
    with_length_into, with_width_into, EdgeOp,
};
use gpurify_geom::ops::{point_in_ring, point_seg_dist2, Point, Seg};
use gpurify_geom::view::{validate_layer_into, PolygonRef, RingRef, ValidatedLayer};
use gpurify_geom::Dbu;
use gpurify_geom::GeometryStore;
use gpurify_geom::LayerId;
use gpurify_geom::{Bbox, StrTable};

/// Why a layout could not be read. Every variant is a refusal: approximating a
/// transform moves geometry and moves verdicts.
#[derive(Debug, Clone, thiserror::Error)]
pub enum LayoutError {
    /// The bytes, after any gunzip, do not open with a GDSII `HEADER` record
    /// (OASIS is not read).
    #[error("unrecognised file format")]
    UnknownFormat,
    /// The stream ends inside a record or before `ENDLIB`, a record's length
    /// is under 4 or odd, a payload is shorter than its type needs, or a
    /// structure is still open at `ENDLIB`. Carries the record's byte offset.
    #[error("truncated record at byte {0}")]
    Truncated(usize),
    /// A record outside the reader's subset or out of place (an element
    /// outside a structure, a nested `BGNSTR`), or an element missing what it
    /// needs: no `LAYER`/`DATATYPE`/`XY`, a boundary under three vertices, a
    /// `TEXT` without exactly one point, a reference without its name or
    /// points, a `PATH` of odd or non-positive `WIDTH` or a `PATHTYPE` other
    /// than 0, 2 or 4. Carries the record type (or the element's) and its
    /// byte offset.
    #[error("unsupported record type {0:#06x} at byte {1}")]
    UnsupportedRecord(u16, usize),
    /// A placed vertex or label lies outside `±2^40` database units
    /// ([`gpurify_geom::MAX_ABS_DBU`]) once its placements are composed.
    #[error("coordinate {0} exceeds the representable range")]
    CoordinateOutOfRange(i64),
    /// A placement that would move geometry off the integer grid or overflow:
    /// absolute `STRANS` magnification or angle, a magnification that is not
    /// a whole number from 1 to 10^6, an angle not a multiple of 90°, an
    /// `AREF` whose pitch does not divide exactly or with a zero count, or
    /// composed transforms overflowing `i64`. Also a `PATH` with a diagonal or
    /// zero-length segment or a vertex that turns back on itself.
    #[error("instance transform is not representable exactly")]
    UnsupportedTransform,
    /// An `SREF` or `AREF` names a structure the library does not define.
    #[error("cell {0} is referenced but not defined")]
    MissingCell(String),
    /// A structure reaches itself again through its references, whether a
    /// root reaches it or not (a library whose every structure is referenced
    /// has such a cycle).
    #[error("cell hierarchy contains a cycle through {0}")]
    CyclicHierarchy(String),
    /// A layout that would flatten to more than [`MAX_FLAT_POLYGONS`] polygons,
    /// counted from the hierarchy before anything is expanded.
    #[error(
        "the layout flattens to {0} polygons, over the {MAX_FLAT_POLYGONS} a flat run \
         holds; GPurify flattens every placement and array"
    )]
    TooManyPolygons(u64),
    /// Under [`LabelDepth::All`], a layout that would place more than
    /// [`MAX_FLAT_POLYGONS`] labels, every cell's texts once per placement,
    /// counted from the hierarchy before anything is expanded. Labels are
    /// held to the polygons' cap.
    #[error(
        "the layout places {0} labels, over the {MAX_FLAT_POLYGONS} a flat run \
         holds; every cell's labels were asked for, once per placement"
    )]
    TooManyLabels(u64),
    /// A placement chain deeper than [`MAX_HIERARCHY_DEPTH`] levels, refused
    /// rather than walked: flattening recurses once per level.
    #[error("cell hierarchy is deeper than {MAX_HIERARCHY_DEPTH} levels at {0}")]
    HierarchyTooDeep(String),
    /// A shape or text on a stream pair the deck neither declares nor ignores,
    /// under [`UnknownLayers::Reject`].
    #[error(
        "layer {0}/{1} is in neither the deck's layer table nor its ignore list \
         (`ignore gds({0}, {1})`)"
    )]
    UnknownLayer(u16, u16),
    /// Without `UNITS`, no length in the deck can be converted to the layout's grid.
    #[error("the layout has no UNITS record, so its database unit is unknown")]
    NoUnits,
    /// Every length is measured on an integer grid of database units per micrometre.
    #[error("a database unit of {0:e} m is not a whole number of units per micrometre")]
    UnsupportedUnits(f64),
    /// A derived layer's computation failed: usually an operand holding a
    /// ring that is not simple and rectilinear (a diagonal edge, a
    /// self-crossing), or sizing past the coordinate range.
    #[error("derived layer {0:?} could not be computed: {1}")]
    Derived(gpurify_geom::LayerId, BooleanError),
    /// The file could not be read or un-gzipped.
    #[error("io: {0}")]
    Io(String),
}

/// The deepest placement chain a layout may have, root included.
///
/// Flattening recurses once per level, so without a cap a deep enough chain
/// would overflow the stack instead of returning an error. Real layouts nest
/// tens of levels; 1024 leaves room for any of them and stays well inside a
/// test thread's 2 MiB stack.
pub const MAX_HIERARCHY_DEPTH: u32 = 1024;

/// The most polygons a layout may flatten to.
///
/// `GPurify` checks a flat copy of the layout, so a 32767 × 32767 array of a
/// cell is about 10⁹ polygons per shape in it: hours of expansion and more
/// memory than any machine, before the polygon ids (`u32`) overflow. The count
/// is taken from the hierarchy first, and a layout over the cap is refused
/// before anything is expanded. 2²⁸ polygons is about 20 GB of flat geometry.
// ponytail: a flat cap; checking hierarchically, without flattening, is the
// upgrade that lifts it.
pub const MAX_FLAT_POLYGONS: u64 = 1 << 28;

/// How to treat geometry on a stream pair the deck neither declares nor
/// ignores. A pair listed with `ignore gds(L, D)` is dropped either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownLayers {
    /// Refuse the layout. What a signoff run uses.
    Reject,
    /// Drop the shape or label, uncounted. Not for signoff: what is dropped
    /// is checked by no rule.
    Drop,
}

/// Which cells' `TEXT` elements are placed as labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelDepth {
    /// Root cells only. A sub-cell's text names a net of that sub-cell (`d`,
    /// `sd_0`), not of the design, and two of them on one flattened net are a
    /// conflict nobody drew. Calibre's `TEXT DEPTH PRIMARY` default.
    Top,
    /// Every cell, transformed into the root frame.
    All,
}

/// A GDSII file's bytes, gunzipped when the file is gzip (every member of a
/// multi-member gzip, so a concatenated file is never read partially).
///
/// # Errors
///
/// [`LayoutError::Io`] when the file cannot be read or decompressed, and
/// [`LayoutError::UnknownFormat`] when the bytes do not open with a GDSII
/// `HEADER` record.
pub fn read_gds_bytes(path: &std::path::Path) -> Result<Vec<u8>, LayoutError> {
    use std::io::Read;
    let io = |e: std::io::Error| LayoutError::Io(e.to_string());

    let raw = std::fs::read(path).map_err(io)?;
    let bytes = if raw.starts_with(&[0x1f, 0x8b]) {
        // `MultiGzDecoder`: `GzDecoder` stops after the first member, a silently partial layout.
        let mut bytes = Vec::new();
        flate2::read::MultiGzDecoder::new(&raw[..])
            .read_to_end(&mut bytes)
            .map_err(io)?;
        bytes
    } else {
        raw
    };
    // A GDSII `HEADER` record: length 6, type 0, data type 2.
    if bytes.starts_with(&[0x00, 0x06, 0x00, 0x02]) {
        Ok(bytes)
    } else {
        Err(LayoutError::UnknownFormat)
    }
}

/// Compute `deck`'s derived layers into a store built in memory from its base
/// layers, as [`gds::Library::flatten`] does after reading a stream. `deck` is
/// anything holding the layer table: a [`Deck`](crate::deck::Deck), or a deck
/// compiled from one.
/// `with_text` reads `provenance`'s placed labels; bind them afterwards with
/// [`Provenance::resolve_labels`].
///
/// `store` must have been finished with the table's
/// [`len`](LayerTable::len) layers and hold shapes on drawn layers only;
/// derived layers are appended in id order.
///
/// # Errors
///
/// [`LayoutError::Derived`] naming the first derived layer that could not be
/// computed.
///
/// # Panics
///
/// When `store` has fewer layers than the deck, or already holds shapes on a
/// derived layer.
pub fn derive_layers<D: AsRef<LayerTable> + ?Sized>(
    store: &mut GeometryStore,
    deck: &D,
    provenance: &Provenance,
    strings: &StrTable,
) -> Result<(), LayoutError> {
    derive_layers_into(store, deck.as_ref(), &provenance.placed, strings)
}

/// Compute every deck-derived layer and append it to the store, in id order.
/// Operands only name lower ids, so one forward pass suffices. `labels` are
/// the placed texts, named in `strings`, that `with_text` reads.
fn derive_layers_into(
    store: &mut GeometryStore,
    layers: &LayerTable,
    labels: &[PlacedLabel],
    strings: &StrTable,
) -> Result<(), LayoutError> {
    let mut folded = ValidatedLayer::default();
    let mut operand = ValidatedLayer::default();
    let mut combined = ValidatedLayer::default();
    let mut raw = ValidatedLayer::default();
    let (mut edges, mut edges_out) = (Vec::<Seg>::new(), Vec::<Seg>::new());
    let (mut xs, mut ys) = (Vec::<Dbu>::new(), Vec::<Dbu>::new());
    let (mut start, mut len) = (Vec::<u32>::new(), Vec::<u32>::new());

    for (layer, op, operands) in layers.derived() {
        let blame = |why: BooleanError| LayoutError::Derived(*layer, why);
        // An operand's polygons, merged: selections and sizing read whole shapes.
        let mut merged = |id: LayerId, out: &mut ValidatedLayer| {
            validate_layer_into(store, id, &mut raw)?;
            merge_into(&raw, out)
        };

        if layers.is_edges(*layer) {
            let receiver = operands[0];
            match *op {
                DerivedOp::Edges => {
                    merged(receiver, &mut folded).map_err(blame)?;
                    edges_into(&folded, &mut edges);
                }
                DerivedOp::And | DerivedOp::Or | DerivedOp::Not => {
                    let how = match op {
                        DerivedOp::And => EdgeOp::And,
                        DerivedOp::Or => EdgeOp::Or,
                        _ => EdgeOp::Not,
                    };
                    edges.clear();
                    edges.extend_from_slice(store.edges_on_layer(receiver));
                    for &next in &operands[1..] {
                        edge_boolean_into(&edges, store.edges_on_layer(next), how, &mut edges_out);
                        std::mem::swap(&mut edges, &mut edges_out);
                    }
                }
                DerivedOp::Interacting(keep) => {
                    merged(operands[1], &mut operand).map_err(blame)?;
                    edge_interacting_into(
                        store.edges_on_layer(receiver),
                        &operand,
                        keep,
                        &mut edges,
                    );
                }
                DerivedOp::Part(inside) => {
                    merged(operands[1], &mut operand).map_err(blame)?;
                    edge_part_into(store.edges_on_layer(receiver), &operand, inside, &mut edges);
                }
                DerivedOp::WithLength(lo, hi) => {
                    with_length_into(store.edges_on_layer(receiver), lo..=hi, &mut edges);
                }
                DerivedOp::Oriented(vertical) => {
                    edges.clear();
                    edges.extend(
                        store
                            .edges_on_layer(receiver)
                            .iter()
                            .filter(|e| (e.a.x == e.b.x) == vertical)
                            .copied(),
                    );
                }
                _ => unreachable!("the parser gives an edge result only to edge operations"),
            }
            store.append_edges(*layer, &edges);
            continue;
        }

        match *op {
            DerivedOp::And | DerivedOp::Or | DerivedOp::Not => {
                validate_layer_into(store, operands[0], &mut folded)
                    .map_err(|why| blame(why.into()))?;
                for &next in &operands[1..] {
                    validate_layer_into(store, next, &mut operand)
                        .map_err(|why| blame(why.into()))?;
                    match op {
                        DerivedOp::And => intersection_into(&folded, &operand, &mut combined),
                        DerivedOp::Or => union_into(&folded, &operand, &mut combined),
                        _ => subtraction_into(&folded, &operand, &mut combined),
                    }
                    .map_err(blame)?;
                    std::mem::swap(&mut folded, &mut combined);
                }
            }
            _ => {
                merged(operands[0], &mut operand).map_err(blame)?;
                // `with_text` reads the texts on its layer argument, not its shapes.
                if let (Some(&other), false) =
                    (operands.get(1), matches!(op, DerivedOp::WithText { .. }))
                {
                    merged(other, &mut combined).map_err(blame)?;
                }
                let (a, b) = (&operand, &combined);
                match *op {
                    DerivedOp::Sized(by) => sized_into(a, by, &mut folded),
                    DerivedOp::Interacting(keep) => {
                        interacting_into(a, b, keep, &mut folded);
                        Ok(())
                    }
                    DerivedOp::Inside => inside_into(a, b, &mut folded),
                    DerivedOp::Outside => outside_into(a, b, &mut folded),
                    DerivedOp::Overlapping => overlapping_into(a, b, true, &mut folded),
                    DerivedOp::Covering(keep) => covering_into(a, b, keep, &mut folded),
                    DerivedOp::Holes => holes_into(a, &mut folded),
                    DerivedOp::Extents => extents_into(a, &mut folded),
                    DerivedOp::WithArea(lo, hi) => {
                        with_area_into(a, lo..=hi, &mut folded);
                        Ok(())
                    }
                    DerivedOp::WithWidth(lo, hi) => {
                        with_width_into(a, lo..=hi, &mut folded);
                        Ok(())
                    }
                    DerivedOp::Rectangles { square, keep } => {
                        rectangles_into(a, square, keep, &mut folded);
                        Ok(())
                    }
                    DerivedOp::WithBbox { longer, lo, hi } => {
                        with_bbox_into(a, longer, lo..=hi, &mut folded);
                        Ok(())
                    }
                    DerivedOp::WithText { keep, text } => {
                        let pattern = layers.text(text);
                        let matching: Vec<Point> = labels
                            .iter()
                            .filter(|label| {
                                label.layer == operands[1]
                                    && glob_matches(pattern, strings.resolve(label.name))
                            })
                            .map(|label| label.at)
                            .collect();
                        // ponytail: every matching text against every shape; index the
                        // points by x if a layer carries thousands of texts.
                        let flags: Vec<bool> = (0..crate::narrow(a.len()))
                            .map(|idx| {
                                let poly = a.get(idx);
                                let holds = matching.iter().any(|&p| {
                                    poly.bbox().contains(Bbox::point(p.x, p.y))
                                        && on_material(poly, p)
                                });
                                holds == keep
                            })
                            .collect();
                        a.select_into(&flags, &mut folded);
                        Ok(())
                    }
                    _ => unreachable!("the parser gives an edge operation an edge result"),
                }
                .map_err(blame)?;
            }
        }

        xs.clear();
        ys.clear();
        start.clear();
        len.clear();
        for polygon in 0..crate::narrow(folded.len()) {
            let polygon = folded.get(polygon);
            // Outer first, then its holes: `validate_layer_into`'s ring order.
            for ring in std::iter::once(polygon.outer()).chain(polygon.holes()) {
                let (ring_xs, ring_ys) = ring.coords();
                start.push(crate::narrow(xs.len()));
                len.push(crate::narrow(ring_xs.len()));
                xs.extend_from_slice(ring_xs);
                ys.extend_from_slice(ring_ys);
            }
        }
        store.append_layer(*layer, &xs, &ys, &start, &len);
    }
    Ok(())
}

/// Whether `p` lies on the polygon's material, its boundary included.
fn on_material(poly: PolygonRef<'_>, p: Point) -> bool {
    let on_ring = |ring: RingRef<'_>| {
        let (xs, ys) = ring.coords();
        (0..xs.len()).any(|i| {
            let j = (i + 1) % xs.len();
            let edge = Seg {
                a: Point { x: xs[i], y: ys[i] },
                b: Point { x: xs[j], y: ys[j] },
            };
            point_seg_dist2(p, edge).raw() == 0
        })
    };
    point_in_ring(poly.outer(), p)
        && poly
            .holes()
            .all(|hole| !point_in_ring(hole, p) || on_ring(hole))
}

/// A glob over the whole text: `*` matches any run, `?` one character, and
/// every other character itself, case included. The deck's text patterns
/// (`with_text`, `lvs connect_implicit`) match so.
pub fn glob_matches(pattern: &str, text: &str) -> bool {
    let (pattern, text): (Vec<char>, Vec<char>) =
        (pattern.chars().collect(), text.chars().collect());
    let (mut p, mut t) = (0, 0);
    // The last `*` and the text position it was tried at, to widen on a miss.
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        match pattern.get(p) {
            Some('*') => {
                star = Some((p, t));
                p += 1;
            }
            Some(&c) if c == '?' || c == text[t] => {
                p += 1;
                t += 1;
            }
            _ => match star {
                Some((at, from)) => {
                    p = at + 1;
                    t = from + 1;
                    star = Some((at, from + 1));
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|&c| c == '*')
}

/// GDSII: a record stream of `(length, tag, payload)`.
pub mod gds {
    use super::{
        LabelDepth, LayerTable, LayoutError, UnknownLayers, MAX_FLAT_POLYGONS, MAX_HIERARCHY_DEPTH,
    };
    use crate::narrow;
    use crate::provenance::Provenance;
    use fearless_simd::{dispatch, i64x4, mask64x4, prelude::*, Level};
    use gpurify_geom::boolean::canonical_rings_into;
    use gpurify_geom::{Dbu, Grid, LayerId, MAX_ABS_DBU};
    use gpurify_geom::{GeometryStore, GeometryStoreBuilder};
    use gpurify_geom::{StrId, StrTable};

    // Record tags as on the wire: `(record type << 8) | data type`.
    const HEADER: u16 = 0x0002;
    const BGNLIB: u16 = 0x0102;
    const LIBNAME: u16 = 0x0206;
    const UNITS: u16 = 0x0305;
    const ENDLIB: u16 = 0x0400;
    const BGNSTR: u16 = 0x0502;
    const STRNAME: u16 = 0x0606;
    const ENDSTR: u16 = 0x0700;
    const BOUNDARY: u16 = 0x0800;
    const PATH: u16 = 0x0900;
    const SREF: u16 = 0x0A00;
    const AREF: u16 = 0x0B00;
    const TEXT: u16 = 0x0C00;
    const LAYER: u16 = 0x0D02;
    const DATATYPE: u16 = 0x0E02;
    const WIDTH: u16 = 0x0F03;
    const XY: u16 = 0x1003;
    const ENDEL: u16 = 0x1100;
    const SNAME: u16 = 0x1206;
    const COLROW: u16 = 0x1302;
    const NODE: u16 = 0x1500;
    const TEXTTYPE: u16 = 0x1602;
    const PRESENTATION: u16 = 0x1701;
    const STRING: u16 = 0x1906;
    const STRANS: u16 = 0x1A01;
    const MAG: u16 = 0x1B05;
    const ANGLE: u16 = 0x1C05;
    const REFLIBS: u16 = 0x1F06;
    const FONTS: u16 = 0x2006;
    const GENERATIONS: u16 = 0x2202;
    const ATTRTABLE: u16 = 0x2306;
    const PATHTYPE: u16 = 0x2102;
    const ELFLAGS: u16 = 0x2601;
    const PROPATTR: u16 = 0x2B02;
    const PROPVALUE: u16 = 0x2C06;
    const BOX: u16 = 0x2D00;
    const BOXTYPE: u16 = 0x2E02;
    const PLEX: u16 = 0x2F03;
    const BGNEXTN: u16 = 0x3003;
    const ENDEXTN: u16 = 0x3103;
    const FORMAT: u16 = 0x3602;
    const MASK: u16 = 0x3706;
    const ENDMASKS: u16 = 0x3800;
    const LIBDIRSIZE: u16 = 0x3902;
    const SRFNAME: u16 = 0x3A06;
    const LIBSECUR: u16 = 0x3B02;

    /// `STRANS` bit 0 (MSB first): reflect about the X axis before rotating.
    const STRANS_REFLECT: u16 = 0x8000;
    /// `STRANS` bits 13-14: absolute magnification/angle, which do not compose. Refused.
    const STRANS_ABSOLUTE: u16 = 0x0006;

    /// One geometry element as the file states it, before any transform.
    struct Elem {
        layer: u16,
        datatype: u16,
        vert_start: u32,
        vert_len: u32,
    }

    /// One `SREF` or `AREF`; an `SREF` is the 1×1 array with zero steps.
    struct Ref {
        cell: StrId,
        /// Index into `Library::cells`, resolved once parsing is done.
        child: u32,
        /// The child's own transform; its translation is the array origin.
        place: Xform,
        col_step: (i64, i64),
        row_step: (i64, i64),
        cols: u32,
        rows: u32,
    }

    /// One `TEXT` as the file states it, before any transform.
    struct Text {
        layer: u16,
        texttype: u16,
        x: i64,
        y: i64,
        string: StrId,
    }

    /// One structure, as ranges into the library's element, reference and text lists.
    struct Cell {
        name: StrId,
        elem_start: u32,
        elem_end: u32,
        ref_start: u32,
        ref_end: u32,
        text_start: u32,
        text_end: u32,
    }

    /// An exact instance transform: integral magnification, optional reflection
    /// about X, a quarter turn, a translation. Closed under composition since
    /// `F·R_q = R_{-q}·F`.
    #[derive(Clone, Copy)]
    struct Xform {
        mag: i64,
        flip: bool,
        quadrant: u8,
        dx: i64,
        dy: i64,
    }

    impl Xform {
        const IDENTITY: Self = Self {
            mag: 1,
            flip: false,
            quadrant: 0,
            dx: 0,
            dy: 0,
        };

        /// The linear part `(a, b, c, e)` of `x' = a·x + b·y`, `y' = c·x + e·y`.
        fn linear(self) -> (i64, i64, i64, i64) {
            let (a, b, c, e) = match self.quadrant & 3 {
                0 => (1, 0, 0, 1),
                1 => (0, -1, 1, 0),
                2 => (-1, 0, 0, -1),
                _ => (0, 1, -1, 0),
            };
            // Reflection runs before rotation: the second column negated.
            let s = if self.flip { -1 } else { 1 };
            (
                self.mag * a,
                self.mag * b * s,
                self.mag * c,
                self.mag * e * s,
            )
        }

        /// `self` applied to a point. `None` on i64 overflow.
        fn apply(self, x: i64, y: i64) -> Option<(i64, i64)> {
            let (a, b, c, e) = self.linear();
            let x2 = a
                .checked_mul(x)?
                .checked_add(b.checked_mul(y)?)?
                .checked_add(self.dx)?;
            let y2 = c
                .checked_mul(x)?
                .checked_add(e.checked_mul(y)?)?
                .checked_add(self.dy)?;
            Some((x2, y2))
        }

        /// `self` applied after `child`. `None` on i64 overflow: nested magnifications
        /// multiply, and a wrapped value could pass the coordinate bound.
        fn compose(self, child: Self) -> Option<Self> {
            let (dx, dy) = self.apply(child.dx, child.dy)?;
            Some(Self {
                mag: self.mag.checked_mul(child.mag)?,
                flip: self.flip ^ child.flip,
                // A reflecting parent reverses the child's turn as it commutes past it.
                quadrant: if self.flip {
                    (self.quadrant + 4 - (child.quadrant & 3)) & 3
                } else {
                    (self.quadrant + child.quadrant) & 3
                },
                dx,
                dy,
            })
        }
    }

    /// A parsed library: hierarchy intact, nothing mapped to a deck yet.
    ///
    /// [`Library::parse`] interns every layout string (cell names, `TEXT`s,
    /// `PROPVALUE`s) in file order; [`Library::flatten`] interns nothing.
    ///
    /// Shapes are already normalised as parsed: every `BOUNDARY` and `BOX` is
    /// one counter-clockwise outer ring without its repeated closing point, a
    /// keyhole boundary (how GDSII writes a hole) is split into its outer and
    /// clockwise holes, and every `PATH` is stroked into its outline, exactly
    /// (an outline that revisits a vertex, a path running back over itself,
    /// is split as a keyhole is, into the region it sweeps).
    /// Rings are not otherwise validated here: a diagonal or self-crossing
    /// boundary is refused where a check or derived layer reads its layer.
    #[derive(Default)]
    pub struct Library {
        /// The `UNITS` record's second value; `None` until one is read.
        metres_per_dbu: Option<f64>,
        cells: Vec<Cell>,
        elems: Vec<Elem>,
        refs: Vec<Ref>,
        texts: Vec<Text>,
        xs: Vec<i64>,
        ys: Vec<i64>,
    }

    /// One `(tag, payload)` record and the offset just past it.
    fn record(bytes: &[u8], at: usize) -> Result<(u16, &[u8], usize), LayoutError> {
        let head = bytes.get(at..at + 4).ok_or(LayoutError::Truncated(at))?;
        let len = usize::from(u16::from_be_bytes([head[0], head[1]]));
        let tag = u16::from_be_bytes([head[2], head[3]]);
        // Shorter than its header would loop forever; odd is not GDSII.
        if len < 4 || len % 2 != 0 {
            return Err(LayoutError::Truncated(at));
        }
        let payload = bytes
            .get(at + 4..at + len)
            .ok_or(LayoutError::Truncated(at))?;
        Ok((tag, payload, at + len))
    }

    /// A two-byte integer payload.
    fn word(payload: &[u8], at: usize) -> Result<u16, LayoutError> {
        match payload {
            [hi, lo, ..] => Ok(u16::from_be_bytes([*hi, *lo])),
            _ => Err(LayoutError::Truncated(at)),
        }
    }

    /// A four-byte signed integer payload.
    fn long(payload: &[u8], at: usize) -> Result<i64, LayoutError> {
        match payload {
            [a, b, c, d, ..] => Ok(i64::from(i32::from_be_bytes([*a, *b, *c, *d]))),
            _ => Err(LayoutError::Truncated(at)),
        }
    }

    /// An ASCII payload, with the NUL the format pads odd names with removed.
    fn ascii(payload: &[u8]) -> std::borrow::Cow<'_, str> {
        let end = payload.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
        String::from_utf8_lossy(&payload[..end])
    }

    /// An eight-byte GDSII real: `± fraction / 2^56 · 16^(exponent − 64)`.
    /// The 56-bit fraction loses bits in f64; callers accept only values exact in f64.
    #[expect(clippy::cast_precision_loss)]
    fn real(payload: &[u8], at: usize) -> Result<f64, LayoutError> {
        const SCALE: f64 = 72_057_594_037_927_936.0; // 2^56
        let bytes: [u8; 8] = payload
            .get(..8)
            .and_then(|s| s.try_into().ok())
            .ok_or(LayoutError::Truncated(at))?;
        let sign = if bytes[0] & 0x80 == 0 { 1.0 } else { -1.0 };
        let exponent = i32::from(bytes[0] & 0x7f) - 64;
        let fraction = u64::from_be_bytes([
            0, bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        Ok(sign * (fraction as f64) / SCALE * 16f64.powi(exponent))
    }

    /// One 8-byte `XY` point.
    fn xy(p: &[u8]) -> (i64, i64) {
        (
            i64::from(i32::from_be_bytes([p[0], p[1], p[2], p[3]])),
            i64::from(i32::from_be_bytes([p[4], p[5], p[6], p[7]])),
        )
    }

    /// Append an `XY` payload to the coordinate columns.
    fn points(
        xs: &mut Vec<i64>,
        ys: &mut Vec<i64>,
        payload: &[u8],
        at: usize,
    ) -> Result<(), LayoutError> {
        if !payload.len().is_multiple_of(8) {
            return Err(LayoutError::Truncated(at));
        }
        for (x, y) in payload.as_chunks::<8>().0.iter().map(|p| xy(p)) {
            xs.push(x);
            ys.push(y);
        }
        Ok(())
    }

    impl Library {
        /// The layout's grid, from its `UNITS` record: how many database units
        /// make one micrometre.
        ///
        /// # Errors
        ///
        /// [`LayoutError::NoUnits`] when the stream has no `UNITS` record, and
        /// [`LayoutError::UnsupportedUnits`] when its database unit is not a
        /// whole fraction of a micrometre (within the 1e-9 relative error an
        /// eight-byte GDSII real carries, so a written 1 nm reads as exactly 1000).
        pub fn grid(&self) -> Result<Grid, LayoutError> {
            let metres = self.metres_per_dbu.ok_or(LayoutError::NoUnits)?;
            let per_um = 1e-6 / metres;
            let whole = per_um.round();
            // `!(a <= b)` refuses NaN and infinities with the misfits.
            if !(whole >= 1.0 && (per_um - whole).abs() <= whole * 1e-9 && whole < 1e15) {
                return Err(LayoutError::UnsupportedUnits(metres));
            }
            #[expect(
                clippy::cast_possible_truncation,
                reason = "whole is a positive integer below 1e15"
            )]
            let per_um = whole as i64;
            Grid::new(per_um).map_err(|_| LayoutError::UnsupportedUnits(metres))
        }

        /// Reads the record stream in one pass. Every record is consumed,
        /// skipped, or refused; bytes after `ENDLIB` (block padding) are ignored.
        /// Glyph records on a `TEXT` (font, size, angle) and properties are
        /// accepted and discarded.
        ///
        /// # Errors
        ///
        /// [`LayoutError::Truncated`], [`LayoutError::UnsupportedRecord`] or
        /// [`LayoutError::UnsupportedTransform`] at the first record that cannot
        /// be read exactly, and [`LayoutError::MissingCell`] for a reference to
        /// an undefined structure. On error, `strings` may have gained names.
        pub fn parse(bytes: &[u8], strings: &mut StrTable) -> Result<Self, LayoutError> {
            let mut lib = Library::default();
            let mut stroke = Stroke::default();
            let mut open: Option<usize> = None;
            let mut at = 0usize;

            loop {
                let (tag, payload, next) = record(bytes, at)?;
                let in_cell = move || open.ok_or(LayoutError::UnsupportedRecord(tag, at));
                match tag {
                    ENDLIB => break,
                    // Coordinates stay database units; `UNITS` only names their size.
                    UNITS => {
                        let metres = payload.get(8..).ok_or(LayoutError::Truncated(at))?;
                        lib.metres_per_dbu = Some(real(metres, at)?);
                    }
                    HEADER | BGNLIB | LIBNAME | REFLIBS | FONTS | GENERATIONS | ATTRTABLE
                    | FORMAT | MASK | ENDMASKS | LIBDIRSIZE | SRFNAME | LIBSECUR => {}
                    BGNSTR => {
                        if open.is_some() {
                            return Err(LayoutError::UnsupportedRecord(tag, at));
                        }
                        open = Some(lib.cells.len());
                        lib.cells.push(Cell {
                            // Set by STRNAME; a structure without one is refused at ENDSTR.
                            name: StrId(u32::MAX),
                            elem_start: narrow(lib.elems.len()),
                            elem_end: narrow(lib.elems.len()),
                            ref_start: narrow(lib.refs.len()),
                            ref_end: narrow(lib.refs.len()),
                            text_start: narrow(lib.texts.len()),
                            text_end: narrow(lib.texts.len()),
                        });
                    }
                    STRNAME => {
                        let index = in_cell()?;
                        lib.cells[index].name = strings.intern(&ascii(payload));
                    }
                    ENDSTR => {
                        let index = in_cell()?;
                        open = None;
                        let cell = &mut lib.cells[index];
                        if cell.name == StrId(u32::MAX) {
                            return Err(LayoutError::UnsupportedRecord(BGNSTR, at));
                        }
                        cell.elem_end = narrow(lib.elems.len());
                        cell.ref_end = narrow(lib.refs.len());
                        cell.text_end = narrow(lib.texts.len());
                    }
                    BOUNDARY | BOX => {
                        in_cell()?;
                        at = boundary(&mut lib, strings, bytes, next, at, tag)?;
                        continue;
                    }
                    PATH => {
                        in_cell()?;
                        at = path(&mut lib, strings, &mut stroke, bytes, next, at)?;
                        continue;
                    }
                    SREF | AREF => {
                        in_cell()?;
                        at = reference(&mut lib, strings, bytes, next, at, tag == AREF)?;
                        continue;
                    }
                    TEXT => {
                        in_cell()?;
                        at = text(&mut lib, strings, bytes, next, at)?;
                        continue;
                    }
                    // A NODE has no shape and no name: nothing to record.
                    NODE => {
                        at = skip_element(bytes, next)?;
                        continue;
                    }
                    _ => return Err(LayoutError::UnsupportedRecord(tag, at)),
                }
                at = next;
            }

            if open.is_some() {
                return Err(LayoutError::Truncated(at));
            }

            // Resolve every reference to its cell index. Sorted by name, then index.
            let mut by_name: Vec<u32> = (0..narrow(lib.cells.len())).collect();
            by_name.sort_unstable_by_key(|&i| (lib.cells[i as usize].name, i));
            for r in &mut lib.refs {
                let found = by_name.binary_search_by_key(&r.cell, |&i| lib.cells[i as usize].name);
                r.child = match found {
                    Ok(at) => by_name[at],
                    Err(_) => {
                        return Err(LayoutError::MissingCell(strings.resolve(r.cell).to_owned()))
                    }
                };
            }
            debug_assert!(
                lib.xs.len() == lib.ys.len()
                    && lib.elems.iter().all(|e| {
                        e.vert_len >= 3
                            && e.vert_start as usize + e.vert_len as usize <= lib.xs.len()
                    }),
                "every element is a ring of at least three vertices inside the coordinate columns"
            );
            debug_assert!(
                lib.cells.iter().all(|c| {
                    c.elem_start <= c.elem_end
                        && c.elem_end as usize <= lib.elems.len()
                        && c.ref_start <= c.ref_end
                        && c.ref_end as usize <= lib.refs.len()
                        && c.text_start <= c.text_end
                        && c.text_end as usize <= lib.texts.len()
                }) && lib
                    .refs
                    .iter()
                    .all(|r| (r.child as usize) < lib.cells.len()),
                "every cell's ranges lie in the element, reference and text lists, and every \
                 reference names a cell"
            );
            Ok(lib)
        }
    }

    /// The records any element may carry. `Ok(Some(next))` is the `ENDEL`.
    ///
    /// `reference` does not route through this, so a property on an `SREF` stays a refusal.
    fn element_record(
        strings: &mut StrTable,
        tag: u16,
        payload: &[u8],
        at: usize,
        next: usize,
    ) -> Result<Option<usize>, LayoutError> {
        match tag {
            PROPATTR => {
                word(payload, at)?;
            }
            // Not stored; interned only because interning order is report order.
            PROPVALUE => {
                strings.intern(&ascii(payload));
            }
            ELFLAGS | PLEX => {}
            ENDEL => return Ok(Some(next)),
            _ => return Err(LayoutError::UnsupportedRecord(tag, at)),
        }
        Ok(None)
    }

    /// Consume a `TEXT` through its `ENDEL`. Returns the offset past it.
    ///
    /// `LAYER`, `TEXTTYPE`, one `XY` point and `STRING` are required and kept. The
    /// glyph records (`PRESENTATION`, `PATHTYPE`, `WIDTH`, `STRANS`, `MAG`, `ANGLE`)
    /// leave the point where it is, so they are accepted and discarded.
    fn text(
        lib: &mut Library,
        strings: &mut StrTable,
        bytes: &[u8],
        mut at: usize,
        start: usize,
    ) -> Result<usize, LayoutError> {
        let mut layer: Option<u16> = None;
        let mut texttype: Option<u16> = None;
        let mut point: Option<(i64, i64)> = None;
        let mut string: Option<StrId> = None;

        let end = loop {
            let (tag, payload, next) = record(bytes, at)?;
            match tag {
                LAYER => layer = Some(word(payload, at)?),
                TEXTTYPE => texttype = Some(word(payload, at)?),
                XY => {
                    if !payload.len().is_multiple_of(8) {
                        return Err(LayoutError::Truncated(at));
                    }
                    if payload.len() != 8 {
                        return Err(LayoutError::UnsupportedRecord(TEXT, start));
                    }
                    point = Some(xy(payload));
                }
                STRING => string = Some(strings.intern(&ascii(payload))),
                PRESENTATION | PATHTYPE | WIDTH | STRANS | MAG | ANGLE => {}
                _ => {
                    if let Some(end) = element_record(strings, tag, payload, at, next)? {
                        break end;
                    }
                }
            }
            at = next;
        };

        let (Some(layer), Some(texttype), Some((x, y)), Some(string)) =
            (layer, texttype, point, string)
        else {
            return Err(LayoutError::UnsupportedRecord(TEXT, start));
        };
        lib.texts.push(Text {
            layer,
            texttype,
            x,
            y,
            string,
        });
        Ok(end)
    }

    /// The fewest vertices a keyhole ring can have: outer 4, hole 4, slit ends revisited.
    const KEYHOLE_MIN_VERTS: usize = 10;

    /// Whether a ring revisits a vertex, which is how GDSII writes a hole. Sorts, so O(n log n).
    fn ring_revisits_a_vertex(xs: &[i64], ys: &[i64]) -> bool {
        if xs.len() < KEYHOLE_MIN_VERTS {
            return false;
        }
        let mut seen: Vec<(i64, i64)> = xs.iter().copied().zip(ys.iter().copied()).collect();
        seen.sort_unstable();
        seen.windows(2).any(|w| w[0] == w[1])
    }

    /// Whether two axis-parallel edges of a ring share a stretch of one line:
    /// the ring folds back over itself. A keyhole whose way back out runs on
    /// along the hole's side, past where the way in started, does so without
    /// revisiting a vertex (`sky130_fd_sc_hd`'s level shifters draw poly this
    /// way). Sorts, so O(n log n).
    fn ring_overlaps_itself(xs: &[i64], ys: &[i64]) -> bool {
        let n = xs.len();
        let (mut vertical, mut horizontal) = (Vec::new(), Vec::new());
        for i in 0..n {
            let j = if i + 1 == n { 0 } else { i + 1 };
            let (x0, y0, x1, y1) = (xs[i], ys[i], xs[j], ys[j]);
            if x0 == x1 && y0 != y1 {
                vertical.push((x0, y0.min(y1), y0.max(y1)));
            } else if y0 == y1 && x0 != x1 {
                horizontal.push((y0, x0.min(x1), x0.max(x1)));
            }
        }
        // Sorted by line, then start: an overlap shows between neighbours.
        [vertical, horizontal].iter_mut().any(|edges| {
            edges.sort_unstable();
            edges
                .windows(2)
                .any(|w| w[0].0 == w[1].0 && w[1].1 < w[0].2)
        })
    }

    /// Whether every vertex is inside the domain `canonical_rings_into` asserts.
    /// A ring outside is left for `emit` to refuse with a better message.
    fn ring_is_in_domain(xs: &[i64], ys: &[i64]) -> bool {
        let bound = MAX_ABS_DBU.unsigned_abs();
        xs.iter().chain(ys).all(|&c| c.unsigned_abs() <= bound)
    }

    /// Whether a ring runs clockwise. `i128`: raw file coordinates, not yet bounded.
    fn ring_is_clockwise(xs: &[i64], ys: &[i64]) -> bool {
        let n = xs.len();
        let mut area2: i128 = 0;
        for i in 0..n {
            let j = if i + 1 == n { 0 } else { i + 1 };
            area2 += i128::from(xs[i]) * i128::from(ys[j]) - i128::from(xs[j]) * i128::from(ys[i]);
        }
        area2 < 0
    }

    /// Decompose the ring `lib.xs/ys[first..]`, when it revisits a vertex or
    /// folds back along one line (how
    /// GDSII writes a hole), into its outer ring and holes, each pushed as an
    /// element; returns whether it did. Only then: the sweep reorders vertices,
    /// and vertex 0 is a shape's report point (`erc::first_vertex`). A ring
    /// outside the domain, or one that fails to decompose or traces no ring, is
    /// left untouched for the plain path, where `geom::view` names what is wrong.
    fn push_keyhole(lib: &mut Library, first: usize, layer: u16, datatype: u16) -> bool {
        let (xs, ys) = (&lib.xs[first..], &lib.ys[first..]);
        if !((ring_revisits_a_vertex(xs, ys) || ring_overlaps_itself(xs, ys))
            && ring_is_in_domain(xs, ys))
        {
            return false;
        }
        let (mut rx, mut ry, mut starts) = (Vec::new(), Vec::new(), Vec::new());
        if canonical_rings_into(
            &lib.xs[first..],
            &lib.ys[first..],
            &mut rx,
            &mut ry,
            &mut starts,
        )
        .is_err()
            || starts.len() < 2
        {
            return false;
        }
        lib.xs.truncate(first);
        lib.ys.truncate(first);
        for ring in starts.windows(2) {
            let (lo, hi) = (ring[0] as usize, ring[1] as usize);
            let ring_start = narrow(lib.xs.len());
            lib.xs.extend_from_slice(&rx[lo..hi]);
            lib.ys.extend_from_slice(&ry[lo..hi]);
            lib.elems.push(Elem {
                layer,
                datatype,
                vert_start: ring_start,
                vert_len: narrow(lib.xs.len()) - ring_start,
            });
        }
        true
    }

    /// Consume a `BOUNDARY` or `BOX` through its `ENDEL`. Returns the offset past it.
    fn boundary(
        lib: &mut Library,
        strings: &mut StrTable,
        bytes: &[u8],
        mut at: usize,
        start: usize,
        kind: u16,
    ) -> Result<usize, LayoutError> {
        let vert_start = narrow(lib.xs.len());
        let mut layer: Option<u16> = None;
        let mut datatype: Option<u16> = None;
        let mut seen_xy = false;

        let end = loop {
            let (tag, payload, next) = record(bytes, at)?;
            match tag {
                LAYER => layer = Some(word(payload, at)?),
                // A BOX's type is the second half of the stream pair.
                DATATYPE | BOXTYPE => datatype = Some(word(payload, at)?),
                XY => {
                    points(&mut lib.xs, &mut lib.ys, payload, at)?;
                    seen_xy = true;
                }
                _ => {
                    if let Some(end) = element_record(strings, tag, payload, at, next)? {
                        break end;
                    }
                }
            }
            at = next;
        };

        // A vertex repeated at once is an edge of length zero: it carries no
        // geometry, writers emit it (gf180mcu's unit structures do), and the
        // validator would refuse the ring as degenerate. A ring that would
        // keep fewer than three vertices, its closing point not counted, is
        // left whole for the validator to name as degenerate. Counting
        // without the closing point keeps this a fixed point: written back
        // with its closing point, the stored ring reads back unchanged.
        let first = vert_start as usize;
        let past = lib.xs.len();
        let repeats_previous = |xs: &[i64], ys: &[i64], i: usize| {
            i > first && (xs[i], ys[i]) == (xs[i - 1], ys[i - 1])
        };
        let distinct = (first..past)
            .filter(|&i| !repeats_previous(&lib.xs, &lib.ys, i))
            .count();
        let closed =
            distinct >= 2 && (lib.xs[first], lib.ys[first]) == (lib.xs[past - 1], lib.ys[past - 1]);
        if distinct - usize::from(closed) >= 3 {
            let mut kept = first;
            for i in first..lib.xs.len() {
                if !repeats_previous(&lib.xs, &lib.ys, i) {
                    lib.xs[kept] = lib.xs[i];
                    lib.ys[kept] = lib.ys[i];
                    kept += 1;
                }
            }
            lib.xs.truncate(kept);
            lib.ys.truncate(kept);
        }

        // Drop the closing point the format repeats.
        let last = lib.xs.len().wrapping_sub(1);
        if lib.xs.len() - first >= 2
            && lib.xs[first] == lib.xs[last]
            && lib.ys[first] == lib.ys[last]
        {
            lib.xs.pop();
            lib.ys.pop();
        }

        let vert_len = narrow(lib.xs.len()) - vert_start;
        let (Some(layer), Some(datatype)) = (layer, datatype) else {
            return Err(LayoutError::UnsupportedRecord(kind, start));
        };
        if !seen_xy || vert_len < 3 {
            return Err(LayoutError::UnsupportedRecord(kind, start));
        }

        if push_keyhole(lib, first, layer, datatype) {
            return Ok(end);
        }

        // Every BOUNDARY/BOX is an outer ring, stored counter-clockwise whatever the
        // file's winding: `geom::view` reads clockwise as a hole, and KLayout writes
        // hulls clockwise.
        if ring_is_clockwise(&lib.xs[first..], &lib.ys[first..]) {
            lib.xs[first..].reverse();
            lib.ys[first..].reverse();
        }

        lib.elems.push(Elem {
            layer,
            datatype,
            vert_start,
            vert_len,
        });
        Ok(end)
    }

    /// Per-`PATH` scratch.
    #[derive(Default)]
    struct Stroke {
        /// The centreline, end caps applied.
        pts: Vec<(i64, i64)>,
        /// One unit direction per segment.
        dirs: Vec<(i64, i64)>,
        /// `dirs` with both ends duplicated: `ext[i]` arrives at vertex `i`, `ext[i + 1]` leaves.
        ext: Vec<(i64, i64)>,
        left: Vec<(i64, i64)>,
        right: Vec<(i64, i64)>,
    }

    /// Consume a `PATH` through its `ENDEL`, stroking its `n`-point centreline into
    /// a `2n`-point counter-clockwise ring. Returns the offset past it.
    ///
    /// Exact or refused: every segment axis-parallel and non-degenerate, an even
    /// positive width, no reversing vertex, `PATHTYPE` 0, 2 or 4.
    fn path(
        lib: &mut Library,
        strings: &mut StrTable,
        stroke: &mut Stroke,
        bytes: &[u8],
        mut at: usize,
        start: usize,
    ) -> Result<usize, LayoutError> {
        let vert_start = narrow(lib.xs.len());
        let mut layer: Option<u16> = None;
        let mut datatype: Option<u16> = None;
        let mut seen_xy = false;
        let mut width = 0i64;
        let mut pathtype = 0u16;
        let mut begin_ext = 0i64;
        let mut end_ext = 0i64;

        let end = loop {
            let (tag, payload, next) = record(bytes, at)?;
            match tag {
                LAYER => layer = Some(word(payload, at)?),
                DATATYPE => datatype = Some(word(payload, at)?),
                WIDTH => width = long(payload, at)?,
                PATHTYPE => pathtype = word(payload, at)?,
                BGNEXTN => begin_ext = long(payload, at)?,
                ENDEXTN => end_ext = long(payload, at)?,
                XY => {
                    points(&mut lib.xs, &mut lib.ys, payload, at)?;
                    seen_xy = true;
                }
                _ => {
                    if let Some(end) = element_record(strings, tag, payload, at, next)? {
                        break end;
                    }
                }
            }
            at = next;
        };

        // The centreline leaves the coordinate columns; the outline replaces it.
        let first = vert_start as usize;
        stroke.pts.clear();
        stroke.pts.extend(
            lib.xs[first..]
                .iter()
                .copied()
                .zip(lib.ys[first..].iter().copied()),
        );
        lib.xs.truncate(first);
        lib.ys.truncate(first);

        let (Some(layer), Some(datatype)) = (layer, datatype) else {
            return Err(LayoutError::UnsupportedRecord(PATH, start));
        };
        let n = stroke.pts.len();
        if !seen_xy || n < 2 {
            return Err(LayoutError::UnsupportedRecord(PATH, start));
        }
        // Zero width has no area, negative is "absolute" (does not compose with
        // magnification), odd puts the outline half a unit off grid.
        if width <= 0 || width % 2 != 0 {
            return Err(LayoutError::UnsupportedRecord(WIDTH, start));
        }
        let half = width / 2;
        let (begin_ext, end_ext) = match pathtype {
            0 => (0, 0),
            2 => (half, half),
            4 => (begin_ext, end_ext),
            _ => return Err(LayoutError::UnsupportedRecord(PATHTYPE, start)),
        };

        // Exactly one delta is zero on an axis-parallel, non-degenerate segment.
        let segments = n - 1;
        if !stroke
            .pts
            .windows(2)
            .all(|w| (w[0].0 == w[1].0) ^ (w[0].1 == w[1].1))
        {
            return Err(LayoutError::UnsupportedTransform);
        }
        stroke.dirs.clear();
        stroke.dirs.extend(
            stroke
                .pts
                .windows(2)
                .map(|w| ((w[1].0 - w[0].0).signum(), (w[1].1 - w[0].1).signum())),
        );
        // A reversal has no intersection to miter at.
        if stroke
            .dirs
            .windows(2)
            .any(|w| w[0].0 * w[1].0 + w[0].1 * w[1].1 < 0)
        {
            return Err(LayoutError::UnsupportedTransform);
        }

        // End caps extend the first and last vertex along their own segment.
        let (front, back) = (stroke.dirs[0], stroke.dirs[segments - 1]);
        stroke.pts[0].0 -= begin_ext * front.0;
        stroke.pts[0].1 -= begin_ext * front.1;
        stroke.pts[n - 1].0 += end_ext * back.0;
        stroke.pts[n - 1].1 += end_ext * back.1;

        stroke.ext.clear();
        stroke.ext.push(front);
        stroke.ext.extend_from_slice(&stroke.dirs);
        stroke.ext.push(back);

        // Exact miter: with `d` the dot of the two unit directions, the offset corner
        // is `p + half·(n_in·(1 − d) + n_out)`. `side` is +1 left, −1 right.
        let corner = |side: i64, p: (i64, i64), pv: (i64, i64), cv: (i64, i64)| {
            let dot = pv.0 * cv.0 + pv.1 * cv.1;
            let (inx, iny) = (-pv.1 * side, pv.0 * side);
            let (outx, outy) = (-cv.1 * side, cv.0 * side);
            (
                p.0 + half * (inx * (1 - dot) + outx),
                p.1 + half * (iny * (1 - dot) + outy),
            )
        };
        stroke.left.clear();
        stroke.right.clear();
        for i in 0..n {
            let (p, pv, cv) = (stroke.pts[i], stroke.ext[i], stroke.ext[i + 1]);
            stroke.left.push(corner(1, p, pv, cv));
            stroke.right.push(corner(-1, p, pv, cv));
        }

        // Right side forward, then left back: counter-clockwise.
        lib.xs.extend(stroke.right.iter().map(|p| p.0));
        lib.xs.extend(stroke.left.iter().rev().map(|p| p.0));
        lib.ys.extend(stroke.right.iter().map(|p| p.1));
        lib.ys.extend(stroke.left.iter().rev().map(|p| p.1));

        // A path that runs back over itself strokes an outline that revisits a
        // vertex: read it as a written keyhole is, the region it sweeps, so a
        // path and the boundary its outline is written as read back the same.
        if push_keyhole(lib, first, layer, datatype) {
            return Ok(end);
        }
        lib.elems.push(Elem {
            layer,
            datatype,
            vert_start,
            vert_len: narrow(lib.xs.len()) - vert_start,
        });
        Ok(end)
    }

    /// Consume an `SREF` or `AREF` through its `ENDEL`.
    fn reference(
        lib: &mut Library,
        strings: &mut StrTable,
        bytes: &[u8],
        mut at: usize,
        start: usize,
        array: bool,
    ) -> Result<usize, LayoutError> {
        let mut name: Option<StrId> = None;
        let mut place = Xform::IDENTITY;
        let mut cols = 1u32;
        let mut rows = 1u32;
        // An SREF states one point, an AREF three.
        let mut pt = [(0i64, 0i64); 3];
        let mut points_seen = 0usize;

        let end = loop {
            let (tag, payload, next) = record(bytes, at)?;
            match tag {
                SNAME => name = Some(strings.intern(&ascii(payload))),
                STRANS => {
                    let flags = word(payload, at)?;
                    if flags & STRANS_ABSOLUTE != 0 {
                        return Err(LayoutError::UnsupportedTransform);
                    }
                    place.flip = flags & STRANS_REFLECT != 0;
                }
                MAG => {
                    // Non-integral magnification puts vertices off grid.
                    let m = real(payload, at)?;
                    if !((1.0..=1e6).contains(&m) && m.fract() == 0.0) {
                        return Err(LayoutError::UnsupportedTransform);
                    }
                    #[expect(clippy::cast_possible_truncation, reason = "integral, 1..=1e6")]
                    let m = m as i64;
                    place.mag = m;
                }
                ANGLE => {
                    let quarters = real(payload, at)? / 90.0;
                    if quarters.fract() != 0.0 || quarters.abs() > 1e6 {
                        return Err(LayoutError::UnsupportedTransform);
                    }
                    #[expect(clippy::cast_possible_truncation, reason = "integral, bounded")]
                    let quarters = quarters as i64;
                    place.quadrant = u8::try_from(quarters.rem_euclid(4)).expect("0..=3");
                }
                COLROW => {
                    cols = u32::from(word(payload, at)?);
                    rows = u32::from(word(payload.get(2..).unwrap_or_default(), at)?);
                }
                XY => {
                    if !payload.len().is_multiple_of(8) {
                        return Err(LayoutError::Truncated(at));
                    }
                    for (slot, p) in pt.iter_mut().zip(payload.as_chunks::<8>().0) {
                        *slot = xy(p);
                    }
                    points_seen = payload.len() / 8;
                }
                ELFLAGS | PLEX => {}
                ENDEL => break next,
                _ => return Err(LayoutError::UnsupportedRecord(tag, at)),
            }
            at = next;
        };

        let Some(cell) = name else {
            return Err(LayoutError::UnsupportedRecord(SREF, start));
        };
        if points_seen != if array { 3 } else { 1 } {
            return Err(LayoutError::UnsupportedRecord(SREF, start));
        }
        place.dx = pt[0].0;
        place.dy = pt[0].1;

        // An AREF states the far corners, so the pitch is exact or refused.
        let (col_step, row_step) = if array {
            if cols == 0 || rows == 0 {
                return Err(LayoutError::UnsupportedTransform);
            }
            let step = |far: (i64, i64), n: u32| -> Option<(i64, i64)> {
                let n = i64::from(n);
                let (dx, dy) = (far.0 - pt[0].0, far.1 - pt[0].1);
                (dx % n == 0 && dy % n == 0).then_some((dx / n, dy / n))
            };
            (
                step(pt[1], cols).ok_or(LayoutError::UnsupportedTransform)?,
                step(pt[2], rows).ok_or(LayoutError::UnsupportedTransform)?,
            )
        } else {
            ((0, 0), (0, 0))
        };

        lib.refs.push(Ref {
            cell,
            child: u32::MAX,
            place,
            col_step,
            row_step,
            cols,
            rows,
        });
        Ok(end)
    }

    /// Consume an element whose records carry nothing kept, through its `ENDEL`.
    fn skip_element(bytes: &[u8], mut at: usize) -> Result<usize, LayoutError> {
        loop {
            let (tag, _, next) = record(bytes, at)?;
            at = next;
            if tag == ENDEL {
                return Ok(at);
            }
        }
    }

    /// Largest `|v|` over both columns, 0 when empty. Max and min rather than `abs`,
    /// which wraps on `i64::MIN`.
    #[inline(always)]
    #[expect(
        clippy::inline_always,
        reason = "must inline into dispatch!'s target-feature arm"
    )]
    pub(super) fn max_abs<S: Simd>(s: S, xs: &[i64], ys: &[i64]) -> u64 {
        let (mut hi, mut lo) = (i64x4::splat(s, 0), i64x4::splat(s, 0));
        let mut tail = 0;
        for col in [xs, ys] {
            let (chunks, rest) = col.as_chunks::<4>();
            for chunk in chunks {
                let v = i64x4::from_slice(s, chunk);
                hi = hi.max(v);
                lo = lo.min(v);
            }
            tail = tail.max(max_abs_scalar(rest));
        }
        tail.max(hi.reduce_max().unsigned_abs())
            .max(lo.reduce_min().unsigned_abs())
    }

    pub(super) fn max_abs_scalar(v: &[i64]) -> u64 {
        v.iter().map(|v| v.unsigned_abs()).max().unwrap_or(0)
    }

    /// `out[i] = ±src[i] + d`, negated when `neg`. The caller has proven no overflow.
    #[inline(always)]
    #[expect(
        clippy::inline_always,
        reason = "must inline into dispatch!'s target-feature arm"
    )]
    pub(super) fn shift<S: Simd>(s: S, src: &[i64], neg: bool, d: i64, out: &mut [i64]) {
        let (dv, negv) = (i64x4::splat(s, d), mask64x4::splat(s, neg));
        let (src_chunks, src_tail) = src.as_chunks::<4>();
        let (out_chunks, out_tail) = out.as_chunks_mut::<4>();
        for (v, o) in src_chunks.iter().zip(out_chunks) {
            let v = i64x4::from_slice(s, v);
            (negv.select(-v, v) + dv).store_slice(o);
        }
        shift_scalar(src_tail, neg, d, out_tail);
    }

    pub(super) fn shift_scalar(src: &[i64], neg: bool, d: i64, out: &mut [i64]) {
        for (o, &v) in out.iter_mut().zip(src) {
            *o = if neg { -v } else { v } + d;
        }
    }

    /// The hierarchy walk and the tables it fills.
    struct Flatten<'a> {
        lib: &'a Library,
        layers: &'a LayerTable,
        strings: &'a StrTable,
        unknown: UnknownLayers,
        labels: LabelDepth,
        builder: GeometryStoreBuilder,
        provenance: Provenance,
        /// Cells on the current root-to-here chain, for the cycle check.
        on_chain: Vec<bool>,
        /// Each cell's flat polygon and text counts, from
        /// [`Library::flat_counts`].
        counts: Vec<[u64; 2]>,
        level: Level,
        /// Per-element scratch.
        rx: Vec<i64>,
        ry: Vec<i64>,
        tx: Vec<Dbu>,
        ty: Vec<Dbu>,
    }

    impl Library {
        /// Resolves the hierarchy into one flat, layer-sorted store with the deck's
        /// derived layers appended, plus every root cell's label placed in the
        /// root frame ([`LabelDepth::Top`]).
        ///
        /// A root is a structure no reference names; a library with several
        /// roots flattens them all into one store. Rows on one layer keep the
        /// walk's order: roots in file order, each cell's own shapes before its
        /// references'. `deck` is anything holding the layer table (a
        /// [`Deck`](crate::deck::Deck), or a deck compiled from one) and must
        /// have been parsed against [`Self::grid`]; nothing checks it. `strings` is the table [`Self::parse`] and the
        /// deck interned into; it is read for error names and `with_text`
        /// patterns, never written.
        ///
        /// The returned [`Provenance`] holds the placed labels, bound to no
        /// shape yet: call [`Provenance::resolve_labels`] next.
        ///
        /// The walk costs the flat polygon count times the depth: a
        /// placement of a cell holding no polygon is skipped, never expanded.
        ///
        /// # Errors
        ///
        /// From the count, before anything is expanded:
        /// [`LayoutError::CyclicHierarchy`],
        /// [`LayoutError::HierarchyTooDeep`] and
        /// [`LayoutError::TooManyPolygons`]. Then
        /// [`LayoutError::UnknownLayer`] (under [`UnknownLayers::Reject`]),
        /// [`LayoutError::UnsupportedTransform`] or
        /// [`LayoutError::CoordinateOutOfRange`] while placing, and
        /// [`LayoutError::Derived`] while computing derived layers.
        pub fn flatten<D: AsRef<LayerTable> + ?Sized>(
            &self,
            deck: &D,
            strings: &StrTable,
            unknown: UnknownLayers,
        ) -> Result<(GeometryStore, Provenance), LayoutError> {
            self.flatten_labels(deck, strings, unknown, LabelDepth::Top)
        }

        /// [`Self::flatten`], placing the labels `labels` selects: with
        /// [`LabelDepth::All`], every cell's `TEXT`s, transformed into the root
        /// frame. Those are counted with the polygons and held to the same
        /// cap, and the walk then also expands a placement of a cell that
        /// holds only text: it costs the flat polygon and label counts times
        /// the depth.
        ///
        /// # Errors
        ///
        /// As [`Self::flatten`], and with [`LabelDepth::All`]
        /// [`LayoutError::TooManyLabels`] from the count, after
        /// [`LayoutError::TooManyPolygons`].
        pub fn flatten_labels<D: AsRef<LayerTable> + ?Sized>(
            &self,
            deck: &D,
            strings: &StrTable,
            unknown: UnknownLayers,
            labels: LabelDepth,
        ) -> Result<(GeometryStore, Provenance), LayoutError> {
            let ([polygons, texts], counts) = self.flat_counts(strings)?;
            if polygons > MAX_FLAT_POLYGONS {
                return Err(LayoutError::TooManyPolygons(polygons));
            }
            if labels == LabelDepth::All && texts > MAX_FLAT_POLYGONS {
                return Err(LayoutError::TooManyLabels(texts));
            }

            let layers = deck.as_ref();
            let mut walk = Flatten {
                lib: self,
                layers,
                strings,
                unknown,
                labels,
                builder: GeometryStoreBuilder::with_capacity(self.elems.len(), self.xs.len()),
                provenance: Provenance::default(),
                on_chain: vec![false; self.cells.len()],
                counts,
                level: Level::new(),
                rx: Vec::new(),
                ry: Vec::new(),
                tx: Vec::new(),
                ty: Vec::new(),
            };
            for (index, &is_referenced) in self.referenced().iter().enumerate() {
                if !is_referenced {
                    walk.visit(narrow(index), Xform::IDENTITY, true, 1)?;
                }
            }

            // Labels are not bound yet, so the layer-sort permutation has nothing to move.
            let (mut store, _) = walk.builder.finish(layers.len());
            super::derive_layers_into(&mut store, layers, &walk.provenance.placed, strings)?;
            Ok((store, walk.provenance))
        }
    }

    impl Library {
        /// How many polygons [`Self::flatten`] would produce, before derived
        /// layers and keyhole splitting, counted from the hierarchy without
        /// expanding anything: each root's elements plus each placed child's
        /// count times the placement's array size, saturating. Linear in the
        /// library, so a caller can refuse a layout too large to flatten.
        ///
        /// # Errors
        ///
        /// [`LayoutError::CyclicHierarchy`] for any structure that reaches
        /// itself, whether a root reaches it or not, and
        /// [`LayoutError::HierarchyTooDeep`].
        pub fn flat_polygons(&self, strings: &StrTable) -> Result<u64, LayoutError> {
            self.flat_counts(strings).map(|([polygons, _], _)| polygons)
        }

        /// The flat `[polygons, texts]` of the roots, as
        /// [`Self::flat_polygons`] counts them, and of each cell.
        fn flat_counts(
            &self,
            strings: &StrTable,
        ) -> Result<([u64; 2], Vec<[u64; 2]>), LayoutError> {
            let referenced = self.referenced();
            let mut counted = vec![None; self.cells.len()];
            let mut on_chain = vec![false; self.cells.len()];
            let mut total = [0u64; 2];
            for (index, &is_referenced) in referenced.iter().enumerate() {
                if !is_referenced {
                    let (count, _) =
                        self.flat_count(narrow(index), strings, &mut counted, &mut on_chain, 1)?;
                    total = [0, 1].map(|k| total[k].saturating_add(count[k]));
                }
            }
            // A cycle no root reaches is as malformed as one a root reaches:
            // counting what is left refuses it. A library whose every cell is
            // referenced has no root and is caught here too.
            for index in 0..self.cells.len() {
                if counted[index].is_none() {
                    self.flat_count(narrow(index), strings, &mut counted, &mut on_chain, 1)?;
                }
            }
            let each = counted.iter().map(|c| c.map_or([0; 2], |(count, _)| count));
            Ok((total, each.collect()))
        }

        /// Whether each cell is placed by some reference; the roots are the rest.
        fn referenced(&self) -> Vec<bool> {
            let mut referenced = vec![false; self.cells.len()];
            for reference in &self.refs {
                referenced[reference.child as usize] = true;
            }
            referenced
        }

        /// How many `[polygons, texts]` `cell` flattens to: its own elements
        /// and texts, plus each placed child's counts times the placement's
        /// array size, saturating; and how many levels it spans, itself
        /// included. Memoised in `counted`, both, so a cell first met shallow
        /// and met again at `depth` is held to the depth cap as walking it
        /// again would be. Refuses a cycle and a chain past the depth cap.
        fn flat_count(
            &self,
            cell: u32,
            strings: &StrTable,
            counted: &mut [Option<([u64; 2], u32)>],
            on_chain: &mut [bool],
            depth: u32,
        ) -> Result<([u64; 2], u32), LayoutError> {
            let index = cell as usize;
            let name = || strings.resolve(self.cells[index].name).to_owned();
            if let Some((count, levels)) = counted[index] {
                if depth + levels - 1 > MAX_HIERARCHY_DEPTH {
                    return Err(LayoutError::HierarchyTooDeep(name()));
                }
                return Ok((count, levels));
            }
            if on_chain[index] {
                return Err(LayoutError::CyclicHierarchy(name()));
            }
            if depth > MAX_HIERARCHY_DEPTH {
                return Err(LayoutError::HierarchyTooDeep(name()));
            }
            on_chain[index] = true;
            let entry = &self.cells[index];
            let mut count = [
                u64::from(entry.elem_end - entry.elem_start),
                u64::from(entry.text_end - entry.text_start),
            ];
            let mut levels = 1;
            for reference in &self.refs[entry.ref_start as usize..entry.ref_end as usize] {
                let (child, below) =
                    self.flat_count(reference.child, strings, counted, on_chain, depth + 1)?;
                let copies = u64::from(reference.rows) * u64::from(reference.cols);
                count = [0, 1].map(|k| count[k].saturating_add(child[k].saturating_mul(copies)));
                levels = levels.max(below + 1);
            }
            on_chain[index] = false;
            counted[index] = Some((count, levels));
            Ok((count, levels))
        }
    }

    impl Flatten<'_> {
        /// Emit one cell's geometry under `at`, then recurse into its references.
        /// Its labels are placed when `root`, or under [`LabelDepth::All`].
        fn visit(
            &mut self,
            cell: u32,
            at: Xform,
            root: bool,
            depth: u32,
        ) -> Result<(), LayoutError> {
            let lib = self.lib;
            let index = cell as usize;
            if self.on_chain[index] {
                return Err(LayoutError::CyclicHierarchy(
                    self.strings.resolve(lib.cells[index].name).to_owned(),
                ));
            }
            if depth > MAX_HIERARCHY_DEPTH {
                return Err(LayoutError::HierarchyTooDeep(
                    self.strings.resolve(lib.cells[index].name).to_owned(),
                ));
            }
            self.on_chain[index] = true;

            let entry = &lib.cells[index];
            let elems = &lib.elems[entry.elem_start as usize..entry.elem_end as usize];
            if !self.emit_placed(elems, at)? {
                for elem in elems {
                    self.emit(elem, at)?;
                }
            }
            if root || self.labels == LabelDepth::All {
                for label in &lib.texts[entry.text_start as usize..entry.text_end as usize] {
                    self.place(label, at)?;
                }
            }
            for reference in &lib.refs[entry.ref_start as usize..entry.ref_end as usize] {
                // Below the root only polygons are placed, and texts under
                // `All`, so a cell holding neither, at any depth, is not
                // walked: an array of an empty cell is up to 32767²
                // placements no budget counts.
                let [polygons, texts] = self.counts[reference.child as usize];
                if polygons == 0 && (self.labels == LabelDepth::Top || texts == 0) {
                    continue;
                }
                for r in 0..reference.rows {
                    for c in 0..reference.cols {
                        let placed = Xform {
                            dx: reference.place.dx
                                + i64::from(c) * reference.col_step.0
                                + i64::from(r) * reference.row_step.0,
                            dy: reference.place.dy
                                + i64::from(c) * reference.col_step.1
                                + i64::from(r) * reference.row_step.1,
                            ..reference.place
                        };
                        let at = at
                            .compose(placed)
                            .ok_or(LayoutError::UnsupportedTransform)?;
                        self.visit(reference.child, at, false, depth + 1)?;
                    }
                }
            }

            self.on_chain[index] = false;
            Ok(())
        }

        /// The deck layer for a stream pair; `None` means drop it. A pair the
        /// deck ignores is dropped whatever `unknown` says.
        fn layer(&self, layer: u16, datatype: u16) -> Result<Option<LayerId>, LayoutError> {
            match (self.layers.of_stream(layer, datatype), self.unknown) {
                (Some(id), _) => Ok(Some(id)),
                (None, _) if self.layers.is_ignored(layer, datatype) => Ok(None),
                (None, UnknownLayers::Reject) => Err(LayoutError::UnknownLayer(layer, datatype)),
                (None, UnknownLayers::Drop) => Ok(None),
            }
        }

        /// Transform one label's point into the root frame and record it.
        fn place(&mut self, label: &Text, at: Xform) -> Result<(), LayoutError> {
            let Some(layer) = self.layer(label.layer, label.texttype)? else {
                return Ok(());
            };
            let (x, y) = at
                .apply(label.x, label.y)
                .ok_or(LayoutError::UnsupportedTransform)?;
            for v in [x, y] {
                if v.unsigned_abs() > MAX_ABS_DBU.unsigned_abs() {
                    return Err(LayoutError::CoordinateOutOfRange(v));
                }
            }
            self.provenance.place_label(
                gpurify_geom::ops::Point {
                    x: Dbu::new_unchecked(x),
                    y: Dbu::new_unchecked(y),
                },
                layer,
                label.string,
            );
            Ok(())
        }

        /// One placement's elements at once: their vertex runs are one contiguous block
        /// of `lib.xs`. `Ok(false)` leaves it to per-element [`Self::emit`] (magnified,
        /// or a bound this cannot prove), which reports any error exactly as before.
        fn emit_placed(&mut self, elems: &[Elem], at: Xform) -> Result<bool, LayoutError> {
            let (Some(first), Some(last)) = (elems.first(), elems.last()) else {
                return Ok(true);
            };
            if at.mag != 1 {
                return Ok(false);
            }
            let lib = self.lib;
            let level = self.level;
            let base = first.vert_start as usize;
            let block = base..(last.vert_start + last.vert_len) as usize;
            let (xs, ys) = (&lib.xs[block.clone()], &lib.ys[block]);

            // With mag 1 every output is ±one input + d, so |out| <= max|in| + |d|.
            // In bound, that proves no overflow and no out-of-range vertex.
            let reach = dispatch!(level, s => max_abs(s, xs, ys))
                .checked_add(at.dx.unsigned_abs().max(at.dy.unsigned_abs()));
            if reach.is_none_or(|r| r > MAX_ABS_DBU.unsigned_abs()) {
                return Ok(false);
            }
            // A quarter turn swaps the axes.
            let (a, b, c, e) = at.linear();
            let (from_x, neg_x, from_y, neg_y) = if a == 0 {
                (ys, b < 0, xs, c < 0)
            } else {
                (xs, a < 0, ys, e < 0)
            };
            self.rx.resize(xs.len(), 0);
            self.ry.resize(xs.len(), 0);
            dispatch!(level, s => shift(s, from_x, neg_x, at.dx, &mut self.rx));
            dispatch!(level, s => shift(s, from_y, neg_y, at.dy, &mut self.ry));

            for elem in elems {
                if let Some(layer) = self.layer(elem.layer, elem.datatype)? {
                    let start = elem.vert_start as usize - base;
                    self.push(layer, start..start + elem.vert_len as usize, at.flip);
                }
            }
            Ok(true)
        }

        /// Transform one element into the root frame and push it.
        fn emit(&mut self, elem: &Elem, at: Xform) -> Result<(), LayoutError> {
            let Some(layer) = self.layer(elem.layer, elem.datatype)? else {
                return Ok(());
            };
            let lib = self.lib;
            let run = elem.vert_start as usize..(elem.vert_start + elem.vert_len) as usize;

            self.rx.clear();
            self.ry.clear();
            let mut worst = 0u64;
            for (&x, &y) in lib.xs[run.clone()].iter().zip(&lib.ys[run]) {
                let (x, y) = at.apply(x, y).ok_or(LayoutError::UnsupportedTransform)?;
                worst = worst.max(x.unsigned_abs()).max(y.unsigned_abs());
                self.rx.push(x);
                self.ry.push(y);
            }
            // The `±MAX_ABS_DBU` bound every downstream i128 product rests on, checked once.
            let bound = MAX_ABS_DBU.unsigned_abs();
            if worst > bound {
                let out = self
                    .rx
                    .iter()
                    .chain(&self.ry)
                    .copied()
                    .find(|v| v.unsigned_abs() > bound)
                    .expect("the reduction above found one");
                return Err(LayoutError::CoordinateOutOfRange(out));
            }
            debug_assert!(
                {
                    let (a, b, c, e) = at.linear();
                    (a * e - b * c < 0) == at.flip
                },
                "det < 0 iff flip"
            );
            self.push(layer, 0..self.rx.len(), at.flip);
            Ok(())
        }

        /// Push `rx/ry[run]`, already in bound, as one ring. A mirror (det < 0) turns a
        /// counter-clockwise ring clockwise, which `validate_layer_into` reads as a
        /// hole: reverse `[1..]` so vertex 0, the report point, stays put.
        fn push(&mut self, layer: LayerId, run: std::ops::Range<usize>, flip: bool) {
            self.tx.clear();
            self.tx
                .extend(self.rx[run.clone()].iter().map(|&v| Dbu::new_unchecked(v)));
            self.ty.clear();
            self.ty
                .extend(self.ry[run].iter().map(|&v| Dbu::new_unchecked(v)));
            if flip {
                self.tx[1..].reverse();
                self.ty[1..].reverse();
            }
            self.builder.push(layer, &self.tx, &self.ty);
        }
    }
}

/// Reader tests, and the GDSII round trip. Input is assembled byte by byte from
/// the Calma stream format, so nothing here reads a value out of the code under
/// test.
#[cfg(test)]
mod tests {
    use super::{gds, LayoutError, UnknownLayers};
    use crate::deck::tests::{layer_table, ROWS};
    use crate::deck::Deck;
    use gpurify_geom::StrTable;
    use gpurify_geom::{Bbox, GeometryStore, LayerId, PolyId};
    use gpurify_testgen::shapes::polygon_area;
    use gpurify_testgen::shapes::{Handle, Ids};
    use gpurify_testgen::{dbu, LayoutBuilder};

    #[derive(Debug)]
    struct Layout {
        store: GeometryStore,
        provenance: crate::Provenance,
        strings: StrTable,
    }

    /// Parse and flatten into a fresh string table, placing every cell's labels
    /// so the transform tests can follow a label down the hierarchy.
    fn read(bytes: &[u8], deck: &Deck, unknown: UnknownLayers) -> Result<Layout, LayoutError> {
        let mut strings = StrTable::default();
        let library = gds::Library::parse(bytes, &mut strings)?;
        let (store, provenance) =
            library.flatten_labels(deck, &strings, unknown, super::LabelDepth::All)?;
        Ok(Layout {
            store,
            provenance,
            strings,
        })
    }

    const HEADER: u16 = 0x0002;
    const BGNLIB: u16 = 0x0102;
    const LIBNAME: u16 = 0x0206;
    const UNITS: u16 = 0x0305;
    const BGNSTR: u16 = 0x0502;
    const STRNAME: u16 = 0x0606;
    const BOUNDARY: u16 = 0x0800;
    const SREF: u16 = 0x0A00;
    const LAYER: u16 = 0x0D02;
    const DATATYPE: u16 = 0x0E02;
    const XY: u16 = 0x1003;
    const SNAME: u16 = 0x1206;
    const STRANS: u16 = 0x1A01;
    const MAG: u16 = 0x1B05;
    const ANGLE: u16 = 0x1C05;
    const PROPATTR: u16 = 0x2B02;
    const PROPVALUE: u16 = 0x2C06;
    const ENDEL: u16 = 0x1100;
    const ENDSTR: u16 = 0x0700;
    const ENDLIB: u16 = 0x0400;
    const TEXT: u16 = 0x0C00;
    const TEXTTYPE: u16 = 0x1602;
    const PRESENTATION: u16 = 0x1701;
    const STRING: u16 = 0x1906;

    /// `STRANS` bit 0: reflect about the X axis before rotating. From the spec,
    /// not imported from the code under test.
    const REFLECT: u16 = 0x8000;

    /// One BOUNDARY element: a stream pair, an open point list, and properties.
    struct Boundary {
        layer: u16,
        datatype: u16,
        xs: Vec<i64>,
        ys: Vec<i64>,
        props: Vec<(i16, String)>,
    }

    fn boundary(layer: u16, datatype: u16, xs: &[i64], ys: &[i64]) -> Boundary {
        assert_eq!(xs.len(), ys.len(), "coordinate columns must be parallel");
        Boundary {
            layer,
            datatype,
            xs: xs.to_vec(),
            ys: ys.to_vec(),
            props: Vec::new(),
        }
    }

    impl Boundary {
        /// Attach one `PROPATTR` / `PROPVALUE` pair.
        fn tagged(mut self, attribute: i16, value: &str) -> Self {
            self.props.push((attribute, value.to_owned()));
            self
        }
    }

    fn record(out: &mut Vec<u8>, tag: u16, payload: &[u8]) {
        let length = u16::try_from(payload.len() + 4).expect("a GDSII record is under 64 KiB");
        assert!(length % 2 == 0, "GDSII records have an even length");
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&tag.to_be_bytes());
        out.extend_from_slice(payload);
    }

    /// A GDSII eight-byte real. Only positive values occur here.
    fn gds_real(value: f64) -> [u8; 8] {
        const TWO_POW_56: f64 = 72_057_594_037_927_936.0;
        assert!(value > 0.0, "a GDSII unit is positive");
        let mut exponent = 64i32;
        let mut mantissa = value;
        while mantissa >= 1.0 {
            mantissa /= 16.0;
            exponent += 1;
        }
        while mantissa < 1.0 / 16.0 {
            mantissa *= 16.0;
            exponent -= 1;
        }
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "the mantissa is below one, so the product is below 2^56"
        )]
        let fraction = (mantissa * TWO_POW_56).round() as u64;
        assert!(fraction < 1 << 56, "the fraction overflowed its field");
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "the loops above leave the exponent inside 0..=127"
        )]
        let mut out = [exponent as u8, 0, 0, 0, 0, 0, 0, 0];
        out[1..8].copy_from_slice(&fraction.to_be_bytes()[1..8]);
        out
    }

    /// ASCII payload, NUL-padded to an even length as the format requires.
    fn ascii(text: &str) -> Vec<u8> {
        let mut bytes = text.as_bytes().to_vec();
        if bytes.len() % 2 == 1 {
            bytes.push(0);
        }
        bytes
    }

    /// One `SREF`: the cell placed, the `STRANS` flag word, the rotation in
    /// degrees, and where the child's origin lands. A zero angle writes no
    /// `ANGLE` record, which is how the format spells the default.
    struct Ref {
        cell: &'static str,
        strans: u16,
        angle: f64,
        x: i64,
        y: i64,
        /// Integral: the reader accepts only integral magnification.
        mag: i64,
    }

    fn sref(cell: &'static str, strans: u16, angle: f64, x: i64, y: i64) -> Ref {
        Ref {
            cell,
            strans,
            angle,
            x,
            y,
            // One is the format's default and writes no MAG record.
            mag: 1,
        }
    }

    impl Ref {
        /// Attach a `MAG` record. Integral and in `1..=1e6` or the reader
        /// refuses the instance.
        fn magnified(mut self, mag: i64) -> Self {
            self.mag = mag;
            self
        }
    }

    /// A one-cell GDSII library on a 1000-dbu-per-micrometre grid.
    fn gds_library(cell: &str, elements: &[Boundary]) -> Vec<u8> {
        gds_hierarchy(&[(cell, elements, &[])])
    }

    /// A GDSII library of several cells. Every unreferenced cell is a root.
    fn gds_hierarchy(cells: &[(&str, &[Boundary], &[Ref])]) -> Vec<u8> {
        let mut out = Vec::new();
        record(&mut out, HEADER, &600u16.to_be_bytes());
        record(&mut out, BGNLIB, &[0u8; 24]);
        record(&mut out, LIBNAME, &ascii("GPURIFY.DB"));
        let mut units = Vec::with_capacity(16);
        units.extend_from_slice(&gds_real(1e-3));
        units.extend_from_slice(&gds_real(1e-9));
        record(&mut out, UNITS, &units);

        for (cell, elements, refs) in cells {
            record(&mut out, BGNSTR, &[0u8; 24]);
            record(&mut out, STRNAME, &ascii(cell));
            for element in *elements {
                record(&mut out, BOUNDARY, &[]);
                record(&mut out, LAYER, &element.layer.to_be_bytes());
                record(&mut out, DATATYPE, &element.datatype.to_be_bytes());
                let mut xy = Vec::with_capacity((element.xs.len() + 1) * 8);
                for (&x, &y) in element.xs.iter().zip(&element.ys) {
                    let x = i32::try_from(x).expect("test coordinates fit a GDSII coordinate");
                    let y = i32::try_from(y).expect("test coordinates fit a GDSII coordinate");
                    xy.extend_from_slice(&x.to_be_bytes());
                    xy.extend_from_slice(&y.to_be_bytes());
                }
                // A BOUNDARY's point list closes by repeating its first point.
                xy.extend_from_within(0..8);
                record(&mut out, XY, &xy);
                // Properties follow the geometry and precede ENDEL.
                for (attribute, value) in &element.props {
                    record(&mut out, PROPATTR, &attribute.to_be_bytes());
                    record(&mut out, PROPVALUE, &ascii(value));
                }
                record(&mut out, ENDEL, &[]);
            }
            // The format's order inside an SREF.
            for reference in *refs {
                record(&mut out, SREF, &[]);
                record(&mut out, SNAME, &ascii(reference.cell));
                if reference.strans != 0 {
                    record(&mut out, STRANS, &reference.strans.to_be_bytes());
                }
                // `<strans> ::= STRANS [MAG] [ANGLE]`.
                if reference.mag != 1 {
                    let mag =
                        i32::try_from(reference.mag).expect("a test magnification fits an i32");
                    record(&mut out, MAG, &gds_real(f64::from(mag)));
                }
                if reference.angle != 0.0 {
                    record(&mut out, ANGLE, &gds_real(reference.angle));
                }
                let x =
                    i32::try_from(reference.x).expect("test coordinates fit a GDSII coordinate");
                let y =
                    i32::try_from(reference.y).expect("test coordinates fit a GDSII coordinate");
                let mut xy = Vec::with_capacity(8);
                xy.extend_from_slice(&x.to_be_bytes());
                xy.extend_from_slice(&y.to_be_bytes());
                record(&mut out, XY, &xy);
                record(&mut out, ENDEL, &[]);
            }
            record(&mut out, ENDSTR, &[]);
        }
        record(&mut out, ENDLIB, &[]);
        out
    }

    /// A deck holding nothing but the three layers in `ROWS`.
    fn three_layer_deck(strings: &mut StrTable) -> Deck {
        Deck {
            layers: layer_table(strings, &ROWS),
            ..Deck::default()
        }
    }

    /// One `TEXT` element: a stream pair, one point, and the name.
    struct Label {
        layer: u16,
        texttype: u16,
        x: i64,
        y: i64,
        string: &'static str,
    }

    fn label(layer: u16, texttype: u16, x: i64, y: i64, string: &'static str) -> Label {
        Label {
            layer,
            texttype,
            x,
            y,
            string,
        }
    }

    /// A one-cell library of boundaries and `TEXT`s, from the specification.
    fn gds_labelled(cell: &str, elements: &[Boundary], labels: &[Label]) -> Vec<u8> {
        let mut out = gds_hierarchy(&[(cell, elements, &[])]);
        // Splice the texts in before the closing ENDSTR by rebuilding the tail.
        let tail = out.len() - 8;
        let texts = text_records(labels);
        out.splice(tail..tail, texts);
        out
    }

    /// The `TEXT` element block for a run of labels, ready to splice in.
    fn text_records(labels: &[Label]) -> Vec<u8> {
        let mut texts = Vec::new();
        for label in labels {
            record(&mut texts, TEXT, &[]);
            record(&mut texts, LAYER, &label.layer.to_be_bytes());
            record(&mut texts, TEXTTYPE, &label.texttype.to_be_bytes());
            // Read and discarded by the reader; a real writer emits it.
            record(&mut texts, PRESENTATION, &0x0005u16.to_be_bytes());
            let x = i32::try_from(label.x).expect("test coordinates fit a GDSII coordinate");
            let y = i32::try_from(label.y).expect("test coordinates fit a GDSII coordinate");
            let mut xy = Vec::with_capacity(8);
            xy.extend_from_slice(&x.to_be_bytes());
            xy.extend_from_slice(&y.to_be_bytes());
            record(&mut texts, XY, &xy);
            record(&mut texts, STRING, &ascii(label.string));
            record(&mut texts, ENDEL, &[]);
        }
        texts
    }

    /// A square boundary of side 400 on the deck's first layer.
    fn first_layer_square() -> Boundary {
        boundary(ROWS[0].1, ROWS[0].2, &[0, 400, 400, 0], &[0, 0, 400, 400])
    }

    /// Its bounding box, stated rather than derived.
    fn first_square_bbox() -> Bbox {
        Bbox {
            xlo: dbu(0),
            ylo: dbu(0),
            xhi: dbu(400),
            yhi: dbu(400),
        }
    }

    /// Compare two stores row by row, `GeometryStore` deriving no `PartialEq`.
    fn assert_same_store(what: &str, left: &GeometryStore, right: &GeometryStore) {
        assert_eq!(
            left.poly_count(),
            right.poly_count(),
            "{what}: polygon counts differ"
        );
        assert_eq!(
            left.layer_count(),
            right.layer_count(),
            "{what}: layer counts differ"
        );
        for layer in 0..u16::try_from(left.layer_count()).expect("a deck has tens of layers") {
            assert_eq!(
                left.polys_on_layer(LayerId(layer)),
                right.polys_on_layer(LayerId(layer)),
                "{what}: layer {layer} holds a different row range"
            );
        }
        for row in 0..u32::try_from(left.poly_count()).expect("test stores are small") {
            let poly = PolyId(row);
            assert_eq!(
                left.poly_layer(poly),
                right.poly_layer(poly),
                "{what}: {poly:?} is on a different layer"
            );
            assert_eq!(
                left.poly_bbox(poly),
                right.poly_bbox(poly),
                "{what}: {poly:?} has a different bounding box"
            );
            assert_eq!(
                left.poly_verts(poly),
                right.poly_verts(poly),
                "{what}: {poly:?} has different coordinates"
            );
        }
    }

    /// One layout, stated twice: as a builder-made store, and as the GDSII
    /// library the specification says holds it. Shapes are non-convex and
    /// ungrouped by layer, so the sort has work and a bbox reader cannot pass.
    fn corpus() -> (GeometryStore, Ids, Vec<Handle>, Vec<Boundary>) {
        use gpurify_testgen::shapes::{l_shape, plus_shape, rect};
        let shapes = [
            (0usize, rect(0, 0, 400, 400)),
            (2, l_shape(1_000, 0, 600, 200)),
            (1, rect(2_000, 100, 2_180, 280)),
            (0, plus_shape(4_000, 4_000, 500, 120)),
        ];

        let mut layout = LayoutBuilder::new(ROWS.len());
        let mut elements = Vec::with_capacity(shapes.len());
        let mut handles = Vec::with_capacity(shapes.len());
        for (layer, shape) in &shapes {
            handles
                .push(layout.shape(LayerId(u16::try_from(*layer).expect("three layers")), shape));
            elements.push(boundary(ROWS[*layer].1, ROWS[*layer].2, &shape.0, &shape.1));
        }
        let (store, ids) = layout.finish();
        (store, ids, handles, elements)
    }

    /// One rectangle written at chosen coordinates: the store has a known
    /// answer down to the vertex.
    ///
    /// Oracle: construct-from-answer. The square was written at (0, 0) to
    /// (400, 400) on the deck's first layer, so the store holds those four
    /// vertices, without the closing point a GDSII BOUNDARY repeats, and one
    /// layer range per deck layer.
    #[test]
    fn a_boundary_reads_back_on_the_layer_and_at_the_coordinates_it_was_written_at() {
        let mut strings = StrTable::default();
        let deck = three_layer_deck(&mut strings);
        let bytes = gds_library("TOP", &[first_layer_square()]);

        let layout = read(&bytes, &deck, UnknownLayers::Reject).expect("a well-formed library");

        assert_eq!(layout.store.poly_count(), 1);
        assert_eq!(
            layout.store.layer_count(),
            ROWS.len(),
            "the layer count comes from the deck, so a layer with no geometry \
             still has an empty range"
        );
        assert_eq!(layout.store.poly_layer(PolyId(0)), LayerId(0));
        assert_eq!(
            layout.store.poly_verts(PolyId(0)),
            (
                [dbu(0), dbu(400), dbu(400), dbu(0)].as_slice(),
                [dbu(0), dbu(0), dbu(400), dbu(400)].as_slice()
            ),
            "the closing point a BOUNDARY repeats belongs to the file format, \
             not to the store"
        );
        assert_eq!(layout.store.poly_bbox(PolyId(0)), first_square_bbox());
    }

    /// Oracle: law — a BOUNDARY's point order does not change what it denotes.
    ///
    /// GDSII gives a point list no winding semantics, so the same square listed
    /// clockwise and counter-clockwise is the same square. `geom::view` reads a
    /// clockwise ring as a hole, so a reader that passed the file's order
    /// through turned every shape in a clockwise-wound library into an orphan
    /// hole: `validate_layer_into` then refused the layer and every rule on it
    /// recorded `Refused` while examining nothing. That is how a KLayout-written
    /// library behaved, because `KLayout` normalises its hulls clockwise.
    ///
    /// Asserted through `validate_layer_into` rather than on the stored vertex
    /// order, because the property that matters is that the shape is an outer
    /// with no holes, not which vertex ended up first.
    #[test]
    fn a_clockwise_boundary_is_stored_as_an_outer_not_an_orphan_hole() {
        use gpurify_geom::ops::{winding_of, Winding};
        use gpurify_geom::view::{validate_layer_into, ValidatedLayer};

        let mut strings = StrTable::default();
        let deck = three_layer_deck(&mut strings);

        // The same square, listed both ways round.
        let ccw = boundary(ROWS[0].1, ROWS[0].2, &[0, 400, 400, 0], &[0, 0, 400, 400]);
        let cw = boundary(ROWS[0].1, ROWS[0].2, &[0, 0, 400, 400], &[0, 400, 400, 0]);

        let mut stored = Vec::new();
        for element in [ccw, cw] {
            let bytes = gds_library("TOP", &[element]);
            let layout = read(&bytes, &deck, UnknownLayers::Reject).expect("a well-formed library");

            let (xs, ys) = layout.store.poly_verts(PolyId(0));
            assert_eq!(
                winding_of(xs, ys),
                Some(Winding::CounterClockwise),
                "a BOUNDARY is an outer ring, so it is stored counter-clockwise \
                 whichever way the file listed it"
            );

            let mut valid = ValidatedLayer::default();
            validate_layer_into(&layout.store, LayerId(0), &mut valid).expect(
                "a lone square is an outer with no holes, so the layer validates \
                 whichever way its points were listed",
            );
            assert_eq!(valid.len(), 1, "one square is one polygon");
            let polygon = valid.get(0);
            assert_eq!(polygon.holes().count(), 0, "a square has no holes");
            stored.push(polygon_area(polygon));
        }

        assert_eq!(
            stored[0], stored[1],
            "the same square listed clockwise and counter-clockwise must have \
             the same area; GDSII gives its point order no meaning"
        );
    }

    /// Oracle: closed form — a keyhole BOUNDARY is a polygon with a hole.
    ///
    /// GDSII has no record for a hole, so a shape with one is written as a
    /// single ring that runs in along a line and back out along it. That ring
    /// revisits a vertex, which made `validate_layer_into` refuse it as
    /// self-intersecting and every rule on the layer record `Refused` having
    /// examined nothing. A layer holding one holed polygon could not be checked
    /// at all.
    ///
    /// The area is the assertion that carries this. A decomposition that lost
    /// the hole would still give one polygon, a valid layer and no error;
    /// nothing but the area tells the two apart.
    #[test]
    fn a_keyhole_boundary_reads_back_as_one_polygon_with_its_hole() {
        use gpurify_geom::view::{validate_layer_into, ValidatedLayer};

        let mut strings = StrTable::default();
        let deck = three_layer_deck(&mut strings);

        // 1000 x 1000 with a 400 x 400 hole, entered and left along y = 700.
        let bytes = gds_library(
            "TOP",
            &[boundary(
                ROWS[0].1,
                ROWS[0].2,
                &[0, 0, 300, 300, 700, 700, 0, 0, 1000, 1000],
                &[0, 700, 700, 300, 300, 700, 700, 1000, 1000, 0],
            )],
        );

        let layout = read(&bytes, &deck, UnknownLayers::Reject).expect("a well-formed library");
        assert_eq!(
            layout.store.poly_count(),
            2,
            "the store's model is one simple ring per row, so a holed polygon \
             is stored as the outer and the hole"
        );

        let mut valid = ValidatedLayer::default();
        validate_layer_into(&layout.store, LayerId(0), &mut valid)
            .expect("a keyhole denotes an outer and the hole it contains");

        assert_eq!(valid.len(), 1, "the two rings are one polygon");
        let polygon = valid.get(0);
        assert_eq!(polygon.holes().count(), 1, "and it has one hole");
        assert_eq!(
            polygon_area(polygon).raw(),
            1000 * 1000 - 400 * 400,
            "outer minus hole; a decomposition that dropped the hole would \
             leave the whole square and still validate"
        );
    }

    /// N-c7-3 (found by the `gds` fuzz target's round trip on C7's branch):
    /// a `PATH` that runs back over itself strokes an outline that revisits a
    /// vertex, which was stored as drawn (one self-intersecting row, refused
    /// by every check on its layer) while the same outline written as a
    /// `BOUNDARY` read back as a keyhole: `parse -> write -> parse` changed
    /// the store. Both now read as the region the path sweeps.
    ///
    /// Oracle: hand-derived. The centreline (0,0) (4000,0) (4000,3000)
    /// (0,3000) (0,0), width 2000 with half-width end caps (`PATHTYPE` 2),
    /// sweeps the box -1000..5000 x -1000..4000 less the hole 1000..3000 x
    /// 1000..2000 the loop encloses: one polygon with one hole, area
    /// 6000 x 5000 - 2000 x 1000.
    #[test]
    fn a_path_running_back_over_itself_reads_as_the_region_it_sweeps() {
        use gpurify_geom::view::{validate_layer_into, ValidatedLayer};
        const PATH: u16 = 0x0900;
        const WIDTH: u16 = 0x0F03;
        const PATHTYPE: u16 = 0x2102;

        let mut strings = StrTable::default();
        let deck = three_layer_deck(&mut strings);
        let mut bytes = Vec::new();
        record(&mut bytes, HEADER, &600u16.to_be_bytes());
        record(&mut bytes, BGNLIB, &[0u8; 24]);
        record(&mut bytes, LIBNAME, &ascii("GPURIFY.DB"));
        let mut units = Vec::with_capacity(16);
        units.extend_from_slice(&gds_real(1e-3));
        units.extend_from_slice(&gds_real(1e-9));
        record(&mut bytes, UNITS, &units);
        record(&mut bytes, BGNSTR, &[0u8; 24]);
        record(&mut bytes, STRNAME, &ascii("TOP"));
        record(&mut bytes, PATH, &[]);
        record(&mut bytes, LAYER, &ROWS[0].1.to_be_bytes());
        record(&mut bytes, DATATYPE, &ROWS[0].2.to_be_bytes());
        record(&mut bytes, PATHTYPE, &2u16.to_be_bytes());
        record(&mut bytes, WIDTH, &2000i32.to_be_bytes());
        let mut xy = Vec::new();
        for (x, y) in [(0i32, 0i32), (4000, 0), (4000, 3000), (0, 3000), (0, 0)] {
            xy.extend_from_slice(&x.to_be_bytes());
            xy.extend_from_slice(&y.to_be_bytes());
        }
        record(&mut bytes, XY, &xy);
        record(&mut bytes, ENDEL, &[]);
        record(&mut bytes, ENDSTR, &[]);
        record(&mut bytes, ENDLIB, &[]);

        let layout = read(&bytes, &deck, UnknownLayers::Reject).expect("a well-formed library");
        let mut valid = ValidatedLayer::default();
        validate_layer_into(&layout.store, LayerId(0), &mut valid)
            .expect("the swept region is a valid polygon, not a self-crossing outline");
        assert_eq!(valid.len(), 1, "one swept region");
        let polygon = valid.get(0);
        assert_eq!(polygon.holes().count(), 1, "the loop encloses one hole");
        assert_eq!(polygon_area(polygon).raw(), 6000 * 5000 - 2000 * 1000);
    }

    /// Oracle: `KLayout` 0.30.8 — merging this ring gives one polygon with one
    /// hole of area 1 199 825 (testing-plan F2, finding N-f2-1).
    ///
    /// The poly ring of `sky130_fd_sc_hd__lpflow_lsbuf_lh_isowell_tap_1` enters
    /// its hole along x = 5700 and leaves along the hole's right side, running
    /// on past where it entered, so no vertex is revisited. The ring was kept
    /// whole, every derived layer reading it was refused as self-intersecting,
    /// and with it the whole library.
    #[test]
    fn a_keyhole_leaving_along_the_holes_side_reads_back_with_its_hole() {
        use gpurify_geom::view::{validate_layer_into, ValidatedLayer};

        let mut strings = StrTable::default();
        let deck = three_layer_deck(&mut strings);
        let bytes = gds_library(
            "TOP",
            &[boundary(
                ROWS[0].1,
                ROWS[0].2,
                &[
                    5140, 5140, 5155, 5155, 5700, 5700, 5305, 5305, 5700, 5700, 5710, 5710, 6055,
                    6055, 5850, 5850, 5290, 5290,
                ],
                &[
                    160, 1220, 1220, 2655, 2655, 2505, 2505, 1485, 1485, 4355, 4355, 4375, 4375,
                    4015, 4015, 1015, 1015, 160,
                ],
            )],
        );

        let layout = read(&bytes, &deck, UnknownLayers::Reject).expect("a well-formed library");
        let mut valid = ValidatedLayer::default();
        validate_layer_into(&layout.store, LayerId(0), &mut valid)
            .expect("the ring denotes an outer and the hole it contains");
        assert_eq!(valid.len(), 1, "one polygon");
        let polygon = valid.get(0);
        assert_eq!(polygon.holes().count(), 1, "with one hole");
        assert_eq!(polygon_area(polygon).raw(), 1_199_825, "KLayout's area");
    }

    /// Oracle: closed form — a ring that repeats a vertex at once draws the
    /// ring without the repeat (testing-plan F2, finding N-f2-4).
    ///
    /// gf180mcu's `comp.gds` unit structure draws this U (a 27 x 8 um bar
    /// with a 6 x 6 um notch from below) with its notch corner twice in a
    /// row. The zero-length edge made the validator refuse the ring as
    /// degenerate, and with it every derived layer and the whole layout.
    #[test]
    fn a_vertex_repeated_at_once_is_dropped() {
        use gpurify_geom::view::{validate_layer_into, ValidatedLayer};

        let mut strings = StrTable::default();
        let deck = three_layer_deck(&mut strings);
        let bytes = gds_library(
            "TOP",
            &[boundary(
                ROWS[0].1,
                ROWS[0].2,
                &[0, 0, 6_000, 6_000, 6_000, 8_849, 8_849, -18_151, -18_151],
                &[0, 6_000, 6_000, 0, 0, 0, 8_000, 8_000, 0],
            )],
        );

        let layout = read(&bytes, &deck, UnknownLayers::Reject).expect("a well-formed library");
        assert_eq!(
            layout.store.poly_verts(PolyId(0)).0.len(),
            8,
            "the repeat is gone"
        );
        let mut valid = ValidatedLayer::default();
        validate_layer_into(&layout.store, LayerId(0), &mut valid).expect("a simple U");
        assert_eq!(
            polygon_area(valid.get(0)).raw(),
            27_000 * 8_000 - 6_000 * 6_000,
            "the bar less its notch"
        );
    }

    /// One shape on a known layer and one on an unknown one: `Reject` names the
    /// undeclared stream pair, `Drop` keeps exactly the declared shape.
    ///
    /// Oracle: construct-from-answer, against the documented `UnknownLayers`:
    /// the shape on 99/7, which the deck does not declare, refuses the read
    /// under `Reject` naming 99/7 and is removed under `Drop`, which keeps the
    /// declared square as written.
    #[test]
    fn an_undeclared_layer_is_refused_under_reject_and_dropped_under_drop() {
        let mut strings = StrTable::default();
        let deck = three_layer_deck(&mut strings);
        let bytes = gds_library(
            "TOP",
            &[
                first_layer_square(),
                boundary(99, 7, &[900, 1_300, 1_300, 900], &[0, 0, 400, 400]),
            ],
        );

        match read(&bytes, &deck, UnknownLayers::Reject) {
            Err(LayoutError::UnknownLayer(99, 7)) => {}
            other => panic!(
                "an undeclared stream pair under Reject produced {:?} rather than \
                 UnknownLayer(99, 7)",
                other.map(|l| l.store.poly_count())
            ),
        }

        let dropped = read(&bytes, &deck, UnknownLayers::Drop).expect("Drop never refuses");
        assert_eq!(
            dropped.store.poly_count(),
            1,
            "Drop kept a shape on a layer the deck does not declare, or dropped \
             one it does"
        );
        assert_eq!(dropped.store.poly_layer(PolyId(0)), LayerId(0));
        assert_eq!(
            dropped.store.poly_bbox(PolyId(0)),
            first_square_bbox(),
            "the surviving shape is not the one that was on a declared layer"
        );
    }

    /// A chain of nested cells, each placing the next, the last holding one
    /// square.
    fn chain(levels: usize) -> Vec<u8> {
        let names: Vec<&'static str> = (0..levels)
            .map(|level| &*Box::leak(format!("C{level}").into_boxed_str()))
            .collect();
        let square = [first_layer_square()];
        let refs: Vec<[Ref; 1]> = (0..levels)
            .map(|level| [sref(names[(level + 1) % levels], 0, 0.0, 0, 0)])
            .collect();
        let cells: Vec<(&str, &[Boundary], &[Ref])> = (0..levels)
            .map(|level| {
                let last = level + 1 == levels;
                let elements: &[Boundary] = if last { &square } else { &[] };
                let placed: &[Ref] = if last { &[] } else { &refs[level] };
                (names[level], elements, placed)
            })
            .collect();
        gds_hierarchy(&cells)
    }

    /// Oracle: the stated cap. A chain exactly [`super::MAX_HIERARCHY_DEPTH`]
    /// deep flattens to its one square; one level deeper is refused with an
    /// error, not a stack overflow.
    #[test]
    fn a_hierarchy_deeper_than_the_cap_is_refused_not_overflowed() {
        let mut strings = StrTable::default();
        let deck = three_layer_deck(&mut strings);
        let at_cap = super::MAX_HIERARCHY_DEPTH as usize;
        let layout = read(&chain(at_cap), &deck, UnknownLayers::Reject)
            .expect("a chain at the cap flattens");
        assert_eq!(layout.store.poly_count(), 1);
        assert!(matches!(
            read(&chain(at_cap + 1), &deck, UnknownLayers::Reject),
            Err(LayoutError::HierarchyTooDeep(_))
        ));
    }

    /// F35: a reference cycle is refused whether a root reaches it or not.
    /// `TOP` places nothing, and `A` and `B` place each other: `TOP` is the
    /// only root, the count then starts at `A` (the first cell left), and the
    /// chain `A`, `B`, `A` closes at `A`.
    ///
    /// Oracle: construct-from-answer. `A` and `B` place each other and no root
    /// reaches them, so the hierarchy is cyclic by construction, and the
    /// count's documented start after the roots is `A`.
    #[test]
    fn a_reference_cycle_no_root_reaches_is_refused() {
        let mut strings = StrTable::default();
        let deck = three_layer_deck(&mut strings);
        let square = [first_layer_square()];
        let (to_a, to_b) = ([sref("A", 0, 0.0, 0, 0)], [sref("B", 0, 0.0, 0, 0)]);
        let unreached =
            gds_hierarchy(&[("TOP", &square, &[]), ("A", &[], &to_b), ("B", &[], &to_a)]);
        assert!(matches!(
            read(&unreached, &deck, UnknownLayers::Reject),
            Err(LayoutError::CyclicHierarchy(name)) if name == "A"
        ));
    }

    /// Found by the `gds_structured` fuzz target (E1): the flat count
    /// memoised a cell's count, so a cell first reached from a shallow root
    /// was not held to the depth cap when a deep chain reached it again.
    /// `A` places `LEAF`, then `C0` … `C1023` each place the next and `C1023`
    /// places `LEAF`: from `C0`, `LEAF` is level 1025, one past the cap,
    /// though `A` counted it first at level 2.
    ///
    /// Oracle: construct-from-answer. The chain is built one level past
    /// `MAX_HIERARCHY_DEPTH` (1024), so `LEAF` reached from `C0` is past the
    /// cap whatever the walk memoised from `A`; both the flat count and the
    /// read must say `HierarchyTooDeep`.
    #[test]
    fn a_cell_counted_shallow_is_still_held_to_the_depth_cap_when_reached_deep() {
        let mut strings = StrTable::default();
        let deck = three_layer_deck(&mut strings);
        let chain = super::MAX_HIERARCHY_DEPTH as usize;
        let names: Vec<&'static str> = (0..chain)
            .map(|level| &*Box::leak(format!("C{level}").into_boxed_str()))
            .collect();
        let square = [first_layer_square()];
        let to_leaf = [sref("LEAF", 0, 0.0, 0, 0)];
        let refs: Vec<[Ref; 1]> = (1..chain)
            .map(|next| [sref(names[next], 0, 0.0, 0, 0)])
            .collect();
        let mut cells: Vec<(&str, &[Boundary], &[Ref])> = vec![("A", &[], &to_leaf)];
        for (level, &name) in names.iter().enumerate() {
            let placed: &[Ref] = if level + 1 == chain {
                &to_leaf
            } else {
                &refs[level]
            };
            cells.push((name, &[], placed));
        }
        cells.push(("LEAF", &square, &[]));
        let bytes = gds_hierarchy(&cells);
        let mut library_strings = StrTable::default();
        let library =
            gds::Library::parse(&bytes, &mut library_strings).expect("the library parses");
        assert!(matches!(
            library.flat_polygons(&library_strings),
            Err(LayoutError::HierarchyTooDeep(_))
        ));
        assert!(matches!(
            read(&bytes, &deck, UnknownLayers::Reject),
            Err(LayoutError::HierarchyTooDeep(_))
        ));
    }

    /// Found by the `gds_structured` fuzz target (E1): flattening walked
    /// every placement of a cell holding nothing, uncounted by the polygon
    /// budget. `SQUARE` holds the square; `TOP` is a 32767 × 32767 array of
    /// `MID`, itself a 32767 × 32767 array of the empty `EMPTY`: about 10^18
    /// placements and one polygon, which flattening must return at once.
    ///
    /// Oracle: construct-from-answer. The arrays place only the empty cell, so
    /// the flat store is the one square of `SQUARE`; the test finishing at all
    /// is the other half, since the placements number about 10^18.
    #[test]
    fn arrays_of_an_empty_cell_are_not_walked() {
        let mut bytes = gds_hierarchy(&[
            ("SQUARE", &[first_layer_square()], &[]),
            ("EMPTY", &[], &[]),
        ]);
        bytes.truncate(bytes.len() - 4);
        append_array(&mut bytes, "MID", "EMPTY", i16::MAX, i16::MAX);
        append_array(&mut bytes, "TOP", "MID", i16::MAX, i16::MAX);
        record(&mut bytes, ENDLIB, &[]);

        let mut strings = StrTable::default();
        let deck = three_layer_deck(&mut strings);
        let mut layout_strings = StrTable::default();
        let library = gds::Library::parse(&bytes, &mut layout_strings).expect("it parses");
        let (store, _) = library
            .flatten(&deck, &layout_strings, UnknownLayers::Reject)
            .expect("one square flattens");
        assert_eq!(store.poly_count(), 1);
    }

    /// A two-cell library: `TOP` holds one `AREF` of `cols` × `rows` copies of
    /// `UNIT`, which holds the deck's first-layer square.
    fn gds_array(cols: i16, rows: i16) -> Vec<u8> {
        let mut out = gds_hierarchy(&[("UNIT", &[first_layer_square()], &[])]);
        // Drop the ENDLIB the helper wrote, and append TOP.
        out.truncate(out.len() - 4);
        append_array(&mut out, "TOP", "UNIT", cols, rows);
        record(&mut out, ENDLIB, &[]);
        out
    }

    /// Appends structure `cell` holding one `AREF` of `cols` × `rows` copies
    /// of `child`, 1000 apart.
    fn append_array(out: &mut Vec<u8>, cell: &str, child: &str, cols: i16, rows: i16) {
        const AREF: u16 = 0x0B00;
        const COLROW: u16 = 0x1302;
        record(out, BGNSTR, &[0u8; 24]);
        record(out, STRNAME, &ascii(cell));
        record(out, AREF, &[]);
        record(out, SNAME, &ascii(child));
        let mut colrow = Vec::new();
        colrow.extend_from_slice(&cols.to_be_bytes());
        colrow.extend_from_slice(&rows.to_be_bytes());
        record(out, COLROW, &colrow);
        let pitch = 1_000i32;
        let mut xy = Vec::new();
        for (x, y) in [
            (0, 0),
            (pitch * i32::from(cols), 0),
            (0, pitch * i32::from(rows)),
        ] {
            xy.extend_from_slice(&x.to_be_bytes());
            xy.extend_from_slice(&y.to_be_bytes());
        }
        record(out, XY, &xy);
        record(out, ENDEL, &[]);
        record(out, ENDSTR, &[]);
    }

    /// Oracle: the count, `cols × rows` squares, against
    /// [`super::MAX_FLAT_POLYGONS`]. A small array flattens to its count; the
    /// largest array GDSII can state is refused before anything is expanded,
    /// and so returns at once instead of expanding 10⁹ squares.
    #[test]
    fn an_array_over_the_flat_budget_is_refused_before_it_is_expanded() {
        let mut strings = StrTable::default();
        let deck = three_layer_deck(&mut strings);
        let small = read(&gds_array(3, 2), &deck, UnknownLayers::Reject).expect("6 squares");
        assert_eq!(small.store.poly_count(), 6);

        let started = std::time::Instant::now();
        let refused = read(&gds_array(i16::MAX, i16::MAX), &deck, UnknownLayers::Reject);
        assert!(
            matches!(refused, Err(LayoutError::TooManyPolygons(count)) if count == 32_767 * 32_767),
            "{:?}",
            refused.map(|layout| layout.store.poly_count())
        );
        assert!(started.elapsed().as_secs() < 5, "refused without expanding");
    }

    /// Testing-plan F90. Under [`super::LabelDepth::All`], which `read` asks
    /// for, an array of a cell holding one `TEXT` and no polygon is walked to
    /// place its labels: 3 × 2 places 6, and the largest array GDSII can
    /// state, 32767², is refused before anything is expanded.
    ///
    /// Oracle: the count, `cols × rows` labels, against
    /// [`super::MAX_FLAT_POLYGONS`].
    #[test]
    fn an_array_of_text_over_the_flat_budget_is_refused_before_it_is_expanded() {
        let texts = |cols, rows| {
            let unit = label(ROWS[0].1, ROWS[0].2, 100, 100, "A");
            let mut out = gds_labelled("UNIT", &[], &[unit]);
            // Drop the ENDLIB, and append TOP.
            out.truncate(out.len() - 4);
            append_array(&mut out, "TOP", "UNIT", cols, rows);
            record(&mut out, ENDLIB, &[]);
            out
        };
        let mut strings = StrTable::default();
        let deck = three_layer_deck(&mut strings);
        let small = read(&texts(3, 2), &deck, UnknownLayers::Reject).expect("6 labels");
        assert_eq!(small.provenance.placed().len(), 6);

        let started = std::time::Instant::now();
        let refused = read(&texts(i16::MAX, i16::MAX), &deck, UnknownLayers::Reject);
        assert!(
            matches!(refused, Err(LayoutError::TooManyLabels(count)) if count == 32_767 * 32_767),
            "{:?}",
            refused.map(|layout| layout.provenance.placed().len())
        );
        assert!(started.elapsed().as_secs() < 5, "refused without expanding");
    }

    /// The deck's ignore list drops a stream pair even under `Reject`: the deck,
    /// not the run, decides which layers a signoff may skip. A pair neither
    /// declared nor ignored is still refused.
    ///
    /// Oracle: the deck's documented `ignore` (`docs/deck.md`, Layers: an
    /// ignored pair's shapes are dropped, an undeclared one refuses the
    /// layout): the met1 square survives, 99/7 is dropped, 99/8 is refused.
    #[test]
    fn an_ignored_pair_is_dropped_even_under_reject() {
        let mut strings = StrTable::default();
        let deck = crate::deck::parse_deck(
            "layer met1 = gds(68, 20)\nignore gds(99, 7)\n",
            gpurify_geom::Grid::new(1000).expect("a 1 nm grid"),
            &mut strings,
        )
        .expect("a deck with one layer and one ignored pair");
        let square_on =
            |layer, datatype| boundary(layer, datatype, &[0, 400, 400, 0], &[0, 0, 400, 400]);

        let ignored = gds_library("TOP", &[square_on(68, 20), square_on(99, 7)]);
        let layout = read(&ignored, &deck, UnknownLayers::Reject).expect("99/7 is ignored");
        assert_eq!(
            layout.store.poly_count(),
            1,
            "only the met1 square survives"
        );

        let stray = gds_library("TOP", &[square_on(68, 20), square_on(99, 8)]);
        assert!(matches!(
            read(&stray, &deck, UnknownLayers::Reject),
            Err(LayoutError::UnknownLayer(99, 8))
        ));
    }

    /// A one-cell library whose `UNITS` record states `metres` per database
    /// unit, or that has no `UNITS` record at all.
    fn gds_with_units(metres: Option<f64>) -> Vec<u8> {
        let mut out = Vec::new();
        record(&mut out, HEADER, &600u16.to_be_bytes());
        record(&mut out, BGNLIB, &[0u8; 24]);
        record(&mut out, LIBNAME, &ascii("UNITS.DB"));
        if let Some(metres) = metres {
            let mut units = Vec::with_capacity(16);
            units.extend_from_slice(&gds_real(1e-3));
            units.extend_from_slice(&gds_real(metres));
            record(&mut out, UNITS, &units);
        }
        record(&mut out, BGNSTR, &[0u8; 24]);
        record(&mut out, STRNAME, &ascii("TOP"));
        record(&mut out, ENDSTR, &[]);
        record(&mut out, ENDLIB, &[]);
        out
    }

    /// Oracle: the GDSII definition, database units per micrometre being
    /// 1e-6 m over the stated metres per unit.
    #[test]
    fn the_units_record_is_the_grid() {
        for (metres, per_um) in [(1e-9, 1000), (5e-9, 200), (2.5e-10, 4000), (1e-6, 1)] {
            let library =
                gds::Library::parse(&gds_with_units(Some(metres)), &mut StrTable::default())
                    .expect("a well-formed library");
            assert_eq!(
                library.grid().map(gpurify_geom::Grid::dbu_per_um).ok(),
                Some(per_um),
                "{metres} m per database unit"
            );
        }
    }

    /// A grid the deck cannot be converted onto is refused before any deck is read.
    ///
    /// Oracle: hand-derived. A unit of 3e-9 m is 333.3 units per um and 2e-6 m
    /// half a unit per um, neither a whole number, and a library with no UNITS
    /// record states no grid at all.
    #[test]
    fn a_missing_or_fractional_unit_is_refused() {
        let grid = |metres| {
            gds::Library::parse(&gds_with_units(metres), &mut StrTable::default())
                .expect("a well-formed library")
                .grid()
        };
        assert!(matches!(grid(None), Err(LayoutError::NoUnits)));
        assert!(
            matches!(grid(Some(3e-9)), Err(LayoutError::UnsupportedUnits(_))),
            "333.3 per um"
        );
        assert!(
            matches!(grid(Some(2e-6)), Err(LayoutError::UnsupportedUnits(_))),
            "half a unit per um"
        );
    }

    /// `UnknownLayers` is not a correctness switch: where every layer is
    /// declared, both settings produce the same store.
    ///
    /// Oracle: law, as a differential between the two settings. `UnknownLayers`
    /// decides only what happens to an undeclared pair, so with all three
    /// layers declared `Reject` and `Drop` give the same store.
    #[test]
    fn the_two_unknown_layer_settings_agree_when_every_layer_is_declared() {
        let mut strings = StrTable::default();
        let deck = three_layer_deck(&mut strings);
        let bytes = gds_library(
            "TOP",
            &[
                first_layer_square(),
                boundary(
                    ROWS[1].1,
                    ROWS[1].2,
                    &[900, 1_300, 1_300, 900],
                    &[0, 0, 400, 400],
                ),
                boundary(
                    ROWS[2].1,
                    ROWS[2].2,
                    &[0, 200, 200, 0],
                    &[900, 900, 1_100, 1_100],
                ),
            ],
        );

        let rejecting = read(&bytes, &deck, UnknownLayers::Reject).expect("all layers known");
        let dropping = read(&bytes, &deck, UnknownLayers::Drop).expect("all layers known");
        assert_eq!(rejecting.store.poly_count(), 3);
        assert_same_store("Reject against Drop", &rejecting.store, &dropping.store);
    }

    /// A record whose declared length runs past the end of the file is a
    /// truncation, reported at an offset inside the file.
    ///
    /// Oracle: construct-from-answer. One byte is cut from a well-formed
    /// library, so its last record's header states a length the file does not
    /// hold: a truncation, at an offset inside the file.
    #[test]
    fn a_record_running_past_the_end_of_the_file_is_a_truncation_not_a_short_read() {
        let mut strings = StrTable::default();
        let deck = three_layer_deck(&mut strings);
        let mut bytes = gds_library("TOP", &[first_layer_square()]);
        bytes.pop().expect("the library is not empty");

        match read(&bytes, &deck, UnknownLayers::Reject) {
            Err(LayoutError::Truncated(at)) => assert!(
                at <= bytes.len(),
                "the truncation was reported at byte {at}, past the {} the file has",
                bytes.len()
            ),
            other => panic!(
                "a truncated library produced {:?} rather than Truncated",
                other.map(|l| l.store.poly_count())
            ),
        }
    }

    /// The reader has to turn the GDSII library into the builder-made store,
    /// vertex by vertex. Asserting the whole store also pins push order.
    ///
    /// Oracle: construct-from-answer. `corpus` states one layout twice, as a
    /// store built with `LayoutBuilder` and as the GDSII library the Stream
    /// Format specification says holds it; reading the second must give the
    /// first, row for row.
    #[test]
    fn a_library_holding_a_known_layout_reads_back_as_that_exact_store() {
        let mut strings = StrTable::default();
        let deck = three_layer_deck(&mut strings);
        let (expected, _, _, elements) = corpus();
        let bytes = gds_library("TOP", &elements);

        let read = read(&bytes, &deck, UnknownLayers::Reject)
            .expect("a library built to the format specification");
        assert_eq!(read.store.poly_count(), elements.len());
        assert_same_store("a known layout read from GDSII", &expected, &read.store);
    }

    /// Stream properties are accepted and leave the geometry as it was.
    ///
    /// Oracle: metamorphic relation. Tagging every element of `corpus` with
    /// PROPATTR/PROPVALUE records leaves the geometry alone, so the store is
    /// still the builder-made store of the untagged layout.
    #[test]
    fn stream_properties_are_accepted_and_change_no_geometry() {
        let mut strings = StrTable::default();
        let deck = three_layer_deck(&mut strings);
        let (expected, _, _, elements) = corpus();
        let tagged: Vec<Boundary> = elements
            .into_iter()
            .enumerate()
            .map(|(file_row, element)| {
                let attribute = i16::try_from(file_row + 1).expect("four elements");
                element.tagged(attribute, &format!("element_{file_row}"))
            })
            .collect();
        let bytes = gds_library("TOP", &tagged);

        let layout = read(&bytes, &deck, UnknownLayers::Reject).expect("well formed");
        assert_same_store("a tagged layout", &expected, &layout.store);
    }

    /// Nested magnifications overflow i64 in `compose` (four levels of 1e6) or in
    /// the vertex transform (three). Either is a refusal, never a wrapped coordinate.
    ///
    /// Oracle: hand-derived. Four levels of magnification 1e6 compose to 1e24,
    /// and three put a 400 dbu vertex at 4e20 dbu; both are past i64's 9.2e18,
    /// so the only correct answer is `UnsupportedTransform`.
    #[test]
    fn a_magnification_chain_past_i64_is_refused_rather_than_wrapped() {
        let mut strings = StrTable::default();
        let deck = three_layer_deck(&mut strings);
        let mag = |cell| [sref(cell, 0, 0.0, 0, 0).magnified(1_000_000)];
        let (d, c, b, a) = (mag("D"), mag("C"), mag("B"), mag("A"));
        let square = [first_layer_square()];
        for levels in [3, 4] {
            let chain: [(&str, &[Boundary], &[Ref]); 5] = [
                ("TOP", &[], &a),
                ("A", &[], &b),
                ("B", &[], if levels == 4 { &c } else { &d }),
                ("C", &[], &d),
                ("D", &square, &[]),
            ];
            let cells = if levels == 4 {
                &chain[..]
            } else {
                &[chain[0], chain[1], chain[2], chain[4]][..]
            };
            match read(&gds_hierarchy(cells), &deck, UnknownLayers::Reject) {
                Err(LayoutError::UnsupportedTransform) => {}
                other => panic!(
                    "{levels} levels of 1e6 produced {:?}",
                    other.map(|l| l.store.poly_count())
                ),
            }
        }
    }

    /// The cell every mirroring test below instantiates: a counter-clockwise
    /// right triangle. Chirality is the point — a rectangle is its own mirror
    /// image, so a reader dropping the reflection would reproduce one exactly.
    fn ccw_triangle() -> Boundary {
        boundary(ROWS[0].1, ROWS[0].2, &[0, 200, 0], &[0, 0, 100])
    }

    /// The vertices of a store row, as a pair of owned columns.
    fn verts(store: &GeometryStore, row: u32) -> (Vec<i64>, Vec<i64>) {
        let (xs, ys) = store.poly_verts(PolyId(row));
        (
            xs.iter().map(|d| d.raw()).collect(),
            ys.iter().map(|d| d.raw()).collect(),
        )
    }

    /// `TOP` places `LEAF` twice, plain and under `STRANS 0x8000`. The mirrored
    /// copy is `(x, −y)` shifted by the reference point — determinant −1, so the
    /// ring reverses.
    ///
    /// Oracle: hand-derived. STRANS 0x8000 reflects about x before rotation, so
    /// the triangle (0, 0), (200, 0), (0, 100) under (x, -y) + (1000, 0) is
    /// clockwise, and the store's counter-clockwise rings with vertex 0 fixed
    /// give the listed vertices, reversed from vertex 1.
    #[test]
    fn a_mirrored_instance_keeps_the_orientation_the_cell_was_drawn_with() {
        use gpurify_geom::ops::{winding_of, Winding};

        let mut strings = StrTable::default();
        let deck = three_layer_deck(&mut strings);
        let bytes = gds_hierarchy(&[
            ("LEAF", &[ccw_triangle()], &[]),
            (
                "TOP",
                &[],
                &[
                    sref("LEAF", 0, 0.0, 0, 0),
                    sref("LEAF", REFLECT, 0.0, 1_000, 0),
                ],
            ),
        ]);

        let layout = read(&bytes, &deck, UnknownLayers::Reject).expect("a well-formed library");
        assert_eq!(
            layout.store.poly_count(),
            2,
            "one row per placement of the leaf cell"
        );

        assert_eq!(
            verts(&layout.store, 0),
            (vec![0, 200, 0], vec![0, 0, 100]),
            "the unmirrored placement is the cell as drawn"
        );
        // (0,0), (200,0), (0,100) under (x, −y) + (1000, 0) is clockwise, so
        // the reversal fixes vertex 0 and turns the rest around.
        assert_eq!(
            verts(&layout.store, 1),
            (vec![1_000, 1_000, 1_200], vec![0, -100, 0]),
            "the mirrored placement did not come back in the reversed order a \
             determinant of −1 requires"
        );

        let (xs, ys) = layout.store.poly_verts(PolyId(0));
        assert_eq!(
            winding_of(xs, ys),
            Some(Winding::CounterClockwise),
            "the cell as drawn"
        );
        let (xs, ys) = layout.store.poly_verts(PolyId(1));
        assert_eq!(
            winding_of(xs, ys),
            Some(Winding::CounterClockwise),
            "a cell's rings must have the same orientation wherever the cell is \
             placed; clockwise here is read downstream as a hole"
        );
    }

    /// Two reflections compose to a rotation, so the doubly nested copy must be
    /// the cell as drawn, vertex for vertex. The parity path: a fix that
    /// reversed per level rather than on the composed transform fails here.
    ///
    /// Oracle: law. Two reflections compose to the identity, so the nested copy
    /// is the direct copy vertex for vertex, order included.
    #[test]
    fn a_doubly_mirrored_instance_is_the_cell_as_drawn() {
        let mut strings = StrTable::default();
        let deck = three_layer_deck(&mut strings);
        let bytes = gds_hierarchy(&[
            ("LEAF", &[ccw_triangle()], &[]),
            ("MID", &[], &[sref("LEAF", REFLECT, 0.0, 0, 0)]),
            (
                "TOP",
                &[],
                &[sref("LEAF", 0, 0.0, 0, 0), sref("MID", REFLECT, 0.0, 0, 0)],
            ),
        ]);

        let layout = read(&bytes, &deck, UnknownLayers::Reject).expect("a well-formed library");
        assert_eq!(layout.store.poly_count(), 2);
        assert_eq!(
            verts(&layout.store, 0),
            (vec![0, 200, 0], vec![0, 0, 100]),
            "the direct placement is the cell as drawn"
        );
        assert_eq!(
            verts(&layout.store, 1),
            (vec![0, 200, 0], vec![0, 0, 100]),
            "two reflections compose to the identity, so the nested copy must \
             be indistinguishable from the direct one — order included"
        );
    }

    /// DRC-123, hierarchy flattened at load: `TOP` places `LEAF` four times,
    /// each mirrored and rotated one more quarter turn. The composed linear
    /// part `R_q · diag(1, −1)` has determinant −1 in all four, so all four
    /// rings reverse.
    ///
    /// Oracle: hand-derived. Each placement is the drawn triangle through
    /// `R_q · diag(1, -1)` (GDSII reflects, then rotates) plus its offset,
    /// worked out by hand, reversed from vertex 1 because the determinant is
    /// -1; every ring winds counter-clockwise.
    #[test]
    fn a_mirror_composed_with_each_quarter_turn_still_flattens_counter_clockwise() {
        use gpurify_geom::ops::{winding_of, Winding};

        let mut strings = StrTable::default();
        let deck = three_layer_deck(&mut strings);
        let bytes = gds_hierarchy(&[
            ("LEAF", &[ccw_triangle()], &[]),
            (
                "TOP",
                &[],
                &[
                    sref("LEAF", REFLECT, 0.0, 0, 0),
                    sref("LEAF", REFLECT, 90.0, 2_000, 0),
                    sref("LEAF", REFLECT, 180.0, 4_000, 0),
                    sref("LEAF", REFLECT, 270.0, 6_000, 0),
                ],
            ),
        ]);

        let layout = read(&bytes, &deck, UnknownLayers::Reject).expect("a well-formed library");
        assert_eq!(layout.store.poly_count(), 4);

        // Each row: the drawn triangle through `R_q · diag(1, −1)`, offset by
        // the reference point, then reversed from vertex 1 on.
        let expected = [
            (vec![0, 0, 200], vec![0, -100, 0]),
            (vec![2_000, 2_100, 2_000], vec![0, 0, 200]),
            (vec![4_000, 4_000, 3_800], vec![0, 100, 0]),
            (vec![6_000, 5_900, 6_000], vec![0, 0, -200]),
        ];
        for (row, want) in expected.into_iter().enumerate() {
            let row = u32::try_from(row).expect("four placements");
            assert_eq!(
                verts(&layout.store, row),
                want,
                "the mirrored placement at quarter turn {row} did not flatten to \
                 the reflected-then-rotated triangle in reversed order"
            );
            let (xs, ys) = layout.store.poly_verts(PolyId(row));
            assert_eq!(
                winding_of(xs, ys),
                Some(Winding::CounterClockwise),
                "quarter turn {row} came back clockwise, which is read \
                 downstream as a hole"
            );
        }
    }

    /// A mirror and a rotation split across *two* levels of hierarchy, in both
    /// orders, which are **not** the same transform: reflection runs before
    /// rotation, so `F · R₉₀ · p = (−y, −x)` and `R₉₀ · F · p = (y, x)`. A
    /// composition that *added* the quadrants would give both the same answer;
    /// the `assert_ne!` carries that asymmetry. Both determinants are −1.
    ///
    /// Oracle: hand-derived. `F · R90` maps a point to (-y, -x) and `R90 · F`
    /// to (y, x); the triangle through each, offset and reversed from vertex 1,
    /// is worked out in the comments, and the two must differ.
    #[test]
    fn a_mirror_and_a_rotation_split_across_two_levels_do_not_commute() {
        use gpurify_geom::ops::{winding_of, Winding};

        let mut strings = StrTable::default();
        let deck = three_layer_deck(&mut strings);
        let bytes = gds_hierarchy(&[
            ("LEAF", &[ccw_triangle()], &[]),
            // A rotated child, to sit under a mirrored parent.
            ("ROTATED", &[], &[sref("LEAF", 0, 90.0, 0, 0)]),
            // A mirrored child, to sit under a rotated parent.
            ("MIRRORED", &[], &[sref("LEAF", REFLECT, 0.0, 0, 0)]),
            (
                "TOP",
                &[],
                &[
                    sref("ROTATED", REFLECT, 0.0, 0, 0),
                    sref("MIRRORED", 0, 90.0, 5_000, 0),
                ],
            ),
        ]);

        let layout = read(&bytes, &deck, UnknownLayers::Reject).expect("a well-formed library");
        assert_eq!(layout.store.poly_count(), 2, "one row per leaf placement");

        // (0,0), (200,0), (0,100) through `(−y, −x)` is (0,0), (0,−200),
        // (−100,0) — clockwise — so the reversal fixes vertex 0 and turns the
        // rest around.
        let mirrored_parent = verts(&layout.store, 0);
        assert_eq!(
            mirrored_parent,
            (vec![0, -100, 0], vec![0, 0, -200]),
            "a mirrored parent over a rotated child did not flatten to \
             `F · R₉₀` in reversed order"
        );

        // Through `(y, x)`, offset by (5000, 0): (5000,0), (5000,200),
        // (5100,0) — also clockwise, also reversed.
        let rotated_parent = verts(&layout.store, 1);
        assert_eq!(
            rotated_parent,
            (vec![5_000, 5_100, 5_000], vec![0, 0, 200]),
            "a rotated parent over a mirrored child did not flatten to \
             `R₉₀ · F` in reversed order"
        );

        // The asymmetry, independent of the literals: translated to their own
        // first vertices the two shapes still differ.
        let relative = |(xs, ys): &(Vec<i64>, Vec<i64>)| -> Vec<(i64, i64)> {
            xs.iter()
                .zip(ys)
                .map(|(x, y)| (x - xs[0], y - ys[0]))
                .collect()
        };
        assert_ne!(
            relative(&mirrored_parent),
            relative(&rotated_parent),
            "`F · R_q` and `R_q · F` produced the same shape; the two orders \
             have been collapsed and one of them is now wrong"
        );

        for (row, order) in [(0u32, "mirrored parent"), (1, "rotated parent")] {
            let (xs, ys) = layout.store.poly_verts(PolyId(row));
            assert_eq!(
                winding_of(xs, ys),
                Some(Winding::CounterClockwise),
                "{order}: a cell's rings keep the orientation they were drawn \
                 with however deep the mirror sits; clockwise is read \
                 downstream as a hole"
            );
        }
    }

    /// The stream pairs sky130 uses: `met1.drawing` 68/20, `met1.label` 68/5.
    const LABEL_ROWS: [(&str, u16, u16); 2] = [("met1", 68, 20), ("met1_label", 68, 5)];

    /// A deck whose `met1_label` layer names `met1` — the pairing that makes a
    /// `TEXT` a net label rather than documentation.
    fn labelling_deck(strings: &mut StrTable) -> Deck {
        let layers = layer_table(strings, &LABEL_ROWS);
        let met1 = layers.of_stream(68, 20).expect("the fixture declares met1");
        let text = layers
            .of_stream(68, 5)
            .expect("the fixture declares met1_label");
        Deck {
            connectivity: crate::deck::Connectivity {
                conductors: vec![met1],
                label_layer: vec![text],
                label_names: vec![met1],
                ..crate::deck::Connectivity::default()
            },
            layers,
            ..Deck::default()
        }
    }

    /// One 400-square of met1 at the origin, what every label test aims at.
    fn met1_square() -> Boundary {
        boundary(68, 20, &[0, 400, 400, 0], &[0, 0, 400, 400])
    }

    /// Read a library and bind its labels, returning the resolved column.
    fn bound_labels(bytes: &[u8], deck: &Deck) -> Result<Vec<(PolyId, String)>, crate::LabelError> {
        let mut layout = read(bytes, deck, UnknownLayers::Reject).expect("a well-formed library");
        layout
            .provenance
            .resolve_labels(&layout.store, &deck.connectivity)?;
        Ok(layout
            .provenance
            .labels()
            .iter()
            .map(|&(poly, name)| (poly, layout.strings.resolve(name).to_owned()))
            .collect())
    }

    /// The label is written inside a square the test chose, so which polygon it
    /// must name is known before the reader runs.
    ///
    /// Oracle: construct-from-answer. The one label is drawn at (200, 200),
    /// inside the one 400 square, so it names that polygon.
    #[test]
    fn a_text_inside_a_shape_names_the_net_that_shape_is_on() {
        let mut strings = StrTable::default();
        let deck = labelling_deck(&mut strings);
        let bytes = gds_labelled("TOP", &[met1_square()], &[label(68, 5, 200, 200, "VDD")]);

        let bound = bound_labels(&bytes, &deck).expect("the label sits on the square");

        assert_eq!(
            bound,
            vec![(PolyId(0), "VDD".to_owned())],
            "the one text drawn inside the one square names it"
        );
    }

    /// The boundary counts as inside: pin labels are routinely written at a
    /// corner or an edge midpoint. All four cases the half-open ray cast alone
    /// answers `false` for.
    ///
    /// Oracle: the label binding's documented contract (`provenance.rs`: "The
    /// boundary counts as inside"): each label sits on the square's boundary,
    /// so each names polygon 0.
    #[test]
    fn a_text_on_a_shapes_edge_or_corner_still_names_it() {
        let mut strings = StrTable::default();
        let deck = labelling_deck(&mut strings);

        for (x, y, where_it_is) in [
            (200, 0, "the midpoint of the bottom edge"),
            (0, 200, "the midpoint of the left edge"),
            (400, 200, "the midpoint of the right edge"),
            (0, 0, "the lower-left corner"),
            (400, 400, "the upper-right corner"),
        ] {
            let bytes = gds_labelled("TOP", &[met1_square()], &[label(68, 5, x, y, "VDD")]);
            let bound = bound_labels(&bytes, &deck).unwrap_or_else(|why| {
                panic!("a label at {where_it_is} must bind, not refuse: {why}")
            });
            assert_eq!(
                bound,
                vec![(PolyId(0), "VDD".to_owned())],
                "a label at {where_it_is} is on the conductor"
            );
        }
    }

    /// A text on a layer no `connectivity.labels` row pairs is documentation,
    /// not a net label, and is passed over in silence.
    ///
    /// Oracle: the label binding's documented contract (`provenance.rs`: "A
    /// text on a layer no pairing row names binds nothing"): 68/20 is paired
    /// with nothing.
    #[test]
    fn a_text_on_an_unpaired_layer_is_documentation_and_binds_nothing() {
        let mut strings = StrTable::default();
        // met1's own drawing layer is declared, and deliberately *not* paired.
        let deck = labelling_deck(&mut strings);
        let bytes = gds_labelled(
            "TOP",
            &[met1_square()],
            &[label(68, 20, 200, 200, "a note")],
        );

        let bound = bound_labels(&bytes, &deck).expect("an unpaired text is not a fault");

        assert!(
            bound.is_empty(),
            "a text the deck does not pair names nothing, and must not be \
             guessed onto the shape it happens to sit on"
        );
    }

    /// A label the deck *claims* that lands on no shape is refused: a dropped
    /// one leaves the net with its geometry and without its name.
    ///
    /// Oracle: the label binding's documented contract (`provenance.rs`:
    /// `Unplaced` "for a claimed label on no shape"): (9000, 9000) is far from
    /// the only square (0..400), so the refusal names that point.
    #[test]
    fn a_claimed_label_on_no_shape_is_refused_rather_than_dropped() {
        let mut strings = StrTable::default();
        let deck = labelling_deck(&mut strings);
        // Well clear of the square, which spans 0..400 on both axes.
        let bytes = gds_labelled(
            "TOP",
            &[met1_square()],
            &[label(68, 5, 9_000, 9_000, "VDD")],
        );

        match bound_labels(&bytes, &deck) {
            Err(crate::LabelError::Unplaced { x, y, .. }) => {
                assert_eq!(
                    (x, y),
                    (9_000, 9_000),
                    "the refusal names where the label was"
                );
            }
            Ok(bound) => panic!("a misplaced label was accepted, binding {bound:?}"),
        }
    }

    /// A label under a mirrored instance moves with the geometry it names.
    ///
    /// The translation gives the test its teeth: `y ↦ 1000 − y` puts the square
    /// at y 600..1000 and the label at (200, 800), so a reader leaving it in the
    /// child's frame refuses it. A shift of 400 would be worthless — (200, 200)
    /// is a fixed point of `y ↦ 400 − y`.
    ///
    /// Oracle: hand-derived. The reflection with offset (0, 1000) maps y to
    /// 1000 - y: the square to y 600..1000 and the label to (200, 800), inside
    /// it, so the label binds polygon 0.
    #[test]
    fn a_label_under_a_mirrored_instance_moves_with_the_shape_it_names() {
        let mut strings = StrTable::default();
        let deck = labelling_deck(&mut strings);

        let mut bytes = gds_hierarchy(&[
            ("CHILD", &[met1_square()], &[]),
            ("TOP", &[], &[sref("CHILD", REFLECT, 0.0, 0, 1000)]),
        ]);
        // The label belongs to CHILD, so it is spliced into the first cell.
        let child_end = find_first_endstr(&bytes);
        let mut texts = Vec::new();
        record(&mut texts, TEXT, &[]);
        record(&mut texts, LAYER, &68u16.to_be_bytes());
        record(&mut texts, TEXTTYPE, &5u16.to_be_bytes());
        let mut xy = Vec::with_capacity(8);
        xy.extend_from_slice(&200i32.to_be_bytes());
        xy.extend_from_slice(&200i32.to_be_bytes());
        record(&mut texts, XY, &xy);
        record(&mut texts, STRING, &ascii("VDD"));
        record(&mut texts, ENDEL, &[]);
        bytes.splice(child_end..child_end, texts);

        let bound = bound_labels(&bytes, &deck)
            .expect("the label is mirrored onto the square exactly as the square is");

        assert_eq!(
            bound,
            vec![(PolyId(0), "VDD".to_owned())],
            "a point under a mirrored instance takes the instance transform, \
             the same as every vertex of the shape it names"
        );
    }

    /// By default a sub-cell's label is not a design label: the same library
    /// that binds `VDD` under [`super::LabelDepth::All`] binds nothing.
    ///
    /// Oracle: the documented `LabelDepth`: `Top` (root cells only, Calibre's
    /// `TEXT DEPTH PRIMARY` default) places no `CHILD` text, and `All` places
    /// the one there is.
    #[test]
    fn a_sub_cell_label_is_not_placed_by_default() {
        let mut strings = StrTable::default();
        let deck = labelling_deck(&mut strings);
        let mut bytes = gds_hierarchy(&[
            ("CHILD", &[met1_square()], &[]),
            ("TOP", &[], &[sref("CHILD", 0, 0.0, 0, 0)]),
        ]);
        let child_end = find_first_endstr(&bytes);
        bytes.splice(
            child_end..child_end,
            text_records(&[label(68, 5, 200, 200, "VDD")]),
        );

        let library = gds::Library::parse(&bytes, &mut strings).expect("well formed");
        let (_, top) = library
            .flatten(&deck, &strings, UnknownLayers::Reject)
            .expect("well formed");
        let (_, all) = library
            .flatten_labels(
                &deck,
                &strings,
                UnknownLayers::Reject,
                super::LabelDepth::All,
            )
            .expect("well formed");
        assert!(
            top.placed.is_empty(),
            "a CHILD text was placed as a design label"
        );
        assert_eq!(all.placed.len(), 1, "LabelDepth::All places the CHILD text");
    }

    /// The byte offset of the first `ENDSTR`, where a label belonging to the
    /// first cell has to be spliced.
    fn find_first_endstr(bytes: &[u8]) -> usize {
        let mut at = 0;
        while at + 4 <= bytes.len() {
            let len = usize::from(u16::from_be_bytes([bytes[at], bytes[at + 1]]));
            let tag = u16::from_be_bytes([bytes[at + 2], bytes[at + 3]]);
            assert!(len >= 4, "a GDSII record carries its own header");
            if tag == ENDSTR {
                return at;
            }
            at += len;
        }
        panic!("the fixture library has no ENDSTR");
    }

    // ------------------------------------------ global transform equivariance

    /// One representable instance transform, `W(p) = mag · R_q · Fʳ · p + (dx,
    /// dy)`. Deliberately *not* [`super::gds::Xform`]: an expected answer
    /// computed with the function under test asserts nothing.
    #[derive(Clone, Copy)]
    struct Warp {
        mag: i64,
        reflect: bool,
        quarters: u8,
        dx: i64,
        dy: i64,
    }

    impl Warp {
        /// Apply it, spelled from the specification: the reflection about the X
        /// axis runs **before** the counter-clockwise `ANGLE` rotation.
        fn apply(self, x: i64, y: i64) -> (i64, i64) {
            let (x, y) = if self.reflect { (x, -y) } else { (x, y) };
            let (x, y) = match self.quarters {
                0 => (x, y),
                1 => (-y, x),
                2 => (-x, -y),
                3 => (y, -x),
                _ => unreachable!("a quarter turn is 0..=3"),
            };
            (self.mag * x + self.dx, self.mag * y + self.dy)
        }

        /// The `SREF` that carries it.
        fn sref_of(self, cell: &'static str) -> Ref {
            let strans = if self.reflect { REFLECT } else { 0 };
            sref(
                cell,
                strans,
                f64::from(self.quarters) * 90.0,
                self.dx,
                self.dy,
            )
            .magnified(self.mag)
        }
    }

    /// The library the equivariance law is stated over, optionally wrapped.
    /// `MID` places `LEAF` mirrored and `TOP` places `MID` under a quarter turn,
    /// so the deepest ring arrives through a mirror composed with a rotation
    /// across two levels; `TOP`'s ring at `x = 2·10⁶` makes one magnification
    /// below genuinely unrepresentable.
    ///
    /// Cell order is load-bearing: `LEAF` first so [`find_first_endstr`] owns
    /// its labels, `TOP` last so appending `WRAP` leaves every other cell's
    /// bytes identical and `WRAP` is the only unreferenced cell.
    fn nested_mirror_library(wrap: Option<Warp>) -> Vec<u8> {
        let leaf = [
            ccw_triangle(),
            boundary(ROWS[1].1, ROWS[1].2, &[0, 120, 120, 0], &[0, 0, 60, 60]),
        ];
        let top = [boundary(
            ROWS[2].1,
            ROWS[2].2,
            &[2_000_000, 2_000_400, 2_000_400, 2_000_000],
            &[0, 0, 400, 400],
        )];
        let mid_refs = [sref("LEAF", REFLECT, 0.0, 300, 0)];
        let top_refs = [sref("LEAF", 0, 0.0, 0, 0), sref("MID", 0, 90.0, 1_000, 0)];
        let wrap_refs: Vec<Ref> = wrap.into_iter().map(|w| w.sref_of("TOP")).collect();

        let mut cells: Vec<(&str, &[Boundary], &[Ref])> = vec![
            ("LEAF", &leaf, &[]),
            ("MID", &[], &mid_refs),
            ("TOP", &top, &top_refs),
        ];
        if !wrap_refs.is_empty() {
            cells.push(("WRAP", &[], &wrap_refs));
        }

        let mut bytes = gds_hierarchy(&cells);
        let at = find_first_endstr(&bytes);
        let texts = text_records(&[label(ROWS[1].1, ROWS[1].2, 60, 20, "N1")]);
        bytes.splice(at..at, texts);
        bytes
    }

    /// Global transform equivariance of the whole reader.
    ///
    /// Wrap a library's single root cell in a new outermost cell holding one
    /// `SREF` of it under any representable `W`. Flattening is function
    /// composition, so the result must be the unwrapped result pushed through
    /// `W` and nothing else:
    ///
    /// - **(a)** row count, layer ranges and each row's layer are untouched.
    /// - **(b)** row `i`'s vertices are `W(v_j)` in order, or
    ///   `[W(v₀), W(v_{n−1}), …, W(v₁)]` when `W` reflects — vertex 0 is the
    ///   fixed point `erc::first_vertex` relies on.
    /// - **(c)** every `PlacedLabel` point becomes `W(p)`, same order, layer and
    ///   name.
    ///
    /// The law is stated over the flip-parity *difference*, never the absolute
    /// parity, which is why the fixture contains a cell already placed mirrored
    /// under a rotation two levels deep.
    ///
    /// `Err(LayoutError::CoordinateOutOfRange(_))` is a pass — `W` may leave the
    /// representable domain — but only that one variant, since a reader refusing
    /// every wrapped library would otherwise satisfy the law.
    ///
    /// Oracle: metamorphic relation, transform equivariance: clauses (a) to (c)
    /// above, the unwrapped result through `W`.
    #[test]
    fn wrapping_the_root_in_one_transformed_instance_transforms_the_whole_store() {
        use gpurify_geom::MAX_ABS_DBU;

        let mut strings = StrTable::default();
        let deck = three_layer_deck(&mut strings);

        let base = read(&nested_mirror_library(None), &deck, UnknownLayers::Reject)
            .expect("the unwrapped library is well formed");

        // ---- anti-vacuity: every clause is quantified over rows, layers and
        // labels, so a reader producing none of them satisfies all of them.
        assert_eq!(
            base.store.poly_count(),
            5,
            "the base fixture is one ring in TOP plus two rings under each of \
             the two LEAF placements"
        );
        for layer in 0..3u16 {
            assert!(
                !base.store.polys_on_layer(LayerId(layer)).is_empty(),
                "layer {layer} is empty, so clause (a) has nothing to compare \
                 on it"
            );
        }
        assert_eq!(
            base.provenance.placed.len(),
            2,
            "one TEXT in LEAF and two placements of LEAF, so clause (c) needs \
             two points to move"
        );
        // Both rings on layer 0 are the same drawn triangle, differing only by
        // the mirror inside MID composed with TOP's quarter turn.
        let relative = |(xs, ys): &(Vec<i64>, Vec<i64>)| -> Vec<(i64, i64)> {
            xs.iter()
                .zip(ys)
                .map(|(x, y)| (x - xs[0], y - ys[0]))
                .collect()
        };
        assert_ne!(
            relative(&verts(&base.store, 0)),
            relative(&verts(&base.store, 1)),
            "the two LEAF placements came out congruent by translation, so the \
             base library no longer contains a mirror and the depth half of \
             this law is untested"
        );

        // ---- the transforms, every one representable on this fixture.
        let warps = [
            Warp {
                mag: 1,
                reflect: false,
                quarters: 0,
                dx: 0,
                dy: 0,
            },
            Warp {
                mag: 1,
                reflect: false,
                quarters: 0,
                dx: -7_000,
                dy: 3_000,
            },
            Warp {
                mag: 1,
                reflect: true,
                quarters: 0,
                dx: 0,
                dy: 0,
            },
            Warp {
                mag: 1,
                reflect: false,
                quarters: 1,
                dx: 0,
                dy: 0,
            },
            Warp {
                mag: 1,
                reflect: true,
                quarters: 3,
                dx: 1_234,
                dy: -5_678,
            },
            Warp {
                mag: 3,
                reflect: true,
                quarters: 1,
                dx: -1_000,
                dy: 2_000,
            },
            Warp {
                mag: 3,
                reflect: false,
                quarters: 2,
                dx: 500,
                dy: -500,
            },
        ];
        assert!(
            warps.iter().any(|w| w.reflect)
                && warps.iter().any(|w| !w.reflect)
                && warps.iter().any(|w| w.quarters != 0)
                && warps.iter().any(|w| w.mag > 1),
            "the table has to reach both halves of clause (b), a rotation and a \
             magnification, or it tests translation only"
        );

        for (index, w) in warps.into_iter().enumerate() {
            let what = format!(
                "W#{index} (mag {}, reflect {}, q {}, d ({}, {}))",
                w.mag, w.reflect, w.quarters, w.dx, w.dy
            );
            let wrapped = read(
                &nested_mirror_library(Some(w)),
                &deck,
                UnknownLayers::Reject,
            )
            .unwrap_or_else(|e| {
                panic!(
                    "{what}: every coordinate it produces is inside \
                     ±MAX_ABS_DBU, so refusing it is a defect, not the \
                     out-of-range escape: {e}"
                )
            });

            // (a)
            assert_eq!(
                wrapped.store.poly_count(),
                base.store.poly_count(),
                "{what}: a rigid motion created or destroyed a row"
            );
            for layer in 0..3u16 {
                assert_eq!(
                    wrapped.store.polys_on_layer(LayerId(layer)),
                    base.store.polys_on_layer(LayerId(layer)),
                    "{what}: layer {layer} holds a different row range"
                );
            }

            for row in 0..5u32 {
                assert_eq!(
                    wrapped.store.poly_layer(PolyId(row)),
                    base.store.poly_layer(PolyId(row)),
                    "{what}: row {row} moved to another layer"
                );

                // (b)
                let (bxs, bys) = verts(&base.store, row);
                let n = bxs.len();
                let order: Vec<usize> = if w.reflect {
                    std::iter::once(0).chain((1..n).rev()).collect()
                } else {
                    (0..n).collect()
                };
                let want: (Vec<i64>, Vec<i64>) =
                    order.iter().map(|&j| w.apply(bxs[j], bys[j])).unzip();
                assert_eq!(
                    verts(&wrapped.store, row),
                    want,
                    "{what}: row {row} is not the base row through W; a \
                     reflecting W reverses [1..] and fixes vertex 0, and \
                     nothing else may move"
                );
            }

            // (c)
            let (before, after) = (&base.provenance.placed, &wrapped.provenance.placed);
            assert_eq!(after.len(), before.len(), "{what}: the label count changed");
            for (row, (b, a)) in before.iter().zip(after).enumerate() {
                let (x, y) = w.apply(b.at.x.raw(), b.at.y.raw());
                assert_eq!(
                    (a.at.x.raw(), a.at.y.raw()),
                    (x, y),
                    "{what}: label {row} did not take the same transform its \
                     geometry took"
                );
                assert_eq!(a.layer, b.layer, "{what}: label {row} changed layer");
                assert_eq!(
                    wrapped.strings.resolve(a.name),
                    base.strings.resolve(b.name),
                    "{what}: label {row} changed name"
                );
            }
        }

        // The escape is real, not a blanket: a magnification of 10⁶ lands TOP's
        // ring at 2·10¹², past MAX_ABS_DBU. `CoordinateOutOfRange` specifically.
        let overflow = Warp {
            mag: 1_000_000,
            reflect: false,
            quarters: 0,
            dx: 0,
            dy: 0,
        };
        match read(
            &nested_mirror_library(Some(overflow)),
            &deck,
            UnknownLayers::Reject,
        ) {
            Err(LayoutError::CoordinateOutOfRange(value)) => assert!(
                value.unsigned_abs() > MAX_ABS_DBU.unsigned_abs(),
                "the reported coordinate {value} is inside the domain it was \
                 refused for"
            ),
            other => panic!(
                "a magnification that leaves the representable domain must be \
                 refused as CoordinateOutOfRange, not as {other:?}"
            ),
        }
    }

    /// The placement kernels match their scalar oracles at every length around the
    /// lane count, on random and edge values.
    ///
    /// Oracle: differential against `max_abs_scalar` and `shift_scalar`, at
    /// every length 0 to 13 around the lane count, on random and edge values.
    #[test]
    fn the_placement_kernels_agree_with_their_scalar_versions() {
        use fearless_simd::{dispatch, Level};
        let level = Level::new();
        let mut rng = gpurify_testgen::Rng::new(7);
        let edges = [0, 1, -1, i64::MAX, i64::MIN, 1 << 40, -(1 << 40)];
        for len in 0..=13 {
            for round in 0..20 {
                let mut col = |salt: usize| -> Vec<i64> {
                    (0..len)
                        .map(|i| match (round + i + salt) % 5 {
                            0 => edges[(i + round) % edges.len()],
                            _ => rng.range(-(1 << 41), 1 << 41),
                        })
                        .collect()
                };
                let (xs, ys) = (col(0), col(3));
                let want = gds::max_abs_scalar(&xs).max(gds::max_abs_scalar(&ys));
                assert_eq!(
                    dispatch!(level, s => gds::max_abs(s, &xs, &ys)),
                    want,
                    "len {len}"
                );

                // `shift`'s contract: no overflow, so in-domain inputs only.
                let src: Vec<i64> = xs.iter().map(|&v| v.clamp(-(1 << 41), 1 << 41)).collect();
                for (neg, d) in [(false, 0), (true, 5), (false, -(1 << 40)), (true, 1 << 40)] {
                    let (mut got, mut want) = (vec![0; len], vec![0; len]);
                    dispatch!(level, s => gds::shift(s, &src, neg, d, &mut got));
                    gds::shift_scalar(&src, neg, d, &mut want);
                    assert_eq!(got, want, "len {len}, neg {neg}, d {d}");
                }
            }
        }
    }

    /// Every derived operation through the deck text and the flattener. `met1`
    /// is an L: a 4 um arm `[0,4]x[0,10]` and a 2 um arm `[0,10]x[0,2]` (um).
    /// `met2` holds s1 inside the L, s2 touching its 4 um arm from outside, s3
    /// far away, and s4 straddling the 2 um arm's end. Expected areas and
    /// lengths are worked out by hand from those coordinates.
    ///
    /// Oracle: hand-derived. Each derived layer's areas and lengths are worked
    /// out from the coordinates above under the operation's definition in
    /// `docs/deck.md`, Layers.
    #[test]
    fn every_derived_operation_reads_through_the_deck_into_the_store() {
        let deck_text = "grid 1nm
layer met1 = gds(68, 20)
layer met2 = gds(69, 20)
layer huge = met1.sized(-1um).sized(1um)
layer near = met2.interacting(met1)
layer apart = met2.not_interacting(met1)
layer inner = met2.inside(met1)
layer out = met2.outside(met1)
layer big = met2.with_area(>= 4um2)
layer small = met2.with_area(< 4um2)
layer narrow = met1.with_width(< 3um)
layer box = met1.extents()
layer gaps = met1.holes()
layer e = met1.edges()
layer e_in = e.inside_part(met2)
layer long = e.with_length(>= 10um)
rule huge.w width(huge) >= 1um
";
        let mut strings = StrTable::default();
        let grid = gpurify_geom::Grid::new(1000).expect("1 nm");
        let deck = crate::deck::parse_deck(deck_text, grid, &mut strings).expect("parses");
        let bytes = gds_library(
            "TOP",
            &[
                boundary(
                    68,
                    20,
                    &[0, 10000, 10000, 4000, 4000, 0],
                    &[0, 0, 2000, 2000, 10000, 10000],
                ),
                boundary(69, 20, &[1000, 3000, 3000, 1000], &[5000, 5000, 7000, 7000]),
                boundary(69, 20, &[4000, 6000, 6000, 4000], &[3000, 3000, 5000, 5000]),
                boundary(69, 20, &[20000, 21000, 21000, 20000], &[0, 0, 1000, 1000]),
                boundary(
                    69,
                    20,
                    &[8000, 12000, 12000, 8000],
                    &[-1000, -1000, 1000, 1000],
                ),
            ],
        );
        let library = gds::Library::parse(&bytes, &mut strings).expect("parses");
        let (store, _) = library
            .flatten(&deck, &strings, UnknownLayers::Reject)
            .expect("flattens");
        let id = |name: &str| deck.layers.id(&strings, name).expect(name);
        let um2 = 1_000_000i128;
        let area = |name: &str| -> i128 {
            store
                .polys_on_layer(id(name))
                .map(|row| {
                    let (xs, ys) = store.poly_verts(PolyId(row));
                    gpurify_geom::ops::area2(xs, ys).raw()
                })
                .sum::<i128>()
                / 2
        };
        let count = |name: &str| store.polys_on_layer(id(name)).len();

        assert_eq!(
            area("huge"),
            40 * um2,
            "the 2 um arm is not wider than 2 um"
        );
        assert_eq!((count("near"), area("near")), (3, 16 * um2));
        assert_eq!((count("apart"), area("apart")), (1, um2));
        assert_eq!((count("inner"), area("inner")), (1, 4 * um2));
        assert_eq!(
            (count("out"), area("out")),
            (2, 5 * um2),
            "touching is outside"
        );
        assert_eq!(count("big"), 3);
        assert_eq!(count("small"), 1);
        assert_eq!(
            area("narrow"),
            52 * um2,
            "the whole L, 2 um at its narrowest"
        );
        assert_eq!(area("box"), 100 * um2);
        assert_eq!(count("gaps"), 0);

        let length = |name: &str| -> i64 {
            store
                .edges_on_layer(id(name))
                .iter()
                .map(|s| (s.b.x - s.a.x).abs().raw() + (s.b.y - s.a.y).abs().raw())
                .sum()
        };
        assert!(deck.layers.is_edges(id("e")) && deck.layers.is_edges(id("long")));
        assert!(!deck.layers.is_edges(id("huge")));
        assert_eq!(
            (store.edges_on_layer(id("e")).len(), length("e")),
            (6, 40_000)
        );
        assert_eq!(
            length("e_in"),
            2000 + 1000,
            "the L's bottom and end inside s4"
        );
        assert_eq!(store.edges_on_layer(id("long")).len(), 2);
        assert_eq!(
            store.polys_on_layer(id("e")).len(),
            0,
            "an edge layer has no polygons"
        );

        let rule = &deck.rules.spec[0];
        assert_eq!(deck.rules.layers_of(rule), [id("huge")]);
    }

    /// IHP picks devices by their text (`ext_interacting_with_text(..,
    /// "npn13G2*")`). Squares labelled "npn13G2" and, on the square's edge,
    /// "npn13G2L" match the glob; "pnpMPA" does not. An L whose label sits in
    /// its notch, inside its bounding box but off the shape, holds no text, and
    /// a matching string on another text layer is not read.
    ///
    /// Oracle: construct-from-answer, under `with_text` as `docs/deck.md`
    /// defines it (`*` any run, `?` one character, a text on the edge counts,
    /// `T` a drawn layer): the squares at 0 and 200 hold a match, the others do
    /// not.
    #[test]
    fn with_text_keeps_the_shapes_holding_a_matching_text() {
        let mut strings = StrTable::default();
        let grid = gpurify_geom::Grid::new(1000).expect("1 nm");
        let deck = crate::deck::parse_deck(
            "grid 5nm
layer activ = gds(1, 0)
layer text = gds(63, 0)
layer other = gds(63, 25)
layer npn = activ.with_text(text, \"npn13G2*\")
layer rest = activ.without_text(text, \"npn13G2*\")
",
            grid,
            &mut strings,
        )
        .expect("the deck parses");
        let square = |x: i64| boundary(1, 0, &[x, x + 100, x + 100, x], &[0, 0, 100, 100]);
        let l_shape = boundary(
            1,
            0,
            &[600, 900, 900, 700, 700, 600],
            &[0, 0, 100, 100, 400, 400],
        );
        let bytes = gds_labelled(
            "TOP",
            &[square(0), square(200), square(400), l_shape, square(1_000)],
            &[
                label(63, 0, 50, 50, "npn13G2"),
                label(63, 0, 300, 50, "npn13G2L"),
                label(63, 0, 450, 50, "pnpMPA"),
                label(63, 0, 800, 300, "npn13G2"),
                label(63, 25, 1_050, 50, "npn13G2"),
            ],
        );
        let layout = read(&bytes, &deck, UnknownLayers::Reject).expect("reads");
        let boxes = |name: &str| {
            let layer = deck.layers.id(&strings, name).expect("declared");
            layout
                .store
                .polys_on_layer(layer)
                .map(|row| {
                    let b = layout.store.poly_bbox(PolyId(row));
                    (b.xlo.raw(), b.xhi.raw(), b.yhi.raw())
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(boxes("npn"), [(0, 100, 100), (200, 300, 100)]);
        assert_eq!(
            boxes("rest"),
            [(400, 500, 100), (600, 900, 400), (1_000, 1_100, 100)]
        );
    }

    /// Oracle: the glob `docs/deck.md` documents for `with_text`: `*` any run,
    /// `?` one character, every other character itself, case included, over the
    /// whole text; each pair is decided by hand (`[V]DD` is literal).
    #[test]
    fn a_glob_matches_the_whole_text() {
        use super::glob_matches;
        for (pattern, text) in [
            ("VDD", "VDD"),
            ("VDD*", "VDD"),
            ("VDD*", "VDDIO"),
            ("*IO", "VDDIO"),
            ("V?D", "VDD"),
            ("a*b*c", "axxbyyc"),
            ("*", ""),
        ] {
            assert!(glob_matches(pattern, text), "{pattern} {text}");
        }
        for (pattern, text) in [
            ("VDD", "VDDIO"),
            ("VDD", "vdd"),
            ("V?D", "VD"),
            ("*IO", "VDDIOX"),
            ("a*b*c", "axxbyy"),
            ("[V]DD", "VDD"),
        ] {
            assert!(!glob_matches(pattern, text), "{pattern} {text}");
        }
    }
}
