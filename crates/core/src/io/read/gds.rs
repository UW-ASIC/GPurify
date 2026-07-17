//! Unified GDSII reader/writer.
//!
//! One lossless record database ([`GdsLibrary`]) is the single source of
//! truth: [`read_gds_library`] parses (strict or compatibility mode),
//! [`flatten_gds_library`] resolves hierarchy into per-cell
//! [`GeometryStore`]s ([`GdsLayout`]), and [`write_gds_library`] round-trips.
//! The checked entry points [`read_gds`] / [`read_gds_checked`] are the
//! layout-facing convenience wrappers over that one pipeline — there is no
//! second parser.
//!
//! GDSII is a big-endian, record-based binary format. A record is:
//!   [u16 length][u8 rec_type][u8 data_type][payload...]

/// Unit metadata from the GDS `UNITS` record. Geometry coordinates remain the
/// exact signed database-unit integers stored in the file; the reader never
/// rescales or rounds them.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct GdsUnits {
    /// Size of one database unit expressed in the library's user unit.
    pub user_units_per_database_unit: f64,
    /// Size of one database unit in meters.
    pub meters_per_database_unit: f64,
}

impl GdsUnits {
    /// Size of one database unit in nanometers.
    pub fn database_unit_nm(self) -> f64 {
        self.meters_per_database_unit * 1.0e9
    }
}

/// Geometry records whose GDS `(layer, datatype)` pair was not present in the
/// supplied [`LayerTable`]. Entries are sorted by `(layer, datatype)` so callers
/// can deterministically reject, waive, or report them. TEXT records remain raw
/// metadata in each [`GeometryStore`] and are not counted here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GdsUnmappedLayer {
    pub layer: i32,
    pub datatype: i32,
    pub element_count: usize,
}

/// Parsed GDS: one flattened `GeometryStore` per cell (structure), keyed by name.
pub struct GdsLayout {
    pub cells: HashMap<String, GeometryStore>,
    /// Cells not referenced by any other cell (usually exactly one on real layouts).
    pub top_cells: Vec<String>,
    /// Parsed `UNITS` metadata. `None` preserves compatibility with legacy
    /// record streams that omit the otherwise-standard library record.
    pub units: Option<GdsUnits>,
    /// Counted BOUNDARY/BOX/PATH records on layer pairs absent from the supplied
    /// layer table. Unmapped geometry is never silently invisible to callers.
    pub unmapped_geometry: Vec<GdsUnmappedLayer>,
}
/// Backward-compatible checked import. Structure-only legacy fixtures use
/// compatibility parsing, but all geometry reaches verification through the
/// lossless database and exact flatten adapter.
pub fn read_gds(bytes: &[u8], lt: &LayerTable) -> Result<GdsLayout, String> {
    let options = GdsFlattenOptions {
        geometry_policy: GdsGeometryPolicy::PreserveInvalidForPolygonValidity,
        ..Default::default()
    };
    read_gds_checked(bytes, GdsReadMode::Compatibility, lt, &options)
}

/// Explicit parse/geometry policy entry point. Signoff callers should select
/// `GdsReadMode::Strict` with the default strict flatten options.
pub fn read_gds_checked(
    bytes: &[u8],
    mode: GdsReadMode,
    lt: &LayerTable,
    options: &GdsFlattenOptions,
) -> Result<GdsLayout, String> {
    let library = read_gds_library(bytes, mode).map_err(|error| error.to_string())?;
    flatten_gds_library(&library, lt, options).map_err(|error| error.to_string())
}

// Lossless, hierarchy-preserving GDSII ingestion and checked verification flattening.
//
// Parsing and verification are intentionally separate. [`read_gds_library`] retains
// records which the polygon checkers do not understand. [`flatten_gds_library`] is the
// only bridge to [`GeometryStore`], and fails when a retained construct cannot be
// represented exactly. This prevents a valid stream from becoming an approximate
// verification database without an explicit error.

use crate::geometry::exact::{Point, Ring};
use crate::geometry::GeometryStore;
use crate::params::LayerTable;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;

pub const HEADER: u8 = 0x00;
pub const BGNLIB: u8 = 0x01;
pub const LIBNAME: u8 = 0x02;
pub const UNITS: u8 = 0x03;
pub const ENDLIB: u8 = 0x04;
pub const BGNSTR: u8 = 0x05;
pub const STRNAME: u8 = 0x06;
pub const ENDSTR: u8 = 0x07;
pub const BOUNDARY: u8 = 0x08;
pub const PATH: u8 = 0x09;
pub const SREF: u8 = 0x0a;
pub const AREF: u8 = 0x0b;
pub const TEXT: u8 = 0x0c;
pub const LAYER: u8 = 0x0d;
pub const DATATYPE: u8 = 0x0e;
pub const WIDTH: u8 = 0x0f;
pub const XY: u8 = 0x10;
pub const ENDEL: u8 = 0x11;
pub const SNAME: u8 = 0x12;
pub const COLROW: u8 = 0x13;
pub const TEXTNODE: u8 = 0x14;
pub const NODE: u8 = 0x15;
pub const TEXTTYPE: u8 = 0x16;
pub const PRESENTATION: u8 = 0x17;
pub const STRING: u8 = 0x19;
pub const STRANS: u8 = 0x1a;
pub const MAG: u8 = 0x1b;
pub const ANGLE: u8 = 0x1c;
pub const PATHTYPE: u8 = 0x21;
pub const ELFLAGS: u8 = 0x26;
pub const NODETYPE: u8 = 0x2a;
pub const PROPATTR: u8 = 0x2b;
pub const PROPVALUE: u8 = 0x2c;
pub const BOX: u8 = 0x2d;
pub const BOXTYPE: u8 = 0x2e;
pub const PLEX: u8 = 0x2f;
pub const BGNEXTN: u8 = 0x30;
pub const ENDEXTN: u8 = 0x31;

const DT_NONE: u8 = 0;
const DT_BIT_ARRAY: u8 = 1;
const DT_I16: u8 = 2;
const DT_I32: u8 = 3;
const DT_REAL8: u8 = 5;
const DT_ASCII: u8 = 6;

/// Strict mode requires the complete HEADER/BGNLIB/LIBNAME/UNITS/ENDLIB envelope.
/// Compatibility mode accepts the historic structure-only fixtures used by this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GdsReadMode {
    Strict,
    Compatibility,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayoutErrorKind {
    Malformed,
    InvalidOrder,
    Duplicate,
    Unsupported,
    UndefinedReference,
    HierarchyCycle,
    NonIntegralTransform,
    ArithmeticOverflow,
    CapacityExceeded,
}

/// Typed stream/layout failure. `offset` is present for input-record failures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayoutError {
    pub kind: LayoutErrorKind,
    pub offset: Option<usize>,
    pub message: String,
}

impl LayoutError {
    fn at(kind: LayoutErrorKind, offset: usize, message: impl Into<String>) -> Self {
        Self {
            kind,
            offset: Some(offset),
            message: message.into(),
        }
    }

    pub(crate) fn layout(kind: LayoutErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            offset: None,
            message: message.into(),
        }
    }
}

impl fmt::Display for LayoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(offset) = self.offset {
            write!(f, "GDS at byte offset {offset}: {}", self.message)
        } else {
            write!(f, "GDS: {}", self.message)
        }
    }
}

impl std::error::Error for LayoutError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GdsRawRecord {
    pub record_type: u8,
    pub data_type: u8,
    pub payload: Vec<u8>,
    pub source_offset: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GdsProperty {
    pub attribute: i16,
    /// Padding NUL is removed, but spaces and all other ASCII bytes are retained.
    pub value: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct GdsTransform {
    pub reflected: bool,
    pub absolute_magnification: bool,
    pub absolute_angle: bool,
    pub magnification: Option<f64>,
    pub angle_degrees: Option<f64>,
    /// Bits not assigned by the GDSII transform definition are retained here.
    pub reserved_bits: u16,
}

impl GdsTransform {
    pub fn magnification(self) -> f64 {
        self.magnification.unwrap_or(1.0)
    }
    pub fn angle_degrees(self) -> f64 {
        self.angle_degrees.unwrap_or(0.0)
    }
    pub fn raw_bits(self) -> u16 {
        (if self.reflected { 0x8000 } else { 0 })
            | (if self.absolute_magnification {
                0x0004
            } else {
                0
            })
            | (if self.absolute_angle { 0x0002 } else { 0 })
            | self.reserved_bits
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GdsElementMeta {
    pub properties: Vec<GdsProperty>,
    pub element_flags: Option<u16>,
    pub plex: Option<i32>,
    pub unhandled_records: Vec<GdsRawRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GdsBoundary {
    pub layer: i16,
    pub datatype: i16,
    /// Closed-ring coordinates without the repeated closing vertex.
    pub ring: Vec<Point>,
    pub meta: GdsElementMeta,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GdsPath {
    pub layer: i16,
    pub datatype: i16,
    pub centerline: Vec<Point>,
    pub width: Option<i32>,
    pub path_type: Option<i16>,
    pub begin_extension: Option<i32>,
    pub end_extension: Option<i32>,
    pub meta: GdsElementMeta,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GdsBoxElement {
    pub layer: i16,
    pub box_type: i16,
    pub ring: Vec<Point>,
    pub meta: GdsElementMeta,
}

#[derive(Clone, Debug, PartialEq)]
pub struct GdsText {
    pub layer: i16,
    pub text_type: i16,
    pub origin: Point,
    pub string: String,
    pub presentation: Option<u16>,
    pub path_type: Option<i16>,
    pub width: Option<i32>,
    pub transform: GdsTransform,
    pub meta: GdsElementMeta,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GdsNode {
    pub layer: i16,
    pub node_type: i16,
    pub points: Vec<Point>,
    pub meta: GdsElementMeta,
}

#[derive(Clone, Debug, PartialEq)]
pub struct GdsReference {
    pub structure: String,
    pub origin: Point,
    pub transform: GdsTransform,
    pub meta: GdsElementMeta,
}

#[derive(Clone, Debug, PartialEq)]
pub struct GdsArrayReference {
    pub structure: String,
    pub columns: u16,
    pub rows: u16,
    pub origin: Point,
    /// GDS array endpoint, not a pre-divided pitch vector.
    pub column_endpoint: Point,
    /// GDS array endpoint, not a pre-divided pitch vector.
    pub row_endpoint: Point,
    pub transform: GdsTransform,
    pub meta: GdsElementMeta,
}

#[derive(Clone, Debug, PartialEq)]
pub struct GdsUnsupportedElement {
    pub start_record: GdsRawRecord,
    pub records: Vec<GdsRawRecord>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum GdsElement {
    Boundary(GdsBoundary),
    Path(GdsPath),
    Box(GdsBoxElement),
    Text(GdsText),
    Node(GdsNode),
    Sref(GdsReference),
    Aref(GdsArrayReference),
    Unsupported(GdsUnsupportedElement),
}

impl GdsElement {
    pub fn meta(&self) -> Option<&GdsElementMeta> {
        match self {
            Self::Boundary(v) => Some(&v.meta),
            Self::Path(v) => Some(&v.meta),
            Self::Box(v) => Some(&v.meta),
            Self::Text(v) => Some(&v.meta),
            Self::Node(v) => Some(&v.meta),
            Self::Sref(v) => Some(&v.meta),
            Self::Aref(v) => Some(&v.meta),
            Self::Unsupported(_) => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct GdsStructure {
    pub timestamps: [i16; 12],
    pub name: String,
    pub elements: Vec<GdsElement>,
    pub unhandled_records: Vec<GdsRawRecord>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct GdsLibrary {
    pub version: i16,
    pub timestamps: [i16; 12],
    pub name: String,
    pub units: GdsUnits,
    /// File order is preserved.
    pub structures: Vec<GdsStructure>,
    pub unhandled_records: Vec<GdsRawRecord>,
    /// Which envelope records were present on input. A newly constructed library
    /// should use [`GdsEnvelope::complete`].
    pub envelope: GdsEnvelope,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GdsEnvelope {
    pub header: bool,
    pub bgnlib: bool,
    pub libname: bool,
    pub units: bool,
    pub endlib: bool,
}

impl GdsEnvelope {
    pub const fn complete() -> Self {
        Self {
            header: true,
            bgnlib: true,
            libname: true,
            units: true,
            endlib: true,
        }
    }
}

#[derive(Clone, Debug)]
struct Record {
    ty: u8,
    dt: u8,
    payload: Vec<u8>,
    offset: usize,
}

impl Record {
    fn raw(&self) -> GdsRawRecord {
        GdsRawRecord {
            record_type: self.ty,
            data_type: self.dt,
            payload: self.payload.clone(),
            source_offset: self.offset,
        }
    }
}

fn decode_records(bytes: &[u8]) -> Result<Vec<Record>, LayoutError> {
    let mut records = Vec::new();
    let mut pos = 0usize;
    while pos < bytes.len() {
        if bytes.len() - pos < 4 {
            return Err(LayoutError::at(
                LayoutErrorKind::Malformed,
                pos,
                format!(
                    "truncated record header ({} byte(s) remain)",
                    bytes.len() - pos
                ),
            ));
        }
        let len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
        if len < 4 || len & 1 != 0 {
            return Err(LayoutError::at(
                LayoutErrorKind::Malformed,
                pos,
                format!("invalid record length {len}; it must be even and at least four"),
            ));
        }
        let end = pos.checked_add(len).ok_or_else(|| {
            LayoutError::at(
                LayoutErrorKind::ArithmeticOverflow,
                pos,
                "record length overflow",
            )
        })?;
        if end > bytes.len() {
            return Err(LayoutError::at(
                LayoutErrorKind::Malformed,
                pos,
                format!(
                    "truncated record declares {len} bytes with only {} remaining",
                    bytes.len() - pos
                ),
            ));
        }
        let record = Record {
            ty: bytes[pos + 2],
            dt: bytes[pos + 3],
            payload: bytes[pos + 4..end].to_vec(),
            offset: pos,
        };
        validate_record_shape(&record)?;
        records.push(record);
        pos = end;
    }
    Ok(records)
}

fn validate_record_shape(r: &Record) -> Result<(), LayoutError> {
    let exact = |dt: u8, n: usize| {
        if r.dt != dt || r.payload.len() != n {
            Err(LayoutError::at(
                LayoutErrorKind::Malformed,
                r.offset,
                format!(
                    "record 0x{:02x} has data type 0x{:02x}/{} payload bytes; expected 0x{dt:02x}/{n}",
                    r.ty,
                    r.dt,
                    r.payload.len()
                ),
            ))
        } else {
            Ok(())
        }
    };
    let multiple = |dt: u8, n: usize| {
        if r.dt != dt || r.payload.len() % n != 0 {
            Err(LayoutError::at(
                LayoutErrorKind::Malformed,
                r.offset,
                format!(
                    "record 0x{:02x} has data type 0x{:02x}/{} payload bytes; expected data type 0x{dt:02x} and a multiple of {n}",
                    r.ty,
                    r.dt,
                    r.payload.len()
                ),
            ))
        } else {
            Ok(())
        }
    };
    match r.ty {
        HEADER => exact(DT_I16, 2),
        BGNLIB | BGNSTR => exact(DT_I16, 24),
        LIBNAME | STRNAME | SNAME | STRING | PROPVALUE => multiple(DT_ASCII, 2),
        UNITS => exact(DT_REAL8, 16),
        ENDLIB | ENDSTR | BOUNDARY | PATH | SREF | AREF | TEXT | TEXTNODE | NODE | BOX | ENDEL => {
            exact(DT_NONE, 0)
        }
        LAYER | DATATYPE | TEXTTYPE | PATHTYPE | NODETYPE | PROPATTR | BOXTYPE => exact(DT_I16, 2),
        WIDTH | PLEX | BGNEXTN | ENDEXTN => exact(DT_I32, 4),
        XY => multiple(DT_I32, 8),
        COLROW => exact(DT_I16, 4),
        PRESENTATION | STRANS | ELFLAGS => exact(DT_BIT_ARRAY, 2),
        MAG | ANGLE => exact(DT_REAL8, 8),
        _ => Ok(()),
    }
}

struct Cursor {
    records: Vec<Record>,
    at: usize,
}

impl Cursor {
    fn peek(&self) -> Option<&Record> {
        self.records.get(self.at)
    }
    fn next(&mut self) -> Option<Record> {
        let out = self.records.get(self.at).cloned();
        self.at += usize::from(out.is_some());
        out
    }
    fn take(&mut self, ty: u8, what: &str) -> Result<Record, LayoutError> {
        let r = self.next().ok_or_else(|| {
            LayoutError::layout(LayoutErrorKind::InvalidOrder, format!("missing {what}"))
        })?;
        if r.ty != ty {
            return Err(LayoutError::at(
                LayoutErrorKind::InvalidOrder,
                r.offset,
                format!("expected {what} (0x{ty:02x}), found 0x{:02x}", r.ty),
            ));
        }
        Ok(r)
    }
}

/// Parse an ordered, hierarchy-preserving GDSII library.
pub fn read_gds_library(bytes: &[u8], mode: GdsReadMode) -> Result<GdsLibrary, LayoutError> {
    let records = decode_records(bytes)?;
    let mut c = Cursor { records, at: 0 };
    let strict = mode == GdsReadMode::Strict;

    let had_header = c.peek().map(|r| r.ty) == Some(HEADER);
    let version = if had_header {
        i16_value(&c.next().unwrap())?
    } else if strict {
        return Err(missing_envelope("HEADER"));
    } else {
        600
    };
    let had_bgnlib = c.peek().map(|r| r.ty) == Some(BGNLIB);
    let timestamps = if had_bgnlib {
        timestamps(&c.next().unwrap())?
    } else if strict {
        return Err(missing_envelope("BGNLIB"));
    } else {
        [0; 12]
    };
    let had_libname = c.peek().map(|r| r.ty) == Some(LIBNAME);
    let name = if had_libname {
        ascii(&c.next().unwrap())?
    } else if strict {
        return Err(missing_envelope("LIBNAME"));
    } else {
        String::new()
    };
    let had_units = c.peek().map(|r| r.ty) == Some(UNITS);
    let units = if had_units {
        units(&c.next().unwrap())?
    } else if strict {
        return Err(missing_envelope("UNITS"));
    } else {
        // Compatibility is explicit. Callers using deck-aware load still reject a
        // missing original UNITS record before invoking this API.
        GdsUnits {
            user_units_per_database_unit: 1.0e-3,
            meters_per_database_unit: 1.0e-9,
        }
    };

    let mut structures = Vec::new();
    let mut unhandled_records = Vec::new();
    let mut names = HashSet::new();
    let mut saw_endlib = false;
    while let Some(r) = c.peek() {
        match r.ty {
            BGNSTR => {
                let structure = parse_structure(&mut c, strict)?;
                if !names.insert(structure.name.clone()) {
                    return Err(LayoutError::layout(
                        LayoutErrorKind::Duplicate,
                        format!("duplicate structure name `{}`", structure.name),
                    ));
                }
                structures.push(structure);
            }
            ENDLIB => {
                c.next();
                saw_endlib = true;
                break;
            }
            _ => unhandled_records.push(c.next().unwrap().raw()),
        }
    }
    if strict && !saw_endlib {
        return Err(missing_envelope("ENDLIB"));
    }
    if let Some(r) = c.peek() {
        return Err(LayoutError::at(
            LayoutErrorKind::InvalidOrder,
            r.offset,
            "data follows ENDLIB",
        ));
    }
    if strict && structures.is_empty() {
        return Err(LayoutError::layout(
            LayoutErrorKind::Malformed,
            "library has no structures",
        ));
    }
    Ok(GdsLibrary {
        version,
        timestamps,
        name,
        units,
        structures,
        unhandled_records,
        envelope: GdsEnvelope {
            header: had_header,
            bgnlib: had_bgnlib,
            libname: had_libname,
            units: had_units,
            endlib: saw_endlib,
        },
    })
}

fn missing_envelope(record: &str) -> LayoutError {
    LayoutError::layout(
        LayoutErrorKind::InvalidOrder,
        format!("strict input is missing {record}"),
    )
}

fn parse_structure(c: &mut Cursor, strict: bool) -> Result<GdsStructure, LayoutError> {
    let timestamps = timestamps(&c.take(BGNSTR, "BGNSTR")?)?;
    let name_record = c.take(STRNAME, "STRNAME")?;
    let name = ascii(&name_record)?;
    if name.is_empty() {
        return Err(LayoutError::at(
            LayoutErrorKind::Malformed,
            name_record.offset,
            "empty STRNAME",
        ));
    }
    let mut elements = Vec::new();
    let mut unhandled_records = Vec::new();
    loop {
        let r = c.peek().ok_or_else(|| {
            LayoutError::layout(
                LayoutErrorKind::InvalidOrder,
                format!("structure `{name}` is missing ENDSTR"),
            )
        })?;
        match r.ty {
            ENDSTR => {
                c.next();
                break;
            }
            ENDLIB => {
                return Err(LayoutError::at(
                    LayoutErrorKind::InvalidOrder,
                    r.offset,
                    "ENDLIB before ENDSTR",
                ));
            }
            BOUNDARY | PATH | BOX | TEXT | NODE | SREF | AREF | TEXTNODE => {
                elements.push(parse_element(c, strict)?);
            }
            _ if strict && is_element_attribute(r.ty) => {
                return Err(LayoutError::at(
                    LayoutErrorKind::InvalidOrder,
                    r.offset,
                    format!("element attribute 0x{:02x} outside an element", r.ty),
                ));
            }
            _ => unhandled_records.push(c.next().unwrap().raw()),
        }
    }
    Ok(GdsStructure {
        timestamps,
        name,
        elements,
        unhandled_records,
    })
}

fn is_element_attribute(ty: u8) -> bool {
    matches!(
        ty,
        LAYER
            | DATATYPE
            | WIDTH
            | XY
            | ENDEL
            | SNAME
            | COLROW
            | TEXTTYPE
            | PRESENTATION
            | STRING
            | STRANS
            | MAG
            | ANGLE
            | PATHTYPE
            | ELFLAGS
            | NODETYPE
            | PROPATTR
            | PROPVALUE
            | BOXTYPE
            | PLEX
            | BGNEXTN
            | ENDEXTN
    )
}

#[derive(Default)]
struct ElementFields {
    layer: Option<(i16, usize)>,
    datatype: Option<(i16, usize)>,
    width: Option<i32>,
    xy: Option<(Vec<Point>, usize)>,
    sname: Option<String>,
    colrow: Option<(u16, u16)>,
    presentation: Option<u16>,
    string: Option<String>,
    transform: GdsTransform,
    strans_seen: bool,
    path_type: Option<i16>,
    begin_extension: Option<i32>,
    end_extension: Option<i32>,
    meta: GdsElementMeta,
    pending_property: Option<(i16, usize)>,
}

fn parse_element(c: &mut Cursor, strict: bool) -> Result<GdsElement, LayoutError> {
    let start = c.next().unwrap();
    if start.ty == TEXTNODE {
        let mut records = Vec::new();
        loop {
            let r = c.next().ok_or_else(|| {
                LayoutError::at(
                    LayoutErrorKind::InvalidOrder,
                    start.offset,
                    "TEXTNODE is missing ENDEL",
                )
            })?;
            if r.ty == ENDEL {
                break;
            }
            records.push(r.raw());
        }
        return Ok(GdsElement::Unsupported(GdsUnsupportedElement {
            start_record: start.raw(),
            records,
        }));
    }

    let mut f = ElementFields::default();
    loop {
        let r = c.next().ok_or_else(|| {
            LayoutError::at(
                LayoutErrorKind::InvalidOrder,
                start.offset,
                "element is missing ENDEL",
            )
        })?;
        if r.ty == ENDEL {
            break;
        }
        match r.ty {
            LAYER => set_once(&mut f.layer, (i16_value(&r)?, r.offset), &r, "LAYER")?,
            DATATYPE | TEXTTYPE | NODETYPE | BOXTYPE => set_once(
                &mut f.datatype,
                (i16_value(&r)?, r.offset),
                &r,
                "element type",
            )?,
            WIDTH => set_once(&mut f.width, i32_value(&r)?, &r, "WIDTH")?,
            XY => set_once(&mut f.xy, (points(&r)?, r.offset), &r, "XY")?,
            SNAME => set_once(&mut f.sname, ascii(&r)?, &r, "SNAME")?,
            COLROW => {
                let a = i16::from_be_bytes([r.payload[0], r.payload[1]]);
                let b = i16::from_be_bytes([r.payload[2], r.payload[3]]);
                if a <= 0 || b <= 0 {
                    return Err(LayoutError::at(
                        LayoutErrorKind::Malformed,
                        r.offset,
                        "COLROW values must be positive",
                    ));
                }
                set_once(&mut f.colrow, (a as u16, b as u16), &r, "COLROW")?;
            }
            PRESENTATION => set_once(&mut f.presentation, u16_value(&r)?, &r, "PRESENTATION")?,
            STRING => set_once(&mut f.string, ascii(&r)?, &r, "STRING")?,
            STRANS => {
                let bits = u16_value(&r)?;
                let known = 0x8000 | 0x0004 | 0x0002;
                if f.strans_seen {
                    return Err(duplicate(&r, "STRANS"));
                }
                f.strans_seen = true;
                f.transform.reflected = bits & 0x8000 != 0;
                f.transform.absolute_magnification = bits & 0x0004 != 0;
                f.transform.absolute_angle = bits & 0x0002 != 0;
                f.transform.reserved_bits = bits & !known;
            }
            MAG => {
                if f.transform.magnification.is_some() {
                    return Err(duplicate(&r, "MAG"));
                }
                let v = real8(&r.payload, r.offset)?;
                if !v.is_finite() || v <= 0.0 {
                    return Err(LayoutError::at(
                        LayoutErrorKind::Malformed,
                        r.offset,
                        "MAG must be finite and positive",
                    ));
                }
                f.transform.magnification = Some(v);
            }
            ANGLE => {
                if f.transform.angle_degrees.is_some() {
                    return Err(duplicate(&r, "ANGLE"));
                }
                let v = real8(&r.payload, r.offset)?;
                if !v.is_finite() {
                    return Err(LayoutError::at(
                        LayoutErrorKind::Malformed,
                        r.offset,
                        "ANGLE must be finite",
                    ));
                }
                f.transform.angle_degrees = Some(v);
            }
            PATHTYPE => set_once(&mut f.path_type, i16_value(&r)?, &r, "PATHTYPE")?,
            BGNEXTN => set_once(&mut f.begin_extension, i32_value(&r)?, &r, "BGNEXTN")?,
            ENDEXTN => set_once(&mut f.end_extension, i32_value(&r)?, &r, "ENDEXTN")?,
            ELFLAGS => set_once(&mut f.meta.element_flags, u16_value(&r)?, &r, "ELFLAGS")?,
            PLEX => set_once(&mut f.meta.plex, i32_value(&r)?, &r, "PLEX")?,
            PROPATTR => {
                if f.pending_property.is_some() {
                    return Err(LayoutError::at(
                        LayoutErrorKind::InvalidOrder,
                        r.offset,
                        "PROPATTR before prior PROPVALUE",
                    ));
                }
                f.pending_property = Some((i16_value(&r)?, r.offset));
            }
            PROPVALUE => {
                let (attribute, _) = f.pending_property.take().ok_or_else(|| {
                    LayoutError::at(
                        LayoutErrorKind::InvalidOrder,
                        r.offset,
                        "PROPVALUE without PROPATTR",
                    )
                })?;
                f.meta.properties.push(GdsProperty {
                    attribute,
                    value: ascii(&r)?,
                });
            }
            _ => f.meta.unhandled_records.push(r.raw()),
        }
    }
    if let Some((_, offset)) = f.pending_property {
        return Err(LayoutError::at(
            LayoutErrorKind::InvalidOrder,
            offset,
            "PROPATTR without PROPVALUE",
        ));
    }
    build_element(start, f, strict)
}

fn set_once<T>(slot: &mut Option<T>, value: T, r: &Record, name: &str) -> Result<(), LayoutError> {
    if slot.is_some() {
        return Err(duplicate(r, name));
    }
    *slot = Some(value);
    Ok(())
}

fn duplicate(r: &Record, name: &str) -> LayoutError {
    LayoutError::at(
        LayoutErrorKind::Duplicate,
        r.offset,
        format!("duplicate {name}"),
    )
}

fn require<T>(value: Option<T>, start: &Record, what: &str) -> Result<T, LayoutError> {
    value.ok_or_else(|| {
        LayoutError::at(
            LayoutErrorKind::Malformed,
            start.offset,
            format!("element is missing {what}"),
        )
    })
}

fn build_element(start: Record, f: ElementFields, strict: bool) -> Result<GdsElement, LayoutError> {
    validate_element_fields(&start, &f)?;
    let layer = |f: &ElementFields| require(f.layer.map(|v| v.0), &start, "LAYER");
    let datatype = |f: &ElementFields, name| require(f.datatype.map(|v| v.0), &start, name);
    let xy = |f: &ElementFields| require(f.xy.clone().map(|v| v.0), &start, "XY");
    match start.ty {
        BOUNDARY => {
            let ring = closed_ring(xy(&f)?, f.xy.as_ref().unwrap().1, "BOUNDARY", strict)?;
            Ok(GdsElement::Boundary(GdsBoundary {
                layer: layer(&f)?,
                datatype: datatype(&f, "DATATYPE")?,
                ring,
                meta: f.meta,
            }))
        }
        BOX => {
            let ring = closed_ring(xy(&f)?, f.xy.as_ref().unwrap().1, "BOX", strict)?;
            if strict && ring.len() != 4 {
                return Err(LayoutError::at(
                    LayoutErrorKind::Malformed,
                    start.offset,
                    "BOX must contain exactly four non-closing vertices",
                ));
            }
            if strict && !is_axis_aligned_rectangle(&ring) {
                return Err(LayoutError::at(
                    LayoutErrorKind::Malformed,
                    start.offset,
                    "BOX must be an axis-aligned rectangle",
                ));
            }
            Ok(GdsElement::Box(GdsBoxElement {
                layer: layer(&f)?,
                box_type: datatype(&f, "BOXTYPE")?,
                ring,
                meta: f.meta,
            }))
        }
        PATH => {
            let centerline = xy(&f)?;
            if centerline.len() < 2 {
                return Err(LayoutError::at(
                    LayoutErrorKind::Malformed,
                    start.offset,
                    "PATH needs at least two points",
                ));
            }
            Ok(GdsElement::Path(GdsPath {
                layer: layer(&f)?,
                datatype: datatype(&f, "DATATYPE")?,
                centerline,
                width: f.width,
                path_type: f.path_type,
                begin_extension: f.begin_extension,
                end_extension: f.end_extension,
                meta: f.meta,
            }))
        }
        TEXT => {
            let pts = xy(&f)?;
            if pts.len() != 1 {
                return Err(LayoutError::at(
                    LayoutErrorKind::Malformed,
                    start.offset,
                    "TEXT needs exactly one point",
                ));
            }
            Ok(GdsElement::Text(GdsText {
                layer: layer(&f)?,
                text_type: datatype(&f, "TEXTTYPE")?,
                origin: pts[0],
                string: require(f.string, &start, "STRING")?,
                presentation: f.presentation,
                path_type: f.path_type,
                width: f.width,
                transform: f.transform,
                meta: f.meta,
            }))
        }
        NODE => {
            let points = xy(&f)?;
            if points.is_empty() {
                return Err(LayoutError::at(
                    LayoutErrorKind::Malformed,
                    start.offset,
                    "NODE needs at least one point",
                ));
            }
            Ok(GdsElement::Node(GdsNode {
                layer: layer(&f)?,
                node_type: datatype(&f, "NODETYPE")?,
                points,
                meta: f.meta,
            }))
        }
        SREF => {
            let pts = xy(&f)?;
            if pts.len() != 1 {
                return Err(LayoutError::at(
                    LayoutErrorKind::Malformed,
                    start.offset,
                    "SREF needs exactly one point",
                ));
            }
            Ok(GdsElement::Sref(GdsReference {
                structure: require(f.sname, &start, "SNAME")?,
                origin: pts[0],
                transform: f.transform,
                meta: f.meta,
            }))
        }
        AREF => {
            let pts = xy(&f)?;
            if pts.len() != 3 {
                return Err(LayoutError::at(
                    LayoutErrorKind::Malformed,
                    start.offset,
                    "AREF needs exactly three points",
                ));
            }
            let (columns, rows) = require(f.colrow, &start, "COLROW")?;
            Ok(GdsElement::Aref(GdsArrayReference {
                structure: require(f.sname, &start, "SNAME")?,
                columns,
                rows,
                origin: pts[0],
                column_endpoint: pts[1],
                row_endpoint: pts[2],
                transform: f.transform,
                meta: f.meta,
            }))
        }
        _ => unreachable!(),
    }
}

fn validate_element_fields(start: &Record, f: &ElementFields) -> Result<(), LayoutError> {
    let invalid = match start.ty {
        BOUNDARY | BOX => {
            f.width.is_some()
                || f.sname.is_some()
                || f.colrow.is_some()
                || f.presentation.is_some()
                || f.string.is_some()
                || f.strans_seen
                || f.path_type.is_some()
                || f.begin_extension.is_some()
                || f.end_extension.is_some()
        }
        PATH => {
            f.sname.is_some()
                || f.colrow.is_some()
                || f.presentation.is_some()
                || f.string.is_some()
                || f.strans_seen
        }
        TEXT => {
            f.sname.is_some()
                || f.colrow.is_some()
                || f.begin_extension.is_some()
                || f.end_extension.is_some()
        }
        NODE => {
            f.width.is_some()
                || f.sname.is_some()
                || f.colrow.is_some()
                || f.presentation.is_some()
                || f.string.is_some()
                || f.strans_seen
                || f.path_type.is_some()
                || f.begin_extension.is_some()
                || f.end_extension.is_some()
        }
        SREF => {
            f.layer.is_some()
                || f.datatype.is_some()
                || f.width.is_some()
                || f.colrow.is_some()
                || f.presentation.is_some()
                || f.string.is_some()
                || f.path_type.is_some()
                || f.begin_extension.is_some()
                || f.end_extension.is_some()
        }
        AREF => {
            f.layer.is_some()
                || f.datatype.is_some()
                || f.width.is_some()
                || f.presentation.is_some()
                || f.string.is_some()
                || f.path_type.is_some()
                || f.begin_extension.is_some()
                || f.end_extension.is_some()
        }
        _ => false,
    };
    if invalid {
        Err(LayoutError::at(
            LayoutErrorKind::InvalidOrder,
            start.offset,
            format!(
                "record set contains attributes invalid for element 0x{:02x}",
                start.ty
            ),
        ))
    } else {
        Ok(())
    }
}

fn is_axis_aligned_rectangle(ring: &[Point]) -> bool {
    if ring.len() != 4 {
        return false;
    }
    let xs: BTreeSet<i32> = ring.iter().map(|p| p.x).collect();
    let ys: BTreeSet<i32> = ring.iter().map(|p| p.y).collect();
    xs.len() == 2
        && ys.len() == 2
        && ring.iter().enumerate().all(|(i, a)| {
            let b = ring[(i + 1) % ring.len()];
            a.x == b.x || a.y == b.y
        })
}

fn closed_ring(
    mut points: Vec<Point>,
    offset: usize,
    kind: &str,
    validate_geometry: bool,
) -> Result<Vec<Point>, LayoutError> {
    if points.len() < 4 || points.first() != points.last() {
        return Err(LayoutError::at(
            LayoutErrorKind::Malformed,
            offset,
            format!("{kind} XY must be a closed ring with at least four points"),
        ));
    }
    points.pop();
    if validate_geometry {
        Ring::new(points.clone()).map_err(|e| {
            LayoutError::at(
                LayoutErrorKind::Malformed,
                offset,
                format!("invalid {kind} ring: {e}"),
            )
        })?;
    }
    Ok(points)
}

fn i16_value(r: &Record) -> Result<i16, LayoutError> {
    Ok(i16::from_be_bytes([r.payload[0], r.payload[1]]))
}

fn u16_value(r: &Record) -> Result<u16, LayoutError> {
    Ok(u16::from_be_bytes([r.payload[0], r.payload[1]]))
}

fn i32_value(r: &Record) -> Result<i32, LayoutError> {
    Ok(i32::from_be_bytes(r.payload[..4].try_into().unwrap()))
}

fn timestamps(r: &Record) -> Result<[i16; 12], LayoutError> {
    let mut out = [0; 12];
    for (i, chunk) in r.payload.chunks_exact(2).enumerate() {
        out[i] = i16::from_be_bytes([chunk[0], chunk[1]]);
    }
    Ok(out)
}

fn points(r: &Record) -> Result<Vec<Point>, LayoutError> {
    Ok(r.payload
        .chunks_exact(8)
        .map(|chunk| Point {
            x: i32::from_be_bytes(chunk[..4].try_into().unwrap()),
            y: i32::from_be_bytes(chunk[4..].try_into().unwrap()),
        })
        .collect())
}

fn ascii(r: &Record) -> Result<String, LayoutError> {
    let mut end = r.payload.len();
    if end > 0 && r.payload[end - 1] == 0 {
        end -= 1;
    }
    let bytes = &r.payload[..end];
    if !bytes.is_ascii() {
        return Err(LayoutError::at(
            LayoutErrorKind::Malformed,
            r.offset,
            "ASCII record contains a non-ASCII byte",
        ));
    }
    Ok(String::from_utf8(bytes.to_vec()).expect("ASCII is UTF-8"))
}

fn units(r: &Record) -> Result<GdsUnits, LayoutError> {
    let user = real8(&r.payload[..8], r.offset)?;
    let meters = real8(&r.payload[8..], r.offset)?;
    if !user.is_finite() || user <= 0.0 || !meters.is_finite() || meters <= 0.0 {
        return Err(LayoutError::at(
            LayoutErrorKind::Malformed,
            r.offset,
            "UNITS values must be finite and positive",
        ));
    }
    Ok(GdsUnits {
        user_units_per_database_unit: user,
        meters_per_database_unit: meters,
    })
}

fn real8(bytes: &[u8], offset: usize) -> Result<f64, LayoutError> {
    let sign = if bytes[0] & 0x80 == 0 { 1.0 } else { -1.0 };
    let exponent = i32::from(bytes[0] & 0x7f) - 64;
    let mut mantissa = 0_u64;
    for byte in &bytes[1..8] {
        mantissa = (mantissa << 8) | u64::from(*byte);
    }
    if mantissa == 0 {
        return Ok(0.0);
    }
    let result = sign * (mantissa as f64 / 2_f64.powi(56)) * 16_f64.powi(exponent);
    if result.is_finite() {
        Ok(result)
    } else {
        Err(LayoutError::at(
            LayoutErrorKind::Malformed,
            offset,
            "REAL8 value is not finite",
        ))
    }
}

// ---------------------------------------------------------------------------
// Deterministic writer
// ---------------------------------------------------------------------------

/// Serialize the supported GDSII record set. Unknown records retained by the
/// parser are re-emitted in deterministic scope order. The writer always emits a
/// complete envelope, even when the source was read in compatibility mode.
pub fn write_gds_library(library: &GdsLibrary) -> Result<Vec<u8>, LayoutError> {
    let mut out = Vec::new();
    put_i16(&mut out, HEADER, &[library.version])?;
    put_i16(&mut out, BGNLIB, &library.timestamps)?;
    put_ascii(&mut out, LIBNAME, &library.name)?;
    let mut unit_payload = Vec::with_capacity(16);
    unit_payload.extend_from_slice(&encode_real8(library.units.user_units_per_database_unit)?);
    unit_payload.extend_from_slice(&encode_real8(library.units.meters_per_database_unit)?);
    put_record(&mut out, UNITS, DT_REAL8, &unit_payload)?;
    put_raw_records(&mut out, &library.unhandled_records)?;
    for structure in &library.structures {
        put_i16(&mut out, BGNSTR, &structure.timestamps)?;
        put_ascii(&mut out, STRNAME, &structure.name)?;
        put_raw_records(&mut out, &structure.unhandled_records)?;
        for element in &structure.elements {
            write_element(&mut out, element)?;
        }
        put_record(&mut out, ENDSTR, DT_NONE, &[])?;
    }
    put_record(&mut out, ENDLIB, DT_NONE, &[])?;
    Ok(out)
}

fn write_element(out: &mut Vec<u8>, element: &GdsElement) -> Result<(), LayoutError> {
    match element {
        GdsElement::Boundary(v) => {
            put_record(out, BOUNDARY, DT_NONE, &[])?;
            put_i16(out, LAYER, &[v.layer])?;
            put_i16(out, DATATYPE, &[v.datatype])?;
            put_points(out, &v.ring, true)?;
            write_meta(out, &v.meta)?;
        }
        GdsElement::Path(v) => {
            put_record(out, PATH, DT_NONE, &[])?;
            put_i16(out, LAYER, &[v.layer])?;
            put_i16(out, DATATYPE, &[v.datatype])?;
            if let Some(path_type) = v.path_type {
                put_i16(out, PATHTYPE, &[path_type])?;
            }
            if let Some(width) = v.width {
                put_i32(out, WIDTH, &[width])?;
            }
            if let Some(extension) = v.begin_extension {
                put_i32(out, BGNEXTN, &[extension])?;
            }
            if let Some(extension) = v.end_extension {
                put_i32(out, ENDEXTN, &[extension])?;
            }
            put_points(out, &v.centerline, false)?;
            write_meta(out, &v.meta)?;
        }
        GdsElement::Box(v) => {
            put_record(out, BOX, DT_NONE, &[])?;
            put_i16(out, LAYER, &[v.layer])?;
            put_i16(out, BOXTYPE, &[v.box_type])?;
            put_points(out, &v.ring, true)?;
            write_meta(out, &v.meta)?;
        }
        GdsElement::Text(v) => {
            put_record(out, TEXT, DT_NONE, &[])?;
            put_i16(out, LAYER, &[v.layer])?;
            put_i16(out, TEXTTYPE, &[v.text_type])?;
            if let Some(presentation) = v.presentation {
                put_u16(out, PRESENTATION, &[presentation])?;
            }
            if let Some(path_type) = v.path_type {
                put_i16(out, PATHTYPE, &[path_type])?;
            }
            if let Some(width) = v.width {
                put_i32(out, WIDTH, &[width])?;
            }
            write_transform(out, v.transform)?;
            put_points(out, &[v.origin], false)?;
            put_ascii(out, STRING, &v.string)?;
            write_meta(out, &v.meta)?;
        }
        GdsElement::Node(v) => {
            put_record(out, NODE, DT_NONE, &[])?;
            put_i16(out, LAYER, &[v.layer])?;
            put_i16(out, NODETYPE, &[v.node_type])?;
            put_points(out, &v.points, false)?;
            write_meta(out, &v.meta)?;
        }
        GdsElement::Sref(v) => {
            put_record(out, SREF, DT_NONE, &[])?;
            put_ascii(out, SNAME, &v.structure)?;
            write_transform(out, v.transform)?;
            put_points(out, &[v.origin], false)?;
            write_meta(out, &v.meta)?;
        }
        GdsElement::Aref(v) => {
            put_record(out, AREF, DT_NONE, &[])?;
            put_ascii(out, SNAME, &v.structure)?;
            write_transform(out, v.transform)?;
            put_i16(out, COLROW, &[v.columns as i16, v.rows as i16])?;
            put_points(out, &[v.origin, v.column_endpoint, v.row_endpoint], false)?;
            write_meta(out, &v.meta)?;
        }
        GdsElement::Unsupported(v) => {
            put_raw_record(out, &v.start_record)?;
            put_raw_records(out, &v.records)?;
        }
    }
    put_record(out, ENDEL, DT_NONE, &[])
}

fn write_transform(out: &mut Vec<u8>, transform: GdsTransform) -> Result<(), LayoutError> {
    if transform.raw_bits() != 0 {
        put_u16(out, STRANS, &[transform.raw_bits()])?;
    }
    if let Some(mag) = transform.magnification {
        put_record(out, MAG, DT_REAL8, &encode_real8(mag)?)?;
    }
    if let Some(angle) = transform.angle_degrees {
        put_record(out, ANGLE, DT_REAL8, &encode_real8(angle)?)?;
    }
    Ok(())
}

fn write_meta(out: &mut Vec<u8>, meta: &GdsElementMeta) -> Result<(), LayoutError> {
    if let Some(flags) = meta.element_flags {
        put_u16(out, ELFLAGS, &[flags])?;
    }
    if let Some(plex) = meta.plex {
        put_i32(out, PLEX, &[plex])?;
    }
    for property in &meta.properties {
        put_i16(out, PROPATTR, &[property.attribute])?;
        put_ascii(out, PROPVALUE, &property.value)?;
    }
    put_raw_records(out, &meta.unhandled_records)
}

fn put_points(out: &mut Vec<u8>, points: &[Point], close: bool) -> Result<(), LayoutError> {
    let count = points.len() + usize::from(close);
    let mut payload = Vec::with_capacity(count.saturating_mul(8));
    for point in points
        .iter()
        .chain(if close { points.first() } else { None })
    {
        payload.extend_from_slice(&point.x.to_be_bytes());
        payload.extend_from_slice(&point.y.to_be_bytes());
    }
    put_record(out, XY, DT_I32, &payload)
}

fn put_i16(out: &mut Vec<u8>, ty: u8, values: &[i16]) -> Result<(), LayoutError> {
    let payload: Vec<u8> = values.iter().flat_map(|v| v.to_be_bytes()).collect();
    put_record(out, ty, DT_I16, &payload)
}

fn put_u16(out: &mut Vec<u8>, ty: u8, values: &[u16]) -> Result<(), LayoutError> {
    let payload: Vec<u8> = values.iter().flat_map(|v| v.to_be_bytes()).collect();
    put_record(out, ty, DT_BIT_ARRAY, &payload)
}

fn put_i32(out: &mut Vec<u8>, ty: u8, values: &[i32]) -> Result<(), LayoutError> {
    let payload: Vec<u8> = values.iter().flat_map(|v| v.to_be_bytes()).collect();
    put_record(out, ty, DT_I32, &payload)
}

fn put_ascii(out: &mut Vec<u8>, ty: u8, value: &str) -> Result<(), LayoutError> {
    if !value.is_ascii() {
        return Err(LayoutError::layout(
            LayoutErrorKind::Malformed,
            format!("record 0x{ty:02x} contains non-ASCII text"),
        ));
    }
    let mut payload = value.as_bytes().to_vec();
    if payload.len() & 1 != 0 {
        payload.push(0);
    }
    put_record(out, ty, DT_ASCII, &payload)
}

fn put_raw_records(out: &mut Vec<u8>, records: &[GdsRawRecord]) -> Result<(), LayoutError> {
    for record in records {
        put_raw_record(out, record)?;
    }
    Ok(())
}

fn put_raw_record(out: &mut Vec<u8>, record: &GdsRawRecord) -> Result<(), LayoutError> {
    put_record(out, record.record_type, record.data_type, &record.payload)
}

fn put_record(out: &mut Vec<u8>, ty: u8, dt: u8, payload: &[u8]) -> Result<(), LayoutError> {
    let len = payload.len().checked_add(4).ok_or_else(|| {
        LayoutError::layout(
            LayoutErrorKind::ArithmeticOverflow,
            "record length overflow",
        )
    })?;
    let len = u16::try_from(len).map_err(|_| {
        LayoutError::layout(
            LayoutErrorKind::CapacityExceeded,
            format!("record 0x{ty:02x} exceeds 65535 bytes"),
        )
    })?;
    if len & 1 != 0 {
        return Err(LayoutError::layout(
            LayoutErrorKind::Malformed,
            format!("record 0x{ty:02x} has odd encoded length"),
        ));
    }
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&[ty, dt]);
    out.extend_from_slice(payload);
    Ok(())
}

fn encode_real8(value: f64) -> Result<[u8; 8], LayoutError> {
    if !value.is_finite() {
        return Err(LayoutError::layout(
            LayoutErrorKind::Malformed,
            "cannot encode non-finite REAL8",
        ));
    }
    if value == 0.0 {
        return Ok([0; 8]);
    }
    let sign = if value < 0.0 { 0x80 } else { 0 };
    let mut mantissa = value.abs();
    let mut exponent = 64_i32;
    while mantissa >= 1.0 {
        mantissa /= 16.0;
        exponent += 1;
    }
    while mantissa < 1.0 / 16.0 {
        mantissa *= 16.0;
        exponent -= 1;
    }
    if !(0..=127).contains(&exponent) {
        return Err(LayoutError::layout(
            LayoutErrorKind::ArithmeticOverflow,
            "REAL8 exponent is out of range",
        ));
    }
    let fraction = (mantissa * 2_f64.powi(56)).round();
    if !(0.0..2_f64.powi(56)).contains(&fraction) {
        return Err(LayoutError::layout(
            LayoutErrorKind::ArithmeticOverflow,
            "REAL8 mantissa is out of range",
        ));
    }
    let mut out = (fraction as u64).to_be_bytes();
    out[0] = sign | exponent as u8;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Checked flatten adapter
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct GdsFlattenOptions {
    /// Maximum expanded element/instance visits across one flattened cell.
    pub expansion_limit: usize,
    /// If set, only this root cell is flattened and returned.
    pub selected_top: Option<String>,
    /// Policy for malformed-but-historically-observed BOUNDARY records.
    pub geometry_policy: GdsGeometryPolicy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GdsGeometryPolicy {
    /// Signoff/deck qualification: every polygon must be simple and non-zero-area.
    Strict,
    /// Legacy DRC corpus mode: retain a closed but invalid ring so the always-on
    /// `polygon_validity` checker can produce the expected diagnostic. No signoff
    /// flow should select this policy.
    PreserveInvalidForPolygonValidity,
}

impl Default for GdsFlattenOptions {
    fn default() -> Self {
        Self {
            expansion_limit: 10_000_000,
            selected_top: None,
            geometry_policy: GdsGeometryPolicy::Strict,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Affine {
    a: f64,
    b: f64,
    c: f64,
    d: f64,
    tx: f64,
    ty: f64,
}

impl Affine {
    pub(crate) const IDENTITY: Self = Self {
        a: 1.0,
        b: 0.0,
        c: 0.0,
        d: 1.0,
        tx: 0.0,
        ty: 0.0,
    };

    pub(crate) fn instance(transform: GdsTransform, origin: Point) -> Result<Self, LayoutError> {
        if transform.reserved_bits != 0 {
            return Err(LayoutError::layout(
                LayoutErrorKind::Unsupported,
                format!("STRANS reserved bits 0x{:04x}", transform.reserved_bits),
            ));
        }
        if transform.absolute_magnification || transform.absolute_angle {
            return Err(LayoutError::layout(
                LayoutErrorKind::Unsupported,
                "absolute MAG/ANGLE is retained losslessly but not yet supported by verification flattening",
            ));
        }
        let mag = transform.magnification();
        let angle = transform.angle_degrees().rem_euclid(360.0);
        let quarter = (angle / 90.0).round();
        let (sin, cos) = if (angle - quarter * 90.0).abs() <= 1.0e-12 {
            // Exact orthogonal — avoid trig rounding
            match (quarter as i64).rem_euclid(4) {
                0 => (0.0, 1.0),
                1 => (1.0, 0.0),
                2 => (0.0, -1.0),
                _ => (-1.0, 0.0),
            }
        } else {
            // ponytail: general-angle transform; coordinates are accepted only
            // when they land on exact integers (exact_i32 in Affine::apply).
            let radians = angle.to_radians();
            (radians.sin(), radians.cos())
        };
        let fy = if transform.reflected { -1.0 } else { 1.0 };
        Ok(Self {
            a: mag * cos,
            b: -mag * sin * fy,
            c: mag * sin,
            d: mag * cos * fy,
            tx: origin.x as f64,
            ty: origin.y as f64,
        })
    }

    pub(crate) fn compose(self, child: Self) -> Result<Self, LayoutError> {
        let out = Self {
            a: self.a * child.a + self.b * child.c,
            b: self.a * child.b + self.b * child.d,
            c: self.c * child.a + self.d * child.c,
            d: self.c * child.b + self.d * child.d,
            tx: self.a * child.tx + self.b * child.ty + self.tx,
            ty: self.c * child.tx + self.d * child.ty + self.ty,
        };
        if [out.a, out.b, out.c, out.d, out.tx, out.ty]
            .iter()
            .all(|v| v.is_finite())
        {
            Ok(out)
        } else {
            Err(LayoutError::layout(
                LayoutErrorKind::ArithmeticOverflow,
                "transform composition is not finite",
            ))
        }
    }

    pub(crate) fn apply(self, point: Point) -> Result<Point, LayoutError> {
        let x = self.a * point.x as f64 + self.b * point.y as f64 + self.tx;
        let y = self.c * point.x as f64 + self.d * point.y as f64 + self.ty;
        Ok(Point {
            x: exact_i32(x)?,
            y: exact_i32(y)?,
        })
    }

    fn reverses(self) -> bool {
        self.a * self.d - self.b * self.c < 0.0
    }
}

fn exact_i32(value: f64) -> Result<i32, LayoutError> {
    if !value.is_finite() || value < i32::MIN as f64 || value > i32::MAX as f64 {
        return Err(LayoutError::layout(
            LayoutErrorKind::ArithmeticOverflow,
            format!("transformed coordinate {value} is outside i32"),
        ));
    }
    let rounded = value.round();
    let tolerance = 1.0e-10 * value.abs().max(1.0);
    if (value - rounded).abs() > tolerance.min(1.0e-6) {
        return Err(LayoutError::layout(
            LayoutErrorKind::NonIntegralTransform,
            format!("transformed coordinate {value} is not an integer database unit"),
        ));
    }
    Ok(rounded as i32)
}

/// Convert a retained library to the legacy per-cell polygon stores without
/// approximation. Unsupported records, transforms, and path geometry are errors.
pub fn flatten_gds_library(
    library: &GdsLibrary,
    layers: &LayerTable,
    options: &GdsFlattenOptions,
) -> Result<GdsLayout, LayoutError> {
    if !library.unhandled_records.is_empty() {
        return Err(LayoutError::layout(
            LayoutErrorKind::Unsupported,
            "library contains unhandled records",
        ));
    }
    let by_name: HashMap<&str, &GdsStructure> = library
        .structures
        .iter()
        .map(|s| (s.name.as_str(), s))
        .collect();
    validate_hierarchy(library, &by_name)?;
    let referenced: HashSet<&str> = library
        .structures
        .iter()
        .flat_map(|s| {
            s.elements.iter().filter_map(|e| match e {
                GdsElement::Sref(v) => Some(v.structure.as_str()),
                GdsElement::Aref(v) => Some(v.structure.as_str()),
                _ => None,
            })
        })
        .collect();
    let mut top_cells: Vec<String> = library
        .structures
        .iter()
        .filter(|s| !referenced.contains(s.name.as_str()))
        .map(|s| s.name.clone())
        .collect();
    if let Some(selected) = &options.selected_top {
        if !by_name.contains_key(selected.as_str()) {
            return Err(LayoutError::layout(
                LayoutErrorKind::UndefinedReference,
                format!("selected top `{selected}` is undefined"),
            ));
        }
        top_cells = vec![selected.clone()];
    }

    let roots: Vec<&GdsStructure> = if options.selected_top.is_some() {
        vec![by_name[top_cells[0].as_str()]]
    } else {
        library.structures.iter().collect()
    };
    let mut cells = HashMap::new();
    let mut unmapped = BTreeMap::<(i32, i32), usize>::new();
    for root in roots {
        let mut store = GeometryStore::new();
        let mut visits = 0usize;
        let mut path = vec![root.name.clone()];
        append_structure(
            root,
            &by_name,
            layers,
            Affine::IDENTITY,
            &mut store,
            &mut unmapped,
            &mut visits,
            options.expansion_limit,
            options.geometry_policy,
            &mut path,
            &[],
        )?;
        cells.insert(root.name.clone(), store);
    }
    let unmapped_geometry = unmapped
        .into_iter()
        .map(|((layer, datatype), element_count)| GdsUnmappedLayer {
            layer,
            datatype,
            element_count,
        })
        .collect();
    Ok(GdsLayout {
        cells,
        top_cells,
        units: library.envelope.units.then_some(library.units),
        unmapped_geometry,
    })
}

pub(crate) fn validate_hierarchy<'a>(
    library: &'a GdsLibrary,
    by_name: &HashMap<&'a str, &'a GdsStructure>,
) -> Result<(), LayoutError> {
    for structure in &library.structures {
        if !structure.unhandled_records.is_empty() {
            return Err(LayoutError::layout(
                LayoutErrorKind::Unsupported,
                format!("structure `{}` contains unhandled records", structure.name),
            ));
        }
        for element in &structure.elements {
            if let GdsElement::Sref(v) = element {
                if !by_name.contains_key(v.structure.as_str()) {
                    return Err(LayoutError::layout(
                        LayoutErrorKind::UndefinedReference,
                        format!(
                            "`{}` references undefined `{}`",
                            structure.name, v.structure
                        ),
                    ));
                }
            }
            if let GdsElement::Aref(v) = element {
                if !by_name.contains_key(v.structure.as_str()) {
                    return Err(LayoutError::layout(
                        LayoutErrorKind::UndefinedReference,
                        format!(
                            "`{}` references undefined `{}`",
                            structure.name, v.structure
                        ),
                    ));
                }
            }
        }
    }
    fn visit<'a>(
        name: &'a str,
        by_name: &HashMap<&'a str, &'a GdsStructure>,
        gray: &mut HashSet<&'a str>,
        black: &mut HashSet<&'a str>,
    ) -> Result<(), LayoutError> {
        if black.contains(name) {
            return Ok(());
        }
        if !gray.insert(name) {
            return Err(LayoutError::layout(
                LayoutErrorKind::HierarchyCycle,
                format!("cycle through `{name}`"),
            ));
        }
        for child in by_name[name].elements.iter().filter_map(|e| match e {
            GdsElement::Sref(v) => Some(v.structure.as_str()),
            GdsElement::Aref(v) => Some(v.structure.as_str()),
            _ => None,
        }) {
            visit(child, by_name, gray, black)?;
        }
        gray.remove(name);
        black.insert(name);
        Ok(())
    }
    let mut gray = HashSet::new();
    let mut black = HashSet::new();
    for structure in &library.structures {
        visit(&structure.name, by_name, &mut gray, &mut black)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn append_structure(
    structure: &GdsStructure,
    by_name: &HashMap<&str, &GdsStructure>,
    layers: &LayerTable,
    transform: Affine,
    store: &mut GeometryStore,
    unmapped: &mut BTreeMap<(i32, i32), usize>,
    visits: &mut usize,
    limit: usize,
    geometry_policy: GdsGeometryPolicy,
    hierarchy_path: &mut Vec<String>,
    inherited_properties: &[(i16, String)],
) -> Result<(), LayoutError> {
    for (element_index, element) in structure.elements.iter().enumerate() {
        *visits = visits.checked_add(1).ok_or_else(|| {
            LayoutError::layout(
                LayoutErrorKind::ArithmeticOverflow,
                "expansion counter overflow",
            )
        })?;
        if *visits > limit {
            return Err(LayoutError::layout(
                LayoutErrorKind::CapacityExceeded,
                format!("hierarchy expansion exceeded {limit} visits"),
            ));
        }
        let own_properties: Vec<(i16, String)> = element
            .meta()
            .map(|m| {
                m.properties
                    .iter()
                    .map(|p| (p.attribute, p.value.clone()))
                    .collect()
            })
            .unwrap_or_default();
        let mut properties = inherited_properties.to_vec();
        properties.extend(own_properties);
        match element {
            GdsElement::Boundary(v) => {
                ensure_meta_supported(&v.meta, "BOUNDARY")?;
                append_ring(
                    v.layer,
                    v.datatype,
                    &v.ring,
                    transform,
                    layers,
                    store,
                    unmapped,
                    &properties,
                    hierarchy_path,
                    geometry_policy,
                )?;
            }
            GdsElement::Box(v) => {
                ensure_meta_supported(&v.meta, "BOX")?;
                append_ring(
                    v.layer,
                    v.box_type,
                    &v.ring,
                    transform,
                    layers,
                    store,
                    unmapped,
                    &properties,
                    hierarchy_path,
                    geometry_policy,
                )?;
            }
            GdsElement::Path(v) => {
                let polygons = stroke_path(v)?;
                for ring in polygons {
                    append_ring(
                        v.layer,
                        v.datatype,
                        &ring,
                        transform,
                        layers,
                        store,
                        unmapped,
                        &properties,
                        hierarchy_path,
                        geometry_policy,
                    )?;
                }
            }
            GdsElement::Text(v) => {
                if !v.meta.unhandled_records.is_empty() {
                    return Err(LayoutError::layout(
                        LayoutErrorKind::Unsupported,
                        "TEXT contains unhandled records",
                    ));
                }
                let point = transform.apply(v.origin)?;
                store.add_text_annotated(
                    v.layer as i32,
                    v.text_type as i32,
                    point.x,
                    point.y,
                    v.string.clone(),
                    properties,
                    hierarchy_path.clone(),
                );
            }
            GdsElement::Node(_) => {
                return Err(LayoutError::layout(
                    LayoutErrorKind::Unsupported,
                    format!(
                        "NODE at {}#{element_index} has no verification geometry representation",
                        structure.name
                    ),
                ));
            }
            GdsElement::Unsupported(v) => {
                return Err(LayoutError::layout(
                    LayoutErrorKind::Unsupported,
                    format!(
                        "element record 0x{:02x} is retained but unsupported for verification",
                        v.start_record.record_type
                    ),
                ));
            }
            GdsElement::Sref(v) => {
                ensure_meta_supported(&v.meta, "SREF")?;
                let local = Affine::instance(v.transform, v.origin)?;
                let composed = transform.compose(local)?;
                hierarchy_path.push(format!("{}@{element_index}", v.structure));
                append_structure(
                    by_name[v.structure.as_str()],
                    by_name,
                    layers,
                    composed,
                    store,
                    unmapped,
                    visits,
                    limit,
                    geometry_policy,
                    hierarchy_path,
                    &properties,
                )?;
                hierarchy_path.pop();
            }
            GdsElement::Aref(v) => {
                ensure_meta_supported(&v.meta, "AREF")?;
                let col_dx = exact_pitch(v.column_endpoint.x, v.origin.x, v.columns, "column x")?;
                let col_dy = exact_pitch(v.column_endpoint.y, v.origin.y, v.columns, "column y")?;
                let row_dx = exact_pitch(v.row_endpoint.x, v.origin.x, v.rows, "row x")?;
                let row_dy = exact_pitch(v.row_endpoint.y, v.origin.y, v.rows, "row y")?;
                for column in 0..v.columns {
                    for row in 0..v.rows {
                        let x = checked_array_coordinate(v.origin.x, col_dx, column, row_dx, row)?;
                        let y = checked_array_coordinate(v.origin.y, col_dy, column, row_dy, row)?;
                        let local = Affine::instance(v.transform, Point { x, y })?;
                        let composed = transform.compose(local)?;
                        hierarchy_path
                            .push(format!("{}@{element_index}[{column},{row}]", v.structure));
                        append_structure(
                            by_name[v.structure.as_str()],
                            by_name,
                            layers,
                            composed,
                            store,
                            unmapped,
                            visits,
                            limit,
                            geometry_policy,
                            hierarchy_path,
                            &properties,
                        )?;
                        hierarchy_path.pop();
                    }
                }
            }
        }
    }
    Ok(())
}

pub fn exact_pitch(endpoint: i32, origin: i32, count: u16, axis: &str) -> Result<i32, LayoutError> {
    let delta = i64::from(endpoint) - i64::from(origin);
    let count = i64::from(count);
    if delta % count != 0 {
        return Err(LayoutError::layout(
            LayoutErrorKind::NonIntegralTransform,
            format!("AREF {axis} pitch {delta}/{count} is non-integral"),
        ));
    }
    i32::try_from(delta / count).map_err(|_| {
        LayoutError::layout(
            LayoutErrorKind::ArithmeticOverflow,
            "AREF pitch outside i32",
        )
    })
}

pub(crate) fn checked_array_coordinate(
    origin: i32,
    a: i32,
    ai: u16,
    b: i32,
    bi: u16,
) -> Result<i32, LayoutError> {
    let value = i64::from(origin)
        .checked_add(i64::from(a) * i64::from(ai))
        .and_then(|v| v.checked_add(i64::from(b) * i64::from(bi)))
        .ok_or_else(|| {
            LayoutError::layout(LayoutErrorKind::ArithmeticOverflow, "AREF origin overflow")
        })?;
    i32::try_from(value).map_err(|_| {
        LayoutError::layout(
            LayoutErrorKind::ArithmeticOverflow,
            "AREF origin outside i32",
        )
    })
}

pub(crate) fn ensure_meta_supported(meta: &GdsElementMeta, kind: &str) -> Result<(), LayoutError> {
    if meta.unhandled_records.is_empty() {
        Ok(())
    } else {
        Err(LayoutError::layout(
            LayoutErrorKind::Unsupported,
            format!("{kind} contains unhandled records"),
        ))
    }
}

#[allow(clippy::too_many_arguments)]
fn append_ring(
    layer: i16,
    datatype: i16,
    ring: &[Point],
    transform: Affine,
    layers: &LayerTable,
    store: &mut GeometryStore,
    unmapped: &mut BTreeMap<(i32, i32), usize>,
    properties: &[(i16, String)],
    hierarchy_path: &[String],
    geometry_policy: GdsGeometryPolicy,
) -> Result<(), LayoutError> {
    let mut transformed: Vec<Point> = ring
        .iter()
        .copied()
        .map(|p| transform.apply(p))
        .collect::<Result<_, _>>()?;
    if transform.reverses() {
        transformed.reverse();
    }
    if geometry_policy == GdsGeometryPolicy::Strict {
        Ring::new(transformed.clone()).map_err(|e| {
            LayoutError::layout(
                LayoutErrorKind::Malformed,
                format!("transformed ring is invalid: {e}"),
            )
        })?;
    }
    if let Some(layer_id) = layers.from_gds(layer as i32, datatype as i32) {
        let points: Vec<(i32, i32)> = transformed.iter().map(|p| (p.x, p.y)).collect();
        store.add_polygon_annotated(
            layer_id,
            &points,
            properties.to_vec(),
            hierarchy_path.to_vec(),
        );
    } else {
        *unmapped.entry((layer as i32, datatype as i32)).or_default() += 1;
    }
    Ok(())
}

/// Exact integer stroking supported by the verification adapter. Rectilinear
/// centerlines with even positive width are represented as a union of rectangles.
/// Round caps, diagonal segments, negative absolute widths, and half-grid edges
/// are retained by the library parser but rejected here.
pub fn stroke_path(path: &GdsPath) -> Result<Vec<Vec<Point>>, LayoutError> {
    ensure_meta_supported(&path.meta, "PATH")?;
    let raw_width = path.width.ok_or_else(|| {
        LayoutError::layout(
            LayoutErrorKind::Unsupported,
            "zero/default-width PATH has no area representation",
        )
    })?;
    if raw_width <= 0 {
        return Err(LayoutError::layout(
            LayoutErrorKind::Unsupported,
            "non-positive/absolute PATH WIDTH is retained but not supported for verification",
        ));
    }
    if raw_width & 1 != 0 {
        return Err(LayoutError::layout(
            LayoutErrorKind::NonIntegralTransform,
            format!("PATH width {raw_width} requires half-grid edges"),
        ));
    }
    let path_type = path.path_type.unwrap_or(0);
    if path_type == 1 {
        return Err(LayoutError::layout(
            LayoutErrorKind::Unsupported,
            "round-cap PATHTYPE 1 cannot be represented by exact integer polygons",
        ));
    }
    if !matches!(path_type, 0 | 2 | 4) {
        return Err(LayoutError::layout(
            LayoutErrorKind::Unsupported,
            format!("PATHTYPE {path_type}"),
        ));
    }
    if path_type != 4 && (path.begin_extension.is_some() || path.end_extension.is_some()) {
        return Err(LayoutError::layout(
            LayoutErrorKind::Malformed,
            "BGNEXTN/ENDEXTN require PATHTYPE 4",
        ));
    }
    let half = raw_width / 2;
    let begin = match path_type {
        0 => 0,
        2 => half,
        4 => path.begin_extension.ok_or_else(|| {
            LayoutError::layout(LayoutErrorKind::Malformed, "PATHTYPE 4 is missing BGNEXTN")
        })?,
        _ => unreachable!(),
    };
    let end = match path_type {
        0 => 0,
        2 => half,
        4 => path.end_extension.ok_or_else(|| {
            LayoutError::layout(LayoutErrorKind::Malformed, "PATHTYPE 4 is missing ENDEXTN")
        })?,
        _ => unreachable!(),
    };
    let last =
        path.centerline.len().checked_sub(2).ok_or_else(|| {
            LayoutError::layout(LayoutErrorKind::Malformed, "PATH needs two points")
        })?;
    let mut polygons = Vec::with_capacity(last + 1);
    for index in 0..=last {
        let a = path.centerline[index];
        let b = path.centerline[index + 1];
        if a == b {
            return Err(LayoutError::layout(
                LayoutErrorKind::Malformed,
                format!("PATH has zero-length segment {index}"),
            ));
        }
        let start_extension = if index == 0 { begin } else { half };
        let end_extension = if index == last { end } else { half };
        let ring = if a.y == b.y {
            let direction = if b.x > a.x { 1 } else { -1 };
            let x0 = checked_sub_mul(a.x, direction, start_extension)?;
            let x1 = checked_add_mul(b.x, direction, end_extension)?;
            vec![
                Point::new(x0, checked_sub(a.y, half)?),
                Point::new(x1, checked_sub(a.y, half)?),
                Point::new(x1, checked_add(a.y, half)?),
                Point::new(x0, checked_add(a.y, half)?),
            ]
        } else if a.x == b.x {
            let direction = if b.y > a.y { 1 } else { -1 };
            let y0 = checked_sub_mul(a.y, direction, start_extension)?;
            let y1 = checked_add_mul(b.y, direction, end_extension)?;
            vec![
                Point::new(checked_sub(a.x, half)?, y0),
                Point::new(checked_add(a.x, half)?, y0),
                Point::new(checked_add(a.x, half)?, y1),
                Point::new(checked_sub(a.x, half)?, y1),
            ]
        } else {
            stroke_diagonal_segment(a, b, half, start_extension, end_extension, index)?
        };
        Ring::new(ring.clone()).map_err(|e| {
            LayoutError::layout(
                LayoutErrorKind::Malformed,
                format!("stroked PATH segment is invalid: {e}"),
            )
        })?;
        polygons.push(ring);
    }
    Ok(polygons)
}

/// Stroke a 45-degree diagonal PATH segment into a parallelogram ring.
///
/// For a segment from `a` to `b` with half-width `h`, the perpendicular offset
/// is `(-dy, dx) * h / len`. For exact 45° diagonals (`|dx| == |dy|`), the
/// perpendicular components are `h * |dy| / len` and `h * |dx| / len` which
/// equal `h / sqrt(2)`. Since `len = |dx| * sqrt(2)`, the offsets simplify to
/// `(-sign(dy) * h, sign(dx) * h)` *before* normalization, but the actual
/// perpendicular offset vector is `(-dy, dx) / len * h`.
///
/// For 45° diagonals where `|dx| == |dy| == d`, `len = d * sqrt(2)`, so the
/// perpendicular offset is `(-dy/len * h, dx/len * h) = (-sign(dy)*h/sqrt(2), sign(dx)*h/sqrt(2))`.
/// This is only exactly integer when `h` is a multiple of `sqrt(2)`, which is never
/// for integer `h`. So we compute in f64 and round, accepting the result only when
/// all coordinates land on exact integers (the `exact_i32` check).
// ponytail: non-45-degree diagonals emit Unsupported; add general-angle stroking
// only when real tapeouts need it (rare outside RF/analog).
fn stroke_diagonal_segment(
    a: Point,
    b: Point,
    half: i32,
    start_ext: i32,
    end_ext: i32,
    index: usize,
) -> Result<Vec<Point>, LayoutError> {
    let dx = (b.x as f64) - (a.x as f64);
    let dy = (b.y as f64) - (a.y as f64);
    let adx = dx.abs();
    let ady = dy.abs();

    // Only support exact 45° diagonals
    if (adx - ady).abs() > 0.5 {
        return Err(LayoutError::layout(
            LayoutErrorKind::Unsupported,
            format!(
                "non-45-degree diagonal PATH segment {index} ({},{})->({},{}) is not supported",
                a.x, a.y, b.x, b.y
            ),
        ));
    }

    let len = (dx * dx + dy * dy).sqrt();
    // Unit direction along segment
    let ux = dx / len;
    let uy = dy / len;
    // Perpendicular (left-hand normal)
    let px = -uy;
    let py = ux;

    let h = half as f64;
    let se = start_ext as f64;
    let ee = end_ext as f64;

    // Four corners of the stroked parallelogram:
    // Start edge, offset back along direction by start_ext
    // End edge, offset forward along direction by end_ext
    let ax = a.x as f64 - ux * se;
    let ay = a.y as f64 - uy * se;
    let bx = b.x as f64 + ux * ee;
    let by = b.y as f64 + uy * ee;

    let corners = [
        (ax + px * h, ay + py * h),
        (bx + px * h, by + py * h),
        (bx - px * h, by - py * h),
        (ax - px * h, ay - py * h),
    ];

    let ring: Vec<Point> = corners
        .iter()
        .map(|&(x, y)| Ok(Point::new(exact_i32(x)?, exact_i32(y)?)))
        .collect::<Result<_, LayoutError>>()?;

    Ok(ring)
}

fn checked_add(value: i32, delta: i32) -> Result<i32, LayoutError> {
    value.checked_add(delta).ok_or_else(|| {
        LayoutError::layout(
            LayoutErrorKind::ArithmeticOverflow,
            "PATH coordinate overflow",
        )
    })
}
fn checked_sub(value: i32, delta: i32) -> Result<i32, LayoutError> {
    value.checked_sub(delta).ok_or_else(|| {
        LayoutError::layout(
            LayoutErrorKind::ArithmeticOverflow,
            "PATH coordinate overflow",
        )
    })
}
fn checked_add_mul(value: i32, direction: i32, delta: i32) -> Result<i32, LayoutError> {
    checked_add(
        value,
        direction.checked_mul(delta).ok_or_else(|| {
            LayoutError::layout(
                LayoutErrorKind::ArithmeticOverflow,
                "PATH extension overflow",
            )
        })?,
    )
}
fn checked_sub_mul(value: i32, direction: i32, delta: i32) -> Result<i32, LayoutError> {
    checked_sub(
        value,
        direction.checked_mul(delta).ok_or_else(|| {
            LayoutError::layout(
                LayoutErrorKind::ArithmeticOverflow,
                "PATH extension overflow",
            )
        })?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::LayerDef;

    fn layer_table() -> LayerTable {
        LayerTable::from_defs(
            &[(
                "met1".to_string(),
                LayerDef {
                    layer: 7,
                    datatype: 0,
                },
            )]
            .into_iter()
            .collect(),
        )
    }

    fn meta(attribute: i16, value: &str) -> GdsElementMeta {
        GdsElementMeta {
            properties: vec![GdsProperty {
                attribute,
                value: value.to_string(),
            }],
            ..Default::default()
        }
    }

    fn rectangle(x0: i32, y0: i32, x1: i32, y1: i32) -> Vec<Point> {
        vec![
            Point::new(x0, y0),
            Point::new(x1, y0),
            Point::new(x1, y1),
            Point::new(x0, y1),
        ]
    }

    fn complete_library(structures: Vec<GdsStructure>) -> GdsLibrary {
        GdsLibrary {
            version: 600,
            timestamps: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            name: "lossless library ".to_string(),
            units: GdsUnits {
                user_units_per_database_unit: 1.0e-3,
                meters_per_database_unit: 1.0e-9,
            },
            structures,
            unhandled_records: Vec::new(),
            envelope: GdsEnvelope::complete(),
        }
    }

    fn structure(name: &str, elements: Vec<GdsElement>) -> GdsStructure {
        GdsStructure {
            timestamps: [0; 12],
            name: name.to_string(),
            elements,
            unhandled_records: Vec::new(),
        }
    }

    fn boundary() -> GdsElement {
        GdsElement::Boundary(GdsBoundary {
            layer: 7,
            datatype: 0,
            ring: rectangle(0, 0, 10, 20),
            meta: meta(17, "device property "),
        })
    }

    #[test]
    fn strict_envelope_and_explicit_compatibility() {
        let library = complete_library(vec![structure("top", vec![boundary()])]);
        let full = write_gds_library(&library).expect("write complete library");
        let parsed = read_gds_library(&full, GdsReadMode::Strict).expect("strict complete library");
        assert_eq!(parsed.name, "lossless library ");
        assert_eq!(parsed.structures[0].name, "top");

        let records = decode_records(&full).unwrap();
        let structure_start = records.iter().find(|r| r.ty == BGNSTR).unwrap().offset;
        let endlib_start = records.iter().find(|r| r.ty == ENDLIB).unwrap().offset;
        let structure_only = &full[structure_start..endlib_start];
        let error = read_gds_library(structure_only, GdsReadMode::Strict).unwrap_err();
        assert_eq!(error.kind, LayoutErrorKind::InvalidOrder);
        let compatible = read_gds_library(structure_only, GdsReadMode::Compatibility)
            .expect("explicit legacy compatibility");
        assert!(!compatible.envelope.units);
        assert!(!compatible.envelope.endlib);
        assert_eq!(compatible.structures.len(), 1);
    }

    #[test]
    fn strict_rejects_zero_area_while_legacy_drc_preserves_and_flags_it() {
        let mut library = complete_library(vec![structure("top", vec![boundary()])]);
        let GdsElement::Boundary(shape) = &mut library.structures[0].elements[0] else {
            unreachable!()
        };
        shape.ring = rectangle(0, 0, 0, 500);
        let bytes = write_gds_library(&library).expect("lossless writer retains malformed fixture");

        let strict_error = read_gds_library(&bytes, GdsReadMode::Strict).unwrap_err();
        assert_eq!(strict_error.kind, LayoutErrorKind::Malformed);
        assert!(strict_error
            .message
            .contains("duplicate consecutive vertex"));

        let compatible = read_gds_library(&bytes, GdsReadMode::Compatibility)
            .expect("compatibility parser retains the closed invalid boundary");
        assert_eq!(
            flatten_gds_library(&compatible, &layer_table(), &GdsFlattenOptions::default())
                .err()
                .unwrap()
                .kind,
            LayoutErrorKind::Malformed,
            "strict flatten remains fail-closed even after compatibility parsing"
        );
        let options = GdsFlattenOptions {
            geometry_policy: GdsGeometryPolicy::PreserveInvalidForPolygonValidity,
            ..Default::default()
        };
        let layout = flatten_gds_library(&compatible, &layer_table(), &options)
            .expect("legacy DRC policy retains invalid ring");
        // ponytail: DRC assertion moved to engine (needs gdsverify-drc crate)
        assert!(layout.cells.contains_key("top"));
    }

    #[test]
    fn deterministic_supported_record_round_trip() {
        let leaf = structure(
            "leaf",
            vec![
                boundary(),
                GdsElement::Path(GdsPath {
                    layer: 7,
                    datatype: 0,
                    centerline: vec![Point::new(0, 30), Point::new(20, 30), Point::new(20, 50)],
                    width: Some(4),
                    path_type: Some(4),
                    begin_extension: Some(3),
                    end_extension: Some(5),
                    meta: meta(18, "path"),
                }),
                GdsElement::Box(GdsBoxElement {
                    layer: 7,
                    box_type: 0,
                    ring: rectangle(30, 0, 50, 20),
                    meta: GdsElementMeta::default(),
                }),
                GdsElement::Text(GdsText {
                    layer: 7,
                    text_type: 9,
                    origin: Point::new(5, 5),
                    string: "pin name ".to_string(),
                    presentation: Some(0x0005),
                    path_type: Some(0),
                    width: Some(2),
                    transform: GdsTransform {
                        reflected: true,
                        magnification: Some(2.0),
                        angle_degrees: Some(90.0),
                        ..Default::default()
                    },
                    meta: meta(19, "text"),
                }),
                GdsElement::Node(GdsNode {
                    layer: 7,
                    node_type: 3,
                    points: vec![Point::new(1, 1), Point::new(2, 2)],
                    meta: meta(20, "node"),
                }),
            ],
        );
        let top = structure(
            "top",
            vec![
                GdsElement::Sref(GdsReference {
                    structure: "leaf".to_string(),
                    origin: Point::new(100, 200),
                    transform: GdsTransform {
                        reflected: true,
                        magnification: Some(0.5),
                        angle_degrees: Some(270.0),
                        ..Default::default()
                    },
                    meta: meta(21, "instance"),
                }),
                GdsElement::Aref(GdsArrayReference {
                    structure: "leaf".to_string(),
                    columns: 3,
                    rows: 2,
                    origin: Point::new(0, 0),
                    column_endpoint: Point::new(300, 0),
                    row_endpoint: Point::new(0, 100),
                    transform: GdsTransform::default(),
                    meta: meta(22, "array"),
                }),
            ],
        );
        let bytes1 = write_gds_library(&complete_library(vec![leaf, top])).unwrap();
        let parsed1 = read_gds_library(&bytes1, GdsReadMode::Strict).unwrap();
        let bytes2 = write_gds_library(&parsed1).unwrap();
        let parsed2 = read_gds_library(&bytes2, GdsReadMode::Strict).unwrap();
        assert_eq!(bytes1, bytes2);
        assert_eq!(parsed1, parsed2);
        let GdsElement::Text(text) = &parsed2.structures[0].elements[3] else {
            panic!("TEXT retained")
        };
        assert_eq!(text.string, "pin name ");
        assert_eq!(text.meta.properties[0].value, "text");
    }

    #[test]
    fn exact_path_semantics_and_unsupported_caps() {
        let base = GdsPath {
            layer: 7,
            datatype: 0,
            centerline: vec![Point::new(0, 0), Point::new(20, 0), Point::new(20, 20)],
            width: Some(4),
            path_type: Some(0),
            begin_extension: None,
            end_extension: None,
            meta: GdsElementMeta::default(),
        };
        let rings = stroke_path(&base).expect("rectilinear flush path");
        assert_eq!(rings.len(), 2);
        assert_eq!(rings[0], rectangle(0, -2, 22, 2));
        assert_eq!(rings[1], rectangle(18, -2, 22, 20));

        let square = GdsPath {
            path_type: Some(2),
            ..base.clone()
        };
        let rings = stroke_path(&square).expect("square cap");
        assert_eq!(rings[0][0].x, -2);
        assert_eq!(rings[1][2].y, 22);

        let custom = GdsPath {
            path_type: Some(4),
            begin_extension: Some(3),
            end_extension: Some(7),
            ..base.clone()
        };
        let rings = stroke_path(&custom).expect("custom cap");
        assert_eq!(rings[0][0].x, -3);
        assert_eq!(rings[1][2].y, 27);

        let round = GdsPath {
            path_type: Some(1),
            ..base.clone()
        };
        assert_eq!(
            stroke_path(&round).unwrap_err().kind,
            LayoutErrorKind::Unsupported
        );
        let diagonal = GdsPath {
            centerline: vec![Point::new(0, 0), Point::new(10, 10)],
            ..base.clone()
        };
        // width=4, half=2 on a 45° segment: perpendicular offset is 2/sqrt(2) ≈ 1.414, not integer
        assert_eq!(
            stroke_path(&diagonal).unwrap_err().kind,
            LayoutErrorKind::NonIntegralTransform
        );
        let half_grid = GdsPath {
            width: Some(3),
            ..base
        };
        assert_eq!(
            stroke_path(&half_grid).unwrap_err().kind,
            LayoutErrorKind::NonIntegralTransform
        );
    }

    #[test]
    fn orthogonal_hierarchy_arrays_and_annotations_flatten_exactly() {
        let leaf = structure("leaf", vec![boundary()]);
        let transforms = [
            (Point::new(0, 0), GdsTransform::default()),
            (
                Point::new(100, 0),
                GdsTransform {
                    angle_degrees: Some(90.0),
                    ..Default::default()
                },
            ),
            (
                Point::new(200, 0),
                GdsTransform {
                    angle_degrees: Some(180.0),
                    ..Default::default()
                },
            ),
            (
                Point::new(300, 0),
                GdsTransform {
                    angle_degrees: Some(270.0),
                    ..Default::default()
                },
            ),
            (
                Point::new(400, 0),
                GdsTransform {
                    reflected: true,
                    ..Default::default()
                },
            ),
            (
                Point::new(500, 0),
                GdsTransform {
                    magnification: Some(2.0),
                    ..Default::default()
                },
            ),
        ];
        let mut elements: Vec<GdsElement> = transforms
            .into_iter()
            .enumerate()
            .map(|(index, (origin, transform))| {
                GdsElement::Sref(GdsReference {
                    structure: "leaf".to_string(),
                    origin,
                    transform,
                    meta: meta(30 + index as i16, "ref"),
                })
            })
            .collect();
        elements.push(GdsElement::Aref(GdsArrayReference {
            structure: "leaf".to_string(),
            columns: 3,
            rows: 2,
            origin: Point::new(0, 100),
            column_endpoint: Point::new(30, 100),
            row_endpoint: Point::new(0, 140),
            transform: GdsTransform::default(),
            meta: meta(40, "array"),
        }));
        let library = complete_library(vec![leaf, structure("top", elements)]);
        let layout = flatten_gds_library(
            &library,
            &layer_table(),
            &GdsFlattenOptions {
                selected_top: Some("top".to_string()),
                ..Default::default()
            },
        )
        .expect("all orthogonal transforms flatten exactly");
        let store = &layout.cells["top"];
        assert_eq!(store.poly_count(), 12);
        let bboxes: Vec<(i32, i32, i32, i32)> = store.poly_bbox[..6]
            .iter()
            .map(|b| (b.xmin, b.ymin, b.xmax, b.ymax))
            .collect();
        assert_eq!(
            bboxes,
            [
                (0, 0, 10, 20),
                (80, 0, 100, 10),
                (190, -20, 200, 0),
                (300, -10, 320, 0),
                (400, -20, 410, 0),
                (500, 0, 520, 40),
            ]
        );
        assert_eq!(
            store.poly_properties[0],
            [
                (30, "ref".to_string()),
                (17, "device property ".to_string())
            ]
        );
        assert_eq!(store.poly_hierarchy_path[0], ["top", "leaf@0"]);
        let array_boxes: BTreeSet<_> = store.poly_bbox[6..]
            .iter()
            .map(|b| (b.xmin, b.ymin))
            .collect();
        assert_eq!(
            array_boxes,
            [
                (0, 100),
                (0, 120),
                (10, 100),
                (10, 120),
                (20, 100),
                (20, 120)
            ]
            .into_iter()
            .collect()
        );
    }

    #[test]
    fn flatten_fails_closed_for_nonintegral_absolute_unknown_and_hierarchy_errors() {
        let layers = layer_table();
        let nonintegral = complete_library(vec![
            structure("leaf", vec![boundary()]),
            structure(
                "top",
                vec![GdsElement::Sref(GdsReference {
                    structure: "leaf".to_string(),
                    origin: Point::new(0, 0),
                    transform: GdsTransform {
                        magnification: Some(0.5),
                        ..Default::default()
                    },
                    meta: GdsElementMeta::default(),
                })],
            ),
        ]);
        // The leaf happens to use even coordinates except x=10/y=20, so add an odd point.
        let mut nonintegral = nonintegral;
        let GdsElement::Boundary(shape) = &mut nonintegral.structures[0].elements[0] else {
            unreachable!()
        };
        shape.ring = rectangle(0, 0, 11, 20);
        assert_eq!(
            flatten_gds_library(&nonintegral, &layers, &Default::default())
                .err()
                .unwrap()
                .kind,
            LayoutErrorKind::NonIntegralTransform
        );

        let absolute = complete_library(vec![
            structure("leaf", vec![boundary()]),
            structure(
                "top",
                vec![GdsElement::Sref(GdsReference {
                    structure: "leaf".to_string(),
                    origin: Point::new(0, 0),
                    transform: GdsTransform {
                        absolute_angle: true,
                        ..Default::default()
                    },
                    meta: GdsElementMeta::default(),
                })],
            ),
        ]);
        assert_eq!(
            flatten_gds_library(&absolute, &layers, &Default::default())
                .err()
                .unwrap()
                .kind,
            LayoutErrorKind::Unsupported
        );

        let mut unknown = complete_library(vec![structure("top", vec![boundary()])]);
        unknown.unhandled_records.push(GdsRawRecord {
            record_type: 0x7f,
            data_type: DT_NONE,
            payload: vec![],
            source_offset: 0,
        });
        assert_eq!(
            flatten_gds_library(&unknown, &layers, &Default::default())
                .err()
                .unwrap()
                .kind,
            LayoutErrorKind::Unsupported
        );

        let dangling = complete_library(vec![structure(
            "top",
            vec![GdsElement::Sref(GdsReference {
                structure: "missing".to_string(),
                origin: Point::new(0, 0),
                transform: GdsTransform::default(),
                meta: GdsElementMeta::default(),
            })],
        )]);
        assert_eq!(
            flatten_gds_library(&dangling, &layers, &Default::default())
                .err()
                .unwrap()
                .kind,
            LayoutErrorKind::UndefinedReference
        );

        let cycle = complete_library(vec![
            structure(
                "a",
                vec![GdsElement::Sref(GdsReference {
                    structure: "b".to_string(),
                    origin: Point::new(0, 0),
                    transform: GdsTransform::default(),
                    meta: GdsElementMeta::default(),
                })],
            ),
            structure(
                "b",
                vec![GdsElement::Sref(GdsReference {
                    structure: "a".to_string(),
                    origin: Point::new(0, 0),
                    transform: GdsTransform::default(),
                    meta: GdsElementMeta::default(),
                })],
            ),
        ]);
        assert_eq!(
            flatten_gds_library(&cycle, &layers, &Default::default())
                .err()
                .unwrap()
                .kind,
            LayoutErrorKind::HierarchyCycle
        );
    }

    #[test]
    fn diagonal_45_path_stroking() {
        // A 45° segment (0,0)->(100,100) with width=200 (half=100).
        // len = 100*sqrt(2), perp offset = 100/sqrt(2) = 50*sqrt(2) ≈ 70.71 — not integer.
        // Use a width where half/sqrt(2) is not integer to verify NonIntegralTransform.
        let non_integral = GdsPath {
            layer: 7,
            datatype: 0,
            centerline: vec![Point::new(0, 0), Point::new(100, 100)],
            width: Some(200),
            path_type: Some(0),
            begin_extension: None,
            end_extension: None,
            meta: GdsElementMeta::default(),
        };
        assert_eq!(
            stroke_path(&non_integral).unwrap_err().kind,
            LayoutErrorKind::NonIntegralTransform,
        );

        // Non-45-degree diagonal should be Unsupported
        let non_45 = GdsPath {
            layer: 7,
            datatype: 0,
            centerline: vec![Point::new(0, 0), Point::new(30, 40)],
            width: Some(4),
            path_type: Some(0),
            begin_extension: None,
            end_extension: None,
            meta: GdsElementMeta::default(),
        };
        assert_eq!(
            stroke_path(&non_45).unwrap_err().kind,
            LayoutErrorKind::Unsupported,
        );
    }

    #[test]
    fn all_angle_transform_non_integral_fails() {
        // A 45° rotation of a point (10, 0): x' = cos45*10 ≈ 7.07, not integer
        let transform = GdsTransform {
            angle_degrees: Some(45.0),
            ..Default::default()
        };
        let affine = Affine::instance(transform, Point::new(0, 0)).unwrap();
        assert_eq!(
            affine.apply(Point::new(10, 0)).unwrap_err().kind,
            LayoutErrorKind::NonIntegralTransform,
        );
    }

    #[test]
    fn all_angle_transform_exact_integers() {
        // 0° is orthogonal, still works
        let t0 = Affine::instance(
            GdsTransform {
                angle_degrees: Some(0.0),
                ..Default::default()
            },
            Point::new(5, 10),
        )
        .unwrap();
        assert_eq!(t0.apply(Point::new(3, 4)).unwrap(), Point::new(8, 14));

        // 180° is orthogonal
        let t180 = Affine::instance(
            GdsTransform {
                angle_degrees: Some(180.0),
                ..Default::default()
            },
            Point::new(0, 0),
        )
        .unwrap();
        assert_eq!(
            t180.apply(Point::new(10, 20)).unwrap(),
            Point::new(-10, -20)
        );
    }

    #[test]
    fn malformed_record_corpus_never_panics() {
        let corpus = [
            vec![],
            vec![0],
            vec![0, 4, HEADER],
            vec![0, 3, HEADER, DT_NONE],
            vec![0, 8, XY, DT_I32, 0, 0],
            vec![0, 4, ENDLIB, DT_NONE, 0, 4, HEADER, DT_I16],
            vec![0xff; 31],
        ];
        for bytes in corpus {
            let result = std::panic::catch_unwind(|| read_gds_library(&bytes, GdsReadMode::Strict));
            assert!(result.is_ok(), "parser panicked for {bytes:?}");
            assert!(
                result.unwrap().is_err(),
                "malformed corpus entry was accepted"
            );
        }
    }
}

#[cfg(test)]
mod checked_reader_tests {
    use super::*;
    use crate::params::{LayerDef, LayerTable};

    fn record(out: &mut Vec<u8>, record: u8, data_type: u8, payload: &[u8]) {
        let len = u16::try_from(payload.len() + 4).unwrap();
        out.extend_from_slice(&len.to_be_bytes());
        out.push(record);
        out.push(data_type);
        out.extend_from_slice(payload);
    }

    fn no_data(out: &mut Vec<u8>, record_type: u8) {
        record(out, record_type, DT_NONE, &[]);
    }

    fn i16_record(out: &mut Vec<u8>, record_type: u8, values: &[i16]) {
        let payload: Vec<u8> = values
            .iter()
            .flat_map(|value| value.to_be_bytes())
            .collect();
        record(out, record_type, DT_I16, &payload);
    }

    fn i32_record(out: &mut Vec<u8>, record_type: u8, values: &[i32]) {
        let payload: Vec<u8> = values
            .iter()
            .flat_map(|value| value.to_be_bytes())
            .collect();
        record(out, record_type, DT_I32, &payload);
    }

    fn string_record(out: &mut Vec<u8>, record_type: u8, value: &str) {
        let mut payload = value.as_bytes().to_vec();
        if payload.len() % 2 != 0 {
            payload.push(0);
        }
        record(out, record_type, DT_ASCII, &payload);
    }

    fn gds_real(value: f64) -> [u8; 8] {
        if value == 0.0 {
            return [0; 8];
        }
        let (mut mantissa, mut exponent) = (value.abs(), 64i32);
        while mantissa >= 1.0 {
            mantissa /= 16.0;
            exponent += 1;
        }
        while mantissa < 1.0 / 16.0 {
            mantissa *= 16.0;
            exponent -= 1;
        }
        let bits = (mantissa * 2f64.powi(56)) as u64;
        let mut bytes = bits.to_be_bytes();
        bytes[0] = (if value < 0.0 { 0x80 } else { 0 }) | exponent as u8;
        bytes
    }

    fn begin_structure(out: &mut Vec<u8>, name: &str) {
        i16_record(out, BGNSTR, &[0; 12]);
        string_record(out, STRNAME, name);
    }

    fn rectangle(out: &mut Vec<u8>, layer: i16, datatype: i16) {
        no_data(out, BOUNDARY);
        i16_record(out, LAYER, &[layer]);
        i16_record(out, DATATYPE, &[datatype]);
        i32_record(out, XY, &[0, 0, 100, 0, 100, 100, 0, 100, 0, 0]);
        no_data(out, ENDEL);
    }

    fn layer_table() -> LayerTable {
        let defs = [(
            "met1".into(),
            LayerDef {
                layer: 7,
                datatype: 0,
            },
        )]
        .into_iter()
        .collect();
        LayerTable::from_defs(&defs)
    }

    #[test]
    fn rejects_truncated_and_invalid_records() {
        let table = layer_table();
        let truncated = [0, 8, HEADER, DT_I16, 0, 6];
        let error = read_gds(&truncated, &table)
            .err()
            .expect("declared record extending past EOF must fail");
        assert!(error.contains("truncated record"), "{error}");

        let invalid_length = [0, 2, HEADER, DT_I16];
        let error = read_gds(&invalid_length, &table)
            .err()
            .expect("record shorter than header must fail");
        assert!(error.contains("invalid record length"), "{error}");

        let mut wrong_type = Vec::new();
        record(&mut wrong_type, HEADER, DT_I32, &[0, 6]);
        let error = read_gds(&wrong_type, &table)
            .err()
            .expect("wrong record data type must fail");
        assert!(error.contains("data type"), "{error}");

        let trailing_header = [0u8; 3];
        let error = read_gds(&trailing_header, &table)
            .err()
            .expect("partial header must fail");
        assert!(error.contains("truncated record header"), "{error}");
    }

    #[test]
    fn rejects_duplicate_structures_and_missing_endstr() {
        let table = layer_table();
        let mut duplicate = Vec::new();
        begin_structure(&mut duplicate, "top");
        no_data(&mut duplicate, ENDSTR);
        begin_structure(&mut duplicate, "top");
        no_data(&mut duplicate, ENDSTR);
        let error = read_gds(&duplicate, &table)
            .err()
            .expect("duplicate structure name must fail");
        assert!(error.contains("duplicate structure name `top`"), "{error}");

        let mut missing = Vec::new();
        begin_structure(&mut missing, "unfinished");
        let error = read_gds(&missing, &table)
            .err()
            .expect("missing ENDSTR must fail");
        assert!(error.contains("missing ENDSTR"), "{error}");
    }

    #[test]
    fn exposes_units_without_rescaling_geometry() {
        let table = layer_table();
        let mut bytes = Vec::new();
        let mut unit_payload = Vec::new();
        unit_payload.extend_from_slice(&gds_real(1.0e-3));
        unit_payload.extend_from_slice(&gds_real(1.0e-9));
        record(&mut bytes, UNITS, DT_REAL8, &unit_payload);
        begin_structure(&mut bytes, "top");
        no_data(&mut bytes, BOUNDARY);
        i16_record(&mut bytes, LAYER, &[7]);
        i16_record(&mut bytes, DATATYPE, &[0]);
        i32_record(
            &mut bytes,
            XY,
            &[100, 200, 1100, 200, 1100, 700, 100, 700, 100, 200],
        );
        no_data(&mut bytes, ENDEL);
        no_data(&mut bytes, ENDSTR);

        let layout = read_gds(&bytes, &table).expect("valid layout");
        let units = layout.units.expect("UNITS metadata");
        assert!((units.user_units_per_database_unit - 1.0e-3).abs() < 1.0e-15);
        assert!((units.meters_per_database_unit - 1.0e-9).abs() < 1.0e-21);
        assert!((units.database_unit_nm() - 1.0).abs() < 1.0e-12);

        let bbox = layout.cells["top"].poly_bbox[0];
        assert_eq!(
            (bbox.xmin, bbox.ymin, bbox.xmax, bbox.ymax),
            (100, 200, 1100, 700)
        );
    }

    #[test]
    fn reports_unmapped_geometry_by_layer_pair() {
        let table = layer_table();
        let mut bytes = Vec::new();
        begin_structure(&mut bytes, "top");
        rectangle(&mut bytes, 99, 7);
        rectangle(&mut bytes, 99, 7);
        rectangle(&mut bytes, 98, 0);
        no_data(&mut bytes, ENDSTR);

        let layout = read_gds(&bytes, &table).expect("well-formed unmapped geometry");
        assert_eq!(layout.cells["top"].poly_count(), 0);
        assert_eq!(
            layout.unmapped_geometry,
            [
                GdsUnmappedLayer {
                    layer: 98,
                    datatype: 0,
                    element_count: 1
                },
                GdsUnmappedLayer {
                    layer: 99,
                    datatype: 7,
                    element_count: 2
                },
            ]
        );
    }
}
