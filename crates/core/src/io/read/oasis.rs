//! OASIS 1.0 reader/writer with modal state, PATH, TEXT, repetitions, properties,
//! XYRELATIVE, transformed placements, and CBLOCK decompression.
//!
//! The reader decodes into the same lossless [`GdsLibrary`] record database as GDS.
//! Reference-number tables and validation signatures still return
//! [`OasisErrorKind::Unsupported`].

use super::gds::GdsUnits;
use super::gds::{
    validate_hierarchy, GdsBoundary, GdsElement, GdsElementMeta, GdsEnvelope, GdsLibrary, GdsPath,
    GdsProperty, GdsReference, GdsStructure, GdsText, GdsTransform,
};
use crate::exact::{Point, Ring};
use std::collections::{HashMap, HashSet};

const MAGIC: &[u8; 13] = b"%SEMI-OASIS\r\n";
const PAD: u64 = 0;
const START: u64 = 1;
const END: u64 = 2;
const CELL: u64 = 14;
const XYABSOLUTE: u64 = 15;
const XYRELATIVE: u64 = 16;
const PLACEMENT: u64 = 17;
const PLACEMENT_TRANSFORM: u64 = 18;
const TEXT_RECORD: u64 = 19;
const RECTANGLE: u64 = 20;
const POLYGON: u64 = 21;
const PATH_RECORD: u64 = 22;
const PROPERTY_RECORD: u64 = 28;
const PROPERTY_REPEAT: u64 = 29;
const CBLOCK: u64 = 34;

const EXPLICIT_RECTANGLE_INFO: u8 = 0x7b; // S=0,W=1,H=1,X=1,Y=1,R=0,D=1,L=1
const EXPLICIT_POLYGON_INFO: u8 = 0x3b; // P=1,X=1,Y=1,R=0,D=1,L=1
const EXPLICIT_PLACEMENT_BASE: u8 = 0xb0; // C,N,X,Y; no ref-number/repetition

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OasisCapabilities {
    pub version_1_0: bool,
    pub named_cells: bool,
    pub absolute_coordinates: bool,
    pub explicit_rectangles: bool,
    pub explicit_rectilinear_polygons: bool,
    pub named_orthogonal_placements: bool,
    pub paths: bool,
    pub text: bool,
    pub repetitions: bool,
    pub properties: bool,
    pub modal_fields: bool,
    pub relative_coordinates: bool,
    pub reference_number_tables: bool,
    pub compressed_blocks: bool,
    pub validation_signatures: bool,
    pub max_layer_or_datatype: i32,
}

pub const OASIS_CAPABILITIES: OasisCapabilities = OasisCapabilities {
    version_1_0: true,
    named_cells: true,
    absolute_coordinates: true,
    explicit_rectangles: true,
    explicit_rectilinear_polygons: true,
    named_orthogonal_placements: true,
    paths: true,
    text: true,
    repetitions: true,
    properties: true,
    modal_fields: true,
    relative_coordinates: true,
    reference_number_tables: false,
    compressed_blocks: true,
    validation_signatures: false,
    max_layer_or_datatype: i16::MAX as i32,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OasisErrorKind {
    Malformed,
    InvalidOrder,
    Duplicate,
    Unsupported,
    UndefinedReference,
    HierarchyCycle,
    ArithmeticOverflow,
    CapacityExceeded,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("OASIS at byte offset {offset}: {message}")]
pub struct OasisError {
    pub kind: OasisErrorKind,
    pub offset: usize,
    pub message: String,
}

impl OasisError {
    fn new(kind: OasisErrorKind, offset: usize, message: impl Into<String>) -> Self {
        Self {
            kind,
            offset,
            message: message.into(),
        }
    }

    fn unsupported(offset: usize, message: impl Into<String>) -> Self {
        Self::new(OasisErrorKind::Unsupported, offset, message)
    }
}


// ponytail: only tracks fields we actually parse; add more when needed.
#[derive(Clone, Debug, Default)]
struct ModalState {
    layer: Option<i16>,
    datatype: Option<i16>,
    textlayer: Option<i16>,
    texttype: Option<i16>,
    text_string: Option<String>,
    x: i32,
    y: i32,
    width: Option<i32>,
    height: Option<i32>,
    path_width: Option<i32>,
    xy_relative: bool,
    placement_cell: Option<String>,
    last_property_name: Option<String>,
    pending_properties: Vec<GdsProperty>,
}

impl ModalState {
    fn resolve_x(&mut self, raw: i32) -> Result<i32, OasisError> {
        if self.xy_relative {
            self.x = self.x.checked_add(raw).ok_or_else(|| {
                OasisError::new(
                    OasisErrorKind::ArithmeticOverflow,
                    0,
                    "XYRELATIVE x overflow",
                )
            })?;
        } else {
            self.x = raw;
        }
        Ok(self.x)
    }

    fn resolve_y(&mut self, raw: i32) -> Result<i32, OasisError> {
        if self.xy_relative {
            self.y = self.y.checked_add(raw).ok_or_else(|| {
                OasisError::new(
                    OasisErrorKind::ArithmeticOverflow,
                    0,
                    "XYRELATIVE y overflow",
                )
            })?;
        } else {
            self.y = raw;
        }
        Ok(self.y)
    }

    fn take_properties(&mut self) -> Vec<GdsProperty> {
        std::mem::take(&mut self.pending_properties)
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn byte(&mut self, context: &str) -> Result<u8, OasisError> {
        let byte = self.bytes.get(self.at).copied().ok_or_else(|| {
            OasisError::new(
                OasisErrorKind::Malformed,
                self.at,
                format!("truncated {context}"),
            )
        })?;
        self.at += 1;
        Ok(byte)
    }

    fn unsigned(&mut self, context: &str) -> Result<u64, OasisError> {
        let start = self.at;
        let mut result = 0_u64;
        let mut shift = 0_u32;
        for index in 0..10 {
            let byte = self.byte(context)?;
            let value = u64::from(byte & 0x7f);
            if shift == 63 && value > 1 {
                return Err(OasisError::new(
                    OasisErrorKind::ArithmeticOverflow,
                    start,
                    format!("{context} exceeds u64"),
                ));
            }
            result |= value << shift;
            if byte & 0x80 == 0 {
                if index > 0 && value == 0 {
                    return Err(OasisError::new(
                        OasisErrorKind::Malformed,
                        start,
                        format!("{context} uses a non-canonical varint"),
                    ));
                }
                return Ok(result);
            }
            shift += 7;
        }
        Err(OasisError::new(
            OasisErrorKind::ArithmeticOverflow,
            start,
            format!("{context} varint exceeds ten bytes"),
        ))
    }

    fn signed(&mut self, context: &str) -> Result<i64, OasisError> {
        let start = self.at;
        let encoded = self.internal_integer(1, context)?;
        let magnitude = encoded.0;
        if magnitude > i64::MAX as u64 {
            return Err(OasisError::new(
                OasisErrorKind::ArithmeticOverflow,
                start,
                format!("{context} magnitude exceeds i64"),
            ));
        }
        let magnitude = magnitude as i64;
        Ok(if encoded.1 & 1 != 0 {
            -magnitude
        } else {
            magnitude
        })
    }

    /// Returns `(magnitude, low discriminator bits)`.
    fn internal_integer(&mut self, skip_bits: u8, context: &str) -> Result<(u64, u8), OasisError> {
        let start = self.at;
        let first = self.byte(context)?;
        let bits = first & ((1 << skip_bits) - 1);
        let mut result = u64::from(first & 0x7f) >> skip_bits;
        let mut shift = u32::from(7 - skip_bits);
        let mut byte = first;
        let mut count = 1;
        while byte & 0x80 != 0 {
            if count == 10 || shift >= 64 {
                return Err(OasisError::new(
                    OasisErrorKind::ArithmeticOverflow,
                    start,
                    format!("{context} exceeds u64"),
                ));
            }
            byte = self.byte(context)?;
            let value = u64::from(byte & 0x7f);
            if shift == 63 && value > 1 {
                return Err(OasisError::new(
                    OasisErrorKind::ArithmeticOverflow,
                    start,
                    format!("{context} exceeds u64"),
                ));
            }
            result |= value << shift;
            shift += 7;
            count += 1;
        }
        Ok((result, bits))
    }

    fn nstring(&mut self, context: &str) -> Result<String, OasisError> {
        let start = self.at;
        let length = self.unsigned(&format!("{context} length"))?;
        let length = usize::try_from(length).map_err(|_| {
            OasisError::new(
                OasisErrorKind::CapacityExceeded,
                start,
                format!("{context} length exceeds usize"),
            )
        })?;
        if length == 0 {
            return Err(OasisError::new(
                OasisErrorKind::Malformed,
                start,
                format!("{context} N-string must not be empty"),
            ));
        }
        let end = self.at.checked_add(length).ok_or_else(|| {
            OasisError::new(
                OasisErrorKind::ArithmeticOverflow,
                start,
                "string end overflow",
            )
        })?;
        let bytes = self.bytes.get(self.at..end).ok_or_else(|| {
            OasisError::new(
                OasisErrorKind::Malformed,
                self.at,
                format!("truncated {context}"),
            )
        })?;
        if !bytes.iter().all(|byte| (0x21..=0x7e).contains(byte)) {
            return Err(OasisError::new(
                OasisErrorKind::Malformed,
                self.at,
                format!("{context} is not an OASIS N-string"),
            ));
        }
        self.at = end;
        Ok(String::from_utf8(bytes.to_vec()).expect("N-string is ASCII"))
    }

    /// Read an OASIS A-string (printable ASCII including space, 0x20..=0x7e).
    fn astring(&mut self, context: &str) -> Result<String, OasisError> {
        let start = self.at;
        let length = self.unsigned(&format!("{context} length"))?;
        let length = usize::try_from(length).map_err(|_| {
            OasisError::new(
                OasisErrorKind::CapacityExceeded,
                start,
                format!("{context} length exceeds usize"),
            )
        })?;
        let end = self.at.checked_add(length).ok_or_else(|| {
            OasisError::new(
                OasisErrorKind::ArithmeticOverflow,
                start,
                "string end overflow",
            )
        })?;
        let bytes = self.bytes.get(self.at..end).ok_or_else(|| {
            OasisError::new(
                OasisErrorKind::Malformed,
                self.at,
                format!("truncated {context}"),
            )
        })?;
        if !bytes.iter().all(|b| (0x20..=0x7e).contains(b)) {
            return Err(OasisError::new(
                OasisErrorKind::Malformed,
                self.at,
                format!("{context} is not an OASIS A-string"),
            ));
        }
        self.at = end;
        Ok(String::from_utf8(bytes.to_vec()).expect("A-string is ASCII"))
    }

    fn bstring(&mut self, context: &str) -> Result<&'a [u8], OasisError> {
        let start = self.at;
        let length =
            usize::try_from(self.unsigned(&format!("{context} length"))?).map_err(|_| {
                OasisError::new(
                    OasisErrorKind::CapacityExceeded,
                    start,
                    format!("{context} length exceeds usize"),
                )
            })?;
        let end = self.at.checked_add(length).ok_or_else(|| {
            OasisError::new(
                OasisErrorKind::ArithmeticOverflow,
                start,
                "string end overflow",
            )
        })?;
        let value = self.bytes.get(self.at..end).ok_or_else(|| {
            OasisError::new(
                OasisErrorKind::Malformed,
                self.at,
                format!("truncated {context}"),
            )
        })?;
        self.at = end;
        Ok(value)
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.at)
    }
}

/// Read an OASIS 1.0 stream into the shared lossless hierarchy DB.
pub fn read_oasis(bytes: &[u8]) -> Result<GdsLibrary, OasisError> {
    if bytes.len() < MAGIC.len() || &bytes[..MAGIC.len().min(bytes.len())] != MAGIC {
        return Err(OasisError::new(
            OasisErrorKind::Malformed,
            0,
            "invalid or truncated `%SEMI-OASIS\\r\\n` magic",
        ));
    }
    let mut reader = Reader {
        bytes,
        at: MAGIC.len(),
    };
    let start_offset = reader.at;
    if reader.unsigned("START record ID")? != START {
        return Err(OasisError::new(
            OasisErrorKind::InvalidOrder,
            start_offset,
            "START must immediately follow the magic",
        ));
    }
    let version = reader.nstring("START version")?;
    if version != "1.0" {
        return Err(OasisError::unsupported(
            start_offset,
            format!("OASIS version `{version}`; only 1.0 is supported"),
        ));
    }
    let real_offset = reader.at;
    let real_type = reader.byte("START unit real type")?;
    if real_type != 0 {
        return Err(OasisError::unsupported(
            real_offset,
            format!(
                "START unit real encoding {real_type}; only positive-integer real is supported"
            ),
        ));
    }
    let database_units_per_micron = reader.unsigned("START unit")?;
    if database_units_per_micron == 0 {
        return Err(OasisError::new(
            OasisErrorKind::Malformed,
            real_offset,
            "START unit must be positive",
        ));
    }
    let offset_flag_offset = reader.at;
    let offset_table_flag = reader.unsigned("START offset-table flag")?;
    if offset_table_flag != 0 {
        return Err(OasisError::unsupported(
            offset_flag_offset,
            "offset table in END; subset requires an explicit zero table in START",
        ));
    }
    for _ in 0..6 {
        let strict = reader.unsigned("START table strict flag")?;
        let offset = reader.unsigned("START table offset")?;
        if strict != 0 || offset != 0 {
            return Err(OasisError::unsupported(
                offset_flag_offset,
                "name/property/layer reference-number tables are not supported",
            ));
        }
    }

    let mut structures = Vec::new();
    let mut names = HashSet::new();
    let mut current: Option<GdsStructure> = None;
    let mut current_has_coords = false;
    let mut modal = ModalState::default();
    let mut saw_end = false;

    while reader.at < bytes.len() {
        let record_offset = reader.at;
        let record = reader.unsigned("record ID")?;
        dispatch_record(
            record,
            record_offset,
            &mut reader,
            &mut structures,
            &mut names,
            &mut current,
            &mut current_has_coords,
            &mut modal,
            &mut saw_end,
        )?;
        if saw_end {
            break;
        }
    }

    if !saw_end {
        return Err(OasisError::new(
            OasisErrorKind::InvalidOrder,
            reader.at,
            "missing END record",
        ));
    }
    if reader.at != bytes.len() {
        return Err(OasisError::new(
            OasisErrorKind::InvalidOrder,
            reader.at,
            "data follows END record",
        ));
    }
    if structures.is_empty() {
        return Err(OasisError::new(
            OasisErrorKind::Malformed,
            start_offset,
            "OASIS library has no cells",
        ));
    }
    let units = GdsUnits {
        user_units_per_database_unit: 1.0 / database_units_per_micron as f64,
        meters_per_database_unit: 1.0e-6 / database_units_per_micron as f64,
    };
    let library = GdsLibrary {
        version: 600,
        timestamps: [0; 12],
        name: "OASIS".to_string(),
        units,
        structures,
        unhandled_records: Vec::new(),
        envelope: GdsEnvelope::complete(),
    };
    validate_oasis_hierarchy(&library, start_offset)?;
    Ok(library)
}

#[allow(clippy::too_many_arguments)]
fn dispatch_record(
    record: u64,
    record_offset: usize,
    reader: &mut Reader<'_>,
    structures: &mut Vec<GdsStructure>,
    names: &mut HashSet<String>,
    current: &mut Option<GdsStructure>,
    current_has_coords: &mut bool,
    modal: &mut ModalState,
    saw_end: &mut bool,
) -> Result<(), OasisError> {
    match record {
        PAD => {}
        END => {
            if let Some(structure) = current.take() {
                structures.push(structure);
            }
            read_end(reader, record_offset)?;
            *saw_end = true;
        }
        CELL => {
            if let Some(structure) = current.take() {
                structures.push(structure);
            }
            let name = reader.nstring("CELL name")?;
            if !names.insert(name.clone()) {
                return Err(OasisError::new(
                    OasisErrorKind::Duplicate,
                    record_offset,
                    format!("duplicate CELL `{name}`"),
                ));
            }
            *current = Some(GdsStructure {
                timestamps: [0; 12],
                name,
                elements: Vec::new(),
                unhandled_records: Vec::new(),
            });
            *current_has_coords = false;
            *modal = ModalState::default();
        }
        XYABSOLUTE => {
            require_cell(current, record_offset, "XYABSOLUTE")?;
            *current_has_coords = true;
            modal.xy_relative = false;
        }
        XYRELATIVE => {
            require_cell(current, record_offset, "XYRELATIVE")?;
            *current_has_coords = true;
            modal.xy_relative = true;
        }
        RECTANGLE => {
            require_cell_with_coords(current, *current_has_coords, record_offset, "RECTANGLE")?;
            let elements = read_rectangle_modal(reader, modal, record_offset)?;
            current.as_mut().unwrap().elements.extend(elements);
        }
        POLYGON => {
            require_cell_with_coords(current, *current_has_coords, record_offset, "POLYGON")?;
            let elements = read_polygon_modal(reader, modal, record_offset)?;
            current.as_mut().unwrap().elements.extend(elements);
        }
        PATH_RECORD => {
            require_cell_with_coords(current, *current_has_coords, record_offset, "PATH")?;
            let elements = read_path_record(reader, modal, record_offset)?;
            current.as_mut().unwrap().elements.extend(elements);
        }
        TEXT_RECORD => {
            require_cell_with_coords(current, *current_has_coords, record_offset, "TEXT")?;
            let elements = read_text_record(reader, modal, record_offset)?;
            current.as_mut().unwrap().elements.extend(elements);
        }
        PLACEMENT => {
            require_cell_with_coords(current, *current_has_coords, record_offset, "PLACEMENT")?;
            let elements = read_placement_modal(reader, modal, record_offset)?;
            current.as_mut().unwrap().elements.extend(elements);
        }
        PLACEMENT_TRANSFORM => {
            require_cell_with_coords(
                current,
                *current_has_coords,
                record_offset,
                "PLACEMENT_TRANSFORM",
            )?;
            let elements = read_placement_transform(reader, modal, record_offset)?;
            current.as_mut().unwrap().elements.extend(elements);
        }
        PROPERTY_RECORD => {
            require_cell(current, record_offset, "PROPERTY")?;
            read_property_record(reader, modal, record_offset)?;
        }
        PROPERTY_REPEAT => {
            require_cell(current, record_offset, "PROPERTY_REPEAT")?;
            // ponytail: reuses last property; already in modal.pending_properties
        }
        CBLOCK => {
            let decompressed = read_cblock(reader, record_offset)?;
            let mut sub = Reader {
                bytes: &decompressed,
                at: 0,
            };
            while sub.at < decompressed.len() {
                let sub_record = sub.unsigned("CBLOCK record ID")?;
                dispatch_record(
                    sub_record,
                    record_offset,
                    &mut sub,
                    structures,
                    names,
                    current,
                    current_has_coords,
                    modal,
                    saw_end,
                )?;
                if *saw_end {
                    break;
                }
            }
        }
        START => {
            return Err(OasisError::new(
                OasisErrorKind::InvalidOrder,
                record_offset,
                "duplicate/out-of-order START",
            ));
        }
        unsupported => {
            return Err(OasisError::unsupported(
                record_offset,
                unsupported_record_message(unsupported),
            ));
        }
    }
    Ok(())
}

fn require_cell(
    current: &Option<GdsStructure>,
    offset: usize,
    record: &str,
) -> Result<(), OasisError> {
    if current.is_none() {
        Err(OasisError::new(
            OasisErrorKind::InvalidOrder,
            offset,
            format!("{record} outside CELL"),
        ))
    } else {
        Ok(())
    }
}

fn require_cell_with_coords(
    current: &Option<GdsStructure>,
    has_coords: bool,
    offset: usize,
    record: &str,
) -> Result<(), OasisError> {
    require_cell(current, offset, record)?;
    if !has_coords {
        Err(OasisError::unsupported(
            offset,
            format!("{record} without a preceding XYABSOLUTE or XYRELATIVE"),
        ))
    } else {
        Ok(())
    }
}

fn read_layer(reader: &mut Reader<'_>, context: &str) -> Result<i16, OasisError> {
    let offset = reader.at;
    let value = reader.unsigned(context)?;
    i16::try_from(value).map_err(|_| {
        OasisError::new(
            OasisErrorKind::CapacityExceeded,
            offset,
            format!(
                "{context} {value} exceeds declared subset maximum {}",
                i16::MAX
            ),
        )
    })
}

fn coordinate(reader: &mut Reader<'_>, context: &str) -> Result<i32, OasisError> {
    let offset = reader.at;
    let value = reader.signed(context)?;
    i32::try_from(value).map_err(|_| {
        OasisError::new(
            OasisErrorKind::ArithmeticOverflow,
            offset,
            format!("{context} {value} exceeds i32 database coordinates"),
        )
    })
}

fn dimension(reader: &mut Reader<'_>, context: &str) -> Result<i32, OasisError> {
    let offset = reader.at;
    let value = reader.unsigned(context)?;
    if value == 0 || value > i32::MAX as u64 {
        return Err(OasisError::new(
            if value == 0 {
                OasisErrorKind::Malformed
            } else {
                OasisErrorKind::ArithmeticOverflow
            },
            offset,
            format!("{context} must be in 1..=i32::MAX, got {value}"),
        ));
    }
    Ok(value as i32)
}

fn modal_or<T>(slot: Option<T>, offset: usize, msg: &str) -> Result<T, OasisError> {
    slot.ok_or_else(|| OasisError::new(OasisErrorKind::Malformed, offset, msg))
}

fn checked_add_oas(a: i32, b: i32, offset: usize, msg: &str) -> Result<i32, OasisError> {
    a.checked_add(b)
        .ok_or_else(|| OasisError::new(OasisErrorKind::ArithmeticOverflow, offset, msg))
}

// ---------------------------------------------------------------------------
// Modal-aware record readers (return Vec for repetition expansion)
// ---------------------------------------------------------------------------

fn read_rectangle_modal(
    reader: &mut Reader<'_>,
    modal: &mut ModalState,
    off: usize,
) -> Result<Vec<GdsElement>, OasisError> {
    let info = reader.byte("RECTANGLE info")?;
    let has_l = info & 0x01 != 0;
    let has_d = info & 0x02 != 0;
    let has_rep = info & 0x04 != 0;
    let has_y = info & 0x08 != 0;
    let has_x = info & 0x10 != 0;
    let has_h = info & 0x20 != 0;
    let has_w = info & 0x40 != 0;
    let is_sq = info & 0x80 != 0;

    let layer = if has_l {
        let l = read_layer(reader, "RECTANGLE layer")?;
        modal.layer = Some(l);
        l
    } else {
        modal_or(modal.layer, off, "RECTANGLE omits layer with no modal")?
    };
    let datatype = if has_d {
        let d = read_layer(reader, "RECTANGLE datatype")?;
        modal.datatype = Some(d);
        d
    } else {
        modal_or(
            modal.datatype,
            off,
            "RECTANGLE omits datatype with no modal",
        )?
    };
    let width = if has_w {
        let w = dimension(reader, "RECTANGLE width")?;
        modal.width = Some(w);
        w
    } else {
        modal_or(modal.width, off, "RECTANGLE omits width with no modal")?
    };
    let height = if is_sq {
        width
    } else if has_h {
        let h = dimension(reader, "RECTANGLE height")?;
        modal.height = Some(h);
        h
    } else {
        modal_or(modal.height, off, "RECTANGLE omits height with no modal")?
    };

    let raw_x = if has_x {
        coordinate(reader, "RECTANGLE x")?
    } else {
        modal.x
    };
    let raw_y = if has_y {
        coordinate(reader, "RECTANGLE y")?
    } else {
        modal.y
    };
    let x = modal.resolve_x(raw_x)?;
    let y = modal.resolve_y(raw_y)?;

    let reps = if has_rep {
        read_repetition(reader, off)?
    } else {
        vec![(0, 0)]
    };
    let props = modal.take_properties();

    let mut out = Vec::with_capacity(reps.len());
    for &(rdx, rdy) in &reps {
        let rx = checked_add_oas(x, rdx, off, "RECT rep x")?;
        let ry = checked_add_oas(y, rdy, off, "RECT rep y")?;
        let xmax = checked_add_oas(rx, width, off, "RECT x+w")?;
        let ymax = checked_add_oas(ry, height, off, "RECT y+h")?;
        out.push(GdsElement::Boundary(GdsBoundary {
            layer,
            datatype,
            ring: vec![
                Point::new(rx, ry),
                Point::new(xmax, ry),
                Point::new(xmax, ymax),
                Point::new(rx, ymax),
            ],
            meta: GdsElementMeta {
                properties: props.clone(),
                ..Default::default()
            },
        }));
    }
    Ok(out)
}

fn read_polygon_modal(
    reader: &mut Reader<'_>,
    modal: &mut ModalState,
    off: usize,
) -> Result<Vec<GdsElement>, OasisError> {
    let info = reader.byte("POLYGON info")?;
    let has_l = info & 0x01 != 0;
    let has_d = info & 0x02 != 0;
    let has_rep = info & 0x04 != 0;
    let has_y = info & 0x08 != 0;
    let has_x = info & 0x10 != 0;
    let has_pl = info & 0x20 != 0;

    let layer = if has_l {
        let l = read_layer(reader, "POLYGON layer")?;
        modal.layer = Some(l);
        l
    } else {
        modal_or(modal.layer, off, "POLYGON omits layer with no modal")?
    };
    let datatype = if has_d {
        let d = read_layer(reader, "POLYGON datatype")?;
        modal.datatype = Some(d);
        d
    } else {
        modal_or(modal.datatype, off, "POLYGON omits datatype with no modal")?
    };
    let relative = if has_pl {
        read_point_list(reader, off, "POLYGON")?
    } else {
        return Err(OasisError::unsupported(
            off,
            "POLYGON omits point-list with no modal reuse",
        ));
    };

    let raw_x = if has_x {
        coordinate(reader, "POLYGON x")?
    } else {
        modal.x
    };
    let raw_y = if has_y {
        coordinate(reader, "POLYGON y")?
    } else {
        modal.y
    };
    let ox = modal.resolve_x(raw_x)?;
    let oy = modal.resolve_y(raw_y)?;

    let reps = if has_rep {
        read_repetition(reader, off)?
    } else {
        vec![(0, 0)]
    };
    let props = modal.take_properties();

    let mut out = Vec::with_capacity(reps.len());
    for &(rdx, rdy) in &reps {
        let bx = checked_add_oas(ox, rdx, off, "POLY rep x")?;
        let by = checked_add_oas(oy, rdy, off, "POLY rep y")?;
        let ring: Vec<Point> = relative
            .iter()
            .map(|p| {
                Ok(Point::new(
                    checked_add_oas(bx, p.x, off, "POLY translate x")?,
                    checked_add_oas(by, p.y, off, "POLY translate y")?,
                ))
            })
            .collect::<Result<_, OasisError>>()?;
        Ring::new(ring.clone()).map_err(|e| {
            OasisError::new(
                OasisErrorKind::Malformed,
                off,
                format!("invalid POLYGON: {e}"),
            )
        })?;
        out.push(GdsElement::Boundary(GdsBoundary {
            layer,
            datatype,
            ring,
            meta: GdsElementMeta {
                properties: props.clone(),
                ..Default::default()
            },
        }));
    }
    Ok(out)
}

fn read_point_list(
    reader: &mut Reader<'_>,
    off: usize,
    ctx: &str,
) -> Result<Vec<Point>, OasisError> {
    let pl_type = reader.byte(&format!("{ctx} point-list type"))?;
    let n = reader.unsigned(&format!("{ctx} point count"))?;
    if n < 1 {
        return Err(OasisError::new(
            OasisErrorKind::Malformed,
            off,
            format!("{ctx} needs at least two points"),
        ));
    }
    let n = usize::try_from(n).map_err(|_| {
        OasisError::new(
            OasisErrorKind::CapacityExceeded,
            off,
            format!("{ctx} count > usize"),
        )
    })?;
    let mut pts = Vec::with_capacity(n + 1);
    pts.push(Point::new(0, 0));

    match pl_type {
        0 => {
            for _ in 0..n {
                let dx = coordinate(reader, &format!("{ctx} h-delta"))?;
                let p = *pts.last().unwrap();
                pts.push(Point::new(checked_add_oas(p.x, dx, off, "delta")?, p.y));
            }
        }
        1 => {
            for _ in 0..n {
                let dy = coordinate(reader, &format!("{ctx} v-delta"))?;
                let p = *pts.last().unwrap();
                pts.push(Point::new(p.x, checked_add_oas(p.y, dy, off, "delta")?));
            }
        }
        2 => {
            for _ in 0..n {
                let (mag, dir) = reader.internal_integer(2, &format!("{ctx} 2-delta"))?;
                let mag = i32::try_from(mag).map_err(|_| {
                    OasisError::new(OasisErrorKind::ArithmeticOverflow, off, "delta > i32")
                })?;
                if mag == 0 {
                    return Err(OasisError::new(
                        OasisErrorKind::Malformed,
                        off,
                        "zero delta",
                    ));
                }
                let p = *pts.last().unwrap();
                let (dx, dy) = match dir {
                    0 => (mag, 0),
                    1 => (0, mag),
                    2 => (-mag, 0),
                    3 => (0, -mag),
                    _ => unreachable!(),
                };
                pts.push(Point::new(
                    checked_add_oas(p.x, dx, off, "delta x")?,
                    checked_add_oas(p.y, dy, off, "delta y")?,
                ));
            }
        }
        3 => {
            for _ in 0..n {
                let (mag, dir) = reader.internal_integer(3, &format!("{ctx} 3-delta"))?;
                let mag = i32::try_from(mag).map_err(|_| {
                    OasisError::new(OasisErrorKind::ArithmeticOverflow, off, "delta > i32")
                })?;
                if mag == 0 {
                    return Err(OasisError::new(
                        OasisErrorKind::Malformed,
                        off,
                        "zero delta",
                    ));
                }
                let p = *pts.last().unwrap();
                let (dx, dy) = match dir {
                    0 => (mag, 0),
                    1 => (0, mag),
                    2 => (-mag, 0),
                    3 => (0, -mag),
                    4 => (mag, mag),
                    5 => (-mag, mag),
                    6 => (-mag, -mag),
                    7 => (mag, -mag),
                    _ => unreachable!(),
                };
                pts.push(Point::new(
                    checked_add_oas(p.x, dx, off, "delta x")?,
                    checked_add_oas(p.y, dy, off, "delta y")?,
                ));
            }
        }
        4 | 5 => {
            for _ in 0..n {
                let dx = coordinate(reader, &format!("{ctx} g-dx"))?;
                let dy = coordinate(reader, &format!("{ctx} g-dy"))?;
                let p = *pts.last().unwrap();
                pts.push(Point::new(
                    checked_add_oas(p.x, dx, off, "delta x")?,
                    checked_add_oas(p.y, dy, off, "delta y")?,
                ));
            }
        }
        _ => {
            return Err(OasisError::unsupported(
                off,
                format!("{ctx} point-list type {pl_type} not supported"),
            ));
        }
    }
    Ok(pts)
}

fn read_path_record(
    reader: &mut Reader<'_>,
    modal: &mut ModalState,
    off: usize,
) -> Result<Vec<GdsElement>, OasisError> {
    let info = reader.byte("PATH info")?;
    let has_l = info & 0x01 != 0;
    let has_d = info & 0x02 != 0;
    let has_rep = info & 0x04 != 0;
    let has_y = info & 0x08 != 0;
    let has_x = info & 0x10 != 0;
    let has_pl = info & 0x20 != 0;
    let has_w = info & 0x40 != 0;
    let has_ext = info & 0x80 != 0;

    let layer = if has_l {
        let l = read_layer(reader, "PATH layer")?;
        modal.layer = Some(l);
        l
    } else {
        modal_or(modal.layer, off, "PATH omits layer with no modal")?
    };
    let datatype = if has_d {
        let d = read_layer(reader, "PATH datatype")?;
        modal.datatype = Some(d);
        d
    } else {
        modal_or(modal.datatype, off, "PATH omits datatype with no modal")?
    };
    let pw = if has_w {
        let w = dimension(reader, "PATH width")?;
        modal.path_width = Some(w);
        w
    } else {
        modal_or(modal.path_width, off, "PATH omits width with no modal")?
    };

    let (begin_ext, end_ext) = if has_ext {
        let scheme = reader.byte("PATH ext scheme")?;
        let se = match scheme & 0x0c {
            0x00 => 0i32,
            0x04 => pw / 2,
            0x08 => coordinate(reader, "PATH start ext")?,
            _ => return Err(OasisError::unsupported(off, "PATH ext reserved bits")),
        };
        let ee = match scheme & 0x30 {
            0x00 => 0i32,
            0x10 => pw / 2,
            0x20 => coordinate(reader, "PATH end ext")?,
            _ => return Err(OasisError::unsupported(off, "PATH ext reserved bits")),
        };
        (Some(se), Some(ee))
    } else {
        (None, None)
    };

    let point_list = if has_pl {
        read_point_list(reader, off, "PATH")?
    } else {
        return Err(OasisError::unsupported(
            off,
            "PATH omits point-list with no modal",
        ));
    };

    let raw_x = if has_x {
        coordinate(reader, "PATH x")?
    } else {
        modal.x
    };
    let raw_y = if has_y {
        coordinate(reader, "PATH y")?
    } else {
        modal.y
    };
    let ox = modal.resolve_x(raw_x)?;
    let oy = modal.resolve_y(raw_y)?;

    let reps = if has_rep {
        read_repetition(reader, off)?
    } else {
        vec![(0, 0)]
    };

    let centerline: Vec<Point> = point_list
        .iter()
        .map(|p| {
            Ok(Point::new(
                checked_add_oas(ox, p.x, off, "PATH xlat x")?,
                checked_add_oas(oy, p.y, off, "PATH xlat y")?,
            ))
        })
        .collect::<Result<_, OasisError>>()?;
    if centerline.len() < 2 {
        return Err(OasisError::new(
            OasisErrorKind::Malformed,
            off,
            "PATH < 2 points",
        ));
    }

    let props = modal.take_properties();
    let pt = if begin_ext.is_some() || end_ext.is_some() {
        Some(4i16)
    } else {
        Some(0)
    };

    let mut out = Vec::with_capacity(reps.len());
    for &(rdx, rdy) in &reps {
        let shifted: Vec<Point> = centerline
            .iter()
            .map(|p| {
                Ok(Point::new(
                    checked_add_oas(p.x, rdx, off, "PATH rep x")?,
                    checked_add_oas(p.y, rdy, off, "PATH rep y")?,
                ))
            })
            .collect::<Result<_, OasisError>>()?;
        out.push(GdsElement::Path(GdsPath {
            layer,
            datatype,
            centerline: shifted,
            width: Some(pw),
            path_type: pt,
            begin_extension: begin_ext,
            end_extension: end_ext,
            meta: GdsElementMeta {
                properties: props.clone(),
                ..Default::default()
            },
        }));
    }
    Ok(out)
}

fn read_text_record(
    reader: &mut Reader<'_>,
    modal: &mut ModalState,
    off: usize,
) -> Result<Vec<GdsElement>, OasisError> {
    let info = reader.byte("TEXT info")?;
    let has_l = info & 0x01 != 0;
    let has_d = info & 0x02 != 0;
    let has_rep = info & 0x04 != 0;
    let has_y = info & 0x08 != 0;
    let has_x = info & 0x10 != 0;
    let has_txt = info & 0x20 != 0;
    let has_ref = info & 0x40 != 0;

    if has_ref {
        return Err(OasisError::unsupported(
            off,
            "TEXT reference-number not supported",
        ));
    }

    let text = if has_txt {
        let s = reader.astring("TEXT string")?;
        modal.text_string = Some(s.clone());
        s
    } else {
        modal_or(
            modal.text_string.clone(),
            off,
            "TEXT omits string with no modal",
        )?
    };
    let layer = if has_l {
        let l = read_layer(reader, "TEXT layer")?;
        modal.textlayer = Some(l);
        l
    } else {
        modal_or(modal.textlayer, off, "TEXT omits layer with no modal")?
    };
    let datatype = if has_d {
        let d = read_layer(reader, "TEXT datatype")?;
        modal.texttype = Some(d);
        d
    } else {
        modal_or(modal.texttype, off, "TEXT omits datatype with no modal")?
    };

    let raw_x = if has_x {
        coordinate(reader, "TEXT x")?
    } else {
        modal.x
    };
    let raw_y = if has_y {
        coordinate(reader, "TEXT y")?
    } else {
        modal.y
    };
    let x = modal.resolve_x(raw_x)?;
    let y = modal.resolve_y(raw_y)?;

    let reps = if has_rep {
        read_repetition(reader, off)?
    } else {
        vec![(0, 0)]
    };
    let props = modal.take_properties();

    let mut out = Vec::with_capacity(reps.len());
    for &(rdx, rdy) in &reps {
        out.push(GdsElement::Text(GdsText {
            layer,
            text_type: datatype,
            origin: Point::new(
                checked_add_oas(x, rdx, off, "TEXT rep x")?,
                checked_add_oas(y, rdy, off, "TEXT rep y")?,
            ),
            string: text.clone(),
            presentation: None,
            path_type: None,
            width: None,
            transform: GdsTransform::default(),
            meta: GdsElementMeta {
                properties: props.clone(),
                ..Default::default()
            },
        }));
    }
    Ok(out)
}

fn read_placement_modal(
    reader: &mut Reader<'_>,
    modal: &mut ModalState,
    off: usize,
) -> Result<Vec<GdsElement>, OasisError> {
    let info = reader.byte("PLACEMENT info")?;
    // OASIS PLACEMENT (17) info: C(7) N(6) X(5) Y(4) R(3) A1(2) A0(1) F(0)
    let has_cell = info & 0x80 != 0;
    let has_ref_num = info & 0x40 != 0;
    let has_x = info & 0x20 != 0;
    let has_y = info & 0x10 != 0;
    let has_rep = info & 0x08 != 0;
    let angle_code = (info >> 1) & 0x03;
    let reflected = info & 0x01 != 0;

    if !has_cell && has_ref_num {
        return Err(OasisError::unsupported(
            off,
            "PLACEMENT ref-number not supported",
        ));
    }

    let structure = if has_cell || has_ref_num {
        let s = reader.nstring("PLACEMENT cell name")?;
        modal.placement_cell = Some(s.clone());
        s
    } else {
        modal_or(
            modal.placement_cell.clone(),
            off,
            "PLACEMENT omits cell with no modal",
        )?
    };

    let raw_x = if has_x {
        coordinate(reader, "PLACEMENT x")?
    } else {
        modal.x
    };
    let raw_y = if has_y {
        coordinate(reader, "PLACEMENT y")?
    } else {
        modal.y
    };
    let x = modal.resolve_x(raw_x)?;
    let y = modal.resolve_y(raw_y)?;

    let reps = if has_rep {
        read_repetition(reader, off)?
    } else {
        vec![(0, 0)]
    };
    let props = modal.take_properties();

    let mut out = Vec::with_capacity(reps.len());
    for &(rdx, rdy) in &reps {
        out.push(GdsElement::Sref(GdsReference {
            structure: structure.clone(),
            origin: Point::new(
                checked_add_oas(x, rdx, off, "PLCMT rep x")?,
                checked_add_oas(y, rdy, off, "PLCMT rep y")?,
            ),
            transform: GdsTransform {
                reflected,
                angle_degrees: Some(f64::from(angle_code) * 90.0),
                ..Default::default()
            },
            meta: GdsElementMeta {
                properties: props.clone(),
                ..Default::default()
            },
        }));
    }
    Ok(out)
}

fn read_placement_transform(
    reader: &mut Reader<'_>,
    modal: &mut ModalState,
    off: usize,
) -> Result<Vec<GdsElement>, OasisError> {
    let info = reader.byte("PLACEMENT_TRANSFORM info")?;
    // OASIS PLACEMENT (18) info: C(7) N(6) X(5) Y(4) R(3) M(2) A(1) F(0)
    let has_cell = info & 0x80 != 0;
    let has_ref_num = info & 0x40 != 0;
    let has_x = info & 0x20 != 0;
    let has_y = info & 0x10 != 0;
    let has_rep = info & 0x08 != 0;
    let has_mag = info & 0x04 != 0;
    let has_angle = info & 0x02 != 0;
    let reflected = info & 0x01 != 0;

    if !has_cell && has_ref_num {
        return Err(OasisError::unsupported(
            off,
            "PLACEMENT_TRANSFORM ref-number not supported",
        ));
    }

    let structure = if has_cell || has_ref_num {
        let s = reader.nstring("PLACEMENT_TRANSFORM cell")?;
        modal.placement_cell = Some(s.clone());
        s
    } else {
        modal_or(
            modal.placement_cell.clone(),
            off,
            "PLACEMENT_TRANSFORM omits cell",
        )?
    };

    // ponytail: only positive-integer real (type 0) for mag/angle; upgrade if needed
    let magnification = if has_mag {
        let rt = reader.byte("mag real type")?;
        if rt != 0 {
            return Err(OasisError::unsupported(
                off,
                "non-integer real for magnification",
            ));
        }
        Some(reader.unsigned("magnification")? as f64)
    } else {
        None
    };
    let angle_degrees = if has_angle {
        let rt = reader.byte("angle real type")?;
        if rt != 0 {
            return Err(OasisError::unsupported(off, "non-integer real for angle"));
        }
        Some(reader.unsigned("angle")? as f64)
    } else {
        None
    };

    let raw_x = if has_x {
        coordinate(reader, "PLACEMENT_TRANSFORM x")?
    } else {
        modal.x
    };
    let raw_y = if has_y {
        coordinate(reader, "PLACEMENT_TRANSFORM y")?
    } else {
        modal.y
    };
    let x = modal.resolve_x(raw_x)?;
    let y = modal.resolve_y(raw_y)?;

    let reps = if has_rep {
        read_repetition(reader, off)?
    } else {
        vec![(0, 0)]
    };
    let props = modal.take_properties();

    let mut out = Vec::with_capacity(reps.len());
    for &(rdx, rdy) in &reps {
        out.push(GdsElement::Sref(GdsReference {
            structure: structure.clone(),
            origin: Point::new(
                checked_add_oas(x, rdx, off, "PT rep x")?,
                checked_add_oas(y, rdy, off, "PT rep y")?,
            ),
            transform: GdsTransform {
                reflected,
                magnification,
                angle_degrees,
                ..Default::default()
            },
            meta: GdsElementMeta {
                properties: props.clone(),
                ..Default::default()
            },
        }));
    }
    Ok(out)
}

fn read_property_record(
    reader: &mut Reader<'_>,
    modal: &mut ModalState,
    off: usize,
) -> Result<(), OasisError> {
    let info = reader.byte("PROPERTY info")?;
    let has_ref = info & 0x02 != 0;
    let has_name = info & 0x04 != 0;
    let has_value = info & 0x08 != 0;

    if has_ref {
        return Err(OasisError::unsupported(
            off,
            "PROPERTY ref-number name not supported",
        ));
    }

    let name = if has_name {
        let n = reader.nstring("PROPERTY name")?;
        modal.last_property_name = Some(n.clone());
        n
    } else {
        modal_or(
            modal.last_property_name.clone(),
            off,
            "PROPERTY omits name with no modal",
        )?
    };

    let value_str = if has_value {
        let vc = (info >> 5) & 0x07;
        let count = if vc == 0 {
            0usize
        } else if vc == 7 {
            reader.unsigned("PROPERTY value count")? as usize
        } else {
            vc as usize
        };
        let mut vals = Vec::with_capacity(count);
        for _ in 0..count {
            vals.push(read_property_value(reader, off)?);
        }
        vals.join(";")
    } else {
        String::new()
    };

    modal.pending_properties.push(GdsProperty {
        attribute: 0,
        value: format!("{name}={value_str}"),
    });
    Ok(())
}

fn read_property_value(reader: &mut Reader<'_>, off: usize) -> Result<String, OasisError> {
    let pv = reader.unsigned("PROPERTY value type")?;
    match pv {
        0..=7 => Ok(reader.unsigned("PROPERTY uint value")?.to_string()),
        8 => reader.astring("PROPERTY A-string value"),
        9 => {
            let b = reader.bstring("PROPERTY B-string value")?;
            let mut hex = String::with_capacity(b.len() * 2);
            for byte in b {
                hex.push_str(&format!("{byte:02x}"));
            }
            Ok(hex)
        }
        10 => reader.nstring("PROPERTY N-string value"),
        _ => Err(OasisError::unsupported(
            off,
            format!("PROPERTY value type {pv}"),
        )),
    }
}

// ponytail: types 1-5 (regular/irregular 1D+2D grids); types 6-10 (diagonal)
// return Unsupported — add when real tapeout files need them.
fn read_repetition(reader: &mut Reader<'_>, off: usize) -> Result<Vec<(i32, i32)>, OasisError> {
    let rt = reader.unsigned("repetition type")?;
    match rt {
        1 => {
            let cols = reader.unsigned("rep cols")? as i64 + 2;
            let rows = reader.unsigned("rep rows")? as i64 + 2;
            let cs = dimension(reader, "rep col-space")?;
            let rs = dimension(reader, "rep row-space")?;
            let mut v = Vec::with_capacity((cols * rows) as usize);
            for r in 0..rows {
                for c in 0..cols {
                    v.push((
                        i32::try_from(c * cs as i64).map_err(|_| {
                            OasisError::new(OasisErrorKind::ArithmeticOverflow, off, "rep overflow")
                        })?,
                        i32::try_from(r * rs as i64).map_err(|_| {
                            OasisError::new(OasisErrorKind::ArithmeticOverflow, off, "rep overflow")
                        })?,
                    ));
                }
            }
            Ok(v)
        }
        2 => {
            let n = reader.unsigned("rep count")? as i64 + 2;
            let s = dimension(reader, "rep space")?;
            (0..n)
                .map(|i| {
                    Ok((
                        i32::try_from(i * s as i64).map_err(|_| {
                            OasisError::new(OasisErrorKind::ArithmeticOverflow, off, "rep overflow")
                        })?,
                        0,
                    ))
                })
                .collect()
        }
        3 => {
            let n = reader.unsigned("rep count")? as i64 + 2;
            let s = dimension(reader, "rep space")?;
            (0..n)
                .map(|i| {
                    Ok((
                        0,
                        i32::try_from(i * s as i64).map_err(|_| {
                            OasisError::new(OasisErrorKind::ArithmeticOverflow, off, "rep overflow")
                        })?,
                    ))
                })
                .collect()
        }
        4 => {
            let n = reader.unsigned("rep count")? as usize + 2;
            let mut v = Vec::with_capacity(n);
            v.push((0, 0));
            let mut acc = 0i64;
            for _ in 1..n {
                acc += dimension(reader, "rep space")? as i64;
                v.push((
                    i32::try_from(acc).map_err(|_| {
                        OasisError::new(OasisErrorKind::ArithmeticOverflow, off, "rep overflow")
                    })?,
                    0,
                ));
            }
            Ok(v)
        }
        5 => {
            let n = reader.unsigned("rep count")? as usize + 2;
            let mut v = Vec::with_capacity(n);
            v.push((0, 0));
            let mut acc = 0i64;
            for _ in 1..n {
                acc += dimension(reader, "rep space")? as i64;
                v.push((
                    0,
                    i32::try_from(acc).map_err(|_| {
                        OasisError::new(OasisErrorKind::ArithmeticOverflow, off, "rep overflow")
                    })?,
                ));
            }
            Ok(v)
        }
        6..=10 => Err(OasisError::unsupported(
            off,
            format!("repetition type {rt} (diagonal/arbitrary) not implemented"),
        )),
        _ => Err(OasisError::unsupported(
            off,
            format!("unknown repetition type {rt}"),
        )),
    }
}

fn read_cblock(reader: &mut Reader<'_>, off: usize) -> Result<Vec<u8>, OasisError> {
    let ct = reader.unsigned("CBLOCK type")?;
    if ct != 0 {
        return Err(OasisError::unsupported(
            off,
            format!("CBLOCK type {ct}; only DEFLATE (0) supported"),
        ));
    }
    let uncompressed = reader.unsigned("CBLOCK uncompressed size")? as usize;
    let compressed = reader.unsigned("CBLOCK compressed size")? as usize;
    if reader.remaining() < compressed {
        return Err(OasisError::new(
            OasisErrorKind::Malformed,
            off,
            "CBLOCK data truncated",
        ));
    }
    let data = &reader.bytes[reader.at..reader.at + compressed];
    reader.at += compressed;

    use std::io::Read;
    let mut decoder = flate2::read::DeflateDecoder::new(data);
    let mut out = Vec::with_capacity(uncompressed);
    decoder.read_to_end(&mut out).map_err(|e| {
        OasisError::new(
            OasisErrorKind::Malformed,
            off,
            format!("CBLOCK decompress: {e}"),
        )
    })?;
    if out.len() != uncompressed {
        return Err(OasisError::new(
            OasisErrorKind::Malformed,
            off,
            format!(
                "CBLOCK size mismatch: declared {uncompressed}, got {}",
                out.len()
            ),
        ));
    }
    Ok(out)
}

fn read_end(reader: &mut Reader<'_>, record_offset: usize) -> Result<(), OasisError> {
    let padding = reader.bstring("END padding")?;
    if padding.iter().any(|byte| *byte != 0) {
        return Err(OasisError::new(
            OasisErrorKind::Malformed,
            record_offset,
            "END padding contains nonzero bytes",
        ));
    }
    let validation_offset = reader.at;
    let validation = reader.byte("END validation scheme")?;
    if validation != 0 {
        return Err(OasisError::unsupported(
            validation_offset,
            format!("END validation scheme {validation}; signatures are not implemented"),
        ));
    }
    if reader.at - record_offset != 256 {
        return Err(OasisError::new(
            OasisErrorKind::Malformed,
            record_offset,
            format!(
                "END record occupies {} bytes; required size is 256",
                reader.at - record_offset
            ),
        ));
    }
    Ok(())
}

fn validate_oasis_hierarchy(library: &GdsLibrary, offset: usize) -> Result<(), OasisError> {
    let by_name: HashMap<&str, &GdsStructure> = library
        .structures
        .iter()
        .map(|structure| (structure.name.as_str(), structure))
        .collect();
    validate_hierarchy(library, &by_name).map_err(|error| {
        let kind = match error.kind {
            super::gds::LayoutErrorKind::UndefinedReference => OasisErrorKind::UndefinedReference,
            super::gds::LayoutErrorKind::HierarchyCycle => OasisErrorKind::HierarchyCycle,
            _ => OasisErrorKind::Malformed,
        };
        OasisError::new(kind, offset, error.message)
    })
}

fn unsupported_record_message(record: u64) -> String {
    let name = match record {
        3 | 4 => "CELLNAME/reference-number table",
        5 | 6 => "TEXTSTRING",
        7..=10 => "property name/string table",
        11 | 12 => "LAYERNAME table",
        13 => "reference-number CELL",
        23..=27 => "trapezoid/circle geometry",
        30..=33 => "extension record",
        35 => "unknown record",
        _ => "unknown record",
    };
    format!("record {record} ({name}) is outside the declared OASIS subset")
}

// ---------------------------------------------------------------------------
// Deterministic subset writer (unchanged — only writes explicit nonmodal subset)
// ---------------------------------------------------------------------------

pub fn write_oasis(library: &GdsLibrary) -> Result<Vec<u8>, OasisError> {
    let unit = 1.0e-6 / library.units.meters_per_database_unit;
    let rounded_unit = unit.round();
    if !unit.is_finite()
        || unit <= 0.0
        || (unit - rounded_unit).abs() > 1.0e-9 * unit.abs().max(1.0)
        || rounded_unit > u64::MAX as f64
    {
        return Err(OasisError::unsupported(
            0,
            "OASIS subset writer requires an integer database-units-per-micron value",
        ));
    }
    let mut out = MAGIC.to_vec();
    put_unsigned(&mut out, START);
    put_nstring(&mut out, "1.0")?;
    out.push(0); // positive-integer real
    put_unsigned(&mut out, rounded_unit as u64);
    put_unsigned(&mut out, 0); // offset table is in START
    for _ in 0..12 {
        put_unsigned(&mut out, 0);
    }

    let mut names = HashSet::new();
    for structure in &library.structures {
        if !names.insert(structure.name.as_str()) {
            return Err(OasisError::new(
                OasisErrorKind::Duplicate,
                out.len(),
                format!("duplicate CELL `{}`", structure.name),
            ));
        }
        if !structure.unhandled_records.is_empty() {
            return Err(OasisError::unsupported(
                out.len(),
                format!("CELL `{}` has unhandled GDS records", structure.name),
            ));
        }
        put_unsigned(&mut out, CELL);
        put_nstring(&mut out, &structure.name)?;
        put_unsigned(&mut out, XYABSOLUTE);
        for element in &structure.elements {
            write_oasis_element(&mut out, element)?;
        }
    }
    validate_oasis_hierarchy(library, 0)?;
    write_end(&mut out);
    Ok(out)
}

fn write_oasis_element(out: &mut Vec<u8>, element: &GdsElement) -> Result<(), OasisError> {
    match element {
        GdsElement::Boundary(boundary) => {
            ensure_empty_meta(&boundary.meta, out.len(), "BOUNDARY")?;
            Ring::new(boundary.ring.clone()).map_err(|error| {
                OasisError::new(
                    OasisErrorKind::Malformed,
                    out.len(),
                    format!("invalid BOUNDARY: {error}"),
                )
            })?;
            if let Some((x, y, width, height)) = rectangle_dimensions(&boundary.ring) {
                put_unsigned(out, RECTANGLE);
                out.push(EXPLICIT_RECTANGLE_INFO);
                put_layer(out, boundary.layer, "RECTANGLE layer")?;
                put_layer(out, boundary.datatype, "RECTANGLE datatype")?;
                put_unsigned(out, width as u64);
                put_unsigned(out, height as u64);
                put_signed(out, i64::from(x));
                put_signed(out, i64::from(y));
            } else {
                if !boundary.ring.iter().enumerate().all(|(index, point)| {
                    let next = boundary.ring[(index + 1) % boundary.ring.len()];
                    point.x == next.x || point.y == next.y
                }) {
                    return Err(OasisError::unsupported(
                        out.len(),
                        "non-rectilinear POLYGON",
                    ));
                }
                put_unsigned(out, POLYGON);
                out.push(EXPLICIT_POLYGON_INFO);
                put_layer(out, boundary.layer, "POLYGON layer")?;
                put_layer(out, boundary.datatype, "POLYGON datatype")?;
                out.push(2); // Manhattan 2-delta point list
                put_unsigned(out, (boundary.ring.len() - 1) as u64);
                for edge in boundary.ring.windows(2) {
                    put_2delta(out, edge[1].x - edge[0].x, edge[1].y - edge[0].y)?;
                }
                put_signed(out, i64::from(boundary.ring[0].x));
                put_signed(out, i64::from(boundary.ring[0].y));
            }
        }
        GdsElement::Sref(reference) => {
            ensure_empty_meta(&reference.meta, out.len(), "SREF")?;
            if reference.transform.magnification != None
                || reference.transform.absolute_angle
                || reference.transform.absolute_magnification
                || reference.transform.reserved_bits != 0
            {
                return Err(OasisError::unsupported(
                    out.len(),
                    "SREF transform outside orthogonal PLACEMENT",
                ));
            }
            let angle = reference.transform.angle_degrees().rem_euclid(360.0);
            let quarter = (angle / 90.0).round();
            if (angle - quarter * 90.0).abs() > 1.0e-12 {
                return Err(OasisError::unsupported(
                    out.len(),
                    "non-orthogonal SREF angle",
                ));
            }
            put_unsigned(out, PLACEMENT);
            out.push(
                EXPLICIT_PLACEMENT_BASE
                    | (((quarter as i64).rem_euclid(4) as u8) << 1)
                    | u8::from(reference.transform.reflected),
            );
            put_nstring(out, &reference.structure)?;
            put_signed(out, i64::from(reference.origin.x));
            put_signed(out, i64::from(reference.origin.y));
        }
        GdsElement::Path(_) => {
            return Err(OasisError::unsupported(
                out.len(),
                "PATH write not implemented",
            ))
        }
        GdsElement::Text(_) => {
            return Err(OasisError::unsupported(
                out.len(),
                "TEXT write not implemented",
            ))
        }
        GdsElement::Aref(_) => {
            return Err(OasisError::unsupported(
                out.len(),
                "AREF write not implemented",
            ))
        }
        GdsElement::Box(_) => {
            return Err(OasisError::unsupported(
                out.len(),
                "BOX write not implemented",
            ))
        }
        GdsElement::Node(_) => {
            return Err(OasisError::unsupported(
                out.len(),
                "NODE write not implemented",
            ))
        }
        GdsElement::Unsupported(_) => {
            return Err(OasisError::unsupported(out.len(), "unsupported element"))
        }
    }
    Ok(())
}

fn ensure_empty_meta(meta: &GdsElementMeta, offset: usize, kind: &str) -> Result<(), OasisError> {
    if meta.properties.is_empty()
        && meta.element_flags.is_none()
        && meta.plex.is_none()
        && meta.unhandled_records.is_empty()
    {
        Ok(())
    } else {
        Err(OasisError::unsupported(
            offset,
            format!("{kind} properties/metadata are not implemented"),
        ))
    }
}

fn rectangle_dimensions(ring: &[Point]) -> Option<(i32, i32, i32, i32)> {
    if ring.len() != 4 {
        return None;
    }
    let xmin = ring.iter().map(|point| point.x).min()?;
    let xmax = ring.iter().map(|point| point.x).max()?;
    let ymin = ring.iter().map(|point| point.y).min()?;
    let ymax = ring.iter().map(|point| point.y).max()?;
    let corners: HashSet<(i32, i32)> = ring.iter().map(|point| (point.x, point.y)).collect();
    if corners
        == [(xmin, ymin), (xmax, ymin), (xmax, ymax), (xmin, ymax)]
            .into_iter()
            .collect()
    {
        Some((xmin, ymin, xmax.checked_sub(xmin)?, ymax.checked_sub(ymin)?))
    } else {
        None
    }
}

fn put_layer(out: &mut Vec<u8>, value: i16, context: &str) -> Result<(), OasisError> {
    if value < 0 {
        return Err(OasisError::new(
            OasisErrorKind::Malformed,
            out.len(),
            format!("negative {context}"),
        ));
    }
    put_unsigned(out, value as u64);
    Ok(())
}

fn put_nstring(out: &mut Vec<u8>, value: &str) -> Result<(), OasisError> {
    if value.is_empty() || !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return Err(OasisError::new(
            OasisErrorKind::Malformed,
            out.len(),
            format!("`{value}` is not an OASIS N-string"),
        ));
    }
    put_unsigned(out, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn put_unsigned(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn put_signed(out: &mut Vec<u8>, value: i64) {
    let (magnitude, sign) = if value < 0 {
        (value.unsigned_abs(), 1)
    } else {
        (value as u64, 0)
    };
    put_internal(out, magnitude, 1, sign);
}

fn put_2delta(out: &mut Vec<u8>, dx: i32, dy: i32) -> Result<(), OasisError> {
    let (magnitude, direction) = match (dx, dy) {
        (x, 0) if x > 0 => (x as u64, 0),
        (0, y) if y > 0 => (y as u64, 1),
        (x, 0) if x < 0 => (u64::from(x.unsigned_abs()), 2),
        (0, y) if y < 0 => (u64::from(y.unsigned_abs()), 3),
        _ => {
            return Err(OasisError::new(
                OasisErrorKind::Malformed,
                out.len(),
                "POLYGON edge is zero-length or non-Manhattan",
            ))
        }
    };
    put_internal(out, magnitude, 2, direction);
    Ok(())
}

fn put_internal(out: &mut Vec<u8>, mut magnitude: u64, skip_bits: u8, bits: u8) {
    let first_value_bits = 7 - skip_bits;
    let mut byte = bits | (((magnitude & ((1 << first_value_bits) - 1)) as u8) << skip_bits);
    magnitude >>= first_value_bits;
    if magnitude != 0 {
        byte |= 0x80;
    }
    out.push(byte);
    while magnitude != 0 {
        let mut byte = (magnitude & 0x7f) as u8;
        magnitude >>= 7;
        if magnitude != 0 {
            byte |= 0x80;
        }
        out.push(byte);
    }
}

fn write_end(out: &mut Vec<u8>) {
    let start = out.len();
    put_unsigned(out, END);
    put_unsigned(out, 252);
    out.resize(out.len() + 252, 0);
    out.push(0); // no validation signature
    debug_assert_eq!(out.len() - start, 256);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gds::{read_gds_library, write_gds_library, GdsReadMode};
    use crate::hierarchy_index::{HierarchyIndexOptions, HierarchySpatialIndex};

    fn rectangle(x0: i32, y0: i32, x1: i32, y1: i32) -> Vec<Point> {
        vec![
            Point::new(x0, y0),
            Point::new(x1, y0),
            Point::new(x1, y1),
            Point::new(x0, y1),
        ]
    }

    fn boundary(ring: Vec<Point>) -> GdsElement {
        GdsElement::Boundary(GdsBoundary {
            layer: 7,
            datatype: 0,
            ring,
            meta: GdsElementMeta::default(),
        })
    }

    fn structure(name: &str, elements: Vec<GdsElement>) -> GdsStructure {
        GdsStructure {
            timestamps: [0; 12],
            name: name.to_string(),
            elements,
            unhandled_records: Vec::new(),
        }
    }

    fn library() -> GdsLibrary {
        let l_shape = vec![
            Point::new(0, 0),
            Point::new(30, 0),
            Point::new(30, 10),
            Point::new(10, 10),
            Point::new(10, 30),
            Point::new(0, 30),
        ];
        GdsLibrary {
            version: 600,
            timestamps: [0; 12],
            name: "source".to_string(),
            units: GdsUnits {
                user_units_per_database_unit: 1.0e-3,
                meters_per_database_unit: 1.0e-9,
            },
            structures: vec![
                structure(
                    "leaf",
                    vec![boundary(rectangle(-10, -20, 10, 20)), boundary(l_shape)],
                ),
                structure(
                    "top",
                    vec![GdsElement::Sref(GdsReference {
                        structure: "leaf".to_string(),
                        origin: Point::new(100, 200),
                        transform: GdsTransform {
                            reflected: true,
                            angle_degrees: Some(270.0),
                            ..Default::default()
                        },
                        meta: GdsElementMeta::default(),
                    })],
                ),
            ],
            unhandled_records: Vec::new(),
            envelope: GdsEnvelope::complete(),
        }
    }

    #[test]
    fn declared_capability_matrix_is_explicit() {
        assert!(OASIS_CAPABILITIES.version_1_0);
        assert!(OASIS_CAPABILITIES.explicit_rectangles);
        assert!(OASIS_CAPABILITIES.explicit_rectilinear_polygons);
        assert!(OASIS_CAPABILITIES.named_orthogonal_placements);
        assert!(OASIS_CAPABILITIES.paths);
        assert!(OASIS_CAPABILITIES.text);
        assert!(OASIS_CAPABILITIES.repetitions);
        assert!(OASIS_CAPABILITIES.properties);
        assert!(OASIS_CAPABILITIES.modal_fields);
        assert!(OASIS_CAPABILITIES.compressed_blocks);
    }

    #[test]
    fn oasis_round_trip_and_gds_layout_hash_are_equivalent() {
        let source = library();
        let oasis1 = write_oasis(&source).expect("supported OASIS write");
        assert_eq!(&oasis1[..MAGIC.len()], MAGIC);
        let parsed1 = read_oasis(&oasis1).expect("supported OASIS read");
        let oasis2 = write_oasis(&parsed1).expect("deterministic rewrite");
        let parsed2 = read_oasis(&oasis2).expect("rewritten OASIS read");
        assert_eq!(oasis1, oasis2);
        assert_eq!(parsed1.structures, parsed2.structures);
        assert!((parsed1.units.database_unit_nm() - 1.0).abs() < 1.0e-12);

        let source_index =
            HierarchySpatialIndex::build(&source, HierarchyIndexOptions::default()).unwrap();
        let oasis_index =
            HierarchySpatialIndex::build(&parsed1, HierarchyIndexOptions::default()).unwrap();
        assert_eq!(
            source_index.equivalent_layout_hash("top").unwrap(),
            oasis_index.equivalent_layout_hash("top").unwrap()
        );

        let gds = write_gds_library(&parsed1).expect("OASIS DB is GDS-writable");
        let reparsed_gds = read_gds_library(&gds, GdsReadMode::Strict).unwrap();
        let gds_index =
            HierarchySpatialIndex::build(&reparsed_gds, HierarchyIndexOptions::default()).unwrap();
        assert_eq!(
            oasis_index.equivalent_layout_hash("top").unwrap(),
            gds_index.equivalent_layout_hash("top").unwrap(),
        );
    }

    fn start_prefix() -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        put_unsigned(&mut bytes, START);
        put_nstring(&mut bytes, "1.0").unwrap();
        bytes.push(0);
        put_unsigned(&mut bytes, 1_000);
        put_unsigned(&mut bytes, 0);
        for _ in 0..12 {
            put_unsigned(&mut bytes, 0);
        }
        bytes
    }

    fn add_end(bytes: &mut Vec<u8>) {
        let start = bytes.len();
        put_unsigned(bytes, END);
        put_unsigned(bytes, 252);
        bytes.resize(bytes.len() + 252, 0);
        bytes.push(0);
        debug_assert_eq!(bytes.len() - start, 256);
    }

    #[test]
    fn every_omitted_record_is_offset_bearing_unsupported() {
        // Records now handled: 16 (XYRELATIVE), 18 (PLACEMENT_TRANSFORM),
        // 19 (TEXT), 22 (PATH), 28/29 (PROPERTY), 34 (CBLOCK)
        let unsupported = [
            3_u64, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 23, 24, 25, 26, 27, 30, 31, 32, 33, 35, 127,
        ];
        for record in unsupported {
            let mut bytes = start_prefix();
            let offset = bytes.len();
            put_unsigned(&mut bytes, record);
            let error = read_oasis(&bytes).unwrap_err();
            assert_eq!(error.kind, OasisErrorKind::Unsupported, "record {record}");
            assert_eq!(error.offset, offset, "record {record}");
        }
    }

    #[test]
    fn modal_rectangle_reuses_layer() {
        let mut bytes = start_prefix();
        put_unsigned(&mut bytes, CELL);
        put_nstring(&mut bytes, "top").unwrap();
        put_unsigned(&mut bytes, XYABSOLUTE);
        // First RECTANGLE: explicit everything
        put_unsigned(&mut bytes, RECTANGLE);
        bytes.push(EXPLICIT_RECTANGLE_INFO);
        put_unsigned(&mut bytes, 7); // layer
        put_unsigned(&mut bytes, 0); // datatype
        put_unsigned(&mut bytes, 10); // width
        put_unsigned(&mut bytes, 20); // height
        put_signed(&mut bytes, 0); // x
        put_signed(&mut bytes, 0); // y
                                   // Second RECTANGLE: reuse layer+datatype
        put_unsigned(&mut bytes, RECTANGLE);
        bytes.push(0x7b & !0x01 & !0x02); // omit L and D
        put_unsigned(&mut bytes, 5); // width
        put_unsigned(&mut bytes, 5); // height
        put_signed(&mut bytes, 100); // x
        put_signed(&mut bytes, 100); // y
        add_end(&mut bytes);

        let lib = read_oasis(&bytes).expect("modal rectangle");
        assert_eq!(lib.structures[0].elements.len(), 2);
        let GdsElement::Boundary(b) = &lib.structures[0].elements[1] else {
            panic!("expected boundary");
        };
        assert_eq!(b.layer, 7);
        assert_eq!(b.datatype, 0);
    }

    #[test]
    fn text_record_round_trip() {
        let mut bytes = start_prefix();
        put_unsigned(&mut bytes, CELL);
        put_nstring(&mut bytes, "top").unwrap();
        put_unsigned(&mut bytes, XYABSOLUTE);
        // Explicit TEXT: layer=5, type=9, string="VDD", x=100, y=200
        put_unsigned(&mut bytes, TEXT_RECORD);
        // info: L(1) D(2) X(16) Y(8) T(32) = 0x3b
        bytes.push(0x3b);
        // text string (A-string)
        put_unsigned(&mut bytes, 3); // length
        bytes.extend_from_slice(b"VDD");
        put_unsigned(&mut bytes, 5); // layer
        put_unsigned(&mut bytes, 9); // datatype
        put_signed(&mut bytes, 100); // x
        put_signed(&mut bytes, 200); // y
                                     // Need a RECTANGLE to make it a valid non-empty cell for hierarchy
        put_unsigned(&mut bytes, RECTANGLE);
        bytes.push(EXPLICIT_RECTANGLE_INFO);
        put_unsigned(&mut bytes, 7);
        put_unsigned(&mut bytes, 0);
        put_unsigned(&mut bytes, 10);
        put_unsigned(&mut bytes, 10);
        put_signed(&mut bytes, 0);
        put_signed(&mut bytes, 0);
        add_end(&mut bytes);

        let lib = read_oasis(&bytes).expect("text parse");
        let GdsElement::Text(t) = &lib.structures[0].elements[0] else {
            panic!("expected text");
        };
        assert_eq!(t.string, "VDD");
        assert_eq!(t.layer, 5);
        assert_eq!(t.text_type, 9);
        assert_eq!(t.origin, Point::new(100, 200));
    }

    #[test]
    fn path_record_parses() {
        let mut bytes = start_prefix();
        put_unsigned(&mut bytes, CELL);
        put_nstring(&mut bytes, "top").unwrap();
        put_unsigned(&mut bytes, XYABSOLUTE);
        // PATH: layer=7, datatype=0, width=4, centerline (0,0)->(20,0)
        put_unsigned(&mut bytes, PATH_RECORD);
        // info: L(1) D(2) P(32) X(16) Y(8) W(64) = 0x7b
        bytes.push(0x7b);
        put_unsigned(&mut bytes, 7); // layer
        put_unsigned(&mut bytes, 0); // datatype
        put_unsigned(&mut bytes, 4); // width
                                     // point list type 4 (general dx,dy)
        bytes.push(4);
        put_unsigned(&mut bytes, 1); // 1 delta (2 points total with origin)
        put_signed(&mut bytes, 20); // dx
        put_signed(&mut bytes, 0); // dy
        put_signed(&mut bytes, 0); // x
        put_signed(&mut bytes, 0); // y
        add_end(&mut bytes);

        let lib = read_oasis(&bytes).expect("path parse");
        let GdsElement::Path(p) = &lib.structures[0].elements[0] else {
            panic!("expected path");
        };
        assert_eq!(p.layer, 7);
        assert_eq!(p.width, Some(4));
        assert_eq!(p.centerline.len(), 2);
        assert_eq!(p.centerline[0], Point::new(0, 0));
        assert_eq!(p.centerline[1], Point::new(20, 0));
    }

    #[test]
    fn xyrelative_mode_accumulates() {
        let mut bytes = start_prefix();
        put_unsigned(&mut bytes, CELL);
        put_nstring(&mut bytes, "top").unwrap();
        put_unsigned(&mut bytes, XYABSOLUTE);
        // First rectangle at (10, 20)
        put_unsigned(&mut bytes, RECTANGLE);
        bytes.push(EXPLICIT_RECTANGLE_INFO);
        put_unsigned(&mut bytes, 7);
        put_unsigned(&mut bytes, 0);
        put_unsigned(&mut bytes, 5);
        put_unsigned(&mut bytes, 5);
        put_signed(&mut bytes, 10);
        put_signed(&mut bytes, 20);
        // Switch to XYRELATIVE
        put_unsigned(&mut bytes, XYRELATIVE);
        // Second rectangle with delta (30, 40) -> absolute (40, 60)
        put_unsigned(&mut bytes, RECTANGLE);
        bytes.push(EXPLICIT_RECTANGLE_INFO);
        put_unsigned(&mut bytes, 7);
        put_unsigned(&mut bytes, 0);
        put_unsigned(&mut bytes, 5);
        put_unsigned(&mut bytes, 5);
        put_signed(&mut bytes, 30);
        put_signed(&mut bytes, 40);
        add_end(&mut bytes);

        let lib = read_oasis(&bytes).expect("xyrelative");
        let GdsElement::Boundary(b0) = &lib.structures[0].elements[0] else {
            panic!();
        };
        assert_eq!(b0.ring[0], Point::new(10, 20));
        let GdsElement::Boundary(b1) = &lib.structures[0].elements[1] else {
            panic!();
        };
        assert_eq!(b1.ring[0], Point::new(40, 60));
    }

    #[test]
    fn validation_fail_closed() {
        let mut validation = write_oasis(&library()).unwrap();
        let validation_offset = validation.len() - 1;
        validation[validation_offset] = 1;
        let error = read_oasis(&validation).unwrap_err();
        assert_eq!(error.kind, OasisErrorKind::Unsupported);
        assert_eq!(error.offset, validation_offset);
    }

    #[test]
    fn malformed_truncation_and_varint_corpus_never_panics() {
        let valid = write_oasis(&library()).unwrap();
        let mut corpus = vec![
            Vec::new(),
            b"%SEMI".to_vec(),
            [MAGIC.as_slice(), &[0x81]].concat(),
            [MAGIC.as_slice(), &[1, 3, b'1']].concat(),
            [MAGIC.as_slice(), &[0x80; 11]].concat(),
        ];
        for end in [13, 14, 15, 20, valid.len() - 1] {
            corpus.push(valid[..end].to_vec());
        }
        for bytes in corpus {
            let result = std::panic::catch_unwind(|| read_oasis(&bytes));
            assert!(result.is_ok(), "panic for {bytes:?}");
            assert!(result.unwrap().is_err());
        }
    }

    #[test]
    fn writer_rejects_unimplemented_path_text_repetition_and_properties() {
        let mut source = library();
        let GdsElement::Boundary(boundary) = &mut source.structures[0].elements[0] else {
            unreachable!()
        };
        boundary.meta.properties.push(crate::gds::GdsProperty {
            attribute: 1,
            value: "not-supported".to_string(),
        });
        assert_eq!(
            write_oasis(&source).unwrap_err().kind,
            OasisErrorKind::Unsupported
        );

        let mut source = library();
        source.structures[1]
            .elements
            .push(GdsElement::Aref(crate::gds::GdsArrayReference {
                structure: "leaf".to_string(),
                columns: 2,
                rows: 2,
                origin: Point::new(0, 0),
                column_endpoint: Point::new(20, 0),
                row_endpoint: Point::new(0, 20),
                transform: GdsTransform::default(),
                meta: GdsElementMeta::default(),
            }));
        assert_eq!(
            write_oasis(&source).unwrap_err().kind,
            OasisErrorKind::Unsupported
        );
    }
}
