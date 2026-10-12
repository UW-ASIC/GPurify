//! A flattened design as a GDSII stream on a deck's layers, so the GDS
//! reader, the deck's derived layers and its label binding take it as they
//! take any layout.

use super::lex::MAX_COORD;
use super::{fault, FlatShape, LefDefError};
use crate::deck::{Connectivity, LayerTable};
use gpurify_geom::StrTable;

/// A GDSII layer and datatype.
type Pair = (u16, u16);

/// The flattened `shapes` as one GDSII structure named `design`, at `dbu`
/// database units per micrometre.
///
/// Each LEF layer is the deck layer of the same name (a drawn layer, with a
/// stream pair). A shape on a net gets a `TEXT` of the net's name at its
/// bounding box's centre on the deck's label layer for that layer: the
/// layer itself when a `connect label <layer> names …` row has it as its
/// text layer, else the text layer of a row that names it. Every shape of a
/// net is labelled, so a net DEF draws as two pieces the layout does not
/// join reads as an open, and two nets whose shapes touch as a short,
/// where label binding reports them.
///
/// # Errors
///
/// A LEF layer the deck does not define as a drawn layer; a net shape on
/// a conductor with no label layer; a polygon of more than 8191 vertices;
/// a coordinate past GDSII's 32-bit range.
pub fn to_gds(
    shapes: &[FlatShape],
    dbu: i64,
    design: &str,
    layers: &LayerTable,
    connectivity: &Connectivity,
    strings: &StrTable,
) -> Result<Vec<u8>, LefDefError> {
    let err = |message: String| fault("design", 0, message);
    let mut out = Vec::new();
    record(&mut out, 0x0002, &600_i16.to_be_bytes());
    record(&mut out, 0x0102, &[0; 24]);
    string(&mut out, 0x0206, "LEFDEF");
    #[expect(clippy::cast_precision_loss, reason = "a unit count, exact below 2^53")]
    let per_um = dbu as f64;
    let mut units = real(1.0 / per_um).to_vec();
    units.extend(real(1e-6 / per_um));
    record(&mut out, 0x0305, &units);
    record(&mut out, 0x0502, &[0; 24]);
    string(
        &mut out,
        0x0606,
        if design.is_empty() { "TOP" } else { design },
    );

    // Per LEF layer name: its stream pair and its label pair, looked up once.
    let mut lookup: Vec<(&str, Pair, Option<Pair>)> = Vec::new();
    for flat in shapes {
        let name = flat.shape.layer.as_str();
        let at = if let Some(at) = lookup.iter().position(|(n, _, _)| *n == name) {
            at
        } else {
            {
                let id = layers
                    .id(strings, name)
                    .filter(|&id| !layers.is_derived(id))
                    .ok_or_else(|| {
                        err(format!(
                            "LEF layer {name} is not a drawn layer of the deck; \
                             the deck's layer names must be the LEF's"
                        ))
                    })?;
                let rows = || 0..connectivity.label_layer.len();
                let label = rows()
                    .find(|&r| connectivity.label_layer[r] == id)
                    .or_else(|| rows().find(|&r| connectivity.label_names[r] == id))
                    .map(|r| layers.stream_of(connectivity.label_layer[r]));
                lookup.push((name, layers.stream_of(id), label));
                lookup.len() - 1
            }
        };
        // ponytail: a linear lookup per shape; a design's LEF has tens of layers.
        let (_, (layer, datatype), label) = lookup[at];
        if flat.shape.ring.len() > 8191 {
            return Err(err(format!(
                "a polygon of {} vertices on {name} is more than one GDSII XY record holds",
                flat.shape.ring.len()
            )));
        }
        let mut xy = Vec::with_capacity(8 * (flat.shape.ring.len() + 1));
        for &(x, y) in flat.shape.ring.iter().chain(&flat.shape.ring[..1]) {
            xy.extend(coord(x, name)?.to_be_bytes());
            xy.extend(coord(y, name)?.to_be_bytes());
        }
        record(&mut out, 0x0800, &[]);
        record(&mut out, 0x0D02, &layer.to_be_bytes());
        record(&mut out, 0x0E02, &datatype.to_be_bytes());
        record(&mut out, 0x1003, &xy);
        record(&mut out, 0x1100, &[]);
        let Some(net) = &flat.net else { continue };
        let Some((layer, texttype)) = label else {
            let conductor = layers
                .id(strings, name)
                .is_some_and(|id| connectivity.conductors.contains(&id));
            if conductor {
                return Err(err(format!(
                    "net {net} has shapes on {name}, which no `connect label` row names, \
                     so the net's name would be lost"
                )));
            }
            continue;
        };
        let (xlo, ylo, xhi, yhi) = flat.shape.bbox();
        let (cx, cy) = (xlo + (xhi - xlo) / 2, ylo + (yhi - ylo) / 2);
        let mut point = coord(cx, name)?.to_be_bytes().to_vec();
        point.extend(coord(cy, name)?.to_be_bytes());
        record(&mut out, 0x0C00, &[]);
        record(&mut out, 0x0D02, &layer.to_be_bytes());
        record(&mut out, 0x1602, &texttype.to_be_bytes());
        record(&mut out, 0x1003, &point);
        string(&mut out, 0x1906, net);
        record(&mut out, 0x1100, &[]);
    }
    record(&mut out, 0x0700, &[]);
    record(&mut out, 0x0400, &[]);
    Ok(out)
}

fn coord(v: i64, layer: &str) -> Result<i32, LefDefError> {
    i32::try_from(v)
        .ok()
        .filter(|v| u64::from(v.unsigned_abs()) <= MAX_COORD)
        .ok_or_else(|| {
            fault(
                "design",
                0,
                format!("a shape on {layer} reaches {v}, past GDSII's 32-bit coordinates"),
            )
        })
}

fn record(out: &mut Vec<u8>, tag: u16, payload: &[u8]) {
    let len = u16::try_from(payload.len() + 4).expect("a record under 64 KiB");
    out.extend(len.to_be_bytes());
    out.extend(tag.to_be_bytes());
    out.extend(payload);
}

/// An ASCII record, NUL-padded to an even length.
fn string(out: &mut Vec<u8>, tag: u16, text: &str) {
    let mut bytes = text.as_bytes()[..text.len().min(65_000)].to_vec();
    if bytes.len() % 2 == 1 {
        bytes.push(0);
    }
    record(out, tag, &bytes);
}

/// An eight-byte GDSII real: sign, a base-16 exponent in excess 64, and a
/// 56-bit fraction.
fn real(value: f64) -> [u8; 8] {
    if value == 0.0 {
        return [0; 8];
    }
    let (sign, mut v) = (u8::from(value < 0.0) << 7, value.abs());
    let mut exponent: i32 = 64;
    while v >= 1.0 {
        v /= 16.0;
        exponent += 1;
    }
    while v < 1.0 / 16.0 {
        v *= 16.0;
        exponent -= 1;
    }
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "v is in [1/16, 1), so the fraction is under 2^56"
    )]
    let fraction = ((v * 72_057_594_037_927_936.0).round() as u64).min((1 << 56) - 1);
    let mut out = fraction.to_be_bytes();
    out[0] = sign | u8::try_from(exponent).expect("a unit's exponent is within 0..128");
    out
}
