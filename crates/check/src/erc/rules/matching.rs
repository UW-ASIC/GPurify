//! Matched devices: the transistors a designer marks as one matched group
//! must be identical, parallel and share a centroid.
//!
//! Data in: the store, devices, the group marker layer. Data out: violations
//! and one run per row.

use crate::erc::rules::supply::point_in_region;
use crate::erc::ruleset::RuleHead;
use crate::erc::{first_vertex, record_run, Design};
use crate::report::{LimitSense, Measurement, Outcome, RuleRun, Violation, Violations};
use crate::topology::device::{DeviceMeasure, DeviceParam};
use crate::topology::{DeviceId, NetId, TerminalRole};
use gpurify_geom::ops::{winding_of, Point, Winding};
use gpurify_geom::{Dbu, LayerId, PolyId};
use gpurify_ingest::deck::DeviceKind;
use gpurify_ingest::StrId;

/// A matched group: deck kind `matching`, written `matching(group;
/// tolerance: len)`.
///
/// Each polygon of `group` marks one matched group: the MOS transistors whose
/// marker's centre lies in it. A transistor is a unit (a finger); units with
/// the same model and the same gate, source/drain (either way round) and
/// bulk nets are one device of the group. A row flags:
///
/// - a unit whose model, width or length differs from the group's first
///   unit (the lowest device id): GF180MCU MP.1 "Matched pair device layout
///   shall be exactly identical to each other" and MP.2a "the same
///   dimension ... a unit cell of the same size", and US10216888B2's "same
///   model name (subtype), number of fingers, finger width, and finger
///   length";
/// - a unit whose channel runs across the first unit's: MP.7 "Matched pair
///   devices shall run in parallel and not in perpendicular". A unit's
///   channel runs along the axis of its marker box whose extent is its
///   extracted length; a square marker has no readable axis and is not
///   judged;
/// - a device whose centroid lies more than `tolerance` from the first
///   device's on either axis: the common centroid, "the centroids of the
///   units of each device coincide" (Karmokar et al., ASP-DAC 2022, Eq. 2
///   and 3; Siemens's checker: "If the centers do not match, an error is
///   reported"). A device's centroid is its units' marker-box centres
///   weighted by their marker areas, Hastings's centroid of an array of
///   segments.
///
/// Needs no design intent.
///
/// # Limits
///
/// MP.7's anti-parallel current direction is not checked: a unit's source
/// and drain are in extraction order, and a multi-finger device alternates
/// them by construction. Dummy devices (MP.4), identical surroundings and
/// STI context (MP.5, MP.10), equal well-edge distance (well proximity),
/// and symmetry about an axis are not checked. A marker's centre is its box
/// centre, exact for a rectangle.
///
/// Catalog: ERC-H2 (partial) in the [check catalog]. Defined by
/// [GF180MCU] §10.6.2 MP.1, MP.2a and MP.7; [Karmokar 2022]; [Sarhan 2019]
/// (Siemens, the common-centroid and orientation checks); [US10216888B2]
/// (Cadence, parameter matching); Hastings, *The Art of Analog Layout*
/// (the centroid of an array). Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [GF180MCU]: https://gf180mcu-pdk.readthedocs.io/en/latest/physical_verification/design_manual/drm_10_6_2.html
/// [Karmokar 2022]: http://people.ece.umn.edu/~sachin/conf/aspdac22.pdf
/// [Sarhan 2019]: https://semiengineering.com/automated-analog-design-constraint-checking/
/// [US10216888B2]: https://patents.google.com/patent/US10216888B2/en
#[derive(Debug, Default, Clone, PartialEq)]
pub struct MatchingTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Per row: the layer whose polygons mark matched groups.
    pub group: Vec<LayerId>,
    /// Per row: how far two devices' centroids may lie apart on either axis.
    pub tolerance: Vec<Dbu>,
}

/// One unit's identity and geometry.
#[derive(Clone, Copy, PartialEq)]
struct Unit {
    marker: PolyId,
    model: StrId,
    /// Gate, the two channel ends in ascending order, and bulk.
    nets: [NetId; 4],
    width: Option<Dbu>,
    length: Option<Dbu>,
}

fn length_param(params: &[(DeviceParam, DeviceMeasure)], want: DeviceParam) -> Option<Dbu> {
    params.iter().find_map(|&(param, measure)| match measure {
        DeviceMeasure::Length(length) if param == want => Some(length),
        _ => None,
    })
}

/// `Some(true)` when a unit's channel runs along x, `Some(false)` along y,
/// `None` when its marker box does not say.
fn channel_along_x(design: Design<'_>, unit: &Unit) -> Option<bool> {
    let length = unit.length?;
    let b = design.store.poly_bbox(unit.marker);
    match (b.width() == length, b.height() == length) {
        (true, false) => Some(true),
        (false, true) => Some(false),
        _ => None,
    }
}

/// Runs every [`MatchingTable`] row over every group polygon.
///
/// `examined` counts the units in groups. A parameter or orientation
/// violation sits at the first vertex of the unit's marker, on its layer,
/// measuring the width or length difference against 0, or a differing model
/// or a crossing channel as the count 1 against 0. A centroid violation sits
/// at the first vertex of the device's first marker, measuring the larger
/// of its two offsets from the first device's centroid, rounded up to a
/// unit, against `tolerance`. Every row runs.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
#[allow(
    clippy::cast_precision_loss,
    reason = "marker coordinates and areas are far below 2^53"
)]
pub fn check_matching(
    design: Design<'_>,
    table: &MatchingTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let (store, devices) = (design.store, design.devices);
    for row in 0..table.head.len() {
        let before = out.len();
        let (rule, severity) = (table.head.rule[row], table.head.severity[row]);
        let mut push = |marker: PolyId, measured: Measurement, limit: Measurement| {
            out.push(Violation {
                rule,
                layer: store.poly_layer(marker),
                severity,
                at: first_vertex(store, marker),
                measured,
                limit,
                shapes: (marker, None),
            });
        };
        let mut examined = 0u64;
        for poly in store.polys_on_layer(table.group[row]) {
            let group = PolyId(poly);
            let (gx, gy) = store.poly_verts(group);
            if winding_of(gx, gy) == Some(Winding::Clockwise) {
                continue;
            }
            let mut units: Vec<Unit> = Vec::new();
            // ponytail: every device per group polygon, groups x devices; index
            // the markers by box if designs carry many groups.
            for device in 0..devices.len() {
                if devices.kind[device] != DeviceKind::Mos {
                    continue;
                }
                let id = DeviceId(u32::try_from(device).expect("a device id is a u32"));
                let marker = devices.marker[device];
                let b = store.poly_bbox(marker);
                let centre = Point {
                    x: Dbu::new_unchecked(i64::midpoint(b.xlo.raw(), b.xhi.raw())),
                    y: Dbu::new_unchecked(i64::midpoint(b.ylo.raw(), b.yhi.raw())),
                };
                if !point_in_region(gx, gy, centre) {
                    continue;
                }
                let (nets, roles) = devices.terminals_of(id);
                let mut net = [NetId::NONE; 4];
                let mut ends = Vec::new();
                for (&n, &role) in nets.iter().zip(roles) {
                    match role {
                        TerminalRole::Gate => net[0] = n,
                        TerminalRole::Source | TerminalRole::Drain => ends.push(n),
                        TerminalRole::Bulk => net[3] = n,
                        _ => {}
                    }
                }
                ends.sort_unstable();
                net[1] = ends.first().copied().unwrap_or(NetId::NONE);
                net[2] = ends.get(1).copied().unwrap_or(NetId::NONE);
                let params = devices.params_of(id);
                units.push(Unit {
                    marker,
                    model: devices.model[device],
                    nets: net,
                    width: length_param(params, DeviceParam::Width),
                    length: length_param(params, DeviceParam::Length),
                });
            }
            examined += units.len() as u64;
            let Some(&first) = units.first() else {
                continue;
            };
            // Identical units.
            for unit in &units[1..] {
                if unit.model != first.model {
                    push(unit.marker, Measurement::Count(1), Measurement::Count(0));
                }
                for (theirs, mine) in [(first.width, unit.width), (first.length, unit.length)] {
                    if let (Some(a), Some(b)) = (theirs, mine) {
                        if a != b {
                            push(
                                unit.marker,
                                Measurement::Length(Dbu::new_unchecked((a.raw() - b.raw()).abs())),
                                Measurement::Length(Dbu::new_unchecked(0)),
                            );
                        }
                    }
                }
            }
            // Parallel channels, against the first unit whose axis reads.
            let axes: Vec<Option<bool>> =
                units.iter().map(|u| channel_along_x(design, u)).collect();
            if let Some(reference) = axes.iter().flatten().next().copied() {
                for (unit, axis) in units.iter().zip(&axes) {
                    if axis.is_some_and(|along_x| along_x != reference) {
                        push(unit.marker, Measurement::Count(1), Measurement::Count(0));
                    }
                }
            }
            // Common centroid: devices in order of their first unit.
            let mut keys: Vec<(StrId, [NetId; 4])> = Vec::new();
            let mut sums: Vec<(f64, f64, f64, PolyId)> = Vec::new();
            for unit in &units {
                let b = store.poly_bbox(unit.marker);
                let area = b.area().raw() as f64;
                let (cx, cy) = (
                    (b.xlo.raw() + b.xhi.raw()) as f64 / 2.0,
                    (b.ylo.raw() + b.yhi.raw()) as f64 / 2.0,
                );
                let key = (unit.model, unit.nets);
                let at = keys.iter().position(|k| *k == key).unwrap_or_else(|| {
                    keys.push(key);
                    sums.push((0.0, 0.0, 0.0, unit.marker));
                    keys.len() - 1
                });
                sums[at].0 += area * cx;
                sums[at].1 += area * cy;
                sums[at].2 += area;
            }
            let centroid = |s: &(f64, f64, f64, PolyId)| (s.0 / s.2, s.1 / s.2);
            let Some(reference) = sums.first().map(centroid) else {
                continue;
            };
            let tolerance = table.tolerance[row];
            for s in &sums[1..] {
                let (x, y) = centroid(s);
                let off = (x - reference.0).abs().max((y - reference.1).abs());
                #[allow(
                    clippy::cast_possible_truncation,
                    reason = "an offset within the die fits an i64"
                )]
                let measured = Measurement::Length(Dbu::new_unchecked(off.ceil() as i64));
                let limit = Measurement::Length(tolerance);
                if off > tolerance.raw() as f64 && measured.violates(limit, LimitSense::Maximum) {
                    push(s.3, measured, limit);
                }
            }
        }
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}
