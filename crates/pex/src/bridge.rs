//! Layout/process-stack bridge for the quasi-static PEX solvers.
//!
//! The bridge keeps the public lumped [`NetParasitics`](crate::NetParasitics)
//! contract while replacing the analytical models underneath it:
//!
//! * rectilinear conductor polygons are extruded into 3-D BEM panels and solved
//!   together for a Maxwell capacitance matrix;
//! * sheet-resistance polygons become DC FastHenry segments with conductivity
//!   derived from sheet resistance and physical metal thickness;
//! * fixed via/contact resistances remain fixed deck contributions because they
//!   describe an interface device, not a volume conductor the field solver can
//!   infer.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Once;

use crate::analytical::process_stack::{ProcessLayer, ProcessStack};
use crate::geometry::{decompose_rectilinear, GeometryStore, LayerId, PolyId, Rect};
use crate::params::Deck;
use crate::quasistatic::cap;
use crate::quasistatic::geometry::Vec3;
use crate::quasistatic::henry;
use crate::quasistatic::integrals::panel::Panel;
use crate::NetParasitics;

const METRES_PER_NM: f64 = 1.0e-9;
const AF_PER_F: f64 = 1.0e18;
const MAX_GRID_CELLS: usize = 262_144;
const MAX_PANELS: usize = 20_000;
const DENSE_PANEL_LIMIT: usize = 500;

/// A layout or process-stack condition the field-solver bridge cannot model
/// without fabricating a result.
#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    #[error("deck database unit must be finite and positive, got {0} nm")]
    InvalidDatabaseUnit(f64),
    #[error("PEX layer {layer} has invalid {field} value {value}")]
    InvalidProcessValue {
        layer: LayerId,
        field: &'static str,
        value: f64,
    },
    #[error("polygon {polygon} cannot be extruded for quasi-static PEX: {message}")]
    UnsupportedGeometry { polygon: u32, message: String },
    #[error("conductor union grid needs {cells} cells; limit is {limit}")]
    GridCapacity { cells: usize, limit: usize },
    #[error("extruded layout needs {panels} panels; limit is {limit}")]
    PanelCapacity { panels: usize, limit: usize },
    #[error("capacitance solve failed: {0}")]
    Capacitance(String),
    #[error("resistance solve failed: {0}")]
    Resistance(#[from] henry::SolveError),
    #[error("quasi-static solver returned a non-finite {quantity} for net {net}")]
    NonFiniteResult { net: u32, quantity: &'static str },
}

#[derive(Debug)]
struct VolumeGroup {
    net: u32,
    z0: f64,
    z1: f64,
    dielectric_k: f64,
    rects: Vec<Rect>,
}

/// Extract lumped per-net R/C with the quasi-static solvers.
///
/// Coordinates are converted from layout DBU through [`Deck::dbu_nm`]; stack
/// heights/thicknesses are interpreted in nanometres. The returned map has the
/// same net and unit conventions as analytical
/// [`crate::run_pex_by_net_analytical`].
pub fn extract_quasistatic(
    store: &GeometryStore,
    deck: &Deck,
    net_of_poly: &[u32],
) -> Result<HashMap<u32, NetParasitics>, BridgeError> {
    if !deck.dbu_nm.is_finite() || deck.dbu_nm <= 0.0 {
        return Err(BridgeError::InvalidDatabaseUnit(deck.dbu_nm));
    }

    let stack = ProcessStack::from_deck(deck);
    let stack_by_layer: HashMap<LayerId, &ProcessLayer> = stack
        .layers
        .iter()
        .map(|layer| (layer.layer, layer))
        .collect();
    validate_stack(&stack)?;

    let mut out = HashMap::<u32, NetParasitics>::new();
    let mut grouped = BTreeMap::<(u32, LayerId), VolumeGroup>::new();
    let net_for = |polygon: usize| net_of_poly.get(polygon).copied().unwrap_or(u32::MAX);

    for polygon in 0..store.poly_count() {
        let layer = store.poly_layer[polygon];
        let Some(params) = deck.pex.get(&layer) else {
            continue;
        };
        let net = net_for(polygon);
        let volume_conductor = is_volume_conductor(params);

        if params.via_res_ohm != 0.0 {
            out.entry(net).or_default().r_ohm += params.via_res_ohm;
        }

        if !volume_conductor {
            continue;
        }
        out.entry(net).or_default();
        let process =
            stack_by_layer
                .get(&layer)
                .copied()
                .ok_or(BridgeError::InvalidProcessValue {
                    layer,
                    field: "process-layer mapping",
                    value: f64::NAN,
                })?;
        let rects = decompose_rectilinear(store, PolyId(polygon as u32)).map_err(|error| {
            BridgeError::UnsupportedGeometry {
                polygon: polygon as u32,
                message: error.to_string(),
            }
        })?;
        if rects.is_empty() {
            return Err(BridgeError::UnsupportedGeometry {
                polygon: polygon as u32,
                message: "rectilinear decomposition produced no material".into(),
            });
        }
        grouped
            .entry((net, layer))
            .or_insert_with(|| VolumeGroup {
                net,
                z0: process.height_above_substrate_nm * METRES_PER_NM,
                z1: (process.height_above_substrate_nm + process.thickness_nm) * METRES_PER_NM,
                dielectric_k: process.dielectric_constant,
                rects: Vec::new(),
            })
            .rects
            .extend(rects);
    }

    solve_resistance(store, deck, net_of_poly, &stack_by_layer, &mut out)?;
    solve_capacitance(&grouped, deck.dbu_nm * METRES_PER_NM, &mut out)?;
    Ok(out)
}

fn validate_stack(stack: &ProcessStack) -> Result<(), BridgeError> {
    for layer in &stack.layers {
        for (field, value, positive) in [
            ("thickness_nm", layer.thickness_nm, true),
            ("height_nm", layer.height_above_substrate_nm, false),
            ("dielectric_k", layer.dielectric_constant, true),
        ] {
            if !value.is_finite()
                || (positive && value <= 0.0)
                || (field == "height_nm" && value < 0.0)
            {
                return Err(BridgeError::InvalidProcessValue {
                    layer: layer.layer,
                    field,
                    value,
                });
            }
        }
    }
    Ok(())
}

fn is_volume_conductor(params: &crate::params::PexLayerParams) -> bool {
    params.sheet_res_ohm_sq != 0.0
        || params.area_cap_af_um2 != 0.0
        || params.fringe_cap_af_um != 0.0
        || params.coupling_cap_af_um != 0.0
        || params.interlayer_cap_af_um2 != 0.0
        || (params.thickness_nm > 0.0 && params.via_res_ohm == 0.0)
}

fn solve_resistance(
    store: &GeometryStore,
    deck: &Deck,
    net_of_poly: &[u32],
    stack_by_layer: &HashMap<LayerId, &ProcessLayer>,
    out: &mut HashMap<u32, NetParasitics>,
) -> Result<(), BridgeError> {
    let mut netlist = henry::Netlist::default();
    let mut port_nets = Vec::new();
    let xy_scale = deck.dbu_nm * METRES_PER_NM;

    for polygon in 0..store.poly_count() {
        let layer = store.poly_layer[polygon];
        let Some(params) = deck.pex.get(&layer) else {
            continue;
        };
        if params.sheet_res_ohm_sq == 0.0 {
            continue;
        }
        let process =
            stack_by_layer
                .get(&layer)
                .copied()
                .ok_or(BridgeError::InvalidProcessValue {
                    layer,
                    field: "process-layer mapping",
                    value: f64::NAN,
                })?;
        let metrics = crate::analytical::rectilinear_metrics(store, PolyId(polygon as u32))
            .map_err(|message| BridgeError::UnsupportedGeometry {
                polygon: polygon as u32,
                message,
            })?;
        let length = metrics.equivalent_length_nm * xy_scale;
        let width = metrics.equivalent_width_nm * xy_scale;
        let thickness = process.thickness_nm * METRES_PER_NM;
        let sheet_resistance = params.sheet_res_ohm_sq;
        let sigma = 1.0 / (sheet_resistance * thickness);
        if !length.is_finite()
            || !width.is_finite()
            || !sigma.is_finite()
            || length <= 0.0
            || width <= 0.0
            || sigma <= 0.0
        {
            return Err(BridgeError::InvalidProcessValue {
                layer,
                field: "sheet-resistance volume",
                value: sheet_resistance,
            });
        }

        let bbox = store.poly_bbox[polygon];
        let cx = 0.5 * (f64::from(bbox.xmin) + f64::from(bbox.xmax)) * xy_scale;
        let cy = 0.5 * (f64::from(bbox.ymin) + f64::from(bbox.ymax)) * xy_scale;
        let cz = (process.height_above_substrate_nm + 0.5 * process.thickness_nm) * METRES_PER_NM;
        let along_x = i64::from(bbox.xmax) - i64::from(bbox.xmin)
            >= i64::from(bbox.ymax) - i64::from(bbox.ymin);
        let (p1, p2, wdir) = if along_x {
            (
                [cx - 0.5 * length, cy, cz],
                [cx + 0.5 * length, cy, cz],
                Some([0.0, 1.0, 0.0]),
            )
        } else {
            (
                [cx, cy - 0.5 * length, cz],
                [cx, cy + 0.5 * length, cz],
                Some([1.0, 0.0, 0.0]),
            )
        };

        let index = netlist.segments.len();
        let n1 = format!("N{index}a");
        let n2 = format!("N{index}b");
        insert_node(&mut netlist, n1.clone(), p1);
        insert_node(&mut netlist, n2.clone(), p2);
        netlist.segments.push(henry::Segment {
            name: format!("E{index}"),
            n1: n1.clone(),
            n2: n2.clone(),
            w: width,
            h: thickness,
            sigma,
            nhinc: 1,
            nwinc: 1,
            rw: 2.0,
            rh: 2.0,
            wdir,
        });
        netlist.ports.push(henry::Port {
            name: format!("poly_{polygon}"),
            n1,
            n2,
        });
        port_nets.push(net_of_poly.get(polygon).copied().unwrap_or(u32::MAX));
    }

    if netlist.segments.is_empty() {
        return Ok(());
    }
    netlist.freq = Some(henry::FreqSweep {
        fmin: 0.0,
        fmax: 0.0,
        ndec: 1.0,
    });
    let solved = henry::solve_with(&netlist, henry::Method::Direct)?;
    let resistance = solved.resistance(0);
    for (port, net) in port_nets.into_iter().enumerate() {
        let ohm = resistance[(port, port)];
        if !ohm.is_finite() {
            return Err(BridgeError::NonFiniteResult {
                net,
                quantity: "resistance",
            });
        }
        out.entry(net).or_default().r_ohm += ohm;
    }
    Ok(())
}

fn insert_node(netlist: &mut henry::Netlist, name: String, pos: [f64; 3]) {
    let index = netlist.nodes.len();
    netlist.node_index.insert(name.to_ascii_lowercase(), index);
    netlist.nodes.push(henry::Node { name, pos });
}

fn solve_capacitance(
    groups: &BTreeMap<(u32, LayerId), VolumeGroup>,
    xy_scale: f64,
    out: &mut HashMap<u32, NetParasitics>,
) -> Result<(), BridgeError> {
    if groups.is_empty() {
        return Ok(());
    }

    let nets: BTreeSet<u32> = groups.values().map(|group| group.net).collect();
    let net_index: BTreeMap<u32, usize> = nets
        .iter()
        .enumerate()
        .map(|(index, &net)| (net, index))
        .collect();
    let mut panels = Vec::<Panel>::new();
    let mut panel_eps = Vec::<f64>::new();
    let mut bounds = [
        f64::INFINITY,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NEG_INFINITY,
    ];
    let mut min_z = f64::INFINITY;
    let mut max_thickness = 0.0_f64;

    for group in groups.values() {
        let conductor = net_index[&group.net];
        append_group_panels(group, conductor, xy_scale, &mut panels, &mut panel_eps)?;
        for rect in &group.rects {
            bounds[0] = bounds[0].min(f64::from(rect.x0) * xy_scale);
            bounds[1] = bounds[1].min(f64::from(rect.y0) * xy_scale);
            bounds[2] = bounds[2].max(f64::from(rect.x1) * xy_scale);
            bounds[3] = bounds[3].max(f64::from(rect.y1) * xy_scale);
        }
        min_z = min_z.min(group.z0);
        max_thickness = max_thickness.max(group.z1 - group.z0);
    }

    // A finite substrate reference is included in the same Maxwell solve. If
    // the stack explicitly places its lowest conductor above z=0, z=0 is the
    // substrate; heuristic stacks start at zero, so put the reference one metal
    // thickness below them to avoid coincident surfaces.
    let ground_gap = if min_z > 0.0 {
        min_z
    } else {
        max_thickness.max(100.0 * METRES_PER_NM)
    };
    let ground_z = if min_z > 0.0 { 0.0 } else { min_z - ground_gap };
    let span_x = bounds[2] - bounds[0];
    let span_y = bounds[3] - bounds[1];
    let padding = 0.5 * span_x.max(span_y).max(8.0 * ground_gap);
    let ground_lx = span_x + 2.0 * padding;
    let ground_ly = span_y + 2.0 * padding;
    let ground_id = nets.len();
    let ground_eps = groups
        .values()
        .min_by(|a, b| a.z0.total_cmp(&b.z0))
        .map_or(1.0, |group| group.dielectric_k);
    let ground_nx = (ground_lx / (4.0 * ground_gap)).ceil().clamp(4.0, 32.0) as usize;
    let ground_ny = (ground_ly / (4.0 * ground_gap)).ceil().clamp(4.0, 32.0) as usize;
    let ground = cap::mesh::plate(
        0.5 * (bounds[0] + bounds[2]),
        0.5 * (bounds[1] + bounds[3]),
        ground_z,
        ground_lx,
        ground_ly,
        ground_nx,
        ground_ny,
        ground_id,
    );
    panel_eps.extend(std::iter::repeat(ground_eps).take(ground.len()));
    panels.extend(ground);

    if panels.len() > MAX_PANELS {
        return Err(BridgeError::PanelCapacity {
            panels: panels.len(),
            limit: MAX_PANELS,
        });
    }
    let names: Vec<String> = nets
        .iter()
        .map(|net| format!("net_{net}"))
        .chain(std::iter::once("substrate".into()))
        .collect();

    let first_eps = panel_eps[0];
    let homogeneous = panel_eps
        .iter()
        .all(|eps| (*eps - first_eps).abs() <= first_eps.abs().max(1.0) * 1.0e-12);
    let capacitance = if homogeneous {
        let geometry = cap::from_panels(panels, names);
        let mut solved = if geometry.panels.len() < DENSE_PANEL_LIMIT {
            cap::solve(&geometry, cap::Method::Direct)
                .map_err(|error| BridgeError::Capacitance(error.to_string()))?
        } else {
            cap::fmm_solver::solve(&geometry, 4, 4, 1.0e-8)
        };
        for value in &mut solved.c.data {
            *value *= first_eps;
        }
        solved
    } else {
        if panels.len() >= DENSE_PANEL_LIMIT {
            return Err(BridgeError::PanelCapacity {
                panels: panels.len(),
                limit: DENSE_PANEL_LIMIT - 1,
            });
        }
        let roles = panels
            .iter()
            .zip(panel_eps)
            .map(|(panel, eps_surrounding)| cap::PanelRole::Conductor {
                id: panel.conductor,
                eps_surrounding,
            })
            .collect();
        cap::solve_dielectric(&cap::Problem {
            panels,
            roles,
            conductor_names: names,
        })
        .map_err(|error| BridgeError::Capacitance(error.to_string()))?
    };

    for (&net, &index) in &net_index {
        let cap_af = capacitance.c[(index, index)] * AF_PER_F;
        if !cap_af.is_finite() || cap_af < 0.0 {
            return Err(BridgeError::NonFiniteResult {
                net,
                quantity: "capacitance",
            });
        }
        out.entry(net).or_default().cap_af += cap_af;
    }
    Ok(())
}

fn append_group_panels(
    group: &VolumeGroup,
    conductor: usize,
    xy_scale: f64,
    panels: &mut Vec<Panel>,
    panel_eps: &mut Vec<f64>,
) -> Result<(), BridgeError> {
    let mut xs: Vec<i32> = group
        .rects
        .iter()
        .flat_map(|rect| [rect.x0, rect.x1])
        .collect();
    let mut ys: Vec<i32> = group
        .rects
        .iter()
        .flat_map(|rect| [rect.y0, rect.y1])
        .collect();
    xs.sort_unstable();
    xs.dedup();
    ys.sort_unstable();
    ys.dedup();
    let nx = xs.len().saturating_sub(1);
    let ny = ys.len().saturating_sub(1);
    let cells = nx.checked_mul(ny).unwrap_or(usize::MAX);
    if cells > MAX_GRID_CELLS {
        return Err(BridgeError::GridCapacity {
            cells,
            limit: MAX_GRID_CELLS,
        });
    }

    let mut filled = vec![false; cells];
    for ix in 0..nx {
        for iy in 0..ny {
            filled[ix * ny + iy] = group.rects.iter().any(|rect| {
                rect.x0 <= xs[ix]
                    && rect.x1 >= xs[ix + 1]
                    && rect.y0 <= ys[iy]
                    && rect.y1 >= ys[iy + 1]
            });
        }
    }

    // Greedily merge occupied arrangement cells for top/bottom panels. The
    // sidewalls below still use atomic boundary cells, preserving exact union
    // topology at T-junctions and partial overlaps.
    let mut consumed = vec![false; cells];
    for ix in 0..nx {
        for iy in 0..ny {
            let cell = ix * ny + iy;
            if !filled[cell] || consumed[cell] {
                continue;
            }
            let mut x_end = ix + 1;
            while x_end < nx && filled[x_end * ny + iy] && !consumed[x_end * ny + iy] {
                x_end += 1;
            }
            let mut y_end = iy + 1;
            'rows: while y_end < ny {
                for x in ix..x_end {
                    let next = x * ny + y_end;
                    if !filled[next] || consumed[next] {
                        break 'rows;
                    }
                }
                y_end += 1;
            }
            for x in ix..x_end {
                for y in iy..y_end {
                    consumed[x * ny + y] = true;
                }
            }
            let x0 = f64::from(xs[ix]) * xy_scale;
            let x1 = f64::from(xs[x_end]) * xy_scale;
            let y0 = f64::from(ys[iy]) * xy_scale;
            let y1 = f64::from(ys[y_end]) * xy_scale;
            append_xy_face(panels, x0, x1, y0, y1, group.z1, conductor, false);
            append_xy_face(panels, x0, x1, y0, y1, group.z0, conductor, true);
        }
    }

    for ix in 0..nx {
        for iy in 0..ny {
            if !filled[ix * ny + iy] {
                continue;
            }
            let x0 = f64::from(xs[ix]) * xy_scale;
            let x1 = f64::from(xs[ix + 1]) * xy_scale;
            let y0 = f64::from(ys[iy]) * xy_scale;
            let y1 = f64::from(ys[iy + 1]) * xy_scale;
            if ix == 0 || !filled[(ix - 1) * ny + iy] {
                append_yz_face(panels, x0, y0, y1, group.z0, group.z1, conductor, true);
            }
            if ix + 1 == nx || !filled[(ix + 1) * ny + iy] {
                append_yz_face(panels, x1, y0, y1, group.z0, group.z1, conductor, false);
            }
            if iy == 0 || !filled[ix * ny + iy - 1] {
                append_xz_face(panels, x0, x1, y0, group.z0, group.z1, conductor, false);
            }
            if iy + 1 == ny || !filled[ix * ny + iy + 1] {
                append_xz_face(panels, x0, x1, y1, group.z0, group.z1, conductor, true);
            }
        }
    }
    panel_eps.extend(std::iter::repeat(group.dielectric_k).take(panels.len() - panel_eps.len()));
    if panels.len() > MAX_PANELS {
        return Err(BridgeError::PanelCapacity {
            panels: panels.len(),
            limit: MAX_PANELS,
        });
    }
    Ok(())
}

fn subdivisions(length: f64, transverse: f64) -> usize {
    (length / (4.0 * transverse.max(f64::MIN_POSITIVE)))
        .ceil()
        .clamp(1.0, 32.0) as usize
}

#[allow(clippy::too_many_arguments)]
fn append_xy_face(
    panels: &mut Vec<Panel>,
    x0: f64,
    x1: f64,
    y0: f64,
    y1: f64,
    z: f64,
    conductor: usize,
    reverse: bool,
) {
    let nx = subdivisions(x1 - x0, y1 - y0);
    let ny = subdivisions(y1 - y0, x1 - x0);
    for ix in 0..nx {
        for iy in 0..ny {
            let xa = x0 + (x1 - x0) * ix as f64 / nx as f64;
            let xb = x0 + (x1 - x0) * (ix + 1) as f64 / nx as f64;
            let ya = y0 + (y1 - y0) * iy as f64 / ny as f64;
            let yb = y0 + (y1 - y0) * (iy + 1) as f64 / ny as f64;
            let mut vertices = vec![
                Vec3::new(xa, ya, z),
                Vec3::new(xb, ya, z),
                Vec3::new(xb, yb, z),
                Vec3::new(xa, yb, z),
            ];
            if reverse {
                vertices.reverse();
            }
            panels.push(Panel::new(vertices, conductor));
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn append_yz_face(
    panels: &mut Vec<Panel>,
    x: f64,
    y0: f64,
    y1: f64,
    z0: f64,
    z1: f64,
    conductor: usize,
    reverse: bool,
) {
    let ny = subdivisions(y1 - y0, z1 - z0);
    for iy in 0..ny {
        let ya = y0 + (y1 - y0) * iy as f64 / ny as f64;
        let yb = y0 + (y1 - y0) * (iy + 1) as f64 / ny as f64;
        let mut vertices = vec![
            Vec3::new(x, ya, z0),
            Vec3::new(x, yb, z0),
            Vec3::new(x, yb, z1),
            Vec3::new(x, ya, z1),
        ];
        if reverse {
            vertices.reverse();
        }
        panels.push(Panel::new(vertices, conductor));
    }
}

#[allow(clippy::too_many_arguments)]
fn append_xz_face(
    panels: &mut Vec<Panel>,
    x0: f64,
    x1: f64,
    y: f64,
    z0: f64,
    z1: f64,
    conductor: usize,
    reverse: bool,
) {
    let nx = subdivisions(x1 - x0, z1 - z0);
    for ix in 0..nx {
        let xa = x0 + (x1 - x0) * ix as f64 / nx as f64;
        let xb = x0 + (x1 - x0) * (ix + 1) as f64 / nx as f64;
        let mut vertices = vec![
            Vec3::new(xa, y, z0),
            Vec3::new(xb, y, z0),
            Vec3::new(xb, y, z1),
            Vec3::new(xa, y, z1),
        ];
        if reverse {
            vertices.reverse();
        }
        panels.push(Panel::new(vertices, conductor));
    }
}

static FALLBACK_WARN: Once = Once::new();

/// Log a quasi-static to analytical compatibility fallback once per process.
pub fn warn_fallback_once(error: &BridgeError) {
    FALLBACK_WARN.call_once(|| {
        eprintln!("pex: quasi-static extraction failed ({error}); falling back to analytical");
    });
}
