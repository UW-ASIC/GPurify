//! Hierarchical LVS — bottom-up cell matching with selective flattening.
//!
//! Follows the netgen approach:
//!   1. Build comparison queue from cell hierarchy (bottom-up order).
//!   2. Match cells by name or declared equivalence.
//!   3. Compare matched pairs from bottommost up.
//!   4. Matched cells become abstract devices with pins at parent level.
//!   5. Unmatched or failed cells are flattened into their parent.

use super::compare::{compare, CompareOpts};
use super::extract::extract_netlist_opts;
use super::types::*;
use crate::geometry::*;
use crate::params::Deck;
use std::collections::HashMap;

/// A cell in the layout hierarchy.
pub struct HierCell {
    pub name: String,
    pub geometry: GeometryStore,
    pub instances: Vec<CellInstance>,
    pub ports: Vec<Port>,
}

/// An instance of a subcell placed in a parent cell.
pub struct CellInstance {
    pub cell_name: String,
    pub dx: i32,
    pub dy: i32,
}

/// A boundary pin (port) of a cell.
pub struct Port {
    pub name: String,
    pub layer: LayerId,
    pub bbox: Bbox,
}

/// A matched subcircuit that becomes an abstract device at the parent level.
#[derive(Clone, Debug)]
pub struct SubcircuitDevice {
    pub cell_name: String,
    pub pins: Vec<(String, u32)>, // (pin_name, net_id)
}

/// Cache for matched cell signatures to avoid re-extraction.
// ponytail: simple HashMap keyed by cell name; content-hash invalidation
// if extraction results ever become non-deterministic.
#[derive(Default)]
pub struct HierLvsCacheSimple {
    matched: HashMap<String, SubcircuitDevice>,
}

impl HierLvsCacheSimple {
    pub fn get(&self, cell: &str) -> Option<&SubcircuitDevice> {
        self.matched.get(cell)
    }
    pub fn insert(&mut self, cell: String, device: SubcircuitDevice) {
        self.matched.insert(cell, device);
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.matched.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.matched.is_empty()
    }
}

/// Reference hierarchy for comparison.
pub struct RefHierarchy {
    pub cells: HashMap<String, RefCellNetlist>,
    pub top_cell: String,
}

/// Reference netlist for one cell in the hierarchy.
pub struct RefCellNetlist {
    pub netlist: RefNetlist,
    pub subcircuit_instances: Vec<RefSubcktInstance>,
}

pub struct RefSubcktInstance {
    pub cell_name: String,
    pub pins: Vec<(String, String)>, // (pin_name, net_name)
}

/// Result of hierarchical LVS.
pub struct HierLvsResult {
    pub matched: bool,
    pub per_cell: Vec<(String, LvsResult)>,
    pub flattened_cells: Vec<String>,
    /// Cells that were equated (layout_name -> reference_name used for lookup).
    pub equated: Vec<(String, String)>,
    /// Cells treated as black boxes (skipped extraction, assumed match).
    pub black_boxed: Vec<String>,
}

/// Extract port names from text labels in a cell's geometry.
///
/// Each text element sitting inside a conductor polygon becomes a port with that
/// text's label as its name. The port bbox is the bounding box of the containing polygon.
// ponytail: O(texts * polys) scan, spatial index if cell geometry is large.
pub fn extract_ports_from_text(
    geo: &GeometryStore,
    _net_names: &HashMap<u32, String>,
    net_of_poly: &[u32],
) -> Vec<Port> {
    let mut ports = Vec::new();
    let mut seen: HashMap<String, ()> = HashMap::new();
    for ti in 0..geo.text_count() {
        let tx = geo.text_x[ti];
        let ty = geo.text_y[ti];
        let label = geo.text_string[ti].clone();
        if seen.contains_key(&label) {
            continue;
        }
        for p in 0..geo.poly_count() {
            if p >= net_of_poly.len() {
                break;
            }
            let net = net_of_poly[p];
            if net == u32::MAX {
                continue;
            }
            let s = geo.poly_vert_start[p] as usize;
            let n = geo.poly_vert_len[p] as usize;
            if n < 3 {
                continue;
            }
            let (mut min_x, mut max_x) = (i32::MAX, i32::MIN);
            let (mut min_y, mut max_y) = (i32::MAX, i32::MIN);
            for i in 0..n {
                let vx = geo.verts_x[s + i];
                let vy = geo.verts_y[s + i];
                min_x = min_x.min(vx);
                max_x = max_x.max(vx);
                min_y = min_y.min(vy);
                max_y = max_y.max(vy);
            }
            if tx < min_x || tx > max_x || ty < min_y || ty > max_y {
                continue;
            }
            if point_in_polygon(tx, ty, &geo.verts_x[s..s + n], &geo.verts_y[s..s + n]) {
                seen.insert(label.clone(), ());
                ports.push(Port {
                    name: label.clone(),
                    layer: geo.poly_layer[p],
                    bbox: Bbox {
                        xmin: min_x,
                        ymin: min_y,
                        xmax: max_x,
                        ymax: max_y,
                    },
                });
                break;
            }
        }
    }
    ports
}

/// Winding number point-in-polygon test.
fn point_in_polygon(px: i32, py: i32, xs: &[i32], ys: &[i32]) -> bool {
    let n = xs.len();
    let mut winding = 0i32;
    for i in 0..n {
        let j = (i + 1) % n;
        let (yi, yj) = (ys[i], ys[j]);
        if yi <= py {
            if yj > py {
                let cross = (xs[j] as i64 - xs[i] as i64) * (py as i64 - yi as i64)
                    - (px as i64 - xs[i] as i64) * (yj as i64 - yi as i64);
                if cross > 0 {
                    winding += 1;
                }
            }
        } else if yj <= py {
            let cross = (xs[j] as i64 - xs[i] as i64) * (py as i64 - yi as i64)
                - (px as i64 - xs[i] as i64) * (yj as i64 - yi as i64);
            if cross < 0 {
                winding -= 1;
            }
        }
    }
    winding != 0
}

/// Run hierarchical LVS on a layout hierarchy against a reference hierarchy.
pub fn compare_hierarchical(
    layout: &HashMap<String, HierCell>,
    reference: &RefHierarchy,
    deck: &Deck,
    equate_cells: &[(String, String)],
) -> HierLvsResult {
    compare_hierarchical_cached(
        layout,
        reference,
        deck,
        equate_cells,
        &mut HierLvsCacheSimple::default(),
    )
}

/// Run hierarchical LVS with an external cache for matched cell signatures.
pub fn compare_hierarchical_cached(
    layout: &HashMap<String, HierCell>,
    reference: &RefHierarchy,
    deck: &Deck,
    equate_cells: &[(String, String)],
    cache: &mut HierLvsCacheSimple,
) -> HierLvsResult {
    // Build name equivalence map
    let mut equiv: HashMap<String, String> = HashMap::new();
    let mut equated_record: Vec<(String, String)> = Vec::new();
    for (a, b) in equate_cells {
        equiv.insert(a.clone(), b.clone());
        equiv.insert(b.clone(), a.clone());
        equated_record.push((a.clone(), b.clone()));
    }

    // Topological sort: compare leaf cells first, then parents
    let order = match topo_sort(layout) {
        Ok(o) => o,
        Err(cyc) => {
            return HierLvsResult {
                matched: false,
                per_cell: vec![(
                    cyc.clone(),
                    LvsResult {
                        matched: false,
                        reason: format!("circular cell reference through '{cyc}'"),
                        mismatches: Vec::new(),
                        extracted_devices: 0,
                        nmos: 0,
                        pmos: 0,
                        ambiguous_classes: 0,
                        label_conflicts: Vec::new(),
                        floating_nets: Vec::new(),
                        device_mappings: Vec::new(),
                        net_mappings: Vec::new(),
                        witness: None,
                    },
                )],
                flattened_cells: Vec::new(),
                equated: equated_record,
                black_boxed: Vec::new(),
            };
        }
    };

    let mut matched_cells: HashMap<String, bool> = HashMap::new();
    let mut per_cell: Vec<(String, LvsResult)> = Vec::new();
    let mut flattened: Vec<String> = Vec::new();
    let mut black_boxed: Vec<String> = Vec::new();
    // Working geometry per cell: flattened children get merged in before the
    // parent extracts, so the parent's netlist actually contains their devices.
    let mut work_geo: HashMap<String, GeometryStore> = layout
        .iter()
        .map(|(n, c)| (n.clone(), c.geometry.clone()))
        .collect();

    let opts = ExtractOpts {
        cut_required: deck.lvs_cut_required,
        ..Default::default()
    };
    let cmp_opts = CompareOpts {
        strict: false,
        w_tolerance: deck.w_tolerance.clone(),
        l_tolerance: deck.l_tolerance.clone(),
        pin_swaps: Vec::new(),
    };

    for cell_name in &order {
        if !layout.contains_key(cell_name) {
            continue;
        }

        // Black-box: skip extraction and comparison, treat as matched with
        // ports derived from the reference cell.
        if opts.black_box_cells.contains(cell_name) {
            let ref_name = equiv.get(cell_name).unwrap_or(cell_name);
            if let Some(ref_cell) = reference.cells.get(ref_name) {
                // Build a subcircuit device from reference net names (deduped)
                let mut pin_set: HashMap<String, u32> = HashMap::new();
                for d in &ref_cell.netlist.devices {
                    pin_set.entry(d.gate.clone()).or_insert(0);
                    pin_set.entry(d.source.clone()).or_insert(0);
                    pin_set.entry(d.drain.clone()).or_insert(0);
                }
                let pins: Vec<(String, u32)> = pin_set.into_iter().collect();
                cache.insert(
                    cell_name.clone(),
                    SubcircuitDevice {
                        cell_name: cell_name.clone(),
                        pins,
                    },
                );
            }
            black_boxed.push(cell_name.clone());
            per_cell.push((
                cell_name.clone(),
                LvsResult {
                    matched: true,
                    reason: "black-box: skipped".into(),
                    mismatches: Vec::new(),
                    extracted_devices: 0,
                    nmos: 0,
                    pmos: 0,
                    ambiguous_classes: 0,
                    label_conflicts: Vec::new(),
                    floating_nets: Vec::new(),
                    device_mappings: Vec::new(),
                    net_mappings: Vec::new(),
                    witness: None,
                },
            ));
            matched_cells.insert(cell_name.clone(), true);
            continue;
        }

        // Check cache: if this cell was already matched, reuse the result
        if cache.get(cell_name).is_some() {
            per_cell.push((
                cell_name.clone(),
                LvsResult {
                    matched: true,
                    reason: "cached match".into(),
                    mismatches: Vec::new(),
                    extracted_devices: 0,
                    nmos: 0,
                    pmos: 0,
                    ambiguous_classes: 0,
                    label_conflicts: Vec::new(),
                    floating_nets: Vec::new(),
                    device_mappings: Vec::new(),
                    net_mappings: Vec::new(),
                    witness: None,
                },
            ));
            matched_cells.insert(cell_name.clone(), true);
            continue;
        }

        // Find matching reference cell
        let ref_name = equiv.get(cell_name).unwrap_or(cell_name);
        let Some(ref_cell) = reference.cells.get(ref_name) else {
            // No reference cell -> flatten this cell's geometry into every parent
            // that instantiates it.
            let child_geo = work_geo[cell_name.as_str()].clone();
            for (pname, pcell) in layout.iter() {
                for inst in pcell.instances.iter().filter(|i| &i.cell_name == cell_name) {
                    let dst = work_geo.get_mut(pname).unwrap();
                    append_translated(dst, &child_geo, inst.dx, inst.dy);
                }
            }
            flattened.push(cell_name.clone());
            continue;
        };

        // Extract layout netlist for this cell
        let geo = &work_geo[cell_name.as_str()];
        let ext = match extract_netlist_opts(geo, deck, &opts, crate::backend::Backend::Cpu) {
            Ok(e) => e,
            Err(e) => {
                per_cell.push((
                    cell_name.clone(),
                    LvsResult {
                        matched: false,
                        reason: format!("extraction failed: {}", e),
                        mismatches: Vec::new(),
                        extracted_devices: 0,
                        nmos: 0,
                        pmos: 0,
                        ambiguous_classes: 0,
                        label_conflicts: Vec::new(),
                        floating_nets: Vec::new(),
                        device_mappings: Vec::new(),
                        net_mappings: Vec::new(),
                        witness: None,
                    },
                ));
                flattened.push(cell_name.clone());
                continue;
            }
        };

        let result = compare(&ext, &ref_cell.netlist, &cmp_opts);
        let cell_matched = result.matched;
        per_cell.push((cell_name.clone(), result));

        if cell_matched {
            // Cache the matched cell's subcircuit signature so parents can
            // treat it as an abstract device.
            let pins: Vec<(String, u32)> = ext
                .net_names
                .iter()
                .map(|(&net_id, name)| (name.clone(), net_id))
                .collect();
            cache.insert(
                cell_name.clone(),
                SubcircuitDevice {
                    cell_name: cell_name.clone(),
                    pins,
                },
            );
        } else {
            flattened.push(cell_name.clone());
        }
        matched_cells.insert(cell_name.clone(), cell_matched);
    }

    let all_matched = per_cell.iter().all(|(_, r)| r.matched);
    HierLvsResult {
        matched: all_matched,
        per_cell,
        flattened_cells: flattened,
        equated: equated_record,
        black_boxed,
    }
}

/// Copy every polygon/text of `src` into `dst`, translated by (dx, dy).
fn append_translated(dst: &mut GeometryStore, src: &GeometryStore, dx: i32, dy: i32) {
    let mut pts: Vec<(i32, i32)> = Vec::new();
    for p in 0..src.poly_count() {
        let s = src.poly_vert_start[p] as usize;
        let n = src.poly_vert_len[p] as usize;
        pts.clear();
        pts.extend((0..n).map(|i| (src.verts_x[s + i] + dx, src.verts_y[s + i] + dy)));
        dst.add_polygon(src.poly_layer[p], &pts);
    }
    for i in 0..src.text_count() {
        dst.add_text(
            src.text_layer[i],
            src.text_datatype[i],
            src.text_x[i] + dx,
            src.text_y[i] + dy,
            src.text_string[i].clone(),
        );
    }
}

/// Topological sort of cells — leaves first, parents last.
/// Errors with the offending cell name on a circular reference: a cycle would
/// otherwise silently produce a wrong order and a bogus compare.
fn topo_sort(layout: &HashMap<String, HierCell>) -> Result<Vec<String>, String> {
    #[derive(Clone, Copy, PartialEq)]
    enum Mark {
        Gray,
        Black,
    }
    let mut mark: HashMap<String, Mark> = HashMap::new();
    let mut order: Vec<String> = Vec::new();

    fn visit(
        name: &str,
        layout: &HashMap<String, HierCell>,
        mark: &mut HashMap<String, Mark>,
        order: &mut Vec<String>,
    ) -> Result<(), String> {
        match mark.get(name) {
            Some(Mark::Black) => return Ok(()),
            Some(Mark::Gray) => return Err(name.to_string()),
            None => {}
        }
        mark.insert(name.to_string(), Mark::Gray);
        if let Some(cell) = layout.get(name) {
            for inst in &cell.instances {
                visit(&inst.cell_name, layout, mark, order)?;
            }
        }
        mark.insert(name.to_string(), Mark::Black);
        order.push(name.to_string());
        Ok(())
    }

    for name in layout.keys() {
        visit(name, layout, &mut mark, &mut order)?;
    }
    Ok(order)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{ConnectivityConfig, DeviceConfig, LayerDef, LayerTable, MosRule};
    use crate::schema::PropertyTolerance;

    fn test_deck() -> Deck {
        let names = [
            "nwell", "diff", "poly", "licon", "li", "mcon", "met1", "via1", "met2", "nsdm", "psdm",
        ];
        let mut defs: HashMap<String, LayerDef> = HashMap::new();
        for (i, n) in names.iter().enumerate() {
            defs.insert(
                n.to_string(),
                LayerDef {
                    layer: i as i32 + 1,
                    datatype: 0,
                },
            );
        }
        let lt = LayerTable::from_defs(&defs);
        let conductors = ["diff", "poly", "li", "met1", "met2"]
            .iter()
            .filter_map(|n| lt.id(n))
            .collect();
        let vias = vec![
            (
                lt.id("licon").unwrap(),
                vec![
                    lt.id("diff").unwrap(),
                    lt.id("poly").unwrap(),
                    lt.id("li").unwrap(),
                ],
            ),
            (
                lt.id("mcon").unwrap(),
                vec![lt.id("li").unwrap(), lt.id("met1").unwrap()],
            ),
            (
                lt.id("via1").unwrap(),
                vec![lt.id("met1").unwrap(), lt.id("met2").unwrap()],
            ),
        ];
        let mos_rules = vec![MosRule {
            name: "nmos".into(),
            gate_layer: lt.id("poly").unwrap(),
            channel_layer: lt.id("diff").unwrap(),
            type_implant: lt.id("nsdm").unwrap(),
            device_type: "nmos".into(),
            flavor_markers: Vec::new(),
            well_layer: None,
            device_class: None,
        }];
        Deck {
            layers: lt,
            drc_rules: Vec::new(),
            pex: HashMap::new(),
            dbu_nm: 1.0,
            lvs_cut_required: false,
            strict: false,
            connectivity: ConnectivityConfig { conductors, vias },
            devices: DeviceConfig {
                mos_rules,
                bjt_rules: Vec::new(),
                resistor_rules: Vec::new(),
                diode_rules: Vec::new(),
                cap_rules: Vec::new(),
            },
            w_tolerance: PropertyTolerance::default(),
            l_tolerance: PropertyTolerance::default(),
            fail_on_floating: false,
            erc: crate::params::ErcParams::default(),
            intra_layer_touch: false,
            global_nets: Vec::new(),
            device_catalog: HashMap::new(),
            pex_method: Default::default(),
        }
    }

    fn inv_ref() -> HashMap<String, RefCellNetlist> {
        let mut ref_cells = HashMap::new();
        ref_cells.insert(
            "inv".to_string(),
            RefCellNetlist {
                netlist: RefNetlist {
                    devices: vec![RefDevice {
                        kind: DeviceKind::Nmos,
                        gate: "A".into(),
                        source: "S".into(),
                        drain: "D".into(),
                        w: 0,
                        l: 0,
                        flavor: DeviceFlavor::Standard,
                        ..Default::default()
                    }],
                    net_seeds: HashMap::new(),
                    ref_two_terminal: Vec::new(),
                    ref_bjt: Vec::new(),
                },
                subcircuit_instances: Vec::new(),
            },
        );
        ref_cells
    }

    fn inv_geometry(deck: &Deck) -> GeometryStore {
        let lt = &deck.layers;
        let diff = lt.id("diff").unwrap();
        let poly = lt.id("poly").unwrap();
        let li = lt.id("li").unwrap();
        let nsdm = lt.id("nsdm").unwrap();

        let mut st = GeometryStore::new();
        st.add_rect(diff, 0, 0, 500, 200);
        st.add_rect(poly, 200, -50, 60, 300);
        st.add_rect(li, 50, 50, 100, 100);
        st.add_rect(li, 350, 50, 100, 100);
        st.add_rect(nsdm, -100, -100, 700, 400);
        st
    }

    #[test]
    fn hierarchical_single_cell() {
        let deck = test_deck();
        let st = inv_geometry(&deck);

        let mut layout = HashMap::new();
        layout.insert(
            "inv".to_string(),
            HierCell {
                name: "inv".into(),
                geometry: st,
                instances: Vec::new(),
                ports: Vec::new(),
            },
        );

        let reference = RefHierarchy {
            cells: inv_ref(),
            top_cell: "inv".into(),
        };
        let result = compare_hierarchical(&layout, &reference, &deck, &[]);
        assert!(result.matched, "single-cell hierarchical should match");
        assert_eq!(result.per_cell.len(), 1);
        assert!(result.flattened_cells.is_empty());
        assert!(result.equated.is_empty());
        assert!(result.black_boxed.is_empty());
    }

    #[test]
    fn black_box_cell_via_cache_skips_extraction() {
        // A cell with no geometry would fail extraction, but if it is already in
        // the cache it should be treated as matched without extraction.
        let deck = test_deck();
        let mut layout = HashMap::new();
        layout.insert(
            "mystery".to_string(),
            HierCell {
                name: "mystery".into(),
                geometry: GeometryStore::new(),
                instances: Vec::new(),
                ports: Vec::new(),
            },
        );

        let mut ref_cells = HashMap::new();
        ref_cells.insert(
            "mystery".to_string(),
            RefCellNetlist {
                netlist: RefNetlist {
                    devices: vec![RefDevice {
                        kind: DeviceKind::Nmos,
                        gate: "G".into(),
                        source: "S".into(),
                        drain: "D".into(),
                        ..Default::default()
                    }],
                    net_seeds: HashMap::new(),
                    ref_two_terminal: Vec::new(),
                    ref_bjt: Vec::new(),
                },
                subcircuit_instances: Vec::new(),
            },
        );

        let reference = RefHierarchy {
            cells: ref_cells,
            top_cell: "mystery".into(),
        };

        let mut cache = HierLvsCacheSimple::default();
        cache.insert(
            "mystery".to_string(),
            SubcircuitDevice {
                cell_name: "mystery".into(),
                pins: vec![("G".into(), 0), ("S".into(), 1), ("D".into(), 2)],
            },
        );

        let result = compare_hierarchical_cached(&layout, &reference, &deck, &[], &mut cache);
        assert!(
            result.matched,
            "cached cell should match: {}",
            result.per_cell[0].1.reason
        );
        assert_eq!(result.per_cell.len(), 1);
        assert_eq!(result.per_cell[0].1.reason, "cached match");
    }

    #[test]
    fn matched_cell_populates_cache() {
        let deck = test_deck();
        let st = inv_geometry(&deck);

        let mut layout = HashMap::new();
        layout.insert(
            "inv".to_string(),
            HierCell {
                name: "inv".into(),
                geometry: st,
                instances: Vec::new(),
                ports: Vec::new(),
            },
        );

        let reference = RefHierarchy {
            cells: inv_ref(),
            top_cell: "inv".into(),
        };
        let mut cache = HierLvsCacheSimple::default();
        let result = compare_hierarchical_cached(&layout, &reference, &deck, &[], &mut cache);
        assert!(result.matched);
        assert!(cache.get("inv").is_some(), "matched cell should be cached");
        let device = cache.get("inv").unwrap();
        assert_eq!(device.cell_name, "inv");
    }

    #[test]
    fn equated_cells_use_alternate_name() {
        let deck = test_deck();
        let st = inv_geometry(&deck);

        let mut layout = HashMap::new();
        // Layout cell is called "my_inv" but reference is "inv"
        layout.insert(
            "my_inv".to_string(),
            HierCell {
                name: "my_inv".into(),
                geometry: st,
                instances: Vec::new(),
                ports: Vec::new(),
            },
        );

        let reference = RefHierarchy {
            cells: inv_ref(),
            top_cell: "inv".into(),
        };

        // Without equating, should flatten (no reference for "my_inv")
        let result_no_equate = compare_hierarchical(&layout, &reference, &deck, &[]);
        assert!(
            result_no_equate
                .flattened_cells
                .contains(&"my_inv".to_string()),
            "without equate, cell should be flattened"
        );

        // With equating, should match
        let result = compare_hierarchical(
            &layout,
            &reference,
            &deck,
            &[("my_inv".into(), "inv".into())],
        );
        assert!(result.matched, "equated cell should match");
        assert_eq!(result.equated.len(), 1);
        assert_eq!(result.equated[0], ("my_inv".to_string(), "inv".to_string()));
    }

    #[test]
    fn port_extraction_from_text() {
        let mut geo = GeometryStore::new();
        let layer: LayerId = 7;
        geo.add_rect(layer, 0, 0, 100, 100);
        geo.add_text(layer as i32, 0, 50, 50, "VDD".into());

        let mut net_names = HashMap::new();
        net_names.insert(0u32, "net0".into());
        let net_of_poly = vec![0u32];

        let ports = extract_ports_from_text(&geo, &net_names, &net_of_poly);
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].name, "VDD");
        assert_eq!(ports[0].layer, layer);
    }
}
