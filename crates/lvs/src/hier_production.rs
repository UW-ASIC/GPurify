//! Abstract hierarchy adapter and deterministic hierarchical LVS orchestration.

use super::binding::{BoundReferenceCell, BoundReferenceHierarchy};
use super::production::*;
use rayon::prelude::*;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HierTransform {
    pub xx: i8,
    pub xy: i8,
    pub yx: i8,
    pub yy: i8,
    pub dx: i64,
    pub dy: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{bind_reference_hierarchy, parse_netlist, BlackBoxSpec, ReferenceBindingOptions};

    fn reference(two: bool) -> BoundReferenceHierarchy {
        let second = if two { "X1 x y leaf\n" } else { "" };
        let source = format!(".model dio diode\n.subckt leaf a b\nD0 a b dio\n.ends leaf\n.subckt top x y\nX0 x y leaf\n{second}.ends top\n");
        bind_reference_hierarchy(
            &parse_netlist("hier.sp", &source).unwrap(),
            &ReferenceBindingOptions::new("top"),
        )
        .unwrap()
    }
    fn ref_cell<'a>(r: &'a BoundReferenceHierarchy, source: &str) -> &'a BoundReferenceCell {
        r.cells.values().find(|c| c.source_cell == source).unwrap()
    }
    fn layout(r: &BoundReferenceHierarchy, array: u32) -> HierLayout {
        let leaf = ref_cell(r, "leaf");
        let top = ref_cell(r, "top");
        HierLayout {
            top_cell: "top".into(),
            cells: BTreeMap::from([
                (
                    "leaf".into(),
                    HierLayoutCell {
                        name: "leaf".into(),
                        ports: leaf.ports.clone(),
                        netlist: leaf.netlist.clone(),
                        instances: Vec::new(),
                    },
                ),
                (
                    "top".into(),
                    HierLayoutCell {
                        name: "top".into(),
                        ports: top.ports.clone(),
                        netlist: top.netlist.clone(),
                        instances: vec![HierLayoutInstance {
                            stable_id: "X0".into(),
                            target_cell: "leaf".into(),
                            port_bindings: vec![("a".into(), "x".into()), ("b".into(), "y".into())],
                            transform: HierTransform {
                                xx: -1,
                                yy: 1,
                                ..Default::default()
                            },
                            array: HierArray {
                                columns: array,
                                rows: 1,
                                column_step: (100, 0),
                                row_step: (0, 0),
                            },
                            black_box: false,
                        }],
                    },
                ),
            ]),
        }
    }

    #[test]
    fn hierarchy_and_flattened_results_agree_and_port_swap_witnesses() {
        let reference = reference(false);
        let mut layout = layout(&reference, 1);
        let mut cache = HierLvsCache::default();
        let clean =
            compare_hierarchical_production(&layout, &reference, &Default::default(), &mut cache);
        assert_eq!(clean.status, ProductionLvsStatus::Match);
        layout.cells.get_mut("top").unwrap().instances[0].port_bindings =
            vec![("a".into(), "y".into()), ("b".into(), "x".into())];
        let bad = compare_hierarchical_production(
            &layout,
            &reference,
            &Default::default(),
            &mut HierLvsCache::default(),
        );
        assert_eq!(bad.status, ProductionLvsStatus::Mismatch);
        assert!(matches!(
            bad.flattened.mismatches.first(),
            Some(ProductionMismatch::Topology { .. })
        ));
    }

    #[test]
    fn array_transform_and_selective_flatten_match_two_reference_instances() {
        let reference = reference(true);
        let layout = layout(&reference, 2);
        let options = HierProductionOptions {
            flatten: HierFlattenPolicy::Selective(BTreeSet::from(["leaf".into()])),
            ..Default::default()
        };
        let result = compare_hierarchical_production(
            &layout,
            &reference,
            &options,
            &mut HierLvsCache::default(),
        );
        assert_eq!(result.status, ProductionLvsStatus::Match);
        assert_eq!(result.flattened_cells, ["leaf"]);
    }

    #[test]
    fn black_box_and_equated_top_remain_explicit() {
        let ast = parse_netlist("bb.sp", ".subckt top x y\nX0 x y macro\n.ends top\n").unwrap();
        let mut binding = ReferenceBindingOptions::new("top");
        binding.black_boxes.insert(
            "macro".into(),
            BlackBoxSpec {
                name: "macro".into(),
                ports: vec!["a".into(), "b".into()],
            },
        );
        let reference = bind_reference_hierarchy(&ast, &binding).unwrap();
        let top = ref_cell(&reference, "top");
        let mut layout = HierLayout {
            top_cell: "layout_top".into(),
            cells: BTreeMap::from([(
                "layout_top".into(),
                HierLayoutCell {
                    name: "layout_top".into(),
                    ports: top.ports.clone(),
                    netlist: top.netlist.clone(),
                    instances: vec![HierLayoutInstance {
                        stable_id: "X0".into(),
                        target_cell: "macro".into(),
                        port_bindings: vec![("a".into(), "x".into()), ("b".into(), "y".into())],
                        transform: Default::default(),
                        array: Default::default(),
                        black_box: true,
                    }],
                },
            )]),
        };
        let options = HierProductionOptions {
            equated_cells: BTreeMap::from([("layout_top".into(), "top".into())]),
            ..Default::default()
        };
        assert_eq!(
            compare_hierarchical_production(
                &layout,
                &reference,
                &options,
                &mut HierLvsCache::default()
            )
            .status,
            ProductionLvsStatus::Match
        );
        let assert_black_box_mismatch =
            |layout: &HierLayout, expected_kind: TopologyConflictKind| {
                let result = compare_hierarchical_production(
                    layout,
                    &reference,
                    &options,
                    &mut HierLvsCache::default(),
                );
                assert_eq!(result.status, ProductionLvsStatus::Mismatch);
                let Some(ProductionMismatch::Topology { witness, .. }) =
                    result.flattened.mismatches.first()
                else {
                    panic!("missing black-box topology witness: {result:#?}");
                };
                assert_eq!(witness.kind, expected_kind);
                assert!(!witness.layout_devices.is_empty());
                assert!(!witness.hierarchy_paths.is_empty());
                assert!(!witness.path.is_empty());
            };

        layout.cells.get_mut("layout_top").unwrap().instances[0].port_bindings =
            vec![("a".into(), "y".into()), ("b".into(), "x".into())];
        assert_black_box_mismatch(&layout, TopologyConflictKind::IllegalPinSwap);
        layout.cells.get_mut("layout_top").unwrap().instances[0].port_bindings =
            vec![("a".into(), "x".into()), ("b".into(), "x".into())];
        assert_black_box_mismatch(&layout, TopologyConflictKind::Short);
        let instance = &mut layout.cells.get_mut("layout_top").unwrap().instances[0];
        instance.target_cell = "undefined_macro".into();
        instance.port_bindings = vec![("a".into(), "x".into()), ("b".into(), "y".into())];
        assert_black_box_mismatch(&layout, TopologyConflictKind::PartitionConflict);

        let instance = &mut layout.cells.get_mut("layout_top").unwrap().instances[0];
        instance.target_cell = "macro".into();
        instance.port_bindings = vec![
            ("a".into(), "undefined_net".into()),
            ("b".into(), "y".into()),
        ];
        let undefined_parent = compare_hierarchical_production(
            &layout,
            &reference,
            &options,
            &mut HierLvsCache::default(),
        );
        assert_eq!(undefined_parent.status, ProductionLvsStatus::Error);
        assert!(matches!(
            undefined_parent.flattened.mismatches.first(),
            Some(ProductionMismatch::Input { explanation, .. })
                if explanation.contains("undefined_net")
        ));

        let instance = &mut layout.cells.get_mut("layout_top").unwrap().instances[0];
        instance.port_bindings = vec![("a".into(), "x".into()), ("b".into(), "y".into())];
        let missing_cell_binding = compare_hierarchical_production(
            &layout,
            &reference,
            &HierProductionOptions::default(),
            &mut HierLvsCache::default(),
        );
        assert_eq!(missing_cell_binding.status, ProductionLvsStatus::Mismatch);
        assert!(matches!(
            missing_cell_binding.flattened.mismatches.first(),
            Some(ProductionMismatch::Topology { witness, .. })
                if !witness.hierarchy_paths.is_empty()
        ));
    }

    #[test]
    fn cycles_capacity_and_cache_invalidation_fail_closed() {
        let reference = reference(false);
        let mut layout = layout(&reference, 1);
        let mut cache = HierLvsCache::default();
        let first =
            compare_hierarchical_production(&layout, &reference, &Default::default(), &mut cache);
        assert!(first.cache_misses >= 2);
        let second =
            compare_hierarchical_production(&layout, &reference, &Default::default(), &mut cache);
        assert_eq!(second.cache_hits, second.per_cell.len());
        layout
            .cells
            .get_mut("leaf")
            .unwrap()
            .netlist
            .two_terminal_devices[0]
            .properties
            .insert(
                "AREA".into(),
                TypedProperty::exact(2.0, PropertyUnit::Dimensionless),
            );
        let changed =
            compare_hierarchical_production(&layout, &reference, &Default::default(), &mut cache);
        assert!(changed.cache_misses >= 1 && changed.invalidated_entries >= 1);
        assert_eq!(changed.status, ProductionLvsStatus::Mismatch);
        let too_small = HierProductionOptions {
            max_expanded_instances: 0,
            ..Default::default()
        };
        assert_eq!(
            compare_hierarchical_production(
                &layout,
                &reference,
                &too_small,
                &mut HierLvsCache::default()
            )
            .status,
            ProductionLvsStatus::Error
        );
        layout
            .cells
            .get_mut("leaf")
            .unwrap()
            .instances
            .push(HierLayoutInstance {
                stable_id: "self".into(),
                target_cell: "leaf".into(),
                port_bindings: vec![("a".into(), "a".into()), ("b".into(), "b".into())],
                transform: Default::default(),
                array: Default::default(),
                black_box: false,
            });
        let cycle = compare_hierarchical_production(
            &layout,
            &reference,
            &Default::default(),
            &mut HierLvsCache::default(),
        );
        assert_eq!(cycle.status, ProductionLvsStatus::Error);
        assert!(cycle.reason.contains("cycle"));
    }
}

impl Default for HierTransform {
    fn default() -> Self {
        Self {
            xx: 1,
            xy: 0,
            yx: 0,
            yy: 1,
            dx: 0,
            dy: 0,
        }
    }
}

impl HierTransform {
    fn valid(self) -> bool {
        let det = i16::from(self.xx) * i16::from(self.yy) - i16::from(self.xy) * i16::from(self.yx);
        det.abs() == 1
            && [self.xx, self.xy, self.yx, self.yy]
                .iter()
                .all(|v| (-1..=1).contains(v))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HierArray {
    pub columns: u32,
    pub rows: u32,
    pub column_step: (i64, i64),
    pub row_step: (i64, i64),
}

impl Default for HierArray {
    fn default() -> Self {
        Self {
            columns: 1,
            rows: 1,
            column_step: (0, 0),
            row_step: (0, 0),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct HierLayoutInstance {
    pub stable_id: String,
    pub target_cell: String,
    pub port_bindings: Vec<(String, String)>,
    pub transform: HierTransform,
    pub array: HierArray,
    pub black_box: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HierLayoutCell {
    pub name: String,
    pub ports: Vec<String>,
    pub netlist: DetailedNetlist<String>,
    pub instances: Vec<HierLayoutInstance>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HierLayout {
    pub top_cell: String,
    pub cells: BTreeMap<String, HierLayoutCell>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HierFlattenPolicy {
    Preserve,
    All,
    Selective(BTreeSet<String>),
}

#[derive(Debug, Clone)]
pub struct HierProductionOptions {
    pub compare: ProductionCompareOptions,
    pub equated_cells: BTreeMap<String, String>,
    pub flatten: HierFlattenPolicy,
    pub max_expanded_instances: usize,
}

impl Default for HierProductionOptions {
    fn default() -> Self {
        Self {
            compare: Default::default(),
            equated_cells: BTreeMap::new(),
            flatten: HierFlattenPolicy::Preserve,
            max_expanded_instances: 1_000_000,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct HierLvsCache {
    entries: BTreeMap<String, ProductionLvsResult>,
}

impl HierLvsCache {
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct HierCellComparison {
    pub layout_cell: String,
    pub reference_cell: String,
    pub result: ProductionLvsResult,
    pub cache_hit: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HierProductionResult {
    pub status: ProductionLvsStatus,
    pub reason: String,
    pub per_cell: Vec<HierCellComparison>,
    pub flattened: ProductionLvsResult,
    pub flattened_cells: Vec<String>,
    pub cache_hits: usize,
    pub cache_misses: usize,
    pub invalidated_entries: usize,
}

fn hash(text: &str) -> String {
    let mut h = 0xcbf29ce484222325u64;
    for b in text.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}

fn hierarchy_error(reason: impl Into<String>) -> ProductionLvsResult {
    let reason = reason.into();
    let mismatch_fingerprint = format!("hier:{}", hash(&format!("input|{reason}")));
    ProductionLvsResult {
        status: ProductionLvsStatus::Error,
        reason: reason.clone(),
        device_mappings: Vec::new(),
        net_mappings: Vec::new(),
        mismatches: vec![ProductionMismatch::Input {
            side: "hierarchy".into(),
            object: "layout/reference binding".into(),
            explanation: reason.clone(),
            fingerprint: mismatch_fingerprint,
        }],
        explored_states: 0,
        fingerprint: format!("hier:{}", hash(&reason)),
    }
}

fn validate_layout(layout: &HierLayout, limit: usize) -> Result<usize, String> {
    if !layout.cells.contains_key(&layout.top_cell) {
        return Err(format!("top cell '{}' is undefined", layout.top_cell));
    }
    fn visit(
        name: &str,
        layout: &HierLayout,
        active: &mut Vec<String>,
        count: &mut usize,
        limit: usize,
    ) -> Result<(), String> {
        if active.iter().any(|n| n == name) {
            let mut c = active.clone();
            c.push(name.into());
            return Err(format!("hierarchy cycle: {}", c.join(" -> ")));
        }
        let cell = layout
            .cells
            .get(name)
            .ok_or_else(|| format!("undefined layout cell '{name}'"))?;
        active.push(name.into());
        for instance in &cell.instances {
            if !instance.transform.valid() {
                return Err(format!(
                    "instance '{}': unsupported non-Manhattan transform",
                    instance.stable_id
                ));
            }
            let copies = usize::try_from(instance.array.columns)
                .ok()
                .and_then(|c| {
                    usize::try_from(instance.array.rows)
                        .ok()
                        .and_then(|r| c.checked_mul(r))
                })
                .ok_or_else(|| format!("instance '{}': array size overflow", instance.stable_id))?;
            if copies == 0 {
                return Err(format!(
                    "instance '{}': array dimensions must be positive",
                    instance.stable_id
                ));
            }
            *count = count
                .checked_add(copies)
                .ok_or("expanded instance count overflow")?;
            if *count > limit {
                return Err(format!(
                    "expanded instance capacity {} exceeds limit {limit}",
                    *count
                ));
            }
            let bindings: BTreeSet<&str> = instance
                .port_bindings
                .iter()
                .map(|(port, _)| port.as_str())
                .collect();
            if bindings.len() != instance.port_bindings.len() {
                return Err(format!(
                    "instance '{}': duplicate child port bindings",
                    instance.stable_id
                ));
            }
            for (_, parent_net) in &instance.port_bindings {
                if !cell.netlist.nets.contains_key(parent_net) {
                    return Err(format!(
                        "instance '{}': parent net '{}' is undefined",
                        instance.stable_id, parent_net
                    ));
                }
            }
            if instance.black_box {
                if instance.port_bindings.is_empty() {
                    return Err(format!(
                        "black-box instance '{}': complete port binding map is empty",
                        instance.stable_id
                    ));
                }
            } else {
                let child = layout.cells.get(&instance.target_cell).ok_or_else(|| {
                    format!(
                        "instance '{}': undefined target '{}'",
                        instance.stable_id, instance.target_cell
                    )
                })?;
                if bindings.len() != instance.port_bindings.len()
                    || bindings != child.ports.iter().map(String::as_str).collect()
                {
                    return Err(format!(
                        "instance '{}': port binding set does not equal child ports",
                        instance.stable_id
                    ));
                }
                visit(&instance.target_cell, layout, active, count, limit)?;
            }
        }
        active.pop();
        Ok(())
    }
    let mut count = 0;
    visit(&layout.top_cell, layout, &mut Vec::new(), &mut count, limit)?;
    Ok(count)
}

fn map_connection(
    connection: &TerminalConnection<String>,
    ids: &BTreeMap<String, u32>,
) -> TerminalConnection<u32> {
    match connection {
        TerminalConnection::Connected(net) => TerminalConnection::Connected(ids[net]),
        TerminalConnection::Unresolved(error) => TerminalConnection::Unresolved(error.clone()),
    }
}

fn to_extracted(source: &DetailedNetlist<String>) -> DetailedExtractedNetlist {
    let ids: BTreeMap<String, u32> = source
        .nets
        .keys()
        .enumerate()
        .map(|(i, n)| (n.clone(), i as u32))
        .collect();
    let mut out = DetailedExtractedNetlist::empty(&source.cell_name);
    for (name, net) in &source.nets {
        let id = ids[name];
        out.nets.insert(
            id,
            NetIdentity {
                id,
                labels: net.labels.clone(),
                ports: net.ports.clone(),
                globals: net.globals.clone(),
                hierarchy_path: net.hierarchy_path.clone(),
            },
        );
    }
    out.mos_devices = source
        .mos_devices
        .iter()
        .map(|d| MosDeviceRecord {
            identity: d.identity.clone(),
            kind: d.kind.clone(),
            drain: ids[&d.drain],
            gate: ids[&d.gate],
            source: ids[&d.source],
            body: map_connection(&d.body, &ids),
            well: d.well.as_ref().map(|n| map_connection(n, &ids)),
            substrate: d.substrate.as_ref().map(|n| map_connection(n, &ids)),
            properties: d.properties.clone(),
        })
        .collect();
    out.two_terminal_devices = source
        .two_terminal_devices
        .iter()
        .map(|d| TwoTerminalRecord {
            identity: d.identity.clone(),
            kind: d.kind.clone(),
            terminal_a: ids[&d.terminal_a],
            terminal_b: ids[&d.terminal_b],
            properties: d.properties.clone(),
        })
        .collect();
    out.bjt_devices = source
        .bjt_devices
        .iter()
        .map(|d| BjtDeviceRecord {
            identity: d.identity.clone(),
            kind: d.kind.clone(),
            collector: ids[&d.collector],
            base: ids[&d.base],
            emitter: ids[&d.emitter],
            substrate: d.substrate.as_ref().map(|n| map_connection(n, &ids)),
            properties: d.properties.clone(),
        })
        .collect();
    out.soft_connections = source
        .soft_connections
        .iter()
        .map(|s| SoftConnection {
            from: ids[&s.from],
            to: ids[&s.to],
            policy_id: s.policy_id.clone(),
            hierarchy_path: s.hierarchy_path.clone(),
        })
        .collect();
    out.open_candidates = source
        .open_candidates
        .iter()
        .map(|o| OpenCandidate {
            net_a: ids[&o.net_a],
            net_b: ids[&o.net_b],
            reason: o.reason.clone(),
            hierarchy_path: o.hierarchy_path.clone(),
        })
        .collect();
    out.seed_aliases = source.seed_aliases.clone();
    out
}

fn net_token(
    cell: &DetailedNetlist<String>,
    local: &str,
    path: &str,
    ports: &BTreeMap<String, String>,
) -> String {
    let identity = &cell.nets[local];
    if let Some(global) = identity.globals.iter().next() {
        format!("GLOBAL:{}", global.to_ascii_lowercase())
    } else if let Some(bound) = ports.get(local) {
        bound.clone()
    } else {
        format!("{path}/{local}")
    }
}

fn append_flat(
    dst: &mut DetailedNetlist<String>,
    src: &DetailedNetlist<String>,
    path: &str,
    ports: &BTreeMap<String, String>,
) {
    let map: BTreeMap<String, String> = src
        .nets
        .keys()
        .map(|n| (n.clone(), net_token(src, n, path, ports)))
        .collect();
    for (old, new) in &map {
        let mut identity = src.nets[old].clone();
        identity.id = new.clone();
        identity.hierarchy_path = HierarchyPath(vec![path.into()]);
        dst.nets.entry(new.clone()).or_insert(identity);
    }
    let id = |identity: &DeviceIdentity| {
        let mut x = identity.clone();
        x.stable_id = format!("{path}/{}", x.stable_id);
        x.hierarchy_path = HierarchyPath(vec![path.into()]);
        x
    };
    dst.mos_devices
        .extend(src.mos_devices.iter().map(|d| MosDeviceRecord {
            identity: id(&d.identity),
            kind: d.kind.clone(),
            drain: map[&d.drain].clone(),
            gate: map[&d.gate].clone(),
            source: map[&d.source].clone(),
            body: match &d.body {
                TerminalConnection::Connected(n) => TerminalConnection::Connected(map[n].clone()),
                TerminalConnection::Unresolved(e) => TerminalConnection::Unresolved(e.clone()),
            },
            well: d.well.as_ref().map(|c| match c {
                TerminalConnection::Connected(n) => TerminalConnection::Connected(map[n].clone()),
                TerminalConnection::Unresolved(e) => TerminalConnection::Unresolved(e.clone()),
            }),
            substrate: d.substrate.as_ref().map(|c| match c {
                TerminalConnection::Connected(n) => TerminalConnection::Connected(map[n].clone()),
                TerminalConnection::Unresolved(e) => TerminalConnection::Unresolved(e.clone()),
            }),
            properties: d.properties.clone(),
        }));
    dst.two_terminal_devices
        .extend(src.two_terminal_devices.iter().map(|d| TwoTerminalRecord {
            identity: id(&d.identity),
            kind: d.kind.clone(),
            terminal_a: map[&d.terminal_a].clone(),
            terminal_b: map[&d.terminal_b].clone(),
            properties: d.properties.clone(),
        }));
    dst.bjt_devices
        .extend(src.bjt_devices.iter().map(|d| BjtDeviceRecord {
            identity: id(&d.identity),
            kind: d.kind.clone(),
            collector: map[&d.collector].clone(),
            base: map[&d.base].clone(),
            emitter: map[&d.emitter].clone(),
            substrate: d.substrate.as_ref().map(|c| match c {
                TerminalConnection::Connected(n) => TerminalConnection::Connected(map[n].clone()),
                TerminalConnection::Unresolved(e) => TerminalConnection::Unresolved(e.clone()),
            }),
            properties: d.properties.clone(),
        }));
}

pub(super) fn flatten_layout(layout: &HierLayout) -> Result<DetailedNetlist<String>, String> {
    fn recurse(
        layout: &HierLayout,
        name: &str,
        path: &str,
        ports: BTreeMap<String, String>,
        out: &mut DetailedNetlist<String>,
    ) -> Result<(), String> {
        let cell = &layout.cells[name];
        append_flat(out, &cell.netlist, path, &ports);
        for instance in &cell.instances {
            if instance.black_box {
                continue;
            }
            for column in 0..instance.array.columns {
                for row in 0..instance.array.rows {
                    let child_path = format!("{path}/{}[{column},{row}]", instance.stable_id);
                    let child_ports = instance
                        .port_bindings
                        .iter()
                        .map(|(child, parent)| {
                            (
                                child.clone(),
                                net_token(&cell.netlist, parent, path, &ports),
                            )
                        })
                        .collect();
                    recurse(layout, &instance.target_cell, &child_path, child_ports, out)?;
                }
            }
        }
        Ok(())
    }
    let mut out = DetailedNetlist::empty(&layout.top_cell);
    recurse(
        layout,
        &layout.top_cell,
        &layout.top_cell,
        BTreeMap::new(),
        &mut out,
    )?;
    Ok(out)
}

fn flatten_reference(reference: &BoundReferenceHierarchy) -> Result<DetailedRefNetlist, String> {
    fn recurse(
        reference: &BoundReferenceHierarchy,
        name: &str,
        path: &str,
        ports: BTreeMap<String, String>,
        out: &mut DetailedRefNetlist,
    ) -> Result<(), String> {
        let cell = reference
            .cells
            .get(name)
            .ok_or_else(|| format!("undefined reference specialization '{name}'"))?;
        append_flat(out, &cell.netlist, path, &ports);
        for instance in &cell.instances {
            if !instance.black_box {
                let child_ports = instance
                    .port_bindings
                    .iter()
                    .map(|(child, parent)| {
                        (
                            child.clone(),
                            net_token(&cell.netlist, parent, path, &ports),
                        )
                    })
                    .collect();
                recurse(
                    reference,
                    &instance.target_cell,
                    &format!("{path}/{}", instance.stable_id),
                    child_ports,
                    out,
                )?;
            }
        }
        Ok(())
    }
    let mut out = DetailedRefNetlist::empty(&reference.top_cell);
    recurse(
        reference,
        &reference.top_cell,
        &reference.top_cell,
        BTreeMap::new(),
        &mut out,
    )?;
    Ok(out)
}

fn reference_for_layout<'a>(
    cell: &str,
    reference: &'a BoundReferenceHierarchy,
    options: &HierProductionOptions,
) -> Option<&'a BoundReferenceCell> {
    let target = options
        .equated_cells
        .iter()
        .find_map(|(a, b)| a.eq_ignore_ascii_case(cell).then_some(b.as_str()))
        .unwrap_or(cell);
    reference
        .cells
        .values()
        .filter(|c| c.source_cell.eq_ignore_ascii_case(target))
        .min_by_key(|c| &c.specialization)
}

type BlackBoxSignature = (String, Vec<(String, String)>);

#[derive(Clone)]
struct BlackBoxEvidence {
    signature: BlackBoxSignature,
    object: String,
    hierarchy_path: HierarchyPath,
}

fn canonical_black_box_signature(target: &str, bindings: &[(String, String)]) -> BlackBoxSignature {
    let mut bindings = bindings
        .iter()
        .map(|(port, net)| (port.to_ascii_lowercase(), net.to_ascii_lowercase()))
        .collect::<Vec<_>>();
    bindings.sort();
    (target.to_ascii_lowercase(), bindings)
}

fn compare_black_boxes(
    layout: &HierLayout,
    reference: &BoundReferenceHierarchy,
    options: &HierProductionOptions,
) -> Option<ProductionMismatch> {
    for (cell_name, cell) in &layout.cells {
        let reference_cell = reference_for_layout(cell_name, reference, options);
        let mut layout_evidence = Vec::new();
        for instance in cell.instances.iter().filter(|instance| instance.black_box) {
            for column in 0..instance.array.columns {
                for row in 0..instance.array.rows {
                    layout_evidence.push(BlackBoxEvidence {
                        signature: canonical_black_box_signature(
                            &instance.target_cell,
                            &instance.port_bindings,
                        ),
                        object: format!(
                            "blackbox:{cell_name}/{}[{column},{row}]",
                            instance.stable_id
                        ),
                        hierarchy_path: HierarchyPath(vec![
                            cell_name.clone(),
                            format!("{}[{column},{row}]", instance.stable_id),
                        ]),
                    });
                }
            }
        }
        let reference_evidence = reference_cell
            .into_iter()
            .flat_map(|reference_cell| reference_cell.instances.iter())
            .filter(|instance| instance.black_box)
            .map(|instance| BlackBoxEvidence {
                signature: canonical_black_box_signature(
                    &instance.target_cell,
                    &instance.port_bindings,
                ),
                object: format!("blackbox:reference/{}", instance.stable_id),
                hierarchy_path: instance.hierarchy_path.clone(),
            })
            .collect::<Vec<_>>();
        let mut layout_by_signature = BTreeMap::<BlackBoxSignature, Vec<BlackBoxEvidence>>::new();
        let mut reference_by_signature =
            BTreeMap::<BlackBoxSignature, Vec<BlackBoxEvidence>>::new();
        for evidence in layout_evidence {
            layout_by_signature
                .entry(evidence.signature.clone())
                .or_default()
                .push(evidence);
        }
        for evidence in reference_evidence {
            reference_by_signature
                .entry(evidence.signature.clone())
                .or_default()
                .push(evidence);
        }
        let signatures = layout_by_signature
            .keys()
            .chain(reference_by_signature.keys())
            .cloned()
            .collect::<BTreeSet<_>>();
        if signatures.iter().all(|signature| {
            layout_by_signature.get(signature).map_or(0, Vec::len)
                == reference_by_signature.get(signature).map_or(0, Vec::len)
        }) {
            continue;
        }
        let layout_cause = signatures.iter().find_map(|signature| {
            let layout_count = layout_by_signature.get(signature).map_or(0, Vec::len);
            let reference_count = reference_by_signature.get(signature).map_or(0, Vec::len);
            (layout_count > reference_count)
                .then(|| layout_by_signature[signature].first().cloned())
                .flatten()
        });
        let reference_cause = signatures.iter().find_map(|signature| {
            let layout_count = layout_by_signature.get(signature).map_or(0, Vec::len);
            let reference_count = reference_by_signature.get(signature).map_or(0, Vec::len);
            (reference_count > layout_count)
                .then(|| reference_by_signature[signature].first().cloned())
                .flatten()
        });
        let layout_signature = layout_cause.as_ref().map(|cause| &cause.signature);
        let reference_signature = reference_cause.as_ref().map(|cause| &cause.signature);
        let layout_is_shorted = layout_signature.is_some_and(|(_, bindings)| {
            let nets = bindings.iter().map(|(_, net)| net).collect::<BTreeSet<_>>();
            nets.len() < bindings.len()
        });
        let reference_is_shorted = reference_signature.is_some_and(|(_, bindings)| {
            let nets = bindings.iter().map(|(_, net)| net).collect::<BTreeSet<_>>();
            nets.len() < bindings.len()
        });
        let kind = if layout_is_shorted && !reference_is_shorted {
            TopologyConflictKind::Short
        } else if layout_signature
            .zip(reference_signature)
            .is_some_and(|(layout, reference)| layout.0 == reference.0)
        {
            TopologyConflictKind::IllegalPinSwap
        } else {
            TopologyConflictKind::PartitionConflict
        };
        let explanation = format!(
            "black-box target/port map mismatch in layout cell `{cell_name}`: layout {:?}, reference {:?}",
            layout_signature, reference_signature
        );
        let witness = TopologyWitness {
            kind,
            layout_devices: layout_cause
                .as_ref()
                .map(|cause| vec![cause.object.clone()])
                .unwrap_or_default(),
            reference_devices: reference_cause
                .as_ref()
                .map(|cause| vec![cause.object.clone()])
                .unwrap_or_default(),
            layout_nets: Vec::new(),
            reference_nets: reference_signature
                .map(|(_, bindings)| bindings.iter().map(|(_, net)| net.clone()).collect())
                .unwrap_or_default(),
            path: layout_signature
                .into_iter()
                .flat_map(|(_, bindings)| bindings.iter())
                .map(|(port, net)| format!("layout-port:{port}={net}"))
                .chain(
                    reference_signature
                        .into_iter()
                        .flat_map(|(_, bindings)| bindings.iter())
                        .map(|(port, net)| format!("reference-port:{port}={net}")),
                )
                .collect(),
            hierarchy_paths: layout_cause
                .iter()
                .map(|cause| cause.hierarchy_path.clone())
                .chain(
                    reference_cause
                        .iter()
                        .map(|cause| cause.hierarchy_path.clone()),
                )
                .collect(),
            explanation: explanation.clone(),
        };
        let canonical = format!("blackbox|{witness:?}");
        return Some(ProductionMismatch::Topology {
            witness,
            fingerprint: format!("hier:{}", hash(&canonical)),
        });
    }
    None
}

pub fn compare_hierarchical_production(
    layout: &HierLayout,
    reference: &BoundReferenceHierarchy,
    options: &HierProductionOptions,
    cache: &mut HierLvsCache,
) -> HierProductionResult {
    if let Err(error) = validate_layout(layout, options.max_expanded_instances) {
        let flat = hierarchy_error(error.clone());
        return HierProductionResult {
            status: ProductionLvsStatus::Error,
            reason: error,
            per_cell: Vec::new(),
            flattened: flat,
            flattened_cells: Vec::new(),
            cache_hits: 0,
            cache_misses: 0,
            invalidated_entries: 0,
        };
    }
    if let Some(mismatch) = compare_black_boxes(layout, reference, options) {
        let reason = "hierarchical black-box target/port map mismatch".to_string();
        let fingerprint = format!("hier:{}", hash(&format!("{mismatch:?}")));
        return HierProductionResult {
            status: ProductionLvsStatus::Mismatch,
            reason: reason.clone(),
            per_cell: Vec::new(),
            flattened: ProductionLvsResult {
                status: ProductionLvsStatus::Mismatch,
                reason,
                device_mappings: Vec::new(),
                net_mappings: Vec::new(),
                mismatches: vec![mismatch],
                explored_states: 0,
                fingerprint,
            },
            flattened_cells: Vec::new(),
            cache_hits: 0,
            cache_misses: 0,
            invalidated_entries: 0,
        };
    }
    let mut jobs = Vec::new();
    let mut hits = Vec::new();
    let mut valid_prefixes = BTreeSet::new();
    for (name, cell) in &layout.cells {
        let Some(reference_cell) = reference_for_layout(name, reference, options) else {
            continue;
        };
        let prefix = format!("{name}|{}|", reference_cell.specialization);
        valid_prefixes.insert(prefix.clone());
        let key = format!(
            "{prefix}{}",
            hash(&format!("{:?}|{:?}", cell, reference_cell))
        );
        if let Some(result) = cache.entries.get(&key) {
            hits.push(HierCellComparison {
                layout_cell: name.clone(),
                reference_cell: reference_cell.specialization.clone(),
                result: result.clone(),
                cache_hit: true,
            });
        } else {
            jobs.push((
                key,
                name.clone(),
                cell.netlist.clone(),
                reference_cell.specialization.clone(),
                reference_cell.netlist.clone(),
            ));
        }
    }
    let computed: Vec<_> = jobs
        .par_iter()
        .map(
            |(key, name, layout_netlist, reference_name, reference_netlist)| {
                let result = compare_production(
                    &to_extracted(layout_netlist),
                    reference_netlist,
                    &options.compare,
                );
                (
                    key.clone(),
                    HierCellComparison {
                        layout_cell: name.clone(),
                        reference_cell: reference_name.clone(),
                        result,
                        cache_hit: false,
                    },
                )
            },
        )
        .collect();
    let mut invalidated = 0;
    cache.entries.retain(|key, _| {
        let keep = valid_prefixes.iter().any(|prefix| key.starts_with(prefix))
            && (computed.iter().any(|(new, _)| new == key)
                || hits.iter().any(|hit| {
                    key.starts_with(&format!("{}|{}|", hit.layout_cell, hit.reference_cell))
                }));
        if !keep {
            invalidated += 1;
        }
        keep
    });
    for (key, comparison) in &computed {
        cache.entries.insert(key.clone(), comparison.result.clone());
    }
    let mut per_cell = hits;
    per_cell.extend(computed.into_iter().map(|(_, c)| c));
    per_cell.sort_by(|a, b| a.layout_cell.cmp(&b.layout_cell));
    let flat = match (flatten_layout(layout), flatten_reference(reference)) {
        (Ok(l), Ok(r)) => compare_production(&to_extracted(&l), &r, &options.compare),
        (Err(e), _) | (_, Err(e)) => hierarchy_error(e),
    };
    let flattened_cells = match &options.flatten {
        HierFlattenPolicy::Preserve => Vec::new(),
        HierFlattenPolicy::All => layout.cells.keys().cloned().collect(),
        HierFlattenPolicy::Selective(cells) => cells
            .iter()
            .filter(|c| layout.cells.contains_key(*c))
            .cloned()
            .collect(),
    };
    let structural_match = per_cell.iter().all(|c| c.result.status.is_match());
    let status = if structural_match && flat.status.is_match() {
        ProductionLvsStatus::Match
    } else if flat.status == ProductionLvsStatus::Indeterminate {
        ProductionLvsStatus::Indeterminate
    } else if flat.status == ProductionLvsStatus::Error {
        ProductionLvsStatus::Error
    } else {
        ProductionLvsStatus::Mismatch
    };
    HierProductionResult {
        status,
        reason: if status.is_match() {
            "hierarchy-preserving and flattened comparisons agree".into()
        } else {
            "hierarchical LVS mismatch".into()
        },
        cache_hits: per_cell.iter().filter(|c| c.cache_hit).count(),
        cache_misses: per_cell.iter().filter(|c| !c.cache_hit).count(),
        invalidated_entries: invalidated,
        per_cell,
        flattened: flat,
        flattened_cells,
    }
}
