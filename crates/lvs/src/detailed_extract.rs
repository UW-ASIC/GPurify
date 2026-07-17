//! Detailed layout extraction with explicit terminal validity and named-net identity.

use super::extract::extract_raw;
use super::production::*;
use super::types::{DeviceFlavor, DeviceKind, ExtractOpts, TwoTerminalKind};
use crate::backend::Backend;
use crate::geometry::exact::{Point, PointClassification, Polygon};
use crate::geometry::{GeometryStore, LayerId, PolyId};
use crate::params::{Deck, MosRule};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetailedExtractionErrorKind {
    InvalidGeometry,
    UnsupportedGeometry,
    Connectivity,
    AmbiguousText,
    UnattachedText,
    LabelConflict,
    MissingPort,
    DeviceRecognition,
    InvalidProperty,
    InvalidPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailedExtractionError {
    pub kind: DetailedExtractionErrorKind,
    pub object: String,
    pub hierarchy_path: HierarchyPath,
    pub message: String,
}

impl DetailedExtractionError {
    fn new(
        kind: DetailedExtractionErrorKind,
        object: impl Into<String>,
        hierarchy_path: HierarchyPath,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            object: object.into(),
            hierarchy_path,
            message: message.into(),
        }
    }
}

impl fmt::Display for DetailedExtractionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [{}]: {}",
            self.object, self.hierarchy_path, self.message
        )
    }
}

impl std::error::Error for DetailedExtractionError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedSoftConnection {
    pub from_name: String,
    pub to_name: String,
    pub policy_id: String,
}

#[derive(Debug, Clone)]
pub struct DetailedExtractionOptions {
    pub cell_name: String,
    pub extract: ExtractOpts,
    pub ports: BTreeMap<String, PortDirection>,
    pub globals: BTreeSet<String>,
    pub soft_connections: Vec<NamedSoftConnection>,
    pub require_all_text_attached: bool,
    pub allow_multiple_labels_per_net: bool,
    /// Explicit shared-substrate net for MOS rules without a well layer.
    pub default_substrate_net: Option<u32>,
}

impl Default for DetailedExtractionOptions {
    fn default() -> Self {
        Self {
            cell_name: "TOP".into(),
            extract: ExtractOpts::default(),
            ports: BTreeMap::new(),
            globals: BTreeSet::new(),
            soft_connections: Vec::new(),
            require_all_text_attached: true,
            allow_multiple_labels_per_net: false,
            default_substrate_net: None,
        }
    }
}

fn exact_polygon(
    store: &GeometryStore,
    polygon: PolyId,
    path: &HierarchyPath,
) -> Result<Polygon, DetailedExtractionError> {
    let points = store
        .vertices(polygon)
        .map(|(x, y)| Point::new(x, y))
        .collect();
    Polygon::from_outer(points).map_err(|error| {
        DetailedExtractionError::new(
            DetailedExtractionErrorKind::InvalidGeometry,
            format!("polygon {}", polygon.0),
            path.clone(),
            format!("shared exact-geometry validation failed: {error}"),
        )
    })
}

fn text_candidate_layers(deck: &Deck, layer: i32, datatype: i32) -> Vec<LayerId> {
    if let Some(exact) = deck.layers.from_gds(layer, datatype) {
        return vec![exact];
    }
    deck.layers
        .id_to_gds
        .iter()
        .enumerate()
        .filter_map(|(id, &(gds_layer, _))| (gds_layer == layer).then_some(id as LayerId))
        .collect()
}

fn associate_text(
    store: &GeometryStore,
    deck: &Deck,
    exact: &[Polygon],
    net_of_poly: &[u32],
    text_index: usize,
    options: &DetailedExtractionOptions,
    path: &HierarchyPath,
) -> Result<Option<u32>, DetailedExtractionError> {
    let layers = text_candidate_layers(
        deck,
        store.text_layer[text_index],
        store.text_datatype[text_index],
    );
    if layers.is_empty() {
        return Err(DetailedExtractionError::new(
            DetailedExtractionErrorKind::UnattachedText,
            format!("text {text_index}"),
            path.clone(),
            format!(
                "text '{}' uses GDS layer/type ({}, {}) absent from the deck",
                store.text_string[text_index],
                store.text_layer[text_index],
                store.text_datatype[text_index]
            ),
        ));
    }
    let point = Point::new(store.text_x[text_index], store.text_y[text_index]);
    let layer_set: HashSet<LayerId> = layers.into_iter().collect();
    let mut interior_nets = BTreeSet::new();
    let mut boundary_nets = BTreeSet::new();
    for polygon in 0..store.poly_count() {
        if !layer_set.contains(&store.poly_layer[polygon]) {
            continue;
        }
        let net = net_of_poly[polygon];
        if net == u32::MAX {
            continue;
        }
        match exact[polygon].classify_point(point) {
            PointClassification::Inside => {
                interior_nets.insert(net);
            }
            PointClassification::Boundary => {
                boundary_nets.insert(net);
            }
            PointClassification::Outside => {}
        }
    }
    let candidates = if interior_nets.is_empty() {
        boundary_nets
    } else {
        interior_nets
    };
    match candidates.len() {
        0 if options.require_all_text_attached => Err(DetailedExtractionError::new(
            DetailedExtractionErrorKind::UnattachedText,
            format!("text {text_index}"),
            path.clone(),
            format!(
                "text '{}' at ({}, {}) is not attached to conductor geometry",
                store.text_string[text_index], store.text_x[text_index], store.text_y[text_index]
            ),
        )),
        0 => Ok(None),
        1 => Ok(candidates.iter().next().copied()),
        _ => Err(DetailedExtractionError::new(
            DetailedExtractionErrorKind::AmbiguousText,
            format!("text {text_index}"),
            path.clone(),
            format!(
                "text '{}' is geometrically associated with multiple nets {:?}",
                store.text_string[text_index], candidates
            ),
        )),
    }
}

fn mos_kind_name(kind: &DeviceKind) -> &'static str {
    match kind {
        DeviceKind::Nmos => "nmos",
        DeviceKind::Pmos => "pmos",
        DeviceKind::Npn => "npn",
        DeviceKind::Pnp => "pnp",
    }
}

fn match_mos_rule<'a>(
    deck: &'a Deck,
    kind: &DeviceKind,
    flavor: DeviceFlavor,
    class: Option<&str>,
    device_index: usize,
    path: &HierarchyPath,
) -> Result<&'a MosRule, DetailedExtractionError> {
    let candidates: Vec<&MosRule> = deck
        .devices
        .mos_rules
        .iter()
        .filter(|rule| {
            rule.device_type.eq_ignore_ascii_case(mos_kind_name(kind))
                && rule.device_class.as_deref() == class
                && (flavor == DeviceFlavor::Standard
                    || rule.flavor_markers.iter().any(|(_, marker)| {
                        marker.eq_ignore_ascii_case(match flavor {
                            DeviceFlavor::Lvt => "lvt",
                            DeviceFlavor::Hvt => "hvt",
                            DeviceFlavor::Standard => "standard",
                        })
                    }))
        })
        .collect();
    match candidates.as_slice() {
        [rule] => Ok(*rule),
        [] => Err(DetailedExtractionError::new(
            DetailedExtractionErrorKind::DeviceRecognition,
            format!("MOS {device_index}"),
            path.clone(),
            "extracted MOS cannot be associated with a configured recognition rule",
        )),
        _ => Err(DetailedExtractionError::new(
            DetailedExtractionErrorKind::DeviceRecognition,
            format!("MOS {device_index}"),
            path.clone(),
            format!(
                "extracted MOS identity is ambiguous across rules {:?}",
                candidates
                    .iter()
                    .map(|rule| rule.name.as_str())
                    .collect::<Vec<_>>()
            ),
        )),
    }
}

fn property(
    value: f64,
    unit: PropertyUnit,
    object: &str,
    path: &HierarchyPath,
) -> Result<TypedProperty, DetailedExtractionError> {
    if !value.is_finite() {
        return Err(DetailedExtractionError::new(
            DetailedExtractionErrorKind::InvalidProperty,
            object,
            path.clone(),
            "extracted property is non-finite",
        ));
    }
    Ok(TypedProperty::exact(value, unit))
}

fn identity(
    stable_id: String,
    path: &HierarchyPath,
    model: Option<String>,
    device_class: Option<String>,
    flavor: DeviceFlavor,
) -> DeviceIdentity {
    DeviceIdentity {
        stable_id,
        hierarchy_path: path.clone(),
        model,
        device_class,
        flavor,
    }
}

/// Extract a production netlist. The raw core retains individual MOS fingers
/// and the unambiguous `u32::MAX` unresolved-body marker; neither is exposed by
/// the legacy API.
pub fn extract_detailed_netlist(
    store: &GeometryStore,
    deck: &Deck,
    options: &DetailedExtractionOptions,
    backend: Backend,
) -> Result<DetailedExtractedNetlist, DetailedExtractionError> {
    let path = HierarchyPath::root(&options.cell_name);
    if options.cell_name.trim().is_empty() {
        return Err(DetailedExtractionError::new(
            DetailedExtractionErrorKind::InvalidPolicy,
            "cell",
            path,
            "cell_name must not be empty",
        ));
    }

    let mut exact = Vec::with_capacity(store.poly_count());
    for polygon in 0..store.poly_count() {
        exact.push(exact_polygon(store, PolyId(polygon as u32), &path)?);
    }

    let raw = extract_raw(store, deck, &options.extract, backend, false)
        .map(|r| r.netlist)
        .map_err(|message| {
            let kind = if message.contains("ambiguously matches MOS")
                || message.contains("no matching MOS")
            {
                DetailedExtractionErrorKind::DeviceRecognition
            } else if message.contains("non-rectilinear") || message.contains("all-angle") {
                DetailedExtractionErrorKind::UnsupportedGeometry
            } else {
                DetailedExtractionErrorKind::Connectivity
            };
            DetailedExtractionError::new(kind, "layout", path.clone(), message)
        })?;

    let mut labels_by_net: BTreeMap<u32, BTreeSet<String>> = BTreeMap::new();
    for (&polygon, label) in &store.net_labels {
        let Some(&net) = raw.net_of_poly.get(polygon as usize) else {
            return Err(DetailedExtractionError::new(
                DetailedExtractionErrorKind::LabelConflict,
                format!("polygon {polygon}"),
                path,
                format!("label '{label}' references a nonexistent polygon"),
            ));
        };
        if net == u32::MAX {
            return Err(DetailedExtractionError::new(
                DetailedExtractionErrorKind::LabelConflict,
                format!("polygon {polygon}"),
                path,
                format!("label '{label}' is attached to non-conductor geometry"),
            ));
        }
        labels_by_net.entry(net).or_default().insert(label.clone());
    }
    for text_index in 0..store.text_count() {
        if let Some(net) = associate_text(
            store,
            deck,
            &exact,
            &raw.net_of_poly,
            text_index,
            options,
            &path,
        )? {
            labels_by_net
                .entry(net)
                .or_default()
                .insert(store.text_string[text_index].clone());
        }
    }

    // Complement polygon/text labels with net_names from raw extraction.
    // ponytail: additive only — existing labels take precedence.
    for (&net, name) in &raw.net_names {
        labels_by_net.entry(net).or_default().insert(name.clone());
    }

    if !options.allow_multiple_labels_per_net {
        if let Some((&net, labels)) = labels_by_net.iter().find(|(_, labels)| labels.len() > 1) {
            return Err(DetailedExtractionError::new(
                DetailedExtractionErrorKind::LabelConflict,
                format!("net {net}"),
                path,
                format!("net has conflicting labels {labels:?}"),
            ));
        }
    }

    let mut nets_by_label: BTreeMap<String, BTreeSet<u32>> = BTreeMap::new();
    for (&net, labels) in &labels_by_net {
        for label in labels {
            nets_by_label
                .entry(label.to_ascii_lowercase())
                .or_default()
                .insert(net);
        }
    }

    let mut out = DetailedExtractedNetlist::empty(&options.cell_name);
    let mut actual_nets: BTreeSet<u32> = raw
        .net_of_poly
        .iter()
        .copied()
        .filter(|net| *net != u32::MAX)
        .collect();
    for device in &raw.devices {
        actual_nets.extend([device.drain, device.gate, device.source]);
        if device.body != u32::MAX {
            actual_nets.insert(device.body);
        }
    }
    for device in &raw.two_terminal {
        actual_nets.extend([device.terminal_a, device.terminal_b]);
    }
    for device in &raw.bjt_devices {
        actual_nets.extend([device.collector, device.base, device.emitter]);
    }
    for net in actual_nets {
        let labels = labels_by_net.remove(&net).unwrap_or_default();
        let mut ports = BTreeMap::new();
        let mut globals = BTreeSet::new();
        for label in &labels {
            if let Some(direction) = options.ports.iter().find_map(|(name, direction)| {
                name.eq_ignore_ascii_case(label).then_some(*direction)
            }) {
                ports.insert(label.clone(), direction);
            }
            if options
                .globals
                .iter()
                .chain(deck.global_nets.iter())
                .any(|name| name.eq_ignore_ascii_case(label))
            {
                globals.insert(label.clone());
            }
        }
        out.nets.insert(
            net,
            NetIdentity {
                id: net,
                labels,
                ports,
                globals,
                hierarchy_path: path.clone(),
            },
        );
    }

    for required_port in options.ports.keys() {
        let found = out.nets.values().any(|net| {
            net.ports
                .keys()
                .any(|name| name.eq_ignore_ascii_case(required_port))
        });
        if !found {
            return Err(DetailedExtractionError::new(
                DetailedExtractionErrorKind::MissingPort,
                required_port,
                path,
                "required layout port was not found on conductor geometry",
            ));
        }
    }

    for (label, nets) in nets_by_label.iter().filter(|(_, nets)| nets.len() > 1) {
        let mut ordered = nets.iter().copied();
        let first = ordered.next().expect("len > 1");
        for other in ordered {
            out.open_candidates.push(OpenCandidate {
                net_a: first,
                net_b: other,
                reason: format!("label '{label}' occurs on disconnected conductor nets"),
                hierarchy_path: path.clone(),
            });
        }
    }

    for policy in &options.soft_connections {
        let lookup = |name: &str| -> Result<u32, DetailedExtractionError> {
            let key = name.to_ascii_lowercase();
            let nets = nets_by_label.get(&key).ok_or_else(|| {
                DetailedExtractionError::new(
                    DetailedExtractionErrorKind::InvalidPolicy,
                    &policy.policy_id,
                    path.clone(),
                    format!("soft-connect name '{name}' was not found"),
                )
            })?;
            if nets.len() != 1 {
                return Err(DetailedExtractionError::new(
                    DetailedExtractionErrorKind::InvalidPolicy,
                    &policy.policy_id,
                    path.clone(),
                    format!("soft-connect name '{name}' is not unique: {nets:?}"),
                ));
            }
            Ok(*nets.iter().next().unwrap())
        };
        out.soft_connections.push(SoftConnection {
            from: lookup(&policy.from_name)?,
            to: lookup(&policy.to_name)?,
            policy_id: policy.policy_id.clone(),
            hierarchy_path: path.clone(),
        });
    }

    if let Some(substrate) = options.default_substrate_net {
        if !out.nets.contains_key(&substrate) {
            return Err(DetailedExtractionError::new(
                DetailedExtractionErrorKind::InvalidPolicy,
                format!("net {substrate}"),
                path,
                "configured default substrate net does not exist",
            ));
        }
    }

    for (index, device) in raw.devices.iter().enumerate() {
        if device.w <= 0 || device.l <= 0 {
            return Err(DetailedExtractionError::new(
                DetailedExtractionErrorKind::InvalidProperty,
                format!("MOS {index}"),
                path,
                format!("non-positive W/L {}/{}", device.w, device.l),
            ));
        }
        let rule = match_mos_rule(
            deck,
            &device.kind,
            device.flavor,
            device.device_class.as_deref(),
            index,
            &path,
        )?;
        let unresolved = || {
            TerminalConnection::Unresolved(UnresolvedTerminal {
                reason: format!(
                    "MOS rule '{}' did not resolve a body/well conductor",
                    rule.name
                ),
                hierarchy_path: path.clone(),
            })
        };
        let (body, well, substrate) = if rule.well_layer.is_some() {
            if device.body == u32::MAX {
                (unresolved(), Some(unresolved()), None)
            } else {
                (
                    TerminalConnection::Connected(device.body),
                    Some(TerminalConnection::Connected(device.body)),
                    None,
                )
            }
        } else if let Some(net) = options.default_substrate_net {
            (
                TerminalConnection::Connected(net),
                None,
                Some(TerminalConnection::Connected(net)),
            )
        } else {
            let unresolved = TerminalConnection::Unresolved(UnresolvedTerminal {
                reason: format!(
                    "MOS rule '{}' declares no well layer and no default substrate policy was supplied",
                    rule.name
                ),
                hierarchy_path: path.clone(),
            });
            (unresolved.clone(), None, Some(unresolved))
        };
        let width = f64::from(device.w) * deck.dbu_nm;
        let length = f64::from(device.l) * deck.dbu_nm;
        let mut properties = BTreeMap::new();
        properties.insert(
            "W".into(),
            property(width, PropertyUnit::Nanometer, "W", &path)?,
        );
        properties.insert(
            "L".into(),
            property(length, PropertyUnit::Nanometer, "L", &path)?,
        );
        properties.insert(
            "NF".into(),
            property(1.0, PropertyUnit::Count, "NF", &path)?,
        );
        properties.insert("M".into(), property(1.0, PropertyUnit::Count, "M", &path)?);
        properties.insert(
            "CHANNEL_AREA".into(),
            property(
                width * length,
                PropertyUnit::SquareNanometer,
                "CHANNEL_AREA",
                &path,
            )?,
        );
        properties.insert(
            "CHANNEL_PERIMETER".into(),
            property(
                2.0 * (width + length),
                PropertyUnit::Nanometer,
                "CHANNEL_PERIMETER",
                &path,
            )?,
        );
        out.mos_devices.push(MosDeviceRecord {
            identity: identity(
                format!("{}:M{index}", options.cell_name),
                &path,
                Some(rule.name.clone()),
                device.device_class.clone(),
                device.flavor,
            ),
            kind: device.kind.clone(),
            drain: device.drain,
            gate: device.gate,
            source: device.source,
            body,
            well,
            substrate,
            properties,
        });
    }

    for (index, device) in raw.two_terminal.iter().enumerate() {
        let (unit, scale) = match device.kind {
            TwoTerminalKind::Resistor => (PropertyUnit::Ohm, 1.0),
            TwoTerminalKind::Capacitor => (PropertyUnit::Farad, 1.0e-18),
            TwoTerminalKind::Diode => (PropertyUnit::Dimensionless, 1.0),
        };
        let mut properties = BTreeMap::new();
        if device.kind != TwoTerminalKind::Diode || device.value != 0.0 {
            properties.insert(
                "VALUE".into(),
                property(device.value * scale, unit, "VALUE", &path)?,
            );
        }
        out.two_terminal_devices.push(TwoTerminalRecord {
            identity: identity(
                format!("{}:X{index}", options.cell_name),
                &path,
                Some(device.name.clone()),
                None,
                DeviceFlavor::Standard,
            ),
            kind: device.kind.clone(),
            terminal_a: device.terminal_a,
            terminal_b: device.terminal_b,
            properties,
        });
    }

    for (index, device) in raw.bjt_devices.iter().enumerate() {
        out.bjt_devices.push(BjtDeviceRecord {
            identity: identity(
                format!("{}:Q{index}", options.cell_name),
                &path,
                Some(device.name.clone()),
                None,
                DeviceFlavor::Standard,
            ),
            kind: device.kind.clone(),
            collector: device.collector,
            base: device.base,
            emitter: device.emitter,
            substrate: None,
            properties: BTreeMap::new(),
        });
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{
        ConnectivityConfig, DeviceConfig, ErcParams, LayerDef, LayerTable, MosRule,
    };
    use crate::schema::PropertyTolerance;
    use std::collections::HashMap;

    fn deck(with_well: bool) -> Deck {
        let definitions = [
            ("nwell", 1, 0),
            ("diff", 2, 0),
            ("poly", 3, 0),
            ("nsdm", 4, 0),
            ("met1", 7, 0),
            ("via1", 8, 0),
        ]
        .into_iter()
        .map(|(name, layer, datatype)| (name.to_string(), LayerDef { layer, datatype }))
        .collect();
        let layers = LayerTable::from_defs(&definitions);
        let nwell = layers.id("nwell").unwrap();
        let diff = layers.id("diff").unwrap();
        let poly = layers.id("poly").unwrap();
        let met1 = layers.id("met1").unwrap();
        let via1 = layers.id("via1").unwrap();
        Deck {
            connectivity: ConnectivityConfig {
                conductors: vec![nwell, diff, poly, met1],
                vias: vec![(via1, vec![met1])],
            },
            devices: DeviceConfig {
                mos_rules: vec![MosRule {
                    name: "nch".into(),
                    gate_layer: poly,
                    channel_layer: diff,
                    type_implant: layers.id("nsdm").unwrap(),
                    device_type: "nmos".into(),
                    flavor_markers: Vec::new(),
                    well_layer: with_well.then_some(nwell),
                    device_class: Some("core".into()),
                }],
                ..Default::default()
            },
            layers,
            drc_rules: Vec::new(),
            pex: HashMap::new(),
            dbu_nm: 1.0,
            lvs_cut_required: true,
            strict: true,
            w_tolerance: PropertyTolerance::default(),
            l_tolerance: PropertyTolerance::default(),
            fail_on_floating: false,
            erc: ErcParams::default(),
            intra_layer_touch: false,
            global_nets: Vec::new(),
            device_catalog: HashMap::new(),
            pex_method: Default::default(),
        }
    }

    fn mos_geometry(deck: &Deck, gates: &[i32]) -> GeometryStore {
        let mut store = GeometryStore::new();
        let nwell = deck.layers.id("nwell").unwrap();
        let diff = deck.layers.id("diff").unwrap();
        let poly = deck.layers.id("poly").unwrap();
        let nsdm = deck.layers.id("nsdm").unwrap();
        store.add_rect(nwell, -100, -100, 1200, 400);
        store.add_rect(diff, 0, 0, 1000, 200);
        for &x in gates {
            store.add_rect(poly, x, -50, 60, 300);
        }
        store.add_rect(nsdm, -50, -50, 1100, 300);
        store
    }

    #[test]
    fn resolved_body_on_real_net_zero_is_not_an_unresolved_sentinel() {
        let deck = deck(true);
        let store = mos_geometry(&deck, &[400]);
        let extracted = extract_detailed_netlist(
            &store,
            &deck,
            &DetailedExtractionOptions {
                cell_name: "body0".into(),
                extract: ExtractOpts {
                    cut_required: true,
                    ..Default::default()
                },
                ..Default::default()
            },
            Backend::Cpu,
        )
        .unwrap();
        assert_eq!(extracted.mos_devices.len(), 1);
        assert_eq!(extracted.mos_devices[0].body.connected(), Some(&0));
        assert_eq!(
            extracted.mos_devices[0]
                .well
                .as_ref()
                .and_then(TerminalConnection::connected),
            Some(&0)
        );
        assert_eq!(
            extracted.mos_devices[0].properties["W"].unit,
            PropertyUnit::Nanometer
        );
        assert!(extracted.mos_devices[0]
            .properties
            .contains_key("CHANNEL_AREA"));
    }

    #[test]
    fn individual_fingers_are_preserved_with_stable_identity() {
        let deck = deck(true);
        let store = mos_geometry(&deck, &[200, 600]);
        let extracted = extract_detailed_netlist(
            &store,
            &deck,
            &DetailedExtractionOptions {
                cell_name: "fingers".into(),
                extract: ExtractOpts {
                    cut_required: true,
                    ..Default::default()
                },
                ..Default::default()
            },
            Backend::Cpu,
        )
        .unwrap();
        assert_eq!(extracted.mos_devices.len(), 2);
        assert_eq!(extracted.mos_devices[0].identity.stable_id, "fingers:M0");
        assert_eq!(extracted.mos_devices[1].identity.stable_id, "fingers:M1");
        assert_eq!(extracted.mos_devices[0].properties["NF"].value, 1.0);
    }

    fn labeled_metals() -> (Deck, GeometryStore, PolyId, PolyId) {
        let deck = deck(false);
        let met1 = deck.layers.id("met1").unwrap();
        let mut store = GeometryStore::new();
        let left = store.add_rect(met1, 0, 0, 100, 100);
        let right = store.add_rect(met1, 200, 0, 100, 100);
        (deck, store, left, right)
    }

    #[test]
    fn text_ports_globals_and_soft_connects_are_structured() {
        let (mut deck, mut store, _, _) = labeled_metals();
        store.add_text(7, 99, 50, 50, "A".into());
        store.add_text(7, 99, 250, 50, "VSS".into());
        deck.global_nets.push("VSS".into());
        let extracted = extract_detailed_netlist(
            &store,
            &deck,
            &DetailedExtractionOptions {
                cell_name: "labels".into(),
                ports: BTreeMap::from([("A".into(), PortDirection::Input)]),
                soft_connections: vec![NamedSoftConnection {
                    from_name: "A".into(),
                    to_name: "VSS".into(),
                    policy_id: "substrate-soft".into(),
                }],
                ..Default::default()
            },
            Backend::Cpu,
        )
        .unwrap();
        let a = extracted
            .nets
            .values()
            .find(|net| net.labels.contains("A"))
            .unwrap();
        assert_eq!(a.ports["A"], PortDirection::Input);
        let vss = extracted
            .nets
            .values()
            .find(|net| net.labels.contains("VSS"))
            .unwrap();
        assert!(vss.globals.contains("VSS"));
        assert_eq!(extracted.soft_connections.len(), 1);
    }

    #[test]
    fn ambiguous_boundary_text_and_conflicting_labels_fail() {
        let mut deck = deck(false);
        deck.intra_layer_touch = false;
        let met1 = deck.layers.id("met1").unwrap();
        let mut store = GeometryStore::new();
        store.add_rect(met1, 0, 0, 100, 100);
        store.add_rect(met1, 100, 0, 100, 100);
        store.add_text(7, 99, 100, 50, "AMB".into());
        let error =
            extract_detailed_netlist(&store, &deck, &Default::default(), Backend::Cpu).unwrap_err();
        assert_eq!(error.kind, DetailedExtractionErrorKind::AmbiguousText);

        let (deck, mut store, left, _) = labeled_metals();
        store.net_labels.insert(left.0, "A".into());
        store.add_text(7, 99, 50, 50, "B".into());
        let error =
            extract_detailed_netlist(&store, &deck, &Default::default(), Backend::Cpu).unwrap_err();
        assert_eq!(error.kind, DetailedExtractionErrorKind::LabelConflict);
    }

    #[test]
    fn disconnected_repeated_label_becomes_explicit_open_candidate() {
        let (deck, mut store, left, right) = labeled_metals();
        store.net_labels.insert(left.0, "OPEN".into());
        store.net_labels.insert(right.0, "OPEN".into());
        let extracted =
            extract_detailed_netlist(&store, &deck, &Default::default(), Backend::Cpu).unwrap();
        assert_eq!(extracted.open_candidates.len(), 1);
        assert!(extracted.open_candidates[0].reason.contains("disconnected"));
    }

    #[test]
    fn non_rectilinear_uses_bbox_fallback_in_detailed() {
        let deck = deck(false);
        let met1 = deck.layers.id("met1").unwrap();
        let mut diagonal = GeometryStore::new();
        diagonal.add_polygon(met1, &[(0, 0), (100, 0), (80, 100), (0, 100)]);
        // ponytail: non-rectilinear now succeeds with bbox approximation
        let result = extract_detailed_netlist(&diagonal, &deck, &Default::default(), Backend::Cpu);
        assert!(
            result.is_ok(),
            "non-rectilinear should use bbox fallback: {:?}",
            result.err()
        );
    }

    #[test]
    fn invalid_geometry_fails_before_recognition() {
        let deck = deck(false);
        let met1 = deck.layers.id("met1").unwrap();
        let mut bow_tie = GeometryStore::new();
        bow_tie.add_polygon(met1, &[(0, 0), (100, 100), (0, 100), (100, 0)]);
        let error = extract_detailed_netlist(&bow_tie, &deck, &Default::default(), Backend::Cpu)
            .unwrap_err();
        assert_eq!(error.kind, DetailedExtractionErrorKind::InvalidGeometry);
    }
}
