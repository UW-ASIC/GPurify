//! Typed adapter from the lossless GDS hierarchy to production hierarchical LVS.
//!
//! Electrical evidence is deliberately narrow. Local connectivity and devices are
//! extracted by the production extractor. Ports originate only from configured GDS
//! TEXT evidence attached to exactly one conductor net. Instance ports bind only by
//! exact transformed access-geometry contact or an explicitly configured instance
//! property. Unsupported transforms and ambiguous/missing evidence are errors.

use super::detailed_extract::{extract_detailed_netlist, DetailedExtractionOptions};
use super::extract::extract_raw;
use super::hier_production::{
    flatten_layout, HierArray, HierLayout, HierLayoutCell, HierLayoutInstance, HierTransform,
};
use super::production::*;
use super::types::{DeviceRecognitionSource, ExtractOpts};
use crate::backend::Backend;
use crate::gds::{
    exact_pitch, flatten_gds_library, stroke_path, GdsElement, GdsElementMeta, GdsFlattenOptions,
    GdsGeometryPolicy, GdsLibrary, GdsProperty, GdsStructure, GdsTransform,
};
use gdsverify_core::exact::{classify_polygon_contact, Point, PolygonContact, Ring};
use crate::geometry::{GeometryStore, LayerId, PolyId};
use crate::params::Deck;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;

/// Hard pre-recursion bound for the current W2/W4 flatten consumers. The
/// adapter's iterative selected-top audit runs first and rejects deeper cones.
pub const GDS_ADAPTER_MAX_STACK_SAFE_DEPTH: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GdsHierarchyAdapterErrorKind {
    InvalidOptions,
    Unsupported,
    UnknownLayer,
    Extraction,
    MissingEvidence,
    AmbiguousEvidence,
    ConflictingEvidence,
    UndefinedCell,
    HierarchyCycle,
    CapacityExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GdsHierarchyAdapterError {
    pub kind: GdsHierarchyAdapterErrorKind,
    pub structure: String,
    pub element_index: Option<usize>,
    pub hierarchy_path: HierarchyPath,
    pub message: String,
}

impl GdsHierarchyAdapterError {
    fn new(
        kind: GdsHierarchyAdapterErrorKind,
        structure: impl Into<String>,
        element_index: Option<usize>,
        hierarchy_path: HierarchyPath,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            structure: structure.into(),
            element_index,
            hierarchy_path,
            message: message.into(),
        }
    }

    fn cell(kind: GdsHierarchyAdapterErrorKind, cell: &str, message: impl Into<String>) -> Self {
        Self::new(kind, cell, None, cell_path(cell), message)
    }

    fn element(
        kind: GdsHierarchyAdapterErrorKind,
        cell: &str,
        element: usize,
        message: impl Into<String>,
    ) -> Self {
        Self::new(
            kind,
            cell,
            Some(element),
            element_path(cell, element),
            message,
        )
    }
}

impl fmt::Display for GdsHierarchyAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.element_index {
            Some(index) => write!(
                f,
                "{} element {index} [{}]: {}",
                self.structure, self.hierarchy_path, self.message
            ),
            None => write!(
                f,
                "{} [{}]: {}",
                self.structure, self.hierarchy_path, self.message
            ),
        }
    }
}

impl std::error::Error for GdsHierarchyAdapterError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GdsTextEvidenceRule {
    pub layer: i16,
    pub datatype: i16,
    /// If true, the TEXT string is one candidate electrical name.
    pub use_string: bool,
    /// Property attributes whose values are candidate electrical names.
    pub label_property_attributes: BTreeSet<i16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GdsBlackBoxAdapterSpec {
    /// Complete, ordered black-box port declaration. Empty maps are rejected.
    pub ports: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct GdsHierarchyAdapterOptions {
    pub top_cell: String,
    pub text_evidence: Vec<GdsTextEvidenceRule>,
    /// Per-cell required port names and directions.
    pub cell_ports: BTreeMap<String, BTreeMap<String, PortDirection>>,
    pub global_names: BTreeSet<String>,
    /// GDS property attributes with exact `child_port=parent_net_name` values.
    pub instance_binding_property_attributes: BTreeSet<i16>,
    pub black_boxes: BTreeMap<String, GdsBlackBoxAdapterSpec>,
    /// Layout-cell -> reference-cell declarations returned alongside the layout.
    pub equated_cells: BTreeMap<String, String>,
    pub extract: ExtractOpts,
    pub default_substrate_nets: BTreeMap<String, u32>,
    pub reject_unconfigured_text: bool,
    pub allow_boundary_port_contact: bool,
    pub max_array_copies: usize,
    /// Maximum expanded non-black-box instance count across the selected top.
    pub max_hierarchy_expanded_instances: usize,
    /// Requested maximum cell nesting depth, additionally capped by
    /// [`GDS_ADAPTER_MAX_STACK_SAFE_DEPTH`] before recursive W2/W4 consumers.
    pub max_hierarchy_depth: usize,
    /// W2 flattening counts geometry and reference visits, not only instances.
    pub max_physical_flatten_visits: usize,
}

impl GdsHierarchyAdapterOptions {
    pub fn new(top_cell: impl Into<String>) -> Self {
        Self {
            top_cell: top_cell.into(),
            text_evidence: Vec::new(),
            cell_ports: BTreeMap::new(),
            global_names: BTreeSet::new(),
            instance_binding_property_attributes: BTreeSet::new(),
            black_boxes: BTreeMap::new(),
            equated_cells: BTreeMap::new(),
            extract: ExtractOpts::default(),
            default_substrate_nets: BTreeMap::new(),
            reject_unconfigured_text: true,
            allow_boundary_port_contact: false,
            max_array_copies: 1_000_000,
            max_hierarchy_expanded_instances: 1_000_000,
            max_hierarchy_depth: GDS_ADAPTER_MAX_STACK_SAFE_DEPTH,
            max_physical_flatten_visits: 10_000_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GdsAdapterObjectKind {
    Boundary,
    Box,
    Path,
    Text,
    Sref,
    Aref,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GdsObjectProvenance {
    pub stable_id: String,
    pub hierarchy_path: HierarchyPath,
    pub structure: String,
    pub element_index: usize,
    pub kind: GdsAdapterObjectKind,
    /// Raw GDS properties are retained verbatim. They remain uninterpreted and
    /// have no electrical meaning unless an adapter option explicitly accepts
    /// their attribute as TEXT-name or instance-binding evidence.
    pub properties: Vec<GdsProperty>,
    pub element_flags: Option<u16>,
    pub plex: Option<i32>,
    pub text: Option<String>,
    pub local_net: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GdsHierarchyProvenance {
    pub objects: BTreeMap<String, GdsObjectProvenance>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GdsHierarchyAdapterResult {
    pub layout: HierLayout,
    pub equated_cells: BTreeMap<String, String>,
    pub provenance: GdsHierarchyProvenance,
    pub physical_correlation: GdsPhysicalCorrelationStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GdsPhysicalCorrelationStatus {
    /// Independent flattened physical extraction matched the composed hierarchy.
    Correlated,
    /// Every reachable nonopaque shape was correlated. Geometry inside these
    /// selected-top-reachable opaque cells was pruned from both physical and
    /// composed views; hierarchical LVS must still compare every target and map.
    OpaqueBlackBoxes { cells: BTreeSet<String> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GdsDrcHierarchyContext {
    pub stable_paths: Vec<HierarchyPath>,
}

/// W3 context types are not present in the W2+W4 integration base. Keep the
/// stable paths observable, but fail explicitly instead of fabricating a DRC context.
pub fn export_w3_drc_hierarchy_context(
    adapted: &GdsHierarchyAdapterResult,
) -> Result<GdsDrcHierarchyContext, GdsHierarchyAdapterError> {
    let paths = adapted
        .provenance
        .objects
        .values()
        .map(|object| object.hierarchy_path.clone())
        .collect::<Vec<_>>();
    Err(GdsHierarchyAdapterError::cell(
        GdsHierarchyAdapterErrorKind::Unsupported,
        &adapted.layout.top_cell,
        format!(
            "W3 DRC hierarchy/context consumer is absent in this integration base; {} stable GDS paths remain available in provenance",
            paths.len()
        ),
    ))
}

#[derive(Clone)]
struct SourceShape {
    stable_id: String,
    layer: LayerId,
    ring: Ring,
}

#[derive(Clone)]
struct NetShape {
    net: String,
    layer: LayerId,
    ring: Ring,
}

#[derive(Clone)]
struct LocalCell {
    netlist: DetailedNetlist<String>,
    ports: Vec<String>,
    port_access: BTreeMap<String, Vec<NetShape>>,
    net_shapes: Vec<NetShape>,
}

fn cell_path(cell: &str) -> HierarchyPath {
    HierarchyPath(vec![format!("gds:{cell}")])
}

fn element_path(cell: &str, element: usize) -> HierarchyPath {
    HierarchyPath(vec![format!("gds:{cell}"), format!("E{element}")])
}

fn source_path(cell: &str, element: usize, part: usize) -> HierarchyPath {
    let mut path = element_path(cell, element);
    if part != 0 {
        path.0.push(format!("P{part}"));
    }
    path
}

fn source_id(cell: &str, element: usize, part: usize) -> String {
    if part == 0 {
        format!("gds:{cell}:E{element}")
    } else {
        format!("gds:{cell}:E{element}:P{part}")
    }
}

fn meta(element: &GdsElement) -> Option<&GdsElementMeta> {
    element.meta()
}

fn evidence_rule<'a>(
    options: &'a GdsHierarchyAdapterOptions,
    layer: i16,
    datatype: i16,
) -> Option<&'a GdsTextEvidenceRule> {
    options
        .text_evidence
        .iter()
        .find(|rule| rule.layer == layer && rule.datatype == datatype)
}

fn derive_text_name(
    cell: &str,
    element: usize,
    text: &crate::gds::GdsText,
    rule: &GdsTextEvidenceRule,
) -> Result<String, GdsHierarchyAdapterError> {
    let mut candidates = BTreeSet::new();
    if rule.use_string && !text.string.trim().is_empty() {
        candidates.insert(text.string.trim().to_string());
    }
    for property in &text.meta.properties {
        if rule.label_property_attributes.contains(&property.attribute)
            && !property.value.trim().is_empty()
        {
            candidates.insert(property.value.trim().to_string());
        }
    }
    let folded: BTreeSet<String> = candidates
        .iter()
        .map(|candidate| candidate.to_ascii_lowercase())
        .collect();
    if candidates.is_empty() {
        return Err(GdsHierarchyAdapterError::element(
            GdsHierarchyAdapterErrorKind::MissingEvidence,
            cell,
            element,
            "configured TEXT evidence has no nonempty accepted string/property value",
        ));
    }
    if folded.len() != 1 {
        return Err(GdsHierarchyAdapterError::element(
            GdsHierarchyAdapterErrorKind::ConflictingEvidence,
            cell,
            element,
            format!("TEXT string/properties disagree: {candidates:?}"),
        ));
    }
    Ok(candidates.into_iter().next().unwrap())
}

fn add_provenance(
    provenance: &mut GdsHierarchyProvenance,
    cell: &str,
    element: usize,
    part: usize,
    kind: GdsAdapterObjectKind,
    meta: Option<&GdsElementMeta>,
    text: Option<String>,
) {
    let stable_id = source_id(cell, element, part);
    provenance.objects.insert(
        stable_id.clone(),
        GdsObjectProvenance {
            stable_id,
            hierarchy_path: source_path(cell, element, part),
            structure: cell.to_string(),
            element_index: element,
            kind,
            properties: meta.map(|meta| meta.properties.clone()).unwrap_or_default(),
            element_flags: meta.and_then(|meta| meta.element_flags),
            plex: meta.and_then(|meta| meta.plex),
            text,
            local_net: None,
        },
    );
}

fn build_local_store(
    structure: &GdsStructure,
    deck: &Deck,
    options: &GdsHierarchyAdapterOptions,
    provenance: &mut GdsHierarchyProvenance,
) -> Result<(GeometryStore, Vec<SourceShape>, Vec<usize>), GdsHierarchyAdapterError> {
    let mut store = GeometryStore::new();
    let mut source_shapes = Vec::new();
    let mut text_elements = Vec::new();
    for (element_index, element) in structure.elements.iter().enumerate() {
        let element_meta = meta(element);
        if element_meta.is_some_and(|meta| !meta.unhandled_records.is_empty()) {
            return Err(GdsHierarchyAdapterError::element(
                GdsHierarchyAdapterErrorKind::Unsupported,
                &structure.name,
                element_index,
                "element contains unhandled GDS records with no electrical semantics",
            ));
        }
        let properties = element_meta
            .map(|meta| meta.properties.clone())
            .unwrap_or_default();
        match element {
            GdsElement::Boundary(boundary) => {
                let layer = deck
                    .layers
                    .from_gds(boundary.layer as i32, boundary.datatype as i32)
                    .ok_or_else(|| {
                        GdsHierarchyAdapterError::element(
                            GdsHierarchyAdapterErrorKind::UnknownLayer,
                            &structure.name,
                            element_index,
                            format!(
                                "BOUNDARY layer/type ({}, {}) is absent from deck",
                                boundary.layer, boundary.datatype
                            ),
                        )
                    })?;
                let ring = Ring::new(boundary.ring.clone()).map_err(|error| {
                    GdsHierarchyAdapterError::element(
                        GdsHierarchyAdapterErrorKind::Extraction,
                        &structure.name,
                        element_index,
                        format!("invalid BOUNDARY: {error}"),
                    )
                })?;
                let points = boundary
                    .ring
                    .iter()
                    .map(|point| (point.x, point.y))
                    .collect::<Vec<_>>();
                let stable_id = source_id(&structure.name, element_index, 0);
                store.add_polygon_annotated(
                    layer,
                    &points,
                    properties
                        .iter()
                        .map(|property| (property.attribute, property.value.clone()))
                        .collect(),
                    element_path(&structure.name, element_index).0,
                );
                source_shapes.push(SourceShape {
                    stable_id,
                    layer,
                    ring,
                });
                add_provenance(
                    provenance,
                    &structure.name,
                    element_index,
                    0,
                    GdsAdapterObjectKind::Boundary,
                    element_meta,
                    None,
                );
            }
            GdsElement::Box(box_element) => {
                let layer = deck
                    .layers
                    .from_gds(box_element.layer as i32, box_element.box_type as i32)
                    .ok_or_else(|| {
                        GdsHierarchyAdapterError::element(
                            GdsHierarchyAdapterErrorKind::UnknownLayer,
                            &structure.name,
                            element_index,
                            format!(
                                "BOX layer/type ({}, {}) is absent from deck",
                                box_element.layer, box_element.box_type
                            ),
                        )
                    })?;
                let ring = Ring::new(box_element.ring.clone()).map_err(|error| {
                    GdsHierarchyAdapterError::element(
                        GdsHierarchyAdapterErrorKind::Extraction,
                        &structure.name,
                        element_index,
                        format!("invalid BOX: {error}"),
                    )
                })?;
                let points = box_element
                    .ring
                    .iter()
                    .map(|point| (point.x, point.y))
                    .collect::<Vec<_>>();
                let stable_id = source_id(&structure.name, element_index, 0);
                store.add_polygon_annotated(
                    layer,
                    &points,
                    properties
                        .iter()
                        .map(|property| (property.attribute, property.value.clone()))
                        .collect(),
                    element_path(&structure.name, element_index).0,
                );
                source_shapes.push(SourceShape {
                    stable_id,
                    layer,
                    ring,
                });
                add_provenance(
                    provenance,
                    &structure.name,
                    element_index,
                    0,
                    GdsAdapterObjectKind::Box,
                    element_meta,
                    None,
                );
            }
            GdsElement::Path(path) => {
                let layer = deck
                    .layers
                    .from_gds(path.layer as i32, path.datatype as i32)
                    .ok_or_else(|| {
                        GdsHierarchyAdapterError::element(
                            GdsHierarchyAdapterErrorKind::UnknownLayer,
                            &structure.name,
                            element_index,
                            format!(
                                "PATH layer/type ({}, {}) is absent from deck",
                                path.layer, path.datatype
                            ),
                        )
                    })?;
                let rings = stroke_path(path).map_err(|error| {
                    GdsHierarchyAdapterError::element(
                        GdsHierarchyAdapterErrorKind::Unsupported,
                        &structure.name,
                        element_index,
                        error.to_string(),
                    )
                })?;
                for (part, points) in rings.into_iter().enumerate() {
                    let ring = Ring::new(points.clone()).map_err(|error| {
                        GdsHierarchyAdapterError::element(
                            GdsHierarchyAdapterErrorKind::Extraction,
                            &structure.name,
                            element_index,
                            format!("invalid stroked PATH: {error}"),
                        )
                    })?;
                    let tuples = points
                        .iter()
                        .map(|point| (point.x, point.y))
                        .collect::<Vec<_>>();
                    let stable_id = source_id(&structure.name, element_index, part);
                    store.add_polygon_annotated(
                        layer,
                        &tuples,
                        properties
                            .iter()
                            .map(|property| (property.attribute, property.value.clone()))
                            .collect(),
                        element_path(&structure.name, element_index).0,
                    );
                    source_shapes.push(SourceShape {
                        stable_id,
                        layer,
                        ring,
                    });
                    add_provenance(
                        provenance,
                        &structure.name,
                        element_index,
                        part,
                        GdsAdapterObjectKind::Path,
                        element_meta,
                        None,
                    );
                }
            }
            GdsElement::Text(text) => {
                let Some(rule) = evidence_rule(options, text.layer, text.text_type) else {
                    if options.reject_unconfigured_text {
                        return Err(GdsHierarchyAdapterError::element(
                            GdsHierarchyAdapterErrorKind::Unsupported,
                            &structure.name,
                            element_index,
                            format!(
                                "TEXT layer/type ({}, {}) has no configured evidence rule",
                                text.layer, text.text_type
                            ),
                        ));
                    }
                    add_provenance(
                        provenance,
                        &structure.name,
                        element_index,
                        0,
                        GdsAdapterObjectKind::Text,
                        element_meta,
                        Some(text.string.clone()),
                    );
                    continue;
                };
                let label = derive_text_name(&structure.name, element_index, text, rule)?;
                store.add_text_annotated(
                    text.layer as i32,
                    text.text_type as i32,
                    text.origin.x,
                    text.origin.y,
                    label.clone(),
                    properties
                        .iter()
                        .map(|property| (property.attribute, property.value.clone()))
                        .collect(),
                    element_path(&structure.name, element_index).0,
                );
                text_elements.push(element_index);
                add_provenance(
                    provenance,
                    &structure.name,
                    element_index,
                    0,
                    GdsAdapterObjectKind::Text,
                    element_meta,
                    Some(label),
                );
            }
            GdsElement::Sref(_) => add_provenance(
                provenance,
                &structure.name,
                element_index,
                0,
                GdsAdapterObjectKind::Sref,
                element_meta,
                None,
            ),
            GdsElement::Aref(_) => add_provenance(
                provenance,
                &structure.name,
                element_index,
                0,
                GdsAdapterObjectKind::Aref,
                element_meta,
                None,
            ),
            GdsElement::Node(_) | GdsElement::Unsupported(_) => {
                return Err(GdsHierarchyAdapterError::element(
                    GdsHierarchyAdapterErrorKind::Unsupported,
                    &structure.name,
                    element_index,
                    "element has no production LVS adapter semantics",
                ));
            }
        }
    }
    Ok((store, source_shapes, text_elements))
}

fn source_sets_by_net(
    raw_net_of_poly: &[u32],
    source_shapes: &[SourceShape],
) -> BTreeMap<u32, BTreeSet<String>> {
    let mut sources = BTreeMap::<u32, BTreeSet<String>>::new();
    for (polygon, &net) in raw_net_of_poly.iter().enumerate() {
        if net != u32::MAX {
            if let Some(source) = source_shapes.get(polygon) {
                sources
                    .entry(net)
                    .or_default()
                    .insert(source.stable_id.clone());
            }
        }
    }
    sources
}

fn stable_net_names(
    cell: &str,
    detailed: &DetailedExtractedNetlist,
    sources: &BTreeMap<u32, BTreeSet<String>>,
) -> Result<BTreeMap<u32, String>, GdsHierarchyAdapterError> {
    let names = detailed
        .nets
        .iter()
        .map(|(&net, identity)| {
            // W4's hierarchy contract names child bindings by declared port.
            // Give a uniquely declared port net that canonical ID while retaining
            // its source-shape identity in NetIdentity.hierarchy_path/provenance.
            if let Some(port) = (identity.ports.len() == 1)
                .then(|| identity.ports.keys().next().cloned())
                .flatten()
            {
                return (net, port);
            }
            let source = sources
                .get(&net)
                .and_then(|sources| sources.iter().next())
                .cloned()
                .unwrap_or_else(|| format!("gds:{cell}:derived"));
            (net, format!("{source}:N{net}"))
        })
        .collect::<BTreeMap<_, _>>();
    let mut owners = BTreeMap::<String, (u32, String)>::new();
    for (&net, name) in &names {
        let folded = name.to_ascii_lowercase();
        if let Some((other_net, other_name)) = owners.insert(folded, (net, name.clone())) {
            return Err(GdsHierarchyAdapterError::cell(
                GdsHierarchyAdapterErrorKind::ConflictingEvidence,
                cell,
                format!(
                    "generated/configured net names collide: net {other_net} `{other_name}` and net {net} `{name}`"
                ),
            ));
        }
    }
    Ok(names)
}

fn map_terminal(
    terminal: &TerminalConnection<u32>,
    names: &BTreeMap<u32, String>,
    hierarchy_path: &HierarchyPath,
) -> TerminalConnection<String> {
    match terminal {
        TerminalConnection::Connected(net) => TerminalConnection::Connected(names[net].clone()),
        TerminalConnection::Unresolved(error) => {
            let mut error = error.clone();
            error.hierarchy_path = hierarchy_path.clone();
            TerminalConnection::Unresolved(error)
        }
    }
}

fn stringify_netlist(
    cell: &str,
    source: &DetailedExtractedNetlist,
    names: &BTreeMap<u32, String>,
    sources: &BTreeMap<u32, BTreeSet<String>>,
    recognition: &[DeviceRecognitionSource],
    source_shapes: &[SourceShape],
) -> Result<DetailedNetlist<String>, GdsHierarchyAdapterError> {
    if !source.two_terminal_devices.is_empty() || !source.bjt_devices.is_empty() {
        return Err(GdsHierarchyAdapterError::cell(
            GdsHierarchyAdapterErrorKind::Unsupported,
            cell,
            "GDS adapter cannot yet link two-terminal/BJT recognition to exact source geometry",
        ));
    }
    if recognition.len() != source.mos_devices.len() {
        return Err(GdsHierarchyAdapterError::cell(
            GdsHierarchyAdapterErrorKind::Unsupported,
            cell,
            format!(
                "MOS recognition provenance has {} entries for {} devices",
                recognition.len(),
                source.mos_devices.len()
            ),
        ));
    }
    let mut out = DetailedNetlist::empty(cell);
    for (&net, identity) in &source.nets {
        let id = names[&net].clone();
        let source_path = sources
            .get(&net)
            .and_then(|set| set.iter().next())
            .cloned()
            .unwrap_or_else(|| format!("gds:{cell}:derived:N{net}"));
        out.nets.insert(
            id.clone(),
            NetIdentity {
                id,
                labels: identity.labels.clone(),
                ports: identity.ports.clone(),
                globals: identity.globals.clone(),
                hierarchy_path: HierarchyPath(vec![format!("gds:{cell}"), source_path]),
            },
        );
    }
    for (index, (device, recognized)) in source
        .mos_devices
        .iter()
        .zip(recognition.iter())
        .enumerate()
    {
        if !device
            .identity
            .model
            .as_deref()
            .is_some_and(|model| model.eq_ignore_ascii_case(&recognized.rule_id))
        {
            return Err(GdsHierarchyAdapterError::cell(
                GdsHierarchyAdapterErrorKind::ConflictingEvidence,
                cell,
                format!(
                    "MOS {index} model {:?} contradicts recognition rule `{}`",
                    device.identity.model, recognized.rule_id
                ),
            ));
        }
        let gate = source_shapes
            .get(recognized.gate_polygon as usize)
            .ok_or_else(|| {
                GdsHierarchyAdapterError::cell(
                    GdsHierarchyAdapterErrorKind::Extraction,
                    cell,
                    format!(
                        "MOS {index} gate polygon {} is outside source geometry",
                        recognized.gate_polygon
                    ),
                )
            })?;
        let channel = source_shapes
            .get(recognized.channel_polygon as usize)
            .ok_or_else(|| {
                GdsHierarchyAdapterError::cell(
                    GdsHierarchyAdapterErrorKind::Extraction,
                    cell,
                    format!(
                        "MOS {index} channel polygon {} is outside source geometry",
                        recognized.channel_polygon
                    ),
                )
            })?;
        let mut hierarchy = vec![
            format!("gds:{cell}"),
            gate.stable_id.clone(),
            channel.stable_id.clone(),
        ];
        if let Some(well) = recognized.well_polygon {
            let well = source_shapes.get(well as usize).ok_or_else(|| {
                GdsHierarchyAdapterError::cell(
                    GdsHierarchyAdapterErrorKind::Extraction,
                    cell,
                    format!("MOS {index} well polygon {well} is outside source geometry"),
                )
            })?;
            hierarchy.push(well.stable_id.clone());
        }
        hierarchy.push(format!("M{index}"));
        let hierarchy_path = HierarchyPath(hierarchy);
        let stable_id = format!(
            "gds:{cell}:MOS:{}:{}:{}",
            recognized.rule_id, gate.stable_id, channel.stable_id
        );
        out.mos_devices.push(MosDeviceRecord {
            identity: DeviceIdentity {
                stable_id,
                hierarchy_path: hierarchy_path.clone(),
                model: device.identity.model.clone(),
                device_class: device.identity.device_class.clone(),
                flavor: device.identity.flavor,
            },
            kind: device.kind.clone(),
            drain: names[&device.drain].clone(),
            gate: names[&device.gate].clone(),
            source: names[&device.source].clone(),
            body: map_terminal(&device.body, names, &hierarchy_path),
            well: device
                .well
                .as_ref()
                .map(|terminal| map_terminal(terminal, names, &hierarchy_path)),
            substrate: device
                .substrate
                .as_ref()
                .map(|terminal| map_terminal(terminal, names, &hierarchy_path)),
            properties: device.properties.clone(),
        });
    }
    out.soft_connections = source
        .soft_connections
        .iter()
        .map(|connection| SoftConnection {
            from: names[&connection.from].clone(),
            to: names[&connection.to].clone(),
            policy_id: connection.policy_id.clone(),
            hierarchy_path: cell_path(cell),
        })
        .collect();
    out.open_candidates = source
        .open_candidates
        .iter()
        .map(|candidate| OpenCandidate {
            net_a: names[&candidate.net_a].clone(),
            net_b: names[&candidate.net_b].clone(),
            reason: candidate.reason.clone(),
            hierarchy_path: cell_path(cell),
        })
        .collect();
    out.seed_aliases = source.seed_aliases.clone();
    Ok(out)
}

fn build_local_cell(
    structure: &GdsStructure,
    deck: &Deck,
    options: &GdsHierarchyAdapterOptions,
    backend: Backend,
    provenance: &mut GdsHierarchyProvenance,
) -> Result<LocalCell, GdsHierarchyAdapterError> {
    let (store, source_shapes, text_elements) =
        build_local_store(structure, deck, options, provenance)?;
    let extract_result =
        extract_raw(&store, deck, &options.extract, backend, false).map_err(|message| {
            GdsHierarchyAdapterError::cell(
                GdsHierarchyAdapterErrorKind::Extraction,
                &structure.name,
                message,
            )
        })?;
    let (raw, device_sources) = (extract_result.netlist, extract_result.sources);
    let ports = options
        .cell_ports
        .get(&structure.name)
        .cloned()
        .unwrap_or_default();
    let mut detailed = extract_detailed_netlist(
        &store,
        deck,
        &DetailedExtractionOptions {
            cell_name: structure.name.clone(),
            extract: options.extract.clone(),
            ports: ports.clone(),
            globals: options.global_names.clone(),
            require_all_text_attached: true,
            allow_multiple_labels_per_net: false,
            default_substrate_net: options.default_substrate_nets.get(&structure.name).copied(),
            ..Default::default()
        },
        backend,
    )
    .map_err(|error| {
        let kind = match error.kind {
            super::detailed_extract::DetailedExtractionErrorKind::AmbiguousText => {
                GdsHierarchyAdapterErrorKind::AmbiguousEvidence
            }
            super::detailed_extract::DetailedExtractionErrorKind::MissingPort
            | super::detailed_extract::DetailedExtractionErrorKind::UnattachedText => {
                GdsHierarchyAdapterErrorKind::MissingEvidence
            }
            super::detailed_extract::DetailedExtractionErrorKind::LabelConflict => {
                GdsHierarchyAdapterErrorKind::ConflictingEvidence
            }
            super::detailed_extract::DetailedExtractionErrorKind::UnsupportedGeometry => {
                GdsHierarchyAdapterErrorKind::Unsupported
            }
            _ => GdsHierarchyAdapterErrorKind::Extraction,
        };
        GdsHierarchyAdapterError::new(
            kind,
            &structure.name,
            None,
            error.hierarchy_path,
            error.message,
        )
    })?;

    // Electrical identity uses the configured spelling; raw TEXT spelling stays
    // in labels/provenance. This prevents `P` vs `p` from changing hierarchy keys.
    for identity in detailed.nets.values_mut() {
        let mut canonical_ports = BTreeMap::new();
        for (observed, direction) in &identity.ports {
            let Some(configured) = ports
                .keys()
                .find(|name| name.eq_ignore_ascii_case(observed))
            else {
                return Err(GdsHierarchyAdapterError::cell(
                    GdsHierarchyAdapterErrorKind::Extraction,
                    &structure.name,
                    format!("extracted port `{observed}` has no canonical configuration"),
                ));
            };
            canonical_ports.insert(configured.clone(), *direction);
        }
        identity.ports = canonical_ports;
        let mut canonical_globals = BTreeSet::new();
        for observed in &identity.globals {
            let Some(configured) = options
                .global_names
                .iter()
                .chain(deck.global_nets.iter())
                .find(|name| name.eq_ignore_ascii_case(observed))
            else {
                return Err(GdsHierarchyAdapterError::cell(
                    GdsHierarchyAdapterErrorKind::Extraction,
                    &structure.name,
                    format!("extracted global `{observed}` has no canonical configuration"),
                ));
            };
            canonical_globals.insert(configured.clone());
        }
        identity.globals = canonical_globals;
    }

    // A repeated label on disconnected nets is ambiguous adapter evidence, not a
    // soft/open hint that may be guessed through hierarchy.
    let mut nets_by_label = BTreeMap::<String, BTreeSet<u32>>::new();
    for (&net, identity) in &detailed.nets {
        for label in &identity.labels {
            nets_by_label
                .entry(label.to_ascii_lowercase())
                .or_default()
                .insert(net);
        }
    }
    if let Some((label, nets)) = nets_by_label.iter().find(|(_, nets)| nets.len() != 1) {
        return Err(GdsHierarchyAdapterError::cell(
            GdsHierarchyAdapterErrorKind::AmbiguousEvidence,
            &structure.name,
            format!("label `{label}` resolves to multiple local nets {nets:?}"),
        ));
    }

    let sources = source_sets_by_net(&raw.net_of_poly, &source_shapes);
    let names = stable_net_names(&structure.name, &detailed, &sources)?;
    if raw.net_of_poly.len() != source_shapes.len() {
        return Err(GdsHierarchyAdapterError::cell(
            GdsHierarchyAdapterErrorKind::Extraction,
            &structure.name,
            format!(
                "extractor returned {} polygon-net identities for {} source shapes",
                raw.net_of_poly.len(),
                source_shapes.len()
            ),
        ));
    }
    for (polygon, source) in source_shapes.iter().enumerate() {
        let object = provenance
            .objects
            .get_mut(&source.stable_id)
            .ok_or_else(|| {
                GdsHierarchyAdapterError::cell(
                    GdsHierarchyAdapterErrorKind::Extraction,
                    &structure.name,
                    format!(
                        "source shape `{}` has no provenance object",
                        source.stable_id
                    ),
                )
            })?;
        let raw_net = raw.net_of_poly[polygon];
        if raw_net == u32::MAX {
            if !object.properties.is_empty() {
                return Err(GdsHierarchyAdapterError::new(
                    GdsHierarchyAdapterErrorKind::Unsupported,
                    &structure.name,
                    Some(object.element_index),
                    object.hierarchy_path.clone(),
                    "property-bearing source geometry is not a conductor and cannot be linked to an electrical identity; properties remain uninterpreted",
                ));
            }
            continue;
        }
        let name = names.get(&raw_net).ok_or_else(|| {
            GdsHierarchyAdapterError::new(
                GdsHierarchyAdapterErrorKind::Extraction,
                &structure.name,
                Some(object.element_index),
                object.hierarchy_path.clone(),
                format!("conductor net {raw_net} has no stable electrical identity"),
            )
        })?;
        match &object.local_net {
            None => object.local_net = Some(name.clone()),
            Some(existing) if existing == name => {}
            Some(existing) => {
                return Err(GdsHierarchyAdapterError::new(
                    GdsHierarchyAdapterErrorKind::AmbiguousEvidence,
                    &structure.name,
                    Some(object.element_index),
                    object.hierarchy_path.clone(),
                    format!(
                        "one GDS source object resolves to multiple electrical identities `{existing}` and `{name}`"
                    ),
                ));
            }
        }
    }
    let netlist = stringify_netlist(
        &structure.name,
        &detailed,
        &names,
        &sources,
        &device_sources,
        &source_shapes,
    )?;

    let mut net_shapes = Vec::new();
    for (polygon, &net) in raw.net_of_poly.iter().enumerate() {
        if net == u32::MAX {
            continue;
        }
        let Some(source) = source_shapes.get(polygon) else {
            continue;
        };
        let Some(name) = names.get(&net) else {
            continue;
        };
        net_shapes.push(NetShape {
            net: name.clone(),
            layer: source.layer,
            ring: source.ring.clone(),
        });
    }
    let mut port_access = BTreeMap::<String, Vec<NetShape>>::new();
    for (&net, identity) in &detailed.nets {
        for port in identity.ports.keys() {
            let access = net_shapes
                .iter()
                .filter(|shape| shape.net == names[&net])
                .cloned()
                .collect::<Vec<_>>();
            if access.is_empty() {
                return Err(GdsHierarchyAdapterError::cell(
                    GdsHierarchyAdapterErrorKind::MissingEvidence,
                    &structure.name,
                    format!("port `{port}` has no conductor access geometry"),
                ));
            }
            port_access.insert(port.clone(), access);
        }
    }

    for (text_index, element_index) in text_elements.into_iter().enumerate() {
        let label = &store.text_string[text_index];
        let matches = netlist
            .nets
            .iter()
            .filter(|(_, identity)| {
                identity
                    .labels
                    .iter()
                    .any(|name| name.eq_ignore_ascii_case(label))
            })
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(GdsHierarchyAdapterError::element(
                if matches.is_empty() {
                    GdsHierarchyAdapterErrorKind::MissingEvidence
                } else {
                    GdsHierarchyAdapterErrorKind::AmbiguousEvidence
                },
                &structure.name,
                element_index,
                format!("TEXT label `{label}` resolves to {} nets", matches.len()),
            ));
        }
        if let Some(object) =
            provenance
                .objects
                .get_mut(&source_id(&structure.name, element_index, 0))
        {
            object.local_net = Some(matches[0].clone());
        }
    }

    Ok(LocalCell {
        netlist,
        ports: ports.keys().cloned().collect(),
        port_access,
        net_shapes,
    })
}

fn validate_options(
    library: &GdsLibrary,
    deck: &Deck,
    options: &GdsHierarchyAdapterOptions,
) -> Result<(), GdsHierarchyAdapterError> {
    let envelope = library.envelope;
    if !(envelope.header
        && envelope.bgnlib
        && envelope.libname
        && envelope.units
        && envelope.endlib)
    {
        return Err(GdsHierarchyAdapterError::cell(
            GdsHierarchyAdapterErrorKind::Unsupported,
            &options.top_cell,
            "production hierarchy adaptation requires a complete strict GDS envelope including UNITS",
        ));
    }
    let gds_dbu_nm = library.units.meters_per_database_unit * 1.0e9;
    if !gds_dbu_nm.is_finite()
        || gds_dbu_nm <= 0.0
        || !deck.dbu_nm.is_finite()
        || deck.dbu_nm <= 0.0
        || (gds_dbu_nm - deck.dbu_nm).abs()
            > 1.0e-12 * gds_dbu_nm.abs().max(deck.dbu_nm.abs()).max(1.0)
    {
        return Err(GdsHierarchyAdapterError::cell(
            GdsHierarchyAdapterErrorKind::ConflictingEvidence,
            &options.top_cell,
            format!(
                "GDS database unit {gds_dbu_nm} nm conflicts with deck DBU {} nm",
                deck.dbu_nm
            ),
        ));
    }
    if !library.unhandled_records.is_empty() {
        return Err(GdsHierarchyAdapterError::cell(
            GdsHierarchyAdapterErrorKind::Unsupported,
            &options.top_cell,
            "library contains unhandled GDS records with no electrical semantics",
        ));
    }
    if options.top_cell.trim().is_empty() {
        return Err(GdsHierarchyAdapterError::cell(
            GdsHierarchyAdapterErrorKind::InvalidOptions,
            "<options>",
            "top_cell must not be empty",
        ));
    }
    if options.max_array_copies == 0
        || options.max_hierarchy_expanded_instances == 0
        || options.max_hierarchy_depth == 0
        || options.max_physical_flatten_visits == 0
    {
        return Err(GdsHierarchyAdapterError::cell(
            GdsHierarchyAdapterErrorKind::InvalidOptions,
            &options.top_cell,
            "array, expanded-hierarchy, and hierarchy-depth limits must be positive",
        ));
    }
    let cells: HashSet<&str> = library
        .structures
        .iter()
        .map(|structure| structure.name.as_str())
        .collect();
    if !cells.contains(options.top_cell.as_str()) {
        return Err(GdsHierarchyAdapterError::cell(
            GdsHierarchyAdapterErrorKind::UndefinedCell,
            &options.top_cell,
            "configured top cell is undefined",
        ));
    }
    let mut folded_cells = BTreeMap::<String, String>::new();
    for structure in &library.structures {
        let folded = structure.name.to_ascii_lowercase();
        if let Some(previous) = folded_cells.insert(folded, structure.name.clone()) {
            return Err(GdsHierarchyAdapterError::cell(
                GdsHierarchyAdapterErrorKind::ConflictingEvidence,
                &structure.name,
                format!(
                    "GDS structure names `{previous}` and `{}` collide case-insensitively",
                    structure.name
                ),
            ));
        }
    }
    for (cell, ports) in &options.cell_ports {
        if !cells.contains(cell.as_str()) {
            return Err(GdsHierarchyAdapterError::cell(
                GdsHierarchyAdapterErrorKind::InvalidOptions,
                cell,
                "port configuration names an undefined or non-canonical GDS structure",
            ));
        }
        let mut folded_ports = BTreeSet::new();
        for port in ports.keys() {
            if port.is_empty()
                || port.trim() != port
                || !folded_ports.insert(port.to_ascii_lowercase())
            {
                return Err(GdsHierarchyAdapterError::cell(
                    GdsHierarchyAdapterErrorKind::InvalidOptions,
                    cell,
                    format!("port `{port}` is empty, whitespace-padded, or case-duplicate"),
                ));
            }
        }
    }
    let mut folded_globals = BTreeSet::new();
    for global in &options.global_names {
        if global.is_empty()
            || global.trim() != global
            || !folded_globals.insert(global.to_ascii_lowercase())
        {
            return Err(GdsHierarchyAdapterError::cell(
                GdsHierarchyAdapterErrorKind::InvalidOptions,
                &options.top_cell,
                format!("global `{global}` is empty, whitespace-padded, or case-duplicate"),
            ));
        }
    }
    let mut text_pairs = HashSet::new();
    for rule in &options.text_evidence {
        if !text_pairs.insert((rule.layer, rule.datatype)) {
            return Err(GdsHierarchyAdapterError::cell(
                GdsHierarchyAdapterErrorKind::InvalidOptions,
                &options.top_cell,
                format!(
                    "duplicate TEXT evidence rule ({}, {})",
                    rule.layer, rule.datatype
                ),
            ));
        }
        if !rule.use_string && rule.label_property_attributes.is_empty() {
            return Err(GdsHierarchyAdapterError::cell(
                GdsHierarchyAdapterErrorKind::InvalidOptions,
                &options.top_cell,
                "TEXT evidence rule accepts neither string nor property",
            ));
        }
    }
    let mut folded_black_boxes = BTreeSet::new();
    for (name, black_box) in &options.black_boxes {
        if name.trim().is_empty() || black_box.ports.is_empty() {
            return Err(GdsHierarchyAdapterError::cell(
                GdsHierarchyAdapterErrorKind::InvalidOptions,
                &options.top_cell,
                format!("black box `{name}` requires a nonempty complete port map"),
            ));
        }
        if name.trim() != name || !folded_black_boxes.insert(name.to_ascii_lowercase()) {
            return Err(GdsHierarchyAdapterError::cell(
                GdsHierarchyAdapterErrorKind::InvalidOptions,
                &options.top_cell,
                format!("black box `{name}` is whitespace-padded or case-duplicate"),
            ));
        }
        let folded = black_box
            .ports
            .iter()
            .map(|port| port.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        if folded.len() != black_box.ports.len()
            || black_box
                .ports
                .iter()
                .any(|port| port.is_empty() || port.trim() != port)
        {
            return Err(GdsHierarchyAdapterError::cell(
                GdsHierarchyAdapterErrorKind::InvalidOptions,
                &options.top_cell,
                format!("black box `{name}` has empty/duplicate ports"),
            ));
        }
    }
    for (layout, reference) in &options.equated_cells {
        if !cells.contains(layout.as_str()) || reference.trim().is_empty() {
            return Err(GdsHierarchyAdapterError::cell(
                GdsHierarchyAdapterErrorKind::InvalidOptions,
                layout,
                "equated-cell declaration has undefined layout cell or empty reference cell",
            ));
        }
    }
    Ok(())
}

fn black_box<'a>(
    options: &'a GdsHierarchyAdapterOptions,
    target: &str,
) -> Option<&'a GdsBlackBoxAdapterSpec> {
    options
        .black_boxes
        .iter()
        .find_map(|(name, spec)| name.eq_ignore_ascii_case(target).then_some(spec))
}

fn parse_explicit_bindings(
    cell: &str,
    element: usize,
    meta: &GdsElementMeta,
    accepted: &BTreeSet<i16>,
) -> Result<BTreeMap<String, String>, GdsHierarchyAdapterError> {
    let mut bindings = BTreeMap::new();
    for property in &meta.properties {
        if !accepted.contains(&property.attribute) {
            continue;
        }
        let mut pieces = property.value.split('=');
        let child = pieces.next().unwrap_or("").trim();
        let parent = pieces.next().unwrap_or("").trim();
        if child.is_empty() || parent.is_empty() || pieces.next().is_some() {
            return Err(GdsHierarchyAdapterError::element(
                GdsHierarchyAdapterErrorKind::ConflictingEvidence,
                cell,
                element,
                format!(
                    "instance property {} must be exactly `child_port=parent_net_name`",
                    property.attribute
                ),
            ));
        }
        let folded = child.to_ascii_lowercase();
        if bindings
            .keys()
            .any(|existing: &String| existing.eq_ignore_ascii_case(child))
        {
            return Err(GdsHierarchyAdapterError::element(
                GdsHierarchyAdapterErrorKind::ConflictingEvidence,
                cell,
                element,
                format!("duplicate explicit binding for child port `{folded}`"),
            ));
        }
        bindings.insert(child.to_string(), parent.to_string());
    }
    Ok(bindings)
}

fn lookup_parent_net(
    cell: &str,
    element: usize,
    local: &LocalCell,
    evidence: &str,
) -> Result<String, GdsHierarchyAdapterError> {
    let matches = local
        .netlist
        .nets
        .iter()
        .filter(|(_, identity)| {
            identity
                .labels
                .iter()
                .chain(identity.ports.keys())
                .chain(identity.globals.iter())
                .any(|name| name.eq_ignore_ascii_case(evidence))
        })
        .map(|(name, _)| name.clone())
        .collect::<BTreeSet<_>>();
    match matches.len() {
        1 => Ok(matches.into_iter().next().unwrap()),
        0 => Err(GdsHierarchyAdapterError::element(
            GdsHierarchyAdapterErrorKind::MissingEvidence,
            cell,
            element,
            format!("explicit parent net evidence `{evidence}` was not found"),
        )),
        _ => Err(GdsHierarchyAdapterError::element(
            GdsHierarchyAdapterErrorKind::AmbiguousEvidence,
            cell,
            element,
            format!("explicit parent net evidence `{evidence}` is ambiguous: {matches:?}"),
        )),
    }
}

fn transform_for(
    cell: &str,
    element: usize,
    transform: GdsTransform,
    origin: Point,
) -> Result<HierTransform, GdsHierarchyAdapterError> {
    if transform.absolute_angle
        || transform.absolute_magnification
        || transform.reserved_bits != 0
        || transform
            .magnification
            .is_some_and(|magnification| (magnification - 1.0).abs() > 1.0e-12)
    {
        return Err(GdsHierarchyAdapterError::element(
            GdsHierarchyAdapterErrorKind::Unsupported,
            cell,
            element,
            "absolute/reserved/non-unit-magnification transform has no W4 HierTransform representation",
        ));
    }
    let angle = transform.angle_degrees().rem_euclid(360.0);
    let quarter = (angle / 90.0).round();
    if (angle - quarter * 90.0).abs() > 1.0e-12 {
        return Err(GdsHierarchyAdapterError::element(
            GdsHierarchyAdapterErrorKind::Unsupported,
            cell,
            element,
            format!(
                "non-orthogonal transform angle {}",
                transform.angle_degrees()
            ),
        ));
    }
    let (rxx, rxy, ryx, ryy) = match (quarter as i64).rem_euclid(4) {
        0 => (1, 0, 0, 1),
        1 => (0, -1, 1, 0),
        2 => (-1, 0, 0, -1),
        _ => (0, 1, -1, 0),
    };
    let mirror_y = if transform.reflected { -1 } else { 1 };
    Ok(HierTransform {
        xx: rxx,
        xy: rxy * mirror_y,
        yx: ryx,
        yy: ryy * mirror_y,
        dx: i64::from(origin.x),
        dy: i64::from(origin.y),
    })
}

fn apply_transform(
    cell: &str,
    element: usize,
    transform: HierTransform,
    offset: (i64, i64),
    ring: &Ring,
) -> Result<Ring, GdsHierarchyAdapterError> {
    let points = ring
        .vertices()
        .iter()
        .map(|point| {
            let x = i64::from(transform.xx) * i64::from(point.x)
                + i64::from(transform.xy) * i64::from(point.y)
                + transform.dx
                + offset.0;
            let y = i64::from(transform.yx) * i64::from(point.x)
                + i64::from(transform.yy) * i64::from(point.y)
                + transform.dy
                + offset.1;
            Ok(Point::new(
                i32::try_from(x).map_err(|_| {
                    GdsHierarchyAdapterError::element(
                        GdsHierarchyAdapterErrorKind::Unsupported,
                        cell,
                        element,
                        "transformed port access x is outside integer GDS coordinates",
                    )
                })?,
                i32::try_from(y).map_err(|_| {
                    GdsHierarchyAdapterError::element(
                        GdsHierarchyAdapterErrorKind::Unsupported,
                        cell,
                        element,
                        "transformed port access y is outside integer GDS coordinates",
                    )
                })?,
            ))
        })
        .collect::<Result<Vec<_>, GdsHierarchyAdapterError>>()?;
    Ring::new(points).map_err(|error| {
        GdsHierarchyAdapterError::element(
            GdsHierarchyAdapterErrorKind::Unsupported,
            cell,
            element,
            format!("transformed port access is invalid: {error}"),
        )
    })
}

fn geometric_candidates(
    cell: &str,
    element: usize,
    access: &[NetShape],
    parent: &LocalCell,
    transform: HierTransform,
    offset: (i64, i64),
    allow_boundary: bool,
) -> Result<BTreeSet<String>, GdsHierarchyAdapterError> {
    let mut candidates = BTreeSet::new();
    for child in access {
        let transformed = apply_transform(cell, element, transform, offset, &child.ring)?;
        for parent_shape in &parent.net_shapes {
            if child.layer != parent_shape.layer {
                continue;
            }
            let contact = classify_polygon_contact(&transformed, &parent_shape.ring);
            if contact == PolygonContact::AreaOverlap
                || (allow_boundary && contact == PolygonContact::Touch)
            {
                candidates.insert(parent_shape.net.clone());
            }
        }
    }
    Ok(candidates)
}

fn geometric_binding(
    cell: &str,
    element: usize,
    port: &str,
    access: &[NetShape],
    parent: &LocalCell,
    transform: HierTransform,
    offset: (i64, i64),
    allow_boundary: bool,
) -> Result<String, GdsHierarchyAdapterError> {
    let candidates = geometric_candidates(
        cell,
        element,
        access,
        parent,
        transform,
        offset,
        allow_boundary,
    )?;
    match candidates.len() {
        1 => Ok(candidates.into_iter().next().unwrap()),
        0 => Err(GdsHierarchyAdapterError::element(
            GdsHierarchyAdapterErrorKind::MissingEvidence,
            cell,
            element,
            format!("child port `{port}` has no exact contact with a parent conductor net"),
        )),
        _ => Err(GdsHierarchyAdapterError::element(
            GdsHierarchyAdapterErrorKind::AmbiguousEvidence,
            cell,
            element,
            format!("child port `{port}` contacts multiple parent nets {candidates:?}"),
        )),
    }
}

fn build_instance(
    parent_structure: &GdsStructure,
    element_index: usize,
    target: &str,
    transform: GdsTransform,
    origin: Point,
    array: HierArray,
    meta: &GdsElementMeta,
    parent: &LocalCell,
    locals: &BTreeMap<String, LocalCell>,
    options: &GdsHierarchyAdapterOptions,
) -> Result<HierLayoutInstance, GdsHierarchyAdapterError> {
    let bb = black_box(options, target);
    let (ports, access) = if let Some(spec) = bb {
        (spec.ports.clone(), None)
    } else {
        let child = locals.get(target).ok_or_else(|| {
            GdsHierarchyAdapterError::element(
                GdsHierarchyAdapterErrorKind::UndefinedCell,
                &parent_structure.name,
                element_index,
                format!("instance target `{target}` is undefined and not a configured black box"),
            )
        })?;
        (child.ports.clone(), Some(&child.port_access))
    };
    let explicit = parse_explicit_bindings(
        &parent_structure.name,
        element_index,
        meta,
        &options.instance_binding_property_attributes,
    )?;
    for explicit_port in explicit.keys() {
        if !ports
            .iter()
            .any(|port| port.eq_ignore_ascii_case(explicit_port))
        {
            return Err(GdsHierarchyAdapterError::element(
                GdsHierarchyAdapterErrorKind::ConflictingEvidence,
                &parent_structure.name,
                element_index,
                format!("explicit binding names unknown child port `{explicit_port}`"),
            ));
        }
    }
    if bb.is_some()
        && ports.iter().any(|port| {
            !explicit
                .keys()
                .any(|candidate| candidate.eq_ignore_ascii_case(port))
        })
    {
        return Err(GdsHierarchyAdapterError::element(
            GdsHierarchyAdapterErrorKind::MissingEvidence,
            &parent_structure.name,
            element_index,
            "black-box instance requires an explicit property binding for every declared port",
        ));
    }
    let transform = transform_for(&parent_structure.name, element_index, transform, origin)?;
    let copies = usize::try_from(array.columns)
        .ok()
        .and_then(|columns| {
            usize::try_from(array.rows)
                .ok()
                .and_then(|rows| columns.checked_mul(rows))
        })
        .ok_or_else(|| {
            GdsHierarchyAdapterError::element(
                GdsHierarchyAdapterErrorKind::CapacityExceeded,
                &parent_structure.name,
                element_index,
                "array copy count overflow",
            )
        })?;
    if copies == 0 || copies > options.max_array_copies {
        return Err(GdsHierarchyAdapterError::element(
            GdsHierarchyAdapterErrorKind::CapacityExceeded,
            &parent_structure.name,
            element_index,
            format!(
                "array has {copies} copies; configured limit is {}",
                options.max_array_copies
            ),
        ));
    }
    let mut canonical_bindings: Option<Vec<(String, String)>> = None;
    for column in 0..array.columns {
        for row in 0..array.rows {
            let offset = (
                i64::from(column) * array.column_step.0 + i64::from(row) * array.row_step.0,
                i64::from(column) * array.column_step.1 + i64::from(row) * array.row_step.1,
            );
            let mut bindings = Vec::new();
            for port in &ports {
                let parent_net = if let Some(parent_name) = explicit
                    .iter()
                    .find_map(|(child, parent)| child.eq_ignore_ascii_case(port).then_some(parent))
                {
                    let explicit_net = lookup_parent_net(
                        &parent_structure.name,
                        element_index,
                        parent,
                        parent_name,
                    )?;
                    if let Some(port_access) = access.and_then(|access| {
                        access.iter().find_map(|(name, shapes)| {
                            name.eq_ignore_ascii_case(port).then_some(shapes)
                        })
                    }) {
                        let physical = geometric_candidates(
                            &parent_structure.name,
                            element_index,
                            port_access,
                            parent,
                            transform,
                            offset,
                            options.allow_boundary_port_contact,
                        )?;
                        if !physical.is_empty()
                            && (physical.len() != 1 || !physical.contains(&explicit_net))
                        {
                            return Err(GdsHierarchyAdapterError::element(
                                GdsHierarchyAdapterErrorKind::ConflictingEvidence,
                                &parent_structure.name,
                                element_index,
                                format!(
                                    "explicit binding `{port}={parent_name}` resolves to `{explicit_net}` but exact access geometry contacts {physical:?} at AREF copy [{column},{row}]"
                                ),
                            ));
                        }
                    }
                    explicit_net
                } else {
                    let access = access
                        .and_then(|access| {
                            access.iter().find_map(|(name, shapes)| {
                                name.eq_ignore_ascii_case(port).then_some(shapes)
                            })
                        })
                        .ok_or_else(|| {
                            GdsHierarchyAdapterError::element(
                                GdsHierarchyAdapterErrorKind::MissingEvidence,
                                &parent_structure.name,
                                element_index,
                                format!("child port `{port}` has no access geometry"),
                            )
                        })?;
                    geometric_binding(
                        &parent_structure.name,
                        element_index,
                        port,
                        access,
                        parent,
                        transform,
                        offset,
                        options.allow_boundary_port_contact,
                    )?
                };
                bindings.push((port.clone(), parent_net));
            }
            if let Some(canonical) = &canonical_bindings {
                if canonical != &bindings {
                    return Err(GdsHierarchyAdapterError::element(
                        GdsHierarchyAdapterErrorKind::ConflictingEvidence,
                        &parent_structure.name,
                        element_index,
                        format!(
                            "AREF copies produce different port maps; W4 HierLayout stores one map per array: first {canonical:?}, copy [{column},{row}] {bindings:?}"
                        ),
                    ));
                }
            } else {
                canonical_bindings = Some(bindings);
            }
        }
    }
    Ok(HierLayoutInstance {
        stable_id: format!("gds:{}:E{element_index}", parent_structure.name),
        target_cell: target.to_string(),
        port_bindings: canonical_bindings.unwrap_or_default(),
        transform,
        array,
        black_box: bb.is_some(),
    })
}

fn array_for(
    cell: &str,
    element: usize,
    reference: &crate::gds::GdsArrayReference,
) -> Result<HierArray, GdsHierarchyAdapterError> {
    if reference.columns == 0 || reference.rows == 0 {
        return Err(GdsHierarchyAdapterError::element(
            GdsHierarchyAdapterErrorKind::ConflictingEvidence,
            cell,
            element,
            format!(
                "AREF dimensions must be positive, got {} columns x {} rows",
                reference.columns, reference.rows
            ),
        ));
    }
    let pitch = |endpoint: i32, origin: i32, count: u16, axis: &str| {
        exact_pitch(endpoint, origin, count, axis)
            .map(i64::from)
            .map_err(|error| {
                GdsHierarchyAdapterError::element(
                    GdsHierarchyAdapterErrorKind::Unsupported,
                    cell,
                    element,
                    error.to_string(),
                )
            })
    };
    Ok(HierArray {
        columns: u32::from(reference.columns),
        rows: u32::from(reference.rows),
        column_step: (
            pitch(
                reference.column_endpoint.x,
                reference.origin.x,
                reference.columns,
                "column x",
            )?,
            pitch(
                reference.column_endpoint.y,
                reference.origin.y,
                reference.columns,
                "column y",
            )?,
        ),
        row_step: (
            pitch(
                reference.row_endpoint.x,
                reference.origin.x,
                reference.rows,
                "row x",
            )?,
            pitch(
                reference.row_endpoint.y,
                reference.origin.y,
                reference.rows,
                "row y",
            )?,
        ),
    })
}

fn selected_top_nonopaque_structures(
    library: &GdsLibrary,
    options: &GdsHierarchyAdapterOptions,
) -> Result<BTreeSet<String>, GdsHierarchyAdapterError> {
    #[derive(Debug)]
    struct Frame {
        cell: String,
        next_element: usize,
    }

    let by_name = library
        .structures
        .iter()
        .map(|structure| (structure.name.as_str(), structure))
        .collect::<BTreeMap<_, _>>();
    let depth_limit = options
        .max_hierarchy_depth
        .min(GDS_ADAPTER_MAX_STACK_SAFE_DEPTH);
    let mut colors = BTreeMap::<String, u8>::new();
    colors.insert(options.top_cell.clone(), 1);
    let mut stack = vec![Frame {
        cell: options.top_cell.clone(),
        next_element: 0,
    }];
    let mut postorder = Vec::new();
    while !stack.is_empty() {
        let depth = stack.len();
        let current = stack.last().unwrap().cell.clone();
        if depth > depth_limit {
            let path = stack
                .iter()
                .map(|frame| frame.cell.clone())
                .collect::<Vec<_>>();
            return Err(GdsHierarchyAdapterError::cell(
                GdsHierarchyAdapterErrorKind::CapacityExceeded,
                &current,
                format!(
                    "selected-top hierarchy depth {depth} exceeds stack-safe/configured limit {depth_limit} along {}",
                    path.join(" -> ")
                ),
            ));
        }
        let structure = by_name.get(current.as_str()).ok_or_else(|| {
            GdsHierarchyAdapterError::cell(
                GdsHierarchyAdapterErrorKind::UndefinedCell,
                &current,
                "selected-top hierarchy references an undefined nonopaque cell",
            )
        })?;
        if !structure.unhandled_records.is_empty() {
            return Err(GdsHierarchyAdapterError::cell(
                GdsHierarchyAdapterErrorKind::Unsupported,
                &current,
                "reachable nonopaque structure contains unhandled GDS records",
            ));
        }
        let next = stack.last().unwrap().next_element;
        if next == structure.elements.len() {
            let completed = stack.pop().unwrap().cell;
            colors.insert(completed.clone(), 2);
            postorder.push(completed);
            continue;
        }
        let element = &structure.elements[next];
        stack.last_mut().unwrap().next_element += 1;
        let target = match element {
            GdsElement::Sref(reference) => Some(reference.structure.as_str()),
            GdsElement::Aref(reference) => {
                if reference.columns == 0 || reference.rows == 0 {
                    return Err(GdsHierarchyAdapterError::element(
                        GdsHierarchyAdapterErrorKind::ConflictingEvidence,
                        &current,
                        next,
                        format!(
                            "AREF dimensions must be positive, got {} columns x {} rows",
                            reference.columns, reference.rows
                        ),
                    ));
                }
                let copies = usize::from(reference.columns)
                    .checked_mul(usize::from(reference.rows))
                    .ok_or_else(|| {
                        GdsHierarchyAdapterError::element(
                            GdsHierarchyAdapterErrorKind::CapacityExceeded,
                            &current,
                            next,
                            "AREF copy count overflow",
                        )
                    })?;
                if copies > options.max_array_copies {
                    return Err(GdsHierarchyAdapterError::element(
                        GdsHierarchyAdapterErrorKind::CapacityExceeded,
                        &current,
                        next,
                        format!(
                            "array has {copies} copies; configured limit is {}",
                            options.max_array_copies
                        ),
                    ));
                }
                Some(reference.structure.as_str())
            }
            _ => None,
        };
        let Some(target) = target else {
            continue;
        };
        if black_box(options, target).is_some() {
            // Configured opaque targets are terminal boundary objects whether
            // or not a body structure exists. Never traverse their descendants.
            continue;
        }
        if !by_name.contains_key(target) {
            return Err(GdsHierarchyAdapterError::element(
                GdsHierarchyAdapterErrorKind::UndefinedCell,
                &current,
                next,
                format!("undefined nonopaque instance target `{target}`"),
            ));
        }
        match colors.get(target).copied().unwrap_or(0) {
            2 => {}
            1 => {
                let mut cycle = stack
                    .iter()
                    .map(|frame| frame.cell.clone())
                    .collect::<Vec<_>>();
                cycle.push(target.to_string());
                return Err(GdsHierarchyAdapterError::element(
                    GdsHierarchyAdapterErrorKind::HierarchyCycle,
                    &current,
                    next,
                    format!("hierarchy cycle: {}", cycle.join(" -> ")),
                ));
            }
            _ => {
                colors.insert(target.to_string(), 1);
                stack.push(Frame {
                    cell: target.to_string(),
                    next_element: 0,
                });
            }
        }
    }

    let mut expanded = BTreeMap::<String, usize>::new();
    for name in &postorder {
        let structure = by_name[name.as_str()];
        let mut total = 0usize;
        for (element_index, element) in structure.elements.iter().enumerate() {
            let (target, copies) = match element {
                GdsElement::Sref(reference) => (reference.structure.as_str(), 1usize),
                GdsElement::Aref(reference) => (
                    reference.structure.as_str(),
                    usize::from(reference.columns)
                        .checked_mul(usize::from(reference.rows))
                        .ok_or_else(|| {
                            GdsHierarchyAdapterError::element(
                                GdsHierarchyAdapterErrorKind::CapacityExceeded,
                                name,
                                element_index,
                                "AREF copy count overflow",
                            )
                        })?,
                ),
                _ => continue,
            };
            let descendants = if black_box(options, target).is_some() {
                0
            } else {
                expanded[target]
            };
            let contribution = copies
                .checked_mul(descendants.checked_add(1).ok_or_else(|| {
                    GdsHierarchyAdapterError::cell(
                        GdsHierarchyAdapterErrorKind::CapacityExceeded,
                        name,
                        "expanded hierarchy count overflow",
                    )
                })?)
                .ok_or_else(|| {
                    GdsHierarchyAdapterError::cell(
                        GdsHierarchyAdapterErrorKind::CapacityExceeded,
                        name,
                        "expanded hierarchy count overflow",
                    )
                })?;
            total = total.checked_add(contribution).ok_or_else(|| {
                GdsHierarchyAdapterError::cell(
                    GdsHierarchyAdapterErrorKind::CapacityExceeded,
                    name,
                    "expanded hierarchy count overflow",
                )
            })?;
            if total > options.max_hierarchy_expanded_instances {
                return Err(GdsHierarchyAdapterError::cell(
                    GdsHierarchyAdapterErrorKind::CapacityExceeded,
                    name,
                    format!(
                        "expanded hierarchy count {total} exceeds configured limit {}",
                        options.max_hierarchy_expanded_instances
                    ),
                ));
            }
        }
        expanded.insert(name.clone(), total);
    }
    Ok(postorder.into_iter().collect())
}

fn validate_adapter_hierarchy(
    layout: &HierLayout,
    options: &GdsHierarchyAdapterOptions,
) -> Result<(), GdsHierarchyAdapterError> {
    #[derive(Debug)]
    struct Frame {
        cell: String,
        next_instance: usize,
    }

    if !layout.cells.contains_key(&layout.top_cell) {
        return Err(GdsHierarchyAdapterError::cell(
            GdsHierarchyAdapterErrorKind::UndefinedCell,
            &layout.top_cell,
            "undefined hierarchy top cell",
        ));
    }
    // 0/absent = white, 1 = active, 2 = complete. This explicit DFS avoids
    // process-stack recursion and visits shared DAG nodes only once.
    let mut colors = BTreeMap::<String, u8>::new();
    colors.insert(layout.top_cell.clone(), 1);
    let mut stack = vec![Frame {
        cell: layout.top_cell.clone(),
        next_instance: 0,
    }];
    let depth_limit = options
        .max_hierarchy_depth
        .min(GDS_ADAPTER_MAX_STACK_SAFE_DEPTH);
    let mut postorder = Vec::new();
    while !stack.is_empty() {
        let depth = stack.len();
        let frame_cell = stack.last().unwrap().cell.clone();
        if depth > depth_limit {
            let path = stack
                .iter()
                .map(|frame| frame.cell.clone())
                .collect::<Vec<_>>();
            return Err(GdsHierarchyAdapterError::cell(
                GdsHierarchyAdapterErrorKind::CapacityExceeded,
                &frame_cell,
                format!(
                    "hierarchy depth {} exceeds stack-safe/configured limit {} along {}",
                    depth,
                    depth_limit,
                    path.join(" -> ")
                ),
            ));
        }
        let cell = layout.cells.get(&frame_cell).ok_or_else(|| {
            GdsHierarchyAdapterError::cell(
                GdsHierarchyAdapterErrorKind::UndefinedCell,
                &frame_cell,
                "undefined hierarchy cell",
            )
        })?;
        let next_instance = stack.last().unwrap().next_instance;
        if next_instance == cell.instances.len() {
            let completed = stack.pop().unwrap().cell;
            colors.insert(completed.clone(), 2);
            postorder.push(completed);
            continue;
        }
        let instance = cell.instances[next_instance].clone();
        stack.last_mut().unwrap().next_instance += 1;
        if instance.black_box {
            continue;
        }
        match colors.get(&instance.target_cell).copied().unwrap_or(0) {
            2 => continue,
            1 => {
                let mut cycle = stack
                    .iter()
                    .map(|frame| frame.cell.clone())
                    .collect::<Vec<_>>();
                cycle.push(instance.target_cell.clone());
                return Err(GdsHierarchyAdapterError::cell(
                    GdsHierarchyAdapterErrorKind::HierarchyCycle,
                    &frame_cell,
                    format!("hierarchy cycle: {}", cycle.join(" -> ")),
                ));
            }
            _ => {
                if !layout.cells.contains_key(&instance.target_cell) {
                    return Err(GdsHierarchyAdapterError::cell(
                        GdsHierarchyAdapterErrorKind::UndefinedCell,
                        &frame_cell,
                        format!("undefined hierarchy cell `{}`", instance.target_cell),
                    ));
                }
                colors.insert(instance.target_cell.clone(), 1);
                stack.push(Frame {
                    cell: instance.target_cell.clone(),
                    next_instance: 0,
                });
            }
        }
    }

    let mut expanded = BTreeMap::<String, usize>::new();
    for name in postorder {
        let cell = &layout.cells[&name];
        let mut total = 0usize;
        for instance in &cell.instances {
            let copies = usize::try_from(instance.array.columns)
                .ok()
                .and_then(|columns| {
                    usize::try_from(instance.array.rows)
                        .ok()
                        .and_then(|rows| columns.checked_mul(rows))
                })
                .ok_or_else(|| {
                    GdsHierarchyAdapterError::cell(
                        GdsHierarchyAdapterErrorKind::CapacityExceeded,
                        &name,
                        format!("instance `{}` copy count overflows", instance.stable_id),
                    )
                })?;
            let descendants = if instance.black_box {
                0
            } else {
                expanded[&instance.target_cell]
            };
            let contribution = copies
                .checked_mul(descendants.checked_add(1).ok_or_else(|| {
                    GdsHierarchyAdapterError::cell(
                        GdsHierarchyAdapterErrorKind::CapacityExceeded,
                        &name,
                        "expanded hierarchy count overflow",
                    )
                })?)
                .ok_or_else(|| {
                    GdsHierarchyAdapterError::cell(
                        GdsHierarchyAdapterErrorKind::CapacityExceeded,
                        &name,
                        "expanded hierarchy count overflow",
                    )
                })?;
            total = total.checked_add(contribution).ok_or_else(|| {
                GdsHierarchyAdapterError::cell(
                    GdsHierarchyAdapterErrorKind::CapacityExceeded,
                    &name,
                    "expanded hierarchy count overflow",
                )
            })?;
            if total > options.max_hierarchy_expanded_instances {
                return Err(GdsHierarchyAdapterError::cell(
                    GdsHierarchyAdapterErrorKind::CapacityExceeded,
                    &name,
                    format!(
                        "expanded hierarchy count {total} exceeds configured limit {}",
                        options.max_hierarchy_expanded_instances
                    ),
                ));
            }
        }
        expanded.insert(name, total);
    }
    Ok(())
}

fn canonical_physical_library(
    library: &GdsLibrary,
    options: &GdsHierarchyAdapterOptions,
    reachable_nonopaque: &BTreeSet<String>,
) -> Result<GdsLibrary, GdsHierarchyAdapterError> {
    let mut canonical = library.clone();
    canonical
        .structures
        .retain(|structure| reachable_nonopaque.contains(&structure.name));
    for structure in &mut canonical.structures {
        let mut retained = Vec::with_capacity(structure.elements.len());
        for (element_index, mut element) in structure.elements.drain(..).enumerate() {
            let opaque_target = match &element {
                GdsElement::Sref(reference) => Some(reference.structure.as_str()),
                GdsElement::Aref(reference) => Some(reference.structure.as_str()),
                _ => None,
            }
            .is_some_and(|target| black_box(options, target).is_some());
            if opaque_target {
                // Opaque interiors are absent from both this physical view and
                // W4's composed view. Surrounding/reachable geometry remains.
                continue;
            }
            if let GdsElement::Text(text) = &mut element {
                let Some(rule) = evidence_rule(options, text.layer, text.text_type) else {
                    if options.reject_unconfigured_text {
                        return Err(GdsHierarchyAdapterError::element(
                            GdsHierarchyAdapterErrorKind::Unsupported,
                            &structure.name,
                            element_index,
                            "physical flatten encountered unconfigured TEXT evidence",
                        ));
                    }
                    // W2 flatten preserves all text. Remove explicitly ignored
                    // annotations so they cannot become accidental physical nets.
                    continue;
                };
                text.string = derive_text_name(&structure.name, element_index, text, rule)?;
            }
            retained.push(element);
        }
        structure.elements = retained;
    }
    Ok(canonical)
}

fn deduplicate_flat_store(
    source: &GeometryStore,
    cell: &str,
) -> Result<GeometryStore, GdsHierarchyAdapterError> {
    let mut out = GeometryStore::new();
    let mut seen = BTreeMap::<(LayerId, Vec<(i32, i32)>), PolyId>::new();
    let mut old_to_new = Vec::with_capacity(source.poly_count());
    for polygon in 0..source.poly_count() {
        let points = source
            .vertices(PolyId(polygon as u32))
            .map(|(x, y)| Point::new(x, y))
            .collect::<Vec<_>>();
        let mut ring = Ring::new(points).map_err(|error| {
            GdsHierarchyAdapterError::cell(
                GdsHierarchyAdapterErrorKind::Extraction,
                cell,
                format!("flattened polygon {polygon} is invalid: {error}"),
            )
        })?;
        if ring.signed_area2() < 0 {
            let mut reversed = ring.vertices().to_vec();
            reversed.reverse();
            ring = Ring::new(reversed).map_err(|error| {
                GdsHierarchyAdapterError::cell(
                    GdsHierarchyAdapterErrorKind::Extraction,
                    cell,
                    format!("flattened polygon {polygon} winding normalization failed: {error}"),
                )
            })?;
        }
        let key = (
            source.poly_layer[polygon],
            ring.vertices()
                .iter()
                .map(|point| (point.x, point.y))
                .collect::<Vec<_>>(),
        );
        let mapped = if let Some(existing) = seen.get(&key) {
            *existing
        } else {
            let created = out.add_polygon_annotated(
                key.0,
                &key.1,
                source.poly_properties[polygon].clone(),
                source.poly_hierarchy_path[polygon].clone(),
            );
            seen.insert(key, created);
            created
        };
        old_to_new.push(mapped);
    }
    for (&old, label) in &source.net_labels {
        let mapped = old_to_new.get(old as usize).ok_or_else(|| {
            GdsHierarchyAdapterError::cell(
                GdsHierarchyAdapterErrorKind::Extraction,
                cell,
                format!("flattened label references missing polygon {old}"),
            )
        })?;
        if let Some(previous) = out.net_labels.insert(mapped.0, label.clone()) {
            if !previous.eq_ignore_ascii_case(label) {
                return Err(GdsHierarchyAdapterError::cell(
                    GdsHierarchyAdapterErrorKind::ConflictingEvidence,
                    cell,
                    format!(
                        "coincident flattened geometry has conflicting labels `{previous}` and `{label}`"
                    ),
                ));
            }
        }
    }
    for index in 0..source.text_count() {
        out.add_text_annotated(
            source.text_layer[index],
            source.text_datatype[index],
            source.text_x[index],
            source.text_y[index],
            source.text_string[index].clone(),
            source.text_properties[index].clone(),
            source.text_hierarchy_path[index].clone(),
        );
    }
    Ok(out)
}

fn validate_physical_equivalence(
    library: &GdsLibrary,
    deck: &Deck,
    options: &GdsHierarchyAdapterOptions,
    backend: Backend,
    layout: &HierLayout,
) -> Result<GdsPhysicalCorrelationStatus, GdsHierarchyAdapterError> {
    let mut opaque = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let mut pending = vec![layout.top_cell.clone()];
    while let Some(cell_name) = pending.pop() {
        if !visited.insert(cell_name.clone()) {
            continue;
        }
        let cell = &layout.cells[&cell_name];
        for instance in &cell.instances {
            if instance.black_box {
                opaque.insert(instance.target_cell.clone());
            } else {
                pending.push(instance.target_cell.clone());
            }
        }
    }
    if options
        .default_substrate_nets
        .contains_key(&options.top_cell)
        && layout.cells.values().any(|cell| !cell.instances.is_empty())
    {
        return Err(GdsHierarchyAdapterError::cell(
            GdsHierarchyAdapterErrorKind::Unsupported,
            &options.top_cell,
            "numeric default-substrate net identity cannot be preserved across physical hierarchy flattening",
        ));
    }

    let reachable_nonopaque = layout.cells.keys().cloned().collect::<BTreeSet<_>>();
    let canonical = canonical_physical_library(library, options, &reachable_nonopaque)?;
    let flattened = flatten_gds_library(
        &canonical,
        &deck.layers,
        &GdsFlattenOptions {
            expansion_limit: options.max_physical_flatten_visits,
            selected_top: Some(options.top_cell.clone()),
            geometry_policy: GdsGeometryPolicy::Strict,
        },
    )
    .map_err(|error| {
        let kind = match error.kind {
            crate::gds::LayoutErrorKind::CapacityExceeded
            | crate::gds::LayoutErrorKind::ArithmeticOverflow => {
                GdsHierarchyAdapterErrorKind::CapacityExceeded
            }
            crate::gds::LayoutErrorKind::UndefinedReference => {
                GdsHierarchyAdapterErrorKind::UndefinedCell
            }
            crate::gds::LayoutErrorKind::HierarchyCycle => {
                GdsHierarchyAdapterErrorKind::HierarchyCycle
            }
            _ => GdsHierarchyAdapterErrorKind::Unsupported,
        };
        GdsHierarchyAdapterError::cell(
            kind,
            &options.top_cell,
            format!("strict physical GDS flatten failed: {error}"),
        )
    })?;
    let store = flattened.cells.get(&options.top_cell).ok_or_else(|| {
        GdsHierarchyAdapterError::cell(
            GdsHierarchyAdapterErrorKind::Extraction,
            &options.top_cell,
            "strict physical flatten did not return the selected top",
        )
    })?;
    let normalized = deduplicate_flat_store(store, &options.top_cell)?;
    let physical = extract_detailed_netlist(
        &normalized,
        deck,
        &DetailedExtractionOptions {
            cell_name: options.top_cell.clone(),
            extract: options.extract.clone(),
            ports: options
                .cell_ports
                .get(&options.top_cell)
                .cloned()
                .unwrap_or_default(),
            globals: options.global_names.clone(),
            require_all_text_attached: true,
            // Hierarchy legitimately creates aliases such as child port `P`
            // attached to parent rail `VDD`; repeated labels on disconnected
            // nets still become explicit open candidates.
            allow_multiple_labels_per_net: true,
            default_substrate_net: options
                .default_substrate_nets
                .get(&options.top_cell)
                .copied(),
            ..Default::default()
        },
        backend,
    )
    .map_err(|error| {
        GdsHierarchyAdapterError::new(
            GdsHierarchyAdapterErrorKind::ConflictingEvidence,
            &options.top_cell,
            None,
            error.hierarchy_path,
            format!("flattened physical extraction failed: {}", error.message),
        )
    })?;
    let composed = flatten_layout(layout).map_err(|message| {
        GdsHierarchyAdapterError::cell(
            GdsHierarchyAdapterErrorKind::Extraction,
            &options.top_cell,
            format!("composed hierarchy flatten failed: {message}"),
        )
    })?;
    let comparison = compare_production(&physical, &composed, &ProductionCompareOptions::default());
    if comparison.status != ProductionLvsStatus::Match {
        let kind = if comparison.status == ProductionLvsStatus::Indeterminate {
            GdsHierarchyAdapterErrorKind::CapacityExceeded
        } else {
            GdsHierarchyAdapterErrorKind::ConflictingEvidence
        };
        return Err(GdsHierarchyAdapterError::cell(
            kind,
            &options.top_cell,
            format!(
                "flattened physical extraction contradicts composed hierarchy: {}; witness {:?}",
                comparison.reason,
                comparison.mismatches.first()
            ),
        ));
    }
    if opaque.is_empty() {
        Ok(GdsPhysicalCorrelationStatus::Correlated)
    } else {
        Ok(GdsPhysicalCorrelationStatus::OpaqueBlackBoxes { cells: opaque })
    }
}

/// Build a hierarchy-preserving W4 layout from the W2 lossless GDS database.
pub fn adapt_gds_hierarchy_to_lvs(
    library: &GdsLibrary,
    deck: &Deck,
    options: &GdsHierarchyAdapterOptions,
    backend: Backend,
) -> Result<GdsHierarchyAdapterResult, GdsHierarchyAdapterError> {
    validate_options(library, deck, options)?;
    // This iterative, selected-top-only audit precedes every local extraction
    // and every remaining recursive W2/W4 consumer.
    let reachable_nonopaque = selected_top_nonopaque_structures(library, options)?;
    let mut provenance = GdsHierarchyProvenance::default();
    let mut locals = BTreeMap::<String, LocalCell>::new();
    for structure in library
        .structures
        .iter()
        .filter(|structure| reachable_nonopaque.contains(&structure.name))
    {
        locals.insert(
            structure.name.clone(),
            build_local_cell(structure, deck, options, backend, &mut provenance)?,
        );
    }
    let mut cells = BTreeMap::new();
    for structure in library
        .structures
        .iter()
        .filter(|structure| reachable_nonopaque.contains(&structure.name))
    {
        let local = &locals[&structure.name];
        let mut instances = Vec::new();
        for (element_index, element) in structure.elements.iter().enumerate() {
            match element {
                GdsElement::Sref(reference) => {
                    instances.push(build_instance(
                        structure,
                        element_index,
                        &reference.structure,
                        reference.transform,
                        reference.origin,
                        HierArray::default(),
                        &reference.meta,
                        local,
                        &locals,
                        options,
                    )?);
                }
                GdsElement::Aref(reference) => {
                    instances.push(build_instance(
                        structure,
                        element_index,
                        &reference.structure,
                        reference.transform,
                        reference.origin,
                        array_for(&structure.name, element_index, reference)?,
                        &reference.meta,
                        local,
                        &locals,
                        options,
                    )?);
                }
                _ => {}
            }
        }
        cells.insert(
            structure.name.clone(),
            HierLayoutCell {
                name: structure.name.clone(),
                ports: local.ports.clone(),
                netlist: local.netlist.clone(),
                instances,
            },
        );
    }
    let layout = HierLayout {
        top_cell: options.top_cell.clone(),
        cells,
    };
    validate_adapter_hierarchy(&layout, options)?;
    let physical_correlation =
        validate_physical_equivalence(library, deck, options, backend, &layout)?;
    Ok(GdsHierarchyAdapterResult {
        layout,
        equated_cells: options.equated_cells.clone(),
        provenance,
        physical_correlation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gds::GdsUnits;
    use crate::gds::{
        read_gds_library, write_gds_library, GdsArrayReference, GdsBoundary, GdsEnvelope, GdsNode,
        GdsPath, GdsReadMode, GdsReference, GdsText,
    };
    use crate::params::{
        ConnectivityConfig, DeviceConfig, ErcParams, LayerDef, LayerTable, MosRule, ResistorRule,
    };
    use crate::schema::PropertyTolerance;
    use crate::{
        bind_reference_hierarchy, compare_hierarchical_production, parse_netlist, ConfiguredModel,
        DeviceFlavor, DeviceKind, HierLvsCache, HierProductionOptions, ProductionLvsStatus,
        ProductionMismatch, ReferenceBindingOptions,
    };
    use std::collections::HashMap;

    fn rect(x0: i32, y0: i32, x1: i32, y1: i32) -> Vec<Point> {
        vec![
            Point::new(x0, y0),
            Point::new(x1, y0),
            Point::new(x1, y1),
            Point::new(x0, y1),
        ]
    }

    fn properties(values: &[(i16, &str)]) -> GdsElementMeta {
        GdsElementMeta {
            properties: values
                .iter()
                .map(|(attribute, value)| GdsProperty {
                    attribute: *attribute,
                    value: (*value).to_string(),
                })
                .collect(),
            ..Default::default()
        }
    }

    fn boundary(
        layer: i16,
        x0: i32,
        y0: i32,
        x1: i32,
        y1: i32,
        meta: GdsElementMeta,
    ) -> GdsElement {
        GdsElement::Boundary(GdsBoundary {
            layer,
            datatype: 0,
            ring: rect(x0, y0, x1, y1),
            meta,
        })
    }

    fn text(layer: i16, x: i32, y: i32, value: &str, meta: GdsElementMeta) -> GdsElement {
        GdsElement::Text(GdsText {
            layer,
            text_type: 99,
            origin: Point::new(x, y),
            string: value.to_string(),
            presentation: None,
            path_type: None,
            width: None,
            transform: GdsTransform::default(),
            meta,
        })
    }

    fn sref(target: &str, x: i32, y: i32, meta: GdsElementMeta) -> GdsElement {
        GdsElement::Sref(GdsReference {
            structure: target.to_string(),
            origin: Point::new(x, y),
            transform: GdsTransform::default(),
            meta,
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

    fn library(structures: Vec<GdsStructure>) -> GdsLibrary {
        GdsLibrary {
            version: 600,
            timestamps: [0; 12],
            name: "adapter-fixture".into(),
            units: GdsUnits {
                user_units_per_database_unit: 1.0e-3,
                meters_per_database_unit: 1.0e-9,
            },
            structures,
            unhandled_records: Vec::new(),
            envelope: GdsEnvelope::complete(),
        }
    }

    /// All adapter tests cross the real writer and strict lossless reader. This
    /// catches record/transform/property regressions that hand-built stores hide.
    fn lossless_round_trip(source: GdsLibrary) -> GdsLibrary {
        let bytes = write_gds_library(&source).expect("write strict GDS fixture");
        read_gds_library(&bytes, GdsReadMode::Strict).expect("read strict GDS fixture")
    }

    fn deck() -> Deck {
        let definitions: HashMap<String, LayerDef> = [
            ("nwell", 1, 0),
            ("diff", 2, 0),
            ("poly", 3, 0),
            ("nsdm", 4, 0),
            ("licon", 5, 0),
            ("met1", 7, 0),
        ]
        .into_iter()
        .map(|(name, layer, datatype)| (name.to_string(), LayerDef { layer, datatype }))
        .collect();
        let layers = LayerTable::from_defs(&definitions);
        let nwell = layers.id("nwell").unwrap();
        let diff = layers.id("diff").unwrap();
        let poly = layers.id("poly").unwrap();
        let nsdm = layers.id("nsdm").unwrap();
        let licon = layers.id("licon").unwrap();
        let met1 = layers.id("met1").unwrap();
        Deck {
            layers,
            drc_rules: Vec::new(),
            pex: HashMap::new(),
            dbu_nm: 1.0,
            lvs_cut_required: true,
            strict: true,
            connectivity: ConnectivityConfig {
                conductors: vec![nwell, diff, poly, met1],
                vias: vec![(licon, vec![diff, met1])],
            },
            devices: DeviceConfig {
                mos_rules: vec![MosRule {
                    name: "nch".into(),
                    gate_layer: poly,
                    channel_layer: diff,
                    type_implant: nsdm,
                    device_type: "nmos".into(),
                    flavor_markers: Vec::new(),
                    well_layer: Some(nwell),
                    device_class: Some("core".into()),
                }],
                ..Default::default()
            },
            w_tolerance: PropertyTolerance::default(),
            l_tolerance: PropertyTolerance::default(),
            fail_on_floating: false,
            intra_layer_touch: false,
            global_nets: Vec::new(),
            erc: ErcParams::default(),
            device_catalog: HashMap::new(),
            pex_method: Default::default(),
        }
    }

    fn five_ports() -> BTreeMap<String, PortDirection> {
        ["S", "D", "G1", "G2", "B"]
            .into_iter()
            .map(|name| (name.to_string(), PortDirection::Inout))
            .collect()
    }

    fn string_evidence_options(top: &str, cells: &[&str]) -> GdsHierarchyAdapterOptions {
        let mut options = GdsHierarchyAdapterOptions::new(top);
        options.extract.cut_required = true;
        options.text_evidence = [1, 3, 7]
            .into_iter()
            .map(|layer| GdsTextEvidenceRule {
                layer,
                datatype: 99,
                use_string: true,
                label_property_attributes: BTreeSet::new(),
            })
            .collect();
        for cell in cells {
            options.cell_ports.insert((*cell).to_string(), five_ports());
        }
        options
    }

    fn series_leaf() -> GdsStructure {
        structure(
            "leaf",
            vec![
                boundary(
                    1,
                    -100,
                    -100,
                    1100,
                    300,
                    properties(&[(100, "well-source")]),
                ),
                boundary(2, 0, 0, 1000, 200, properties(&[(101, "diff-source")])),
                boundary(3, 300, -50, 360, 250, GdsElementMeta::default()),
                boundary(3, 650, -50, 710, 250, GdsElementMeta::default()),
                boundary(4, -50, -50, 1050, 250, GdsElementMeta::default()),
                boundary(7, 50, 50, 200, 150, properties(&[(102, "source-pad")])),
                boundary(5, 80, 70, 170, 130, GdsElementMeta::default()),
                boundary(7, 450, 50, 550, 150, GdsElementMeta::default()),
                boundary(5, 470, 70, 530, 130, GdsElementMeta::default()),
                boundary(7, 800, 50, 950, 150, GdsElementMeta::default()),
                boundary(5, 830, 70, 920, 130, GdsElementMeta::default()),
                text(1, -50, -50, "B", GdsElementMeta::default()),
                text(7, 100, 100, "S", properties(&[(200, "raw-text-property")])),
                text(7, 875, 100, "D", GdsElementMeta::default()),
                text(3, 330, -25, "G1", GdsElementMeta::default()),
                text(3, 680, -25, "G2", GdsElementMeta::default()),
                text(7, 500, 100, "MID", GdsElementMeta::default()),
            ],
        )
    }

    fn access_cell(name: &str, child: &str) -> GdsStructure {
        structure(
            name,
            vec![
                boundary(1, -100, -100, 1100, 300, GdsElementMeta::default()),
                boundary(7, 50, 50, 200, 150, GdsElementMeta::default()),
                boundary(7, 800, 50, 950, 150, GdsElementMeta::default()),
                boundary(3, 300, -50, 360, 250, GdsElementMeta::default()),
                boundary(3, 650, -50, 710, 250, GdsElementMeta::default()),
                text(1, -50, -50, "B", GdsElementMeta::default()),
                text(7, 100, 100, "S", GdsElementMeta::default()),
                text(7, 875, 100, "D", GdsElementMeta::default()),
                text(3, 330, -25, "G1", GdsElementMeta::default()),
                text(3, 680, -25, "G2", GdsElementMeta::default()),
                sref(child, 0, 0, properties(&[(700, "raw-instance-property")])),
            ],
        )
    }

    fn shifted_top() -> GdsStructure {
        structure(
            "top",
            vec![
                boundary(1, 1900, -100, 3100, 300, GdsElementMeta::default()),
                boundary(7, 2050, 50, 2200, 150, GdsElementMeta::default()),
                boundary(7, 2800, 50, 2950, 150, GdsElementMeta::default()),
                boundary(3, 2300, -50, 2360, 250, GdsElementMeta::default()),
                boundary(3, 2650, -50, 2710, 250, GdsElementMeta::default()),
                text(1, 1950, -50, "B", GdsElementMeta::default()),
                text(7, 2100, 100, "S", GdsElementMeta::default()),
                text(7, 2875, 100, "D", GdsElementMeta::default()),
                text(3, 2330, -25, "G1", GdsElementMeta::default()),
                text(3, 2680, -25, "G2", GdsElementMeta::default()),
                sref("mid", 2000, 0, GdsElementMeta::default()),
            ],
        )
    }

    #[test]
    fn lossless_series_extracts_typed_topology_and_bidirectional_provenance() {
        let library = lossless_round_trip(library(vec![series_leaf()]));
        let adapted = adapt_gds_hierarchy_to_lvs(
            &library,
            &deck(),
            &string_evidence_options("leaf", &["leaf"]),
            Backend::Cpu,
        )
        .expect("adapt series cell");
        let leaf = &adapted.layout.cells["leaf"];
        assert_eq!(leaf.netlist.mos_devices.len(), 2);
        assert!(leaf.instances.is_empty());
        let middle = leaf
            .netlist
            .nets
            .iter()
            .find_map(|(id, net)| net.labels.contains("MID").then_some(id))
            .expect("middle series net");
        assert!(leaf
            .netlist
            .mos_devices
            .iter()
            .all(|device| { &device.drain == middle || &device.source == middle }));

        for device in &leaf.netlist.mos_devices {
            assert!(device.identity.hierarchy_path.0.len() >= 4);
            assert!(device.identity.hierarchy_path.0[0].starts_with("gds:leaf"));
            for source in &device.identity.hierarchy_path.0[1..3] {
                assert!(adapted.provenance.objects.contains_key(source));
            }
            assert!(device.identity.stable_id.contains(":MOS:nch:"));
            assert!(!device.properties.contains_key("raw-text-property"));
        }
        for net in leaf.netlist.nets.values() {
            assert_ne!(net.hierarchy_path, HierarchyPath::root("leaf"));
            assert!(adapted
                .provenance
                .objects
                .contains_key(&net.hierarchy_path.0[1]));
        }
        for object in adapted.provenance.objects.values().filter(|object| {
            matches!(
                object.kind,
                GdsAdapterObjectKind::Boundary | GdsAdapterObjectKind::Path
            ) && !object.properties.is_empty()
        }) {
            let net = object
                .local_net
                .as_ref()
                .expect("property source linked to net");
            assert!(leaf.netlist.nets.contains_key(net));
        }
        let raw_text = adapted
            .provenance
            .objects
            .values()
            .find(|object| object.properties.iter().any(|p| p.attribute == 200))
            .expect("raw TEXT property provenance");
        assert_eq!(raw_text.properties[0].value, "raw-text-property");
        assert!(raw_text.local_net.is_some());

        let unsupported = export_w3_drc_hierarchy_context(&adapted).unwrap_err();
        assert_eq!(unsupported.kind, GdsHierarchyAdapterErrorKind::Unsupported);
        assert!(unsupported
            .message
            .contains("W3 DRC hierarchy/context consumer is absent"));
        assert_eq!(
            adapted.physical_correlation,
            GdsPhysicalCorrelationStatus::Correlated
        );
    }

    #[test]
    fn nested_srefs_preserve_hierarchy_and_produce_qualified_mismatch_witness() {
        let library = lossless_round_trip(library(vec![
            series_leaf(),
            access_cell("mid", "leaf"),
            shifted_top(),
        ]));
        let mut adapted = adapt_gds_hierarchy_to_lvs(
            &library,
            &deck(),
            &string_evidence_options("top", &["leaf", "mid", "top"]),
            Backend::Cpu,
        )
        .expect("adapt nested hierarchy");
        assert_eq!(adapted.layout.cells.len(), 3);
        assert_eq!(adapted.layout.cells["top"].netlist.mos_devices.len(), 0);
        assert_eq!(adapted.layout.cells["mid"].netlist.mos_devices.len(), 0);
        assert_eq!(adapted.layout.cells["leaf"].netlist.mos_devices.len(), 2);
        let top_instance = &adapted.layout.cells["top"].instances[0];
        assert_eq!(top_instance.target_cell, "mid");
        assert_eq!(top_instance.transform.dx, 2000);
        assert_eq!(adapted.layout.cells["mid"].instances[0].target_cell, "leaf");
        assert_eq!(top_instance.port_bindings.len(), 5);
        assert_eq!(
            adapted.layout.cells["mid"].instances[0].port_bindings.len(),
            5
        );

        let spice = ".model nch nmos\n\
.subckt leaf S D G1 G2 B\n\
M0 MID G1 S B nch W=200n L=60n\n\
M1 D G2 MID B nch W=200n L=60n\n\
.ends leaf\n\
.subckt mid S D G1 G2 B\n\
X0 S D G1 G2 B leaf\n\
.ends mid\n\
.subckt top S D G1 G2 B\n\
X0 S D G1 G2 B mid\n\
.ends top\n";
        let ast = parse_netlist("nested.sp", spice).expect("parse reference");
        let mut binding = ReferenceBindingOptions::new("top");
        binding.configured_models.insert(
            "nch".into(),
            ConfiguredModel {
                kind: DeviceKind::Nmos,
                flavor: DeviceFlavor::Standard,
                device_class: Some("core".into()),
            },
        );
        for property in ["W", "L"] {
            binding.property_tolerances.insert(
                property.into(),
                NumericTolerance {
                    absolute: 1.0e-9,
                    relative_percent: 0.0,
                },
            );
        }
        let mut reference = bind_reference_hierarchy(&ast, &binding).expect("bind reference");
        for cell in reference.cells.values_mut() {
            for device in &mut cell.netlist.mos_devices {
                device.well = Some(device.body.clone());
            }
        }
        let mut compare_options = HierProductionOptions::default();
        compare_options.compare.require_exact_property_set = false;
        let clean = compare_hierarchical_production(
            &adapted.layout,
            &reference,
            &compare_options,
            &mut HierLvsCache::default(),
        );
        assert_eq!(clean.status, ProductionLvsStatus::Match, "{clean:#?}");

        let bindings = &mut adapted.layout.cells.get_mut("top").unwrap().instances[0].port_bindings;
        let g1 = bindings
            .iter()
            .find(|(port, _)| port.eq_ignore_ascii_case("G1"))
            .unwrap()
            .1
            .clone();
        let g2 = bindings
            .iter()
            .find(|(port, _)| port.eq_ignore_ascii_case("G2"))
            .unwrap()
            .1
            .clone();
        for (port, net) in bindings {
            if port.eq_ignore_ascii_case("G1") {
                *net = g2.clone();
            } else if port.eq_ignore_ascii_case("G2") {
                *net = g1.clone();
            }
        }
        let bad = compare_hierarchical_production(
            &adapted.layout,
            &reference,
            &compare_options,
            &mut HierLvsCache::default(),
        );
        assert_eq!(bad.status, ProductionLvsStatus::Mismatch);
        let witness = bad
            .flattened
            .mismatches
            .iter()
            .find_map(|mismatch| match mismatch {
                ProductionMismatch::Topology { witness, .. } => Some(witness),
                _ => None,
            })
            .expect("topology witness");
        assert!(
            witness
                .layout_devices
                .iter()
                .any(|device| device.contains("top/gds:top:E")
                    && device.contains("gds:mid:E")
                    && device.contains("gds:leaf")),
            "{witness:#?}"
        );
        assert!(
            witness.hierarchy_paths.iter().any(|path| path
                .0
                .iter()
                .any(|part| part.contains("top/gds:top:E") && part.contains("gds:mid:E"))),
            "{witness:#?}"
        );
    }

    #[test]
    fn aref_globals_property_names_and_exact_path_access_are_preserved() {
        let child = structure(
            "tap",
            vec![
                boundary(7, 0, 0, 50, 50, properties(&[(40, "raw-child-shape")])),
                text(7, 25, 25, "ignored", properties(&[(77, "P")])),
            ],
        );
        let top = structure(
            "array_top",
            vec![
                GdsElement::Path(GdsPath {
                    layer: 7,
                    datatype: 0,
                    centerline: vec![Point::new(0, 25), Point::new(450, 25)],
                    width: Some(100),
                    path_type: Some(0),
                    begin_extension: None,
                    end_extension: None,
                    meta: properties(&[(41, "raw-rail-path")]),
                }),
                text(7, 100, 25, "ignored", properties(&[(77, "RAIL")])),
                GdsElement::Aref(GdsArrayReference {
                    structure: "tap".into(),
                    columns: 2,
                    rows: 1,
                    origin: Point::new(0, 0),
                    column_endpoint: Point::new(400, 0),
                    row_endpoint: Point::new(0, 0),
                    transform: GdsTransform::default(),
                    meta: properties(&[(901, "raw-array-property")]),
                }),
            ],
        );
        let library = lossless_round_trip(library(vec![child, top]));
        let mut options = GdsHierarchyAdapterOptions::new("array_top");
        options.text_evidence.push(GdsTextEvidenceRule {
            layer: 7,
            datatype: 99,
            use_string: false,
            label_property_attributes: BTreeSet::from([77]),
        });
        options.cell_ports.insert(
            "tap".into(),
            BTreeMap::from([("P".into(), PortDirection::Inout)]),
        );
        options.cell_ports.insert(
            "array_top".into(),
            BTreeMap::from([("RAIL".into(), PortDirection::Power)]),
        );
        options.global_names.insert("RAIL".into());
        options
            .equated_cells
            .insert("array_top".into(), "schematic_array_top".into());
        let adapted = adapt_gds_hierarchy_to_lvs(&library, &deck(), &options, Backend::Cpu)
            .expect("adapt exact AREF");
        let instance = &adapted.layout.cells["array_top"].instances[0];
        assert_eq!(instance.target_cell, "tap");
        assert_eq!(instance.array.columns, 2);
        assert_eq!(instance.array.rows, 1);
        assert_eq!(instance.array.column_step, (200, 0));
        assert_eq!(instance.port_bindings, vec![("P".into(), "RAIL".into())]);
        assert!(adapted.layout.cells["array_top"].netlist.nets["RAIL"]
            .globals
            .contains("RAIL"));
        assert_eq!(adapted.equated_cells["array_top"], "schematic_array_top");

        let path = adapted
            .provenance
            .objects
            .values()
            .find(|object| object.kind == GdsAdapterObjectKind::Path)
            .expect("PATH provenance");
        assert_eq!(path.properties[0].value, "raw-rail-path");
        assert_eq!(path.local_net.as_deref(), Some("RAIL"));
        let child_shape = adapted
            .provenance
            .objects
            .values()
            .find(|object| object.properties.iter().any(|p| p.attribute == 40))
            .expect("child shape provenance");
        assert_eq!(child_shape.local_net.as_deref(), Some("P"));
        let array = adapted
            .provenance
            .objects
            .values()
            .find(|object| object.kind == GdsAdapterObjectKind::Aref)
            .expect("AREF provenance");
        assert_eq!(array.properties[0].value, "raw-array-property");
        assert!(array.local_net.is_none());
        assert_eq!(adapted.layout.cells.len(), 2, "hierarchy was not flattened");
    }

    #[test]
    fn missing_conflicting_nonconductive_and_multinet_evidence_fail_typed() {
        let labeled = || {
            lossless_round_trip(library(vec![structure(
                "top",
                vec![
                    boundary(7, 0, 0, 100, 100, GdsElementMeta::default()),
                    text(7, 50, 50, "A", GdsElementMeta::default()),
                ],
            )]))
        };
        let mut missing_options = GdsHierarchyAdapterOptions::new("top");
        missing_options.text_evidence.push(GdsTextEvidenceRule {
            layer: 7,
            datatype: 99,
            use_string: true,
            label_property_attributes: BTreeSet::new(),
        });
        missing_options.cell_ports.insert(
            "top".into(),
            BTreeMap::from([
                ("A".into(), PortDirection::Input),
                ("MISSING".into(), PortDirection::Output),
            ]),
        );
        let missing =
            adapt_gds_hierarchy_to_lvs(&labeled(), &deck(), &missing_options, Backend::Cpu)
                .unwrap_err();
        assert_eq!(missing.kind, GdsHierarchyAdapterErrorKind::MissingEvidence);

        let conflicting_library = lossless_round_trip(library(vec![structure(
            "top",
            vec![
                boundary(7, 0, 0, 100, 100, GdsElementMeta::default()),
                text(7, 50, 50, "A", properties(&[(77, "B")])),
            ],
        )]));
        let mut conflicting_options = GdsHierarchyAdapterOptions::new("top");
        conflicting_options.text_evidence.push(GdsTextEvidenceRule {
            layer: 7,
            datatype: 99,
            use_string: true,
            label_property_attributes: BTreeSet::from([77]),
        });
        let conflicting = adapt_gds_hierarchy_to_lvs(
            &conflicting_library,
            &deck(),
            &conflicting_options,
            Backend::Cpu,
        )
        .unwrap_err();
        assert_eq!(
            conflicting.kind,
            GdsHierarchyAdapterErrorKind::ConflictingEvidence
        );

        let nonconductive_library = lossless_round_trip(library(vec![structure(
            "top",
            vec![boundary(
                4,
                0,
                0,
                100,
                100,
                properties(&[(42, "implant-property")]),
            )],
        )]));
        let nonconductive = adapt_gds_hierarchy_to_lvs(
            &nonconductive_library,
            &deck(),
            &GdsHierarchyAdapterOptions::new("top"),
            Backend::Cpu,
        )
        .unwrap_err();
        assert_eq!(
            nonconductive.kind,
            GdsHierarchyAdapterErrorKind::Unsupported
        );
        assert!(nonconductive.message.contains("not a conductor"));

        let multinet_library = lossless_round_trip(library(vec![structure(
            "top",
            vec![
                boundary(7, 0, 0, 100, 100, GdsElementMeta::default()),
                boundary(7, 100, 0, 200, 100, GdsElementMeta::default()),
                text(7, 100, 50, "AMB", GdsElementMeta::default()),
            ],
        )]));
        let mut multinet_options = GdsHierarchyAdapterOptions::new("top");
        multinet_options.text_evidence.push(GdsTextEvidenceRule {
            layer: 7,
            datatype: 99,
            use_string: true,
            label_property_attributes: BTreeSet::new(),
        });
        let multinet =
            adapt_gds_hierarchy_to_lvs(&multinet_library, &deck(), &multinet_options, Backend::Cpu)
                .unwrap_err();
        assert_eq!(
            multinet.kind,
            GdsHierarchyAdapterErrorKind::AmbiguousEvidence
        );
    }

    #[test]
    fn ambiguous_instance_binding_and_unsupported_transform_fail_closed() {
        let child = structure(
            "child",
            vec![
                boundary(7, 0, 0, 300, 100, GdsElementMeta::default()),
                text(7, 150, 50, "P", GdsElementMeta::default()),
            ],
        );
        let top = structure(
            "top",
            vec![
                boundary(7, 0, 0, 100, 100, GdsElementMeta::default()),
                boundary(7, 200, 0, 300, 100, GdsElementMeta::default()),
                text(7, 50, 50, "A", GdsElementMeta::default()),
                text(7, 250, 50, "B", GdsElementMeta::default()),
                sref("child", 0, 0, GdsElementMeta::default()),
            ],
        );
        let ambiguous_library = lossless_round_trip(library(vec![child, top]));
        let mut options = GdsHierarchyAdapterOptions::new("top");
        options.text_evidence.push(GdsTextEvidenceRule {
            layer: 7,
            datatype: 99,
            use_string: true,
            label_property_attributes: BTreeSet::new(),
        });
        options.cell_ports.insert(
            "child".into(),
            BTreeMap::from([("P".into(), PortDirection::Inout)]),
        );
        let ambiguous =
            adapt_gds_hierarchy_to_lvs(&ambiguous_library, &deck(), &options, Backend::Cpu)
                .unwrap_err();
        assert_eq!(
            ambiguous.kind,
            GdsHierarchyAdapterErrorKind::AmbiguousEvidence
        );
        assert!(ambiguous.message.contains("multiple parent nets"));

        let mut transform_library = library(vec![
            series_leaf(),
            access_cell("mid", "leaf"),
            shifted_top(),
        ]);
        let GdsElement::Sref(reference) = transform_library
            .structures
            .iter_mut()
            .find(|structure| structure.name == "top")
            .unwrap()
            .elements
            .last_mut()
            .unwrap()
        else {
            unreachable!()
        };
        reference.transform.angle_degrees = Some(45.0);
        let transform_library = lossless_round_trip(transform_library);
        let unsupported = adapt_gds_hierarchy_to_lvs(
            &transform_library,
            &deck(),
            &string_evidence_options("top", &["leaf", "mid", "top"]),
            Backend::Cpu,
        )
        .unwrap_err();
        assert_eq!(unsupported.kind, GdsHierarchyAdapterErrorKind::Unsupported);
        assert!(unsupported.message.contains("non-orthogonal transform"));
    }

    #[test]
    fn black_box_requires_complete_configured_property_map() {
        let make_library = |binding: bool| {
            let meta = if binding {
                properties(&[(88, "A=N"), (901, "raw-blackbox-property")])
            } else {
                properties(&[(901, "raw-blackbox-property")])
            };
            lossless_round_trip(library(vec![structure(
                "top",
                vec![
                    boundary(7, 0, 0, 100, 100, GdsElementMeta::default()),
                    text(7, 50, 50, "N", GdsElementMeta::default()),
                    sref("macro", 0, 0, meta),
                ],
            )]))
        };
        let mut options = GdsHierarchyAdapterOptions::new("top");
        options.text_evidence.push(GdsTextEvidenceRule {
            layer: 7,
            datatype: 99,
            use_string: true,
            label_property_attributes: BTreeSet::new(),
        });
        options.cell_ports.insert(
            "top".into(),
            BTreeMap::from([("N".into(), PortDirection::Inout)]),
        );
        options.instance_binding_property_attributes.insert(88);
        options.black_boxes.insert(
            "macro".into(),
            GdsBlackBoxAdapterSpec {
                ports: vec!["A".into()],
            },
        );
        options
            .equated_cells
            .insert("top".into(), "schematic_top".into());

        let missing =
            adapt_gds_hierarchy_to_lvs(&make_library(false), &deck(), &options, Backend::Cpu)
                .unwrap_err();
        assert_eq!(missing.kind, GdsHierarchyAdapterErrorKind::MissingEvidence);
        assert!(missing.message.contains("every declared port"));

        let adapted =
            adapt_gds_hierarchy_to_lvs(&make_library(true), &deck(), &options, Backend::Cpu)
                .expect("explicit black-box map");
        assert_eq!(
            adapted.physical_correlation,
            GdsPhysicalCorrelationStatus::OpaqueBlackBoxes {
                cells: BTreeSet::from(["macro".into()])
            }
        );
        let instance = &adapted.layout.cells["top"].instances[0];
        assert!(instance.black_box);
        assert_eq!(instance.target_cell, "macro");
        assert_eq!(instance.port_bindings, vec![("A".into(), "N".into())]);
        assert_eq!(adapted.equated_cells["top"], "schematic_top");
        let reference = adapted
            .provenance
            .objects
            .values()
            .find(|object| object.kind == GdsAdapterObjectKind::Sref)
            .expect("black-box reference provenance");
        assert_eq!(reference.properties.len(), 2);
        assert!(reference.local_net.is_none());
    }

    #[test]
    fn strict_envelope_and_dbu_are_mandatory() {
        let complete = library(vec![structure("top", Vec::new())]);
        let options = GdsHierarchyAdapterOptions::new("top");

        let mut incomplete = complete.clone();
        incomplete.envelope.units = false;
        let error =
            adapt_gds_hierarchy_to_lvs(&incomplete, &deck(), &options, Backend::Cpu).unwrap_err();
        assert_eq!(error.kind, GdsHierarchyAdapterErrorKind::Unsupported);
        assert!(error.message.contains("complete strict GDS envelope"));

        let mut wrong_dbu = complete;
        wrong_dbu.units.meters_per_database_unit = 2.0e-9;
        let error =
            adapt_gds_hierarchy_to_lvs(&wrong_dbu, &deck(), &options, Backend::Cpu).unwrap_err();
        assert_eq!(
            error.kind,
            GdsHierarchyAdapterErrorKind::ConflictingEvidence
        );
        assert!(error.message.contains("conflicts with deck DBU"));
    }

    #[test]
    fn port_case_is_canonical_and_generated_name_collisions_are_errors() {
        let case_library = lossless_round_trip(library(vec![structure(
            "top",
            vec![
                boundary(7, 0, 0, 100, 100, GdsElementMeta::default()),
                text(7, 50, 50, "P", GdsElementMeta::default()),
            ],
        )]));
        let mut options = GdsHierarchyAdapterOptions::new("top");
        options.text_evidence.push(GdsTextEvidenceRule {
            layer: 7,
            datatype: 99,
            use_string: true,
            label_property_attributes: BTreeSet::new(),
        });
        options.cell_ports.insert(
            "top".into(),
            BTreeMap::from([("p".into(), PortDirection::Inout)]),
        );
        let adapted = adapt_gds_hierarchy_to_lvs(&case_library, &deck(), &options, Backend::Cpu)
            .expect("case-insensitive TEXT binds to configured spelling");
        assert!(adapted.layout.cells["top"].netlist.nets.contains_key("p"));
        assert_eq!(adapted.layout.cells["top"].ports, vec!["p"]);

        options.cell_ports.insert(
            "top".into(),
            BTreeMap::from([
                ("P".into(), PortDirection::Input),
                ("p".into(), PortDirection::Output),
            ]),
        );
        let duplicate =
            adapt_gds_hierarchy_to_lvs(&case_library, &deck(), &options, Backend::Cpu).unwrap_err();
        assert_eq!(duplicate.kind, GdsHierarchyAdapterErrorKind::InvalidOptions);
        assert!(duplicate.message.contains("case-duplicate"));

        let collision_name = "gds:top:E0:N0";
        let collision_library = lossless_round_trip(library(vec![structure(
            "top",
            vec![
                boundary(7, 0, 0, 100, 100, GdsElementMeta::default()),
                boundary(7, 200, 0, 300, 100, GdsElementMeta::default()),
                text(7, 250, 50, collision_name, GdsElementMeta::default()),
            ],
        )]));
        let mut collision_options = GdsHierarchyAdapterOptions::new("top");
        collision_options.text_evidence.push(GdsTextEvidenceRule {
            layer: 7,
            datatype: 99,
            use_string: true,
            label_property_attributes: BTreeSet::new(),
        });
        collision_options.cell_ports.insert(
            "top".into(),
            BTreeMap::from([(collision_name.into(), PortDirection::Inout)]),
        );
        let collision = adapt_gds_hierarchy_to_lvs(
            &collision_library,
            &deck(),
            &collision_options,
            Backend::Cpu,
        )
        .unwrap_err();
        assert_eq!(
            collision.kind,
            GdsHierarchyAdapterErrorKind::ConflictingEvidence
        );
        assert!(collision.message.contains("net names collide"));
    }

    #[test]
    fn explicit_properties_cannot_contradict_exact_geometry_or_aref_copies() {
        let child = structure(
            "child",
            vec![
                boundary(7, 0, 0, 100, 100, GdsElementMeta::default()),
                text(7, 50, 50, "P", GdsElementMeta::default()),
            ],
        );
        let top = structure(
            "top",
            vec![
                boundary(7, 0, 0, 100, 100, GdsElementMeta::default()),
                boundary(7, 200, 0, 300, 100, GdsElementMeta::default()),
                text(7, 50, 50, "A", GdsElementMeta::default()),
                text(7, 250, 50, "B", GdsElementMeta::default()),
                sref("child", 0, 0, properties(&[(88, "P=B")])),
            ],
        );
        let contradiction_library = lossless_round_trip(library(vec![child.clone(), top]));
        let mut options = GdsHierarchyAdapterOptions::new("top");
        options.text_evidence.push(GdsTextEvidenceRule {
            layer: 7,
            datatype: 99,
            use_string: true,
            label_property_attributes: BTreeSet::new(),
        });
        options.cell_ports.insert(
            "child".into(),
            BTreeMap::from([("P".into(), PortDirection::Inout)]),
        );
        options.instance_binding_property_attributes.insert(88);
        let contradiction =
            adapt_gds_hierarchy_to_lvs(&contradiction_library, &deck(), &options, Backend::Cpu)
                .unwrap_err();
        assert_eq!(
            contradiction.kind,
            GdsHierarchyAdapterErrorKind::ConflictingEvidence
        );
        assert!(contradiction
            .message
            .contains("exact access geometry contacts"));

        let array_top = structure(
            "top",
            vec![
                boundary(7, 0, 0, 100, 100, GdsElementMeta::default()),
                boundary(7, 200, 0, 300, 100, GdsElementMeta::default()),
                text(7, 50, 50, "A", GdsElementMeta::default()),
                text(7, 250, 50, "B", GdsElementMeta::default()),
                GdsElement::Aref(GdsArrayReference {
                    structure: "child".into(),
                    columns: 2,
                    rows: 1,
                    origin: Point::new(0, 0),
                    column_endpoint: Point::new(400, 0),
                    row_endpoint: Point::new(0, 0),
                    transform: GdsTransform::default(),
                    meta: GdsElementMeta::default(),
                }),
            ],
        );
        options.instance_binding_property_attributes.clear();
        let inconsistent_library = lossless_round_trip(library(vec![child, array_top]));
        let inconsistent =
            adapt_gds_hierarchy_to_lvs(&inconsistent_library, &deck(), &options, Backend::Cpu)
                .unwrap_err();
        assert_eq!(
            inconsistent.kind,
            GdsHierarchyAdapterErrorKind::ConflictingEvidence
        );
        assert!(inconsistent
            .message
            .contains("AREF copies produce different port maps"));
    }

    #[test]
    fn zero_arrays_and_deep_or_expansive_dags_fail_with_typed_capacity() {
        let child = structure("child", Vec::new());
        let top = structure(
            "top",
            vec![GdsElement::Aref(GdsArrayReference {
                structure: "child".into(),
                columns: 0,
                rows: 1,
                origin: Point::new(0, 0),
                column_endpoint: Point::new(0, 0),
                row_endpoint: Point::new(0, 0),
                transform: GdsTransform::default(),
                meta: GdsElementMeta::default(),
            })],
        );
        let zero = adapt_gds_hierarchy_to_lvs(
            &library(vec![child, top]),
            &deck(),
            &GdsHierarchyAdapterOptions::new("top"),
            Backend::Cpu,
        )
        .unwrap_err();
        assert_eq!(zero.kind, GdsHierarchyAdapterErrorKind::ConflictingEvidence);
        assert!(zero.message.contains("dimensions must be positive"));

        let deep = library(vec![
            structure("leaf", Vec::new()),
            structure("c1", vec![sref("leaf", 0, 0, GdsElementMeta::default())]),
            structure("c2", vec![sref("c1", 0, 0, GdsElementMeta::default())]),
            structure("top", vec![sref("c2", 0, 0, GdsElementMeta::default())]),
        ]);
        let mut depth_options = GdsHierarchyAdapterOptions::new("top");
        depth_options.max_hierarchy_depth = 2;
        let depth =
            adapt_gds_hierarchy_to_lvs(&deep, &deck(), &depth_options, Backend::Cpu).unwrap_err();
        assert_eq!(depth.kind, GdsHierarchyAdapterErrorKind::CapacityExceeded);
        assert!(depth.message.contains("hierarchy depth"));

        let expansive = library(vec![
            structure("leaf", Vec::new()),
            structure(
                "mid",
                vec![
                    sref("leaf", 0, 0, GdsElementMeta::default()),
                    sref("leaf", 100, 0, GdsElementMeta::default()),
                ],
            ),
            structure(
                "top",
                vec![
                    sref("mid", 0, 0, GdsElementMeta::default()),
                    sref("mid", 100, 0, GdsElementMeta::default()),
                ],
            ),
        ]);
        let mut capacity_options = GdsHierarchyAdapterOptions::new("top");
        capacity_options.max_hierarchy_expanded_instances = 3;
        let capacity =
            adapt_gds_hierarchy_to_lvs(&expansive, &deck(), &capacity_options, Backend::Cpu)
                .unwrap_err();
        assert_eq!(
            capacity.kind,
            GdsHierarchyAdapterErrorKind::CapacityExceeded
        );
        assert!(capacity.message.contains("expanded hierarchy count"));
    }

    #[test]
    fn physical_flatten_rejects_hidden_parent_child_and_sibling_shorts() {
        let child = structure(
            "child",
            vec![boundary(7, 0, 0, 100, 100, GdsElementMeta::default())],
        );
        let parent_overlap = lossless_round_trip(library(vec![
            child.clone(),
            structure(
                "top",
                vec![
                    boundary(7, 50, 0, 150, 100, GdsElementMeta::default()),
                    sref("child", 0, 0, GdsElementMeta::default()),
                ],
            ),
        ]));
        let error = adapt_gds_hierarchy_to_lvs(
            &parent_overlap,
            &deck(),
            &GdsHierarchyAdapterOptions::new("top"),
            Backend::Cpu,
        )
        .unwrap_err();
        assert_eq!(
            error.kind,
            GdsHierarchyAdapterErrorKind::ConflictingEvidence
        );
        assert!(error
            .message
            .contains("flattened physical extraction contradicts"));

        let sibling_overlap = lossless_round_trip(library(vec![
            child,
            structure(
                "top",
                vec![
                    sref("child", 0, 0, GdsElementMeta::default()),
                    sref("child", 50, 0, GdsElementMeta::default()),
                ],
            ),
        ]));
        let error = adapt_gds_hierarchy_to_lvs(
            &sibling_overlap,
            &deck(),
            &GdsHierarchyAdapterOptions::new("top"),
            Backend::Cpu,
        )
        .unwrap_err();
        assert_eq!(
            error.kind,
            GdsHierarchyAdapterErrorKind::ConflictingEvidence
        );
        assert!(error
            .message
            .contains("flattened physical extraction contradicts"));
    }

    #[test]
    fn physical_flatten_rejects_cross_boundary_mos_recognition() {
        let child = structure(
            "child",
            vec![
                boundary(1, -20, -20, 120, 120, GdsElementMeta::default()),
                boundary(2, 0, 0, 100, 100, GdsElementMeta::default()),
                boundary(4, -10, -10, 110, 110, GdsElementMeta::default()),
            ],
        );
        let top = structure(
            "top",
            vec![
                boundary(3, 40, -20, 60, 120, GdsElementMeta::default()),
                sref("child", 0, 0, GdsElementMeta::default()),
            ],
        );
        let cross_boundary = lossless_round_trip(library(vec![child, top]));
        let error = adapt_gds_hierarchy_to_lvs(
            &cross_boundary,
            &deck(),
            &GdsHierarchyAdapterOptions::new("top"),
            Backend::Cpu,
        )
        .unwrap_err();
        assert_eq!(
            error.kind,
            GdsHierarchyAdapterErrorKind::ConflictingEvidence
        );
        assert!(
            error
                .message
                .contains("flattened physical extraction contradicts"),
            "{}",
            error.message
        );
    }

    fn opaque_options() -> GdsHierarchyAdapterOptions {
        let mut options = GdsHierarchyAdapterOptions::new("top");
        options.text_evidence.push(GdsTextEvidenceRule {
            layer: 7,
            datatype: 99,
            use_string: true,
            label_property_attributes: BTreeSet::new(),
        });
        options.instance_binding_property_attributes.insert(88);
        options.black_boxes.insert(
            "macro".into(),
            GdsBlackBoxAdapterSpec {
                ports: vec!["A".into()],
            },
        );
        options
    }

    fn append_opaque_macro(elements: &mut Vec<GdsElement>) {
        elements.push(boundary(7, 1000, 0, 1100, 100, GdsElementMeta::default()));
        elements.push(text(7, 1050, 50, "BB", GdsElementMeta::default()));
        elements.push(sref("macro", 2000, 0, properties(&[(88, "A=BB")])));
    }

    #[test]
    fn opaque_cells_never_suppress_reachable_nonopaque_physical_conflicts() {
        let child = structure(
            "child",
            vec![boundary(7, 0, 0, 100, 100, GdsElementMeta::default())],
        );
        let mut parent_elements = vec![
            boundary(7, 50, 0, 150, 100, GdsElementMeta::default()),
            sref("child", 0, 0, GdsElementMeta::default()),
        ];
        append_opaque_macro(&mut parent_elements);
        let parent_short = lossless_round_trip(library(vec![
            child.clone(),
            structure("macro", Vec::new()),
            structure("top", parent_elements),
        ]));
        let error =
            adapt_gds_hierarchy_to_lvs(&parent_short, &deck(), &opaque_options(), Backend::Cpu)
                .unwrap_err();
        assert_eq!(
            error.kind,
            GdsHierarchyAdapterErrorKind::ConflictingEvidence
        );
        assert!(error
            .message
            .contains("flattened physical extraction contradicts"));

        let mut sibling_elements = vec![
            sref("child", 0, 0, GdsElementMeta::default()),
            sref("child", 50, 0, GdsElementMeta::default()),
        ];
        append_opaque_macro(&mut sibling_elements);
        let sibling_short = lossless_round_trip(library(vec![
            child,
            structure("macro", Vec::new()),
            structure("top", sibling_elements),
        ]));
        let error =
            adapt_gds_hierarchy_to_lvs(&sibling_short, &deck(), &opaque_options(), Backend::Cpu)
                .unwrap_err();
        assert_eq!(
            error.kind,
            GdsHierarchyAdapterErrorKind::ConflictingEvidence
        );

        let device_child = structure(
            "device_child",
            vec![
                boundary(1, -20, -20, 120, 120, GdsElementMeta::default()),
                boundary(2, 0, 0, 100, 100, GdsElementMeta::default()),
                boundary(4, -10, -10, 110, 110, GdsElementMeta::default()),
            ],
        );
        let mut device_top = vec![
            boundary(3, 40, -20, 60, 120, GdsElementMeta::default()),
            sref("device_child", 0, 0, GdsElementMeta::default()),
        ];
        append_opaque_macro(&mut device_top);
        let cross_boundary = lossless_round_trip(library(vec![
            device_child,
            structure("macro", Vec::new()),
            structure("top", device_top),
        ]));
        let error =
            adapt_gds_hierarchy_to_lvs(&cross_boundary, &deck(), &opaque_options(), Backend::Cpu)
                .unwrap_err();
        assert_eq!(
            error.kind,
            GdsHierarchyAdapterErrorKind::ConflictingEvidence
        );
    }

    #[test]
    fn unrelated_opaque_cells_do_not_change_selected_top_scope() {
        let mut unused = Vec::new();
        append_opaque_macro(&mut unused);
        let library = lossless_round_trip(library(vec![
            structure(
                "top",
                vec![boundary(7, 0, 0, 100, 100, GdsElementMeta::default())],
            ),
            structure("unused", unused),
            structure("macro", Vec::new()),
        ]));
        let adapted =
            adapt_gds_hierarchy_to_lvs(&library, &deck(), &opaque_options(), Backend::Cpu)
                .expect("unrelated opaque cell must not suppress or broaden top correlation");
        assert_eq!(
            adapted.physical_correlation,
            GdsPhysicalCorrelationStatus::Correlated
        );
    }

    #[test]
    fn opaque_defined_invalid_bodies_match_undefined_boundary_semantics() {
        let mut top_elements = Vec::new();
        append_opaque_macro(&mut top_elements);
        let undefined = lossless_round_trip(library(vec![structure("top", top_elements.clone())]));
        let options = opaque_options();
        let undefined_result =
            adapt_gds_hierarchy_to_lvs(&undefined, &deck(), &options, Backend::Cpu)
                .expect("configured undefined opaque boundary");

        let invalid_interior = structure(
            "macro",
            vec![
                text(99, 0, 0, "UNCONFIGURED", GdsElementMeta::default()),
                GdsElement::Node(GdsNode {
                    layer: 99,
                    node_type: 0,
                    points: vec![Point::new(0, 0)],
                    meta: GdsElementMeta::default(),
                }),
                sref("bad_descendant", 0, 0, GdsElementMeta::default()),
            ],
        );
        let bad_descendant = structure(
            "bad_descendant",
            vec![GdsElement::Node(GdsNode {
                layer: 99,
                node_type: 0,
                points: vec![Point::new(0, 0)],
                meta: GdsElementMeta::default(),
            })],
        );
        let defined = lossless_round_trip(library(vec![
            structure("top", top_elements.clone()),
            invalid_interior,
            bad_descendant,
        ]));
        let defined_result = adapt_gds_hierarchy_to_lvs(&defined, &deck(), &options, Backend::Cpu)
            .expect("defined invalid opaque body and descendants are not inspected");
        assert_eq!(undefined_result.layout, defined_result.layout);
        assert_eq!(undefined_result.provenance, defined_result.provenance);
        assert_eq!(
            defined_result.physical_correlation,
            GdsPhysicalCorrelationStatus::OpaqueBlackBoxes {
                cells: BTreeSet::from(["macro".into()])
            }
        );

        let mut resistor_deck = deck();
        resistor_deck.devices.resistor_rules.push(ResistorRule {
            name: "opaque_resistor".into(),
            body_layer: resistor_deck.layers.id("met1").unwrap(),
            marker_layer: resistor_deck.layers.id("nsdm").unwrap(),
            terminal_layer: resistor_deck.layers.id("poly").unwrap(),
        });
        let device_interior = structure(
            "macro",
            vec![
                boundary(7, 0, 0, 300, 100, GdsElementMeta::default()),
                boundary(4, 0, 0, 300, 100, GdsElementMeta::default()),
                boundary(3, 0, 0, 50, 100, GdsElementMeta::default()),
                boundary(3, 250, 0, 300, 100, GdsElementMeta::default()),
            ],
        );
        let defined_device = lossless_round_trip(library(vec![
            structure("top", top_elements),
            device_interior,
        ]));
        adapt_gds_hierarchy_to_lvs(&defined_device, &resistor_deck, &options, Backend::Cpu)
            .expect("unsupported opaque device interior is pruned before recognition");
    }

    #[test]
    fn opaque_boundary_maps_are_checked_before_ignoring_invalid_body() {
        let mut top_elements = vec![
            boundary(7, 1000, 0, 1100, 100, GdsElementMeta::default()),
            text(7, 1050, 50, "BB", GdsElementMeta::default()),
            sref("macro", 2000, 0, GdsElementMeta::default()),
        ];
        let invalid_body = structure(
            "macro",
            vec![GdsElement::Node(GdsNode {
                layer: 99,
                node_type: 0,
                points: vec![Point::new(0, 0)],
                meta: GdsElementMeta::default(),
            })],
        );
        let library = lossless_round_trip(library(vec![
            structure("top", std::mem::take(&mut top_elements)),
            invalid_body,
        ]));
        let error = adapt_gds_hierarchy_to_lvs(&library, &deck(), &opaque_options(), Backend::Cpu)
            .unwrap_err();
        assert_eq!(error.kind, GdsHierarchyAdapterErrorKind::MissingEvidence);
        assert!(error.message.contains("every declared port"));
    }

    fn hierarchy_chain(root: &str, prefix: &str, depth: usize) -> Vec<GdsStructure> {
        let mut structures = Vec::with_capacity(depth);
        let mut previous: Option<String> = None;
        for index in 0..depth {
            let name = if index + 1 == depth {
                root.to_string()
            } else {
                format!("{prefix}{index}")
            };
            let elements = previous
                .as_deref()
                .map(|target| vec![sref(target, 0, 0, GdsElementMeta::default())])
                .unwrap_or_default();
            structures.push(structure(&name, elements));
            previous = Some(name);
        }
        structures
    }

    #[test]
    fn selected_top_depth_bound_precedes_recursive_consumers() {
        let accepted = library(hierarchy_chain(
            "top",
            "accepted_",
            GDS_ADAPTER_MAX_STACK_SAFE_DEPTH,
        ));
        let accepted_result = adapt_gds_hierarchy_to_lvs(
            &accepted,
            &deck(),
            &GdsHierarchyAdapterOptions::new("top"),
            Backend::Cpu,
        )
        .expect("stack-safe hard limit is accepted");
        assert_eq!(
            accepted_result.layout.cells.len(),
            GDS_ADAPTER_MAX_STACK_SAFE_DEPTH
        );

        let over = library(hierarchy_chain(
            "top",
            "over_",
            GDS_ADAPTER_MAX_STACK_SAFE_DEPTH + 1,
        ));
        let error = adapt_gds_hierarchy_to_lvs(
            &over,
            &deck(),
            &GdsHierarchyAdapterOptions::new("top"),
            Backend::Cpu,
        )
        .unwrap_err();
        assert_eq!(error.kind, GdsHierarchyAdapterErrorKind::CapacityExceeded);
        assert!(error.message.contains("stack-safe/configured limit"));

        let mut unrelated = vec![structure("top", Vec::new())];
        unrelated.extend(hierarchy_chain(
            "unrelated_root",
            "unrelated_",
            GDS_ADAPTER_MAX_STACK_SAFE_DEPTH + 64,
        ));
        let unrelated_result = adapt_gds_hierarchy_to_lvs(
            &library(unrelated),
            &deck(),
            &GdsHierarchyAdapterOptions::new("top"),
            Backend::Cpu,
        )
        .expect("unrelated deep hierarchy is outside selected-top scope");
        assert_eq!(unrelated_result.layout.cells.len(), 1);
        assert_eq!(
            unrelated_result.physical_correlation,
            GdsPhysicalCorrelationStatus::Correlated
        );
    }
}
