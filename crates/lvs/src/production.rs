//! Deterministic, body-aware LVS data model and graph matcher.
//!
//! The original LVS structs remain source-compatible for existing callers.  This
//! module adds an explicit production model where unresolved terminals cannot be
//! confused with electrical net zero, properties carry units/tolerances, and a
//! checker never reports a match after a search-capacity or input-scope failure.

use super::types::*;
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HierarchyPath(pub Vec<String>);

impl HierarchyPath {
    pub fn root(cell: impl Into<String>) -> Self {
        Self(vec![cell.into()])
    }

    pub fn child(&self, instance: impl Into<String>) -> Self {
        let mut path = self.0.clone();
        path.push(instance.into());
        Self(path)
    }
}

impl fmt::Display for HierarchyPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.join("/"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedTerminal {
    pub reason: String,
    pub hierarchy_path: HierarchyPath,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminalConnection<N> {
    Connected(N),
    Unresolved(UnresolvedTerminal),
}

impl<N> TerminalConnection<N> {
    pub fn connected(&self) -> Option<&N> {
        match self {
            Self::Connected(net) => Some(net),
            Self::Unresolved(_) => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PropertyUnit {
    Dimensionless,
    Nanometer,
    SquareNanometer,
    Ohm,
    Farad,
    Ampere,
    Volt,
    Count,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NumericTolerance {
    pub absolute: f64,
    /// Percent, so `1.0` means one percent.
    pub relative_percent: f64,
}

impl NumericTolerance {
    pub const EXACT: Self = Self {
        absolute: 0.0,
        relative_percent: 0.0,
    };

    fn valid(self) -> bool {
        self.absolute.is_finite()
            && self.absolute >= 0.0
            && self.relative_percent.is_finite()
            && self.relative_percent >= 0.0
    }

    fn accepts(self, got: f64, expected: f64) -> bool {
        let allowed = self
            .absolute
            .max(expected.abs() * self.relative_percent / 100.0);
        (got - expected).abs() <= allowed
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TypedProperty {
    pub value: f64,
    pub unit: PropertyUnit,
    /// Reference-side tolerance. Layout-side tolerances are ignored.
    pub tolerance: NumericTolerance,
    pub model_revision: Option<String>,
}

impl TypedProperty {
    pub fn exact(value: f64, unit: PropertyUnit) -> Self {
        Self {
            value,
            unit,
            tolerance: NumericTolerance::EXACT,
            model_revision: None,
        }
    }

    fn validate(&self, name: &str) -> Result<(), String> {
        if !self.value.is_finite() {
            return Err(format!("property '{name}' is non-finite"));
        }
        if !self.tolerance.valid() {
            return Err(format!("property '{name}' has an invalid tolerance"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PortDirection {
    Input,
    Output,
    Inout,
    Power,
    Ground,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetIdentity<N> {
    pub id: N,
    pub labels: BTreeSet<String>,
    pub ports: BTreeMap<String, PortDirection>,
    pub globals: BTreeSet<String>,
    pub hierarchy_path: HierarchyPath,
}

impl<N> NetIdentity<N> {
    fn names(&self) -> impl Iterator<Item = &String> {
        self.labels
            .iter()
            .chain(self.ports.keys())
            .chain(self.globals.iter())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoftConnection<N> {
    pub from: N,
    pub to: N,
    pub policy_id: String,
    pub hierarchy_path: HierarchyPath,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenCandidate<N> {
    pub net_a: N,
    pub net_b: N,
    pub reason: String,
    pub hierarchy_path: HierarchyPath,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub stable_id: String,
    pub hierarchy_path: HierarchyPath,
    pub model: Option<String>,
    pub device_class: Option<String>,
    pub flavor: DeviceFlavor,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MosDeviceRecord<N> {
    pub identity: DeviceIdentity,
    pub kind: DeviceKind,
    pub drain: N,
    pub gate: N,
    pub source: N,
    pub body: TerminalConnection<N>,
    /// Optional process context beyond the four electrical MOS terminals.
    pub well: Option<TerminalConnection<N>>,
    pub substrate: Option<TerminalConnection<N>>,
    /// W, L, NF, M, AD/AS/PD/PS and foundry-specific typed properties.
    pub properties: BTreeMap<String, TypedProperty>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TwoTerminalRecord<N> {
    pub identity: DeviceIdentity,
    pub kind: TwoTerminalKind,
    pub terminal_a: N,
    pub terminal_b: N,
    pub properties: BTreeMap<String, TypedProperty>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BjtDeviceRecord<N> {
    pub identity: DeviceIdentity,
    pub kind: DeviceKind,
    pub collector: N,
    pub base: N,
    pub emitter: N,
    pub substrate: Option<TerminalConnection<N>>,
    pub properties: BTreeMap<String, TypedProperty>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DetailedNetlist<N> {
    pub cell_name: String,
    pub mos_devices: Vec<MosDeviceRecord<N>>,
    pub two_terminal_devices: Vec<TwoTerminalRecord<N>>,
    pub bjt_devices: Vec<BjtDeviceRecord<N>>,
    pub nets: BTreeMap<N, NetIdentity<N>>,
    pub soft_connections: Vec<SoftConnection<N>>,
    pub open_candidates: Vec<OpenCandidate<N>>,
    /// Explicit layout-name -> reference-name seed aliases.
    pub seed_aliases: BTreeMap<String, String>,
}

pub type DetailedExtractedNetlist = DetailedNetlist<u32>;
pub type DetailedRefNetlist = DetailedNetlist<String>;

impl<N: Ord> DetailedNetlist<N> {
    pub fn empty(cell_name: impl Into<String>) -> Self {
        Self {
            cell_name: cell_name.into(),
            mos_devices: Vec::new(),
            two_terminal_devices: Vec::new(),
            bjt_devices: Vec::new(),
            nets: BTreeMap::new(),
            soft_connections: Vec::new(),
            open_candidates: Vec::new(),
            seed_aliases: BTreeMap::new(),
        }
    }
}

fn legacy_identity(prefix: &str, index: usize, flavor: DeviceFlavor) -> DeviceIdentity {
    DeviceIdentity {
        stable_id: format!("{prefix}{index}"),
        hierarchy_path: HierarchyPath::root("legacy"),
        model: None,
        device_class: None,
        flavor,
    }
}

fn unresolved_legacy_body(index: usize) -> TerminalConnection<u32> {
    TerminalConnection::Unresolved(UnresolvedTerminal {
        reason: format!("legacy extracted device {index} does not carry body-resolution evidence"),
        hierarchy_path: HierarchyPath::root("legacy"),
    })
}

fn unresolved_reference_body(index: usize) -> TerminalConnection<String> {
    TerminalConnection::Unresolved(UnresolvedTerminal {
        reason: format!("legacy RefDevice {index} has no body terminal"),
        hierarchy_path: HierarchyPath::root("legacy"),
    })
}

fn add_net<N: Clone + Ord>(netlist: &mut DetailedNetlist<N>, id: N) {
    netlist.nets.entry(id.clone()).or_insert(NetIdentity {
        id,
        labels: BTreeSet::new(),
        ports: BTreeMap::new(),
        globals: BTreeSet::new(),
        hierarchy_path: HierarchyPath::root("legacy"),
    });
}

impl DetailedExtractedNetlist {
    /// Compatibility adapter. Body is deliberately unresolved even when the
    /// legacy `body` field is zero/nonzero because that field has no validity bit
    /// and historically used zero as a sentinel that collides with real net 0.
    pub fn from_legacy(legacy: &ExtractedNetlist, cell_name: impl Into<String>) -> Self {
        let mut out = Self::empty(cell_name);
        for (index, device) in legacy.devices.iter().enumerate() {
            for net in [device.drain, device.gate, device.source] {
                add_net(&mut out, net);
            }
            let mut properties = BTreeMap::new();
            if device.w > 0 {
                properties.insert(
                    "W".into(),
                    TypedProperty::exact(f64::from(device.w), PropertyUnit::Nanometer),
                );
            }
            if device.l > 0 {
                properties.insert(
                    "L".into(),
                    TypedProperty::exact(f64::from(device.l), PropertyUnit::Nanometer),
                );
            }
            out.mos_devices.push(MosDeviceRecord {
                identity: DeviceIdentity {
                    device_class: device.device_class.clone(),
                    ..legacy_identity("layout:M", index, device.flavor)
                },
                kind: device.kind.clone(),
                drain: device.drain,
                gate: device.gate,
                source: device.source,
                body: unresolved_legacy_body(index),
                well: None,
                substrate: None,
                properties,
            });
        }
        for (index, device) in legacy.two_terminal.iter().enumerate() {
            add_net(&mut out, device.terminal_a);
            add_net(&mut out, device.terminal_b);
            let mut properties = BTreeMap::new();
            if device.value.is_finite() && device.value != 0.0 {
                properties.insert(
                    "VALUE".into(),
                    TypedProperty::exact(device.value, PropertyUnit::Dimensionless),
                );
            }
            out.two_terminal_devices.push(TwoTerminalRecord {
                identity: legacy_identity("layout:X", index, DeviceFlavor::Standard),
                kind: device.kind.clone(),
                terminal_a: device.terminal_a,
                terminal_b: device.terminal_b,
                properties,
            });
        }
        for (index, device) in legacy.bjt_devices.iter().enumerate() {
            for net in [device.collector, device.base, device.emitter] {
                add_net(&mut out, net);
            }
            out.bjt_devices.push(BjtDeviceRecord {
                identity: legacy_identity("layout:Q", index, DeviceFlavor::Standard),
                kind: device.kind.clone(),
                collector: device.collector,
                base: device.base,
                emitter: device.emitter,
                substrate: None,
                properties: BTreeMap::new(),
            });
        }
        for net in 0..legacy.net_count as u32 {
            add_net(&mut out, net);
        }
        out
    }
}

impl DetailedRefNetlist {
    pub fn from_legacy(legacy: &RefNetlist, cell_name: impl Into<String>) -> Self {
        let mut out = Self::empty(cell_name);
        for (index, device) in legacy.devices.iter().enumerate() {
            for net in [&device.drain, &device.gate, &device.source] {
                add_net(&mut out, net.clone());
            }
            let mut properties = BTreeMap::new();
            if device.w > 0 {
                properties.insert(
                    "W".into(),
                    TypedProperty::exact(f64::from(device.w), PropertyUnit::Nanometer),
                );
            }
            if device.l > 0 {
                properties.insert(
                    "L".into(),
                    TypedProperty::exact(f64::from(device.l), PropertyUnit::Nanometer),
                );
            }
            out.mos_devices.push(MosDeviceRecord {
                identity: legacy_identity("reference:M", index, device.flavor),
                kind: device.kind.clone(),
                drain: device.drain.clone(),
                gate: device.gate.clone(),
                source: device.source.clone(),
                body: unresolved_reference_body(index),
                well: None,
                substrate: None,
                properties,
            });
        }
        for (index, device) in legacy.ref_two_terminal.iter().enumerate() {
            add_net(&mut out, device.terminal_a.clone());
            add_net(&mut out, device.terminal_b.clone());
            out.two_terminal_devices.push(TwoTerminalRecord {
                identity: legacy_identity("reference:X", index, DeviceFlavor::Standard),
                kind: device.kind.clone(),
                terminal_a: device.terminal_a.clone(),
                terminal_b: device.terminal_b.clone(),
                properties: BTreeMap::new(),
            });
        }
        for (index, device) in legacy.ref_bjt.iter().enumerate() {
            for net in [&device.collector, &device.base, &device.emitter] {
                add_net(&mut out, net.clone());
            }
            out.bjt_devices.push(BjtDeviceRecord {
                identity: legacy_identity("reference:Q", index, DeviceFlavor::Standard),
                kind: device.kind.clone(),
                collector: device.collector.clone(),
                base: device.base.clone(),
                emitter: device.emitter.clone(),
                substrate: None,
                properties: BTreeMap::new(),
            });
        }
        for (reference_name, layout_name) in &legacy.net_seeds {
            if let Some(net) = out.nets.get_mut(reference_name) {
                net.labels.insert(reference_name.clone());
            }
            out.seed_aliases
                .insert(layout_name.clone(), reference_name.clone());
        }
        out
    }
}

/// Source-compatible builder for the unchanged legacy `RefDevice` struct.
#[derive(Debug, Clone)]
pub struct LegacyRefDeviceBuilder {
    device: RefDevice,
}

impl LegacyRefDeviceBuilder {
    pub fn new(
        kind: DeviceKind,
        drain: impl Into<String>,
        gate: impl Into<String>,
        source: impl Into<String>,
    ) -> Self {
        Self {
            device: RefDevice {
                kind,
                gate: gate.into(),
                source: source.into(),
                drain: drain.into(),
                w: 0,
                l: 0,
                flavor: DeviceFlavor::Standard,
                ..Default::default()
            },
        }
    }

    pub fn dimensions_nm(mut self, width: i32, length: i32) -> Self {
        self.device.w = width;
        self.device.l = length;
        self
    }

    pub fn flavor(mut self, flavor: DeviceFlavor) -> Self {
        self.device.flavor = flavor;
        self
    }

    pub fn build(self) -> RefDevice {
        self.device
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductionLvsStatus {
    Match,
    Mismatch,
    Indeterminate,
    Error,
}

impl ProductionLvsStatus {
    pub fn is_match(self) -> bool {
        self == Self::Match
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PropertyDelta {
    pub property: String,
    pub layout_value: Option<f64>,
    pub reference_value: Option<f64>,
    pub unit: Option<PropertyUnit>,
    pub tolerance: Option<NumericTolerance>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopologyConflictKind {
    Open,
    Short,
    IllegalPinSwap,
    PartitionConflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyWitness {
    pub kind: TopologyConflictKind,
    pub layout_devices: Vec<String>,
    pub reference_devices: Vec<String>,
    pub layout_nets: Vec<u32>,
    pub reference_nets: Vec<String>,
    /// Alternating stable device/net labels where a path is available.
    pub path: Vec<String>,
    pub hierarchy_paths: Vec<HierarchyPath>,
    pub explanation: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProductionMismatch {
    Input {
        side: String,
        object: String,
        explanation: String,
        fingerprint: String,
    },
    DeviceCount {
        signature: String,
        layout: usize,
        reference: usize,
        fingerprint: String,
    },
    SeedConflict {
        layout_name: String,
        reference_name: String,
        explanation: String,
        fingerprint: String,
    },
    Topology {
        witness: TopologyWitness,
        fingerprint: String,
    },
    Property {
        layout_device: String,
        reference_device: String,
        delta: PropertyDelta,
        hierarchy_paths: Vec<HierarchyPath>,
        fingerprint: String,
    },
    Capacity {
        explored_states: usize,
        limit: usize,
        fingerprint: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceMapping {
    pub reference_id: String,
    pub layout_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetMapping {
    pub reference_net: String,
    pub layout_net: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProductionLvsResult {
    pub status: ProductionLvsStatus,
    pub reason: String,
    pub device_mappings: Vec<DeviceMapping>,
    pub net_mappings: Vec<NetMapping>,
    pub mismatches: Vec<ProductionMismatch>,
    pub explored_states: usize,
    pub fingerprint: String,
}

#[derive(Debug, Clone)]
pub struct ProductionCompareOptions {
    pub allow_source_drain_swap: bool,
    pub require_resolved_bulk: bool,
    pub require_named_ports: bool,
    pub require_exact_property_set: bool,
    pub max_search_states: usize,
    /// Model-name -> canonical model-name. Lookup is case-insensitive.
    pub model_aliases: BTreeMap<String, String>,
    /// Additional layout-name -> reference-name constraints.
    pub seed_pairs: BTreeMap<String, String>,
}

impl Default for ProductionCompareOptions {
    fn default() -> Self {
        Self {
            allow_source_drain_swap: true,
            require_resolved_bulk: true,
            require_named_ports: true,
            require_exact_property_set: true,
            max_search_states: 1_000_000,
            model_aliases: BTreeMap::new(),
            seed_pairs: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum PinRole {
    Gate,
    SourceDrain,
    Source,
    Drain,
    Body,
    Well,
    Substrate,
    Terminal,
    Anode,
    Cathode,
    Collector,
    Base,
    Emitter,
    Soft,
}

#[derive(Debug, Clone)]
struct MatchDevice<N> {
    id: String,
    path: HierarchyPath,
    base: String,
    pins: Vec<(PinRole, N)>,
    properties: BTreeMap<String, TypedProperty>,
}

#[derive(Debug, Clone)]
struct MatchGraph<N> {
    devices: Vec<MatchDevice<N>>,
    nets: BTreeMap<N, NetIdentity<N>>,
}

fn canonical_name(name: &str) -> String {
    name.to_ascii_lowercase()
}

fn canonical_model(model: Option<&str>, options: &ProductionCompareOptions) -> String {
    let Some(model) = model else {
        return "<none>".into();
    };
    let key = canonical_name(model);
    options
        .model_aliases
        .iter()
        .find_map(|(alias, target)| {
            alias
                .eq_ignore_ascii_case(&key)
                .then(|| canonical_name(target))
        })
        .unwrap_or(key)
}

fn device_base(
    family: &str,
    kind: &DeviceKind,
    identity: &DeviceIdentity,
    options: &ProductionCompareOptions,
) -> String {
    format!(
        "{family}:{kind:?}:{}:{}:{:?}",
        canonical_model(identity.model.as_deref(), options),
        identity
            .device_class
            .as_deref()
            .map(canonical_name)
            .unwrap_or_else(|| "<none>".into()),
        identity.flavor,
    )
}

fn unresolved_input(
    side: &str,
    device: &DeviceIdentity,
    terminal: &str,
    unresolved: &UnresolvedTerminal,
) -> ProductionMismatch {
    let explanation = format!("{terminal} terminal is unresolved: {}", unresolved.reason);
    let canonical = format!(
        "input|{side}|{}|{terminal}|{}|{}",
        device.stable_id, unresolved.hierarchy_path, unresolved.reason
    );
    ProductionMismatch::Input {
        side: side.into(),
        object: device.stable_id.clone(),
        explanation,
        fingerprint: stable_fingerprint(&canonical),
    }
}

fn push_connection<N: Clone>(
    pins: &mut Vec<(PinRole, N)>,
    connection: &TerminalConnection<N>,
    role: PinRole,
    terminal: &str,
    side: &str,
    identity: &DeviceIdentity,
    options: &ProductionCompareOptions,
    errors: &mut Vec<ProductionMismatch>,
) {
    match connection {
        TerminalConnection::Connected(net) => pins.push((role, net.clone())),
        TerminalConnection::Unresolved(unresolved) if options.require_resolved_bulk => {
            errors.push(unresolved_input(side, identity, terminal, unresolved));
        }
        TerminalConnection::Unresolved(_) => {}
    }
}

fn validate_device_input(
    side: &str,
    identity: &DeviceIdentity,
    properties: &BTreeMap<String, TypedProperty>,
    ids: &mut HashSet<String>,
    errors: &mut Vec<ProductionMismatch>,
) {
    if !ids.insert(canonical_name(&identity.stable_id)) {
        let canonical = format!("input|{side}|duplicate|{}", identity.stable_id);
        errors.push(ProductionMismatch::Input {
            side: side.into(),
            object: identity.stable_id.clone(),
            explanation: "duplicate stable device ID".into(),
            fingerprint: stable_fingerprint(&canonical),
        });
    }
    for (name, property) in properties {
        if let Err(explanation) = property.validate(name) {
            let canonical = format!(
                "input|{side}|property|{}|{name}|{explanation}",
                identity.stable_id
            );
            errors.push(ProductionMismatch::Input {
                side: side.into(),
                object: identity.stable_id.clone(),
                explanation,
                fingerprint: stable_fingerprint(&canonical),
            });
        }
    }
}

fn build_graph<N: Clone + Ord + fmt::Debug>(
    netlist: &DetailedNetlist<N>,
    side: &str,
    options: &ProductionCompareOptions,
) -> Result<MatchGraph<N>, Vec<ProductionMismatch>> {
    let mut errors = Vec::new();
    let mut ids = HashSet::new();
    let mut devices = Vec::new();

    for (key, identity) in &netlist.nets {
        if key != &identity.id {
            let canonical = format!("input|{side}|net-key|{key:?}|{:?}", identity.id);
            errors.push(ProductionMismatch::Input {
                side: side.into(),
                object: format!("net {key:?}"),
                explanation: "net map key differs from NetIdentity.id".into(),
                fingerprint: stable_fingerprint(&canonical),
            });
        }
    }

    for device in &netlist.mos_devices {
        validate_device_input(
            side,
            &device.identity,
            &device.properties,
            &mut ids,
            &mut errors,
        );
        let mut pins = vec![
            (PinRole::Gate, device.gate.clone()),
            (
                if options.allow_source_drain_swap {
                    PinRole::SourceDrain
                } else {
                    PinRole::Drain
                },
                device.drain.clone(),
            ),
            (
                if options.allow_source_drain_swap {
                    PinRole::SourceDrain
                } else {
                    PinRole::Source
                },
                device.source.clone(),
            ),
        ];
        push_connection(
            &mut pins,
            &device.body,
            PinRole::Body,
            "body",
            side,
            &device.identity,
            options,
            &mut errors,
        );
        if let Some(well) = &device.well {
            push_connection(
                &mut pins,
                well,
                PinRole::Well,
                "well",
                side,
                &device.identity,
                options,
                &mut errors,
            );
        }
        if let Some(substrate) = &device.substrate {
            push_connection(
                &mut pins,
                substrate,
                PinRole::Substrate,
                "substrate",
                side,
                &device.identity,
                options,
                &mut errors,
            );
        }
        devices.push(MatchDevice {
            id: device.identity.stable_id.clone(),
            path: device.identity.hierarchy_path.clone(),
            base: device_base("MOS", &device.kind, &device.identity, options),
            pins,
            properties: device.properties.clone(),
        });
    }

    for device in &netlist.two_terminal_devices {
        validate_device_input(
            side,
            &device.identity,
            &device.properties,
            &mut ids,
            &mut errors,
        );
        let polar = device.kind == TwoTerminalKind::Diode;
        devices.push(MatchDevice {
            id: device.identity.stable_id.clone(),
            path: device.identity.hierarchy_path.clone(),
            base: format!(
                "TWO:{:?}:{}:{}:{:?}",
                device.kind,
                canonical_model(device.identity.model.as_deref(), options),
                device
                    .identity
                    .device_class
                    .as_deref()
                    .map(canonical_name)
                    .unwrap_or_else(|| "<none>".into()),
                device.identity.flavor,
            ),
            pins: vec![
                (
                    if polar {
                        PinRole::Anode
                    } else {
                        PinRole::Terminal
                    },
                    device.terminal_a.clone(),
                ),
                (
                    if polar {
                        PinRole::Cathode
                    } else {
                        PinRole::Terminal
                    },
                    device.terminal_b.clone(),
                ),
            ],
            properties: device.properties.clone(),
        });
    }

    for device in &netlist.bjt_devices {
        validate_device_input(
            side,
            &device.identity,
            &device.properties,
            &mut ids,
            &mut errors,
        );
        let mut pins = vec![
            (PinRole::Collector, device.collector.clone()),
            (PinRole::Base, device.base.clone()),
            (PinRole::Emitter, device.emitter.clone()),
        ];
        if let Some(substrate) = &device.substrate {
            push_connection(
                &mut pins,
                substrate,
                PinRole::Substrate,
                "substrate",
                side,
                &device.identity,
                options,
                &mut errors,
            );
        }
        devices.push(MatchDevice {
            id: device.identity.stable_id.clone(),
            path: device.identity.hierarchy_path.clone(),
            base: device_base("BJT", &device.kind, &device.identity, options),
            pins,
            properties: device.properties.clone(),
        });
    }

    for connection in &netlist.soft_connections {
        devices.push(MatchDevice {
            id: format!(
                "soft:{}:{}",
                connection.policy_id, connection.hierarchy_path
            ),
            path: connection.hierarchy_path.clone(),
            base: format!("SOFT:{}", canonical_name(&connection.policy_id)),
            pins: vec![
                (PinRole::Soft, connection.from.clone()),
                (PinRole::Soft, connection.to.clone()),
            ],
            properties: BTreeMap::new(),
        });
    }

    for device in &devices {
        for (_, net) in &device.pins {
            if !netlist.nets.contains_key(net) {
                let canonical = format!("input|{side}|{}|missing-net|{net:?}", device.id);
                errors.push(ProductionMismatch::Input {
                    side: side.into(),
                    object: device.id.clone(),
                    explanation: format!("terminal references undeclared net {net:?}"),
                    fingerprint: stable_fingerprint(&canonical),
                });
            }
        }
    }

    if errors.is_empty() {
        devices.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(MatchGraph {
            devices,
            nets: netlist.nets.clone(),
        })
    } else {
        Err(errors)
    }
}

fn property_delta(
    layout: &MatchDevice<u32>,
    reference: &MatchDevice<String>,
    options: &ProductionCompareOptions,
) -> Option<PropertyDelta> {
    if options.require_exact_property_set {
        for name in layout.properties.keys().chain(reference.properties.keys()) {
            let layout_property = layout.properties.get(name);
            let reference_property = reference.properties.get(name);
            if layout_property.is_none() || reference_property.is_none() {
                return Some(PropertyDelta {
                    property: name.clone(),
                    layout_value: layout_property.map(|property| property.value),
                    reference_value: reference_property.map(|property| property.value),
                    unit: reference_property
                        .map(|property| property.unit)
                        .or_else(|| layout_property.map(|property| property.unit)),
                    tolerance: reference_property.map(|property| property.tolerance),
                });
            }
        }
    }
    for (name, expected) in &reference.properties {
        let Some(got) = layout.properties.get(name) else {
            return Some(PropertyDelta {
                property: name.clone(),
                layout_value: None,
                reference_value: Some(expected.value),
                unit: Some(expected.unit),
                tolerance: Some(expected.tolerance),
            });
        };
        if got.unit != expected.unit
            || got.model_revision != expected.model_revision
            || !expected.tolerance.accepts(got.value, expected.value)
        {
            return Some(PropertyDelta {
                property: name.clone(),
                layout_value: Some(got.value),
                reference_value: Some(expected.value),
                unit: Some(expected.unit),
                tolerance: Some(expected.tolerance),
            });
        }
    }
    None
}

fn name_index<N: Clone + Ord + fmt::Debug>(
    graph: &MatchGraph<N>,
) -> Result<BTreeMap<String, N>, String> {
    let mut index = BTreeMap::new();
    for identity in graph.nets.values() {
        for name in identity.names() {
            let key = canonical_name(name);
            if let Some(existing) = index.insert(key.clone(), identity.id.clone()) {
                if existing != identity.id {
                    return Err(format!(
                        "name '{name}' is attached to multiple nets ({existing:?}, {:?})",
                        identity.id
                    ));
                }
            }
        }
    }
    Ok(index)
}

#[derive(Clone, Default)]
struct SearchState {
    ref_to_layout_net: BTreeMap<String, u32>,
    layout_to_ref_net: BTreeMap<u32, String>,
    ref_to_layout_device: BTreeMap<String, String>,
    used_layout_devices: BTreeSet<usize>,
}

fn assign_net(state: &mut SearchState, reference: &str, layout: u32) -> bool {
    if let Some(existing) = state.ref_to_layout_net.get(reference) {
        return *existing == layout;
    }
    if let Some(existing) = state.layout_to_ref_net.get(&layout) {
        return existing == reference;
    }
    state
        .ref_to_layout_net
        .insert(reference.to_string(), layout);
    state
        .layout_to_ref_net
        .insert(layout, reference.to_string());
    true
}

fn role_groups<N: Clone + Ord>(pins: &[(PinRole, N)]) -> BTreeMap<PinRole, Vec<N>> {
    let mut groups: BTreeMap<PinRole, Vec<N>> = BTreeMap::new();
    for (role, net) in pins {
        groups.entry(*role).or_default().push(net.clone());
    }
    for nets in groups.values_mut() {
        nets.sort();
    }
    groups
}

fn permutations<T: Clone>(values: &[T]) -> Vec<Vec<T>> {
    if values.len() <= 1 {
        return vec![values.to_vec()];
    }
    let mut out = Vec::new();
    for index in 0..values.len() {
        let mut remaining = values.to_vec();
        let head = remaining.remove(index);
        for mut tail in permutations(&remaining) {
            let mut permutation = vec![head.clone()];
            permutation.append(&mut tail);
            out.push(permutation);
        }
    }
    out
}

fn pin_assignments(
    reference: &MatchDevice<String>,
    layout: &MatchDevice<u32>,
) -> Vec<Vec<(String, u32)>> {
    let reference_groups = role_groups(&reference.pins);
    let layout_groups = role_groups(&layout.pins);
    if reference_groups.keys().collect::<Vec<_>>() != layout_groups.keys().collect::<Vec<_>>() {
        return Vec::new();
    }
    let mut assignments = vec![Vec::new()];
    for (role, reference_nets) in reference_groups {
        let Some(layout_nets) = layout_groups.get(&role) else {
            return Vec::new();
        };
        if reference_nets.len() != layout_nets.len() {
            return Vec::new();
        }
        let mut next = Vec::new();
        for permutation in permutations(layout_nets) {
            for existing in &assignments {
                let mut combined = existing.clone();
                combined.extend(
                    reference_nets
                        .iter()
                        .cloned()
                        .zip(permutation.iter().copied()),
                );
                next.push(combined);
            }
        }
        assignments = next;
    }
    assignments.sort();
    assignments.dedup();
    assignments
}

#[derive(Default)]
struct SearchDiagnostics {
    explored: usize,
    capacity_hit: bool,
    first_property: Option<(usize, usize, PropertyDelta)>,
    first_conflict: Option<(usize, usize, Vec<(String, u32)>)>,
}

fn exact_search(
    reference: &MatchGraph<String>,
    layout: &MatchGraph<u32>,
    options: &ProductionCompareOptions,
    order: &[usize],
    candidates: &[Vec<usize>],
    depth: usize,
    state: SearchState,
    diagnostics: &mut SearchDiagnostics,
) -> Option<SearchState> {
    if depth == order.len() {
        return Some(state);
    }
    let reference_index = order[depth];
    let reference_device = &reference.devices[reference_index];
    for &layout_index in &candidates[reference_index] {
        if state.used_layout_devices.contains(&layout_index) {
            continue;
        }
        diagnostics.explored += 1;
        if diagnostics.explored > options.max_search_states {
            diagnostics.capacity_hit = true;
            return None;
        }
        let layout_device = &layout.devices[layout_index];
        if let Some(delta) = property_delta(layout_device, reference_device, options) {
            diagnostics
                .first_property
                .get_or_insert((reference_index, layout_index, delta));
            continue;
        }
        for assignment in pin_assignments(reference_device, layout_device) {
            let mut next = state.clone();
            let valid = assignment.iter().all(|(reference_net, layout_net)| {
                assign_net(&mut next, reference_net, *layout_net)
            });
            if !valid {
                diagnostics.first_conflict.get_or_insert((
                    reference_index,
                    layout_index,
                    assignment,
                ));
                continue;
            }
            next.used_layout_devices.insert(layout_index);
            next.ref_to_layout_device
                .insert(reference_device.id.clone(), layout_device.id.clone());
            if let Some(solution) = exact_search(
                reference,
                layout,
                options,
                order,
                candidates,
                depth + 1,
                next,
                diagnostics,
            ) {
                return Some(solution);
            }
            if diagnostics.capacity_hit {
                return None;
            }
        }
    }
    None
}

fn shortest_net_path(graph: &MatchGraph<u32>, start: u32, goal: u32) -> Vec<String> {
    if start == goal {
        return vec![format!("net:{start}")];
    }
    let mut adjacency: BTreeMap<u32, Vec<(u32, String)>> = BTreeMap::new();
    for device in &graph.devices {
        for (_, a) in &device.pins {
            for (_, b) in &device.pins {
                if a != b {
                    adjacency
                        .entry(*a)
                        .or_default()
                        .push((*b, device.id.clone()));
                }
            }
        }
    }
    for neighbors in adjacency.values_mut() {
        neighbors.sort();
        neighbors.dedup();
    }
    let mut queue = VecDeque::from([start]);
    let mut previous: BTreeMap<u32, (u32, String)> = BTreeMap::new();
    let mut seen = BTreeSet::from([start]);
    while let Some(net) = queue.pop_front() {
        for (next, device) in adjacency.get(&net).into_iter().flatten() {
            if seen.insert(*next) {
                previous.insert(*next, (net, device.clone()));
                if *next == goal {
                    let mut steps = vec![format!("net:{goal}")];
                    let mut cursor = goal;
                    while cursor != start {
                        let (prior, via) = &previous[&cursor];
                        steps.push(format!("device:{via}"));
                        steps.push(format!("net:{prior}"));
                        cursor = *prior;
                    }
                    steps.reverse();
                    return steps;
                }
                queue.push_back(*next);
            }
        }
    }
    Vec::new()
}

fn stable_fingerprint(text: &str) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in text.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("lvs:{hash:016x}")
}

fn result(
    status: ProductionLvsStatus,
    reason: impl Into<String>,
    state: Option<SearchState>,
    mismatches: Vec<ProductionMismatch>,
    explored_states: usize,
) -> ProductionLvsResult {
    let reason = reason.into();
    let canonical = format!("{status:?}|{reason}|{mismatches:?}");
    let (device_mappings, net_mappings) = if let Some(state) = state {
        (
            state
                .ref_to_layout_device
                .into_iter()
                .map(|(reference_id, layout_id)| DeviceMapping {
                    reference_id,
                    layout_id,
                })
                .collect(),
            state
                .ref_to_layout_net
                .into_iter()
                .map(|(reference_net, layout_net)| NetMapping {
                    reference_net,
                    layout_net,
                })
                .collect(),
        )
    } else {
        (Vec::new(), Vec::new())
    };
    ProductionLvsResult {
        status,
        reason,
        device_mappings,
        net_mappings,
        mismatches,
        explored_states,
        fingerprint: stable_fingerprint(&canonical),
    }
}

fn bind_named_seeds(
    layout: &MatchGraph<u32>,
    reference: &MatchGraph<String>,
    layout_netlist: &DetailedExtractedNetlist,
    reference_netlist: &DetailedRefNetlist,
    options: &ProductionCompareOptions,
    state: &mut SearchState,
) -> Result<(), ProductionMismatch> {
    let layout_names = name_index(layout).map_err(|explanation| {
        let canonical = format!("seed|layout|{explanation}");
        ProductionMismatch::SeedConflict {
            layout_name: String::new(),
            reference_name: String::new(),
            explanation,
            fingerprint: stable_fingerprint(&canonical),
        }
    })?;
    let reference_names = name_index(reference).map_err(|explanation| {
        let canonical = format!("seed|reference|{explanation}");
        ProductionMismatch::SeedConflict {
            layout_name: String::new(),
            reference_name: String::new(),
            explanation,
            fingerprint: stable_fingerprint(&canonical),
        }
    })?;

    let mut aliases = layout_netlist.seed_aliases.clone();
    aliases.extend(reference_netlist.seed_aliases.clone());
    aliases.extend(options.seed_pairs.clone());
    for name in layout_names.keys() {
        if reference_names.contains_key(name) {
            aliases.entry(name.clone()).or_insert_with(|| name.clone());
        }
    }
    for (layout_name, reference_name) in aliases {
        let layout_key = canonical_name(&layout_name);
        let reference_key = canonical_name(&reference_name);
        let Some(layout_net) = layout_names.get(&layout_key) else {
            let explanation = format!("layout seed name '{layout_name}' was not found");
            let canonical = format!("seed|{layout_name}|{reference_name}|{explanation}");
            return Err(ProductionMismatch::SeedConflict {
                layout_name,
                reference_name,
                explanation,
                fingerprint: stable_fingerprint(&canonical),
            });
        };
        let Some(reference_net) = reference_names.get(&reference_key) else {
            let explanation = format!("reference seed name '{reference_name}' was not found");
            let canonical = format!("seed|{layout_name}|{reference_name}|{explanation}");
            return Err(ProductionMismatch::SeedConflict {
                layout_name,
                reference_name,
                explanation,
                fingerprint: stable_fingerprint(&canonical),
            });
        };
        if !assign_net(state, reference_net, *layout_net) {
            let explanation = format!(
                "seed '{layout_name}' -> '{reference_name}' conflicts with an existing net mapping"
            );
            let canonical = format!("seed|{layout_name}|{reference_name}|{explanation}");
            return Err(ProductionMismatch::SeedConflict {
                layout_name,
                reference_name,
                explanation,
                fingerprint: stable_fingerprint(&canonical),
            });
        }
    }

    if options.require_named_ports {
        for identity in reference.nets.values() {
            for name in identity.ports.keys().chain(identity.globals.iter()) {
                if !layout_names.contains_key(&canonical_name(name)) {
                    let explanation =
                        format!("named reference port/global '{name}' has no layout binding");
                    let canonical = format!("seed|required|{name}|{explanation}");
                    return Err(ProductionMismatch::SeedConflict {
                        layout_name: name.clone(),
                        reference_name: name.clone(),
                        explanation,
                        fingerprint: stable_fingerprint(&canonical),
                    });
                }
            }
        }
    }
    Ok(())
}

/// Deterministic exact device/net graph matching.  Color/signature bucketing is
/// only a candidate filter; correctness comes from the explicit bijective
/// terminal mapping search. Exceeding `max_search_states` returns
/// `Indeterminate`, never `Match`.
pub fn compare_production(
    layout_netlist: &DetailedExtractedNetlist,
    reference_netlist: &DetailedRefNetlist,
    options: &ProductionCompareOptions,
) -> ProductionLvsResult {
    if options.max_search_states == 0 {
        let mismatch = ProductionMismatch::Capacity {
            explored_states: 0,
            limit: 0,
            fingerprint: stable_fingerprint("capacity|0|0"),
        };
        return result(
            ProductionLvsStatus::Indeterminate,
            "deterministic search is disabled by a zero state limit",
            None,
            vec![mismatch],
            0,
        );
    }
    if !layout_netlist.open_candidates.is_empty() {
        let candidate = &layout_netlist.open_candidates[0];
        let canonical = format!(
            "open-candidate|{}|{}|{}|{}",
            candidate.net_a, candidate.net_b, candidate.reason, candidate.hierarchy_path
        );
        let witness = TopologyWitness {
            kind: TopologyConflictKind::Open,
            layout_devices: Vec::new(),
            reference_devices: Vec::new(),
            layout_nets: vec![candidate.net_a, candidate.net_b],
            reference_nets: Vec::new(),
            path: Vec::new(),
            hierarchy_paths: vec![candidate.hierarchy_path.clone()],
            explanation: candidate.reason.clone(),
        };
        return result(
            ProductionLvsStatus::Mismatch,
            "layout extraction reported an unresolved open candidate",
            None,
            vec![ProductionMismatch::Topology {
                witness,
                fingerprint: stable_fingerprint(&canonical),
            }],
            0,
        );
    }

    let layout = match build_graph(layout_netlist, "layout", options) {
        Ok(graph) => graph,
        Err(errors) => {
            return result(
                ProductionLvsStatus::Error,
                "invalid layout netlist input",
                None,
                errors,
                0,
            )
        }
    };
    let reference = match build_graph(reference_netlist, "reference", options) {
        Ok(graph) => graph,
        Err(errors) => {
            return result(
                ProductionLvsStatus::Error,
                "invalid reference netlist input",
                None,
                errors,
                0,
            )
        }
    };

    let mut layout_counts = BTreeMap::new();
    let mut reference_counts = BTreeMap::new();
    for device in &layout.devices {
        *layout_counts.entry(device.base.clone()).or_insert(0usize) += 1;
    }
    for device in &reference.devices {
        *reference_counts
            .entry(device.base.clone())
            .or_insert(0usize) += 1;
    }
    for signature in layout_counts
        .keys()
        .chain(reference_counts.keys())
        .collect::<BTreeSet<_>>()
    {
        let layout_count = layout_counts.get(signature).copied().unwrap_or(0);
        let reference_count = reference_counts.get(signature).copied().unwrap_or(0);
        if layout_count != reference_count {
            let canonical = format!("device-count|{signature}|{layout_count}|{reference_count}");
            return result(
                ProductionLvsStatus::Mismatch,
                "device signature count mismatch",
                None,
                vec![ProductionMismatch::DeviceCount {
                    signature: (*signature).clone(),
                    layout: layout_count,
                    reference: reference_count,
                    fingerprint: stable_fingerprint(&canonical),
                }],
                0,
            );
        }
    }

    let mut initial = SearchState::default();
    if let Err(mismatch) = bind_named_seeds(
        &layout,
        &reference,
        layout_netlist,
        reference_netlist,
        options,
        &mut initial,
    ) {
        return result(
            ProductionLvsStatus::Mismatch,
            "named net seed conflict",
            None,
            vec![mismatch],
            0,
        );
    }

    let candidates: Vec<Vec<usize>> = reference
        .devices
        .iter()
        .map(|reference_device| {
            layout
                .devices
                .iter()
                .enumerate()
                .filter_map(|(index, layout_device)| {
                    (reference_device.base == layout_device.base).then_some(index)
                })
                .collect()
        })
        .collect();
    let mut order: Vec<usize> = (0..reference.devices.len()).collect();
    order.sort_by(|a, b| {
        candidates[*a]
            .len()
            .cmp(&candidates[*b].len())
            .then_with(|| reference.devices[*a].id.cmp(&reference.devices[*b].id))
    });

    let mut diagnostics = SearchDiagnostics::default();
    let solution = exact_search(
        &reference,
        &layout,
        options,
        &order,
        &candidates,
        0,
        initial,
        &mut diagnostics,
    );
    if let Some(mut solution) = solution {
        let remaining_reference: Vec<String> = reference
            .nets
            .keys()
            .filter(|net| !solution.ref_to_layout_net.contains_key(*net))
            .cloned()
            .collect();
        let remaining_layout: Vec<u32> = layout
            .nets
            .keys()
            .filter(|net| !solution.layout_to_ref_net.contains_key(*net))
            .copied()
            .collect();
        if remaining_reference.len() != remaining_layout.len() {
            let explanation = format!(
                "unmatched net count differs after device mapping: layout {} vs reference {}",
                remaining_layout.len(),
                remaining_reference.len()
            );
            let hierarchy_paths = remaining_layout
                .iter()
                .filter_map(|net| layout_netlist.nets.get(net))
                .map(|identity| identity.hierarchy_path.clone())
                .chain(
                    remaining_reference
                        .iter()
                        .filter_map(|net| reference_netlist.nets.get(net))
                        .map(|identity| identity.hierarchy_path.clone()),
                )
                .collect();
            let witness = TopologyWitness {
                kind: if layout.nets.len() < reference.nets.len() {
                    TopologyConflictKind::Short
                } else {
                    TopologyConflictKind::Open
                },
                layout_devices: Vec::new(),
                reference_devices: Vec::new(),
                layout_nets: remaining_layout,
                reference_nets: remaining_reference,
                path: Vec::new(),
                hierarchy_paths,
                explanation: explanation.clone(),
            };
            let canonical = format!("unmatched-net-count|{witness:?}");
            return result(
                ProductionLvsStatus::Mismatch,
                explanation,
                None,
                vec![ProductionMismatch::Topology {
                    witness,
                    fingerprint: stable_fingerprint(&canonical),
                }],
                diagnostics.explored,
            );
        }
        for (reference_net, layout_net) in remaining_reference.into_iter().zip(remaining_layout) {
            assign_net(&mut solution, &reference_net, layout_net);
        }
        return result(
            ProductionLvsStatus::Match,
            "deterministic body-aware graph match",
            Some(solution),
            Vec::new(),
            diagnostics.explored,
        );
    }

    if diagnostics.capacity_hit {
        let mismatch = ProductionMismatch::Capacity {
            explored_states: diagnostics.explored,
            limit: options.max_search_states,
            fingerprint: stable_fingerprint(&format!(
                "capacity|{}|{}",
                diagnostics.explored, options.max_search_states
            )),
        };
        return result(
            ProductionLvsStatus::Indeterminate,
            "deterministic search capacity exceeded",
            None,
            vec![mismatch],
            diagnostics.explored,
        );
    }
    if let Some((reference_index, layout_index, delta)) = diagnostics.first_property {
        let reference_device = &reference.devices[reference_index];
        let layout_device = &layout.devices[layout_index];
        let canonical = format!(
            "property|{}|{}|{:?}",
            layout_device.id, reference_device.id, delta
        );
        return result(
            ProductionLvsStatus::Mismatch,
            "device property mismatch",
            None,
            vec![ProductionMismatch::Property {
                layout_device: layout_device.id.clone(),
                reference_device: reference_device.id.clone(),
                delta,
                hierarchy_paths: vec![layout_device.path.clone(), reference_device.path.clone()],
                fingerprint: stable_fingerprint(&canonical),
            }],
            diagnostics.explored,
        );
    }

    let (layout_devices, reference_devices, layout_nets, reference_nets, path, hierarchy_paths) =
        if let Some((reference_index, layout_index, assignment)) = diagnostics.first_conflict {
            let layout_device = &layout.devices[layout_index];
            let reference_device = &reference.devices[reference_index];
            let nets: Vec<u32> = assignment.iter().map(|(_, net)| *net).collect();
            let path = if nets.len() >= 2 {
                shortest_net_path(&layout, nets[0], nets[1])
            } else {
                Vec::new()
            };
            (
                vec![layout_device.id.clone()],
                vec![reference_device.id.clone()],
                nets,
                assignment.iter().map(|(net, _)| net.clone()).collect(),
                path,
                vec![layout_device.path.clone(), reference_device.path.clone()],
            )
        } else {
            let explanation =
                "matcher exhausted without recording a causal topology conflict".to_string();
            let mismatch = ProductionMismatch::Input {
                side: "matcher".into(),
                object: "exact-search".into(),
                explanation: explanation.clone(),
                fingerprint: stable_fingerprint(&format!("matcher-causal-gap|{explanation}")),
            };
            return result(
                ProductionLvsStatus::Error,
                explanation,
                None,
                vec![mismatch],
                diagnostics.explored,
            );
        };
    let explanation =
        "equal device counts cannot satisfy a bijective terminal/net mapping".to_string();
    let witness = TopologyWitness {
        kind: TopologyConflictKind::PartitionConflict,
        layout_devices,
        reference_devices,
        layout_nets,
        reference_nets,
        path,
        hierarchy_paths,
        explanation: explanation.clone(),
    };
    let canonical = format!("topology|{witness:?}");
    result(
        ProductionLvsStatus::Mismatch,
        explanation,
        None,
        vec![ProductionMismatch::Topology {
            witness,
            fingerprint: stable_fingerprint(&canonical),
        }],
        diagnostics.explored,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn identity(id: &str) -> DeviceIdentity {
        DeviceIdentity {
            stable_id: id.into(),
            hierarchy_path: HierarchyPath::root("top"),
            model: Some("nch".into()),
            device_class: Some("core".into()),
            flavor: DeviceFlavor::Standard,
        }
    }

    fn layout_mos(id: &str, d: u32, g: u32, s: u32, b: u32) -> MosDeviceRecord<u32> {
        MosDeviceRecord {
            identity: identity(id),
            kind: DeviceKind::Nmos,
            drain: d,
            gate: g,
            source: s,
            body: TerminalConnection::Connected(b),
            well: None,
            substrate: None,
            properties: BTreeMap::from([
                (
                    "L".into(),
                    TypedProperty::exact(100.0, PropertyUnit::Nanometer),
                ),
                ("M".into(), TypedProperty::exact(1.0, PropertyUnit::Count)),
                ("NF".into(), TypedProperty::exact(1.0, PropertyUnit::Count)),
                (
                    "W".into(),
                    TypedProperty::exact(1000.0, PropertyUnit::Nanometer),
                ),
            ]),
        }
    }

    fn reference_mos(id: &str, d: &str, g: &str, s: &str, b: &str) -> MosDeviceRecord<String> {
        let layout = layout_mos(id, 0, 1, 2, 3);
        MosDeviceRecord {
            identity: layout.identity,
            kind: layout.kind,
            drain: d.into(),
            gate: g.into(),
            source: s.into(),
            body: TerminalConnection::Connected(b.into()),
            well: None,
            substrate: None,
            properties: layout.properties,
        }
    }

    fn add_layout_net(netlist: &mut DetailedExtractedNetlist, id: u32, name: Option<&str>) {
        let mut labels = BTreeSet::new();
        if let Some(name) = name {
            labels.insert(name.into());
        }
        netlist.nets.insert(
            id,
            NetIdentity {
                id,
                labels,
                ports: BTreeMap::new(),
                globals: BTreeSet::new(),
                hierarchy_path: HierarchyPath::root("top"),
            },
        );
    }

    fn add_reference_net(netlist: &mut DetailedRefNetlist, id: &str, named: bool) {
        let mut labels = BTreeSet::new();
        if named {
            labels.insert(id.into());
        }
        netlist.nets.insert(
            id.into(),
            NetIdentity {
                id: id.into(),
                labels,
                ports: BTreeMap::new(),
                globals: BTreeSet::new(),
                hierarchy_path: HierarchyPath::root("top"),
            },
        );
    }

    fn one_mos(named: bool) -> (DetailedExtractedNetlist, DetailedRefNetlist) {
        let mut layout = DetailedExtractedNetlist::empty("top");
        layout.mos_devices.push(layout_mos("M0", 0, 1, 2, 3));
        for (id, name) in [(0, "D"), (1, "G"), (2, "S"), (3, "B")] {
            add_layout_net(&mut layout, id, named.then_some(name));
        }
        let mut reference = DetailedRefNetlist::empty("top");
        reference
            .mos_devices
            .push(reference_mos("M0", "D", "G", "S", "B"));
        for name in ["D", "G", "S", "B"] {
            add_reference_net(&mut reference, name, named);
        }
        (layout, reference)
    }

    #[test]
    fn legacy_adapter_never_treats_net_zero_as_resolved_body() {
        let legacy_layout = ExtractedNetlist {
            devices: vec![Device {
                kind: DeviceKind::Nmos,
                gate: 0,
                source: 1,
                drain: 2,
                body: 0,
                flavor: DeviceFlavor::Standard,
                w: 1000,
                l: 100,
                device_class: None,
                ..Default::default()
            }],
            bjt_devices: Vec::new(),
            net_count: 3,
            used_nets: 3,
            net_of_poly: Vec::new(),
            label_conflicts: Vec::new(),
            two_terminal: Vec::new(),
            floating_nets: Vec::new(),
            net_names: HashMap::new(),
        };
        let legacy_reference = RefNetlist {
            devices: vec![LegacyRefDeviceBuilder::new(DeviceKind::Nmos, "D", "G", "S")
                .dimensions_nm(1000, 100)
                .build()],
            net_seeds: HashMap::new(),
            ref_two_terminal: Vec::new(),
            ref_bjt: Vec::new(),
        };
        let layout = DetailedExtractedNetlist::from_legacy(&legacy_layout, "top");
        let reference = DetailedRefNetlist::from_legacy(&legacy_reference, "top");
        assert!(matches!(
            layout.mos_devices[0].body,
            TerminalConnection::Unresolved(_)
        ));
        assert_eq!(
            compare_production(&layout, &reference, &ProductionCompareOptions::default()).status,
            ProductionLvsStatus::Error
        );
        let options = ProductionCompareOptions {
            require_resolved_bulk: false,
            ..Default::default()
        };
        assert!(compare_production(&layout, &reference, &options)
            .status
            .is_match());
    }

    #[test]
    fn body_swap_is_a_seeded_topology_mismatch() {
        let (mut layout, mut reference) = one_mos(true);
        layout.mos_devices.push(layout_mos("M1", 4, 5, 6, 7));
        reference
            .mos_devices
            .push(reference_mos("M1", "D1", "G1", "S1", "B1"));
        for (id, name) in [(4, "D1"), (5, "G1"), (6, "S1"), (7, "B1")] {
            add_layout_net(&mut layout, id, Some(name));
            add_reference_net(&mut reference, name, true);
        }
        layout.mos_devices[0].body = TerminalConnection::Connected(7);
        layout.mos_devices[1].body = TerminalConnection::Connected(3);
        let compared = compare_production(&layout, &reference, &Default::default());
        assert_eq!(compared.status, ProductionLvsStatus::Mismatch);
        assert!(compared.reason.contains("terminal/net mapping"));
    }

    #[test]
    fn named_seeds_constrain_otherwise_isomorphic_polarity() {
        let mut layout = DetailedExtractedNetlist::empty("top");
        add_layout_net(&mut layout, 0, Some("A"));
        add_layout_net(&mut layout, 1, Some("B"));
        layout.two_terminal_devices.push(TwoTerminalRecord {
            identity: identity("D0"),
            kind: TwoTerminalKind::Diode,
            terminal_a: 1,
            terminal_b: 0,
            properties: BTreeMap::new(),
        });
        let mut reference = DetailedRefNetlist::empty("top");
        add_reference_net(&mut reference, "A", true);
        add_reference_net(&mut reference, "B", true);
        reference.two_terminal_devices.push(TwoTerminalRecord {
            identity: identity("D0"),
            kind: TwoTerminalKind::Diode,
            terminal_a: "A".into(),
            terminal_b: "B".into(),
            properties: BTreeMap::new(),
        });
        let compared = compare_production(&layout, &reference, &Default::default());
        assert_eq!(compared.status, ProductionLvsStatus::Mismatch);

        for net in layout.nets.values_mut() {
            net.labels.clear();
        }
        for net in reference.nets.values_mut() {
            net.labels.clear();
        }
        assert!(compare_production(&layout, &reference, &Default::default())
            .status
            .is_match());
    }

    #[test]
    fn source_drain_swap_is_legal_but_gate_swap_is_not() {
        let (layout, mut reference) = one_mos(true);
        reference.mos_devices[0].drain = "S".into();
        reference.mos_devices[0].source = "D".into();
        assert!(compare_production(&layout, &reference, &Default::default())
            .status
            .is_match());

        reference.mos_devices[0].gate = "D".into();
        reference.mos_devices[0].drain = "G".into();
        let compared = compare_production(&layout, &reference, &Default::default());
        assert_eq!(compared.status, ProductionLvsStatus::Mismatch);
    }

    #[test]
    fn equal_device_counts_with_wrong_topology_remain_mismatch() {
        let mut layout = DetailedExtractedNetlist::empty("top");
        for net in 0..3 {
            add_layout_net(&mut layout, net, None);
        }
        for id in ["R0", "R1"] {
            layout.two_terminal_devices.push(TwoTerminalRecord {
                identity: identity(id),
                kind: TwoTerminalKind::Resistor,
                terminal_a: 0,
                terminal_b: 1,
                properties: BTreeMap::new(),
            });
        }
        let mut reference = DetailedRefNetlist::empty("top");
        for net in ["A", "B", "C"] {
            add_reference_net(&mut reference, net, false);
        }
        reference.two_terminal_devices.push(TwoTerminalRecord {
            identity: identity("R0"),
            kind: TwoTerminalKind::Resistor,
            terminal_a: "A".into(),
            terminal_b: "B".into(),
            properties: BTreeMap::new(),
        });
        reference.two_terminal_devices.push(TwoTerminalRecord {
            identity: identity("R1"),
            kind: TwoTerminalKind::Resistor,
            terminal_a: "B".into(),
            terminal_b: "C".into(),
            properties: BTreeMap::new(),
        });
        let compared = compare_production(&layout, &reference, &Default::default());
        assert_eq!(compared.status, ProductionLvsStatus::Mismatch);
        assert!(matches!(
            compared.mismatches.first(),
            Some(ProductionMismatch::Topology { .. })
        ));
    }

    #[test]
    fn unmatched_net_count_reports_only_derived_identity_paths() {
        let mut layout = DetailedExtractedNetlist::empty("layout_top");
        add_layout_net(&mut layout, 0, None);
        layout.nets.get_mut(&0).unwrap().hierarchy_path =
            HierarchyPath(vec!["layout/isolated-0".into()]);
        let mut reference = DetailedRefNetlist::empty("reference_top");
        add_reference_net(&mut reference, "A", false);
        add_reference_net(&mut reference, "B", false);
        reference.nets.get_mut("A").unwrap().hierarchy_path =
            HierarchyPath(vec!["reference/isolated-A".into()]);
        reference.nets.get_mut("B").unwrap().hierarchy_path =
            HierarchyPath(vec!["reference/isolated-B".into()]);

        let compared = compare_production(&layout, &reference, &Default::default());
        assert_eq!(compared.status, ProductionLvsStatus::Mismatch);
        let Some(ProductionMismatch::Topology { witness, .. }) = compared.mismatches.first() else {
            panic!("missing unmatched-net witness: {compared:#?}");
        };
        assert_eq!(witness.kind, TopologyConflictKind::Short);
        assert_eq!(witness.layout_nets, vec![0]);
        assert_eq!(witness.reference_nets, vec!["A", "B"]);
        assert_eq!(
            witness.hierarchy_paths,
            vec![
                HierarchyPath(vec!["layout/isolated-0".into()]),
                HierarchyPath(vec!["reference/isolated-A".into()]),
                HierarchyPath(vec!["reference/isolated-B".into()]),
            ]
        );
    }

    #[test]
    fn property_delta_reports_units_tolerance_and_stable_fingerprint() {
        let (mut layout, mut reference) = one_mos(false);
        layout.mos_devices[0].properties.get_mut("W").unwrap().value = 1010.0;
        reference.mos_devices[0]
            .properties
            .get_mut("W")
            .unwrap()
            .tolerance = NumericTolerance {
            absolute: 5.0,
            relative_percent: 0.0,
        };
        let first = compare_production(&layout, &reference, &Default::default());
        let second = compare_production(&layout, &reference, &Default::default());
        assert_eq!(first.status, ProductionLvsStatus::Mismatch);
        assert_eq!(first.fingerprint, second.fingerprint);
        let Some(ProductionMismatch::Property { delta, .. }) = first.mismatches.first() else {
            panic!("expected property witness: {:?}", first.mismatches);
        };
        assert_eq!(delta.property, "W");
        assert_eq!(delta.unit, Some(PropertyUnit::Nanometer));
        assert_eq!(delta.tolerance.unwrap().absolute, 5.0);
    }

    #[test]
    fn search_capacity_is_indeterminate_never_clean() {
        let (layout, reference) = one_mos(false);
        let options = ProductionCompareOptions {
            max_search_states: 0,
            ..Default::default()
        };
        let compared = compare_production(&layout, &reference, &options);
        assert_eq!(compared.status, ProductionLvsStatus::Indeterminate);
        assert!(!compared.status.is_match());
    }
}
