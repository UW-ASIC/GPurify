//! ERC — electrical rule checking on extracted layout, including the
//! tapeout-oriented signoff analyses (antenna, density/CMP, IR drop,
//! electromigration, reliability, ESD/latch-up).
//!
//! Operates on a GeometryStore + Deck, using LVS extraction results for
//! connectivity. One rule per file in `rules/`, globbed at compile time by
//! build.rs; each implements [`crate::rule::Rule`] over [`ErcCtx`].
//!
//! Heuristic checks report plain [`ErcViolation`]s. The signoff analyses
//! report typed [`CheckReport`]s with four states; [`CheckStatus::NotRun`] and
//! [`CheckStatus::Error`] are not clean.  Electrical analyses need stimuli and
//! foundry-qualified limits; silently substituting defaults would create a
//! dangerous false-clean result.

pub mod esd_extract;
#[cfg(feature = "gpu")]
pub mod gpu;
mod power;
pub mod power_extract;
pub mod substrate_extract;

// Re-exports so internal `crate::*` paths resolve after workspace split
pub use gdsverify_backend as backend;
pub use gdsverify_backend::rule;
pub use gdsverify_core::geometry;
pub use gdsverify_core::params;
pub use gdsverify_lvs as lvs;
pub use gdsverify_pex as pex;

use crate::backend::{Backend, BackendTelemetry};
use crate::geometry::{Bbox, GeometryStore, LayerId, PolyId};
use crate::lvs::{extract_netlist, ExtractedNetlist};
use crate::params::Deck;

/// Public error surface for the ERC entry point that used to return
/// `Result<_, String>`. `Display` reproduces the original message verbatim,
/// so callers matching on substrings keep working.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ErcError {
    /// Connectivity extraction (LVS) failed.
    #[error("{0}")]
    Extraction(String),
}

impl From<crate::lvs::LvsError> for ErcError {
    fn from(e: crate::lvs::LvsError) -> Self {
        ErcError::Extraction(e.to_string())
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ErcViolation {
    pub check: String,
    pub detail: String,
    pub x: i32,
    pub y: i32,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ErcReport {
    pub violations: Vec<ErcViolation>,
    pub signoff: SignoffSuiteReport,
}

impl ErcReport {
    #[must_use]
    pub fn by_check(&self, check: &str) -> Vec<&ErcViolation> {
        self.violations
            .iter()
            .filter(|v| v.check == check)
            .collect()
    }
}

/// Everything every ERC rule reads. The netlist is extracted once per run
/// (exactly as before, when it was shared through an `Arc`) and lent to the
/// rules by reference.
#[derive(Clone, Copy)]
pub struct ErcCtx<'a> {
    pub store: &'a GeometryStore,
    pub deck: &'a Deck,
    pub ext: &'a ExtractedNetlist,
    /// Tapeout signoff inputs; a check whose input is missing reports NotRun.
    pub config: &'a SignoffConfig,
    /// Power-grid solve shared by IR-drop and EM (`run_erc` computes it once).
    /// `None` means no power config was supplied.
    pub power: Option<&'a Result<PowerSolution, String>>,
}

/// Nets connected to any extracted device terminal: MOS (gate/source/drain),
/// BJT (collector/base/emitter), and two-terminal (resistor/cap/diode)
/// devices. Rules that classify a net as "not connected to any device" must
/// use this, not `ext.devices` alone — a pure-BJT or passive-only block is
/// not an unconnected one.
#[must_use]
pub fn device_connected_nets(ext: &ExtractedNetlist) -> std::collections::HashSet<u32> {
    let mut nets = std::collections::HashSet::new();
    for d in &ext.devices {
        nets.extend([d.gate, d.source, d.drain]);
    }
    for d in &ext.bjt_devices {
        nets.extend([d.collector, d.base, d.emitter]);
    }
    for d in &ext.two_terminal {
        nets.extend([d.terminal_a, d.terminal_b]);
    }
    nets
}

/// One finding from the merged engine: a heuristic violation, or one typed
/// signoff check report.
#[derive(Debug, Clone)]
pub enum ErcFinding {
    Violation(ErcViolation),
    Antenna(AntennaReport),
    DensityCmp(DensityCmpReport),
    IrDrop(IrDropReport),
    Electromigration(ElectromigrationReport),
    Reliability(ReliabilityReport),
    EsdLatchup(EsdLatchupReport),
}

/// A boxed ERC rule, usable with any context lifetime.
pub type BoxedRule = Box<dyn for<'a> crate::rule::Rule<ErcCtx<'a>, Finding = ErcFinding>>;

/// Adapts a `Finding = ErcViolation` rule to the merged finding type, so the
/// heuristic checks stay written against plain violations.
pub struct Wrap<R>(pub R);

impl<'a, R> crate::rule::Rule<ErcCtx<'a>> for Wrap<R>
where
    R: for<'b> crate::rule::Rule<ErcCtx<'b>, Finding = ErcViolation>,
{
    type Finding = ErcFinding;

    fn id(&self) -> &str {
        self.0.id()
    }

    fn check(&self, ctx: &ErcCtx<'a>, backend: Backend) -> Vec<ErcFinding> {
        self.0
            .check(ctx, backend)
            .into_iter()
            .map(ErcFinding::Violation)
            .collect()
    }
}

pub mod rules {
    pub use super::BoxedRule;
    /// One per rule file: build the rule from the deck, or `None` when the
    /// rule is inapplicable for this deck.  Signoff rules always mount; each
    /// one reports `NotRun` itself when its input is missing, so a missing
    /// config never silently drops a check.
    pub type Factory = fn(&crate::params::Deck) -> Option<BoxedRule>;
    include!(concat!(env!("OUT_DIR"), "/erc_rules.rs"));
}

pub use rules::multiple_drivers::MultipleDriverCheck;
pub use rules::tie_high_low::TieHighLowCheck;

pub use esd_extract::{
    extract_esd_evidence, EsdClamp, EsdEvidence, EsdPath, GuardRing, IoPad, PadDirection,
};
pub use power::{
    solve_power_grid, BranchCurrent, ElectromigrationConfig, IrDropConfig, NodeVoltage, PowerEdge,
    PowerEdgeKind, PowerGrid, PowerNode, PowerSignoffConfig, PowerSolution, PowerSolveConfig,
};
pub use power_extract::{extract_power_grid, identify_power_nets, PowerNetClassification};
pub use rules::antenna::check_fabrication_stage_antenna;
pub use rules::antenna::{
    check_antenna, check_antenna_from_deck, AntennaCollector, AntennaConfig, AntennaDiode,
    AntennaGate, AntennaMeasurement, AntennaNetResult, AntennaReport, AntennaRule,
};
pub use rules::density_cmp::{
    check_density_cmp, CmpModel, DensityCmpConfig, DensityCmpReport, DensityCmpRule,
    DensityWindowResult,
};
pub use rules::electromigration::{
    analyze_electromigration, ElectromigrationReport, EmBranchResult,
};
pub use rules::esd_latchup::{
    check_esd_latchup, EsdEdge, EsdLatchupConfig, EsdLatchupReport, EsdNode, EsdNodeKind,
    EsdPathRequirement, EsdPathResult, GuardRingEvidence, LatchupSite,
};
pub use rules::ir_drop::{analyze_ir_drop, IrDropReport};
pub use rules::reliability::{
    check_reliability, derive_thermal_stresses, derive_voltage_stresses, AgingStress,
    AgingStressResult, ReliabilityConfig, ReliabilityReport, ThermalStress, VoltageStress,
};
pub use substrate_extract::{
    extract_substrate_evidence, LatchupSeverity, LatchupSite as SubstrateLatchupSite,
    SubstrateEvidence, SubstrateTap, WellRegion, WellType,
};

/// Stable identity for every tapeout signoff check in this engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SignoffCheck {
    Antenna,
    DensityCmp,
    IrDrop,
    Electromigration,
    Reliability,
    EsdLatchup,
}

/// A check is clean only when it ran successfully and found no violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CheckStatus {
    Clean,
    Violations,
    NotRun,
    Error,
}

/// Common violation record used by all signoff analyses.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SignoffViolation {
    pub check: SignoffCheck,
    pub rule_id: String,
    pub message: String,
    pub location: Option<(i32, i32)>,
    pub measured: Option<f64>,
    pub limit: Option<f64>,
    pub units: String,
    #[serde(default)]
    pub evidence_id: Option<String>,
}

/// Status and diagnostics common to all typed check reports.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CheckReport {
    pub check: SignoffCheck,
    pub status: CheckStatus,
    pub violations: Vec<SignoffViolation>,
    pub diagnostics: Vec<String>,
}

impl CheckReport {
    pub fn clean(check: SignoffCheck) -> Self {
        Self {
            check,
            status: CheckStatus::Clean,
            violations: Vec::new(),
            diagnostics: Vec::new(),
        }
    }

    pub fn not_run(check: SignoffCheck, reason: impl Into<String>) -> Self {
        Self {
            check,
            status: CheckStatus::NotRun,
            violations: Vec::new(),
            diagnostics: vec![reason.into()],
        }
    }

    pub fn error(check: SignoffCheck, reason: impl Into<String>) -> Self {
        Self {
            check,
            status: CheckStatus::Error,
            violations: Vec::new(),
            diagnostics: vec![reason.into()],
        }
    }

    pub(crate) fn from_violations(
        check: SignoffCheck,
        violations: Vec<SignoffViolation>,
        diagnostics: Vec<String>,
    ) -> Self {
        let status = if violations.is_empty() {
            CheckStatus::Clean
        } else {
            CheckStatus::Violations
        };
        Self {
            check,
            status,
            violations,
            diagnostics,
        }
    }

    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.status == CheckStatus::Clean
    }

    #[must_use]
    pub fn is_blocking(&self) -> bool {
        !self.is_clean()
    }
}

/// Inputs for all six requested signoff families.
#[derive(Debug, Clone, Default)]
pub struct SignoffConfig {
    pub antenna: Option<AntennaConfig>,
    pub density_cmp: Option<DensityCmpConfig>,
    pub power: Option<PowerSignoffConfig>,
    pub reliability: Option<ReliabilityConfig>,
    pub esd_latchup: Option<EsdLatchupConfig>,
    /// Fabrication layer order for stage-aware antenna analysis.
    pub layer_order: Option<Vec<LayerId>>,
}

/// One report object for a tapeout gate.  `all_clean()` requires all six checks
/// to have actually run; `NOT_RUN` is therefore blocking by construction.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignoffSuiteReport {
    pub antenna: AntennaReport,
    pub density_cmp: DensityCmpReport,
    pub ir_drop: IrDropReport,
    pub electromigration: ElectromigrationReport,
    pub reliability: ReliabilityReport,
    pub esd_latchup: EsdLatchupReport,
}

impl SignoffSuiteReport {
    /// Fail-closed suite for when the shared ERC context cannot be built at
    /// all (connectivity extraction failed): every check reports `Error`.
    pub(crate) fn all_error(reason: &str) -> Self {
        Self {
            antenna: AntennaReport::error(reason),
            density_cmp: DensityCmpReport::error(reason),
            ir_drop: IrDropReport::error(reason),
            electromigration: ElectromigrationReport::error(reason),
            reliability: ReliabilityReport::error(reason),
            esd_latchup: EsdLatchupReport::error(reason),
        }
    }

    #[must_use]
    pub fn checks(&self) -> [&CheckReport; 6] {
        [
            &self.antenna.check,
            &self.density_cmp.check,
            &self.ir_drop.check,
            &self.electromigration.check,
            &self.reliability.check,
            &self.esd_latchup.check,
        ]
    }

    #[must_use]
    pub fn all_clean(&self) -> bool {
        self.checks().iter().all(|r| r.is_clean())
    }

    #[must_use]
    pub fn blocking_checks(&self) -> Vec<SignoffCheck> {
        self.checks()
            .iter()
            .filter(|r| r.is_blocking())
            .map(|r| r.check)
            .collect()
    }
}

/// Extract the netlist once, auto-derive a power grid if none was supplied,
/// solve it, mount every rule, run them, and assemble the report. Shared by
/// both the CPU entry (`run_erc`) and the forced-backend entry.
fn run_erc_inner(
    store: &GeometryStore,
    deck: &Deck,
    config: &SignoffConfig,
    ext: &ExtractedNetlist,
    backend: Backend,
) -> ErcReport {
    // ponytail: auto-extract power grid when config.power is None but we have connectivity.
    // This is a best-effort fallback; explicit config is always preferred.
    let auto_power = if config.power.is_none() && !ext.net_names.is_empty() {
        let classification = power_extract::identify_power_nets(deck, &ext.net_names);
        if !classification.power_nets.is_empty() || !classification.ground_nets.is_empty() {
            let grid = power_extract::extract_power_grid(store, deck, ext, &classification);
            if !grid.nodes.is_empty() && !grid.edges.is_empty() {
                Some(PowerSignoffConfig {
                    grid,
                    solver: PowerSolveConfig::default(),
                    ir_drop: None,
                    electromigration: None,
                })
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    let effective_power = config.power.as_ref().or(auto_power.as_ref());
    let power_solve = effective_power.map(|p| solve_power_grid(&p.grid, &p.solver));
    let ctx = ErcCtx {
        store,
        deck,
        ext,
        config,
        power: power_solve.as_ref(),
    };
    let mounted: Vec<BoxedRule> = rules::FACTORIES.iter().filter_map(|f| f(deck)).collect();

    let mut violations = Vec::new();
    let mut antenna = None;
    let mut density_cmp = None;
    let mut ir_drop = None;
    let mut electromigration = None;
    let mut reliability = None;
    let mut esd_latchup = None;
    for finding in crate::rule::run_rules(&mounted, &ctx, backend) {
        match finding {
            ErcFinding::Violation(v) => violations.push(v),
            ErcFinding::Antenna(r) => antenna = Some(r),
            ErcFinding::DensityCmp(r) => density_cmp = Some(r),
            ErcFinding::IrDrop(r) => ir_drop = Some(r),
            ErcFinding::Electromigration(r) => electromigration = Some(r),
            ErcFinding::Reliability(r) => reliability = Some(r),
            ErcFinding::EsdLatchup(r) => esd_latchup = Some(r),
        }
    }
    // Every signoff family has exactly one always-mounted rule; a missing
    // finding is a registry bug, not a signoff result.
    ErcReport {
        violations,
        signoff: SignoffSuiteReport {
            antenna: antenna.expect("antenna signoff rule did not report"),
            density_cmp: density_cmp.expect("density/CMP signoff rule did not report"),
            ir_drop: ir_drop.expect("IR-drop signoff rule did not report"),
            electromigration: electromigration
                .expect("electromigration signoff rule did not report"),
            reliability: reliability.expect("reliability signoff rule did not report"),
            esd_latchup: esd_latchup.expect("ESD/latch-up signoff rule did not report"),
        },
    }
}

/// Run the merged ERC engine: heuristic electrical checks plus the signoff
/// suite, sharing one extracted netlist and one power-grid solve.  Missing
/// signoff input is reported as `NOT_RUN`; extraction failure fails closed.
#[must_use]
pub fn run_erc(store: &GeometryStore, deck: &Deck, config: &SignoffConfig) -> ErcReport {
    let ext = match extract_netlist(store, deck) {
        Ok(ext) => ext,
        Err(e) => {
            let reason = format!("ERC connectivity extraction failed: {e}");
            return ErcReport {
                violations: vec![ErcViolation {
                    check: "erc_extraction_error".into(),
                    detail: reason.clone(),
                    x: 0,
                    y: 0,
                }],
                signoff: SignoffSuiteReport::all_error(&reason),
            };
        }
    };
    // ERC's public entry is CPU-backed (as at baseline).
    run_erc_inner(store, deck, config, &ext, Backend::Cpu)
}

/// Forced-backend ERC: same as `run_erc` but with explicit backend + telemetry.
/// ponytail: ERC has no GPU seam of its own, so `Gpu` runs on CPU and telemetry
/// records actual = Cpu directly (no session plumbing).
pub fn run_erc_backend(
    store: &GeometryStore,
    deck: &Deck,
    config: &SignoffConfig,
    backend: crate::backend::Backend,
) -> Result<(ErcReport, BackendTelemetry), ErcError> {
    let ext = extract_netlist(store, deck)?;
    let report = run_erc_inner(store, deck, config, &ext, Backend::Cpu);
    let telemetry = BackendTelemetry::new(backend, Backend::Cpu);
    Ok((report, telemetry))
}

/// Return a bbox only when `p` is exactly an axis-aligned rectangle.
pub(crate) fn polygon_rect(store: &GeometryStore, p: PolyId) -> Option<Bbox> {
    let (s, e) = store.poly_range(p);
    if e - s != 4 {
        return None;
    }
    let bb = store.poly_bbox[p.0 as usize];
    if bb.width() <= 0 || bb.height() <= 0 {
        return None;
    }
    let mut corners = std::collections::BTreeSet::new();
    for edge in store.edges_of(p) {
        let pt = (edge.x0, edge.y0);
        if pt.0 != bb.xmin && pt.0 != bb.xmax {
            return None;
        }
        if pt.1 != bb.ymin && pt.1 != bb.ymax {
            return None;
        }
        corners.insert(pt);

        // A proper rectangle walks one horizontal or vertical side at a time.
        // Merely seeing the four bbox corners would also accept a self-crossing
        // bow-tie ordering, whose bbox area is not its polygon area.
        let next = (edge.x1, edge.y1);
        if (pt.0 == next.0) == (pt.1 == next.1) {
            return None;
        }
    }
    let bbox_area = i64::from(bb.width()) * i64::from(bb.height());
    if corners.len() == 4 && store.area(p) == bbox_area {
        Some(bb)
    } else {
        None
    }
}

/// Exact union area and perimeter for axis-aligned rectangles.
pub(crate) fn rect_union_metrics(rects: &[Bbox]) -> (f64, f64) {
    if rects.is_empty() {
        return (0.0, 0.0);
    }
    let mut xs: Vec<i32> = rects.iter().flat_map(|r| [r.xmin, r.xmax]).collect();
    let mut ys: Vec<i32> = rects.iter().flat_map(|r| [r.ymin, r.ymax]).collect();
    xs.sort_unstable();
    xs.dedup();
    ys.sort_unstable();
    ys.dedup();
    if xs.len() < 2 || ys.len() < 2 {
        return (0.0, 0.0);
    }

    let nx = xs.len() - 1;
    let ny = ys.len() - 1;
    let mut covered = vec![false; nx * ny];
    for ix in 0..nx {
        for iy in 0..ny {
            let x0 = xs[ix];
            let x1 = xs[ix + 1];
            let y0 = ys[iy];
            let y1 = ys[iy + 1];
            covered[ix * ny + iy] = rects
                .iter()
                .any(|r| r.xmin <= x0 && r.xmax >= x1 && r.ymin <= y0 && r.ymax >= y1);
        }
    }

    let mut area = 0.0;
    let mut perimeter = 0.0;
    let is_covered = |ix: isize, iy: isize| -> bool {
        ix >= 0
            && iy >= 0
            && (ix as usize) < nx
            && (iy as usize) < ny
            && covered[ix as usize * ny + iy as usize]
    };
    for ix in 0..nx {
        for iy in 0..ny {
            if !covered[ix * ny + iy] {
                continue;
            }
            let dx = f64::from(xs[ix + 1] - xs[ix]);
            let dy = f64::from(ys[iy + 1] - ys[iy]);
            area += dx * dy;
            if !is_covered(ix as isize - 1, iy as isize) {
                perimeter += dy;
            }
            if !is_covered(ix as isize + 1, iy as isize) {
                perimeter += dy;
            }
            if !is_covered(ix as isize, iy as isize - 1) {
                perimeter += dx;
            }
            if !is_covered(ix as isize, iy as isize + 1) {
                perimeter += dx;
            }
        }
    }
    (area, perimeter)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CheckStatus, Deck, GeometryStore};

    #[test]
    fn extraction_failure_is_not_clean() {
        let deck = Deck::from_json(
            r#"{
            "layers": {"met1": {"layer": 1, "datatype": 0}},
            "drc": {},
            "pex": {}
        }"#,
        )
        .unwrap();
        let report = run_erc(&GeometryStore::new(), &deck, &SignoffConfig::default());
        assert_eq!(report.by_check("erc_extraction_error").len(), 1);
        // Extraction failure fails the signoff suite closed too.
        assert!(report
            .signoff
            .checks()
            .iter()
            .all(|r| r.status == CheckStatus::Error));
    }

    fn antenna_deck() -> Deck {
        Deck::from_json(
            r#"{
            "layers": {
                "diff": {"layer": 1, "datatype": 0},
                "poly": {"layer": 2, "datatype": 0},
                "nsdm": {"layer": 3, "datatype": 0},
                "met1": {"layer": 4, "datatype": 0},
                "diode": {"layer": 5, "datatype": 0}
            },
            "drc": {},
            "pex": {},
            "connectivity": {
                "conductors": ["diff", "poly", "met1"],
                "intra_layer_touch": true
            },
            "device_recognition": {
                "mos": [{
                    "name": "nmos",
                    "gate_layer": "poly",
                    "channel_layer": "diff",
                    "type_implant": "nsdm",
                    "device_type": "nmos"
                }]
            }
        }"#,
        )
        .unwrap()
    }

    #[test]
    fn signoff_missing_inputs_are_not_clean() {
        let deck = antenna_deck();
        let report = run_erc(&GeometryStore::new(), &deck, &SignoffConfig::default()).signoff;
        assert!(!report.all_clean());
        assert_eq!(report.blocking_checks().len(), 6);
        assert!(report
            .checks()
            .iter()
            .all(|r| r.status == CheckStatus::NotRun));

        let invalid_density = run_erc(
            &GeometryStore::new(),
            &deck,
            &SignoffConfig {
                density_cmp: Some(DensityCmpConfig {
                    die: Bbox {
                        xmin: 0,
                        ymin: 0,
                        xmax: 100,
                        ymax: 100,
                    },
                    include_partial_windows: true,
                    rules: vec![DensityCmpRule {
                        id: "unknown.layer".into(),
                        layer: u16::MAX,
                        window_width: 100,
                        window_height: 100,
                        step_x: 100,
                        step_y: 100,
                        min_density: Some(0.0),
                        max_density: Some(1.0),
                        max_neighbor_delta: None,
                        cmp: None,
                    }],
                }),
                ..Default::default()
            },
        )
        .signoff;
        assert_eq!(invalid_density.density_cmp.check.status, CheckStatus::Error);
    }

    #[test]
    fn antenna_ratio_is_checked_per_connected_gate_net() {
        let deck = antenna_deck();
        let diff = deck.layers.id("diff").unwrap();
        let poly = deck.layers.id("poly").unwrap();
        let nsdm = deck.layers.id("nsdm").unwrap();
        let met1 = deck.layers.id("met1").unwrap();
        let mut store = GeometryStore::new();
        store.add_rect(diff, 0, 0, 100, 100);
        store.add_rect(poly, 40, -20, 20, 140);
        store.add_rect(nsdm, -10, -10, 120, 120);
        store.add_rect(met1, 40, -20, 1000, 1000);
        let report = check_antenna(
            &store,
            &deck,
            &AntennaConfig {
                cut_required: Some(false),
                rules: vec![AntennaRule {
                    id: "ant.m1".into(),
                    gates: vec![AntennaGate {
                        gate_layer: poly,
                        channel_layer: diff,
                    }],
                    collectors: vec![AntennaCollector {
                        layer: met1,
                        measurement: AntennaMeasurement::Area,
                    }],
                    max_egar: 100.0,
                    diode: None,
                }],
            },
        );
        assert_eq!(report.check.status, CheckStatus::Violations);
        assert_eq!(report.check.violations.len(), 1);
        assert!(report.nets[0].egar > 100.0);
    }

    #[test]
    fn antenna_diode_marker_is_attributed_to_its_conductor_net() {
        let deck = antenna_deck();
        let diff = deck.layers.id("diff").unwrap();
        let poly = deck.layers.id("poly").unwrap();
        let nsdm = deck.layers.id("nsdm").unwrap();
        let met1 = deck.layers.id("met1").unwrap();
        let diode = deck.layers.id("diode").unwrap();
        let mut store = GeometryStore::new();
        store.add_rect(diff, 0, 0, 100, 100);
        store.add_rect(poly, 40, -20, 20, 140);
        store.add_rect(nsdm, -10, -10, 120, 120);
        store.add_rect(met1, 40, -20, 1000, 1000);
        // Recognition marker overlaps met1, but is deliberately absent from
        // `connectivity.conductors` in antenna_deck().
        store.add_rect(diode, 100, 100, 100, 100);

        let report = check_antenna(
            &store,
            &deck,
            &AntennaConfig {
                cut_required: Some(false),
                rules: vec![AntennaRule {
                    id: "ant.m1.diode".into(),
                    gates: vec![AntennaGate {
                        gate_layer: poly,
                        channel_layer: diff,
                    }],
                    collectors: vec![AntennaCollector {
                        layer: met1,
                        measurement: AntennaMeasurement::Area,
                    }],
                    max_egar: 100.0,
                    diode: Some(AntennaDiode {
                        layer: diode,
                        area_credit_per_um2: 0.0,
                        fixed_bonus: 0.0,
                        full_waiver: true,
                    }),
                }],
            },
        );
        assert_eq!(report.check.status, CheckStatus::Clean);
        assert_eq!(report.nets.len(), 1);
        assert!(report.nets[0].waived);
        assert!(report.nets[0].diode_area_um2 > 0.0);
    }

    #[test]
    fn antenna_diode_marker_cannot_bridge_distinct_nets() {
        let deck = antenna_deck();
        let diff = deck.layers.id("diff").unwrap();
        let poly = deck.layers.id("poly").unwrap();
        let met1 = deck.layers.id("met1").unwrap();
        let diode = deck.layers.id("diode").unwrap();
        let mut store = GeometryStore::new();
        store.add_rect(met1, 0, 0, 100, 100);
        store.add_rect(met1, 200, 0, 100, 100);
        store.add_rect(diode, 50, 0, 200, 100);

        let report = check_antenna(
            &store,
            &deck,
            &AntennaConfig {
                cut_required: Some(false),
                rules: vec![AntennaRule {
                    id: "ant.ambiguous_diode".into(),
                    gates: vec![AntennaGate {
                        gate_layer: poly,
                        channel_layer: diff,
                    }],
                    collectors: vec![AntennaCollector {
                        layer: met1,
                        measurement: AntennaMeasurement::Area,
                    }],
                    max_egar: 100.0,
                    diode: Some(AntennaDiode {
                        layer: diode,
                        area_credit_per_um2: 0.0,
                        fixed_bonus: 0.0,
                        full_waiver: true,
                    }),
                }],
            },
        );
        assert_eq!(report.check.status, CheckStatus::Error);
        assert!(report.check.diagnostics[0].contains("multiple extracted nets"));
    }

    #[test]
    fn density_checks_empty_die_windows_and_gradient() {
        let mut store = GeometryStore::new();
        store.add_rect(0, 0, 0, 50, 100);
        let report = check_density_cmp(
            &store,
            &DensityCmpConfig {
                die: Bbox {
                    xmin: 0,
                    ymin: 0,
                    xmax: 100,
                    ymax: 100,
                },
                include_partial_windows: false,
                rules: vec![DensityCmpRule {
                    id: "m1".into(),
                    layer: 0,
                    window_width: 50,
                    window_height: 100,
                    step_x: 50,
                    step_y: 100,
                    min_density: Some(0.4),
                    max_density: Some(1.0),
                    max_neighbor_delta: Some(0.5),
                    cmp: None,
                }],
            },
        );
        assert_eq!(report.windows.len(), 2);
        assert_eq!(report.windows[0].density, 1.0);
        assert_eq!(report.windows[1].density, 0.0);
        assert_eq!(report.check.status, CheckStatus::Violations);
        assert!(report
            .check
            .violations
            .iter()
            .any(|v| v.rule_id.ends_with("min_density")));
        assert!(report
            .check
            .violations
            .iter()
            .any(|v| v.rule_id.ends_with("density_gradient")));
    }

    #[test]
    fn density_rejects_steps_that_leave_unchecked_gaps() {
        let report = check_density_cmp(
            &GeometryStore::new(),
            &DensityCmpConfig {
                die: Bbox {
                    xmin: 0,
                    ymin: 0,
                    xmax: 100,
                    ymax: 100,
                },
                include_partial_windows: true,
                rules: vec![DensityCmpRule {
                    id: "m1".into(),
                    layer: 0,
                    window_width: 20,
                    window_height: 20,
                    step_x: 21,
                    step_y: 20,
                    min_density: Some(0.0),
                    max_density: None,
                    max_neighbor_delta: None,
                    cmp: None,
                }],
            },
        );
        assert_eq!(report.check.status, CheckStatus::Error);

        let trailing_edge = check_density_cmp(
            &GeometryStore::new(),
            &DensityCmpConfig {
                die: Bbox {
                    xmin: 0,
                    ymin: 0,
                    xmax: 250,
                    ymax: 100,
                },
                include_partial_windows: false,
                rules: vec![DensityCmpRule {
                    id: "m1.trailing".into(),
                    layer: 0,
                    window_width: 100,
                    window_height: 100,
                    step_x: 100,
                    step_y: 100,
                    min_density: Some(0.0),
                    max_density: Some(1.0),
                    max_neighbor_delta: None,
                    cmp: None,
                }],
            },
        );
        assert_eq!(trailing_edge.check.status, CheckStatus::Error);
        assert!(trailing_edge.check.diagnostics[0].contains("unchecked die-edge strip"));
    }

    #[test]
    fn power_solver_resolves_sub_ampere_loads_and_ir_needs_scope() {
        let grid = PowerGrid {
            nodes: vec![
                PowerNode {
                    id: "supply".into(),
                    x: 0,
                    y: 0,
                    nominal_voltage_v: 1.0,
                    fixed_voltage_v: Some(1.0),
                    load_current_a: 0.0,
                    check_ir_drop: false,
                },
                PowerNode {
                    id: "load".into(),
                    x: 1,
                    y: 0,
                    nominal_voltage_v: 1.0,
                    fixed_voltage_v: None,
                    load_current_a: 1.0e-12,
                    check_ir_drop: true,
                },
            ],
            edges: vec![PowerEdge {
                id: "r".into(),
                from: 0,
                to: 1,
                resistance_ohm: 1.0e6,
                length_um: 1.0,
                kind: PowerEdgeKind::Metal {
                    width_um: 1.0,
                    thickness_um: 1.0,
                },
                temperature_c: 25.0,
                max_current_density_a_per_um2: Some(1.0),
                max_current_per_cut_a: None,
                blech_product_limit_a_per_um: None,
                em_exempt: false,
            }],
        };
        let solution = solve_power_grid(&grid, &PowerSolveConfig::default()).unwrap();
        assert!((solution.node_voltages[1].drop_v - 1.0e-6).abs() < 1.0e-12);

        let mut no_scope = grid.clone();
        no_scope.nodes[1].check_ir_drop = false;
        let report = analyze_ir_drop(
            &no_scope,
            &solution,
            &IrDropConfig {
                max_drop_v: Some(1.0),
                max_drop_pct: None,
                max_overvoltage_v: None,
            },
        );
        assert_eq!(report.check.status, CheckStatus::Error);
    }

    fn simple_power() -> (PowerGrid, PowerSolution) {
        let grid = PowerGrid {
            nodes: vec![
                PowerNode {
                    id: "VDD".into(),
                    x: 0,
                    y: 0,
                    nominal_voltage_v: 1.0,
                    fixed_voltage_v: Some(1.0),
                    load_current_a: 0.0,
                    check_ir_drop: true,
                },
                PowerNode {
                    id: "LOAD".into(),
                    x: 10,
                    y: 0,
                    nominal_voltage_v: 1.0,
                    fixed_voltage_v: None,
                    load_current_a: 0.1,
                    check_ir_drop: true,
                },
            ],
            edges: vec![PowerEdge {
                id: "M1.0".into(),
                from: 0,
                to: 1,
                resistance_ohm: 1.0,
                length_um: 10.0,
                kind: PowerEdgeKind::Metal {
                    width_um: 1.0,
                    thickness_um: 1.0,
                },
                temperature_c: 25.0,
                max_current_density_a_per_um2: Some(0.05),
                max_current_per_cut_a: None,
                blech_product_limit_a_per_um: None,
                em_exempt: false,
            }],
        };
        let solution = solve_power_grid(&grid, &PowerSolveConfig::default()).unwrap();
        (grid, solution)
    }

    #[test]
    fn dc_grid_drives_ir_and_em_checks() {
        let (grid, solution) = simple_power();
        assert!((solution.node_voltages[1].voltage_v - 0.9).abs() < 1e-9);
        assert!((solution.branch_currents[0].current_a - 0.1).abs() < 1e-9);
        let ir = analyze_ir_drop(
            &grid,
            &solution,
            &IrDropConfig {
                max_drop_v: Some(0.05),
                max_drop_pct: Some(5.0),
                max_overvoltage_v: None,
            },
        );
        assert_eq!(ir.check.status, CheckStatus::Violations);
        let em = analyze_electromigration(
            &grid,
            &solution,
            &ElectromigrationConfig {
                default_max_current_density_a_per_um2: None,
                default_max_current_per_cut_a: None,
                reference_temperature_c: 25.0,
                activation_energy_ev: 0.7,
                current_exponent: 2.0,
                max_temperature_c: Some(125.0),
            },
        );
        assert_eq!(em.check.status, CheckStatus::Violations);
        assert!((em.branches[0].current_density_a_per_um2.unwrap() - 0.1).abs() < 1e-9);
    }

    #[test]
    fn power_grid_rejects_duplicate_edge_identity() {
        let (mut grid, _) = simple_power();
        grid.edges.push(grid.edges[0].clone());
        assert!(solve_power_grid(&grid, &PowerSolveConfig::default()).is_err());
    }

    #[test]
    fn reliability_models_voltage_thermal_and_lifetime() {
        let report = check_reliability(&ReliabilityConfig {
            required_lifetime_hours: 100_000.0,
            voltage_stresses: vec![VoltageStress {
                id: "oxide".into(),
                measured_abs_v: 2.0,
                max_abs_v: 1.8,
                location: None,
            }],
            thermal_stresses: vec![ThermalStress {
                id: "junction".into(),
                measured_c: 100.0,
                max_c: 125.0,
                location: None,
            }],
            aging_stresses: vec![AgingStress {
                id: "bti".into(),
                mechanism: "BTI".into(),
                reference_lifetime_hours: 200_000.0,
                reference_stress: 1.0,
                applied_stress: 2.0,
                stress_exponent: 2.0,
                reference_temperature_c: 25.0,
                applied_temperature_c: 25.0,
                activation_energy_ev: 0.0,
                duty_cycle: 1.0,
                location: None,
            }],
        });
        assert_eq!(report.check.status, CheckStatus::Violations);
        assert_eq!(report.aging[0].predicted_lifetime_hours, 50_000.0);
        assert_eq!(report.check.violations.len(), 2);
    }

    #[test]
    fn esd_path_and_latchup_evidence_can_be_clean() {
        let config = EsdLatchupConfig {
            nodes: vec![
                EsdNode {
                    id: "PAD".into(),
                    kind: EsdNodeKind::IoPad,
                    x: 0,
                    y: 0,
                },
                EsdNode {
                    id: "VSS".into(),
                    kind: EsdNodeKind::Ground,
                    x: 10,
                    y: 0,
                },
            ],
            edges: vec![EsdEdge {
                id: "clamp".into(),
                from: 0,
                to: 1,
                bidirectional: false,
                resistance_ohm: 1.0,
                current_capacity_a: 2.0,
                clamp_voltage_v: 4.0,
            }],
            esd_paths: vec![EsdPathRequirement {
                id: "pad_to_vss".into(),
                source: 0,
                explicit_targets: vec![],
                target_kinds: vec![EsdNodeKind::Ground],
                required_current_a: 1.0,
                max_path_resistance_ohm: 2.0,
                max_clamp_voltage_v: 5.0,
            }],
            latchup_sites: vec![LatchupSite {
                id: "io_site".into(),
                location: (0, 0),
                guard_ring: Some(GuardRingEvidence {
                    id: "gr0".into(),
                    bias_node: 1,
                    continuous: true,
                    width_um: 2.0,
                    aggressor_distance_um: 1.0,
                    victim_distance_um: 1.0,
                    nearest_tap_distance_um: 5.0,
                }),
                allowed_bias_kinds: vec![EsdNodeKind::Ground],
                min_guard_ring_width_um: 1.0,
                max_aggressor_distance_um: 2.0,
                max_victim_distance_um: 2.0,
                max_tap_distance_um: 10.0,
            }],
        };
        let report = check_esd_latchup(&config);
        assert_eq!(report.check.status, CheckStatus::Clean);
        assert_eq!(report.paths.len(), 1);

        let mut missing_latchup = config.clone();
        missing_latchup.latchup_sites.clear();
        assert_eq!(
            check_esd_latchup(&missing_latchup).check.status,
            CheckStatus::Error
        );

        let mut missing_esd = config;
        missing_esd.esd_paths.clear();
        assert_eq!(
            check_esd_latchup(&missing_esd).check.status,
            CheckStatus::Error
        );
    }

    #[test]
    fn rectangle_union_does_not_double_count_overlap() {
        let (area, perimeter) = rect_union_metrics(&[
            Bbox {
                xmin: 0,
                ymin: 0,
                xmax: 10,
                ymax: 10,
            },
            Bbox {
                xmin: 5,
                ymin: 0,
                xmax: 15,
                ymax: 10,
            },
        ]);
        assert_eq!(area, 150.0);
        assert_eq!(perimeter, 50.0);
    }

    #[test]
    fn polygon_rect_rejects_bow_tie_corner_order() {
        let mut store = GeometryStore::new();
        let p = store.add_polygon(0, &[(0, 0), (10, 10), (10, 0), (0, 10)]);
        assert_eq!(polygon_rect(&store, p), None);
    }
}
