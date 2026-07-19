//! # gdsverify
//!
//! GPU-accelerated GDS verification: DRC, LVS, PEX, ERC.
//!
//! This crate re-exports the workspace sub-crates under stable paths so
//! downstream code can `use gdsverify::*`.
//!
//! Note vs the pre-crates2 facade: there is no `session`/`Col` arena and no
//! `verify_kernel`/`kernel_fn` macro re-export — the kernel-transpiling macro
//! was removed and GPU kernels are hand-written GLSL (see the `gpu` feature and
//! `MIGRATION.md`).

pub mod env_meta;
pub mod manifest;

// Sub-crate re-exports — keep the old `gdsverify::backend`, `gdsverify::drc`, etc. paths.
pub use gdsverify_backend as backend;
pub use gdsverify_backend::rule;
pub use gdsverify_core as core;
pub use gdsverify_drc as drc;
pub use gdsverify_erc as erc;
pub use gdsverify_lvs as lvs;
pub use gdsverify_pex as pex;

pub use gdsverify_backend as gpu;
pub use gdsverify_core::gds;
pub use gdsverify_core::geometry;
pub use gdsverify_core::hierarchy_index;
pub use gdsverify_core::oasis;
pub use gdsverify_core::params;
pub use gdsverify_core::read;
pub use gdsverify_core::schema;

pub use backend::{available_backends, gpu_ready, Backend, BackendTelemetry};
pub use drc::{
    run_drc, run_drc_backend, run_drc_backend_strict, run_drc_no_density, DrcReport, Violation,
};
pub use erc::{
    analyze_electromigration, analyze_ir_drop, check_antenna, check_antenna_from_deck,
    check_density_cmp, check_esd_latchup, check_reliability, run_erc, run_erc_backend,
    solve_power_grid, AgingStress, AgingStressResult, AntennaCollector, AntennaConfig,
    AntennaDiode, AntennaGate, AntennaMeasurement, AntennaNetResult, AntennaReport, AntennaRule,
    BranchCurrent, CheckReport, CheckStatus, CmpModel, DensityCmpConfig, DensityCmpReport,
    DensityCmpRule, DensityWindowResult, ElectromigrationConfig, ElectromigrationReport,
    EmBranchResult, ErcCtx, ErcFinding, ErcReport, ErcViolation, EsdEdge, EsdLatchupConfig,
    EsdLatchupReport, EsdNode, EsdNodeKind, EsdPathRequirement, EsdPathResult, GuardRingEvidence,
    IrDropConfig, IrDropReport, LatchupSite, MultipleDriverCheck, NodeVoltage, PowerEdge,
    PowerEdgeKind, PowerGrid, PowerNode, PowerSignoffConfig, PowerSolution, PowerSolveConfig,
    ReliabilityConfig, ReliabilityReport, SignoffCheck, SignoffConfig, SignoffSuiteReport,
    SignoffViolation, ThermalStress, TieHighLowCheck, VoltageStress,
};
pub use gds::{read_gds, read_gds_checked, GdsLayout, GdsUnits, GdsUnmappedLayer};
pub use gds::{
    flatten_gds_library, read_gds_library, stroke_path, write_gds_library, GdsArrayReference,
    GdsBoundary, GdsBoxElement, GdsElement, GdsElementMeta, GdsEnvelope, GdsFlattenOptions,
    GdsGeometryPolicy, GdsLibrary, GdsNode, GdsPath, GdsProperty, GdsRawRecord, GdsReadMode,
    GdsReference, GdsStructure, GdsText, GdsTransform, GdsUnsupportedElement, LayoutError,
    LayoutErrorKind,
};
pub use geometry::{Bbox, Edge, GeometryStore, LayerId, PolyId};
pub use hierarchy_index::{
    GdsLayerIdentity, HierarchyCandidate, HierarchyIndexOptions, HierarchySpatialIndex,
    IndexedShapeKind, InstancePathEntry, TileCandidates, TileGrid, TileId, VerificationTile,
};
pub use lvs::binding::{
    bind_reference_hierarchy, evaluate_parameter_expression, BindingError, BindingErrorKind,
    BlackBoxSpec, BoundReferenceCell, BoundReferenceHierarchy, BoundReferenceInstance,
    ConfiguredModel, ParameterEnvironment, ReferenceBindingOptions,
};
pub use lvs::detailed_extract::{
    extract_detailed_netlist, DetailedExtractionError, DetailedExtractionErrorKind,
    DetailedExtractionOptions, NamedSoftConnection,
};
pub use lvs::gds_adapter::{
    adapt_gds_hierarchy_to_lvs, export_w3_drc_hierarchy_context, GdsAdapterObjectKind,
    GdsBlackBoxAdapterSpec, GdsDrcHierarchyContext, GdsHierarchyAdapterError,
    GdsHierarchyAdapterErrorKind, GdsHierarchyAdapterOptions, GdsHierarchyAdapterResult,
    GdsHierarchyProvenance, GdsObjectProvenance, GdsPhysicalCorrelationStatus, GdsTextEvidenceRule,
    GDS_ADAPTER_MAX_STACK_SAFE_DEPTH,
};
pub use lvs::hier_production::{
    compare_hierarchical_production, HierArray, HierCellComparison, HierFlattenPolicy, HierLayout,
    HierLayoutCell, HierLayoutInstance, HierLvsCache, HierProductionOptions, HierProductionResult,
    HierTransform,
};
pub use lvs::netlist::{
    leaf_subcircuit_to_ref_netlist, parse_engineering_number, parse_netlist,
    parse_netlist_with_includes, BjtModelBinding, EngineeringNumber, EngineeringSuffix,
    IncludeDecl, InstanceKind, ModelDecl, ModelPrimitive, MosModelBinding, NetlistAst,
    NetlistError, NetlistErrorKind, NetlistInstance, ParameterDecl, ParameterExpr,
    RefConversionError, RefConversionErrorKind, RefConversionOptions, ResolvedInclude, SourceSpan,
    Subcircuit,
};
pub use lvs::production::{
    compare_production, BjtDeviceRecord, DetailedExtractedNetlist, DetailedNetlist,
    DetailedRefNetlist, DeviceIdentity, DeviceMapping, HierarchyPath, LegacyRefDeviceBuilder,
    MosDeviceRecord, NetIdentity, NetMapping, NumericTolerance, OpenCandidate, PortDirection,
    ProductionCompareOptions, ProductionLvsResult, ProductionLvsStatus, ProductionMismatch,
    PropertyDelta, PropertyUnit, SoftConnection, TerminalConnection, TopologyConflictKind,
    TopologyWitness, TwoTerminalRecord, TypedProperty, UnresolvedTerminal,
};
pub use lvs::{
    compare, extract_netlist, extract_netlist_backend, extract_netlist_opts, reduce_netlist,
    to_spice, CompareOpts, Device, DeviceFlavor, DeviceKind, ExtractOpts, ExtractedNetlist,
    LvsResult, PortMap, RefDevice, RefNetlist, RefTwoTerminal, SpiceOpts, TwoTerminalDevice,
    TwoTerminalKind,
};
pub use oasis::{
    read_oasis, write_oasis, OasisCapabilities, OasisError, OasisErrorKind, OASIS_CAPABILITIES,
};
pub use params::{Deck, DrcRuleParam, LayerDef, LayerTable, PexMethod};
pub use pex::{
    run_pex, run_pex_backend, run_pex_by_net, run_pex_by_net_analytical,
    run_pex_by_net_analytical_checked, run_pex_by_net_checked, run_pex_by_net_with_accuracy,
    run_pex_by_net_with_accuracy_checked, Accuracy, NetParasitics, Parasitic, PexReport,
};
pub use rule::{run_rules, Rule};
pub use schema::{DrcRuleSchema, LvsSchema, VerifySchema};

const GDS_DBU_REL_TOLERANCE: f64 = 1.0e-9;
const GDS_DBU_ABS_TOLERANCE_NM: f64 = 1.0e-12;

fn validate_gds_database_units(units: Option<GdsUnits>, deck_dbu_nm: f64) -> Result<(), String> {
    if !deck_dbu_nm.is_finite() || deck_dbu_nm <= 0.0 {
        return Err(format!(
            "deck database unit must be finite and positive, got {deck_dbu_nm} nm"
        ));
    }
    let units = units.ok_or_else(|| {
        "GDS has no UNITS record; deck-aware loading cannot establish coordinate units".to_string()
    })?;
    let gds_dbu_nm = units.database_unit_nm();
    if !gds_dbu_nm.is_finite() || gds_dbu_nm <= 0.0 {
        return Err(format!(
            "GDS database unit must be finite and positive, got {gds_dbu_nm} nm"
        ));
    }
    let tolerance = GDS_DBU_ABS_TOLERANCE_NM
        .max(GDS_DBU_REL_TOLERANCE * deck_dbu_nm.abs().max(gds_dbu_nm.abs()));
    if (gds_dbu_nm - deck_dbu_nm).abs() > tolerance {
        return Err(format!(
            "GDS database unit {gds_dbu_nm} nm does not match deck database unit \
             {deck_dbu_nm} nm (tolerance {tolerance} nm); coordinates were not rescaled"
        ));
    }
    Ok(())
}

/// Load a GDS file with the legacy DRC-compatibility policy.
///
/// # Errors
/// Returns an error string when the file cannot be read, parsed, or when its
/// database units do not match the deck.
pub fn load_gds(path: &str, deck: &Deck) -> Result<GdsLayout, String> {
    load_gds_with_policy(path, deck, GdsLoadPolicy::LegacyDrcCompatibility)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GdsLoadPolicy {
    LegacyDrcCompatibility,
    StrictSignoff,
}

/// Load a GDS file with strict signoff parsing.
///
/// # Errors
/// See [`load_gds`].
pub fn load_gds_strict(path: &str, deck: &Deck) -> Result<GdsLayout, String> {
    load_gds_with_policy(path, deck, GdsLoadPolicy::StrictSignoff)
}

/// Load a GDS file under an explicit [`GdsLoadPolicy`].
///
/// # Errors
/// Returns an error string when the file cannot be read, parsed, or when its
/// database units do not match the deck.
pub fn load_gds_with_policy(
    path: &str,
    deck: &Deck,
    policy: GdsLoadPolicy,
) -> Result<GdsLayout, String> {
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    let layout = match policy {
        GdsLoadPolicy::LegacyDrcCompatibility => read_gds(&bytes, &deck.layers)?,
        GdsLoadPolicy::StrictSignoff => read_gds_checked(
            &bytes,
            GdsReadMode::Strict,
            &deck.layers,
            &GdsFlattenOptions::default(),
        )?,
    };
    validate_gds_database_units(layout.units, deck.dbu_nm)?;
    Ok(layout)
}

/// Extract a netlist from the layout and compare it against `reference`.
#[must_use]
pub fn run_lvs(store: &GeometryStore, deck: &Deck, reference: &RefNetlist) -> LvsResult {
    let opts = ExtractOpts {
        cut_required: deck.lvs_cut_required,
        ..Default::default()
    };
    let ext = match extract_netlist_opts(store, deck, &opts, Backend::Cpu) {
        Ok(e) => e,
        Err(e) => {
            return LvsResult {
                matched: false,
                reason: format!("extraction failed: {e}"),
                extracted_devices: 0,
                nmos: 0,
                pmos: 0,
                ambiguous_classes: 0,
                label_conflicts: Vec::new(),
                mismatches: Vec::new(),
                floating_nets: Vec::new(),
                device_mappings: Vec::new(),
                net_mappings: Vec::new(),
                witness: None,
            }
        }
    };
    let cmp_opts = CompareOpts {
        strict: deck.strict,
        w_tolerance: deck.w_tolerance.clone(),
        l_tolerance: deck.l_tolerance.clone(),
        pin_swaps: Vec::new(),
    };
    let mut result = compare(&ext, reference, &cmp_opts);
    if deck.fail_on_floating && !ext.floating_nets.is_empty() {
        result.matched = false;
        result.reason = format!("{} floating extracted net(s)", ext.floating_nets.len());
    }
    result
}

#[cfg(test)]
mod unit_contract_tests {
    use super::*;

    fn units(database_unit_nm: f64) -> GdsUnits {
        GdsUnits {
            user_units_per_database_unit: 1.0e-3,
            meters_per_database_unit: database_unit_nm * 1.0e-9,
        }
    }

    #[test]
    fn deck_aware_gds_units_fail_closed() {
        let missing = validate_gds_database_units(None, 1.0)
            .expect_err("missing GDS UNITS must not inherit the deck unit silently");
        assert!(missing.contains("no UNITS"), "{missing}");

        let mismatch = validate_gds_database_units(Some(units(2.0)), 1.0)
            .expect_err("mismatched coordinate units must not be silently rescaled");
        assert!(mismatch.contains("does not match"), "{mismatch}");

        validate_gds_database_units(Some(units(1.0 + 5.0e-10)), 1.0)
            .expect("REAL8 representation noise within the documented tolerance is accepted");
        assert!(validate_gds_database_units(Some(units(1.0 + 2.0e-9)), 1.0).is_err());
    }
}
