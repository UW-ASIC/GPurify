//! Machine-readable capability manifest for qualification tracking.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityStatus {
    Qualified,
    Experimental,
    Unsupported,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    pub id: String,
    pub engine: String,
    pub category: String,
    pub status: CapabilityStatus,
    pub test_ids: Vec<String>,
    pub backend_coverage: Vec<String>,
    pub oracle: String,
    pub limitations: Vec<String>,
}

fn cap(
    id: &str,
    engine: &str,
    cat: &str,
    status: CapabilityStatus,
    backends: &[&str],
    oracle: &str,
) -> Capability {
    Capability {
        id: id.into(),
        engine: engine.into(),
        category: cat.into(),
        status,
        test_ids: Vec::new(),
        backend_coverage: backends.iter().map(|s| s.to_string()).collect(),
        oracle: oracle.into(),
        limitations: Vec::new(),
    }
}

fn with_tests(mut c: Capability, ids: &[&str]) -> Capability {
    c.test_ids = ids.iter().map(|s| s.to_string()).collect();
    c
}

/// Map DRC rule names from conformance/manifest.json to capability test_ids.
fn drc_test_ids(rule: &str) -> &'static [&'static str] {
    match rule {
        "min_width" => &[
            "DRC_MW_PASS",
            "DRC_MW_FAIL",
            "DRC_MW_LSHAPE",
            "DRC_FUZZ_ZERO_W",
            "DRC_PATH_BEND",
            "DRC_MW_DIAG_FAIL",
            "DRC_MW_DIAG_PASS",
        ],
        "min_spacing" => &[
            "DRC_MS_PASS",
            "DRC_MS_FAIL",
            "DRC_NVS_MERGE_SPACE",
            "DRC_NVS_SEP_SPACE",
            "DRC_HIER",
            "DRC_HIER_NEST",
            "DRC_PATH",
            "DRC_FUZZ_COIN_SP",
            "DRC_STRICT_MERGE_SP",
            "DRC_STRICT_SEP_SP",
        ],
        "min_spacing_diff" => &["DRC_MSD_PASS", "DRC_MSD_FAIL"],
        "min_enclosure" => &[
            "DRC_ENC_PASS",
            "DRC_ENC_FAIL",
            "DRC_ENC_UNHOSTED",
            "DRC_ENC_CONC_PASS",
            "DRC_ENC_CONC_FAIL",
            "DRC_WE_PASS",
            "DRC_WE_FAIL",
            "DRC_WE_NONE",
        ],
        "min_extension" => &[
            "DRC_EXT_PASS",
            "DRC_EXT_FAIL",
            "DRC_EXT_H_PASS",
            "DRC_EXT_H_FAIL",
        ],
        "min_area" => &["DRC_MA_PASS", "DRC_MA_FAIL", "DRC_MA_EXACT"],
        "min_enclosed_area" => &["DRC_MEA_PASS", "DRC_MEA_FAIL"],
        "notch" => &[
            "DRC_N_PASS",
            "DRC_N_FAIL",
            "DRC_NVS_MERGE_NOTCH",
            "DRC_NVS_SEP_NOTCH",
            "DRC_FUZZ_COIN_N",
            "DRC_STRICT_MERGE_N",
        ],
        "corner_to_corner" => &["DRC_C2C_PASS", "DRC_C2C_FAIL"],
        "max_width" => &["DRC_XW_PASS", "DRC_XW_FAIL"],
        "off_grid" => &["DRC_OG_PASS", "DRC_OG_FAIL", "DRC_FUZZ_OFFG"],
        "angle" => &[
            "DRC_ANG_PASS",
            "DRC_ANG_FAIL",
            "DRC_FUZZ_SELF_ANG",
            "DRC_FUZZ_ACUTE_ANG",
        ],
        // ponytail: density capability covers both min_density and max_density rules
        "density" => &[
            "DRC_MD_PASS",
            "DRC_MD_FAIL",
            "DRC_MD_MULTI",
            "DRC_XD_PASS",
            "DRC_XD_FAIL",
            "DRC_DGRAD_MAX",
            "DRC_DGRAD_MIN",
        ],
        "cheesing" => &["DRC_CH_PASS", "DRC_CH_FAIL", "DRC_CH_SMALL"],
        "min_edge_length" => &["DRC_EL_PASS", "DRC_EL_FAIL"],
        "eol_spacing" => &[
            "DRC_EOL_PASS",
            "DRC_EOL_FAIL",
            "DRC_EOL_WIDE",
            "DRC_EOL_SIDE",
        ],
        "max_distance_to_tap" => &["DRC_MDT_PASS", "DRC_MDT_FAIL"],
        "antenna" => &["DRC_ANT_PASS", "DRC_ANT_FAIL"],
        "antenna_car" => &["DRC_CAR_PASS", "DRC_CAR_FAIL", "DRC_CAR_DIODE"],
        "asymmetric_enclosure" => &[
            "DRC_AENC_PASS",
            "DRC_AENC_FAIL",
            "UNSUP_DRC_ASYMMETRIC_ENCLOSURE",
        ],
        "multi_patterning" => &["DRC_MP_PASS", "DRC_MP_FAIL", "UNSUP_DRC_MULTI_PATTERNING"],
        _ => &[],
    }
}

pub fn builtin_manifest() -> Vec<Capability> {
    use CapabilityStatus::*;
    let cpu = &["cpu"][..];
    let both = &["cpu", "gpu"][..];

    let mut m = Vec::new();

    // --- DRC rules ---
    let drc_qualified = [
        "min_width",
        "min_spacing",
        "min_spacing_diff",
        "min_edge_length",
        "min_area",
        "min_enclosed_area",
        "min_enclosure",
        "min_extension",
        "notch",
        "corner_to_corner",
        "max_width",
        "off_grid",
        "angle",
        "density",
        "cheesing",
    ];
    for r in &drc_qualified {
        m.push(with_tests(
            cap(
                &format!("drc_{r}"),
                "drc",
                "rule",
                Qualified,
                both,
                "klayout",
            ),
            drc_test_ids(r),
        ));
    }
    let drc_experimental = [
        "eol_spacing",
        "max_distance_to_tap",
        "antenna",
        "antenna_car",
    ];
    for r in &drc_experimental {
        m.push(with_tests(
            cap(
                &format!("drc_{r}"),
                "drc",
                "rule",
                Experimental,
                both,
                "none",
            ),
            drc_test_ids(r),
        ));
    }
    let drc_unsupported = ["asymmetric_enclosure", "multi_patterning"];
    for r in &drc_unsupported {
        m.push(with_tests(
            cap(&format!("drc_{r}"), "drc", "rule", Unsupported, cpu, "none"),
            drc_test_ids(r),
        ));
    }

    // DRC support systems
    m.push(cap(
        "drc_derived_layers",
        "drc",
        "support",
        Qualified,
        cpu,
        "exact",
    ));
    m.push(cap("drc_fill", "drc", "support", Qualified, cpu, "exact"));
    m.push(cap(
        "drc_coloring",
        "drc",
        "support",
        Experimental,
        cpu,
        "none",
    ));
    m.push(cap(
        "drc_results_db",
        "drc",
        "support",
        Qualified,
        cpu,
        "exact",
    ));
    m.push(cap("drc_waiver", "drc", "support", Qualified, cpu, "exact"));

    // --- LVS ---
    m.push(with_tests(
        cap(
            "lvs_mos_extraction",
            "lvs",
            "extraction",
            Qualified,
            both,
            "hand_authored",
        ),
        &[
            "LVS_CLEAN_MATCH",
            "LVS_SD_PERMUTE",
            "LVS_DEVICE_MISMATCH",
            "LVS_FINGERS_MATCH",
            "LVS_FINGERS_MISMATCH",
            "LVS_PARAM_MATCH",
            "LVS_PARAM_MISMATCH",
            "LVS_HVT_MATCH",
            "LVS_HVT_MISMATCH",
            "LVS_LVT_MATCH",
        ],
    ));
    m.push(cap(
        "lvs_bjt_extraction",
        "lvs",
        "extraction",
        Experimental,
        cpu,
        "hand_authored",
    ));
    m.push(cap(
        "lvs_two_terminal",
        "lvs",
        "extraction",
        Experimental,
        cpu,
        "hand_authored",
    ));
    m.push(with_tests(
        cap(
            "lvs_connectivity",
            "lvs",
            "extraction",
            Qualified,
            both,
            "exact",
        ),
        &[
            "LVS_TOPO_MISMATCH",
            "LVS_INTENTIONAL_SHORT",
            "LVS_INTENTIONAL_OPEN",
        ],
    ));
    m.push(with_tests(
        cap(
            "lvs_label_binding",
            "lvs",
            "extraction",
            Qualified,
            cpu,
            "hand_authored",
        ),
        &["LVS_CLEAN_MATCH"],
    ));
    m.push(with_tests(
        cap(
            "lvs_comparison",
            "lvs",
            "comparison",
            Qualified,
            cpu,
            "hand_authored",
        ),
        &[
            "LVS_CLEAN_MATCH",
            "LVS_SD_PERMUTE",
            "LVS_DEVICE_MISMATCH",
            "LVS_TOPO_MISMATCH",
            "LVS_ISOMORPHIC",
            "LVS_PARAM_MATCH",
            "LVS_PARAM_MISMATCH",
        ],
    ));
    m.push(cap(
        "lvs_hierarchy",
        "lvs",
        "comparison",
        Experimental,
        cpu,
        "none",
    ));
    m.push(cap(
        "lvs_gpu_compare",
        "lvs",
        "comparison",
        Experimental,
        both,
        "none",
    ));
    m.push(cap(
        "lvs_spice_parser",
        "lvs",
        "parser",
        Qualified,
        cpu,
        "hand_authored",
    ));
    m.push(cap(
        "lvs_cdl_parser",
        "lvs",
        "parser",
        Qualified,
        cpu,
        "hand_authored",
    ));
    m.push(cap(
        "lvs_spectre_parser",
        "lvs",
        "parser",
        Experimental,
        cpu,
        "hand_authored",
    ));
    m.push(with_tests(
        cap(
            "lvs_series_parallel",
            "lvs",
            "reduction",
            Experimental,
            cpu,
            "none",
        ),
        &["LVS_SERIES_MERGE", "LVS_PARALLEL_MERGE"],
    ));

    // --- ERC signoff ---
    m.push(with_tests(
        cap(
            "erc_antenna",
            "erc",
            "signoff",
            Qualified,
            cpu,
            "analytical",
        ),
        &["ERC_ANTENNA_ELEC_PASS", "ERC_ANTENNA_ELEC_FAIL"],
    ));
    m.push(cap(
        "erc_density_cmp",
        "erc",
        "signoff",
        Qualified,
        cpu,
        "analytical",
    ));
    m.push(cap(
        "erc_ir_drop",
        "erc",
        "signoff",
        Experimental,
        cpu,
        "analytical",
    ));
    m.push(with_tests(
        cap(
            "erc_electromigration",
            "erc",
            "signoff",
            Experimental,
            cpu,
            "analytical",
        ),
        &["ERC_EM_FAIL", "ERC_EM_PASS"],
    ));
    m.push(cap(
        "erc_reliability",
        "erc",
        "signoff",
        Experimental,
        cpu,
        "analytical",
    ));
    m.push(with_tests(
        cap(
            "erc_esd_latchup",
            "erc",
            "signoff",
            Experimental,
            cpu,
            "analytical",
        ),
        &["ERC_ESD_MISSING", "ERC_ESD_PASS"],
    ));

    // ERC heuristic
    m.push(with_tests(
        cap(
            "erc_supply_short",
            "erc",
            "heuristic",
            Qualified,
            cpu,
            "hand_authored",
        ),
        &["ERC_VDD_VSS_SHORT", "ERC_VDD_VSS_PASS"],
    ));
    m.push(with_tests(
        cap(
            "erc_floating_gate",
            "erc",
            "heuristic",
            Qualified,
            cpu,
            "hand_authored",
        ),
        &["ERC_FLOAT_GATE", "ERC_FLOAT_GATE_PASS"],
    ));
    m.push(with_tests(
        cap(
            "erc_floating_well",
            "erc",
            "heuristic",
            Qualified,
            cpu,
            "hand_authored",
        ),
        &["ERC_FLOAT_WELL", "ERC_FLOAT_WELL_PASS"],
    ));
    m.push(with_tests(
        cap(
            "erc_missing_tie",
            "erc",
            "heuristic",
            Qualified,
            cpu,
            "hand_authored",
        ),
        &["ERC_MISSING_TIE"],
    ));
    m.push(with_tests(
        cap(
            "erc_multiple_drivers",
            "erc",
            "heuristic",
            Qualified,
            cpu,
            "hand_authored",
        ),
        &["ERC_MULTI_DRIVER", "ERC_MULTI_DRIVER_PASS"],
    ));
    m.push(with_tests(
        cap(
            "erc_hv_domain",
            "erc",
            "heuristic",
            Qualified,
            cpu,
            "hand_authored",
        ),
        &["ERC_HV_CROSS", "ERC_HV_PASS"],
    ));
    m.push(with_tests(
        cap(
            "erc_unconnected_pin",
            "erc",
            "heuristic",
            Qualified,
            cpu,
            "hand_authored",
        ),
        &["ERC_UNCONNECTED"],
    ));
    m.push(with_tests(
        cap(
            "erc_soft_connection",
            "erc",
            "heuristic",
            Qualified,
            cpu,
            "hand_authored",
        ),
        &["ERC_SOFT_CONN"],
    ));
    m.push(with_tests(
        cap(
            "erc_tie_high_low",
            "erc",
            "heuristic",
            Qualified,
            cpu,
            "hand_authored",
        ),
        &["ERC_TIE_HL", "ERC_TIE_HL_PASS"],
    ));

    // ERC extraction
    m.push(cap(
        "erc_power_extract",
        "erc",
        "extraction",
        Experimental,
        cpu,
        "none",
    ));
    m.push(with_tests(
        cap(
            "erc_esd_extract",
            "erc",
            "extraction",
            Experimental,
            cpu,
            "none",
        ),
        &["ERC_ESD_MISSING", "ERC_ESD_PASS"],
    ));
    m.push(cap(
        "erc_substrate_extract",
        "erc",
        "extraction",
        Experimental,
        cpu,
        "none",
    ));

    // --- PEX ---
    m.push(with_tests(
        cap(
            "pex_resistance",
            "pex",
            "mechanism",
            Qualified,
            cpu,
            "analytical",
        ),
        &[
            "PEX_WIRE_R",
            "PEX_LONG_WIRE_R",
            "PEX_WIDTH_100",
            "PEX_WIDTH_400",
            "PEX_DIFF_M1R",
            "PEX_DIFF_M2R",
            "PEX_MET2_R",
            "PEX_NEG_R",
            "PEX_NEG_R2",
        ],
    ));
    m.push(with_tests(
        cap(
            "pex_via_resistance",
            "pex",
            "mechanism",
            Qualified,
            cpu,
            "analytical",
        ),
        &["PEX_VIA_R", "PEX_VIA_R2", "PEX_NEG_VIA"],
    ));
    m.push(with_tests(
        cap(
            "pex_area_cap",
            "pex",
            "mechanism",
            Qualified,
            cpu,
            "analytical",
        ),
        &["PEX_PLATE_C", "PEX_FILL", "PEX_MET2_CAP", "PEX_NEG_AC"],
    ));
    m.push(cap(
        "pex_fringe_cap",
        "pex",
        "mechanism",
        Qualified,
        cpu,
        "analytical",
    ));
    m.push(with_tests(
        cap(
            "pex_coupling_cap",
            "pex",
            "mechanism",
            Qualified,
            cpu,
            "analytical",
        ),
        &[
            "PEX_COUPLING_C",
            "PEX_SPACING_100",
            "PEX_SPACING_400",
            "PEX_VERT_COUPLING",
            "PEX_MET2_COUPLING",
            "PEX_NEG_CC",
            "PEX_NEG_CC2",
        ],
    ));
    m.push(with_tests(
        cap(
            "pex_interlayer_cap",
            "pex",
            "mechanism",
            Qualified,
            cpu,
            "analytical",
        ),
        &["PEX_CROSSOVER", "PEX_NEG_IL"],
    ));
    m.push(with_tests(
        cap("pex_graph", "pex", "mechanism", Experimental, cpu, "none"),
        &["PEX_PER_NET", "PEX_NEG_PNET"],
    ));
    m.push(cap(
        "pex_reduce",
        "pex",
        "mechanism",
        Experimental,
        cpu,
        "none",
    ));
    m.push(cap(
        "pex_spef",
        "pex",
        "mechanism",
        Experimental,
        cpu,
        "none",
    ));
    m.push(cap(
        "pex_dspf",
        "pex",
        "mechanism",
        Experimental,
        cpu,
        "none",
    ));
    m.push(with_tests(
        cap(
            "pex_inductance",
            "pex",
            "mechanism",
            Unsupported,
            cpu,
            "none",
        ),
        &["UNSUP_PEX_INDUCTANCE"],
    ));
    m.push(cap(
        "pex_device_parasitics",
        "pex",
        "mechanism",
        Experimental,
        cpu,
        "none",
    ));
    m.push(cap(
        "pex_process_stack",
        "pex",
        "mechanism",
        Experimental,
        cpu,
        "none",
    ));

    // --- Core IO ---
    m.push(cap("gds_read", "core", "io", Qualified, cpu, "klayout"));
    m.push(cap("gds_write", "core", "io", Qualified, cpu, "klayout"));
    m.push(cap("oasis_read", "core", "io", Experimental, cpu, "none"));
    m.push(cap("oasis_write", "core", "io", Experimental, cpu, "none"));

    // --- Core geometry ---
    m.push(cap(
        "exact_boolean_union",
        "core",
        "geometry",
        Qualified,
        cpu,
        "exact",
    ));
    m.push(cap(
        "exact_boolean_intersection",
        "core",
        "geometry",
        Qualified,
        cpu,
        "exact",
    ));
    m.push(cap(
        "exact_boolean_subtraction",
        "core",
        "geometry",
        Qualified,
        cpu,
        "exact",
    ));
    m.push(cap(
        "exact_polygon_offset",
        "core",
        "geometry",
        Qualified,
        cpu,
        "exact",
    ));
    m.push(cap(
        "exact_predicates",
        "core",
        "geometry",
        Qualified,
        cpu,
        "exact",
    ));
    m.push(cap(
        "hierarchy_spatial_index",
        "core",
        "geometry",
        Qualified,
        cpu,
        "exact",
    ));
    m.push(cap(
        "rectilinear_decomposition",
        "core",
        "geometry",
        Qualified,
        cpu,
        "exact",
    ));

    m
}

pub fn load_manifest(path: &str) -> Result<Vec<Capability>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

pub fn save_manifest(path: &str, manifest: &[Capability]) -> Result<(), String> {
    let json = serde_json::to_string_pretty(manifest).map_err(|e| e.to_string())?;
    std::fs::write(path, json).map_err(|e| e.to_string())
}

/// Every Unsupported capability must have at least one negative test verifying
/// it does not produce CLEAN/MATCH.
pub fn validate_no_false_clean(manifest: &[Capability]) -> Vec<String> {
    manifest
        .iter()
        .filter(|c| c.status == CapabilityStatus::Unsupported && c.test_ids.is_empty())
        .map(|c| format!("{}: unsupported but no negative test", c.id))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_has_minimum_entries() {
        let m = builtin_manifest();
        assert!(
            m.len() >= 60,
            "manifest has {} entries, expected >= 60",
            m.len()
        );
    }

    #[test]
    fn all_ids_unique() {
        let m = builtin_manifest();
        let mut ids: Vec<_> = m.iter().map(|c| &c.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), m.len(), "duplicate capability IDs found");
    }

    #[test]
    fn serialize_roundtrip() {
        let m = builtin_manifest();
        let json = serde_json::to_string(&m).unwrap();
        let back: Vec<Capability> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), m.len());
    }
}
