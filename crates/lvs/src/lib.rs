//! LVS: extract a netlist from layout, then compare it to a reference schematic netlist.
//!
//! Pipeline:
//!   1. Connectivity extraction — sweep-line candidates → exact predicates → connected
//!      components (host union-find or GPU FastSV via `core::connectivity`).
//!   2. Device extraction — gate-over-channel recognized via PDK rules; type from implant.
//!      MOS/BJT/2-terminal live in extract.rs; planned R/C/diode stubs in devices.rs (L4.3).
//!   3. Comparison — iterative partition refinement over both extracted and reference graphs.
//!
//! Module ownership (Wave 4 alignment):
//!   L4.1  netlist.rs, binding.rs         — reference netlist dialect
//!   L4.2  extract.rs                     — connectivity + evidence binding
//!   L4.3  devices.rs, extract.rs helpers — device recognition + properties
//!   L4.4  compare.rs                     — graph matching + symmetric reductions
//!   L4.5  hierarchical.rs, hier_production.rs, gds_adapter.rs — hierarchy + production

pub mod binding;
pub mod compare;
pub mod derived;
pub mod detailed_extract;
pub mod devices;
pub mod extract;
pub mod gds_adapter;
pub mod gpu_compare;
pub mod hier_production;
pub mod hierarchical;
pub mod netlist;
pub mod production;
pub mod spectre;
pub mod spice;
pub mod types;

pub use binding::*;
pub use compare::{compare, CompareOpts, PinSwapGroup};
pub use derived::evaluate_derived_layers;
pub use detailed_extract::*;
pub use extract::{
    extract_netlist, extract_netlist_opts, extract_raw, reduce_netlist, ExtractResult,
};
pub use gds_adapter::*;
pub use hier_production::*;
pub use hierarchical::{
    compare_hierarchical, compare_hierarchical_cached, HierCell, HierLvsCacheSimple, HierLvsResult,
    RefHierarchy,
};
pub use netlist::*;
pub use production::*;
pub use spectre::parse_spectre;
pub use spice::{to_spice, PortMap, SpiceOpts};
pub use types::*;

// Re-exports so internal `crate::*` paths resolve after workspace split
pub use gdsverify_backend as backend;
pub use gdsverify_backend::rule;
pub use gdsverify_backend::session;
pub use gdsverify_core::gds;
pub use gdsverify_core::gds_lossless;
pub use gdsverify_core::geometry;
pub use gdsverify_core::hierarchy_index;
pub use gdsverify_core::params;
pub use gdsverify_core::schema;
pub use gdsverify_pex as pex;

use std::cell::RefCell;

/// Context handed to the check rules after the compare pipeline's
/// extract/graph-build/refinement stages have run.
pub struct LvsCtx<'a> {
    pub extracted: &'a ExtractedNetlist,
    pub reference: &'a RefNetlist,
    pub opts: &'a CompareOpts,
    /// Refined class/graph state; `None` while the pre-refinement
    /// (device-count fast-fail, floating-net, label-conflict) rules run.
    pub refined: Option<&'a compare::Refined>,
    /// First failing rule's reason string, set via [`LvsCtx::fail`]. A rule
    /// that records findings without setting this is non-fatal.
    pub fail_reason: RefCell<Option<String>>,
}

impl LvsCtx<'_> {
    /// Record this comparison's failure reason (first writer wins).
    pub fn fail(&self, reason: String) {
        self.fail_reason.borrow_mut().get_or_insert(reason);
    }
}

/// A boxed LVS check rule, as handed back by the generated rule registry.
pub type BoxedRule = Box<dyn for<'a> crate::rule::Rule<LvsCtx<'a>, Finding = Mismatch>>;

pub mod rules {
    use super::BoxedRule;
    /// One factory per file in `src/lvs/rules/`; `None` = rule not applicable.
    pub type Factory = fn(&super::CompareOpts) -> Option<BoxedRule>;
    include!(concat!(env!("OUT_DIR"), "/lvs_rules.rs"));
}

/// Forced-backend extraction: returns both netlist and telemetry.
/// `Backend::Gpu` without a device → `Err`.
pub fn extract_netlist_backend(
    store: &crate::geometry::GeometryStore,
    deck: &crate::params::Deck,
    backend: crate::backend::Backend,
) -> Result<(ExtractedNetlist, crate::backend::BackendTelemetry), String> {
    let session = crate::session::Session::new(backend).map_err(|e| e.to_string())?;
    let netlist = extract_netlist_opts(
        store,
        deck,
        &ExtractOpts {
            cut_required: deck.lvs_cut_required,
            ..Default::default()
        },
        backend,
    )?;
    Ok((netlist, session.telemetry()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::Backend;
    use crate::geometry::{Bbox, GeometryStore};
    use crate::params::{ConnectivityConfig, Deck, DeviceConfig, LayerDef, LayerTable, MosRule};
    use std::collections::HashMap;

    fn layer_table() -> LayerTable {
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
        LayerTable::from_defs(&defs)
    }

    fn test_deck() -> Deck {
        let lt = layer_table();
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
        let mos_rules = vec![
            MosRule {
                name: "nmos".into(),
                gate_layer: lt.id("poly").unwrap(),
                channel_layer: lt.id("diff").unwrap(),
                type_implant: lt.id("nsdm").unwrap(),
                device_type: "nmos".into(),
                flavor_markers: Vec::new(),
                well_layer: None,
                device_class: None,
            },
            MosRule {
                name: "pmos".into(),
                gate_layer: lt.id("poly").unwrap(),
                channel_layer: lt.id("diff").unwrap(),
                type_implant: lt.id("psdm").unwrap(),
                device_type: "pmos".into(),
                flavor_markers: Vec::new(),
                well_layer: None,
                device_class: None,
            },
        ];
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
            w_tolerance: crate::schema::PropertyTolerance::default(),
            l_tolerance: crate::schema::PropertyTolerance::default(),
            fail_on_floating: false,
            erc: crate::params::ErcParams::default(),
            intra_layer_touch: false,
            global_nets: Vec::new(),
            device_catalog: HashMap::new(),
            pex_method: Default::default(),
        }
    }

    #[test]
    fn gate_split_two_fingers() {
        let deck = test_deck();
        let lt = &deck.layers;
        let diff = lt.id("diff").unwrap();
        let poly = lt.id("poly").unwrap();
        let li = lt.id("li").unwrap();
        let nsdm = lt.id("nsdm").unwrap();

        let mut st = GeometryStore::new();
        let d = st.add_rect(diff, 0, 0, 1000, 200);
        st.add_rect(poly, 200, -50, 60, 300);
        st.add_rect(poly, 600, -50, 60, 300);
        st.add_rect(li, 50, 50, 100, 100);
        st.add_rect(li, 350, 50, 100, 100);
        st.add_rect(li, 800, 50, 100, 100);
        let imp = st.add_rect(nsdm, -100, -100, 1200, 400);

        let ext = extract_netlist(&st, &deck).unwrap();
        assert_eq!(ext.devices.len(), 2);
        let (d0, d1) = (&ext.devices[0], &ext.devices[1]);
        assert_eq!(d0.kind, DeviceKind::Nmos);
        assert_eq!(d1.kind, DeviceKind::Nmos);
        assert_ne!(d0.gate, d1.gate);
        assert_ne!(d0.source, d0.drain);
        assert_ne!(d1.source, d1.drain);
        assert_eq!(d0.drain, d1.source);
        assert_ne!(d0.source, d1.drain);
        assert_eq!((d0.w, d0.l), (200, 60));
        assert_eq!((d1.w, d1.l), (200, 60));
        assert_eq!(ext.net_count, 5);
        assert_eq!(ext.used_nets, 5);
        assert_eq!(ext.net_of_poly.len(), st.poly_count());
        assert_eq!(ext.net_of_poly[d.0 as usize], d0.source);
        assert_eq!(ext.net_of_poly[imp.0 as usize], u32::MAX);
    }

    fn two_device_reference() -> RefNetlist {
        RefNetlist {
            devices: vec![
                RefDevice {
                    kind: DeviceKind::Pmos,
                    gate: "A".into(),
                    source: "VDD".into(),
                    drain: "Y".into(),
                    w: 0,
                    l: 0,
                    flavor: DeviceFlavor::Standard,
                    ..Default::default()
                },
                RefDevice {
                    kind: DeviceKind::Nmos,
                    gate: "A".into(),
                    source: "VSS".into(),
                    drain: "Y".into(),
                    w: 0,
                    l: 0,
                    flavor: DeviceFlavor::Standard,
                    ..Default::default()
                },
            ],
            net_seeds: HashMap::new(),
            ref_two_terminal: Vec::new(),
            ref_bjt: Vec::new(),
        }
    }

    #[test]
    fn compare_detects_swapped_gate() {
        let reference = two_device_reference();
        let cmp_opts = CompareOpts::default();

        let good = ExtractedNetlist {
            devices: vec![
                Device {
                    kind: DeviceKind::Pmos,
                    gate: 0,
                    source: 1,
                    drain: 2,
                    body: 0,
                    flavor: DeviceFlavor::Standard,
                    w: 0,
                    l: 0,
                    device_class: None,
                    ..Default::default()
                },
                Device {
                    kind: DeviceKind::Nmos,
                    gate: 0,
                    source: 3,
                    drain: 2,
                    body: 0,
                    flavor: DeviceFlavor::Standard,
                    w: 0,
                    l: 0,
                    device_class: None,
                    ..Default::default()
                },
            ],
            net_count: 4,
            used_nets: 4,
            net_of_poly: Vec::new(),
            label_conflicts: Vec::new(),
            two_terminal: Vec::new(),
            bjt_devices: Vec::new(),
            floating_nets: Vec::new(),
            net_names: HashMap::new(),
        };
        let r = compare(&good, &reference, &cmp_opts);
        assert!(r.matched, "good wiring should match: {}", r.reason);

        let bad = ExtractedNetlist {
            devices: vec![
                Device {
                    kind: DeviceKind::Pmos,
                    gate: 0,
                    source: 1,
                    drain: 2,
                    body: 0,
                    flavor: DeviceFlavor::Standard,
                    w: 0,
                    l: 0,
                    device_class: None,
                    ..Default::default()
                },
                Device {
                    kind: DeviceKind::Nmos,
                    gate: 4,
                    source: 3,
                    drain: 2,
                    body: 0,
                    flavor: DeviceFlavor::Standard,
                    w: 0,
                    l: 0,
                    device_class: None,
                    ..Default::default()
                },
            ],
            net_count: 5,
            used_nets: 5,
            net_of_poly: Vec::new(),
            label_conflicts: Vec::new(),
            two_terminal: Vec::new(),
            bjt_devices: Vec::new(),
            floating_nets: Vec::new(),
            net_names: HashMap::new(),
        };
        let r = compare(&bad, &reference, &cmp_opts);
        assert!(!r.matched);
        assert!(
            r.reason.starts_with("topology mismatch"),
            "reason: {}",
            r.reason
        );
    }

    fn inverter_extracted(nmos_w: i32) -> ExtractedNetlist {
        ExtractedNetlist {
            devices: vec![
                Device {
                    kind: DeviceKind::Pmos,
                    gate: 0,
                    source: 1,
                    drain: 2,
                    body: 0,
                    flavor: DeviceFlavor::Standard,
                    w: 5000,
                    l: 1000,
                    device_class: None,
                    ..Default::default()
                },
                Device {
                    kind: DeviceKind::Nmos,
                    gate: 0,
                    source: 3,
                    drain: 2,
                    body: 0,
                    flavor: DeviceFlavor::Standard,
                    w: nmos_w,
                    l: 1000,
                    device_class: None,
                    ..Default::default()
                },
            ],
            net_count: 4,
            used_nets: 4,
            net_of_poly: Vec::new(),
            label_conflicts: Vec::new(),
            two_terminal: Vec::new(),
            bjt_devices: Vec::new(),
            floating_nets: Vec::new(),
            net_names: HashMap::new(),
        }
    }

    fn inverter_reference(w: (i32, i32), l: (i32, i32)) -> RefNetlist {
        RefNetlist {
            devices: vec![
                RefDevice {
                    kind: DeviceKind::Pmos,
                    gate: "A".into(),
                    source: "VDD".into(),
                    drain: "Y".into(),
                    w: w.0,
                    l: l.0,
                    flavor: DeviceFlavor::Standard,
                    ..Default::default()
                },
                RefDevice {
                    kind: DeviceKind::Nmos,
                    gate: "A".into(),
                    source: "VSS".into(),
                    drain: "Y".into(),
                    w: w.1,
                    l: l.1,
                    flavor: DeviceFlavor::Standard,
                    ..Default::default()
                },
            ],
            net_seeds: HashMap::new(),
            ref_two_terminal: Vec::new(),
            ref_bjt: Vec::new(),
        }
    }

    #[test]
    fn parametric_wrong_width_mismatch() {
        let reference = inverter_reference((5000, 2000), (1000, 1000));
        let cmp_opts = CompareOpts::default();

        let r = compare(&inverter_extracted(1500), &reference, &cmp_opts);
        assert!(!r.matched);
        assert!(
            r.reason.starts_with("parametric mismatch"),
            "reason: {}",
            r.reason
        );

        let r = compare(&inverter_extracted(2000), &reference, &cmp_opts);
        assert!(r.matched, "exact W/L should match: {}", r.reason);

        let r = compare(&inverter_extracted(2030), &reference, &cmp_opts);
        assert!(r.matched, "within-tolerance W should match: {}", r.reason);
    }

    #[test]
    fn parametric_two_fingers() {
        let deck = test_deck();
        let lt = &deck.layers;
        let diff = lt.id("diff").unwrap();
        let poly = lt.id("poly").unwrap();
        let li = lt.id("li").unwrap();
        let nsdm = lt.id("nsdm").unwrap();

        let mut st = GeometryStore::new();
        st.add_rect(diff, 0, 0, 1000, 5000);
        st.add_rect(poly, 200, -50, 60, 5100);
        st.add_rect(poly, 600, -50, 60, 5100);
        st.add_rect(li, 50, 2000, 100, 100);
        st.add_rect(li, 350, 2000, 100, 100);
        st.add_rect(li, 800, 2000, 100, 100);
        st.add_rect(nsdm, -100, -100, 1200, 5200);

        let ext = extract_netlist(&st, &deck).unwrap();
        assert_eq!(ext.devices.len(), 2);
        assert!(ext.devices.iter().all(|d| d.w == 5000 && d.l == 60));

        let make_ref = |w: i32| RefNetlist {
            devices: vec![
                RefDevice {
                    kind: DeviceKind::Nmos,
                    gate: "A1".into(),
                    source: "S".into(),
                    drain: "M".into(),
                    w,
                    l: 60,
                    flavor: DeviceFlavor::Standard,
                    ..Default::default()
                },
                RefDevice {
                    kind: DeviceKind::Nmos,
                    gate: "A2".into(),
                    source: "M".into(),
                    drain: "D".into(),
                    w,
                    l: 60,
                    flavor: DeviceFlavor::Standard,
                    ..Default::default()
                },
            ],
            net_seeds: HashMap::new(),
            ref_two_terminal: Vec::new(),
            ref_bjt: Vec::new(),
        };

        let cmp_opts = CompareOpts::default();
        let r = compare(&ext, &make_ref(5000), &cmp_opts);
        assert!(r.matched, "per-finger W=5000 should match: {}", r.reason);

        let r = compare(&ext, &make_ref(4000), &cmp_opts);
        assert!(!r.matched);
        assert!(
            r.reason.starts_with("parametric mismatch"),
            "reason: {}",
            r.reason
        );
    }

    #[test]
    fn parametric_legacy_mode_skips() {
        let cmp_opts = CompareOpts::default();
        let reference = inverter_reference((0, 2000), (1000, 1000));
        let r = compare(&inverter_extracted(999), &reference, &cmp_opts);
        assert!(r.matched, "legacy mode must skip parametric: {}", r.reason);

        let reference = inverter_reference((5000, 2000), (1000, 0));
        let r = compare(&inverter_extracted(999), &reference, &cmp_opts);
        assert!(r.matched, "l == 0 must also skip parametric: {}", r.reason);
    }

    #[test]
    fn cut_required_connectivity() {
        let deck = test_deck();
        let lt = &deck.layers;
        let diff = lt.id("diff").unwrap();
        let li = lt.id("li").unwrap();
        let licon = lt.id("licon").unwrap();
        let met1 = lt.id("met1").unwrap();
        let mcon = lt.id("mcon").unwrap();

        let mut st = GeometryStore::new();
        let d = st.add_rect(diff, 0, 0, 400, 200);
        let l = st.add_rect(li, 100, 50, 100, 100);

        let opts = ExtractOpts {
            cut_required: true,
            ..Default::default()
        };
        let ext = extract_netlist_opts(&st, &deck, &opts, Backend::Cpu).unwrap();
        assert_eq!(
            ext.net_count, 2,
            "li over diff without licon must not connect"
        );
        assert_ne!(ext.net_of_poly[d.0 as usize], ext.net_of_poly[l.0 as usize]);

        let ext_default = extract_netlist(&st, &deck).unwrap();
        assert_eq!(ext_default.net_count, 1);

        st.add_rect(licon, 120, 70, 60, 60);
        let ext = extract_netlist_opts(&st, &deck, &opts, Backend::Cpu).unwrap();
        assert_eq!(ext.net_count, 1, "licon must bridge diff <-> li");
        assert_eq!(ext.net_of_poly[d.0 as usize], ext.net_of_poly[l.0 as usize]);

        let m = st.add_rect(met1, 100, 50, 100, 100);
        let ext = extract_netlist_opts(&st, &deck, &opts, Backend::Cpu).unwrap();
        assert_eq!(
            ext.net_count, 2,
            "met1 over li without mcon must not connect"
        );
        assert_ne!(ext.net_of_poly[m.0 as usize], ext.net_of_poly[l.0 as usize]);
        st.add_rect(mcon, 130, 80, 40, 40);
        let ext = extract_netlist_opts(&st, &deck, &opts, Backend::Cpu).unwrap();
        assert_eq!(ext.net_count, 1, "mcon must bridge li <-> met1");
    }

    #[test]
    fn exact_concave_geometry_does_not_bbox_short() {
        let mut deck = test_deck();
        deck.intra_layer_touch = true;
        let met1 = deck.layers.id("met1").unwrap();
        let mut st = GeometryStore::new();

        // Bottom/left L and top/right L have strongly overlapping bboxes but
        // their actual polygons are disjoint.
        let a = st.add_polygon(
            met1,
            &[(0, 0), (100, 0), (100, 20), (20, 20), (20, 100), (0, 100)],
        );
        let b = st.add_polygon(
            met1,
            &[
                (30, 110),
                (110, 110),
                (110, 30),
                (130, 30),
                (130, 130),
                (30, 130),
            ],
        );
        assert!(st.poly_bbox[a.0 as usize].overlaps(&st.poly_bbox[b.0 as usize]));

        let ext = extract_netlist(&st, &deck).unwrap();
        assert_eq!(
            ext.net_count, 2,
            "overlapping bboxes must not create an LVS short"
        );
        assert_ne!(ext.net_of_poly[a.0 as usize], ext.net_of_poly[b.0 as usize]);
    }

    #[test]
    fn device_marker_requires_actual_channel_overlap() {
        let deck = test_deck();
        let diff = deck.layers.id("diff").unwrap();
        let poly = deck.layers.id("poly").unwrap();
        let nsdm = deck.layers.id("nsdm").unwrap();
        let psdm = deck.layers.id("psdm").unwrap();
        let mut st = GeometryStore::new();
        st.add_rect(diff, 0, 0, 100, 100);
        st.add_rect(poly, 40, -20, 20, 140);
        let false_n = st.add_polygon(
            nsdm,
            &[
                (-10, -10),
                (110, -10),
                (110, -1),
                (-1, -1),
                (-1, 110),
                (-10, 110),
            ],
        );
        st.add_rect(psdm, 30, -10, 40, 120);
        assert!(st.poly_bbox[false_n.0 as usize].overlaps(&Bbox {
            xmin: 40,
            ymin: 0,
            xmax: 60,
            ymax: 100,
        }));

        let ext = extract_netlist(&st, &deck).unwrap();
        assert_eq!(ext.devices.len(), 1);
        assert_eq!(
            ext.devices[0].kind,
            DeviceKind::Pmos,
            "an implant bbox in a concave void must not classify the channel"
        );
    }

    #[test]
    fn non_rectilinear_uses_bbox_fallback() {
        let deck = test_deck();
        let met1 = deck.layers.id("met1").unwrap();
        let mut non_rect = GeometryStore::new();
        non_rect.add_polygon(met1, &[(0, 0), (100, 0), (80, 100), (0, 100)]);
        // ponytail: non-rectilinear now succeeds with bbox approximation
        let ext =
            extract_netlist(&non_rect, &deck).expect("non-rectilinear should use bbox fallback");
        assert_eq!(
            ext.net_count, 1,
            "single non-rect polygon should form one net"
        );
    }

    #[test]
    fn unclassified_geometry_fails_closed() {
        let deck = test_deck();
        let diff = deck.layers.id("diff").unwrap();
        let poly = deck.layers.id("poly").unwrap();
        let mut no_implant = GeometryStore::new();
        no_implant.add_rect(diff, 0, 0, 100, 100);
        no_implant.add_rect(poly, 40, -20, 20, 140);
        let err = extract_netlist(&no_implant, &deck)
            .err()
            .expect("unclassified channel must fail");
        assert!(
            err.contains("no matching MOS type implant"),
            "unexpected diagnostic: {err}"
        );

        let nsdm = deck.layers.id("nsdm").unwrap();
        let psdm = deck.layers.id("psdm").unwrap();
        let mut ambiguous_implant = GeometryStore::new();
        ambiguous_implant.add_rect(diff, 0, 0, 100, 100);
        ambiguous_implant.add_rect(poly, 40, -20, 20, 140);
        ambiguous_implant.add_rect(nsdm, -10, -10, 120, 120);
        ambiguous_implant.add_rect(psdm, -10, -10, 120, 120);
        let err = extract_netlist(&ambiguous_implant, &deck)
            .err()
            .expect("overlapping N/P implants must not select the first rule");
        assert!(err.contains("ambiguously matches MOS rules"), "{err}");

        let mut flavor_deck = test_deck();
        let hvt = flavor_deck.layers.id("nwell").unwrap();
        let lvt = flavor_deck.layers.id("licon").unwrap();
        flavor_deck.devices.mos_rules[0].flavor_markers =
            vec![(hvt, "hvt".into()), (lvt, "lvt".into())];
        let mut ambiguous_flavor = GeometryStore::new();
        ambiguous_flavor.add_rect(diff, 0, 0, 100, 100);
        ambiguous_flavor.add_rect(poly, 40, -20, 20, 140);
        ambiguous_flavor.add_rect(nsdm, -10, -10, 120, 120);
        ambiguous_flavor.add_rect(hvt, 30, -10, 40, 120);
        ambiguous_flavor.add_rect(lvt, 30, -10, 40, 120);
        let err = extract_netlist(&ambiguous_flavor, &flavor_deck)
            .err()
            .expect("overlapping HVT/LVT markers must not select the first marker");
        assert!(err.contains("multiple flavor markers"), "{err}");
    }

    #[test]
    fn global_net_merge_remaps_extracted_body_terminal() {
        let mut deck = test_deck();
        let nwell = deck.layers.id("nwell").unwrap();
        let diff = deck.layers.id("diff").unwrap();
        let poly = deck.layers.id("poly").unwrap();
        let nsdm = deck.layers.id("nsdm").unwrap();
        deck.connectivity.conductors.push(nwell);
        deck.devices.mos_rules[0].well_layer = Some(nwell);
        deck.global_nets.push("VBB".into());

        let mut st = GeometryStore::new();
        let remote_body = st.add_rect(nwell, -500, 0, 100, 100);
        st.add_rect(diff, 0, 0, 100, 100);
        st.add_rect(poly, 40, -20, 20, 140);
        st.add_rect(nsdm, -10, -10, 120, 120);
        let local_body = st.add_rect(nwell, -10, -10, 120, 120);
        st.net_labels.insert(remote_body.0, "VBB".into());
        st.net_labels.insert(local_body.0, "VBB".into());

        let ext = extract_netlist(&st, &deck).unwrap();
        assert_eq!(ext.devices.len(), 1);
        let global = ext.net_of_poly[remote_body.0 as usize];
        assert_eq!(global, ext.net_of_poly[local_body.0 as usize]);
        assert_eq!(
            ext.devices[0].body, global,
            "body terminal must follow global-net canonicalization"
        );
    }

    #[test]
    fn exact_boundary_contact_obeys_touch_policy() {
        let mut deck = test_deck();
        let met1 = deck.layers.id("met1").unwrap();
        let mut st = GeometryStore::new();
        let a = st.add_rect(met1, 0, 0, 100, 100);
        let b = st.add_rect(met1, 100, 20, 80, 60);

        deck.intra_layer_touch = false;
        let open = extract_netlist(&st, &deck).unwrap();
        assert_ne!(
            open.net_of_poly[a.0 as usize],
            open.net_of_poly[b.0 as usize]
        );

        deck.intra_layer_touch = true;
        let joined = extract_netlist(&st, &deck).unwrap();
        assert_eq!(
            joined.net_count, 1,
            "shared boundary must connect when enabled"
        );
        assert_eq!(
            joined.net_of_poly[a.0 as usize],
            joined.net_of_poly[b.0 as usize]
        );
    }

    #[test]
    fn cutless_mode_only_joins_declared_layer_pairs() {
        let deck = test_deck();
        let li = deck.layers.id("li").unwrap();
        let met1 = deck.layers.id("met1").unwrap();
        let met2 = deck.layers.id("met2").unwrap();

        let mut unrelated = GeometryStore::new();
        let l = unrelated.add_rect(li, 0, 0, 100, 100);
        let m2 = unrelated.add_rect(met2, 0, 0, 100, 100);
        let ext = extract_netlist(&unrelated, &deck).unwrap();
        assert_ne!(
            ext.net_of_poly[l.0 as usize], ext.net_of_poly[m2.0 as usize],
            "li/met2 have no common declared via and must remain isolated"
        );

        let mut related = GeometryStore::new();
        let l = related.add_rect(li, 0, 0, 100, 100);
        let m1 = related.add_rect(met1, 0, 0, 100, 100);
        let ext = extract_netlist(&related, &deck).unwrap();
        assert_eq!(
            ext.net_of_poly[l.0 as usize], ext.net_of_poly[m1.0 as usize],
            "legacy cutless mode may join layers paired by declared mcon"
        );
    }

    #[test]
    fn vialess_legacy_fallback_is_explicitly_cutless_only() {
        let mut deck = test_deck();
        deck.connectivity.vias.clear();
        let li = deck.layers.id("li").unwrap();
        let met2 = deck.layers.id("met2").unwrap();
        let mut st = GeometryStore::new();
        let l = st.add_rect(li, 0, 0, 100, 100);
        let m = st.add_rect(met2, 0, 0, 100, 100);

        let legacy = extract_netlist_opts(
            &st,
            &deck,
            &ExtractOpts {
                cut_required: false,
                ..Default::default()
            },
            Backend::Cpu,
        )
        .unwrap();
        assert_eq!(
            legacy.net_of_poly[l.0 as usize],
            legacy.net_of_poly[m.0 as usize]
        );

        let strict = extract_netlist_opts(
            &st,
            &deck,
            &ExtractOpts {
                cut_required: true,
                ..Default::default()
            },
            Backend::Cpu,
        )
        .unwrap();
        assert_ne!(
            strict.net_of_poly[l.0 as usize],
            strict.net_of_poly[m.0 as usize]
        );
    }

    /// Symmetric diff pair: two NMOS with shared source, mirrored drain/gate.
    /// This is an automorphism — the old comparator would stall; the new one
    /// must break it and still match.
    #[test]
    fn automorphism_diff_pair() {
        let reference = RefNetlist {
            devices: vec![
                RefDevice {
                    kind: DeviceKind::Nmos,
                    gate: "INP".into(),
                    source: "TAIL".into(),
                    drain: "OUTN".into(),
                    w: 0,
                    l: 0,
                    flavor: DeviceFlavor::Standard,
                    ..Default::default()
                },
                RefDevice {
                    kind: DeviceKind::Nmos,
                    gate: "INN".into(),
                    source: "TAIL".into(),
                    drain: "OUTP".into(),
                    w: 0,
                    l: 0,
                    flavor: DeviceFlavor::Standard,
                    ..Default::default()
                },
            ],
            net_seeds: HashMap::new(),
            ref_two_terminal: Vec::new(),
            ref_bjt: Vec::new(),
        };

        // Extracted: same topology, different net numbering
        let good = ExtractedNetlist {
            devices: vec![
                Device {
                    kind: DeviceKind::Nmos,
                    gate: 10,
                    source: 20,
                    drain: 30,
                    body: 0,
                    flavor: DeviceFlavor::Standard,
                    w: 0,
                    l: 0,
                    device_class: None,
                    ..Default::default()
                },
                Device {
                    kind: DeviceKind::Nmos,
                    gate: 11,
                    source: 20,
                    drain: 31,
                    body: 0,
                    flavor: DeviceFlavor::Standard,
                    w: 0,
                    l: 0,
                    device_class: None,
                    ..Default::default()
                },
            ],
            net_count: 5,
            used_nets: 5,
            net_of_poly: Vec::new(),
            label_conflicts: Vec::new(),
            two_terminal: Vec::new(),
            bjt_devices: Vec::new(),
            floating_nets: Vec::new(),
            net_names: HashMap::new(),
        };
        let r = compare(&good, &reference, &CompareOpts::default());
        assert!(r.matched, "symmetric diff pair should match: {}", r.reason);
        // Automorphism should be resolved (0 ambiguous after breaking)
        assert_eq!(
            r.ambiguous_classes, 0,
            "automorphisms should be fully resolved"
        );
    }

    /// Two-terminal device on wrong net must be caught (not just count-checked).
    #[test]
    fn two_terminal_wrong_net() {
        let reference = RefNetlist {
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
            ref_two_terminal: vec![RefTwoTerminal {
                kind: TwoTerminalKind::Resistor,
                name: "r1".into(),
                terminal_a: "D".into(),
                terminal_b: "VDD".into(),
            }],
            ref_bjt: Vec::new(),
        };

        // Correct: resistor between drain and VDD
        let good = ExtractedNetlist {
            devices: vec![Device {
                kind: DeviceKind::Nmos,
                gate: 0,
                source: 1,
                drain: 2,
                body: 0,
                flavor: DeviceFlavor::Standard,
                w: 0,
                l: 0,
                device_class: None,
                ..Default::default()
            }],
            net_count: 4,
            used_nets: 4,
            net_of_poly: Vec::new(),
            label_conflicts: Vec::new(),
            two_terminal: vec![TwoTerminalDevice {
                kind: TwoTerminalKind::Resistor,
                name: "r1".into(),
                terminal_a: 2,
                terminal_b: 3,
                value: 100.0,
            }],
            bjt_devices: Vec::new(),
            floating_nets: Vec::new(),
            net_names: HashMap::new(),
        };
        let r = compare(&good, &reference, &CompareOpts::default());
        assert!(
            r.matched,
            "correct resistor placement should match: {}",
            r.reason
        );

        // Wrong: resistor between gate and VDD (should be drain/source and VDD).
        // Gate is not S/D-permutable, so this is a genuine topology mismatch.
        let bad = ExtractedNetlist {
            devices: vec![Device {
                kind: DeviceKind::Nmos,
                gate: 0,
                source: 1,
                drain: 2,
                body: 0,
                flavor: DeviceFlavor::Standard,
                w: 0,
                l: 0,
                device_class: None,
                ..Default::default()
            }],
            net_count: 4,
            used_nets: 4,
            net_of_poly: Vec::new(),
            label_conflicts: Vec::new(),
            two_terminal: vec![TwoTerminalDevice {
                kind: TwoTerminalKind::Resistor,
                name: "r1".into(),
                terminal_a: 0,
                terminal_b: 3,
                value: 100.0,
            }],
            bjt_devices: Vec::new(),
            floating_nets: Vec::new(),
            net_names: HashMap::new(),
        };
        let r = compare(&bad, &reference, &CompareOpts::default());
        assert!(!r.matched, "resistor on gate (not S/D) should mismatch");
    }
}
