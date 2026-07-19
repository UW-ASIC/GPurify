use gdsverify_core::geometry::GeometryStore;
use gdsverify_core::params::Deck;
use gdsverify_pex::{
    run_pex_by_net, run_pex_by_net_with_accuracy, run_pex_by_net_with_accuracy_checked, Accuracy,
    PexError,
};

fn deck(method: &str) -> Deck {
    Deck::from_json(&format!(
        r#"{{
            "layers": {{
                "met1": {{ "layer": 68, "datatype": 20 }},
                "via1": {{ "layer": 67, "datatype": 44 }}
            }},
            "drc": {{}},
            "pex_method": "{method}",
            "pex": {{
                "met1": {{
                    "sheet_res_ohm_sq": 0.1,
                    "area_cap_af_um2": 25.0,
                    "fringe_cap_af_um": 40.0,
                    "coupling_cap_af_um": 100.0,
                    "coupling_ref_spacing_nm": 200.0,
                    "thickness_nm": 200.0,
                    "height_nm": 500.0,
                    "dielectric_k": 3.9
                }},
                "via1": {{
                    "sheet_res_ohm_sq": 0.0,
                    "area_cap_af_um2": 0.0,
                    "fringe_cap_af_um": 0.0,
                    "coupling_cap_af_um": 0.0,
                    "coupling_ref_spacing_nm": 1.0,
                    "via_res_ohm": 5.0,
                    "thickness_nm": 200.0,
                    "height_nm": 300.0,
                    "dielectric_k": 3.9
                }}
            }}
        }}"#
    ))
    .unwrap()
}

#[test]
fn field_solver_is_a_real_drop_in_for_per_net_pex() {
    let deck = deck("field_solver");
    let met1 = deck.layers.id("met1").unwrap();
    let mut store = GeometryStore::new();
    store.add_rect(met1, 0, 0, 2_000, 500);

    let analytical = run_pex_by_net_with_accuracy(&store, &deck, &[7], Accuracy::Analytical)[&7];
    let field = run_pex_by_net_with_accuracy_checked(&store, &deck, &[7], Accuracy::Quasistatic)
        .unwrap()[&7];

    // The DC FastHenry segment preserves the sheet-resistance contract.
    assert!((field.r_ohm - analytical.r_ohm).abs() < 1.0e-12);
    // Capacitance is produced by the 3-D Maxwell solve, not the analytical
    // area/fringe formula, so it must be physical and observably independent.
    assert!(field.cap_af.is_finite() && field.cap_af > 0.0);
    assert!((field.cap_af - analytical.cap_af).abs() > 1.0e-3);

    // The deck-selected API is the same drop-in shape and reaches the same path.
    assert_eq!(run_pex_by_net(&store, &deck, &[7])[&7], field);
}

#[test]
fn same_net_overlaps_are_unioned_before_panelization() {
    let deck = deck("field_solver");
    let met1 = deck.layers.id("met1").unwrap();
    let mut store = GeometryStore::new();
    store.add_rect(met1, 0, 0, 1_000, 500);
    store.add_rect(met1, 500, 0, 1_000, 500);

    let result =
        run_pex_by_net_with_accuracy_checked(&store, &deck, &[3, 3], Accuracy::Quasistatic)
            .unwrap();
    assert!(result[&3].cap_af.is_finite() && result[&3].cap_af > 0.0);
    assert!(result[&3].r_ohm > 0.0);
}

#[test]
fn fixed_via_resistance_remains_a_deck_contribution() {
    let deck = deck("field_solver");
    let via1 = deck.layers.id("via1").unwrap();
    let mut store = GeometryStore::new();
    store.add_rect(via1, 0, 0, 100, 100);
    store.add_rect(via1, 200, 0, 100, 100);

    let result =
        run_pex_by_net_with_accuracy_checked(&store, &deck, &[9, 9], Accuracy::Quasistatic)
            .unwrap();
    assert_eq!(result[&9].r_ohm, 10.0);
    assert_eq!(result[&9].cap_af, 0.0);
}

#[test]
fn layout_dbu_is_applied_before_the_field_solve() {
    let one_nm = deck("field_solver");
    let mut two_nm = deck("field_solver");
    two_nm.dbu_nm = 2.0;
    let met1 = one_nm.layers.id("met1").unwrap();
    let mut store = GeometryStore::new();
    store.add_rect(met1, 0, 0, 1_000, 500);

    let at_one_nm =
        run_pex_by_net_with_accuracy_checked(&store, &one_nm, &[4], Accuracy::Quasistatic).unwrap()
            [&4];
    let at_two_nm =
        run_pex_by_net_with_accuracy_checked(&store, &two_nm, &[4], Accuracy::Quasistatic).unwrap()
            [&4];

    // A DBU scale changes physical dimensions but not the rectangle's square
    // count, so R is invariant while the field-solved capacitance changes.
    assert!((at_one_nm.r_ohm - at_two_nm.r_ohm).abs() < 1.0e-12);
    assert!((at_one_nm.cap_af - at_two_nm.cap_af).abs() > 1.0e-3);
}

#[test]
fn checked_field_solver_fails_closed_on_non_manhattan_geometry() {
    let deck = deck("field_solver");
    let met1 = deck.layers.id("met1").unwrap();
    let mut store = GeometryStore::new();
    store.add_polygon(met1, &[(0, 0), (1_000, 0), (800, 500), (0, 500)]);

    let error = run_pex_by_net_with_accuracy_checked(&store, &deck, &[1], Accuracy::Quasistatic)
        .unwrap_err();
    let PexError::UnsupportedGeometry(diagnostics) = error;
    assert!(
        matches!(
            diagnostics.as_slice(),
            [gdsverify_pex::Parasitic::ExtractionDiagnostic { model, message, .. }]
                if model == "quasistatic"
                    && (message.contains("non-rectilinear") || message.contains("non-Manhattan"))
        ),
        "{diagnostics:?}"
    );
}
