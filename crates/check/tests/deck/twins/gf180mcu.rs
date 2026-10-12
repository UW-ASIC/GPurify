//! The Rust twin of `pdks/gf180mcu.deck`: the same deck stated with
//! [`DeckBuilder`], statement by statement, `for` loops unrolled and `let`
//! bindings substituted. Translated once from the deck text by a reader of
//! the deck language independent of the parser; the twin test holds this
//! to the parsed text. After editing the deck, edit this to match: the test
//! names the first difference.

#![allow(clippy::unreadable_literal, reason = "values as the deck writes them")]

use gpurify_check::deck::rules::{
    angle, antenna, antenna_electrical, cut_size, drain_source, edge_min_length,
    em_current_density, esd_topological, floating_gate, floating_well, forbidden, gate_oxide,
    global_density, ir_drop, max_distance_to_tap, max_width, min_area, min_enclosed_area,
    min_enclosure, min_extension, min_spacing, min_spacing_diff, min_width, multiple_drivers,
    must_be_inside, notch, off_grid, overlap, supply_short, tie_high_low, unconnected_pin,
    via_array_spacing, wide_dependent_spacing,
};
use gpurify_check::deck::{BuildError, CompiledDeck, DeckBuilder, LayerRef};
use gpurify_geom::{Dbu, DbuArea, Grid, StrTable};
use gpurify_ingest::deck::{DeviceKind, DeviceValue, StackSource};
use std::collections::HashMap;

fn nm(raw: i64) -> Dbu {
    Dbu::new_unchecked(raw)
}

fn nm2(raw: i64) -> DbuArea {
    DbuArea::new(i128::from(raw))
}

/// `pdks/gf180mcu.deck`, built on a 1 nm grid into `strings`.
#[allow(
    clippy::too_many_lines,
    reason = "a whole deck, statement by statement"
)]
pub fn build(strings: &mut StrTable) -> Result<CompiledDeck, BuildError> {
    let mut d = DeckBuilder::new(Grid::new(1000).expect("a 1 nm grid"), strings);
    let mut l: HashMap<&str, LayerRef> = HashMap::new();
    l.insert("dnwell", d.layer("dnwell", (12, 0)));
    l.insert("nwell", d.layer("nwell", (21, 0)));
    l.insert("lvpwell", d.layer("lvpwell", (204, 0)));
    l.insert("comp", d.layer("comp", (22, 0)));
    l.insert("dualgate", d.layer("dualgate", (55, 0)));
    l.insert("poly2", d.layer("poly2", (30, 0)));
    l.insert("nplus", d.layer("nplus", (32, 0)));
    l.insert("pplus", d.layer("pplus", (31, 0)));
    l.insert("sab", d.layer("sab", (49, 0)));
    l.insert("esd", d.layer("esd", (24, 0)));
    l.insert("contact", d.layer("contact", (33, 0)));
    l.insert("metal1", d.layer("metal1", (34, 0)));
    l.insert("via1", d.layer("via1", (35, 0)));
    l.insert("metal2", d.layer("metal2", (36, 0)));
    l.insert("via2", d.layer("via2", (38, 0)));
    l.insert("metal3", d.layer("metal3", (42, 0)));
    l.insert("via3", d.layer("via3", (40, 0)));
    l.insert("metal4", d.layer("metal4", (46, 0)));
    l.insert("via4", d.layer("via4", (41, 0)));
    l.insert("metal5", d.layer("metal5", (81, 0)));
    l.insert("via5", d.layer("via5", (82, 0)));
    l.insert("metaltop", d.layer("metaltop", (53, 0)));
    l.insert("pad", d.layer("pad", (37, 0)));
    l.insert("resistor", d.layer("resistor", (62, 0)));
    l.insert("fusetop", d.layer("fusetop", (75, 0)));
    l.insert("nat", d.layer("nat", (5, 0)));
    l.insert("mvsd", d.layer("mvsd", (210, 0)));
    l.insert("mvpsd", d.layer("mvpsd", (11, 39)));
    l.insert("poly2_dummy", d.layer("poly2_dummy", (30, 4)));
    l.insert("metal1_dummy", d.layer("metal1_dummy", (34, 4)));
    l.insert("metal2_dummy", d.layer("metal2_dummy", (36, 4)));
    l.insert("metal3_dummy", d.layer("metal3_dummy", (42, 4)));
    l.insert("metal4_dummy", d.layer("metal4_dummy", (46, 4)));
    l.insert("metal5_dummy", d.layer("metal5_dummy", (81, 4)));
    l.insert("metaltop_dummy", d.layer("metaltop_dummy", (53, 4)));
    l.insert("comp_label", d.layer("comp_label", (22, 10)));
    l.insert("poly2_label", d.layer("poly2_label", (30, 10)));
    l.insert("metal1_label", d.layer("metal1_label", (34, 10)));
    l.insert("metal2_label", d.layer("metal2_label", (36, 10)));
    l.insert("metal3_label", d.layer("metal3_label", (42, 10)));
    l.insert("metal4_label", d.layer("metal4_label", (46, 10)));
    l.insert("metal5_label", d.layer("metal5_label", (81, 10)));
    l.insert("metaltop_label", d.layer("metaltop_label", (53, 10)));
    l.insert("res_mk", d.layer("res_mk", (110, 5)));
    l.insert("v5_xtor", d.layer("v5_xtor", (112, 1)));
    l.insert("cap_mk", d.layer("cap_mk", (117, 5)));
    l.insert("mos_cap_mk", d.layer("mos_cap_mk", (166, 5)));
    l.insert("drc_bjt", d.layer("drc_bjt", (127, 5)));
    l.insert("esd_mk", d.layer("esd_mk", (24, 5)));
    l.insert("ldmos_xtor", d.layer("ldmos_xtor", (226, 0)));
    l.insert("plfuse", d.layer("plfuse", (125, 5)));
    l.insert("otp_mk", d.layer("otp_mk", (173, 5)));
    l.insert("metal1_res", d.layer("metal1_res", (110, 11)));
    l.insert("metal2_res", d.layer("metal2_res", (110, 12)));
    l.insert("metal3_res", d.layer("metal3_res", (110, 13)));
    l.insert("metal6_res", d.layer("metal6_res", (110, 16)));
    l.insert("ncomp", d.derived("ncomp", l["comp"].and(l["nplus"])));
    l.insert("pcomp", d.derived("pcomp", l["comp"].and(l["pplus"])));
    l.insert("gate", d.derived("gate", l["poly2"].and(l["comp"])));
    l.insert("ngate", d.derived("ngate", l["gate"].and(l["nplus"])));
    l.insert("pgate", d.derived("pgate", l["gate"].and(l["pplus"])));
    l.insert(
        "gate_hv",
        d.derived("gate_hv", l["gate"].and(l["dualgate"])),
    );
    l.insert(
        "comp_hv",
        d.derived("comp_hv", l["comp"].interacting(l["dualgate"])),
    );
    l.insert(
        "poly2_hv",
        d.derived(
            "poly2_hv",
            l["poly2"].interacting(l["dualgate"]).outside(l["plfuse"]),
        ),
    );
    l.insert(
        "nwell_hv",
        d.derived("nwell_hv", l["nwell"].interacting(l["dualgate"])),
    );
    l.insert(
        "lvpwell_hv",
        d.derived("lvpwell_hv", l["lvpwell"].interacting(l["dualgate"])),
    );
    l.insert(
        "dnwell_hv",
        d.derived("dnwell_hv", l["dnwell"].interacting(l["dualgate"])),
    );
    l.insert(
        "nwell_out_dn",
        d.derived("nwell_out_dn", l["nwell"].outside(l["dnwell"])),
    );
    l.insert(
        "nwell_in_dn",
        d.derived("nwell_in_dn", l["nwell"].interacting(l["dnwell"])),
    );
    l.insert(
        "lvpwell_in_dn",
        d.derived("lvpwell_in_dn", l["lvpwell"].inside(l["dnwell"])),
    );
    l.insert(
        "lvpwell_dn",
        d.derived("lvpwell_dn", l["lvpwell"].interacting(l["dnwell"])),
    );
    l.insert(
        "lvpwell_out_dn",
        d.derived("lvpwell_out_dn", l["lvpwell"].outside(l["dnwell"])),
    );
    l.insert(
        "nw_res_mk",
        d.derived(
            "nw_res_mk",
            l["res_mk"]
                .interacting(l["nwell"])
                .not(l["res_mk"].inside(l["nwell"])),
        ),
    );
    l.insert(
        "nwell_res",
        d.derived("nwell_res", l["nwell_out_dn"].and(l["nw_res_mk"])),
    );
    l.insert(
        "comp_moscap",
        d.derived("comp_moscap", l["comp"].and(l["mos_cap_mk"])),
    );
    l.insert(
        "comp_in_moscap",
        d.derived("comp_in_moscap", l["comp"].inside(l["mos_cap_mk"])),
    );
    l.insert(
        "comp_nocap",
        d.derived("comp_nocap", l["comp"].not(l["comp_in_moscap"])),
    );
    l.insert(
        "comp_bjt",
        d.derived("comp_bjt", l["comp"].inside(l["drc_bjt"])),
    );
    l.insert(
        "ntap",
        d.derived("ntap", l["ncomp"].inside(l["nwell"]).not(l["res_mk"])),
    );
    l.insert(
        "ptap",
        d.derived(
            "ptap",
            l["pcomp"]
                .outside(l["nwell"])
                .outside(l["dnwell"])
                .not(l["res_mk"]),
        ),
    );
    l.insert(
        "sd",
        d.derived(
            "sd",
            l["comp"]
                .not(l["poly2"])
                .not(l["res_mk"])
                .not(l["ntap"])
                .not(l["ptap"]),
        ),
    );
    l.insert(
        "poly2_con",
        d.derived("poly2_con", l["poly2"].not(l["res_mk"]).not(l["plfuse"])),
    );
    l.insert(
        "metal1_con",
        d.derived("metal1_con", l["metal1"].not(l["metal1_res"])),
    );
    l.insert(
        "metal2_con",
        d.derived("metal2_con", l["metal2"].not(l["metal2_res"])),
    );
    l.insert(
        "metal3_con",
        d.derived("metal3_con", l["metal3"].not(l["metal3_res"])),
    );
    l.insert(
        "metaltop_con",
        d.derived("metaltop_con", l["metaltop"].not(l["metal6_res"])),
    );
    l.insert(
        "via5_nomim",
        d.derived("via5_nomim", l["via5"].not(l["fusetop"])),
    );
    l.insert(
        "ntap_dn",
        d.derived(
            "ntap_dn",
            l["ncomp"].outside(l["lvpwell"]).inside(l["dnwell"]),
        ),
    );
    l.insert(
        "ntap_dn_hv",
        d.derived("ntap_dn_hv", l["ntap_dn"].interacting(l["dualgate"])),
    );
    l.insert(
        "ncomp_notgate",
        d.derived("ncomp_notgate", l["ncomp"].not_interacting(l["gate"])),
    );
    l.insert(
        "ncomp_dn",
        d.derived("ncomp_dn", l["ncomp_notgate"].interacting(l["dnwell"])),
    );
    l.insert(
        "ncomp_dn_hv",
        d.derived("ncomp_dn_hv", l["ncomp_dn"].interacting(l["dualgate"])),
    );
    l.insert(
        "pcomp_out_dn",
        d.derived("pcomp_out_dn", l["pcomp"].outside(l["dnwell"])),
    );
    l.insert(
        "pcomp_nw",
        d.derived("pcomp_nw", l["pcomp_out_dn"].interacting(l["nwell"])),
    );
    l.insert(
        "pcomp_nw_hv",
        d.derived("pcomp_nw_hv", l["pcomp_nw"].interacting(l["dualgate"])),
    );
    l.insert(
        "ncomp_out_dn",
        d.derived("ncomp_out_dn", l["ncomp"].outside(l["dnwell"])),
    );
    l.insert(
        "ncomp_nw",
        d.derived("ncomp_nw", l["ncomp_out_dn"].interacting(l["nwell"])),
    );
    l.insert(
        "ncomp_nw_hv",
        d.derived("ncomp_nw_hv", l["ncomp_nw"].interacting(l["dualgate"])),
    );
    l.insert(
        "pcomp_dn",
        d.derived("pcomp_dn", l["pcomp"].interacting(l["dnwell"])),
    );
    l.insert(
        "pcomp_dn_hv",
        d.derived("pcomp_dn_hv", l["pcomp_dn"].interacting(l["dualgate"])),
    );
    l.insert(
        "pcomp_out_nw",
        d.derived("pcomp_out_nw", l["pcomp"].outside(l["nwell"])),
    );
    l.insert(
        "pcomp_lvp",
        d.derived(
            "pcomp_lvp",
            l["pcomp_out_nw"].interacting(l["lvpwell_in_dn"]),
        ),
    );
    l.insert(
        "pcomp_lvp_hv",
        d.derived("pcomp_lvp_hv", l["pcomp_lvp"].interacting(l["dualgate"])),
    );
    l.insert(
        "pcomp_in_dn",
        d.derived("pcomp_in_dn", l["pcomp"].inside(l["dnwell"])),
    );
    l.insert(
        "pcomp_dn_nolvp",
        d.derived("pcomp_dn_nolvp", l["pcomp_in_dn"].outside(l["lvpwell"])),
    );
    l.insert(
        "pcomp_dn_nolvp_hv",
        d.derived(
            "pcomp_dn_nolvp_hv",
            l["pcomp_dn_nolvp"].interacting(l["dualgate"]),
        ),
    );
    l.insert(
        "ncomp_in_dn",
        d.derived("ncomp_in_dn", l["ncomp"].inside(l["dnwell"])),
    );
    l.insert(
        "ncomp_lvp",
        d.derived("ncomp_lvp", l["ncomp_in_dn"].interacting(l["lvpwell"])),
    );
    l.insert(
        "ncomp_lvp_hv",
        d.derived("ncomp_lvp_hv", l["ncomp_lvp"].interacting(l["dualgate"])),
    );
    l.insert(
        "ncomp_psub",
        d.derived(
            "ncomp_psub",
            l["ncomp"].outside(l["nwell"]).outside(l["dnwell"]),
        ),
    );
    l.insert(
        "ncomp_psub_hv",
        d.derived("ncomp_psub_hv", l["ncomp_psub"].interacting(l["dualgate"])),
    );
    l.insert(
        "pcomp_psub",
        d.derived(
            "pcomp_psub",
            l["pcomp"].outside(l["nwell"]).outside(l["dnwell"]),
        ),
    );
    l.insert(
        "pcomp_psub_hv",
        d.derived("pcomp_psub_hv", l["pcomp_psub"].interacting(l["dualgate"])),
    );
    l.insert(
        "pcomp_in_nw",
        d.derived("pcomp_in_nw", l["pcomp"].inside(l["nwell"])),
    );
    l.insert(
        "pcomp_in_nw_hv",
        d.derived(
            "pcomp_in_nw_hv",
            l["pcomp_in_nw"].interacting(l["dualgate"]),
        ),
    );
    l.insert(
        "ncomp_out_nw",
        d.derived("ncomp_out_nw", l["ncomp"].outside(l["nwell"])),
    );
    l.insert(
        "ncomp_out_nw_hv",
        d.derived(
            "ncomp_out_nw_hv",
            l["ncomp_out_nw"].interacting(l["dualgate"]),
        ),
    );
    l.insert(
        "comp_out_dv",
        d.derived("comp_out_dv", l["comp"].outside(l["dualgate"])),
    );
    l.insert("comp_dv", d.derived("comp_dv", l["comp_hv"].not(l["ptap"])));
    l.insert(
        "poly2_field",
        d.derived("poly2_field", l["poly2"].outside(l["comp"])),
    );
    l.insert(
        "comp_hv_noext",
        d.derived(
            "comp_hv_noext",
            l["comp_hv"].outside(l["mvsd"]).outside(l["mvpsd"]),
        ),
    );
    l.insert("poly_sab", d.derived("poly_sab", l["poly2"].and(l["sab"])));
    l.insert(
        "poly_sab_nonp",
        d.derived("poly_sab_nonp", l["poly_sab"].outside(l["nplus"])),
    );
    l.insert(
        "poly_sab_nopp",
        d.derived("poly_sab_nopp", l["poly_sab"].outside(l["pplus"])),
    );
    l.insert(
        "poly_sab_np",
        d.derived("poly_sab_np", l["poly_sab"].interacting(l["nplus"])),
    );
    l.insert(
        "poly_sab_pp",
        d.derived(
            "poly_sab_pp",
            l["poly_sab"]
                .not_interacting(l["resistor"])
                .interacting(l["pplus"]),
        ),
    );
    l.insert("comp_sab", d.derived("comp_sab", l["comp"].and(l["sab"])));
    l.insert(
        "comp_sab_np",
        d.derived("comp_sab_np", l["comp_sab"].interacting(l["nplus"])),
    );
    l.insert(
        "comp_sab_pp",
        d.derived("comp_sab_pp", l["comp_sab"].interacting(l["pplus"])),
    );
    l.insert(
        "sab_main",
        d.derived("sab_main", l["sab"].outside(l["otp_mk"])),
    );
    l.insert(
        "sab_field",
        d.derived("sab_field", l["sab_main"].outside(l["comp"])),
    );
    l.insert(
        "comp_nosab",
        d.derived("comp_nosab", l["comp"].outside(l["sab"])),
    );
    l.insert(
        "poly2_on_field",
        d.derived("poly2_on_field", l["poly2"].not(l["comp"])),
    );
    l.insert(
        "sab_off_pf",
        d.derived("sab_off_pf", l["sab_main"].outside(l["poly2_on_field"])),
    );
    l.insert(
        "pf_nosab",
        d.derived("pf_nosab", l["poly2_on_field"].outside(l["sab"])),
    );
    l.insert(
        "sab_off_gate",
        d.derived("sab_off_gate", l["sab_main"].outside(l["gate"])),
    );
    l.insert(
        "gate_nosab",
        d.derived("gate_nosab", l["gate"].outside(l["sab"])),
    );
    l.insert(
        "sab_noesd",
        d.derived("sab_noesd", l["sab_main"].outside(l["esd_mk"])),
    );
    l.insert(
        "poly2_noesd",
        d.derived("poly2_noesd", l["poly2"].outside(l["esd_mk"])),
    );
    l.insert(
        "ncomp_out_esd",
        d.derived("ncomp_out_esd", l["ncomp"].outside(l["esd"])),
    );
    l.insert("implant", d.derived("implant", l["nplus"].or(l["pplus"])));
    l.insert(
        "implant_out_esd",
        d.derived("implant_out_esd", l["implant"].outside(l["esd"])),
    );
    l.insert(
        "contact_poly",
        d.derived("contact_poly", l["contact"].interacting(l["poly2"])),
    );
    l.insert(
        "contact_comp",
        d.derived("contact_comp", l["contact"].interacting(l["comp"])),
    );
    l.insert(
        "metal5_mim",
        d.derived("metal5_mim", l["metal5"].interacting(l["fusetop"])),
    );
    l.insert(
        "mimtm_virtual",
        d.derived(
            "mimtm_virtual",
            l["fusetop"].sized(nm(1060)).and(l["metal5_mim"]),
        ),
    );
    l.insert(
        "metal5_nomim",
        d.derived("metal5_nomim", l["metal5"].not_interacting(l["fusetop"])),
    );
    l.insert(
        "via5_on_mim",
        d.derived("via5_on_mim", l["via5"].interacting(l["mimtm_virtual"])),
    );
    l.insert(
        "via5_top",
        d.derived("via5_top", l["via5"].interacting(l["fusetop"])),
    );
    l.insert(
        "via5_in_top",
        d.derived("via5_in_top", l["via5"].inside(l["fusetop"])),
    );
    l.insert(
        "ncomp_nat",
        d.derived(
            "ncomp_nat",
            l["ncomp"].outside(l["nwell"]).interacting(l["nat"]),
        ),
    );
    l.insert(
        "comp_out_nat",
        d.derived("comp_out_nat", l["comp"].outside(l["nat"])),
    );
    l.insert(
        "nat_hv",
        d.derived("nat_hv", l["nat"].interacting(l["dualgate"])),
    );
    l.insert(
        "pres_poly",
        d.derived(
            "pres_poly",
            l["poly2"]
                .and(l["pplus"])
                .group()
                .interacting(l["sab"])
                .interacting(l["res_mk"])
                .not_interacting(l["resistor"]),
        ),
    );
    l.insert(
        "lres_poly",
        d.derived(
            "lres_poly",
            l["poly2"]
                .and(l["nplus"])
                .group()
                .interacting(l["sab"])
                .interacting(l["res_mk"]),
        ),
    );
    l.insert(
        "hres_poly",
        d.derived(
            "hres_poly",
            l["poly2"]
                .interacting(l["pplus"])
                .interacting(l["sab"])
                .interacting(l["res_mk"])
                .interacting(l["resistor"]),
        ),
    );
    l.insert(
        "poly2_nosab",
        d.derived("poly2_nosab", l["poly2"].not_interacting(l["sab"])),
    );
    l.insert(
        "contact_pres",
        d.derived("contact_pres", l["contact"].inside(l["pres_poly"])),
    );
    l.insert(
        "contact_lres",
        d.derived("contact_lres", l["contact"].inside(l["lres_poly"])),
    );
    l.insert(
        "contact_hres",
        d.derived("contact_hres", l["contact"].inside(l["hres_poly"])),
    );
    l.insert(
        "resistor_h",
        d.derived("resistor_h", l["resistor"].interacting(l["hres_poly"])),
    );
    l.insert(
        "poly2_fill",
        d.derived("poly2_fill", l["poly2"].or(l["poly2_dummy"])),
    );
    l.insert(
        "metal1_fill",
        d.derived("metal1_fill", l["metal1"].or(l["metal1_dummy"])),
    );
    l.insert(
        "metal2_fill",
        d.derived("metal2_fill", l["metal2"].or(l["metal2_dummy"])),
    );
    l.insert(
        "metal3_fill",
        d.derived("metal3_fill", l["metal3"].or(l["metal3_dummy"])),
    );
    l.insert(
        "metal4_fill",
        d.derived("metal4_fill", l["metal4"].or(l["metal4_dummy"])),
    );
    l.insert(
        "metal5_fill",
        d.derived("metal5_fill", l["metal5"].or(l["metal5_dummy"])),
    );
    l.insert(
        "metaltop_fill",
        d.derived("metaltop_fill", l["metaltop"].or(l["metaltop_dummy"])),
    );
    l.insert(
        "ng",
        d.derived(
            "ng",
            l["ngate"]
                .not(l["sab"])
                .not(l["esd_mk"])
                .group()
                .not_interacting(l["mos_cap_mk"]),
        ),
    );
    l.insert(
        "pg",
        d.derived(
            "pg",
            l["pgate"]
                .not(l["sab"])
                .not(l["esd_mk"])
                .group()
                .not_interacting(l["mos_cap_mk"]),
        ),
    );
    l.insert(
        "nfet_03v3_g",
        d.derived("nfet_03v3_g", l["ng"].not(l["dualgate"])),
    );
    l.insert(
        "pfet_03v3_g",
        d.derived("pfet_03v3_g", l["pg"].not(l["dualgate"])),
    );
    l.insert(
        "nfet_06v0_g",
        d.derived(
            "nfet_06v0_g",
            l["ng"]
                .and(l["dualgate"])
                .not(l["nat"])
                .not(l["ldmos_xtor"]),
        ),
    );
    l.insert(
        "pfet_06v0_g",
        d.derived(
            "pfet_06v0_g",
            l["pg"].and(l["dualgate"]).not(l["ldmos_xtor"]),
        ),
    );
    l.insert(
        "nfet_06v0_nvt_g",
        d.derived("nfet_06v0_nvt_g", l["ng"].and(l["dualgate"]).and(l["nat"])),
    );
    l.insert(
        "nfet_03v3_dss_g",
        d.derived(
            "nfet_03v3_dss_g",
            l["ngate"]
                .and(l["esd_mk"])
                .not(l["dualgate"])
                .group()
                .interacting(l["sab"]),
        ),
    );
    l.insert(
        "pfet_03v3_dss_g",
        d.derived(
            "pfet_03v3_dss_g",
            l["pgate"]
                .and(l["esd_mk"])
                .not(l["dualgate"])
                .group()
                .interacting(l["sab"]),
        ),
    );
    l.insert(
        "nfet_06v0_dss_g",
        d.derived(
            "nfet_06v0_dss_g",
            l["ngate"]
                .and(l["esd_mk"])
                .and(l["dualgate"])
                .group()
                .interacting(l["sab"]),
        ),
    );
    l.insert(
        "pfet_06v0_dss_g",
        d.derived(
            "pfet_06v0_dss_g",
            l["pgate"]
                .and(l["esd_mk"])
                .and(l["dualgate"])
                .group()
                .interacting(l["sab"]),
        ),
    );
    l.insert(
        "cap_nmos_03v3_b_g",
        d.derived(
            "cap_nmos_03v3_b_g",
            l["ngate"]
                .not(l["dualgate"])
                .group()
                .interacting(l["mos_cap_mk"])
                .inside(l["nwell"]),
        ),
    );
    l.insert(
        "cap_pmos_03v3_b_g",
        d.derived(
            "cap_pmos_03v3_b_g",
            l["pgate"]
                .not(l["dualgate"])
                .group()
                .interacting(l["mos_cap_mk"])
                .outside(l["nwell"]),
        ),
    );
    l.insert(
        "cap_nmos_06v0_b_g",
        d.derived(
            "cap_nmos_06v0_b_g",
            l["ngate"]
                .and(l["dualgate"])
                .group()
                .interacting(l["mos_cap_mk"])
                .inside(l["nwell"]),
        ),
    );
    l.insert(
        "cap_pmos_06v0_b_g",
        d.derived(
            "cap_pmos_06v0_b_g",
            l["pgate"]
                .and(l["dualgate"])
                .group()
                .interacting(l["mos_cap_mk"])
                .outside(l["nwell"]),
        ),
    );
    l.insert(
        "npolyf_u_r",
        d.derived(
            "npolyf_u_r",
            l["poly2"].and(l["nplus"]).and(l["sab"]).and(l["res_mk"]),
        ),
    );
    l.insert(
        "ppolyf_u_r",
        d.derived(
            "ppolyf_u_r",
            l["poly2"]
                .and(l["pplus"])
                .and(l["sab"])
                .and(l["res_mk"])
                .group()
                .not_interacting(l["resistor"]),
        ),
    );
    l.insert(
        "npolyf_s_r",
        d.derived(
            "npolyf_s_r",
            l["poly2"]
                .and(l["nplus"])
                .and(l["res_mk"])
                .group()
                .not_interacting(l["sab"]),
        ),
    );
    l.insert(
        "ppolyf_s_r",
        d.derived(
            "ppolyf_s_r",
            l["poly2"]
                .and(l["pplus"])
                .and(l["res_mk"])
                .group()
                .not_interacting(l["sab"]),
        ),
    );
    l.insert(
        "ppolyf_u_1k_r",
        d.derived(
            "ppolyf_u_1k_r",
            l["poly2"]
                .and(l["sab"])
                .and(l["res_mk"])
                .and(l["resistor"])
                .not(l["dualgate"]),
        ),
    );
    l.insert(
        "ppolyf_u_1k_6p0_r",
        d.derived(
            "ppolyf_u_1k_6p0_r",
            l["poly2"]
                .and(l["sab"])
                .and(l["res_mk"])
                .and(l["resistor"])
                .and(l["dualgate"]),
        ),
    );
    l.insert(
        "nplus_u_r",
        d.derived("nplus_u_r", l["ncomp"].and(l["sab"]).and(l["res_mk"])),
    );
    l.insert(
        "pplus_u_r",
        d.derived("pplus_u_r", l["pcomp"].and(l["sab"]).and(l["res_mk"])),
    );
    l.insert(
        "nplus_s_r",
        d.derived(
            "nplus_s_r",
            l["ncomp"]
                .and(l["res_mk"])
                .group()
                .not_interacting(l["sab"]),
        ),
    );
    l.insert(
        "pplus_s_r",
        d.derived(
            "pplus_s_r",
            l["pcomp"]
                .and(l["res_mk"])
                .group()
                .not_interacting(l["sab"]),
        ),
    );
    l.insert(
        "rm1_r",
        d.derived("rm1_r", l["metal1"].and(l["metal1_res"])),
    );
    l.insert(
        "rm2_r",
        d.derived("rm2_r", l["metal2"].and(l["metal2_res"])),
    );
    l.insert(
        "rm3_r",
        d.derived("rm3_r", l["metal3"].and(l["metal3_res"])),
    );
    l.insert(
        "tm9k_r",
        d.derived("tm9k_r", l["metaltop"].and(l["metal6_res"])),
    );
    d.rule("DN.1", min_width(l["dnwell"], nm(1700)));
    d.rule("DN.2a", min_spacing(l["dnwell"], nm(2500)));
    d.rule("DN.2a.notch", notch(l["dnwell"], nm(2500)));
    d.rule("LPW.1_3.3V", min_width(l["lvpwell"], nm(600)));
    d.rule("LPW.1_5V", min_width(l["lvpwell_hv"], nm(740)));
    d.rule("LPW.2b", min_spacing(l["lvpwell"], nm(860)));
    d.rule("LPW.2b.notch", notch(l["lvpwell"], nm(860)));
    d.rule(
        "LPW.3",
        min_enclosure(l["lvpwell_dn"], l["dnwell"], nm(2500)),
    );
    d.rule(
        "LPW.11",
        min_spacing_diff(l["lvpwell_out_dn"], l["dnwell"], nm(1500)),
    );
    d.rule("NW.1a", min_width(l["nwell"], nm(860)));
    d.rule("NW.1b", min_width(l["nwell_res"], nm(2000)));
    d.rule("NW.2a_3.3V", min_spacing(l["nwell"], nm(600)));
    d.rule("NW.2a_3.3V.notch", notch(l["nwell"], nm(600)));
    d.rule("NW.2a_5V", min_spacing(l["nwell_hv"], nm(740)));
    d.rule("NW.2a_5V.notch", notch(l["nwell_hv"], nm(740)));
    d.rule(
        "NW.3",
        min_spacing_diff(l["nwell_out_dn"], l["dnwell"], nm(3100)),
    );
    d.rule(
        "NW.5",
        min_enclosure(l["nwell_in_dn"], l["dnwell"], nm(500)),
    );
    d.rule("DF.1a_3.3V", min_width(l["comp"], nm(220)));
    d.rule("DF.1a_5V", min_width(l["comp_hv"], nm(300)));
    d.rule("DF.1c", min_width(l["comp_moscap"], nm(1000)));
    d.rule(
        "DF.2a_3.3V",
        edge_min_length(l["gate"].edges().and(l["poly2"].edges()), nm(220)),
    );
    d.rule(
        "DF.2a_5V",
        edge_min_length(l["gate_hv"].edges().and(l["poly2"].edges()), nm(300)),
    );
    d.rule("DF.2b", max_width(l["comp_nocap"], nm(100000)));
    d.rule("DF.3a_3.3V", min_spacing(l["comp"], nm(280)));
    d.rule("DF.3a_3.3V.notch", notch(l["comp"], nm(280)));
    d.rule("DF.3a_5V", min_spacing(l["comp_hv"], nm(360)));
    d.rule("DF.3a_5V.notch", notch(l["comp_hv"], nm(360)));
    d.rule("DF.3c_3.3V", min_spacing(l["comp_bjt"], nm(320)));
    d.rule("DF.3c_3.3V.notch", notch(l["comp_bjt"], nm(320)));
    d.rule(
        "DF.4a_3.3V",
        min_spacing_diff(l["ntap_dn"], l["lvpwell_in_dn"], nm(120)),
    );
    d.rule(
        "DF.4a_5V",
        min_spacing_diff(l["ntap_dn_hv"], l["lvpwell_in_dn"], nm(160)),
    );
    d.rule(
        "DF.4b_3.3V",
        min_enclosure(l["ncomp_dn"], l["dnwell"], nm(620)),
    );
    d.rule(
        "DF.4b_5V",
        min_enclosure(l["ncomp_dn_hv"], l["dnwell"], nm(660)),
    );
    d.rule(
        "DF.4c_3.3V",
        min_enclosure(l["pcomp_nw"], l["nwell"], nm(430)),
    );
    d.rule(
        "DF.4c_5V",
        min_enclosure(l["pcomp_nw_hv"], l["nwell"], nm(600)),
    );
    d.rule(
        "DF.4d_3.3V",
        min_enclosure(l["ncomp_nw"], l["nwell"], nm(120)),
    );
    d.rule(
        "DF.4d_5V",
        min_enclosure(l["ncomp_nw_hv"], l["nwell"], nm(160)),
    );
    d.rule(
        "DF.4e_3.3V",
        min_enclosure(l["pcomp_dn"], l["dnwell"], nm(930)),
    );
    d.rule(
        "DF.4e_5V",
        min_enclosure(l["pcomp_dn_hv"], l["dnwell"], nm(1100)),
    );
    d.rule(
        "DF.5_3.3V",
        min_enclosure(l["pcomp_lvp"], l["lvpwell_in_dn"], nm(120)),
    );
    d.rule(
        "DF.5_5V",
        min_enclosure(l["pcomp_lvp_hv"], l["lvpwell_in_dn"], nm(160)),
    );
    d.rule("DF.6_3.3V", min_extension(l["comp"], l["poly2"], nm(240)));
    d.rule(
        "DF.6_5V",
        min_extension(l["comp_hv_noext"], l["poly2"], nm(400)),
    );
    d.rule(
        "DF.7_3.3V",
        min_spacing_diff(l["pcomp_dn_nolvp"], l["lvpwell_in_dn"], nm(430)),
    );
    d.rule(
        "DF.7_5V",
        min_spacing_diff(l["pcomp_dn_nolvp_hv"], l["lvpwell_in_dn"], nm(600)),
    );
    d.rule(
        "DF.8_3.3V",
        min_enclosure(l["ncomp_lvp"], l["lvpwell_in_dn"], nm(430)),
    );
    d.rule(
        "DF.8_5V",
        min_enclosure(l["ncomp_lvp_hv"], l["lvpwell_in_dn"], nm(600)),
    );
    d.rule("DF.9", min_area(l["comp"], nm2(202500)));
    d.rule(
        "DF.10",
        min_area(l["comp"].holes().not(l["comp"]), nm2(260000)),
    );
    d.rule(
        "DF.13_3.3V",
        max_distance_to_tap(l["pcomp_in_nw"], l["ntap"], nm(20000)),
    );
    d.rule(
        "DF.13_5V",
        max_distance_to_tap(l["pcomp_in_nw_hv"], l["ntap"], nm(15000)),
    );
    d.rule(
        "DF.14_3.3V",
        max_distance_to_tap(l["ncomp_out_nw"], l["ptap"], nm(20000)),
    );
    d.rule(
        "DF.14_5V",
        max_distance_to_tap(l["ncomp_out_nw_hv"], l["ptap"], nm(15000)),
    );
    d.rule(
        "DF.16_3.3V",
        min_spacing_diff(l["ncomp_psub"], l["nwell_out_dn"], nm(430)),
    );
    d.rule(
        "DF.16_5V",
        min_spacing_diff(l["ncomp_psub_hv"], l["nwell_out_dn"], nm(600)),
    );
    d.rule(
        "DF.17_3.3V",
        min_spacing_diff(l["pcomp_psub"], l["nwell_out_dn"], nm(120)),
    );
    d.rule(
        "DF.17_5V",
        min_spacing_diff(l["pcomp_psub_hv"], l["nwell_out_dn"], nm(160)),
    );
    d.rule(
        "DF.18",
        min_spacing_diff(l["pcomp_psub"], l["dnwell"], nm(2500)),
    );
    d.rule(
        "DF.19_3.3V",
        min_spacing_diff(l["ncomp_psub"], l["dnwell"], nm(3200)),
    );
    d.rule(
        "DF.19_5V",
        min_spacing_diff(l["ncomp_psub_hv"], l["dnwell"], nm(3280)),
    );
    d.rule(
        "DV.1",
        min_enclosure(l["dnwell_hv"], l["dualgate"], nm(500)),
    );
    d.rule("DV.2", min_spacing(l["dualgate"], nm(440)));
    d.rule("DV.2.notch", notch(l["dualgate"], nm(440)));
    d.rule(
        "DV.3",
        min_spacing_diff(l["dualgate"], l["comp_out_dv"], nm(240)),
    );
    d.rule("DV.5", min_width(l["dualgate"], nm(700)));
    d.rule("DV.6", min_enclosure(l["comp_dv"], l["dualgate"], nm(240)));
    d.rule("DV.8", min_enclosure(l["poly2_hv"], l["dualgate"], nm(400)));
    d.rule("PL.1_3.3V", min_width(l["poly2"], nm(180)));
    d.rule("PL.1_5V", min_width(l["poly2_hv"], nm(200)));
    d.rule(
        "PL.2_3.3V",
        edge_min_length(l["gate"].edges().and(l["comp"].edges()), nm(280)),
    );
    d.rule(
        "PL.2_5V_n",
        edge_min_length(
            l["ngate"]
                .and(l["dualgate"])
                .group()
                .edges()
                .and(l["comp"].edges()),
            nm(600),
        ),
    );
    d.rule(
        "PL.2_5V_p",
        edge_min_length(
            l["pgate"]
                .and(l["dualgate"])
                .group()
                .edges()
                .and(l["comp"].edges()),
            nm(500),
        ),
    );
    d.rule("PL.3a", min_spacing(l["poly2"], nm(240)));
    d.rule("PL.3a.notch", notch(l["poly2"], nm(240)));
    d.rule("PL.4", min_extension(l["poly2"], l["comp"], nm(220)));
    d.rule(
        "PL.5a_3.3V",
        min_spacing_diff(l["poly2_field"], l["comp"], nm(100)),
    );
    d.rule(
        "PL.5a_5V",
        min_spacing_diff(l["poly2_field"], l["comp_hv"], nm(300)),
    );
    d.rule("PL.8", global_density(l["poly2_fill"], None, 0.14, false));
    d.rule("NP.1", min_width(l["nplus"], nm(400)));
    d.rule("NP.2", min_spacing(l["nplus"], nm(400)));
    d.rule("NP.2.notch", notch(l["nplus"], nm(400)));
    d.rule("NP.5a", min_enclosure(l["ngate"], l["nplus"], nm(230)));
    d.rule(
        "NP.7",
        min_spacing_diff(l["nplus"], l["poly_sab_nonp"], nm(180)),
    );
    d.rule("NP.8a", min_area(l["nplus"], nm2(350000)));
    d.rule("NP.8b", min_enclosed_area(l["nplus"], nm2(350000)));
    d.rule("NP.9", min_enclosure(l["poly_sab_np"], l["nplus"], nm(180)));
    d.rule(
        "NP.10",
        min_enclosure(l["comp_sab_np"], l["nplus"], nm(180)),
    );
    d.rule("PP.1", min_width(l["pplus"], nm(400)));
    d.rule("PP.2", min_spacing(l["pplus"], nm(400)));
    d.rule("PP.2.notch", notch(l["pplus"], nm(400)));
    d.rule("PP.5a", min_enclosure(l["pgate"], l["pplus"], nm(230)));
    d.rule(
        "PP.7",
        min_spacing_diff(l["pplus"], l["poly_sab_nopp"], nm(180)),
    );
    d.rule("PP.8a", min_area(l["pplus"], nm2(350000)));
    d.rule("PP.8b", min_enclosed_area(l["pplus"], nm2(350000)));
    d.rule("PP.9", min_enclosure(l["poly_sab_pp"], l["pplus"], nm(180)));
    d.rule(
        "PP.10",
        min_enclosure(l["comp_sab_pp"], l["pplus"], nm(180)),
    );
    d.rule("SB.1", min_width(l["sab"], nm(420)));
    d.rule("SB.2", min_spacing(l["sab_main"], nm(420)));
    d.rule("SB.2.notch", notch(l["sab_main"], nm(420)));
    d.rule(
        "SB.3",
        min_spacing_diff(l["sab_field"], l["comp_nosab"], nm(220)),
    );
    d.rule(
        "SB.4",
        min_spacing_diff(l["sab_main"], l["contact"], nm(150)),
    );
    d.rule(
        "SB.5a",
        min_spacing_diff(l["sab_off_pf"], l["pf_nosab"], nm(300)),
    );
    d.rule(
        "SB.5b",
        min_spacing_diff(l["sab_off_gate"], l["gate_nosab"], nm(280)),
    );
    d.rule("SB.6", min_extension(l["sab"], l["comp"], nm(220)));
    d.rule("SB.7", min_extension(l["comp"], l["sab"], nm(220)));
    d.rule("SB.9", min_extension(l["sab_main"], l["poly2"], nm(220)));
    d.rule("SB.10", min_extension(l["poly2"], l["sab"], nm(220)));
    d.rule("SB.11", overlap(l["sab_main"], l["comp"], nm(220)));
    d.rule("SB.12", overlap(l["sab_noesd"], l["poly2_noesd"], nm(220)));
    d.rule("SB.13", min_area(l["sab_main"], nm2(2000000)));
    d.rule("ESD.1", min_width(l["esd"], nm(600)));
    d.rule("ESD.2", min_spacing(l["esd"], nm(600)));
    d.rule("ESD.2.notch", notch(l["esd"], nm(600)));
    d.rule(
        "ESD.3a",
        min_spacing_diff(l["esd"], l["ncomp_out_esd"], nm(600)),
    );
    d.rule("ESD.4b", overlap(l["esd"], l["comp"], nm(450)));
    d.rule("ESD.5a", min_area(l["esd"], nm2(490000)));
    d.rule("ESD.5b", min_enclosed_area(l["esd"], nm2(490000)));
    d.rule(
        "ESD.8",
        min_spacing_diff(l["esd"], l["implant_out_esd"], nm(300)),
    );
    d.rule("CO.1", cut_size(l["contact"], nm(220), nm(220)));
    d.rule("CO.2a", min_spacing(l["contact"], nm(250)));
    d.rule("CO.2b", via_array_spacing(l["contact"], 15, nm(280)));
    d.rule("CO.3", min_enclosure(l["contact_poly"], l["poly2"], nm(70)));
    d.rule("CO.4", min_enclosure(l["contact_comp"], l["comp"], nm(70)));
    d.rule("CO.6", min_enclosure(l["contact"], l["metal1"], nm(5)));
    d.rule(
        "CO.7",
        min_spacing_diff(l["contact_comp"], l["gate"], nm(150)),
    );
    d.rule(
        "CO.8",
        min_spacing_diff(l["contact_poly"], l["comp"], nm(170)),
    );
    d.rule("M1.1", min_width(l["metal1"], nm(230)));
    d.rule("M1.2a", min_spacing(l["metal1"], nm(230)));
    d.rule("M1.2a.notch", notch(l["metal1"], nm(230)));
    d.rule(
        "M1.2b",
        wide_dependent_spacing(l["metal1"], nm(10000), nm(300)),
    );
    d.rule("M1.3", min_area(l["metal1"], nm2(144400)));
    d.rule("M1.4", global_density(l["metal1_fill"], None, 0.30, false));
    d.rule("M2.1", min_width(l["metal2"], nm(280)));
    d.rule("M2.2a", min_spacing(l["metal2"], nm(280)));
    d.rule("M2.2a.notch", notch(l["metal2"], nm(280)));
    d.rule(
        "M2.2b",
        wide_dependent_spacing(l["metal2"], nm(10000), nm(300)),
    );
    d.rule("M2.3", min_area(l["metal2"], nm2(144400)));
    d.rule("M2.4", global_density(l["metal2_fill"], None, 0.30, false));
    d.rule("M3.1", min_width(l["metal3"], nm(280)));
    d.rule("M3.2a", min_spacing(l["metal3"], nm(280)));
    d.rule("M3.2a.notch", notch(l["metal3"], nm(280)));
    d.rule(
        "M3.2b",
        wide_dependent_spacing(l["metal3"], nm(10000), nm(300)),
    );
    d.rule("M3.3", min_area(l["metal3"], nm2(144400)));
    d.rule("M3.4", global_density(l["metal3_fill"], None, 0.30, false));
    d.rule("M4.1", min_width(l["metal4"], nm(280)));
    d.rule("M4.2a", min_spacing(l["metal4"], nm(280)));
    d.rule("M4.2a.notch", notch(l["metal4"], nm(280)));
    d.rule(
        "M4.2b",
        wide_dependent_spacing(l["metal4"], nm(10000), nm(300)),
    );
    d.rule("M4.3", min_area(l["metal4"], nm2(144400)));
    d.rule("M4.4", global_density(l["metal4_fill"], None, 0.30, false));
    d.rule("M5.1", min_width(l["metal5"], nm(280)));
    d.rule("M5.2a", min_spacing(l["metal5"], nm(280)));
    d.rule("M5.2a.notch", notch(l["metal5"], nm(280)));
    d.rule(
        "M5.2b",
        wide_dependent_spacing(l["metal5"], nm(10000), nm(300)),
    );
    d.rule("M5.3", min_area(l["metal5"], nm2(144400)));
    d.rule("M5.4", global_density(l["metal5_fill"], None, 0.30, false));
    d.rule("V1.1", cut_size(l["via1"], nm(260), nm(260)));
    d.rule("V1.2a", min_spacing(l["via1"], nm(260)));
    d.rule("V1.2b", via_array_spacing(l["via1"], 15, nm(360)));
    d.rule("V1.4a", min_enclosure(l["via1"], l["metal2"], nm(10)));
    d.rule("V2.1", cut_size(l["via2"], nm(260), nm(260)));
    d.rule("V2.2a", min_spacing(l["via2"], nm(260)));
    d.rule("V2.2b", via_array_spacing(l["via2"], 15, nm(360)));
    d.rule("V2.4a", min_enclosure(l["via2"], l["metal3"], nm(10)));
    d.rule("V3.1", cut_size(l["via3"], nm(260), nm(260)));
    d.rule("V3.2a", min_spacing(l["via3"], nm(260)));
    d.rule("V3.2b", via_array_spacing(l["via3"], 15, nm(360)));
    d.rule("V3.4a", min_enclosure(l["via3"], l["metal4"], nm(10)));
    d.rule("V4.1", cut_size(l["via4"], nm(260), nm(260)));
    d.rule("V4.2a", min_spacing(l["via4"], nm(260)));
    d.rule("V4.2b", via_array_spacing(l["via4"], 15, nm(360)));
    d.rule("V4.4a", min_enclosure(l["via4"], l["metal5"], nm(10)));
    d.rule("V5.1", cut_size(l["via5"], nm(260), nm(260)));
    d.rule("V5.2a", min_spacing(l["via5"], nm(260)));
    d.rule("V5.2b", via_array_spacing(l["via5"], 15, nm(360)));
    d.rule("V5.4a", min_enclosure(l["via5"], l["metaltop"], nm(10)));
    d.rule("V2.3b", min_enclosure(l["via2"], l["metal2"], nm(10)));
    d.rule("V3.3b", min_enclosure(l["via3"], l["metal3"], nm(10)));
    d.rule("V4.3b", min_enclosure(l["via4"], l["metal4"], nm(10)));
    d.rule("V5.3b", min_enclosure(l["via5"], l["metal5"], nm(10)));
    d.rule("MT.1", min_width(l["metaltop"], nm(440)));
    d.rule("MT.2a", min_spacing(l["metaltop"], nm(460)));
    d.rule("MT.2a.notch", notch(l["metaltop"], nm(460)));
    d.rule(
        "MT.2b",
        wide_dependent_spacing(l["metaltop"], nm(10000), nm(600)),
    );
    d.rule(
        "MT.3",
        global_density(l["metaltop_fill"], None, 0.30, false),
    );
    d.rule("MT.4", min_area(l["metaltop"], nm2(562500)));
    d.rule(
        "MIMTM.1",
        min_spacing_diff(l["metal5_nomim"], l["mimtm_virtual"], nm(1200)),
    );
    d.rule(
        "MIMTM.2",
        min_enclosure(l["via5_on_mim"], l["metal5"], nm(400)),
    );
    d.rule(
        "MIMTM.3",
        min_enclosure(l["fusetop"], l["mimtm_virtual"], nm(600)),
    );
    d.rule(
        "MIMTM.4",
        min_enclosure(l["via5_top"], l["fusetop"], nm(400)),
    );
    d.rule(
        "MIMTM.5",
        min_spacing_diff(l["fusetop"], l["via5_nomim"], nm(400)),
    );
    d.rule("MIMTM.6", min_spacing(l["fusetop"], nm(600)));
    d.rule("MIMTM.6.notch", notch(l["fusetop"], nm(600)));
    d.rule("MIMTM.8a", min_area(l["fusetop"], nm2(25000000)));
    d.rule("MIMTM.9", min_spacing(l["via5_in_top"], nm(500)));
    d.rule("NAT.1", min_enclosure(l["ncomp_nat"], l["nat"], nm(2000)));
    d.rule(
        "NAT.2",
        min_spacing_diff(l["nat"], l["comp_out_nat"], nm(300)),
    );
    d.rule("NAT.3", min_spacing_diff(l["nat"], l["nwell"], nm(500)));
    d.rule("NAT.7", min_spacing(l["nat"], nm(740)));
    d.rule("NAT.7.notch", notch(l["nat"], nm(740)));
    d.rule("PRES.1", min_width(l["pres_poly"], nm(800)));
    d.rule("PRES.2", min_spacing(l["pres_poly"], nm(400)));
    d.rule(
        "PRES.3",
        min_spacing_diff(l["pres_poly"], l["comp"], nm(600)),
    );
    d.rule(
        "PRES.4",
        min_spacing_diff(l["pres_poly"], l["poly2_nosab"], nm(600)),
    );
    d.rule("PRES.5", min_enclosure(l["pres_poly"], l["pplus"], nm(300)));
    d.rule(
        "PRES.7",
        min_spacing_diff(l["contact_pres"], l["sab"], nm(220)),
    );
    d.rule("LRES.1", min_width(l["lres_poly"], nm(800)));
    d.rule("LRES.2", min_spacing(l["lres_poly"], nm(400)));
    d.rule(
        "LRES.3",
        min_spacing_diff(l["lres_poly"], l["comp"], nm(600)),
    );
    d.rule(
        "LRES.4",
        min_spacing_diff(l["lres_poly"], l["poly2_nosab"], nm(600)),
    );
    d.rule("LRES.5", min_enclosure(l["lres_poly"], l["nplus"], nm(300)));
    d.rule(
        "LRES.7",
        min_spacing_diff(l["contact_lres"], l["sab"], nm(220)),
    );
    d.rule("HRES.1", min_spacing(l["resistor_h"], nm(400)));
    d.rule("HRES.1.notch", notch(l["resistor_h"], nm(400)));
    d.rule("HRES.2", min_width(l["hres_poly"], nm(1000)));
    d.rule("HRES.3", min_spacing(l["hres_poly"], nm(400)));
    d.rule("HRES.3.notch", notch(l["hres_poly"], nm(400)));
    d.rule(
        "HRES.4",
        min_enclosure(l["hres_poly"], l["resistor"], nm(400)),
    );
    d.rule(
        "HRES.5",
        min_spacing_diff(l["resistor_h"], l["poly2_nosab"], nm(300)),
    );
    d.rule(
        "HRES.6",
        min_spacing_diff(l["resistor_h"], l["comp"], nm(300)),
    );
    d.rule(
        "HRES.7",
        min_enclosure(l["contact_hres"], l["pplus"], nm(200)),
    );
    d.rule(
        "HRES.8",
        min_spacing_diff(l["contact_hres"], l["sab"], nm(220)),
    );
    d.rule("OFFGRID", off_grid(nm(5)));
    d.rule("ACUTE", angle(None, &[0, 45, 90, 135]));
    l.insert(
        "gate_thin",
        d.derived("gate_thin", l["gate"].not(l["dualgate"])),
    );
    l.insert("ant_comp", d.derived("ant_comp", l["comp"].not(l["poly2"])));
    d.rule(
        "ANT.1",
        antenna(
            l["gate_thin"],
            &[l["poly2_con"]],
            200.0,
            Some(nm(200)),
            None,
        ),
    );
    d.rule(
        "ANT.1.DG",
        antenna(l["gate_hv"], &[l["poly2_con"]], 200.0, Some(nm(200)), None),
    );
    d.rule(
        "ANT.2",
        antenna_electrical(
            l["gate_thin"],
            &[l["metal1_con"]],
            400.0,
            Some(nm(540)),
            1.0,
            Some(l["ant_comp"]),
            0.0,
            0.0,
            0.0,
            2.0,
            &[],
            &[],
            None,
        ),
    );
    d.rule(
        "ANT.2.DG",
        antenna_electrical(
            l["gate_hv"],
            &[l["metal1_con"]],
            400.0,
            Some(nm(540)),
            1.0,
            Some(l["ant_comp"]),
            0.0,
            0.0,
            0.0,
            15.0,
            &[],
            &[],
            None,
        ),
    );
    d.rule(
        "ANT.3",
        antenna_electrical(
            l["gate_thin"],
            &[l["metal2_con"]],
            400.0,
            Some(nm(540)),
            1.0,
            Some(l["ant_comp"]),
            0.0,
            0.0,
            0.0,
            2.0,
            &[],
            &[],
            None,
        ),
    );
    d.rule(
        "ANT.3.DG",
        antenna_electrical(
            l["gate_hv"],
            &[l["metal2_con"]],
            400.0,
            Some(nm(540)),
            1.0,
            Some(l["ant_comp"]),
            0.0,
            0.0,
            0.0,
            15.0,
            &[],
            &[],
            None,
        ),
    );
    d.rule(
        "ANT.4",
        antenna_electrical(
            l["gate_thin"],
            &[l["metal3_con"]],
            400.0,
            Some(nm(540)),
            1.0,
            Some(l["ant_comp"]),
            0.0,
            0.0,
            0.0,
            2.0,
            &[],
            &[],
            None,
        ),
    );
    d.rule(
        "ANT.4.DG",
        antenna_electrical(
            l["gate_hv"],
            &[l["metal3_con"]],
            400.0,
            Some(nm(540)),
            1.0,
            Some(l["ant_comp"]),
            0.0,
            0.0,
            0.0,
            15.0,
            &[],
            &[],
            None,
        ),
    );
    d.rule(
        "ANT.5",
        antenna_electrical(
            l["gate_thin"],
            &[l["metal4"]],
            400.0,
            Some(nm(540)),
            1.0,
            Some(l["ant_comp"]),
            0.0,
            0.0,
            0.0,
            2.0,
            &[],
            &[],
            None,
        ),
    );
    d.rule(
        "ANT.5.DG",
        antenna_electrical(
            l["gate_hv"],
            &[l["metal4"]],
            400.0,
            Some(nm(540)),
            1.0,
            Some(l["ant_comp"]),
            0.0,
            0.0,
            0.0,
            15.0,
            &[],
            &[],
            None,
        ),
    );
    d.rule(
        "ANT.6",
        antenna_electrical(
            l["gate_thin"],
            &[l["metal5"]],
            400.0,
            Some(nm(540)),
            1.0,
            Some(l["ant_comp"]),
            0.0,
            0.0,
            0.0,
            2.0,
            &[],
            &[],
            None,
        ),
    );
    d.rule(
        "ANT.6.DG",
        antenna_electrical(
            l["gate_hv"],
            &[l["metal5"]],
            400.0,
            Some(nm(540)),
            1.0,
            Some(l["ant_comp"]),
            0.0,
            0.0,
            0.0,
            15.0,
            &[],
            &[],
            None,
        ),
    );
    d.rule(
        "ANT.7",
        antenna_electrical(
            l["gate_thin"],
            &[l["metaltop_con"]],
            400.0,
            Some(nm(990)),
            1.0,
            Some(l["ant_comp"]),
            0.0,
            0.0,
            0.0,
            2.0,
            &[],
            &[],
            None,
        ),
    );
    d.rule(
        "ANT.7.DG",
        antenna_electrical(
            l["gate_hv"],
            &[l["metaltop_con"]],
            400.0,
            Some(nm(990)),
            1.0,
            Some(l["ant_comp"]),
            0.0,
            0.0,
            0.0,
            15.0,
            &[],
            &[],
            None,
        ),
    );
    d.rule(
        "ANT.8",
        antenna(l["gate_thin"], &[l["contact"]], 10.0, None, None),
    );
    d.rule(
        "ANT.8.DG",
        antenna(l["gate_hv"], &[l["contact"]], 10.0, None, None),
    );
    d.rule(
        "ANT.9",
        antenna_electrical(
            l["gate_thin"],
            &[l["via1"]],
            20.0,
            None,
            1.0,
            Some(l["ant_comp"]),
            0.0,
            0.0,
            0.0,
            2.0,
            &[],
            &[],
            None,
        ),
    );
    d.rule(
        "ANT.9.DG",
        antenna_electrical(
            l["gate_hv"],
            &[l["via1"]],
            20.0,
            None,
            1.0,
            Some(l["ant_comp"]),
            0.0,
            0.0,
            0.0,
            15.0,
            &[],
            &[],
            None,
        ),
    );
    d.rule(
        "ANT.10",
        antenna_electrical(
            l["gate_thin"],
            &[l["via2"]],
            20.0,
            None,
            1.0,
            Some(l["ant_comp"]),
            0.0,
            0.0,
            0.0,
            2.0,
            &[],
            &[],
            None,
        ),
    );
    d.rule(
        "ANT.10.DG",
        antenna_electrical(
            l["gate_hv"],
            &[l["via2"]],
            20.0,
            None,
            1.0,
            Some(l["ant_comp"]),
            0.0,
            0.0,
            0.0,
            15.0,
            &[],
            &[],
            None,
        ),
    );
    d.rule(
        "ANT.11",
        antenna_electrical(
            l["gate_thin"],
            &[l["via3"]],
            20.0,
            None,
            1.0,
            Some(l["ant_comp"]),
            0.0,
            0.0,
            0.0,
            2.0,
            &[],
            &[],
            None,
        ),
    );
    d.rule(
        "ANT.11.DG",
        antenna_electrical(
            l["gate_hv"],
            &[l["via3"]],
            20.0,
            None,
            1.0,
            Some(l["ant_comp"]),
            0.0,
            0.0,
            0.0,
            15.0,
            &[],
            &[],
            None,
        ),
    );
    d.rule(
        "ANT.12",
        antenna_electrical(
            l["gate_thin"],
            &[l["via4"]],
            20.0,
            None,
            1.0,
            Some(l["ant_comp"]),
            0.0,
            0.0,
            0.0,
            2.0,
            &[],
            &[],
            None,
        ),
    );
    d.rule(
        "ANT.12.DG",
        antenna_electrical(
            l["gate_hv"],
            &[l["via4"]],
            20.0,
            None,
            1.0,
            Some(l["ant_comp"]),
            0.0,
            0.0,
            0.0,
            15.0,
            &[],
            &[],
            None,
        ),
    );
    d.rule(
        "ANT.13",
        antenna_electrical(
            l["gate_thin"],
            &[l["via5_nomim"]],
            20.0,
            None,
            1.0,
            Some(l["ant_comp"]),
            0.0,
            0.0,
            0.0,
            2.0,
            &[],
            &[],
            None,
        ),
    );
    d.rule(
        "ANT.13.DG",
        antenna_electrical(
            l["gate_hv"],
            &[l["via5_nomim"]],
            20.0,
            None,
            1.0,
            Some(l["ant_comp"]),
            0.0,
            0.0,
            0.0,
            15.0,
            &[],
            &[],
            None,
        ),
    );
    d.rule(
        "EM.14.3_Mn",
        em_current_density(
            &[
                l["metal1_con"],
                l["metal2_con"],
                l["metal3_con"],
                l["metal4"],
                l["metal5"],
            ],
            2090.0,
            580.0,
            None,
            None,
        ),
    );
    d.rule(
        "EM.14.3_MT",
        em_current_density(&[l["metaltop_con"]], 3770.0, 580.0, None, None),
    );
    d.rule(
        "EM.14.4_Vn",
        em_current_density(
            &[l["via1"], l["via2"], l["via3"], l["via4"], l["via5_nomim"]],
            2090.0,
            580.0,
            None,
            None,
        ),
    );
    d.rule(
        "EM.14.4_CO",
        em_current_density(&[l["contact"]], 2090.0, 430.0, None, None),
    );
    d.rule("LU.9_10", supply_short(l["ntap"], l["ptap"], None));
    d.rule("floating_nwell", floating_well(l["nwell"], l["ntap"]));
    d.rule(
        "floating_lvpwell",
        floating_well(l["lvpwell_in_dn"], l["pcomp_lvp"]),
    );
    d.rule("floating_gate", floating_gate(false));
    d.rule("tie_high_low", tie_high_low().warning());
    d.rule("multiple_drivers", multiple_drivers(1));
    d.rule("ir_drop", ir_drop());
    d.rule(
        "unconnected_metaltop",
        unconnected_pin(&[l["metaltop_con"]]).warning(),
    );
    d.rule(
        "ESD.clamp_path",
        esd_topological(
            l["pad"],
            &[
                "nfet_03v3_dss",
                "pfet_03v3_dss",
                "nfet_06v0_dss",
                "pfet_06v0_dss",
            ],
        ),
    );
    d.rule(
        "OX.3v3",
        gate_oxide(
            &["nfet_03v3", "pfet_03v3", "nfet_03v3_dss", "pfet_03v3_dss"],
            3300.0,
        ),
    );
    d.rule(
        "OX.6v0",
        gate_oxide(
            &[
                "nfet_06v0",
                "pfet_06v0",
                "nfet_06v0_nvt",
                "nfet_06v0_dss",
                "pfet_06v0_dss",
            ],
            6000.0,
        ),
    );
    d.rule(
        "DS.3v3",
        drain_source(
            &["nfet_03v3", "pfet_03v3", "nfet_03v3_dss", "pfet_03v3_dss"],
            3300.0,
        ),
    );
    d.rule(
        "DS.6v0",
        drain_source(
            &[
                "nfet_06v0",
                "pfet_06v0",
                "nfet_06v0_nvt",
                "nfet_06v0_dss",
                "pfet_06v0_dss",
            ],
            6000.0,
        ),
    );
    d.conductors(&[
        l["sd"],
        l["ntap"],
        l["ptap"],
        l["poly2_con"],
        l["metal1_con"],
        l["metal2_con"],
        l["metal3_con"],
        l["metal4"],
        l["metal5"],
        l["metaltop_con"],
    ]);
    d.touch_within_layer();
    d.via(l["contact"], (l["sd"], l["metal1_con"]));
    d.via(l["contact"], (l["ntap"], l["metal1_con"]));
    d.via(l["contact"], (l["ptap"], l["metal1_con"]));
    d.via(l["contact"], (l["poly2_con"], l["metal1_con"]));
    d.via(l["via1"], (l["metal1_con"], l["metal2_con"]));
    d.via(l["via2"], (l["metal2_con"], l["metal3_con"]));
    d.via(l["via3"], (l["metal3_con"], l["metal4"]));
    d.via(l["via4"], (l["metal4"], l["metal5"]));
    d.via(l["via5_nomim"], (l["metal5"], l["metaltop_con"]));
    d.label(l["comp_label"], l["sd"]);
    d.label(l["poly2_label"], l["poly2_con"]);
    d.label(l["metal1_label"], l["metal1_con"]);
    d.label(l["metal2_label"], l["metal2_con"]);
    d.label(l["metal3_label"], l["metal3_con"]);
    d.label(l["metal4_label"], l["metal4"]);
    d.label(l["metal5_label"], l["metal5"]);
    d.label(l["metaltop_label"], l["metaltop_con"]);
    d.device(
        DeviceKind::Mos,
        l["nfet_03v3_g"],
        "nfet_03v3",
        &[l["poly2_con"], l["sd"], l["sd"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Mos,
        l["pfet_03v3_g"],
        "pfet_03v3",
        &[l["poly2_con"], l["sd"], l["sd"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Mos,
        l["nfet_06v0_g"],
        "nfet_06v0",
        &[l["poly2_con"], l["sd"], l["sd"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Mos,
        l["pfet_06v0_g"],
        "pfet_06v0",
        &[l["poly2_con"], l["sd"], l["sd"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Mos,
        l["nfet_06v0_nvt_g"],
        "nfet_06v0_nvt",
        &[l["poly2_con"], l["sd"], l["sd"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Mos,
        l["nfet_03v3_dss_g"],
        "nfet_03v3_dss",
        &[l["poly2_con"], l["sd"], l["sd"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Mos,
        l["pfet_03v3_dss_g"],
        "pfet_03v3_dss",
        &[l["poly2_con"], l["sd"], l["sd"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Mos,
        l["nfet_06v0_dss_g"],
        "nfet_06v0_dss",
        &[l["poly2_con"], l["sd"], l["sd"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Mos,
        l["pfet_06v0_dss_g"],
        "pfet_06v0_dss",
        &[l["poly2_con"], l["sd"], l["sd"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Capacitor,
        l["cap_nmos_03v3_b_g"],
        "cap_nmos_03v3_b",
        &[l["poly2_con"], l["ntap"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Capacitor,
        l["cap_pmos_03v3_b_g"],
        "cap_pmos_03v3_b",
        &[l["poly2_con"], l["ptap"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Capacitor,
        l["cap_nmos_06v0_b_g"],
        "cap_nmos_06v0_b",
        &[l["poly2_con"], l["ntap"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Capacitor,
        l["cap_pmos_06v0_b_g"],
        "cap_pmos_06v0_b",
        &[l["poly2_con"], l["ptap"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Resistor,
        l["npolyf_u_r"],
        "npolyf_u",
        &[l["poly2_con"], l["poly2_con"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Resistor,
        l["ppolyf_u_r"],
        "ppolyf_u",
        &[l["poly2_con"], l["poly2_con"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Resistor,
        l["npolyf_s_r"],
        "npolyf_s",
        &[l["poly2_con"], l["poly2_con"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Resistor,
        l["ppolyf_s_r"],
        "ppolyf_s",
        &[l["poly2_con"], l["poly2_con"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Resistor,
        l["ppolyf_u_1k_r"],
        "ppolyf_u_1k",
        &[l["poly2_con"], l["poly2_con"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Resistor,
        l["ppolyf_u_1k_6p0_r"],
        "ppolyf_u_1k_6p0",
        &[l["poly2_con"], l["poly2_con"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Resistor,
        l["nplus_u_r"],
        "nplus_u",
        &[l["sd"], l["sd"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Resistor,
        l["pplus_u_r"],
        "pplus_u",
        &[l["sd"], l["sd"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Resistor,
        l["nplus_s_r"],
        "nplus_s",
        &[l["sd"], l["sd"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Resistor,
        l["pplus_s_r"],
        "pplus_s",
        &[l["sd"], l["sd"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Resistor,
        l["rm1_r"],
        "rm1",
        &[l["metal1_con"], l["metal1_con"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Resistor,
        l["rm2_r"],
        "rm2",
        &[l["metal2_con"], l["metal2_con"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Resistor,
        l["rm3_r"],
        "rm3",
        &[l["metal3_con"], l["metal3_con"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Resistor,
        l["tm9k_r"],
        "tm9k",
        &[l["metaltop_con"], l["metaltop_con"]],
        DeviceValue::default(),
    );
    d.pex(
        l["sd"],
        StackSource {
            thickness_nm: 300.0,
            height_nm: 14.5,
            sheet_res_ohm_sq: 7.0,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 4.0,
            tc: None,
        },
    );
    d.pex(
        l["ntap"],
        StackSource {
            thickness_nm: 300.0,
            height_nm: 14.5,
            sheet_res_ohm_sq: 6.3,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 4.0,
            tc: None,
        },
    );
    d.pex(
        l["ptap"],
        StackSource {
            thickness_nm: 300.0,
            height_nm: 14.5,
            sheet_res_ohm_sq: 7.0,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 4.0,
            tc: None,
        },
    );
    d.pex(
        l["poly2_con"],
        StackSource {
            thickness_nm: 200.0,
            height_nm: 320.0,
            sheet_res_ohm_sq: 7.3,
            area_cap_af_um2: 110.67,
            fringe_cap_af_um: 50.72,
            dielectric_k: 4.0,
            tc: None,
        },
    );
    d.pex(
        l["contact"],
        StackSource {
            thickness_nm: 915.5,
            height_nm: 314.5,
            sheet_res_ohm_sq: 8.0,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 4.0,
            tc: None,
        },
    );
    d.pex(
        l["metal1_con"],
        StackSource {
            thickness_nm: 550.0,
            height_nm: 1230.0,
            sheet_res_ohm_sq: 0.09,
            area_cap_af_um2: 29.304,
            fringe_cap_af_um: 39.431,
            dielectric_k: 4.0,
            tc: None,
        },
    );
    d.pex(
        l["via1"],
        StackSource {
            thickness_nm: 600.0,
            height_nm: 1780.0,
            sheet_res_ohm_sq: 4.5,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 4.0,
            tc: None,
        },
    );
    d.pex(
        l["metal2_con"],
        StackSource {
            thickness_nm: 550.0,
            height_nm: 2380.0,
            sheet_res_ohm_sq: 0.09,
            area_cap_af_um2: 15.016,
            fringe_cap_af_um: 33.298,
            dielectric_k: 4.0,
            tc: None,
        },
    );
    d.pex(
        l["via2"],
        StackSource {
            thickness_nm: 600.0,
            height_nm: 2930.0,
            sheet_res_ohm_sq: 4.5,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 4.0,
            tc: None,
        },
    );
    d.pex(
        l["metal3_con"],
        StackSource {
            thickness_nm: 550.0,
            height_nm: 3530.0,
            sheet_res_ohm_sq: 0.09,
            area_cap_af_um2: 10.094,
            fringe_cap_af_um: 30.021,
            dielectric_k: 4.0,
            tc: None,
        },
    );
    d.pex(
        l["via3"],
        StackSource {
            thickness_nm: 600.0,
            height_nm: 4080.0,
            sheet_res_ohm_sq: 4.5,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 4.0,
            tc: None,
        },
    );
    d.pex(
        l["metal4"],
        StackSource {
            thickness_nm: 550.0,
            height_nm: 4680.0,
            sheet_res_ohm_sq: 0.09,
            area_cap_af_um2: 7.602,
            fringe_cap_af_um: 28.153,
            dielectric_k: 4.0,
            tc: None,
        },
    );
    d.pex(
        l["via4"],
        StackSource {
            thickness_nm: 600.0,
            height_nm: 5230.0,
            sheet_res_ohm_sq: 4.5,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 4.0,
            tc: None,
        },
    );
    d.pex(
        l["metal5"],
        StackSource {
            thickness_nm: 550.0,
            height_nm: 5830.0,
            sheet_res_ohm_sq: 0.09,
            area_cap_af_um2: 5.798,
            fringe_cap_af_um: 30.386,
            dielectric_k: 4.0,
            tc: None,
        },
    );
    d.pex(
        l["via5_nomim"],
        StackSource {
            thickness_nm: 900.0,
            height_nm: 6380.0,
            sheet_res_ohm_sq: 4.5,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 4.0,
            tc: None,
        },
    );
    d.pex(
        l["metaltop_con"],
        StackSource {
            thickness_nm: 1002.5,
            height_nm: 7280.0,
            sheet_res_ohm_sq: 0.04,
            area_cap_af_um2: 4.8793,
            fringe_cap_af_um: 9.595,
            dielectric_k: 4.0,
            tc: None,
        },
    );
    d.rule("LPW.12", forbidden(l["lvpwell"].and(l["nwell"])));
    d.rule("NW.4", forbidden(l["nwell"].and(l["lvpwell"])));
    d.rule(
        "NW.6",
        forbidden(l["nwell"].inside(l["res_mk"]).and(l["dnwell"])),
    );
    d.rule("DV.7", forbidden(l["comp_dv"].not(l["dualgate"])));
    d.rule(
        "PL.9",
        forbidden(
            l["poly2"]
                .and(l["dualgate"])
                .group()
                .interacting(l["poly2"].not(l["dualgate"])),
        ),
    );
    d.rule(
        "PL.11",
        forbidden(l["v5_xtor"].not_interacting(l["dualgate"])),
    );
    d.rule(
        "PL.12",
        forbidden(l["comp"].interacting(l["v5_xtor"]).not(l["v5_xtor"])),
    );
    d.rule("SB.8", forbidden(l["contact"].inside(l["sab"])));
    d.rule("ESD.3b", forbidden(l["esd"].and(l["pcomp"])));
    d.rule("ESD.7", forbidden(l["esd"].and(l["pcomp"])));
    d.rule("ESD.9", must_be_inside(l["esd"], l["dualgate"]));
    d.rule("CO.10", forbidden(l["contact"].and(l["gate"])));
    d.rule(
        "CO.11",
        forbidden(l["contact"].not(l["comp"].or(l["poly2"]).group())),
    );
    d.rule(
        "MIMTM.10",
        forbidden(l["via4"].interacting(l["metal5_mim"])),
    );
    d.rule("NAT.10", forbidden(l["nwell"].inside(l["nat"])));
    d.rule(
        "NAT.11",
        forbidden(l["ncomp"].and(l["nat"]).group().outside(l["poly2"])),
    );
    d.rule(
        "NAT.12",
        forbidden(
            l["poly2"]
                .and(l["nat"])
                .group()
                .not_interacting(l["comp"])
                .or(l["poly2"].and(l["nat"]).and(l["res_mk"])),
        ),
    );
    d.rule("V1.3a", must_be_inside(l["via1"], l["metal1"]));
    d.rule(
        "DF.11",
        edge_min_length(l["ncomp"].edges().and(l["pcomp"].edges()), nm(300)),
    );
    d.finish()
}
