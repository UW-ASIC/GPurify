//! The Rust twin of `pdks/ihp_sg13g2.deck`: the same deck stated with
//! [`DeckBuilder`], statement by statement, `for` loops unrolled and `let`
//! bindings substituted. Translated once from the deck text by a reader of
//! the deck language independent of the parser; the twin test holds this
//! to the parsed text. After editing the deck, edit this to match: the test
//! names the first difference.

#![allow(clippy::unreadable_literal, reason = "values as the deck writes them")]

use gpurify_check::deck::rules::{
    angle, antenna, asymmetric_enclosure, cut_size, density, drain_source, edge_width,
    em_current_density, esd_topological, floating_gate, floating_well, forbidden, gate_oxide,
    global_density, ir_drop, max_width, min_area, min_enclosed_area, min_enclosure, min_extension,
    min_spacing, min_spacing_diff, min_width, missing_tie, multiple_drivers, must_be_inside, notch,
    off_grid, spacing_table, supply_short, tie_high_low, unconnected_pin, via_array_spacing,
};
use gpurify_check::deck::{Bound, BuildError, CompiledDeck, DeckBuilder, LayerRef};
use gpurify_geom::{Dbu, DbuArea, Grid, StrTable};
use gpurify_ingest::deck::{DeviceKind, DeviceValue, StackSource};
use std::collections::HashMap;

fn nm(raw: i64) -> Dbu {
    Dbu::new_unchecked(raw)
}

fn nm2(raw: i64) -> DbuArea {
    DbuArea::new(i128::from(raw))
}

/// `pdks/ihp_sg13g2.deck`, built on a 1 nm grid into `strings`.
#[allow(
    clippy::too_many_lines,
    reason = "a whole deck, statement by statement"
)]
pub fn build(strings: &mut StrTable) -> Result<CompiledDeck, BuildError> {
    let mut d = DeckBuilder::new(Grid::new(1000).expect("a 1 nm grid"), strings);
    let mut l: HashMap<&str, LayerRef> = HashMap::new();
    l.insert("activ", d.layer("activ", (1, 0)));
    l.insert("activ_mask", d.layer("activ_mask", (1, 20)));
    l.insert("activ_filler", d.layer("activ_filler", (1, 22)));
    l.insert("gatpoly", d.layer("gatpoly", (5, 0)));
    l.insert("gatpoly_filler", d.layer("gatpoly_filler", (5, 22)));
    l.insert("cont", d.layer("cont", (6, 0)));
    l.insert("nsd", d.layer("nsd", (7, 0)));
    l.insert("nsd_block", d.layer("nsd_block", (7, 21)));
    l.insert("metal1", d.layer("metal1", (8, 0)));
    l.insert("metal1_filler", d.layer("metal1_filler", (8, 22)));
    l.insert("metal1_slit", d.layer("metal1_slit", (8, 24)));
    l.insert("metal1_label", d.layer("metal1_label", (8, 25)));
    l.insert("passiv", d.layer("passiv", (9, 0)));
    l.insert("metal2", d.layer("metal2", (10, 0)));
    l.insert("metal2_filler", d.layer("metal2_filler", (10, 22)));
    l.insert("metal2_slit", d.layer("metal2_slit", (10, 24)));
    l.insert("metal2_label", d.layer("metal2_label", (10, 25)));
    l.insert("psd", d.layer("psd", (14, 0)));
    l.insert("via1", d.layer("via1", (19, 0)));
    l.insert("res", d.layer("res", (24, 0)));
    l.insert("trans", d.layer("trans", (26, 0)));
    l.insert("ind", d.layer("ind", (27, 0)));
    l.insert("salblock", d.layer("salblock", (28, 0)));
    l.insert("via2", d.layer("via2", (29, 0)));
    l.insert("metal3", d.layer("metal3", (30, 0)));
    l.insert("metal3_filler", d.layer("metal3_filler", (30, 22)));
    l.insert("metal3_slit", d.layer("metal3_slit", (30, 24)));
    l.insert("metal3_label", d.layer("metal3_label", (30, 25)));
    l.insert("nwell", d.layer("nwell", (31, 0)));
    l.insert("nbulay", d.layer("nbulay", (32, 0)));
    l.insert("nbulay_block", d.layer("nbulay_block", (32, 21)));
    l.insert("mim", d.layer("mim", (36, 0)));
    l.insert("edgeseal", d.layer("edgeseal", (39, 0)));
    l.insert("dfpad", d.layer("dfpad", (41, 0)));
    l.insert("thickgateox", d.layer("thickgateox", (44, 0)));
    l.insert("pwell_block", d.layer("pwell_block", (46, 21)));
    l.insert("via3", d.layer("via3", (49, 0)));
    l.insert("metal4", d.layer("metal4", (50, 0)));
    l.insert("metal4_filler", d.layer("metal4_filler", (50, 22)));
    l.insert("metal4_slit", d.layer("metal4_slit", (50, 24)));
    l.insert("metal4_label", d.layer("metal4_label", (50, 25)));
    l.insert("via4", d.layer("via4", (66, 0)));
    l.insert("metal5", d.layer("metal5", (67, 0)));
    l.insert("metal5_filler", d.layer("metal5_filler", (67, 22)));
    l.insert("metal5_slit", d.layer("metal5_slit", (67, 24)));
    l.insert("metal5_label", d.layer("metal5_label", (67, 25)));
    l.insert("recog_esd", d.layer("recog_esd", (99, 30)));
    l.insert("recog_diode", d.layer("recog_diode", (99, 31)));
    l.insert("extblock", d.layer("extblock", (111, 0)));
    l.insert("topvia1", d.layer("topvia1", (125, 0)));
    l.insert("topmetal1", d.layer("topmetal1", (126, 0)));
    l.insert("topmetal1_filler", d.layer("topmetal1_filler", (126, 22)));
    l.insert("topmetal1_slit", d.layer("topmetal1_slit", (126, 24)));
    l.insert("topmetal1_label", d.layer("topmetal1_label", (126, 25)));
    l.insert("polyres", d.layer("polyres", (128, 0)));
    l.insert("topvia2", d.layer("topvia2", (133, 0)));
    l.insert("topmetal2", d.layer("topmetal2", (134, 0)));
    l.insert("topmetal2_filler", d.layer("topmetal2_filler", (134, 22)));
    l.insert("topmetal2_slit", d.layer("topmetal2_slit", (134, 24)));
    l.insert("topmetal2_label", d.layer("topmetal2_label", (134, 25)));
    l.insert("lbe", d.layer("lbe", (157, 0)));
    l.insert("prboundary", d.layer("prboundary", (189, 0)));
    l.insert("gate", d.derived("gate", l["gatpoly"].and(l["activ"])));
    l.insert("res_mk", d.derived("res_mk", l["polyres"].or(l["res"])));
    l.insert(
        "nact",
        d.derived("nact", l["activ"].not(l["psd"]).group().not(l["nsd_block"])),
    );
    l.insert("pact", d.derived("pact", l["activ"].and(l["psd"])));
    l.insert(
        "nsd_c",
        d.derived("nsd_c", l["nact"].not(l["gatpoly"]).group().not(l["nwell"])),
    );
    l.insert(
        "ntap",
        d.derived("ntap", l["nact"].not(l["gatpoly"]).group().and(l["nwell"])),
    );
    l.insert(
        "psd_c",
        d.derived("psd_c", l["pact"].not(l["gatpoly"]).group().and(l["nwell"])),
    );
    l.insert(
        "ptap",
        d.derived("ptap", l["pact"].not(l["gatpoly"]).group().not(l["nwell"])),
    );
    l.insert(
        "gatpoly_c",
        d.derived("gatpoly_c", l["gatpoly"].not(l["res_mk"])),
    );
    l.insert("pact_nw", d.derived("pact_nw", l["pact"].and(l["nwell"])));
    l.insert(
        "pact_pw",
        d.derived(
            "pact_pw",
            l["pact"].not(l["nwell"]).group().not(l["pwell_block"]),
        ),
    );
    l.insert(
        "nact_pw",
        d.derived(
            "nact_pw",
            l["nact"].not(l["nwell"]).group().not(l["pwell_block"]),
        ),
    );
    l.insert("nact_out", d.derived("nact_out", l["nact"].not(l["nwell"])));
    l.insert(
        "nbl_pre",
        d.derived(
            "nbl_pre",
            l["nwell"]
                .sized(nm(-1500))
                .sized(nm(1500))
                .sized(nm(1000))
                .or(l["nbulay"]),
        ),
    );
    l.insert("nbl", d.derived("nbl", l["nbl_pre"].not(l["nbulay_block"])));
    l.insert(
        "mos_exc",
        d.derived(
            "mos_exc",
            l["recog_esd"]
                .or(l["recog_diode"])
                .group()
                .or(l["pwell_block"])
                .group()
                .or(l["trans"])
                .group()
                .or(l["salblock"])
                .group()
                .or(l["extblock"]),
        ),
    );
    l.insert(
        "gate_dev",
        d.derived(
            "gate_dev",
            l["gate"].not(l["res_mk"]).group().not(l["mos_exc"]),
        ),
    );
    l.insert(
        "ngate",
        d.derived(
            "ngate",
            l["gate_dev"].not(l["psd"]).group().not(l["nsd_block"]),
        ),
    );
    l.insert(
        "pgate",
        d.derived("pgate", l["gate_dev"].and(l["psd"]).group().and(l["nwell"])),
    );
    l.insert(
        "ngate_lv",
        d.derived("ngate_lv", l["ngate"].not(l["thickgateox"])),
    );
    l.insert(
        "ngate_hv",
        d.derived("ngate_hv", l["ngate"].and(l["thickgateox"])),
    );
    l.insert(
        "pgate_lv",
        d.derived("pgate_lv", l["pgate"].not(l["thickgateox"])),
    );
    l.insert(
        "pgate_hv",
        d.derived("pgate_hv", l["pgate"].and(l["thickgateox"])),
    );
    l.insert(
        "gate_nw",
        d.derived(
            "gate_nw",
            l["gate"].and(l["nwell"]).group().not(l["nbulay"]),
        ),
    );
    l.insert(
        "gate_pw",
        d.derived("gate_pw", l["gate"].not(l["psd"]).group().not(l["nwell"])),
    );
    l.insert("rbody", d.derived("rbody", l["gatpoly"].and(l["polyres"])));
    l.insert(
        "rsil_body",
        d.derived(
            "rsil_body",
            l["rbody"]
                .and(l["res"])
                .group()
                .not(l["psd"])
                .group()
                .not(l["salblock"]),
        ),
    );
    l.insert(
        "rppd_body",
        d.derived(
            "rppd_body",
            l["rbody"]
                .and(l["psd"])
                .group()
                .and(l["salblock"])
                .group()
                .not(l["nsd"]),
        ),
    );
    l.insert(
        "rhigh_body",
        d.derived(
            "rhigh_body",
            l["rbody"]
                .and(l["psd"])
                .group()
                .and(l["nsd"])
                .group()
                .and(l["salblock"]),
        ),
    );
    l.insert(
        "rsil_poly",
        d.derived("rsil_poly", l["gatpoly"].interacting(l["rsil_body"])),
    );
    l.insert(
        "rppd_poly",
        d.derived("rppd_poly", l["gatpoly"].interacting(l["rppd_body"])),
    );
    l.insert(
        "rhigh_poly",
        d.derived("rhigh_poly", l["gatpoly"].interacting(l["rhigh_body"])),
    );
    l.insert(
        "esd_vdd",
        d.derived(
            "esd_vdd",
            l["recog_esd"]
                .interacting(l["psd_c"])
                .not_interacting(l["gatpoly"])
                .not_interacting(l["nbulay"]),
        ),
    );
    l.insert(
        "esd_vss",
        d.derived(
            "esd_vss",
            l["recog_esd"]
                .interacting(l["nsd_c"])
                .not_interacting(l["psd_c"])
                .not_interacting(l["gatpoly"])
                .not_interacting(l["nbulay"]),
        ),
    );
    l.insert(
        "topvia1_m5",
        d.derived("topvia1_m5", l["topvia1"].not(l["mim"])),
    );
    l.insert(
        "activ_den",
        d.derived(
            "activ_den",
            l["activ"].or(l["activ_filler"]).group().or(l["activ_mask"]),
        ),
    );
    l.insert(
        "gatpoly_den",
        d.derived("gatpoly_den", l["gatpoly"].or(l["gatpoly_filler"])),
    );
    l.insert(
        "metal1_den",
        d.derived(
            "metal1_den",
            l["metal1"]
                .or(l["metal1_filler"])
                .group()
                .not(l["metal1_slit"]),
        ),
    );
    l.insert(
        "metal2_den",
        d.derived(
            "metal2_den",
            l["metal2"]
                .or(l["metal2_filler"])
                .group()
                .not(l["metal2_slit"]),
        ),
    );
    l.insert(
        "metal3_den",
        d.derived(
            "metal3_den",
            l["metal3"]
                .or(l["metal3_filler"])
                .group()
                .not(l["metal3_slit"]),
        ),
    );
    l.insert(
        "metal4_den",
        d.derived(
            "metal4_den",
            l["metal4"]
                .or(l["metal4_filler"])
                .group()
                .not(l["metal4_slit"]),
        ),
    );
    l.insert(
        "metal5_den",
        d.derived(
            "metal5_den",
            l["metal5"]
                .or(l["metal5_filler"])
                .group()
                .not(l["metal5_slit"]),
        ),
    );
    l.insert(
        "topmetal1_den",
        d.derived(
            "topmetal1_den",
            l["topmetal1"]
                .or(l["topmetal1_filler"])
                .group()
                .not(l["topmetal1_slit"]),
        ),
    );
    l.insert(
        "topmetal2_den",
        d.derived(
            "topmetal2_den",
            l["topmetal2"]
                .or(l["topmetal2_filler"])
                .group()
                .not(l["topmetal2_slit"]),
        ),
    );
    l.insert(
        "metal1_wide",
        d.derived(
            "metal1_wide",
            l["metal1"]
                .not(l["metal1_slit"])
                .group()
                .not(l["dfpad"])
                .group()
                .not(l["mim"].or(l["ind"]).group()),
        ),
    );
    l.insert(
        "metal2_wide",
        d.derived(
            "metal2_wide",
            l["metal2"]
                .not(l["metal2_slit"])
                .group()
                .not(l["dfpad"])
                .group()
                .not(l["mim"].or(l["ind"]).group()),
        ),
    );
    l.insert(
        "metal3_wide",
        d.derived(
            "metal3_wide",
            l["metal3"]
                .not(l["metal3_slit"])
                .group()
                .not(l["dfpad"])
                .group()
                .not(l["mim"].or(l["ind"]).group()),
        ),
    );
    l.insert(
        "metal4_wide",
        d.derived(
            "metal4_wide",
            l["metal4"]
                .not(l["metal4_slit"])
                .group()
                .not(l["dfpad"])
                .group()
                .not(l["mim"].or(l["ind"]).group()),
        ),
    );
    l.insert(
        "metal5_wide",
        d.derived(
            "metal5_wide",
            l["metal5"]
                .not(l["metal5_slit"])
                .group()
                .not(l["dfpad"])
                .group()
                .not(l["mim"].or(l["ind"]).group()),
        ),
    );
    l.insert(
        "topmetal1_wide",
        d.derived(
            "topmetal1_wide",
            l["topmetal1"]
                .not(l["topmetal1_slit"])
                .group()
                .not(l["dfpad"])
                .group()
                .not(l["mim"].or(l["ind"]).group()),
        ),
    );
    l.insert(
        "topmetal2_wide",
        d.derived(
            "topmetal2_wide",
            l["topmetal2"]
                .not(l["topmetal2_slit"])
                .group()
                .not(l["dfpad"])
                .group()
                .not(l["mim"].or(l["ind"]).group()),
        ),
    );
    l.insert("pad", d.derived("pad", l["passiv"].and(l["dfpad"])));
    l.insert(
        "iso_pwell",
        d.derived("iso_pwell", l["nwell"].holes().and(l["nbulay"])),
    );
    l.insert(
        "pact_nw_lv",
        d.derived("pact_nw_lv", l["pact_nw"].not(l["thickgateox"])),
    );
    l.insert(
        "pact_nw_hv",
        d.derived("pact_nw_hv", l["pact_nw"].and(l["thickgateox"])),
    );
    l.insert(
        "nact_out_lv",
        d.derived("nact_out_lv", l["nact_out"].not(l["thickgateox"])),
    );
    l.insert(
        "nact_out_hv",
        d.derived("nact_out_hv", l["nact_out"].and(l["thickgateox"])),
    );
    l.insert(
        "ntie_lv",
        d.derived(
            "ntie_lv",
            l["nact"].and(l["nwell"]).group().not(l["thickgateox"]),
        ),
    );
    l.insert(
        "ntie_hv",
        d.derived(
            "ntie_hv",
            l["nact"].and(l["nwell"]).group().and(l["thickgateox"]),
        ),
    );
    l.insert(
        "pact_pw_lv",
        d.derived("pact_pw_lv", l["pact_pw"].not(l["thickgateox"])),
    );
    l.insert(
        "pact_pw_hv",
        d.derived("pact_pw_hv", l["pact_pw"].and(l["thickgateox"])),
    );
    l.insert(
        "nact_pw_lv",
        d.derived("nact_pw_lv", l["nact_pw"].not(l["thickgateox"])),
    );
    l.insert(
        "nact_pw_hv",
        d.derived("nact_pw_hv", l["nact_pw"].and(l["thickgateox"])),
    );
    l.insert(
        "nwell_unrel_pwb",
        d.derived(
            "nwell_unrel_pwb",
            l["nwell"].not_interacting(l["pwell_block"]),
        ),
    );
    l.insert(
        "nact_unrel_nbl",
        d.derived("nact_unrel_nbl", l["nact"].not_interacting(l["nbl"])),
    );
    l.insert(
        "pact_unrel_nbl",
        d.derived("pact_unrel_nbl", l["pact"].not_interacting(l["nbl"])),
    );
    l.insert(
        "nbl_unrel_nblb",
        d.derived(
            "nbl_unrel_nblb",
            l["nbl_pre"].not_interacting(l["nbulay_block"]),
        ),
    );
    l.insert(
        "afil_in_pwb",
        d.derived("afil_in_pwb", l["activ_filler"].inside(l["pwell_block"])),
    );
    l.insert(
        "activ_tgo",
        d.derived("activ_tgo", l["activ"].interacting(l["thickgateox"])),
    );
    l.insert(
        "activ_no_tgo",
        d.derived("activ_no_tgo", l["activ"].not_interacting(l["thickgateox"])),
    );
    l.insert(
        "gate_tgo",
        d.derived("gate_tgo", l["gate"].interacting(l["thickgateox"])),
    );
    l.insert(
        "gate_no_tgo",
        d.derived("gate_no_tgo", l["gate"].not_interacting(l["thickgateox"])),
    );
    l.insert(
        "gate_hv",
        d.derived("gate_hv", l["gate"].and(l["thickgateox"])),
    );
    l.insert(
        "gatpoly_field_only",
        d.derived(
            "gatpoly_field_only",
            l["gatpoly"].not_interacting(l["activ"]),
        ),
    );
    l.insert(
        "activ_no_poly",
        d.derived("activ_no_poly", l["activ"].not_interacting(l["gatpoly"])),
    );
    l.insert(
        "pact_whole_nw",
        d.derived(
            "pact_whole_nw",
            l["activ"].inside(l["psd"]).inside(l["nwell"]),
        ),
    );
    l.insert(
        "pact_whole_pw",
        d.derived(
            "pact_whole_pw",
            l["activ"].inside(l["psd"]).outside(l["nwell"]),
        ),
    );
    l.insert(
        "nact_unrel_pw",
        d.derived(
            "nact_unrel_pw",
            l["activ"].not_interacting(l["psd"]).outside(l["nwell"]),
        ),
    );
    l.insert(
        "nact_unrel_nw",
        d.derived(
            "nact_unrel_nw",
            l["activ"].not_interacting(l["psd"]).inside(l["nwell"]),
        ),
    );
    l.insert(
        "ntap_abutted",
        d.derived("ntap_abutted", l["ntap"].interacting(l["psd_c"])),
    );
    l.insert(
        "ptap_abutted",
        d.derived("ptap_abutted", l["ptap"].interacting(l["nsd_c"])),
    );
    l.insert(
        "pfet_gate_lv",
        d.derived("pfet_gate_lv", l["gate_nw"].not(l["thickgateox"])),
    );
    l.insert(
        "pfet_gate_hv",
        d.derived("pfet_gate_hv", l["gate_nw"].and(l["thickgateox"])),
    );
    l.insert(
        "nfet_gate_lv",
        d.derived("nfet_gate_lv", l["gate_pw"].not(l["thickgateox"])),
    );
    l.insert(
        "nfet_gate_hv",
        d.derived("nfet_gate_hv", l["gate_pw"].and(l["thickgateox"])),
    );
    l.insert(
        "psd_unrel_nsdb",
        d.derived("psd_unrel_nsdb", l["psd"].not_interacting(l["nsd_block"])),
    );
    l.insert(
        "psd_unrel_ext",
        d.derived("psd_unrel_ext", l["psd"].not_interacting(l["extblock"])),
    );
    l.insert(
        "activ_unrel_sal",
        d.derived("activ_unrel_sal", l["activ"].not_interacting(l["salblock"])),
    );
    l.insert(
        "gatpoly_unrel_sal",
        d.derived(
            "gatpoly_unrel_sal",
            l["gatpoly"].not_interacting(l["salblock"]),
        ),
    );
    l.insert(
        "cont_activ",
        d.derived("cont_activ", l["cont"].and(l["activ"])),
    );
    l.insert(
        "cont_poly",
        d.derived("cont_poly", l["cont"].and(l["gatpoly"])),
    );
    l.insert(
        "cont_nact",
        d.derived("cont_nact", l["cont"].and(l["nact"])),
    );
    l.insert(
        "cont_pact",
        d.derived("cont_pact", l["cont"].and(l["pact"])),
    );
    l.insert(
        "sal_rppd",
        d.derived("sal_rppd", l["salblock"].interacting(l["rppd_body"])),
    );
    l.insert(
        "sal_rhigh",
        d.derived("sal_rhigh", l["salblock"].interacting(l["rhigh_body"])),
    );
    l.insert(
        "iso_pwell_activ",
        d.derived("iso_pwell_activ", l["activ"].and(l["iso_pwell"])),
    );
    l.insert(
        "nsdb_iso",
        d.derived("nsdb_iso", l["nsd_block"].inside(l["iso_pwell"])),
    );
    l.insert(
        "topvia1_mim",
        d.derived("topvia1_mim", l["topvia1"].interacting(l["mim"])),
    );
    l.insert(
        "topmetal1_unrel_mim",
        d.derived(
            "topmetal1_unrel_mim",
            l["topmetal1"].not_interacting(l["mim"]),
        ),
    );
    d.rule("NW.a", min_width(l["nwell"], nm(620)));
    d.rule("NW.b", min_spacing(l["nwell"], nm(620)));
    d.rule("NW.b.notch", notch(l["nwell"], nm(620)));
    d.rule("NW.c", min_enclosure(l["pact_nw_lv"], l["nwell"], nm(310)));
    d.rule("NW.c1", min_enclosure(l["pact_nw_hv"], l["nwell"], nm(620)));
    d.rule(
        "NW.d",
        min_spacing_diff(l["nwell"], l["nact_out_lv"], nm(310)),
    );
    d.rule(
        "NW.d1",
        min_spacing_diff(l["nwell"], l["nact_out_hv"], nm(620)),
    );
    d.rule("NW.e", min_enclosure(l["ntie_lv"], l["nwell"], nm(240)));
    d.rule("NW.e1", min_enclosure(l["ntie_hv"], l["nwell"], nm(620)));
    d.rule(
        "NW.f",
        min_spacing_diff(l["nwell"], l["pact_pw_lv"], nm(240)),
    );
    d.rule(
        "NW.f1",
        min_spacing_diff(l["nwell"], l["pact_pw_hv"], nm(620)),
    );
    d.rule("PWB.a", min_width(l["pwell_block"], nm(620)));
    d.rule("PWB.b", min_spacing(l["pwell_block"], nm(620)));
    d.rule("PWB.b.notch", notch(l["pwell_block"], nm(620)));
    d.rule(
        "PWB.c",
        min_spacing_diff(l["pwell_block"], l["nwell_unrel_pwb"], nm(620)),
    );
    d.rule(
        "PWB.e",
        min_spacing_diff(l["pwell_block"], l["nact_pw_lv"], nm(310)),
    );
    d.rule(
        "PWB.e1",
        min_spacing_diff(l["pwell_block"], l["nact_pw_hv"], nm(620)),
    );
    d.rule(
        "PWB.f",
        min_spacing_diff(l["pwell_block"], l["pact_pw_lv"], nm(240)),
    );
    d.rule(
        "PWB.f1",
        min_spacing_diff(l["pwell_block"], l["pact_pw_hv"], nm(620)),
    );
    d.rule("NBL.a", min_width(l["nbl"], nm(1000)));
    d.rule("NBL.b", min_spacing(l["nbl"], nm(1500)));
    d.rule("NBL.b.notch", notch(l["nbl"], nm(1500)));
    d.rule(
        "NBL.e",
        min_spacing_diff(l["nbl"], l["nact_unrel_nbl"], nm(1000)),
    );
    d.rule(
        "NBL.f",
        min_spacing_diff(l["nbl"], l["pact_unrel_nbl"], nm(500)),
    );
    d.rule("NBLB.a", min_width(l["nbulay_block"], nm(1500)));
    d.rule("NBLB.b", min_spacing(l["nbulay_block"], nm(1000)));
    d.rule("NBLB.b.notch", notch(l["nbulay_block"], nm(1000)));
    d.rule(
        "NBLB.c",
        min_enclosure(l["nbulay_block"], l["nbl_pre"], nm(1000)),
    );
    d.rule(
        "NBLB.d",
        min_spacing_diff(l["nbulay_block"], l["nbl_unrel_nblb"], nm(1500)),
    );
    d.rule("Act.a", min_width(l["activ"], nm(150)));
    d.rule("Act.b", min_spacing(l["activ"], nm(210)));
    d.rule("Act.b.notch", notch(l["activ"], nm(210)));
    d.rule("Act.c", min_extension(l["activ"], l["gatpoly"], nm(230)));
    d.rule("Act.d", min_area(l["activ"], nm2(122000)));
    d.rule("Act.e", min_enclosed_area(l["activ"], nm2(150000)));
    d.rule("AFil.a", max_width(l["activ_filler"], nm(5000)));
    d.rule("AFil.a1", min_width(l["activ_filler"], nm(1000)));
    d.rule("AFil.b", min_spacing(l["activ_filler"], nm(420)));
    d.rule(
        "AFil.c.Cont",
        min_spacing_diff(l["activ_filler"], l["cont"], nm(1100)),
    );
    d.rule(
        "AFil.c.GatPoly",
        min_spacing_diff(l["activ_filler"], l["gatpoly"], nm(1100)),
    );
    d.rule(
        "AFil.c1",
        min_spacing_diff(l["activ_filler"], l["activ"], nm(420)),
    );
    d.rule(
        "AFil.d.NWell",
        min_spacing_diff(l["activ_filler"], l["nwell"], nm(1000)),
    );
    d.rule(
        "AFil.d.nBuLay",
        min_spacing_diff(l["activ_filler"], l["nbl"], nm(1000)),
    );
    d.rule(
        "AFil.e",
        min_spacing_diff(l["activ_filler"], l["trans"], nm(1000)),
    );
    d.rule(
        "AFil.j.nSDblock",
        min_enclosure(l["afil_in_pwb"], l["nsd_block"], nm(250)),
    );
    d.rule(
        "AFil.j.SalBlock",
        min_enclosure(l["afil_in_pwb"], l["salblock"], nm(250)),
    );
    d.rule(
        "AFil.g",
        global_density(l["activ_den"], Some(l["prboundary"].into()), 0.35, false),
    );
    d.rule(
        "AFil.g1",
        global_density(l["activ_den"], Some(l["prboundary"].into()), 0.55, true),
    );
    d.rule(
        "AFil.g2",
        density(
            l["activ_den"],
            Some(l["prboundary"].into()),
            nm(800000),
            nm(400000),
            0.25,
            false,
        ),
    );
    d.rule(
        "AFil.g3",
        density(
            l["activ_den"],
            Some(l["prboundary"].into()),
            nm(800000),
            nm(400000),
            0.65,
            true,
        ),
    );
    d.rule(
        "TGO.a",
        min_enclosure(l["activ_tgo"], l["thickgateox"], nm(270)),
    );
    d.rule(
        "TGO.b",
        min_spacing_diff(l["thickgateox"], l["activ_no_tgo"], nm(270)),
    );
    d.rule(
        "TGO.c",
        min_enclosure(l["gate_tgo"], l["thickgateox"], nm(340)),
    );
    d.rule(
        "TGO.d",
        min_spacing_diff(l["thickgateox"], l["gate_no_tgo"], nm(340)),
    );
    d.rule("TGO.e", min_spacing(l["thickgateox"], nm(860)));
    d.rule("TGO.e.notch", notch(l["thickgateox"], nm(860)));
    d.rule("TGO.f", min_width(l["thickgateox"], nm(860)));
    d.rule("Gat.a", min_width(l["gatpoly"], nm(130)));
    d.rule("Gat.a1", min_width(l["ngate_lv"], nm(130)));
    d.rule("Gat.a2", min_width(l["pgate_lv"], nm(130)));
    d.rule(
        "Gat.a3",
        edge_width(l["ngate_hv"].edges().not(l["activ"].edges()), nm(450)),
    );
    d.rule(
        "Gat.a4",
        edge_width(l["pgate_hv"].edges().not(l["activ"].edges()), nm(400)),
    );
    d.rule("Gat.b", min_spacing(l["gatpoly"], nm(180)));
    d.rule("Gat.b.notch", notch(l["gatpoly"], nm(180)));
    d.rule("Gat.b1", min_spacing(l["gate_hv"], nm(250)));
    d.rule("Gat.c", min_extension(l["gatpoly"], l["activ"], nm(180)));
    d.rule(
        "Gat.d",
        min_spacing_diff(l["gatpoly_field_only"], l["activ"], nm(70)),
    );
    d.rule(
        "Gat.d.2",
        min_spacing_diff(l["gatpoly"], l["activ_no_poly"], nm(70)),
    );
    d.rule("Gat.e", min_area(l["gatpoly"], nm2(90000)));
    d.rule("GFil.a", max_width(l["gatpoly_filler"], nm(5000)));
    d.rule("GFil.b", min_width(l["gatpoly_filler"], nm(700)));
    d.rule("GFil.c", min_spacing(l["gatpoly_filler"], nm(800)));
    d.rule(
        "GFil.d.Activ",
        min_spacing_diff(l["gatpoly_filler"], l["activ"], nm(1100)),
    );
    d.rule(
        "GFil.d.GatPoly",
        min_spacing_diff(l["gatpoly_filler"], l["gatpoly"], nm(1100)),
    );
    d.rule(
        "GFil.d.Cont",
        min_spacing_diff(l["gatpoly_filler"], l["cont"], nm(1100)),
    );
    d.rule(
        "GFil.d.pSD",
        min_spacing_diff(l["gatpoly_filler"], l["psd"], nm(1100)),
    );
    d.rule(
        "GFil.d.nSDblock",
        min_spacing_diff(l["gatpoly_filler"], l["nsd_block"], nm(1100)),
    );
    d.rule(
        "GFil.d.SalBlock",
        min_spacing_diff(l["gatpoly_filler"], l["salblock"], nm(1100)),
    );
    d.rule(
        "GFil.e.NWell",
        min_spacing_diff(l["gatpoly_filler"], l["nwell"], nm(1100)),
    );
    d.rule(
        "GFil.e.nBuLay",
        min_spacing_diff(l["gatpoly_filler"], l["nbl"], nm(1100)),
    );
    d.rule(
        "GFil.f",
        min_spacing_diff(l["gatpoly_filler"], l["trans"], nm(1100)),
    );
    d.rule(
        "GFil.g",
        global_density(l["gatpoly_den"], Some(l["prboundary"].into()), 0.15, false),
    );
    d.rule(
        "GFil.j",
        min_extension(l["gatpoly_filler"], l["activ_filler"], nm(180)),
    );
    d.rule("pSD.a", min_width(l["psd"], nm(310)));
    d.rule("pSD.b", min_spacing(l["psd"], nm(310)));
    d.rule("pSD.b.notch", notch(l["psd"], nm(310)));
    d.rule(
        "pSD.c",
        min_enclosure(l["pact_whole_nw"], l["psd"], nm(180)),
    );
    d.rule(
        "pSD.c1",
        min_enclosure(l["pact_whole_pw"], l["psd"], nm(30)),
    );
    d.rule(
        "pSD.d",
        min_spacing_diff(l["psd"], l["nact_unrel_pw"], nm(180)),
    );
    d.rule(
        "pSD.d1",
        min_spacing_diff(l["psd"], l["nact_unrel_nw"], nm(30)),
    );
    d.rule("pSD.g.NWellTie", min_area(l["ntap_abutted"], nm2(90000)));
    d.rule(
        "pSD.g.SubstrateTie",
        min_area(l["ptap_abutted"], nm2(90000)),
    );
    d.rule("pSD.i", min_enclosure(l["pfet_gate_lv"], l["psd"], nm(300)));
    d.rule(
        "pSD.i1",
        min_enclosure(l["pfet_gate_hv"], l["psd"], nm(400)),
    );
    d.rule(
        "pSD.j",
        min_spacing_diff(l["psd"], l["nfet_gate_lv"], nm(300)),
    );
    d.rule(
        "pSD.j1",
        min_spacing_diff(l["psd"], l["nfet_gate_hv"], nm(400)),
    );
    d.rule("pSD.k", min_area(l["psd"], nm2(250000)));
    d.rule("pSD.l", min_enclosed_area(l["psd"], nm2(250000)));
    d.rule("pSD.m", min_spacing_diff(l["psd"], l["rsil_poly"], nm(180)));
    d.rule("pSD.n", min_enclosure(l["rppd_poly"], l["psd"], nm(180)));
    d.rule("nSDB.a", min_width(l["nsd_block"], nm(310)));
    d.rule("nSDB.b", min_spacing(l["nsd_block"], nm(310)));
    d.rule("nSDB.b.notch", notch(l["nsd_block"], nm(310)));
    d.rule(
        "nSDB.c",
        min_spacing_diff(l["nsd_block"], l["psd_unrel_nsdb"], nm(310)),
    );
    d.rule("EXTB.a", min_width(l["extblock"], nm(310)));
    d.rule("EXTB.b", min_spacing(l["extblock"], nm(310)));
    d.rule("EXTB.b.notch", notch(l["extblock"], nm(310)));
    d.rule(
        "EXTB.c",
        min_spacing_diff(l["extblock"], l["psd_unrel_ext"], nm(310)),
    );
    d.rule("Sal.a", min_width(l["salblock"], nm(420)));
    d.rule("Sal.b", min_spacing(l["salblock"], nm(420)));
    d.rule("Sal.b.notch", notch(l["salblock"], nm(420)));
    d.rule(
        "Sal.c.Activ",
        min_extension(l["salblock"], l["activ"], nm(200)),
    );
    d.rule(
        "Sal.c.GatPoly",
        min_extension(l["salblock"], l["gatpoly"], nm(200)),
    );
    d.rule(
        "Sal.d.Activ",
        min_spacing_diff(l["salblock"], l["activ_unrel_sal"], nm(200)),
    );
    d.rule(
        "Sal.d.GatPoly",
        min_spacing_diff(l["salblock"], l["gatpoly_unrel_sal"], nm(200)),
    );
    d.rule("Sal.e", min_spacing_diff(l["salblock"], l["cont"], nm(200)));
    d.rule("Cnt.a", min_width(l["cont"], nm(160)));
    d.rule("Cnt.a.max", max_width(l["cont"], nm(160)));
    d.rule(
        "CntB.a1",
        forbidden(
            l["cont"]
                .non_squares()
                .with_bbox_max(&[Bound::Below(nm(340))]),
        ),
    );
    d.rule("Cnt.b", min_spacing(l["cont"], nm(180)));
    d.rule("Cnt.b1", via_array_spacing(l["cont"], 24, nm(200)));
    d.rule("Cnt.c", min_enclosure(l["cont_activ"], l["activ"], nm(70)));
    d.rule("Cnt.d", min_enclosure(l["cont_poly"], l["gatpoly"], nm(70)));
    d.rule(
        "Cnt.e",
        min_spacing_diff(l["cont_poly"], l["activ"], nm(140)),
    );
    d.rule(
        "Cnt.f",
        min_spacing_diff(l["cont_activ"], l["gatpoly"], nm(110)),
    );
    d.rule("Cnt.g1", min_spacing_diff(l["psd"], l["cont_nact"], nm(90)));
    d.rule("Cnt.g2", min_enclosure(l["cont_pact"], l["psd"], nm(90)));
    d.rule("M1.a", min_width(l["metal1"], nm(160)));
    d.rule("M1.b", min_spacing(l["metal1"], nm(180)));
    d.rule("M1.b.notch", notch(l["metal1"], nm(180)));
    d.rule(
        "M1.c1",
        asymmetric_enclosure(l["cont"], l["metal1"], nm(50)),
    );
    d.rule("M1.d", min_area(l["metal1"], nm2(90000)));
    d.rule(
        "M1.j",
        global_density(l["metal1_den"], Some(l["prboundary"].into()), 0.35, false),
    );
    d.rule(
        "M1.k",
        global_density(l["metal1_den"], Some(l["prboundary"].into()), 0.60, true),
    );
    d.rule("M2.a", min_width(l["metal2"], nm(200)));
    d.rule("M2.b", min_spacing(l["metal2"], nm(210)));
    d.rule("M2.b.notch", notch(l["metal2"], nm(210)));
    d.rule("M2.c", min_enclosure(l["via1"], l["metal2"], nm(5)));
    d.rule(
        "M2.c1",
        asymmetric_enclosure(l["via1"], l["metal2"], nm(50)),
    );
    d.rule("M2.d", min_area(l["metal2"], nm2(144000)));
    d.rule(
        "M2.j",
        global_density(l["metal2_den"], Some(l["prboundary"].into()), 0.35, false),
    );
    d.rule(
        "M2.k",
        global_density(l["metal2_den"], Some(l["prboundary"].into()), 0.60, true),
    );
    d.rule("M3.a", min_width(l["metal3"], nm(200)));
    d.rule("M3.b", min_spacing(l["metal3"], nm(210)));
    d.rule("M3.b.notch", notch(l["metal3"], nm(210)));
    d.rule("M3.c", min_enclosure(l["via2"], l["metal3"], nm(5)));
    d.rule(
        "M3.c1",
        asymmetric_enclosure(l["via2"], l["metal3"], nm(50)),
    );
    d.rule("M3.d", min_area(l["metal3"], nm2(144000)));
    d.rule(
        "M3.j",
        global_density(l["metal3_den"], Some(l["prboundary"].into()), 0.35, false),
    );
    d.rule(
        "M3.k",
        global_density(l["metal3_den"], Some(l["prboundary"].into()), 0.60, true),
    );
    d.rule("M4.a", min_width(l["metal4"], nm(200)));
    d.rule("M4.b", min_spacing(l["metal4"], nm(210)));
    d.rule("M4.b.notch", notch(l["metal4"], nm(210)));
    d.rule("M4.c", min_enclosure(l["via3"], l["metal4"], nm(5)));
    d.rule(
        "M4.c1",
        asymmetric_enclosure(l["via3"], l["metal4"], nm(50)),
    );
    d.rule("M4.d", min_area(l["metal4"], nm2(144000)));
    d.rule(
        "M4.j",
        global_density(l["metal4_den"], Some(l["prboundary"].into()), 0.35, false),
    );
    d.rule(
        "M4.k",
        global_density(l["metal4_den"], Some(l["prboundary"].into()), 0.60, true),
    );
    d.rule("M5.a", min_width(l["metal5"], nm(200)));
    d.rule("M5.b", min_spacing(l["metal5"], nm(210)));
    d.rule("M5.b.notch", notch(l["metal5"], nm(210)));
    d.rule("M5.c", min_enclosure(l["via4"], l["metal5"], nm(5)));
    d.rule(
        "M5.c1",
        asymmetric_enclosure(l["via4"], l["metal5"], nm(50)),
    );
    d.rule("M5.d", min_area(l["metal5"], nm2(144000)));
    d.rule(
        "M5.j",
        global_density(l["metal5_den"], Some(l["prboundary"].into()), 0.35, false),
    );
    d.rule(
        "M5.k",
        global_density(l["metal5_den"], Some(l["prboundary"].into()), 0.60, true),
    );
    d.rule("M1Fil.a1", min_width(l["metal1_filler"], nm(1000)));
    d.rule("M1Fil.a2", max_width(l["metal1_filler"], nm(5000)));
    d.rule("M1Fil.b", min_spacing(l["metal1_filler"], nm(420)));
    d.rule(
        "M1Fil.c",
        min_spacing_diff(l["metal1_filler"], l["metal1"], nm(420)),
    );
    d.rule(
        "M1Fil.d",
        min_spacing_diff(l["metal1_filler"], l["trans"], nm(1000)),
    );
    d.rule(
        "M1Fil.h",
        density(
            l["metal1_den"],
            Some(l["prboundary"].into()),
            nm(800000),
            nm(400000),
            0.25,
            false,
        ),
    );
    d.rule(
        "M1Fil.k",
        density(
            l["metal1_den"],
            Some(l["prboundary"].into()),
            nm(800000),
            nm(400000),
            0.75,
            true,
        ),
    );
    d.rule("M2Fil.a1", min_width(l["metal2_filler"], nm(1000)));
    d.rule("M2Fil.a2", max_width(l["metal2_filler"], nm(5000)));
    d.rule("M2Fil.b", min_spacing(l["metal2_filler"], nm(420)));
    d.rule(
        "M2Fil.c",
        min_spacing_diff(l["metal2_filler"], l["metal2"], nm(420)),
    );
    d.rule(
        "M2Fil.d",
        min_spacing_diff(l["metal2_filler"], l["trans"], nm(1000)),
    );
    d.rule(
        "M2Fil.h",
        density(
            l["metal2_den"],
            Some(l["prboundary"].into()),
            nm(800000),
            nm(400000),
            0.25,
            false,
        ),
    );
    d.rule(
        "M2Fil.k",
        density(
            l["metal2_den"],
            Some(l["prboundary"].into()),
            nm(800000),
            nm(400000),
            0.75,
            true,
        ),
    );
    d.rule("M3Fil.a1", min_width(l["metal3_filler"], nm(1000)));
    d.rule("M3Fil.a2", max_width(l["metal3_filler"], nm(5000)));
    d.rule("M3Fil.b", min_spacing(l["metal3_filler"], nm(420)));
    d.rule(
        "M3Fil.c",
        min_spacing_diff(l["metal3_filler"], l["metal3"], nm(420)),
    );
    d.rule(
        "M3Fil.d",
        min_spacing_diff(l["metal3_filler"], l["trans"], nm(1000)),
    );
    d.rule(
        "M3Fil.h",
        density(
            l["metal3_den"],
            Some(l["prboundary"].into()),
            nm(800000),
            nm(400000),
            0.25,
            false,
        ),
    );
    d.rule(
        "M3Fil.k",
        density(
            l["metal3_den"],
            Some(l["prboundary"].into()),
            nm(800000),
            nm(400000),
            0.75,
            true,
        ),
    );
    d.rule("M4Fil.a1", min_width(l["metal4_filler"], nm(1000)));
    d.rule("M4Fil.a2", max_width(l["metal4_filler"], nm(5000)));
    d.rule("M4Fil.b", min_spacing(l["metal4_filler"], nm(420)));
    d.rule(
        "M4Fil.c",
        min_spacing_diff(l["metal4_filler"], l["metal4"], nm(420)),
    );
    d.rule(
        "M4Fil.d",
        min_spacing_diff(l["metal4_filler"], l["trans"], nm(1000)),
    );
    d.rule(
        "M4Fil.h",
        density(
            l["metal4_den"],
            Some(l["prboundary"].into()),
            nm(800000),
            nm(400000),
            0.25,
            false,
        ),
    );
    d.rule(
        "M4Fil.k",
        density(
            l["metal4_den"],
            Some(l["prboundary"].into()),
            nm(800000),
            nm(400000),
            0.75,
            true,
        ),
    );
    d.rule("M5Fil.a1", min_width(l["metal5_filler"], nm(1000)));
    d.rule("M5Fil.a2", max_width(l["metal5_filler"], nm(5000)));
    d.rule("M5Fil.b", min_spacing(l["metal5_filler"], nm(420)));
    d.rule(
        "M5Fil.c",
        min_spacing_diff(l["metal5_filler"], l["metal5"], nm(420)),
    );
    d.rule(
        "M5Fil.d",
        min_spacing_diff(l["metal5_filler"], l["trans"], nm(1000)),
    );
    d.rule(
        "M5Fil.h",
        density(
            l["metal5_den"],
            Some(l["prboundary"].into()),
            nm(800000),
            nm(400000),
            0.25,
            false,
        ),
    );
    d.rule(
        "M5Fil.k",
        density(
            l["metal5_den"],
            Some(l["prboundary"].into()),
            nm(800000),
            nm(400000),
            0.75,
            true,
        ),
    );
    d.rule("V1.a", cut_size(l["via1"], nm(190), nm(190)));
    d.rule("V1.b", min_spacing(l["via1"], nm(220)));
    d.rule("V1.b1", via_array_spacing(l["via1"], 15, nm(290)));
    d.rule("V1.c", min_enclosure(l["via1"], l["metal1"], nm(10)));
    d.rule(
        "V1.c1",
        asymmetric_enclosure(l["via1"], l["metal1"], nm(50)),
    );
    d.rule("V2.a", cut_size(l["via2"], nm(190), nm(190)));
    d.rule("V2.b", min_spacing(l["via2"], nm(220)));
    d.rule("V2.b1", via_array_spacing(l["via2"], 15, nm(290)));
    d.rule("V2.c", min_enclosure(l["via2"], l["metal2"], nm(5)));
    d.rule(
        "V2.c1",
        asymmetric_enclosure(l["via2"], l["metal2"], nm(50)),
    );
    d.rule("V3.a", cut_size(l["via3"], nm(190), nm(190)));
    d.rule("V3.b", min_spacing(l["via3"], nm(220)));
    d.rule("V3.b1", via_array_spacing(l["via3"], 15, nm(290)));
    d.rule("V3.c", min_enclosure(l["via3"], l["metal3"], nm(5)));
    d.rule(
        "V3.c1",
        asymmetric_enclosure(l["via3"], l["metal3"], nm(50)),
    );
    d.rule("V4.a", cut_size(l["via4"], nm(190), nm(190)));
    d.rule("V4.b", min_spacing(l["via4"], nm(220)));
    d.rule("V4.b1", via_array_spacing(l["via4"], 15, nm(290)));
    d.rule("V4.c", min_enclosure(l["via4"], l["metal4"], nm(5)));
    d.rule(
        "V4.c1",
        asymmetric_enclosure(l["via4"], l["metal4"], nm(50)),
    );
    d.rule("TV1.a", cut_size(l["topvia1"], nm(420), nm(420)));
    d.rule("TV1.b", min_spacing(l["topvia1"], nm(420)));
    d.rule("TV1.c", min_enclosure(l["topvia1"], l["metal5"], nm(100)));
    d.rule(
        "TV1.d",
        min_enclosure(l["topvia1"], l["topmetal1"], nm(420)),
    );
    d.rule("TM1.a", min_width(l["topmetal1"], nm(1640)));
    d.rule("TM1.b", min_spacing(l["topmetal1"], nm(1640)));
    d.rule("TM1.b.notch", notch(l["topmetal1"], nm(1640)));
    d.rule(
        "TM1.c",
        global_density(
            l["topmetal1_den"],
            Some(l["prboundary"].into()),
            0.25,
            false,
        ),
    );
    d.rule(
        "TM1.d",
        global_density(l["topmetal1_den"], Some(l["prboundary"].into()), 0.70, true),
    );
    d.rule("TV2.a", cut_size(l["topvia2"], nm(900), nm(900)));
    d.rule("TV2.b", min_spacing(l["topvia2"], nm(1060)));
    d.rule(
        "TV2.c",
        min_enclosure(l["topvia2"], l["topmetal1"], nm(500)),
    );
    d.rule(
        "TV2.d",
        min_enclosure(l["topvia2"], l["topmetal2"], nm(500)),
    );
    d.rule("TM2.a", min_width(l["topmetal2"], nm(2000)));
    d.rule("TM2.b", min_spacing(l["topmetal2"], nm(2000)));
    d.rule("TM2.b.notch", notch(l["topmetal2"], nm(2000)));
    d.rule(
        "TM2.c",
        global_density(
            l["topmetal2_den"],
            Some(l["prboundary"].into()),
            0.25,
            false,
        ),
    );
    d.rule(
        "TM2.d",
        global_density(l["topmetal2_den"], Some(l["prboundary"].into()), 0.70, true),
    );
    d.rule("TM1Fil.a", min_width(l["topmetal1_filler"], nm(5000)));
    d.rule("TM1Fil.a1", max_width(l["topmetal1_filler"], nm(10000)));
    d.rule("TM1Fil.b", min_spacing(l["topmetal1_filler"], nm(3000)));
    d.rule(
        "TM1Fil.c",
        min_spacing_diff(l["topmetal1_filler"], l["topmetal1"], nm(3000)),
    );
    d.rule(
        "TM1Fil.d",
        min_spacing_diff(l["topmetal1_filler"], l["trans"], nm(4900)),
    );
    d.rule("TM2Fil.a", min_width(l["topmetal2_filler"], nm(5000)));
    d.rule("TM2Fil.a1", max_width(l["topmetal2_filler"], nm(10000)));
    d.rule("TM2Fil.b", min_spacing(l["topmetal2_filler"], nm(3000)));
    d.rule(
        "TM2Fil.c",
        min_spacing_diff(l["topmetal2_filler"], l["topmetal2"], nm(3000)),
    );
    d.rule(
        "TM2Fil.d",
        min_spacing_diff(l["topmetal2_filler"], l["trans"], nm(4900)),
    );
    d.rule("Pas.a", min_width(l["passiv"], nm(2100)));
    d.rule("Pas.b", min_spacing(l["passiv"], nm(3500)));
    d.rule("Pas.b.notch", notch(l["passiv"], nm(3500)));
    d.rule(
        "Pas.c",
        min_enclosure(l["passiv"], l["topmetal2"], nm(2100)),
    );
    d.rule("Rsil.a", min_width(l["rsil_body"], nm(500)));
    d.rule("Rsil.b", min_spacing_diff(l["res"], l["cont"], nm(120)));
    d.rule(
        "Rsil.d",
        min_spacing_diff(l["psd"], l["rsil_poly"], nm(180)),
    );
    d.rule(
        "Rsil.e",
        min_enclosure(l["rsil_poly"], l["extblock"], nm(180)),
    );
    d.rule("Rsil.f", min_width(l["res"], nm(500)));
    d.rule("Rppd.a", min_width(l["rppd_body"], nm(500)));
    d.rule("Rppd.b", min_enclosure(l["rppd_poly"], l["psd"], nm(180)));
    d.rule(
        "Rppd.c",
        min_spacing_diff(l["sal_rppd"], l["cont"], nm(200)),
    );
    d.rule(
        "Rppd.d",
        min_enclosure(l["rppd_poly"], l["extblock"], nm(180)),
    );
    d.rule("Rppd.e", min_width(l["sal_rppd"], nm(500)));
    d.rule("Rhi.a", min_width(l["rhigh_body"], nm(500)));
    d.rule(
        "Rhi.c.pSD",
        min_enclosure(l["rhigh_poly"], l["psd"], nm(180)),
    );
    d.rule(
        "Rhi.c.nSD",
        min_enclosure(l["rhigh_poly"], l["nsd"], nm(180)),
    );
    d.rule(
        "Rhi.d",
        min_spacing_diff(l["sal_rhigh"], l["cont"], nm(200)),
    );
    d.rule(
        "Rhi.e",
        min_enclosure(l["rhigh_poly"], l["extblock"], nm(180)),
    );
    d.rule("Rhi.f", min_width(l["sal_rhigh"], nm(500)));
    d.rule(
        "nmosi.b",
        min_enclosure(l["iso_pwell_activ"], l["nbl"], nm(1240)),
    );
    d.rule(
        "nmosi.c",
        min_spacing_diff(l["nwell"], l["iso_pwell_activ"], nm(390)),
    );
    d.rule("nmosi.f", min_width(l["nsdb_iso"], nm(620)));
    d.rule("Pad.a1", max_width(l["pad"], nm(150000)));
    d.rule("Pad.d", min_spacing_diff(l["pad"], l["edgeseal"], nm(7500)));
    l.insert(
        "activ_chip",
        d.derived("activ_chip", l["activ"].not(l["edgeseal"])),
    );
    l.insert(
        "es_activ",
        d.derived("es_activ", l["activ"].and(l["edgeseal"])),
    );
    l.insert("es_psd", d.derived("es_psd", l["psd"].and(l["edgeseal"])));
    l.insert(
        "es_metal1",
        d.derived("es_metal1", l["metal1"].and(l["edgeseal"])),
    );
    l.insert(
        "es_metal2",
        d.derived("es_metal2", l["metal2"].and(l["edgeseal"])),
    );
    l.insert(
        "es_metal3",
        d.derived("es_metal3", l["metal3"].and(l["edgeseal"])),
    );
    l.insert(
        "es_metal4",
        d.derived("es_metal4", l["metal4"].and(l["edgeseal"])),
    );
    l.insert(
        "es_metal5",
        d.derived("es_metal5", l["metal5"].and(l["edgeseal"])),
    );
    l.insert(
        "es_topmetal1",
        d.derived("es_topmetal1", l["topmetal1"].and(l["edgeseal"])),
    );
    l.insert(
        "es_topmetal2",
        d.derived("es_topmetal2", l["topmetal2"].and(l["edgeseal"])),
    );
    l.insert(
        "es_cont",
        d.derived("es_cont", l["cont"].and(l["edgeseal"])),
    );
    l.insert(
        "es_via1",
        d.derived("es_via1", l["via1"].and(l["edgeseal"])),
    );
    l.insert(
        "es_via2",
        d.derived("es_via2", l["via2"].and(l["edgeseal"])),
    );
    l.insert(
        "es_via3",
        d.derived("es_via3", l["via3"].and(l["edgeseal"])),
    );
    l.insert(
        "es_via4",
        d.derived("es_via4", l["via4"].and(l["edgeseal"])),
    );
    l.insert(
        "es_topvia1",
        d.derived("es_topvia1", l["topvia1"].and(l["edgeseal"])),
    );
    l.insert(
        "es_topvia2",
        d.derived("es_topvia2", l["topvia2"].and(l["edgeseal"])),
    );
    d.rule("Seal.a_Activ", min_width(l["es_activ"], nm(3500)));
    d.rule(
        "Seal.b_Activ",
        min_spacing_diff(l["activ_chip"], l["es_activ"], nm(4900)),
    );
    d.rule("Seal.a_pSD", min_width(l["es_psd"], nm(3500)));
    d.rule(
        "Seal.b_pSD",
        min_spacing_diff(l["activ_chip"], l["es_psd"], nm(4900)),
    );
    d.rule("Seal.a_Metal1", min_width(l["es_metal1"], nm(3500)));
    d.rule(
        "Seal.b_Metal1",
        min_spacing_diff(l["activ_chip"], l["es_metal1"], nm(4900)),
    );
    d.rule("Seal.a_Metal2", min_width(l["es_metal2"], nm(3500)));
    d.rule(
        "Seal.b_Metal2",
        min_spacing_diff(l["activ_chip"], l["es_metal2"], nm(4900)),
    );
    d.rule("Seal.a_Metal3", min_width(l["es_metal3"], nm(3500)));
    d.rule(
        "Seal.b_Metal3",
        min_spacing_diff(l["activ_chip"], l["es_metal3"], nm(4900)),
    );
    d.rule("Seal.a_Metal4", min_width(l["es_metal4"], nm(3500)));
    d.rule(
        "Seal.b_Metal4",
        min_spacing_diff(l["activ_chip"], l["es_metal4"], nm(4900)),
    );
    d.rule("Seal.a_Metal5", min_width(l["es_metal5"], nm(3500)));
    d.rule(
        "Seal.b_Metal5",
        min_spacing_diff(l["activ_chip"], l["es_metal5"], nm(4900)),
    );
    d.rule("Seal.a_TopMetal1", min_width(l["es_topmetal1"], nm(3500)));
    d.rule(
        "Seal.b_TopMetal1",
        min_spacing_diff(l["activ_chip"], l["es_topmetal1"], nm(4900)),
    );
    d.rule("Seal.a_TopMetal2", min_width(l["es_topmetal2"], nm(3500)));
    d.rule(
        "Seal.b_TopMetal2",
        min_spacing_diff(l["activ_chip"], l["es_topmetal2"], nm(4900)),
    );
    d.rule("Seal.c.Cont", min_width(l["es_cont"], nm(160)));
    d.rule("Seal.c.Cont.max", max_width(l["es_cont"], nm(160)));
    d.rule(
        "Seal.d.Cont",
        min_enclosure(l["es_cont"], l["es_activ"], nm(1300)),
    );
    d.rule("Seal.c.Via1", min_width(l["es_via1"], nm(190)));
    d.rule("Seal.c.Via1.max", max_width(l["es_via1"], nm(190)));
    d.rule(
        "Seal.d.Via1",
        min_enclosure(l["es_via1"], l["es_activ"], nm(1300)),
    );
    d.rule("Seal.c.Via2", min_width(l["es_via2"], nm(190)));
    d.rule("Seal.c.Via2.max", max_width(l["es_via2"], nm(190)));
    d.rule(
        "Seal.d.Via2",
        min_enclosure(l["es_via2"], l["es_activ"], nm(1300)),
    );
    d.rule("Seal.c.Via3", min_width(l["es_via3"], nm(190)));
    d.rule("Seal.c.Via3.max", max_width(l["es_via3"], nm(190)));
    d.rule(
        "Seal.d.Via3",
        min_enclosure(l["es_via3"], l["es_activ"], nm(1300)),
    );
    d.rule("Seal.c.Via4", min_width(l["es_via4"], nm(190)));
    d.rule("Seal.c.Via4.max", max_width(l["es_via4"], nm(190)));
    d.rule(
        "Seal.d.Via4",
        min_enclosure(l["es_via4"], l["es_activ"], nm(1300)),
    );
    d.rule("Seal.c.TopVia1", min_width(l["es_topvia1"], nm(420)));
    d.rule("Seal.c.TopVia1.max", max_width(l["es_topvia1"], nm(420)));
    d.rule(
        "Seal.d.TopVia1",
        min_enclosure(l["es_topvia1"], l["es_activ"], nm(1300)),
    );
    d.rule("Seal.c.TopVia2", min_width(l["es_topvia2"], nm(900)));
    d.rule("Seal.c.TopVia2.max", max_width(l["es_topvia2"], nm(900)));
    d.rule(
        "Seal.d.TopVia2",
        min_enclosure(l["es_topvia2"], l["es_activ"], nm(1300)),
    );
    d.rule("MIM.a", min_width(l["mim"], nm(1140)));
    d.rule("MIM.b", min_spacing(l["mim"], nm(600)));
    d.rule("MIM.c", min_enclosure(l["mim"], l["metal5"], nm(600)));
    d.rule("MIM.d", min_enclosure(l["topvia1_mim"], l["mim"], nm(360)));
    d.rule(
        "MIM.e",
        min_spacing_diff(l["topmetal1_unrel_mim"], l["mim"], nm(600)),
    );
    d.rule("MIM.f", min_area(l["mim"], nm2(1300000)));
    d.rule("Slt.a.M1", min_width(l["metal1_slit"], nm(2800)));
    d.rule("Slt.b.M1", max_width(l["metal1_slit"], nm(20000)));
    d.rule("Slt.c.M1", max_width(l["metal1_wide"], nm(30000)));
    d.rule(
        "Slt.f.M1",
        min_enclosure(l["metal1_slit"], l["metal1"], nm(1000)),
    );
    d.rule("Slt.a.M2", min_width(l["metal2_slit"], nm(2800)));
    d.rule("Slt.b.M2", max_width(l["metal2_slit"], nm(20000)));
    d.rule("Slt.c.M2", max_width(l["metal2_wide"], nm(30000)));
    d.rule(
        "Slt.f.M2",
        min_enclosure(l["metal2_slit"], l["metal2"], nm(1000)),
    );
    d.rule("Slt.a.M3", min_width(l["metal3_slit"], nm(2800)));
    d.rule("Slt.b.M3", max_width(l["metal3_slit"], nm(20000)));
    d.rule("Slt.c.M3", max_width(l["metal3_wide"], nm(30000)));
    d.rule(
        "Slt.f.M3",
        min_enclosure(l["metal3_slit"], l["metal3"], nm(1000)),
    );
    d.rule("Slt.a.M4", min_width(l["metal4_slit"], nm(2800)));
    d.rule("Slt.b.M4", max_width(l["metal4_slit"], nm(20000)));
    d.rule("Slt.c.M4", max_width(l["metal4_wide"], nm(30000)));
    d.rule(
        "Slt.f.M4",
        min_enclosure(l["metal4_slit"], l["metal4"], nm(1000)),
    );
    d.rule("Slt.a.M5", min_width(l["metal5_slit"], nm(2800)));
    d.rule("Slt.b.M5", max_width(l["metal5_slit"], nm(20000)));
    d.rule("Slt.c.M5", max_width(l["metal5_wide"], nm(30000)));
    d.rule(
        "Slt.f.M5",
        min_enclosure(l["metal5_slit"], l["metal5"], nm(1000)),
    );
    d.rule("Slt.a.TM1", min_width(l["topmetal1_slit"], nm(2800)));
    d.rule("Slt.b.TM1", max_width(l["topmetal1_slit"], nm(20000)));
    d.rule("Slt.c.TM1", max_width(l["topmetal1_wide"], nm(30000)));
    d.rule(
        "Slt.f.TM1",
        min_enclosure(l["topmetal1_slit"], l["topmetal1"], nm(1000)),
    );
    d.rule("Slt.a.TM2", min_width(l["topmetal2_slit"], nm(2800)));
    d.rule("Slt.b.TM2", max_width(l["topmetal2_slit"], nm(20000)));
    d.rule("Slt.c.TM2", max_width(l["topmetal2_wide"], nm(30000)));
    d.rule(
        "Slt.f.TM2",
        min_enclosure(l["topmetal2_slit"], l["topmetal2"], nm(1000)),
    );
    d.rule(
        "Slt.g.M5",
        min_spacing_diff(l["metal5_slit"], l["mim"], nm(600)),
    );
    d.rule(
        "Slt.g.TM1",
        min_spacing_diff(l["topmetal1_slit"], l["mim"], nm(600)),
    );
    d.rule(
        "Slt.h1.Cont",
        min_spacing_diff(l["metal1_slit"], l["cont"], nm(300)),
    );
    d.rule(
        "Slt.h1.Via1",
        min_spacing_diff(l["metal1_slit"], l["via1"], nm(300)),
    );
    d.rule(
        "Slt.h2.M2.below",
        min_spacing_diff(l["metal2_slit"], l["via1"], nm(300)),
    );
    d.rule(
        "Slt.h2.M2.above",
        min_spacing_diff(l["metal2_slit"], l["via2"], nm(300)),
    );
    d.rule(
        "Slt.h2.M3.below",
        min_spacing_diff(l["metal3_slit"], l["via2"], nm(300)),
    );
    d.rule(
        "Slt.h2.M3.above",
        min_spacing_diff(l["metal3_slit"], l["via3"], nm(300)),
    );
    d.rule(
        "Slt.h2.M4.below",
        min_spacing_diff(l["metal4_slit"], l["via3"], nm(300)),
    );
    d.rule(
        "Slt.h2.M4.above",
        min_spacing_diff(l["metal4_slit"], l["via4"], nm(300)),
    );
    d.rule(
        "Slt.h2.M5.below",
        min_spacing_diff(l["metal5_slit"], l["via4"], nm(300)),
    );
    d.rule(
        "Slt.h2.M5.above",
        min_spacing_diff(l["metal5_slit"], l["topvia1"], nm(300)),
    );
    d.rule(
        "Slt.h3.TopVia1",
        min_spacing_diff(l["topmetal1_slit"], l["topvia1"], nm(1000)),
    );
    d.rule(
        "Slt.h3.TopVia2",
        min_spacing_diff(l["topmetal1_slit"], l["topvia2"], nm(1000)),
    );
    d.rule(
        "Slt.h4",
        min_spacing_diff(l["topmetal2_slit"], l["topvia2"], nm(1000)),
    );
    d.rule("LBE.a", min_width(l["lbe"], nm(100000)));
    d.rule("LBE.b", max_width(l["lbe"], nm(1500000)));
    d.rule("LBE.b2", min_area(l["lbe"], nm2(30000000000)));
    d.rule("LBE.c", min_spacing(l["lbe"], nm(100000)));
    d.rule("LBE.c.notch", notch(l["lbe"], nm(100000)));
    d.rule(
        "LBE.e.dfPad",
        min_spacing_diff(l["lbe"], l["dfpad"], nm(50000)),
    );
    d.rule(
        "LBE.e.Passiv",
        min_spacing_diff(l["lbe"], l["passiv"], nm(50000)),
    );
    d.rule("LBE.f", min_spacing_diff(l["lbe"], l["activ"], nm(30000)));
    d.rule(
        "LBE.i",
        global_density(l["lbe"], Some(l["prboundary"].into()), 0.20, true),
    );
    d.rule("OffGrid", off_grid(nm(5)));
    d.rule("Angle", angle(None, &[0, 45, 90, 135]));
    d.rule("Angle.Cont", angle(Some(l["cont"].into()), &[0, 90]));
    d.rule("Angle.Via1", angle(Some(l["via1"].into()), &[0, 90]));
    d.rule("Angle.Via2", angle(Some(l["via2"].into()), &[0, 90]));
    d.rule("Angle.Via3", angle(Some(l["via3"].into()), &[0, 90]));
    d.rule("Angle.Via4", angle(Some(l["via4"].into()), &[0, 90]));
    d.rule("Angle.TopVia1", angle(Some(l["topvia1"].into()), &[0, 90]));
    d.rule("Angle.TopVia2", angle(Some(l["topvia2"].into()), &[0, 90]));
    d.rule(
        "Ant.a",
        antenna(l["gate"], &[l["gatpoly_c"]], 201.0, None, None),
    );
    d.rule("Ant.c", antenna(l["gate"], &[l["cont"]], 20.0, None, None));
    d.rule(
        "Ant.b_Metal1",
        antenna(l["gate"], &[l["metal1"]], 200.0, None, None),
    );
    d.rule(
        "Ant.b_Metal2",
        antenna(l["gate"], &[l["metal1"], l["metal2"]], 200.0, None, None),
    );
    d.rule(
        "Ant.b_Metal3",
        antenna(
            l["gate"],
            &[l["metal1"], l["metal2"], l["metal3"]],
            200.0,
            None,
            None,
        ),
    );
    d.rule(
        "Ant.b_Metal4",
        antenna(
            l["gate"],
            &[l["metal1"], l["metal2"], l["metal3"], l["metal4"]],
            200.0,
            None,
            None,
        ),
    );
    d.rule(
        "Ant.b_Metal5",
        antenna(
            l["gate"],
            &[
                l["metal1"],
                l["metal2"],
                l["metal3"],
                l["metal4"],
                l["metal5"],
            ],
            200.0,
            None,
            None,
        ),
    );
    d.rule(
        "Ant.b_TopMetal1",
        antenna(
            l["gate"],
            &[
                l["metal1"],
                l["metal2"],
                l["metal3"],
                l["metal4"],
                l["metal5"],
                l["topmetal1"],
            ],
            200.0,
            None,
            None,
        ),
    );
    d.rule(
        "Ant.b_TopMetal2",
        antenna(
            l["gate"],
            &[
                l["metal1"],
                l["metal2"],
                l["metal3"],
                l["metal4"],
                l["metal5"],
                l["topmetal1"],
                l["topmetal2"],
            ],
            200.0,
            None,
            None,
        ),
    );
    d.rule(
        "Ant.d_Via1",
        antenna(l["gate"], &[l["via1"]], 20.0, None, None),
    );
    d.rule(
        "Ant.d_Via2",
        antenna(l["gate"], &[l["via1"], l["via2"]], 20.0, None, None),
    );
    d.rule(
        "Ant.d_Via3",
        antenna(
            l["gate"],
            &[l["via1"], l["via2"], l["via3"]],
            20.0,
            None,
            None,
        ),
    );
    d.rule(
        "Ant.d_Via4",
        antenna(
            l["gate"],
            &[l["via1"], l["via2"], l["via3"], l["via4"]],
            20.0,
            None,
            None,
        ),
    );
    d.rule(
        "Ant.d_TopVia1",
        antenna(
            l["gate"],
            &[l["via1"], l["via2"], l["via3"], l["via4"], l["topvia1_m5"]],
            20.0,
            None,
            None,
        ),
    );
    d.rule(
        "Ant.d_TopVia2",
        antenna(
            l["gate"],
            &[
                l["via1"],
                l["via2"],
                l["via3"],
                l["via4"],
                l["topvia1_m5"],
                l["topvia2"],
            ],
            20.0,
            None,
            None,
        ),
    );
    d.rule("LU.a", missing_tie(l["pact_nw"], l["ntap"], nm(20000)));
    d.rule("LU.b", missing_tie(l["nact_pw"], l["ptap"], nm(20000)));
    d.rule("floating_nwell", floating_well(l["nwell"], l["ntap"]));
    d.rule("supply_short", supply_short(l["ntap"], l["ptap"], None));
    d.rule(
        "EM.Metal1",
        em_current_density(&[l["metal1"], l["cont"]], 1000.0, 300.0),
    );
    d.rule(
        "EM.Metal2",
        em_current_density(&[l["metal2"], l["via1"]], 2000.0, 400.0),
    );
    d.rule(
        "EM.Metal3",
        em_current_density(&[l["metal3"], l["via2"]], 2000.0, 400.0),
    );
    d.rule(
        "EM.Metal4",
        em_current_density(&[l["metal4"], l["via3"]], 2000.0, 400.0),
    );
    d.rule(
        "EM.Metal5",
        em_current_density(&[l["metal5"], l["via4"]], 2000.0, 400.0),
    );
    d.rule(
        "EM.TopMetal1",
        em_current_density(&[l["topmetal1"], l["topvia1_m5"]], 15000.0, 1400.0),
    );
    d.rule(
        "EM.TopMetal2",
        em_current_density(&[l["topmetal2"], l["topvia2"]], 16000.0, 10000.0),
    );
    d.rule(
        "GOX.lv",
        gate_oxide(&["sg13_lv_nmos", "sg13_lv_pmos"], 1200.0),
    );
    d.rule(
        "GOX.hv",
        gate_oxide(&["sg13_hv_nmos", "sg13_hv_pmos"], 3300.0),
    );
    d.rule(
        "VDS.lv",
        drain_source(&["sg13_lv_nmos", "sg13_lv_pmos"], 1200.0),
    );
    d.rule(
        "VDS.hv",
        drain_source(&["sg13_hv_nmos", "sg13_hv_pmos"], 3300.0),
    );
    d.rule(
        "ESD.pad",
        esd_topological(
            l["dfpad"],
            &["diodevdd_2kv", "diodevss_2kv", "nmoscl_2", "nmoscl_4"],
        ),
    );
    d.rule("floating_gate", floating_gate(false));
    d.rule("tie_high_low", tie_high_low().warning());
    d.rule("multiple_drivers", multiple_drivers(1));
    d.rule("ir_drop", ir_drop());
    d.rule(
        "unconnected_conductor",
        unconnected_pin(&[
            l["gatpoly_c"],
            l["metal1"],
            l["metal2"],
            l["metal3"],
            l["metal4"],
            l["metal5"],
            l["topmetal1"],
            l["topmetal2"],
        ]),
    );
    d.conductors(&[
        l["nsd_c"],
        l["psd_c"],
        l["ntap"],
        l["ptap"],
        l["gatpoly_c"],
        l["metal1"],
        l["metal2"],
        l["metal3"],
        l["metal4"],
        l["metal5"],
        l["topmetal1"],
        l["topmetal2"],
    ]);
    d.touch_within_layer();
    d.via(l["cont"], (l["nsd_c"], l["metal1"]));
    d.via(l["cont"], (l["psd_c"], l["metal1"]));
    d.via(l["cont"], (l["ntap"], l["metal1"]));
    d.via(l["cont"], (l["ptap"], l["metal1"]));
    d.via(l["cont"], (l["gatpoly_c"], l["metal1"]));
    d.via(l["via1"], (l["metal1"], l["metal2"]));
    d.via(l["via2"], (l["metal2"], l["metal3"]));
    d.via(l["via3"], (l["metal3"], l["metal4"]));
    d.via(l["via4"], (l["metal4"], l["metal5"]));
    d.via(l["topvia1_m5"], (l["metal5"], l["topmetal1"]));
    d.via(l["topvia2"], (l["topmetal1"], l["topmetal2"]));
    d.label(l["metal1_label"], l["metal1"]);
    d.label(l["metal2_label"], l["metal2"]);
    d.label(l["metal3_label"], l["metal3"]);
    d.label(l["metal4_label"], l["metal4"]);
    d.label(l["metal5_label"], l["metal5"]);
    d.label(l["topmetal1_label"], l["topmetal1"]);
    d.label(l["topmetal2_label"], l["topmetal2"]);
    d.device(
        DeviceKind::Mos,
        l["ngate_lv"],
        "sg13_lv_nmos",
        &[l["gatpoly_c"], l["nsd_c"], l["nsd_c"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Mos,
        l["ngate_hv"],
        "sg13_hv_nmos",
        &[l["gatpoly_c"], l["nsd_c"], l["nsd_c"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Mos,
        l["pgate_lv"],
        "sg13_lv_pmos",
        &[l["gatpoly_c"], l["psd_c"], l["psd_c"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Mos,
        l["pgate_hv"],
        "sg13_hv_pmos",
        &[l["gatpoly_c"], l["psd_c"], l["psd_c"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Resistor,
        l["rsil_body"],
        "rsil",
        &[l["gatpoly_c"], l["gatpoly_c"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Resistor,
        l["rppd_body"],
        "rppd",
        &[l["gatpoly_c"], l["gatpoly_c"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Resistor,
        l["rhigh_body"],
        "rhigh",
        &[l["gatpoly_c"], l["gatpoly_c"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Capacitor,
        l["mim"],
        "cap_cmim",
        &[l["topmetal1"], l["metal5"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Bjt,
        l["esd_vdd"],
        "diodevdd_2kv",
        &[l["ntap"], l["psd_c"], l["ptap"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Bjt,
        l["esd_vss"],
        "diodevss_2kv",
        &[l["ptap"], l["nsd_c"], l["ntap"]],
        DeviceValue::default(),
    );
    d.pex(
        l["nsd_c"],
        StackSource {
            thickness_nm: 400.0,
            height_nm: 0.0,
            sheet_res_ohm_sq: 1.0,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 3.95,
            tc: None,
        },
    );
    d.pex(
        l["psd_c"],
        StackSource {
            thickness_nm: 400.0,
            height_nm: 0.0,
            sheet_res_ohm_sq: 1.0,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 3.95,
            tc: None,
        },
    );
    d.pex(
        l["ntap"],
        StackSource {
            thickness_nm: 400.0,
            height_nm: 0.0,
            sheet_res_ohm_sq: 1.0,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 3.95,
            tc: None,
        },
    );
    d.pex(
        l["ptap"],
        StackSource {
            thickness_nm: 400.0,
            height_nm: 0.0,
            sheet_res_ohm_sq: 1.0,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 3.95,
            tc: None,
        },
    );
    d.pex(
        l["gatpoly_c"],
        StackSource {
            thickness_nm: 160.0,
            height_nm: 400.0,
            sheet_res_ohm_sq: 7.0,
            area_cap_af_um2: 87.43,
            fringe_cap_af_um: 0.0,
            dielectric_k: 4.1,
            tc: None,
        },
    );
    d.pex(
        l["cont"],
        StackSource {
            thickness_nm: 640.0,
            height_nm: 400.0,
            sheet_res_ohm_sq: 17.0,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 4.1,
            tc: None,
        },
    );
    d.pex(
        l["metal1"],
        StackSource {
            thickness_nm: 420.0,
            height_nm: 1040.0,
            sheet_res_ohm_sq: 0.11,
            area_cap_af_um2: 37.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 4.1,
            tc: None,
        },
    );
    d.pex(
        l["via1"],
        StackSource {
            thickness_nm: 540.0,
            height_nm: 1460.0,
            sheet_res_ohm_sq: 9.0,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 4.1,
            tc: None,
        },
    );
    d.pex(
        l["metal2"],
        StackSource {
            thickness_nm: 490.0,
            height_nm: 2000.0,
            sheet_res_ohm_sq: 0.088,
            area_cap_af_um2: 18.15,
            fringe_cap_af_um: 0.0,
            dielectric_k: 4.1,
            tc: None,
        },
    );
    d.pex(
        l["via2"],
        StackSource {
            thickness_nm: 540.0,
            height_nm: 2490.0,
            sheet_res_ohm_sq: 9.0,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 4.1,
            tc: None,
        },
    );
    d.pex(
        l["metal3"],
        StackSource {
            thickness_nm: 490.0,
            height_nm: 3030.0,
            sheet_res_ohm_sq: 0.088,
            area_cap_af_um2: 11.98,
            fringe_cap_af_um: 0.0,
            dielectric_k: 4.1,
            tc: None,
        },
    );
    d.pex(
        l["via3"],
        StackSource {
            thickness_nm: 540.0,
            height_nm: 3520.0,
            sheet_res_ohm_sq: 9.0,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 4.1,
            tc: None,
        },
    );
    d.pex(
        l["metal4"],
        StackSource {
            thickness_nm: 490.0,
            height_nm: 4060.0,
            sheet_res_ohm_sq: 0.088,
            area_cap_af_um2: 8.94,
            fringe_cap_af_um: 0.0,
            dielectric_k: 4.1,
            tc: None,
        },
    );
    d.pex(
        l["via4"],
        StackSource {
            thickness_nm: 540.0,
            height_nm: 4550.0,
            sheet_res_ohm_sq: 9.0,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 4.1,
            tc: None,
        },
    );
    d.pex(
        l["metal5"],
        StackSource {
            thickness_nm: 490.0,
            height_nm: 5090.0,
            sheet_res_ohm_sq: 0.088,
            area_cap_af_um2: 7.13,
            fringe_cap_af_um: 0.0,
            dielectric_k: 4.1,
            tc: None,
        },
    );
    d.pex(
        l["topvia1_m5"],
        StackSource {
            thickness_nm: 850.0,
            height_nm: 5580.0,
            sheet_res_ohm_sq: 2.2,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 4.1,
            tc: None,
        },
    );
    d.pex(
        l["topmetal1"],
        StackSource {
            thickness_nm: 2000.0,
            height_nm: 6430.0,
            sheet_res_ohm_sq: 0.018,
            area_cap_af_um2: 5.65,
            fringe_cap_af_um: 0.0,
            dielectric_k: 4.1,
            tc: None,
        },
    );
    d.pex(
        l["topvia2"],
        StackSource {
            thickness_nm: 2800.0,
            height_nm: 8430.0,
            sheet_res_ohm_sq: 1.1,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 4.1,
            tc: None,
        },
    );
    d.pex(
        l["topmetal2"],
        StackSource {
            thickness_nm: 3000.0,
            height_nm: 11230.0,
            sheet_res_ohm_sq: 0.011,
            area_cap_af_um2: 3.23,
            fringe_cap_af_um: 0.0,
            dielectric_k: 4.1,
            tc: None,
        },
    );
    d.rule(
        "M1.e",
        spacing_table(
            l["metal1"],
            &[nm(0), nm(1000)],
            &[nm(0), nm(300)],
            &[nm(180), nm(180), nm(180), nm(220)],
        ),
    );
    d.rule(
        "M1.f",
        spacing_table(
            l["metal1"],
            &[nm(0), nm(10000)],
            &[nm(0), nm(10000)],
            &[nm(180), nm(180), nm(180), nm(600)],
        ),
    );
    d.rule(
        "M2.e",
        spacing_table(
            l["metal2"],
            &[nm(0), nm(1000)],
            &[nm(0), nm(390)],
            &[nm(210), nm(210), nm(210), nm(240)],
        ),
    );
    d.rule(
        "M2.f",
        spacing_table(
            l["metal2"],
            &[nm(0), nm(10000)],
            &[nm(0), nm(10000)],
            &[nm(210), nm(210), nm(210), nm(600)],
        ),
    );
    d.rule(
        "M3.e",
        spacing_table(
            l["metal3"],
            &[nm(0), nm(1000)],
            &[nm(0), nm(390)],
            &[nm(210), nm(210), nm(210), nm(240)],
        ),
    );
    d.rule(
        "M3.f",
        spacing_table(
            l["metal3"],
            &[nm(0), nm(10000)],
            &[nm(0), nm(10000)],
            &[nm(210), nm(210), nm(210), nm(600)],
        ),
    );
    d.rule(
        "M4.e",
        spacing_table(
            l["metal4"],
            &[nm(0), nm(1000)],
            &[nm(0), nm(390)],
            &[nm(210), nm(210), nm(210), nm(240)],
        ),
    );
    d.rule(
        "M4.f",
        spacing_table(
            l["metal4"],
            &[nm(0), nm(10000)],
            &[nm(0), nm(10000)],
            &[nm(210), nm(210), nm(210), nm(600)],
        ),
    );
    d.rule(
        "M5.e",
        spacing_table(
            l["metal5"],
            &[nm(0), nm(1000)],
            &[nm(0), nm(390)],
            &[nm(210), nm(210), nm(210), nm(240)],
        ),
    );
    d.rule(
        "M5.f",
        spacing_table(
            l["metal5"],
            &[nm(0), nm(10000)],
            &[nm(0), nm(10000)],
            &[nm(210), nm(210), nm(210), nm(600)],
        ),
    );
    l.insert("biwind", d.layer("biwind", (3, 0)));
    l.insert("pemwind", d.layer("pemwind", (11, 0)));
    l.insert("baspoly", d.layer("baspoly", (13, 0)));
    l.insert("deepco", d.layer("deepco", (35, 0)));
    l.insert("pempoly", d.layer("pempoly", (53, 0)));
    l.insert("empoly", d.layer("empoly", (55, 0)));
    l.insert("ldmos", d.layer("ldmos", (57, 0)));
    l.insert("pbiwind", d.layer("pbiwind", (58, 0)));
    l.insert("nodrc", d.layer("nodrc", (62, 0)));
    l.insert("flash", d.layer("flash", (71, 0)));
    l.insert("colwind", d.layer("colwind", (139, 0)));
    d.rule("forbidden.BiWind", forbidden(l["biwind"]));
    d.rule("forbidden.PEmWind", forbidden(l["pemwind"]));
    d.rule("forbidden.BasPoly", forbidden(l["baspoly"]));
    d.rule("forbidden.DeepCo", forbidden(l["deepco"]));
    d.rule("forbidden.PEmPoly", forbidden(l["pempoly"]));
    d.rule("forbidden.EmPoly", forbidden(l["empoly"]));
    d.rule("forbidden.LDMOS", forbidden(l["ldmos"]));
    d.rule("forbidden.PBiWind", forbidden(l["pbiwind"]));
    d.rule("forbidden.NoDRC", forbidden(l["nodrc"]));
    d.rule("forbidden.Flash", forbidden(l["flash"]));
    d.rule("forbidden.ColWind", forbidden(l["colwind"]));
    d.rule(
        "Cnt.g",
        forbidden(l["cont"].not(l["activ"].or(l["gatpoly"]).group())),
    );
    d.rule("Cnt.h", must_be_inside(l["cont"], l["metal1"]));
    d.rule("Cnt.j", forbidden(l["cont"].and(l["gate"])));
    d.rule("nSDB.e", forbidden(l["nsd_block"].and(l["cont"])));
    d.rule(
        "MIM.h",
        forbidden(l["topvia1"].interacting(l["mim"]).not(l["mim"])),
    );
    d.rule("Pad.i", must_be_inside(l["dfpad"], l["topmetal2"]));
    l.insert("metal1_pin", d.layer("metal1_pin", (8, 2)));
    d.rule("Pin.e", must_be_inside(l["metal1_pin"], l["metal1"]));
    l.insert("text", d.layer("text", (63, 0)));
    l.insert(
        "nmoscl_2",
        d.derived("nmoscl_2", l["recog_esd"].with_text(l["text"], "nmoscl_2")),
    );
    l.insert(
        "nmoscl_4",
        d.derived("nmoscl_4", l["recog_esd"].with_text(l["text"], "nmoscl_4")),
    );
    d.device(
        DeviceKind::Diode,
        l["nmoscl_2"],
        "nmoscl_2",
        &[l["ntap"], l["ptap"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Diode,
        l["nmoscl_4"],
        "nmoscl_4",
        &[l["ntap"], l["ptap"]],
        DeviceValue::default(),
    );
    d.rule("Gat.f", forbidden(l["gate"].non_rectangles()));
    d.finish()
}
