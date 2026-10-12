//! The Rust twin of `pdks/sky130.deck`: the same deck stated with
//! [`DeckBuilder`], statement by statement, `for` loops unrolled and `let`
//! bindings substituted. Translated once from the deck text by a reader of
//! the deck language independent of the parser; the twin test holds this
//! to the parsed text. After editing the deck, edit this to match: the test
//! names the first difference.

#![allow(clippy::unreadable_literal, reason = "values as the deck writes them")]

use gpurify_check::deck::rules::{
    angle, antenna, antenna_electrical, asymmetric_enclosure, attached_wide_spacing, cut_size,
    density_cmp, drain_source, edge_enclosure, edge_min_length, edge_spacing, edge_width,
    em_current_density, esd_topological, floating_gate, floating_well, forbidden, gate_oxide,
    ir_drop, min_area, min_enclosed_area, min_enclosure, min_extension, min_spacing,
    min_spacing_diff, min_width, multiple_drivers, must_be_inside, must_contain, notch, off_grid,
    soft_connection, supply_short, tie_high_low, unconnected_pin, well_bias,
    wide_dependent_spacing,
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

/// `pdks/sky130.deck`, built on a 1 nm grid into `strings`.
#[allow(
    clippy::too_many_lines,
    reason = "a whole deck, statement by statement"
)]
pub fn build(strings: &mut StrTable) -> Result<CompiledDeck, BuildError> {
    let mut d = DeckBuilder::new(Grid::new(1000).expect("a 1 nm grid"), strings);
    let mut l: HashMap<&str, LayerRef> = HashMap::new();
    l.insert("dnwell", d.layer("dnwell", (64, 18)));
    l.insert("nwell", d.layer("nwell", (64, 20)));
    l.insert("diff", d.layer("diff", (65, 20)));
    l.insert("tap", d.layer("tap", (65, 44)));
    l.insert("diff_rs", d.layer("diff_rs", (65, 13)));
    l.insert("poly", d.layer("poly", (66, 20)));
    l.insert("poly_rs", d.layer("poly_rs", (66, 13)));
    l.insert("licon", d.layer("licon", (66, 44)));
    l.insert("li", d.layer("li", (67, 20)));
    l.insert("li_rs", d.layer("li_rs", (67, 13)));
    l.insert("mcon", d.layer("mcon", (67, 44)));
    l.insert("met1", d.layer("met1", (68, 20)));
    l.insert("via", d.layer("via", (68, 44)));
    l.insert("met2", d.layer("met2", (69, 20)));
    l.insert("via2", d.layer("via2", (69, 44)));
    l.insert("met3", d.layer("met3", (70, 20)));
    l.insert("via3", d.layer("via3", (70, 44)));
    l.insert("met4", d.layer("met4", (71, 20)));
    l.insert("via4", d.layer("via4", (71, 44)));
    l.insert("met5", d.layer("met5", (72, 20)));
    l.insert("pad", d.layer("pad", (76, 20)));
    l.insert("nsm", d.layer("nsm", (61, 20)));
    l.insert("capm", d.layer("capm", (89, 44)));
    l.insert("cap2m", d.layer("cap2m", (97, 44)));
    l.insert("hvi", d.layer("hvi", (75, 20)));
    l.insert("hvtp", d.layer("hvtp", (78, 44)));
    l.insert("hvtr", d.layer("hvtr", (18, 20)));
    l.insert("lvtn", d.layer("lvtn", (125, 44)));
    l.insert("hvntm", d.layer("hvntm", (125, 20)));
    l.insert("ncm", d.layer("ncm", (92, 44)));
    l.insert("nsdm", d.layer("nsdm", (93, 44)));
    l.insert("psdm", d.layer("psdm", (94, 20)));
    l.insert("rpm", d.layer("rpm", (86, 20)));
    l.insert("urpm", d.layer("urpm", (79, 20)));
    l.insert("npc", d.layer("npc", (95, 20)));
    l.insert("areaid_ce", d.layer("areaid_ce", (81, 2)));
    l.insert("areaid_sc", d.layer("areaid_sc", (81, 4)));
    l.insert("areaid_ed", d.layer("areaid_ed", (81, 19)));
    l.insert("areaid_diode", d.layer("areaid_diode", (81, 23)));
    l.insert("pnp", d.layer("pnp", (82, 44)));
    l.insert("tunm", d.layer("tunm", (80, 20)));
    l.insert("poly_label", d.layer("poly_label", (66, 5)));
    l.insert("li_label", d.layer("li_label", (67, 5)));
    l.insert("met1_label", d.layer("met1_label", (68, 5)));
    l.insert("met2_label", d.layer("met2_label", (69, 5)));
    l.insert("met3_label", d.layer("met3_label", (70, 5)));
    l.insert("met4_label", d.layer("met4_label", (71, 5)));
    l.insert("met5_label", d.layer("met5_label", (72, 5)));
    l.insert("li_pin", d.layer("li_pin", (67, 16)));
    l.insert("met1_pin", d.layer("met1_pin", (68, 16)));
    l.insert("met2_pin", d.layer("met2_pin", (69, 16)));
    l.insert("met3_pin", d.layer("met3_pin", (70, 16)));
    l.insert("met4_pin", d.layer("met4_pin", (71, 16)));
    l.insert("met5_pin", d.layer("met5_pin", (72, 16)));
    l.insert("nwell_label", d.layer("nwell_label", (64, 5)));
    l.insert("nwell_pin", d.layer("nwell_pin", (64, 16)));
    l.insert("pwell_label", d.layer("pwell_label", (64, 59)));
    l.insert("pwell_pin", d.layer("pwell_pin", (122, 16)));
    l.insert("pwell_drawing", d.layer("pwell_drawing", (64, 44)));
    l.insert("prBoundary", d.layer("prBoundary", (235, 4)));
    l.insert(
        "nsd",
        d.derived(
            "nsd",
            l["diff"]
                .not(l["poly"])
                .group()
                .not(l["diff_rs"])
                .group()
                .and(l["nsdm"]),
        ),
    );
    l.insert(
        "psd",
        d.derived(
            "psd",
            l["diff"]
                .not(l["poly"])
                .group()
                .not(l["diff_rs"])
                .group()
                .and(l["psdm"]),
        ),
    );
    l.insert("ntap", d.derived("ntap", l["tap"].and(l["nsdm"])));
    l.insert("ptap", d.derived("ptap", l["tap"].and(l["psdm"])));
    l.insert("poly_c", d.derived("poly_c", l["poly"].not(l["poly_rs"])));
    l.insert("li_c", d.derived("li_c", l["li"].not(l["li_rs"])));
    l.insert("licon_nd", d.derived("licon_nd", l["licon"].and(l["nsd"])));
    l.insert("licon_pd", d.derived("licon_pd", l["licon"].and(l["psd"])));
    l.insert("licon_nt", d.derived("licon_nt", l["licon"].and(l["ntap"])));
    l.insert("licon_pt", d.derived("licon_pt", l["licon"].and(l["ptap"])));
    l.insert(
        "licon_po",
        d.derived("licon_po", l["licon"].and(l["poly_c"])),
    );
    l.insert(
        "psub",
        d.derived(
            "psub",
            l["diff"]
                .or(l["tap"])
                .group()
                .not(l["nwell"])
                .group()
                .not(l["dnwell"]),
        ),
    );
    l.insert(
        "psub_tie",
        d.derived("psub_tie", l["ptap"].not(l["dnwell"])),
    );
    l.insert(
        "pwell_iso",
        d.derived("pwell_iso", l["dnwell"].not(l["nwell"])),
    );
    l.insert(
        "nwell_tie",
        d.derived("nwell_tie", l["ntap"].and(l["nwell"])),
    );
    l.insert(
        "pwell_iso_tie",
        d.derived("pwell_iso_tie", l["ptap"].and(l["pwell_iso"])),
    );
    l.insert("via3_m3", d.derived("via3_m3", l["via3"].not(l["capm"])));
    l.insert("via4_m4", d.derived("via4_m4", l["via4"].not(l["cap2m"])));
    l.insert("difftap", d.derived("difftap", l["diff"].or(l["tap"])));
    l.insert(
        "nwell_filled",
        d.derived("nwell_filled", l["nwell"].or(l["nwell"].holes())),
    );
    l.insert(
        "nwell_hole",
        d.derived("nwell_hole", l["nwell"].holes().interacting(l["dnwell"])),
    );
    l.insert("gate", d.derived("gate", l["poly"].and(l["diff"])));
    l.insert("nfet", d.derived("nfet", l["gate"].and(l["nsdm"])));
    l.insert("pfet", d.derived("pfet", l["gate"].and(l["psdm"])));
    l.insert(
        "pmos_well",
        d.derived("pmos_well", l["nwell"].interacting(l["pfet"])),
    );
    l.insert("ndiff", d.derived("ndiff", l["diff"].and(l["nsdm"])));
    l.insert("pdiff", d.derived("pdiff", l["diff"].and(l["psdm"])));
    l.insert(
        "ndifftap",
        d.derived("ndifftap", l["difftap"].and(l["nsdm"])),
    );
    l.insert(
        "pdifftap",
        d.derived("pdifftap", l["difftap"].and(l["psdm"])),
    );
    l.insert("xfom", d.derived("xfom", l["difftap"].not(l["poly"])));
    l.insert(
        "poly_licon",
        d.derived(
            "poly_licon",
            l["licon"].not_interacting(l["xfom"]).interacting(l["poly"]),
        ),
    );
    l.insert(
        "licon_dt",
        d.derived("licon_dt", l["licon"].interacting(l["difftap"])),
    );
    l.insert(
        "licon_diff",
        d.derived("licon_diff", l["licon"].interacting(l["diff"])),
    );
    l.insert(
        "iso_tap",
        d.derived("iso_tap", l["tap"].not_interacting(l["diff"])),
    );
    l.insert(
        "licon_iso_tap",
        d.derived("licon_iso_tap", l["licon"].interacting(l["iso_tap"])),
    );
    l.insert(
        "ntap_licon",
        d.derived("ntap_licon", l["ntap"].interacting(l["licon"])),
    );
    l.insert(
        "gate_sc",
        d.derived("gate_sc", l["gate"].inside(l["areaid_sc"])),
    );
    l.insert(
        "gate_nsc",
        d.derived("gate_nsc", l["gate"].outside(l["areaid_sc"])),
    );
    l.insert(
        "poly_res",
        d.derived("poly_res", l["poly"].and(l["poly_rs"])),
    );
    l.insert(
        "poly_plain",
        d.derived("poly_plain", l["poly"].not_interacting(l["poly_rs"])),
    );
    l.insert(
        "poly_field",
        d.derived("poly_field", l["poly"].not_interacting(l["diff"])),
    );
    l.insert(
        "poly_off_tap",
        d.derived("poly_off_tap", l["poly"].not_interacting(l["tap"])),
    );
    l.insert(
        "poly_out_rpm",
        d.derived("poly_out_rpm", l["poly"].outside(l["rpm"])),
    );
    l.insert(
        "prec_rpm",
        d.derived(
            "prec_rpm",
            l["rpm"]
                .and(l["psdm"])
                .group()
                .and(l["poly"].interacting(l["poly_rs"])),
        ),
    );
    l.insert(
        "prec_res",
        d.derived(
            "prec_res",
            l["rpm"]
                .or(l["urpm"])
                .group()
                .and(l["psdm"])
                .group()
                .and(l["poly"].interacting(l["poly_rs"])),
        ),
    );
    l.insert(
        "licon_prec",
        d.derived("licon_prec", l["licon"].inside(l["prec_res"])),
    );
    l.insert(
        "licon_std",
        d.derived("licon_std", l["licon"].outside(l["prec_res"])),
    );
    l.insert(
        "poly_licon_nrpm",
        d.derived(
            "poly_licon_nrpm",
            l["poly_licon"].outside(l["rpm"]).outside(l["urpm"]),
        ),
    );
    l.insert("li_res", d.derived("li_res", l["li"].and(l["li_rs"])));
    l.insert("nwell_lv", d.derived("nwell_lv", l["nwell"].not(l["hvi"])));
    l.insert(
        "tap_nwell_lv",
        d.derived("tap_nwell_lv", l["tap"].and(l["nwell_lv"])),
    );
    l.insert(
        "var_channel",
        d.derived(
            "var_channel",
            l["poly"].and(l["tap"]).group().and(l["nwell"]),
        ),
    );
    l.insert(
        "licon_var_tap",
        d.derived("licon_var_tap", l["licon"].interacting(l["tap_nwell_lv"])),
    );
    l.insert(
        "var_poly",
        d.derived("var_poly", l["poly"].interacting(l["var_channel"])),
    );
    l.insert(
        "var_hvt",
        d.derived("var_hvt", l["var_channel"].interacting(l["hvtp"])),
    );
    l.insert(
        "var_lvt",
        d.derived("var_lvt", l["var_channel"].not_interacting(l["hvtp"])),
    );
    l.insert(
        "hvt_pfet",
        d.derived("hvt_pfet", l["pfet"].interacting(l["hvtp"])),
    );
    l.insert(
        "lvt_pfet",
        d.derived("lvt_pfet", l["pfet"].not_interacting(l["hvtp"])),
    );
    l.insert(
        "hvtr_pfet",
        d.derived("hvtr_pfet", l["pfet"].interacting(l["hvtr"])),
    );
    l.insert(
        "lvtn_gate",
        d.derived("lvtn_gate", l["gate"].interacting(l["lvtn"])),
    );
    l.insert(
        "std_gate",
        d.derived("std_gate", l["gate"].not_interacting(l["lvtn"])),
    );
    l.insert(
        "lvtn_pfet",
        d.derived("lvtn_pfet", l["pfet"].interacting(l["lvtn"])),
    );
    l.insert(
        "nwell_ce",
        d.derived("nwell_ce", l["nwell"].and(l["areaid_ce"])),
    );
    l.insert(
        "ncm_pdiff",
        d.derived("ncm_pdiff", l["pdiff"].interacting(l["ncm"])),
    );
    l.insert(
        "lvtn_gate_or_diff",
        d.derived(
            "lvtn_gate_or_diff",
            l["gate"]
                .and(l["lvtn"])
                .group()
                .or(l["diff"].interacting(l["lvtn"])),
        ),
    );
    l.insert(
        "ndiff_body",
        d.derived(
            "ndiff_body",
            l["diff"].interacting(l["nsdm"]).not_interacting(l["tap"]),
        ),
    );
    l.insert(
        "pdiff_body",
        d.derived(
            "pdiff_body",
            l["diff"].interacting(l["psdm"]).not_interacting(l["tap"]),
        ),
    );
    l.insert(
        "ntap_body",
        d.derived(
            "ntap_body",
            l["tap"].interacting(l["nsdm"]).not_interacting(l["diff"]),
        ),
    );
    l.insert(
        "ptap_body",
        d.derived(
            "ptap_body",
            l["tap"].interacting(l["psdm"]).not_interacting(l["diff"]),
        ),
    );
    l.insert(
        "p_lone",
        d.derived("p_lone", l["pdifftap"].not_interacting(l["ndifftap"])),
    );
    l.insert(
        "n_lone",
        d.derived("n_lone", l["ndifftap"].not_interacting(l["pdifftap"])),
    );
    l.insert(
        "hv_nwell",
        d.derived("hv_nwell", l["nwell"].interacting(l["hvi"])),
    );
    l.insert(
        "hdiff",
        d.derived(
            "hdiff",
            l["diff"].inside(l["hvi"]).not_interacting(l["diff_rs"]),
        ),
    );
    l.insert("hndiff", d.derived("hndiff", l["ndiff"].inside(l["hvi"])));
    l.insert("hpdiff", d.derived("hpdiff", l["pdiff"].inside(l["hvi"])));
    l.insert("hntap", d.derived("hntap", l["ntap"].inside(l["hvi"])));
    l.insert(
        "iso_ptap",
        d.derived("iso_ptap", l["ptap"].not_interacting(l["diff"])),
    );
    l.insert(
        "difftap_hv",
        d.derived("difftap_hv", l["difftap"].interacting(l["hvi"])),
    );
    l.insert(
        "difftap_lv",
        d.derived("difftap_lv", l["difftap"].outside(l["hvi"])),
    );
    l.insert(
        "nwell_out_hvi",
        d.derived("nwell_out_hvi", l["nwell"].outside(l["hvi"])),
    );
    l.insert(
        "ndiff_lv",
        d.derived("ndiff_lv", l["ndiff"].outside(l["hvi"])),
    );
    l.insert(
        "hvntm_ndiff",
        d.derived("hvntm_ndiff", l["hndiff"].outside(l["areaid_ce"])),
    );
    l.insert(
        "capm_m3_free",
        d.derived("capm_m3_free", l["met3"].not_interacting(l["capm"])),
    );
    l.insert(
        "cap2m_m4_free",
        d.derived("cap2m_m4_free", l["met4"].not_interacting(l["cap2m"])),
    );
    l.insert("ngate", d.derived("ngate", l["nfet"].not(l["areaid_ed"])));
    l.insert("pgate", d.derived("pgate", l["pfet"].not(l["areaid_ed"])));
    l.insert(
        "nfet_01v8",
        d.derived("nfet_01v8", l["ngate"].not(l["hvi"]).group().not(l["lvtn"])),
    );
    l.insert(
        "nfet_01v8_lvt",
        d.derived(
            "nfet_01v8_lvt",
            l["ngate"].and(l["lvtn"]).group().not(l["hvi"]),
        ),
    );
    l.insert(
        "nfet_g5v0d10v5",
        d.derived("nfet_g5v0d10v5", l["ngate"].and(l["hvi"])),
    );
    l.insert(
        "esd_nfet_g5v0d10v5",
        d.derived(
            "esd_nfet_g5v0d10v5",
            l["nfet"].and(l["hvi"]).group().and(l["areaid_ed"]),
        ),
    );
    l.insert(
        "pfet_01v8",
        d.derived(
            "pfet_01v8",
            l["pgate"]
                .not(l["hvi"])
                .group()
                .not(l["lvtn"])
                .group()
                .not(l["hvtp"]),
        ),
    );
    l.insert(
        "pfet_01v8_lvt",
        d.derived(
            "pfet_01v8_lvt",
            l["pgate"].and(l["lvtn"]).group().not(l["hvi"]),
        ),
    );
    l.insert(
        "pfet_01v8_hvt",
        d.derived(
            "pfet_01v8_hvt",
            l["pgate"].and(l["hvtp"]).group().not(l["hvi"]),
        ),
    );
    l.insert(
        "pfet_g5v0d10v5",
        d.derived("pfet_g5v0d10v5", l["pgate"].and(l["hvi"])),
    );
    l.insert(
        "esd_pfet_g5v0d10v5",
        d.derived(
            "esd_pfet_g5v0d10v5",
            l["pfet"].and(l["hvi"]).group().and(l["areaid_ed"]),
        ),
    );
    l.insert(
        "rbody_po",
        d.derived(
            "rbody_po",
            l["poly_res"].not(l["rpm"]).group().not(l["urpm"]),
        ),
    );
    l.insert(
        "rbody_high_po",
        d.derived("rbody_high_po", l["poly_res"].and(l["rpm"])),
    );
    l.insert(
        "rbody_xhigh_po",
        d.derived("rbody_xhigh_po", l["poly_res"].and(l["urpm"])),
    );
    l.insert(
        "rbody_nd",
        d.derived(
            "rbody_nd",
            l["diff"]
                .and(l["diff_rs"])
                .group()
                .and(l["nsdm"])
                .group()
                .not(l["hvi"]),
        ),
    );
    l.insert(
        "rbody_pd",
        d.derived(
            "rbody_pd",
            l["diff"]
                .and(l["diff_rs"])
                .group()
                .and(l["psdm"])
                .group()
                .not(l["hvi"]),
        ),
    );
    l.insert(
        "rbody_nd_hv",
        d.derived(
            "rbody_nd_hv",
            l["diff"]
                .and(l["diff_rs"])
                .group()
                .and(l["nsdm"])
                .and(l["hvi"]),
        ),
    );
    l.insert(
        "rbody_pd_hv",
        d.derived(
            "rbody_pd_hv",
            l["diff"]
                .and(l["diff_rs"])
                .group()
                .and(l["psdm"])
                .and(l["hvi"]),
        ),
    );
    l.insert(
        "ndiode",
        d.derived(
            "ndiode",
            l["diff"]
                .and(l["nsdm"])
                .group()
                .and(l["areaid_diode"])
                .group()
                .not(l["poly"])
                .group()
                .not(l["psdm"])
                .group()
                .not(l["hvtp"]),
        ),
    );
    l.insert(
        "ndiode_sub",
        d.derived(
            "ndiode_sub",
            l["ndiode"]
                .not(l["nwell"])
                .group()
                .not(l["dnwell"])
                .group()
                .not_interacting(l["areaid_ed"]),
        ),
    );
    l.insert(
        "diode_pw2nd_05v5",
        d.derived(
            "diode_pw2nd_05v5",
            l["ndiode_sub"].not(l["hvi"]).group().not(l["lvtn"]),
        ),
    );
    l.insert(
        "diode_pw2nd_05v5_lvt",
        d.derived(
            "diode_pw2nd_05v5_lvt",
            l["ndiode_sub"].not(l["hvi"]).group().and(l["lvtn"]),
        ),
    );
    l.insert(
        "diode_pw2nd_05v5_nvt",
        d.derived(
            "diode_pw2nd_05v5_nvt",
            l["ndiode_sub"].and(l["hvi"]).group().and(l["lvtn"]),
        ),
    );
    l.insert(
        "diode_pw2nd_11v0",
        d.derived(
            "diode_pw2nd_11v0",
            l["ndiode_sub"].and(l["hvi"]).group().not(l["lvtn"]),
        ),
    );
    l.insert(
        "cap_var_lvt",
        d.derived("cap_var_lvt", l["var_lvt"].not(l["hvi"]).group()),
    );
    l.insert(
        "cap_var_hvt",
        d.derived("cap_var_hvt", l["var_hvt"].not(l["hvi"]).group()),
    );
    l.insert(
        "cap_var_5v",
        d.derived("cap_var_5v", l["var_channel"].and(l["hvi"])),
    );
    d.rule("dnwell.2", min_width(l["dnwell"], nm(3000)));
    d.rule("dnwell.3", min_spacing(l["dnwell"], nm(6300)));
    d.rule("dnwell.3.notch", notch(l["dnwell"], nm(6300)));
    d.rule("nwell.1", min_width(l["nwell"], nm(840)));
    d.rule("nwell.2a", min_spacing(l["nwell"], nm(1270)));
    d.rule("nwell.2a.notch", notch(l["nwell"], nm(1270)));
    d.rule(
        "nwell.5",
        min_enclosure(l["dnwell"], l["nwell_filled"], nm(400)),
    );
    d.rule(
        "nwell.6",
        min_enclosure(l["nwell_hole"], l["dnwell"], nm(1030)),
    );
    d.rule("hvtp.1", min_width(l["hvtp"], nm(380)));
    d.rule("hvtp.2", min_spacing(l["hvtp"], nm(380)));
    d.rule("hvtp.2.notch", notch(l["hvtp"], nm(380)));
    d.rule("hvtp.3", min_enclosure(l["hvt_pfet"], l["hvtp"], nm(180)));
    d.rule(
        "hvtp.4",
        min_spacing_diff(l["lvt_pfet"], l["hvtp"], nm(180)),
    );
    d.rule("hvtp.5", min_area(l["hvtp"], nm2(265000)));
    d.rule("hvtp.6", min_enclosed_area(l["hvtp"], nm2(265000)));
    d.rule("hvtr.1", min_width(l["hvtr"], nm(380)));
    d.rule("hvtr.2", min_spacing_diff(l["hvtp"], l["hvtr"], nm(380)));
    d.rule("hvtr.3", min_enclosure(l["hvtr_pfet"], l["hvtr"], nm(180)));
    d.rule("lvtn.1a", min_width(l["lvtn"], nm(380)));
    d.rule("lvtn.2", min_spacing(l["lvtn"], nm(380)));
    d.rule("lvtn.2.notch", notch(l["lvtn"], nm(380)));
    d.rule(
        "lvtn.3a",
        min_spacing_diff(l["std_gate"], l["lvtn"], nm(180)),
    );
    d.rule("lvtn.4b", min_enclosure(l["lvtn_gate"], l["lvtn"], nm(180)));
    d.rule("lvtn.9", min_spacing_diff(l["lvtn"], l["hvtp"], nm(380)));
    d.rule(
        "lvtn.12",
        min_spacing_diff(l["lvtn"], l["nwell_ce"], nm(380)),
    );
    d.rule("lvtn.13", min_area(l["lvtn"], nm2(265000)));
    d.rule("lvtn.14", min_enclosed_area(l["lvtn"], nm2(265000)));
    d.rule("ncm.1", min_width(l["ncm"], nm(380)));
    d.rule("ncm.2a", min_spacing(l["ncm"], nm(380)));
    d.rule("ncm.2a.notch", notch(l["ncm"], nm(380)));
    d.rule("ncm.3", min_enclosure(l["ncm_pdiff"], l["ncm"], nm(180)));
    d.rule(
        "ncm.5",
        min_spacing_diff(l["ncm"], l["lvtn_gate_or_diff"], nm(230)),
    );
    d.rule("ncm.6", min_spacing_diff(l["ncm"], l["nfet"], nm(200)));
    d.rule("ncm.7", min_area(l["ncm"], nm2(265000)));
    d.rule("ncm.8", min_enclosed_area(l["ncm"], nm2(265000)));
    d.rule("difftap.1", min_width(l["diff"], nm(150)));
    d.rule("difftap.1.tap", min_width(l["tap"], nm(150)));
    d.rule("difftap.3", min_spacing(l["difftap"], nm(270)));
    d.rule("difftap.3.notch", notch(l["difftap"], nm(270)));
    d.rule("difftap.8", min_enclosure(l["pdiff"], l["nwell"], nm(180)));
    d.rule(
        "difftap.9",
        min_spacing_diff(l["ndiff"], l["nwell"], nm(340)),
    );
    d.rule("difftap.10", min_enclosure(l["ntap"], l["nwell"], nm(180)));
    d.rule(
        "difftap.11",
        min_spacing_diff(l["ptap"], l["nwell"], nm(130)),
    );
    d.rule("poly.1a", min_width(l["poly"], nm(150)));
    d.rule(
        "poly.1b",
        edge_width(l["lvtn_pfet"].edges().not(l["diff"].edges()), nm(350)),
    );
    d.rule(
        "difftap.2",
        edge_width(l["gate_nsc"].edges().and(l["diff"].edges()), nm(420)),
    );
    d.rule(
        "difftap.2b",
        edge_width(l["gate_sc"].edges().and(l["diff"].edges()), nm(360)),
    );
    d.rule("poly.2", min_spacing(l["poly"], nm(210)));
    d.rule("poly.2.notch", notch(l["poly"], nm(210)));
    d.rule("poly.3", min_width(l["poly_res"], nm(330)));
    d.rule(
        "poly.4",
        min_spacing_diff(l["poly_field"], l["diff"], nm(75)),
    );
    d.rule(
        "poly.5",
        min_spacing_diff(l["poly_off_tap"], l["tap"], nm(55)),
    );
    d.rule("poly.7", min_extension(l["diff"], l["poly"], nm(250)));
    d.rule("poly.8", min_extension(l["poly"], l["diff"], nm(130)));
    d.rule(
        "poly.9",
        min_spacing_diff(l["poly_res"], l["poly_plain"], nm(480)),
    );
    d.rule(
        "poly.9.difftap",
        min_spacing_diff(l["poly_res"], l["difftap"], nm(480)),
    );
    d.rule("rpm.1a", min_width(l["rpm"], nm(1270)));
    d.rule("rpm.2", min_spacing(l["rpm"], nm(840)));
    d.rule("rpm.2.notch", notch(l["rpm"], nm(840)));
    d.rule("rpm.3", min_enclosure(l["prec_rpm"], l["rpm"], nm(200)));
    d.rule("rpm.4", min_enclosure(l["prec_rpm"], l["psdm"], nm(110)));
    d.rule("rpm.5", min_enclosure(l["prec_rpm"], l["npc"], nm(95)));
    d.rule("rpm.6", min_spacing_diff(l["rpm"], l["nsdm"], nm(200)));
    d.rule(
        "rpm.7",
        min_spacing_diff(l["rpm"], l["poly_out_rpm"], nm(200)),
    );
    d.rule(
        "rpm.9",
        min_spacing_diff(l["prec_rpm"], l["hvntm"], nm(185)),
    );
    d.rule("varac.1", min_width(l["var_channel"], nm(180)));
    d.rule(
        "varac.3",
        min_spacing_diff(l["var_lvt"], l["hvtp"], nm(180)),
    );
    d.rule(
        "varac.4",
        min_spacing_diff(l["licon_var_tap"], l["var_channel"], nm(250)),
    );
    d.rule("varac.5", min_enclosure(l["var_poly"], l["nwell"], nm(150)));
    d.rule("varac.8", min_enclosure(l["var_hvt"], l["hvtp"], nm(255)));
    d.rule("npc.1", min_width(l["npc"], nm(270)));
    d.rule("npc.2", min_spacing(l["npc"], nm(270)));
    d.rule("npc.2.notch", notch(l["npc"], nm(270)));
    d.rule("npc.4", min_spacing_diff(l["npc"], l["gate"], nm(90)));
    d.rule("nsd.1", min_width(l["nsdm"], nm(380)));
    d.rule("psd.1", min_width(l["psdm"], nm(380)));
    d.rule("nsd.2", min_spacing(l["nsdm"], nm(380)));
    d.rule("nsd.2.notch", notch(l["nsdm"], nm(380)));
    d.rule("psd.2", min_spacing(l["psdm"], nm(380)));
    d.rule("psd.2.notch", notch(l["psdm"], nm(380)));
    d.rule("nsd.5a", min_enclosure(l["ndiff_body"], l["nsdm"], nm(125)));
    d.rule("psd.5a", min_enclosure(l["pdiff_body"], l["psdm"], nm(125)));
    d.rule("nsd.5b", min_enclosure(l["ntap_body"], l["nsdm"], nm(125)));
    d.rule("psd.5b", min_enclosure(l["ptap_body"], l["psdm"], nm(125)));
    d.rule("nsd.7", min_spacing_diff(l["nsdm"], l["p_lone"], nm(130)));
    d.rule("psd.7", min_spacing_diff(l["psdm"], l["n_lone"], nm(130)));
    d.rule("nsd.10a", min_area(l["nsdm"], nm2(265000)));
    d.rule("psd.10b", min_area(l["psdm"], nm2(255000)));
    d.rule("nsd.11", min_enclosed_area(l["nsdm"], nm2(265000)));
    d.rule("psd.11", min_enclosed_area(l["psdm"], nm2(265000)));
    d.rule("licon.1", cut_size(l["licon_std"], nm(170), nm(170)));
    d.rule("licon.1b", cut_size(l["licon_prec"], nm(190), nm(2000)));
    d.rule("licon.2", min_spacing(l["licon"], nm(170)));
    d.rule(
        "licon.5a",
        min_enclosure(l["licon_diff"], l["diff"], nm(40)),
    );
    d.rule(
        "licon.5c",
        asymmetric_enclosure(l["licon_diff"], l["diff"], nm(60)),
    );
    d.rule(
        "licon.7",
        asymmetric_enclosure(l["licon_iso_tap"], l["tap"], nm(120)),
    );
    d.rule("licon.8", min_enclosure(l["poly_licon"], l["poly"], nm(50)));
    d.rule(
        "licon.8a",
        asymmetric_enclosure(l["poly_licon"], l["poly"], nm(80)),
    );
    d.rule(
        "licon.9",
        min_spacing_diff(l["poly_licon_nrpm"], l["psdm"], nm(110)),
    );
    d.rule(
        "licon.10",
        min_spacing_diff(l["licon_var_tap"], l["var_channel"], nm(250)),
    );
    d.rule(
        "licon.11",
        min_spacing_diff(l["licon_dt"], l["gate_nsc"], nm(55)),
    );
    d.rule(
        "licon.11a",
        min_spacing_diff(l["licon_dt"], l["gate_sc"], nm(50)),
    );
    d.rule(
        "licon.13",
        min_spacing_diff(l["npc"], l["licon_dt"], nm(90)),
    );
    d.rule(
        "licon.14",
        min_spacing_diff(l["poly_licon"], l["difftap"], nm(190)),
    );
    d.rule(
        "licon.15",
        min_enclosure(l["poly_licon"], l["npc"], nm(100)),
    );
    d.rule("li.1", min_width(l["li"], nm(170)));
    d.rule("li.3", min_spacing(l["li"], nm(170)));
    d.rule("li.3.notch", notch(l["li"], nm(170)));
    d.rule("li.5", asymmetric_enclosure(l["licon"], l["li"], nm(80)));
    d.rule("li.6", min_area(l["li"], nm2(56100)));
    d.rule("li.7", min_width(l["li_res"], nm(290)));
    d.rule("ct.1", cut_size(l["mcon"], nm(170), nm(170)));
    d.rule("ct.2", min_spacing(l["mcon"], nm(190)));
    d.rule("m1.1", min_width(l["met1"], nm(140)));
    d.rule("m1.2", min_spacing(l["met1"], nm(140)));
    d.rule("m1.2.notch", notch(l["met1"], nm(140)));
    d.rule(
        "m1.3b",
        wide_dependent_spacing(l["met1"], nm(3000), nm(280)),
    );
    d.rule("m2.1", min_width(l["met2"], nm(140)));
    d.rule("m2.2", min_spacing(l["met2"], nm(140)));
    d.rule("m2.2.notch", notch(l["met2"], nm(140)));
    d.rule(
        "m2.3b",
        wide_dependent_spacing(l["met2"], nm(3000), nm(280)),
    );
    d.rule("m3.1", min_width(l["met3"], nm(300)));
    d.rule("m3.2", min_spacing(l["met3"], nm(300)));
    d.rule("m3.2.notch", notch(l["met3"], nm(300)));
    d.rule(
        "m3.3d",
        wide_dependent_spacing(l["met3"], nm(3000), nm(400)),
    );
    d.rule("m4.1", min_width(l["met4"], nm(300)));
    d.rule("m4.2", min_spacing(l["met4"], nm(300)));
    d.rule("m4.2.notch", notch(l["met4"], nm(300)));
    d.rule(
        "m4.5b",
        wide_dependent_spacing(l["met4"], nm(3000), nm(400)),
    );
    d.rule(
        "m1.3a",
        attached_wide_spacing(l["met1"], nm(3000), nm(280), nm(280)),
    );
    d.rule(
        "m2.3a",
        attached_wide_spacing(l["met2"], nm(3000), nm(280), nm(280)),
    );
    d.rule(
        "m3.3c",
        attached_wide_spacing(l["met3"], nm(3000), nm(400), nm(400)),
    );
    d.rule(
        "m4.5a",
        attached_wide_spacing(l["met4"], nm(3000), nm(400), nm(400)),
    );
    d.rule("m1.6", min_area(l["met1"], nm2(83000)));
    d.rule("m2.6", min_area(l["met2"], nm2(67600)));
    d.rule("m3.6", min_area(l["met3"], nm2(240000)));
    d.rule("m4.4a", min_area(l["met4"], nm2(240000)));
    d.rule("m1.7", min_enclosed_area(l["met1"], nm2(140000)));
    d.rule("m2.7", min_enclosed_area(l["met2"], nm2(140000)));
    d.rule("m5.1", min_width(l["met5"], nm(1600)));
    d.rule("m5.2", min_spacing(l["met5"], nm(1600)));
    d.rule("m5.2.notch", notch(l["met5"], nm(1600)));
    d.rule("m5.4", min_area(l["met5"], nm2(4000000)));
    d.rule("m1.4", min_enclosure(l["mcon"], l["met1"], nm(30)));
    d.rule("m1.5", asymmetric_enclosure(l["mcon"], l["met1"], nm(60)));
    d.rule("via.1a", cut_size(l["via"], nm(150), nm(150)));
    d.rule("via.2", min_spacing(l["via"], nm(170)));
    d.rule("via.4a", min_enclosure(l["via"], l["met1"], nm(55)));
    d.rule("via.5a", asymmetric_enclosure(l["via"], l["met1"], nm(85)));
    d.rule("m2.4", min_enclosure(l["via"], l["met2"], nm(55)));
    d.rule("m2.5", asymmetric_enclosure(l["via"], l["met2"], nm(85)));
    d.rule("via2.1a", cut_size(l["via2"], nm(200), nm(200)));
    d.rule("via2.2", min_spacing(l["via2"], nm(200)));
    d.rule("via2.4", min_enclosure(l["via2"], l["met2"], nm(40)));
    d.rule("via2.5", asymmetric_enclosure(l["via2"], l["met2"], nm(85)));
    d.rule("m3.4", min_enclosure(l["via2"], l["met3"], nm(65)));
    d.rule("via3.1", cut_size(l["via3"], nm(200), nm(200)));
    d.rule("via3.2", min_spacing(l["via3"], nm(200)));
    d.rule("via3.4", min_enclosure(l["via3"], l["met3"], nm(60)));
    d.rule("via3.5", asymmetric_enclosure(l["via3"], l["met3"], nm(90)));
    d.rule("m4.3", min_enclosure(l["via3"], l["met4"], nm(65)));
    d.rule("via4.1", cut_size(l["via4"], nm(800), nm(800)));
    d.rule("via4.2", min_spacing(l["via4"], nm(800)));
    d.rule("via4.4", min_enclosure(l["via4"], l["met4"], nm(190)));
    d.rule("m5.3", min_enclosure(l["via4"], l["met5"], nm(310)));
    d.rule("capm.1", min_width(l["capm"], nm(1000)));
    d.rule("capm.2a", min_spacing(l["capm"], nm(840)));
    d.rule("capm.3", min_enclosure(l["capm"], l["met3"], nm(140)));
    d.rule(
        "capm.4",
        min_enclosure(l["via3"].interacting(l["capm"]), l["capm"], nm(140)),
    );
    d.rule(
        "capm.11",
        min_spacing_diff(l["capm_m3_free"], l["capm"], nm(500)),
    );
    d.rule("capm.7", forbidden(l["capm"].non_rectangles()));
    d.rule("cap2m.1", min_width(l["cap2m"], nm(1000)));
    d.rule("cap2m.2a", min_spacing(l["cap2m"], nm(840)));
    d.rule("cap2m.3", min_enclosure(l["cap2m"], l["met4"], nm(140)));
    d.rule(
        "cap2m.4",
        min_enclosure(l["via4"].interacting(l["cap2m"]), l["cap2m"], nm(200)),
    );
    d.rule(
        "cap2m.11",
        min_spacing_diff(l["cap2m_m4_free"], l["cap2m"], nm(500)),
    );
    d.rule("pad.2", min_spacing(l["pad"], nm(1270)));
    d.rule("nsm.1", min_width(l["nsm"], nm(3000)));
    d.rule("nsm.2", min_spacing(l["nsm"], nm(4000)));
    d.rule("hvi.1", min_width(l["hvi"], nm(600)));
    d.rule("hvi.2a", min_spacing(l["hvi"], nm(700)));
    d.rule("hvi.2a.notch", notch(l["hvi"], nm(700)));
    d.rule(
        "hvi.5",
        min_spacing_diff(l["hvi"], l["nwell_out_hvi"], nm(700)),
    );
    d.rule("difftap.14", min_width(l["hdiff"], nm(290)));
    d.rule("difftap.15a", min_spacing(l["hdiff"], nm(300)));
    d.rule(
        "difftap.15b",
        min_spacing_diff(l["hndiff"], l["iso_ptap"], nm(370)),
    );
    d.rule(
        "difftap.17",
        min_enclosure(l["hpdiff"], l["nwell"], nm(330)),
    );
    d.rule(
        "difftap.18",
        min_spacing_diff(l["ndiff"], l["hv_nwell"], nm(430)),
    );
    d.rule("difftap.19", min_enclosure(l["hntap"], l["nwell"], nm(330)));
    d.rule(
        "difftap.20",
        min_spacing_diff(l["ptap"], l["hv_nwell"], nm(430)),
    );
    d.rule(
        "difftap.22",
        min_enclosure(l["difftap_hv"], l["hvi"], nm(180)),
    );
    d.rule(
        "difftap.23",
        min_spacing_diff(l["difftap_lv"], l["hvi"], nm(180)),
    );
    d.rule(
        "difftap.24",
        min_spacing_diff(l["nwell"], l["hndiff"], nm(430)),
    );
    d.rule("hvntm.1", min_width(l["hvntm"], nm(700)));
    d.rule("hvntm.2", min_spacing(l["hvntm"], nm(700)));
    d.rule("hvntm.2.notch", notch(l["hvntm"], nm(700)));
    d.rule(
        "hvntm.3",
        min_enclosure(l["hvntm_ndiff"], l["hvntm"], nm(185)),
    );
    d.rule(
        "hvntm.4",
        min_spacing_diff(l["ndiff_lv"], l["hvntm"], nm(185)),
    );
    d.rule("hvntm.5", min_spacing_diff(l["pdiff"], l["hvntm"], nm(185)));
    d.rule(
        "hvntm.6a",
        min_spacing_diff(l["iso_ptap"], l["hvntm"], nm(185)),
    );
    d.rule("x.1b", off_grid(nm(5)));
    d.rule("x.3a", angle(None, &[0, 45, 90, 135]));
    l.insert(
        "pantenna_short",
        d.derived(
            "pantenna_short",
            l["tap"].not(l["poly"]).group().not(l["nwell"]),
        ),
    );
    l.insert(
        "antenna_diode",
        d.derived(
            "antenna_diode",
            l["diff"]
                .or(l["tap"])
                .group()
                .not(l["poly"].or(l["pantenna_short"])),
        ),
    );
    d.rule(
        "ar.poly.1",
        antenna(
            l["gate"],
            &[l["poly_c"]],
            50.0,
            Some(nm(180)),
            Some(l["pantenna_short"]),
        ),
    );
    d.rule(
        "ar.licon.1",
        antenna(
            l["gate"],
            &[
                l["licon_po"],
                l["licon_nd"],
                l["licon_pd"],
                l["licon_nt"],
                l["licon_pt"],
            ],
            3.0,
            None,
            Some(l["pantenna_short"]),
        ),
    );
    d.rule(
        "ar.li.1",
        antenna_electrical(
            l["gate"],
            &[l["li_c"]],
            75.0,
            Some(nm(100)),
            1.0,
            Some(l["antenna_diode"]),
            450.0,
            0.0,
            0.0,
            0.0,
            &[],
            &[],
            Some(l["pantenna_short"]),
        ),
    );
    d.rule(
        "ar.mcon.1",
        antenna_electrical(
            l["gate"],
            &[l["mcon"]],
            3.0,
            None,
            1.0,
            Some(l["antenna_diode"]),
            18.0,
            0.0,
            0.0,
            0.0,
            &[],
            &[],
            Some(l["pantenna_short"]),
        ),
    );
    d.rule(
        "ar.met1.1",
        antenna_electrical(
            l["gate"],
            &[l["met1"]],
            400.0,
            Some(nm(350)),
            1.0,
            Some(l["antenna_diode"]),
            400.0,
            2200.0,
            0.0,
            0.0,
            &[],
            &[],
            Some(l["pantenna_short"]),
        ),
    );
    d.rule(
        "ar.via.1",
        antenna_electrical(
            l["gate"],
            &[l["via"]],
            6.0,
            None,
            1.0,
            Some(l["antenna_diode"]),
            36.0,
            0.0,
            0.0,
            0.0,
            &[],
            &[],
            Some(l["pantenna_short"]),
        ),
    );
    d.rule(
        "ar.met2.1",
        antenna_electrical(
            l["gate"],
            &[l["met2"]],
            400.0,
            Some(nm(350)),
            1.0,
            Some(l["antenna_diode"]),
            400.0,
            2200.0,
            0.0,
            0.0,
            &[],
            &[],
            Some(l["pantenna_short"]),
        ),
    );
    d.rule(
        "ar.via2.1",
        antenna_electrical(
            l["gate"],
            &[l["via2"]],
            6.0,
            None,
            1.0,
            Some(l["antenna_diode"]),
            36.0,
            0.0,
            0.0,
            0.0,
            &[],
            &[],
            Some(l["pantenna_short"]),
        ),
    );
    d.rule(
        "ar.met3.1",
        antenna_electrical(
            l["gate"],
            &[l["met3"]],
            400.0,
            Some(nm(800)),
            1.0,
            Some(l["antenna_diode"]),
            400.0,
            2200.0,
            0.0,
            0.0,
            &[],
            &[],
            Some(l["pantenna_short"]),
        ),
    );
    d.rule(
        "ar.via3.1",
        antenna_electrical(
            l["gate"],
            &[l["via3_m3"]],
            6.0,
            None,
            1.0,
            Some(l["antenna_diode"]),
            36.0,
            0.0,
            0.0,
            0.0,
            &[],
            &[],
            Some(l["pantenna_short"]),
        ),
    );
    d.rule(
        "ar.met4.1",
        antenna_electrical(
            l["gate"],
            &[l["met4"]],
            400.0,
            Some(nm(800)),
            1.0,
            Some(l["antenna_diode"]),
            400.0,
            2200.0,
            0.0,
            0.0,
            &[],
            &[],
            Some(l["pantenna_short"]),
        ),
    );
    d.rule(
        "ar.via4.1",
        antenna_electrical(
            l["gate"],
            &[l["via4_m4"]],
            6.0,
            None,
            1.0,
            Some(l["antenna_diode"]),
            36.0,
            0.0,
            0.0,
            0.0,
            &[],
            &[],
            Some(l["pantenna_short"]),
        ),
    );
    d.rule(
        "ar.met5.1",
        antenna_electrical(
            l["gate"],
            &[l["met5"]],
            400.0,
            Some(nm(1200)),
            1.0,
            Some(l["antenna_diode"]),
            400.0,
            2200.0,
            0.0,
            0.0,
            &[],
            &[],
            Some(l["pantenna_short"]),
        ),
    );
    d.rule(
        "x.22",
        unconnected_pin(&[
            l["poly_c"],
            l["li_c"],
            l["met1"],
            l["met2"],
            l["met3"],
            l["met4"],
            l["met5"],
        ]),
    );
    d.rule("nwell.4", floating_well(l["nwell"], l["ntap_licon"]));
    d.rule(
        "supply_short",
        supply_short(l["ntap"], l["ptap"], Some(l["pmos_well"].into())),
    );
    d.rule(
        "soft_connection",
        soft_connection(&[l["ntap"], l["ptap"], l["nwell"], l["pwell_iso"]]),
    );
    d.rule("floating_gate", floating_gate(false));
    d.rule("tie_high_low", tie_high_low().warning());
    d.rule("ir_drop", ir_drop());
    d.rule("multiple_drivers", multiple_drivers(1));
    d.rule(
        "esd.pad",
        esd_topological(
            l["pad"],
            &[
                "sky130_fd_pr__esd_nfet_g5v0d10v5",
                "sky130_fd_pr__esd_pfet_g5v0d10v5",
            ],
        ),
    );
    d.rule(
        "vgs.01v8",
        gate_oxide(
            &[
                "sky130_fd_pr__nfet_01v8",
                "sky130_fd_pr__nfet_01v8_lvt",
                "sky130_fd_pr__pfet_01v8",
                "sky130_fd_pr__pfet_01v8_lvt",
                "sky130_fd_pr__pfet_01v8_hvt",
            ],
            1950.0,
        ),
    );
    d.rule(
        "vds.01v8",
        drain_source(
            &[
                "sky130_fd_pr__nfet_01v8",
                "sky130_fd_pr__nfet_01v8_lvt",
                "sky130_fd_pr__pfet_01v8",
                "sky130_fd_pr__pfet_01v8_lvt",
                "sky130_fd_pr__pfet_01v8_hvt",
            ],
            1950.0,
        ),
    );
    d.rule(
        "vgs.g5v0",
        gate_oxide(
            &[
                "sky130_fd_pr__nfet_g5v0d10v5",
                "sky130_fd_pr__pfet_g5v0d10v5",
                "sky130_fd_pr__esd_pfet_g5v0d10v5",
            ],
            5500.0,
        ),
    );
    d.rule(
        "vgs.esd_nfet",
        gate_oxide(&["sky130_fd_pr__esd_nfet_g5v0d10v5"], 5000.0),
    );
    d.rule(
        "vds.d10v5",
        drain_source(
            &[
                "sky130_fd_pr__nfet_g5v0d10v5",
                "sky130_fd_pr__pfet_g5v0d10v5",
                "sky130_fd_pr__esd_nfet_g5v0d10v5",
                "sky130_fd_pr__esd_pfet_g5v0d10v5",
            ],
            11000.0,
        ),
    );
    d.rule(
        "well_bias",
        well_bias(
            &[
                "sky130_fd_pr__pfet_01v8",
                "sky130_fd_pr__pfet_01v8_lvt",
                "sky130_fd_pr__pfet_01v8_hvt",
                "sky130_fd_pr__pfet_g5v0d10v5",
                "sky130_fd_pr__esd_pfet_g5v0d10v5",
            ],
            &[
                "sky130_fd_pr__nfet_01v8",
                "sky130_fd_pr__nfet_01v8_lvt",
                "sky130_fd_pr__nfet_g5v0d10v5",
                "sky130_fd_pr__esd_nfet_g5v0d10v5",
            ],
        ),
    );
    d.rule(
        "EM.met1_mcon",
        em_current_density(&[l["met1"], l["mcon"]], 2800.0, 360.0, None, None),
    );
    d.rule(
        "EM.met2_via1",
        em_current_density(&[l["met2"], l["via"]], 2800.0, 290.0, None, None),
    );
    d.rule(
        "EM.met3_via2",
        em_current_density(&[l["met3"], l["via2"]], 6800.0, 480.0, None, None),
    );
    d.rule(
        "EM.met4_via3",
        em_current_density(&[l["met4"], l["via3_m3"]], 6800.0, 480.0, None, None),
    );
    d.rule(
        "EM.met5_via4",
        em_current_density(&[l["met5"], l["via4_m4"]], 10170.0, 2490.0, None, None),
    );
    d.rule(
        "m1.density",
        density_cmp(
            l["met1"],
            nm(700000),
            nm(700000),
            nm(70000),
            nm(70000),
            None,
            Some(0.7),
            None,
            false,
            None,
            None,
            None,
        )
        .warning(),
    );
    d.rule(
        "m2.density",
        density_cmp(
            l["met2"],
            nm(700000),
            nm(700000),
            nm(70000),
            nm(70000),
            None,
            Some(0.7),
            None,
            false,
            None,
            None,
            None,
        )
        .warning(),
    );
    d.rule(
        "m3.density",
        density_cmp(
            l["met3"],
            nm(700000),
            nm(700000),
            nm(70000),
            nm(70000),
            None,
            Some(0.7),
            None,
            false,
            None,
            None,
            None,
        )
        .warning(),
    );
    d.rule(
        "m4.density",
        density_cmp(
            l["met4"],
            nm(700000),
            nm(700000),
            nm(70000),
            nm(70000),
            None,
            Some(0.7),
            None,
            false,
            None,
            None,
            None,
        )
        .warning(),
    );
    d.conductors(&[
        l["nsd"],
        l["psd"],
        l["ntap"],
        l["ptap"],
        l["nwell"],
        l["pwell_iso"],
        l["poly_c"],
        l["li_c"],
        l["met1"],
        l["met2"],
        l["met3"],
        l["met4"],
        l["met5"],
    ]);
    d.touch_within_layer();
    d.via(l["licon_nd"], (l["nsd"], l["li_c"]));
    d.via(l["licon_pd"], (l["psd"], l["li_c"]));
    d.via(l["licon_nt"], (l["ntap"], l["li_c"]));
    d.via(l["licon_pt"], (l["ptap"], l["li_c"]));
    d.global(l["psub"]);
    d.via(l["psub_tie"], (l["ptap"], l["psub"]));
    d.via(l["nwell_tie"], (l["ntap"], l["nwell"]));
    d.via(l["pwell_iso_tie"], (l["ptap"], l["pwell_iso"]));
    d.via(l["licon_po"], (l["poly_c"], l["li_c"]));
    d.via(l["mcon"], (l["li_c"], l["met1"]));
    d.via(l["via"], (l["met1"], l["met2"]));
    d.via(l["via2"], (l["met2"], l["met3"]));
    d.via(l["via3_m3"], (l["met3"], l["met4"]));
    d.via(l["via4_m4"], (l["met4"], l["met5"]));
    d.label(l["nwell_label"], l["nwell"]);
    d.label(l["poly"], l["poly_c"]);
    d.label(l["poly_label"], l["poly_c"]);
    d.label(l["li"], l["li_c"]);
    d.label(l["li_label"], l["li_c"]);
    d.label(l["li_pin"], l["li_c"]);
    d.label(l["met1"], l["met1"]);
    d.label(l["met1_label"], l["met1"]);
    d.label(l["met1_pin"], l["met1"]);
    d.label(l["met2"], l["met2"]);
    d.label(l["met2_label"], l["met2"]);
    d.label(l["met2_pin"], l["met2"]);
    d.label(l["met3"], l["met3"]);
    d.label(l["met3_label"], l["met3"]);
    d.label(l["met3_pin"], l["met3"]);
    d.label(l["met4"], l["met4"]);
    d.label(l["met4_label"], l["met4"]);
    d.label(l["met4_pin"], l["met4"]);
    d.label(l["met5"], l["met5"]);
    d.label(l["met5_label"], l["met5"]);
    d.label(l["met5_pin"], l["met5"]);
    d.device(
        DeviceKind::Mos,
        l["nfet_01v8"],
        "sky130_fd_pr__nfet_01v8",
        &[l["poly_c"], l["nsd"], l["nsd"], l["psub"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Mos,
        l["nfet_01v8"],
        "sky130_fd_pr__nfet_01v8",
        &[l["poly_c"], l["nsd"], l["nsd"], l["pwell_iso"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Mos,
        l["nfet_01v8_lvt"],
        "sky130_fd_pr__nfet_01v8_lvt",
        &[l["poly_c"], l["nsd"], l["nsd"], l["psub"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Mos,
        l["nfet_01v8_lvt"],
        "sky130_fd_pr__nfet_01v8_lvt",
        &[l["poly_c"], l["nsd"], l["nsd"], l["pwell_iso"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Mos,
        l["nfet_g5v0d10v5"],
        "sky130_fd_pr__nfet_g5v0d10v5",
        &[l["poly_c"], l["nsd"], l["nsd"], l["psub"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Mos,
        l["nfet_g5v0d10v5"],
        "sky130_fd_pr__nfet_g5v0d10v5",
        &[l["poly_c"], l["nsd"], l["nsd"], l["pwell_iso"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Mos,
        l["esd_nfet_g5v0d10v5"],
        "sky130_fd_pr__esd_nfet_g5v0d10v5",
        &[l["poly_c"], l["nsd"], l["nsd"], l["psub"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Mos,
        l["esd_nfet_g5v0d10v5"],
        "sky130_fd_pr__esd_nfet_g5v0d10v5",
        &[l["poly_c"], l["nsd"], l["nsd"], l["pwell_iso"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Mos,
        l["pfet_01v8"],
        "sky130_fd_pr__pfet_01v8",
        &[l["poly_c"], l["psd"], l["psd"], l["nwell"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Mos,
        l["pfet_01v8_lvt"],
        "sky130_fd_pr__pfet_01v8_lvt",
        &[l["poly_c"], l["psd"], l["psd"], l["nwell"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Mos,
        l["pfet_01v8_hvt"],
        "sky130_fd_pr__pfet_01v8_hvt",
        &[l["poly_c"], l["psd"], l["psd"], l["nwell"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Mos,
        l["pfet_g5v0d10v5"],
        "sky130_fd_pr__pfet_g5v0d10v5",
        &[l["poly_c"], l["psd"], l["psd"], l["nwell"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Mos,
        l["esd_pfet_g5v0d10v5"],
        "sky130_fd_pr__esd_pfet_g5v0d10v5",
        &[l["poly_c"], l["psd"], l["psd"], l["nwell"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Resistor,
        l["rbody_po"],
        "sky130_fd_pr__res_generic_po",
        &[l["poly_c"], l["poly_c"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Resistor,
        l["rbody_high_po"],
        "sky130_fd_pr__res_high_po",
        &[l["poly_c"], l["poly_c"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Resistor,
        l["rbody_xhigh_po"],
        "sky130_fd_pr__res_xhigh_po",
        &[l["poly_c"], l["poly_c"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Resistor,
        l["rbody_nd"],
        "sky130_fd_pr__res_generic_nd",
        &[l["nsd"], l["nsd"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Resistor,
        l["rbody_pd"],
        "sky130_fd_pr__res_generic_pd",
        &[l["psd"], l["psd"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Resistor,
        l["rbody_nd_hv"],
        "sky130_fd_pr__res_generic_nd__hv",
        &[l["nsd"], l["nsd"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Resistor,
        l["rbody_pd_hv"],
        "sky130_fd_pr__res_generic_pd__hv",
        &[l["psd"], l["psd"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Resistor,
        l["li_res"],
        "sky130_fd_pr__res_generic_l1",
        &[l["li_c"], l["li_c"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Diode,
        l["diode_pw2nd_05v5"],
        "sky130_fd_pr__diode_pw2nd_05v5",
        &[l["psub"], l["nsd"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Diode,
        l["diode_pw2nd_05v5_lvt"],
        "sky130_fd_pr__diode_pw2nd_05v5_lvt",
        &[l["psub"], l["nsd"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Diode,
        l["diode_pw2nd_05v5_nvt"],
        "sky130_fd_pr__diode_pw2nd_05v5_nvt",
        &[l["psub"], l["nsd"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Diode,
        l["diode_pw2nd_11v0"],
        "sky130_fd_pr__diode_pw2nd_11v0",
        &[l["psub"], l["nsd"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Capacitor,
        l["capm"],
        "sky130_fd_pr__cap_mim_m3_1",
        &[l["met4"], l["met3"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Capacitor,
        l["cap2m"],
        "sky130_fd_pr__cap_mim_m3_2",
        &[l["met5"], l["met4"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Capacitor,
        l["cap_var_lvt"],
        "sky130_fd_pr__cap_var_lvt",
        &[l["poly_c"], l["ntap"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Capacitor,
        l["cap_var_hvt"],
        "sky130_fd_pr__cap_var_hvt",
        &[l["poly_c"], l["ntap"]],
        DeviceValue::default(),
    );
    d.device(
        DeviceKind::Capacitor,
        l["cap_var_5v"],
        "sky130_fd_pr__cap_var",
        &[l["poly_c"], l["ntap"]],
        DeviceValue::default(),
    );
    d.pex(
        l["nsd"],
        StackSource {
            thickness_nm: 120.0,
            height_nm: 206.2,
            sheet_res_ohm_sq: 120.0,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 3.9,
            tc: None,
        },
    );
    d.pex(
        l["psd"],
        StackSource {
            thickness_nm: 120.0,
            height_nm: 206.2,
            sheet_res_ohm_sq: 197.0,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 3.9,
            tc: None,
        },
    );
    d.pex(
        l["ntap"],
        StackSource {
            thickness_nm: 120.0,
            height_nm: 206.2,
            sheet_res_ohm_sq: 120.0,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 3.9,
            tc: None,
        },
    );
    d.pex(
        l["ptap"],
        StackSource {
            thickness_nm: 120.0,
            height_nm: 206.2,
            sheet_res_ohm_sq: 197.0,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 3.9,
            tc: None,
        },
    );
    d.pex(
        l["nwell"],
        StackSource {
            thickness_nm: 206.2,
            height_nm: 0.0,
            sheet_res_ohm_sq: 950.0,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 3.9,
            tc: None,
        },
    );
    d.pex(
        l["pwell_iso"],
        StackSource {
            thickness_nm: 206.2,
            height_nm: 0.0,
            sheet_res_ohm_sq: 4400.0,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 3.9,
            tc: None,
        },
    );
    d.pex(
        l["nwell_tie"],
        StackSource {
            thickness_nm: 120.0,
            height_nm: 206.2,
            sheet_res_ohm_sq: 120.0,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 3.9,
            tc: None,
        },
    );
    d.pex(
        l["pwell_iso_tie"],
        StackSource {
            thickness_nm: 120.0,
            height_nm: 206.2,
            sheet_res_ohm_sq: 197.0,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 3.9,
            tc: None,
        },
    );
    d.pex(
        l["poly_c"],
        StackSource {
            thickness_nm: 180.0,
            height_nm: 326.2,
            sheet_res_ohm_sq: 48.2,
            area_cap_af_um2: 106.13,
            fringe_cap_af_um: 55.27,
            dielectric_k: 3.9,
            tc: None,
        },
    );
    d.pex(
        l["licon_nd"],
        StackSource {
            thickness_nm: 610.0,
            height_nm: 326.2,
            sheet_res_ohm_sq: 185.0,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 3.9,
            tc: None,
        },
    );
    d.pex(
        l["licon_pd"],
        StackSource {
            thickness_nm: 610.0,
            height_nm: 326.2,
            sheet_res_ohm_sq: 585.0,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 3.9,
            tc: None,
        },
    );
    d.pex(
        l["licon_nt"],
        StackSource {
            thickness_nm: 610.0,
            height_nm: 326.2,
            sheet_res_ohm_sq: 185.0,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 3.9,
            tc: None,
        },
    );
    d.pex(
        l["licon_pt"],
        StackSource {
            thickness_nm: 610.0,
            height_nm: 326.2,
            sheet_res_ohm_sq: 585.0,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 3.9,
            tc: None,
        },
    );
    d.pex(
        l["licon_po"],
        StackSource {
            thickness_nm: 430.0,
            height_nm: 506.2,
            sheet_res_ohm_sq: 152.0,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 3.9,
            tc: None,
        },
    );
    d.pex(
        l["li_c"],
        StackSource {
            thickness_nm: 100.0,
            height_nm: 936.1,
            sheet_res_ohm_sq: 12.8,
            area_cap_af_um2: 36.99,
            fringe_cap_af_um: 40.7,
            dielectric_k: 4.05,
            tc: None,
        },
    );
    d.pex(
        l["mcon"],
        StackSource {
            thickness_nm: 340.0,
            height_nm: 1036.1,
            sheet_res_ohm_sq: 9.3,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 4.05,
            tc: None,
        },
    );
    d.pex(
        l["met1"],
        StackSource {
            thickness_nm: 360.0,
            height_nm: 1376.1,
            sheet_res_ohm_sq: 0.125,
            area_cap_af_um2: 25.78,
            fringe_cap_af_um: 40.57,
            dielectric_k: 4.5,
            tc: None,
        },
    );
    d.pex(
        l["via"],
        StackSource {
            thickness_nm: 270.0,
            height_nm: 1736.1,
            sheet_res_ohm_sq: 4.5,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 4.5,
            tc: None,
        },
    );
    d.pex(
        l["met2"],
        StackSource {
            thickness_nm: 360.0,
            height_nm: 2006.1,
            sheet_res_ohm_sq: 0.125,
            area_cap_af_um2: 17.5,
            fringe_cap_af_um: 37.76,
            dielectric_k: 4.2,
            tc: None,
        },
    );
    d.pex(
        l["via2"],
        StackSource {
            thickness_nm: 420.0,
            height_nm: 2366.1,
            sheet_res_ohm_sq: 3.41,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 4.2,
            tc: None,
        },
    );
    d.pex(
        l["met3"],
        StackSource {
            thickness_nm: 845.0,
            height_nm: 2786.1,
            sheet_res_ohm_sq: 0.047,
            area_cap_af_um2: 12.37,
            fringe_cap_af_um: 40.99,
            dielectric_k: 4.1,
            tc: None,
        },
    );
    d.pex(
        l["via3_m3"],
        StackSource {
            thickness_nm: 390.0,
            height_nm: 3631.1,
            sheet_res_ohm_sq: 3.41,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 4.1,
            tc: None,
        },
    );
    d.pex(
        l["met4"],
        StackSource {
            thickness_nm: 845.0,
            height_nm: 4021.1,
            sheet_res_ohm_sq: 0.047,
            area_cap_af_um2: 8.42,
            fringe_cap_af_um: 36.68,
            dielectric_k: 4.0,
            tc: None,
        },
    );
    d.pex(
        l["via4_m4"],
        StackSource {
            thickness_nm: 505.0,
            height_nm: 4866.1,
            sheet_res_ohm_sq: 0.38,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 4.0,
            tc: None,
        },
    );
    d.pex(
        l["met5"],
        StackSource {
            thickness_nm: 1260.0,
            height_nm: 5371.1,
            sheet_res_ohm_sq: 0.029,
            area_cap_af_um2: 6.32,
            fringe_cap_af_um: 38.85,
            dielectric_k: 3.9,
            tc: None,
        },
    );
    d.rule(
        "x.10",
        forbidden(l["poly_rs"].or(l["diff_rs"]).group().and(l["licon"])),
    );
    d.rule("dnwell.4", forbidden(l["dnwell"].and(l["pnp"])));
    d.rule(
        "licon.4",
        forbidden(
            l["licon"]
                .outside(l["li"])
                .or(l["licon"].outside(l["poly"].or(l["difftap"]))),
        ),
    );
    d.rule(
        "licon.6",
        forbidden(
            l["licon"]
                .and(l["tap"])
                .group()
                .interacting(l["licon"].not(l["tap"])),
        ),
    );
    d.rule("licon.16", must_contain(l["tap"], l["licon"], 1));
    d.rule(
        "licon.17",
        forbidden(l["licon"].and(l["poly"]).group().and(l["difftap"])),
    );
    d.rule("licon.18", must_be_inside(l["poly_licon"], l["npc"]));
    d.rule("ct.4", must_be_inside(l["mcon"], l["li"]));
    d.rule(
        "poly.12",
        forbidden(l["poly"].not(l["nwell_lv"]).group().and(l["tap"])),
    );
    d.rule(
        "poly.14",
        forbidden(
            l["gate"]
                .and(l["hvi"])
                .group()
                .interacting(l["gate"].not(l["hvi"])),
        ),
    );
    d.rule("poly.15", forbidden(l["poly"].and(l["diff_rs"])));
    d.rule(
        "nsd.8",
        forbidden(
            l["nsdm"]
                .and(l["pdifftap"])
                .group()
                .or(l["psdm"].and(l["ndifftap"]).group()),
        ),
    );
    d.rule(
        "nsd.9",
        forbidden(l["difftap"].not(l["nsdm"].or(l["psdm"]).group())),
    );
    d.rule(
        "rpm.8",
        forbidden(
            l["poly"]
                .and(l["rpm"])
                .group()
                .interacting(l["poly"].not(l["rpm"])),
        ),
    );
    d.rule(
        "varac.7",
        forbidden(l["nwell"].interacting(l["var_channel"]).and(l["pdiff"])),
    );
    d.rule("nwell.9", must_be_inside(l["hv_nwell"], l["hvi"]));
    d.rule(
        "difftap.21",
        forbidden(
            l["difftap"]
                .and(l["hvi"])
                .group()
                .interacting(l["difftap"].not(l["hvi"])),
        ),
    );
    d.rule("hvi.4", forbidden(l["hvi"].and(l["tunm"])));
    d.rule("hvntm.9", forbidden(l["hvntm"].and(l["areaid_ce"])));
    d.rule("hvntm.10", forbidden(l["hvntm"].outside(l["hvi"])));
    l.insert(
        "butt",
        d.derived("butt", l["tap"].edges().and(l["diff"].edges())),
    );
    d.rule("difftap.4", edge_min_length(l["butt"], nm(290)));
    d.rule("difftap.5", edge_spacing(l["butt"], None, nm(400)));
    d.rule(
        "difftap.7",
        edge_spacing(
            l["tap"]
                .edges()
                .not(l["diff"].edges())
                .group()
                .not_interacting(l["diff"]),
            Some(l["diff"].edges()),
            nm(130),
        ),
    );
    d.rule(
        "difftap.7.diff",
        edge_spacing(
            l["diff"]
                .edges()
                .not(l["tap"].edges())
                .group()
                .not_interacting(l["tap"]),
            Some(l["tap"].edges()),
            nm(130),
        ),
    );
    d.rule(
        "nsd.5a.butted",
        edge_enclosure(
            l["diff"]
                .interacting(l["tap"])
                .interacting(l["nsdm"])
                .edges()
                .not(l["tap"].edges()),
            l["nsdm"],
            nm(125),
        ),
    );
    d.rule(
        "psd.5a.butted",
        edge_enclosure(
            l["diff"]
                .interacting(l["tap"])
                .interacting(l["psdm"])
                .edges()
                .not(l["tap"].edges()),
            l["psdm"],
            nm(125),
        ),
    );
    d.rule(
        "nsd.5b.butted",
        edge_enclosure(
            l["tap"]
                .interacting(l["diff"])
                .interacting(l["nsdm"])
                .edges()
                .not(l["diff"].edges()),
            l["nsdm"],
            nm(125),
        ),
    );
    d.rule(
        "psd.5b.butted",
        edge_enclosure(
            l["tap"]
                .interacting(l["diff"])
                .interacting(l["psdm"])
                .edges()
                .not(l["diff"].edges()),
            l["psdm"],
            nm(125),
        ),
    );
    d.rule(
        "nsd.6",
        forbidden(l["butt"].outside_part(l["nsdm"].or(l["psdm"]))),
    );
    d.rule(
        "licon.5b",
        edge_spacing(
            l["licon"].inside(l["tap"]).edges(),
            Some(l["butt"].into()),
            nm(60),
        ),
    );
    d.rule(
        "poly.6",
        min_spacing_diff(l["gate"], l["tap"].interacting(l["diff"]), nm(300)),
    );
    d.rule(
        "hvntm.6b",
        forbidden(
            l["ptap"]
                .edges()
                .and(l["diff"].edges())
                .group()
                .inside_part(l["hvntm"]),
        ),
    );
    d.finish()
}
