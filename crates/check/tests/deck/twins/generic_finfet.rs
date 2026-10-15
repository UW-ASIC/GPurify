//! The Rust twin of `pdks/generic_finfet.deck`: the same deck stated with
//! [`DeckBuilder`], statement by statement, `for` loops unrolled and `let`
//! bindings substituted. Translated once from the deck text by a reader of
//! the deck language independent of the parser; the twin test holds this
//! to the parsed text. After editing the deck, edit this to match: the test
//! names the first difference.

#![allow(clippy::unreadable_literal, reason = "values as the deck writes them")]

use gpurify_check::deck::rules::{
    angle, asymmetric_enclosure, corner_to_corner, edge_enclosure, edge_facing_space, edge_width,
    eol_spacing, exact_pitch, forbidden, full_width, ir_drop, max_width, min_area, min_edge_length,
    min_enclosed_area, min_enclosure, min_extension, min_spacing, min_spacing_diff, min_width,
    missing_tie, must_be_inside, overlap, tip_spacing_table, wide_dependent_spacing,
};
use gpurify_check::deck::{Bound, BuildError, CompiledDeck, DeckBuilder, LayerRef};
use gpurify_geom::{Dbu, DbuArea, Grid, StrTable};
use gpurify_ingest::deck::StackSource;
use std::collections::HashMap;

fn nm(raw: i64) -> Dbu {
    Dbu::new_unchecked(raw)
}

fn nm2(raw: i64) -> DbuArea {
    DbuArea::new(i128::from(raw))
}

/// `pdks/generic_finfet.deck`, built on a 1 nm grid into `strings`.
#[allow(
    clippy::too_many_lines,
    reason = "a whole deck, statement by statement"
)]
pub fn build(strings: &mut StrTable) -> Result<CompiledDeck, BuildError> {
    let mut d = DeckBuilder::new(Grid::new(1000).expect("a 1 nm grid"), strings);
    let mut l: HashMap<&str, LayerRef> = HashMap::new();
    l.insert("WELL", d.layer("WELL", (1, 0)));
    l.insert("FIN", d.layer("FIN", (2, 0)));
    l.insert("GATE", d.layer("GATE", (7, 0)));
    l.insert("DUMMY", d.layer("DUMMY", (8, 0)));
    l.insert("GCUT", d.layer("GCUT", (10, 0)));
    l.insert("ACTIVE", d.layer("ACTIVE", (11, 0)));
    l.insert("NSELECT", d.layer("NSELECT", (12, 0)));
    l.insert("PSELECT", d.layer("PSELECT", (13, 0)));
    l.insert("SDT", d.layer("SDT", (88, 0)));
    l.insert("SLVT", d.layer("SLVT", (97, 0)));
    l.insert("LVT", d.layer("LVT", (98, 0)));
    l.insert("SRAMVT", d.layer("SRAMVT", (110, 0)));
    l.insert("LIG", d.layer("LIG", (16, 0)));
    l.insert("LISD", d.layer("LISD", (17, 0)));
    l.insert("V0", d.layer("V0", (18, 0)));
    l.insert("M1", d.layer("M1", (19, 0)));
    l.insert("V1", d.layer("V1", (21, 0)));
    l.insert("M2", d.layer("M2", (20, 0)));
    l.insert("V2", d.layer("V2", (25, 0)));
    l.insert("M3", d.layer("M3", (30, 0)));
    l.insert("V3", d.layer("V3", (35, 0)));
    l.insert("M4", d.layer("M4", (40, 0)));
    l.insert("V4", d.layer("V4", (45, 0)));
    l.insert("M5", d.layer("M5", (50, 0)));
    l.insert("V5", d.layer("V5", (55, 0)));
    l.insert("M6", d.layer("M6", (60, 0)));
    l.insert("V6", d.layer("V6", (65, 0)));
    l.insert("M7", d.layer("M7", (70, 0)));
    l.insert("V7", d.layer("V7", (75, 0)));
    l.insert("M8", d.layer("M8", (80, 0)));
    l.insert("V8", d.layer("V8", (85, 0)));
    l.insert("M9", d.layer("M9", (90, 0)));
    l.insert("V9", d.layer("V9", (95, 0)));
    l.insert("PAD", d.layer("PAD", (96, 0)));
    l.insert("SRAMDRC", d.layer("SRAMDRC", (99, 0)));
    l.insert("BOUNDARY", d.layer("BOUNDARY", (100, 0)));
    l.insert("M1_LABEL", d.layer("M1_LABEL", (19, 2)));
    l.insert("M2_LABEL", d.layer("M2_LABEL", (20, 2)));
    l.insert("M3_LABEL", d.layer("M3_LABEL", (30, 2)));
    l.insert("M4_LABEL", d.layer("M4_LABEL", (40, 2)));
    l.insert("M5_LABEL", d.layer("M5_LABEL", (50, 2)));
    l.insert("M6_LABEL", d.layer("M6_LABEL", (60, 2)));
    l.insert("M7_LABEL", d.layer("M7_LABEL", (70, 2)));
    l.insert("M8_LABEL", d.layer("M8_LABEL", (80, 2)));
    l.insert("M9_LABEL", d.layer("M9_LABEL", (90, 2)));
    l.insert(
        "GATE_UNCUT",
        d.derived("GATE_UNCUT", l["GATE"].not(l["GCUT"])),
    );
    l.insert(
        "CHANNEL",
        d.derived("CHANNEL", l["GATE_UNCUT"].and(l["ACTIVE"])),
    );
    l.insert(
        "GATE_FIELD",
        d.derived("GATE_FIELD", l["GATE_UNCUT"].not_interacting(l["ACTIVE"])),
    );
    l.insert(
        "ACTIVE_LOGIC",
        d.derived("ACTIVE_LOGIC", l["ACTIVE"].not_interacting(l["SRAMDRC"])),
    );
    l.insert(
        "ACTIVE_SRAM",
        d.derived("ACTIVE_SRAM", l["ACTIVE"].interacting(l["SRAMDRC"])),
    );
    l.insert(
        "ACTIVE_IN_WELL",
        d.derived(
            "ACTIVE_IN_WELL",
            l["ACTIVE"].outside(l["SRAMDRC"]).interacting(l["WELL"]),
        ),
    );
    l.insert(
        "ACTIVE_OUT_WELL",
        d.derived(
            "ACTIVE_OUT_WELL",
            l["ACTIVE"].outside(l["SRAMDRC"]).outside(l["WELL"]),
        ),
    );
    l.insert("SELECT", d.derived("SELECT", l["NSELECT"].or(l["PSELECT"])));
    l.insert(
        "SDT_LOGIC",
        d.derived("SDT_LOGIC", l["SDT"].not_interacting(l["SRAMDRC"])),
    );
    l.insert(
        "SDT_SRAM",
        d.derived("SDT_SRAM", l["SDT"].interacting(l["SRAMDRC"])),
    );
    l.insert(
        "LIG_LOGIC",
        d.derived("LIG_LOGIC", l["LIG"].outside(l["SRAMDRC"])),
    );
    l.insert(
        "LIG_SRAM",
        d.derived("LIG_SRAM", l["LIG"].interacting(l["SRAMDRC"])),
    );
    l.insert(
        "V0_LISD",
        d.derived(
            "V0_LISD",
            l["V0"].interacting(l["LISD"]).not_interacting(l["LIG"]),
        ),
    );
    l.insert(
        "V0_LIG",
        d.derived(
            "V0_LIG",
            l["V0"].interacting(l["LIG"]).not(l["V0"].inside(l["LISD"])),
        ),
    );
    l.insert("LIG_LISD", d.derived("LIG_LISD", l["LIG"].and(l["LISD"])));
    l.insert(
        "LIG_GATE",
        d.derived("LIG_GATE", l["LIG_LOGIC"].and(l["GATE_UNCUT"])),
    );
    l.insert(
        "LIG_GATE_SRAM",
        d.derived("LIG_GATE_SRAM", l["LIG_SRAM"].and(l["GATE_UNCUT"])),
    );
    l.insert(
        "V0_LIG_OVERLAP",
        d.derived("V0_LIG_OVERLAP", l["V0_LIG"].and(l["LIG"])),
    );
    l.insert(
        "GCUT_FREE_GATE",
        d.derived("GCUT_FREE_GATE", l["GATE"].not_interacting(l["GCUT"])),
    );
    l.insert(
        "ACTIVE_NSELECT",
        d.derived(
            "ACTIVE_NSELECT",
            l["ACTIVE_LOGIC"].interacting(l["NSELECT"]),
        ),
    );
    l.insert(
        "ACTIVE_PSELECT",
        d.derived(
            "ACTIVE_PSELECT",
            l["ACTIVE_LOGIC"].interacting(l["PSELECT"]),
        ),
    );
    l.insert(
        "ACTIVE_SLVT",
        d.derived("ACTIVE_SLVT", l["ACTIVE_LOGIC"].interacting(l["SLVT"])),
    );
    l.insert(
        "ACTIVE_LVT",
        d.derived("ACTIVE_LVT", l["ACTIVE_LOGIC"].interacting(l["LVT"])),
    );
    l.insert(
        "ACTIVE_SRAMVT",
        d.derived("ACTIVE_SRAMVT", l["ACTIVE_LOGIC"].interacting(l["SRAMVT"])),
    );
    l.insert(
        "NTAP",
        d.derived(
            "NTAP",
            l["ACTIVE"]
                .and(l["NSELECT"])
                .and(l["WELL"])
                .group()
                .not_interacting(l["GATE"]),
        ),
    );
    l.insert(
        "PTAP",
        d.derived(
            "PTAP",
            l["ACTIVE"]
                .and(l["PSELECT"])
                .group()
                .not(l["WELL"])
                .group()
                .not_interacting(l["GATE"]),
        ),
    );
    l.insert(
        "PMOS_ACTIVE",
        d.derived(
            "PMOS_ACTIVE",
            l["ACTIVE"]
                .and(l["PSELECT"])
                .and(l["WELL"])
                .group()
                .interacting(l["GATE"]),
        ),
    );
    l.insert(
        "NMOS_ACTIVE",
        d.derived(
            "NMOS_ACTIVE",
            l["ACTIVE"]
                .and(l["NSELECT"])
                .group()
                .not(l["WELL"])
                .group()
                .interacting(l["GATE"]),
        ),
    );
    d.rule("GEOMETRY.NONORTHOGONAL", angle(None, &[0, 90]));
    d.rule("WELL.W.2", min_width(l["WELL"], nm(54)));
    d.rule("WELL.S.2", min_spacing(l["WELL"], nm(54)));
    d.rule("WELL.A.1A", min_area(l["WELL"], nm2(5832)));
    d.rule("WELL.A.1B", min_enclosed_area(l["WELL"], nm2(5832)));
    d.rule("FIN.W.1", min_width(l["FIN"], nm(7)));
    d.rule("FIN.W.1.max", max_width(l["FIN"], nm(7)));
    d.rule("FIN.S.1.space", min_spacing(l["FIN"], nm(20)));
    d.rule("GATE.W.1", min_width(l["GATE"], nm(20)));
    d.rule("GATE.W.1.max", max_width(l["GATE"], nm(20)));
    d.rule("GATE.S.2", min_spacing(l["GATE"], nm(34)));
    d.rule(
        "GATE.ACTIVE.EX.1",
        min_extension(l["GATE_UNCUT"], l["ACTIVE"], nm(4)),
    );
    d.rule(
        "GATE.ACTIVE.EX.2",
        min_extension(l["ACTIVE"], l["GATE_UNCUT"], nm(25)),
    );
    d.rule(
        "GATE.ACTIVE.S.4",
        min_spacing_diff(l["ACTIVE"], l["GATE_FIELD"], nm(9)),
    );
    d.rule("ACTIVE.W.3", min_width(l["ACTIVE"], nm(16)));
    d.rule("ACTIVE.S.1", min_spacing(l["ACTIVE"], nm(27)));
    d.rule(
        "ACTIVE.FIN.EX.1",
        min_extension(l["ACTIVE"], l["FIN"], nm(10)),
    );
    d.rule(
        "ACTIVE.WELL.S.4",
        min_spacing_diff(l["ACTIVE_OUT_WELL"], l["WELL"], nm(27)),
    );
    d.rule(
        "ACTIVE.WELL.EN.1",
        min_enclosure(l["ACTIVE_IN_WELL"], l["WELL"], nm(27)),
    );
    d.rule("ACTIVE.A.1A", min_area(l["ACTIVE_LOGIC"], nm2(864)));
    d.rule(
        "ACTIVE.A.1B",
        min_enclosed_area(l["ACTIVE_LOGIC"], nm2(864)),
    );
    d.rule("SRAM.ACTIVE.A.2A", min_area(l["ACTIVE_SRAM"], nm2(432)));
    d.rule(
        "SRAM.ACTIVE.A.2B",
        min_enclosed_area(l["ACTIVE_SRAM"], nm2(432)),
    );
    d.rule(
        "ACTIVE.AUX.1",
        min_enclosure(l["ACTIVE"], l["SELECT"], nm(1)),
    );
    d.rule(
        "ACTIVE.LUP.1.PMOS",
        missing_tie(l["PMOS_ACTIVE"], l["NTAP"], nm(30000)),
    );
    d.rule(
        "ACTIVE.LUP.1.NMOS",
        missing_tie(l["NMOS_ACTIVE"], l["PTAP"], nm(30000)),
    );
    d.rule("GCUT.W.1", min_width(l["GCUT"], nm(17)));
    d.rule(
        "GCUT.ACTIVE.S.1",
        min_spacing_diff(l["GCUT"], l["CHANNEL"], nm(4)),
    );
    d.rule(
        "GCUT.GATE.EX.1",
        min_extension(l["GCUT"], l["GATE"], nm(17)),
    );
    d.rule(
        "GCUT.GATE.S.2",
        min_spacing_diff(l["GCUT"], l["GCUT_FREE_GATE"], nm(17)),
    );
    d.rule("NSELECT.W.2", min_width(l["NSELECT"], nm(54)));
    d.rule(
        "NSELECT.ACTIVE.EN.2",
        min_enclosure(l["ACTIVE_NSELECT"], l["NSELECT"], nm(27)),
    );
    d.rule(
        "NSELECT.GATE.EX.1",
        min_extension(l["NSELECT"], l["GATE_UNCUT"], nm(7)),
    );
    d.rule("PSELECT.W.2", min_width(l["PSELECT"], nm(54)));
    d.rule(
        "PSELECT.ACTIVE.EN.2",
        min_enclosure(l["ACTIVE_PSELECT"], l["PSELECT"], nm(27)),
    );
    d.rule(
        "PSELECT.GATE.EX.1",
        min_extension(l["PSELECT"], l["GATE_UNCUT"], nm(7)),
    );
    d.rule("SLVT.W.2", min_width(l["SLVT"], nm(54)));
    d.rule(
        "SLVT.ACTIVE.EN.2",
        min_enclosure(l["ACTIVE_SLVT"], l["SLVT"], nm(27)),
    );
    d.rule(
        "SLVT.GATE.EX.1",
        min_extension(l["SLVT"], l["GATE_UNCUT"], nm(7)),
    );
    d.rule("LVT.W.2", min_width(l["LVT"], nm(54)));
    d.rule(
        "LVT.ACTIVE.EN.2",
        min_enclosure(l["ACTIVE_LVT"], l["LVT"], nm(27)),
    );
    d.rule(
        "LVT.GATE.EX.1",
        min_extension(l["LVT"], l["GATE_UNCUT"], nm(7)),
    );
    d.rule("SRAMVT.W.2", min_width(l["SRAMVT"], nm(54)));
    d.rule(
        "SRAMVT.ACTIVE.EN.2",
        min_enclosure(l["ACTIVE_SRAMVT"], l["SRAMVT"], nm(27)),
    );
    d.rule(
        "SRAMVT.GATE.EX.1",
        min_extension(l["SRAMVT"], l["GATE_UNCUT"], nm(7)),
    );
    d.rule("SDT.W.1", min_width(l["SDT_LOGIC"], nm(24)));
    d.rule("SRAM.SDT.W.4", min_width(l["SDT_SRAM"], nm(17)));
    d.rule("SDT.GATE.S.2", min_spacing_diff(l["SDT"], l["GATE"], nm(5)));
    d.rule("LISD.W.1", min_width(l["LISD"], nm(24)));
    d.rule("LISD.S.1", min_spacing(l["LISD"], nm(18)));
    d.rule("LISD.S.2", eol_spacing(l["LISD"], nm(37), nm(25)));
    d.rule("LISD.A.1", min_area(l["LISD"], nm2(648)));
    d.rule("LIG.W.1", min_width(l["LIG"], nm(16)));
    d.rule("LIG.S.1", min_spacing(l["LIG"], nm(18)));
    d.rule("LIG.S.2", eol_spacing(l["LIG"], nm(37), nm(25)));
    d.rule(
        "LIG.GATE.S.10",
        min_spacing_diff(l["LIG"], l["CHANNEL"], nm(5)),
    );
    d.rule("LIG.A.1", min_area(l["LIG"], nm2(324)));
    d.rule("LIG.LISD.A.2", min_area(l["LIG_LISD"], nm2(128)));
    d.rule("LIG.GATE.A.3", min_area(l["LIG_GATE"], nm2(320)));
    d.rule("SRAM.LIG.GATE.A.4", min_area(l["LIG_GATE_SRAM"], nm2(240)));
    d.rule("LIG.LISD.OV.1", overlap(l["LIG"], l["LISD"], nm(8)));
    d.rule(
        "SRAM.LIG.GATE.OV.2",
        overlap(l["LIG_SRAM"], l["GATE_UNCUT"], nm(15)),
    );
    d.rule("V0.W.1", min_width(l["V0"], nm(18)));
    d.rule("V0.S.1", min_spacing(l["V0"], nm(18)));
    d.rule("V0.S.2", corner_to_corner(l["V0"], nm(23)));
    d.rule("V0.M1.EN.1", asymmetric_enclosure(l["V0"], l["M1"], nm(5)));
    d.rule(
        "V0.LISD.EN.2",
        asymmetric_enclosure(l["V0_LISD"], l["LISD"], nm(3)),
    );
    d.rule("V0.LIG.A.1", min_area(l["V0_LIG_OVERLAP"], nm2(288)));
    d.rule("M1.W.1", min_width(l["M1"], nm(18)));
    d.rule("M1.S.1", min_spacing(l["M1"], nm(18)));
    d.rule("M1.S.2", eol_spacing(l["M1"], nm(37), nm(25)));
    d.rule("M1.S.6", corner_to_corner(l["M1"], nm(20)));
    d.rule("M1.A.1", min_area(l["M1"], nm2(504)));
    d.rule("M2.W.1", min_width(l["M2"], nm(18)));
    d.rule("M2.S.1", min_spacing(l["M2"], nm(18)));
    d.rule("M2.S.2", eol_spacing(l["M2"], nm(37), nm(25)));
    d.rule("M2.S.6", corner_to_corner(l["M2"], nm(20)));
    d.rule("M2.A.1", min_area(l["M2"], nm2(504)));
    d.rule("M3.W.1", min_width(l["M3"], nm(18)));
    d.rule("M3.S.1", min_spacing(l["M3"], nm(18)));
    d.rule("M3.S.2", eol_spacing(l["M3"], nm(37), nm(25)));
    d.rule("M3.S.6", corner_to_corner(l["M3"], nm(20)));
    d.rule("M3.A.1", min_area(l["M3"], nm2(504)));
    d.rule("V1.W.1", min_width(l["V1"], nm(18)));
    d.rule("V1.S.1", min_spacing(l["V1"], nm(18)));
    d.rule("V1.S.2", corner_to_corner(l["V1"], nm(23)));
    d.rule("V2.W.1", min_width(l["V2"], nm(18)));
    d.rule("V2.S.1", min_spacing(l["V2"], nm(18)));
    d.rule("V2.S.2", corner_to_corner(l["V2"], nm(23)));
    d.rule("V3.W.1", min_width(l["V3"], nm(18)));
    d.rule("V3.S.1", min_spacing(l["V3"], nm(18)));
    d.rule("V3.S.2", corner_to_corner(l["V3"], nm(23)));
    d.rule("V1.M1.EN.1", asymmetric_enclosure(l["V1"], l["M1"], nm(5)));
    d.rule("V1.M1.EN.1.ALL", min_enclosure(l["V1"], l["M1"], nm(2)));
    d.rule("V2.M2.EN.1", asymmetric_enclosure(l["V2"], l["M2"], nm(5)));
    d.rule("V3.M3.EN.1", asymmetric_enclosure(l["V3"], l["M3"], nm(5)));
    d.rule("V1.M2.EN.2", asymmetric_enclosure(l["V1"], l["M2"], nm(5)));
    d.rule("V2.M3.EN.2", asymmetric_enclosure(l["V2"], l["M3"], nm(5)));
    d.rule("V3.M4.EN.2", asymmetric_enclosure(l["V3"], l["M4"], nm(11)));
    d.rule("M4.W.1", min_width(l["M4"], nm(24)));
    d.rule("M4.W.2", max_width(l["M4"], nm(480)));
    d.rule("M4.S.1", min_spacing(l["M4"], nm(24)));
    d.rule("M5.W.1", min_width(l["M5"], nm(24)));
    d.rule("M5.W.2", max_width(l["M5"], nm(480)));
    d.rule("M5.S.1", min_spacing(l["M5"], nm(24)));
    d.rule("M6.W.1", min_width(l["M6"], nm(32)));
    d.rule("M6.W.2", max_width(l["M6"], nm(640)));
    d.rule("M6.S.1", min_spacing(l["M6"], nm(32)));
    d.rule("M7.W.1", min_width(l["M7"], nm(32)));
    d.rule("M7.W.2", max_width(l["M7"], nm(640)));
    d.rule("M7.S.1", min_spacing(l["M7"], nm(32)));
    d.rule("M4.W.5", edge_width(l["M4"].edges().vertical(), nm(44)));
    d.rule(
        "M4.S.2",
        edge_facing_space(l["M4"].edges().vertical(), nm(40)),
    );
    d.rule("M5.W.5", edge_width(l["M5"].edges().horizontal(), nm(44)));
    d.rule(
        "M5.S.2",
        edge_facing_space(l["M5"].edges().horizontal(), nm(40)),
    );
    d.rule("V4.W.1", min_width(l["V4"], nm(24)));
    d.rule("V4.W.1.max", max_width(l["V4"], nm(24)));
    d.rule("V4.S.1", min_spacing(l["V4"], nm(33)));
    d.rule("V4.S.3", corner_to_corner(l["V4"], nm(33)));
    d.rule("V4.M4.EN.1", asymmetric_enclosure(l["V4"], l["M4"], nm(11)));
    d.rule("V4.M5.EN.2", asymmetric_enclosure(l["V4"], l["M5"], nm(11)));
    d.rule("V5.W.1", min_width(l["V5"], nm(24)));
    d.rule("V5.W.1.max", max_width(l["V5"], nm(24)));
    d.rule("V5.S.1", min_spacing(l["V5"], nm(33)));
    d.rule("V5.S.3", corner_to_corner(l["V5"], nm(33)));
    d.rule("V5.M5.EN.1", asymmetric_enclosure(l["V5"], l["M5"], nm(11)));
    d.rule("V5.M6.EN.2", asymmetric_enclosure(l["V5"], l["M6"], nm(11)));
    d.rule("V6.W.1", min_width(l["V6"], nm(32)));
    d.rule("V6.W.1.max", max_width(l["V6"], nm(32)));
    d.rule("V6.S.1", min_spacing(l["V6"], nm(45)));
    d.rule("V6.S.3", corner_to_corner(l["V6"], nm(45)));
    d.rule("V6.M6.EN.1", asymmetric_enclosure(l["V6"], l["M6"], nm(11)));
    d.rule("V6.M7.EN.2", asymmetric_enclosure(l["V6"], l["M7"], nm(11)));
    d.rule("V7.W.1", min_width(l["V7"], nm(32)));
    d.rule("V7.W.1.max", max_width(l["V7"], nm(32)));
    d.rule("V7.S.1", min_spacing(l["V7"], nm(45)));
    d.rule("V7.S.3", corner_to_corner(l["V7"], nm(45)));
    d.rule("V7.M7.EN.1", asymmetric_enclosure(l["V7"], l["M7"], nm(11)));
    d.rule("V7.M8.EN.2", asymmetric_enclosure(l["V7"], l["M8"], nm(11)));
    d.rule("M8.W.1", min_width(l["M8"], nm(40)));
    d.rule("M8.W.5", max_width(l["M8"], nm(2000)));
    d.rule("M8.S.1", min_spacing(l["M8"], nm(40)));
    d.rule("M8.S.4", wide_dependent_spacing(l["M8"], nm(60), nm(60)));
    d.rule("M8.S.5", wide_dependent_spacing(l["M8"], nm(80), nm(80)));
    d.rule("M8.S.6", wide_dependent_spacing(l["M8"], nm(120), nm(120)));
    d.rule("M8.S.7", wide_dependent_spacing(l["M8"], nm(500), nm(500)));
    d.rule(
        "M8.S.8",
        wide_dependent_spacing(l["M8"], nm(1000), nm(1000)),
    );
    d.rule("M8.A.1", min_area(l["M8"], nm2(7520)));
    d.rule("M8.L.1", min_edge_length(l["M8"], nm(40)));
    d.rule("M9.W.1", min_width(l["M9"], nm(40)));
    d.rule("M9.W.5", max_width(l["M9"], nm(2000)));
    d.rule("M9.S.1", min_spacing(l["M9"], nm(40)));
    d.rule("M9.S.4", wide_dependent_spacing(l["M9"], nm(60), nm(60)));
    d.rule("M9.S.5", wide_dependent_spacing(l["M9"], nm(80), nm(80)));
    d.rule("M9.S.6", wide_dependent_spacing(l["M9"], nm(120), nm(120)));
    d.rule("M9.S.7", wide_dependent_spacing(l["M9"], nm(500), nm(500)));
    d.rule(
        "M9.S.8",
        wide_dependent_spacing(l["M9"], nm(1000), nm(1000)),
    );
    d.rule("M9.A.1", min_area(l["M9"], nm2(7520)));
    d.rule("M9.L.1", min_edge_length(l["M9"], nm(40)));
    d.rule("V8.W.1", min_width(l["V8"], nm(40)));
    d.rule("V8.W.1.max", max_width(l["V8"], nm(40)));
    d.rule("V8.S.1", min_spacing(l["V8"], nm(57)));
    d.rule("V8.S.2", corner_to_corner(l["V8"], nm(57)));
    d.rule("V8.M8.EN.1", asymmetric_enclosure(l["V8"], l["M8"], nm(20)));
    d.rule("V8.M9.EN.2", asymmetric_enclosure(l["V8"], l["M9"], nm(20)));
    d.rule("V9.W.1", min_width(l["V9"], nm(40)));
    d.rule("V9.W.1.max", max_width(l["V9"], nm(40)));
    d.rule("V9.S.1", min_spacing(l["V9"], nm(57)));
    d.rule("V9.S.2", corner_to_corner(l["V9"], nm(57)));
    d.rule("V9.M9.EN.1", asymmetric_enclosure(l["V9"], l["M9"], nm(20)));
    d.rule(
        "V9.PAD.EN.2",
        asymmetric_enclosure(l["V9"], l["PAD"], nm(20)),
    );
    d.rule("ir_drop", ir_drop());
    d.conductors(&[
        l["M1"], l["M2"], l["M3"], l["M4"], l["M5"], l["M6"], l["M7"], l["M8"], l["M9"],
    ]);
    d.touch_within_layer();
    d.via(l["V1"], (l["M1"], l["M2"]));
    d.via(l["V2"], (l["M2"], l["M3"]));
    d.via(l["V3"], (l["M3"], l["M4"]));
    d.via(l["V4"], (l["M4"], l["M5"]));
    d.via(l["V5"], (l["M5"], l["M6"]));
    d.via(l["V6"], (l["M6"], l["M7"]));
    d.via(l["V7"], (l["M7"], l["M8"]));
    d.via(l["V8"], (l["M8"], l["M9"]));
    d.label(l["M1_LABEL"], l["M1"]);
    d.label(l["M2_LABEL"], l["M2"]);
    d.label(l["M3_LABEL"], l["M3"]);
    d.label(l["M4_LABEL"], l["M4"]);
    d.label(l["M5_LABEL"], l["M5"]);
    d.label(l["M6_LABEL"], l["M6"]);
    d.label(l["M7_LABEL"], l["M7"]);
    d.label(l["M8_LABEL"], l["M8"]);
    d.label(l["M9_LABEL"], l["M9"]);
    d.pex(
        l["M1"],
        StackSource {
            thickness_nm: 36.0,
            height_nm: 0.0,
            sheet_res_ohm_sq: 1.2675,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 0.0,
            tc: None,
        },
    );
    d.pex(
        l["V1"],
        StackSource {
            thickness_nm: 36.0,
            height_nm: 36.0,
            sheet_res_ohm_sq: 17.2,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 0.0,
            tc: None,
        },
    );
    d.pex(
        l["M2"],
        StackSource {
            thickness_nm: 36.0,
            height_nm: 72.0,
            sheet_res_ohm_sq: 0.534829,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 0.0,
            tc: None,
        },
    );
    d.pex(
        l["V2"],
        StackSource {
            thickness_nm: 36.0,
            height_nm: 108.0,
            sheet_res_ohm_sq: 17.2,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 0.0,
            tc: None,
        },
    );
    d.pex(
        l["M3"],
        StackSource {
            thickness_nm: 36.0,
            height_nm: 144.0,
            sheet_res_ohm_sq: 0.563166,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 0.0,
            tc: None,
        },
    );
    d.pex(
        l["V3"],
        StackSource {
            thickness_nm: 36.0,
            height_nm: 180.0,
            sheet_res_ohm_sq: 17.2,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 0.0,
            tc: None,
        },
    );
    d.pex(
        l["M4"],
        StackSource {
            thickness_nm: 48.0,
            height_nm: 216.0,
            sheet_res_ohm_sq: 0.432876,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 0.0,
            tc: None,
        },
    );
    d.pex(
        l["V4"],
        StackSource {
            thickness_nm: 48.0,
            height_nm: 264.0,
            sheet_res_ohm_sq: 11.8,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 0.0,
            tc: None,
        },
    );
    d.pex(
        l["M5"],
        StackSource {
            thickness_nm: 48.0,
            height_nm: 312.0,
            sheet_res_ohm_sq: 0.455844,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 0.0,
            tc: None,
        },
    );
    d.pex(
        l["V5"],
        StackSource {
            thickness_nm: 48.0,
            height_nm: 360.0,
            sheet_res_ohm_sq: 11.8,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 0.0,
            tc: None,
        },
    );
    d.pex(
        l["M6"],
        StackSource {
            thickness_nm: 64.0,
            height_nm: 408.0,
            sheet_res_ohm_sq: 0.380147,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 0.0,
            tc: None,
        },
    );
    d.pex(
        l["V6"],
        StackSource {
            thickness_nm: 64.0,
            height_nm: 472.0,
            sheet_res_ohm_sq: 8.2,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 0.0,
            tc: None,
        },
    );
    d.pex(
        l["M7"],
        StackSource {
            thickness_nm: 64.0,
            height_nm: 536.0,
            sheet_res_ohm_sq: 0.400307,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 0.0,
            tc: None,
        },
    );
    d.pex(
        l["V7"],
        StackSource {
            thickness_nm: 64.0,
            height_nm: 600.0,
            sheet_res_ohm_sq: 8.2,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 0.0,
            tc: None,
        },
    );
    d.pex(
        l["M8"],
        StackSource {
            thickness_nm: 80.0,
            height_nm: 664.0,
            sheet_res_ohm_sq: 0.337906,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 0.0,
            tc: None,
        },
    );
    d.pex(
        l["V8"],
        StackSource {
            thickness_nm: 80.0,
            height_nm: 744.0,
            sheet_res_ohm_sq: 6.3,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 0.0,
            tc: None,
        },
    );
    d.pex(
        l["M9"],
        StackSource {
            thickness_nm: 80.0,
            height_nm: 824.0,
            sheet_res_ohm_sq: 0.355822,
            area_cap_af_um2: 0.0,
            fringe_cap_af_um: 0.0,
            dielectric_k: 0.0,
            tc: None,
        },
    );
    d.rule(
        "GCUT.AUX.1",
        forbidden(l["GCUT"].not_interacting(l["GATE"])),
    );
    d.rule(
        "NSELECT.PSELECT.AUX.1",
        forbidden(l["NSELECT"].and(l["PSELECT"])),
    );
    d.rule(
        "VT.AUX.2",
        forbidden(
            l["SLVT"]
                .and(l["LVT"])
                .group()
                .or(l["SLVT"].and(l["SRAMVT"]).group())
                .or(l["LVT"].and(l["SRAMVT"]).group()),
        ),
    );
    d.rule("SDT.ACTIVE.AUX.3", forbidden(l["SDT"].outside(l["ACTIVE"])));
    d.rule("SDT.LISD.AUX.4", must_be_inside(l["SDT"], l["LISD"]));
    d.rule(
        "SRAM.ACTIVE.AUX.2",
        forbidden(l["ACTIVE"].outside(l["SRAMDRC"]).interacting(l["SRAMDRC"])),
    );
    // Rules the chosen-edge, table, pitch and shape-class kinds express.
    let vertical = |n: &str| l[n].edges().vertical();
    let horizontal = |n: &str| l[n].edges().horizontal();
    // A vertical edge of `layer` inside, or on the edge of, GATE.
    let on_gate = |layer: &str| {
        l[layer]
            .edges()
            .vertical()
            .inside_part(l["GATE"])
            .or(l[layer].edges().vertical().and(l["GATE"].edges()).group())
    };
    d.rule("WELL.W.1", edge_width(vertical("WELL"), nm(108)));
    d.rule("WELL.S.1", edge_facing_space(horizontal("WELL"), nm(108)));
    d.rule("FIN.W.2", edge_width(vertical("FIN"), nm(108)));
    d.rule("FIN.S.1", exact_pitch(l["FIN"], true, nm(27)));
    d.rule("FIN.AUX.1", forbidden(l["FIN"].non_rectangles()));
    d.rule("GATE.W.2", edge_width(horizontal("GATE"), nm(40)));
    d.rule("GATE.S.1", exact_pitch(l["GATE"], false, nm(54)));
    d.rule("GATE.AUX.1", forbidden(l["GATE"].non_rectangles()));
    d.rule("GATE.ACTIVE.AUX.3", forbidden(on_gate("ACTIVE")));
    d.rule("ACTIVE.W.1", edge_width(horizontal("ACTIVE"), nm(27)));
    d.rule("ACTIVE.S.2B", edge_facing_space(vertical("ACTIVE"), nm(38)));
    d.rule("GCUT.S.3", edge_facing_space(horizontal("GCUT"), nm(35)));
    d.rule("GCUT.AUX.2", forbidden(on_gate("GCUT")));
    for (layer, active) in [
        ("NSELECT", "ACTIVE_NSELECT"),
        ("PSELECT", "ACTIVE_PSELECT"),
        ("SLVT", "ACTIVE_SLVT"),
        ("LVT", "ACTIVE_LVT"),
        ("SRAMVT", "ACTIVE_SRAMVT"),
    ] {
        d.rule(
            &format!("{layer}.W.1"),
            edge_width(vertical(layer), nm(108)),
        );
        d.rule(
            &format!("{layer}.ACTIVE.EN.1"),
            edge_enclosure(vertical(active), l[layer], nm(46)),
        );
    }
    d.rule("SDT.W.2", edge_width(horizontal("SDT_LOGIC"), nm(27)));
    d.rule("SDT.S.1", edge_facing_space(vertical("SDT"), nm(30)));
    for (id, sdt, other, limit) in [
        ("SDT.ACTIVE.OV.1", "SDT_LOGIC", "ACTIVE", 27),
        ("SDT.LISD.OV.2", "SDT_LOGIC", "LISD", 27),
        ("SRAM.SDT.ACTIVE.OV.3", "SDT_SRAM", "ACTIVE", 17),
        ("SRAM.SDT.LISD.OV.4", "SDT_SRAM", "LISD", 17),
    ] {
        let shared = l[sdt].and(l[other]).group();
        d.rule(id, edge_width(shared.edges().horizontal(), nm(limit)));
    }
    d.rule(
        "SDT.ACTIVE.AUX.2",
        forbidden(horizontal("SDT_LOGIC").not(horizontal("ACTIVE"))),
    );
    let tips = [nm(0), nm(24), nm(37)];
    let (s18, s25, s27, s31) = (nm(18), nm(25), nm(27), nm(31));
    d.rule(
        "LISD.S.3",
        tip_spacing_table(
            l["LISD"].outside(l["SRAMDRC"]),
            &tips,
            &[s18, s18, s25, s18, s27, s25, s25, s25, s18],
        ),
    );
    d.rule(
        "SRAM.LISD.S.4",
        tip_spacing_table(
            l["LISD"].interacting(l["SRAMDRC"]),
            &[nm(0), nm(37)],
            &[s27, s25, s25, s18],
        ),
    );
    let euv = [s31, s31, s25, s31, s27, s25, s25, s25, s18];
    d.rule("LIG.S.3", tip_spacing_table(l["LIG_LOGIC"], &tips, &euv));
    d.rule("LIG.GATE.AUX.1", forbidden(on_gate("LIG_LOGIC")));
    d.rule("V0.M1.AUX.3", full_width(l["V0"], l["M1"]));
    for m in ["M1", "M2", "M3"] {
        d.rule(&format!("{m}.S.3"), tip_spacing_table(l[m], &tips, &euv));
    }
    for (v, above) in [("V1", "M2"), ("V2", "M3"), ("V3", "M4")] {
        d.rule(&format!("{v}.{above}.AUX.2"), full_width(l[v], l[above]));
    }
    for m in ["M4", "M5", "M6", "M7"] {
        d.rule(&format!("{m}.AUX.3"), forbidden(l[m].non_rectangles()));
    }
    d.rule("M6.W.5", edge_width(vertical("M6"), nm(44)));
    d.rule("M6.S.2", edge_facing_space(vertical("M6"), nm(40)));
    d.rule("M7.W.5", edge_width(horizontal("M7"), nm(44)));
    d.rule("M7.S.2", edge_facing_space(horizontal("M7"), nm(40)));
    for (v, above) in [("V4", "M5"), ("V5", "M6"), ("V6", "M7"), ("V7", "M8")] {
        d.rule(&format!("{v}.{above}.AUX.2"), full_width(l[v], l[above]));
    }
    for m in ["M8", "M9"] {
        d.rule(
            &format!("{m}.S.2"),
            tip_spacing_table(l[m], &[nm(0), nm(80)], &[nm(46), nm(43), nm(43), nm(40)]),
        );
        for (w, from, below, limit) in [
            ("W.2", 400, Some(1200), 60),
            ("W.3", 1200, Some(1800), 80),
            ("W.4", 1800, None, 120),
        ] {
            let mut bounds = vec![Bound::AtLeast(nm(from))];
            bounds.extend(below.map(|b| Bound::Below(nm(b))));
            d.rule(
                &format!("{m}.{w}"),
                min_width(l[m].with_bbox_max(&bounds), nm(limit)),
            );
        }
    }
    d.finish()
}
