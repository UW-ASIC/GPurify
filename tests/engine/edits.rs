//! Layout edits the deck configures: density fill (FLOW-007) and DRC-clean
//! enhancement (FLOW-009), each written as GDSII and checked again by the
//! deck it was made for.

use gpurify::engine::enhance::enhance_gds;
use gpurify::engine::fill::fill_gds;
use gpurify::engine::pipeline::{load, Inputs};
use gpurify::engine::run::{run, Checks, RunOptions};
use gpurify::engine::Outputs;
use gpurify_geom::{Bbox, GeometryStoreBuilder, Grid};
use gpurify_ingest::deck::parse_deck;
use gpurify_ingest::StrTable;
use gpurify_testgen::gds::{write_store_labelled, Label};
use gpurify_testgen::shapes::dbu;
use std::collections::BTreeMap;
use std::path::PathBuf;

/// A rectangle in nm on a deck layer, by name.
pub type Rect<'a> = (&'a str, i64, i64, i64, i64);

/// Writes `deck` and a one-cell layout of `rects` and `labels` (layer,
/// text, x, y) into a scratch directory named `tag`.
pub fn layout(tag: &str, deck: &str, rects: &[Rect], labels: &[(&str, &str, i64, i64)]) -> Inputs {
    let dir = std::env::temp_dir().join(format!("gpurify-edits-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let mut strings = StrTable::default();
    let grid = Grid::new(1000).expect("a 1 nm grid");
    let parsed = parse_deck(deck, grid, &mut strings).expect("the test deck parses");
    let id = |name: &str| parsed.layers.id(&strings, name).expect("a deck layer");
    let mut builder = GeometryStoreBuilder::default();
    for &(layer, xlo, ylo, xhi, yhi) in rects {
        builder.push(
            id(layer),
            &[xlo, xhi, xhi, xlo].map(dbu),
            &[ylo, ylo, yhi, yhi].map(dbu),
        );
    }
    let (store, _) = builder.finish(parsed.layers.len());
    let labels: Vec<Label> = (labels.iter())
        .map(|&(layer, text, x, y)| Label {
            layer: id(layer),
            x,
            y,
            text,
        })
        .collect();
    let mut bytes = Vec::new();
    write_store_labelled(&store, &parsed.layers, &labels, "top", &mut bytes)
        .expect("the layout writes");
    std::fs::write(dir.join("in.gds"), bytes).expect("writable");
    std::fs::write(dir.join("test.deck"), deck).expect("writable");
    Inputs {
        layout: dir.join("in.gds"),
        deck: dir.join("test.deck"),
        ..Inputs::default()
    }
}

/// `inputs` with `bytes` as its layout, written beside the input.
fn written(inputs: &Inputs, bytes: &[u8]) -> Inputs {
    let out: PathBuf = inputs.layout.with_file_name("out.gds");
    std::fs::write(&out, bytes).expect("writable");
    Inputs {
        layout: out,
        ..inputs.clone()
    }
}

/// The boxes on `layer`, in nm, sorted.
fn boxes(inputs: &Inputs, layer: &str) -> Vec<(i64, i64, i64, i64)> {
    let loaded = load(inputs).expect("the layout loads");
    let id = (loaded.deck.layers.id(&loaded.strings, layer)).expect("a deck layer");
    let mut out: Vec<_> = (loaded.store.layer_bboxes(id).iter())
        .map(|b: &Bbox| (b.xlo.raw(), b.ylo.raw(), b.xhi.raw(), b.yhi.raw()))
        .collect();
    out.sort_unstable();
    out
}

/// DRC of `inputs`: findings per rule id.
pub fn drc(inputs: &Inputs) -> (Outputs, BTreeMap<String, usize>) {
    let options = RunOptions {
        checks: Checks {
            drc: true,
            erc: false,
            lvs: false,
            pex: false,
        },
        lvs: gpurify_check::lvs::CompareOptions::default(),
        quasistatic_nets: Vec::new(),
    };
    let (loaded, _, outputs, _) = run(inputs, &options).expect("DRC runs");
    let mut per_rule = BTreeMap::new();
    for row in 0..outputs.violations.len() {
        let name = loaded
            .strings
            .resolve(outputs.violations.rule[row])
            .to_owned();
        *per_rule.entry(name).or_insert(0) += 1;
    }
    (outputs, per_rule)
}

/// A 10 um die (a boundary layer), met1 down its left 2 um, density read
/// over met1 and its fill. `extra` adds rules or overrides the window.
fn fill_deck(window: &str, max: &str, extra: &str) -> String {
    format!(
        "grid 1nm
layer met1 = gds(1, 0)
layer fill1 = gds(1, 1)
layer nofill = gds(2, 0)
layer die = gds(3, 0)
layer m1all = met1 or fill1
rule pd.min density(m1all, die; window: {window}, step: {window}) >= 0.3
rule pd.max density(m1all, die; window: {window}, step: {window}) <= {max}
rule f.w width(fill1) >= 1um
rule f.s space(fill1) >= 1um
rule f.d space(fill1, met1) >= 1um
rule f.x forbidden(fill1 and nofill)
fill fill1 for m1all size 1um space 1um keep 1um avoid [met1, nofill]
{extra}
"
    )
}

const DIE: Rect = ("die", 0, 0, 10_000, 10_000);
const MET1: Rect = ("met1", 0, 0, 2_000, 10_000);

/// The squares at these (x, y) corners, in um.
fn squares(corners: &[(i64, i64)]) -> Vec<(i64, i64, i64, i64)> {
    let mut out: Vec<_> = (corners.iter())
        .map(|&(x, y)| (x * 1000, y * 1000, x * 1000 + 1000, y * 1000 + 1000))
        .collect();
    out.sort_unstable();
    out
}

/// Proves catalog FLOW-007: fill brings a short window up to its minimum
/// and the filled layout passes the deck's own DRC.
///
/// Oracle: hand-derived. One 10 um window holds met1's 20 um² of 100; the
/// sites are 1 um squares on a 2 um pitch from the die's corner, and those
/// at x = 0 and 2 um are within 1 um of met1, which leaves the columns at
/// 4, 6 and 8 um. Ten squares bring the window to exactly 0.3, so fill
/// stops at the tenth, taken row by row from the bottom: three rows of
/// three and (4, 6). And a law: the output has no DRC finding at all,
/// density, fill width and spacing, fill to metal, no-fill overlap
/// included. Filling every free site (15), or blocking at `keep` as a
/// strict gap, breaks the count.
#[test]
fn fill_tops_a_window_up_to_its_minimum_and_the_result_is_drc_clean() {
    let inputs = layout("min", &fill_deck("10um", "0.6", ""), &[DIE, MET1], &[]);
    let (bytes, counts) = fill_gds(&inputs, &[]).expect("fill runs");
    assert_eq!(counts, [10]);
    let out = written(&inputs, &bytes);
    let mut want: Vec<(i64, i64)> = [0, 2, 4]
        .into_iter()
        .flat_map(|y| [4, 6, 8].map(|x| (x, y)))
        .collect();
    want.push((4, 6));
    assert_eq!(boxes(&out, "fill1"), squares(&want));
    let (outputs, per_rule) = drc(&out);
    assert!(per_rule.is_empty(), "{per_rule:?} {outputs:?}");
    // The input is short of the minimum: the fill is what fixed it.
    assert_eq!(drc(&inputs).1.get("pd.min"), Some(&1));
}

/// Fill never passes a maximum, even short of the minimum.
///
/// Oracle: hand-derived. With the maximum at 0.25 over met1's 0.2, five
/// squares of 1 % each reach it exactly (legal, a limit is inclusive) and a
/// sixth would pass it: (4, 0), (6, 0), (8, 0), (4, 2), (6, 2). The window
/// stays below its 0.3 minimum, which the deck's rule reports, and the
/// maximum holds.
#[test]
fn fill_stops_at_a_maximum_even_below_the_minimum() {
    let inputs = layout("max", &fill_deck("10um", "0.25", ""), &[DIE, MET1], &[]);
    let (bytes, counts) = fill_gds(&inputs, &[]).expect("fill runs");
    assert_eq!(counts, [5]);
    let out = written(&inputs, &bytes);
    assert_eq!(
        boxes(&out, "fill1"),
        squares(&[(4, 0), (6, 0), (8, 0), (4, 2), (6, 2)])
    );
    let per_rule = drc(&out).1;
    assert_eq!(per_rule.get("pd.min"), Some(&1), "{per_rule:?}");
    assert_eq!(per_rule.get("pd.max"), None, "{per_rule:?}");
}

/// Fill keeps out of a no-fill region by `keep`, and each window is filled
/// on its own.
///
/// Oracle: hand-derived. A no-fill box over x = 7 to 10 um blocks the
/// sites closer than 1 um, the columns at 6 and 8 um, leaving x = 4 um:
/// five squares, 25 %, short of the minimum (one finding), none on the
/// no-fill box. With 5 um windows (2 x 2, met1 giving the left two 40 %),
/// only the right two want fill, and only from the sites inside them, x =
/// 6 and 8 um: three rows in the lower (6 squares, 24 %) and two in the
/// upper (4, 16 %), both still short, the left column untouched.
#[test]
fn fill_avoids_no_fill_regions_and_fills_window_by_window() {
    let blocked = ("nofill", 7_000, 0, 10_000, 10_000);
    let inputs = layout(
        "nofill",
        &fill_deck("10um", "0.6", ""),
        &[DIE, MET1, blocked],
        &[],
    );
    let (bytes, counts) = fill_gds(&inputs, &[]).expect("fill runs");
    assert_eq!(counts, [5]);
    let out = written(&inputs, &bytes);
    let column: Vec<(i64, i64)> = [0, 2, 4, 6, 8].map(|y| (4, y)).to_vec();
    assert_eq!(boxes(&out, "fill1"), squares(&column));
    let per_rule = drc(&out).1;
    assert_eq!(
        (per_rule.get("pd.min"), per_rule.get("f.x")),
        (Some(&1), None)
    );

    let inputs = layout("windows", &fill_deck("5um", "0.6", ""), &[DIE, MET1], &[]);
    let (bytes, counts) = fill_gds(&inputs, &[]).expect("fill runs");
    assert_eq!(counts, [10]);
    let out = written(&inputs, &bytes);
    let right: Vec<(i64, i64)> = [0, 2, 4, 6, 8]
        .into_iter()
        .flat_map(|y| [6, 8].map(|x| (x, y)))
        .collect();
    assert_eq!(boxes(&out, "fill1"), squares(&right));
    assert_eq!(drc(&out).1.get("pd.min"), Some(&2));
}

/// A deck whose `fill` line names a layer no density rule measures is
/// refused: nothing would say how much to fill.
///
/// Oracle: the refusal `docs/deck.md` states for a `fill` line.
#[test]
fn fill_without_a_density_rule_is_refused() {
    let deck = fill_deck("10um", "0.6", "").replace("for m1all", "for met1");
    let inputs = layout("norule", &deck, &[DIE, MET1], &[]);
    let error = fill_gds(&inputs, &[]).expect_err("no rule measures met1");
    assert!(error.to_string().contains("no density"), "{error}");
}

/// Two metals joined by vias, a redundant-via rule on them, and a strap.
fn enhance_deck(extra: &str) -> String {
    format!(
        "grid 1nm
layer met1 = gds(1, 0)
layer via1 = gds(2, 0)
layer met2 = gds(3, 0)
layer m1lbl = gds(1, 5)
connect conductors [met1, met2]
connect touch_within_layer
connect via via1 [met1, met2]
connect label m1lbl names met1
rule v.r via_redundancy(via1, met1, met2; pitch: 200nm, space: 100nm) >= 1
rule v.s space(via1) >= 100nm
rule m1.s space(met1) >= 140nm
{extra}
"
    )
}

/// A redundant cut goes where the deck's `via_redundancy` rule finds room,
/// and is kept only when it adds no finding.
///
/// Oracle: hand-derived. A 100 nm cut at (0, 0) on met1 and met2 plates
/// 500 x 100 nm (x from 0) has room only to its right, moved one 200 nm
/// pitch: the cut (200, 0)-(300, 100), 100 nm from the first (the space).
/// The via has room, so the rule's rate is 1 before and after (no `v.r`
/// finding), and the output is clean. With `enclosure(via1, met1) >=
/// 10nm` in the deck the new cut is 0 nm from met1's edge, as the old one
/// is: a finding the input lacked at a new place, so the cut is taken back
/// and the output's findings are the input's.
#[test]
fn a_redundant_cut_is_added_where_the_rule_finds_room_and_taken_back_on_a_new_finding() {
    let rects = [
        ("met1", 0, 0, 500, 100),
        ("met2", 0, 0, 500, 100),
        ("via1", 0, 0, 100, 100),
    ];
    let inputs = layout("cut", &enhance_deck(""), &rects, &[]);
    assert!(drc(&inputs).1.is_empty(), "{:?}", drc(&inputs).1);
    let (bytes, kept) = enhance_gds(&inputs, &[]).expect("enhance runs");
    assert_eq!((kept.cuts, kept.sides), (1, 0));
    let out = written(&inputs, &bytes);
    assert_eq!(boxes(&out, "via1"), [(0, 0, 100, 100), (200, 0, 300, 100)]);
    assert!(drc(&out).1.is_empty(), "{:?}", drc(&out).1);

    let enclosed = enhance_deck("rule v.e enclosure(via1, met1) >= 10nm");
    let inputs = layout("cut-back", &enclosed, &rects, &[]);
    let before = drc(&inputs).1;
    let (bytes, kept) = enhance_gds(&inputs, &[]).expect("enhance runs");
    assert_eq!(kept.cuts, 0);
    let out = written(&inputs, &bytes);
    assert_eq!(boxes(&out, "via1"), [(0, 0, 100, 100)]);
    assert_eq!(drc(&out).1, before);
}

/// Proves catalog FLOW-009: a dead via, with no room for a second cut,
/// gets one with the metal it needs, and the redundant-via rate rises.
///
/// Oracle: hand-derived. A 100 nm cut at (0, 0) on met1 and met2 pads
/// that enclose it by 20 nm (-20 to 120 nm square) is dead: no neighbour
/// one 200 nm pitch away lies on the pads, so the rate is 0, one `v.r`
/// finding. The first neighbour, to the right, is (200, 0)-(300, 100); each
/// metal gets the box round both cuts grown by its own 20 nm margin,
/// (-20, -20)-(320, 120), so the new cut is enclosed by 20 nm as the old
/// is (`v.e` holds). The output's rate is 1: no finding at all.
#[test]
fn a_dead_via_gets_a_second_cut_and_its_metal_and_the_rate_rises() {
    let deck = enhance_deck("rule v.e enclosure(via1, met1) >= 20nm");
    let rects = [
        ("met1", -20, -20, 120, 120),
        ("met2", -20, -20, 120, 120),
        ("via1", 0, 0, 100, 100),
    ];
    let inputs = layout("dead", &deck, &rects, &[]);
    let (outputs, per_rule) = drc(&inputs);
    assert_eq!(per_rule.get("v.r"), Some(&1), "{per_rule:?}");
    assert_eq!(
        outputs.violations.measured[0],
        gpurify_check::report::Measurement::Ratio(0.0)
    );
    let (bytes, kept) = enhance_gds(&inputs, &[]).expect("enhance runs");
    assert_eq!(kept.cuts, 1);
    let out = written(&inputs, &bytes);
    assert_eq!(boxes(&out, "via1"), [(0, 0, 100, 100), (200, 0, 300, 100)]);
    for metal in ["met1", "met2"] {
        assert_eq!(
            boxes(&out, metal),
            [(-20, -20, 120, 120), (-20, -20, 320, 120)],
            "{metal}"
        );
    }
    assert!(drc(&out).1.is_empty(), "{:?}", drc(&out).1);
}

/// The rate `v.r` measures: 1 when the rule reports nothing.
fn rate(outputs: &Outputs, strings: &gpurify_ingest::StrTable) -> f64 {
    (0..outputs.violations.len())
        .find(|&row| strings.resolve(outputs.violations.rule[row]) == "v.r")
        .map_or(1.0, |row| match outputs.violations.measured[row] {
            gpurify_check::report::Measurement::Ratio(r) => r,
            other => panic!("v.r measures a ratio, not {other:?}"),
        })
}

/// One seed: random vias, pads and wires; enhance; the laws.
fn enhance_laws(seed: u64) {
    let mut rng = gpurify_testgen::rng::Rng::new(seed);
    let deck = enhance_deck(
        "rule v.e enclosure(via1, met1) >= 20nm
rule m2.s space(met2) >= 140nm
widen met1 net \"V*\" by 100nm",
    );
    let mut rects: Vec<(&str, i64, i64, i64, i64)> = Vec::new();
    let mut labels = Vec::new();
    for _ in 0..rng.range(1, 8) {
        let (x, y) = (rng.range(0, 40) * 100, rng.range(0, 40) * 100);
        rects.push(("via1", x, y, x + 100, y + 100));
        for metal in ["met1", "met2"] {
            let e = [0, 1, 2, 3].map(|_| rng.range(0, 4) * 20);
            let long = rng.below(3) == 0;
            let reach = if long { rng.range(2, 8) * 100 } else { 0 };
            rects.push((
                metal,
                x - e[0],
                y - e[1],
                x + 100 + e[2] + reach,
                y + 100 + e[3],
            ));
        }
    }
    for k in 0..rng.range(0, 4) {
        let (x, y) = (rng.range(0, 40) * 100, rng.range(0, 40) * 100);
        let w = rng.range(2, 6) * 100;
        rects.push(("met1", x, y, x + w, y + 2_000));
        if k == 0 {
            labels.push(("m1lbl", "VDD", x + w / 2, y + 1_000));
        }
    }
    let inputs = layout(&format!("law{seed}"), &deck, &rects, &labels);
    let Ok(before) = gpurify::engine::run::run(
        &inputs,
        &RunOptions {
            checks: Checks {
                drc: true,
                erc: false,
                lvs: false,
                pex: false,
            },
            lvs: gpurify_check::lvs::CompareOptions::default(),
            quasistatic_nets: Vec::new(),
        },
    ) else {
        // A label on two touching shapes of different names, say.
        return;
    };
    let (bytes, kept) = enhance_gds(&inputs, &[]).expect("enhance runs");
    let out = written(&inputs, &bytes);
    let after = gpurify::engine::run::run(
        &out,
        &RunOptions {
            checks: Checks {
                drc: true,
                erc: false,
                lvs: false,
                pex: false,
            },
            lvs: gpurify_check::lvs::CompareOptions::default(),
            quasistatic_nets: Vec::new(),
        },
    )
    .expect("the output runs");
    let place = |loaded: &gpurify::engine::Loaded, outputs: &Outputs| {
        let mut set: BTreeMap<(String, i64, i64), usize> = BTreeMap::new();
        for row in 0..outputs.violations.len() {
            let rule = loaded
                .strings
                .resolve(outputs.violations.rule[row])
                .to_owned();
            if rule == "v.r" {
                continue;
            }
            let at = outputs.violations.at[row];
            *set.entry((rule, at.x.raw(), at.y.raw())).or_insert(0) += 1;
        }
        set
    };
    let (was, now) = (place(&before.0, &before.2), place(&after.0, &after.2));
    for (key, n) in &now {
        assert!(
            was.get(key).is_some_and(|w| w >= n),
            "seed {seed}: new {key:?}"
        );
    }
    assert!(
        rate(&after.2, &after.0.strings) >= rate(&before.2, &before.0.strings),
        "seed {seed}: the rate fell"
    );
    assert_eq!(
        after.1.nets.net_count(),
        before.1.nets.net_count(),
        "seed {seed}: nets joined"
    );
    let cuts = |inputs: &Inputs| boxes(inputs, "via1").len();
    assert_eq!(cuts(&out), cuts(&inputs) + kept.cuts, "seed {seed}");
}

/// Proves catalog FLOW-009 as a law over random layouts.
///
/// Oracle: law. On 15 random layouts of vias (pads of random enclosure,
/// some on long wires), loose met1 wires and a labelled supply strap, the
/// enhanced layout has no finding the input lacked (rule and place), a
/// redundant-via rate no lower, the same number of nets, and exactly the
/// input's cuts plus those it says it added. Dropping the rollback breaks
/// it; the candidates' net filter is pinned by the strap test, and the
/// loop's net count stands behind it here.
#[test]
fn enhancement_adds_no_finding_and_never_lowers_the_rate() {
    for seed in 0..15 {
        enhance_laws(seed);
    }
}

/// The same laws at nightly depth: 300 layouts.
///
/// Oracle: law, as `enhancement_adds_no_finding_and_never_lowers_the_rate`.
#[test]
#[ignore = "nightly depth: cargo test --test engine -- --ignored"]
fn enhancement_adds_no_finding_and_never_lowers_the_rate_nightly() {
    for seed in 15..315 {
        enhance_laws(seed);
    }
}

/// A strap widens on a side only where that adds no finding and touches
/// no other net.
///
/// Oracle: hand-derived. A 1 um wide vertical VPWR strap (x 0 to 1 um) on
/// met1, widened 200 nm a side: its left strip is clear and kept; on its
/// right a met1 wire of another net 300 nm away would be 100 nm from the
/// strip, under `m1.s` (140 nm), so that side is taken back: the strap
/// becomes x -200 nm to 1 um. A strap whose net matches no pattern, and a
/// strip that would touch another net (the wire 150 nm away, touching a
/// 200 nm strip), are never candidates.
#[test]
fn a_strap_widens_only_where_no_finding_follows() {
    let deck = enhance_deck("widen met1 net \"VP*\" by 200nm");
    let rects = [
        ("met1", 0, 0, 1_000, 10_000),
        ("met1", 1_300, 0, 1_500, 10_000),
    ];
    let labels = [
        ("m1lbl", "VPWR", 500, 5_000),
        ("m1lbl", "sig", 1_400, 5_000),
    ];
    let inputs = layout("strap", &deck, &rects, &labels);
    let (bytes, kept) = enhance_gds(&inputs, &[]).expect("enhance runs");
    assert_eq!((kept.cuts, kept.sides), (0, 1));
    let out = written(&inputs, &bytes);
    let loaded = load(&out).expect("loads");
    let met1 = loaded
        .deck
        .layers
        .id(&loaded.strings, "met1")
        .expect("met1");
    let rows = loaded.store.layer_bboxes(met1);
    assert_eq!(rows.len(), 3, "the strip is its own boundary");
    assert!(rows.iter().any(|b| (b.xlo.raw(), b.xhi.raw()) == (-200, 0)));
    assert!(drc(&out).1.is_empty(), "{:?}", drc(&out).1);

    let touching = [
        ("met1", 0, 0, 1_000, 10_000),
        ("met1", 1_150, 0, 1_500, 10_000),
    ];
    let inputs = layout("strap-touch", &deck, &touching, &labels);
    let (_, kept) = enhance_gds(&inputs, &[]).expect("enhance runs");
    assert_eq!(kept.sides, 1, "the right strip would short sig");
    let other = enhance_deck("widen met1 net \"VGND\" by 200nm");
    let inputs = layout("strap-none", &other, &rects, &labels);
    assert_eq!(enhance_gds(&inputs, &[]).expect("runs").1.sides, 0);
}
