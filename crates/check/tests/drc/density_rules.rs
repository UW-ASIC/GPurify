//! Area-family kinds read from deck text (`drc::rules::area`): `aspect_ratio`,
//! `region_density`, `cover_density`, `density_balance`, `critical_area` and
//! its weighted mean. The cases are the root suite's exhaustive fixtures
//! (`tests/exhaustive/drc_overlay.rs`, `drc_dimension.rs`) at the crate
//! level, with the same oracles.

use crate::common::deck::{
    area, check, check_under, deck, new_deck, ratio, rect, Shape, Symmetry, Want,
};

/// Windows anchor on the die's corner: translations only.
fn identity(s: Symmetry) -> bool {
    s.turns == 0 && !s.mirror
}

fn ratio_of(n: i64, d: f64) -> f64 {
    #[allow(clippy::cast_precision_loss, reason = "small integers")]
    let n = n as f64;
    n / d
}

/// Oracle: ratios fixed by construction, the limit swept one grid step
/// either side (a 100-wide bar 299, 300 and 301 long under 3; 249, 250 and
/// 251 under 2.5): at the limit is legal, above it is one finding of
/// `long / short` at the bar's centre.
#[test]
fn aspect_ratio_holds_the_long_side_over_the_short_one_to_the_limit() {
    for (limit, text, lengths) in [(300, "3", [299, 300, 301]), (250, "2.5", [249, 250, 251])] {
        let deck = deck(&format!("rule ar aspect_ratio(met1) <= {text}"));
        for l in lengths {
            let want: Vec<Want> = if l > limit {
                vec![ratio("ar", ratio_of(l, 100.0)).at2(100, l)]
            } else {
                vec![]
            };
            check(
                &format!("bar/{l}"),
                &deck,
                &[rect("met1", 0, 0, 100, l)],
                &["ar"],
                &want,
            );
        }
    }
}

/// Oracle: the merged figure's bounding box, by construction. A 301 bar
/// drawn as two abutting halves is one figure at 3.01 (each half alone is
/// 1.5); an L of two 400 x 100 arms has a square box (1, legal; each arm
/// alone is 4); a 1000 x 200 ring drawn as four rectangles is 5, its hole
/// changing nothing; an empty layer is legal.
#[test]
fn aspect_ratio_judges_merged_figures_by_their_box() {
    let deck = deck("rule ar aspect_ratio(met1) <= 3");
    let cases: [(&str, Vec<Shape>, Vec<Want>); 4] = [
        (
            "halves",
            vec![rect("met1", 0, 0, 100, 150), rect("met1", 0, 150, 100, 301)],
            vec![ratio("ar", 3.01)],
        ),
        (
            "l_of_two_long_arms",
            vec![rect("met1", 0, 0, 400, 100), rect("met1", 0, 100, 100, 400)],
            vec![],
        ),
        (
            "ring",
            vec![
                rect("met1", 0, 0, 1000, 50),
                rect("met1", 0, 150, 1000, 200),
                rect("met1", 0, 50, 100, 150),
                rect("met1", 900, 50, 1000, 150),
            ],
            vec![ratio("ar", 5.0)],
        ),
        ("empty", vec![rect("met2", 0, 0, 1000, 100)], vec![]),
    ];
    for (name, shapes, want) in cases {
        check(name, &deck, &shapes, &["ar"], &want);
    }
}

/// `region_density(met3, cap)` against 25% (maximum) and 10% (minimum).
const REGION: &str = "rule dmax region_density(met3, cap) <= 25%\n\
                      rule dmin region_density(met3, cap) >= 10%";

/// Oracle: coverages fixed by construction. Rows 249, 250 and 251 tall in a
/// 1000 square capacitor are 24.9%, 25% and 25.1%: only the last breaks the
/// maximum, at the capacitor's centre (500, 500).
#[test]
fn region_density_is_the_layer_s_share_of_each_region_figure() {
    let deck = new_deck(&["met3", "cap"], REGION);
    for h in [249, 250, 251] {
        let want: Vec<Want> = if h > 250 {
            vec![ratio("dmax", ratio_of(h, 1000.0)).at(500, 500)]
        } else {
            vec![]
        };
        check(
            &format!("coverage/{h}"),
            &deck,
            &[rect("cap", 0, 0, 1000, 1000), rect("met3", 0, 0, 1000, h)],
            &["dmax", "dmin"],
            &want,
        );
    }
}

/// Oracle: coverages fixed by construction.
/// - Two capacitors at 30% and 5% are a finding each, against the maximum
///   and the minimum, at their own centres (one extent for both would read
///   17.5% and pass);
/// - met3 reaching outside its capacitor counts only inside (25%, legal;
///   37.5% if counted whole);
/// - met3 filling only the hole of a ring-shaped capacitor is 0 of the
///   ring, below the minimum (filling the hole would read 25%);
/// - met3 with no capacitor is no finding.
#[test]
fn region_density_counts_only_inside_each_region_figure() {
    let deck = new_deck(&["met3", "cap"], REGION);
    let ring = [
        rect("cap", 0, 0, 1000, 250),
        rect("cap", 0, 750, 1000, 1000),
        rect("cap", 0, 250, 250, 750),
        rect("cap", 750, 250, 1000, 750),
    ];
    let cases: [(&str, Vec<Shape>, Vec<Want>); 4] = [
        (
            "two_regions",
            vec![
                rect("cap", 0, 0, 1000, 1000),
                rect("met3", 0, 0, 1000, 300),
                rect("cap", 3000, 0, 4000, 1000),
                rect("met3", 3000, 0, 4000, 50),
            ],
            vec![
                ratio("dmax", 0.3).at(500, 500),
                ratio("dmin", 0.05).at(3500, 500),
            ],
        ),
        (
            "outside_not_counted",
            vec![
                rect("cap", 0, 0, 1000, 1000),
                rect("met3", -500, 0, 1000, 250),
            ],
            vec![],
        ),
        (
            "holed_region",
            ring.iter()
                .cloned()
                .chain([rect("met3", 250, 250, 750, 750)])
                .collect(),
            vec![ratio("dmin", 0.0)],
        ),
        ("no_region", vec![rect("met3", 0, 0, 1000, 1000)], vec![]),
    ];
    for (name, shapes, want) in cases {
        check(name, &deck, &shapes, &["dmax", "dmin"], &want);
    }
}

/// Oracle: coverage and density by hand from the drawn areas, one 1000 nm
/// window over a die `[0, 1000]²` (area 10^6), bands starting at cover 25%,
/// 50% and 100% asking density 25%, 50% and 75%. A cover of exactly 50% is
/// the 50% band inclusive (need 0.5) and the 25% band exclusive (0.25); a
/// full cover is the 100% band inclusive (0.75) and the 50% band exclusive
/// (0.5); 49.9% and 50.1% fall either side alike; 20% is below every band
/// (not judged, even with nothing held). The held layer's area is swept a
/// step either side of each need, one finding below it, at the window's
/// centre (500, 500), measuring the density.
#[test]
fn cover_density_holds_each_window_to_the_band_its_cover_picks() {
    for (cover, incl, excl) in [
        (500_000, Some(500_000), Some(250_000)),
        (1_000_000, Some(750_000), Some(500_000)),
        (499_000, Some(250_000), Some(250_000)),
        (501_000, Some(500_000), Some(500_000)),
        (200_000, None, None),
    ] {
        for (inclusive, need) in [(true, incl), (false, excl)] {
            let deck = new_deck(
                &["m", "c", "die"],
                &format!(
                    "rule cd cover_density(m, c, die; window: 1000nm, step: 1000nm, \
                     cover: [25%, 50%, 100%], density: [25%, 50%, 75%], inclusive: {inclusive})"
                ),
            );
            let held = match need {
                Some(need) => vec![need - 1000, need, need + 1000],
                None => vec![0, 100_000],
            };
            for held in held {
                let mut shapes = vec![
                    rect("die", 0, 0, 1000, 1000),
                    rect("c", 0, 0, 1000, cover / 1000),
                ];
                if held > 0 {
                    shapes.push(rect("m", 0, 0, held / 1000, 1000));
                }
                let want: Vec<Want> = match need {
                    Some(need) if held < need => {
                        vec![ratio("cd", ratio_of(held, 1e6)).at(500, 500)]
                    }
                    _ => vec![],
                };
                check_under(
                    &format!("cover_density/{cover}/{inclusive}/{held}"),
                    &deck,
                    &shapes,
                    &["cd"],
                    &want,
                    identity,
                );
            }
        }
    }
}

/// Oracle: the balance by hand. A 3000 x 1000 die, three 1000 windows. The
/// first holds 500 x 1000 of `c1` and `c2` 1000 tall and 249, 250 or 251
/// wide (balance 0.498, 0.5, 0.502 against 0.5); the second only `c1`
/// (balance 0, a finding at (1500, 500)); the third neither (not judged).
#[test]
fn density_balance_is_the_lesser_coverage_over_the_greater_per_window() {
    let deck = new_deck(
        &["die", "c1", "c2"],
        "rule bal density_balance(c1, c2, die; window: 1000nm, step: 1000nm) >= 0.5",
    );
    for w in [249, 250, 251] {
        let mut want = vec![ratio("bal", 0.0).at(1500, 500)];
        if w < 250 {
            want.push(ratio("bal", ratio_of(w, 500.0)).at(500, 500));
        }
        check_under(
            &format!("density_balance/{w}"),
            &deck,
            &[
                rect("die", 0, 0, 3000, 1000),
                rect("c1", 0, 0, 500, 1000),
                rect("c2", 600, 0, 600 + w, 1000),
                rect("c1", 1000, 0, 1400, 1000),
            ],
            &["bal"],
            &want,
            identity,
        );
    }
}

/// Lines 1000 long and 100 tall at each `y`.
fn lines(ys: &[i64]) -> Vec<Shape> {
    ys.iter()
        .map(|&y| rect("met1", 0, y, 1000, y + 100))
        .collect()
}

/// Oracle: the closed form (Papadopoulou and Lee, 1999): two parallel lines
/// of length 1000 and a gap 200 under a square defect of half-side 150 have
/// `(1000 + 300)(300 - 200) = 130000`, against limits one square unit
/// either side and at it, at the centre of the region (500, 200). Three
/// such lines under half-side 350 overlap three ways: the pairwise regions
/// cover 1700 x 800 = 1360000, not their sum, and the 150 defect sees
/// 2 x 130000 there. Lines 400 apart are out of reach of a 300 defect; one
/// L-shaped figure has no pair.
#[test]
fn critical_area_is_the_closed_form_of_parallel_lines() {
    let deck = deck(
        "rule below critical_area(met1; radius: 150nm) <= 129999nm2\n\
         rule at critical_area(met1; radius: 150nm) <= 130000nm2\n\
         rule above critical_area(met1; radius: 150nm) <= 130001nm2\n\
         rule wide critical_area(met1; radius: 350nm) <= 1um2",
    );
    let rules = ["below", "at", "above", "wide"];
    check(
        "two_lines",
        &deck,
        &lines(&[0, 300]),
        &rules,
        &[area("below", 130_000).at(500, 200)],
    );
    let three = ["below", "at", "above"].map(|r| area(r, 260_000).at(500, 350));
    let mut want = three.to_vec();
    want.push(area("wide", 1_360_000).at(500, 350));
    check("three_lines", &deck, &lines(&[0, 300, 600]), &rules, &want);
    check("apart", &deck, &lines(&[0, 500]), &rules, &[]);
    check(
        "one_figure",
        &deck,
        &[
            rect("met1", 0, 0, 1000, 100),
            rect("met1", 0, 100, 100, 1000),
        ],
        &rules,
        &[],
    );
}

/// Oracle: the closed form per radius for two lines 1000 long, 200 apart,
/// `(1000 + 2r)(2r - 200)` and 0 below r = 100: 0, 130000 and 450000 at
/// radii 50, 150 and 250; weighted 1/2, 1/4, 1/4 the mean is 32500 + 112500
/// = 145000, found only against 144999, at the centre of the largest
/// radius's region (500, 200). Lines 600 apart are out of reach of every
/// radius.
#[test]
fn mean_critical_area_weights_each_radius() {
    let deck = deck(
        "rule below critical_area(met1; radii: [50nm, 150nm, 250nm], weights: [0.5, 0.25, 0.25]) <= 144999nm2\n\
         rule at critical_area(met1; radii: [50nm, 150nm, 250nm], weights: [0.5, 0.25, 0.25]) <= 145000nm2\n\
         rule above critical_area(met1; radii: [50nm, 150nm, 250nm], weights: [0.5, 0.25, 0.25]) <= 145001nm2",
    );
    let rules = ["below", "at", "above"];
    check(
        "two_lines",
        &deck,
        &lines(&[0, 300]),
        &rules,
        &[area("below", 145_000).at(500, 200)],
    );
    check("out_of_reach", &deck, &lines(&[0, 700]), &rules, &[]);
}
