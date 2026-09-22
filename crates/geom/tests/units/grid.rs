//! The exact-or-rejected boundary between physical length and grid units.
//!
//! Every case here is a closed form: a grid states how many database units one
//! micrometre is, so the answer to "how many units is this length" is a
//! division the test performs itself. The rejections matter more than the
//! conversions. A spacing limit that silently rounds down passes shapes the
//! foundry would reject, which is the fail-open mode this project treats as a
//! defect, so an off-grid length asserts `NotOnGrid` and never a nearby
//! integer.

use gpurify_geom::{prefix, Dbu, Grid, GridError, Length, Qty, MAX_ABS_DBU};
use gpurify_testgen::Rng;

/// A length in nanometres.
fn nm(raw: f64) -> Qty<Length, { prefix::NANO }> {
    Qty::new(raw)
}

/// A length in micrometres.
fn um(raw: f64) -> Qty<Length, { prefix::MICRO }> {
    Qty::new(raw)
}

fn grid(dbu_per_um: i64) -> Grid {
    Grid::new(dbu_per_um).unwrap_or_else(|e| panic!("{dbu_per_um} dbu/um should be legal: {e}"))
}

fn coord(raw: i64) -> Dbu {
    Dbu::new(raw).unwrap_or_else(|| panic!("{raw} should be inside +/-{MAX_ABS_DBU}"))
}

/// Oracle: closed form. `dbu = length_in_micrometres * dbu_per_um`, computed on
/// paper for each row. The two grid resolutions are the ones the `Grid` doc
/// comment names, 1 nm and 5 nm, and both include a length of exactly one grid
/// unit and a length of zero — the two boundaries the test plan calls out,
/// where an implementation using a strict inequality or a truncating division
/// goes wrong and nowhere else does.
#[test]
fn an_on_grid_length_converts_exactly() {
    // (dbu_per_um, nanometres, expected units)
    const NANOMETRES: &[(i64, f64, i64)] = &[
        (1_000, 0.0, 0),
        (1_000, 1.0, 1),
        (1_000, -1.0, -1),
        (1_000, 45.0, 45),
        (1_000, -45.0, -45),
        (1_000, 1_000.0, 1_000),
        (200, 0.0, 0),
        (200, 5.0, 1),
        (200, -5.0, -1),
        (200, 45.0, 9),
        (200, -50.0, -10),
        (200, 1_000.0, 200),
    ];
    // The same arithmetic one prefix up, so the conversion is exercised where
    // the scale factor points the other way. Every value here is exact in
    // binary, keeping the test about the conversion rather than about `f64`
    // rounding.
    const MICROMETRES: &[(i64, f64, i64)] = &[
        (1_000, 1.0, 1_000),
        (1_000, 2.0, 2_000),
        (1_000, -0.25, -250),
        (200, 0.5, 100),
        (200, 1.0, 200),
        (200, -2.0, -400),
    ];

    for &(dbu_per_um, nanometres, expected) in NANOMETRES {
        assert_eq!(
            grid(dbu_per_um).to_dbu(nm(nanometres)),
            Ok(coord(expected)),
            "{nanometres} nm on a {dbu_per_um} dbu/um grid"
        );
    }

    for &(dbu_per_um, micrometres, expected) in MICROMETRES {
        assert_eq!(
            grid(dbu_per_um).to_dbu(um(micrometres)),
            Ok(coord(expected)),
            "{micrometres} um on a {dbu_per_um} dbu/um grid"
        );
    }
}

/// Oracle: closed form. Each row lands strictly between two grid units, so
/// there is a nearby integer a rounding implementation would return, and the
/// assertion is that it returns none of them. Half a unit is included
/// deliberately: it is the value where round-half-up and round-half-even
/// disagree, so an implementation that rounds at all fails here whichever mode
/// it picked.
#[test]
fn an_off_grid_length_is_refused_rather_than_rounded() {
    // (dbu_per_um, nanometres) — none of these is a whole number of units.
    const OFF_GRID: &[(i64, f64)] = &[
        (1_000, 0.5),
        (1_000, 2.5),
        (1_000, -2.5),
        (1_000, 0.25),
        (200, 1.0),
        (200, -1.0),
        (200, 47.0),
        (200, 2.5),
    ];
    for &(dbu_per_um, nanometres) in OFF_GRID {
        assert_eq!(
            grid(dbu_per_um).to_dbu(nm(nanometres)),
            Err(GridError::NotOnGrid),
            "{nanometres} nm is off a {dbu_per_um} dbu/um grid and must not round"
        );
    }
}

/// Oracle: closed form. The last legal coordinate is `MAX_ABS_DBU`, which on a
/// 1 nm grid is that many nanometres, so the boundary is stated on both sides:
/// the endpoint converts, one unit past it does not. The gross overshoot at the
/// end is the guard against a saturating `f64`-to-`i64` cast, which would land
/// on `i64::MAX` and could be mistaken for a value rather than an overflow.
#[test]
fn a_length_beyond_the_coordinate_domain_is_out_of_range() {
    #[allow(
        clippy::cast_precision_loss,
        reason = "MAX_ABS_DBU is 2^40, which f64 represents exactly"
    )]
    let edge = MAX_ABS_DBU as f64;
    let one_nm = grid(1_000);

    assert_eq!(one_nm.to_dbu(nm(edge)), Ok(coord(MAX_ABS_DBU)));
    assert_eq!(one_nm.to_dbu(nm(-edge)), Ok(coord(-MAX_ABS_DBU)));

    for beyond in [edge + 1.0, -edge - 1.0, edge * 2.0, 1e18, -1e18, 1e30] {
        assert_eq!(
            one_nm.to_dbu(nm(beyond)),
            Err(GridError::OutOfRange),
            "{beyond} nm is past the coordinate domain"
        );
    }
}

/// Oracle: closed form. A resolution is a count of database units per
/// micrometre, so zero and every negative are meaningless and one is the
/// smallest that is not. The accepted values read back unchanged, which is the
/// only thing `dbu_per_um` promises.
#[test]
fn a_grid_resolution_must_be_a_positive_count() {
    for bad in [0_i64, -1, -1_000, i64::MIN] {
        assert_eq!(
            Grid::new(bad),
            Err(GridError::BadResolution),
            "{bad} dbu/um is not a resolution"
        );
    }
    for good in [1_i64, 2, 200, 1_000, 10_000] {
        assert_eq!(grid(good).dbu_per_um(), good);
    }
}

/// Oracle: law. `to_length` is documented as total precisely because every
/// `Dbu` is on the grid by construction, so converting out and back is the
/// identity for every coordinate on every grid. That makes it a stronger claim
/// than any single conversion: it fails if either direction carries the wrong
/// scale factor, or if the round trip loses a unit at the sign boundary.
///
/// The resolutions all divide a thousand, so the intermediate nanometre value
/// is exact and the law is about the conversion rather than about `f64`.
#[test]
fn converting_a_coordinate_to_a_length_and_back_is_the_identity() {
    for dbu_per_um in [1_i64, 2, 5, 200, 1_000] {
        let g = grid(dbu_per_um);

        // The endpoints first. On the coarsest of these grids one unit is a
        // thousand nanometres, so the intermediate is `2^40 * 1000`, still
        // under `2^53` and therefore exact — which is the whole reason the
        // round trip is allowed to be stated as equality out here.
        for edge in [MAX_ABS_DBU, -MAX_ABS_DBU, MAX_ABS_DBU - 1, 0] {
            let value = coord(edge);
            assert_eq!(
                g.to_dbu(g.to_length(value)),
                Ok(value),
                "the domain edge on a {dbu_per_um} dbu/um grid"
            );
        }

        let mut rng = Rng::new(19);
        for _ in 0..256 {
            let value = coord(rng.range(-1_000_000, 1_000_001));
            assert_eq!(
                g.to_dbu(g.to_length(value)),
                Ok(value),
                "seed 19 on a {dbu_per_um} dbu/um grid"
            );
        }
    }
}

/// Oracle: closed form. One database unit is `1000 / dbu_per_um` nanometres, so
/// the physical length of a coordinate is arithmetic over the resolution. This
/// pins the direction the round-trip law above cannot: a `to_length` that
/// inverted the ratio would still round-trip with a matching `to_dbu`.
#[test]
fn a_coordinate_measures_a_thousand_nanometres_over_the_resolution() {
    // (dbu_per_um, units, nanometres)
    const CASES: &[(i64, i64, f64)] = &[
        (1_000, 0, 0.0),
        (1_000, 1, 1.0),
        (1_000, -45, -45.0),
        (200, 1, 5.0),
        (200, 9, 45.0),
        (1, 1, 1_000.0),
        (2, 3, 1_500.0),
    ];
    for &(dbu_per_um, units, nanometres) in CASES {
        let actual = grid(dbu_per_um).to_length(coord(units)).raw();
        assert!(
            (actual - nanometres).abs() <= 1e-9,
            "{units} units on a {dbu_per_um} dbu/um grid is {nanometres} nm, got {actual}"
        );
    }
}
