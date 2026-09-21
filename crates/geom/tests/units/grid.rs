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
use gpurify_testgen::{assert_bytes_identical, Rng};

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

/// Oracle: law. The bulk form is documented as the bulk form of `to_dbu`, so
/// row `n` of its output must equal `to_dbu` of row `n` of its input, whatever
/// the input. This also pins the buffer contract: `out` arrives holding junk
/// and must come back holding exactly the converted rows, because a transform
/// that appended instead of clearing would leave a caller reusing one buffer
/// with a deck that grows every time it is loaded.
#[test]
fn the_bulk_conversion_matches_the_scalar_one_row_for_row() {
    let g = grid(200);
    let mut rng = Rng::new(31);
    let lengths: Vec<Qty<Length, { prefix::NANO }>> = (0..256)
        .map(|_| {
            #[allow(
                clippy::cast_precision_loss,
                reason = "the draw is bounded by 2^20, far below 2^53"
            )]
            let units = rng.range(-500_000, 500_000) as f64;
            nm(units * 5.0)
        })
        .collect();

    let mut out = vec![Dbu::new_unchecked(-7); 3];
    g.to_dbu_into(&lengths, &mut out)
        .expect("every row is a multiple of 5 nm on a 5 nm grid");

    assert_eq!(
        out.len(),
        lengths.len(),
        "out must be cleared and refilled, not appended to"
    );
    for (row, length) in lengths.iter().enumerate() {
        assert_eq!(g.to_dbu(*length), Ok(out[row]), "row {row}");
    }

    // An empty deck is a legal deck, and it empties the buffer rather than
    // leaving the previous run's limits in it.
    g.to_dbu_into::<{ prefix::NANO }>(&[], &mut out)
        .expect("no rows, no failures");
    assert!(out.is_empty(), "an empty input must leave an empty buffer");
}

/// Oracle: construct-from-answer. The bad row is placed at a known index with a
/// known reason, so the assertion names both. The doc comment says the
/// conversion stops there because a deck with one bad limit is not partially
/// usable, and an index alone would pass against a transform that reported the
/// wrong failure for the right row.
#[test]
fn the_bulk_conversion_stops_at_the_first_bad_row_and_names_it() {
    let five_nm = grid(200);
    let mut out = Vec::new();

    let off_grid = [nm(5.0), nm(10.0), nm(47.0), nm(3.0)];
    assert_eq!(
        five_nm.to_dbu_into(&off_grid, &mut out),
        Err((2, GridError::NotOnGrid)),
        "row 2 is the first off-grid limit, and row 3 is off-grid too"
    );

    let out_of_range = [nm(5.0), nm(1e18), nm(47.0)];
    assert_eq!(
        five_nm.to_dbu_into(&out_of_range, &mut out),
        Err((1, GridError::OutOfRange)),
        "row 1 overflows the coordinate domain before row 2 goes off-grid"
    );

    let first_row_bad = [nm(1.0)];
    assert_eq!(
        five_nm.to_dbu_into(&first_row_bad, &mut out),
        Err((0, GridError::NotOnGrid))
    );
}

/// Oracle: closed form. This is the portability claim in `Grid`'s own doc
/// comment, written as a test: one deck's worth of limits in nanometres loads
/// against a 1 nm and a 5 nm grid, giving unit counts that differ by the ratio
/// of the resolutions, and the limit that does not land on the coarser grid is
/// refused there and accepted on the finer one.
#[test]
fn one_deck_of_limits_loads_against_two_grids_and_fails_loudly_on_the_coarser() {
    let limits = [nm(5.0), nm(10.0), nm(45.0), nm(100.0)];
    let mut out = Vec::new();

    grid(1_000)
        .to_dbu_into(&limits, &mut out)
        .expect("every limit is a whole number of nanometres");
    assert_eq!(out, [coord(5), coord(10), coord(45), coord(100)]);

    grid(200)
        .to_dbu_into(&limits, &mut out)
        .expect("every limit is a multiple of 5 nm");
    assert_eq!(out, [coord(1), coord(2), coord(9), coord(20)]);

    let unrepresentable = [nm(5.0), nm(47.0)];
    assert_eq!(
        grid(1_000).to_dbu_into(&unrepresentable, &mut out),
        Ok(()),
        "47 nm is representable on a 1 nm grid"
    );
    assert_eq!(out, [coord(5), coord(47)]);
    assert_eq!(
        grid(200).to_dbu_into(&unrepresentable, &mut out),
        Err((1, GridError::NotOnGrid)),
        "47 nm is not representable on a 5 nm grid, and that is an error"
    );
}

/// Oracle: determinism. The bulk conversion writes a buffer, so it is subject
/// to the determinism gate: the same input twice gives the same bytes. The
/// comparison is over the raw little-endian coordinates rather than over `Dbu`
/// equality, because the gate is about what a report would contain and two
/// values comparing equal is a weaker claim than two buffers being identical.
#[test]
fn the_bulk_conversion_is_byte_identical_across_two_runs() {
    let g = grid(1_000);
    let mut rng = Rng::new(83);
    let lengths: Vec<Qty<Length, { prefix::NANO }>> = (0..1_024)
        .map(|_| {
            #[allow(
                clippy::cast_precision_loss,
                reason = "the draw is bounded by 2^20, far below 2^53"
            )]
            let units = rng.range(-1_000_000, 1_000_000) as f64;
            nm(units)
        })
        .collect();

    let mut first = Vec::new();
    let mut second = vec![Dbu::new_unchecked(0); 4_096];
    g.to_dbu_into(&lengths, &mut first)
        .expect("seed 83 is on grid");
    g.to_dbu_into(&lengths, &mut second)
        .expect("seed 83 is on grid");

    let bytes =
        |coords: &[Dbu]| -> Vec<u8> { coords.iter().flat_map(|c| c.raw().to_le_bytes()).collect() };
    assert_bytes_identical(
        "a deck's worth of converted limits",
        &bytes(&first),
        &bytes(&second),
    );
}
