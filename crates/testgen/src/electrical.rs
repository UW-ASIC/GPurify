//! Resistor ladders and parallel-plate capacitors with closed-form answers.

use gpurify_check::erc::power::NetNetworks;
use gpurify_check::topology::NetId;
use gpurify_geom::ops::Point;
use gpurify_geom::{prefix, Qty, Resistance};
use gpurify_geom::{GeometryStore, LayerId};

use crate::shapes::{dbu, LayoutBuilder};

/// Vacuum permittivity, farads per metre.
pub const EPSILON_0: f64 = 8.854_187_812_8e-12;

/// A resistor ladder with a hand-computable end-to-end resistance.
///
/// One stage is `series_ohm` in series with two `parallel_ohm` resistors in
/// parallel, so the total is `rungs * (series_ohm + parallel_ohm / 2)`. The
/// parallel pair is a genuine multi-edge between the same two nodes.
///
/// Stage `k` spans nodes `2k -> 2k+1 -> 2k+2`; the terminals are `0` and
/// `2 * rungs` and no interior node is a terminal.
#[derive(Debug)]
pub struct LadderCase {
    /// One row, ready for `erc::power::effective_resistance_into`.
    pub networks: NetNetworks,
    /// The row index of the ladder within `networks`. Always zero.
    pub row: u32,
    /// The two terminal node indices, within the row.
    pub terminals: (u32, u32),
    /// The answer, in ohms.
    pub expected_ohm: f64,
}

/// Build a ladder of `rungs` stages between two terminals.
///
/// Both resistances must be positive and finite: a zero shorts two nodes and
/// `erc::power` rejects it, so the case would exercise the error path rather
/// than the solve.
#[must_use]
pub fn ladder_network(rungs: u32, series_ohm: f64, parallel_ohm: f64) -> LadderCase {
    assert!(rungs > 0, "a ladder needs at least one stage");
    assert!(
        series_ohm > 0.0 && series_ohm.is_finite(),
        "series resistance {series_ohm} must be positive and finite"
    );
    assert!(
        parallel_ohm > 0.0 && parallel_ohm.is_finite(),
        "parallel resistance {parallel_ohm} must be positive and finite"
    );

    let node_count = 2 * rungs + 1;
    let mut networks = NetNetworks {
        net: vec![NetId(0)],
        node_start: vec![0, node_count],
        node_at: Vec::with_capacity(node_count as usize),
        node_poly: Vec::with_capacity(node_count as usize),
        terminal_start: vec![0, 2],
        terminal: vec![0, 2 * rungs],
        edge_start: vec![0, 3 * rungs],
        edge_from: Vec::with_capacity(3 * rungs as usize),
        edge_to: Vec::with_capacity(3 * rungs as usize),
        edge_resistance: Vec::with_capacity(3 * rungs as usize),
    };

    // Positions carry no electrical meaning, but distinct points are needed so
    // a misreported node location is visible.
    for node in 0..node_count {
        networks.node_at.push(Point {
            x: dbu(i64::from(node) * 1_000),
            y: dbu(0),
        });
        networks.node_poly.push(gpurify_geom::PolyId(node));
    }

    let series = Qty::<Resistance, { prefix::BASE }>::new(series_ohm);
    let parallel = Qty::<Resistance, { prefix::BASE }>::new(parallel_ohm);
    for stage in 0..rungs {
        let a = 2 * stage;
        let b = a + 1;
        let c = a + 2;
        networks.edge_from.push(a);
        networks.edge_to.push(b);
        networks.edge_resistance.push(series);
        // Two edges, same endpoints. Deliberate.
        for _ in 0..2 {
            networks.edge_from.push(b);
            networks.edge_to.push(c);
            networks.edge_resistance.push(parallel);
        }
    }

    LadderCase {
        networks,
        row: 0,
        terminals: (0, 2 * rungs),
        expected_ohm: f64::from(rungs) * (series_ohm + parallel_ohm / 2.0),
    }
}

/// A parallel-plate capacitor and its analytic capacitance, `C = eps_0 k A / d`.
///
/// The fringe coefficient is zero: the parallel-plate formula is the limit of a
/// real capacitor, and only with no fringe correction is it the exact answer
/// rather than an asymptote.
#[derive(Debug)]
pub struct PlateCase {
    /// One rectangular plate on `layer`.
    pub store: GeometryStore,
    pub layer: LayerId,
    pub answer: PlateAnswer,
}

/// The closed form, without the geometry.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PlateAnswer {
    /// Plate area in database units, exact.
    pub area_dbu: i128,
    /// Plate perimeter in database units, exact.
    pub perimeter_dbu: i64,
    /// The deck coefficient, in attofarads per square micrometre.
    pub area_af_um2: f64,
    /// The deck's fringe coefficient. Zero — see [`PlateCase`].
    pub fringe_af_um: f64,
    /// The answer, in femtofarads.
    pub expected_ff: f64,
}

/// The geometry and process of a parallel-plate pair.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PlateSpec {
    pub layer: LayerId,
    /// Plate dimensions in database units.
    pub width_dbu: i64,
    pub length_dbu: i64,
    /// Database units per micrometre, from the run's grid.
    pub dbu_per_um: i64,
    /// Plate separation, in nanometres.
    pub separation_nm: f64,
    /// Relative permittivity of the dielectric between the plates.
    pub dielectric_k: f64,
}

/// The capacitance of a plate, from the formula alone.
#[must_use]
pub fn plate_answer(spec: PlateSpec) -> PlateAnswer {
    assert!(
        spec.width_dbu > 0 && spec.length_dbu > 0 && spec.dbu_per_um > 0,
        "a plate needs positive dimensions and a positive grid"
    );
    assert!(
        spec.separation_nm > 0.0 && spec.separation_nm.is_finite(),
        "separation {} must be positive and finite",
        spec.separation_nm
    );
    assert!(
        spec.dielectric_k > 0.0 && spec.dielectric_k.is_finite(),
        "permittivity {} must be positive and finite",
        spec.dielectric_k
    );

    #[allow(
        clippy::cast_precision_loss,
        reason = "layout dimensions and grids are far below 2^53"
    )]
    let (width_um, length_um) = (
        spec.width_dbu as f64 / spec.dbu_per_um as f64,
        spec.length_dbu as f64 / spec.dbu_per_um as f64,
    );
    let area_um2 = width_um * length_um;

    // epsilon_0 * k / d, carried into attofarads per square micrometre:
    // 1 um^2 is 1e-12 m^2 and 1 F is 1e18 aF, so the factor is 1e6.
    let separation_m = spec.separation_nm * 1e-9;
    let area_af_um2 = EPSILON_0 * spec.dielectric_k / separation_m * 1e6;
    // aF to fF is a factor of a thousand.
    let expected_ff = area_af_um2 * area_um2 / 1_000.0;

    PlateAnswer {
        area_dbu: i128::from(spec.width_dbu) * i128::from(spec.length_dbu),
        perimeter_dbu: 2 * (spec.width_dbu + spec.length_dbu),
        area_af_um2,
        fringe_af_um: 0.0,
        expected_ff,
    }
}

/// Build the plate geometry alongside [`plate_answer`].
#[must_use]
pub fn parallel_plate(spec: PlateSpec) -> PlateCase {
    let answer = plate_answer(spec);
    let mut layout = LayoutBuilder::new(spec.layer.idx() + 1);
    layout.rect(spec.layer, 0, 0, spec.width_dbu, spec.length_dbu);
    let (store, _ids) = layout.finish();
    PlateCase {
        store,
        layer: spec.layer,
        answer,
    }
}

#[cfg(test)]
mod tests {
    use super::{ladder_network, EPSILON_0};

    /// 1 ohm in series with two 2 ohm in parallel is 2 ohms.
    #[test]
    fn one_ladder_stage_is_its_series_resistor_plus_half_its_parallel_pair() {
        let case = ladder_network(1, 1.0, 2.0);
        assert!((case.expected_ohm - 2.0).abs() < 1e-12);
        assert_eq!(case.networks.edge_from.len(), 3);
        assert_eq!(case.terminals, (0, 2));
    }

    /// Ten identical stages are ten times one.
    #[test]
    fn ladder_stages_add_in_series() {
        let one = ladder_network(1, 3.0, 8.0).expected_ohm;
        let ten = ladder_network(10, 3.0, 8.0).expected_ohm;
        assert!(
            (ten - 10.0 * one).abs() < 1e-9,
            "{ten} is not ten times {one}"
        );
    }

    /// CSR offsets match the columns they index.
    #[test]
    fn ladder_csr_offsets_match_the_columns_they_index() {
        let case = ladder_network(6, 1.5, 4.0);
        let n = &case.networks;
        assert_eq!(*n.node_start.last().expect("offsets"), 13);
        assert_eq!(n.node_at.len(), 13);
        assert_eq!(n.node_poly.len(), 13);
        assert_eq!(*n.terminal_start.last().expect("offsets"), 2);
        assert_eq!(n.terminal.len(), 2);
        assert_eq!(*n.edge_start.last().expect("offsets"), 18);
        assert_eq!(n.edge_from.len(), 18);
        assert_eq!(n.edge_to.len(), 18);
        assert_eq!(n.edge_resistance.len(), 18);
    }

    /// One square micrometre of vacuum at a one micrometre gap, worked from the
    /// SI constant to check the unit chain.
    #[test]
    fn parallel_plate_of_one_square_micrometre_matches_epsilon_zero() {
        use super::{plate_answer, PlateSpec};
        let answer = plate_answer(PlateSpec {
            layer: gpurify_geom::LayerId(0),
            width_dbu: 1_000,
            length_dbu: 1_000,
            dbu_per_um: 1_000,
            separation_nm: 1_000.0,
            dielectric_k: 1.0,
        });
        let expected_ff = EPSILON_0 * 1e-12 / 1e-6 * 1e15;
        assert!(
            (answer.expected_ff - expected_ff).abs() < 1e-12,
            "{} is not {expected_ff} fF",
            answer.expected_ff
        );
        assert_eq!(answer.area_dbu, 1_000_000);
        assert_eq!(answer.perimeter_dbu, 4_000);
    }

    /// Capacitance is linear in area and permittivity, inverse in separation.
    #[test]
    fn plate_capacitance_scales_with_area_permittivity_and_inverse_separation() {
        use super::{plate_answer, PlateSpec};
        let base = PlateSpec {
            layer: gpurify_geom::LayerId(0),
            width_dbu: 2_000,
            length_dbu: 3_000,
            dbu_per_um: 1_000,
            separation_nm: 500.0,
            dielectric_k: 3.9,
        };
        let reference = plate_answer(base).expected_ff;

        let doubled_area = plate_answer(PlateSpec {
            width_dbu: 4_000,
            ..base
        })
        .expected_ff;
        assert!((doubled_area - 2.0 * reference).abs() < 1e-9 * reference);

        let doubled_k = plate_answer(PlateSpec {
            dielectric_k: 7.8,
            ..base
        })
        .expected_ff;
        assert!((doubled_k - 2.0 * reference).abs() < 1e-9 * reference);

        let doubled_gap = plate_answer(PlateSpec {
            separation_nm: 1_000.0,
            ..base
        })
        .expected_ff;
        assert!((doubled_gap - reference / 2.0).abs() < 1e-9 * reference);
    }
}
