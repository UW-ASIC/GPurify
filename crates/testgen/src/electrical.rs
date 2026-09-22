//! Resistor ladders with a closed-form end-to-end resistance.

use gpurify_check::erc::power::NetNetworks;
use gpurify_check::topology::NetId;
use gpurify_geom::ops::Point;
use gpurify_geom::{prefix, Qty, Resistance};

use crate::shapes::dbu;

/// A resistor ladder with a hand-computable end-to-end resistance.
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

#[cfg(test)]
mod tests {
    use super::ladder_network;

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
}
