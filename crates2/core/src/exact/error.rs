//! Stable, fail-closed error type for exact geometry construction.

use super::boolean::BooleanOp;
use super::contact::PolygonContact;
use super::predicates::SegmentIntersection;

/// Stable, fail-closed errors returned by exact geometry construction.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ExactGeometryError {
    #[error("ring has {count} vertices; at least three are required")]
    TooFewVertices {
        count: usize,
    },
    #[error("ring has a duplicate consecutive vertex at index {index}")]
    DuplicateConsecutiveVertex {
        index: usize,
    },
    #[error("ring has zero signed area")]
    DegenerateRing,
    #[error("exact geometry arithmetic overflowed i128")]
    ArithmeticOverflow,
    #[error("invalid boundary walk: {0}")]
    InvalidBoundaryWalk(&'static str),
    #[error("ring edges {edge_a} and {edge_b} have forbidden {kind:?} contact")]
    SelfIntersection {
        edge_a: usize,
        edge_b: usize,
        kind: SegmentIntersection,
    },
    #[error("hole {hole} is not strictly contained by its outer ring")]
    HoleOutside {
        hole: usize,
    },
    #[error("hole {hole} touches or crosses its outer ring")]
    HoleTouchesOuter {
        hole: usize,
    },
    #[error("holes {hole_a} and {hole_b} have forbidden {contact:?} contact")]
    HoleConflict {
        hole_a: usize,
        hole_b: usize,
        contact: PolygonContact,
    },
    #[error("{operation:?} is unsupported: {reason}")]
    Unsupported {
        operation: BooleanOp,
        reason: &'static str,
    },
    #[error("exact geometry requires {cells} work units (limit {limit})")]
    CapacityExceeded {
        cells: usize,
        limit: usize,
    },
    #[error("boolean boundary reconstruction failed: {0}")]
    InternalTopology(&'static str),
    #[error("sweep-line degenerate event: {0}")]
    SweepLineDegenerate(&'static str),
    #[error("rational arithmetic exceeded i128 capacity")]
    RationalOverflow,
}
