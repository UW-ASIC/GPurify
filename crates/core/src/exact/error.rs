//! Stable, fail-closed error type for exact geometry construction.

use std::fmt;

use super::boolean::BooleanOp;
use super::contact::PolygonContact;
use super::predicates::SegmentIntersection;

/// Stable, fail-closed errors returned by exact geometry construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExactGeometryError {
    TooFewVertices {
        count: usize,
    },
    DuplicateConsecutiveVertex {
        index: usize,
    },
    DegenerateRing,
    ArithmeticOverflow,
    InvalidBoundaryWalk(&'static str),
    SelfIntersection {
        edge_a: usize,
        edge_b: usize,
        kind: SegmentIntersection,
    },
    HoleOutside {
        hole: usize,
    },
    HoleTouchesOuter {
        hole: usize,
    },
    HoleConflict {
        hole_a: usize,
        hole_b: usize,
        contact: PolygonContact,
    },
    Unsupported {
        operation: BooleanOp,
        reason: &'static str,
    },
    CapacityExceeded {
        cells: usize,
        limit: usize,
    },
    InternalTopology(&'static str),
    SweepLineDegenerate(&'static str),
    RationalOverflow,
}

impl fmt::Display for ExactGeometryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooFewVertices { count } => {
                write!(f, "ring has {count} vertices; at least three are required")
            }
            Self::DuplicateConsecutiveVertex { index } => {
                write!(
                    f,
                    "ring has a duplicate consecutive vertex at index {index}"
                )
            }
            Self::DegenerateRing => write!(f, "ring has zero signed area"),
            Self::ArithmeticOverflow => write!(f, "exact geometry arithmetic overflowed i128"),
            Self::InvalidBoundaryWalk(reason) => {
                write!(f, "invalid boundary walk: {reason}")
            }
            Self::SelfIntersection {
                edge_a,
                edge_b,
                kind,
            } => write!(
                f,
                "ring edges {edge_a} and {edge_b} have forbidden {kind:?} contact"
            ),
            Self::HoleOutside { hole } => {
                write!(f, "hole {hole} is not strictly contained by its outer ring")
            }
            Self::HoleTouchesOuter { hole } => {
                write!(f, "hole {hole} touches or crosses its outer ring")
            }
            Self::HoleConflict {
                hole_a,
                hole_b,
                contact,
            } => write!(
                f,
                "holes {hole_a} and {hole_b} have forbidden {contact:?} contact"
            ),
            Self::Unsupported { operation, reason } => {
                write!(f, "{operation:?} is unsupported: {reason}")
            }
            Self::CapacityExceeded { cells, limit } => {
                write!(
                    f,
                    "exact geometry requires {cells} work units (limit {limit})"
                )
            }
            Self::InternalTopology(reason) => {
                write!(f, "boolean boundary reconstruction failed: {reason}")
            }
            Self::SweepLineDegenerate(reason) => {
                write!(f, "sweep-line degenerate event: {reason}")
            }
            Self::RationalOverflow => {
                write!(f, "rational arithmetic exceeded i128 capacity")
            }
        }
    }
}

impl std::error::Error for ExactGeometryError {}
