//! Exact rectilinear boolean operations.
//!
//! **Rectilinear only, by decision.** The previous implementation dispatched
//! arbitrary-angle input to a general arrangement solver that failed *open* in
//! three places: a hole with no containing outer ring was silently dropped, a
//! `Ring` that failed to construct from a split-produced sliver was skipped
//! with `Err(_) => {}`, and shared boundary edges were skipped on an unproven
//! "the rest will close correctly" argument. Each of those removes area from a
//! verification result without saying so.
//!
//! So: non-rectilinear input is [`BooleanError::NotRectilinear`], and a caller
//! that cannot proceed reports that rather than a clean result.
//!
//! # Testing
//!
//! This module has the strongest oracle in the tree, because the laws are
//! unconditional and independent of any implementation:
//!
//! - `(a − b) ∪ (a ∩ b) == a`
//! - `a ∩ b ⊆ a` and `a ∪ b ⊇ a`
//! - union and intersection are commutative; self-union is idempotent
//! - `area(a ∪ b) + area(a ∩ b) == area(a) + area(b)`
//! - the result is invariant under translation of both inputs

use crate::view::{ValidatedLayer, ValidityError};

/// Why a boolean could not be computed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BooleanError {
    #[error("input is not rectilinear; arbitrary-angle geometry is unsupported")]
    NotRectilinear,
    #[error(transparent)]
    Validity(#[from] ValidityError),
}

/// Union of two validated layers.
///
/// **Transform, A-to-B.** Caller owns `out`, cleared and refilled, so a chain
/// of booleans in a derived-layer expression reuses two buffers by swapping
/// rather than allocating per node.
///
/// Both inputs and the output are [`ValidatedLayer`], so a result is
/// immediately usable as the next operand with no revalidation — the property
/// that makes a derived-layer expression tree cheap.
pub fn union_into(
    a: &ValidatedLayer,
    b: &ValidatedLayer,
    out: &mut ValidatedLayer,
) -> Result<(), BooleanError> {
    todo!()
}

pub fn intersection_into(
    a: &ValidatedLayer,
    b: &ValidatedLayer,
    out: &mut ValidatedLayer,
) -> Result<(), BooleanError> {
    todo!()
}

/// `a` minus `b`.
///
/// Not commutative, and the only one of the three where operand order is a
/// silent-wrong-answer risk rather than a compile error. Named `subtraction`
/// rather than `difference` because "difference" reads as symmetric.
pub fn subtraction_into(
    a: &ValidatedLayer,
    b: &ValidatedLayer,
    out: &mut ValidatedLayer,
) -> Result<(), BooleanError> {
    todo!()
}

/// Grow (`amount > 0`) or shrink (`amount < 0`) by an exact L-infinity square
/// kernel.
///
/// L-infinity, not Euclidean: a square kernel keeps a rectilinear input
/// rectilinear, so the result is representable exactly. A round kernel would
/// need arbitrary angles, which this module refuses on purpose.
pub fn offset_into(
    a: &ValidatedLayer,
    amount: gpurify_units::Dbu,
    out: &mut ValidatedLayer,
) -> Result<(), BooleanError> {
    todo!()
}
