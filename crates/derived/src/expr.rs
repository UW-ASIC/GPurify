//! The derived-layer expression tree and its evaluator.

use gpurify_core::{LayerId, ValidatedLayer};
use gpurify_ingest::StrId;
use gpurify_units::Dbu;

/// A reference to either a base layer or a named derived layer.
///
/// Two variants rather than one id space, because resolving a name to a base
/// layer must fail loudly when the deck does not define it, and a derived name
/// must be resolvable to its expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayerRef {
    Base(LayerId),
    Named(StrId),
}

/// A derived-layer expression.
///
/// A closed enum matched exhaustively, not a trait object: the operator set is
/// fixed by the deck schema, and adding one should break every match until it
/// is handled.
///
/// Boxed children, unusually for this tree — an expression is a handful of
/// nodes evaluated once per layer per run, not bulk data, so an arena would be
/// machinery for nothing.
#[derive(Debug, Clone)]
pub enum DerivedExpr {
    Layer(LayerRef),
    Union(Box<DerivedExpr>, Box<DerivedExpr>),
    Intersection(Box<DerivedExpr>, Box<DerivedExpr>),
    /// `lhs` minus `rhs`. Non-commutative; the only operator where swapping
    /// operands is a silent wrong answer.
    Subtraction(Box<DerivedExpr>, Box<DerivedExpr>),
    /// Grow (positive) or shrink (negative) by an exact L-infinity kernel.
    Offset(Box<DerivedExpr>, Dbu),
    /// Shapes of `operand` that lie inside `region`.
    Inside {
        operand: Box<DerivedExpr>,
        region: Box<DerivedExpr>,
    },
    /// Shapes of `operand` that do **not** lie inside `region`.
    ///
    /// Requires an explicit finite universe: "not inside" over an unbounded
    /// plane is not a set of polygons, and the old implementation's implicit
    /// universe was where several of its surprises lived.
    Outside {
        operand: Box<DerivedExpr>,
        region: Box<DerivedExpr>,
        universe: Box<DerivedExpr>,
    },
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum DerivedError {
    #[error("derived layer {0} is defined in terms of itself")]
    Recursive(String),
    #[error("derived layer {0} is referenced but not defined")]
    Undefined(String),
    #[error("layer reference does not resolve to a layer in the deck")]
    UnknownLayer,
    #[error(transparent)]
    Boolean(#[from] gpurify_core::boolean::BooleanError),
    #[error(transparent)]
    Validity(#[from] gpurify_core::view::ValidityError),
}

/// Evaluates named derived layers once each and caches the results.
///
/// **Five questions.** In: the deck's named expressions and a store. Out: one
/// [`ValidatedLayer`] per name. How many: tens of derived layers per deck, each
/// referenced by many rules — which is exactly why the result is cached and not
/// recomputed. Lifetime: the whole run, built once after the layout is read.
/// Parallelisable: independent expressions are, but the dependency graph must
/// be honoured, so it is evaluated in topological order.
///
/// Recursion is detected during that ordering, not by a depth counter: a cycle
/// is a deck error to report, not a stack to blow.
#[derive(Debug, Default)]
pub struct Evaluator {
    /// Names in evaluation order, so a lookup is a binary search and evaluation
    /// is a forward scan.
    name: Vec<StrId>,
    expr: Vec<DerivedExpr>,
    /// Evaluated results, parallel to `name`.
    result: Vec<ValidatedLayer>,
    /// Scratch buffers reused across the whole evaluation. Two, so a binary
    /// operator can write into one while reading the other, and a chain of
    /// operators swaps rather than allocating per node.
    scratch: [ValidatedLayer; 2],
}

impl Evaluator {
    /// Order the deck's named expressions and reject cycles.
    ///
    /// **Decision** — the ordering is pure and table-testable: a list of
    /// definitions in, either an order or a named cycle out.
    pub fn plan(names: &[StrId], exprs: &[DerivedExpr]) -> Result<Self, DerivedError> {
        todo!()
    }

    /// Evaluate every named layer against a store.
    ///
    /// **Transform.** Fills `self.result`; the scratch buffers are reused, so
    /// this allocates once on first call and never again.
    pub fn evaluate(&mut self, store: &gpurify_core::GeometryStore) -> Result<(), DerivedError> {
        todo!()
    }

    /// A previously evaluated named layer.
    ///
    /// The only way a rule reaches derived geometry, and deliberately the only
    /// way: everything a rule needs is a layer the deck named, so this borrows
    /// shared and every consumer can hold it at once. A rule needing an operand
    /// built from its own parameters — "shapes wider than W" — composes
    /// `core::boolean::*_into` into its own scratch instead. There is no
    /// evaluate-an-arbitrary-expression entry point, because one would need
    /// `&mut self` and would serialise every consumer behind this cache.
    pub fn get(&self, name: StrId) -> Option<&ValidatedLayer> {
        todo!()
    }
}
