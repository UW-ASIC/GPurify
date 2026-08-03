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

#[cfg(test)]
mod tests {
    //! The evaluation order `plan` produces, asserted where it is visible.
    //!
    //! `Evaluator` hands results out by name, never by position, so the order
    //! is on the private side of the interface and `tests/plan.rs` can only see
    //! whether a deck was accepted. That is the acceptance half. The ordering
    //! half is here, for the same reason the prefilter's adapter tests are unit
    //! tests: the property is real, is the point of the function, and is not
    //! observable from outside.

    use super::{DerivedExpr, Evaluator, LayerRef};
    use gpurify_core::LayerId;
    use gpurify_ingest::StrId;

    /// One definition, built so its identity survives into the stored
    /// expression: the base layer on the left spine is a tag, and the named
    /// references hang off it. Every definition has the same shape, so
    /// [`tag_of`] reads the tag back whatever the dependencies are.
    fn definition(tag: u16, dependencies: &[StrId]) -> DerivedExpr {
        let mut expr = DerivedExpr::Layer(LayerRef::Base(LayerId(tag)));
        for &dependency in dependencies {
            expr = DerivedExpr::Union(
                Box::new(expr),
                Box::new(DerivedExpr::Layer(LayerRef::Named(dependency))),
            );
        }
        expr
    }

    /// The tag [`definition`] wrote into an expression.
    fn tag_of(expr: &DerivedExpr) -> u16 {
        match expr {
            DerivedExpr::Layer(LayerRef::Base(LayerId(tag))) => *tag,
            DerivedExpr::Union(lhs, _) => tag_of(lhs),
            other => panic!("not an expression `definition` built: {other:?}"),
        }
    }

    /// Every derived name an expression references, at any depth and through
    /// every operand an operator has. Written out rather than asked of the
    /// crate, because asking the crate would make the test agree with whatever
    /// the crate does.
    fn dependencies_of(expr: &DerivedExpr, out: &mut Vec<StrId>) {
        match expr {
            DerivedExpr::Layer(LayerRef::Named(name)) => out.push(*name),
            DerivedExpr::Layer(LayerRef::Base(_)) => {}
            DerivedExpr::Union(lhs, rhs)
            | DerivedExpr::Intersection(lhs, rhs)
            | DerivedExpr::Subtraction(lhs, rhs) => {
                dependencies_of(lhs, out);
                dependencies_of(rhs, out);
            }
            DerivedExpr::Offset(operand, _) => dependencies_of(operand, out),
            DerivedExpr::Inside { operand, region } => {
                dependencies_of(operand, out);
                dependencies_of(region, out);
            }
            DerivedExpr::Outside {
                operand,
                region,
                universe,
            } => {
                dependencies_of(operand, out);
                dependencies_of(region, out);
                dependencies_of(universe, out);
            }
        }
    }

    /// A diamond whose only valid evaluation order is the exact reverse of both
    /// the order the definitions are written in and the numeric order of their
    /// names.
    ///
    /// `root` needs `left` and `right`, both of which need `leaf`. So `leaf`
    /// must come first and `root` last, while the input lists them
    /// `root, left, right, leaf` with ascending [`StrId`]. An implementation
    /// that preserved input order, or that sorted the names so `get` could
    /// binary-search them, produces a forward scan that evaluates `root`
    /// against results that do not exist yet.
    fn diamond() -> (Vec<StrId>, Vec<DerivedExpr>) {
        let (root, left, right, leaf) = (StrId(10), StrId(20), StrId(30), StrId(40));
        (
            vec![root, left, right, leaf],
            vec![
                definition(10, &[left, right]),
                definition(20, &[leaf]),
                definition(30, &[leaf]),
                definition(40, &[]),
            ],
        )
    }

    /// Oracle: law. A topological order is *defined* by one property — every
    /// dependency sits at a smaller index than the definition naming it — and
    /// that property holds for any legal order of any DAG. So it is checkable
    /// without asserting the particular permutation `plan` happens to pick,
    /// which would be a test of a choice rather than of a requirement.
    #[test]
    fn every_dependency_is_ordered_before_the_definition_that_names_it() {
        let (names, exprs) = diamond();
        let planned = Evaluator::plan(&names, &exprs).expect("a diamond is a DAG");

        let position = |name: StrId| {
            planned
                .name
                .iter()
                .position(|&ordered| ordered == name)
                .unwrap_or_else(|| panic!("{name:?} is missing from the evaluation order"))
        };

        let mut referenced = Vec::new();
        for (name, expr) in names.iter().zip(&exprs) {
            referenced.clear();
            dependencies_of(expr, &mut referenced);
            for &dependency in &referenced {
                assert!(
                    position(dependency) < position(*name),
                    "{dependency:?} is evaluated at index {} but {name:?} needs it at index {}",
                    position(dependency),
                    position(*name)
                );
            }
        }
    }

    /// Oracle: law. Ordering is a permutation, so it neither invents a
    /// definition nor loses one. Without this a `plan` that dropped the
    /// definitions it could not place would satisfy the ordering law above by
    /// emitting nothing at all.
    #[test]
    fn ordering_the_definitions_neither_adds_nor_drops_one() {
        let (names, exprs) = diamond();
        let planned = Evaluator::plan(&names, &exprs).expect("a diamond is a DAG");

        let mut ordered = planned.name.clone();
        ordered.sort_unstable();
        let mut given = names.clone();
        given.sort_unstable();
        assert_eq!(
            ordered, given,
            "the evaluation order is not a permutation of the names it was given"
        );
    }

    /// Oracle: law. Reordering moves names and expressions together or it moves
    /// them apart, and moving them apart is a silent wrong answer rather than
    /// an error: every name still resolves, every expression still evaluates,
    /// and every result belongs to a different layer than it claims. The tag on
    /// each definition is what makes that visible.
    #[test]
    fn reordering_keeps_each_expression_paired_with_its_own_name() {
        let (names, exprs) = diamond();
        let planned = Evaluator::plan(&names, &exprs).expect("a diamond is a DAG");

        assert_eq!(
            planned.name.len(),
            planned.expr.len(),
            "the name and expression columns must stay parallel"
        );
        for (index, name) in planned.name.iter().enumerate() {
            let original = names
                .iter()
                .position(|given| given == name)
                .expect("the order holds only names it was given");
            assert_eq!(
                tag_of(&planned.expr[index]),
                tag_of(&exprs[original]),
                "row {index} pairs {name:?} with another definition's expression"
            );
        }
    }
}
