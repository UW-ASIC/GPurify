//! `Evaluator::plan` as a decision: a list of named definitions in, either an
//! evaluation order or a named cycle out.
//!
//! Rejection needs no geometry: a cycle is a property of the name graph alone,
//! which is why the Definition-Phase comment calls the ordering table-testable,
//! and why a cycle is a deck error rather than a stack overflow.
//!
//! Acceptance does need geometry, for an uncomfortable reason. The order `plan`
//! picks is not observable through the public interface — `Evaluator` hands out
//! results by name, never by position — so `plan(..).expect(..)` on its own is
//! satisfied by an `Evaluator` that quietly dropped every definition it could
//! not place. Evaluating against a store and asking for each name back is the
//! only thing the public interface offers that can tell the two apart, so every
//! acceptance case below ends in [`assert_every_definition_evaluates`]. The
//! sharper statement — that a dependency really does precede the definition
//! naming it — needs the private columns and lives in `src/expr.rs`.

use gpurify_geom::Dbu;
use gpurify_geom::StrId;
use gpurify_geom::{DerivedError, DerivedExpr, Evaluator, LayerRef};
use gpurify_geom::{GeometryStore, LayerId};
use gpurify_testgen::LayoutBuilder;

fn base(layer: u16) -> DerivedExpr {
    DerivedExpr::Layer(LayerRef::Base(LayerId(layer)))
}

fn named(name: StrId) -> DerivedExpr {
    DerivedExpr::Layer(LayerRef::Named(name))
}

fn union(lhs: DerivedExpr, rhs: DerivedExpr) -> DerivedExpr {
    DerivedExpr::Union(Box::new(lhs), Box::new(rhs))
}

fn intersection(lhs: DerivedExpr, rhs: DerivedExpr) -> DerivedExpr {
    DerivedExpr::Intersection(Box::new(lhs), Box::new(rhs))
}

fn offset(operand: DerivedExpr, amount: i64) -> DerivedExpr {
    DerivedExpr::Offset(Box::new(operand), Dbu::new_unchecked(amount))
}

fn outside(operand: DerivedExpr, region: DerivedExpr, universe: DerivedExpr) -> DerivedExpr {
    DerivedExpr::Outside {
        operand: Box::new(operand),
        region: Box::new(region),
        universe: Box::new(universe),
    }
}

/// Plan a list of definitions written as pairs, which is how a deck states
/// them and how every case below reads.
fn plan(definitions: &[(StrId, DerivedExpr)]) -> Result<Evaluator, DerivedError> {
    let names: Vec<StrId> = definitions.iter().map(|(name, _)| *name).collect();
    let exprs: Vec<DerivedExpr> = definitions.iter().map(|(_, expr)| expr.clone()).collect();
    Evaluator::plan(&names, &exprs)
}

/// Three overlapping base layers, which is every base layer any case below
/// names. Contents are arbitrary — nothing here asserts a shape — but they are
/// non-empty, so a definition that failed to evaluate cannot hide behind an
/// empty operand.
fn three_base_layers() -> GeometryStore {
    let mut layout = LayoutBuilder::new(3);
    layout.rect(LayerId(0), 0, 0, 400, 400);
    layout.rect(LayerId(1), 200, 200, 600, 600);
    layout.rect(LayerId(2), -1000, -1000, 1000, 1000);
    let (store, _) = layout.finish();
    store
}

/// Every definition handed to `plan` has a result afterwards.
///
/// This is what turns an accepted plan into a checkable claim. Ordering is
/// invisible from outside, so an implementation that returned an empty
/// `Evaluator`, or that discarded the definitions whose dependencies it could
/// not resolve, satisfies every `expect` in this file and fails here. The
/// evaluation itself is the second half: a name reached before the definition
/// it depends on cannot resolve, so a broken order shows up as an error rather
/// than as a wrong shape.
fn assert_every_definition_evaluates(
    mut evaluator: Evaluator,
    definitions: &[(StrId, DerivedExpr)],
) {
    let store = three_base_layers();
    evaluator
        .evaluate(&store)
        .expect("every reference in an accepted plan resolves against these layers");
    for (name, _) in definitions {
        assert!(
            evaluator.get(*name).is_some(),
            "{name:?} was accepted by plan but has no result, so the ordering \
             dropped the definition rather than placing it"
        );
    }
}

/// Oracle: construct-from-answer. A deck with nothing in it has exactly one
/// legal ordering, the empty one, and no reference in it can fail to resolve.
/// The degenerate case is here because a PDK layer table with no derived
/// layers is common and must not be an error.
#[test]
fn a_deck_defining_no_derived_layers_plans_successfully() {
    let evaluator = plan(&[]).expect("a deck with no derived layers has an empty order");
    assert!(
        evaluator.get(StrId(0)).is_none(),
        "an empty plan resolved a name it was never given"
    );
}

/// Oracle: construct-from-answer. The cycle is written into the input, so the
/// answer is known before `plan` runs: this deck has no evaluation order at
/// all, because `gate` is needed to compute `gate`.
#[test]
fn a_layer_defined_in_terms_of_itself_is_reported_as_a_cycle() {
    let gate = StrId(1);
    let error = plan(&[(gate, union(base(0), named(gate)))])
        .expect_err("a self-reference has no evaluation order");
    assert!(
        matches!(error, DerivedError::Recursive(_)),
        "a self-reference must be Recursive, got {error:?}"
    );
}

/// Oracle: construct-from-answer. Mutual recursion is the case a depth counter
/// gets wrong and an ordering gets right: neither definition is deeper than the
/// other, and neither can be evaluated first.
#[test]
fn two_layers_defined_in_terms_of_each_other_are_reported_as_a_cycle() {
    let (poly, gate) = (StrId(1), StrId(2));
    let error = plan(&[
        (poly, intersection(base(0), named(gate))),
        (gate, intersection(base(1), named(poly))),
    ])
    .expect_err("mutual recursion has no evaluation order");
    assert!(
        matches!(error, DerivedError::Recursive(_)),
        "mutual recursion must be Recursive, got {error:?}"
    );
}

/// Oracle: construct-from-answer. Three definitions round a loop, so a cycle
/// check that only compares a node against its immediate parent misses it.
#[test]
fn a_cycle_through_three_layers_is_reported_rather_than_evaluated() {
    let (first, second, third) = (StrId(1), StrId(2), StrId(3));
    let error = plan(&[
        (first, named(second)),
        (second, named(third)),
        (third, named(first)),
    ])
    .expect_err("a three-layer loop has no evaluation order");
    assert!(
        matches!(error, DerivedError::Recursive(_)),
        "a three-layer loop must be Recursive, got {error:?}"
    );
}

/// Oracle: construct-from-answer. The cycle is reachable only through
/// `Offset`'s single operand, so a dependency walk that handles the two-child
/// operators and forgets the one-child operator plans this deck happily and
/// then recurses forever at evaluation time.
#[test]
fn a_cycle_reached_only_through_an_offset_operand_is_still_a_cycle() {
    let grown = StrId(1);
    let error = plan(&[(grown, offset(named(grown), 25))])
        .expect_err("an offset of itself has no evaluation order");
    assert!(
        matches!(error, DerivedError::Recursive(_)),
        "a cycle under Offset must be Recursive, got {error:?}"
    );
}

/// Oracle: construct-from-answer. `Outside` is the only three-child operator in
/// the enum, and its third child is the universe the operator exists to make
/// explicit. A walk written against two children misses exactly this edge.
#[test]
fn a_cycle_reached_only_through_the_universe_of_an_outside_is_still_a_cycle() {
    let field = StrId(1);
    let error = plan(&[(field, outside(base(0), base(1), named(field)))])
        .expect_err("a universe naming its own result has no evaluation order");
    assert!(
        matches!(error, DerivedError::Recursive(_)),
        "a cycle through the universe of an Outside must be Recursive, got {error:?}"
    );
}

/// Oracle: construct-from-answer. A deck lists definitions in whatever order it
/// was written, so a name used before it is defined is legal and reordering it
/// is the whole job. Rejecting this would make `plan` a validator rather than
/// an ordering.
#[test]
fn a_forward_reference_to_a_later_definition_is_legal() {
    let (channel, gate) = (StrId(1), StrId(2));
    let definitions = [
        (
            channel,
            DerivedExpr::Subtraction(Box::new(base(0)), Box::new(named(gate))),
        ),
        (gate, intersection(base(0), base(1))),
    ];
    let evaluator =
        plan(&definitions).expect("a name defined after its use still has an evaluation order");
    assert_every_definition_evaluates(evaluator, &definitions);
}

/// Oracle: construct-from-answer. `Undefined` and `Recursive` are different
/// deck errors with different fixes, so a name nobody defines must not be
/// reported as a loop.
#[test]
fn a_reference_to_a_name_no_definition_provides_is_rejected_as_undefined() {
    let gate = StrId(1);
    let error = plan(&[(gate, union(base(0), named(StrId(99))))])
        .expect_err("a reference to an undefined name cannot be ordered");
    assert!(
        matches!(error, DerivedError::Undefined(_)),
        "an undefined name must be Undefined, not {error:?}"
    );
}

/// Oracle: construct-from-answer. Same claim as above, reached through the
/// universe child, which is the one an incomplete walk skips. Without this the
/// universe could be silently ignored and every `Outside` would fall back to
/// the implicit unbounded plane this operator was redesigned to forbid.
#[test]
fn an_undefined_name_in_the_universe_of_an_outside_is_rejected() {
    let field = StrId(1);
    let error = plan(&[(field, outside(base(0), base(1), named(StrId(77))))])
        .expect_err("an undefined universe cannot be ordered");
    assert!(
        matches!(error, DerivedError::Undefined(_)),
        "an undefined universe must be Undefined, not {error:?}"
    );
}

/// Oracle: construct-from-answer. A diamond reaches one definition by two
/// distinct paths without any loop. A cycle check that marks a name "seen" and
/// treats the second arrival as recursion — the most common way to write one —
/// rejects this deck, and every real deck is full of diamonds.
#[test]
fn a_definition_reached_by_two_paths_is_not_mistaken_for_a_cycle() {
    let (active, nwell, pdiff, ndiff) = (StrId(1), StrId(2), StrId(3), StrId(4));
    let definitions = [
        (active, intersection(base(0), base(1))),
        (nwell, base(2)),
        (pdiff, intersection(named(active), named(nwell))),
        (
            ndiff,
            DerivedExpr::Subtraction(Box::new(named(active)), Box::new(named(nwell))),
        ),
    ];
    let evaluator =
        plan(&definitions).expect("a diamond of definitions is a DAG and has an evaluation order");
    assert_every_definition_evaluates(evaluator, &definitions);
}

/// Oracle: construct-from-answer. A chain four thousand definitions long is a
/// DAG, so it has an order. The doc comment on `Evaluator` promises recursion
/// is caught by the ordering rather than by a depth counter; the flip side of
/// that promise is that legitimate depth must not be mistaken for a problem,
/// and must not blow the stack proving it.
#[test]
fn a_chain_four_thousand_definitions_deep_is_ordered_without_exhausting_the_stack() {
    const DEPTH: u32 = 4096;
    let mut definitions: Vec<(StrId, DerivedExpr)> = (0..DEPTH - 1)
        .map(|step| (StrId(step), named(StrId(step + 1))))
        .collect();
    definitions.push((StrId(DEPTH - 1), base(0)));
    let evaluator = plan(&definitions).expect("a chain is a DAG whatever its length");
    assert_every_definition_evaluates(evaluator, &definitions);
}
